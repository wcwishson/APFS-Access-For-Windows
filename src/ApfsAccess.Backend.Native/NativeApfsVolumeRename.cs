using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;
using ApfsAccess.Core;

namespace ApfsAccess.Backend.Native;

/// <summary>Exact offline rename scope. No default volume, checkpoint, label, or journal is permitted.</summary>
public sealed record ApfsVolumeRenameRequest(string Image, string ContainerUuid, string VolumeUuid,
    string VolumeOid, string PreimageXid, string NewLabel, string JournalRoot);

public enum ApfsRenameOutcome { Renamed, Refused }

/// <summary>
/// Bounded offline volume rename through the packaged rename-tool transport.
/// The native process re-proves image/container/volume identity and the
/// preimage generation from bytes; this transport binds the tool vector to
/// the plan, scopes one journal directory per image path, recovers at most
/// one accepted-but-unrecovered operation, and verifies every claim.
/// </summary>
public sealed class ApfsVolumeRenameResult
{
    internal ApfsVolumeRenameResult(int nativeExitCode, ApfsRenameOutcome outcome, ulong committedXid, string detail)
    { NativeExitCode = nativeExitCode; Outcome = outcome; CommittedXid = committedXid; Detail = detail; }
    public int NativeExitCode { get; }
    public ApfsRenameOutcome Outcome { get; }
    public ulong CommittedXid { get; }
    public string Detail { get; }
}

public sealed class NativeRenameExitException(int exitCode, string diagnostic)
    : IOException($"Native rename failed (exit {exitCode}): {diagnostic}")
{
    public int NativeExitCode { get; } = exitCode;
}

/// <summary>Bounded offline volume rename through the packaged rename-tool transport.</summary>
public sealed class NativeApfsVolumeRename : IManagementRenameKeeper
{
    internal const int MaxOutputBytes = 64 * 1024;
    internal const string RenameToolExeName = "VolumeRenameImage.exe";
    private readonly IObserverRunner runner;
    private readonly string? toolPath;
    private readonly string journalRoot;
    public NativeApfsVolumeRename(string journalRoot) : this(new ProcessObserverRunner(), ResolvePackagedRenameTool(), journalRoot) { }
    internal NativeApfsVolumeRename(IObserverRunner runner, string? toolPath, string journalRoot)
    { this.runner = runner; this.toolPath = toolPath; this.journalRoot = journalRoot; }

    internal static string? ResolvePackagedRenameTool()
        => new[] { Path.Combine(AppContext.BaseDirectory, RenameToolExeName),
            Path.Combine(AppContext.BaseDirectory, "native", RenameToolExeName) }
            .FirstOrDefault(path => File.Exists(path) && NativeApfsObserver.IsPackagedObserverPath(path));

    public static void ValidateRequest(ApfsVolumeRenameRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        // The image needs reliable lease semantics: local fixed drive, exact identity, no aliases.
        // ContainerId grammar is apfs-container:lowercase32hex; reuse the snapshot-reader check
        // with a nonzero decimal OID, then add the rename-specific bindings.
        NativeApfsSnapshotReader.ValidateRequest(request.Image, "apfs-container:" + request.ContainerUuid, request.VolumeOid);
        if (!IsHex(request.ContainerUuid) || !IsHex(request.VolumeUuid) ||
            !NativeApfsSnapshotReader.IsU64(request.PreimageXid, false))
            throw new ArgumentException("Use lowercase hex32 container and volume UUIDs and a canonical nonzero decimal preimage XID.");
        if (request.NewLabel is not { Length: > 0 and <= 255 } ||
            request.NewLabel.Any(static ch => ch == '\0' || ch == '\r' || ch == '\n') ||
            !WellFormedUtf16(request.NewLabel))
            throw new ArgumentException("Use a non-empty volume label up to 255 chars with no NUL/CR/LF or lone surrogates.");
        ValidateJournalRoot(request.JournalRoot);
    }

    internal static bool IsHex(string? value)
        => value is { Length: 32 } && value.All(char.IsAsciiHexDigitLower) && value.Any(static c => c != '0');

    internal static bool WellFormedUtf16(string value)
    {
        for (var i = 0; i < value.Length; i++)
        {
            if (!char.IsSurrogate(value[i])) continue;
            if (!char.IsHighSurrogate(value[i]) || i + 1 >= value.Length || !char.IsLowSurrogate(value[i + 1]))
                return false;
            i++;
        }

        return true;
    }

    internal static void ValidateJournalRoot(string root)
    {
        if (string.IsNullOrEmpty(root) || root.Length < 4 || !char.IsAsciiLetter(root[0]) ||
            root[1] != ':' || root[2] is not ('\\' or '/') || root[2..].Contains(':') ||
            root.Contains('\0') || !Path.IsPathFullyQualified(root) ||
            root[3..].Split(['\\', '/']).Any(p => p.Length == 0 || p is "." or ".." || p.EndsWith(' ') || p.EndsWith('.')))
            throw new ArgumentException("Use an absolute local journal root without device, UNC, ADS, or alias syntax.");
        _ = new UTF8Encoding(false, true).GetBytes(root);
        if (!Directory.Exists(root))
            throw new ArgumentException("The journal root directory must exist.");
    }

    // One journal directory per image path (stable hash): twin copies of one
    // image share volume identity but must never share WAL state.
    internal static string JournalDirFor(string journalRoot, string imagePath)
    {
        var hash = Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes(
            Path.GetFullPath(imagePath).ToUpperInvariant())));
        return Path.Combine(journalRoot, hash);
    }

    public Task<ManagementKeeperRenameResult> RenameVolumeAsync(
        ManagementKeeperRenameRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var transport = new ApfsVolumeRenameRequest(request.ImagePath, request.ContainerUuid,
            request.VolumeUuid, request.VolumeObjectId, request.PreimageXid, request.NewLabel, request.JournalRoot);
        try
        {
            ValidateRequest(transport);
        }
        catch (ArgumentException exception)
        {
            return Task.FromResult(new ManagementKeeperRenameResult(false, 0, ManagementKeeperCodes.InvalidRequest, exception.Message));
        }

        var journalDir = JournalDirFor(transport.JournalRoot, transport.Image);
        Directory.CreateDirectory(journalDir);
        cancellationToken.ThrowIfCancellationRequested();
        RequireTool();
        // Recover at most one accepted-but-unrecovered operation first: the
        // recover verb is idempotent ("No accepted rename" is success), and a
        // recovery proves the preimage XID moved, so the fresh rename below
        // then fails closed on staleness instead of double-applying.
        try
        {
        if (!RunRecover(transport, journalDir, cancellationToken))
            return Task.FromResult(new ManagementKeeperRenameResult(false, 0, ManagementKeeperCodes.Unproven,
                "A previous accepted rename could not be recovered; re-observe and re-plan."));
        return Task.FromResult(RunRename(transport, journalDir, cancellationToken));
        }
        catch(Exception error)when(IsDispatchUncertainty(error))
        {
            return Task.FromResult(new ManagementKeeperRenameResult(false,0,ManagementKeeperCodes.Unproven,
                "Rename dispatch has no proven terminal boundary: "+SingleLine(error.Message)));
        }
    }

    internal ManagementKeeperRenameResult RenameWithOriginalWals(ManagementKeeperRenameRequest request,
        IReadOnlyList<(ulong Oid,string Path)> wallets,string sourceIdentity,CancellationToken cancellationToken)
    {
        var transport=new ApfsVolumeRenameRequest(request.ImagePath,request.ContainerUuid,request.VolumeUuid,
            request.VolumeObjectId,request.PreimageXid,request.NewLabel,request.JournalRoot);
        ValidateRequest(transport);
        if(!string.Equals(request.JournalRoot,journalRoot,StringComparison.OrdinalIgnoreCase)||
            sourceIdentity!=NativeApfsVolumeManagement.SourceIdentity(request.ImagePath,"0")||wallets.Count is <1 or >100||
            !wallets.Any(w=>w.Oid.ToString(CultureInfo.InvariantCulture)==request.VolumeObjectId)||
            wallets.Any(w=>w.Oid==0)||wallets.Select(w=>w.Oid).Distinct().Count()!=wallets.Count||
            wallets.Select(w=>w.Path).Distinct(StringComparer.OrdinalIgnoreCase).Count()!=wallets.Count)
            throw new InvalidDataException("Rename original source/root/WAL census mismatch.");
        foreach(var wallet in wallets)NativeApfsSnapshotReader.ValidateLocalFile(wallet.Path);
        RequireTool();
        var stable=StableFileId(request.ImagePath);
        var hash=NativeApfsVolumeRepair.HashFile(request.ImagePath,cancellationToken);
        var recover=false;
        ObserverRunResult preview;
        while(true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            preview=runner.Run(toolPath!,OriginalArgs(request,wallets,sourceIdentity,null,recover),cancellationToken);
            if(preview.ExitCode==2)throw new NativeRenameExitException(preview.ExitCode,preview.StandardError);
            if(StableFileId(request.ImagePath)!=stable||NativeApfsVolumeRepair.HashFile(request.ImagePath,cancellationToken)!=hash)
                throw new InvalidDataException("Original rename preview changed its source.");
            if(preview.ExitCode==0)break;
            if(!recover&&preview.StandardError.Contains("VolumeRenameOriginalRecoveryRequired",StringComparison.Ordinal))
            {recover=true;continue;}
            return new(false,0,preview.StandardError.Contains("Stale preimage XID",StringComparison.Ordinal)?
                ManagementKeeperCodes.StalePreimage:ManagementKeeperCodes.Refused,SingleLine(preview.StandardError)??"Original rename preview refused.");
        }
        var confirmation=ParseOriginalPreview(preview.StandardOutput,request,sourceIdentity,recover);
        cancellationToken.ThrowIfCancellationRequested();
        try
        {
        var committed=runner.Run(toolPath!,OriginalArgs(request,wallets,sourceIdentity,confirmation,recover),cancellationToken);
        if(committed.ExitCode==2)throw new NativeRenameExitException(committed.ExitCode,committed.StandardError);
        if(StableFileId(request.ImagePath)!=stable)throw new InvalidDataException("Original rename source was replaced.");
        if(committed.ExitCode!=0)
            return new(false,0,ManagementKeeperCodes.Unproven,
                SingleLine(committed.StandardError)??"Original rename commit has no proven terminal boundary; inspect its original journal before retrying.");
        var lines=committed.StandardOutput.Trim().Split('\n',StringSplitOptions.TrimEntries);
        if(lines.Length!=2||ParseOriginalPreview(lines[0],request,sourceIdentity,recover)!=confirmation)
            throw new InvalidDataException("Original rename commit plan echo mismatch.");
        using var document=JsonDocument.Parse(lines[1]);
        var result=document.RootElement;
        ExactOriginalFields(result,"durable checkpointXid acceptedSequence apfsDurableSequence cleanupSequence");
        var xid=OriginalNumber(result,"checkpointXid");
        var accepted=OriginalNumber(result,"acceptedSequence");
        if(result.GetProperty("durable").ValueKind!=JsonValueKind.True||accepted==0||
            OriginalNumber(result,"apfsDurableSequence")!=accepted||OriginalNumber(result,"cleanupSequence")!=accepted||
            (recover?xid<ulong.Parse(request.PreimageXid,CultureInfo.InvariantCulture):xid<=ulong.Parse(request.PreimageXid,CultureInfo.InvariantCulture)))
            throw new InvalidDataException("Original rename durability/generation mismatch.");
        return recover?new(false,0,ManagementKeeperCodes.StalePreimage,"Recovered original accepted rename; re-observe and re-plan."):
            new(true,xid,ManagementKeeperCodes.Committed,$"Renamed oid={request.VolumeObjectId} xid={xid.ToString(CultureInfo.InvariantCulture)}.");
        }
        catch(Exception error)when(IsDispatchUncertainty(error))
        {
            return new(false,0,ManagementKeeperCodes.Unproven,
                "Original rename dispatch has no proven terminal boundary: "+SingleLine(error.Message));
        }
    }

    private static bool IsDispatchUncertainty(Exception error)
        => error is IOException or InvalidDataException or JsonException or InvalidOperationException or
            KeyNotFoundException or FormatException or OverflowException or UnauthorizedAccessException or System.ComponentModel.Win32Exception or
            OperationCanceledException or TimeoutException;

    private static List<string> OriginalArgs(ManagementKeeperRenameRequest request,IReadOnlyList<(ulong Oid,string Path)> wallets,
        string sourceIdentity,string? confirmation,bool recover)
    {
        var args=new List<string>{"--original","--image",request.ImagePath,"--container",request.ContainerUuid,"--volume",request.VolumeUuid,
            "--oid",request.VolumeObjectId,"--xid",request.PreimageXid,"--name",request.NewLabel,"--source-identity",sourceIdentity};
        foreach(var wallet in wallets.OrderBy(w=>w.Oid))args.AddRange(["--wal",wallet.Oid.ToString(CultureInfo.InvariantCulture)+"="+wallet.Path]);
        args.Add(confirmation is null?"--dry-run":"--commit");
        if(confirmation is not null)args.AddRange(["--confirm",confirmation]);
        if(recover)args.Add("--recover");
        return args;
    }

    private static string ParseOriginalPreview(string text,ManagementKeeperRenameRequest request,string sourceIdentity,bool recover)
    {
        if(text.Length>MaxOutputBytes)throw new InvalidDataException("Original rename preview exceeds bound.");
        using var document=JsonDocument.Parse(text);
        var plan=document.RootElement;
        ExactOriginalFields(plan,"schema mode recover oid xid sourceIdentity labelSha256 confirm");
        var hash=Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(request.NewLabel)));
        var token=plan.GetProperty("confirm").GetString();
        if(OriginalNumber(plan,"schema")!=1||plan.GetProperty("mode").GetString()!="rename-original"||
            plan.GetProperty("recover").GetBoolean()!=recover||OriginalNumber(plan,"oid").ToString(CultureInfo.InvariantCulture)!=request.VolumeObjectId||
            OriginalNumber(plan,"xid").ToString(CultureInfo.InvariantCulture)!=request.PreimageXid||
            plan.GetProperty("sourceIdentity").GetString()!=sourceIdentity||plan.GetProperty("labelSha256").GetString()!=hash||
            token is not{Length:64}||!token.All(char.IsAsciiHexDigitLower))
            throw new InvalidDataException("Original rename preview does not bind its request.");
        return token;
    }

    private static void ExactOriginalFields(JsonElement value,string names)
    {
        if(value.ValueKind!=JsonValueKind.Object)throw new InvalidDataException("Expected original rename object.");
        var fields=names.Split(' ').ToHashSet(StringComparer.Ordinal);
        foreach(var field in value.EnumerateObject())if(!fields.Remove(field.Name))throw new InvalidDataException("Unknown or duplicate original rename field.");
        if(fields.Count!=0)throw new InvalidDataException("Missing original rename field.");
    }

    private static ulong OriginalNumber(JsonElement value,string name)
    {
        var number=value.GetProperty(name);
        if(!number.TryGetUInt64(out var result)||number.GetRawText()!=result.ToString(CultureInfo.InvariantCulture))
            throw new InvalidDataException("Expected canonical original rename number.");
        return result;
    }

    private void RequireTool()
    {
        if (toolPath is null || !File.Exists(toolPath))
            throw new FileNotFoundException("Package VolumeRenameImage.exe adjacent to the CLI or in its native directory.");
        NativeApfsSnapshotReader.ValidateLocalFile(toolPath);
    }

    private bool RunRecover(ApfsVolumeRenameRequest request, string journalDir, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        RequireTool();
        var wire = runner.Run(toolPath!,
            ["recover", request.Image, request.ContainerUuid, request.VolumeUuid,
                request.VolumeOid, journalDir], cancellationToken);
        if (wire.ExitCode == 2)
            throw new NativeRenameExitException(wire.ExitCode, wire.StandardError);
        if (wire.ExitCode != 0) return false;
        var line = SingleLine(wire.StandardOutput);
        if(line is null)return false;
        var prefix=line.StartsWith("Recovered oid=",StringComparison.Ordinal)?"Recovered oid=":"No accepted rename oid=";
        prefix+=request.VolumeOid+" xid=";
        return line.StartsWith(prefix,StringComparison.Ordinal)&&NativeApfsSnapshotReader.IsU64(line[prefix.Length..],false);
    }

    private ManagementKeeperRenameResult RunRename(
        ApfsVolumeRenameRequest request, string journalDir, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        RequireTool();
        var stableBefore = StableFileId(request.Image);
        var hashBefore = NativeApfsVolumeRepair.HashFile(request.Image,cancellationToken);
        var wire = runner.Run(toolPath!,
            ["rename", request.Image, request.ContainerUuid, request.VolumeUuid,
                request.VolumeOid, request.PreimageXid, request.NewLabel, journalDir], cancellationToken);
        cancellationToken.ThrowIfCancellationRequested();
        if (wire.ExitCode == 2)
            throw new NativeRenameExitException(wire.ExitCode, wire.StandardError);
        if (wire.ExitCode != 0)
        {
            var refusal = SingleLine(wire.StandardError) ?? "The native rename tool refused the operation.";
            if (refusal == "Rename refused or requires recovery: Stale preimage XID" &&
                StableFileId(request.Image)==stableBefore && NativeApfsVolumeRepair.HashFile(request.Image,cancellationToken)==hashBefore)
                return new ManagementKeeperRenameResult(false, 0, ManagementKeeperCodes.StalePreimage, refusal);
            if (StableFileId(request.Image) != stableBefore)
                throw new InvalidDataException("The image file was replaced during a refused rename.");
            return new ManagementKeeperRenameResult(false, 0, ManagementKeeperCodes.Unproven, refusal);
        }

        var committed = ParseRenamed(wire.StandardOutput, request);
        if (StableFileId(request.Image) != stableBefore)
            throw new InvalidDataException("The image file was replaced during rename.");
        return new ManagementKeeperRenameResult(true, committed, ManagementKeeperCodes.Committed,
            $"Renamed oid={request.VolumeOid} xid={committed.ToString(CultureInfo.InvariantCulture)}.");
    }

    internal static ulong ParseRenamed(string output, ApfsVolumeRenameRequest request)
    {
        var line = SingleLine(output) ??
            throw new InvalidDataException("The native rename tool returned no parsable claim.");
        // Exact claim binding: Renamed oid=<oid> xid=<xid> label=<label>.
        var prefix = $"Renamed oid={request.VolumeOid} xid=";
        if (!line.StartsWith(prefix, StringComparison.Ordinal))
            throw new InvalidDataException("The native rename claim does not bind the requested object ID.");
        var rest = line[prefix.Length..];
        var space = rest.IndexOf(' ');
        if (space <= 0 || !ulong.TryParse(rest[..space], NumberStyles.None,
                CultureInfo.InvariantCulture, out var xid) || xid == 0 ||
            xid.ToString(CultureInfo.InvariantCulture) != rest[..space])
            throw new InvalidDataException("The native rename claim carries no canonical nonzero checkpoint XID.");
        if (!rest[(space + 1)..].Equals("label=" + request.NewLabel, StringComparison.Ordinal))
            throw new InvalidDataException("The native rename claim does not bind the requested label.");
        if (!NativeApfsSnapshotReader.IsU64(request.PreimageXid, false) ||
            xid <= ulong.Parse(request.PreimageXid, CultureInfo.InvariantCulture))
            throw new InvalidDataException("The committed generation must advance past the preimage generation.");
        return xid;
    }

    internal static string? SingleLine(string output)
    {
        Require(new UTF8Encoding(false, true).GetByteCount(output) <= MaxOutputBytes);
        var lines = output.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries);
        return lines.Length == 1 ? lines[0] : null;
    }

    internal static string StableFileId(string path)
    {
        using var handle = File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        if (!GetFileInformationByHandle(handle, out var info)) throw new IOException("Cannot establish image file identity.");
        return FormattableString.Invariant($"windows-file:{info.VolumeSerial}:{((ulong)info.IndexHigh << 32) | info.IndexLow}");
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileInformation
    {
        public uint Attributes, CreationLow, CreationHigh, AccessLow, AccessHigh, WriteLow, WriteHigh,
            VolumeSerial, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
    }
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out FileInformation info);

    private static void Require(bool value)
    {
        if (!value) throw new InvalidDataException("The native rename output exceeds the bounded size.");
    }
}
