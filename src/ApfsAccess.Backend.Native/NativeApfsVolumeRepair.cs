using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

namespace ApfsAccess.Backend.Native;

/// <summary>Exact offline repair scope. No default volume, checkpoint, intent, or journal is permitted.</summary>
public sealed record ApfsVolumeRepairRequest(string Image, string ContainerId, string VolumeUuid,
    string VolumeOid, string CheckpointXid, string StoreOffsetBytes, string StoreSizeBytes,
    string Journal, string EvidenceDir, string ExpectedCount, bool Confirm)
{
    public string ApprovalMode { get; init; } = string.Empty;
    public string ApprovedSourceIdentity { get; init; } = string.Empty;
    public string ApprovedSourceSha256 { get; init; } = string.Empty;
}

public enum ApfsRepairOutcome { RepairedAndVerified, HealthyNoFinding, NeedsConfirmation, Refused }

/// <summary>
/// Bounded offline RCT2 repair through the packaged repair-tool transport. The native process
/// generates and consumes its own one-use confirmation token internally; this transport carries
/// the operator's explicit intent and verifies every claim. Opt-in exact-source-v1
/// also carries the reviewed public file identity and complete preimage SHA-256.
/// </summary>
public sealed class ApfsVolumeRepairResult
{
    internal ApfsVolumeRepairResult(int nativeExitCode, ApfsRepairOutcome outcome, JsonElement report)
    { NativeExitCode = nativeExitCode; Outcome = outcome; Report = report; }
    public int NativeExitCode { get; }
    public ApfsRepairOutcome Outcome { get; }
    public JsonElement Report { get; }
}

public sealed class NativeRepairExitException(int exitCode, string diagnostic)
    : IOException($"Native repair failed (exit {exitCode}): {diagnostic}")
{
    public int NativeExitCode { get; } = exitCode;
}

/// <summary>Bounded offline RCT2 repair through the packaged repair-tool transport.</summary>
public sealed class NativeApfsVolumeRepair
{
    internal const int MaxReportBytes = 64 * 1024;
    internal const string RepairToolExeName = "ApfsVolumeRepairTool.exe";
    public const string ExactSourceApprovalMode = "exact-source-v1";
    private readonly IObserverRunner runner;
    private readonly string? toolPath;
    public NativeApfsVolumeRepair() : this(new ProcessObserverRunner(), ResolvePackagedRepairTool()) { }
    internal NativeApfsVolumeRepair(IObserverRunner runner, string? toolPath)
    { this.runner = runner; this.toolPath = toolPath; }

    internal static string? ResolvePackagedRepairTool()
        => new[] { Path.Combine(AppContext.BaseDirectory, RepairToolExeName),
            Path.Combine(AppContext.BaseDirectory, "native", RepairToolExeName) }
            .FirstOrDefault(path => File.Exists(path) && NativeApfsObserver.IsPackagedObserverPath(path));

    public static void ValidateRequest(ApfsVolumeRepairRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        // The image needs reliable lease semantics: local fixed drive, exact identity, no aliases.
        NativeApfsSnapshotReader.ValidateRequest(request.Image, request.ContainerId, request.VolumeOid);
        if (!IsHex(request.VolumeUuid) || !NativeApfsSnapshotReader.IsU64(request.CheckpointXid, false) ||
            !NativeApfsSnapshotReader.IsU64(request.StoreOffsetBytes) || !NativeApfsSnapshotReader.IsU64(request.StoreSizeBytes, false))
            throw new ArgumentException("Use a nonzero lowercase hex32 volume UUID and canonical decimal uint64 XID, offset and size; XID and size must be nonzero.");
        var size = (ulong)new FileInfo(request.Image).Length;
        var offset = ulong.Parse(request.StoreOffsetBytes, CultureInfo.InvariantCulture);
        if (offset > size || ulong.Parse(request.StoreSizeBytes, CultureInfo.InvariantCulture) > size - offset)
            throw new ArgumentException("The exact store window must fit inside the image.");
        ValidateOutputPath(request.Journal, "journal");
        ValidateOutputPath(request.EvidenceDir, "evidence directory", directory: true);
        if (string.Equals(Path.GetFullPath(request.Journal), request.Image, StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("The journal path must not be the image itself.");
        if (request.Confirm && !NativeApfsSnapshotReader.IsU64(request.ExpectedCount))
            throw new ArgumentException("Confirmation requires an exact expected count.");
        if (!request.Confirm && !string.IsNullOrEmpty(request.ExpectedCount))
            throw new ArgumentException("An expected count without --confirm states no intent; pass --confirm to apply.");
        ValidateApproval(request);
    }

    private static void ValidateApproval(ApfsVolumeRepairRequest request)
    {
        if (request.ApprovalMode is not ("" or ExactSourceApprovalMode))
            throw new ArgumentException("Unknown repair approval mode.");
        var supplied = !string.IsNullOrEmpty(request.ApprovedSourceIdentity) || !string.IsNullOrEmpty(request.ApprovedSourceSha256);
        if (request.ApprovalMode.Length == 0)
        {
            if (supplied) throw new ArgumentException("Source approval requires exact-source-v1 mode.");
            return;
        }
        if (ulong.Parse(request.StoreOffsetBytes, CultureInfo.InvariantCulture) != 0 ||
            ulong.Parse(request.StoreSizeBytes, CultureInfo.InvariantCulture) != (ulong)new FileInfo(request.Image).Length ||
            new FileInfo(request.Image).Length > 256L * 1024 * 1024)
            throw new ArgumentException("Exact source approval requires one complete image of at most 256MiB at offset zero.");
        if (request.Confirm ? !IsApprovalIdentity(request.ApprovedSourceIdentity, request) || !IsSha256(request.ApprovedSourceSha256) : supplied)
            throw new ArgumentException("Confirmed exact source repair requires the reviewed source identity and lowercase SHA-256; dry runs carry no approval.");
    }

    internal static void ValidateOutputPath(string path, string what, bool directory = false)
    {
        if (string.IsNullOrEmpty(path) || path.Length < 4 || !char.IsAsciiLetter(path[0]) ||
            path[1] != ':' || path[2] is not ('\\' or '/') || path[2..].Contains(':') ||
            path.Contains('\0') || !Path.IsPathFullyQualified(path) ||
            path[3..].Split(['\\', '/']).Any(p => p.Length == 0 || p is "." or ".." || p.EndsWith(' ') || p.EndsWith('.')))
            throw new ArgumentException($"Use an absolute local {what} path without device, UNC, ADS, or alias syntax.");
        _ = new UTF8Encoding(false, true).GetBytes(path);
        if (!directory)
        {
            var parent = Path.GetDirectoryName(Path.GetFullPath(path));
            if (string.IsNullOrEmpty(parent) || !Directory.Exists(parent))
                throw new ArgumentException($"The {what} parent directory must exist.");
        }
    }

    public ApfsVolumeRepairResult Repair(ApfsVolumeRepairRequest request, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ValidateRequest(request);
        if (toolPath is null) throw new FileNotFoundException("Package ApfsVolumeRepairTool.exe adjacent to the CLI or in its native directory.");
        NativeApfsSnapshotReader.ValidateLocalFile(toolPath);
        var preHash = HashFile(request.Image, cancellationToken);
        var preIdentity = ReadIdentity(request.Image);
        var strict = request.ApprovalMode == ExactSourceApprovalMode;
        var preApprovalIdentity = strict ? ReadApprovalIdentity(request.Image) : null;
        var arguments = new List<string> { "--image", request.Image,
            "--container-uuid", request.ContainerId[15..], "--volume-uuid", request.VolumeUuid,
            "--volume-oid", request.VolumeOid, "--checkpoint-xid", request.CheckpointXid,
            "--store-offset-bytes", request.StoreOffsetBytes, "--store-size-bytes", request.StoreSizeBytes,
            "--journal", request.Journal, "--evidence-dir", request.EvidenceDir };
        if (!string.IsNullOrEmpty(request.ExpectedCount)) { arguments.Add("--expected-count"); arguments.Add(request.ExpectedCount); }
        if (request.Confirm) arguments.Add("--confirm");
        if (strict)
        {
            arguments.Add("--approval-mode"); arguments.Add(ExactSourceApprovalMode);
            if (request.Confirm)
            {
                arguments.Add("--approved-source-identity"); arguments.Add(request.ApprovedSourceIdentity);
                arguments.Add("--approved-source-sha256"); arguments.Add(request.ApprovedSourceSha256);
            }
        }
        var wire = runner.Run(toolPath, arguments, cancellationToken);
        cancellationToken.ThrowIfCancellationRequested();
        if (wire.ExitCode is not (0 or 3 or 4)) throw new NativeRepairExitException(wire.ExitCode, wire.StandardError);
        var result = ParseReport(wire.StandardOutput, wire.ExitCode, request);
        // Identity must survive every outcome (no replacement); bytes must survive every
        // refusal/healthy/dry-run outcome (native claims bytesUnchanged, verified here).
        if (preIdentity != ReadIdentity(request.Image))
            throw new InvalidDataException("Image identity changed during repair.");
        if (strict && result.Report.GetProperty("source") is { ValueKind: JsonValueKind.Object } source &&
            (source.GetProperty("identity").GetString() != preApprovalIdentity || source.GetProperty("sha256").GetString() != preHash))
            throw new InvalidDataException("Native repair source evidence differs from the observed invocation preimage.");
        var bytesUnchanged = result.Report.GetProperty("bytesUnchanged");
        if (bytesUnchanged.ValueKind == JsonValueKind.True && preHash != HashFile(request.Image, cancellationToken))
            throw new InvalidDataException("Native repair claimed unchanged bytes but the image changed.");
        cancellationToken.ThrowIfCancellationRequested();
        return result;
    }

    internal static string ReadIdentity(string path)
    {
        using var handle = File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        if (!GetFileInformationByHandle(handle, out var info)) throw new IOException("Cannot establish image file identity.");
        return FormattableString.Invariant($"windows-file:{info.VolumeSerial}:{Join(info.IndexHigh, info.IndexLow)}:{Join(info.SizeHigh, info.SizeLow)}");
    }

    internal static string HashFile(string path, CancellationToken cancellationToken)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        using var sha = System.Security.Cryptography.SHA256.Create();
        var hash = sha.ComputeHash(stream);
        cancellationToken.ThrowIfCancellationRequested();
        return Convert.ToHexStringLower(hash);
    }

    internal static string ReadApprovalIdentity(string path)
    {
        using var handle = File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        if (!GetFileInformationByHandle(handle, out var info) ||
            !GetFileInformationByHandleEx(handle, 18, out var id, (uint)Marshal.SizeOf<FileIdInformation>()))
            throw new IOException("Cannot establish exact image file identity.");
        return "windows-image-v1:" + id.VolumeSerial.ToString("x16", CultureInfo.InvariantCulture) +
            Convert.ToHexStringLower(id.FileId) + "0000000000000000" +
            Join(info.SizeHigh, info.SizeLow).ToString("x16", CultureInfo.InvariantCulture) + ":" +
            Join(info.CreationHigh, info.CreationLow).ToString(CultureInfo.InvariantCulture);
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileIdInformation
    {
        public ulong VolumeSerial;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public byte[] FileId;
    }
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(SafeFileHandle handle, int kind, out FileIdInformation info, uint size);

    private static ulong Join(uint high, uint low) => ((ulong)high << 32) | low;
    [StructLayout(LayoutKind.Sequential)]
    private struct FileInformation
    {
        public uint Attributes, CreationLow, CreationHigh, AccessLow, AccessHigh, WriteLow, WriteHigh,
            VolumeSerial, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
    }
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out FileInformation info);

    internal static ApfsVolumeRepairResult ParseReport(string json, int exitCode, ApfsVolumeRepairRequest request)
    {
        try
        {
            Require(new UTF8Encoding(false, true).GetByteCount(json) <= MaxReportBytes);
            using var document = JsonDocument.Parse(json);
            var root = document.RootElement;
            var strict = request.ApprovalMode == ExactSourceApprovalMode;
            Require(request.ApprovalMode is "" or ExactSourceApprovalMode);
            Object(root, "format version command success exitCode code error image scope finding plan applied replayed postVerify journal backup bytesUnchanged" + (strict ? " source" : ""));
            Require(Text(root, "format") == "apfs-access-repair" && EnumNumber(root, "version", strict ? 2 : 1) == (strict ? 2 : 1) &&
                Text(root, "command") == "repair");
            Require(RawNumber(root, "exitCode") == (ulong)exitCode && Bool(root, "success") == (exitCode == 0));
            var code = Text(root, "code");
            var outcome = code switch
            {
                "RepairedAndVerified" => ApfsRepairOutcome.RepairedAndVerified,
                "RepairHealthyNoFinding" => ApfsRepairOutcome.HealthyNoFinding,
                "RepairNeedsConfirmation" => ApfsRepairOutcome.NeedsConfirmation,
                "RepairRefused" => ApfsRepairOutcome.Refused,
                _ => throw new InvalidDataException("Native repair returned an unknown result code."),
            };
            Require(exitCode == (outcome switch
            {
                ApfsRepairOutcome.RepairedAndVerified or ApfsRepairOutcome.HealthyNoFinding => 0,
                ApfsRepairOutcome.NeedsConfirmation => 3,
                _ => 4,
            }));
            if (exitCode == 2 || exitCode == 5) throw new InvalidDataException("Native repair exit code disagrees with its contract.");
            var image = root.GetProperty("image"); Object(image, "path sizeBytes");
            Require(Text(image, "path") == request.Image);
            Require(RawNumber(image, "sizeBytes") > 0 || (strict && outcome == ApfsRepairOutcome.Refused));
            var scope = root.GetProperty("scope");
            Object(scope, "containerUuid volumeUuid volumeOid checkpointXid storeOffsetBytes storeSizeBytes");
            Require(Text(scope, "containerUuid") == request.ContainerId[15..] && Text(scope, "volumeUuid") == request.VolumeUuid &&
                ScopeNumber(scope, "volumeOid", strict) == request.VolumeOid && ScopeNumber(scope, "checkpointXid", strict) == request.CheckpointXid &&
                ScopeNumber(scope, "storeOffsetBytes", strict) == request.StoreOffsetBytes && ScopeNumber(scope, "storeSizeBytes", strict) == request.StoreSizeBytes);
            if (strict)
            {
                var source = root.GetProperty("source");
                if (source.ValueKind == JsonValueKind.Null) Require(outcome == ApfsRepairOutcome.Refused);
                else
                {
                    Object(source, "identity sha256");
                    Require(IsApprovalIdentity(Text(source, "identity"), request) && IsSha256(Text(source, "sha256")) &&
                        RawNumber(image, "sizeBytes").ToString(CultureInfo.InvariantCulture) == request.StoreSizeBytes);
                    if (outcome == ApfsRepairOutcome.RepairedAndVerified && !Bool(root, "replayed"))
                        Require(request.Confirm && Text(source, "identity") == request.ApprovedSourceIdentity &&
                            Text(source, "sha256") == request.ApprovedSourceSha256);
                }
            }
            var finding = root.GetProperty("finding");
            if (outcome == ApfsRepairOutcome.HealthyNoFinding) Require(finding.ValueKind == JsonValueKind.Null);
            else if (outcome != ApfsRepairOutcome.Refused || HasFinding(root))
            {
                if (finding.ValueKind != JsonValueKind.Null)
                {
                    Object(finding, "code severity check detail");
                    EnumNumber(finding, "code", 25); EnumNumber(finding, "severity", 3); EnumNumber(finding, "check", 20);
                    Text(finding, "detail");
                }
            }
            var plan = root.GetProperty("plan");
            if (outcome == ApfsRepairOutcome.HealthyNoFinding) Require(plan.ValueKind == JsonValueKind.Null);
            else if (plan.ValueKind != JsonValueKind.Null)
            {
                Object(plan, "expectedCount");
                Require(NativeApfsSnapshotReader.IsU64(plan.GetProperty("expectedCount").GetRawText(), true));
                if (!string.IsNullOrEmpty(request.ExpectedCount) && (!strict || outcome != ApfsRepairOutcome.Refused))
                    Require(plan.GetProperty("expectedCount").GetRawText() == request.ExpectedCount);
            }
            var repaired = outcome == ApfsRepairOutcome.RepairedAndVerified;
            if (strict && outcome == ApfsRepairOutcome.NeedsConfirmation)
                Require(!request.Confirm && plan.ValueKind == JsonValueKind.Object && finding.ValueKind == JsonValueKind.Object &&
                    EnumNumber(finding, "code", 25) == 25 && EnumNumber(finding, "severity", 3) == 3 && EnumNumber(finding, "check", 20) == 7);
            var replayed = Bool(root, "replayed");
            Require(Bool(root, "applied") == repaired && (!replayed || repaired));
            if (repaired)
            {
                if (replayed)
                    Require(finding.ValueKind == JsonValueKind.Null && plan.ValueKind == JsonValueKind.Null);
                else
                    Require(request.Confirm && !string.IsNullOrEmpty(request.ExpectedCount) &&
                        finding.ValueKind == JsonValueKind.Object && plan.ValueKind == JsonValueKind.Object &&
                        EnumNumber(finding, "code", 25) == 25 && EnumNumber(finding, "severity", 3) == 3 &&
                        EnumNumber(finding, "check", 20) == 7);
            }
            var post = root.GetProperty("postVerify");
            if (outcome is ApfsRepairOutcome.RepairedAndVerified or ApfsRepairOutcome.HealthyNoFinding)
            {
                Require(post.ValueKind == JsonValueKind.Object);
                Object(post, "outcome findings");
                Require(EnumNumber(post, "outcome", 3) == 1 && RawNumber(post, "findings") == 0);
            }
            else Require(post.ValueKind == JsonValueKind.Null);
            Require(Text(root, "journal") == request.Journal);
            var backup = root.GetProperty("backup");
            Require(backup.ValueKind is JsonValueKind.String or JsonValueKind.Null);
            if (backup.ValueKind == JsonValueKind.String) Text(root, "backup");
            var unchanged = root.GetProperty("bytesUnchanged");
            Require(unchanged.ValueKind is JsonValueKind.True or JsonValueKind.False or JsonValueKind.Null);
            if (unchanged.ValueKind == JsonValueKind.True) Require(exitCode is 0 or 3 or 4);
            if (strict && outcome != ApfsRepairOutcome.RepairedAndVerified) Require(unchanged.ValueKind == JsonValueKind.True);
            return new(exitCode, outcome, root.Clone());
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException or FormatException or OverflowException or ArgumentException or KeyNotFoundException or InvalidDataException)
        { throw new InvalidDataException("Native repair tool returned invalid or mismatched output.", ex); }
    }

    private static bool HasFinding(JsonElement root)
        => root.GetProperty("finding").ValueKind != JsonValueKind.Null;

    private static bool IsHex(string? value) => value is { Length: 32 } && value.All(char.IsAsciiHexDigitLower) && value.Any(c => c != '0');
    private static bool IsSha256(string? value) => value is { Length: 64 } && value.All(char.IsAsciiHexDigitLower);
    private static bool IsApprovalIdentity(string? value, ApfsVolumeRepairRequest request)
    {
        const string prefix = "windows-image-v1:";
        return value is not null && value.StartsWith(prefix, StringComparison.Ordinal) && value.Length > prefix.Length + 81 &&
            value.AsSpan(prefix.Length, 80).ToString().All(char.IsAsciiHexDigitLower) && value[prefix.Length + 80] == ':' &&
            NativeApfsSnapshotReader.IsU64(value[(prefix.Length + 81)..]) &&
            value.Substring(prefix.Length + 48, 16) == ulong.Parse(request.StoreOffsetBytes, CultureInfo.InvariantCulture).ToString("x16", CultureInfo.InvariantCulture) &&
            value.Substring(prefix.Length + 64, 16) == ulong.Parse(request.StoreSizeBytes, CultureInfo.InvariantCulture).ToString("x16", CultureInfo.InvariantCulture);
    }
    private static string ScopeNumber(JsonElement scope, string key, bool strict)
    {
        var element = scope.GetProperty(key);
        // Native v1 emits numbers. Preserve the canonical decimal strings
        // accepted by the original managed v1 contract and its callers.
        var value = !strict && element.ValueKind == JsonValueKind.String ? Text(scope, key) : element.GetRawText();
        Require(NativeApfsSnapshotReader.IsU64(value)); return value;
    }
    private static string Text(JsonElement obj, string key)
    { var text = obj.GetProperty(key).GetString(); Require(text is not null); _ = new UTF8Encoding(false, true).GetByteCount(text!); return text!; }
    private static bool Bool(JsonElement obj, string key) => obj.GetProperty(key).GetBoolean();
    private static int EnumNumber(JsonElement obj, string key, int max)
    { var value = obj.GetProperty(key).GetInt32(); Require(value >= 1 && value <= max); return value; }
    private static ulong RawNumber(JsonElement obj, string key)
    { var value = obj.GetProperty(key); Require(value.ValueKind == JsonValueKind.Number); return value.GetUInt64(); }
    private static void Object(JsonElement obj, string fields)
    {
        Require(obj.ValueKind == JsonValueKind.Object);
        var expected = fields.Split(' ').ToHashSet(StringComparer.Ordinal);
        foreach (var property in obj.EnumerateObject()) Require(expected.Remove(property.Name));
        Require(expected.Count == 0);
    }
    private static void Require(bool condition)
    { if (!condition) throw new InvalidDataException("Native repair tool returned invalid or mismatched output."); }
}
