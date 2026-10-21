using System.Globalization;
using System.Runtime.InteropServices;
using System.Text.Json;
using ApfsAccess.Core;
using Microsoft.Win32.SafeHandles;

namespace ApfsAccess.Backend.Native;

public sealed class NativeApfsVolumeManagement
{
    internal const string ToolName = "VolumeManagementImage.exe";
    private readonly IObserverRunner _runner;
    private readonly string? _tool;
    private readonly string _root;
    private readonly string _spool;
    public NativeApfsVolumeManagement(string root, string spool) : this(new ProcessObserverRunner(), ResolveTool(), root, spool) { }
    internal NativeApfsVolumeManagement(IObserverRunner runner, string? tool, string root, string spool)
    { _runner = runner; _tool = tool; _root = root; _spool = spool; }
    private static string? ResolveTool() => new[] { Path.Combine(AppContext.BaseDirectory, ToolName),
        Path.Combine(AppContext.BaseDirectory, "native", ToolName) }.FirstOrDefault(p => File.Exists(p) && NativeApfsObserver.IsPackagedObserverPath(p));

    public VolumeTopologyObservation Observe(VerifyScope scope, DeviceInventory inventory, string recoveryRoot, CancellationToken token)
    {
        RequireRoots();
        var identity = ObservationIdentity(scope.ImagePath, scope.StoreOffsetBytes, scope.StoreSizeBytes);
        var wire = Run(["--mode", "observe", "--image", scope.ImagePath, "--offset", scope.StoreOffsetBytes], token);
        if (wire.ExitCode != 0) throw new IOException("VolumeManagementObservationUnavailable: " + wire.StandardOutput);
        using var doc = JsonDocument.Parse(wire.StandardOutput);
        var j = doc.RootElement;
        Fields(j, "schemaVersion operation readOnly image offsetBytes storeSizeBytes sourceIdentity containerUuid checkpointXid blockBytes nextOid volumes");
        Require(j.GetProperty("schemaVersion").GetInt32() == 1 && Text(j, "operation") == "volume-management-observe" &&
            j.GetProperty("readOnly").GetBoolean(), "Invalid read-only volume management observation.");
        var volumes = j.GetProperty("volumes").EnumerateArray().Select(v =>
        {
            Fields(v, "volumeUuid oid");
            return (Uuid: Hex(v, "volumeUuid"), Oid: Num(v, "oid", false));
        }).ToArray();
        var result = new VolumeTopologyObservation(Text(j, "image"), Num(j, "offsetBytes"), Num(j, "storeSizeBytes", false),
            Text(j, "sourceIdentity"), Hex(j, "containerUuid"), Num(j, "checkpointXid", false), Num(j, "blockBytes", false),
            Num(j, "nextOid", false), _spool, []);
        Require(Same(result.Image, scope.ImagePath) && result.OffsetBytes == scope.StoreOffsetBytes &&
            result.StoreSizeBytes == scope.StoreSizeBytes && result.ContainerUuid == scope.ContainerId[15..] &&
            result.CheckpointXid == scope.CheckpointXid && Same(result.SpoolRoot, _spool) &&
            result.SourceIdentity == identity && identity == ObservationIdentity(scope.ImagePath, scope.StoreOffsetBytes, scope.StoreSizeBytes), "Observation scope or source identity changed.");
        var census = NativeRecoveryStorage.BindCensus(scope, inventory, volumes, _spool, recoveryRoot, _root,
            () => ObserveHistory(scope.ImagePath, scope.StoreOffsetBytes, identity, result.CheckpointXid, recoveryRoot, token));
        ValidateCensus(census);
        return result with { Volumes = census };
    }

    private IReadOnlyList<NativeRecoveryStorage.HistoryMember> ObserveHistory(string image, string offset, string identity,
        string checkpoint, string recoveryRoot, CancellationToken token)
    {
        var wire = Run(["--mode", "history", "--image", image, "--offset", offset, "--journal-directory", _root,
            "--history-spool-root", _spool, "--history-recovery-root", recoveryRoot], token);
        using var doc = JsonDocument.Parse(wire.StandardOutput); var j = doc.RootElement;
        Fields(j, "schemaVersion operation admitted error sourceIdentity checkpointXid members");
        Require(wire.ExitCode == 0 && j.GetProperty("schemaVersion").GetInt32() == 1 &&
            Text(j, "operation") == "volume-history-observe" && j.GetProperty("admitted").GetBoolean() &&
            Text(j, "error") == "" && Text(j, "sourceIdentity") == identity && Num(j, "checkpointXid", false) == checkpoint &&
            SourceIdentity(image, offset, bounded: false) == identity, "VolumeManagementNativeHistoryUnproved: " + Text(j, "error"));
        return j.GetProperty("members").EnumerateArray().Select(m =>
        {
            Fields(m, "containerUuid volumeUuid oid path markerCheckpointXid");
            var bound = Num(m, "markerCheckpointXid", false);
            Require(ulong.Parse(bound, CultureInfo.InvariantCulture) <= ulong.Parse(checkpoint, CultureInfo.InvariantCulture) &&
                VolumeTopologyProfile.LocalPath(Text(m, "path")), "VolumeManagementHistoryMemberInvalid");
            return new NativeRecoveryStorage.HistoryMember(Hex(m, "containerUuid"),
                new VolumeTopologyWal(Num(m, "oid", false), Hex(m, "volumeUuid"), Text(m, "path")), bound);
        }).ToArray();
    }

    public VolumeTopologyResult Execute(VolumeTopologyRequest request, VolumeTopologyMode mode, string? confirmation, CancellationToken token,
        string? recoveryRoot = null)
    {
        RequireRoots(); ValidateRequest(request);
        Require(Same(request.JournalRoot, _root) && Same(request.SpoolRoot, _spool), "VolumeManagementStableRootMismatch");
        var physical = request.PhysicalBindingHex is null ? null : VolumePhysicalBinding.Parse(request.PhysicalBindingHex);
        if (physical is not null)
        {
            Require(recoveryRoot is not null, "Physical topology requires complete original recovery roots.");
            ValidateStoreRoot(recoveryRoot!);
        }
        else Require(request.SourceIdentity == SourceIdentity(request.Image, request.OffsetBytes), "VolumeManagementSourceIdentityChanged");
        var args = new List<string> { "--operation", request.Operation, "--mode", mode switch
            { VolumeTopologyMode.Prepare => "dry-run", VolumeTopologyMode.Apply => "apply", VolumeTopologyMode.Cancel => "cancel", _ => "recover" },
            "--image", physical?.Instance ?? request.Image, "--journal-directory", _root, "--offset", request.OffsetBytes,
            "--container", request.ContainerUuid, "--volume", request.VolumeUuid, "--oid", request.VolumeOid, "--xid", request.PreXid };
        if (physical is not null)
        {
            args.AddRange(["--source-kind", "physical", "--physical-binding-hex", request.PhysicalBindingHex!]);
            if (mode is VolumeTopologyMode.Prepare or VolumeTopologyMode.Apply) args.AddRange(["--physical-device", request.Image]);
        }
        foreach (var wal in request.SiblingWals.OrderBy(w => ulong.Parse(w.Oid, CultureInfo.InvariantCulture))) args.AddRange(["--wal", wal.Oid + "=" + wal.Path]);
        if (recoveryRoot is not null) args.AddRange(["--history-spool-root", _spool, "--history-recovery-root", recoveryRoot]);
        if (request.Operation == "create") args.AddRange(["--name", request.Name!, "--quota-blocks", request.QuotaBlocks!,
            "--reserve-blocks", request.ReserveBlocks!, "--case-sensitive", request.CaseSensitive!.Value ? "true" : "false"]);
        if (mode is VolumeTopologyMode.Apply or VolumeTopologyMode.Cancel)
        {
            Require(confirmation is { Length: 64 } && confirmation.All(char.IsAsciiHexDigitLower), "Invalid confirmation token.");
            args.AddRange(["--confirm", confirmation!]);
        }
        else Require(confirmation is null, "This mode does not accept confirmation.");
        var result = ParseResult(Run(args, token), request, mode);
        if (physical is null) Require(request.SourceIdentity == SourceIdentity(request.Image, request.OffsetBytes), "VolumeManagementSourceIdentityChanged");
        return result;
    }

    private ObserverRunResult Run(IReadOnlyList<string> args, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        if (_tool is null) throw new FileNotFoundException("VolumeManagementImage.exe is not packaged.");
        NativeApfsSnapshotReader.ValidateLocalFile(_tool);
        var wire = _runner.Run(_tool, args, token);
        if (System.Text.Encoding.UTF8.GetByteCount(wire.StandardOutput) > 256 * 1024) throw new InvalidDataException("Volume management output exceeded its limit.");
        return wire;
    }

    internal static VolumeTopologyResult ParseResult(ObserverRunResult wire, VolumeTopologyRequest r, VolumeTopologyMode mode)
    {
        using var doc = JsonDocument.Parse(wire.StandardOutput);
        var j = doc.RootElement;
        Fields(j, "schemaVersion operation outcome error image sourceIdentity journal containerUuid volumeUuid volumeOid offsetBytes preXid postXid blockBytes freeBlocksBefore freeBlocksAfter allocatedBlocks deferredBlocks expiresUnixSeconds confirmationToken siblingWals name quotaBlocks reserveBlocks caseSensitive");
        var outcome = Text(j, "outcome");
        var pre = Num(j, "preXid");
        var physical = r.PhysicalBindingHex is null ? null : VolumePhysicalBinding.Parse(r.PhysicalBindingHex);
        Require(j.GetProperty("schemaVersion").GetInt32() == 1 && Text(j, "operation") == "volume-" + r.Operation &&
            Same(Text(j, "image"), physical?.Instance ?? r.Image) && Text(j, "containerUuid") == r.ContainerUuid && Text(j, "volumeUuid") == r.VolumeUuid &&
            Num(j, "volumeOid", false) == r.VolumeOid && Num(j, "offsetBytes") == r.OffsetBytes &&
            (pre == r.PreXid || (pre == "0" && outcome is "refused" or "cancelled")), "Native request binding mismatch.");
        var wals = j.GetProperty("siblingWals").EnumerateArray().Select(w =>
        { Fields(w, "oid path"); return (Oid: Num(w, "oid", false), Path: Text(w, "path")); }).ToArray();
        Require(wals.Length == r.SiblingWals.Count && wals.All(w => r.SiblingWals.Count(v => v.Oid == w.Oid && Same(v.Path, w.Path)) == 1) &&
            wals.Select(w => w.Oid).Distinct().Count() == wals.Length, "Native sibling census mismatch.");
        Require(Text(j, "name") == (r.Name ?? "") && Num(j, "quotaBlocks") == (r.QuotaBlocks ?? "0") &&
            Num(j, "reserveBlocks") == (r.ReserveBlocks ?? "0") && j.GetProperty("caseSensitive").GetBoolean() == (r.CaseSensitive ?? false), "Native option binding mismatch.");
        var expectedExit = outcome switch { "prepared" or "committed" or "cancelled" => 0, "refused" => 1, "recovery-required" => 3, _ => -1 };
        Require(wire.ExitCode == expectedExit || wire.ExitCode == 2 && outcome == "refused" && Text(j, "error").StartsWith("invalid-arguments:", StringComparison.Ordinal), "Native outcome/exit mismatch.");
        var source = Text(j, "sourceIdentity"); var journal = Text(j, "journal");
        var post = Num(j, "postXid"); var block = Num(j, "blockBytes");
        var expires = Num(j, "expiresUnixSeconds"); var confirm = Text(j, "confirmationToken");
        foreach (var key in new[] { "freeBlocksBefore", "freeBlocksAfter", "allocatedBlocks", "deferredBlocks" }) _ = Num(j, key);
        if (outcome is "prepared" or "committed" or "cancelled" or "recovery-required" ||
            outcome == "refused" && Text(j, "error") == "VolumeManagementConfirmationExpired")
            Require(source == r.SourceIdentity && VolumeTopologyProfile.LocalPath(journal) && Same(Path.GetDirectoryName(journal)!, r.JournalRoot), "Native source/journal binding mismatch.");
        Require(outcome == "prepared" ? mode == VolumeTopologyMode.Prepare && confirm.Length == 64 && confirm.All(char.IsAsciiHexDigitLower) &&
            ulong.Parse(expires, CultureInfo.InvariantCulture) > 0 && block != "0" : confirm.Length == 0, "Native confirmation evidence mismatch.");
        if (outcome == "committed") Require((mode is VolumeTopologyMode.Apply or VolumeTopologyMode.Recover) &&
            ulong.Parse(post, CultureInfo.InvariantCulture) > ulong.Parse(r.PreXid, CultureInfo.InvariantCulture) && block != "0", "Native commit proof is missing.");
        Require(mode != VolumeTopologyMode.Prepare || outcome != "committed", "Prepare cannot mutate.");
        Require(mode != VolumeTopologyMode.Prepare || outcome != "cancelled", "Prepare cannot cancel an issued token.");
        return new(outcome, Text(j, "error"), source, journal, pre, post, block, confirm,
            checked((long)ulong.Parse(expires, CultureInfo.InvariantCulture)), j.Clone());
    }

    private void RequireRoots()
    {
        ValidateStoreRoot(_root);
        ValidateStoreRoot(_spool);
        if (!Directory.Exists(_root) || !Directory.Exists(_spool)) throw new IOException("VolumeManagementStableRootUnavailable");
    }
    public static void ValidateIntentFile(string path) => NativeApfsSnapshotReader.ValidateLocalFile(path);
    public static void ValidateStoreRoot(string path)
    {
        NativeApfsVolumeRename.ValidateJournalRoot(path);
        for (var dir = new DirectoryInfo(path); dir is not null; dir = dir.Parent)
            if ((dir.Attributes & FileAttributes.ReparsePoint) != 0) throw new IOException("Reparse management roots are not supported.");
        if (new DriveInfo(Path.GetPathRoot(path)!).DriveType == DriveType.Network) throw new IOException("Management roots must be local.");
    }
    public static void ValidateRequest(VolumeTopologyRequest r)
    {
        if (r.ImageOptions is not null) { NativeApfsVolumeImageManagement.ValidateRequest(r); return; }
        var physical = r.PhysicalBindingHex is null ? null : VolumePhysicalBinding.Parse(r.PhysicalBindingHex);
        Require(r.Operation is "create" or "delete" && (physical is null ? VolumeTopologyProfile.LocalPath(r.Image) :
                VolumePhysicalBinding.IsDevicePath(r.Image) && physical.Limit <= VolumeTopologyProfile.MaximumImageBytes &&
                r.OffsetBytes == physical.BaseOffset.ToString(CultureInfo.InvariantCulture) && r.SourceIdentity == physical.SourceIdentity) &&
            VolumeTopologyProfile.Uuid(r.ContainerUuid) && VolumeTopologyProfile.Uuid(r.VolumeUuid) &&
            VolumeTopologyProfile.Number(r.OffsetBytes) && VolumeTopologyProfile.Number(r.VolumeOid, false) &&
            VolumeTopologyProfile.Number(r.PreXid, false) && r.SourceIdentity.Length == 80 && r.SourceIdentity.All(char.IsAsciiHexDigitLower), "Invalid native request identity.");
        ValidateCensus(r.SiblingWals);
        if (physical is not null)
        {
            Require(VolumeTopologyProfile.LocalPath(r.SpoolRoot), "Physical topology requires the trusted spool root.");
            foreach (var wal in r.SiblingWals)
            {
                var identity = NativeApfsBackend.BuildRecoveryIdentityFromComponents(physical.PartitionGuid, r.ContainerUuid,
                    ulong.Parse(wal.Oid, CultureInfo.InvariantCulture), false) ?? throw new InvalidDataException("Physical original WAL identity unavailable.");
                Require(Same(wal.Path, NativeRecoveryStorage.CanonicalWal(r.SpoolRoot, identity)), "Physical original WAL namespace mismatch.");
            }
            if (r.Operation == "create") Require(r.SiblingWals.All(w => w.Oid != r.VolumeOid && w.VolumeUuid != r.VolumeUuid),
                "Physical create destination must be absent from the current sibling census.");
        }
        if (r.Operation == "create") Require(!string.IsNullOrWhiteSpace(r.Name) && r.Name.Length <= 255 &&
            !r.Name.Any(c => c is '\0' or '\r' or '\n') && VolumeTopologyProfile.Number(r.QuotaBlocks) &&
            VolumeTopologyProfile.Number(r.ReserveBlocks) && r.CaseSensitive is not null, "Create needs explicit valid options.");
        else Require(r.Name is null && r.QuotaBlocks is null && r.ReserveBlocks is null && r.CaseSensitive is null &&
            r.SiblingWals.Count(w => w.Oid == r.VolumeOid && w.VolumeUuid == r.VolumeUuid) == 1, "Delete needs an exact current volume and no create options.");
    }
    internal static void ValidateCensus(IReadOnlyList<VolumeTopologyWal> wals)
    {
        Require(wals is { Count: > 0 and <= 100 } && wals.All(w => VolumeTopologyProfile.Number(w.Oid, false) &&
            VolumeTopologyProfile.Uuid(w.VolumeUuid) && VolumeTopologyProfile.LocalPath(w.Path)) &&
            wals.Select(w => w.Oid).Distinct().Count() == wals.Count &&
            wals.Select(w => w.VolumeUuid).Distinct().Count() == wals.Count &&
            wals.Select(w => w.Path).Distinct(StringComparer.OrdinalIgnoreCase).Count() == wals.Count, "Invalid complete sibling WAL census.");
    }
    private static string ObservationIdentity(string image, string offset, string size)
    {
        Require(VolumeTopologyProfile.Number(size, false) && ulong.Parse(size, CultureInfo.InvariantCulture) <=
            (offset == "0" ? VolumeTopologyProfile.MaximumStreamedImageBytes : VolumeTopologyProfile.MaximumImageBytes), "VolumeManagementObservationSizeExceeded");
        return SourceIdentity(image, offset, bounded: false);
    }
    internal static string SourceIdentity(string image, string offset, bool bounded = true)
    {
        Require(VolumeTopologyProfile.LocalPath(image) && VolumeTopologyProfile.Number(offset), "Image must be an exact local file.");
        NativeApfsSnapshotReader.ValidateLocalFile(image);
        using var handle = File.OpenHandle(image, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        return SourceIdentity(handle, image, offset, bounded);
    }
    internal static string SourceIdentity(SafeFileHandle handle, string image, string offset, bool bounded = true)
    {
        Require(VolumeTopologyProfile.LocalPath(image) && VolumeTopologyProfile.Number(offset), "Image must be an exact local file.");
        NativeApfsSnapshotReader.ValidateIdentity(handle, image);
        if (!GetFileInformationByHandleEx(handle, 18, out FileId id, (uint)Marshal.SizeOf<FileId>()) ||
            !GetFileInformationByHandle(handle, out FileInfoNative info) || info.Links != 1 ||
            (info.Attributes & (uint)(FileAttributes.Directory | FileAttributes.Device | FileAttributes.ReparsePoint)) != 0)
            throw new IOException("VolumeManagementImageIdentityUnavailable");
        var size = ((ulong)info.SizeHigh << 32) | info.SizeLow;
        var start = ulong.Parse(offset, CultureInfo.InvariantCulture);
        Require(size > start && (!bounded || size - start <= VolumeTopologyProfile.MaximumImageBytes), "VolumeManagementBoundedImageSizeExceeded");
        return id.Serial.ToString("x16", CultureInfo.InvariantCulture) + Convert.ToHexStringLower(id.Identifier) +
            start.ToString("x16", CultureInfo.InvariantCulture) + size.ToString("x16", CultureInfo.InvariantCulture);
    }
    [StructLayout(LayoutKind.Sequential)] private struct FileId
    { public ulong Serial; [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public byte[] Identifier; }
    [StructLayout(LayoutKind.Sequential)] private struct FileInfoNative
    { public uint Attributes, CreationLow, CreationHigh, AccessLow, AccessHigh, WriteLow, WriteHigh, Serial, SizeHigh, SizeLow, Links, IndexHigh, IndexLow; }
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(SafeFileHandle h, int c, out FileId info, uint size);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle h, out FileInfoNative info);
    private static string Text(JsonElement j, string key) => j.GetProperty(key).GetString() ?? throw new InvalidDataException("Null native field.");
    private static string Num(JsonElement j, string key, bool zero = true) { var s = Text(j, key); Require(VolumeTopologyProfile.Number(s, zero), "Invalid native number."); return s; }
    private static string Hex(JsonElement j, string key) { var s = Text(j, key); Require(VolumeTopologyProfile.Uuid(s), "Invalid native UUID."); return s; }
    private static bool Same(string a, string b) => string.Equals(a, b, StringComparison.OrdinalIgnoreCase);
    private static void Fields(JsonElement j, string fields)
    { var expected = fields.Split(' ').ToHashSet(); foreach (var p in j.EnumerateObject()) Require(expected.Remove(p.Name), "Unknown or duplicate native field."); Require(expected.Count == 0, "Missing native field."); }
    private static void Require(bool ok, string why) { if (!ok) throw new InvalidDataException(why); }
}

public sealed partial class NativeApfsBackend : IVolumeTopologyBackend
{
    private NativeApfsVolumeImageManagement ImageKeeper(string operation) => new(_observerRunner,
        NativeApfsVolumeImageManagement.ResolveTool(operation),
        _options.ManagementJournalRoot ?? throw new IOException("ManagementJournalRoot is not configured."),
        Environment.GetEnvironmentVariable("APFSACCESS_SPOOL_ROOT") ?? throw new IOException("Original production spool root is not configured."));
    private NativeApfsVolumeManagement TopologyKeeper() => new(_observerRunner,
        new[] { Path.Combine(AppContext.BaseDirectory, NativeApfsVolumeManagement.ToolName), Path.Combine(AppContext.BaseDirectory, "native", NativeApfsVolumeManagement.ToolName) }
            .FirstOrDefault(p => File.Exists(p) && NativeApfsObserver.IsPackagedObserverPath(p)),
        _options.ManagementJournalRoot ?? throw new IOException("ManagementJournalRoot is not configured."),
        Environment.GetEnvironmentVariable("APFSACCESS_SPOOL_ROOT") ?? throw new IOException("Original production spool root is not configured."));
    public Task<VolumeTopologyObservation> ObserveVolumeTopologyAsync(VerifyScope scope, DeviceInventory inventory, CancellationToken token)
        => Task.Run(() => {
            NativeManagementJournalAdmission.RequireImage(_options.ManagementJournalRoot, scope.ImagePath, scope.StoreOffsetBytes);
            var recovery = Environment.GetEnvironmentVariable("APFSACCESS_RECOVERY_ROOT") ?? throw new IOException("Stable recovery root is not configured.");
            var observed = TopologyKeeper().Observe(scope, inventory, recovery, token);
            NativeOrdinaryImageOwnership.RequireCensus(_options.ManagementJournalRoot!, scope.ImagePath, scope.StoreOffsetBytes,
                observed.SpoolRoot, recovery, observed.ContainerUuid, observed.Volumes);
            return observed;
        }, token);
    public Task<VolumeTopologyResult> RunVolumeTopologyAsync(VolumeTopologyRequest request, VolumeTopologyMode mode, string? confirmation, CancellationToken token)
        => Task.Run(() =>
        {
            if ((mode is VolumeTopologyMode.Prepare or VolumeTopologyMode.Apply) && !_options.EnableImageManagementMutations)
                throw new IOException("ImageManagementMutationsDisabled");
            if (request.ImageOptions is not null && (mode is VolumeTopologyMode.Prepare or VolumeTopologyMode.Apply) && !_options.EnableImageResizeFormat)
                throw new IOException("ImageResizeFormatDisabled");
            if (request.PhysicalBindingHex is not null)
            {
                RequirePhysicalVolumeOptions(request.PhysicalBindingHex, mode is VolumeTopologyMode.Prepare or VolumeTopologyMode.Apply);
                NativeManagementJournalAdmission.RequireClearRoot(_options.ManagementJournalRoot, true);
                var physicalRecovery = Environment.GetEnvironmentVariable("APFSACCESS_RECOVERY_ROOT") ?? throw new IOException("Stable recovery root is not configured.");
                return request.ImageOptions is null ? TopologyKeeper().Execute(request, mode, confirmation, token, physicalRecovery) :
                    ImageKeeper(request.Operation).Execute(request, mode, confirmation, token, physicalRecovery);
            }
            NativeManagementJournalAdmission.RequireImage(_options.ManagementJournalRoot, request.Image, request.OffsetBytes,
                mode == VolumeTopologyMode.Prepare ? null : request);
            NativeOrdinaryImageOwnership.RequireCensus(_options.ManagementJournalRoot!, request.Image, request.OffsetBytes, request.SpoolRoot,
                Environment.GetEnvironmentVariable("APFSACCESS_RECOVERY_ROOT") ?? throw new IOException("Stable recovery root is not configured."), request.ContainerUuid, request.SiblingWals);
            var recoveryRoot = Environment.GetEnvironmentVariable("APFSACCESS_RECOVERY_ROOT") ?? throw new IOException("Stable recovery root is not configured.");
            using var disposition = NativeRecoveryStorage.AcquireForNativeKeeper(request, recoveryRoot, _options.ManagementJournalRoot!);
            return request.ImageOptions is not null ? ImageKeeper(request.Operation).Execute(request, mode, confirmation, token, recoveryRoot) :
                TopologyKeeper().Execute(request, mode, confirmation, token, recoveryRoot);
        }, token);
    private HostProcessState? GetRetainedOrdinaryImageOwner_NoLock(string image)
    {
        var groups = _containerGroups.Values.Where(g => string.Equals(g.DevicePath, image, StringComparison.OrdinalIgnoreCase)).ToArray();
        if (groups.Any(g => g.IsPoisoned)) throw new IOException("OrdinaryImageRetainedOwnerUnproved");
        bool Matches(HostProcessState host) => string.Equals(host.OrdinaryImageLaunch?.Record.Image, image, StringComparison.OrdinalIgnoreCase);
        if (_retainedStartupHosts.Values.Any(Matches)) throw new IOException("OrdinaryImageRetainedOwnerUnproved");
        var owners = groups.Select(g => g.Owner).Concat(_hosts.Values.Where(Matches)).Distinct().ToArray();
        if (owners.Length == 0) return null;
        if (owners.Length != 1) throw new IOException("OrdinaryImageRetainedOwnerAmbiguous");
        var owner = owners[0];
        if (owner.OrdinaryImageLaunch is null || owner.ProcessId <= 0 || owner.ProcessCreationTimeFileTimeUtc is not > 0 ||
            TryProbeExactProcessHandleExit(owner.Process) != false ||
            !TryProbeProcessCreationTime(owner.ProcessId, out var creationTime) || creationTime != owner.ProcessCreationTimeFileTimeUtc)
            throw new IOException("OrdinaryImageRetainedOwnerUnproved");
        return owner;
    }

    private void RequireOrdinaryImageRegistration_NoLock(HostProcessState owner, string image)
    {
        var launch = owner.OrdinaryImageLaunch ?? throw new IOException("OrdinaryImageRetainedOwnerUnproved");
        RequireOrdinaryImageLaunchConfiguration(launch, image);
        if (owner.OrdinaryImageDiscovery is not { } discovery || !string.Equals(discovery.DeviceId, image, StringComparison.OrdinalIgnoreCase))
            throw new IOException("OrdinaryImageRetainedInventoryUnproved");
        if (owner.RequestedAccessMode != MountAccessMode.ReadWrite) return;
        foreach (var group in _containerGroups.Values.Where(g => ReferenceEquals(g.Owner, owner)))
        foreach (var member in group.Members.Values)
        {
            if (!launch.Record.LaunchBindings.Any(b => b.ContainerUuid == group.ContainerUuid &&
                b.Oid == member.ObjectId.ToString(CultureInfo.InvariantCulture) && b.RecoveryIdentity == member.RecoveryIdentity))
                throw new IOException("OrdinaryImageRetainedLaunchBindingChanged");
        }
    }

    private void RequireOrdinaryImageLaunchConfiguration(NativeOrdinaryImageOwnership.RetainedLaunch launch, string image)
    {
        RequireOrdinaryImageRegistrationsConfiguration();
        var registrations = _options.OrdinaryManagementImages.Where(r => string.Equals(r.DestinationImage, image, StringComparison.OrdinalIgnoreCase)).ToArray();
        if (registrations.Length != 1) throw new IOException("OrdinaryImageRetainedRegistrationChanged");
        launch.RequireRegistration(registrations[0],
            _options.ManagementJournalRoot ?? throw new IOException("Fresh ordinary image registration requires a stable management root."),
            Environment.GetEnvironmentVariable("APFSACCESS_SPOOL_ROOT") ?? throw new IOException("Explicit stable spool root is required."),
            Environment.GetEnvironmentVariable("APFSACCESS_RECOVERY_ROOT") ?? throw new IOException("Explicit stable recovery root is required."));
    }

    private void RequireOrdinaryImageRegistrationsConfiguration()
    {
        if (!_ordinaryImageRegistrations.SequenceEqual(_options.OrdinaryManagementImages))
            throw new IOException("OrdinaryImageRetainedRegistrationChanged");
    }

    private void EnsureOrdinaryImageRegistrations(CancellationToken token)
    {
        RequireOrdinaryImageRegistrationsConfiguration();
        if (_ordinaryImageRegistrations.Length == 0) return;
        var root = _options.ManagementJournalRoot ?? throw new IOException("Fresh ordinary image registration requires a stable management root.");
        var spool = Environment.GetEnvironmentVariable("APFSACCESS_SPOOL_ROOT") ?? throw new IOException("Explicit stable spool root is required.");
        var recovery = Environment.GetEnvironmentVariable("APFSACCESS_RECOVERY_ROOT") ?? throw new IOException("Explicit stable recovery root is required.");
        _gate.Wait(token);
        try
        {
            foreach (var registration in _options.OrdinaryManagementImages)
            {
                token.ThrowIfCancellationRequested();
                var owner = GetRetainedOrdinaryImageOwner_NoLock(registration.DestinationImage);
                if (owner is null) NativeOrdinaryImageOwnership.RegisterFreshCopy(registration, root, spool, recovery);
                else RequireOrdinaryImageRegistration_NoLock(owner, registration.DestinationImage);
            }
        }
        finally { _gate.Release(); }
    }
}
