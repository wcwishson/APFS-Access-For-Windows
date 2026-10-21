using System.Globalization;
using System.Text.Json;
using ApfsAccess.Core;

namespace ApfsAccess.Backend.Native;

public sealed class NativeApfsVolumeImageManagement
{
    private readonly IObserverRunner _runner;
    private readonly string? _tool;
    private readonly string _root;
    private readonly string _spool;
    internal NativeApfsVolumeImageManagement(IObserverRunner runner, string? tool, string root, string spool)
    { _runner = runner; _tool = tool; _root = root; _spool = spool; }
    internal static string? ResolveTool(string operation)
    {
        var name = operation is "format" or "erase" ? "VolumeFormatImage.exe" : "VolumeResizeImage.exe";
        return new[] { Path.Combine(AppContext.BaseDirectory, name), Path.Combine(AppContext.BaseDirectory, "native", name) }
            .FirstOrDefault(p => File.Exists(p) && NativeApfsObserver.IsPackagedObserverPath(p));
    }
    public static string DestinationWal(string spool, string container)
        => DestinationWal(spool, container, null);
    public static string DestinationWal(string spool, string container, Guid? partitionGuid)
    {
        NativeApfsVolumeManagement.ValidateStoreRoot(spool);
        Require(VolumeTopologyProfile.Uuid(container), "Invalid format destination UUID.");
        var identity = NativeApfsBackend.BuildRecoveryIdentityFromComponents(partitionGuid, container, 1024, partitionGuid is null) ??
            throw new InvalidDataException("Format destination recovery identity unavailable.");
        return NativeRecoveryStorage.CanonicalWal(spool, identity);
    }
    public static void ValidateRequest(VolumeTopologyRequest r)
    {
        var o = r.ImageOptions ?? throw new InvalidDataException("Image options required.");
        var physical = r.PhysicalBindingHex is null ? null : VolumePhysicalBinding.Parse(r.PhysicalBindingHex);
        Require(r.Operation is "grow" or "shrink" or "format" or "erase" &&
            (physical is null ? r.OffsetBytes == "0" && VolumeTopologyProfile.LocalPath(r.Image) :
                VolumePhysicalBinding.IsDevicePath(r.Image) &&
                r.OffsetBytes == physical.BaseOffset.ToString(CultureInfo.InvariantCulture) &&
                o.ExpectedBytes == physical.Limit.ToString(CultureInfo.InvariantCulture) && r.SourceIdentity == physical.SourceIdentity) &&
            VolumeTopologyProfile.Uuid(r.ContainerUuid) &&
            VolumeTopologyProfile.Uuid(r.VolumeUuid) && VolumeTopologyProfile.Number(r.VolumeOid, false) &&
            VolumeTopologyProfile.Number(r.PreXid, false) && r.SourceIdentity is { Length: 80 } && r.SourceIdentity.All(char.IsAsciiHexDigitLower),
            "Invalid image keeper source identity.");
        NativeApfsVolumeManagement.ValidateCensus(r.SiblingWals);
        Require(r.SiblingWals.Count(w => w.Oid == r.VolumeOid && w.VolumeUuid == r.VolumeUuid) == 1 &&
            Capacity(o.ExpectedBytes) && Capacity(o.TargetBytes) && r.QuotaBlocks is null && r.ReserveBlocks is null,
            "Invalid image keeper capacity or complete census.");
        var format = r.Operation is "format" or "erase";
        if (format)
            Require(o.TargetBytes == o.ExpectedBytes && VolumeTopologyProfile.Uuid(o.NewContainerUuid) &&
                VolumeTopologyProfile.Uuid(o.NewVolumeUuid) && o.NewContainerUuid != r.ContainerUuid &&
                o.NewVolumeUuid != r.VolumeUuid && VolumeTopologyProfile.LocalPath(o.NewVolumeWal) &&
                Same(o.NewVolumeWal!, DestinationWal(r.SpoolRoot, o.NewContainerUuid!, physical?.PartitionGuid)) &&
                !string.IsNullOrWhiteSpace(r.Name) && r.Name.Length <= 255 && !r.Name.Any(c => c is '\0' or '\r' or '\n') &&
                r.CaseSensitive is not null, "Invalid format destination or options.");
        else
            Require(o.NewContainerUuid is null && o.NewVolumeUuid is null && o.NewVolumeWal is null &&
                r.Name is null && r.CaseSensitive is null &&
                (r.Operation == "grow" ? ulong.Parse(o.TargetBytes) > ulong.Parse(o.ExpectedBytes) : ulong.Parse(o.TargetBytes) < ulong.Parse(o.ExpectedBytes)),
                "Invalid resize direction or format options.");
        if (physical is not null && !format)
            Require(physical.AllowsResizeTarget(ulong.Parse(o.TargetBytes, CultureInfo.InvariantCulture)),
                "Physical resize must stay within the held disk and preserve a container window's original partition.");
        if (physical is not null)
            foreach (var wal in r.SiblingWals)
            {
                var identity = NativeApfsBackend.BuildRecoveryIdentityFromComponents(physical.PartitionGuid, r.ContainerUuid,
                    ulong.Parse(wal.Oid, CultureInfo.InvariantCulture), false) ?? throw new InvalidDataException("Physical original WAL identity unavailable.");
                Require(Same(wal.Path, NativeRecoveryStorage.CanonicalWal(r.SpoolRoot, identity)), "Physical original WAL namespace mismatch.");
            }
    }
    public VolumeTopologyResult Execute(VolumeTopologyRequest r, VolumeTopologyMode mode, string? token, CancellationToken ct, string? recoveryRoot = null)
    {
        ValidateRequest(r);
        NativeApfsVolumeManagement.ValidateStoreRoot(_root); NativeApfsVolumeManagement.ValidateStoreRoot(_spool);
        Require(Same(r.JournalRoot, _root) && Same(r.SpoolRoot, _spool), "ImageKeeperStableRootMismatch");
        var physical = r.PhysicalBindingHex is null ? null : VolumePhysicalBinding.Parse(r.PhysicalBindingHex);
        if (physical is not null)
        {
            Require(recoveryRoot is not null, "Physical keeper requires complete original recovery roots.");
            NativeApfsVolumeManagement.ValidateStoreRoot(recoveryRoot!);
        }
        var before = physical?.SourceIdentity ?? NativeApfsVolumeManagement.SourceIdentity(r.Image, "0", bounded: false);
        Require(mode == VolumeTopologyMode.Recover && physical is null ? before[..64] == r.SourceIdentity[..64] : before == r.SourceIdentity,
            "ImageKeeperSourceIdentityChanged");
        var o = r.ImageOptions!;
        var args = new List<string> { "--operation", r.Operation, "--mode", mode switch {
            VolumeTopologyMode.Prepare => "dry-run", VolumeTopologyMode.Apply => "apply", VolumeTopologyMode.Cancel => "cancel", _ => "recover" },
            "--image", physical?.Instance ?? r.Image, "--journal-directory", _root, "--container", r.ContainerUuid, "--volume", r.VolumeUuid,
            "--oid", r.VolumeOid, "--xid", r.PreXid, "--expected-bytes", o.ExpectedBytes, "--target-bytes", o.TargetBytes };
        if (physical is not null)
        {
            args.AddRange(["--source-kind", "physical", "--physical-binding-hex", r.PhysicalBindingHex!]);
            if (mode is VolumeTopologyMode.Prepare or VolumeTopologyMode.Apply) args.AddRange(["--physical-device", r.Image]);
        }
        foreach (var wal in r.SiblingWals.OrderBy(w => ulong.Parse(w.Oid, CultureInfo.InvariantCulture))) args.AddRange(["--wal", wal.Oid + "=" + wal.Path]);
        if (recoveryRoot is not null) args.AddRange(["--history-spool-root", _spool, "--history-recovery-root", recoveryRoot]);
        if (r.Operation is "format" or "erase") args.AddRange(["--new-container", o.NewContainerUuid!, "--new-volume", o.NewVolumeUuid!,
            "--new-wal", o.NewVolumeWal!, "--name", r.Name!, "--case-sensitive", r.CaseSensitive!.Value ? "true" : "false"]);
        if (mode is VolumeTopologyMode.Apply or VolumeTopologyMode.Cancel)
        { Require(token is { Length: 64 } && token.All(char.IsAsciiHexDigitLower), "Invalid image confirmation token."); args.AddRange(["--confirm", token!]); }
        else Require(token is null, "This mode does not accept confirmation.");
        ct.ThrowIfCancellationRequested();
        if (_tool is null) throw new FileNotFoundException("Image keeper is not packaged.");
        NativeApfsSnapshotReader.ValidateLocalFile(_tool);
        if (mode == VolumeTopologyMode.Prepare && r.Operation is "format" or "erase")
        {
            // The saved new UUID owns this destination only; native creates and leases the WAL.
            var directory = Path.GetDirectoryName(o.NewVolumeWal!)!;
            Directory.CreateDirectory(directory);
            NativeApfsVolumeManagement.ValidateStoreRoot(directory);
        }
        var wire = RunnerFor(r).Run(_tool, args, ct);
        Require(System.Text.Encoding.UTF8.GetByteCount(wire.StandardOutput) <= 256 * 1024, "Image keeper output exceeds its bound.");
        var result = ParseResult(wire, r, mode);
        // The physical keeper rebinds the private capability and validates all
        // original WAL/history/marker evidence under that same held window.
        if (physical is not null) return result;
        var after = NativeApfsVolumeManagement.SourceIdentity(r.Image, "0", bounded: false);
        Require(after[..64] == r.SourceIdentity[..64], "ImageKeeperSourceFileChanged");
        if (result.Committed) Require(after[64..] == ulong.Parse(o.TargetBytes, CultureInfo.InvariantCulture).ToString("x16"), "Image keeper committed capacity mismatch.");
        else if (mode != VolumeTopologyMode.Recover && result.Outcome != "recovery-required") Require(after == before, "Image keeper changed an uncommitted source.");
        return result;
    }
    internal IObserverRunner RunnerFor(VolumeTopologyRequest request)
    {
        var o = request.ImageOptions!;
        var bytes = Math.Max(ulong.Parse(o.ExpectedBytes, CultureInfo.InvariantCulture), ulong.Parse(o.TargetBytes, CultureInfo.InvariantCulture));
        if (bytes <= VolumeTopologyProfile.MaximumImageBytes || _runner is not ProcessObserverRunner process ||
            process.Timeout != TimeSpan.FromSeconds(60)) return _runner;
        // Whole-source evidence and verification require several passes. Keep a
        // finite deadline while preserving caller cancellation and owned cleanup.
        var gibibytes = (bytes + (1UL << 30) - 1) >> 30;
        var timeout = TimeSpan.FromMinutes(Math.Min(24UL * 60, 5 + 2 * gibibytes));
        return new ProcessObserverRunner { Timeout = timeout, MaxOutputBytes = process.MaxOutputBytes,
            KillGracePeriod = process.KillGracePeriod };
    }
    internal static VolumeTopologyResult ParseResult(ObserverRunResult wire, VolumeTopologyRequest r, VolumeTopologyMode mode)
    {
        using var doc = JsonDocument.Parse(wire.StandardOutput); var j = doc.RootElement; var o = r.ImageOptions!;
        var fields = "schemaVersion operation outcome error image journal sourceIdentity containerUuid volumeUuid volumeOid expectedBytes targetBytes preXid postXid freeBlocksBefore freeBlocksAfter expiresUnixSeconds confirmationToken newContainerUuid newVolumeUuid newVolumeOid newVolumeWal name caseSensitive siblingWals".Split(' ').ToHashSet();
        foreach (var p in j.EnumerateObject()) Require(fields.Remove(p.Name), "Unknown or duplicate image keeper field.");
        Require(fields.Count == 0 && j.GetProperty("schemaVersion").GetInt32() == 1, "Missing image keeper fields.");
        string Text(string key) => j.GetProperty(key).GetString() ?? throw new InvalidDataException("Null image keeper field.");
        string Num(string key) { var s = Text(key); Require(VolumeTopologyProfile.Number(s), "Invalid image keeper decimal."); return s; }
        var outcome = Text("outcome"); var error = Text("error"); var pre = Num("preXid"); var post = Num("postXid");
        var physical = r.PhysicalBindingHex is null ? null : VolumePhysicalBinding.Parse(r.PhysicalBindingHex);
        Require(Text("operation") == r.Operation && Same(Text("image"), physical?.Instance ?? r.Image) && Text("containerUuid") == r.ContainerUuid &&
            Text("volumeUuid") == r.VolumeUuid && Num("volumeOid") == r.VolumeOid && Num("expectedBytes") == o.ExpectedBytes &&
            Num("targetBytes") == o.TargetBytes && (pre == r.PreXid || pre == "0" && outcome is "refused" or "cancelled"), "Image keeper request binding mismatch.");
        var format = r.Operation is "format" or "erase";
        Require(Text("newContainerUuid") == (o.NewContainerUuid ?? "") && Text("newVolumeUuid") == (o.NewVolumeUuid ?? "") &&
            Num("newVolumeOid") == (format ? "1024" : "0") && Same(Text("newVolumeWal"), o.NewVolumeWal ?? "") &&
            Text("name") == (r.Name ?? "") && j.GetProperty("caseSensitive").GetBoolean() == (r.CaseSensitive ?? false), "Image keeper destination binding mismatch.");
        var wals = j.GetProperty("siblingWals").EnumerateArray().ToArray();
        Require(wals.Length == r.SiblingWals.Count && wals.All(w => w.EnumerateObject().Select(p => p.Name).Order().SequenceEqual(new[] { "oid", "path" }) &&
            r.SiblingWals.Count(v => v.Oid == w.GetProperty("oid").GetString() && Same(v.Path, w.GetProperty("path").GetString()!)) == 1) &&
            wals.Select(w => w.GetProperty("oid").GetString()).Distinct().Count() == wals.Length, "Image keeper sibling census mismatch.");
        var exit = outcome switch { "prepared" or "committed" or "cancelled" => 0, "refused" => 1, "recovery-required" => 3, _ => -1 };
        Require(wire.ExitCode == exit || wire.ExitCode == 2 && outcome == "refused" && error.StartsWith("invalid-arguments:", StringComparison.Ordinal), "Image keeper exit/outcome mismatch.");
        var source = Text("sourceIdentity"); var journal = Text("journal"); var confirmation = Text("confirmationToken"); var expiry = Num("expiresUnixSeconds");
        _ = Num("freeBlocksBefore"); _ = Num("freeBlocksAfter");
        var sourceBound = source == r.SourceIdentity || physical is null && mode == VolumeTopologyMode.Recover && source is { Length: 80 } &&
            source[..64] == r.SourceIdentity[..64] && (source[64..] == ulong.Parse(o.ExpectedBytes).ToString("x16") || source[64..] == ulong.Parse(o.TargetBytes).ToString("x16"));
        if (outcome != "refused") Require(sourceBound && VolumeTopologyProfile.LocalPath(journal) &&
            Same(Path.GetDirectoryName(journal)!, r.JournalRoot) && journal.EndsWith(".vif1", StringComparison.Ordinal), "Image keeper source/journal binding mismatch.");
        Require(outcome == "prepared" ? mode == VolumeTopologyMode.Prepare && confirmation is { Length: 64 } &&
            confirmation.All(char.IsAsciiHexDigitLower) && ulong.Parse(expiry) > 0 : confirmation.Length == 0, "Image keeper token evidence mismatch.");
        if (outcome == "committed") Require(mode is VolumeTopologyMode.Apply or VolumeTopologyMode.Recover && ulong.Parse(post) > ulong.Parse(r.PreXid), "Image keeper commit proof missing.");
        Require(mode != VolumeTopologyMode.Prepare || outcome is not ("committed" or "cancelled"), "Prepare cannot mutate or cancel.");
        return new(outcome, error, source, journal, pre, post, "4096", confirmation, checked((long)ulong.Parse(expiry)), j.Clone());
    }
    private static bool Capacity(string s) => VolumeTopologyProfile.Number(s, false) &&
        ulong.Parse(s, CultureInfo.InvariantCulture) is >= 1048576 and <= VolumeTopologyProfile.MaximumStreamedImageBytes &&
        ulong.Parse(s, CultureInfo.InvariantCulture) % 4096 == 0;
    private static bool Same(string a, string b) => string.Equals(a, b, StringComparison.OrdinalIgnoreCase);
    private static void Require(bool ok, string why) { if (!ok) throw new InvalidDataException(why); }
}
