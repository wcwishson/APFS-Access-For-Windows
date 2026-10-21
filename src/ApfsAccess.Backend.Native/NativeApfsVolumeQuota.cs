using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;
using ApfsAccess.Core;

namespace ApfsAccess.Backend.Native;

/// <summary>Exact offline quota/reserve scope. No default volume, checkpoint, limit, journal, or sibling is permitted.</summary>
public sealed record ApfsVolumeQuotaRequest(string Image, string ContainerUuid, string VolumeUuid,
    string VolumeOid, string PreimageXid, string QuotaBytes, string ReserveBytes,
    IReadOnlyList<string> SiblingOids, string JournalRoot);

/// <summary>
/// Bounded offline quota/reserve keeper through the packaged quota-tool
/// transport. The native process re-proves image/container/volume identity
/// and the preimage generation from bytes, requires a complete per-volume
/// WAL census, and binds every commit to a dry-run confirm token. This
/// transport observes the block size read-only, converts byte limits to
/// whole blocks, re-runs the dry-run to bind the token, and verifies
/// every claim (exit code, strict JSON binding, stable file identity).
/// </summary>
public sealed class NativeApfsVolumeQuota : IManagementQuotaKeeper
{
    internal const int MaxOutputBytes = 256 * 1024;
    internal const string QuotaToolExeName = "VolumeQuotaReserveImageTool.exe";
    private readonly IObserverRunner runner;
    private readonly string? toolPath;
    private readonly string journalRoot;
    public NativeApfsVolumeQuota(string journalRoot) : this(new ProcessObserverRunner(), ResolvePackagedQuotaTool(), journalRoot) { }
    internal NativeApfsVolumeQuota(IObserverRunner runner, string? toolPath, string journalRoot)
    { this.runner = runner; this.toolPath = toolPath; this.journalRoot = journalRoot; }

    internal static string? ResolvePackagedQuotaTool()
        => new[] { Path.Combine(AppContext.BaseDirectory, QuotaToolExeName),
            Path.Combine(AppContext.BaseDirectory, "native", QuotaToolExeName) }
            .FirstOrDefault(path => File.Exists(path) && NativeApfsObserver.IsPackagedObserverPath(path));

    public static void ValidateRequest(ApfsVolumeQuotaRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        NativeApfsSnapshotReader.ValidateRequest(request.Image, "apfs-container:" + request.ContainerUuid, request.VolumeOid);
        if (!IsHex(request.ContainerUuid) || !IsHex(request.VolumeUuid) ||
            !NativeApfsSnapshotReader.IsU64(request.PreimageXid, false) ||
            !NativeApfsSnapshotReader.IsU64(request.QuotaBytes) ||
            !NativeApfsSnapshotReader.IsU64(request.ReserveBytes))
            throw new ArgumentException("Use lowercase hex32 container and volume UUIDs, a canonical nonzero decimal preimage XID, and canonical decimal quota/reserve byte limits.");
        if (request.SiblingOids is null || request.SiblingOids.Count > 100 ||
            request.SiblingOids.Any(sibling => !NativeApfsSnapshotReader.IsU64(sibling, false) ||
                string.Equals(sibling, request.VolumeOid, StringComparison.Ordinal)) ||
            request.SiblingOids.Distinct(StringComparer.Ordinal).Count() != request.SiblingOids.Count)
            throw new ArgumentException("Sibling volume object IDs must be distinct canonical nonzero decimals, none equal to the target.");
        NativeApfsVolumeRename.ValidateJournalRoot(request.JournalRoot);
    }

    internal static bool IsHex(string? value)
        => value is { Length: 32 } && value.All(char.IsAsciiHexDigitLower) && value.Any(static c => c != '0');

    internal static string JournalDirFor(string journalRoot, string imagePath)
        => NativeApfsVolumeRename.JournalDirFor(journalRoot, imagePath);

    public Task<ManagementKeeperQuotaResult> SetQuotaReserveAsync(
        ManagementKeeperQuotaRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var transport = new ApfsVolumeQuotaRequest(request.ImagePath, request.ContainerUuid,
            request.VolumeUuid, request.VolumeObjectId, request.PreimageXid, request.QuotaBytes,
            request.ReserveBytes, request.SiblingObjectIds, request.JournalRoot);
        try
        {
            ValidateRequest(transport);
        }
        catch (ArgumentException exception)
        {
            return Task.FromResult(new ManagementKeeperQuotaResult(false, 0, ManagementKeeperCodes.InvalidRequest, exception.Message));
        }

        return Task.FromResult(RunQuota(transport, cancellationToken));
    }

    internal sealed record DryOutcome(
        bool Ok, QuotaPlan? Plan, string? Reason, bool IsStale, bool NeedsRecovery)
    {
        public static DryOutcome PlanOk(QuotaPlan plan) => new(true, plan, null, false, false);
        public static DryOutcome Fail(string reason, bool isStale, bool needsRecovery)
            => new(false, null, reason, isStale, needsRecovery);
    }

    internal ManagementKeeperQuotaResult SetQuotaReserveWithOriginalWals(ManagementKeeperQuotaRequest request,
        IReadOnlyList<(ulong Oid, string Path)> wallets, ulong blockBytes, CancellationToken cancellationToken)
    {
        var transport = new ApfsVolumeQuotaRequest(request.ImagePath, request.ContainerUuid, request.VolumeUuid,
            request.VolumeObjectId, request.PreimageXid, request.QuotaBytes, request.ReserveBytes, request.SiblingObjectIds, request.JournalRoot);
        ValidateRequest(transport);
        if (!string.Equals(journalRoot, request.JournalRoot, StringComparison.OrdinalIgnoreCase) || blockBytes == 0 ||
            wallets.Count != 1 + request.SiblingObjectIds.Count || wallets.Select(w => w.Oid).Distinct().Count() != wallets.Count ||
            !wallets.Select(w => w.Oid).ToHashSet().SetEquals(request.SiblingObjectIds.Append(request.VolumeObjectId).Select(ulong.Parse)) ||
            wallets.Select(w => w.Path).Distinct(StringComparer.OrdinalIgnoreCase).Count() != wallets.Count)
            throw new InvalidDataException("Quota original root/WAL census binding mismatch.");
        foreach (var wal in wallets)
        {
            NativeApfsSnapshotReader.ValidateLocalFile(wal.Path);
        }
        return RunQuota(transport, cancellationToken, wallets.OrderBy(w => w.Oid).ToArray(), blockBytes);
    }

    private ManagementKeeperQuotaResult RunQuota(ApfsVolumeQuotaRequest request, CancellationToken cancellationToken,
        IReadOnlyList<(ulong Oid, string Path)>? originalWallets = null, ulong? originalBlockBytes = null)
    {
        RequireTool();
        var preHash = NativeApfsVolumeRepair.HashFile(request.Image, cancellationToken);
        var wallets = originalWallets;
        if (wallets is null)
        {
            var journalDir = JournalDirFor(request.JournalRoot, request.Image);
            Directory.CreateDirectory(journalDir);
            wallets = WalletPaths(journalDir, request);
        }
        var blockBytes = originalBlockBytes;
        if (blockBytes is null)
        {
            var probe = DryRun(request, wallets, "0", "0", cancellationToken);
            if (!probe.Ok) return MapRefusal(request, wallets, probe, preHash, cancellationToken);
            blockBytes = probe.Plan!.BlockBytes;
        }
        var quotaBlocks = ToBlocks(request.QuotaBytes, blockBytes.Value);
        var reserveBlocks = ToBlocks(request.ReserveBytes, blockBytes.Value);
        if (quotaBlocks is null || reserveBlocks is null)
            return new ManagementKeeperQuotaResult(false, 0, ManagementKeeperCodes.InvalidRequest,
                "The byte limits overflow the container block accounting.");
        // Bind: dry-run at the converted limits produces the confirm token.
        var bound = DryRun(request, wallets,
            quotaBlocks.Value.ToString(CultureInfo.InvariantCulture),
            reserveBlocks.Value.ToString(CultureInfo.InvariantCulture), cancellationToken);
        if (!bound.Ok) return MapRefusal(request, wallets, bound, preHash, cancellationToken, originalBlockBytes);
        if (bound.Plan!.BlockBytes != blockBytes.Value)
            throw new InvalidDataException("Quota block size differs from the authoritative observation or probe.");
        VerifyUnchanged(request, preHash, cancellationToken);
        return Commit(request, wallets, bound.Plan!, cancellationToken, originalWallets is not null);
    }

    private ManagementKeeperQuotaResult MapRefusal(
        ApfsVolumeQuotaRequest request,
        IReadOnlyList<(ulong Oid, string Path)> wallets,
        DryOutcome dry,
        string preHash,
        CancellationToken cancellationToken,
        ulong? originalBlockBytes = null)
    {
        if (dry.NeedsRecovery)
            return Recover(request, wallets, preHash, cancellationToken, originalBlockBytes);

        return new ManagementKeeperQuotaResult(false, 0,
            dry.IsStale ? ManagementKeeperCodes.StalePreimage : ManagementKeeperCodes.Refused,
            dry.Reason ?? "The native quota tool refused the operation.");
    }

    // Recovery protocol for one accepted-but-unrecovered operation left by
    // an interrupted keeper run. The recover preview re-validates the WAL
    // intent read-only; the recover commit replays it with the current
    // request's converted values, which the tool binds against the WAL
    // intent exactly (mismatch fails closed). Either way the generation
    // may have moved, so success reports StalePreimage: the caller
    // re-observes and re-plans rather than committing blind, keeping the
    // evidence chain auditable. Values from the interrupted plan live in
    // its evidence record when the caller must retry with them.
    private ManagementKeeperQuotaResult Recover(
        ApfsVolumeQuotaRequest request,
        IReadOnlyList<(ulong Oid, string Path)> wallets,
        string preHash,
        CancellationToken cancellationToken,
        ulong? originalBlockBytes = null)
    {
        var previewQuota = originalBlockBytes is { } block ? ToBlocks(request.QuotaBytes, block)?.ToString(CultureInfo.InvariantCulture) : "0";
        var previewReserve = originalBlockBytes is { } reserveBlock ? ToBlocks(request.ReserveBytes, reserveBlock)?.ToString(CultureInfo.InvariantCulture) : "0";
        if (previewQuota is null || previewReserve is null)
            return new(false, 0, ManagementKeeperCodes.InvalidRequest, "Quota recovery limits overflow.");
        var preview = DryRun(request, wallets, previewQuota, previewReserve, cancellationToken, recover: true);
        if (!preview.Ok || preview.Plan is null)
            return new ManagementKeeperQuotaResult(false, 0, ManagementKeeperCodes.Refused,
                preview.Reason ?? "A previous accepted quota operation could not be recovered; re-observe and re-plan.");
        if (originalBlockBytes is { } expectedBlock && preview.Plan.BlockBytes != expectedBlock)
            throw new InvalidDataException("Quota recovery block size changed from the authoritative observation.");
        var quotaBlocks = ToBlocks(request.QuotaBytes, preview.Plan.BlockBytes);
        var reserveBlocks = ToBlocks(request.ReserveBytes, preview.Plan.BlockBytes);
        if (quotaBlocks is null || reserveBlocks is null)
            return new ManagementKeeperQuotaResult(false, 0, ManagementKeeperCodes.InvalidRequest,
                "The byte limits overflow the container block accounting.");
        if (originalBlockBytes is not null) VerifyUnchanged(request, preHash, cancellationToken);
        var stableBefore = originalBlockBytes is null ? null : NativeApfsVolumeRename.StableFileId(request.Image);
        var wire = runner.Run(toolPath!,
            CommitArgs(request, wallets,
                quotaBlocks.Value.ToString(CultureInfo.InvariantCulture),
                reserveBlocks.Value.ToString(CultureInfo.InvariantCulture),
                preview.Plan.ConfirmToken, recover: true), cancellationToken);
        if (wire.ExitCode == 2)
            throw new NativeQuotaExitException(wire.ExitCode, wire.StandardError);
        if (wire.ExitCode != 0)
        {
            var refusal = RefusalReason(wire.StandardError);
            if (IsStaleReason(refusal)) return Stale(request, refusal);
            return new ManagementKeeperQuotaResult(false, 0, ManagementKeeperCodes.Refused, refusal);
        }

        try
        {
            var durable = ParseCommitOutput(wire.StandardOutput, request, preview.Plan, originalBlockBytes is not null);
            // Recovery may only finish cleanup of an already published checkpoint.
            if (originalBlockBytes is not null &&
                (durable < preview.Plan.PreimageXid || NativeApfsVolumeRename.StableFileId(request.Image) != stableBefore))
                throw new InvalidDataException("Quota recovery did not retain source identity and the confirmed generation.");
        }
        catch (InvalidDataException exception)
        {
            return new ManagementKeeperQuotaResult(false, 0, ManagementKeeperCodes.Refused, exception.Message);
        }

        return new ManagementKeeperQuotaResult(false, 0, ManagementKeeperCodes.StalePreimage,
            "A previous accepted quota operation was recovered; the generation moved, so re-observe and re-plan.");
    }

    private ManagementKeeperQuotaResult Commit(
        ApfsVolumeQuotaRequest request,
        IReadOnlyList<(ulong Oid, string Path)> wallets,
        QuotaPlan plan,
        CancellationToken cancellationToken,
        bool requirePlanEcho = false)
    {
        var stableBefore = NativeApfsVolumeRename.StableFileId(request.Image);
        var wire = runner.Run(toolPath!,
            CommitArgs(request, wallets, plan.QuotaBlocks, plan.ReserveBlocks, plan.ConfirmToken, recover: false),
            cancellationToken);
        cancellationToken.ThrowIfCancellationRequested();
        if (wire.ExitCode == 2)
            throw new NativeQuotaExitException(wire.ExitCode, wire.StandardError);
        if (wire.ExitCode != 0)
        {
            var refusal = RefusalReason(wire.StandardError);
            if (IsStaleReason(refusal)) return Stale(request, refusal);
            if (NativeApfsVolumeRename.StableFileId(request.Image) != stableBefore)
                throw new InvalidDataException("The image file was replaced during a refused quota operation.");
            return new ManagementKeeperQuotaResult(false, 0, ManagementKeeperCodes.Refused, refusal);
        }

        var durable = ParseCommitOutput(wire.StandardOutput, request, plan, requirePlanEcho);
        if (durable <= plan.PreimageXid)
            throw new InvalidDataException("The committed generation must advance past the preimage generation.");
        if (NativeApfsVolumeRename.StableFileId(request.Image) != stableBefore)
            throw new InvalidDataException("The image file was replaced during the quota commit.");
        return new ManagementKeeperQuotaResult(true, durable, ManagementKeeperCodes.Committed,
            $"Quota committed oid={request.VolumeOid} xid={durable.ToString(CultureInfo.InvariantCulture)}.");
    }

    private static ManagementKeeperQuotaResult Stale(ApfsVolumeQuotaRequest request, string refusal)
        => new(false, 0, ManagementKeeperCodes.StalePreimage, refusal);

    private DryOutcome DryRun(
        ApfsVolumeQuotaRequest request,
        IReadOnlyList<(ulong Oid, string Path)> wallets,
        string quotaBlocks,
        string reserveBlocks,
        CancellationToken cancellationToken,
        bool recover = false)
    {
        var args = new List<string>
        {
            "--image", request.Image, "--offset", "0",
            "--container", request.ContainerUuid, "--volume", request.VolumeUuid,
            "--oid", request.VolumeOid, "--xid", request.PreimageXid,
            "--quota-blocks", quotaBlocks, "--reserve-blocks", reserveBlocks,
        };
        foreach (var (oid, path) in wallets)
        {
            args.Add("--wal");
            args.Add($"{oid.ToString(CultureInfo.InvariantCulture)}={path}");
        }

        args.Add("--dry-run");
        if (recover) args.Add("--recover");
        var wire = runner.Run(toolPath!, args, cancellationToken);
        if (wire.ExitCode == 2)
            throw new NativeQuotaExitException(wire.ExitCode, wire.StandardError);
        if (wire.ExitCode != 0)
        {
            var refusal = RefusalReason(wire.StandardError);
            return DryOutcome.Fail(refusal, IsStaleReason(refusal), NeedsRecovery(refusal));
        }

        try
        {
            return DryOutcome.PlanOk(ParsePlan(wire.StandardOutput, request, quotaBlocks, reserveBlocks));
        }
        catch (InvalidDataException exception)
        {
            return DryOutcome.Fail(exception.Message, isStale: false, needsRecovery: false);
        }
    }

    private static List<string> CommitArgs(
        ApfsVolumeQuotaRequest request,
        IReadOnlyList<(ulong Oid, string Path)> wallets,
        string quotaBlocks,
        string reserveBlocks,
        string confirm,
        bool recover)
    {
        var args = new List<string>
        {
            "--image", request.Image, "--offset", "0",
            "--container", request.ContainerUuid, "--volume", request.VolumeUuid,
            "--oid", request.VolumeOid, "--xid", request.PreimageXid,
            "--quota-blocks", quotaBlocks, "--reserve-blocks", reserveBlocks,
        };
        foreach (var (oid, path) in wallets)
        {
            args.Add("--wal");
            args.Add($"{oid.ToString(CultureInfo.InvariantCulture)}={path}");
        }

        args.Add("--commit");
        args.Add("--confirm");
        args.Add(confirm);
        if (recover) args.Add("--recover");
        return args;
    }

    private static IReadOnlyList<(ulong Oid, string Path)> WalletPaths(string journalDir, ApfsVolumeQuotaRequest request)
    {
        var oids = new List<ulong> { ulong.Parse(request.VolumeOid, CultureInfo.InvariantCulture) };
        oids.AddRange(request.SiblingOids.Select(sibling => ulong.Parse(sibling, CultureInfo.InvariantCulture)));
        return oids.OrderBy(oid => oid)
            .Select(oid => (oid, Path.Combine(journalDir, $"{oid.ToString(CultureInfo.InvariantCulture)}.wal")))
            .ToArray();
    }

    internal sealed record QuotaPlan(
        ulong PreimageXid, ulong TargetOid, string QuotaBlocks, string ReserveBlocks,
        ulong BlockBytes, string ConfirmToken, IReadOnlyList<ulong> VolumeOids);

    internal static QuotaPlan ParsePlan(
        string output, ApfsVolumeQuotaRequest request, string quotaBlocks, string reserveBlocks)
    {
        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(SingleLine(output) ??
                throw new InvalidDataException("The native quota tool returned no parsable plan."));
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException("The native quota tool returned no parsable plan.", exception);
        }

        using (document)
        {
        var root = document.RootElement;
        RequireKeys(root, ["operation", "xid", "oid", "quotaBlocks", "reserveBlocks", "blockBytes", "freeBlocks", "confirm", "volumes"]);
        if (root.GetProperty("operation").GetUInt64() != 20)
            throw new InvalidDataException("The quota plan is not operation 20.");
        var xid = root.GetProperty("xid").GetUInt64();
        if (xid == 0 || xid.ToString(CultureInfo.InvariantCulture) != request.PreimageXid)
            throw new InvalidDataException("The quota plan does not bind the requested preimage generation.");
        var oid = root.GetProperty("oid").GetUInt64();
        if (oid == 0 || oid.ToString(CultureInfo.InvariantCulture) != request.VolumeOid)
            throw new InvalidDataException("The quota plan does not bind the requested volume.");
        if (root.GetProperty("quotaBlocks").GetUInt64().ToString(CultureInfo.InvariantCulture) != quotaBlocks ||
            root.GetProperty("reserveBlocks").GetUInt64().ToString(CultureInfo.InvariantCulture) != reserveBlocks)
            throw new InvalidDataException("The quota plan does not bind the requested limits.");
        var blockBytes = root.GetProperty("blockBytes").GetUInt64();
        if (blockBytes == 0)
            throw new InvalidDataException("The quota plan carries no usable block size.");
        var confirm = root.GetProperty("confirm").GetString();
        if (confirm is not { Length: 64 } || !confirm.All(char.IsAsciiHexDigitLower))
            throw new InvalidDataException("The quota plan carries no well-formed confirm token.");
        var oids = root.GetProperty("volumes").EnumerateArray().Select(volume =>
        {
            RequireKeys(volume, ["oid", "charged", "quota", "reserve"]);
            return volume.GetProperty("oid").GetUInt64();
        }).ToArray();
        if (oids.Length != 1 + request.SiblingOids.Count || oids.Distinct().Count() != oids.Length ||
            !oids.ToHashSet().SetEquals(request.SiblingOids.Append(request.VolumeOid).Select(ulong.Parse)))
            throw new InvalidDataException("The quota plan census does not cover the container volumes.");
        return new QuotaPlan(xid, oid, quotaBlocks, reserveBlocks, blockBytes, confirm, oids);
        }
    }

    internal static ulong ParseDurable(string output)
    {
        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(SingleLine(output) ??
                throw new InvalidDataException("The native quota tool returned no parsable commit."));
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException("The native quota tool returned no parsable commit.", exception);
        }

        using (document)
        {
            var root = document.RootElement;
            RequireKeys(root, ["durable", "checkpointXid", "cleanupSequence"]);
            if (root.GetProperty("durable").GetBoolean() != true)
                throw new InvalidDataException("The quota commit did not report durable.");
            return root.GetProperty("checkpointXid").GetUInt64();
        }
    }

    internal static ulong ParseCommitOutput(string output, ApfsVolumeQuotaRequest request, QuotaPlan plan, bool requirePlanEcho = false)
    {
        RequireBytes(new UTF8Encoding(false, true).GetByteCount(output) <= MaxOutputBytes);
        var lines = output.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries);
        if (lines.Length == 1 && !requirePlanEcho) return ParseDurable(lines[0]); // Existing standalone transport vectors.
        if (lines.Length != 2) throw new InvalidDataException("The native quota commit report shape is not exact.");
        var echoed = ParsePlan(lines[0], request, plan.QuotaBlocks, plan.ReserveBlocks);
        if (echoed.ConfirmToken != plan.ConfirmToken || echoed.BlockBytes != plan.BlockBytes ||
            !echoed.VolumeOids.Order().SequenceEqual(plan.VolumeOids.Order()))
            throw new InvalidDataException("The native quota commit changed the confirmed plan.");
        return ParseDurable(lines[1]);
    }

    internal static void RequireKeys(JsonElement element, IReadOnlyList<string> keys)
    {
        if (element.ValueKind != JsonValueKind.Object)
            throw new InvalidDataException("The native quota tool returned a malformed report.");
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in element.EnumerateObject())
            if (!seen.Add(property.Name)) throw new InvalidDataException("The native quota report has duplicate fields.");
        if (!seen.SetEquals(keys))
            throw new InvalidDataException("The native quota report shape is not exact.");
    }

    internal static string? SingleLine(string output)
    {
        RequireBytes(new UTF8Encoding(false, true).GetByteCount(output) <= MaxOutputBytes);
        var lines = output.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries);
        return lines.Length == 1 ? lines[0] : null;
    }

    internal static ulong? ToBlocks(string byteCount, ulong blockBytes)
    {
        if (blockBytes == 0) return null;
        var bytes = ulong.Parse(byteCount, CultureInfo.InvariantCulture);
        if (bytes == 0) return 0;
        var blocks = bytes / blockBytes;
        if (bytes % blockBytes != 0) blocks++;
        return blocks == 0 ? null : blocks;
    }

    internal static string RefusalReason(string standardError)
    {
        var line = SingleLine(standardError);
        if (line is not null && line.StartsWith("REFUSED ", StringComparison.Ordinal))
            return line["REFUSED ".Length..];
        return "The native quota tool refused the operation.";
    }

    internal static bool IsStaleReason(string refusal)
        => refusal.Contains("mismatch", StringComparison.OrdinalIgnoreCase) ||
            refusal.Contains("changed after dry-run", StringComparison.OrdinalIgnoreCase) ||
            refusal.Contains("moved", StringComparison.OrdinalIgnoreCase);

    internal static bool NeedsRecovery(string refusal)
        => refusal.Contains("accepted", StringComparison.OrdinalIgnoreCase) &&
            (refusal.Contains("conflict", StringComparison.OrdinalIgnoreCase) ||
                refusal.Contains("replay", StringComparison.OrdinalIgnoreCase) ||
                refusal.Contains("recover", StringComparison.OrdinalIgnoreCase));

    private static void VerifyUnchanged(
        ApfsVolumeQuotaRequest request, string preHash, CancellationToken cancellationToken)
    {
        if (preHash != NativeApfsVolumeRepair.HashFile(request.Image, cancellationToken))
            throw new InvalidDataException("A read-only quota dry-run changed image bytes.");
    }

    private void RequireTool()
    {
        if (toolPath is null || !File.Exists(toolPath))
            throw new FileNotFoundException("Package VolumeQuotaReserveImageTool.exe adjacent to the CLI or in its native directory.");
        NativeApfsSnapshotReader.ValidateLocalFile(toolPath);
    }

    private static void RequireBytes(bool value)
    {
        if (!value) throw new InvalidDataException("The native quota output exceeds the bounded size.");
    }
}

public sealed class NativeQuotaExitException(int exitCode, string diagnostic)
    : IOException($"Native quota failed (exit {exitCode}): {diagnostic}")
{
    public int NativeExitCode { get; } = exitCode;
}
