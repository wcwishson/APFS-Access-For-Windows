using System.Globalization;
using System.Text;
using System.Text.Json;

namespace ApfsAccess.Backend.Native;

public sealed record ApfsSnapshotAttributionRequest(string Image, string ContainerId, string VolumeUuid,
    string VolumeOid, string CheckpointXid, string StoreOffsetBytes, string StoreSizeBytes)
{
    internal ApfsImageVerificationRequest ExactScope => new(Image, ContainerId, VolumeUuid, VolumeOid,
        CheckpointXid, StoreOffsetBytes, StoreSizeBytes);
}

public sealed record ApfsSnapshotAttributionResult(int NativeExitCode, bool Complete, JsonElement Report);

public sealed partial class NativeApfsImageVerifier
{
    public static void ValidateSnapshotAttributionRequest(ApfsSnapshotAttributionRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        ValidateRequest(request.ExactScope);
    }

    public ApfsSnapshotAttributionResult ObserveSnapshotAttribution(ApfsSnapshotAttributionRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();
        ValidateSnapshotAttributionRequest(request);
        if (observerPath is null) throw new FileNotFoundException("Package ApfsObserver.exe adjacent to the CLI or in its native directory.");
        NativeApfsSnapshotReader.ValidateLocalFile(observerPath);
        using var source = File.OpenHandle(request.Image, FileMode.Open, FileAccess.Read, FileShare.Read);
        NativeApfsSnapshotReader.ValidateIdentity(source, request.Image);
        var identity = ReadIdentity(source);
        string[] arguments = ["--image", request.Image, "--mode", "snapshot-attribution",
            "--container-uuid", request.ContainerId[15..], "--volume-uuid", request.VolumeUuid,
            "--volume-oid", request.VolumeOid, "--checkpoint-xid", request.CheckpointXid,
            "--store-offset-bytes", request.StoreOffsetBytes, "--store-size-bytes", request.StoreSizeBytes];
        var wire = runner.Run(observerPath, arguments, cancellationToken);
        cancellationToken.ThrowIfCancellationRequested();
        if (wire.ExitCode is not (0 or 3)) throw new NativeVerificationExitException(wire.ExitCode, wire.StandardError);
        var result = ParseSnapshotAttribution(wire.StandardOutput, wire.ExitCode, request, identity, cancellationToken);
        NativeApfsSnapshotReader.ValidateIdentity(source, request.Image);
        if (identity != ReadIdentity(source)) throw new InvalidDataException("Image identity changed during snapshot accounting.");
        cancellationToken.ThrowIfCancellationRequested();
        return result;
    }

    internal static ApfsSnapshotAttributionResult ParseSnapshotAttribution(string json, int exitCode,
        ApfsSnapshotAttributionRequest request, string identity, CancellationToken cancellationToken = default)
    {
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            Require(new UTF8Encoding(false, true).GetByteCount(json) <= MaxReportBytes);
            using var document = JsonDocument.Parse(json);
            var root = document.RootElement;
            var complete = Bool(root, "complete");
            Object(root, "format version readOnly complete source scope" + (complete
                ? " allocationUnitBytes retainedCheckpointXids referencedMetadata referencedPayload catalogMetadata snapshots"
                : " reason"));
            Require(Text(root, "format") == "apfs-access-snapshot-space-attribution" &&
                root.GetProperty("version").GetInt32() == 1 && Bool(root, "readOnly") && exitCode == (complete ? 0 : 3));
            var source = root.GetProperty("source"); Object(source, "path identity");
            Require(Text(source, "path") == request.Image && Text(source, "identity") == identity);
            var scope = root.GetProperty("scope");
            Object(scope, "containerUuid volumeUuid volumeOid checkpointXid storeOffsetBytes storeSizeBytes");
            Exact(scope, request.ExactScope);
            if (!complete)
            {
                var reason = Text(root, "reason");
                Require(reason.Length is > 0 and <= 65535 && !reason.Contains('\0'));
                return new(exitCode, false, root.Clone());
            }

            var unit = root.GetProperty("allocationUnitBytes").GetUInt32();
            var size = Number(scope, "storeSizeBytes", false);
            Require(unit is >= 4096 and <= 65536 && (unit & (unit - 1)) == 0 && size % unit == 0 &&
                Number(scope, "storeOffsetBytes") % unit == 0);
            var capacity = size / unit;
            var xids = root.GetProperty("retainedCheckpointXids");
            Require(xids.ValueKind == JsonValueKind.Array && xids.GetArrayLength() is > 0 and <= 1000000);
            ulong previous = 0;
            foreach (var item in xids.EnumerateArray())
            {
                cancellationToken.ThrowIfCancellationRequested();
                var text = item.GetString(); Require(NativeApfsSnapshotReader.IsU64(text, false));
                var xid = ulong.Parse(text!, CultureInfo.InvariantCulture);
                Require(xid > previous); previous = xid;
            }
            Require(previous == Number(scope, "checkpointXid", false));
            var metadata = AttributionAmount(root.GetProperty("referencedMetadata"), capacity, unit);
            var payload = AttributionAmount(root.GetProperty("referencedPayload"), capacity, unit);
            var catalog = AttributionAmount(root.GetProperty("catalogMetadata"), capacity, unit);
            Require(catalog > 0 && metadata <= catalog && payload <= capacity - catalog);
            var snapshots = root.GetProperty("snapshots");
            Require(snapshots.ValueKind == JsonValueKind.Array && snapshots.GetArrayLength() <= 1000000);
            var names = new HashSet<string>(StringComparer.Ordinal);
            var totals = new (ulong Referenced, ulong UniqueOther, ulong Shared)[2];
            previous = 0;
            foreach (var row in snapshots.EnumerateArray())
            {
                cancellationToken.ThrowIfCancellationRequested();
                Object(row, "snapshotXid name metadata payload purgeableMarkedPayload applePurgeable reclaimable");
                var xid = Number(row, "snapshotXid", false);
                var name = Text(row, "name");
                Require(xid > previous && xid <= Number(scope, "checkpointXid", false) &&
                    name.Length > 0 && !name.Contains('\0') && Encoding.UTF8.GetByteCount(name) <= 65535 && names.Add(name) &&
                    row.GetProperty("applePurgeable").ValueKind == JsonValueKind.Null &&
                    row.GetProperty("reclaimable").ValueKind == JsonValueKind.Null &&
                    AttributionAmount(row.GetProperty("purgeableMarkedPayload"), capacity, unit) == 0);
                previous = xid;
                var fields = new[] { row.GetProperty("metadata"), row.GetProperty("payload") };
                var unions = new[] { metadata, payload };
                for (var index = 0; index < fields.Length; ++index)
                {
                    var measures = AttributionMeasures(fields[index], unions[index], capacity, unit);
                    Require(index != 0 || measures.Referenced > 0);
                    ref var total = ref totals[index];
                    total.Referenced += Math.Min(capacity - total.Referenced, measures.Referenced);
                    var unique = measures.Referenced - measures.Shared;
                    Require(unique <= unions[index] - total.UniqueOther);
                    total.UniqueOther += unique;
                    total.Shared += Math.Min(2 * capacity - total.Shared, measures.Shared);
                }
            }
            var completeUnions = new[] { metadata, payload };
            for (var index = 0; index < totals.Length; ++index)
            {
                var union = completeUnions[index]; var total = totals[index];
                Require(union <= total.Referenced && total.Shared >= 2 * (union - total.UniqueOther));
                foreach (var row in snapshots.EnumerateArray())
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    Require(AttributionAmount(row.GetProperty(index == 0 ? "metadata" : "payload")
                        .GetProperty("sharedWithOtherSnapshots"), capacity, unit) <= union - total.UniqueOther);
                }
            }
            cancellationToken.ThrowIfCancellationRequested();
            return new(exitCode, true, root.Clone());
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException or KeyNotFoundException or
            FormatException or OverflowException or EncoderFallbackException)
        { throw new InvalidDataException("Native observer returned invalid snapshot space attribution.", ex); }
    }

    private static ulong AttributionAmount(JsonElement value, ulong capacity, uint unit)
    {
        Object(value, "blocks bytes");
        var blocks = Number(value, "blocks");
        Require(blocks <= capacity && Number(value, "bytes") == checked(blocks * unit));
        return blocks;
    }

    private static (ulong Referenced, ulong Shared) AttributionMeasures(JsonElement value, ulong union, ulong capacity, uint unit)
    {
        Object(value, "referenced sharedWithLive absentFromLive sharedWithOtherSnapshots uniqueInVisibleInventory retainedOrPeerProtected potentialReclaimUpperBound");
        ulong Amount(string name) => AttributionAmount(value.GetProperty(name), capacity, unit);
        var referenced = Amount("referenced"); var live = Amount("sharedWithLive");
        var absent = Amount("absentFromLive"); var other = Amount("sharedWithOtherSnapshots");
        var unique = Amount("uniqueInVisibleInventory"); var protectedBlocks = Amount("retainedOrPeerProtected");
        var candidate = Amount("potentialReclaimUpperBound");
        Require(referenced <= union && live <= referenced && absent == referenced - live && other <= referenced &&
            unique <= referenced - live && unique <= referenced - other &&
            unique >= (referenced - live > other ? referenced - live - other : 0) && protectedBlocks <= referenced &&
            candidate <= unique && candidate <= referenced - protectedBlocks &&
            candidate >= (unique > protectedBlocks ? unique - protectedBlocks : 0));
        return (referenced, other);
    }
}
