using System.Text;
using System.Text.Json;

namespace ApfsAccess.Backend.Native;

public sealed record ApfsMarkedOwnerSpaceRequest(ApfsSnapshotAttributionRequest Endpoint, string? FromXid = null);
public sealed record ApfsMarkedOwnerSpaceResult(int NativeExitCode, bool Complete, JsonElement Report);

public sealed partial class NativeApfsImageVerifier
{
    public static void ValidateMarkedOwnerSpaceRequest(ApfsMarkedOwnerSpaceRequest request)
    {
        ArgumentNullException.ThrowIfNull(request); ValidateSnapshotAttributionRequest(request.Endpoint);
        if (request.FromXid is not null && (!NativeApfsSnapshotReader.IsU64(request.FromXid, false) ||
            ulong.Parse(request.FromXid, System.Globalization.CultureInfo.InvariantCulture) >=
            ulong.Parse(request.Endpoint.CheckpointXid, System.Globalization.CultureInfo.InvariantCulture)))
            throw new ArgumentException("Use a canonical earlier retained checkpoint XID.");
    }

    public ApfsMarkedOwnerSpaceResult ObserveMarkedOwnerSpace(ApfsMarkedOwnerSpaceRequest request, CancellationToken token = default)
    {
        ValidateMarkedOwnerSpaceRequest(request); token.ThrowIfCancellationRequested();
        if (observerPath is null) throw new FileNotFoundException("The packaged marked-owner observer is unavailable.");
        NativeApfsSnapshotReader.ValidateLocalFile(observerPath); var q = request.Endpoint;
        using var held = File.OpenHandle(q.Image, FileMode.Open, FileAccess.Read, FileShare.Read);
        NativeApfsSnapshotReader.ValidateIdentity(held, q.Image); var identity = ReadIdentity(held);
        var args = new List<string> { "--mode", "marked-owner-space", "--image", q.Image, "--container-uuid", q.ContainerId[15..],
            "--volume-uuid", q.VolumeUuid, "--volume-oid", q.VolumeOid, "--checkpoint-xid", q.CheckpointXid,
            "--store-offset-bytes", q.StoreOffsetBytes, "--store-size-bytes", q.StoreSizeBytes };
        if (request.FromXid is not null) args.AddRange(["--retained-from-xid", request.FromXid]);
        var wire = runner.Run(observerPath, args.ToArray(), token); token.ThrowIfCancellationRequested();
        if (wire.ExitCode is not (0 or 3)) throw new NativeVerificationExitException(wire.ExitCode, wire.StandardError);
        var result = ParseMarkedOwnerSpace(wire.StandardOutput, wire.ExitCode, request, identity, token);
        NativeApfsSnapshotReader.ValidateIdentity(held, q.Image);
        if (identity != ReadIdentity(held)) throw new InvalidDataException("Marked-owner source changed during accounting.");
        token.ThrowIfCancellationRequested(); return result;
    }

    internal static ApfsMarkedOwnerSpaceResult ParseMarkedOwnerSpace(string json, int exit,
        ApfsMarkedOwnerSpaceRequest request, string identity, CancellationToken token = default)
    {
        try
        {
            token.ThrowIfCancellationRequested(); Require(Encoding.UTF8.GetByteCount(json) <= MaxReportBytes);
            using var document = JsonDocument.Parse(json); var root = document.RootElement; var complete = Bool(root, "complete");
            Require(Text(root, "format") == "apfs-access-marked-owner-space-attribution" && root.GetProperty("version").GetInt32() == 1 &&
                Bool(root, "readOnly") && exit == (complete ? 0 : 3));
            var from = root.GetProperty("fromXid"); Require(request.FromXid is null ? from.ValueKind == JsonValueKind.Null : from.GetString() == request.FromXid);
            if (!complete)
            {
                Object(root, "format version readOnly complete fromXid source scope reason");
                var source = root.GetProperty("source"); Object(source, "path identity");
                Require(Text(source, "path") == request.Endpoint.Image && Text(source, "identity") == identity);
                Object(root.GetProperty("scope"), "containerUuid volumeUuid volumeOid checkpointXid storeOffsetBytes storeSizeBytes");
                Exact(root.GetProperty("scope"), request.Endpoint.ExactScope);
                var reason = Text(root, "reason"); Require(reason.Length is > 0 and <= 65535 && !reason.Contains('\0'));
                return new(exit, false, root.Clone());
            }
            Object(root, "format version readOnly complete fromXid checkpointXids protectionScope hiddenOwnersComplete marked visibleMetadataUnion visiblePayloadUnion catalogMetadata catalogMetadataRanges protectedMetadataRanges protectedPayloadRanges views snapshotAllocationChargeBytes applePurgeableBytes reclaimableBytes");
            Require(Text(root, "protectionScope") == "explicit-retained-checkpoints-and-visible-peers" && !Bool(root, "hiddenOwnersComplete"));
            foreach (var key in new[] { "snapshotAllocationChargeBytes", "applePurgeableBytes", "reclaimableBytes" }) Require(root.GetProperty(key).ValueKind == JsonValueKind.Null);
            var marked = ParseMarkedReferenceSpace(root.GetProperty("marked").GetRawText(), 0, request.Endpoint, identity, token).Report;
            var unit = marked.GetProperty("allocationUnitBytes").GetUInt32();
            var capacity = Number(marked.GetProperty("scope"), "storeSizeBytes", false) / unit; var math = new ProfileSetMath(token);
            var xids = root.GetProperty("checkpointXids"); Require(xids.ValueKind == JsonValueKind.Array && xids.GetArrayLength() is > 0 and <= 1000000);
            ulong last = 0; var chain = new List<string>();
            foreach (var item in xids.EnumerateArray()) { math.Tick(); var xid = item.GetString()!; Require(NativeApfsSnapshotReader.IsU64(xid, false));
                var value = ulong.Parse(xid, System.Globalization.CultureInfo.InvariantCulture); Require(value > last); last = value; chain.Add(xid); }
            Require(chain[^1] == request.Endpoint.CheckpointXid && (request.FromXid is null ? chain.Count == 1 : chain.Count > 1 && chain[0] == request.FromXid));
            long rangeCount = 0;
            List<ProfileSpan> Ranges(JsonElement parent, string key)
            {
                var array = parent.GetProperty(key); Require(array.ValueKind == JsonValueKind.Array &&
                    (rangeCount += array.GetArrayLength()) <= 1000000); var output = new List<ProfileSpan>();
                foreach (var r in array.EnumerateArray()) { math.Tick(); Object(r, "physicalBlock blockCount");
                    var start = Number(r, "physicalBlock"); var count = Number(r, "blockCount", false);
                    Require(start < capacity && count <= capacity - start && (output.Count == 0 || start > output[^1].End)); output.Add(new(start, start + count)); }
                return output;
            }
            ulong Amount(JsonElement parent, string key) => AttributionAmount(parent.GetProperty(key), capacity, unit);
            var pm = Ranges(root, "protectedMetadataRanges"); var pp = Ranges(root, "protectedPayloadRanges");
            var external = math.Union(pm.Concat(pp)); var rows = root.GetProperty("views"); var markedRows = marked.GetProperty("views");
            var catalogMetadata = Ranges(root, "catalogMetadataRanges"); Require(catalogMetadata.Count > 0);
            Require(rows.ValueKind == JsonValueKind.Array && rows.GetArrayLength() == markedRows.GetArrayLength());
            var views = new List<(List<ProfileSpan> Metadata, List<ProfileSpan> Payload, List<ProfileSpan> Unmarked, List<ProfileSpan> Marked)>();
            var at = 0;
            foreach (var row in rows.EnumerateArray())
            {
                math.Tick(); Object(row, "metadataRanges payloadRanges unmarkedPayloadRanges metadata markedPayload sharedWithUnmarkedInView");
                var m = Ranges(row, "metadataRanges"); var p = Ranges(row, "payloadRanges"); var u = Ranges(row, "unmarkedPayloadRanges");
                var markedSet = Ranges(markedRows[at++], "filePayloadRanges"); Require(m.Count > 0);
                var union = math.Union(markedSet.Concat(u));
                Require(math.Difference(union, p).Count == 0 && math.Difference(p, union).Count == 0);
                views.Add((m,p,u,markedSet));
            }
            var allM = math.Union(views.SelectMany(v => v.Metadata)); var allP = math.Union(views.SelectMany(v => v.Payload));
            math.Disjoint(allM, allP); math.Disjoint(pm, pp); math.Disjoint(pm, allP); math.Disjoint(pp, allM);
            math.Disjoint(catalogMetadata, allP); math.Disjoint(catalogMetadata, pp);
            Require(math.Difference(allM, catalogMetadata).Count == 0 && Amount(root, "catalogMetadata") == math.Count(catalogMetadata));
            Require(Amount(root, "visibleMetadataUnion") == math.Count(allM) && Amount(root, "visiblePayloadUnion") == math.Count(allP));
            void Measures(JsonElement a, List<ProfileSpan> refs, List<ProfileSpan> current, List<ProfileSpan> other, List<ProfileSpan> sameUnmarked)
            {
                Object(a, "referenced sharedWithLive absentFromLive sharedWithOtherSnapshots uniqueInVisibleInventory retainedOrPeerProtected potentialReclaimUpperBound");
                var count = math.Count(refs); var absent = math.Count(math.Difference(refs, current));
                var unique = math.Difference(refs, math.Union(current.Concat(other).Concat(sameUnmarked)));
                Require(Amount(a, "referenced") == count && Amount(a, "sharedWithLive") == count - absent && Amount(a, "absentFromLive") == absent &&
                    Amount(a, "sharedWithOtherSnapshots") == count - math.Count(math.Difference(refs, other)) &&
                    Amount(a, "uniqueInVisibleInventory") == math.Count(unique) &&
                    Amount(a, "retainedOrPeerProtected") == count - math.Count(math.Difference(refs, external)) &&
                    Amount(a, "potentialReclaimUpperBound") == math.Count(math.Difference(unique, external)));
            }
            for (var i = 0; i < views.Count; ++i)
            {
                math.Tick(); var v = views[i]; var otherM = new List<ProfileSpan>(); var otherP = new List<ProfileSpan>();
                for (var j = 0; j + 1 < views.Count; ++j) { math.Tick(); if (j == i) continue;
                    math.Tick(views[j].Metadata.Count + views[j].Payload.Count); otherM.AddRange(views[j].Metadata); otherP.AddRange(views[j].Payload); }
                var current = i + 1 == views.Count;
                Measures(rows[i].GetProperty("metadata"), v.Metadata, current ? [] : views[^1].Metadata, math.Union(otherM), []);
                Measures(rows[i].GetProperty("markedPayload"), v.Marked, current ? v.Unmarked : views[^1].Payload, math.Union(otherP), v.Unmarked);
                Require(Amount(rows[i], "sharedWithUnmarkedInView") == math.Count(v.Marked) - math.Count(math.Difference(v.Marked, v.Unmarked)));
            }
            token.ThrowIfCancellationRequested(); return new(exit, true, root.Clone());
        }
        catch (Exception error) when (error is JsonException or KeyNotFoundException or InvalidOperationException or FormatException or OverflowException)
        { throw new InvalidDataException("Invalid marked-owner space document.", error); }
    }
}
