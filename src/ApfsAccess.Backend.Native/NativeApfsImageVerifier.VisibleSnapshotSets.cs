using System.Globalization;
using System.Text.Json;

namespace ApfsAccess.Backend.Native;

public sealed partial class NativeApfsImageVerifier
{
    private readonly record struct ProfileSpan(ulong Start, ulong End);
    private sealed record ProfileView(ulong Volume, ulong Xid, bool Current, string Name, JsonElement Descriptor,
        ulong DeclaredBlocks, List<ProfileSpan> Metadata, List<ProfileSpan> Payload);
    private sealed record ProfileCheckpoint(ulong Xid, List<ProfileSpan> Metadata, List<ProfileSpan> Payload, List<ProfileView> Views);

    // Bounded protocol arithmetic only. APFS parsing/admission stays native.
    private sealed class ProfileSetMath(CancellationToken token)
    {
        private long work;
        internal void Tick(long count = 1) { token.ThrowIfCancellationRequested(); Require(count >= 0 && (work = checked(work + count)) <= 1000000); }
        internal List<ProfileSpan> Union(IEnumerable<ProfileSpan> input)
        {
            var sorted = new List<ProfileSpan>(); foreach (var range in input) { Tick(); sorted.Add(range); }
            sorted.Sort((a, b) => { Require(++work <= 1000000); var order = a.Start.CompareTo(b.Start); return order == 0 ? a.End.CompareTo(b.End) : order; });
            token.ThrowIfCancellationRequested(); var result = new List<ProfileSpan>();
            foreach (var range in sorted) {
                Tick(); if (result.Count > 0 && range.Start <= result[^1].End)
                    result[^1] = new(result[^1].Start, Math.Max(result[^1].End, range.End));
                else result.Add(range);
            }
            return result;
        }
        internal List<ProfileSpan> Difference(List<ProfileSpan> left, List<ProfileSpan> right)
        {
            var result = new List<ProfileSpan>(); var j = 0;
            foreach (var range in left) {
                Tick(); var at = range.Start;
                while (j < right.Count && right[j].End <= at) { Tick(); ++j; }
                for (var k = j; k < right.Count && right[k].Start < range.End; ++k) {
                    Tick(); if (right[k].Start > at) result.Add(new(at, right[k].Start));
                    at = Math.Max(at, right[k].End); if (at >= range.End) break;
                }
                if (at < range.End) result.Add(new(at, range.End));
            }
            return result;
        }
        internal ulong Count(List<ProfileSpan> ranges) { ulong result = 0; foreach (var range in ranges) { Tick(); result = checked(result + range.End - range.Start); } return result; }
        internal void Disjoint(List<ProfileSpan> a, List<ProfileSpan> b)
        {
            var i = 0; var j = 0;
            while (i < a.Count && j < b.Count) { Tick(); if (a[i].End <= b[j].Start) ++i; else if (b[j].End <= a[i].Start) ++j; else Require(false); }
        }
    }

    private static void ValidateVisibleSnapshotSets(JsonElement root, ApfsVisibleSnapshotProfileRequest request,
        ulong[] sizes, ulong[] offsets, CancellationToken token)
    {
        var q = request.Endpoint; var math = new ProfileSetMath(token); var graph = root.GetProperty("graph");
        Object(graph, "allocationUnitBytes snapshotOwnerScope chainXids checkpoints");
        var bs = graph.GetProperty("allocationUnitBytes").GetUInt32();
        Require(bs >= 4096 && bs <= 65536 && (bs & (bs - 1)) == 0 && Text(graph, "snapshotOwnerScope") == "canonical-visible-inventories-and-explicit-parents" &&
            sizes.All(x => x % bs == 0) && offsets.All(x => x % bs == 0));
        var capacity = checked(sizes[0] / bs + (q.Fusion ? sizes[1] / bs : 0)); var tier = ProfileHistoryTier2ByteAddress / bs;
        bool Address(ulong start, ulong count = 1) => count > 0 && (start < sizes[0] / bs ? count <= sizes[0] / bs - start :
            q.Fusion && start >= tier && start - tier < sizes[1] / bs && count <= sizes[1] / bs - (start - tier));
        long rangeCount = 0;
        List<ProfileSpan> Ranges(JsonElement parent, string name, bool nonempty = false)
        {
            var input = parent.GetProperty(name); Require(input.ValueKind == JsonValueKind.Array && (!nonempty || input.GetArrayLength() > 0));
            rangeCount += input.GetArrayLength(); Require(rangeCount <= 1000000); var result = new List<ProfileSpan>();
            foreach (var range in input.EnumerateArray()) {
                math.Tick(); Object(range, "physicalBlock blockCount"); var start = Number(range, "physicalBlock"); var count = Number(range, "blockCount", false);
                Require(Address(start, count) && (result.Count == 0 || start > result[^1].End)); result.Add(new(start, checked(start + count)));
            }
            return result;
        }
        ulong Amount(JsonElement parent, string name)
        {
            var value = parent.GetProperty(name); Object(value, "blocks bytes"); var blocks = Number(value, "blocks");
            Require(blocks <= capacity && Number(value, "bytes") == checked(blocks * bs)); return blocks;
        }
        JsonElement Descriptor(JsonElement parent, ulong volume, ulong xid, ulong parentXid, bool current)
        {
            var value = parent.GetProperty("descriptor"); Object(value, "objectId xid physicalBlock");
            var oid = Number(value, "objectId", false); var generation = Number(value, "xid", false); var physical = Number(value, "physicalBlock", false);
            Require(Address(physical) && generation <= parentXid && (current ? oid == volume : oid == physical && generation >= xid)); return value;
        }
        var selected = root.GetProperty("selected");
        Object(selected, "containerUuid volumeUuid volumeOid checkpointXid storeOffsetBytes storeSizeBytes checkpointPhysicalBlock volumeSuperblockPhysicalBlock volumeSuperblockXid rootOid rootPhysicalBlock");
        Exact(selected, q.WireScope);
        Require(Number(selected, "checkpointPhysicalBlock", false) < sizes[0] / bs && Address(Number(selected, "volumeSuperblockPhysicalBlock", false)) &&
            Address(Number(selected, "rootPhysicalBlock", false)) && Number(selected, "rootOid", false) > 0 &&
            Number(selected, "volumeSuperblockXid", false) <= ulong.Parse(q.CheckpointXid, CultureInfo.InvariantCulture));
        var chain = graph.GetProperty("chainXids"); var parents = graph.GetProperty("checkpoints");
        Require(chain.ValueKind == JsonValueKind.Array && chain.GetArrayLength() is > 0 and <= 1000000 && parents.ValueKind == JsonValueKind.Array && parents.GetArrayLength() == chain.GetArrayLength() &&
            (request.FromXid is null ? chain.GetArrayLength() == 1 : chain.GetArrayLength() >= 2 && chain[0].GetString() == request.FromXid) && chain[chain.GetArrayLength() - 1].GetString() == q.CheckpointXid);
        var checkpoints = new List<ProfileCheckpoint>(); ulong previousXid = 0;
        foreach (var parent in parents.EnumerateArray()) {
            math.Tick(); Object(parent, "checkpointXid metadataRanges payloadRanges views");
            var xid = Number(parent, "checkpointXid", false); Require(xid > previousXid && chain[checkpoints.Count].GetString() == xid.ToString(CultureInfo.InvariantCulture)); previousXid = xid;
            var metadata = Ranges(parent, "metadataRanges", true); var payload = Ranges(parent, "payloadRanges");
            Require(math.Count(metadata) <= capacity && math.Count(payload) <= capacity - math.Count(metadata));
            var input = parent.GetProperty("views"); Require(input.ValueKind == JsonValueKind.Array && input.GetArrayLength() is > 0 and <= 1000000);
            var views = new List<ProfileView>(); ulong volume = 0, lastSnapshot = 0; var hadCurrent = false; var names = new HashSet<string>(StringComparer.Ordinal);
            var previousPeers = new List<ProfileSpan>(); var peerPayload = new List<ProfileSpan>();
            foreach (var value in input.EnumerateArray()) {
                math.Tick(); Object(value, "volumeOid viewXid current name descriptor declaredFilesystemAllocation filesystemRecordCount metadataRanges payloadRanges");
                var owner = Number(value, "volumeOid", false); var viewXid = Number(value, "viewXid", false); var current = Bool(value, "current"); var name = value.GetProperty("name").GetString();
                Require(owner >= volume && (q.Fusion || value.GetProperty("volumeOid").GetString() == q.VolumeOid));
                if (owner != volume) { Require(volume == 0 || hadCurrent); previousPeers = math.Union(previousPeers.Concat(peerPayload)); peerPayload = []; volume = owner; hadCurrent = false; lastSnapshot = 0; names.Clear(); }
                Require(!hadCurrent && viewXid <= xid && (current ? viewXid == xid && name == "" : viewXid > lastSnapshot && name is not null && names.Add(name)));
                if (!current) ProfileText(value, "name"); lastSnapshot = viewXid; hadCurrent = current;
                var descriptor = Descriptor(value, owner, viewXid, xid, current); var declared = Amount(value, "declaredFilesystemAllocation");
                var vm = Ranges(value, "metadataRanges", true); var vp = Ranges(value, "payloadRanges");
                Require(Number(value, "filesystemRecordCount", false) <= 1000000 && math.Difference(vm, metadata).Count == 0 && math.Difference(vp, payload).Count == 0 &&
                    math.Difference([new(Number(descriptor, "physicalBlock"), checked(Number(descriptor, "physicalBlock") + 1))], vm).Count == 0);
                math.Disjoint(previousPeers, vp); peerPayload = math.Union(peerPayload.Concat(vp));
                views.Add(new(owner, viewXid, current, name!, descriptor, declared, vm, vp));
            }
            Require(hadCurrent && math.Difference(payload, math.Union(views.SelectMany(v => v.Payload))).Count == 0);
            checkpoints.Add(new(xid, metadata, payload, views));
        }
        math.Disjoint(math.Union(checkpoints.SelectMany(cp => cp.Metadata)), math.Union(checkpoints.SelectMany(cp => cp.Payload)));
        var endpoint = checkpoints[^1]; var selectedVolume = ulong.Parse(q.VolumeOid, CultureInfo.InvariantCulture);
        var live = endpoint.Views.Single(v => v.Volume == selectedVolume && v.Current);
        Require(Number(live.Descriptor, "physicalBlock") == Number(selected, "volumeSuperblockPhysicalBlock") &&
            Number(live.Descriptor, "xid") == Number(selected, "volumeSuperblockXid") &&
            math.Difference([new(Number(selected, "rootPhysicalBlock"), checked(Number(selected, "rootPhysicalBlock") + 1))], live.Metadata).Count == 0 &&
            math.Difference([new(Number(selected, "checkpointPhysicalBlock"), checked(Number(selected, "checkpointPhysicalBlock") + 1))], endpoint.Metadata).Count == 0);
        var snapshots = endpoint.Views.Where(v => v.Volume == selectedVolume && !v.Current).ToArray();
        var external = math.Union(checkpoints.Take(checkpoints.Count - 1).SelectMany(cp => cp.Metadata.Concat(cp.Payload)).Concat(
            endpoint.Views.Where(v => v.Volume != selectedVolume).SelectMany(v => v.Metadata.Concat(v.Payload))));
        var attribution = root.GetProperty("attribution");
        Object(attribution, "protectionScope hiddenOwnersComplete liveMetadata livePayload referencedSnapshotMetadata referencedSnapshotPayload snapshots");
        Require(Text(attribution, "protectionScope") == "explicit-checkpoint-chain-and-visible-peers" && !Bool(attribution, "hiddenOwnersComplete") &&
            Amount(attribution, "liveMetadata") == math.Count(live.Metadata) && Amount(attribution, "livePayload") == math.Count(live.Payload) &&
            Amount(attribution, "referencedSnapshotMetadata") == math.Count(math.Union(snapshots.SelectMany(v => v.Metadata))) &&
            Amount(attribution, "referencedSnapshotPayload") == math.Count(math.Union(snapshots.SelectMany(v => v.Payload))));
        var rows = attribution.GetProperty("snapshots"); Require(rows.ValueKind == JsonValueKind.Array && rows.GetArrayLength() == snapshots.Length);
        void Measures(JsonElement row, string field, List<ProfileSpan> refs, List<ProfileSpan> current, List<ProfileSpan> other)
        {
            var a = row.GetProperty(field); Object(a, "referenced sharedWithLive absentFromLive sharedWithOtherSnapshots uniqueInVisibleInventory retainedOrPeerProtected potentialReclaimUpperBound");
            var count = math.Count(refs); var absent = math.Count(math.Difference(refs, current)); var unique = math.Difference(refs, math.Union(current.Concat(other)));
            Require(Amount(a, "referenced") == count && Amount(a, "sharedWithLive") == count - absent && Amount(a, "absentFromLive") == absent &&
                Amount(a, "sharedWithOtherSnapshots") == count - math.Count(math.Difference(refs, other)) && Amount(a, "uniqueInVisibleInventory") == math.Count(unique) &&
                Amount(a, "retainedOrPeerProtected") == count - math.Count(math.Difference(refs, external)) && Amount(a, "potentialReclaimUpperBound") == math.Count(math.Difference(unique, external)));
        }
        for (var i = 0; i < snapshots.Length; ++i) {
            math.Tick(); var row = rows[i]; var view = snapshots[i]; Object(row, "snapshotXid name descriptor declaredFilesystemAllocation metadata payload");
            Require(Number(row, "snapshotXid", false) == view.Xid && Text(row, "name") == view.Name && Amount(row, "declaredFilesystemAllocation") == view.DeclaredBlocks);
            var descriptor = Descriptor(row, view.Volume, view.Xid, endpoint.Xid, false);
            foreach (var field in new[] { "objectId", "xid", "physicalBlock" }) Require(Number(descriptor, field) == Number(view.Descriptor, field));
            var others = snapshots.Where((_, n) => n != i).ToArray();
            Measures(row, "metadata", view.Metadata, live.Metadata, math.Union(others.SelectMany(v => v.Metadata)));
            Measures(row, "payload", view.Payload, live.Payload, math.Union(others.SelectMany(v => v.Payload)));
        }
    }
}
