using System.Globalization;
using System.Diagnostics.CodeAnalysis;
using System.Numerics;
using System.Text.Json;
using ApfsAccess.Core;

namespace ApfsAccess.Backend.Native;

// Validates the observer's structured claims; never reads APFS bytes, derives
// role flags, or produces a replacement space calculation for consumers.
internal static class ObserverTopologyMetadataValidation
{
    private static readonly string[] VolumeFields = ["roleName", "groupUuid", "groupMetadataValid", "groupAssociationStatus"];
    private static readonly string[] GroupFields = ["containerId", "associationStatus", "systemVolumeId", "dataVolumeId"];

    internal static void ValidateShape(string json)
    {
        using var document = JsonDocument.Parse(json);
        var root = document.RootElement;
        RejectDuplicateProperties(root);
        var extended = root.TryGetProperty("topologyMetadataVersion", out var version);
        Require(!extended || (version.ValueKind == JsonValueKind.Number && version.TryGetInt32(out var n) &&
            n == ApfsTopology.TopologyMetadataVersion), "unsupported topologyMetadataVersion");
        if (!root.TryGetProperty("topology", out var topology)) return; // envelope validator handles absence
        CheckFields(topology, "containers", ["sharedSpace"], extended);
        CheckFields(topology, "volumes", VolumeFields, extended);
        CheckFields(topology, "groups", GroupFields, extended);
        if (topology.TryGetProperty("volumes", out var volumes) && volumes.ValueKind == JsonValueKind.Array)
            foreach (var volume in volumes.EnumerateArray())
                Require(volume.TryGetProperty("roleRaw", out _), "missing required roleRaw");
        if (topology.TryGetProperty("stores", out var stores) && stores.ValueKind == JsonValueKind.Array)
            foreach (var store in stores.EnumerateArray())
                foreach (var field in new[] { "blockSizeBytes", "totalBlocks" })
                    if (store.ValueKind == JsonValueKind.Object && store.TryGetProperty(field, out var value))
                        Require(value.ValueKind == JsonValueKind.Number && value.TryGetUInt64(out _), "malformed store geometry");
    }

    private static void CheckFields(JsonElement topology, string collection, string[] fields, bool extended)
    {
        if (!topology.TryGetProperty(collection, out var items) || items.ValueKind != JsonValueKind.Array) return;
        foreach (var item in items.EnumerateArray())
        {
            Require(item.ValueKind == JsonValueKind.Object, "invalid topology record");
            foreach (var field in fields)
                Require(item.TryGetProperty(field, out _) == extended,
                    "partial or unversioned topology metadata: " + field);
        }
    }

    private static void RejectDuplicateProperties(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var p in element.EnumerateObject())
            {
                Require(names.Add(p.Name), "duplicate JSON property: " + p.Name);
                RejectDuplicateProperties(p.Value);
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
            foreach (var item in element.EnumerateArray()) RejectDuplicateProperties(item);
    }

    internal static void Validate(ApfsObserverEvidence evidence)
    {
        var t = evidence.Topology;
        var extended = evidence.TopologyMetadataVersion.HasValue;
        var volumes = t.Volumes.ToDictionary(v => v.Id, StringComparer.Ordinal);
        var groups = new Dictionary<(string Container, string Group), ApfsGroupRecord>();
        var assignments = new HashSet<string>(StringComparer.Ordinal);
        foreach (var group in t.Groups)
        {
            Require(group is not null && ApfsTopology.TryParseGroupId(group.Id, out var uuid) &&
                uuid == group.Uuid && group.Uuid != new string('0', 32) && group.VolumeIds is not null &&
                group.VolumeIds.Count >= 2 && group.VolumeIds.Distinct(StringComparer.Ordinal).Count() == group.VolumeIds.Count,
                "invalid group identity or membership");
            var members = group!.VolumeIds.Select(id => id is not null && volumes.TryGetValue(id, out var v)
                ? v : throw Invalid("dangling group member")).ToArray();
            var container = members[0].ContainerId;
            Require(members.All(v => v.ContainerId == container && v.GroupId == group.Id && assignments.Add(v.Id)),
                "cross-container, duplicate or nonreciprocal group assignment");
            Require(groups.TryAdd((container, group.Id), group), "duplicate container/group assignment");
            if (extended) Require(group.ContainerId == container, "wrong group container");
        }
        foreach (var v in t.Volumes)
        {
            // v1 historically also used an empty string for no emitted group.
            if (v.GroupId is not null && (extended || v.GroupId.Length != 0))
                Require(groups.TryGetValue((v.ContainerId, v.GroupId), out var g) && g.VolumeIds.Contains(v.Id),
                    "dangling or nonreciprocal volume group");
        }
        if (!extended) return; // Legacy has no verified association targets or space claims.

        foreach (var container in t.Containers)
        {
            Require(t.Stores.Where(s => s.ContainerId == container.Id).All(s => s.Uuid == container.Uuid),
                "store/container UUID mismatch");
            foreach (var store in t.Stores.Where(s => s.ContainerId == container.Id))
            {
                Require(store.BlockSizeBytes is null || store.BlockSizeBytes == container.BlockSizeBytes, "store block size mismatch");
                if (store.TotalBlocks is { } total)
                    Require(total != 0 && new BigInteger(total) * container.BlockSizeBytes <= store.SizeBytes &&
                        (container.SharedSpace is null || container.SharedSpace.Total?.Blocks == total), "store total blocks mismatch");
            }
            var members = t.Volumes.Where(v => v.ContainerId == container.Id).ToArray();
            var xid = U64(container.CheckpointXid);
            Require(xid != 0, "zero checkpoint identity");
            var uuids = new HashSet<string>(StringComparer.Ordinal);
            foreach (var v in members)
            {
                Require(U64(v.SuperblockXid) is var vx && vx != 0 && vx <= xid, "volume checkpoint outside container checkpoint");
                Require(v.Uuid.Length == 0 || (v.Uuid != new string('0', 32) && uuids.Add(v.Uuid)), "duplicate or zero volume UUID");
                ValidateRole(v);
                Require(v.GroupUuid is null || (ApfsTopology.TryParseGroupId("apfs-group:" + v.GroupUuid, out _) &&
                    v.GroupUuid != new string('0', 32)), "invalid group UUID");
                // Feature tokens are already decoded by native code. Check the
                // claimed relationship against that evidence; no bit masking.
                var metadataValid = v.CompatibleFeatureBits.Contains("0x10") == (v.GroupUuid is not null) &&
                    (v.GroupUuid is null || v.RoleName is "system" or "data");
                Require(v.GroupMetadataValid == metadataValid, "contradictory group metadata validity");
                if (v.GroupUuid is null)
                    Require(v.GroupId is null && v.GroupAssociationStatus == (metadataValid ? "none" : "malformed"),
                        "ungrouped volume claims an association");
            }
            foreach (var set in members.Where(v => v.GroupUuid is not null).GroupBy(v => v.GroupUuid!))
            {
                var grouped = set.ToArray();
                var system = grouped.Where(v => v.RoleName == "system").ToArray();
                var data = grouped.Where(v => v.RoleName == "data").ToArray();
                var status = grouped.Any(v => v.GroupMetadataValid != true || v.Uuid.Length == 0) ? "malformed" :
                    system.Length > 1 || data.Length > 1 ? "ambiguous" :
                    system.Length == 1 && data.Length == 1 ? "valid-system-data" : "incomplete";
                Require(grouped.All(v => v.GroupAssociationStatus == status), "false group association status");
                var id = "apfs-group:" + set.Key;
                if (grouped.Length == 1)
                {
                    Require(grouped[0].GroupId is null && !groups.ContainsKey((container.Id, id)), "singleton group must not route");
                    continue;
                }
                Require(groups.TryGetValue((container.Id, id), out var g) &&
                    g.VolumeIds.ToHashSet(StringComparer.Ordinal).SetEquals(grouped.Select(v => v.Id)), "missing or incomplete group assignment");
                Require(g!.AssociationStatus == status, "false group status");
                Require(g.SystemVolumeId == (status == "valid-system-data" ? system[0].Id : null) &&
                    g.DataVolumeId == (status == "valid-system-data" ? data[0].Id : null), "false System/Data targets");
            }
            if (container.SharedSpace is { } space) ValidateSpace(t, container, space);
        }
    }

    private static void ValidateRole(ApfsVolumeRecord v)
    {
        // Exact wire enum consistency only. Never decompose roleRaw as flags or
        // infer a role when the native roleName extension is absent.
        long? declaredRaw = v.RoleName switch
        {
            "none" => 0, "system" => 1, "user" => 2, "recovery" => 4, "vm" => 8,
            "preboot" => 16, "installer" => 32, "data" => 64, "baseband" => 128,
            "update" => 192, "xart" => 256, "hardware" => 320, "backup" => 384,
            "enterprise" => 576, "prelogin" => 704, "unknown" => null,
            _ => throw Invalid("invalid exact role name"),
        };
        Require(v.RoleRaw is >= 0 and <= ushort.MaxValue &&
            (declaredRaw.HasValue ? v.RoleRaw == declaredRaw :
                v.RoleRaw is not (0 or 1 or 2 or 4 or 8 or 16 or 32 or 64 or 128 or 192 or 256 or 320 or 384 or 576 or 704)),
            "contradictory role name/raw enum");
        Require(v.Roles.Count == 1 && v.Roles[0] == (v.RoleName == "none" ? "data" : v.RoleName), "contradictory role category");
    }

    private static void ValidateSpace(ApfsTopologySnapshot t, ApfsContainerRecord c, ApfsSharedSpaceProjection s)
    {
        Require(!c.Fusion && c.StoreIds.Count == 1 && s.ContainerId == c.Id &&
            s.CheckpointXid == U64(c.CheckpointXid) && s.AllocationUnitBytes == c.BlockSizeBytes &&
            s.AllocationUnitBytes is 4096 or 8192 or 16384 or 32768 or 65536, "unverified shared-space identity or geometry");
        Amount(s.Total, s.AllocationUnitBytes); Amount(s.Free, s.AllocationUnitBytes); Amount(s.Used, s.AllocationUnitBytes);
        Require(s.Total.Blocks != 0 && s.Free.Blocks <= s.Total.Blocks && s.Used.Blocks == s.Total.Blocks - s.Free.Blocks &&
            s.Total.Bytes <= (ulong)t.Stores.Single(store => store.Id == c.StoreIds[0]).SizeBytes, "impossible container space");
        Require(s.Volumes is not null && s.Volumes.All(v => v is not null && v.VolumeId is not null) &&
            s.Volumes.Select(v => v.VolumeId).Distinct(StringComparer.Ordinal).Count() == s.Volumes.Count &&
            c.VolumeIds.ToHashSet(StringComparer.Ordinal).SetEquals(s.Volumes.Select(v => v.VolumeId)), "shared-space volume set mismatch");
        BigInteger unmet = 0;
        foreach (var v in s.Volumes!)
        {
            Require(ApfsTopology.TryParseVolumeId(v.VolumeId, out var hex, out var oid) && hex == c.Uuid && oid == v.ObjectId,
                "shared-space volume identity mismatch");
            Amount(v.Allocated, s.AllocationUnitBytes); Amount(v.Available, s.AllocationUnitBytes);
            Amount(v.SiblingReserveRemaining, s.AllocationUnitBytes);
            if (v.Reserve is { } reserve) { Amount(reserve, s.AllocationUnitBytes); Require(reserve.Blocks != 0 && reserve.Blocks <= s.Total.Blocks, "invalid reserve"); }
            if (v.Quota is { } quota) { Amount(quota, s.AllocationUnitBytes); Require(quota.Blocks != 0, "zero quota must be unset"); }
            Require(v.Allocated.Blocks <= s.Used.Blocks && (v.Quota is null || (v.Reserve?.Blocks ?? 0) <= v.Quota.Blocks) &&
                v.Snapshot is null && v.Purgeable is null, "invalid or unsupported volume counters");
            unmet += Unmet(v);
        }
        Require(unmet <= s.Free.Blocks, "reserves exceed shared free space");
        foreach (var v in s.Volumes!)
        {
            var siblings = unmet - Unmet(v);
            var available = new BigInteger(s.Free.Blocks) - siblings;
            if (v.Quota is { } quota) available = BigInteger.Min(available, BigInteger.Max(0, new BigInteger(quota.Blocks) - v.Allocated.Blocks));
            Require(v.SiblingReserveRemaining.Blocks == siblings && v.Available.Blocks == available, "contradictory shared availability");
        }
    }

    private static BigInteger Unmet(ApfsVolumeSpaceProjection v)
        => BigInteger.Max(0, new BigInteger(v.Reserve?.Blocks ?? 0) - v.Allocated.Blocks);
    private static void Amount(ApfsSpaceAmount? a, uint unit)
        => Require(a is not null && new BigInteger(a.Blocks) * unit == a.Bytes, "missing, overflowing or inconsistent space amount");
    private static ulong U64(string text) => ulong.Parse(text, NumberStyles.None, CultureInfo.InvariantCulture);
    private static InvalidOperationException Invalid(string message) => new("ApfsObserver.exe emitted invalid topology metadata: " + message);
    private static void Require([DoesNotReturnIf(false)] bool condition, string message) { if (!condition) throw Invalid(message); }
}
