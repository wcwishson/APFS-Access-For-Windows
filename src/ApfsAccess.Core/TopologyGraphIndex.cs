namespace ApfsAccess.Core;

public sealed class TopologyGraphIndex
{
    public const int Limit = 4096;
    public Dictionary<string, ApfsStoreRecord> Stores { get; } = new(StringComparer.Ordinal);
    public bool Complete { get; private set; } = true;

    public static TopologyGraphIndex? Create(ApfsTopologySnapshot? t)
    {
        if (t is null) return null;
        if (t.Disks is null || t.Partitions is null || t.Stores is null || t.Containers is null || t.Volumes is null || t.Groups is null ||
            (long)t.Disks.Count + t.Partitions.Count + t.Stores.Count + t.Containers.Count + t.Volumes.Count + t.Groups.Count > Limit) return null;
        var index = new TopologyGraphIndex();
        var ids = new Dictionary<string, int>(StringComparer.Ordinal);
        string[] prefixes = ["apfs-disk:", "apfs-part:", "apfs-store:", "apfs-container:", "apfs-vol:", "apfs-group:"];
        bool Add(string? id, int kind) => Text(id) && id!.StartsWith(prefixes[kind], StringComparison.Ordinal) && ids.TryAdd(id, kind);
        bool Edge(string? id, int kind)
        {
            if (!Text(id)) return false;
            if (ids.TryGetValue(id!, out var actual)) return actual == kind;
            index.Complete = false;
            return true;
        }
        int edges = 0;
        bool List(IReadOnlyList<string>? list) => list is not null && list.Count <= Limit &&
            (edges += list.Count) <= Limit * 8 && list.All(Text) && list.Distinct(StringComparer.Ordinal).Count() == list.Count;
        foreach (var d in t.Disks) if (d is null || !Add(d.Id, 0) || !Text(d.DeviceIdentifier)) return null;
        foreach (var p in t.Partitions) if (p is null || !Add(p.Id, 1)) return null;
        foreach (var s in t.Stores) { if (s is null || !Add(s.Id, 2)) return null; index.Stores.Add(s.Id, s); }
        foreach (var c in t.Containers) if (c is null || !Add(c.Id, 3) || !List(c.StoreIds) || !List(c.VolumeIds) ||
            !List(c.CompatibleFeatureBits) || !List(c.UnknownFeatureBits) || !List(c.IncompatibleFeatureBits) ||
            !List(c.ReadonlyFeatureBits ?? [])) return null;
        foreach (var v in t.Volumes) if (v is null || !Add(v.Id, 4) || !Text(v.Name) ||
            !List(v.Roles) || !List(v.CompatibleFeatureBits) || !List(v.UnknownFeatureBits) ||
            !List(v.IncompatibleFeatureBits) || !List(v.ReadonlyFeatureBits ?? [])) return null;
        foreach (var g in t.Groups) if (g is null || !Add(g.Id, 5) || !List(g.VolumeIds)) return null;
        var containers = t.Containers.ToDictionary(c => c.Id, StringComparer.Ordinal);
        var volumes = t.Volumes.ToDictionary(v => v.Id, StringComparer.Ordinal);
        foreach (var p in t.Partitions) if (!Edge(p.DiskId, 0)) return null;
        foreach (var s in t.Stores)
        {
            if (string.IsNullOrEmpty(s.PartitionId) && s.DiskId is null) index.Complete = false;
            if ((!string.IsNullOrEmpty(s.PartitionId) && !Edge(s.PartitionId, 1)) ||
                (s.DiskId is not null && (!string.IsNullOrEmpty(s.PartitionId) || !Edge(s.DiskId, 0))) || !Edge(s.ContainerId, 3)) return null;
            if (!containers.TryGetValue(s.ContainerId, out var c) || !c.StoreIds.Contains(s.Id, StringComparer.Ordinal)) index.Complete = false;
        }
        foreach (var c in t.Containers)
        {
            if (c.StoreIds.Count == 0) index.Complete = false;
            foreach (var id in c.StoreIds)
            {
                if (!Edge(id, 2)) return null;
                if (index.Stores.TryGetValue(id, out var s) && s.ContainerId != c.Id) return null;
            }
            foreach (var id in c.VolumeIds)
            {
                if (!Edge(id, 4)) return null;
                if (volumes.TryGetValue(id, out var v) && v.ContainerId != c.Id) return null;
            }
        }
        foreach (var v in t.Volumes)
        {
            if (!Edge(v.ContainerId, 3)) return null;
            if (!containers.TryGetValue(v.ContainerId, out var c) || !c.VolumeIds.Contains(v.Id, StringComparer.Ordinal)) index.Complete = false;
        }
        var groups = t.Groups.ToDictionary(g => g.Id, StringComparer.Ordinal);
        foreach (var g in t.Groups)
        {
            if (!Edge(g.ContainerId, 3) || g.VolumeIds.Count == 0 || !Guid.TryParse(g.Uuid, out var groupUuid) || groupUuid == Guid.Empty) return null;
            if (g.AssociationStatus is "ambiguous" or "malformed") return null;
            if (g.AssociationStatus == "incomplete") index.Complete = false;
            if (g.AssociationStatus is not (null or "incomplete" or "valid-system-data")) return null;
            if (g.AssociationStatus == "valid-system-data" && (g.SystemVolumeId is null || g.DataVolumeId is null ||
                g.SystemVolumeId == g.DataVolumeId || g.VolumeIds.Count != 2)) return null;
            foreach (var id in g.VolumeIds)
                if (!Edge(id, 4) || !volumes.TryGetValue(id, out var member) || member.GroupId != g.Id ||
                    member.ContainerId != g.ContainerId || member.GroupMetadataValid == false ||
                    member.GroupAssociationStatus != g.AssociationStatus ||
                    (g.AssociationStatus is not null && member.GroupMetadataValid != true) || !Guid.TryParse(member.GroupUuid, out var uuid) || uuid != groupUuid) return null;
            foreach (var id in new[] { g.SystemVolumeId, g.DataVolumeId }.Where(id => id is not null))
                if (!g.VolumeIds.Contains(id!, StringComparer.Ordinal)) return null;
            if (g.SystemVolumeId is {} system && !volumes[system].Roles.Contains("system", StringComparer.Ordinal)) return null;
            if (g.DataVolumeId is {} data && !volumes[data].Roles.Contains("data", StringComparer.Ordinal)) return null;
        }
        foreach (var v in t.Volumes)
            if (v.GroupId is {} id && (!groups.TryGetValue(id, out var group) || group.ContainerId != v.ContainerId ||
                !group.VolumeIds.Contains(v.Id, StringComparer.Ordinal)) || v.GroupId is null && v.GroupUuid is not null) return null;
        return index;
    }

    public static bool Text(string? value) => !string.IsNullOrWhiteSpace(value) && value.Length <= 4096;
}

