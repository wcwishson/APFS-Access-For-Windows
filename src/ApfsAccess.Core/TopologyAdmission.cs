using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace ApfsAccess.Core;

// Shared structural/row admission. Capability decisions still belong to the existing evaluator.
public static class TopologyAdmission
{
    public static bool Validate(DeviceInventory d)
    {
        if (d?.Device is null || !d.Device.IsConnected || d.Volumes is null || d.Volumes.Count > TopologyGraphIndex.Limit ||
            d.Volumes.Any(v => v is null || !string.Equals(v.DeviceId, d.Device.DeviceId, StringComparison.OrdinalIgnoreCase)) ||
            d.Volumes.Select(v => v.VolumeId).Distinct(StringComparer.OrdinalIgnoreCase).Count() != d.Volumes.Count) return false;
        if (d.Topology is null) return d.Volumes.All(v => v.BackupImageWrite is null);
        var o = d.Topology;
        var graph = TopologyGraphIndex.Create(o.Snapshot);
        if (graph is not { Complete: true } || o.Generation <= 0 || o.DeviceId != d.Device.DeviceId ||
            o.DiskIds is null || o.DiskIds.Count == 0 || o.DiskIds.Count > TopologyGraphIndex.Limit ||
            o.DiskIds.Distinct(StringComparer.Ordinal).Count() != o.DiskIds.Count ||
            o.DiskIds.Any(id => !o.Snapshot.Disks.Any(disk => disk.Id == id && string.Equals(disk.DeviceIdentifier, d.Device.DeviceId, StringComparison.OrdinalIgnoreCase)))) return false;
        if (o.Snapshot.Disks.Any(disk => disk.SizeBytes <= 0 || !ApfsTopology.TryParseDiskId(disk.Id, out _)) ||
            o.Snapshot.Partitions.Any(p => p.StartByte < 0 || p.SizeBytes <= 0 || p.Index <= 0 ||
                !ApfsTopology.TryParsePartitionId(p.Id, out var id) || !Guid.TryParse(p.Uuid, out var uuid) || id != uuid) ||
            o.Snapshot.Stores.Any(s => s.OffsetBytes < 0 || s.SizeBytes <= 0)) return false;
        var boundDiskIds = o.DiskIds.ToHashSet(StringComparer.Ordinal);
        var partitions = o.Snapshot.Partitions.ToDictionary(p => p.Id, StringComparer.Ordinal);
        foreach (var row in d.Volumes)
        {
            var v = o.Snapshot.Volumes.SingleOrDefault(v => v.Id == row.CatalogVolumeId);
            var c = v is null ? null : o.Snapshot.Containers.SingleOrDefault(c => c.Id == v.ContainerId);
            if (v is null || c is null || !SameUuid(row.CatalogVolumeUuid, v.Uuid) || !SameUuid(row.CatalogContainerUuid, c.Uuid) ||
                !ulong.TryParse(v.ObjectId, out var oid) || oid == 0 || oid != row.CatalogVolumeObjectId ||
                row.CatalogDecision is null || row.CatalogReasons is null || row.CatalogAutoMountAllowed is null ||
                !TopologyGraphIndex.Text(row.VolumeId) || !TopologyGraphIndex.Text(row.DeviceId) || row.CatalogReasons.Count > TopologyGraphIndex.Limit ||
                row.CatalogReasons.Any(r => !TopologyGraphIndex.Text(r))) return false;
            // A valid disk elsewhere in the graph cannot bind this row. Its
            // container must actually have a store on an advertised source disk.
            // Shared containers may also have stores on other member disks.
            if (!c.StoreIds.Any(id => {
                var store = graph.Stores[id];
                var diskId = string.IsNullOrEmpty(store.PartitionId) ? store.DiskId : partitions[store.PartitionId].DiskId;
                return diskId is not null && boundDiskIds.Contains(diskId);
            })) return false;
            if (!ApfsTopology.TryParseContainerId(c.Id, out var containerHex) || !Guid.TryParse(c.Uuid, out var containerUuid) ||
                containerUuid.ToString("N") != containerHex || !ApfsTopology.TryParseVolumeId(v.Id, out var volumeContainerHex, out var volumeOid) ||
                volumeContainerHex != containerHex || volumeOid != oid) return false;
            var capability = ApfsVolumeCapabilities.Evaluate(v, c);
            // Reject contradictory advertised permission; never replace row evidence with a more permissive verdict.
            var evidence = row with { CatalogDecision = capability.Decision, CatalogReasons = capability.Reasons, CatalogAutoMountAllowed = capability.AutoMountAllowed };
            if (row.BackupImageWrite is not null &&
                (BackupImageMountPolicy.Observe(evidence, o) != row.BackupImageWrite ||
                 !BackupImageMountPolicy.HasCandidate(row))) return false;
            if (CatalogMountPolicy.AllowsMount(row, false) && !CatalogMountPolicy.AllowsMount(evidence, false) ||
                CatalogMountPolicy.AllowsReadOnlyInspection(row) && !CatalogMountPolicy.AllowsMount(evidence, true)) return false;
        }
        return true;
    }

    public static bool SameUuid(string? a, string? b) => Guid.TryParse(a, out var x) && x != Guid.Empty && Guid.TryParse(b, out var y) && x == y;

    // A capability/ancestry observation, not a polling counter. A same-identity refresh
    // keeps this contract; any selected security evidence or member change invalidates it.
    public static string Contract(DeviceInventory d, VolumeInfo row)
    {
        if (!Validate(d) || d.Topology is null) throw new InvalidOperationException("Current topology evidence is unavailable.");
        var t = d.Topology.Snapshot;
        var v = t.Volumes.Single(v => v.Id == row.CatalogVolumeId);
        var c = t.Containers.Single(c => c.Id == v.ContainerId);
        var text = JsonSerializer.Serialize(new {
            row.DeviceId, row.VolumeId, row.RecoveryIdentity, row.CatalogVolumeUuid, row.CatalogContainerUuid, row.CatalogVolumeObjectId,
            row.CatalogDecision, row.CatalogAutoMountAllowed, Reasons = row.CatalogReasons!.Order(StringComparer.Ordinal).ToArray(), row.SupportsExplorerMount, row.SupportsReadWrite, row.SupportsNativeWrite, row.IsEncrypted,
            row.BackupImageWrite,
            Volume = new { v.Id, v.ContainerId, v.GroupId, v.GroupUuid, v.GroupMetadataValid, v.GroupAssociationStatus, v.CaseMode, v.EncryptionMode, v.Locked,
                Roles = v.Roles.Order(StringComparer.Ordinal).ToArray(), Compatible = v.CompatibleFeatureBits.Order(StringComparer.Ordinal).ToArray(), Unknown = v.UnknownFeatureBits.Order(StringComparer.Ordinal).ToArray(),
                Incompatible = v.IncompatibleFeatureBits.Order(StringComparer.Ordinal).ToArray(), Readonly = (v.ReadonlyFeatureBits ?? []).Order(StringComparer.Ordinal).ToArray() },
            Container = new { c.Id, c.Uuid, c.Fusion, Members = c.StoreIds.Order(StringComparer.Ordinal).ToArray(),
                Compatible = c.CompatibleFeatureBits.Order(StringComparer.Ordinal).ToArray(), Unknown = c.UnknownFeatureBits.Order(StringComparer.Ordinal).ToArray(),
                Incompatible = c.IncompatibleFeatureBits.Order(StringComparer.Ordinal).ToArray(), Readonly = (c.ReadonlyFeatureBits ?? []).Order(StringComparer.Ordinal).ToArray() },
            Stores = t.Stores.Where(s => c.StoreIds.Contains(s.Id)).OrderBy(s => s.Id, StringComparer.Ordinal).ToArray(),
            Partitions = t.Partitions.OrderBy(p => p.Id, StringComparer.Ordinal).ToArray(), Disks = t.Disks.OrderBy(d => d.Id, StringComparer.Ordinal).ToArray(),
            Groups = t.Groups.Where(g => g.Id == v.GroupId).OrderBy(g => g.Id, StringComparer.Ordinal).Select(g => new { g.Id, g.Uuid, g.ContainerId, g.AssociationStatus, g.SystemVolumeId, g.DataVolumeId, Members = g.VolumeIds.Order(StringComparer.Ordinal).ToArray() }).ToArray()
        });
        return "selected-v1:" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text))).ToLowerInvariant();
    }
}
