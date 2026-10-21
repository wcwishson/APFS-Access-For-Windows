using ApfsAccess.Core;
using ApfsAccess.Ipc;

namespace ApfsAccess.Tray;

// IPC is a trust boundary even when its usual producer validates observer evidence.
// Typed edges bound the depth; missing edges are visible but cannot authorize actions.
internal static class TopologyStatusProjection
{
    internal static DriveDashboardRow DisableActions(DriveDashboardRow r) => r with
    {
        CanOpen = false, CanEject = false, CanFix = false, CanInspectReadOnly = false, CanMountBackupReadWrite = false,
        CanVerifyOffline = false, CanVerifyLive = false, CanManageOffline = false,
        CanMutateSnapshots = false, CanRecoverSnapshots = false, CanManageTopologyImage = false, CanResizeFormatImage = false, CanListSnapshots = false,
        DriveLetterPreference = null
    };

    internal static bool IsBounded(StatusChangedPayload s)
    {
        var count = s.MountedVolumes?.Count ?? 0;
        if (count > TopologyGraphIndex.Limit || s.ConnectedInventory?.Count > TopologyGraphIndex.Limit) return false;
        if (s.MountedVolumes?.Any(v => v is null || !TopologyGraphIndex.Text(v.VolumeId)) == true) return false;
        long graphCount = 0;
        foreach (var d in s.ConnectedInventory ?? [])
        {
            if (d?.Device is null || d.Volumes is null || !TopologyGraphIndex.Text(d.Device.DeviceId) ||
                (count += d.Volumes.Count) > TopologyGraphIndex.Limit ||
                d.Volumes.Any(v => v is null || !TopologyGraphIndex.Text(v.VolumeId) || !TopologyGraphIndex.Text(v.DeviceId))) return false;
            if (d.Topology?.Snapshot is {} t)
            {
                graphCount += (long)(t.Disks?.Count ?? 0) + (t.Partitions?.Count ?? 0) + (t.Stores?.Count ?? 0) +
                    (t.Containers?.Count ?? 0) + (t.Volumes?.Count ?? 0) + (t.Groups?.Count ?? 0);
                if (graphCount > TopologyGraphIndex.Limit) return false;
            }
        }
        return true;
    }

    internal static bool Matches(MountedVolumeDisplay m, VolumeInfo v, bool requireUuid) =>
        string.Equals(m.DeviceId, v.DeviceId, StringComparison.OrdinalIgnoreCase) &&
        string.Equals(m.VolumeId, v.VolumeId, StringComparison.Ordinal) &&
        string.Equals(m.CatalogVolumeId, v.CatalogVolumeId, StringComparison.Ordinal) &&
        string.Equals(m.CatalogContainerUuid, v.CatalogContainerUuid, StringComparison.OrdinalIgnoreCase) &&
        m.CatalogVolumeObjectId == v.CatalogVolumeObjectId &&
        (!requireUuid || string.Equals(m.CatalogVolumeUuid, v.CatalogVolumeUuid, StringComparison.OrdinalIgnoreCase)) &&
        (requireUuid ? m.RecoveryIdentity == v.RecoveryIdentity : m.RecoveryIdentity is null || v.RecoveryIdentity is null || m.RecoveryIdentity == v.RecoveryIdentity);

    internal static IReadOnlyList<TopologyDashboardNode> Project(StatusChangedPayload status)
    {
        var result = new List<TopologyDashboardNode>();
        var inventory = status.ConnectedInventory ?? [];
        var mounts = status.MountedVolumes ?? [];
        var targetCounts = inventory.SelectMany(d => d.Volumes).ToLookup(v => v.VolumeId, StringComparer.OrdinalIgnoreCase);
        var surfaceRows = DriveDashboardPresenter.BuildRows(status).ToLookup(DriveDashboardPresenter.RowIdentity, StringComparer.Ordinal);
        var assigned = new HashSet<MountedVolumeDisplay>();
        var buckets = inventory.GroupBy(d => d.Device.DeviceId, StringComparer.OrdinalIgnoreCase);
        foreach (var bucket in buckets)
        {
            var d = bucket.First();
            // Scope node keys, not catalog IDs, because each raw disk may use apfs-store:raw.
            string Key(string id) => System.Text.Json.JsonSerializer.Serialize(new[] { d.Device.DeviceId, id });
            var observation = d.Topology;
            var graph = TopologyGraphIndex.Create(observation?.Snapshot);
            if (bucket.Count() != 1 || !TopologyAdmission.Validate(d) || !d.Device.IsConnected || (observation is not null &&
                (status.InventoryGeneration is not > 0 || observation.Generation <= 0 || observation.DeviceId != d.Device.DeviceId ||
                 observation.DiskIds is null || observation.DiskIds.Count == 0 || observation.DiskIds.Count > TopologyGraphIndex.Limit ||
                 graph is null || observation.DiskIds.Distinct(StringComparer.Ordinal).Count() != observation.DiskIds.Count ||
                 observation.DiskIds.Any(id => !observation.Snapshot.Disks.Any(disk => disk.Id == id &&
                     string.Equals(disk.DeviceIdentifier, d.Device.DeviceId, StringComparison.OrdinalIgnoreCase))))))
            {
                result.Add(new(Key("invalid"), null, d.Device.DisplayName + " · Details unavailable", TopologyDashboard.Unavailable, DashboardPalette.Red));
                continue;
            }
            var current = mounts.Where(m => d.Volumes.Count(v => Matches(m, v, observation is not null)) == 1).ToArray();
            foreach (var m in current) assigned.Add(m);
            var local = status with { ConnectedInventory = [d with { Topology = null }], MountedVolumes = current, InventoryGeneration = null };
            var projected = TopologyDashboard.Project(local, observation?.Snapshot);
            var diskIds = observation?.DiskIds.ToHashSet(StringComparer.Ordinal);
            foreach (var node in projected)
            {
                var row = node.Row;
                if (row is not null && observation is not null)
                {
                    // The local rendering pass omits topology to avoid recursion. Restore
                    // actions from the full observation, including owners on other sources.
                    var sourceRows = surfaceRows[DriveDashboardPresenter.RowIdentity(row)].Where(r =>
                        r.RecoveryIdentity == row.RecoveryIdentity && r.IsMounted == row.IsMounted).ToArray();
                    if (sourceRows.Length == 1)
                        row = row with { CanVerifyOffline = sourceRows[0].CanVerifyOffline, CanVerifyLive = sourceRows[0].CanVerifyLive, CanManageOffline = sourceRows[0].CanManageOffline,
                            CanMutateSnapshots = sourceRows[0].CanMutateSnapshots, CanRecoverSnapshots = sourceRows[0].CanRecoverSnapshots,
                            CanManageTopologyImage = sourceRows[0].CanManageTopologyImage,
                            CanResizeFormatImage = sourceRows[0].CanResizeFormatImage,
                            ManagementScope = sourceRows[0].ManagementScope,
                            CanMountBackupReadWrite = sourceRows[0].CanMountBackupReadWrite,
                            Summary = sourceRows[0].CanMountBackupReadWrite ? sourceRows[0].Summary : row.Summary,
                            CanListSnapshots = sourceRows[0].CanListSnapshots, SnapshotScope = sourceRows[0].SnapshotScope,
                            CatalogSpace = sourceRows[0].CatalogSpace };
                    var volumes = d.Volumes.Where(v => v.VolumeId == row.VolumeId && v.CatalogVolumeId == row.CatalogVolumeId).ToArray();
                    var catalog = observation.Snapshot.Volumes.SingleOrDefault(v => v.Id == row.CatalogVolumeId);
                    var container = catalog is null ? null : observation.Snapshot.Containers.SingleOrDefault(c => c.Id == catalog.ContainerId);
                    if (volumes.Length != 1 || catalog is null || container is null ||
                        !SameUuid(volumes[0].CatalogVolumeUuid, catalog.Uuid) ||
                        !SameUuid(volumes[0].CatalogContainerUuid, container.Uuid) ||
                        !ulong.TryParse(catalog.ObjectId, out var objectId) || volumes[0].CatalogVolumeObjectId != objectId)
                        row = DisableActions(row);
                    else
                    {
                        // Reuse the catalog evaluator; inconsistent display evidence
                        // may restrict the inventory verdict, never promote it.
                        var capability = ApfsVolumeCapabilities.Evaluate(catalog, container);
                        var evidence = volumes[0] with { CatalogDecision = capability.Decision,
                            CatalogReasons = capability.Reasons, CatalogAutoMountAllowed = capability.AutoMountAllowed };
                        var ordinary = CatalogMountPolicy.AllowsOrdinaryMount(evidence);
                        row = row with { CanManageOffline = row.CanManageOffline && ordinary,
                            CanMutateSnapshots = row.CanMutateSnapshots && ordinary, CanRecoverSnapshots = row.CanRecoverSnapshots && ordinary,
                            CanManageTopologyImage = row.CanManageTopologyImage && ordinary,
                            CanResizeFormatImage = row.CanResizeFormatImage && ordinary,
                            CanListSnapshots = row.CanListSnapshots && ordinary };
                        if (!CatalogMountPolicy.AllowsMount(evidence, row.CanInspectReadOnly) &&
                            !(row.CanMountBackupReadWrite && BackupImageMountPolicy.HasCandidate(evidence) &&
                              evidence.BackupImageWrite == BackupImageMountPolicy.Observe(evidence, observation)))
                            row = row with { CanFix = false, CanInspectReadOnly = false, CanMountBackupReadWrite = false, DriveLetterPreference = null };
                    }
                }
                // A duplicate target on any device, or mismatched bucket, cannot authorize a legacy volume callback.
                if (row is not null && (targetCounts[row.VolumeId].Count() != 1 ||
                    d.Volumes.Count(v => v.DeviceId == d.Device.DeviceId && v.CatalogVolumeId == row.CatalogVolumeId && v.VolumeId == row.VolumeId) != 1))
                    row = DisableActions(row);
                result.Add(node with { Text = diskIds?.Contains(node.Id) == true ? d.Device.DisplayName : node.Text, Id = Key(node.Id), ParentId = node.ParentId is {} p ? Key(p) : null,
                    ReferenceId = node.ReferenceId is {} r ? Key(r) : null, MemberIds = node.MemberIds?.Select(Key).ToArray(), Row = row });
            }
        }
        // A retained mount may outlive a disconnect or failed discovery. Keep its
        // health visible, but do not attach it to another observation or target it.
        var stale = mounts.Where(m => !assigned.Contains(m)).ToArray();
        if (stale.Length > 0)
            result.AddRange(TopologyDashboard.Project(status with { ConnectedInventory = [], MountedVolumes = stale, InventoryGeneration = null })
                .Where(n => n.Row is not null).Select(n => n with { Id = "stale:" + n.Id, ParentId = null,
                    Row = DisableActions(n.Row!), Details = n.Details + "\nDisconnected" }));
        return result;
    }

    private static bool SameUuid(string? left, string? right) =>
        Guid.TryParse(left, out var a) && a != Guid.Empty && Guid.TryParse(right, out var b) && a == b;
}
