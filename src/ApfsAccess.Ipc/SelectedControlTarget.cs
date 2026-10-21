using ApfsAccess.Core;

namespace ApfsAccess.Ipc;

public static class SelectedControlTarget
{
    public static bool IsAdvertised(ApfsControlTarget t) => t.VolumeUuid is not null || t.ContainerUuid is not null || t.VolumeObjectId is not null || t.ObservationContract is not null;
    public static bool IsWellFormed(ApfsControlTarget t) =>
        (t.RegisteredImage is null || ImageMatches(t)) &&
        (t.RegisteredFusion is null || t.RegisteredImage is null && FusionMatches(t)) &&
        TopologyGraphIndex.Text(t.DeviceId) && TopologyGraphIndex.Text(t.VolumeId) &&
        (!IsAdvertised(t) || TopologyAdmission.SameUuid(t.VolumeUuid, t.VolumeUuid) && TopologyAdmission.SameUuid(t.ContainerUuid, t.ContainerUuid) &&
            t.VolumeObjectId is > 0 && TopologyGraphIndex.Text(t.RecoveryIdentity) && t.ObservationContract is { Length: 76 } contract &&
            contract.StartsWith("selected-v1:", StringComparison.Ordinal) && contract[12..].All(Uri.IsHexDigit));

    public static ApfsControlTarget ForImage(EncryptedImageProfile p) => new(p.ImagePath, p.VolumeId, p.Contract, p.VolumeUuid, p.ContainerUuid, p.VolumeObjectId, p.Contract, p);
    public static ApfsControlTarget ForFusion(FusionImageProfile p) => new(p.DeviceId, p.VolumeId, p.Contract,
        p.VolumeUuid, p.ContainerUuid, p.VolumeOid, p.Contract, RegisteredFusion: p.Snapshot());
    private static bool FusionMatches(ApfsControlTarget t) => t.RegisteredFusion is {} p && p.IsValid() &&
        string.Equals(t.DeviceId, p.DeviceId, StringComparison.OrdinalIgnoreCase) && t.VolumeId == p.VolumeId &&
        t.VolumeUuid == p.VolumeUuid && t.ContainerUuid == p.ContainerUuid && t.VolumeObjectId == p.VolumeOid &&
        t.RecoveryIdentity == p.Contract && t.ObservationContract == p.Contract;
    private static bool ImageMatches(ApfsControlTarget t) => t.RegisteredImage is {} p && p.IsValid() &&
        string.Equals(t.DeviceId, p.ImagePath, StringComparison.OrdinalIgnoreCase) && t.VolumeId == p.VolumeId &&
        t.VolumeUuid == p.VolumeUuid && t.ContainerUuid == p.ContainerUuid && t.VolumeObjectId == p.VolumeObjectId &&
        t.RecoveryIdentity == p.Contract && t.ObservationContract == p.Contract;

    public static ApfsControlTarget Create(DeviceInventory d, VolumeInfo v) => v.RegisteredFusion is {} fusion ? ForFusion(fusion) : v.RegisteredImage is {} p ? ForImage(p) : new(v.DeviceId, v.VolumeId, v.RecoveryIdentity,
        v.CatalogVolumeUuid, v.CatalogContainerUuid, v.CatalogVolumeObjectId, TopologyAdmission.Contract(d, v));

    public static bool Matches(IReadOnlyList<DeviceInventory> inventory, ApfsControlTarget target)
    {
        if (!IsWellFormed(target) || inventory.Count > TopologyGraphIndex.Limit) return false;
        var devices = inventory.Where(d => d?.Device is not null && string.Equals(d.Device.DeviceId, target.DeviceId, StringComparison.OrdinalIgnoreCase)).ToArray();
        // The current backend mutation API routes by VolumeId: enforce global uniqueness.
        if (devices.Length != 1 || inventory.Sum(d => d?.Volumes?.Count ?? TopologyGraphIndex.Limit + 1) > TopologyGraphIndex.Limit ||
            inventory.Sum(d => d.Volumes.Count(v => v is not null && string.Equals(v.VolumeId, target.VolumeId, StringComparison.OrdinalIgnoreCase))) != 1 ||
            !TopologyAdmission.Validate(devices[0])) return false;
        var rows = devices[0].Volumes.Where(v => string.Equals(v.VolumeId, target.VolumeId, StringComparison.OrdinalIgnoreCase)).ToArray();
        if (rows.Length != 1 || target.RecoveryIdentity is not null && rows[0].RecoveryIdentity != target.RecoveryIdentity) return false;
        if (!IsAdvertised(target)) return rows[0].RegisteredImage is null && rows[0].RegisteredFusion is null; // Bounded older sender; current graph checks still apply.
        var row = rows[0];
        if (target.RegisteredFusion is {} fusion) return row.RegisteredFusion?.Contract == fusion.Contract && FusionMatches(target);
        if (row.RegisteredFusion is not null) return false;
        if (target.RegisteredImage is {} image) return row.RegisteredImage == image && ImageMatches(target);
        if (row.RegisteredImage is not null) return false;
        return devices[0].Topology is not null && TopologyAdmission.SameUuid(target.VolumeUuid, row.CatalogVolumeUuid) &&
            TopologyAdmission.SameUuid(target.ContainerUuid, row.CatalogContainerUuid) && target.VolumeObjectId == row.CatalogVolumeObjectId &&
            target.ObservationContract == TopologyAdmission.Contract(devices[0], row);
    }

    public static bool MatchesMount(ApfsControlTarget target, MountedVolumeState m) =>
        string.Equals(target.DeviceId, m.DeviceId, StringComparison.OrdinalIgnoreCase) && string.Equals(target.VolumeId, m.VolumeId, StringComparison.OrdinalIgnoreCase) &&
        (target.RecoveryIdentity is null || target.RecoveryIdentity == m.RecoveryIdentity) &&
        (!IsAdvertised(target) || TopologyAdmission.SameUuid(target.VolumeUuid, m.CatalogVolumeUuid) && TopologyAdmission.SameUuid(target.ContainerUuid, m.CatalogContainerUuid) && target.VolumeObjectId == m.CatalogVolumeObjectId);
}
