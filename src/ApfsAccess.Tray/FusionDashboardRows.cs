using ApfsAccess.Core;
using ApfsAccess.Ipc;

namespace ApfsAccess.Tray;

public static class FusionDashboardRows
{
    public static List<DriveDashboardRow> Apply(IEnumerable<DriveDashboardRow> rows, StatusChangedPayload status) => rows.Select(row => {
        var devices = (status.ConnectedInventory ?? []).Where(d => d.Device.DeviceId == row.DeviceId).ToArray();
        if (devices.Length != 1 || !TopologyAdmission.Validate(devices[0])) return row;
        var volumes = devices[0].Volumes.Where(v => v.VolumeId == row.VolumeId && v.RegisteredFusion is not null).ToArray();
        if (volumes.Length != 1) return row;
        var volume = volumes[0]; var profile = volume.RegisteredFusion!;
        if (!profile.IsValid() || profile.Members.Any(m => m.Identity is null) || volume.RecoveryIdentity != profile.Contract) return row;
        return row with { RegisteredFusion = profile.Snapshot(), CanFix = !row.IsMounted, CanInspectReadOnly = false,
            CanManageOffline = false, CanManageTopologyImage = false, CanResizeFormatImage = false,
            CanMutateSnapshots = false, CanRecoverSnapshots = false, CanListSnapshots = false,
            StateText = row.IsMounted ? row.StateText : "Not mounted",
            Summary = row.IsMounted ? row.Summary : "Fusion image pair ready for native admission.",
            Details = row.Details.Concat(profile.Members.Select(m => $"{m.Role}: {m.Path} ({m.StoreOffset}, {m.StoreSize})")).ToArray() };
    }).ToList();
}
