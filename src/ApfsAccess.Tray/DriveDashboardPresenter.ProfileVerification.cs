using ApfsAccess.Core;
using ApfsAccess.Ipc;

namespace ApfsAccess.Tray;

public static partial class DriveDashboardPresenter
{
    public static bool CanVerifyCurrentProfile(DriveDashboardRow row) => row.RegisteredFusion is { } fusion
        ? row.RegisteredImage is null && fusion.IsValid() && fusion.Members.All(m=>m.Identity is not null) &&
            ProfileVerificationUnavailableReason(row) is null && row.RecoveryIdentity==fusion.Contract &&
            row.DeviceId==fusion.DeviceId && row.VolumeId==fusion.VolumeId && row.CatalogVolumeObjectId==fusion.VolumeOid &&
            TopologyAdmission.SameUuid(row.CatalogContainerUuid,fusion.ContainerUuid) &&
            TopologyAdmission.SameUuid(row.CatalogVolumeUuid,fusion.VolumeUuid)
        : row.RegisteredImage is { } p &&
        p.IsValid() && row.EncryptionState is (EncryptedVolumeState.Locked or EncryptedVolumeState.Unlocked or EncryptedVolumeState.Failed) &&
        ProfileVerificationUnavailableReason(row) is null &&
        string.Equals(row.DeviceId,p.ImagePath,StringComparison.OrdinalIgnoreCase) &&
        row.CatalogVolumeObjectId==p.VolumeObjectId && row.VolumeId==p.VolumeId &&
        TopologyAdmission.SameUuid(row.CatalogContainerUuid,p.ContainerUuid) &&
        TopologyAdmission.SameUuid(row.CatalogVolumeUuid,p.VolumeUuid);

    public static string? ProfileVerificationUnavailableReason(DriveDashboardRow row) =>
        row.RegisteredFusion is not null && (row.IsMounted || !string.IsNullOrWhiteSpace(row.MountPoint) ||
            !string.IsNullOrWhiteSpace(row.MountPath) || row.State==DriveDashboardState.FinishingWrites)
            ? "Unmount both Fusion members and wait until the pair is offline before verification." :
        row.RegisteredImage is {Writable:true} &&
        (row.EncryptionState!=EncryptedVolumeState.Locked || row.IsMounted ||
            !string.IsNullOrWhiteSpace(row.MountPoint) || !string.IsNullOrWhiteSpace(row.MountPath))
            ? "Lock this writable image and wait until it is offline before verification." : null;

    public static void RequireCurrentProfileRow(StatusChangedPayload status,DriveDashboardRow selected,bool connected)
    {
        if(ProfileVerificationUnavailableReason(selected) is { } selectedReason)throw new InvalidOperationException(selectedReason);
        if(!connected || !CanVerifyCurrentProfile(selected))throw new InvalidOperationException("The registered image selection is unavailable.");
        var matches=BuildRows(status).Where(r=>RowIdentity(r)==RowIdentity(selected)).ToArray();
        if(matches.Length==1 && ProfileVerificationUnavailableReason(matches[0]) is { } currentReason)
            throw new InvalidOperationException(currentReason);
        if(matches.Length!=1 || !CanVerifyCurrentProfile(matches[0]) ||
            matches[0].RegisteredImage?.Contract!=selected.RegisteredImage?.Contract ||
            matches[0].RegisteredFusion?.Contract!=selected.RegisteredFusion?.Contract)
            throw new InvalidOperationException("The registered image selection changed. Refresh the volume list.");
        if(selected.RegisteredFusion is { } fusion &&
            (status.ConnectedInventory??[]).SelectMany(d=>d.Volumes).Count(v=>v.VolumeId==fusion.VolumeId)!=1)
            throw new InvalidOperationException("The registered Fusion owner is ambiguous. Refresh the volume list.");
    }
}
