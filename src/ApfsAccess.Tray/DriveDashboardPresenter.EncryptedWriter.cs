using ApfsAccess.Core;
using ApfsAccess.Ipc;

namespace ApfsAccess.Tray;

public static partial class DriveDashboardPresenter
{
    private static DriveDashboardRow EncryptedWriterRow(StatusChangedPayload payload, DriveDashboardRow row, VolumeInfo volume)
    {
        var profile = volume.RegisteredImage!;
        var owners = (payload.MountedVolumes ?? []).Where(m =>
            m.VolumeId == profile.VolumeId && string.Equals(m.DeviceId, profile.ImagePath, StringComparison.OrdinalIgnoreCase)).ToArray();
        var owner = owners.Length == 1 ? owners[0] : null;
        var exact = payload.State != RuntimeState.Error && row.State != DriveDashboardState.Problem &&
            owner is { HasRuntimeStatus: true, HostProcessId: > 0, HostProcessCreationTimeFileTimeUtc: > 0, State: RuntimeState.MountedRw } &&
            owner.RecoveryIdentity == profile.Contract && owner.CatalogVolumeId == profile.VolumeId &&
            TopologyAdmission.SameUuid(owner.CatalogContainerUuid, profile.ContainerUuid) &&
            TopologyAdmission.SameUuid(owner.CatalogVolumeUuid, profile.VolumeUuid) && owner.CatalogVolumeObjectId == profile.VolumeObjectId &&
            owner.AccessMode == MountAccessMode.ReadWrite && owner.WriteEnabled && owner.MountReady &&
            owner.WriteBackend == "Native" && owner.CommitModel == NativeWriteCommitModel.CanonicalApfsCheckpoint &&
            owner.NativeWriteEngineState == NativeWriteEngineState.Transactional &&
            owner.NativeWriteValidationState == NativeWriteValidationState.CanonicalImageValidated &&
            owner.NativeWriteReadiness == NativeWriteReadiness.CommitReady && !owner.RecoveryActive &&
            owner.NativeWriteSafetyState is NativeWriteSafetyState.PilotReadWrite or NativeWriteSafetyState.StableReadWrite && string.IsNullOrEmpty(owner.RecoveryReason) &&
            owner.LastCommitXid is {} xid && xid >= profile.CheckpointXid && owner.DirtyTransactionCount >= 0 &&
            owner.WalAcceptedSequence >= owner.WalApfsDurableSequence &&
            owner.WalApfsDurableSequence >= owner.WalCleanupSequence;
        var pending = exact && (owner!.PendingDurability || owner.WalAcceptedSequence != owner.WalCleanupSequence ||
            owner.DirtyTransactionCount > 0 || owner.ShutdownDrainActive || owner.InFlightMutationCallbacks > 0);
        var healthy = exact && !pending && row.State == DriveDashboardState.HealthyReadWrite;
        var state = pending ? DriveDashboardState.FinishingWrites : healthy ? DriveDashboardState.HealthyReadWrite : DriveDashboardState.Problem;
        return row with {
            RegisteredImage = profile, EncryptionState = EncryptedVolumeState.Unlocked,
            CanFix = false, CanInspectReadOnly = false, CanUnlock = false, CanLock = row.IsMounted,
            CanOpen = exact && row.CanOpen, State = state, Palette = ToPalette(state),
            StateText = pending ? "Finishing writes" : healthy ? "Unlocked · Read/write" : "Writer requires attention",
            Summary = pending ? "Accepted image changes are still being completed."
                : healthy ? "Read/write access to the selected image."
                : "Read/write ownership or recovery is not proven. Lock the image before retrying."
        };
    }
}
