using ApfsAccess.Core;
namespace ApfsAccess.Ipc;

public static class MountedStatusProjection
{
    public static IReadOnlyList<MountedVolumeDisplay> FromMounts(IReadOnlyList<MountedVolumeState> mounts)
        => mounts
            .Where(static mount => !string.IsNullOrWhiteSpace(mount.MountPoint))
            .Select(static mount => new MountedVolumeDisplay(
                VolumeId: mount.VolumeId,
                MountPoint: mount.MountPoint,
                VolumeName: !string.IsNullOrWhiteSpace(mount.VolumeName)
                    ? mount.VolumeName
                    : TryParseVolumeNameFromVolumeId(mount.VolumeId) ?? "APFS",
                DeviceId: !string.IsNullOrWhiteSpace(mount.DeviceId)
                    ? mount.DeviceId
                    : TryParseDeviceIdFromVolumeId(mount.VolumeId) ?? string.Empty,
                DeviceDisplayName: !string.IsNullOrWhiteSpace(mount.DeviceDisplayName)
                    ? mount.DeviceDisplayName
                    : TryParseDeviceIdFromVolumeId(mount.VolumeId) ?? "APFS drive",
                AccessMode: mount.AccessMode,
                RecoveryIdentity: mount.RecoveryIdentity,
                State: mount.AccessMode == MountAccessMode.ReadWrite
                    ? RuntimeState.MountedRw
                    : RuntimeState.MountedRo,
                WriteEnabled: mount.AccessMode == MountAccessMode.ReadWrite,
                WriteBackend: mount.WriteBackend,
                CommitModel: mount.CommitModel,
                NativeWriteReadiness: mount.NativeWriteReadiness,
                NativeWriteEngineState: mount.NativeWriteEngineState,
                NativeWriteValidationState: mount.NativeWriteValidationState,
                NativeWriteSafetyState: mount.NativeWriteSafetyState,
                RecoveryActive: mount.RecoveryActive,
                RecoveryReason: mount.RecoveryReason,
                LastRecoveryAction: mount.LastRecoveryAction,
                LastCommitXid: mount.LastCommitXid,
                WriteIncompatibilities: mount.WriteIncompatibilities,
                WriteUnsupportedFeatures: mount.WriteUnsupportedFeatures,
                DirtyTransactionCount: mount.DirtyTransactionCount,
                ShutdownDrainActive: mount.ShutdownDrainActive,
                InFlightMutationCallbacks: mount.InFlightMutationCallbacks,
                NativeWriteValidationEvidence: mount.NativeWriteValidationEvidence,
                NativeWriteDiagnostics: mount.NativeWriteDiagnostics,
                MountReady: mount.MountReady,
                HostProcessId: mount.HostProcessId,
                WalAcceptedSequence: mount.WalAcceptedSequence,
                WalApfsDurableSequence: mount.WalApfsDurableSequence,
                WalCleanupSequence: mount.WalCleanupSequence,
                PendingDurability: mount.RuntimeMutationPending || mount.RuntimeWatermarksKnown == false ||
                    mount.WalCleanupSequence < mount.WalApfsDurableSequence || mount.WalAcceptedSequence > mount.WalApfsDurableSequence ||
                    mount.DirtyTransactionCount > 0 ||
                    mount.ShutdownDrainActive ||
                    mount.InFlightMutationCallbacks > 0,
                HostOwnershipState: mount.HostProcessId > 0 ? "owned" : "unknown",
                CatalogVolumeId: mount.CatalogVolumeId,
                CatalogVolumeUuid: mount.CatalogVolumeUuid,
                CatalogContainerUuid: mount.CatalogContainerUuid,
                CatalogVolumeObjectId: mount.CatalogVolumeObjectId,
                CatalogDecision: mount.CatalogDecision,
                CatalogReasons: mount.CatalogReasons,
                CatalogAutoMountAllowed: mount.CatalogAutoMountAllowed,
                CatalogSpace: mount.CatalogSpace,
                HasRuntimeStatus: mount.RuntimeWatermarksKnown ?? true, SnapshotInventorySupported: mount.SnapshotInventorySupported,
                SnapshotMutationSupported: mount.SnapshotMutationSupported,
                SnapshotRecoverySupported: mount.SnapshotRecoverySupported,
                VolumeVerificationSupported: mount.VolumeVerificationSupported,
                VolumeVerificationScope: mount.VolumeVerificationScope,
                HostProcessCreationTimeFileTimeUtc: mount.HostProcessCreationTimeFileTimeUtc))
            .OrderBy(static volume => volume.MountPoint, StringComparer.OrdinalIgnoreCase)
            .ToArray();

    private static string? TryParseVolumeNameFromVolumeId(string? id)
    {
        if (string.IsNullOrWhiteSpace(id)) return null;
        var i = id.LastIndexOf('|');
        var value = i < 0 || i >= id.Length - 1 ? null : id[(i + 1)..].Trim();
        return string.IsNullOrWhiteSpace(value) ? null : value;
    }
    private static string? TryParseDeviceIdFromVolumeId(string? id)
    {
        if (string.IsNullOrWhiteSpace(id)) return null;
        var i = id.IndexOf('|');
        var value = i <= 0 ? null : id[..i].Trim();
        return string.IsNullOrWhiteSpace(value) ? null : value;
    }
}
