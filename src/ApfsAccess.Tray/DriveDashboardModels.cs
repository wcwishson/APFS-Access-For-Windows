namespace ApfsAccess.Tray;

public enum DriveDashboardState
{
    Idle = 0,
    HealthyReadWrite = 1,
    FinishingWrites = 2,
    ReadOnly = 3,
    Attention = 4,
    Problem = 5,
}

public enum DashboardPalette
{
    Gray = 0,
    Green = 1,
    Blue = 2,
    Yellow = 3,
    Orange = 4,
    Red = 5,
}

public sealed record DriveDashboardRow(
    string VolumeId,
    string DeviceName,
    string VolumeName,
    string MountPoint,
    string MountPath,
    DriveDashboardState State,
    DashboardPalette Palette,
    string StateText,
    string Summary,
    bool CanOpen,
    bool CanEject,
    bool CanFix,
    IReadOnlyList<string> Details,
    IReadOnlyList<string> FixGuidance,
    string? CatalogVolumeId = null,
    string? CatalogContainerUuid = null,
    ulong? CatalogVolumeObjectId = null,
    string? DeviceId = null,
    ApfsAccess.Core.DriveLetterPreference? DriveLetterPreference = null,
    bool IsMounted = true,
    bool CanInspectReadOnly = false,
    string? RecoveryIdentity = null,
    string? CatalogVolumeUuid = null,
    ApfsAccess.Core.EncryptedImageProfile? RegisteredImage = null,
    ApfsAccess.Core.EncryptedVolumeState? EncryptionState = null,
    bool CanUnlock = false, bool CanLock = false,
    bool CanVerifyOffline = false, bool CanManageOffline = false,
    bool CanMutateSnapshots = false, bool CanRecoverSnapshots = false,
    ApfsAccess.Core.ApfsVolumeSpaceObservation? CatalogSpace = null,
    bool CanManageTopologyImage = false,
    bool CanListSnapshots = false,
    ApfsAccess.Core.VerifyScope? SnapshotScope = null,
    bool CanVerifyLive = false,
    bool CanResizeFormatImage = false,
    ApfsAccess.Core.SnapshotRuntimeAuthority? SnapshotRuntimeAuthority = null,
    ApfsAccess.Core.FusionImageProfile? RegisteredFusion = null,
    bool CanMountBackupReadWrite = false,
    ApfsAccess.Core.VerifyScope? ManagementScope = null
)
{
    public bool CanMount => !IsMounted && (CanFix || CanInspectReadOnly || CanMountBackupReadWrite);
    public bool CanPlanImageOperation(string operation) => operation is "grow" or "shrink" or "format" or "erase" &&
        CanResizeFormatImage && (ManagementScope ?? SnapshotScope) is { } scope &&
        (ApfsAccess.Core.VolumeTopologyProfile.IsStreamedImage(scope, operation) || ApfsAccess.Core.VolumeTopologyProfile.IsPhysicalManagement(scope, operation));
    public bool CanResizeImage => CanPlanImageOperation("grow") || CanPlanImageOperation("shrink");
    public bool CanFormatImage => CanPlanImageOperation("format") || CanPlanImageOperation("erase");
}
