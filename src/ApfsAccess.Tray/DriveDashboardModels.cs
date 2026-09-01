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
    IReadOnlyList<string> FixGuidance
);
