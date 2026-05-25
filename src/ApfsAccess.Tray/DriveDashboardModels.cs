namespace ApfsAccess.Tray;

public enum DriveDashboardState
{
    Idle = 0,
    HealthyReadWrite = 1,
    ReadOnly = 2,
    Attention = 3,
    Problem = 4,
}

public enum DashboardPalette
{
    Gray = 0,
    Green = 1,
    Yellow = 2,
    Orange = 3,
    Red = 4,
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
