using ApfsAccess.Core;
using ApfsAccess.Ipc;
using ApfsAccess.Tray;

namespace ApfsAccess.Tray.Tests;

public sealed class DriveDashboardPresenterTests
{
    [Fact]
    public void BuildRows_ClassifiesHealthyReadWriteVolumeAsGreenAndDisablesFix()
    {
        var payload = NewPayload(
            RuntimeState.MountedRw,
            writeEnabled: true,
            mountedVolumes:
            [
                NewMountedVolume(MountAccessMode.ReadWrite)
            ],
            nativeWriteSafetyState: NativeWriteSafetyState.PilotReadWrite,
            recoveryActive: false,
            dirtyTransactionCount: 0);

        var rows = DriveDashboardPresenter.BuildRows(payload);

        var row = Assert.Single(rows);
        Assert.Equal(DriveDashboardState.HealthyReadWrite, row.State);
        Assert.Equal("Healthy read/write", row.StateText);
        Assert.Equal(DashboardPalette.Green, row.Palette);
        Assert.False(row.CanFix);
        Assert.True(row.CanEject);
        Assert.True(row.CanOpen);
    }

    [Fact]
    public void BuildRows_ClassifiesReadOnlyVolumeAsYellowAndEnablesFix()
    {
        var payload = NewPayload(
            RuntimeState.MountedRo,
            writeEnabled: false,
            mountedVolumes:
            [
                NewMountedVolume(MountAccessMode.ReadOnly)
            ],
            nativeWriteSafetyState: NativeWriteSafetyState.ReadOnlyFallback,
            recoveryActive: false,
            dirtyTransactionCount: 0);

        var rows = DriveDashboardPresenter.BuildRows(payload);

        var row = Assert.Single(rows);
        Assert.Equal(DriveDashboardState.ReadOnly, row.State);
        Assert.Equal("Read-only", row.StateText);
        Assert.Equal(DashboardPalette.Yellow, row.Palette);
        Assert.True(row.CanFix);
        Assert.True(row.CanEject);
        Assert.True(row.CanOpen);
    }

    [Fact]
    public void BuildRows_ClassifiesRecoveryBlockedAsProblemEvenIfMounted()
    {
        var payload = NewPayload(
            RuntimeState.MountedRw,
            writeEnabled: false,
            mountedVolumes:
            [
                NewMountedVolume(MountAccessMode.ReadWrite)
            ],
            nativeWriteSafetyState: NativeWriteSafetyState.RecoveryBlocked,
            recoveryActive: true,
            recoveryReason: "ReplayCanonicalCandidateMissing");

        var row = Assert.Single(DriveDashboardPresenter.BuildRows(payload));

        Assert.Equal(DriveDashboardState.Problem, row.State);
        Assert.Equal(DashboardPalette.Red, row.Palette);
        Assert.True(row.CanFix);
        Assert.Contains(row.Details, detail => detail.Contains("ReplayCanonicalCandidateMissing", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void BuildRows_ClassifiesDirtyTransactionsAsAttention()
    {
        var payload = NewPayload(
            RuntimeState.MountedRw,
            writeEnabled: true,
            mountedVolumes:
            [
                NewMountedVolume(MountAccessMode.ReadWrite)
            ],
            nativeWriteSafetyState: NativeWriteSafetyState.PilotReadWrite,
            dirtyTransactionCount: 2);

        var row = Assert.Single(DriveDashboardPresenter.BuildRows(payload));

        Assert.Equal(DriveDashboardState.Attention, row.State);
        Assert.Equal(DashboardPalette.Orange, row.Palette);
        Assert.True(row.CanFix);
    }

    [Fact]
    public void BuildRows_ReturnsIdlePlaceholderWhenNoVolumeMounted()
    {
        var payload = NewPayload(
            RuntimeState.Idle,
            writeEnabled: false,
            mountedVolumes: []);

        var row = Assert.Single(DriveDashboardPresenter.BuildRows(payload));

        Assert.Equal(DriveDashboardState.Idle, row.State);
        Assert.Equal(DashboardPalette.Gray, row.Palette);
        Assert.Equal("No APFS drives mounted", row.DeviceName);
        Assert.False(row.CanOpen);
        Assert.False(row.CanEject);
        Assert.False(row.CanFix);
    }

    [Fact]
    public void BuildRows_EnablesFixWhenUnmountedDriveWasSafelyEjected()
    {
        var payload = NewPayload(
            RuntimeState.Idle,
            writeEnabled: false,
            mountedVolumes: [],
            warnings: ["'Main' is safely ejected; unplug and reinsert it to mount again."]);

        var row = Assert.Single(DriveDashboardPresenter.BuildRows(payload));

        Assert.Equal(DriveDashboardState.Attention, row.State);
        Assert.Equal(DashboardPalette.Orange, row.Palette);
        Assert.False(row.CanEject);
        Assert.True(row.CanFix);
        Assert.Contains("safely ejected", row.Summary, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void BuildRows_ReturnsProblemPlaceholderWhenServiceReportsErrorWithoutMountedVolume()
    {
        var payload = NewPayload(
            RuntimeState.Error,
            writeEnabled: false,
            mountedVolumes: []);

        var row = Assert.Single(DriveDashboardPresenter.BuildRows(payload));

        Assert.Equal(DriveDashboardState.Problem, row.State);
        Assert.Equal(DashboardPalette.Red, row.Palette);
        Assert.Equal("APFS Access needs attention", row.DeviceName);
        Assert.True(row.CanFix);
    }

    [Fact]
    public void BuildRows_PrefersDeviceAndVolumeNamesAndNormalizesDriveLabel()
    {
        var payload = NewPayload(
            RuntimeState.MountedRw,
            writeEnabled: true,
            mountedVolumes:
            [
                NewMountedVolume(
                    MountAccessMode.ReadWrite,
                    deviceDisplayName: "Samsung Flash Drive FIT USB Device",
                    volumeName: "Main",
                    mountPoint: "e:\\")
            ],
            nativeWriteSafetyState: NativeWriteSafetyState.PilotReadWrite);

        var row = Assert.Single(DriveDashboardPresenter.BuildRows(payload));

        Assert.Equal("Samsung Flash Drive FIT USB Device", row.DeviceName);
        Assert.Equal("Main", row.VolumeName);
        Assert.Equal("E:", row.MountPoint);
        Assert.Contains(row.Details, detail => detail == "Backend: Native");
        Assert.Contains(row.Details, detail => detail == "Warnings: none");
    }

    [Fact]
    public void BuildSummary_ReportsMountedVolumeCountAndWorstState()
    {
        var payload = NewPayload(
            RuntimeState.MountedRo,
            writeEnabled: false,
            mountedVolumes:
            [
                NewMountedVolume(MountAccessMode.ReadOnly)
            ],
            nativeWriteSafetyState: NativeWriteSafetyState.ReadOnlyFallback);

        var summary = DriveDashboardPresenter.BuildSummary(payload);

        Assert.Equal("1 APFS drive mounted. Attention may be needed.", summary);
    }

    private static StatusChangedPayload NewPayload(
        RuntimeState state,
        bool writeEnabled,
        IReadOnlyList<MountedVolumeDisplay> mountedVolumes,
        NativeWriteSafetyState nativeWriteSafetyState = NativeWriteSafetyState.ReadOnlyFallback,
        bool recoveryActive = false,
        string? recoveryReason = null,
        int dirtyTransactionCount = 0,
        bool shutdownDrainActive = false,
        int inFlightMutationCallbacks = 0,
        IReadOnlyList<string>? warnings = null,
        IReadOnlyList<string>? compatibilityWarnings = null,
        IReadOnlyList<NativeWriteDiagnostic>? diagnostics = null)
    {
        return new StatusChangedPayload(
            State: state,
            MountPoints: mountedVolumes
                .Select(static volume => volume.MountPoint)
                .Where(static mountPoint => !string.IsNullOrWhiteSpace(mountPoint))
                .ToArray(),
            LastError: state == RuntimeState.Error ? "Mount failed" : null,
            TimestampUtc: DateTime.UtcNow,
            Warnings: warnings ?? Array.Empty<string>(),
            WriteEnabled: writeEnabled,
            CompatibilityWarnings: compatibilityWarnings ?? Array.Empty<string>(),
            MountedVolumes: mountedVolumes,
            WriteBackend: "Native",
            CommitModel: NativeWriteCommitModel.CanonicalApfsCheckpoint,
            NativeWriteReadiness: NativeWriteReadiness.CommitReady,
            NativeWriteEngineState: NativeWriteEngineState.HardwareValidated,
            NativeWriteValidationState: NativeWriteValidationState.HardwarePilotValidated,
            RecoveryActive: recoveryActive,
            RecoveryReason: recoveryReason,
            LastCommitXid: 10316,
            NativeWriteSafetyState: nativeWriteSafetyState,
            DirtyTransactionCount: dirtyTransactionCount,
            ShutdownDrainActive: shutdownDrainActive,
            InFlightMutationCallbacks: inFlightMutationCallbacks,
            NativeWriteDiagnostics: diagnostics);
    }

    private static MountedVolumeDisplay NewMountedVolume(
        MountAccessMode accessMode,
        string deviceDisplayName = "APFS USB Device",
        string volumeName = "Main",
        string mountPoint = "E:\\")
    {
        return new MountedVolumeDisplay(
            VolumeId: @"\\.\PhysicalDrive2|Main",
            MountPoint: mountPoint,
            VolumeName: volumeName,
            DeviceId: @"\\.\PhysicalDrive2",
            DeviceDisplayName: deviceDisplayName,
            AccessMode: accessMode);
    }
}
