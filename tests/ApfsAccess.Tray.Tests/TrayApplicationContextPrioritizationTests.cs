using System.Reflection;
using System.Runtime.CompilerServices;
using ApfsAccess.Core;
using ApfsAccess.Ipc;
using ApfsAccess.Tray;

namespace ApfsAccess.Tray.Tests;

public sealed class TrayApplicationContextPrioritizationTests
{
    [Theory]
    [InlineData(true, true, true)]
    [InlineData(true, false, true)]
    [InlineData(false, false, true)]
    [InlineData(false, true, false)]
    public void ShouldCompleteQuit_RequiresAcknowledgementWhileServiceIsRunning(
        bool acknowledged,
        bool serviceRunning,
        bool expected)
    {
        Assert.Equal(expected, InvokeShouldCompleteQuit(acknowledged, serviceRunning));
    }

    [Theory]
    [InlineData("Write blocked (reason=CanonicalCommitNotReady)", "CanonicalCommitNotReady")]
    [InlineData("Write blocked (reason=NativeWriteNotReady).", "NativeWriteNotReady")]
    [InlineData("Write blocked (reason=CanonicalPathNotActive)", "CanonicalPathNotActive")]
    [InlineData("Write blocked (reason = CanonicalCommitNotReady)", null)]
    [InlineData("Write blocked", null)]
    [InlineData("", null)]
    [InlineData(null, null)]
    public void NativeWriteRecoveryReasons_ParsesSupportedReasonPattern(string? warning, string? expected)
    {
        var actual = NativeWriteRecoveryReasons.TryExtractReasonToken(warning);
        Assert.Equal(expected, actual);
    }

    [Theory]
    [InlineData("CanonicalStateNotLoaded", 0)]
    [InlineData("NativeWriteNotReady", 0)]
    [InlineData("WriteDeviceNotAllowed", 0)]
    [InlineData("CommitPathNotReady", 0)]
    [InlineData("CanonicalCommitNotReady", 0)]
    [InlineData("FixtureCompatibilityPathActive", 0)]
    [InlineData("ScaffoldCommitBlobActive", 0)]
    [InlineData("IntegrityMissingAllocationMap", 1)]
    [InlineData("ReplayCheckpointPendingWindow", 1)]
    [InlineData("ReplayCheckpointNotPendingWindow", 1)]
    [InlineData("ReplayCanonicalCandidateMissing", 1)]
    [InlineData("CanonicalPathNotActive", 2)]
    [InlineData("WriteGateBlocked", 3)]
    [InlineData("", int.MaxValue)]
    [InlineData(null, int.MaxValue)]
    public void NativeWriteRecoveryReasons_PrioritizesCanonicalGateReasons(string? recoveryReason, int expected)
    {
        var actual = NativeWriteRecoveryReasons.GetPriority(recoveryReason);
        Assert.Equal(expected, actual);
    }

    [Theory]
    [InlineData("Write blocked (reason=CanonicalCommitNotReady)", 0)]
    [InlineData("Write blocked (reason=FixtureCompatibilityPathActive)", 0)]
    [InlineData("Write blocked (reason=ScaffoldCommitBlobActive)", 0)]
    [InlineData("Write blocked (reason=IntegrityMissingAllocationMap)", 1)]
    [InlineData("Write blocked (reason=ReplayCheckpointPendingWindow)", 1)]
    [InlineData("Write blocked (reason=ReplayCheckpointNotPendingWindow)", 1)]
    [InlineData("Write blocked (reason=ReplayCanonicalCandidateMissing)", 1)]
    [InlineData("Write blocked (reason=CanonicalPathNotActive)", 2)]
    [InlineData("Write blocked (reason=WriteGateBlocked)", 3)]
    [InlineData("Write blocked", int.MaxValue)]
    [InlineData("", int.MaxValue)]
    public void GetWarningPriority_UsesEmbeddedRecoveryReason(string warning, int expected)
    {
        var actual = InvokeGetWarningPriority(warning);
        Assert.Equal(expected, actual);
    }

    [Fact]
    public void SelectPrimaryRecoveryReason_PrefersCanonicalReasonFromWarningsOverGenericRecoveryReason()
    {
        var payload = new StatusChangedPayload(
            State: RuntimeState.Error,
            MountPoints: Array.Empty<string>(),
            LastError: "error",
            TimestampUtc: DateTime.UtcNow,
            Warnings: ["Native write blocked (reason=CanonicalCommitNotReady)"],
            WriteEnabled: false,
            CompatibilityWarnings: ["General warning"],
            RecoveryActive: true,
            RecoveryReason: "WriteGateBlocked");

        var primary = InvokeSelectPrimaryRecoveryReason(payload);

        Assert.Equal("CanonicalCommitNotReady", primary);
    }

    [Fact]
    public void SelectPrimaryRecoveryReason_ConsidersDiagnosticRecoveryReasons()
    {
        var payload = new StatusChangedPayload(
            State: RuntimeState.MountedRo,
            MountPoints: ["P:\\"],
            LastError: null,
            TimestampUtc: DateTime.UtcNow,
            Warnings: Array.Empty<string>(),
            WriteEnabled: false,
            CompatibilityWarnings: Array.Empty<string>(),
            RecoveryActive: true,
            RecoveryReason: "WriteGateBlocked",
            NativeWriteDiagnostics:
            [
                new NativeWriteDiagnostic(
                    Code: "NativeWriteCanonicalGateFailure",
                    Message: "canonical gate failure",
                    IsFailClosed: true,
                    RecoveryReason: "CanonicalStateNotLoaded"),
            ]);

        var primary = InvokeSelectPrimaryRecoveryReason(payload);

        Assert.Equal("CanonicalStateNotLoaded", primary);
    }

    [Fact]
    public void SelectPrimaryRecoveryReason_PrefersReplayCandidateMissingOverCanonicalPathFromWarnings()
    {
        var payload = new StatusChangedPayload(
            State: RuntimeState.Error,
            MountPoints: Array.Empty<string>(),
            LastError: "error",
            TimestampUtc: DateTime.UtcNow,
            Warnings:
            [
                "Native write blocked (reason=CanonicalPathNotActive)",
                "Native write blocked (reason=ReplayCanonicalCandidateMissing)",
            ],
            WriteEnabled: false,
            CompatibilityWarnings: Array.Empty<string>(),
            RecoveryActive: true,
            RecoveryReason: "WriteGateBlocked");

        var primary = InvokeSelectPrimaryRecoveryReason(payload);

        Assert.Equal("ReplayCanonicalCandidateMissing", primary);
    }

    [Fact]
    public void SelectPrimaryRecoveryReason_ReturnsNullWhenNoSignalsPresent()
    {
        var payload = new StatusChangedPayload(
            State: RuntimeState.Idle,
            MountPoints: Array.Empty<string>(),
            LastError: null,
            TimestampUtc: DateTime.UtcNow,
            Warnings: Array.Empty<string>(),
            WriteEnabled: false,
            CompatibilityWarnings: Array.Empty<string>(),
            RecoveryActive: false);

        var primary = InvokeSelectPrimaryRecoveryReason(payload);

        Assert.Null(primary);
    }

    [Theory]
    [InlineData(RuntimeState.MountedRw, "APFS Access: mounted read/write (1)")]
    [InlineData(RuntimeState.MountedRo, "APFS Access: mounted read-only (1)")]
    public void BuildNotifyIconText_LabelsMountedAccessMode(RuntimeState state, string expected)
    {
        var payload = new StatusChangedPayload(
            State: state,
            MountPoints: ["P:\\"],
            LastError: null,
            TimestampUtc: DateTime.UtcNow,
            Warnings: Array.Empty<string>(),
            WriteEnabled: state == RuntimeState.MountedRw,
            CompatibilityWarnings: Array.Empty<string>(),
            RecoveryActive: false);

        var text = InvokeBuildNotifyIconText(payload);

        Assert.Equal(expected, text);
    }

    [Fact]
    public void BuildNotifyIconText_DoesNotSurfaceTransientMutationCallbackCount()
    {
        var payload = new StatusChangedPayload(
            State: RuntimeState.MountedRw,
            MountPoints: ["P:\\"],
            LastError: null,
            TimestampUtc: DateTime.UtcNow,
            Warnings: Array.Empty<string>(),
            WriteEnabled: true,
            CompatibilityWarnings: Array.Empty<string>(),
            RecoveryActive: false,
            InFlightMutationCallbacks: 2);

        var text = InvokeBuildNotifyIconText(payload);

        Assert.Equal("APFS Access: mounted read/write (1)", text);
    }

    [Fact]
    public void SelectNotifyIconState_UsesReadOnlyIconForReadOnlyMountedVolume()
    {
        var payload = new StatusChangedPayload(
            State: RuntimeState.MountedRo,
            MountPoints: ["P:\\"],
            LastError: null,
            TimestampUtc: DateTime.UtcNow,
            Warnings: Array.Empty<string>(),
            WriteEnabled: false,
            CompatibilityWarnings: Array.Empty<string>(),
            MountedVolumes:
            [
                new MountedVolumeDisplay(
                    VolumeId: @"\\.\PhysicalDrive2|Main",
                    MountPoint: "P:\\",
                    VolumeName: "Main",
                    DeviceId: @"\\.\PhysicalDrive2",
                    DeviceDisplayName: "APFS drive",
                    AccessMode: MountAccessMode.ReadOnly)
            ],
            NativeWriteSafetyState: NativeWriteSafetyState.ReadOnlyFallback);

        Assert.Equal(RuntimeState.MountedRo, InvokeSelectNotifyIconState(payload));
    }

    [Fact]
    public void ReadOnlyTrayIcon_IsYellowAndDistinctFromReadWriteIcon()
    {
        var iconDirectory = Path.Combine(AppContext.BaseDirectory, "assets", "icons");
        var readWriteColor = ReadTrayIconPrimaryColor(Path.Combine(iconDirectory, "tray_mounted_rw.ico"));
        var readOnlyColor = ReadTrayIconPrimaryColor(Path.Combine(iconDirectory, "tray_mounted_ro.ico"));

        Assert.Equal(Color.FromArgb(33, 150, 83).ToArgb(), readWriteColor.ToArgb());
        Assert.Equal(Color.FromArgb(214, 158, 46).ToArgb(), readOnlyColor.ToArgb());
        Assert.NotEqual(readWriteColor.ToArgb(), readOnlyColor.ToArgb());
    }

    [Fact]
    public void SelectBalloonIcon_TreatsHealthyReadWriteNoticeAsInfo()
    {
        var payload = new StatusChangedPayload(
            State: RuntimeState.MountedRw,
            MountPoints: ["P:\\"],
            LastError: null,
            TimestampUtc: DateTime.UtcNow,
            Warnings: ["Mounted 'Main' with native write enabled."],
            WriteEnabled: true,
            CompatibilityWarnings: Array.Empty<string>(),
            NativeWriteSafetyState: NativeWriteSafetyState.PilotReadWrite);

        var icon = InvokeSelectBalloonIcon(payload);

        Assert.Equal(ToolTipIcon.Info, icon);
    }

    [Fact]
    public void SelectBalloonIcon_TreatsHealthyReadWriteWithoutVolumeRowsAsInfo()
    {
        var payload = new StatusChangedPayload(
            State: RuntimeState.MountedRw,
            MountPoints: ["P:\\"],
            LastError: null,
            TimestampUtc: DateTime.UtcNow,
            Warnings: ["Mounted 'Main' with native write enabled."],
            WriteEnabled: true,
            CompatibilityWarnings: Array.Empty<string>(),
            NativeWriteSafetyState: NativeWriteSafetyState.ReadOnlyFallback);

        var icon = InvokeSelectBalloonIcon(payload);

        Assert.Equal(ToolTipIcon.Info, icon);
    }

    [Fact]
    public void SelectBalloonStateAndTitle_TreatMountedRwWithLaggingWriteFlagAsHealthy()
    {
        var payload = new StatusChangedPayload(
            State: RuntimeState.MountedRw,
            MountPoints: ["P:\\"],
            LastError: null,
            TimestampUtc: DateTime.UtcNow,
            Warnings: ["Mounted 'Main' with native write enabled."],
            WriteEnabled: false,
            CompatibilityWarnings: Array.Empty<string>(),
            NativeWriteSafetyState: NativeWriteSafetyState.ReadOnlyFallback);

        var state = InvokeSelectBalloonState(payload);
        var title = InvokeSelectBalloonTitle(state);
        var icon = InvokeSelectBalloonIcon(payload);

        Assert.Equal(DriveDashboardState.HealthyReadWrite, state);
        Assert.Equal("APFS Access Healthy", title);
        Assert.Equal(ToolTipIcon.Info, icon);
    }

    [Fact]
    public void SelectBalloonIcon_UsesMountedVolumeHealthWhenTopLevelWriteFlagLags()
    {
        var payload = new StatusChangedPayload(
            State: RuntimeState.MountedRw,
            MountPoints: ["P:\\"],
            LastError: null,
            TimestampUtc: DateTime.UtcNow,
            Warnings: ["Mounted 'Main' with native write enabled."],
            WriteEnabled: false,
            CompatibilityWarnings: Array.Empty<string>(),
            MountedVolumes:
            [
                new MountedVolumeDisplay(
                    VolumeId: @"\\.\PhysicalDrive2|Main",
                    MountPoint: "P:\\",
                    VolumeName: "Main",
                    DeviceId: @"\\.\PhysicalDrive2",
                    DeviceDisplayName: "APFS drive",
                    AccessMode: MountAccessMode.ReadWrite)
            ],
            NativeWriteSafetyState: NativeWriteSafetyState.PilotReadWrite);

        var icon = InvokeSelectBalloonIcon(payload);

        Assert.Equal(ToolTipIcon.Info, icon);
    }

    [Fact]
    public void SelectBalloonIcon_UsesReadWriteMountWhenSafetyStateLags()
    {
        var payload = new StatusChangedPayload(
            State: RuntimeState.MountedRw,
            MountPoints: ["P:\\"],
            LastError: null,
            TimestampUtc: DateTime.UtcNow,
            Warnings: ["Mounted 'Main' with native write enabled."],
            WriteEnabled: true,
            CompatibilityWarnings: Array.Empty<string>(),
            MountedVolumes:
            [
                new MountedVolumeDisplay(
                    VolumeId: @"\\.\PhysicalDrive2|Main",
                    MountPoint: "P:\\",
                    VolumeName: "Main",
                    DeviceId: @"\\.\PhysicalDrive2",
                    DeviceDisplayName: "APFS drive",
                    AccessMode: MountAccessMode.ReadWrite)
            ],
            NativeWriteSafetyState: NativeWriteSafetyState.ReadOnlyFallback);

        var icon = InvokeSelectBalloonIcon(payload);

        Assert.Equal(ToolTipIcon.Info, icon);
    }

    [Fact]
    public void SelectBalloonStateAndTitle_UseReadWriteVolumeHealthWhenSafetyStateLags()
    {
        var payload = new StatusChangedPayload(
            State: RuntimeState.MountedRw,
            MountPoints: ["P:\\"],
            LastError: null,
            TimestampUtc: DateTime.UtcNow,
            Warnings: ["Mounted 'Main' with native write enabled."],
            WriteEnabled: true,
            CompatibilityWarnings: Array.Empty<string>(),
            MountedVolumes:
            [
                new MountedVolumeDisplay(
                    VolumeId: @"\\.\PhysicalDrive2|Main",
                    MountPoint: "P:\\",
                    VolumeName: "Main",
                    DeviceId: @"\\.\PhysicalDrive2",
                    DeviceDisplayName: "APFS drive",
                    AccessMode: MountAccessMode.ReadWrite)
            ],
            NativeWriteSafetyState: NativeWriteSafetyState.ReadOnlyFallback);

        var state = InvokeSelectBalloonState(payload);
        var title = InvokeSelectBalloonTitle(state);

        Assert.Equal(DriveDashboardState.HealthyReadWrite, state);
        Assert.Equal("APFS Access Healthy", title);
    }

    [Fact]
    public void SelectBalloonStateAndTitle_UseReadWriteVolumeHealthWhenTopLevelFlagsLag()
    {
        var payload = new StatusChangedPayload(
            State: RuntimeState.MountedRw,
            MountPoints: ["P:\\"],
            LastError: null,
            TimestampUtc: DateTime.UtcNow,
            Warnings: ["Mounted 'Main' with native write enabled."],
            WriteEnabled: false,
            CompatibilityWarnings: Array.Empty<string>(),
            MountedVolumes:
            [
                new MountedVolumeDisplay(
                    VolumeId: @"\\.\PhysicalDrive2|Main",
                    MountPoint: "P:\\",
                    VolumeName: "Main",
                    DeviceId: @"\\.\PhysicalDrive2",
                    DeviceDisplayName: "APFS drive",
                    AccessMode: MountAccessMode.ReadWrite)
            ],
            NativeWriteSafetyState: NativeWriteSafetyState.ReadOnlyFallback);

        var state = InvokeSelectBalloonState(payload);
        var title = InvokeSelectBalloonTitle(state);

        Assert.Equal(DriveDashboardState.HealthyReadWrite, state);
        Assert.Equal("APFS Access Healthy", title);
    }

    [Fact]
    public void SelectBalloonStateAndTitle_UseReadOnlyVolumeHealthWhenTopLevelFlagsLag()
    {
        var payload = new StatusChangedPayload(
            State: RuntimeState.MountedRw,
            MountPoints: ["P:\\"],
            LastError: null,
            TimestampUtc: DateTime.UtcNow,
            Warnings: ["Mounted 'Main' with native write enabled."],
            WriteEnabled: true,
            CompatibilityWarnings: Array.Empty<string>(),
            MountedVolumes:
            [
                new MountedVolumeDisplay(
                    VolumeId: @"\\.\PhysicalDrive2|Main",
                    MountPoint: "P:\\",
                    VolumeName: "Main",
                    DeviceId: @"\\.\PhysicalDrive2",
                    DeviceDisplayName: "APFS drive",
                    AccessMode: MountAccessMode.ReadOnly)
            ],
            NativeWriteSafetyState: NativeWriteSafetyState.PilotReadWrite);

        var state = InvokeSelectBalloonState(payload);
        var title = InvokeSelectBalloonTitle(state);
        var icon = InvokeSelectBalloonIcon(payload);

        Assert.Equal(DriveDashboardState.ReadOnly, state);
        Assert.Equal("APFS Access Read-only", title);
        Assert.Equal(ToolTipIcon.Warning, icon);
    }

    [Fact]
    public void SelectBalloonStateAndTitle_UseWorstMountedStateForMixedReadWriteMounts()
    {
        var payload = new StatusChangedPayload(
            State: RuntimeState.MountedRw,
            MountPoints: ["P:\\", "Q:\\"],
            LastError: null,
            TimestampUtc: DateTime.UtcNow,
            Warnings: ["Mounted APFS volumes."],
            WriteEnabled: true,
            CompatibilityWarnings: Array.Empty<string>(),
            MountedVolumes:
            [
                new MountedVolumeDisplay(
                    VolumeId: @"\\.\PhysicalDrive2|Main",
                    MountPoint: "P:\\",
                    VolumeName: "Main",
                    DeviceId: @"\\.\PhysicalDrive2",
                    DeviceDisplayName: "APFS drive",
                    AccessMode: MountAccessMode.ReadWrite),
                new MountedVolumeDisplay(
                    VolumeId: @"\\.\PhysicalDrive2|Recovery",
                    MountPoint: "Q:\\",
                    VolumeName: "Recovery",
                    DeviceId: @"\\.\PhysicalDrive2",
                    DeviceDisplayName: "APFS drive",
                    AccessMode: MountAccessMode.ReadOnly)
            ],
            NativeWriteSafetyState: NativeWriteSafetyState.PilotReadWrite);

        var state = InvokeSelectBalloonState(payload);
        var title = InvokeSelectBalloonTitle(state);
        var icon = InvokeSelectBalloonIcon(payload);

        Assert.Equal(DriveDashboardState.ReadOnly, state);
        Assert.Equal("APFS Access Read-only", title);
        Assert.Equal(ToolTipIcon.Warning, icon);
    }

    [Fact]
    public void SelectBalloonStateAndTitle_IgnoreStaleWarningsWhenMountedVolumeIsHealthyReadWrite()
    {
        var payload = new StatusChangedPayload(
            State: RuntimeState.MountedRw,
            MountPoints: ["P:\\"],
            LastError: null,
            TimestampUtc: DateTime.UtcNow,
            Warnings: ["Native write was temporarily unavailable during startup."],
            WriteEnabled: false,
            CompatibilityWarnings:
            [
                "'P:\\' has write incompatibilities: stale startup diagnostic"
            ],
            MountedVolumes:
            [
                new MountedVolumeDisplay(
                    VolumeId: @"\\.\PhysicalDrive2|Main",
                    MountPoint: "P:\\",
                    VolumeName: "Main",
                    DeviceId: @"\\.\PhysicalDrive2",
                    DeviceDisplayName: "APFS drive",
                    AccessMode: MountAccessMode.ReadWrite)
            ],
            NativeWriteSafetyState: NativeWriteSafetyState.ReadOnlyFallback);

        var state = InvokeSelectBalloonState(payload);
        var title = InvokeSelectBalloonTitle(state);
        var icon = InvokeSelectBalloonIcon(payload);

        Assert.Equal(DriveDashboardState.HealthyReadWrite, state);
        Assert.Equal("APFS Access Healthy", title);
        Assert.Equal(ToolTipIcon.Info, icon);
    }

    [Fact]
    public void SelectNotifyIconState_UsesSameHealthStateAsBalloonForStaleWarnings()
    {
        var payload = new StatusChangedPayload(
            State: RuntimeState.MountedRw,
            MountPoints: ["P:\\"],
            LastError: null,
            TimestampUtc: DateTime.UtcNow,
            Warnings: ["Native write was temporarily unavailable during startup."],
            WriteEnabled: false,
            CompatibilityWarnings:
            [
                "'P:\\' has write incompatibilities: stale startup diagnostic"
            ],
            MountedVolumes:
            [
                new MountedVolumeDisplay(
                    VolumeId: @"\\.\PhysicalDrive2|Main",
                    MountPoint: "P:\\",
                    VolumeName: "Main",
                    DeviceId: @"\\.\PhysicalDrive2",
                    DeviceDisplayName: "APFS drive",
                    AccessMode: MountAccessMode.ReadWrite)
            ],
            NativeWriteSafetyState: NativeWriteSafetyState.ReadOnlyFallback);

        var balloonState = InvokeSelectBalloonState(payload);
        var notifyIconState = InvokeSelectNotifyIconState(payload);

        Assert.Equal(DriveDashboardState.HealthyReadWrite, balloonState);
        Assert.Equal(RuntimeState.MountedRw, notifyIconState);
    }

    [Fact]
    public void BuildStatusBalloonWarnings_SuppressesStaleWarningsWhenMountedVolumeIsHealthyReadWrite()
    {
        var payload = new StatusChangedPayload(
            State: RuntimeState.MountedRw,
            MountPoints: ["P:\\"],
            LastError: null,
            TimestampUtc: DateTime.UtcNow,
            Warnings: ["Native write was temporarily unavailable during startup."],
            WriteEnabled: false,
            CompatibilityWarnings:
            [
                "'P:\\' has write incompatibilities: stale startup diagnostic"
            ],
            MountedVolumes:
            [
                new MountedVolumeDisplay(
                    VolumeId: @"\\.\PhysicalDrive2|Main",
                    MountPoint: "P:\\",
                    VolumeName: "Main",
                    DeviceId: @"\\.\PhysicalDrive2",
                    DeviceDisplayName: "APFS drive",
                    AccessMode: MountAccessMode.ReadWrite)
            ],
            NativeWriteSafetyState: NativeWriteSafetyState.ReadOnlyFallback);

        var warnings = InvokeBuildStatusBalloonWarnings(payload);

        Assert.Empty(warnings);
    }

    [Fact]
    public void BuildStatusBalloonWarnings_SuppressesHealthyMountNoticeWhenStateIsStillStarting()
    {
        var payload = new StatusChangedPayload(
            State: RuntimeState.Starting,
            MountPoints: ["P:\\"],
            LastError: null,
            TimestampUtc: DateTime.UtcNow,
            Warnings: ["Mounted 'Main' with native write enabled."],
            WriteEnabled: true,
            CompatibilityWarnings: Array.Empty<string>(),
            NativeWriteSafetyState: NativeWriteSafetyState.PilotReadWrite);

        var warnings = InvokeBuildStatusBalloonWarnings(payload);

        Assert.Empty(warnings);
    }

    [Fact]
    public void BuildNotifyIconText_SuppressesStaleWarningBadgeWhenMountedVolumeIsHealthyReadWrite()
    {
        var payload = new StatusChangedPayload(
            State: RuntimeState.MountedRw,
            MountPoints: ["P:\\"],
            LastError: null,
            TimestampUtc: DateTime.UtcNow,
            Warnings: ["Native write was temporarily unavailable during startup."],
            WriteEnabled: false,
            CompatibilityWarnings:
            [
                "'P:\\' has write incompatibilities: stale startup diagnostic"
            ],
            MountedVolumes:
            [
                new MountedVolumeDisplay(
                    VolumeId: @"\\.\PhysicalDrive2|Main",
                    MountPoint: "P:\\",
                    VolumeName: "Main",
                    DeviceId: @"\\.\PhysicalDrive2",
                    DeviceDisplayName: "APFS drive",
                    AccessMode: MountAccessMode.ReadWrite)
            ],
            RecoveryActive: true,
            RecoveryReason: "CanonicalCommitNotReady",
            NativeWriteSafetyState: NativeWriteSafetyState.RecoveryBlocked);

        var text = InvokeBuildNotifyIconText(payload);

        Assert.Equal("APFS Access: mounted read/write (1)", text);
    }

    [Fact]
    public void BuildStatusBalloonWarnings_KeepsReadOnlyWarningsWhenMountedVolumeIsReadOnly()
    {
        var payload = new StatusChangedPayload(
            State: RuntimeState.MountedRo,
            MountPoints: ["P:\\"],
            LastError: null,
            TimestampUtc: DateTime.UtcNow,
            Warnings: ["Refresh did not restore write access."],
            WriteEnabled: false,
            CompatibilityWarnings: Array.Empty<string>(),
            MountedVolumes:
            [
                new MountedVolumeDisplay(
                    VolumeId: @"\\.\PhysicalDrive2|Main",
                    MountPoint: "P:\\",
                    VolumeName: "Main",
                    DeviceId: @"\\.\PhysicalDrive2",
                    DeviceDisplayName: "APFS drive",
                    AccessMode: MountAccessMode.ReadOnly)
            ],
            NativeWriteSafetyState: NativeWriteSafetyState.ReadOnlyFallback);

        var warnings = InvokeBuildStatusBalloonWarnings(payload);

        Assert.Equal(["Refresh did not restore write access."], warnings);
    }

    [Fact]
    public void BuildStatusBalloonWarnings_SuppressesWarningsWhenMountedVolumeIsFinishingWrites()
    {
        var payload = new StatusChangedPayload(
            State: RuntimeState.MountedRw,
            MountPoints: ["P:\\"],
            LastError: null,
            TimestampUtc: DateTime.UtcNow,
            Warnings: ["Native writes are still being committed."],
            WriteEnabled: true,
            CompatibilityWarnings: Array.Empty<string>(),
            MountedVolumes:
            [
                new MountedVolumeDisplay(
                    VolumeId: @"\\.\PhysicalDrive2|Main",
                    MountPoint: "P:\\",
                    VolumeName: "Main",
                    DeviceId: @"\\.\PhysicalDrive2",
                    DeviceDisplayName: "APFS drive",
                    AccessMode: MountAccessMode.ReadWrite)
            ],
            NativeWriteSafetyState: NativeWriteSafetyState.PilotReadWrite,
            DirtyTransactionCount: 2);

        var state = InvokeSelectBalloonState(payload);
        var icon = InvokeSelectBalloonIcon(payload);
        var warnings = InvokeBuildStatusBalloonWarnings(payload);

        Assert.Equal(DriveDashboardState.FinishingWrites, state);
        Assert.Equal(ToolTipIcon.Info, icon);
        Assert.Empty(warnings);
    }

    [Fact]
    public void SelectBalloonStateAndTitle_IgnoreStaleRecoveryStateWhenMountedVolumeIsHealthyReadWrite()
    {
        var payload = new StatusChangedPayload(
            State: RuntimeState.MountedRw,
            MountPoints: ["P:\\"],
            LastError: null,
            TimestampUtc: DateTime.UtcNow,
            Warnings: ["Native write was temporarily unavailable during startup."],
            WriteEnabled: true,
            CompatibilityWarnings: Array.Empty<string>(),
            MountedVolumes:
            [
                new MountedVolumeDisplay(
                    VolumeId: @"\\.\PhysicalDrive2|Main",
                    MountPoint: "P:\\",
                    VolumeName: "Main",
                    DeviceId: @"\\.\PhysicalDrive2",
                    DeviceDisplayName: "APFS drive",
                    AccessMode: MountAccessMode.ReadWrite)
            ],
            RecoveryActive: true,
            RecoveryReason: "stale startup probe",
            NativeWriteSafetyState: NativeWriteSafetyState.RecoveryBlocked);

        var state = InvokeSelectBalloonState(payload);
        var title = InvokeSelectBalloonTitle(state);
        var icon = InvokeSelectBalloonIcon(payload);

        Assert.Equal(DriveDashboardState.HealthyReadWrite, state);
        Assert.Equal("APFS Access Healthy", title);
        Assert.Equal(ToolTipIcon.Info, icon);
    }

    [Fact]
    public void SelectBalloonStateAndTitle_IgnoreStaleDiagnosticsWhenMountedVolumeIsHealthyReadWrite()
    {
        var payload = new StatusChangedPayload(
            State: RuntimeState.MountedRw,
            MountPoints: ["P:\\"],
            LastError: null,
            TimestampUtc: DateTime.UtcNow,
            Warnings: ["Native write blocked (reason=CanonicalCommitNotReady)"],
            WriteEnabled: false,
            CompatibilityWarnings:
            [
                "'P:\\' has write incompatibilities: stale startup diagnostic"
            ],
            MountedVolumes:
            [
                new MountedVolumeDisplay(
                    VolumeId: @"\\.\PhysicalDrive2|Main",
                    MountPoint: "P:\\",
                    VolumeName: "Main",
                    DeviceId: @"\\.\PhysicalDrive2",
                    DeviceDisplayName: "APFS drive",
                    AccessMode: MountAccessMode.ReadWrite)
            ],
            RecoveryActive: true,
            RecoveryReason: "CanonicalCommitNotReady",
            NativeWriteSafetyState: NativeWriteSafetyState.RecoveryBlocked,
            NativeWriteDiagnostics:
            [
                new NativeWriteDiagnostic(
                    Code: "CanonicalCommitNotReady",
                    Message: "Stale startup diagnostic.",
                    IsFailClosed: true,
                    RecoveryReason: "CanonicalCommitNotReady")
            ]);

        var state = InvokeSelectBalloonState(payload);
        var title = InvokeSelectBalloonTitle(state);
        var icon = InvokeSelectBalloonIcon(payload);
        var notifyIconState = InvokeSelectNotifyIconState(payload);

        Assert.Equal(DriveDashboardState.HealthyReadWrite, state);
        Assert.Equal("APFS Access Healthy", title);
        Assert.Equal(ToolTipIcon.Info, icon);
        Assert.Equal(RuntimeState.MountedRw, notifyIconState);
    }

    [Fact]
    public void SelectBalloonStateAndTitle_UseFinishingWritesForHealthyReadWriteWithDirtyWork()
    {
        var payload = new StatusChangedPayload(
            State: RuntimeState.MountedRw,
            MountPoints: ["P:\\"],
            LastError: null,
            TimestampUtc: DateTime.UtcNow,
            Warnings: ["Native writes are still being committed."],
            WriteEnabled: true,
            CompatibilityWarnings: Array.Empty<string>(),
            MountedVolumes:
            [
                new MountedVolumeDisplay(
                    VolumeId: @"\\.\PhysicalDrive2|Main",
                    MountPoint: "P:\\",
                    VolumeName: "Main",
                    DeviceId: @"\\.\PhysicalDrive2",
                    DeviceDisplayName: "APFS drive",
                    AccessMode: MountAccessMode.ReadWrite)
            ],
            NativeWriteSafetyState: NativeWriteSafetyState.PilotReadWrite,
            DirtyTransactionCount: 2);

        var state = InvokeSelectBalloonState(payload);
        var title = InvokeSelectBalloonTitle(state);
        var icon = InvokeSelectBalloonIcon(payload);

        Assert.Equal(DriveDashboardState.FinishingWrites, state);
        Assert.Equal("APFS Access Finishing Writes", title);
        Assert.Equal(ToolTipIcon.Info, icon);
    }

    [Fact]
    public void SelectActionBalloon_UsesLatestHealthyMountStateForFailureNotice()
    {
        var context = CreateUninitializedContextWithLatestStatus(new StatusChangedPayload(
            State: RuntimeState.MountedRw,
            MountPoints: ["P:\\"],
            LastError: null,
            TimestampUtc: DateTime.UtcNow,
            Warnings: ["Previous stale warning"],
            WriteEnabled: false,
            CompatibilityWarnings: Array.Empty<string>(),
            MountedVolumes:
            [
                new MountedVolumeDisplay(
                    VolumeId: @"\\.\PhysicalDrive2|Main",
                    MountPoint: "P:\\",
                    VolumeName: "Main",
                    DeviceId: @"\\.\PhysicalDrive2",
                    DeviceDisplayName: "APFS drive",
                    AccessMode: MountAccessMode.ReadWrite)
            ],
            NativeWriteSafetyState: NativeWriteSafetyState.ReadOnlyFallback));

        var title = InvokeSelectActionBalloonTitle(context, success: false);
        var icon = InvokeSelectActionBalloonIcon(context, success: false);

        Assert.Equal("APFS Access Healthy", title);
        Assert.Equal(ToolTipIcon.Info, icon);
    }

    [Fact]
    public void SelectActionBalloon_UsesLatestHealthyMountStateForSuccessNotice()
    {
        var context = CreateUninitializedContextWithLatestStatus(new StatusChangedPayload(
            State: RuntimeState.MountedRw,
            MountPoints: ["P:\\"],
            LastError: null,
            TimestampUtc: DateTime.UtcNow,
            Warnings: ["Previous stale warning"],
            WriteEnabled: false,
            CompatibilityWarnings: Array.Empty<string>(),
            MountedVolumes:
            [
                new MountedVolumeDisplay(
                    VolumeId: @"\\.\PhysicalDrive2|Main",
                    MountPoint: "P:\\",
                    VolumeName: "Main",
                    DeviceId: @"\\.\PhysicalDrive2",
                    DeviceDisplayName: "APFS drive",
                    AccessMode: MountAccessMode.ReadWrite)
            ],
            NativeWriteSafetyState: NativeWriteSafetyState.ReadOnlyFallback));

        var title = InvokeSelectActionBalloonTitle(context, success: true);
        var icon = InvokeSelectActionBalloonIcon(context, success: true);

        Assert.Equal("APFS Access Healthy", title);
        Assert.Equal(ToolTipIcon.Info, icon);
    }

    [Fact]
    public void SelectActionFeedback_UsesMountedHealthyStateForSuccessNotice()
    {
        var context = CreateUninitializedContextWithLatestStatus(new StatusChangedPayload(
            State: RuntimeState.MountedRw,
            MountPoints: ["P:\\"],
            LastError: null,
            TimestampUtc: DateTime.UtcNow,
            Warnings: ["Previous stale warning"],
            WriteEnabled: false,
            CompatibilityWarnings: Array.Empty<string>(),
            MountedVolumes:
            [
                new MountedVolumeDisplay(
                    VolumeId: @"\\.\PhysicalDrive2|Main",
                    MountPoint: "P:\\",
                    VolumeName: "Main",
                    DeviceId: @"\\.\PhysicalDrive2",
                    DeviceDisplayName: "APFS drive",
                    AccessMode: MountAccessMode.ReadWrite)
            ],
            NativeWriteSafetyState: NativeWriteSafetyState.ReadOnlyFallback));

        var title = InvokeSelectActionFeedbackTitle(context, success: true, volumeId: @"\\.\PhysicalDrive2|Main");
        var icon = InvokeSelectActionFeedbackIcon(context, success: true, volumeId: @"\\.\PhysicalDrive2|Main");

        Assert.Equal("APFS Access Healthy", title);
        Assert.Equal(ToolTipIcon.Info, icon);
    }

    [Fact]
    public void SelectActionFeedback_UsesReadOnlyStateForSuccessfulActionWhenDriveRemainsReadOnly()
    {
        var context = CreateUninitializedContextWithLatestStatus(new StatusChangedPayload(
            State: RuntimeState.MountedRo,
            MountPoints: ["P:\\"],
            LastError: null,
            TimestampUtc: DateTime.UtcNow,
            Warnings: ["Refresh did not restore write access."],
            WriteEnabled: false,
            CompatibilityWarnings: Array.Empty<string>(),
            MountedVolumes:
            [
                new MountedVolumeDisplay(
                    VolumeId: @"\\.\PhysicalDrive2|Main",
                    MountPoint: "P:\\",
                    VolumeName: "Main",
                    DeviceId: @"\\.\PhysicalDrive2",
                    DeviceDisplayName: "APFS drive",
                    AccessMode: MountAccessMode.ReadOnly)
            ],
            NativeWriteSafetyState: NativeWriteSafetyState.ReadOnlyFallback));

        var title = InvokeSelectActionFeedbackTitle(context, success: true, volumeId: @"\\.\PhysicalDrive2|Main");
        var icon = InvokeSelectActionFeedbackIcon(context, success: true, volumeId: @"\\.\PhysicalDrive2|Main");

        Assert.Equal("APFS Access Read-only", title);
        Assert.Equal(ToolTipIcon.Warning, icon);
    }

    [Fact]
    public void SelectActionFeedback_UsesMountedHealthyStateForFailureNotice()
    {
        var context = CreateUninitializedContextWithLatestStatus(new StatusChangedPayload(
            State: RuntimeState.MountedRw,
            MountPoints: ["P:\\"],
            LastError: null,
            TimestampUtc: DateTime.UtcNow,
            Warnings: ["Refresh request failed, but the selected drive is still healthy."],
            WriteEnabled: false,
            CompatibilityWarnings: Array.Empty<string>(),
            MountedVolumes:
            [
                new MountedVolumeDisplay(
                    VolumeId: @"\\.\PhysicalDrive2|Main",
                    MountPoint: "P:\\",
                    VolumeName: "Main",
                    DeviceId: @"\\.\PhysicalDrive2",
                    DeviceDisplayName: "APFS drive",
                    AccessMode: MountAccessMode.ReadWrite)
            ],
            NativeWriteSafetyState: NativeWriteSafetyState.ReadOnlyFallback));

        var title = InvokeSelectActionFeedbackTitle(context, success: false, volumeId: @"\\.\PhysicalDrive2|Main");
        var icon = InvokeSelectActionFeedbackIcon(context, success: false, volumeId: @"\\.\PhysicalDrive2|Main");

        Assert.Equal("APFS Access Healthy", title);
        Assert.Equal(ToolTipIcon.Info, icon);
    }

    [Fact]
    public void SelectActionFeedback_UsesFinishingWritesStateForFailureNotice()
    {
        var context = CreateUninitializedContextWithLatestStatus(new StatusChangedPayload(
            State: RuntimeState.MountedRw,
            MountPoints: ["P:\\"],
            LastError: null,
            TimestampUtc: DateTime.UtcNow,
            Warnings: ["Previous write drain notice."],
            WriteEnabled: true,
            CompatibilityWarnings: Array.Empty<string>(),
            MountedVolumes:
            [
                new MountedVolumeDisplay(
                    VolumeId: @"\\.\PhysicalDrive2|Main",
                    MountPoint: "P:\\",
                    VolumeName: "Main",
                    DeviceId: @"\\.\PhysicalDrive2",
                    DeviceDisplayName: "APFS drive",
                    AccessMode: MountAccessMode.ReadWrite)
            ],
            NativeWriteSafetyState: NativeWriteSafetyState.StableReadWrite,
            DirtyTransactionCount: 3));

        var title = InvokeSelectActionFeedbackTitle(context, success: false, volumeId: @"\\.\PhysicalDrive2|Main");
        var icon = InvokeSelectActionFeedbackIcon(context, success: false, volumeId: @"\\.\PhysicalDrive2|Main");

        Assert.Equal("APFS Access Finishing Writes", title);
        Assert.Equal(ToolTipIcon.Info, icon);
    }

    [Fact]
    public void SelectActionBalloon_UsesLatestReadOnlyMountStateForFailureNotice()
    {
        var context = CreateUninitializedContextWithLatestStatus(new StatusChangedPayload(
            State: RuntimeState.MountedRo,
            MountPoints: ["P:\\"],
            LastError: null,
            TimestampUtc: DateTime.UtcNow,
            Warnings: ["Refresh did not restore write access."],
            WriteEnabled: false,
            CompatibilityWarnings: Array.Empty<string>(),
            MountedVolumes:
            [
                new MountedVolumeDisplay(
                    VolumeId: @"\\.\PhysicalDrive2|Main",
                    MountPoint: "P:\\",
                    VolumeName: "Main",
                    DeviceId: @"\\.\PhysicalDrive2",
                    DeviceDisplayName: "APFS drive",
                    AccessMode: MountAccessMode.ReadOnly)
            ],
            NativeWriteSafetyState: NativeWriteSafetyState.ReadOnlyFallback));

        var title = InvokeSelectActionBalloonTitle(context, success: false);
        var icon = InvokeSelectActionBalloonIcon(context, success: false);

        Assert.Equal("APFS Access Read-only", title);
        Assert.Equal(ToolTipIcon.Warning, icon);
    }

    [Fact]
    public void SelectActionBalloon_UsesLatestProblemStateForSuccessNotice()
    {
        var context = CreateUninitializedContextWithLatestStatus(new StatusChangedPayload(
            State: RuntimeState.Error,
            MountPoints: Array.Empty<string>(),
            LastError: "Service disconnected.",
            TimestampUtc: DateTime.UtcNow,
            Warnings: ["Service disconnected."],
            WriteEnabled: false,
            CompatibilityWarnings: Array.Empty<string>(),
            NativeWriteSafetyState: NativeWriteSafetyState.RecoveryBlocked));

        var title = InvokeSelectActionBalloonTitle(context, success: true);
        var icon = InvokeSelectActionBalloonIcon(context, success: true);

        Assert.Equal("APFS Access Problem", title);
        Assert.Equal(ToolTipIcon.Error, icon);
    }

    [Fact]
    public void SelectBalloonStateAndTitle_UseProblemForMountedRecoveryBlockedReadOnlyVolume()
    {
        var payload = new StatusChangedPayload(
            State: RuntimeState.MountedRo,
            MountPoints: ["P:\\"],
            LastError: null,
            TimestampUtc: DateTime.UtcNow,
            Warnings: ["Recovery blocked."],
            WriteEnabled: false,
            CompatibilityWarnings: Array.Empty<string>(),
            MountedVolumes:
            [
                new MountedVolumeDisplay(
                    VolumeId: @"\\.\PhysicalDrive2|Main",
                    MountPoint: "P:\\",
                    VolumeName: "Main",
                    DeviceId: @"\\.\PhysicalDrive2",
                    DeviceDisplayName: "APFS drive",
                    AccessMode: MountAccessMode.ReadOnly)
            ],
            RecoveryActive: true,
            RecoveryReason: "checkpoint replay blocked",
            NativeWriteSafetyState: NativeWriteSafetyState.RecoveryBlocked);

        var state = InvokeSelectBalloonState(payload);
        var title = InvokeSelectBalloonTitle(state);
        var icon = InvokeSelectBalloonIcon(payload);

        Assert.Equal(DriveDashboardState.Problem, state);
        Assert.Equal("APFS Access Problem", title);
        Assert.Equal(ToolTipIcon.Error, icon);
    }

    [Theory]
    [InlineData(RuntimeState.MountedRo, NativeWriteSafetyState.ReadOnlyFallback, false, false, ToolTipIcon.Warning)]
    [InlineData(RuntimeState.MountedRw, NativeWriteSafetyState.RecoveryBlocked, true, true, ToolTipIcon.Error)]
    public void SelectBalloonIcon_FollowsMountHealth(
        RuntimeState state,
        NativeWriteSafetyState safety,
        bool recoveryActive,
        bool writeEnabled,
        ToolTipIcon expected)
    {
        var payload = new StatusChangedPayload(
            State: state,
            MountPoints: ["P:\\"],
            LastError: null,
            TimestampUtc: DateTime.UtcNow,
            Warnings: ["Status changed."],
            WriteEnabled: writeEnabled,
            CompatibilityWarnings: Array.Empty<string>(),
            RecoveryActive: recoveryActive,
            NativeWriteSafetyState: safety);

        var icon = InvokeSelectBalloonIcon(payload);

        Assert.Equal(expected, icon);
    }

    [Theory]
    [InlineData(MountAccessMode.ReadWrite, DriveDashboardState.HealthyReadWrite, "APFS Access Healthy", ToolTipIcon.Info)]
    [InlineData(MountAccessMode.ReadOnly, DriveDashboardState.ReadOnly, "APFS Access Read-only", ToolTipIcon.Warning)]
    public void SelectBalloonStateAndTitle_MatchMountedVolumeRowHealth(
        MountAccessMode accessMode,
        DriveDashboardState expectedState,
        string expectedTitle,
        ToolTipIcon expectedIcon)
    {
        var payload = new StatusChangedPayload(
            State: RuntimeState.MountedRw,
            MountPoints: ["P:\\"],
            LastError: null,
            TimestampUtc: DateTime.UtcNow,
            Warnings: ["Previous status warning"],
            WriteEnabled: accessMode == MountAccessMode.ReadWrite,
            CompatibilityWarnings: Array.Empty<string>(),
            MountedVolumes:
            [
                new MountedVolumeDisplay(
                    VolumeId: @"\\.\PhysicalDrive2|Main",
                    MountPoint: "P:\\",
                    VolumeName: "Main",
                    DeviceId: @"\\.\PhysicalDrive2",
                    DeviceDisplayName: "APFS drive",
                    AccessMode: accessMode)
            ],
            NativeWriteSafetyState: accessMode == MountAccessMode.ReadWrite
                ? NativeWriteSafetyState.StableReadWrite
                : NativeWriteSafetyState.ReadOnlyFallback);

        var dashboardState = Assert.Single(DriveDashboardPresenter.BuildRows(payload)).State;
        var balloonState = InvokeSelectBalloonState(payload);
        var title = InvokeSelectBalloonTitle(balloonState);
        var icon = InvokeSelectBalloonIcon(payload);

        Assert.Equal(expectedState, dashboardState);
        Assert.Equal(dashboardState, balloonState);
        Assert.Equal(expectedTitle, title);
        Assert.Equal(expectedIcon, icon);
    }

    [Theory]
    [InlineData(DriveDashboardState.Problem, true)]
    [InlineData(DriveDashboardState.ReadOnly, true)]
    [InlineData(DriveDashboardState.Attention, true)]
    [InlineData(DriveDashboardState.FinishingWrites, false)]
    [InlineData(DriveDashboardState.HealthyReadWrite, false)]
    [InlineData(DriveDashboardState.Idle, false)]
    public void ShouldShowHealthTransitionBalloon_OnlyAnnouncesRecoveryToHealthyReadWrite(
        DriveDashboardState previousState,
        bool expected)
    {
        var actual = InvokeShouldShowHealthTransitionBalloon(
            previousState,
            DriveDashboardState.HealthyReadWrite);

        Assert.Equal(expected, actual);
    }

    [Fact]
    public void ShouldShowHealthTransitionBalloon_DoesNotAnnounceInitialHealthyMount()
    {
        var actual = InvokeShouldShowHealthTransitionBalloon(
            null,
            DriveDashboardState.HealthyReadWrite);

        Assert.False(actual);
    }

    [Fact]
    public void BuildHealthTransitionBalloonMessage_UsesMountedVolumeDriveAndName()
    {
        var payload = new StatusChangedPayload(
            State: RuntimeState.MountedRw,
            MountPoints: ["P:\\"],
            LastError: null,
            TimestampUtc: DateTime.UtcNow,
            Warnings: ["Previous warning"],
            WriteEnabled: true,
            CompatibilityWarnings: Array.Empty<string>(),
            MountedVolumes:
            [
                new MountedVolumeDisplay(
                    VolumeId: @"\\.\PhysicalDrive2|Main",
                    MountPoint: "P:\\",
                    VolumeName: "Main",
                    DeviceId: @"\\.\PhysicalDrive2",
                    DeviceDisplayName: "APFS drive",
                    AccessMode: MountAccessMode.ReadWrite)
            ],
            NativeWriteSafetyState: NativeWriteSafetyState.StableReadWrite);

        var message = InvokeBuildHealthTransitionBalloonMessage(payload);

        Assert.Equal("P: (Main) is mounted with full read/write access.", message);
    }

    [Fact]
    public void BuildEjectMenuDescriptors_UsesDeviceNameDriveAndVolume()
    {
        var payload = new StatusChangedPayload(
            State: RuntimeState.MountedRw,
            MountPoints: ["E:\\"],
            LastError: null,
            TimestampUtc: DateTime.UtcNow,
            Warnings: Array.Empty<string>(),
            WriteEnabled: true,
            CompatibilityWarnings: Array.Empty<string>(),
            MountedVolumes:
            [
                new MountedVolumeDisplay(
                    VolumeId: @"\\.\PhysicalDrive2|Main",
                    MountPoint: "E:\\",
                    VolumeName: "Main",
                    DeviceId: @"\\.\PhysicalDrive2",
                    DeviceDisplayName: "Samsung Flash Drive FIT USB Device",
                    AccessMode: MountAccessMode.ReadWrite)
            ]);

        var descriptors = InvokeBuildEjectMenuDescriptors(payload);

        var descriptor = Assert.Single(descriptors);
        Assert.Equal(@"\\.\PhysicalDrive2|Main", descriptor.VolumeId);
        Assert.Equal("Eject Samsung Flash Drive FIT USB Device (E:, Main)", descriptor.Text);
    }

    [Fact]
    public void BuildEjectMenuDescriptors_FallsBackToMountPointWhenMountedVolumeDetailsMissing()
    {
        var payload = new StatusChangedPayload(
            State: RuntimeState.MountedRo,
            MountPoints: ["E:\\"],
            LastError: null,
            TimestampUtc: DateTime.UtcNow,
            Warnings: Array.Empty<string>(),
            WriteEnabled: false,
            CompatibilityWarnings: Array.Empty<string>(),
            MountedVolumes: Array.Empty<MountedVolumeDisplay>());

        var descriptors = InvokeBuildEjectMenuDescriptors(payload);

        var descriptor = Assert.Single(descriptors);
        Assert.Null(descriptor.VolumeId);
        Assert.Equal("Eject APFS drive E:", descriptor.Text);
    }

    [Fact]
    public void UpdateEjectMenu_PreservesExistingItemsForSemanticallyIdenticalSnapshot()
    {
        using var menuItem = new ToolStripMenuItem("Eject APFS drives");
        var context = (TrayApplicationContext)RuntimeHelpers.GetUninitializedObject(typeof(TrayApplicationContext));
        var ejectField = typeof(TrayApplicationContext).GetField(
            "_ejectItem",
            BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(ejectField);
        ejectField!.SetValue(context, menuItem);

        var payload = NewTwoVolumeMountedPayload();
        InvokeUpdateEjectMenu(context, payload);
        var firstItems = menuItem.DropDownItems.Cast<ToolStripMenuItem>().ToArray();

        InvokeUpdateEjectMenu(context, payload with { TimestampUtc = payload.TimestampUtc.AddSeconds(1) });
        var secondItems = menuItem.DropDownItems.Cast<ToolStripMenuItem>().ToArray();

        Assert.Equal(2, firstItems.Length);
        Assert.Equal(2, secondItems.Length);
        Assert.Same(firstItems[0], secondItems[0]);
        Assert.Same(firstItems[1], secondItems[1]);
    }

    [Fact]
    public void UpdateEjectMenu_RebuildsAndAppliesChangedVolumeDescriptor()
    {
        using var menuItem = new ToolStripMenuItem("Eject APFS drives");
        var context = (TrayApplicationContext)RuntimeHelpers.GetUninitializedObject(typeof(TrayApplicationContext));
        var ejectField = typeof(TrayApplicationContext).GetField(
            "_ejectItem",
            BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(ejectField);
        ejectField!.SetValue(context, menuItem);

        var payload = NewTwoVolumeMountedPayload();
        InvokeUpdateEjectMenu(context, payload);
        var firstItems = menuItem.DropDownItems.Cast<ToolStripMenuItem>().ToArray();
        var changedVolume = payload.MountedVolumes![1] with
        {
            VolumeId = @"\\.\PhysicalDrive2|Photos",
            MountPoint = "G:\\",
            VolumeName = "Photos",
        };

        InvokeUpdateEjectMenu(
            context,
            payload with
            {
                MountPoints = ["E:\\", "G:\\"],
                TimestampUtc = payload.TimestampUtc.AddSeconds(1),
                MountedVolumes = [payload.MountedVolumes[0], changedVolume],
            });
        var changedItems = menuItem.DropDownItems.Cast<ToolStripMenuItem>().ToArray();

        Assert.Equal(2, changedItems.Length);
        Assert.NotSame(firstItems[0], changedItems[0]);
        Assert.NotSame(firstItems[1], changedItems[1]);
        Assert.Equal("Eject Samsung Flash Drive FIT USB Device (G:, Photos)", changedItems[1].Text);
        Assert.Equal(@"\\.\PhysicalDrive2|Photos", changedItems[1].Tag);
    }

    [Fact]
    public void EjectRequestTimeout_CoversBackendStopAndDriveRemovalBudget()
    {
        var timeout = InvokeEjectRequestTimeout();

        Assert.True(timeout >= TimeSpan.FromSeconds(125));
    }

    [Fact]
    public void FixRequestTimeout_AllowsServiceRefreshAndRemountBudget()
    {
        var timeout = InvokeFixRequestTimeout();

        Assert.True(timeout >= TimeSpan.FromSeconds(60));
    }

    [Fact]
    public void ResetEjectMenu_DisablesAndClearsStaleEntries()
    {
        using var menuItem = new ToolStripMenuItem("Eject stale");
        menuItem.Enabled = true;
        menuItem.Tag = @"\\.\PhysicalDrive2|Main";
        menuItem.DropDownItems.Add(new ToolStripMenuItem("Eject stale child"));

        InvokeResetEjectMenu(menuItem);

        Assert.False(menuItem.Enabled);
        Assert.Null(menuItem.Tag);
        Assert.Equal("Eject APFS drives", menuItem.Text);
        Assert.Empty(menuItem.DropDownItems);
    }

    [Fact]
    public void IsCurrentServiceExecutablePath_RejectsDifferentPortablePayload()
    {
        var candidates = new[]
        {
            @"C:\Users\ExampleUser\AppData\Local\ApfsAccessPortable\payload-NEW\ApfsAccess.Service.exe",
        };

        var isCurrent = InvokeIsCurrentServiceExecutablePath(
            @"C:\Users\ExampleUser\AppData\Local\ApfsAccessPortable\payload-OLD\ApfsAccess.Service.exe",
            candidates);

        Assert.False(isCurrent);
    }

    [Fact]
    public void IsCurrentServiceExecutablePath_AcceptsMatchingPayloadWithCaseDifferences()
    {
        var candidates = new[]
        {
            @"C:\Users\ExampleUser\AppData\Local\ApfsAccessPortable\payload-NEW\ApfsAccess.Service.exe",
        };

        var isCurrent = InvokeIsCurrentServiceExecutablePath(
            @"c:\users\exampleuser\appdata\local\apfsaccessportable\payload-new\apfsaccess.service.exe",
            candidates);

        Assert.True(isCurrent);
    }

    private static int InvokeGetWarningPriority(string warning)
    {
        var method = typeof(TrayApplicationContext).GetMethod(
            "GetWarningPriority",
            BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        var result = method!.Invoke(null, [warning]);
        return Assert.IsType<int>(result);
    }

    private static string? InvokeSelectPrimaryRecoveryReason(StatusChangedPayload payload)
    {
        var method = typeof(TrayApplicationContext).GetMethod(
            "SelectPrimaryRecoveryReason",
            BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        var result = method!.Invoke(null, [payload]);
        return result as string;
    }

    private static string InvokeBuildNotifyIconText(StatusChangedPayload payload)
    {
        var method = typeof(TrayApplicationContext).GetMethod(
            "BuildNotifyIconText",
            BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        var result = method!.Invoke(null, [payload]);
        return Assert.IsType<string>(result);
    }

    private static ToolTipIcon InvokeSelectBalloonIcon(StatusChangedPayload payload)
    {
        var method = typeof(TrayApplicationContext).GetMethod(
            "SelectBalloonIcon",
            BindingFlags.NonPublic | BindingFlags.Static,
            binder: null,
            types: [typeof(StatusChangedPayload)],
            modifiers: null);
        Assert.NotNull(method);

        var result = method!.Invoke(null, [payload]);
        return Assert.IsType<ToolTipIcon>(result);
    }

    private static IReadOnlyList<string> InvokeBuildStatusBalloonWarnings(StatusChangedPayload payload)
    {
        var method = typeof(TrayApplicationContext).GetMethod(
            "BuildStatusBalloonWarnings",
            BindingFlags.NonPublic | BindingFlags.Static,
            binder: null,
            types: [typeof(StatusChangedPayload)],
            modifiers: null);
        Assert.NotNull(method);

        var result = method!.Invoke(null, [payload]);
        return Assert.IsAssignableFrom<IReadOnlyList<string>>(result);
    }

    private static RuntimeState InvokeSelectNotifyIconState(StatusChangedPayload payload)
    {
        var method = typeof(TrayApplicationContext).GetMethod(
            "SelectNotifyIconState",
            BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        var result = method!.Invoke(null, [payload]);
        return Assert.IsType<RuntimeState>(result);
    }

    private static Color ReadTrayIconPrimaryColor(string path)
    {
        Assert.True(File.Exists(path), $"Tray icon was not copied to the test output: {path}");
        using var icon = new Icon(path, 256, 256);
        using var bitmap = icon.ToBitmap();
        var colors = new Dictionary<int, (Color Color, int Count)>();
        for (var y = 0; y < bitmap.Height; y++)
        {
            for (var x = 0; x < bitmap.Width; x++)
            {
                var color = bitmap.GetPixel(x, y);
                var channelRange = Math.Max(color.R, Math.Max(color.G, color.B)) -
                    Math.Min(color.R, Math.Min(color.G, color.B));
                if (color.A < 200 || channelRange < 20)
                {
                    continue;
                }

                var key = color.ToArgb();
                colors[key] = colors.TryGetValue(key, out var existing)
                    ? (color, existing.Count + 1)
                    : (color, 1);
            }
        }

        return colors.Values.OrderByDescending(static entry => entry.Count).First().Color;
    }

    private static DriveDashboardState InvokeSelectBalloonState(StatusChangedPayload payload)
    {
        var method = typeof(TrayApplicationContext).GetMethod(
            "SelectBalloonState",
            BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        var result = method!.Invoke(null, [payload]);
        return Assert.IsType<DriveDashboardState>(result);
    }

    private static string InvokeSelectBalloonTitle(DriveDashboardState state)
    {
        var method = typeof(TrayApplicationContext).GetMethod(
            "SelectBalloonTitle",
            BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        var result = method!.Invoke(null, [state]);
        return Assert.IsType<string>(result);
    }

    private static bool InvokeShouldShowHealthTransitionBalloon(
        DriveDashboardState? previousState,
        DriveDashboardState currentState)
    {
        var method = typeof(TrayApplicationContext).GetMethod(
            "ShouldShowHealthTransitionBalloon",
            BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        var result = method!.Invoke(null, [previousState, currentState]);
        return Assert.IsType<bool>(result);
    }

    private static string InvokeBuildHealthTransitionBalloonMessage(StatusChangedPayload payload)
    {
        var method = typeof(TrayApplicationContext).GetMethod(
            "BuildHealthTransitionBalloonMessage",
            BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        var result = method!.Invoke(null, [payload]);
        return Assert.IsType<string>(result);
    }

    private static TrayApplicationContext CreateUninitializedContextWithLatestStatus(StatusChangedPayload payload)
    {
        var context = (TrayApplicationContext)RuntimeHelpers.GetUninitializedObject(typeof(TrayApplicationContext));
        var field = typeof(TrayApplicationContext).GetField(
            "_latestStatus",
            BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(field);

        field!.SetValue(context, payload);
        return context;
    }

    private static string InvokeSelectActionBalloonTitle(TrayApplicationContext context, bool success)
    {
        var method = typeof(TrayApplicationContext).GetMethod(
            "SelectActionBalloonTitle",
            BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(method);

        var result = method!.Invoke(context, [success]);
        return Assert.IsType<string>(result);
    }

    private static string InvokeSelectActionFeedbackTitle(TrayApplicationContext context, bool success, string? volumeId)
    {
        var method = typeof(TrayApplicationContext).GetMethod(
            "SelectActionFeedbackTitle",
            BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(method);

        var result = method!.Invoke(context, [success, volumeId]);
        return Assert.IsType<string>(result);
    }

    private static ToolTipIcon InvokeSelectActionBalloonIcon(TrayApplicationContext context, bool success)
    {
        var method = typeof(TrayApplicationContext).GetMethod(
            "SelectActionBalloonIcon",
            BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(method);

        var result = method!.Invoke(context, [success]);
        return Assert.IsType<ToolTipIcon>(result);
    }

    private static ToolTipIcon InvokeSelectActionFeedbackIcon(TrayApplicationContext context, bool success, string? volumeId)
    {
        var method = typeof(TrayApplicationContext).GetMethod(
            "SelectActionFeedbackIcon",
            BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(method);

        var result = method!.Invoke(context, [success, volumeId]);
        return Assert.IsType<ToolTipIcon>(result);
    }

    private static IReadOnlyList<EjectMenuDescriptor> InvokeBuildEjectMenuDescriptors(StatusChangedPayload payload)
    {
        var method = typeof(TrayApplicationContext).GetMethod(
            "BuildEjectMenuDescriptors",
            BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        var result = method!.Invoke(null, [payload]);
        return Assert.IsAssignableFrom<IReadOnlyList<EjectMenuDescriptor>>(result);
    }

    private static TimeSpan InvokeEjectRequestTimeout()
    {
        var field = typeof(TrayApplicationContext).GetField(
            "EjectRequestTimeout",
            BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(field);

        var result = field!.GetValue(null);
        return Assert.IsType<TimeSpan>(result);
    }

    private static TimeSpan InvokeFixRequestTimeout()
    {
        var field = typeof(TrayApplicationContext).GetField(
            "FixRequestTimeout",
            BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(field);

        var result = field!.GetValue(null);
        return Assert.IsType<TimeSpan>(result);
    }

    private static void InvokeResetEjectMenu(ToolStripMenuItem menuItem)
    {
        var method = typeof(TrayApplicationContext).GetMethod(
            "ResetEjectMenu",
            BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        method!.Invoke(null, [menuItem]);
    }

    private static void InvokeUpdateEjectMenu(TrayApplicationContext context, StatusChangedPayload payload)
    {
        var method = typeof(TrayApplicationContext).GetMethod(
            "UpdateEjectMenu",
            BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(method);

        method!.Invoke(context, [payload]);
    }

    private static StatusChangedPayload NewTwoVolumeMountedPayload()
        => new(
            State: RuntimeState.MountedRw,
            MountPoints: ["E:\\", "F:\\"],
            LastError: null,
            TimestampUtc: DateTime.UtcNow,
            Warnings: Array.Empty<string>(),
            WriteEnabled: true,
            CompatibilityWarnings: Array.Empty<string>(),
            MountedVolumes:
            [
                new MountedVolumeDisplay(
                    VolumeId: @"\\.\PhysicalDrive2|Main",
                    MountPoint: "E:\\",
                    VolumeName: "Main",
                    DeviceId: @"\\.\PhysicalDrive2",
                    DeviceDisplayName: "Samsung Flash Drive FIT USB Device",
                    AccessMode: MountAccessMode.ReadWrite),
                new MountedVolumeDisplay(
                    VolumeId: @"\\.\PhysicalDrive2|Archive",
                    MountPoint: "F:\\",
                    VolumeName: "Archive",
                    DeviceId: @"\\.\PhysicalDrive2",
                    DeviceDisplayName: "Samsung Flash Drive FIT USB Device",
                    AccessMode: MountAccessMode.ReadWrite)
            ]);

    private static bool InvokeIsCurrentServiceExecutablePath(string? executablePath, IEnumerable<string> candidates)
    {
        var method = typeof(TrayApplicationContext).GetMethod(
            "IsCurrentServiceExecutablePath",
            BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        var result = method!.Invoke(null, [executablePath, candidates]);
        return Assert.IsType<bool>(result);
    }

    private static bool InvokeShouldCompleteQuit(bool acknowledged, bool serviceRunning)
    {
        var method = typeof(TrayApplicationContext).GetMethod(
            "ShouldCompleteQuit",
            BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        var result = method!.Invoke(null, [acknowledged, serviceRunning]);
        return Assert.IsType<bool>(result);
    }
}
