using System.Reflection;
using ApfsAccess.Core;
using ApfsAccess.Ipc;
using ApfsAccess.Tray;

namespace ApfsAccess.Tray.Tests;

public sealed class TrayApplicationContextPrioritizationTests
{
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
    [InlineData(RuntimeState.MountedRw, "APFS Access: mounted RW (1)")]
    [InlineData(RuntimeState.MountedRo, "APFS Access: mounted RO (1)")]
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
            @"C:\Users\guosen\AppData\Local\ApfsAccessPortable\payload-NEW\ApfsAccess.Service.exe",
        };

        var isCurrent = InvokeIsCurrentServiceExecutablePath(
            @"C:\Users\guosen\AppData\Local\ApfsAccessPortable\payload-OLD\ApfsAccess.Service.exe",
            candidates);

        Assert.False(isCurrent);
    }

    [Fact]
    public void IsCurrentServiceExecutablePath_AcceptsMatchingPayloadWithCaseDifferences()
    {
        var candidates = new[]
        {
            @"C:\Users\guosen\AppData\Local\ApfsAccessPortable\payload-NEW\ApfsAccess.Service.exe",
        };

        var isCurrent = InvokeIsCurrentServiceExecutablePath(
            @"c:\users\guosen\appdata\local\apfsaccessportable\payload-new\apfsaccess.service.exe",
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

    private static bool InvokeIsCurrentServiceExecutablePath(string? executablePath, IEnumerable<string> candidates)
    {
        var method = typeof(TrayApplicationContext).GetMethod(
            "IsCurrentServiceExecutablePath",
            BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        var result = method!.Invoke(null, [executablePath, candidates]);
        return Assert.IsType<bool>(result);
    }
}
