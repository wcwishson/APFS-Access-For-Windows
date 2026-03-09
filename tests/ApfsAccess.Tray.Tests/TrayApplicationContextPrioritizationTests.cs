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
    public void TryExtractReasonTokenFromWarning_ParsesSupportedReasonPattern(string? warning, string? expected)
    {
        var actual = InvokeTryExtractReasonTokenFromWarning(warning);
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
    [InlineData("ReplayCheckpointPendingWindow", 1)]
    [InlineData("ReplayCheckpointNotPendingWindow", 1)]
    [InlineData("ReplayCanonicalCandidateMissing", 1)]
    [InlineData("CanonicalPathNotActive", 2)]
    [InlineData("WriteGateBlocked", 3)]
    [InlineData("", int.MaxValue)]
    [InlineData(null, int.MaxValue)]
    public void GetRecoveryReasonPriority_PrioritizesCanonicalGateReasons(string? recoveryReason, int expected)
    {
        var actual = InvokeGetRecoveryReasonPriority(recoveryReason);
        Assert.Equal(expected, actual);
    }

    [Theory]
    [InlineData("Write blocked (reason=CanonicalCommitNotReady)", 0)]
    [InlineData("Write blocked (reason=FixtureCompatibilityPathActive)", 0)]
    [InlineData("Write blocked (reason=ScaffoldCommitBlobActive)", 0)]
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

    private static string? InvokeTryExtractReasonTokenFromWarning(string? warning)
    {
        var method = typeof(TrayApplicationContext).GetMethod(
            "TryExtractReasonTokenFromWarning",
            BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        var result = method!.Invoke(null, [warning]);
        return result as string;
    }

    private static int InvokeGetRecoveryReasonPriority(string? recoveryReason)
    {
        var method = typeof(TrayApplicationContext).GetMethod(
            "GetRecoveryReasonPriority",
            BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        var result = method!.Invoke(null, [recoveryReason]);
        return Assert.IsType<int>(result);
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
}
