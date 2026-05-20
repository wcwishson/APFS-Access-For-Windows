using System.Reflection;
using System.Runtime.CompilerServices;
using ApfsAccess.Core;
using ApfsAccess.Service;

namespace ApfsAccess.Service.Tests;

public sealed class ApfsMountWorkerPrioritizationTests
{
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
    public void GetRecoveryReasonPriority_PrioritizesCanonicalGateReasons(string? recoveryReason, int expected)
    {
        var actual = InvokeGetRecoveryReasonPriority(recoveryReason);
        Assert.Equal(expected, actual);
    }

    [Theory]
    [InlineData("Write blocked for 'Macintosh HD' (reason=NativeWriteNotReady)", 0)]
    [InlineData("Write blocked for 'Macintosh HD' (reason=FixtureCompatibilityPathActive)", 0)]
    [InlineData("Write blocked for 'Macintosh HD' (reason=ScaffoldCommitBlobActive)", 0)]
    [InlineData("Write blocked for 'Macintosh HD' (reason=IntegrityMissingAllocationMap)", 1)]
    [InlineData("Write blocked for 'Macintosh HD' (reason=ReplayCheckpointPendingWindow)", 1)]
    [InlineData("Write blocked for 'Macintosh HD' (reason=ReplayCheckpointNotPendingWindow)", 1)]
    [InlineData("Write blocked for 'Macintosh HD' (reason=ReplayCanonicalCandidateMissing)", 1)]
    [InlineData("Write blocked for 'Macintosh HD' (reason=CanonicalPathNotActive)", 2)]
    [InlineData("Write blocked for 'Macintosh HD' (reason=WriteGateBlocked)", 3)]
    [InlineData("Write blocked for 'Macintosh HD'", 4)]
    [InlineData("", int.MaxValue)]
    public void GetCompatibilityWarningPriority_PrioritizesCanonicalReasonTokens(string warning, int expected)
    {
        var actual = InvokeGetCompatibilityWarningPriority(warning);
        Assert.Equal(expected, actual);
    }

    [Fact]
    public void BuildRuntimeCompatibilityWarnings_OrdersCanonicalRecoveryBlocksBeforeGeneralReasons()
    {
        var options = new ServiceHostOptions();
        var mounts = new[]
        {
            new MountedVolumeState(
                VolumeId: @"\\.\PhysicalDrive3|general",
                MountPoint: "A:\\",
                AccessMode: MountAccessMode.ReadOnly,
                WriteBackend: "Native",
                NativeWriteReadiness: NativeWriteReadiness.Degraded,
                RecoveryActive: true,
                RecoveryReason: "WriteGateBlocked",
                NativeWriteSafetyState: NativeWriteSafetyState.RecoveryBlocked,
                LastRecoveryAction: "DowngradedAfterWriteGateBlocked"),
            new MountedVolumeState(
                VolumeId: @"\\.\PhysicalDrive3|canonical",
                MountPoint: "Z:\\",
                AccessMode: MountAccessMode.ReadOnly,
                WriteBackend: "Native",
                NativeWriteReadiness: NativeWriteReadiness.MutationReady,
                RecoveryActive: true,
                RecoveryReason: "CanonicalCommitNotReady",
                NativeWriteSafetyState: NativeWriteSafetyState.RecoveryBlocked,
                LastRecoveryAction: "DowngradedAfterCanonicalGateFailure"),
        };

        var warnings = InvokeBuildRuntimeCompatibilityWarnings(mounts, options);

        Assert.Equal(2, warnings.Count);
        Assert.Contains("Native write is safety-blocked for 'Z:\\'", warnings[0]);
        Assert.Contains("reason=CanonicalCommitNotReady", warnings[0]);
        Assert.Contains("Native write is safety-blocked for 'A:\\'", warnings[1]);
        Assert.Contains("reason=WriteGateBlocked", warnings[1]);
    }

    [Fact]
    public void BuildRuntimeCompatibilityWarnings_OrdersByDiagnosticFallbackRecoveryReason()
    {
        var options = new ServiceHostOptions();
        var mounts = new[]
        {
            new MountedVolumeState(
                VolumeId: @"\\.\PhysicalDrive7|general",
                MountPoint: "A:\\",
                AccessMode: MountAccessMode.ReadOnly,
                WriteBackend: "Native",
                NativeWriteReadiness: NativeWriteReadiness.Degraded,
                RecoveryActive: true,
                RecoveryReason: "WriteGateBlocked",
                NativeWriteSafetyState: NativeWriteSafetyState.RecoveryBlocked,
                LastRecoveryAction: "DowngradedAfterWriteGateBlocked"),
            new MountedVolumeState(
                VolumeId: @"\\.\PhysicalDrive7|diag",
                MountPoint: "Z:\\",
                AccessMode: MountAccessMode.ReadOnly,
                WriteBackend: "Native",
                NativeWriteReadiness: NativeWriteReadiness.MutationReady,
                RecoveryActive: true,
                RecoveryReason: null,
                NativeWriteSafetyState: NativeWriteSafetyState.RecoveryBlocked,
                NativeWriteDiagnostics:
                [
                    new NativeWriteDiagnostic(
                        Code: "NativeWriteCanonicalCommitNotReady",
                        Message: "Commit path is not canonical-ready.",
                        IsFailClosed: true,
                        Scope: "Runtime:Recovery",
                        RecoveryReason: "CanonicalCommitNotReady",
                        RecoveryAction: "DowngradedAfterCanonicalGateFailure")
                ]),
        };

        var warnings = InvokeBuildRuntimeCompatibilityWarnings(mounts, options);

        Assert.Equal(2, warnings.Count);
        Assert.Contains("Native write is safety-blocked for 'Z:\\'", warnings[0]);
        Assert.Contains("reason=CanonicalCommitNotReady", warnings[0]);
        Assert.Contains("Native write is safety-blocked for 'A:\\'", warnings[1]);
        Assert.Contains("reason=WriteGateBlocked", warnings[1]);
    }

    [Fact]
    public void BuildRuntimeCompatibilityWarnings_PrioritizesReplayCandidateMissingBeforeCanonicalPathProofMissing()
    {
        var options = new ServiceHostOptions();
        var mounts = new[]
        {
            new MountedVolumeState(
                VolumeId: @"\\.\PhysicalDrive9|canonical-path",
                MountPoint: "A:\\",
                AccessMode: MountAccessMode.ReadOnly,
                WriteBackend: "Native",
                NativeWriteReadiness: NativeWriteReadiness.Degraded,
                RecoveryActive: true,
                RecoveryReason: "CanonicalPathNotActive",
                NativeWriteSafetyState: NativeWriteSafetyState.RecoveryBlocked,
                LastRecoveryAction: "DowngradedAfterCanonicalPathProofMissing"),
            new MountedVolumeState(
                VolumeId: @"\\.\PhysicalDrive9|replay-candidate",
                MountPoint: "Z:\\",
                AccessMode: MountAccessMode.ReadOnly,
                WriteBackend: "Native",
                NativeWriteReadiness: NativeWriteReadiness.Degraded,
                RecoveryActive: true,
                RecoveryReason: "ReplayCanonicalCandidateMissing",
                NativeWriteSafetyState: NativeWriteSafetyState.RecoveryBlocked,
                LastRecoveryAction: "ReplaySkippedFailClosed"),
        };

        var warnings = InvokeBuildRuntimeCompatibilityWarnings(mounts, options);

        Assert.Equal(2, warnings.Count);
        Assert.Contains("Native write is safety-blocked for 'Z:\\'", warnings[0]);
        Assert.Contains("reason=ReplayCanonicalCandidateMissing", warnings[0]);
        Assert.Contains("Native write is safety-blocked for 'A:\\'", warnings[1]);
        Assert.Contains("reason=CanonicalPathNotActive", warnings[1]);
    }

    [Fact]
    public void BuildRuntimeCompatibilityWarnings_IncludesShutdownDrainPressureSummary()
    {
        var options = new ServiceHostOptions();
        var mounts = new[]
        {
            new MountedVolumeState(
                VolumeId: @"\\.\PhysicalDrive3|one",
                MountPoint: "P:\\",
                AccessMode: MountAccessMode.ReadOnly,
                WriteBackend: "Native",
                NativeWriteReadiness: NativeWriteReadiness.MutationReady,
                ShutdownDrainActive: true,
                InFlightMutationCallbacks: 3),
            new MountedVolumeState(
                VolumeId: @"\\.\PhysicalDrive3|two",
                MountPoint: "Q:\\",
                AccessMode: MountAccessMode.ReadOnly,
                WriteBackend: "Native",
                NativeWriteReadiness: NativeWriteReadiness.MutationReady,
                ShutdownDrainActive: true,
                InFlightMutationCallbacks: 2),
        };

        var warnings = InvokeBuildRuntimeCompatibilityWarnings(mounts, options);

        var drainWarning = Assert.Single(warnings, static x => x.Contains("Native shutdown drain is active for", StringComparison.OrdinalIgnoreCase));
        Assert.Contains("P:\\, Q:\\", drainWarning);
        Assert.Contains("in-flight=5", drainWarning);
    }

    [Fact]
    public void BuildRuntimeCompatibilityWarnings_UsesDiagnosticRecoveryReasonAndAction_WhenMountReasonMissing()
    {
        var options = new ServiceHostOptions();
        var mounts = new[]
        {
            new MountedVolumeState(
                VolumeId: @"\\.\PhysicalDrive4|one",
                MountPoint: "R:\\",
                AccessMode: MountAccessMode.ReadOnly,
                WriteBackend: "Native",
                NativeWriteReadiness: NativeWriteReadiness.MutationReady,
                RecoveryActive: true,
                RecoveryReason: null,
                NativeWriteSafetyState: NativeWriteSafetyState.RecoveryBlocked,
                NativeWriteDiagnostics:
                [
                    new NativeWriteDiagnostic(
                        Code: "NativeWriteCanonicalPathNotActive",
                        Message: "Canonical proof missing.",
                        IsFailClosed: true,
                        Scope: "Runtime:Recovery",
                        RecoveryReason: "CanonicalPathNotActive",
                        RecoveryAction: "DowngradedAfterCanonicalPathProofMissing")
                ]),
        };

        var warnings = InvokeBuildRuntimeCompatibilityWarnings(mounts, options);
        var warning = Assert.Single(warnings);
        Assert.Contains("reason=CanonicalPathNotActive", warning);
        Assert.Contains("action=DowngradedAfterCanonicalPathProofMissing", warning);
    }

    [Fact]
    public void ResolveWriteTelemetry_SelectsPrimaryRecoveryByReasonPriorityBeforeReadiness()
    {
        var mounts = new[]
        {
            new MountedVolumeState(
                VolumeId: @"\\.\PhysicalDrive3|general",
                MountPoint: "A:\\",
                AccessMode: MountAccessMode.ReadOnly,
                WriteBackend: "Native",
                NativeWriteReadiness: NativeWriteReadiness.Degraded,
                RecoveryActive: true,
                RecoveryReason: "WriteGateBlocked",
                NativeWriteSafetyState: NativeWriteSafetyState.RecoveryBlocked,
                LastRecoveryAction: "DowngradedAfterWriteGateBlocked"),
            new MountedVolumeState(
                VolumeId: @"\\.\PhysicalDrive3|canonical",
                MountPoint: "Z:\\",
                AccessMode: MountAccessMode.ReadOnly,
                WriteBackend: "Native",
                NativeWriteReadiness: NativeWriteReadiness.MutationReady,
                RecoveryActive: true,
                RecoveryReason: "NativeWriteNotReady",
                NativeWriteSafetyState: NativeWriteSafetyState.RecoveryBlocked,
                LastRecoveryAction: "DowngradedAfterCanonicalGateFailure"),
        };

        var telemetry = InvokeResolveWriteTelemetry(mounts);

        Assert.Equal("Native", GetTupleItem<string>(telemetry, 0));
        Assert.True(GetTupleItem<bool>(telemetry, 7));
        Assert.Equal("NativeWriteNotReady", GetTupleItem<string?>(telemetry, 8));
        Assert.Equal("DowngradedAfterCanonicalGateFailure", GetTupleItem<string?>(telemetry, 13));
    }

    [Fact]
    public void ResolveWriteTelemetry_PrioritizesDiagnosticFallbackReasonAcrossMounts()
    {
        var mounts = new[]
        {
            new MountedVolumeState(
                VolumeId: @"\\.\PhysicalDrive8|general",
                MountPoint: "A:\\",
                AccessMode: MountAccessMode.ReadOnly,
                WriteBackend: "Native",
                NativeWriteReadiness: NativeWriteReadiness.Degraded,
                RecoveryActive: true,
                RecoveryReason: "WriteGateBlocked",
                NativeWriteSafetyState: NativeWriteSafetyState.RecoveryBlocked,
                LastRecoveryAction: "DowngradedAfterWriteGateBlocked"),
            new MountedVolumeState(
                VolumeId: @"\\.\PhysicalDrive8|diag",
                MountPoint: "Z:\\",
                AccessMode: MountAccessMode.ReadOnly,
                WriteBackend: "Native",
                NativeWriteReadiness: NativeWriteReadiness.MutationReady,
                RecoveryActive: true,
                RecoveryReason: null,
                LastRecoveryAction: null,
                NativeWriteSafetyState: NativeWriteSafetyState.RecoveryBlocked,
                NativeWriteDiagnostics:
                [
                    new NativeWriteDiagnostic(
                        Code: "NativeWriteCommitPathNotReady",
                        Message: "Commit path is not ready.",
                        IsFailClosed: true,
                        Scope: "Runtime:Recovery",
                        RecoveryReason: "CommitPathNotReady",
                        RecoveryAction: "DowngradedAfterCanonicalGateFailure")
                ]),
        };

        var telemetry = InvokeResolveWriteTelemetry(mounts);

        Assert.Equal("CommitPathNotReady", GetTupleItem<string?>(telemetry, 8));
        Assert.Equal("DowngradedAfterCanonicalGateFailure", GetTupleItem<string?>(telemetry, 13));
    }

    [Fact]
    public void ResolveWriteTelemetry_ForEqualPriorityPrefersHigherReadinessThenMountPoint()
    {
        var mounts = new[]
        {
            new MountedVolumeState(
                VolumeId: @"\\.\PhysicalDrive3|lower",
                MountPoint: "A:\\",
                AccessMode: MountAccessMode.ReadOnly,
                WriteBackend: "Native",
                NativeWriteReadiness: NativeWriteReadiness.MutationReady,
                RecoveryActive: true,
                RecoveryReason: "CommitPathNotReady",
                NativeWriteSafetyState: NativeWriteSafetyState.RecoveryBlocked,
                LastRecoveryAction: "LowerReadinessAction"),
            new MountedVolumeState(
                VolumeId: @"\\.\PhysicalDrive3|higher",
                MountPoint: "Z:\\",
                AccessMode: MountAccessMode.ReadOnly,
                WriteBackend: "Native",
                NativeWriteReadiness: NativeWriteReadiness.Degraded,
                RecoveryActive: true,
                RecoveryReason: "CommitPathNotReady",
                NativeWriteSafetyState: NativeWriteSafetyState.RecoveryBlocked,
                LastRecoveryAction: "HigherReadinessAction"),
        };

        var telemetry = InvokeResolveWriteTelemetry(mounts);

        Assert.Equal("CommitPathNotReady", GetTupleItem<string?>(telemetry, 8));
        Assert.Equal("HigherReadinessAction", GetTupleItem<string?>(telemetry, 13));
    }

    [Fact]
    public void ResolveWriteTelemetry_AggregatesDirtyInflightAndShutdownSignals()
    {
        var mounts = new[]
        {
            new MountedVolumeState(
                VolumeId: @"\\.\PhysicalDrive3|one",
                MountPoint: "P:\\",
                AccessMode: MountAccessMode.ReadOnly,
                WriteBackend: "Native",
                NativeWriteReadiness: NativeWriteReadiness.MutationReady,
                RecoveryActive: false,
                NativeWriteSafetyState: NativeWriteSafetyState.ReadOnlyFallback,
                DirtyTransactionCount: 3,
                ShutdownDrainActive: false,
                InFlightMutationCallbacks: 2),
            new MountedVolumeState(
                VolumeId: @"\\.\PhysicalDrive3|two",
                MountPoint: "Q:\\",
                AccessMode: MountAccessMode.ReadOnly,
                WriteBackend: "Native",
                NativeWriteReadiness: NativeWriteReadiness.MutationReady,
                RecoveryActive: false,
                NativeWriteSafetyState: NativeWriteSafetyState.ReadOnlyFallback,
                DirtyTransactionCount: 5,
                ShutdownDrainActive: true,
                InFlightMutationCallbacks: 4),
        };

        var telemetry = InvokeResolveWriteTelemetry(mounts);

        Assert.Equal(8, GetTupleItem<int>(telemetry, 14));
        Assert.True(GetTupleItem<bool>(telemetry, 15));
        Assert.Equal(6, GetTupleItem<int>(telemetry, 16));
    }

    [Fact]
    public void ResolveWriteTelemetry_AggregatesExtendedValidationEvidenceAndLatestProfile()
    {
        var mounts = new[]
        {
            new MountedVolumeState(
                VolumeId: @"\\.\PhysicalDrive3|one",
                MountPoint: "P:\\",
                AccessMode: MountAccessMode.ReadOnly,
                WriteBackend: "Native",
                NativeWriteReadiness: NativeWriteReadiness.MutationReady,
                NativeWriteValidationEvidence: new NativeWriteValidationEvidence(
                    CrashFaultPasses: 6,
                    CrashStageMatrixPasses: 4,
                    HardwarePilotPasses: 3,
                    HotUnplugPasses: 2,
                    MacOsValidationPasses: 2,
                    MacOsConsistencyPasses: 1,
                    PowerLossReplayPasses: 1,
                    PowerLossPassVerified: false,
                    LastValidatedUtc: DateTime.Parse("2026-02-25T08:30:00Z").ToUniversalTime(),
                    LastValidationProfileId: "profile-old")),
            new MountedVolumeState(
                VolumeId: @"\\.\PhysicalDrive3|two",
                MountPoint: "Q:\\",
                AccessMode: MountAccessMode.ReadOnly,
                WriteBackend: "Native",
                NativeWriteReadiness: NativeWriteReadiness.MutationReady,
                NativeWriteValidationEvidence: new NativeWriteValidationEvidence(
                    CrashFaultPasses: 2,
                    CrashStageMatrixPasses: 5,
                    HardwarePilotPasses: 4,
                    HotUnplugPasses: 3,
                    MacOsValidationPasses: 3,
                    MacOsConsistencyPasses: 2,
                    PowerLossReplayPasses: 2,
                    PowerLossPassVerified: true,
                    LastValidatedUtc: DateTime.Parse("2026-02-26T09:15:00Z").ToUniversalTime(),
                    LastValidationProfileId: "profile-new")),
        };

        var telemetry = InvokeResolveWriteTelemetry(mounts);
        var aggregated = GetTupleItem<NativeWriteValidationEvidence>(telemetry, 5);

        Assert.Equal(6, aggregated.CrashFaultPasses);
        Assert.Equal(5, aggregated.CrashStageMatrixPasses);
        Assert.Equal(4, aggregated.HardwarePilotPasses);
        Assert.Equal(3, aggregated.HotUnplugPasses);
        Assert.Equal(3, aggregated.MacOsValidationPasses);
        Assert.Equal(2, aggregated.MacOsConsistencyPasses);
        Assert.Equal(2, aggregated.PowerLossReplayPasses);
        Assert.True(aggregated.PowerLossPassVerified);
        Assert.Equal(DateTime.Parse("2026-02-26T09:15:00Z").ToUniversalTime(), aggregated.LastValidatedUtc);
        Assert.Equal("profile-new", aggregated.LastValidationProfileId);
    }

    [Fact]
    public void ResolveWriteTelemetry_UsesDiagnosticRecoveryReasonAndActionFallback()
    {
        var mounts = new[]
        {
            new MountedVolumeState(
                VolumeId: @"\\.\PhysicalDrive6|diag",
                MountPoint: "S:\\",
                AccessMode: MountAccessMode.ReadOnly,
                WriteBackend: "Native",
                NativeWriteReadiness: NativeWriteReadiness.MutationReady,
                RecoveryActive: true,
                RecoveryReason: null,
                LastRecoveryAction: null,
                NativeWriteSafetyState: NativeWriteSafetyState.RecoveryBlocked,
                NativeWriteDiagnostics:
                [
                    new NativeWriteDiagnostic(
                        Code: "NativeWriteCanonicalPathNotActive",
                        Message: "Canonical proof missing.",
                        IsFailClosed: true,
                        Scope: "Runtime:Recovery",
                        RecoveryReason: "CanonicalPathNotActive",
                        RecoveryAction: "DowngradedAfterCanonicalPathProofMissing")
                ]),
        };

        var telemetry = InvokeResolveWriteTelemetry(mounts);
        Assert.Equal("CanonicalPathNotActive", GetTupleItem<string?>(telemetry, 8));
        Assert.Equal("DowngradedAfterCanonicalPathProofMissing", GetTupleItem<string?>(telemetry, 13));
    }

    [Fact]
    public void ResolveWriteTelemetry_FallsBackToDiagnosticActionFromPrioritizedRecoveryMount()
    {
        var mounts = new[]
        {
            new MountedVolumeState(
                VolumeId: @"\\.\PhysicalDrive9|general",
                MountPoint: "A:\\",
                AccessMode: MountAccessMode.ReadOnly,
                WriteBackend: "Native",
                NativeWriteReadiness: NativeWriteReadiness.Degraded,
                RecoveryActive: true,
                RecoveryReason: "WriteGateBlocked",
                LastRecoveryAction: null,
                NativeWriteSafetyState: NativeWriteSafetyState.RecoveryBlocked,
                NativeWriteDiagnostics:
                [
                    new NativeWriteDiagnostic(
                        Code: "NativeWriteWriteGateBlocked",
                        Message: "Write gate blocked.",
                        IsFailClosed: true,
                        Scope: "Runtime:Recovery",
                        RecoveryReason: "WriteGateBlocked",
                        RecoveryAction: "DowngradedAfterWriteGateBlocked")
                ]),
            new MountedVolumeState(
                VolumeId: @"\\.\PhysicalDrive9|diag",
                MountPoint: "Z:\\",
                AccessMode: MountAccessMode.ReadOnly,
                WriteBackend: "Native",
                NativeWriteReadiness: NativeWriteReadiness.MutationReady,
                RecoveryActive: true,
                RecoveryReason: null,
                LastRecoveryAction: null,
                NativeWriteSafetyState: NativeWriteSafetyState.RecoveryBlocked,
                NativeWriteDiagnostics:
                [
                    new NativeWriteDiagnostic(
                        Code: "NativeWriteCanonicalCommitNotReady",
                        Message: "Canonical commit not ready.",
                        IsFailClosed: true,
                        Scope: "Runtime:Recovery",
                        RecoveryReason: "CanonicalCommitNotReady",
                        RecoveryAction: "DowngradedAfterCanonicalGateFailure")
                ]),
        };

        var telemetry = InvokeResolveWriteTelemetry(mounts);

        Assert.Equal("CanonicalCommitNotReady", GetTupleItem<string?>(telemetry, 8));
        Assert.Equal("DowngradedAfterCanonicalGateFailure", GetTupleItem<string?>(telemetry, 13));
    }

    private static IReadOnlyList<string> InvokeBuildRuntimeCompatibilityWarnings(
        IReadOnlyList<MountedVolumeState> mounts,
        ServiceHostOptions options)
    {
        var method = typeof(ApfsMountWorker).GetMethod(
            "BuildRuntimeCompatibilityWarnings",
            BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        var result = method!.Invoke(null, [mounts, options]);
        Assert.NotNull(result);
        return Assert.IsAssignableFrom<IReadOnlyList<string>>(result);
    }

    private static int InvokeGetRecoveryReasonPriority(string? recoveryReason)
    {
        var method = typeof(ApfsMountWorker).GetMethod(
            "GetRecoveryReasonPriority",
            BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        var result = method!.Invoke(null, [recoveryReason]);
        return Assert.IsType<int>(result);
    }

    private static int InvokeGetCompatibilityWarningPriority(string warning)
    {
        var method = typeof(ApfsMountWorker).GetMethod(
            "GetCompatibilityWarningPriority",
            BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        var result = method!.Invoke(null, [warning]);
        return Assert.IsType<int>(result);
    }

    private static ITuple InvokeResolveWriteTelemetry(IReadOnlyList<MountedVolumeState> mounts)
    {
        var method = typeof(ApfsMountWorker).GetMethod(
            "ResolveWriteTelemetry",
            BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        var result = method!.Invoke(null, [mounts]);
        Assert.NotNull(result);

        return Assert.IsAssignableFrom<ITuple>(result);
    }

    private static T GetTupleItem<T>(ITuple tuple, int index)
    {
        var value = tuple[index];
        if (value is null)
        {
            return default!;
        }

        return Assert.IsType<T>(value);
    }
}
