using System.Reflection;
using ApfsAccess.Backend.Native;
using ApfsAccess.Core;

namespace ApfsAccess.Backend.Native.Tests;

public sealed class NativeApfsBackendRuntimeStatusTests
{
    [Fact]
    public async Task ReadHostRuntimeStatusAsync_ReturnsFallback_WhenStatusFileMissing()
    {
        var missingPath = Path.Combine(Path.GetTempPath(), $"apfsaccess_missing_{Guid.NewGuid():N}.status.json");
        var status = await InvokeReadHostRuntimeStatusAsync(
            statusFilePath: missingPath,
            accessMode: MountAccessMode.ReadWrite,
            configuredWriteBackend: "Native",
            timeout: TimeSpan.FromMilliseconds(220));

        Assert.Equal("Native", status.WriteBackend);
        Assert.Equal(NativeWriteReadiness.BootstrapReady, status.NativeWriteReadiness);
        Assert.Equal(NativeWriteValidationState.Scaffold, status.NativeWriteValidationState);
        Assert.False(status.RecoveryActive);
        Assert.Null(status.RecoveryReason);
        Assert.Null(status.LastCommitXid);
        Assert.Equal(NativeWriteSafetyState.PilotReadWrite, status.NativeWriteSafetyState);
        Assert.Null(status.LastRecoveryAction);
        Assert.Equal(0, status.DirtyTransactionCount);
        Assert.False(status.ShutdownDrainActive);
        Assert.Equal(0, status.InFlightMutationCallbacks);
        Assert.Equal(0, status.HostProcessId);
    }

    [Fact]
    public async Task ReadHostRuntimeStatusAsync_NormalizesNativePayloadValues()
    {
        using var statusFile = new TemporaryStatusFile("""
            {
              "writeBackend": " native ",
              "nativeWriteReadiness": " commitready ",
              "nativeWriteValidationState": " canonicalimagevalidated ",
              "nativeWriteSafetyState": " pilotreadwrite ",
              "recoveryActive": true,
              "recoveryReason": "  RecoveryMarkerDirty  ",
              "lastCommitXid": 77,
              "lastRecoveryAction": "ReplaySkippedFailClosed",
              "dirtyTransactionCount": 9,
              "shutdownDrainActive": true,
              "inFlightMutationCallbacks": 4,
              "validationCrashFaultPasses": 3,
              "validationCrashStageMatrixPasses": 4,
              "validationHardwarePilotPasses": 5,
              "validationHotUnplugPasses": 6,
              "validationMacOsValidationPasses": 7,
              "validationMacOsConsistencyPasses": 8,
              "validationPowerLossReplayPasses": 9,
              "validationPowerLossPassVerified": true,
              "validationLastValidatedUtc": "2026-02-24T01:02:03Z",
              "validationLastValidationProfileId": "raw::pd3::main",
              "fixtureLegacyFallbackActive": true,
              "fixtureCompatibilityPathActive": true,
              "usesScaffoldCommitBlob": true,
              "commitStage": " before-checkpoint-switch ",
              "replayStage": " replay-before-checkpoint-switch ",
              "commitBlobMagic": " APFSRWCANON3 ",
              "canonicalPathActive": false,
              "canonicalGateFailure": " CanonicalStateNotLoaded ",
              "replayCheckpointCandidatePresent": true,
              "replayCheckpointPendingWindow": false
            }
            """);

        var status = await InvokeReadHostRuntimeStatusAsync(
            statusFilePath: statusFile.Path,
            accessMode: MountAccessMode.ReadWrite,
            configuredWriteBackend: "Overlay",
            timeout: TimeSpan.FromMilliseconds(220));

        Assert.Equal("Native", status.WriteBackend);
        Assert.Equal(NativeWriteReadiness.CommitReady, status.NativeWriteReadiness);
        Assert.Equal(NativeWriteValidationState.Scaffold, status.NativeWriteValidationState);
        Assert.True(status.RecoveryActive);
        Assert.Equal("RecoveryMarkerDirty", status.RecoveryReason);
        Assert.Equal((ulong)77, status.LastCommitXid);
        Assert.Equal(NativeWriteSafetyState.RecoveryBlocked, status.NativeWriteSafetyState);
        Assert.Equal("ReplaySkippedFailClosed", status.LastRecoveryAction);
        Assert.Equal(9, status.DirtyTransactionCount);
        Assert.True(status.ShutdownDrainActive);
        Assert.Equal(4, status.InFlightMutationCallbacks);
        Assert.NotNull(status.ValidationEvidence);
        Assert.Equal(3, status.ValidationEvidence!.CrashFaultPasses);
        Assert.Equal(4, status.ValidationEvidence.CrashStageMatrixPasses);
        Assert.Equal(5, status.ValidationEvidence.HardwarePilotPasses);
        Assert.Equal(6, status.ValidationEvidence.HotUnplugPasses);
        Assert.Equal(7, status.ValidationEvidence.MacOsValidationPasses);
        Assert.Equal(8, status.ValidationEvidence.MacOsConsistencyPasses);
        Assert.Equal(9, status.ValidationEvidence.PowerLossReplayPasses);
        Assert.True(status.ValidationEvidence.PowerLossPassVerified);
        Assert.Equal(DateTime.Parse("2026-02-24T01:02:03Z").ToUniversalTime(), status.ValidationEvidence.LastValidatedUtc);
        Assert.Equal("raw::pd3::main", status.ValidationEvidence.LastValidationProfileId);
        Assert.True(status.FixtureLegacyFallbackActive);
        Assert.True(status.FixtureCompatibilityPathActive);
        Assert.True(status.UsesScaffoldCommitBlob);
        Assert.Equal("before-checkpoint-switch", status.CommitStage);
        Assert.Equal("replay-before-checkpoint-switch", status.ReplayStage);
        Assert.Equal("APFSRWCANON3", status.CommitBlobMagic);
        Assert.False(status.CanonicalPathActive);
        Assert.Equal("CanonicalStateNotLoaded", status.CanonicalGateFailure);
        Assert.True(status.ReplayCheckpointCandidatePresent);
        Assert.False(status.ReplayCheckpointPendingWindow);
    }

    [Theory]
    [InlineData("ScaffoldCheckpoint", "CommitReady", false)]
    [InlineData("CanonicalApfsCheckpoint", "BootstrapReady", false)]
    [InlineData("CanonicalApfsCheckpoint", "CommitReady", true)]
    public async Task ReadHostRuntimeStatusAsync_ClampsReportedValidationState_WhenCanonicalEligibilityMissing(
        string commitModel,
        string readiness,
        bool recoveryActive)
    {
        using var statusFile = new TemporaryStatusFile($$"""
            {
              "writeBackend": "Native",
              "commitModel": "{{commitModel}}",
              "nativeWriteReadiness": "{{readiness}}",
              "nativeWriteValidationState": "Stable",
              "recoveryActive": {{(recoveryActive ? "true" : "false")}},
              "lastCommitXid": 79
            }
            """);

        var status = await InvokeReadHostRuntimeStatusAsync(
            statusFilePath: statusFile.Path,
            accessMode: MountAccessMode.ReadWrite,
            configuredWriteBackend: "Native",
            timeout: TimeSpan.FromMilliseconds(220));

        Assert.Equal("Native", status.WriteBackend);
        Assert.Equal(NativeWriteValidationState.Scaffold, status.NativeWriteValidationState);
        Assert.Equal((ulong)79, status.LastCommitXid);
    }

    [Fact]
    public async Task ReadHostRuntimeStatusAsync_UnknownBackendFallsBackToOverlayAndClampsReadiness()
    {
        using var statusFile = new TemporaryStatusFile("""
            {
              "writeBackend": "mystery",
              "nativeWriteReadiness": "CommitReady",
              "recoveryActive": false,
              "lastCommitXid": 10
            }
            """);

        var status = await InvokeReadHostRuntimeStatusAsync(
            statusFilePath: statusFile.Path,
            accessMode: MountAccessMode.ReadWrite,
            configuredWriteBackend: "Overlay",
            timeout: TimeSpan.FromMilliseconds(220));

        Assert.Equal("Overlay", status.WriteBackend);
        Assert.Equal(NativeWriteReadiness.MutationReady, status.NativeWriteReadiness);
        Assert.Equal(NativeWriteValidationState.Scaffold, status.NativeWriteValidationState);
        Assert.False(status.RecoveryActive);
        Assert.Equal((ulong)10, status.LastCommitXid);
        Assert.Equal(NativeWriteSafetyState.PilotReadWrite, status.NativeWriteSafetyState);
    }

    [Fact]
    public async Task ReadHostRuntimeStatusAsync_ReadOnlyForcesDisabledTelemetry()
    {
        using var statusFile = new TemporaryStatusFile("""
            {
              "writeBackend": "Native",
              "nativeWriteReadiness": "CommitReady",
              "recoveryActive": true,
              "recoveryReason": "best-effort",
              "lastCommitXid": 91
            }
            """);

        var status = await InvokeReadHostRuntimeStatusAsync(
            statusFilePath: statusFile.Path,
            accessMode: MountAccessMode.ReadOnly,
            configuredWriteBackend: "Native",
            timeout: TimeSpan.FromMilliseconds(220));

        Assert.Equal("Disabled", status.WriteBackend);
        Assert.Equal(NativeWriteReadiness.Unavailable, status.NativeWriteReadiness);
        Assert.Equal(NativeWriteValidationState.Scaffold, status.NativeWriteValidationState);
        Assert.True(status.RecoveryActive);
        Assert.Equal("best-effort", status.RecoveryReason);
        Assert.Equal((ulong)91, status.LastCommitXid);
        Assert.Equal(NativeWriteSafetyState.ReadOnlyFallback, status.NativeWriteSafetyState);
    }

    [Fact]
    public async Task ReadHostRuntimeStatusAsync_ZeroCommitXidNormalizesToNull()
    {
        using var statusFile = new TemporaryStatusFile("""
            {
              "writeBackend": "Native",
              "nativeWriteReadiness": "BootstrapReady",
              "recoveryActive": false,
              "lastCommitXid": 0
            }
            """);

        var status = await InvokeReadHostRuntimeStatusAsync(
            statusFilePath: statusFile.Path,
            accessMode: MountAccessMode.ReadWrite,
            configuredWriteBackend: "Native",
            timeout: TimeSpan.FromMilliseconds(220));

        Assert.Equal("Native", status.WriteBackend);
        Assert.Equal(NativeWriteReadiness.BootstrapReady, status.NativeWriteReadiness);
        Assert.Equal(NativeWriteValidationState.Scaffold, status.NativeWriteValidationState);
        Assert.Null(status.LastCommitXid);
        Assert.Equal(NativeWriteSafetyState.PilotReadWrite, status.NativeWriteSafetyState);
    }

    [Fact]
    public async Task ReadHostRuntimeStatusAsync_CanonicalizesKnownRecoveryReasonTokens()
    {
        using var statusFile = new TemporaryStatusFile("""
            {
              "writeBackend": "Native",
              "nativeWriteReadiness": "Degraded",
              "recoveryActive": true,
              "recoveryReason": " commit timed-out ",
              "lastCommitXid": 11
            }
            """);

        var status = await InvokeReadHostRuntimeStatusAsync(
            statusFilePath: statusFile.Path,
            accessMode: MountAccessMode.ReadWrite,
            configuredWriteBackend: "Native",
            timeout: TimeSpan.FromMilliseconds(220));

        Assert.Equal("Native", status.WriteBackend);
        Assert.Equal(NativeWriteReadiness.Degraded, status.NativeWriteReadiness);
        Assert.Equal(NativeWriteValidationState.Scaffold, status.NativeWriteValidationState);
        Assert.True(status.RecoveryActive);
        Assert.Equal("CommitTimedOut", status.RecoveryReason);
        Assert.Equal((ulong)11, status.LastCommitXid);
        Assert.Equal(NativeWriteSafetyState.RecoveryBlocked, status.NativeWriteSafetyState);
        Assert.Equal("DowngradedAfterCommitTimeout", status.LastRecoveryAction);
    }

    [Fact]
    public async Task ReadHostRuntimeStatusAsync_CanonicalizesCommitModelMismatchReason()
    {
        using var statusFile = new TemporaryStatusFile("""
            {
              "writeBackend": "Native",
              "nativeWriteReadiness": "MutationReady",
              "recoveryActive": true,
              "recoveryReason": " commit model not canonical ",
              "lastCommitXid": 17
            }
            """);

        var status = await InvokeReadHostRuntimeStatusAsync(
            statusFilePath: statusFile.Path,
            accessMode: MountAccessMode.ReadWrite,
            configuredWriteBackend: "Native",
            timeout: TimeSpan.FromMilliseconds(220));

        Assert.Equal("Native", status.WriteBackend);
        Assert.Equal(NativeWriteReadiness.MutationReady, status.NativeWriteReadiness);
        Assert.Equal(NativeWriteValidationState.Scaffold, status.NativeWriteValidationState);
        Assert.True(status.RecoveryActive);
        Assert.Equal("CommitModelNotCanonical", status.RecoveryReason);
        Assert.Equal((ulong)17, status.LastCommitXid);
        Assert.Equal(NativeWriteSafetyState.RecoveryBlocked, status.NativeWriteSafetyState);
        Assert.Equal("DowngradedAfterCommitModelMismatch", status.LastRecoveryAction);
    }

    [Theory]
    [InlineData(" canonical path not active ", "CanonicalPathNotActive", "DowngradedAfterCanonicalPathProofMissing")]
    [InlineData(" canonical state not loaded ", "CanonicalStateNotLoaded", "DowngradedAfterCanonicalGateFailure")]
    [InlineData(" canonical volume state load failed ", "CanonicalVolumeStateLoadFailed", "DowngradedAfterCanonicalGateFailure")]
    [InlineData(" canonical object map state invalid ", "CanonicalObjectMapStateInvalid", "DowngradedAfterCanonicalGateFailure")]
    [InlineData(" canonical spaceman state invalid ", "CanonicalSpacemanStateInvalid", "DowngradedAfterCanonicalGateFailure")]
    [InlineData(" canonical volume tree state invalid ", "CanonicalVolumeTreeStateInvalid", "DowngradedAfterCanonicalGateFailure")]
    [InlineData(" native write not ready ", "NativeWriteNotReady", "DowngradedAfterCanonicalGateFailure")]
    [InlineData(" write device not allowed ", "WriteDeviceNotAllowed", "DowngradedAfterCanonicalGateFailure")]
    [InlineData(" commit path not ready ", "CommitPathNotReady", "DowngradedAfterCanonicalGateFailure")]
    [InlineData(" canonical commit not ready ", "CanonicalCommitNotReady", "DowngradedAfterCanonicalGateFailure")]
    public async Task ReadHostRuntimeStatusAsync_CanonicalizesCanonicalGateFailureReasons(
        string rawRecoveryReason,
        string expectedRecoveryReason,
        string expectedLastRecoveryAction)
    {
        using var statusFile = new TemporaryStatusFile($$"""
            {
              "writeBackend": "Native",
              "nativeWriteReadiness": "MutationReady",
              "recoveryActive": true,
              "recoveryReason": "{{rawRecoveryReason}}",
              "lastCommitXid": 18
            }
            """);

        var status = await InvokeReadHostRuntimeStatusAsync(
            statusFilePath: statusFile.Path,
            accessMode: MountAccessMode.ReadWrite,
            configuredWriteBackend: "Native",
            timeout: TimeSpan.FromMilliseconds(220));

        Assert.Equal("Native", status.WriteBackend);
        Assert.Equal(NativeWriteReadiness.MutationReady, status.NativeWriteReadiness);
        Assert.Equal(NativeWriteValidationState.Scaffold, status.NativeWriteValidationState);
        Assert.True(status.RecoveryActive);
        Assert.Equal(expectedRecoveryReason, status.RecoveryReason);
        Assert.Equal((ulong)18, status.LastCommitXid);
        Assert.Equal(NativeWriteSafetyState.RecoveryBlocked, status.NativeWriteSafetyState);
        Assert.Equal(expectedLastRecoveryAction, status.LastRecoveryAction);
    }

    [Fact]
    public async Task ReadHostRuntimeStatusAsync_DerivesCanonicalGateFailure_FromCanonicalRecoveryReason_WhenPayloadFieldMissing()
    {
        using var statusFile = new TemporaryStatusFile("""
            {
              "writeBackend": "Native",
              "nativeWriteReadiness": "MutationReady",
              "recoveryActive": true,
              "recoveryReason": " commit path not ready ",
              "lastCommitXid": 181
            }
            """);

        var status = await InvokeReadHostRuntimeStatusAsync(
            statusFilePath: statusFile.Path,
            accessMode: MountAccessMode.ReadWrite,
            configuredWriteBackend: "Native",
            timeout: TimeSpan.FromMilliseconds(220));

        Assert.Equal("Native", status.WriteBackend);
        Assert.Equal(NativeWriteReadiness.MutationReady, status.NativeWriteReadiness);
        Assert.True(status.RecoveryActive);
        Assert.Equal("CommitPathNotReady", status.RecoveryReason);
        Assert.Equal("CommitPathNotReady", status.CanonicalGateFailure);
        Assert.Equal((ulong)181, status.LastCommitXid);
        Assert.Equal("DowngradedAfterCanonicalGateFailure", status.LastRecoveryAction);
    }

    [Fact]
    public async Task ReadHostRuntimeStatusAsync_DerivesCanonicalGateFailure_WhenPayloadBackendIsDisabledAfterFailClosed()
    {
        using var statusFile = new TemporaryStatusFile("""
            {
              "writeBackend": "Disabled",
              "nativeWriteReadiness": "Degraded",
              "recoveryActive": true,
              "recoveryReason": " canonical commit not ready ",
              "lastCommitXid": 182
            }
            """);

        var status = await InvokeReadHostRuntimeStatusAsync(
            statusFilePath: statusFile.Path,
            accessMode: MountAccessMode.ReadWrite,
            configuredWriteBackend: "Native",
            timeout: TimeSpan.FromMilliseconds(220));

        Assert.Equal("Native", status.WriteBackend);
        Assert.Equal(NativeWriteReadiness.Degraded, status.NativeWriteReadiness);
        Assert.True(status.RecoveryActive);
        Assert.Equal("CanonicalCommitNotReady", status.RecoveryReason);
        Assert.Equal("CanonicalCommitNotReady", status.CanonicalGateFailure);
        Assert.False(status.CanonicalPathActive);
        Assert.Equal((ulong)182, status.LastCommitXid);
        Assert.Equal("DowngradedAfterCanonicalGateFailure", status.LastRecoveryAction);
    }

    [Fact]
    public async Task ReadHostRuntimeStatusAsync_CanonicalizesWriteGateBlockedReason()
    {
        using var statusFile = new TemporaryStatusFile("""
            {
              "writeBackend": "Native",
              "nativeWriteReadiness": "MutationReady",
              "recoveryActive": true,
              "recoveryReason": " write gate blocked ",
              "lastCommitXid": 21
            }
            """);

        var status = await InvokeReadHostRuntimeStatusAsync(
            statusFilePath: statusFile.Path,
            accessMode: MountAccessMode.ReadWrite,
            configuredWriteBackend: "Native",
            timeout: TimeSpan.FromMilliseconds(220));

        Assert.Equal("Native", status.WriteBackend);
        Assert.Equal(NativeWriteReadiness.MutationReady, status.NativeWriteReadiness);
        Assert.Equal(NativeWriteValidationState.Scaffold, status.NativeWriteValidationState);
        Assert.True(status.RecoveryActive);
        Assert.Equal("WriteGateBlocked", status.RecoveryReason);
        Assert.Equal((ulong)21, status.LastCommitXid);
        Assert.Equal(NativeWriteSafetyState.RecoveryBlocked, status.NativeWriteSafetyState);
        Assert.Equal("DowngradedAfterWriteGatePolicy", status.LastRecoveryAction);
    }

    [Fact]
    public async Task ReadHostRuntimeStatusAsync_CanonicalizesValidationCrashFaultEvidenceReason()
    {
        using var statusFile = new TemporaryStatusFile("""
            {
              "writeBackend": "Native",
              "nativeWriteReadiness": "MutationReady",
              "recoveryActive": true,
              "recoveryReason": " validation crash fault evidence insufficient ",
              "lastCommitXid": 22
            }
            """);

        var status = await InvokeReadHostRuntimeStatusAsync(
            statusFilePath: statusFile.Path,
            accessMode: MountAccessMode.ReadWrite,
            configuredWriteBackend: "Native",
            timeout: TimeSpan.FromMilliseconds(220));

        Assert.Equal("Native", status.WriteBackend);
        Assert.Equal(NativeWriteReadiness.MutationReady, status.NativeWriteReadiness);
        Assert.Equal(NativeWriteValidationState.Scaffold, status.NativeWriteValidationState);
        Assert.True(status.RecoveryActive);
        Assert.Equal("ValidationCrashFaultEvidenceInsufficient", status.RecoveryReason);
        Assert.Equal((ulong)22, status.LastCommitXid);
        Assert.Equal(NativeWriteSafetyState.RecoveryBlocked, status.NativeWriteSafetyState);
        Assert.Equal("DowngradedAfterValidationCrashFaultGate", status.LastRecoveryAction);
    }

    [Fact]
    public async Task ReadHostRuntimeStatusAsync_CanonicalizesValidationStableEvidenceStaleReason()
    {
        using var statusFile = new TemporaryStatusFile("""
            {
              "writeBackend": "Native",
              "nativeWriteReadiness": "CommitReady",
              "recoveryActive": true,
              "recoveryReason": " validation stable evidence stale ",
              "lastCommitXid": 27
            }
            """);

        var status = await InvokeReadHostRuntimeStatusAsync(
            statusFilePath: statusFile.Path,
            accessMode: MountAccessMode.ReadWrite,
            configuredWriteBackend: "Native",
            timeout: TimeSpan.FromMilliseconds(220));

        Assert.Equal("Native", status.WriteBackend);
        Assert.Equal(NativeWriteReadiness.CommitReady, status.NativeWriteReadiness);
        Assert.Equal(NativeWriteValidationState.Scaffold, status.NativeWriteValidationState);
        Assert.True(status.RecoveryActive);
        Assert.Equal("ValidationStableEvidenceStale", status.RecoveryReason);
        Assert.Equal((ulong)27, status.LastCommitXid);
        Assert.Equal(NativeWriteSafetyState.RecoveryBlocked, status.NativeWriteSafetyState);
        Assert.Equal("DowngradedAfterValidationStableStale", status.LastRecoveryAction);
    }

    [Fact]
    public async Task ReadHostRuntimeStatusAsync_ParsesValidationEvidenceFields()
    {
        var lastValidatedUtc = DateTime.UtcNow.AddMinutes(-10);
        using var statusFile = new TemporaryStatusFile($$"""
            {
              "writeBackend": "Native",
              "nativeWriteReadiness": "CommitReady",
              "nativeWriteValidationState": "CanonicalImageValidated",
              "recoveryActive": false,
              "hostPid": 4242,
              "validationCrashFaultPasses": 2,
              "validationHardwarePilotPasses": 3,
              "validationMacOsValidationPasses": 1,
              "validationPowerLossPassVerified": true,
              "validationLastValidatedUtc": "{{lastValidatedUtc:o}}"
            }
            """);

        var status = await InvokeReadHostRuntimeStatusAsync(
            statusFilePath: statusFile.Path,
            accessMode: MountAccessMode.ReadWrite,
            configuredWriteBackend: "Native",
            timeout: TimeSpan.FromMilliseconds(220));

        Assert.NotNull(status.ValidationEvidence);
        Assert.Equal(2, status.ValidationEvidence!.CrashFaultPasses);
        Assert.Equal(3, status.ValidationEvidence.HardwarePilotPasses);
        Assert.Equal(1, status.ValidationEvidence.MacOsValidationPasses);
        Assert.True(status.ValidationEvidence.PowerLossPassVerified);
        Assert.True(status.ValidationEvidence.LastValidatedUtc.HasValue);
        Assert.Equal(lastValidatedUtc.ToUniversalTime(), status.ValidationEvidence.LastValidatedUtc!.Value);
        Assert.Equal(4242, status.HostProcessId);
    }

    [Fact]
    public async Task ReadHostRuntimeStatusAsync_LenientlyParsesStringEncodedTelemetryFields()
    {
        using var statusFile = new TemporaryStatusFile("""
            {
              "writeBackend": "Native",
              "commitModel": "CanonicalApfsCheckpoint",
              "nativeWriteReadiness": "CommitReady",
              "nativeWriteValidationState": "CanonicalImageValidated",
              "recoveryActive": "false",
              "lastCommitXid": "99",
              "dirtyTransactionCount": "12",
              "shutdownDrainActive": "true",
              "inFlightMutationCallbacks": "7",
              "hostPid": "4567",
              "validationCrashFaultPasses": "2",
              "validationHotUnplugPasses": "3",
              "validationPowerLossPassVerified": "1",
              "fixtureCompatibilityPathActive": "false",
              "usesScaffoldCommitBlob": "0",
              "canonicalPathActive": "true",
              "replayCheckpointCandidatePresent": "true",
              "replayCheckpointPendingWindow": "false"
            }
            """);

        var status = await InvokeReadHostRuntimeStatusAsync(
            statusFilePath: statusFile.Path,
            accessMode: MountAccessMode.ReadWrite,
            configuredWriteBackend: "Native",
            timeout: TimeSpan.FromMilliseconds(240));

        Assert.Equal("Native", status.WriteBackend);
        Assert.Equal(NativeWriteReadiness.CommitReady, status.NativeWriteReadiness);
        Assert.Equal(NativeWriteValidationState.CanonicalImageValidated, status.NativeWriteValidationState);
        Assert.Equal((ulong)99, status.LastCommitXid);
        Assert.Equal(12, status.DirtyTransactionCount);
        Assert.True(status.ShutdownDrainActive);
        Assert.Equal(7, status.InFlightMutationCallbacks);
        Assert.Equal(4567, status.HostProcessId);
        Assert.NotNull(status.ValidationEvidence);
        Assert.Equal(2, status.ValidationEvidence!.CrashFaultPasses);
        Assert.Equal(3, status.ValidationEvidence.HotUnplugPasses);
        Assert.True(status.ValidationEvidence.PowerLossPassVerified);
        Assert.False(status.FixtureCompatibilityPathActive);
        Assert.False(status.UsesScaffoldCommitBlob);
        Assert.True(status.CanonicalPathActive);
        Assert.True(status.ReplayCheckpointCandidatePresent);
        Assert.False(status.ReplayCheckpointPendingWindow);
    }

    [Fact]
    public async Task ReadHostRuntimeStatusAsync_LenientlyClampsOversizedNumericTelemetry()
    {
        using var statusFile = new TemporaryStatusFile("""
            {
              "writeBackend": "Native",
              "nativeWriteReadiness": "CommitReady",
              "recoveryActive": "false",
              "lastCommitXid": "18446744073709551615",
              "dirtyTransactionCount": "9223372036854775807",
              "inFlightMutationCallbacks": "9223372036854775807",
              "hostPid": "9223372036854775807",
              "validationCrashFaultPasses": "9223372036854775807",
              "validationCrashStageMatrixPasses": "9223372036854775807",
              "validationHardwarePilotPasses": "9223372036854775807",
              "validationHotUnplugPasses": "9223372036854775807",
              "validationMacOsValidationPasses": "9223372036854775807",
              "validationMacOsConsistencyPasses": "9223372036854775807",
              "validationPowerLossReplayPasses": "9223372036854775807"
            }
            """);

        var status = await InvokeReadHostRuntimeStatusAsync(
            statusFilePath: statusFile.Path,
            accessMode: MountAccessMode.ReadWrite,
            configuredWriteBackend: "Native",
            timeout: TimeSpan.FromMilliseconds(240));

        Assert.Equal("Native", status.WriteBackend);
        Assert.Equal(NativeWriteReadiness.CommitReady, status.NativeWriteReadiness);
        Assert.Equal((ulong)18446744073709551615UL, status.LastCommitXid);
        Assert.Equal(int.MaxValue, status.DirtyTransactionCount);
        Assert.Equal(int.MaxValue, status.InFlightMutationCallbacks);
        Assert.Equal(int.MaxValue, status.HostProcessId);
        Assert.NotNull(status.ValidationEvidence);
        Assert.Equal(int.MaxValue, status.ValidationEvidence!.CrashFaultPasses);
        Assert.Equal(int.MaxValue, status.ValidationEvidence.CrashStageMatrixPasses);
        Assert.Equal(int.MaxValue, status.ValidationEvidence.HardwarePilotPasses);
        Assert.Equal(int.MaxValue, status.ValidationEvidence.HotUnplugPasses);
        Assert.Equal(int.MaxValue, status.ValidationEvidence.MacOsValidationPasses);
        Assert.Equal(int.MaxValue, status.ValidationEvidence.MacOsConsistencyPasses);
        Assert.Equal(int.MaxValue, status.ValidationEvidence.PowerLossReplayPasses);
    }

    [Fact]
    public async Task ReadHostRuntimeStatusAsync_LenientParserKeepsValidFieldsWhenCounterTokensAreInvalid()
    {
        using var statusFile = new TemporaryStatusFile("""
            {
              "writeBackend": "Native",
              "nativeWriteReadiness": "Degraded",
              "recoveryActive": "no",
              "recoveryReason": "commit timed-out",
              "lastCommitXid": "101",
              "dirtyTransactionCount": "not-a-number",
              "shutdownDrainActive": "yes",
              "inFlightMutationCallbacks": "n/a",
              "hostPid": "pid-33",
              "validationCrashFaultPasses": "unknown"
            }
            """);

        var status = await InvokeReadHostRuntimeStatusAsync(
            statusFilePath: statusFile.Path,
            accessMode: MountAccessMode.ReadWrite,
            configuredWriteBackend: "Native",
            timeout: TimeSpan.FromMilliseconds(240));

        Assert.Equal("Native", status.WriteBackend);
        Assert.Equal(NativeWriteReadiness.Degraded, status.NativeWriteReadiness);
        Assert.True(status.RecoveryActive);
        Assert.Equal("CommitTimedOut", status.RecoveryReason);
        Assert.Equal((ulong)101, status.LastCommitXid);
        Assert.Equal(NativeWriteSafetyState.RecoveryBlocked, status.NativeWriteSafetyState);
        Assert.Equal(0, status.DirtyTransactionCount);
        Assert.True(status.ShutdownDrainActive);
        Assert.Equal(0, status.InFlightMutationCallbacks);
        Assert.Equal(0, status.HostProcessId);
        Assert.Null(status.ValidationEvidence);
    }

    [Theory]
    [InlineData(" fixture legacy fallback active ", "FixtureLegacyFallbackActive", "DowngradedAfterFixtureFallback")]
    [InlineData(" scaffold commit blob active ", "ScaffoldCommitBlobActive", "DowngradedAfterScaffoldCommitBlob")]
    public async Task ReadHostRuntimeStatusAsync_CanonicalizesFixtureAndScaffoldSafetyReasons(
        string rawRecoveryReason,
        string expectedRecoveryReason,
        string expectedLastRecoveryAction)
    {
        using var statusFile = new TemporaryStatusFile($$"""
            {
              "writeBackend": "Native",
              "nativeWriteReadiness": "MutationReady",
              "recoveryActive": true,
              "recoveryReason": "{{rawRecoveryReason}}",
              "lastCommitXid": 18
            }
            """);

        var status = await InvokeReadHostRuntimeStatusAsync(
            statusFilePath: statusFile.Path,
            accessMode: MountAccessMode.ReadWrite,
            configuredWriteBackend: "Native",
            timeout: TimeSpan.FromMilliseconds(220));

        Assert.Equal("Native", status.WriteBackend);
        Assert.Equal(NativeWriteReadiness.MutationReady, status.NativeWriteReadiness);
        Assert.Equal(NativeWriteValidationState.Scaffold, status.NativeWriteValidationState);
        Assert.True(status.RecoveryActive);
        Assert.Equal(expectedRecoveryReason, status.RecoveryReason);
        Assert.Equal((ulong)18, status.LastCommitXid);
        Assert.Equal(NativeWriteSafetyState.RecoveryBlocked, status.NativeWriteSafetyState);
        Assert.Equal(expectedLastRecoveryAction, status.LastRecoveryAction);
    }

    [Theory]
    [InlineData(" fixture legacy fallback active ", true, false, false)]
    [InlineData(" fixture compatibility path active ", false, true, false)]
    [InlineData(" scaffold commit blob active ", false, false, true)]
    public async Task ReadHostRuntimeStatusAsync_DerivesCompatibilityFlags_FromRecoveryReason_WhenPayloadFlagsMissing(
        string rawRecoveryReason,
        bool expectedFixtureLegacyFallbackActive,
        bool expectedFixtureCompatibilityPathActive,
        bool expectedUsesScaffoldCommitBlob)
    {
        using var statusFile = new TemporaryStatusFile($$"""
            {
              "writeBackend": "Disabled",
              "nativeWriteReadiness": "Degraded",
              "recoveryActive": true,
              "recoveryReason": "{{rawRecoveryReason}}",
              "lastCommitXid": 183
            }
            """);

        var status = await InvokeReadHostRuntimeStatusAsync(
            statusFilePath: statusFile.Path,
            accessMode: MountAccessMode.ReadWrite,
            configuredWriteBackend: "Native",
            timeout: TimeSpan.FromMilliseconds(220));

        Assert.Equal("Native", status.WriteBackend);
        Assert.Equal(NativeWriteReadiness.Degraded, status.NativeWriteReadiness);
        Assert.True(status.RecoveryActive);
        Assert.Equal((ulong)183, status.LastCommitXid);
        Assert.Equal(expectedFixtureLegacyFallbackActive, status.FixtureLegacyFallbackActive);
        Assert.Equal(expectedFixtureCompatibilityPathActive, status.FixtureCompatibilityPathActive);
        Assert.Equal(expectedUsesScaffoldCommitBlob, status.UsesScaffoldCommitBlob);
    }

    [Fact]
    public async Task ReadHostRuntimeStatusAsync_CanonicalizesIntegrityMountFailureReason()
    {
        using var statusFile = new TemporaryStatusFile("""
            {
              "writeBackend": "Native",
              "nativeWriteReadiness": "RecoveryMode",
              "recoveryActive": true,
              "recoveryReason": " integrity check failed on mount ",
              "lastCommitXid": 19
            }
            """);

        var status = await InvokeReadHostRuntimeStatusAsync(
            statusFilePath: statusFile.Path,
            accessMode: MountAccessMode.ReadWrite,
            configuredWriteBackend: "Native",
            timeout: TimeSpan.FromMilliseconds(220));

        Assert.Equal("Native", status.WriteBackend);
        Assert.Equal(NativeWriteReadiness.RecoveryMode, status.NativeWriteReadiness);
        Assert.Equal(NativeWriteValidationState.Scaffold, status.NativeWriteValidationState);
        Assert.True(status.RecoveryActive);
        Assert.Equal("IntegrityCheckFailedOnMount", status.RecoveryReason);
        Assert.Equal((ulong)19, status.LastCommitXid);
        Assert.Equal(NativeWriteSafetyState.RecoveryBlocked, status.NativeWriteSafetyState);
        Assert.Equal("BootstrapIntegrityBlocked", status.LastRecoveryAction);
    }

    [Fact]
    public async Task ReadHostRuntimeStatusAsync_CanonicalizesMissingAllocationMapReason()
    {
        using var statusFile = new TemporaryStatusFile("""
            {
              "writeBackend": "Native",
              "nativeWriteReadiness": "RecoveryMode",
              "recoveryActive": true,
              "recoveryReason": " missing allocation ",
              "lastCommitXid": 20
            }
            """);

        var status = await InvokeReadHostRuntimeStatusAsync(
            statusFilePath: statusFile.Path,
            accessMode: MountAccessMode.ReadWrite,
            configuredWriteBackend: "Native",
            timeout: TimeSpan.FromMilliseconds(220));

        Assert.Equal("Native", status.WriteBackend);
        Assert.Equal(NativeWriteReadiness.RecoveryMode, status.NativeWriteReadiness);
        Assert.True(status.RecoveryActive);
        Assert.Equal("IntegrityMissingAllocationMap", status.RecoveryReason);
        Assert.Equal((ulong)20, status.LastCommitXid);
        Assert.Equal(NativeWriteSafetyState.RecoveryBlocked, status.NativeWriteSafetyState);
        Assert.Equal("BootstrapIntegrityMissingAllocationMap", status.LastRecoveryAction);
    }

    [Fact]
    public async Task ReadHostRuntimeStatusAsync_DerivesReplayFailClosedAction_WhenReplayReasonReported()
    {
        using var statusFile = new TemporaryStatusFile("""
            {
              "writeBackend": "Native",
              "nativeWriteReadiness": "RecoveryMode",
              "recoveryActive": false,
              "recoveryReason": "ReplayCommitBlobInvalid",
              "lastCommitXid": 23
            }
            """);

        var status = await InvokeReadHostRuntimeStatusAsync(
            statusFilePath: statusFile.Path,
            accessMode: MountAccessMode.ReadWrite,
            configuredWriteBackend: "Native",
            timeout: TimeSpan.FromMilliseconds(220));

        Assert.Equal("Native", status.WriteBackend);
        Assert.Equal(NativeWriteReadiness.RecoveryMode, status.NativeWriteReadiness);
        Assert.Equal(NativeWriteValidationState.Scaffold, status.NativeWriteValidationState);
        Assert.True(status.RecoveryActive);
        Assert.Equal("ReplayCommitBlobInvalid", status.RecoveryReason);
        Assert.Equal((ulong)23, status.LastCommitXid);
        Assert.Equal(NativeWriteSafetyState.RecoveryBlocked, status.NativeWriteSafetyState);
        Assert.Equal("ReplaySkippedFailClosed", status.LastRecoveryAction);
    }

    [Theory]
    [InlineData(" persistent state ahead of superblock ", "PersistentStateAheadOfSuperblock")]
    [InlineData(" persistent state behind superblock ", "PersistentStateBehindSuperblock")]
    public async Task ReadHostRuntimeStatusAsync_CanonicalizesPersistentStateReplayReasons(
        string rawRecoveryReason,
        string expectedRecoveryReason)
    {
        using var statusFile = new TemporaryStatusFile($$"""
            {
              "writeBackend": "Native",
              "nativeWriteReadiness": "RecoveryMode",
              "recoveryActive": false,
              "recoveryReason": "{{rawRecoveryReason}}",
              "lastCommitXid": 24
            }
            """);

        var status = await InvokeReadHostRuntimeStatusAsync(
            statusFilePath: statusFile.Path,
            accessMode: MountAccessMode.ReadWrite,
            configuredWriteBackend: "Native",
            timeout: TimeSpan.FromMilliseconds(220));

        Assert.Equal("Native", status.WriteBackend);
        Assert.Equal(NativeWriteReadiness.RecoveryMode, status.NativeWriteReadiness);
        Assert.Equal(NativeWriteValidationState.Scaffold, status.NativeWriteValidationState);
        Assert.True(status.RecoveryActive);
        Assert.Equal(expectedRecoveryReason, status.RecoveryReason);
        Assert.Equal((ulong)24, status.LastCommitXid);
        Assert.Equal(NativeWriteSafetyState.RecoveryBlocked, status.NativeWriteSafetyState);
        Assert.Equal("ReplaySkippedFailClosed", status.LastRecoveryAction);
    }

    [Theory]
    [InlineData(" replay integrity check failed ", "ReplayIntegrityCheckFailed")]
    [InlineData(" replay checkpoint pending window ", "ReplayCheckpointPendingWindow")]
    [InlineData(" replay checkpoint not pending window ", "ReplayCheckpointNotPendingWindow")]
    [InlineData(" replay interrupted before checkpoint switch ", "ReplayInterruptedBeforeCheckpointSwitch")]
    [InlineData(" replay checkpoint write failed ", "ReplayCheckpointWriteFailed")]
    [InlineData(" replay interrupted before checkpoint flush ", "ReplayInterruptedBeforeCheckpointFlush")]
    [InlineData(" replay checkpoint flush failed ", "ReplayCheckpointFlushFailed")]
    public async Task ReadHostRuntimeStatusAsync_CanonicalizesReplayStageFailureReasons(
        string rawRecoveryReason,
        string expectedRecoveryReason)
    {
        using var statusFile = new TemporaryStatusFile($$"""
            {
              "writeBackend": "Native",
              "nativeWriteReadiness": "RecoveryMode",
              "recoveryActive": false,
              "recoveryReason": "{{rawRecoveryReason}}",
              "lastCommitXid": 26
            }
            """);

        var status = await InvokeReadHostRuntimeStatusAsync(
            statusFilePath: statusFile.Path,
            accessMode: MountAccessMode.ReadWrite,
            configuredWriteBackend: "Native",
            timeout: TimeSpan.FromMilliseconds(220));

        Assert.Equal("Native", status.WriteBackend);
        Assert.Equal(NativeWriteReadiness.RecoveryMode, status.NativeWriteReadiness);
        Assert.Equal(NativeWriteValidationState.Scaffold, status.NativeWriteValidationState);
        Assert.True(status.RecoveryActive);
        Assert.Equal(expectedRecoveryReason, status.RecoveryReason);
        Assert.Equal((ulong)26, status.LastCommitXid);
        Assert.Equal(NativeWriteSafetyState.RecoveryBlocked, status.NativeWriteSafetyState);
        Assert.Equal("ReplaySkippedFailClosed", status.LastRecoveryAction);
    }

    [Theory]
    [InlineData(" commit interrupted before replay persist ", "CommitInterruptedBeforeReplayPersist", "DowngradedAfterPersistFailure")]
    [InlineData(" commit replay persist failed ", "CommitReplayPersistFailed", "DowngradedAfterPersistFailure")]
    [InlineData(" commit interrupted before replay roundtrip verify ", "CommitInterruptedBeforeReplayRoundTripVerify", "DowngradedAfterPersistFailure")]
    [InlineData(" commit replay roundtrip failed ", "CommitReplayRoundTripFailed", "DowngradedAfterPersistFailure")]
    [InlineData(" commit interrupted before checkpoint roundtrip verify ", "CommitInterruptedBeforeCheckpointRoundTripVerify", "DowngradedAfterCheckpointInterruption")]
    [InlineData(" commit checkpoint roundtrip failed ", "CommitCheckpointRoundTripFailed", "DowngradedAfterCheckpointWriteFailure")]
    public async Task ReadHostRuntimeStatusAsync_CanonicalizesReplayCheckpointPersistFailureReasons(
        string rawRecoveryReason,
        string expectedRecoveryReason,
        string expectedLastRecoveryAction)
    {
        using var statusFile = new TemporaryStatusFile($$"""
            {
              "writeBackend": "Native",
              "nativeWriteReadiness": "Degraded",
              "recoveryActive": false,
              "recoveryReason": "{{rawRecoveryReason}}",
              "lastCommitXid": 28
            }
            """);

        var status = await InvokeReadHostRuntimeStatusAsync(
            statusFilePath: statusFile.Path,
            accessMode: MountAccessMode.ReadWrite,
            configuredWriteBackend: "Native",
            timeout: TimeSpan.FromMilliseconds(220));

        Assert.Equal("Native", status.WriteBackend);
        Assert.Equal(NativeWriteReadiness.Degraded, status.NativeWriteReadiness);
        Assert.Equal(NativeWriteValidationState.Scaffold, status.NativeWriteValidationState);
        Assert.True(status.RecoveryActive);
        Assert.Equal(expectedRecoveryReason, status.RecoveryReason);
        Assert.Equal((ulong)28, status.LastCommitXid);
        Assert.Equal(NativeWriteSafetyState.RecoveryBlocked, status.NativeWriteSafetyState);
        Assert.Equal(expectedLastRecoveryAction, status.LastRecoveryAction);
    }

    [Fact]
    public async Task ReadHostRuntimeStatusAsync_CanonicalizesDirtyTransactionLimitReason()
    {
        using var statusFile = new TemporaryStatusFile("""
            {
              "writeBackend": "Native",
              "nativeWriteReadiness": "CommitReady",
              "recoveryActive": false,
              "recoveryReason": " dirty transaction limit exceeded ",
              "lastCommitXid": 31,
              "dirtyTransactionCount": 256
            }
            """);

        var status = await InvokeReadHostRuntimeStatusAsync(
            statusFilePath: statusFile.Path,
            accessMode: MountAccessMode.ReadWrite,
            configuredWriteBackend: "Native",
            timeout: TimeSpan.FromMilliseconds(220));

        Assert.Equal("Native", status.WriteBackend);
        Assert.Equal(NativeWriteReadiness.CommitReady, status.NativeWriteReadiness);
        Assert.Equal(NativeWriteValidationState.Scaffold, status.NativeWriteValidationState);
        Assert.True(status.RecoveryActive);
        Assert.Equal("DirtyTransactionLimitExceeded", status.RecoveryReason);
        Assert.Equal((ulong)31, status.LastCommitXid);
        Assert.Equal(NativeWriteSafetyState.RecoveryBlocked, status.NativeWriteSafetyState);
        Assert.Equal("DowngradedAfterDirtyTransactionLimit", status.LastRecoveryAction);
        Assert.Equal(256, status.DirtyTransactionCount);
    }

    [Fact]
    public async Task ReadHostRuntimeStatusAsync_MalformedJsonFallsBackAfterTimeout()
    {
        using var statusFile = new TemporaryStatusFile("{ \"writeBackend\": \"Native\"");

        var status = await InvokeReadHostRuntimeStatusAsync(
            statusFilePath: statusFile.Path,
            accessMode: MountAccessMode.ReadWrite,
            configuredWriteBackend: "Overlay",
            timeout: TimeSpan.FromMilliseconds(240));

        Assert.Equal("Overlay", status.WriteBackend);
        Assert.Equal(NativeWriteReadiness.MutationReady, status.NativeWriteReadiness);
        Assert.Equal(NativeWriteValidationState.Scaffold, status.NativeWriteValidationState);
        Assert.False(status.RecoveryActive);
        Assert.Null(status.RecoveryReason);
        Assert.Null(status.LastCommitXid);
        Assert.Equal(NativeWriteSafetyState.PilotReadWrite, status.NativeWriteSafetyState);
    }

    private static async Task<HostRuntimeStatusProjection> InvokeReadHostRuntimeStatusAsync(
        string statusFilePath,
        MountAccessMode accessMode,
        string configuredWriteBackend,
        TimeSpan timeout)
    {
        var method = typeof(NativeApfsBackend).GetMethod(
            "ReadHostRuntimeStatusAsync",
            BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        var taskObj = method!.Invoke(null, [statusFilePath, accessMode, configuredWriteBackend, timeout, CancellationToken.None]);
        Assert.NotNull(taskObj);
        var task = (Task)taskObj!;
        await task.ConfigureAwait(false);

        var resultProperty = taskObj!.GetType().GetProperty("Result", BindingFlags.Public | BindingFlags.Instance);
        Assert.NotNull(resultProperty);
        var result = resultProperty!.GetValue(taskObj);
        Assert.NotNull(result);

        var resultType = result!.GetType();
        var writeBackend = (string?)resultType.GetProperty("WriteBackend", BindingFlags.Public | BindingFlags.Instance)?.GetValue(result);
        var nativeWriteReadiness = (NativeWriteReadiness?)resultType.GetProperty("NativeWriteReadiness", BindingFlags.Public | BindingFlags.Instance)?.GetValue(result);
        var nativeWriteValidationState = (NativeWriteValidationState?)resultType.GetProperty("NativeWriteValidationState", BindingFlags.Public | BindingFlags.Instance)?.GetValue(result);
        var recoveryActive = (bool?)resultType.GetProperty("RecoveryActive", BindingFlags.Public | BindingFlags.Instance)?.GetValue(result);
        var recoveryReason = (string?)resultType.GetProperty("RecoveryReason", BindingFlags.Public | BindingFlags.Instance)?.GetValue(result);
        var lastCommitXid = (ulong?)resultType.GetProperty("LastCommitXid", BindingFlags.Public | BindingFlags.Instance)?.GetValue(result);
        var nativeWriteSafetyState = (NativeWriteSafetyState?)resultType.GetProperty("NativeWriteSafetyState", BindingFlags.Public | BindingFlags.Instance)?.GetValue(result);
        var lastRecoveryAction = (string?)resultType.GetProperty("LastRecoveryAction", BindingFlags.Public | BindingFlags.Instance)?.GetValue(result);
        var dirtyTransactionCount = (int?)resultType.GetProperty("DirtyTransactionCount", BindingFlags.Public | BindingFlags.Instance)?.GetValue(result);
        var shutdownDrainActive = (bool?)resultType.GetProperty("ShutdownDrainActive", BindingFlags.Public | BindingFlags.Instance)?.GetValue(result);
        var inFlightMutationCallbacks = (int?)resultType.GetProperty("InFlightMutationCallbacks", BindingFlags.Public | BindingFlags.Instance)?.GetValue(result);
        var hostProcessId = (int?)resultType.GetProperty("HostProcessId", BindingFlags.Public | BindingFlags.Instance)?.GetValue(result);
        var fixtureLegacyFallbackActive = (bool?)resultType.GetProperty("FixtureLegacyFallbackActive", BindingFlags.Public | BindingFlags.Instance)?.GetValue(result);
        var fixtureCompatibilityPathActive = (bool?)resultType.GetProperty("FixtureCompatibilityPathActive", BindingFlags.Public | BindingFlags.Instance)?.GetValue(result);
        var usesScaffoldCommitBlob = (bool?)resultType.GetProperty("UsesScaffoldCommitBlob", BindingFlags.Public | BindingFlags.Instance)?.GetValue(result);
        var validationEvidence = (NativeWriteValidationEvidence?)resultType.GetProperty("ValidationEvidence", BindingFlags.Public | BindingFlags.Instance)?.GetValue(result);
        var commitStage = (string?)resultType.GetProperty("CommitStage", BindingFlags.Public | BindingFlags.Instance)?.GetValue(result);
        var replayStage = (string?)resultType.GetProperty("ReplayStage", BindingFlags.Public | BindingFlags.Instance)?.GetValue(result);
        var commitBlobMagic = (string?)resultType.GetProperty("CommitBlobMagic", BindingFlags.Public | BindingFlags.Instance)?.GetValue(result);
        var canonicalPathActive = (bool?)resultType.GetProperty("CanonicalPathActive", BindingFlags.Public | BindingFlags.Instance)?.GetValue(result);
        var canonicalGateFailure = (string?)resultType.GetProperty("CanonicalGateFailure", BindingFlags.Public | BindingFlags.Instance)?.GetValue(result);
        var replayCheckpointCandidatePresent = (bool?)resultType.GetProperty("ReplayCheckpointCandidatePresent", BindingFlags.Public | BindingFlags.Instance)?.GetValue(result);
        var replayCheckpointPendingWindow = (bool?)resultType.GetProperty("ReplayCheckpointPendingWindow", BindingFlags.Public | BindingFlags.Instance)?.GetValue(result);

        Assert.NotNull(writeBackend);
        Assert.NotNull(nativeWriteReadiness);
        Assert.NotNull(nativeWriteValidationState);
        Assert.NotNull(recoveryActive);
        Assert.NotNull(nativeWriteSafetyState);
        Assert.NotNull(dirtyTransactionCount);
        Assert.NotNull(shutdownDrainActive);
        Assert.NotNull(inFlightMutationCallbacks);
        Assert.NotNull(hostProcessId);
        Assert.NotNull(fixtureLegacyFallbackActive);
        Assert.NotNull(fixtureCompatibilityPathActive);
        Assert.NotNull(usesScaffoldCommitBlob);

        return new HostRuntimeStatusProjection(
            WriteBackend: writeBackend!,
            NativeWriteReadiness: nativeWriteReadiness!.Value,
            NativeWriteValidationState: nativeWriteValidationState!.Value,
            RecoveryActive: recoveryActive!.Value,
            RecoveryReason: recoveryReason,
            LastCommitXid: lastCommitXid,
            NativeWriteSafetyState: nativeWriteSafetyState!.Value,
            LastRecoveryAction: lastRecoveryAction,
            DirtyTransactionCount: dirtyTransactionCount!.Value,
            ShutdownDrainActive: shutdownDrainActive!.Value,
            InFlightMutationCallbacks: inFlightMutationCallbacks!.Value,
            HostProcessId: hostProcessId!.Value,
            FixtureLegacyFallbackActive: fixtureLegacyFallbackActive!.Value,
            FixtureCompatibilityPathActive: fixtureCompatibilityPathActive!.Value,
            UsesScaffoldCommitBlob: usesScaffoldCommitBlob!.Value,
            ValidationEvidence: validationEvidence,
            CommitStage: commitStage,
            ReplayStage: replayStage,
            CommitBlobMagic: commitBlobMagic,
            CanonicalPathActive: canonicalPathActive,
            CanonicalGateFailure: canonicalGateFailure,
            ReplayCheckpointCandidatePresent: replayCheckpointCandidatePresent,
            ReplayCheckpointPendingWindow: replayCheckpointPendingWindow
        );
    }

    private sealed record HostRuntimeStatusProjection(
        string WriteBackend,
        NativeWriteReadiness NativeWriteReadiness,
        NativeWriteValidationState NativeWriteValidationState,
        bool RecoveryActive,
        string? RecoveryReason,
        ulong? LastCommitXid,
        NativeWriteSafetyState NativeWriteSafetyState,
        string? LastRecoveryAction,
        int DirtyTransactionCount,
        bool ShutdownDrainActive,
        int InFlightMutationCallbacks,
        int HostProcessId,
        bool FixtureLegacyFallbackActive,
        bool FixtureCompatibilityPathActive,
        bool UsesScaffoldCommitBlob,
        NativeWriteValidationEvidence? ValidationEvidence,
        string? CommitStage,
        string? ReplayStage,
        string? CommitBlobMagic,
        bool? CanonicalPathActive,
        string? CanonicalGateFailure,
        bool? ReplayCheckpointCandidatePresent,
        bool? ReplayCheckpointPendingWindow);

    private sealed class TemporaryStatusFile : IDisposable
    {
        public TemporaryStatusFile(string content)
        {
            Path = System.IO.Path.Combine(
                System.IO.Path.GetTempPath(),
                $"apfsaccess_status_{Guid.NewGuid():N}.json");
            File.WriteAllText(Path, content);
        }

        public string Path { get; }

        public void Dispose()
        {
            try
            {
                if (File.Exists(Path))
                {
                    File.Delete(Path);
                }
            }
            catch
            {
                // Best-effort cleanup.
            }
        }
    }
}
