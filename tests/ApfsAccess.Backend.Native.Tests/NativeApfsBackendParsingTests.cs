using System.Collections;
using System.Reflection;
using ApfsAccess.Backend.Native;
using ApfsAccess.Core;

namespace ApfsAccess.Backend.Native.Tests;

public sealed class NativeApfsBackendParsingTests
{
    [Fact]
    public void ParseVolumeRows_ParsesHeaderWithoutColon_AndSkipsIndexedNoise()
    {
        var stdout = """
                     APFS: listsubvolumes returns 0
                     Volumes (3)
                       Volume[0]: Main
                       Volume[1]: Data encrypted
                       Volume[2]: Recovery locked
                     APFS: listsubvolumes returns 0
                     """;

        var rows = InvokeParseVolumeRows(stdout);

        Assert.Equal(3, rows.Count);
        Assert.Contains(rows, row => row.Name == "Main" && row.IsEncrypted == false);
        Assert.Contains(rows, row => row.Name == "Data" && row.IsEncrypted);
        Assert.Contains(rows, row => row.Name == "Recovery" && row.IsEncrypted);
        Assert.DoesNotContain(rows, row => row.Name.Contains("Volume[", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void ParseVolumeRows_UsesQuotedNames_WhenPresent()
    {
        var stdout = """
                     Volumes:
                       [0] 'Macintosh HD'
                       Volume[1]: 'Macintosh HD - Data' (encrypted)
                       Volume[2]: 'System Snapshot' locked
                     APFS: listsubvolumes returns 0
                     """;

        var rows = InvokeParseVolumeRows(stdout);

        Assert.Equal(3, rows.Count);
        Assert.Contains(rows, row => row.Name == "Macintosh HD" && row.IsEncrypted == false);
        Assert.Contains(rows, row => row.Name == "Macintosh HD - Data" && row.IsEncrypted);
        Assert.Contains(rows, row => row.Name == "System Snapshot" && row.IsEncrypted);
    }

    [Fact]
    public void ParseVolumeRows_PreservesUnquotedMultiWordNames_AndTrimsTrailingMetadata()
    {
        var stdout = """
                     Volumes:
                       Volume[0]: Macintosh HD - Data read-only
                       Volume[1]: Time Machine Backup role=recovery
                       Volume[2]: Work Files
                     APFS: listsubvolumes returns 0
                     """;

        var rows = InvokeParseVolumeRows(stdout);

        Assert.Equal(3, rows.Count);
        Assert.Contains(rows, row => row.Name == "Macintosh HD - Data");
        Assert.Contains(rows, row => row.Name == "Time Machine Backup");
        Assert.Contains(rows, row => row.Name == "Work Files");
    }

    [Fact]
    public void ParseVolumeRows_ExtractsExpandedWriteIncompatibilities()
    {
        var stdout = """
                     Volumes:
                       Volume[0]: Main read-only role=preboot
                       Volume[1]: SnapshotVolume (snapshot, case-sensitive)
                     APFS: listsubvolumes returns 0
                     """;

        var rows = InvokeParseVolumeRows(stdout);

        Assert.Equal(2, rows.Count);

        var main = Assert.Single(rows, static row => row.Name == "Main");
        Assert.Contains(
            "Volume is marked read-only and cannot be mounted writable.",
            main.WriteIncompatibilities);
        Assert.Contains(
            "Special-role APFS volumes (preboot/recovery/vm) are not writable in this release.",
            main.WriteIncompatibilities);
        Assert.Contains("VolumeReadOnly", main.WriteUnsupportedFeatures);
        Assert.Contains("RolePrebootRecoveryVm", main.WriteUnsupportedFeatures);

        var snapshot = Assert.Single(rows, static row => row.Name == "SnapshotVolume");
        Assert.Contains(
            "Snapshot/clone mutation semantics are not supported in v1 native write mode.",
            snapshot.WriteIncompatibilities);
        Assert.Contains(
            "Case-sensitive APFS volumes are not supported in v1 native write mode.",
            snapshot.WriteIncompatibilities);
        Assert.Contains("SnapshotOrClone", snapshot.WriteUnsupportedFeatures);
        Assert.Contains("CaseSensitive", snapshot.WriteUnsupportedFeatures);
    }

    [Fact]
    public void ParseVolumeRows_ClassifiesRoleSystemAsSealedSystemUnsupported()
    {
        var stdout = """
                     Volumes:
                       Volume[0]: Macintosh HD role = system
                     APFS: listsubvolumes returns 0
                     """;

        var rows = InvokeParseVolumeRows(stdout);

        var system = Assert.Single(rows, static row => row.Name == "Macintosh HD");
        Assert.Contains("SealedSystemVolume", system.WriteUnsupportedFeatures);
        Assert.Contains(
            "Sealed/system APFS volumes are not writable in this release.",
            system.WriteIncompatibilities);
    }

    [Fact]
    public void ParseVolumeRows_KeepsRoleDataVolumeDiscoverable()
    {
        var stdout = """
                     Volumes:
                       Volume[0]: Macintosh HD - Data role = data
                     APFS: listsubvolumes returns 0
                     """;

        var rows = InvokeParseVolumeRows(stdout);

        var dataVolume = Assert.Single(rows, static row => row.Name == "Macintosh HD - Data");
        Assert.Empty(dataVolume.WriteUnsupportedFeatures);
        Assert.Empty(dataVolume.WriteIncompatibilities);
    }

    [Fact]
    public void ParseVolumeRows_IgnoresLinesThatContainOnlyMetadataTokens()
    {
        var stdout = """
                     Volumes:
                       [0]
                       Volume[3]:
                       encrypted
                       locked
                     APFS: listsubvolumes returns 0
                     """;

        var rows = InvokeParseVolumeRows(stdout);

        Assert.Empty(rows);
    }

    [Fact]
    public void ParseVolumeRows_ReturnsEmpty_WhenVolumesSectionMissing()
    {
        var stdout = """
                     APFS: enumroot returns 0
                     APFS: listsubvolumes returns 0
                     """;

        var rows = InvokeParseVolumeRows(stdout);

        Assert.Empty(rows);
    }

    [Theory]
    [InlineData(@"\\.\PhysicalDrive3", false)]
    [InlineData(@"\\?\PhysicalDrive8", false)]
    [InlineData(@"C:\fixtures\sample.apfs.img", true)]
    [InlineData(@"C:\fixtures\sample.img", true)]
    [InlineData(@"C:\fixtures\sample.apfs.fixture", true)]
    [InlineData(@"C:\images\sample.apfs", true)]
    [InlineData(@"C:\images\sample.fixture", true)]
    [InlineData(@"C:\work\synthetic\sample.bin", false)]
    [InlineData(@"C:\work\fixture-sample.bin", false)]
    [InlineData(@"C:\fixtures\canonical-sample.bin", false)]
    [InlineData(@"C:\work\nonfixture-sample.bin", false)]
    [InlineData(@"C:\work\prefixfixture\sample.bin", false)]
    [InlineData(@"C:\work\canonical-sample.bin", false)]
    [InlineData("", false)]
    [InlineData(null, false)]
    public void IsFixtureImagePath_DetectsFixtureLikeDevicePaths(string? devicePath, bool expected)
    {
        Assert.Equal(expected, InvokeIsFixtureImagePath(devicePath));
    }

    [Theory]
    [InlineData(@"\\.\PhysicalDrive3", false, false, false, true, true, true)]
    [InlineData(@"\\?\PhysicalDrive8", false, true, false, true, true, true)]
    [InlineData(@"C:\images\canonical-sample.bin", false, false, false, true, true, true)]
    [InlineData(@"C:\images\canonical-sample.bin", true, false, true, true, true, true)]
    public void ResolveEffectiveNonFixtureScaffoldControls_EnforcesRawDeviceSafetyOverrides(
        string deviceId,
        bool configuredDisallowScaffoldCommit,
        bool configuredRejectScaffoldReplay,
        bool configuredRequireCanonicalReplayCandidate,
        bool expectedDisallowScaffoldCommit,
        bool expectedRejectScaffoldReplay,
        bool expectedRequireCanonicalReplayCandidate)
    {
        var options = new ServiceHostOptions
        {
            NativeWriteDisallowScaffoldCommitOnNonFixture = configuredDisallowScaffoldCommit,
            NativeWriteRejectScaffoldReplayBlobOnNonFixture = configuredRejectScaffoldReplay,
            NativeWriteRequireCanonicalReplayCandidateOnNonFixture = configuredRequireCanonicalReplayCandidate,
        };

        using var backend = new NativeApfsBackend(options);
        var controls = InvokeResolveEffectiveNonFixtureScaffoldControls(backend, deviceId);

        Assert.Equal(expectedDisallowScaffoldCommit, controls.DisallowScaffoldCommitOnNonFixture);
        Assert.Equal(expectedRejectScaffoldReplay, controls.RejectScaffoldReplayBlobOnNonFixture);
        Assert.Equal(expectedRequireCanonicalReplayCandidate, controls.RequireCanonicalReplayCandidateOnNonFixture);
    }

    [Theory]
    [InlineData(null, true, false)]
    [InlineData("", true, false)]
    [InlineData(@"\\.\PhysicalDrive6", true, false)]
    [InlineData(@"\\?\PhysicalDrive2", false, false)]
    [InlineData(@"C:\images\canonical-sample.bin", true, false)]
    [InlineData(@"C:\fixtures\sample.apfs.img", true, true)]
    [InlineData(@"C:\fixtures\sample.apfs.img", false, false)]
    public void ResolveEffectiveAllowLegacyScaffoldForFixtures_IsFixtureScopedAndFailClosed(
        string? deviceId,
        bool configuredAllowLegacyScaffoldForFixtures,
        bool expectedAllowLegacyScaffoldForFixtures)
    {
        var options = new ServiceHostOptions
        {
            NativeWriteAllowLegacyScaffoldForFixtures = configuredAllowLegacyScaffoldForFixtures,
        };

        using var backend = new NativeApfsBackend(options);
        var effectiveAllowLegacyScaffoldForFixtures =
            InvokeResolveEffectiveAllowLegacyScaffoldForFixtures(backend, deviceId);

        Assert.Equal(expectedAllowLegacyScaffoldForFixtures, effectiveAllowLegacyScaffoldForFixtures);
    }

    [Theory]
    [InlineData(@"\\.\PhysicalDrive6|Main", false, false, false, true, true, true)]
    [InlineData(@"C:\fixtures\sample.apfs.img|Main", false, false, false, false, false, false)]
    [InlineData(@"C:\fixtures\sample.apfs.img|Main", true, false, true, true, false, true)]
    public void ResolveEffectiveNonFixtureScaffoldControlsForMountedVolume_UsesVolumeIdDevicePrefixWhenCacheMisses(
        string volumeId,
        bool configuredDisallowScaffoldCommit,
        bool configuredRejectScaffoldReplay,
        bool configuredRequireCanonicalReplayCandidate,
        bool expectedDisallowScaffoldCommit,
        bool expectedRejectScaffoldReplay,
        bool expectedRequireCanonicalReplayCandidate)
    {
        var options = new ServiceHostOptions
        {
            NativeWriteDisallowScaffoldCommitOnNonFixture = configuredDisallowScaffoldCommit,
            NativeWriteRejectScaffoldReplayBlobOnNonFixture = configuredRejectScaffoldReplay,
            NativeWriteRequireCanonicalReplayCandidateOnNonFixture = configuredRequireCanonicalReplayCandidate,
        };

        using var backend = new NativeApfsBackend(options);
        var controls = InvokeResolveEffectiveNonFixtureScaffoldControlsForMountedVolume(backend, volumeId);

        Assert.Equal(expectedDisallowScaffoldCommit, controls.DisallowScaffoldCommitOnNonFixture);
        Assert.Equal(expectedRejectScaffoldReplay, controls.RejectScaffoldReplayBlobOnNonFixture);
        Assert.Equal(expectedRequireCanonicalReplayCandidate, controls.RequireCanonicalReplayCandidateOnNonFixture);
    }

    [Theory]
    [InlineData(MountAccessMode.ReadOnly, "Native", "Disabled", NativeWriteReadiness.Unavailable)]
    [InlineData(MountAccessMode.ReadWrite, "Native", "Native", NativeWriteReadiness.BootstrapReady)]
    [InlineData(MountAccessMode.ReadWrite, "Overlay", "Overlay", NativeWriteReadiness.MutationReady)]
    [InlineData(MountAccessMode.ReadWrite, "Disabled", "Disabled", NativeWriteReadiness.Unavailable)]
    public void BuildDefaultHostRuntimeStatus_ResolvesExpectedFallback(
        MountAccessMode accessMode,
        string configuredBackend,
        string expectedBackend,
        NativeWriteReadiness expectedReadiness)
    {
        var status = InvokeBuildDefaultHostRuntimeStatus(accessMode, configuredBackend);

        Assert.Equal(expectedBackend, status.WriteBackend);
        Assert.Equal(expectedReadiness, status.NativeWriteReadiness);
        Assert.Equal(NativeWriteValidationState.Scaffold, status.NativeWriteValidationState);
        Assert.False(status.RecoveryActive);
        Assert.Null(status.RecoveryReason);
        Assert.Null(status.LastCommitXid);
        Assert.False(status.ShutdownDrainActive);
        Assert.Equal(0, status.InFlightMutationCallbacks);
        Assert.Equal(
            accessMode == MountAccessMode.ReadWrite && !string.Equals(expectedBackend, "Disabled", StringComparison.OrdinalIgnoreCase)
                ? NativeWriteSafetyState.PilotReadWrite
                : NativeWriteSafetyState.ReadOnlyFallback,
            status.NativeWriteSafetyState);
    }

    [Theory]
    [InlineData("CommitTimedOut", "NativeWriteCommitTimedOut", "RecoveryFailClosedCommitTimeout")]
    [InlineData("CommitCheckpointWriteFailed", "NativeWriteCommitPersistFailed", "RecoveryFailClosedCommitPersistFailed")]
    [InlineData("CommitObjectMapRoundTripFailed", "NativeWriteCommitPersistFailed", "RecoveryFailClosedCommitPersistFailed")]
    [InlineData("CommitSpacemanRoundTripFailed", "NativeWriteCommitPersistFailed", "RecoveryFailClosedCommitPersistFailed")]
    [InlineData("CommitInodeRoundTripFailed", "NativeWriteCommitPersistFailed", "RecoveryFailClosedCommitPersistFailed")]
    [InlineData("CommitBtreeRoundTripFailed", "NativeWriteCommitPersistFailed", "RecoveryFailClosedCommitPersistFailed")]
    [InlineData("IntegrityCheckFailedOnMount", "NativeWriteIntegrityCheckFailed", "RecoveryFailClosedIntegrity")]
    [InlineData("IntegrityMissingAllocationMap", "NativeWriteIntegrityMissingAllocationMap", "RecoveryFailClosedIntegrityAllocationMap")]
    [InlineData("PersistentStateAheadOfSuperblock", "NativeWriteReplayFailed", "RecoveryFailClosedReplay")]
    [InlineData("PersistentStateBehindSuperblock", "NativeWriteReplayFailed", "RecoveryFailClosedReplay")]
    [InlineData("ReplayIntegrityCheckFailed", "NativeWriteReplayFailed", "RecoveryFailClosedReplay")]
    [InlineData("ReplayCommitBlobInvalid", "NativeWriteReplayFailed", "RecoveryFailClosedReplay")]
    [InlineData("ReplayCanonicalCandidateMissing", "NativeWriteReplayFailed", "RecoveryFailClosedReplay")]
    [InlineData("ReplayCheckpointPendingWindow", "NativeWriteReplayFailed", "RecoveryFailClosedReplay")]
    [InlineData("ReplayCheckpointNotPendingWindow", "NativeWriteReplayFailed", "RecoveryFailClosedReplay")]
    [InlineData("ReplayInterruptedBeforeCheckpointSwitch", "NativeWriteReplayFailed", "RecoveryFailClosedReplay")]
    [InlineData("ReplayCheckpointWriteFailed", "NativeWriteReplayFailed", "RecoveryFailClosedReplay")]
    [InlineData("ReplayInterruptedBeforeCheckpointFlush", "NativeWriteReplayFailed", "RecoveryFailClosedReplay")]
    [InlineData("ReplayCheckpointFlushFailed", "NativeWriteReplayFailed", "RecoveryFailClosedReplay")]
    [InlineData("CommitInterruptedBeforeReplayPersist", "NativeWriteCommitPersistFailed", "RecoveryFailClosedCommitPersistFailed")]
    [InlineData("CommitReplayPersistFailed", "NativeWriteCommitPersistFailed", "RecoveryFailClosedCommitPersistFailed")]
    [InlineData("CommitInterruptedBeforeReplayRoundTripVerify", "NativeWriteCommitPersistFailed", "RecoveryFailClosedCommitPersistFailed")]
    [InlineData("CommitReplayRoundTripFailed", "NativeWriteCommitPersistFailed", "RecoveryFailClosedCommitPersistFailed")]
    [InlineData("CommitInterruptedBeforeCheckpointRoundTripVerify", "NativeWriteCommitPersistFailed", "RecoveryFailClosedCommitPersistFailed")]
    [InlineData("CommitCheckpointRoundTripFailed", "NativeWriteCommitPersistFailed", "RecoveryFailClosedCommitPersistFailed")]
    [InlineData("NativeWriteBootstrapFailed", "NativeWriteBootstrapFailed", "RecoveryFailClosedBootstrap")]
    [InlineData("FixtureLegacyFallbackActive", "NativeWriteFixtureFallbackActive", "RecoveryFailClosedFixtureFallback")]
    [InlineData("ScaffoldCommitBlobActive", "NativeWriteScaffoldCommitBlobActive", "RecoveryFailClosedScaffoldCommitBlob")]
    [InlineData("RecoveryMarkerDirty", "NativeWriteRecoveryMarkerDirty", "RecoveryFailClosedMarkerDirty")]
    [InlineData("DirtyTransactionLimitExceeded", "NativeWriteDirtyTransactionLimitExceeded", "RecoveryFailClosedDirtyLimit")]
    [InlineData("CanonicalPathNotActive", "NativeWriteCanonicalPathNotActive", "RecoveryFailClosedCanonicalPath")]
    [InlineData("CanonicalStateNotLoaded", "NativeWriteCanonicalGateFailure", "RecoveryFailClosedCanonicalGate")]
    [InlineData("CanonicalVolumeStateLoadFailed", "NativeWriteCanonicalGateFailure", "RecoveryFailClosedCanonicalGate")]
    [InlineData("CanonicalObjectMapStateInvalid", "NativeWriteCanonicalGateFailure", "RecoveryFailClosedCanonicalGate")]
    [InlineData("CanonicalSpacemanStateInvalid", "NativeWriteCanonicalGateFailure", "RecoveryFailClosedCanonicalGate")]
    [InlineData("CanonicalVolumeTreeStateInvalid", "NativeWriteCanonicalGateFailure", "RecoveryFailClosedCanonicalGate")]
    [InlineData("NativeWriteNotReady", "NativeWriteCanonicalGateFailure", "RecoveryFailClosedCanonicalGate")]
    [InlineData("WriteDeviceNotAllowed", "NativeWriteCanonicalGateFailure", "RecoveryFailClosedCanonicalGate")]
    [InlineData("CommitPathNotReady", "NativeWriteCanonicalGateFailure", "RecoveryFailClosedCanonicalGate")]
    [InlineData("CanonicalCommitNotReady", "NativeWriteCanonicalGateFailure", "RecoveryFailClosedCanonicalGate")]
    [InlineData("ValidationEvidenceInsufficient", "NativeWriteValidationEvidenceInsufficient", "RecoveryFailClosedValidationEvidence")]
    [InlineData("ValidationCrashFaultEvidenceInsufficient", "NativeWriteValidationCrashFaultEvidenceInsufficient", "RecoveryFailClosedValidationCrashFaultEvidence")]
    [InlineData("ValidationHardwarePilotEvidenceInsufficient", "NativeWriteValidationHardwarePilotEvidenceInsufficient", "RecoveryFailClosedValidationHardwarePilotEvidence")]
    [InlineData("ValidationCrossOsEvidenceInsufficient", "NativeWriteValidationCrossOsEvidenceInsufficient", "RecoveryFailClosedValidationCrossOsEvidence")]
    [InlineData("ValidationMacOsEvidenceInsufficient", "NativeWriteValidationMacOsEvidenceInsufficient", "RecoveryFailClosedValidationMacOsEvidence")]
    [InlineData("ValidationPowerLossEvidenceInsufficient", "NativeWriteValidationPowerLossEvidenceInsufficient", "RecoveryFailClosedValidationPowerLossEvidence")]
    [InlineData("ValidationCanonicalEvidenceInsufficient", "NativeWriteValidationCanonicalEvidenceInsufficient", "RecoveryFailClosedValidationCanonicalEvidence")]
    [InlineData("ValidationHardwarePilotEvidenceStale", "NativeWriteValidationHardwarePilotEvidenceStale", "RecoveryFailClosedValidationHardwarePilotStale")]
    [InlineData("ValidationStableEvidenceStale", "NativeWriteValidationStableEvidenceStale", "RecoveryFailClosedValidationStableStale")]
    [InlineData("WriteGateBlocked", "NativeWriteGateBlocked", "RecoveryFailClosedWriteGate")]
    [InlineData("unknown-reason", "NativeWriteRecoveryFailClosed", "RecoveryFailClosed")]
    [InlineData(null, "NativeWriteRecoveryFailClosed", "RecoveryFailClosed")]
    public void RecoveryFailClosedMappings_ReturnExpectedDiagnosticAndGateState(
        string? recoveryReason,
        string expectedDiagnosticCode,
        string expectedGateState)
    {
        var diagnosticCode = InvokeStaticStringMethod(
            "BuildRecoveryFailClosedDiagnosticCode",
            recoveryReason);
        var gateState = InvokeStaticStringMethod(
            "BuildRecoveryFailClosedGateState",
            recoveryReason);

        Assert.Equal(expectedDiagnosticCode, diagnosticCode);
        Assert.Equal(expectedGateState, gateState);
    }

    [Fact]
    public void BuildNativeWriteDiagnostics_EmitsValidationGateDiagnosticForValidationReason()
    {
        var diagnostics = InvokeBuildNativeWriteDiagnostics(
            effectiveAccessMode: MountAccessMode.ReadOnly,
            effectiveWriteBackend: "Native",
            effectiveValidationState: NativeWriteValidationState.CanonicalImageValidated,
            requiredValidationState: NativeWriteValidationState.HardwarePilotValidated,
            recoveryReason: "ValidationCrashFaultEvidenceInsufficient",
            recoveryAction: "DowngradedAfterValidationCrashFaultGate",
            validationEvidence: new NativeWriteValidationEvidence(CrashFaultPasses: 1),
            recoveryActive: true,
            failClosedTriggered: true,
            scope: "Runtime");

        var diagnostic = Assert.Single(diagnostics);
        Assert.Equal("NativeWriteValidationCrashFaultEvidenceInsufficient", diagnostic.Code);
        Assert.Equal("Runtime:ValidationGate", diagnostic.Scope);
        Assert.True(diagnostic.IsFailClosed);
        Assert.Equal("ValidationCrashFaultEvidenceInsufficient", diagnostic.RecoveryReason);
        Assert.Equal(NativeWriteValidationState.CanonicalImageValidated, diagnostic.ValidationState);
        Assert.Equal(NativeWriteValidationState.HardwarePilotValidated, diagnostic.RequiredValidationState);
        Assert.NotNull(diagnostic.ValidationEvidence);
        Assert.Equal(1, diagnostic.ValidationEvidence!.CrashFaultPasses);
    }

    [Fact]
    public void BuildNativeWriteDiagnostics_EmitsValidationGapDiagnosticWithoutRecoveryReason()
    {
        var diagnostics = InvokeBuildNativeWriteDiagnostics(
            effectiveAccessMode: MountAccessMode.ReadWrite,
            effectiveWriteBackend: "Native",
            effectiveValidationState: NativeWriteValidationState.CanonicalImageValidated,
            requiredValidationState: NativeWriteValidationState.Stable,
            recoveryReason: null,
            recoveryAction: null,
            validationEvidence: new NativeWriteValidationEvidence(CrashFaultPasses: 2, HardwarePilotPasses: 1),
            recoveryActive: false,
            failClosedTriggered: false,
            scope: "Mount");

        var diagnostic = Assert.Single(diagnostics);
        Assert.Equal("NativeWriteValidationStableRequired", diagnostic.Code);
        Assert.Equal("Mount:ValidationGate", diagnostic.Scope);
        Assert.True(diagnostic.IsFailClosed);
        Assert.Equal("ValidationEvidenceInsufficient", diagnostic.RecoveryReason);
        Assert.Equal(NativeWriteValidationState.CanonicalImageValidated, diagnostic.ValidationState);
        Assert.Equal(NativeWriteValidationState.Stable, diagnostic.RequiredValidationState);
    }

    [Fact]
    public void BuildHostRuntimeStatusFromPayload_ForcesRecoveryState_WhenReplayReasonIsPresent()
    {
        var status = InvokeBuildHostRuntimeStatusFromPayload(
            accessMode: MountAccessMode.ReadWrite,
            configuredBackend: "Native",
            payloadWriteBackend: "Native",
            payloadCommitModel: null,
            payloadReadiness: "CommitReady",
            payloadRecoveryActive: false,
            payloadRecoveryReason: "ReplayCommitBlobInvalid",
            payloadLastCommitXid: 51,
            payloadSafetyState: null,
            payloadLastRecoveryAction: null,
            payloadDirtyTransactionCount: 0);

        Assert.Equal("Native", status.WriteBackend);
        Assert.Equal(NativeWriteReadiness.CommitReady, status.NativeWriteReadiness);
        Assert.True(status.RecoveryActive);
        Assert.Equal("ReplayCommitBlobInvalid", status.RecoveryReason);
        Assert.Equal((ulong)51, status.LastCommitXid);
        Assert.Equal(NativeWriteSafetyState.RecoveryBlocked, status.NativeWriteSafetyState);
        Assert.Equal("ReplaySkippedFailClosed", status.LastRecoveryAction);
        Assert.Equal(NativeWriteValidationState.Scaffold, status.NativeWriteValidationState);
        Assert.False(status.ShutdownDrainActive);
        Assert.Equal(0, status.InFlightMutationCallbacks);
    }

    [Fact]
    public void BuildHostRuntimeStatusFromPayload_DerivesCanonicalGateFailure_FromCanonicalRecoveryReason_WhenPayloadFieldMissing()
    {
        var status = InvokeBuildHostRuntimeStatusFromPayload(
            accessMode: MountAccessMode.ReadWrite,
            configuredBackend: "Native",
            payloadWriteBackend: "Native",
            payloadCommitModel: "CanonicalApfsCheckpoint",
            payloadReadiness: "MutationReady",
            payloadRecoveryActive: true,
            payloadRecoveryReason: " canonical commit not ready ",
            payloadLastCommitXid: 52,
            payloadSafetyState: null,
            payloadLastRecoveryAction: null,
            payloadDirtyTransactionCount: 0,
            payloadCanonicalGateFailure: null);

        Assert.Equal("Native", status.WriteBackend);
        Assert.Equal("CanonicalCommitNotReady", status.RecoveryReason);
        Assert.Equal("CanonicalCommitNotReady", status.CanonicalGateFailure);
        Assert.False(status.CanonicalPathActive);
        Assert.Equal((ulong)52, status.LastCommitXid);
        Assert.Equal(NativeWriteSafetyState.RecoveryBlocked, status.NativeWriteSafetyState);
    }

    [Fact]
    public void BuildHostRuntimeStatusFromPayload_ParsesValidationEvidencePayload()
    {
        var lastValidatedUtc = DateTime.UtcNow.AddMinutes(-15);
        var status = InvokeBuildHostRuntimeStatusFromPayload(
            accessMode: MountAccessMode.ReadWrite,
            configuredBackend: "Native",
            payloadWriteBackend: "Native",
            payloadCommitModel: "CanonicalApfsCheckpoint",
            payloadReadiness: "CommitReady",
            payloadRecoveryActive: false,
            payloadRecoveryReason: null,
            payloadLastCommitXid: 92,
            payloadSafetyState: "PilotReadWrite",
            payloadLastRecoveryAction: null,
            payloadDirtyTransactionCount: 0,
            payloadValidationState: "CanonicalImageValidated",
            payloadShutdownDrainActive: false,
            payloadInFlightMutationCallbacks: 0,
            payloadHostPid: 8899,
            payloadValidationCrashFaultPasses: 4,
            payloadValidationHardwarePilotPasses: 6,
            payloadValidationMacOsValidationPasses: 2,
            payloadValidationPowerLossPassVerified: true,
            payloadValidationLastValidatedUtc: lastValidatedUtc.ToString("o"));

        Assert.NotNull(status.ValidationEvidence);
        Assert.Equal(4, status.ValidationEvidence!.CrashFaultPasses);
        Assert.Equal(6, status.ValidationEvidence.HardwarePilotPasses);
        Assert.Equal(2, status.ValidationEvidence.MacOsValidationPasses);
        Assert.True(status.ValidationEvidence.PowerLossPassVerified);
        Assert.True(status.ValidationEvidence.LastValidatedUtc.HasValue);
        Assert.Equal(lastValidatedUtc.ToUniversalTime(), status.ValidationEvidence.LastValidatedUtc!.Value);
        Assert.Equal(8899, status.HostProcessId);
    }

    [Theory]
    [InlineData("ScaffoldOnly", NativeWriteValidationState.CanonicalImageValidated, "NativeValidationCanonicalImageRequired", "NativeWriteValidationCanonicalImageRequired")]
    [InlineData("PilotHardware", NativeWriteValidationState.HardwarePilotValidated, "NativeValidationHardwarePilotRequired", "NativeWriteValidationHardwarePilotRequired")]
    [InlineData("Stable", NativeWriteValidationState.Stable, "NativeValidationStableRequired", "NativeWriteValidationStableRequired")]
    [InlineData("unknown", NativeWriteValidationState.CanonicalImageValidated, "NativeValidationCanonicalImageRequired", "NativeWriteValidationCanonicalImageRequired")]
    [InlineData(null, NativeWriteValidationState.CanonicalImageValidated, "NativeValidationCanonicalImageRequired", "NativeWriteValidationCanonicalImageRequired")]
    public void NativeWriteValidationPromotionRequirement_ResolvesExpectedThresholdAndCodes(
        string? policy,
        NativeWriteValidationState expectedState,
        string expectedGateState,
        string expectedDiagnosticCode)
    {
        var requiredState = InvokeResolveRequiredValidationStateForPromotionPolicy(policy);
        Assert.Equal(expectedState, requiredState);
        Assert.Equal(expectedGateState, InvokeBuildNativeValidationGateState(requiredState));
        Assert.Equal(expectedDiagnosticCode, InvokeBuildNativeValidationDiagnosticCode(requiredState));
    }

    [Theory]
    [InlineData(MountAccessMode.ReadWrite, "Native", NativeWriteValidationState.CanonicalImageValidated, NativeWriteValidationState.HardwarePilotValidated, "ValidationEvidenceInsufficient")]
    [InlineData(MountAccessMode.ReadWrite, "Native", NativeWriteValidationState.Stable, NativeWriteValidationState.HardwarePilotValidated, null)]
    [InlineData(MountAccessMode.ReadOnly, "Native", NativeWriteValidationState.CanonicalImageValidated, NativeWriteValidationState.HardwarePilotValidated, null)]
    [InlineData(MountAccessMode.ReadWrite, "Disabled", NativeWriteValidationState.CanonicalImageValidated, NativeWriteValidationState.HardwarePilotValidated, null)]
    public void GetValidationPolicyFailClosedReason_ReturnsExpectedResult(
        MountAccessMode accessMode,
        string writeBackend,
        NativeWriteValidationState effectiveValidationState,
        NativeWriteValidationState requiredValidationState,
        string? expectedReason)
    {
        var reason = InvokeGetValidationPolicyFailClosedReason(
            accessMode,
            writeBackend,
            effectiveValidationState,
            requiredValidationState);
        Assert.Equal(expectedReason, reason);
    }

    [Theory]
    [InlineData("PilotHardware", true, 2, 2, 2, true, 1, 2, 0, false, NativeWriteValidationState.CanonicalImageValidated, NativeWriteValidationState.HardwarePilotValidated, "ValidationCrashFaultEvidenceInsufficient")]
    [InlineData("PilotHardware", false, 0, 3, 2, true, 5, 1, 0, false, NativeWriteValidationState.CanonicalImageValidated, NativeWriteValidationState.HardwarePilotValidated, "ValidationHardwarePilotEvidenceInsufficient")]
    [InlineData("Stable", true, 1, 2, 3, true, 3, 3, 1, false, NativeWriteValidationState.HardwarePilotValidated, NativeWriteValidationState.Stable, "ValidationCrossOsEvidenceInsufficient")]
    [InlineData("Stable", true, 1, 2, 3, true, 3, 3, 3, false, NativeWriteValidationState.CrossOsValidated, NativeWriteValidationState.Stable, "ValidationPowerLossEvidenceInsufficient")]
    [InlineData("ScaffoldOnly", false, 0, 0, 0, false, 0, 0, 0, false, NativeWriteValidationState.Scaffold, NativeWriteValidationState.CanonicalImageValidated, "ValidationCanonicalEvidenceInsufficient")]
    public void GetValidationPolicyFailClosedReasonDetailed_ReturnsThresholdSpecificReasons(
        string promotionPolicy,
        bool crashFaultMatrixRequired,
        int minCrashFaultPasses,
        int minHardwarePilotPasses,
        int minMacOsValidationPasses,
        bool stableRequiresPowerLossPass,
        int crashFaultPasses,
        int hardwarePilotPasses,
        int macOsValidationPasses,
        bool powerLossPassVerified,
        NativeWriteValidationState effectiveValidationState,
        NativeWriteValidationState requiredValidationState,
        string expectedReason)
    {
        var options = new ServiceHostOptions
        {
            NativeWritePromotionPolicy = promotionPolicy,
            NativeWriteCrashFaultMatrixRequired = crashFaultMatrixRequired,
            NativeWriteMinCrashFaultPasses = minCrashFaultPasses,
            NativeWriteMinCrashStageMatrixPasses = 0,
            NativeWriteMinHardwarePilotPasses = minHardwarePilotPasses,
            NativeWriteMinHotUnplugPasses = 0,
            NativeWriteMinMacOsValidationPasses = minMacOsValidationPasses,
            NativeWriteMinMacOsConsistencyPasses = 0,
            NativeWriteMinPowerLossReplayPasses = 0,
            NativeWriteStableRequiresPowerLossPass = stableRequiresPowerLossPass,
            NativeWriteEvidenceStorePath = string.Empty,
        };

        var reason = InvokeGetValidationPolicyFailClosedReasonDetailed(
            options,
            MountAccessMode.ReadWrite,
            "Native",
            effectiveValidationState,
            requiredValidationState,
            new NativeWriteValidationEvidence(
                CrashFaultPasses: crashFaultPasses,
                HardwarePilotPasses: hardwarePilotPasses,
                MacOsValidationPasses: macOsValidationPasses,
                PowerLossPassVerified: powerLossPassVerified,
                LastValidatedUtc: DateTime.UtcNow));

        Assert.Equal(expectedReason, reason);
    }

    [Theory]
    [InlineData("PilotHardware", NativeWriteValidationState.HardwarePilotValidated, "ValidationHardwarePilotEvidenceStale")]
    [InlineData("Stable", NativeWriteValidationState.Stable, "ValidationStableEvidenceStale")]
    public void GetValidationPolicyFailClosedReasonDetailed_ReturnsStaleEvidenceReasons_ForRawPhysicalVolumes(
        string promotionPolicy,
        NativeWriteValidationState requiredValidationState,
        string expectedReason)
    {
        var options = new ServiceHostOptions
        {
            NativeWritePromotionPolicy = promotionPolicy,
            NativeWriteCrashFaultMatrixRequired = true,
            NativeWriteMinCrashFaultPasses = 1,
            NativeWriteMinCrashStageMatrixPasses = 0,
            NativeWriteMinHardwarePilotPasses = 1,
            NativeWriteMinHotUnplugPasses = 0,
            NativeWriteMinMacOsValidationPasses = 1,
            NativeWriteMinMacOsConsistencyPasses = 0,
            NativeWriteMinPowerLossReplayPasses = 0,
            NativeWriteStableRequiresPowerLossPass = false,
            NativeWriteValidationEvidenceMaxAgeDays = 7,
            NativeWriteEvidenceStorePath = string.Empty,
        };

        var reason = InvokeGetValidationPolicyFailClosedReasonDetailed(
            options,
            MountAccessMode.ReadWrite,
            "Native",
            requiredValidationState,
            requiredValidationState,
            new NativeWriteValidationEvidence(
                CrashFaultPasses: 8,
                HardwarePilotPasses: 8,
                MacOsValidationPasses: 8,
                PowerLossPassVerified: true,
                LastValidatedUtc: DateTime.UtcNow.AddDays(-8)),
            new VolumeInfo(
                VolumeId: @"\\.\PhysicalDrive3|Main",
                DeviceId: @"\\.\PhysicalDrive3",
                VolumeName: "Main",
                SupportsReadWrite: true,
                IsEncrypted: false,
                SupportsExplorerMount: true,
                NativeVolumePath: @"\\.\PhysicalDrive3\ApfsAccess_Volumes\Main",
                SupportsNativeWrite: true,
                WriteBlockReason: null,
                WriteIncompatibilities: Array.Empty<string>(),
                WriteUnsupportedFeatures: Array.Empty<string>(),
                NativeWriteReadiness: NativeWriteReadiness.CommitReady));

        Assert.Equal(expectedReason, reason);
    }

    [Fact]
    public void GetValidationPolicyFailClosedReasonDetailed_IgnoresStaleness_ForNonRawImageVolumes()
    {
        var options = new ServiceHostOptions
        {
            NativeWritePromotionPolicy = "Stable",
            NativeWriteCrashFaultMatrixRequired = true,
            NativeWriteMinCrashFaultPasses = 1,
            NativeWriteMinCrashStageMatrixPasses = 0,
            NativeWriteMinHardwarePilotPasses = 1,
            NativeWriteMinHotUnplugPasses = 0,
            NativeWriteMinMacOsValidationPasses = 1,
            NativeWriteMinMacOsConsistencyPasses = 0,
            NativeWriteMinPowerLossReplayPasses = 0,
            NativeWriteStableRequiresPowerLossPass = true,
            NativeWriteValidationEvidenceMaxAgeDays = 7,
            NativeWriteEvidenceStorePath = string.Empty,
        };
        var imageVolume = new VolumeInfo(
            VolumeId: @"C:\fixtures\sample.apfs.img|Main",
            DeviceId: @"C:\fixtures\sample.apfs.img",
            VolumeName: "Main",
            SupportsReadWrite: true,
            IsEncrypted: false,
            SupportsExplorerMount: true,
            NativeVolumePath: @"C:\fixtures\sample.apfs.img\ApfsAccess_Volumes\Main",
            SupportsNativeWrite: true,
            WriteBlockReason: null,
            WriteIncompatibilities: Array.Empty<string>(),
            WriteUnsupportedFeatures: Array.Empty<string>(),
            NativeWriteReadiness: NativeWriteReadiness.CommitReady
        );

        var reason = InvokeGetValidationPolicyFailClosedReasonDetailed(
            options,
            MountAccessMode.ReadWrite,
            "Native",
            NativeWriteValidationState.Stable,
            NativeWriteValidationState.Stable,
            new NativeWriteValidationEvidence(
                CrashFaultPasses: 8,
                HardwarePilotPasses: 8,
                MacOsValidationPasses: 8,
                PowerLossPassVerified: true,
                LastValidatedUtc: DateTime.UtcNow.AddDays(-30)),
            imageVolume);

        Assert.Null(reason);
    }

    [Fact]
    public void GetValidationPolicyFailClosedReasonDetailed_UsesProfileLedgerForRawPhysicalPilotThresholds()
    {
        var options = new ServiceHostOptions
        {
            NativeWritePromotionPolicy = "PilotHardware",
            NativeWriteCrashFaultMatrixRequired = false,
            NativeWriteMinCrashFaultPasses = 0,
            NativeWriteMinCrashStageMatrixPasses = 0,
            NativeWriteMinHardwarePilotPasses = 2,
            NativeWriteMinHotUnplugPasses = 0,
            NativeWriteMinMacOsValidationPasses = 0,
            NativeWriteMinMacOsConsistencyPasses = 0,
            NativeWriteMinPowerLossReplayPasses = 0,
            NativeWriteStableRequiresPowerLossPass = false,
            NativeWriteValidationEvidenceMaxAgeDays = 0,
            NativeWriteEvidenceStorePath = string.Empty,
        };
        var rawVolume = new VolumeInfo(
            VolumeId: @"\\.\PhysicalDrive5|Main",
            DeviceId: @"\\.\PhysicalDrive5",
            VolumeName: "Main",
            SupportsReadWrite: true,
            IsEncrypted: false,
            SupportsExplorerMount: true,
            NativeVolumePath: @"\\.\PhysicalDrive5\ApfsAccess_Volumes\Main",
            SupportsNativeWrite: true,
            WriteBlockReason: null,
            WriteIncompatibilities: Array.Empty<string>(),
            WriteUnsupportedFeatures: Array.Empty<string>(),
            NativeWriteReadiness: NativeWriteReadiness.CommitReady
        );

        var reason = InvokeGetValidationPolicyFailClosedReasonDetailed(
            options,
            MountAccessMode.ReadWrite,
            "Native",
            NativeWriteValidationState.HardwarePilotValidated,
            NativeWriteValidationState.HardwarePilotValidated,
            new NativeWriteValidationEvidence(
                CrashFaultPasses: 9,
                HardwarePilotPasses: 9,
                MacOsValidationPasses: 9,
                PowerLossPassVerified: true,
                LastValidatedUtc: DateTime.UtcNow),
            rawVolume);

        Assert.Equal("ValidationHardwarePilotEvidenceInsufficient", reason);
    }

    [Fact]
    public void BuildValidationEvidenceDiagnosticDetail_IncludesThresholdsAndStalenessForRawVolumes()
    {
        var options = new ServiceHostOptions
        {
            NativeWritePromotionPolicy = "Stable",
            NativeWriteCrashFaultMatrixRequired = true,
            NativeWriteMinCrashFaultPasses = 2,
            NativeWriteMinHardwarePilotPasses = 3,
            NativeWriteMinMacOsValidationPasses = 2,
            NativeWriteStableRequiresPowerLossPass = true,
            NativeWriteValidationEvidenceMaxAgeDays = 7,
            NativeWriteEvidenceStorePath = string.Empty,
        };
        var volume = new VolumeInfo(
            VolumeId: @"\\.\PhysicalDrive7|Main",
            DeviceId: @"\\.\PhysicalDrive7",
            VolumeName: "Main",
            SupportsReadWrite: true,
            IsEncrypted: false,
            SupportsExplorerMount: true,
            NativeVolumePath: @"\\.\PhysicalDrive7\ApfsAccess_Volumes\Main",
            SupportsNativeWrite: true,
            WriteBlockReason: null,
            WriteIncompatibilities: Array.Empty<string>(),
            WriteUnsupportedFeatures: Array.Empty<string>(),
            NativeWriteReadiness: NativeWriteReadiness.CommitReady
        );

        var detail = InvokeBuildValidationEvidenceDiagnosticDetail(
            options,
            volume,
            requiredValidationState: NativeWriteValidationState.Stable,
            evidence: new NativeWriteValidationEvidence(
                CrashFaultPasses: 1,
                HardwarePilotPasses: 1,
                MacOsValidationPasses: 1,
                PowerLossPassVerified: false,
                LastValidatedUtc: DateTime.UtcNow.AddDays(-10)),
            failClosedReason: "ValidationStableEvidenceStale",
            nowUtc: DateTime.UtcNow);

        Assert.Contains("scope=raw", detail);
        Assert.Contains("crash=1/2", detail);
        Assert.Contains("hardware=1/3", detail);
        Assert.Contains("macos=1/2", detail);
        Assert.Contains("powerLoss=false/true", detail);
        Assert.Contains("maxAgeDays=7", detail);
        Assert.Contains("stale=true", detail);
        Assert.Contains("reason=ValidationStableEvidenceStale", detail);
    }

    [Fact]
    public void BuildValidationEvidenceDiagnosticDetail_UsesCanonicalThresholdsForNonRawVolumes()
    {
        var options = new ServiceHostOptions
        {
            NativeWritePromotionPolicy = "ScaffoldOnly",
            NativeWriteCrashFaultMatrixRequired = true,
            NativeWriteMinCrashFaultPasses = 3,
            NativeWriteMinHardwarePilotPasses = 4,
            NativeWriteMinMacOsValidationPasses = 5,
            NativeWriteStableRequiresPowerLossPass = true,
            NativeWriteValidationEvidenceMaxAgeDays = 30,
            NativeWriteEvidenceStorePath = string.Empty,
        };
        var volume = new VolumeInfo(
            VolumeId: @"C:\fixtures\sample.apfs.img|Main",
            DeviceId: @"C:\fixtures\sample.apfs.img",
            VolumeName: "Main",
            SupportsReadWrite: true,
            IsEncrypted: false,
            SupportsExplorerMount: true,
            NativeVolumePath: @"C:\fixtures\sample.apfs.img\ApfsAccess_Volumes\Main",
            SupportsNativeWrite: true,
            WriteBlockReason: null,
            WriteIncompatibilities: Array.Empty<string>(),
            WriteUnsupportedFeatures: Array.Empty<string>(),
            NativeWriteReadiness: NativeWriteReadiness.CommitReady
        );

        var detail = InvokeBuildValidationEvidenceDiagnosticDetail(
            options,
            volume,
            requiredValidationState: NativeWriteValidationState.CanonicalImageValidated,
            evidence: new NativeWriteValidationEvidence(
                CrashFaultPasses: 0,
                HardwarePilotPasses: 0,
                MacOsValidationPasses: 0,
                PowerLossPassVerified: false,
                LastValidatedUtc: null),
            failClosedReason: "ValidationCanonicalEvidenceInsufficient",
            nowUtc: DateTime.UtcNow);

        Assert.Contains("scope=nonraw", detail);
        Assert.Contains("crash=0/0", detail);
        Assert.Contains("hardware=0/0", detail);
        Assert.Contains("macos=0/0", detail);
        Assert.Contains("powerLoss=false/false", detail);
        Assert.Contains("maxAgeDays=0", detail);
        Assert.Contains("stale=false", detail);
        Assert.Contains("reason=ValidationCanonicalEvidenceInsufficient", detail);
    }

    [Theory]
    [InlineData(MountAccessMode.ReadWrite, "Native", false, "WriteGateBlocked")]
    [InlineData(MountAccessMode.ReadWrite, "Overlay", false, "WriteGateBlocked")]
    [InlineData(MountAccessMode.ReadOnly, "Native", false, null)]
    [InlineData(MountAccessMode.ReadWrite, "Disabled", false, null)]
    [InlineData(MountAccessMode.ReadWrite, "Native", true, null)]
    public void GetWriteGateFailClosedReason_ReturnsExpectedResult(
        MountAccessMode accessMode,
        string writeBackend,
        bool allowWrite,
        string? expectedReason)
    {
        var reason = InvokeGetWriteGateFailClosedReason(
            accessMode,
            writeBackend,
            new WriteGateDecision(
                AllowWrite: allowWrite,
                GateState: allowWrite ? "Enabled" : "PilotAllowListBlocked",
                Reason: allowWrite ? null : "blocked for test"));

        Assert.Equal(expectedReason, reason);
    }

    [Theory]
    [InlineData(MountAccessMode.ReadOnly, "Native", NativeWriteCommitModel.CanonicalApfsCheckpoint, NativeWriteReadiness.CommitReady, false, NativeWriteValidationState.Stable, NativeWriteValidationState.Scaffold)]
    [InlineData(MountAccessMode.ReadWrite, "Disabled", NativeWriteCommitModel.CanonicalApfsCheckpoint, NativeWriteReadiness.CommitReady, false, NativeWriteValidationState.Stable, NativeWriteValidationState.Scaffold)]
    [InlineData(MountAccessMode.ReadWrite, "Native", NativeWriteCommitModel.CanonicalApfsCheckpoint, NativeWriteReadiness.CommitReady, true, NativeWriteValidationState.Stable, NativeWriteValidationState.Scaffold)]
    [InlineData(MountAccessMode.ReadWrite, "Native", NativeWriteCommitModel.ScaffoldCheckpoint, NativeWriteReadiness.CommitReady, false, NativeWriteValidationState.Stable, NativeWriteValidationState.Scaffold)]
    [InlineData(MountAccessMode.ReadWrite, "Native", NativeWriteCommitModel.CanonicalApfsCheckpoint, NativeWriteReadiness.BootstrapReady, false, NativeWriteValidationState.Stable, NativeWriteValidationState.Scaffold)]
    [InlineData(MountAccessMode.ReadWrite, "Native", NativeWriteCommitModel.CanonicalApfsCheckpoint, NativeWriteReadiness.MutationReady, false, NativeWriteValidationState.Stable, NativeWriteValidationState.Scaffold)]
    [InlineData(MountAccessMode.ReadWrite, "Native", NativeWriteCommitModel.CanonicalApfsCheckpoint, NativeWriteReadiness.CommitReady, false, NativeWriteValidationState.Scaffold, NativeWriteValidationState.CanonicalImageValidated)]
    [InlineData(MountAccessMode.ReadWrite, "Native", NativeWriteCommitModel.CanonicalApfsCheckpoint, NativeWriteReadiness.CommitReady, false, NativeWriteValidationState.HardwarePilotValidated, NativeWriteValidationState.HardwarePilotValidated)]
    public void ResolveObservedValidationStateForEvidence_DerivesExpectedState(
        MountAccessMode accessMode,
        string writeBackend,
        NativeWriteCommitModel commitModel,
        NativeWriteReadiness readiness,
        bool recoveryActive,
        NativeWriteValidationState reportedState,
        NativeWriteValidationState expectedState)
    {
        var observed = InvokeResolveObservedValidationStateForEvidence(
            accessMode,
            writeBackend,
            commitModel,
            readiness,
            recoveryActive,
            reportedState
        );

        Assert.Equal(expectedState, observed);
    }

    [Theory]
    [InlineData(@"\\.\PhysicalDrive7", NativeWriteValidationState.Stable, NativeWriteValidationState.Stable)]
    [InlineData(@"\\?\PhysicalDrive9", NativeWriteValidationState.HardwarePilotValidated, NativeWriteValidationState.HardwarePilotValidated)]
    [InlineData(@"C:\fixtures\sample.apfs.img", NativeWriteValidationState.Stable, NativeWriteValidationState.CanonicalImageValidated)]
    [InlineData(@"C:\images\external.apfs", NativeWriteValidationState.CrossOsValidated, NativeWriteValidationState.CanonicalImageValidated)]
    [InlineData(@"C:\images\external.apfs", NativeWriteValidationState.CanonicalImageValidated, NativeWriteValidationState.CanonicalImageValidated)]
    public void ClampObservedValidationStateForVolume_RestrictsNonRawMediaPromotion(
        string deviceId,
        NativeWriteValidationState observedState,
        NativeWriteValidationState expectedState)
    {
        var volume = new VolumeInfo(
            VolumeId: $"{deviceId}|Main",
            DeviceId: deviceId,
            VolumeName: "Main",
            SupportsReadWrite: true,
            IsEncrypted: false,
            SupportsExplorerMount: true,
            NativeVolumePath: $@"{deviceId}\ApfsAccess_Volumes\Main",
            SupportsNativeWrite: true,
            WriteBlockReason: null,
            WriteIncompatibilities: Array.Empty<string>(),
            WriteUnsupportedFeatures: Array.Empty<string>(),
            NativeWriteReadiness: NativeWriteReadiness.CommitReady
        );

        var clamped = InvokeClampObservedValidationStateForVolume(observedState, volume);
        Assert.Equal(expectedState, clamped);
    }

    [Fact]
    public void PromoteValidationEvidenceForObservedState_AccumulatesThresholdCountersIncrementally()
    {
        var nowUtc = new DateTime(2026, 2, 24, 0, 0, 0, DateTimeKind.Utc);
        var baseline = new NativeWriteValidationEvidence(
            CrashFaultPasses: 0,
            HardwarePilotPasses: 1,
            MacOsValidationPasses: 0,
            PowerLossPassVerified: false,
            LastValidatedUtc: null
        );

        var promotedHardware1 = InvokePromoteValidationEvidenceForObservedState(
            baseline,
            NativeWriteValidationState.HardwarePilotValidated,
            minCrashFaultPasses: 2,
            minHardwarePilotPasses: 3,
            minMacOsValidationPasses: 4,
            stableRequiresPowerLossPass: true,
            nowUtc: nowUtc
        );

        Assert.Equal(1, promotedHardware1.CrashFaultPasses);
        Assert.Equal(2, promotedHardware1.HardwarePilotPasses);
        Assert.Equal(0, promotedHardware1.MacOsValidationPasses);
        Assert.False(promotedHardware1.PowerLossPassVerified);
        Assert.Equal(nowUtc, promotedHardware1.LastValidatedUtc);

        var promotedHardware2 = InvokePromoteValidationEvidenceForObservedState(
            promotedHardware1,
            NativeWriteValidationState.HardwarePilotValidated,
            minCrashFaultPasses: 2,
            minHardwarePilotPasses: 3,
            minMacOsValidationPasses: 4,
            stableRequiresPowerLossPass: true,
            nowUtc: nowUtc.AddMinutes(5)
        );

        Assert.Equal(2, promotedHardware2.CrashFaultPasses);
        Assert.Equal(3, promotedHardware2.HardwarePilotPasses);
        Assert.Equal(0, promotedHardware2.MacOsValidationPasses);
        Assert.False(promotedHardware2.PowerLossPassVerified);
        Assert.Equal(nowUtc.AddMinutes(5), promotedHardware2.LastValidatedUtc);

        var promotedHardware3 = InvokePromoteValidationEvidenceForObservedState(
            promotedHardware2,
            NativeWriteValidationState.HardwarePilotValidated,
            minCrashFaultPasses: 2,
            minHardwarePilotPasses: 3,
            minMacOsValidationPasses: 4,
            stableRequiresPowerLossPass: true,
            nowUtc: nowUtc.AddMinutes(10)
        );
        Assert.Equal(2, promotedHardware3.CrashFaultPasses);
        Assert.Equal(3, promotedHardware3.HardwarePilotPasses);
        Assert.Equal(0, promotedHardware3.MacOsValidationPasses);
        Assert.False(promotedHardware3.PowerLossPassVerified);
        Assert.Equal(nowUtc.AddMinutes(5), promotedHardware3.LastValidatedUtc);

        var promotedCrossOs = InvokePromoteValidationEvidenceForObservedState(
            promotedHardware3,
            NativeWriteValidationState.CrossOsValidated,
            minCrashFaultPasses: 2,
            minHardwarePilotPasses: 3,
            minMacOsValidationPasses: 4,
            stableRequiresPowerLossPass: true,
            nowUtc: nowUtc.AddMinutes(15)
        );
        Assert.Equal(1, promotedCrossOs.MacOsValidationPasses);
        Assert.False(promotedCrossOs.PowerLossPassVerified);
        Assert.Equal(nowUtc.AddMinutes(15), promotedCrossOs.LastValidatedUtc);

        var promotedStable = InvokePromoteValidationEvidenceForObservedState(
            promotedCrossOs,
            NativeWriteValidationState.Stable,
            minCrashFaultPasses: 2,
            minHardwarePilotPasses: 3,
            minMacOsValidationPasses: 4,
            stableRequiresPowerLossPass: true,
            nowUtc: nowUtc.AddMinutes(20)
        );
        Assert.Equal(2, promotedStable.MacOsValidationPasses);
        Assert.True(promotedStable.PowerLossPassVerified);
        Assert.Equal(nowUtc.AddMinutes(20), promotedStable.LastValidatedUtc);
    }

    [Fact]
    public void PromoteValidationEvidenceForObservedState_DoesNotIncrementCounters_WhenSessionPromotionDisabled()
    {
        var nowUtc = new DateTime(2026, 2, 24, 12, 0, 0, DateTimeKind.Utc);
        var baseline = new NativeWriteValidationEvidence(
            CrashFaultPasses: 1,
            HardwarePilotPasses: 2,
            MacOsValidationPasses: 1,
            PowerLossPassVerified: false,
            LastValidatedUtc: nowUtc.AddMinutes(-10));

        var promoted = InvokePromoteValidationEvidenceForObservedState(
            baseline,
            NativeWriteValidationState.Stable,
            minCrashFaultPasses: 2,
            minHardwarePilotPasses: 3,
            minMacOsValidationPasses: 2,
            stableRequiresPowerLossPass: true,
            nowUtc: nowUtc,
            allowCounterIncrement: false);

        Assert.Equal(baseline.CrashFaultPasses, promoted.CrashFaultPasses);
        Assert.Equal(baseline.HardwarePilotPasses, promoted.HardwarePilotPasses);
        Assert.Equal(baseline.MacOsValidationPasses, promoted.MacOsValidationPasses);
        Assert.Equal(baseline.PowerLossPassVerified, promoted.PowerLossPassVerified);
        Assert.Equal(baseline.LastValidatedUtc, promoted.LastValidatedUtc);
    }

    [Fact]
    public void ShouldPromoteValidationEvidenceForSession_OnlyPromotesOnNewSessionToken()
    {
        var options = new ServiceHostOptions
        {
            NativeWriteEvidenceStorePath = string.Empty,
        };

        using var backend = new NativeApfsBackend(options);
        var first = InvokeShouldPromoteValidationEvidenceForSession(
            backend,
            "raw::physicaldrive3::main",
            hostProcessId: 4001,
            runtimeSessionId: @"C:\Temp\apfs\status_a.json");
        var second = InvokeShouldPromoteValidationEvidenceForSession(
            backend,
            "raw::physicaldrive3::main",
            hostProcessId: 4001,
            runtimeSessionId: @"C:\Temp\apfs\status_a.json");
        var third = InvokeShouldPromoteValidationEvidenceForSession(
            backend,
            "raw::physicaldrive3::main",
            hostProcessId: 4001,
            runtimeSessionId: @"C:\Temp\apfs\status_b.json");

        Assert.True(first);
        Assert.False(second);
        Assert.True(third);
    }

    [Fact]
    public void MergeValidationEvidenceFromRuntimeStatus_IgnoresRuntimeSeedEvidence_ForRawPhysicalByDefault()
    {
        var options = new ServiceHostOptions
        {
            NativeWriteEvidenceStorePath = string.Empty,
            NativeWriteMinCrashFaultPasses = 3,
            NativeWriteMinHardwarePilotPasses = 3,
            NativeWriteMinMacOsValidationPasses = 2,
            NativeWriteStableRequiresPowerLossPass = true,
            NativeWriteAllowRuntimeEvidenceSeedForRawPhysicalDevices = false,
        };
        using var backend = new NativeApfsBackend(options);
        var volume = new VolumeInfo(
            VolumeId: @"\\.\PhysicalDrive3|Main",
            DeviceId: @"\\.\PhysicalDrive3",
            VolumeName: "Main",
            SupportsReadWrite: true,
            IsEncrypted: false,
            SupportsExplorerMount: true,
            NativeVolumePath: @"\\.\PhysicalDrive3\ApfsAccess_Volumes\Main",
            SupportsNativeWrite: true,
            WriteBlockReason: null,
            WriteIncompatibilities: Array.Empty<string>(),
            WriteUnsupportedFeatures: Array.Empty<string>(),
            NativeWriteReadiness: NativeWriteReadiness.CommitReady
        );
        var runtimeStatus = CreateHostRuntimeStatusRaw(
            writeBackend: "Native",
            commitModel: NativeWriteCommitModel.CanonicalApfsCheckpoint,
            nativeWriteReadiness: NativeWriteReadiness.CommitReady,
            recoveryActive: false,
            recoveryReason: null,
            lastCommitXid: 123,
            nativeWriteSafetyState: NativeWriteSafetyState.PilotReadWrite,
            lastRecoveryAction: null,
            dirtyTransactionCount: 0,
            nativeWriteValidationState: NativeWriteValidationState.CanonicalImageValidated,
            shutdownDrainActive: false,
            inFlightMutationCallbacks: 0,
            hostProcessId: 4321,
            validationEvidence: new NativeWriteValidationEvidence(
                CrashFaultPasses: 10,
                HardwarePilotPasses: 10,
                MacOsValidationPasses: 10,
                PowerLossPassVerified: true,
                LastValidatedUtc: DateTime.UtcNow.AddDays(-1))
        );

        var merged = InvokeMergeValidationEvidenceFromRuntimeStatus(
            backend,
            volume,
            MountAccessMode.ReadWrite,
            runtimeStatus,
            baselineEvidence: new NativeWriteValidationEvidence(),
            runtimeSessionId: @"C:\Temp\status_raw.json");

        Assert.Equal(0, merged.CrashFaultPasses);
        Assert.Equal(0, merged.HardwarePilotPasses);
        Assert.Equal(0, merged.MacOsValidationPasses);
        Assert.False(merged.PowerLossPassVerified);
    }

    [Fact]
    public void MergeValidationEvidenceFromRuntimeStatus_AcceptsRuntimeSeedEvidence_ForNonRawMedia()
    {
        var options = new ServiceHostOptions
        {
            NativeWriteEvidenceStorePath = string.Empty,
            NativeWriteAllowRuntimeEvidenceSeedForRawPhysicalDevices = false,
        };
        using var backend = new NativeApfsBackend(options);
        var volume = new VolumeInfo(
            VolumeId: @"C:\fixtures\sample.apfs.img|Main",
            DeviceId: @"C:\fixtures\sample.apfs.img",
            VolumeName: "Main",
            SupportsReadWrite: true,
            IsEncrypted: false,
            SupportsExplorerMount: true,
            NativeVolumePath: @"C:\fixtures\sample.apfs.img\ApfsAccess_Volumes\Main",
            SupportsNativeWrite: true,
            WriteBlockReason: null,
            WriteIncompatibilities: Array.Empty<string>(),
            WriteUnsupportedFeatures: Array.Empty<string>(),
            NativeWriteReadiness: NativeWriteReadiness.CommitReady
        );
        var runtimeStatus = CreateHostRuntimeStatusRaw(
            writeBackend: "Native",
            commitModel: NativeWriteCommitModel.CanonicalApfsCheckpoint,
            nativeWriteReadiness: NativeWriteReadiness.CommitReady,
            recoveryActive: false,
            recoveryReason: null,
            lastCommitXid: 124,
            nativeWriteSafetyState: NativeWriteSafetyState.PilotReadWrite,
            lastRecoveryAction: null,
            dirtyTransactionCount: 0,
            nativeWriteValidationState: NativeWriteValidationState.CanonicalImageValidated,
            shutdownDrainActive: false,
            inFlightMutationCallbacks: 0,
            hostProcessId: 4322,
            validationEvidence: new NativeWriteValidationEvidence(
                CrashFaultPasses: 7,
                HardwarePilotPasses: 8,
                MacOsValidationPasses: 9,
                PowerLossPassVerified: true,
                LastValidatedUtc: DateTime.UtcNow.AddDays(-1))
        );

        var merged = InvokeMergeValidationEvidenceFromRuntimeStatus(
            backend,
            volume,
            MountAccessMode.ReadWrite,
            runtimeStatus,
            baselineEvidence: new NativeWriteValidationEvidence(),
            runtimeSessionId: @"C:\Temp\status_img.json");

        Assert.Equal(7, merged.CrashFaultPasses);
        Assert.Equal(8, merged.HardwarePilotPasses);
        Assert.Equal(9, merged.MacOsValidationPasses);
        Assert.True(merged.PowerLossPassVerified);
    }

    [Fact]
    public void MergeValidationEvidenceFromRuntimeStatus_AcceptsRuntimeSeedEvidence_ForRawPhysicalWhenOptedIn()
    {
        var options = new ServiceHostOptions
        {
            NativeWriteEvidenceStorePath = string.Empty,
            NativeWriteAllowRuntimeEvidenceSeedForRawPhysicalDevices = true,
        };
        using var backend = new NativeApfsBackend(options);
        var volume = new VolumeInfo(
            VolumeId: @"\\.\PhysicalDrive5|Main",
            DeviceId: @"\\.\PhysicalDrive5",
            VolumeName: "Main",
            SupportsReadWrite: true,
            IsEncrypted: false,
            SupportsExplorerMount: true,
            NativeVolumePath: @"\\.\PhysicalDrive5\ApfsAccess_Volumes\Main",
            SupportsNativeWrite: true,
            WriteBlockReason: null,
            WriteIncompatibilities: Array.Empty<string>(),
            WriteUnsupportedFeatures: Array.Empty<string>(),
            NativeWriteReadiness: NativeWriteReadiness.CommitReady
        );
        var runtimeStatus = CreateHostRuntimeStatusRaw(
            writeBackend: "Native",
            commitModel: NativeWriteCommitModel.CanonicalApfsCheckpoint,
            nativeWriteReadiness: NativeWriteReadiness.CommitReady,
            recoveryActive: false,
            recoveryReason: null,
            lastCommitXid: 125,
            nativeWriteSafetyState: NativeWriteSafetyState.PilotReadWrite,
            lastRecoveryAction: null,
            dirtyTransactionCount: 0,
            nativeWriteValidationState: NativeWriteValidationState.CanonicalImageValidated,
            shutdownDrainActive: false,
            inFlightMutationCallbacks: 0,
            hostProcessId: 4323,
            validationEvidence: new NativeWriteValidationEvidence(
                CrashFaultPasses: 4,
                HardwarePilotPasses: 5,
                MacOsValidationPasses: 6,
                PowerLossPassVerified: true,
                LastValidatedUtc: DateTime.UtcNow.AddDays(-1))
        );

        var merged = InvokeMergeValidationEvidenceFromRuntimeStatus(
            backend,
            volume,
            MountAccessMode.ReadWrite,
            runtimeStatus,
            baselineEvidence: new NativeWriteValidationEvidence(),
            runtimeSessionId: @"C:\Temp\status_raw_optin.json");

        Assert.Equal(4, merged.CrashFaultPasses);
        Assert.Equal(5, merged.HardwarePilotPasses);
        Assert.Equal(6, merged.MacOsValidationPasses);
        Assert.True(merged.PowerLossPassVerified);
    }

    [Fact]
    public void MergeValidationEvidenceFromRuntimeStatus_PromotesCounters_WhenRawValidationEvidenceAndCanonicalProofAreActive()
    {
        var options = new ServiceHostOptions
        {
            NativeWriteEvidenceStorePath = string.Empty,
            NativeWriteAllowRuntimeEvidenceSeedForRawPhysicalDevices = true,
            NativeWriteMinCrashFaultPasses = 2,
            NativeWriteMinCrashStageMatrixPasses = 2,
            NativeWriteMinHardwarePilotPasses = 2,
            NativeWriteMinHotUnplugPasses = 2,
        };
        using var backend = new NativeApfsBackend(options);
        var volume = new VolumeInfo(
            VolumeId: @"\\.\PhysicalDrive7|Main",
            DeviceId: @"\\.\PhysicalDrive7",
            VolumeName: "Main",
            SupportsReadWrite: true,
            IsEncrypted: false,
            SupportsExplorerMount: true,
            NativeVolumePath: @"\\.\PhysicalDrive7\ApfsAccess_Volumes\Main",
            SupportsNativeWrite: true,
            WriteBlockReason: null,
            WriteIncompatibilities: Array.Empty<string>(),
            WriteUnsupportedFeatures: Array.Empty<string>(),
            NativeWriteReadiness: NativeWriteReadiness.CommitReady
        );
        var runtimeStatus = CreateHostRuntimeStatusRaw(
            writeBackend: "Native",
            commitModel: NativeWriteCommitModel.CanonicalApfsCheckpoint,
            nativeWriteReadiness: NativeWriteReadiness.CommitReady,
            recoveryActive: false,
            recoveryReason: null,
            lastCommitXid: 211,
            nativeWriteSafetyState: NativeWriteSafetyState.PilotReadWrite,
            lastRecoveryAction: null,
            dirtyTransactionCount: 0,
            nativeWriteValidationState: NativeWriteValidationState.HardwarePilotValidated,
            shutdownDrainActive: false,
            inFlightMutationCallbacks: 0,
            hostProcessId: 6111,
            validationEvidence: new NativeWriteValidationEvidence(
                LastValidatedUtc: DateTime.UtcNow.AddMinutes(-5)),
            fixtureLegacyFallbackActive: false,
            fixtureCompatibilityPathActive: false,
            usesScaffoldCommitBlob: false,
            commitStage: "commit-finalize",
            replayStage: null,
            commitBlobMagic: "APFSRWCANON3",
            canonicalPathActive: true,
            canonicalGateFailure: null);

        var merged = InvokeMergeValidationEvidenceFromRuntimeStatus(
            backend,
            volume,
            MountAccessMode.ReadWrite,
            runtimeStatus,
            baselineEvidence: new NativeWriteValidationEvidence(),
            runtimeSessionId: @"C:\Temp\status_raw_promote.json");

        Assert.Equal(1, merged.CrashFaultPasses);
        Assert.Equal(1, merged.CrashStageMatrixPasses);
        Assert.Equal(1, merged.HardwarePilotPasses);
        Assert.Equal(1, merged.HotUnplugPasses);
        Assert.True(merged.LastValidatedUtc.HasValue);
    }

    [Fact]
    public void MergeValidationEvidenceFromRuntimeStatus_DoesNotPromoteCounters_WhenRawValidationEvidenceIsMissing()
    {
        var options = new ServiceHostOptions
        {
            NativeWriteEvidenceStorePath = string.Empty,
            NativeWriteAllowRuntimeEvidenceSeedForRawPhysicalDevices = true,
            NativeWriteMinCrashFaultPasses = 2,
            NativeWriteMinCrashStageMatrixPasses = 2,
            NativeWriteMinHardwarePilotPasses = 2,
            NativeWriteMinHotUnplugPasses = 2,
        };
        using var backend = new NativeApfsBackend(options);
        var volume = new VolumeInfo(
            VolumeId: @"\\.\PhysicalDrive17|Main",
            DeviceId: @"\\.\PhysicalDrive17",
            VolumeName: "Main",
            SupportsReadWrite: true,
            IsEncrypted: false,
            SupportsExplorerMount: true,
            NativeVolumePath: @"\\.\PhysicalDrive17\ApfsAccess_Volumes\Main",
            SupportsNativeWrite: true,
            WriteBlockReason: null,
            WriteIncompatibilities: Array.Empty<string>(),
            WriteUnsupportedFeatures: Array.Empty<string>(),
            NativeWriteReadiness: NativeWriteReadiness.CommitReady
        );
        var runtimeStatus = CreateHostRuntimeStatusRaw(
            writeBackend: "Native",
            commitModel: NativeWriteCommitModel.CanonicalApfsCheckpoint,
            nativeWriteReadiness: NativeWriteReadiness.CommitReady,
            recoveryActive: false,
            recoveryReason: null,
            lastCommitXid: 217,
            nativeWriteSafetyState: NativeWriteSafetyState.PilotReadWrite,
            lastRecoveryAction: null,
            dirtyTransactionCount: 0,
            nativeWriteValidationState: NativeWriteValidationState.HardwarePilotValidated,
            shutdownDrainActive: false,
            inFlightMutationCallbacks: 0,
            hostProcessId: 6117,
            validationEvidence: null,
            fixtureLegacyFallbackActive: false,
            fixtureCompatibilityPathActive: false,
            usesScaffoldCommitBlob: false,
            commitStage: "commit-finalize",
            replayStage: null,
            commitBlobMagic: "APFSRWCANON3",
            canonicalPathActive: true,
            canonicalGateFailure: null);

        var merged = InvokeMergeValidationEvidenceFromRuntimeStatus(
            backend,
            volume,
            MountAccessMode.ReadWrite,
            runtimeStatus,
            baselineEvidence: new NativeWriteValidationEvidence(),
            runtimeSessionId: @"C:\Temp\status_raw_missing_evidence.json");

        Assert.Equal(0, merged.CrashFaultPasses);
        Assert.Equal(0, merged.CrashStageMatrixPasses);
        Assert.Equal(0, merged.HardwarePilotPasses);
        Assert.Equal(0, merged.HotUnplugPasses);
    }

    [Fact]
    public void MergeValidationEvidenceFromRuntimeStatus_DoesNotPromoteCounters_WhenRawValidationEvidenceProfileDoesNotMatchVolumeProfile()
    {
        var options = new ServiceHostOptions
        {
            NativeWriteEvidenceStorePath = string.Empty,
            NativeWriteAllowRuntimeEvidenceSeedForRawPhysicalDevices = true,
            NativeWriteMinCrashFaultPasses = 2,
            NativeWriteMinCrashStageMatrixPasses = 2,
            NativeWriteMinHardwarePilotPasses = 2,
            NativeWriteMinHotUnplugPasses = 2,
        };
        using var backend = new NativeApfsBackend(options);
        var volume = new VolumeInfo(
            VolumeId: @"\\.\PhysicalDrive27|Main",
            DeviceId: @"\\.\PhysicalDrive27",
            VolumeName: "Main",
            SupportsReadWrite: true,
            IsEncrypted: false,
            SupportsExplorerMount: true,
            NativeVolumePath: @"\\.\PhysicalDrive27\ApfsAccess_Volumes\Main",
            SupportsNativeWrite: true,
            WriteBlockReason: null,
            WriteIncompatibilities: Array.Empty<string>(),
            WriteUnsupportedFeatures: Array.Empty<string>(),
            NativeWriteReadiness: NativeWriteReadiness.CommitReady
        );
        var runtimeStatus = CreateHostRuntimeStatusRaw(
            writeBackend: "Native",
            commitModel: NativeWriteCommitModel.CanonicalApfsCheckpoint,
            nativeWriteReadiness: NativeWriteReadiness.CommitReady,
            recoveryActive: false,
            recoveryReason: null,
            lastCommitXid: 227,
            nativeWriteSafetyState: NativeWriteSafetyState.PilotReadWrite,
            lastRecoveryAction: null,
            dirtyTransactionCount: 0,
            nativeWriteValidationState: NativeWriteValidationState.HardwarePilotValidated,
            shutdownDrainActive: false,
            inFlightMutationCallbacks: 0,
            hostProcessId: 6227,
            validationEvidence: new NativeWriteValidationEvidence(
                LastValidatedUtc: DateTime.UtcNow.AddMinutes(-2),
                LastValidationProfileId: "raw::\\\\.\\physicaldrive99::other"),
            fixtureLegacyFallbackActive: false,
            fixtureCompatibilityPathActive: false,
            usesScaffoldCommitBlob: false,
            commitStage: "commit-finalize",
            replayStage: null,
            commitBlobMagic: "APFSRWCANON3",
            canonicalPathActive: true,
            canonicalGateFailure: null);

        var merged = InvokeMergeValidationEvidenceFromRuntimeStatus(
            backend,
            volume,
            MountAccessMode.ReadWrite,
            runtimeStatus,
            baselineEvidence: new NativeWriteValidationEvidence(),
            runtimeSessionId: @"C:\Temp\status_raw_profile_mismatch.json");

        Assert.Equal(0, merged.CrashFaultPasses);
        Assert.Equal(0, merged.CrashStageMatrixPasses);
        Assert.Equal(0, merged.HardwarePilotPasses);
        Assert.Equal(0, merged.HotUnplugPasses);
    }

    [Fact]
    public void MergeValidationEvidenceFromRuntimeStatus_DoesNotPromoteCounters_WhenNonFixtureCanonicalProofMissing()
    {
        var options = new ServiceHostOptions
        {
            NativeWriteEvidenceStorePath = string.Empty,
            NativeWriteAllowRuntimeEvidenceSeedForRawPhysicalDevices = false,
            NativeWriteMinCrashFaultPasses = 2,
            NativeWriteMinCrashStageMatrixPasses = 2,
            NativeWriteMinHardwarePilotPasses = 2,
            NativeWriteMinHotUnplugPasses = 2,
        };
        using var backend = new NativeApfsBackend(options);
        var volume = new VolumeInfo(
            VolumeId: @"\\.\PhysicalDrive8|Main",
            DeviceId: @"\\.\PhysicalDrive8",
            VolumeName: "Main",
            SupportsReadWrite: true,
            IsEncrypted: false,
            SupportsExplorerMount: true,
            NativeVolumePath: @"\\.\PhysicalDrive8\ApfsAccess_Volumes\Main",
            SupportsNativeWrite: true,
            WriteBlockReason: null,
            WriteIncompatibilities: Array.Empty<string>(),
            WriteUnsupportedFeatures: Array.Empty<string>(),
            NativeWriteReadiness: NativeWriteReadiness.CommitReady
        );
        var runtimeStatus = CreateHostRuntimeStatusRaw(
            writeBackend: "Native",
            commitModel: NativeWriteCommitModel.CanonicalApfsCheckpoint,
            nativeWriteReadiness: NativeWriteReadiness.CommitReady,
            recoveryActive: false,
            recoveryReason: null,
            lastCommitXid: 212,
            nativeWriteSafetyState: NativeWriteSafetyState.PilotReadWrite,
            lastRecoveryAction: null,
            dirtyTransactionCount: 0,
            nativeWriteValidationState: NativeWriteValidationState.HardwarePilotValidated,
            shutdownDrainActive: false,
            inFlightMutationCallbacks: 0,
            hostProcessId: 6112,
            validationEvidence: null,
            fixtureLegacyFallbackActive: false,
            fixtureCompatibilityPathActive: false,
            usesScaffoldCommitBlob: false,
            commitStage: "commit-finalize",
            replayStage: null,
            commitBlobMagic: "APFSRWCANON3",
            canonicalPathActive: null,
            canonicalGateFailure: null);

        var merged = InvokeMergeValidationEvidenceFromRuntimeStatus(
            backend,
            volume,
            MountAccessMode.ReadWrite,
            runtimeStatus,
            baselineEvidence: new NativeWriteValidationEvidence(),
            runtimeSessionId: @"C:\Temp\status_raw_no_promote.json");

        Assert.Equal(0, merged.CrashFaultPasses);
        Assert.Equal(0, merged.CrashStageMatrixPasses);
        Assert.Equal(0, merged.HardwarePilotPasses);
        Assert.Equal(0, merged.HotUnplugPasses);
        Assert.False(merged.LastValidatedUtc.HasValue);
    }

    [Fact]
    public void MergeValidationEvidenceFromRuntimeStatus_DoesNotPromoteCounters_WhenHardwareValidationLacksStageProof()
    {
        var options = new ServiceHostOptions
        {
            NativeWriteEvidenceStorePath = string.Empty,
            NativeWriteAllowRuntimeEvidenceSeedForRawPhysicalDevices = false,
            NativeWriteMinCrashFaultPasses = 2,
            NativeWriteMinCrashStageMatrixPasses = 2,
            NativeWriteMinHardwarePilotPasses = 2,
            NativeWriteMinHotUnplugPasses = 2,
        };
        using var backend = new NativeApfsBackend(options);
        var volume = new VolumeInfo(
            VolumeId: @"\\.\PhysicalDrive18|Main",
            DeviceId: @"\\.\PhysicalDrive18",
            VolumeName: "Main",
            SupportsReadWrite: true,
            IsEncrypted: false,
            SupportsExplorerMount: true,
            NativeVolumePath: @"\\.\PhysicalDrive18\ApfsAccess_Volumes\Main",
            SupportsNativeWrite: true,
            WriteBlockReason: null,
            WriteIncompatibilities: Array.Empty<string>(),
            WriteUnsupportedFeatures: Array.Empty<string>(),
            NativeWriteReadiness: NativeWriteReadiness.CommitReady
        );
        var runtimeStatus = CreateHostRuntimeStatusRaw(
            writeBackend: "Native",
            commitModel: NativeWriteCommitModel.CanonicalApfsCheckpoint,
            nativeWriteReadiness: NativeWriteReadiness.CommitReady,
            recoveryActive: false,
            recoveryReason: null,
            lastCommitXid: null,
            nativeWriteSafetyState: NativeWriteSafetyState.PilotReadWrite,
            lastRecoveryAction: null,
            dirtyTransactionCount: 0,
            nativeWriteValidationState: NativeWriteValidationState.HardwarePilotValidated,
            shutdownDrainActive: false,
            inFlightMutationCallbacks: 0,
            hostProcessId: 7001,
            validationEvidence: null,
            fixtureLegacyFallbackActive: false,
            fixtureCompatibilityPathActive: false,
            usesScaffoldCommitBlob: false,
            commitStage: null,
            replayStage: null,
            commitBlobMagic: "APFSRWCANON3",
            canonicalPathActive: true,
            canonicalGateFailure: null);

        var merged = InvokeMergeValidationEvidenceFromRuntimeStatus(
            backend,
            volume,
            MountAccessMode.ReadWrite,
            runtimeStatus,
            baselineEvidence: new NativeWriteValidationEvidence(),
            runtimeSessionId: @"C:\Temp\status_raw_stageproof_missing.json");

        Assert.Equal(0, merged.CrashFaultPasses);
        Assert.Equal(0, merged.CrashStageMatrixPasses);
        Assert.Equal(0, merged.HardwarePilotPasses);
        Assert.Equal(0, merged.HotUnplugPasses);
        Assert.False(merged.LastValidatedUtc.HasValue);
    }

    [Fact]
    public void ShouldFailClosedForRuntimeStatus_UsesRecoveryReasonAndSafetyStateSignals()
    {
        var reasonOnlyStatus = CreateHostRuntimeStatusRaw(
            writeBackend: "Native",
            commitModel: NativeWriteCommitModel.ScaffoldCheckpoint,
            nativeWriteReadiness: NativeWriteReadiness.CommitReady,
            recoveryActive: false,
            recoveryReason: "ReplayCommitBlobInvalid",
            lastCommitXid: 77,
            nativeWriteSafetyState: NativeWriteSafetyState.PilotReadWrite,
            lastRecoveryAction: null,
            dirtyTransactionCount: 0,
            nativeWriteValidationState: NativeWriteValidationState.Scaffold,
            shutdownDrainActive: false,
            inFlightMutationCallbacks: 0);

        Assert.True(InvokeShouldFailClosedForRuntimeStatus(reasonOnlyStatus, "FailClosed"));
        Assert.False(InvokeShouldFailClosedForRuntimeStatus(reasonOnlyStatus, "BestEffort"));

        var safetyBlockedStatus = CreateHostRuntimeStatusRaw(
            writeBackend: "Native",
            commitModel: NativeWriteCommitModel.ScaffoldCheckpoint,
            nativeWriteReadiness: NativeWriteReadiness.CommitReady,
            recoveryActive: false,
            recoveryReason: null,
            lastCommitXid: 78,
            nativeWriteSafetyState: NativeWriteSafetyState.RecoveryBlocked,
            lastRecoveryAction: null,
            dirtyTransactionCount: 0,
            nativeWriteValidationState: NativeWriteValidationState.Scaffold,
            shutdownDrainActive: false,
            inFlightMutationCallbacks: 0);
        Assert.True(InvokeShouldFailClosedForRuntimeStatus(safetyBlockedStatus, "FailClosed"));

        var healthyStatus = CreateHostRuntimeStatusRaw(
            writeBackend: "Native",
            commitModel: NativeWriteCommitModel.ScaffoldCheckpoint,
            nativeWriteReadiness: NativeWriteReadiness.CommitReady,
            recoveryActive: false,
            recoveryReason: null,
            lastCommitXid: 79,
            nativeWriteSafetyState: NativeWriteSafetyState.PilotReadWrite,
            lastRecoveryAction: null,
            dirtyTransactionCount: 0,
            nativeWriteValidationState: NativeWriteValidationState.Scaffold,
            shutdownDrainActive: false,
            inFlightMutationCallbacks: 0);
        Assert.False(InvokeShouldFailClosedForRuntimeStatus(healthyStatus, "FailClosed"));
    }

    [Fact]
    public void GetFailClosedReasonForRuntimeStatus_TriggersOnDirtyTransactionLimitBreach()
    {
        var highDirtyNativeStatus = CreateHostRuntimeStatusRaw(
            writeBackend: "Native",
            commitModel: NativeWriteCommitModel.ScaffoldCheckpoint,
            nativeWriteReadiness: NativeWriteReadiness.CommitReady,
            recoveryActive: false,
            recoveryReason: null,
            lastCommitXid: 90,
            nativeWriteSafetyState: NativeWriteSafetyState.PilotReadWrite,
            lastRecoveryAction: null,
            dirtyTransactionCount: 129,
            nativeWriteValidationState: NativeWriteValidationState.Scaffold,
            shutdownDrainActive: false,
            inFlightMutationCallbacks: 0);

        Assert.Equal(
            "DirtyTransactionLimitExceeded",
            InvokeGetFailClosedReasonForRuntimeStatus(highDirtyNativeStatus, "FailClosed", 128));
        Assert.Null(InvokeGetFailClosedReasonForRuntimeStatus(highDirtyNativeStatus, "FailClosed", 512));
        Assert.Null(InvokeGetFailClosedReasonForRuntimeStatus(highDirtyNativeStatus, "BestEffort", 128));

        var highDirtyOverlayStatus = CreateHostRuntimeStatusRaw(
            writeBackend: "Overlay",
            commitModel: NativeWriteCommitModel.ScaffoldCheckpoint,
            nativeWriteReadiness: NativeWriteReadiness.MutationReady,
            recoveryActive: false,
            recoveryReason: null,
            lastCommitXid: 91,
            nativeWriteSafetyState: NativeWriteSafetyState.PilotReadWrite,
            lastRecoveryAction: null,
            dirtyTransactionCount: 1000,
            nativeWriteValidationState: NativeWriteValidationState.Scaffold,
            shutdownDrainActive: false,
            inFlightMutationCallbacks: 0);
        Assert.Null(InvokeGetFailClosedReasonForRuntimeStatus(highDirtyOverlayStatus, "FailClosed", 128));
    }

    [Fact]
    public void GetFailClosedReasonForRuntimeStatus_TriggersOnFixtureFallbackSignal()
    {
        var fixtureFallbackStatus = CreateHostRuntimeStatusRaw(
            writeBackend: "Native",
            commitModel: NativeWriteCommitModel.CanonicalApfsCheckpoint,
            nativeWriteReadiness: NativeWriteReadiness.CommitReady,
            recoveryActive: false,
            recoveryReason: null,
            lastCommitXid: 99,
            nativeWriteSafetyState: NativeWriteSafetyState.PilotReadWrite,
            lastRecoveryAction: null,
            dirtyTransactionCount: 0,
            nativeWriteValidationState: NativeWriteValidationState.CanonicalImageValidated,
            shutdownDrainActive: false,
            inFlightMutationCallbacks: 0,
            fixtureLegacyFallbackActive: true);

        Assert.Equal(
            "FixtureLegacyFallbackActive",
            InvokeGetFailClosedReasonForRuntimeStatus(fixtureFallbackStatus, "FailClosed", 128));
        Assert.Null(InvokeGetFailClosedReasonForRuntimeStatus(fixtureFallbackStatus, "BestEffort", 128));
    }

    [Fact]
    public void GetFailClosedReasonForRuntimeStatus_RejectsScaffoldReplayAndCanonicalProofGaps_OnNonFixtureMedia()
    {
        var scaffoldReplayStatus = CreateHostRuntimeStatusRaw(
            writeBackend: "Native",
            commitModel: NativeWriteCommitModel.CanonicalApfsCheckpoint,
            nativeWriteReadiness: NativeWriteReadiness.CommitReady,
            recoveryActive: false,
            recoveryReason: null,
            lastCommitXid: 1337,
            nativeWriteSafetyState: NativeWriteSafetyState.PilotReadWrite,
            lastRecoveryAction: null,
            dirtyTransactionCount: 0,
            nativeWriteValidationState: NativeWriteValidationState.CanonicalImageValidated,
            commitBlobMagic: "APFSRWSCAFF3");

        Assert.Equal(
            "ScaffoldCommitBlobActive",
            InvokeGetFailClosedReasonForRuntimeStatus(
                scaffoldReplayStatus,
                "FailClosed",
                128,
                isFixtureImage: false,
                disallowScaffoldCommitOnNonFixture: true,
                rejectScaffoldReplayBlobOnNonFixture: true,
                requireCanonicalReplayCandidateOnNonFixture: true));

        var canonicalProofGapStatus = CreateHostRuntimeStatusRaw(
            writeBackend: "Native",
            commitModel: NativeWriteCommitModel.CanonicalApfsCheckpoint,
            nativeWriteReadiness: NativeWriteReadiness.CommitReady,
            recoveryActive: false,
            recoveryReason: null,
            lastCommitXid: 1338,
            nativeWriteSafetyState: NativeWriteSafetyState.PilotReadWrite,
            lastRecoveryAction: null,
            dirtyTransactionCount: 0,
            nativeWriteValidationState: NativeWriteValidationState.CanonicalImageValidated,
            commitBlobMagic: "APFSRWCANON3",
            canonicalPathActive: false,
            canonicalGateFailure: "CanonicalStateNotLoaded");

        Assert.Equal(
            "CanonicalStateNotLoaded",
            InvokeGetFailClosedReasonForRuntimeStatus(
                canonicalProofGapStatus,
                "FailClosed",
                128,
                isFixtureImage: false,
                disallowScaffoldCommitOnNonFixture: true,
                rejectScaffoldReplayBlobOnNonFixture: true,
                requireCanonicalReplayCandidateOnNonFixture: true));

        var canonicalProofMissingStatus = CreateHostRuntimeStatusRaw(
            writeBackend: "Native",
            commitModel: NativeWriteCommitModel.CanonicalApfsCheckpoint,
            nativeWriteReadiness: NativeWriteReadiness.CommitReady,
            recoveryActive: false,
            recoveryReason: null,
            lastCommitXid: 1339,
            nativeWriteSafetyState: NativeWriteSafetyState.PilotReadWrite,
            lastRecoveryAction: null,
            dirtyTransactionCount: 0,
            nativeWriteValidationState: NativeWriteValidationState.CanonicalImageValidated,
            commitBlobMagic: "APFSRWCANON3",
            canonicalPathActive: null,
            canonicalGateFailure: null);

        Assert.Equal(
            "CanonicalPathNotActive",
            InvokeGetFailClosedReasonForRuntimeStatus(
                canonicalProofMissingStatus,
                "FailClosed",
                128,
                isFixtureImage: false,
                disallowScaffoldCommitOnNonFixture: true,
                rejectScaffoldReplayBlobOnNonFixture: true,
                requireCanonicalReplayCandidateOnNonFixture: true));

        var replayPendingWindowStatus = CreateHostRuntimeStatusRaw(
            writeBackend: "Native",
            commitModel: NativeWriteCommitModel.CanonicalApfsCheckpoint,
            nativeWriteReadiness: NativeWriteReadiness.RecoveryMode,
            recoveryActive: true,
            recoveryReason: "ReplayCheckpointPendingWindow",
            lastCommitXid: 1340,
            nativeWriteSafetyState: NativeWriteSafetyState.RecoveryBlocked,
            lastRecoveryAction: "ReplaySkippedFailClosed",
            dirtyTransactionCount: 0,
            nativeWriteValidationState: NativeWriteValidationState.CanonicalImageValidated,
            commitBlobMagic: "APFSRWCANON3",
            canonicalPathActive: null,
            canonicalGateFailure: null);

        Assert.Equal(
            "ReplayCheckpointPendingWindow",
            InvokeGetFailClosedReasonForRuntimeStatus(
                replayPendingWindowStatus,
                "FailClosed",
                128,
                isFixtureImage: false,
                disallowScaffoldCommitOnNonFixture: true,
                rejectScaffoldReplayBlobOnNonFixture: true,
                requireCanonicalReplayCandidateOnNonFixture: true));

        var replayNotPendingWindowStatus = CreateHostRuntimeStatusRaw(
            writeBackend: "Native",
            commitModel: NativeWriteCommitModel.CanonicalApfsCheckpoint,
            nativeWriteReadiness: NativeWriteReadiness.RecoveryMode,
            recoveryActive: true,
            recoveryReason: "ReplayCheckpointNotPendingWindow",
            lastCommitXid: 1341,
            nativeWriteSafetyState: NativeWriteSafetyState.RecoveryBlocked,
            lastRecoveryAction: "ReplaySkippedFailClosed",
            dirtyTransactionCount: 0,
            nativeWriteValidationState: NativeWriteValidationState.CanonicalImageValidated,
            commitBlobMagic: "APFSRWCANON3",
            canonicalPathActive: null,
            canonicalGateFailure: null);

        Assert.Equal(
            "ReplayCheckpointNotPendingWindow",
            InvokeGetFailClosedReasonForRuntimeStatus(
                replayNotPendingWindowStatus,
                "FailClosed",
                128,
                isFixtureImage: false,
                disallowScaffoldCommitOnNonFixture: true,
                rejectScaffoldReplayBlobOnNonFixture: true,
                requireCanonicalReplayCandidateOnNonFixture: true));

        var replayPendingWindowTelemetryStatus = CreateHostRuntimeStatusRaw(
            writeBackend: "Native",
            commitModel: NativeWriteCommitModel.CanonicalApfsCheckpoint,
            nativeWriteReadiness: NativeWriteReadiness.RecoveryMode,
            recoveryActive: true,
            recoveryReason: null,
            lastCommitXid: 1342,
            nativeWriteSafetyState: NativeWriteSafetyState.RecoveryBlocked,
            lastRecoveryAction: "ReplaySkippedFailClosed",
            dirtyTransactionCount: 0,
            nativeWriteValidationState: NativeWriteValidationState.CanonicalImageValidated,
            commitBlobMagic: "APFSRWCANON3",
            canonicalPathActive: null,
            canonicalGateFailure: null);
        SetHostRuntimeStatusReplayTelemetry(
            replayPendingWindowTelemetryStatus,
            replayCheckpointCandidatePresent: true,
            replayCheckpointPendingWindow: true);

        Assert.Equal(
            "ReplayCheckpointPendingWindow",
            InvokeGetFailClosedReasonForRuntimeStatus(
                replayPendingWindowTelemetryStatus,
                "FailClosed",
                128,
                isFixtureImage: false,
                disallowScaffoldCommitOnNonFixture: true,
                rejectScaffoldReplayBlobOnNonFixture: true,
                requireCanonicalReplayCandidateOnNonFixture: true));

        var replayNotPendingWindowTelemetryStatus = CreateHostRuntimeStatusRaw(
            writeBackend: "Native",
            commitModel: NativeWriteCommitModel.CanonicalApfsCheckpoint,
            nativeWriteReadiness: NativeWriteReadiness.RecoveryMode,
            recoveryActive: true,
            recoveryReason: null,
            lastCommitXid: 1343,
            nativeWriteSafetyState: NativeWriteSafetyState.RecoveryBlocked,
            lastRecoveryAction: "ReplaySkippedFailClosed",
            dirtyTransactionCount: 0,
            nativeWriteValidationState: NativeWriteValidationState.CanonicalImageValidated,
            commitBlobMagic: "APFSRWCANON3",
            canonicalPathActive: null,
            canonicalGateFailure: null);
        SetHostRuntimeStatusReplayTelemetry(
            replayNotPendingWindowTelemetryStatus,
            replayCheckpointCandidatePresent: true,
            replayCheckpointPendingWindow: false);

        Assert.Equal(
            "ReplayCheckpointNotPendingWindow",
            InvokeGetFailClosedReasonForRuntimeStatus(
                replayNotPendingWindowTelemetryStatus,
                "FailClosed",
                128,
                isFixtureImage: false,
                disallowScaffoldCommitOnNonFixture: true,
                rejectScaffoldReplayBlobOnNonFixture: true,
                requireCanonicalReplayCandidateOnNonFixture: true));
    }

    [Fact]
    public void GetFailClosedReasonForRuntimeStatus_IgnoresStaleReplayTelemetry_WhenCanonicalNativeStatusIsHealthy()
    {
        var status = CreateHostRuntimeStatusRaw(
            writeBackend: "Native",
            commitModel: NativeWriteCommitModel.CanonicalApfsCheckpoint,
            nativeWriteReadiness: NativeWriteReadiness.CommitReady,
            recoveryActive: false,
            recoveryReason: null,
            lastCommitXid: 1344,
            nativeWriteSafetyState: NativeWriteSafetyState.PilotReadWrite,
            lastRecoveryAction: null,
            dirtyTransactionCount: 0,
            nativeWriteValidationState: NativeWriteValidationState.CanonicalImageValidated,
            commitBlobMagic: "APFSRWCANON3",
            canonicalPathActive: true,
            canonicalGateFailure: null);
        SetHostRuntimeStatusReplayTelemetry(
            status,
            replayCheckpointCandidatePresent: true,
            replayCheckpointPendingWindow: false);

        Assert.Null(
            InvokeGetFailClosedReasonForRuntimeStatus(
                status,
                "FailClosed",
                128,
                isFixtureImage: false,
                disallowScaffoldCommitOnNonFixture: true,
                rejectScaffoldReplayBlobOnNonFixture: true,
                requireCanonicalReplayCandidateOnNonFixture: true));
    }

    [Fact]
    public void GetFailClosedReasonForRuntimeStatus_PrioritizesNonFixtureCanonicalSafetySignalsOverGenericRecoveryReason()
    {
        var fixtureCompatibilityStatus = CreateHostRuntimeStatusRaw(
            writeBackend: "Native",
            commitModel: NativeWriteCommitModel.CanonicalApfsCheckpoint,
            nativeWriteReadiness: NativeWriteReadiness.CommitReady,
            recoveryActive: true,
            recoveryReason: "RecoveryRequired",
            lastCommitXid: 1401,
            nativeWriteSafetyState: NativeWriteSafetyState.RecoveryBlocked,
            lastRecoveryAction: null,
            dirtyTransactionCount: 0,
            nativeWriteValidationState: NativeWriteValidationState.CanonicalImageValidated,
            fixtureCompatibilityPathActive: true);

        Assert.Equal(
            "FixtureCompatibilityPathActive",
            InvokeGetFailClosedReasonForRuntimeStatus(
                fixtureCompatibilityStatus,
                "FailClosed",
                128,
                isFixtureImage: false,
                disallowScaffoldCommitOnNonFixture: true,
                rejectScaffoldReplayBlobOnNonFixture: true,
                requireCanonicalReplayCandidateOnNonFixture: true));

        var scaffoldBlobStatus = CreateHostRuntimeStatusRaw(
            writeBackend: "Native",
            commitModel: NativeWriteCommitModel.CanonicalApfsCheckpoint,
            nativeWriteReadiness: NativeWriteReadiness.CommitReady,
            recoveryActive: true,
            recoveryReason: "RecoveryRequired",
            lastCommitXid: 1402,
            nativeWriteSafetyState: NativeWriteSafetyState.RecoveryBlocked,
            lastRecoveryAction: null,
            dirtyTransactionCount: 0,
            nativeWriteValidationState: NativeWriteValidationState.CanonicalImageValidated,
            usesScaffoldCommitBlob: true);

        Assert.Equal(
            "ScaffoldCommitBlobActive",
            InvokeGetFailClosedReasonForRuntimeStatus(
                scaffoldBlobStatus,
                "FailClosed",
                128,
                isFixtureImage: false,
                disallowScaffoldCommitOnNonFixture: true,
                rejectScaffoldReplayBlobOnNonFixture: true,
                requireCanonicalReplayCandidateOnNonFixture: true));

        var scaffoldAndFixtureCompatibilityStatus = CreateHostRuntimeStatusRaw(
            writeBackend: "Native",
            commitModel: NativeWriteCommitModel.CanonicalApfsCheckpoint,
            nativeWriteReadiness: NativeWriteReadiness.CommitReady,
            recoveryActive: true,
            recoveryReason: "RecoveryRequired",
            lastCommitXid: 1403,
            nativeWriteSafetyState: NativeWriteSafetyState.RecoveryBlocked,
            lastRecoveryAction: null,
            dirtyTransactionCount: 0,
            nativeWriteValidationState: NativeWriteValidationState.CanonicalImageValidated,
            fixtureCompatibilityPathActive: true,
            usesScaffoldCommitBlob: true);

        Assert.Equal(
            "ScaffoldCommitBlobActive",
            InvokeGetFailClosedReasonForRuntimeStatus(
                scaffoldAndFixtureCompatibilityStatus,
                "FailClosed",
                128,
                isFixtureImage: false,
                disallowScaffoldCommitOnNonFixture: true,
                rejectScaffoldReplayBlobOnNonFixture: true,
                requireCanonicalReplayCandidateOnNonFixture: true));
    }

    [Fact]
    public void GetFailClosedReasonForRuntimeStatus_UsesCanonicalGateFailure_OnNonFixtureEvenWhenCanonicalReplayToggleDisabled()
    {
        var canonicalGateFailureStatus = CreateHostRuntimeStatusRaw(
            writeBackend: "Native",
            commitModel: NativeWriteCommitModel.CanonicalApfsCheckpoint,
            nativeWriteReadiness: NativeWriteReadiness.CommitReady,
            recoveryActive: true,
            recoveryReason: "RecoveryRequired",
            lastCommitXid: 1450,
            nativeWriteSafetyState: NativeWriteSafetyState.RecoveryBlocked,
            lastRecoveryAction: null,
            dirtyTransactionCount: 0,
            nativeWriteValidationState: NativeWriteValidationState.CanonicalImageValidated,
            fixtureCompatibilityPathActive: false,
            usesScaffoldCommitBlob: false,
            canonicalPathActive: false,
            canonicalGateFailure: "CommitPathNotReady");

        Assert.Equal(
            "CommitPathNotReady",
            InvokeGetFailClosedReasonForRuntimeStatus(
                canonicalGateFailureStatus,
                "FailClosed",
                128,
                isFixtureImage: false,
                disallowScaffoldCommitOnNonFixture: false,
                rejectScaffoldReplayBlobOnNonFixture: false,
                requireCanonicalReplayCandidateOnNonFixture: false));
    }

    [Fact]
    public void GetFailClosedReasonForRuntimeStatus_PreservesIntegrityAllocationMapReason_OnNonFixture()
    {
        var status = CreateHostRuntimeStatusRaw(
            writeBackend: "Native",
            commitModel: NativeWriteCommitModel.CanonicalApfsCheckpoint,
            nativeWriteReadiness: NativeWriteReadiness.RecoveryMode,
            recoveryActive: true,
            recoveryReason: "IntegrityMissingAllocationMap",
            lastCommitXid: 1452,
            nativeWriteSafetyState: NativeWriteSafetyState.RecoveryBlocked,
            lastRecoveryAction: "BootstrapIntegrityMissingAllocationMap",
            dirtyTransactionCount: 0,
            nativeWriteValidationState: NativeWriteValidationState.CanonicalImageValidated,
            fixtureCompatibilityPathActive: false,
            usesScaffoldCommitBlob: false,
            canonicalPathActive: null,
            canonicalGateFailure: null);

        Assert.Equal(
            "IntegrityMissingAllocationMap",
            InvokeGetFailClosedReasonForRuntimeStatus(
                status,
                "FailClosed",
                128,
                isFixtureImage: false,
                disallowScaffoldCommitOnNonFixture: true,
                rejectScaffoldReplayBlobOnNonFixture: true,
                requireCanonicalReplayCandidateOnNonFixture: true));
    }

    [Fact]
    public void GetFailClosedReasonForRuntimeStatus_RequiresCanonicalPathProof_OnNonFixtureEvenWhenCanonicalReplayToggleDisabled()
    {
        var canonicalProofMissingStatus = CreateHostRuntimeStatusRaw(
            writeBackend: "Native",
            commitModel: NativeWriteCommitModel.CanonicalApfsCheckpoint,
            nativeWriteReadiness: NativeWriteReadiness.CommitReady,
            recoveryActive: false,
            recoveryReason: null,
            lastCommitXid: 1451,
            nativeWriteSafetyState: NativeWriteSafetyState.PilotReadWrite,
            lastRecoveryAction: null,
            dirtyTransactionCount: 0,
            nativeWriteValidationState: NativeWriteValidationState.CanonicalImageValidated,
            fixtureCompatibilityPathActive: false,
            usesScaffoldCommitBlob: false,
            canonicalPathActive: null,
            canonicalGateFailure: null);

        Assert.Equal(
            "CanonicalPathNotActive",
            InvokeGetFailClosedReasonForRuntimeStatus(
                canonicalProofMissingStatus,
                "FailClosed",
                128,
                isFixtureImage: false,
                disallowScaffoldCommitOnNonFixture: false,
                rejectScaffoldReplayBlobOnNonFixture: false,
                requireCanonicalReplayCandidateOnNonFixture: false));
    }

    [Fact]
    public void GetFailClosedReasonForRuntimeStatus_RejectsScaffoldSignals_OnNonFixtureEvenWhenControlsRelaxed()
    {
        var scaffoldFlagStatus = CreateHostRuntimeStatusRaw(
            writeBackend: "Native",
            commitModel: NativeWriteCommitModel.CanonicalApfsCheckpoint,
            nativeWriteReadiness: NativeWriteReadiness.CommitReady,
            recoveryActive: false,
            recoveryReason: null,
            lastCommitXid: 1455,
            nativeWriteSafetyState: NativeWriteSafetyState.PilotReadWrite,
            lastRecoveryAction: null,
            dirtyTransactionCount: 0,
            nativeWriteValidationState: NativeWriteValidationState.CanonicalImageValidated,
            fixtureCompatibilityPathActive: false,
            usesScaffoldCommitBlob: true,
            canonicalPathActive: true,
            canonicalGateFailure: null);

        Assert.Equal(
            "ScaffoldCommitBlobActive",
            InvokeGetFailClosedReasonForRuntimeStatus(
                scaffoldFlagStatus,
                "BestEffort",
                128,
                isFixtureImage: false,
                disallowScaffoldCommitOnNonFixture: false,
                rejectScaffoldReplayBlobOnNonFixture: false,
                requireCanonicalReplayCandidateOnNonFixture: false));

        var scaffoldMagicStatus = CreateHostRuntimeStatusRaw(
            writeBackend: "Native",
            commitModel: NativeWriteCommitModel.CanonicalApfsCheckpoint,
            nativeWriteReadiness: NativeWriteReadiness.CommitReady,
            recoveryActive: false,
            recoveryReason: null,
            lastCommitXid: 1456,
            nativeWriteSafetyState: NativeWriteSafetyState.PilotReadWrite,
            lastRecoveryAction: null,
            dirtyTransactionCount: 0,
            nativeWriteValidationState: NativeWriteValidationState.CanonicalImageValidated,
            fixtureCompatibilityPathActive: false,
            usesScaffoldCommitBlob: false,
            commitBlobMagic: "APFSRWSCAFF3",
            canonicalPathActive: true,
            canonicalGateFailure: null);

        Assert.Equal(
            "ScaffoldCommitBlobActive",
            InvokeGetFailClosedReasonForRuntimeStatus(
                scaffoldMagicStatus,
                "BestEffort",
                128,
                isFixtureImage: false,
                disallowScaffoldCommitOnNonFixture: false,
                rejectScaffoldReplayBlobOnNonFixture: false,
                requireCanonicalReplayCandidateOnNonFixture: false));
    }

    [Fact]
    public void ShouldBlockObservedValidationPromotionForRuntimeStatus_RequiresCanonicalPathProof_OnNonFixtureEvenWhenControlsRelaxed()
    {
        var status = CreateHostRuntimeStatusRaw(
            writeBackend: "Native",
            commitModel: NativeWriteCommitModel.CanonicalApfsCheckpoint,
            nativeWriteReadiness: NativeWriteReadiness.CommitReady,
            recoveryActive: false,
            recoveryReason: null,
            lastCommitXid: 1452,
            nativeWriteSafetyState: NativeWriteSafetyState.PilotReadWrite,
            lastRecoveryAction: null,
            dirtyTransactionCount: 0,
            nativeWriteValidationState: NativeWriteValidationState.CanonicalImageValidated,
            fixtureLegacyFallbackActive: false,
            fixtureCompatibilityPathActive: false,
            usesScaffoldCommitBlob: false,
            canonicalPathActive: null,
            canonicalGateFailure: null);

        Assert.True(
            InvokeShouldBlockObservedValidationPromotionForRuntimeStatus(
                deviceId: @"\\.\PhysicalDrive9",
                requestedAccessMode: MountAccessMode.ReadWrite,
                runtimeWriteBackend: "Native",
                runtimeStatus: status,
                disallowScaffoldCommitOnNonFixture: false,
                rejectScaffoldReplayBlobOnNonFixture: false,
                requireCanonicalReplayCandidateOnNonFixture: false));
    }

    [Fact]
    public void ShouldBlockObservedValidationPromotionForRuntimeStatus_AlwaysBlocksScaffoldSignals_OnNonFixtureEvenWhenControlsRelaxed()
    {
        var scaffoldFlagStatus = CreateHostRuntimeStatusRaw(
            writeBackend: "Native",
            commitModel: NativeWriteCommitModel.CanonicalApfsCheckpoint,
            nativeWriteReadiness: NativeWriteReadiness.CommitReady,
            recoveryActive: false,
            recoveryReason: null,
            lastCommitXid: 1457,
            nativeWriteSafetyState: NativeWriteSafetyState.PilotReadWrite,
            lastRecoveryAction: null,
            dirtyTransactionCount: 0,
            nativeWriteValidationState: NativeWriteValidationState.CanonicalImageValidated,
            fixtureLegacyFallbackActive: false,
            fixtureCompatibilityPathActive: false,
            usesScaffoldCommitBlob: true,
            canonicalPathActive: true,
            canonicalGateFailure: null);

        Assert.True(
            InvokeShouldBlockObservedValidationPromotionForRuntimeStatus(
                deviceId: @"\\.\PhysicalDrive9",
                requestedAccessMode: MountAccessMode.ReadWrite,
                runtimeWriteBackend: "Native",
                runtimeStatus: scaffoldFlagStatus,
                disallowScaffoldCommitOnNonFixture: false,
                rejectScaffoldReplayBlobOnNonFixture: false,
                requireCanonicalReplayCandidateOnNonFixture: false));

        var scaffoldMagicStatus = CreateHostRuntimeStatusRaw(
            writeBackend: "Native",
            commitModel: NativeWriteCommitModel.CanonicalApfsCheckpoint,
            nativeWriteReadiness: NativeWriteReadiness.CommitReady,
            recoveryActive: false,
            recoveryReason: null,
            lastCommitXid: 1458,
            nativeWriteSafetyState: NativeWriteSafetyState.PilotReadWrite,
            lastRecoveryAction: null,
            dirtyTransactionCount: 0,
            nativeWriteValidationState: NativeWriteValidationState.CanonicalImageValidated,
            fixtureLegacyFallbackActive: false,
            fixtureCompatibilityPathActive: false,
            usesScaffoldCommitBlob: false,
            commitBlobMagic: "APFSRWSCAFF3",
            canonicalPathActive: true,
            canonicalGateFailure: null);

        Assert.True(
            InvokeShouldBlockObservedValidationPromotionForRuntimeStatus(
                deviceId: @"\\.\PhysicalDrive9",
                requestedAccessMode: MountAccessMode.ReadWrite,
                runtimeWriteBackend: "Native",
                runtimeStatus: scaffoldMagicStatus,
                disallowScaffoldCommitOnNonFixture: false,
                rejectScaffoldReplayBlobOnNonFixture: false,
                requireCanonicalReplayCandidateOnNonFixture: false));
    }

    [Fact]
    public void ShouldBlockObservedValidationPromotionForRuntimeStatus_AlwaysBlocksReplayCandidateMissing_OnNonFixture()
    {
        var status = CreateHostRuntimeStatusRaw(
            writeBackend: "Native",
            commitModel: NativeWriteCommitModel.CanonicalApfsCheckpoint,
            nativeWriteReadiness: NativeWriteReadiness.RecoveryMode,
            recoveryActive: true,
            recoveryReason: "ReplayCanonicalCandidateMissing",
            lastCommitXid: 1453,
            nativeWriteSafetyState: NativeWriteSafetyState.RecoveryBlocked,
            lastRecoveryAction: "ReplaySkippedFailClosed",
            dirtyTransactionCount: 0,
            nativeWriteValidationState: NativeWriteValidationState.CanonicalImageValidated,
            fixtureLegacyFallbackActive: false,
            fixtureCompatibilityPathActive: false,
            usesScaffoldCommitBlob: false,
            canonicalPathActive: true,
            canonicalGateFailure: null);

        Assert.True(
            InvokeShouldBlockObservedValidationPromotionForRuntimeStatus(
                deviceId: @"\\.\PhysicalDrive9",
                requestedAccessMode: MountAccessMode.ReadWrite,
                runtimeWriteBackend: "Native",
                runtimeStatus: status,
                disallowScaffoldCommitOnNonFixture: true,
                rejectScaffoldReplayBlobOnNonFixture: true,
                requireCanonicalReplayCandidateOnNonFixture: false));

        Assert.True(
            InvokeShouldBlockObservedValidationPromotionForRuntimeStatus(
                deviceId: @"\\.\PhysicalDrive9",
                requestedAccessMode: MountAccessMode.ReadWrite,
                runtimeWriteBackend: "Native",
                runtimeStatus: status,
                disallowScaffoldCommitOnNonFixture: true,
                rejectScaffoldReplayBlobOnNonFixture: true,
                requireCanonicalReplayCandidateOnNonFixture: true));
    }

    [Fact]
    public void GetFailClosedReasonForRuntimeStatus_AlwaysFailClosesReplayCandidateMissing_OnNonFixtureBestEffort()
    {
        var status = CreateHostRuntimeStatusRaw(
            writeBackend: "Native",
            commitModel: NativeWriteCommitModel.CanonicalApfsCheckpoint,
            nativeWriteReadiness: NativeWriteReadiness.RecoveryMode,
            recoveryActive: true,
            recoveryReason: "ReplayCanonicalCandidateMissing",
            lastCommitXid: 1454,
            nativeWriteSafetyState: NativeWriteSafetyState.RecoveryBlocked,
            lastRecoveryAction: "ReplaySkippedFailClosed",
            dirtyTransactionCount: 0,
            nativeWriteValidationState: NativeWriteValidationState.CanonicalImageValidated,
            fixtureLegacyFallbackActive: false,
            fixtureCompatibilityPathActive: false,
            usesScaffoldCommitBlob: false,
            canonicalPathActive: true,
            canonicalGateFailure: null);

        Assert.Equal(
            "ReplayCanonicalCandidateMissing",
            InvokeGetFailClosedReasonForRuntimeStatus(
                status,
                "BestEffort",
                128,
                isFixtureImage: false,
                disallowScaffoldCommitOnNonFixture: true,
                rejectScaffoldReplayBlobOnNonFixture: true,
                requireCanonicalReplayCandidateOnNonFixture: false));

        Assert.Equal(
            "ReplayCanonicalCandidateMissing",
            InvokeGetFailClosedReasonForRuntimeStatus(
                status,
                "BestEffort",
                128,
                isFixtureImage: false,
                disallowScaffoldCommitOnNonFixture: true,
                rejectScaffoldReplayBlobOnNonFixture: true,
                requireCanonicalReplayCandidateOnNonFixture: true));
    }

    [Theory]
    [InlineData("FixtureLegacyFallback", "FixtureLegacyFallbackActive")]
    [InlineData("ScaffoldCommitBlob", "ScaffoldCommitBlobActive")]
    [InlineData("CanonicalProofMissing", "CanonicalPathNotActive")]
    [InlineData("ReplayPendingWindow", "ReplayCheckpointPendingWindow")]
    [InlineData("ReplayCanonicalCandidateMissing", "ReplayCanonicalCandidateMissing")]
    public void GetFailClosedReasonForRuntimeStatus_EnforcesNonFixtureCanonicalSafetySignals_EvenWhenBestEffort(
        string scenario,
        string expectedReason)
    {
        object status = scenario switch
        {
            "FixtureLegacyFallback" => CreateHostRuntimeStatusRaw(
                writeBackend: "Native",
                commitModel: NativeWriteCommitModel.CanonicalApfsCheckpoint,
                nativeWriteReadiness: NativeWriteReadiness.CommitReady,
                recoveryActive: false,
                recoveryReason: null,
                lastCommitXid: 1500,
                nativeWriteSafetyState: NativeWriteSafetyState.PilotReadWrite,
                lastRecoveryAction: null,
                dirtyTransactionCount: 0,
                nativeWriteValidationState: NativeWriteValidationState.CanonicalImageValidated,
                fixtureLegacyFallbackActive: true),
            "ScaffoldCommitBlob" => CreateHostRuntimeStatusRaw(
                writeBackend: "Native",
                commitModel: NativeWriteCommitModel.CanonicalApfsCheckpoint,
                nativeWriteReadiness: NativeWriteReadiness.CommitReady,
                recoveryActive: false,
                recoveryReason: null,
                lastCommitXid: 1501,
                nativeWriteSafetyState: NativeWriteSafetyState.PilotReadWrite,
                lastRecoveryAction: null,
                dirtyTransactionCount: 0,
                nativeWriteValidationState: NativeWriteValidationState.CanonicalImageValidated,
                usesScaffoldCommitBlob: true),
            "CanonicalProofMissing" => CreateHostRuntimeStatusRaw(
                writeBackend: "Native",
                commitModel: NativeWriteCommitModel.CanonicalApfsCheckpoint,
                nativeWriteReadiness: NativeWriteReadiness.CommitReady,
                recoveryActive: false,
                recoveryReason: null,
                lastCommitXid: 1502,
                nativeWriteSafetyState: NativeWriteSafetyState.PilotReadWrite,
                lastRecoveryAction: null,
                dirtyTransactionCount: 0,
                nativeWriteValidationState: NativeWriteValidationState.CanonicalImageValidated,
                canonicalPathActive: null,
                canonicalGateFailure: null),
            "ReplayPendingWindow" => CreateHostRuntimeStatusRaw(
                writeBackend: "Native",
                commitModel: NativeWriteCommitModel.CanonicalApfsCheckpoint,
                nativeWriteReadiness: NativeWriteReadiness.RecoveryMode,
                recoveryActive: true,
                recoveryReason: null,
                lastCommitXid: 1503,
                nativeWriteSafetyState: NativeWriteSafetyState.RecoveryBlocked,
                lastRecoveryAction: "ReplaySkippedFailClosed",
                dirtyTransactionCount: 0,
                nativeWriteValidationState: NativeWriteValidationState.CanonicalImageValidated),
            "ReplayCanonicalCandidateMissing" => CreateHostRuntimeStatusRaw(
                writeBackend: "Native",
                commitModel: NativeWriteCommitModel.CanonicalApfsCheckpoint,
                nativeWriteReadiness: NativeWriteReadiness.RecoveryMode,
                recoveryActive: true,
                recoveryReason: "ReplayCanonicalCandidateMissing",
                lastCommitXid: 1504,
                nativeWriteSafetyState: NativeWriteSafetyState.RecoveryBlocked,
                lastRecoveryAction: "ReplaySkippedFailClosed",
                dirtyTransactionCount: 0,
                nativeWriteValidationState: NativeWriteValidationState.CanonicalImageValidated),
            _ => throw new InvalidOperationException($"Unknown scenario '{scenario}'."),
        };

        if (scenario == "ReplayPendingWindow")
        {
            SetHostRuntimeStatusReplayTelemetry(
                status,
                replayCheckpointCandidatePresent: true,
                replayCheckpointPendingWindow: true);
        }

        var reason = InvokeGetFailClosedReasonForRuntimeStatus(
            status,
            "BestEffort",
            128,
            isFixtureImage: false,
            disallowScaffoldCommitOnNonFixture: true,
            rejectScaffoldReplayBlobOnNonFixture: true,
            requireCanonicalReplayCandidateOnNonFixture: true);

        Assert.Equal(expectedReason, reason);
    }

    private static List<ParsedVolumeRowProjection> InvokeParseVolumeRows(string stdout)
    {
        var parseMethod = typeof(NativeApfsBackend).GetMethod(
            "ParseVolumeRows",
            BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(parseMethod);

        var raw = parseMethod!.Invoke(null, [stdout]);
        Assert.NotNull(raw);

        var rows = new List<ParsedVolumeRowProjection>();
        foreach (var row in (IEnumerable)raw!)
        {
            var rowType = row!.GetType();
            var name = (string?)rowType.GetProperty("Name", BindingFlags.Public | BindingFlags.Instance)?.GetValue(row);
            var isEncrypted = (bool?)rowType.GetProperty("IsEncrypted", BindingFlags.Public | BindingFlags.Instance)?.GetValue(row);
            var writeIncompatibilities = (IReadOnlyList<string>?)rowType
                .GetProperty("WriteIncompatibilities", BindingFlags.Public | BindingFlags.Instance)
                ?.GetValue(row);
            var writeUnsupportedFeatures = (IReadOnlyList<string>?)rowType
                .GetProperty("WriteUnsupportedFeatures", BindingFlags.Public | BindingFlags.Instance)
                ?.GetValue(row);
            if (!string.IsNullOrWhiteSpace(name) && isEncrypted.HasValue)
            {
                rows.Add(new ParsedVolumeRowProjection(
                    name,
                    isEncrypted.Value,
                    writeIncompatibilities ?? Array.Empty<string>(),
                    writeUnsupportedFeatures ?? Array.Empty<string>()));
            }
        }

        return rows;
    }

    private static HostRuntimeStatusProjection InvokeBuildDefaultHostRuntimeStatus(
        MountAccessMode accessMode,
        string configuredBackend)
    {
        var method = typeof(NativeApfsBackend).GetMethod(
            "BuildDefaultHostRuntimeStatus",
            BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        var result = method!.Invoke(null, [accessMode, configuredBackend]);
        Assert.NotNull(result);

        return ProjectHostRuntimeStatus(result!);
    }

    private static HostRuntimeStatusProjection InvokeBuildHostRuntimeStatusFromPayload(
        MountAccessMode accessMode,
        string configuredBackend,
        string? payloadWriteBackend,
        string? payloadCommitModel,
        string? payloadReadiness,
        bool payloadRecoveryActive,
        string? payloadRecoveryReason,
        ulong? payloadLastCommitXid,
        string? payloadSafetyState,
        string? payloadLastRecoveryAction,
        int? payloadDirtyTransactionCount,
        string? payloadValidationState = null,
        bool? payloadShutdownDrainActive = null,
        int? payloadInFlightMutationCallbacks = null,
        int? payloadHostPid = null,
        int? payloadValidationCrashFaultPasses = null,
        int? payloadValidationCrashStageMatrixPasses = null,
        int? payloadValidationHardwarePilotPasses = null,
        int? payloadValidationHotUnplugPasses = null,
        int? payloadValidationMacOsValidationPasses = null,
        int? payloadValidationMacOsConsistencyPasses = null,
        int? payloadValidationPowerLossReplayPasses = null,
        bool? payloadValidationPowerLossPassVerified = null,
        string? payloadValidationLastValidatedUtc = null,
        string? payloadValidationLastProfileId = null,
        bool? payloadFixtureCompatibilityPathActive = null,
        string? payloadCommitStage = null,
        string? payloadReplayStage = null,
        string? payloadCommitBlobMagic = null,
        bool? payloadCanonicalPathActive = null,
        string? payloadCanonicalGateFailure = null)
    {
        var status = InvokeBuildHostRuntimeStatusFromPayloadRaw(
            accessMode,
            configuredBackend,
            payloadWriteBackend,
            payloadCommitModel,
            payloadReadiness,
            payloadRecoveryActive,
            payloadRecoveryReason,
            payloadLastCommitXid,
            payloadSafetyState,
            payloadLastRecoveryAction,
            payloadDirtyTransactionCount,
            payloadValidationState,
            payloadShutdownDrainActive,
            payloadInFlightMutationCallbacks,
            payloadHostPid,
            payloadValidationCrashFaultPasses,
            payloadValidationCrashStageMatrixPasses,
            payloadValidationHardwarePilotPasses,
            payloadValidationHotUnplugPasses,
            payloadValidationMacOsValidationPasses,
            payloadValidationMacOsConsistencyPasses,
            payloadValidationPowerLossReplayPasses,
            payloadValidationPowerLossPassVerified,
            payloadValidationLastValidatedUtc,
            payloadValidationLastProfileId,
            payloadFixtureCompatibilityPathActive,
            payloadCommitStage,
            payloadReplayStage,
            payloadCommitBlobMagic,
            payloadCanonicalPathActive,
            payloadCanonicalGateFailure);
        return ProjectHostRuntimeStatus(status);
    }

    private static object InvokeBuildHostRuntimeStatusFromPayloadRaw(
        MountAccessMode accessMode,
        string configuredBackend,
        string? payloadWriteBackend,
        string? payloadCommitModel,
        string? payloadReadiness,
        bool payloadRecoveryActive,
        string? payloadRecoveryReason,
        ulong? payloadLastCommitXid,
        string? payloadSafetyState,
        string? payloadLastRecoveryAction,
        int? payloadDirtyTransactionCount,
        string? payloadValidationState = null,
        bool? payloadShutdownDrainActive = null,
        int? payloadInFlightMutationCallbacks = null,
        int? payloadHostPid = null,
        int? payloadValidationCrashFaultPasses = null,
        int? payloadValidationCrashStageMatrixPasses = null,
        int? payloadValidationHardwarePilotPasses = null,
        int? payloadValidationHotUnplugPasses = null,
        int? payloadValidationMacOsValidationPasses = null,
        int? payloadValidationMacOsConsistencyPasses = null,
        int? payloadValidationPowerLossReplayPasses = null,
        bool? payloadValidationPowerLossPassVerified = null,
        string? payloadValidationLastValidatedUtc = null,
        string? payloadValidationLastProfileId = null,
        bool? payloadFixtureCompatibilityPathActive = null,
        string? payloadCommitStage = null,
        string? payloadReplayStage = null,
        string? payloadCommitBlobMagic = null,
        bool? payloadCanonicalPathActive = null,
        string? payloadCanonicalGateFailure = null)
    {
        var buildDefaultMethod = typeof(NativeApfsBackend).GetMethod(
            "BuildDefaultHostRuntimeStatus",
            BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(buildDefaultMethod);
        var fallback = buildDefaultMethod!.Invoke(null, [accessMode, configuredBackend]);
        Assert.NotNull(fallback);

        var payloadType = typeof(NativeApfsBackend).GetNestedType(
            "HostRuntimeStatusPayload",
            BindingFlags.NonPublic);
        Assert.NotNull(payloadType);

        var payloadCtor = payloadType!.GetConstructors(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)
            .Single(static ctor => ctor.GetParameters().Length == 31);
        var payload = payloadCtor.Invoke(
            [
                payloadWriteBackend,
                payloadCommitModel,
                payloadReadiness,
                payloadValidationState,
                payloadRecoveryActive,
                payloadRecoveryReason,
                payloadLastCommitXid,
                payloadSafetyState,
                payloadLastRecoveryAction,
                payloadDirtyTransactionCount,
                payloadShutdownDrainActive,
                payloadInFlightMutationCallbacks,
                payloadHostPid,
                payloadValidationCrashFaultPasses,
                payloadValidationCrashStageMatrixPasses,
                payloadValidationHardwarePilotPasses,
                payloadValidationHotUnplugPasses,
                payloadValidationMacOsValidationPasses,
                payloadValidationMacOsConsistencyPasses,
                payloadValidationPowerLossReplayPasses,
                payloadValidationPowerLossPassVerified,
                payloadValidationLastValidatedUtc,
                payloadValidationLastProfileId,
                null,
                payloadFixtureCompatibilityPathActive,
                null,
                payloadCommitStage,
                payloadReplayStage,
                payloadCommitBlobMagic,
                payloadCanonicalPathActive,
                payloadCanonicalGateFailure
            ]);

        var buildFromPayloadMethod = typeof(NativeApfsBackend).GetMethod(
            "BuildHostRuntimeStatusFromPayload",
            BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(buildFromPayloadMethod);
        var status = buildFromPayloadMethod!.Invoke(null, [payload, accessMode, fallback]);
        Assert.NotNull(status);
        return status!;
    }

    private static object CreateHostRuntimeStatusRaw(
        string writeBackend,
        NativeWriteCommitModel commitModel,
        NativeWriteReadiness nativeWriteReadiness,
        bool recoveryActive,
        string? recoveryReason,
        ulong? lastCommitXid,
        NativeWriteSafetyState nativeWriteSafetyState,
        string? lastRecoveryAction,
        int dirtyTransactionCount,
        NativeWriteValidationState nativeWriteValidationState = NativeWriteValidationState.Scaffold,
        bool shutdownDrainActive = false,
        int inFlightMutationCallbacks = 0,
        int hostProcessId = 0,
        NativeWriteValidationEvidence? validationEvidence = null,
        bool fixtureLegacyFallbackActive = false,
        bool fixtureCompatibilityPathActive = false,
        bool usesScaffoldCommitBlob = false,
        string? commitStage = null,
        string? replayStage = null,
        string? commitBlobMagic = null,
        bool? canonicalPathActive = null,
        string? canonicalGateFailure = null)
    {
        var statusType = typeof(NativeApfsBackend).GetNestedType(
            "HostRuntimeStatus",
            BindingFlags.NonPublic);
        Assert.NotNull(statusType);

        var statusCtor = statusType!.GetConstructors(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)
            .Single(static ctor => ctor.GetParameters().Length == 22);
        return statusCtor.Invoke(
            [
                writeBackend,
                commitModel,
                nativeWriteReadiness,
                nativeWriteValidationState,
                recoveryActive,
                recoveryReason,
                lastCommitXid,
                nativeWriteSafetyState,
                lastRecoveryAction,
                dirtyTransactionCount,
                shutdownDrainActive,
                inFlightMutationCallbacks,
                hostProcessId,
                validationEvidence,
                fixtureLegacyFallbackActive,
                fixtureCompatibilityPathActive,
                usesScaffoldCommitBlob,
                commitStage,
                replayStage,
                commitBlobMagic,
                canonicalPathActive,
                canonicalGateFailure
            ]);
    }

    private static void SetHostRuntimeStatusReplayTelemetry(
        object status,
        bool? replayCheckpointCandidatePresent,
        bool? replayCheckpointPendingWindow)
    {
        var statusType = status.GetType();
        var candidateProperty = statusType.GetProperty(
            "ReplayCheckpointCandidatePresent",
            BindingFlags.Public | BindingFlags.Instance);
        Assert.NotNull(candidateProperty);
        candidateProperty!.SetValue(status, replayCheckpointCandidatePresent);

        var pendingProperty = statusType.GetProperty(
            "ReplayCheckpointPendingWindow",
            BindingFlags.Public | BindingFlags.Instance);
        Assert.NotNull(pendingProperty);
        pendingProperty!.SetValue(status, replayCheckpointPendingWindow);
    }

    private static bool InvokeShouldFailClosedForRuntimeStatus(object status, string? recoveryPolicy)
    {
        var method = typeof(NativeApfsBackend).GetMethod(
            "ShouldFailClosedForRuntimeStatus",
            BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        var result = method!.Invoke(null, [status, recoveryPolicy]);
        Assert.IsType<bool>(result);
        return (bool)result!;
    }

    private static bool InvokeShouldBlockObservedValidationPromotionForRuntimeStatus(
        string? deviceId,
        MountAccessMode requestedAccessMode,
        string runtimeWriteBackend,
        object runtimeStatus,
        bool disallowScaffoldCommitOnNonFixture,
        bool rejectScaffoldReplayBlobOnNonFixture,
        bool requireCanonicalReplayCandidateOnNonFixture)
    {
        var method = typeof(NativeApfsBackend).GetMethod(
            "ShouldBlockObservedValidationPromotionForRuntimeStatus",
            BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        var strictControls = (
            disallowScaffoldCommitOnNonFixture,
            rejectScaffoldReplayBlobOnNonFixture,
            requireCanonicalReplayCandidateOnNonFixture);

        var result = method!.Invoke(
            null,
            [
                deviceId,
                requestedAccessMode,
                runtimeWriteBackend,
                runtimeStatus,
                strictControls
            ]);
        Assert.IsType<bool>(result);
        return (bool)result!;
    }

    private static string? InvokeGetFailClosedReasonForRuntimeStatus(
        object status,
        string? recoveryPolicy,
        int maxDirtyTransactions,
        bool isFixtureImage = true,
        bool disallowScaffoldCommitOnNonFixture = false,
        bool rejectScaffoldReplayBlobOnNonFixture = false,
        bool requireCanonicalReplayCandidateOnNonFixture = false)
    {
        var method = typeof(NativeApfsBackend).GetMethod(
            "GetFailClosedReasonForRuntimeStatus",
            BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        var result = method!.Invoke(
            null,
            [
                status,
                recoveryPolicy,
                maxDirtyTransactions,
                isFixtureImage,
                disallowScaffoldCommitOnNonFixture,
                rejectScaffoldReplayBlobOnNonFixture,
                requireCanonicalReplayCandidateOnNonFixture
            ]);
        return result as string;
    }

    private static NativeWriteValidationState InvokeResolveRequiredValidationStateForPromotionPolicy(string? policy)
    {
        var method = typeof(NativeApfsBackend).GetMethod(
            "ResolveRequiredValidationStateForPromotionPolicy",
            BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        var result = method!.Invoke(null, [policy]);
        Assert.IsType<NativeWriteValidationState>(result);
        return (NativeWriteValidationState)result!;
    }

    private static string InvokeBuildNativeValidationGateState(NativeWriteValidationState requiredState)
    {
        var method = typeof(NativeApfsBackend).GetMethod(
            "BuildNativeValidationGateState",
            BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        var result = method!.Invoke(null, [requiredState]);
        Assert.IsType<string>(result);
        return (string)result!;
    }

    private static string InvokeBuildNativeValidationDiagnosticCode(NativeWriteValidationState requiredState)
    {
        var method = typeof(NativeApfsBackend).GetMethod(
            "BuildNativeValidationDiagnosticCode",
            BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        var result = method!.Invoke(null, [requiredState]);
        Assert.IsType<string>(result);
        return (string)result!;
    }

    private static NativeWriteValidationState InvokeResolveObservedValidationStateForEvidence(
        MountAccessMode accessMode,
        string writeBackend,
        NativeWriteCommitModel commitModel,
        NativeWriteReadiness readiness,
        bool recoveryActive,
        NativeWriteValidationState reportedState)
    {
        var method = typeof(NativeApfsBackend).GetMethod(
            "ResolveObservedValidationStateForEvidence",
            BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        var result = method!.Invoke(
            null,
            [accessMode, writeBackend, commitModel, readiness, recoveryActive, reportedState]);
        Assert.IsType<NativeWriteValidationState>(result);
        return (NativeWriteValidationState)result!;
    }

    private static NativeWriteValidationState InvokeClampObservedValidationStateForVolume(
        NativeWriteValidationState observedState,
        VolumeInfo volume)
    {
        var method = typeof(NativeApfsBackend).GetMethod(
            "ClampObservedValidationStateForVolume",
            BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        var result = method!.Invoke(null, [observedState, volume]);
        Assert.IsType<NativeWriteValidationState>(result);
        return (NativeWriteValidationState)result!;
    }

    private static NativeWriteValidationEvidence InvokePromoteValidationEvidenceForObservedState(
        NativeWriteValidationEvidence baseline,
        NativeWriteValidationState observedState,
        int minCrashFaultPasses,
        int minHardwarePilotPasses,
        int minMacOsValidationPasses,
        bool stableRequiresPowerLossPass,
        DateTime nowUtc,
        bool allowCounterIncrement = true,
        int minCrashStageMatrixPasses = 0,
        int minHotUnplugPasses = 0,
        int minMacOsConsistencyPasses = 0,
        int minPowerLossReplayPasses = 0,
        string? lastValidationProfileId = null)
    {
        var method = typeof(NativeApfsBackend).GetMethod(
            "PromoteValidationEvidenceForObservedState",
            BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        var result = method!.Invoke(
            null,
            [
                baseline,
                observedState,
                minCrashFaultPasses,
                minCrashStageMatrixPasses,
                minHardwarePilotPasses,
                minHotUnplugPasses,
                minMacOsValidationPasses,
                minMacOsConsistencyPasses,
                minPowerLossReplayPasses,
                stableRequiresPowerLossPass,
                nowUtc,
                allowCounterIncrement,
                lastValidationProfileId
            ]);
        Assert.IsType<NativeWriteValidationEvidence>(result);
        return (NativeWriteValidationEvidence)result!;
    }

    private static bool InvokeShouldPromoteValidationEvidenceForSession(
        NativeApfsBackend backend,
        string profileId,
        int hostProcessId,
        string? runtimeSessionId)
    {
        var method = typeof(NativeApfsBackend).GetMethod(
            "ShouldPromoteValidationEvidenceForSession",
            BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(method);

        var result = method!.Invoke(backend, [profileId, hostProcessId, runtimeSessionId]);
        Assert.IsType<bool>(result);
        return (bool)result!;
    }

    private static NativeWriteValidationEvidence InvokeMergeValidationEvidenceFromRuntimeStatus(
        NativeApfsBackend backend,
        VolumeInfo volume,
        MountAccessMode requestedAccessMode,
        object runtimeStatus,
        NativeWriteValidationEvidence baselineEvidence,
        string? runtimeSessionId)
    {
        var method = typeof(NativeApfsBackend).GetMethod(
            "MergeValidationEvidenceFromRuntimeStatus",
            BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(method);

        var result = method!.Invoke(
            backend,
            [volume, requestedAccessMode, runtimeStatus, baselineEvidence, runtimeSessionId]);
        Assert.IsType<NativeWriteValidationEvidence>(result);
        return (NativeWriteValidationEvidence)result!;
    }

    private static string? InvokeGetValidationPolicyFailClosedReason(
        MountAccessMode accessMode,
        string writeBackend,
        NativeWriteValidationState effectiveValidationState,
        NativeWriteValidationState requiredValidationState)
    {
        var method = typeof(NativeApfsBackend).GetMethod(
            "GetValidationPolicyFailClosedReason",
            BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        var result = method!.Invoke(
            null,
            [accessMode, writeBackend, effectiveValidationState, requiredValidationState]);
        return result as string;
    }

    private static string? InvokeGetValidationPolicyFailClosedReasonDetailed(
        ServiceHostOptions options,
        MountAccessMode accessMode,
        string writeBackend,
        NativeWriteValidationState effectiveValidationState,
        NativeWriteValidationState requiredValidationState,
        NativeWriteValidationEvidence validationEvidence,
        VolumeInfo? volume = null)
    {
        using var backend = new NativeApfsBackend(options);

        var method = typeof(NativeApfsBackend).GetMethod(
            "GetValidationPolicyFailClosedReasonDetailed",
            BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(method);

        var targetVolume = volume ?? new VolumeInfo(
            VolumeId: @"C:\fixtures\sample.apfs.img|Main",
            DeviceId: @"C:\fixtures\sample.apfs.img",
            VolumeName: "Main",
            SupportsReadWrite: true,
            IsEncrypted: false,
            SupportsExplorerMount: true,
            NativeVolumePath: @"C:\fixtures\sample.apfs.img\ApfsAccess_Volumes\Main",
            SupportsNativeWrite: true,
            WriteBlockReason: null,
            WriteIncompatibilities: Array.Empty<string>(),
            WriteUnsupportedFeatures: Array.Empty<string>(),
            NativeWriteReadiness: NativeWriteReadiness.CommitReady
        );

        var result = method!.Invoke(
            backend,
            [accessMode, writeBackend, effectiveValidationState, requiredValidationState, validationEvidence, targetVolume]);
        return result as string;
    }

    private static string InvokeBuildValidationEvidenceDiagnosticDetail(
        ServiceHostOptions options,
        VolumeInfo volume,
        NativeWriteValidationState requiredValidationState,
        NativeWriteValidationEvidence evidence,
        string? failClosedReason,
        DateTime nowUtc)
    {
        using var backend = new NativeApfsBackend(options);

        var method = typeof(NativeApfsBackend).GetMethod(
            "BuildValidationEvidenceDiagnosticDetail",
            BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(method);

        var result = method!.Invoke(
            backend,
            [volume, requiredValidationState, evidence, failClosedReason, nowUtc]);
        Assert.IsType<string>(result);
        return (string)result!;
    }

    private static string? InvokeGetWriteGateFailClosedReason(
        MountAccessMode accessMode,
        string writeBackend,
        WriteGateDecision writeGateDecision)
    {
        var method = typeof(NativeApfsBackend).GetMethod(
            "GetWriteGateFailClosedReason",
            BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        var result = method!.Invoke(
            null,
            [accessMode, writeBackend, writeGateDecision]);
        return result as string;
    }

    private static bool InvokeIsFixtureImagePath(string? devicePath)
    {
        var method = typeof(NativeApfsBackend).GetMethod(
            "IsFixtureImagePath",
            BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        var result = method!.Invoke(null, [devicePath]);
        Assert.IsType<bool>(result);
        return (bool)result!;
    }

    private static (bool DisallowScaffoldCommitOnNonFixture, bool RejectScaffoldReplayBlobOnNonFixture, bool RequireCanonicalReplayCandidateOnNonFixture)
        InvokeResolveEffectiveNonFixtureScaffoldControls(
            NativeApfsBackend backend,
            string? deviceId)
    {
        var method = typeof(NativeApfsBackend).GetMethod(
            "ResolveEffectiveNonFixtureScaffoldControls",
            BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(method);

        var result = method!.Invoke(backend, [deviceId]);
        Assert.IsType<(bool DisallowScaffoldCommitOnNonFixture, bool RejectScaffoldReplayBlobOnNonFixture, bool RequireCanonicalReplayCandidateOnNonFixture)>(result);
        return ((bool DisallowScaffoldCommitOnNonFixture, bool RejectScaffoldReplayBlobOnNonFixture, bool RequireCanonicalReplayCandidateOnNonFixture))result!;
    }

    private static (bool DisallowScaffoldCommitOnNonFixture, bool RejectScaffoldReplayBlobOnNonFixture, bool RequireCanonicalReplayCandidateOnNonFixture)
        InvokeResolveEffectiveNonFixtureScaffoldControlsForMountedVolume(
            NativeApfsBackend backend,
            string? volumeId)
    {
        var method = typeof(NativeApfsBackend).GetMethod(
            "ResolveEffectiveNonFixtureScaffoldControlsForMountedVolume",
            BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(method);

        var result = method!.Invoke(backend, [volumeId]);
        Assert.IsType<(bool DisallowScaffoldCommitOnNonFixture, bool RejectScaffoldReplayBlobOnNonFixture, bool RequireCanonicalReplayCandidateOnNonFixture)>(result);
        return ((bool DisallowScaffoldCommitOnNonFixture, bool RejectScaffoldReplayBlobOnNonFixture, bool RequireCanonicalReplayCandidateOnNonFixture))result!;
    }

    private static bool InvokeResolveEffectiveAllowLegacyScaffoldForFixtures(
        NativeApfsBackend backend,
        string? deviceId)
    {
        var method = typeof(NativeApfsBackend).GetMethod(
            "ResolveEffectiveAllowLegacyScaffoldForFixtures",
            BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(method);

        var result = method!.Invoke(backend, [deviceId]);
        Assert.IsType<bool>(result);
        return (bool)result!;
    }

    private static HostRuntimeStatusProjection ProjectHostRuntimeStatus(object result)
    {
        var resultType = result.GetType();
        var writeBackend = (string?)resultType.GetProperty("WriteBackend", BindingFlags.Public | BindingFlags.Instance)?.GetValue(result);
        var commitModel = (NativeWriteCommitModel?)resultType.GetProperty("CommitModel", BindingFlags.Public | BindingFlags.Instance)?.GetValue(result);
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
        var validationEvidence = (NativeWriteValidationEvidence?)resultType.GetProperty("ValidationEvidence", BindingFlags.Public | BindingFlags.Instance)?.GetValue(result);
        var fixtureLegacyFallbackActive = (bool?)resultType.GetProperty("FixtureLegacyFallbackActive", BindingFlags.Public | BindingFlags.Instance)?.GetValue(result);
        var usesScaffoldCommitBlob = (bool?)resultType.GetProperty("UsesScaffoldCommitBlob", BindingFlags.Public | BindingFlags.Instance)?.GetValue(result);
        var commitStage = (string?)resultType.GetProperty("CommitStage", BindingFlags.Public | BindingFlags.Instance)?.GetValue(result);
        var replayStage = (string?)resultType.GetProperty("ReplayStage", BindingFlags.Public | BindingFlags.Instance)?.GetValue(result);
        var commitBlobMagic = (string?)resultType.GetProperty("CommitBlobMagic", BindingFlags.Public | BindingFlags.Instance)?.GetValue(result);
        var canonicalPathActive = (bool?)resultType.GetProperty("CanonicalPathActive", BindingFlags.Public | BindingFlags.Instance)?.GetValue(result);
        var canonicalGateFailure = (string?)resultType.GetProperty("CanonicalGateFailure", BindingFlags.Public | BindingFlags.Instance)?.GetValue(result);

        Assert.NotNull(writeBackend);
        Assert.NotNull(commitModel);
        Assert.NotNull(nativeWriteReadiness);
        Assert.NotNull(nativeWriteValidationState);
        Assert.NotNull(recoveryActive);
        Assert.NotNull(nativeWriteSafetyState);
        Assert.NotNull(dirtyTransactionCount);
        Assert.NotNull(shutdownDrainActive);
        Assert.NotNull(inFlightMutationCallbacks);
        Assert.NotNull(hostProcessId);
        Assert.NotNull(fixtureLegacyFallbackActive);
        Assert.NotNull(usesScaffoldCommitBlob);

        return new HostRuntimeStatusProjection(
            writeBackend!,
            commitModel!.Value,
            nativeWriteReadiness!.Value,
            nativeWriteValidationState!.Value,
            recoveryActive!.Value,
            recoveryReason,
            lastCommitXid,
            nativeWriteSafetyState!.Value,
            lastRecoveryAction,
            dirtyTransactionCount!.Value,
            shutdownDrainActive!.Value,
            inFlightMutationCallbacks!.Value,
            hostProcessId!.Value,
            validationEvidence,
            fixtureLegacyFallbackActive!.Value,
            usesScaffoldCommitBlob!.Value,
            commitStage,
            replayStage,
            commitBlobMagic,
            canonicalPathActive,
            canonicalGateFailure);
    }

    private static string InvokeStaticStringMethod(string methodName, string? arg)
    {
        var method = typeof(NativeApfsBackend).GetMethod(
            methodName,
            BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        var result = method!.Invoke(null, [arg]);
        Assert.IsType<string>(result);
        return (string)result!;
    }

    private static IReadOnlyList<NativeWriteDiagnostic> InvokeBuildNativeWriteDiagnostics(
        MountAccessMode effectiveAccessMode,
        string effectiveWriteBackend,
        NativeWriteValidationState effectiveValidationState,
        NativeWriteValidationState requiredValidationState,
        string? recoveryReason,
        string? recoveryAction,
        NativeWriteValidationEvidence? validationEvidence,
        bool recoveryActive,
        bool failClosedTriggered,
        string scope,
        string? commitStage = null,
        string? replayStage = null,
        string? commitBlobMagic = null,
        bool? canonicalPathActive = null,
        string? deviceProfileId = null,
        bool? replayCheckpointCandidatePresent = null,
        bool? replayCheckpointPendingWindow = null)
    {
        var method = typeof(NativeApfsBackend).GetMethod(
            "BuildNativeWriteDiagnostics",
            BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        var result = method!.Invoke(
            null,
            [
                effectiveAccessMode,
                effectiveWriteBackend,
                effectiveValidationState,
                requiredValidationState,
                recoveryReason,
                recoveryAction,
                validationEvidence,
                recoveryActive,
                failClosedTriggered,
                scope,
                commitStage,
                replayStage,
                commitBlobMagic,
                canonicalPathActive,
                deviceProfileId,
                replayCheckpointCandidatePresent,
                replayCheckpointPendingWindow,
            ]);
        Assert.NotNull(result);
        Assert.IsAssignableFrom<IEnumerable>(result);

        var diagnostics = ((IEnumerable)result!)
            .Cast<object>()
            .Select(static item => Assert.IsType<NativeWriteDiagnostic>(item))
            .ToArray();
        return diagnostics;
    }

    private sealed record ParsedVolumeRowProjection(
        string Name,
        bool IsEncrypted,
        IReadOnlyList<string> WriteIncompatibilities,
        IReadOnlyList<string> WriteUnsupportedFeatures);

    private sealed record HostRuntimeStatusProjection(
        string WriteBackend,
        NativeWriteCommitModel CommitModel,
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
        NativeWriteValidationEvidence? ValidationEvidence,
        bool FixtureLegacyFallbackActive,
        bool UsesScaffoldCommitBlob,
        string? CommitStage,
        string? ReplayStage,
        string? CommitBlobMagic,
        bool? CanonicalPathActive,
        string? CanonicalGateFailure);
}
