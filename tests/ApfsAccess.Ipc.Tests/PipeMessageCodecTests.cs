using ApfsAccess.Core;
using ApfsAccess.Ipc;

namespace ApfsAccess.Ipc.Tests;

public sealed class PipeMessageCodecTests
{
    [Fact]
    public void SerializeAndDeserialize_RoundTripsStatusPayload()
    {
        var source = PipeMessageCodec.Create(
            ApfsMessageTypes.StatusChanged,
            new StatusChangedPayload(
                RuntimeState.MountedRw,
                new[] { "X:\\", "Y:\\" },
                null,
                DateTime.UtcNow,
                new[] { "Sample warning" },
                WriteEnabled: true,
                CompatibilityWarnings: new[] { "Sample compatibility warning" },
                MountedVolumes:
                [
                    new MountedVolumeDisplay(
                        VolumeId: @"\\.\PhysicalDrive3|Main",
                        MountPoint: "X:\\",
                        VolumeName: "Main",
                        DeviceId: @"\\.\PhysicalDrive3",
                        DeviceDisplayName: "Sample USB Device",
                        AccessMode: MountAccessMode.ReadWrite),
                ],
                WriteBackend: "Native",
                NativeWriteReadiness: NativeWriteReadiness.CommitReady,
                NativeWriteEngineState: NativeWriteEngineState.Transactional,
                NativeWriteValidationState: NativeWriteValidationState.CanonicalImageValidated,
                RecoveryActive: true,
                RecoveryReason: "CommitTimedOut",
                LastCommitXid: 42,
                NativeWriteSafetyState: NativeWriteSafetyState.PilotReadWrite,
                WriteIncompatibilities: new[] { "Case-sensitive APFS volumes are not supported in v1 native write mode." },
                LastRecoveryAction: "ReplaySkippedFailClosed",
                DirtyTransactionCount: 3,
                ShutdownDrainActive: true,
                InFlightMutationCallbacks: 2,
                NativeWriteValidationEvidence: new NativeWriteValidationEvidence(
                    CrashFaultPasses: 1,
                    CrashStageMatrixPasses: 2,
                    HardwarePilotPasses: 2,
                    HotUnplugPasses: 1,
                    MacOsValidationPasses: 1,
                    MacOsConsistencyPasses: 1,
                    PowerLossReplayPasses: 1,
                    PowerLossPassVerified: false,
                    LastValidatedUtc: DateTime.UtcNow,
                    LastValidationProfileId: "raw::physicaldrive3::main"),
                NativeWriteDiagnostics: new[]
                {
                    new NativeWriteDiagnostic(
                        Code: "NativeWriteValidationCrashFaultEvidenceInsufficient",
                        Message: "native write crash-fault evidence does not meet the configured promotion threshold",
                        IsFailClosed: true,
                        Scope: "Runtime:ValidationGate",
                        RecoveryReason: "ValidationCrashFaultEvidenceInsufficient",
                        RecoveryAction: "DowngradedAfterValidationCrashFaultGate",
                        ValidationState: NativeWriteValidationState.CanonicalImageValidated,
                        RequiredValidationState: NativeWriteValidationState.HardwarePilotValidated,
                        ValidationEvidence: new NativeWriteValidationEvidence(
                            CrashFaultPasses: 1,
                            CrashStageMatrixPasses: 0,
                            HardwarePilotPasses: 0,
                            HotUnplugPasses: 0,
                            MacOsValidationPasses: 0,
                            MacOsConsistencyPasses: 0,
                            PowerLossReplayPasses: 0,
                            PowerLossPassVerified: false,
                            LastValidatedUtc: DateTime.UtcNow),
                        ValidationScenario: "CrashFault",
                        EvidenceSnapshotId: "snapshot-0001")
                }
            ),
            requestId: "req-1"
        );

        var json = PipeMessageCodec.Serialize(source);
        var success = PipeMessageCodec.TryDeserialize(json, out var deserialized);

        Assert.True(success);
        Assert.NotNull(deserialized);
        Assert.Equal(ApfsMessageTypes.StatusChanged, deserialized!.Type);
        Assert.Equal("req-1", deserialized.RequestId);

        var payloadSuccess = PipeMessageCodec.TryGetPayload<StatusChangedPayload>(deserialized, out var payload);
        Assert.True(payloadSuccess);
        Assert.NotNull(payload);
        Assert.Equal(RuntimeState.MountedRw, payload!.State);
        Assert.Equal(2, payload.MountPoints.Count);
        Assert.NotNull(payload.MountedVolumes);
        var mountedVolume = Assert.Single(payload.MountedVolumes!);
        Assert.Equal(@"\\.\PhysicalDrive3|Main", mountedVolume.VolumeId);
        Assert.Equal("Sample USB Device", mountedVolume.DeviceDisplayName);
        Assert.Single(payload.Warnings);
        Assert.True(payload.WriteEnabled);
        Assert.Single(payload.CompatibilityWarnings);
        Assert.Equal("Native", payload.WriteBackend);
        Assert.Equal(NativeWriteReadiness.CommitReady, payload.NativeWriteReadiness);
        Assert.Equal(NativeWriteEngineState.Transactional, payload.NativeWriteEngineState);
        Assert.Equal(NativeWriteValidationState.CanonicalImageValidated, payload.NativeWriteValidationState);
        Assert.True(payload.RecoveryActive);
        Assert.Equal("CommitTimedOut", payload.RecoveryReason);
        Assert.Equal((ulong)42, payload.LastCommitXid);
        Assert.Equal(NativeWriteSafetyState.PilotReadWrite, payload.NativeWriteSafetyState);
        Assert.Single(payload.WriteIncompatibilities!);
        Assert.Equal("ReplaySkippedFailClosed", payload.LastRecoveryAction);
        Assert.Equal(3, payload.DirtyTransactionCount);
        Assert.True(payload.ShutdownDrainActive);
        Assert.Equal(2, payload.InFlightMutationCallbacks);
        Assert.NotNull(payload.NativeWriteValidationEvidence);
        Assert.Equal(1, payload.NativeWriteValidationEvidence!.CrashFaultPasses);
        Assert.Equal(2, payload.NativeWriteValidationEvidence.CrashStageMatrixPasses);
        Assert.Equal(2, payload.NativeWriteValidationEvidence.HardwarePilotPasses);
        Assert.Equal(1, payload.NativeWriteValidationEvidence.HotUnplugPasses);
        Assert.Equal(1, payload.NativeWriteValidationEvidence.MacOsConsistencyPasses);
        Assert.Equal(1, payload.NativeWriteValidationEvidence.PowerLossReplayPasses);
        Assert.Equal("raw::physicaldrive3::main", payload.NativeWriteValidationEvidence.LastValidationProfileId);
        Assert.NotNull(payload.NativeWriteDiagnostics);
        Assert.Single(payload.NativeWriteDiagnostics!);
        Assert.Equal("NativeWriteValidationCrashFaultEvidenceInsufficient", payload.NativeWriteDiagnostics[0].Code);
        Assert.Equal("ValidationCrashFaultEvidenceInsufficient", payload.NativeWriteDiagnostics[0].RecoveryReason);
        Assert.Equal("CrashFault", payload.NativeWriteDiagnostics[0].ValidationScenario);
        Assert.Equal("snapshot-0001", payload.NativeWriteDiagnostics[0].EvidenceSnapshotId);
    }

    [Fact]
    public void SerializeAndDeserialize_RoundTripsRefreshRequestPayload()
    {
        var source = PipeMessageCodec.Create(
            ApfsMessageTypes.RefreshRequested,
            new RefreshRequestedPayload(
                Requester: "tester",
                TimestampUtc: DateTime.UtcNow,
                ClearUserEjectedVolumes: true),
            requestId: "refresh-1"
        );

        var json = PipeMessageCodec.Serialize(source);
        var success = PipeMessageCodec.TryDeserialize(json, out var deserialized);

        Assert.True(success);
        Assert.NotNull(deserialized);
        Assert.Equal(ApfsMessageTypes.RefreshRequested, deserialized!.Type);
        Assert.Equal("refresh-1", deserialized.RequestId);

        var payloadSuccess = PipeMessageCodec.TryGetPayload<RefreshRequestedPayload>(deserialized, out var payload);
        Assert.True(payloadSuccess);
        Assert.NotNull(payload);
        Assert.Equal("tester", payload!.Requester);
        Assert.True(payload.ClearUserEjectedVolumes);
    }

    [Fact]
    public void TryDeserialize_AcceptsUnknownTypeWithoutThrowing()
    {
        const string json = "{\"type\":\"SomeFutureMessage\",\"requestId\":\"abc\",\"payload\":{\"value\":123}}";

        var success = PipeMessageCodec.TryDeserialize(json, out var message);

        Assert.True(success);
        Assert.NotNull(message);
        Assert.Equal("SomeFutureMessage", message!.Type);
    }
}
