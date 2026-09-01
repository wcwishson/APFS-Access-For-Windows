using System.Text.Json;
using ApfsAccess.Core;
using ApfsAccess.Ipc;

namespace ApfsAccess.Ipc.Tests;

public sealed class PipeMessageCodecTests
{
    [Fact]
    public void AgentOperationContractsExposeAbsoluteExpiry()
    {
        Assert.NotNull(typeof(ControlOperationRequestPayload).GetProperty("ExpiresAtUtc"));
        Assert.NotNull(typeof(OperationResultPayload).GetProperty("ExpiresAtUtc"));
    }

    [Fact]
    public void StatusChanged_RoundTripsPerVolumeTruthFields()
    {
        var display = new MountedVolumeDisplay(
            "device-a|rw", "R:\\", "Writable", "device-a", "APFS device", MountAccessMode.ReadWrite,
            RecoveryIdentity: "rw-identity",
            State: RuntimeState.MountedRw,
            WriteEnabled: true,
            WriteBackend: "Native",
            CommitModel: NativeWriteCommitModel.CanonicalApfsCheckpoint,
            NativeWriteReadiness: NativeWriteReadiness.CommitReady,
            NativeWriteEngineState: NativeWriteEngineState.Transactional,
            NativeWriteValidationState: NativeWriteValidationState.HardwarePilotValidated,
            NativeWriteSafetyState: NativeWriteSafetyState.StableReadWrite,
            RecoveryActive: true,
            RecoveryReason: "rw-recovery",
            LastRecoveryAction: "rw-action",
            LastCommitXid: 123,
            WriteIncompatibilities: ["rw-incompatibility"],
            WriteUnsupportedFeatures: ["rw-unsupported"],
            DirtyTransactionCount: 1,
            ShutdownDrainActive: true,
            InFlightMutationCallbacks: 2,
            NativeWriteValidationEvidence: new NativeWriteValidationEvidence(CrashFaultPasses: 3),
            NativeWriteDiagnostics: [new NativeWriteDiagnostic("rw-validation", "rw diagnostic")],
            MountReady: true,
            HostProcessId: 4242,
            WalAcceptedSequence: 12,
            WalApfsDurableSequence: 10,
            WalCleanupSequence: 8,
            PendingDurability: true,
            HostOwnershipState: "owned");
        var source = PipeMessageCodec.Create(
            ApfsMessageTypes.StatusChanged,
            new StatusChangedPayload(
                RuntimeState.MountedRw, ["R:\\"], null, DateTime.UtcNow, [], true, [], [display]));

        var json = PipeMessageCodec.Serialize(source);
        Assert.True(PipeMessageCodec.TryDeserialize(json, out var envelope, out _, out var diagnostic), diagnostic);
        Assert.True(PipeMessageCodec.TryGetPayload<StatusChangedPayload>(envelope!, out var payload));
        var actual = Assert.Single(payload!.MountedVolumes!);

        Assert.Equal(JsonSerializer.Serialize(display), JsonSerializer.Serialize(actual));
    }

    [Fact]
    public void Inventory_RoundTripsVolumeRecoveryIdentity()
    {
        var source = PipeMessageCodec.Create(
            ApfsMessageTypes.Inventory,
            new InventoryPayload(
                [new DeviceInventory(
                    new DeviceInfo("device-a", "APFS device", true),
                    [new VolumeInfo("device-a|rw", "device-a", "Writable", true, RecoveryIdentity: "Case-Sensitive-ID")])],
                DateTime.UtcNow));

        var json = PipeMessageCodec.Serialize(source);
        Assert.True(PipeMessageCodec.TryDeserialize(json, out var envelope, out _, out var diagnostic), diagnostic);
        Assert.True(PipeMessageCodec.TryGetPayload<InventoryPayload>(envelope!, out var payload));

        Assert.Equal("Case-Sensitive-ID", Assert.Single(Assert.Single(payload!.Devices).Volumes).RecoveryIdentity);
    }

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
                ClearUserEjectedVolumes: true,
                VolumeId: @"\\.\PhysicalDrive3|Main"),
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
        Assert.Equal(@"\\.\PhysicalDrive3|Main", payload.VolumeId);
    }

    [Fact]
    public void SerializeAndDeserialize_RoundTripsServiceStoppingPayload()
    {
        var timestamp = DateTime.UtcNow;
        var source = PipeMessageCodec.Create(
            ApfsMessageTypes.ServiceStopping,
            new ServiceStoppingPayload(
                TimestampUtc: timestamp,
                CleanupCompleted: true,
                RemainingMountPoints: Array.Empty<string>(),
                HostOwnershipReleased: true,
                PendingDurabilityCleared: true),
            requestId: "stop-1");

        var success = PipeMessageCodec.TryDeserialize(
            PipeMessageCodec.Serialize(source),
            out var deserialized);

        Assert.True(success);
        Assert.NotNull(deserialized);
        Assert.Equal(ApfsMessageTypes.ServiceStopping, deserialized!.Type);
        Assert.Equal("stop-1", deserialized.RequestId);

        var payloadSuccess = PipeMessageCodec.TryGetPayload<ServiceStoppingPayload>(
            deserialized,
            out var payload);

        Assert.True(payloadSuccess);
        Assert.NotNull(payload);
        Assert.Equal(timestamp, payload!.TimestampUtc);
        Assert.True(payload.CleanupCompleted);
        Assert.Empty(payload.RemainingMountPoints!);
        Assert.True(payload.HostOwnershipReleased);
        Assert.True(payload.PendingDurabilityCleared);
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

    [Fact]
    public void TryDeserializeSyntaxOnly_AcceptsSemanticallyInvalidSchema2Envelope()
    {
        var json = Schema2Json(
            2,
            ApfsMessageTypes.ControlOperationRequest,
            "00000000-0000-0000-0000-000000000001",
            "{\"operationId\":\"00000000-0000-0000-0000-000000000001\",\"command\":\"mount\",\"target\":null}");

        var success = PipeMessageCodec.TryDeserializeSyntaxOnly(json, out var envelope);

        Assert.True(success);
        Assert.NotNull(envelope);
        Assert.False(PipeMessageCodec.Validate(envelope!).IsValid);
    }

    [Theory]
    [InlineData("")]
    [InlineData("{")]
    [InlineData("null")]
    [InlineData("{\"type\":\" \"}")]
    public void TryDeserializeSyntaxOnly_RejectsNonEnvelopeInput(string json)
    {
        var success = PipeMessageCodec.TryDeserializeSyntaxOnly(json, out var envelope);

        Assert.False(success);
        Assert.Null(envelope);
    }

    [Fact]
    public void TryDeserialize_RejectsMalformedJsonWithStableDiagnostic()
    {
        var success = PipeMessageCodec.TryDeserialize(
            "{\"schemaVersion\":2,\"type\":\"ControlOperationRequest\"",
            out var envelope,
            out var code,
            out var diagnostic);

        Assert.False(success);
        Assert.Null(envelope);
        Assert.Equal(ApfsOperationCodes.MalformedMessage, code);
        Assert.Contains("JSON", diagnostic, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void TryDeserialize_RejectsUnsupportedSchemaWithStableDiagnostic()
    {
        var success = PipeMessageCodec.TryDeserialize(
            Schema2Json(3, ApfsMessageTypes.ControlOperationRequest, "request-1", ValidRequestPayload()),
            out var envelope,
            out var code,
            out var diagnostic);

        Assert.False(success);
        Assert.Null(envelope);
        Assert.Equal(ApfsOperationCodes.UnsupportedSchema, code);
        Assert.Contains("schema", diagnostic, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void TryDeserialize_RejectsBlankSchema2RequestId()
    {
        var json = Schema2Json(2, ApfsMessageTypes.ControlOperationRequest, " ", ValidRequestPayload());

        var success = PipeMessageCodec.TryDeserialize(json, out _, out var code, out var diagnostic);

        Assert.False(success);
        Assert.Equal(ApfsOperationCodes.InvalidArguments, code);
        Assert.Contains("requestId", diagnostic, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void TryDeserialize_RejectsMalformedCallerOperationId()
    {
        var payload = "{\"operationId\":\"not-a-guid\",\"command\":\"mount\",\"target\":{" +
                       "\"deviceId\":\"dev-a\",\"volumeId\":\"dev-a|Main\"}}";

        var success = PipeMessageCodec.TryDeserialize(
            Schema2Json(2, ApfsMessageTypes.ControlOperationRequest, "00000000-0000-0000-0000-000000000009", payload),
            out _,
            out var code,
            out var diagnostic);

        Assert.False(success);
        Assert.Equal(ApfsOperationCodes.InvalidOperationId, code);
        Assert.Contains("operationId", diagnostic, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void TryDeserialize_RejectsUnknownCommand()
    {
        var payload = "{\"operationId\":\"00000000-0000-0000-0000-000000000005\",\"command\":\"format\",\"target\":{" +
                       "\"deviceId\":\"dev-a\",\"volumeId\":\"dev-a|Main\"}}";

        var success = PipeMessageCodec.TryDeserialize(
            Schema2Json(2, ApfsMessageTypes.ControlOperationRequest, "00000000-0000-0000-0000-000000000005", payload),
            out _,
            out var code,
            out var diagnostic);

        Assert.False(success);
        Assert.Equal(ApfsOperationCodes.UnknownCommand, code);
        Assert.Contains("command", diagnostic, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void TryDeserialize_RejectsMissingOrAmbiguousTarget()
    {
        var missingTarget = Schema2Json(
            2,
            ApfsMessageTypes.ControlOperationRequest,
            "00000000-0000-0000-0000-000000000001",
            "{\"operationId\":\"00000000-0000-0000-0000-000000000001\",\"command\":\"mount\",\"target\":null}");
        var ambiguousTarget = Schema2Json(
            2,
            ApfsMessageTypes.ControlOperationRequest,
            "00000000-0000-0000-0000-000000000002",
            "{\"operationId\":\"00000000-0000-0000-0000-000000000002\",\"command\":\"mount\",\"target\":{" +
            "\"deviceId\":\"dev-a\",\"driveLetter\":\"X:\"}}");

        AssertInvalidTarget(missingTarget);
        AssertInvalidTarget(ambiguousTarget);
    }

    [Fact]
    public void TryDeserialize_RejectsMismatchedDeviceAndVolume()
    {
        var payload = "{\"operationId\":\"00000000-0000-0000-0000-000000000003\",\"command\":\"eject\",\"target\":{" +
                       "\"deviceId\":\"dev-a\",\"volumeId\":\"dev-b|Main\"}}";

        var success = PipeMessageCodec.TryDeserialize(
            Schema2Json(2, ApfsMessageTypes.ControlOperationRequest, "00000000-0000-0000-0000-000000000003", payload),
            out _,
            out var code,
            out var diagnostic);

        Assert.False(success);
        Assert.Equal(ApfsOperationCodes.AmbiguousTarget, code);
        Assert.Contains("volumeId", diagnostic, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData(ApfsControlCommands.Mount)]
    [InlineData(ApfsControlCommands.Fix)]
    [InlineData(ApfsControlCommands.Eject)]
    public void Schema2ControlRequest_AcceptsExactTargetForMountFixAndEject(string command)
    {
        const string operationId = "00000000-0000-0000-0000-000000000006";
        var requestedMode = command == ApfsControlCommands.Mount
            ? $",\"requestedMode\":\"{ApfsControlModes.ReadWrite}\""
            : string.Empty;
        var payload = $"{{\"operationId\":\"00000000-0000-0000-0000-000000000006\",\"command\":\"{command}\",\"target\":{{" +
                       $"\"deviceId\":\"dev-a\",\"volumeId\":\"dev-a|Main\"}}{requestedMode}," +
                       "\"expiresAtUtc\":\"2026-08-28T23:59:59Z\"}";

        var success = PipeMessageCodec.TryDeserialize(
            Schema2Json(2, ApfsMessageTypes.ControlOperationRequest, operationId, payload),
            out var envelope,
            out var code,
            out var diagnostic);

        Assert.True(success, diagnostic);
        Assert.Equal(ApfsOperationCodes.OperationSucceeded, code);
        Assert.NotNull(envelope);
    }

    [Fact]
    public void Schema2ControlRequest_RejectsMissingAbsoluteExpiry()
    {
        const string operationId = "00000000-0000-0000-0000-000000000008";
        var payload = $"{{\"operationId\":\"{operationId}\",\"command\":\"mount\",\"target\":{{" +
                      "\"deviceId\":\"dev-a\",\"volumeId\":\"dev-a|Main\"},\"requestedMode\":\"read-write\"}";

        var success = PipeMessageCodec.TryDeserialize(
            Schema2Json(2, ApfsMessageTypes.ControlOperationRequest, operationId, payload),
            out _,
            out var code,
            out var diagnostic);

        Assert.False(success);
        Assert.Equal(ApfsOperationCodes.InvalidArguments, code);
        Assert.Contains("expiresAtUtc", diagnostic, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Schema2ControlRequest_AcceptsQuitWithoutTarget()
    {
        var payload = "{\"operationId\":\"00000000-0000-0000-0000-000000000007\",\"command\":\"quit\"," +
                      "\"expiresAtUtc\":\"2026-08-28T23:59:59Z\"}";

        var success = PipeMessageCodec.TryDeserialize(
            Schema2Json(2, ApfsMessageTypes.ControlOperationRequest, "00000000-0000-0000-0000-000000000007", payload),
            out var envelope,
            out var code,
            out var diagnostic);

        Assert.True(success, diagnostic);
        Assert.Equal(ApfsOperationCodes.OperationSucceeded, code);
        Assert.NotNull(envelope);
    }

    [Fact]
    public void TryDeserialize_RejectsTargetForQuit()
    {
        var payload = "{\"operationId\":\"00000000-0000-0000-0000-000000000004\",\"command\":\"quit\",\"target\":{" +
                       "\"deviceId\":\"dev-a\",\"volumeId\":\"dev-a|Main\"}}";

        var success = PipeMessageCodec.TryDeserialize(
            Schema2Json(2, ApfsMessageTypes.ControlOperationRequest, "00000000-0000-0000-0000-000000000004", payload),
            out _,
            out var code,
            out var diagnostic);

        Assert.False(success);
        Assert.Equal(ApfsOperationCodes.InvalidArguments, code);
        Assert.Contains("target", diagnostic, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Schema2ControlRequest_RoundTripsWithStableJsonNames()
    {
        var operationId = Guid.Parse("00000000-0000-0000-0000-000000000010");
        var source = PipeMessageCodec.Create(
            ApfsMessageTypes.ControlOperationRequest,
            new ControlOperationRequestPayload(
                OperationId: operationId.ToString("D"),
                Command: ApfsControlCommands.Mount,
                Target: new ApfsControlTarget(
                    DeviceId: "dev-a",
                    VolumeId: "dev-a|Main",
                    RecoveryIdentity: "apfs-recovery-v1|sample"),
                RequestedMode: ApfsControlModes.ReadWrite,
                ExpiresAtUtc: new DateTime(2026, 8, 28, 23, 59, 59, DateTimeKind.Utc)),
            requestId: operationId.ToString("D"),
            schemaVersion: PipeSchemaVersions.Schema2);

        var json = PipeMessageCodec.Serialize(source);
        var success = PipeMessageCodec.TryDeserialize(json, out var deserialized, out var code, out var diagnostic);

        Assert.True(success, diagnostic);
        Assert.Equal(ApfsOperationCodes.OperationSucceeded, code);
        Assert.Null(diagnostic);
        Assert.NotNull(deserialized);
        Assert.Equal(2, deserialized!.SchemaVersion);
        Assert.Contains("\"schemaVersion\":2", json, StringComparison.Ordinal);
        Assert.Contains("\"operationId\"", json, StringComparison.Ordinal);
        Assert.Contains("\"recoveryIdentity\"", json, StringComparison.Ordinal);
        Assert.Contains("\"expiresAtUtc\"", json, StringComparison.Ordinal);
        Assert.DoesNotContain("driveLetter", json, StringComparison.OrdinalIgnoreCase);

        Assert.True(PipeMessageCodec.TryGetPayload<ControlOperationRequestPayload>(deserialized, out var payload));
        Assert.NotNull(payload);
        Assert.Equal(operationId.ToString("D"), payload!.OperationId);
        Assert.Equal(ApfsControlCommands.Mount, payload.Command);
        Assert.Equal("dev-a", payload.Target!.DeviceId);
        Assert.Equal("dev-a|Main", payload.Target.VolumeId);
        Assert.Equal(ApfsControlModes.ReadWrite, payload.RequestedMode);
        Assert.Equal(new DateTime(2026, 8, 28, 23, 59, 59, DateTimeKind.Utc), payload.ExpiresAtUtc);
    }

    [Fact]
    public void Schema2ResultQuery_RoundTripsWithValidOperationId()
    {
        var operationId = Guid.NewGuid().ToString("D");
        var source = PipeMessageCodec.Create(
            ApfsMessageTypes.OperationResultQuery,
            new OperationResultQueryPayload(operationId),
            requestId: operationId,
            schemaVersion: PipeSchemaVersions.Schema2);

        var success = PipeMessageCodec.TryDeserialize(
            PipeMessageCodec.Serialize(source),
            out var envelope,
            out var code,
            out var diagnostic);

        Assert.True(success, diagnostic);
        Assert.Equal(ApfsOperationCodes.OperationSucceeded, code);
        Assert.NotNull(envelope);
        Assert.True(PipeMessageCodec.TryGetPayload<OperationResultQueryPayload>(envelope!, out var payload));
        Assert.Equal(operationId, payload!.OperationId);
    }

    [Fact]
    public void Schema2CancellationRequest_RoundTripsWithValidOperationId()
    {
        var operationId = Guid.NewGuid().ToString("D");
        var source = PipeMessageCodec.Create(
            ApfsMessageTypes.CancellationRequest,
            new OperationCancellationRequestPayload(operationId),
            requestId: operationId,
            schemaVersion: PipeSchemaVersions.Schema2);

        var success = PipeMessageCodec.TryDeserialize(
            PipeMessageCodec.Serialize(source),
            out var envelope,
            out var code,
            out var diagnostic);

        Assert.True(success, diagnostic);
        Assert.Equal(ApfsOperationCodes.OperationSucceeded, code);
        Assert.NotNull(envelope);
        Assert.True(PipeMessageCodec.TryGetPayload<OperationCancellationRequestPayload>(envelope!, out var payload));
        Assert.Equal(operationId, payload!.OperationId);
    }

    [Theory]
    [InlineData(ApfsMessageTypes.OperationResultQuery)]
    [InlineData(ApfsMessageTypes.CancellationRequest)]
    public void TryDeserialize_RejectsInvalidQueryAndCancellationOperationIds(string messageType)
    {
        var payload = "{\"operationId\":\"not-a-guid\"}";

        var success = PipeMessageCodec.TryDeserialize(
            Schema2Json(2, messageType, "00000000-0000-0000-0000-000000000099", payload),
            out _,
            out var code,
            out var diagnostic);

        Assert.False(success);
        Assert.Equal(ApfsOperationCodes.InvalidOperationId, code);
        Assert.Contains("operationId", diagnostic, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Schema2OperationResult_RoundTripsAllStableFields()
    {
        var requestedAt = new DateTime(2026, 8, 27, 1, 2, 3, DateTimeKind.Utc);
        var startedAt = requestedAt.AddSeconds(1);
        var completedAt = requestedAt.AddSeconds(2);
        var expiresAt = requestedAt.AddMinutes(1);
        var target = new ApfsControlTarget("dev-a", "dev-a|Main", "apfs-recovery-v1|sample");
        var source = PipeMessageCodec.Create(
            ApfsMessageTypes.OperationResult,
            new OperationResultPayload(
                OperationId: "00000000-0000-0000-0000-000000000020",
                Command: ApfsControlCommands.Mount,
                Target: target,
                Fingerprint: ApfsOperationFingerprint.Compute(
                    ApfsControlCommands.Mount,
                    target,
                    ApfsControlModes.ReadWrite,
                    expiresAt),
                State: ApfsOperationStates.Succeeded,
                Code: ApfsOperationCodes.OperationSucceeded,
                Success: true,
                RequestedAtUtc: requestedAt,
                StartedAtUtc: startedAt,
                CompletedAtUtc: completedAt,
                FinalStatus: "healthy-rw",
                EvidencePath: "D:\\evidence\\operation.json",
                RequestedMode: ApfsControlModes.ReadWrite,
                EffectiveMode: ApfsControlModes.ReadWrite,
                RecoveryState: "clean",
                RecoveryActive: false,
                DirtyTransactionCount: 0,
                PendingDurability: false,
                MountProof: "present",
                OwnershipProof: "not-applicable",
                DurabilityProof: "not-applicable",
                Diagnostic: null,
                ExpiresAtUtc: expiresAt),
            requestId: "00000000-0000-0000-0000-000000000020",
            schemaVersion: PipeSchemaVersions.Schema2);

        var json = PipeMessageCodec.Serialize(source);
        var success = PipeMessageCodec.TryDeserialize(json, out var envelope, out var code, out var diagnostic);

        Assert.True(success, diagnostic);
        Assert.Equal(ApfsOperationCodes.OperationSucceeded, code);
        Assert.Contains("\"finalStatus\"", json, StringComparison.Ordinal);
        Assert.Contains("\"evidencePath\"", json, StringComparison.Ordinal);
        Assert.Contains("\"requestedMode\"", json, StringComparison.Ordinal);
        Assert.Contains("\"effectiveMode\"", json, StringComparison.Ordinal);
        Assert.Contains("\"recoveryState\"", json, StringComparison.Ordinal);
        Assert.Contains("\"dirtyTransactionCount\"", json, StringComparison.Ordinal);
        Assert.Contains("\"mountProof\"", json, StringComparison.Ordinal);
        Assert.Contains("\"ownershipProof\"", json, StringComparison.Ordinal);
        Assert.Contains("\"durabilityProof\"", json, StringComparison.Ordinal);
        Assert.Contains("\"expiresAtUtc\"", json, StringComparison.Ordinal);
        Assert.DoesNotContain("\"OperationId\"", json, StringComparison.Ordinal);

        Assert.True(PipeMessageCodec.TryGetPayload<OperationResultPayload>(envelope!, out var payload));
        Assert.NotNull(payload);
        Assert.Equal("00000000-0000-0000-0000-000000000020", payload!.OperationId);
        Assert.Equal(ApfsOperationStates.Succeeded, payload.State);
        Assert.Equal("healthy-rw", payload.FinalStatus);
        Assert.Equal(ApfsControlModes.ReadWrite, payload.EffectiveMode);
        Assert.Equal("not-applicable", payload.DurabilityProof);
        Assert.Equal(requestedAt.AddMinutes(1), payload.ExpiresAtUtc);
    }

    [Fact]
    public void Schema1Envelope_DefaultsToOneAndUnknownTypesRemainForwardCompatible()
    {
        var legacy = PipeMessageCodec.Create(
            ApfsMessageTypes.Ping,
            new PingPayload(DateTime.UtcNow),
            requestId: "legacy-1");

        Assert.Equal(PipeSchemaVersions.Schema1, legacy.SchemaVersion);
        Assert.True(PipeMessageCodec.TryDeserialize(PipeMessageCodec.Serialize(legacy), out var legacyEnvelope));
        Assert.Equal(PipeSchemaVersions.Schema1, legacyEnvelope!.SchemaVersion);

        const string futureSchema1 = "{\"type\":\"SomeFutureMessage\",\"requestId\":\"\",\"payload\":{\"driveLetter\":\"X:\"}}";
        var success = PipeMessageCodec.TryDeserialize(futureSchema1, out var futureEnvelope, out var code, out var diagnostic);

        Assert.True(success, diagnostic);
        Assert.Equal(PipeSchemaVersions.Schema1, futureEnvelope!.SchemaVersion);
        Assert.Equal(ApfsOperationCodes.OperationSucceeded, code);
    }

    [Fact]
    public void ResultCodes_ExposeStableWireValues()
    {
        Assert.Equal("ambiguous-target", ApfsOperationCodes.AmbiguousTarget);
        Assert.Equal("elevation-failed", ApfsOperationCodes.ElevationFailed);
        Assert.Equal("operation-conflict", ApfsOperationCodes.OperationConflict);
        Assert.Equal("operation-in-progress", ApfsOperationCodes.OperationInProgress);
        Assert.Equal("operation-cancelled", ApfsOperationCodes.OperationCancelled);
        Assert.Equal("not-cancellable", ApfsOperationCodes.NotCancellable);
        Assert.Equal("service-unavailable", ApfsOperationCodes.ServiceUnavailable);
    }

    private static string ValidRequestPayload()
        => "{\"operationId\":\"00000000-0000-0000-0000-000000000001\",\"command\":\"mount\",\"target\":{" +
           "\"deviceId\":\"dev-a\",\"volumeId\":\"dev-a|Main\"},\"requestedMode\":\"read-write\"}";

    private static string Schema2Json(int schemaVersion, string type, string requestId, string payload)
        => $"{{\"schemaVersion\":{schemaVersion},\"type\":{JsonSerializer.Serialize(type)},\"requestId\":{JsonSerializer.Serialize(requestId)},\"payload\":{payload}}}";

    private static void AssertInvalidTarget(string json)
    {
        var success = PipeMessageCodec.TryDeserialize(json, out _, out var code, out var diagnostic);

        Assert.False(success);
        Assert.Equal(ApfsOperationCodes.AmbiguousTarget, code);
        Assert.Contains("target", diagnostic, StringComparison.OrdinalIgnoreCase);
    }
}
