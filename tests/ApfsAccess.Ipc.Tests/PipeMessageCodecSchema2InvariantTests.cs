using System.Text.Json.Nodes;
using ApfsAccess.Ipc;

namespace ApfsAccess.Ipc.Tests;

public sealed class PipeMessageCodecSchema2InvariantTests
{
    private const string OperationId = "00000000-0000-0000-0000-000000000101";
    private const string OtherOperationId = "00000000-0000-0000-0000-000000000102";

    [Fact]
    public void OperationFingerprint_NormalizesIdentityAndBindsAbsoluteExpiry()
    {
        var expiresAtUtc = new DateTime(2026, 8, 27, 1, 1, 0, DateTimeKind.Utc);

        var fingerprint = ApfsOperationFingerprint.Compute(
            " MOUNT ",
            new ApfsControlTarget(" DEV-A ", " DEV-A|MAIN ", " Opaque-Identity "),
            "RW",
            expiresAtUtc);

        Assert.Equal(
            "sha256:5f62b3db01f87e6d590662ad55814e67b5b73a7542c29201aef2f81bc5181bc0",
            fingerprint);
        Assert.NotEqual(
            fingerprint,
            ApfsOperationFingerprint.Compute(
                ApfsControlCommands.Mount,
                new ApfsControlTarget("dev-a", "dev-a|main", "Opaque-Identity"),
                ApfsControlModes.ReadWrite,
                expiresAtUtc.AddTicks(1)));
    }

    [Theory]
    [InlineData(ApfsMessageTypes.ControlOperationRequest, "00000000-0000-0000-0000-00000000010A", "00000000-0000-0000-0000-00000000010A")]
    [InlineData(ApfsMessageTypes.ControlOperationRequest, OperationId, OtherOperationId)]
    [InlineData(ApfsMessageTypes.OperationResultQuery, "{00000000-0000-0000-0000-000000000101}", "{00000000-0000-0000-0000-000000000101}")]
    [InlineData(ApfsMessageTypes.CancellationRequest, OperationId, OtherOperationId)]
    public void Schema2Request_RejectsNoncanonicalOrMismatchedOperationIdentity(
        string messageType,
        string payloadOperationId,
        string envelopeRequestId)
    {
        object payload = messageType switch
        {
            ApfsMessageTypes.ControlOperationRequest => new ControlOperationRequestPayload(
                payloadOperationId,
                ApfsControlCommands.Mount,
                new ApfsControlTarget("dev-a", "dev-a|Main"),
                ApfsControlModes.ReadWrite),
            ApfsMessageTypes.OperationResultQuery => new OperationResultQueryPayload(payloadOperationId),
            _ => new OperationCancellationRequestPayload(payloadOperationId),
        };
        var envelope = PipeMessageCodec.Create(messageType, payload, envelopeRequestId, PipeSchemaVersions.Schema2);

        var validation = PipeMessageCodec.Validate(envelope);

        Assert.False(validation.IsValid);
        Assert.Equal(ApfsOperationCodes.InvalidOperationId, validation.Code);
    }

    [Theory]
    [InlineData(ApfsControlCommands.Mount, null)]
    [InlineData(ApfsControlCommands.Mount, "READ-WRITE")]
    [InlineData(ApfsControlCommands.Fix, ApfsControlModes.ReadWrite)]
    [InlineData(ApfsControlCommands.Eject, ApfsControlModes.ReadOnly)]
    [InlineData(ApfsControlCommands.Quit, ApfsControlModes.ReadWrite)]
    public void Schema2ControlRequest_RejectsInvalidCommandModeCombination(string command, string? requestedMode)
    {
        var target = command == ApfsControlCommands.Quit
            ? null
            : new ApfsControlTarget("dev-a", "dev-a|Main");
        var envelope = PipeMessageCodec.Create(
            ApfsMessageTypes.ControlOperationRequest,
            new ControlOperationRequestPayload(OperationId, command, target, requestedMode),
            OperationId,
            PipeSchemaVersions.Schema2);

        var validation = PipeMessageCodec.Validate(envelope);

        Assert.False(validation.IsValid);
        Assert.Equal(ApfsOperationCodes.InvalidArguments, validation.Code);
    }

    [Theory]
    [InlineData(ApfsOperationStates.Failed, ApfsOperationCodes.OperationSucceeded, true)]
    [InlineData(ApfsOperationStates.Succeeded, ApfsOperationCodes.OperationFailed, false)]
    [InlineData(ApfsOperationStates.Cancelled, ApfsOperationCodes.OperationCancelled, true)]
    public void Schema2OperationResult_RejectsContradictoryTerminalStateCodeAndSuccess(
        string state,
        string code,
        bool success)
    {
        var envelope = ResultEnvelope(ValidMountResult() with
        {
            State = state,
            Code = code,
            Success = success,
        });

        var validation = PipeMessageCodec.Validate(envelope);

        Assert.False(validation.IsValid);
        Assert.Equal(ApfsOperationCodes.MalformedMessage, validation.Code);
    }

    [Fact]
    public void Schema2OperationResult_RejectsMissingOrOutOfOrderTerminalTimestamps()
    {
        var valid = ValidMountResult();
        var invalidResults = new[]
        {
            valid with { StartedAtUtc = valid.RequestedAtUtc.AddSeconds(-1) },
            valid with { CompletedAtUtc = valid.StartedAtUtc!.Value.AddSeconds(-1) },
            valid with { CompletedAtUtc = null },
        };

        foreach (var result in invalidResults)
        {
            var validation = PipeMessageCodec.Validate(ResultEnvelope(result));
            Assert.False(validation.IsValid);
            Assert.Equal(ApfsOperationCodes.MalformedMessage, validation.Code);
        }
    }

    [Fact]
    public void Schema2OperationResult_RequiresAbsoluteUtcExpiryForContextualResults()
    {
        var valid = ValidMountResult();

        Assert.False(PipeMessageCodec.Validate(ResultEnvelope(valid with { ExpiresAtUtc = null })).IsValid);
        Assert.False(PipeMessageCodec.Validate(ResultEnvelope(valid with
        {
            ExpiresAtUtc = DateTime.SpecifyKind(valid.ExpiresAtUtc!.Value, DateTimeKind.Unspecified),
        })).IsValid);
        Assert.True(PipeMessageCodec.Validate(ResultEnvelope(valid)).IsValid);
    }

    [Fact]
    public void Schema2OperationResult_RejectsMissingMismatchedOrExpiryStaleFingerprint()
    {
        var valid = ValidMountResult();
        var invalidResults = new[]
        {
            valid with { Fingerprint = null },
            valid with { Fingerprint = "sha256:0000000000000000000000000000000000000000000000000000000000000000" },
            valid with { ExpiresAtUtc = valid.ExpiresAtUtc!.Value.AddTicks(1) },
        };

        foreach (var result in invalidResults)
        {
            var validation = PipeMessageCodec.Validate(ResultEnvelope(result));
            Assert.False(validation.IsValid);
            Assert.Equal(ApfsOperationCodes.MalformedMessage, validation.Code);
        }
    }

    [Theory]
    [InlineData(ApfsOperationStates.Accepted)]
    [InlineData(ApfsOperationStates.InProgress)]
    public void Schema2ContextualNonterminalResult_RequiresConservativeProof(string state)
    {
        var terminal = ValidMountResult();
        var valid = terminal with
        {
            State = state,
            Code = ApfsOperationCodes.OperationInProgress,
            Success = false,
            StartedAtUtc = state == ApfsOperationStates.InProgress ? terminal.RequestedAtUtc : null,
            CompletedAtUtc = null,
            FinalStatus = "not-proven",
            EffectiveMode = null,
            RecoveryState = "not-proven",
            PendingDurability = true,
            MountProof = "not-proven",
            OwnershipProof = "not-proven",
            DurabilityProof = "not-proven",
        };
        var invalidResults = new[]
        {
            valid with { PendingDurability = false },
            valid with { FinalStatus = null },
            valid with { MountProof = null },
            valid with { OwnershipProof = null },
            valid with { DurabilityProof = null },
        };

        Assert.True(PipeMessageCodec.Validate(ResultEnvelope(valid)).IsValid);
        foreach (var result in invalidResults)
        {
            var validation = PipeMessageCodec.Validate(ResultEnvelope(result));
            Assert.False(validation.IsValid);
            Assert.Equal(ApfsOperationCodes.MalformedMessage, validation.Code);
        }
    }

    [Fact]
    public void Schema2TimeoutResult_RequiresConservativeUnreconciledProof()
    {
        var terminal = ValidMountResult();
        var valid = terminal with
        {
            State = ApfsOperationStates.Failed,
            Code = ApfsOperationCodes.Timeout,
            Success = false,
            FinalStatus = "not-proven",
            EffectiveMode = null,
            RecoveryState = "not-proven",
            PendingDurability = true,
            MountProof = "not-proven",
            OwnershipProof = "not-proven",
            DurabilityProof = "not-proven",
        };
        var invalidResults = new[]
        {
            valid with { PendingDurability = false },
            valid with { FinalStatus = null },
            valid with { MountProof = null },
            valid with { OwnershipProof = null },
            valid with { DurabilityProof = null },
        };

        Assert.True(PipeMessageCodec.Validate(ResultEnvelope(valid)).IsValid);
        foreach (var result in invalidResults)
        {
            var validation = PipeMessageCodec.Validate(ResultEnvelope(result));
            Assert.False(validation.IsValid);
            Assert.Equal(ApfsOperationCodes.MalformedMessage, validation.Code);
        }
    }

    [Fact]
    public void Schema2MountSuccess_RejectsModeDowngradePendingDurabilityAndMissingProofs()
    {
        var valid = ValidMountResult();
        var invalidResults = new[]
        {
            valid with { EffectiveMode = ApfsControlModes.ReadOnly },
            valid with { PendingDurability = true },
            valid with { MountProof = null },
            valid with { OwnershipProof = null },
            valid with { DurabilityProof = null },
        };

        foreach (var result in invalidResults)
        {
            var validation = PipeMessageCodec.Validate(ResultEnvelope(result));
            Assert.False(validation.IsValid);
            Assert.Equal(ApfsOperationCodes.MalformedMessage, validation.Code);
        }
    }

    [Fact]
    public void Schema2EjectAndQuitSuccess_RequireCommandSpecificTerminalProof()
    {
        var valid = ValidMountResult();
        var ejectWithoutOwnership = valid with
        {
            Command = ApfsControlCommands.Eject,
            RequestedMode = null,
            EffectiveMode = ApfsControlModes.ReadWrite,
            FinalStatus = "absent",
            MountProof = "absent",
            OwnershipProof = "not-proven",
            DurabilityProof = "proven",
        };
        ejectWithoutOwnership = ejectWithoutOwnership with
        {
            Fingerprint = ApfsOperationFingerprint.Compute(
                ejectWithoutOwnership.Command,
                ejectWithoutOwnership.Target,
                ejectWithoutOwnership.RequestedMode,
                ejectWithoutOwnership.ExpiresAtUtc!.Value),
        };
        var quitWithoutMarker = valid with
        {
            Command = ApfsControlCommands.Quit,
            Target = null,
            RequestedMode = null,
            EffectiveMode = null,
            FinalStatus = "shutdown-complete",
            MountProof = "no-mounts",
            OwnershipProof = "proven",
            DurabilityProof = "proven",
            QuitMarkerWritten = false,
        };
        quitWithoutMarker = quitWithoutMarker with
        {
            Fingerprint = ApfsOperationFingerprint.Compute(
                quitWithoutMarker.Command,
                quitWithoutMarker.Target,
                quitWithoutMarker.RequestedMode,
                quitWithoutMarker.ExpiresAtUtc!.Value),
        };

        Assert.False(PipeMessageCodec.Validate(ResultEnvelope(ejectWithoutOwnership)).IsValid);
        Assert.False(PipeMessageCodec.Validate(ResultEnvelope(quitWithoutMarker)).IsValid);
    }

    [Fact]
    public void Schema2AlreadyAchievedEject_RemainsAValidIdempotentTerminalResult()
    {
        var result = ValidMountResult() with
        {
            Command = ApfsControlCommands.Eject,
            RequestedMode = null,
            EffectiveMode = null,
            Code = ApfsOperationCodes.AlreadyAchieved,
            FinalStatus = "absent",
            MountProof = "absent",
            OwnershipProof = "not-proven",
            DurabilityProof = "not-proven",
        };
        result = result with
        {
            Fingerprint = ApfsOperationFingerprint.Compute(
                result.Command,
                result.Target,
                result.RequestedMode,
                result.ExpiresAtUtc!.Value),
        };

        var validation = PipeMessageCodec.Validate(ResultEnvelope(result));

        Assert.True(validation.IsValid, validation.Diagnostic);
    }

    [Fact]
    public void Schema2PreAdmissionFailure_AllowsMissingTargetAndRequestedMode()
    {
        var result = ValidMountResult() with
        {
            Target = null,
            Fingerprint = ApfsOperationFingerprint.Compute(
                ApfsControlCommands.Mount,
                target: null,
                requestedMode: null,
                ValidMountResult().ExpiresAtUtc!.Value),
            State = ApfsOperationStates.Failed,
            Code = ApfsOperationCodes.AmbiguousTarget,
            Success = false,
            RequestedMode = null,
            EffectiveMode = null,
            FinalStatus = null,
            RecoveryState = null,
            MountProof = null,
            OwnershipProof = null,
            DurabilityProof = null,
        };

        var validation = PipeMessageCodec.Validate(ResultEnvelope(result));

        Assert.True(validation.IsValid, validation.Diagnostic);
        Assert.False(PipeMessageCodec.Validate(ResultEnvelope(result with
        {
            Fingerprint = "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        })).IsValid);
    }

    [Fact]
    public void Schema2OperationResult_AllowsUnknownOptionalDiagnosticsWhenCoreFieldsStayConsistent()
    {
        var envelope = ResultEnvelope(ValidMountResult());
        envelope.Payload!["futureDiagnostic"] = new JsonObject
        {
            ["name"] = "forward-compatible",
            ["value"] = 42,
        };

        var validation = PipeMessageCodec.Validate(envelope);

        Assert.True(validation.IsValid, validation.Diagnostic);
    }

    [Fact]
    public void Schema2OperationResult_AllowsTruthfulContextlessUnknownFailure()
    {
        var now = new DateTime(2026, 8, 28, 1, 0, 0, DateTimeKind.Utc);
        var result = new OperationResultPayload(
            OperationId,
            ApfsControlCommands.Unknown,
            Target: null,
            Fingerprint: null,
            State: ApfsOperationStates.Failed,
            Code: ApfsOperationCodes.OperationFailed,
            Success: false,
            RequestedAtUtc: now,
            StartedAtUtc: now,
            CompletedAtUtc: now,
            RequestedMode: null,
            Diagnostic: "No operation context is available.");

        var validation = PipeMessageCodec.Validate(ResultEnvelope(result));

        Assert.True(validation.IsValid, validation.Diagnostic);
        Assert.False(PipeMessageCodec.Validate(ResultEnvelope(result with
        {
            Fingerprint = "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        })).IsValid);
    }

    [Fact]
    public void Schema2ControlRequest_RejectsUnknownCommand()
    {
        var request = PipeMessageCodec.Create(
            ApfsMessageTypes.ControlOperationRequest,
            new ControlOperationRequestPayload(OperationId, ApfsControlCommands.Unknown, Target: null),
            OperationId,
            PipeSchemaVersions.Schema2);

        var validation = PipeMessageCodec.Validate(request);

        Assert.False(validation.IsValid);
        Assert.Equal(ApfsOperationCodes.UnknownCommand, validation.Code);
    }

    [Theory]
    [InlineData(true, false, false)]
    [InlineData(false, true, false)]
    [InlineData(false, false, true)]
    public void Schema2OperationResult_RejectsUnknownWhenSuccessfulTargetedOrModeful(
        bool success,
        bool hasTarget,
        bool hasRequestedMode)
    {
        var now = new DateTime(2026, 8, 28, 1, 0, 0, DateTimeKind.Utc);
        var result = new OperationResultPayload(
            OperationId,
            ApfsControlCommands.Unknown,
            hasTarget ? new ApfsControlTarget("dev-a", "dev-a|Main") : null,
            Fingerprint: null,
            State: success ? ApfsOperationStates.Succeeded : ApfsOperationStates.Failed,
            Code: success ? ApfsOperationCodes.OperationSucceeded : ApfsOperationCodes.OperationFailed,
            Success: success,
            RequestedAtUtc: now,
            StartedAtUtc: now,
            CompletedAtUtc: now,
            FinalStatus: success ? "complete" : null,
            RequestedMode: hasRequestedMode ? ApfsControlModes.ReadOnly : null);

        var validation = PipeMessageCodec.Validate(ResultEnvelope(result));

        Assert.False(validation.IsValid);
    }

    private static PipeEnvelope ResultEnvelope(OperationResultPayload result)
        => PipeMessageCodec.Create(
            ApfsMessageTypes.OperationResult,
            result,
            result.OperationId,
            PipeSchemaVersions.Schema2);

    private static OperationResultPayload ValidMountResult()
    {
        var requestedAt = new DateTime(2026, 8, 27, 1, 0, 0, DateTimeKind.Utc);
        var expiresAtUtc = requestedAt.AddMinutes(1);
        var target = new ApfsControlTarget("dev-a", "dev-a|Main", "Opaque-Identity");
        return new OperationResultPayload(
            OperationId,
            ApfsControlCommands.Mount,
            target,
            Fingerprint: ApfsOperationFingerprint.Compute(
                ApfsControlCommands.Mount,
                target,
                ApfsControlModes.ReadWrite,
                expiresAtUtc),
            State: ApfsOperationStates.Succeeded,
            Code: ApfsOperationCodes.OperationSucceeded,
            Success: true,
            RequestedAtUtc: requestedAt,
            StartedAtUtc: requestedAt.AddSeconds(1),
            CompletedAtUtc: requestedAt.AddSeconds(2),
            FinalStatus: "healthy-rw",
            RequestedMode: ApfsControlModes.ReadWrite,
            EffectiveMode: ApfsControlModes.ReadWrite,
            RecoveryState: "clean",
            RecoveryActive: false,
            DirtyTransactionCount: 0,
            PendingDurability: false,
            MountProof: "present",
            OwnershipProof: "not-applicable",
            DurabilityProof: "not-applicable",
            ExpiresAtUtc: expiresAtUtc);
    }
}
