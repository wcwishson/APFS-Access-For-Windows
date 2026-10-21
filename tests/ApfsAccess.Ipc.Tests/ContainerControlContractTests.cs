using ApfsAccess.Core;
using ApfsAccess.Ipc;

namespace ApfsAccess.Ipc.Tests;

// Task 12 Step 5: container-wide mount/unmount envelope contract. Container
// targets carry deviceId plus containerUuid and never a volumeId; membership
// is resolved against live inventory downstream, so the envelope pins shape,
// mode, fingerprint binding, and terminal proofs only.
public sealed class ContainerControlContractTests
{
    private static readonly string OperationId = Guid.NewGuid().ToString("D");
    private static readonly string ContainerUuid = new('a', 32);
    private static readonly ApfsControlTarget Target = new("device-1", string.Empty, null, null, ContainerUuid);
    private static readonly ApfsControlTarget DeviceTarget = new("device-1", string.Empty);
    private static readonly DateTime Expiry = new(2026, 9, 17, 12, 0, 0, DateTimeKind.Utc);

    [Fact]
    public void Fingerprint_BindsContainerUuidAndIgnoresOperationId()
    {
        var first = new ControlOperationRequestPayload(
            OperationId, ApfsControlCommands.ContainerMount, Target, ApfsControlModes.ReadWrite, Expiry);
        Assert.Equal(
            ApfsOperationFingerprint.Compute(first),
            ApfsOperationFingerprint.Compute(first with { OperationId = Guid.NewGuid().ToString("D") }));
        Assert.NotEqual(
            ApfsOperationFingerprint.Compute(first),
            ApfsOperationFingerprint.Compute(first with
            {
                Target = Target with { ContainerUuid = new string('b', 32) },
            }));
        Assert.NotEqual(
            ApfsOperationFingerprint.Compute(first),
            ApfsOperationFingerprint.Compute(first with { Command = ApfsControlCommands.ContainerUnmount }));
    }

    [Theory]
    [InlineData(ApfsControlCommands.ContainerMount)]
    [InlineData(ApfsControlCommands.ContainerUnmount)]
    public void RequestEnvelope_AcceptsWellFormedContainerCommands(string command)
    {
        var request = ContainerRequest(command);
        var envelope = PipeMessageCodec.Create(ApfsMessageTypes.ControlOperationRequest, request, OperationId, PipeSchemaVersions.Schema2);
        var validation = PipeMessageCodec.Validate(envelope);
        Assert.True(validation.IsValid, validation.Diagnostic);
    }

    [Fact]
    public void RequestEnvelope_RejectsVolumeTargetsModeGapsAndModeLeaks()
    {
        var mount = ContainerRequest(ApfsControlCommands.ContainerMount);
        Assert.Equal(ApfsOperationCodes.AmbiguousTarget, ValidateRequest(mount with
        {
            Target = new ApfsControlTarget("device-1", "device-1|Main", null, null, ContainerUuid),
        }).Code);
        Assert.Equal(ApfsOperationCodes.AmbiguousTarget, ValidateRequest(mount with
        {
            Target = new ApfsControlTarget("device-1", string.Empty),
        }).Code);
        Assert.Equal(ApfsOperationCodes.InvalidArguments, ValidateRequest(mount with
        {
            RequestedMode = null,
        }).Code);
        var unmount = ContainerRequest(ApfsControlCommands.ContainerUnmount);
        Assert.Equal(ApfsOperationCodes.InvalidArguments, ValidateRequest(unmount with
        {
            RequestedMode = ApfsControlModes.ReadWrite,
        }).Code);
    }

    [Theory]
    [InlineData(ApfsControlCommands.ContainerMount, "container-mounted")]
    [InlineData(ApfsControlCommands.ContainerUnmount, "container-unmounted")]
    public void ResultEnvelope_AcceptsProvenContainerTerminals(string command, string finalStatus)
    {
        var request = ContainerRequest(command);
        var now = DateTime.UtcNow;
        var result = command == ApfsControlCommands.ContainerMount
            ? new OperationResultPayload(
                request.OperationId, command, request.Target,
                ApfsOperationFingerprint.Compute(request),
                ApfsOperationStates.Succeeded, ApfsOperationCodes.OperationSucceeded, true,
                now.AddSeconds(-1), now, now,
                FinalStatus: finalStatus, RequestedMode: request.RequestedMode,
                EffectiveMode: request.RequestedMode,
                MountProof: "present", OwnershipProof: "not-applicable",
                DurabilityProof: "not-applicable", ExpiresAtUtc: request.ExpiresAtUtc)
            : new OperationResultPayload(
                request.OperationId, command, request.Target,
                ApfsOperationFingerprint.Compute(request),
                ApfsOperationStates.Succeeded, ApfsOperationCodes.OperationSucceeded, true,
                now.AddSeconds(-1), now, now,
                FinalStatus: finalStatus,
                MountProof: "absent", OwnershipProof: "proven",
                DurabilityProof: "proven", ExpiresAtUtc: request.ExpiresAtUtc);
        var envelope = PipeMessageCodec.Create(ApfsMessageTypes.OperationResult, result, request.OperationId, PipeSchemaVersions.Schema2);
        var validation = PipeMessageCodec.Validate(envelope);
        Assert.True(validation.IsValid, validation.Diagnostic);
    }

    [Fact]
    public void ResultEnvelope_RejectsUnprovenContainerTerminals()
    {
        var request = ContainerRequest(ApfsControlCommands.ContainerMount);
        var now = DateTime.UtcNow;
        var modeMismatch = new OperationResultPayload(
            request.OperationId, request.Command, request.Target,
            ApfsOperationFingerprint.Compute(request),
            ApfsOperationStates.Succeeded, ApfsOperationCodes.OperationSucceeded, true,
            now.AddSeconds(-1), now, now,
            FinalStatus: "container-mounted", RequestedMode: ApfsControlModes.ReadWrite,
            EffectiveMode: ApfsControlModes.ReadOnly,
            MountProof: "present", OwnershipProof: "not-applicable",
            DurabilityProof: "not-applicable", ExpiresAtUtc: request.ExpiresAtUtc);
        Assert.Equal(ApfsOperationCodes.MalformedMessage, ValidateResult(modeMismatch).Code);
        var unmount = ContainerRequest(ApfsControlCommands.ContainerUnmount);
        var unproven = new OperationResultPayload(
            unmount.OperationId, unmount.Command, unmount.Target,
            ApfsOperationFingerprint.Compute(unmount),
            ApfsOperationStates.Succeeded, ApfsOperationCodes.OperationSucceeded, true,
            now.AddSeconds(-1), now, now,
            FinalStatus: "container-unmounted",
            MountProof: "absent", OwnershipProof: "not-proven",
            DurabilityProof: "proven", ExpiresAtUtc: unmount.ExpiresAtUtc);
        Assert.Equal(ApfsOperationCodes.MalformedMessage, ValidateResult(unproven).Code);
    }

    [Fact]
    public void ResultEnvelope_AcceptsContainerUnmountAlreadyAchieved()
    {
        var request = ContainerRequest(ApfsControlCommands.ContainerUnmount);
        var now = DateTime.UtcNow;
        var result = new OperationResultPayload(
            request.OperationId, request.Command, request.Target,
            ApfsOperationFingerprint.Compute(request),
            ApfsOperationStates.Succeeded, ApfsOperationCodes.AlreadyAchieved, true,
            now.AddSeconds(-1), now, now,
            FinalStatus: "container-unmounted",
            MountProof: "absent", OwnershipProof: "not-proven",
            DurabilityProof: "not-proven", ExpiresAtUtc: request.ExpiresAtUtc);
        var envelope = PipeMessageCodec.Create(ApfsMessageTypes.OperationResult, result, request.OperationId, PipeSchemaVersions.Schema2);
        var validation = PipeMessageCodec.Validate(envelope);
        Assert.True(validation.IsValid, validation.Diagnostic);
    }

    private static ControlOperationRequestPayload ContainerRequest(string command)
        => command == ApfsControlCommands.ContainerMount
            ? new ControlOperationRequestPayload(
                OperationId, command, Target, ApfsControlModes.ReadWrite, Expiry)
            : new ControlOperationRequestPayload(
                OperationId, command, Target, ExpiresAtUtc: Expiry);

    private static PipeMessageValidationResult ValidateRequest(ControlOperationRequestPayload request)
        => PipeMessageCodec.Validate(PipeMessageCodec.Create(
            ApfsMessageTypes.ControlOperationRequest, request, OperationId, PipeSchemaVersions.Schema2));

    private static PipeMessageValidationResult ValidateResult(OperationResultPayload result)
        => PipeMessageCodec.Validate(PipeMessageCodec.Create(
            ApfsMessageTypes.OperationResult, result, result.OperationId, PipeSchemaVersions.Schema2));

    [Fact]
    public void Fingerprint_BindsDeviceTarget()
    {
        var first = new ControlOperationRequestPayload(
            OperationId, ApfsControlCommands.DeviceEject, DeviceTarget, ExpiresAtUtc: Expiry);
        Assert.Equal(
            ApfsOperationFingerprint.Compute(first),
            ApfsOperationFingerprint.Compute(first with { OperationId = Guid.NewGuid().ToString("D") }));
        Assert.NotEqual(
            ApfsOperationFingerprint.Compute(first),
            ApfsOperationFingerprint.Compute(first with
            {
                Target = DeviceTarget with { DeviceId = "device-2" },
            }));
    }

    [Fact]
    public void RequestEnvelope_AcceptsWellFormedDeviceEject()
    {
        var request = new ControlOperationRequestPayload(
            OperationId, ApfsControlCommands.DeviceEject, DeviceTarget, ExpiresAtUtc: Expiry);
        var envelope = PipeMessageCodec.Create(ApfsMessageTypes.ControlOperationRequest, request, OperationId, PipeSchemaVersions.Schema2);
        var validation = PipeMessageCodec.Validate(envelope);
        Assert.True(validation.IsValid, validation.Diagnostic);
    }

    [Fact]
    public void RequestEnvelope_RejectsScopedDeviceTargets()
    {
        var volume = new ControlOperationRequestPayload(
            OperationId, ApfsControlCommands.DeviceEject,
            new ApfsControlTarget("device-1", "device-1|Main"), ExpiresAtUtc: Expiry);
        Assert.Equal(ApfsOperationCodes.AmbiguousTarget, ValidateRequest(volume).Code);
        var container = new ControlOperationRequestPayload(
            OperationId, ApfsControlCommands.DeviceEject, Target, ExpiresAtUtc: Expiry);
        Assert.Equal(ApfsOperationCodes.AmbiguousTarget, ValidateRequest(container).Code);
        var modeless = new ControlOperationRequestPayload(
            OperationId, ApfsControlCommands.DeviceEject, DeviceTarget,
            RequestedMode: ApfsControlModes.ReadWrite, ExpiresAtUtc: Expiry);
        Assert.Equal(ApfsOperationCodes.InvalidArguments, ValidateRequest(modeless).Code);
    }

    [Theory]
    [InlineData("device-ejected")]
    public void ResultEnvelope_AcceptsProvenDeviceTerminals(string finalStatus)
    {
        var request = new ControlOperationRequestPayload(
            OperationId, ApfsControlCommands.DeviceEject, DeviceTarget, ExpiresAtUtc: Expiry);
        var now = DateTime.UtcNow;
        var result = new OperationResultPayload(
            request.OperationId, request.Command, request.Target,
            ApfsOperationFingerprint.Compute(request),
            ApfsOperationStates.Succeeded, ApfsOperationCodes.OperationSucceeded, true,
            now.AddSeconds(-1), now, now,
            FinalStatus: finalStatus,
            MountProof: "absent", OwnershipProof: "proven",
            DurabilityProof: "proven", ExpiresAtUtc: request.ExpiresAtUtc);
        var envelope = PipeMessageCodec.Create(ApfsMessageTypes.OperationResult, result, request.OperationId, PipeSchemaVersions.Schema2);
        var validation = PipeMessageCodec.Validate(envelope);
        Assert.True(validation.IsValid, validation.Diagnostic);
    }
}
