using ApfsAccess.Core;
using ApfsAccess.Ipc;

namespace ApfsAccess.Ipc.Tests;

public sealed class SnapshotControlContractTests
{
    private static readonly string OperationId = Guid.NewGuid().ToString("D");
    private static readonly ApfsControlTarget Target = new("device-1", "device-1|Main", "apfs-recovery-v1|main");
    private static readonly DateTime Expiry = new(2026, 9, 11, 12, 0, 0, DateTimeKind.Utc);
    private static readonly string[] Identity = ["21", "victim", "249", "17", "230", "8293", "8", "250", "20"];

    [Fact]
    public void OfflineSnapshotInventoryAndVerifyRequireTheirOwnTerminalProof()
    {
        foreach (var command in new[] { ApfsControlCommands.SnapshotList, ApfsControlCommands.VolumeVerify })
        {
            var request = new ControlOperationRequestPayload(OperationId, command, Target, ExpiresAtUtc: Expiry);
            Assert.True(ValidateRequest(request).IsValid);
            Assert.False(ValidateRequest(request with { SnapshotName = "injected" }).IsValid);
            var now = DateTime.UtcNow;
            var result = new OperationResultPayload(OperationId, command, Target, ApfsOperationFingerprint.Compute(request),
                ApfsOperationStates.Succeeded, ApfsOperationCodes.OperationSucceeded, true, now, now, now,
                FinalStatus: command == ApfsControlCommands.SnapshotList ? "snapshot-inventory" : "verified-covered-scope",
                MountProof: "absent", OwnershipProof: "proven", DurabilityProof: "not-applicable", ExpiresAtUtc: Expiry,
                SnapshotInventory: command == ApfsControlCommands.SnapshotList ? System.Text.Json.JsonSerializer.SerializeToElement(new { format = "apfs-access-snapshot-inventory", snapshots = Array.Empty<object>() }) : null);
            Assert.True(ValidateResult(result).IsValid);
            Assert.False(ValidateResult(result with { MountProof = "present" }).IsValid);
            Assert.False(ValidateResult(result with { OwnershipProof = "not-proven" }).IsValid);
            if (command == ApfsControlCommands.SnapshotList) Assert.False(ValidateResult(result with { SnapshotInventory = null }).IsValid);
        }
    }

    [Fact]
    public void Fingerprint_BindsSnapshotName()
    {
        var first = new ControlOperationRequestPayload(OperationId, ApfsControlCommands.SnapshotCreate, Target, ExpiresAtUtc: Expiry, SnapshotName: "backup");
        Assert.Equal(
            ApfsOperationFingerprint.Compute(first),
            ApfsOperationFingerprint.Compute(first with { OperationId = Guid.NewGuid().ToString("D") }));
        Assert.NotEqual(
            ApfsOperationFingerprint.Compute(first),
            ApfsOperationFingerprint.Compute(first with { SnapshotName = "other" }));
    }

    [Fact]
    public void Fingerprint_BindsDeleteIdentity()
    {
        var first = new ControlOperationRequestPayload(OperationId, ApfsControlCommands.SnapshotDelete, Target, ExpiresAtUtc: Expiry, SnapshotIdentity: Identity);
        Assert.NotEqual(
            ApfsOperationFingerprint.Compute(first),
            ApfsOperationFingerprint.Compute(first with { SnapshotIdentity = new[] { "22", "victim", "249", "17", "230", "8293", "8", "250", "20" } }));
        Assert.Equal(
            ApfsOperationFingerprint.Compute(first),
            ApfsOperationFingerprint.Compute(first with { SnapshotIdentity = [.. Identity] }));
    }

    [Fact]
    public void Fingerprint_RecoverNeedsNoParameters()
    {
        var first = new ControlOperationRequestPayload(OperationId, ApfsControlCommands.SnapshotRecover, Target, ExpiresAtUtc: Expiry);
        var second = new ControlOperationRequestPayload(Guid.NewGuid().ToString("D"), ApfsControlCommands.SnapshotRecover, Target, ExpiresAtUtc: Expiry);
        Assert.Equal(ApfsOperationFingerprint.Compute(first), ApfsOperationFingerprint.Compute(second));
        Assert.NotEqual(
            ApfsOperationFingerprint.Compute(first),
            ApfsOperationFingerprint.Compute(first with { Command = ApfsControlCommands.SnapshotCreate, SnapshotName = "backup" }));
    }

    [Theory]
    [InlineData(ApfsControlCommands.SnapshotCreate)]
    [InlineData(ApfsControlCommands.SnapshotDelete)]
    [InlineData(ApfsControlCommands.SnapshotRecover)]
    public void RequestEnvelope_AcceptsWellFormedSnapshotCommands(string command)
    {
        var request = SnapshotRequest(command);
        var envelope = PipeMessageCodec.Create(ApfsMessageTypes.ControlOperationRequest, request, OperationId, PipeSchemaVersions.Schema2);
        var validation = PipeMessageCodec.Validate(envelope);
        Assert.True(validation.IsValid, validation.Diagnostic);
    }

    [Fact]
    public void RequestEnvelope_RejectsMismatchedSnapshotParameters()
    {
        var create = SnapshotRequest(ApfsControlCommands.SnapshotCreate);
        Assert.Equal(ApfsOperationCodes.InvalidArguments, ValidateRequest(create with { SnapshotIdentity = Identity }).Code);
        var delete = SnapshotRequest(ApfsControlCommands.SnapshotDelete);
        Assert.Equal(ApfsOperationCodes.InvalidArguments, ValidateRequest(delete with { SnapshotName = "victim" }).Code);
        Assert.Equal(ApfsOperationCodes.InvalidArguments, ValidateRequest(delete with { SnapshotIdentity = ["21", "victim"] }).Code);
        Assert.Equal(ApfsOperationCodes.InvalidArguments, ValidateRequest(delete with { SnapshotIdentity = ["01", "victim", "249", "17", "230", "8293", "8", "250", "20"] }).Code);
        var recover = SnapshotRequest(ApfsControlCommands.SnapshotRecover);
        Assert.Equal(ApfsOperationCodes.InvalidArguments, ValidateRequest(recover with { SnapshotName = "backup" }).Code);
        var mount = new ControlOperationRequestPayload(OperationId, ApfsControlCommands.Mount, Target, ApfsControlModes.ReadWrite, Expiry, SnapshotName: "backup");
        Assert.Equal(ApfsOperationCodes.InvalidArguments, ValidateRequest(mount).Code);
    }

    [Theory]
    [InlineData(ApfsControlCommands.SnapshotCreate, "snapshot-created")]
    [InlineData(ApfsControlCommands.SnapshotDelete, "snapshot-deleted")]
    [InlineData(ApfsControlCommands.SnapshotRecover, "snapshot-recovered")]
    [InlineData(ApfsControlCommands.SnapshotRecover, "snapshot-recover-noop")]
    public void ResultEnvelope_AcceptsProvenSnapshotTerminals(string command, string finalStatus)
    {
        var request = SnapshotRequest(command);
        var now = DateTime.UtcNow;
        var result = new OperationResultPayload(
            request.OperationId, command, request.Target,
            ApfsOperationFingerprint.Compute(request),
            ApfsOperationStates.Succeeded, ApfsOperationCodes.OperationSucceeded, true,
            now.AddSeconds(-1), now, now,
            FinalStatus: finalStatus, MountProof: "present", OwnershipProof: "proven",
            DurabilityProof: "not-applicable", ExpiresAtUtc: request.ExpiresAtUtc,
            SnapshotName: request.SnapshotName, SnapshotIdentity: request.SnapshotIdentity);
        var envelope = PipeMessageCodec.Create(ApfsMessageTypes.OperationResult, result, request.OperationId, PipeSchemaVersions.Schema2);
        var validation = PipeMessageCodec.Validate(envelope);
        Assert.True(validation.IsValid, validation.Diagnostic);
    }

    [Fact]
    public void ResultEnvelope_RejectsUnprovenOrMismatchedSnapshotTerminals()
    {
        var request = SnapshotRequest(ApfsControlCommands.SnapshotCreate);
        var now = DateTime.UtcNow;
        var missingProof = new OperationResultPayload(
            request.OperationId, request.Command, request.Target,
            ApfsOperationFingerprint.Compute(request),
            ApfsOperationStates.Succeeded, ApfsOperationCodes.OperationSucceeded, true,
            now.AddSeconds(-1), now, now,
            FinalStatus: "snapshot-created", MountProof: "present", OwnershipProof: "not-proven",
            DurabilityProof: "not-applicable", ExpiresAtUtc: request.ExpiresAtUtc,
            SnapshotName: request.SnapshotName);
        Assert.Equal(ApfsOperationCodes.MalformedMessage, ValidateResult(missingProof).Code);
        var wrongFinal = missingProof with { FinalStatus = "healthy-rw", OwnershipProof = "proven" };
        Assert.Equal(ApfsOperationCodes.MalformedMessage, ValidateResult(wrongFinal).Code);
        var tampered = missingProof with
        {
            FinalStatus = "snapshot-created",
            OwnershipProof = "proven",
            SnapshotName = "someone-else",
        };
        Assert.Equal(ApfsOperationCodes.MalformedMessage, ValidateResult(tampered).Code);
    }

    private static ControlOperationRequestPayload SnapshotRequest(string command)
        => command switch
        {
            ApfsControlCommands.SnapshotCreate => new ControlOperationRequestPayload(
                OperationId, command, Target, ExpiresAtUtc: Expiry, SnapshotName: "backup"),
            ApfsControlCommands.SnapshotDelete => new ControlOperationRequestPayload(
                OperationId, command, Target, ExpiresAtUtc: Expiry, SnapshotIdentity: Identity),
            _ => new ControlOperationRequestPayload(
                OperationId, command, Target, ExpiresAtUtc: Expiry),
        };

    private static PipeMessageValidationResult ValidateRequest(ControlOperationRequestPayload request)
        => PipeMessageCodec.Validate(PipeMessageCodec.Create(
            ApfsMessageTypes.ControlOperationRequest, request, OperationId, PipeSchemaVersions.Schema2));

    private static PipeMessageValidationResult ValidateResult(OperationResultPayload result)
        => PipeMessageCodec.Validate(PipeMessageCodec.Create(
            ApfsMessageTypes.OperationResult, result, result.OperationId, PipeSchemaVersions.Schema2));
}
