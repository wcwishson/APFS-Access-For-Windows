using ApfsAccess.Core;
using ApfsAccess.Ipc;

namespace ApfsAccess.Ipc.Tests;

// Task 11 Step 2: the pipe envelope carries verify-plan-confirm-apply
// parameters. These pins prove the fingerprint binds the operation and
// mutation values (never the server-issued token echo), the envelope
// accepts well-formed plan/apply requests and rejects cross-command
// parameters, and only a fully-echoed plan issuance validates as a
// successful terminal.
public sealed class ManagementPlanContractTests
{
    private static readonly string OperationId = Guid.NewGuid().ToString("D");
    private static readonly ApfsControlTarget Target = new("device-1", "device-1|Main", "apfs-recovery-v1|main");
    private static readonly DateTime Expiry = new(2026, 9, 13, 12, 0, 0, DateTimeKind.Utc);

    private static readonly string ImagePath = @"D:\keeper-test\image.apfs";

    private static ControlOperationRequestPayload PlanRequest(
        string operation = ApfsManagementOperations.RenameVolume)
        => new(OperationId, ApfsControlCommands.ManagementPlan, Target, ExpiresAtUtc: Expiry,
            ManagementOperation: operation);

    private static ControlOperationRequestPayload ApplyRequest(
        string operation = ApfsManagementOperations.RenameVolume,
        string? token = "abcdef0123456789",
        string? name = "Renamed",
        string? quota = null,
        string? reserve = null,
        string? imagePath = null)
        => new(OperationId, ApfsControlCommands.ManagementApply, Target, ExpiresAtUtc: Expiry,
            ManagementOperation: operation, ManagementToken: token, ManagementName: name,
            ManagementQuotaBytes: quota, ManagementReserveBytes: reserve,
            ManagementImagePath: imagePath ?? ImagePath);

    private static PipeMessageValidationResult ValidateRequest(ControlOperationRequestPayload request)
    {
        var envelope = PipeMessageCodec.Create(
            ApfsMessageTypes.ControlOperationRequest, request, OperationId, PipeSchemaVersions.Schema2);
        return PipeMessageCodec.Validate(envelope);
    }

    private static PipeMessageValidationResult ValidateResult(OperationResultPayload result)
    {
        var envelope = PipeMessageCodec.Create(
            ApfsMessageTypes.OperationResult, result, OperationId, PipeSchemaVersions.Schema2);
        return PipeMessageCodec.Validate(envelope);
    }

    [Fact]
    public void Fingerprint_BindsOperationAndMutationValues()
    {
        var first = PlanRequest();
        Assert.Equal(
            ApfsOperationFingerprint.Compute(first),
            ApfsOperationFingerprint.Compute(first with { OperationId = Guid.NewGuid().ToString("D") }));
        Assert.NotEqual(
            ApfsOperationFingerprint.Compute(first),
            ApfsOperationFingerprint.Compute(first with { ManagementOperation = ApfsManagementOperations.SetQuotaReserve }));
        var apply = ApplyRequest();
        Assert.NotEqual(ApfsOperationFingerprint.Compute(apply), ApfsOperationFingerprint.Compute(first));
        Assert.NotEqual(
            ApfsOperationFingerprint.Compute(apply),
            ApfsOperationFingerprint.Compute(apply with { ManagementName = "Other" }));
        Assert.NotEqual(
            ApfsOperationFingerprint.Compute(apply),
            ApfsOperationFingerprint.Compute(apply with { ManagementToken = "fedcba9876543210" }));
        Assert.NotEqual(
            ApfsOperationFingerprint.Compute(apply),
            ApfsOperationFingerprint.Compute(apply with { ManagementImagePath = @"D:\other\image.apfs" }));
        var quota = ApplyRequest(
            ApfsManagementOperations.SetQuotaReserve, "abcdef0123456789", null, "65536", "20480");
        Assert.NotEqual(
            ApfsOperationFingerprint.Compute(quota),
            ApfsOperationFingerprint.Compute(quota with { ManagementQuotaBytes = "65537" }));
    }

    [Fact]
    public void Fingerprint_ForResultReproducesPlanRequest()
    {
        var request = PlanRequest();
        var now = DateTime.UtcNow;
        var result = new OperationResultPayload(
            request.OperationId, request.Command, request.Target,
            ApfsOperationFingerprint.Compute(request),
            ApfsOperationStates.Succeeded, ApfsOperationCodes.OperationSucceeded, true,
            now.AddSeconds(-1), now, now,
            FinalStatus: "management-plan-issued", MountProof: "absent", OwnershipProof: "proven",
            DurabilityProof: "not-applicable", ExpiresAtUtc: request.ExpiresAtUtc,
            ManagementOperation: request.ManagementOperation,
            ManagementPlanId: "mgmt-plan-v1:abc",
            ManagementToken: "issued-server-token",
            ManagementObservedXid: "90");
        Assert.Equal(ApfsOperationFingerprint.Compute(request), ApfsOperationFingerprint.ComputeForResult(result));
    }

    [Fact]
    public void Fingerprint_ForResultReproducesApplyRequest()
    {
        var request = ApplyRequest();
        var result = new OperationResultPayload(
            request.OperationId, request.Command, request.Target,
            ApfsOperationFingerprint.Compute(request),
            ApfsOperationStates.Failed, ApfsOperationCodes.ServiceUnavailable, false,
            DateTime.UtcNow.AddSeconds(-1), DateTime.UtcNow, DateTime.UtcNow,
            FinalStatus: "keeper-unavailable", MountProof: "absent", OwnershipProof: "proven",
            DurabilityProof: "not-applicable", ExpiresAtUtc: request.ExpiresAtUtc,
            ManagementOperation: request.ManagementOperation,
            ManagementToken: request.ManagementToken,
            ManagementObservedXid: "90",
            ManagementName: request.ManagementName,
            ManagementImagePath: request.ManagementImagePath);
        Assert.Equal(ApfsOperationFingerprint.Compute(request), ApfsOperationFingerprint.ComputeForResult(result));
    }

    [Fact]
    public void ResultEnvelope_AcceptsAppliedRenameTerminal()
    {
        var request = ApplyRequest();
        var now = DateTime.UtcNow;
        var result = new OperationResultPayload(
            request.OperationId, request.Command, request.Target,
            ApfsOperationFingerprint.Compute(request),
            ApfsOperationStates.Succeeded, ApfsOperationCodes.OperationSucceeded, true,
            now.AddSeconds(-1), now, now,
            FinalStatus: "management-applied", MountProof: "absent", OwnershipProof: "proven",
            DurabilityProof: "proven", ExpiresAtUtc: request.ExpiresAtUtc,
            ManagementOperation: request.ManagementOperation,
            ManagementToken: request.ManagementToken,
            ManagementObservedXid: "91",
            ManagementName: request.ManagementName,
            ManagementImagePath: request.ManagementImagePath);
        var validation = ValidateResult(result);
        Assert.True(validation.IsValid, validation.Diagnostic);
    }

    [Fact]
    public void ResultEnvelope_RejectsMismatchedApplyTerminals()
    {
        var request = ApplyRequest();
        var now = DateTime.UtcNow;
        OperationResultPayload Applied(string finalStatus, string durability, string? token, string? xid)
            => new(request.OperationId, request.Command, request.Target,
                ApfsOperationFingerprint.Compute(request),
                ApfsOperationStates.Succeeded, ApfsOperationCodes.OperationSucceeded, true,
                now.AddSeconds(-1), now, now,
                FinalStatus: finalStatus, MountProof: "absent", OwnershipProof: "proven",
                DurabilityProof: durability, ExpiresAtUtc: request.ExpiresAtUtc,
                ManagementOperation: request.ManagementOperation,
                ManagementToken: token,
                ManagementObservedXid: xid,
                ManagementName: request.ManagementName,
                ManagementImagePath: request.ManagementImagePath);
        Assert.Equal(ApfsOperationCodes.MalformedMessage, ValidateResult(Applied("management-applied", "not-applicable", request.ManagementToken, "91")).Code);
        Assert.Equal(ApfsOperationCodes.MalformedMessage, ValidateResult(Applied("management-applied", "proven", "other-token", "91")).Code);
        Assert.Equal(ApfsOperationCodes.MalformedMessage, ValidateResult(Applied("healthy-rw", "proven", request.ManagementToken, "91")).Code);
    }

    [Theory]
    [InlineData(ApfsManagementOperations.RenameVolume)]
    [InlineData(ApfsManagementOperations.SetQuotaReserve)]
    public void RequestEnvelope_AcceptsWellFormedPlan(string operation)
    {
        var validation = ValidateRequest(PlanRequest(operation));
        Assert.True(validation.IsValid, validation.Diagnostic);
    }

    [Fact]
    public void RequestEnvelope_AcceptsWellFormedApply()
    {
        Assert.True(ValidateRequest(ApplyRequest()).IsValid);
        var quota = ApplyRequest(ApfsManagementOperations.SetQuotaReserve, "abcdef0123456789", null, "65536", "20480");
        Assert.True(ValidateRequest(quota).IsValid);
    }

    [Fact]
    public void RequestEnvelope_RejectsMismatchedManagementParameters()
    {
        Assert.Equal(ApfsOperationCodes.InvalidArguments,
            ValidateRequest(PlanRequest() with { ManagementToken = "token" }).Code);
        Assert.Equal(ApfsOperationCodes.InvalidArguments,
            ValidateRequest(PlanRequest() with { ManagementName = "Renamed" }).Code);
        Assert.Equal(ApfsOperationCodes.InvalidArguments,
            ValidateRequest(PlanRequest() with { ManagementImagePath = ImagePath }).Code);
        Assert.Equal(ApfsOperationCodes.InvalidArguments,
            ValidateRequest(ApplyRequest() with { ManagementToken = null }).Code);
        Assert.Equal(ApfsOperationCodes.InvalidArguments,
            ValidateRequest(ApplyRequest() with { ManagementImagePath = null }).Code);
        Assert.Equal(ApfsOperationCodes.InvalidArguments,
            ValidateRequest(ApplyRequest() with { ManagementToken = "  " }).Code);
        // Unknown operation spellings pass envelope shape (non-empty
        // string) and are refused by service admission membership instead.
        var mount = new ControlOperationRequestPayload(
            OperationId, ApfsControlCommands.Mount, Target, ApfsControlModes.ReadWrite, Expiry,
            ManagementOperation: ApfsManagementOperations.RenameVolume);
        Assert.Equal(ApfsOperationCodes.InvalidArguments, ValidateRequest(mount).Code);
    }

    [Fact]
    public void ResultEnvelope_AcceptsIssuedPlanTerminal()
    {
        var request = PlanRequest();
        var now = DateTime.UtcNow;
        var result = new OperationResultPayload(
            request.OperationId, request.Command, request.Target,
            ApfsOperationFingerprint.Compute(request),
            ApfsOperationStates.Succeeded, ApfsOperationCodes.OperationSucceeded, true,
            now.AddSeconds(-1), now, now,
            FinalStatus: "management-plan-issued", MountProof: "absent", OwnershipProof: "proven",
            DurabilityProof: "not-applicable", ExpiresAtUtc: request.ExpiresAtUtc,
            ManagementOperation: request.ManagementOperation,
            ManagementPlanId: "mgmt-plan-v1:abc",
            ManagementToken: "issued-server-token",
            ManagementObservedXid: "90");
        var validation = ValidateResult(result);
        Assert.True(validation.IsValid, validation.Diagnostic);
    }

    [Fact]
    public void ResultEnvelope_RejectsUnprovenOrMismatchedPlanTerminals()
    {
        var request = PlanRequest();
        var now = DateTime.UtcNow;
        OperationResultPayload Issued(string finalStatus, string mountProof, string? planId, string? token, string? xid)
            => new(request.OperationId, request.Command, request.Target,
                ApfsOperationFingerprint.Compute(request),
                ApfsOperationStates.Succeeded, ApfsOperationCodes.OperationSucceeded, true,
                now.AddSeconds(-1), now, now,
                FinalStatus: finalStatus, MountProof: mountProof, OwnershipProof: "proven",
                DurabilityProof: "not-applicable", ExpiresAtUtc: request.ExpiresAtUtc,
                ManagementOperation: request.ManagementOperation,
                ManagementPlanId: planId, ManagementToken: token, ManagementObservedXid: xid);
        Assert.Equal(ApfsOperationCodes.MalformedMessage, ValidateResult(Issued("management-plan-issued", "present", "mgmt-plan-v1:abc", "t", "90")).Code);
        Assert.Equal(ApfsOperationCodes.MalformedMessage, ValidateResult(Issued("management-plan-issued", "absent", null, "t", "90")).Code);
        Assert.Equal(ApfsOperationCodes.MalformedMessage, ValidateResult(Issued("management-plan-issued", "absent", "mgmt-plan-v1:abc", "t", "0")).Code);
        Assert.Equal(ApfsOperationCodes.MalformedMessage, ValidateResult(Issued("management-plan-issued", "absent", "mgmt-plan-v1:abc", "t", "not-a-number")).Code);
        Assert.Equal(ApfsOperationCodes.MalformedMessage, ValidateResult(Issued("healthy-rw", "absent", "mgmt-plan-v1:abc", "t", "90")).Code);
    }
}
