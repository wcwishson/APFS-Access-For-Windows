using ApfsAccess.Core;
using ApfsAccess.Ipc;

namespace ApfsAccess.Ipc.Tests;

public sealed class LiveVolumeVerificationContractTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void RetainedReportsRoundTripBothVerdictsAndCannotClaimMutation(bool damaged)
    {
        var scope = LiveVerificationFixture.Scope();
        var target = new ApfsControlTarget(@"D:\fixture.apfs", ApfsTopology.BuildVolumeId(scope.ContainerUuid, 101), "recovery", scope.VolumeUuid, scope.ContainerUuid, 101,
            "selected-v1:" + new string('a', 64));
        var request = new ControlOperationRequestPayload(Guid.NewGuid().ToString("D"), ApfsControlCommands.VolumeVerify,
            target, ExpiresAtUtc: DateTime.UtcNow.AddMinutes(1));
        var result = new OperationResultPayload(request.OperationId, request.Command, target, ApfsOperationFingerprint.Compute(request),
            damaged ? ApfsOperationStates.Failed : ApfsOperationStates.Succeeded,
            damaged ? ApfsOperationCodes.BlockedRecovery : ApfsOperationCodes.OperationSucceeded, !damaged, DateTime.UtcNow,
            StartedAtUtc: DateTime.UtcNow, CompletedAtUtc: DateTime.UtcNow,
            FinalStatus: damaged ? "verification-not-complete" : "verified-covered-scope", MountProof: "present",
            OwnershipProof: "proven", DurabilityProof: "not-applicable", ExpiresAtUtc: request.ExpiresAtUtc,
            VolumeVerificationReport: LiveVerificationFixture.Element(LiveVerificationFixture.Report(damaged: damaged)));
        PipeMessageValidationResult Validate(OperationResultPayload value) =>
            PipeMessageCodec.Validate(PipeMessageCodec.Create(ApfsMessageTypes.OperationResult, value, request.OperationId, 2));
        Assert.True(Validate(result).IsValid, Validate(result).Diagnostic);
        Assert.False(Validate(result with { Target = target with { VolumeObjectId = 102 } }).IsValid);
        Assert.False(Validate(result with { Success = damaged }).IsValid);
        Assert.False(Validate(result with { DurabilityProof = "proven" }).IsValid);
        Assert.False(Validate(result with { MountProof = "absent" }).IsValid);
        Assert.False(Validate(result with { Command = ApfsControlCommands.SnapshotList }).IsValid);
    }
}
