using ApfsAccess.Core;

namespace ApfsAccess.Ipc.Tests;

public sealed class ImageKeyManagementObservationTests
{
    private static ImageKeyManagementEndpoint Plain => new(@"D:\private\image.raw", "image-writer-v1:1:2:4194304:0:4194304",
        0, 4194304, "d08a9fa0-d5a5-458b-813e-ebf9bf5d5338", "458ed10d-8ac3-4af1-8dfd-3954d151a3f3", 1026, 4, ImageEncryptionMode.Plain);
    private static ImageKeyManagementRequest Request => new("cf5cac71-9edc-4cbc-a73d-477dca61caee", ImageKeyManagementAction.Observe, Plain);
    private static ImageKeyManagementReceipt Receipt => new(Request.OperationId, Request.Action, Plain, Plain, 0, 0, 0, true, true);

    [Fact]
    public void PristineCleanObservationNeedsNoAcceptedMutation()
    {
        Assert.True(Request.IsValid());
        Assert.Equal(0, Request.CredentialCount);
        Assert.True(Receipt.Proves(Request));
        Assert.False((Receipt with { Action = ImageKeyManagementAction.Encrypt }).Proves(Request));
        var mutation = Request with { Action = ImageKeyManagementAction.Encrypt };
        Assert.False((Receipt with { Action = mutation.Action }).Proves(mutation));
    }

    [Fact]
    public void KeylessAcceptedRecoveryMayAdvanceModeButCannotSubstituteImageOrRollback()
    {
        var encrypted = Plain with { CheckpointXid = 5, Mode = ImageEncryptionMode.SoftwareOneKeyGenerationZero,
            Keybag = new(0, 5, 0, 5, "cf5cac71-9edc-4cbc-a73d-477dca61caee", "includes-header") };
        var recovered = Receipt with { After = encrypted, AcceptedSequence = 60, DurableSequence = 60, CleanedSequence = 60 };
        Assert.True(recovered.Proves(Request));
        Assert.False((recovered with { After = encrypted with { SourceId = "image-writer-v1:1:3:4194304:0:4194304" } }).Proves(Request));
        Assert.False((recovered with { After = encrypted with { VolumeObjectId = 1027 } }).Proves(Request));
        Assert.False((recovered with { After = Plain with { CheckpointXid = 3 } }).Proves(Request));
        Assert.False((recovered with { CleanedSequence = 59 }).Proves(Request));
        Assert.False((recovered with { OwnerClosed = false }).Proves(Request));
        Assert.False((recovered with { KeyRevoked = false }).Proves(Request));
    }

    [Fact]
    public void PersistedObservationCannotMasqueradeAsAConfirmedMutation()
    {
        var now = DateTime.UtcNow;
        var request = new ControlOperationRequestPayload(Request.OperationId, ApfsControlCommands.ImageKeyManagement, null,
            ExpiresAtUtc: now.AddMinutes(1), KeyManagement: Request);
        Assert.True(PipeMessageCodec.Validate(PipeMessageCodec.Create(ApfsMessageTypes.ControlOperationRequest, request, Request.OperationId, 2)).IsValid);
        var result = new OperationResultPayload(Request.OperationId, request.Command, null, ApfsOperationFingerprint.Compute(request),
            ApfsOperationStates.Succeeded, ApfsOperationCodes.OperationSucceeded, true, now, now, now,
            FinalStatus: "image-keys-observed", MountProof: "absent", OwnershipProof: "proven", DurabilityProof: "proven",
            ExpiresAtUtc: request.ExpiresAtUtc,
            KeyManagement: Request, KeyManagementReceipt: Receipt);
        bool Valid(OperationResultPayload value) => PipeMessageCodec.Validate(PipeMessageCodec.Create(ApfsMessageTypes.OperationResult, value, Request.OperationId, 2)).IsValid;
        Assert.True(Valid(result));
        Assert.False(Valid(result with { FinalStatus = "image-keys-updated" }));
        Assert.False(Valid(result with { KeyManagementReceipt = null }));
        Assert.False(Valid(result with { RecoveryActive = true }));
        Assert.False(Valid(result with { KeyManagement = Request with { Action = ImageKeyManagementAction.Encrypt } }));
        Assert.NotEqual(ApfsOperationFingerprint.Compute(request), ApfsOperationFingerprint.Compute(request with
            { KeyManagement = Request with { Action = ImageKeyManagementAction.Encrypt } }));
    }
}
