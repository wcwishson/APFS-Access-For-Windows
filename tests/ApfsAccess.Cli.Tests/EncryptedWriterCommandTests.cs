using ApfsAccess.Cli;
using ApfsAccess.Core;
using ApfsAccess.Ipc;

namespace ApfsAccess.Cli.Tests;

public sealed class EncryptedWriterCommandTests
{
    [Fact] public void IsolatedEncryptedCommandsRequireCanonicalInstanceAndKeepCredentialSelectionExact()
    {
        var id = Guid.NewGuid();
        var parsed = EncryptedImageCommand.Parse(["unlock", "--private-instance", id.ToString("D"),
            "--device-id", @"D:\private.apfs", "--volume-id", "id", "--credential-stdin"]);
        Assert.Equal(id, parsed.PrivateInstanceId); Assert.True(parsed.CredentialStdin);
        Assert.True(FusionControlEndpoint.IsPrivateInstance(FusionControlEndpoint.ForPrivateInstance(id)));
        foreach (var bad in new[] { Guid.Empty.ToString("D"), id.ToString("N"), "\\\\other\\pipe\\arbitrary" })
            Assert.Throws<ArgumentException>(() => EncryptedImageCommand.Parse(["register-image", "--profile", "selectors.json", "--private-instance", bad]));
        Assert.Throws<ArgumentException>(() => EncryptedImageCommand.Parse(["lock", "--device-id", @"D:\private.apfs", "--volume-id", "id",
            "--private-instance", id.ToString("D"), "--private-instance", id.ToString("D")]));
        Assert.Null(EncryptedImageCommand.Parse(["register-image", "--profile", "selectors.json"]).PrivateInstanceId);
    }

    [Fact] public void UnlockSuccessProofCannotSubstituteReadOnlyForExplicitWriterOrWriterForReadOnly()
    {
        var p = new EncryptedImageProfile(@"D:\private.apfs", "image-writer-v1:1:2:8192:0:8192", 0, 8192,
            "11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222", 1026, 7, 0, 2, 0, 2,
            "33333333-3333-3333-3333-333333333333", "includes-header") { Writable = true };
        var now = DateTime.UtcNow;
        OperationResultPayload Result(EncryptedImageProfile profile, bool writable)
        {
            var request = new ControlOperationRequestPayload(Guid.NewGuid().ToString("D"), "unlock", SelectedControlTarget.ForImage(profile), ExpiresAtUtc: now.AddSeconds(30));
            return new(request.OperationId, request.Command, request.Target, ApfsOperationFingerprint.Compute(request), ApfsOperationStates.Succeeded,
                ApfsOperationCodes.OperationSucceeded, true, now, now, now, FinalStatus: writable ? "unlocked-read-write" : "unlocked-read-only",
                EffectiveMode: writable ? ApfsControlModes.ReadWrite : ApfsControlModes.ReadOnly, MountProof: "present",
                ExpiresAtUtc: request.ExpiresAtUtc, EncryptionState: EncryptedVolumeState.Unlocked);
        }
        bool Valid(OperationResultPayload result) => PipeMessageCodec.Validate(PipeMessageCodec.Create(ApfsMessageTypes.OperationResult, result, result.OperationId, 2)).IsValid;
        Assert.True(Valid(Result(p, true))); Assert.False(Valid(Result(p, false)));
        var ro = p with { Writable = false, SourceId = "windows-file:1:2:8192:3:scope:0:8192" };
        Assert.True(Valid(Result(ro, false))); Assert.False(Valid(Result(ro, true)));
        Assert.False(Valid(Result(p, true) with { PendingDurability = true }));
        Assert.False(Valid(Result(p, true) with { MountProof = "not-proven" }));
    }
}
