using ApfsAccess.Core;
using ApfsAccess.Ipc;

namespace ApfsAccess.Cli.Tests;

public sealed class EncryptedRepeatedLockCommandTests
{
    [Theory]
    [InlineData("valid")] [InlineData("owner")] [InlineData("namespace")]
    [InlineData("durability")] [InlineData("pending")] [InlineData("selection")]
    [InlineData("state")] [InlineData("recovery")] [InlineData("mode")]
    public void TerminalAlreadyLockedWireRequiresExactObservationAndNoInventedDurability(string fault)
    {
        var p=new EncryptedImageProfile(@"D:\closed.apfs","image-writer-v1:1:2:4096:0:4096",0,4096,
            "11111111-1111-1111-1111-111111111111","22222222-2222-2222-2222-222222222222",12,8,0,2,0,2,
            "33333333-3333-3333-3333-333333333333","includes-header") { Writable=true };
        var now=DateTime.UtcNow;
        var request=new ControlOperationRequestPayload(Guid.NewGuid().ToString("D"),"lock",SelectedControlTarget.ForImage(p),ExpiresAtUtc:now.AddSeconds(30));
        var result=new OperationResultPayload(request.OperationId,request.Command,request.Target,ApfsOperationFingerprint.Compute(request),
            ApfsOperationStates.Succeeded,ApfsOperationCodes.AlreadyAchieved,true,now,now,now,
            FinalStatus:"already-locked",MountProof:"absent",OwnershipProof:"proven",DurabilityProof:"not-applicable",
            ExpiresAtUtc:request.ExpiresAtUtc,EncryptionState:EncryptedVolumeState.Locked);
        result=fault switch {
            "owner"=>result with { OwnershipProof="not-proven" }, "namespace"=>result with { MountProof="present" },
            "durability"=>result with { DurabilityProof="proven" }, "pending"=>result with { PendingDurability=true },
            "selection"=>result with { Target=request.Target! with { RegisteredImage=p with { Writable=false } } },
            "state"=>result with { EncryptionState=EncryptedVolumeState.Failed },
            "recovery"=>result with { RecoveryActive=true }, "mode"=>result with { EffectiveMode="read-write" }, _=>result
        };
        Assert.Equal(fault=="valid",PipeMessageCodec.Validate(PipeMessageCodec.Create(ApfsMessageTypes.OperationResult,result,result.OperationId,2)).IsValid);
    }
}
