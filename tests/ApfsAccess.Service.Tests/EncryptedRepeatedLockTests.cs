using ApfsAccess.Core;
using ApfsAccess.Ipc;

namespace ApfsAccess.Service.Tests;

public sealed partial class EncryptedControl659Tests
{
    [Fact]
    public async Task RepeatedLockUsesCleanRetirementWithoutAnotherStopOrDurabilityReceipt()
    {
        using var h=new Harness();
        Assert.True((await h.Exchange(WriterRequest("register-image"))).Success);
        Assert.True((await h.Exchange(WriterRequest("unlock"))).Success);
        var first=await h.Exchange(WriterRequest("lock"));
        Assert.True(first.Success,first.Diagnostic); Assert.Equal("proven",first.DurabilityProof);
        var request=WriterRequest("lock");
        var repeat=await h.Exchange(request);
        Assert.True(repeat.Success,repeat.Diagnostic);
        Assert.Equal(ApfsOperationCodes.AlreadyAchieved,repeat.Code);
        Assert.Equal(ApfsOperationStates.Succeeded,repeat.State);
        Assert.Equal("already-locked",repeat.FinalStatus);
        Assert.Equal(EncryptedVolumeState.Locked,repeat.EncryptionState);
        Assert.Equal("absent",repeat.MountProof); Assert.Equal("proven",repeat.OwnershipProof);
        Assert.Equal("not-applicable",repeat.DurabilityProof); Assert.False(repeat.PendingDurability);
        Assert.Equal(repeat,await h.Exchange(request)); // Replay does not mint another observation.
        Assert.Equal(1,h.Backend.Stops); Assert.Equal(1,h.Backend.LockObservations);
    }

    [Theory]
    [InlineData("unknown")] [InlineData("source")] [InlineData("owner")]
    [InlineData("namespace")] [InlineData("foreign")] [InlineData("ambiguous")]
    public async Task RepeatedLockRefusesMissingOrInvalidatedRetirement(string fault)
    {
        using var h=new Harness();
        Assert.True((await h.Exchange(WriterRequest("register-image"))).Success);
        if (fault!="unknown")
        {
            Assert.True((await h.Exchange(WriterRequest("unlock"))).Success);
            Assert.True((await h.Exchange(WriterRequest("lock"))).Success);
        }
        h.Backend.ChangedRetiredSource=fault=="source";
        h.Backend.HostProof=fault!="owner"; h.Backend.AbsenceProof=fault!="namespace";
        h.Backend.ForeignOwner=fault=="foreign"; h.Backend.AmbiguousOwner=fault=="ambiguous";
        var result=await h.Exchange(WriterRequest("lock"));
        Assert.False(result.Success); Assert.Equal(ApfsOperationStates.Failed,result.State);
        Assert.Equal(ApfsOperationCodes.OperationFailed,result.Code);
        Assert.Equal(EncryptedVolumeState.Failed,result.EncryptionState);
        Assert.DoesNotContain("inconsistent",result.Diagnostic??"",StringComparison.OrdinalIgnoreCase);
        Assert.NotEqual("already-locked",result.FinalStatus);
    }

    [Fact]
    public async Task RepeatedLockRejectsStaleSelectionAndMountedOwnerStillUsesOriginalStop()
    {
        using var h=new Harness();
        Assert.True((await h.Exchange(WriterRequest("register-image"))).Success);
        Assert.True((await h.Exchange(WriterRequest("unlock"))).Success);
        h.Backend.CleanRetirement=true; // A stale receipt cannot override the current mounted owner.
        Assert.True((await h.Exchange(WriterRequest("lock"))).Success);
        Assert.Equal(1,h.Backend.Stops);
        var stale=WriterRequest("lock") with { Target=SelectedControlTarget.ForImage(WriterProfile with { CheckpointXid=9 }) };
        var result=await h.Exchange(stale);
        Assert.False(result.Success); Assert.NotEqual(ApfsOperationCodes.AlreadyAchieved,result.Code);
        Assert.Equal(0,h.Backend.LockObservations);
    }
}
