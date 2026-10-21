using ApfsAccess.Core;
using ApfsAccess.Ipc;
namespace ApfsAccess.Service.Tests;
public sealed partial class EncryptedControl659Tests
{
    private sealed class Clock : TimeProvider
    {
        private DateTimeOffset now=DateTimeOffset.UtcNow;
        public override DateTimeOffset GetUtcNow()=>now;
        public void Advance()=>now=now.AddSeconds(6);
    }
    private sealed class Barrier
    {
        public TaskCompletionSource Entered {get;}=new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Release {get;}=new(TaskCreationOptions.RunContinuationsAsynchronously);
        public async Task Wait(CancellationToken ct) { Entered.TrySetResult(); await Release.Task.WaitAsync(ct); }
        public Task Arrived()=>Entered.Task.WaitAsync(TimeSpan.FromSeconds(15));
    }
    private static async Task<EncryptedVolumeState?> Display(Harness h)=>(await h.Backend.ProbeVolumesAsync(Profile.ImagePath,default)).Single().EncryptionState;

    [Theory] [InlineData("lock",false)] [InlineData("lock",true)] [InlineData("eject",false)] [InlineData("eject",true)]
    public async Task OldStopCompletionCannotOverwriteNewUnlockAfterWorkerRelease676(string command,bool cancel)
    {
        using var h=new Harness(); await h.Operations.ExecuteOrReplayAsync(Request("register-image"));
        Assert.True((await h.Operations.ExecuteOrReplayAsync(Request("unlock"))).Success); h.Clock.Advance();
        var probe=new Barrier(); var credential=new Barrier(); h.Backend.AfterStopProbe=probe.Wait;
        using var cancellation=new CancellationTokenSource();
        var stopping=h.Executor.ExecuteAsync(Request(command),cancellation.Token);
        await probe.Arrived(); Assert.Empty(h.Backend.Mounts); Assert.Equal(1,h.Backend.Stops);
        // The authoritative post-eject probe runs after the mutation lock is released.
        h.Executor.CredentialReceiver=async(_,_,_,ct)=>{await credential.Wait(ct); return Credential();};
        var unlocking=h.Operations.ExecuteOrReplayAsync(Request("unlock")); await credential.Arrived();
        try
        {
            Assert.Equal(EncryptedVolumeState.Unlocking,await Display(h));
            if(cancel) cancellation.Cancel(); probe.Release.TrySetResult(); await stopping;
            Assert.Equal(EncryptedVolumeState.Unlocking,await Display(h));
        }
        finally { probe.Release.TrySetResult(); credential.Release.TrySetResult(); }
        Assert.True((await unlocking).Success); Assert.Single(h.Backend.Mounts);
        Assert.Equal(EncryptedVolumeState.Unlocked,await Display(h));
    }

    [Fact] public async Task CancellationBeforeReservationCannotOverwriteNewUnlock676()
    {
        using var h=new Harness(); await h.Operations.ExecuteOrReplayAsync(Request("register-image"));
        var discovery=new Barrier(); var credential=new Barrier(); h.Backend.BeforeProbe=discovery.Wait;
        using var cancellation=new CancellationTokenSource();
        var older=h.Executor.ExecuteAsync(Request("lock"),cancellation.Token); await discovery.Arrived();
        h.Executor.CredentialReceiver=async(_,_,_,ct)=>{await credential.Wait(ct);return Credential();};
        var newer=h.Operations.ExecuteOrReplayAsync(Request("unlock")); await credential.Arrived();
        try { cancellation.Cancel(); Assert.False((await older).Success); Assert.Equal(EncryptedVolumeState.Unlocking,await Display(h)); }
        finally { discovery.Release.TrySetResult(); credential.Release.TrySetResult(); }
        Assert.True((await newer).Success); Assert.Single(h.Backend.Mounts);
    }

    [Fact] public async Task DuplicateRegistrationFailureCannotRelabelMountedOwner676()
    {
        using var h=new Harness(); await h.Operations.ExecuteOrReplayAsync(Request("register-image"));
        Assert.True((await h.Operations.ExecuteOrReplayAsync(Request("unlock"))).Success);
        Assert.False((await h.Operations.ExecuteOrReplayAsync(Request("register-image"))).Success);
        Assert.Single(h.Backend.Mounts); Assert.Equal(EncryptedVolumeState.Unlocked,await Display(h));
        Assert.True((await h.Operations.ExecuteOrReplayAsync(Request("lock"))).Success);
        Assert.Empty(h.Backend.Mounts); Assert.Equal(1,h.Backend.Stops);
    }

    [Theory] [InlineData(false)] [InlineData(true)]
    public async Task RegistrationCompletionOrCancellationCannotOverwriteLaterUnlock676(bool cancel)
    {
        using var h=new Harness(); var registration=new Barrier(); var credential=new Barrier();
        h.Backend.BeforeRegister=registration.Wait;
        using var cancellation=new CancellationTokenSource();
        var registering=h.Executor.ExecuteAsync(Request("register-image"),cancellation.Token);
        await registration.Arrived();
        h.Executor.CredentialReceiver=async(_,_,_,ct)=>{await credential.Wait(ct);return Credential();};
        var unlocking=h.Operations.ExecuteOrReplayAsync(Request("unlock")); await credential.Arrived();
        try
        {
            if(cancel) cancellation.Cancel(); registration.Release.TrySetResult();
            Assert.False((await registering).Success);
            Assert.Equal(EncryptedVolumeState.Unlocking,await Display(h));
            Assert.Empty(h.Backend.Mounts);
        }
        finally { registration.Release.TrySetResult(); credential.Release.TrySetResult(); }
        Assert.True((await unlocking).Success); Assert.Single(h.Backend.Mounts);
        Assert.Equal(EncryptedVolumeState.Unlocked,await Display(h));
    }

    [Theory] [InlineData(true)] [InlineData(false)]
    public async Task UnlockDuringTeardownWaitsForActualOwnerRelease676(bool hostReleased)
    {
        using var h=new Harness(); await h.Operations.ExecuteOrReplayAsync(Request("register-image"));
        Assert.True((await h.Operations.ExecuteOrReplayAsync(Request("unlock"))).Success); h.Clock.Advance();
        var teardown=new Barrier(); var received=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        h.Backend.BeforeStop=teardown.Wait; h.Backend.HostProof=hostReleased;
        var stopping=h.Operations.ExecuteOrReplayAsync(Request("lock")); await teardown.Arrived();
        h.Executor.CredentialReceiver=(_,_,_,_)=>{received.TrySetResult();return Task.FromResult(Credential());};
        var unlocking=h.Operations.ExecuteOrReplayAsync(Request("unlock"));
        await received.Task.WaitAsync(TimeSpan.FromSeconds(15));
        try { Assert.False(unlocking.IsCompleted); Assert.Single(h.Backend.Mounts); Assert.Equal(1,h.Backend.Unlocks); Assert.Equal(0,h.Backend.Stops); }
        finally { teardown.Release.TrySetResult(); }
        await stopping;
        var unlocked=await unlocking;
        if(hostReleased) Assert.True(unlocked.Success,$"{unlocked.Diagnostic} Unlocks={h.Backend.Unlocks}, stops={h.Backend.Stops}, mounts={h.Backend.Mounts.Count}");
        else Assert.False(unlocked.Success);
        if(hostReleased) Assert.Single(h.Backend.Mounts); else Assert.Empty(h.Backend.Mounts);
        Assert.Equal(hostReleased?2:1,h.Backend.Unlocks); Assert.Equal(1,h.Backend.Stops);
        Assert.Equal(hostReleased?EncryptedVolumeState.Unlocked:EncryptedVolumeState.Failed,await Display(h));
    }

    [Theory] [InlineData(false)] [InlineData(true)]
    public async Task UnlockRevalidatesLatestOverlappingInventoryBeforeStartingOwner(bool changed)
    {
        using var h=new Harness();
        Assert.True((await h.Operations.ExecuteOrReplayAsync(Request("register-image"))).Success);
        var discovery=new Barrier();
        h.Executor.CredentialReceiver=(_,_,_,_)=>{
            h.Backend.BeforeProbe=discovery.Wait;
            return Task.FromResult(Credential());
        };
        var unlocking=h.Operations.ExecuteOrReplayAsync(Request("unlock"));
        await discovery.Arrived();
        try {
            if(changed)h.Backend.ObservedCheckpoint=9;
            await h.Worker.GetInventoryAsync(CancellationToken.None);
        }
        finally {discovery.Release.TrySetResult();}
        var result=await unlocking;
        if(changed) {
            Assert.False(result.Success);Assert.Equal(0,h.Backend.Unlocks);Assert.Empty(h.Backend.Mounts);
        } else {
            Assert.True(result.Success,result.Diagnostic);Assert.Equal(1,h.Backend.Unlocks);Assert.Single(h.Backend.Mounts);
        }
    }
}
