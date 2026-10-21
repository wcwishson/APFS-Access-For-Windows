using ApfsAccess.Core;
using ApfsAccess.Ipc;

namespace ApfsAccess.Service.Tests;

public sealed partial class EncryptedControl659Tests
{
    private static EncryptedImageProfile WriterProfile => Profile with { Writable = true, SourceId = "image-writer-v1:1:2:4096:0:4096" };
    private static ControlOperationRequestPayload WriterRequest(string command) => Request(command) with { Target = SelectedControlTarget.ForImage(WriterProfile) };

    [Fact] public async Task ExplicitWriterFlowsThroughServiceWorkerReplayAndCleanLockWithExactMode()
    {
        using var h = new Harness();
        Assert.True((await h.Exchange(WriterRequest("register-image"))).Success);
        var request = WriterRequest("unlock");
        var unlocked = await h.Exchange(request);
        Assert.True(unlocked.Success, unlocked.Diagnostic);
        Assert.Equal("unlocked-read-write", unlocked.FinalStatus); Assert.Equal(ApfsControlModes.ReadWrite, unlocked.EffectiveMode);
        Assert.Equal(MountAccessMode.ReadWrite, Assert.Single(h.Backend.Mounts).AccessMode);
        Assert.Equal(unlocked, await h.Exchange(request)); Assert.Equal(1, h.Backend.Unlocks);
        var stopped = await h.Exchange(WriterRequest("lock"));
        Assert.True(stopped.Success, stopped.Diagnostic);
        Assert.Equal("proven", stopped.OwnershipProof); Assert.Equal("proven", stopped.DurabilityProof);
        Assert.Equal("absent", stopped.MountProof); Assert.Empty(h.Backend.Mounts);
    }

    [Fact] public async Task WriterDoesNotReportSuccessForReadOnlyFallbackOrMissingCanonicalProof()
    {
        foreach (var fallback in new[] { true, false })
        {
            using var h = new Harness();
            Assert.True((await h.Operations.ExecuteOrReplayAsync(WriterRequest("register-image"))).Success);
            if (fallback) h.Backend.OverrideMode = MountAccessMode.ReadOnly;
            else h.Backend.WriterProof = false;
            var result = await h.Operations.ExecuteOrReplayAsync(WriterRequest("unlock"));
            Assert.False(result.Success); Assert.Equal(EncryptedVolumeState.Failed, result.EncryptionState);
            Assert.Equal(fallback ? ApfsControlModes.ReadOnly : ApfsControlModes.ReadWrite, result.EffectiveMode);
            Assert.Single(h.Backend.Mounts); // The original owner still needs the real lock path.
        }
    }

    [Fact] public async Task WriterRejectsChangedCheckpointAndRequestedModeBeforeCredentialOrMutation()
    {
        using var h = new Harness();
        Assert.True((await h.Operations.ExecuteOrReplayAsync(WriterRequest("register-image"))).Success);
        var reads = 0;
        h.Executor.CredentialReceiver = (_, _, _, _) => { ++reads; throw new InvalidOperationException(); };
        var changed = WriterRequest("unlock") with { Target = SelectedControlTarget.ForImage(WriterProfile with { CheckpointXid = 9 }) };
        Assert.False((await h.Operations.ExecuteOrReplayAsync(changed)).Success);
        Assert.False((await h.Operations.ExecuteOrReplayAsync(WriterRequest("unlock") with { RequestedMode = ApfsControlModes.ReadOnly })).Success);
        Assert.Equal(0, reads); Assert.Equal(0, h.Backend.Unlocks); Assert.Empty(h.Backend.Mounts);
    }
}
