using ApfsAccess.Core;
using ApfsAccess.Ipc;
using ApfsAccess.Service;

namespace ApfsAccess.Service.Tests;

public sealed partial class AgentControlCommandExecutorTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ImageRepair_PlainFixResumesOnlyPreviouslyAcceptedOriginalAfterRestartAndExpiry(bool legacy)
    {
        var backend = new RepairBackend();
        var clock = new RepairClock(DateTimeOffset.UtcNow);
        ImageRepairIntent original;
        using (var first = CreateWorker(backend, backend.Root))
        {
            var executor = new AgentControlCommandExecutor(first, timeProvider: clock);
            var request = backend.Fix(legacy);
            var offered = (await executor.ExecuteAsync(request, default)).ImageRepairOffer!;
            backend.ApplyFailure = () => throw new IOException("Mock lost accepted repair response.");
            var failed = await executor.ExecuteAsync(backend.Approve(request, offered), default);
            Assert.False(failed.Success);
            original = backend.Read();
            Assert.True(original.Pending);
        }
        backend.ApplyFailure = null;
        backend.Replay = true;
        backend.Repaired = true;
        backend.Basis.Xid = "8";
        clock.Now = clock.Now.AddMinutes(3);
        using var restarted = CreateWorker(backend, backend.Root);
        var next = backend.Fix(legacy) with { ExpiresAtUtc = clock.Now.UtcDateTime.AddMinutes(2) };
        Assert.Null(next.ApprovedImageRepairPlanId);
        var resumed = await new AgentControlCommandExecutor(restarted, timeProvider: clock).ExecuteAsync(next, default);
        Assert.True(resumed.Success, resumed.Diagnostic);
        Assert.Equal("healthy-rw", resumed.FinalStatus);
        Assert.Null(resumed.ApprovedImageRepairPlanId);
        Assert.Equal(ApfsOperationFingerprint.Compute(next), resumed.Fingerprint);
        Assert.Equal(original.Offer.PlanId, resumed.ImageRepairReceipt!.PlanId);
        Assert.Equal(original.AcceptedOperationId, resumed.ImageRepairReceipt.OriginalAcceptedOperationId);
        Assert.True(resumed.ImageRepairReceipt.Replayed);
        AssertWireResult(resumed);
        var accepted = backend.Calls.Where(call => call.Approval is not null).ToArray();
        Assert.Equal(2, accepted.Length);
        Assert.Equal(accepted[0], accepted[1]);
        Assert.Equal(original.AcceptedOperationId, backend.Read().AcceptedOperationId);
        Assert.Equal(original.AcceptedFingerprint, backend.Read().AcceptedFingerprint);
        Assert.Equal(1, backend.MountCalls);
        Assert.Equal(1, backend.LiveCalls);
    }

    [Fact]
    public async Task ImageRepair_PlainFixDoesNotAcceptAnOfferedButUnapprovedRepair()
    {
        var backend = new RepairBackend();
        using var worker = CreateWorker(backend, backend.Root);
        var executor = new AgentControlCommandExecutor(worker);
        var first = await executor.ExecuteAsync(backend.Fix(true), default);
        Assert.NotNull(first.ImageRepairOffer);
        var again = await executor.ExecuteAsync(backend.Fix(true), default);
        Assert.False(again.Success);
        Assert.Equal("repair-confirmation-required", again.FinalStatus);
        Assert.NotNull(again.ImageRepairOffer);
        Assert.Equal(0, backend.ApplyCalls);
        Assert.Equal(0, backend.MountCalls);
        using var store = new ImageRepairIntentStore(backend.Root);
        Assert.All(store.ReadAll(), intent => Assert.Equal("offered", intent.State));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ImageRepair_PlainFixCannotResumeChangedSelectionOrHideNativeRefusal(bool wrongTarget)
    {
        var backend = new RepairBackend();
        using var worker = CreateWorker(backend, backend.Root);
        var executor = new AgentControlCommandExecutor(worker);
        var request = backend.Fix(false);
        var offered = (await executor.ExecuteAsync(request, default)).ImageRepairOffer!;
        backend.ApplyFailure = () => throw new IOException("Mock lost accepted repair response.");
        Assert.False((await executor.ExecuteAsync(backend.Approve(request, offered), default)).Success);
        var original = backend.Read();
        backend.ApplyFailure = null;
        backend.ApplyRefused = true;
        var retry = backend.Fix(false);
        if (wrongTarget) retry = retry with { Target = retry.Target! with { RecoveryIdentity = "different-original" } };
        var result = await executor.ExecuteAsync(retry, default);
        Assert.False(result.Success);
        Assert.True(backend.Read().Pending);
        Assert.Equal(original.AcceptedOperationId, backend.Read().AcceptedOperationId);
        Assert.Equal(0, backend.MountCalls);
        Assert.Equal(wrongTarget ? 1 : 2, backend.ApplyCalls);
        if (!wrongTarget) Assert.True(result.PendingDurability);
        AssertWireResult(result);
    }
}
