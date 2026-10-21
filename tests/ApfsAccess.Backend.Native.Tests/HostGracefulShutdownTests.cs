using System.Diagnostics;
using System.Reflection;
using ApfsAccess.Backend.Native;

namespace ApfsAccess.Backend.Native.Tests;

public sealed partial class HostProcessGuardianTests
{
    [Fact]
    public async Task OrdinaryShutdown_FinalProofSerializesWithObserverCleanup()
    {
        var root = CreateTestDirectory();
        var lifetimePath = Path.Combine(root, "host.alive");
        var release = Path.Combine(root, "test-drain.alive");
        File.WriteAllText(release, "private drain");
        using var lifetime = HostLifetimeSentinel.Create(lifetimePath);
        using var gate = HostStartupGate.Create(root);
        var start = DedicatedGuardianChild(root);
        start.Environment["GUARDIAN_CHILD_GRACEFUL_LIFETIME"] = release;
        var launch = HostProcessGuardian.Start(start, gate);
        var guardian = launch.Guardian!;
        var backend = LifecycleBackend(root, new HostProcessLifecycleTestHooks { IsMountVisible = _ => false });
        var state = LifecycleState(launch.Process, guardian, lifetime, lifetimePath, gate.FilePath, root);
        state.GetType().GetProperty("TrackedMountPoint")!.SetValue(state, "R:\\");
        Assert.True((bool)GetHosts(backend).GetType().GetMethod("TryAdd")!.Invoke(GetHosts(backend), ["R:\\", state])!);
        var finalization = typeof(NativeApfsBackend).GetField("_disposeFinalizationSync", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(backend)!;
        using var lockHeld = new ManualResetEventSlim();
        using var finishCleanup = new ManualResetEventSlim();
        Task? cleanup = null;
        Task? stop = null;
        try
        {
            WaitForDedicatedReady(root);
            WriteLifecycleTerminal(root, guardian.ProcessId, "wal-pending");
            stop = (Task)InvokePrivate(backend, "StopMountedHostProcessAsync", state, CancellationToken.None)!;
            cleanup = Task.Run(() =>
            {
                lock (finalization)
                {
                    lockHeld.Set();
                    Assert.True(finishCleanup.Wait(TimeSpan.FromSeconds(5)));
                    Assert.True((bool)InvokePrivate(backend, "CleanupHostResources", state)!);
                }
            });
            Assert.True(lockHeld.Wait(TimeSpan.FromSeconds(3)));
            WriteLifecycleTerminal(root, guardian.ProcessId);
            File.Delete(release);
            Assert.True(SpinWait.SpinUntil(() => guardian.IsSettled, TimeSpan.FromSeconds(3)));
            await Task.Delay(300);
            Assert.False(stop.IsCompleted, "Final proof must wait for the observer's existing cleanup lock.");
            finishCleanup.Set();
            await cleanup.WaitAsync(TimeSpan.FromSeconds(3));
            await stop.WaitAsync(TimeSpan.FromSeconds(3));
            var result = BuildLifecycleUnmount(stop.GetType().GetProperty("Result")!.GetValue(stop)!);
            Assert.True(result.Success, result.Error);
            Assert.True(result.HostOwnershipReleased);
            Assert.True(result.PendingDurabilityCleared);
        }
        finally
        {
            WriteLifecycleTerminal(root, guardian.ProcessId);
            File.Delete(release);
            finishCleanup.Set();
            if (cleanup is not null) await cleanup.WaitAsync(TimeSpan.FromSeconds(5));
            if (stop is not null) await stop.WaitAsync(TimeSpan.FromSeconds(5));
            guardian.Dispose();
            await guardian.OwnershipReleased.WaitAsync(TimeSpan.FromSeconds(5));
            launch.StartupStderr?.Dispose();
            launch.Process.Dispose();
            backend.Dispose();
            Directory.Delete(root, true);
        }
    }

    [Fact]
    public async Task OrdinaryShutdown_UnpublishedNativeWriterRetainsOriginalReplayOwner()
    {
        var root = CreateTestDirectory();
        var lifetimePath = Path.Combine(root, "host.alive");
        var release = Path.Combine(root, "test-replay.alive");
        File.WriteAllText(release, "private replay stays active until released");
        using var lifetime = HostLifetimeSentinel.Create(lifetimePath);
        using var gate = HostStartupGate.Create(root);
        var start = DedicatedGuardianChild(root);
        start.Environment["GUARDIAN_CHILD_GRACEFUL_LIFETIME"] = release;
        var launch = HostProcessGuardian.Start(start, gate);
        var guardian = launch.Guardian!;
        var observerProofs = 0;
        var diagnostics = new System.Collections.Concurrent.ConcurrentQueue<string>();
        var backend = LifecycleBackend(root, new HostProcessLifecycleTestHooks
        {
            IsMountVisible = _ => false,
            BeforeObserverProof = _ => Interlocked.Increment(ref observerProofs),
            OnLifecycleDiagnostic = diagnostics.Enqueue,
        });
        var state = LifecycleState(launch.Process, guardian, lifetime, lifetimePath, gate.FilePath, root);
        state.GetType().GetProperty("RequestedAccessMode")!.SetValue(state, ApfsAccess.Core.MountAccessMode.ReadWrite);
        state.GetType().GetProperty("ConfiguredWriteBackend")!.SetValue(state, "Native");
        var passed = false;
        try
        {
            WaitForDedicatedReady(root);
            WriteLifecycleTerminal(root, guardian.ProcessId, "wal-pending");
            var stop = (Task)InvokePrivate(backend, "StopStartedHostProcessAsync", "R:\\", state, CancellationToken.None)!;
            await stop.WaitAsync(TimeSpan.FromSeconds(5));
            var proof = stop.GetType().GetProperty("Result")!.GetValue(stop)!;
            Assert.False(LifecycleFlag(proof, "ForcedKill"), "The unpublished Native writer was forced after grace.");
            Assert.False(LifecycleFlag(proof, "ProcessExited"), "The held replay child exited before its release.");
            Assert.True(ContainsHost(backend, "R:\\"));
            Assert.False(guardian.IsSettled, "The original replay guardian must remain unsettled.");
            Assert.False(guardian.OwnershipReleased.IsCompleted, "Replay ownership was released early.");
            await Task.Delay(1200);
            Assert.False(guardian.IsSettled, "The observer must preserve the same accepted replay owner.");
            WriteLifecycleTerminal(root, guardian.ProcessId);
            File.Delete(release);
            await guardian.OwnershipReleased.WaitAsync(TimeSpan.FromSeconds(5));
            var removed = SpinWait.SpinUntil(() => !ContainsHost(backend, "R:\\"), TimeSpan.FromSeconds(5));
            var retained = removed ? null : GetHosts(backend).GetType().GetProperty("Item")!.GetValue(GetHosts(backend), ["R:\\"]);
            var finalProof = retained is null ? null : InvokePrivate(backend, "CaptureHostStopResult", retained);
            Assert.True(removed,
                $"Guardian release must remove the original tracked owner. Root={root}; observerProofs={observerProofs}; " +
                $"observers={GetPrivateDictionaryCount(backend, "_hostExitObservers")}; " +
                $"proof={System.Text.Json.JsonSerializer.Serialize(finalProof)}; diagnostics={string.Join(",", diagnostics)}");
            passed = true;
        }
        finally
        {
            WriteLifecycleTerminal(root, guardian.ProcessId);
            File.Delete(release);
            guardian.Dispose();
            await guardian.OwnershipReleased.WaitAsync(TimeSpan.FromSeconds(5));
            launch.StartupStderr?.Dispose();
            launch.Process.Dispose();
            backend.Dispose();
            if (passed) Directory.Delete(root, true);
        }
    }

    [Theory]
    [InlineData(false, false, false)]
    [InlineData(true, false, false)]
    [InlineData(false, true, false)]
    [InlineData(false, false, true)]
    public async Task OrdinaryShutdown_GraceDeadlineNeverKillsOwnedDrain(bool cancelRequest, bool startObserver, bool disposeBackend)
    {
        var root = CreateTestDirectory();
        var lifetimePath = Path.Combine(root, "host.alive");
        var release = Path.Combine(root, "test-drain.alive");
        File.WriteAllText(release, "The test alone releases this offline child.");
        using var lifetime = HostLifetimeSentinel.Create(lifetimePath);
        using var gate = HostStartupGate.Create(root);
        var start = DedicatedGuardianChild(root);
        start.Environment["GUARDIAN_CHILD_GRACEFUL_LIFETIME"] = release;
        var launch = HostProcessGuardian.Start(start, gate);
        var guardian = launch.Guardian!;
        var killCalls = 0;
        using var cleanupHooks = new GuardianCleanupHookScope(new HostGuardianCleanupTestHooks
        {
            TerminateJob = (job, code) => { Interlocked.Increment(ref killCalls); return TerminateTestJob(job, code); },
        });
        var backend = LifecycleBackend(root, new HostProcessLifecycleTestHooks { IsMountVisible = _ => false });
        var state = LifecycleState(launch.Process, guardian, lifetime, lifetimePath, gate.FilePath, root);
        state.GetType().GetProperty("TrackedMountPoint")!.SetValue(state, "R:\\");
        Assert.True((bool)GetHosts(backend).GetType().GetMethod("TryAdd")!.Invoke(GetHosts(backend), ["R:\\", state])!);
        using var cancellation = new CancellationTokenSource();
        Task<ApfsAccess.Core.UnmountResult>? stop = null;
        try
        {
            WaitForDedicatedReady(root);
            WriteLifecycleTerminal(root, guardian.ProcessId, "wal-pending");
            stop = backend.UnmountAsync("R:\\", cancellation.Token);
            Assert.True(SpinWait.SpinUntil(() => !File.Exists(lifetimePath), TimeSpan.FromSeconds(2)));
            if (cancelRequest) cancellation.Cancel();
            if (startObserver) InvokePrivate(backend, "EnsureHostExitObserver", "R:\\", state);
            if (disposeBackend) await Task.Run(backend.Dispose).WaitAsync(TimeSpan.FromSeconds(3));
            await Task.Delay(1500);

            InvokePrivate(backend, "EnforceHostTermination", state);
            Assert.False(stop.IsCompleted, "An observation deadline cannot finish or kill a pending ordinary drain.");
            Assert.False(guardian.IsSettled);
            Assert.False(guardian.OwnershipReleased.IsCompleted);
            Assert.True(ContainsHost(backend, "R:\\"));
            Assert.Equal(0, Volatile.Read(ref killCalls));
            Assert.False((bool)state.GetType().GetProperty("ForcedTerminationRequested")!.GetValue(state)!);
            Assert.True(File.Exists(Path.Combine(root, "host.status.json")));

            WriteLifecycleTerminal(root, guardian.ProcessId);
            File.Delete(release);
            var result = await stop.WaitAsync(TimeSpan.FromSeconds(8));
            Assert.True(result.Success, result.Error);
            Assert.True(result.MountRemoved);
            Assert.True(result.HostOwnershipReleased);
            Assert.True(result.PendingDurabilityCleared);
            Assert.Equal(0, Volatile.Read(ref killCalls));
            await guardian.OwnershipReleased.WaitAsync(TimeSpan.FromSeconds(5));
        }
        finally
        {
            WriteLifecycleTerminal(root, guardian.ProcessId);
            File.Delete(release);
            if (stop is not null) await stop.WaitAsync(TimeSpan.FromSeconds(10));
            guardian.Dispose();
            await guardian.OwnershipReleased.WaitAsync(TimeSpan.FromSeconds(5));
            launch.StartupStderr?.Dispose();
            launch.Process.Dispose();
            backend.Dispose();
            Directory.Delete(root, true);
        }
    }

    [Theory]
    [InlineData(0)]
    [InlineData(17)]
    public async Task OrdinaryShutdown_ActualFailureNeverBecomesCleanProof(int exitCode)
    {
        var root = CreateTestDirectory();
        var lifetimePath = Path.Combine(root, "host.alive");
        var release = Path.Combine(root, "test-drain.alive");
        File.WriteAllText(release, "retain until the test publishes its actual outcome");
        using var lifetime = HostLifetimeSentinel.Create(lifetimePath);
        using var gate = HostStartupGate.Create(root);
        var start = DedicatedGuardianChild(root);
        start.Environment["GUARDIAN_CHILD_GRACEFUL_LIFETIME"] = release;
        var launch = HostProcessGuardian.Start(start, gate);
        var guardian = launch.Guardian!;
        var backend = LifecycleBackend(root, new HostProcessLifecycleTestHooks { IsMountVisible = _ => false });
        var state = LifecycleState(launch.Process, guardian, lifetime, lifetimePath, gate.FilePath, root);
        Assert.True((bool)GetHosts(backend).GetType().GetMethod("TryAdd")!.Invoke(GetHosts(backend), ["R:\\", state])!);
        Task<ApfsAccess.Core.UnmountResult>? stop = null;
        try
        {
            WaitForDedicatedReady(root);
            WriteLifecycleTerminal(root, guardian.ProcessId, exitCode == 0 ? "wal-pending" : null);
            stop = backend.UnmountAsync("R:\\", CancellationToken.None);
            Assert.True(SpinWait.SpinUntil(() => !File.Exists(lifetimePath), TimeSpan.FromSeconds(2)));
            if (exitCode == 0) File.Delete(release);
            else Assert.True(guardian.TryTerminate((uint)exitCode)); // Deliberate offline native-failure control.
            var result = await stop.WaitAsync(TimeSpan.FromSeconds(8));
            Assert.False(result.Success);
            Assert.False(result.PendingDurabilityCleared);
            Assert.True(result.HostOwnershipReleased);
            Assert.False((bool)state.GetType().GetProperty("ForcedTerminationRequested")!.GetValue(state)!);
            if (exitCode != 0) Assert.Contains(exitCode.ToString(), result.Error);
        }
        finally
        {
            File.Delete(release);
            if (stop is not null) await stop.WaitAsync(TimeSpan.FromSeconds(10));
            guardian.Dispose();
            await guardian.OwnershipReleased.WaitAsync(TimeSpan.FromSeconds(5));
            launch.StartupStderr?.Dispose();
            launch.Process.Dispose();
            backend.Dispose();
            Directory.Delete(root, true);
        }
    }
}
