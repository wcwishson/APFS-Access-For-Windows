using System.Diagnostics;
using System.Reflection;
using System.Text.Json;
using ApfsAccess.Backend.Native;
using ApfsAccess.Core;
using Microsoft.Win32.SafeHandles;

namespace ApfsAccess.Backend.Native.Tests;

public sealed partial class HostProcessGuardianTests
{
    [Fact]
    public void BackendLifecycleBareExitCodeNeverClaimsCleanUnmount()
    {
        var type = typeof(NativeApfsBackend).GetNestedType("HostStopResult", BindingFlags.NonPublic)!;
        var stop = Activator.CreateInstance(type, [true, false, 0])!;
        var result = BuildLifecycleUnmount(stop);
        Assert.False(result.Success);
        Assert.False(result.MountRemoved);
        Assert.False(result.HostOwnershipReleased);
        Assert.False(result.PendingDurabilityCleared);
    }

    [Theory]
    [InlineData("absent", "Absent", 1)]
    [InlineData("path-error", "Unknown", 1)]
    [InlineData("access-error", "Unknown", 1)]
    [InlineData("zero-error", "Unknown", 1)]
    [InlineData("present", "Present", 1)]
    [InlineData("buffer-exhausted", "Unknown", 4)]
    [InlineData("buffer-then-present", "Present", 2)]
    [InlineData("buffer-then-absent", "Absent", 2)]
    [InlineData("throws", "Unknown", 1)]
    public void BackendLifecycleDosDeviceProofPreservesProductionQueryFailures(string vector, string expected, int calls)
    {
        var root = CreateTestDirectory();
        var capacities = new List<int>();
        using var backend = LifecycleBackend(root, new HostProcessLifecycleTestHooks
        {
            QueryDosDevice = (name, capacity) =>
            {
                Assert.Equal("R:", name);
                capacities.Add(capacity);
                return vector switch
                {
                    "absent" => (0u, 2),
                    "path-error" => (0u, 3),
                    "access-error" => (0u, 5),
                    "zero-error" => (0u, 0),
                    "present" => (17u, 5), // Last error is irrelevant on success.
                    "buffer-exhausted" => (0u, 122),
                    "buffer-then-present" => capacity == 4096 ? (0u, 122) : (17u, 0),
                    "buffer-then-absent" => capacity == 4096 ? (0u, 122) : (0u, 2),
                    _ => throw new IOException("Injected Win32 query exception."),
                };
            },
            QueryMountAttributes = _ => throw new InvalidOperationException("Must not probe a drive through its filesystem."),
        });
        try
        {
            Assert.Equal(expected, InvokePrivate(backend, "ProbeMountNamespaceForCleanup", "r:\\")!.ToString());
            Assert.Equal(calls, capacities.Count);
            Assert.Equal(Enumerable.Range(0, calls).Select(index => 4096 << index), capacities);
        }
        finally { Directory.Delete(root, true); }
    }

    [Theory]
    [InlineData(0xffffffffu, 2, "Absent")]
    [InlineData(0xffffffffu, 3, "Absent")]
    [InlineData(0xffffffffu, 5, "Unknown")]
    [InlineData(0xffffffffu, 32, "Unknown")]
    [InlineData(0xffffffffu, 123, "Unknown")]
    [InlineData(0x410u, 0, "Present")]
    [InlineData(0x10u, 5, "Absent")]
    [InlineData(0x20u, 0, "Unknown")]
    public void BackendLifecycleDirectoryProofUsesExactPathAndExplicitAttributes(uint attributes, int error, string expected)
    {
        var root = CreateTestDirectory();
        var point = Path.Combine(root, "original-mount");
        var calls = 0;
        using var backend = LifecycleBackend(root, new HostProcessLifecycleTestHooks
        {
            QueryDosDevice = (_, _) => throw new InvalidOperationException("Must not query the directory's drive root."),
            QueryMountAttributes = path =>
            {
                Assert.Equal(point, path);
                calls++;
                return (attributes, error);
            },
        });
        try
        {
            Assert.Equal(expected, InvokePrivate(backend, "ProbeMountNamespaceForCleanup", point)!.ToString());
            Assert.Equal(1, calls);
        }
        finally { Directory.Delete(root, true); }
    }

    [Fact]
    public void BackendLifecycleDirectoryProofReadsOnlyDedicatedNtfsPaths()
    {
        var root = CreateTestDirectory();
        using var backend = LifecycleBackend(root, new HostProcessLifecycleTestHooks());
        try
        {
            var point = Path.Combine(root, "ordinary-directory");
            Directory.CreateDirectory(point);
            Assert.Equal("Absent", InvokePrivate(backend, "ProbeMountNamespaceForCleanup", point)!.ToString());
            Assert.Equal("Absent", InvokePrivate(backend, "ProbeMountNamespaceForCleanup", Path.Combine(root, "missing"))!.ToString());
            var file = Path.Combine(root, "ordinary-file");
            File.WriteAllText(file, "Dedicated offline namespace fixture.");
            Assert.Equal("Unknown", InvokePrivate(backend, "ProbeMountNamespaceForCleanup", file)!.ToString());
        }
        finally { Directory.Delete(root, true); }
    }

    [Theory]
    [InlineData("")]
    [InlineData("relative")]
    [InlineData("R:relative")]
    [InlineData("\\\\synthetic-server\\share")]
    public void BackendLifecycleInvalidNamespaceCannotProbeAnotherScope(string point)
    {
        var root = CreateTestDirectory();
        var calls = 0;
        using var backend = LifecycleBackend(root, new HostProcessLifecycleTestHooks
        {
            QueryDosDevice = (_, _) => { calls++; return (0u, 2); },
            QueryMountAttributes = _ => { calls++; return (0xffffffffu, 2); },
        });
        try
        {
            Assert.Equal("Unknown", InvokePrivate(backend, "ProbeMountNamespaceForCleanup", point)!.ToString());
            Assert.Equal(0, calls);
        }
        finally { Directory.Delete(root, true); }
    }

    [Theory]
    [InlineData(false, 5)]
    [InlineData(false, 3)]
    [InlineData(false, 122)]
    [InlineData(false, -1)]
    [InlineData(true, 5)]
    [InlineData(true, -1)]
    public async Task BackendLifecycleActualFinalProbeRetainsUnknownOwnerAndRetries(bool directory, int error)
    {
        var root = CreateTestDirectory();
        var point = directory ? Path.Combine(root, "original-mount") : "R:\\";
        if (directory) Directory.CreateDirectory(point);
        var uncertain = true;
        var calls = 0;
        var hooks = new HostProcessLifecycleTestHooks
        {
            QueryDosDevice = (name, _) =>
            {
                Assert.False(directory);
                Assert.Equal("R:", name);
                calls++;
                if (uncertain && error == -1) throw new IOException("Query failure.");
                return (0u, uncertain ? error : 2);
            },
            QueryMountAttributes = path =>
            {
                Assert.True(directory);
                Assert.Equal(point, path);
                calls++;
                if (uncertain && error == -1) throw new IOException("Attribute failure.");
                return uncertain ? (uint.MaxValue, error) : (0x10u, 0);
            },
        };
        var lifetimePath = Path.Combine(root, "host.alive");
        using var lifetime = HostLifetimeSentinel.Create(lifetimePath);
        using var gate = HostStartupGate.Create(root);
        var start = DedicatedGuardianChild(root);
        start.Environment["GUARDIAN_CHILD_GRACEFUL_LIFETIME"] = lifetimePath;
        var launch = HostProcessGuardian.Start(start, gate);
        var guardian = launch.Guardian!;
        var original = (SafeProcessHandle)GuardianHandle(guardian, "_processHandle");
        var backend = LifecycleBackend(root, hooks);
        var state = LifecycleState(launch.Process, guardian, lifetime, lifetimePath, gate.FilePath, root);
        state.GetType().GetProperty("OriginalMountPoints")!.SetValue(state, new[] { point });
        try
        {
            WaitForDedicatedReady(root);
            WriteLifecycleTerminal(root, guardian.ProcessId);
            var stop = await StopLifecycleHost(backend, state, CancellationToken.None);
            Assert.True(LifecycleFlag(stop, "ProcessExited"));
            Assert.True(LifecycleFlag(stop, "GuardianSettled"));
            Assert.False(LifecycleFlag(stop, "MountAbsent"));
            Assert.False((bool)InvokePrivate(backend, "CleanupHostResources", state)!);
            Assert.True(calls > 0);
            Assert.Null(hooks.IsMountVisible);
            Assert.True(File.Exists(Path.Combine(root, "host.status.json")));
            Assert.True(File.Exists(gate.FilePath));
            Assert.False(original.IsClosed);
            Assert.False(guardian.OwnershipReleased.IsCompleted);
            var result = BuildLifecycleUnmount(InvokePrivate(backend, "CaptureHostStopResult", state)!);
            Assert.False(result.Success);
            Assert.False(result.HostOwnershipReleased);
            Assert.False(result.PendingDurabilityCleared);
            uncertain = false;
            Assert.True((bool)InvokePrivate(backend, "CleanupHostResources", state)!);
            await guardian.OwnershipReleased.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.True(original.IsClosed);
            Assert.False(File.Exists(Path.Combine(root, "host.status.json")));
            result = BuildLifecycleUnmount(InvokePrivate(backend, "CaptureHostStopResult", state)!);
            Assert.True(result.Success);
            Assert.True(result.HostOwnershipReleased);
            Assert.True(result.PendingDurabilityCleared);
        }
        finally
        {
            uncertain = false;
            guardian.Dispose();
            await guardian.OwnershipReleased.WaitAsync(TimeSpan.FromSeconds(5));
            launch.StartupStderr?.Dispose();
            launch.Process.Dispose();
            backend.Dispose();
            Directory.Delete(root, true);
        }
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task BackendLifecycleGracefulStopPreservesExactExitAndAvoidsKill(bool cancel, bool failObservation)
    {
        var root = CreateTestDirectory();
        var lifetimePath = Path.Combine(root, "host.alive");
        using var lifetime = HostLifetimeSentinel.Create(lifetimePath);
        using var gate = HostStartupGate.Create(root);
        var start = DedicatedGuardianChild(root);
        start.Environment["GUARDIAN_CHILD_GRACEFUL_LIFETIME"] = lifetimePath;
        start.Environment["GUARDIAN_CHILD_GRACEFUL_DELAY_MS"] = "200";
        var launch = HostProcessGuardian.Start(start, gate);
        var guardian = launch.Guardian!;
        var hooks = new HostProcessLifecycleTestHooks { IsMountVisible = _ => false };
        if (failObservation) hooks.WaitForExitAsync = (_, _) => throw new IOException("Injected wait failure.");
        var backend = LifecycleBackend(root, hooks);
        var state = LifecycleState(launch.Process, guardian, lifetime, lifetimePath, gate.FilePath, root);
        try
        {
            WaitForDedicatedReady(root);
            WriteLifecycleTerminal(root, guardian.ProcessId);
            // The suspended-launch Process wrapper is deliberately unusable. The
            // original guardian handle must supply native exit zero independently.
            launch.Process.Dispose();
            using var cancellation = new CancellationTokenSource();
            if (cancel) cancellation.Cancel();
            var elapsed = Stopwatch.StartNew();
            var stop = await StopLifecycleHost(backend, state, cancellation.Token);
            Assert.True(elapsed.Elapsed >= TimeSpan.FromMilliseconds(150));
            Assert.True(LifecycleFlag(stop, "ProcessExited"));
            Assert.False(LifecycleFlag(stop, "ForcedKill"));
            Assert.Equal(0, stop.GetType().GetProperty("ExitCode")!.GetValue(stop));
            Assert.False(BuildLifecycleUnmount(stop).HostOwnershipReleased);
            Assert.True((bool)InvokePrivate(backend, "CleanupHostResources", state)!);
            await guardian.OwnershipReleased.WaitAsync(TimeSpan.FromSeconds(5));
            stop = InvokePrivate(backend, "CaptureHostStopResult", state)!;
            var result = BuildLifecycleUnmount(stop);
            Assert.True(result.Success);
            Assert.True(result.MountRemoved);
            Assert.True(result.HostOwnershipReleased);
            Assert.True(result.PendingDurabilityCleared);
            Assert.False(File.Exists(Path.Combine(root, "host.status.json")));
        }
        finally
        {
            guardian.Dispose();
            await guardian.OwnershipReleased.WaitAsync(TimeSpan.FromSeconds(5));
            launch.StartupStderr?.Dispose();
            launch.Process.Dispose();
            backend.Dispose();
            Directory.Delete(root, true);
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task BackendLifecycleCanceledOrExceptionalStopEnforcesDelayedDescendant(bool throwObservation)
    {
        var root = CreateTestDirectory();
        var allowJob = 0;
        var attempts = 0;
        using var scope = new GuardianCleanupHookScope(new HostGuardianCleanupTestHooks
        {
            TerminateJob = (job, code) =>
            {
                Interlocked.Increment(ref attempts);
                return Volatile.Read(ref allowJob) != 0 && TerminateTestJob(job, code);
            },
        });
        var lifetimePath = Path.Combine(root, "host.alive");
        using var lifetime = HostLifetimeSentinel.Create(lifetimePath);
        using var gate = HostStartupGate.Create(root);
        var launch = HostProcessGuardian.Start(DedicatedGuardianChild(root, descendant: true), gate);
        var guardian = launch.Guardian!;
        var original = (SafeProcessHandle)GuardianHandle(guardian, "_processHandle");
        var jobHandle = GuardianHandle(guardian, "_job");
        var hooks = new HostProcessLifecycleTestHooks { IsMountVisible = _ => false };
        if (throwObservation) hooks.WaitForExitAsync = (_, _) => throw new IOException("Injected wait failure.");
        var backend = LifecycleBackend(root, hooks);
        var state = LifecycleState(launch.Process, guardian, lifetime, lifetimePath, gate.FilePath, root);
        try
        {
            WaitForDedicatedReady(root);
            var descendantPid = uint.Parse(File.ReadAllText(Path.Combine(root, "ready.txt")));
            Assert.True(TestJobActiveProcesses(jobHandle) >= 2);
            WriteLifecycleTerminal(root, guardian.ProcessId);
            using var cancellation = new CancellationTokenSource();
            cancellation.Cancel();
            var elapsed = Stopwatch.StartNew();
            var stopTask = StopLifecycleHost(backend, state, cancellation.Token);
            await Task.Delay(150);
            Assert.Equal(0, Volatile.Read(ref attempts));
            var stop = await stopTask.WaitAsync(TimeSpan.FromSeconds(6));
            Assert.True(elapsed.Elapsed >= TimeSpan.FromSeconds(1));
            Assert.True(LifecycleFlag(stop, "ProcessExited"));
            Assert.True(LifecycleFlag(stop, "ForcedKill"));
            Assert.Equal(13, stop.GetType().GetProperty("ExitCode")!.GetValue(stop));
            Assert.True(Volatile.Read(ref attempts) >= 3);
            Assert.True(TestJobActiveProcesses(jobHandle) >= 1);
            Assert.False((bool)InvokePrivate(backend, "CleanupHostResources", state)!);
            Assert.True(File.Exists(Path.Combine(root, "host.status.json")));
            Assert.True(File.Exists(gate.FilePath));
            Assert.False(original.IsClosed);
            Assert.False(guardian.OwnershipReleased.IsCompleted);
            Assert.False(BuildLifecycleUnmount(stop).Success);
            Volatile.Write(ref allowJob, 1);
            Assert.True(SpinWait.SpinUntil(() => guardian.IsSettled, TimeSpan.FromSeconds(5)));
            Assert.True(SpinWait.SpinUntil(() => DedicatedPidAbsent(descendantPid), TimeSpan.FromSeconds(5)));
            Assert.True((bool)InvokePrivate(backend, "CleanupHostResources", state)!);
            stop = InvokePrivate(backend, "CaptureHostStopResult", state)!;
            var result = BuildLifecycleUnmount(stop);
            Assert.False(result.Success);
            Assert.True(result.HostOwnershipReleased);
            Assert.False(result.PendingDurabilityCleared);
        }
        finally
        {
            Volatile.Write(ref allowJob, 1);
            guardian.Dispose();
            await guardian.OwnershipReleased.WaitAsync(TimeSpan.FromSeconds(5));
            launch.StartupStderr?.Dispose();
            launch.Process.Dispose();
            backend.Dispose();
            Directory.Delete(root, true);
        }
    }

    [Theory]
    [InlineData("mount-present")]
    [InlineData("mount-unknown")]
    [InlineData("status-missing")]
    [InlineData("status-malformed")]
    [InlineData("wrong-owner")]
    [InlineData("mount-ready")]
    [InlineData("wal-pending")]
    [InlineData("missing-drain")]
    [InlineData("duplicate-field")]
    public async Task BackendLifecycleRetainsResourcesUntilMountAndNativeTerminalProof(string failure)
    {
        var root = CreateTestDirectory();
        var mountAbsent = failure is not ("mount-present" or "mount-unknown");
        var probeThrows = failure == "mount-unknown";
        var lifetimePath = Path.Combine(root, "host.alive");
        using var lifetime = HostLifetimeSentinel.Create(lifetimePath);
        using var gate = HostStartupGate.Create(root);
        var start = DedicatedGuardianChild(root);
        start.Environment["GUARDIAN_CHILD_GRACEFUL_LIFETIME"] = lifetimePath;
        var launch = HostProcessGuardian.Start(start, gate);
        var guardian = launch.Guardian!;
        var backend = LifecycleBackend(root, new HostProcessLifecycleTestHooks
        {
            IsMountVisible = _ => probeThrows ? throw new IOException("Unknown namespace.") : !mountAbsent,
        });
        var state = LifecycleState(launch.Process, guardian, lifetime, lifetimePath, gate.FilePath, root);
        try
        {
            WaitForDedicatedReady(root);
            WriteLifecycleTerminal(root, guardian.ProcessId, failure);
            var stop = await StopLifecycleHost(backend, state, CancellationToken.None);
            var result = BuildLifecycleUnmount(stop);
            Assert.False(result.Success);
            Assert.False(result.HostOwnershipReleased);
            Assert.False(result.PendingDurabilityCleared);
            if (failure == "wal-pending")
            {
                // An explicit terminal failure is releasable, but never durable/clean.
                Assert.True((bool)InvokePrivate(backend, "CleanupHostResources", state)!);
                result = BuildLifecycleUnmount(InvokePrivate(backend, "CaptureHostStopResult", state)!);
                Assert.False(result.Success);
                Assert.False(result.PendingDurabilityCleared);
                Assert.True(result.HostOwnershipReleased);
            }
            else
            {
                Assert.False((bool)InvokePrivate(backend, "CleanupHostResources", state)!);
                Assert.True(File.Exists(gate.FilePath));
                Assert.False(guardian.OwnershipReleased.IsCompleted);
                mountAbsent = true;
                probeThrows = false;
                WriteLifecycleTerminal(root, guardian.ProcessId);
                Assert.True((bool)InvokePrivate(backend, "CleanupHostResources", state)!);
                Assert.True(BuildLifecycleUnmount(InvokePrivate(backend, "CaptureHostStopResult", state)!).Success);
            }
        }
        finally
        {
            guardian.Dispose();
            await guardian.OwnershipReleased.WaitAsync(TimeSpan.FromSeconds(5));
            launch.StartupStderr?.Dispose();
            launch.Process.Dispose();
            backend.Dispose();
            Directory.Delete(root, true);
        }
    }

    [Theory]
    [InlineData("same")]
    [InlineData("unknown")]
    [InlineData("exception")]
    public async Task BackendLifecycleOriginalIdentityDistinguishesSameRowFromOwnedReusedRow(string initialRow)
    {
        var root = CreateTestDirectory();
        var newRoot = CreateTestDirectory();
        using var newRow = Process.Start(DedicatedGuardianChild(newRoot))!;
        WaitForDedicatedReady(newRoot);
        var branch = 0;
        long originalCreation = 0;
        using var scope = new GuardianCleanupHookScope(new HostGuardianCleanupTestHooks
        {
            OriginalIdentityAbsent = (_, _) => false,
            CurrentProcessCreationTime = _ => Volatile.Read(ref branch) == 0
                ? initialRow switch { "same" => originalCreation, "exception" => throw new IOException("Unknown current row."), _ => null }
                : newRow.StartTime.ToUniversalTime().ToFileTimeUtc(),
        });
        var lifetimePath = Path.Combine(root, "host.alive");
        using var lifetime = HostLifetimeSentinel.Create(lifetimePath);
        using var gate = HostStartupGate.Create(root);
        var launch = HostProcessGuardian.Start(DedicatedGuardianChild(root), gate);
        var guardian = launch.Guardian!;
        originalCreation = guardian.CreationTimeFileTimeUtc;
        var original = (SafeProcessHandle)GuardianHandle(guardian, "_processHandle");
        var backend = LifecycleBackend(root, new HostProcessLifecycleTestHooks { IsMountVisible = _ => false });
        var state = LifecycleState(launch.Process, guardian, lifetime, lifetimePath, gate.FilePath, root);
        try
        {
            WaitForDedicatedReady(root);
            WriteLifecycleTerminal(root, guardian.ProcessId);
            Assert.NotEqual(originalCreation, newRow.StartTime.ToUniversalTime().ToFileTimeUtc());
            Assert.True(TerminateTestProcess(original, 0));
            Assert.True(launch.Process.WaitForExit(5_000));
            launch.Process.Dispose();
            Assert.Equal(0u, WaitForTestProcess(original, 0));
            Assert.False(guardian.TryObserveProcessExit(out _));
            Assert.False((bool)InvokePrivate(backend, "CleanupHostResources", state)!);
            Assert.True(File.Exists(Path.Combine(root, "host.status.json")));
            Volatile.Write(ref branch, 1);
            Assert.True(guardian.TryObserveProcessExit(out var code));
            Assert.Equal(0, code);
            Assert.True(SpinWait.SpinUntil(() => guardian.IsSettled, TimeSpan.FromSeconds(5)));
            Assert.True((bool)InvokePrivate(backend, "CleanupHostResources", state)!);
            await guardian.OwnershipReleased.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.True(original.IsClosed);
            Assert.True(guardian.TryObserveProcessExit(out code));
            Assert.Equal(0, code);
            Assert.True(BuildLifecycleUnmount(InvokePrivate(backend, "CaptureHostStopResult", state)!).Success);
            Assert.False(newRow.HasExited);
        }
        finally
        {
            Volatile.Write(ref branch, 1);
            guardian.Dispose();
            await guardian.OwnershipReleased.WaitAsync(TimeSpan.FromSeconds(5));
            launch.StartupStderr?.Dispose();
            launch.Process.Dispose();
            var newRowPid = checked((uint)newRow.Id);
            newRow.Kill();
            await newRow.WaitForExitAsync();
            newRow.Dispose();
            Assert.True(SpinWait.SpinUntil(() => DedicatedPidAbsent(newRowPid), TimeSpan.FromSeconds(5)));
            backend.Dispose();
            Directory.Delete(root, true);
            Directory.Delete(newRoot, true);
        }
    }

    [Fact]
    public async Task BackendLifecycleObserverExceptionStillSettlesTrackedOwnership()
    {
        var root = CreateTestDirectory();
        var lifetimePath = Path.Combine(root, "host.alive");
        using var lifetime = HostLifetimeSentinel.Create(lifetimePath);
        using var gate = HostStartupGate.Create(root);
        var launch = HostProcessGuardian.Start(DedicatedGuardianChild(root), gate);
        var guardian = launch.Guardian!;
        var failures = 0;
        var backend = LifecycleBackend(root, new HostProcessLifecycleTestHooks
        {
            IsMountVisible = _ => false,
            WaitForExitAsync = (_, _) => throw new IOException("Failed stop observation."),
            BeforeObserverProof = _ => { Interlocked.Increment(ref failures); throw new IOException("Failed observer observation."); },
        });
        var state = LifecycleState(launch.Process, guardian, lifetime, lifetimePath, gate.FilePath, root);
        state.GetType().GetProperty("TrackedMountPoint")!.SetValue(state, "R:\\");
        var hosts = GetHosts(backend);
        Assert.True((bool)hosts.GetType().GetMethod("TryAdd")!.Invoke(hosts, ["R:\\", state])!);
        try
        {
            WaitForDedicatedReady(root);
            // Missing status forces the real retained-owner observer branch.
            var stop = await StopLifecycleHost(backend, state, new CancellationToken(true));
            Assert.True(LifecycleFlag(stop, "ProcessExited"));
            Assert.True(LifecycleFlag(stop, "ForcedKill"));
            Assert.True(ContainsHost(backend, "R:\\"));
            Assert.True(SpinWait.SpinUntil(() => Volatile.Read(ref failures) > 0, TimeSpan.FromSeconds(5)));
            Assert.True(File.Exists(gate.FilePath));
            WriteLifecycleTerminal(root, guardian.ProcessId);
            Assert.True(SpinWait.SpinUntil(() => !ContainsHost(backend, "R:\\"), TimeSpan.FromSeconds(5)));
            await guardian.OwnershipReleased.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.False(File.Exists(Path.Combine(root, "host.status.json")));
            var result = BuildLifecycleUnmount(InvokePrivate(backend, "CaptureHostStopResult", state)!);
            Assert.False(result.Success);
            Assert.True(result.HostOwnershipReleased);
            Assert.False(result.PendingDurabilityCleared);
        }
        finally
        {
            WriteLifecycleTerminal(root, guardian.ProcessId);
            backend.Dispose();
            guardian.Dispose();
            await guardian.OwnershipReleased.WaitAsync(TimeSpan.FromSeconds(5));
            launch.StartupStderr?.Dispose();
            launch.Process.Dispose();
            Directory.Delete(root, true);
        }
    }

    [Theory]
    [InlineData("later-peer")]
    [InlineData("wrong-start")]
    [InlineData("wrong-container")]
    [InlineData("lease-held")]
    [InlineData("missing-status")]
    [InlineData("production-query-error")]
    public async Task BackendLifecycleContainerReapRequiresOriginalOwnerAndAllPeers(string failure)
    {
        const string uuid = "12345678123412341234123456789abc";
        var root = CreateTestDirectory();
        var lifetimePath = Path.Combine(root, "host.alive");
        using var lifetime = HostLifetimeSentinel.Create(lifetimePath);
        using var gate = HostStartupGate.Create(root);
        var start = DedicatedGuardianChild(root);
        start.Environment["GUARDIAN_CHILD_GRACEFUL_LIFETIME"] = lifetimePath;
        var launch = HostProcessGuardian.Start(start, gate);
        var guardian = launch.Guardian!;
        var laterPeerVisible = failure is "later-peer" or "production-query-error";
        var backend = LifecycleBackend(root, new HostProcessLifecycleTestHooks
        {
            IsMountVisible = failure == "production-query-error" ? null : point => point == "S:\\" && laterPeerVisible,
            QueryDosDevice = (name, _) =>
            {
                Assert.Contains(name, new[] { "R:", "S:" });
                return (0u, name == "S:" && laterPeerVisible ? 5 : 2);
            },
        });
        var state = LifecycleState(launch.Process, guardian, lifetime, lifetimePath, gate.FilePath, root);
        var manifestPath = Path.Combine(root, "launch.manifest.json");
        File.WriteAllText(manifestPath, "Original manifest fixture retained by owner.");
        state.GetType().GetProperty("ContainerUuid")!.SetValue(state, uuid);
        state.GetType().GetProperty("ContainerManifestPath")!.SetValue(state, manifestPath);
        var type = typeof(NativeApfsBackend).GetNestedType("ContainerGroupState", BindingFlags.NonPublic)!;
        var group = Activator.CreateInstance(type, [uuid, "dedicated-fake-device", 0UL, manifestPath, state, false])!;
        var members = group.GetType().GetProperty("Members")!.GetValue(group)!;
        var memberType = typeof(NativeApfsBackend).GetNestedType("ContainerGroupMember", BindingFlags.NonPublic)!;
        foreach (var point in new[] { "R:\\", "S:\\" })
        {
            var member = Activator.CreateInstance(memberType, ["fake-volume", point, 1UL, false, "", true, true, DateTime.UtcNow])!;
            Assert.True((bool)members.GetType().GetMethod("TryAdd")!.Invoke(members, [point, member])!);
        }
        var groups = typeof(NativeApfsBackend).GetField("_containerGroups", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(backend)!;
        Assert.True((bool)groups.GetType().GetMethod("TryAdd")!.Invoke(groups, [uuid, group])!);
        void WriteStatus(bool repaired)
        {
            if (!repaired && failure == "missing-status") return;
            File.WriteAllText(Path.Combine(root, "host.status.json"), JsonSerializer.Serialize(new
            {
                containerUuid = !repaired && failure == "wrong-container" ? "87654321123412341234123456789abc" : uuid,
                ownerPid = guardian.ProcessId,
                ownerStartFileTimeUtc = guardian.CreationTimeFileTimeUtc + (!repaired && failure == "wrong-start" ? 1 : 0),
                leaseHeld = !repaired && failure == "lease-held",
                checkpointXid = 1,
                recoveryRequired = false,
                recoveryVolumeObjectId = (ulong?)null,
                recoveryReason = "",
                volumes = Array.Empty<object>(),
            }));
        }
        try
        {
            WaitForDedicatedReady(root);
            WriteStatus(false);
            await StopLifecycleHost(backend, state, CancellationToken.None);
            Assert.False((bool)InvokePrivate(backend, "ReapContainerGroup_NoLock", group, "offline-proof")!);
            Assert.Equal(1, GetPrivateDictionaryCount(backend, "_containerGroups"));
            Assert.True(File.Exists(manifestPath));
            Assert.True(File.Exists(gate.FilePath));
            Assert.False(guardian.OwnershipReleased.IsCompleted);
            laterPeerVisible = false;
            WriteStatus(true);
            Assert.True((bool)InvokePrivate(backend, "ReapContainerGroup_NoLock", group, "offline-settled")!);
            Assert.Equal(0, GetPrivateDictionaryCount(backend, "_containerGroups"));
            Assert.False(File.Exists(manifestPath));
            Assert.False(File.Exists(Path.Combine(root, "host.status.json")));
            Assert.True(BuildLifecycleUnmount(InvokePrivate(backend, "CaptureHostStopResult", state)!).Success);
        }
        finally
        {
            laterPeerVisible = false;
            WriteStatus(true);
            backend.Dispose();
            guardian.Dispose();
            await guardian.OwnershipReleased.WaitAsync(TimeSpan.FromSeconds(5));
            launch.StartupStderr?.Dispose();
            launch.Process.Dispose();
            Directory.Delete(root, true);
        }
    }

    [Fact]
    public async Task BackendLifecycleCleanupExceptionKeepsSidecarsAndAllowsRetry()
    {
        var root = CreateTestDirectory();
        var lifetimePath = Path.Combine(root, "host.alive");
        using var lifetime = HostLifetimeSentinel.Create(lifetimePath);
        using var gate = HostStartupGate.Create(root);
        var start = DedicatedGuardianChild(root);
        start.Environment["GUARDIAN_CHILD_GRACEFUL_LIFETIME"] = lifetimePath;
        var launch = HostProcessGuardian.Start(start, gate);
        var guardian = launch.Guardian!;
        var backend = LifecycleBackend(root, new HostProcessLifecycleTestHooks { IsMountVisible = _ => false });
        var state = LifecycleState(launch.Process, guardian, lifetime, lifetimePath, gate.FilePath, root);
        using var stream = new FailFirstDisposeStream();
        state.GetType().GetProperty("StartupStderr")!.SetValue(state, HostStartupStderr.Start(stream));
        try
        {
            WaitForDedicatedReady(root);
            WriteLifecycleTerminal(root, guardian.ProcessId);
            await StopLifecycleHost(backend, state, CancellationToken.None);
            Assert.False((bool)InvokePrivate(backend, "CleanupHostResources", state)!);
            Assert.True(File.Exists(Path.Combine(root, "host.status.json")));
            Assert.True(File.Exists(gate.FilePath));
            Assert.False(BuildLifecycleUnmount(InvokePrivate(backend, "CaptureHostStopResult", state)!).Success);
            Assert.True((bool)InvokePrivate(backend, "CleanupHostResources", state)!);
            Assert.False(File.Exists(Path.Combine(root, "host.status.json")));
            Assert.True(BuildLifecycleUnmount(InvokePrivate(backend, "CaptureHostStopResult", state)!).Success);
        }
        finally
        {
            guardian.Dispose();
            await guardian.OwnershipReleased.WaitAsync(TimeSpan.FromSeconds(5));
            launch.StartupStderr?.Dispose();
            launch.Process.Dispose();
            backend.Dispose();
            Directory.Delete(root, true);
        }
    }

    private sealed class FailFirstDisposeStream : MemoryStream
    {
        private int _disposeAttempts;
        protected override void Dispose(bool disposing)
        {
            if (disposing && Interlocked.Increment(ref _disposeAttempts) == 1)
                throw new IOException("Injected retained stream disposal failure.");
            base.Dispose(disposing);
        }
    }

    private static NativeApfsBackend LifecycleBackend(string root, HostProcessLifecycleTestHooks hooks)
        => new(new ServiceHostOptions
        {
            NativeHostStopTimeoutSeconds = 1,
            NativeWriteEvidenceStorePath = Path.Combine(root, "evidence.json"),
        }, hooks);

    private static object LifecycleState(Process process, HostProcessGuardian guardian, HostLifetimeSentinel lifetime,
        string lifetimePath, string gatePath, string root)
    {
        var state = CreateHostProcessState(process, guardian, lifetime, lifetimePath, gatePath,
            Path.Combine(root, "host.status.json"), publishTerminal: false);
        state.GetType().GetProperty("OriginalMountPoints")!.SetValue(state, new[] { "R:\\" });
        return state;
    }

    private static async Task<object> StopLifecycleHost(NativeApfsBackend backend, object state, CancellationToken token)
    {
        var task = (Task)InvokePrivate(backend, "StopHostProcessAsync", state, token)!;
        await task;
        return task.GetType().GetProperty("Result")!.GetValue(task)!;
    }

    private static bool LifecycleFlag(object value, string property)
        => (bool)value.GetType().GetProperty(property)!.GetValue(value)!;

    private static UnmountResult BuildLifecycleUnmount(object stop)
        => (UnmountResult)typeof(NativeApfsBackend).GetMethod("BuildCompletedUnmountResult",
            BindingFlags.NonPublic | BindingFlags.Static)!.Invoke(null, ["R:\\", stop])!;

    private static void WaitForDedicatedReady(string root)
        => Assert.True(SpinWait.SpinUntil(() => File.Exists(Path.Combine(root, "ready.txt")), TimeSpan.FromSeconds(5)));

    private static void WriteLifecycleTerminal(string root, uint processId, string? failure = null)
    {
        var path = Path.Combine(root, "host.status.json");
        if (failure == "status-missing") return;
        if (failure == "status-malformed") { File.WriteAllText(path, "{"); return; }
        var fields = new Dictionary<string, object>
        {
            ["hostPid"] = failure == "wrong-owner" ? processId + 1 : processId,
            ["mountReady"] = failure == "mount-ready",
            ["dirtyTransactionCount"] = 0,
            ["inFlightMutationCallbacks"] = 0,
            ["closeCommitDeferred"] = false,
            ["deferredCommitRequested"] = false,
            ["deferredCommitInFlight"] = false,
            ["walRecoveryStateValid"] = true,
            ["walAcceptedSequence"] = 3,
            ["walApfsDurableSequence"] = failure == "wal-pending" ? 2 : 3,
            ["walCleanupSequence"] = failure == "wal-pending" ? 2 : 3,
            ["shutdownDrainActive"] = true,
            ["payloadSpoolDirtyRangeCount"] = 0,
            ["payloadSpoolIndexDirty"] = false,
            ["payloadSpoolRecoveryRequired"] = false,
        };
        if (failure == "missing-drain") fields.Remove("dirtyTransactionCount");
        var json = JsonSerializer.Serialize(fields);
        if (failure == "duplicate-field") json = json[..^1] + ",\"mountReady\":false}";
        File.WriteAllText(path, json);
    }
}
