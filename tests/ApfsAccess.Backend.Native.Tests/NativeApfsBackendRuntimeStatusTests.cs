using System.Reflection;
using System.Diagnostics;
using ApfsAccess.Backend.Native;
using ApfsAccess.Core;

namespace ApfsAccess.Backend.Native.Tests;

public sealed class NativeApfsBackendRuntimeStatusTests
{
    [Fact]
    public async Task ApplyMountedRuntimeState_PropagatesHostAndWalFacts()
    {
        using var statusFile = new TemporaryStatusFile("""
            {
              "writeBackend": "Overlay",
              "nativeWriteReadiness": "MutationReady",
              "nativeWriteSafetyState": "PilotReadWrite",
              "recoveryActive": false,
              "mountReady": true,
              "hostPid": 4242,
              "walAcceptedSequence": 12,
              "walApfsDurableSequence": 10,
              "walCleanupSequence": 8
            }
            """);
        var root = Path.Combine(Path.GetTempPath(), "apfsaccess_phase10", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        using var process = StartLongRunningProcess();
        using var backend = new NativeApfsBackend(CreateOverlayRuntimeOptions());
        SeedMountedHost(
            backend,
            process,
            Path.Combine(root, "lifetime"),
            statusFile.Path,
            configuredWriteBackend: "Overlay",
            writeBackend: "Overlay",
            readiness: NativeWriteReadiness.MutationReady);

        var snapshot = InvokeCaptureRuntimeStatusRefreshSnapshot(backend);
        var statuses = await InvokeReadRuntimeStatusesAsync(backend, snapshot);
        InvokeApplyMountedRuntimeState(backend, snapshot, statuses);

        var mount = GetSeededMount(backend);
        Assert.True(mount.MountReady);
        Assert.Equal(4242, mount.HostProcessId);
        Assert.Equal(12UL, mount.WalAcceptedSequence);
        Assert.Equal(10UL, mount.WalApfsDurableSequence);
        Assert.Equal(8UL, mount.WalCleanupSequence);
        process.Kill(entireProcessTree: true);
    }

    [Fact]
    public async Task ApplyMountedRuntimeState_RejectsSameMetadataStatusChangedAfterUnlockedRead()
    {
        var healthyStatus = """
            {
              "writeBackend": "Overlay",
              "nativeWriteReadiness": "MutationReady",
              "nativeWriteSafetyState": "PilotReadWrite",
              "recoveryActive": false,
              "lastCommitXid": 10,
              "mountReady": true
            }
            """ + new string(' ', 256);
        using var statusFile = new TemporaryStatusFile(healthyStatus);
        var root = Path.Combine(Path.GetTempPath(), "apfsaccess_phase8", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        using var process = StartLongRunningProcess();
        using var backend = new NativeApfsBackend(CreateOverlayRuntimeOptions());
        SeedMountedHost(
            backend,
            process,
            Path.Combine(root, "lifetime"),
            statusFile.Path,
            configuredWriteBackend: "Overlay",
            writeBackend: "Overlay",
            readiness: NativeWriteReadiness.MutationReady);
        var snapshot = InvokeCaptureRuntimeStatusRefreshSnapshot(backend);
        var statuses = await InvokeReadRuntimeStatusesAsync(backend, snapshot);
        var originalLength = new FileInfo(statusFile.Path).Length;
        var originalCreationTime = File.GetCreationTimeUtc(statusFile.Path);
        var originalLastWriteTime = File.GetLastWriteTimeUtc(statusFile.Path);

        var failClosedStatus = """
            {
              "writeBackend": "Overlay",
              "nativeWriteReadiness": "Degraded",
              "nativeWriteSafetyState": "RecoveryBlocked",
              "recoveryActive": true,
              "recoveryReason": "RecoveryMarkerDirty",
              "lastCommitXid": 11,
              "mountReady": true
            }
            """;
        Assert.True(failClosedStatus.Length < healthyStatus.Length);
        await statusFile.WritePreservingIdentityMetadataAsync(
            failClosedStatus.PadRight(healthyStatus.Length));
        Assert.Equal(originalLength, new FileInfo(statusFile.Path).Length);
        Assert.Equal(originalCreationTime, File.GetCreationTimeUtc(statusFile.Path));
        Assert.Equal(originalLastWriteTime, File.GetLastWriteTimeUtc(statusFile.Path));
        InvokeApplyMountedRuntimeState(backend, snapshot, statuses);

        var mount = GetSeededMount(backend);
        Assert.Equal(MountAccessMode.ReadOnly, mount.AccessMode);
        Assert.True(mount.RecoveryActive);
        Assert.Equal("RuntimeStatusChangedBeforeApply", mount.RecoveryReason);
        Assert.Equal(NativeWriteSafetyState.RecoveryBlocked, mount.NativeWriteSafetyState);
        process.Kill(entireProcessTree: true);
    }

    [Fact]
    public async Task ApplyMountedRuntimeState_FailsClosedWhenStatusResultIsMissing()
    {
        using var statusFile = new TemporaryStatusFile("""
            {
              "writeBackend": "Overlay",
              "nativeWriteReadiness": "MutationReady",
              "recoveryActive": false,
              "mountReady": true
            }
            """);
        var root = Path.Combine(Path.GetTempPath(), "apfsaccess_phase8", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        using var process = StartLongRunningProcess();
        using var backend = new NativeApfsBackend(CreateOverlayRuntimeOptions());
        SeedMountedHost(
            backend,
            process,
            Path.Combine(root, "lifetime"),
            statusFile.Path,
            configuredWriteBackend: "Overlay",
            writeBackend: "Overlay",
            readiness: NativeWriteReadiness.MutationReady);
        var snapshot = InvokeCaptureRuntimeStatusRefreshSnapshot(backend);
        var statuses = await InvokeReadRuntimeStatusesAsync(backend, snapshot);
        statuses.GetType().GetMethod("Clear")!.Invoke(statuses, null);

        InvokeApplyMountedRuntimeState(backend, snapshot, statuses);

        var mount = GetSeededMount(backend);
        Assert.Equal(MountAccessMode.ReadOnly, mount.AccessMode);
        Assert.True(mount.RecoveryActive);
        Assert.Equal("RuntimeStatusUntrusted", mount.RecoveryReason);
        Assert.Equal(NativeWriteSafetyState.RecoveryBlocked, mount.NativeWriteSafetyState);
        process.Kill(entireProcessTree: true);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task GetMountStateAsync_FailsClosedWhenRwRuntimeStatusIsUntrusted(bool malformed)
    {
        using var statusFile = new TemporaryStatusFile(malformed ? "{ not-json" : "placeholder");
        if (!malformed)
        {
            File.Delete(statusFile.Path);
        }

        var root = Path.Combine(Path.GetTempPath(), "apfsaccess_phase8", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        using var process = StartLongRunningProcess();
        using var backend = new NativeApfsBackend(CreateOverlayRuntimeOptions());
        SeedMountedHost(
            backend,
            process,
            Path.Combine(root, "lifetime"),
            statusFile.Path,
            configuredWriteBackend: "Overlay",
            writeBackend: "Overlay",
            readiness: NativeWriteReadiness.MutationReady);

        var mounts = await backend.GetMountStateAsync(CancellationToken.None);

        var mount = Assert.Single(mounts);
        Assert.Equal(MountAccessMode.ReadOnly, mount.AccessMode);
        Assert.True(mount.RecoveryActive);
        Assert.Equal("RuntimeStatusUntrusted", mount.RecoveryReason);
        Assert.Equal(NativeWriteSafetyState.RecoveryBlocked, mount.NativeWriteSafetyState);
        process.Kill(entireProcessTree: true);
    }

    [Fact]
    public async Task ReadHostRuntimeStatusCachedAsync_CoalescesConcurrentCacheMisses()
    {
        using var statusFile = new TemporaryStatusFile("""
            {
              "writeBackend": "Native",
              "nativeWriteReadiness": "CommitReady",
              "recoveryActive": false,
              "lastCommitXid": 10
            }
            """);
        using var statusLock = new FileStream(
            statusFile.Path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.None);
        using var backend = new NativeApfsBackend(new ServiceHostOptions());

        var first = InvokeReadHostRuntimeStatusCachedAsync(
            backend,
            statusFile.Path,
            MountAccessMode.ReadWrite,
            configuredWriteBackend: "Native",
            timeout: TimeSpan.FromMilliseconds(600));
        var second = InvokeReadHostRuntimeStatusCachedAsync(
            backend,
            statusFile.Path,
            MountAccessMode.ReadWrite,
            configuredWriteBackend: "Native",
            timeout: TimeSpan.FromMilliseconds(600));
        await Task.Delay(60);
        statusLock.Dispose();

        await Task.WhenAll(first, second);

        Assert.Equal(1, GetPrivateLong(backend, "_runtimeStatusReadOperationCount"));
    }

    [Fact]
    public async Task Dispose_CancelsAndDrainsUnlockedRuntimeStatusRefresh()
    {
        using var statusFile = new TemporaryStatusFile("""
            {
              "writeBackend": "Overlay",
              "nativeWriteReadiness": "MutationReady",
              "recoveryActive": false
            }
            """);
        using var statusLock = new FileStream(
            statusFile.Path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.None);
        var root = Path.Combine(Path.GetTempPath(), "apfsaccess_phase8", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        using var process = StartLongRunningProcess();
        var backend = new NativeApfsBackend(CreateOverlayRuntimeOptions());
        SeedMountedHost(
            backend,
            process,
            Path.Combine(root, "lifetime"),
            statusFile.Path,
            configuredWriteBackend: "Overlay",
            writeBackend: "Overlay",
            readiness: NativeWriteReadiness.MutationReady);
        var refresh = backend.GetMountStateAsync(CancellationToken.None);
        await Task.Delay(60);

        var dispose = Task.Run(backend.Dispose);

        await dispose.WaitAsync(TimeSpan.FromSeconds(5));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            async () =>
            {
                await refresh.WaitAsync(TimeSpan.FromSeconds(2));
            });
    }

    [Fact]
    public async Task Dispose_WaitsForMountQueuedOnLifecycleGate_AndRejectsLaterMounts()
    {
        var backend = new NativeApfsBackend(new ServiceHostOptions
        {
            NativeFsHostPath = Environment.ProcessPath,
        });
        SeedVolume(backend);
        var gate = GetPrivateGate(backend);
        await gate.WaitAsync();
        using var mountCancellation = new CancellationTokenSource();
        var mount = backend.MountAsync(
            new MountRequest(@"\\.\PhysicalDrive9|Main", 'S', MountAccessMode.ReadOnly),
            mountCancellation.Token);
        var dispose = Task.Run(backend.Dispose);
        Task? concurrentDispose = null;

        try
        {
            await Assert.ThrowsAsync<TimeoutException>(
                async () => await dispose.WaitAsync(TimeSpan.FromMilliseconds(200)));
            concurrentDispose = Task.Run(backend.Dispose);
            await Assert.ThrowsAsync<TimeoutException>(
                async () => await concurrentDispose.WaitAsync(TimeSpan.FromMilliseconds(200)));
        }
        finally
        {
            mountCancellation.Cancel();
            try
            {
                await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await mount);
            }
            finally
            {
                gate.Release();
            }
        }

        await dispose.WaitAsync(TimeSpan.FromSeconds(5));
        await Assert.IsAssignableFrom<Task>(concurrentDispose).WaitAsync(TimeSpan.FromSeconds(5));
        await Assert.ThrowsAsync<ObjectDisposedException>(
            async () => await backend.MountAsync(
                new MountRequest(@"\\.\PhysicalDrive9|Main", 'S', MountAccessMode.ReadOnly),
                CancellationToken.None));
    }

    [Fact]
    public async Task Dispose_WaitsForUnmountQueuedOnLifecycleGate()
    {
        var backend = new NativeApfsBackend(CreateOverlayRuntimeOptions());
        var gate = GetPrivateGate(backend);
        await gate.WaitAsync();
        using var unmountCancellation = new CancellationTokenSource();
        var unmount = backend.UnmountAsync("R:\\", unmountCancellation.Token);
        var dispose = Task.Run(backend.Dispose);

        try
        {
            await Assert.ThrowsAsync<TimeoutException>(
                async () => await dispose.WaitAsync(TimeSpan.FromMilliseconds(200)));
        }
        finally
        {
            unmountCancellation.Cancel();
            try
            {
                await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await unmount);
            }
            finally
            {
                gate.Release();
            }
        }

        await dispose.WaitAsync(TimeSpan.FromSeconds(5));
    }

    [Fact]
    public async Task Unmount_CancellationAfterStopSignalDoesNotAbandonHostOwnership()
    {
        var root = Path.Combine(Path.GetTempPath(), "apfsaccess_phase8", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        var lifetimePath = Path.Combine(root, "lifetime");
        var statusPath = Path.Combine(root, "status.json");
        File.WriteAllText(lifetimePath, "alive");
        File.WriteAllText(statusPath, "{}");

        using var process = StartLongRunningProcess();
        var processId = process.Id;
        using var backend = new NativeApfsBackend(CreateOverlayRuntimeOptions());
        SeedMountedHost(
            backend,
            process,
            lifetimePath,
            statusPath,
            configuredWriteBackend: "Overlay",
            writeBackend: "Overlay",
            readiness: NativeWriteReadiness.MutationReady);
        using var cancellation = new CancellationTokenSource();

        try
        {
            var unmount = backend.UnmountAsync("R:\\", cancellation.Token);
            var stopSignalDeadline = DateTime.UtcNow + TimeSpan.FromSeconds(2);
            while (File.Exists(lifetimePath) && DateTime.UtcNow < stopSignalDeadline)
            {
                await Task.Delay(10);
            }
            Assert.False(File.Exists(lifetimePath));
            cancellation.Cancel();

            var result = await unmount.WaitAsync(TimeSpan.FromSeconds(5));

            Assert.Throws<ArgumentException>(() => Process.GetProcessById(processId));
            Assert.True(result.MountRemoved);
        }
        finally
        {
            try
            {
                using var remaining = Process.GetProcessById(processId);
                remaining.Kill(entireProcessTree: true);
                remaining.WaitForExit(2_000);
            }
            catch (ArgumentException)
            {
                // The expected path already reaped the process.
            }

            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task Unmount_CancellationWhileWaitingForDriveRemovalPreservesCompletedStop()
    {
        using var backend = new NativeApfsBackend(CreateOverlayRuntimeOptions());
        SeedCompletedHostStop(backend, "C:\\");
        using var cancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => backend.UnmountAsync("C:\\", cancellation.Token));

        Assert.True(HasCompletedHostStop(backend, "C:\\"));
    }

    [Fact]
    public async Task GetMountStateAsync_WritesFailClosedMarkerOnlyAfterGateIsReleased()
    {
        using var statusFile = new TemporaryStatusFile("{ not-json");
        var root = Path.Combine(Path.GetTempPath(), "apfsaccess_phase8", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        using var process = StartLongRunningProcess();
        using var backend = new NativeApfsBackend(CreateOverlayRuntimeOptions());
        SeedMountedHost(
            backend,
            process,
            Path.Combine(root, "lifetime"),
            statusFile.Path,
            configuredWriteBackend: "Overlay",
            writeBackend: "Overlay",
            readiness: NativeWriteReadiness.MutationReady);

        var mounts = await backend.GetMountStateAsync(CancellationToken.None);

        Assert.Equal(MountAccessMode.ReadOnly, Assert.Single(mounts).AccessMode);
        Assert.Equal(0, GetPrivateLong(backend, "_writeSessionMarkerIoWhileGateHeldCount"));
        process.Kill(entireProcessTree: true);
    }

    [Fact]
    public async Task GetMountStateAsync_DoesNotReapplyRwSnapshotAfterHostExitsDuringStatusRead()
    {
        var root = Path.Combine(Path.GetTempPath(), "apfsaccess_phase8", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        var lifetimePath = Path.Combine(root, "lifetime");
        var statusPath = Path.Combine(root, "status.json");
        using var process = StartLongRunningProcess();
        using var backend = new NativeApfsBackend(new ServiceHostOptions());
        await File.WriteAllTextAsync(
            statusPath,
            "{\"writeBackend\":\"Native\",\"recoveryActive\":true,\"recoveryReason\":\"InjectedStatus\"}");
        using var statusLock = new FileStream(
            statusPath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.None);

        SeedMountedHost(backend, process, lifetimePath, statusPath);
        var refreshTask = backend.GetMountStateAsync(CancellationToken.None);
        await Task.Delay(60);
        process.Kill(entireProcessTree: true);
        statusLock.Dispose();

        var mounts = await refreshTask;

        var mount = Assert.Single(mounts);
        Assert.Equal(MountAccessMode.ReadOnly, mount.AccessMode);
        Assert.True(mount.RecoveryActive);
        Assert.Equal("FsHostExitedUnexpectedly", mount.RecoveryReason);
        Assert.Equal(NativeWriteSafetyState.RecoveryBlocked, mount.NativeWriteSafetyState);
    }

    [Fact]
    public async Task GetMountStateAsync_DoesNotApplyOldHostStatusToReplacementHost()
    {
        using var oldStatusFile = new TemporaryStatusFile("""
            {
              "writeBackend": "Native",
              "nativeWriteReadiness": "Degraded",
              "recoveryActive": true,
              "recoveryReason": "OldHostRecovery"
            }
            """);
        using var oldStatusLock = new FileStream(
            oldStatusFile.Path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.None);
        using var replacementStatusFile = new TemporaryStatusFile("""
            {
              "writeBackend": "Native",
              "nativeWriteReadiness": "CommitReady",
              "recoveryActive": false
            }
            """);
        var root = Path.Combine(Path.GetTempPath(), "apfsaccess_phase8", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        using var oldProcess = StartLongRunningProcess();
        using var replacementProcess = StartLongRunningProcess();
        using var backend = new NativeApfsBackend(new ServiceHostOptions());
        SeedMountedHost(
            backend,
            oldProcess,
            Path.Combine(root, "old-lifetime"),
            oldStatusFile.Path);
        var refresh = backend.GetMountStateAsync(CancellationToken.None);
        var readStartTimeout = Stopwatch.StartNew();
        while (GetPrivateLong(backend, "_runtimeStatusReadOperationCount") == 0 &&
               readStartTimeout.Elapsed < TimeSpan.FromSeconds(2))
        {
            await Task.Delay(10);
        }
        Assert.Equal(1, GetPrivateLong(backend, "_runtimeStatusReadOperationCount"));
        var replacement = new MountedVolumeState(
            VolumeId: @"\\.\PhysicalDrive9|Replacement",
            MountPoint: "R:\\",
            AccessMode: MountAccessMode.ReadWrite,
            VolumeName: "Replacement",
            DeviceId: @"\\.\PhysicalDrive9",
            WriteBackend: "Native",
            NativeWriteReadiness: NativeWriteReadiness.CommitReady,
            NativeWriteSafetyState: NativeWriteSafetyState.PilotReadWrite);
        ReplaceMountedHost(
            backend,
            replacementProcess,
            Path.Combine(root, "replacement-lifetime"),
            replacementStatusFile.Path,
            replacement);
        oldStatusLock.Dispose();

        var mount = Assert.Single(await refresh);

        Assert.Equal(replacement, mount);
        Assert.False(mount.RecoveryActive);
        Assert.Null(mount.RecoveryReason);
        oldProcess.Kill(entireProcessTree: true);
        replacementProcess.Kill(entireProcessTree: true);
    }

    private static Process StartLongRunningProcess()
    {
        var process = Process.Start(new ProcessStartInfo
        {
            FileName = Path.Combine(Environment.SystemDirectory, "PING.EXE"),
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            ArgumentList =
            {
                "-n",
                "20",
                "127.0.0.1",
            },
        });
        return process ?? throw new InvalidOperationException("Could not start the test host process.");
    }

    private static void SeedMountedHost(
        NativeApfsBackend backend,
        Process process,
        string lifetimePath,
        string statusPath,
        string configuredWriteBackend = "Native",
        string writeBackend = "Native",
        NativeWriteReadiness readiness = NativeWriteReadiness.CommitReady)
    {
        const string mountPoint = "R:\\";
        var hostType = typeof(NativeApfsBackend).GetNestedType(
            "HostProcessState",
            BindingFlags.NonPublic);
        Assert.NotNull(hostType);

        var host = Activator.CreateInstance(
            hostType!,
            BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic,
            binder: null,
            args: [process, lifetimePath, statusPath, MountAccessMode.ReadWrite, configuredWriteBackend],
            culture: null);
        Assert.NotNull(host);

        var hostMap = typeof(NativeApfsBackend)
            .GetField("_hosts", BindingFlags.NonPublic | BindingFlags.Instance)!
            .GetValue(backend)!;
        var mountMap = typeof(NativeApfsBackend)
            .GetField("_mounts", BindingFlags.NonPublic | BindingFlags.Instance)!
            .GetValue(backend)!;
        var volumeMap = typeof(NativeApfsBackend)
            .GetField("_volumeCache", BindingFlags.NonPublic | BindingFlags.Instance)!
            .GetValue(backend)!;
        Assert.True((bool)hostMap.GetType().GetMethod("TryAdd")!.Invoke(hostMap, [mountPoint, host])!);
        Assert.True((bool)mountMap.GetType().GetMethod("TryAdd")!.Invoke(
            mountMap,
            [
                mountPoint,
                new MountedVolumeState(
                    VolumeId: @"\\.\PhysicalDrive9|Main",
                    MountPoint: mountPoint,
                    AccessMode: MountAccessMode.ReadWrite,
                    VolumeName: "Main",
                    DeviceId: @"\\.\PhysicalDrive9",
                    WriteBackend: writeBackend,
                    NativeWriteReadiness: readiness,
                    NativeWriteSafetyState: NativeWriteSafetyState.PilotReadWrite)
            ])!);
        Assert.True((bool)volumeMap.GetType().GetMethod("TryAdd")!.Invoke(
            volumeMap,
            [
                @"\\.\PhysicalDrive9|Main",
                new VolumeInfo(
                    VolumeId: @"\\.\PhysicalDrive9|Main",
                    DeviceId: @"\\.\PhysicalDrive9",
                    VolumeName: "Main",
                    SupportsReadWrite: true,
                    SupportsNativeWrite: true)
            ])!);
    }

    private static void SeedCompletedHostStop(NativeApfsBackend backend, string mountPoint)
    {
        var stopType = typeof(NativeApfsBackend).GetNestedType(
            "HostStopResult",
            BindingFlags.NonPublic);
        Assert.NotNull(stopType);
        var stop = Activator.CreateInstance(
            stopType!,
            BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic,
            binder: null,
            args: [true, false, 0],
            culture: null);
        Assert.NotNull(stop);

        var stopMap = typeof(NativeApfsBackend)
            .GetField("_completedHostStops", BindingFlags.NonPublic | BindingFlags.Instance)!
            .GetValue(backend)!;
        Assert.True((bool)stopMap.GetType().GetMethod("TryAdd")!.Invoke(
            stopMap,
            [mountPoint, stop])!);
    }

    private static bool HasCompletedHostStop(NativeApfsBackend backend, string mountPoint)
    {
        var stopMap = typeof(NativeApfsBackend)
            .GetField("_completedHostStops", BindingFlags.NonPublic | BindingFlags.Instance)!
            .GetValue(backend)!;
        return (bool)stopMap.GetType().GetMethod("ContainsKey")!.Invoke(
            stopMap,
            [mountPoint])!;
    }

    private static void SeedVolume(NativeApfsBackend backend)
    {
        var volumeMap = typeof(NativeApfsBackend)
            .GetField("_volumeCache", BindingFlags.NonPublic | BindingFlags.Instance)!
            .GetValue(backend)!;
        Assert.True((bool)volumeMap.GetType().GetMethod("TryAdd")!.Invoke(
            volumeMap,
            [
                @"\\.\PhysicalDrive9|Main",
                new VolumeInfo(
                    VolumeId: @"\\.\PhysicalDrive9|Main",
                    DeviceId: @"\\.\PhysicalDrive9",
                    VolumeName: "Main",
                    SupportsReadWrite: true,
                    SupportsNativeWrite: true)
            ])!);
    }

    private static SemaphoreSlim GetPrivateGate(NativeApfsBackend backend)
        => Assert.IsType<SemaphoreSlim>(typeof(NativeApfsBackend)
            .GetField("_gate", BindingFlags.NonPublic | BindingFlags.Instance)!
            .GetValue(backend));

    private static void ReplaceMountedHost(
        NativeApfsBackend backend,
        Process process,
        string lifetimePath,
        string statusPath,
        MountedVolumeState mount)
    {
        var hostType = typeof(NativeApfsBackend).GetNestedType(
            "HostProcessState",
            BindingFlags.NonPublic);
        Assert.NotNull(hostType);
        var host = Activator.CreateInstance(
            hostType!,
            BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic,
            binder: null,
            args: [process, lifetimePath, statusPath, MountAccessMode.ReadWrite, "Native"],
            culture: null);
        Assert.NotNull(host);

        var hostMap = typeof(NativeApfsBackend)
            .GetField("_hosts", BindingFlags.NonPublic | BindingFlags.Instance)!
            .GetValue(backend)!;
        var mountMap = typeof(NativeApfsBackend)
            .GetField("_mounts", BindingFlags.NonPublic | BindingFlags.Instance)!
            .GetValue(backend)!;
        hostMap.GetType().GetProperty("Item")!.SetValue(hostMap, host, ["R:\\"]);
        mountMap.GetType().GetProperty("Item")!.SetValue(mountMap, mount, ["R:\\"]);
        var versionField = typeof(NativeApfsBackend).GetField(
            "_mountStateVersion",
            BindingFlags.NonPublic | BindingFlags.Instance)!;
        versionField.SetValue(backend, (long)versionField.GetValue(backend)! + 1);
    }

    private static ServiceHostOptions CreateOverlayRuntimeOptions()
        => new()
        {
            EnableNativeWrite = true,
            WriteRolloutChannel = "Enabled",
            WriteBackendMode = "Overlay",
            NativeWriteAllowRawPhysicalDevices = true,
            NativeWritePromotionPolicy = "Pilot",
            NativeWriteRequireCanonicalCommit = false,
            NativeWriteDisallowScaffoldCommitOnNonFixture = false,
            NativeWriteRejectScaffoldReplayBlobOnNonFixture = false,
            NativeWriteRequireCanonicalReplayCandidateOnNonFixture = false,
            NativeWriteCrossOsValidationRequired = false,
            NativeWriteCrashFaultMatrixRequired = false,
            NativeWriteRequireMacOsValidationForStable = false,
            NativeWriteStableRequiresPowerLossPass = false,
            NativeHostStopTimeoutSeconds = 1,
            NativeWriteEvidenceStorePath = Path.Combine(
                Path.GetTempPath(),
                "apfsaccess_phase8",
                Guid.NewGuid().ToString("N"),
                "evidence.json"),
        };

    private static object InvokeCaptureRuntimeStatusRefreshSnapshot(NativeApfsBackend backend)
    {
        var method = typeof(NativeApfsBackend).GetMethod(
            "CaptureRuntimeStatusRefreshSnapshot_NoLock",
            BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(method);
        var snapshot = method!.Invoke(backend, null);
        Assert.NotNull(snapshot);
        return snapshot!;
    }

    private static async Task<object> InvokeReadRuntimeStatusesAsync(NativeApfsBackend backend, object snapshot)
    {
        var method = typeof(NativeApfsBackend).GetMethod(
            "ReadRuntimeStatusesAsync",
            BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(method);
        var taskObject = method!.Invoke(backend, [snapshot, CancellationToken.None]);
        var task = Assert.IsAssignableFrom<Task>(taskObject);
        await task.ConfigureAwait(false);
        var result = taskObject!.GetType().GetProperty("Result")!.GetValue(taskObject);
        Assert.NotNull(result);
        return result!;
    }

    private static void InvokeApplyMountedRuntimeState(
        NativeApfsBackend backend,
        object snapshot,
        object statuses)
    {
        var method = typeof(NativeApfsBackend).GetMethod(
            "ApplyMountedRuntimeState_NoLock",
            BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(method);
        method!.Invoke(backend, [snapshot, statuses]);
    }

    private static MountedVolumeState GetSeededMount(NativeApfsBackend backend)
    {
        var mountMap = typeof(NativeApfsBackend)
            .GetField("_mounts", BindingFlags.NonPublic | BindingFlags.Instance)!
            .GetValue(backend)!;
        var values = Assert.IsAssignableFrom<IEnumerable<MountedVolumeState>>(
            mountMap.GetType().GetProperty("Values")!.GetValue(mountMap));
        return Assert.Single(values);
    }

    private static long GetPrivateLong(NativeApfsBackend backend, string fieldName)
    {
        var field = typeof(NativeApfsBackend).GetField(
            fieldName,
            BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(field);
        return Assert.IsType<long>(field!.GetValue(backend));
    }

    [Theory]
    [InlineData(true, false, 0, true)]
    [InlineData(true, false, 10, false)]
    [InlineData(true, true, 0, false)]
    [InlineData(false, false, null, false)]
    public void IsCleanHostStop_RequiresNaturalZeroExit(
        bool processExited,
        bool forcedKill,
        int? exitCode,
        bool expected)
    {
        var method = typeof(NativeApfsBackend).GetMethod(
            "IsCleanHostStop",
            BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        var result = method!.Invoke(null, [processExited, forcedKill, exitCode]);
        Assert.Equal(expected, Assert.IsType<bool>(result));
    }

    [Theory]
    [InlineData(true, false, MountAccessMode.ReadWrite, "Native", false)]
    [InlineData(true, true, MountAccessMode.ReadWrite, "Native", true)]
    [InlineData(false, true, MountAccessMode.ReadWrite, "Native", true)]
    [InlineData(true, false, MountAccessMode.ReadOnly, "Native", true)]
    [InlineData(true, false, MountAccessMode.ReadWrite, "Overlay", true)]
    public void IsMountStartupReady_RequiresSettledStatusForNativeReadWrite(
        bool driveVisible,
        bool hostMountReady,
        MountAccessMode accessMode,
        string configuredWriteBackend,
        bool expected)
    {
        var method = typeof(NativeApfsBackend).GetMethod(
            "IsMountStartupReady",
            BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        var result = method!.Invoke(
            null,
            [driveVisible, hostMountReady, accessMode, configuredWriteBackend]);
        Assert.Equal(expected, Assert.IsType<bool>(result));
    }

    [Fact]
    public async Task ReadHostRuntimeStatusAsync_ReturnsFallback_WhenStatusFileMissing()
    {
        var missingPath = Path.Combine(Path.GetTempPath(), $"apfsaccess_missing_{Guid.NewGuid():N}.status.json");
        var status = await InvokeReadHostRuntimeStatusAsync(
            statusFilePath: missingPath,
            accessMode: MountAccessMode.ReadWrite,
            configuredWriteBackend: "Native",
            timeout: TimeSpan.FromMilliseconds(220));

        Assert.Equal("Native", status.WriteBackend);
        Assert.Equal(NativeWriteReadiness.BootstrapReady, status.NativeWriteReadiness);
        Assert.Equal(NativeWriteValidationState.Scaffold, status.NativeWriteValidationState);
        Assert.False(status.RecoveryActive);
        Assert.Null(status.RecoveryReason);
        Assert.Null(status.LastCommitXid);
        Assert.Equal(NativeWriteSafetyState.PilotReadWrite, status.NativeWriteSafetyState);
        Assert.Null(status.LastRecoveryAction);
        Assert.Equal(0, status.DirtyTransactionCount);
        Assert.False(status.ShutdownDrainActive);
        Assert.Equal(0, status.InFlightMutationCallbacks);
        Assert.Equal(0, status.HostProcessId);
    }

    [Fact]
    public async Task ReadHostRuntimeStatusAsync_NormalizesNativePayloadValues()
    {
        using var statusFile = new TemporaryStatusFile("""
            {
              "writeBackend": " native ",
              "nativeWriteReadiness": " commitready ",
              "nativeWriteValidationState": " canonicalimagevalidated ",
              "nativeWriteSafetyState": " pilotreadwrite ",
              "recoveryActive": true,
              "recoveryReason": "  RecoveryMarkerDirty  ",
              "lastCommitXid": 77,
              "lastRecoveryAction": "ReplaySkippedFailClosed",
              "dirtyTransactionCount": 9,
              "shutdownDrainActive": true,
              "inFlightMutationCallbacks": 4,
              "validationCrashFaultPasses": 3,
              "validationCrashStageMatrixPasses": 4,
              "validationHardwarePilotPasses": 5,
              "validationHotUnplugPasses": 6,
              "validationMacOsValidationPasses": 7,
              "validationMacOsConsistencyPasses": 8,
              "validationPowerLossReplayPasses": 9,
              "validationPowerLossPassVerified": true,
              "validationLastValidatedUtc": "2026-02-24T01:02:03Z",
              "validationLastValidationProfileId": "raw::pd3::main",
              "fixtureLegacyFallbackActive": true,
              "fixtureCompatibilityPathActive": true,
              "usesScaffoldCommitBlob": true,
              "commitStage": " before-checkpoint-switch ",
              "replayStage": " replay-before-checkpoint-switch ",
              "commitBlobMagic": " APFSRWCANON3 ",
              "canonicalPathActive": false,
              "canonicalGateFailure": " CanonicalStateNotLoaded ",
              "replayCheckpointCandidatePresent": true,
              "replayCheckpointPendingWindow": false
            }
            """);

        var status = await InvokeReadHostRuntimeStatusAsync(
            statusFilePath: statusFile.Path,
            accessMode: MountAccessMode.ReadWrite,
            configuredWriteBackend: "Overlay",
            timeout: TimeSpan.FromMilliseconds(220));

        Assert.Equal("Native", status.WriteBackend);
        Assert.Equal(NativeWriteReadiness.CommitReady, status.NativeWriteReadiness);
        Assert.Equal(NativeWriteValidationState.Scaffold, status.NativeWriteValidationState);
        Assert.True(status.RecoveryActive);
        Assert.Equal("RecoveryMarkerDirty", status.RecoveryReason);
        Assert.Equal((ulong)77, status.LastCommitXid);
        Assert.Equal(NativeWriteSafetyState.RecoveryBlocked, status.NativeWriteSafetyState);
        Assert.Equal("ReplaySkippedFailClosed", status.LastRecoveryAction);
        Assert.Equal(9, status.DirtyTransactionCount);
        Assert.True(status.ShutdownDrainActive);
        Assert.Equal(4, status.InFlightMutationCallbacks);
        Assert.NotNull(status.ValidationEvidence);
        Assert.Equal(3, status.ValidationEvidence!.CrashFaultPasses);
        Assert.Equal(4, status.ValidationEvidence.CrashStageMatrixPasses);
        Assert.Equal(5, status.ValidationEvidence.HardwarePilotPasses);
        Assert.Equal(6, status.ValidationEvidence.HotUnplugPasses);
        Assert.Equal(7, status.ValidationEvidence.MacOsValidationPasses);
        Assert.Equal(8, status.ValidationEvidence.MacOsConsistencyPasses);
        Assert.Equal(9, status.ValidationEvidence.PowerLossReplayPasses);
        Assert.True(status.ValidationEvidence.PowerLossPassVerified);
        Assert.Equal(DateTime.Parse("2026-02-24T01:02:03Z").ToUniversalTime(), status.ValidationEvidence.LastValidatedUtc);
        Assert.Equal("raw::pd3::main", status.ValidationEvidence.LastValidationProfileId);
        Assert.True(status.FixtureLegacyFallbackActive);
        Assert.True(status.FixtureCompatibilityPathActive);
        Assert.True(status.UsesScaffoldCommitBlob);
        Assert.Equal("before-checkpoint-switch", status.CommitStage);
        Assert.Equal("replay-before-checkpoint-switch", status.ReplayStage);
        Assert.Equal("APFSRWCANON3", status.CommitBlobMagic);
        Assert.False(status.CanonicalPathActive);
        Assert.Equal("CanonicalStateNotLoaded", status.CanonicalGateFailure);
        Assert.True(status.ReplayCheckpointCandidatePresent);
        Assert.False(status.ReplayCheckpointPendingWindow);
    }

    [Theory]
    [InlineData("ScaffoldCheckpoint", "CommitReady", false)]
    [InlineData("CanonicalApfsCheckpoint", "BootstrapReady", false)]
    [InlineData("CanonicalApfsCheckpoint", "CommitReady", true)]
    public async Task ReadHostRuntimeStatusAsync_ClampsReportedValidationState_WhenCanonicalEligibilityMissing(
        string commitModel,
        string readiness,
        bool recoveryActive)
    {
        using var statusFile = new TemporaryStatusFile($$"""
            {
              "writeBackend": "Native",
              "commitModel": "{{commitModel}}",
              "nativeWriteReadiness": "{{readiness}}",
              "nativeWriteValidationState": "Stable",
              "recoveryActive": {{(recoveryActive ? "true" : "false")}},
              "lastCommitXid": 79
            }
            """);

        var status = await InvokeReadHostRuntimeStatusAsync(
            statusFilePath: statusFile.Path,
            accessMode: MountAccessMode.ReadWrite,
            configuredWriteBackend: "Native",
            timeout: TimeSpan.FromMilliseconds(220));

        Assert.Equal("Native", status.WriteBackend);
        Assert.Equal(NativeWriteValidationState.Scaffold, status.NativeWriteValidationState);
        Assert.Equal((ulong)79, status.LastCommitXid);
    }

    [Fact]
    public async Task ReadHostRuntimeStatusAsync_UnknownBackendFallsBackToOverlayAndClampsReadiness()
    {
        using var statusFile = new TemporaryStatusFile("""
            {
              "writeBackend": "mystery",
              "nativeWriteReadiness": "CommitReady",
              "recoveryActive": false,
              "lastCommitXid": 10
            }
            """);

        var status = await InvokeReadHostRuntimeStatusAsync(
            statusFilePath: statusFile.Path,
            accessMode: MountAccessMode.ReadWrite,
            configuredWriteBackend: "Overlay",
            timeout: TimeSpan.FromMilliseconds(220));

        Assert.Equal("Overlay", status.WriteBackend);
        Assert.Equal(NativeWriteReadiness.MutationReady, status.NativeWriteReadiness);
        Assert.Equal(NativeWriteValidationState.Scaffold, status.NativeWriteValidationState);
        Assert.False(status.RecoveryActive);
        Assert.Equal((ulong)10, status.LastCommitXid);
        Assert.Equal(NativeWriteSafetyState.PilotReadWrite, status.NativeWriteSafetyState);
    }

    [Fact]
    public async Task ReadHostRuntimeStatusAsync_ReadOnlyForcesDisabledTelemetry()
    {
        using var statusFile = new TemporaryStatusFile("""
            {
              "writeBackend": "Native",
              "nativeWriteReadiness": "CommitReady",
              "recoveryActive": true,
              "recoveryReason": "best-effort",
              "lastCommitXid": 91
            }
            """);

        var status = await InvokeReadHostRuntimeStatusAsync(
            statusFilePath: statusFile.Path,
            accessMode: MountAccessMode.ReadOnly,
            configuredWriteBackend: "Native",
            timeout: TimeSpan.FromMilliseconds(220));

        Assert.Equal("Disabled", status.WriteBackend);
        Assert.Equal(NativeWriteReadiness.Unavailable, status.NativeWriteReadiness);
        Assert.Equal(NativeWriteValidationState.Scaffold, status.NativeWriteValidationState);
        Assert.True(status.RecoveryActive);
        Assert.Equal("best-effort", status.RecoveryReason);
        Assert.Equal((ulong)91, status.LastCommitXid);
        Assert.Equal(NativeWriteSafetyState.ReadOnlyFallback, status.NativeWriteSafetyState);
    }

    [Fact]
    public async Task ReadHostRuntimeStatusAsync_ZeroCommitXidNormalizesToNull()
    {
        using var statusFile = new TemporaryStatusFile("""
            {
              "writeBackend": "Native",
              "nativeWriteReadiness": "BootstrapReady",
              "recoveryActive": false,
              "lastCommitXid": 0
            }
            """);

        var status = await InvokeReadHostRuntimeStatusAsync(
            statusFilePath: statusFile.Path,
            accessMode: MountAccessMode.ReadWrite,
            configuredWriteBackend: "Native",
            timeout: TimeSpan.FromMilliseconds(220));

        Assert.Equal("Native", status.WriteBackend);
        Assert.Equal(NativeWriteReadiness.BootstrapReady, status.NativeWriteReadiness);
        Assert.Equal(NativeWriteValidationState.Scaffold, status.NativeWriteValidationState);
        Assert.Null(status.LastCommitXid);
        Assert.Equal(NativeWriteSafetyState.PilotReadWrite, status.NativeWriteSafetyState);
    }

    [Fact]
    public async Task ReadHostRuntimeStatusAsync_CanonicalizesKnownRecoveryReasonTokens()
    {
        using var statusFile = new TemporaryStatusFile("""
            {
              "writeBackend": "Native",
              "nativeWriteReadiness": "Degraded",
              "recoveryActive": true,
              "recoveryReason": " commit timed-out ",
              "lastCommitXid": 11
            }
            """);

        var status = await InvokeReadHostRuntimeStatusAsync(
            statusFilePath: statusFile.Path,
            accessMode: MountAccessMode.ReadWrite,
            configuredWriteBackend: "Native",
            timeout: TimeSpan.FromMilliseconds(220));

        Assert.Equal("Native", status.WriteBackend);
        Assert.Equal(NativeWriteReadiness.Degraded, status.NativeWriteReadiness);
        Assert.Equal(NativeWriteValidationState.Scaffold, status.NativeWriteValidationState);
        Assert.True(status.RecoveryActive);
        Assert.Equal("CommitTimedOut", status.RecoveryReason);
        Assert.Equal((ulong)11, status.LastCommitXid);
        Assert.Equal(NativeWriteSafetyState.RecoveryBlocked, status.NativeWriteSafetyState);
        Assert.Equal("DowngradedAfterCommitTimeout", status.LastRecoveryAction);
    }

    [Fact]
    public async Task ReadHostRuntimeStatusAsync_CanonicalizesCommitModelMismatchReason()
    {
        using var statusFile = new TemporaryStatusFile("""
            {
              "writeBackend": "Native",
              "nativeWriteReadiness": "MutationReady",
              "recoveryActive": true,
              "recoveryReason": " commit model not canonical ",
              "lastCommitXid": 17
            }
            """);

        var status = await InvokeReadHostRuntimeStatusAsync(
            statusFilePath: statusFile.Path,
            accessMode: MountAccessMode.ReadWrite,
            configuredWriteBackend: "Native",
            timeout: TimeSpan.FromMilliseconds(220));

        Assert.Equal("Native", status.WriteBackend);
        Assert.Equal(NativeWriteReadiness.MutationReady, status.NativeWriteReadiness);
        Assert.Equal(NativeWriteValidationState.Scaffold, status.NativeWriteValidationState);
        Assert.True(status.RecoveryActive);
        Assert.Equal("CommitModelNotCanonical", status.RecoveryReason);
        Assert.Equal((ulong)17, status.LastCommitXid);
        Assert.Equal(NativeWriteSafetyState.RecoveryBlocked, status.NativeWriteSafetyState);
        Assert.Equal("DowngradedAfterCommitModelMismatch", status.LastRecoveryAction);
    }

    [Theory]
    [InlineData(" canonical path not active ", "CanonicalPathNotActive", "DowngradedAfterCanonicalPathProofMissing")]
    [InlineData(" canonical state not loaded ", "CanonicalStateNotLoaded", "DowngradedAfterCanonicalGateFailure")]
    [InlineData(" canonical volume state load failed ", "CanonicalVolumeStateLoadFailed", "DowngradedAfterCanonicalGateFailure")]
    [InlineData(" canonical object map state invalid ", "CanonicalObjectMapStateInvalid", "DowngradedAfterCanonicalGateFailure")]
    [InlineData(" canonical spaceman state invalid ", "CanonicalSpacemanStateInvalid", "DowngradedAfterCanonicalGateFailure")]
    [InlineData(" canonical volume tree state invalid ", "CanonicalVolumeTreeStateInvalid", "DowngradedAfterCanonicalGateFailure")]
    [InlineData(" native write not ready ", "NativeWriteNotReady", "DowngradedAfterCanonicalGateFailure")]
    [InlineData(" write device not allowed ", "WriteDeviceNotAllowed", "DowngradedAfterCanonicalGateFailure")]
    [InlineData(" commit path not ready ", "CommitPathNotReady", "DowngradedAfterCanonicalGateFailure")]
    [InlineData(" canonical commit not ready ", "CanonicalCommitNotReady", "DowngradedAfterCanonicalGateFailure")]
    public async Task ReadHostRuntimeStatusAsync_CanonicalizesCanonicalGateFailureReasons(
        string rawRecoveryReason,
        string expectedRecoveryReason,
        string expectedLastRecoveryAction)
    {
        using var statusFile = new TemporaryStatusFile($$"""
            {
              "writeBackend": "Native",
              "nativeWriteReadiness": "MutationReady",
              "recoveryActive": true,
              "recoveryReason": "{{rawRecoveryReason}}",
              "lastCommitXid": 18
            }
            """);

        var status = await InvokeReadHostRuntimeStatusAsync(
            statusFilePath: statusFile.Path,
            accessMode: MountAccessMode.ReadWrite,
            configuredWriteBackend: "Native",
            timeout: TimeSpan.FromMilliseconds(220));

        Assert.Equal("Native", status.WriteBackend);
        Assert.Equal(NativeWriteReadiness.MutationReady, status.NativeWriteReadiness);
        Assert.Equal(NativeWriteValidationState.Scaffold, status.NativeWriteValidationState);
        Assert.True(status.RecoveryActive);
        Assert.Equal(expectedRecoveryReason, status.RecoveryReason);
        Assert.Equal((ulong)18, status.LastCommitXid);
        Assert.Equal(NativeWriteSafetyState.RecoveryBlocked, status.NativeWriteSafetyState);
        Assert.Equal(expectedLastRecoveryAction, status.LastRecoveryAction);
    }

    [Fact]
    public async Task ReadHostRuntimeStatusAsync_DerivesCanonicalGateFailure_FromCanonicalRecoveryReason_WhenPayloadFieldMissing()
    {
        using var statusFile = new TemporaryStatusFile("""
            {
              "writeBackend": "Native",
              "nativeWriteReadiness": "MutationReady",
              "recoveryActive": true,
              "recoveryReason": " commit path not ready ",
              "lastCommitXid": 181
            }
            """);

        var status = await InvokeReadHostRuntimeStatusAsync(
            statusFilePath: statusFile.Path,
            accessMode: MountAccessMode.ReadWrite,
            configuredWriteBackend: "Native",
            timeout: TimeSpan.FromMilliseconds(220));

        Assert.Equal("Native", status.WriteBackend);
        Assert.Equal(NativeWriteReadiness.MutationReady, status.NativeWriteReadiness);
        Assert.True(status.RecoveryActive);
        Assert.Equal("CommitPathNotReady", status.RecoveryReason);
        Assert.Equal("CommitPathNotReady", status.CanonicalGateFailure);
        Assert.Equal((ulong)181, status.LastCommitXid);
        Assert.Equal("DowngradedAfterCanonicalGateFailure", status.LastRecoveryAction);
    }

    [Fact]
    public async Task ReadHostRuntimeStatusAsync_DerivesCanonicalGateFailure_WhenPayloadBackendIsDisabledAfterFailClosed()
    {
        using var statusFile = new TemporaryStatusFile("""
            {
              "writeBackend": "Disabled",
              "nativeWriteReadiness": "Degraded",
              "recoveryActive": true,
              "recoveryReason": " canonical commit not ready ",
              "lastCommitXid": 182
            }
            """);

        var status = await InvokeReadHostRuntimeStatusAsync(
            statusFilePath: statusFile.Path,
            accessMode: MountAccessMode.ReadWrite,
            configuredWriteBackend: "Native",
            timeout: TimeSpan.FromMilliseconds(220));

        Assert.Equal("Native", status.WriteBackend);
        Assert.Equal(NativeWriteReadiness.Degraded, status.NativeWriteReadiness);
        Assert.True(status.RecoveryActive);
        Assert.Equal("CanonicalCommitNotReady", status.RecoveryReason);
        Assert.Equal("CanonicalCommitNotReady", status.CanonicalGateFailure);
        Assert.False(status.CanonicalPathActive);
        Assert.Equal((ulong)182, status.LastCommitXid);
        Assert.Equal("DowngradedAfterCanonicalGateFailure", status.LastRecoveryAction);
    }

    [Theory]
    [InlineData("ImmutableRecoveryIdentityMissing")]
    [InlineData("ImmutableRecoveryIdentityInvalid")]
    [InlineData("LegacyRecoveryEvidenceAmbiguous")]
    public async Task ReadHostRuntimeStatusAsync_PreservesMountedIdentityDowngradeForRegistration(
        string recoveryReason)
    {
        using var statusFile = new TemporaryStatusFile($$"""
            {
              "writeBackend": "Disabled",
              "nativeWriteReadiness": "Degraded",
              "nativeWriteSafetyState": "ReadOnlyFallback",
              "recoveryActive": true,
              "recoveryReason": "{{recoveryReason}}"
            }
            """);

        var status = await InvokeReadHostRuntimeStatusAsync(
            statusFilePath: statusFile.Path,
            accessMode: MountAccessMode.ReadWrite,
            configuredWriteBackend: "Native",
            timeout: TimeSpan.FromMilliseconds(220));

        Assert.Equal("Disabled", status.WriteBackend);
        Assert.Equal(
            recoveryReason,
            InvokeMountedReadOnlyIdentityFallbackReason(
                MountAccessMode.ReadWrite,
                status.WriteBackend,
                status.RecoveryReason));
    }

    [Fact]
    public async Task ReadHostRuntimeStatusAsync_CanonicalizesWriteGateBlockedReason()
    {
        using var statusFile = new TemporaryStatusFile("""
            {
              "writeBackend": "Native",
              "nativeWriteReadiness": "MutationReady",
              "recoveryActive": true,
              "recoveryReason": " write gate blocked ",
              "lastCommitXid": 21
            }
            """);

        var status = await InvokeReadHostRuntimeStatusAsync(
            statusFilePath: statusFile.Path,
            accessMode: MountAccessMode.ReadWrite,
            configuredWriteBackend: "Native",
            timeout: TimeSpan.FromMilliseconds(220));

        Assert.Equal("Native", status.WriteBackend);
        Assert.Equal(NativeWriteReadiness.MutationReady, status.NativeWriteReadiness);
        Assert.Equal(NativeWriteValidationState.Scaffold, status.NativeWriteValidationState);
        Assert.True(status.RecoveryActive);
        Assert.Equal("WriteGateBlocked", status.RecoveryReason);
        Assert.Equal((ulong)21, status.LastCommitXid);
        Assert.Equal(NativeWriteSafetyState.RecoveryBlocked, status.NativeWriteSafetyState);
        Assert.Equal("DowngradedAfterWriteGatePolicy", status.LastRecoveryAction);
    }

    [Fact]
    public async Task ReadHostRuntimeStatusAsync_CanonicalizesValidationCrashFaultEvidenceReason()
    {
        using var statusFile = new TemporaryStatusFile("""
            {
              "writeBackend": "Native",
              "nativeWriteReadiness": "MutationReady",
              "recoveryActive": true,
              "recoveryReason": " validation crash fault evidence insufficient ",
              "lastCommitXid": 22
            }
            """);

        var status = await InvokeReadHostRuntimeStatusAsync(
            statusFilePath: statusFile.Path,
            accessMode: MountAccessMode.ReadWrite,
            configuredWriteBackend: "Native",
            timeout: TimeSpan.FromMilliseconds(220));

        Assert.Equal("Native", status.WriteBackend);
        Assert.Equal(NativeWriteReadiness.MutationReady, status.NativeWriteReadiness);
        Assert.Equal(NativeWriteValidationState.Scaffold, status.NativeWriteValidationState);
        Assert.True(status.RecoveryActive);
        Assert.Equal("ValidationCrashFaultEvidenceInsufficient", status.RecoveryReason);
        Assert.Equal((ulong)22, status.LastCommitXid);
        Assert.Equal(NativeWriteSafetyState.RecoveryBlocked, status.NativeWriteSafetyState);
        Assert.Equal("DowngradedAfterValidationCrashFaultGate", status.LastRecoveryAction);
    }

    [Fact]
    public async Task ReadHostRuntimeStatusAsync_CanonicalizesValidationStableEvidenceStaleReason()
    {
        using var statusFile = new TemporaryStatusFile("""
            {
              "writeBackend": "Native",
              "nativeWriteReadiness": "CommitReady",
              "recoveryActive": true,
              "recoveryReason": " validation stable evidence stale ",
              "lastCommitXid": 27
            }
            """);

        var status = await InvokeReadHostRuntimeStatusAsync(
            statusFilePath: statusFile.Path,
            accessMode: MountAccessMode.ReadWrite,
            configuredWriteBackend: "Native",
            timeout: TimeSpan.FromMilliseconds(220));

        Assert.Equal("Native", status.WriteBackend);
        Assert.Equal(NativeWriteReadiness.CommitReady, status.NativeWriteReadiness);
        Assert.Equal(NativeWriteValidationState.Scaffold, status.NativeWriteValidationState);
        Assert.True(status.RecoveryActive);
        Assert.Equal("ValidationStableEvidenceStale", status.RecoveryReason);
        Assert.Equal((ulong)27, status.LastCommitXid);
        Assert.Equal(NativeWriteSafetyState.RecoveryBlocked, status.NativeWriteSafetyState);
        Assert.Equal("DowngradedAfterValidationStableStale", status.LastRecoveryAction);
    }

    [Fact]
    public async Task ReadHostRuntimeStatusAsync_ParsesValidationEvidenceFields()
    {
        var lastValidatedUtc = DateTime.UtcNow.AddMinutes(-10);
        using var statusFile = new TemporaryStatusFile($$"""
            {
              "writeBackend": "Native",
              "nativeWriteReadiness": "CommitReady",
              "nativeWriteValidationState": "CanonicalImageValidated",
              "recoveryActive": false,
              "hostPid": 4242,
              "validationCrashFaultPasses": 2,
              "validationHardwarePilotPasses": 3,
              "validationMacOsValidationPasses": 1,
              "validationPowerLossPassVerified": true,
              "validationLastValidatedUtc": "{{lastValidatedUtc:o}}"
            }
            """);

        var status = await InvokeReadHostRuntimeStatusAsync(
            statusFilePath: statusFile.Path,
            accessMode: MountAccessMode.ReadWrite,
            configuredWriteBackend: "Native",
            timeout: TimeSpan.FromMilliseconds(220));

        Assert.NotNull(status.ValidationEvidence);
        Assert.Equal(2, status.ValidationEvidence!.CrashFaultPasses);
        Assert.Equal(3, status.ValidationEvidence.HardwarePilotPasses);
        Assert.Equal(1, status.ValidationEvidence.MacOsValidationPasses);
        Assert.True(status.ValidationEvidence.PowerLossPassVerified);
        Assert.True(status.ValidationEvidence.LastValidatedUtc.HasValue);
        Assert.Equal(lastValidatedUtc.ToUniversalTime(), status.ValidationEvidence.LastValidatedUtc!.Value);
        Assert.Equal(4242, status.HostProcessId);
    }

    [Fact]
    public async Task ReadHostRuntimeStatusAsync_LenientlyParsesStringEncodedTelemetryFields()
    {
        using var statusFile = new TemporaryStatusFile("""
            {
              "writeBackend": "Native",
              "commitModel": "CanonicalApfsCheckpoint",
              "nativeWriteReadiness": "CommitReady",
              "nativeWriteValidationState": "CanonicalImageValidated",
              "recoveryActive": "false",
              "lastCommitXid": "99",
              "dirtyTransactionCount": "12",
              "shutdownDrainActive": "true",
              "inFlightMutationCallbacks": "7",
              "hostPid": "4567",
              "validationCrashFaultPasses": "2",
              "validationHotUnplugPasses": "3",
              "validationPowerLossPassVerified": "1",
              "fixtureCompatibilityPathActive": "false",
              "usesScaffoldCommitBlob": "0",
              "canonicalPathActive": "true",
              "replayCheckpointCandidatePresent": "true",
              "replayCheckpointPendingWindow": "false"
            }
            """);

        var status = await InvokeReadHostRuntimeStatusAsync(
            statusFilePath: statusFile.Path,
            accessMode: MountAccessMode.ReadWrite,
            configuredWriteBackend: "Native",
            timeout: TimeSpan.FromMilliseconds(240));

        Assert.Equal("Native", status.WriteBackend);
        Assert.Equal(NativeWriteReadiness.CommitReady, status.NativeWriteReadiness);
        Assert.Equal(NativeWriteValidationState.CanonicalImageValidated, status.NativeWriteValidationState);
        Assert.Equal((ulong)99, status.LastCommitXid);
        Assert.Equal(12, status.DirtyTransactionCount);
        Assert.True(status.ShutdownDrainActive);
        Assert.Equal(7, status.InFlightMutationCallbacks);
        Assert.Equal(4567, status.HostProcessId);
        Assert.NotNull(status.ValidationEvidence);
        Assert.Equal(2, status.ValidationEvidence!.CrashFaultPasses);
        Assert.Equal(3, status.ValidationEvidence.HotUnplugPasses);
        Assert.True(status.ValidationEvidence.PowerLossPassVerified);
        Assert.False(status.FixtureCompatibilityPathActive);
        Assert.False(status.UsesScaffoldCommitBlob);
        Assert.True(status.CanonicalPathActive);
        Assert.True(status.ReplayCheckpointCandidatePresent);
        Assert.False(status.ReplayCheckpointPendingWindow);
    }

    [Fact]
    public async Task ReadHostRuntimeStatusAsync_LenientlyClampsOversizedNumericTelemetry()
    {
        using var statusFile = new TemporaryStatusFile("""
            {
              "writeBackend": "Native",
              "nativeWriteReadiness": "CommitReady",
              "recoveryActive": "false",
              "lastCommitXid": "18446744073709551615",
              "dirtyTransactionCount": "9223372036854775807",
              "inFlightMutationCallbacks": "9223372036854775807",
              "hostPid": "9223372036854775807",
              "validationCrashFaultPasses": "9223372036854775807",
              "validationCrashStageMatrixPasses": "9223372036854775807",
              "validationHardwarePilotPasses": "9223372036854775807",
              "validationHotUnplugPasses": "9223372036854775807",
              "validationMacOsValidationPasses": "9223372036854775807",
              "validationMacOsConsistencyPasses": "9223372036854775807",
              "validationPowerLossReplayPasses": "9223372036854775807"
            }
            """);

        var status = await InvokeReadHostRuntimeStatusAsync(
            statusFilePath: statusFile.Path,
            accessMode: MountAccessMode.ReadWrite,
            configuredWriteBackend: "Native",
            timeout: TimeSpan.FromMilliseconds(240));

        Assert.Equal("Native", status.WriteBackend);
        Assert.Equal(NativeWriteReadiness.CommitReady, status.NativeWriteReadiness);
        Assert.Equal((ulong)18446744073709551615UL, status.LastCommitXid);
        Assert.Equal(int.MaxValue, status.DirtyTransactionCount);
        Assert.Equal(int.MaxValue, status.InFlightMutationCallbacks);
        Assert.Equal(int.MaxValue, status.HostProcessId);
        Assert.NotNull(status.ValidationEvidence);
        Assert.Equal(int.MaxValue, status.ValidationEvidence!.CrashFaultPasses);
        Assert.Equal(int.MaxValue, status.ValidationEvidence.CrashStageMatrixPasses);
        Assert.Equal(int.MaxValue, status.ValidationEvidence.HardwarePilotPasses);
        Assert.Equal(int.MaxValue, status.ValidationEvidence.HotUnplugPasses);
        Assert.Equal(int.MaxValue, status.ValidationEvidence.MacOsValidationPasses);
        Assert.Equal(int.MaxValue, status.ValidationEvidence.MacOsConsistencyPasses);
        Assert.Equal(int.MaxValue, status.ValidationEvidence.PowerLossReplayPasses);
    }

    [Fact]
    public async Task ReadHostRuntimeStatusAsync_LenientParserKeepsValidFieldsWhenCounterTokensAreInvalid()
    {
        using var statusFile = new TemporaryStatusFile("""
            {
              "writeBackend": "Native",
              "nativeWriteReadiness": "Degraded",
              "recoveryActive": "no",
              "recoveryReason": "commit timed-out",
              "lastCommitXid": "101",
              "dirtyTransactionCount": "not-a-number",
              "shutdownDrainActive": "yes",
              "inFlightMutationCallbacks": "n/a",
              "hostPid": "pid-33",
              "validationCrashFaultPasses": "unknown"
            }
            """);

        var status = await InvokeReadHostRuntimeStatusAsync(
            statusFilePath: statusFile.Path,
            accessMode: MountAccessMode.ReadWrite,
            configuredWriteBackend: "Native",
            timeout: TimeSpan.FromMilliseconds(240));

        Assert.Equal("Native", status.WriteBackend);
        Assert.Equal(NativeWriteReadiness.Degraded, status.NativeWriteReadiness);
        Assert.True(status.RecoveryActive);
        Assert.Equal("CommitTimedOut", status.RecoveryReason);
        Assert.Equal((ulong)101, status.LastCommitXid);
        Assert.Equal(NativeWriteSafetyState.RecoveryBlocked, status.NativeWriteSafetyState);
        Assert.Equal(0, status.DirtyTransactionCount);
        Assert.True(status.ShutdownDrainActive);
        Assert.Equal(0, status.InFlightMutationCallbacks);
        Assert.Equal(0, status.HostProcessId);
        Assert.Null(status.ValidationEvidence);
    }

    [Theory]
    [InlineData(" fixture legacy fallback active ", "FixtureLegacyFallbackActive", "DowngradedAfterFixtureFallback")]
    [InlineData(" scaffold commit blob active ", "ScaffoldCommitBlobActive", "DowngradedAfterScaffoldCommitBlob")]
    public async Task ReadHostRuntimeStatusAsync_CanonicalizesFixtureAndScaffoldSafetyReasons(
        string rawRecoveryReason,
        string expectedRecoveryReason,
        string expectedLastRecoveryAction)
    {
        using var statusFile = new TemporaryStatusFile($$"""
            {
              "writeBackend": "Native",
              "nativeWriteReadiness": "MutationReady",
              "recoveryActive": true,
              "recoveryReason": "{{rawRecoveryReason}}",
              "lastCommitXid": 18
            }
            """);

        var status = await InvokeReadHostRuntimeStatusAsync(
            statusFilePath: statusFile.Path,
            accessMode: MountAccessMode.ReadWrite,
            configuredWriteBackend: "Native",
            timeout: TimeSpan.FromMilliseconds(220));

        Assert.Equal("Native", status.WriteBackend);
        Assert.Equal(NativeWriteReadiness.MutationReady, status.NativeWriteReadiness);
        Assert.Equal(NativeWriteValidationState.Scaffold, status.NativeWriteValidationState);
        Assert.True(status.RecoveryActive);
        Assert.Equal(expectedRecoveryReason, status.RecoveryReason);
        Assert.Equal((ulong)18, status.LastCommitXid);
        Assert.Equal(NativeWriteSafetyState.RecoveryBlocked, status.NativeWriteSafetyState);
        Assert.Equal(expectedLastRecoveryAction, status.LastRecoveryAction);
    }

    [Theory]
    [InlineData(" fixture legacy fallback active ", true, false, false)]
    [InlineData(" fixture compatibility path active ", false, true, false)]
    [InlineData(" scaffold commit blob active ", false, false, true)]
    public async Task ReadHostRuntimeStatusAsync_DerivesCompatibilityFlags_FromRecoveryReason_WhenPayloadFlagsMissing(
        string rawRecoveryReason,
        bool expectedFixtureLegacyFallbackActive,
        bool expectedFixtureCompatibilityPathActive,
        bool expectedUsesScaffoldCommitBlob)
    {
        using var statusFile = new TemporaryStatusFile($$"""
            {
              "writeBackend": "Disabled",
              "nativeWriteReadiness": "Degraded",
              "recoveryActive": true,
              "recoveryReason": "{{rawRecoveryReason}}",
              "lastCommitXid": 183
            }
            """);

        var status = await InvokeReadHostRuntimeStatusAsync(
            statusFilePath: statusFile.Path,
            accessMode: MountAccessMode.ReadWrite,
            configuredWriteBackend: "Native",
            timeout: TimeSpan.FromMilliseconds(220));

        Assert.Equal("Native", status.WriteBackend);
        Assert.Equal(NativeWriteReadiness.Degraded, status.NativeWriteReadiness);
        Assert.True(status.RecoveryActive);
        Assert.Equal((ulong)183, status.LastCommitXid);
        Assert.Equal(expectedFixtureLegacyFallbackActive, status.FixtureLegacyFallbackActive);
        Assert.Equal(expectedFixtureCompatibilityPathActive, status.FixtureCompatibilityPathActive);
        Assert.Equal(expectedUsesScaffoldCommitBlob, status.UsesScaffoldCommitBlob);
    }

    [Fact]
    public async Task ReadHostRuntimeStatusAsync_CanonicalizesIntegrityMountFailureReason()
    {
        using var statusFile = new TemporaryStatusFile("""
            {
              "writeBackend": "Native",
              "nativeWriteReadiness": "RecoveryMode",
              "recoveryActive": true,
              "recoveryReason": " integrity check failed on mount ",
              "lastCommitXid": 19
            }
            """);

        var status = await InvokeReadHostRuntimeStatusAsync(
            statusFilePath: statusFile.Path,
            accessMode: MountAccessMode.ReadWrite,
            configuredWriteBackend: "Native",
            timeout: TimeSpan.FromMilliseconds(220));

        Assert.Equal("Native", status.WriteBackend);
        Assert.Equal(NativeWriteReadiness.RecoveryMode, status.NativeWriteReadiness);
        Assert.Equal(NativeWriteValidationState.Scaffold, status.NativeWriteValidationState);
        Assert.True(status.RecoveryActive);
        Assert.Equal("IntegrityCheckFailedOnMount", status.RecoveryReason);
        Assert.Equal((ulong)19, status.LastCommitXid);
        Assert.Equal(NativeWriteSafetyState.RecoveryBlocked, status.NativeWriteSafetyState);
        Assert.Equal("BootstrapIntegrityBlocked", status.LastRecoveryAction);
    }

    [Fact]
    public async Task ReadHostRuntimeStatusAsync_CanonicalizesMissingAllocationMapReason()
    {
        using var statusFile = new TemporaryStatusFile("""
            {
              "writeBackend": "Native",
              "nativeWriteReadiness": "RecoveryMode",
              "recoveryActive": true,
              "recoveryReason": " missing allocation ",
              "lastCommitXid": 20
            }
            """);

        var status = await InvokeReadHostRuntimeStatusAsync(
            statusFilePath: statusFile.Path,
            accessMode: MountAccessMode.ReadWrite,
            configuredWriteBackend: "Native",
            timeout: TimeSpan.FromMilliseconds(220));

        Assert.Equal("Native", status.WriteBackend);
        Assert.Equal(NativeWriteReadiness.RecoveryMode, status.NativeWriteReadiness);
        Assert.True(status.RecoveryActive);
        Assert.Equal("IntegrityMissingAllocationMap", status.RecoveryReason);
        Assert.Equal((ulong)20, status.LastCommitXid);
        Assert.Equal(NativeWriteSafetyState.RecoveryBlocked, status.NativeWriteSafetyState);
        Assert.Equal("BootstrapIntegrityMissingAllocationMap", status.LastRecoveryAction);
    }

    [Fact]
    public async Task ReadHostRuntimeStatusAsync_DerivesReplayFailClosedAction_WhenReplayReasonReported()
    {
        using var statusFile = new TemporaryStatusFile("""
            {
              "writeBackend": "Native",
              "nativeWriteReadiness": "RecoveryMode",
              "recoveryActive": false,
              "recoveryReason": "ReplayCommitBlobInvalid",
              "lastCommitXid": 23
            }
            """);

        var status = await InvokeReadHostRuntimeStatusAsync(
            statusFilePath: statusFile.Path,
            accessMode: MountAccessMode.ReadWrite,
            configuredWriteBackend: "Native",
            timeout: TimeSpan.FromMilliseconds(220));

        Assert.Equal("Native", status.WriteBackend);
        Assert.Equal(NativeWriteReadiness.RecoveryMode, status.NativeWriteReadiness);
        Assert.Equal(NativeWriteValidationState.Scaffold, status.NativeWriteValidationState);
        Assert.True(status.RecoveryActive);
        Assert.Equal("ReplayCommitBlobInvalid", status.RecoveryReason);
        Assert.Equal((ulong)23, status.LastCommitXid);
        Assert.Equal(NativeWriteSafetyState.RecoveryBlocked, status.NativeWriteSafetyState);
        Assert.Equal("ReplaySkippedFailClosed", status.LastRecoveryAction);
    }

    [Theory]
    [InlineData(" persistent state ahead of superblock ", "PersistentStateAheadOfSuperblock")]
    [InlineData(" persistent state behind superblock ", "PersistentStateBehindSuperblock")]
    public async Task ReadHostRuntimeStatusAsync_CanonicalizesPersistentStateReplayReasons(
        string rawRecoveryReason,
        string expectedRecoveryReason)
    {
        using var statusFile = new TemporaryStatusFile($$"""
            {
              "writeBackend": "Native",
              "nativeWriteReadiness": "RecoveryMode",
              "recoveryActive": false,
              "recoveryReason": "{{rawRecoveryReason}}",
              "lastCommitXid": 24
            }
            """);

        var status = await InvokeReadHostRuntimeStatusAsync(
            statusFilePath: statusFile.Path,
            accessMode: MountAccessMode.ReadWrite,
            configuredWriteBackend: "Native",
            timeout: TimeSpan.FromMilliseconds(220));

        Assert.Equal("Native", status.WriteBackend);
        Assert.Equal(NativeWriteReadiness.RecoveryMode, status.NativeWriteReadiness);
        Assert.Equal(NativeWriteValidationState.Scaffold, status.NativeWriteValidationState);
        Assert.True(status.RecoveryActive);
        Assert.Equal(expectedRecoveryReason, status.RecoveryReason);
        Assert.Equal((ulong)24, status.LastCommitXid);
        Assert.Equal(NativeWriteSafetyState.RecoveryBlocked, status.NativeWriteSafetyState);
        Assert.Equal("ReplaySkippedFailClosed", status.LastRecoveryAction);
    }

    [Theory]
    [InlineData(" replay integrity check failed ", "ReplayIntegrityCheckFailed")]
    [InlineData(" replay checkpoint pending window ", "ReplayCheckpointPendingWindow")]
    [InlineData(" replay checkpoint not pending window ", "ReplayCheckpointNotPendingWindow")]
    [InlineData(" replay interrupted before checkpoint switch ", "ReplayInterruptedBeforeCheckpointSwitch")]
    [InlineData(" replay checkpoint write failed ", "ReplayCheckpointWriteFailed")]
    [InlineData(" replay interrupted before checkpoint flush ", "ReplayInterruptedBeforeCheckpointFlush")]
    [InlineData(" replay checkpoint flush failed ", "ReplayCheckpointFlushFailed")]
    public async Task ReadHostRuntimeStatusAsync_CanonicalizesReplayStageFailureReasons(
        string rawRecoveryReason,
        string expectedRecoveryReason)
    {
        using var statusFile = new TemporaryStatusFile($$"""
            {
              "writeBackend": "Native",
              "nativeWriteReadiness": "RecoveryMode",
              "recoveryActive": false,
              "recoveryReason": "{{rawRecoveryReason}}",
              "lastCommitXid": 26
            }
            """);

        var status = await InvokeReadHostRuntimeStatusAsync(
            statusFilePath: statusFile.Path,
            accessMode: MountAccessMode.ReadWrite,
            configuredWriteBackend: "Native",
            timeout: TimeSpan.FromMilliseconds(220));

        Assert.Equal("Native", status.WriteBackend);
        Assert.Equal(NativeWriteReadiness.RecoveryMode, status.NativeWriteReadiness);
        Assert.Equal(NativeWriteValidationState.Scaffold, status.NativeWriteValidationState);
        Assert.True(status.RecoveryActive);
        Assert.Equal(expectedRecoveryReason, status.RecoveryReason);
        Assert.Equal((ulong)26, status.LastCommitXid);
        Assert.Equal(NativeWriteSafetyState.RecoveryBlocked, status.NativeWriteSafetyState);
        Assert.Equal("ReplaySkippedFailClosed", status.LastRecoveryAction);
    }

    [Theory]
    [InlineData(" commit interrupted before replay persist ", "CommitInterruptedBeforeReplayPersist", "DowngradedAfterPersistFailure")]
    [InlineData(" commit replay persist failed ", "CommitReplayPersistFailed", "DowngradedAfterPersistFailure")]
    [InlineData(" commit interrupted before replay roundtrip verify ", "CommitInterruptedBeforeReplayRoundTripVerify", "DowngradedAfterPersistFailure")]
    [InlineData(" commit replay roundtrip failed ", "CommitReplayRoundTripFailed", "DowngradedAfterPersistFailure")]
    [InlineData(" commit interrupted before checkpoint roundtrip verify ", "CommitInterruptedBeforeCheckpointRoundTripVerify", "DowngradedAfterCheckpointInterruption")]
    [InlineData(" commit checkpoint roundtrip failed ", "CommitCheckpointRoundTripFailed", "DowngradedAfterCheckpointWriteFailure")]
    public async Task ReadHostRuntimeStatusAsync_CanonicalizesReplayCheckpointPersistFailureReasons(
        string rawRecoveryReason,
        string expectedRecoveryReason,
        string expectedLastRecoveryAction)
    {
        using var statusFile = new TemporaryStatusFile($$"""
            {
              "writeBackend": "Native",
              "nativeWriteReadiness": "Degraded",
              "recoveryActive": false,
              "recoveryReason": "{{rawRecoveryReason}}",
              "lastCommitXid": 28
            }
            """);

        var status = await InvokeReadHostRuntimeStatusAsync(
            statusFilePath: statusFile.Path,
            accessMode: MountAccessMode.ReadWrite,
            configuredWriteBackend: "Native",
            timeout: TimeSpan.FromMilliseconds(220));

        Assert.Equal("Native", status.WriteBackend);
        Assert.Equal(NativeWriteReadiness.Degraded, status.NativeWriteReadiness);
        Assert.Equal(NativeWriteValidationState.Scaffold, status.NativeWriteValidationState);
        Assert.True(status.RecoveryActive);
        Assert.Equal(expectedRecoveryReason, status.RecoveryReason);
        Assert.Equal((ulong)28, status.LastCommitXid);
        Assert.Equal(NativeWriteSafetyState.RecoveryBlocked, status.NativeWriteSafetyState);
        Assert.Equal(expectedLastRecoveryAction, status.LastRecoveryAction);
    }

    [Fact]
    public async Task ReadHostRuntimeStatusAsync_CanonicalizesDirtyTransactionLimitReason()
    {
        using var statusFile = new TemporaryStatusFile("""
            {
              "writeBackend": "Native",
              "nativeWriteReadiness": "CommitReady",
              "recoveryActive": false,
              "recoveryReason": " dirty transaction limit exceeded ",
              "lastCommitXid": 31,
              "dirtyTransactionCount": 256
            }
            """);

        var status = await InvokeReadHostRuntimeStatusAsync(
            statusFilePath: statusFile.Path,
            accessMode: MountAccessMode.ReadWrite,
            configuredWriteBackend: "Native",
            timeout: TimeSpan.FromMilliseconds(220));

        Assert.Equal("Native", status.WriteBackend);
        Assert.Equal(NativeWriteReadiness.CommitReady, status.NativeWriteReadiness);
        Assert.Equal(NativeWriteValidationState.Scaffold, status.NativeWriteValidationState);
        Assert.True(status.RecoveryActive);
        Assert.Equal("DirtyTransactionLimitExceeded", status.RecoveryReason);
        Assert.Equal((ulong)31, status.LastCommitXid);
        Assert.Equal(NativeWriteSafetyState.RecoveryBlocked, status.NativeWriteSafetyState);
        Assert.Equal("DowngradedAfterDirtyTransactionLimit", status.LastRecoveryAction);
        Assert.Equal(256, status.DirtyTransactionCount);
    }

    [Fact]
    public async Task ReadHostRuntimeStatusAsync_CanonicalizesNativeMutationStagingFailureReason()
    {
        using var statusFile = new TemporaryStatusFile("""
            {
              "writeBackend": "Disabled",
              "commitModel": "ScaffoldCheckpoint",
              "nativeWriteReadiness": "Degraded",
              "nativeWriteSafetyState": "ReadOnlyFallback",
              "recoveryActive": true,
              "recoveryReason": " native mutation staging failed ",
              "lastRecoveryAction": "DowngradedAfterMutationStagingFailure",
              "lastCommitXid": 4839,
              "dirtyTransactionCount": 128
            }
            """);

        var status = await InvokeReadHostRuntimeStatusAsync(
            statusFilePath: statusFile.Path,
            accessMode: MountAccessMode.ReadWrite,
            configuredWriteBackend: "Native",
            timeout: TimeSpan.FromMilliseconds(220));

        Assert.Equal("Native", status.WriteBackend);
        Assert.Equal(NativeWriteReadiness.Degraded, status.NativeWriteReadiness);
        Assert.True(status.RecoveryActive);
        Assert.Equal("NativeMutationStagingFailed", status.RecoveryReason);
        Assert.Equal("DowngradedAfterMutationStagingFailure", status.LastRecoveryAction);
        Assert.Equal((ulong)4839, status.LastCommitXid);
        Assert.Equal(128, status.DirtyTransactionCount);
        Assert.Equal(NativeWriteSafetyState.RecoveryBlocked, status.NativeWriteSafetyState);
    }

    [Fact]
    public async Task ReadHostRuntimeStatusAsync_MalformedJsonFallsBackAfterTimeout()
    {
        using var statusFile = new TemporaryStatusFile("{ \"writeBackend\": \"Native\"");

        var status = await InvokeReadHostRuntimeStatusAsync(
            statusFilePath: statusFile.Path,
            accessMode: MountAccessMode.ReadWrite,
            configuredWriteBackend: "Overlay",
            timeout: TimeSpan.FromMilliseconds(240));

        Assert.Equal("Overlay", status.WriteBackend);
        Assert.Equal(NativeWriteReadiness.MutationReady, status.NativeWriteReadiness);
        Assert.Equal(NativeWriteValidationState.Scaffold, status.NativeWriteValidationState);
        Assert.False(status.RecoveryActive);
        Assert.Null(status.RecoveryReason);
        Assert.Null(status.LastCommitXid);
        Assert.Equal(NativeWriteSafetyState.PilotReadWrite, status.NativeWriteSafetyState);
    }

    [Fact]
    public async Task ReadHostRuntimeStatusCachedAsync_InvalidatesSameLengthContentChangeWithPreservedTimestamp()
    {
        using var statusFile = new TemporaryStatusFile("""
            {
              "writeBackend": "Native",
              "nativeWriteReadiness": "CommitReady",
              "recoveryActive": false,
              "lastCommitXid": 10
            }
            """);
        using var backend = new NativeApfsBackend(new ServiceHostOptions());

        var first = await InvokeReadHostRuntimeStatusCachedAsync(
            backend,
            statusFile.Path,
            MountAccessMode.ReadWrite,
            configuredWriteBackend: "Native",
            timeout: TimeSpan.FromMilliseconds(220));
        await statusFile.WritePreservingTimestampAsync("""
            {
              "writeBackend": "Native",
              "nativeWriteReadiness": "CommitReady",
              "recoveryActive": false,
              "lastCommitXid": 99
            }
            """);
        var second = await InvokeReadHostRuntimeStatusCachedAsync(
            backend,
            statusFile.Path,
            MountAccessMode.ReadWrite,
            configuredWriteBackend: "Native",
            timeout: TimeSpan.FromMilliseconds(220));

        Assert.Equal((ulong)10, first.LastCommitXid);
        Assert.Equal((ulong)99, second.LastCommitXid);
    }

    [Fact]
    public async Task ReadHostRuntimeStatusCachedAsync_InvalidatesWhenStatusTimestampChanges()
    {
        using var statusFile = new TemporaryStatusFile("""
            {
              "writeBackend": "Native",
              "nativeWriteReadiness": "CommitReady",
              "recoveryActive": false,
              "lastCommitXid": 10
            }
            """);
        using var backend = new NativeApfsBackend(new ServiceHostOptions());

        var first = await InvokeReadHostRuntimeStatusCachedAsync(
            backend,
            statusFile.Path,
            MountAccessMode.ReadWrite,
            configuredWriteBackend: "Native",
            timeout: TimeSpan.FromMilliseconds(220));
        await statusFile.WriteWithNewTimestampAsync("""
            {
              "writeBackend": "Native",
              "nativeWriteReadiness": "CommitReady",
              "recoveryActive": true,
              "recoveryReason": "RecoveryMarkerDirty",
              "lastCommitXid": 99
            }
            """);
        var second = await InvokeReadHostRuntimeStatusCachedAsync(
            backend,
            statusFile.Path,
            MountAccessMode.ReadWrite,
            configuredWriteBackend: "Native",
            timeout: TimeSpan.FromMilliseconds(220));

        Assert.Equal((ulong)10, first.LastCommitXid);
        Assert.Equal((ulong)99, second.LastCommitXid);
        Assert.True(second.RecoveryActive);
        Assert.Equal("RecoveryMarkerDirty", second.RecoveryReason);
    }

    private static async Task<HostRuntimeStatusProjection> InvokeReadHostRuntimeStatusAsync(
        string statusFilePath,
        MountAccessMode accessMode,
        string configuredWriteBackend,
        TimeSpan timeout)
    {
        var method = typeof(NativeApfsBackend).GetMethod(
            "ReadHostRuntimeStatusAsync",
            BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        var taskObj = method!.Invoke(null, [statusFilePath, accessMode, configuredWriteBackend, timeout, CancellationToken.None]);
        Assert.NotNull(taskObj);
        var task = (Task)taskObj!;
        await task.ConfigureAwait(false);

        var resultProperty = taskObj!.GetType().GetProperty("Result", BindingFlags.Public | BindingFlags.Instance);
        Assert.NotNull(resultProperty);
        var result = resultProperty!.GetValue(taskObj);
        Assert.NotNull(result);

        return ProjectHostRuntimeStatus(result!);
    }

    private static string? InvokeMountedReadOnlyIdentityFallbackReason(
        MountAccessMode requestedAccessMode,
        string hostWriteBackend,
        string? recoveryReason)
    {
        var method = typeof(NativeApfsBackend).GetMethod(
            "GetMountedReadOnlyIdentityFallbackReason",
            BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        return (string?)method!.Invoke(
            null,
            [requestedAccessMode, hostWriteBackend, recoveryReason]);
    }

    private static async Task<HostRuntimeStatusProjection> InvokeReadHostRuntimeStatusCachedAsync(
        NativeApfsBackend backend,
        string statusFilePath,
        MountAccessMode accessMode,
        string configuredWriteBackend,
        TimeSpan timeout)
    {
        var method = typeof(NativeApfsBackend).GetMethod(
            "ReadHostRuntimeStatusCachedAsync",
            BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(method);

        var taskObj = method!.Invoke(backend, [statusFilePath, accessMode, configuredWriteBackend, timeout, CancellationToken.None]);
        Assert.NotNull(taskObj);
        var task = (Task)taskObj!;
        await task.ConfigureAwait(false);

        var resultProperty = taskObj!.GetType().GetProperty("Result", BindingFlags.Public | BindingFlags.Instance);
        Assert.NotNull(resultProperty);
        var result = resultProperty!.GetValue(taskObj);
        Assert.NotNull(result);

        return ProjectHostRuntimeStatus(result!);
    }

    private static HostRuntimeStatusProjection ProjectHostRuntimeStatus(object result)
    {
        var resultType = result.GetType();
        var writeBackend = (string?)resultType.GetProperty("WriteBackend", BindingFlags.Public | BindingFlags.Instance)?.GetValue(result);
        var nativeWriteReadiness = (NativeWriteReadiness?)resultType.GetProperty("NativeWriteReadiness", BindingFlags.Public | BindingFlags.Instance)?.GetValue(result);
        var nativeWriteValidationState = (NativeWriteValidationState?)resultType.GetProperty("NativeWriteValidationState", BindingFlags.Public | BindingFlags.Instance)?.GetValue(result);
        var recoveryActive = (bool?)resultType.GetProperty("RecoveryActive", BindingFlags.Public | BindingFlags.Instance)?.GetValue(result);
        var recoveryReason = (string?)resultType.GetProperty("RecoveryReason", BindingFlags.Public | BindingFlags.Instance)?.GetValue(result);
        var lastCommitXid = (ulong?)resultType.GetProperty("LastCommitXid", BindingFlags.Public | BindingFlags.Instance)?.GetValue(result);
        var nativeWriteSafetyState = (NativeWriteSafetyState?)resultType.GetProperty("NativeWriteSafetyState", BindingFlags.Public | BindingFlags.Instance)?.GetValue(result);
        var lastRecoveryAction = (string?)resultType.GetProperty("LastRecoveryAction", BindingFlags.Public | BindingFlags.Instance)?.GetValue(result);
        var dirtyTransactionCount = (int?)resultType.GetProperty("DirtyTransactionCount", BindingFlags.Public | BindingFlags.Instance)?.GetValue(result);
        var shutdownDrainActive = (bool?)resultType.GetProperty("ShutdownDrainActive", BindingFlags.Public | BindingFlags.Instance)?.GetValue(result);
        var inFlightMutationCallbacks = (int?)resultType.GetProperty("InFlightMutationCallbacks", BindingFlags.Public | BindingFlags.Instance)?.GetValue(result);
        var hostProcessId = (int?)resultType.GetProperty("HostProcessId", BindingFlags.Public | BindingFlags.Instance)?.GetValue(result);
        var fixtureLegacyFallbackActive = (bool?)resultType.GetProperty("FixtureLegacyFallbackActive", BindingFlags.Public | BindingFlags.Instance)?.GetValue(result);
        var fixtureCompatibilityPathActive = (bool?)resultType.GetProperty("FixtureCompatibilityPathActive", BindingFlags.Public | BindingFlags.Instance)?.GetValue(result);
        var usesScaffoldCommitBlob = (bool?)resultType.GetProperty("UsesScaffoldCommitBlob", BindingFlags.Public | BindingFlags.Instance)?.GetValue(result);
        var validationEvidence = (NativeWriteValidationEvidence?)resultType.GetProperty("ValidationEvidence", BindingFlags.Public | BindingFlags.Instance)?.GetValue(result);
        var commitStage = (string?)resultType.GetProperty("CommitStage", BindingFlags.Public | BindingFlags.Instance)?.GetValue(result);
        var replayStage = (string?)resultType.GetProperty("ReplayStage", BindingFlags.Public | BindingFlags.Instance)?.GetValue(result);
        var commitBlobMagic = (string?)resultType.GetProperty("CommitBlobMagic", BindingFlags.Public | BindingFlags.Instance)?.GetValue(result);
        var canonicalPathActive = (bool?)resultType.GetProperty("CanonicalPathActive", BindingFlags.Public | BindingFlags.Instance)?.GetValue(result);
        var canonicalGateFailure = (string?)resultType.GetProperty("CanonicalGateFailure", BindingFlags.Public | BindingFlags.Instance)?.GetValue(result);
        var replayCheckpointCandidatePresent = (bool?)resultType.GetProperty("ReplayCheckpointCandidatePresent", BindingFlags.Public | BindingFlags.Instance)?.GetValue(result);
        var replayCheckpointPendingWindow = (bool?)resultType.GetProperty("ReplayCheckpointPendingWindow", BindingFlags.Public | BindingFlags.Instance)?.GetValue(result);

        Assert.NotNull(writeBackend);
        Assert.NotNull(nativeWriteReadiness);
        Assert.NotNull(nativeWriteValidationState);
        Assert.NotNull(recoveryActive);
        Assert.NotNull(nativeWriteSafetyState);
        Assert.NotNull(dirtyTransactionCount);
        Assert.NotNull(shutdownDrainActive);
        Assert.NotNull(inFlightMutationCallbacks);
        Assert.NotNull(hostProcessId);
        Assert.NotNull(fixtureLegacyFallbackActive);
        Assert.NotNull(fixtureCompatibilityPathActive);
        Assert.NotNull(usesScaffoldCommitBlob);

        return new HostRuntimeStatusProjection(
            WriteBackend: writeBackend!,
            NativeWriteReadiness: nativeWriteReadiness!.Value,
            NativeWriteValidationState: nativeWriteValidationState!.Value,
            RecoveryActive: recoveryActive!.Value,
            RecoveryReason: recoveryReason,
            LastCommitXid: lastCommitXid,
            NativeWriteSafetyState: nativeWriteSafetyState!.Value,
            LastRecoveryAction: lastRecoveryAction,
            DirtyTransactionCount: dirtyTransactionCount!.Value,
            ShutdownDrainActive: shutdownDrainActive!.Value,
            InFlightMutationCallbacks: inFlightMutationCallbacks!.Value,
            HostProcessId: hostProcessId!.Value,
            FixtureLegacyFallbackActive: fixtureLegacyFallbackActive!.Value,
            FixtureCompatibilityPathActive: fixtureCompatibilityPathActive!.Value,
            UsesScaffoldCommitBlob: usesScaffoldCommitBlob!.Value,
            ValidationEvidence: validationEvidence,
            CommitStage: commitStage,
            ReplayStage: replayStage,
            CommitBlobMagic: commitBlobMagic,
            CanonicalPathActive: canonicalPathActive,
            CanonicalGateFailure: canonicalGateFailure,
            ReplayCheckpointCandidatePresent: replayCheckpointCandidatePresent,
            ReplayCheckpointPendingWindow: replayCheckpointPendingWindow
        );
    }

    private sealed record HostRuntimeStatusProjection(
        string WriteBackend,
        NativeWriteReadiness NativeWriteReadiness,
        NativeWriteValidationState NativeWriteValidationState,
        bool RecoveryActive,
        string? RecoveryReason,
        ulong? LastCommitXid,
        NativeWriteSafetyState NativeWriteSafetyState,
        string? LastRecoveryAction,
        int DirtyTransactionCount,
        bool ShutdownDrainActive,
        int InFlightMutationCallbacks,
        int HostProcessId,
        bool FixtureLegacyFallbackActive,
        bool FixtureCompatibilityPathActive,
        bool UsesScaffoldCommitBlob,
        NativeWriteValidationEvidence? ValidationEvidence,
        string? CommitStage,
        string? ReplayStage,
        string? CommitBlobMagic,
        bool? CanonicalPathActive,
        string? CanonicalGateFailure,
        bool? ReplayCheckpointCandidatePresent,
        bool? ReplayCheckpointPendingWindow);

    private sealed class TemporaryStatusFile : IDisposable
    {
        public TemporaryStatusFile(string content)
        {
            Path = System.IO.Path.Combine(
                System.IO.Path.GetTempPath(),
                $"apfsaccess_status_{Guid.NewGuid():N}.json");
            File.WriteAllText(Path, content);
        }

        public string Path { get; }

        public async Task WritePreservingTimestampAsync(string content)
        {
            var timestamp = File.GetLastWriteTimeUtc(Path);
            await File.WriteAllTextAsync(Path, content);
            File.SetLastWriteTimeUtc(Path, timestamp);
        }

        public async Task WriteWithNewTimestampAsync(string content)
        {
            var timestamp = File.GetLastWriteTimeUtc(Path);
            await File.WriteAllTextAsync(Path, content);
            var nextTimestamp = timestamp.AddSeconds(2);
            if (nextTimestamp <= File.GetLastWriteTimeUtc(Path))
            {
                nextTimestamp = File.GetLastWriteTimeUtc(Path).AddSeconds(2);
            }

            File.SetLastWriteTimeUtc(Path, nextTimestamp);
        }

        public async Task WritePreservingIdentityMetadataAsync(string content)
        {
            var creationTime = File.GetCreationTimeUtc(Path);
            var lastWriteTime = File.GetLastWriteTimeUtc(Path);
            await File.WriteAllTextAsync(Path, content);
            File.SetCreationTimeUtc(Path, creationTime);
            File.SetLastWriteTimeUtc(Path, lastWriteTime);
        }

        public void Dispose()
        {
            try
            {
                if (File.Exists(Path))
                {
                    File.Delete(Path);
                }
            }
            catch
            {
                // Best-effort cleanup.
            }
        }
    }
}
