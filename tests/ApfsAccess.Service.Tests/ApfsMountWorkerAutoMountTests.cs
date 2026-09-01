using ApfsAccess.Core;
using ApfsAccess.Service;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace ApfsAccess.Service.Tests;

public sealed class ApfsMountWorkerAutoMountTests
{
    [Fact]
    public async Task StopAsync_CancelsBlockedUnmountAtConfiguredDeadline()
    {
        var backend = new ControllableBackend();
        var worker = CreateWorker(
            backend,
            new RuntimeStatusPublisher(),
            new ServiceHostOptions
            {
                AutoMountEnabled = true,
                EnableNativeWrite = false,
                ReadWriteMode = "RwWithRoFallback",
                PollSeconds = 60,
                NativeHostStopTimeoutSeconds = 1,
            });

        await InvokeRunCycleAsync(worker);
        backend.StallNextUnmount();
        await worker.StartAsync(CancellationToken.None);

        var stopTask = worker.StopAsync(CancellationToken.None);
        var completedBeforeRelease = false;
        try
        {
            await backend.WaitForUnmountStartedAsync().WaitAsync(TimeSpan.FromSeconds(5));
            completedBeforeRelease = await Task.WhenAny(
                stopTask,
                Task.Delay(TimeSpan.FromSeconds(3))) == stopTask;
        }
        finally
        {
            backend.ReleaseUnmount();
            await stopTask.WaitAsync(TimeSpan.FromSeconds(5));
            worker.Dispose();
        }

        Assert.True(completedBeforeRelease, "Service stop should bound a blocked unmount using the configured host-stop deadline.");
        Assert.True(backend.UnmountCancellationObserved);
    }

    [Fact]
    public async Task EnsureMountedExact_StartedBeforeShutdownCannotRemountAfterShutdownPreparation()
    {
        var backend = new ControllableBackend
        {
            SupportsNativeWrite = false,
        };
        var worker = CreateWorker(
            backend,
            new RuntimeStatusPublisher(),
            new ServiceHostOptions
            {
                AutoMountEnabled = true,
                EnableNativeWrite = true,
                WriteRolloutChannel = "Enabled",
                ReadWriteMode = "RwWithRoFallback",
                AllowWriteOnUnsupportedFeatures = false,
                NativeWriteAllowRawPhysicalDevices = true,
                NativeWritePromotionPolicy = "PilotHardware",
                NativeHostStopTimeoutSeconds = 2,
            });

        Task<(bool Success, string Message)>? activeRefresh = null;
        Task<(bool Success, string Message)>? queuedMount = null;
        Task<ShutdownPreparationResult>? shutdown = null;

        try
        {
            await InvokeRunCycleAsync(worker);
            Assert.Single(await backend.GetMountStateAsync(CancellationToken.None));

            backend.SupportsNativeWrite = true;
            backend.StallNextUnmount();
            activeRefresh = worker.RefreshAsync(
                clearUserEjectedVolumes: true,
                ControllableBackend.VolumeId,
                CancellationToken.None);
            await backend.WaitForUnmountStartedAsync().WaitAsync(TimeSpan.FromSeconds(2));

            backend.StallNextDeviceProbe();
            queuedMount = worker.EnsureMountedExactAsync(
                ControllableBackend.DeviceId,
                ControllableBackend.VolumeId,
                MountAccessMode.ReadWrite,
                CancellationToken.None);
            await backend.WaitForDeviceProbeAsync().WaitAsync(TimeSpan.FromSeconds(2));

            shutdown = worker.PrepareForShutdownAsync(CancellationToken.None);
            backend.ReleaseUnmount();
            await shutdown.WaitAsync(TimeSpan.FromSeconds(5));

            backend.ReleaseDeviceProbe();
            var queuedResult = await queuedMount.WaitAsync(TimeSpan.FromSeconds(5));

            Assert.False(queuedResult.Success);
            Assert.Contains("shutdown", queuedResult.Message, StringComparison.OrdinalIgnoreCase);
            Assert.Equal(2, backend.MountAttempts);
            Assert.Empty(await backend.GetMountStateAsync(CancellationToken.None));
        }
        finally
        {
            backend.ReleaseUnmount();
            backend.ReleaseDeviceProbe();
            if (activeRefresh is not null)
            {
                await activeRefresh.WaitAsync(TimeSpan.FromSeconds(5));
            }

            if (shutdown is not null)
            {
                await shutdown.WaitAsync(TimeSpan.FromSeconds(5));
            }

            if (queuedMount is not null)
            {
                await queuedMount.WaitAsync(TimeSpan.FromSeconds(5));
            }

            worker.Dispose();
        }
    }

    [Fact]
    public async Task RunCycle_RemountsAfterUserEjectedDriveWasPhysicallyDisconnected()
    {
        var backend = new ControllableBackend();
        var worker = CreateWorker(backend);

        await InvokeRunCycleAsync(worker);
        Assert.Single(await backend.GetMountStateAsync(CancellationToken.None));

        var eject = await worker.EjectAsync(ControllableBackend.VolumeId, CancellationToken.None);
        Assert.True(eject.Success);
        Assert.Empty(await backend.GetMountStateAsync(CancellationToken.None));

        backend.IsConnected = false;
        await InvokeRunCycleAsync(worker);

        backend.IsConnected = true;
        await InvokeRunCycleAsync(worker);

        Assert.Single(await backend.GetMountStateAsync(CancellationToken.None));
        Assert.Equal(2, backend.MountAttempts);
    }

    [Fact]
    public async Task Refresh_ClearsPriorUserEjectAndMountsConnectedVolume()
    {
        var backend = new ControllableBackend();
        var worker = CreateWorker(backend);

        await InvokeRunCycleAsync(worker);
        Assert.Single(await backend.GetMountStateAsync(CancellationToken.None));

        var eject = await worker.EjectAsync(ControllableBackend.VolumeId, CancellationToken.None);
        Assert.True(eject.Success);
        Assert.Empty(await backend.GetMountStateAsync(CancellationToken.None));

        await InvokeRunCycleAsync(worker);
        Assert.Empty(await backend.GetMountStateAsync(CancellationToken.None));

        var refresh = await worker.RefreshAsync(clearUserEjectedVolumes: true, CancellationToken.None);

        Assert.True(refresh.Success);
        Assert.Single(await backend.GetMountStateAsync(CancellationToken.None));
        Assert.Equal(2, backend.MountAttempts);
    }

    [Fact]
    public async Task Refresh_RemountsReadOnlyVolumeWhenWriteBecomesAvailable()
    {
        var backend = new ControllableBackend
        {
            SupportsNativeWrite = false,
        };
        var worker = CreateWorker(
            backend,
            new RuntimeStatusPublisher(),
            new ServiceHostOptions
            {
                AutoMountEnabled = true,
                EnableNativeWrite = true,
                WriteRolloutChannel = "Enabled",
                ReadWriteMode = "RwWithRoFallback",
                AllowWriteOnUnsupportedFeatures = false,
                NativeWriteAllowRawPhysicalDevices = true,
                NativeWritePromotionPolicy = "PilotHardware",
            });

        await InvokeRunCycleAsync(worker);
        var readOnlyMount = Assert.Single(await backend.GetMountStateAsync(CancellationToken.None));
        Assert.Equal(MountAccessMode.ReadOnly, readOnlyMount.AccessMode);

        backend.SupportsNativeWrite = true;
        var refresh = await worker.RefreshAsync(clearUserEjectedVolumes: true, CancellationToken.None);

        Assert.True(refresh.Success);
        var readWriteMount = Assert.Single(await backend.GetMountStateAsync(CancellationToken.None));
        Assert.Equal(MountAccessMode.ReadWrite, readWriteMount.AccessMode);
        Assert.Equal(2, backend.MountAttempts);
        Assert.Contains("R:\\", backend.UnmountHistory);
    }

    [Fact]
    public async Task Refresh_RemountsDegradedReadWriteVolume()
    {
        var backend = new ControllableBackend
        {
            SupportsNativeWrite = true,
        };
        var worker = CreateWorker(
            backend,
            new RuntimeStatusPublisher(),
            new ServiceHostOptions
            {
                AutoMountEnabled = true,
                EnableNativeWrite = true,
                WriteRolloutChannel = "Enabled",
                ReadWriteMode = "RwWithRoFallback",
                AllowWriteOnUnsupportedFeatures = false,
                NativeWriteAllowRawPhysicalDevices = true,
                NativeWritePromotionPolicy = "PilotHardware",
            });

        await InvokeRunCycleAsync(worker);
        var initialMount = Assert.Single(await backend.GetMountStateAsync(CancellationToken.None));
        Assert.Equal(MountAccessMode.ReadWrite, initialMount.AccessMode);

        backend.MarkMountedVolumeDegraded(ControllableBackend.VolumeId);
        var refresh = await worker.RefreshAsync(
            clearUserEjectedVolumes: true,
            ControllableBackend.VolumeId,
            CancellationToken.None);

        Assert.True(refresh.Success);
        var remounted = Assert.Single(await backend.GetMountStateAsync(CancellationToken.None));
        Assert.Equal(MountAccessMode.ReadWrite, remounted.AccessMode);
        Assert.False(remounted.RecoveryActive);
        Assert.Equal(NativeWriteSafetyState.PilotReadWrite, remounted.NativeWriteSafetyState);
        Assert.Equal(2, backend.MountAttempts);
        Assert.Contains("R:\\", backend.UnmountHistory);
    }

    [Fact]
    public async Task Refresh_WhenDegradedUnmountFinalizationFails_QuarantinesWithoutSameCycleRemount()
    {
        var backend = new ControllableBackend
        {
            SupportsNativeWrite = true,
            FailWriteFinalizationAfterUnmount = true,
        };
        var statusPublisher = new RuntimeStatusPublisher();
        var worker = CreateWorker(
            backend,
            statusPublisher,
            new ServiceHostOptions
            {
                AutoMountEnabled = true,
                EnableNativeWrite = true,
                WriteRolloutChannel = "Enabled",
                ReadWriteMode = "RwWithRoFallback",
                AllowWriteOnUnsupportedFeatures = false,
                NativeWriteAllowRawPhysicalDevices = true,
                NativeWritePromotionPolicy = "PilotHardware",
            });

        await InvokeRunCycleAsync(worker);
        backend.MarkMountedVolumeDegraded(ControllableBackend.VolumeId);

        var refresh = await worker.RefreshAsync(
            clearUserEjectedVolumes: true,
            ControllableBackend.VolumeId,
            CancellationToken.None);

        Assert.True(refresh.Success);
        Assert.Empty(await backend.GetMountStateAsync(CancellationToken.None));
        Assert.Equal(1, backend.MountAttempts);
        Assert.Contains(
            statusPublisher.Latest.Warnings,
            warning => warning.Contains("finalize", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(
            statusPublisher.Latest.Warnings,
            warning => warning.Contains("pending writes", StringComparison.OrdinalIgnoreCase));

        await InvokeRunCycleAsync(worker);

        Assert.Empty(await backend.GetMountStateAsync(CancellationToken.None));
        Assert.Equal(1, backend.MountAttempts);
    }

    [Fact]
    public async Task EnsureMounted_WhenFinalizationFails_ReportsUnsafeQuarantineInsteadOfSuccess()
    {
        var backend = new ControllableBackend
        {
            SupportsNativeWrite = true,
            FailWriteFinalizationAfterUnmount = true,
        };
        var worker = CreateWorker(
            backend,
            new RuntimeStatusPublisher(),
            new ServiceHostOptions
            {
                AutoMountEnabled = true,
                EnableNativeWrite = true,
                WriteRolloutChannel = "Enabled",
                ReadWriteMode = "RwWithRoFallback",
                AllowWriteOnUnsupportedFeatures = false,
                NativeWriteAllowRawPhysicalDevices = true,
                NativeWritePromotionPolicy = "PilotHardware",
            });

        await InvokeRunCycleAsync(worker);
        backend.MarkMountedVolumeDegraded(ControllableBackend.VolumeId);

        var result = await worker.EnsureMountedAsync(ControllableBackend.VolumeId, CancellationToken.None);

        Assert.False(result.Success);
        Assert.Contains("could not be mounted", result.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Empty(await backend.GetMountStateAsync(CancellationToken.None));
        Assert.Equal(1, backend.MountAttempts);
    }

    [Fact]
    public async Task RunCycle_DoesNotWarnForHealthyNativeWriteMountDiagnostic()
    {
        var backend = new ControllableBackend
        {
            SupportsNativeWrite = true,
            MountDiagnosticCode = "ExperimentalNativeWriteMount",
        };
        var statusPublisher = new RuntimeStatusPublisher();
        var worker = CreateWorker(
            backend,
            statusPublisher,
            new ServiceHostOptions
            {
                AutoMountEnabled = true,
                EnableNativeWrite = true,
                WriteRolloutChannel = "Enabled",
                ReadWriteMode = "RwWithRoFallback",
                AllowWriteOnUnsupportedFeatures = false,
                NativeWriteAllowRawPhysicalDevices = true,
                NativeWritePromotionPolicy = "PilotHardware",
            });

        await InvokeRunCycleAsync(worker);

        Assert.Equal(RuntimeState.MountedRw, statusPublisher.Latest.State);
        Assert.True(statusPublisher.Latest.WriteEnabled);
        Assert.Equal(NativeWriteSafetyState.PilotReadWrite, statusPublisher.Latest.NativeWriteSafetyState);
        Assert.Empty(statusPublisher.Latest.Warnings);
    }

    [Fact]
    public async Task RunCycle_DoesNotWarnForAnyHealthyReadWriteDiagnostic()
    {
        var backend = new ControllableBackend
        {
            SupportsNativeWrite = true,
            MountDiagnosticCode = "HealthyCanonicalNativeWriteMount",
        };
        var statusPublisher = new RuntimeStatusPublisher();
        var worker = CreateWorker(
            backend,
            statusPublisher,
            new ServiceHostOptions
            {
                AutoMountEnabled = true,
                EnableNativeWrite = true,
                WriteRolloutChannel = "Enabled",
                ReadWriteMode = "RwWithRoFallback",
                AllowWriteOnUnsupportedFeatures = false,
                NativeWriteAllowRawPhysicalDevices = true,
                NativeWritePromotionPolicy = "PilotHardware",
            });

        await InvokeRunCycleAsync(worker);

        Assert.Equal(RuntimeState.MountedRw, statusPublisher.Latest.State);
        Assert.True(statusPublisher.Latest.WriteEnabled);
        Assert.Equal(NativeWriteSafetyState.PilotReadWrite, statusPublisher.Latest.NativeWriteSafetyState);
        Assert.Empty(statusPublisher.Latest.Warnings);
    }

    [Fact]
    public async Task Refresh_TargetedFixRemountsOnlySelectedReadOnlyVolume()
    {
        var backend = new ControllableBackend
        {
            IncludeSecondaryVolume = true,
            SupportsNativeWrite = false,
            SecondarySupportsNativeWrite = false,
        };
        var worker = CreateWorker(
            backend,
            new RuntimeStatusPublisher(),
            new ServiceHostOptions
            {
                AutoMountEnabled = true,
                EnableNativeWrite = true,
                WriteRolloutChannel = "Enabled",
                ReadWriteMode = "RwWithRoFallback",
                AllowWriteOnUnsupportedFeatures = false,
                NativeWriteAllowRawPhysicalDevices = true,
                NativeWritePromotionPolicy = "PilotHardware",
            },
            new SequentialMountPolicy('R', 'S'));

        await InvokeRunCycleAsync(worker);
        var initialMounts = (await backend.GetMountStateAsync(CancellationToken.None))
            .OrderBy(static mount => mount.MountPoint, StringComparer.OrdinalIgnoreCase)
            .ToArray();
        var initialMountByVolumeId = initialMounts.ToDictionary(
            static mount => mount.VolumeId,
            StringComparer.OrdinalIgnoreCase);
        Assert.Collection(
            initialMounts,
            mount => Assert.Equal(MountAccessMode.ReadOnly, mount.AccessMode),
            mount => Assert.Equal(MountAccessMode.ReadOnly, mount.AccessMode));

        backend.SupportsNativeWrite = true;
        backend.SecondarySupportsNativeWrite = true;
        var refresh = await InvokeTargetedRefreshAsync(worker, ControllableBackend.VolumeId);

        Assert.True(refresh.Success);
        var remounted = (await backend.GetMountStateAsync(CancellationToken.None))
            .ToDictionary(static mount => mount.VolumeId, StringComparer.OrdinalIgnoreCase);
        Assert.Equal(MountAccessMode.ReadWrite, remounted[ControllableBackend.VolumeId].AccessMode);
        Assert.Equal(MountAccessMode.ReadOnly, remounted[ControllableBackend.SecondaryVolumeId].AccessMode);
        Assert.Equal(2, backend.MountAttemptsByVolumeId[ControllableBackend.VolumeId]);
        Assert.Equal(1, backend.MountAttemptsByVolumeId[ControllableBackend.SecondaryVolumeId]);
        Assert.Contains(initialMountByVolumeId[ControllableBackend.VolumeId].MountPoint, backend.UnmountHistory);
        Assert.DoesNotContain(initialMountByVolumeId[ControllableBackend.SecondaryVolumeId].MountPoint, backend.UnmountHistory);
    }

    [Fact]
    public async Task Eject_FailsAndKeepsMountVisibleWhenDriveLetterStillExists()
    {
        var backend = new ControllableBackend { KeepStaleMountAfterUnmount = true };
        var statusPublisher = new RuntimeStatusPublisher();
        var worker = CreateWorker(backend, statusPublisher);

        await InvokeRunCycleAsync(worker);
        Assert.Single(await backend.GetMountStateAsync(CancellationToken.None));

        var eject = await worker.EjectAsync(ControllableBackend.VolumeId, CancellationToken.None);

        Assert.False(eject.Success);
        Assert.Contains("still mounted", eject.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(["R:\\"], statusPublisher.Latest.MountPoints);
        Assert.Contains(
            statusPublisher.Latest.Warnings,
            warning => warning.Contains("remained visible", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(
            statusPublisher.Latest.Warnings,
            warning => warning.Contains("close Explorer windows", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task RunCycle_DebouncesOneMissingDeviceScanBeforeUnmounting()
    {
        var backend = new ControllableBackend();
        var statusPublisher = new RuntimeStatusPublisher();
        var worker = CreateWorker(backend, statusPublisher);

        await InvokeRunCycleAsync(worker);
        Assert.Single(await backend.GetMountStateAsync(CancellationToken.None));

        backend.IsConnected = false;
        backend.ClearMountsWhenDisconnected = false;
        await InvokeRunCycleAsync(worker);

        Assert.Single(await backend.GetMountStateAsync(CancellationToken.None));
        Assert.Equal(["R:\\"], statusPublisher.Latest.MountPoints);
        Assert.Contains(
            statusPublisher.Latest.Warnings,
            warning => warning.Contains("waiting for another scan", StringComparison.OrdinalIgnoreCase));

        await InvokeRunCycleAsync(worker);

        Assert.Empty(await backend.GetMountStateAsync(CancellationToken.None));
        Assert.Empty(statusPublisher.Latest.MountPoints);
    }

    [Fact]
    public async Task RunCycle_RefreshesAuthoritativeStateOnceAfterSuccessfulMount()
    {
        var backend = new ControllableBackend
        {
            AuthoritativeLastCommitXid = 183,
            AuthoritativeRecoveryActive = true,
            AuthoritativeRecoveryReason = "RecoveryMarkerDirty",
        };
        var statusPublisher = new RuntimeStatusPublisher();
        var worker = CreateWorker(backend, statusPublisher);

        await InvokeRunCycleAsync(worker);

        Assert.Equal(2, backend.GetMountStateCalls);
        Assert.Equal((ulong)183, statusPublisher.Latest.LastCommitXid);
        Assert.True(statusPublisher.Latest.RecoveryActive);
        Assert.Equal("RecoveryMarkerDirty", statusPublisher.Latest.RecoveryReason);
    }

    [Fact]
    public async Task Eject_WhenFinalWriteDrainFails_RemovesGoneMountButDoesNotReportSafeEject()
    {
        var backend = new ControllableBackend { FailWriteFinalizationAfterUnmount = true };
        var statusPublisher = new RuntimeStatusPublisher();
        var worker = CreateWorker(backend, statusPublisher);

        await InvokeRunCycleAsync(worker);
        var eject = await worker.EjectAsync(ControllableBackend.VolumeId, CancellationToken.None);

        Assert.False(eject.Success);
        Assert.Contains("finalize", eject.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Empty(statusPublisher.Latest.MountPoints);
        Assert.DoesNotContain(
            statusPublisher.Latest.Warnings,
            warning => warning.Contains("safely ejected", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Eject_WhenFinalWriteDrainFails_QuarantinesVolumeFromAutomaticRemount()
    {
        var backend = new ControllableBackend { FailWriteFinalizationAfterUnmount = true };
        var statusPublisher = new RuntimeStatusPublisher();
        var worker = CreateWorker(backend, statusPublisher);

        await InvokeRunCycleAsync(worker);
        var eject = await worker.EjectAsync(ControllableBackend.VolumeId, CancellationToken.None);

        Assert.False(eject.Success);
        Assert.Empty(await backend.GetMountStateAsync(CancellationToken.None));

        await InvokeRunCycleAsync(worker);

        Assert.Empty(await backend.GetMountStateAsync(CancellationToken.None));
        Assert.Equal(1, backend.MountAttempts);
        Assert.Contains(
            statusPublisher.Latest.Warnings,
            warning => warning.Contains("unsafe", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Refresh_WhenNoRemountHappens_ReusesOneMountStateSnapshot()
    {
        var backend = new ControllableBackend();
        var worker = CreateWorker(backend);

        await InvokeRunCycleAsync(worker);
        backend.GetMountStateCalls = 0;

        var refresh = await worker.RefreshAsync(clearUserEjectedVolumes: false, CancellationToken.None);

        Assert.True(refresh.Success);
        Assert.Equal(1, backend.GetMountStateCalls);
    }

    [Fact]
    public async Task Eject_WhenDriveIsUnmounted_ReusesPreEjectSnapshotForRemainingState()
    {
        var backend = new ControllableBackend();
        var worker = CreateWorker(backend);

        await InvokeRunCycleAsync(worker);
        backend.GetMountStateCalls = 0;

        var eject = await worker.EjectAsync(ControllableBackend.VolumeId, CancellationToken.None);

        Assert.True(eject.Success);
        Assert.Equal(1, backend.GetMountStateCalls);
    }

    [Fact]
    public async Task Eject_CompletesWhileDeviceProbeIsStalled_AndLateProbeDoesNotRemount()
    {
        var backend = new ControllableBackend();
        var worker = CreateWorker(backend);

        await InvokeRunCycleAsync(worker);
        Assert.Single(await backend.GetMountStateAsync(CancellationToken.None));

        backend.StallNextDeviceProbe();
        var stalledCycle = InvokeRunCycleAsync(worker);
        await backend.WaitForDeviceProbeAsync().WaitAsync(TimeSpan.FromSeconds(2));
        Assert.False(stalledCycle.IsCompleted);

        (bool Success, string Message) eject;
        try
        {
            eject = await worker
                .EjectAsync(ControllableBackend.VolumeId, CancellationToken.None)
                .WaitAsync(TimeSpan.FromSeconds(2));
        }
        finally
        {
            backend.ReleaseDeviceProbe();
        }

        Assert.True(eject.Success, eject.Message);
        Assert.Empty(await backend.GetMountStateAsync(CancellationToken.None));

        await stalledCycle.WaitAsync(TimeSpan.FromSeconds(2));
        Assert.Empty(await backend.GetMountStateAsync(CancellationToken.None));
        Assert.Equal(1, backend.MountAttempts);
    }

    [Fact]
    public async Task EjectQueuedBehindRefreshRemount_WaitsThenUnmountsTheFreshInstance()
    {
        var backend = new ControllableBackend { SupportsNativeWrite = false };
        var worker = CreateWorker(
            backend,
            new RuntimeStatusPublisher(),
            new ServiceHostOptions
            {
                AutoMountEnabled = true,
                EnableNativeWrite = true,
                WriteRolloutChannel = "Enabled",
                ReadWriteMode = "RwWithRoFallback",
                AllowWriteOnUnsupportedFeatures = false,
                NativeWriteAllowRawPhysicalDevices = true,
                NativeWritePromotionPolicy = "PilotHardware",
            });

        await InvokeRunCycleAsync(worker);
        var initialMount = Assert.Single(await backend.GetMountStateAsync(CancellationToken.None));
        Assert.Equal(MountAccessMode.ReadOnly, initialMount.AccessMode);

        backend.SupportsNativeWrite = true;
        backend.StallNextUnmount();
        var refreshTask = worker.RefreshAsync(clearUserEjectedVolumes: true, CancellationToken.None);
        await backend.WaitForUnmountStartedAsync().WaitAsync(TimeSpan.FromSeconds(2));
        Assert.False(refreshTask.IsCompleted);

        var ejectTask = worker.EjectAsync(ControllableBackend.VolumeId, CancellationToken.None);
        var ejectOrTimeout = await Task.WhenAny(ejectTask, Task.Delay(TimeSpan.FromMilliseconds(200)));
        Assert.False(ejectOrTimeout == ejectTask);
        backend.ReleaseUnmount();

        var refreshCompletedFirst = await Task.WhenAny(refreshTask, ejectTask) == refreshTask;
        var refresh = await refreshTask;
        var eject = await ejectTask;

        Assert.True(refreshCompletedFirst, "The refresh holding the operation lock must finish before the queued eject runs.");
        Assert.True(refresh.Success, refresh.Message);
        Assert.True(eject.Success, eject.Message);

        Assert.Empty(await backend.GetMountStateAsync(CancellationToken.None));
        Assert.Equal(2, backend.UnmountHistory.Count);
        Assert.All(backend.UnmountHistory, mountPoint => Assert.Equal("R:\\", mountPoint));
        Assert.Equal(2, backend.MountAttempts);
    }

    [Fact]
    public async Task RefreshQueuedBehindEject_RemountsOnlyAfterTheEjectCommitted()
    {
        var backend = new ControllableBackend();
        var worker = CreateWorker(backend);

        await InvokeRunCycleAsync(worker);
        Assert.Single(await backend.GetMountStateAsync(CancellationToken.None));

        backend.StallNextUnmount();
        var ejectTask = worker.EjectAsync(ControllableBackend.VolumeId, CancellationToken.None);
        await backend.WaitForUnmountStartedAsync().WaitAsync(TimeSpan.FromSeconds(2));
        Assert.False(ejectTask.IsCompleted);

        var refreshTask = worker.RefreshAsync(clearUserEjectedVolumes: true, CancellationToken.None);
        var refreshOrTimeout = await Task.WhenAny(refreshTask, Task.Delay(TimeSpan.FromMilliseconds(200)));
        Assert.False(refreshOrTimeout == refreshTask);
        backend.ReleaseUnmount();

        var ejectCompletedFirst = await Task.WhenAny(ejectTask, refreshTask) == ejectTask;
        var eject = await ejectTask;
        var refresh = await refreshTask;

        Assert.True(ejectCompletedFirst, "The eject holding the operation lock must finish before the queued refresh runs.");
        Assert.True(eject.Success, eject.Message);
        Assert.True(refresh.Success, refresh.Message);

        Assert.Single(await backend.GetMountStateAsync(CancellationToken.None));
        Assert.Single(backend.UnmountHistory);
        Assert.Equal(2, backend.MountAttempts);
    }

    [Fact]
    public async Task CycleEnteredAfterEjectEntry_CannotRemountTheEjectedVolume()
    {
        var backend = new ControllableBackend();
        var worker = CreateWorker(backend);

        await InvokeRunCycleAsync(worker);
        Assert.Single(await backend.GetMountStateAsync(CancellationToken.None));

        backend.StallNextUnmount();
        var ejectTask = worker.EjectAsync(ControllableBackend.VolumeId, CancellationToken.None);
        await backend.WaitForUnmountStartedAsync().WaitAsync(TimeSpan.FromSeconds(2));
        Assert.False(ejectTask.IsCompleted);

        var cycleTask = InvokeRunCycleAsync(worker);
        var cycleOrTimeout = await Task.WhenAny(cycleTask, Task.Delay(TimeSpan.FromMilliseconds(200)));
        Assert.False(cycleOrTimeout == cycleTask);
        backend.ReleaseUnmount();

        var eject = await ejectTask;
        Assert.True(eject.Success, eject.Message);

        await cycleTask.WaitAsync(TimeSpan.FromSeconds(2));
        Assert.Empty(await backend.GetMountStateAsync(CancellationToken.None));
        Assert.Equal(1, backend.MountAttempts);
    }

    [Fact]
    public async Task RunCycle_WhenMountStateDoesNotChange_PollsMountStateOnlyOnce()
    {
        var backend = new ControllableBackend();
        var worker = CreateWorker(backend);

        await InvokeRunCycleAsync(worker);
        backend.GetMountStateCalls = 0;

        await InvokeRunCycleAsync(worker);

        Assert.Equal(1, backend.GetMountStateCalls);
    }

    [Fact]
    public async Task RunCycle_WhenAutoMountDisabled_PollsMountStateOnlyOnce()
    {
        var backend = new ControllableBackend();
        var worker = CreateWorker(
            backend,
            new RuntimeStatusPublisher(),
            new ServiceHostOptions
            {
                AutoMountEnabled = false,
                EnableNativeWrite = false,
                ReadWriteMode = "RwWithRoFallback",
            });

        await InvokeRunCycleAsync(worker);

        Assert.Equal(1, backend.GetMountStateCalls);
        Assert.Equal(0, backend.MountAttempts);
    }

    [Fact]
    public async Task EnsureMountedExact_WhenAutoMountDisabled_MountsOnlyTheExplicitTarget()
    {
        var backend = new ControllableBackend
        {
            SupportsNativeWrite = true,
        };
        var worker = CreateWorker(
            backend,
            new RuntimeStatusPublisher(),
            new ServiceHostOptions
            {
                AutoMountEnabled = false,
                EnableNativeWrite = true,
                WriteRolloutChannel = "Enabled",
                WriteBackendMode = "Native",
                NativeWriteAllowRawPhysicalDevices = true,
                NativeWritePromotionPolicy = "PilotHardware",
                ReadWriteMode = "RwWithRoFallback",
            });

        await InvokeRunCycleAsync(worker);
        Assert.Equal(0, backend.MountAttempts);

        var result = await worker.EnsureMountedExactAsync(
            ControllableBackend.DeviceId,
            ControllableBackend.VolumeId,
            MountAccessMode.ReadWrite,
            CancellationToken.None);

        Assert.True(result.Success, result.Message);
        var mounted = Assert.Single(await backend.GetMountStateAsync(CancellationToken.None));
        Assert.Equal(ControllableBackend.VolumeId, mounted.VolumeId);
        Assert.Equal(MountAccessMode.ReadWrite, mounted.AccessMode);
        Assert.Equal(1, backend.MountAttempts);
    }

    private static ApfsMountWorker CreateWorker(IApfsBackend backend)
        => CreateWorker(backend, new RuntimeStatusPublisher());

    private static ApfsMountWorker CreateWorker(IApfsBackend backend, RuntimeStatusPublisher statusPublisher)
        => CreateWorker(
            backend,
            statusPublisher,
            new ServiceHostOptions
            {
                AutoMountEnabled = true,
                EnableNativeWrite = false,
                ReadWriteMode = "RwWithRoFallback",
            });

    private static ApfsMountWorker CreateWorker(
        IApfsBackend backend,
        RuntimeStatusPublisher statusPublisher,
        ServiceHostOptions options,
        IMountPolicy? mountPolicy = null)
        => new(
            NullLogger<ApfsMountWorker>.Instance,
            backend,
            mountPolicy ?? new FixedMountPolicy('R'),
            statusPublisher,
            new FixedOptionsMonitor(options)
        );

    private static async Task InvokeRunCycleAsync(ApfsMountWorker worker)
    {
        var method = typeof(ApfsMountWorker).GetMethod(
            "RunCycleAsync",
            System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic);
        Assert.NotNull(method);

        var result = method!.Invoke(worker, [CancellationToken.None]);
        var task = Assert.IsAssignableFrom<Task>(result);
        await task;
    }

    private static async Task<(bool Success, string Message)> InvokeTargetedRefreshAsync(
        ApfsMountWorker worker,
        string volumeId)
    {
        var method = typeof(ApfsMountWorker).GetMethod(
            "RefreshAsync",
            [
                typeof(bool),
                typeof(string),
                typeof(CancellationToken),
            ]);
        Assert.NotNull(method);

        var result = method!.Invoke(worker, [true, volumeId, CancellationToken.None]);
        var task = Assert.IsAssignableFrom<Task<(bool Success, string Message)>>(result);
        return await task;
    }

    private sealed class ControllableBackend : IApfsBackend
    {
        public const string DeviceId = @"\\.\PhysicalDrive9";
        public const string VolumeId = DeviceId + "|Main";
        public const string SecondaryVolumeId = DeviceId + "|Archive";

        private readonly Dictionary<string, MountedVolumeState> _mounts = new(StringComparer.OrdinalIgnoreCase);

        private TaskCompletionSource _deviceProbeStarted = NewSignal();

        private TaskCompletionSource _deviceProbeRelease = NewSignal();

        private bool _stallNextDeviceProbe;

        private TaskCompletionSource _unmountStarted = NewSignal();

        private TaskCompletionSource _unmountRelease = NewSignal();

        private bool _stallNextUnmount;

        public bool IsConnected { get; set; } = true;

        public bool SupportsNativeWrite { get; set; }

        public bool IncludeSecondaryVolume { get; set; }

        public bool SecondarySupportsNativeWrite { get; set; }

        public bool KeepStaleMountAfterUnmount { get; init; }

        public bool FailWriteFinalizationAfterUnmount { get; init; }

        public bool ClearMountsWhenDisconnected { get; set; } = true;

        public bool UnmountCancellationObserved { get; private set; }

        public string? MountDiagnosticCode { get; set; }

        public ulong? AuthoritativeLastCommitXid { get; init; }

        public bool AuthoritativeRecoveryActive { get; init; }

        public string? AuthoritativeRecoveryReason { get; init; }

        private readonly Dictionary<string, int> _unmountAttemptsByMountPoint = new(StringComparer.OrdinalIgnoreCase);

        private readonly HashSet<string> _unmountedMountPoints = new(StringComparer.OrdinalIgnoreCase);

        private readonly List<string> _unmountHistory = [];

        public IReadOnlyList<string> UnmountHistory => _unmountHistory;

        private readonly Dictionary<string, int> _mountAttemptsByVolumeId = new(StringComparer.OrdinalIgnoreCase);

        public IReadOnlyDictionary<string, int> MountAttemptsByVolumeId => _mountAttemptsByVolumeId;

        public int MountAttempts { get; private set; }

        public int GetMountStateCalls { get; set; }

        public void StallNextDeviceProbe()
        {
            _deviceProbeStarted = NewSignal();
            _deviceProbeRelease = NewSignal();
            _stallNextDeviceProbe = true;
        }

        public Task WaitForDeviceProbeAsync() => _deviceProbeStarted.Task;

        public void ReleaseDeviceProbe() => _deviceProbeRelease.TrySetResult();

        public void StallNextUnmount()
        {
            _unmountStarted = NewSignal();
            _unmountRelease = NewSignal();
            _stallNextUnmount = true;
        }

        public Task WaitForUnmountStartedAsync() => _unmountStarted.Task;

        public void ReleaseUnmount() => _unmountRelease.TrySetResult();

        public async Task<IReadOnlyList<DeviceInfo>> ProbeDevicesAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (_stallNextDeviceProbe)
            {
                _stallNextDeviceProbe = false;
                _deviceProbeStarted.TrySetResult();
                await _deviceProbeRelease.Task.WaitAsync(cancellationToken);
            }

            return IsConnected
                ? [new DeviceInfo(DeviceId, "Test APFS USB", true)]
                : [];
        }

        public Task<IReadOnlyList<VolumeInfo>> ProbeVolumesAsync(string deviceId, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!IsConnected || !string.Equals(deviceId, DeviceId, StringComparison.OrdinalIgnoreCase))
            {
                return Task.FromResult<IReadOnlyList<VolumeInfo>>([]);
            }

            List<VolumeInfo> volumes =
            [
                new VolumeInfo(
                    VolumeId,
                    DeviceId,
                    "Main",
                    SupportsReadWrite: true,
                    SupportsNativeWrite: SupportsNativeWrite)
            ];
            if (IncludeSecondaryVolume)
            {
                volumes.Add(new VolumeInfo(
                    SecondaryVolumeId,
                    DeviceId,
                    "Archive",
                    SupportsReadWrite: true,
                    SupportsNativeWrite: SecondarySupportsNativeWrite));
            }

            return Task.FromResult<IReadOnlyList<VolumeInfo>>(volumes);
        }

        public Task<MountResult> MountAsync(MountRequest request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            MountAttempts++;
            _mountAttemptsByVolumeId.TryGetValue(request.VolumeId, out var attempts);
            _mountAttemptsByVolumeId[request.VolumeId] = attempts + 1;

            if (!IsConnected)
            {
                return Task.FromResult(new MountResult(
                    Success: false,
                    MountPoint: null,
                    Error: "Device is disconnected.",
                    EffectiveAccessMode: request.AccessMode));
            }

            var mountPoint = $"{char.ToUpperInvariant(request.DriveLetter)}:\\";
            _unmountedMountPoints.Remove(mountPoint);
            _mounts[mountPoint] = new MountedVolumeState(
                request.VolumeId,
                mountPoint,
                request.AccessMode,
                VolumeName: string.Equals(request.VolumeId, SecondaryVolumeId, StringComparison.OrdinalIgnoreCase) ? "Archive" : "Main",
                DeviceId: DeviceId,
                DeviceDisplayName: "Test APFS USB",
                WriteBackend: request.AccessMode == MountAccessMode.ReadWrite ? "Native" : "Disabled",
                NativeWriteReadiness: request.AccessMode == MountAccessMode.ReadWrite
                    ? NativeWriteReadiness.CommitReady
                    : NativeWriteReadiness.Unavailable,
                NativeWriteSafetyState: request.AccessMode == MountAccessMode.ReadWrite
                    ? NativeWriteSafetyState.PilotReadWrite
                    : NativeWriteSafetyState.ReadOnlyFallback,
                RecoveryActive: AuthoritativeRecoveryActive,
                LastCommitXid: AuthoritativeLastCommitXid,
                RecoveryReason: AuthoritativeRecoveryReason);

            return Task.FromResult(new MountResult(
                Success: true,
                MountPoint: mountPoint,
                Error: null,
                EffectiveAccessMode: request.AccessMode,
                DiagnosticCode: MountDiagnosticCode,
                IsReadOnly: request.AccessMode == MountAccessMode.ReadOnly,
                WriteEnabled: request.AccessMode == MountAccessMode.ReadWrite,
                WriteBackend: request.AccessMode == MountAccessMode.ReadWrite ? "Native" : "Disabled",
                NativeWriteReadiness: request.AccessMode == MountAccessMode.ReadWrite
                    ? NativeWriteReadiness.CommitReady
                    : NativeWriteReadiness.Unavailable,
                NativeWriteSafetyState: request.AccessMode == MountAccessMode.ReadWrite
                    ? NativeWriteSafetyState.PilotReadWrite
                    : NativeWriteSafetyState.ReadOnlyFallback));
        }

        public void MarkMountedVolumeDegraded(string volumeId)
        {
            var degraded = _mounts
                .Where(entry => string.Equals(entry.Value.VolumeId, volumeId, StringComparison.OrdinalIgnoreCase))
                .ToArray();
            foreach (var entry in degraded)
            {
                _mounts[entry.Key] = entry.Value with
                {
                    RecoveryActive = true,
                    RecoveryReason = "CommitInvariantFailed",
                    NativeWriteSafetyState = NativeWriteSafetyState.ReadOnlyFallback,
                    WriteBackend = "Disabled",
                    NativeWriteReadiness = NativeWriteReadiness.Degraded,
                    LastRecoveryAction = "DowngradedAfterInvariantFailure",
                };
            }
        }

        public async Task<UnmountResult> UnmountAsync(string mountPoint, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            _unmountedMountPoints.Add(mountPoint);
            _unmountHistory.Add(mountPoint);
            _unmountAttemptsByMountPoint.TryGetValue(mountPoint, out var attempts);
            _unmountAttemptsByMountPoint[mountPoint] = attempts + 1;
            if (_stallNextUnmount)
            {
                _stallNextUnmount = false;
                _unmountStarted.TrySetResult();
                try
                {
                    await _unmountRelease.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    UnmountCancellationObserved = true;
                    throw;
                }
            }

            if (!KeepStaleMountAfterUnmount || attempts > 0)
            {
                _mounts.Remove(mountPoint);
            }

            if (_mounts.ContainsKey(mountPoint))
            {
                return new UnmountResult(
                    false,
                    mountPoint,
                    $"Mount point '{mountPoint}' remained visible after FsHost stopped. Close Explorer windows or files and try eject again.");
            }

            return FailWriteFinalizationAfterUnmount
                ? new UnmountResult(
                    false,
                    mountPoint,
                    "FsHost stopped, but it failed to finalize pending writes.",
                    MountRemoved: true,
                    HostOwnershipReleased: true,
                    PendingDurabilityCleared: false)
                : new UnmountResult(
                    true,
                    mountPoint,
                    null,
                    MountRemoved: true,
                    HostOwnershipReleased: true,
                    PendingDurabilityCleared: true);
        }

        public Task<IReadOnlyList<MountedVolumeState>> GetMountStateAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            GetMountStateCalls++;
            if (!IsConnected && ClearMountsWhenDisconnected)
            {
                _mounts.Clear();
            }

            return Task.FromResult<IReadOnlyList<MountedVolumeState>>(_mounts.Values.ToArray());
        }

        private static TaskCompletionSource NewSignal()
            => new(TaskCreationOptions.RunContinuationsAsynchronously);
    }

    private sealed class FixedMountPolicy(char driveLetter) : IMountPolicy
    {
        public char SelectDriveLetter(VolumeInfo volume, IReadOnlySet<char> usedLetters)
        {
            _ = volume;
            _ = usedLetters;
            return driveLetter;
        }

        public bool ShouldAutoMount(VolumeInfo volume)
        {
            _ = volume;
            return true;
        }
    }

    private sealed class SequentialMountPolicy(params char[] driveLetters) : IMountPolicy
    {
        public char SelectDriveLetter(VolumeInfo volume, IReadOnlySet<char> usedLetters)
        {
            _ = volume;
            foreach (var driveLetter in driveLetters)
            {
                var normalized = char.ToUpperInvariant(driveLetter);
                if (!usedLetters.Contains(normalized))
                {
                    return normalized;
                }
            }

            return char.ToUpperInvariant(driveLetters[^1]);
        }

        public bool ShouldAutoMount(VolumeInfo volume)
        {
            _ = volume;
            return true;
        }
    }

    private sealed class FixedOptionsMonitor(ServiceHostOptions options) : IOptionsMonitor<ServiceHostOptions>
    {
        public ServiceHostOptions CurrentValue => options;

        public ServiceHostOptions Get(string? name)
        {
            _ = name;
            return options;
        }

        public IDisposable? OnChange(Action<ServiceHostOptions, string?> listener)
        {
            _ = listener;
            return null;
        }
    }
}
