using ApfsAccess.Core;
using ApfsAccess.Service;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace ApfsAccess.Service.Tests;

public sealed class ApfsMountWorkerAutoMountTests
{
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
    public async Task RunCycle_ReusesMountStateInsteadOfPollingNativeStatusRepeatedly()
    {
        var backend = new ControllableBackend();
        var worker = CreateWorker(backend);

        await InvokeRunCycleAsync(worker);

        Assert.Equal(2, backend.GetMountStateCalls);
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

        public bool IsConnected { get; set; } = true;

        public bool SupportsNativeWrite { get; set; }

        public bool IncludeSecondaryVolume { get; set; }

        public bool SecondarySupportsNativeWrite { get; set; }

        public bool KeepStaleMountAfterUnmount { get; init; }

        public bool ClearMountsWhenDisconnected { get; set; } = true;

        private readonly Dictionary<string, int> _unmountAttemptsByMountPoint = new(StringComparer.OrdinalIgnoreCase);

        private readonly HashSet<string> _unmountedMountPoints = new(StringComparer.OrdinalIgnoreCase);

        private readonly List<string> _unmountHistory = [];

        public IReadOnlyList<string> UnmountHistory => _unmountHistory;

        private readonly Dictionary<string, int> _mountAttemptsByVolumeId = new(StringComparer.OrdinalIgnoreCase);

        public IReadOnlyDictionary<string, int> MountAttemptsByVolumeId => _mountAttemptsByVolumeId;

        public int MountAttempts { get; private set; }

        public int GetMountStateCalls { get; set; }

        public Task<IReadOnlyList<DeviceInfo>> ProbeDevicesAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult<IReadOnlyList<DeviceInfo>>(IsConnected
                ? [new DeviceInfo(DeviceId, "Test APFS USB", true)]
                : []);
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
                DeviceDisplayName: "Test APFS USB");

            return Task.FromResult(new MountResult(
                Success: true,
                MountPoint: mountPoint,
                Error: null,
                EffectiveAccessMode: request.AccessMode,
                IsReadOnly: request.AccessMode == MountAccessMode.ReadOnly,
                WriteEnabled: request.AccessMode == MountAccessMode.ReadWrite));
        }

        public Task<UnmountResult> UnmountAsync(string mountPoint, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            _unmountedMountPoints.Add(mountPoint);
            _unmountHistory.Add(mountPoint);
            _unmountAttemptsByMountPoint.TryGetValue(mountPoint, out var attempts);
            _unmountAttemptsByMountPoint[mountPoint] = attempts + 1;
            if (!KeepStaleMountAfterUnmount || attempts > 0)
            {
                _mounts.Remove(mountPoint);
            }

            return Task.FromResult(_mounts.ContainsKey(mountPoint)
                ? new UnmountResult(false, mountPoint, $"Mount point '{mountPoint}' remained visible after FsHost stopped. Close Explorer windows or files and try eject again.")
                : new UnmountResult(true, mountPoint, null));
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
