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
    public async Task Eject_TreatsSuccessfulUnmountAsSafeWhenMountStateRefreshLags()
    {
        var backend = new ControllableBackend { KeepStaleMountAfterUnmount = true };
        var statusPublisher = new RuntimeStatusPublisher();
        var worker = CreateWorker(backend, statusPublisher);

        await InvokeRunCycleAsync(worker);
        Assert.Single(await backend.GetMountStateAsync(CancellationToken.None));

        var eject = await worker.EjectAsync(ControllableBackend.VolumeId, CancellationToken.None);

        Assert.True(eject.Success);
        Assert.Contains("safely ejected", eject.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Empty(statusPublisher.Latest.MountPoints);
        Assert.Contains(
            statusPublisher.Latest.Warnings,
            warning => warning.Contains("unplug and reinsert", StringComparison.OrdinalIgnoreCase));
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
        ServiceHostOptions options)
        => new(
            NullLogger<ApfsMountWorker>.Instance,
            backend,
            new FixedMountPolicy('R'),
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

    private sealed class ControllableBackend : IApfsBackend
    {
        public const string DeviceId = @"\\.\PhysicalDrive9";
        public const string VolumeId = DeviceId + "|Main";

        private readonly Dictionary<string, MountedVolumeState> _mounts = new(StringComparer.OrdinalIgnoreCase);

        public bool IsConnected { get; set; } = true;

        public bool KeepStaleMountAfterUnmount { get; init; }

        private readonly HashSet<string> _unmountedMountPoints = new(StringComparer.OrdinalIgnoreCase);

        public int MountAttempts { get; private set; }

        public int GetMountStateCalls { get; private set; }

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
            return Task.FromResult<IReadOnlyList<VolumeInfo>>(
                IsConnected && string.Equals(deviceId, DeviceId, StringComparison.OrdinalIgnoreCase)
                    ? [new VolumeInfo(VolumeId, DeviceId, "Main", SupportsReadWrite: true)]
                    : []);
        }

        public Task<MountResult> MountAsync(MountRequest request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            MountAttempts++;

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
                VolumeName: "Main",
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
            if (!KeepStaleMountAfterUnmount)
            {
                _mounts.Remove(mountPoint);
            }

            return Task.FromResult(new UnmountResult(true, mountPoint, null));
        }

        public Task<IReadOnlyList<MountedVolumeState>> GetMountStateAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            GetMountStateCalls++;
            if (!IsConnected)
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
