using ApfsAccess.Core;
using ApfsAccess.Service;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace ApfsAccess.Service.Tests;

public sealed class ApfsMountWorkerShutdownProofTests
{
    [Fact]
    public async Task PrepareForShutdown_NominalSuccessWithoutTypedProofsIsNotSafe()
    {
        var mount = Mounted("device-1", "device-1|Main", "E:\\");
        var backend = new ShutdownBackend(
            [mount],
            [new UnmountResult(
                Success: true,
                MountPoint: mount.MountPoint,
                Error: null,
                MountRemoved: true)]);
        using var worker = CreateWorker(backend);

        var result = await worker.PrepareForShutdownAsync(CancellationToken.None);

        Assert.False(result.CleanupCompleted);
        Assert.False(result.HostOwnershipReleased);
        Assert.False(result.PendingDurabilityCleared);
        Assert.Empty(result.RemainingMounts);
        var unmount = Assert.Single(result.UnmountResultsOrEmpty).Value;
        Assert.True(unmount.Success);
        Assert.True(unmount.MountRemoved);
        Assert.False(unmount.HostOwnershipReleased);
        Assert.False(unmount.PendingDurabilityCleared);
    }

    [Fact]
    public async Task PrepareForShutdown_ErrorRetainsCompletedFailedAndNotReachedResults()
    {
        var first = Mounted("device-1", "device-1|One", "E:\\");
        var second = Mounted("device-2", "device-2|Two", "F:\\");
        var third = Mounted("device-3", "device-3|Three", "G:\\");
        var backend = new ShutdownBackend(
            [first, second, third],
            (index, mountPoint, _) => index switch
            {
                0 => Task.FromResult(SafeUnmount(mountPoint)),
                1 => throw new InvalidOperationException("injected stop failure"),
                _ => throw new Xunit.Sdk.XunitException("A mount after the failed volume must not be attempted."),
            });
        using var worker = CreateWorker(backend);

        var result = await worker.PrepareForShutdownAsync(CancellationToken.None);

        Assert.False(result.CleanupCompleted);
        Assert.False(result.HostOwnershipReleased);
        Assert.False(result.PendingDurabilityCleared);
        Assert.Equal([second.VolumeId, third.VolumeId], result.RemainingMounts.Select(mount => mount.VolumeId));
        Assert.Equal(3, result.UnmountResultsOrEmpty.Count);
        Assert.True(result.UnmountResultsOrEmpty[first.VolumeId].PendingDurabilityCleared);
        Assert.Contains("injected stop failure", result.UnmountResultsOrEmpty[second.VolumeId].Error);
        Assert.Contains("not reached", result.UnmountResultsOrEmpty[third.VolumeId].Error, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(2, backend.UnmountCalls);
        Assert.False(backend.MountStateTokenWasCancelled[^1]);
    }

    [Fact]
    public async Task PrepareForShutdown_TimeoutRetainsAllResultsAndReconcilesWithIndependentToken()
    {
        var first = Mounted("device-1", "device-1|One", "E:\\");
        var second = Mounted("device-2", "device-2|Two", "F:\\");
        var third = Mounted("device-3", "device-3|Three", "G:\\");
        var backend = new ShutdownBackend(
            [first, second, third],
            async (index, mountPoint, cancellationToken) =>
            {
                if (index == 0)
                {
                    return SafeUnmount(mountPoint);
                }

                await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
                throw new Xunit.Sdk.XunitException("The timed-out unmount should be cancelled.");
            });
        using var worker = CreateWorker(backend);

        var result = await worker.PrepareForShutdownAsync(CancellationToken.None);

        Assert.False(result.CleanupCompleted);
        Assert.False(result.HostOwnershipReleased);
        Assert.False(result.PendingDurabilityCleared);
        Assert.Equal([second.VolumeId, third.VolumeId], result.RemainingMounts.Select(mount => mount.VolumeId));
        Assert.Equal(3, result.UnmountResultsOrEmpty.Count);
        Assert.True(result.UnmountResultsOrEmpty[first.VolumeId].HostOwnershipReleased);
        Assert.Contains("cancel", result.UnmountResultsOrEmpty[second.VolumeId].Error, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("not reached", result.UnmountResultsOrEmpty[third.VolumeId].Error, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(2, backend.UnmountCalls);
        Assert.False(backend.MountStateTokenWasCancelled[^1]);
    }

    private static ApfsMountWorker CreateWorker(IApfsBackend backend)
        => new(
            NullLogger<ApfsMountWorker>.Instance,
            backend,
            new NoopMountPolicy(),
            new RuntimeStatusPublisher(),
            new FixedOptionsMonitor(new ServiceHostOptions
            {
                NativeHostStopTimeoutSeconds = 1,
            }));

    private static MountedVolumeState Mounted(string deviceId, string volumeId, string mountPoint)
        => new(
            VolumeId: volumeId,
            MountPoint: mountPoint,
            AccessMode: MountAccessMode.ReadWrite,
            VolumeName: volumeId,
            DeviceId: deviceId,
            NativeWriteSafetyState: NativeWriteSafetyState.PilotReadWrite);

    private static UnmountResult SafeUnmount(string mountPoint)
        => new(
            Success: true,
            MountPoint: mountPoint,
            Error: null,
            MountRemoved: true,
            HostOwnershipReleased: true,
            PendingDurabilityCleared: true);

    private sealed class ShutdownBackend : IApfsBackend
    {
        private readonly List<MountedVolumeState> _mounts;
        private readonly Func<int, string, CancellationToken, Task<UnmountResult>> _unmount;
        private int _unmountIndex;

        public ShutdownBackend(
            IReadOnlyList<MountedVolumeState> mounts,
            IReadOnlyList<UnmountResult> unmountResults)
            : this(
                mounts,
                (index, mountPoint, _) => Task.FromResult(
                    unmountResults[index] with { MountPoint = mountPoint }))
        {
        }

        public ShutdownBackend(
            IReadOnlyList<MountedVolumeState> mounts,
            Func<int, string, CancellationToken, Task<UnmountResult>> unmount)
        {
            _mounts = [.. mounts];
            _unmount = unmount;
        }

        public int UnmountCalls => _unmountIndex;

        public List<bool> MountStateTokenWasCancelled { get; } = [];

        public Task<IReadOnlyList<DeviceInfo>> ProbeDevicesAsync(CancellationToken cancellationToken)
            => throw new NotSupportedException();

        public Task<IReadOnlyList<VolumeInfo>> ProbeVolumesAsync(
            string deviceId,
            CancellationToken cancellationToken)
            => throw new NotSupportedException();

        public Task<MountResult> MountAsync(MountRequest request, CancellationToken cancellationToken)
            => throw new NotSupportedException();

        public async Task<UnmountResult> UnmountAsync(string mountPoint, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var index = _unmountIndex++;
            var result = await _unmount(index, mountPoint, cancellationToken);
            if (result.MountRemoved)
            {
                _mounts.RemoveAll(mount => string.Equals(
                    mount.MountPoint,
                    mountPoint,
                    StringComparison.OrdinalIgnoreCase));
            }

            return result;
        }

        public Task<IReadOnlyList<MountedVolumeState>> GetMountStateAsync(
            CancellationToken cancellationToken)
        {
            MountStateTokenWasCancelled.Add(cancellationToken.IsCancellationRequested);
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult<IReadOnlyList<MountedVolumeState>>(_mounts.ToArray());
        }
    }

    private sealed class NoopMountPolicy : IMountPolicy
    {
        public char SelectDriveLetter(VolumeInfo volume, IReadOnlySet<char> usedLetters) => 'Z';

        public bool ShouldAutoMount(VolumeInfo volume) => false;
    }

    private sealed class FixedOptionsMonitor(ServiceHostOptions options) : IOptionsMonitor<ServiceHostOptions>
    {
        public ServiceHostOptions CurrentValue => options;

        public ServiceHostOptions Get(string? name) => options;

        public IDisposable? OnChange(Action<ServiceHostOptions, string?> listener) => null;
    }
}
