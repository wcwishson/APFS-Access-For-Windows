using ApfsAccess.Core;
using ApfsAccess.Backend.Native;
using ApfsAccess.Service;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace ApfsAccess.Service.Tests;

public sealed class ApfsMountWorkerShutdownProofTests
{
    [Fact]
    public async Task PrepareForShutdown_OneAttemptCompletesAfterAnOwnedDrainExceedsObservationWindow()
    {
        var first = Mounted("device-1", "device-1|Alpha", "E:\\");
        var last = Mounted("device-1", "device-1|Beta", "F:\\");
        var backend = new GracefulShutdownBackend([first, last], async (index, mountPoint, token) =>
        {
            token.ThrowIfCancellationRequested();
            if (index == 0) await Task.Delay(1500);
            return SafeUnmount(mountPoint);
        });
        using var worker = CreateWorker(backend);

        var result = await worker.PrepareForShutdownAsync(CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(6));

        Assert.True(result.CleanupCompleted, result.Diagnostic);
        Assert.True(result.HostOwnershipReleased);
        Assert.True(result.PendingDurabilityCleared);
        Assert.Empty(result.RemainingMounts);
        Assert.Equal(2, backend.UnmountCalls);
        Assert.DoesNotContain(true, backend.MountStateTokenWasCancelled);
    }

    [Fact]
    public async Task ExactEject_AcceptsProvenMemberDetachWhileOriginalSiblingOwnerRemains()
    {
        var first = SharedMounted("device-1|Alpha", "E:\\");
        var last = SharedMounted("device-1|Beta", "F:\\");
        var backend = new ShutdownBackend([first, last], (_, mountPoint, _) => Task.FromResult(
            SafeUnmount(mountPoint) with { HostOwnershipReleased = false, ContainerMemberDetached = true }));
        using var worker = CreateWorker(backend);

        var result = await worker.EjectExactAsync("device-1", first.VolumeId, CancellationToken.None, first.RecoveryIdentity);

        Assert.True(result.Success, result.Message);
        Assert.Equal(last, Assert.Single(result.RemainingMounts));
        var proof = result.UnmountResults[first.VolumeId];
        Assert.False(proof.HostOwnershipReleased);
        Assert.True(proof.ContainerMemberDetached);
        Assert.Equal(1, backend.UnmountCalls);
        Assert.Equal(0, backend.TerminalProofCalls);
    }

    [Theory]
    [InlineData("different-pid")]
    [InlineData("different-birth")]
    [InlineData("different-container")]
    [InlineData("different-device")]
    [InlineData("different-recovery")]
    [InlineData("not-ready")]
    [InlineData("draining")]
    public async Task ExactEject_RejectsUnprovedRetainedSibling(string change)
    {
        var first = SharedMounted("device-1|Alpha", "E:\\");
        var last = SharedMounted("device-1|Beta", "F:\\");
        var backend = new ShutdownBackend([first, last], (_, mountPoint, _) => Task.FromResult(
            SafeUnmount(mountPoint) with { HostOwnershipReleased = false, ContainerMemberDetached = true }))
        {
            TransformAfterUnmount = state => change switch
            {
                "different-pid" => state with { HostProcessId = state.HostProcessId + 1 },
                "different-birth" => state with { HostProcessCreationTimeFileTimeUtc = state.HostProcessCreationTimeFileTimeUtc + 1 },
                "different-container" => state with { CatalogContainerUuid = new string('b', 32) },
                "different-device" => state with { DeviceId = "device-2" },
                "different-recovery" => state with { RecoveryIdentity = "other-recovery" },
                "not-ready" => state with { MountReady = false },
                _ => state with { ShutdownDrainActive = true },
            },
        };
        using var worker = CreateWorker(backend);

        var result = await worker.EjectExactAsync("device-1", first.VolumeId, CancellationToken.None, first.RecoveryIdentity);

        Assert.False(result.Success);
        Assert.False(result.UnmountResults[first.VolumeId].ContainerMemberDetached);
        Assert.False(result.UnmountResults[first.VolumeId].HostOwnershipReleased);
    }

    [Fact]
    public async Task PrepareForShutdown_MemberDetachCannotReplaceOriginalHostExitProof()
    {
        var first = SharedMounted("device-1|Alpha", "E:\\");
        var last = SharedMounted("device-1|Beta", "F:\\");
        var backend = new ShutdownBackend([first, last], (_, mountPoint, _) => Task.FromResult(
            SafeUnmount(mountPoint) with { HostOwnershipReleased = false, ContainerMemberDetached = true }));
        using var worker = CreateWorker(backend);

        var result = await worker.PrepareForShutdownAsync(CancellationToken.None);

        Assert.False(result.CleanupCompleted);
        Assert.False(result.HostOwnershipReleased);
        Assert.True(backend.TerminalProofCalls > 0);
    }

    private static MountedVolumeState SharedMounted(string volumeId, string mountPoint)
        => Mounted("device-1", volumeId, mountPoint) with
        {
            CatalogContainerUuid = new string('a', 32),
            RecoveryIdentity = "apfs-recovery-v1-" + volumeId.Split('|')[1],
            MountReady = true,
        };

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task EjectAll_RequiresOriginalHostExitForEarlierDetachedMember(bool hostExited)
    {
        var first = SharedMounted("device-1|Alpha", "E:\\");
        var last = SharedMounted("device-1|Beta", "F:\\");
        var backend = new ShutdownBackend([first, last], (index, mountPoint, _) => Task.FromResult(
            index == 1 || (index > 1 && hostExited)
                ? SafeUnmount(mountPoint)
                : SafeUnmount(mountPoint) with { HostOwnershipReleased = false, ContainerMemberDetached = true }));
        using var worker = CreateWorker(backend);

        var result = await worker.EjectAsync(null, CancellationToken.None);

        Assert.Equal(hostExited, result.Success);
        Assert.Equal(2, backend.UnmountCalls);
        Assert.Equal(1, backend.TerminalProofCalls);
    }

    [Fact]
    public async Task PrepareForShutdown_RequeriesDetachedMemberAfterLastSharedHostMemberDrains()
    {
        var first = Mounted("device-1", "device-1|Alpha", "E:\\");
        var last = Mounted("device-1", "device-1|Beta", "F:\\");
        var backend = new ShutdownBackend([first, last], (index, mountPoint, _) =>
        {
            Assert.Equal(index == 1 ? last.MountPoint : first.MountPoint, mountPoint);
            return Task.FromResult(index == 0
                ? SafeUnmount(mountPoint) with { HostOwnershipReleased = false }
                : SafeUnmount(mountPoint));
        });
        using var worker = CreateWorker(backend);

        var result = await worker.PrepareForShutdownAsync(CancellationToken.None);

        Assert.Equal(2, backend.UnmountCalls);
        Assert.Equal(1, backend.TerminalProofCalls);
        Assert.True(result.CleanupCompleted);
        Assert.True(result.HostOwnershipReleased);
        Assert.True(result.PendingDurabilityCleared);
        Assert.Empty(result.RemainingMounts);
        Assert.Null(result.Diagnostic);
        Assert.All(result.UnmountResultsOrEmpty.Values, proof => Assert.True(proof.HostOwnershipReleased));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task EjectAll_DoesNotClaimSuccessWhenFinalMountAbsenceIsUnproved(bool observationThrows)
    {
        var first = SharedMounted("device-1|Alpha", "E:\\");
        var last = SharedMounted("device-1|Beta", "F:\\");
        var backend = new ShutdownBackend([first, last], (index, mountPoint, _) => Task.FromResult(
            index == 0 ? SafeUnmount(mountPoint) with { HostOwnershipReleased = false } : SafeUnmount(mountPoint)))
        {
            MountReportedAfterReproof = observationThrows ? null : first,
            ThrowStateReadAfterReproof = observationThrows,
        };
        using var worker = CreateWorker(backend);

        var result = await worker.EjectAsync(null, CancellationToken.None);

        Assert.False(result.Success);
        Assert.Equal(2, backend.UnmountCalls);
        Assert.Equal(1, backend.TerminalProofCalls);
        if (observationThrows)
            Assert.Contains("could not be verified", result.Message, StringComparison.OrdinalIgnoreCase);
        else
            Assert.Contains("E:", result.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData(false, true, true, true, "E:\\")]
    [InlineData(true, false, true, true, "E:\\")]
    [InlineData(true, true, false, true, "E:\\")]
    [InlineData(true, true, true, false, "E:\\")]
    [InlineData(true, true, true, true, "G:\\")]
    [InlineData(true, true, true, true, "E:\\")]
    public async Task PrepareForShutdown_RejectsIncompleteOrMismatchedTerminalReproof(
        bool success, bool removed, bool ownership, bool durability, string proofMountPoint)
    {
        var first = Mounted("device-1", "device-1|Alpha", "E:\\");
        var last = Mounted("device-1", "device-1|Beta", "F:\\");
        var detached = SafeUnmount(first.MountPoint) with { HostOwnershipReleased = false };
        var backend = new ShutdownBackend([first, last], (index, mountPoint, _) => Task.FromResult(index switch
        {
            0 => detached,
            1 => SafeUnmount(mountPoint),
            _ => new UnmountResult(success, proofMountPoint, "injected terminal proof failure", removed, ownership, durability),
        }));
        using var worker = CreateWorker(backend);

        var result = await worker.PrepareForShutdownAsync(CancellationToken.None);

        Assert.Equal(2, backend.UnmountCalls);
        Assert.Equal(1, backend.TerminalProofCalls);
        Assert.False(result.CleanupCompleted);
        Assert.False(result.HostOwnershipReleased);
        Assert.True(result.PendingDurabilityCleared);
        Assert.Equal(detached, result.UnmountResultsOrEmpty[first.VolumeId]);
        Assert.Contains("terminal proof", result.Diagnostic, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task PrepareForShutdown_RechecksAuthoritativeAbsenceAfterTerminalReproof()
    {
        var first = Mounted("device-1", "device-1|Alpha", "E:\\");
        var last = Mounted("device-1", "device-1|Beta", "F:\\");
        var backend = new ShutdownBackend([first, last], (index, mountPoint, _) => Task.FromResult(index == 0
            ? SafeUnmount(mountPoint) with { HostOwnershipReleased = false }
            : SafeUnmount(mountPoint))) { MountReportedAfterReproof = first };
        using var worker = CreateWorker(backend);

        var result = await worker.PrepareForShutdownAsync(CancellationToken.None);

        Assert.Equal(2, backend.UnmountCalls);
        Assert.Equal(1, backend.TerminalProofCalls);
        Assert.False(result.CleanupCompleted);
        Assert.False(result.HostOwnershipReleased);
        Assert.False(result.PendingDurabilityCleared);
        Assert.Equal(first, Assert.Single(result.RemainingMounts));
        Assert.True(result.UnmountResultsOrEmpty[first.VolumeId].HostOwnershipReleased);
        Assert.Contains("Remaining mounts: E:", result.Diagnostic);
    }

    [Fact]
    public async Task PrepareForShutdown_ActualDurabilityFailureIsNotReplacedBySiblingHostExit()
    {
        var first = Mounted("device-1", "device-1|Alpha", "E:\\");
        var last = Mounted("device-1", "device-1|Beta", "F:\\");
        var failed = new UnmountResult(false, first.MountPoint, "pending writes were not finalized safely", MountRemoved: true);
        var backend = new ShutdownBackend([first, last], (index, mountPoint, _) => Task.FromResult(index switch
        {
            0 => failed,
            1 => SafeUnmount(mountPoint),
            _ => failed,
        }));
        using var worker = CreateWorker(backend);

        var result = await worker.PrepareForShutdownAsync(CancellationToken.None);

        Assert.Equal(2, backend.UnmountCalls);
        Assert.Equal(1, backend.TerminalProofCalls);
        Assert.False(result.CleanupCompleted);
        Assert.False(result.HostOwnershipReleased);
        Assert.False(result.PendingDurabilityCleared);
        Assert.Equal(failed, result.UnmountResultsOrEmpty[first.VolumeId]);
        Assert.Contains(failed.Error!, result.Diagnostic);
    }

    [Fact]
    public async Task PrepareForShutdown_TerminalReproofTimeoutRetainsIndependentDurabilityEvidence()
    {
        var first = Mounted("device-1", "device-1|Alpha", "E:\\");
        var last = Mounted("device-1", "device-1|Beta", "F:\\");
        var detached = SafeUnmount(first.MountPoint) with { HostOwnershipReleased = false };
        var backend = new ShutdownBackend([first, last], async (index, mountPoint, token) =>
        {
            if (index == 0) return detached;
            if (index == 1) return SafeUnmount(mountPoint);
            await Task.Delay(Timeout.InfiniteTimeSpan, token);
            throw new Xunit.Sdk.XunitException("Terminal reproof must be bounded.");
        });
        using var worker = CreateWorker(backend);

        var result = await worker.PrepareForShutdownAsync(CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(5));

        Assert.False(result.CleanupCompleted);
        Assert.False(result.HostOwnershipReleased);
        Assert.True(result.PendingDurabilityCleared);
        Assert.Equal(detached, result.UnmountResultsOrEmpty[first.VolumeId]);
        Assert.Contains("terminal proof", result.Diagnostic, StringComparison.OrdinalIgnoreCase);
    }

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
            HostProcessId: 42,
            HostProcessCreationTimeFileTimeUtc: 134364468045847446,
            NativeWriteSafetyState: NativeWriteSafetyState.PilotReadWrite);

    private static UnmountResult SafeUnmount(string mountPoint)
        => new(
            Success: true,
            MountPoint: mountPoint,
            Error: null,
            MountRemoved: true,
            HostOwnershipReleased: true,
            PendingDurabilityCleared: true);

    private class ShutdownBackend : IApfsBackend, IUnmountTerminalStateBackend
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

        public int UnmountCalls => _unmountIndex - TerminalProofCalls;

        public int TerminalProofCalls { get; private set; }

        public Task<UnmountResult> GetUnmountTerminalStateAsync(MountedVolumeState selected, CancellationToken token)
        {
            TerminalProofCalls++;
            return _unmount(_unmountIndex++, selected.MountPoint, token);
        }

        public MountedVolumeState? MountReportedAfterReproof { get; init; }

        public bool ThrowStateReadAfterReproof { get; init; }

        public Func<MountedVolumeState, MountedVolumeState>? TransformAfterUnmount { get; init; }

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
            if (_unmountIndex > 2 && ThrowStateReadAfterReproof)
                throw new IOException("Injected final mount observation failure.");
            if (_unmountIndex > 2 && MountReportedAfterReproof is { } remaining)
                return Task.FromResult<IReadOnlyList<MountedVolumeState>>([remaining]);
            if (_unmountIndex > 0 && TransformAfterUnmount is not null)
                return Task.FromResult<IReadOnlyList<MountedVolumeState>>(_mounts.Select(TransformAfterUnmount).ToArray());
            return Task.FromResult<IReadOnlyList<MountedVolumeState>>(_mounts.ToArray());
        }
    }

    private sealed class GracefulShutdownBackend(
        IReadOnlyList<MountedVolumeState> mounts,
        Func<int, string, CancellationToken, Task<UnmountResult>> unmount)
        : ShutdownBackend(mounts, unmount), IGracefulShutdownBackend
    {
        public Task<UnmountResult> UnmountForShutdownAsync(string mountPoint, CancellationToken token)
            => UnmountAsync(mountPoint, token);
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
