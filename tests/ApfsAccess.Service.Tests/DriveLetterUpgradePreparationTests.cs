using System.Reflection;
using ApfsAccess.Core;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace ApfsAccess.Service.Tests;

public sealed class DriveLetterUpgradePreparationTests : IDisposable
{
    private const BindingFlags Private = BindingFlags.Instance | BindingFlags.NonPublic;
    private static readonly Guid Uuid = Guid.Parse("11111111-2222-3333-4444-555555555555");
    private static readonly Guid ReplacementUuid = Guid.Parse("66666666-7777-8888-9999-aaaaaaaaaaaa");
    private static readonly VolumeInfo Volume = new("volume", "device", "Upgrade", false,
        CatalogVolumeId: ApfsTopology.BuildVolumeId(new string('a', 32), 201), CatalogVolumeUuid: Uuid.ToString("D"));
    private readonly string _root = Path.Combine(Path.GetTempPath(), "upgrade-preparation-" + Guid.NewGuid().ToString("N"));
    private readonly VolumeDriveLetterAssignments _store;
    private readonly Backend _backend = new();
    private readonly RuntimeStatusPublisher _publisher = new();
    private readonly ApfsMountWorker _worker;

    public DriveLetterUpgradePreparationTests()
    {
        Directory.CreateDirectory(_root);
        _store = new(Path.Combine(_root, "letters.json"));
        Assert.True(_store.SetPreference(Uuid, 'T'));
        _worker = new(NullLogger<ApfsMountWorker>.Instance, _backend,
            new FirstFreeMountPolicy(["R", "T"], _store), _publisher, new Options());
    }

    public void Dispose() { _worker.Dispose(); Directory.Delete(_root, true); }
    private Task Cycle() => (Task)typeof(ApfsMountWorker).GetMethod("RunCycleAsync", Private)!.Invoke(_worker, [CancellationToken.None])!;

    private async Task<MountedVolumeState> StartUpgrade()
    {
        await Cycle();
        var original = Assert.Single(await _backend.GetMountStateAsync(CancellationToken.None));
        Assert.Equal(MountAccessMode.ReadOnly, original.AccessMode);
        Assert.Equal("T:\\", original.MountPoint);
        Assert.Equal(MountAccessMode.ReadOnly, Assert.Single(_backend.Requests).AccessMode);
        AssertConsistentMount(original);
        _backend.CurrentVolume = Volume with { SupportsNativeWrite = true };
        Assert.True(WriteGatePolicy.EvaluateForVolume(new Options().CurrentValue, _backend.CurrentVolume).AllowWrite);
        return original;
    }

    private void AssertConsistentMount(MountedVolumeState expected)
    {
        Assert.Equal(expected, Assert.Single(_backend.Mounts));
        var published = Assert.Single(_publisher.Latest.MountedVolumes!);
        Assert.Equal(expected.VolumeId, published.VolumeId);
        Assert.Equal(expected.MountPoint, published.MountPoint);
        Assert.Equal(expected.AccessMode, published.AccessMode);
        Assert.Equal([expected.MountPoint], _publisher.Latest.MountPoints);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task EjectDuringUpgradePreparationSurvivesOrdinaryCycle(bool targeted)
    {
        await StartUpgrade();
        var lease = new ReadLease(_store);
        Task<(bool Success, string Message)>? refresh = null;
        bool ejectSuccess = false;
        try
        {
            await lease.Entered.Task.WaitAsync(TimeSpan.FromSeconds(3));
            Assert.Throws<IOException>(() => new FileStream(Path.Combine(_root, "letters.json.lock"), FileMode.CreateNew).Dispose());
            refresh = _worker.RefreshAsync(true, CancellationToken.None);
            await WaitForSettingsWaiter();
            // This must finish while the real storage lease is still held.
            ejectSuccess = targeted
                ? (await _worker.EjectExactAsync(Volume.DeviceId, Volume.VolumeId, CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(3))).Success
                : (await _worker.EjectAllAsync(CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(3))).Success;
        }
        finally { await lease.DisposeAsync(); if (refresh is not null) await refresh.WaitAsync(TimeSpan.FromSeconds(5)); }

        Assert.False((await refresh!).Success);
        Assert.Empty(_backend.Mounts);
        Assert.Empty(_publisher.Latest.MountedVolumes!);
        await Cycle(); // Shipped reconnect policy is enabled; no explicit reset of eject suppression.
        Assert.Empty(_backend.Mounts);
        Assert.Empty(_publisher.Latest.MountedVolumes!);
        Assert.Empty(_publisher.Latest.MountPoints);
        Assert.Single(_backend.Requests);
        Assert.Equal(1, _backend.Unmounts);
        Assert.True(ejectSuccess);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task NewerInventoryDuringUpgradePreparationKeepsOriginalMountAndStatus(bool replaceUuid)
    {
        var original = await StartUpgrade();
        var originalStatus = _publisher.Latest;
        var lease = new ReadLease(_store);
        Task<(bool Success, string Message)>? refresh = null;
        Task<IReadOnlyList<DeviceInventory>>? inventory = null;
        try
        {
            await lease.Entered.Task.WaitAsync(TimeSpan.FromSeconds(3));
            refresh = _worker.RefreshAsync(true, CancellationToken.None);
            await WaitForSettingsWaiter();
            if (replaceUuid) _backend.CurrentVolume = _backend.CurrentVolume with { CatalogVolumeUuid = ReplacementUuid.ToString("D") };
            inventory = _worker.GetInventoryAsync(CancellationToken.None);
            // Probe and admission run synchronously before inventory's storage read.
            Assert.Equal(3, _backend.Observations);
            Assert.False(inventory.IsCompleted);
        }
        finally
        {
            await lease.DisposeAsync();
            if (refresh is not null) await refresh.WaitAsync(TimeSpan.FromSeconds(5));
            if (inventory is not null) await inventory.WaitAsync(TimeSpan.FromSeconds(5));
        }
        Assert.False((await refresh!).Success);
        AssertConsistentMount(original);
        Assert.Same(originalStatus, _publisher.Latest);
        Assert.Equal(0, _backend.Unmounts);
        Assert.Single(_backend.Requests);
        Assert.True(_store.TryGetPreference(Uuid, out var saved));
        Assert.Equal('T', saved);
        Assert.True(_store.TryGetPreference(ReplacementUuid, out var replacement));
        Assert.Null(replacement);
    }

    [Fact]
    public async Task UpgradeReusesPreparedSavedLetterWithoutStorageWaitAfterUnmount()
    {
        await StartUpgrade();
        ReadLease? afterUnmount = null;
        _backend.AfterUnmount = async () =>
        {
            afterUnmount = new ReadLease(_store);
            await afterUnmount.Entered.Task.WaitAsync(TimeSpan.FromSeconds(3));
        };
        Task<(bool Success, string Message)>? refresh = null;
        try
        {
            refresh = _worker.RefreshAsync(true, CancellationToken.None);
            Assert.True((await refresh.WaitAsync(TimeSpan.FromSeconds(3))).Success);
            var upgraded = Assert.Single(_backend.Mounts);
            Assert.Equal(MountAccessMode.ReadWrite, upgraded.AccessMode);
            Assert.Equal("T:\\", upgraded.MountPoint); // The old T must be excluded from occupancy.
            AssertConsistentMount(upgraded);
            Assert.Equal(2, _backend.Requests.Count);
            Assert.All(_backend.Requests, request => Assert.Equal('T', request.DriveLetter));
            Assert.Equal(1, _backend.Unmounts);
        }
        finally
        {
            if (afterUnmount is not null) await afterUnmount.DisposeAsync();
            if (refresh is not null) await refresh.WaitAsync(TimeSpan.FromSeconds(5));
        }
    }

    [Fact]
    public async Task MultipleUpgradesPrepareAllLettersBeforeFirstUnmount()
    {
        await StartUpgrade();
        Assert.True(_store.SetPreference(ReplacementUuid, 'R'));
        _backend.Sibling = Volume with
        {
            VolumeId = "sibling", CatalogVolumeId = ApfsTopology.BuildVolumeId(new string('a', 32), 202),
            CatalogVolumeUuid = ReplacementUuid.ToString("D")
        };
        await Cycle();
        Assert.Equal(2, _backend.Mounts.Count);
        Assert.All(_backend.Mounts, mount => Assert.Equal(MountAccessMode.ReadOnly, mount.AccessMode));
        _backend.Sibling = _backend.Sibling with { SupportsNativeWrite = true };
        ReadLease? afterUnmount = null;
        _backend.AfterUnmount = async () =>
        {
            if (afterUnmount is not null) return;
            afterUnmount = new ReadLease(_store);
            await afterUnmount.Entered.Task.WaitAsync(TimeSpan.FromSeconds(3));
        };
        Task<(bool Success, string Message)>? refresh = null;
        try
        {
            refresh = _worker.RefreshAsync(true, CancellationToken.None);
            Assert.True((await refresh.WaitAsync(TimeSpan.FromSeconds(3))).Success);
            Assert.Equal(2, _backend.Mounts.Count);
            Assert.Equal(2, _publisher.Latest.MountedVolumes!.Count);
            Assert.All(_backend.Mounts, mount => Assert.Equal(MountAccessMode.ReadWrite, mount.AccessMode));
            Assert.All(_publisher.Latest.MountedVolumes!, mount => Assert.Equal(MountAccessMode.ReadWrite, mount.AccessMode));
            Assert.Equal(new[] { 'T', 'R', 'T', 'R' }, _backend.Requests.Select(request => request.DriveLetter));
            Assert.Equal(2, _backend.Unmounts);
        }
        finally
        {
            if (afterUnmount is not null) await afterUnmount.DisposeAsync();
            if (refresh is not null) await refresh.WaitAsync(TimeSpan.FromSeconds(5));
        }
    }

    [Fact]
    public async Task CancellationDuringUpgradePreparationKeepsOriginalAndReleasesMountGate()
    {
        var original = await StartUpgrade();
        await using var lease = new ReadLease(_store);
        await lease.Entered.Task.WaitAsync(TimeSpan.FromSeconds(3));
        using var cancel = new CancellationTokenSource();
        var refresh = _worker.RefreshAsync(true, cancel.Token);
        await WaitForSettingsWaiter();
        cancel.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => refresh.WaitAsync(TimeSpan.FromSeconds(3)));
        AssertConsistentMount(original);
        Assert.Equal(0, _backend.Unmounts);
        Assert.True((await _worker.EjectAllAsync(CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(3))).Success);
    }

    [Fact]
    public async Task RuntimeTelemetryRefreshDoesNotInvalidatePreparedUpgrade()
    {
        await StartUpgrade();
        _backend.RefreshDiagnostics = true;
        Assert.True((await _worker.RefreshAsync(true, CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(3))).Success);
        var upgraded = Assert.Single(_backend.Mounts);
        Assert.Equal(MountAccessMode.ReadWrite, upgraded.AccessMode);
        Assert.Equal("T:\\", upgraded.MountPoint);
        AssertConsistentMount(upgraded);
        Assert.Equal(2, _backend.Requests.Count);
        Assert.Equal(1, _backend.Unmounts);
    }

    [Fact]
    public async Task CancellationAfterUnmountDoesNotConsumePreparedLetterAndReleasesMountGate()
    {
        await StartUpgrade();
        using var cancel = new CancellationTokenSource();
        _backend.AfterUnmount = () => { cancel.Cancel(); return Task.CompletedTask; };
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            _worker.RefreshAsync(true, cancel.Token).WaitAsync(TimeSpan.FromSeconds(3)));
        Assert.Empty(_backend.Mounts);
        Assert.Single(_backend.Requests);
        Assert.Equal(1, _backend.Unmounts);
        Assert.True((await _worker.EjectAllAsync(CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(3))).Success);
        Assert.Empty(_publisher.Latest.MountedVolumes!);
    }

    [Fact]
    public async Task BackendReplacementDuringPreparationRejectsOldPlanAndPublishesCurrentMount()
    {
        var original = await StartUpgrade();
        var replacement = original with { MountPoint = "R:\\", RecoveryIdentity = "replacement-instance" };
        var lease = new ReadLease(_store);
        Task<(bool Success, string Message)>? refresh = null;
        try
        {
            await lease.Entered.Task.WaitAsync(TimeSpan.FromSeconds(3));
            refresh = _worker.RefreshAsync(true, CancellationToken.None);
            await WaitForSettingsWaiter();
            _backend.Mounts[0] = replacement;
        }
        finally { await lease.DisposeAsync(); if (refresh is not null) await refresh.WaitAsync(TimeSpan.FromSeconds(5)); }
        Assert.True((await refresh!).Success);
        AssertConsistentMount(replacement);
        Assert.Equal(0, _backend.Unmounts);
        Assert.Single(_backend.Requests);
    }

    private async Task WaitForSettingsWaiter()
    {
        var gate = (SemaphoreSlim)typeof(VolumeDriveLetterAssignments).GetField("_settingsGate", Private)!.GetValue(_store)!;
        var count = typeof(SemaphoreSlim).GetField("m_waitCount", Private)!;
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(3));
        while ((int)count.GetValue(gate)! == 0) await Task.Delay(5, timeout.Token);
    }

    // Production WithState owns both the shared settings gate and the exclusive
    // filesystem lease before invoking this read-only callback.
    private sealed class ReadLease : IAsyncDisposable
    {
        private readonly TaskCompletionSource _release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly Task _read;
        public ReadLease(VolumeDriveLetterAssignments store)
        {
            _read = Task.Run(() =>
            {
                Func<Dictionary<Guid, char>, bool> read = state =>
                {
                    Assert.Equal('T', state[Uuid]);
                    Entered.SetResult();
                    if (!_release.Task.Wait(TimeSpan.FromSeconds(15))) throw new TimeoutException("Lease not released.");
                    return false;
                };
                Assert.Equal(true, typeof(VolumeDriveLetterAssignments).GetMethod("WithState", Private)!.Invoke(store, [read, CancellationToken.None]));
            });
        }
        public async ValueTask DisposeAsync() { _release.TrySetResult(); await _read; }
    }

    private sealed class Options : IOptionsMonitor<ServiceHostOptions>
    {
        public ServiceHostOptions CurrentValue { get; } = new()
        {
            AutoMountEnabled = true, EnableNativeWrite = true, WriteRolloutChannel = "Enabled",
            NativeAutoRemountOnReconnect = true
        };
        public ServiceHostOptions Get(string? name) => CurrentValue;
        public IDisposable? OnChange(Action<ServiceHostOptions, string?> listener) => null;
    }

    private sealed class Backend : IApfsBackend
    {
        public VolumeInfo CurrentVolume = Volume;
        public VolumeInfo? Sibling;
        public List<MountRequest> Requests { get; } = [];
        public List<MountedVolumeState> Mounts { get; } = [];
        public int Observations;
        public int Unmounts;
        public bool RefreshDiagnostics;
        public Func<Task>? AfterUnmount;
        public Task<IReadOnlyList<DeviceInventory>> ProbeInventoryAsync(bool authoritative, CancellationToken token)
        {
            Observations++;
            return Task.FromResult<IReadOnlyList<DeviceInventory>>([new(new("device", "Disk", true),
                Sibling is null ? [CurrentVolume] : [CurrentVolume, Sibling])]);
        }
        public Task<IReadOnlyList<DeviceInfo>> ProbeDevicesAsync(CancellationToken token) => throw new NotSupportedException();
        public Task<IReadOnlyList<VolumeInfo>> ProbeVolumesAsync(string device, CancellationToken token) => throw new NotSupportedException();
        public Task<IReadOnlyList<MountedVolumeState>> GetMountStateAsync(CancellationToken token)
        {
            if (RefreshDiagnostics)
                for (var i = 0; i < Mounts.Count; i++)
                    Mounts[i] = Mounts[i] with { NativeWriteDiagnostics = [], WalAcceptedSequence = Mounts[i].WalAcceptedSequence + 1 };
            return Task.FromResult<IReadOnlyList<MountedVolumeState>>(Mounts.ToArray());
        }
        public Task<MountResult> MountAsync(MountRequest request, CancellationToken token)
        {
            Requests.Add(request);
            var path = $"{request.DriveLetter}:\\";
            Mounts.Add(new(request.VolumeId, path, request.AccessMode, "Upgrade", "device", "Disk",
                CatalogVolumeId: request.VolumeId == Volume.VolumeId ? Volume.CatalogVolumeId : Sibling!.CatalogVolumeId));
            return Task.FromResult(new MountResult(true, path, null, request.AccessMode));
        }
        public async Task<UnmountResult> UnmountAsync(string path, CancellationToken token)
        {
            Unmounts++;
            Mounts.RemoveAll(m => m.MountPoint == path);
            if (AfterUnmount is not null) await AfterUnmount();
            return new(true, path, null, true, true, true);
        }
    }
}
