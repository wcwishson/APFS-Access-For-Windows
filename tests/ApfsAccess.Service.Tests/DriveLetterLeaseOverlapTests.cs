using System.Reflection;
using ApfsAccess.Core;
using ApfsAccess.Ipc;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace ApfsAccess.Service.Tests;

public sealed class DriveLetterLeaseOverlapTests : IDisposable
{
    private const BindingFlags Private = BindingFlags.NonPublic | BindingFlags.Instance;
    private readonly string _root = Path.Combine(Path.GetTempPath(), "letter-lease-" + Guid.NewGuid().ToString("N"));
    private static readonly Guid A = Guid.Parse("11111111-2222-3333-4444-555555555555");
    private static readonly Guid B = Guid.Parse("66666666-7777-8888-9999-aaaaaaaaaaaa");
    private static readonly VolumeInfo Volume = new("volume", "device", "Name", false,
        CatalogVolumeId: ApfsTopology.BuildVolumeId(new string('a', 32), 201), CatalogVolumeUuid: A.ToString("N"));
    public DriveLetterLeaseOverlapTests() => Directory.CreateDirectory(_root);
    public void Dispose() => Directory.Delete(_root, true);
    private VolumeDriveLetterAssignments Store() => new(Path.Combine(_root, "letters.json"));
    private static Task Cycle(ApfsMountWorker worker) => (Task)typeof(ApfsMountWorker).GetMethod("RunCycleAsync", Private)!.Invoke(worker, [CancellationToken.None])!;
    private static ApfsMountWorker Worker(Backend backend, IMountPolicy policy, RuntimeStatusPublisher publisher)
        => new(NullLogger<ApfsMountWorker>.Instance, backend, policy, publisher, new Options());
    private static DriveLetterPreferenceRequestPayload Request => new(Volume.DeviceId, Volume.VolumeId, A.ToString("D"), "T");

    // The callback runs inside production WithState, after the real .lock lease and
    // checked JSON read. No mock serializes or replaces the storage operation.
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
                    Assert.Equal('T', state[A]);
                    Entered.SetResult();
                    if (!_release.Task.Wait(TimeSpan.FromSeconds(15))) throw new TimeoutException("Lease test was not released.");
                    return false;
                };
                Assert.Equal(true, typeof(VolumeDriveLetterAssignments).GetMethod("WithState", Private)!.Invoke(store, [read, CancellationToken.None]));
            });
        }
        public async ValueTask DisposeAsync() { _release.TrySetResult(); await _read; }
    }

    [Theory]
    [InlineData("cycle")]
    [InlineData("refresh")]
    [InlineData("exact")]
    [InlineData("batch")]
    public async Task ActualReadLeaseCannotDiscardAvailableSavedT(string caller)
    {
        var store = Store();
        Assert.True(store.SetPreference(A, 'T'));
        var backend = new Backend { Batch = caller == "batch" };
        var publisher = new RuntimeStatusPublisher();
        using var worker = Worker(backend, new FirstFreeMountPolicy(["R", "T", "S"], store), publisher);
        var lease = new ReadLease(store);
        Task operation = Task.CompletedTask;
        try
        {
            await lease.Entered.Task.WaitAsync(TimeSpan.FromSeconds(3));
            Assert.Throws<IOException>(() => new FileStream(Path.Combine(_root, "letters.json.lock"), FileMode.CreateNew).Dispose());
            operation = caller switch
            {
                "refresh" => worker.RefreshAsync(false, CancellationToken.None),
                "exact" => worker.EnsureMountedExactAsync(Volume.DeviceId, Volume.VolumeId, null, CancellationToken.None),
                _ => Cycle(worker)
            };
            // Reach a real queued settings operation, not merely an unscheduled task.
            await WaitForSettingsWaiter(store);
            var mountGate = (SemaphoreSlim)typeof(ApfsMountWorker).GetField("_mountOperationLock", Private)!.GetValue(worker)!;
            Assert.True(await mountGate.WaitAsync(TimeSpan.FromSeconds(2)));
            mountGate.Release();
            Assert.Empty(backend.Requests);
        }
        finally { await lease.DisposeAsync(); await operation.WaitAsync(TimeSpan.FromSeconds(5)); }
        Assert.Equal('T', Assert.Single(backend.Requests, r => r.VolumeId == Volume.VolumeId).DriveLetter);
        Assert.Equal(caller == "batch" ? 2 : 1, backend.Requests.Count);
        Assert.Equal("T", publisher.Latest.MountedVolumes!.Single(m => m.VolumeId == Volume.VolumeId).DriveLetterPreference!.PreferredLetter);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ConcurrentInventoryAndExplicitSaveWaitForRealReadLease(bool separateStore)
    {
        var store = Store();
        Assert.True(store.SetPreference(A, 'T'));
        using var worker = Worker(new(), new FirstFreeMountPolicy(["R", "T"], store), new());
        var lease = new ReadLease(separateStore ? Store() : store);
        Task<IReadOnlyList<DeviceInventory>>? inventory = null;
        Task<AckPayload>? save = null;
        try
        {
            await lease.Entered.Task.WaitAsync(TimeSpan.FromSeconds(3));
            inventory = worker.GetInventoryAsync(CancellationToken.None);
            save = worker.SetDriveLetterPreferenceAsync(Request, CancellationToken.None);
            await WaitForSettingsWaiter(store);
            Assert.False(inventory.IsCompleted);
            Assert.False(save.IsCompleted);
            Assert.True((await worker.EjectAllAsync(CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(2))).Success);
        }
        finally { await lease.DisposeAsync(); }
        Assert.True((await save!.WaitAsync(TimeSpan.FromSeconds(5))).Success);
        Assert.Equal("T", Assert.Single(Assert.Single(await inventory!).Volumes).DriveLetterPreference!.PreferredLetter);
    }

    [Fact]
    public async Task CancellationWhileWaitingForRealReadLeaseDoesNotCommit()
    {
        var store = Store();
        Assert.True(store.SetPreference(A, 'T'));
        var before = File.ReadAllBytes(Path.Combine(_root, "letters.json"));
        using var worker = Worker(new(), new FirstFreeMountPolicy(["R", "T"], store), new());
        await using var lease = new ReadLease(store);
        await lease.Entered.Task.WaitAsync(TimeSpan.FromSeconds(3));
        using var cancel = new CancellationTokenSource();
        var save = worker.SetDriveLetterPreferenceAsync(Request with { Letter = "R" }, cancel.Token);
        await WaitForSettingsWaiter(store);
        cancel.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => save.WaitAsync(TimeSpan.FromSeconds(3)));
        Assert.Equal(before, File.ReadAllBytes(Path.Combine(_root, "letters.json")));
        Assert.True((await worker.EjectAllAsync(CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(2))).Success);
    }

    [Theory]
    [InlineData("eject")]
    [InlineData("replacement")]
    public async Task SelectionRevalidatesAfterWaitingForActualLease(string competing)
    {
        var store = Store();
        Assert.True(store.SetPreference(A, 'T'));
        var backend = new Backend();
        using var worker = Worker(backend, new FirstFreeMountPolicy(["R", "T"], store), new());
        var lease = new ReadLease(store);
        Task cycle = Task.CompletedTask;
        Task? inventory = null;
        try
        {
            await lease.Entered.Task.WaitAsync(TimeSpan.FromSeconds(3));
            cycle = Cycle(worker);
            await WaitForSettingsWaiter(store);
            if (competing == "eject")
                Assert.True((await worker.EjectAllAsync(CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(2))).Success);
            else
            {
                backend.Volumes = [Volume with { CatalogVolumeUuid = B.ToString("D") }];
                inventory = worker.GetInventoryAsync(CancellationToken.None);
                Assert.Equal(2, backend.Observations);
            }
        }
        finally { await lease.DisposeAsync(); await cycle.WaitAsync(TimeSpan.FromSeconds(5)); if (inventory is not null) await inventory; }
        Assert.Empty(backend.Requests);
        Assert.True(store.TryGetPreference(A, out var saved));
        Assert.Equal('T', saved);
        Assert.True(store.TryGetPreference(B, out var replacement));
        Assert.Null(replacement);
    }

    private static async Task WaitForSettingsWaiter(VolumeDriveLetterAssignments store)
    {
        // Monitor.Wait inside SemaphoreSlim.Wait increments this field while the
        // real synchronous store caller waits. Inspect only test-owned objects.
        var gate = (SemaphoreSlim)typeof(VolumeDriveLetterAssignments).GetField("_settingsGate", Private)!.GetValue(store)!;
        var count = typeof(SemaphoreSlim).GetField("m_waitCount", Private)!;
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(3));
        while ((int)count.GetValue(gate)! == 0) await Task.Delay(5, timeout.Token);
    }

    [Fact]
    public async Task PreferenceSubscriberCanReenterInventoryAndSaveOutsideWorkerLocks()
    {
        var publisher = new RuntimeStatusPublisher();
        using var worker = Worker(new(), new FirstFreeMountPolicy(["R", "T"], Store()), publisher);
        await Cycle(worker);
        var invoked = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        publisher.StatusChanged += payload =>
        {
            if (payload.MountedVolumes?.SingleOrDefault()?.DriveLetterPreference?.PreferredLetter != "T") return;
            try
            {
                Task.Run(async () =>
                {
                    _ = publisher.Latest;
                    await worker.GetInventoryAsync(CancellationToken.None);
                    Assert.True((await worker.SetDriveLetterPreferenceAsync(Request, CancellationToken.None)).Success);
                }).WaitAsync(TimeSpan.FromSeconds(3)).GetAwaiter().GetResult();
                invoked.TrySetResult();
            }
            catch (Exception ex) { invoked.TrySetException(ex); }
        };
        Assert.True((await worker.SetDriveLetterPreferenceAsync(Request, CancellationToken.None)).Success);
        await invoked.Task.WaitAsync(TimeSpan.FromSeconds(5));
    }

    [Fact]
    public async Task AtomicReplacementRejectsActualCompetingEjectAndPreservesItsWholePayload()
    {
        var backend = new Backend();
        var publisher = new RuntimeStatusPublisher();
        using var worker = Worker(backend, new FirstFreeMountPolicy(["R", "T"], Store()), publisher);
        await Cycle(worker);
        var expected = publisher.Latest;
        Assert.Single(expected.MountedVolumes!);
        var attempted = expected with { MountedVolumes = expected.MountedVolumes!.Select(m => m with
            { DriveLetterPreference = new(A.ToString("D"), "T", "R", "next-mount", "Saved", "RT", true) }).ToArray() };
        var checkedStatus = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var replace = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var publication = Task.Run(async () =>
        {
            Assert.Same(expected, publisher.Latest); // The old caller-side check passed.
            checkedStatus.SetResult();
            await replace.Task;
            Assert.False(publisher.TryPublish(expected, attempted, out var notify));
            Assert.Null(notify);
        });
        try
        {
            await checkedStatus.Task.WaitAsync(TimeSpan.FromSeconds(3));
            Assert.True((await worker.EjectAllAsync(CancellationToken.None)).Success);
            Assert.Equal(1, backend.Unmounts);
            var ejected = publisher.Latest;
            Assert.Empty(ejected.MountedVolumes!);
            Assert.Empty(ejected.MountPoints);
            Assert.NotEmpty(ejected.Warnings);
            replace.SetResult();
            await publication.WaitAsync(TimeSpan.FromSeconds(3));
            // Reference identity proves every non-preference field (health, warnings,
            // durability, timestamp, mounts and errors) is still the eject payload.
            Assert.Same(ejected, publisher.Latest);
        }
        finally { replace.TrySetResult(); await publication; }
    }

    private sealed class Options : IOptionsMonitor<ServiceHostOptions>
    {
        public ServiceHostOptions CurrentValue { get; } = new() { AutoMountEnabled = true, EnableNativeWrite = false };
        public ServiceHostOptions Get(string? name) => CurrentValue;
        public IDisposable? OnChange(Action<ServiceHostOptions, string?> listener) => null;
    }
    private sealed class Backend : IApfsBackend, IContainerMountBackend
    {
        public bool Batch;
        public VolumeInfo[] Volumes = [Volume];
        public List<MountRequest> Requests { get; } = [];
        private readonly List<MountedVolumeState> _mounts = [];
        public int Observations;
        public int Unmounts;
        public Task<IReadOnlyList<DeviceInventory>> ProbeInventoryAsync(bool authoritative, CancellationToken token)
        {
            Observations++;
            var volumes = Batch ? new[] { Volume, Volume with { VolumeId = "sibling", CatalogVolumeId = ApfsTopology.BuildVolumeId(new string('a', 32), 202), CatalogVolumeUuid = B.ToString("N") } } : Volumes;
            return Task.FromResult<IReadOnlyList<DeviceInventory>>([new(new("device", "Disk", true), volumes)]);
        }
        public Task<IReadOnlyList<DeviceInfo>> ProbeDevicesAsync(CancellationToken token) => throw new NotSupportedException();
        public Task<IReadOnlyList<VolumeInfo>> ProbeVolumesAsync(string device, CancellationToken token) => throw new NotSupportedException();
        public Task<IReadOnlyList<MountedVolumeState>> GetMountStateAsync(CancellationToken token) => Task.FromResult<IReadOnlyList<MountedVolumeState>>(_mounts.ToArray());
        public Task<MountResult> MountAsync(MountRequest request, CancellationToken token)
        {
            Requests.Add(request);
            _mounts.Add(new(request.VolumeId, $"{request.DriveLetter}:\\", MountAccessMode.ReadOnly, "Name", "device", "Disk",
                CatalogVolumeId: request.VolumeId == Volume.VolumeId ? Volume.CatalogVolumeId : ApfsTopology.BuildVolumeId(new string('a', 32), 202)));
            return Task.FromResult(new MountResult(true, $"{request.DriveLetter}:\\", null, MountAccessMode.ReadOnly));
        }
        public async Task<IReadOnlyList<MountResult>> MountContainerAsync(IReadOnlyList<MountRequest> requests, CancellationToken token)
        {
            var results = new List<MountResult>();
            foreach (var request in requests) results.Add(await MountAsync(request, token));
            return results;
        }
        public Task<UnmountResult> UnmountAsync(string path, CancellationToken token)
        {
            Unmounts++;
            _mounts.RemoveAll(m => m.MountPoint == path);
            return Task.FromResult(new UnmountResult(true, path, null, true, true, true));
        }
    }
}
