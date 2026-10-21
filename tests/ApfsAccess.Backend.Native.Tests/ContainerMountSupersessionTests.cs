using System.Reflection;
using System.Text.Json;
using ApfsAccess.Core;
using ApfsAccess.Ipc;
using ApfsAccess.Service;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit.Abstractions;

namespace ApfsAccess.Backend.Native.Tests;

public sealed class ContainerMountSupersessionTests(ITestOutputHelper output)
{
    private const BindingFlags Private = BindingFlags.Instance | BindingFlags.NonPublic;
    private const string Container = "11111111222233334444555555555555";
    private static readonly Guid FirstUuid = Guid.Parse("66666666-7777-8888-9999-aaaaaaaaaaaa");
    private static readonly Guid SecondUuid = Guid.Parse("bbbbbbbb-cccc-dddd-eeee-ffffffffffff");
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    public async Task RejectedOlderCycleCannotSupersedeContainerLetterPreparation(int pausedSelection)
    {
        using var fixture = new Fixture(pausedSelection, pauseFirstDiscovery: true);
        var older = Cycle(fixture.Worker);
        await fixture.Backend.DiscoveryEntered.Task.WaitAsync(Timeout);
        var mount = fixture.Mount();
        try
        {
            await fixture.Policy.SelectionEntered.Task.WaitAsync(Timeout);
            var before = Generations(fixture.Worker);
            Assert.Equal((1L, 1L, 2L), before);
            Assert.Empty(fixture.Backend.Requests);
            fixture.Backend.ReleaseDiscovery.TrySetResult();
            await older.WaitAsync(Timeout);
            var after = Generations(fixture.Worker);
            output.WriteLine($"Before older cycle: {before}; after: {after}; backend batches: {fixture.Backend.BatchCalls}");
            // The rejected cycle must leave the admitted command and inventory intact.
            Assert.Equal(before.Command, after.Command);
            Assert.Equal(before.Discovery, after.Discovery);
            fixture.Policy.ReleaseSelection.TrySetResult();
            var result = await mount.WaitAsync(Timeout);
            output.WriteLine($"Container mount result: {result.Success}; diagnostic: {result.Message}");
            Assert.True(result.Success, result.Message);
            Assert.Equal(before.Operation, after.Operation);
            fixture.AssertMounted();
            Assert.Equal(2, fixture.Backend.Observations);
        }
        finally
        {
            fixture.Release();
            await older.WaitAsync(Timeout);
            await mount.WaitAsync(Timeout);
        }
    }

    [Fact]
    public async Task ContainerBatchUsesDistinctPersistedLettersWithoutCompetition()
    {
        using var fixture = new Fixture(pausedSelection: 0);
        Assert.True((await fixture.Mount().WaitAsync(Timeout)).Success);
        fixture.AssertMounted();
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    public async Task ConcurrentPreferenceChangeStillSupersedesEntireUnlaunchedBatch(int pausedSelection)
    {
        using var fixture = new Fixture(pausedSelection);
        await AssertSuperseded(fixture, async () =>
        {
            var volume = fixture.Backend.Volumes[0];
            var result = await fixture.Worker.SetDriveLetterPreferenceAsync(
                new(volume.DeviceId, volume.VolumeId, FirstUuid.ToString("D"), fixture.Letters[2].ToString()), default).WaitAsync(Timeout);
            Assert.True(result.Success, result.Message);
        });
        Assert.True(fixture.Store.TryGetPreference(FirstUuid, out var saved));
        Assert.Equal(fixture.Letters[2], saved);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ConcurrentEjectStillSupersedesEntireUnlaunchedBatch(bool containerEject)
    {
        using var fixture = new Fixture(pausedSelection: 2);
        await AssertSuperseded(fixture, async () =>
        {
            if (containerEject)
            {
                var result = await fixture.Worker.EjectContainerAsync(fixture.Device, Container, default).WaitAsync(Timeout);
                Assert.True(result.Success, result.Message);
            }
            else
            {
                var result = await fixture.Worker.EjectAllAsync(default).WaitAsync(Timeout);
                Assert.True(result.Success, result.Message);
            }
        });
    }

    [Fact]
    public async Task AdmittedNewerCycleStillSupersedesUnlaunchedBatch()
    {
        using var fixture = new Fixture(pausedSelection: 2);
        await AssertSuperseded(fixture, () => Cycle(fixture.Worker).WaitAsync(Timeout));
        Assert.Equal(2L, Generations(fixture.Worker).Discovery);
    }

    [Fact]
    public async Task ReplacementIdentityStillSupersedesUnlaunchedBatch()
    {
        using var fixture = new Fixture(pausedSelection: 2);
        await AssertSuperseded(fixture, async () =>
        {
            fixture.Backend.Volumes = [fixture.Backend.Volumes[0] with { CatalogVolumeUuid = Guid.NewGuid().ToString("N") }, fixture.Backend.Volumes[1]];
            await fixture.Worker.GetInventoryAsync(default).WaitAsync(Timeout);
        });
    }

    [Fact]
    public async Task ShutdownStillSupersedesUnlaunchedBatch()
    {
        using var fixture = new Fixture(pausedSelection: 2);
        await AssertSuperseded(fixture, async () =>
        {
            var result = await fixture.Worker.PrepareForShutdownAsync(default).WaitAsync(Timeout);
            Assert.True(result.CleanupCompleted);
            Assert.True(result.HostOwnershipReleased);
            Assert.True(result.PendingDurabilityCleared);
            Assert.Empty(result.RemainingMounts);
        });
    }

    [Fact]
    public async Task CancellationStillPreventsBatchAndRestoresMountGate()
    {
        using var fixture = new Fixture(pausedSelection: 2);
        using var cancellation = new CancellationTokenSource();
        var mount = fixture.Mount(cancellation.Token);
        try
        {
            await fixture.Policy.SelectionEntered.Task.WaitAsync(Timeout);
            cancellation.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => mount.WaitAsync(Timeout));
            fixture.AssertNotMounted();
            await AssertGateAvailable(fixture.Worker);
        }
        finally
        {
            fixture.Release();
            try { await mount.WaitAsync(Timeout); } catch (OperationCanceledException) { }
        }
    }

    private static async Task AssertSuperseded(Fixture fixture, Func<Task> competing)
    {
        var mount = fixture.Mount();
        try
        {
            await fixture.Policy.SelectionEntered.Task.WaitAsync(Timeout);
            Assert.Empty(fixture.Backend.Requests);
            await competing();
            fixture.Policy.ReleaseSelection.TrySetResult();
            var result = await mount.WaitAsync(Timeout);
            Assert.False(result.Success);
            Assert.Equal("Container mount was superseded while preparing drive-letter settings.", result.Message);
            fixture.AssertNotMounted();
            await AssertGateAvailable(fixture.Worker);
        }
        finally { fixture.Release(); await mount.WaitAsync(Timeout); }
    }

    private static async Task AssertGateAvailable(ApfsMountWorker worker)
    {
        var gate = (SemaphoreSlim)typeof(ApfsMountWorker).GetField("_mountOperationLock", Private)!.GetValue(worker)!;
        Assert.True(await gate.WaitAsync(Timeout));
        gate.Release();
    }

    private static (long Command, long Operation, long Discovery) Generations(ApfsMountWorker worker)
    {
        return (Read("_mountCommandGeneration"), Read("_mountOperationGeneration"), Read("_admittedDiscoveryGeneration"));
        long Read(string field) => (long)typeof(ApfsMountWorker).GetField(field, Private)!.GetValue(worker)!;
    }

    private static Task Cycle(ApfsMountWorker worker)
        => (Task)typeof(ApfsMountWorker).GetMethod("RunCycleAsync", Private)!.Invoke(worker, [CancellationToken.None])!;

    private sealed class Fixture : IDisposable
    {
        private readonly DTempDirectory _temp = DTempDirectory.Create("mount-supersession");
        public string Device { get; }
        public char[] Letters { get; }
        public Backend Backend { get; }
        public BlockingPolicy Policy { get; }
        public VolumeDriveLetterAssignments Store { get; }
        public ApfsMountWorker Worker { get; }

        public Fixture(int pausedSelection, bool pauseFirstDiscovery = false)
        {
            Device = Path.Combine(_temp.Path, "owned.apfs.img");
            var occupied = Environment.GetLogicalDrives().Select(drive => char.ToUpperInvariant(drive[0])).ToHashSet();
            Letters = Enumerable.Range('D', 23).Select(value => (char)value).Where(letter => !occupied.Contains(letter)).Take(3).ToArray();
            Assert.Equal(3, Letters.Length);
            Store = new(Path.Combine(_temp.Path, "letters.json"));
            Assert.True(Store.SetPreference(FirstUuid, Letters[0]));
            Assert.True(Store.SetPreference(SecondUuid, Letters[1]));
            Backend = new(Device, [Volume(201, FirstUuid, "First"), Volume(202, SecondUuid, "Second")], pauseFirstDiscovery);
            Policy = new(new FirstFreeMountPolicy(Letters.Select(letter => letter.ToString()), Store), pausedSelection);
            Worker = new(NullLogger<ApfsMountWorker>.Instance, Backend, Policy, new(), new Options());
        }

        private VolumeInfo Volume(ulong oid, Guid uuid, string name) => new(
            ApfsTopology.BuildVolumeId(Container, oid), Device, name, false,
            CatalogVolumeId: ApfsTopology.BuildVolumeId(Container, oid), CatalogVolumeUuid: uuid.ToString("N"),
            CatalogContainerUuid: Container, CatalogVolumeObjectId: oid);

        public Task<(bool Success, string Message)> Mount(CancellationToken token = default)
            => Worker.MountContainerAsync(Device, Container, Backend.Volumes.ToArray(), MountAccessMode.ReadWrite, token);

        public void AssertMounted()
        {
            Assert.Equal(1, Backend.BatchCalls);
            Assert.Equal(0, Backend.SingleCalls);
            Assert.Equal(Letters.Take(2), Backend.Requests.Select(request => request.DriveLetter));
            Assert.Equal(Backend.Volumes.Select(volume => volume.VolumeId), Backend.Requests.Select(request => request.VolumeId));
            Assert.Equal(2, Backend.Mounts.Count);
            using var state = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(_temp.Path, "letters.json")));
            Assert.Equal(Letters[0].ToString(), state.RootElement.GetProperty(FirstUuid.ToString("D")).GetString());
            Assert.Equal(Letters[1].ToString(), state.RootElement.GetProperty(SecondUuid.ToString("D")).GetString());
        }

        public void AssertNotMounted()
        {
            Assert.Equal(0, Backend.BatchCalls);
            Assert.Equal(0, Backend.SingleCalls);
            Assert.Empty(Backend.Requests);
            Assert.Empty(Backend.Mounts);
        }

        public void Release() { Backend.ReleaseDiscovery.TrySetResult(); Policy.ReleaseSelection.TrySetResult(); }
        public void Dispose() { Release(); Worker.Dispose(); _temp.Dispose(); }
    }

    private sealed class BlockingPolicy(FirstFreeMountPolicy inner, int pausedSelection) : IMountPolicy
    {
        private int _selection;
        public TaskCompletionSource SelectionEntered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource ReleaseSelection { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public bool RequiresDriveLetterStorage => inner.RequiresDriveLetterStorage;
        public void UpdateDiscovery(IReadOnlyList<VolumeInfo> volumes) => inner.UpdateDiscovery(volumes);
        public bool ShouldAutoMount(VolumeInfo volume) => inner.ShouldAutoMount(volume);
        public char SelectDriveLetter(VolumeInfo volume, IReadOnlySet<char> occupied) => inner.SelectDriveLetter(volume, occupied);
        public Func<CancellationToken, char> PrepareDriveLetterSelection(VolumeInfo volume, IReadOnlySet<char> occupied)
        {
            var select = inner.PrepareDriveLetterSelection(volume, occupied);
            return token =>
            {
                if (Interlocked.Increment(ref _selection) == pausedSelection)
                {
                    SelectionEntered.TrySetResult();
                    ReleaseSelection.Task.WaitAsync(Timeout, token).GetAwaiter().GetResult();
                }
                return select(token);
            };
        }
        public Func<CancellationToken, DriveLetterPreferenceResult> PrepareDriveLetterPreference(VolumeInfo volume, Guid uuid, char letter)
            => inner.PrepareDriveLetterPreference(volume, uuid, letter);
        public DriveLetterPreference GetDriveLetterPreference(VolumeInfo volume, char? actual) => inner.GetDriveLetterPreference(volume, actual);
        public DriveLetterPreference GetCachedDriveLetterPreference(VolumeInfo volume, char? actual) => inner.GetCachedDriveLetterPreference(volume, actual);
    }

    private sealed class Options : IOptionsMonitor<ServiceHostOptions>
    {
        public ServiceHostOptions CurrentValue { get; } = new() { AutoMountEnabled = false, EnableNativeWrite = false };
        public ServiceHostOptions Get(string? name) => CurrentValue;
        public IDisposable? OnChange(Action<ServiceHostOptions, string?> listener) => null;
    }

    // Only discovery and mount results are simulated; worker generations and settings storage are production code.
    private sealed class Backend(string device, IReadOnlyList<VolumeInfo> volumes, bool pauseFirstDiscovery) : IApfsBackend, IContainerMountBackend
    {
        public IReadOnlyList<VolumeInfo> Volumes { get; set; } = volumes;
        public TaskCompletionSource DiscoveryEntered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource ReleaseDiscovery { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public List<MountRequest> Requests { get; } = [];
        public List<MountedVolumeState> Mounts { get; } = [];
        public int Observations;
        public int BatchCalls;
        public int SingleCalls;
        public async Task<IReadOnlyList<DeviceInventory>> ProbeInventoryAsync(bool authoritative, CancellationToken token)
        {
            var captured = Volumes.ToArray();
            if (Interlocked.Increment(ref Observations) == 1 && pauseFirstDiscovery)
            {
                DiscoveryEntered.TrySetResult();
                await ReleaseDiscovery.Task.WaitAsync(Timeout, token);
            }
            return [new(new(device, "Fixture", true), captured)];
        }
        public Task<IReadOnlyList<DeviceInfo>> ProbeDevicesAsync(CancellationToken token) => throw new NotSupportedException();
        public Task<IReadOnlyList<VolumeInfo>> ProbeVolumesAsync(string deviceId, CancellationToken token) => throw new NotSupportedException();
        public Task<IReadOnlyList<MountedVolumeState>> GetMountStateAsync(CancellationToken token)
            => Task.FromResult<IReadOnlyList<MountedVolumeState>>(Mounts.ToArray());
        public Task<MountResult> MountAsync(MountRequest request, CancellationToken token)
        {
            SingleCalls++;
            throw new InvalidOperationException("Container siblings must be submitted as one batch.");
        }
        public Task<IReadOnlyList<MountResult>> MountContainerAsync(IReadOnlyList<MountRequest> requests, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            BatchCalls++;
            Requests.AddRange(requests);
            var results = requests.Select(request =>
            {
                var volume = Volumes.Single(volume => volume.VolumeId == request.VolumeId);
                var mountPoint = $"{request.DriveLetter}:\\";
                Mounts.Add(new(request.VolumeId, mountPoint, request.AccessMode, DeviceId: device,
                    CatalogVolumeId: volume.CatalogVolumeId, CatalogContainerUuid: Container));
                return new MountResult(true, mountPoint, null, request.AccessMode);
            }).ToArray();
            return Task.FromResult<IReadOnlyList<MountResult>>(results);
        }
        public Task<UnmountResult> UnmountAsync(string mountPoint, CancellationToken token)
        {
            Mounts.RemoveAll(mount => mount.MountPoint == mountPoint);
            return Task.FromResult(new UnmountResult(true, mountPoint, null, true, true, true));
        }
    }
}
