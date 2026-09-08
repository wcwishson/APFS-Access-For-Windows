using System.Reflection;
using System.Text.Json;
using ApfsAccess.Core;
using ApfsAccess.Ipc;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace ApfsAccess.Service.Tests;

public sealed class DriveLetterConcurrencyRepairTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "preference-repair-" + Guid.NewGuid().ToString("N"));
    private static readonly Guid A = Guid.Parse("11111111-2222-3333-4444-555555555555");
    private static readonly Guid B = Guid.Parse("66666666-7777-8888-9999-aaaaaaaaaaaa");
    private static VolumeInfo Volume => new("volume", "device", "Name", false,
        CatalogVolumeId: ApfsTopology.BuildVolumeId(new string('a', 32), 201), CatalogVolumeUuid: A.ToString("N"));
    private string State => Path.Combine(_root, "letters.json");
    public DriveLetterConcurrencyRepairTests() => Directory.CreateDirectory(_root);
    public void Dispose() => Directory.Delete(_root, true);
    private FirstFreeMountPolicy Policy() => new(["R", "S", "T"], new VolumeDriveLetterAssignments(State));
    private static DriveLetterPreferenceRequestPayload Request => new(Volume.DeviceId, Volume.VolumeId, A.ToString("D"), "T");
    private static ApfsMountWorker Worker(IApfsBackend backend, IMountPolicy policy, RuntimeStatusPublisher? publisher = null)
        => new(NullLogger<ApfsMountWorker>.Instance, backend, policy, publisher ?? new(), new Options());
    private static Task Cycle(ApfsMountWorker worker) => (Task)typeof(ApfsMountWorker)
        .GetMethod("RunCycleAsync", BindingFlags.Instance | BindingFlags.NonPublic)!.Invoke(worker, [CancellationToken.None])!;

    [Theory]
    [InlineData("changed", true)]
    [InlineData("duplicate", true)]
    [InlineData("empty", true)]
    [InlineData("changed", false)]
    [InlineData("duplicate", false)]
    [InlineData("empty", false)]
    public async Task OlderBackgroundCannotReinstallIdentityAfterNewerValidationOrInventory(string scenario, bool preference)
    {
        var backend = new Backend { PauseFirst = true };
        var policy = Policy();
        var store = new VolumeDriveLetterAssignments(State);
        Assert.True(store.SetPreference(A, 'T'));
        var before = File.ReadAllBytes(State);
        using var worker = Worker(backend, policy);
        var old = Cycle(worker);
        try
        {
            await backend.FirstCaptured.Task.WaitAsync(TimeSpan.FromSeconds(2));
            backend.Volumes = scenario switch
            {
                "changed" => [Volume with { CatalogVolumeUuid = B.ToString("N") }],
                "duplicate" => [Volume, Volume with { DeviceId = "other", VolumeId = "other", IsEncrypted = true,
                    CatalogVolumeId = ApfsTopology.BuildVolumeId(new string('b', 32), 202) }],
                _ => []
            };
            if (preference)
                Assert.False((await worker.SetDriveLetterPreferenceAsync(Request, CancellationToken.None)).Success);
            else
                await worker.GetInventoryAsync(CancellationToken.None);
            Assert.False(policy.GetDriveLetterPreference(Volume, null).CanEdit);
            backend.ReleaseFirst.TrySetResult();
            await old.WaitAsync(TimeSpan.FromSeconds(2));
            Assert.False(policy.GetDriveLetterPreference(Volume, null).CanEdit);
            Assert.Equal('R', policy.SelectDriveLetter(Volume, new HashSet<char>()));
            Assert.Equal(before, File.ReadAllBytes(State));
            Assert.Equal(0, backend.Mutations);
            Assert.Equal(2, backend.Observations);
        }
        finally { backend.ReleaseFirst.TrySetResult(); await old; }
    }

    [Fact]
    public async Task OlderPreferenceValidationCannotOverwriteNewerInventory()
    {
        var backend = new Backend { PauseFirst = true };
        var policy = Policy();
        using var worker = Worker(backend, policy);
        var old = worker.SetDriveLetterPreferenceAsync(Request, CancellationToken.None);
        try
        {
            await backend.FirstCaptured.Task.WaitAsync(TimeSpan.FromSeconds(2));
            backend.Volumes = [Volume with { CatalogVolumeUuid = B.ToString("N") }];
            await worker.GetInventoryAsync(CancellationToken.None);
            backend.ReleaseFirst.TrySetResult();
            var result = await old.WaitAsync(TimeSpan.FromSeconds(2));
            Assert.False(result.Success);
            Assert.Contains("superseded", result.Message);
            Assert.False(policy.GetDriveLetterPreference(Volume, null).CanEdit);
            Assert.False(File.Exists(State));
        }
        finally { backend.ReleaseFirst.TrySetResult(); await old; }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task PendingStorageNeverHoldsMountLockAndCancellationRespectsRealCommit(bool afterCommit)
    {
        var backend = new Backend();
        var policy = new BlockingPolicy(Policy(), afterCommit);
        using var worker = Worker(backend, policy);
        using var cancel = new CancellationTokenSource();
        var edit = worker.SetDriveLetterPreferenceAsync(Request, cancel.Token);
        try
        {
            await policy.Entered.Task.WaitAsync(TimeSpan.FromSeconds(2));
            if (afterCommit) Assert.Equal("T", JsonDocument.Parse(File.ReadAllBytes(State)).RootElement.GetProperty(A.ToString("D")).GetString());
            cancel.Cancel();
            await Assert.ThrowsAsync<TimeoutException>(() => edit.WaitAsync(TimeSpan.FromMilliseconds(30)));
            Assert.False(edit.IsCompleted); // The caller timeout did not cancel this synchronous storage boundary.
            Assert.True((await worker.EjectAllAsync(CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(2))).Success);
            Assert.NotEmpty(await worker.GetInventoryAsync(CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(2)));
            policy.Release.TrySetResult();
            if (afterCommit)
            {
                var result = await edit.WaitAsync(TimeSpan.FromSeconds(2));
                Assert.True(result.Success, result.Message);
                Assert.Equal("ok", result.Code);
                Assert.Contains("saved", result.Message);
            }
            else
            {
                await Assert.ThrowsAnyAsync<OperationCanceledException>(() => edit.WaitAsync(TimeSpan.FromSeconds(2)));
                Assert.False(File.Exists(State));
            }
            Assert.Equal(0, backend.Mutations);
            Assert.True((await worker.SetDriveLetterPreferenceAsync(Request, CancellationToken.None)).Success);
        }
        finally
        {
            policy.Release.TrySetResult();
            try { await edit; } catch (OperationCanceledException) { }
        }
    }

    [Fact]
    public async Task InventoryAndPreferenceRemainResponsiveWhileMountLockIsOwned()
    {
        var backend = new Backend();
        using var worker = Worker(backend, Policy());
        var mountLock = (SemaphoreSlim)typeof(ApfsMountWorker).GetField("_mountOperationLock", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(worker)!;
        await mountLock.WaitAsync();
        try
        {
            Assert.NotEmpty(await worker.GetInventoryAsync(CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(2)));
            Assert.True((await worker.SetDriveLetterPreferenceAsync(Request, CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(2))).Success);
            Assert.Equal(0, backend.Mutations);
        }
        finally { mountLock.Release(); }
    }

    [Fact]
    public async Task DisplaySubscriberFailureAfterStorageCommitStillReturnsSavedSuccess()
    {
        var backend = new Backend();
        var publisher = new RuntimeStatusPublisher();
        publisher.Publish(publisher.Latest with { MountedVolumes = [new(Volume.VolumeId, "R:\\", "Name", Volume.DeviceId, "Disk", MountAccessMode.ReadOnly)] });
        using var worker = Worker(backend, Policy(), publisher);
        publisher.StatusChanged += _ => throw new InvalidOperationException("controlled display failure");
        var result = await worker.SetDriveLetterPreferenceAsync(Request, CancellationToken.None);
        Assert.True(result.Success);
        using var json = JsonDocument.Parse(File.ReadAllBytes(State));
        Assert.Equal("T", json.RootElement.GetProperty(A.ToString("D")).GetString());
    }

    private sealed class BlockingPolicy(FirstFreeMountPolicy inner, bool afterCommit) : IMountPolicy
    {
        public TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public void UpdateDiscovery(IReadOnlyList<VolumeInfo> volumes) => inner.UpdateDiscovery(volumes);
        public bool ShouldAutoMount(VolumeInfo volume) => false;
        public char SelectDriveLetter(VolumeInfo volume, IReadOnlySet<char> letters) => inner.SelectDriveLetter(volume, letters);
        public DriveLetterPreference? GetDriveLetterPreference(VolumeInfo volume, char? letter) => inner.GetDriveLetterPreference(volume, letter);
        public Func<CancellationToken, DriveLetterPreferenceResult> PrepareDriveLetterPreference(VolumeInfo volume, Guid uuid, char letter)
        {
            var realCommit = inner.PrepareDriveLetterPreference(volume, uuid, letter);
            return token =>
            {
                var result = afterCommit ? realCommit(token) : null;
                Entered.TrySetResult();
                if (!Release.Task.Wait(TimeSpan.FromSeconds(10))) throw new TimeoutException("Test storage gate was not released.");
                return result ?? realCommit(token);
            };
        }
    }
    private sealed class Options : IOptionsMonitor<ServiceHostOptions>
    {
        public ServiceHostOptions CurrentValue { get; } = new() { AutoMountEnabled = false, EnableNativeWrite = false };
        public ServiceHostOptions Get(string? name) => CurrentValue;
        public IDisposable? OnChange(Action<ServiceHostOptions, string?> listener) => null;
    }
    private sealed class Backend : IApfsBackend
    {
        public VolumeInfo[] Volumes = [Volume];
        public bool PauseFirst;
        public int Observations;
        public int Mutations;
        public TaskCompletionSource FirstCaptured { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource ReleaseFirst { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public async Task<IReadOnlyList<DeviceInventory>> ProbeInventoryAsync(bool authoritative, CancellationToken token)
        {
            Assert.True(authoritative);
            var snapshot = Volumes.ToArray();
            if (Interlocked.Increment(ref Observations) == 1 && PauseFirst)
            {
                FirstCaptured.TrySetResult();
                await ReleaseFirst.Task.WaitAsync(token);
            }
            return snapshot.GroupBy(v => v.DeviceId).Select(g => new DeviceInventory(new(g.Key, "Disk", true), g.ToArray())).ToArray();
        }
        public Task<IReadOnlyList<DeviceInfo>> ProbeDevicesAsync(CancellationToken token) => throw new InvalidOperationException("Use the catalog observation contract.");
        public Task<IReadOnlyList<VolumeInfo>> ProbeVolumesAsync(string device, CancellationToken token) => throw new InvalidOperationException("Use the catalog observation contract.");
        public Task<IReadOnlyList<MountedVolumeState>> GetMountStateAsync(CancellationToken token) => Task.FromResult<IReadOnlyList<MountedVolumeState>>([]);
        public Task<MountResult> MountAsync(MountRequest request, CancellationToken token) { Mutations++; throw new InvalidOperationException("No mounts allowed."); }
        public Task<UnmountResult> UnmountAsync(string path, CancellationToken token) { Mutations++; throw new InvalidOperationException("No unmounts allowed."); }
    }
}
