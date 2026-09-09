using ApfsAccess.Core;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace ApfsAccess.Service.Tests;

public sealed class RoleMountPolicyTests
{
    private static VolumeInfo Special(string role = "system") => new("v", "d", "Inspection", true,
        SupportsNativeWrite: true, CatalogDecision: ApfsCapabilityDecision.Readable,
        CatalogReasons: [ApfsVolumeCapabilities.SpecialRoleReason(role)], CatalogAutoMountAllowed: false);

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task FirstFreeDoesNotAutoMountProtectedCatalog(bool refresh)
    {
        var backend = new Backend([Special()]);
        using var worker = Worker(backend);
        if (refresh) await worker.RefreshAsync(true, CancellationToken.None);
        else await Cycle(worker);
        Assert.Empty(backend.Requests);
    }

    private static ApfsMountWorker Worker(Backend backend, RuntimeStatusPublisher? publisher = null) => new(
        NullLogger<ApfsMountWorker>.Instance, backend, new FirstFreeMountPolicy(["R", "S", "T"]),
        publisher ?? new RuntimeStatusPublisher(), new Options());

    [Fact]
    public async Task AdmittedStatusInventoryClearsOnDisconnectAndCannotAuthorizeStaleInspection()
    {
        var backend = new Backend([Special()]);
        var publisher = new RuntimeStatusPublisher();
        using var worker = Worker(backend, publisher);
        await Cycle(worker);
        var visible = Assert.Single(Assert.Single(publisher.Latest.ConnectedInventory!).Volumes);
        Assert.Equal("v", visible.VolumeId);
        Assert.Equal(Special().CatalogReasons, visible.CatalogReasons);
        backend.Connected = false;
        await Cycle(worker);
        Assert.Empty(publisher.Latest.ConnectedInventory!);
        Assert.False((await worker.EnsureMountedExactAsync("d", "v", MountAccessMode.ReadOnly, CancellationToken.None)).Success);
        Assert.Empty(backend.Requests);
    }

    [Theory]
    [InlineData("system")]
    [InlineData("preboot")]
    [InlineData("recovery")]
    [InlineData("vm")]
    [InlineData("update")]
    [InlineData("backup")]
    public async Task SpecialRoleRequiresExactReadOnlyRequestAndNeverUpgrades(string role)
    {
        var backend = new Backend([Special(role)]);
        using var worker = Worker(backend);
        await Cycle(worker);
        await worker.RefreshAsync(true, CancellationToken.None);
        Assert.Empty(backend.Requests);
        var fix = await worker.EnsureMountedExactAsync("d", "v", MountAccessMode.ReadWrite, CancellationToken.None);
        Assert.False(fix.Success);
        Assert.Contains("read/write mount refused", fix.Message);
        Assert.Empty(backend.Requests);
        var defaultMount = await worker.EnsureMountedExactAsync("d", "v", null, CancellationToken.None);
        Assert.False(defaultMount.Success);
        var inspect = await worker.EnsureMountedExactAsync("d", "v", MountAccessMode.ReadOnly, CancellationToken.None);
        Assert.True(inspect.Success, inspect.Message);
        Assert.Equal(MountAccessMode.ReadOnly, Assert.Single(backend.Requests).AccessMode);
        await worker.RefreshAsync(true, CancellationToken.None);
        await Cycle(worker);
        fix = await worker.EnsureMountedExactAsync("d", "v", MountAccessMode.ReadWrite, CancellationToken.None);
        Assert.False(fix.Success);
        Assert.Single(backend.Requests);
        Assert.Equal(0, backend.Unmounts);
        Assert.Equal(MountAccessMode.ReadOnly, Assert.Single(backend.Mounts).AccessMode);
    }

    public static IEnumerable<object[]> UnreadableVolumes()
    {
        yield return [Special("unknown")];
        yield return [Special("future-role")];
        yield return [Special() with { CatalogDecision = ApfsCapabilityDecision.Locked }];
        yield return [Special() with { CatalogDecision = ApfsCapabilityDecision.Unsupported }];
        yield return [Special() with { CatalogDecision = (ApfsCapabilityDecision)99 }];
        yield return [Special() with { IsEncrypted = true }];
        yield return [Special() with { SupportsExplorerMount = false }];
        yield return [Special() with { CatalogAutoMountAllowed = true }];
        yield return [Special() with { CatalogAutoMountAllowed = null }];
        yield return [Special() with { CatalogDecision = null }];
        yield return [Special() with { CatalogReasons = null }];
        yield return [Special() with { CatalogReasons = [] }];
        yield return [Special() with { CatalogReasons = ["special-role:system", "unknown-features"] }];
        yield return [Special() with { CatalogDecision = ApfsCapabilityDecision.Writable, CatalogAutoMountAllowed = true }];
    }

    [Theory]
    [MemberData(nameof(UnreadableVolumes))]
    public async Task UnreadableOrContradictoryCatalogNeverReachesBackend(VolumeInfo volume)
    {
        var backend = new Backend([volume]);
        using var worker = Worker(backend);
        await Cycle(worker);
        await worker.RefreshAsync(true, CancellationToken.None);
        foreach (var mode in new[] { MountAccessMode.ReadOnly, MountAccessMode.ReadWrite })
        {
            var result = await worker.EnsureMountedExactAsync("d", "v", mode, CancellationToken.None);
            Assert.False(result.Success);
        }
        Assert.Empty(backend.Requests);
        Assert.Equal(0, backend.Unmounts);
    }

    [Fact]
    public async Task BatchFiltersSpecialVolumesAndRetainsOrdinaryAndLegacyWrites()
    {
        var ordinary = Special() with { VolumeId = "data", CatalogDecision = ApfsCapabilityDecision.Writable,
            CatalogReasons = [], CatalogAutoMountAllowed = true };
        var legacy = new VolumeInfo("legacy", "d", "Legacy", true, SupportsNativeWrite: true);
        var backend = new Backend([Special(), ordinary, legacy]);
        using var worker = Worker(backend);
        await Cycle(worker);
        Assert.Equal(1, backend.Batches);
        Assert.Equal(new[] { "data", "legacy" }, backend.Requests.Select(r => r.VolumeId));
        Assert.All(backend.Requests, r => Assert.Equal(MountAccessMode.ReadWrite, r.AccessMode));
    }

    [Fact]
    public async Task ChangedCatalogDoesNotReopenExistingReadOnlyMountForUpgrade()
    {
        var ordinary = Special() with { CatalogDecision = ApfsCapabilityDecision.Writable,
            CatalogReasons = [], CatalogAutoMountAllowed = true };
        var backend = new Backend([ordinary]);
        using var worker = Worker(backend);
        Assert.True((await worker.EnsureMountedExactAsync("d", "v", MountAccessMode.ReadOnly, CancellationToken.None)).Success);
        backend.Volumes = [Special()];
        await worker.RefreshAsync(true, CancellationToken.None);
        Assert.Single(backend.Requests);
        Assert.Equal(0, backend.Unmounts);
    }

    [Fact]
    public async Task ExplicitInspectionStillChecksExactIdentityAndCancellation()
    {
        var backend = new Backend([Special() with { RecoveryIdentity = "current" }]);
        using var worker = Worker(backend);
        Assert.False((await worker.EnsureMountedExactAsync("other", "v", MountAccessMode.ReadOnly, CancellationToken.None)).Success);
        Assert.False((await worker.EnsureMountedExactAsync("d", "v", MountAccessMode.ReadOnly, CancellationToken.None, "stale")).Success);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            worker.EnsureMountedExactAsync("d", "v", MountAccessMode.ReadOnly, cancellation.Token));
        backend.Volumes = [Special(), Special()];
        Assert.False((await worker.EnsureMountedAsync("v", MountAccessMode.ReadOnly, CancellationToken.None)).Success);
        Assert.Empty(backend.Requests);
    }

    [Fact]
    public async Task ReadOnlyFeatureRequiresSupportedExplicitInspection()
    {
        var backend = new Backend([Special() with { CatalogDecision = ApfsCapabilityDecision.ReadOnlyFeature,
            CatalogReasons = [ApfsVolumeCapabilities.ReasonReadonlyFeatures] }]);
        using var worker = Worker(backend);
        await worker.RefreshAsync(true, CancellationToken.None);
        Assert.Empty(backend.Requests);
        Assert.True((await worker.EnsureMountedExactAsync("d", "v", MountAccessMode.ReadOnly, CancellationToken.None)).Success);
        Assert.Equal(MountAccessMode.ReadOnly, Assert.Single(backend.Requests).AccessMode);
    }

    private static Task Cycle(ApfsMountWorker worker) => (Task)typeof(ApfsMountWorker)
        .GetMethod("RunCycleAsync", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!
        .Invoke(worker, [CancellationToken.None])!;

    private sealed class Options : IOptionsMonitor<ServiceHostOptions>
    {
        public ServiceHostOptions CurrentValue { get; } = new()
        {
            AutoMountEnabled = true, EnableNativeWrite = true, WriteRolloutChannel = "Enabled",
            AllowWriteOnUnsupportedFeatures = true, ReadWriteMode = "RwWithRoFallback",
        };
        public ServiceHostOptions Get(string? name) => CurrentValue;
        public IDisposable? OnChange(Action<ServiceHostOptions, string?> listener) => null;
    }

    private sealed class Backend(IReadOnlyList<VolumeInfo> volumes) : IApfsBackend, IContainerMountBackend
    {
        public IReadOnlyList<VolumeInfo> Volumes { get; set; } = volumes;
        public List<MountRequest> Requests { get; } = [];
        public List<MountedVolumeState> Mounts { get; } = [];
        public int Batches { get; private set; }
        public int Unmounts { get; private set; }
        public bool Connected { get; set; } = true;
        public Task<IReadOnlyList<DeviceInfo>> ProbeDevicesAsync(CancellationToken ct) => Task.FromResult<IReadOnlyList<DeviceInfo>>(Connected ? [new("d", "Disk", true)] : []);
        public Task<IReadOnlyList<VolumeInfo>> ProbeVolumesAsync(string id, CancellationToken ct) => Task.FromResult(Volumes);
        public Task<IReadOnlyList<MountedVolumeState>> GetMountStateAsync(CancellationToken ct) => Task.FromResult<IReadOnlyList<MountedVolumeState>>(Mounts.ToArray());
        public Task<MountResult> MountAsync(MountRequest request, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            Requests.Add(request);
            var point = $"{request.DriveLetter}:\\";
            Mounts.Add(new(request.VolumeId, point, request.AccessMode, DeviceId: "d"));
            return Task.FromResult(new MountResult(true, point, null, request.AccessMode));
        }
        public async Task<IReadOnlyList<MountResult>> MountContainerAsync(IReadOnlyList<MountRequest> requests, CancellationToken ct)
        {
            Batches++;
            var results = new List<MountResult>();
            foreach (var request in requests) results.Add(await MountAsync(request, ct));
            return results;
        }
        public Task<UnmountResult> UnmountAsync(string point, CancellationToken ct)
        {
            Unmounts++;
            Mounts.RemoveAll(m => m.MountPoint == point);
            return Task.FromResult(new UnmountResult(true, point, null));
        }
    }
}
