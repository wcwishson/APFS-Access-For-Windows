using ApfsAccess.Core;
using ApfsAccess.Ipc;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace ApfsAccess.Service.Tests;

public sealed class DriveLetterPreferenceTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "preference-service-" + Guid.NewGuid().ToString("N"));
    private readonly Guid _uuid = Guid.Parse("fbda2042-9e07-420e-aea1-eafefed58643");
    private string StatePath => Path.Combine(_root, "letters.json");
    private VolumeInfo Volume => new("exact-volume", "exact-device", "Same name", false,
        CatalogVolumeId: ApfsTopology.BuildVolumeId(new string('a', 32), 42), CatalogVolumeUuid: _uuid.ToString("N"));
    public DriveLetterPreferenceTests() => Directory.CreateDirectory(_root);
    public void Dispose() => Directory.Delete(_root, true);
    private FirstFreeMountPolicy Policy() => new(["R", "S", "T"], new VolumeDriveLetterAssignments(StatePath));
    private ApfsMountWorker Worker(FakeBackend backend, FirstFreeMountPolicy policy, RuntimeStatusPublisher? publisher = null)
        => new(NullLogger<ApfsMountWorker>.Instance, backend, policy, publisher ?? new(), new Options());
    private DriveLetterPreferenceRequestPayload Request(string letter = "T") => new(Volume.DeviceId, Volume.VolumeId, _uuid.ToString("D"), letter);

    private async Task<char> SelectForTest(ApfsMountWorker worker)
    {
        const System.Reflection.BindingFlags flags = System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic;
        var gate = (SemaphoreSlim)typeof(ApfsMountWorker).GetField("_mountOperationLock", flags)!.GetValue(worker)!;
        await gate.WaitAsync();
        try
        {
            return await (Task<char>)typeof(ApfsMountWorker).GetMethod("SelectDriveLetterForVolumeAsync", flags)!
                .Invoke(worker, [Volume, new HashSet<char>(), 0L, CancellationToken.None])!;
        }
        finally { gate.Release(); }
    }
    [Fact]
    public async Task RuntimeRequestPersistsAndFreshPolicySelectsNextMountWithoutTouchingCurrentWork()
    {
        var backend = new FakeBackend([Volume]);
        var policy = Policy(); policy.UpdateDiscovery([Volume]);
        var publisher = new RuntimeStatusPublisher();
        var mounted = new MountedVolumeDisplay(Volume.VolumeId, "R:\\", Volume.VolumeName, Volume.DeviceId, "Disk", MountAccessMode.ReadOnly,
            CatalogVolumeId: Volume.CatalogVolumeId, DirtyTransactionCount: 7, PendingDurability: true);
        publisher.Publish(publisher.Latest with { MountedVolumes = [mounted] });
        using var worker = Worker(backend, policy, publisher);

        Assert.Equal('R', await SelectForTest(worker));
        var ack = await worker.SetDriveLetterPreferenceAsync(Request("t"), CancellationToken.None);
        Assert.True(ack.Success);
        Assert.Contains("next clean mount", ack.Message);
        var display = Assert.Single(ack.Status!.MountedVolumes!);
        Assert.Equal("T", display.DriveLetterPreference!.PreferredLetter);
        Assert.Equal("R", display.DriveLetterPreference.ActualLetter);
        Assert.Equal("next-mount", display.DriveLetterPreference.State);
        Assert.Equal(7, display.DirtyTransactionCount);
        Assert.True(display.PendingDurability);
        Assert.Equal(mounted.MountPoint, display.MountPoint);
        Assert.Equal(0, backend.MutationCalls);
        var fresh = Policy(); fresh.UpdateDiscovery([Volume]);
        Assert.Equal('T', fresh.SelectDriveLetter(Volume, new HashSet<char>()));
        Assert.Equal("preferred", fresh.GetDriveLetterPreference(Volume, 'T').State);
    }

    [Fact]
    public async Task OccupiedPreferenceIsTemporaryAndReclaimedWithoutOverwritingStorage()
    {
        var policy = Policy();
        using var worker = Worker(new([Volume]), policy);
        Assert.True((await worker.SetDriveLetterPreferenceAsync(Request(), CancellationToken.None)).Success);
        var before = File.ReadAllBytes(StatePath);
        Assert.Equal('R', policy.SelectDriveLetter(Volume, new HashSet<char> { 't' }));
        var display = policy.GetDriveLetterPreference(Volume, 'R');
        Assert.Equal("preference-occupied", display.State);
        Assert.Equal("T", display.PreferredLetter); Assert.Equal("R", display.ActualLetter);
        Assert.Contains("occupied", display.Text);
        Assert.Equal(before, File.ReadAllBytes(StatePath));
        Assert.Equal('T', policy.SelectDriveLetter(Volume, new HashSet<char>()));
    }

    [Theory]
    [InlineData("missing")]
    [InlineData("changed-uuid")]
    [InlineData("duplicate-uuid")]
    [InlineData("duplicate-catalog")]
    [InlineData("duplicate-runtime-id")]
    [InlineData("invalid-catalog")]
    [InlineData("missing-uuid")]
    public async Task RefusesStaleOrAmbiguousIdentityWithoutStorage(string scenario)
    {
        var other = Volume with { DeviceId = "other-device", VolumeId = "other-volume", IsEncrypted = true };
        VolumeInfo[] volumes = scenario switch {
            "missing" => [],
            "changed-uuid" => [Volume with { CatalogVolumeUuid = Guid.NewGuid().ToString("N") }],
            "duplicate-uuid" => [Volume, other with { CatalogVolumeId = ApfsTopology.BuildVolumeId(new string('b', 32), 43) }],
            "duplicate-catalog" => [Volume, other with { CatalogVolumeUuid = Guid.NewGuid().ToString("N") }],
            "duplicate-runtime-id" => [Volume, Volume with { CatalogVolumeId = ApfsTopology.BuildVolumeId(new string('b', 32), 43), CatalogVolumeUuid = Guid.NewGuid().ToString("N") }],
            "invalid-catalog" => [Volume with { CatalogVolumeId = "Same name" }],
            _ => [Volume with { CatalogVolumeUuid = null }]
        };
        var backend = new FakeBackend(volumes);
        using var worker = Worker(backend, Policy());
        var ack = await worker.SetDriveLetterPreferenceAsync(Request(), CancellationToken.None);
        Assert.False(ack.Success);
        Assert.Contains(ack.Code, new[] { "missing-volume", "ambiguous-target" });
        Assert.False(File.Exists(StatePath)); Assert.Equal(0, backend.MutationCalls);
    }

    [Theory]
    [InlineData("")]
    [InlineData("TT")]
    [InlineData("T:")]
    [InlineData("1")]
    [InlineData("A")]
    public async Task InvalidLetterIsRefused(string letter)
    {
        using var worker = Worker(new([Volume]), Policy());
        var ack = await worker.SetDriveLetterPreferenceAsync(Request(letter), CancellationToken.None);
        Assert.False(ack.Success); Assert.Equal("invalid-arguments", ack.Code);
        Assert.False(File.Exists(StatePath));
    }

    [Theory]
    [InlineData("corrupt")]
    [InlineData("locked")]
    public async Task StorageFailureIsReportedAndExistingBytesSurvive(string scenario)
    {
        File.WriteAllText(StatePath, scenario == "corrupt" ? "bad json" : "{}");
        if (scenario == "locked") File.WriteAllText(StatePath + ".lock", "busy");
        var before = File.ReadAllBytes(StatePath);
        var policy = Policy(); using var worker = Worker(new([Volume]), policy);
        var ack = await worker.SetDriveLetterPreferenceAsync(Request(), CancellationToken.None);
        Assert.False(ack.Success); Assert.Equal("preference-storage-failed", ack.Code);
        Assert.Equal(before, File.ReadAllBytes(StatePath));
        Assert.Equal("storage-unavailable", policy.GetDriveLetterPreference(Volume, 'R').State);
    }

    [Fact]
    public async Task InventoryExposesUuidAndPreferenceAndClearsDisconnectedIdentity()
    {
        var backend = new FakeBackend([Volume]); var policy = Policy();
        using var worker = Worker(backend, policy);
        Assert.True((await worker.SetDriveLetterPreferenceAsync(Request(), CancellationToken.None)).Success);
        var inventory = await worker.GetInventoryAsync(CancellationToken.None);
        var preference = Assert.Single(Assert.Single(inventory).Volumes).DriveLetterPreference!;
        Assert.Equal(_uuid.ToString("D"), preference.VolumeUuid); Assert.Equal("T", preference.PreferredLetter);
        backend.Volumes = [];
        Assert.Empty(await worker.GetInventoryAsync(CancellationToken.None));
        Assert.False(policy.GetDriveLetterPreference(Volume, null).CanEdit);
        Assert.False((await worker.SetDriveLetterPreferenceAsync(Request("S"), CancellationToken.None)).Success);
    }

    [Fact]
    public async Task ReplacedUuidCannotInheritMountedChooserIdentity()
    {
        var backend = new FakeBackend([Volume]); var policy = Policy(); policy.UpdateDiscovery([Volume]);
        using var worker = Worker(backend, policy);

        await SelectForTest(worker);
        backend.Volumes = [Volume with { CatalogVolumeUuid = Guid.NewGuid().ToString("N") }];
        await worker.GetInventoryAsync(CancellationToken.None);
        var displayMethod = typeof(ApfsMountWorker).GetMethod("PreferenceForDisplay", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!;
        var display = Assert.IsType<DriveLetterPreference>(displayMethod.Invoke(worker, [Volume.DeviceId, Volume.VolumeId, Volume.CatalogVolumeId, "R:\\"]));
        Assert.False(display.CanEdit); Assert.Null(display.VolumeUuid);
        Assert.Equal("identity-unavailable", display.State);
        Assert.False((await worker.SetDriveLetterPreferenceAsync(Request(), CancellationToken.None)).Success);
    }

    [Fact]
    public async Task SavingSamePreferenceRetainsCollisionReason()
    {
        var policy = Policy(); using var worker = Worker(new([Volume]), policy);
        await worker.SetDriveLetterPreferenceAsync(Request(), CancellationToken.None);
        policy.SelectDriveLetter(Volume, new HashSet<char> { 'T' });
        await worker.SetDriveLetterPreferenceAsync(Request(), CancellationToken.None);
        Assert.Equal("preference-occupied", policy.GetDriveLetterPreference(Volume, 'R').State);
    }

    private sealed class Options : IOptionsMonitor<ServiceHostOptions>
    {
        public ServiceHostOptions CurrentValue { get; } = new();
        public ServiceHostOptions Get(string? name) => CurrentValue;
        public IDisposable? OnChange(Action<ServiceHostOptions, string?> listener) => null;
    }
    private sealed class FakeBackend(VolumeInfo[] volumes) : IApfsBackend
    {
        public VolumeInfo[] Volumes = volumes;
        public int MutationCalls;
        public Task<IReadOnlyList<DeviceInfo>> ProbeDevicesAsync(CancellationToken token)
            => Task.FromResult<IReadOnlyList<DeviceInfo>>(Volumes.Select(v => v.DeviceId).Distinct().Select(id => new DeviceInfo(id, "Disk", true)).ToArray());
        public Task<IReadOnlyList<VolumeInfo>> ProbeVolumesAsync(string id, CancellationToken token)
            => Task.FromResult<IReadOnlyList<VolumeInfo>>(Volumes.Where(v => v.DeviceId == id).ToArray());
        public Task<IReadOnlyList<MountedVolumeState>> GetMountStateAsync(CancellationToken token)
            => Task.FromResult<IReadOnlyList<MountedVolumeState>>([]);
        public Task<MountResult> MountAsync(MountRequest request, CancellationToken token) { MutationCalls++; throw new InvalidOperationException("No mounts permitted"); }
        public Task<UnmountResult> UnmountAsync(string point, CancellationToken token) { MutationCalls++; throw new InvalidOperationException("No unmounts permitted"); }
    }
}
