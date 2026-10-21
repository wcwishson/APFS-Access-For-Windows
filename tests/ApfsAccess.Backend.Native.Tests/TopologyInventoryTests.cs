using System.Text.Json.Nodes;
using ApfsAccess.Core;
using ApfsAccess.Ipc;

namespace ApfsAccess.Backend.Native.Tests;

public sealed class TopologyInventoryTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "topology-native-" + Guid.NewGuid().ToString("N"));
    public TopologyInventoryTests() => Directory.CreateDirectory(_root);
    public void Dispose() => Directory.Delete(_root, true);

    private string Image(string name)
    {
        var path = Path.Combine(_root, name + ".img");
        SyntheticApfsTestImage.Create(path, 8);
        return path;
    }

    private NativeApfsBackend Backend(Runner runner, params string[] images)
    {
        var observer = Path.Combine(_root, "observer.exe");
        File.WriteAllBytes(observer, [0x4d, 0x5a]); // Runner seam only; never executed.
        return new(new ServiceHostOptions { NativeAutoDiscoverPhysicalDrives = false, NativeDeviceCandidates = images }, null, runner, observer);
    }

    private static string Evidence(string image, ulong oid = 201)
    {
        var json = JsonNode.Parse(ObserverEvidenceJson.BuildSingleContainer(new string('a', 32),
            [new("Same name", oid)], NativeApfsObserver.BuildDeviceSlug(image), devicePath: image))!;
        json["source"]!["path"] = image;
        json["topology"]!["disks"]![0]!["deviceIdentifier"] = image;
        return json.ToJsonString();
    }

    [Fact]
    public async Task CachedInventoryKeepsItsOwnSnapshotAndGenerationWithoutStatusObserverReads()
    {
        var image = Image("one");
        var runner = new Runner(path => Evidence(path));
        using var backend = Backend(runner, image);
        var first = Assert.Single(await backend.ProbeInventoryAsync(true, default));
        var topology = Assert.IsType<ApfsDiscoveryTopology>(first.Topology);
        Assert.Equal(image, topology.DeviceId);
        Assert.Equal(topology.Snapshot.Volumes[0].Id, first.Volumes[0].CatalogVolumeId);
        Assert.Equal(topology.DiskIds[0], topology.Snapshot.Stores[0].DiskId);
        var cached = Assert.Single(await backend.ProbeInventoryAsync(false, default));
        Assert.Same(topology, cached.Topology);
        await backend.GetMountStateAsync(default);
        await backend.GetMountStateAsync(default);
        Assert.Equal(1, runner.Calls);
        runner.Json = path => Evidence(path, 202);
        var fresh = Assert.Single(await backend.ProbeInventoryAsync(true, default));
        Assert.True(fresh.Topology!.Generation > topology.Generation);
        Assert.NotEqual(first.Volumes[0].CatalogVolumeId, fresh.Volumes[0].CatalogVolumeId);
        Assert.Equal(first.Volumes[0].CatalogVolumeId, topology.Snapshot.Volumes[0].Id);
        Assert.Equal(2, runner.Calls);
        var payload = new StatusChangedPayload(RuntimeState.Idle, [], null, DateTime.UtcNow, [], false, [],
            ConnectedInventory: [fresh], InventoryGeneration: 17);
        var wire = PipeMessageCodec.Serialize(PipeMessageCodec.Create(ApfsMessageTypes.StatusChanged, payload));
        Assert.True(PipeMessageCodec.TryDeserialize(wire, out var message));
        Assert.True(PipeMessageCodec.TryGetPayload<StatusChangedPayload>(message!, out var decoded));
        Assert.Equal(fresh.Topology.Generation, decoded!.ConnectedInventory![0].Topology!.Generation);
        Assert.Equal(fresh.Topology.Snapshot.Stores[0].DiskId, decoded.ConnectedInventory[0].Topology!.Snapshot.Stores[0].DiskId);
    }

    [Fact]
    public async Task FailureAndDisconnectCannotRetainSuccessfulTopology()
    {
        var image = Image("disconnect");
        var runner = new Runner(path => Evidence(path));
        using var backend = Backend(runner, image);
        Assert.NotNull(Assert.Single(await backend.ProbeInventoryAsync(true, default)).Topology);
        runner.Json = _ => "invalid evidence";
        var fallback = Assert.Single(await backend.ProbeInventoryAsync(true, default));
        Assert.Null(fallback.Topology);
        Assert.Null(fallback.Volumes[0].CatalogVolumeId);
        File.Delete(image);
        Assert.Empty(await backend.ProbeInventoryAsync(true, default));
        Assert.Empty(await backend.ProbeInventoryAsync(false, default));
    }

    [Fact]
    public async Task TwoDevicesNeverExchangeSnapshotsAndUnboundSourceCannotExportTopology()
    {
        var a = Image("a"); var b = Image("b");
        var runner = new Runner(path => Evidence(path, path == a ? 201UL : 202UL));
        using var backend = Backend(runner, a, b);
        var devices = await backend.ProbeInventoryAsync(true, default);
        Assert.Equal(2, devices.Count);
        Assert.All(devices, d =>
        {
            Assert.Equal(d.Device.DeviceId, d.Topology!.DeviceId);
            Assert.Equal(d.Device.DeviceId, d.Topology.Snapshot.Disks[0].DeviceIdentifier);
            Assert.Equal(d.Volumes[0].CatalogVolumeId, d.Topology.Snapshot.Volumes[0].Id);
        });
        runner.Json = _ => Evidence(a);
        devices = await backend.ProbeInventoryAsync(true, default);
        Assert.NotNull(devices.Single(d => d.Device.DeviceId == a).Topology);
        Assert.DoesNotContain(devices, d => d.Device.DeviceId == b);
    }

    [Theory]
    [InlineData("path")]
    [InlineData("identifier")]
    [InlineData("disk-id")]
    public async Task FailedSourceBindingCannotExportActionableRowsOrRetainCachedIdentity(string mismatch)
    {
        var image = Image("binding");
        var runner = new Runner(path => Evidence(path));
        using var backend = Backend(runner, image);
        Assert.NotEmpty(await backend.ProbeInventoryAsync(true, default));
        runner.Json = path => {
            var json = JsonNode.Parse(Evidence(path))!;
            if (mismatch == "path") json["source"]!["path"] = "unrelated.img";
            else if (mismatch == "identifier") json["topology"]!["disks"]![0]!["deviceIdentifier"] = "unrelated.img";
            else json["topology"]!["disks"]![0]!["id"] = "apfs-disk:unrelated";
            return json.ToJsonString();
        };
        Assert.Empty(await backend.ProbeInventoryAsync(true, default));
        Assert.Empty(await backend.ProbeInventoryAsync(false, default));
        Assert.Empty(await backend.ProbeVolumesAsync(image, default));
    }

    [Fact]
    public async Task ConcurrentProbesSerializeSnapshotAndRowsAsOneObservation()
    {
        var image = Image("ordered");
        using var entered = new ManualResetEventSlim(); using var release = new ManualResetEventSlim();
        var runner = new Runner(path => { entered.Set(); Assert.True(release.Wait(TimeSpan.FromSeconds(10))); return Evidence(path); });
        using var backend = Backend(runner, image);
        var first = backend.ProbeInventoryAsync(true, default);
        Assert.True(entered.Wait(TimeSpan.FromSeconds(5)));
        var second = backend.ProbeInventoryAsync(true, default);
        try { Assert.Equal(1, runner.Calls); Assert.False(second.IsCompleted); }
        finally { release.Set(); }
        var results = await Task.WhenAll(first, second).WaitAsync(TimeSpan.FromSeconds(10));
        Assert.True(results[1][0].Topology!.Generation > results[0][0].Topology!.Generation);
        Assert.Equal(2, runner.Calls);
    }

    private sealed class Runner(Func<string, string> json) : IObserverRunner
    {
        public Func<string, string> Json = json;
        public int Calls;
        public ObserverRunResult Run(string observerPath, IReadOnlyList<string> arguments)
        {
            Interlocked.Increment(ref Calls);
            return new(0, Json(arguments[1]), "");
        }
    }
}
