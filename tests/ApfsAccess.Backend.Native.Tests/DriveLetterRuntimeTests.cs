using System.Reflection;
using System.Text.Json;
using System.Text.Json.Nodes;
using ApfsAccess.Core;
using ApfsAccess.Service;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace ApfsAccess.Backend.Native.Tests;

public sealed class DriveLetterRuntimeTests
{
    private const string Container = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    private const string FirstUuid = "11111111-2222-3333-4444-555555555555";
    private const string SecondUuid = "66666666-7777-8888-9999-aaaaaaaaaaaa";
    private static string Id(ulong oid) => ApfsTopology.BuildVolumeId(Container, oid);

    [Fact]
    public async Task ObserverDiscoveryThroughServicePersistsReclaimsAndPreservesOccupiedPreference()
    {
        using var temp = DTempDirectory.Create("drive-letter-runtime");
        var image = Path.Combine(temp.Path, "fixture.apfs.img");
        SyntheticApfsTestImage.Create(image, sizeMiB: 4);
        var state = Path.Combine(temp.Path, "letters.json");
        var pool = FreeLetters();

        using (var native = Native(Evidence(reverse: false, devicePath: image), temp))
        {
            var backend = new RecordingBackend(native, image);
            using var worker = Worker(backend, Policy(state, pool));
            await Cycle(worker);
            Assert.Equal(1, backend.BatchCalls);
            Assert.Equal(new[] { pool[0], pool[1] }, backend.Requests.Select(r => r.DriveLetter));
            Assert.Equal(new[] { FirstUuid, SecondUuid }.Select(u => Guid.Parse(u).ToString("N")),
                backend.LastDiscovery.Select(v => v.CatalogVolumeUuid));
            Assert.All(backend.LastDiscovery, v => Assert.Equal("Same name", v.VolumeName));
            Assert.Equal(new[] { Id(201), Id(202) }, backend.LastDiscovery.Select(v => v.CatalogVolumeId));
        }

        var original = File.ReadAllBytes(state);
        using (var json = JsonDocument.Parse(original))
        {
            Assert.Equal(pool[0].ToString(), json.RootElement.GetProperty(FirstUuid).GetString());
            Assert.Equal(pool[1].ToString(), json.RootElement.GetProperty(SecondUuid).GetString());
        }

        // New backend, worker and policy: the observer now enumerates identical labels in reverse order.
        using (var native = Native(Evidence(reverse: true, devicePath: image), temp))
        {
            var backend = new RecordingBackend(native, image);
            using var worker = Worker(backend, Policy(state, pool));
            await Cycle(worker);
            Assert.Equal(new[] { Id(202), Id(201) }, backend.Requests.Select(r => r.VolumeId));
            Assert.Equal(new[] { pool[1], pool[0] }, backend.Requests.Select(r => r.DriveLetter));
        }
        Assert.Equal(original, File.ReadAllBytes(state));

        // Explicit mounting also feeds discovery before selection, including an occupied preference.
        using (var native = Native(Evidence(reverse: true, devicePath: image), temp))
        {
            var backend = new RecordingBackend(native, image);
            backend.Mounts.Add(new MountedVolumeState("occupied", $"{pool[1]}:\\", MountAccessMode.ReadOnly));
            using var worker = Worker(backend, Policy(state, pool), autoMount: false);
            var result = await worker.EnsureMountedExactAsync(image, Id(202), MountAccessMode.ReadOnly, CancellationToken.None);
            Assert.True(result.Success, result.Message);
            Assert.Equal(pool[0], Assert.Single(backend.Requests).DriveLetter);
        }
        Assert.Equal(original, File.ReadAllBytes(state));

        using (var native = Native(Evidence(reverse: true, devicePath: image), temp))
        {
            var backend = new RecordingBackend(native, image);
            using var worker = Worker(backend, Policy(state, pool), autoMount: false);
            var result = await worker.EnsureMountedExactAsync(image, Id(202), MountAccessMode.ReadOnly, CancellationToken.None);
            Assert.True(result.Success, result.Message);
            Assert.Equal(pool[1], Assert.Single(backend.Requests).DriveLetter);
        }
        Assert.Equal(original, File.ReadAllBytes(state));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task ServiceUsesCompleteCrossDeviceSnapshotAndClearsDisconnectedAssociations(bool duplicateId)
    {
        using var temp = DTempDirectory.Create("drive-letter-snapshot");
        var state = Path.Combine(temp.Path, "letters.json");
        var pool = FreeLetters();
        var store = new VolumeDriveLetterAssignments(state);
        Assert.True(store.SetPreference(Guid.Parse(FirstUuid), pool[2]));
        var policy = new FirstFreeMountPolicy(pool.Select(c => c.ToString()), store);
        var first = new VolumeInfo(Id(201), "device-one", "Same name", false,
            CatalogVolumeId: Id(201), CatalogVolumeUuid: FirstUuid);
        var second = first with
        {
            DeviceId = "device-two",
            VolumeId = duplicateId ? Id(201) : Id(202),
            CatalogVolumeId = duplicateId ? Id(201) : Id(202),
            CatalogVolumeUuid = duplicateId ? SecondUuid : FirstUuid,
            IsEncrypted = true,
        };
        var backend = new RecordingBackend(null, "unused") { Snapshot = [first, second] };
        using var worker = Worker(backend, policy, autoMount: false);
        await Cycle(worker);
        Assert.Equal(pool[0], policy.SelectDriveLetter(first, new HashSet<char>()));
        Assert.Equal(pool[0], policy.SelectDriveLetter(second, new HashSet<char>()));
        backend.Snapshot = [first];
        await Cycle(worker);
        Assert.Equal(pool[2], policy.SelectDriveLetter(first, new HashSet<char>()));
        backend.Snapshot = [];
        await Cycle(worker);
        Assert.Equal(pool[0], policy.SelectDriveLetter(first, new HashSet<char>()));
        using var json = JsonDocument.Parse(File.ReadAllBytes(state));
        Assert.Single(json.RootElement.EnumerateObject());
        Assert.Equal(pool[2].ToString(), json.RootElement.GetProperty(FirstUuid).GetString());
    }

    [Fact]
    public async Task MissingObserverCatalogKeepsServiceFirstFreeAndDoesNotPersist()
    {
        using var temp = DTempDirectory.Create("drive-letter-legacy");
        var image = Path.Combine(temp.Path, "legacy.apfs.img");
        SyntheticApfsTestImage.Create(image, sizeMiB: 4);
        using var native = new NativeApfsBackend(
            new ServiceHostOptions { NativeAutoDiscoverPhysicalDrives = false },
            lifecycleTestHooks: null, observerRunner: new EvidenceRunner(""),
            observerPathOverride: Path.Combine(temp.Path, "missing.exe"));
        var state = Path.Combine(temp.Path, "letters.json");
        var pool = FreeLetters();
        var backend = new RecordingBackend(native, image);
        using var worker = Worker(backend, Policy(state, pool));
        await Cycle(worker);
        Assert.Null(Assert.Single(backend.LastDiscovery).CatalogVolumeUuid);
        Assert.Null(Assert.Single(backend.LastDiscovery).CatalogVolumeId);
        Assert.Equal(pool[0], Assert.Single(backend.Requests).DriveLetter);
        Assert.False(File.Exists(state));
    }

    private static string Evidence(bool reverse, string? devicePath = null)
    {
        var evidence = JsonNode.Parse(ObserverEvidenceJson.BuildSingleContainer(Container,
            [new("Same name", 201), new("Same name", 202)], devicePath: devicePath ?? "given-path"))!;
        var volumes = evidence["topology"]!["volumes"]!.AsArray();
        volumes[0]!["uuid"] = Guid.Parse(FirstUuid).ToString("N");
        volumes[1]!["uuid"] = Guid.Parse(SecondUuid).ToString("N");
        if (reverse)
        {
            var ids = evidence["topology"]!["containers"]![0]!["volumeIds"]!.AsArray();
            ids.Clear();
            ids.Add(Id(202));
            ids.Add(Id(201));
        }
        var json = evidence.ToJsonString();
        Assert.NotNull(NativeApfsObserver.ParseAndValidateEvidence(json));
        return json;
    }

    private static NativeApfsBackend Native(string evidence, DTempDirectory temp) => new(
        new ServiceHostOptions { BackendMode = "Native", NativeAutoDiscoverPhysicalDrives = false },
        lifecycleTestHooks: null, observerRunner: new EvidenceRunner(evidence),
        observerPathOverride: StagedPackagedObserver.StageStable("drive-letter-runtime"));

    private sealed class EvidenceRunner(string evidence) : IObserverRunner
    {
        public ObserverRunResult Run(string executable, IReadOnlyList<string> arguments)
            => new(0, evidence, string.Empty);
    }

    private static char[] FreeLetters()
    {
        var used = Environment.GetLogicalDrives().Select(d => char.ToUpperInvariant(d[0])).ToHashSet();
        var letters = Enumerable.Range('D', 23).Select(n => (char)n).Where(c => !used.Contains(c)).Take(3).ToArray();
        Assert.Equal(3, letters.Length);
        return letters;
    }

    private static FirstFreeMountPolicy Policy(string path, char[] pool)
        => new(pool.Select(c => c.ToString()), new VolumeDriveLetterAssignments(path));

    private static ApfsMountWorker Worker(IApfsBackend backend, IMountPolicy policy, bool autoMount = true)
        => new(NullLogger<ApfsMountWorker>.Instance, backend, policy, new RuntimeStatusPublisher(),
            new FixedOptions(new ServiceHostOptions { AutoMountEnabled = autoMount, EnableNativeWrite = false }));

    private static Task Cycle(ApfsMountWorker worker)
        => (Task)typeof(ApfsMountWorker).GetMethod("RunCycleAsync", BindingFlags.Instance | BindingFlags.NonPublic)!
            .Invoke(worker, [CancellationToken.None])!;

    private sealed class FixedOptions(ServiceHostOptions options) : IOptionsMonitor<ServiceHostOptions>
    {
        public ServiceHostOptions CurrentValue => options;
        public ServiceHostOptions Get(string? name) => options;
        public IDisposable? OnChange(Action<ServiceHostOptions, string?> listener) => null;
    }

    // Native discovery only reads synthetic image files. Mount operations are recorded, never delegated.
    private sealed class RecordingBackend(NativeApfsBackend? native, string image) : IApfsBackend, IContainerMountBackend
    {
        public IReadOnlyList<VolumeInfo>? Snapshot { get; set; }
        public IReadOnlyList<VolumeInfo> LastDiscovery { get; private set; } = [];
        public List<MountRequest> Requests { get; } = [];
        public List<MountedVolumeState> Mounts { get; } = [];
        public int BatchCalls { get; private set; }
        public Task<IReadOnlyList<DeviceInfo>> ProbeDevicesAsync(CancellationToken cancellationToken)
            => Task.FromResult<IReadOnlyList<DeviceInfo>>(Snapshot is null
                ? [new(image, "Fixture", true)]
                : Snapshot.Select(v => v.DeviceId).Distinct().Select(d => new DeviceInfo(d, "Fixture", true)).ToArray());
        public async Task<IReadOnlyList<VolumeInfo>> ProbeVolumesAsync(string deviceId, CancellationToken cancellationToken)
        {
            LastDiscovery = Snapshot is null
                ? await native!.ProbeVolumesAsync(deviceId, cancellationToken)
                : Snapshot.Where(v => v.DeviceId == deviceId).ToArray();
            return LastDiscovery;
        }
        public Task<MountResult> MountAsync(MountRequest request, CancellationToken cancellationToken)
        {
            Requests.Add(request);
            var mountPoint = $"{request.DriveLetter}:\\";
            Mounts.Add(new(request.VolumeId, mountPoint, request.AccessMode, DeviceId: image));
            return Task.FromResult(new MountResult(true, mountPoint, null, request.AccessMode));
        }
        public async Task<IReadOnlyList<MountResult>> MountContainerAsync(IReadOnlyList<MountRequest> requests, CancellationToken cancellationToken)
        {
            BatchCalls++;
            var results = new List<MountResult>();
            foreach (var request in requests) results.Add(await MountAsync(request, cancellationToken));
            return results;
        }
        public Task<UnmountResult> UnmountAsync(string mountPoint, CancellationToken cancellationToken)
        {
            Mounts.RemoveAll(m => m.MountPoint == mountPoint);
            return Task.FromResult(new UnmountResult(true, mountPoint, null, true, true, true));
        }
        public Task<IReadOnlyList<MountedVolumeState>> GetMountStateAsync(CancellationToken cancellationToken)
            => Task.FromResult<IReadOnlyList<MountedVolumeState>>(Mounts.ToArray());
    }
}
