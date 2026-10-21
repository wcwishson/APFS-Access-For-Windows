using System.Diagnostics;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using ApfsAccess.Core;
using ApfsAccess.Ipc;
using ApfsAccess.Service;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit.Abstractions;

namespace ApfsAccess.Backend.Native.Tests;

public sealed class DriveLetterDiscoveryRepairTests(ITestOutputHelper output)
{
    private const string Container = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    private static readonly Guid A = Guid.Parse("11111111-2222-3333-4444-555555555555");
    private static readonly Guid B = Guid.Parse("66666666-7777-8888-9999-aaaaaaaaaaaa");
    private static string Id(ulong oid) => ApfsTopology.BuildVolumeId(Container, oid);

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AuthoritativeWorkerBypassesRealCacheWithUnchangedImageLayout(bool duplicate)
    {
        var root = Root();
        var image = Path.Combine(root, "layout.apfs.img");
        SyntheticApfsTestImage.CreateCatalogFixture(image, new CatalogFixtureSpec(16,
            [new CatalogPartitionSpec("APFS", ContainerUuid: Guid.Parse(Container),
                Volumes: [new CatalogVolumeSpec("Same name", VolumeUuid: A, ObjectId: 201)])]));
        var original = SHA256.HashData(File.ReadAllBytes(image));
        var timestamp = File.GetLastWriteTimeUtc(image);
        var observer = Path.Combine(root, "fixture-observer.exe");
        File.WriteAllBytes(observer, [0x4d, 0x5a]); // Evidence runner only: never executed.
        var runner = new CatalogRunner(Evidence(A, image));
        using var native = Native(image, observer, runner);
        var first = Assert.Single(await native.ProbeVolumesAsync(image, CancellationToken.None));
        Assert.Equal(A.ToString("N"), first.CatalogVolumeUuid);
        var path = Path.Combine(root, "letters.json");
        var store = new VolumeDriveLetterAssignments(path);
        Assert.True(store.SetPreference(A, 'T'));
        var bytes = File.ReadAllBytes(path);
        var policy = new FirstFreeMountPolicy(["R", "S", "T"], store);
        using var worker = Worker(native, policy);
        await worker.GetInventoryAsync(CancellationToken.None);
        var calls = runner.Calls;
        runner.Json = duplicate ? Evidence(A, image, duplicate: true) : Evidence(B, image);

        // The unchanged-layout/metadata cache really contains A. This ordinary
        // probe must hit it; only the production authoritative API defeats it.
        Assert.Equal(A.ToString("N"), Assert.Single(await native.ProbeVolumesAsync(image, CancellationToken.None)).CatalogVolumeUuid);
        Assert.Equal(calls, runner.Calls);
        var result = await worker.SetDriveLetterPreferenceAsync(new(image, Id(201), A.ToString("D"), "S"), CancellationToken.None);
        Assert.False(result.Success);
        Assert.Equal("ambiguous-target", result.Code);
        Assert.Equal(calls + 1, runner.Calls); // One fresh catalog, not two per device.
        Assert.Equal(bytes, File.ReadAllBytes(path));
        Assert.False(policy.GetDriveLetterPreference(first, null).CanEdit);
        Assert.Equal('R', policy.SelectDriveLetter(first, new HashSet<char>()));
        Assert.Equal(bytes, File.ReadAllBytes(path));
        var refreshed = await native.ProbeVolumesAsync(image, CancellationToken.None);
        Assert.Equal(duplicate ? 2 : 1, refreshed.Count);
        Assert.Equal((duplicate ? A : B).ToString("N"), refreshed[0].CatalogVolumeUuid);

        // A normal background cycle must also refresh identity without an edit.
        runner.Json = Evidence(B, image);
        await Cycle(worker);
        Assert.False(policy.GetDriveLetterPreference(first, null).CanEdit);
        Assert.Equal(original, SHA256.HashData(File.ReadAllBytes(image)));
        Assert.Equal(timestamp, File.GetLastWriteTimeUtc(image));
        output.WriteLine($"layout/image SHA256={Convert.ToHexString(original)}; observer calls={runner.Calls}; no native executable or mount used");
    }

    [Fact]
    public async Task ProductionObserverCancellationStopsOwnedChildAndReleasesDiscoveryAndMountLocks()
    {
        var root = Root();
        var child = Environment.GetEnvironmentVariable("APFS_TEST_OBSERVER_CHILD");
        Assert.False(string.IsNullOrWhiteSpace(child), "Build the observer child harness (scripts/build_observer_child.ps1) before this focused test.");
        Assert.StartsWith("D:\\", Path.GetFullPath(child!), StringComparison.OrdinalIgnoreCase);
        Assert.True(File.Exists(child));
        var image = Path.Combine(root, "safe.apfs.img");
        SyntheticApfsTestImage.Create(image, 4);
        var owner = Path.Combine(root, "child-owner.json");
        var runner = new ChildRunner(child!, owner, Evidence(A, image));
        using var native = Native(image, child!, runner);
        var path = Path.Combine(root, "letters.json");
        using var worker = Worker(native, new FirstFreeMountPolicy(["R", "S", "T"], new(path)));
        using var cancel = new CancellationTokenSource();
        var request = worker.SetDriveLetterPreferenceAsync(new(image, Id(201), A.ToString("D"), "T"), cancel.Token);
        try
        {
            var ready = Stopwatch.StartNew();
            byte[]? ownerBytes = null;
            while (ownerBytes is null && ready.Elapsed < TimeSpan.FromSeconds(5))
            {
                if (File.Exists(owner))
                {
                    try
                    {
                        ownerBytes = File.ReadAllBytes(owner);
                    }
                    catch (IOException ex) when ((ex.HResult & 0xffff) == 32)
                    {
                    }
                }
                if (ownerBytes is null) await Task.Delay(20);
            }
            Assert.True(ownerBytes is not null, "Owned child did not publish a readable identity proof.");
            using var identity = JsonDocument.Parse(ownerBytes);
            var pid = identity.RootElement.GetProperty("processId").GetInt32();
            using var exactChild = Process.GetProcessById(pid);
            Assert.Equal(Path.GetFullPath(child!), identity.RootElement.GetProperty("imagePath").GetString(), ignoreCase: true);
            Assert.Equal(identity.RootElement.GetProperty("processStartTimeUtcTicks").GetInt64(), exactChild.StartTime.ToUniversalTime().Ticks);
            Assert.False(exactChild.HasExited);

            // A caller timeout leaves the real operation alive. Eject with zero
            // mounts proves mount-lock responsiveness while discovery is blocked.
            await Assert.ThrowsAsync<TimeoutException>(() => request.WaitAsync(TimeSpan.FromMilliseconds(30)));
            Assert.False(request.IsCompleted);
            Assert.True((await worker.EjectAllAsync(CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(2))).Success);
            var queued = native.ProbeInventoryAsync(true, CancellationToken.None);
            Assert.False(queued.IsCompleted);
            var elapsed = Stopwatch.StartNew();
            cancel.Cancel();
            var error = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => request.WaitAsync(TimeSpan.FromSeconds(4)));
            Assert.True(exactChild.HasExited);
            Assert.Contains("exit confirmed", error.Message);
            Assert.False(File.Exists(path));
            Assert.NotEmpty(await queued.WaitAsync(TimeSpan.FromSeconds(2)));
            Assert.True((await worker.SetDriveLetterPreferenceAsync(new(image, Id(201), A.ToString("D"), "S"), CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(2))).Success);
            output.WriteLine($"owned PID={pid}; start ticks={exactChild.StartTime.ToUniversalTime().Ticks}; cancellation + cleanup + next request={elapsed.ElapsedMilliseconds} ms; executable SHA256={Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(child!)))}");
        }
        finally
        {
            cancel.Cancel();
            try { await request.WaitAsync(TimeSpan.FromSeconds(7)); } catch (OperationCanceledException) { }
        }
    }

    private string Root()
    {
        var root = Path.Combine(Environment.GetEnvironmentVariable("APFS_REPAIR_EVIDENCE") ?? "D:\\Temp\\ApfsAccessTests", "repair-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        output.WriteLine("retained fixture: " + root);
        return root;
    }

    private static string Evidence(Guid uuid, string imagePath, bool duplicate = false)
    {
        var node = JsonNode.Parse(ObserverEvidenceJson.BuildSingleContainer(Container,
            duplicate ? [new("Same name", 201), new("Other", 202)] : [new("Same name", 201)], devicePath: imagePath))!;
        foreach (var volume in node["topology"]!["volumes"]!.AsArray()) volume!["uuid"] = uuid.ToString("N");
        var json = node.ToJsonString();
        Assert.NotNull(NativeApfsObserver.ParseAndValidateEvidence(json));
        return json;
    }

    private static NativeApfsBackend Native(string image, string observer, IObserverRunner runner)
        => new(new ServiceHostOptions { NativeAutoDiscoverPhysicalDrives = false, NativeDeviceCandidates = [image] }, null, runner, observer);
    private static ApfsMountWorker Worker(IApfsBackend backend, IMountPolicy policy)
        => new(NullLogger<ApfsMountWorker>.Instance, backend, policy, new(), new Options());
    private static Task Cycle(ApfsMountWorker worker)
        => (Task)typeof(ApfsMountWorker).GetMethod("RunCycleAsync", BindingFlags.Instance | BindingFlags.NonPublic)!.Invoke(worker, [CancellationToken.None])!;
    private sealed class Options : IOptionsMonitor<ServiceHostOptions>
    {
        public ServiceHostOptions CurrentValue { get; } = new() { AutoMountEnabled = false, EnableNativeWrite = false };
        public ServiceHostOptions Get(string? name) => CurrentValue;
        public IDisposable? OnChange(Action<ServiceHostOptions, string?> listener) => null;
    }
    private sealed class CatalogRunner(string json) : IObserverRunner
    {
        public string Json = json;
        public int Calls;
        public ObserverRunResult Run(string path, IReadOnlyList<string> arguments) { Calls++; return new(0, Json, ""); }
    }
    private sealed class ChildRunner(string child, string owner, string evidence) : IObserverRunner
    {
        private int _calls;
        public ObserverRunResult Run(string path, IReadOnlyList<string> arguments) => throw new InvalidOperationException("Cancellation must reach the observer boundary.");
        public ObserverRunResult Run(string path, IReadOnlyList<string> arguments, CancellationToken token)
        {
            if (Interlocked.Increment(ref _calls) != 1) return new(0, evidence, "");
            return new ProcessObserverRunner().Run(child, ["--result-path", owner, "--sleep-ms", "5000"], token);
        }
    }
}
