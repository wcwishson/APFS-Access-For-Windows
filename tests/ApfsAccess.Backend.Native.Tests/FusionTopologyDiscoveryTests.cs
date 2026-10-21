using ApfsAccess.Core;

namespace ApfsAccess.Backend.Native.Tests;

// Task 9 managed Fusion discovery: two-store observer evidence binds to one
// canonical container topology fail-closed. RW admission stays closed
// elsewhere (FusionBacked write block); this covers topology projection only.
public sealed class FusionTopologyDiscoveryTests
{
    private const string ContainerHex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    [Fact]
    public void FusionArguments_EmitTwoStoreFusionVector()
    {
        var args = NativeApfsObserver.BuildFusionObserverArguments(
            @"D:\fusion\main.apfs", @"D:\fusion\tier2.apfs", "managed-discovery", "main.apfs");

        Assert.Equal(
            ["--store-a", @"D:\fusion\main.apfs", "--store-b", @"D:\fusion\tier2.apfs",
             "--profile", "managed-discovery", "--mode", "fusion", "--device-id", "main.apfs"],
            args);
    }

    [Fact]
    public void FusionArguments_RejectDistinctnessViolations()
    {
        Assert.Throws<ArgumentException>(() => NativeApfsObserver.BuildFusionObserverArguments(
            @"D:\fusion\main.apfs", @"D:\fusion\main.apfs", "managed-discovery", "main.apfs"));
        Assert.Throws<ArgumentException>(() => NativeApfsObserver.BuildFusionObserverArguments(
            "", @"D:\fusion\tier2.apfs", "managed-discovery", "main.apfs"));
    }

    [Fact]
    public void BindFusionPair_ReturnsCanonicalSortedDiskIds()
    {
        using var temp = DTempDirectory.Create("fusion-bind");
        // Input order is reverse-sorted on purpose: DiskIds must be canonical.
        var storeA = Path.Combine(temp.Path, "z-main.apfs");
        var storeB = Path.Combine(temp.Path, "a-tier2.apfs");
        var evidence = NativeApfsObserver.ParseAndValidateEvidence(
            ObserverEvidenceJson.BuildFusionPair(
                ContainerHex, [new ObserverEvidenceJson.VolumeJson("Data", 101)], storeA, storeB));

        var bound = NativeApfsBackend.BindFusionDiscoveryTopology(storeA, storeB, 42, evidence);

        Assert.NotNull(bound);
        Assert.Equal(storeA, bound!.DeviceId);
        Assert.Equal(42, bound.Generation);
        Assert.Equal(
            [ApfsTopology.BuildDiskId("a-tier2.apfs"), ApfsTopology.BuildDiskId("z-main.apfs")],
            bound.DiskIds);
        var container = Assert.Single(bound.Snapshot.Containers);
        Assert.True(container.Fusion);
        Assert.Equal(2, container.StoreIds.Count);
        Assert.Equal("101", Assert.Single(bound.Snapshot.Volumes).ObjectId);
    }

    [Theory]
    [InlineData(true, false, false, false, false)]
    [InlineData(false, true, false, false, false)]
    [InlineData(false, false, true, false, false)]
    [InlineData(false, false, false, true, false)]
    [InlineData(false, false, false, false, true)]
    public void BindFusionPair_RefusesAmbiguousOrMismatchedSets(
        bool swapPaths, bool samePath, bool collectMode, bool nonFusionContainer, bool unknownDisk)
    {
        using var temp = DTempDirectory.Create("fusion-refuse");
        var storeA = Path.Combine(temp.Path, "main.apfs");
        var storeB = Path.Combine(temp.Path, "tier2.apfs");
        string json;
        string bindA = storeA, bindB = storeB;
        if (collectMode)
        {
            json = ObserverEvidenceJson.BuildSingleContainer(
                ContainerHex, [new ObserverEvidenceJson.VolumeJson("Data", 101)]);
        }
        else
        {
            json = ObserverEvidenceJson.BuildFusionPair(
                ContainerHex, [new ObserverEvidenceJson.VolumeJson("Data", 101)], storeA, storeB);
            if (nonFusionContainer)
            {
                json = json.Replace("\"fusion\":true", "\"fusion\":false", StringComparison.Ordinal);
            }
        }

        if (swapPaths) (bindA, bindB) = (bindB, bindA);
        if (samePath) bindB = bindA;
        if (unknownDisk) { bindA = Path.Combine(temp.Path, "other.apfs"); bindB = storeB; }

        var evidence = NativeApfsObserver.ParseAndValidateEvidence(json);
        Assert.Null(NativeApfsBackend.BindFusionDiscoveryTopology(bindA, bindB, 7, evidence));
    }

    [Fact]
    public void RunFusionEvidence_InvokesFusionVectorAndBinds()
    {
        using var temp = DTempDirectory.Create("fusion-invoke");
        var observerShim = Path.Combine(temp.Path, "ApfsObserver.exe");
        File.WriteAllBytes(observerShim, [0x4D, 0x5A]);
        var storeA = Path.Combine(temp.Path, "main.apfs");
        var storeB = Path.Combine(temp.Path, "tier2.apfs");
        File.WriteAllBytes(storeA, new byte[4096]);
        File.WriteAllBytes(storeB, new byte[4096]);
        var evidence = ObserverEvidenceJson.BuildFusionPair(
            ContainerHex, [new ObserverEvidenceJson.VolumeJson("Data", 101)], storeA, storeB);
        var runner = new CapturingRunner(new ObserverRunResult(0, evidence, string.Empty));
        using var backend = new NativeApfsBackend(
            new ServiceHostOptions { BackendMode = "Native", NativeAutoDiscoverPhysicalDrives = false },
            lifecycleTestHooks: null,
            observerRunner: runner,
            observerPathOverride: observerShim);

        var observed = backend.RunFusionObserverEvidenceOrThrow(storeA, storeB, "managed-discovery");
        var bound = NativeApfsBackend.BindFusionDiscoveryTopology(storeA, storeB, 9, observed);

        Assert.Equal(
            ["--store-a", storeA, "--store-b", storeB,
             "--profile", "managed-discovery", "--mode", "fusion", "--device-id", "main.apfs"],
            runner.LastArguments);
        Assert.NotNull(bound);
        Assert.Equal(2, bound!.DiskIds.Count);
        Assert.Equal("Data", Assert.Single(bound.Snapshot.Volumes).Name);
    }

    [Fact]
    public void RunFusionEvidence_SurfacesStderrFailClosed()
    {
        using var temp = DTempDirectory.Create("fusion-stderr");
        var observerShim = Path.Combine(temp.Path, "ApfsObserver.exe");
        File.WriteAllBytes(observerShim, [0x4D, 0x5A]);
        var runner = new CapturingRunner(new ObserverRunResult(2, string.Empty, "error: ambiguous members"));
        using var backend = new NativeApfsBackend(
            new ServiceHostOptions(),
            lifecycleTestHooks: null,
            observerRunner: runner,
            observerPathOverride: observerShim);

        var exception = Assert.Throws<InvalidOperationException>(
            () => backend.RunFusionObserverEvidenceOrThrow(@"D:\f\a.apfs", @"D:\f\b.apfs", "managed-discovery"));
        Assert.Contains("error: ambiguous members", exception.Message);
    }

    private sealed class CapturingRunner(ObserverRunResult result) : IObserverRunner
    {
        public string? LastObserverPath { get; private set; }

        public IReadOnlyList<string>? LastArguments { get; private set; }

        public ObserverRunResult Run(string observerPath, IReadOnlyList<string> arguments)
        {
            LastObserverPath = observerPath;
            LastArguments = arguments.ToArray();
            return result;
        }
    }
}
