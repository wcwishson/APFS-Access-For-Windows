using System.Reflection;
using System.Security.Cryptography;
using ApfsAccess.Core;

namespace ApfsAccess.Backend.Native.Tests;

// Real-binary integration: FAILS (never skips) when the STABLE observer
// binary is missing. Uses catalog fixtures built by CreateCatalogFixture.
public sealed class ObserverCatalogIntegrationTests
{
    private static string RealObserverPath()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        for (var level = 0; level < 14 && directory is not null; level++)
        {
            var candidate = Path.Combine(
                directory.FullName, "build", "ApfsAccess.ApfsRwEngine", "Release", "ApfsObserver.exe");
            if (File.Exists(candidate))
            {
                return candidate;
            }

            directory = directory.Parent;
        }

        Assert.Fail(
            "Integration requires build/ApfsAccess.ApfsRwEngine/Release/ApfsObserver.exe; refusing to skip.");
        throw new InvalidOperationException("Unreachable.");
    }

    [Fact]
    public void ObserverBinary_IsPresentForIntegration()
    {
        Assert.True(File.Exists(RealObserverPath()));
    }

    [Fact]
    public async Task SingleVolume_EndToEndAttachParsesAndEvaluatesWritable()
    {
        var observerPath = RealObserverPath();
        using var temp = DTempDirectory.Create("observer-e2e");
        var imagePath = Path.Combine(temp.Path, "single.apfs.img");
        var fixture = SyntheticApfsTestImage.CreateCatalogFixture(
            imagePath,
            new CatalogFixtureSpec(16, [new CatalogPartitionSpec("LegacyName", Volumes: [new CatalogVolumeSpec("Data")])]));
        var partition = Assert.Single(fixture.Partitions);
        var containerHex = Convert.ToHexString(partition.ContainerUuid.ToByteArray()).ToLowerInvariant();
        using var backend = new NativeApfsBackend(
            new ServiceHostOptions
            {
                BackendMode = "Native",
                NativeAutoDiscoverPhysicalDrives = false,
                NativeObserverPath = observerPath,
            },
            lifecycleTestHooks: null,
            observerRunner: null,
            observerPathOverride: observerPath);

        var snapshot = backend.TryDiscoverTopologySnapshot(imagePath, "integration-single");
        Assert.NotNull(snapshot);
        var observedVolume = Assert.Single(snapshot!.Volumes);
        Assert.Equal("Data", observedVolume.Name);
        Assert.Equal("101", observedVolume.ObjectId);
        Assert.Equal($"apfs-vol:{containerHex}:101", observedVolume.Id);

        var volume = Assert.Single(
            await backend.ProbeVolumesAsync(imagePath, CancellationToken.None));
        Assert.Equal("LegacyName", volume.VolumeName);
        Assert.Equal($"apfs-vol:{containerHex}:101", volume.CatalogVolumeId);
        Assert.Equal(containerHex, volume.CatalogContainerUuid);
        Assert.Equal(101UL, volume.CatalogVolumeObjectId);
        Assert.Equal(ApfsCapabilityDecision.Writable, volume.CatalogDecision);
        Assert.Equal([], volume.CatalogReasons);
        Assert.True(volume.CatalogAutoMountAllowed);

        var target = ReadMountTarget(backend, volume);
        Assert.Equal(101UL, target.VolumeObjectId);
        Assert.Equal(containerHex, target.ContainerUuidHex);
    }

    [Fact]
    public void EvidenceEnvelopeConsts_AndSourceSha256Binding()
    {
        var observerPath = RealObserverPath();
        using var temp = DTempDirectory.Create("observer-envelope");
        var imagePath = Path.Combine(temp.Path, "bound.apfs.img");
        SyntheticApfsTestImage.CreateCatalogFixture(imagePath);
        using var backend = new NativeApfsBackend(
            new ServiceHostOptions(),
            lifecycleTestHooks: null,
            observerRunner: null,
            observerPathOverride: observerPath);

        var evidence = backend.RunObserverEvidenceOrThrow(imagePath, "integration-envelope");

        Assert.Equal(ApfsTopology.EvidenceFormat, evidence.Format);
        Assert.Equal(ApfsTopology.EvidenceVersion, evidence.Version);
        Assert.Equal(ApfsTopology.ObserverId, evidence.ObserverId);
        Assert.False(evidence.Synthetic);
        Assert.Equal("full", evidence.Source.HashScope);
        using var stream = File.OpenRead(imagePath);
        var recomputed = Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
        Assert.Equal(recomputed, evidence.Source.Sha256);
        Assert.Equal(new FileInfo(imagePath).Length, evidence.Source.SizeBytes);
    }

    [Fact]
    public async Task MultiVolumeContainer_NameMatchAttachesUniqueOid()
    {
        var observerPath = RealObserverPath();
        using var temp = DTempDirectory.Create("observer-multivol");
        var imagePath = Path.Combine(temp.Path, "multivol.apfs.img");
        var fixture = SyntheticApfsTestImage.CreateCatalogFixture(
            imagePath,
            new CatalogFixtureSpec(16, [new CatalogPartitionSpec(
                "Data",
                Volumes: [new CatalogVolumeSpec("Data"), new CatalogVolumeSpec("Backup")])]));
        var containerHex = Convert.ToHexString(
            Assert.Single(fixture.Partitions).ContainerUuid.ToByteArray()).ToLowerInvariant();
        using var backend = new NativeApfsBackend(
            new ServiceHostOptions { BackendMode = "Native", NativeAutoDiscoverPhysicalDrives = false },
            lifecycleTestHooks: null,
            observerRunner: null,
            observerPathOverride: observerPath);

        var snapshot = backend.TryDiscoverTopologySnapshot(imagePath, "integration-multivol");
        Assert.NotNull(snapshot);
        Assert.Equal(2, snapshot!.Volumes.Count);

        var volume = Assert.Single(
            await backend.ProbeVolumesAsync(imagePath, CancellationToken.None));
        Assert.Equal("Data", volume.VolumeName);
        Assert.Equal(101UL, volume.CatalogVolumeObjectId);
        Assert.Equal($"apfs-vol:{containerHex}:101", volume.CatalogVolumeId);
        Assert.Equal(ApfsCapabilityDecision.Writable, volume.CatalogDecision);
    }

    [Fact]
    public async Task DuplicateVolumeNames_StayAmbiguousNull()
    {
        var observerPath = RealObserverPath();
        using var temp = DTempDirectory.Create("observer-dupname");
        var imagePath = Path.Combine(temp.Path, "dupname.apfs.img");
        SyntheticApfsTestImage.CreateCatalogFixture(
            imagePath,
            new CatalogFixtureSpec(16, [new CatalogPartitionSpec(
                "Data",
                Volumes: [new CatalogVolumeSpec("Data"), new CatalogVolumeSpec("Data")])]));
        using var backend = new NativeApfsBackend(
            new ServiceHostOptions { BackendMode = "Native", NativeAutoDiscoverPhysicalDrives = false },
            lifecycleTestHooks: null,
            observerRunner: null,
            observerPathOverride: observerPath);

        // Duplicate APSB names are reported (not fatal), but both legacy
        // matches are ambiguous, so no OID attaches.
        var snapshot = backend.TryDiscoverTopologySnapshot(imagePath, "integration-dupname");
        Assert.NotNull(snapshot);
        Assert.Equal(2, snapshot!.Volumes.Count);

        var volume = Assert.Single(
            await backend.ProbeVolumesAsync(imagePath, CancellationToken.None));
        Assert.Equal("Data", volume.VolumeName);
        Assert.Null(volume.CatalogVolumeObjectId);
        Assert.Null(volume.CatalogVolumeId);
        var target = ReadMountTarget(backend, volume);
        Assert.Null(target.VolumeObjectId);
    }

    private static (ulong? VolumeObjectId, string? ContainerUuidHex) ReadMountTarget(
        NativeApfsBackend backend, VolumeInfo volume)
    {
        var method = typeof(NativeApfsBackend).GetMethod(
            "ResolveMountTarget", BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(method);
        var target = method!.Invoke(backend, [volume]);
        Assert.NotNull(target);
        var targetType = target!.GetType();
        return (
            (ulong?)targetType.GetProperty("VolumeObjectId")!.GetValue(target),
            (string?)targetType.GetProperty("ContainerUuidHex")!.GetValue(target));
    }
}
