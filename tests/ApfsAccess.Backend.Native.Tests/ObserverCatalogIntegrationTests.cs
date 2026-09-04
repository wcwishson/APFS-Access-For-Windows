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
        var stagedObserver = StagedPackagedObserver.Stage(observerPath, "e2e-single");
        using var backend = new NativeApfsBackend(
            new ServiceHostOptions
            {
                BackendMode = "Native",
                NativeAutoDiscoverPhysicalDrives = false,
                NativeObserverPath = stagedObserver,
            },
            lifecycleTestHooks: null,
            observerRunner: null,
            observerPathOverride: stagedObserver);

        var snapshot = backend.TryDiscoverTopologySnapshot(imagePath, "integration-single");
        Assert.NotNull(snapshot);
        var observedVolume = Assert.Single(snapshot!.Volumes);
        Assert.Equal("Data", observedVolume.Name);
        Assert.Equal("101", observedVolume.ObjectId);
        Assert.Equal($"apfs-vol:{containerHex}:101", observedVolume.Id);

        var volume = Assert.Single(
            await backend.ProbeVolumesAsync(imagePath, CancellationToken.None));
        // A2: the row is the snapshot volume ("Data"); the legacy GPT name
        // ("LegacyName") supplies only mount-path affordances.
        Assert.Equal("Data", volume.VolumeName);
        Assert.Equal($"apfs-vol:{containerHex}:101", volume.VolumeId);
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
        var stagedObserver = StagedPackagedObserver.Stage(observerPath, "multivol");
        using var backend = new NativeApfsBackend(
            new ServiceHostOptions { BackendMode = "Native", NativeAutoDiscoverPhysicalDrives = false },
            lifecycleTestHooks: null,
            observerRunner: null,
            observerPathOverride: stagedObserver);

        var snapshot = backend.TryDiscoverTopologySnapshot(
            imagePath, "integration-multivol", out var observerError);
        Assert.True(snapshot is not null, observerError);
        Assert.Equal(2, snapshot!.Volumes.Count);

        // A2: one row per snapshot volume (the single legacy GPT row only
        // supplies affordances).
        var volumes = (await backend.ProbeVolumesAsync(imagePath, CancellationToken.None))
            .OrderBy(static volume => volume.VolumeName, StringComparer.Ordinal)
            .ToArray();
        Assert.Equal(2, volumes.Length);
        var volume = volumes.First(static row => row.VolumeName == "Data");
        Assert.Equal(101UL, volume.CatalogVolumeObjectId);
        Assert.Equal($"apfs-vol:{containerHex}:101", volume.VolumeId);
        Assert.Equal($"apfs-vol:{containerHex}:101", volume.CatalogVolumeId);
        Assert.Equal(ApfsCapabilityDecision.Writable, volume.CatalogDecision);
    }

    [Fact]
    public async Task DuplicateVolumeNames_StayIndependentlyAddressable()
    {
        var observerPath = RealObserverPath();
        using var temp = DTempDirectory.Create("observer-dupname");
        var imagePath = Path.Combine(temp.Path, "dupname.apfs.img");
        var fixture = SyntheticApfsTestImage.CreateCatalogFixture(
            imagePath,
            new CatalogFixtureSpec(16, [new CatalogPartitionSpec(
                "Data",
                Volumes: [new CatalogVolumeSpec("Data"), new CatalogVolumeSpec("Data")])]));
        var containerHex = Convert.ToHexString(
            Assert.Single(fixture.Partitions).ContainerUuid.ToByteArray()).ToLowerInvariant();
        using var backend = new NativeApfsBackend(
            new ServiceHostOptions { BackendMode = "Native", NativeAutoDiscoverPhysicalDrives = false },
            lifecycleTestHooks: null,
            observerRunner: null,
            observerPathOverride: observerPath);

        // Duplicate APSB names are reported (not fatal); A3 keeps both rows
        // independently addressable by canonical ID.
        var snapshot = backend.TryDiscoverTopologySnapshot(imagePath, "integration-dupname");
        Assert.NotNull(snapshot);
        Assert.Equal(2, snapshot!.Volumes.Count);

        var volumes = (await backend.ProbeVolumesAsync(imagePath, CancellationToken.None))
            .OrderBy(static volume => volume.VolumeId, StringComparer.Ordinal)
            .ToArray();
        Assert.Equal(2, volumes.Length);
        Assert.NotEqual(volumes[0].VolumeId, volumes[1].VolumeId);
        Assert.All(volumes, static volume => Assert.StartsWith("apfs-vol:", volume.VolumeId));
        Assert.NotEqual(volumes[0].NativeVolumePath, volumes[1].NativeVolumePath);
        var target = ReadMountTarget(backend, volumes[0]);
        Assert.NotNull(target.VolumeObjectId);
        Assert.Equal(containerHex, target.ContainerUuidHex);
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
