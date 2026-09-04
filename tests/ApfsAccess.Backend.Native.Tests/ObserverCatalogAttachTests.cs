using System.Reflection;
using ApfsAccess.Core;

namespace ApfsAccess.Backend.Native.Tests;

public sealed class ObserverCatalogAttachTests
{
    [Fact]
    public async Task ObserverAbsent_KeepsLegacyNamesMountTargetsAndIdentityByteIdentical()
    {
        using var temp = DTempDirectory.Create("attach-absent");
        var imagePath = Path.Combine(temp.Path, "legacy.apfs.img");
        SyntheticApfsTestImage.Create(imagePath, sizeMiB: 4);
        using var backend = new NativeApfsBackend(
            new ServiceHostOptions { BackendMode = "Native", NativeAutoDiscoverPhysicalDrives = false },
            lifecycleTestHooks: null,
            observerRunner: new StubRunner(new ObserverRunResult(0, "{}", string.Empty)),
            observerPathOverride: null);

        var volume = Assert.Single(
            await backend.ProbeVolumesAsync(imagePath, CancellationToken.None));

        Assert.Equal($"{imagePath}|Main", volume.VolumeId);
        Assert.Equal("Main", volume.VolumeName);
        Assert.Null(volume.CatalogVolumeId);
        Assert.Null(volume.CatalogContainerUuid);
        Assert.Null(volume.CatalogVolumeObjectId);
        Assert.Null(volume.CatalogDecision);
        Assert.Null(volume.CatalogReasons);
        Assert.Null(volume.CatalogAutoMountAllowed);
        var target = ReadMountTarget(backend, volume);
        Assert.Equal(0UL, target.OffsetBytes);
        Assert.Null(target.VolumeObjectId);
        Assert.Null(target.ContainerUuidHex);
        var containerHexUpper = Convert.ToHexString(
            new Guid("A9CB92D2-8B7C-4B59-9EAB-633C7625F491").ToByteArray());
        Assert.Equal(
            BuildRecoveryIdentity(null, containerHexUpper, 0x54UL, allowPartitionlessIdentity: true),
            target.RecoveryIdentity);
    }

    [Fact]
    public async Task SingleContainerSingleVolume_SnapshotRowCarriesSnapshotIdentityWithLegacyAffordances()
    {
        // A2: rows come from the snapshot only. The legacy GPT name
        // ("LegacyName") survives nowhere in the row; it only supplies
        // mount-path affordances (device offset, partition GUID) matched by
        // container UUID.
        using var temp = DTempDirectory.Create("attach-single");
        var imagePath = Path.Combine(temp.Path, "single.apfs.img");
        var fixture = SyntheticApfsTestImage.CreateCatalogFixture(
            imagePath,
            new CatalogFixtureSpec(16, [new CatalogPartitionSpec("LegacyName", Volumes: [new CatalogVolumeSpec("Data")])]));
        var partition = Assert.Single(fixture.Partitions);
        var containerHex = ContainerHexOf(partition.ContainerUuid);
        var evidence = ObserverEvidenceJson.BuildSingleContainer(
            containerHex, [new ObserverEvidenceJson.VolumeJson("Data", 101)]);
        using var backend = CreateBackend(evidence, temp);

        var volume = Assert.Single(
            await backend.ProbeVolumesAsync(imagePath, CancellationToken.None));

        Assert.Equal($"apfs-vol:{containerHex}:101", volume.VolumeId);
        Assert.Equal("Data", volume.VolumeName);
        Assert.Equal($"apfs-vol:{containerHex}:101", volume.CatalogVolumeId);
        Assert.Equal(containerHex, volume.CatalogContainerUuid);
        Assert.Equal(101UL, volume.CatalogVolumeObjectId);
        var target = ReadMountTarget(backend, volume);
        Assert.Equal(101UL, target.VolumeObjectId);
        Assert.Equal(containerHex, target.ContainerUuidHex);
        Assert.Equal((ulong)partition.StartByte, target.OffsetBytes);
        Assert.Equal(
            BuildRecoveryIdentity(
                partition.PartitionUuid,
                Convert.ToHexString(partition.ContainerUuid.ToByteArray()),
                101UL,
                allowPartitionlessIdentity: false),
            target.RecoveryIdentity);
    }

    [Fact]
    public async Task SnapshotRows_EachCarryOwnOidForRecoveryIdentity()
    {
        using var temp = DTempDirectory.Create("attach-namematch");
        var imagePath = Path.Combine(temp.Path, "multi.apfs.img");
        var fixture = SyntheticApfsTestImage.CreateCatalogFixture(
            imagePath,
            new CatalogFixtureSpec(16, [new CatalogPartitionSpec(
                "P",
                Volumes: [new CatalogVolumeSpec("Other"), new CatalogVolumeSpec("P")])]));
        var partition = Assert.Single(fixture.Partitions);
        var containerHex = ContainerHexOf(partition.ContainerUuid);
        var evidence = ObserverEvidenceJson.BuildSingleContainer(
            containerHex,
            [new ObserverEvidenceJson.VolumeJson("Other", 101),
             new ObserverEvidenceJson.VolumeJson("P", 102)]);
        using var backend = CreateBackend(evidence, temp);

        // A2: one row per snapshot volume, not one row per legacy partition.
        var volumes = (await backend.ProbeVolumesAsync(imagePath, CancellationToken.None))
            .OrderBy(static volume => volume.VolumeName, StringComparer.Ordinal)
            .ToArray();

        Assert.Equal(2, volumes.Length);
        Assert.Equal($"apfs-vol:{containerHex}:101", volumes[0].VolumeId);
        Assert.Equal($"apfs-vol:{containerHex}:102", volumes[1].VolumeId);
        foreach (var volume in volumes)
        {
            var target = ReadMountTarget(backend, volume);
            Assert.Equal(volume.CatalogVolumeObjectId, target.VolumeObjectId);
            Assert.Equal(
                BuildRecoveryIdentity(
                    partition.PartitionUuid,
                    Convert.ToHexString(partition.ContainerUuid.ToByteArray()),
                    volume.CatalogVolumeObjectId,
                    allowPartitionlessIdentity: false),
                target.RecoveryIdentity);
        }

        Assert.NotEqual(
            ReadMountTarget(backend, volumes[0]).RecoveryIdentity,
            ReadMountTarget(backend, volumes[1]).RecoveryIdentity);
    }

    [Fact]
    public async Task DuplicateSnapshotNames_StayIndependentlyAddressable()
    {
        // A3: duplicate display names are two rows with distinct canonical
        // IDs (the old unique-or-null name-match rule is superseded).
        using var temp = DTempDirectory.Create("attach-ambiguous");
        var imagePath = Path.Combine(temp.Path, "dup.apfs.img");
        var fixture = SyntheticApfsTestImage.CreateCatalogFixture(
            imagePath,
            new CatalogFixtureSpec(16, [new CatalogPartitionSpec(
                "Data",
                Volumes: [new CatalogVolumeSpec("Data"), new CatalogVolumeSpec("Data")])]));
        var partition = Assert.Single(fixture.Partitions);
        var containerHex = ContainerHexOf(partition.ContainerUuid);
        var evidence = ObserverEvidenceJson.BuildSingleContainer(
            containerHex,
            [new ObserverEvidenceJson.VolumeJson("Data", 101),
             new ObserverEvidenceJson.VolumeJson("Data", 102)]);
        using var backend = CreateBackend(evidence, temp);

        var volumes = (await backend.ProbeVolumesAsync(imagePath, CancellationToken.None))
            .OrderBy(static volume => volume.VolumeId, StringComparer.Ordinal)
            .ToArray();

        Assert.Equal(2, volumes.Length);
        Assert.Equal($"apfs-vol:{containerHex}:101", volumes[0].VolumeId);
        Assert.Equal($"apfs-vol:{containerHex}:102", volumes[1].VolumeId);
        Assert.NotEqual(volumes[0].NativeVolumePath, volumes[1].NativeVolumePath);
        Assert.Equal(101UL, volumes[0].CatalogVolumeObjectId);
        Assert.Equal(102UL, volumes[1].CatalogVolumeObjectId);
        var target0 = ReadMountTarget(backend, volumes[0]);
        var target1 = ReadMountTarget(backend, volumes[1]);
        Assert.Equal(101UL, target0.VolumeObjectId);
        Assert.Equal(102UL, target1.VolumeObjectId);
        Assert.Equal(containerHex, target0.ContainerUuidHex);
        // Each row binds its own SELECTED oid in the recovery identity.
        Assert.Equal(
            BuildRecoveryIdentity(
                partition.PartitionUuid,
                Convert.ToHexString(partition.ContainerUuid.ToByteArray()),
                101UL,
                allowPartitionlessIdentity: false),
            target0.RecoveryIdentity);
        Assert.Equal(
            BuildRecoveryIdentity(
                partition.PartitionUuid,
                Convert.ToHexString(partition.ContainerUuid.ToByteArray()),
                102UL,
                allowPartitionlessIdentity: false),
            target1.RecoveryIdentity);
    }

    [Fact]
    public async Task UnmatchedNames_SnapshotRowsStandAlone()
    {
        // A2: snapshot rows never depend on legacy GPT names; evidence names
        // unrelated to every legacy name still enumerate fully.
        using var temp = DTempDirectory.Create("attach-unmatched");
        var imagePath = Path.Combine(temp.Path, "unmatched.apfs.img");
        var fixture = SyntheticApfsTestImage.CreateCatalogFixture(
            imagePath,
            new CatalogFixtureSpec(16,
            [
                new CatalogPartitionSpec("Alpha", Volumes: [new CatalogVolumeSpec("A")]),
                new CatalogPartitionSpec("Beta", Volumes: [new CatalogVolumeSpec("B")]),
            ]));
        var hexes = fixture.Partitions.Select(static partition => ContainerHexOf(partition.ContainerUuid)).ToArray();
        var evidence = ObserverEvidenceJson.BuildContainers(
            [(hexes[0], [new ObserverEvidenceJson.VolumeJson("X", 101)]),
             (hexes[1], [new ObserverEvidenceJson.VolumeJson("Y", 102)])]);
        using var backend = CreateBackend(evidence, temp);

        var volumes = (await backend.ProbeVolumesAsync(imagePath, CancellationToken.None))
            .OrderBy(static volume => volume.VolumeName, StringComparer.Ordinal)
            .ToArray();

        Assert.Equal(2, volumes.Length);
        Assert.Equal("X", volumes[0].VolumeName);
        Assert.Equal("Y", volumes[1].VolumeName);
        Assert.Equal($"apfs-vol:{hexes[0]}:101", volumes[0].VolumeId);
        Assert.Equal($"apfs-vol:{hexes[1]}:102", volumes[1].VolumeId);
        Assert.Equal(101UL, volumes[0].CatalogVolumeObjectId);
        Assert.Equal(102UL, volumes[1].CatalogVolumeObjectId);
    }

    [Fact]
    public async Task MultiPartition_NameMatchAttachesEachVolumeOid()
    {
        using var temp = DTempDirectory.Create("attach-multi");
        var imagePath = Path.Combine(temp.Path, "multi-part.apfs.img");
        var fixture = SyntheticApfsTestImage.CreateCatalogFixture(
            imagePath,
            new CatalogFixtureSpec(16,
            [
                new CatalogPartitionSpec("Data", Volumes: [new CatalogVolumeSpec("Data")]),
                new CatalogPartitionSpec("Backup", Volumes: [new CatalogVolumeSpec("Backup")]),
            ]));
        var hexes = fixture.Partitions.Select(static partition => ContainerHexOf(partition.ContainerUuid)).ToArray();
        var evidence = ObserverEvidenceJson.BuildContainers(
            [(hexes[0], [new ObserverEvidenceJson.VolumeJson("Data", 101)]),
             (hexes[1], [new ObserverEvidenceJson.VolumeJson("Backup", 103)])]);
        using var backend = CreateBackend(evidence, temp);

        var volumes = (await backend.ProbeVolumesAsync(imagePath, CancellationToken.None))
            .OrderBy(static volume => volume.VolumeName, StringComparer.Ordinal)
            .ToArray();

        Assert.Equal(2, volumes.Length);
        Assert.Equal(103UL, volumes[0].CatalogVolumeObjectId);
        Assert.Equal($"apfs-vol:{hexes[1]}:103", volumes[0].CatalogVolumeId);
        Assert.Equal($"apfs-vol:{hexes[1]}:103", volumes[0].VolumeId);
        Assert.Equal(101UL, volumes[1].CatalogVolumeObjectId);
        Assert.Equal($"apfs-vol:{hexes[0]}:101", volumes[1].CatalogVolumeId);
        Assert.Equal($"apfs-vol:{hexes[0]}:101", volumes[1].VolumeId);
    }

    [Fact]
    public async Task OrdinaryUnencryptedDataVolume_EvaluatesWritable()
    {
        using var temp = DTempDirectory.Create("attach-capability");
        var imagePath = Path.Combine(temp.Path, "capable.apfs.img");
        var fixture = SyntheticApfsTestImage.CreateCatalogFixture(
            imagePath,
            new CatalogFixtureSpec(16, [new CatalogPartitionSpec("LegacyName", Volumes: [new CatalogVolumeSpec("Data")])]));
        var containerHex = ContainerHexOf(Assert.Single(fixture.Partitions).ContainerUuid);
        var evidence = ObserverEvidenceJson.BuildSingleContainer(
            containerHex, [new ObserverEvidenceJson.VolumeJson("Data", 101)]);
        using var backend = CreateBackend(evidence, temp);

        var volume = Assert.Single(
            await backend.ProbeVolumesAsync(imagePath, CancellationToken.None));

        Assert.Equal(ApfsCapabilityDecision.Writable, volume.CatalogDecision);
        Assert.Equal([], volume.CatalogReasons);
        Assert.True(volume.CatalogAutoMountAllowed);
        // Legacy write derivations are unchanged by catalog evidence.
        Assert.False(volume.SupportsReadWrite);
        Assert.False(volume.SupportsNativeWrite);
    }

    [Fact]
    public async Task EncryptedVolume_EvaluatesLockedWithoutChangingLegacyDerivations()
    {
        using var temp = DTempDirectory.Create("attach-locked");
        var imagePath = Path.Combine(temp.Path, "locked.apfs.img");
        var fixture = SyntheticApfsTestImage.CreateCatalogFixture(
            imagePath,
            new CatalogFixtureSpec(16, [new CatalogPartitionSpec(
                "LegacyName",
                Volumes: [new CatalogVolumeSpec("Data", FsFlags: 0x8)])]));
        var containerHex = ContainerHexOf(Assert.Single(fixture.Partitions).ContainerUuid);
        var evidence = ObserverEvidenceJson.BuildSingleContainer(
            containerHex, [new ObserverEvidenceJson.VolumeJson("Data", 101, FsFlags: 0x8, EncryptionMode: "password")]);
        using var backend = CreateBackend(evidence, temp);

        var volume = Assert.Single(
            await backend.ProbeVolumesAsync(imagePath, CancellationToken.None));

        Assert.Equal(ApfsCapabilityDecision.Locked, volume.CatalogDecision);
        Assert.Equal(["locked-encrypted"], volume.CatalogReasons);
        Assert.False(volume.CatalogAutoMountAllowed);
        Assert.False(volume.SupportsReadWrite);
    }

    private static NativeApfsBackend CreateBackend(string evidence, DTempDirectory temp)
    {
        // Stage under the test host base directory so provenance treats the
        // seam override as packaged (trusted), matching production layout.
        var stagedObserver = StagedPackagedObserver.StageStable("attach");
        return new NativeApfsBackend(
            new ServiceHostOptions { BackendMode = "Native", NativeAutoDiscoverPhysicalDrives = false },
            lifecycleTestHooks: null,
            observerRunner: new StubRunner(new ObserverRunResult(0, evidence, string.Empty)),
            observerPathOverride: stagedObserver);
    }

    private sealed class StubRunner(ObserverRunResult result) : IObserverRunner
    {
        public ObserverRunResult Run(string observerPath, IReadOnlyList<string> arguments) => result;
    }

    private static string ContainerHexOf(Guid containerUuid)
        => Convert.ToHexString(containerUuid.ToByteArray()).ToLowerInvariant();

    private static (ulong OffsetBytes, string? RecoveryIdentity, ulong? VolumeObjectId, string? ContainerUuidHex)
        ReadMountTarget(NativeApfsBackend backend, VolumeInfo volume)
    {
        var method = typeof(NativeApfsBackend).GetMethod(
            "ResolveMountTarget", BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(method);
        var target = method!.Invoke(backend, [volume]);
        Assert.NotNull(target);
        var targetType = target!.GetType();
        return (
            (ulong)targetType.GetProperty("DeviceOffsetBytes")!.GetValue(target)!,
            (string?)targetType.GetProperty("RecoveryIdentity")!.GetValue(target),
            (ulong?)targetType.GetProperty("VolumeObjectId")!.GetValue(target),
            (string?)targetType.GetProperty("ContainerUuidHex")!.GetValue(target));
    }

    private static string? BuildRecoveryIdentity(
        Guid? partitionUniqueGuid, string? containerUuid, ulong? firstVolumeObjectId, bool allowPartitionlessIdentity)
    {
        var method = typeof(NativeApfsBackend).GetMethod(
            "BuildRecoveryIdentityFromComponents", BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);
        return (string?)method!.Invoke(
            null, [partitionUniqueGuid, containerUuid, firstVolumeObjectId, allowPartitionlessIdentity]);
    }
}
