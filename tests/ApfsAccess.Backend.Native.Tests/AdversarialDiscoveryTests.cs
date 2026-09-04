using System.Diagnostics;
using System.Reflection;
using ApfsAccess.Core;

namespace ApfsAccess.Backend.Native.Tests;

// A11 managed integration/adversarial: same-name volumes, same OID in
// different containers, malformed-GPT behavior per A2 rules, FsHost selector
// matrix at the mount-target seam, canonical-ID surfacing.
public sealed class AdversarialDiscoveryTests
{
    private const string ContainerHexA = "a9cb92d28b7c4b599eab633c7625f491";
    private const string ContainerHexB = "cccccccccccccccccccccccccccccccc";

    [Fact]
    public async Task SameNameVolumes_DiscoveryKeepsTwoRowsWithDistinctCanonicalIds()
    {
        using var temp = DTempDirectory.Create("adversarial-samename");
        var imagePath = Path.Combine(temp.Path, "samename.apfs.img");
        SyntheticApfsTestImage.CreateCatalogFixture(
            imagePath,
            new CatalogFixtureSpec(16, [new CatalogPartitionSpec(
                "P", Volumes: [new CatalogVolumeSpec("Data")])]));
        var evidence = ObserverEvidenceJson.BuildSingleContainer(
            ContainerHexA,
            [new ObserverEvidenceJson.VolumeJson("Data", 201),
             new ObserverEvidenceJson.VolumeJson("Data", 202)]);
        using var backend = CreateBackend(evidence, temp);

        var volumes = (await backend.ProbeVolumesAsync(imagePath, CancellationToken.None))
            .OrderBy(static volume => volume.VolumeId, StringComparer.Ordinal)
            .ToArray();

        Assert.Equal(2, volumes.Length);
        Assert.Equal($"apfs-vol:{ContainerHexA}:201", volumes[0].VolumeId);
        Assert.Equal($"apfs-vol:{ContainerHexA}:202", volumes[1].VolumeId);
        // Same display name, but independently addressable mount surface.
        Assert.Equal("Data", volumes[0].VolumeName);
        Assert.Equal("Data", volumes[1].VolumeName);
        Assert.NotEqual(volumes[0].NativeVolumePath, volumes[1].NativeVolumePath);
        var target0 = ReadMountTarget(backend, volumes[0]);
        var target1 = ReadMountTarget(backend, volumes[1]);
        Assert.Equal(201UL, target0.VolumeObjectId);
        Assert.Equal(202UL, target1.VolumeObjectId);
        Assert.Equal(ContainerHexA, target0.ContainerUuidHex);
        Assert.NotEqual(target0.RecoveryIdentity, target1.RecoveryIdentity);
    }

    [Fact]
    public async Task SameOidDifferentContainers_DiscoveryKeepsTwoRows()
    {
        using var temp = DTempDirectory.Create("adversarial-sameoid");
        var imagePath = Path.Combine(temp.Path, "sameoid.apfs.img");
        SyntheticApfsTestImage.CreateCatalogFixture(
            imagePath,
            new CatalogFixtureSpec(16, [new CatalogPartitionSpec(
                "P", Volumes: [new CatalogVolumeSpec("Data")])]));
        var evidence = ObserverEvidenceJson.BuildContainers(
            [(ContainerHexA, [new ObserverEvidenceJson.VolumeJson("Alpha", 101)]),
             (ContainerHexB, [new ObserverEvidenceJson.VolumeJson("Beta", 101)])]);
        using var backend = CreateBackend(evidence, temp);

        var volumes = (await backend.ProbeVolumesAsync(imagePath, CancellationToken.None))
            .OrderBy(static volume => volume.VolumeId, StringComparer.Ordinal)
            .ToArray();

        Assert.Equal(2, volumes.Length);
        Assert.Equal($"apfs-vol:{ContainerHexA}:101", volumes[0].VolumeId);
        Assert.Equal($"apfs-vol:{ContainerHexB}:101", volumes[1].VolumeId);
        Assert.Equal("Alpha", volumes[0].VolumeName);
        Assert.Equal("Beta", volumes[1].VolumeName);
    }

    [Fact]
    public async Task MalformedGptImage_ObserverFails_LegacyEmptyPerBranchRules()
    {
        // Malformed GPT + failed snapshot on an image path => legacy fallback
        // runs but finds no legacy rows => empty list, no throw.
        using var temp = DTempDirectory.Create("adversarial-gpt");
        var imagePath = Path.Combine(temp.Path, "truncated.apfs.img");
        await File.WriteAllBytesAsync(imagePath, new byte[] { 0x45, 0x46, 0x49, 0x20 });
        var runner = new StubRunner(new ObserverRunResult(1, string.Empty, "short read"));
        using var backend = CreateBackendWithRunner(runner, temp);

        var volumes = await backend.ProbeVolumesAsync(imagePath, CancellationToken.None);

        Assert.Empty(volumes);
    }

    [Fact]
    public async Task FsHostSelectorMatrix_AttachedOmitsNothing_UnattachedOmitsBoth()
    {
        using var temp = DTempDirectory.Create("adversarial-args");
        var imagePath = Path.Combine(temp.Path, "args.apfs.img");
        var fixture = SyntheticApfsTestImage.CreateCatalogFixture(
            imagePath,
            new CatalogFixtureSpec(16, [new CatalogPartitionSpec(
                "P", Volumes: [new CatalogVolumeSpec("Data")])]));
        var containerHex = ContainerHexOf(Assert.Single(fixture.Partitions).ContainerUuid);
        var evidence = ObserverEvidenceJson.BuildSingleContainer(
            containerHex, [new ObserverEvidenceJson.VolumeJson("Snap", 201)]);
        using var backend = CreateBackend(evidence, temp);
        var attached = Assert.Single(
            await backend.ProbeVolumesAsync(imagePath, CancellationToken.None));
        var attachedTarget = ReadMountTarget(backend, attached);

        var attachedArgs = new ProcessStartInfo();
        NativeApfsBackend.AppendVolumeSelectorArguments(
            attachedArgs, attached.VolumeName, attachedTarget.VolumeObjectId, attachedTarget.ContainerUuidHex);
        Assert.Equal(
            ["--volume", "Snap", "--volume-oid", "201", "--container-id", containerHex],
            attachedArgs.ArgumentList);

        // Legacy row without an attachment omits both selectors.
        using var legacyTemp = DTempDirectory.Create("adversarial-args-legacy");
        var legacyPath = Path.Combine(legacyTemp.Path, "legacy.apfs.img");
        SyntheticApfsTestImage.Create(legacyPath, sizeMiB: 4);
        using var legacyBackend = new NativeApfsBackend(
            new ServiceHostOptions { BackendMode = "Native", NativeAutoDiscoverPhysicalDrives = false },
            lifecycleTestHooks: null,
            observerRunner: new StubRunner(new ObserverRunResult(2, string.Empty, "off")),
            observerPathOverride: Path.Combine(legacyTemp.Path, "missing.exe"));
        var legacyVolume = Assert.Single(
            await legacyBackend.ProbeVolumesAsync(legacyPath, CancellationToken.None));
        var legacyTarget = ReadMountTarget(legacyBackend, legacyVolume);
        Assert.Null(legacyTarget.VolumeObjectId);
        Assert.Null(legacyTarget.ContainerUuidHex);

        var legacyArgs = new ProcessStartInfo();
        NativeApfsBackend.AppendVolumeSelectorArguments(
            legacyArgs, legacyVolume.VolumeName, legacyTarget.VolumeObjectId, legacyTarget.ContainerUuidHex);
        Assert.Equal(["--volume", "Main"], legacyArgs.ArgumentList);
    }

    [Fact]
    public async Task StatusSurface_ExposesCanonicalIdsAdditively()
    {
        using var temp = DTempDirectory.Create("adversarial-surface");
        var imagePath = Path.Combine(temp.Path, "surface.apfs.img");
        SyntheticApfsTestImage.CreateCatalogFixture(
            imagePath,
            new CatalogFixtureSpec(16, [new CatalogPartitionSpec(
                "P", Volumes: [new CatalogVolumeSpec("Data")])]));
        var evidence = ObserverEvidenceJson.BuildSingleContainer(
            ContainerHexA, [new ObserverEvidenceJson.VolumeJson("Snap", 201)]);
        using var backend = CreateBackend(evidence, temp);

        var volume = Assert.Single(
            await backend.ProbeVolumesAsync(imagePath, CancellationToken.None));

        // Canonical routing ID plus the additive catalog projection fields
        // that status/IPC/CLI/tray surfaces already carry through.
        Assert.Equal($"apfs-vol:{ContainerHexA}:201", volume.VolumeId);
        Assert.True(NativeApfsBackend.TryParseCanonicalVolumeId(
            volume.VolumeId, out var hex, out var oid));
        Assert.Equal(ContainerHexA, hex);
        Assert.Equal(201UL, oid);
        Assert.Equal($"apfs-vol:{ContainerHexA}:201", volume.CatalogVolumeId);
        Assert.Equal(ContainerHexA, volume.CatalogContainerUuid);
        Assert.Equal(201UL, volume.CatalogVolumeObjectId);
        Assert.NotNull(volume.CatalogDecision);
        Assert.False(string.IsNullOrWhiteSpace(volume.DeviceId));
        Assert.False(string.IsNullOrWhiteSpace(volume.VolumeName));
        Assert.False(string.IsNullOrWhiteSpace(volume.NativeVolumePath));
    }

    private static NativeApfsBackend CreateBackend(string evidence, DTempDirectory temp)
        => CreateBackendWithRunner(
            new StubRunner(new ObserverRunResult(0, evidence, string.Empty)), temp);

    private static NativeApfsBackend CreateBackendWithRunner(StubRunner runner, DTempDirectory temp)
    {
        var observerShim = Path.Combine(temp.Path, "ApfsObserver.exe");
        File.WriteAllBytes(observerShim, [0x4D, 0x5A]);
        return new NativeApfsBackend(
            new ServiceHostOptions { BackendMode = "Native", NativeAutoDiscoverPhysicalDrives = false },
            lifecycleTestHooks: null,
            observerRunner: runner,
            observerPathOverride: observerShim);
    }

    private sealed class StubRunner(ObserverRunResult result) : IObserverRunner
    {
        public ObserverRunResult Run(string observerPath, IReadOnlyList<string> arguments) => result;
    }

    private static string ContainerHexOf(Guid containerUuid)
        => Convert.ToHexString(containerUuid.ToByteArray()).ToLowerInvariant();

    private static (ulong? VolumeObjectId, string? ContainerUuidHex, string? RecoveryIdentity) ReadMountTarget(
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
            (string?)targetType.GetProperty("ContainerUuidHex")!.GetValue(target),
            (string?)targetType.GetProperty("RecoveryIdentity")!.GetValue(target));
    }
}
