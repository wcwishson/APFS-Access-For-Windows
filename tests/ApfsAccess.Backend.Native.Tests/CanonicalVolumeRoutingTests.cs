using System.Diagnostics;
using System.Reflection;
using ApfsAccess.Core;

namespace ApfsAccess.Backend.Native.Tests;

// A3 container-qualified routing: canonical apfs-vol:<hex32>:<oid> is the
// routing key; legacy device|name translates only on a unique cached name
// match; duplicates stay independently addressable; FsHost launch carries
// --volume-oid + --container-id whenever the attachment is known.
// RED first: TryParseCanonicalVolumeId/TryResolveCanonicalVolumeId do not
// exist yet and discovery is still legacy-sized.
public sealed class CanonicalVolumeRoutingTests
{
    private const string ContainerHexA = "a9cb92d28b7c4b599eab633c7625f491";
    private const string ContainerHexB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    [Fact]
    public void TryParseCanonicalVolumeId_AcceptsCanonical_RejectsMalformed()
    {
        Assert.True(NativeApfsBackend.TryParseCanonicalVolumeId(
            $"apfs-vol:{ContainerHexA}:101", out var hex, out var oid));
        Assert.Equal(ContainerHexA, hex);
        Assert.Equal(101UL, oid);

        Assert.False(NativeApfsBackend.TryParseCanonicalVolumeId(
            @"D:\x.apfs.img|Main", out _, out _));
        Assert.False(NativeApfsBackend.TryParseCanonicalVolumeId(
            $"apfs-vol:{ContainerHexA}", out _, out _));
        Assert.False(NativeApfsBackend.TryParseCanonicalVolumeId(
            "apfs-vol:ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ:101", out _, out _));
        Assert.False(NativeApfsBackend.TryParseCanonicalVolumeId(
            $"apfs-vol:{ContainerHexA}:0101", out _, out _));
        Assert.False(NativeApfsBackend.TryParseCanonicalVolumeId(null, out _, out _));
        Assert.False(NativeApfsBackend.TryParseCanonicalVolumeId(string.Empty, out _, out _));
    }

    [Fact]
    public async Task LegacyVolumeId_TranslatesOnlyOnUniqueCachedNameMatch()
    {
        using var temp = DTempDirectory.Create("routing-translate");
        var imagePath = Path.Combine(temp.Path, "route.apfs.img");
        SyntheticApfsTestImage.CreateCatalogFixture(
            imagePath,
            new CatalogFixtureSpec(16, [new CatalogPartitionSpec(
                "P",
                Volumes: [new CatalogVolumeSpec("Other"), new CatalogVolumeSpec("P")])]));
        var evidence = ObserverEvidenceJson.BuildSingleContainer(
            ContainerHexA,
            [new ObserverEvidenceJson.VolumeJson("SnapA", 201),
             new ObserverEvidenceJson.VolumeJson("SnapB", 202)], devicePath: imagePath);
        using var backend = CreateBackend(evidence, temp);
        await backend.ProbeVolumesAsync(imagePath, CancellationToken.None);

        Assert.True(backend.TryResolveCanonicalVolumeId($"{imagePath}|SnapA", out var canonical));
        Assert.Equal($"apfs-vol:{ContainerHexA}:201", canonical);

        // Name match is case-insensitive, mirroring legacy VolumeId semantics.
        Assert.True(backend.TryResolveCanonicalVolumeId($"{imagePath}|snapa", out _));

        // Zero matches => fail.
        Assert.False(backend.TryResolveCanonicalVolumeId($"{imagePath}|Missing", out _));
        // Unknown device => fail.
        Assert.False(backend.TryResolveCanonicalVolumeId(@"D:\nope.apfs.img|SnapA", out _));
        // Malformed => fail.
        Assert.False(backend.TryResolveCanonicalVolumeId("not-a-volume-id", out _));
    }

    [Fact]
    public async Task LegacyVolumeId_AmbiguousCachedName_FailsTranslation()
    {
        using var temp = DTempDirectory.Create("routing-ambiguous");
        var imagePath = Path.Combine(temp.Path, "ambiguous.apfs.img");
        SyntheticApfsTestImage.CreateCatalogFixture(
            imagePath,
            new CatalogFixtureSpec(16, [new CatalogPartitionSpec(
                "P", Volumes: [new CatalogVolumeSpec("Data")])]));
        var evidence = ObserverEvidenceJson.BuildSingleContainer(
            ContainerHexA,
            [new ObserverEvidenceJson.VolumeJson("Data", 201),
             new ObserverEvidenceJson.VolumeJson("Data", 202)], devicePath: imagePath);
        using var backend = CreateBackend(evidence, temp);
        var volumes = await backend.ProbeVolumesAsync(imagePath, CancellationToken.None);

        Assert.Equal(2, volumes.Count);
        Assert.False(backend.TryResolveCanonicalVolumeId($"{imagePath}|Data", out _));

        // ...but each canonical ID still routes directly.
        var first = await InvokeResolveVolumeAsync(backend, $"apfs-vol:{ContainerHexA}:201", CancellationToken.None);
        var second = await InvokeResolveVolumeAsync(backend, $"apfs-vol:{ContainerHexA}:202", CancellationToken.None);
        Assert.Equal($"apfs-vol:{ContainerHexA}:201", first?.VolumeId);
        Assert.Equal($"apfs-vol:{ContainerHexA}:202", second?.VolumeId);
    }

    [Fact]
    public async Task SameOidDifferentContainers_IndependentlyAddressable()
    {
        using var temp = DTempDirectory.Create("routing-sameoid");
        var imagePath = Path.Combine(temp.Path, "sameoid.apfs.img");
        SyntheticApfsTestImage.CreateCatalogFixture(
            imagePath,
            new CatalogFixtureSpec(16, [new CatalogPartitionSpec(
                "P", Volumes: [new CatalogVolumeSpec("Data")])]));
        var evidence = ObserverEvidenceJson.BuildContainers(
            [(ContainerHexA, [new ObserverEvidenceJson.VolumeJson("Data", 101)]),
             (ContainerHexB, [new ObserverEvidenceJson.VolumeJson("Data", 101)])], devicePath: imagePath);
        using var backend = CreateBackend(evidence, temp);

        var volumes = (await backend.ProbeVolumesAsync(imagePath, CancellationToken.None))
            .OrderBy(static volume => volume.VolumeId, StringComparer.Ordinal)
            .ToArray();

        Assert.Equal(2, volumes.Length);
        Assert.Equal($"apfs-vol:{ContainerHexA}:101", volumes[0].VolumeId);
        Assert.Equal($"apfs-vol:{ContainerHexB}:101", volumes[1].VolumeId);
        Assert.NotEqual(
            ReadMountTarget(backend, volumes[0]).RecoveryIdentity,
            ReadMountTarget(backend, volumes[1]).RecoveryIdentity);

        var resolvedA = await InvokeResolveVolumeAsync(backend, $"apfs-vol:{ContainerHexA}:101", CancellationToken.None);
        var resolvedB = await InvokeResolveVolumeAsync(backend, $"apfs-vol:{ContainerHexB}:101", CancellationToken.None);
        Assert.Equal(ContainerHexA, resolvedA?.CatalogContainerUuid);
        Assert.Equal(ContainerHexB, resolvedB?.CatalogContainerUuid);
    }

    [Fact]
    public async Task ResolveVolumeAsync_CanonicalRoundTrip_AndUnknownOidIsNull()
    {
        using var temp = DTempDirectory.Create("routing-roundtrip");
        var imagePath = Path.Combine(temp.Path, "roundtrip.apfs.img");
        SyntheticApfsTestImage.CreateCatalogFixture(
            imagePath,
            new CatalogFixtureSpec(16, [new CatalogPartitionSpec(
                "P", Volumes: [new CatalogVolumeSpec("Data")])]));
        var evidence = ObserverEvidenceJson.BuildSingleContainer(
            ContainerHexA, [new ObserverEvidenceJson.VolumeJson("SnapA", 201)], devicePath: imagePath);
        using var backend = CreateBackend(evidence, temp);
        var discovered = Assert.Single(
            await backend.ProbeVolumesAsync(imagePath, CancellationToken.None));

        var resolved = await InvokeResolveVolumeAsync(backend, discovered.VolumeId, CancellationToken.None);

        Assert.NotNull(resolved);
        Assert.Equal(discovered.VolumeId, resolved!.VolumeId);

        var unknown = await InvokeResolveVolumeAsync(
            backend, $"apfs-vol:{ContainerHexA}:999", CancellationToken.None);
        Assert.Null(unknown);
    }

    [Fact]
    public async Task ResolveVolumeAsync_LegacyName_TranslatesToCanonicalRow()
    {
        using var temp = DTempDirectory.Create("routing-legacyname");
        var imagePath = Path.Combine(temp.Path, "legacyname.apfs.img");
        SyntheticApfsTestImage.CreateCatalogFixture(
            imagePath,
            new CatalogFixtureSpec(16, [new CatalogPartitionSpec(
                "P", Volumes: [new CatalogVolumeSpec("Data")])]));
        var evidence = ObserverEvidenceJson.BuildSingleContainer(
            ContainerHexA, [new ObserverEvidenceJson.VolumeJson("SnapA", 201)], devicePath: imagePath);
        using var backend = CreateBackend(evidence, temp);

        var resolved = await InvokeResolveVolumeAsync(
            backend, $"{imagePath}|SnapA", CancellationToken.None);

        Assert.NotNull(resolved);
        Assert.Equal($"apfs-vol:{ContainerHexA}:201", resolved!.VolumeId);

        var missing = await InvokeResolveVolumeAsync(
            backend, $"{imagePath}|Nope", CancellationToken.None);
        Assert.Null(missing);
    }

    [Theory]
    [InlineData(201UL, ContainerHexA, new[] { "--volume", "Data", "--volume-oid", "201", "--container-id", ContainerHexA })]
    [InlineData(null, null, new[] { "--volume", "Data" })]
    [InlineData(202UL, null, new[] { "--volume", "Data", "--volume-oid", "202" })]
    [InlineData(0UL, ContainerHexA, new[] { "--volume", "Data", "--container-id", ContainerHexA })]
    public void AppendVolumeSelectorArguments_ContainerIdMatrix(
        ulong? oid, string? containerHex, string[] expected)
    {
        var psi = new ProcessStartInfo();
        NativeApfsBackend.AppendVolumeSelectorArguments(psi, "Data", oid, containerHex);

        Assert.Equal(expected, psi.ArgumentList);
    }

    private static NativeApfsBackend CreateBackend(string evidence, DTempDirectory temp)
    {
        var observerShim = Path.Combine(temp.Path, "ApfsObserver.exe");
        File.WriteAllBytes(observerShim, [0x4D, 0x5A]);
        return new NativeApfsBackend(
            new ServiceHostOptions { BackendMode = "Native", NativeAutoDiscoverPhysicalDrives = false },
            lifecycleTestHooks: null,
            observerRunner: new StubRunner(new ObserverRunResult(0, evidence, string.Empty)),
            observerPathOverride: observerShim);
    }

    private sealed class StubRunner(ObserverRunResult result) : IObserverRunner
    {
        public ObserverRunResult Run(string observerPath, IReadOnlyList<string> arguments) => result;
    }

    private static async Task<VolumeInfo?> InvokeResolveVolumeAsync(
        NativeApfsBackend backend, string volumeId, CancellationToken cancellationToken)
    {
        var method = typeof(NativeApfsBackend).GetMethod(
            "ResolveVolumeAsync", BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(method);
        var raw = method!.Invoke(backend, [volumeId, cancellationToken]);
        var task = Assert.IsAssignableFrom<Task<VolumeInfo?>>(raw);
        return await task;
    }

    private static (string? RecoveryIdentity, ulong? VolumeObjectId, string? ContainerUuidHex) ReadMountTarget(
        NativeApfsBackend backend, VolumeInfo volume)
    {
        var method = typeof(NativeApfsBackend).GetMethod(
            "ResolveMountTarget", BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(method);
        var target = method!.Invoke(backend, [volume]);
        Assert.NotNull(target);
        var targetType = target!.GetType();
        return (
            (string?)targetType.GetProperty("RecoveryIdentity")!.GetValue(target),
            (ulong?)targetType.GetProperty("VolumeObjectId")!.GetValue(target),
            (string?)targetType.GetProperty("ContainerUuidHex")!.GetValue(target));
    }
}
