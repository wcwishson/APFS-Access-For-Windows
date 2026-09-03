using System.Diagnostics;
using System.Reflection;
using ApfsAccess.Core;

namespace ApfsAccess.Backend.Native.Tests;

public sealed class ObserverTopologyDiscoveryTests
{
    private const string ContainerHex = "a9cb92d28b7c4b599eab633c7625f491";

    [Fact]
    public void ObserverArguments_UseImageCollectVectorWithDeviceSlug()
    {
        var args = NativeApfsObserver.BuildObserverArguments(
            @"D:\images\single.apfs.img", "managed-discovery", "single.apfs.img");

        Assert.Equal(
            ["--image", @"D:\images\single.apfs.img", "--profile", "managed-discovery",
             "--mode", "collect", "--device-id", "single.apfs.img"],
            args);
    }

    [Fact]
    public void ObserverArguments_UseDeviceFlagForRawPhysicalPaths()
    {
        var args = NativeApfsObserver.BuildObserverArguments(
            @"\\.\PhysicalDrive2", "managed-discovery", "PhysicalDrive2");

        Assert.Equal("--device", args[0]);
        Assert.Equal(@"\\.\PhysicalDrive2", args[1]);
        Assert.Contains("--device-id", args);
        Assert.Contains("PhysicalDrive2", args);
    }

    [Fact]
    public void BuildDeviceSlug_MirrorsNativeSlugFallbackRules()
    {
        Assert.Equal("single.apfs.img", NativeApfsObserver.BuildDeviceSlug(@"D:\images\single.apfs.img"));
        Assert.Equal("PhysicalDrive2", NativeApfsObserver.BuildDeviceSlug(@"\\.\PhysicalDrive2"));
        Assert.Equal("my-image-", NativeApfsObserver.BuildDeviceSlug("my image!"));
        Assert.Equal("device", NativeApfsObserver.BuildDeviceSlug("!!!"));
    }

    [Fact]
    public void TryDiscoverTopologySnapshot_InvokesConfiguredObserverWithExpectedVector()
    {
        using var temp = DTempDirectory.Create("observer-invoke");
        var observerShim = Path.Combine(temp.Path, "ApfsObserver.exe");
        File.WriteAllBytes(observerShim, [0x4D, 0x5A]);
        var imagePath = Path.Combine(temp.Path, "single.apfs.img");
        File.WriteAllBytes(imagePath, new byte[4096]);
        var evidence = ObserverEvidenceJson.BuildSingleContainer(
            ContainerHex, [new ObserverEvidenceJson.VolumeJson("Data", 101)]);
        var runner = new CapturingRunner(new ObserverRunResult(0, evidence, string.Empty));
        using var backend = new NativeApfsBackend(
            new ServiceHostOptions { BackendMode = "Native", NativeAutoDiscoverPhysicalDrives = false },
            lifecycleTestHooks: null,
            observerRunner: runner,
            observerPathOverride: observerShim);

        var snapshot = backend.TryDiscoverTopologySnapshot(imagePath, "managed-discovery");

        Assert.NotNull(snapshot);
        Assert.Equal(observerShim, runner.LastObserverPath);
        Assert.Equal(
            ["--image", imagePath, "--profile", "managed-discovery",
             "--mode", "collect", "--device-id", "single.apfs.img"],
            runner.LastArguments);
        var volume = Assert.Single(snapshot!.Volumes);
        Assert.Equal("Data", volume.Name);
        Assert.Equal("101", volume.ObjectId);
    }

    [Theory]
    [InlineData(2, "{\"incomplete\":", "error: ambiguous identities")]
    [InlineData(0, "", "")]
    [InlineData(0, "   ", "")]
    [InlineData(0, "{not json", "")]
    public void TryDiscoverTopologySnapshot_FailsClosedToNull(
        int exitCode, string stdout, string stderr)
    {
        using var temp = DTempDirectory.Create("observer-failclosed");
        var observerShim = Path.Combine(temp.Path, "ApfsObserver.exe");
        File.WriteAllBytes(observerShim, [0x4D, 0x5A]);
        var runner = new CapturingRunner(new ObserverRunResult(exitCode, stdout, stderr));
        using var backend = new NativeApfsBackend(
            new ServiceHostOptions(),
            lifecycleTestHooks: null,
            observerRunner: runner,
            observerPathOverride: observerShim);

        Assert.Null(backend.TryDiscoverTopologySnapshot(@"D:\images\single.apfs.img", "managed-discovery"));
    }

    [Fact]
    public void TryDiscoverTopologySnapshot_RejectsEnvelopeMismatchAndSynthetic()
    {
        using var temp = DTempDirectory.Create("observer-envelope");
        var observerShim = Path.Combine(temp.Path, "ApfsObserver.exe");
        File.WriteAllBytes(observerShim, [0x4D, 0x5A]);
        var valid = ObserverEvidenceJson.BuildSingleContainer(
            ContainerHex, [new ObserverEvidenceJson.VolumeJson("Data", 101)]);
        var tampered = valid.Replace(
            "\"format\":\"apfs-access-raw-evidence\"", "\"format\":\"something-else\"");
        var synthetic = valid.Replace("\"synthetic\":false", "\"synthetic\":true");
        using var backend = new NativeApfsBackend(
            new ServiceHostOptions(),
            lifecycleTestHooks: null,
            observerRunner: new ScriptedRunner([tampered, synthetic]),
            observerPathOverride: observerShim);

        Assert.Null(backend.TryDiscoverTopologySnapshot(@"D:\x.img", "p"));
        Assert.Null(backend.TryDiscoverTopologySnapshot(@"D:\x.img", "p"));
    }

    [Fact]
    public void TryDiscoverTopologySnapshot_RejectsEvidenceMissingSecondarySources()
    {
        using var temp = DTempDirectory.Create("observer-no-secondary");
        var observerShim = Path.Combine(temp.Path, "ApfsObserver.exe");
        File.WriteAllBytes(observerShim, [0x4D, 0x5A]);
        var valid = ObserverEvidenceJson.BuildSingleContainer(
            ContainerHex, [new ObserverEvidenceJson.VolumeJson("Data", 101)]);
        var withoutSecondary = valid.Replace(",\"secondarySources\":[]", string.Empty, StringComparison.Ordinal);
        Assert.DoesNotContain("secondarySources", withoutSecondary, StringComparison.Ordinal);
        using var backend = new NativeApfsBackend(
            new ServiceHostOptions(),
            lifecycleTestHooks: null,
            observerRunner: new CapturingRunner(new ObserverRunResult(0, withoutSecondary, string.Empty)),
            observerPathOverride: observerShim);

        // Freeze v1.1: secondarySources is REQUIRED top-level; absent => fail closed.
        Assert.Null(backend.TryDiscoverTopologySnapshot(@"D:\x.img", "p"));
    }

    [Fact]
    public void TryDiscoverTopologySnapshot_ReturnsNullWhenObserverIsAbsent()
    {
        using var backend = new NativeApfsBackend(
            new ServiceHostOptions(),
            lifecycleTestHooks: null,
            observerRunner: new CapturingRunner(new ObserverRunResult(0, "{}", string.Empty)),
            observerPathOverride: null);

        Assert.Null(backend.TryDiscoverTopologySnapshot(@"D:\images\single.apfs.img", "managed-discovery"));
    }

    [Fact]
    public void RunObserverEvidenceOrThrow_SurfacesStderrInException()
    {
        using var temp = DTempDirectory.Create("observer-stderr");
        var observerShim = Path.Combine(temp.Path, "ApfsObserver.exe");
        File.WriteAllBytes(observerShim, [0x4D, 0x5A]);
        var runner = new CapturingRunner(new ObserverRunResult(2, string.Empty, "error: ambiguous identities"));
        using var backend = new NativeApfsBackend(
            new ServiceHostOptions(),
            lifecycleTestHooks: null,
            observerRunner: runner,
            observerPathOverride: observerShim);

        var exception = Assert.Throws<InvalidOperationException>(
            () => backend.RunObserverEvidenceOrThrow(@"D:\images\single.apfs.img", "managed-discovery"));
        Assert.Contains("error: ambiguous identities", exception.Message);
    }

    [Fact]
    public void VolumeMountTarget_KeepsLegacyPositionalConstructionWithNullCatalogDefaults()
    {
        var targetType = typeof(NativeApfsBackend).GetNestedType(
            "VolumeMountTarget", BindingFlags.NonPublic);
        Assert.NotNull(targetType);

        var constructors = targetType!.GetConstructors(
            BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
        var legacy = Assert.Single(
            constructors, static ctor => ctor.GetParameters().Length == 3);

        var target = legacy.Invoke(["dev", 0UL, "rec"]);
        Assert.Null(targetType.GetProperty("VolumeObjectId")!.GetValue(target));
        Assert.Null(targetType.GetProperty("ContainerUuidHex")!.GetValue(target));
        Assert.Equal("dev", targetType.GetProperty("DevicePath")!.GetValue(target));
        Assert.Equal("rec", targetType.GetProperty("RecoveryIdentity")!.GetValue(target));
    }

    [Fact]
    public void AppendVolumeSelectorArguments_OmitsOidWhenUnset()
    {
        var psi = new ProcessStartInfo();
        NativeApfsBackend.AppendVolumeSelectorArguments(psi, "Data", null);

        Assert.Equal(["--volume", "Data"], psi.ArgumentList);
    }

    [Fact]
    public void AppendVolumeSelectorArguments_EmitsVolumeOidWhenSet()
    {
        var psi = new ProcessStartInfo();
        NativeApfsBackend.AppendVolumeSelectorArguments(psi, "Data", 101UL);

        Assert.Equal(["--volume", "Data", "--volume-oid", "101"], psi.ArgumentList);
    }

    [Fact]
    public void AppendVolumeSelectorArguments_OmitsZeroOid()
    {
        var psi = new ProcessStartInfo();
        NativeApfsBackend.AppendVolumeSelectorArguments(psi, "Data", 0UL);

        Assert.Equal(["--volume", "Data"], psi.ArgumentList);
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

    private sealed class ScriptedRunner(IReadOnlyList<string> outputs) : IObserverRunner
    {
        private int _index;

        public ObserverRunResult Run(string observerPath, IReadOnlyList<string> arguments)
            => new(0, outputs[Math.Min(_index++, outputs.Count - 1)], string.Empty);
    }
}
