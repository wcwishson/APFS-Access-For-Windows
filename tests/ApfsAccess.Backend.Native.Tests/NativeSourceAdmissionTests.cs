using System.Reflection;
using System.Text.Json;
using ApfsAccess.Core;

namespace ApfsAccess.Backend.Native.Tests;

[Collection("ObserverPathEnv")]
public sealed class NativeSourceAdmissionTests
{
    private static ServiceHostOptions Options() => new()
    {
        BackendMode = "Native",
        EnableNativeWrite = true,
        WriteBackendMode = "Native",
        WriteRolloutChannel = "Enabled",
        AllowWriteOnUnsupportedFeatures = true,
        NativeWriteAllowRawPhysicalDevices = true,
        NativeWritePromotionPolicy = "Stable",
        NativeAutoDiscoverPhysicalDrives = false,
    };

    [Theory]
    [InlineData(@"\\.\PhysicalDrive1", @"\\.\PhysicalDrive1", true)]
    [InlineData(@"\\?\PhysicalDrive1", @"\\.\PhysicalDrive1", true)]
    [InlineData(@"\\.\PhysicalDrive1", @"\\?\PhysicalDrive1", true)]
    [InlineData(@"\\.\PhysicalDrive10", @"\\.\PhysicalDrive1", false)]
    [InlineData(@"\\.\PhysicalDrive12", @"\\.\PhysicalDrive1", false)]
    [InlineData(@"\\?\PhysicalDrive12", @"\\.\PhysicalDrive1", false)]
    [InlineData(@"\\.\PhysicalDrive1", "PhysicalDrive", false)]
    public void RawDriveAllowListRequiresTheExactDevice(string source, string allowed, bool expected)
    {
        var options = RawPilotOptions(true, [allowed]);

        Assert.Equal(expected, NativeWriteSourceAdmission.IsAllowListedRawDrive(source, options));
    }

    [Theory]
    [InlineData(@"\\.\PhysicalDrive999")]
    [InlineData(@"\\?\PhysicalDrive999")]
    [InlineData(@"\\.\Harddisk999Partition1")]
    [InlineData(@"\\?\GLOBALROOT\Device\Harddisk999\DR999")]
    [InlineData(@"\\.\pipe\apfs-never-connect")]
    [InlineData(@"NUL")]
    [InlineData(@"D:\NUL.img")]
    public void UnverifiedSource_CannotBePromotedByConfigurationOrOverride(string source)
    {
        var options = Options();
        using var backend = new NativeApfsBackend(options);
        AssertBlocked(BuildLegacyVolume(backend, source), options);
    }

    [Fact]
    public void MissingFileAndDirectory_AreNotWritableImages()
    {
        using var temp = DTempDirectory.Create("admission-missing");
        var options = Options();
        using var backend = new NativeApfsBackend(options);
        AssertBlocked(BuildLegacyVolume(backend, Path.Combine(temp.Path, "absent.img")), options);
        AssertBlocked(BuildLegacyVolume(backend, temp.Path), options);
    }

    [Fact]
    public void RegularLocalFile_RemainsEligible_RegardlessOfExtension()
    {
        using var temp = DTempDirectory.Create("admission-file");
        var path = Path.Combine(temp.Path, "volume.bin");
        File.WriteAllBytes(path, [1, 2, 3]);
        var options = Options();
        using var backend = new NativeApfsBackend(options);
        foreach (var source in new[] { path, @"\\?\" + path })
        {
            var volume = BuildLegacyVolume(backend, source);
            Assert.True(volume.SupportsNativeWrite);
            Assert.True(volume.SupportsReadWrite);
            Assert.True(WriteGatePolicy.EvaluateForVolume(options, volume).AllowWrite);
        }
        Assert.Equal(new byte[] { 1, 2, 3 }, File.ReadAllBytes(path));
    }

    [Fact]
    public void SourceAdmission_IsRecheckedForCachedPolicyInput()
    {
        using var temp = DTempDirectory.Create("admission-cached");
        var path = Path.Combine(temp.Path, "volume.bin");
        File.WriteAllBytes(path, [1]);
        var options = Options();
        using var backend = new NativeApfsBackend(options);
        var volume = BuildLegacyVolume(backend, path);
        Assert.True(volume.SupportsNativeWrite);
        File.Delete(path);
        var method = typeof(NativeApfsBackend).GetMethod("EvaluateWriteGateDecision",
            BindingFlags.Instance | BindingFlags.NonPublic)!;
        var gate = Assert.IsType<WriteGateDecision>(method.Invoke(backend, [volume]));
        Assert.False(gate.AllowWrite);
        Assert.Equal("NativeSourceAdmissionBlocked", gate.GateState);
    }

    [Fact]
    public void ReparsePointAndAlternateStream_AreNotAdmittedAsImages()
    {
        using var temp = DTempDirectory.Create("admission-reparse");
        var path = Path.Combine(temp.Path, "volume.bin");
        var alias = Path.Combine(temp.Path, "alias.img");
        File.WriteAllBytes(path, [1]);
        File.CreateSymbolicLink(alias, path);
        File.WriteAllBytes(path + ":alternate", [2]);
        using var backend = new NativeApfsBackend(Options());
        AssertBlocked(BuildLegacyVolume(backend, alias), Options());
        AssertBlocked(BuildLegacyVolume(backend, path + ":alternate"), Options());
    }

    [Fact]
    public async Task ReadOnlyImage_KeepsWritableFormatDecision_ButBlocksEffectiveWrite()
    {
        using var temp = DTempDirectory.Create("admission-readonly");
        var path = Path.Combine(temp.Path, "volume.apfs.img");
        SyntheticApfsTestImage.CreateCatalogFixture(path,
            new CatalogFixtureSpec(16, [new CatalogPartitionSpec(
                "P", Volumes: [new CatalogVolumeSpec("Data")])]));
        var evidence = ObserverEvidenceJson.BuildSingleContainer(
            "a9cb92d28b7c4b599eab633c7625f491",
            [new ObserverEvidenceJson.VolumeJson("Data", 201)], devicePath: path);
        var options = Options();
        using var backend = new NativeApfsBackend(options, lifecycleTestHooks: null,
            observerRunner: new StubRunner(evidence),
            observerPathOverride: StagedPackagedObserver.StageStable("admission"));
        var originalAttributes = File.GetAttributes(path);
        try
        {
            File.SetAttributes(path, originalAttributes | FileAttributes.ReadOnly);
            var volume = Assert.Single(await backend.ProbeVolumesAsync(path, CancellationToken.None));
            Assert.Equal(ApfsCapabilityDecision.Writable, volume.CatalogDecision);
            AssertBlocked(volume, options);
            var copy = JsonSerializer.Deserialize<VolumeInfo>(JsonSerializer.Serialize(volume));
            AssertBlocked(Assert.IsType<VolumeInfo>(copy), options);
        }
        finally
        {
            File.SetAttributes(path, originalAttributes);
        }
        var refreshed = Assert.Single(await backend.ProbeVolumesAsync(path, CancellationToken.None));
        Assert.True(refreshed.SupportsNativeWrite);
        Assert.True(WriteGatePolicy.EvaluateForVolume(options, refreshed).AllowWrite);
    }

    [Theory]
    [InlineData(@"\\.\PhysicalDrive2", true, true)]
    [InlineData(@"\\?\PhysicalDrive2", true, true)]
    [InlineData(@"\\.\PHYSICALDRIVE2", true, true)]
    [InlineData(@"\\.\PhysicalDrive2", false, false)]
    [InlineData(@"\\.\PhysicalDrive999", false, true)]
    [InlineData(@"\\.\Harddisk2Partition1", false, true)]
    [InlineData(@"\\.\PhysicalDrive2x", false, true)]
    [InlineData(@"\\.\PhysicalDrive", false, true)]
    [InlineData(@"D:\volume.img", false, true)]
    public void IsAllowListedRawDrive_MatchesSpellingAndPilotAllowList(
        string source, bool expected, bool allowRaw)
    {
        var options = RawPilotOptions(allowRaw, [@"\\.\PhysicalDrive2"]);
        Assert.Equal(expected, NativeWriteSourceAdmission.IsAllowListedRawDrive(source, options));
        Assert.False(NativeWriteSourceAdmission.IsAllowListedRawDrive(source, null));
        Assert.False(NativeWriteSourceAdmission.IsAllowListedRawDrive(
            source, RawPilotOptions(true, [])));
    }

    [Fact]
    public void AllowListedButAbsent_RawDrive_StaysBlockedOnHandleProof()
    {
        var options = RawPilotOptions(true, [@"\\.\PhysicalDrive999"]);
        using var backend = new NativeApfsBackend(options);
        Assert.True(NativeWriteSourceAdmission.IsAllowListedRawDrive(@"\\.\PhysicalDrive999", options));
        AssertBlocked(BuildLegacyVolume(backend, @"\\.\PhysicalDrive999"), options);
    }

    [SacrificialRawFact]
    public void SacrificialRawDrive_AllowListed_AdmitsAtSpellingLayer()
    {
        // Hardware-gated pilot pin: runs only when the operator explicitly
        // opts in with the sacrificial device present. It proves the spelling
        // + allow-list + disk-handle proof chain end to end on real media;
        // downstream gates (catalog, evidence, readiness) still decide writes.
        var options = RawPilotOptions(true, [@"\\.\PhysicalDrive2"]);
        Assert.Null(NativeWriteSourceAdmission.GetBlockReason(@"\\.\PhysicalDrive2", options));
    }

    private static ServiceHostOptions RawPilotOptions(bool allowRaw, string[] allowList) => new()
    {
        BackendMode = "Native",
        EnableNativeWrite = true,
        WriteBackendMode = "Native",
        WriteRolloutChannel = "Enabled",
        AllowWriteOnUnsupportedFeatures = true,
        NativeWriteAllowRawPhysicalDevices = allowRaw,
        NativeWriteHardwarePilotDeviceAllowList = allowList,
        NativeWritePromotionPolicy = "Stable",
        NativeAutoDiscoverPhysicalDrives = false,
    };

    private static VolumeInfo BuildLegacyVolume(NativeApfsBackend backend, string source)
    {
        var method = typeof(NativeApfsBackend).GetMethod("TryBuildVolumeFromId",
            BindingFlags.Instance | BindingFlags.NonPublic)!;
        object?[] arguments = [source + "|Data", null];
        Assert.True((bool)method.Invoke(backend, arguments)!);
        return Assert.IsType<VolumeInfo>(arguments[1]);
    }

    private static void AssertBlocked(VolumeInfo volume, ServiceHostOptions options)
    {
        Assert.False(volume.SupportsNativeWrite);
        Assert.False(volume.SupportsReadWrite);
        Assert.Equal(NativeWriteReadiness.Unavailable, volume.NativeWriteReadiness);
        Assert.False(string.IsNullOrWhiteSpace(volume.WriteBlockReason));
        var decision = WriteGatePolicy.EvaluateForVolume(options, volume);
        Assert.False(decision.AllowWrite);
        Assert.Equal("NativeSourceAdmissionBlocked", decision.GateState);
    }

    private sealed class StubRunner(string evidence) : IObserverRunner
    {
        public ObserverRunResult Run(string observerPath, IReadOnlyList<string> arguments)
            => new(0, evidence, string.Empty);
    }

    private sealed class SacrificialRawFactAttribute : FactAttribute
    {
        public SacrificialRawFactAttribute()
        {
            if (!string.Equals(Environment.GetEnvironmentVariable("APFSACCESS_ALLOW_SACRIFICIAL_RAW"), "1", StringComparison.Ordinal))
                Skip = "Requires an explicitly approved sacrificial physical drive.";
        }
    }
}
