using ApfsAccess.Core;

namespace ApfsAccess.Backend.Native.Tests;

// A4 single capability enforcement: with a catalog attachment, writability
// derives SOLELY from ApfsVolumeCapabilities.Evaluate. No write-gate flag,
// config, or override may re-enable it.
// RED first: CreateDiscoveredVolumeInfo still derives writability from legacy
// config-only inputs and WriteGatePolicy has no catalog check.
[Collection("ObserverPathEnv")]
public sealed class CatalogCapabilityEnforcementTests
{
    private const string ContainerHex = "a9cb92d28b7c4b599eab633c7625f491";

    private static ServiceHostOptions WritableConfig() => new()
    {
        BackendMode = "Native",
        NativeAutoDiscoverPhysicalDrives = false,
        EnableNativeWrite = true,
        WriteRolloutChannel = "Enabled",
        WriteBackendMode = "Native",
        // The override path: must NOT flip catalog-locked volumes writable.
        AllowWriteOnUnsupportedFeatures = true,
    };

    [Fact]
    public async Task CatalogLockedVolume_StaysNonWritableDespiteWritableConfigAndOverride()
    {
        using var temp = DTempDirectory.Create("cap-locked");
        var imagePath = Path.Combine(temp.Path, "locked.apfs.img");
        SyntheticApfsTestImage.CreateCatalogFixture(
            imagePath,
            new CatalogFixtureSpec(16, [new CatalogPartitionSpec(
                "P", Volumes: [new CatalogVolumeSpec("Data")])]));
        var evidence = ObserverEvidenceJson.BuildSingleContainer(
            ContainerHex,
            [new ObserverEvidenceJson.VolumeJson("Data", 201, EncryptionMode: "password", Locked: true)], devicePath: imagePath);
        using var backend = CreateBackend(evidence, temp, WritableConfig());

        var volume = Assert.Single(
            await backend.ProbeVolumesAsync(imagePath, CancellationToken.None));

        Assert.Equal(ApfsCapabilityDecision.Locked, volume.CatalogDecision);
        Assert.False(volume.SupportsReadWrite);
        Assert.False(volume.SupportsNativeWrite);
        Assert.True(volume.IsEncrypted);

        var gate = WriteGatePolicy.EvaluateForVolume(WritableConfig(), volume);
        Assert.False(gate.AllowWrite);
    }

    [Fact]
    public async Task CatalogUnsupportedVolume_StaysNonWritableWithOverride()
    {
        using var temp = DTempDirectory.Create("cap-unsupported");
        var imagePath = Path.Combine(temp.Path, "unsupported.apfs.img");
        SyntheticApfsTestImage.CreateCatalogFixture(
            imagePath,
            new CatalogFixtureSpec(16, [new CatalogPartitionSpec(
                "P", Volumes: [new CatalogVolumeSpec("Data")])]));
        var evidence = ObserverEvidenceJson.BuildSingleContainer(
            ContainerHex,
            [new ObserverEvidenceJson.VolumeJson("Data", 201, IncompatibleFeatures: 0x4)], devicePath: imagePath);
        using var backend = CreateBackend(evidence, temp, WritableConfig());

        var volume = Assert.Single(
            await backend.ProbeVolumesAsync(imagePath, CancellationToken.None));

        Assert.Equal(ApfsCapabilityDecision.Unsupported, volume.CatalogDecision);
        Assert.False(volume.SupportsReadWrite);
        Assert.False(volume.SupportsNativeWrite);
        Assert.False(WriteGatePolicy.EvaluateForVolume(WritableConfig(), volume).AllowWrite);
    }

    [Fact]
    public async Task CatalogReadOnlyFeatureVolume_StaysNonWritableWithOverride()
    {
        using var temp = DTempDirectory.Create("cap-rofeature");
        var imagePath = Path.Combine(temp.Path, "rofeature.apfs.img");
        SyntheticApfsTestImage.CreateCatalogFixture(
            imagePath,
            new CatalogFixtureSpec(16, [new CatalogPartitionSpec(
                "P", Volumes: [new CatalogVolumeSpec("Data")])]));
        var evidence = ObserverEvidenceJson.BuildSingleContainer(
            ContainerHex,
            [new ObserverEvidenceJson.VolumeJson("Data", 201, ReadonlyFeatures: 0x2)], devicePath: imagePath);
        using var backend = CreateBackend(evidence, temp, WritableConfig());

        var volume = Assert.Single(
            await backend.ProbeVolumesAsync(imagePath, CancellationToken.None));

        Assert.Equal(ApfsCapabilityDecision.ReadOnlyFeature, volume.CatalogDecision);
        Assert.False(volume.SupportsReadWrite);
        Assert.False(WriteGatePolicy.EvaluateForVolume(WritableConfig(), volume).AllowWrite);
    }

    [Fact]
    public async Task CatalogSpecialRoleVolume_StaysReadableNeverWritable()
    {
        using var temp = DTempDirectory.Create("cap-role");
        var imagePath = Path.Combine(temp.Path, "role.apfs.img");
        SyntheticApfsTestImage.CreateCatalogFixture(
            imagePath,
            new CatalogFixtureSpec(16, [new CatalogPartitionSpec(
                "P", Volumes: [new CatalogVolumeSpec("Data")])]));
        var evidence = ObserverEvidenceJson.BuildSingleContainer(
            ContainerHex,
            [new ObserverEvidenceJson.VolumeJson("Data", 201, Roles: ["system"])], devicePath: imagePath);
        using var backend = CreateBackend(evidence, temp, WritableConfig());

        var volume = Assert.Single(
            await backend.ProbeVolumesAsync(imagePath, CancellationToken.None));

        Assert.Equal(ApfsCapabilityDecision.Readable, volume.CatalogDecision);
        Assert.False(volume.CatalogAutoMountAllowed);
        Assert.False(volume.SupportsReadWrite);
        Assert.False(WriteGatePolicy.EvaluateForVolume(WritableConfig(), volume).AllowWrite);
    }

    [Fact]
    public async Task CatalogWritableVolume_RespectsWritableConfig()
    {
        using var temp = DTempDirectory.Create("cap-writable");
        var imagePath = Path.Combine(temp.Path, "writable.apfs.img");
        SyntheticApfsTestImage.CreateCatalogFixture(
            imagePath,
            new CatalogFixtureSpec(16, [new CatalogPartitionSpec(
                "P", Volumes: [new CatalogVolumeSpec("Data")])]));
        var evidence = ObserverEvidenceJson.BuildSingleContainer(
            ContainerHex, [new ObserverEvidenceJson.VolumeJson("Data", 201)], devicePath: imagePath);
        using var backend = CreateBackend(evidence, temp, WritableConfig());

        var volume = Assert.Single(
            await backend.ProbeVolumesAsync(imagePath, CancellationToken.None));

        // Positive control: the catalog gate clamps but never forces; a
        // writable catalog decision with a writable config stays writable.
        Assert.Equal(ApfsCapabilityDecision.Writable, volume.CatalogDecision);
        Assert.True(volume.SupportsReadWrite);
        Assert.True(volume.SupportsNativeWrite);
        Assert.True(WriteGatePolicy.EvaluateForVolume(WritableConfig(), volume).AllowWrite);
    }

    [Fact]
    public async Task OverrideSourcedEvidence_CapsWritableDecisionToReadable()
    {
        // End-to-end provenance: the constructor test seam counts as packaged
        // (trusted), but an env-var-resolved observer is override-sourced, so
        // its Writable decision must cap at Readable with the
        // untrusted-observer-source reason.
        using var temp = DTempDirectory.Create("cap-provenance");
        var imagePath = Path.Combine(temp.Path, "provenance.apfs.img");
        SyntheticApfsTestImage.CreateCatalogFixture(
            imagePath,
            new CatalogFixtureSpec(16, [new CatalogPartitionSpec(
                "P", Volumes: [new CatalogVolumeSpec("Data")])]));
        var evidence = ObserverEvidenceJson.BuildSingleContainer(
            ContainerHex, [new ObserverEvidenceJson.VolumeJson("Data", 201)], devicePath: imagePath);
        var observerShim = Path.Combine(temp.Path, "ApfsObserver.exe");
        File.WriteAllBytes(observerShim, [0x4D, 0x5A]);
        var previous = Environment.GetEnvironmentVariable(NativeApfsObserver.PathOverrideVariable);
        try
        {
            Environment.SetEnvironmentVariable(NativeApfsObserver.PathOverrideVariable, observerShim);
            using var backend = new NativeApfsBackend(
                WritableConfig(),
                lifecycleTestHooks: null,
                observerRunner: new StubRunner(new ObserverRunResult(0, evidence, string.Empty)),
                observerPathOverride: null);

            var volume = Assert.Single(
                await backend.ProbeVolumesAsync(imagePath, CancellationToken.None));

            Assert.Equal(ApfsCapabilityDecision.Readable, volume.CatalogDecision);
            Assert.Contains(
                NativeApfsObserver.UntrustedObserverSourceReason,
                volume.CatalogReasons ?? []);
            Assert.False(volume.CatalogAutoMountAllowed);
            Assert.False(volume.SupportsReadWrite);
        }
        finally
        {
            Environment.SetEnvironmentVariable(NativeApfsObserver.PathOverrideVariable, previous);
        }
    }

    private static NativeApfsBackend CreateBackend(
        string evidence, DTempDirectory temp, ServiceHostOptions options)
    {
        // Packaged staging keeps the Writable positive control truthful; the
        // non-writable decisions asserted elsewhere are unaffected by trust.
        var stagedObserver = StagedPackagedObserver.StageStable("cap");
        return new NativeApfsBackend(
            options,
            lifecycleTestHooks: null,
            observerRunner: new StubRunner(new ObserverRunResult(0, evidence, string.Empty)),
            observerPathOverride: stagedObserver);
    }

    [Fact]
    public async Task DirectOverrideEvidence_CapsWritableDecisionToReadable()
    {
        // A10: a constructor-seam override outside the packaged tree is a
        // development override like any other — its Writable decision must
        // cap at Readable and never authorize RW.
        using var temp = DTempDirectory.Create("cap-direct-override");
        var imagePath = Path.Combine(temp.Path, "override.apfs.img");
        SyntheticApfsTestImage.CreateCatalogFixture(
            imagePath,
            new CatalogFixtureSpec(16, [new CatalogPartitionSpec(
                "P", Volumes: [new CatalogVolumeSpec("Data")])]));
        var evidence = ObserverEvidenceJson.BuildSingleContainer(
            ContainerHex, [new ObserverEvidenceJson.VolumeJson("Data", 201)], devicePath: imagePath);
        // Deliberately NOT the staged helper: this override lives outside the
        // packaged tree, so provenance must cap it.
        var observerShim = Path.Combine(temp.Path, "ApfsObserver.exe");
        File.WriteAllBytes(observerShim, [0x4D, 0x5A]);
        using var backend = new NativeApfsBackend(
            WritableConfig(),
            lifecycleTestHooks: null,
            observerRunner: new StubRunner(new ObserverRunResult(0, evidence, string.Empty)),
            observerPathOverride: observerShim);

        var volume = Assert.Single(
            await backend.ProbeVolumesAsync(imagePath, CancellationToken.None));

        Assert.Equal(ApfsCapabilityDecision.Readable, volume.CatalogDecision);
        Assert.Contains(
            NativeApfsObserver.UntrustedObserverSourceReason,
            volume.CatalogReasons ?? []);
        Assert.False(volume.SupportsReadWrite);
    }

    private sealed class StubRunner(ObserverRunResult result) : IObserverRunner
    {
        public ObserverRunResult Run(string observerPath, IReadOnlyList<string> arguments) => result;
    }
}
