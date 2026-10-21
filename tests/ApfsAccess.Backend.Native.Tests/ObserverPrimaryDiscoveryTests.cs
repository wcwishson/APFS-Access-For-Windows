using System.Reflection;
using System.Text.Json;
using ApfsAccess.Core;

namespace ApfsAccess.Backend.Native.Tests;

// A2 observer-primary discovery: one row per snapshot volume (never sized
// from legacy); legacy consulted only for mount-path affordances; missing
// binary => byte-identical legacy; failed snapshot + binary present => raw
// devices fail closed (empty + diagnostic), image paths keep legacy fallback.
// RED first: TryGetLastDiscoveryDiagnostic does not exist yet, and rows are
// still legacy-sized while a snapshot is present.
public sealed class ObserverPrimaryDiscoveryTests
{
    [Fact]
    public async Task SnapshotPresent_RowsSizedFromSnapshotWithCanonicalIds()
    {
        using var temp = DTempDirectory.Create("primary-rows");
        var imagePath = Path.Combine(temp.Path, "primary.apfs.img");
        var fixture = SyntheticApfsTestImage.CreateCatalogFixture(
            imagePath,
            new CatalogFixtureSpec(16, [new CatalogPartitionSpec(
                "LegacyName",
                Volumes: [new CatalogVolumeSpec("Data")])]));
        var partition = Assert.Single(fixture.Partitions);
        var containerHex = ContainerHexOf(partition.ContainerUuid);
        // Snapshot disagrees with legacy on purpose: different names, oids,
        // and TWO volumes where legacy sees one partition row.
        var evidence = ObserverEvidenceJson.BuildSingleContainer(
            containerHex,
            [new ObserverEvidenceJson.VolumeJson("SnapA", 201),
             new ObserverEvidenceJson.VolumeJson("SnapB", 202)], devicePath: imagePath);
        using var backend = CreateBackend(evidence, temp);

        var volumes = (await backend.ProbeVolumesAsync(imagePath, CancellationToken.None))
            .OrderBy(static volume => volume.VolumeName, StringComparer.Ordinal)
            .ToArray();

        Assert.Equal(2, volumes.Length);
        Assert.DoesNotContain(volumes, static volume => volume.VolumeName == "LegacyName");
        Assert.Equal($"apfs-vol:{containerHex}:201", volumes[0].VolumeId);
        Assert.Equal($"apfs-vol:{containerHex}:202", volumes[1].VolumeId);
        Assert.Equal("SnapA", volumes[0].VolumeName);
        Assert.Equal("SnapB", volumes[1].VolumeName);
        Assert.Equal(imagePath, volumes[0].DeviceId);
        Assert.Equal(containerHex, volumes[0].CatalogContainerUuid);
        Assert.Equal(201UL, volumes[0].CatalogVolumeObjectId);
        Assert.Equal($"apfs-vol:{containerHex}:201", volumes[0].CatalogVolumeId);
        Assert.Equal(ApfsCapabilityDecision.Writable, volumes[0].CatalogDecision);
        // Legacy affordances: mount paths and device offsets still come from
        // the GPT/superblock parse, matched by container UUID.
        Assert.Equal(
            $@"{imagePath}\ApfsAccess_Volumes\SnapA",
            volumes[0].NativeVolumePath);
        Assert.Equal((ulong)partition.StartByte, ReadMountTarget(backend, volumes[0]).OffsetBytes);
        // Recovery identity binds the container UUID + SELECTED (snapshot)
        // OID, not the legacy first-observed OID.
        var expectedIdentity = BuildRecoveryIdentity(
            partition.PartitionUuid,
            Convert.ToHexString(partition.ContainerUuid.ToByteArray()),
            201UL,
            allowPartitionlessIdentity: false);
        Assert.Equal(expectedIdentity, ReadMountTarget(backend, volumes[0]).RecoveryIdentity);
        Assert.False(backend.TryGetLastDiscoveryDiagnostic(imagePath, out _));
    }

    [Fact]
    public async Task ObserverBinaryMissing_ByteIdenticalLegacy()
    {
        using var temp = DTempDirectory.Create("primary-missing");
        var imagePath = Path.Combine(temp.Path, "legacy.apfs.img");
        SyntheticApfsTestImage.Create(imagePath, sizeMiB: 4);
        var runner = new StubRunner(new ObserverRunResult(2, string.Empty, "no observer"));
        using var backend = new NativeApfsBackend(
            new ServiceHostOptions { BackendMode = "Native", NativeAutoDiscoverPhysicalDrives = false },
            lifecycleTestHooks: null,
            observerRunner: runner,
            observerPathOverride: Path.Combine(temp.Path, "does-not-exist.exe"));

        var volume = Assert.Single(
            await backend.ProbeVolumesAsync(imagePath, CancellationToken.None));

        Assert.Equal($"{imagePath}|Main", volume.VolumeId);
        Assert.Equal("Main", volume.VolumeName);
        Assert.Null(volume.CatalogVolumeId);
        Assert.Null(volume.CatalogContainerUuid);
        Assert.Null(volume.CatalogVolumeObjectId);
        Assert.Null(volume.CatalogDecision);
        Assert.Equal(0, runner.CallCount);
        Assert.False(backend.TryGetLastDiscoveryDiagnostic(imagePath, out _));
    }

    [Fact]
    public async Task SnapshotFailed_RawPhysical_FailsClosedEmptyWithDiagnostic()
    {
        using var temp = DTempDirectory.Create("primary-rawfail");
        var runner = new StubRunner(new ObserverRunResult(2, string.Empty, "catalog unreadable"));
        using var backend = CreateBackendWithRunner(runner, temp);
        const string deviceId = @"\\.\PhysicalDrive31";

        var volumes = await backend.ProbeVolumesAsync(deviceId, CancellationToken.None);

        Assert.Empty(volumes);
        Assert.Equal("--device", runner.LastArguments?[0]);
        Assert.True(backend.TryGetLastDiscoveryDiagnostic(deviceId, out var diagnostic));
        Assert.False(string.IsNullOrWhiteSpace(diagnostic));
        Assert.Contains("failing closed", diagnostic, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task SnapshotFailed_ImagePath_FallsBackToLegacy()
    {
        using var temp = DTempDirectory.Create("primary-imgfallback");
        var imagePath = Path.Combine(temp.Path, "fallback.apfs.img");
        SyntheticApfsTestImage.Create(imagePath, sizeMiB: 4);
        var runner = new StubRunner(new ObserverRunResult(2, string.Empty, "catalog unreadable"));
        using var backend = CreateBackendWithRunner(runner, temp);

        var volume = Assert.Single(
            await backend.ProbeVolumesAsync(imagePath, CancellationToken.None));

        Assert.Equal($"{imagePath}|Main", volume.VolumeId);
        Assert.Equal("--image", runner.LastArguments?[0]);
        Assert.False(backend.TryGetLastDiscoveryDiagnostic(imagePath, out _));
    }

    [Fact]
    public async Task RawDiscoveryFailure_EvidenceSurvivesRecoveryAndDeduplicatesRepeatedFailure()
    {
        using var temp = DTempDirectory.Create("primary-failure-evidence");
        const string deviceId = @"\\.\PhysicalDrive31";
        var runner = new StubRunner(new ObserverRunResult(5, string.Empty, "error: checkpoint read refused"));
        using var backend = CreateBackendWithRunner(runner, temp);
        typeof(NativeApfsBackend).GetField("_writeDiagnosticsRoot", BindingFlags.Instance | BindingFlags.NonPublic)!
            .SetValue(backend, temp.Path);

        Assert.Empty(await backend.ProbeVolumesAsync(deviceId, CancellationToken.None));
        Assert.Empty(await backend.ProbeVolumesAsync(deviceId, CancellationToken.None));
        var evidencePath = Assert.Single(Directory.GetFiles(temp.Path, "backend-observer-discovery-failed-*.json"));
        using var evidence = JsonDocument.Parse(await File.ReadAllTextAsync(evidencePath));
        var detail = evidence.RootElement.GetProperty("detail").GetString()!;
        Assert.Contains(deviceId, detail);
        Assert.Contains("managed-discovery", detail);
        Assert.Contains("exit code 5", detail);
        Assert.Contains("error: checkpoint read refused", detail);
        Assert.Contains("failing closed", detail);
        Assert.Equal(Environment.ProcessId, evidence.RootElement.GetProperty("processId").GetInt32());
        Assert.Equal(JsonValueKind.String, evidence.RootElement.GetProperty("timestampUtc").ValueKind);

        runner.Result = new(0, ObserverEvidenceJson.BuildSingleContainer(
            new string('a', 32), [new ObserverEvidenceJson.VolumeJson("Data", 101)], devicePath: deviceId), string.Empty);
        Assert.NotEmpty(await backend.ProbeVolumesAsync(deviceId, CancellationToken.None));
        Assert.False(backend.TryGetLastDiscoveryDiagnostic(deviceId, out _));
        Assert.Equal(evidencePath, Assert.Single(Directory.GetFiles(temp.Path, "backend-observer-discovery-failed-*.json")));
        using var recoveredEvidence = JsonDocument.Parse(await File.ReadAllTextAsync(evidencePath));
        Assert.Equal(detail, recoveredEvidence.RootElement.GetProperty("detail").GetString());
    }

    [Fact]
    public async Task RejectedObserverSource_EvidenceNamesExactRequestedDevice()
    {
        using var temp = DTempDirectory.Create("primary-source-evidence");
        const string requestedDevice = @"\\.\PhysicalDrive31";
        var evidence = ObserverEvidenceJson.BuildSingleContainer(new string('a', 32),
            [new ObserverEvidenceJson.VolumeJson("Data", 101)], devicePath: @"\\.\PhysicalDrive32");
        using var backend = CreateBackend(evidence, temp);
        typeof(NativeApfsBackend).GetField("_writeDiagnosticsRoot", BindingFlags.Instance | BindingFlags.NonPublic)!
            .SetValue(backend, temp.Path);
        Assert.Empty(await backend.ProbeVolumesAsync(requestedDevice, CancellationToken.None));
        var path = Assert.Single(Directory.GetFiles(temp.Path, "backend-observer-discovery-failed-*.json"));
        using var saved = JsonDocument.Parse(await File.ReadAllTextAsync(path));
        var detail = saved.RootElement.GetProperty("detail").GetString()!;
        Assert.Contains(requestedDevice, detail);
        Assert.Contains("source identity could not be verified", detail);
    }

    [Fact]
    public async Task DiagnosticWriteFailure_DoesNotChangeRawDiscoveryRefusal()
    {
        using var temp = DTempDirectory.Create("primary-evidence-unwritable");
        var blocker = Path.Combine(temp.Path, "file-not-directory");
        await File.WriteAllTextAsync(blocker, "blocked");
        using var backend = CreateBackendWithRunner(new StubRunner(new(5, string.Empty, "catalog unreadable")), temp);
        typeof(NativeApfsBackend).GetField("_writeDiagnosticsRoot", BindingFlags.Instance | BindingFlags.NonPublic)!
            .SetValue(backend, blocker);
        const string deviceId = @"\\.\PhysicalDrive31";
        Assert.Empty(await backend.ProbeVolumesAsync(deviceId, CancellationToken.None));
        Assert.True(backend.TryGetLastDiscoveryDiagnostic(deviceId, out var diagnostic));
        Assert.Contains("exit code 5", diagnostic);
        Assert.Contains("catalog unreadable", diagnostic);
    }

    [Fact]
    public async Task MalformedGptImage_ObserverFails_YieldsEmptyWithoutThrow()
    {
        using var temp = DTempDirectory.Create("primary-malformed");
        var imagePath = Path.Combine(temp.Path, "garbage.img");
        var random = new Random(1234);
        var bytes = new byte[64 * 1024];
        random.NextBytes(bytes);
        await File.WriteAllBytesAsync(imagePath, bytes);
        var runner = new StubRunner(new ObserverRunResult(2, string.Empty, "no superblock"));
        using var backend = CreateBackendWithRunner(runner, temp);

        var volumes = await backend.ProbeVolumesAsync(imagePath, CancellationToken.None);

        Assert.Empty(volumes);
    }

    private static NativeApfsBackend CreateBackend(string evidence, DTempDirectory temp)
        => CreateBackendWithRunner(
            new StubRunner(new ObserverRunResult(0, evidence, string.Empty)), temp);

    private static NativeApfsBackend CreateBackendWithRunner(StubRunner runner, DTempDirectory temp)
    {
        // Packaged staging keeps Writable-capable assertions truthful: the
        // seam override resolves under the test host base directory.
        var stagedObserver = StagedPackagedObserver.StageStable("primary");
        return new NativeApfsBackend(
            new ServiceHostOptions { BackendMode = "Native", NativeAutoDiscoverPhysicalDrives = false },
            lifecycleTestHooks: null,
            observerRunner: runner,
            observerPathOverride: stagedObserver);
    }

    private sealed class StubRunner(ObserverRunResult result) : IObserverRunner
    {
        public ObserverRunResult Result { get; set; } = result;
        public int CallCount { get; private set; }

        public IReadOnlyList<string>? LastArguments { get; private set; }

        public ObserverRunResult Run(string observerPath, IReadOnlyList<string> arguments)
        {
            CallCount++;
            LastArguments = arguments.ToArray();
            return Result;
        }
    }

    private static string ContainerHexOf(Guid containerUuid)
        => Convert.ToHexString(containerUuid.ToByteArray()).ToLowerInvariant();

    private static (ulong OffsetBytes, string? RecoveryIdentity) ReadMountTarget(
        NativeApfsBackend backend, VolumeInfo volume)
    {
        var method = typeof(NativeApfsBackend).GetMethod(
            "ResolveMountTarget", BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(method);
        var target = method!.Invoke(backend, [volume]);
        Assert.NotNull(target);
        var targetType = target!.GetType();
        return (
            (ulong)targetType.GetProperty("DeviceOffsetBytes")!.GetValue(target)!,
            (string?)targetType.GetProperty("RecoveryIdentity")!.GetValue(target));
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
