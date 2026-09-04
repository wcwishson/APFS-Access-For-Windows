using System.Diagnostics;
using System.Reflection;
using System.Text.Json;
using ApfsAccess.Core;

namespace ApfsAccess.Backend.Native.Tests;

// Task 2 backend grouping (managed side): mount requests group by container
// UUID and launch ONE FsHost per container with `--container-manifest`.
// Only volumes without an authoritative container UUID keep the legacy
// one-shot launch path. The fake FsHost shim follows HostProcessGuardianTests
// (StartProcess hook returning a real ping child; no WinFsp/driver ops).
public sealed class ContainerSessionGroupingTests : IDisposable
{
    private const string ContainerHexA = "a9cb92d28b7c4b599eab633c7625f491";
    private const string ContainerHexB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    private static readonly string[] VolatileArgumentFlags =
    [
        "--lifetime-file",
        "--startup-gate-file",
        "--startup-gate-token",
        "--status-file",
    ];

    private readonly List<Process> _children = new();
    private readonly List<NativeApfsBackend> _backends = new();
    private readonly object _sync = new();

    [Fact]
    public async Task Plan_TwoVolumesSameContainer_FormsOneManifestPlan()
    {
        using var temp = DTempDirectory.Create("container-plan-same");
        using var backend = await CreateProbedBackendAsync(
            temp,
            ObserverEvidenceJson.BuildSingleContainer(
                ContainerHexA,
                [new ObserverEvidenceJson.VolumeJson("Data", 101),
                 new ObserverEvidenceJson.VolumeJson("Backup", 102)]));
        var planned = BuildPlanned(backend, ["R", "S"], MountAccessMode.ReadOnly);

        var plans = backend.PlanContainerGroups(planned);

        var plan = Assert.Single(plans);
        Assert.Equal(ContainerHexA, plan.ContainerUuid);
        Assert.Equal(2, plan.Members.Count);
    }

    [Fact]
    public async Task Plan_SingleVolumeContainers_RetainCanonicalContainerIdentity()
    {
        using var temp = DTempDirectory.Create("container-plan-solo");
        using var backend = await CreateProbedBackendAsync(
            temp,
            ObserverEvidenceJson.BuildContainers(
                [(ContainerHexA, [new ObserverEvidenceJson.VolumeJson("Data", 101)]),
                 (ContainerHexB, [new ObserverEvidenceJson.VolumeJson("Media", 201)])]));
        var planned = BuildPlanned(backend, ["R", "S"], MountAccessMode.ReadOnly);

        var plans = backend.PlanContainerGroups(planned);

        Assert.Equal(2, plans.Count);
        Assert.Equal([ContainerHexA, ContainerHexB], plans.Select(static plan => plan.ContainerUuid));
        Assert.All(plans, static plan => Assert.Single(plan.Members));
    }

    [Fact]
    public async Task Plan_VolumeWithoutContainerUuid_StaysSoloLegacy()
    {
        using var temp = DTempDirectory.Create("container-plan-nouuid");
        var imagePath = Path.Combine(temp.Path, "legacy.apfs.img");
        SyntheticApfsTestImage.Create(imagePath, sizeMiB: 4);
        using var backend = CreateBackend("{}", temp);
        var volumes = await backend.ProbeVolumesAsync(imagePath, CancellationToken.None);
        var volume = Assert.Single(volumes);
        Assert.Null(volume.CatalogContainerUuid);

        var planned = new NativeApfsBackend.PlannedVolume(
            new MountRequest(volume.VolumeId, 'R', MountAccessMode.ReadOnly),
            volume,
            volume.DeviceId,
            0,
            null,
            null,
            "R:\\");
        var plans = backend.PlanContainerGroups([planned]);

        var plan = Assert.Single(plans);
        Assert.Null(plan.ContainerUuid);
    }

    [Fact]
    public async Task Start_TwoVolumesSameContainer_OneLaunchWithBothVolumesInManifest()
    {
        using var temp = DTempDirectory.Create("container-start-same");
        var launched = new List<string[]>();
        using var backend = await CreateProbedBackendAsync(
            temp,
            ObserverEvidenceJson.BuildSingleContainer(
                ContainerHexA,
                [new ObserverEvidenceJson.VolumeJson("Data", 101),
                 new ObserverEvidenceJson.VolumeJson("Backup", 102)]),
            launched);
        var planned = BuildPlanned(backend, ["R", "S"], MountAccessMode.ReadOnly);
        var plan = Assert.Single(backend.PlanContainerGroups(planned));

        var key = backend.StartContainerGroupOwner(plan);

        Assert.Equal(ContainerHexA, key);
        Assert.Single(launched);
        var manifestPath = ManifestPathFromArgs(launched[0]);
        Assert.StartsWith(@"D:\", manifestPath, StringComparison.OrdinalIgnoreCase);
        var manifest = ReadManifest(manifestPath);
        Assert.Equal(ContainerHexA, manifest.ContainerUuid);
        Assert.Equal(2, manifest.ObjectIds.Count);
        Assert.Contains(101UL, manifest.ObjectIds);
        Assert.Contains(102UL, manifest.ObjectIds);
        Assert.Equal(manifest.Sha256, manifest.RecomputedSha256);
        Assert.DoesNotContain("--volume", launched[0]);
        Assert.DoesNotContain("--mount", launched[0]);
    }

    [Fact]
    public async Task Start_TwoMultiVolumeContainers_TwoLaunchesWithSeparateManifests()
    {
        using var temp = DTempDirectory.Create("container-start-two");
        var launched = new List<string[]>();
        using var backend = await CreateProbedBackendAsync(
            temp,
            ObserverEvidenceJson.BuildContainers(
                [(ContainerHexA, [new ObserverEvidenceJson.VolumeJson("Data", 101),
                                  new ObserverEvidenceJson.VolumeJson("Backup", 102)]),
                 (ContainerHexB, [new ObserverEvidenceJson.VolumeJson("Media", 201),
                                  new ObserverEvidenceJson.VolumeJson("Archive", 202)])]),
            launched);
        var planned = BuildPlanned(backend, ["R", "S", "T", "Q"], MountAccessMode.ReadOnly);
        var plans = backend.PlanContainerGroups(planned);
        Assert.Equal(2, plans.Count);

        foreach (var plan in plans)
        {
            backend.StartContainerGroupOwner(plan);
        }

        Assert.Equal(2, launched.Count);
        var first = ManifestPathFromArgs(launched[0]);
        var second = ManifestPathFromArgs(launched[1]);
        Assert.NotEqual(first, second);
        var firstOids = ReadManifest(first).ObjectIds;
        var secondOids = ReadManifest(second).ObjectIds;
        Assert.Empty(firstOids.Intersect(secondOids));
        Assert.Equal(4, firstOids.Union(secondOids).Count());
    }

    [Fact]
    public void Start_MixedDeviceSameContainer_FailsClosed()
    {
        using var temp = DTempDirectory.Create("container-start-mixed");
        using var backend = CreateBackend("{}", temp);
        var first = new VolumeInfo(
            @"D:\a.apfs.img|Data", @"D:\a.apfs.img", "Data", SupportsReadWrite: false,
            CatalogContainerUuid: ContainerHexA);
        var second = new VolumeInfo(
            @"D:\b.apfs.img|Data", @"D:\b.apfs.img", "Data", SupportsReadWrite: false,
            CatalogContainerUuid: ContainerHexA);
        var plan = new NativeApfsBackend.ContainerMountPlan(ContainerHexA, new[]
        {
            new NativeApfsBackend.PlannedVolume(
                new MountRequest(first.VolumeId, 'R', MountAccessMode.ReadOnly),
                first, @"D:\a.apfs.img", 0, 101, "rec-1", "R:\\"),
            new NativeApfsBackend.PlannedVolume(
                new MountRequest(second.VolumeId, 'S', MountAccessMode.ReadOnly),
                second, @"D:\b.apfs.img", 0, 102, "rec-2", "S:\\"),
        });

        Assert.Throws<ContainerManifestException>(() => backend.StartContainerGroupOwner(plan));
    }

    [Fact]
    public async Task MountContainer_SingleVolume_KeepsLegacyLaunchArgs()
    {
        using var temp = DTempDirectory.Create("container-single-legacy");
        var imagePath = Path.Combine(temp.Path, "single.apfs.img");
        SyntheticApfsTestImage.Create(imagePath, sizeMiB: 4);
        var launched = new List<string[]>();
        var backend = CreateBackend("{}", temp, launched);
        _backends.Add(backend);
        var volume = Assert.Single(await backend.ProbeVolumesAsync(imagePath, CancellationToken.None));

        // Baseline: the legacy one-shot launch directly (no mount wait).
        var startHost = typeof(NativeApfsBackend).GetMethod(
            "StartHostProcess", BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(startHost);
        startHost!.Invoke(backend, [volume, "R:\\", MountAccessMode.ReadOnly]);

        // Container call with a single volume must take the same path.
        var results = await backend.MountContainerAsync(
            [new MountRequest(volume.VolumeId, 'R', MountAccessMode.ReadOnly)],
            CancellationToken.None);

        Assert.Equal(2, launched.Count);
        Assert.Equal(StripVolatile(launched[0]), StripVolatile(launched[1]));
        Assert.DoesNotContain("--container-manifest", launched[1]);
        Assert.Contains("--volume", launched[1]);
        var result = Assert.Single(results);
        Assert.False(result.Success);
        Assert.Equal("FsHostStartupTimeout", result.DiagnosticCode);
    }

    [Fact]
    public async Task MountAsync_CanonicalSingleVolume_UsesContainerOwner()
    {
        using var temp = DTempDirectory.Create("container-single-canonical");
        var launched = new List<string[]>();
        var backend = await CreateProbedBackendAsync(
            temp,
            ObserverEvidenceJson.BuildSingleContainer(
                ContainerHexA,
                [new ObserverEvidenceJson.VolumeJson("Data", 101)]),
            launched);
        var volume = Assert.Single(BuildPlanned(backend, ["R"], MountAccessMode.ReadOnly));

        var result = await backend.MountAsync(volume.Request, CancellationToken.None);

        Assert.False(result.Success);
        Assert.Equal("FsHostStartupTimeout", result.DiagnosticCode);
        var launch = Assert.Single(launched);
        Assert.Contains("--container-manifest", launch);
        Assert.DoesNotContain("--volume", launch);
    }

    [Fact]
    public async Task MountContainer_OneEligibleCanonicalSurvivorUsesContainerOwner()
    {
        using var temp = DTempDirectory.Create("container-one-survivor");
        var launched = new List<string[]>();
        var backend = await CreateProbedBackendAsync(
            temp,
            ObserverEvidenceJson.BuildSingleContainer(
                ContainerHexA,
                [new ObserverEvidenceJson.VolumeJson("Data", 101),
                 new ObserverEvidenceJson.VolumeJson("Backup", 102)]),
            launched);
        var volumeCache = (System.Collections.IDictionary)typeof(NativeApfsBackend)
            .GetField("_volumeCache", BindingFlags.NonPublic | BindingFlags.Instance)!
            .GetValue(backend)!;
        var cached = volumeCache.Values.Cast<VolumeInfo>()
            .OrderBy(static volume => volume.VolumeId, StringComparer.Ordinal)
            .ToArray();
        var mounts = (System.Collections.IDictionary)typeof(NativeApfsBackend)
            .GetField("_mounts", BindingFlags.NonPublic | BindingFlags.Instance)!
            .GetValue(backend)!;
        mounts["S:\\"] = new MountedVolumeState("occupied", "S:\\", MountAccessMode.ReadOnly);

        var results = await backend.MountContainerAsync(
            [new MountRequest(cached[0].VolumeId, 'R', MountAccessMode.ReadOnly),
             new MountRequest(cached[1].VolumeId, 'S', MountAccessMode.ReadOnly)],
            CancellationToken.None);

        Assert.Equal(2, results.Count);
        Assert.All(results, static result => Assert.NotNull(result));
        Assert.Contains(results, static result => result.DiagnosticCode == "FsHostStartupTimeout");
        Assert.Contains(results, static result => result.DiagnosticCode == "MountPointBusy");
        var launch = Assert.Single(launched);
        Assert.Contains("--container-manifest", launch);
        Assert.DoesNotContain("--volume", launch);
    }

    public void Dispose()
    {
        foreach (var backend in _backends)
        {
            try
            {
                backend.Dispose();
            }
            catch
            {
            }
        }

        lock (_sync)
        {
            foreach (var child in _children)
            {
                try
                {
                    if (!child.HasExited)
                    {
                        child.Kill(entireProcessTree: true);
                        child.WaitForExit(2_000);
                    }
                }
                catch
                {
                }

                try
                {
                    child.Dispose();
                }
                catch
                {
                }
            }

            _children.Clear();
        }
    }

    private async Task<NativeApfsBackend> CreateProbedBackendAsync(
        DTempDirectory temp,
        string evidence,
        List<string[]>? launched = null)
    {
        var imagePath = Path.Combine(temp.Path, "fixture.apfs.img");
        SyntheticApfsTestImage.CreateCatalogFixture(imagePath);
        var backend = CreateBackend(evidence, temp, launched);
        var volumes = await backend.ProbeVolumesAsync(imagePath, CancellationToken.None);
        Assert.NotEmpty(volumes);
        return backend;
    }

    private NativeApfsBackend CreateBackend(
        string evidence, DTempDirectory temp, List<string[]>? launched = null)
    {
        var observerShim = Path.Combine(temp.Path, "ApfsObserver.exe");
        File.WriteAllBytes(observerShim, [0x4D, 0x5A]);
        var hooks = new HostProcessLifecycleTestHooks
        {
            StartProcess = psi =>
            {
                launched?.Add(psi.ArgumentList.ToArray());
                return StartPingChild(30);
            },
        };
        var backend = new NativeApfsBackend(
            new ServiceHostOptions
            {
                BackendMode = "Native",
                NativeAutoDiscoverPhysicalDrives = false,
                NativeFsHostPath = Path.Combine(Environment.SystemDirectory, "PING.EXE"),
                NativeHostStartupTimeoutSeconds = 2,
                NativeHostStopTimeoutSeconds = 2,
                NativeWriteEvidenceStorePath = Path.Combine(temp.Path, "evidence.json"),
            },
            hooks,
            observerRunner: new StubRunner(new ObserverRunResult(0, evidence, string.Empty)),
            observerPathOverride: observerShim);
        _backends.Add(backend);
        return backend;
    }

    private NativeApfsBackend.PlannedVolume[] BuildPlanned(
        NativeApfsBackend backend, string[] letters, MountAccessMode accessMode)
    {
        var volumesField = typeof(NativeApfsBackend)
            .GetField("_volumeCache", BindingFlags.NonPublic | BindingFlags.Instance)!
            .GetValue(backend);
        var cached = ((System.Collections.IDictionary)volumesField!)
            .Values.Cast<VolumeInfo>()
            .OrderBy(static volume => volume.VolumeId, StringComparer.Ordinal)
            .ToArray();
        Assert.Equal(letters.Length, cached.Length);
        return cached.Select((volume, index) =>
        {
            var target = ReadMountTarget(backend, volume);
            var letter = letters[index][0];
            return new NativeApfsBackend.PlannedVolume(
                new MountRequest(volume.VolumeId, letter, accessMode),
                volume,
                target.DevicePath!,
                target.DeviceOffsetBytes ?? 0,
                target.VolumeObjectId,
                target.RecoveryIdentity,
                $"{char.ToUpperInvariant(letter)}:\\");
        }).ToArray();
    }

    private static (string? DevicePath, ulong? DeviceOffsetBytes, ulong? VolumeObjectId, string? RecoveryIdentity)
        ReadMountTarget(NativeApfsBackend backend, VolumeInfo volume)
    {
        var method = typeof(NativeApfsBackend).GetMethod(
            "ResolveMountTarget", BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(method);
        var target = method!.Invoke(backend, [volume]);
        Assert.NotNull(target);
        var targetType = target!.GetType();
        return (
            (string?)targetType.GetProperty("DevicePath")!.GetValue(target),
            (ulong?)targetType.GetProperty("DeviceOffsetBytes")!.GetValue(target),
            (ulong?)targetType.GetProperty("VolumeObjectId")!.GetValue(target),
            (string?)targetType.GetProperty("RecoveryIdentity")!.GetValue(target));
    }

    private static string ManifestPathFromArgs(string[] args)
    {
        var flag = Array.IndexOf(args, "--container-manifest");
        Assert.True(flag >= 0 && flag + 1 < args.Length);
        return args[flag + 1];
    }

    private static (string ContainerUuid, List<ulong> ObjectIds, string Sha256, string RecomputedSha256)
        ReadManifest(string manifestPath)
    {
        using var stream = File.OpenRead(manifestPath);
        using var document = JsonDocument.Parse(stream);
        var root = document.RootElement;
        var containerUuid = root.GetProperty("containerUuid").GetString()!;
        var sha256 = root.GetProperty("manifestSha256").GetString()!;
        var oids = root.GetProperty("volumes").EnumerateArray()
            .Select(static element => element.GetProperty("objectId").GetUInt64())
            .ToList();
        var recomputed = ContainerManifestWriter.ComputeManifestSha256(
            containerUuid,
            root.GetProperty("device").GetString()!,
            root.GetProperty("deviceOffsetBytes").GetUInt64(),
            root.GetProperty("volumes").EnumerateArray().Select(static element => new ContainerManifestVolume(
                element.GetProperty("objectId").GetUInt64(),
                element.GetProperty("containerUuid").GetString()!,
                element.GetProperty("name").GetString(),
                element.GetProperty("mount").GetString()!,
                element.GetProperty("requestedWrite").GetBoolean(),
                element.GetProperty("recoveryIdentity").GetString())).ToArray());
        return (containerUuid, oids, sha256, recomputed);
    }

    private static List<string> StripVolatile(string[] args)
    {
        var stripped = new List<string>(args.Length);
        for (var index = 0; index < args.Length; index++)
        {
            stripped.Add(args[index]);
            if (Array.IndexOf(VolatileArgumentFlags, args[index]) >= 0)
            {
                index++;
            }
        }

        return stripped;
    }

    private Process StartPingChild(int count)
    {
        var child = Process.Start(new ProcessStartInfo
        {
            FileName = Path.Combine(Environment.SystemDirectory, "PING.EXE"),
            ArgumentList =
            {
                "-n",
                count.ToString(System.Globalization.CultureInfo.InvariantCulture),
                "127.0.0.1",
            },
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        })!;
        lock (_sync)
        {
            _children.Add(child);
        }

        return child;
    }

    private sealed class StubRunner(ObserverRunResult result) : IObserverRunner
    {
        public ObserverRunResult Run(string observerPath, IReadOnlyList<string> arguments) => result;
    }
}
