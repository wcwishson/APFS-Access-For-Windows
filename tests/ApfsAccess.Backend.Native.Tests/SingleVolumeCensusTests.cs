using System.Collections;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using ApfsAccess.Core;

namespace ApfsAccess.Backend.Native.Tests;

public sealed partial class ContainerSessionRoutingTests
{
    private static void EnableCensusWrite(ServiceHostOptions options)
    {
        options.EnableNativeWrite = true;
        options.WriteRolloutChannel = "Enabled";
        options.WriteBackendMode = "Native";
    }
    private static ServiceHostOptions CensusOptions(NativeApfsBackend backend)
    {
        var options = (ServiceHostOptions)typeof(NativeApfsBackend).GetField("_options", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(backend)!;
        options.EnableNativeWrite = true;
        options.WriteRolloutChannel = "Enabled";
        options.WriteBackendMode = "Native";
        return options;
    }

    private static void AdmitFixtureCatalog(NativeApfsBackend backend)
    {
        // The stub observer intentionally yields untrusted discovery. Supply the
        // trusted catalog verdict at this planner boundary; native tests prove bytes.
        var cache = (IDictionary)typeof(NativeApfsBackend).GetField("_volumeCache", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(backend)!;
        foreach (var volume in cache.Values.Cast<VolumeInfo>().ToArray())
            cache[volume.VolumeId] = volume with { CatalogDecision = ApfsCapabilityDecision.Writable,
                CatalogReasons = [], CatalogAutoMountAllowed = true, SupportsReadWrite = true,
                SupportsNativeWrite = true, WriteBlockReason = null, WriteIncompatibilities = [], WriteUnsupportedFeatures = [] };
    }

    [Theory]
    [InlineData(2)]
    [InlineData(3)]
    public async Task Census_OneSelectedOfMany_UsesOriginalEligiblePeerIdentityWithoutLetter(int count)
    {
        using var temp = DTempDirectory.Create("census-plan");
        var rows = Enumerable.Range(0, count).Select(i => new ObserverEvidenceJson.VolumeJson("Data" + i, (ulong)(101 + i))).ToArray();
        var backend = await CreateProbedBackendAsync(temp, ObserverEvidenceJson.BuildSingleContainer(ContainerHexA, rows,
            devicePath: Path.Combine(temp.Path, "fixture.apfs.img")), configureOptions: EnableCensusWrite);
        CensusOptions(backend);
        AdmitFixtureCatalog(backend);
        var planned = BuildPlanned(backend, count == 2 ? ["R", "S"] : ["R", "S", "T"], MountAccessMode.ReadWrite);
        var manifest = backend.BuildContainerManifestRows(new(ContainerHexA, [planned[0]]));
        Assert.Equal(count, manifest.Count);
        Assert.Equal("R:\\", Assert.Single(manifest.Where(row => row.InitiallyActive)).MountPoint);
        foreach (var peer in manifest.Where(row => !row.InitiallyActive))
        {
            Assert.Empty(peer.MountPoint);
            Assert.Equal(planned.Single(row => row.VolumeObjectId == peer.ObjectId).RecoveryIdentity, peer.RecoveryIdentity);
        }
        var mounts = (IDictionary)typeof(NativeApfsBackend).GetField("_mounts", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(backend)!;
        Assert.Empty(mounts);
    }

    [Theory]
    [InlineData("unsupported")]
    [InlineData("allowlist")]
    [InlineData("encrypted")]
    public async Task Census_PeerAdmissionRefusesWithoutInventingEligibility(string reason)
    {
        using var temp = DTempDirectory.Create("census-refusal");
        var backend = await CreateProbedBackendAsync(temp, ObserverEvidenceJson.BuildSingleContainer(ContainerHexA,
            [new("Data", 101), new("Peer", 102)], devicePath: Path.Combine(temp.Path, "fixture.apfs.img")), configureOptions: EnableCensusWrite);
        var options = CensusOptions(backend);
        AdmitFixtureCatalog(backend);
        var planned = BuildPlanned(backend, ["R", "S"], MountAccessMode.ReadWrite);
        var cache = (IDictionary)typeof(NativeApfsBackend).GetField("_volumeCache", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(backend)!;
        var peer = planned[1].Volume;
        if (reason == "allowlist") { options.WriteRolloutChannel = "Pilot"; options.NativeWritePilotVolumeAllowList = [planned[0].Volume.VolumeId]; }
        else cache[peer.VolumeId] = reason == "encrypted" ? peer with { IsEncrypted = true } : peer with { SupportsNativeWrite = false, WriteUnsupportedFeatures = ["unsupported-peer"] };
        var error = Assert.Throws<ContainerManifestException>(() => backend.BuildContainerManifestRows(new(ContainerHexA, [planned[0]])));
        Assert.Contains("CheckpointCensusPeerAdmissionRefused", error.Message);
    }

    [Theory]
    [InlineData(2, "Overlay")]
    [InlineData(3, "Overlay")]
    [InlineData(2, " overlay ")]
    [InlineData(3, " overlay ")]
    public async Task Census_OverlayRequest_PreservesSelectedOnlyV1(int count, string writeBackend)
    {
        using var temp = DTempDirectory.Create("census-overlay");
        var rows = Enumerable.Range(0, count).Select(i => new ObserverEvidenceJson.VolumeJson("Data" + i, (ulong)(101 + i))).ToArray();
        var backend = await CreateProbedBackendAsync(temp, ObserverEvidenceJson.BuildSingleContainer(ContainerHexA, rows,
            devicePath: Path.Combine(temp.Path, "fixture.apfs.img")), configureOptions: EnableCensusWrite);
        var options = CensusOptions(backend);
        AdmitFixtureCatalog(backend);
        var planned = BuildPlanned(backend, count == 2 ? ["R", "S"] : ["R", "S", "T"], MountAccessMode.ReadWrite);
        options.WriteBackendMode = writeBackend;
        var cache = (IDictionary)typeof(NativeApfsBackend).GetField("_volumeCache", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(backend)!;
        foreach (var peer in planned.Skip(1))
            cache[peer.Volume.VolumeId] = peer.Volume with { SupportsNativeWrite = false, WriteUnsupportedFeatures = ["unsupported-peer"] };

        var manifest = backend.BuildContainerManifestRows(new(ContainerHexA, [planned[0]]));
        var selected = Assert.Single(manifest);
        Assert.True(selected.InitiallyActive);
        Assert.Equal(planned[0].VolumeObjectId, selected.ObjectId);
        Assert.Equal("R:\\", selected.MountPoint);
        var written = ContainerManifestWriter.WriteManifest(ContainerHexA, planned[0].DevicePath,
            planned[0].DeviceOffsetBytes, manifest, temp.Path);
        using var document = JsonDocument.Parse(File.ReadAllText(written.ManifestPath));
        Assert.Equal(1, document.RootElement.GetProperty("version").GetInt32());
        Assert.False(document.RootElement.GetProperty("volumes")[0].TryGetProperty("initiallyActive", out _));
    }

    [Fact]
    public async Task Census_LastActiveEjectWithDormantPeer_ProvesOriginalHostExit()
    {
        using var temp = DTempDirectory.Create("census-eject");
        var launched = new List<string[]>(); var visibility = new ConcurrentDictionary<string, bool>();
        var backend = await CreateProbedBackendAsync(temp, ObserverEvidenceJson.BuildSingleContainer(ContainerHexA,
            [new("Data", 101), new("Peer", 102)], devicePath: Path.Combine(temp.Path, "fixture.apfs.img")), launched, visibility,
            hooks => hooks.ProbeExactProcessHandleExit = process => { if (!process.HasExited) return false; visibility["R:\\"] = false; return true; });
        var planned = BuildPlanned(backend, ["R", "S"], MountAccessMode.ReadOnly);
        backend.StartContainerGroupOwner(new(ContainerHexA, [planned[0]]));
        var group = GetContainerGroup(backend, ContainerHexA);
        var dormant = (IDictionary)group.GetType().GetProperty("DormantMembers")!.GetValue(group)!;
        dormant[102ul] = new ContainerManifestVolume(102, ContainerHexA, "Peer", "", true, planned[1].RecoveryIdentity, false);
        visibility["R:\\"] = true;
        var owner = GetContainerOwnerPid(backend, ContainerHexA);
        Assert.Single(await backend.GetMountStateAsync(CancellationToken.None));
        var result = await backend.UnmountAsync("R:\\", CancellationToken.None);
        Assert.False(result.ContainerMemberDetached);
        PublishTerminalContainerStatus(backend);
        visibility["R:\\"] = false;
        Assert.True(SpinWait.SpinUntil(() => GetContainerGroupCount(backend) == 0, TimeSpan.FromSeconds(10)), result.Error);
        Assert.False(IsProcessAlive(owner));
        Assert.Empty(await backend.GetMountStateAsync(CancellationToken.None));
    }

    [Theory]
    [InlineData("readonly")]
    [InlineData("busy")]
    [InlineData("mode")]
    [InlineData("lost-reply")]
    public async Task Census_LateActivation_UsesCurrentTargetAndContainsAmbiguity(string scenario)
    {
        using var temp = DTempDirectory.Create("census-activate");
        var launched = new List<string[]>(); var visibility = new ConcurrentDictionary<string, bool>();
        Process? child = null;
        var childPid = 0;
        var childExitCode = -1;
        Task gracefulExit = Task.CompletedTask;
        var backend = await CreateProbedBackendAsync(temp, ObserverEvidenceJson.BuildSingleContainer(ContainerHexA,
            [new("Data", 101), new("Peer", 102)], devicePath: Path.Combine(temp.Path, "fixture.apfs.img")), launched, visibility,
            hooks => hooks.StartProcess = start =>
            {
                var arguments = start.ArgumentList.ToArray();
                launched.Add(arguments);
                child = Process.Start(new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "cmd.exe"))
                {
                    ArgumentList = { "/d", "/c", "set /p census_stop=&exit /b 0" },
                    UseShellExecute = false, CreateNoWindow = true, RedirectStandardInput = true,
                    RedirectStandardOutput = true, RedirectStandardError = true,
                })!;
                lock (_sync) _children.Add(child);
                childPid = child.Id;
                var observer = Process.GetProcessById(childPid);
                var input = child.StandardInput;
                gracefulExit = Task.Run(async () =>
                {
                    using var retainedObserver = observer;
                    var lifetime = ArgumentValue(arguments, "--lifetime-file");
                    var deadline = DateTime.UtcNow.AddSeconds(20);
                    while (File.Exists(lifetime) && DateTime.UtcNow < deadline) await Task.Delay(10);
                    Assert.False(File.Exists(lifetime), "The owner received no graceful stop.");
                    await input.WriteLineAsync("drained");
                    await input.FlushAsync();
                    await retainedObserver.WaitForExitAsync();
                    childExitCode = retainedObserver.ExitCode;
                    Assert.Equal(0, childExitCode);
                });
                return child;
            });
        var planned = BuildPlanned(backend, ["R", "S"], MountAccessMode.ReadOnly);
        backend.StartContainerGroupOwner(new(ContainerHexA, [planned[0]]));
        var group = GetContainerGroup(backend, ContainerHexA);
        var dormant = (IDictionary)group.GetType().GetProperty("DormantMembers")!.GetValue(group)!;
        dormant[102ul] = new ContainerManifestVolume(102, ContainerHexA, "Peer", "", true, planned[1].RecoveryIdentity, false);
        visibility["R:\\"] = true;
        var ownerPid = GetContainerOwnerPid(backend, ContainerHexA);
        Action<JsonObject> addPeer = status => {
            var array = status["volumes"]!.AsArray(); var peer = array[0]!.DeepClone().AsObject();
            peer["objectId"] = 102ul; peer["canonicalId"] = $"apfs-vol:{ContainerHexA}:102";
            peer["recoveryIdentity"] = planned[1].RecoveryIdentity; peer["mountPoint"] = visibility.GetValueOrDefault("T:\\") ? "T:\\" : "";
            peer["mounted"] = visibility.GetValueOrDefault("T:\\"); peer["ready"] = visibility.GetValueOrDefault("T:\\"); array.Add(peer);
        };
        PublishContainerStatus(launched[0], ownerPid, visibility, addPeer);
        var originalOwner = group.GetType().GetProperty("Owner")!.GetValue(group)!;
        var readyMethod = typeof(NativeApfsBackend).GetMethod("IsContainerStartupStatusReady", BindingFlags.Static | BindingFlags.NonPublic)!;
        var status = await backend.GetContainerMountStatusAsync(ContainerHexA, CancellationToken.None);
        Assert.True((bool)readyMethod.Invoke(null, [group, new[] { planned[0] }, status])!);
        var invalid = status with { Volumes = status.Volumes.Select(row => row.ObjectId == 102 ? row with { Mounted = true, Ready = true } : row).ToArray() };
        Assert.False((bool)readyMethod.Invoke(null, [group, new[] { planned[0] }, invalid])!);
        var requestPath = ArgumentValue(launched[0], "--container-control-file");
        Task responder = Task.CompletedTask;
        if (scenario is "readonly" or "lost-reply")
            responder = Task.Run(async () => {
                var deadline = DateTime.UtcNow.AddSeconds(5);
                while (!File.Exists(requestPath) && DateTime.UtcNow < deadline) await Task.Delay(10);
                Assert.True(File.Exists(requestPath));
                string[] lines;
                while (true)
                {
                    try
                    {
                        lines = File.ReadAllLines(requestPath);
                        break;
                    }
                    catch (IOException error) when (
                        error.HResult == unchecked((int)0x80070020) && DateTime.UtcNow < deadline)
                    {
                        await Task.Delay(10);
                        if (DateTime.UtcNow >= deadline) throw;
                    }
                }
                Assert.Equal("activate", lines[3]); Assert.Equal("102", lines[4]);
                Assert.Equal("T:\\", lines[5]); Assert.Equal("R", lines[6]); Assert.Equal(7, lines.Length);
                File.Delete(requestPath); visibility["T:\\"] = true;
                PublishContainerStatus(launched[0], ownerPid, visibility, addPeer);
                if (scenario == "readonly") File.WriteAllText(requestPath + ".response", $"APFS-CONTROL/1\n{lines[1]}\nok\nAttached\n");
            });
        if (scenario == "busy") visibility["T:\\"] = true;
        var result = await backend.MountAsync(new(planned[1].Volume.VolumeId, 'T',
            scenario == "mode" ? MountAccessMode.ReadWrite : MountAccessMode.ReadOnly), CancellationToken.None);
        await responder;
        Assert.Single(launched);
        if (scenario == "readonly") {
            Assert.True(result.Success, result.Error); Assert.True(result.IsReadOnly); Assert.False(result.WriteEnabled);
            Assert.Equal("T:\\", result.MountPoint); Assert.Empty(dormant);
            Assert.DoesNotContain((await backend.GetMountStateAsync(CancellationToken.None)), row => row.MountPoint == "S:\\");
        } else {
            Assert.False(result.Success);
            if (scenario == "lost-reply") {
                Assert.Equal(2, GetContainerGroupMemberCount(backend, ContainerHexA));
                Assert.False(IsProcessAlive(ownerPid));
            } else Assert.False(File.Exists(requestPath));
        }
        // A close of the owner must terminate the original child even with a dormant context.
        visibility["R:\\"] = false;
        visibility["T:\\"] = false;
        PublishTerminalContainerStatus(backend);
        backend.Dispose();
        await gracefulExit.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(ownerPid, childPid);
        Assert.Equal(0, childExitCode);
        Assert.False((bool)originalOwner.GetType().GetProperty("ForcedTerminationRequested")!.GetValue(originalOwner)!);
        Assert.True(SpinWait.SpinUntil(() => !IsProcessAlive(ownerPid), TimeSpan.FromSeconds(5)));
    }
}

public sealed class SingleVolumeCensusManifestTests
{
    [Theory]
    [InlineData(2)]
    [InlineData(3)]
    public void VersionTwo_BindsActivationAndNoPeerMount(int count)
    {
        using var temp = DTempDirectory.Create("census-wire");
        const string uuid = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", device = "D:\\never-opened.img";
        var volumes = Enumerable.Range(0, count).Select(i => new ContainerManifestVolume((ulong)(101 + i), uuid, "Data",
            i == 0 ? "R:\\" : "", true, "original-" + i, i == 0)).ToArray();
        var canonical = $"manifest-check-v2\n{uuid}\n{device}\n0\n";
        for (var i = 0; i < count; ++i)
            canonical += $"{101 + i}\n{uuid}\nData\n{(i == 0 ? "R:\\" : "")}\nW\noriginal-{i}\n{(i == 0 ? "A" : "I")}\n";
        var expected = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical))).ToLowerInvariant();
        var written = ContainerManifestWriter.WriteManifest(uuid, device, 0, volumes, temp.Path);
        Assert.Equal(expected, written.ManifestSha256);
        using var document = JsonDocument.Parse(File.ReadAllText(written.ManifestPath));
        Assert.Equal(2, document.RootElement.GetProperty("version").GetInt32());
        Assert.False(document.RootElement.GetProperty("volumes")[1].GetProperty("initiallyActive").GetBoolean());
        var altered = volumes.ToArray(); altered[1] = altered[1] with { InitiallyActive = true };
        Assert.NotEqual(expected, ContainerManifestWriter.ComputeManifestSha256(uuid, device, 0, altered));
        altered[1] = volumes[1] with { MountPoint = "S:\\" };
        Assert.Throws<ContainerManifestException>(() => ContainerManifestWriter.WriteManifest(uuid, device, 0, altered, temp.Path));
        altered[1] = volumes[1] with { RequestedWrite = false };
        Assert.Throws<ContainerManifestException>(() => ContainerManifestWriter.WriteManifest(uuid, device, 0, altered, temp.Path));
        altered[1] = volumes[1] with { ObjectId = 101 };
        Assert.Throws<ContainerManifestException>(() => ContainerManifestWriter.WriteManifest(uuid, device, 0, altered, temp.Path));
    }
}
