using System.Collections;
using System.Collections.Concurrent;
using System.Reflection;
using System.Text.Json;
using ApfsAccess.Core;
using ApfsAccess.TestFixtures;

namespace ApfsAccess.Backend.Native.Tests;

public sealed class PhysicalWritePermissionBackendTests
{
    private const BindingFlags Private = BindingFlags.NonPublic | BindingFlags.Instance;

    [Fact]
    public async Task PendingOwnerEnforcementRetainsExactOwnerButAdmissionAndOtherOwnersRemainBlocked()
    {
        using var f = new PhysicalWritePermissionFixture();
        var manager = f.Manager();
        var probes = new List<(string, bool)>();
        var hooks = new HostProcessLifecycleTestHooks { SourceAdmission = (device, options) =>
        {
            lock (probes) probes.Add((device, options.NativeWriteAllowRawPhysicalDevices));
            return NativeWriteSourceAdmission.IsAllowListedRawDrive(device, options) ? null : "source-blocked";
        } };
        using var backend = new NativeApfsBackend(f.Options, hooks, null, null, manager);
        var masked = PhysicalWritePermissionFixture.Mask(f.Volume);
        Assert.False(Gate(backend, masked).AllowWrite);
        using var request = manager.Begin(f.Options, masked, default);
        Assert.True(Gate(backend, masked).AllowWrite);
        manager.RetainOwner(f.Volume, 1234, 5678, "V:\\");
        Task check;
        using (ExecutionContext.SuppressFlow())
            check = Task.Run(() =>
            {
                manager.Observe(f.Volume, f.Topology);
                Assert.False(Gate(backend, masked).AllowWrite);
                Assert.True(Retained(backend, masked, 1234, 5678).AllowWrite);
                Assert.False(Retained(backend, masked, 1234, 5679).AllowWrite);
                Assert.False(Retained(backend, masked, 1235, 5678).AllowWrite);
                var start = typeof(NativeApfsBackend).GetMethod("AllowsRawHostStartup", Private)!;
                Assert.False((bool)start.Invoke(backend, [masked])!);
            });
        await check;
        Assert.Contains(probes, x => x.Item2);
        request.Dispose();
        Assert.False(Retained(backend, masked, 1234, 5678).AllowWrite);
    }

    [Fact]
    public void CensusIncludesUnselectedPeerOnlyAsDormantAndLateWritableActivationStillRefuses()
    {
        using var f = new PhysicalWritePermissionFixture();
        var peer = f.Volume with { VolumeId = $"apfs-vol:{PhysicalWritePermissionFixture.Container}:102",
            CatalogVolumeId = $"apfs-vol:{PhysicalWritePermissionFixture.Container}:102", CatalogVolumeObjectId = 102,
            CatalogVolumeUuid = new string('e', 32), RecoveryIdentity = "peer-recovery", VolumeName = "Unselected" };
        var s = f.Topology.Snapshot;
        f.Topology = f.Topology with { Snapshot = s with
        {
            Containers = [s.Containers[0] with { VolumeIds = [f.Volume.VolumeId, peer.VolumeId] }],
            Volumes = [s.Volumes[0], s.Volumes[0] with { Id = peer.VolumeId, Uuid = peer.CatalogVolumeUuid!, ObjectId = "102" }],
        } };
        var manager = f.Manager();
        manager.Observe(peer, f.Topology);
        var hooks = new HostProcessLifecycleTestHooks { SourceAdmission = (device, options) =>
            NativeWriteSourceAdmission.IsAllowListedRawDrive(device, options) ? null : "source-blocked" };
        using var backend = new NativeApfsBackend(f.Options, hooks, null, null, manager);
        var cache = (ConcurrentDictionary<string, VolumeInfo>)typeof(NativeApfsBackend).GetField("_volumeCache", Private)!.GetValue(backend)!;
        peer = PhysicalWritePermissionFixture.Mask(peer) with { NativeVolumePath = "catalog-peer" };
        cache[peer.VolumeId] = peer;
        var targets = (IDictionary)typeof(NativeApfsBackend).GetField("_mountTargetsByVolumeId", Private)!.GetValue(backend)!;
        var targetType = typeof(NativeApfsBackend).GetNestedType("VolumeMountTarget", BindingFlags.NonPublic)!;
        targets[peer.VolumeId] = Activator.CreateInstance(targetType, [peer.DeviceId, (ulong)(1L << 20), peer.RecoveryIdentity,
            peer.CatalogVolumeObjectId, peer.CatalogContainerUuid, null, null])!;
        var member = new NativeApfsBackend.PlannedVolume(new(f.Volume.VolumeId, 'V', MountAccessMode.ReadWrite), f.Volume,
            f.Volume.DeviceId, 1UL << 20, 101, f.Volume.RecoveryIdentity, "V:\\");
        using var request = manager.Begin(f.Options, f.Volume, default);
        var rows = backend.BuildContainerManifestRows(new(PhysicalWritePermissionFixture.Container, [member]));
        Assert.Equal(2, rows.Count);
        Assert.True(rows[0].InitiallyActive);
        Assert.True(rows[0].RequestedWrite);
        Assert.Equal("V:\\", rows[0].MountPoint);
        Assert.False(rows[1].InitiallyActive);
        Assert.True(rows[1].RequestedWrite);
        Assert.Equal(string.Empty, rows[1].MountPoint);
        Assert.False(Gate(backend, peer).AllowWrite);
        Assert.Same(f.Options, manager.Resolve(f.Options, peer).Options);
        Assert.Single(rows.Where(r => r.InitiallyActive && r.RequestedWrite));
        var written = ContainerManifestWriter.WriteManifest(PhysicalWritePermissionFixture.Container, f.Volume.DeviceId, 1UL << 20, rows, f.Root);
        using var document = JsonDocument.Parse(File.ReadAllText(written.ManifestPath));
        Assert.Equal(2, document.RootElement.GetProperty("version").GetInt32());
        var wirePeer = document.RootElement.GetProperty("volumes").EnumerateArray().Single(v => v.GetProperty("objectId").GetUInt64() == 102);
        Assert.False(wirePeer.GetProperty("initiallyActive").GetBoolean());
        Assert.Equal(string.Empty, wirePeer.GetProperty("mount").GetString());
        Assert.Empty((IDictionary)typeof(NativeApfsBackend).GetField("_mounts", Private)!.GetValue(backend)!);
        request.Confirm(f.Options, f.Volume, default);
        Assert.False(Gate(backend, peer).AllowWrite);
        var otherSource = peer with { DeviceId = @"\\.\PhysicalDrive901" };
        Assert.False(Gate(backend, otherSource).AllowWrite);
    }

    [Fact]
    public void PermissionNeverBypassesFinalNativeSourceAdmission()
    {
        using var f = new PhysicalWritePermissionFixture();
        var manager = f.Manager();
        var calls = 0;
        using var backend = new NativeApfsBackend(f.Options, new HostProcessLifecycleTestHooks
        { SourceAdmission = (_, options) => { calls++; Assert.True(options.NativeWriteAllowRawPhysicalDevices); return "native-source-identity-refused"; } }, null, null, manager);
        using var request = manager.Begin(f.Options, f.Volume, default);
        var gate = Gate(backend, PhysicalWritePermissionFixture.Mask(f.Volume));
        Assert.False(gate.AllowWrite);
        Assert.Equal("native-source-identity-refused", gate.Reason);
        Assert.Equal(1, calls);
    }

    private static WriteGateDecision Gate(NativeApfsBackend backend, VolumeInfo volume)
        => (WriteGateDecision)typeof(NativeApfsBackend).GetMethod("EvaluateWriteGateDecision", Private)!.Invoke(backend, [volume])!;
    private static WriteGateDecision Retained(NativeApfsBackend backend, VolumeInfo volume, int pid, long birth)
        => (WriteGateDecision)typeof(NativeApfsBackend).GetMethod("EvaluateRetainedWriteGateDecision", Private)!.Invoke(backend, [volume, pid, birth, "V:\\"])!;
}
