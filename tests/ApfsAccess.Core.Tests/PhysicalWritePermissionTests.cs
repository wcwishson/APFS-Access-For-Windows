using System.Text.Json.Nodes;
using ApfsAccess.Core;
using ApfsAccess.TestFixtures;

namespace ApfsAccess.Core.Tests;

public sealed class PhysicalWritePermissionTests
{
    [Fact]
    public async Task PendingOwnerIsRetainedOnlyForExactIncarnationInIndependentBackgroundContext()
    {
        using var f = new PhysicalWritePermissionFixture();
        var manager = f.Manager();
        var masked = PhysicalWritePermissionFixture.Mask(f.Volume);
        using var request = manager.Begin(f.Options, f.Volume, default);
        manager.RetainOwner(f.Volume, 1234, 5678, "V:\\");
        Task check;
        using (ExecutionContext.SuppressFlow())
            check = Task.Run(() =>
            {
                manager.Observe(f.Volume, f.Topology); // independent authoritative discovery/status cycle
                Assert.Same(f.Options, manager.Resolve(f.Options, masked).Options);
                var retained = manager.ResolveForOwner(f.Options, masked, 1234, 5678, "V:\\");
                Assert.True(WriteGatePolicy.EvaluateForVolume(retained.Options, retained.Volume).AllowWrite);
                Assert.Same(f.Options, manager.ResolveForOwner(f.Options, masked, 1234, 5679, "V:\\").Options);
                Assert.Same(f.Options, manager.ResolveForOwner(f.Options, masked, 1235, 5678, "V:\\").Options);
                Assert.Same(f.Options, manager.ResolveForOwner(f.Options, masked, 1234, 5678, "W:\\").Options);
                Assert.Same(f.Options, f.Manager().ResolveForOwner(f.Options, masked, 1234, 5678, "V:\\").Options);
            });
        await check;
        request.Dispose();
        Assert.Same(f.Options, manager.ResolveForOwner(f.Options, masked, 1234, 5678, "V:\\").Options);
    }

    [Fact]
    public async Task ExplicitPermissionCommitsOnlyAfterCompletionAndSurvivesRestartWithoutMutatingOptions()
    {
        using var f = new PhysicalWritePermissionFixture();
        var manager = f.Manager();
        var masked = PhysicalWritePermissionFixture.Mask(f.Volume);
        Assert.Same(f.Options, manager.Resolve(f.Options, masked).Options);
        Assert.False(File.Exists(f.StorePath));
        using (var request = manager.Begin(f.Options, masked, default))
        {
            Assert.True(File.Exists(f.StorePath));
            var admitted = manager.Resolve(f.Options, masked);
            Assert.NotSame(f.Options, admitted.Options);
            Assert.True(WriteGatePolicy.EvaluateForVolume(admitted.Options, admitted.Volume).AllowWrite);
            Assert.Equal([PhysicalWritePermissionFixture.Device], admitted.Options.NativeWriteHardwarePilotDeviceAllowList);
            Assert.Same(f.Options.NativeWritePilotVolumeAllowList, admitted.Options.NativeWritePilotVolumeAllowList);
            Assert.Same(f.Options, f.Manager().Resolve(f.Options, masked).Options);
            Assert.Same(f.Options, manager.ResolveForDiscovery(f.Options, masked).Options);
            Task<bool> unrelated;
            using (ExecutionContext.SuppressFlow())
                unrelated = Task.Run(() => ReferenceEquals(f.Options, manager.Resolve(f.Options, masked).Options));
            Assert.True(await unrelated);
            request.Confirm(f.Options, masked, default);
        }
        Assert.True(f.Manager().Resolve(f.Options, masked).Options.NativeWriteAllowRawPhysicalDevices);
        Assert.False(f.Options.NativeWriteAllowRawPhysicalDevices);
        Assert.Empty(f.Options.NativeWriteHardwarePilotDeviceAllowList);
        Assert.DoesNotContain(PhysicalWritePermissionFixture.VolumeUuid, File.ReadAllText(f.StorePath));
    }

    [Theory]
    [InlineData("volume")] [InlineData("oid")] [InlineData("recovery")] [InlineData("disk")]
    [InlineData("partition")] [InlineData("geometry")] [InlineData("device")] [InlineData("container")]
    public void PersistedPermissionRefusesChangedIdentity(string change)
    {
        using var f = new PhysicalWritePermissionFixture();
        var manager = f.Manager();
        using (var request = manager.Begin(f.Options, f.Volume, default)) request.Confirm(f.Options, f.Volume, default);
        var s = f.Topology.Snapshot;
        switch (change)
        {
            case "volume": f.Volume = f.Volume with { CatalogVolumeUuid = new string('f', 32) }; s = s with { Volumes = [s.Volumes[0] with { Uuid = f.Volume.CatalogVolumeUuid! }] }; break;
            case "oid": f.Volume = f.Volume with { CatalogVolumeObjectId = 102 }; break;
            case "recovery": f.Volume = f.Volume with { RecoveryIdentity = "changed" }; break;
            case "container": f.Volume = f.Volume with { CatalogContainerUuid = new string('f', 32) }; break;
            case "disk": s = s with { Disks = [s.Disks[0] with { Uuid = Guid.NewGuid().ToString() }] }; break;
            case "partition": s = s with { Partitions = [s.Partitions[0] with { Uuid = Guid.NewGuid().ToString() }] }; break;
            case "geometry": s = s with { Stores = [s.Stores[0] with { SizeBytes = s.Stores[0].SizeBytes - 4096 }] }; break;
            case "device": f.Volume = f.Volume with { DeviceId = @"\\.\PhysicalDrive901" }; break;
        }
        f.Topology = f.Topology with { Snapshot = s };
        var restarted = f.Manager();
        Assert.Same(f.Options, restarted.Resolve(f.Options, PhysicalWritePermissionFixture.Mask(f.Volume)).Options);
    }

    [Theory]
    [InlineData("system")] [InlineData("backup")] [InlineData("fusion")] [InlineData("encrypted")]
    [InlineData("unknown")] [InlineData("readonly")] [InlineData("ambiguous")] [InlineData("untrusted")]
    public void CatalogCannotBePromotedByPermission(string refusal)
    {
        using var f = new PhysicalWritePermissionFixture();
        var s = f.Topology.Snapshot;
        var v = s.Volumes[0];
        switch (refusal)
        {
            case "system": case "backup": v = v with { Roles = [refusal] }; break;
            case "fusion": s = s with { Containers = [s.Containers[0] with { Fusion = true }] }; break;
            case "encrypted": v = v with { EncryptionMode = "password" }; break;
            case "unknown": v = v with { UnknownFeatureBits = ["0x8000"] }; break;
            case "readonly": v = v with { ReadonlyFeatureBits = ["0x8000"] }; break;
            case "ambiguous": s = s with { Disks = [s.Disks[0], s.Disks[0]] }; break;
            case "untrusted": f.Volume = f.Volume with { CatalogDecision = ApfsCapabilityDecision.Readable }; break;
        }
        f.Topology = f.Topology with { Snapshot = s with { Volumes = [v] } };
        var manager = f.Manager();
        Assert.Throws<IOException>(() => manager.Begin(f.Options, f.Volume, default));
        Assert.False(File.Exists(f.StorePath));
    }

    [Theory]
    [InlineData("disabled")] [InlineData("rollout")] [InlineData("pilot")] [InlineData("hardware")]
    [InlineData("backend")] [InlineData("promotion")]
    public void ConsentPreservesAdministrativeAndPilotPolicies(string policy)
    {
        using var f = new PhysicalWritePermissionFixture();
        var manager = f.Manager();
        using (var request = manager.Begin(f.Options, f.Volume, default)) request.Confirm(f.Options, f.Volume, default);
        switch (policy)
        {
            case "disabled": f.Options.EnableNativeWrite = false; break;
            case "rollout": f.Options.WriteRolloutChannel = "Disabled"; break;
            case "pilot": f.Options.NativeWritePilotVolumeAllowList = ["other-volume"]; break;
            case "hardware": f.Options.NativeWriteHardwarePilotDeviceAllowList = [@"\\.\PhysicalDrive901"]; break;
            case "backend": f.Options.WriteBackendMode = "Overlay"; break;
            case "promotion": f.Options.NativeWritePromotionPolicy = "ScaffoldOnly"; break;
        }
        Assert.Same(f.Options, manager.Resolve(f.Options, f.Volume).Options);
        Assert.Throws<IOException>(() => manager.Begin(f.Options, f.Volume, default));
    }

    [Fact]
    public void CancellationOrAbandonmentNeverCreatesRestartPermission()
    {
        using var f = new PhysicalWritePermissionFixture();
        var manager = f.Manager();
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();
        Assert.Throws<OperationCanceledException>(() => manager.Begin(f.Options, f.Volume, cancelled.Token));
        Assert.False(File.Exists(f.StorePath));
        using (var request = manager.Begin(f.Options, f.Volume, default))
            Assert.Throws<OperationCanceledException>(() => request.Confirm(f.Options, f.Volume, cancelled.Token));
        Assert.Same(f.Options, manager.Resolve(f.Options, f.Volume).Options);
        Assert.Same(f.Options, f.Manager().Resolve(f.Options, f.Volume).Options);
    }

    [Fact]
    public void CorruptOrUnavailableStoreDoesNotUsePreviouslyLoadedGrant()
    {
        using var f = new PhysicalWritePermissionFixture();
        var manager = f.Manager();
        using (var request = manager.Begin(f.Options, f.Volume, default)) request.Confirm(f.Options, f.Volume, default);
        var original = File.ReadAllText(f.StorePath);
        var tampered = JsonNode.Parse(original)!;
        var payload = Convert.FromBase64String(tampered["Protected"]!.GetValue<string>());
        payload[payload.Length / 2] ^= 1;
        tampered["Protected"] = Convert.ToBase64String(payload);
        File.WriteAllText(f.StorePath, tampered.ToJsonString());
        Assert.Same(f.Options, manager.Resolve(f.Options, f.Volume).Options);
        Assert.ThrowsAny<Exception>(() => manager.Begin(f.Options, f.Volume, default));
        File.WriteAllText(f.StorePath, original);
        using var blocked = new FileStream(f.StorePath + ".lock", FileMode.CreateNew, FileAccess.Write, FileShare.None, 1, FileOptions.DeleteOnClose);
        Assert.Same(f.Options, manager.Resolve(f.Options, f.Volume).Options);
        Assert.Throws<IOException>(() => manager.Begin(f.Options, f.Volume, default));
    }

    [Fact]
    public void ReparseStoreOrAncestorRefusesWithoutChangingDestination()
    {
        using var f = new PhysicalWritePermissionFixture();
        var target = Path.Combine(f.Root, "target.json");
        File.WriteAllText(target, "original");
        File.CreateSymbolicLink(f.StorePath, target);
        Assert.Throws<IOException>(() => f.Manager().Begin(f.Options, f.Volume, default));
        Assert.Equal("original", File.ReadAllText(target));
        File.Delete(f.StorePath);
        var link = Path.Combine(f.Root, "redirected");
        Directory.CreateSymbolicLink(link, f.Root);
        try
        {
            var manager = new PhysicalWritePermissions(Path.Combine(link, "new.json"));
            manager.Observe(f.Volume, f.Topology);
            Assert.Throws<IOException>(() => manager.Begin(f.Options, f.Volume, default));
            Assert.False(File.Exists(Path.Combine(f.Root, "new.json")));
        }
        finally { Directory.Delete(link); }
    }

    [Fact]
    public void CheckpointChangesKeepPermissionAndUnrelatedGrantedVolumeIsPreserved()
    {
        using var f = new PhysicalWritePermissionFixture();
        var manager = f.Manager();
        using (var request = manager.Begin(f.Options, f.Volume, default)) request.Confirm(f.Options, f.Volume, default);
        var other = f.Volume with { VolumeId = $"apfs-vol:{PhysicalWritePermissionFixture.Container}:102",
            CatalogVolumeId = $"apfs-vol:{PhysicalWritePermissionFixture.Container}:102", CatalogVolumeObjectId = 102,
            CatalogVolumeUuid = new string('e', 32), RecoveryIdentity = "peer-recovery" };
        var s = f.Topology.Snapshot;
        f.Topology = f.Topology with { Snapshot = s with
        {
            Containers = [s.Containers[0] with { CheckpointXid = "11", VolumeIds = [f.Volume.VolumeId, other.VolumeId] }],
            Volumes = [s.Volumes[0] with { SuperblockXid = "11" }, s.Volumes[0] with
                { Id = other.VolumeId, Uuid = other.CatalogVolumeUuid!, ObjectId = "102" }],
        } };
        manager.Observe(f.Volume, f.Topology);
        manager.Observe(other, f.Topology);
        Assert.True(manager.Resolve(f.Options, f.Volume).Options.NativeWriteAllowRawPhysicalDevices);
        Assert.Same(f.Options, manager.Resolve(f.Options, other).Options);
        Assert.True(manager.ResolveCensus(f.Options, f.Volume, PhysicalWritePermissionFixture.Mask(other)).Options.NativeWriteAllowRawPhysicalDevices);
        Assert.Same(f.Options, manager.Resolve(f.Options, other).Options);
        using (var request = manager.Begin(f.Options, other, default)) request.Confirm(f.Options, other, default);
        Assert.True(manager.Resolve(f.Options, f.Volume).Options.NativeWriteAllowRawPhysicalDevices);
        Assert.True(manager.Resolve(f.Options, other).Options.NativeWriteAllowRawPhysicalDevices);
    }
}
