using System.Collections;
using System.Diagnostics;
using System.Reflection;
using System.Text.Json.Nodes;
using ApfsAccess.Core;

namespace ApfsAccess.Backend.Native.Tests;

public sealed class SnapshotRecoveryRoutingTests
{
    [SnapshotRecoveryStatusFact]
    public async Task ActuallyDegradedNativeAcceptedOwnerRemainsRefusedThroughBackendProjectionAndRoute()
    {
        var fixture = SnapshotRecoveryFixture.Load(degraded: true);
        var status = ContainerStatusReader.Parse(fixture.StatusJson);
        var child = status.Volumes.Single(v => v.ObjectId == 101);
        Assert.True(child.RecoveryActive); Assert.True(child.WriteDegraded); Assert.False(child.Writable);
        Assert.False(child.SnapshotRecoverySupported);
        using var route = new RetainedRoute(fixture);
        var mount = Assert.Single(await route.Backend.GetMountStateAsync(default));
        Assert.True(mount.RecoveryActive); Assert.False(mount.SnapshotRecoverySupported);
        Assert.False((await route.Backend.SendSnapshotControlAsync(status.ContainerUuid, 101, SnapshotControlAction.Recover, null, default)).Success);
        Assert.False(File.Exists(route.ControlPath));
    }

    [SnapshotRecoveryStatusFact]
    public async Task ActualAcceptedNativeStatusReachesRecoveryRouteAndKeepsCreateDeleteClosed()
    {
        var fixture = SnapshotRecoveryFixture.Load();
        var status = ContainerStatusReader.Parse(fixture.StatusJson);
        var child = status.Volumes.Single(v => v.ObjectId == 101);
        Assert.True(child.SnapshotRecoverySupported); Assert.False(child.SnapshotInventorySupported); Assert.False(child.SnapshotMutationSupported);
        using var route = new RetainedRoute(fixture);
        var mount = Assert.Single(await route.Backend.GetMountStateAsync(default));
        Assert.True(mount.SnapshotRecoverySupported); Assert.False(mount.SnapshotMutationSupported);
        var pending = route.Backend.SendSnapshotControlAsync(status.ContainerUuid, 101, SnapshotControlAction.Recover, null, default);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        while (!File.Exists(route.ControlPath) && !pending.IsCompleted) await Task.Delay(5, deadline.Token);
        Assert.True(File.Exists(route.ControlPath), "Recovery did not reach the authenticated owner channel.");
        var lines = await File.ReadAllLinesAsync(route.ControlPath, deadline.Token);
        Assert.Equal(5, lines.Length); Assert.Equal("snapshot-recover", lines[3]); Assert.Equal("101", lines[4]);
        Assert.Equal(route.Token, lines[2]);
        await File.WriteAllTextAsync(route.ControlPath + ".tmp", $"APFS-CONTROL/1\n{lines[1]}\nok\nSnapshotRecovered\n", deadline.Token);
        File.Move(route.ControlPath + ".tmp", route.ControlPath + ".response");
        Assert.True((await pending).Success);
        Assert.False((await route.Backend.SendSnapshotControlAsync(status.ContainerUuid, 101, SnapshotControlAction.Create, ["Blocked"], default)).Success);
        Assert.False((await route.Backend.SendSnapshotControlAsync(status.ContainerUuid, 101, SnapshotControlAction.Delete,
            ["21", "backup", "249", "17", "230", "8293", "8", "250", "7"], default)).Success);
        Assert.False(File.Exists(route.ControlPath));
    }

    [SnapshotRecoveryStatusFact]
    public async Task RecoveryRouteRefusesStaleStatusWrongOwnerProfileAndMemberBeforeDispatch()
    {
        var fixture = SnapshotRecoveryFixture.Load();
        foreach (var failure in new[] { "capability", "stale", "owner", "recovery-identity", "container", "physical", "offset", "readonly", "detached" })
        {
            using var route = new RetainedRoute(fixture, failure);
            var result = await route.Backend.SendSnapshotControlAsync(route.Container, 101, SnapshotControlAction.Recover, null, default);
            Assert.False(result.Success, failure); Assert.False(File.Exists(route.ControlPath), failure);
        }
    }

    // Only seed retained routing state; never launch a host, mount or acquire a raw handle.
    private sealed class RetainedRoute : IDisposable
    {
        private readonly DTempDirectory _temp = DTempDirectory.Create("snapshot-recovery-route");
        private readonly Process _process = Process.GetCurrentProcess();
        private readonly IDictionary _groups;
        private readonly IDictionary _mounts;
        public NativeApfsBackend Backend { get; }
        public string ControlPath { get; }
        public string Container { get; }
        public string Token { get; } = new('b', 64);

        public RetainedRoute(SnapshotRecoveryFixture fixture, string? failure = null)
        {
            var raw = JsonNode.Parse(fixture.StatusJson)!;
            var status = ContainerStatusReader.Parse(fixture.StatusJson);
            Container = status.ContainerUuid;
            var child = status.Volumes.Single(v => v.ObjectId == 101);
            raw["ownerPid"] = _process.Id;
            raw["ownerStartFileTimeUtc"] = _process.StartTime.ToUniversalTime().ToFileTimeUtc();
            var row = raw["volumes"]!.AsArray().Single(v => v!["objectId"]!.GetValue<ulong>() == 101)!;
            if (failure == "capability") row["snapshotRecoverySupported"] = false;
            if (failure == "owner") raw["ownerPid"] = 0;
            if (failure == "recovery-identity") row["recoveryIdentity"] = "other";
            if (failure == "container") raw["containerUuid"] = new string('f', 32);
            var statusPath = Path.Combine(_temp.Path, "status.json");
            File.WriteAllText(statusPath, raw.ToJsonString());
            if (failure == "stale") File.SetLastWriteTimeUtc(statusPath, DateTime.UtcNow.AddMinutes(-2));
            ControlPath = Path.Combine(_temp.Path, "control");
            Backend = new(new ServiceHostOptions { EnableImageSnapshots = true, WriteBackendMode = "Native" });
            var flags = BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic;
            var hostType = typeof(NativeApfsBackend).GetNestedType("HostProcessState", BindingFlags.NonPublic)!;
            var owner = hostType.GetConstructors(flags).Single(c => c.GetParameters().Length == 8).Invoke(
                [_process, null, null, "", "", statusPath, MountAccessMode.ReadWrite, "Native"]);
            hostType.GetProperty("ContainerControlFilePath")!.SetValue(owner, ControlPath);
            hostType.GetProperty("ContainerControlToken")!.SetValue(owner, Token);
            var groupType = typeof(NativeApfsBackend).GetNestedType("ContainerGroupState", BindingFlags.NonPublic)!;
            var source = failure == "physical" ? @"\\.\PhysicalDrive2" : fixture.Source;
            var group = groupType.GetConstructors(flags).Single().Invoke(
                [Container, source, failure == "offset" ? 4096UL : 0UL, "", owner, true]);
            var memberType = typeof(NativeApfsBackend).GetNestedType("ContainerGroupMember", BindingFlags.NonPublic)!;
            var member = memberType.GetConstructors(flags).Single(c => c.GetParameters().Length == 8).Invoke(
                [child.CanonicalId, "R:\\", 101UL, failure != "readonly", child.RecoveryIdentity, true, failure != "detached", DateTime.UtcNow]);
            ((IDictionary)groupType.GetProperty("Members")!.GetValue(group)!)["R:\\"] = member;
            _groups = (IDictionary)typeof(NativeApfsBackend).GetField("_containerGroups", flags)!.GetValue(Backend)!;
            _groups[Container] = group;
            _mounts = (IDictionary)typeof(NativeApfsBackend).GetField("_mounts", flags)!.GetValue(Backend)!;
            _mounts["R:\\"] = new MountedVolumeState(child.CanonicalId, "R:\\", MountAccessMode.ReadOnly,
                DeviceId: source, RecoveryIdentity: child.RecoveryIdentity, CatalogContainerUuid: Container,
                CatalogVolumeObjectId: 101, CatalogVolumeUuid: fixture.VolumeUuid);
        }

        public void Dispose()
        {
            _groups.Clear(); _mounts.Clear(); Backend.Dispose(); _process.Dispose(); _temp.Dispose();
        }
    }
}
