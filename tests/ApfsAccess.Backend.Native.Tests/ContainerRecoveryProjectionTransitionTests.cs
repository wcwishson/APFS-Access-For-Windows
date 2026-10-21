using System.Collections;
using System.Diagnostics;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json.Nodes;
using ApfsAccess.Core;

namespace ApfsAccess.Backend.Native.Tests;

public sealed class ContainerRecoveryProjectionTransitionTests
{
    public static IEnumerable<object[]> RecoveryTransitions()
    {
        foreach (var name in new[] { "ordinary.bin", "ordinary.apfs", "ordinary.img", "ordinary.apfs.img", "ordinary.fixture", "ordinary.apfs.fixture" })
        foreach (var readiness in new[] { NativeWriteReadiness.RecoveryMode, NativeWriteReadiness.Degraded })
            yield return [name, readiness];
    }

    public static IEnumerable<object[]> RefusalTransitions()
    {
        foreach (var name in new[] { "ordinary.bin", "ordinary.apfs" })
        foreach (var failure in new[] { "dirty", "unknown", "stale", "stale-owner", "lease-lost", "callbacks", "deferred" })
            yield return [name, failure];
    }

    [RecoveryProjectionStatusTheory]
    [MemberData(nameof(RecoveryTransitions))]
    public async Task FirstFreshCleanStatusAfterRecoveryOrDegradedIsHealthyAndRepeatedProbeIsStable(
        string name, NativeWriteReadiness previousReadiness)
    {
        using var route = new RetainedProjection(name);
        var disabled = Captured("disabled-native-status.json");
        var previous = Child(disabled);
        previous["recoveryActive"] = previousReadiness == NativeWriteReadiness.RecoveryMode;
        route.Publish(disabled);
        var before = await route.Probe();
        Assert.Equal(previousReadiness, before.NativeWriteReadiness);
        Assert.False(StrictFreshRwHealthy(before));

        route.Publish(Captured("recovered-native-status.json"));
        var statusBytes = File.ReadAllBytes(route.StatusPath);
        var first = await route.Probe();
        Assert.True(StrictFreshRwHealthy(first), $"The FIRST fresh probe must be healthy: {name}, {previousReadiness}, {first.NativeWriteSafetyState}.");
        Assert.Equal(MountAccessMode.ReadWrite, first.AccessMode);
        Assert.Equal("Native", first.WriteBackend);
        Assert.Equal(NativeWriteSafetyState.PilotReadWrite, first.NativeWriteSafetyState);
        Assert.Equal(route.IsFixture ? NativeWriteReadiness.Unavailable : NativeWriteReadiness.CommitReady, first.NativeWriteReadiness);
        Assert.Equal(route.IsFixture ? NativeWriteCommitModel.ScaffoldCheckpoint : NativeWriteCommitModel.CanonicalApfsCheckpoint, first.CommitModel);
        Assert.False(first.RecoveryActive);
        Assert.Null(first.RecoveryReason);
        Assert.Equal(0, first.DirtyTransactionCount);
        Assert.Equal(6UL, first.WalAcceptedSequence);
        Assert.Equal(6UL, first.WalApfsDurableSequence);
        Assert.Equal(6UL, first.WalCleanupSequence);
        Assert.Equal(9UL, first.LastCommitXid);
        Assert.Equal(before.HostProcessId, first.HostProcessId);
        Assert.Equal(before.RecoveryIdentity, first.RecoveryIdentity);
        Assert.Equal(before.CatalogVolumeObjectId, first.CatalogVolumeObjectId);
        Assert.Equal(before.CatalogContainerUuid, first.CatalogContainerUuid);
        Assert.Equal(before.CatalogVolumeUuid, first.CatalogVolumeUuid);
        Assert.NotNull(first.VolumeVerificationScope);
        Assert.Equal("101", first.VolumeVerificationScope.VolumeOid);
        Assert.Equal("9", first.VolumeVerificationScope.CheckpointXid);

        // Repetition verifies stability only after the first probe has independently passed.
        var repeated = await route.Probe();
        Assert.Equal(first, repeated);
        Assert.True(StrictFreshRwHealthy(repeated));
        Assert.Equal(statusBytes, File.ReadAllBytes(route.StatusPath));
        Assert.False(File.Exists(route.ControlPath));
    }

    [RecoveryProjectionStatusTheory]
    [MemberData(nameof(RefusalTransitions))]
    public async Task NewDirtyUnknownOrStaleOwnerCannotReusePreviousHealthyProjection(string name, string failure)
    {
        using var route = new RetainedProjection(name);
        route.Publish(Captured("recovered-native-status.json"));
        Assert.True(StrictFreshRwHealthy(await route.Probe()));
        var raw = Captured("recovered-native-status.json");
        var child = Child(raw);
        switch (failure)
        {
            case "dirty": child["dirtyTransactionCount"] = 1; child["walAcceptedSequence"] = 7; break;
            case "callbacks": child["inFlightMutationCallbacks"] = 1; break;
            case "deferred": child["deferredCommitRequested"] = true; break;
            case "lease-lost": raw["leaseHeld"] = false;
                foreach (var volume in raw["volumes"]!.AsArray())
                {
                    volume!["snapshotInventorySupported"] = false; volume["snapshotMutationSupported"] = false;
                    volume["snapshotRecoverySupported"] = false; volume["volumeVerificationSupported"] = false;
                    volume["volumeVerificationScope"] = null;
                }
                break;
        }
        route.Publish(raw, failure == "stale-owner" ? 1 : 0);
        if (failure == "unknown") File.WriteAllText(route.StatusPath, "{malformed");
        if (failure == "stale") File.SetLastWriteTimeUtc(route.StatusPath, DateTime.UtcNow.AddMinutes(-2));
        var first = await route.Probe();
        Assert.False(StrictFreshRwHealthy(first));
        if (failure is "dirty" or "callbacks" or "deferred")
        {
            Assert.True(first.RuntimeWatermarksKnown);
            Assert.True(first.RuntimeMutationPending);
        }
        else
        {
            Assert.Equal(MountAccessMode.ReadOnly, first.AccessMode);
            Assert.Equal(NativeWriteReadiness.Unavailable, first.NativeWriteReadiness);
            Assert.Equal(NativeWriteSafetyState.ReadOnlyFallback, first.NativeWriteSafetyState);
        }
        var repeated = await route.Probe();
        Assert.False(StrictFreshRwHealthy(repeated));
        Assert.Equal(first, repeated);
        Assert.False(File.Exists(route.ControlPath));
    }

    private static JsonObject Captured(string name)
    {
        var root = Environment.GetEnvironmentVariable("APFSACCESS_RECOVERY_PROJECTION_STATUS_DIR")!;
        var bytes = File.ReadAllBytes(Path.Combine(root, name));
        Assert.Equal(name == "disabled-native-status.json"
            ? "A81A7C30BC45A45F997B8B12BBE13C2EFF1724D116CB0F4057894E7879D82009"
            : "A84DBA602862D25CC8ED75596FA1D99250B6209A270D97A1C37A35B221861662", Convert.ToHexString(SHA256.HashData(bytes)));
        return JsonNode.Parse(bytes)!.AsObject();
    }

    private static JsonNode Child(JsonNode raw)
        => raw["volumes"]!.AsArray().Single(v => v!["objectId"]!.GetValue<ulong>() == 101)!;

    private static bool StrictFreshRwHealthy(MountedVolumeState mount)
        => mount.MountReady && mount.AccessMode == MountAccessMode.ReadWrite && mount.WriteBackend == "Native" &&
           !mount.RecoveryActive && mount.DirtyTransactionCount == 0 && !mount.ShutdownDrainActive &&
           mount.InFlightMutationCallbacks == 0 && mount.RuntimeWatermarksKnown == true && !mount.RuntimeMutationPending &&
           mount.WalAcceptedSequence == mount.WalApfsDurableSequence && mount.WalAcceptedSequence == mount.WalCleanupSequence &&
           mount.VolumeVerificationSupported && mount.VolumeVerificationScope is not null &&
           mount.NativeWriteSafetyState is NativeWriteSafetyState.PilotReadWrite or NativeWriteSafetyState.StableReadWrite;

    // Replay captured status with a test PID/start and retained member; no native host, mount, lease, or control dispatch.
    private sealed class RetainedProjection : IDisposable
    {
        private const BindingFlags Flags = BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic;
        private readonly DTempDirectory _temp = DTempDirectory.Create("recovery-projection-transition");
        private readonly Process _process = Process.GetCurrentProcess();
        private readonly NativeApfsBackend _backend;
        private readonly IDictionary _groups;
        private readonly IDictionary _mounts;
        public string StatusPath { get; }
        public string ControlPath { get; }
        public bool IsFixture { get; }

        public RetainedProjection(string name)
        {
            StatusPath = Path.Combine(_temp.Path, "status.json");
            ControlPath = Path.Combine(_temp.Path, "control");
            IsFixture = name != "ordinary.bin";
            _backend = new(new ServiceHostOptions { EnableImageSnapshots = true, WriteBackendMode = "Native", NativeAutoRemountOnReconnect = false });
            var raw = Captured("recovered-native-status.json");
            var container = raw["containerUuid"]!.GetValue<string>();
            var child = Child(raw);
            var canonical = child["canonicalId"]!.GetValue<string>();
            var recovery = child["recoveryIdentity"]!.GetValue<string>();
            var source = Path.Combine(_temp.Path, name);
            var type = typeof(NativeApfsBackend);
            var hostType = type.GetNestedType("HostProcessState", BindingFlags.NonPublic)!;
            var owner = hostType.GetConstructors(Flags).Single(c => c.GetParameters().Length == 8).Invoke(
                [_process, null, null, "", "", StatusPath, MountAccessMode.ReadWrite, "Native"]);
            hostType.GetProperty("ContainerControlFilePath")!.SetValue(owner, ControlPath);
            hostType.GetProperty("ContainerControlToken")!.SetValue(owner, new string('b', 64));
            var groupType = type.GetNestedType("ContainerGroupState", BindingFlags.NonPublic)!;
            var group = groupType.GetConstructors(Flags).Single().Invoke([container, source, 0UL, "", owner, true]);
            var memberType = type.GetNestedType("ContainerGroupMember", BindingFlags.NonPublic)!;
            var member = memberType.GetConstructors(Flags).Single(c => c.GetParameters().Length == 8).Invoke(
                [canonical, "R:\\", 101UL, true, recovery, true, true, DateTime.UtcNow]);
            ((IDictionary)groupType.GetProperty("Members")!.GetValue(group)!)["R:\\"] = member;
            _groups = (IDictionary)type.GetField("_containerGroups", Flags)!.GetValue(_backend)!;
            _mounts = (IDictionary)type.GetField("_mounts", Flags)!.GetValue(_backend)!;
            _groups[container] = group;
            _mounts["R:\\"] = new MountedVolumeState(canonical, "R:\\", MountAccessMode.ReadOnly,
                DeviceId: source, RecoveryIdentity: recovery, CatalogContainerUuid: container, CatalogVolumeObjectId: 101,
                CatalogVolumeUuid: child["volumeVerificationScope"]!["volumeUuid"]!.GetValue<string>(), CatalogVolumeId: canonical);
        }

        public void Publish(JsonObject raw, long ownerStartDelta = 0)
        {
            raw["ownerPid"] = _process.Id;
            raw["ownerStartFileTimeUtc"] = _process.StartTime.ToUniversalTime().ToFileTimeUtc() + ownerStartDelta;
            File.WriteAllText(StatusPath, raw.ToJsonString());
        }

        public async Task<MountedVolumeState> Probe() => Assert.Single(await _backend.GetMountStateAsync(default));
        public void Dispose() { _groups.Clear(); _mounts.Clear(); _backend.Dispose(); _process.Dispose(); _temp.Dispose(); }
    }
}

internal sealed class RecoveryProjectionStatusTheoryAttribute : TheoryAttribute
{
    public RecoveryProjectionStatusTheoryAttribute()
    {
        if (Environment.GetEnvironmentVariable("APFSACCESS_RECOVERY_PROJECTION_STATUS_DIR") is null)
            Skip = "Requires pinned captured Tesla dirty/recovered native status; replay uses no native runtime.";
    }
}
