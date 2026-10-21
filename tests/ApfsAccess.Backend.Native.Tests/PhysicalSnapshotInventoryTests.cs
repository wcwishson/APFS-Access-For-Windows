using System.Collections;
using System.Diagnostics;
using System.Reflection;
using System.Text.Json;
using System.Text.Json.Nodes;
using ApfsAccess.Core;

namespace ApfsAccess.Backend.Native.Tests;

public sealed class PhysicalSnapshotInventoryTests
{
    private const string Container = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    private const string Volume = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    private static LiveVolumeVerificationScope Scope => new("raw:gpt-held-window", "retained-admitted-raw",
        Container, Volume, "101", "91", "8192", "134217728");

    [Fact]
    public void PhysicalInventoryLaunchIsIndependentDefaultOffAndKeepsImageProfile()
    {
        var options = new ServiceHostOptions { WriteBackendMode = "Native", NativeWriteAllowRawPhysicalDevices = true };
        var volume = new VolumeInfo("main", @"\\.\PhysicalDrive2", "Main", true);
        var manifest = new WrittenContainerManifest("unused", "unused", Container, volume.DeviceId, 8192,
            [new(101, Container, "Main", "R:\\", true, "recovery")]);
        Assert.False(NativePhysicalSnapshotInventoryLaunch.ShouldEnable(options, manifest, volume, true));
        options.EnableRetainedPhysicalSnapshotInventory = true;
        Assert.True(NativePhysicalSnapshotInventoryLaunch.ShouldEnable(options, manifest, volume, true));
        Assert.False(NativeImageSnapshotLaunch.ShouldEnable(options, manifest, volume, true));
        Assert.False(NativePhysicalSnapshotInventoryLaunch.ShouldEnable(options, manifest with { Device = @"D:\file.apfs" }, volume, true));
        Assert.False(NativePhysicalSnapshotInventoryLaunch.ShouldEnable(options, manifest, volume, false));
        Assert.False(NativePhysicalSnapshotInventoryLaunch.ShouldEnable(options, manifest, volume with { IsEncrypted = true }, true));
        Assert.False(NativePhysicalSnapshotInventoryLaunch.ShouldEnable(options, manifest, volume with { WriteUnsupportedFeatures = ["FusionBacked"] }, true));
        options.NativeWriteAllowRawPhysicalDevices = false;
        Assert.False(NativePhysicalSnapshotInventoryLaunch.ShouldEnable(options, manifest, volume, true));
    }

    [Fact]
    public async Task ScopedListReachesSameCredentialOwnerAndRawMutationCapabilitiesStayFalse()
    {
        using var route = new Route();
        var mount = Assert.Single(await route.Backend.GetMountStateAsync(default));
        Assert.True(mount.SnapshotInventorySupported);
        Assert.False(mount.SnapshotMutationSupported); Assert.False(mount.SnapshotRecoverySupported);
        var pending = route.Send(SnapshotControlAction.List, Scope.RequestLines);
        var lines = await route.Request(pending);
        Assert.Equal("snapshot-list", lines[3]); Assert.Equal(route.Token, lines[2]);
        Assert.Equal(Scope.RequestLines, lines.Skip(5));
        var inventory = new LiveSnapshotInventory(Container, Volume, "101", "92", "8192", "134217728", []);
        await route.Reply(lines, inventory);
        var result = await pending;
        Assert.True(result.Success, result.Code); Assert.Equal("8192", result.Inventory!.StoreOffsetBytes);
        foreach (var action in new[] { SnapshotControlAction.Create, SnapshotControlAction.Delete, SnapshotControlAction.Recover })
        {
            Assert.False((await route.Send(action, action == SnapshotControlAction.Create ? ["blocked"] : null)).Success);
            Assert.False(File.Exists(route.Control));
        }
    }

    [Theory]
    [InlineData("opt-out")] [InlineData("raw-opt-out")] [InlineData("missing-scope")]
    [InlineData("scope-kind")] [InlineData("scope-base")] [InlineData("owner-start")]
    [InlineData("recovery-identity")] [InlineData("stale")] [InlineData("missing-status")]
    [InlineData("dirty-peer")] [InlineData("peer-debt")] [InlineData("missing-peer")]
    [InlineData("credential")] [InlineData("overflow")]
    public async Task PhysicalListRefusesUnprovedOwnerOrWindowBeforePublication(string failure)
    {
        using var route = new Route(failure);
        var result = await route.Send(SnapshotControlAction.List, failure == "missing-scope" ? null : Scope.RequestLines);
        Assert.False(result.Success, failure); Assert.False(File.Exists(route.Control));
    }

    [Theory]
    [InlineData("uuid")] [InlineData("size")] [InlineData("base")]
    public async Task PhysicalListBindsTypedResponseToRetainedWindow(string change)
    {
        using var route = new Route();
        var pending = route.Send(SnapshotControlAction.List, Scope.RequestLines);
        var lines = await route.Request(pending);
        var result = new LiveSnapshotInventory(Container, Volume, "101", "92", "8192", "134217728", []);
        result = change switch { "uuid" => result with { VolumeUuid = new string('f', 32) },
            "size" => result with { StoreSizeBytes = "134217729" }, _ => result with { StoreOffsetBytes = "0" } };
        await route.Reply(lines, result);
        Assert.Equal("ControlResponseInvalid", (await pending).Code);
    }

    [Fact]
    public void TypedInventoryWindowRejectsOverflowAndMatchesCurrentScopeWithoutDiscoveryXid()
    {
        var inventory = new LiveSnapshotInventory(Container, Volume, "101", "92", "8192", "134217728", []);
        Assert.True(LiveSnapshotInventory.Parse(inventory.ToJson()).MatchesScope(Scope));
        Assert.Throws<InvalidDataException>(() => LiveSnapshotInventory.Parse(
            (inventory with { StoreOffsetBytes = ulong.MaxValue.ToString() }).ToJson()));
    }

    // This fixture tests managed retained routing only. It creates no raw lease or host.
    private sealed class Route : IDisposable
    {
        private const BindingFlags Flags = BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic;
        private readonly DTempDirectory _temp = DTempDirectory.Create("physical-snapshot-inventory");
        private readonly Process _process = Process.GetCurrentProcess();
        private readonly IDictionary _groups, _mounts;
        public NativeApfsBackend Backend { get; }
        public string Control { get; }
        public string Token { get; } = new('b', 64);
        public Route(string? failure = null)
        {
            Control = Path.Combine(_temp.Path, "control");
            var statusPath = Path.Combine(_temp.Path, "status.json");
            var scope = Scope;
            if (failure == "scope-kind") scope = scope with { SourceKind = "retained-image" };
            if (failure == "scope-base") scope = scope with { StoreOffsetBytes = "0" };
            if (failure == "overflow") scope = scope with { StoreSizeBytes = ulong.MaxValue.ToString() };
            object Row(ulong oid) => new
            {
                objectId = oid.ToString(), canonicalId = $"apfs-vol:{Container}:{oid}", mounted = true, ready = true, writable = true,
                recoveryActive = false, writeDegraded = false, recoveryReason = "", recoveryIdentity = failure == "recovery-identity" && oid == 101 ? "replacement" : $"rec-{oid}",
                snapshotInventorySupported = true, snapshotMutationSupported = true, snapshotRecoverySupported = true,
                volumeVerificationSupported = true,
                volumeVerificationScope = new { sourceIdentity = scope.SourceIdentity, sourceKind = scope.SourceKind,
                    containerUuid = Container, volumeUuid = oid == 101 ? Volume : new string('c', 32), volumeOid = oid.ToString(),
                    checkpointXid = "91", storeOffsetBytes = scope.StoreOffsetBytes, storeSizeBytes = scope.StoreSizeBytes },
                dirtyTransactionCount = failure == "dirty-peer" && oid == 102 ? 1 : 0, inFlightMutationCallbacks = 0,
                closeCommitDeferred = false, deferredCommitRequested = false, deferredCommitInFlight = false, shutdownDrainActive = false,
                walAcceptedSequence = failure == "peer-debt" && oid == 102 ? "2" : "1", walApfsDurableSequence = "1", walCleanupSequence = "1",
                walRecoveryStateValid = true, payloadSpoolDirtyRangeCount = "0", payloadSpoolIndexDirty = false,
                payloadSpoolRecoveryRequired = false
            };
            File.WriteAllText(statusPath, JsonSerializer.Serialize(new { containerUuid = Container, ownerPid = _process.Id,
                ownerStartFileTimeUtc = _process.StartTime.ToUniversalTime().ToFileTimeUtc() + (failure == "owner-start" ? 1 : 0),
                leaseHeld = true, checkpointXid = "91", recoveryRequired = false, recoveryVolumeObjectId = (string?)null, recoveryReason = "",
                volumes = failure == "missing-peer" ? new[] { Row(101) } : new[] { Row(101), Row(102) } }));
            if (failure == "stale") File.SetLastWriteTimeUtc(statusPath, DateTime.UtcNow.AddMinutes(-2));
            if (failure == "missing-status") File.Delete(statusPath);
            Backend = new(new ServiceHostOptions { EnableImageSnapshots = true, EnableRetainedPhysicalSnapshotInventory = failure != "opt-out",
                NativeWriteAllowRawPhysicalDevices = failure != "raw-opt-out", WriteBackendMode = "Native" });
            var hostType = typeof(NativeApfsBackend).GetNestedType("HostProcessState", BindingFlags.NonPublic)!;
            var owner = hostType.GetConstructors(Flags).Single(c => c.GetParameters().Length == 8).Invoke(
                [_process, null, null, "", "", statusPath, MountAccessMode.ReadWrite, "Native"]);
            hostType.GetProperty("ContainerControlFilePath")!.SetValue(owner, Control);
            hostType.GetProperty("ContainerControlToken")!.SetValue(owner, failure == "credential" ? "" : Token);
            var groupType = typeof(NativeApfsBackend).GetNestedType("ContainerGroupState", BindingFlags.NonPublic)!;
            var group = groupType.GetConstructors(Flags).Single().Invoke([Container, @"\\.\PhysicalDrive2", 8192UL, "", owner, true]);
            var memberType = typeof(NativeApfsBackend).GetNestedType("ContainerGroupMember", BindingFlags.NonPublic)!;
            var members = (IDictionary)groupType.GetProperty("Members")!.GetValue(group)!;
            foreach (var oid in new[] { 101UL, 102UL })
            {
                var point = oid == 101 ? "R:\\" : "S:\\";
                members[point] = memberType.GetConstructors(Flags).Single(c => c.GetParameters().Length == 8).Invoke(
                    [$"apfs-vol:{Container}:{oid}", point, oid, true, $"rec-{oid}", true, true, DateTime.UtcNow]);
            }
            _groups = (IDictionary)typeof(NativeApfsBackend).GetField("_containerGroups", Flags)!.GetValue(Backend)!;
            _groups[Container] = group;
            _mounts = (IDictionary)typeof(NativeApfsBackend).GetField("_mounts", Flags)!.GetValue(Backend)!;
            _mounts["R:\\"] = new MountedVolumeState($"apfs-vol:{Container}:101", "R:\\", MountAccessMode.ReadWrite,
                DeviceId: @"\\.\PhysicalDrive2", RecoveryIdentity: "rec-101", CatalogContainerUuid: Container, CatalogVolumeObjectId: 101, CatalogVolumeUuid: Volume);
        }
        public Task<SnapshotControlResult> Send(SnapshotControlAction action, IReadOnlyList<string>? extras)
            => Backend.SendSnapshotControlAsync(Container, 101, action, extras, default);
        public async Task<string[]> Request(Task<SnapshotControlResult> pending)
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            while (!pending.IsCompleted && !File.Exists(Control)) await Task.Delay(5, timeout.Token);
            Assert.True(File.Exists(Control), pending.IsCompleted ? (await pending).Code : "No request");
            return await File.ReadAllLinesAsync(Control, timeout.Token);
        }
        public async Task Reply(string[] lines, LiveSnapshotInventory inventory)
        {
            await File.WriteAllTextAsync(Control + ".tmp", $"APFS-CONTROL/1\n{lines[1]}\nok\nSnapshotInventory\nsnapshot-inventory-json/1\n{inventory.ToJson().GetRawText()}\n");
            File.Move(Control + ".tmp", Control + ".response");
        }
        public void Dispose() { _groups.Clear(); _mounts.Clear(); Backend.Dispose(); _process.Dispose(); _temp.Dispose(); }
    }
}
