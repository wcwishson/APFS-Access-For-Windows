using System.Reflection;
using ApfsAccess.Core;
using ApfsAccess.Ipc;
using ApfsAccess.Service;
using ApfsAccess.Tray;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace ApfsAccess.Tray.Tests;

public sealed partial class TopologyStatusIntegrationTests
{
    private const string Hex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    private static string Id(ulong oid) => ApfsTopology.BuildVolumeId(Hex, oid);
    private static DeviceInventory Inventory(long generation = 1)
    {
        var container = ApfsTopology.BuildContainerId(Hex);
        ApfsVolumeRecord V(ulong oid) => new(Id(oid), Guid.NewGuid().ToString("D"), oid.ToString(), container,
            "Same name", true, ["data"], 32, null, "sensitive", "none", false, [], [], [], "1", "7");
        var topology = new ApfsTopologySnapshot([new("apfs-disk:d", "d", null, 100000)], [],
            [new("apfs-store:raw", Hex, "", container, 0, 100000, DiskId: "apfs-disk:d")],
            [new(container, Hex, 4096, ["apfs-store:raw"], [Id(201), Id(202)], false, "7", [], [], [])],
            [V(201), V(202)], []);
        return new(new("d", "Disk", true), topology.Volumes.Select((v, i) => new VolumeInfo(v.Id, "d", v.Name, true,
            RecoveryIdentity: "recovery-" + v.ObjectId, CatalogVolumeId: v.Id, CatalogContainerUuid: Hex,
            CatalogVolumeObjectId: (ulong)(201 + i), CatalogDecision: ApfsCapabilityDecision.Writable,
            CatalogAutoMountAllowed: true, CatalogReasons: [], CatalogVolumeUuid: v.Uuid)).ToArray(), new(generation, "d", ["apfs-disk:d"], topology));
    }

    [Theory]
    [InlineData("disk-source")]
    [InlineData("uuid")]
    [InlineData("container-uuid")]
    [InlineData("object-id")]
    [InlineData("null-container-features")]
    [InlineData("huge-container-features")]
    [InlineData("unsupported")]
    [InlineData("special-role")]
    [InlineData("empty-role")]
    public void ConflictingTopologyEvidenceCannotAuthorizeMount(string mutation)
    {
        var d = Inventory(); var t = d.Topology!.Snapshot;
        t = mutation switch {
            "disk-source" => t with { Disks = [t.Disks[0] with { DeviceIdentifier = "other" }] },
            "uuid" => t with { Volumes = [t.Volumes[0] with { Uuid = Guid.NewGuid().ToString("D") }, t.Volumes[1]] },
            "container-uuid" => t with { Containers = [t.Containers[0] with { Uuid = Guid.NewGuid().ToString("D") }] },
            "object-id" => t with { Volumes = [t.Volumes[0] with { ObjectId = "999" }, t.Volumes[1]] },
            "null-container-features" => t with { Containers = [t.Containers[0] with { UnknownFeatureBits = null! }] },
            "huge-container-features" => t with { Containers = [t.Containers[0] with { CompatibleFeatureBits = Enumerable.Repeat("bit", 4097).ToArray() }] },
            "unsupported" => t with { Containers = [t.Containers[0] with { UnknownFeatureBits = ["unknown"] }] },
            "special-role" => t with { Volumes = [t.Volumes[0] with { Roles = ["system"] }, t.Volumes[1]] },
            _ => t with { Volumes = [t.Volumes[0] with { Roles = [] }, t.Volumes[1]] }
        };
        d = d with { Topology = d.Topology with { Snapshot = t } };
        var status = new StatusChangedPayload(RuntimeState.Idle, [], null, DateTime.UtcNow, [], false, [],
            ConnectedInventory: [d], InventoryGeneration: 1);
        var rows = TopologyDashboard.Project(status).Where(n => n.Row?.VolumeId == Id(201)).Select(n => n.Row!).ToArray();
        Assert.All(rows, r => { Assert.False(r.CanFix); Assert.False(r.CanInspectReadOnly); });
    }

    [Fact]
    public void ChangedVolumeUuidRejectsThePreviouslySelectedMountRow()
    {
        var d = Inventory();
        var status = new StatusChangedPayload(RuntimeState.Idle, [], null, DateTime.UtcNow, [], false, [],
            ConnectedInventory: [d], InventoryGeneration: 1);
        var selected = TopologyDashboard.Project(status).Single(n => n.Row?.VolumeId == Id(201)).Row!;
        var replacement = Guid.NewGuid().ToString("D");
        d = d with { Volumes = [d.Volumes[0] with { CatalogVolumeUuid = replacement }, d.Volumes[1]],
            Topology = d.Topology! with { Snapshot = d.Topology.Snapshot with {
                Volumes = [d.Topology.Snapshot.Volumes[0] with { Uuid = replacement }, d.Topology.Snapshot.Volumes[1]] } } };
        var current = status with { ConnectedInventory = [d], InventoryGeneration = 2 };
        Assert.Throws<InvalidOperationException>(() => DriveDashboardPresenter.CreateMountRequest(current, selected));
        Assert.NotNull(DriveDashboardPresenter.CreateMountRequest(current,
            TopologyDashboard.Project(current).Single(n => n.Row?.VolumeId == Id(201)).Row!));
    }

    private static MountedVolumeState Mount(VolumeInfo v, string drive, bool rw) => new(v.VolumeId, drive,
        rw ? MountAccessMode.ReadWrite : MountAccessMode.ReadOnly, v.VolumeName, v.DeviceId, "Disk",
        NativeWriteSafetyState: rw ? NativeWriteSafetyState.StableReadWrite : NativeWriteSafetyState.ReadOnlyFallback,
        RecoveryIdentity: v.RecoveryIdentity, MountReady: true, CatalogVolumeId: v.CatalogVolumeId,
        CatalogContainerUuid: v.CatalogContainerUuid, CatalogVolumeObjectId: v.CatalogVolumeObjectId,
        CatalogDecision: v.CatalogDecision, CatalogAutoMountAllowed: v.CatalogAutoMountAllowed,
        CatalogReasons: v.CatalogReasons, CatalogVolumeUuid: v.CatalogVolumeUuid);

    private static ApfsMountWorker Worker(Backend backend, RuntimeStatusPublisher publisher)
        => new(NullLogger<ApfsMountWorker>.Instance, backend, new Policy(), publisher, new Options());
    private static Task Cycle(ApfsMountWorker worker) => (Task)typeof(ApfsMountWorker)
        .GetMethod("RunCycleAsync", BindingFlags.NonPublic | BindingFlags.Instance)!.Invoke(worker, [CancellationToken.None])!;
    private static StatusChangedPayload Wire(RuntimeStatusPublisher publisher)
    {
        var encoded = PipeMessageCodec.Serialize(PipeMessageCodec.Create(ApfsMessageTypes.StatusChanged, publisher.Latest));
        Assert.True(PipeMessageCodec.TryDeserialize(encoded, out var envelope));
        Assert.True(PipeMessageCodec.TryGetPayload<StatusChangedPayload>(envelope!, out var decoded));
        return decoded!;
    }

    [Fact]
    public async Task RealServiceStatusAndWirePreserveSameNameIdentityHealthAndSelectedActions()
    {
        var d = Inventory(); var backend = new Backend { Devices = [d], Mounts = [Mount(d.Volumes[0], "R:\\", true), Mount(d.Volumes[1], "S:\\", false)] };
        var publisher = new RuntimeStatusPublisher(); using var worker = Worker(backend, publisher);
        await Cycle(worker);
        var status = Wire(publisher);
        Assert.Equal(1, status.InventoryGeneration);
        Assert.Equal(d.Topology!.Generation, status.ConnectedInventory![0].Topology!.Generation);
        var nodes = TopologyDashboard.Project(status);
        var a = Assert.Single(nodes, n => n.Row?.VolumeId == Id(201));
        var b = Assert.Single(nodes, n => n.Row?.VolumeId == Id(202));
        Assert.Equal(DashboardPalette.Green, a.Palette);
        Assert.Equal(DashboardPalette.Yellow, b.Palette);
        Assert.Equal(DashboardPalette.Yellow, nodes.Single(n => n.Id == a.ParentId).Palette);
        Assert.False(a.Row!.CanFix); Assert.True(b.Row!.CanFix);
        Sta(() =>
        {
            string? opened = null, ejected = null, fixedId = null;
            using var form = new DashboardForm(p => { opened = p; return Task.CompletedTask; },
                id => { ejected = id; return Task.CompletedTask; }, id => { fixedId = id; return Task.CompletedTask; });
            form.ApplyStatus(status); // The actual application status entry point, no injected snapshot.
            var tree = Controls(form).OfType<TreeView>().Single(); _ = tree.Handle;
            tree.SelectedNode = tree.Nodes.Find(b.Id, true).Single();
            Click(form, "Open"); Click(form, "Eject"); Click(form, "Fix");
            Assert.Equal("S:\\", opened); Assert.Equal(Id(202), ejected); Assert.Equal(Id(202), fixedId);
            var selected = tree.SelectedNode;
            form.ApplyStatus(status with { TimestampUtc = status.TimestampUtc.AddSeconds(1) });
            Assert.Same(selected, tree.SelectedNode); Assert.False(form.Visible);
        });
    }

    [Fact]
    public async Task UnmountedSelectionBuildsRealExactRequestAndReachesExistingWorkerCallback()
    {
        var backend = new Backend { Devices = [Inventory()] }; var publisher = new RuntimeStatusPublisher();
        using var worker = Worker(backend, publisher);
        await worker.GetInventoryAsync(default);
        var status = Wire(publisher);
        ControlOperationRequestPayload? request = null;
        Sta(() =>
        {
            using var form = new DashboardForm(_ => Task.CompletedTask, _ => Task.CompletedTask, _ => Task.CompletedTask,
                mountVolumeAsync: row => { request = DriveDashboardPresenter.CreateMountRequest(status, row); return Task.CompletedTask; });
            form.ApplyStatus(status);
            var tree = Controls(form).OfType<TreeView>().Single(); _ = tree.Handle;
            tree.SelectedNode = AllNodes(tree.Nodes).Single(n => (n.Tag as TopologyDashboardNode)?.Row?.VolumeId == Id(202));
            Click(form, "Mount"); Assert.False(form.Visible);
        });
        Assert.Equal(SelectedControlTarget.Create(backend.Devices[0], backend.Devices[0].Volumes[1]), request!.Target);
        // Existing service selection path, with an in-memory backend only.
        await worker.EnsureMountedExactAsync(request.Target!.DeviceId, request.Target.VolumeId,
            MountAccessMode.ReadOnly, default, request.Target.RecoveryIdentity);
        Assert.NotEmpty(backend.Requests);
        Assert.All(backend.Requests, r => Assert.Equal(Id(202), r.VolumeId));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task DisconnectOrFailedNewGenerationClearsTopologyAndDisablesRetainedMounts(bool failure)
    {
        var d = Inventory(); var backend = new Backend { Devices = [d], Mounts = [Mount(d.Volumes[0], "R:\\", true)] };
        var publisher = new RuntimeStatusPublisher(); using var worker = Worker(backend, publisher);
        await Cycle(worker); var first = Wire(publisher);
        backend.Devices = []; backend.Fail = failure;
        if (failure) await Assert.ThrowsAsync<IOException>(() => worker.GetInventoryAsync(default));
        else await worker.GetInventoryAsync(default);
        var latest = Wire(publisher);
        Assert.True(latest.InventoryGeneration > first.InventoryGeneration); Assert.Empty(latest.ConnectedInventory!);
        var rows = TopologyDashboard.Project(latest).Where(n => n.Row is not null).Select(n => n.Row!).ToArray();
        Assert.Single(rows); Assert.All(rows, AssertDisabled);
        Assert.True(TrayApplicationContext.IsOlderStatus(latest, first));
        Sta(() =>
        {
            using var form = new DashboardForm(_ => Task.CompletedTask, _ => Task.CompletedTask, _ => Task.CompletedTask);
            form.ApplyStatus(latest); form.ApplyStatus(first);
            Assert.DoesNotContain(AllNodes(Controls(form).OfType<TreeView>().Single().Nodes), n => (n.Tag as TopologyDashboardNode)?.Row?.CanOpen == true);
        });
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task OlderSlowSuccessOrFailureCannotRestoreOrEraseNewerObservation(bool oldFails)
    {
        var backend = new Backend { Devices = [Inventory()], Pause = true, FailPaused = oldFails };
        var publisher = new RuntimeStatusPublisher(); using var worker = Worker(backend, publisher);
        var old = worker.GetInventoryAsync(default);
        await backend.Entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        backend.Devices = [Inventory(20)];
        try
        {
            await worker.GetInventoryAsync(default); var generation = publisher.Latest.InventoryGeneration;
            backend.Release.TrySetResult();
            if (oldFails) await Assert.ThrowsAsync<IOException>(() => old); else await old;
            var status = Wire(publisher);
            Assert.Equal(generation, status.InventoryGeneration);
            Assert.Equal(20, status.ConnectedInventory![0].Topology!.Generation);
        }
        finally { backend.Release.TrySetResult(); }
    }

    [Theory]
    [InlineData("duplicate")]
    [InlineData("cycle")]
    [InlineData("missing")]
    [InlineData("null")]
    [InlineData("huge")]
    [InlineData("wrong-device")]
    public async Task MalformedStatusCannotThrowOrEnableAnyTarget(string mutation)
    {
        var d = Inventory(); var t = d.Topology!.Snapshot;
        t = mutation switch
        {
            "duplicate" => t with { Volumes = [t.Volumes[0], t.Volumes[0]] },
            "cycle" => t with { Stores = [t.Stores[0] with { PartitionId = t.Containers[0].Id, DiskId = null }] },
            "missing" => t with { Containers = [t.Containers[0] with { StoreIds = ["apfs-store:missing"] }] },
            "null" => t with { Volumes = null! },
            "huge" => t with { Disks = Enumerable.Repeat(t.Disks[0], 4097).ToArray() },
            _ => t
        };
        d = d with { Topology = d.Topology with { Snapshot = t, DeviceId = mutation == "wrong-device" ? "other" : "d" } };
        var backend = new Backend { Devices = [d] }; var publisher = new RuntimeStatusPublisher(); using var worker = Worker(backend, publisher);
        await worker.GetInventoryAsync(default); var status = Wire(publisher);
        var nodes = TopologyDashboard.Project(status);
        Assert.All(nodes.Where(n => n.Row is not null), n => AssertDisabled(n.Row!));
        Assert.Throws<InvalidOperationException>(() => DriveDashboardPresenter.CreateMountRequest(status,
            DriveDashboardPresenter.BuildRows(status).First()));
        Sta(() =>
        {
            using var form = new DashboardForm(_ => Task.CompletedTask, _ => Task.CompletedTask, _ => Task.CompletedTask);
            form.ApplyStatus(status); Assert.False(form.Visible);
        });
    }

    [Fact]
    public async Task UnrelatedCatalogMountAndOtherDeviceNeverAttachToSelectedTopology()
    {
        var d = Inventory(); var publisher = new RuntimeStatusPublisher();
        var backend = new Backend { Devices = [d], Mounts = [Mount(d.Volumes[0], "R:\\", true) with { DeviceId = "other" },
            Mount(d.Volumes[1], "S:\\", false) with { CatalogVolumeId = Id(202).ToUpperInvariant() },
            Mount(d.Volumes[0], "T:\\", true) with { CatalogVolumeUuid = Guid.NewGuid().ToString("N") }] };
        using var worker = Worker(backend, publisher); await Cycle(worker);
        var nodes = TopologyDashboard.Project(Wire(publisher));
        Assert.All(nodes.Where(n => n.Row?.IsMounted == true), n => { Assert.Null(n.ParentId); AssertDisabled(n.Row!); });
        Assert.All(nodes.Where(n => n.Row is { IsMounted: false }), n => Assert.Equal("", n.Row!.MountPoint));
    }

    [Fact]
    public async Task LegacyBackendAndLegacyStatusRemainUsableWithoutTopology()
    {
        var d = Inventory() with { Topology = null }; var backend = new Backend { Devices = [d] };
        var publisher = new RuntimeStatusPublisher(); using var worker = Worker(backend, publisher);
        await worker.GetInventoryAsync(default);
        Assert.Contains(TopologyDashboard.Project(Wire(publisher)), n => n.Row?.CanFix == true);
        var legacy = new StatusChangedPayload(RuntimeState.MountedRo, ["R:\\"], null, DateTime.UtcNow, [], false, [],
            [new("legacy", "R:\\", "Name", "d", "Disk", MountAccessMode.ReadOnly)]);
        Assert.Contains(TopologyDashboard.Project(legacy), n => n.Row?.CanEject == true);
    }

    private static void AssertDisabled(DriveDashboardRow r)
    { Assert.False(r.CanOpen); Assert.False(r.CanEject); Assert.False(r.CanFix); Assert.False(r.CanInspectReadOnly); Assert.Null(r.DriveLetterPreference); }
    private static void Click(Control root, string text) => typeof(Button).GetMethod("OnClick", BindingFlags.Instance | BindingFlags.NonPublic)!
        .Invoke(Controls(root).OfType<Button>().Single(b => b.Text == text), [EventArgs.Empty]);
    private static IEnumerable<Control> Controls(Control root)
    { foreach (Control c in root.Controls) { yield return c; foreach (var child in Controls(c)) yield return child; } }
    private static IEnumerable<TreeNode> AllNodes(TreeNodeCollection nodes)
    { foreach (TreeNode n in nodes) { yield return n; foreach (var child in AllNodes(n.Nodes)) yield return child; } }
    private static void Sta(Action action)
    {
        Exception? error = null; var thread = new Thread(() => { try { action(); } catch (Exception e) { error = e; } });
        thread.SetApartmentState(ApartmentState.STA); thread.Start(); Assert.True(thread.Join(TimeSpan.FromSeconds(15)));
        if (error is not null) System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(error).Throw();
    }
    private sealed class Options : IOptionsMonitor<ServiceHostOptions>
    {
        public ServiceHostOptions CurrentValue { get; } = new() { AutoMountEnabled = false, EnableNativeWrite = false };
        public ServiceHostOptions Get(string? name) => CurrentValue;
        public IDisposable? OnChange(Action<ServiceHostOptions, string?> listener) => null;
    }
    private sealed class Policy : IMountPolicy
    { public char SelectDriveLetter(VolumeInfo v, IReadOnlySet<char> used) => 'R'; public bool ShouldAutoMount(VolumeInfo v) => false; }
    private sealed class Backend : IApfsBackend
    {
        public DeviceInventory[] Devices = []; public MountedVolumeState[] Mounts = [];
        public bool Fail, Pause, FailPaused; public int Calls; public Action<int>? BeforeProbe; public int UnmountCalls; public bool SucceedMutations; public List<MountRequest> Requests = [];
        public TaskCompletionSource Entered = new(TaskCreationOptions.RunContinuationsAsynchronously), Release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public async Task<IReadOnlyList<DeviceInventory>> ProbeInventoryAsync(bool authoritative, CancellationToken token)
        {
            Assert.True(authoritative); BeforeProbe?.Invoke(Calls + 1); var result = Devices;
            if (Interlocked.Increment(ref Calls) == 1 && Pause)
            { Entered.SetResult(); await Release.Task.WaitAsync(token); if (FailPaused) throw new IOException("failed older observation"); }
            if (Fail) throw new IOException("failed observation"); return result;
        }
        public Task<IReadOnlyList<DeviceInfo>> ProbeDevicesAsync(CancellationToken t) => throw new InvalidOperationException();
        public Task<IReadOnlyList<VolumeInfo>> ProbeVolumesAsync(string id, CancellationToken t) => throw new InvalidOperationException();
        public Task<IReadOnlyList<MountedVolumeState>> GetMountStateAsync(CancellationToken t) => Task.FromResult<IReadOnlyList<MountedVolumeState>>(Mounts);
        public Task<MountResult> MountAsync(MountRequest r, CancellationToken t)
        { t.ThrowIfCancellationRequested(); Requests.Add(r);
          if (!SucceedMutations) return Task.FromResult(new MountResult(false, null, "fixture refusal", r.AccessMode));
          var v = Devices.SelectMany(d => d.Volumes).Single(v => v.VolumeId == r.VolumeId);
          var m = Mount(v, $"{r.DriveLetter}:\\", r.AccessMode == MountAccessMode.ReadWrite); Mounts = Mounts.Append(m).ToArray();
          return Task.FromResult(new MountResult(true, m.MountPoint, null, r.AccessMode)); }
        public Task<UnmountResult> UnmountAsync(string path, CancellationToken t)
        { t.ThrowIfCancellationRequested(); UnmountCalls++; if (!SucceedMutations) throw new InvalidOperationException("No unmount expected");
          Mounts = Mounts.Where(m => m.MountPoint != path).ToArray(); return Task.FromResult(new UnmountResult(true, path, null, true, true, true)); }
    }
}
