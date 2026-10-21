using System.Reflection;
using ApfsAccess.Core;
using ApfsAccess.Ipc;
using ApfsAccess.Service;
using ApfsAccess.Tray;
using ApfsAccess.Backend.Native;

namespace ApfsAccess.Tray.Tests;

public sealed partial class TopologyStatusIntegrationTests
{
    private static DeviceInventory ActionInventory() { var d = Inventory(); return d with { Volumes = d.Volumes.Select(v => v with { SupportsNativeWrite = true }).ToArray() }; }
    private sealed class ActionPolicy : IMountPolicy { public char SelectDriveLetter(VolumeInfo v, IReadOnlySet<char> used) => 'R'; public bool ShouldAutoMount(VolumeInfo v) => v.VolumeId == Id(202); }
    private sealed class ActionOptions : Microsoft.Extensions.Options.IOptionsMonitor<ServiceHostOptions>
    {
        public ServiceHostOptions CurrentValue { get; } = new() { AutoMountEnabled = true, EnableNativeWrite = true, WriteRolloutChannel = "Enabled", WriteBackendMode = "Native", NativeWritePromotionPolicy = "ScaffoldOnly", ReadWriteMode = "RwWithRoFallback" };
        public ServiceHostOptions Get(string? name) => CurrentValue;
        public IDisposable? OnChange(Action<ServiceHostOptions, string?> listener) => null;
    }
    private static ApfsMountWorker ActionWorker(Backend b) => new(Microsoft.Extensions.Logging.Abstractions.NullLogger<ApfsMountWorker>.Instance, b, new ActionPolicy(), new(), new ActionOptions());

    private static DeviceInventory ReplaceUuid(DeviceInventory d)
    {
        var uuid = Guid.NewGuid().ToString("D"); var t = d.Topology!.Snapshot;
        return d with { Volumes = [d.Volumes[0], d.Volumes[1] with { CatalogVolumeUuid = uuid }],
            Topology = d.Topology with { Generation = d.Topology.Generation + 1, Snapshot = t with { Volumes = [t.Volumes[0], t.Volumes[1] with { Uuid = uuid }] } } };
    }
    private static ControlOperationRequestPayload SelectedRequest(DeviceInventory d, string command) => new(Guid.NewGuid().ToString("D"), command,
        SelectedControlTarget.Create(d, d.Volumes[1]), command != ApfsControlCommands.Mount ? null : ApfsControlModes.ReadOnly, DateTime.UtcNow.AddSeconds(90));
    private static ControlOperationRequestPayload WireRequest(ControlOperationRequestPayload request)
    {
        var json = PipeMessageCodec.Serialize(PipeMessageCodec.Create(ApfsMessageTypes.ControlOperationRequest, request, request.OperationId, 2));
        Assert.True(PipeMessageCodec.TryDeserialize(json, out var envelope));
        Assert.True(PipeMessageCodec.Validate(envelope!).IsValid);
        Assert.True(PipeMessageCodec.TryGetPayload<ControlOperationRequestPayload>(envelope!, out var received));
        Assert.Equal(request, received); return received!;
    }

    [Theory]
    [InlineData("mount", 1)] [InlineData("fix", 1)] [InlineData("eject", 1)]
    [InlineData("mount", 4)] [InlineData("fix", 4)] [InlineData("eject", 2)]
    public async Task SelectedActions615_ReplacementAtAdmissionOrLastProbeNeverMutates(string command, int replaceAt)
    {
        var d = ActionInventory(); var backend = new Backend { Devices = [d], SucceedMutations = true };
        if (command == "eject") backend.Mounts = [Mount(d.Volumes[0], "Q:\\", false), Mount(d.Volumes[1], "R:\\", false)];
        backend.BeforeProbe = count => { if (count == replaceAt) backend.Devices = [ReplaceUuid(d)]; };
        using var worker = ActionWorker(backend);
        var result = await new AgentControlCommandExecutor(worker).ExecuteAsync(WireRequest(SelectedRequest(d, command)), default);
        Assert.False(result.Success, result.Diagnostic); Assert.Empty(backend.Requests); Assert.Equal(0, backend.UnmountCalls);
        Assert.True(backend.Calls >= replaceAt); // This is a real last-probe assertion, not an earlier refusal.
    }

    [Theory]
    [InlineData("mount")] [InlineData("fix")] [InlineData("eject")]
    public async Task SelectedActions615_SameIdentityGenerationRefreshExecutesOnlySelectedSibling(string command)
    {
        var d = ActionInventory(); var backend = new Backend { Devices = [d], SucceedMutations = true };
        if (command == "eject") backend.Mounts = [Mount(d.Volumes[0], "Q:\\", false), Mount(d.Volumes[1], "R:\\", false)];
        backend.BeforeProbe = count => backend.Devices = [d with { Topology = d.Topology! with { Generation = 100 + count } }];
        using var worker = ActionWorker(backend);
        var result = await new AgentControlCommandExecutor(worker).ExecuteAsync(WireRequest(SelectedRequest(d, command)), default);
        Assert.True(result.Success, result.Diagnostic);
        if (command == "eject") { Assert.Equal(1, backend.UnmountCalls); Assert.Equal(Id(201), Assert.Single(backend.Mounts).VolumeId); }
        else { Assert.Equal(Id(202), Assert.Single(backend.Requests).VolumeId); Assert.Equal(Id(202), Assert.Single(backend.Mounts).VolumeId); }
    }

    [Theory]
    [InlineData("null-list")] [InlineData("missing-edge")] [InlineData("row-uuid")] [InlineData("group-cross-container")]
    [InlineData("missing-reasons")] [InlineData("wrong-source")] [InlineData("wrong-type")]
    [InlineData("negative-size")] [InlineData("contradictory-catalog-id")]
    [InlineData("unbound-raw-ancestry")] [InlineData("unbound-partition-ancestry")]
    public async Task SelectedActions615_DirectLegacySenderCannotBypassAdvertisedGraph(string mutation)
    {
        var d = ActionInventory(); var t = d.Topology!.Snapshot;
        d = mutation switch {
            "unbound-raw-ancestry" => d with { Topology = d.Topology with { Snapshot = t with {
                Disks = [t.Disks[0], new("apfs-disk:other", "other", null, 100000)],
                Stores = [t.Stores[0] with { DiskId = "apfs-disk:other" }] } } },
            "unbound-partition-ancestry" => d with { Topology = d.Topology with { Snapshot = t with {
                Disks = [t.Disks[0], new("apfs-disk:other", "other", null, 100000)],
                Partitions = [new("apfs-part:bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", "apfs-disk:other", 1, 0, 100000, "type", "APFS")],
                Stores = [t.Stores[0] with { DiskId = null, PartitionId = "apfs-part:bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb" }] } } },
            "negative-size" => d with { Topology = d.Topology with { Snapshot = t with { Disks = [t.Disks[0] with { SizeBytes = -1 }] } } },
            "contradictory-catalog-id" => d with { Topology = d.Topology with { Snapshot = t with { Volumes = [t.Volumes[0], t.Volumes[1] with { ObjectId = "999" }] } }, Volumes = [d.Volumes[0], d.Volumes[1] with { CatalogVolumeObjectId = 999 }] },
            "null-list" => d with { Topology = d.Topology with { Snapshot = t with { Stores = null! } } },
            "missing-edge" => d with { Topology = d.Topology with { Snapshot = t with { Stores = [] } } },
            "row-uuid" => d with { Volumes = [d.Volumes[0], d.Volumes[1] with { CatalogVolumeUuid = Guid.NewGuid().ToString() }] },
            "group-cross-container" => d with { Topology = d.Topology with { Snapshot = t with { Groups = [new("apfs-group:x", Guid.NewGuid().ToString(), [Id(202)], "apfs-container:other")] } } },
            "missing-reasons" => d with { Volumes = [d.Volumes[0], d.Volumes[1] with { CatalogReasons = null }] },
            "wrong-source" => d with { Topology = d.Topology with { Snapshot = t with { Disks = [t.Disks[0] with { DeviceIdentifier = "replaced" }] } } },
            _ => d with { Topology = d.Topology with { Snapshot = t with { Volumes = [t.Volumes[0], t.Volumes[1] with { ContainerId = "apfs-disk:d" }] } } }
        };
        var backend = new Backend { Devices = [d], SucceedMutations = true }; using var worker = ActionWorker(backend);
        var request = new ControlOperationRequestPayload(Guid.NewGuid().ToString(), "mount", new("d", Id(202)), "read-only", DateTime.UtcNow.AddSeconds(90));
        var result = await new AgentControlCommandExecutor(worker).ExecuteAsync(WireRequest(request), default);
        Assert.False(result.Success); Assert.Empty(backend.Requests); Assert.Equal(0, backend.UnmountCalls);
    }

    [Fact]
    public async Task SelectedActions615_CallerCancellationStopsFreshProbeWithoutMutation()
    {
        var d = ActionInventory(); using var cts = new CancellationTokenSource();
        var backend = new Backend { Devices = [d], SucceedMutations = true, BeforeProbe = count => { if(count == 4) cts.Cancel(); } };
        using var worker = ActionWorker(backend);
        var result = await new AgentControlCommandExecutor(worker).ExecuteAsync(WireRequest(SelectedRequest(d, "mount")), cts.Token);
        Assert.False(result.Success); Assert.Equal(ApfsOperationStates.Cancelled, result.State); Assert.True(cts.IsCancellationRequested);
        Assert.Empty(backend.Requests); Assert.Equal(0, backend.UnmountCalls);
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public void SelectedActions633_BoundPartitionAndSharedContainerRetainSelection(bool shared)
    {
        var d = ActionInventory(); var t = d.Topology!.Snapshot;
        const string partitionId = "apfs-part:bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
        var localStore = t.Stores[0] with { DiskId = null, PartitionId = partitionId };
        t = t with {
            Partitions = [new(partitionId, "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", "apfs-disk:d", 1, 0, 100000, "type", "APFS")],
            Stores = [localStore]
        };
        if (shared) t = t with {
            Disks = [t.Disks[0], new("apfs-disk:other", "other", null, 100000)],
            Stores = [localStore, localStore with { Id = "apfs-store:other", PartitionId = "", DiskId = "apfs-disk:other" }],
            Containers = [t.Containers[0] with { StoreIds = [localStore.Id, "apfs-store:other"] }]
        };
        d = d with { Topology = d.Topology with { Snapshot = t } };
        Assert.True(TopologyAdmission.Validate(d));
        var target = SelectedControlTarget.Create(d, d.Volumes[1]);
        Assert.True(SelectedControlTarget.Matches([d], target));
        var refreshed = d with { Topology = d.Topology with { Generation = 99, Snapshot = t with {
            Containers = [t.Containers[0] with { CheckpointXid = "999" }],
            Volumes = t.Volumes.Select(v => v with { Name = "Renamed", SuperblockXid = "999" }).ToArray()
        } }, Volumes = d.Volumes.Select(v => v with { VolumeName = "Renamed" }).ToArray() };
        Assert.True(SelectedControlTarget.Matches([refreshed], target));
    }

    [Theory]
    [InlineData("eject")] [InlineData("fix")] [InlineData("mount")]
    public void SelectedActions615_HiddenDashboardCallbacksKeepExactSameLabelSelection(string command)
    {
        var d = ActionInventory(); var mounts = command == "mount" ? Array.Empty<MountedVolumeState>() : new[] { Mount(d.Volumes[0], "Q:\\", true), Mount(d.Volumes[1], "R:\\", false) };
        var status = new StatusChangedPayload(RuntimeState.MountedRo, mounts.Select(m => m.MountPoint).ToArray(), null, DateTime.UtcNow, [], false, [],
            MountedVolumes: MountedStatusProjection.FromMounts(mounts), ConnectedInventory: [d], InventoryGeneration: 1);
        ControlOperationRequestPayload? captured = null;
        Task Capture(DriveDashboardRow row) { captured = WireRequest(DriveDashboardPresenter.CreateSelectedRequest(status, row, command)); return Task.CompletedTask; }
        Sta(() => {
            using var form = new DashboardForm(_ => Task.CompletedTask, _ => throw new Exception("Legacy eject must not run"), _ => throw new Exception("Legacy fix must not run"),
                mountVolumeAsync: Capture, ejectVolumeAsync: Capture, fixVolumeAsync: Capture);
            form.ApplyStatus(status); var tree = Controls(form).OfType<TreeView>().Single(); _ = tree.Handle;
            tree.SelectedNode = AllNodes(tree.Nodes).Single(n => (n.Tag as TopologyDashboardNode)?.Row?.VolumeId == Id(202));
            Click(form, char.ToUpperInvariant(command[0]) + command[1..]); Assert.False(form.Visible);
        });
        Assert.NotNull(captured); Assert.Equal(SelectedControlTarget.Create(d, d.Volumes[1]), captured.Target);
        var stale = TopologyDashboard.Project(status).Single(n => n.Row?.VolumeId == Id(202)).Row!;
        Assert.Throws<InvalidOperationException>(() => DriveDashboardPresenter.CreateSelectedRequest(status with { ConnectedInventory = [ReplaceUuid(d)] }, stale, command));
    }

    [Fact]
    public void SelectedActions615_TrayMenusCarryFullRowAndRefreshReplacements()
    {
        var d = ActionInventory(); var status = new StatusChangedPayload(RuntimeState.MountedRo, ["R:\\"], null, DateTime.UtcNow, [], false, [],
            MountedVolumes: MountedStatusProjection.FromMounts([Mount(d.Volumes[1], "R:\\", false)]), ConnectedInventory: [d], InventoryGeneration: 1);
        var method = typeof(TrayApplicationContext).GetMethod("BuildEjectMenuDescriptors", BindingFlags.Static | BindingFlags.NonPublic)!;
        var descriptors = (IReadOnlyList<EjectMenuDescriptor>)method.Invoke(null, [status])!;
        var row = Assert.Single(descriptors).Row; Assert.NotNull(row);
        Assert.Equal(SelectedControlTarget.Create(d, d.Volumes[1]), DriveDashboardPresenter.CreateSelectedRequest(status, row, "eject").Target);
        var changed = status with { ConnectedInventory = [ReplaceUuid(d)] };
        Assert.Empty((IReadOnlyList<EjectMenuDescriptor>)method.Invoke(null, [changed])!);
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public void SelectedActions615_GroupRelationshipsAreReciprocalAndSurviveLongLabelRefresh(bool breakReciprocal)
    {
        var d = ActionInventory(); var t = d.Topology!.Snapshot; var uuid = Guid.NewGuid().ToString("D"); var gid = "apfs-group:" + uuid;
        t = t with { Groups = [new(gid, uuid, [Id(201), Id(202)], t.Containers[0].Id, "valid-system-data", Id(201), Id(202))],
            Volumes = t.Volumes.Select(v => v with { GroupId = gid, GroupUuid = uuid, GroupMetadataValid = true, GroupAssociationStatus = "valid-system-data", Roles = v.Id == Id(201) ? ["system"] : ["data"], Name = new string('W', 1000) }).ToArray() };
        if (breakReciprocal) t = t with { Groups = [t.Groups[0] with { VolumeIds = [Id(201)] }] };
        d = d with { Topology = d.Topology with { Snapshot = t }, Volumes = [d.Volumes[0] with { CatalogDecision = ApfsCapabilityDecision.Readable, CatalogReasons = ["special-role:system"], CatalogAutoMountAllowed = false }, d.Volumes[1]] };
        Assert.Equal(!breakReciprocal, TopologyAdmission.Validate(d));
        if (breakReciprocal) return;
        var status = new StatusChangedPayload(RuntimeState.Idle, [], null, DateTime.UtcNow, [], false, [], ConnectedInventory: [d], InventoryGeneration: 1);
        var nodes = TopologyDashboard.Project(status); var group = Assert.Single(nodes, n => n.Id.Contains(gid));
        Assert.Equal(2, group.MemberIds!.Count); Assert.All(nodes.Where(n => n.Row is not null), n => Assert.Equal(group.Id, n.ParentId));
        Sta(() => { using var form = new DashboardForm(_ => Task.CompletedTask, _ => Task.CompletedTask, _ => Task.CompletedTask);
            form.ApplyStatus(status); var tree = Controls(form).OfType<TreeView>().Single(); _ = tree.Handle;
            tree.SelectedNode = tree.Nodes.Find(group.Id, true).Single(); var selected = tree.SelectedNode; selected.Expand();
            form.ApplyStatus(status with { InventoryGeneration = 20 }); Assert.Same(selected, tree.SelectedNode); Assert.True(selected.IsExpanded); Assert.False(form.Visible); });
    }

    private sealed class OfflineLifetime615 : Microsoft.Extensions.Hosting.IHostApplicationLifetime
    {
        public CancellationToken ApplicationStarted => default; public CancellationToken ApplicationStopping => default; public CancellationToken ApplicationStopped => default;
        public void StopApplication() => throw new InvalidOperationException("No application stop expected.");
    }

    [Theory]
    [InlineData("mount", false)] [InlineData("fix", false)] [InlineData("eject", false)]
    [InlineData("mount", true)] [InlineData("fix", true)] [InlineData("eject", true)]
    public async Task SelectedActions615_HiddenTrayClickThroughRealPipeExecutorWorkerAndReplay(string command, bool replace)
    {
        var d = ActionInventory(); var mounts = command == "mount" ? Array.Empty<MountedVolumeState>() : new[] { Mount(d.Volumes[0], "Q:\\", true), Mount(d.Volumes[1], "R:\\", false) };
        var status = new StatusChangedPayload(RuntimeState.MountedRo, mounts.Select(m => m.MountPoint).ToArray(), null, DateTime.UtcNow, [], false, [],
            MountedVolumes: MountedStatusProjection.FromMounts(mounts), ConnectedInventory: [d], InventoryGeneration: 1);
        var backend = new Backend { Devices = [replace ? ReplaceUuid(d) : d], Mounts = mounts, SucceedMutations = true };
        using var worker = ActionWorker(backend); var executor = new AgentControlCommandExecutor(worker);
        var root = Path.Combine(Path.GetTempPath(), "pipe615-" + Guid.NewGuid().ToString("N"));
        var operationType = typeof(TrayPipeHostService).Assembly.GetType("ApfsAccess.Service.AgentControlOperationService")!;
        var operationService = Activator.CreateInstance(operationType, BindingFlags.Instance | BindingFlags.NonPublic,
            null, [new Func<ControlOperationRequestPayload, CancellationToken, Task<OperationResultPayload>>(executor.ExecuteAsync), root, null, null, null, null], null)!;
        using var host = (TrayPipeHostService)Activator.CreateInstance(typeof(TrayPipeHostService), BindingFlags.Instance | BindingFlags.NonPublic,
            null, [Microsoft.Extensions.Logging.Abstractions.NullLogger<TrayPipeHostService>.Instance, new RuntimeStatusPublisher(), worker, new OfflineLifetime615(), operationService], null)!;
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        async Task<OperationResultPayload> Exchange(ControlOperationRequestPayload request)
        {
            var name = "ApfsAccess.Offline615." + Guid.NewGuid().ToString("N");
            await using var server = new System.IO.Pipes.NamedPipeServerStream(name, System.IO.Pipes.PipeDirection.InOut, 1, System.IO.Pipes.PipeTransmissionMode.Byte, System.IO.Pipes.PipeOptions.Asynchronous);
            await using var client = new System.IO.Pipes.NamedPipeClientStream(".", name, System.IO.Pipes.PipeDirection.InOut, System.IO.Pipes.PipeOptions.Asynchronous);
            var waiting = server.WaitForConnectionAsync(deadline.Token); await client.ConnectAsync(deadline.Token); await waiting;
            await using var peer = new PipePeer(server); await using var sender = new PipePeer(client);
            var handling = (Task)typeof(TrayPipeHostService).GetMethod("HandleClientAsync", BindingFlags.Instance | BindingFlags.NonPublic)!.Invoke(host, [peer, deadline.Token])!;
            try {
                Assert.Equal(ApfsMessageTypes.StatusChanged, (await sender.ReadMessageAsync(deadline.Token))!.Type);
                await sender.SendAsync(PipeMessageCodec.Create(ApfsMessageTypes.ControlOperationRequest, request, request.OperationId, 2), deadline.Token);
                while (true) {
                    var response = await sender.ReadMessageAsync(deadline.Token); Assert.NotNull(response);
                    if (response.Type != ApfsMessageTypes.OperationResult) continue;
                    Assert.True(PipeMessageCodec.Validate(response).IsValid, PipeMessageCodec.Validate(response).Diagnostic);
                    Assert.True(PipeMessageCodec.TryGetPayload<OperationResultPayload>(response, out var result));
                    if (result!.State is ApfsOperationStates.Accepted or ApfsOperationStates.InProgress) {
                        await sender.SendAsync(PipeMessageCodec.Create(ApfsMessageTypes.OperationResultQuery, new OperationResultQueryPayload(request.OperationId), request.OperationId, 2), deadline.Token); continue; }
                    return result;
                }
            } finally { await sender.DisposeAsync(); await handling.WaitAsync(deadline.Token); }
        }
        ControlOperationRequestPayload? captured = null;
        Sta(() => {
            var row = TopologyDashboard.Project(status).Single(n => n.Row?.VolumeId == Id(202)).Row!;
            using var item = TrayApplicationContext.CreateSelectedActionItem(row, command,
                (selected, action) => { captured = DriveDashboardPresenter.CreateSelectedRequest(status, selected, action); return Task.CompletedTask; }, ex => throw ex);
            item.PerformClick(); Assert.NotNull(captured);
        });
        try {
            var first = await Exchange(captured!); Assert.Equal(!replace, first.Success);
            var mutations = backend.Requests.Count + backend.UnmountCalls;
            Assert.Equal(replace ? 0 : command == "fix" ? 2 : 1, mutations);
            var replay = await Exchange(captured!); Assert.Equal(first, replay); Assert.Equal(mutations, backend.Requests.Count + backend.UnmountCalls);
            Assert.Equal(SelectedControlTarget.Create(d, d.Volumes[1]), first.Target);
        } finally { await (Task)operationType.GetMethod("StopAsync")!.Invoke(operationService, [CancellationToken.None])!; }
    }

    [Fact]
    public async Task SelectedActions615_HiddenPreferenceSaveUsesWireUuidAndRejectsReplacement()
    {
        var d = ActionInventory(); var v = d.Volumes[1];
        var preference = new DriveLetterPreference(v.CatalogVolumeUuid, "R", "R", "preferred", "Preferred R", "RST", true);
        var mount = MountedStatusProjection.FromMounts([Mount(v, "R:\\", false)]).Single() with { DriveLetterPreference = preference };
        var status = new StatusChangedPayload(RuntimeState.MountedRo, ["R:\\"], null, DateTime.UtcNow, [], false, [],
            MountedVolumes: [mount], ConnectedInventory: [d], InventoryGeneration: 1);
        var row = TopologyDashboard.Project(status).Single(n => n.Row?.VolumeId == Id(202)).Row!;
        DriveLetterPreferenceRequestPayload? captured = null;
        Sta(() => { using var form = new DashboardForm(_ => Task.CompletedTask, _ => Task.CompletedTask, _ => Task.CompletedTask,
                setDriveLetterAsync: (selected, letter) => { captured = DriveDashboardPresenter.CreatePreferenceRequest(status, selected, letter); return Task.CompletedTask; });
            form.ApplyStatus(status);
            typeof(DashboardForm).GetMethod("SaveDriveLetterPreferenceAsync", BindingFlags.Instance | BindingFlags.NonPublic)!.Invoke(form, [row, "T"]);
            Assert.False(form.Visible); });
        Assert.NotNull(captured); Assert.Equal(SelectedControlTarget.Create(d, v), captured.Target);
        var wire = PipeMessageCodec.Serialize(PipeMessageCodec.Create(ApfsMessageTypes.DriveLetterPreferenceRequested, captured));
        Assert.True(PipeMessageCodec.TryDeserialize(wire, out var envelope));
        Assert.True(PipeMessageCodec.TryGetPayload<DriveLetterPreferenceRequestPayload>(envelope!, out var received));
        var path = Path.Combine(Path.GetTempPath(), "preference615-" + Guid.NewGuid().ToString("N"), "letters.json");
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var backend = new Backend { Devices = [d] };
        var policy = new FirstFreeMountPolicy(["R", "S", "T"], new VolumeDriveLetterAssignments(path));
        using var worker = new ApfsMountWorker(Microsoft.Extensions.Logging.Abstractions.NullLogger<ApfsMountWorker>.Instance, backend, policy, new(), new ActionOptions());
        var saved = await worker.SetDriveLetterPreferenceAsync(received!, default); Assert.True(saved.Success, saved.Message);
        var before = File.ReadAllBytes(path);
        backend.Devices = [ReplaceUuid(d)];
        var refused = await worker.SetDriveLetterPreferenceAsync(received! with { Letter = "S" }, default);
        Assert.False(refused.Success); Assert.Equal(before, File.ReadAllBytes(path)); Assert.Empty(backend.Requests); Assert.Equal(0, backend.UnmountCalls);
        Assert.Throws<InvalidOperationException>(() => DriveDashboardPresenter.CreatePreferenceRequest(status with { ConnectedInventory = backend.Devices }, row, "S"));
    }

    [Fact]
    public async Task SelectedActions615_MountedFixRefusesReplacementBeforeUnmountAndCanRecoverSameOwner()
    {
        foreach (var replace in new[] { true, false })
        {
            var d = ActionInventory(); var backend = new Backend { Devices = [d], SucceedMutations = true,
                Mounts = [Mount(d.Volumes[0], "Q:\\", true), Mount(d.Volumes[1], "R:\\", false)] };
            if (replace) backend.BeforeProbe = count => { if (count == 4) backend.Devices = [ReplaceUuid(d)]; };
            using var worker = ActionWorker(backend);
            var result = await new AgentControlCommandExecutor(worker).ExecuteAsync(WireRequest(SelectedRequest(d, "fix")), default);
            Assert.Equal(!replace, result.Success);
            Assert.Equal(replace ? 0 : 1, backend.UnmountCalls); Assert.Equal(replace ? 0 : 1, backend.Requests.Count);
            Assert.Contains(backend.Mounts, m => m.VolumeId == Id(201) && m.MountPoint == "Q:\\");
            Assert.True(backend.Calls >= 4);
        }
    }

    [Theory]
    [InlineData(true, false, DashboardPalette.Yellow)] [InlineData(false, false, DashboardPalette.Green)] [InlineData(true, true, DashboardPalette.Red)]
    public void Observer615_ActualHostSchemaUsesProductionParserAndDashboard(bool readOnly, bool recovery, DashboardPalette expected)
    {
        var json = System.Text.Json.JsonSerializer.Serialize(new { explicitReadOnly = readOnly, immutableEncryptedImage = readOnly,
            encryptedHealth = recovery ? "FailedReadOnly" : "ReadOnly", hostPid = 123, mountReady = true,
            writeBackend = readOnly ? "Disabled" : "Native", nativeWriteReadiness = "CommitReady", nativeWriteValidationState = "Scaffold",
            nativeWriteSafetyState = readOnly ? "ImmutableEncryptedImageReadOnly" : "StableReadWrite", recoveryActive = false,
            recoveryReason = (string?)null, dirtyTransactionCount = 0, shutdownDrainActive = false, inFlightMutationCallbacks = 0 });
        var mount = NativeApfsBackend.ProjectObservedHostStatus(json, "windows-file:fixture", "D:\\offline-fixture");
        Assert.Equal(expected, DriveDashboardPresenter.ProjectObservedMount(mount).Palette);
        Assert.Equal(readOnly ? MountAccessMode.ReadOnly : MountAccessMode.ReadWrite, mount.AccessMode); Assert.Equal(123, mount.HostProcessId);
    }
}
