using System.Text.Json;
using System.Text.Json.Nodes;
using ApfsAccess.Core;
using ApfsAccess.Ipc;
using ApfsAccess.Service;
using ApfsAccess.Tray;

namespace ApfsAccess.Tray.Tests;

public sealed class RawSnapshotPresenterTests
{
    private const string Raw = @"\\.\PhysicalDrive99";
    private const string Image = @"D:\snapshot-presenter-not-opened.apfs";
    private const string Container = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    private const string Volume = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    private const long Creation = 134048736000000000;
    private static readonly string[] DeleteIdentity = ["21", "backup", "249", "17", "230", "8293", "8", "250", "90"];

    private static StatusChangedPayload Status(bool raw = true, bool mounted = true, bool recovery = false)
    {
        var path = raw ? Raw : Image;
        var cid = ApfsTopology.BuildContainerId(Container);
        var vid = ApfsTopology.BuildVolumeId(Container, 101);
        long offset = raw ? 1048576 : 0;
        const long size = 2097152;
        var topology = new ApfsTopologySnapshot([new("apfs-disk:image", path, null, offset + size)], [],
            [new("apfs-store:raw", Container, "", cid, offset, size, BlockSizeBytes: 4096, TotalBlocks: 512, DiskId: "apfs-disk:image")],
            [new(cid, Container, 4096, ["apfs-store:raw"], [vid], false, "90", [], [], [])],
            [new(vid, Volume, "101", cid, "Synthetic", true, ["data"], 64, null, "sensitive", "none", false, [], [], [], "7", "90")], []);
        var v = new VolumeInfo(vid, path, "Synthetic", true, SupportsNativeWrite: true, RecoveryIdentity: "rec-1",
            CatalogVolumeId: vid, CatalogContainerUuid: Container, CatalogVolumeObjectId: 101,
            CatalogDecision: ApfsCapabilityDecision.Writable, CatalogReasons: [], CatalogAutoMountAllowed: true, CatalogVolumeUuid: Volume);
        var device = new DeviceInventory(new(path, "Synthetic", true), [v], new(1, path, ["apfs-disk:image"], topology));
        var scope = recovery ? null : new LiveVolumeVerificationScope("opaque-original-authority", raw ? "retained-admitted-raw" : "retained-image",
            Container, Volume, "101", "90", offset.ToString(), size.ToString());
        // Most cases inject the display boundary; dedicated cases exercise the real mounted-state projection.
        var display = new MountedVolumeDisplay(vid, "R:\\", "Synthetic", path, "Synthetic", recovery ? MountAccessMode.ReadOnly : MountAccessMode.ReadWrite,
            "rec-1", RuntimeState.MountedRw, WriteEnabled: !recovery, WriteBackend: "Native",
            NativeWriteSafetyState: recovery ? NativeWriteSafetyState.RecoveryBlocked : NativeWriteSafetyState.StableReadWrite,
            RecoveryActive: recovery, MountReady: true, HostProcessId: 123, CatalogVolumeId: vid,
            CatalogContainerUuid: Container, CatalogVolumeObjectId: 101, CatalogDecision: v.CatalogDecision, CatalogReasons: [],
            CatalogAutoMountAllowed: true, HasRuntimeStatus: true, CatalogVolumeUuid: Volume,
            SnapshotInventorySupported: !recovery, SnapshotMutationSupported: !recovery, SnapshotRecoverySupported: true,
            VolumeVerificationSupported: scope is not null, VolumeVerificationScope: scope, HostProcessCreationTimeFileTimeUtc: raw ? Creation : 0);
        return new(mounted ? RuntimeState.MountedRw : RuntimeState.Idle, mounted ? ["R:\\"] : [], null, DateTime.UtcNow, [], mounted, [],
            MountedVolumes: mounted ? [display] : [], ConnectedInventory: [device], InventoryGeneration: 1);
    }

    private static DriveDashboardRow Selected(StatusChangedPayload status)
        => Assert.Single(TopologyDashboard.Project(status), n => n.Row is not null).Row!;

    private static StatusChangedPayload ChangeOwner(StatusChangedPayload status, Func<MountedVolumeDisplay, MountedVolumeDisplay> change)
        => status with { MountedVolumes = [change(status.MountedVolumes![0])] };

    private static ControlOperationRequestPayload Request(StatusChangedPayload status, DriveDashboardRow selected, string command)
        => DriveDashboardPresenter.CreateSnapshotRequest(status, selected, command,
            command == ApfsControlCommands.SnapshotCreate ? "backup" : null,
            command == ApfsControlCommands.SnapshotDelete ? DeleteIdentity : null);

    private static StatusChangedPayload Wire(StatusChangedPayload status)
    {
        var envelope = PipeMessageCodec.Create(ApfsMessageTypes.StatusChanged, status);
        Assert.True(PipeMessageCodec.TryDeserialize(PipeMessageCodec.Serialize(envelope), out var parsed));
        Assert.True(PipeMessageCodec.TryGetPayload<StatusChangedPayload>(parsed!, out var current));
        return current!;
    }

    private static MountedVolumeState Mounted(StatusChangedPayload status)
    {
        var m = status.MountedVolumes![0];
        return new(m.VolumeId, m.MountPoint, m.AccessMode, m.VolumeName, m.DeviceId, m.DeviceDisplayName,
            WriteBackend: m.WriteBackend, NativeWriteSafetyState: m.NativeWriteSafetyState,
            RecoveryIdentity: m.RecoveryIdentity, MountReady: m.MountReady, HostProcessId: m.HostProcessId,
            CatalogVolumeId: m.CatalogVolumeId, CatalogVolumeUuid: m.CatalogVolumeUuid,
            CatalogContainerUuid: m.CatalogContainerUuid, CatalogVolumeObjectId: m.CatalogVolumeObjectId,
            CatalogDecision: m.CatalogDecision, CatalogReasons: m.CatalogReasons, CatalogAutoMountAllowed: m.CatalogAutoMountAllowed,
            RuntimeWatermarksKnown: true, SnapshotInventorySupported: m.SnapshotInventorySupported,
            SnapshotMutationSupported: m.SnapshotMutationSupported, SnapshotRecoverySupported: m.SnapshotRecoverySupported,
            VolumeVerificationSupported: m.VolumeVerificationSupported, VolumeVerificationScope: m.VolumeVerificationScope,
            HostProcessCreationTimeFileTimeUtc: m.HostProcessCreationTimeFileTimeUtc);
    }

    private static StatusChangedPayload SamsungShape()
    {
        // Saved held-window evidence: base 209735680, NX 134217728, GPT length 128111046656.
        // Capabilities and identity are injected native status authority, never inferred from this geometry.
        var status = Status(); var d = status.ConnectedInventory![0]; var t = d.Topology!;
        var partitionUuid = "cccccccc-cccc-cccc-cccc-cccccccccccc";
        var partitionId = ApfsTopology.BuildPartitionId(Guid.Parse(partitionUuid));
        var disk = t.Snapshot.Disks[0] with { SizeBytes = 128320801792 };
        var store = t.Snapshot.Stores[0] with { OffsetBytes = 209735680, SizeBytes = 128111046656,
            TotalBlocks = 32768, PartitionId = partitionId, DiskId = null };
        var partition = new ApfsPartitionRecord(partitionId, partitionUuid, disk.Id, 2, store.OffsetBytes, store.SizeBytes,
            "7c3457ef-0000-11aa-aa11-00306543ecac", "apfs");
        status = status with { ConnectedInventory = [d with { Topology = t with { Snapshot = t.Snapshot with {
            Disks = [disk], Partitions = [partition], Stores = [store] } } }] };
        return ChangeOwner(status, m => m with { VolumeVerificationScope = m.VolumeVerificationScope! with {
            StoreOffsetBytes = "209735680", StoreSizeBytes = "134217728" } });
    }

    [Theory]
    [InlineData(ApfsControlCommands.SnapshotList)]
    [InlineData(ApfsControlCommands.SnapshotCreate)]
    [InlineData(ApfsControlCommands.SnapshotDelete)]
    public void MountedStateProjectionWirePreservesCurrentNativeAuthority(string command)
    {
        var status = SamsungShape(); var mount = Mounted(status);
        var current = Wire(status with { MountedVolumes = MountedStatusProjection.FromMounts([mount]) });
        var row = Selected(current);
        Assert.True(row.CanListSnapshots); Assert.True(row.CanMutateSnapshots); Assert.False(row.CanRecoverSnapshots);
        Assert.Equal(mount.VolumeVerificationScope, row.SnapshotRuntimeAuthority!.Scope);
        Assert.Equal(mount.HostProcessCreationTimeFileTimeUtc, row.SnapshotRuntimeAuthority.HostProcessCreationTimeFileTimeUtc);
        Assert.Equal("209735680", row.SnapshotScope!.StoreOffsetBytes);
        Assert.Equal("134217728", row.SnapshotScope.StoreSizeBytes);
        var request = Request(current, row, command);
        Assert.Equal(SelectedControlTarget.Create(current.ConnectedInventory![0], current.ConnectedInventory[0].Volumes[0]), request.Target);
        Assert.Equal(command == ApfsControlCommands.SnapshotCreate ? "backup" : null, request.SnapshotName);
        Assert.Equal(command == ApfsControlCommands.SnapshotDelete ? DeleteIdentity : null, request.SnapshotIdentity);
        Assert.True(PipeMessageCodec.Validate(PipeMessageCodec.Create(ApfsMessageTypes.ControlOperationRequest, request, request.OperationId, 2)).IsValid);
        Assert.Empty(SnapshotInventoryView.Parse(new LiveSnapshotInventory(Container, Volume, "101", "90",
            "209735680", "134217728", []).ToJson(), row).Entries);
    }

    [Theory]
    [InlineData("runtime")]
    [InlineData("creation")]
    [InlineData("scope")]
    [InlineData("capabilities")]
    public void MountedStateProjectionWireClearsUnknownAuthority(string change)
    {
        var status = SamsungShape(); var mount = Mounted(status);
        var initial = Wire(status with { MountedVolumes = MountedStatusProjection.FromMounts([mount]) });
        var selected = Selected(initial); Assert.True(selected.CanMutateSnapshots);
        mount = change switch {
            "runtime" => mount with { RuntimeWatermarksKnown = false, HostProcessCreationTimeFileTimeUtc = 0,
                VolumeVerificationScope = null, VolumeVerificationSupported = false,
                SnapshotInventorySupported = false, SnapshotMutationSupported = false },
            "creation" => mount with { HostProcessCreationTimeFileTimeUtc = 0 },
            "scope" => mount with { VolumeVerificationScope = null },
            _ => mount with { SnapshotInventorySupported = false, SnapshotMutationSupported = false }
        };
        var current = Wire(status with { MountedVolumes = MountedStatusProjection.FromMounts([mount]) });
        Assert.Equal(mount.HostProcessCreationTimeFileTimeUtc, current.MountedVolumes![0].HostProcessCreationTimeFileTimeUtc);
        Assert.Equal(mount.VolumeVerificationScope, current.MountedVolumes[0].VolumeVerificationScope);
        var row = Selected(current);
        Assert.False(row.CanListSnapshots); Assert.False(row.CanMutateSnapshots); Assert.False(row.CanRecoverSnapshots);
        foreach (var command in new[] { ApfsControlCommands.SnapshotList, ApfsControlCommands.SnapshotCreate, ApfsControlCommands.SnapshotDelete })
            Assert.Throws<InvalidOperationException>(() => Request(current, selected, command));
    }

    [Theory]
    [InlineData("wrong-base")]
    [InlineData("spillover")]
    [InlineData("unaligned")]
    [InlineData("nx-mismatch")]
    [InlineData("nx-zero")]
    [InlineData("nx-overflow")]
    [InlineData("block-zero")]
    [InlineData("block-mismatch")]
    [InlineData("store-identity")]
    [InlineData("volume-identity")]
    [InlineData("window-overflow")]
    [InlineData("unqualified")]
    [InlineData("no-capability")]
    public void SamsungPartitionCannotAuthorizeWrongOrUnqualifiedWindow(string change)
    {
        var status = SamsungShape(); var selected = Selected(status); Assert.True(selected.CanMutateSnapshots);
        var d = status.ConnectedInventory![0]; var t = d.Topology!; var store = t.Snapshot.Stores[0];
        store = change switch {
            "nx-zero" => store with { TotalBlocks = 0 },
            "nx-overflow" => store with { TotalBlocks = ulong.MaxValue },
            "block-zero" => store with { BlockSizeBytes = 0 },
            "block-mismatch" => store with { BlockSizeBytes = 8192 },
            "store-identity" => store with { Uuid = new string('d', 32) },
            _ => store
        };
        status = status with { ConnectedInventory = [d with { Topology = t with { Snapshot = t.Snapshot with { Stores = [store] } } }] };
        status = ChangeOwner(status, m => m with { VolumeVerificationScope = m.VolumeVerificationScope! with {
            StoreOffsetBytes = change == "wrong-base" ? "209739776" : "209735680",
            StoreSizeBytes = change switch {
                "spillover" => "128111050752", "unaligned" => "134217729", "nx-mismatch" => "67108864",
                "window-overflow" => ulong.MaxValue.ToString(), _ => "134217728" },
            VolumeOid = change == "volume-identity" ? "102" : "101",
            SourceKind = change == "unqualified" ? "raw" : "retained-admitted-raw" },
            SnapshotInventorySupported = change != "no-capability" });
        var row = Selected(status); Assert.False(row.CanListSnapshots); Assert.False(row.CanMutateSnapshots);
        foreach (var command in new[] { ApfsControlCommands.SnapshotList, ApfsControlCommands.SnapshotCreate, ApfsControlCommands.SnapshotDelete })
            Assert.Throws<InvalidOperationException>(() => Request(status, selected, command));
    }

    [Fact]
    public void OptionalLegacyBlockCountStillRequiresExactBaseAndNativeAuthority()
    {
        var status = SamsungShape(); var d = status.ConnectedInventory![0]; var t = d.Topology!;
        status = status with { ConnectedInventory = [d with { Topology = t with { Snapshot = t.Snapshot with {
            Stores = [t.Snapshot.Stores[0] with { TotalBlocks = null, BlockSizeBytes = null }] } } }] };
        var row = Selected(status); Assert.True(row.CanMutateSnapshots);
        Assert.Equal("134217728", row.SnapshotScope!.StoreSizeBytes);
        foreach (var invalid in new[] {
            ChangeOwner(status, m => m with { VolumeVerificationScope = m.VolumeVerificationScope! with { StoreOffsetBytes = "209739776" } }),
            ChangeOwner(status, m => m with { VolumeVerificationSupported = false }),
            ChangeOwner(status, m => m with { VolumeVerificationScope = m.VolumeVerificationScope! with { StoreSizeBytes = "128111050752" } }) })
            Assert.False(Selected(invalid).CanListSnapshots);
    }

    [Theory]
    [InlineData("source")]
    [InlineData("window")]
    [InlineData("incarnation")]
    public void SamsungSelectionRejectsChangedOtherwiseValidNativeAuthority(string change)
    {
        var status = SamsungShape(); var selected = Selected(status);
        var current = ChangeOwner(status, m => m with {
            HostProcessCreationTimeFileTimeUtc = change == "incarnation" ? Creation + 1 : Creation,
            VolumeVerificationScope = m.VolumeVerificationScope! with {
                SourceIdentity = change == "source" ? "replacement-native-source" : m.VolumeVerificationScope.SourceIdentity,
                StoreSizeBytes = change == "window" ? "67108864" : "134217728" } });
        if (change == "window") {
            var d = current.ConnectedInventory![0]; var t = d.Topology!;
            current = current with { ConnectedInventory = [d with { Topology = t with { Snapshot = t.Snapshot with {
                Stores = [t.Snapshot.Stores[0] with { TotalBlocks = 16384 }] } } }] };
        }
        Assert.True(Selected(current).CanMutateSnapshots);
        foreach (var command in new[] { ApfsControlCommands.SnapshotList, ApfsControlCommands.SnapshotCreate, ApfsControlCommands.SnapshotDelete })
            Assert.Throws<InvalidOperationException>(() => Request(current, selected, command));
    }

    [Theory]
    [InlineData(ApfsControlCommands.SnapshotList)]
    [InlineData(ApfsControlCommands.SnapshotCreate)]
    [InlineData(ApfsControlCommands.SnapshotDelete)]
    public void CurrentRawAuthorityEnablesExactSelectedRequest(string command)
    {
        var status = Status();
        var envelope = PipeMessageCodec.Create(ApfsMessageTypes.StatusChanged, status);
        Assert.True(PipeMessageCodec.TryDeserialize(PipeMessageCodec.Serialize(envelope), out var parsed));
        Assert.True(PipeMessageCodec.TryGetPayload<StatusChangedPayload>(parsed!, out var current));
        var row = Selected(current!);
        Assert.True(row.CanListSnapshots); Assert.True(row.CanMutateSnapshots); Assert.False(row.CanRecoverSnapshots);
        Assert.Equal(current!.MountedVolumes![0].VolumeVerificationScope, row.SnapshotRuntimeAuthority!.Scope);
        Assert.Equal(123, row.SnapshotRuntimeAuthority.HostProcessId);
        Assert.Equal(Creation, row.SnapshotRuntimeAuthority.HostProcessCreationTimeFileTimeUtc);
        Assert.Equal("1048576", row.SnapshotScope!.StoreOffsetBytes);
        Assert.Equal("2097152", row.SnapshotScope.StoreSizeBytes);
        var request = Request(current, row, command);
        Assert.Equal(SelectedControlTarget.Create(current.ConnectedInventory![0], current.ConnectedInventory[0].Volumes[0]), request.Target);
        Assert.Equal(command, request.Command); Assert.Null(request.RequestedMode);
        Assert.Equal(command == ApfsControlCommands.SnapshotCreate ? "backup" : null, request.SnapshotName);
        Assert.Equal(command == ApfsControlCommands.SnapshotDelete ? DeleteIdentity : null, request.SnapshotIdentity);
        Assert.True(PipeMessageCodec.Validate(PipeMessageCodec.Create(ApfsMessageTypes.ControlOperationRequest, request, request.OperationId, 2)).IsValid);
        var inventory = new LiveSnapshotInventory(Container, Volume, "101", "90", "1048576", "2097152", []).ToJson();
        Assert.Empty(SnapshotInventoryView.Parse(inventory, row).Entries);
        Assert.False(row.CanVerifyOffline); Assert.False(row.CanManageOffline); Assert.False(row.CanManageTopologyImage);
    }

    [Theory]
    [InlineData("creation-unknown")]
    [InlineData("creation-invalid")]
    [InlineData("creation-overflow")]
    [InlineData("pid")]
    [InlineData("runtime")]
    [InlineData("ready")]
    [InlineData("scope-missing")]
    [InlineData("verification")]
    [InlineData("source-kind")]
    [InlineData("source-kind-unknown")]
    [InlineData("source-empty")]
    [InlineData("source-control")]
    [InlineData("container")]
    [InlineData("volume")]
    [InlineData("oid")]
    [InlineData("offset")]
    [InlineData("offset-noncanonical")]
    [InlineData("size")]
    [InlineData("window-overflow")]
    [InlineData("checkpoint")]
    [InlineData("recovery-id")]
    [InlineData("inventory-capability")]
    [InlineData("degraded")]
    [InlineData("readiness-degraded")]
    [InlineData("recovery-reason")]
    [InlineData("recovery")]
    [InlineData("pending")]
    [InlineData("backend")]
    [InlineData("ambiguous")]
    [InlineData("conflicting-owner")]
    [InlineData("disconnected")]
    [InlineData("unobserved")]
    [InlineData("no-topology")]
    [InlineData("duplicate-inventory")]
    [InlineData("catalog-policy")]
    [InlineData("encrypted")]
    public void IncompleteOrWrongRawAuthorityRefuses(string change)
    {
        var status = Status(); var m = status.MountedVolumes![0]; var scope = m.VolumeVerificationScope!;
        var updated = change switch {
            "creation-unknown" => m with { HostProcessCreationTimeFileTimeUtc = 0 },
            "creation-invalid" => m with { HostProcessCreationTimeFileTimeUtc = -1 },
            "creation-overflow" => m with { HostProcessCreationTimeFileTimeUtc = long.MaxValue },
            "pid" => m with { HostProcessId = 0 },
            "runtime" => m with { HasRuntimeStatus = false },
            "ready" => m with { MountReady = false },
            "scope-missing" => m with { VolumeVerificationScope = null },
            "verification" => m with { VolumeVerificationSupported = false },
            "source-kind" => m with { VolumeVerificationScope = scope with { SourceKind = "retained-image" } },
            "source-kind-unknown" => m with { VolumeVerificationScope = scope with { SourceKind = "raw" } },
            "source-empty" => m with { VolumeVerificationScope = scope with { SourceIdentity = "" } },
            "source-control" => m with { VolumeVerificationScope = scope with { SourceIdentity = "bad\nidentity" } },
            "container" => m with { VolumeVerificationScope = scope with { ContainerUuid = new string('c', 32) } },
            "volume" => m with { VolumeVerificationScope = scope with { VolumeUuid = new string('c', 32) } },
            "oid" => m with { VolumeVerificationScope = scope with { VolumeOid = "102" } },
            "offset" => m with { VolumeVerificationScope = scope with { StoreOffsetBytes = "0" } },
            "offset-noncanonical" => m with { VolumeVerificationScope = scope with { StoreOffsetBytes = "01048576" } },
            "size" => m with { VolumeVerificationScope = scope with { StoreSizeBytes = "1048576" } },
            "window-overflow" => m with { VolumeVerificationScope = scope with { StoreSizeBytes = ulong.MaxValue.ToString() } },
            "checkpoint" => m with { VolumeVerificationScope = scope with { CheckpointXid = "00" } },
            "recovery-id" => m with { RecoveryIdentity = "other" },
            "inventory-capability" => m with { SnapshotInventorySupported = false },
            "degraded" => m with { WriteEnabled = false, NativeWriteSafetyState = NativeWriteSafetyState.ReadOnlyFallback },
            "readiness-degraded" => m with { NativeWriteReadiness = NativeWriteReadiness.Degraded },
            "recovery-reason" => m with { RecoveryReason = "WriteDegraded" },
            "recovery" => m with { RecoveryActive = true },
            "pending" => m with { PendingDurability = true },
            "backend" => m with { WriteBackend = "Mock" },
            _ => m
        };
        status = status with { MountedVolumes = [updated] };
        if (change == "ambiguous") status = status with { MountedVolumes = [m, m with { HostProcessId = 124 }] };
        if (change == "conflicting-owner") status = status with { MountedVolumes = [m, m with { RecoveryIdentity = "other" }] };
        if (change == "disconnected") {
            var d = status.ConnectedInventory![0]; status = status with { ConnectedInventory = [d with { Device = d.Device with { IsConnected = false } }] };
        }
        if (change == "unobserved") status = status with { InventoryGeneration = null };
        if (change == "no-topology") {
            var d = status.ConnectedInventory![0]; status = status with { ConnectedInventory = [d with { Topology = null }] };
        }
        if (change == "duplicate-inventory") status = status with { ConnectedInventory = [status.ConnectedInventory![0], status.ConnectedInventory[0]] };
        if (change is "catalog-policy" or "encrypted") {
            var d = status.ConnectedInventory![0]; var v = d.Volumes[0];
            status = status with { ConnectedInventory = [d with { Volumes = [change == "encrypted" ? v with { IsEncrypted = true } :
                v with { CatalogDecision = ApfsCapabilityDecision.Unsupported }] }] };
        }
        Assert.All(DriveDashboardPresenter.BuildRows(status), r => {
            Assert.False(r.CanListSnapshots); Assert.False(r.CanMutateSnapshots); Assert.False(r.CanRecoverSnapshots);
        });
        var old = Selected(Status());
        foreach (var command in new[] { ApfsControlCommands.SnapshotList, ApfsControlCommands.SnapshotCreate, ApfsControlCommands.SnapshotDelete })
            Assert.Throws<InvalidOperationException>(() => Request(status, old, command));
    }

    [Theory]
    [InlineData("pid")]
    [InlineData("creation")]
    [InlineData("source")]
    [InlineData("checkpoint")]
    [InlineData("window")]
    [InlineData("recovery-id")]
    [InlineData("capability")]
    public void SelectedRequestRejectsChangedCurrentAuthority(string change)
    {
        var status = Status(); var selected = Selected(status);
        status = ChangeOwner(status, owner => change switch {
            "pid" => owner with { HostProcessId = 124 },
            "creation" => owner with { HostProcessCreationTimeFileTimeUtc = Creation + 1 },
            "source" => owner with { VolumeVerificationScope = owner.VolumeVerificationScope! with { SourceIdentity = "another-original-authority" } },
            "checkpoint" => owner with { VolumeVerificationScope = owner.VolumeVerificationScope! with { CheckpointXid = "91" } },
            "window" => owner with { VolumeVerificationScope = owner.VolumeVerificationScope! with { StoreOffsetBytes = "2097152" } },
            "recovery-id" => owner with { RecoveryIdentity = "rec-2" },
            _ => owner with { SnapshotMutationSupported = false }
        });
        if (change == "window") {
            var d = status.ConnectedInventory![0]; var t = d.Topology!;
            var store = t.Snapshot.Stores[0] with { OffsetBytes = 2097152 };
            var disk = t.Snapshot.Disks[0] with { SizeBytes = 4194304 };
            status = status with { ConnectedInventory = [d with { Topology = t with { Snapshot = t.Snapshot with { Stores = [store], Disks = [disk] } } }] };
        }
        if (change == "recovery-id") {
            var d = status.ConnectedInventory![0]; status = status with { ConnectedInventory = [d with { Volumes = [d.Volumes[0] with { RecoveryIdentity = "rec-2" }] }] };
        }
        if (change != "capability") Assert.True(Selected(status).CanMutateSnapshots);
        foreach (var command in new[] { ApfsControlCommands.SnapshotList, ApfsControlCommands.SnapshotCreate, ApfsControlCommands.SnapshotDelete })
            Assert.Throws<InvalidOperationException>(() => Request(status, selected, command));
    }

    [Fact]
    public void RawRecoveryStaysUnavailableWithOrWithoutHealthyScope()
    {
        foreach (var status in new[] { Status(), Status(recovery: true) }) {
            var row = Selected(status); Assert.False(row.CanRecoverSnapshots);
            Assert.Throws<InvalidOperationException>(() => Request(status, row, ApfsControlCommands.SnapshotRecover));
        }
    }

    [Fact]
    public void MutationCapabilityIsIndependentOfReadInventory()
    {
        var status = ChangeOwner(Status(), m => m with { SnapshotMutationSupported = false }); var row = Selected(status);
        Assert.True(row.CanListSnapshots); Assert.False(row.CanMutateSnapshots);
        Request(status, row, ApfsControlCommands.SnapshotList);
        Assert.Throws<InvalidOperationException>(() => Request(status, row, ApfsControlCommands.SnapshotCreate));
    }

    [Fact]
    public void SelectedRuntimePinsCannotBeDroppedOrReplaced()
    {
        var status = Status(); var selected = Selected(status);
        foreach (var stale in new[] { selected with { SnapshotRuntimeAuthority = null }, selected with { SnapshotScope = null },
            selected with { SnapshotRuntimeAuthority = selected.SnapshotRuntimeAuthority! with { HostProcessCreationTimeFileTimeUtc = 0 } } })
            Assert.Throws<InvalidOperationException>(() => Request(status, stale, ApfsControlCommands.SnapshotList));
    }

    [Fact]
    public void KnownWireIncarnationRequiresPositiveOwnerPid()
    {
        var status = ChangeOwner(Status(), m => m with { HostProcessId = 0 });
        Assert.False(PipeMessageCodec.Validate(PipeMessageCodec.Create(ApfsMessageTypes.StatusChanged, status)).IsValid);
    }

    [Theory]
    [InlineData(ApfsControlCommands.SnapshotList)]
    [InlineData(ApfsControlCommands.SnapshotCreate)]
    [InlineData(ApfsControlCommands.SnapshotDelete)]
    [InlineData(ApfsControlCommands.SnapshotRecover)]
    public void ImageRequestsKeepExistingScopeAndFieldsWithoutOwnerIncarnation(string command)
    {
        var status = Status(raw: false); var selected = Selected(status);
        Assert.Null(selected.SnapshotRuntimeAuthority); Assert.Equal("0", selected.SnapshotScope!.StoreOffsetBytes);
        var request = Request(status, selected, command);
        Assert.Equal(SelectedControlTarget.Create(status.ConnectedInventory![0], status.ConnectedInventory[0].Volumes[0]), request.Target);
        Assert.Equal(command == ApfsControlCommands.SnapshotCreate ? "backup" : null, request.SnapshotName);
        Assert.Equal(command == ApfsControlCommands.SnapshotDelete ? DeleteIdentity : null, request.SnapshotIdentity);
    }

    [Fact]
    public void OfflineAndRecoveringImagesKeepExistingAvailability()
    {
        var offline = Status(raw: false, mounted: false); var row = Selected(offline);
        Assert.True(row.CanVerifyOffline); Assert.Null(row.SnapshotRuntimeAuthority);
        Request(offline, row, ApfsControlCommands.SnapshotList);
        var recovery = Status(raw: false, recovery: true); row = Selected(recovery);
        Assert.True(row.CanRecoverSnapshots); Assert.False(row.CanMutateSnapshots);
        Request(recovery, row, ApfsControlCommands.SnapshotRecover);
    }

    [Theory]
    [InlineData("-1")]
    [InlineData("9223372036854775807")]
    [InlineData("\"134048736000000000\"")]
    [InlineData("null")]
    public void StatusWireRejectsInvalidOwnerIncarnation(string json)
    {
        var envelope = PipeMessageCodec.Create(ApfsMessageTypes.StatusChanged, Status());
        ((JsonObject)((JsonArray)envelope.Payload!["mountedVolumes"]!)[0]!) ["hostProcessCreationTimeFileTimeUtc"] = JsonNode.Parse(json);
        Assert.False(PipeMessageCodec.Validate(envelope).IsValid);
        Assert.False(PipeMessageCodec.TryDeserialize(PipeMessageCodec.Serialize(envelope), out _));
    }

    [Fact]
    public void OptionalOwnerIncarnationKeepsLegacyWireAndCoreDefaults()
    {
        Assert.Equal(0, new MountedVolumeState("v", "R:\\", MountAccessMode.ReadOnly).HostProcessCreationTimeFileTimeUtc);
        var status = ChangeOwner(Status(), m => m with { HostProcessCreationTimeFileTimeUtc = 0 });
        var envelope = PipeMessageCodec.Create(ApfsMessageTypes.StatusChanged, status);
        var mount = (JsonObject)((JsonArray)envelope.Payload!["mountedVolumes"]!)[0]!;
        Assert.False(mount.ContainsKey("hostProcessCreationTimeFileTimeUtc"));
        Assert.True(PipeMessageCodec.TryGetPayload<StatusChangedPayload>(envelope, out var legacy));
        Assert.False(Selected(legacy!).CanListSnapshots);
    }

    [Fact]
    public void PublisherNotifiesOwnerIncarnationAndNativeScopeChanges()
    {
        var publisher = new RuntimeStatusPublisher(); int events = 0; publisher.StatusChanged += _ => events++;
        var initial = Status(); publisher.Publish(initial); Assert.Equal(1, events);
        publisher.Publish(initial with { TimestampUtc = initial.TimestampUtc.AddSeconds(1) }); Assert.Equal(1, events);
        var replacement = ChangeOwner(initial, m => m with { HostProcessCreationTimeFileTimeUtc = Creation + 1 });
        publisher.Publish(replacement); Assert.Equal(2, events);
        var scope = ChangeOwner(replacement, m => m with { VolumeVerificationScope = m.VolumeVerificationScope! with { SourceIdentity = "another-authority" } });
        publisher.Publish(scope); Assert.Equal(3, events); Assert.Same(scope, publisher.Latest);
    }
}
