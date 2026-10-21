using System.Text.Json;
using ApfsAccess.Core;
using ApfsAccess.Ipc;
using ApfsAccess.Tray;
using ApfsAccess.Backend.Native;

namespace ApfsAccess.Tray.Tests;

internal static class WindowsSurfaceFixture
{
    public const string Image = @"D:\img.apfs";
    public const string Hex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    public const string VolumeHex = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    public static DeviceInventory Inventory(long imageBytes = 100000)
    {
        var containerId = ApfsTopology.BuildContainerId(Hex);
        var volumeId = ApfsTopology.BuildVolumeId(Hex, 101);
        var topology = new ApfsTopologySnapshot([new("apfs-disk:image", Image, null, imageBytes)], [],
            [new("apfs-store:raw", Hex, "", containerId, 0, imageBytes, DiskId: "apfs-disk:image")],
            [new(containerId, Hex, 4096, ["apfs-store:raw"], [volumeId], false, "90", [], [], [])],
            [new(volumeId, VolumeHex, "101", containerId, "Main", true, ["data"], 64, null, "sensitive", "none", false, [], [], [], "7", "90")], []);
        var volume = new VolumeInfo(volumeId, Image, "Main", true, SupportsNativeWrite: true, RecoveryIdentity: "rec-1",
            CatalogVolumeId: volumeId, CatalogContainerUuid: Hex, CatalogVolumeObjectId: 101,
            CatalogDecision: ApfsCapabilityDecision.Writable, CatalogReasons: [], CatalogAutoMountAllowed: true, CatalogVolumeUuid: VolumeHex);
        return new(new(Image, "Image", true), [volume], new(1, Image, ["apfs-disk:image"], topology));
    }

    public static StatusChangedPayload Status(bool mounted = false, bool recovery = false, bool snapshotRuntimeReady = true)
    {
        var device = Inventory(); var v = device.Volumes[0];
        var mounts = mounted ? MountedStatusProjection.FromMounts([new(v.VolumeId, "R:\\", MountAccessMode.ReadWrite,
            v.VolumeName, v.DeviceId, "Image", WriteBackend: "Native", NativeWriteSafetyState: NativeWriteSafetyState.StableReadWrite,
            RecoveryActive: recovery, MountReady: true, HostProcessId: 123, RecoveryIdentity: v.RecoveryIdentity, CatalogVolumeId: v.CatalogVolumeId,
            CatalogContainerUuid: v.CatalogContainerUuid, CatalogVolumeObjectId: v.CatalogVolumeObjectId,
            CatalogDecision: v.CatalogDecision, CatalogReasons: [], CatalogAutoMountAllowed: true, CatalogVolumeUuid: v.CatalogVolumeUuid,
            SnapshotInventorySupported: snapshotRuntimeReady && !recovery,
            SnapshotMutationSupported: snapshotRuntimeReady && !recovery,
            SnapshotRecoverySupported: snapshotRuntimeReady)]) : [];
        return new(mounted ? RuntimeState.MountedRw : RuntimeState.Idle, mounted ? ["R:\\"] : [], null, DateTime.UtcNow, [], false, [],
            MountedVolumes: mounts, ConnectedInventory: [device], InventoryGeneration: 1, ManagementJournalRootInspected: true, ImageManagementMutationsEnabled: true);
    }

    public static JsonElement SnapshotInventory(string volume = VolumeHex) => JsonSerializer.SerializeToElement(new
    {
        format = "apfs-access-snapshot-inventory", version = 1, readOnly = true, source = new { path = Image },
        containerUuid = Hex, volumeUuid = volume, volumeOid = "101", checkpointXid = "90",
        snapshots = new[] { new { name = "backup", xid = "21", createTimeNs = "0", superblockPhysicalBlock = "249",
            omapPhysicalBlock = "17", omapTreePhysicalBlock = "230", rootOid = "8293", rootPhysicalBlock = "8", extentrefPhysicalBlock = "250" } }
    });
}

public sealed class WindowsSurfacePresenterTests
{
    [SnapshotRecoveryStatusFact]
    public void SnapshotRecoveryFromActualNativeAcceptedStatusSurvivesIpcAndBuildsExactRequest()
        => CheckActualNativeRecoveryRequest(degraded: false);

    [SnapshotRecoveryStatusFact]
    public void SnapshotRecoveryFromActuallyDegradedNativeAcceptedStatusStaysUnavailableThroughIpc()
        => CheckActualNativeRecoveryRequest(degraded: true);

    private static void CheckActualNativeRecoveryRequest(bool degraded)
    {
        var fixture = SnapshotRecoveryFixture.Load(degraded);
        var native = (ContainerMountStatus)typeof(ContainerStatusReader).GetMethod("Parse",
            System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic)!.Invoke(null, [fixture.StatusJson])!;
        var child = native.Volumes.Single(v => v.ObjectId == 101);
        var inventory = fixture.Inventory(native.ContainerUuid, child.ObjectId, child.RecoveryIdentity);
        var volume = inventory.Volumes[0];
        var mount = new MountedVolumeState(volume.VolumeId, "R:\\", child.Writable ? MountAccessMode.ReadWrite : MountAccessMode.ReadOnly,
            DeviceId: fixture.Source, RecoveryIdentity: child.RecoveryIdentity, MountReady: child.Ready, HostProcessId: native.OwnerPid,
            RecoveryActive: child.RecoveryActive, RecoveryReason: child.RecoveryReason, CatalogVolumeId: volume.CatalogVolumeId,
            CatalogContainerUuid: native.ContainerUuid, CatalogVolumeObjectId: child.ObjectId, CatalogVolumeUuid: fixture.VolumeUuid,
            SnapshotRecoverySupported: child.SnapshotRecoverySupported, SnapshotInventorySupported: child.SnapshotInventorySupported,
            SnapshotMutationSupported: child.SnapshotMutationSupported);
        var status = WindowsSurfaceFixture.Status() with { ConnectedInventory = [inventory], MountedVolumes = MountedStatusProjection.FromMounts([mount]) };
        status = JsonSerializer.Deserialize<StatusChangedPayload>(JsonSerializer.Serialize(status))!;
        Assert.True(PipeMessageCodec.Validate(PipeMessageCodec.Create(ApfsMessageTypes.StatusChanged, status)).IsValid);
        var row = Assert.Single(DriveDashboardPresenter.BuildRows(status));
        Assert.False(row.CanListSnapshots); Assert.False(row.CanMutateSnapshots);
        if (degraded)
        {
            Assert.False(row.CanRecoverSnapshots);
            Assert.Throws<InvalidOperationException>(() => DriveDashboardPresenter.CreateSnapshotRequest(status, row, ApfsControlCommands.SnapshotRecover));
            return;
        }
        Assert.True(row.CanRecoverSnapshots);
        var request = DriveDashboardPresenter.CreateSnapshotRequest(status, row, ApfsControlCommands.SnapshotRecover);
        Assert.Equal(SelectedControlTarget.Create(inventory, volume), request.Target);
        Assert.Null(request.SnapshotName); Assert.Null(request.SnapshotIdentity);
        Assert.True(PipeMessageCodec.Validate(PipeMessageCodec.Create(ApfsMessageTypes.ControlOperationRequest, request, request.OperationId, 2)).IsValid);
    }

    [Fact]
    public void ResizeFormatRequiresExplicitServiceGateStreamedWholeImageAndNativeReadiness()
    {
        var status = WindowsSurfaceFixture.Status() with { ConnectedInventory = [WindowsSurfaceFixture.Inventory(2097152)],
            VolumeManagementReadyImages = [WindowsSurfaceFixture.Image] };
        Assert.False(Assert.Single(DriveDashboardPresenter.BuildRows(status)).CanResizeFormatImage);
        Assert.True(Assert.Single(DriveDashboardPresenter.BuildRows(status with { ImageResizeFormatEnabled = true })).CanResizeFormatImage);
        Assert.False(Assert.Single(DriveDashboardPresenter.BuildRows(status with { ImageResizeFormatEnabled = true, ManagementJournalRootInspected = false })).CanResizeFormatImage);
        Assert.True(Assert.Single(DriveDashboardPresenter.BuildRows(status with { ImageResizeFormatEnabled = true, ConnectedInventory = [WindowsSurfaceFixture.Inventory(536870912)] })).CanResizeFormatImage);
    }
    [Theory]
    [InlineData(536870912L, true)] [InlineData(1099511627776L, true)]
    [InlineData(1099511631872L, false)] [InlineData(536870913L, false)]
    public void StreamedImageAvailabilityKeepsExactOperationAndBoundedCreateDelete(long bytes, bool available)
    {
        var status = WindowsSurfaceFixture.Status() with { ConnectedInventory = [WindowsSurfaceFixture.Inventory(bytes)],
            VolumeManagementReadyImages = [WindowsSurfaceFixture.Image], ImageResizeFormatEnabled = true };
        var row = Assert.Single(DriveDashboardPresenter.BuildRows(status));
        Assert.Equal(available, row.CanResizeImage); Assert.Equal(available, row.CanFormatImage);
        foreach (var operation in new[] { "grow", "shrink", "format", "erase" })
            Assert.Equal(available, row.CanPlanImageOperation(operation));
        Assert.False(row.CanPlanImageOperation("create")); Assert.False(row.CanPlanImageOperation("delete"));
        Assert.False(row.CanManageTopologyImage);
        Assert.False(Assert.Single(DriveDashboardPresenter.BuildRows(status with { VolumeManagementReadyImages = [] })).CanResizeFormatImage);
        if (row.SnapshotScope is { } scope) {
            var offset = row with { CanResizeFormatImage = true, SnapshotScope = scope with { StoreOffsetBytes = "4096" },
                ManagementScope = scope with { StoreOffsetBytes = "4096" } };
            Assert.False(offset.CanResizeImage); Assert.False(offset.CanFormatImage);
        }
    }
    [Fact]
    public void PhysicalManagementRequiresNativeReadinessAndOnlyOffersFormatOrErase()
    {
        const string device = @"\\.\PhysicalDrive2";
        var original = WindowsSurfaceFixture.Inventory(536870912);
        var topology = original.Topology!;
        var inventory = original with {
            Device = original.Device with { DeviceId = device },
            Volumes = [original.Volumes[0] with { DeviceId = device }],
            Topology = topology with { DeviceId = device, Snapshot = topology.Snapshot with {
                Disks = [topology.Snapshot.Disks[0] with { DeviceIdentifier = device, SizeBytes = 128L<<30 }],
                Stores = [topology.Snapshot.Stores[0] with { OffsetBytes = 1048576,
                    BlockSizeBytes = 4096, TotalBlocks = 536870912UL / 4096 }]
            } }
        };
        Assert.True(TopologyAdmission.Validate(inventory));
        var status = WindowsSurfaceFixture.Status() with { ConnectedInventory = [inventory], ImageResizeFormatEnabled = true,
            VolumeManagementReadyImages = [device] };
        var row = Assert.Single(DriveDashboardPresenter.BuildRows(status));
        Assert.Null(row.SnapshotScope); Assert.NotNull(row.ManagementScope);
        Assert.True(row.CanPlanImageOperation("format")); Assert.True(row.CanPlanImageOperation("erase"));
        Assert.True(row.CanResizeImage); Assert.True(row.CanPlanImageOperation("grow")); Assert.True(row.CanPlanImageOperation("shrink"));
        Assert.False(row.CanPlanImageOperation("create")); Assert.False(row.CanPlanImageOperation("delete"));
        Assert.False(row.CanManageTopologyImage); Assert.False(row.CanVerifyOffline);
        var missingGeometry = inventory with { Topology = inventory.Topology! with { Snapshot = inventory.Topology.Snapshot with {
            Stores = [inventory.Topology.Snapshot.Stores[0] with { TotalBlocks = null }]
        } } };
        Assert.Null(Assert.Single(DriveDashboardPresenter.BuildRows(status with { ConnectedInventory = [missingGeometry] })).ManagementScope);
        Assert.False(Assert.Single(DriveDashboardPresenter.BuildRows(status with { VolumeManagementReadyImages = [] })).CanFormatImage);
        Assert.False(Assert.Single(DriveDashboardPresenter.BuildRows(status with { ManagementJournalRootInspected = false })).CanFormatImage);
        var mounted = WindowsSurfaceFixture.Status(true).MountedVolumes![0] with { DeviceId = device };
        Assert.False(Assert.Single(DriveDashboardPresenter.BuildRows(status with { MountedVolumes = [mounted] })).CanFormatImage);
    }
    [Fact]
    public void UninspectedManagementRootCannotAdvertiseAnyImageManagementAction()
    {
        var status = WindowsSurfaceFixture.Status() with { ManagementJournalRootInspected = false,
            VolumeManagementReadyImages = [WindowsSurfaceFixture.Image] };
        var row = Assert.Single(DriveDashboardPresenter.BuildRows(status));
        Assert.False(row.CanManageOffline); Assert.False(row.CanManageTopologyImage); Assert.True(row.CanVerifyOffline);
    }

    [Theory]
    [InlineData(134217728L, true)] [InlineData(268435456L, true)] [InlineData(268439552L, false)]
    public void BoundedPhysicalTopologyRequiresCanonicalReadinessAndQuiescedSource(long bytes, bool available)
    {
        const string device = @"\\.\PhysicalDrive42";
        var original = WindowsSurfaceFixture.Inventory(bytes); var topology = original.Topology!;
        var inventory = original with {
            Device = original.Device with { DeviceId = device }, Volumes = [original.Volumes[0] with { DeviceId = device }],
            Topology = topology with { DeviceId = device, Snapshot = topology.Snapshot with {
                Disks = [topology.Snapshot.Disks[0] with { DeviceIdentifier = device, SizeBytes = 4L << 30 }],
                Stores = [topology.Snapshot.Stores[0] with { OffsetBytes = 1048576,
                    BlockSizeBytes = 4096, TotalBlocks = (ulong)bytes / 4096 }]
            } }
        };
        var status = WindowsSurfaceFixture.Status() with { ConnectedInventory = [inventory], VolumeManagementReadyImages = [device] };
        var row = Assert.Single(DriveDashboardPresenter.BuildRows(status));
        Assert.Equal(available, row.CanManageTopologyImage);
        var missingGeometry = inventory with { Topology = inventory.Topology! with { Snapshot = inventory.Topology.Snapshot with {
            Stores = [inventory.Topology.Snapshot.Stores[0] with { BlockSizeBytes = null }]
        } } };
        Assert.False(Assert.Single(DriveDashboardPresenter.BuildRows(status with { ConnectedInventory = [missingGeometry] })).CanManageTopologyImage);
        Assert.False(row.CanPlanImageOperation("create")); Assert.False(row.CanPlanImageOperation("delete"));
        Assert.False(Assert.Single(DriveDashboardPresenter.BuildRows(status with { VolumeManagementReadyImages = [] })).CanManageTopologyImage);
        Assert.False(Assert.Single(DriveDashboardPresenter.BuildRows(status with { ManagementJournalRootInspected = false })).CanManageTopologyImage);
        Assert.False(Assert.Single(DriveDashboardPresenter.BuildRows(status with { ImageManagementMutationsEnabled = false })).CanManageTopologyImage);
        var mount = WindowsSurfaceFixture.Status(true).MountedVolumes![0] with { DeviceId = device };
        Assert.False(Assert.Single(DriveDashboardPresenter.BuildRows(status with { MountedVolumes = [mount] })).CanManageTopologyImage);
    }

    [Fact]
    public void HealthyRwWithoutSnapshotEnrollmentCannotAdvertiseMutationOrRecovery()
    {
        var status = WindowsSurfaceFixture.Status(true, snapshotRuntimeReady: false);
        var row = Assert.Single(DriveDashboardPresenter.BuildRows(status));
        Assert.False(row.CanMutateSnapshots); Assert.False(row.CanRecoverSnapshots);
        Assert.Contains("SnapshotRuntimeOwnerNotReady", DriveDashboardPresenter.VolumeUnavailableActionReason("snapshots"));
    }

    [Fact]
    public void TopologyImageControlsRequireNativeObservationAndEntireSourceOffline()
    {
        var status = WindowsSurfaceFixture.Status();
        Assert.False(Assert.Single(DriveDashboardPresenter.BuildRows(status)).CanManageTopologyImage);
        status = status with { VolumeManagementReadyImages = [WindowsSurfaceFixture.Image] };
        Assert.True(Assert.Single(DriveDashboardPresenter.BuildRows(status)).CanManageTopologyImage);
        var mounted = status with { MountedVolumes = WindowsSurfaceFixture.Status(true).MountedVolumes };
        Assert.False(Assert.Single(DriveDashboardPresenter.BuildRows(mounted)).CanManageTopologyImage);
    }
    [Fact]
    public void OfflineActionsRequireAllSourceOwnersAbsentAndAnAdmittedGraph()
    {
        var status = WindowsSurfaceFixture.Status();
        var row = Assert.Single(DriveDashboardPresenter.BuildRows(status));
        Assert.True(row.CanVerifyOffline); Assert.True(row.CanManageOffline);
        var otherMount = WindowsSurfaceFixture.Status(true).MountedVolumes![0] with { VolumeId = "sibling", CatalogVolumeId = null };
        var live = status with { MountedVolumes = [otherMount] };
        var selected = DriveDashboardPresenter.BuildRows(live).Single(r => r.VolumeId == row.VolumeId);
        Assert.False(selected.CanVerifyOffline); Assert.False(selected.CanManageOffline);
        Assert.Throws<InvalidOperationException>(() => DriveDashboardPresenter.CreateManagementPlanRequest(live, row, ApfsManagementOperations.RenameVolume));
        var d = status.ConnectedInventory![0];
        var invalid = status with { ConnectedInventory = [d with { Topology = d.Topology! with { DeviceId = "other" } }] };
        Assert.All(TopologyDashboard.Project(invalid).Where(n => n.Row is not null), n =>
        { Assert.False(n.Row!.CanManageOffline); Assert.False(n.Row.CanVerifyOffline); Assert.False(n.Row.CanMutateSnapshots); });
    }

    [Fact]
    public void ManagementEditorRequestsBindTheSelectedSourceAndRejectClones()
    {
        var status = WindowsSurfaceFixture.Status(); var row = Assert.Single(DriveDashboardPresenter.BuildRows(status));
        var request = DriveDashboardPresenter.CreateManagementApplyRequest(status, row, ApfsManagementOperations.SetQuotaReserve,
            "token", quotaBytes: "65536", reserveBytes: "20480", imagePath: WindowsSurfaceFixture.Image);
        Assert.Equal(SelectedControlTarget.Create(status.ConnectedInventory![0], status.ConnectedInventory[0].Volumes[0]), request.Target);
        Assert.Equal("65536", request.ManagementQuotaBytes); Assert.Equal("20480", request.ManagementReserveBytes);
        Assert.Throws<InvalidOperationException>(() => DriveDashboardPresenter.CreateManagementApplyRequest(status, row,
            ApfsManagementOperations.RenameVolume, "token", name: "New", imagePath: @"D:\clone.apfs"));
    }

    [Fact]
    public void SnapshotInventorySuppliesAllNineDeleteIdentityFields()
    {
        var offline = WindowsSurfaceFixture.Status(); var row = Assert.Single(DriveDashboardPresenter.BuildRows(offline));
        var view = SnapshotInventoryView.Parse(WindowsSurfaceFixture.SnapshotInventory(), row);
        var entry = Assert.Single(view.Entries);
        Assert.Equal(new[] { "21", "backup", "249", "17", "230", "8293", "8", "250", "90" }, entry.DeleteIdentity);
        Assert.Throws<InvalidDataException>(() => SnapshotInventoryView.Parse(WindowsSurfaceFixture.SnapshotInventory(new string('c', 32)), row));
        Assert.Throws<InvalidOperationException>(() => DriveDashboardPresenter.CreateSnapshotRequest(offline, row,
            ApfsControlCommands.SnapshotDelete, identity: entry.DeleteIdentity));
        var mounted = WindowsSurfaceFixture.Status(true); var selected = Assert.Single(DriveDashboardPresenter.BuildRows(mounted));
        Assert.True(selected.CanMutateSnapshots);
        var request = DriveDashboardPresenter.CreateSnapshotRequest(mounted, selected, ApfsControlCommands.SnapshotDelete, identity: entry.DeleteIdentity);
        Assert.True(PipeMessageCodec.Validate(PipeMessageCodec.Create(ApfsMessageTypes.ControlOperationRequest, request, request.OperationId, 2)).IsValid);
        Assert.Equal(entry.DeleteIdentity, request.SnapshotIdentity);
        Assert.Throws<InvalidOperationException>(() => DriveDashboardPresenter.CreateSnapshotRequest(mounted, selected,
            ApfsControlCommands.SnapshotDelete, identity: ["21", "backup"]));
    }

    [Fact]
    public void SnapshotCreateRecoverAndListUseDifferentOwnerConditions()
    {
        var offline = WindowsSurfaceFixture.Status(); var row = Assert.Single(DriveDashboardPresenter.BuildRows(offline));
        Assert.Equal(ApfsControlCommands.SnapshotList, DriveDashboardPresenter.CreateSnapshotRequest(offline, row, ApfsControlCommands.SnapshotList).Command);
        var mounted = WindowsSurfaceFixture.Status(true); row = Assert.Single(DriveDashboardPresenter.BuildRows(mounted));
        var create = DriveDashboardPresenter.CreateSnapshotRequest(mounted, row, ApfsControlCommands.SnapshotCreate, name: "New snapshot");
        Assert.Equal("New snapshot", create.SnapshotName);
        Assert.Null(create.SnapshotIdentity);
        Assert.True(row.CanListSnapshots);
        Assert.Equal(ApfsControlCommands.SnapshotList, DriveDashboardPresenter.CreateSnapshotRequest(mounted, row, ApfsControlCommands.SnapshotList).Command);
        var recovery = WindowsSurfaceFixture.Status(true, true); row = Assert.Single(DriveDashboardPresenter.BuildRows(recovery));
        Assert.False(row.CanMutateSnapshots); Assert.False(row.CanListSnapshots); Assert.True(row.CanRecoverSnapshots);
        Assert.Equal(ApfsControlCommands.SnapshotRecover,
            DriveDashboardPresenter.CreateSnapshotRequest(recovery, row, ApfsControlCommands.SnapshotRecover).Command);
        Assert.Throws<InvalidOperationException>(() => DriveDashboardPresenter.CreateSnapshotRequest(recovery, row,
            ApfsControlCommands.SnapshotCreate, name: "Blocked"));
        Assert.Throws<InvalidOperationException>(() => DriveDashboardPresenter.CreateSnapshotRequest(recovery, row,
            ApfsControlCommands.SnapshotDelete, identity: ["21", "backup", "249", "17", "230", "8293", "8", "250", "90"]));
    }

    [Theory]
    [InlineData("capability")]
    [InlineData("owner")]
    [InlineData("runtime")]
    [InlineData("ready")]
    [InlineData("recovery-identity")]
    [InlineData("unmounted")]
    [InlineData("encrypted")]
    [InlineData("source")]
    public void SnapshotRecoveryRefusesLostEligibilityOrStaleSelectedTarget(string change)
    {
        var status = WindowsSurfaceFixture.Status(true, true);
        var selected = Assert.Single(DriveDashboardPresenter.BuildRows(status));
        var mount = status.MountedVolumes![0];
        var device = status.ConnectedInventory![0];
        status = change switch
        {
            "capability" => status with { MountedVolumes = [mount with { SnapshotRecoverySupported = false }] },
            "owner" => status with { MountedVolumes = [mount with { HostProcessId = 0 }] },
            "runtime" => status with { MountedVolumes = [mount with { HasRuntimeStatus = false }] },
            "ready" => status with { MountedVolumes = [mount with { MountReady = false }] },
            "recovery-identity" => status with { MountedVolumes = [mount with { RecoveryIdentity = "other" }] },
            "unmounted" => status with { MountedVolumes = [] },
            "encrypted" => status with { ConnectedInventory = [device with { Volumes = [device.Volumes[0] with { IsEncrypted = true }] }] },
            _ => status with { ConnectedInventory = [device with { Topology = device.Topology! with { DeviceId = "other" } }] }
        };
        Assert.Throws<InvalidOperationException>(() => DriveDashboardPresenter.CreateSnapshotRequest(status, selected,
            ApfsControlCommands.SnapshotRecover));
    }
}
