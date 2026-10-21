using ApfsAccess.Core;
using ApfsAccess.Ipc;
using ApfsAccess.Tray;

namespace ApfsAccess.Tray.Tests;

public sealed class BackupImageDashboardTests
{
    private static StatusChangedPayload Status()
    {
        const string image = @"D:\BackupDashboardTests\backup.apfs";
        const string uuid = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", vuuid = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        var cid = "apfs-container:" + uuid; var vid = ApfsTopology.BuildVolumeId(uuid, 101);
        var did = ApfsTopology.BuildDiskId("backup-dashboard"); var sid = ApfsTopology.BuildRawStoreId();
        var row = new VolumeInfo(vid, image, "Backup", true, SupportsNativeWrite: true,
            RecoveryIdentity: "backup-original", CatalogVolumeId: vid, CatalogContainerUuid: uuid, CatalogVolumeObjectId: 101,
            CatalogDecision: ApfsCapabilityDecision.Readable, CatalogReasons: ["special-role:backup"],
            CatalogAutoMountAllowed: false, CatalogVolumeUuid: vuuid);
        var graph = new ApfsTopologySnapshot([new(did, image, null, 8192)], [],
            [new(sid, "", "", cid, 0, 8192, 4096, 2, did)],
            [new(cid, uuid, 4096, [sid], [vid], false, "20", [], [], [], [])],
            [new(vid, vuuid, "101", cid, "Backup", true, ["backup"], 384, null, "sensitive", "none", false,
                [], [], [], "1", "20", [])], []);
        var observation = new ApfsDiscoveryTopology(1, image, [did], graph);
        row = row with { BackupImageWrite = BackupImageMountPolicy.Observe(row, observation) };
        return new(RuntimeState.Idle, [], null, DateTime.UtcNow, [], false, [],
            ConnectedInventory: [new(new(image, "Backup image", true), [row], observation)], InventoryGeneration: 1);
    }

    [Fact]
    public void BoundBackupMountUsesReadWriteAndKeepsGenericFixAndSnapshotMutationUnavailable()
    {
        var status = Status();
        var row = Assert.Single(TopologyDashboard.Project(status).Where(n => n.Row is not null)).Row!;
        Assert.True(row.CanMountBackupReadWrite); Assert.True(row.CanMount);
        Assert.False(DriveDashboardPresenter.CanFixVolume(row));
        Assert.False(row.CanMutateSnapshots); Assert.False(row.CanManageTopologyImage);
        var request = DriveDashboardPresenter.CreateMountRequest(status, row);
        Assert.Equal(ApfsControlModes.ReadWrite, request.RequestedMode);
        Assert.Equal(ApfsControlCommands.Mount, request.Command);
        Assert.Equal(status.ConnectedInventory![0].Volumes[0].VolumeId, request.Target!.VolumeId);
    }

    [Fact]
    public void ChangedReadonlyBitsAndMissingTopologyRevokeBackupAction()
    {
        var status = Status();
        var row = Assert.Single(TopologyDashboard.Project(status).Where(n => n.Row is not null)).Row!;
        var inventory = status.ConnectedInventory![0]; var observation = inventory.Topology!;
        var graph = observation.Snapshot;
        var altered = status with { ConnectedInventory = [inventory with { Topology = observation with {
            Snapshot = graph with { Volumes = [graph.Volumes[0] with { ReadonlyFeatureBits = ["0x1"] }] } } }] };
        Assert.Throws<InvalidOperationException>(() => DriveDashboardPresenter.CreateMountRequest(altered, row));
        var missing = status with { ConnectedInventory = [inventory with { Topology = null }] };
        Assert.DoesNotContain(DriveDashboardPresenter.BuildRows(missing), r => r.CanMountBackupReadWrite);
        Assert.Throws<InvalidOperationException>(() => DriveDashboardPresenter.CreateMountRequest(missing, row));
    }
}
