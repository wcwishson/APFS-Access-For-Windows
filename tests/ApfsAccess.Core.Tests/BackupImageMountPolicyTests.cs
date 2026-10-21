using ApfsAccess.Core;

namespace ApfsAccess.Core.Tests;

public sealed class BackupImageMountPolicyTests
{
    private const string Image = @"D:\BackupProfileTests\backup.apfs";
    private const string Container = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    private const string Volume = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    private static (VolumeInfo Row, ApfsDiscoveryTopology Observation) Fixture()
    {
        var diskId = ApfsTopology.BuildDiskId("backup-image");
        var containerId = "apfs-container:" + Container;
        var volumeId = ApfsTopology.BuildVolumeId(Container, 101);
        var storeId = ApfsTopology.BuildRawStoreId();
        var row = new VolumeInfo(volumeId, Image, "History", false, RecoveryIdentity: "original-recovery",
            CatalogVolumeId: volumeId, CatalogContainerUuid: Container, CatalogVolumeObjectId: 101,
            CatalogDecision: ApfsCapabilityDecision.Readable, CatalogReasons: ["special-role:backup"],
            CatalogAutoMountAllowed: false, CatalogVolumeUuid: Volume);
        var snapshot = new ApfsTopologySnapshot([new(diskId, Image, null, 8192)], [],
            [new(storeId, "cccccccccccccccccccccccccccccccc", "", containerId, 0, 8192, 4096, 2, diskId)],
            [new(containerId, Container, 4096, [storeId], [volumeId], false, "20", [], [], [], [])],
            [new(volumeId, Volume, "101", containerId, "History", true, ["backup"], 384, null,
                "sensitive", "none", false, [], [], [], "1", "20", [])], []);
        return (row, new(1, Image, [diskId], snapshot));
    }

    private static ServiceHostOptions Options() => new()
    {
        EnableBackupImageWrites = true, EnableNativeWrite = true, WriteRolloutChannel = "Pilot",
        WriteBackendMode = "Native", WriteSafetyLevel = "Strict", NativeWriteMaxDirtyTransactions = 1,
        NativeWriteAllowLegacyScaffoldForFixtures = false, NativeWriteCrashReplayMode = "ReplayIfSafe",
        ManagementJournalRoot = @"D:\BackupProfileTests\journal"
    };

    [Fact]
    public void ExactPhysicalPartitionRequiresSeparateHeldOptionAndQualifiedRecoveryOwner()
    {
        var (row, observation) = Fixture();
        const string device = @"\\.\PhysicalDrive42";
        const string partition = "dddddddddddddddddddddddddddddddd";
        var t = observation.Snapshot;
        var disk = t.Disks[0] with { DeviceIdentifier = device, SizeBytes = 1048576 + 8192 };
        var partId = ApfsTopology.BuildPartitionId(Guid.Parse(partition));
        var store = t.Stores[0] with { Id = ApfsTopology.BuildStoreId(Guid.Parse(partition)),
            Uuid = partition, OffsetBytes = 1048576, PartitionId = partId, DiskId = null };
        var graph = t with { Disks = [disk], Stores = [store], Containers = [t.Containers[0] with { StoreIds = [store.Id] }],
            Partitions = [new(partId, partition, disk.Id, 1, 1048576, 8192,
                "7c3457ef-0000-11aa-aa11-00306543ecac", "apfs")] };
        row = row with { DeviceId = device };
        observation = observation with { DeviceId = device, Snapshot = graph };
        row = row with { BackupImageWrite = BackupImageMountPolicy.Observe(row, observation), SupportsNativeWrite = true };
        Assert.NotNull(row.BackupImageWrite);
        Assert.False(BackupImageMountPolicy.CanRequest(Options(), row));
        var options = Options(); options.EnableBackupImageWrites = false; options.EnableBackupHeldWrites = true;
        options.NativeWriteAllowRawPhysicalDevices = true;
        options.RawSnapshotHardwareQualification = new() { Scheme = RawSnapshotHardwareQualificationScheme.QualifiedSerialTuple,
            BusType = 7, Vendor = "Qualified", Product = "Storage", QualifiedSerial = "QualifiedSerial42" };
        Assert.True(BackupImageMountPolicy.CanRequest(options, row));
        Assert.False(CatalogMountPolicy.AllowsOrdinaryMount(row));
        options.NativeWriteAllowRawPhysicalDevices = false;
        Assert.False(BackupImageMountPolicy.CanRequest(options, row));
        Assert.Null(BackupImageMountPolicy.Observe(row, observation with {
            Snapshot = graph with { Partitions = [graph.Partitions[0] with { StartByte = long.MaxValue }] } }));
        Assert.Null(BackupImageMountPolicy.Observe(row, observation with {
            Snapshot = graph with { Volumes = [graph.Volumes[0] with { RoleRaw = 0x181 }] } }));
    }

    [Fact]
    public void ExplicitBoundedImageRetainsReadableCatalogAndNeverBecomesOrdinaryAutomount()
    {
        var (row, observation) = Fixture();
        row = row with { BackupImageWrite = BackupImageMountPolicy.Observe(row, observation), SupportsNativeWrite = true };
        Assert.NotNull(row.BackupImageWrite);
        Assert.True(BackupImageMountPolicy.AllowsExplicitMount(Options(), row, MountAccessMode.ReadWrite));
        Assert.False(BackupImageMountPolicy.AllowsExplicitMount(Options(), row, null));
        Assert.False(CatalogMountPolicy.AllowsOrdinaryMount(row));
        Assert.True(CatalogMountPolicy.AllowsReadOnlyInspection(row));
        Assert.Equal(ApfsCapabilityDecision.Readable, row.CatalogDecision);
        Assert.True(WriteGatePolicy.EvaluateForVolume(Options(), row).AllowWrite);
        var disabled = Options(); disabled.EnableBackupImageWrites = false;
        Assert.False(WriteGatePolicy.EvaluateForVolume(disabled, row).AllowWrite);
    }

    [Fact]
    public void PhysicalPathsMixedRolesReadonlyBitsSlicesAndSiblingGraphsCannotGainCandidate()
    {
        var (row, observation) = Fixture();
        var snapshot = observation.Snapshot;
        var bad = new[]
        {
            snapshot with { Volumes = [snapshot.Volumes[0] with { RoleRaw = 0x181 }] },
            snapshot with { Volumes = [snapshot.Volumes[0] with { ReadonlyFeatureBits = ["0x1"] }] },
            snapshot with { Containers = [snapshot.Containers[0] with { UnknownFeatureBits = ["0x2"] }] },
            snapshot with { Stores = [snapshot.Stores[0] with { OffsetBytes = 4096 }] },
            snapshot with { Volumes = [snapshot.Volumes[0], snapshot.Volumes[0] with { ObjectId = "102" }] },
            snapshot with { Containers = [snapshot.Containers[0] with { Fusion = true }] },
            snapshot with { Disks = [snapshot.Disks[0] with { SizeBytes = 16384 }] },
        };
        Assert.All(bad, graph => Assert.Null(BackupImageMountPolicy.Observe(row, observation with { Snapshot = graph })));
        Assert.Null(BackupImageMountPolicy.Observe(row with { DeviceId = @"\\.\PhysicalDrive3" }, observation));
        Assert.Null(BackupImageMountPolicy.Observe(row, observation with { DeviceId = @"D:\foreign.apfs" }));
    }

    [Fact]
    public void SelectedTopologyRejectsForgedBackupScopeAndPolicyKeepsOtherGates()
    {
        var (row, observation) = Fixture();
        row = row with { BackupImageWrite = BackupImageMountPolicy.Observe(row, observation), SupportsNativeWrite = true };
        var options = Options(); options.NativeWritePilotVolumeAllowList = ["different-volume"];
        Assert.False(WriteGatePolicy.EvaluateForVolume(options, row).AllowWrite);
        options = Options(); options.AllowWriteOnUnsupportedFeatures = true; options.WriteBackendMode = "Overlay";
        Assert.False(WriteGatePolicy.EvaluateForVolume(options, row).AllowWrite);
        options = Options(); options.NativeWriteRequireCanonicalCommit = false;
        Assert.False(BackupImageMountPolicy.CanRequest(options, row));
        Assert.False(BackupImageMountPolicy.HasCandidate(row with {
            BackupImageWrite = row.BackupImageWrite! with { VolumeObjectId = 102 } }));
        Assert.False(BackupImageMountPolicy.CanRequest(Options(), row with { NativeWriteAdmissionBlockReason = "unproved-source" }));
        var inventory = new DeviceInventory(new(Image, "Backup", true), [row], observation);
        Assert.True(TopologyAdmission.Validate(inventory));
        Assert.False(TopologyAdmission.Validate(inventory with { Topology = null }));
        Assert.False(TopologyAdmission.Validate(inventory with { Volumes = [row with {
            BackupImageWrite = row.BackupImageWrite! with { CheckpointXid = 21 } }] }));
    }
}
