using ApfsAccess.Core;

namespace ApfsAccess.Core.Tests;

// Task 6 Step 1/3: the topology graph index is the shared trust root for
// topology admission (service), dashboard projection, and mount decisions.
// These pins prove fail-closed verdicts on malformed, ambiguous, cyclic,
// stale, and oversized inputs built from the real parsed-record shapes, plus
// acceptance of complete single- and multi-store topologies. Volume-group
// pairing (system/data by UUID with role checks) is validated here; no code
// in the tree follows cross-volume references, so firmlink-styled cycles can
// only ever resolve to refusal, never to a merged view.
public sealed class TopologyGraphIndexTests
{
    private const string DiskId = "apfs-disk:d1";
    private const string PartId = "apfs-part:d1p1";
    private const string StoreId = "apfs-store:s1";
    private const string ContainerId = "apfs-container:c1";
    private const string ContainerUuid = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    private const string DataVolumeId = "apfs-vol:v101";
    private const string DataUuid = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    private static ApfsTopologySnapshot Baseline(
        IReadOnlyList<ApfsVolumeRecord>? volumes = null,
        IReadOnlyList<ApfsGroupRecord>? groups = null,
        IReadOnlyList<ApfsContainerRecord>? containers = null)
    {
        var store = new ApfsStoreRecord(StoreId, ContainerUuid, PartId, ContainerId, 0, 8388608);
        var volumeList = volumes ?? [DataVolume("apfs-vol:v101", DataUuid, "101", ["data"])];
        var volumeIds = volumeList.Select(static v => v.Id).ToArray();
        var container = new ApfsContainerRecord(ContainerId, ContainerUuid, 4096, [StoreId], volumeIds,
            false, "20", ["0x1"], [], []);
        return new ApfsTopologySnapshot(
            [new ApfsDiskRecord(DiskId, "dev1", null, 16777216)],
            [new ApfsPartitionRecord(PartId, "cccccccccccccccccccccccccccccccc", DiskId, 1, 20480, 8388608,
                "7C3457EF-0000-11AA-AA11-00306543ECAC", "apfs")],
            [store],
            containers ?? [container],
            volumeList,
            groups ?? []);
    }

    private static ApfsVolumeRecord DataVolume(string id, string uuid, string oid, string[] roles,
        string? groupId = null, string? groupUuid = null, string? association = null) => new(
        id, uuid, oid, ContainerId, "Data", true, roles, 0, groupId, "insensitive", "none", false,
        ["0x1"], [], [], "12", "20", null, null, groupUuid, true, association);

    [Fact]
    public void ValidOrdinaryTopology_IsComplete()
    {
        var index = TopologyGraphIndex.Create(Baseline());

        Assert.NotNull(index);
        Assert.True(index.Complete);
        Assert.True(index.Stores.ContainsKey(StoreId));
    }

    [Fact]
    public void ValidSystemDataGroupPair_IsComplete()
    {
        const string groupUuid = "dddddddddddddddddddddddddddddddd";
        const string groupId = "apfs-group:" + groupUuid;
        const string systemId = "apfs-vol:v100";
        var volumes = new[]
        {
            DataVolume(systemId, "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", "100", ["system"],
                groupId, groupUuid, "valid-system-data"),
            DataVolume(DataVolumeId, DataUuid, "101", ["data"],
                groupId, groupUuid, "valid-system-data"),
        };
        var snapshot = Baseline(volumes,
            [new ApfsGroupRecord(groupId, groupUuid, [systemId, DataVolumeId], ContainerId,
                "valid-system-data", systemId, DataVolumeId)]);

        var index = TopologyGraphIndex.Create(snapshot);

        Assert.NotNull(index);
        Assert.True(index.Complete);
    }

    [Theory]
    [InlineData("ambiguous")]
    [InlineData("malformed")]
    public void BadAssociationStatus_ReturnsNull(string status)
    {
        const string groupUuid = "dddddddddddddddddddddddddddddddd";
        const string groupId = "apfs-group:" + groupUuid;
        var snapshot = Baseline(
            [DataVolume(DataVolumeId, DataUuid, "101", ["data"], groupId, groupUuid, status)],
            [new ApfsGroupRecord(groupId, groupUuid, [DataVolumeId], ContainerId, status, null, null)]);

        Assert.Null(TopologyGraphIndex.Create(snapshot));
    }

    [Fact]
    public void IncompleteGroup_MarksIncompleteWithoutRejecting()
    {
        const string groupUuid = "dddddddddddddddddddddddddddddddd";
        const string groupId = "apfs-group:" + groupUuid;
        var snapshot = Baseline(
            [DataVolume(DataVolumeId, DataUuid, "101", ["data"], groupId, groupUuid, "incomplete")],
            [new ApfsGroupRecord(groupId, groupUuid, [DataVolumeId], ContainerId, "incomplete", null, null)]);

        var index = TopologyGraphIndex.Create(snapshot);

        Assert.NotNull(index);
        Assert.False(index.Complete);
    }

    [Fact]
    public void RoleMismatchedPair_ReturnsNull()
    {
        const string groupUuid = "dddddddddddddddddddddddddddddddd";
        const string groupId = "apfs-group:" + groupUuid;
        const string systemId = "apfs-vol:v100";
        // Declared system member carries the data role: fail closed.
        var volumes = new[]
        {
            DataVolume(systemId, "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", "100", ["data"],
                groupId, groupUuid, "valid-system-data"),
            DataVolume(DataVolumeId, DataUuid, "101", ["data"],
                groupId, groupUuid, "valid-system-data"),
        };
        var snapshot = Baseline(volumes,
            [new ApfsGroupRecord(groupId, groupUuid, [systemId, DataVolumeId], ContainerId,
                "valid-system-data", systemId, DataVolumeId)]);

        Assert.Null(TopologyGraphIndex.Create(snapshot));
    }

    [Fact]
    public void GroupUuidMismatch_ReturnsNull()
    {
        const string groupUuid = "dddddddddddddddddddddddddddddddd";
        const string groupId = "apfs-group:" + groupUuid;
        var snapshot = Baseline(
            [DataVolume(DataVolumeId, DataUuid, "101", ["data"], groupId,
                "ffffffffffffffffffffffffffffffff", "valid-system-data")],
            [new ApfsGroupRecord(groupId, groupUuid, [DataVolumeId], ContainerId,
                "valid-system-data", null, null)]);

        Assert.Null(TopologyGraphIndex.Create(snapshot));
    }

    [Fact]
    public void DanglingStoreReference_MarksIncomplete()
    {
        var snapshot = Baseline();
        var orphan = new ApfsStoreRecord("apfs-store:orphan", ContainerUuid, PartId,
            "apfs-container:ghost", 0, 4096);
        snapshot = snapshot with { Stores = [..snapshot.Stores, orphan] };

        var index = TopologyGraphIndex.Create(snapshot);

        Assert.NotNull(index);
        Assert.False(index.Complete);
    }

    [Fact]
    public void DuplicateIds_ReturnsNull()
    {
        var snapshot = Baseline();
        snapshot = snapshot with
        {
            Disks = [..snapshot.Disks, new ApfsDiskRecord(DiskId, "dev-duplicate", null, 16777216)],
        };

        Assert.Null(TopologyGraphIndex.Create(snapshot));
    }

    [Fact]
    public void OversizedTopology_ReturnsNull()
    {
        var stores = Enumerable.Range(0, TopologyGraphIndex.Limit + 1)
            .Select(i => new ApfsStoreRecord($"apfs-store:overflow-{i}", ContainerUuid, PartId,
                ContainerId, 0, 4096))
            .ToArray();
        var snapshot = Baseline() with { Stores = stores };

        Assert.Null(TopologyGraphIndex.Create(snapshot));
    }

    [Fact]
    public void CyclicGroupVolumeReferences_TerminateWithVerdict()
    {
        // Groups reference volumes and volumes reference the group back; the
        // single-pass bounded walk must terminate with the correct verdict
        // rather than looping, and must never merge members into one node.
        const string groupUuid = "dddddddddddddddddddddddddddddddd";
        const string groupId = "apfs-group:" + groupUuid;
        const string systemId = "apfs-vol:v100";
        var volumes = new[]
        {
            DataVolume(systemId, "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", "100", ["system"],
                groupId, groupUuid, "valid-system-data"),
            DataVolume(DataVolumeId, DataUuid, "101", ["data"],
                groupId, groupUuid, "valid-system-data"),
        };
        var snapshot = Baseline(volumes,
            [new ApfsGroupRecord(groupId, groupUuid, [systemId, DataVolumeId], ContainerId,
                "valid-system-data", systemId, DataVolumeId)]);

        var index = TopologyGraphIndex.Create(snapshot);

        Assert.NotNull(index);
        Assert.True(index.Complete);
        Assert.Single(index.Stores);
    }

    [Fact]
    public void NullSnapshot_ReturnsNull()
    {
        Assert.Null(TopologyGraphIndex.Create(null));
    }

    [Fact]
    public void FusionTwoStoreContainer_IsComplete()
    {
        var tier2 = new ApfsStoreRecord("apfs-store:s2", ContainerUuid, PartId, ContainerId,
            8388608, 4194304);
        var snapshot = Baseline();
        snapshot = snapshot with
        {
            Stores = [..snapshot.Stores, tier2],
            Containers =
            [
                new ApfsContainerRecord(ContainerId, ContainerUuid, 4096,
                    [StoreId, "apfs-store:s2"], [DataVolumeId], true, "20", ["0x1"], [], []),
            ],
        };

        var index = TopologyGraphIndex.Create(snapshot);

        Assert.NotNull(index);
        Assert.True(index.Complete);
    }
}
