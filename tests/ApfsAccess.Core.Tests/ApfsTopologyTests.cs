using System.Text.Json.Nodes;
using ApfsAccess.Core;

namespace ApfsAccess.Core.Tests;

public sealed class ApfsTopologyTests
{
    // ---- Canonical identity grammar: section 3 vectors ----

    [Fact]
    public void DiskId_BuildAndParse_RoundTrips()
    {
        var id = ApfsTopology.BuildDiskId("image-main");

        Assert.Equal("apfs-disk:image-main", id);
        Assert.True(ApfsTopology.TryParseDiskId(id, out var slug));
        Assert.Equal("image-main", slug);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("apfs-disk:")]
    [InlineData("apfs-vol:image-main")]
    [InlineData("apfs-disk:a|b")]
    [InlineData("apfs-disk:a b")]
    public void DiskId_InvalidInputs_AreRejected(string? candidate)
    {
        Assert.False(ApfsTopology.TryParseDiskId(candidate, out _));
        Assert.Throws<ArgumentException>(() => ApfsTopology.BuildDiskId(candidate!));
    }

    [Fact]
    public void PartitionId_BuildAndParse_RoundTripsLowercaseGuid()
    {
        var guid = new Guid("11111111-2222-3333-4444-555555555555");

        var id = ApfsTopology.BuildPartitionId(guid);

        Assert.Equal("apfs-part:11111111-2222-3333-4444-555555555555", id);
        Assert.True(ApfsTopology.TryParsePartitionId(id, out var parsed));
        Assert.Equal(guid, parsed);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("apfs-part:")]
    [InlineData("apfs-part:AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE")]
    [InlineData("apfs-part:not-a-guid")]
    [InlineData("apfs-part:11111111222233334444555555555555")]
    [InlineData("apfs-disk:11111111-2222-3333-4444-555555555555")]
    public void PartitionId_InvalidInputs_AreRejected(string? candidate)
    {
        Assert.False(ApfsTopology.TryParsePartitionId(candidate, out _));
    }

    [Fact]
    public void StoreId_BuildAndParse_RoundTrips()
    {
        var guid = new Guid("11111111-2222-3333-4444-555555555555");

        var id = ApfsTopology.BuildStoreId(guid);

        Assert.Equal("apfs-store:11111111-2222-3333-4444-555555555555", id);
        Assert.True(ApfsTopology.TryParseStoreId(id, out var parsedGuid, out var isRaw));
        Assert.False(isRaw);
        Assert.Equal(guid, parsedGuid);
    }

    [Fact]
    public void StoreId_RawVariant_ParsesAsRaw()
    {
        Assert.Equal("apfs-store:raw", ApfsTopology.BuildRawStoreId());
        Assert.True(ApfsTopology.TryParseStoreId("apfs-store:raw", out var guid, out var isRaw));
        Assert.True(isRaw);
        Assert.Null(guid);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("apfs-store:")]
    [InlineData("apfs-store:RAW")]
    [InlineData("apfs-store:NOT-A-GUID")]
    [InlineData("apfs-disk:raw")]
    public void StoreId_InvalidInputs_AreRejected(string? candidate)
    {
        Assert.False(ApfsTopology.TryParseStoreId(candidate, out _, out _));
    }

    [Fact]
    public void ContainerId_BuildAndParse_RoundTrips()
    {
        const string hex = "a9cb92d28b7c4b599eab633c7625f491";

        var id = ApfsTopology.BuildContainerId(hex);

        Assert.Equal("apfs-container:" + hex, id);
        Assert.True(ApfsTopology.TryParseContainerId(id, out var parsed));
        Assert.Equal(hex, parsed);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("apfs-container:")]
    [InlineData("apfs-container:A9CB92D28B7C4B599EAB633C7625F491")]
    [InlineData("apfs-container:a9cb92d28b7c4b599eab633c7625f49")]
    [InlineData("apfs-container:zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz")]
    [InlineData("apfs-vol:a9cb92d28b7c4b599eab633c7625f491")]
    public void ContainerId_InvalidInputs_AreRejected(string? candidate)
    {
        Assert.False(ApfsTopology.TryParseContainerId(candidate, out _));
        if (candidate is not null)
        {
            Assert.Throws<ArgumentException>(() => ApfsTopology.BuildContainerId(candidate));
        }
    }

    [Fact]
    public void VolumeId_BuildAndParse_RoundTrips()
    {
        const string hex = "a9cb92d28b7c4b599eab633c7625f491";

        var id = ApfsTopology.BuildVolumeId(hex, 101);

        Assert.Equal("apfs-vol:" + hex + ":101", id);
        Assert.True(ApfsTopology.TryParseVolumeId(id, out var parsedHex, out var oid));
        Assert.Equal(hex, parsedHex);
        Assert.Equal(101UL, oid);
    }

    [Theory]
    [InlineData("apfs-vol:a9cb92d28b7c4b599eab633c7625f491:0101")]
    [InlineData("apfs-vol:a9cb92d28b7c4b599eab633c7625f491:-1")]
    [InlineData("apfs-vol:a9cb92d28b7c4b599eab633c7625f491:18446744073709551616")]
    [InlineData("apfs-vol:a9cb92d28b7c4b599eab633c7625f491:notanumber")]
    [InlineData("apfs-vol:a9cb92d28b7c4b599eab633c7625f491:")]
    [InlineData("apfs-vol:a9cb92d28b7c4b599eab633c7625f491")]
    [InlineData("apfs-vol:A9CB92D28B7C4B599EAB633C7625F491:101")]
    [InlineData("")]
    [InlineData(null)]
    public void VolumeId_InvalidInputs_AreRejected(string? candidate)
    {
        Assert.False(ApfsTopology.TryParseVolumeId(candidate, out _, out _));
    }

    [Fact]
    public void GroupId_BuildAndParse_RoundTrips()
    {
        const string hex = "dddddddddddddddddddddddddddddddd";

        var id = ApfsTopology.BuildGroupId(hex);

        Assert.Equal("apfs-group:" + hex, id);
        Assert.True(ApfsTopology.TryParseGroupId(id, out var parsed));
        Assert.Equal(hex, parsed);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("apfs-group:")]
    [InlineData("apfs-group:DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD")]
    [InlineData("apfs-vol:dddddddddddddddddddddddddddddddd")]
    public void GroupId_InvalidInputs_AreRejected(string? candidate)
    {
        Assert.False(ApfsTopology.TryParseGroupId(candidate, out _));
    }

    // ---- Legacy device|volumeName <-> typed lookup ----

    [Fact]
    public void LegacyLookup_UniqueNameOnDevice_ResolvesTypedId()
    {
        var snapshot = SingleDeviceSnapshot();

        Assert.True(ApfsTopology.TryResolveTypedVolumeId(
            snapshot, "main", "Data", out var typedId, out var error));
        Assert.Equal("apfs-vol:a9cb92d28b7c4b599eab633c7625f491:101", typedId);
        Assert.Equal(string.Empty, error);
    }

    [Fact]
    public void LegacyLookup_NameMatch_IsCaseInsensitive()
    {
        var snapshot = SingleDeviceSnapshot();

        Assert.True(ApfsTopology.TryResolveTypedVolumeId(
            snapshot, "MAIN", "data", out var typedId, out _));
        Assert.Equal("apfs-vol:a9cb92d28b7c4b599eab633c7625f491:101", typedId);
    }

    [Theory]
    [InlineData("missing-device", "Data")]
    [InlineData("main", "NoSuchVolume")]
    [InlineData("main", "")]
    [InlineData("main", "   ")]
    [InlineData("", "Data")]
    public void LegacyLookup_UnknownDeviceOrNameOrEmpty_ReturnsError(string deviceId, string volumeName)
    {
        var snapshot = SingleDeviceSnapshot();

        Assert.False(ApfsTopology.TryResolveTypedVolumeId(
            snapshot, deviceId, volumeName, out var typedId, out var error));
        Assert.Null(typedId);
        Assert.False(string.IsNullOrWhiteSpace(error));
    }

    [Fact]
    public void LegacyLookup_DuplicateNameOnDevice_IsAmbiguousError()
    {
        var snapshot = AmbiguousNameSnapshot();

        Assert.False(ApfsTopology.TryResolveTypedVolumeId(
            snapshot, "main", "Data", out var typedId, out var error));
        Assert.Null(typedId);
        Assert.Contains("mbiguous", error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void LegacyLookup_SameNameOnDifferentDevices_ResolvesPerDevice()
    {
        var snapshot = TwoDeviceSnapshot();

        Assert.True(ApfsTopology.TryResolveTypedVolumeId(
            snapshot, "main", "Data", out var mainId, out _));
        Assert.True(ApfsTopology.TryResolveTypedVolumeId(
            snapshot, "other", "Data", out var otherId, out _));
        Assert.NotEqual(mainId, otherId);
    }

    [Fact]
    public void LegacyReverse_UniqueName_RoundTripsWithoutLoss()
    {
        var snapshot = SingleDeviceSnapshot();

        Assert.True(ApfsTopology.TryBuildLegacyVolumeId(
            snapshot,
            "apfs-vol:a9cb92d28b7c4b599eab633c7625f491:101",
            out var legacyId, out var lossy, out var error));
        Assert.Equal("main|Data", legacyId);
        Assert.False(lossy);
        Assert.Equal(string.Empty, error);
    }

    [Fact]
    public void LegacyReverse_CollidingName_SucceedsWithLossyFlag()
    {
        var snapshot = AmbiguousNameSnapshot();

        Assert.True(ApfsTopology.TryBuildLegacyVolumeId(
            snapshot,
            "apfs-vol:a9cb92d28b7c4b599eab633c7625f491:101",
            out var legacyId, out var lossy, out _));
        Assert.Equal("main|Data", legacyId);
        Assert.True(lossy);
    }

    [Fact]
    public void LegacyReverse_UnknownTypedId_ReturnsError()
    {
        var snapshot = SingleDeviceSnapshot();

        Assert.False(ApfsTopology.TryBuildLegacyVolumeId(
            snapshot, "apfs-vol:ffffffffffffffffffffffffffffffff:999",
            out var legacyId, out _, out var error));
        Assert.Null(legacyId);
        Assert.False(string.IsNullOrWhiteSpace(error));
    }

    // ---- Observer JSON deserialization, field-for-field ----

    [Fact]
    public void ParseEvidence_HandWrittenSample_MatchesSchemaFieldForField()
    {
        var evidence = ApfsTopology.ParseEvidence(SampleEvidenceJson);

        Assert.Equal("apfs-access-raw-evidence", evidence.Format);
        Assert.Equal(1, evidence.Version);
        Assert.Equal("apfs-access-owned-raw-observer", evidence.ObserverId);
        Assert.Equal("1.0.0", evidence.ObserverVersion);
        Assert.Equal("collect", evidence.Mode);
        Assert.Equal("single-volume", evidence.Profile);
        Assert.False(evidence.Synthetic);

        Assert.Equal("image", evidence.Source.Kind);
        Assert.Equal("given-path", evidence.Source.Path);
        Assert.Equal(8388608L, evidence.Source.SizeBytes);
        Assert.Equal("full", evidence.Source.HashScope);
        Assert.Equal("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", evidence.Source.Sha256);
        Assert.NotNull(evidence.SecondarySources);
        Assert.Empty(evidence.SecondarySources!);

        var disk = Assert.Single(evidence.Topology.Disks);
        Assert.Equal("apfs-disk:main", disk.Id);
        Assert.Equal("main", disk.DeviceIdentifier);
        Assert.Null(disk.Uuid);
        Assert.Equal(8388608L, disk.SizeBytes);

        var partition = Assert.Single(evidence.Topology.Partitions);
        Assert.Equal("apfs-part:11111111-2222-3333-4444-555555555555", partition.Id);
        Assert.Equal("11111111-2222-3333-4444-555555555555", partition.Uuid);
        Assert.Equal("apfs-disk:main", partition.DiskId);
        Assert.Equal(1, partition.Index);
        Assert.Equal(20480L, partition.StartByte);
        Assert.Equal(8366080L, partition.SizeBytes);
        Assert.Equal("7c3457ef-0000-11aa-aa11-00306543ecac", partition.TypeGuid);
        Assert.Equal("apfs", partition.Usage);

        var store = Assert.Single(evidence.Topology.Stores);
        Assert.Equal("apfs-store:11111111-2222-3333-4444-555555555555", store.Id);
        Assert.Equal("a9cb92d28b7c4b599eab633c7625f491", store.Uuid);
        Assert.Equal("apfs-part:11111111-2222-3333-4444-555555555555", store.PartitionId);
        Assert.Equal("apfs-container:a9cb92d28b7c4b599eab633c7625f491", store.ContainerId);
        Assert.Equal(20480L, store.OffsetBytes);
        Assert.Equal(8366080L, store.SizeBytes);

        var container = Assert.Single(evidence.Topology.Containers);
        Assert.Equal("apfs-container:a9cb92d28b7c4b599eab633c7625f491", container.Id);
        Assert.Equal("a9cb92d28b7c4b599eab633c7625f491", container.Uuid);
        Assert.Equal(4096L, container.BlockSizeBytes);
        Assert.Equal(
            ["apfs-store:11111111-2222-3333-4444-555555555555"],
            container.StoreIds);
        Assert.Equal(
            [
                "apfs-vol:a9cb92d28b7c4b599eab633c7625f491:101",
                "apfs-vol:a9cb92d28b7c4b599eab633c7625f491:102",
            ],
            container.VolumeIds);
        Assert.False(container.Fusion);
        Assert.Equal("7", container.CheckpointXid);
        Assert.Equal(["0x1"], container.CompatibleFeatureBits);
        Assert.Empty(container.ReadonlyFeatureBits!);
        Assert.Empty(container.UnknownFeatureBits);
        Assert.Empty(container.IncompatibleFeatureBits);

        Assert.Equal(2, evidence.Topology.Volumes.Count);
        var data = evidence.Topology.Volumes[0];
        Assert.Equal("apfs-vol:a9cb92d28b7c4b599eab633c7625f491:101", data.Id);
        Assert.Equal("c3d4e5f60718293a4b5c6d7e8f90a1b2", data.Uuid);
        Assert.Equal("101", data.ObjectId);
        Assert.Equal("apfs-container:a9cb92d28b7c4b599eab633c7625f491", data.ContainerId);
        Assert.Equal("Data", data.Name);
        Assert.True(data.NameUtf8Valid);
        Assert.Equal(["data"], data.Roles);
        Assert.Equal(32L, data.RoleRaw);
        Assert.Equal("apfs-group:dddddddddddddddddddddddddddddddd", data.GroupId);
        Assert.Equal("sensitive", data.CaseMode);
        Assert.Equal("none", data.EncryptionMode);
        Assert.False(data.Locked);
        Assert.Equal(["0x1"], data.CompatibleFeatureBits);
        Assert.Empty(data.ReadonlyFeatureBits!);
        Assert.Empty(data.UnknownFeatureBits);
        Assert.Empty(data.IncompatibleFeatureBits);
        Assert.Equal("12", data.SuperblockBlock);
        Assert.Equal("7", data.SuperblockXid);

        var system = evidence.Topology.Volumes[1];
        Assert.Equal("apfs-vol:a9cb92d28b7c4b599eab633c7625f491:102", system.Id);
        Assert.Equal(string.Empty, system.Uuid);
        Assert.Equal("102", system.ObjectId);
        Assert.Equal("System", system.Name);
        Assert.Equal(["system"], system.Roles);
        Assert.Equal(1L, system.RoleRaw);
        Assert.Equal("insensitive", system.CaseMode);
        Assert.Equal("13", system.SuperblockBlock);

        var group = Assert.Single(evidence.Topology.Groups);
        Assert.Equal("apfs-group:dddddddddddddddddddddddddddddddd", group.Id);
        Assert.Equal("dddddddddddddddddddddddddddddddd", group.Uuid);
        Assert.Equal(
            [
                "apfs-vol:a9cb92d28b7c4b599eab633c7625f491:101",
                "apfs-vol:a9cb92d28b7c4b599eab633c7625f491:102",
            ],
            group.VolumeIds);

        // The parsed snapshot must serve the legacy lookup directly.
        Assert.True(ApfsTopology.TryResolveTypedVolumeId(
            evidence.Topology, "main", "Data", out var typedId, out _));
        Assert.Equal("apfs-vol:a9cb92d28b7c4b599eab633c7625f491:101", typedId);
    }

    [Fact]
    public void ParseEvidence_PreV11SampleWithoutSecondarySources_StillParsesLeniently()
    {
        // Core parsing stays lenient (absent => null); REQUIRED-envelope
        // enforcement lives in NativeApfsObserver.ParseAndValidateEvidence.
        var node = JsonNode.Parse(SampleEvidenceJson)!.AsObject();
        Assert.True(node.Remove("secondarySources"));
        var evidence = ApfsTopology.ParseEvidence(node.ToJsonString());

        Assert.Null(evidence.SecondarySources);
        Assert.Equal("apfs-access-raw-evidence", evidence.Format);
    }

    // ---- Helpers ----

    private const string ContainerHex = "a9cb92d28b7c4b599eab633c7625f491";
    private const string MainContainerId = "apfs-container:" + ContainerHex;
    private const string DataVolumeId = "apfs-vol:" + ContainerHex + ":101";
    private const string SystemVolumeId = "apfs-vol:" + ContainerHex + ":102";

    private static ApfsTopologySnapshot SingleDeviceSnapshot() => new(
        Disks: [new ApfsDiskRecord("apfs-disk:main", "main", null, 8388608)],
        Partitions:
        [
            new ApfsPartitionRecord(
                "apfs-part:11111111-2222-3333-4444-555555555555",
                "11111111-2222-3333-4444-555555555555",
                "apfs-disk:main", 1, 20480, 8366080,
                "7c3457ef-0000-11aa-aa11-00306543ecac", "apfs"),
        ],
        Stores:
        [
            new ApfsStoreRecord(
                "apfs-store:11111111-2222-3333-4444-555555555555",
                ContainerHex,
                "apfs-part:11111111-2222-3333-4444-555555555555",
                MainContainerId, 20480, 8366080),
        ],
        Containers:
        [
            new ApfsContainerRecord(
                MainContainerId, ContainerHex, 4096,
                ["apfs-store:11111111-2222-3333-4444-555555555555"],
                [DataVolumeId, SystemVolumeId],
                false, "7", ["0x1"], [], []),
        ],
        Volumes:
        [
            DataVolume("Data", DataVolumeId, "101"),
            DataVolume("System", SystemVolumeId, "102", ["system"], 1),
        ],
        Groups: []);

    private static ApfsTopologySnapshot AmbiguousNameSnapshot()
    {
        const string container2Hex = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        const string container2Id = "apfs-container:" + container2Hex;
        const string dupVolumeId = "apfs-vol:" + container2Hex + ":201";
        var base_ = SingleDeviceSnapshot();
        return base_ with
        {
            Stores =
            [
                .. base_.Stores,
                new ApfsStoreRecord(
                    "apfs-store:22222222-2222-2222-2222-222222222222",
                    container2Hex,
                    "apfs-part:22222222-2222-2222-2222-222222222222",
                    container2Id, 16777216, 8366080),
            ],
            Partitions =
            [
                .. base_.Partitions,
                new ApfsPartitionRecord(
                    "apfs-part:22222222-2222-2222-2222-222222222222",
                    "22222222-2222-2222-2222-222222222222",
                    "apfs-disk:main", 2, 16777216, 8366080,
                    "7c3457ef-0000-11aa-aa11-00306543ecac", "apfs"),
            ],
            Containers =
            [
                .. base_.Containers,
                new ApfsContainerRecord(
                    container2Id, container2Hex, 4096,
                    ["apfs-store:22222222-2222-2222-2222-222222222222"],
                    [dupVolumeId],
                    false, "7", ["0x1"], [], []),
            ],
            Volumes =
            [
                .. base_.Volumes,
                DataVolume("Data", dupVolumeId, "201", ContainerId: container2Id),
            ],
        };
    }

    private static ApfsTopologySnapshot TwoDeviceSnapshot()
    {
        const string container2Hex = "cccccccccccccccccccccccccccccccc";
        const string container2Id = "apfs-container:" + container2Hex;
        const string otherVolumeId = "apfs-vol:" + container2Hex + ":301";
        var base_ = SingleDeviceSnapshot();
        return base_ with
        {
            Disks =
            [
                .. base_.Disks,
                new ApfsDiskRecord("apfs-disk:other", "other", null, 8388608),
            ],
            Stores =
            [
                .. base_.Stores,
                new ApfsStoreRecord(
                    "apfs-store:raw", container2Hex, string.Empty,
                    container2Id, 0, 8388608),
            ],
            Containers =
            [
                .. base_.Containers,
                new ApfsContainerRecord(
                    container2Id, container2Hex, 4096,
                    ["apfs-store:raw"],
                    [otherVolumeId],
                    false, "7", ["0x1"], [], []),
            ],
            Volumes =
            [
                .. base_.Volumes,
                DataVolume("Data", otherVolumeId, "301", ContainerId: container2Id),
            ],
        };
    }

    private static ApfsVolumeRecord DataVolume(
        string name,
        string id,
        string objectId,
        IReadOnlyList<string>? roles = null,
        long roleRaw = 32,
        string? ContainerId = null) => new(
            Id: id,
            Uuid: "c3d4e5f60718293a4b5c6d7e8f90a1b2",
            ObjectId: objectId,
            ContainerId: ContainerId ?? MainContainerId,
            Name: name,
            NameUtf8Valid: true,
            Roles: roles ?? ["data"],
            RoleRaw: roleRaw,
            GroupId: null,
            CaseMode: "sensitive",
            EncryptionMode: "none",
            Locked: false,
            CompatibleFeatureBits: ["0x1"],
            UnknownFeatureBits: [],
            IncompatibleFeatureBits: [],
            SuperblockBlock: "12",
            SuperblockXid: "7");

    private const string SampleEvidenceJson =
        """
        {
          "format": "apfs-access-raw-evidence",
          "version": 1,
          "observerId": "apfs-access-owned-raw-observer",
          "observerVersion": "1.0.0",
          "mode": "collect",
          "profile": "single-volume",
          "synthetic": false,
          "source": {
            "kind": "image",
            "path": "given-path",
            "sizeBytes": 8388608,
            "hashScope": "full",
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
          },
          "secondarySources": [],
          "topology": {
            "disks": [
              {"id": "apfs-disk:main", "deviceIdentifier": "main", "uuid": null, "sizeBytes": 8388608}
            ],
            "partitions": [
              {"id": "apfs-part:11111111-2222-3333-4444-555555555555", "uuid": "11111111-2222-3333-4444-555555555555", "diskId": "apfs-disk:main", "index": 1, "startByte": 20480, "sizeBytes": 8366080, "typeGuid": "7c3457ef-0000-11aa-aa11-00306543ecac", "usage": "apfs"}
            ],
            "stores": [
              {"id": "apfs-store:11111111-2222-3333-4444-555555555555", "uuid": "a9cb92d28b7c4b599eab633c7625f491", "partitionId": "apfs-part:11111111-2222-3333-4444-555555555555", "containerId": "apfs-container:a9cb92d28b7c4b599eab633c7625f491", "offsetBytes": 20480, "sizeBytes": 8366080}
            ],
            "containers": [
              {"id": "apfs-container:a9cb92d28b7c4b599eab633c7625f491", "uuid": "a9cb92d28b7c4b599eab633c7625f491", "blockSizeBytes": 4096, "storeIds": ["apfs-store:11111111-2222-3333-4444-555555555555"], "volumeIds": ["apfs-vol:a9cb92d28b7c4b599eab633c7625f491:101", "apfs-vol:a9cb92d28b7c4b599eab633c7625f491:102"], "fusion": false, "checkpointXid": "7", "compatibleFeatureBits": ["0x1"], "readonlyFeatureBits": [], "unknownFeatureBits": [], "incompatibleFeatureBits": []}
            ],
            "volumes": [
              {"id": "apfs-vol:a9cb92d28b7c4b599eab633c7625f491:101", "uuid": "c3d4e5f60718293a4b5c6d7e8f90a1b2", "objectId": "101", "containerId": "apfs-container:a9cb92d28b7c4b599eab633c7625f491", "name": "Data", "nameUtf8Valid": true, "roles": ["data"], "roleRaw": 32, "groupId": "apfs-group:dddddddddddddddddddddddddddddddd", "caseMode": "sensitive", "encryptionMode": "none", "locked": false, "compatibleFeatureBits": ["0x1"], "readonlyFeatureBits": [], "unknownFeatureBits": [], "incompatibleFeatureBits": [], "superblockBlock": "12", "superblockXid": "7"},
              {"id": "apfs-vol:a9cb92d28b7c4b599eab633c7625f491:102", "uuid": "", "objectId": "102", "containerId": "apfs-container:a9cb92d28b7c4b599eab633c7625f491", "name": "System", "nameUtf8Valid": true, "roles": ["system"], "roleRaw": 1, "groupId": "apfs-group:dddddddddddddddddddddddddddddddd", "caseMode": "insensitive", "encryptionMode": "none", "locked": false, "compatibleFeatureBits": ["0x1"], "readonlyFeatureBits": [], "unknownFeatureBits": [], "incompatibleFeatureBits": [], "superblockBlock": "13", "superblockXid": "7"}
            ],
            "groups": [
              {"id": "apfs-group:dddddddddddddddddddddddddddddddd", "uuid": "dddddddddddddddddddddddddddddddd", "volumeIds": ["apfs-vol:a9cb92d28b7c4b599eab633c7625f491:101", "apfs-vol:a9cb92d28b7c4b599eab633c7625f491:102"]}
            ]
          }
        }
        """;
}
