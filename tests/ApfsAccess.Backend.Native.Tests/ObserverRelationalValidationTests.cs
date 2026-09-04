using System.Text.Json.Nodes;
using ApfsAccess.Core;

namespace ApfsAccess.Backend.Native.Tests;

// A9 managed relational validation: hostile-output battery.
// RED first: each hostile case must throw InvalidOperationException.
public sealed class ObserverRelationalValidationTests
{
    private const string ContainerHex = "a9cb92d28b7c4b599eab633c7625f491";
    private const string ContainerHex2 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    [Fact]
    public void ValidEvidence_PassesRelationalValidation()
    {
        var json = ObserverEvidenceJson.BuildSingleContainer(
            ContainerHex, [new ObserverEvidenceJson.VolumeJson("Data", 101)]);
        var evidence = NativeApfsObserver.ParseAndValidateEvidence(json);
        Assert.NotNull(evidence);
    }

    [Fact]
    public void DanglingVolumeContainerId_Throws()
    {
        var json = MutateTopology(ObserverEvidenceJson.BuildSingleContainer(
            ContainerHex, [new ObserverEvidenceJson.VolumeJson("Data", 101)]),
            topo => topo["volumes"]![0]!["containerId"] = "apfs-container:ffffffffffffffffffffffffffffffff");
        Assert.Throws<InvalidOperationException>(() => NativeApfsObserver.ParseAndValidateEvidence(json));
    }

    [Fact]
    public void DanglingStoreContainerId_Throws()
    {
        var json = MutateTopology(ObserverEvidenceJson.BuildSingleContainer(
            ContainerHex, [new ObserverEvidenceJson.VolumeJson("Data", 101)]),
            topo => topo["stores"]![0]!["containerId"] = "apfs-container:ffffffffffffffffffffffffffffffff");
        Assert.Throws<InvalidOperationException>(() => NativeApfsObserver.ParseAndValidateEvidence(json));
    }

    [Fact]
    public void DanglingPartitionDiskId_Throws()
    {
        var json = MutateTopology(ValidWithPartition(),
            topo => topo["partitions"]![0]!["diskId"] = "apfs-disk:missing");
        Assert.Throws<InvalidOperationException>(() => NativeApfsObserver.ParseAndValidateEvidence(json));
    }

    [Fact]
    public void DuplicateVolumeIds_Throws()
    {
        var json = ObserverEvidenceJson.BuildSingleContainer(
            ContainerHex,
            [new ObserverEvidenceJson.VolumeJson("Data", 101),
             new ObserverEvidenceJson.VolumeJson("Backup", 101)]);
        // Same OID => same volume id apfs-vol:<hex>:101 duplicated.
        Assert.Throws<InvalidOperationException>(() => NativeApfsObserver.ParseAndValidateEvidence(json));
    }

    [Fact]
    public void DuplicateContainerIds_Throws()
    {
        var baseJson = ObserverEvidenceJson.BuildContainers(
            [(ContainerHex, [new ObserverEvidenceJson.VolumeJson("Data", 101)]),
             (ContainerHex2, [new ObserverEvidenceJson.VolumeJson("Backup", 102)])]);
        var node = JsonNode.Parse(baseJson)!.AsObject();
        var containers = node["topology"]!["containers"]!.AsArray();
        // Force second container to reuse first container's id.
        containers[1]!["id"] = containers[0]!["id"]!.GetValue<string>();
        Assert.Throws<InvalidOperationException>(() => NativeApfsObserver.ParseAndValidateEvidence(node.ToJsonString()));
    }

    [Fact]
    public void ContainerVolumeIds_SubsetMismatch_Throws()
    {
        var json = MutateTopology(ObserverEvidenceJson.BuildSingleContainer(
            ContainerHex,
            [new ObserverEvidenceJson.VolumeJson("Data", 101),
             new ObserverEvidenceJson.VolumeJson("Backup", 102)]),
            topo =>
            {
                // Container lists only first volume (subset).
                var container = topo["containers"]![0]!.AsObject();
                container["volumeIds"] = new JsonArray($"apfs-vol:{ContainerHex}:101");
            });
        Assert.Throws<InvalidOperationException>(() => NativeApfsObserver.ParseAndValidateEvidence(json));
    }

    [Fact]
    public void ContainerVolumeIds_SupersetMismatch_Throws()
    {
        var json = MutateTopology(ObserverEvidenceJson.BuildSingleContainer(
            ContainerHex, [new ObserverEvidenceJson.VolumeJson("Data", 101)]),
            topo =>
            {
                var container = topo["containers"]![0]!.AsObject();
                var arr = container["volumeIds"]!.AsArray();
                arr.Add($"apfs-vol:{ContainerHex}:999");
            });
        Assert.Throws<InvalidOperationException>(() => NativeApfsObserver.ParseAndValidateEvidence(json));
    }

    [Fact]
    public void ContainerStoreIds_SubsetMismatch_Throws()
    {
        var json = MutateTopology(ObserverEvidenceJson.BuildSingleContainer(
            ContainerHex, [new ObserverEvidenceJson.VolumeJson("Data", 101)]),
            topo =>
            {
                var container = topo["containers"]![0]!.AsObject();
                container["storeIds"] = new JsonArray();
            });
        Assert.Throws<InvalidOperationException>(() => NativeApfsObserver.ParseAndValidateEvidence(json));
    }

    [Fact]
    public void ContainerStoreIds_SupersetMismatch_Throws()
    {
        var json = MutateTopology(ObserverEvidenceJson.BuildSingleContainer(
            ContainerHex, [new ObserverEvidenceJson.VolumeJson("Data", 101)]),
            topo =>
            {
                var container = topo["containers"]![0]!.AsObject();
                var arr = container["storeIds"]!.AsArray();
                arr.Add("apfs-store:ffffffff-ffff-ffff-ffff-ffffffffffff");
            });
        Assert.Throws<InvalidOperationException>(() => NativeApfsObserver.ParseAndValidateEvidence(json));
    }

    [Fact]
    public void BadContainerUuidFormat_Throws()
    {
        var json = MutateTopology(ObserverEvidenceJson.BuildSingleContainer(
            ContainerHex, [new ObserverEvidenceJson.VolumeJson("Data", 101)]),
            topo => topo["containers"]![0]!["uuid"] = "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ");
        Assert.Throws<InvalidOperationException>(() => NativeApfsObserver.ParseAndValidateEvidence(json));
    }

    [Fact]
    public void BadVolumeObjectIdFormat_LeadingZeros_Throws()
    {
        var json = MutateTopology(ObserverEvidenceJson.BuildSingleContainer(
            ContainerHex, [new ObserverEvidenceJson.VolumeJson("Data", 101)]),
            topo =>
            {
                topo["volumes"]![0]!["objectId"] = "0101";
                topo["volumes"]![0]!["id"] = $"apfs-vol:{ContainerHex}:0101";
            });
        Assert.Throws<InvalidOperationException>(() => NativeApfsObserver.ParseAndValidateEvidence(json));
    }

    [Fact]
    public void BadCheckpointXidFormat_Throws()
    {
        var json = MutateTopology(ObserverEvidenceJson.BuildSingleContainer(
            ContainerHex, [new ObserverEvidenceJson.VolumeJson("Data", 101)]),
            topo => topo["containers"]![0]!["checkpointXid"] = "not-a-number");
        Assert.Throws<InvalidOperationException>(() => NativeApfsObserver.ParseAndValidateEvidence(json));
    }

    [Fact]
    public void BadFeatureBitsFormat_Throws()
    {
        var json = MutateTopology(ObserverEvidenceJson.BuildSingleContainer(
            ContainerHex, [new ObserverEvidenceJson.VolumeJson("Data", 101)]),
            topo => topo["volumes"]![0]!["compatibleFeatureBits"] = new JsonArray("1", "0X2"));
        Assert.Throws<InvalidOperationException>(() => NativeApfsObserver.ParseAndValidateEvidence(json));
    }

    [Fact]
    public void FusionMode_WithSingleStore_Throws()
    {
        var json = MutateEnvelope(ObserverEvidenceJson.BuildSingleContainer(
            ContainerHex, [new ObserverEvidenceJson.VolumeJson("Data", 101)]),
            env => env["mode"] = "fusion");
        Assert.Throws<InvalidOperationException>(() => NativeApfsObserver.ParseAndValidateEvidence(json));
    }

    [Fact]
    public void InvalidMode_Throws()
    {
        var json = MutateEnvelope(ObserverEvidenceJson.BuildSingleContainer(
            ContainerHex, [new ObserverEvidenceJson.VolumeJson("Data", 101)]),
            env => env["mode"] = "invalid-mode");
        Assert.Throws<InvalidOperationException>(() => NativeApfsObserver.ParseAndValidateEvidence(json));
    }

    [Fact]
    public void EmptyProfile_Throws()
    {
        var json = MutateEnvelope(ObserverEvidenceJson.BuildSingleContainer(
            ContainerHex, [new ObserverEvidenceJson.VolumeJson("Data", 101)]),
            env => env["profile"] = "");
        Assert.Throws<InvalidOperationException>(() => NativeApfsObserver.ParseAndValidateEvidence(json));
    }

    [Fact]
    public void SyntheticTrue_Throws()
    {
        var json = MutateEnvelope(ObserverEvidenceJson.BuildSingleContainer(
            ContainerHex, [new ObserverEvidenceJson.VolumeJson("Data", 101)]),
            env => env["synthetic"] = true);
        Assert.Throws<InvalidOperationException>(() => NativeApfsObserver.ParseAndValidateEvidence(json));
    }

    [Fact]
    public void WrongFormatConst_Throws()
    {
        var json = MutateEnvelope(ObserverEvidenceJson.BuildSingleContainer(
            ContainerHex, [new ObserverEvidenceJson.VolumeJson("Data", 101)]),
            env => env["format"] = "wrong-format");
        Assert.Throws<InvalidOperationException>(() => NativeApfsObserver.ParseAndValidateEvidence(json));
    }

    [Fact]
    public void WrongVersionConst_Throws()
    {
        var json = MutateEnvelope(ObserverEvidenceJson.BuildSingleContainer(
            ContainerHex, [new ObserverEvidenceJson.VolumeJson("Data", 101)]),
            env => env["version"] = 999);
        Assert.Throws<InvalidOperationException>(() => NativeApfsObserver.ParseAndValidateEvidence(json));
    }

    [Fact]
    public void WrongObserverIdConst_Throws()
    {
        var json = MutateEnvelope(ObserverEvidenceJson.BuildSingleContainer(
            ContainerHex, [new ObserverEvidenceJson.VolumeJson("Data", 101)]),
            env => env["observerId"] = "someone-else");
        Assert.Throws<InvalidOperationException>(() => NativeApfsObserver.ParseAndValidateEvidence(json));
    }

    [Fact]
    public void EmptyTopology_DisksEmpty_Throws()
    {
        var json = MutateTopology(ObserverEvidenceJson.BuildSingleContainer(
            ContainerHex, [new ObserverEvidenceJson.VolumeJson("Data", 101)]),
            topo => topo["disks"] = new JsonArray());
        Assert.Throws<InvalidOperationException>(() => NativeApfsObserver.ParseAndValidateEvidence(json));
    }

    [Fact]
    public void EmptyTopology_VolumesEmpty_Throws()
    {
        var json = MutateTopology(ObserverEvidenceJson.BuildSingleContainer(
            ContainerHex, [new ObserverEvidenceJson.VolumeJson("Data", 101)]),
            topo =>
            {
                topo["volumes"] = new JsonArray();
                topo["containers"]![0]!["volumeIds"] = new JsonArray();
            });
        Assert.Throws<InvalidOperationException>(() => NativeApfsObserver.ParseAndValidateEvidence(json));
    }

    [Fact]
    public void SourceFull_WithoutSha256_Throws()
    {
        var json = MutateEnvelope(ObserverEvidenceJson.BuildSingleContainer(
            ContainerHex, [new ObserverEvidenceJson.VolumeJson("Data", 101)]),
            env =>
            {
                env["source"]!["hashScope"] = "full";
                env["source"]!["sha256"] = null;
            });
        Assert.Throws<InvalidOperationException>(() => NativeApfsObserver.ParseAndValidateEvidence(json));
    }

    [Fact]
    public void SourceNone_WithSha256Present_Throws()
    {
        var json = MutateEnvelope(ObserverEvidenceJson.BuildSingleContainer(
            ContainerHex, [new ObserverEvidenceJson.VolumeJson("Data", 101)]),
            env =>
            {
                env["source"]!["hashScope"] = "none";
                env["source"]!["sha256"] = new string('a', 64);
            });
        Assert.Throws<InvalidOperationException>(() => NativeApfsObserver.ParseAndValidateEvidence(json));
    }

    [Fact]
    public void SourceFull_WithBadSha256Format_Throws()
    {
        var json = MutateEnvelope(ObserverEvidenceJson.BuildSingleContainer(
            ContainerHex, [new ObserverEvidenceJson.VolumeJson("Data", 101)]),
            env =>
            {
                env["source"]!["hashScope"] = "full";
                env["source"]!["sha256"] = "NOTHEX";
            });
        Assert.Throws<InvalidOperationException>(() => NativeApfsObserver.ParseAndValidateEvidence(json));
    }

    [Fact]
    public void GroupTooFewVolumes_Throws()
    {
        var json = MutateTopology(ObserverEvidenceJson.BuildSingleContainer(
            ContainerHex, [new ObserverEvidenceJson.VolumeJson("Data", 101)]),
            topo =>
            {
                topo["groups"] = new JsonArray(new JsonObject
                {
                    ["id"] = "apfs-group:dddddddddddddddddddddddddddddddd",
                    ["uuid"] = "dddddddddddddddddddddddddddddddd",
                    ["volumeIds"] = new JsonArray($"apfs-vol:{ContainerHex}:101"),
                });
            });
        Assert.Throws<InvalidOperationException>(() => NativeApfsObserver.ParseAndValidateEvidence(json));
    }

    [Fact]
    public void GroupDanglingVolume_Throws()
    {
        var json = MutateTopology(ObserverEvidenceJson.BuildSingleContainer(
            ContainerHex,
            [new ObserverEvidenceJson.VolumeJson("Data", 101),
             new ObserverEvidenceJson.VolumeJson("Backup", 102)]),
            topo =>
            {
                topo["groups"] = new JsonArray(new JsonObject
                {
                    ["id"] = "apfs-group:dddddddddddddddddddddddddddddddd",
                    ["uuid"] = "dddddddddddddddddddddddddddddddd",
                    ["volumeIds"] = new JsonArray(
                        $"apfs-vol:{ContainerHex}:101",
                        $"apfs-vol:{ContainerHex}:999"),
                });
            });
        Assert.Throws<InvalidOperationException>(() => NativeApfsObserver.ParseAndValidateEvidence(json));
    }

    [Fact]
    public void GroupDuplicateVolumeIds_Throws()
    {
        var json = MutateTopology(ObserverEvidenceJson.BuildSingleContainer(
            ContainerHex,
            [new ObserverEvidenceJson.VolumeJson("Data", 101),
             new ObserverEvidenceJson.VolumeJson("Backup", 102)]),
            topo =>
            {
                topo["groups"] = new JsonArray(new JsonObject
                {
                    ["id"] = "apfs-group:dddddddddddddddddddddddddddddddd",
                    ["uuid"] = "dddddddddddddddddddddddddddddddd",
                    ["volumeIds"] = new JsonArray(
                        $"apfs-vol:{ContainerHex}:101",
                        $"apfs-vol:{ContainerHex}:101"),
                });
            });
        Assert.Throws<InvalidOperationException>(() => NativeApfsObserver.ParseAndValidateEvidence(json));
    }

    private static string MutateTopology(string json, Action<JsonObject> mutate)
    {
        var node = JsonNode.Parse(json)!.AsObject();
        mutate(node["topology"]!.AsObject());
        return node.ToJsonString();
    }

    private static string MutateEnvelope(string json, Action<JsonObject> mutate)
    {
        var node = JsonNode.Parse(json)!.AsObject();
        mutate(node);
        return node.ToJsonString();
    }

    private static string ValidWithPartition()
    {
        // Build a topology with one disk + one partition referencing it,
        // one store referencing the partition, one container, one volume.
        var containerHex = ContainerHex;
        var baseJson = ObserverEvidenceJson.BuildSingleContainer(
            containerHex, [new ObserverEvidenceJson.VolumeJson("Data", 101)]);
        var node = JsonNode.Parse(baseJson)!.AsObject();
        var topo = node["topology"]!.AsObject();
        var diskId = topo["disks"]![0]!["id"]!.GetValue<string>();
        var partitionId = "apfs-part:11111111-2222-3333-4444-555555555555";
        topo["partitions"] = new JsonArray(new JsonObject
        {
            ["id"] = partitionId,
            ["uuid"] = "11111111-2222-3333-4444-555555555555",
            ["diskId"] = diskId,
            ["index"] = 1,
            ["startByte"] = 20480,
            ["sizeBytes"] = 8366080,
            ["typeGuid"] = "7c3457ef-0000-11aa-aa11-00306543ecac",
            ["usage"] = "apfs",
        });
        // Point the store at the partition (helper uses empty partitionId for raw).
        topo["stores"]![0]!["partitionId"] = partitionId;
        topo["stores"]![0]!["id"] = partitionId.Replace("apfs-part:", "apfs-store:");
        // Fix container.storeIds to match the renamed store.
        topo["containers"]![0]!["storeIds"] = new JsonArray(topo["stores"]![0]!["id"]!.GetValue<string>());
        return node.ToJsonString();
    }
}
