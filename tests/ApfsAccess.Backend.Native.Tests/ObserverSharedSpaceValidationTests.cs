using System.Globalization;
using System.Text.Json.Nodes;
using ApfsAccess.Core;

namespace ApfsAccess.Backend.Native.Tests;

public sealed class ObserverSharedSpaceValidationTests
{
    [Fact]
    public void DisplayObservationBindsExactVolumeAndCheckpoint()
    {
        var topology = ObserverMetadataValidationTests.Parse(Payload()).Topology;
        var container = topology.Containers[0];
        var volume = topology.Volumes[1];
        var observed = NativeApfsObserver.ObserveVolumeSpace(container, volume);
        Assert.NotNull(observed);
        Assert.Equal(102UL, observed.Volume.ObjectId);
        Assert.Equal(35UL * 4096, observed.Volume.Available.Bytes);
        Assert.Equal(60UL * 4096, observed.ContainerFree.Bytes);
        Assert.Null(observed.Volume.Snapshot);
        Assert.Null(NativeApfsObserver.ObserveVolumeSpace(container with { CheckpointXid = "8" }, volume));
        Assert.Null(NativeApfsObserver.ObserveVolumeSpace(container, volume with { ContainerId = "another" }));
        Assert.Null(NativeApfsObserver.ObserveVolumeSpace(container, volume with { ObjectId = "101" }));
        var repeated = container.SharedSpace! with { Volumes = [observed.Volume, observed.Volume] };
        Assert.Null(NativeApfsObserver.ObserveVolumeSpace(container with { SharedSpace = repeated }, volume));
    }

    private static JsonObject Amount(ulong blocks) => new()
    {
        ["blocks"] = blocks.ToString(CultureInfo.InvariantCulture),
        ["bytes"] = checked(blocks * 4096).ToString(CultureInfo.InvariantCulture),
    };

    internal static JsonObject Payload()
    {
        var root = ObserverMetadataValidationTests.Payload(true);
        root["topology"]!["containers"]![0]!["sharedSpace"] = new JsonObject
        {
            ["containerId"] = "apfs-container:" + ObserverMetadataValidationTests.Container,
            ["checkpointXid"] = "7", ["allocationUnitBytes"] = 4096,
            ["total"] = Amount(100), ["free"] = Amount(60), ["used"] = Amount(40),
            ["volumes"] = new JsonArray(Volume(101, 10, 20, null, 15, 45), Volume(102, 15, 30, 50, 10, 35)),
        };
        return root;
    }

    private static JsonObject Volume(ulong oid, ulong allocated, ulong? reserve, ulong? quota, ulong siblings, ulong available) => new()
    {
        ["volumeId"] = $"apfs-vol:{ObserverMetadataValidationTests.Container}:{oid}", ["objectId"] = oid.ToString(),
        ["allocated"] = Amount(allocated), ["reserve"] = reserve.HasValue ? Amount(reserve.Value) : null,
        ["quota"] = quota.HasValue ? Amount(quota.Value) : null, ["siblingReserveRemaining"] = Amount(siblings),
        ["available"] = Amount(available), ["snapshot"] = null, ["purgeable"] = null,
    };

    [Fact]
    public void SharedProjectionPreservesSiblingAvailabilityAndUnknownCounters()
    {
        var s = ObserverMetadataValidationTests.Parse(Payload()).Topology.Containers[0].SharedSpace!;
        Assert.Equal(60UL, s.Free.Blocks);
        Assert.Equal(40UL, s.Used.Blocks); // not the sum of per-volume allocations (25)
        Assert.Equal(45UL, s.Volumes[0].Available.Blocks);
        Assert.Equal(35UL, s.Volumes[1].Available.Blocks); // total available > free is valid
        Assert.Null(s.Volumes[0].Quota);
        Assert.All(s.Volumes, v => { Assert.Null(v.Snapshot); Assert.Null(v.Purgeable); });
    }

    [Fact]
    public void UnknownProjectionRemainsNullAndLegacyHasNoMetadata()
    {
        Assert.Null(ObserverMetadataValidationTests.Parse(ObserverMetadataValidationTests.Payload()).Topology.Containers[0].SharedSpace);
        var legacy = NativeApfsObserver.ParseAndValidateEvidence(ObserverEvidenceJson.BuildSingleContainer(
            ObserverMetadataValidationTests.Container, [new("Data", 101)]));
        Assert.Null(legacy.TopologyMetadataVersion);
        Assert.Null(legacy.Topology.Volumes[0].RoleName);
        Assert.Null(legacy.Topology.Volumes[0].GroupMetadataValid);
        Assert.Null(legacy.Topology.Containers[0].SharedSpace);
    }

    [Theory]
    [InlineData(10)]
    [InlineData(15)]
    public void ExhaustedAndExceededQuotaReportKnownZero(int quota)
    {
        var root = Payload(); var s = Space(root); var vs = s["volumes"]!;
        vs[1]!["reserve"] = null; vs[1]!["quota"] = Amount((ulong)quota); vs[1]!["available"] = Amount(0);
        vs[0]!["siblingReserveRemaining"] = Amount(0); vs[0]!["available"] = Amount(60);
        Assert.Equal(0UL, ObserverMetadataValidationTests.Parse(root).Topology.Containers[0].SharedSpace!.Volumes[1].Available.Bytes);
    }

    [Fact]
    public void CheckpointAndQuotaAboveSignedAndDoublePrecisionRemainExact()
    {
        var root = Payload(); var s = Space(root);
        root["topology"]!["containers"]![0]!["checkpointXid"] = ulong.MaxValue.ToString();
        s["checkpointXid"] = ulong.MaxValue.ToString();
        s["volumes"]![0]!["quota"] = Amount(ulong.MaxValue / 4096);
        var parsed = ObserverMetadataValidationTests.Parse(root).Topology.Containers[0].SharedSpace!;
        Assert.Equal(ulong.MaxValue, parsed.CheckpointXid);
        Assert.Equal(ulong.MaxValue - 4095, parsed.Volumes[0].Quota!.Bytes);
    }

    [Fact]
    public void FullContainerAndZeroAllocationRemainKnownZeros()
    {
        var root = Payload(); var s = Space(root);
        s["free"] = Amount(0); s["used"] = Amount(100);
        foreach (var v in s["volumes"]!.AsArray())
        {
            v!["allocated"] = Amount(0); v["reserve"] = null; v["quota"] = null;
            v["siblingReserveRemaining"] = Amount(0); v["available"] = Amount(0);
        }
        var parsed = ObserverMetadataValidationTests.Parse(root).Topology.Containers[0].SharedSpace!;
        Assert.Equal(0UL, parsed.Free.Bytes);
        Assert.All(parsed.Volumes, v => { Assert.Equal(0UL, v.Allocated.Bytes); Assert.Equal(0UL, v.Available.Bytes); });
    }

    [Theory]
    [InlineData("container")][InlineData("checkpoint")][InlineData("blocksize")]
    [InlineData("fusion")][InlineData("multistore")][InlineData("missing-volume")]
    [InlineData("duplicate-volume")][InlineData("wrong-oid")][InlineData("cross-container-volume")]
    [InlineData("total-used")][InlineData("free-over-total")][InlineData("oversize-store")]
    [InlineData("allocated-over-used")][InlineData("reserve-over-total")][InlineData("reserve-over-quota")]
    [InlineData("overcommit")][InlineData("wrong-siblings")][InlineData("wrong-available")]
    [InlineData("overflow")][InlineData("u64-overflow")][InlineData("numeric-u64")][InlineData("leading-zero")]
    [InlineData("negative")][InlineData("zero-reserve")][InlineData("zero-quota")]
    [InlineData("snapshot-zero")][InlineData("purgeable-zero")][InlineData("null-allocated")]
    [InlineData("missing-quota")][InlineData("missing-snapshot")][InlineData("unknown-field")]
    public void InvalidPresentSpaceRejected(string mutation)
    {
        var root = Payload(); var s = Space(root); var vs = s["volumes"]!.AsArray(); var v = vs[0]!.AsObject();
        switch (mutation)
        {
            case "container": s["containerId"] = "apfs-container:" + new string('f', 32); break;
            case "checkpoint": s["checkpointXid"] = "6"; break;
            case "blocksize": s["allocationUnitBytes"] = 16384; break;
            case "fusion": root["topology"]!["containers"]![0]!["fusion"] = true; break;
            case "multistore":
                var store = root["topology"]!["stores"]![0]!.DeepClone(); store["id"] = "apfs-store:extra";
                root["topology"]!["stores"]!.AsArray().Add(store);
                root["topology"]!["containers"]![0]!["storeIds"]!.AsArray().Add("apfs-store:extra"); break;
            case "missing-volume": vs.RemoveAt(1); break;
            case "duplicate-volume": vs.Add(v.DeepClone()); break;
            case "wrong-oid": v["objectId"] = "999"; break;
            case "cross-container-volume": v["volumeId"] = $"apfs-vol:{new string('f',32)}:101"; break;
            case "total-used": s["used"] = Amount(39); break;
            case "free-over-total": s["free"] = Amount(101); break;
            case "oversize-store": root["topology"]!["stores"]![0]!["sizeBytes"] = 4096; break;
            case "allocated-over-used": v["allocated"] = Amount(41); break;
            case "reserve-over-total": v["reserve"] = Amount(101); break;
            case "reserve-over-quota": v["quota"] = Amount(19); break;
            case "overcommit": v["reserve"] = Amount(90); break;
            case "wrong-siblings": v["siblingReserveRemaining"] = Amount(14); break;
            case "wrong-available": v["available"] = Amount(46); break;
            case "overflow": v["allocated"]!["blocks"] = ulong.MaxValue.ToString(); break;
            case "u64-overflow": s["checkpointXid"] = "18446744073709551616"; break;
            case "numeric-u64": s["checkpointXid"] = 7; break;
            case "leading-zero": s["checkpointXid"] = "07"; break;
            case "negative": v["allocated"]!["blocks"] = "-1"; break;
            case "zero-reserve": v["reserve"] = Amount(0); break;
            case "zero-quota": v["quota"] = Amount(0); break;
            case "snapshot-zero": v["snapshot"] = Amount(0); break;
            case "purgeable-zero": v["purgeable"] = Amount(0); break;
            case "null-allocated": v["allocated"] = null; break;
            case "missing-quota": v.Remove("quota"); break;
            case "missing-snapshot": v.Remove("snapshot"); break;
            case "unknown-field": s["available"] = Amount(99); break;
        }
        Assert.Throws<InvalidOperationException>(() => ObserverMetadataValidationTests.Parse(root));
    }

    private static JsonObject Space(JsonObject root) => root["topology"]!["containers"]![0]!["sharedSpace"]!.AsObject();

    [Theory]
    [InlineData("blockSizeBytes", "16384")]
    [InlineData("blockSizeBytes", "null")]
    [InlineData("totalBlocks", "99")]
    [InlineData("totalBlocks", "0")]
    [InlineData("totalBlocks", "null")]
    [InlineData("totalBlocks", "18446744073709551616")]
    public void PresentStoreGeometryMustAgreeWithProjection(string field, string value)
    {
        var root = Payload(); root["topology"]!["stores"]![0]![field] = JsonNode.Parse(value);
        Assert.Throws<InvalidOperationException>(() => ObserverMetadataValidationTests.Parse(root));
    }

    [Fact]
    public void MatchingOptionalStoreGeometryIsTyped()
    {
        var root = Payload(); var store = root["topology"]!["stores"]![0]!;
        store["blockSizeBytes"] = 4096; store["totalBlocks"] = 100;
        var parsed = ObserverMetadataValidationTests.Parse(root).Topology.Stores[0];
        Assert.Equal(4096L, parsed.BlockSizeBytes); Assert.Equal(100UL, parsed.TotalBlocks);
    }
}
