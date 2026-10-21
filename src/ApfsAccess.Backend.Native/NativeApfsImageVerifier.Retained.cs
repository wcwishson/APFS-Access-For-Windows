using System.Globalization;
using System.Text.Json;

namespace ApfsAccess.Backend.Native;

public sealed partial class NativeApfsImageVerifier
{
    private static void ValidateRetainedOwnership(JsonElement root, JsonElement scope, int outcome)
    {
        var accounting = root.GetProperty("retainedOwnership");
        if (outcome != 1) { Require(accounting.ValueKind == JsonValueKind.Null); return; }
        Object(accounting, "checkpointXids metadataRanges payloadRanges allocatedMainBlocks allocatedInternalBlocks " +
            "ownedMainBlocks ownedInternalBlocks reservedMainBlocks deferredMainBlocks deferredInternalBlocks " +
            "snapshotPayloadUsage snapshotTotalBytes purgeableBytes");
        Require(accounting.GetProperty("snapshotTotalBytes").ValueKind == JsonValueKind.Null &&
            accounting.GetProperty("purgeableBytes").ValueKind == JsonValueKind.Null);
        var limit = Number(scope, "maxRecords");
        var census = root.GetProperty("allocationCensus");
        var capacity = Number(census, "containerBlockCount", false);
        var blockSize = Number(census, "blockSizeBytes", false);
        Require(capacity == Number(scope, "storeSizeBytes", false) / blockSize &&
            Number(scope, "storeSizeBytes", false) % blockSize == 0);
        var xids = accounting.GetProperty("checkpointXids");
        Require(xids.ValueKind == JsonValueKind.Array && xids.GetArrayLength() > 0 &&
            (ulong)xids.GetArrayLength() <= limit);
        ulong previous = 0;
        foreach (var xid in xids.EnumerateArray())
        {
            var text = xid.GetString();
            Require(NativeApfsSnapshotReader.IsU64(text, false));
            var value = ulong.Parse(text!, CultureInfo.InvariantCulture);
            Require(value > previous); previous = value;
        }
        Require(previous == Number(scope, "checkpointXid", false));
        var metadata = accounting.GetProperty("metadataRanges");
        var payload = accounting.GetProperty("payloadRanges");
        Require(metadata.ValueKind == JsonValueKind.Array && payload.ValueKind == JsonValueKind.Array &&
            (ulong)metadata.GetArrayLength() + (ulong)payload.GetArrayLength() + (ulong)xids.GetArrayLength() <= limit);
        var metadataBlocks = ValidateRanges(metadata, capacity);
        var payloadBlocks = ValidateRanges(payload, capacity);
        Require(metadataBlocks > 0 && checked(metadataBlocks + payloadBlocks) <= capacity);
        RequireDisjoint(metadata, payload);
        Require(metadata.EnumerateArray().Any(range => Number(range, "physicalBlock") == 0));
        foreach (var key in "checkpointPhysicalBlock volumeSuperblockPhysicalBlock rootPhysicalBlock".Split(' '))
        {
            var block = Number(root.GetProperty("selected"), key, false);
            Require(metadata.EnumerateArray().Any(range => {
                var first = Number(range, "physicalBlock");
                return block >= first && block - first < Number(range, "blockCount", false);
            }));
        }
        var main = Number(accounting, "allocatedMainBlocks");
        var internalBlocks = Number(accounting, "allocatedInternalBlocks");
        var ownedMain = Number(accounting, "ownedMainBlocks");
        var ownedInternal = Number(accounting, "ownedInternalBlocks");
        Require(main == checked(ownedMain + Number(accounting, "reservedMainBlocks") + Number(accounting, "deferredMainBlocks")) &&
            internalBlocks == checked(ownedInternal + Number(accounting, "deferredInternalBlocks")) &&
            main <= capacity && internalBlocks <= main &&
            ownedMain == checked(metadataBlocks + payloadBlocks) && ownedInternal <= metadataBlocks &&
            Number(census, "currentMetadataBlocks", false) <= metadataBlocks &&
            Number(census, "currentPayloadBlocks") <= payloadBlocks);
        // The internal pool is also reserved in the main address space. These
        // two allocator totals are separate partitions and must not be added.
        Require(Number(census, "unattributedMainBlocks") == 0 && Number(census, "unattributedInternalBlocks") == 0);
        var usage = accounting.GetProperty("snapshotPayloadUsage");
        Require(usage.ValueKind == JsonValueKind.Array && usage.GetArrayLength() > 0 &&
            (ulong)usage.GetArrayLength() <= limit);
        var volumes = new HashSet<ulong>();
        ulong previousVolume = 0, referencedTotal = 0;
        foreach (var volume in usage.EnumerateArray())
        {
            Object(volume, "volumeOid referencedBlocks exclusiveBlocks referencedBytes exclusiveBytes");
            var oid = Number(volume, "volumeOid", false);
            Require(oid > previousVolume && volumes.Add(oid)); previousVolume = oid;
            var referenced = Number(volume, "referencedBlocks");
            var exclusive = Number(volume, "exclusiveBlocks");
            Require(exclusive <= referenced && referenced <= payloadBlocks - referencedTotal &&
                Number(volume, "referencedBytes") == checked(referenced * blockSize) &&
                Number(volume, "exclusiveBytes") == checked(exclusive * blockSize));
            referencedTotal = checked(referencedTotal + referenced);
        }
        Require(volumes.Contains(Number(scope, "volumeOid", false)));
    }
}
