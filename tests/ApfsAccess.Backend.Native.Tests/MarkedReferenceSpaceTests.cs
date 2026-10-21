using System.Text.Json.Nodes;
using ApfsAccess.Backend.Native;

namespace ApfsAccess.Backend.Native.Tests;

public sealed class MarkedReferenceSpaceTests
{
    private static readonly ApfsSnapshotAttributionRequest Request = new("D:\\marked.apfs", "apfs-container:" + new string('a', 32),
        new string('b', 32), "101", "20", "0", "2097152");
    internal static JsonObject Document()
    {
        var root = JsonNode.Parse("""
        {"format":"apfs-access-marked-reference-space","version":1,"readOnly":true,"complete":true,
         "source":{"path":"","identity":"held-identity"},
         "scope":{"containerUuid":"","volumeUuid":"","volumeOid":"101","checkpointXid":"20","storeOffsetBytes":"0","storeSizeBytes":"2097152"},
         "allocationUnitBytes":4096,"namespaceAndDirectory7ReferencesVerified":true,"catalogMetadataAndPayloadAllocationVerified":true,
         "hiddenOwnersComplete":false,"retainedCheckpointHistoryVerified":false,
         "recordMeaning":"literal-is-purgeable-private-stream-file-extent-union",
         "filePayloadMeaning":"literal-is-purgeable-file-and-external-attribute-physical-union",
         "literalRecordUnion":{"blocks":"3","bytes":"12288"},"filePayloadUnion":{"blocks":"4","bytes":"16384"},
         "views":[
          {"viewXid":"18","current":false,"name":"first","markedRegularInodes":"1","wantOnlyRegularInodes":"1","literalRecordPayload":{"blocks":"2","bytes":"8192"},"filePayload":{"blocks":"2","bytes":"8192"},"filePayloadRanges":[{"physicalBlock":"220","blockCount":"2"}]},
          {"viewXid":"19","current":false,"name":"second","markedRegularInodes":"1","wantOnlyRegularInodes":"0","literalRecordPayload":{"blocks":"2","bytes":"8192"},"filePayload":{"blocks":"2","bytes":"8192"},"filePayloadRanges":[{"physicalBlock":"221","blockCount":"2"}]},
          {"viewXid":"20","current":true,"name":"","markedRegularInodes":"1","wantOnlyRegularInodes":"1","literalRecordPayload":{"blocks":"3","bytes":"12288"},"filePayload":{"blocks":"4","bytes":"16384"},"filePayloadRanges":[{"physicalBlock":"220","blockCount":"4"}]}],
         "snapshotAllocationChargeBytes":null,"applePurgeableBytes":null,"reclaimableBytes":null}
        """)!.AsObject();
        root["source"]!["path"] = Request.Image; root["scope"]!["containerUuid"] = new string('a', 32); root["scope"]!["volumeUuid"] = new string('b', 32); return root;
    }
    [Fact] public void SharedSnapshotsAndFullFileUnionAreIndependentOfLiteralRecordsAndOsPolicy()
    {
        var result = NativeApfsImageVerifier.ParseMarkedReferenceSpace(Document().ToJsonString(), 0, Request, "held-identity");
        Assert.True(result.Complete); Assert.Equal("4", result.Report.GetProperty("filePayloadUnion").GetProperty("blocks").GetString());
        Assert.Equal("3", result.Report.GetProperty("literalRecordUnion").GetProperty("blocks").GetString());
        Assert.Equal(3, result.PhysicalViews.Count);
        Assert.Equal(4096UL, result.PhysicalViews[0].SharedWithOtherSnapshotsBytes);
        Assert.Equal(8192UL, result.PhysicalViews[0].SharedWithCurrentBytes);
        Assert.Equal(4096UL, result.PhysicalViews[^1].UniqueInMarkedInventoryBytes);
    }
    [Fact] public void PartialOverlapComputesExactPhysicalPartitionsWithoutReleaseAuthority()
    {
        var doc = Document(); var current = doc["views"]![2]!;
        current["literalRecordPayload"] = JsonNode.Parse("{\"blocks\":\"2\",\"bytes\":\"8192\"}");
        current["filePayload"] = JsonNode.Parse("{\"blocks\":\"2\",\"bytes\":\"8192\"}");
        current["filePayloadRanges"] = JsonNode.Parse("[{\"physicalBlock\":\"222\",\"blockCount\":\"2\"}]");
        var result = NativeApfsImageVerifier.ParseMarkedReferenceSpace(doc.ToJsonString(), 0, Request, "held-identity");
        var first = result.PhysicalViews[0]; var second = result.PhysicalViews[1]; var live = result.PhysicalViews[2];
        Assert.Equal((0UL, 8192UL, 4096UL, 4096UL),
            (first.SharedWithCurrentBytes, first.AbsentFromCurrentBytes, first.SharedWithOtherSnapshotsBytes, first.UniqueInMarkedInventoryBytes));
        Assert.Equal((4096UL, 4096UL, 4096UL, 0UL),
            (second.SharedWithCurrentBytes, second.AbsentFromCurrentBytes, second.SharedWithOtherSnapshotsBytes, second.UniqueInMarkedInventoryBytes));
        Assert.Equal((4096UL, 4096UL), (live.SharedWithOtherSnapshotsBytes, live.UniqueInMarkedInventoryBytes));
        Assert.Equal(System.Text.Json.JsonValueKind.Null, result.Report.GetProperty("reclaimableBytes").ValueKind);
    }
    [Fact] public void ContradictoryUnionScopeRangesFlagsAndPolicyNeverPublish()
    {
        Action<JsonObject>[] faults = [
            r => r["format"] = "apfs-access-snapshot-space-attribution", r => r["version"] = 2,
            r => r["source"]!["identity"] = "wrong", r => r["source"]!["path"] = "D:\\other.apfs",
            r => r["scope"]!["checkpointXid"] = "19", r => r["scope"]!["volumeOid"] = "102",
            r => r["allocationUnitBytes"] = 3000, r => r["hiddenOwnersComplete"] = true,
            r => r["retainedCheckpointHistoryVerified"] = true, r => r["namespaceAndDirectory7ReferencesVerified"] = false,
            r => r["catalogMetadataAndPayloadAllocationVerified"] = false, r => r["applePurgeableBytes"] = "0",
            r => r["reclaimableBytes"] = "16384", r => r["snapshotAllocationChargeBytes"] = "1",
            r => r["filePayloadUnion"]!["blocks"] = "8", r => r["filePayloadUnion"]!["bytes"] = "16385",
            r => r["views"]![0]!["filePayloadRanges"]![0]!["physicalBlock"] = "511",
            r => r["views"]![0]!["filePayloadRanges"]![0]!["blockCount"] = "0",
            r => r["views"]![0]!["filePayloadRanges"]!.AsArray().Add(JsonNode.Parse("{\"physicalBlock\":\"221\",\"blockCount\":\"1\"}")),
            r => r["views"]![0]!["current"] = true, r => r["views"]![1]!["name"] = "first",
            r => r["views"]![0]!["viewXid"] = "018", r => r["views"]![2]!["markedRegularInodes"] = "0",
            r => r["literalRecordUnion"]!["blocks"] = "1", r => r["filePayloadMeaning"] = "guaranteed-purgeable",
            r => r["unexpected"] = true
        ];
        foreach (var fault in faults) { var root = Document(); fault(root); Assert.Throws<InvalidDataException>(() => NativeApfsImageVerifier.ParseMarkedReferenceSpace(root.ToJsonString(), 0, Request, "held-identity")); }
        Assert.Throws<InvalidDataException>(() => NativeApfsImageVerifier.ParseMarkedReferenceSpace(Document().ToJsonString(), 3, Request, "held-identity"));
    }
    [Fact] public void EmptySnapshotViewsCannotBypassTheArithmeticWorkBound()
    {
        var doc = Document(); var views = new JsonArray();
        for (var i = 1; i <= 2049; ++i)
        {
            var row = doc["views"]![0]!.DeepClone();
            row["viewXid"] = i.ToString(System.Globalization.CultureInfo.InvariantCulture);
            row["current"] = i == 2049; row["name"] = i == 2049 ? "" : "empty-" + i;
            row["markedRegularInodes"] = "0"; row["wantOnlyRegularInodes"] = "0";
            row["literalRecordPayload"] = JsonNode.Parse("{\"blocks\":\"0\",\"bytes\":\"0\"}");
            row["filePayload"] = JsonNode.Parse("{\"blocks\":\"0\",\"bytes\":\"0\"}");
            row["filePayloadRanges"] = new JsonArray(); views.Add(row);
        }
        doc["views"] = views; doc["scope"]!["checkpointXid"] = "2049";
        doc["literalRecordUnion"] = JsonNode.Parse("{\"blocks\":\"0\",\"bytes\":\"0\"}");
        doc["filePayloadUnion"] = JsonNode.Parse("{\"blocks\":\"0\",\"bytes\":\"0\"}");
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        Assert.Throws<InvalidDataException>(() => NativeApfsImageVerifier.ParseMarkedReferenceSpace(doc.ToJsonString(), 0,
            Request with { CheckpointXid = "2049" }, "held-identity", stop.Token));
    }
    [Fact] public void RefusedDocumentIsSeparateAndCancellationIsPreserved()
    {
        var root = Document(); var failure = new JsonObject { ["format"] = root["format"]!.DeepClone(), ["version"] = 1,
            ["readOnly"] = true, ["complete"] = false, ["source"] = root["source"]!.DeepClone(), ["scope"] = root["scope"]!.DeepClone(), ["reason"] = "unsupported-history" };
        Assert.False(NativeApfsImageVerifier.ParseMarkedReferenceSpace(failure.ToJsonString(), 3, Request, "held-identity").Complete);
        failure["filePayloadUnion"] = root["filePayloadUnion"]!.DeepClone();
        Assert.Throws<InvalidDataException>(() => NativeApfsImageVerifier.ParseMarkedReferenceSpace(failure.ToJsonString(), 3, Request, "held-identity"));
        using var stop = new CancellationTokenSource(); stop.Cancel();
        Assert.Throws<OperationCanceledException>(() => NativeApfsImageVerifier.ParseMarkedReferenceSpace(root.ToJsonString(), 0, Request, "held-identity", stop.Token));
    }
}
