using System.Text.Json;
using System.Text.Json.Nodes;
using ApfsAccess.Backend.Native;

namespace ApfsAccess.Backend.Native.Tests;

public sealed class MarkedOwnerSpaceTests
{
    private static readonly ApfsMarkedOwnerSpaceRequest Request = new(new("D:\\marked.apfs", "apfs-container:" + new string('a',32),
        new string('b',32), "101", "20", "0", "2097152"), "18");
    private static JsonNode Amount(ulong blocks) => JsonSerializer.SerializeToNode(new { blocks = blocks.ToString(), bytes = (blocks*4096).ToString() })!;
    private static JsonNode Ranges(ulong start, ulong count) => JsonSerializer.SerializeToNode(new[] {new {physicalBlock=start.ToString(),blockCount=count.ToString()}})!;
    private static JsonNode Measures(ulong count, ulong shared, ulong other, ulong unique, ulong external, ulong upper) => new JsonObject {
        ["referenced"]=Amount(count),["sharedWithLive"]=Amount(shared),["absentFromLive"]=Amount(count-shared),
        ["sharedWithOtherSnapshots"]=Amount(other),["uniqueInVisibleInventory"]=Amount(unique),
        ["retainedOrPeerProtected"]=Amount(external),["potentialReclaimUpperBound"]=Amount(upper)};
    internal static JsonObject Document()
    {
        var rows = new JsonArray();
        for (var i=0;i<3;++i) rows.Add(new JsonObject {
            ["metadataRanges"]=Ranges((ulong)(10+i*2),1),["payloadRanges"]=Ranges((ulong)(i==2?220:220+i),(ulong)(i==2?4:2)),
            ["unmarkedPayloadRanges"]=i==2?Ranges(220,3):new JsonArray(),
            ["metadata"]=Measures(1,0,0,1,i==0?1UL:0UL,i==0?0UL:1UL),
            ["markedPayload"]=i==2?Measures(4,3,3,1,1,1):Measures(2,2,1,0,i==0?1UL:0UL,0),
            ["sharedWithUnmarkedInView"]=Amount(i==2?3UL:0UL)});
        return new() { ["format"]="apfs-access-marked-owner-space-attribution",["version"]=1,["readOnly"]=true,["complete"]=true,
            ["fromXid"]="18",["checkpointXids"]=new JsonArray("18","19","20"),
            ["protectionScope"]="explicit-retained-checkpoints-and-visible-peers",["hiddenOwnersComplete"]=false,
            ["marked"]=MarkedReferenceSpaceTests.Document(),["visibleMetadataUnion"]=Amount(3),["visiblePayloadUnion"]=Amount(4),
            ["catalogMetadata"]=Amount(3),["catalogMetadataRanges"]=JsonNode.Parse("[{\"physicalBlock\":\"10\",\"blockCount\":\"1\"},{\"physicalBlock\":\"12\",\"blockCount\":\"1\"},{\"physicalBlock\":\"14\",\"blockCount\":\"1\"}]"),
            ["protectedMetadataRanges"]=Ranges(10,1),["protectedPayloadRanges"]=Ranges(220,1),["views"]=rows,
            ["snapshotAllocationChargeBytes"]=null,["applePurgeableBytes"]=null,["reclaimableBytes"]=null };
    }
    [Fact] public void AllVisibleCloneAndRetainedOverlapsHaveExactIndependentPartitions()
    {
        var result=NativeApfsImageVerifier.ParseMarkedOwnerSpace(Document().ToJsonString(),0,Request,"held-identity");
        Assert.True(result.Complete);
        var current=result.Report.GetProperty("views")[2];
        Assert.Equal("12288",current.GetProperty("sharedWithUnmarkedInView").GetProperty("bytes").GetString());
        Assert.Equal("4096",current.GetProperty("markedPayload").GetProperty("potentialReclaimUpperBound").GetProperty("bytes").GetString());
        Assert.Equal(JsonValueKind.Null,result.Report.GetProperty("reclaimableBytes").ValueKind);
    }
    [Fact] public void ContradictoryAmountsOmittedOwnersProtectedAliasesAndStaleBindingRefuse()
    {
        Action<JsonObject>[] faults=[
            r=>r["fromXid"]="17",r=>r["checkpointXids"]![0]="17",r=>r["hiddenOwnersComplete"]=true,
            r=>r["views"]![2]!["unmarkedPayloadRanges"]=new JsonArray(),
            r=>r["views"]![2]!["markedPayload"]!["potentialReclaimUpperBound"]=Amount(4),
            r=>r["views"]![0]!["markedPayload"]!["retainedOrPeerProtected"]=Amount(2),
            r=>r["visiblePayloadUnion"]=Amount(5),r=>r["protectedMetadataRanges"]=Ranges(220,1),
            r=>r["protectedPayloadRanges"]=Ranges(10,1),r=>r["marked"]!["scope"]!["checkpointXid"]="21",
            r=>r["applePurgeableBytes"]="0",r=>r["views"]![0]!["payloadRanges"]=new JsonArray(),
            r=>r["views"]![2]!["sharedWithUnmarkedInView"]=Amount(0),
            r=>r["views"]![1]!["metadata"]!["sharedWithOtherSnapshots"]=Amount(1),
            r=>r["catalogMetadata"]=Amount(4),r=>r["catalogMetadataRanges"]=new JsonArray()];
        foreach(var fault in faults){var doc=Document();fault(doc);Assert.Throws<InvalidDataException>(()=>
            NativeApfsImageVerifier.ParseMarkedOwnerSpace(doc.ToJsonString(),0,Request,"held-identity"));}
        Assert.Throws<InvalidDataException>(()=>NativeApfsImageVerifier.ParseMarkedOwnerSpace(Document().ToJsonString(),0,Request,"wrong-source"));
        var aliased=Document();aliased["protectedMetadataRanges"]=Ranges(230,1);aliased["protectedPayloadRanges"]=Ranges(230,1);
        Assert.Throws<InvalidDataException>(()=>NativeApfsImageVerifier.ParseMarkedOwnerSpace(aliased.ToJsonString(),0,Request,"held-identity"));
    }
    [Fact] public void FailureHasNoCompleteAccountingAndCancellationIsSticky()
    {
        var doc=Document(); var marked=doc["marked"]!;
        var refusal=new JsonObject{["format"]=doc["format"]!.DeepClone(),["version"]=1,["readOnly"]=true,["complete"]=false,
            ["fromXid"]="18",["source"]=marked["source"]!.DeepClone(),["scope"]=marked["scope"]!.DeepClone(),["reason"]="Missing retained parent"};
        Assert.False(NativeApfsImageVerifier.ParseMarkedOwnerSpace(refusal.ToJsonString(),3,Request,"held-identity").Complete);
        refusal["views"]=new JsonArray();Assert.Throws<InvalidDataException>(()=>NativeApfsImageVerifier.ParseMarkedOwnerSpace(refusal.ToJsonString(),3,Request,"held-identity"));
        using var stop=new CancellationTokenSource();stop.Cancel();
        Assert.ThrowsAny<OperationCanceledException>(()=>NativeApfsImageVerifier.ParseMarkedOwnerSpace(doc.ToJsonString(),0,Request,"held-identity",stop.Token));
    }
}
