using System.Text.Json;
using System.Text.Json.Nodes;

namespace ApfsAccess.Backend.Native.Tests;

public sealed class RetainedProfileVerificationTests : IDisposable
{
    private const string MainId="windows-file:1:2:131072:3",TierId="windows-file:1:4:32768:3";
    private readonly string folder=Path.Combine(Path.GetTempPath(),"retained-profile-"+Guid.NewGuid().ToString("N"));
    public RetainedProfileVerificationTests(){Directory.CreateDirectory(folder);File.WriteAllBytes(Path.Combine(folder,"main.apfs"),new byte[155648]);File.WriteAllBytes(Path.Combine(folder,"tier.apfs"),new byte[36864]);}
    public void Dispose()=>Directory.Delete(folder,true);
    private ApfsRetainedProfileVerificationRequest Request(bool fusion=true)=>new(new(
        fusion?"fusion-clean-cache":"encrypted-onekey-generation-zero",Path.Combine(folder,"main.apfs"),"apfs-container:"+new string('a',32),
        new string('b',32),"101","7",fusion?"8192":"20480","131072",fusion?Path.Combine(folder,"tier.apfs"):null,
        fusion?"4096":null,fusion?"32768":null,fusion?new string('c',32):null,fusion?"linux-apfs-last-byte-low-bit":null),"5");
    private JsonObject Report(bool fusion=true)
    {
        var q=Request(fusion).Endpoint;var identity=fusion?MainId+":fusion:"+q.FusionUuid+":"+TierId:MainId+":scope:20480:131072";
        var stores=new JsonArray(JsonSerializer.SerializeToNode(new{role=fusion?"main":"container",id=fusion?MainId:identity,label=q.Image,offsetBytes=fusion?"8192":"0",sizeBytes="131072"}));
        if(fusion)stores.Add(JsonSerializer.SerializeToNode(new{role="tier2",id=TierId,label=q.Tier2Image,offsetBytes="4096",sizeBytes="32768"}));
        return JsonSerializer.SerializeToNode(new{
            format="apfs-access-retained-profile-verification",version=1,readOnly=true,profile=q.Profile,
            source=new{identity,coordinateSystem=fusion?"member-image-relative":"container-relative",stores},
            requestedScope=new{containerUuid=new string('a',32),volumeUuid=new string('b',32),volumeOid="101",checkpointXid="7",
                storeOffsetBytes=fusion?"8192":"0",storeSizeBytes="131072",maxReads="65536",maxReadBytes="268435456",maxRecords="1000000",maxRecordBytes="268435456",
                requireWholeVolume=false,requirePayloadContentHashes=false,observePayloadContent=false,accountRetainedOwnership=false,retainedFromXid=(string?)null},
            fromXid="5",selected=new{containerUuid=new string('a',32),volumeUuid=new string('b',32),volumeOid="101",checkpointXid="7",
                storeOffsetBytes=fusion?"8192":"0",storeSizeBytes="131072",checkpointPhysicalBlock="1",volumeSuperblockPhysicalBlock="2",volumeSuperblockXid="7",rootOid="1001",rootPhysicalBlock="3"},
            outcome=1,outcomeName="Complete",wholeVolumeVerified=false,retainedOwnershipComplete=false,payloadContentHashesVerified=false,
            historicalNamespaceVerified=true,sourceReads="3",sourceReadBytes="12288",
            history=new{allocationUnitBytes=4096,snapshotOwnerScope="canonical-empty-inventories-only",chainXids=new[]{"5","6","7"},
                checkpoints=new[]{"5","6","7"}.Select(x=>new{checkpointXid=x,metadataRanges=new[]{new{physicalBlock="2",blockCount="2"},new{physicalBlock="5",blockCount="1"}},
                    payloadRanges=new[]{new{physicalBlock="10",blockCount="2"}}})},
            snapshotAllocationChargeBytes=(string?)null,applePurgeableBytes=(string?)null,reclaimableBytes=(string?)null,findings=Array.Empty<object>(),
            coverage=new[]{new{check=22,implemented=true,required=true,state=2,scopeDetail="Finite canonical chain and empty inventories only"}}
        })!.AsObject();
    }
    private ApfsRetainedProfileVerificationResult Parse(JsonObject value,bool fusion=true,int exit=0,CancellationToken token=default)=>
        NativeApfsImageVerifier.ValidateRetainedProfileReport(value.ToJsonString(),exit,Request(fusion),MainId,fusion?TierId:null,token);

    [Fact] public void BothProfilesRequireExplicitChainAndKeepPolicyUnknown()
    {
        foreach(var fusion in new[]{false,true}){
            var result=Parse(Report(fusion),fusion);Assert.Equal(ApfsVerificationOutcome.Complete,result.Outcome);
            Assert.Equal(3,result.Report.GetProperty("history").GetProperty("checkpoints").GetArrayLength());
            Assert.Equal(JsonValueKind.Null,result.Report.GetProperty("snapshotAllocationChargeBytes").ValueKind);
        }
        foreach(var from in new[]{"0","05","7","8"})Assert.Throws<ArgumentException>(()=>NativeApfsImageVerifier.ValidateRetainedProfileRequest(Request() with{FromXid=from}));
        Assert.Throws<ArgumentException>(()=>NativeApfsImageVerifier.ValidateRetainedProfileRequest(Request() with{Endpoint=Request().Endpoint with{RetainedFromXid="5"}}));
    }
    [Fact] public void ContradictorySourceScopeHistoryAndPhysicalPartitionsAreRejected()
    {
        Action<JsonObject>[] faults=[r=>r["version"]=2,r=>r["source"]!["identity"]="foreign",r=>r["source"]!["stores"]![1]!["id"]=MainId,
            r=>r["source"]!["stores"]![1]!["offsetBytes"]="0",r=>r["fromXid"]="4",r=>r["requestedScope"]!["checkpointXid"]="6",
            r=>r["selected"]!["rootPhysicalBlock"]="100",r=>r["historicalNamespaceVerified"]=null,r=>r["history"]!["chainXids"]![1]="5",
            r=>r["history"]!["checkpoints"]![0]!["checkpointXid"]="6",r=>r["history"]!["checkpoints"]!.AsArray().RemoveAt(0),
            r=>r["history"]!["checkpoints"]![0]!["payloadRanges"]![0]!["physicalBlock"]="100",
            r=>r["history"]!["checkpoints"]![0]!["payloadRanges"]![0]!["blockCount"]="40",
            r=>r["history"]!["checkpoints"]![2]!["payloadRanges"]![0]!["physicalBlock"]="2",
            r=>r["history"]!["checkpoints"]![0]!["metadataRanges"]![1]!["physicalBlock"]="4",
            r=>r["history"]!["snapshotOwnerScope"]="whole-volume",r=>r["applePurgeableBytes"]="0",r=>r["snapshotAllocationChargeBytes"]="1",
            r=>r["reclaimableBytes"]="4096",r=>r["retainedOwnershipComplete"]=true,r=>r["wholeVolumeVerified"]=true,
            r=>r["coverage"]![0]!["state"]=4,r=>r["coverage"]![0]!["required"]=false];
        foreach(var fault in faults){var r=Report();fault(r);Assert.Throws<InvalidDataException>(()=>Parse(r));}
        var tier=Report();tier["history"]!["checkpoints"]![0]!["payloadRanges"]![0]!["physicalBlock"]=(0x4000000000000000UL/4096+6).ToString();
        Assert.Equal(ApfsVerificationOutcome.Complete,Parse(tier).Outcome);
        tier["history"]!["checkpoints"]![0]!["payloadRanges"]![0]!["blockCount"]="3";Assert.Throws<InvalidDataException>(()=>Parse(tier));
    }
    [Fact] public void IncompleteAndRefusedCannotPublishPartialProof()
    {
        foreach(var refused in new[]{false,true}){
            var r=Report();r["outcome"]=refused?3:2;r["outcomeName"]=refused?"Refused":"Incomplete";r["selected"]=null;r["history"]=null;r["historicalNamespaceVerified"]=null;
            r["coverage"]![0]!["state"]=refused?4:3;
            r["findings"]!.AsArray().Add(JsonSerializer.SerializeToNode(new{code=refused?8:6,severity=refused?2:3,check=22,volumeOid="101",objectId=(string?)null,
                physicalBlock=(string?)null,checkpointXid="5",failedSourceOffsetBytes=(string?)null,detail="Typed history failure"}));
            var exit=refused?4:3;Assert.Equal(refused?ApfsVerificationOutcome.Refused:ApfsVerificationOutcome.Incomplete,Parse(r,exit:exit).Outcome);
            foreach(var field in new[]{"selected","history","historicalNamespaceVerified"}){
                var bad=r.DeepClone().AsObject();bad[field]=Report()[field]!.DeepClone();Assert.Throws<InvalidDataException>(()=>Parse(bad,exit:exit));}
            Assert.Throws<InvalidDataException>(()=>Parse(r,exit:0));
        }
    }
    [Fact] public void DuplicateFieldsCancellationAndReadBudgetContradictionsFail()
    {
        var r=Report();var text=r.ToJsonString().Replace("\"version\":1","\"version\":1,\"version\":1",StringComparison.Ordinal);
        Assert.Throws<InvalidDataException>(()=>NativeApfsImageVerifier.ValidateRetainedProfileReport(text,0,Request(),MainId,TierId));
        using var stop=new CancellationTokenSource();stop.Cancel();Assert.Throws<OperationCanceledException>(()=>Parse(r,token:stop.Token));
        r["sourceReadBytes"]="268435457";Assert.Throws<InvalidDataException>(()=>Parse(r));
    }
}
