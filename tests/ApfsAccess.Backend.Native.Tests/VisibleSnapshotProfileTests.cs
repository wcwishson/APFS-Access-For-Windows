using System.Text.Json;
using System.Text.Json.Nodes;

namespace ApfsAccess.Backend.Native.Tests;

public sealed class VisibleSnapshotProfileTests : IDisposable
{
    private const string MainId="windows-file:1:2:139264:3",TierId="windows-file:1:4:36864:3";
    private readonly string folder=Path.Combine(Path.GetTempPath(),"visible-profile-"+Guid.NewGuid().ToString("N"));
    public VisibleSnapshotProfileTests(){Directory.CreateDirectory(folder);File.WriteAllBytes(Path.Combine(folder,"main.apfs"),new byte[139264]);File.WriteAllBytes(Path.Combine(folder,"tier.apfs"),new byte[36864]);}
    public void Dispose()=>Directory.Delete(folder,true);
    private ApfsVisibleSnapshotProfileRequest Request()=>new(new("fusion-clean-cache",Path.Combine(folder,"main.apfs"),"apfs-container:"+new string('a',32),
        new string('b',32),"101","7","8192","131072",Path.Combine(folder,"tier.apfs"),"4096","32768",new string('c',32),"linux-apfs-last-byte-low-bit"),"4");
    private static object[] R(params (int Start,int Count)[] ranges)=>ranges.Select(x=>(object)new{physicalBlock=x.Start.ToString(),blockCount=x.Count.ToString()}).ToArray();
    private static object A(int blocks)=>new{blocks=blocks.ToString(),bytes=(blocks*4096).ToString()};
    private static object D(int block,int xid)=>new{objectId=(block==2?101:block==8?102:block).ToString(),xid=xid.ToString(),physicalBlock=block.ToString()};
    private static object V(int volume,int xid,bool current,string name,int block,object[] metadata,object[] payload)=>new{
        volumeOid=volume.ToString(),viewXid=xid.ToString(),current,name,descriptor=D(block,xid),declaredFilesystemAllocation=A(17),filesystemRecordCount="1",metadataRanges=metadata,payloadRanges=payload};
    private static object M(int refs,int shared,int other,int unique,int protectedCount,int upper)=>new{
        referenced=A(refs),sharedWithLive=A(shared),absentFromLive=A(refs-shared),sharedWithOtherSnapshots=A(other),uniqueInVisibleInventory=A(unique),retainedOrPeerProtected=A(protectedCount),potentialReclaimUpperBound=A(upper)};
    private JsonObject Report()
    {
        var q=Request().Endpoint;
        return JsonSerializer.SerializeToNode(new{
            format="apfs-access-visible-snapshot-profile-verification",version=1,readOnly=true,profile=q.Profile,
            source=new{identity=MainId+":fusion:"+q.FusionUuid+":"+TierId,coordinateSystem="member-image-relative",stores=new[]{
                new{role="main",id=MainId,label=q.Image,offsetBytes="8192",sizeBytes="131072"},new{role="tier2",id=TierId,label=q.Tier2Image,offsetBytes="4096",sizeBytes="32768"}}},
            requestedScope=new{containerUuid=new string('a',32),volumeUuid=new string('b',32),volumeOid="101",checkpointXid="7",storeOffsetBytes="8192",storeSizeBytes="131072",
                maxReads="65536",maxReadBytes="268435456",maxRecords="1000000",maxRecordBytes="268435456",requireWholeVolume=false,requirePayloadContentHashes=false,observePayloadContent=false,accountRetainedOwnership=false,retainedFromXid=(string?)null},
            fromXid="4",selected=new{containerUuid=new string('a',32),volumeUuid=new string('b',32),volumeOid="101",checkpointXid="7",storeOffsetBytes="8192",storeSizeBytes="131072",
                checkpointPhysicalBlock="1",volumeSuperblockPhysicalBlock="2",volumeSuperblockXid="7",rootOid="1001",rootPhysicalBlock="4"},
            outcome=1,outcomeName="Complete",wholeVolumeVerified=false,retainedOwnershipComplete=false,payloadContentHashesVerified=false,visibleSnapshotNamespacesVerified=true,sourceReads="3",sourceReadBytes="12288",
            graph=new{allocationUnitBytes=4096,snapshotOwnerScope="canonical-visible-inventories-and-explicit-parents",chainXids=new[]{"4","7"},checkpoints=new object[]{
                new{checkpointXid="4",metadataRanges=R((2,2)),payloadRanges=R((20,1)),views=new[]{V(101,4,true,"",2,R((2,2)),R((20,1)))}},
                new{checkpointXid="7",metadataRanges=R((1,6),(8,1)),payloadRanges=R((20,6),(28,1)),views=new[]{
                    V(101,5,false,"older",5,R((3,1),(5,1)),R((20,4))),V(101,6,false,"newer",6,R((3,1),(6,1)),R((22,3))),
                    V(101,7,true,"",2,R((2,3)),R((23,3))),V(102,7,true,"",8,R((8,1)),R((28,1)))}}}},
            attribution=new{protectionScope="explicit-checkpoint-chain-and-visible-peers",hiddenOwnersComplete=false,liveMetadata=A(3),livePayload=A(3),referencedSnapshotMetadata=A(3),referencedSnapshotPayload=A(5),
                snapshots=new[]{new{snapshotXid="5",name="older",descriptor=D(5,5),declaredFilesystemAllocation=A(17),metadata=M(2,1,1,1,1,1),payload=M(4,1,2,2,1,1)},
                    new{snapshotXid="6",name="newer",descriptor=D(6,6),declaredFilesystemAllocation=A(17),metadata=M(2,1,1,1,1,1),payload=M(3,2,2,0,0,0)}}},
            counterMeaning="parsed-apfs-fs-alloc-count-at-descriptor-xid",independentSnapshotChargeVerified=false,snapshotAllocationChargeBytes=(string?)null,applePurgeableBytes=(string?)null,reclaimableBytes=(string?)null,
            findings=Array.Empty<object>(),coverage=new[]{new{check=20,implemented=true,required=true,state=2,scopeDetail="Canonical visible snapshots and explicit parents"}}
        })!.AsObject();
    }
    private ApfsVisibleSnapshotProfileResult Parse(JsonObject r,int exit=0,CancellationToken token=default)=>
        NativeApfsImageVerifier.ValidateVisibleSnapshotProfileReport(r.ToJsonString(),exit,Request(),MainId,TierId,token);
    [Fact] public void LiteralOverlappingInventorySubtractsLiveOtherSnapshotsAndRetainedParents()
    {
        var result=Parse(Report());Assert.Equal(ApfsVerificationOutcome.Complete,result.Outcome);
        var a=result.Report.GetProperty("attribution");Assert.Equal("5",a.GetProperty("referencedSnapshotPayload").GetProperty("blocks").GetString());
        Assert.Equal("1",a.GetProperty("snapshots")[0].GetProperty("payload").GetProperty("potentialReclaimUpperBound").GetProperty("blocks").GetString());
        Assert.Equal(JsonValueKind.Null,result.Report.GetProperty("applePurgeableBytes").ValueKind);
    }
    [Fact] public void ContradictoryPartitionsCountersIdentitiesAndPhysicalClaimsAreRejected()
    {
        Action<JsonObject>[] faults=[r=>r["source"]!["identity"]="stale",r=>r["source"]!["stores"]![1]!["id"]=MainId,
            r=>r["source"]!["stores"]![1]!["offsetBytes"]="0",r=>r["fromXid"]="3",r=>r["selected"]!["checkpointXid"]="6",r=>r["selected"]!["volumeSuperblockPhysicalBlock"]="8",r=>r["selected"]!["rootPhysicalBlock"]="6",
            r=>r["graph"]!["chainXids"]![0]="5",r=>r["graph"]!["checkpoints"]![1]!["views"]![0]!["viewXid"]="8",
            r=>r["graph"]!["checkpoints"]![1]!["views"]![1]!["name"]="older",r=>r["graph"]!["checkpoints"]![1]!["views"]![2]!["current"]=false,
            r=>r["graph"]!["checkpoints"]![1]!["metadataRanges"]![0]!["blockCount"]="31",
            r=>r["graph"]!["checkpoints"]![1]!["payloadRanges"]![0]!["physicalBlock"]="100",
            r=>r["graph"]!["checkpoints"]![1]!["views"]![3]!["payloadRanges"]![0]!["physicalBlock"]="20",
            r=>r["attribution"]!["snapshots"]![0]!["payload"]!["potentialReclaimUpperBound"]!["blocks"]="2",
            r=>r["attribution"]!["snapshots"]![0]!["payload"]!["potentialReclaimUpperBound"]!["bytes"]="0",
            r=>r["attribution"]!["snapshots"]![0]!["payload"]!["sharedWithLive"]=JsonSerializer.SerializeToNode(A(2)),
            r=>r["attribution"]!["referencedSnapshotPayload"]=JsonSerializer.SerializeToNode(A(7)),
            r=>r["attribution"]!["snapshots"]![0]!["declaredFilesystemAllocation"]=JsonSerializer.SerializeToNode(A(16)),
            r=>r["attribution"]!["hiddenOwnersComplete"]=true,r=>r["independentSnapshotChargeVerified"]=true,r=>r["snapshotAllocationChargeBytes"]="4096",
            r=>r["applePurgeableBytes"]="0",r=>r["reclaimableBytes"]="4096",r=>r["sourceReadBytes"]="268435457"];
        foreach(var fault in faults){var r=Report();fault(r);Assert.Throws<InvalidDataException>(()=>Parse(r));}
    }
    [Fact] public void IncompleteRefusedAndCancelledNeverPublishCompleteAttribution()
    {
        foreach(var refused in new[]{false,true}){
            var r=Report();r["outcome"]=refused?3:2;r["outcomeName"]=refused?"Refused":"Incomplete";
            r["selected"]=null;r["graph"]=null;r["attribution"]=null;r["visibleSnapshotNamespacesVerified"]=null;r["coverage"]![0]!["state"]=refused?4:3;
            r["findings"]!.AsArray().Add(JsonSerializer.SerializeToNode(new{code=refused?8:6,severity=refused?2:3,check=20,volumeOid="101",objectId=(string?)null,physicalBlock=(string?)null,
                checkpointXid="4",failedSourceOffsetBytes=(string?)null,detail="Typed bounded failure"}));
            var exit=refused?4:3;Assert.Equal(refused?ApfsVerificationOutcome.Refused:ApfsVerificationOutcome.Incomplete,Parse(r,exit).Outcome);
            foreach(var field in new[]{"selected","graph","attribution","visibleSnapshotNamespacesVerified"}){
                var bad=r.DeepClone().AsObject();bad[field]=Report()[field]!.DeepClone();Assert.Throws<InvalidDataException>(()=>Parse(bad,exit));}
        }
        using var stop=new CancellationTokenSource();stop.Cancel();Assert.Throws<OperationCanceledException>(()=>Parse(Report(),token:stop.Token));
        var duplicate=Report().ToJsonString().Replace("\"version\":1","\"version\":1,\"version\":1",StringComparison.Ordinal);
        Assert.Throws<InvalidDataException>(()=>NativeApfsImageVerifier.ValidateVisibleSnapshotProfileReport(duplicate,0,Request(),MainId,TierId));
    }
}
