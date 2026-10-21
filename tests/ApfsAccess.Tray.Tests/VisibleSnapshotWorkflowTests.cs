using System.Text.Json;
using System.Text.Json.Nodes;
using ApfsAccess.Backend.Native;
using ApfsAccess.Cli;

namespace ApfsAccess.Tray.Tests;

public sealed class VisibleSnapshotWorkflowTests : IDisposable
{
    private readonly string folder=Path.Combine(Path.GetTempPath(),"visible-gui-"+Guid.NewGuid().ToString("N"));
    public VisibleSnapshotWorkflowTests(){Directory.CreateDirectory(folder);foreach(var name in new[]{"main","tier"})File.WriteAllBytes(Path.Combine(folder,name),new byte[131072]);}
    public void Dispose()=>Directory.Delete(folder,true);
    private ApfsCurrentProfileVerificationRequest Request()=>NativeApfsImageVerifier.CaptureCurrentProfileBindings(new("fusion-clean-cache",Path.Combine(folder,"main"),
        "apfs-container:"+new string('a',32),new string('b',32),"101","7","0","131072",Path.Combine(folder,"tier"),"0","32768",new string('c',32),"linux-apfs-last-byte-low-bit"));
    private static ApfsVisibleSnapshotProfileResult Report(ApfsVisibleSnapshotProfileRequest request)
    {
        var r=ProfileVerificationTests.Report(request.Endpoint);r["format"]="apfs-access-visible-snapshot-profile-verification";r.Remove("counts");r["fromXid"]=request.FromXid;
        r["visibleSnapshotNamespacesVerified"]=true;r["counterMeaning"]="parsed-apfs-fs-alloc-count-at-descriptor-xid";r["independentSnapshotChargeVerified"]=false;
        object Amount(int n)=>new{blocks=n.ToString(),bytes=(n*4096).ToString()};
        object[] R(int start,int count)=>[new{physicalBlock=start.ToString(),blockCount=count.ToString()}];
        var desc=new{objectId="101",xid="7",physicalBlock="2"};
        var parent=new{checkpointXid="7",metadataRanges=R(1,3),payloadRanges=R(10,1),views=new[]{new{volumeOid="101",viewXid="7",current=true,name="",descriptor=desc,
            declaredFilesystemAllocation=Amount(5),filesystemRecordCount="2",metadataRanges=R(2,2),payloadRanges=R(10,1)}}};
        var parents=new JsonArray();if(request.FromXid is not null){var old=JsonSerializer.SerializeToNode(parent)!;old["checkpointXid"]=request.FromXid;old["views"]![0]!["viewXid"]=request.FromXid;old["views"]![0]!["descriptor"]!["xid"]=request.FromXid;parents.Add(old);}
        parents.Add(JsonSerializer.SerializeToNode(parent));
        r["graph"]=new JsonObject{["allocationUnitBytes"]=4096,["snapshotOwnerScope"]="canonical-visible-inventories-and-explicit-parents",["chainXids"]=new JsonArray(parents.Select(x=>x!["checkpointXid"]!.DeepClone()).ToArray()),["checkpoints"]=parents};
        r["attribution"]=JsonSerializer.SerializeToNode(new{protectionScope="explicit-checkpoint-chain-and-visible-peers",hiddenOwnersComplete=false,liveMetadata=Amount(2),livePayload=Amount(1),referencedSnapshotMetadata=Amount(0),referencedSnapshotPayload=Amount(0),snapshots=Array.Empty<object>()});
        r["coverage"]=JsonSerializer.SerializeToNode(new[]{new{check=20,implemented=true,required=true,state=2,scopeDetail="Visible snapshots and explicit parents"}});
        return new(0,ApfsVerificationOutcome.Complete,JsonSerializer.SerializeToElement(r));
    }
    private static ProfileVerificationClient Client(Func<ApfsVisibleSnapshotProfileRequest,SupervisedCredential?,CancellationToken,Task<ApfsVisibleSnapshotProfileResult>> run,bool available=true)=>
        new(available,(_,_,_)=>throw new InvalidOperationException("Wrong current route"),snapshotVerify:run);
    [Fact] public async Task NewWorkflowHoldsBothMembersAcrossAwaitAndLabelsUnknownPolicies()
    {
        var r=Request();var checks=0;
        var client=Client(async(q,c,t)=>{Assert.Null(c);Assert.Equal("5",q.FromXid);await Task.Delay(1,t);
            foreach(var path in new[]{q.Endpoint.Image,q.Endpoint.Tier2Image!})Assert.Throws<IOException>(()=>File.OpenHandle(path,FileMode.Open,FileAccess.Write,FileShare.ReadWrite));return Report(q);});
        var display=await client.RunVisibleSnapshotsAsync(new(r),"5",null,()=>++checks,default);
        Assert.Equal(2,checks);Assert.Contains("5, 7",display.Scope);Assert.Contains(r.ExpectedTier2Identity!,display.Scope);
        Assert.Contains("Hidden owners: Not verified",display.Scope);Assert.Contains("Apple purgeable: Unknown",display.Policy);
    }
    [Fact] public async Task StaleBeforeAfterCancellationWrongIdentityAndUnavailableCannotPublish()
    {
        var r=Request();var ran=0;var calls=0;var client=Client((q,c,t)=>{++ran;return Task.FromResult(Report(q));});
        await Assert.ThrowsAsync<InvalidOperationException>(()=>client.RunVisibleSnapshotsAsync(new(r),null,null,()=>throw new InvalidOperationException("stale"),default));Assert.Equal(0,ran);
        await Assert.ThrowsAsync<InvalidOperationException>(()=>client.RunVisibleSnapshotsAsync(new(r),null,null,()=>{if(++calls==2)throw new InvalidOperationException("stale after await");},default));Assert.Equal(1,ran);
        await Assert.ThrowsAsync<InvalidDataException>(()=>client.RunVisibleSnapshotsAsync(new(r with{ExpectedTier2Identity="stale"}),null,null,()=>{},default));Assert.Equal(1,ran);
        using var stop=new CancellationTokenSource();stop.Cancel();await Assert.ThrowsAsync<OperationCanceledException>(()=>client.RunVisibleSnapshotsAsync(new(r),null,null,()=>{},stop.Token));Assert.Equal(1,ran);
        await Assert.ThrowsAsync<FileNotFoundException>(()=>Client((q,c,t)=>throw new InvalidOperationException(),false).RunVisibleSnapshotsAsync(new(r),null,null,()=>{},default));
        var encrypted=r with{Profile="encrypted-onekey-generation-zero",Tier2Image=null,Tier2OffsetBytes=null,Tier2SizeBytes=null,FusionUuid=null,FusionRoleConvention=null,ExpectedTier2Identity=null};
        await Assert.ThrowsAsync<ArgumentException>(()=>client.RunVisibleSnapshotsAsync(new(encrypted),null,null,()=>{},default));Assert.Equal(1,ran);
    }
    [Fact] public async Task SharedDecoderRejectsForeignScopeAndFabricatedPolicyFromClient()
    {
        var r=Request();foreach(var field in new[]{"applePurgeableBytes","reclaimableBytes","snapshotAllocationChargeBytes"}){
            var client=Client((q,c,t)=>{var a=JsonNode.Parse(Report(q).Report.GetRawText())!;a[field]="0";return Task.FromResult(new ApfsVisibleSnapshotProfileResult(0,ApfsVerificationOutcome.Complete,JsonSerializer.SerializeToElement(a)));});
            await Assert.ThrowsAsync<InvalidDataException>(()=>client.RunVisibleSnapshotsAsync(new(r),null,null,()=>{},default));
        }
    }
}
