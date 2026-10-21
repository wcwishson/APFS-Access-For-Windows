using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using ApfsAccess.Backend.Native;
using ApfsAccess.Cli;
using ApfsAccess.Core;
using ApfsAccess.Ipc;

namespace ApfsAccess.Tray.Tests;

public sealed class ProfileVerificationTests : IDisposable
{
    private readonly string folder=Path.Combine(Path.GetTempPath(),"profile-gui-"+Guid.NewGuid().ToString("N"));
    private ApfsCurrentProfileVerificationRequest Request(bool fusion=true)
    {
        Directory.CreateDirectory(folder);var main=Path.Combine(folder,"main.apfs");var tier=Path.Combine(folder,"tier.apfs");
        if(!File.Exists(main))File.WriteAllBytes(main,new byte[131072]);if(!File.Exists(tier))File.WriteAllBytes(tier,new byte[32768]);
        return NativeApfsImageVerifier.CaptureCurrentProfileBindings(new(fusion?"fusion-clean-cache":"encrypted-onekey-generation-zero",main,
            "apfs-container:"+new string('a',32),new string('b',32),"101","7","0","131072",fusion?tier:null,
            fusion?"0":null,fusion?"32768":null,fusion?new string('c',32):null,fusion?"linux-apfs-last-byte-low-bit":null));
    }
    internal static JsonObject Report(ApfsCurrentProfileVerificationRequest req)
    {
        var fusion=req.Profile=="fusion-clean-cache";var id=fusion?req.ExpectedMainIdentity+":fusion:"+req.FusionUuid+":"+req.ExpectedTier2Identity:
            req.ExpectedMainIdentity+":scope:"+req.StoreOffsetBytes+":"+req.StoreSizeBytes;
        var scope=JsonSerializer.SerializeToNode(new {containerUuid=new string('a',32),volumeUuid=new string('b',32),volumeOid="101",checkpointXid="7",
            storeOffsetBytes="0",storeSizeBytes="131072",maxReads="65536",maxReadBytes="268435456",maxRecords="1000000",maxRecordBytes="268435456",
            requireWholeVolume=false,requirePayloadContentHashes=false,observePayloadContent=false,accountRetainedOwnership=false,retainedFromXid=(string?)null})!;
        var selected=JsonSerializer.SerializeToNode(new {containerUuid=new string('a',32),volumeUuid=new string('b',32),volumeOid="101",checkpointXid="7",
            storeOffsetBytes="0",storeSizeBytes="131072",checkpointPhysicalBlock="1",volumeSuperblockPhysicalBlock="2",volumeSuperblockXid="7",rootOid="1001",rootPhysicalBlock="3"});
        var stores=new JsonArray(JsonSerializer.SerializeToNode(new {role=fusion?"main":"container",id=fusion?req.ExpectedMainIdentity:id,label=req.Image,offsetBytes="0",sizeBytes="131072"}));
        if(fusion)stores.Add(JsonSerializer.SerializeToNode(new {role="tier2",id=req.ExpectedTier2Identity,label=req.Tier2Image,offsetBytes="0",sizeBytes="32768"}));
        var coverage=new JsonArray();
        foreach(var check in new[]{1,2,3,5,6,7,8,9,11,13,17}.Concat(fusion?new[]{16,18}:new[]{15}))
            coverage.Add(JsonSerializer.SerializeToNode(new {check,implemented=check!=13,required=check!=13,state=check==13?5:2,scopeDetail="Current canonical graph"}));
        return new(){["format"]="apfs-access-current-profile-verification",["version"]=1,["readOnly"]=true,["profile"]=req.Profile,
            ["source"]=new JsonObject{["identity"]=id,["coordinateSystem"]=fusion?"member-image-relative":"container-relative",["stores"]=stores},
            ["requestedScope"]=scope,["selected"]=selected,["outcome"]=1,["outcomeName"]="Complete",["wholeVolumeVerified"]=false,
            ["retainedOwnershipComplete"]=false,["payloadContentHashesVerified"]=false,["sourceReads"]="2",["sourceReadBytes"]="8192",
            ["counts"]=JsonSerializer.SerializeToNode(new {allocationUnitBytes=4096,volumeCount=fusion?"2":"1",filesystemRecords="10",physicalExtentRecords="2",metadataDependencyBlocks="6",
                metadataCountScope=fusion?"current-object-tree-union":"current-metadata-dependency-and-guard-union"}),
            ["snapshotAllocationChargeBytes"]=null,["applePurgeableBytes"]=null,["reclaimableBytes"]=null,["findings"]=new JsonArray(),["coverage"]=coverage};
    }
    private static ApfsCurrentProfileVerificationResult Complete(JsonObject report)=>new(0,ApfsVerificationOutcome.Complete,JsonSerializer.SerializeToElement(report));
    internal static ApfsRetainedProfileVerificationResult History(ApfsCurrentProfileVerificationRequest q)
    {
        var report=Report(q);report["format"]="apfs-access-retained-profile-verification";report.Remove("counts");report["fromXid"]="5";
        report["historicalNamespaceVerified"]=true;
        report["history"]=JsonSerializer.SerializeToNode(new{allocationUnitBytes=4096,snapshotOwnerScope="canonical-empty-inventories-only",chainXids=new[]{"5","7"},
            checkpoints=new[]{"5","7"}.Select(x=>new{checkpointXid=x,metadataRanges=new[]{new{physicalBlock="2",blockCount="2"}},payloadRanges=new[]{new{physicalBlock="10",blockCount="2"}}})});
        report["coverage"]=JsonSerializer.SerializeToNode(new[]{new{check=22,implemented=true,required=true,state=2,scopeDetail="Explicit checkpoint chain; empty snapshot inventories only"}});
        return new(0,ApfsVerificationOutcome.Complete,JsonSerializer.SerializeToElement(report));
    }
    [Fact] public async Task RetainedWorkflowHoldsBothMembersAndPublishesExactScope()
    {
        var r=Request();var checkedRow=0;
        var client=new ProfileVerificationClient(true,(_,_,_)=>throw new InvalidOperationException("Current route must not run"),async(q,c,t)=>{
            Assert.Null(c);Assert.Equal("5",q.FromXid);Assert.Null(q.Endpoint.RetainedFromXid);await Task.Delay(1,t);
            foreach(var path in new[]{q.Endpoint.Image,q.Endpoint.Tier2Image!})Assert.Throws<IOException>(()=>File.OpenHandle(path,FileMode.Open,FileAccess.Write,FileShare.ReadWrite));
            return History(q.Endpoint);});
        var result=await client.RunRetainedAsync(new(r),"5",null,()=>++checkedRow,default);
        Assert.Equal(2,checkedRow);Assert.Equal(ApfsVerificationOutcome.Complete,result.Outcome);
        Assert.Contains("5, 7",result.Scope);Assert.Contains("canonical-empty-inventories-only",result.Scope);Assert.Contains("Unknown",result.Policy);
        Assert.Contains(r.ExpectedTier2Identity!,result.Scope);
    }
    [Fact] public async Task RetainedWrongBindingStaleStateAndCancellationCannotPublish()
    {
        var r=Request();var ran=0;var callbacks=0;
        Task<ApfsRetainedProfileVerificationResult> Run(ApfsRetainedProfileVerificationRequest q,SupervisedCredential? c,CancellationToken t){++ran;return Task.FromResult(History(q.Endpoint));}
        var client=new ProfileVerificationClient(true,(_,_,_)=>throw new InvalidOperationException(),Run);
        await Assert.ThrowsAsync<InvalidOperationException>(()=>client.RunRetainedAsync(new(r),"5",null,()=>throw new InvalidOperationException("stale"),default));Assert.Equal(0,ran);
        await Assert.ThrowsAsync<InvalidOperationException>(()=>client.RunRetainedAsync(new(r),"5",null,()=>{if(++callbacks==2)throw new InvalidOperationException("state changed");},default));Assert.Equal(1,ran);
        await Assert.ThrowsAsync<InvalidDataException>(()=>client.RunRetainedAsync(new(r with{ExpectedTier2Identity="foreign"}),"5",null,()=>{},default));Assert.Equal(1,ran);
        using var stop=new CancellationTokenSource();stop.Cancel();await Assert.ThrowsAsync<OperationCanceledException>(()=>client.RunRetainedAsync(new(r),"5",null,()=>{},stop.Token));Assert.Equal(1,ran);
        foreach(var from in new[]{"0","7","05"})await Assert.ThrowsAsync<ArgumentException>(()=>client.RunRetainedAsync(new(r),from,null,()=>{},default));Assert.Equal(1,ran);
        var wrong=new ProfileVerificationClient(true,(_,_,_)=>throw new InvalidOperationException(),(q,c,t)=>{
            var report=JsonNode.Parse(History(q.Endpoint).Report.GetRawText())!.AsObject();report["fromXid"]="4";
            return Task.FromResult(new ApfsRetainedProfileVerificationResult(0,ApfsVerificationOutcome.Complete,JsonSerializer.SerializeToElement(report)));});
        await Assert.ThrowsAsync<InvalidDataException>(()=>wrong.RunRetainedAsync(new(r),"5",null,()=>{},default));
        var unavailable=new ProfileVerificationClient(false,(_,_,_)=>throw new InvalidOperationException(),Run);
        await Assert.ThrowsAsync<FileNotFoundException>(()=>unavailable.RunRetainedAsync(new(r),"5",null,()=>{},default));Assert.Equal(1,ran);
        await Assert.ThrowsAsync<ArgumentException>(()=>client.RunRetainedAsync(new(Request(false)),"5",null,()=>{},default));Assert.Equal(1,ran);
    }
    private static MemoryStream Selectors(ApfsCurrentProfileVerificationRequest request)=>new(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new{
        format="apfs-access-current-profile-selection",version=1,request},new JsonSerializerOptions{PropertyNamingPolicy=JsonNamingPolicy.CamelCase})));
    [Fact] public void RegisteredZeroBagProfileKeepsExactSourceAndVolumeBinding()
    {
        var r=Request(false);var p=new EncryptedImageProfile(r.Image,r.ExpectedMainIdentity+":scope:0:131072",0,131072,
            Guid.ParseExact(new string('a',32),"N").ToString("D"),Guid.ParseExact(new string('b',32),"N").ToString("D"),101,7,0,2,0,2,
            "33333333-3333-3333-3333-333333333333","includes-header");
        var selected=ProfileVerificationSelection.Registered(p);Assert.Equal(r,selected.Request);
        Assert.Throws<InvalidDataException>(()=>ProfileVerificationSelection.Registered(p with {SourceId="windows-file:0:0:131072:0:scope:0:131072"}));
        Assert.Throws<InvalidDataException>(()=>ProfileVerificationSelection.Registered(p with {VolumeObjectId=0}));
    }
    [Fact] public void FusionSelectionRequiresBothExactMembersWindowsAndCurrentScope()
    {
        var r=Request();using(var stream=Selectors(r)){Assert.Equal(r,ProfileVerificationSelection.ReadFusion(stream).Request);}
        foreach(var bad in new[]{r with {Tier2Image=null},r with {Tier2Image=r.Image},r with {Tier2SizeBytes="32769"},
            r with {ExpectedTier2Identity="foreign"},r with {RequireWholeVolume=true},r with {RetainedFromXid="6"}})
        {using var stream=Selectors(bad);Assert.Throws<InvalidDataException>(()=>ProfileVerificationSelection.ReadFusion(stream));}
        using var oversized=new MemoryStream(new byte[16385]);Assert.Throws<InvalidDataException>(()=>ProfileVerificationSelection.ReadFusion(oversized));
    }
    [Fact] public async Task ExactReportUsesSharedDecoderAndHoldsBothFilesAcrossAwait()
    {
        var r=Request();var current=0;
        var client=new ProfileVerificationClient(true,async(q,credential,token)=>{
            Assert.Null(credential);await Task.Delay(1,token);
            foreach(var path in new[]{q.Image,q.Tier2Image!})Assert.Throws<IOException>(()=>File.OpenHandle(path,FileMode.Open,FileAccess.Write,FileShare.ReadWrite));
            return Complete(Report(q));});
        var display=await client.RunAsync(new(r),null,()=>++current,default);
        Assert.Equal(2,current);Assert.Contains(r.Image,display.Scope);Assert.Contains(r.Tier2Image!,display.Scope);
        Assert.Contains(r.ExpectedTier2Identity!,display.Scope);Assert.Contains("Unknown",display.Policy);
        Assert.Equal(ApfsVerificationOutcome.Complete,display.Outcome);
    }
    [Fact] public async Task WrongScopeCoveragePolicyAndTerminalOutcomeCannotPublish()
    {
        var r=Request();
        Action<JsonObject>[] faults=[v=>v["requestedScope"]!["checkpointXid"]="6",v=>v["wholeVolumeVerified"]=true,
            v=>v["source"]!["stores"]![1]!["offsetBytes"]="4096",v=>v["reclaimableBytes"]="4096",
            v=>v["coverage"]!.AsArray().RemoveAt(8),v=>v["format"]="apfs-access-verification",v=>v["version"]=2];
        foreach(var fault in faults){var value=Report(r);fault(value);var current=0;
            var client=new ProfileVerificationClient(true,(_,_,_)=>Task.FromResult(Complete(value)));
            await Assert.ThrowsAsync<InvalidDataException>(()=>client.RunAsync(new(r),null,()=>++current,default));Assert.Equal(1,current);}
        var inconsistent=new ProfileVerificationClient(true,(_,_,_)=>Task.FromResult(Complete(Report(r)) with {Outcome=ApfsVerificationOutcome.Refused}));
        await Assert.ThrowsAsync<InvalidDataException>(()=>inconsistent.RunAsync(new(r),null,()=>{},default));
    }
    [Fact] public async Task StaleSelectionsBeforeAndAfterNativeWorkReject()
    {
        var r=Request();var ran=0;
        var client=new ProfileVerificationClient(true,(_,_,_)=>{++ran;return Task.FromResult(Complete(Report(r)));});
        await Assert.ThrowsAsync<InvalidOperationException>(()=>client.RunAsync(new(r),null,()=>throw new InvalidOperationException("stale"),default));Assert.Equal(0,ran);
        var calls=0;await Assert.ThrowsAsync<InvalidOperationException>(()=>client.RunAsync(new(r),null,()=>{if(++calls==2)throw new InvalidOperationException("stale");},default));Assert.Equal(1,ran);
        await Assert.ThrowsAsync<InvalidDataException>(()=>client.RunAsync(new(r with {ExpectedMainIdentity="foreign"}),null,()=>{},default));Assert.Equal(1,ran);
    }
    [Fact] public async Task CapabilityCancellationAndCredentialFailuresDoNotStartNativeWork()
    {
        var r=Request();var ran=0;Task<ApfsCurrentProfileVerificationResult> Run(ApfsCurrentProfileVerificationRequest q,SupervisedCredential? c,CancellationToken t)
        {++ran;return Task.FromResult(Complete(Report(q)));}
        var unavailable=new ProfileVerificationClient(false,Run);
        await Assert.ThrowsAsync<FileNotFoundException>(()=>unavailable.RunAsync(new(r),null,()=>{},default));
        var client=new ProfileVerificationClient(true,Run);using var cancel=new CancellationTokenSource();cancel.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(()=>client.RunAsync(new(r),null,()=>{},cancel.Token));
        using var secret=new System.Security.SecureString();secret.AppendChar('x');using var credential=SupervisedCredential.FromSecureString(secret);
        await Assert.ThrowsAsync<ArgumentException>(()=>client.RunAsync(new(r),credential,()=>{},default));
        await Assert.ThrowsAsync<ArgumentException>(()=>client.RunAsync(new(Request(false)),null,()=>{},default));Assert.Equal(0,ran);
    }
    [Fact] public async Task CancellationWaitsForOwnedWorkAndReleasesBothMemberLeases()
    {
        var r=Request();var started=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var client=new ProfileVerificationClient(true,async(_,_,token)=>{started.SetResult();await Task.Delay(Timeout.Infinite,token);throw new Exception("unreachable");});
        using var cancel=new CancellationTokenSource();var pending=client.RunAsync(new(r),null,()=>{},cancel.Token);
        await started.Task;cancel.Cancel();await Assert.ThrowsAnyAsync<OperationCanceledException>(()=>pending);
        foreach(var path in new[]{r.Image,r.Tier2Image!})using(File.OpenHandle(path,FileMode.Open,FileAccess.Write,FileShare.Read)){}
    }
    private static EncryptedImageProfile Writable(ApfsCurrentProfileVerificationRequest request)
    {
        var parts=request.ExpectedMainIdentity!.Split(':');
        return new EncryptedImageProfile(request.Image,$"image-writer-v1:{parts[1]}:{parts[2]}:{parts[3]}:0:131072",0,131072,
            Guid.ParseExact(new string('a',32),"N").ToString("D"),Guid.ParseExact(new string('b',32),"N").ToString("D"),
            101,7,0,2,0,2,"33333333-3333-3333-3333-333333333333","includes-header"){Writable=true};
    }
    [Fact] public async Task WritableRegistrationUsesBoundReadOnlyIdentityAndLeaseThroughAwait()
    {
        var r=Request(false);var profile=Writable(r);Assert.True(profile.IsValid());
        var selected=ProfileVerificationSelection.Registered(profile);Assert.Null(selected.Request.ExpectedMainIdentity);
        using var secret=new System.Security.SecureString();secret.AppendChar('x');using var credential=SupervisedCredential.FromSecureString(secret);
        var ran=0;var client=new ProfileVerificationClient(true,async(q,c,token)=>{
            ++ran;Assert.Same(credential,c);Assert.Equal(r.ExpectedMainIdentity,q.ExpectedMainIdentity);
            Assert.NotEqual(profile.SourceId,q.ExpectedMainIdentity);await Task.Delay(1,token);
            Assert.Throws<IOException>(()=>File.OpenHandle(q.Image,FileMode.Open,FileAccess.Write,FileShare.ReadWrite));
            return Complete(Report(q));});
        var display=await client.RunAsync(selected,credential,()=>{},default);
        Assert.Equal(1,ran);Assert.Equal(ApfsVerificationOutcome.Complete,display.Outcome);
        Assert.Null(display.Report.GetProperty("applePurgeableBytes").GetString());
        using(File.OpenHandle(r.Image,FileMode.Open,FileAccess.Write,FileShare.Read)){}
    }
    [Fact] public async Task WritableIdentityAndSelectorChangesRejectBeforeNativeWork()
    {
        var r=Request(false);var profile=Writable(r);var ran=0;
        using var secret=new System.Security.SecureString();secret.AppendChar('x');using var credential=SupervisedCredential.FromSecureString(secret);
        var client=new ProfileVerificationClient(true,(q,_,_)=>{++ran;return Task.FromResult(Complete(Report(q)));});
        var parts=profile.SourceId.Split(':');parts[2]=(ulong.Parse(parts[2])+1).ToString(System.Globalization.CultureInfo.InvariantCulture);
        var foreign=ProfileVerificationSelection.Registered(profile with {SourceId=string.Join(':',parts)});
        await Assert.ThrowsAsync<IOException>(()=>client.RunAsync(foreign,credential,()=>{},default));
        var selected=ProfileVerificationSelection.Registered(profile);
        await Assert.ThrowsAsync<InvalidDataException>(()=>client.RunAsync(selected with {Request=selected.Request with {CheckpointXid="8"}},credential,()=>{},default));
        await Assert.ThrowsAsync<ArgumentException>(()=>client.RunAsync(selected,null,()=>{},default));
        Assert.Equal(0,ran);
    }
    [Fact] public async Task WritableCancellationReleasesDedicatedReadOnlyPin()
    {
        var r=Request(false);var selected=ProfileVerificationSelection.Registered(Writable(r));
        using var secret=new System.Security.SecureString();secret.AppendChar('x');using var credential=SupervisedCredential.FromSecureString(secret);
        var started=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var client=new ProfileVerificationClient(true,async(_,_,token)=>{started.SetResult();await Task.Delay(Timeout.Infinite,token);throw new Exception("unreachable");});
        using var cancel=new CancellationTokenSource();var pending=client.RunAsync(selected,credential,()=>{},cancel.Token);
        await started.Task;cancel.Cancel();await Assert.ThrowsAnyAsync<OperationCanceledException>(()=>pending);
        using(File.OpenHandle(r.Image,FileMode.Open,FileAccess.ReadWrite,FileShare.None)){}
    }
    private static StatusChangedPayload RegisteredStatus(EncryptedImageProfile profile,EncryptedVolumeState state,bool mounted)
    {
        var volume=new VolumeInfo(profile.VolumeId,profile.ImagePath,"Encrypted image",false,IsEncrypted:true,RecoveryIdentity:profile.Contract,
            CatalogVolumeId:profile.VolumeId,CatalogContainerUuid:profile.ContainerUuid,CatalogVolumeObjectId:profile.VolumeObjectId,
            CatalogDecision:ApfsCapabilityDecision.Locked,CatalogReasons:["encrypted"],CatalogAutoMountAllowed:false,CatalogVolumeUuid:profile.VolumeUuid,
            RegisteredImage:profile,EncryptionState:state);
        MountedVolumeDisplay[] mounts=mounted?[new(profile.VolumeId,"R:\\",volume.VolumeName,profile.ImagePath,"Image",profile.AccessMode,
            RecoveryIdentity:profile.Contract,CatalogVolumeId:profile.VolumeId,CatalogContainerUuid:profile.ContainerUuid,
            CatalogVolumeObjectId:profile.VolumeObjectId,CatalogVolumeUuid:profile.VolumeUuid)]:[];
        return new(mounted?RuntimeState.MountedRw:RuntimeState.Idle,mounted?["R:\\"]:[],null,DateTime.UtcNow,[],mounted,[],MountedVolumes:mounts,
            ConnectedInventory:[new(new(profile.ImagePath,"Registered image",true),[volume])],InventoryGeneration:1);
    }
    [Fact] public async Task WritableServiceStateMustStayLockedAndOfflineBeforeAnyNativeWork()
    {
        var r=Request(false);var profile=Writable(r);var status=RegisteredStatus(profile,EncryptedVolumeState.Locked,false);
        var selected=Assert.Single(DriveDashboardPresenter.BuildRows(status));Assert.True(DriveDashboardPresenter.CanVerifyCurrentProfile(selected));
        var ran=0;var client=new ProfileVerificationClient(true,(q,_,_)=>{++ran;return Task.FromResult(Complete(Report(q)));});
        using var secret=new System.Security.SecureString();secret.AppendChar('x');using var credential=SupervisedCredential.FromSecureString(secret);
        foreach(var state in Enum.GetValues<EncryptedVolumeState>())foreach(var mounted in new[]{false,true})
        {
            if(state==EncryptedVolumeState.Locked&&!mounted)continue;
            status=RegisteredStatus(profile,state,mounted);
            var row=Assert.Single(DriveDashboardPresenter.BuildRows(status));Assert.False(DriveDashboardPresenter.CanVerifyCurrentProfile(row));
            Assert.Contains("Lock",DriveDashboardPresenter.ProfileVerificationUnavailableReason(row));
            var error=await Assert.ThrowsAsync<InvalidOperationException>(()=>client.RunAsync(ProfileVerificationSelection.Registered(profile),credential,
                ()=>DriveDashboardPresenter.RequireCurrentProfileRow(status,selected,true),default));
            Assert.Contains("offline",error.Message);
        }
        Assert.Equal(0,ran);
        status=RegisteredStatus(profile,EncryptedVolumeState.Locked,false);
        await client.RunAsync(ProfileVerificationSelection.Registered(profile),credential,
            ()=>DriveDashboardPresenter.RequireCurrentProfileRow(status,selected,true),default);
        Assert.Equal(1,ran);
    }
    [Fact] public async Task WritableStateChangeDuringVerificationCannotPublishAndReadOnlyUnlockedRemainsAllowed()
    {
        var r=Request(false);var profile=Writable(r);var status=RegisteredStatus(profile,EncryptedVolumeState.Locked,false);
        var selected=Assert.Single(DriveDashboardPresenter.BuildRows(status));
        using var secret=new System.Security.SecureString();secret.AppendChar('x');using var credential=SupervisedCredential.FromSecureString(secret);
        var client=new ProfileVerificationClient(true,(q,_,_)=>{
            status=RegisteredStatus(profile,EncryptedVolumeState.Unlocked,true);return Task.FromResult(Complete(Report(q)));});
        await Assert.ThrowsAsync<InvalidOperationException>(()=>client.RunAsync(ProfileVerificationSelection.Registered(profile),credential,
            ()=>DriveDashboardPresenter.RequireCurrentProfileRow(status,selected,true),default));
        var readOnly=profile with {Writable=false,SourceId=r.ExpectedMainIdentity+":scope:0:131072"};
        status=RegisteredStatus(readOnly,EncryptedVolumeState.Unlocked,true);
        selected=Assert.Single(DriveDashboardPresenter.BuildRows(status));Assert.True(DriveDashboardPresenter.CanVerifyCurrentProfile(selected));
        var allowed=new ProfileVerificationClient(true,(q,_,_)=>Task.FromResult(Complete(Report(q))));
        var display=await allowed.RunAsync(ProfileVerificationSelection.Registered(readOnly),credential,
            ()=>DriveDashboardPresenter.RequireCurrentProfileRow(status,selected,true),default);
        Assert.Equal(ApfsVerificationOutcome.Complete,display.Outcome);
    }
    public void Dispose(){if(Directory.Exists(folder))Directory.Delete(folder,true);}
}
