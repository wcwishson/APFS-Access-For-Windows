using System.Text.Json;
using ApfsAccess.Core;

namespace ApfsAccess.Core.Tests;

public sealed class BoundTopologyActionContractTests
{
    private static DeviceInventory Source()
    {
        var hex=new string('a',32);var container=ApfsTopology.BuildContainerId(hex);const string path=@"D:\bounded-actions.apfs";
        var rows=Enumerable.Range(0,2).Select(i=>new VolumeInfo(ApfsTopology.BuildVolumeId(hex,(ulong)(101+i)),path,$"Member {i+1}",true,
            SupportsNativeWrite:true,RecoveryIdentity:$"owner-{i}",CatalogVolumeId:ApfsTopology.BuildVolumeId(hex,(ulong)(101+i)),
            CatalogContainerUuid:hex,CatalogVolumeObjectId:(ulong)(101+i),CatalogDecision:ApfsCapabilityDecision.Writable,
            CatalogReasons:[],CatalogAutoMountAllowed:true,CatalogVolumeUuid:new string((char)('b'+i),32))).ToArray();
        var graph=new ApfsTopologySnapshot([new("apfs-disk:image",path,null,2097152)],[],
            [new("apfs-store:image",hex,"",container,0,2097152,DiskId:"apfs-disk:image")],
            [new(container,hex,4096,["apfs-store:image"],rows.Select(v=>v.CatalogVolumeId!).ToArray(),false,"90",[],[],[])],
            rows.Select(v=>new ApfsVolumeRecord(v.CatalogVolumeId!,v.CatalogVolumeUuid!,v.CatalogVolumeObjectId!.Value.ToString(),
                container,v.VolumeName,true,["data"],64,null,"sensitive","none",false,[],[],[],"7","90")).ToArray(),[]);
        return new(new(path,"Image",true),rows,new(1,path,["apfs-disk:image"],graph));
    }

    [Fact] public void BoundBatchAndLeafKeepExistingActionWireAndUnboundRefusals()
    {
        var source=Source();Assert.True(TopologyAdmission.Validate(source));
        var contracts=source.Volumes.ToDictionary(v=>v.VolumeId,v=>TopologyAdmission.Contract(source,v));
        var batch=ApfsTopologyActionContract.ForBoundMemberBatch(source,"90",contracts,true,true);
        Assert.True(ApfsTopologyActionContract.Find(batch,ApfsTopologyAction.Verify).IsAvailable);
        Assert.True(ApfsTopologyActionContract.Find(batch,ApfsTopologyAction.Repair).IsAvailable);
        Assert.False(ApfsTopologyActionContract.Find(batch,ApfsTopologyAction.Manage).IsAvailable);
        var leaf=ApfsTopologyActionContract.ForBoundOfflineMember(source,"90",contracts,source.Volumes[1].VolumeId,true);
        Assert.True(ApfsTopologyActionContract.Find(leaf,ApfsTopologyAction.Manage).IsAvailable);
        var unbound=ApfsTopologyActionContract.ForContainer(true,true,true);
        Assert.Equal(ApfsTopologyActionContract.LiveVerifyUnavailable,ApfsTopologyActionContract.Find(unbound,ApfsTopologyAction.Verify).Code);
        Assert.Equal(ApfsTopologyActionContract.LiveRepairUnavailable,ApfsTopologyActionContract.Find(unbound,ApfsTopologyAction.Repair).Code);
        Assert.Equal(ApfsTopologyActionContract.LiveContainerManagementUnavailable,ApfsTopologyActionContract.Find(unbound,ApfsTopologyAction.Manage).Code);
        Assert.All(unbound.Where(c=>c.Action is ApfsTopologyAction.Verify or ApfsTopologyAction.Repair or ApfsTopologyAction.Manage),c=>Assert.False(c.IsAvailable));
        var wire=JsonSerializer.Serialize(new ApfsActionCapability(ApfsTopologyAction.Manage,ApfsActionAvailability.Refused,
            "live-container-management-unavailable","recorded baseline"),new JsonSerializerOptions{PropertyNamingPolicy=JsonNamingPolicy.CamelCase});
        Assert.Equal("{\"action\":14,\"availability\":2,\"code\":\"live-container-management-unavailable\",\"reason\":\"recorded baseline\",\"isAvailable\":false}",wire);
        Assert.Equal(Enumerable.Range(0,17),Enum.GetValues<ApfsTopologyAction>().Select(a=>(int)a));
    }

    [Fact] public void PartialCheckpointWindowContractAndCatalogAliasesCannotBind()
    {
        var source=Source();var contracts=source.Volumes.ToDictionary(v=>v.VolumeId,v=>TopologyAdmission.Contract(source,v));
        foreach(var xid in new[]{"91","090","0",""})
            Assert.Throws<InvalidOperationException>(()=>ApfsTopologyActionContract.ForBoundMemberBatch(source,xid,contracts,true,true));
        Assert.Throws<InvalidOperationException>(()=>ApfsTopologyActionContract.ForBoundMemberBatch(source,"90",contracts.Take(1).ToDictionary(p=>p.Key,p=>p.Value),true,true));
        var changed=source with{Topology=source.Topology! with{Snapshot=source.Topology.Snapshot with{
            Stores=[source.Topology.Snapshot.Stores[0] with{SizeBytes=1048576}]}}};
        Assert.True(TopologyAdmission.Validate(changed));
        Assert.Throws<InvalidOperationException>(()=>ApfsTopologyActionContract.ForBoundMemberBatch(changed,"90",contracts,true,true));
        var forged=contracts.ToDictionary(p=>p.Key,p=>"selected-v1:"+new string('0',64));
        Assert.Throws<InvalidOperationException>(()=>ApfsTopologyActionContract.ForBoundMemberBatch(source,"90",forged,true,true));
        var alias=source with{Volumes=[source.Volumes[0],source.Volumes[0] with{VolumeId=source.Volumes[1].VolumeId}]};
        var aliasContracts=alias.Volumes.ToDictionary(v=>v.VolumeId,v=>TopologyAdmission.Contract(alias,v));
        Assert.Throws<InvalidOperationException>(()=>ApfsTopologyActionContract.ForBoundMemberBatch(alias,"90",aliasContracts,true,true));
        Assert.Throws<InvalidOperationException>(()=>ApfsTopologyActionContract.ForBoundOfflineMember(source,"90",contracts,"foreign-member",true));
        Assert.False(ApfsTopologyActionContract.Find(ApfsTopologyActionContract.ForBoundOfflineMember(source,"90",contracts,
            source.Volumes[0].VolumeId,false),ApfsTopologyAction.Manage).IsAvailable);
    }
}
