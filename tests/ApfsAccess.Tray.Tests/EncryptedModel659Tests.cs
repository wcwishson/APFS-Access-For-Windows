using ApfsAccess.Core;
using ApfsAccess.Ipc;
namespace ApfsAccess.Tray.Tests;
public sealed class EncryptedModel659Tests
{
    private static EncryptedImageProfile Profile => new(@"D:\test-image.apfs","windows-file:1:2:4096:4:scope:0:4096",0,4096,
        "11111111-1111-1111-1111-111111111111","22222222-2222-2222-2222-222222222222",12,8,1,8,2,8,
        "33333333-3333-3333-3333-333333333333","includes-header");
    private static StatusChangedPayload Status(EncryptedVolumeState state,bool mounted)
    {
        var p=Profile;var v=new VolumeInfo(p.VolumeId,p.ImagePath,"Encrypted image",false,IsEncrypted:true,RecoveryIdentity:p.Contract,
            CatalogVolumeId:p.VolumeId,CatalogContainerUuid:p.ContainerUuid,CatalogVolumeObjectId:p.VolumeObjectId,
            CatalogDecision:ApfsCapabilityDecision.Locked,CatalogReasons:["encrypted"],CatalogAutoMountAllowed:false,CatalogVolumeUuid:p.VolumeUuid,
            RegisteredImage:p,EncryptionState:state);
        MountedVolumeDisplay[] mounts=mounted?[new(p.VolumeId,"R:\\",v.VolumeName,p.ImagePath,"Image",MountAccessMode.ReadOnly,RecoveryIdentity:p.Contract,
            CatalogVolumeId:p.VolumeId,CatalogContainerUuid:p.ContainerUuid,CatalogVolumeObjectId:p.VolumeObjectId,CatalogVolumeUuid:p.VolumeUuid)]:[];
        return new(RuntimeState.MountedRo,mounted?["R:\\"]:[],null,DateTime.UtcNow,[],false,[],MountedVolumes:mounts,
            ConnectedInventory:[new(new(p.ImagePath,"Registered image",true),[v])],InventoryGeneration:1);
    }
    [Theory] [InlineData(EncryptedVolumeState.Locked,false,true,false)] [InlineData(EncryptedVolumeState.Unlocked,true,false,true)]
    [InlineData(EncryptedVolumeState.Unlocking,false,false,false)] [InlineData(EncryptedVolumeState.Locking,true,false,false)]
    [InlineData(EncryptedVolumeState.Failed,false,true,false)]
    public void ModelExposesRealActionsAndReadableState(EncryptedVolumeState state,bool mounted,bool unlock,bool locked)
    {
        var status=Status(state,mounted);var row=Assert.Single(DriveDashboardPresenter.BuildRows(status));
        Assert.Equal(unlock,row.CanUnlock);Assert.Equal(locked,row.CanLock);Assert.False(row.CanFix);Assert.False(row.CanInspectReadOnly);
        if(state is EncryptedVolumeState.Locked or EncryptedVolumeState.Unlocked or EncryptedVolumeState.Failed) Assert.Equal(DashboardPalette.Yellow,row.Palette);
        Assert.DoesNotContain(" RO",row.StateText);Assert.DoesNotContain(" RW",row.StateText);
        if(unlock||locked) {var request=DriveDashboardPresenter.CreateSelectedRequest(status,row,unlock?"unlock":"lock");Assert.Equal(Profile,request.Target!.RegisteredImage);Assert.True(SelectedControlTarget.IsWellFormed(request.Target));}
    }
    [Fact] public void ImageMemberAndContainerAreRenderedWithoutInventingGpt()
    {
        var nodes=TopologyDashboard.Project(Status(EncryptedVolumeState.Locked,false));var row=Assert.Single(nodes,n=>n.Row is not null);
        var container=Assert.Single(nodes,n=>n.Id==row.ParentId);Assert.Contains(Profile.ContainerUuid,container.Details);
        var store=Assert.Single(nodes,n=>n.Id==container.ParentId);Assert.Contains(Profile.SourceId,store.Details);
        Assert.DoesNotContain(nodes,n=>n.Text.Contains("GPT"));
    }
    [Fact] public void DuplicateImageIdentityCannotOfferUnlockOrLock()
    {
        var status=Status(EncryptedVolumeState.Locked,false);status=status with {ConnectedInventory=[status.ConnectedInventory![0],status.ConnectedInventory![0]]};
        var row=Assert.Single(DriveDashboardPresenter.BuildRows(status));Assert.False(row.CanUnlock);Assert.False(row.CanLock);
    }
}
