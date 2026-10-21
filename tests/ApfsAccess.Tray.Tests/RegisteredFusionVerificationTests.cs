using System.Reflection;
using System.Windows.Forms;
using ApfsAccess.Backend.Native;
using ApfsAccess.Core;
using ApfsAccess.Ipc;

namespace ApfsAccess.Tray.Tests;

public sealed class RegisteredFusionVerificationTests : IDisposable
{
    private readonly string folder=Path.Combine(Path.GetTempPath(),"registered-fusion-verify-"+Guid.NewGuid().ToString("N"));

    private FusionImageProfile Profile()
    {
        Directory.CreateDirectory(folder);
        var main=Path.Combine(folder,"main.apfs");var tier=Path.Combine(folder,"tier.apfs");
        File.WriteAllBytes(main,new byte[131072]);File.WriteAllBytes(tier,new byte[32768]);
        return Capture(new(new string('a',32),new string('c',32),new string('b',32),101,7,
            [new(tier,"tier2","tier-store",0,32768),new(main,"main","main-store",0,131072)]));
    }

    internal static FusionImageProfile Capture(FusionImageProfile profile)
    {
        using var held=NativeFusionImageLaunch.Prepare(new(profile.ContainerUuid,profile.FusionUuid,profile.VolumeUuid,
            profile.VolumeOid,profile.CheckpointXid,profile.Members.Select(m=>new FusionImageMemberSelection(
                m.Path,m.Role,m.StoreId,m.StoreOffset,m.StoreSize)).ToArray()));
        return profile with{Members=profile.Members.Select(m=>m with{Identity=held.Members.Single(x=>x.Selection.Role==m.Role).Identity}).ToArray()};
    }

    internal static StatusChangedPayload Status(FusionImageProfile profile,bool mounted=false)
    {
        var volume=new VolumeInfo(profile.VolumeId,profile.DeviceId,"Fusion pair",true,SupportsNativeWrite:true,
            RecoveryIdentity:profile.Contract,CatalogVolumeId:profile.VolumeId,CatalogContainerUuid:profile.ContainerUuid,
            CatalogVolumeObjectId:profile.VolumeOid,CatalogDecision:ApfsCapabilityDecision.Readable,CatalogReasons:["registered-fusion-explicit-owner"],
            CatalogAutoMountAllowed:false,CatalogVolumeUuid:profile.VolumeUuid,RegisteredFusion:profile);
        MountedVolumeDisplay[] mounts=mounted?[new(profile.VolumeId,"R:\\",volume.VolumeName,profile.DeviceId,"Pair",MountAccessMode.ReadWrite,
            RecoveryIdentity:profile.Contract,CatalogVolumeId:profile.VolumeId,CatalogContainerUuid:profile.ContainerUuid,
            CatalogVolumeObjectId:profile.VolumeOid,CatalogVolumeUuid:profile.VolumeUuid)]:[];
        return new(mounted?RuntimeState.MountedRw:RuntimeState.Idle,mounted?["R:\\"]:[],null,DateTime.UtcNow,[],mounted,[],
            MountedVolumes:mounts,ConnectedInventory:[new(new(profile.DeviceId,"Fusion pair",true),[volume])],InventoryGeneration:1);
    }

    [Fact] public async Task RegisteredPairUsesCanonicalIdentitiesRolesAndRetainsReadLeases()
    {
        var profile=Profile();var selected=ProfileVerificationSelection.Registered(profile);
        Assert.Equal(profile.Members.Single(m=>m.Role=="main").Path,selected.Request.Image);
        Assert.Equal(profile.Members.Single(m=>m.Role=="tier2").Path,selected.Request.Tier2Image);
        var calls=0;
        var client=new ProfileVerificationClient(true,async(q,credential,token)=>{
            ++calls;Assert.Null(credential);await Task.Delay(1,token);
            foreach(var member in profile.Members)
                Assert.Throws<IOException>(()=>File.OpenHandle(member.Path,FileMode.Open,FileAccess.Write,FileShare.ReadWrite));
            return new(0,ApfsVerificationOutcome.Complete,System.Text.Json.JsonSerializer.SerializeToElement(ProfileVerificationTests.Report(q)));
        });
        var result=await client.RunAsync(selected,null,selected.RequireCurrentSources,default);
        Assert.Equal(1,calls);Assert.Equal(ApfsVerificationOutcome.Complete,result.Outcome);
        Assert.Contains(selected.Request.ExpectedTier2Identity!,result.Scope);
        await Assert.ThrowsAsync<InvalidDataException>(()=>client.RunAsync(selected with{Request=selected.Request with{CheckpointXid="8"}},null,()=>{},default));
        Assert.Equal(1,calls);
        var wrong=profile with{Members=profile.Members.Select((m,i)=>i==0?m with{Identity="foreign"}:m).ToArray()};
        Assert.Throws<InvalidDataException>(()=>ProfileVerificationSelection.Registered(wrong));
        Assert.Throws<InvalidDataException>(()=>ProfileVerificationSelection.Registered(profile with{Members=profile.Members.Select((m,i)=>i==0?m with{Identity=null}:m).ToArray()}));
        File.Delete(profile.Members[0].Path);
        Assert.Throws<FileNotFoundException>(()=>selected.RequireCurrentSources());
    }

    [Fact] public async Task RemountAndChangedRegistrationCannotPublishRegisteredResult()
    {
        var profile=Profile();var status=Status(profile);var selected=Assert.Single(DriveDashboardPresenter.BuildRows(status));
        Assert.True(DriveDashboardPresenter.CanVerifyCurrentProfile(selected));
        DriveDashboardPresenter.RequireCurrentProfileRow(status,selected,true);
        var calls=0;var client=new ProfileVerificationClient(true,(q,c,t)=>{
            ++calls;status=Status(profile,true);
            return Task.FromResult(new ApfsCurrentProfileVerificationResult(0,ApfsVerificationOutcome.Complete,
                System.Text.Json.JsonSerializer.SerializeToElement(ProfileVerificationTests.Report(q))));});
        await Assert.ThrowsAsync<InvalidOperationException>(()=>client.RunAsync(ProfileVerificationSelection.Registered(profile),null,
            ()=>DriveDashboardPresenter.RequireCurrentProfileRow(status,selected,true),default));
        Assert.Equal(1,calls);
        var mounted=Assert.Single(DriveDashboardPresenter.BuildRows(status));Assert.False(DriveDashboardPresenter.CanVerifyCurrentProfile(mounted));
        Assert.Contains("offline",DriveDashboardPresenter.ProfileVerificationUnavailableReason(mounted));
        foreach(var changed in new[]{profile with{CheckpointXid=8},profile with{Members=profile.Members.Select((m,i)=>i==0?m with{StoreOffset=4096}:m).ToArray()}})
            Assert.Throws<InvalidOperationException>(()=>DriveDashboardPresenter.RequireCurrentProfileRow(Status(changed),selected,true));
        status=Status(profile);status=status with{ConnectedInventory=[status.ConnectedInventory![0],status.ConnectedInventory[0]]};
        Assert.Throws<InvalidOperationException>(()=>DriveDashboardPresenter.RequireCurrentProfileRow(status,selected,true));
        Assert.Throws<InvalidOperationException>(()=>DriveDashboardPresenter.RequireCurrentProfileRow(Status(profile),selected,false));
    }

    [Fact] public void ChangedExplicitMemberClearsRealFormCoverageAndSuccess()
    {
        Exception? failure=null;
        var thread=new Thread(()=>{try{CheckChangedExplicitMember();}catch(Exception ex){failure=ex;}});
        thread.SetApartmentState(ApartmentState.STA);thread.Start();thread.Join();
        if(failure is not null)System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(failure).Throw();
    }

    private void CheckChangedExplicitMember()
    {
        var selected=new ProfileVerificationSelection(ProfileVerificationSelection.Registered(Profile()).Request);
        using var form=new ProfileVerificationDialog(selected,null,selected.RequireCurrentSources,false,
            new ProfileVerificationClient(true,(_,_,_)=>throw new InvalidOperationException("This display probe cannot launch work.")));
        var report=ProfileVerificationTests.Report(selected.Request);
        form.DisplayResult(new(ApfsVerificationOutcome.Complete,System.Text.Json.JsonSerializer.SerializeToElement(report)),false);
        var grid=(DataGridView)typeof(ProfileVerificationDialog).GetField("coverage",BindingFlags.Instance|BindingFlags.NonPublic)!.GetValue(form)!;
        Assert.NotNull(grid.DataSource);
        var member=selected.Request.Tier2Image!;
        File.SetLastWriteTimeUtc(member,File.GetLastWriteTimeUtc(member).AddSeconds(2));
        form.RevalidateDisplayedSelection();
        Assert.Null(grid.DataSource);
        var status=(Label)typeof(ProfileVerificationDialog).GetField("status",BindingFlags.Instance|BindingFlags.NonPublic)!.GetValue(form)!;
        Assert.DoesNotContain("Complete:",status.Text);
        var scope=(TextBox)typeof(ProfileVerificationDialog).GetField("scope",BindingFlags.Instance|BindingFlags.NonPublic)!.GetValue(form)!;
        Assert.DoesNotContain("Covered volumes:",scope.Text);
    }

    [Fact] public void ProductionDashboardDispatchesExactRegisteredPairAndDisablesAfterMount()
    {
        Exception? failure=null;
        var thread=new Thread(()=>{try{
            var profile=Profile();DriveDashboardRow? dispatched=null;
            using var form=new DashboardForm(_=>Task.CompletedTask,_=>Task.CompletedTask,_=>Task.CompletedTask,
                verifyProfileAsync:row=>{dispatched=row;return Task.CompletedTask;});
            form.ApplyStatus(Status(profile));
            var tree=(TreeView)typeof(DashboardForm).GetField("_topologyTree",BindingFlags.Instance|BindingFlags.NonPublic)!.GetValue(form)!;
            IEnumerable<TreeNode> Nodes(TreeNodeCollection roots)=>roots.Cast<TreeNode>().SelectMany(n=>new[]{n}.Concat(Nodes(n.Nodes)));
            _=tree.Handle;
            tree.SelectedNode=Nodes(tree.Nodes).Single(n=>n.Tag is TopologyDashboardNode{Row:{ } row}&&row.VolumeId==profile.VolumeId);
            var button=(Button)typeof(DashboardForm).GetField("_profileVerifyButton",BindingFlags.Instance|BindingFlags.NonPublic)!.GetValue(form)!;
            Assert.True(button.Enabled);
            typeof(Button).GetMethod("OnClick",BindingFlags.Instance|BindingFlags.NonPublic)!.Invoke(button,[EventArgs.Empty]);
            Assert.NotNull(dispatched);Assert.Equal(profile.Contract,dispatched.RegisteredFusion!.Contract);
            form.ApplyStatus(Status(profile,true));Assert.False(button.Enabled);
            Assert.Contains("Unmount",button.Text);Assert.False(form.Visible);
        }catch(Exception ex){failure=ex;}});
        thread.SetApartmentState(ApartmentState.STA);thread.Start();thread.Join();
        if(failure is not null)System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(failure).Throw();
    }

    public void Dispose(){if(Directory.Exists(folder))Directory.Delete(folder,true);}
}
