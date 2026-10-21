using System.Reflection;
using System.Windows.Forms;
using ApfsAccess.Core;
using ApfsAccess.Ipc;

namespace ApfsAccess.Tray.Tests;

public sealed class ContainerManagementSelectionTests
{
    private static readonly VerifyScope Scope=new(@"D:\ApfsAccessScratch\container-member-selection.apfs",
        "apfs-container:"+new string('a',32),new string('b',32),"101","20","0","2097152");
    private static StatusChangedPayload Status(VerifyScope? scope=null)=>MarkedReferenceSpaceWorkflowTests.StatusFor(scope??Scope) with{
        MountedVolumes=[],ManagementJournalRootInspected=true,ImageManagementMutationsEnabled=true,
        VolumeManagementReadyImages=[(scope??Scope).ImagePath]};

    [Fact] public void ParentSelectionRejectsCheckpointOrMembershipDriftBeforeLeafManagement()
    {
        var status=Status();var rows=DriveDashboardPresenter.BuildRows(status);
        Assert.True(Assert.Single(rows).CanManageOffline);
        var selected=ContainerManagementSelection.Capture(status,rows);
        var resolved=selected.Resolve(status,rows[0].VolumeId);
        Assert.Equal(rows[0].VolumeId,resolved.VolumeId);Assert.Equal(rows[0].SnapshotScope,resolved.SnapshotScope);
        Assert.Equal(rows[0].RecoveryIdentity,resolved.RecoveryIdentity);
        Assert.Throws<InvalidOperationException>(()=>selected.Resolve(Status(Scope with{CheckpointXid="21"}),rows[0].VolumeId));
        Assert.Throws<InvalidOperationException>(()=>selected.Resolve(status,ApfsTopology.BuildVolumeId(new string('a',32),102)));
        Assert.Throws<InvalidOperationException>(()=>ContainerManagementSelection.Capture(status,[]));
        Assert.Throws<InvalidOperationException>(()=>ContainerManagementSelection.Capture(status,[rows[0],rows[0] with{CatalogVolumeObjectId=102}]));
        var ambiguous=status with{ConnectedInventory=[status.ConnectedInventory![0],status.ConnectedInventory[0]]};
        Assert.Throws<InvalidOperationException>(()=>selected.Resolve(ambiguous,rows[0].VolumeId));
        Assert.Throws<InvalidOperationException>(()=>selected.Resolve(status with{ManagementJournalRootInspected=false},rows[0].VolumeId));
    }

    [Fact] public void RealContainerChooserAndDashboardDispatchExactMemberAndStopOnDrift()
    {
        Exception? failure=null;var thread=new Thread(()=>{try{
            WindowsFormsSynchronizationContext.AutoInstall=false;
            var status=Status();var rows=DriveDashboardPresenter.BuildRows(status);var selected=ContainerManagementSelection.Capture(status,rows);
            using var picker=new ContainerManagementDialog(selected);Assert.Equal(rows[0].VolumeId,picker.SelectedVolumeId);Assert.False(picker.Visible);
            var count=0;DriveDashboardRow? received=null;
            using var form=new DashboardForm(_=>Task.CompletedTask,_=>Task.CompletedTask,_=>Task.CompletedTask,
                manageVolumeAsync:row=>{++count;received=row;return Task.CompletedTask;});
            form.ApplyStatus(status);
            var tree=(TreeView)typeof(DashboardForm).GetField("_topologyTree",BindingFlags.Instance|BindingFlags.NonPublic)!.GetValue(form)!;
            IEnumerable<TreeNode> Nodes(TreeNodeCollection roots)=>roots.Cast<TreeNode>().SelectMany(n=>new[]{n}.Concat(Nodes(n.Nodes)));
            _=tree.Handle;tree.SelectedNode=Nodes(tree.Nodes).Single(n=>n.Tag is TopologyDashboardNode node&&node.Id.Contains("apfs-container:")&&node.Row is null);
            var button=(Button)typeof(DashboardForm).GetField("_containerManageButton",BindingFlags.Instance|BindingFlags.NonPublic)!.GetValue(form)!;
            Assert.True(button.Enabled);
            form.DispatchContainerManagement(selected,picker.SelectedVolumeId!);
            Assert.Equal(1,count);Assert.Equal(rows[0].VolumeId,received!.VolumeId);Assert.Equal(rows[0].RecoveryIdentity,received.RecoveryIdentity);
            form.ApplyStatus(Status(Scope with{CheckpointXid="21"}));
            Assert.Throws<InvalidOperationException>(()=>form.DispatchContainerManagement(selected,picker.SelectedVolumeId!));Assert.Equal(1,count);
            Assert.False(form.Visible);
        }catch(Exception ex){failure=ex;}});
        thread.SetApartmentState(ApartmentState.STA);thread.Start();thread.Join();
        if(failure is not null)System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(failure).Throw();
    }
}
