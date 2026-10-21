using System.Reflection;
using System.Windows.Forms;
using ApfsAccess.Core;
using ApfsAccess.Ipc;

namespace ApfsAccess.Tray.Tests;

public sealed class BoundContainerActionsTests
{
    [Fact] public void RealContainerControlsExposeBoundActionsAndRejectOldLeafOrDuplicateOwners()
    {
        Exception? failure=null;var thread=new Thread(()=>{try{
            WindowsFormsSynchronizationContext.AutoInstall=false;
            var status=OfflineImageFixTests.Status() with{ManagementJournalRootInspected=true};
            var rows=ContainerVerificationFixture.Rows(status);
            Assert.True(ContainerVolumeVerification.Capture(status,rows).Capability.IsAvailable);
            Assert.True(ContainerFixFlow.Capture(status,rows).Capability.IsAvailable);
            var selection=ContainerManagementSelection.Capture(status,rows);Assert.True(selection.Capability.IsAvailable);
            var selected=rows[1];var sent=0;
            using var form=new DashboardForm(_=>Task.CompletedTask,_=>Task.CompletedTask,_=>Task.CompletedTask,
                fixContainerAsync:_=>Task.CompletedTask,verifyContainerAsync:_=>Task.CompletedTask,
                manageVolumeAsync:row=>{Assert.Equal(selected.VolumeId,row.VolumeId);++sent;return Task.CompletedTask;});
            form.ApplyStatus(status);var tree=Get<TreeView>(form,"_topologyTree");
            IEnumerable<TreeNode> Nodes(TreeNodeCollection roots)=>roots.Cast<TreeNode>().SelectMany(n=>new[]{n}.Concat(Nodes(n.Nodes)));
            _=tree.Handle;tree.SelectedNode=Nodes(tree.Nodes).Single(n=>n.Tag is TopologyDashboardNode node&&node.Row is null&&node.Id.Contains("apfs-container:"));
            Assert.True(Get<Button>(form,"_containerVerifyButton").Enabled);Assert.True(Get<Button>(form,"_containerFixButton").Enabled);
            Assert.True(Get<Button>(form,"_containerManageButton").Enabled);
            form.DispatchContainerManagement(selection,selected.VolumeId);Assert.Equal(1,sent);
            var source=status.ConnectedInventory![0];var changed=status with{ConnectedInventory=[source with{Topology=source.Topology! with{
                Snapshot=source.Topology.Snapshot with{Containers=source.Topology.Snapshot.Containers.Select(c=>c with{CheckpointXid="91"}).ToArray(),
                Volumes=source.Topology.Snapshot.Volumes.Select(v=>v with{SuperblockXid="91"}).ToArray()}}}]};
            form.ApplyStatus(changed);
            Assert.Throws<InvalidOperationException>(()=>form.DispatchContainerManagement(selection,selected.VolumeId));Assert.Equal(1,sent);
            var owner=OfflineImageFixTests.Status(mounted:true).MountedVolumes![0];
            form.ApplyStatus(status with{MountedVolumes=[owner,owner]});
            Assert.False(Get<Button>(form,"_containerVerifyButton").Enabled);Assert.False(Get<Button>(form,"_containerFixButton").Enabled);
            Assert.False(Get<Button>(form,"_containerManageButton").Enabled);Assert.False(form.Visible);
        }catch(Exception e){failure=e;}});
        thread.SetApartmentState(ApartmentState.STA);thread.Start();thread.Join();
        if(failure is not null)System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(failure).Throw();
    }
    private static T Get<T>(object owner,string field)=>(T)owner.GetType().GetField(field,BindingFlags.Instance|BindingFlags.NonPublic)!.GetValue(owner)!;
}
