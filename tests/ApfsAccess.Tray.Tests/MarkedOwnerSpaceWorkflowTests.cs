using System.Reflection;
using System.Text.Json;
using System.Windows.Forms;
using ApfsAccess.Backend.Native;
using ApfsAccess.Tray;

namespace ApfsAccess.Tray.Tests;

public sealed class MarkedOwnerSpaceWorkflowTests
{
    [Fact] public async Task ChangedSelectionAndCancellationCannotPublishAcceptedOwnerAccounting()
    {
        var scope=MarkedReferenceSpaceWorkflowTests.TemporaryScope();var status=MarkedReferenceSpaceWorkflowTests.StatusFor(scope);
        var workflow=MarkedReferenceSpaceWorkflowTests.Workflow(scope,()=>status);
        var pending=new TaskCompletionSource<ApfsMarkedOwnerSpaceResult>(TaskCreationOptions.RunContinuationsAsynchronously);
        var client=new MarkedOwnerSpaceClient(true,(request,_)=>{Assert.Equal("18",request.FromXid);return pending.Task;});
        var run=workflow.ReadOwnerSpaceAsync(client,"18",default);
        status=MarkedReferenceSpaceWorkflowTests.StatusFor(scope with{CheckpointXid="21"});pending.SetResult(Unknown());
        await Assert.ThrowsAsync<InvalidOperationException>(()=>run);Assert.Null(workflow.OwnerSpaceSummary);
        status=MarkedReferenceSpaceWorkflowTests.StatusFor(scope);
        using var stop=new CancellationTokenSource();pending=new(TaskCreationOptions.RunContinuationsAsynchronously);
        run=workflow.ReadOwnerSpaceAsync(client,"18",stop.Token);stop.Cancel();Assert.False(run.IsCompleted);pending.SetResult(Unknown());
        await Assert.ThrowsAnyAsync<OperationCanceledException>(()=>run);Assert.Null(workflow.OwnerSpaceSummary);
        var unavailable=new MarkedOwnerSpaceClient(false,(_,_)=>throw new Exception("must not launch"));
        await Assert.ThrowsAsync<FileNotFoundException>(()=>workflow.ReadOwnerSpaceAsync(unavailable,"18",default));
    }
    [Fact] public void RealOwnerFormDisposalRetainsAcceptedWaitAndNoLateValues()=>MarkedReferenceSpaceDialogTests.OnSta(()=>{
        var scope=MarkedReferenceSpaceWorkflowTests.TemporaryScope();var status=MarkedReferenceSpaceWorkflowTests.StatusFor(scope);
        var workflow=MarkedReferenceSpaceWorkflowTests.Workflow(scope,()=>status);
        var pending=new TaskCompletionSource<ApfsMarkedOwnerSpaceResult>(TaskCreationOptions.RunContinuationsAsynchronously);CancellationToken accepted=default;
        var client=new MarkedOwnerSpaceClient(true,(_,token)=>{accepted=token;return pending.Task;});
        using var form=new VolumeSnapshotDialog(workflow,_=>throw new Exception("no browse"),ownerSpaceClient:client);
        var details=MarkedReferenceSpaceDialogTests.Field<TextBox>(form,"_ownerDetails");var changes=0;details.TextChanged+=(_,_)=>changes++;
        var run=Invoke(form);form.Dispose();var after=changes;
        Assert.True(accepted.IsCancellationRequested);Assert.False(run.IsCompleted);pending.SetResult(Unknown());run.GetAwaiter().GetResult();
        Assert.Null(workflow.OwnerSpaceSummary);Assert.Equal(after,changes);
    });
    internal static Task Invoke(VolumeSnapshotDialog form)=>(Task)typeof(VolumeSnapshotDialog)
        .GetMethod("ReadOwnerSpaceAsync",BindingFlags.Instance|BindingFlags.NonPublic)!.Invoke(form,[])!;
    private static ApfsMarkedOwnerSpaceResult Unknown()=>new(3,false,JsonSerializer.SerializeToElement(new{reason="unsupported retained owner"}));
}
