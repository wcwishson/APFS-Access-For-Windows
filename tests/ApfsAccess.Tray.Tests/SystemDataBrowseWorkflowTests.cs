using System.Text.Json;
using System.Text.Json.Nodes;
using System.Windows.Forms;
using System.Reflection;
using ApfsAccess.Backend.Native;
using ApfsAccess.Core;
using ApfsAccess.Ipc;

namespace ApfsAccess.Tray.Tests;

public sealed class SystemDataBrowseWorkflowTests : IDisposable
{
    private readonly string folder=Path.Combine(Path.GetTempPath(),"system-data-gui-"+Guid.NewGuid().ToString("N"));
    private static readonly JsonSerializerOptions Options=new(){PropertyNamingPolicy=JsonNamingPolicy.CamelCase};
    internal sealed class Child : ISnapshotBrowseProcess
    {
        private readonly TaskCompletionSource<SnapshotBrowseExit> terminal=new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly TaskCompletionSource CloseRequested=new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal int Closes;
        public Task<SnapshotBrowseExit> Completion=>terminal.Task;
        public Task CloseAsync(){++Closes;CloseRequested.TrySetResult();return Task.CompletedTask;}
        internal void Release(SnapshotBrowseExit result)=>terminal.TrySetResult(result);
        public void Dispose(){}
    }
    private SystemDataBrowseSelection Selection()
    {
        Directory.CreateDirectory(folder);var image=Path.Combine(folder,"pair.apfs");
        if(!File.Exists(image))File.WriteAllBytes(image,new byte[8192]);
        using var held=NativeSystemDataBrowseLaunch.Prepare(image,"apfs-container:"+new string('a',32),new string('d',32),"101","102","20");
        return held.Selection;
    }
    internal static StatusChangedPayload Offline()=>new(RuntimeState.Idle,[],null,DateTime.UtcNow,[],false,[],MountedVolumes:[],ConnectedInventory:[]);
    private SystemDataBrowseRequest Request(SystemDataBrowseSelection s,bool copying=false)=>new(s,
        Path.Combine(folder,Guid.NewGuid().ToString("N")),copying?Path.Combine(folder,"copy-"+Guid.NewGuid().ToString("N")):null);
    internal static JsonElement Ready(SystemDataBrowseRequest q,string id)=>JsonSerializer.SerializeToElement(new{
        operationId=id,mountPoint=Path.Combine(q.SessionDirectory,"mount"),selection=q.Selection,
        imageDerivedAdmission=true,capability=NativeSystemDataBrowseLaunch.Capability},Options);
    internal static SnapshotBrowseExit Terminal(SystemDataBrowseRequest q,string id,bool teardown=true)=>new(0,JsonSerializer.Serialize(new{
        schemaVersion=2,command="system-data-browse",operationId=id,success=true,exitCode=0,error=(string?)null,
        mountPoint=Path.Combine(q.SessionDirectory,"mount"),sessionDirectory=q.SessionDirectory,nativeAdmissionProven=true,
        selection=q.Selection,capability=NativeSystemDataBrowseLaunch.Capability,
        copyOut=q.CopyOut is null?null:new{files=4,directories=5,bytes=781},teardownProven=teardown,
        supervisorEvidence=Path.Combine(q.SessionDirectory,"supervisor.json")},Options),"");

    [Fact] public async Task SourceAndOfflineChangesRejectBeforeAChildAndProtocolRejectsForeignPair()
    {
        var s=Selection();var started=0;var client=new SystemDataBrowseClient(_=>{++started;throw new Exception("No child may start.");});
        await Assert.ThrowsAsync<InvalidDataException>(()=>client.RunAsync(Request(s with{SourceSha256=new string('f',64)}),_=>{},()=>{},default));
        var status=Offline() with{MountedVolumes=[new("pair","R:\\","System",s.Image,"Image",MountAccessMode.ReadOnly)]};
        await Assert.ThrowsAsync<InvalidOperationException>(()=>client.RunAsync(Request(s),_=>{},()=>SystemDataBrowseWorkflow.RequireOffline(status,true,s),default));
        Assert.Throws<InvalidOperationException>(()=>SystemDataBrowseWorkflow.RequireOffline(Offline(),false,s));
        using var stop=new CancellationTokenSource();stop.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(()=>client.RunAsync(Request(s),_=>{},()=>{},stop.Token));Assert.Equal(0,started);
        var q=Request(s,true);var id=Guid.NewGuid().ToString("D");
        Action<JsonObject>[] faults=[x=>x["selection"]!["groupUuid"]=new string('e',32),x=>x["selection"]!["systemOid"]="102",
            x=>x["selection"]!["dataOid"]="103",x=>x["selection"]!["checkpointXid"]="19",x=>x["selection"]!["sourceSha256"]=new string('f',64),
            x=>x["operationId"]=Guid.NewGuid().ToString("D"),x=>x["teardownProven"]=false,x=>x["nativeAdmissionProven"]=false,
            x=>x["capability"]!["unifiedMutations"]=true,x=>x["sessionDirectory"]=Path.Combine(folder,"foreign")];
        foreach(var fault in faults){var root=JsonNode.Parse(Terminal(q,id).StandardOutput)!.AsObject();fault(root);
            Assert.Throws<SystemDataBrowseException>(()=>SystemDataBrowseProtocol.Terminal(new(0,root.ToJsonString(),""),q,id,false));}
        var amounts=SystemDataBrowseProtocol.Terminal(Terminal(q,id),q,id,false);Assert.Equal(4,amounts.Files);Assert.Equal(q.CopyOut,amounts.Destination);
        using var selector=new MemoryStream(System.Text.Encoding.UTF8.GetBytes(JsonSerializer.Serialize(s,Options)));
        Assert.Equal(s,SystemDataBrowseWorkflow.ReadSelection(selector));
        var args=SystemDataBrowseClient.StartInfo(q,"cli.exe").ArgumentList.ToArray();
        Assert.Contains("--close-on-stdin",args);Assert.Contains(s.GroupUuid,args);Assert.Contains(s.SystemOid,args);Assert.Contains(s.DataOid,args);Assert.DoesNotContain("--readwrite",args);
    }

    [Fact] public async Task CancellationRetainsSourceAndAcceptedChildUntilConfirmedRetirement()
    {
        var s=Selection();var q=Request(s);var child=new Child();var id=Guid.NewGuid().ToString("D");
        var ready=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var client=new SystemDataBrowseClient(_=>child,_=>Ready(q,id));using var stop=new CancellationTokenSource();
        var pending=client.RunAsync(q,_=>ready.SetResult(),()=>{},stop.Token);await ready.Task;stop.Cancel();await child.CloseRequested.Task;
        Assert.False(pending.IsCompleted);
        Assert.Throws<IOException>(()=>File.OpenHandle(s.Image,FileMode.Open,FileAccess.Write,FileShare.ReadWrite));
        child.Release(Terminal(q,id));await Assert.ThrowsAsync<SystemDataBrowseCancelledException>(()=>pending);
        using(File.OpenHandle(s.Image,FileMode.Open,FileAccess.Write,FileShare.Read)){}
    }

    [Fact] public async Task AcceptedOperationRejectsCheckpointDisconnectOrMountedSiblingBeforePublishingCopy()
    {
        var s=Selection();
        var scope=new VerifyScope(s.Image,"apfs-container:"+s.ContainerUuid,new string('b',32),s.SystemOid,
            s.CheckpointXid,"0",s.SourceSizeBytes.ToString(System.Globalization.CultureInfo.InvariantCulture));
        StatusChangedPayload Status(VerifyScope value)=>MarkedReferenceSpaceWorkflowTests.StatusFor(value) with{MountedVolumes=[]};
        foreach(var drift in new[]{"checkpoint","disconnected","mounted-sibling"})
        {
            var status=Status(scope);var connected=true;var q=Request(s,true);var child=new Child();
            var id=Guid.NewGuid().ToString("D");
            var ready=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var client=new SystemDataBrowseClient(_=>child,_=>{ready.TrySetResult();return Ready(q,id);});
            var pending=client.RunAsync(q,_=>throw new Exception("Copy must not open Explorer."),
                ()=>SystemDataBrowseWorkflow.RequireOffline(status,connected,s),default);
            await ready.Task.WaitAsync(TimeSpan.FromSeconds(10));
            if(drift=="checkpoint")status=Status(scope with{CheckpointXid="21"});
            else if(drift=="disconnected")connected=false;
            else status=status with{MountedVolumes=[new("peer-volume","R:\\","Data",s.Image,"Image",MountAccessMode.ReadOnly)]};
            await child.CloseRequested.Task.WaitAsync(TimeSpan.FromSeconds(10));
            Assert.False(pending.IsCompleted);
            Assert.Throws<IOException>(()=>File.OpenHandle(s.Image,FileMode.Open,FileAccess.Write,FileShare.ReadWrite));
            child.Release(Terminal(q,id));
            var failure=await Assert.ThrowsAsync<SystemDataBrowseException>(()=>pending);
            Assert.True(failure.TeardownConfirmed);
            Assert.Contains(drift=="checkpoint"?"checkpoint":drift=="disconnected"?"Reconnect":"Unmount",failure.Message);
            using(File.OpenHandle(s.Image,FileMode.Open,FileAccess.Write,FileShare.Read)){}
        }
    }

    [Fact] public void DisposedProductionFormKeepsPendingClosureAndNeverPublishesLateResult()=>Sta(()=>
    {
        var context=new HeadlessContextForSystemData();SynchronizationContext.SetSynchronizationContext(context);
        var s=Selection();var held=NativeSystemDataBrowseLaunch.Prepare(s.Image,"apfs-container:"+s.ContainerUuid,s.GroupUuid,s.SystemOid,s.DataOid,s.CheckpointXid);
        var child=new Child();SystemDataBrowseRequest? request=null;var id=Guid.NewGuid().ToString("D");
        var ready=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var client=new SystemDataBrowseClient(q=>{request=q;return child;},_=>request is null?null:Ready(request,id));
        using var form=new SystemDataBrowseDialog(new(held,_=>{}),_=>ready.TrySetResult(),client);
        var running=form.RunAsync(false);context.Wait(ready.Task);form.Dispose();context.Wait(child.CloseRequested.Task);
        Assert.False(running.IsCompleted);Assert.NotNull(form.Pending);Assert.False(form.Pending!.IsCompleted);
        Assert.Throws<IOException>(()=>File.OpenHandle(s.Image,FileMode.Open,FileAccess.Write,FileShare.ReadWrite));
        child.Release(Terminal(request!,id));context.Wait(running);Assert.True(form.IsDisposed);Assert.True(form.Pending.IsCompleted);
        using(File.OpenHandle(s.Image,FileMode.Open,FileAccess.Write,FileShare.Read)){}
    });

    [Fact] public void UnconfirmedClosureDisablesAnotherProductionOperation()=>Sta(()=>
    {
        var context=new HeadlessContextForSystemData();SynchronizationContext.SetSynchronizationContext(context);
        var s=Selection();var held=NativeSystemDataBrowseLaunch.Prepare(s.Image,"apfs-container:"+s.ContainerUuid,s.GroupUuid,s.SystemOid,s.DataOid,s.CheckpointXid);
        var starts=0;var client=new SystemDataBrowseClient(q=>{++starts;var child=new Child();child.Release(Terminal(q,Guid.NewGuid().ToString("D"),false));return child;});
        using var form=new SystemDataBrowseDialog(new(held,_=>{}),_=>throw new Exception("Unconfirmed work must not open Explorer."),client);
        context.Wait(form.RunAsync(false));
        var label=(Label)typeof(SystemDataBrowseDialog).GetField("status",BindingFlags.Instance|BindingFlags.NonPublic)!.GetValue(form)!;
        Assert.Contains("unconfirmed",label.Text);Assert.False(((Button)typeof(SystemDataBrowseDialog).GetField("browse",BindingFlags.Instance|BindingFlags.NonPublic)!.GetValue(form)!).Enabled);
        context.Wait(form.RunAsync(false));Assert.Equal(1,starts);
    });

    private static void Sta(Action body)
    {
        Exception? failure=null;var thread=new Thread(()=>{try{WindowsFormsSynchronizationContext.AutoInstall=false;body();}catch(Exception ex){failure=ex;}});
        thread.SetApartmentState(ApartmentState.STA);thread.Start();thread.Join();
        if(failure is not null)System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(failure).Throw();
    }
    private sealed class HeadlessContextForSystemData : SynchronizationContext
    {
        private readonly System.Collections.Concurrent.ConcurrentQueue<(SendOrPostCallback,object?)> queue=new();
        public override void Post(SendOrPostCallback callback,object? state)=>queue.Enqueue((callback,state));
        internal void Wait(Task task){while(!task.IsCompleted){while(queue.TryDequeue(out var item))item.Item1(item.Item2);Thread.Sleep(1);}task.GetAwaiter().GetResult();}
    }
    public void Dispose(){if(Directory.Exists(folder))Directory.Delete(folder,true);}
}
