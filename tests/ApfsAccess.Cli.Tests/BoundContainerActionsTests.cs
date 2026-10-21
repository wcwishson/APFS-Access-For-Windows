using System.Text.Json;
using ApfsAccess.Core;
using ApfsAccess.Ipc;

namespace ApfsAccess.Cli.Tests;

public sealed class BoundContainerActionsTests
{
    [Fact] public void PrivateManagementEndpointUsesExistingInstancePolicyAndPreservesLiteralValues()
    {
        var id=Guid.Parse("01234567-89ab-cdef-0123-456789abcdef");var common=new[]{"container-manage","apply","--device-id",CliContainerVerificationFixture.Image,
            "--container-id",CliContainerVerificationFixture.Hex,"--volume-id",ApfsTopology.BuildVolumeId(CliContainerVerificationFixture.Hex,101),
            "--operation","rename-volume","--token","token","--image-path",CliContainerVerificationFixture.Image,"--name","--private-instance"};
        var normal=ContainerManagementCommand.Translate(common);Assert.Null(normal.PrivateInstance);
        var selected=ContainerManagementCommand.Translate(common.Concat(new[]{"--private-instance",id.ToString("D")}).ToArray());
        Assert.Equal(id,selected.PrivateInstance);Assert.Equal(normal.LeafArguments,selected.LeafArguments);
        Assert.True(FusionControlEndpoint.IsPrivateInstance(FusionControlEndpoint.ForPrivateInstance(selected.PrivateInstance!.Value)));
        foreach(var value in new[]{Guid.Empty.ToString("D"),id.ToString("N"),id.ToString("D").ToUpperInvariant(),"arbitrary-pipe"})
            Assert.Throws<ArgumentException>(()=>ContainerManagementCommand.Translate(common.Concat(new[]{"--private-instance",value}).ToArray()));
        Assert.Throws<ArgumentException>(()=>ContainerManagementCommand.Translate(common.Concat(new[]{"--private-instance",id.ToString("D"),"--private-instance",id.ToString("D")}).ToArray()));
    }

    [Fact] public async Task NormalContainerCommandStillDispatchesExactMembersAndEmitsExistingEnvelope()
    {
        var status=CliContainerVerificationFixture.Status(live:false);var client=new FakeContainerVerificationClient(status);
        var previous=Console.Out;using var output=new StringWriter();Console.SetOut(output);int exit;
        try{exit=await ContainerCommand.RunAsync(["container-verify","--device-id",CliContainerVerificationFixture.Image,
            "--container-id",CliContainerVerificationFixture.Hex],client);}finally{Console.SetOut(previous);}
        Assert.Equal(0,exit);Assert.Equal(2,client.Requests.Count);
        Assert.Equal(status.ConnectedInventory![0].Volumes.Select(v=>v.VolumeId),client.Requests.Select(r=>r.Target!.VolumeId));
        Assert.All(client.Requests,r=>{Assert.Equal(ApfsControlCommands.VolumeVerify,r.Command);
            Assert.True(SelectedControlTarget.Matches(status.ConnectedInventory,r.Target!));});
        using var json=JsonDocument.Parse(output.ToString());var root=json.RootElement;
        Assert.Equal(2,root.GetProperty("schemaVersion").GetInt32());Assert.Equal("client-batch",root.GetProperty("execution").GetString());
        Assert.False(root.GetProperty("atomicContainerVerification").GetBoolean());Assert.Equal(2,root.GetProperty("verified").GetInt32());
        Assert.Equal(new[]{"atomicContainerVerification","batchId","childCommand","code","command","diagnostic","dryRun","execution",
            "exitCode","inspectionOnly","operationId","operationIssued","schemaVersion","scope","success","verified","volumes"},
            root.EnumerateObject().Select(p=>p.Name).Order(StringComparer.Ordinal));
    }

    [Fact] public void OfflineLeafRejectsCheckpointDriftBetweenGreetingAndFreshInventory()
    {
        var status=CliContainerVerificationFixture.Status(live:false) with{ManagementJournalRootInspected=true};
        var source=status.ConnectedInventory![0];var target=SelectedControlTarget.Create(source,source.Volumes[1]);
        Assert.True(BoundContainerActions.RequireOfflineMember(status,target,status.ConnectedInventory).IsAvailable);
        var changed=source with{Topology=source.Topology! with{Snapshot=source.Topology.Snapshot with{
            Containers=source.Topology.Snapshot.Containers.Select(c=>c with{CheckpointXid="91"}).ToArray(),
            Volumes=source.Topology.Snapshot.Volumes.Select(v=>v with{SuperblockXid="91"}).ToArray()}}};
        // The legacy observation contract deliberately excludes the rolling XID.
        Assert.Equal(target.ObservationContract,SelectedControlTarget.Create(changed,changed.Volumes[1]).ObservationContract);
        Assert.Throws<InvalidOperationException>(()=>BoundContainerActions.RequireOfflineMember(status,target,[changed]));
        Assert.Throws<InvalidOperationException>(()=>BoundContainerActions.RequireOfflineMember(status with{ManagementJournalRootInspected=false},target,status.ConnectedInventory));
        var mounted=CliContainerVerificationFixture.Status(live:true) with{ManagementJournalRootInspected=true};
        Assert.Throws<InvalidOperationException>(()=>BoundContainerActions.RequireOfflineMember(mounted,target,mounted.ConnectedInventory!));
        Assert.Throws<InvalidOperationException>(()=>BoundContainerActions.RequireOfflineMember(status,target with{VolumeId="foreign"},status.ConnectedInventory));
        Assert.Throws<InvalidOperationException>(()=>BoundContainerActions.RequireOfflineMember(status,target,[source,source]));
    }
}
