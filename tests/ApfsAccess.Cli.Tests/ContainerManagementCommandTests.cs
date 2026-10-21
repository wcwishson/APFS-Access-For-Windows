using ApfsAccess.Core;
using ApfsAccess.Ipc;

namespace ApfsAccess.Cli.Tests;

public sealed class ContainerManagementCommandTests
{
    [Fact] public async Task ExplicitContainerPlanAndApplyDispatchExistingLeafOperations()
    {
        var container=new string('a',32);var volume=ApfsTopology.BuildVolumeId(container,101);var count=0;
        var common=new[]{"--device-id",@"D:\private.apfs","--container-id",container,"--volume-id",volume,"--operation","rename-volume"};
        var exit=await ContainerManagementCommand.RunAsync(new[]{"container-manage","plan"}.Concat(common).ToArray(),(args,id)=>{
            ++count;Assert.Equal(container,id);var parsed=ManagementCommand.Parse(args);Assert.Equal("management-plan",parsed.Action);Assert.Equal(volume,parsed.VolumeId);
            return Task.FromResult(0);});Assert.Equal(0,exit);
        exit=await ContainerManagementCommand.RunAsync(new[]{"container-manage","apply"}.Concat(common).Concat(new[]{"--token","token","--image-path",@"D:\private.apfs","--name","--container-id"}).ToArray(),(args,id)=>{
            ++count;var parsed=ManagementCommand.Parse(args);Assert.Equal("management-apply",parsed.Action);Assert.Equal("--container-id",parsed.Name);Assert.Equal(container,id);
            return Task.FromResult(0);});Assert.Equal(0,exit);Assert.Equal(2,count);
    }

    [Fact] public void WrongContainerAndMalformedRequestsCannotReachExistingPlanner()
    {
        var a=new string('a',32);var b=new string('b',32);
        var target=new ApfsControlTarget(DeviceId:@"D:\private.apfs",VolumeId:ApfsTopology.BuildVolumeId(a,101),ContainerUuid:a);
        ManagementCommand.RequireContainerTarget(a,target);
        Assert.Throws<ArgumentException>(()=>ManagementCommand.RequireContainerTarget(b,target));
        Assert.Throws<ArgumentException>(()=>ManagementCommand.RequireContainerTarget(a,target with{ContainerUuid=null}));
        foreach(var extra in new[]{Array.Empty<string>(),new[]{"--container-id",a,"--container-id",b},new[]{"--container-id",new string('0',32)}})
            Assert.Throws<ArgumentException>(()=>ContainerManagementCommand.Translate(new[]{"container-manage","plan"}.Concat(extra).ToArray()));
    }

    [Fact] public async Task CancelledAndExpiredRequestsStopBeforeTheServiceConnection()
    {
        var args=new[]{"management-plan","--device-id",@"D:\private.apfs","--volume-id",ApfsTopology.BuildVolumeId(new string('a',32),101),"--operation","rename-volume"};
        using var stop=new CancellationTokenSource();stop.Cancel();
        Assert.Equal(5,await ManagementCommand.RunAsync(args,new string('a',32),stop.Token));
        Assert.Equal(5,await ManagementCommand.RunAsync(args,new string('a',32),operationDeadlineUtc:DateTimeOffset.UtcNow.AddSeconds(-1)));
    }
}
