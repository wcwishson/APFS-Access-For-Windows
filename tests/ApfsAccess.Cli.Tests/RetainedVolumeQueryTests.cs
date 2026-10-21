using ApfsAccess.Core;
using ApfsAccess.Ipc;

namespace ApfsAccess.Cli.Tests;

public sealed class RetainedVolumeQueryTests
{
    [Fact]
    public void OrdinaryVolumeVerifyVerbCannotSelectPhysicalFixMetadataMode()
    {
        string[] args = ["volume-verify", "--device-id", @"D:\image.apfs", "--volume-id", "main"];
        Assert.Equal(ApfsControlCommands.VolumeVerify, ManagementCommand.Parse(args).Action);
        Assert.Throws<ArgumentException>(() => ManagementCommand.Parse(["volume-verify-metadata", ..args.Skip(1)]));
        Assert.Throws<ArgumentException>(() => ManagementCommand.Parse([..args, "--metadata-only"]));
    }

    [Theory]
    [InlineData("volume-verify")]
    [InlineData("snapshot-list")]
    public void MountedQueriesUseAdmittedInventoryAndRefuseMissingCache(string command)
    {
        var options = ManagementCommand.Parse([command, "--device-id", @"D:\image.apfs", "--volume-id", "main"]);
        var volume = new VolumeInfo("main", options.DeviceId, "Main", true);
        var device = new DeviceInventory(new(options.DeviceId, "Image", true), [volume]);
        var status = new StatusChangedPayload(RuntimeState.MountedRw, ["R:\\"], null, DateTime.UtcNow, [], false, [],
            ConnectedInventory: [device], MountedVolumes: [new("main", "R:\\", "Main", options.DeviceId, "Image", MountAccessMode.ReadWrite)]);
        PipeEnvelope Greeting(StatusChangedPayload value) => PipeMessageCodec.Create(ApfsMessageTypes.StatusChanged, value);
        Assert.Equal(device.Device.DeviceId, Assert.Single(ManagementCommand.RetainedQueryInventory(options, Greeting(status))!.Devices).Device.DeviceId);
        Assert.Throws<IOException>(() => ManagementCommand.RetainedQueryInventory(options, Greeting(status with { ConnectedInventory = null })));
        Assert.Null(ManagementCommand.RetainedQueryInventory(options, Greeting(status with { MountedVolumes = [] })));
    }
}
