using ApfsAccess.Ipc;

namespace ApfsAccess.Cli.Tests;

public sealed class ManagementCommandTests
{
    private const string DeviceId = "device-1";
    private const string VolumeId = "volume-1";

    [Fact]
    public void ParseOfflineVerifyAndSnapshotListCannotCarryMutationParameters()
    {
        foreach (var command in new[] { "volume-verify", "snapshot-list" })
        {
            string[] args = [command, "--device-id", @"D:\image.apfs", "--volume-id", @"D:\image.apfs|Main"];
            var options = ManagementCommand.Parse(args);
            Assert.Equal(command, options.Action); Assert.Null(options.Operation); Assert.Null(options.Token);
            Assert.Throws<ArgumentException>(() => ManagementCommand.Parse([..args, "--operation", "rename-volume"]));
            Assert.Throws<ArgumentException>(() => ManagementCommand.Parse([..args, "--image-path", @"D:\clone.apfs"]));
            Assert.True(ManagementCommand.Parse([..args, "--dry-run"]).DryRun);
        }
    }

    [Fact]
    public void ParsePlanRequiresDeviceVolumeAndOperation()
    {
        var options = ManagementCommand.Parse(
            ["management-plan", "--device-id", DeviceId, "--volume-id", VolumeId, "--operation", "rename-volume"]);
        Assert.Equal("management-plan", options.Action);
        Assert.Equal(DeviceId, options.DeviceId);
        Assert.Equal(VolumeId, options.VolumeId);
        Assert.Equal(ApfsManagementOperations.RenameVolume, options.Operation);
        Assert.Null(options.Token);
        Assert.False(options.DryRun);
        Assert.True(Guid.TryParseExact(options.OperationId, "D", out _));
    }

    [Fact]
    public void ParsePlanAcceptsQuotaOperation()
    {
        var options = ManagementCommand.Parse(
            ["management-plan", "--device-id", DeviceId, "--volume-id", VolumeId, "--operation", "set-quota-reserve"]);
        Assert.Equal(ApfsManagementOperations.SetQuotaReserve, options.Operation);
    }

    [Fact]
    public void ParsePlanRejectsUnknownOperationAndExtras()
    {
        Assert.Throws<ArgumentException>(() => ManagementCommand.Parse(
            ["management-plan", "--device-id", DeviceId, "--volume-id", VolumeId, "--operation", "format"]));
        Assert.Throws<ArgumentException>(() => ManagementCommand.Parse(
            ["management-plan", "--device-id", DeviceId, "--volume-id", VolumeId, "--operation", "rename-volume", "--token", "t"]));
        Assert.Throws<ArgumentException>(() => ManagementCommand.Parse(
            ["management-plan", "--device-id", DeviceId, "--operation", "rename-volume"]));
    }

    [Fact]
    public void ParseApplyRenameRequiresTokenNameAndImagePath()
    {
        var options = ManagementCommand.Parse(
            ["management-apply", "--device-id", DeviceId, "--volume-id", VolumeId, "--operation", "rename-volume",
                "--token", "token-1", "--name", "Data2", "--image-path", "C:\\img.apfs"]);
        Assert.Equal("management-apply", options.Action);
        Assert.Equal("token-1", options.Token);
        Assert.Equal("Data2", options.Name);
        Assert.Equal("C:\\img.apfs", options.ImagePath);
        Assert.Null(options.QuotaBytes);
    }

    [Fact]
    public void ParseApplyQuotaRequiresTokenImagePathAndBothValues()
    {
        var options = ManagementCommand.Parse(
            ["management-apply", "--device-id", DeviceId, "--volume-id", VolumeId, "--operation", "set-quota-reserve",
                "--token", "token-2", "--quota-bytes", "100", "--reserve-bytes", "50", "--image-path", "C:\\img.apfs"]);
        Assert.Equal("100", options.QuotaBytes);
        Assert.Equal("50", options.ReserveBytes);
        Assert.Equal("C:\\img.apfs", options.ImagePath);
        Assert.Null(options.Name);
    }

    [Fact]
    public void ParseApplyRejectsMixedParameters()
    {
        Assert.Throws<ArgumentException>(() => ManagementCommand.Parse(
            ["management-apply", "--device-id", DeviceId, "--volume-id", VolumeId, "--operation", "rename-volume",
                "--token", "t", "--name", "Data2", "--image-path", "C:\\img.apfs", "--quota-bytes", "1"]));
        Assert.Throws<ArgumentException>(() => ManagementCommand.Parse(
            ["management-apply", "--device-id", DeviceId, "--volume-id", VolumeId, "--operation", "set-quota-reserve",
                "--token", "t", "--quota-bytes", "100", "--reserve-bytes", "50", "--image-path", "C:\\img.apfs", "--name", "Data2"]));
        Assert.Throws<ArgumentException>(() => ManagementCommand.Parse(
            ["management-apply", "--device-id", DeviceId, "--volume-id", VolumeId, "--operation", "set-quota-reserve",
                "--token", "t", "--quota-bytes", "100", "--reserve-bytes", "50"]));
        Assert.Throws<ArgumentException>(() => ManagementCommand.Parse(
            ["management-apply", "--device-id", DeviceId, "--volume-id", VolumeId, "--operation", "rename-volume", "--token", "t", "--name", "Data2"]));
        Assert.Throws<ArgumentException>(() => ManagementCommand.Parse(
            ["management-apply", "--device-id", DeviceId, "--volume-id", VolumeId, "--operation", "rename-volume", "--name", "Data2", "--image-path", "C:\\img.apfs"]));
    }

    [Fact]
    public void ParseRejectsUnknownActionsAndBadOperationIds()
    {
        Assert.Throws<ArgumentException>(() => ManagementCommand.Parse(
            ["management", "--device-id", DeviceId, "--volume-id", VolumeId, "--operation", "rename-volume"]));
        Assert.Throws<ArgumentException>(() => ManagementCommand.Parse(
            ["management-plan", "--device-id", DeviceId, "--volume-id", VolumeId, "--operation", "rename-volume", "--operation-id", "not-a-guid"]));
    }

    [Fact]
    public void CommandNameEchoesCallerVerb()
    {
        Assert.Equal("management-plan", ManagementCommand.CommandName(["management-plan"]));
        Assert.Equal("management-apply", ManagementCommand.CommandName(["management-apply"]));
        Assert.Equal("management", ManagementCommand.CommandName(["bogus"]));
    }
}
