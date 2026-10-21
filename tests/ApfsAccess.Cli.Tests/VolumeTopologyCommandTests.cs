using ApfsAccess.Ipc;

namespace ApfsAccess.Cli.Tests;

public sealed class VolumeTopologyCommandTests
{
    [Theory]
    [InlineData("grow")] [InlineData("shrink")] [InlineData("format")] [InlineData("erase")]
    public void PhysicalImagePlansAcceptOnlyCanonicalDeviceSyntaxWithoutCallerAuthority(string kind)
    {
        var format = kind is "format" or "erase";
        string[] Args(string device) => [format ? ApfsControlCommands.VolumeFormatPlan : ApfsControlCommands.VolumeResizePlan,
            "--device-id", device, "--volume-id", "selected", "--kind", kind,
            .. format ? new[] { "--name", "Fresh", "--case-sensitive", "false" } : new[] { "--target-bytes", "3145728" }];
        var valid = Args(@"\\.\PhysicalDrive2");
        Assert.Equal(@"\\.\PhysicalDrive2", ManagementCommand.Parse(valid).DeviceId);
        foreach (var device in new[] { @"\\.\PhysicalDrive02", @"\\.\PhysicalDrive-1", @"\\.\PhysicalDrive2\child", @"\\?\PhysicalDrive2" })
            Assert.Throws<ArgumentException>(() => ManagementCommand.Parse(Args(device)));
        foreach (var authority in new[] { "--physical-binding-hex", "--physical-device", "--oid", "--wal", "--xid" })
            Assert.Throws<ArgumentException>(() => ManagementCommand.Parse([.. valid, authority, "guess"]));
    }

    [Theory]
    [InlineData("grow")] [InlineData("shrink")] [InlineData("format")] [InlineData("erase")]
    public void ImageKeeperPlansHaveTypedOptionsAndNoCallerNativeAuthority(string kind)
    {
        var format = kind is "format" or "erase";
        string[] args = [format ? ApfsControlCommands.VolumeFormatPlan : ApfsControlCommands.VolumeResizePlan,
            "--device-id", @"D:\image.apfs", "--volume-id", "selected", "--kind", kind,
            .. format ? new[] { "--name", "Fresh", "--case-sensitive", "true" } : new[] { "--target-bytes", "3145728" }];
        var options = ManagementCommand.Parse(args); Assert.Equal(kind, options.VolumeManagement!.Kind);
        foreach (var authority in new[] { "--new-container", "--new-volume", "--new-wal", "--expected-bytes", "--journal-directory" })
            Assert.Throws<ArgumentException>(() => ManagementCommand.Parse([..args, authority, "guess"]));
    }
    [Fact]
    public void CreateRequiresExplicitOptionsAndDoesNotAcceptCallerOidUuidOrWalAuthority()
    {
        string[] args = [ApfsControlCommands.VolumeCreatePlan, "--device-id", @"D:\image.apfs", "--container-uuid", new string('a', 32),
            "--name", "Data", "--quota-bytes", "0", "--reserve-bytes", "0", "--case-sensitive", "false"];
        var parsed = ManagementCommand.Parse(args);
        Assert.Equal(new VolumeManagementParameters("create", "Data", "0", "0", false), parsed.VolumeManagement);
        Assert.Null(parsed.Token); Assert.Equal("", parsed.VolumeId);
        foreach (var option in new[] { "--oid", "--volume-uuid", "--wal", "--journal-directory", "--xid" })
            Assert.Throws<ArgumentException>(() => ManagementCommand.Parse([..args, option, "123"]));
        Assert.Throws<ArgumentException>(() => ManagementCommand.Parse(args[..^2]));
        Assert.Throws<ArgumentException>(() => ManagementCommand.Parse([..args[..^1], "yes"]));
    }
    [Fact]
    public void RecoveryUsesOriginalPlanQueryInsteadOfCurrentInventoryAuthority()
    {
        var plan = Guid.NewGuid().ToString("D");
        foreach (var command in new[] { ApfsControlCommands.VolumeManagementApply, ApfsControlCommands.VolumeManagementCancel, ApfsControlCommands.VolumeManagementRecover })
        {
            var options = ManagementCommand.Parse([command, "--plan-operation-id", plan]);
            Assert.Equal(plan, options.PlanOperationId); Assert.Null(options.VolumeManagement);
            Assert.Throws<ArgumentException>(() => ManagementCommand.Parse([command, "--plan-operation-id", plan, "--device-id", @"D:\clone.apfs"]));
        }
    }
    [Fact]
    public void DeleteCannotAcceptCreationValues()
    {
        string[] args = [ApfsControlCommands.VolumeDeletePlan, "--device-id", @"D:\image.apfs", "--volume-id", "selected"];
        Assert.Equal("delete", ManagementCommand.Parse(args).VolumeManagement!.Kind);
        Assert.Throws<ArgumentException>(() => ManagementCommand.Parse([..args, "--name", "Data"]));
        Assert.Equal("delete", ManagementCommand.Parse([ApfsControlCommands.VolumeDeletePlan, "--device-id", @"\\.\PhysicalDrive42", "--volume-id", "selected"]).VolumeManagement!.Kind);
    }

    [Theory]
    [InlineData("create")] [InlineData("delete")]
    public void PhysicalTopologyUsesSelectedDeviceButNeverCallerNativeAuthority(string kind)
    {
        string[] Args(string device) => kind == "create" ?
            [ApfsControlCommands.VolumeCreatePlan, "--device-id", device, "--container-uuid", new string('a', 32),
                "--name", "Peer", "--quota-bytes", "0", "--reserve-bytes", "0", "--case-sensitive", "false"] :
            [ApfsControlCommands.VolumeDeletePlan, "--device-id", device, "--volume-id", "selected"];
        var valid = Args(@"\\.\PhysicalDrive42");
        Assert.Equal(kind, ManagementCommand.Parse(valid).VolumeManagement!.Kind);
        foreach (var device in new[] { @"\\.\PhysicalDrive042", @"\\.\PhysicalDrive-1", @"\\.\PhysicalDrive42\child", @"\\?\PhysicalDrive42" })
            Assert.Throws<ArgumentException>(() => ManagementCommand.Parse(Args(device)));
        foreach (var authority in new[] { "--physical-binding-hex", "--physical-device", "--oid", "--wal", "--xid", "--volume-uuid", "--journal-directory" })
            Assert.Throws<ArgumentException>(() => ManagementCommand.Parse([.. valid, authority, "guess"]));
    }
}
