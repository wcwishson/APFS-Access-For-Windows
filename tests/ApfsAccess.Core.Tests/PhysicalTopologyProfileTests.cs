using ApfsAccess.Core;

namespace ApfsAccess.Core.Tests;

public sealed class PhysicalTopologyProfileTests
{
    private static DeviceInventory Inventory(ulong? blocks = 32768, long? blockBytes = 4096, long partitionBytes = 128111046656)
    {
        const string device = @"\\.\PhysicalDrive42", container = "aaaaaaaa000040008000000000000001", volume = "bbbbbbbb000040008000000000000001";
        var cid = ApfsTopology.BuildContainerId(container); var vid = ApfsTopology.BuildVolumeId(container, 101);
        var row = new VolumeInfo(vid, device, "Peer", true, CatalogVolumeId: vid, CatalogContainerUuid: container,
            CatalogVolumeUuid: volume, CatalogVolumeObjectId: 101);
        var graph = new ApfsTopologySnapshot([new("apfs-disk:test", device, null, 128320801792)], [],
            [new("apfs-store:test", container, "", cid, 209735680, partitionBytes, blockBytes, blocks, "apfs-disk:test")],
            [new(cid, container, 4096, ["apfs-store:test"], [vid], false, "19", [], [], [])],
            [new(vid, volume, "101", cid, "Peer", true, ["data"], 64, null, "sensitive", "none", false, [], [], [], "7", "19")], []);
        return new(new(device, "Fictional selected device", true), [row], new(1, device, ["apfs-disk:test"], graph));
    }

    [Theory]
    [InlineData(32768UL, "134217728")] [InlineData(262144UL, "1073741824")]
    public void PhysicalScopeUsesApfsPrefixAndPreservesPartition(ulong blocks, string expected)
    {
        var inventory = Inventory(blocks); var row = inventory.Volumes[0];
        var result = VolumeTopologyProfile.DeriveManagementScope(inventory, row, "format");
        Assert.True(result.Ok, result.Detail); Assert.Equal(expected, result.Scope!.StoreSizeBytes);
        Assert.Equal("209735680", result.Scope.StoreOffsetBytes);
        Assert.Equal(128111046656, inventory.Topology!.Snapshot.Stores[0].SizeBytes);
        Assert.False(VerifyScopeDerivation.TryDerive(inventory, row).Ok);
    }

    [Theory]
    [InlineData(null, 4096L, 128111046656)] [InlineData(0UL, 4096L, 128111046656)]
    [InlineData(255UL, 4096L, 128111046656)]
    [InlineData(32768UL, null, 128111046656)] [InlineData(32768UL, 2048L, 128111046656)]
    [InlineData(32768UL, 4096L, 67108864L)] [InlineData(ulong.MaxValue, 4096L, long.MaxValue)]
    [InlineData(268435457UL, 4096L, 2199023255552)]
    public void PhysicalScopeRefusesMissingContradictoryOrOverflowGeometry(ulong? blocks, long? unit, long partitionBytes)
    {
        var inventory = Inventory(blocks, unit, partitionBytes);
        var result = VolumeTopologyProfile.DeriveManagementScope(inventory, inventory.Volumes[0], "format");
        Assert.False(result.Ok); Assert.Equal(VerifyScopeDerivation.InvalidGeometry, result.Code); Assert.Null(result.Scope);
    }

    [Theory]
    [InlineData("create", 1048576UL, true)] [InlineData("delete", 268435456UL, true)]
    [InlineData("create", 268439552UL, false)] [InlineData("delete", 1073741824UL, false)]
    [InlineData("create", 1048575UL, false)] [InlineData("delete", 134217729UL, false)]
    public void TopologyHasIndependentBoundedPhysicalProfile(string operation, ulong bytes, bool admitted)
    {
        var scope = new VerifyScope(ImagePath: @"\\.\PhysicalDrive42", ContainerId: "apfs-container:" + new string('a', 32),
            VolumeUuid: new string('b', 32), VolumeObjectId: "101", CheckpointXid: "7", StoreOffsetBytes: "1048576", StoreSizeBytes: bytes.ToString());
        Assert.Equal(admitted, VolumeTopologyProfile.IsPhysicalTopology(scope, operation));
        Assert.Equal(admitted, VolumeTopologyProfile.IsPhysicalManagement(scope, operation));
        Assert.False(VolumeTopologyProfile.IsStreamedImage(scope, operation));
        Assert.False(VolumeTopologyProfile.IsPhysicalTopology(scope with { ImagePath = @"D:\image.apfs" }, operation));
        Assert.False(VolumeTopologyProfile.IsPhysicalTopology(scope with { StoreOffsetBytes = "1048577" }, operation));
    }
}
