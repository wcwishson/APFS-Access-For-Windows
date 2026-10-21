using ApfsAccess.Core;

namespace ApfsAccess.Core.Tests;

// Task 10 Step 5: the offline-verify scope binds every tool field to
// observed inventory records. These pins prove exact derivation on a
// complete single-store topology and typed refusal for every
// incomplete, multi-store, physical, Fusion, or unobservable shape.
public sealed class VerifyScopeDerivationTests
{
    private const string Device = @"D:\images\disk.apfs.img";
    private const string Volume = @"D:\images\disk.apfs.img|Main";
    private const string ContainerHex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    private const string VolumeHex = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    private const string DiskId = "apfs-disk:test";
    private const string PartitionUuid = "11111111-2222-3333-4444-555555555555";

    private static string ContainerId => "apfs-container:" + ContainerHex;
    private static string StoreId => "apfs-store:" + PartitionUuid;
    private static string VolumeId => $"apfs-vol:{ContainerHex}:101";

    private static VolumeInfo Row(
        string? deviceId = Device,
        string? containerUuid = ContainerHex,
        string? volumeUuid = VolumeHex,
        ulong? oid = 101)
        => new(Volume, deviceId!, "Main", SupportsReadWrite: true,
            CatalogVolumeId: VolumeId,
            CatalogContainerUuid: containerUuid,
            CatalogVolumeObjectId: oid,
            CatalogVolumeUuid: volumeUuid);

    private static DeviceInventory Inventory(
        string xid = "90",
        bool fusion = false,
        IReadOnlyList<string>? storeIds = null,
        long offset = 1048576,
        long size = 100000000,
        bool topology = true)
    {
        var device = new DeviceInfo(Device, "Test image", true);
        var row = Row();
        if (!topology) return new(device, [row]);
        var partitionId = "apfs-part:" + PartitionUuid;
        var container = new ApfsContainerRecord(ContainerId, ContainerHex, 4096,
            storeIds ?? [StoreId], [VolumeId], fusion, xid, [], [], []);
        var snapshot = new ApfsTopologySnapshot(
            [new ApfsDiskRecord(DiskId, Device, null, 200000000000)],
            [new ApfsPartitionRecord(partitionId, PartitionUuid, DiskId, 1, 0, 100000000000,
                "7C3457EF-0000-11AA-AA11-00306543ECAC", "Apple_APFS")],
            [new ApfsStoreRecord(StoreId, ContainerHex, partitionId, ContainerId, offset, size, 4096, null, null)],
            [container],
            [new ApfsVolumeRecord(VolumeId, VolumeHex, "101", ContainerId, "Main", true,
                ["data"], 64, null, "CaseSensitive", "none", false, [], [], [], "7", xid)],
            []);
        return new(device, [row],
            new ApfsDiscoveryTopology(1, Device, [DiskId], snapshot));
    }

    [Fact]
    public void Derive_RejectsContradictorySourceAndMembership()
    {
        var d = Inventory(); var t = d.Topology!;
        foreach (var changed in new[] {
            d with { Device = d.Device with { DeviceId = @"D:\other.apfs" } },
            d with { Topology = t with { DeviceId = @"D:\other.apfs" } },
            d with { Volumes = [Row(), Row()] },
            d with { Topology = t with { Snapshot = t.Snapshot with { Containers = [t.Snapshot.Containers[0], t.Snapshot.Containers[0]] } } },
            d with { Topology = t with { Snapshot = t.Snapshot with { Volumes = [t.Snapshot.Volumes[0] with { ObjectId = "102" }] } } },
            d with { Topology = t with { Snapshot = t.Snapshot with { Containers = [t.Snapshot.Containers[0] with { VolumeIds = [] }] } } }
        }) Assert.False(VerifyScopeDerivation.TryDerive(changed, Row()).Ok);
    }

    [Fact]
    public void Derive_NullInputs_Throw()
    {
        Assert.Throws<ArgumentNullException>(() => VerifyScopeDerivation.TryDerive(null!, Row()));
        Assert.Throws<ArgumentNullException>(() => VerifyScopeDerivation.TryDerive(Inventory(), null!));
    }

    [Fact]
    public void Derive_CompleteSingleStore_BindsEveryField()
    {
        var verdict = VerifyScopeDerivation.TryDerive(Inventory(), Row());
        Assert.True(verdict.Ok, verdict.Detail);
        Assert.Equal(VerifyScopeDerivation.Derived, verdict.Code);
        Assert.NotNull(verdict.Scope);
        var scope = verdict.Scope!;
        Assert.Equal(Device, scope.ImagePath);
        Assert.Equal(ContainerId, scope.ContainerId);
        Assert.Equal(VolumeHex, scope.VolumeUuid);
        Assert.Equal("101", scope.VolumeObjectId);
        Assert.Equal("90", scope.CheckpointXid);
        Assert.Equal("1048576", scope.StoreOffsetBytes);
        Assert.Equal("100000000", scope.StoreSizeBytes);
    }

    [Fact]
    public void Derive_ZeroOffset_Accepted()
    {
        var verdict = VerifyScopeDerivation.TryDerive(Inventory(offset: 0), Row());
        Assert.True(verdict.Ok, verdict.Detail);
        Assert.NotNull(verdict.Scope);
        Assert.Equal("0", verdict.Scope!.StoreOffsetBytes);
    }

    [Fact]
    public void Derive_MissingTopology_Refused()
    {
        var verdict = VerifyScopeDerivation.TryDerive(Inventory(topology: false), Row());
        Assert.False(verdict.Ok);
        Assert.Equal(VerifyScopeDerivation.NoTopology, verdict.Code);
        Assert.Null(verdict.Scope);
    }

    [Theory]
    [InlineData(@"\\.\PhysicalDrive2")]
    [InlineData(@"\\?\PhysicalDrive2")]
    [InlineData(@"\\?\GLOBALROOT\Device\HarddiskVolume1")]
    public void Derive_PhysicalTarget_Refused(string deviceId)
    {
        var verdict = VerifyScopeDerivation.TryDerive(Inventory(), Row(deviceId));
        Assert.False(verdict.Ok);
        Assert.Equal(VerifyScopeDerivation.PhysicalTarget, verdict.Code);
    }

    [Theory]
    [InlineData("device-1")]
    [InlineData(@"\\server\share\disk.apfs.img")]
    [InlineData(@"D:\image.apfs.img:stream")]
    public void Derive_NonImageTarget_Refused(string deviceId)
    {
        var verdict = VerifyScopeDerivation.TryDerive(Inventory(), Row(deviceId));
        Assert.False(verdict.Ok);
        Assert.Equal(VerifyScopeDerivation.NonImageTarget, verdict.Code);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Derive_MissingDeviceIdentity_Refused(string? deviceId)
    {
        var verdict = VerifyScopeDerivation.TryDerive(Inventory(), Row(deviceId!));
        Assert.False(verdict.Ok);
        Assert.Equal(VerifyScopeDerivation.InvalidTarget, verdict.Code);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Derive_MissingRowIdentity_Refused(string? uuid)
    {
        var verdict = VerifyScopeDerivation.TryDerive(
            Inventory(), Row(containerUuid: uuid, volumeUuid: uuid));
        Assert.False(verdict.Ok);
        Assert.Equal(VerifyScopeDerivation.IdentityIncomplete, verdict.Code);
    }

    [Theory]
    [InlineData("not-a-guid")]
    [InlineData("00000000-0000-0000-0000-000000000000")]
    [InlineData("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz")]
    public void Derive_MalformedVolumeUuid_Refused(string uuid)
    {
        var verdict = VerifyScopeDerivation.TryDerive(Inventory(), Row(volumeUuid: uuid));
        Assert.False(verdict.Ok);
        Assert.Equal(VerifyScopeDerivation.IdentityIncomplete, verdict.Code);
    }

    [Theory]
    [InlineData("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")]
    [InlineData("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")]
    [InlineData("{BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB}")]
    public void Derive_NonCanonicalVolumeUuid_Normalized(string uuid)
    {
        var verdict = VerifyScopeDerivation.TryDerive(Inventory(), Row(volumeUuid: uuid));
        Assert.True(verdict.Ok, verdict.Detail);
        Assert.NotNull(verdict.Scope);
        Assert.Equal(VolumeHex, verdict.Scope!.VolumeUuid);
    }

    [Fact]
    public void Derive_ZeroObjectId_Refused()
    {
        var verdict = VerifyScopeDerivation.TryDerive(Inventory(), Row(oid: 0));
        Assert.False(verdict.Ok);
        Assert.Equal(VerifyScopeDerivation.IdentityIncomplete, verdict.Code);
    }

    [Fact]
    public void Derive_ContainerUnresolved_Refused()
    {
        var verdict = VerifyScopeDerivation.TryDerive(
            Inventory(), Row(containerUuid: new string('c', 32)));
        Assert.False(verdict.Ok);
        Assert.Equal(VerifyScopeDerivation.ContainerUnresolved, verdict.Code);
    }

    [Fact]
    public void Derive_FusionContainer_Refused()
    {
        var verdict = VerifyScopeDerivation.TryDerive(Inventory(fusion: true), Row());
        Assert.False(verdict.Ok);
        Assert.Equal(VerifyScopeDerivation.FusionContainer, verdict.Code);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(2)]
    public void Derive_NonSingleStore_Refused(int stores)
    {
        var ids = Enumerable.Range(0, stores).Select(i => $"apfs-store:s{i}").ToArray();
        var verdict = VerifyScopeDerivation.TryDerive(Inventory(storeIds: ids), Row());
        Assert.False(verdict.Ok);
        Assert.Equal(VerifyScopeDerivation.MultiStore, verdict.Code);
    }

    [Fact]
    public void Derive_NegativeOffset_Refused()
    {
        var verdict = VerifyScopeDerivation.TryDerive(Inventory(offset: -4096), Row());
        Assert.False(verdict.Ok);
        Assert.Equal(VerifyScopeDerivation.InvalidGeometry, verdict.Code);
    }

    [Fact]
    public void Derive_ZeroSize_Refused()
    {
        var verdict = VerifyScopeDerivation.TryDerive(Inventory(size: 0), Row());
        Assert.False(verdict.Ok);
        Assert.Equal(VerifyScopeDerivation.InvalidGeometry, verdict.Code);
    }

    [Theory]
    [InlineData("0")]
    [InlineData("01")]
    [InlineData("not-a-number")]
    [InlineData("")]
    public void Derive_BadCheckpoint_Refused(string xid)
    {
        var verdict = VerifyScopeDerivation.TryDerive(Inventory(xid: xid), Row());
        Assert.False(verdict.Ok);
        Assert.Equal(VerifyScopeDerivation.UnobservableCheckpoint, verdict.Code);
    }
}


