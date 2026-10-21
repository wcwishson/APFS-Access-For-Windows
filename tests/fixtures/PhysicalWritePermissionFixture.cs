using ApfsAccess.Core;

namespace ApfsAccess.TestFixtures;

// Pure catalog projection; none of these unit tests opens a physical source.
public sealed class PhysicalWritePermissionFixture : IDisposable
{
    public const string Device = @"\\.\PhysicalDrive900";
    public const string Container = "cdcdcdcdcdcd4dcd8dcdcdcdcdcdcdcd";
    public const string VolumeUuid = "abababababab4bab8bababababababab";
    public const string Disk = "apfs-disk:permission-unit";
    public string Root { get; } = Path.Combine(Path.GetTempPath(), "physical-permission-unit-" + Guid.NewGuid().ToString("N"));
    public string StorePath => Path.Combine(Root, "permissions.json");
    public ServiceHostOptions Options { get; } = new()
    {
        BackendMode = "Native", AutoMountEnabled = true, EnableNativeWrite = true,
        WriteRolloutChannel = "Pilot", WriteBackendMode = "Native", NativeWritePromotionPolicy = "CanonicalImage",
        ReadWriteMode = "RwWithRoFallback", NativeAutoRemountOnReconnect = false,
    };

    public VolumeInfo Volume { get; set; } = new($"apfs-vol:{Container}:101", Device, "Selected",
        SupportsReadWrite: true, SupportsNativeWrite: true, NativeWriteReadiness: NativeWriteReadiness.BootstrapReady,
        RecoveryIdentity: "physical-unit-recovery-101", CatalogVolumeId: $"apfs-vol:{Container}:101",
        CatalogContainerUuid: Container, CatalogVolumeObjectId: 101, CatalogDecision: ApfsCapabilityDecision.Writable,
        CatalogReasons: [], CatalogAutoMountAllowed: true, CatalogVolumeUuid: VolumeUuid);

    public ApfsDiscoveryTopology Topology { get; set; }

    public PhysicalWritePermissionFixture()
    {
        Directory.CreateDirectory(Root);
        const string partitionUuid = "12345678-1234-4234-8234-123456789abc";
        var cid = "apfs-container:" + Container;
        var sid = "apfs-store:" + partitionUuid;
        var pid = "apfs-part:" + partitionUuid;
        var row = new ApfsVolumeRecord(Volume.VolumeId, VolumeUuid, "101", cid, "Selected", true, ["data"], 0,
            null, "insensitive", "none", false, [], [], [], "22", "10", []);
        var snapshot = new ApfsTopologySnapshot(
            [new(Disk, Device, "fedcba98-7654-4321-8abc-123456789abc", 64L << 20)],
            [new(pid, partitionUuid, Disk, 1, 1L << 20, 32L << 20, "7C3457EF-0000-11AA-AA11-00306543ECAC", "Apple_APFS")],
            [new(sid, Container, pid, cid, 1L << 20, 32L << 20, 4096, 8192)],
            [new(cid, Container, 4096, [sid], [Volume.VolumeId], false, "10", [], [], [], [])], [row], []);
        Topology = new(1, Device, [Disk], snapshot);
    }

    public PhysicalWritePermissions Manager()
    {
        var manager = new PhysicalWritePermissions(StorePath);
        manager.Observe(Volume, Topology);
        return manager;
    }

    public static VolumeInfo Mask(VolumeInfo v) => v with
    {
        SupportsReadWrite = false, SupportsNativeWrite = false, NativeWriteReadiness = NativeWriteReadiness.Unavailable,
        NativeWriteAdmissionBlockReason = "raw source requires explicit permission", WriteBlockReason = "raw source requires explicit permission",
    };

    public void Dispose() => Directory.Delete(Root, recursive: true);
}
