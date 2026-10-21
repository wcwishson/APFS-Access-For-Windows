using System.Text.Json;
using ApfsAccess.Core;

internal sealed record SnapshotRecoveryFixture(string StatusJson, string Source, string VolumeUuid, long StoreSizeBytes)
{
    public static SnapshotRecoveryFixture Load(bool degraded = false)
    {
        using var document = JsonDocument.Parse(File.ReadAllText(Environment.GetEnvironmentVariable("APFSACCESS_SNAPSHOT_RECOVERY_STATUS")!));
        var root = document.RootElement;
        return new(root.GetProperty(degraded ? "degradedStatus" : "status").GetRawText(), root.GetProperty("source").GetString()!, root.GetProperty("volumeUuid").GetString()!,
            root.GetProperty("storeSizeBytes").GetInt64());
    }

    public DeviceInventory Inventory(string container, ulong oid, string recoveryIdentity)
    {
        var cid = ApfsTopology.BuildContainerId(container); var vid = ApfsTopology.BuildVolumeId(container, oid);
        const string disk = "apfs-disk:image", store = "apfs-store:raw";
        var graph = new ApfsTopologySnapshot([new(disk, Source, null, StoreSizeBytes)], [],
            [new(store, container, "", cid, 0, StoreSizeBytes, DiskId: disk)],
            [new(cid, container, 4096, [store], [vid], false, "7", [], [], [])],
            [new(vid, VolumeUuid, oid.ToString(), cid, "Data", true, ["data"], 64, null, "sensitive", "none", false, [], [], [], "7", "7")], []);
        var volume = new VolumeInfo(vid, Source, "Data", true, SupportsNativeWrite: true, RecoveryIdentity: recoveryIdentity,
            CatalogVolumeId: vid, CatalogContainerUuid: container, CatalogVolumeObjectId: oid,
            CatalogVolumeUuid: VolumeUuid, CatalogDecision: ApfsCapabilityDecision.Writable, CatalogReasons: [], CatalogAutoMountAllowed: true);
        return new(new(Source, "Image", true), [volume], new(1, Source, [disk], graph));
    }
}

internal sealed class SnapshotRecoveryStatusFactAttribute : FactAttribute
{
    public SnapshotRecoveryStatusFactAttribute()
    {
        if (Environment.GetEnvironmentVariable("APFSACCESS_SNAPSHOT_RECOVERY_STATUS") is null)
            Skip = "A status document from the actual native accepted snapshot debt regression is required.";
    }
}
