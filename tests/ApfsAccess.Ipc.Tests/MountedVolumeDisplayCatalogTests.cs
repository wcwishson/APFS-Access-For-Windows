using System.Text.Json;
using System.Text.Json.Serialization;
using ApfsAccess.Core;
using ApfsAccess.Ipc;

namespace ApfsAccess.Ipc.Tests;

public sealed class MountedVolumeDisplayCatalogTests
{
    private const string ContainerHex = "a9cb92d28b7c4b599eab633c7625f491";

    private static readonly JsonSerializerOptions CliJsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() },
    };

    [Fact]
    public void StatusOutput_ProjectsCanonicalCatalogFields()
    {
        var display = new MountedVolumeDisplay(
            VolumeId: @"D:\disk.apfs.img|LegacyName",
            MountPoint: "E:",
            VolumeName: "LegacyName",
            DeviceId: @"D:\disk.apfs.img",
            DeviceDisplayName: "APFS Image (disk.apfs.img)",
            AccessMode: MountAccessMode.ReadOnly,
            CatalogVolumeId: $"apfs-vol:{ContainerHex}:101",
            CatalogContainerUuid: ContainerHex,
            CatalogVolumeObjectId: 101UL,
            CatalogDecision: ApfsCapabilityDecision.Writable,
            CatalogReasons: [],
            CatalogAutoMountAllowed: true);

        using var json = JsonDocument.Parse(JsonSerializer.Serialize(display, CliJsonOptions));
        var root = json.RootElement;
        Assert.Equal($"apfs-vol:{ContainerHex}:101", root.GetProperty("catalogVolumeId").GetString());
        Assert.Equal(ContainerHex, root.GetProperty("catalogContainerUuid").GetString());
        Assert.Equal(101UL, root.GetProperty("catalogVolumeObjectId").GetUInt64());
        Assert.Equal("Writable", root.GetProperty("catalogDecision").GetString());
        Assert.True(root.GetProperty("catalogAutoMountAllowed").GetBoolean());
    }

    [Fact]
    public void LegacyConstruction_KeepsNullCatalogDefaults()
    {
        var display = new MountedVolumeDisplay(
            VolumeId: @"D:\disk.apfs.img|Main",
            MountPoint: "E:",
            VolumeName: "Main",
            DeviceId: @"D:\disk.apfs.img",
            DeviceDisplayName: "APFS drive",
            AccessMode: MountAccessMode.ReadOnly);

        Assert.Null(display.CatalogVolumeId);
        Assert.Null(display.CatalogContainerUuid);
        Assert.Null(display.CatalogVolumeObjectId);
        Assert.Null(display.CatalogDecision);
        Assert.Null(display.CatalogReasons);
        Assert.Null(display.CatalogAutoMountAllowed);
        Assert.Equal(@"D:\disk.apfs.img|Main", display.VolumeId);
    }
}
