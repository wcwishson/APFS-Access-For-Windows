using System.Text.Json;
using System.Text.Json.Serialization;

namespace ApfsAccess.Core.Tests;

public sealed class CatalogProjectionTests
{
    private const string ContainerHex = "a9cb92d28b7c4b599eab633c7625f491";

    private static readonly JsonSerializerOptions CliJsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() },
    };

    [Fact]
    public void LegacyVolumeIdForm_IsUnchangedAndCatalogFieldsDefaultToNull()
    {
        var volume = new VolumeInfo(
            VolumeId: @"D:\disk.apfs.img|Main",
            DeviceId: @"D:\disk.apfs.img",
            VolumeName: "Main",
            SupportsReadWrite: false);

        Assert.Equal(@"D:\disk.apfs.img|Main", volume.VolumeId);
        Assert.Null(volume.CatalogVolumeId);
        Assert.Null(volume.CatalogContainerUuid);
        Assert.Null(volume.CatalogVolumeObjectId);
        Assert.Null(volume.CatalogDecision);
        Assert.Null(volume.CatalogReasons);
        Assert.Null(volume.CatalogAutoMountAllowed);
    }

    [Fact]
    public void VolumesOutput_ProjectsCanonicalCatalogFields()
    {
        var volume = new VolumeInfo(
            VolumeId: @"D:\disk.apfs.img|LegacyName",
            DeviceId: @"D:\disk.apfs.img",
            VolumeName: "LegacyName",
            SupportsReadWrite: false,
            CatalogVolumeId: $"apfs-vol:{ContainerHex}:101",
            CatalogContainerUuid: ContainerHex,
            CatalogVolumeObjectId: 101UL,
            CatalogDecision: ApfsCapabilityDecision.Writable,
            CatalogReasons: [],
            CatalogAutoMountAllowed: true);

        using var json = JsonDocument.Parse(JsonSerializer.Serialize(volume, CliJsonOptions));
        var root = json.RootElement;
        Assert.Equal(@"D:\disk.apfs.img|LegacyName", root.GetProperty("volumeId").GetString());
        Assert.Equal($"apfs-vol:{ContainerHex}:101", root.GetProperty("catalogVolumeId").GetString());
        Assert.Equal(ContainerHex, root.GetProperty("catalogContainerUuid").GetString());
        Assert.Equal(101UL, root.GetProperty("catalogVolumeObjectId").GetUInt64());
        Assert.Equal("Writable", root.GetProperty("catalogDecision").GetString());
        Assert.Equal(JsonValueKind.Array, root.GetProperty("catalogReasons").ValueKind);
        Assert.True(root.GetProperty("catalogAutoMountAllowed").GetBoolean());
    }

    [Fact]
    public void VolumesOutput_EmitsCatalogFieldNamesEvenWhenNull()
    {
        var volume = new VolumeInfo(
            VolumeId: @"D:\disk.apfs.img|Main",
            DeviceId: @"D:\disk.apfs.img",
            VolumeName: "Main",
            SupportsReadWrite: false);

        using var json = JsonDocument.Parse(JsonSerializer.Serialize(volume, CliJsonOptions));
        var root = json.RootElement;
        foreach (var name in new[]
                 {
                     "catalogVolumeId", "catalogContainerUuid", "catalogVolumeObjectId",
                     "catalogDecision", "catalogReasons", "catalogAutoMountAllowed",
                 })
        {
            Assert.True(root.TryGetProperty(name, out _), $"Missing additive field '{name}'.");
        }
    }

    [Fact]
    public void MountedVolumeState_CarriesCatalogFieldsAsNullDefaults()
    {
        var state = new MountedVolumeState(
            VolumeId: @"D:\disk.apfs.img|Main",
            MountPoint: "E:",
            AccessMode: MountAccessMode.ReadOnly);

        Assert.Null(state.CatalogVolumeId);
        Assert.Null(state.CatalogContainerUuid);
        Assert.Null(state.CatalogVolumeObjectId);
        Assert.Null(state.CatalogDecision);
        Assert.Null(state.CatalogReasons);
        Assert.Null(state.CatalogAutoMountAllowed);
    }

    [Fact]
    public void CanonicalVolumeId_MatchesObserverEvidenceGrammar()
    {
        var canonical = ApfsTopology.BuildVolumeId(ContainerHex, 101);

        Assert.Equal($"apfs-vol:{ContainerHex}:101", canonical);
        Assert.True(ApfsTopology.TryParseVolumeId(canonical, out var hex, out var oid));
        Assert.Equal(ContainerHex, hex);
        Assert.Equal(101UL, oid);
    }
}
