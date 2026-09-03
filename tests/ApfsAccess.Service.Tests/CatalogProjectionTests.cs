using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;
using ApfsAccess.Core;
using ApfsAccess.Ipc;
using ApfsAccess.Service;

namespace ApfsAccess.Service.Tests;

public sealed class CatalogProjectionTests
{
    private const string ContainerHex = "a9cb92d28b7c4b599eab633c7625f491";

    [Fact]
    public void BuildMountedVolumeDisplays_ProjectsCatalogFieldsAdditively()
    {
        var mounts = new[]
        {
            new MountedVolumeState(
                VolumeId: "device-a|LegacyName",
                MountPoint: "R:\\",
                AccessMode: MountAccessMode.ReadOnly,
                VolumeName: "LegacyName",
                DeviceId: "device-a",
                CatalogVolumeId: $"apfs-vol:{ContainerHex}:101",
                CatalogContainerUuid: ContainerHex,
                CatalogVolumeObjectId: 101UL,
                CatalogDecision: ApfsCapabilityDecision.Writable,
                CatalogReasons: [],
                CatalogAutoMountAllowed: true),
        };

        var display = Assert.Single(InvokeBuildMountedVolumeDisplays(mounts));

        Assert.Equal($"apfs-vol:{ContainerHex}:101", display.CatalogVolumeId);
        Assert.Equal(ContainerHex, display.CatalogContainerUuid);
        Assert.Equal(101UL, display.CatalogVolumeObjectId);
        Assert.Equal(ApfsCapabilityDecision.Writable, display.CatalogDecision);
        Assert.Equal([], display.CatalogReasons);
        Assert.True(display.CatalogAutoMountAllowed);
        Assert.Equal("device-a|LegacyName", display.VolumeId);

        var jsonOptions = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            Converters = { new JsonStringEnumConverter() },
        };
        var element = JsonSerializer.SerializeToElement(display, jsonOptions);
        Assert.Equal($"apfs-vol:{ContainerHex}:101", element.GetProperty("catalogVolumeId").GetString());
        Assert.Equal(ContainerHex, element.GetProperty("catalogContainerUuid").GetString());
        Assert.Equal(101UL, element.GetProperty("catalogVolumeObjectId").GetUInt64());
        Assert.Equal("Writable", element.GetProperty("catalogDecision").GetString());
        Assert.True(element.GetProperty("catalogAutoMountAllowed").GetBoolean());
    }

    [Fact]
    public void BuildMountedVolumeDisplays_LeavesCatalogFieldsNullWhenStateHasNone()
    {
        var mounts = new[]
        {
            new MountedVolumeState(
                VolumeId: "device-a|Main",
                MountPoint: "R:\\",
                AccessMode: MountAccessMode.ReadOnly),
        };

        var display = Assert.Single(InvokeBuildMountedVolumeDisplays(mounts));

        Assert.Null(display.CatalogVolumeId);
        Assert.Null(display.CatalogContainerUuid);
        Assert.Null(display.CatalogVolumeObjectId);
        Assert.Null(display.CatalogDecision);
        Assert.Null(display.CatalogReasons);
        Assert.Null(display.CatalogAutoMountAllowed);
    }

    private static IReadOnlyList<MountedVolumeDisplay> InvokeBuildMountedVolumeDisplays(
        IReadOnlyList<MountedVolumeState> mounts)
    {
        var method = typeof(ApfsMountWorker).GetMethod(
            "BuildMountedVolumeDisplays",
            BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        var result = method!.Invoke(null, [mounts]);
        return Assert.IsAssignableFrom<IReadOnlyList<MountedVolumeDisplay>>(result);
    }
}
