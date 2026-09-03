using ApfsAccess.Core;
using ApfsAccess.Ipc;
using ApfsAccess.Tray;

namespace ApfsAccess.Tray.Tests;

public sealed class DriveDashboardCatalogTests
{
    private const string ContainerHex = "a9cb92d28b7c4b599eab633c7625f491";

    [Fact]
    public void BuildRows_ProjectsCatalogIdentityWithoutChangingClassification()
    {
        var payload = NewPayload(
            RuntimeState.MountedRw,
            writeEnabled: true,
            mountedVolumes:
            [
                new MountedVolumeDisplay(
                    VolumeId: @"\\.\PhysicalDrive2|Main",
                    MountPoint: "E:\\",
                    VolumeName: "Main",
                    DeviceId: @"\\.\PhysicalDrive2",
                    DeviceDisplayName: "APFS USB Device",
                    AccessMode: MountAccessMode.ReadWrite,
                    CatalogVolumeId: $"apfs-vol:{ContainerHex}:101",
                    CatalogContainerUuid: ContainerHex,
                    CatalogVolumeObjectId: 101UL),
            ],
            nativeWriteSafetyState: NativeWriteSafetyState.PilotReadWrite);

        var row = Assert.Single(DriveDashboardPresenter.BuildRows(payload));

        Assert.Equal(DriveDashboardState.HealthyReadWrite, row.State);
        Assert.Equal($"apfs-vol:{ContainerHex}:101", row.CatalogVolumeId);
        Assert.Equal(ContainerHex, row.CatalogContainerUuid);
        Assert.Equal(101UL, row.CatalogVolumeObjectId);
        Assert.Contains(row.Details, static detail => detail.Contains(ContainerHex, StringComparison.Ordinal));
        Assert.Contains(row.Details, static detail => detail.Contains("101", StringComparison.Ordinal));
    }

    [Fact]
    public void BuildRows_LeavesCatalogFieldsNullWhenDisplayHasNone()
    {
        var payload = NewPayload(
            RuntimeState.MountedRw,
            writeEnabled: true,
            mountedVolumes:
            [
                new MountedVolumeDisplay(
                    VolumeId: @"\\.\PhysicalDrive2|Main",
                    MountPoint: "E:\\",
                    VolumeName: "Main",
                    DeviceId: @"\\.\PhysicalDrive2",
                    DeviceDisplayName: "APFS USB Device",
                    AccessMode: MountAccessMode.ReadWrite),
            ],
            nativeWriteSafetyState: NativeWriteSafetyState.PilotReadWrite);

        var row = Assert.Single(DriveDashboardPresenter.BuildRows(payload));

        Assert.Equal(DriveDashboardState.HealthyReadWrite, row.State);
        Assert.Null(row.CatalogVolumeId);
        Assert.Null(row.CatalogContainerUuid);
        Assert.Null(row.CatalogVolumeObjectId);
    }

    private static StatusChangedPayload NewPayload(
        RuntimeState state,
        bool writeEnabled,
        IReadOnlyList<MountedVolumeDisplay> mountedVolumes,
        NativeWriteSafetyState nativeWriteSafetyState = NativeWriteSafetyState.ReadOnlyFallback)
    {
        return new StatusChangedPayload(
            State: state,
            MountPoints: mountedVolumes
                .Select(static volume => volume.MountPoint)
                .Where(static mountPoint => !string.IsNullOrWhiteSpace(mountPoint))
                .ToArray(),
            LastError: null,
            TimestampUtc: DateTime.UtcNow,
            Warnings: Array.Empty<string>(),
            WriteEnabled: writeEnabled,
            CompatibilityWarnings: Array.Empty<string>(),
            MountedVolumes: mountedVolumes,
            NativeWriteSafetyState: nativeWriteSafetyState);
    }
}
