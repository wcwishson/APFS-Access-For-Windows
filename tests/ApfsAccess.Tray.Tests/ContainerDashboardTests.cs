using ApfsAccess.Core;
using ApfsAccess.Ipc;
using ApfsAccess.Tray;

namespace ApfsAccess.Tray.Tests;

// Task 12 Step 3 container actions (mount eligible / unmount all) at the
// presenter layer: resolution, availability, and request building. The
// service re-resolves membership authoritatively; these pins lock the
// fail-closed button/request contract.
public sealed class ContainerDashboardTests
{
    private const string DeviceId = @"\\.\PhysicalDrive2";
    private const string ContainerUuid = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    [Fact]
    public void TryResolveContainerTarget_AcceptsOneSharedContainer()
    {
        var rows = new[]
        {
            ContainerRow(@"\\.\PhysicalDrive2|Main", IsMounted: false, canFix: true),
            ContainerRow(@"\\.\PhysicalDrive2|Backup", IsMounted: false, canFix: true),
        };

        Assert.True(DriveDashboardPresenter.TryResolveContainerTarget(rows, out var deviceId, out var containerUuid));
        Assert.Equal(DeviceId, deviceId);
        Assert.Equal(ContainerUuid, containerUuid);
    }

    [Fact]
    public void TryResolveContainerTarget_RejectsMixedOrBlankIdentity()
    {
        var baseRow = ContainerRow(@"\\.\PhysicalDrive2|Main", IsMounted: false, canFix: true);
        Assert.False(DriveDashboardPresenter.TryResolveContainerTarget([], out _, out _));
        Assert.False(DriveDashboardPresenter.TryResolveContainerTarget(
            [baseRow, baseRow with { DeviceId = @"\\.\PhysicalDrive3" }], out _, out _));
        Assert.False(DriveDashboardPresenter.TryResolveContainerTarget(
            [baseRow, baseRow with { CatalogContainerUuid = new string('b', 32) }], out _, out _));
        Assert.False(DriveDashboardPresenter.TryResolveContainerTarget(
            [baseRow, baseRow with { CatalogContainerUuid = null }], out _, out _));
    }

    [Fact]
    public void ContainerActions_FollowRowMountability()
    {
        var unmounted = new[]
        {
            ContainerRow(@"\\.\PhysicalDrive2|Main", IsMounted: false, canFix: true),
            ContainerRow(@"\\.\PhysicalDrive2|Backup", IsMounted: false, canFix: false),
        };
        Assert.True(DriveDashboardPresenter.ContainerMountAvailable(unmounted));
        Assert.False(DriveDashboardPresenter.ContainerUnmountAvailable(unmounted));

        var mounted = new[]
        {
            ContainerRow(@"\\.\PhysicalDrive2|Main", IsMounted: true, canFix: false, canEject: true),
        };
        Assert.False(DriveDashboardPresenter.ContainerMountAvailable(mounted));
        Assert.True(DriveDashboardPresenter.ContainerUnmountAvailable(mounted));

        var needsFix = new[]
        {
            ContainerRow(@"\\.\PhysicalDrive2|Main", IsMounted: true, canFix: true, canEject: true),
            ContainerRow(@"\\.\PhysicalDrive2|Backup", IsMounted: false, canFix: true),
        };
        Assert.True(DriveDashboardPresenter.ContainerFixAvailable(needsFix));
        Assert.False(DriveDashboardPresenter.ContainerFixAvailable(unmounted));
    }

    [Fact]
    public void CreateContainerRequest_MountBindsContainerTargetAndMode()
    {
        var payload = InventoryPayload(
            RuntimeState.Idle,
            InventoryVolume(@"\\.\PhysicalDrive2|Main", "Main", 101),
            InventoryVolume(@"\\.\PhysicalDrive2|Backup", "Backup", 102));
        var rows = DriveDashboardPresenter.BuildRows(payload)
            .Where(static r => !string.IsNullOrWhiteSpace(r.VolumeId)).ToArray();
        Assert.Equal(2, rows.Length);

        var request = DriveDashboardPresenter.CreateContainerRequest(
            payload, rows, ApfsControlCommands.ContainerMount);

        Assert.Equal(ApfsControlCommands.ContainerMount, request.Command);
        Assert.Equal(DeviceId, request.Target!.DeviceId);
        Assert.Equal(string.Empty, request.Target.VolumeId);
        Assert.Equal(ContainerUuid, request.Target.ContainerUuid);
        Assert.Equal(ApfsControlModes.ReadWrite, request.RequestedMode);
        var envelope = PipeMessageCodec.Create(
            ApfsMessageTypes.ControlOperationRequest, request, request.OperationId, PipeSchemaVersions.Schema2);
        Assert.True(PipeMessageCodec.Validate(envelope).IsValid);
    }

    [Fact]
    public void CreateContainerRequest_UnmountCarriesNoMode()
    {
        var payload = MountedPayload(RuntimeState.MountedRw,
            MountedVolume(@"\\.\PhysicalDrive2|Main", "Main", 101, "E:\\"),
            MountedVolume(@"\\.\PhysicalDrive2|Backup", "Backup", 102, "F:\\"));
        var rows = DriveDashboardPresenter.BuildRows(payload)
            .Where(static r => !string.IsNullOrWhiteSpace(r.VolumeId)).ToArray();
        Assert.Equal(2, rows.Length);

        var request = DriveDashboardPresenter.CreateContainerRequest(
            payload, rows, ApfsControlCommands.ContainerUnmount);

        Assert.Equal(ApfsControlCommands.ContainerUnmount, request.Command);
        Assert.Null(request.RequestedMode);
        Assert.Equal(ContainerUuid, request.Target!.ContainerUuid);
    }

    [Fact]
    public void CreateContainerRequest_RejectsUnknownCommandAndStaleSelection()
    {
        var payload = InventoryPayload(
            RuntimeState.Idle,
            InventoryVolume(@"\\.\PhysicalDrive2|Main", "Main", 101));
        var rows = DriveDashboardPresenter.BuildRows(payload)
            .Where(static r => !string.IsNullOrWhiteSpace(r.VolumeId)).ToArray();
        Assert.Single(rows);

        Assert.Throws<InvalidOperationException>(() =>
            DriveDashboardPresenter.CreateContainerRequest(payload, rows, ApfsControlCommands.Mount));
        var changed = InventoryPayload(
            RuntimeState.Idle,
            InventoryVolume(@"\\.\PhysicalDrive2|Other", "Other", 103));
        Assert.Throws<InvalidOperationException>(() =>
            DriveDashboardPresenter.CreateContainerRequest(changed, rows, ApfsControlCommands.ContainerMount));
    }

    [Fact]
    public void TryResolveDeviceTarget_AcceptsSharedDeviceAcrossContainers()
    {
        var rows = new[]
        {
            ContainerRow(@"\\.\PhysicalDrive2|Main", IsMounted: false, canFix: true),
            ContainerRow(@"\\.\PhysicalDrive2|Backup", IsMounted: false, canFix: true),
        };

        Assert.True(DriveDashboardPresenter.TryResolveDeviceTarget(rows, out var deviceId));
        Assert.Equal(DeviceId, deviceId);
        Assert.False(DriveDashboardPresenter.TryResolveDeviceTarget([], out _));
        Assert.False(DriveDashboardPresenter.TryResolveDeviceTarget(
            [rows[0], rows[0] with { DeviceId = @"\\.\PhysicalDrive3" }], out _));
    }

    [Fact]
    public void DeviceEjectAvailable_RequiresMountedRow()
    {
        var unmounted = new[]
        {
            ContainerRow(@"\\.\PhysicalDrive2|Main", IsMounted: false, canFix: true),
        };
        Assert.False(DriveDashboardPresenter.DeviceEjectAvailable(unmounted));

        var mounted = new[]
        {
            ContainerRow(@"\\.\PhysicalDrive2|Main", IsMounted: true, canFix: false, canEject: true),
        };
        Assert.True(DriveDashboardPresenter.DeviceEjectAvailable(mounted));
    }

    [Fact]
    public void CreateDeviceRequest_BindsDeviceOnlyTarget()
    {
        var payload = MountedPayload(RuntimeState.MountedRw,
            MountedVolume(@"\\.\PhysicalDrive2|Main", "Main", 101, "E:\\"),
            MountedVolume(@"\\.\PhysicalDrive2|Backup", "Backup", 102, "F:\\"));
        var rows = DriveDashboardPresenter.BuildRows(payload)
            .Where(static r => !string.IsNullOrWhiteSpace(r.VolumeId)).ToArray();
        Assert.Equal(2, rows.Length);

        var request = DriveDashboardPresenter.CreateDeviceRequest(payload, rows);

        Assert.Equal(ApfsControlCommands.DeviceEject, request.Command);
        Assert.Equal(DeviceId, request.Target!.DeviceId);
        Assert.True(string.IsNullOrEmpty(request.Target.VolumeId));
        Assert.True(string.IsNullOrEmpty(request.Target.ContainerUuid));
        Assert.Null(request.RequestedMode);
        var envelope = PipeMessageCodec.Create(
            ApfsMessageTypes.ControlOperationRequest, request, request.OperationId, PipeSchemaVersions.Schema2);
        Assert.True(PipeMessageCodec.Validate(envelope).IsValid);
    }

    [Fact]
    public void CreateDeviceRequest_RejectsMissingDeviceAndEmptySelection()
    {
        var payload = MountedPayload(RuntimeState.MountedRw,
            MountedVolume(@"\\.\PhysicalDrive2|Main", "Main", 101, "E:\\"));
        var rows = DriveDashboardPresenter.BuildRows(payload)
            .Where(static r => !string.IsNullOrWhiteSpace(r.VolumeId)).ToArray();
        Assert.Single(rows);

        var gone = MountedPayload(RuntimeState.MountedRw,
            MountedVolume(@"\\.\PhysicalDrive9|Main", "Main", 101, "E:\\"));
        Assert.Throws<InvalidOperationException>(() =>
            DriveDashboardPresenter.CreateDeviceRequest(gone, rows));
        Assert.Throws<InvalidOperationException>(() =>
            DriveDashboardPresenter.CreateDeviceRequest(payload, []));
    }

    private static DriveDashboardRow ContainerRow(string volumeId, bool IsMounted, bool canFix, bool canEject = false)
        => new(
            VolumeId: volumeId,
            DeviceName: "APFS USB Device",
            VolumeName: "Main",
            MountPoint: IsMounted ? "E:\\" : string.Empty,
            MountPath: string.Empty,
            State: IsMounted ? DriveDashboardState.HealthyReadWrite : DriveDashboardState.Idle,
            Palette: DashboardPalette.Gray,
            StateText: IsMounted ? "Healthy read/write" : "Not mounted",
            Summary: string.Empty,
            CanOpen: IsMounted,
            CanEject: canEject,
            CanFix: canFix,
            Details: [],
            FixGuidance: [],
            CatalogContainerUuid: ContainerUuid,
            DeviceId: DeviceId,
            IsMounted: IsMounted,
            CanInspectReadOnly: false);

    private static VolumeInfo InventoryVolume(string volumeId, string name, ulong objectId)
        => new(
            VolumeId: volumeId,
            DeviceId: DeviceId,
            VolumeName: name,
            SupportsReadWrite: true,
            RecoveryIdentity: "apfs-recovery-v1|main",
            CatalogVolumeId: volumeId,
            CatalogContainerUuid: ContainerUuid,
            CatalogVolumeObjectId: objectId,
            CatalogDecision: ApfsCapabilityDecision.Writable,
            CatalogReasons: [],
            CatalogAutoMountAllowed: true,
            CatalogVolumeUuid: new string('b', 32));

    private static StatusChangedPayload InventoryPayload(RuntimeState state, params VolumeInfo[] volumes)
        => new(
            State: state,
            MountPoints: [],
            LastError: null,
            TimestampUtc: DateTime.UtcNow,
            Warnings: [],
            WriteEnabled: false,
            CompatibilityWarnings: [],
            ConnectedInventory:
            [
                new DeviceInventory(new DeviceInfo(DeviceId, "APFS USB Device", true), volumes),
            ]);

    private static MountedVolumeDisplay MountedVolume(
        string volumeId, string name, ulong objectId, string mountPoint,
        MountAccessMode accessMode = MountAccessMode.ReadWrite)
        => new(
            VolumeId: volumeId,
            MountPoint: mountPoint,
            VolumeName: name,
            DeviceId: DeviceId,
            DeviceDisplayName: "APFS USB Device",
            AccessMode: accessMode,
            RecoveryIdentity: "apfs-recovery-v1|main",
            CatalogVolumeId: volumeId,
            CatalogContainerUuid: ContainerUuid,
            CatalogVolumeObjectId: objectId,
            CatalogVolumeUuid: new string('b', 32),
            CatalogDecision: ApfsCapabilityDecision.Writable,
            CatalogReasons: [],
            CatalogAutoMountAllowed: true);

    private static StatusChangedPayload MountedPayload(RuntimeState state, params MountedVolumeDisplay[] mounted)
        => new(
            State: state,
            MountPoints: mounted.Select(static m => m.MountPoint).ToArray(),
            LastError: null,
            TimestampUtc: DateTime.UtcNow,
            Warnings: [],
            WriteEnabled: true,
            CompatibilityWarnings: [],
            MountedVolumes: mounted,
            ConnectedInventory:
            [
                new DeviceInventory(
                    new DeviceInfo(DeviceId, "APFS USB Device", true),
                    mounted.Select(static m => InventoryVolume(
                        m.VolumeId, m.VolumeName, m.CatalogVolumeObjectId ?? 101)).ToArray()),
            ]);
}
