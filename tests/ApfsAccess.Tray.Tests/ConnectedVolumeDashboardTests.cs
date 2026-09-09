using ApfsAccess.Core;
using ApfsAccess.Ipc;
using ApfsAccess.Tray;

namespace ApfsAccess.Tray.Tests;

public sealed class ConnectedVolumeDashboardTests
{
    private static VolumeInfo Volume(string id = "v") => new(id, "d", "Same name", true,
        RecoveryIdentity: "recovery", CatalogVolumeId: "catalog:" + id, CatalogContainerUuid: "container",
        CatalogVolumeObjectId: 7, CatalogDecision: ApfsCapabilityDecision.Readable,
        CatalogReasons: ["special-role:system"], CatalogAutoMountAllowed: false);

    private static StatusChangedPayload Status(params VolumeInfo[] volumes) => new(RuntimeState.Idle, [], null,
        DateTime.UtcNow, [], false, [], ConnectedInventory: [new(new("d", "Disk", true), volumes)]);

    [Fact]
    public void MixedRowsPreserveIdentityAndOnlyCountActualMounts()
    {
        var v = Volume("mounted");
        var status = Status(v, Volume("protected"), Volume("locked") with { IsEncrypted = true }) with
        {
            State = RuntimeState.MountedRw, WriteEnabled = true,
            MountedVolumes = [new(v.VolumeId, "R:\\", v.VolumeName, "d", "Disk", MountAccessMode.ReadWrite,
                CatalogVolumeId: v.CatalogVolumeId, CatalogContainerUuid: v.CatalogContainerUuid,
                CatalogVolumeObjectId: v.CatalogVolumeObjectId)]
        };
        var rows = DriveDashboardPresenter.BuildRows(status);
        Assert.Equal(3, rows.Count);
        Assert.Single(rows, r => r.IsMounted);
        Assert.StartsWith("1 APFS drive mounted", DriveDashboardPresenter.BuildSummary(status));
        Assert.Equal("Locked", rows.Single(r => r.VolumeId == "locked").StateText);
        var protectedRow = rows.Single(r => r.VolumeId == "protected");
        Assert.True(protectedRow.CanInspectReadOnly);
        Assert.False(protectedRow.CanFix);
        Assert.Contains("Catalog reasons: special-role:system", protectedRow.Details);
        Assert.Equal("container", protectedRow.CatalogContainerUuid);
    }

    [Fact]
    public void InspectionUsesExactSchemaTwoReadOnlyRequestAndRejectsDisconnectedSelection()
    {
        var status = Status(Volume("d|v"));
        var row = Assert.Single(DriveDashboardPresenter.BuildRows(status));
        var request = DriveDashboardPresenter.CreateMountRequest(status, row);
        Assert.Equal(new ApfsControlTarget("d", "d|v", "recovery"), request.Target);
        Assert.Equal(ApfsControlModes.ReadOnly, request.RequestedMode);
        Assert.Equal(ApfsControlCommands.Mount, request.Command);
        var validation = PipeMessageCodec.Validate(PipeMessageCodec.Create(ApfsMessageTypes.ControlOperationRequest,
            request, request.OperationId, PipeSchemaVersions.Schema2));
        Assert.True(validation.IsValid, validation.Diagnostic);
        Assert.Throws<InvalidOperationException>(() => DriveDashboardPresenter.CreateMountRequest(Status(), row));
        Assert.False(Assert.Single(DriveDashboardPresenter.BuildRows(Status())).CanFix);
        Assert.Equal("No APFS drives mounted.", DriveDashboardPresenter.BuildSummary(status));
    }

    [Fact]
    public void DuplicateRoutingIdentitiesNeverAuthorizeEvenWithDifferentCatalogIds()
    {
        foreach (var other in new[] { Volume(), Volume() with { CatalogVolumeId = "other", CatalogVolumeObjectId = 8 } })
        {
            var status = Status(Volume(), other);
            var rows = DriveDashboardPresenter.BuildRows(status);
            Assert.Equal(other.CatalogVolumeId == Volume().CatalogVolumeId ? 1 : 2, rows.Count);
            Assert.All(rows, row => {
                Assert.False(row.CanInspectReadOnly);
                Assert.False(row.CanFix);
                Assert.Throws<InvalidOperationException>(() => DriveDashboardPresenter.CreateMountRequest(status, row));
            });
        }
    }

    [Fact]
    public void OrdinaryUnmountedMountAndStableRowIdentitySurviveStatusAndMountChanges()
    {
        var v = Volume("d|v") with { CatalogDecision = ApfsCapabilityDecision.Writable,
            CatalogReasons = [], CatalogAutoMountAllowed = true };
        var status = Status(v);
        var row = Assert.Single(DriveDashboardPresenter.BuildRows(status));
        Assert.True(row.CanFix);
        Assert.Equal(ApfsControlModes.ReadWrite, DriveDashboardPresenter.CreateMountRequest(status, row).RequestedMode);
        var mounted = status with { MountedVolumes = [new(v.VolumeId, "R:\\", v.VolumeName, "d", "Disk",
            MountAccessMode.ReadOnly, CatalogVolumeId: v.CatalogVolumeId,
            CatalogContainerUuid: v.CatalogContainerUuid, CatalogVolumeObjectId: v.CatalogVolumeObjectId)] };
        Assert.Equal(DriveDashboardPresenter.RowIdentity(row),
            DriveDashboardPresenter.RowIdentity(Assert.Single(DriveDashboardPresenter.BuildRows(mounted))));
        Assert.Equal(DriveDashboardPresenter.RowIdentity(row), DriveDashboardPresenter.RowIdentity(
            Assert.Single(DriveDashboardPresenter.BuildRows(status with { TimestampUtc = DateTime.UtcNow.AddSeconds(1) }))));
    }

    [Theory]
    [InlineData(ApfsCapabilityDecision.Locked)]
    [InlineData(ApfsCapabilityDecision.Unsupported)]
    [InlineData((ApfsCapabilityDecision)99)]
    public void UnavailableVolumesDoNotPromiseRepair(ApfsCapabilityDecision decision)
    {
        var status = Status(Volume() with { CatalogDecision = decision });
        var row = Assert.Single(DriveDashboardPresenter.BuildRows(status));
        Assert.False(row.CanFix);
        Assert.False(row.CanInspectReadOnly);
        Assert.Contains(row.Details, s => s.StartsWith("Catalog decision:"));
    }

    [Fact]
    public void ProtectedDiscoveryDoesNotChangeMountHealthOrBecomeAGlobalError()
    {
        var method = typeof(TrayApplicationContext).GetMethod("SelectBalloonState",
            System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic)!;
        var status = Status(Volume());
        Assert.Equal(DriveDashboardState.Idle, method.Invoke(null, [status]));
        status = status with { State = RuntimeState.MountedRw, WriteEnabled = true,
            MountedVolumes = [new("data", "R:\\", "Data", "d", "Disk", MountAccessMode.ReadWrite)] };
        Assert.Equal(DriveDashboardState.HealthyReadWrite, method.Invoke(null, [status]));
    }
}
