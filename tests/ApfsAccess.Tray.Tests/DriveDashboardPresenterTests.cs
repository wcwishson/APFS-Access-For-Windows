using ApfsAccess.Core;
using ApfsAccess.Ipc;
using ApfsAccess.Tray;

namespace ApfsAccess.Tray.Tests;

public sealed class DriveDashboardPresenterTests
{
    [Theory]
    [InlineData(RuntimeState.Starting)]
    [InlineData(RuntimeState.Error)]
    public void BuildRows_UnmountedCatalogDetailsExposeServiceFailureWithoutFailingSiblings(RuntimeState serviceState)
    {
        const string error = "Native helper exited with code 5 before mount readiness.";
        var failed = new VolumeInfo("failed", "disk", "Main", false,
            CatalogVolumeId: "catalog-main", CatalogDecision: ApfsCapabilityDecision.Writable,
            CatalogReasons: [], CatalogAutoMountAllowed: true);
        var idle = failed with { VolumeId = "idle", VolumeName = "Archive", CatalogVolumeId = "catalog-archive" };
        var healthy = new MountedVolumeState("healthy", "R:\\", MountAccessMode.ReadWrite,
            VolumeName: "Healthy", DeviceId: "disk", MountReady: true,
            NativeWriteSafetyState: NativeWriteSafetyState.StableReadWrite);
        var payload = NewPayload(serviceState, false, MountedStatusProjection.FromMounts([healthy]),
            warnings: [$"Mount failed for 'Main': {error}", "Automatic mount retry for 'failed' is paused."]) with
        {
            LastError = error,
            ConnectedInventory = [new(new("disk", "Disk", true), [failed, idle])],
        };

        var rows = DriveDashboardPresenter.BuildRows(payload);
        var failedRow = Assert.Single(rows, row => row.VolumeId == "failed");
        Assert.Contains($"Service state: {serviceState}", failedRow.Details);
        Assert.Contains($"Service last error: {error}", failedRow.Details);
        Assert.Contains(failedRow.Details, line => line.StartsWith("Service warnings:") && line.Contains("Automatic mount retry"));
        Assert.Contains("Catalog decision: Writable", failedRow.Details);
        Assert.True(failedRow.CanFix);
        Assert.False(failedRow.CanInspectReadOnly);
        Assert.False(failedRow.CanOpen);

        var healthyRow = Assert.Single(rows, row => row.VolumeId == "healthy");
        Assert.Equal(DriveDashboardState.HealthyReadWrite, healthyRow.State);
        Assert.Equal(DashboardPalette.Green, healthyRow.Palette);
        Assert.False(healthyRow.CanFix);
        Assert.DoesNotContain(error, string.Join("\n", healthyRow.Details));
        Assert.DoesNotContain("Automatic mount retry", string.Join("\n", healthyRow.Details));
        var idleRow = Assert.Single(rows, row => row.VolumeId == "idle");
        Assert.Equal(DriveDashboardState.Idle, idleRow.State);
        Assert.Equal("Not mounted.", idleRow.Summary);
    }

    [Fact]
    public void CopyInfo_UnmountedAndMountedDiagnosticsStayScopedToSelectedVolume()
    {
        Exception? failure = null;
        var thread = new Thread(() =>
        {
            try
            {
                const string error = "Native helper exited with code 5 before mount readiness.";
                var healthy = new MountedVolumeState("healthy", "R:\\", MountAccessMode.ReadWrite,
                    VolumeName: "Healthy", DeviceId: "disk", MountReady: true,
                    NativeWriteSafetyState: NativeWriteSafetyState.StableReadWrite);
                var degraded = new MountedVolumeState("degraded", "S:\\", MountAccessMode.ReadOnly,
                    VolumeName: "Degraded", DeviceId: "disk", MountReady: true,
                    RecoveryActive: true, RecoveryReason: "Volume-local recovery",
                    NativeWriteSafetyState: NativeWriteSafetyState.RecoveryBlocked,
                    NativeWriteDiagnostics: [new("LocalRecovery", "Volume-local recovery")]);
                var status = NewPayload(RuntimeState.Error, false, MountedStatusProjection.FromMounts([healthy, degraded]),
                    warnings: [$"Mount failed for 'Main': {error}"],
                    compatibilityWarnings: ["Sibling startup failed"],
                    diagnostics: [new("SiblingStartup", error)]) with
                {
                    LastError = error,
                    ConnectedInventory = [new(new("disk", "Disk", true), [new VolumeInfo("failed", "disk", "Main", false)])],
                };
                var copies = new List<string>();
                using var form = new DashboardForm(_ => Task.CompletedTask, _ => Task.CompletedTask, _ => Task.CompletedTask,
                    copyText: copies.Add);
                const System.Reflection.BindingFlags flags = System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic;
                var tree = (System.Windows.Forms.TreeView)typeof(DashboardForm).GetField("_topologyTree", flags)!.GetValue(form)!;
                var copy = (System.Windows.Forms.Button)typeof(DashboardForm).GetField("_copyDetailsButton", flags)!.GetValue(form)!;
                _ = tree.Handle;
                form.ApplyStatus(status);
                var nodes = tree.Nodes.Find("inventory-device:disk", true).Single().Nodes.Cast<System.Windows.Forms.TreeNode>().ToArray();
                foreach (var volumeId in new[] { "failed", "degraded", "healthy" })
                {
                        var node = Assert.Single(nodes, candidate => ((TopologyDashboardNode)candidate.Tag!).Row?.VolumeId == volumeId);
                        tree.SelectedNode = node;
                        typeof(DashboardForm).GetMethod("ShowSelectedNode", flags)!.Invoke(form, null);
                        typeof(System.Windows.Forms.Button).GetMethod("OnClick", flags)!.Invoke(copy, [EventArgs.Empty]);
                        var copied = copies[^1];
                        Assert.Equal(((TopologyDashboardNode)node.Tag!).Details, copied);
                        if (volumeId == "failed")
                        {
                            Assert.Contains($"Service last error: {error}", copied);
                            Assert.Contains($"Service diagnostics: SiblingStartup: {error}", copied);
                        }
                        else
                        {
                            Assert.DoesNotContain(error, copied);
                            Assert.DoesNotContain("Sibling startup failed", copied);
                            Assert.DoesNotContain("SiblingStartup", copied);
                            Assert.Contains(volumeId == "degraded" ? "LocalRecovery: Volume-local recovery" : "State: Healthy read/write", copied);
                        }
                }
                Assert.Equal(3, copies.Count);
            }
            catch (Exception ex) { failure = ex; }
        });
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        thread.Join();
        if (failure is not null) System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(failure).Throw();
    }

    [Fact]
    public void BuildRows_ServiceFailureDetailsPreserveLockedAndAmbiguousCapabilityFences()
    {
        var locked = new VolumeInfo("locked", "disk", "Locked", false, IsEncrypted: true,
            CatalogDecision: ApfsCapabilityDecision.Locked, CatalogReasons: ["locked"], CatalogAutoMountAllowed: false);
        var duplicate = new VolumeInfo("duplicate", "disk", "Duplicate", false);
        var payload = NewPayload(RuntimeState.Error, false, []) with
        {
            ConnectedInventory = [new(new("disk", "Disk", true), [locked, duplicate, duplicate])],
        };

        var rows = DriveDashboardPresenter.BuildRows(payload);
        Assert.Equal(2, rows.Count);
        Assert.All(rows, row =>
        {
            Assert.Contains("Service last error: Mount failed", row.Details);
            Assert.False(row.CanFix);
            Assert.False(row.CanInspectReadOnly);
            Assert.False(row.CanOpen);
            Assert.False(row.CanEject);
        });
        Assert.Equal("Locked", Assert.Single(rows, row => row.VolumeId == "locked").StateText);
    }

    [Fact]
    public void BuildRows_ClassifiesHealthyReadWriteVolumeAsGreenAndDisablesFix()
    {
        var payload = NewPayload(
            RuntimeState.MountedRw,
            writeEnabled: true,
            mountedVolumes:
            [
                NewMountedVolume(MountAccessMode.ReadWrite)
            ],
            nativeWriteSafetyState: NativeWriteSafetyState.PilotReadWrite,
            recoveryActive: false,
            dirtyTransactionCount: 0);

        var rows = DriveDashboardPresenter.BuildRows(payload);

        var row = Assert.Single(rows);
        Assert.Equal(DriveDashboardState.HealthyReadWrite, row.State);
        Assert.Equal("Healthy read/write", row.StateText);
        Assert.Equal(DashboardPalette.Green, row.Palette);
        Assert.False(row.CanFix);
        Assert.True(row.CanEject);
        Assert.True(row.CanOpen);
    }

    [Fact]
    public void BuildRows_RegisteredImageProblemRowPointsAtOfflineVerifyAndRepair()
    {
        var profile = new EncryptedImageProfile(@"D:\repair-image.apfs", "windows-file:1:2:4096:4:scope:0:4096", 0, 4096,
            "11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222", 12, 8, 1, 8, 2, 8,
            "33333333-3333-3333-3333-333333333333", "includes-header");
        var inventoryVolume = new VolumeInfo(@"\\.\PhysicalDrive2|Main", @"\\.\PhysicalDrive2", "Main", false,
            RecoveryIdentity: profile.Contract, CatalogVolumeId: profile.VolumeId,
            CatalogContainerUuid: profile.ContainerUuid, CatalogVolumeObjectId: profile.VolumeObjectId,
            CatalogVolumeUuid: profile.VolumeUuid, RegisteredImage: profile);
        // The mounted row must carry the same bound catalog identity the
        // inventory reports, otherwise they are two different volumes.
        var mounted = NewMountedVolume(MountAccessMode.ReadOnly) with
        {
            CatalogVolumeId = profile.VolumeId,
            CatalogContainerUuid = profile.ContainerUuid,
            CatalogVolumeObjectId = profile.VolumeObjectId,
            CatalogVolumeUuid = profile.VolumeUuid,
            RecoveryIdentity = profile.Contract,
        };
        var payload = NewPayload(
            RuntimeState.MountedRo,
            writeEnabled: false,
            mountedVolumes:
            [
                mounted
            ],
            nativeWriteSafetyState: NativeWriteSafetyState.ReadOnlyFallback,
            recoveryActive: false,
            dirtyTransactionCount: 0) with
        {
            ConnectedInventory = [new(new(@"\\.\PhysicalDrive2", "APFS USB Device", true), [inventoryVolume])],
        };

        var row = Assert.Single(DriveDashboardPresenter.BuildRows(payload));

        Assert.Contains(row.FixGuidance, line => line.Contains("APFSAccess.Cli.exe verify --help", StringComparison.Ordinal));
        Assert.Contains(row.FixGuidance, line => line.Contains("separate repair command that refuses anything outside its contract", StringComparison.Ordinal));
    }

    [Fact]
    public void BuildRows_PhysicalDeviceProblemRowOmitsOfflineRepairPointer()
    {
        var payload = NewPayload(
            RuntimeState.MountedRo,
            writeEnabled: false,
            mountedVolumes:
            [
                NewMountedVolume(MountAccessMode.ReadOnly)
            ],
            nativeWriteSafetyState: NativeWriteSafetyState.ReadOnlyFallback,
            recoveryActive: false,
            dirtyTransactionCount: 0);

        var row = Assert.Single(DriveDashboardPresenter.BuildRows(payload));

        Assert.DoesNotContain(row.FixGuidance, line => line.Contains("separate repair command", StringComparison.Ordinal));
    }

    [Fact]
    public void CreateSelectedRequest_RejectsManagementActions()
    {
        // No Manage/format/create/delete surface exists until Task 11 lands
        // each keeper slice behind the management gate. The action allow-list
        // must reject management verbs even for a fully matched identity.
        var profile = new EncryptedImageProfile(@"D:\repair-image.apfs", "windows-file:1:2:4096:4:scope:0:4096", 0, 4096,
            "11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222", 12, 8, 1, 8, 2, 8,
            "33333333-3333-3333-3333-333333333333", "includes-header");
        var inventoryVolume = new VolumeInfo(@"\\.\PhysicalDrive2|Main", @"\\.\PhysicalDrive2", "Main", false,
            RecoveryIdentity: profile.Contract, CatalogVolumeId: profile.VolumeId,
            CatalogContainerUuid: profile.ContainerUuid, CatalogVolumeObjectId: profile.VolumeObjectId,
            CatalogVolumeUuid: profile.VolumeUuid, RegisteredImage: profile);
        var mounted = NewMountedVolume(MountAccessMode.ReadOnly) with
        {
            CatalogVolumeId = profile.VolumeId,
            CatalogContainerUuid = profile.ContainerUuid,
            CatalogVolumeObjectId = profile.VolumeObjectId,
            CatalogVolumeUuid = profile.VolumeUuid,
            RecoveryIdentity = profile.Contract,
        };
        var status = NewPayload(
            RuntimeState.MountedRo,
            writeEnabled: false,
            mountedVolumes:
            [
                mounted
            ],
            nativeWriteSafetyState: NativeWriteSafetyState.ReadOnlyFallback,
            recoveryActive: false,
            dirtyTransactionCount: 0) with
        {
            ConnectedInventory = [new(new(@"\\.\PhysicalDrive2", "APFS USB Device", true), [inventoryVolume])],
        };

        var row = Assert.Single(DriveDashboardPresenter.BuildRows(status));

        foreach (var command in new[] { "manage", "format", "volume-create", "volume-delete" })
        {
            var error = Assert.Throws<InvalidOperationException>(
                () => DriveDashboardPresenter.CreateSelectedRequest(status, row, command));
            Assert.Contains("unavailable", error.Message, StringComparison.OrdinalIgnoreCase);
        }
    }

    [Fact]
    public void CreateManagementPlanRequest_BuildsValidatedPlanPayload()
    {
        var (status, row) = NewContainerIdentifiedSelection();

        var request = DriveDashboardPresenter.CreateManagementPlanRequest(
            status, row, ApfsManagementOperations.RenameVolume);

        Assert.Equal(ApfsControlCommands.ManagementPlan, request.Command);
        Assert.Equal(ApfsManagementOperations.RenameVolume, request.ManagementOperation);
        Assert.Null(request.ManagementToken);
        Assert.True(Guid.TryParseExact(request.OperationId, "D", out _));
    }

    [Fact]
    public void CreateManagementApplyRequest_BuildsRenameAndQuotaPayloads()
    {
        var (status, row) = NewContainerIdentifiedSelection();

        var rename = DriveDashboardPresenter.CreateManagementApplyRequest(
            status, row, ApfsManagementOperations.RenameVolume, "token-1", name: "Data2", imagePath: @"D:\img.apfs");
        Assert.Equal(ApfsControlCommands.ManagementApply, rename.Command);
        Assert.Equal("token-1", rename.ManagementToken);
        Assert.Equal("Data2", rename.ManagementName);
        Assert.Null(rename.ManagementQuotaBytes);

        var quota = DriveDashboardPresenter.CreateManagementApplyRequest(
            status, row, ApfsManagementOperations.SetQuotaReserve, "token-2", quotaBytes: "100", reserveBytes: "50", imagePath: @"D:\img.apfs");
        Assert.Equal("100", quota.ManagementQuotaBytes);
        Assert.Equal("50", quota.ManagementReserveBytes);
        Assert.Equal(@"D:\img.apfs", quota.ManagementImagePath);
        Assert.Null(quota.ManagementName);
    }

    [Fact]
    public void CreateManagementRequest_RejectsUnknownOperationMixedParametersAndIdentityDrift()
    {
        var (status, row) = NewContainerIdentifiedSelection();

        Assert.Throws<InvalidOperationException>(() =>
            DriveDashboardPresenter.CreateManagementPlanRequest(status, row, "format"));
        Assert.Throws<InvalidOperationException>(() =>
            DriveDashboardPresenter.CreateManagementApplyRequest(
                status, row, ApfsManagementOperations.RenameVolume, "t", name: "Data2",
                imagePath: @"D:\img.apfs", quotaBytes: "1"));
        Assert.Throws<InvalidOperationException>(() =>
            DriveDashboardPresenter.CreateManagementApplyRequest(
                status, row, ApfsManagementOperations.RenameVolume, "  "));
        var drifted = row with { RecoveryIdentity = "drifted" };
        Assert.Throws<InvalidOperationException>(() =>
            DriveDashboardPresenter.CreateManagementPlanRequest(status, drifted, ApfsManagementOperations.RenameVolume));
    }

    private static (StatusChangedPayload, DriveDashboardRow) NewContainerIdentifiedSelection()
    {
        var status = WindowsSurfaceFixture.Status();
        return (status, Assert.Single(DriveDashboardPresenter.BuildRows(status)));
    }

    [Fact]
    public void ContainerWithoutExactVerificationEvidenceIsRefusedAndManageStaysDisabled()
    {
        var payload = NewPayload(
            RuntimeState.MountedRw,
            writeEnabled: true,
            mountedVolumes:
            [
                NewMountedVolume(MountAccessMode.ReadWrite)
            ],
            nativeWriteSafetyState: NativeWriteSafetyState.PilotReadWrite,
            recoveryActive: false,
            dirtyTransactionCount: 0);

        var rows = DriveDashboardPresenter.BuildRows(payload);

        Assert.False(DriveDashboardPresenter.ContainerVerifyAvailable(rows));
        Assert.False(DriveDashboardPresenter.ContainerManageAvailable(rows));
        Assert.False(ContainerVolumeVerification.TryCapture(payload, rows, out _, out _));
        Assert.Contains("offline container member", DriveDashboardPresenter.ContainerUnavailableActionReason("container-manage"), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void FormatSpaceBytes_UsesSizedUnitsWithTwoDecimals()
    {
        Assert.Equal("0 bytes", DriveDashboardPresenter.FormatSpaceBytes(0));
        Assert.Equal("999 bytes", DriveDashboardPresenter.FormatSpaceBytes(999));
        Assert.Equal("1.00 KB", DriveDashboardPresenter.FormatSpaceBytes(1024));
        Assert.Equal("4.00 KB", DriveDashboardPresenter.FormatSpaceBytes(4096));
        Assert.Equal("1.50 MB", DriveDashboardPresenter.FormatSpaceBytes(1572864));
        Assert.Equal("2.50 GB", DriveDashboardPresenter.FormatSpaceBytes(2684354560));
        Assert.Equal("2.50 GB", DriveDashboardPresenter.FormatByteSize(2684354560));
        Assert.Equal("0 bytes", DriveDashboardPresenter.FormatByteSize(-5));
    }

    [Fact]
    public void BuildRows_ClassifiesReadOnlyVolumeAsYellowAndEnablesFix()
    {
        var payload = NewPayload(
            RuntimeState.MountedRo,
            writeEnabled: false,
            mountedVolumes:
            [
                NewMountedVolume(MountAccessMode.ReadOnly)
            ],
            nativeWriteSafetyState: NativeWriteSafetyState.ReadOnlyFallback,
            recoveryActive: false,
            dirtyTransactionCount: 0);

        var rows = DriveDashboardPresenter.BuildRows(payload);

        var row = Assert.Single(rows);
        Assert.Equal(DriveDashboardState.ReadOnly, row.State);
        Assert.Equal("Read-only", row.StateText);
        Assert.Equal(DashboardPalette.Yellow, row.Palette);
        Assert.True(row.CanFix);
        Assert.True(row.CanEject);
        Assert.True(row.CanOpen);
    }

    [Fact]
    public void BuildRows_ClassifiesRecoveryBlockedAsProblemWhenMountStateHasNoVolumeRows()
    {
        var payload = NewPayload(
            RuntimeState.MountedRw,
            writeEnabled: false,
            mountedVolumes: [],
            nativeWriteSafetyState: NativeWriteSafetyState.RecoveryBlocked,
            recoveryActive: true,
            recoveryReason: "ReplayCanonicalCandidateMissing");

        var row = Assert.Single(DriveDashboardPresenter.BuildRows(payload));

        Assert.Equal(DriveDashboardState.Problem, row.State);
        Assert.Equal(DashboardPalette.Red, row.Palette);
        Assert.True(row.CanFix);
        Assert.Contains("Current recovery reason: ReplayCanonicalCandidateMissing", row.FixGuidance);
    }

    [Fact]
    public void BuildRows_IgnoresStaleWarningsWhenMountedVolumeIsHealthyReadWrite()
    {
        var payload = NewPayload(
            RuntimeState.MountedRw,
            writeEnabled: true,
            mountedVolumes:
            [
                NewMountedVolume(MountAccessMode.ReadWrite)
            ],
            nativeWriteSafetyState: NativeWriteSafetyState.PilotReadWrite,
            warnings: ["Drive status refresh is delayed."]);

        var row = Assert.Single(DriveDashboardPresenter.BuildRows(payload));

        Assert.Equal(DriveDashboardState.HealthyReadWrite, row.State);
        Assert.Equal(DashboardPalette.Green, row.Palette);
        Assert.False(row.CanFix);
        Assert.Contains(row.Details, detail => detail.Contains("Drive status refresh is delayed.", StringComparison.Ordinal));
    }

    [Fact]
    public void BuildRows_UsesMountedReadWriteVolumeWhenTopLevelFlagsLag()
    {
        var payload = NewPayload(
            RuntimeState.MountedRw,
            writeEnabled: false,
            mountedVolumes:
            [
                NewMountedVolume(MountAccessMode.ReadWrite)
            ],
            nativeWriteSafetyState: NativeWriteSafetyState.ReadOnlyFallback,
            warnings: ["Native write was temporarily unavailable during startup."],
            compatibilityWarnings: ["Stale startup diagnostic"]);

        var row = Assert.Single(DriveDashboardPresenter.BuildRows(payload));

        Assert.Equal(DriveDashboardState.HealthyReadWrite, row.State);
        Assert.Equal("Healthy read/write", row.StateText);
        Assert.Equal(DashboardPalette.Green, row.Palette);
        Assert.False(row.CanFix);
        Assert.Contains(row.Details, detail => detail.Contains("Native write was temporarily unavailable", StringComparison.Ordinal));
    }

    [Fact]
    public void BuildRows_UsesMountedReadWriteVolumeWhenRecoveryFlagsLag()
    {
        var payload = NewPayload(
            RuntimeState.MountedRw,
            writeEnabled: true,
            mountedVolumes:
            [
                NewMountedVolume(MountAccessMode.ReadWrite)
            ],
            nativeWriteSafetyState: NativeWriteSafetyState.RecoveryBlocked,
            recoveryActive: true,
            recoveryReason: "stale startup probe",
            warnings: ["Native write was temporarily unavailable during startup."]);

        var row = Assert.Single(DriveDashboardPresenter.BuildRows(payload));

        Assert.Equal(DriveDashboardState.HealthyReadWrite, row.State);
        Assert.Equal(DashboardPalette.Green, row.Palette);
        Assert.False(row.CanFix);
        Assert.Contains(row.Details, detail => detail == "Recovery: active");
        Assert.Contains(row.Details, detail => detail == "Recovery reason: stale startup probe");
    }

    [Fact]
    public void BuildRows_ClassifiesMountedRecoveryBlockedReadOnlyVolumeAsProblem()
    {
        var payload = NewPayload(
            RuntimeState.MountedRo,
            writeEnabled: false,
            mountedVolumes:
            [
                NewMountedVolume(MountAccessMode.ReadOnly)
            ],
            nativeWriteSafetyState: NativeWriteSafetyState.RecoveryBlocked,
            recoveryActive: true,
            recoveryReason: "checkpoint replay blocked");

        var row = Assert.Single(DriveDashboardPresenter.BuildRows(payload));

        Assert.Equal(DriveDashboardState.Problem, row.State);
        Assert.Equal(DashboardPalette.Red, row.Palette);
        Assert.True(row.CanFix);
        Assert.Contains("Current recovery reason: checkpoint replay blocked", row.FixGuidance);
    }

    [Fact]
    public void BuildRows_ClassifiesPendingWriteBackAsFinishingWrites()
    {
        var payload = NewPayload(
            RuntimeState.MountedRw,
            writeEnabled: true,
            mountedVolumes:
            [
                NewMountedVolume(MountAccessMode.ReadWrite)
            ],
            nativeWriteSafetyState: NativeWriteSafetyState.PilotReadWrite,
            dirtyTransactionCount: 2);

        var row = Assert.Single(DriveDashboardPresenter.BuildRows(payload));

        Assert.Equal(DriveDashboardState.FinishingWrites, row.State);
        Assert.Equal("Finishing writes", row.StateText);
        Assert.Equal(DashboardPalette.Blue, row.Palette);
        Assert.False(row.CanFix);
        Assert.Contains("Wait a moment before unplugging", row.Summary);
    }

    [Fact]
    public void BuildRows_DoesNotClassifyTransientCallbacksAsFinishingWrites()
    {
        var payload = NewPayload(
            RuntimeState.MountedRw,
            writeEnabled: true,
            mountedVolumes:
            [
                NewMountedVolume(MountAccessMode.ReadWrite)
            ],
            nativeWriteSafetyState: NativeWriteSafetyState.PilotReadWrite,
            dirtyTransactionCount: 0,
            inFlightMutationCallbacks: 2);

        var row = Assert.Single(DriveDashboardPresenter.BuildRows(payload));

        Assert.Equal(DriveDashboardState.HealthyReadWrite, row.State);
        Assert.Equal("Healthy read/write", row.StateText);
        Assert.Contains(row.Details, detail => detail == "Active file operations: 2");
    }

    [Fact]
    public void BuildRows_ReturnsIdlePlaceholderWhenNoVolumeMounted()
    {
        var payload = NewPayload(
            RuntimeState.Idle,
            writeEnabled: false,
            mountedVolumes: []);

        var row = Assert.Single(DriveDashboardPresenter.BuildRows(payload));

        Assert.Equal(DriveDashboardState.Idle, row.State);
        Assert.Equal(DashboardPalette.Gray, row.Palette);
        Assert.Equal("No APFS drives mounted", row.DeviceName);
        Assert.False(row.CanOpen);
        Assert.False(row.CanEject);
        Assert.False(row.CanFix);
    }

    [Fact]
    public void BuildRows_EnablesFixWhenUnmountedDriveWasSafelyEjected()
    {
        var payload = NewPayload(
            RuntimeState.Idle,
            writeEnabled: false,
            mountedVolumes: [],
            warnings: ["'Main' is safely ejected; unplug and reinsert it to mount again."]);

        var row = Assert.Single(DriveDashboardPresenter.BuildRows(payload));

        Assert.Equal(DriveDashboardState.Attention, row.State);
        Assert.Equal(DashboardPalette.Orange, row.Palette);
        Assert.False(row.CanEject);
        Assert.True(row.CanFix);
        Assert.Contains("safely ejected", row.Summary, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void BuildRows_ReturnsProblemPlaceholderWhenServiceReportsErrorWithoutMountedVolume()
    {
        var payload = NewPayload(
            RuntimeState.Error,
            writeEnabled: false,
            mountedVolumes: []);

        var row = Assert.Single(DriveDashboardPresenter.BuildRows(payload));

        Assert.Equal(DriveDashboardState.Problem, row.State);
        Assert.Equal(DashboardPalette.Red, row.Palette);
        Assert.Equal("APFS Access needs attention", row.DeviceName);
        Assert.True(row.CanFix);
    }

    [Fact]
    public void BuildRows_PrefersDeviceAndVolumeNamesAndNormalizesDriveLabel()
    {
        var payload = NewPayload(
            RuntimeState.MountedRw,
            writeEnabled: true,
            mountedVolumes:
            [
                NewMountedVolume(
                    MountAccessMode.ReadWrite,
                    deviceDisplayName: "Samsung Flash Drive FIT USB Device",
                    volumeName: "Main",
                    mountPoint: "e:\\")
            ],
            nativeWriteSafetyState: NativeWriteSafetyState.PilotReadWrite);

        var row = Assert.Single(DriveDashboardPresenter.BuildRows(payload));

        Assert.Equal("Samsung Flash Drive FIT USB Device", row.DeviceName);
        Assert.Equal("Main", row.VolumeName);
        Assert.Equal("E:", row.MountPoint);
        Assert.Contains(row.Details, detail => detail == "Backend: Native");
        Assert.Contains(row.Details, detail => detail == "Warnings: none");
    }

    [Fact]
    public void BuildSummary_ReportsMountedVolumeCountAndWorstState()
    {
        var payload = NewPayload(
            RuntimeState.MountedRo,
            writeEnabled: false,
            mountedVolumes:
            [
                NewMountedVolume(MountAccessMode.ReadOnly)
            ],
            nativeWriteSafetyState: NativeWriteSafetyState.ReadOnlyFallback);

        var summary = DriveDashboardPresenter.BuildSummary(payload);

        Assert.Equal("1 APFS drive mounted. Attention may be needed.", summary);
    }

    [Fact]
    public void BuildSummary_StillReportsWorstMountedStateForMixedVolumes()
    {
        var payload = NewPayload(
            RuntimeState.MountedRw,
            writeEnabled: true,
            mountedVolumes:
            [
                NewMountedVolume(MountAccessMode.ReadWrite, mountPoint: "P:\\"),
                NewMountedVolume(MountAccessMode.ReadOnly, mountPoint: "Q:\\")
            ],
            nativeWriteSafetyState: NativeWriteSafetyState.PilotReadWrite);

        var summary = DriveDashboardPresenter.BuildSummary(payload);

        Assert.Equal("2 APFS drives mounted. Attention may be needed.", summary);
    }

    private static StatusChangedPayload NewPayload(
        RuntimeState state,
        bool writeEnabled,
        IReadOnlyList<MountedVolumeDisplay> mountedVolumes,
        NativeWriteSafetyState nativeWriteSafetyState = NativeWriteSafetyState.ReadOnlyFallback,
        bool recoveryActive = false,
        string? recoveryReason = null,
        int dirtyTransactionCount = 0,
        bool shutdownDrainActive = false,
        int inFlightMutationCallbacks = 0,
        IReadOnlyList<string>? warnings = null,
        IReadOnlyList<string>? compatibilityWarnings = null,
        IReadOnlyList<NativeWriteDiagnostic>? diagnostics = null)
    {
        return new StatusChangedPayload(
            State: state,
            MountPoints: mountedVolumes
                .Select(static volume => volume.MountPoint)
                .Where(static mountPoint => !string.IsNullOrWhiteSpace(mountPoint))
                .ToArray(),
            LastError: state == RuntimeState.Error ? "Mount failed" : null,
            TimestampUtc: DateTime.UtcNow,
            Warnings: warnings ?? Array.Empty<string>(),
            WriteEnabled: writeEnabled,
            CompatibilityWarnings: compatibilityWarnings ?? Array.Empty<string>(),
            MountedVolumes: mountedVolumes,
            WriteBackend: "Native",
            CommitModel: NativeWriteCommitModel.CanonicalApfsCheckpoint,
            NativeWriteReadiness: NativeWriteReadiness.CommitReady,
            NativeWriteEngineState: NativeWriteEngineState.HardwareValidated,
            NativeWriteValidationState: NativeWriteValidationState.HardwarePilotValidated,
            RecoveryActive: recoveryActive,
            RecoveryReason: recoveryReason,
            LastCommitXid: 10316,
            NativeWriteSafetyState: nativeWriteSafetyState,
            DirtyTransactionCount: dirtyTransactionCount,
            ShutdownDrainActive: shutdownDrainActive,
            InFlightMutationCallbacks: inFlightMutationCallbacks,
            NativeWriteDiagnostics: diagnostics);
    }

    private static MountedVolumeDisplay NewMountedVolume(
        MountAccessMode accessMode,
        string deviceDisplayName = "APFS USB Device",
        string volumeName = "Main",
        string mountPoint = "E:\\")
    {
        return new MountedVolumeDisplay(
            VolumeId: @"\\.\PhysicalDrive2|Main",
            MountPoint: mountPoint,
            VolumeName: volumeName,
            DeviceId: @"\\.\PhysicalDrive2",
            DeviceDisplayName: deviceDisplayName,
            AccessMode: accessMode);
    }
}
