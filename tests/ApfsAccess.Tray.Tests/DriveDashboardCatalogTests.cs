using ApfsAccess.Core;
using ApfsAccess.Ipc;
using ApfsAccess.Tray;

namespace ApfsAccess.Tray.Tests;

public sealed class DriveDashboardCatalogTests
{
    private const string ContainerHex = "a9cb92d28b7c4b599eab633c7625f491";

    [Fact]
    public void VolumeRowsKeepSiblingRecoveryAndDurabilitySeparateAfterIpcRoundtrip()
    {
        var healthy = new MountedVolumeDisplay("healthy", "R:\\", "Data", "d", "Disk",
            MountAccessMode.ReadWrite, State: RuntimeState.MountedRw, WriteEnabled: true,
            NativeWriteSafetyState: NativeWriteSafetyState.StableReadWrite, MountReady: true,
            LastCommitXid: 101, HasRuntimeStatus: true);
        var recovering = healthy with { VolumeId = "recovery", MountPoint = "S:\\",
            RecoveryActive = true, RecoveryReason = "SiblingRecovery", LastCommitXid = 202 };
        var writing = healthy with { VolumeId = "writing", MountPoint = "T:\\",
            WalAcceptedSequence = 8, WalApfsDurableSequence = 7, LastCommitXid = 303 };
        var readOnly = healthy with { VolumeId = "readonly", MountPoint = "U:\\",
            AccessMode = MountAccessMode.ReadOnly, State = RuntimeState.MountedRo, WriteEnabled = false,
            NativeWriteSafetyState = NativeWriteSafetyState.ReadOnlyFallback };
        var status = NewPayload(RuntimeState.Error, false, [healthy, recovering, writing, readOnly]) with
        { RecoveryActive = true, RecoveryReason = "SiblingRecovery", DirtyTransactionCount = 12, LastCommitXid = 202 };
        var wire = System.Text.Json.JsonSerializer.Serialize(status);
        var restored = System.Text.Json.JsonSerializer.Deserialize<StatusChangedPayload>(wire)!;
        var rows = DriveDashboardPresenter.BuildRows(restored).ToDictionary(row => row.VolumeId);
        Assert.Equal(DriveDashboardState.HealthyReadWrite, rows["healthy"].State);
        Assert.Equal(DashboardPalette.Green, rows["healthy"].Palette);
        Assert.False(rows["healthy"].CanFix);
        Assert.Contains("Dirty transactions: 0", rows["healthy"].Details);
        Assert.Contains("Recovery: inactive", rows["healthy"].Details);
        Assert.Contains("Last commit: 101", rows["healthy"].Details);
        Assert.Equal(DriveDashboardState.Problem, rows["recovery"].State);
        Assert.Equal(DriveDashboardState.FinishingWrites, rows["writing"].State);
        Assert.Equal(DriveDashboardState.ReadOnly, rows["readonly"].State);
        Assert.Equal(DashboardPalette.Yellow, rows["readonly"].Palette);
    }

    [Fact]
    public void RuntimeStatusMustProveReadinessAndCannotMaskRecoveryWithReadWriteMode()
    {
        var volume = new MountedVolumeDisplay("v", "R:\\", "Data", "d", "Disk", MountAccessMode.ReadWrite,
            State: RuntimeState.MountedRw, WriteEnabled: true,
            NativeWriteSafetyState: NativeWriteSafetyState.StableReadWrite, HasRuntimeStatus: true);
        var status = NewPayload(RuntimeState.MountedRw, true, [volume]);
        Assert.Equal(DriveDashboardState.Attention, Assert.Single(DriveDashboardPresenter.BuildRows(status)).State);
        status = status with { MountedVolumes = [volume with { MountReady = true,
            NativeWriteSafetyState = NativeWriteSafetyState.RecoveryBlocked }] };
        Assert.Equal(DriveDashboardState.Problem, Assert.Single(DriveDashboardPresenter.BuildRows(status)).State);
    }

    [Fact]
    public void CatalogSpaceSurvivesIpcAndKeepsUnknownDistinctFromZero()
    {
        const string volumeId = "apfs-vol:" + ContainerHex + ":101";
        var knownZero = new ApfsSpaceAmount(0, 0);
        var observed = new ApfsVolumeSpaceObservation("apfs-container:" + ContainerHex, 7,
            new(100, 409600), new(60, 245760),
            new(volumeId, 101, new(10, 40960), null, new(10, 40960), knownZero, knownZero, null, null));
        var volume = new MountedVolumeDisplay("v", @"D:\PrivateMounts\quota", "Data", "d", "Disk",
            MountAccessMode.ReadWrite, CatalogVolumeId: volumeId, CatalogContainerUuid: ContainerHex,
            CatalogVolumeObjectId: 101, CatalogSpace: observed);
        var wire = System.Text.Json.JsonSerializer.Serialize(volume);
        var restored = System.Text.Json.JsonSerializer.Deserialize<MountedVolumeDisplay>(wire)!;
        var row = Assert.Single(DriveDashboardPresenter.BuildRows(NewPayload(RuntimeState.MountedRw, true, [restored])));
        Assert.Equal(@"D:\PrivateMounts\quota", row.MountPath);
        Assert.Equal(@"D:\PrivateMounts\quota", row.MountPoint);
        Assert.Contains("Volume available at scan: 0 bytes", row.Details);
        Assert.Contains("Snapshot space: Unknown", row.Details);
        Assert.Contains("Purgeable space: Unknown", row.Details);
        Assert.Contains("Volume reservation: None", row.Details);
        Assert.Contains("Space at last scan (checkpoint 7):", row.Details);
        var other = restored with { CatalogVolumeObjectId = 102 };
        var otherRow = Assert.Single(DriveDashboardPresenter.BuildRows(NewPayload(RuntimeState.MountedRw, true, [other])));
        Assert.DoesNotContain(otherRow.Details, line => line.StartsWith("Space at last scan"));
    }

    [Theory]
    [InlineData(ApfsCapabilityDecision.Readable)]
    [InlineData(ApfsCapabilityDecision.Locked)]
    [InlineData(ApfsCapabilityDecision.Unsupported)]
    [InlineData(ApfsCapabilityDecision.Writable)]
    public void CatalogBlockedVolumeDoesNotOfferWritableFix(ApfsCapabilityDecision decision)
    {
        var payload = NewPayload(RuntimeState.MountedRo, false,
            [new MountedVolumeDisplay("v", "R:\\", "System", "d", "Disk", MountAccessMode.ReadOnly,
                CatalogDecision: decision, CatalogReasons: ["special-role:system"], CatalogAutoMountAllowed: false)]);
        var row = Assert.Single(DriveDashboardPresenter.BuildRows(payload));
        Assert.False(row.CanFix);
        Assert.True(row.CanOpen);
        Assert.True(row.CanEject);
        Assert.Contains(row.FixGuidance, guidance => guidance.Contains("prevents writable repair", StringComparison.Ordinal));
    }

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
