namespace ApfsAccess.Core;

// Discovery is permission to request native admission, never a graph/write proof.
public sealed record BackupImageWriteCandidate(string ContainerUuid, string VolumeUuid,
    ulong VolumeObjectId, ulong CheckpointXid, ulong StoreSizeBytes,
    ulong StoreOffsetBytes = 0, string? PartitionUuid = null);

public static class BackupImageMountPolicy
{
    public const string PhysicalRecoveryBridgeRequired =
        "BackupPhysicalAcceptedRecoveryBridgeRequired: physical backup writes require a held-window accepted-recovery owner; read-only inspection remains available.";

    public static bool ConfigurationAllows(ServiceHostOptions options) =>
        (options.EnableBackupImageWrites || HeldConfigurationAllows(options)) && WriteGatePolicy.EvaluateForRequest(options).AllowWrite &&
        string.Equals(options.WriteBackendMode, "Native", StringComparison.OrdinalIgnoreCase) &&
        string.Equals(options.WriteSafetyLevel, "Strict", StringComparison.OrdinalIgnoreCase) &&
        options.NativeWriteStrictMode && options.NativeWriteRequireCanonicalCommit &&
        options.NativeWriteIntegrityCheckOnMount && !options.NativeWriteAllowLegacyScaffoldForFixtures &&
        !options.AllowWriteOnUnsupportedFeatures &&
        options.NativeWriteMaxDirtyTransactions == 1 &&
        string.Equals(options.NativeWriteRecoveryPolicy, "FailClosed", StringComparison.OrdinalIgnoreCase) &&
        string.Equals(options.NativeWriteCrashReplayMode, "ReplayIfSafe", StringComparison.OrdinalIgnoreCase) &&
        VolumeTopologyProfile.LocalPath(options.ManagementJournalRoot);

    private static bool HeldConfigurationAllows(ServiceHostOptions options) =>
        options.EnableBackupHeldWrites && options.NativeWriteAllowRawPhysicalDevices &&
        options.RawSnapshotHardwareQualification is { Scheme: RawSnapshotHardwareQualificationScheme.QualifiedSerialTuple,
            BusType: 7, Vendor.Length: > 0, Product.Length: > 0, QualifiedSerial.Length: > 0, QualifiedVpdType: null };

    public static bool HasCandidate(VolumeInfo row) => row.BackupImageWrite is { } candidate &&
        !row.IsEncrypted && row.SupportsExplorerMount && row.RegisteredImage is null && row.RegisteredFusion is null &&
        (candidate.PartitionUuid is null ? VolumeTopologyProfile.LocalPath(row.DeviceId) && candidate.StoreOffsetBytes == 0 :
            VolumePhysicalBinding.IsDevicePath(row.DeviceId) && candidate.StoreOffsetBytes > 0 &&
            candidate.StoreOffsetBytes % 4096 == 0 && VolumeTopologyProfile.Uuid(candidate.PartitionUuid)) &&
        candidate.VolumeObjectId > 0 && candidate.CheckpointXid > 0 &&
        candidate.StoreSizeBytes is > 0 and <= (256UL << 20) && candidate.StoreSizeBytes % 4096 == 0 &&
        row.CatalogDecision == ApfsCapabilityDecision.Readable && row.CatalogAutoMountAllowed == false &&
        row.CatalogReasons is { Count: 1 } && row.CatalogReasons[0] == "special-role:backup" &&
        TopologyAdmission.SameUuid(candidate.ContainerUuid, row.CatalogContainerUuid) &&
        TopologyAdmission.SameUuid(candidate.VolumeUuid, row.CatalogVolumeUuid) &&
        candidate.VolumeObjectId == row.CatalogVolumeObjectId &&
        row.VolumeId == ApfsTopology.BuildVolumeId(Guid.Parse(candidate.ContainerUuid).ToString("N"), candidate.VolumeObjectId) &&
        !string.IsNullOrWhiteSpace(row.RecoveryIdentity);

    public static bool CanRequest(ServiceHostOptions options, VolumeInfo row) =>
        ConfigurationAllows(options) && HasCandidate(row) &&
        (row.BackupImageWrite!.PartitionUuid is null ? options.EnableBackupImageWrites : HeldConfigurationAllows(options)) &&
        string.IsNullOrEmpty(row.NativeWriteAdmissionBlockReason);

    public static bool AllowsExplicitMount(ServiceHostOptions options, VolumeInfo row, MountAccessMode? mode) =>
        mode == MountAccessMode.ReadWrite && CanRequest(options, row);

    public static BackupImageWriteCandidate? Observe(VolumeInfo row, ApfsDiscoveryTopology? observation)
    {
        if (observation is null || observation.DeviceId != row.DeviceId || observation.Generation <= 0 ||
            (!VolumeTopologyProfile.LocalPath(row.DeviceId) && !VolumePhysicalBinding.IsDevicePath(row.DeviceId)) || row.IsEncrypted) return null;
        var t = observation.Snapshot;
        if (TopologyGraphIndex.Create(t) is not { Complete: true }) return null;
        var physical = VolumePhysicalBinding.IsDevicePath(row.DeviceId);
        if (t.Disks.Count != 1 || t.Containers.Count != 1 || t.Stores.Count != 1 || t.Volumes.Count != 1 ||
            t.Partitions.Count != (physical ? 1 : 0) || t.Groups.Count != 0 || observation.DiskIds.Count != 1) return null;
        var disk = t.Disks[0]; var container = t.Containers[0]; var store = t.Stores[0]; var volume = t.Volumes[0];
        var partition = physical ? t.Partitions[0] : null;
        if (physical && (partition!.Id != store.PartitionId || partition.DiskId != disk.Id ||
            !VolumeTopologyProfile.Uuid(partition.Uuid) || !TopologyAdmission.SameUuid(store.Uuid, partition.Uuid) ||
            partition.StartByte <= 0 || partition.StartByte % 4096 != 0 ||
            partition.StartByte != store.OffsetBytes || partition.SizeBytes < store.SizeBytes ||
            partition.StartByte > disk.SizeBytes || partition.SizeBytes > disk.SizeBytes - partition.StartByte ||
            !TopologyAdmission.SameUuid(partition.TypeGuid, "7c3457ef-0000-11aa-aa11-00306543ecac"))) return null;
        if (disk.DeviceIdentifier != row.DeviceId || disk.Id != observation.DiskIds[0] ||
            volume.Id != row.CatalogVolumeId || volume.Id != row.VolumeId ||
            volume.ContainerId != container.Id || store.ContainerId != container.Id ||
            (physical ? store.DiskId is not null : store.DiskId != disk.Id) || (!physical && (!string.IsNullOrEmpty(store.PartitionId) || store.OffsetBytes != 0 ||
            store.SizeBytes != disk.SizeBytes)) || store.SizeBytes is <= 0 or > (256L << 20) ||
            store.SizeBytes % 4096 != 0 || container.BlockSizeBytes != 4096 || container.Fusion ||
            container.StoreIds.Count != 1 || container.StoreIds[0] != store.Id ||
            container.VolumeIds.Count != 1 || container.VolumeIds[0] != volume.Id ||
            volume.RoleRaw != 0x180 || volume.Roles.Count != 1 || volume.Roles[0] != "backup" ||
            volume.Locked || volume.EncryptionMode != "none" || volume.GroupId is not null ||
            volume.UnknownFeatureBits.Count != 0 || volume.IncompatibleFeatureBits.Count != 0 ||
            (volume.ReadonlyFeatureBits?.Count ?? 0) != 0 || container.UnknownFeatureBits.Count != 0 ||
            container.IncompatibleFeatureBits.Count != 0 || (container.ReadonlyFeatureBits?.Count ?? 0) != 0 ||
            !TopologyAdmission.SameUuid(volume.Uuid, row.CatalogVolumeUuid) ||
            !TopologyAdmission.SameUuid(container.Uuid, row.CatalogContainerUuid) ||
            !ulong.TryParse(volume.ObjectId, System.Globalization.NumberStyles.None,
                System.Globalization.CultureInfo.InvariantCulture, out var oid) || oid != row.CatalogVolumeObjectId ||
            !ulong.TryParse(container.CheckpointXid, System.Globalization.NumberStyles.None,
                System.Globalization.CultureInfo.InvariantCulture, out var xid) || xid == 0) return null;
        var candidate = new BackupImageWriteCandidate(container.Uuid, volume.Uuid, oid, xid, (ulong)store.SizeBytes,
            (ulong)store.OffsetBytes, partition?.Uuid);
        return HasCandidate(row with { BackupImageWrite = candidate }) ? candidate : null;
    }
}
