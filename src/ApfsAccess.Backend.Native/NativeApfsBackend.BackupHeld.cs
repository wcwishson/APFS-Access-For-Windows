using System.Globalization;
using ApfsAccess.Core;

namespace ApfsAccess.Backend.Native;

public sealed partial class NativeApfsBackend
{
    private NativeBackupImageWriteLaunch PrepareBackupHeldForApp(VolumeInfo volume, ulong offset, CancellationToken token)
    {
        if (!BackupImageMountPolicy.CanRequest(_options, volume) || volume.BackupImageWrite is not { PartitionUuid: not null } c ||
            offset != c.StoreOffsetBytes || _options.RawSnapshotHardwareQualification is not { } q)
            throw new IOException("BackupHeldAppAdmissionRequired");
        NativeManagementJournalAdmission.RequireClearRoot(_options.ManagementJournalRoot, true);
        var tool = new[] { Path.Combine(AppContext.BaseDirectory, "VolumePhysicalObserve.exe"),
            Path.Combine(AppContext.BaseDirectory, "native", "VolumePhysicalObserve.exe") }
            .FirstOrDefault(p => File.Exists(p) && NativeApfsObserver.IsPackagedObserverPath(p)) ?? throw new IOException("VolumePhysicalObserveNotPackaged");
        NativeApfsSnapshotReader.ValidateLocalFile(tool);
        var wire = _observerRunner.Run(tool, ["--device", volume.DeviceId,
            "--base", c.StoreOffsetBytes.ToString(CultureInfo.InvariantCulture), "--limit", c.StoreSizeBytes.ToString(CultureInfo.InvariantCulture),
            "--vendor", q.Vendor!, "--product", q.Product!, "--serial", q.QualifiedSerial!,
            "--container", Guid.Parse(c.ContainerUuid).ToString("N"), "--volume", Guid.Parse(c.VolumeUuid).ToString("N"),
            "--oid", c.VolumeObjectId.ToString(CultureInfo.InvariantCulture), "--xid", c.CheckpointXid.ToString(CultureInfo.InvariantCulture)], token);
        return NativeBackupImageWriteLaunch.PrepareHeld(volume, _options.ManagementJournalRoot!, wire, q, token);
    }
}
