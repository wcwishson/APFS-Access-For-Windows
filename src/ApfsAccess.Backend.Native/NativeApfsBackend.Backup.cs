using System.Globalization;
using System.Text.Json;
using ApfsAccess.Core;

namespace ApfsAccess.Backend.Native;

public sealed partial class NativeApfsBackend
{
    private DiscoveredDevice? RetainedBackupDiscovery_NoLock(string image)
    {
        bool Matches(HostProcessState host) => string.Equals(host.BackupImageLaunch?.Selection.Image, image, StringComparison.OrdinalIgnoreCase);
        if (_retainedStartupHosts.Values.Any(Matches)) throw new IOException("BackupImageRetainedOwnerUnproved");
        var owners = _hosts.Values.Where(Matches).Distinct().ToArray();
        if (owners.Length == 0) return null;
        if (owners.Length != 1) throw new IOException("BackupImageRetainedOwnerAmbiguous");
        var owner = owners[0];
        var discovery = owner.BackupImageDiscovery;
        var selection = owner.BackupImageLaunch!.Selection;
        if (owner.ProcessId <= 0 || owner.ProcessCreationTimeFileTimeUtc is not > 0 ||
            TryProbeExactProcessHandleExit(owner.Process) != false ||
            !TryProbeProcessCreationTime(owner.ProcessId, out var creation) || creation != owner.ProcessCreationTimeFileTimeUtc ||
            discovery is null || !string.Equals(discovery.DeviceId, image, StringComparison.OrdinalIgnoreCase) ||
            discovery.Volumes.Count != 1 || discovery.Volumes[0].MountTarget.VolumeObjectId != ulong.Parse(selection.VolumeOid, CultureInfo.InvariantCulture) ||
            !TopologyAdmission.SameUuid(discovery.Volumes[0].CatalogVolumeUuid, selection.VolumeUuid) ||
            !TopologyAdmission.SameUuid(discovery.Volumes[0].MountTarget.ContainerUuidHex, selection.ContainerUuid))
            throw new IOException("BackupImageRetainedInventoryUnproved");
        return discovery;
    }

    private VolumeInfo AttachBackupImageCandidate(VolumeInfo volume, ApfsDiscoveryTopology? topology)
    {
        var candidate = BackupImageMountPolicy.ConfigurationAllows(_options) ? BackupImageMountPolicy.Observe(volume, topology) : null;
        if (candidate is not null && !BackupImageMountPolicy.CanRequest(_options, volume with { BackupImageWrite = candidate }))
            candidate = null;
        if (candidate is null && !VolumeTopologyProfile.LocalPath(volume.DeviceId) && volume.CatalogDecision == ApfsCapabilityDecision.Readable &&
            volume.CatalogReasons is { Count: 1 } && volume.CatalogReasons[0] == "special-role:backup")
            return volume with { SupportsReadWrite = false, SupportsNativeWrite = false,
                NativeWriteReadiness = NativeWriteReadiness.Unavailable,
                WriteBlockReason = BackupImageMountPolicy.PhysicalRecoveryBridgeRequired,
                NativeWriteAdmissionBlockReason = BackupImageMountPolicy.PhysicalRecoveryBridgeRequired };
        if (candidate is null) return volume;
        return volume with { BackupImageWrite = candidate, SupportsReadWrite = true, SupportsNativeWrite = true,
            NativeWriteReadiness = NativeWriteReadiness.BootstrapReady,
            WriteBlockReason = "The bounded backup image requires complete native admission at mount." };
    }

    private NativeBackupImageWriteLaunch PrepareBackupImageForApp(VolumeInfo volume, CancellationToken token)
    {
        if (!BackupImageMountPolicy.CanRequest(_options, volume))
            throw new IOException("BackupImageAppAdmissionRequired");
        var target = ResolveMountTarget(volume);
        if (volume.BackupImageWrite?.PartitionUuid is not null)
            return PrepareBackupHeldForApp(volume, target.DeviceOffsetBytes, token);
        if (target.DeviceOffsetBytes != 0 || target.DevicePath != volume.DeviceId ||
            target.VolumeObjectId != volume.CatalogVolumeObjectId ||
            !TopologyAdmission.SameUuid(target.ContainerUuidHex, volume.CatalogContainerUuid))
            throw new IOException("BackupImageAppSelectionChanged");
        token.ThrowIfCancellationRequested();
        NativeManagementJournalAdmission.RequireImage(_options.ManagementJournalRoot, target.DevicePath, "0");
        token.ThrowIfCancellationRequested();
        var launch = NativeBackupImageWriteLaunch.Prepare(target.DevicePath,
            "apfs-container:" + Guid.Parse(volume.CatalogContainerUuid!).ToString("N"),
            volume.CatalogVolumeObjectId!.Value.ToString(CultureInfo.InvariantCulture), _options.ManagementJournalRoot!, token);
        try { launch.BindDiscoveredSelection(volume); return launch; }
        catch { launch.Dispose(); throw; }
    }

    private static async Task<bool> BackupReadyMatchesAsync(HostProcessState host, CancellationToken token)
    {
        if (host.BackupImageLaunch is null) return true;
        var snapshot = await CaptureRuntimeStatusFileSnapshotAsync(host.StatusFilePath, token).ConfigureAwait(false);
        if (!snapshot.IsStable || snapshot.Content is null) return false;
        try
        {
            using var document = JsonDocument.Parse(snapshot.Content);
            return host.BackupImageLaunch.MatchesReadyStatus(document.RootElement, host.ProcessId);
        }
        catch (JsonException) { return false; }
    }
}
