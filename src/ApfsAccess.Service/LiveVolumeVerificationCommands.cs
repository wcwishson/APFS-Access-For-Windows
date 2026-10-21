using ApfsAccess.Core;
using ApfsAccess.Ipc;

namespace ApfsAccess.Service;

public sealed partial class ApfsMountWorker
{
    public Task<LiveVolumeVerificationReport?> TryVerifyLiveVolumeAsync(ApfsControlTarget target, CancellationToken token,
        bool metadataOnly = false)
        => WithMountOperationsPausedAsync<LiveVolumeVerificationReport?>(async ct =>
        {
            var mounts = await _backend.GetMountStateAsync(ct).ConfigureAwait(false);
            var owners = mounts.Where(m => string.Equals(m.DeviceId, target.DeviceId, StringComparison.OrdinalIgnoreCase) ||
                TopologyAdmission.SameUuid(m.CatalogContainerUuid, target.ContainerUuid)).ToArray();
            if (owners.Length == 0) return null;
            var inventory = _admittedDiscovery?.Inventory;
            if (inventory is null || !SelectedControlTarget.Matches(inventory, target))
                throw new OfflineImageOperationException(ApfsOperationCodes.AmbiguousTarget, "Refresh the selected verification identity.");
            var device = inventory.Single(d => string.Equals(d.Device.DeviceId, target.DeviceId, StringComparison.OrdinalIgnoreCase));
            var volume = device.Volumes.Single(v => v.VolumeId == target.VolumeId);
            var exact = owners.Where(m => SelectedControlTarget.MatchesMount(target, m)).ToArray();
            if (_backend is not ILiveVolumeVerificationBackend live || exact.Length != 1 ||
                exact[0] is not { VolumeVerificationSupported: true, VolumeVerificationScope: {} scope } ||
                !TopologyAdmission.SameUuid(scope.ContainerUuid, volume.CatalogContainerUuid) ||
                !TopologyAdmission.SameUuid(scope.VolumeUuid, volume.CatalogVolumeUuid) ||
                scope.VolumeOid != volume.CatalogVolumeObjectId?.ToString(System.Globalization.CultureInfo.InvariantCulture) ||
                !CatalogMountPolicy.AllowsOrdinaryMount(volume) || volume.IsEncrypted || volume.RegisteredImage is not null)
                throw new OfflineImageOperationException(ApfsOperationCodes.ServiceUnavailable, "VolumeVerificationOwnerRefused: Live verification is unavailable for the exact owner.");
            // Scope and checkpoint come from this retained owner, never a reopened observer.
            var result = await (metadataOnly ? live.VerifyLiveVolumeMetadataAsync(scope, ct) :
                live.VerifyLiveVolumeAsync(scope, ct)).ConfigureAwait(false);
            if (!result.Success || result.Report is null)
                throw new OfflineImageOperationException(ApfsOperationCodes.OperationFailed, result.Code);
            var report = LiveVolumeVerificationReport.Parse(result.Report.Json);
            if (report.Scope != scope)
                throw new OfflineImageOperationException(ApfsOperationCodes.AmbiguousTarget, "VolumeVerificationScopeChanged");
            return report;
        }, token);
}
