using ApfsAccess.Core;
using ApfsAccess.Ipc;

namespace ApfsAccess.Service;

public sealed class OfflineImageOperationException(string code, string message) : IOException(message)
{
    public string Code { get; } = code;
}

public sealed partial class ApfsMountWorker
{
    internal string? ConfiguredManagementJournalRoot => _optionsMonitor.CurrentValue.ManagementJournalRoot;

    // The gate covers discovery, quiesce and the entire offline tool lifetime.
    // Polling, mount, unlock and shutdown cannot acquire a competing owner here.
    public async Task<T> WithMountOperationsPausedAsync<T>(Func<CancellationToken, Task<T>> operation,
        CancellationToken cancellationToken)
    {
        using var notifications = new DeferredNotifications(this);
        await _mountOperationLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (Volatile.Read(ref _shutdownRequested) != 0)
                throw new OfflineImageOperationException(ApfsOperationCodes.ServiceUnavailable, "Service shutdown has started.");
            ++_mountOperationGeneration;
            return await operation(cancellationToken).ConfigureAwait(false);
        }
        finally { _mountOperationLock.Release(); }
    }

    public Task<ImageVerifyResult?> VerifyOfflineVolumeAsync(ApfsControlTarget target, bool quiesceSelected,
        CancellationToken cancellationToken)
        => _backend is not IVerifyBackend ? Task.FromResult<ImageVerifyResult?>(null) :
            WithOfflineVolumeAsync(target, quiesceSelected, VerifyImageAsync, cancellationToken);

    public Task<T> WithOfflineVolumeAsync<T>(ApfsControlTarget target, bool quiesceSelected,
        Func<VerifyScope, CancellationToken, Task<T>> operation, CancellationToken cancellationToken)
        => WithMountOperationsPausedAsync(async token =>
        {
            var (device, volume, scope) = await ObserveOfflineTargetAsync(target, token).ConfigureAwait(false);
            if (VolumeIntentBlocks(scope.ImagePath)) throw new OfflineImageOperationException(ApfsOperationCodes.BlockedRecovery,
                "Volume management intent requires reconciliation before offline access.");
            var admittedTarget = SelectedControlTarget.Create(device, volume);
            var mounts = await _backend.GetMountStateAsync(token).ConfigureAwait(false);
            var affected = mounts.Where(m => SameOfflineSource(m, device, volume)).ToArray();
            if (affected.Length != 0)
            {
                if (!quiesceSelected || affected.Length != 1 || !SelectedControlTarget.MatchesMount(target, affected[0]))
                    throw new OfflineImageOperationException(ApfsOperationCodes.UnsafeOwnership,
                        "quiesce-required: Unmount every volume using this image before offline verification or repair.");
                var warnings = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                var detached = await UnmountAsync(affected, token, warnings).ConfigureAwait(false);
                foreach (var mount in detached.Removed) _userEjectedVolumeIds.Add(mount.VolumeId);
                foreach (var mount in detached.UnsafeRemoved) _unsafeUnmountedVolumeIds.Add(mount.VolumeId);
                var result = detached.Results.GetValueOrDefault(affected[0].VolumeId);
                mounts = await _backend.GetMountStateAsync(token).ConfigureAwait(false);
                PublishFromMounts(mounts, null, warnings, []);
                if (result is not { Success: true, MountRemoved: true, HostOwnershipReleased: true, PendingDurabilityCleared: true } ||
                    mounts.Any(m => SameOfflineSource(m, device, volume)))
                    throw new OfflineImageOperationException(ApfsOperationCodes.UnsafeOwnership,
                        "quiesce-unproven: Offline verification requires released ownership and proven durable teardown.");
                // Teardown may publish a newer checkpoint. Never verify the pre-drain XID.
                (device, volume, scope) = await ObserveOfflineTargetAsync(admittedTarget, token).ConfigureAwait(false);
            }
            if (device.Volumes.Any(v => _unsafeUnmountedVolumeIds.Contains(v.VolumeId)))
                throw new OfflineImageOperationException(ApfsOperationCodes.UnsafeOwnership,
                    "quiesce-unproven: A previous unsafe teardown still owns recovery debt for this image.");
            return await operation(scope, token).ConfigureAwait(false);
        }, cancellationToken);

    public bool HasUnsafeOfflineTeardown(DeviceInventory device)
        => device.Volumes.Any(v => _unsafeUnmountedVolumeIds.Contains(v.VolumeId));

    private async Task<(DeviceInventory Device, VolumeInfo Volume, VerifyScope Scope)> ObserveOfflineTargetAsync(
        ApfsControlTarget target, CancellationToken cancellationToken)
    {
        var discovery = await DiscoverVolumesAsync(cancellationToken).ConfigureAwait(false);
        if (!TryAdmitDiscovery(discovery) || !SelectedControlTarget.Matches(discovery.Inventory, target))
            throw new OfflineImageOperationException(ApfsOperationCodes.AmbiguousTarget,
                "The selected image identity or topology changed before offline verification.");
        var device = discovery.Inventory.Single(d => string.Equals(d.Device.DeviceId, target.DeviceId, StringComparison.OrdinalIgnoreCase));
        var volume = device.Volumes.Single(v => string.Equals(v.VolumeId, target.VolumeId, StringComparison.OrdinalIgnoreCase));
        var derived = VerifyScopeDerivation.TryDerive(device, volume);
        if (!derived.Ok || derived.Scope is null)
            throw new OfflineImageOperationException(ApfsOperationCodes.ServiceUnavailable,
                $"verify:skipped:{derived.Code} {derived.Detail}");
        return (device, volume, derived.Scope);
    }

    private static bool SameOfflineSource(MountedVolumeState mount, DeviceInventory device, VolumeInfo volume)
        => string.Equals(mount.DeviceId, device.Device.DeviceId, StringComparison.OrdinalIgnoreCase) ||
            TopologyAdmission.SameUuid(mount.CatalogContainerUuid, volume.CatalogContainerUuid);
}
