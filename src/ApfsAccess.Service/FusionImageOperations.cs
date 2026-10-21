using ApfsAccess.Core;
using ApfsAccess.Ipc;

namespace ApfsAccess.Service;

public sealed partial class ApfsMountWorker
{
    private IFusionImageBackend FusionBackend => _backend as IFusionImageBackend ?? throw new InvalidOperationException("Fusion images require the native backend.");
    public long ReserveFusionCommand() => Interlocked.Increment(ref _mountCommandGeneration);

    public async Task RegisterFusionImageAsync(FusionImageProfile profile, long generation, CancellationToken token)
    {
        await _mountOperationLock.WaitAsync(token).ConfigureAwait(false);
        try
        {
            if (Volatile.Read(ref _shutdownRequested) != 0 || generation != Volatile.Read(ref _mountCommandGeneration))
                throw new InvalidOperationException("Fusion registration was superseded.");
            await FusionBackend.RegisterFusionImageAsync(profile, token).ConfigureAwait(false);
        }
        finally { _mountOperationLock.Release(); }
    }

    public async Task<MountResult> MountSelectedFusionAsync(ApfsControlTarget target, long generation, CancellationToken token)
    {
        using var notifications = new DeferredNotifications(this);
        await _mountOperationLock.WaitAsync(token).ConfigureAwait(false);
        try
        {
            ++_mountOperationGeneration;
            var discovery = await DiscoverVolumesAsync(token).ConfigureAwait(false);
            if (Volatile.Read(ref _shutdownRequested) != 0 || generation != Volatile.Read(ref _mountCommandGeneration) ||
                target.RegisteredFusion is null || !TryAdmitDiscovery(discovery) || !SelectedControlTarget.Matches(discovery.Inventory, target))
                throw new InvalidOperationException("The exact selected Fusion pair changed before mount.");
            var mounts = await _backend.GetMountStateAsync(token).ConfigureAwait(false);
            if (mounts.Any(m => m.VolumeId == target.VolumeId)) throw new InvalidOperationException("A Fusion owner is already registered for this volume.");
            await ValidateSelectedMutationAsync(target, token).ConfigureAwait(false);
            if (generation != Volatile.Read(ref _mountCommandGeneration)) throw new InvalidOperationException("Fusion mount was superseded.");
            var result = await FusionBackend.MountFusionImageAsync(target.RegisteredFusion, token).ConfigureAwait(false);
            if (result.Success) { _userEjectedVolumeIds.Remove(target.VolumeId); _unsafeUnmountedVolumeIds.Remove(target.VolumeId); }
            return result;
        }
        finally { _mountOperationLock.Release(); }
    }

    public async Task RefreshFusionStatusAsync(CancellationToken token)
    {
        await GetInventoryAsync(token).ConfigureAwait(false);
        using var notifications = new DeferredNotifications(this);
        await _mountOperationLock.WaitAsync(token).ConfigureAwait(false);
        try { PublishFromMounts(await _backend.GetMountStateAsync(token).ConfigureAwait(false), null, new HashSet<string>(), []); }
        finally { _mountOperationLock.Release(); }
    }
}
