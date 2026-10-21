using ApfsAccess.Core;
using ApfsAccess.Ipc;
using ApfsAccess.Cli;
namespace ApfsAccess.Service;
public sealed partial class ApfsMountWorker
{
    private IEncryptedImageBackend EncryptedBackend => _backend as IEncryptedImageBackend ?? throw new InvalidOperationException("Encrypted images require the native backend.");
    private readonly object _encryptedStateSync = new();
    public bool TrySetEncryptionState(string volumeId,EncryptedVolumeState state,long generation)
    {
        lock(_encryptedStateSync)
        {
            if(generation==0 || generation != Volatile.Read(ref _mountCommandGeneration) || Volatile.Read(ref _shutdownRequested)!=0) return false;
            EncryptedBackend.SetEncryptionState(volumeId,state); return true;
        }
    }
    public async Task<bool> RegisterEncryptedImageAsync(EncryptedImageProfile profile,long generation,CancellationToken token)
    {
        await _mountOperationLock.WaitAsync(token).ConfigureAwait(false);
        try
        {
            if(Volatile.Read(ref _shutdownRequested)!=0 || generation!=Volatile.Read(ref _mountCommandGeneration)) return false;
            await EncryptedBackend.RegisterEncryptedImageAsync(profile,token).ConfigureAwait(false);
            return TrySetEncryptionState(profile.VolumeId,EncryptedVolumeState.Locked,generation);
        }
        finally { _mountOperationLock.Release(); }
    }
    public async Task RefreshEncryptedStatusAsync(CancellationToken token)
    {
        await GetInventoryAsync(token).ConfigureAwait(false);
        using var notifications=new DeferredNotifications(this);
        await _mountOperationLock.WaitAsync(token).ConfigureAwait(false);
        try { var mounts=await _backend.GetMountStateAsync(token).ConfigureAwait(false); PublishFromMounts(mounts,null,new HashSet<string>(),[]); }
        finally { _mountOperationLock.Release(); }
    }
    public async Task WaitForEncryptedTransitionAsync(CancellationToken token)
    {
        await _mountOperationLock.WaitAsync(token).ConfigureAwait(false);
        _mountOperationLock.Release();
    }
    public long ReserveEncryptedCommand() { lock(_encryptedStateSync) return Interlocked.Increment(ref _mountCommandGeneration); }
    public async Task<EncryptedImageLockObservation> ObserveLockedImageAsync(ApfsControlTarget target, long generation, CancellationToken token)
    {
        await _mountOperationLock.WaitAsync(token).ConfigureAwait(false);
        try
        {
            await ValidateSelectedMutationAsync(target, token).ConfigureAwait(false);
            if (Volatile.Read(ref _shutdownRequested) != 0 || generation != Volatile.Read(ref _mountCommandGeneration) ||
                _unsafeUnmountedVolumeIds.Contains(target.VolumeId) || target.RegisteredImage is not {} profile ||
                _backend is not IEncryptedImageLockObserver observer ||
                (await _backend.GetMountStateAsync(token).ConfigureAwait(false)).Any(m => m.VolumeId == target.VolumeId))
                return EncryptedImageLockObservation.Unproven;
            return await observer.ObserveLockedImageAsync(profile, token).ConfigureAwait(false);
        }
        finally { _mountOperationLock.Release(); }
    }
    public async Task<bool> UnlockEncryptedImageAsync(ApfsControlTarget target,SupervisedCredential credential,long generation,CancellationToken token)
    {

        using var notifications=new DeferredNotifications(this);
        await _mountOperationLock.WaitAsync(token).ConfigureAwait(false);
        try
        {
            ++_mountOperationGeneration;
            // Discover after acquiring ownership: teardown may have admitted newer inventory while we waited.
            var discovery=await DiscoverVolumesAsync(token).ConfigureAwait(false);
            Action? notification;
            lock(_discoveryAdmissionSync)
            {
                if(!TryAdmitDiscovery(discovery,out notification))
                {
                    if(_admittedDiscovery is not {} latest || !ReferenceEquals(discovery.Options,latest.Options)) return false;
                    discovery=latest;
                }
            }
            NotifyDiscovery(notification);
            if(Volatile.Read(ref _shutdownRequested)!=0 || generation!=Volatile.Read(ref _mountCommandGeneration) ||
                !SelectedControlTarget.Matches(discovery.Inventory,target)) return false;
            var volume=discovery.Volumes.Single(v=>v.VolumeId==target.VolumeId);
            var mounts=await _backend.GetMountStateAsync(token).ConfigureAwait(false);
            // Namespace absence is not proof that an earlier host released ownership.
            // An unsafe teardown remains blocked even when its mount entry disappeared.
            if(_unsafeUnmountedVolumeIds.Contains(target.VolumeId) || mounts.Any(m=>m.VolumeId==target.VolumeId)) return false;
            var letters=new HashSet<char>(mounts.Select(TryGetDriveLetter).Where(l=>l.HasValue).Select(l=>l!.Value));
            var letter=await SelectDriveLetterForVolumeAsync(volume,letters,discovery.Generation,token).ConfigureAwait(false);
            await ValidateSelectedMutationAsync(target,token).ConfigureAwait(false);
            if(Volatile.Read(ref _shutdownRequested)!=0 || generation!=Volatile.Read(ref _mountCommandGeneration)) return false;
            var result=await EncryptedBackend.UnlockEncryptedImageAsync(new(volume.VolumeId,letter,target.RegisteredImage!.AccessMode),target.RegisteredImage,credential,token).ConfigureAwait(false);
            if(result.Success) { _userEjectedVolumeIds.Remove(volume.VolumeId); _unsafeUnmountedVolumeIds.Remove(volume.VolumeId); }
            return result.Success;
        }
        finally { _mountOperationLock.Release(); }
    }
}
