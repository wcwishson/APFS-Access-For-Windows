using ApfsAccess.Core;
using ApfsAccess.Ipc;
using ApfsAccess.Cli;
namespace ApfsAccess.Service;
public sealed partial class AgentControlCommandExecutor
{
    private readonly System.Collections.Concurrent.ConcurrentDictionary<string,DateTime> _unlockRetryAfter = new(StringComparer.Ordinal);
    internal Func<string,int,long,CancellationToken,Task<SupervisedCredential>> CredentialReceiver { get; set; } = EncryptedCredentialTransport.ReceiveAsync;
    private async Task<OperationResultPayload> ExecuteEncryptionAsync(ControlOperationRequestPayload request,DateTime requested,DateTime started,CancellationToken token)
    {
        OperationResultPayload Fail(string code,string text) => BuildResult(request,requested,started,false,code,"failed",diagnostic:text)
            with { EncryptionState=EncryptedVolumeState.Failed };
        if (request.Target?.RegisteredImage is not {} profile || !SelectedControlTarget.IsWellFormed(request.Target) || request.RequestedMode is not null)
            return Fail(ApfsOperationCodes.InvalidArguments,"An exact registered encrypted image target and its selected access mode are required.");
        long generation=0;
        void UpdateFailureState()
        {
            // A request that never owned a generation, or failed registration,
            // must not relabel an existing mounted owner.
            if(generation!=0 && request.Command!=ApfsControlCommands.RegisterImage)
                _worker.TrySetEncryptionState(profile.VolumeId,EncryptedVolumeState.Failed,generation);
        }
        try
        {
            if(request.Command==ApfsControlCommands.RegisterImage)
            {
                generation=_worker.ReserveEncryptedCommand();
                if(!await _worker.RegisterEncryptedImageAsync(profile,generation,token).ConfigureAwait(false))
                    return Fail(ApfsOperationCodes.OperationConflict,"Registration was superseded; refresh the selected image.");
                return BuildResult(request,requested,started,true,ApfsOperationCodes.OperationSucceeded,"locked") with { EncryptionState=EncryptedVolumeState.Locked };
            }
            var resolution=await ResolveTargetAsync(request.Target,token).ConfigureAwait(false);
            if(!resolution.IsValid) return Fail(resolution.Code,"Registered image selection changed. Refresh before acting.");
            if(request.Command==ApfsControlCommands.Lock)
            {
                generation=_worker.ReserveEncryptedCommand();
                if (profile.Writable && await _worker.ObserveLockedImageAsync(request.Target,generation,token).ConfigureAwait(false) == EncryptedImageLockObservation.AlreadyLocked)
                {
                    if (!_worker.TrySetEncryptionState(profile.VolumeId,EncryptedVolumeState.Locked,generation))
                        return Fail(ApfsOperationCodes.OperationConflict,"A newer command owns this selection; refresh before acting.");
                    return BuildResult(request,requested,started,true,ApfsOperationCodes.AlreadyAchieved,"already-locked",
                        mountProof:"absent",ownershipProof:"proven",durabilityProof:"not-applicable",
                        diagnostic:"Already locked. The recorded clean owner is retired and its namespace is absent.")
                        with { EncryptionState=EncryptedVolumeState.Locked };
                }
                _worker.TrySetEncryptionState(profile.VolumeId,EncryptedVolumeState.Locking,generation);
                var result=await ExecuteEjectAsync(request,requested,started,token,generation).ConfigureAwait(false);
                if(result.Success && (result.OwnershipProof!="proven" || result.MountProof!="absent" || result.DurabilityProof!="proven"))
                    result=result with { Success=false,State=ApfsOperationStates.Failed,Code=ApfsOperationCodes.OperationFailed,FinalStatus="not-proven",
                        Diagnostic="The original host and mount absence were not fully proven. Refresh the selected session." };
                if(!_worker.TrySetEncryptionState(profile.VolumeId,result.Success?EncryptedVolumeState.Locked:EncryptedVolumeState.Failed,generation))
                    return result with { Success=false,State=ApfsOperationStates.Failed,Code=ApfsOperationCodes.OperationConflict,
                        FinalStatus="superseded",EncryptionState=null,Diagnostic="A newer command owns the encrypted image state; refresh before acting." };
                return result with { FinalStatus=result.Success?"locked":result.FinalStatus,
                    EncryptionState=result.Success?EncryptedVolumeState.Locked:EncryptedVolumeState.Failed };
            }
            var now=_timeProvider.GetUtcNow().UtcDateTime;
            // Reserve the next attempt atomically. Competing unlocks cannot consume
            // parallel guesses even before the serialized worker mutation begins.
            lock(_unlockRetryAfter)
            {
                if(_unlockRetryAfter.TryGetValue(profile.Contract,out var retry) && now<retry)
                    return Fail(ApfsOperationCodes.OperationConflict,"Wait 5 seconds before trying to unlock again.");
                _unlockRetryAfter[profile.Contract]=now.AddSeconds(5);
            }
            generation=_worker.ReserveEncryptedCommand();
            _worker.TrySetEncryptionState(profile.VolumeId,EncryptedVolumeState.Unlocking,generation);
            await _worker.GetInventoryAsync(token).ConfigureAwait(false);
            using var credential=await CredentialReceiver(request.OperationId,request.CredentialClientProcessId,request.CredentialClientStartTimeUtcTicks,token).ConfigureAwait(false);
            using var handoff=CancellationTokenSource.CreateLinkedTokenSource(token); handoff.CancelAfter(TimeSpan.FromSeconds(15));
            var outcome=await _worker.UnlockEncryptedImageAsync(request.Target,credential,generation,handoff.Token).ConfigureAwait(false);
            var probe=await ProbeAuthoritativeMountStateAsync().ConfigureAwait(false);
            var mounts=FindExactMounts(probe.Mounts,request.Target);
            var success=outcome && probe.Succeeded && mounts.Count==1 && mounts[0].AccessMode==profile.AccessMode &&
                mounts[0].MountReady && mounts[0].HostProcessId>0 && !mounts[0].RecoveryActive;
            if(success && profile.Writable) success=mounts[0].WriteBackend=="Native" &&
                mounts[0].CommitModel==NativeWriteCommitModel.CanonicalApfsCheckpoint &&
                mounts[0].NativeWriteReadiness==NativeWriteReadiness.CommitReady &&
                mounts[0].NativeWriteValidationState==NativeWriteValidationState.CanonicalImageValidated &&
                mounts[0].RuntimeWatermarksKnown == true && mounts[0].LastCommitXid>=profile.CheckpointXid;
            if(!_worker.TrySetEncryptionState(profile.VolumeId,success?EncryptedVolumeState.Unlocked:EncryptedVolumeState.Failed,generation)) success=false;
            return BuildResult(request,requested,started,success,success?ApfsOperationCodes.OperationSucceeded:ApfsOperationCodes.OperationFailed,
                success?profile.Writable?"unlocked-read-write":"unlocked-read-only":"failed",
                effectiveMode:mounts.Count==1 ? mounts[0].AccessMode==MountAccessMode.ReadWrite?ApfsControlModes.ReadWrite:ApfsControlModes.ReadOnly : null,
                mountProof:success?"present":"not-proven",
                diagnostic:success?profile.Writable?"Unlocked with read/write access to this image.":"Unlocked with read-only access.":"Unlock failed. Check the password and image selectors, then retry.")
                with { EncryptionState=success?EncryptedVolumeState.Unlocked:EncryptedVolumeState.Failed };
        }
        catch(OperationCanceledException)
        {
            UpdateFailureState();
            return Fail(ApfsOperationCodes.OperationCancelled,"Unlock or lock was cancelled; refresh to inspect the owned session.") with { State=ApfsOperationStates.Cancelled };
        }
        catch
        {
            UpdateFailureState();
            return Fail(ApfsOperationCodes.OperationFailed,"Encrypted image operation failed. Refresh and check the image selectors or password.");
        }
        finally
        {
            using var refresh=new CancellationTokenSource(TimeSpan.FromSeconds(2));
            try { await _worker.RefreshEncryptedStatusAsync(refresh.Token).ConfigureAwait(false); } catch { /* Next ordinary inventory cycle reconciles display. */ }
        }
    }
}
