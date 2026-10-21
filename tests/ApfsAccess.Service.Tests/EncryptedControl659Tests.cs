using System.Security;
using System.Reflection;
using System.IO.Pipes;
using ApfsAccess.Cli;
using ApfsAccess.Core;
using ApfsAccess.Ipc;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
namespace ApfsAccess.Service.Tests;
public sealed partial class EncryptedControl659Tests
{
    internal static EncryptedImageProfile Profile => new(@"D:\test-image.apfs","windows-file:1:2:4096:4:scope:0:4096",0,4096,
        "11111111-1111-1111-1111-111111111111","22222222-2222-2222-2222-222222222222",12,8,1,8,2,8,
        "33333333-3333-3333-3333-333333333333","includes-header");
    private static SupervisedCredential Credential() { using var s=new SecureString(); s.AppendChar('x'); return SupervisedCredential.FromSecureString(s); }
    private static ControlOperationRequestPayload Request(string command) => new(Guid.NewGuid().ToString("D"),command,
        command=="quit"?null:SelectedControlTarget.ForImage(Profile),ExpiresAtUtc:DateTime.UtcNow.AddSeconds(45));
    [Fact] public async Task DispatcherRegisterUnlockLockReplayAndQueryShareCanonicalService()
    {
        using var h=new Harness();
        var register=await h.Exchange(Request("register-image")); Assert.True(register.Success,register.Diagnostic);
        var request=Request("unlock");
        var unlock=await h.Exchange(request); Assert.True(unlock.Success,unlock.Diagnostic);
        Assert.Equal(EncryptedVolumeState.Unlocked,unlock.EncryptionState); Assert.Equal("read-only",unlock.EffectiveMode);
        Assert.Equal(unlock,await h.Exchange(request)); Assert.Equal(unlock,h.Operations.Query(request.OperationId)); Assert.Equal(1,h.Backend.Unlocks);
        var locked=await h.Exchange(Request("lock")); Assert.True(locked.Success,locked.Diagnostic);
        Assert.Equal("proven",locked.OwnershipProof); Assert.Equal("absent",locked.MountProof); Assert.Empty(h.Backend.Mounts);
        Assert.Equal(1,h.Backend.Stops);
        Assert.All(Directory.GetFiles(h.Root,"*",SearchOption.AllDirectories),p=>Assert.DoesNotContain("credentialClientProcessId",File.ReadAllText(p),StringComparison.OrdinalIgnoreCase));
    }
    [Theory] [InlineData("unlock")] [InlineData("lock")] [InlineData("mount")] [InlineData("fix")]
    public async Task IncorrectIdentityNeverMutates(string command)
    {
        using var h=new Harness(); await h.Operations.ExecuteOrReplayAsync(Request("register-image"));
        var request=Request(command); request=request with { Target=request.Target! with { VolumeUuid=Guid.NewGuid().ToString("D") },RequestedMode=command=="mount"?"read-only":null };
        var result=await h.Operations.ExecuteOrReplayAsync(request); Assert.False(result.Success); Assert.Equal(0,h.Backend.Unlocks+h.Backend.Stops);
    }
    [Theory] [InlineData("mount","read-write")] [InlineData("mount","read-only")] [InlineData("unlock","read-write")]
    public async Task OrdinaryMountAndEncryptedWritesStayClosed(string command,string mode)
    {
        using var h=new Harness(); await h.Operations.ExecuteOrReplayAsync(Request("register-image"));
        var result=await h.Operations.ExecuteOrReplayAsync(Request(command) with { RequestedMode=mode }); Assert.False(result.Success); Assert.Equal(0,h.Backend.Unlocks);
    }
    [Fact] public async Task WrongPasswordIsSanitizedAndRateLimited()
    {
        using var h=new Harness(); await h.Operations.ExecuteOrReplayAsync(Request("register-image"));
        var marker=Guid.NewGuid().ToString("N"); h.Executor.CredentialReceiver=(_,_,_,_)=>throw new IOException(marker);
        var first=await h.Operations.ExecuteOrReplayAsync(Request("unlock")); Assert.False(first.Success); Assert.Equal(EncryptedVolumeState.Failed,first.EncryptionState);
        var next=await h.Operations.ExecuteOrReplayAsync(Request("unlock")); Assert.Equal(ApfsOperationCodes.OperationConflict,next.Code);
        foreach(var p in Directory.GetFiles(h.Root,"*",SearchOption.AllDirectories)) Assert.DoesNotContain(marker,File.ReadAllText(p));
    }
    [Fact] public async Task ExplicitCancellationBeforeCredentialDoesNotMount()
    {
        using var h=new Harness(); await h.Operations.ExecuteOrReplayAsync(Request("register-image"));
        var entered=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        h.Executor.CredentialReceiver=async(_,_,_,ct)=>{ entered.SetResult(); await Task.Delay(Timeout.Infinite,ct); return Credential(); };
        var request=Request("unlock"); var running=h.Operations.ExecuteOrReplayAsync(request); await entered.Task.WaitAsync(TimeSpan.FromSeconds(3));
        await h.Operations.CancelAsync(request.OperationId,CancellationToken.None); var result=await running;
        Assert.False(result.Success); Assert.Equal(0,h.Backend.Unlocks); Assert.Empty(h.Backend.Mounts);
    }
    [Theory] [InlineData("lock")] [InlineData("eject")] [InlineData("quit")]
    public async Task LaterStopSupersedesPendingCredentialWithoutOrphan(string stop)
    {
        using var h=new Harness(); await h.Operations.ExecuteOrReplayAsync(Request("register-image"));
        var entered=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously); var release=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        h.Executor.CredentialReceiver=async(_,_,_,ct)=>{ entered.SetResult(); await release.Task.WaitAsync(ct); return Credential(); };
        var running=h.Operations.ExecuteOrReplayAsync(Request("unlock")); await entered.Task.WaitAsync(TimeSpan.FromSeconds(3));
        var stopped=await h.Operations.ExecuteOrReplayAsync(Request(stop));
        var stoppedState=(await h.Backend.ProbeVolumesAsync(Profile.ImagePath,default)).Single().EncryptionState;
        release.TrySetResult(); var unlock=await running;
        Assert.Equal(stoppedState,(await h.Backend.ProbeVolumesAsync(Profile.ImagePath,default)).Single().EncryptionState);
        Assert.False(unlock.Success); Assert.Equal(0,h.Backend.Unlocks); Assert.Empty(h.Backend.Mounts);
    }
    [Theory] [InlineData(false,true)] [InlineData(true,false)]
    public async Task LockCannotSucceedWithoutOriginalHostAndDirectAbsence(bool host,bool absent)
    {
        using var h=new Harness(); await h.Operations.ExecuteOrReplayAsync(Request("register-image"));
        Assert.True((await h.Operations.ExecuteOrReplayAsync(Request("unlock"))).Success);
        h.Backend.HostProof=host; h.Backend.AbsenceProof=absent;
        var result=await h.Operations.ExecuteOrReplayAsync(Request("lock")); Assert.False(result.Success); Assert.NotEqual(EncryptedVolumeState.Locked,result.EncryptionState);
    }
    [Fact] public async Task DisconnectDoesNotCancelOwnedUnlock()
    {
        using var h=new Harness(); await h.Operations.ExecuteOrReplayAsync(Request("register-image"));
        var entered=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously); var release=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        h.Executor.CredentialReceiver=async(_,_,_,ct)=>{entered.SetResult(); await release.Task.WaitAsync(ct); return Credential();};
        var request=Request("unlock"); var exchange=h.Exchange(request,entered.Task); await entered.Task.WaitAsync(TimeSpan.FromSeconds(3)); release.SetResult();
        await exchange; for(var i=0;i<50 && h.Operations.Query(request.OperationId)?.State==ApfsOperationStates.Accepted;i++) await Task.Delay(20);
        var result=h.Operations.Query(request.OperationId); Assert.True(result?.Success,result?.Diagnostic); Assert.Single(h.Backend.Mounts);
        Assert.True((await h.Operations.ExecuteOrReplayAsync(Request("lock"))).Success);
    }
    [Theory] [InlineData("lock")] [InlineData("eject")]
    public async Task StopDuringHostStartupWaitsForTheOriginalOwner(string command)
    {
        using var h=new Harness(); await h.Operations.ExecuteOrReplayAsync(Request("register-image"));
        h.Backend.PauseUnlock=true;
        var unlock=h.Operations.ExecuteOrReplayAsync(Request("unlock"));
        await h.Backend.UnlockEntered.Task.WaitAsync(TimeSpan.FromSeconds(3));
        var stopping=h.Operations.ExecuteOrReplayAsync(Request(command));
        Assert.False(stopping.IsCompleted); h.Backend.UnlockRelease.SetResult();
        await unlock; var stopped=await stopping; Assert.True(stopped.Success,stopped.Diagnostic);
        Assert.Empty(h.Backend.Mounts); Assert.Equal(1,h.Backend.Unlocks); Assert.Equal(1,h.Backend.Stops);
        Assert.Equal(EncryptedVolumeState.Locked,(await h.Backend.ProbeVolumesAsync(Profile.ImagePath,default)).Single().EncryptionState);
    }

    [Theory] [InlineData(true)] [InlineData(false)]
    public async Task UnlockCannotSucceedWithoutReadyOriginalHost(bool missingReady)
    {
        using var h=new Harness(); await h.Operations.ExecuteOrReplayAsync(Request("register-image"));
        if(missingReady) h.Backend.Ready=false; else h.Backend.HostId=0;
        var result=await h.Operations.ExecuteOrReplayAsync(Request("unlock")); Assert.False(result.Success);
        Assert.Equal(EncryptedVolumeState.Failed,result.EncryptionState);Assert.Single(h.Backend.Mounts);
    }
    [Fact] public async Task LockWithoutOriginalHostCannotUpgradeAlreadyAbsentToProvenSuccess()
    {
        using var h=new Harness(); await h.Operations.ExecuteOrReplayAsync(Request("register-image"));
        var locked=await h.Exchange(Request("lock"));
        Assert.False(locked.Success); Assert.Equal(EncryptedVolumeState.Failed,locked.EncryptionState);
        Assert.Equal("not-proven",locked.OwnershipProof); Assert.Equal(0,h.Backend.Stops);
    }
    private sealed class Harness : IDisposable
    {
        public string Root {get;}=Path.Combine(Path.GetTempPath(),"encrypted659",Guid.NewGuid().ToString("N"));
        public Clock Clock {get;}=new(); public Backend Backend {get;}=new(); public ApfsMountWorker Worker {get;} public AgentControlCommandExecutor Executor {get;}
        public AgentControlOperationService Operations {get;} private TrayPipeHostService Host {get;}
        public Harness()
        {
            var publisher=new RuntimeStatusPublisher(); Worker=new(NullLogger<ApfsMountWorker>.Instance,Backend,new Policy(),publisher,new Options());
            Executor=new(Worker,_=>true,Clock); Executor.CredentialReceiver=(_,_,_,_)=>Task.FromResult(Credential());
            Operations=new(Executor.ExecuteAsync,Root); Host=new(NullLogger<TrayPipeHostService>.Instance,publisher,Worker,new Lifetime(),Operations);
        }
        public async Task<OperationResultPayload> Exchange(ControlOperationRequestPayload request,Task? disconnect=null)
        {
            using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(8)); var pipeName="encrypted659-"+Guid.NewGuid().ToString("N");
            await using var server=new NamedPipeServerStream(pipeName,PipeDirection.InOut,1,PipeTransmissionMode.Byte,PipeOptions.Asynchronous);
            await using var client=new NamedPipeClientStream(".",pipeName,PipeDirection.InOut,PipeOptions.Asynchronous);
            var connected=server.WaitForConnectionAsync(deadline.Token); await client.ConnectAsync(deadline.Token); await connected;
            await using var serverPeer=new PipePeer(server); await using var clientPeer=new PipePeer(client);
            var method=typeof(TrayPipeHostService).GetMethod("HandleClientAsync",BindingFlags.NonPublic|BindingFlags.Instance)!;
            var handler=(Task)method.Invoke(Host,[serverPeer,deadline.Token])!;
            await clientPeer.ReadMessageAsync(deadline.Token);
            await clientPeer.SendAsync(PipeMessageCodec.Create(ApfsMessageTypes.ControlOperationRequest,request,request.OperationId,2),deadline.Token);
            if(disconnect is not null) {await disconnect; await clientPeer.DisposeAsync(); await handler; return Operations.Query(request.OperationId)!;}
            OperationResultPayload? result=null;
            while(result is null) { var response=await clientPeer.ReadMessageAsync(deadline.Token); if(response?.Type==ApfsMessageTypes.OperationResult) {Assert.True(PipeMessageCodec.Validate(response).IsValid,PipeMessageCodec.Validate(response).Diagnostic);PipeMessageCodec.TryGetPayload(response,out result);} }
            await clientPeer.DisposeAsync(); await handler; return result;
        }
        public void Dispose() { Operations.StopAsync(CancellationToken.None).GetAwaiter().GetResult(); Worker.Dispose(); }
    }
    private sealed class Backend : IApfsBackend,IEncryptedImageBackend,IEncryptedImageLockObserver
    {
        public Func<CancellationToken,Task>? BeforeProbe, AfterStopProbe, BeforeStop, BeforeRegister; private EncryptedImageProfile? profile; private EncryptedVolumeState state; public List<MountedVolumeState> Mounts {get;}=[];
        public int Unlocks,Stops; public bool HostProof=true,AbsenceProof=true;
        public bool CleanRetirement, ChangedRetiredSource, ForeignOwner, AmbiguousOwner;
        public int LockObservations;
        public Task<EncryptedImageLockObservation> ObserveLockedImageAsync(EncryptedImageProfile selected,CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested(); LockObservations++;
            return Task.FromResult(CleanRetirement && profile==selected && Mounts.Count==0 && HostProof && AbsenceProof &&
                !ChangedRetiredSource && !ForeignOwner && !AmbiguousOwner ? EncryptedImageLockObservation.AlreadyLocked : EncryptedImageLockObservation.Unproven);
        }
        public ulong? ObservedCheckpoint;
        public bool WriterProof=true; public MountAccessMode? OverrideMode;
        public bool Ready=true;public int HostId=42;public bool PauseUnlock; public TaskCompletionSource UnlockEntered=new(TaskCreationOptions.RunContinuationsAsynchronously),UnlockRelease=new(TaskCreationOptions.RunContinuationsAsynchronously);
        public async Task RegisterEncryptedImageAsync(EncryptedImageProfile p,CancellationToken ct) { if(profile is not null)throw new IOException();profile=p;state=EncryptedVolumeState.Locked; if(BeforeRegister is {} hook) await hook(ct);}
        public void SetEncryptionState(string id,EncryptedVolumeState s) {state=s;}
        private VolumeInfo Volume {
            get {
            var observed=ObservedCheckpoint is {} checkpoint ? profile! with { CheckpointXid=checkpoint } : profile!;
            return new(observed.VolumeId,observed.ImagePath,"Encrypted image",observed.Writable,IsEncrypted:true,RecoveryIdentity:observed.Contract,
            CatalogVolumeId:observed.VolumeId,CatalogContainerUuid:observed.ContainerUuid,CatalogVolumeObjectId:observed.VolumeObjectId,
            CatalogDecision:ApfsCapabilityDecision.Locked,CatalogReasons:["encrypted"],CatalogAutoMountAllowed:false,CatalogVolumeUuid:observed.VolumeUuid,
            RegisteredImage:observed,EncryptionState:state);
            }
        }
        public async Task<IReadOnlyList<DeviceInfo>> ProbeDevicesAsync(CancellationToken ct) { if(Interlocked.Exchange(ref BeforeProbe,null) is {} hook) await hook(ct); return profile is null?[]:[new(profile.ImagePath,"Image",true)]; }
        public Task<IReadOnlyList<VolumeInfo>> ProbeVolumesAsync(string id,CancellationToken ct)=>Task.FromResult<IReadOnlyList<VolumeInfo>>(profile is null?[]:[Volume]);
        public Task<MountResult> MountAsync(MountRequest r,CancellationToken ct)=>throw new InvalidOperationException("Ordinary mount must not run");
        public async Task<MountResult> UnlockEncryptedImageAsync(MountRequest r,EncryptedImageProfile p,SupervisedCredential c,CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested(); Assert.Equal(p.AccessMode,r.AccessMode); Unlocks++;
            CleanRetirement=false;
            if(PauseUnlock) {UnlockEntered.SetResult(); await UnlockRelease.Task.WaitAsync(ct);}
            Mounts.Add(new(p.VolumeId,$"{r.DriveLetter}:\\",OverrideMode??p.AccessMode,DeviceId:p.ImagePath,RecoveryIdentity:p.Contract,
                CatalogVolumeId:p.VolumeId,CatalogContainerUuid:p.ContainerUuid,CatalogVolumeObjectId:p.VolumeObjectId,CatalogVolumeUuid:p.VolumeUuid,MountReady:Ready,HostProcessId:HostId,
                WriteBackend:p.Writable&&WriterProof?"Native":"Disabled",
                CommitModel:p.Writable&&WriterProof?NativeWriteCommitModel.CanonicalApfsCheckpoint:NativeWriteCommitModel.ScaffoldCheckpoint,
                NativeWriteReadiness:p.Writable&&WriterProof?NativeWriteReadiness.CommitReady:NativeWriteReadiness.Unavailable,
                NativeWriteValidationState:p.Writable&&WriterProof?NativeWriteValidationState.CanonicalImageValidated:NativeWriteValidationState.Scaffold,
                RuntimeWatermarksKnown:p.Writable&&WriterProof,LastCommitXid:p.CheckpointXid));
            return new MountResult(true,Mounts[0].MountPoint,null,OverrideMode??p.AccessMode);
        }
        public async Task<UnmountResult> UnmountAsync(string p,CancellationToken ct) { if(BeforeStop is {} hook) await hook(ct); Stops++;if(AbsenceProof)Mounts.Clear();CleanRetirement=HostProof&&AbsenceProof;return new UnmountResult(HostProof&&AbsenceProof,p,null,MountRemoved:AbsenceProof,HostOwnershipReleased:HostProof,PendingDurabilityCleared:true);}
        public async Task<IReadOnlyList<MountedVolumeState>> GetMountStateAsync(CancellationToken ct) { if(Stops>0 && Interlocked.Exchange(ref AfterStopProbe,null) is {} hook) await hook(ct); return Mounts.ToArray(); }
    }
    private sealed class Policy : IMountPolicy { public char SelectDriveLetter(VolumeInfo v,IReadOnlySet<char> used)=>'R'; public bool ShouldAutoMount(VolumeInfo v)=>false; }
    private sealed class Options : IOptionsMonitor<ServiceHostOptions>
    { public ServiceHostOptions CurrentValue {get;}=new(){AutoMountEnabled=false}; public ServiceHostOptions Get(string? name)=>CurrentValue; public IDisposable? OnChange(Action<ServiceHostOptions,string?> listener)=>null; }
    private sealed class Lifetime : IHostApplicationLifetime { public CancellationToken ApplicationStarted=>default;public CancellationToken ApplicationStopping=>default; public CancellationToken ApplicationStopped=>default;public void StopApplication(){} }
}
