using System.Reflection;
using ApfsAccess.Core;

namespace ApfsAccess.Backend.Native.Tests;

[Collection("ManagementQuotaEndpointEnvironment")]
public sealed class ManagementRenameEndpointTests
{
    [Fact] public async Task BackendWaitsForOwnerGateAndRejectsUnregisteredOrChangedOriginalBeforeTransport()
    {
        var root=Path.Combine(Path.GetTempPath(),"rename-endpoint-"+Guid.NewGuid().ToString("N"));
        foreach(var folder in new[]{"journal","spool","recovery"})Directory.CreateDirectory(Path.Combine(root,folder));
        var source=Path.Combine(root,"source.apfs");var image=Path.Combine(root,"image.apfs");
        using(var f=File.Create(source))f.SetLength(1048576);
        File.Copy(source,image);
        var spool=Environment.GetEnvironmentVariable("APFSACCESS_SPOOL_ROOT");var recovery=Environment.GetEnvironmentVariable("APFSACCESS_RECOVERY_ROOT");
        Environment.SetEnvironmentVariable("APFSACCESS_SPOOL_ROOT",Path.Combine(root,"spool"));
        Environment.SetEnvironmentVariable("APFSACCESS_RECOVERY_ROOT",Path.Combine(root,"recovery"));
        var runner=new NoNativeContact();
        var options=new ServiceHostOptions{NativeAutoDiscoverPhysicalDrives=false,EnableImageManagementMutations=true,
            ManagementJournalRoot=Path.Combine(root,"journal"),OrdinaryManagementImages=[new(source,image)]};
        var request=new ManagementKeeperRenameRequest(image,new string('a',32),new string('b',32),"101","7","Exact",options.ManagementJournalRoot);
        using var backend=new NativeApfsBackend(options,lifecycleTestHooks:null,observerRunner:runner,observerPathOverride:Path.Combine(root,"absent.exe"));
        Assert.IsAssignableFrom<IManagementRenameKeeper>(backend);
        try
        {
            var gate=(SemaphoreSlim)typeof(NativeApfsBackend).GetField("_gate",BindingFlags.Instance|BindingFlags.NonPublic)!.GetValue(backend)!;
            await gate.WaitAsync();Task<ManagementKeeperRenameResult> pending;
            try{pending=backend.RenameVolumeAsync(request,default);Assert.False(pending.IsCompleted);}
            finally{gate.Release();}
            var missing=await pending;Assert.False(missing.Committed);Assert.Contains("OrdinaryImageOriginalLaunchOwnershipMissing",missing.Detail);
            // The real fresh-copy producer, rather than a fabricated provenance record.
            var destination=Path.Combine(root,"fresh.apfs");
            NativeOrdinaryImageOwnership.RegisterFreshCopy(new(source,destination),options.ManagementJournalRoot,Path.Combine(root,"spool"),Path.Combine(root,"recovery"));
            options.OrdinaryManagementImages=[new(source,destination)];
            using var fresh=new NativeApfsBackend(options,lifecycleTestHooks:null,observerRunner:runner,observerPathOverride:Path.Combine(root,"absent.exe"));
            var current=request with{ImagePath=destination};
            var prior=Path.Combine(root,"spool","prior.wal");File.WriteAllText(prior,"unproved prior runtime evidence");
            var history=await fresh.RenameVolumeAsync(current,default);
            Assert.False(history.Committed);Assert.Contains("ManagementRenamePriorRuntimeEvidenceUnsupported",history.Detail);
            File.Move(prior,Path.Combine(root,"preserved-prior.wal"));
            var intent=NativeApfsVolumeRename.JournalDirFor(options.ManagementJournalRoot,destination);
            Directory.CreateDirectory(intent);File.WriteAllText(Path.Combine(intent,"accepted-original.txt"),"Unproved prior accepted intent must remain untouched.");
            var intentRefusal=await fresh.RenameVolumeAsync(current,default);
            Assert.False(intentRefusal.Committed);Assert.Contains("ManagementRenamePriorIntentUnsupported",intentRefusal.Detail);
            Directory.Move(intent,Path.Combine(root,"preserved-prior-intent"));
            using(var file=new FileStream(destination,FileMode.Open,FileAccess.Write,FileShare.None)){file.Position=500;file.WriteByte(1);}
            var changed=await fresh.RenameVolumeAsync(current,default);
            Assert.False(changed.Committed);Assert.Contains("ManagementRenameFreshPreimageRequired",changed.Detail);
            using(var file=new FileStream(destination,FileMode.Open,FileAccess.Write,FileShare.None)){file.Position=500;file.WriteByte(0);}
            var start=new System.Diagnostics.ProcessStartInfo("never-executed.exe");
            start.Environment["APFSACCESS_SPOOL_ROOT"]=Path.Combine(root,"spool");start.Environment["APFSACCESS_RECOVERY_ROOT"]=Path.Combine(root,"recovery");
            _=NativeOrdinaryImageOwnership.CaptureLaunch(start,options.ManagementJournalRoot,destination,"0",
                [new(ApfsTopology.BuildVolumeId(new string('a',32),101),destination,"Historical",true,
                    RecoveryIdentity:NativeApfsBackend.BuildRecoveryIdentityFromComponents(null,new string('a',32),101,true),
                    CatalogContainerUuid:new string('a',32),CatalogVolumeUuid:new string('b',32),CatalogVolumeObjectId:101)]);
            var launched=await fresh.RenameVolumeAsync(current,default);
            Assert.False(launched.Committed);Assert.Contains("ManagementRenameOriginalWalOrMarkerMissing",launched.Detail);
            using var stop=new CancellationTokenSource();stop.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(()=>fresh.RenameVolumeAsync(current,stop.Token));
            fresh.Dispose();
            await Assert.ThrowsAsync<ObjectDisposedException>(()=>fresh.RenameVolumeAsync(current,default));
            Assert.Equal(0,runner.Calls);
            using var original=File.OpenRead(source);Assert.Equal(0,original.ReadByte());
            File.WriteAllText(Path.Combine(root,"result.txt"),"PASS owner-gate, missing original, real fresh registration, prior runtime evidence, prior intent, changed preimage, captured launch history, cancellation and disposal; native contacts=0");
        }
        finally{Environment.SetEnvironmentVariable("APFSACCESS_SPOOL_ROOT",spool);Environment.SetEnvironmentVariable("APFSACCESS_RECOVERY_ROOT",recovery);}
    }
    private sealed class NoNativeContact : IObserverRunner
    {
        internal int Calls;
        public ObserverRunResult Run(string executable,IReadOnlyList<string> arguments)=>Run(executable,arguments,default);
        public ObserverRunResult Run(string executable,IReadOnlyList<string> arguments,CancellationToken token)
        {++Calls;throw new InvalidOperationException("Refused inputs cannot contact native tools.");}
    }
}
