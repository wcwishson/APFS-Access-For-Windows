using System.Reflection;
using ApfsAccess.Core;

namespace ApfsAccess.Backend.Native.Tests;

[Collection("ManagementQuotaEndpointEnvironment")]
public sealed class RegisteredQuotaFreshAdmissionTests
{
    [Fact] public async Task RegisteredFreshQuotaWaitsForGateAndRejectsUnprovedSourceHistoryWithoutNativeCalls()
    {
        var root=Path.Combine(Path.GetTempPath(),"registered-quota-"+Guid.NewGuid().ToString("N"));
        foreach(var folder in new[]{"journal","spool","recovery"})Directory.CreateDirectory(Path.Combine(root,folder));
        var source=Path.Combine(root,"source.apfs");var image=Path.Combine(root,"image.apfs");
        using(var file=File.Create(source))file.SetLength(1048576);
        var journal=Path.Combine(root,"journal");var spool=Path.Combine(root,"spool");var recovery=Path.Combine(root,"recovery");
        NativeOrdinaryImageOwnership.RegisterFreshCopy(new(source,image),journal,spool,recovery);
        var oldSpool=Environment.GetEnvironmentVariable("APFSACCESS_SPOOL_ROOT");var oldRecovery=Environment.GetEnvironmentVariable("APFSACCESS_RECOVERY_ROOT");
        Environment.SetEnvironmentVariable("APFSACCESS_SPOOL_ROOT",spool);Environment.SetEnvironmentVariable("APFSACCESS_RECOVERY_ROOT",recovery);
        var calls=new NoNativeContact();
        using var backend=new NativeApfsBackend(new ServiceHostOptions{NativeAutoDiscoverPhysicalDrives=false,
            EnableImageManagementMutations=true,ManagementJournalRoot=journal,OrdinaryManagementImages=[new(source,image)]},
            lifecycleTestHooks:null,observerRunner:calls,observerPathOverride:Path.Combine(root,"absent.exe"));
        var request=new ManagementKeeperQuotaRequest(image,new string('a',32),new string('b',32),"101","7","1048576","524288",["102"],journal);
        try
        {
            var prior=Path.Combine(spool,"prior.wal");File.WriteAllText(prior,"Retain this unproved original.");
            var gate=(SemaphoreSlim)typeof(NativeApfsBackend).GetField("_gate",BindingFlags.Instance|BindingFlags.NonPublic)!.GetValue(backend)!;
            await gate.WaitAsync();Task<ManagementKeeperQuotaResult> pending;
            try{pending=backend.SetQuotaReserveAsync(request,default);Assert.False(pending.IsCompleted);}
            finally{gate.Release();}
            var runtime=await pending.WaitAsync(TimeSpan.FromSeconds(3));Assert.False(runtime.Committed);
            Assert.Contains("ManagementQuotaPriorRuntimeEvidenceUnsupported",runtime.Detail);
            Assert.Equal("Retain this unproved original.",File.ReadAllText(prior));File.Move(prior,Path.Combine(root,"preserved-prior.wal"));
            var intent=NativeApfsVolumeQuota.JournalDirFor(journal,image);Directory.CreateDirectory(intent);
            var accepted=Path.Combine(intent,"101.wal");File.WriteAllText(accepted,"Prior accepted bytes cannot be replaced by an empty WAL.");
            var old=await backend.SetQuotaReserveAsync(request,default);Assert.False(old.Committed);Assert.Contains("ManagementQuotaPriorIntentUnsupported",old.Detail);
            Assert.Equal("Prior accepted bytes cannot be replaced by an empty WAL.",File.ReadAllText(accepted));Directory.Move(intent,Path.Combine(root,"preserved-intent"));
            using(var file=new FileStream(image,FileMode.Open,FileAccess.Write,FileShare.None)){file.Position=500;file.WriteByte(1);}
            var changed=await backend.SetQuotaReserveAsync(request,default);Assert.False(changed.Committed);Assert.Contains("ManagementQuotaFreshPreimageRequired",changed.Detail);
            using(var file=new FileStream(image,FileMode.Open,FileAccess.Write,FileShare.None)){file.Position=500;file.WriteByte(0);}
            using(var file=new FileStream(source,FileMode.Open,FileAccess.Write,FileShare.None)){file.Position=500;file.WriteByte(1);}
            var altered=await backend.SetQuotaReserveAsync(request,default);Assert.False(altered.Committed);Assert.Contains("ManagementQuotaOriginalSourceChanged",altered.Detail);
            using(var file=new FileStream(source,FileMode.Open,FileAccess.Write,FileShare.None)){file.Position=500;file.WriteByte(0);}
            using var stop=new CancellationTokenSource();stop.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(()=>backend.SetQuotaReserveAsync(request,stop.Token));
            backend.Dispose();await Assert.ThrowsAsync<ObjectDisposedException>(()=>backend.SetQuotaReserveAsync(request,default));
            Assert.Equal(0,calls.Count);Assert.False(Directory.Exists(intent));
            File.WriteAllText(Path.Combine(root,"result.txt"),"PASS gate waiting, preserved prior runtime/intent, changed source and target, cancellation/disposal; zero native calls.");
        }
        finally{Environment.SetEnvironmentVariable("APFSACCESS_SPOOL_ROOT",oldSpool);Environment.SetEnvironmentVariable("APFSACCESS_RECOVERY_ROOT",oldRecovery);}
    }
    private sealed class NoNativeContact : IObserverRunner
    {
        internal int Count;
        public ObserverRunResult Run(string executable,IReadOnlyList<string> args){++Count;throw new InvalidOperationException("Refused sources cannot reach native tools.");}
    }
}
