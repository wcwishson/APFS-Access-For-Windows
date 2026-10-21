using ApfsAccess.Core;

namespace ApfsAccess.Backend.Native.Tests;

public sealed class EncryptedZeroBagRegistrationTests : IDisposable
{
    private readonly string path = Path.Combine(Path.GetTempPath(),"zero-bag-"+Guid.NewGuid().ToString("N")+".apfs");
    private EncryptedImageProfile Profile()
    {
        File.WriteAllBytes(path,new byte[8192]); using var handle=File.OpenHandle(path);
        return new(path,NativeApfsBackend.ImageIdentity(handle)+":scope:0:8192",0,8192,
            "11111111-1111-1111-1111-111111111111","22222222-2222-2222-2222-222222222222",1026,7,0,7,0,7,
            "33333333-3333-3333-3333-333333333333","includes-header");
    }
    [Fact] public async Task ZeroKeybagHeaderIdsRegisterWithoutChangingVolumeIdentityOrStartingHost()
    {
        var profile=Profile(); Assert.True(profile.IsValid());
        using var backend=new NativeApfsBackend(new ServiceHostOptions());
        await backend.RegisterEncryptedImageAsync(profile,default);
        var volume=Assert.Single(await backend.ProbeVolumesAsync(path,default));
        Assert.Equal(profile,volume.RegisteredImage); Assert.Equal((ulong)1026,volume.CatalogVolumeObjectId);
        Assert.Equal(EncryptedVolumeState.Locked,volume.EncryptionState); Assert.False(volume.SupportsReadWrite);
    }
    [Fact] public async Task VolumeAndGenerationGuardsAndExactFileBindingStillRefuse()
    {
        var profile=Profile();
        foreach(var bad in new[]{profile with {VolumeObjectId=0},profile with {CheckpointXid=0},
            profile with {ContainerBagXid=0},profile with {VolumeBagXid=0},profile with {SourceId=""}})
            Assert.False(bad.IsValid());
        using var backend=new NativeApfsBackend(new ServiceHostOptions());
        await Assert.ThrowsAsync<InvalidOperationException>(()=>backend.RegisterEncryptedImageAsync(
            profile with {SourceId="windows-file:0:0:8192:0:scope:0:8192"},default));
        using var cancel=new CancellationTokenSource();cancel.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(()=>backend.RegisterEncryptedImageAsync(profile,cancel.Token));
    }
    [Fact] public void PersistedPublicSelectorsKeepZeroBagIdsAndNonzeroVolumeAndGenerations()
    {
        var profile=Profile();
        var options=new System.Text.Json.JsonSerializerOptions {IgnoreReadOnlyProperties=true};
        var encoded=System.Text.Json.JsonSerializer.Serialize(profile,options);
        var decoded=System.Text.Json.JsonSerializer.Deserialize<EncryptedImageProfile>(encoded)!;
        Assert.Equal(profile,decoded); Assert.True(decoded.IsValid()); Assert.Equal(profile.Contract,decoded.Contract);
        var args=decoded.HostArguments().ToArray();
        foreach(var flag in new[]{"--encrypted-container-bag-oid","--encrypted-volume-bag-oid"})
            Assert.Equal("0",args[Array.IndexOf(args,flag)+1]);
        Assert.Equal("1026",args[Array.IndexOf(args,"--volume-oid")+1]);
        Assert.Equal("7",args[Array.IndexOf(args,"--encrypted-checkpoint-xid")+1]);
        Assert.True((profile with {ContainerBagOid=1,VolumeBagOid=2}).IsValid());
    }
    public void Dispose(){if(File.Exists(path))File.Delete(path);}
}
