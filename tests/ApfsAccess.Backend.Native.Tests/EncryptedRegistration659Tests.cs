using ApfsAccess.Core;
namespace ApfsAccess.Backend.Native.Tests;
public sealed class EncryptedRegistration659Tests
{
    private static EncryptedImageProfile Profile(string path,string id) => new(path,id+":scope:0:4096",0,4096,
        "11111111-1111-1111-1111-111111111111","22222222-2222-2222-2222-222222222222",12,8,1,8,2,8,
        "33333333-3333-3333-3333-333333333333","includes-header");
    private static (string Path,EncryptedImageProfile Profile) Image()
    {
        var path=System.IO.Path.Combine(System.IO.Path.GetTempPath(),"image659-"+Guid.NewGuid().ToString("N")+".apfs");
        File.WriteAllBytes(path,new byte[4096]);using var handle=File.OpenHandle(path);
        return(path,Profile(path,NativeApfsBackend.ImageIdentity(handle)));
    }
    [Fact] public async Task RegistrationPinsExactOriginalRegularFileAndReleasesOnDispose()
    {
        var image=Image(); using(var backend=new NativeApfsBackend(new ServiceHostOptions()))
        {
            await backend.RegisterEncryptedImageAsync(image.Profile,default);
            Assert.Throws<IOException>(()=>File.OpenHandle(image.Path,FileMode.Open,FileAccess.Write,FileShare.ReadWrite));
            await Assert.ThrowsAsync<InvalidOperationException>(()=>backend.RegisterEncryptedImageAsync(image.Profile,default));
            var inventory=await backend.ProbeInventoryAsync(true,default);var volume=Assert.Single(Assert.Single(inventory).Volumes);
            Assert.Equal(image.Profile,volume.RegisteredImage);Assert.True(volume.IsEncrypted);Assert.False(volume.SupportsReadWrite);
            Assert.Equal(EncryptedVolumeState.Locked,volume.EncryptionState);
            var direct=Assert.Single(await backend.ProbeVolumesAsync(image.Path,default));
            Assert.Equal((volume.VolumeId,volume.RegisteredImage,volume.EncryptionState),(direct.VolumeId,direct.RegisteredImage,direct.EncryptionState));
        }
        using(var writable=File.OpenHandle(image.Path,FileMode.Open,FileAccess.Write,FileShare.Read)){} File.Delete(image.Path);
    }
    [Theory] [InlineData(true)] [InlineData(false)]
    public async Task IdentityMismatchAndMemberBoundsFailBeforeAnyHost(bool identity)
    {
        var image=Image();using(var backend=new NativeApfsBackend(new ServiceHostOptions()))
        {
            var profile=identity?image.Profile with {SourceId="windows-file:0:0:4096:0:scope:0:4096"}:image.Profile with {StoreSize=4097};
            await Assert.ThrowsAsync<InvalidOperationException>(()=>backend.RegisterEncryptedImageAsync(profile,default));
            Assert.Empty(await backend.ProbeInventoryAsync(true,default));
        }
        File.Delete(image.Path);
    }
    [Fact] public async Task ActualBackendLaunchArgumentsBindFullNativeScopeAndNeverUseDisplayNameAsSelector()
    {
        var image=Image(); System.Diagnostics.ProcessStartInfo? captured=null;
        var hooks=new HostProcessLifecycleTestHooks {StartProcess=psi=>{captured=psi;return null!;}};
        var host=Environment.GetEnvironmentVariable("APFSACCESS_TEST_FSHOST");
        Assert.True(File.Exists(host),"An explicit native host path is required; StartProcess below intercepts every launch.");
        using(var backend=new NativeApfsBackend(new ServiceHostOptions {NativeFsHostPath=host},hooks))
        {
            await backend.RegisterEncryptedImageAsync(image.Profile,default);
            var volume=Assert.Single(await backend.ProbeVolumesAsync(image.Path,default));
            using var secret=new System.Security.SecureString();secret.AppendChar('x');
            using var credential=ApfsAccess.Cli.SupervisedCredential.FromSecureString(secret);
            var start=typeof(NativeApfsBackend).GetMethod("StartHostProcess",System.Reflection.BindingFlags.NonPublic|System.Reflection.BindingFlags.Instance)!;
            Assert.Throws<System.Reflection.TargetInvocationException>(()=>start.Invoke(backend,[volume,"R:\\",MountAccessMode.ReadOnly,credential]));
            Assert.NotNull(captured);var args=captured.ArgumentList.ToArray();
            Assert.DoesNotContain("--volume",args);Assert.DoesNotContain("--recovery-identity",args);Assert.DoesNotContain("--readwrite",args);
            Assert.Equal(image.Profile.SourceId,args[Array.IndexOf(args,"--encrypted-source-id")+1]);
            Assert.EndsWith(":scope:0:4096",image.Profile.SourceId);
            Assert.Equal("Disabled",args[Array.IndexOf(args,"--write-backend")+1]);
            Assert.Equal("12",args[Array.IndexOf(args,"--volume-oid")+1]);
            Assert.Equal(Guid.Parse(image.Profile.ContainerUuid).ToString("N"),args[Array.IndexOf(args,"--container-id")+1]);
            Assert.Contains("--readonly",args);Assert.Contains("--parent-pid",args);Assert.Contains("--lifetime-file",args);
        }
        File.Delete(image.Path);
    }
    [Fact] public async Task CancellationDoesNotRegisterOrHoldImage()
    {
        var image=Image(); using(var backend=new NativeApfsBackend(new ServiceHostOptions()))
        {
            using var cancel=new CancellationTokenSource();cancel.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(()=>backend.RegisterEncryptedImageAsync(image.Profile,cancel.Token));
        }
        using(var writable=File.OpenHandle(image.Path,FileMode.Open,FileAccess.Write,FileShare.Read)){} File.Delete(image.Path);
    }
}
