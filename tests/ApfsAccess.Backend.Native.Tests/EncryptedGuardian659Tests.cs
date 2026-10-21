using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json;
using ApfsAccess.Cli;
namespace ApfsAccess.Backend.Native.Tests;
public sealed class EncryptedGuardian659Tests
{
    [Theory] [InlineData(1)] [InlineData(257)] [InlineData(1024)]
    public async Task ExistingGuardianHandsOnlyCredentialToRealNativeReceiver(int size)
    {
        var probe=Environment.GetEnvironmentVariable("APFSACCESS_CREDENTIAL_PROBE"); Assert.True(File.Exists(probe),"Build the harmless native credential probe before this focused test.");
        var root=Path.Combine(Path.GetTempPath(),"guardian659",Guid.NewGuid().ToString("N"));Directory.CreateDirectory(root);
        var output=Path.Combine(root,"proof.json");using var gate=HostStartupGate.Create(root);
        using var excluded=new EventWaitHandle(false,EventResetMode.ManualReset);
        Assert.True(SetHandleInformation(excluded.SafeWaitHandle.DangerousGetHandle(),1,1));
        var frame=new byte[8+size];BitConverter.GetBytes(0x31435041).CopyTo(frame,0);BitConverter.GetBytes(size).CopyTo(frame,4);
        for(var i=0;i<size;i++)frame[8+i]=(byte)(1+i%255);
        using var input=new MemoryStream(frame);using var credential=await SupervisedCredential.ReceiveAsync(input,default);Array.Clear(frame);
        credential.CreateChildPipe();
        var info=new ProcessStartInfo(probe!) { UseShellExecute=false,CreateNoWindow=true,WorkingDirectory=root };
        foreach(var argument in new[]{output,"normal",excluded.SafeWaitHandle.DangerousGetHandle().ToString(),size.ToString()})info.ArgumentList.Add(argument);
        var launch=HostProcessGuardian.StartWithCredential(info,gate,credential.Reader);
        using var process=launch.Process;using var guardian=launch.Guardian!;
        _ = process.SafeHandle;
        try
        {
            credential.ReleaseLocalReader();credential.Send(default,()=>{if(process.HasExited)throw new IOException("Probe exited");});
            Assert.True(process.WaitForExit(6000)); Assert.Equal(0,process.ExitCode);Assert.True(guardian.WaitForEmpty(TimeSpan.FromSeconds(2)));
            using var result=JsonDocument.Parse(File.ReadAllText(output));var proof=result.RootElement;
            Assert.True(proof.GetProperty("accepted").GetBoolean());Assert.True(proof.GetProperty("exact").GetBoolean());
            Assert.False(proof.GetProperty("excludedInherited").GetBoolean());Assert.False(proof.GetProperty("outputInherited").GetBoolean());
            Assert.Equal(Environment.ProcessId,proof.GetProperty("serverPid").GetInt32());
        }
        finally {if(!process.HasExited) {guardian.TryTerminate(1);Assert.True(process.WaitForExit(5000));}}
    }
    [DllImport("kernel32.dll",SetLastError=true)]private static extern bool SetHandleInformation(nint handle,uint mask,uint flags);
}
