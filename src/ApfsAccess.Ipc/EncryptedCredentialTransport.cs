using System.IO.Pipes;
using ApfsAccess.Cli;
namespace ApfsAccess.Ipc;

// The JSON channel contains only selectors and operation identity. A separate,
// one-instance pipe binds APC1 bytes to the exact authenticated control client.
public static class EncryptedCredentialTransport
{
    public static string PipeName(string operationId)
    {
        if (!Guid.TryParseExact(operationId,"D",out var id) || id.ToString("D") != operationId)
            throw new ArgumentException("Invalid credential operation identity.");
        return "ApfsAccess.Unlock."+operationId;
    }
    public static Task<SupervisedCredential> ReceiveAsync(string operationId, int expectedClientPid, long expectedStartTime, CancellationToken token)
        => OperatingSystem.IsWindows() ? ReceiveCoreAsync(operationId,expectedClientPid,expectedStartTime,token,NamedPipeEndpointAuthentication.AuthenticateClient) : throw new PlatformNotSupportedException();
    internal static async Task<SupervisedCredential> ReceiveCoreAsync(string operationId,int expectedClientPid,long expectedStartTime,CancellationToken token,Action<NamedPipeServerStream> authenticate)
    {
        if (!OperatingSystem.IsWindows() || expectedClientPid <= 0 || expectedStartTime <= 0) throw new UnauthorizedAccessException("Authenticated credential client required.");
        using var deadline=CancellationTokenSource.CreateLinkedTokenSource(token); deadline.CancelAfter(TimeSpan.FromSeconds(10));
        await using var pipe = new NamedPipeServerStream(PipeName(operationId),PipeDirection.InOut,1,
            PipeTransmissionMode.Byte,PipeOptions.Asynchronous|PipeOptions.CurrentUserOnly,2048,2048);
        await pipe.WaitForConnectionAsync(deadline.Token).ConfigureAwait(false);
        authenticate(pipe);
        if (WindowsPipeEndpointIdentitySource.Instance.GetClientProcessId(pipe) != expectedClientPid)
            throw new UnauthorizedAccessException("Credential client differs from selected operation owner.");
        using var client=System.Diagnostics.Process.GetProcessById(expectedClientPid);
        if (client.StartTime.ToUniversalTime().Ticks != expectedStartTime) throw new UnauthorizedAccessException("Credential owner changed.");
        await pipe.WriteAsync(new byte[]{1},deadline.Token).ConfigureAwait(false);
        return await SupervisedCredential.ReceiveAsync(pipe,deadline.Token).ConfigureAwait(false);
    }
    public static Task SendAsync(string operationId, SupervisedCredential credential, CancellationToken token)
        => OperatingSystem.IsWindows() ? SendCoreAsync(operationId,credential,token,NamedPipeEndpointAuthentication.AuthenticateServer) : throw new PlatformNotSupportedException();
    internal static async Task SendCoreAsync(string operationId,SupervisedCredential credential,CancellationToken token,Action<NamedPipeClientStream> authenticate)
    {
        using (credential)
        {
            if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
            using var deadline=CancellationTokenSource.CreateLinkedTokenSource(token); deadline.CancelAfter(TimeSpan.FromSeconds(10));
            await using var pipe = new NamedPipeClientStream(".",PipeName(operationId),PipeDirection.InOut,PipeOptions.Asynchronous);
            await pipe.ConnectAsync(deadline.Token).ConfigureAwait(false);
            authenticate(pipe);
            var ready=new byte[1]; await pipe.ReadExactlyAsync(ready,deadline.Token).ConfigureAwait(false);
            if(ready[0]!=1) throw new IOException("Credential transport was refused.");
            await credential.SendAsync(pipe,deadline.Token).ConfigureAwait(false);
        } // EOF is required; an accepted operation is owned by the service after this point.
    }
}
