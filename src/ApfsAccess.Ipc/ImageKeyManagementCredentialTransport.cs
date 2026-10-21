using System.IO.Pipes;
using ApfsAccess.Cli;

namespace ApfsAccess.Ipc;

public static class ImageKeyManagementCredentialTransport
{
    public static string PipeName(string operationId)
    {
        if (!Guid.TryParseExact(operationId, "D", out var id) || id.ToString("D") != operationId)
            throw new ArgumentException("Invalid credential operation identity.");
        return "ApfsAccess.KeyManagement." + operationId;
    }

    public static Task<SupervisedCredentialSet> ReceiveAsync(string operationId, int expectedClientPid,
        long expectedStartTime, int expectedCount, CancellationToken token)
        => ReceiveCoreAsync(operationId, expectedClientPid, expectedStartTime, expectedCount, token,
            NamedPipeEndpointAuthentication.AuthenticateClient);

    internal static async Task<SupervisedCredentialSet> ReceiveCoreAsync(string operationId, int expectedClientPid,
        long expectedStartTime, int expectedCount, CancellationToken token, Action<NamedPipeServerStream> authenticate)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        if (expectedClientPid <= 0 || expectedStartTime <= 0 || expectedCount is not (1 or 2))
            throw new UnauthorizedAccessException("Authenticated credential client and exact frame count required.");
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        deadline.CancelAfter(TimeSpan.FromSeconds(10));
        await using var pipe = new NamedPipeServerStream(PipeName(operationId), PipeDirection.InOut, 1,
            PipeTransmissionMode.Byte, PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly, 4096, 4096);
        await pipe.WaitForConnectionAsync(deadline.Token).ConfigureAwait(false);
        authenticate(pipe);
        if (WindowsPipeEndpointIdentitySource.Instance.GetClientProcessId(pipe) != expectedClientPid)
            throw new UnauthorizedAccessException("Credential client differs from selected operation owner.");
        using var client = System.Diagnostics.Process.GetProcessById(expectedClientPid);
        if (client.StartTime.ToUniversalTime().Ticks != expectedStartTime)
            throw new UnauthorizedAccessException("Credential owner changed.");
        await pipe.WriteAsync(new byte[] { 1 }, deadline.Token).ConfigureAwait(false);
        return await SupervisedCredentialSet.ReceiveAsync(pipe, expectedCount, deadline.Token).ConfigureAwait(false);
    }

    public static Task SendAsync(string operationId, SupervisedCredentialSet credentials, CancellationToken token)
        => SendCoreAsync(operationId, credentials, token, NamedPipeEndpointAuthentication.AuthenticateServer);

    internal static async Task SendCoreAsync(string operationId, SupervisedCredentialSet credentials,
        CancellationToken token, Action<NamedPipeClientStream> authenticate)
    {
        using (credentials)
        {
            if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
            deadline.CancelAfter(TimeSpan.FromSeconds(10));
            await using var pipe = new NamedPipeClientStream(".", PipeName(operationId), PipeDirection.InOut, PipeOptions.Asynchronous);
            await pipe.ConnectAsync(deadline.Token).ConfigureAwait(false);
            authenticate(pipe);
            var ready = new byte[1];
            await pipe.ReadExactlyAsync(ready, deadline.Token).ConfigureAwait(false);
            if (ready[0] != 1) throw new IOException("Credential transport was refused.");
            await credentials.SendAsync(pipe, deadline.Token).ConfigureAwait(false);
        }
    }
}
