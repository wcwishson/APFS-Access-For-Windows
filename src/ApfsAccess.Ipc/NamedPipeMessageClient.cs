using System.IO.Pipes;

namespace ApfsAccess.Ipc;

public static class NamedPipeMessageClient
{
    public static async Task<PipePeer> ConnectAsync(
        string pipeName,
        int timeoutMilliseconds,
        CancellationToken cancellationToken
    )
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(pipeName);
        if (timeoutMilliseconds <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(timeoutMilliseconds));
        }

        var client = new NamedPipeClientStream(
            serverName: ".",
            pipeName,
            PipeDirection.InOut,
            PipeOptions.Asynchronous
        );

        try
        {
            await client.ConnectAsync(timeoutMilliseconds, cancellationToken).ConfigureAwait(false);
            if (NamedPipeEndpointAuthentication.IsRequired(pipeName))
            {
                if (!OperatingSystem.IsWindows())
                {
                    throw new PlatformNotSupportedException(
                        "The production APFS Access pipe requires Windows endpoint authentication.");
                }

                NamedPipeEndpointAuthentication.AuthenticateServer(client);
            }

            return new PipePeer(client);
        }
        catch
        {
            client.Dispose();
            throw;
        }
    }
}
