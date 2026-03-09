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

        await client.ConnectAsync(timeoutMilliseconds, cancellationToken).ConfigureAwait(false);
        return new PipePeer(client);
    }
}
