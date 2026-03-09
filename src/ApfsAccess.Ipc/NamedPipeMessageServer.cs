using System.Collections.Concurrent;
using System.IO.Pipes;

namespace ApfsAccess.Ipc;

public sealed class NamedPipeMessageServer
{
    private readonly string _pipeName;

    public NamedPipeMessageServer(string pipeName)
    {
        _pipeName = string.IsNullOrWhiteSpace(pipeName)
            ? throw new ArgumentException("Pipe name cannot be null or whitespace.", nameof(pipeName))
            : pipeName;
    }

    public async Task RunAsync(Func<PipePeer, CancellationToken, Task> clientHandler, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(clientHandler);

        var activeClients = new ConcurrentDictionary<int, Task>();
        var clientCounter = 0;

        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                var serverStream = new NamedPipeServerStream(
                    _pipeName,
                    PipeDirection.InOut,
                    NamedPipeServerStream.MaxAllowedServerInstances,
                    PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous
                );

                try
                {
                    await serverStream.WaitForConnectionAsync(cancellationToken).ConfigureAwait(false);
                }
                catch
                {
                    serverStream.Dispose();
                    throw;
                }

                var clientId = Interlocked.Increment(ref clientCounter);
                var task = Task.Run(async () =>
                {
                    await using var peer = new PipePeer(serverStream);
                    try
                    {
                        await clientHandler(peer, cancellationToken).ConfigureAwait(false);
                    }
                    catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                    {
                        // Expected during shutdown.
                    }
                }, cancellationToken);

                activeClients[clientId] = task;
                _ = task.ContinueWith(
                    _ =>
                    {
                        activeClients.TryRemove(clientId, out Task? removedTask);
                    },
                    CancellationToken.None,
                    TaskContinuationOptions.ExecuteSynchronously,
                    TaskScheduler.Default
                );
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // Expected during shutdown.
        }

        await Task.WhenAll(activeClients.Values).ConfigureAwait(false);
    }
}

