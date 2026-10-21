using System.Threading.Channels;

namespace ApfsAccess.Ipc;

public sealed class AgentControlClient : IAsyncDisposable
{
    private readonly PipePeer _peer;
    private readonly CancellationTokenSource _receiveCancellation;
    private readonly Channel<PipeEnvelope> _replies = Channel.CreateBounded<PipeEnvelope>(
        new BoundedChannelOptions(1) { SingleWriter = true, SingleReader = true });
    private readonly Task _receiver;
    private readonly object _disposeSync = new();
    private Task? _disposeTask;

    public StatusChangedPayload InitialStatus { get; }
    public StatusChangedPayload ValidatedInitialStatus => InitialStatus;

    private AgentControlClient(PipePeer peer, StatusChangedPayload initialStatus, CancellationToken cancellationToken)
    {
        _peer = peer;
        InitialStatus = initialStatus;
        _receiveCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        _receiver = ReceiveAsync();
    }

    public static async Task<AgentControlClient> ConnectAsync(
        PipePeer peer, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(peer);
        try
        {
            var greeting = await peer.ReadMessageAsync(cancellationToken).ConfigureAwait(false);
            var status = RequireStatus(greeting);
            return new AgentControlClient(peer, status, cancellationToken);
        }
        catch
        {
            await peer.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    public static async Task<AgentControlClient> ConnectAsync(
        string pipeName, int timeoutMilliseconds, CancellationToken cancellationToken)
    {
        var peer = await NamedPipeMessageClient.ConnectAsync(
            pipeName, timeoutMilliseconds, cancellationToken).ConfigureAwait(false);
        try
        {
            return await ConnectAsync(peer, cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            throw;
        }
    }

    public Task SendAsync(PipeEnvelope message, CancellationToken cancellationToken)
        => _peer.SendAsync(message, cancellationToken);

    public async Task<PipeEnvelope?> ReadMessageAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        while (await _replies.Reader.WaitToReadAsync(cancellationToken).ConfigureAwait(false))
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (_replies.Reader.TryRead(out var message)) return message;
        }
        cancellationToken.ThrowIfCancellationRequested();
        return null;
    }

    private async Task ReceiveAsync()
    {
        try
        {
            while (await _peer.ReadMessageAsync(_receiveCancellation.Token).ConfigureAwait(false) is { } message)
            {
                // Broadcasts may precede the service's initial write. Keep draining
                // status while sending, without accumulating an unbounded queue.
                if (message.Type == ApfsMessageTypes.StatusChanged)
                {
                    RequireStatus(message);
                    continue;
                }
                await _replies.Writer.WriteAsync(message, _receiveCancellation.Token).ConfigureAwait(false);
            }
            _replies.Writer.TryComplete();
        }
        catch (OperationCanceledException) when (_receiveCancellation.IsCancellationRequested)
        {
            _replies.Writer.TryComplete();
        }
        catch (Exception error)
        {
            _replies.Writer.TryComplete(error);
        }
    }

    private static StatusChangedPayload RequireStatus(PipeEnvelope? message)
    {
        if (message is null || message.Type != ApfsMessageTypes.StatusChanged ||
            !PipeMessageCodec.Validate(message).IsValid ||
            !PipeMessageCodec.TryGetPayload<StatusChangedPayload>(message, out var status) || status is null)
            throw new IOException("The service returned an invalid initial status. Refresh before retrying.");
        return status;
    }

    public ValueTask DisposeAsync()
    {
        lock (_disposeSync)
        {
            _disposeTask ??= DisposeCoreAsync();
            return new ValueTask(_disposeTask);
        }
    }

    private async Task DisposeCoreAsync()
    {
        _receiveCancellation.Cancel();
        await _peer.DisposeAsync().ConfigureAwait(false);
        await _receiver.ConfigureAwait(false);
        _receiveCancellation.Dispose();
    }
}
