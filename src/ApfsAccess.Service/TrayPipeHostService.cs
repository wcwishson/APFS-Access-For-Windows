using System.Collections.Concurrent;
using ApfsAccess.Ipc;
using Microsoft.Extensions.Hosting;

namespace ApfsAccess.Service;

public sealed class TrayPipeHostService : BackgroundService
{
    private readonly ILogger<TrayPipeHostService> _logger;
    private readonly RuntimeStatusPublisher _statusPublisher;
    private readonly ApfsMountWorker _mountWorker;
    private readonly IHostApplicationLifetime _applicationLifetime;
    private readonly NamedPipeMessageServer _server;
    private readonly ConcurrentDictionary<Guid, PipePeer> _clients = new();

    public TrayPipeHostService(
        ILogger<TrayPipeHostService> logger,
        RuntimeStatusPublisher statusPublisher,
        ApfsMountWorker mountWorker,
        IHostApplicationLifetime applicationLifetime
    )
    {
        _logger = logger;
        _statusPublisher = statusPublisher;
        _mountWorker = mountWorker;
        _applicationLifetime = applicationLifetime;
        _server = new NamedPipeMessageServer(ApfsPipeConstants.PipeName);
    }

    public override Task StartAsync(CancellationToken cancellationToken)
    {
        _statusPublisher.StatusChanged += OnStatusChanged;
        return base.StartAsync(cancellationToken);
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        _statusPublisher.StatusChanged -= OnStatusChanged;

        foreach (var kvp in _clients.ToArray())
        {
            if (_clients.TryRemove(kvp.Key, out var peer))
            {
                await peer.DisposeAsync().ConfigureAwait(false);
            }
        }

        await base.StopAsync(cancellationToken).ConfigureAwait(false);
    }

    protected override Task ExecuteAsync(CancellationToken stoppingToken)
        => _server.RunAsync(HandleClientAsync, stoppingToken);

    private async Task HandleClientAsync(PipePeer peer, CancellationToken cancellationToken)
    {
        var clientId = Guid.NewGuid();
        _clients[clientId] = peer;
        _logger.LogInformation("Tray client connected: {ClientId}", clientId);

        try
        {
            var initial = PipeMessageCodec.Create(
                ApfsMessageTypes.StatusChanged,
                _statusPublisher.Latest
            );
            await peer.SendAsync(initial, cancellationToken).ConfigureAwait(false);

            while (!cancellationToken.IsCancellationRequested)
            {
                var message = await peer.ReadMessageAsync(cancellationToken).ConfigureAwait(false);
                if (message is null)
                {
                    break;
                }

                switch (message.Type)
                {
                    case ApfsMessageTypes.QuitRequested:
                    {
                        var ack = PipeMessageCodec.Create(
                            ApfsMessageTypes.Ack,
                            new AckPayload(true, "Shutdown requested."),
                            message.RequestId
                        );
                        await peer.SendAsync(ack, cancellationToken).ConfigureAwait(false);
                        _applicationLifetime.StopApplication();
                        break;
                    }
                    case ApfsMessageTypes.EjectRequested:
                    {
                        PipeMessageCodec.TryGetPayload<EjectRequestedPayload>(message, out var payload);
                        var result = await _mountWorker
                            .EjectAsync(payload?.VolumeId, cancellationToken)
                            .ConfigureAwait(false);
                        var ack = PipeMessageCodec.Create(
                            ApfsMessageTypes.Ack,
                            new AckPayload(result.Success, result.Message),
                            message.RequestId
                        );
                        await peer.SendAsync(ack, cancellationToken).ConfigureAwait(false);
                        break;
                    }
                    case ApfsMessageTypes.RefreshRequested:
                    {
                        PipeMessageCodec.TryGetPayload<RefreshRequestedPayload>(message, out var payload);
                        var result = await _mountWorker
                            .RefreshAsync(payload?.ClearUserEjectedVolumes == true, cancellationToken)
                            .ConfigureAwait(false);
                        var ack = PipeMessageCodec.Create(
                            ApfsMessageTypes.Ack,
                            new AckPayload(result.Success, result.Message),
                            message.RequestId
                        );
                        await peer.SendAsync(ack, cancellationToken).ConfigureAwait(false);
                        break;
                    }
                    case ApfsMessageTypes.Ping:
                    {
                        var pong = PipeMessageCodec.Create(
                            ApfsMessageTypes.Pong,
                            new PongPayload(DateTime.UtcNow),
                            message.RequestId
                        );
                        await peer.SendAsync(pong, cancellationToken).ConfigureAwait(false);
                        break;
                    }
                    default:
                    {
                        var ack = PipeMessageCodec.Create(
                            ApfsMessageTypes.Ack,
                            new AckPayload(false, $"Unsupported message type '{message.Type}'."),
                            message.RequestId
                        );
                        await peer.SendAsync(ack, cancellationToken).ConfigureAwait(false);
                        break;
                    }
                }
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // Expected during service shutdown.
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Tray client handler error for {ClientId}", clientId);
        }
        finally
        {
            _clients.TryRemove(clientId, out _);
            _logger.LogInformation("Tray client disconnected: {ClientId}", clientId);
        }
    }

    private void OnStatusChanged(StatusChangedPayload payload)
    {
        _ = BroadcastStatusAsync(payload);
    }

    private async Task BroadcastStatusAsync(StatusChangedPayload payload)
    {
        if (_clients.IsEmpty)
        {
            return;
        }

        var message = PipeMessageCodec.Create(ApfsMessageTypes.StatusChanged, payload);
        foreach (var kvp in _clients.ToArray())
        {
            try
            {
                await kvp.Value.SendAsync(message, CancellationToken.None).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to push status to client {ClientId}", kvp.Key);
                _clients.TryRemove(kvp.Key, out _);
            }
        }
    }
}
