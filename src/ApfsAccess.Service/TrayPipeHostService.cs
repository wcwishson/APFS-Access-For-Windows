using System.Collections.Concurrent;
using ApfsAccess.Core;
using ApfsAccess.Ipc;
using Microsoft.Extensions.Hosting;

namespace ApfsAccess.Service;

public sealed class TrayPipeHostService : BackgroundService
{
    private static readonly TimeSpan AgentCancellationWaitTimeout = TimeSpan.FromSeconds(2);
    private static readonly TimeSpan PeerCleanupTimeout = TimeSpan.FromSeconds(2);
    private static readonly TimeSpan ServiceStopTimeout = TimeSpan.FromSeconds(3);
    private readonly ILogger<TrayPipeHostService> _logger;
    private readonly RuntimeStatusPublisher _statusPublisher;
    private readonly ApfsMountWorker _mountWorker;
    private readonly IHostApplicationLifetime _applicationLifetime;
    private readonly AgentControlOperationService? _operationService;
    private readonly LegacyTrayOperationAdapter? _legacyOperations;
    private readonly NamedPipeMessageServer _server;
    private readonly ConcurrentDictionary<Guid, PipePeer> _clients = new();
    private readonly object _broadcastSync = new();
    private StatusChangedPayload? _pendingBroadcast;
    private bool _broadcastPumpActive;

    public TrayPipeHostService(
        ILogger<TrayPipeHostService> logger,
        RuntimeStatusPublisher statusPublisher,
        ApfsMountWorker mountWorker,
        IHostApplicationLifetime applicationLifetime
    ) : this(logger, statusPublisher, mountWorker, applicationLifetime, operationService: null)
    {
    }

    internal TrayPipeHostService(
        ILogger<TrayPipeHostService> logger,
        RuntimeStatusPublisher statusPublisher,
        ApfsMountWorker mountWorker,
        IHostApplicationLifetime applicationLifetime,
        AgentControlOperationService? operationService
    )
    {
        _logger = logger;
        _statusPublisher = statusPublisher;
        _mountWorker = mountWorker;
        _applicationLifetime = applicationLifetime;
        _operationService = operationService;
        _legacyOperations = operationService is null
            ? null
            : new LegacyTrayOperationAdapter(operationService, mountWorker);
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
        using var stopTimeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        stopTimeoutCts.CancelAfter(ServiceStopTimeout);
        var stopToken = stopTimeoutCts.Token;

        if (_operationService is not null)
        {
            try
            {
                await _operationService.StopAsync(stopToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (stopToken.IsCancellationRequested)
            {
                _logger.LogWarning(
                    "Timed out waiting for agent-control operations during service stop; continuing bounded peer cleanup.");
            }
        }

        var cleanupTasks = _clients
            .ToArray()
            .Select(kvp => Task.Run(
                () => DisposePeerWithinDeadlineAsync(kvp.Key, kvp.Value, stopToken),
                CancellationToken.None))
            .ToArray();
        try
        {
            await Task.WhenAll(cleanupTasks).WaitAsync(stopToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (stopToken.IsCancellationRequested)
        {
            _logger.LogWarning(
                "The service stop deadline expired while pipe clients were still cleaning up; active clients may remain.");
        }

        await base.StopAsync(stopToken).ConfigureAwait(false);
    }

    private async Task DisposePeerWithinDeadlineAsync(
        Guid clientId,
        PipePeer peer,
        CancellationToken stopToken)
    {
        _clients.TryRemove(clientId, out _);
        try
        {
            await peer
                .DisposeAsync(PeerCleanupTimeout)
                .WaitAsync(stopToken)
                .ConfigureAwait(false);
        }
        catch (TimeoutException exception)
        {
            _logger.LogWarning(
                exception,
                "Timed out during peer cleanup for {ClientId}; the client may remain active after the service stop deadline.",
                clientId);
        }
        catch (OperationCanceledException) when (stopToken.IsCancellationRequested)
        {
            _logger.LogWarning(
                "Peer cleanup for {ClientId} was abandoned at the service stop deadline; the client may remain active.",
                clientId);
        }
        catch (Exception exception)
        {
            _logger.LogWarning(
                exception,
                "Peer cleanup failed for {ClientId}; the client may remain active after service stop.",
                clientId);
        }
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
                PipeEnvelope? message;
                try
                {
                    message = await peer.ReadMessageAsync(cancellationToken).ConfigureAwait(false);
                }
                catch (InvalidDataException ex)
                {
                    var rejection = PipeMessageCodec.Create(
                        ApfsMessageTypes.Ack,
                        new AckPayload(
                            false,
                            ex.Message,
                            ApfsOperationCodes.MalformedMessage,
                            _statusPublisher.Latest));
                    await TrySendAckBestEffortAsync(
                        peer,
                        rejection,
                        cancellationToken).ConfigureAwait(false);
                    break;
                }

                if (message is null)
                {
                    break;
                }

                var validation = PipeMessageCodec.Validate(message);
                if (!validation.IsValid)
                {
                    await SendValidationFailureAsync(
                        peer,
                        message,
                        validation,
                        cancellationToken).ConfigureAwait(false);
                    continue;
                }

                if (message.SchemaVersion == PipeSchemaVersions.Schema2 &&
                    IsAgentControlMessage(message.Type))
                {
                    var stopRequested = await HandleAgentControlMessageAsync(
                        peer,
                        message,
                        cancellationToken).ConfigureAwait(false);
                    if (stopRequested)
                    {
                        return;
                    }

                    continue;
                }

                switch (message.Type)
                {
                    case ApfsMessageTypes.QuitRequested:
                    {
                        if (!PipeMessageCodec.TryGetPayload<QuitRequestedPayload>(message, out var payload) || payload is null)
                        {
                            await SendLegacyPayloadFailureAsync(peer, message, cancellationToken).ConfigureAwait(false);
                            break;
                        }

                        var result = await ExecuteLegacyMutationAsync(
                            message,
                            ApfsControlCommands.Quit,
                            payload.TimestampUtc,
                            volumeId: null,
                            cancellationToken).ConfigureAwait(false);
                        var ack = CreateLegacyOperationAck(message, result);
                        await TrySendAckBestEffortAsync(
                            peer,
                            ack,
                            cancellationToken).ConfigureAwait(false);
                        if (!HasTerminalQuitEvidence(result))
                        {
                            _logger.LogWarning(
                                "Legacy quit did not produce terminal shutdown evidence; application stop was not requested.");
                            break;
                        }

                        await BroadcastServiceStoppingAsync(result).ConfigureAwait(false);
                        _applicationLifetime.StopApplication();
                        return;
                    }
                    case ApfsMessageTypes.EjectRequested:
                    {
                        if (!PipeMessageCodec.TryGetPayload<EjectRequestedPayload>(message, out var payload) || payload is null)
                        {
                            await SendLegacyPayloadFailureAsync(peer, message, cancellationToken).ConfigureAwait(false);
                            break;
                        }

                        var result = await ExecuteLegacyMutationAsync(
                            message,
                            ApfsControlCommands.Eject,
                            payload.TimestampUtc,
                            payload.VolumeId,
                            cancellationToken).ConfigureAwait(false);
                        var ack = CreateLegacyOperationAck(message, result);
                        await peer.SendAsync(ack, cancellationToken).ConfigureAwait(false);
                        break;
                    }
                    case ApfsMessageTypes.RefreshRequested:
                    {
                        if (!PipeMessageCodec.TryGetPayload<RefreshRequestedPayload>(message, out var payload) || payload is null)
                        {
                            await SendLegacyPayloadFailureAsync(peer, message, cancellationToken).ConfigureAwait(false);
                            break;
                        }

                        PipeEnvelope ack;
                        if (payload.ClearUserEjectedVolumes)
                        {
                            var result = await ExecuteLegacyMutationAsync(
                                message,
                                ApfsControlCommands.Mount,
                                payload.TimestampUtc,
                                payload.VolumeId,
                                cancellationToken).ConfigureAwait(false);
                            ack = CreateLegacyOperationAck(message, result);
                        }
                        else
                        {
                            var result = await RefreshLegacyInventoryReadOnlyAsync(
                                payload.VolumeId,
                                cancellationToken).ConfigureAwait(false);
                            ack = PipeMessageCodec.Create(
                                ApfsMessageTypes.Ack,
                                new AckPayload(
                                    result.Success,
                                    result.Message,
                                    result.Code,
                                    _statusPublisher.Latest),
                                message.RequestId);
                        }

                        await peer.SendAsync(ack, cancellationToken).ConfigureAwait(false);
                        break;
                    }
                    case ApfsMessageTypes.MountRequested:
                    {
                        if (!PipeMessageCodec.TryGetPayload<MountRequestedPayload>(message, out var payload) || payload is null)
                        {
                            await SendLegacyPayloadFailureAsync(peer, message, cancellationToken).ConfigureAwait(false);
                            break;
                        }

                        var result = await ExecuteLegacyMutationAsync(
                            message,
                            ApfsControlCommands.Mount,
                            payload.TimestampUtc,
                            payload.VolumeId,
                            cancellationToken).ConfigureAwait(false);
                        var ack = CreateLegacyOperationAck(message, result);
                        await peer.SendAsync(ack, cancellationToken).ConfigureAwait(false);
                        break;
                    }
                    case ApfsMessageTypes.FixRequested:
                    {
                        if (!PipeMessageCodec.TryGetPayload<FixRequestedPayload>(message, out var payload) || payload is null)
                        {
                            await SendLegacyPayloadFailureAsync(peer, message, cancellationToken).ConfigureAwait(false);
                            break;
                        }

                        var result = await ExecuteLegacyMutationAsync(
                            message,
                            ApfsControlCommands.Fix,
                            payload.TimestampUtc,
                            payload.VolumeId,
                            cancellationToken).ConfigureAwait(false);
                        var ack = CreateLegacyOperationAck(message, result);
                        await peer.SendAsync(ack, cancellationToken).ConfigureAwait(false);
                        break;
                    }
                    case ApfsMessageTypes.InventoryRequested:
                    {
                        var inventory = await _mountWorker
                            .GetInventoryAsync(cancellationToken)
                            .ConfigureAwait(false);
                        var response = PipeMessageCodec.Create(
                            ApfsMessageTypes.Inventory,
                            new InventoryPayload(inventory, DateTime.UtcNow),
                            message.RequestId
                        );
                        await peer.SendAsync(response, cancellationToken).ConfigureAwait(false);
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
                            new AckPayload(
                                false,
                                $"Unsupported message type '{message.Type}'.",
                                ApfsOperationCodes.InvalidArguments,
                                _statusPublisher.Latest),
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
            await peer.DisposeAsync().ConfigureAwait(false);
        }
    }

    private async Task<bool> HandleAgentControlMessageAsync(
        PipePeer peer,
        PipeEnvelope message,
        CancellationToken cancellationToken)
    {
        OperationResultPayload result;
        if (_operationService is null)
        {
            result = CreateOperationFailure(
                message,
                ApfsOperationCodes.ServiceUnavailable,
                "The agent control operation service is unavailable.");
        }
        else
        {
            result = message.Type switch
            {
                ApfsMessageTypes.ControlOperationRequest
                    when PipeMessageCodec.TryGetPayload<ControlOperationRequestPayload>(message, out var request) && request is not null
                    => await _operationService.ExecuteOrReplayAsync(request).ConfigureAwait(false),
                ApfsMessageTypes.OperationResultQuery
                    when PipeMessageCodec.TryGetPayload<OperationResultQueryPayload>(message, out var query) && query is not null
                    => _operationService.Query(query.OperationId)
                       ?? CreateOperationFailure(message, ApfsOperationCodes.OperationFailed, "The requested operation is unknown."),
                ApfsMessageTypes.CancellationRequest
                    when PipeMessageCodec.TryGetPayload<OperationCancellationRequestPayload>(message, out var cancellation) && cancellation is not null
                    => await CancelAgentOperationAsync(
                        cancellation.OperationId,
                        cancellationToken).ConfigureAwait(false),
                _ => CreateOperationFailure(
                    message,
                    ApfsOperationCodes.MalformedMessage,
                    "The schema-2 operation payload is malformed."),
            };
        }

        var response = PipeMessageCodec.Create(
            ApfsMessageTypes.OperationResult,
            result,
            result.OperationId,
            PipeSchemaVersions.Schema2);
        await TrySendOperationResultBestEffortAsync(
            peer,
            response,
            cancellationToken).ConfigureAwait(false);

        if (message.Type != ApfsMessageTypes.ControlOperationRequest ||
            !string.Equals(result.Command, ApfsControlCommands.Quit, StringComparison.Ordinal))
        {
            return false;
        }

        if (!HasSuccessfulTerminalEvidence(result))
        {
            _logger.LogWarning(
                "Agent-control quit did not produce existing terminal evidence; application stop was not requested.");
            return false;
        }

        await BroadcastServiceStoppingAsync(result).ConfigureAwait(false);
        _applicationLifetime.StopApplication();
        return true;
    }

    private async Task<OperationResultPayload> CancelAgentOperationAsync(
        string operationId,
        CancellationToken cancellationToken)
    {
        using var waitCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        waitCts.CancelAfter(AgentCancellationWaitTimeout);
        try
        {
            return await _operationService!
                .CancelAsync(operationId, waitCts.Token)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return _operationService!.Cancel(operationId);
        }
    }

    private async Task SendValidationFailureAsync(
        PipePeer peer,
        PipeEnvelope message,
        PipeMessageValidationResult validation,
        CancellationToken cancellationToken)
    {
        if (message.SchemaVersion == PipeSchemaVersions.Schema2 &&
            IsAgentControlMessage(message.Type))
        {
            var result = CreateOperationFailure(message, validation.Code, validation.Diagnostic);
            var response = PipeMessageCodec.Create(
                ApfsMessageTypes.OperationResult,
                result,
                result.OperationId,
                PipeSchemaVersions.Schema2);
            await TrySendOperationResultBestEffortAsync(peer, response, cancellationToken).ConfigureAwait(false);
            return;
        }

        var ack = PipeMessageCodec.Create(
            ApfsMessageTypes.Ack,
            new AckPayload(false, validation.Diagnostic, validation.Code, _statusPublisher.Latest),
            message.RequestId);
        await TrySendAckBestEffortAsync(peer, ack, cancellationToken).ConfigureAwait(false);
    }

    private Task SendLegacyPayloadFailureAsync(
        PipePeer peer,
        PipeEnvelope message,
        CancellationToken cancellationToken)
    {
        var ack = PipeMessageCodec.Create(
            ApfsMessageTypes.Ack,
            new AckPayload(
                false,
                $"The '{message.Type}' payload is malformed.",
                ApfsOperationCodes.MalformedMessage,
                _statusPublisher.Latest),
            message.RequestId);
        return TrySendAckBestEffortAsync(peer, ack, cancellationToken);
    }

    private async Task<OperationResultPayload> ExecuteLegacyMutationAsync(
        PipeEnvelope message,
        string command,
        DateTime timestampUtc,
        string? volumeId,
        CancellationToken cancellationToken)
    {
        if (_legacyOperations is null)
        {
            return CreateLegacyOperationFailure(
                message,
                command,
                timestampUtc,
                ApfsOperationCodes.ServiceUnavailable,
                "The durable operation service is unavailable.");
        }

        try
        {
            return await _legacyOperations
                .ExecuteAsync(message, command, timestampUtc, volumeId, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return CreateLegacyOperationFailure(
                message,
                command,
                timestampUtc,
                ApfsOperationCodes.OperationCancelled,
                "The legacy operation request was cancelled before durable admission completed.");
        }
        catch (OperationCanceledException)
        {
            return CreateLegacyOperationFailure(
                message,
                command,
                timestampUtc,
                ApfsOperationCodes.Timeout,
                "Live APFS inventory did not resolve before the bounded legacy operation deadline.");
        }
        catch (TimeoutException)
        {
            return CreateLegacyOperationFailure(
                message,
                command,
                timestampUtc,
                ApfsOperationCodes.Timeout,
                "Live APFS inventory did not resolve before the bounded legacy operation deadline.");
        }
        catch (Exception exception)
        {
            _logger.LogWarning(exception, "Legacy {Command} routing failed before durable execution.", command);
            return CreateLegacyOperationFailure(
                message,
                command,
                timestampUtc,
                ApfsOperationCodes.OperationFailed,
                exception.Message);
        }
    }

    private async Task<LegacyReadOnlyRefreshResult> RefreshLegacyInventoryReadOnlyAsync(
        string? volumeId,
        CancellationToken cancellationToken)
    {
        if (_legacyOperations is null)
        {
            return new LegacyReadOnlyRefreshResult(
                false,
                ApfsOperationCodes.ServiceUnavailable,
                "The legacy inventory service is unavailable.");
        }

        try
        {
            return await _legacyOperations
                .RefreshReadOnlyAsync(volumeId, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return new LegacyReadOnlyRefreshResult(
                false,
                ApfsOperationCodes.OperationCancelled,
                "The read-only inventory refresh was cancelled.");
        }
        catch (OperationCanceledException)
        {
            return new LegacyReadOnlyRefreshResult(
                false,
                ApfsOperationCodes.Timeout,
                "The read-only inventory refresh exceeded its bounded deadline.");
        }
        catch (TimeoutException)
        {
            return new LegacyReadOnlyRefreshResult(
                false,
                ApfsOperationCodes.Timeout,
                "The read-only inventory refresh exceeded its bounded deadline.");
        }
        catch (Exception exception)
        {
            _logger.LogWarning(exception, "Legacy read-only inventory refresh failed.");
            return new LegacyReadOnlyRefreshResult(
                false,
                ApfsOperationCodes.OperationFailed,
                exception.Message);
        }
    }

    private PipeEnvelope CreateLegacyOperationAck(
        PipeEnvelope request,
        OperationResultPayload result)
        => PipeMessageCodec.Create(
            ApfsMessageTypes.Ack,
            new AckPayload(
                result.Success,
                result.Command == ApfsControlCommands.Quit && result.Success
                    ? "Shutdown requested."
                    : result.Diagnostic ?? result.FinalStatus,
                result.Code,
                _statusPublisher.Latest),
            request.RequestId);

    private static OperationResultPayload CreateLegacyOperationFailure(
        PipeEnvelope message,
        string command,
        DateTime timestampUtc,
        string code,
        string diagnostic)
    {
        var now = DateTime.UtcNow;
        var requestedAtUtc = timestampUtc.Kind == DateTimeKind.Utc
            ? timestampUtc
            : timestampUtc.ToUniversalTime();
        return new OperationResultPayload(
            ResolveLegacyResponseOperationId(message, requestedAtUtc),
            command,
            Target: null,
            Fingerprint: null,
            State: code == ApfsOperationCodes.OperationCancelled
                ? ApfsOperationStates.Cancelled
                : ApfsOperationStates.Failed,
            Code: code,
            Success: false,
            RequestedAtUtc: requestedAtUtc,
            StartedAtUtc: now,
            CompletedAtUtc: now,
            FinalStatus: "not-proven",
            PendingDurability: true,
            MountProof: "not-proven",
            OwnershipProof: "not-proven",
            DurabilityProof: "not-proven",
            Diagnostic: diagnostic,
            ExpiresAtUtc: requestedAtUtc.AddMinutes(2));
    }

    private static string ResolveLegacyResponseOperationId(PipeEnvelope message, DateTime requestedAtUtc)
    {
        if (Guid.TryParse(message.RequestId, out var parsed))
        {
            return parsed.ToString("D").ToLowerInvariant();
        }

        var identity = string.IsNullOrWhiteSpace(message.RequestId)
            ? $"{message.Type}|{requestedAtUtc:O}"
            : message.RequestId.Trim();
        var bytes = System.Security.Cryptography.SHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes($"apfs-access|legacy-tray|{identity}"));
        return new Guid(bytes.AsSpan(0, 16)).ToString("D").ToLowerInvariant();
    }

    private static bool HasSuccessfulTerminalEvidence(OperationResultPayload result)
        => result.Success &&
           result.State == ApfsOperationStates.Succeeded &&
           result.CompletedAtUtc.HasValue &&
           !string.IsNullOrWhiteSpace(result.EvidencePath) &&
           File.Exists(result.EvidencePath);

    private static bool HasTerminalQuitEvidence(OperationResultPayload result)
        => result.Command == ApfsControlCommands.Quit &&
           result.State is ApfsOperationStates.Succeeded or ApfsOperationStates.Failed or ApfsOperationStates.Cancelled &&
           result.CompletedAtUtc.HasValue &&
           result.FinalStatus is "shutdown-complete" or "shutdown-incomplete" &&
           !string.IsNullOrWhiteSpace(result.EvidencePath) &&
           File.Exists(result.EvidencePath);

    private static bool IsAgentControlMessage(string type)
        => type is ApfsMessageTypes.ControlOperationRequest
            or ApfsMessageTypes.OperationResultQuery
            or ApfsMessageTypes.CancellationRequest;

    private static OperationResultPayload CreateOperationFailure(
        PipeEnvelope message,
        string code,
        string? diagnostic)
    {
        var now = DateTime.UtcNow;
        var operationId = ResolveResponseOperationId(message);
        var expiresAtUtc = ResolveResponseExpiry(message);
        var command = expiresAtUtc.HasValue
            ? ResolveResponseCommand(message)
            : ApfsControlCommands.Unknown;
        return new OperationResultPayload(
            operationId,
            command,
            Target: null,
            Fingerprint: null,
            State: ApfsOperationStates.Failed,
            Code: code,
            Success: false,
            RequestedAtUtc: now,
            StartedAtUtc: now,
            CompletedAtUtc: now,
            Diagnostic: diagnostic,
            ExpiresAtUtc: expiresAtUtc);
    }

    private static string ResolveResponseOperationId(PipeEnvelope message)
    {
        if (IsCanonicalOperationId(message.RequestId))
        {
            return message.RequestId!;
        }

        var payloadOperationId = TryGetPayloadString(message, "operationId");
        return IsCanonicalOperationId(payloadOperationId)
            ? payloadOperationId!
            : Guid.NewGuid().ToString("D").ToLowerInvariant();
    }

    private static bool IsCanonicalOperationId(string? value)
        => value is not null &&
           Guid.TryParseExact(value, "D", out var parsed) &&
           string.Equals(value, parsed.ToString("D").ToLowerInvariant(), StringComparison.Ordinal);

    private static string ResolveResponseCommand(PipeEnvelope message)
    {
        var command = TryGetPayloadString(message, "command");
        return command is ApfsControlCommands.Mount
            or ApfsControlCommands.Fix
            or ApfsControlCommands.Eject
            or ApfsControlCommands.Quit
                ? command
                : ApfsControlCommands.Unknown;
    }

    private static DateTime? ResolveResponseExpiry(PipeEnvelope message)
    {
        var value = TryGetPayloadString(message, "expiresAtUtc");
        if (!DateTimeOffset.TryParse(
                value,
                System.Globalization.CultureInfo.InvariantCulture,
                System.Globalization.DateTimeStyles.RoundtripKind,
                out var parsed) ||
            parsed.Offset != TimeSpan.Zero)
        {
            return null;
        }

        return parsed.UtcDateTime;
    }

    private static string? TryGetPayloadString(PipeEnvelope message, string propertyName)
    {
        if (message.Payload is null)
        {
            return null;
        }

        foreach (var property in message.Payload)
        {
            if (!string.Equals(property.Key, propertyName, StringComparison.OrdinalIgnoreCase) || property.Value is null)
            {
                continue;
            }

            try
            {
                return property.Value.GetValue<string>();
            }
            catch (InvalidOperationException)
            {
                return null;
            }
        }

        return null;
    }

    private void OnStatusChanged(StatusChangedPayload payload)
    {
        lock (_broadcastSync)
        {
            _pendingBroadcast = payload;
            if (_broadcastPumpActive)
            {
                return;
            }

            _broadcastPumpActive = true;
        }

        _ = BroadcastLatestStatusAsync();
    }

    private async Task BroadcastLatestStatusAsync()
    {
        while (true)
        {
            StatusChangedPayload? payload;
            lock (_broadcastSync)
            {
                payload = _pendingBroadcast;
                _pendingBroadcast = null;
                if (payload is null)
                {
                    _broadcastPumpActive = false;
                    return;
                }
            }

            if (_clients.IsEmpty)
            {
                continue;
            }

            var message = PipeMessageCodec.Create(ApfsMessageTypes.StatusChanged, payload);
            foreach (var kvp in _clients.ToArray())
            {
                try
                {
                    using var timeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                    await kvp.Value.SendAsync(message, timeoutCts.Token).ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "Failed to push status to client {ClientId}", kvp.Key);
                    _clients.TryRemove(kvp.Key, out _);
                }
            }
        }
    }

    private async Task BroadcastServiceStoppingAsync(OperationResultPayload result)
    {
        var ownershipReleased = string.Equals(
            result.OwnershipProof,
            "proven",
            StringComparison.OrdinalIgnoreCase);
        var durabilityCleared = !result.PendingDurability && string.Equals(
            result.DurabilityProof,
            "proven",
            StringComparison.OrdinalIgnoreCase);
        var message = PipeMessageCodec.Create(
            ApfsMessageTypes.ServiceStopping,
            new ServiceStoppingPayload(
                TimestampUtc: DateTime.UtcNow,
                CleanupCompleted: ownershipReleased && durabilityCleared,
                RemainingMountPoints: ownershipReleased && durabilityCleared
                    ? Array.Empty<string>()
                    : null,
                HostOwnershipReleased: ownershipReleased,
                PendingDurabilityCleared: durabilityCleared,
                Diagnostic: result.Diagnostic));

        var peers = _clients.ToArray();
        if (peers.Length == 0)
        {
            return;
        }

        using var sendTimeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(2));
        var sends = peers.Select(kvp => TrySendServiceStoppingAsync(kvp, message, sendTimeoutCts.Token));
        try
        {
            await Task.WhenAll(sends).WaitAsync(TimeSpan.FromSeconds(3)).ConfigureAwait(false);
        }
        catch (TimeoutException)
        {
            _logger.LogWarning("Timed out notifying clients after the agent-control quit result; proceeding with shutdown.");
        }
    }

    private async Task TrySendAckBestEffortAsync(
        PipePeer peer,
        PipeEnvelope ack,
        CancellationToken cancellationToken)
    {
        try
        {
            using var ackTimeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            ackTimeoutCts.CancelAfter(TimeSpan.FromSeconds(2));
            await peer.SendAsync(ack, ackTimeoutCts.Token).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Quit acknowledgement could not be delivered; proceeding with shutdown.");
        }
    }

    private async Task TrySendOperationResultBestEffortAsync(
        PipePeer peer,
        PipeEnvelope response,
        CancellationToken cancellationToken)
    {
        try
        {
            using var sendTimeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            sendTimeoutCts.CancelAfter(TimeSpan.FromSeconds(2));
            await peer.SendAsync(response, sendTimeoutCts.Token).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Agent-control result could not be delivered; durable operation processing is unchanged.");
        }
    }

    private async Task TrySendServiceStoppingAsync(
        KeyValuePair<Guid, PipePeer> client,
        PipeEnvelope message,
        CancellationToken cancellationToken)
    {
        try
        {
            await client.Value.SendAsync(message, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Failed to notify client {ClientId} that the service is stopping.", client.Key);
            _clients.TryRemove(client.Key, out _);
        }
    }
}
