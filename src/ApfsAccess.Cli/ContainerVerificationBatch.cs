using System.Text.Json;
using ApfsAccess.Core;
using ApfsAccess.Ipc;

namespace ApfsAccess.Cli;

internal interface IContainerVerificationClient : IAsyncDisposable
{
    Task<StatusChangedPayload> ReadFreshStatusAsync(CancellationToken cancellationToken);
    Task<OperationResultPayload> VerifyAsync(ControlOperationRequestPayload request, CancellationToken cancellationToken);
    Task CancelAsync(string operationId, CancellationToken cancellationToken);
}

internal sealed record ContainerVerificationChild(string VolumeId, string VolumeName, ApfsControlTarget Target,
    string State, string Diagnostic, string? OperationId = null, string? Fingerprint = null,
    OperationResultPayload? Result = null);

internal sealed record ContainerVerificationBatchReport(string BatchId, bool DryRun, bool Success, int ExitCode,
    string Code, IReadOnlyList<ContainerVerificationChild> Volumes, string? Diagnostic = null)
{
    public string Scope => ContainerVerificationProof.Scope;
    public bool OperationIssued => Volumes.Any(v => v.OperationId is not null);
}

internal static class ContainerVerificationBatch
{
    internal const string Availability = "available: client batch of sequential existing VolumeVerify requests, subject to complete current membership and owner revalidation. " + ContainerVerificationProof.Scope;
    internal static readonly TimeSpan BatchTimeout = TimeSpan.FromSeconds(180);
    internal static readonly TimeSpan ChildTimeout = TimeSpan.FromSeconds(80);

    internal static async Task<ContainerVerificationBatchReport> RunAsync(ContainerControlOptions options,
        IContainerVerificationClient client, CancellationToken cancellationToken = default,
        DateTimeOffset? operationDeadlineUtc = null)
    {
        var batchDeadline = DateTimeOffset.UtcNow + BatchTimeout;
        if (operationDeadlineUtc is { } supplied && supplied < batchDeadline) batchDeadline = supplied;
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var remaining = batchDeadline - DateTimeOffset.UtcNow;
        if (remaining <= TimeSpan.Zero) deadline.Cancel();
        else deadline.CancelAfter(remaining);
        var token = deadline.Token;
        ContainerVerificationProof proof;
        try
        {
            token.ThrowIfCancellationRequested();
            var status = await client.ReadFreshStatusAsync(token).WaitAsync(token).ConfigureAwait(false);
            token.ThrowIfCancellationRequested();
            proof = ContainerVerificationProof.CaptureForContainer(status, options.DeviceId, options.ContainerId);
            _ = BoundContainerActions.RequireBatch(status, proof.Targets, ApfsTopologyAction.Verify);
        }
        catch (Exception ex)
        {
            return new(options.OperationId, options.DryRun, false,
                ex is OperationCanceledException ? 4 : ex is IOException ? 3 : 5,
                ex is OperationCanceledException ? "verification-interrupted" : ex is IOException ? ApfsOperationCodes.ServiceUnavailable : "verification-unavailable",
                [], ex.Message);
        }

        var results = new List<ContainerVerificationChild>();
        string? stopped = null;
        var exitCode = 0;
        for (var i = 0; i < proof.Volumes.Count; i++)
        {
            var volume = proof.Volumes[i];
            var target = proof.Targets[i];
            if (options.DryRun || stopped is not null)
            {
                results.Add(new(volume.VolumeId, volume.VolumeName, target, "NotAttempted",
                    stopped ?? "Dry run: eligible exact target; no child operation issued."));
                continue;
            }
            ControlOperationRequestPayload request;
            using var childDeadline = CancellationTokenSource.CreateLinkedTokenSource(token);
            childDeadline.CancelAfter(ChildTimeout);
            try
            {
                var current = await client.ReadFreshStatusAsync(childDeadline.Token).WaitAsync(childDeadline.Token).ConfigureAwait(false);
                childDeadline.Token.ThrowIfCancellationRequested();
                // Revalidate all members, including completed ones. No await separates proof and dispatch.
                proof.Revalidate(current);
                _ = BoundContainerActions.RequireBatch(current, proof.Targets, ApfsTopologyAction.Verify);
                childDeadline.Token.ThrowIfCancellationRequested();
                var expiry = DateTimeOffset.UtcNow + ChildTimeout;
                if (expiry > batchDeadline) expiry = batchDeadline;
                string childId;
                do { childId = Guid.NewGuid().ToString("D"); }
                while (childId == options.OperationId || results.Any(r => r.OperationId == childId));
                request = new(childId, ApfsControlCommands.VolumeVerify, target, ExpiresAtUtc: expiry.UtcDateTime);
            }
            catch (Exception ex)
            {
                stopped = ex.Message;
                exitCode = ex is OperationCanceledException ? 4 : 5;
                results.Add(new(volume.VolumeId, volume.VolumeName, target, "NotAttempted", stopped));
                continue;
            }

            OperationResultPayload? result = null;
            try
            {
                result = await client.VerifyAsync(request, childDeadline.Token).WaitAsync(childDeadline.Token).ConfigureAwait(false);
                childDeadline.Token.ThrowIfCancellationRequested();
                ContainerVerificationProof.RequireVerifiedReply(request, result);
                results.Add(new(volume.VolumeId, volume.VolumeName, target, "Verified",
                    result.Diagnostic ?? "Covered current metadata verified.", request.OperationId,
                    ApfsOperationFingerprint.Compute(request), result));
            }
            catch (Exception ex)
            {
                // A timeout or disconnect can leave a child running. Cancel only that child, without retrying it.
                if (ex is OperationCanceledException)
                {
                    using var cancelDeadline = new CancellationTokenSource(TimeSpan.FromSeconds(2));
                    try { await client.CancelAsync(request.OperationId, cancelDeadline.Token).WaitAsync(cancelDeadline.Token).ConfigureAwait(false); }
                    catch (Exception) { /* Best effort; cancellation does not prove the child's outcome. */ }
                }
                stopped = "Stopped after a failed or unconfirmed child operation. Query the child operation ID before retrying.";
                exitCode = ex is OperationCanceledException ? 4 : 5;
                results.Add(new(volume.VolumeId, volume.VolumeName, target, "Failed", ex.Message,
                    request.OperationId, ApfsOperationFingerprint.Compute(request), result));
            }
        }
        var success = options.DryRun || results.Count > 0 && results.All(r => r.State == "Verified");
        return new(options.OperationId, options.DryRun, success, success ? 0 : exitCode,
            success ? options.DryRun ? "inspection-complete" : ApfsOperationCodes.OperationSucceeded : "container-verification-incomplete",
            results.AsReadOnly(), stopped);
    }

    internal static int Emit(ContainerVerificationBatchReport report)
    {
        Console.WriteLine(JsonSerializer.Serialize(new
        {
            schemaVersion = PipeSchemaVersions.Schema2, command = "container-verify",
            operationId = report.BatchId, batchId = report.BatchId, report.Success, report.ExitCode, report.Code,
            report.DryRun, inspectionOnly = report.DryRun, report.OperationIssued,
            execution = "client-batch", childCommand = ApfsControlCommands.VolumeVerify,
            report.Scope, atomicContainerVerification = false,
            verified = report.Volumes.Count(v => v.State == "Verified"), report.Volumes, report.Diagnostic
        }, new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase, WriteIndented = true }));
        return report.ExitCode;
    }
}

internal sealed class PipeContainerVerificationClient : IContainerVerificationClient
{
    private readonly Func<CancellationToken, Task<AgentControlClient>> _connect;
    private AgentControlClient? _client;

    public PipeContainerVerificationClient() : this(token =>
        AgentControlClient.ConnectAsync(ApfsPipeConstants.PipeName, 2000, token)) { }

    internal PipeContainerVerificationClient(Func<CancellationToken, Task<AgentControlClient>> connect)
        => _connect = connect;

    internal PipeContainerVerificationClient(Func<CancellationToken, Task<PipePeer>> connectPeer)
        : this(async token => await AgentControlClient.ConnectAsync(await connectPeer(token).ConfigureAwait(false), token).ConfigureAwait(false)) { }

    public async Task<StatusChangedPayload> ReadFreshStatusAsync(CancellationToken cancellationToken)
    {
        if (_client is not null) await _client.DisposeAsync().ConfigureAwait(false);
        _client = await _connect(cancellationToken).ConfigureAwait(false);
        return _client.ValidatedInitialStatus;
    }

    public async Task<OperationResultPayload> VerifyAsync(ControlOperationRequestPayload request, CancellationToken cancellationToken)
    {
        var client = _client ?? throw new InvalidOperationException("Fresh status must precede verification.");
        var envelope = PipeMessageCodec.Create(ApfsMessageTypes.ControlOperationRequest, request, request.OperationId, PipeSchemaVersions.Schema2);
        if (!PipeMessageCodec.Validate(envelope).IsValid) throw new InvalidOperationException("Invalid volume verification request.");
        await client.SendAsync(envelope, cancellationToken).ConfigureAwait(false);
        return await ReadTerminalAsync(client, request, cancellationToken).ConfigureAwait(false);
    }

    internal static async Task<OperationResultPayload> ReadTerminalAsync(PipePeer peer,
        ControlOperationRequestPayload request, CancellationToken cancellationToken)
    {
        while (true)
        {
            var response = await peer.ReadMessageAsync(cancellationToken).ConfigureAwait(false)
                ?? throw new IOException("The service disconnected; the child outcome is unconfirmed.");
            if (response.Type == ApfsMessageTypes.ServiceStopping) throw new IOException("The service is stopping; the child outcome is unconfirmed.");
            if (response.Type != ApfsMessageTypes.OperationResult || response.RequestId != request.OperationId) continue;
            if (!PipeMessageCodec.Validate(response).IsValid ||
                !PipeMessageCodec.TryGetPayload<OperationResultPayload>(response, out var result) || result is null)
                throw new IOException("Malformed verification result; the child outcome is unconfirmed.");
            if (request.Command == ApfsControlCommands.Fix) ContainerFixProof.ValidateReply(request, result);
            else ContainerVerificationProof.ValidateReply(request, result);
            if (result.State is not (ApfsOperationStates.Accepted or ApfsOperationStates.InProgress)) return result;
            await Task.Delay(200, cancellationToken).ConfigureAwait(false);
            await peer.SendAsync(PipeMessageCodec.Create(ApfsMessageTypes.OperationResultQuery,
                new OperationResultQueryPayload(request.OperationId), request.OperationId, PipeSchemaVersions.Schema2), cancellationToken).ConfigureAwait(false);
        }
    }
    internal static async Task<OperationResultPayload> ReadTerminalAsync(AgentControlClient client,
        ControlOperationRequestPayload request, CancellationToken cancellationToken)
    {
        while (true)
        {
            var response = await client.ReadMessageAsync(cancellationToken).ConfigureAwait(false)
                ?? throw new IOException("The service disconnected; the child outcome is unconfirmed.");
            if (response.Type == ApfsMessageTypes.ServiceStopping) throw new IOException("The service is stopping; the child outcome is unconfirmed.");
            if (response.Type != ApfsMessageTypes.OperationResult || response.RequestId != request.OperationId) continue;
            if (!PipeMessageCodec.Validate(response).IsValid ||
                !PipeMessageCodec.TryGetPayload<OperationResultPayload>(response, out var result) || result is null)
                throw new IOException("Malformed verification result; the child outcome is unconfirmed.");
            if (request.Command == ApfsControlCommands.Fix) ContainerFixProof.ValidateReply(request, result);
            else ContainerVerificationProof.ValidateReply(request, result);
            if (result.State is not (ApfsOperationStates.Accepted or ApfsOperationStates.InProgress)) return result;
            await Task.Delay(200, cancellationToken).ConfigureAwait(false);
            await client.SendAsync(PipeMessageCodec.Create(ApfsMessageTypes.OperationResultQuery,
                new OperationResultQueryPayload(request.OperationId), request.OperationId, PipeSchemaVersions.Schema2), cancellationToken).ConfigureAwait(false);
        }
    }

    public async Task CancelAsync(string operationId, CancellationToken cancellationToken)
    {
        await using var client = await _connect(cancellationToken).ConfigureAwait(false);
        await client.SendAsync(PipeMessageCodec.Create(ApfsMessageTypes.CancellationRequest,
            new OperationCancellationRequestPayload(operationId), operationId, PipeSchemaVersions.Schema2), cancellationToken).ConfigureAwait(false);
    }

    public async ValueTask DisposeAsync()
    {
        if (_client is not null) await _client.DisposeAsync().ConfigureAwait(false);
    }
}
