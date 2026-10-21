using ApfsAccess.Cli;
using ApfsAccess.Core;

namespace ApfsAccess.Ipc;

public static class ImageKeyManagementControlClient
{
    public static Task<OperationResultPayload> ManageAsync(ImageKeyManagementRequest operation,
        SupervisedCredentialSet credentials, CancellationToken token, string? pipeName = null)
        => ExecuteAsync(operation, credentials, token, pipeName);

    public static async Task<ImageKeyManagementEndpoint> ObserveAsync(ImageKeyManagementEndpoint expected,
        CancellationToken token, string? pipeName = null)
    {
        var request = new ImageKeyManagementRequest(Guid.NewGuid().ToString("D"), ImageKeyManagementAction.Observe, expected);
        var result = await ObserveOperationAsync(request, token, pipeName).ConfigureAwait(false);
        if (!result.Success || result.KeyManagementReceipt is not { } receipt || !receipt.Proves(request))
            throw new IOException("The image endpoint could not be refreshed. Inspect its recovery state before retrying.");
        return receipt.After;
    }

    public static Task<OperationResultPayload> ObserveOperationAsync(ImageKeyManagementRequest operation,
        CancellationToken token, string? pipeName = null)
    {
        if (operation.Action != ImageKeyManagementAction.Observe) throw new ArgumentException("An image observation request is required.");
        return ExecuteAsync(operation, null, token, pipeName);
    }

    private static async Task<OperationResultPayload> ExecuteAsync(ImageKeyManagementRequest operation,
        SupervisedCredentialSet? credentials, CancellationToken token, string? pipeName = null)
    {
        using (credentials)
        {
            if (!operation.IsValid() || (operation.Action == ImageKeyManagementAction.Observe
                    ? credentials is not null : credentials is null || credentials.Count != operation.CredentialCount))
                throw new ArgumentException("Invalid image key-management operation.");
            await using var peer = await NamedPipeMessageClient.ConnectAsync(pipeName ?? ApfsPipeConstants.PipeName, 2000, token).ConfigureAwait(false);
            var greeting = await peer.ReadMessageAsync(token).ConfigureAwait(false) ?? throw Refused("greeting-missing");
            if (greeting.Type != ApfsMessageTypes.StatusChanged || !PipeMessageCodec.Validate(greeting).IsValid) throw Refused("greeting-invalid");
            var request = new ControlOperationRequestPayload(operation.OperationId, ApfsControlCommands.ImageKeyManagement, null,
                ExpiresAtUtc: DateTime.UtcNow.AddMinutes(4), KeyManagement: operation);
            var envelope = PipeMessageCodec.Create(ApfsMessageTypes.ControlOperationRequest, request, operation.OperationId, PipeSchemaVersions.Schema2);
            if (!PipeMessageCodec.Validate(envelope).IsValid) throw new ArgumentException("Invalid key-management request envelope.");
            await peer.SendAsync(envelope, token).ConfigureAwait(false);
            using var exchange = CancellationTokenSource.CreateLinkedTokenSource(token);
            var sending = credentials is null ? Task.CompletedTask :
                ImageKeyManagementCredentialTransport.SendAsync(operation.OperationId, credentials, exchange.Token);
            try
            {
                while (true)
                {
                    var response = await peer.ReadMessageAsync(token).ConfigureAwait(false) ?? throw new IOException();
                    if (response.Type != ApfsMessageTypes.OperationResult || response.RequestId != operation.OperationId) continue;
                    if (!PipeMessageCodec.Validate(response).IsValid || !PipeMessageCodec.TryGetPayload<OperationResultPayload>(response, out var result) ||
                        result is null || result.Fingerprint != ApfsOperationFingerprint.Compute(request) || result.KeyManagement != operation)
                        throw new IOException("The key-management result differs from the requested endpoint.");
                    if (result.State is ApfsOperationStates.Accepted or ApfsOperationStates.InProgress)
                    {
                        await Task.Delay(200, token).ConfigureAwait(false);
                        await peer.SendAsync(PipeMessageCodec.Create(ApfsMessageTypes.OperationResultQuery,
                            new OperationResultQueryPayload(operation.OperationId), operation.OperationId, 2), token).ConfigureAwait(false);
                        continue;
                    }
                    if (result.Success) await sending.ConfigureAwait(false);
                    return result;
                }
            }
            catch (OperationCanceledException)
            {
                using var retirement = new CancellationTokenSource(TimeSpan.FromSeconds(2));
                try { await peer.SendAsync(PipeMessageCodec.Create(ApfsMessageTypes.CancellationRequest,
                    new OperationCancellationRequestPayload(operation.OperationId), operation.OperationId, 2), retirement.Token).ConfigureAwait(false); }
                catch { /* The service retains the operation owner until native retirement. */ }
                throw;
            }
            finally { exchange.Cancel(); try { await sending.ConfigureAwait(false); } catch { } }
        }
    }

    private static IOException Refused(string code)
    {
        var error = new IOException("Key-management service protocol refused.");
        error.Data["KeyManagementProtocolCode"] = code; return error;
    }
}
