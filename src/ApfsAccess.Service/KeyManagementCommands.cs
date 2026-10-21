using ApfsAccess.Cli;
using ApfsAccess.Core;
using ApfsAccess.Ipc;

namespace ApfsAccess.Service;

public sealed partial class AgentControlCommandExecutor
{
    internal Func<string, int, long, int, CancellationToken, Task<SupervisedCredentialSet>> KeyManagementCredentialReceiver { get; set; }
        = ImageKeyManagementCredentialTransport.ReceiveAsync;

    private async Task<OperationResultPayload> ExecuteKeyManagementAsync(ControlOperationRequestPayload request,
        DateTime requested, DateTime started, CancellationToken token)
    {
        OperationResultPayload Fail(string code, string text) => BuildResult(request, requested, started, false, code,
            "not-proven", ownershipProof: "not-proven", durabilityProof: "not-proven", diagnostic: text);
        if (request.KeyManagement is not { } operation || !operation.IsValid() || operation.OperationId != request.OperationId ||
            request.Target is not null || request.RequestedMode is not null)
            return Fail(ApfsOperationCodes.InvalidArguments, "Select a current image endpoint and confirm the key operation.");
        try
        {
            if (operation.Action == ImageKeyManagementAction.Observe)
            {
                var observed = await _worker.ObserveImageKeysAsync(operation, token).ConfigureAwait(false);
                if (!observed.Proves(operation)) return Fail(ApfsOperationCodes.OperationFailed, "The image observation lacks a complete native receipt.");
                return BuildResult(request, requested, started, true, ApfsOperationCodes.OperationSucceeded, "image-keys-observed",
                    mountProof: "absent", ownershipProof: "proven", durabilityProof: "proven") with { KeyManagementReceipt = observed };
            }
            using var credentials = await KeyManagementCredentialReceiver(request.OperationId, request.CredentialClientProcessId,
                request.CredentialClientStartTimeUtcTicks, operation.CredentialCount, token).ConfigureAwait(false);
            var receipt = await _worker.ManageImageKeysAsync(operation, credentials, token).ConfigureAwait(false);
            if (!receipt.Proves(operation)) return Fail(ApfsOperationCodes.OperationFailed, "The image operation lacks a complete native receipt.");
            return BuildResult(request, requested, started, true, ApfsOperationCodes.OperationSucceeded, "image-keys-updated",
                mountProof: "absent", ownershipProof: "proven", durabilityProof: "proven") with { KeyManagementReceipt = receipt };
        }
        catch (OperationCanceledException)
        {
            return Fail(ApfsOperationCodes.OperationCancelled, "Key management was cancelled. Refresh the image before retrying.")
                with { State = ApfsOperationStates.Cancelled };
        }
        catch (Exception failure)
        {
            return Fail(ApfsOperationCodes.OperationFailed, KeyManagementFailureDiagnostic(operation.Action, failure));
        }
    }
}

public sealed partial class ApfsMountWorker
{
    public Task<ImageKeyManagementReceipt> ObserveImageKeysAsync(ImageKeyManagementRequest request, CancellationToken token)
        => WithMountOperationsPausedAsync(async cancellation =>
        {
            if (_backend is not IImageKeyManagementObserver backend || VolumeIntentBlocks(request.Expected.ImagePath))
                throw new IOException("The image has another maintenance intent or no native key-management observer.");
            return await backend.ObserveImageKeysAsync(request, cancellation).ConfigureAwait(false);
        }, token);

    public Task<ImageKeyManagementReceipt> ManageImageKeysAsync(ImageKeyManagementRequest request,
        SupervisedCredentialSet credentials, CancellationToken token)
        => WithMountOperationsPausedAsync(async cancellation =>
        {
            if (_backend is not IImageKeyManagementBackend backend || VolumeIntentBlocks(request.Expected.ImagePath))
                throw new IOException("The image has another maintenance intent or no native key-management backend.");
            return await backend.ManageImageKeysAsync(request, credentials, cancellation).ConfigureAwait(false);
        }, token);
}
