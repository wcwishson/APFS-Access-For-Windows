using System.Text.Json;
using System.Text.Json.Nodes;
using ApfsAccess.Core;

namespace ApfsAccess.Ipc;

public static partial class PipeMessageCodec
{
    private static PipeMessageValidationResult ValidateKeyManagementRequest(string command, string operationId, JsonObject payload)
    {
        ImageKeyManagementRequest? request;
        try { request = payload["keyManagement"]?.Deserialize<ImageKeyManagementRequest>(SerializerOptions); }
        catch (JsonException) { return Invalid(ApfsOperationCodes.InvalidArguments, "Invalid image key-management request."); }
        if (command != ApfsControlCommands.ImageKeyManagement)
            return request is null ? Valid() : Invalid(ApfsOperationCodes.InvalidArguments, "Unexpected key-management parameters.");
        return request is not null && request.IsValid() && request.OperationId == operationId &&
            payload.All(p => p.Key is "operationId" or "command" or "target" or "requestedMode" or "expiresAtUtc" or "keyManagement" || p.Value is null) &&
            payload["requestedMode"] is null && payload["target"] is null
            ? Valid() : Invalid(ApfsOperationCodes.InvalidArguments, "An exact image endpoint and key-management action are required.");
    }

    private static PipeMessageValidationResult ValidateKeyManagementResult(OperationResultPayload result)
    {
        if (result.Command != ApfsControlCommands.ImageKeyManagement)
            return result.KeyManagement is null && result.KeyManagementReceipt is null ? Valid() :
                Invalid(ApfsOperationCodes.MalformedMessage, "Unexpected key-management proof.");
        if (result.KeyManagement is not { } request || !request.IsValid() || request.OperationId != result.OperationId ||
            result.Target is not null || result.RequestedMode is not null ||
            result.SnapshotName is not null || result.SnapshotIdentity is not null || result.ManagementOperation is not null ||
            result.ManagementToken is not null || result.ManagementName is not null || result.ManagementQuotaBytes is not null ||
            result.ManagementReserveBytes is not null || result.ManagementImagePath is not null || result.VolumeManagement is not null ||
            result.ApprovedImageRepairPlanId is not null)
            return Invalid(ApfsOperationCodes.MalformedMessage, "Invalid key-management request echo.");
        return result.KeyManagementReceipt is null || result.State == ApfsOperationStates.Succeeded &&
            result.KeyManagementReceipt.Proves(request) ? Valid() :
            Invalid(ApfsOperationCodes.MalformedMessage, "Key-management receipt differs from the exact operation.");
    }

    private static PipeMessageValidationResult ValidateKeyManagementSuccess(OperationResultPayload result)
        => result.KeyManagement is { } request && result.KeyManagementReceipt is { } receipt && receipt.Proves(request) &&
           result.FinalStatus == (request.Action == ImageKeyManagementAction.Observe ? "image-keys-observed" : "image-keys-updated") &&
           result.MountProof == "absent" &&
           result.OwnershipProof == "proven" && result.DurabilityProof == "proven" &&
           !result.RecoveryActive && result.DirtyTransactionCount == 0
           ? Valid() : Invalid(ApfsOperationCodes.MalformedMessage, "Key management requires a clean, closed native receipt.");
}
