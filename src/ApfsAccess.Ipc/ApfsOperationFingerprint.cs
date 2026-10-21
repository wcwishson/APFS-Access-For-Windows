using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace ApfsAccess.Ipc;

public static class ApfsOperationFingerprint
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    public static string Compute(ControlOperationRequestPayload request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (!request.ExpiresAtUtc.HasValue)
        {
            throw new ArgumentException("An absolute UTC operation expiry is required.", nameof(request));
        }

        return Compute(request.Command, request.Target, request.RequestedMode, request.ExpiresAtUtc.Value, request.SnapshotName, request.SnapshotIdentity, request.ManagementOperation, request.ManagementToken, request.ManagementName, request.ManagementQuotaBytes, request.ManagementReserveBytes, request.ManagementImagePath, request.VolumeManagement, request.ApprovedImageRepairPlanId, request.KeyManagement);
    }

    // Recomputes the request fingerprint from a result's echoed parameters.
    // The confirmation token is request-supplied only on management-apply:
    // plan requests never carry one (the envelope refuses it), so plan
    // results recompute with a null token to reproduce the request value.
    public static string ComputeForResult(OperationResultPayload result)
    {
        ArgumentNullException.ThrowIfNull(result);
        return Compute(
            result.Command,
            result.Target,
            result.RequestedMode,
            result.ExpiresAtUtc ?? throw new ArgumentException("An absolute UTC operation expiry is required.", nameof(result)),
            result.SnapshotName,
            result.SnapshotIdentity,
            result.ManagementOperation,
            result.Command == ApfsControlCommands.ManagementApply ? result.ManagementToken : null,
            result.ManagementName,
            result.ManagementQuotaBytes,
            result.ManagementReserveBytes,
            result.ManagementImagePath, result.VolumeManagement, result.ApprovedImageRepairPlanId, result.KeyManagement);
    }

    public static string Compute(
        string command,
        ApfsControlTarget? target,
        string? requestedMode,
        DateTime expiresAtUtc,
        string? snapshotName = null,
        IReadOnlyList<string>? snapshotIdentity = null,
        string? managementOperation = null,
        string? managementToken = null,
        string? managementName = null,
        string? managementQuotaBytes = null,
        string? managementReserveBytes = null,
        string? managementImagePath = null,
        VolumeManagementParameters? volumeManagement = null,
        string? approvedImageRepairPlanId = null,
        ApfsAccess.Core.ImageKeyManagementRequest? keyManagement = null)
    {
        if (expiresAtUtc.Kind != DateTimeKind.Utc)
        {
            throw new ArgumentException("The operation expiry must be an absolute UTC timestamp.", nameof(expiresAtUtc));
        }

        var normalizedCommand = NormalizeToken(command)
            ?? throw new ArgumentException("The operation command is required.", nameof(command));
        var normalizedTarget = target is null
            ? null
            : new ApfsControlTarget(
                NormalizeToken(target.DeviceId) ?? string.Empty,
                NormalizeToken(target.VolumeId) ?? string.Empty,
                NormalizeOpaque(target.RecoveryIdentity));
        var normalizedMode = NormalizeMode(requestedMode);
        var input = new FingerprintInput(
            normalizedCommand,
            normalizedTarget?.DeviceId,
            normalizedTarget?.VolumeId,
            normalizedTarget?.RecoveryIdentity,
            normalizedMode,
            expiresAtUtc);
        var serialized = JsonSerializer.Serialize(input, JsonOptions);
        if (target is not null && SelectedControlTarget.IsAdvertised(target))
            serialized += "\n" + JsonSerializer.Serialize(new { target.VolumeUuid, target.ContainerUuid,
                target.VolumeObjectId, target.ObservationContract }, JsonOptions);
        if (target?.RegisteredImage is {} profile) serialized += "\n" + JsonSerializer.Serialize(profile, JsonOptions);
        if (target?.RegisteredFusion is {} fusion) serialized += "\n" + JsonSerializer.Serialize(fusion, JsonOptions);
        // Snapshot parameters are exact-match material: different names or
        // identities must never share an idempotency fingerprint, so they are
        // JSON-framed (never bare-joined) to keep the encoding unambiguous.
        if (snapshotName is not null || snapshotIdentity is not null)
            serialized += "\n" + JsonSerializer.Serialize(new { snapshotName, snapshotIdentity }, JsonOptions);
        // Management parameters are exact-match material for the same
        // reason: a plan token, name, or quota value must never share an
        // idempotency fingerprint with a different one. The operation token
        // is normalized (contract spelling); token, name, and quota values
        // stay byte-exact like snapshot parameters.
        // The image path is caller-supplied target location material: two
        // applies that differ only in path must never share an idempotency
        // fingerprint. It stays byte-exact (case and separator variants of
        // the same file simply miss sharing, which is safe).
        var normalizedManagementOperation = NormalizeToken(managementOperation);
        var normalizedManagementName = NormalizeOpaque(managementName);
        var normalizedManagementToken = NormalizeOpaque(managementToken);
        var normalizedManagementQuotaBytes = NormalizeOpaque(managementQuotaBytes);
        var normalizedManagementReserveBytes = NormalizeOpaque(managementReserveBytes);
        var normalizedManagementImagePath = NormalizeOpaque(managementImagePath);
        if (normalizedManagementOperation is not null || normalizedManagementToken is not null ||
            normalizedManagementName is not null || normalizedManagementQuotaBytes is not null || normalizedManagementReserveBytes is not null || normalizedManagementImagePath is not null)
            serialized += "\n" + JsonSerializer.Serialize(new { normalizedManagementOperation, normalizedManagementToken, normalizedManagementName, normalizedManagementQuotaBytes, normalizedManagementReserveBytes, normalizedManagementImagePath }, JsonOptions);
        if (volumeManagement is not null) serialized += "\n" + JsonSerializer.Serialize(volumeManagement, JsonOptions);
        if (approvedImageRepairPlanId is not null)
            serialized += "\n" + JsonSerializer.Serialize(new { approvedImageRepairPlanId }, JsonOptions);
        if (keyManagement is not null)
            serialized += "\n" + JsonSerializer.Serialize(new { keyManagement }, JsonOptions);
        var bytes = Encoding.UTF8.GetBytes(serialized);
        return $"sha256:{Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant()}";
    }

    private static string? NormalizeToken(string? value)
        => string.IsNullOrWhiteSpace(value) ? null : value.Trim().ToLowerInvariant();

    private static string? NormalizeOpaque(string? value)
        => string.IsNullOrWhiteSpace(value) ? null : value.Trim();

    private static string? NormalizeMode(string? value)
    {
        if (value is null)
        {
            return null;
        }

        return value.Trim().ToLowerInvariant() switch
        {
            "ro" or "readonly" or "read_only" or "read only" or "read-only" => ApfsControlModes.ReadOnly,
            "rw" or "readwrite" or "read_write" or "read write" or "read-write" => ApfsControlModes.ReadWrite,
            _ => throw new ArgumentException("The requested mode is unknown.", nameof(value)),
        };
    }

    private sealed record FingerprintInput(
        string Command,
        string? DeviceId,
        string? VolumeId,
        string? RecoveryIdentity,
        string? RequestedMode,
        DateTime ExpiresAtUtc);
}
