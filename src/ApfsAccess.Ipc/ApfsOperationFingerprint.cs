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

        return Compute(request.Command, request.Target, request.RequestedMode, request.ExpiresAtUtc.Value);
    }

    public static string Compute(
        string command,
        ApfsControlTarget? target,
        string? requestedMode,
        DateTime expiresAtUtc)
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
        var bytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(input, JsonOptions));
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
