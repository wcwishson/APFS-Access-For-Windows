using System.Security.Cryptography;
using System.Text;
using ApfsAccess.Core;
using ApfsAccess.Ipc;

namespace ApfsAccess.Service;

internal sealed class LegacyTrayOperationAdapter
{
    private static readonly TimeSpan LegacyOperationLifetime = TimeSpan.FromMinutes(2);
    private static readonly TimeSpan InventoryTimeout = TimeSpan.FromSeconds(2);
    private readonly AgentControlOperationService _operationService;
    private readonly ApfsMountWorker _mountWorker;

    internal LegacyTrayOperationAdapter(
        AgentControlOperationService operationService,
        ApfsMountWorker mountWorker)
    {
        _operationService = operationService;
        _mountWorker = mountWorker;
    }

    internal async Task<OperationResultPayload> ExecuteAsync(
        PipeEnvelope message,
        string command,
        DateTime timestampUtc,
        string? volumeId,
        CancellationToken cancellationToken)
    {
        var requestedAtUtc = NormalizeUtc(timestampUtc);
        var expiresAtUtc = requestedAtUtc + LegacyOperationLifetime;
        ApfsControlTarget? target = null;
        string? requestedMode = null;
        if (!string.Equals(command, ApfsControlCommands.Quit, StringComparison.Ordinal))
        {
            var resolution = await ResolveTargetAsync(volumeId, cancellationToken).ConfigureAwait(false);
            target = resolution.Target ?? CreateMissingTarget(volumeId);
            if (command == ApfsControlCommands.Mount)
            {
                requestedMode = resolution.RequestedMode ?? ApfsControlModes.ReadWrite;
            }
        }

        var request = new ControlOperationRequestPayload(
            ResolveOperationId(message, requestedAtUtc),
            command,
            target,
            RequestedMode: requestedMode,
            ExpiresAtUtc: expiresAtUtc);
        return await _operationService.ExecuteOrReplayAsync(request).ConfigureAwait(false);
    }

    internal async Task<LegacyReadOnlyRefreshResult> RefreshReadOnlyAsync(
        string? volumeId,
        CancellationToken cancellationToken)
    {
        var resolution = await ResolveTargetAsync(volumeId, cancellationToken).ConfigureAwait(false);
        if (!string.IsNullOrWhiteSpace(volumeId) && resolution.MatchCount == 0)
        {
            return new LegacyReadOnlyRefreshResult(
                false,
                ApfsOperationCodes.MissingVolume,
                $"Requested APFS volume '{volumeId}' was not found in live inventory.");
        }

        if (!string.IsNullOrWhiteSpace(volumeId) && resolution.MatchCount != 1)
        {
            return new LegacyReadOnlyRefreshResult(
                false,
                ApfsOperationCodes.AmbiguousTarget,
                $"Requested APFS volume '{volumeId}' did not resolve to exactly one connected device and volume.");
        }

        return new LegacyReadOnlyRefreshResult(
            true,
            ApfsOperationCodes.OperationSucceeded,
            "APFS inventory refreshed without changing mount or ejection state.");
    }

    private async Task<LegacyTargetResolution> ResolveTargetAsync(
        string? volumeId,
        CancellationToken cancellationToken)
    {
        using var inventoryCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        inventoryCts.CancelAfter(InventoryTimeout);
        var inventory = await _mountWorker
            .GetInventoryAsync(inventoryCts.Token)
            .WaitAsync(InventoryTimeout, cancellationToken)
            .ConfigureAwait(false);
        var matches = inventory
            .Where(static item => item.Device.IsConnected)
            .SelectMany(item => item.Volumes.Select(volume => (item.Device, Volume: volume)))
            .Where(item => string.Equals(
                item.Device.DeviceId,
                item.Volume.DeviceId,
                StringComparison.OrdinalIgnoreCase))
            .Where(item => string.IsNullOrWhiteSpace(volumeId) || string.Equals(
                item.Volume.VolumeId,
                volumeId,
                StringComparison.OrdinalIgnoreCase))
            .ToArray();
        if (matches.Length == 1)
        {
            var match = matches[0];
            return new LegacyTargetResolution(
                new ApfsControlTarget(
                    match.Device.DeviceId,
                    match.Volume.VolumeId,
                    match.Volume.RecoveryIdentity),
                matches.Length,
                match.Volume.SupportsReadWrite
                    ? ApfsControlModes.ReadWrite
                    : ApfsControlModes.ReadOnly);
        }

        if (matches.Length > 1)
        {
            var distinctTargets = matches
                .Select(match => new ApfsControlTarget(
                    match.Device.DeviceId,
                    match.Volume.VolumeId,
                    match.Volume.RecoveryIdentity))
                .Distinct()
                .ToArray();
            return new LegacyTargetResolution(
                CreateAmbiguousRejectionTarget(distinctTargets),
                matches.Length,
                RequestedMode: null);
        }

        return new LegacyTargetResolution(null, MatchCount: 0, RequestedMode: null);
    }

    private static ApfsControlTarget CreateAmbiguousRejectionTarget(
        IReadOnlyList<ApfsControlTarget> candidates)
    {
        var carrier = candidates
            .OrderBy(static target => target.DeviceId, StringComparer.OrdinalIgnoreCase)
            .ThenBy(static target => target.VolumeId, StringComparer.OrdinalIgnoreCase)
            .First();
        var rejectionIdentity = "legacy-ambiguous-target";
        while (candidates.Any(target => string.Equals(
                   target.RecoveryIdentity,
                   rejectionIdentity,
                   StringComparison.Ordinal)))
        {
            rejectionIdentity += "-x";
        }

        // The known-nonmatching recovery identity forces a durable ambiguous
        // result in the real executor without choosing any candidate to mutate.
        return carrier with { RecoveryIdentity = rejectionIdentity };
    }

    private static ApfsControlTarget? CreateMissingTarget(string? volumeId)
    {
        if (string.IsNullOrWhiteSpace(volumeId))
        {
            return null;
        }

        var separator = volumeId.IndexOf('|');
        if (separator <= 0)
        {
            return null;
        }

        return new ApfsControlTarget(volumeId[..separator], volumeId);
    }

    private static string ResolveOperationId(PipeEnvelope message, DateTime requestedAtUtc)
    {
        if (Guid.TryParse(message.RequestId, out var parsed))
        {
            return parsed.ToString("D").ToLowerInvariant();
        }

        var identity = string.IsNullOrWhiteSpace(message.RequestId)
            ? $"{message.Type}|{requestedAtUtc:O}"
            : message.RequestId.Trim();
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes($"apfs-access|legacy-tray|{identity}"));
        Span<byte> guidBytes = stackalloc byte[16];
        bytes.AsSpan(0, guidBytes.Length).CopyTo(guidBytes);
        guidBytes[7] = (byte)((guidBytes[7] & 0x0f) | 0x50);
        guidBytes[8] = (byte)((guidBytes[8] & 0x3f) | 0x80);
        return new Guid(guidBytes).ToString("D").ToLowerInvariant();
    }

    private static DateTime NormalizeUtc(DateTime value)
        => value.Kind switch
        {
            DateTimeKind.Utc => value,
            DateTimeKind.Local => value.ToUniversalTime(),
            _ => DateTime.SpecifyKind(value, DateTimeKind.Utc),
        };

    private sealed record LegacyTargetResolution(
        ApfsControlTarget? Target,
        int MatchCount,
        string? RequestedMode);
}

internal sealed record LegacyReadOnlyRefreshResult(bool Success, string Code, string Message);
