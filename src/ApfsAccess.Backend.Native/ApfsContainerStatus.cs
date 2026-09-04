using System.Diagnostics;
using System.Globalization;
using System.Text.Json;

namespace ApfsAccess.Backend.Native;

// Frozen contract v1.3 section 7 (managed side), additive status records:
// per-volume mount states plus the container owner PID and lease identity.
// The FsHost-written container status JSON file is the source of truth;
// a missing or stale file is Unknown and must never be reported healthy.
public sealed record ContainerVolumeStatus(
    ulong ObjectId,
    string CanonicalId,
    bool Mounted,
    bool Ready,
    bool Writable,
    string RecoveryIdentity,
    bool RecoveryActive = false,
    bool WriteDegraded = false,
    string RecoveryReason = "");

public sealed record ContainerMountStatus(
    string ContainerUuid,
    int OwnerPid,
    bool LeaseHeld,
    ulong CheckpointXid,
    IReadOnlyList<ContainerVolumeStatus> Volumes,
    bool IsKnown,
    string? UnknownReason,
    DateTimeOffset? ObservedUtc,
    long OwnerStartFileTimeUtc = 0,
    bool RecoveryRequired = false,
    ulong? RecoveryVolumeObjectId = null,
    string RecoveryReason = "");

public static class ContainerStatusUnknownReasons
{
    public const string Missing = "Missing";
    public const string Unreadable = "Unreadable";
    public const string Stale = "Stale";
    public const string SchemaViolation = "SchemaViolation";
    public const string ContainerMismatch = "ContainerMismatch";
    public const string OwnerNotAlive = "OwnerNotAlive";
    public const string OwnerIdentityMismatch = "OwnerIdentityMismatch";
    public const string NoContainerGroup = "NoContainerGroup";
}

public static class ContainerStatusReader
{
    public static readonly TimeSpan DefaultMaxAge = TimeSpan.FromSeconds(30);

    // Total function: every failure mode returns an Unknown status instead
    // of throwing, so callers can never mistake a missing/stale/unparseable
    // file for a healthy container.
    public static ContainerMountStatus TryRead(
        string? statusFilePath,
        string? expectedContainerUuid = null,
        TimeSpan? maxAge = null)
    {
        var limit = maxAge ?? DefaultMaxAge;
        if (string.IsNullOrWhiteSpace(statusFilePath) || !File.Exists(statusFilePath))
        {
            return Unknown(
                expectedContainerUuid,
                ContainerStatusUnknownReasons.Missing);
        }

        DateTime lastWriteUtc;
        try
        {
            lastWriteUtc = File.GetLastWriteTimeUtc(statusFilePath);
        }
        catch
        {
            return Unknown(
                expectedContainerUuid,
                ContainerStatusUnknownReasons.Unreadable);
        }

        if (DateTime.UtcNow - lastWriteUtc > limit)
        {
            return Unknown(
                expectedContainerUuid,
                ContainerStatusUnknownReasons.Stale);
        }

        string text;
        try
        {
            text = File.ReadAllText(statusFilePath);
        }
        catch
        {
            return Unknown(
                expectedContainerUuid,
                ContainerStatusUnknownReasons.Unreadable);
        }

        ContainerMountStatus parsed;
        try
        {
            parsed = Parse(text);
        }
        catch
        {
            return Unknown(
                expectedContainerUuid,
                ContainerStatusUnknownReasons.SchemaViolation);
        }

        if (!string.IsNullOrWhiteSpace(expectedContainerUuid) &&
            !string.Equals(parsed.ContainerUuid, expectedContainerUuid.Trim(), StringComparison.OrdinalIgnoreCase))
        {
            return Unknown(
                expectedContainerUuid,
                ContainerStatusUnknownReasons.ContainerMismatch);
        }

        if (!IsOwnerAlive(parsed.OwnerPid))
        {
            return parsed with
            {
                IsKnown = false,
                UnknownReason = ContainerStatusUnknownReasons.OwnerNotAlive,
                ObservedUtc = DateTimeOffset.UtcNow,
            };
        }
        if (!IsOwnerIdentityCurrent(
                parsed.OwnerPid, parsed.OwnerStartFileTimeUtc))
        {
            return parsed with
            {
                IsKnown = false,
                UnknownReason =
                    ContainerStatusUnknownReasons.OwnerIdentityMismatch,
                ObservedUtc = DateTimeOffset.UtcNow,
            };
        }

        return parsed with { ObservedUtc = DateTimeOffset.UtcNow };
    }

    internal static ContainerMountStatus Parse(string text)
    {
        using var document = JsonDocument.Parse(text);
        var root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object)
        {
            throw new ContainerManifestException("Container status root is not an object.");
        }

        var containerUuid = ContainerManifestWriter.NormalizeContainerUuid(
            GetRequiredString(root, "containerUuid"));
        var ownerPid = GetRequiredInt32(root, "ownerPid");
        if (ownerPid <= 0)
        {
            throw new ContainerManifestException("Container status ownerPid must be positive.");
        }
        var ownerStartFileTimeUtc =
            GetRequiredInt64(root, "ownerStartFileTimeUtc");
        if (ownerStartFileTimeUtc <= 0)
        {
            throw new ContainerManifestException(
                "Container status ownerStartFileTimeUtc must be positive.");
        }

        if (!root.TryGetProperty("leaseHeld", out var leaseHeld) ||
            (leaseHeld.ValueKind != JsonValueKind.True && leaseHeld.ValueKind != JsonValueKind.False))
        {
            throw new ContainerManifestException("Container status leaseHeld must be a boolean.");
        }

        var checkpointXid = GetRequiredUInt64Flexible(root, "checkpointXid");
        var recoveryRequired = GetRequiredBoolean(root, "recoveryRequired");
        var recoveryVolumeObjectId = GetOptionalUInt64Flexible(
            root, "recoveryVolumeObjectId");
        var recoveryReason = GetRequiredStringAllowEmpty(root, "recoveryReason");
        if (!recoveryRequired &&
            (recoveryVolumeObjectId.HasValue || recoveryReason.Length != 0))
        {
            throw new ContainerManifestException(
                "Container status carries recovery detail while recoveryRequired is false.");
        }
        if (recoveryRequired && string.IsNullOrWhiteSpace(recoveryReason))
        {
            throw new ContainerManifestException(
                "Container status recoveryReason is required while recoveryRequired is true.");
        }

        if (!root.TryGetProperty("volumes", out var volumesElement) ||
            volumesElement.ValueKind != JsonValueKind.Array)
        {
            throw new ContainerManifestException("Container status volumes must be an array.");
        }

        var volumes = new List<ContainerVolumeStatus>();
        var seenObjectIds = new HashSet<ulong>();
        foreach (var element in volumesElement.EnumerateArray())
        {
            if (element.ValueKind != JsonValueKind.Object)
            {
                throw new ContainerManifestException("Container status volume entry is not an object.");
            }

            var objectId = GetRequiredUInt64Flexible(element, "objectId");
            var canonicalId = GetRequiredString(element, "canonicalId");
            var mounted = GetRequiredBoolean(element, "mounted");
            var ready = GetRequiredBoolean(element, "ready");
            var writable = GetRequiredBoolean(element, "writable");
            var volumeRecoveryActive = GetRequiredBoolean(element, "recoveryActive");
            var writeDegraded = GetRequiredBoolean(element, "writeDegraded");
            var volumeRecoveryReason = GetRequiredStringAllowEmpty(
                element, "recoveryReason");
            if (objectId == 0 || !seenObjectIds.Add(objectId) ||
                !string.Equals(
                    canonicalId,
                    $"apfs-vol:{containerUuid}:{objectId}",
                    StringComparison.OrdinalIgnoreCase) ||
                (ready && !mounted) ||
                (writable && (!ready || !mounted || volumeRecoveryActive ||
                    writeDegraded || recoveryRequired)) ||
                (volumeRecoveryActive && string.IsNullOrWhiteSpace(volumeRecoveryReason)))
            {
                throw new ContainerManifestException(
                    "Container status volume state is inconsistent.");
            }

            volumes.Add(new ContainerVolumeStatus(
                ObjectId: objectId,
                CanonicalId: canonicalId,
                Mounted: mounted,
                Ready: ready,
                Writable: writable,
                RecoveryIdentity: GetOptionalString(element, "recoveryIdentity") ?? string.Empty,
                RecoveryActive: volumeRecoveryActive,
                WriteDegraded: writeDegraded,
                RecoveryReason: volumeRecoveryReason));
        }

        return new ContainerMountStatus(
            ContainerUuid: containerUuid,
            OwnerPid: ownerPid,
            LeaseHeld: leaseHeld.ValueKind == JsonValueKind.True,
            CheckpointXid: checkpointXid,
            Volumes: volumes.ToArray(),
            IsKnown: true,
            UnknownReason: null,
            ObservedUtc: null,
            OwnerStartFileTimeUtc: ownerStartFileTimeUtc,
            RecoveryRequired: recoveryRequired,
            RecoveryVolumeObjectId: recoveryVolumeObjectId,
            RecoveryReason: recoveryReason);
    }

    internal static bool IsOwnerAlive(int ownerPid)
    {
        if (ownerPid <= 0)
        {
            return false;
        }

        try
        {
            using var process = Process.GetProcessById(ownerPid);
            return !process.HasExited;
        }
        catch (ArgumentException)
        {
            return false;
        }
        catch (InvalidOperationException)
        {
            return false;
        }
        catch (System.ComponentModel.Win32Exception)
        {
            return false;
        }
    }

    internal static bool IsOwnerIdentityCurrent(
        int ownerPid, long expectedStartFileTimeUtc)
    {
        if (ownerPid <= 0 || expectedStartFileTimeUtc <= 0)
        {
            return false;
        }

        try
        {
            using var process = Process.GetProcessById(ownerPid);
            return !process.HasExited &&
                process.StartTime.ToUniversalTime().ToFileTimeUtc() ==
                    expectedStartFileTimeUtc;
        }
        catch (ArgumentException)
        {
            return false;
        }
        catch (InvalidOperationException)
        {
            return false;
        }
        catch (System.ComponentModel.Win32Exception)
        {
            return false;
        }
    }

    private static ContainerMountStatus Unknown(string? containerUuid, string reason)
    {
        string normalized;
        try
        {
            normalized = string.IsNullOrWhiteSpace(containerUuid)
                ? string.Empty
                : ContainerManifestWriter.NormalizeContainerUuid(containerUuid);
        }
        catch
        {
            normalized = string.Empty;
        }

        return new ContainerMountStatus(
            ContainerUuid: normalized,
            OwnerPid: 0,
            LeaseHeld: false,
            CheckpointXid: 0,
            Volumes: Array.Empty<ContainerVolumeStatus>(),
            IsKnown: false,
            UnknownReason: reason,
            ObservedUtc: DateTimeOffset.UtcNow);
    }

    private static string GetRequiredString(JsonElement element, string property)
    {
        if (!element.TryGetProperty(property, out var value) ||
            value.ValueKind != JsonValueKind.String ||
            string.IsNullOrWhiteSpace(value.GetString()))
        {
            throw new ContainerManifestException($"Container status '{property}' must be a nonempty string.");
        }

        return value.GetString()!;
    }

    private static string? GetOptionalString(JsonElement element, string property)
    {
        if (!element.TryGetProperty(property, out var value))
        {
            return null;
        }

        return value.ValueKind switch
        {
            JsonValueKind.String => value.GetString(),
            JsonValueKind.Null => null,
            _ => throw new ContainerManifestException($"Container status '{property}' must be a string."),
        };
    }

    private static string GetRequiredStringAllowEmpty(
        JsonElement element, string property)
    {
        if (!element.TryGetProperty(property, out var value) ||
            value.ValueKind != JsonValueKind.String)
        {
            throw new ContainerManifestException(
                $"Container status '{property}' must be a string.");
        }

        return value.GetString() ?? string.Empty;
    }

    private static int GetRequiredInt32(JsonElement element, string property)
    {
        if (!element.TryGetProperty(property, out var value) ||
            value.ValueKind != JsonValueKind.Number ||
            !value.TryGetInt32(out var number))
        {
            throw new ContainerManifestException($"Container status '{property}' must be an integer.");
        }

        return number;
    }

    private static long GetRequiredInt64(JsonElement element, string property)
    {
        if (!element.TryGetProperty(property, out var value) ||
            value.ValueKind != JsonValueKind.Number ||
            !value.TryGetInt64(out var number))
        {
            throw new ContainerManifestException(
                $"Container status '{property}' must be an integer.");
        }

        return number;
    }

    // u64 fields accept a JSON number or a decimal string (evidence-record
    // convention for u64-safe transport).
    private static ulong GetRequiredUInt64Flexible(JsonElement element, string property)
    {
        if (!element.TryGetProperty(property, out var value))
        {
            throw new ContainerManifestException($"Container status '{property}' is missing.");
        }

        if (value.ValueKind == JsonValueKind.Number && value.TryGetUInt64(out var number))
        {
            return number;
        }

        if (value.ValueKind == JsonValueKind.String &&
            ulong.TryParse(
                value.GetString(),
                NumberStyles.None,
                CultureInfo.InvariantCulture,
                out var parsed))
        {
            return parsed;
        }

        throw new ContainerManifestException($"Container status '{property}' must be a u64 number or decimal string.");
    }

    private static ulong? GetOptionalUInt64Flexible(
        JsonElement element, string property)
    {
        if (!element.TryGetProperty(property, out var value))
        {
            throw new ContainerManifestException(
                $"Container status '{property}' is missing.");
        }
        if (value.ValueKind == JsonValueKind.Null)
        {
            return null;
        }
        if (value.ValueKind == JsonValueKind.Number &&
            value.TryGetUInt64(out var number))
        {
            return number;
        }
        if (value.ValueKind == JsonValueKind.String &&
            ulong.TryParse(
                value.GetString(),
                NumberStyles.None,
                CultureInfo.InvariantCulture,
                out var parsed))
        {
            return parsed;
        }
        throw new ContainerManifestException(
            $"Container status '{property}' must be null or a u64 number or decimal string.");
    }

    private static bool GetRequiredBoolean(JsonElement element, string property)
    {
        if (!element.TryGetProperty(property, out var value) ||
            (value.ValueKind != JsonValueKind.True && value.ValueKind != JsonValueKind.False))
        {
            throw new ContainerManifestException($"Container status '{property}' must be a boolean.");
        }

        return value.ValueKind == JsonValueKind.True;
    }
}
