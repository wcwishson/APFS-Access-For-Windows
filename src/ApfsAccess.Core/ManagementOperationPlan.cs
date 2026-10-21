using System.Security.Cryptography;
using System.Text;

namespace ApfsAccess.Core;

// Task 11 Step 2: verify-plan-confirm-apply semantics for explicit volume
// management. A plan binds the exact operation target (device, container,
// volume, object id), the observed checkpoint generation, and the expected
// capacity change to a server-issued single-use confirmation token. The
// registry copy is the authority at apply time: caller-supplied fields must
// match it exactly, and any checkpoint drift fails closed (the caller must
// re-observe and re-plan; live mounts need the Task 11 quiesce design).
// Only operations with an implemented native planner entry point can be
// planned today (rename, quota/reserve); create/delete/grow/shrink/format
// and credential transitions have no planner and are refused here.
public enum ManagementOperationKind
{
    Unknown = 0,
    RenameVolume = 1,
    SetQuotaReserve = 2,
}

public sealed record ManagementOperationPlan(
    string PlanId,
    ManagementOperationKind Operation,
    string DeviceId,
    Guid ContainerUuid,
    Guid VolumeUuid,
    ulong VolumeObjectId,
    ulong ObservedCheckpointXid,
    long ExpectedCapacityChangeBytes,
    DateTimeOffset IssuedAtUtc,
    TimeSpan TimeToLive,
    string ConfirmationToken)
{
    public DateTimeOffset ExpiresAtUtc => IssuedAtUtc + TimeToLive;
}

public sealed record ManagementApplyRequest(
    string ConfirmationToken,
    string DeviceId,
    Guid ContainerUuid,
    Guid VolumeUuid,
    ulong VolumeObjectId,
    ulong ObservedCheckpointXid);

public sealed record ManagementPlanVerdict(bool Ok, ManagementOperationPlan? Plan, string Code, string? Detail);

public sealed record ManagementApplyVerdict(bool Ok, ManagementOperationPlan? Plan, string Code, string? Detail);

public static class ManagementOperationPlans
{
    public const string Issued = "Issued";
    public const string UnsupportedOperation = "UnsupportedOperation";
    public const string InvalidIdentity = "InvalidIdentity";
    public const string DriveLetterIdentity = "DriveLetterIdentity";
    public const string InvalidCheckpoint = "InvalidCheckpoint";
    public const string CapacityChangeUnsupported = "CapacityChangeUnsupported";
    public const string InvalidLifetime = "InvalidLifetime";
    public const string RegistryFull = "RegistryFull";
    public const string UnknownToken = "UnknownToken";
    public const string ExpiredPlan = "ExpiredPlan";
    public const string IdentityMismatch = "IdentityMismatch";
    public const string OperationMismatch = "OperationMismatch";
    public const string StaleCheckpoint = "StaleCheckpoint";

    public static readonly TimeSpan MinimumTimeToLive = TimeSpan.FromSeconds(30);
    public static readonly TimeSpan MaximumTimeToLive = TimeSpan.FromMinutes(15);
    public static readonly TimeSpan DefaultTimeToLive = TimeSpan.FromMinutes(5);
    public const int MaximumLivePlans = 64;

    public static ManagementPlanVerdict TryIssue(
        ManagementOperationKind operation,
        string? deviceId,
        Guid containerUuid,
        Guid volumeUuid,
        ulong volumeObjectId,
        ulong observedCheckpointXid,
        long expectedCapacityChangeBytes,
        ManagementPlanRegistry registry,
        TimeSpan? timeToLive = null,
        Func<DateTimeOffset>? clock = null)
    {
        ArgumentNullException.ThrowIfNull(registry);
        if (operation is not (ManagementOperationKind.RenameVolume or ManagementOperationKind.SetQuotaReserve))
            return new ManagementPlanVerdict(false, null,
                UnsupportedOperation, $"Operation '{operation}' has no planner entry point.");
        if (containerUuid == Guid.Empty || volumeUuid == Guid.Empty || volumeObjectId == 0 ||
            !TopologyGraphIndex.Text(deviceId))
            return new ManagementPlanVerdict(false, null,
                InvalidIdentity, "Device, container, volume, or object identity is missing or malformed.");
        if (IsDriveLetterIdentity(deviceId!))
            return new ManagementPlanVerdict(false, null,
                DriveLetterIdentity, "Management identity must never default from a drive letter.");
        if (observedCheckpointXid == 0)
            return new ManagementPlanVerdict(false, null,
                InvalidCheckpoint, "Observed checkpoint generation must be nonzero.");
        if (expectedCapacityChangeBytes != 0)
            return new ManagementPlanVerdict(false, null,
                CapacityChangeUnsupported, "Only zero capacity-change operations have a planner today.");
        var ttl = timeToLive ?? DefaultTimeToLive;
        if (ttl < MinimumTimeToLive || ttl > MaximumTimeToLive)
            return new ManagementPlanVerdict(false, null,
                InvalidLifetime, $"Plan lifetime must be between {MinimumTimeToLive} and {MaximumTimeToLive}.");

        var now = GetNow(clock);
        var token = Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();
        var plan = new ManagementOperationPlan(
            ComputePlanId(operation, deviceId!, containerUuid, volumeUuid, volumeObjectId,
                observedCheckpointXid, expectedCapacityChangeBytes, now, ttl),
            operation, deviceId!, containerUuid, volumeUuid, volumeObjectId,
            observedCheckpointXid, expectedCapacityChangeBytes, now, ttl, token);
        if (!registry.TryAdd(plan, now))
            return new ManagementPlanVerdict(false, null,
                RegistryFull, "Too many live management plans are outstanding.");
        return new ManagementPlanVerdict(true, plan, Issued, null);
    }

    public static string ComputePlanId(
        ManagementOperationKind operation,
        string deviceId,
        Guid containerUuid,
        Guid volumeUuid,
        ulong volumeObjectId,
        ulong observedCheckpointXid,
        long expectedCapacityChangeBytes,
        DateTimeOffset issuedAtUtc,
        TimeSpan timeToLive)
    {
        var text = string.Join("|",
            ((int)operation).ToString(System.Globalization.CultureInfo.InvariantCulture),
            deviceId,
            containerUuid.ToString("N"),
            volumeUuid.ToString("N"),
            volumeObjectId.ToString(System.Globalization.CultureInfo.InvariantCulture),
            observedCheckpointXid.ToString(System.Globalization.CultureInfo.InvariantCulture),
            expectedCapacityChangeBytes.ToString(System.Globalization.CultureInfo.InvariantCulture),
            issuedAtUtc.UtcTicks.ToString(System.Globalization.CultureInfo.InvariantCulture),
            timeToLive.Ticks.ToString(System.Globalization.CultureInfo.InvariantCulture));
        return "mgmt-plan-v1:" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text))).ToLowerInvariant();
    }

    private static DateTimeOffset SystemNow() => DateTimeOffset.UtcNow;

    private static DateTimeOffset GetNow(Func<DateTimeOffset>? clock) => clock is null ? SystemNow() : clock();

    public static bool IsDriveLetterIdentity(string deviceId)
        => deviceId.Length >= 2 && char.IsAsciiLetter(deviceId[0]) && deviceId[1] == ':' &&
           (deviceId.Length == 2 || deviceId[2] == '\\' || deviceId[2] == '/') &&
           !VerifyScopeDerivation.IsLocalImagePath(deviceId);
}

// In-memory single-use token store. The stored plan is the authority;
// tokens are unguessable 256-bit values, never derived from plan content.
public sealed class ManagementPlanRegistry
{
    private readonly object _gate = new();
    private readonly Dictionary<string, ManagementOperationPlan> _live = new(StringComparer.Ordinal);
    private readonly Func<DateTimeOffset> _clock;

    public ManagementPlanRegistry(Func<DateTimeOffset>? clock = null)
        => _clock = clock ?? SystemNow;

    private static DateTimeOffset SystemNow() => DateTimeOffset.UtcNow;

    public int LiveCount
    {
        get { lock (_gate) return _live.Count; }
    }

    internal bool TryAdd(ManagementOperationPlan plan, DateTimeOffset now)
    {
        lock (_gate)
        {
            SweepExpiredLocked(now);
            if (_live.Count >= ManagementOperationPlans.MaximumLivePlans) return false;
            _live[plan.ConfirmationToken] = plan;
            return true;
        }
    }

    public ManagementApplyVerdict TryConsume(ManagementApplyRequest request, ManagementOperationKind? operation = null)
    {
        ArgumentNullException.ThrowIfNull(request);
        var now = _clock();
        lock (_gate)
        {
            if (string.IsNullOrWhiteSpace(request.ConfirmationToken) ||
                !_live.TryGetValue(request.ConfirmationToken, out var plan))
            {
                SweepExpiredLocked(now);
                return new ManagementApplyVerdict(false, null, ManagementOperationPlans.UnknownToken,
                    "No live management plan matches this confirmation token.");
            }
            if (now >= plan.ExpiresAtUtc)
            {
                _live.Remove(request.ConfirmationToken);
                return new ManagementApplyVerdict(false, null, ManagementOperationPlans.ExpiredPlan,
                    "The management plan expired; re-observe and re-plan.");
            }
            if (operation is not null && operation != plan.Operation)
                return new(false, null, ManagementOperationPlans.OperationMismatch,
                    "The requested operation does not match the issued management plan.");
            var expectedId = ManagementOperationPlans.ComputePlanId(
                plan.Operation, plan.DeviceId, plan.ContainerUuid, plan.VolumeUuid,
                plan.VolumeObjectId, plan.ObservedCheckpointXid, plan.ExpectedCapacityChangeBytes,
                plan.IssuedAtUtc, plan.TimeToLive);
            if (!string.Equals(expectedId, plan.PlanId, StringComparison.Ordinal) ||
                !string.Equals(request.DeviceId, plan.DeviceId, StringComparison.Ordinal) ||
                request.ContainerUuid != plan.ContainerUuid ||
                request.VolumeUuid != plan.VolumeUuid ||
                request.VolumeObjectId != plan.VolumeObjectId)
                return new ManagementApplyVerdict(false, null, ManagementOperationPlans.IdentityMismatch,
                    "Apply identity does not match the issued plan; the registry copy is authoritative.");
            if (request.ObservedCheckpointXid != plan.ObservedCheckpointXid)
                return new ManagementApplyVerdict(false, null, ManagementOperationPlans.StaleCheckpoint,
                    "Checkpoint generation moved since the plan was issued; re-observe and re-plan.");
            _live.Remove(request.ConfirmationToken);
            return new ManagementApplyVerdict(true, plan, ManagementOperationPlans.Issued, null);
        }
    }

    private void SweepExpiredLocked(DateTimeOffset now)
    {
        foreach (var dead in _live.Where(entry => now >= entry.Value.ExpiresAtUtc).Select(entry => entry.Key).ToArray())
            _live.Remove(dead);
    }
}
