using System.Text.Json.Nodes;
using ApfsAccess.Core;

namespace ApfsAccess.Ipc;

public static class PipeSchemaVersions
{
    public const int Schema1 = 1;
    public const int Schema2 = 2;
}

public sealed record PipeEnvelope(
    string Type,
    string? RequestId,
    JsonObject? Payload,
    int SchemaVersion = PipeSchemaVersions.Schema1);

public sealed record StatusChangedPayload(
    RuntimeState State,
    IReadOnlyList<string> MountPoints,
    string? LastError,
    DateTime TimestampUtc,
    IReadOnlyList<string> Warnings,
    bool WriteEnabled,
    IReadOnlyList<string> CompatibilityWarnings,
    IReadOnlyList<MountedVolumeDisplay>? MountedVolumes = null,
    string WriteBackend = "Disabled",
    NativeWriteCommitModel CommitModel = NativeWriteCommitModel.ScaffoldCheckpoint,
    NativeWriteReadiness NativeWriteReadiness = NativeWriteReadiness.Unavailable,
    NativeWriteEngineState NativeWriteEngineState = NativeWriteEngineState.Scaffold,
    NativeWriteValidationState NativeWriteValidationState = NativeWriteValidationState.Scaffold,
    bool RecoveryActive = false,
    string? RecoveryReason = null,
    ulong? LastCommitXid = null,
    NativeWriteSafetyState NativeWriteSafetyState = NativeWriteSafetyState.ReadOnlyFallback,
    IReadOnlyList<string>? WriteIncompatibilities = null,
    IReadOnlyList<string>? WriteUnsupportedFeatures = null,
    string? LastRecoveryAction = null,
    int DirtyTransactionCount = 0,
    bool ShutdownDrainActive = false,
    int InFlightMutationCallbacks = 0,
    NativeWriteValidationEvidence? NativeWriteValidationEvidence = null,
    IReadOnlyList<NativeWriteDiagnostic>? NativeWriteDiagnostics = null
);

public sealed record QuitRequestedPayload(string Requester, DateTime TimestampUtc);

public sealed record ServiceStoppingPayload(
    DateTime TimestampUtc,
    bool CleanupCompleted = false,
    IReadOnlyList<string>? RemainingMountPoints = null,
    bool HostOwnershipReleased = false,
    bool PendingDurabilityCleared = false,
    string? Diagnostic = null);

public sealed record EjectRequestedPayload(string Requester, DateTime TimestampUtc, string? VolumeId = null);

public sealed record RefreshRequestedPayload(
    string Requester,
    DateTime TimestampUtc,
    bool ClearUserEjectedVolumes = false,
    string? VolumeId = null
);

public sealed record MountRequestedPayload(
    string Requester,
    DateTime TimestampUtc,
    string? VolumeId = null
);

public sealed record FixRequestedPayload(
    string Requester,
    DateTime TimestampUtc,
    string? VolumeId = null
);

public sealed record InventoryPayload(
    IReadOnlyList<DeviceInventory> Devices,
    DateTime TimestampUtc
);

public static class ApfsControlCommands
{
    public const string Unknown = "unknown";
    public const string Mount = "mount";
    public const string Fix = "fix";
    public const string Eject = "eject";
    public const string Quit = "quit";
}

public static class ApfsOperationStates
{
    public const string Accepted = "accepted";
    public const string InProgress = "in-progress";
    public const string Succeeded = "succeeded";
    public const string Failed = "failed";
    public const string Cancelled = "cancelled";
}

public static class ApfsControlModes
{
    public const string ReadOnly = "read-only";
    public const string ReadWrite = "read-write";
}

public sealed record ApfsControlTarget(
    string DeviceId,
    string VolumeId,
    string? RecoveryIdentity = null);

public sealed record ControlOperationRequestPayload(
    string OperationId,
    string Command,
    ApfsControlTarget? Target,
    string? RequestedMode = null,
    DateTime? ExpiresAtUtc = null);

public sealed record OperationResultQueryPayload(string OperationId);

public sealed record OperationCancellationRequestPayload(string OperationId);

public sealed record OperationResultPayload(
    string OperationId,
    string Command,
    ApfsControlTarget? Target,
    string? Fingerprint,
    string State,
    string Code,
    bool Success,
    DateTime RequestedAtUtc,
    DateTime? StartedAtUtc = null,
    DateTime? CompletedAtUtc = null,
    string? FinalStatus = null,
    string? EvidencePath = null,
    string? RequestedMode = null,
    string? EffectiveMode = null,
    string? RecoveryState = null,
    bool RecoveryActive = false,
    int DirtyTransactionCount = 0,
    bool PendingDurability = false,
    string? MountProof = null,
    string? OwnershipProof = null,
    string? DurabilityProof = null,
    string? Diagnostic = null,
    bool QuitMarkerWritten = false,
    DateTime? ExpiresAtUtc = null);

public sealed record AckPayload(
    bool Success,
    string? Message,
    string Code = ApfsOperationCodes.OperationSucceeded,
    StatusChangedPayload? Status = null);

public static class ApfsOperationCodes
{
    public const string OperationSucceeded = "ok";
    public const string AlreadyAchieved = "already-achieved";
    public const string InvalidArguments = "invalid-arguments";
    public const string MissingVolume = "missing-volume";
    public const string Timeout = "timeout";
    public const string BlockedRecovery = "blocked-recovery";
    public const string UnsafeOwnership = "unsafe-ownership";
    public const string OperationFailed = "operation-failed";
    public const string MalformedMessage = "malformed-message";
    public const string UnsupportedSchema = "unsupported-schema";
    public const string UnsupportedMessageType = "unsupported-message-type";
    public const string InvalidOperationId = "invalid-operation-id";
    public const string UnknownCommand = "unknown-command";
    public const string AmbiguousTarget = "ambiguous-target";
    public const string ElevationFailed = "elevation-failed";
    public const string OperationConflict = "operation-conflict";
    public const string OperationInProgress = "operation-in-progress";
    public const string OperationCancelled = "operation-cancelled";
    public const string NotCancellable = "not-cancellable";
    public const string ServiceUnavailable = "service-unavailable";
}

public sealed record PipeMessageValidationResult(
    bool IsValid,
    string Code,
    string? Diagnostic);

public sealed record PingPayload(DateTime TimestampUtc);

public sealed record PongPayload(DateTime TimestampUtc);

public sealed record MountedVolumeDisplay(
    string VolumeId,
    string MountPoint,
    string VolumeName,
    string DeviceId,
    string DeviceDisplayName,
    MountAccessMode AccessMode,
    string? RecoveryIdentity = null,
    RuntimeState State = RuntimeState.MountedRo,
    bool WriteEnabled = false,
    string WriteBackend = "Disabled",
    NativeWriteCommitModel CommitModel = NativeWriteCommitModel.ScaffoldCheckpoint,
    NativeWriteReadiness NativeWriteReadiness = NativeWriteReadiness.Unavailable,
    NativeWriteEngineState NativeWriteEngineState = NativeWriteEngineState.Scaffold,
    NativeWriteValidationState NativeWriteValidationState = NativeWriteValidationState.Scaffold,
    NativeWriteSafetyState NativeWriteSafetyState = NativeWriteSafetyState.ReadOnlyFallback,
    bool RecoveryActive = false,
    string? RecoveryReason = null,
    string? LastRecoveryAction = null,
    ulong? LastCommitXid = null,
    IReadOnlyList<string>? WriteIncompatibilities = null,
    IReadOnlyList<string>? WriteUnsupportedFeatures = null,
    int DirtyTransactionCount = 0,
    bool ShutdownDrainActive = false,
    int InFlightMutationCallbacks = 0,
    NativeWriteValidationEvidence? NativeWriteValidationEvidence = null,
    IReadOnlyList<NativeWriteDiagnostic>? NativeWriteDiagnostics = null,
    bool MountReady = false,
    int HostProcessId = 0,
    ulong WalAcceptedSequence = 0,
    ulong WalApfsDurableSequence = 0,
    ulong WalCleanupSequence = 0,
    bool PendingDurability = false,
    string HostOwnershipState = "unknown"
);
