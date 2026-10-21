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
    IReadOnlyList<NativeWriteDiagnostic>? NativeWriteDiagnostics = null,
    IReadOnlyList<DeviceInventory>? ConnectedInventory = null,
    long? InventoryGeneration = null,
    IReadOnlyList<string>? VolumeManagementReadyImages = null,
    bool ManagementJournalRootInspected = false,
    bool ImageResizeFormatEnabled = false,
    bool ImageManagementMutationsEnabled = false
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
    public const string ContainerMount = "container-mount";
    public const string ContainerUnmount = "container-unmount";
    public const string DeviceEject = "device-eject";
    public const string RegisterImage = "register-image";
    public const string RegisterFusion = "register-fusion";
    public const string Unlock = "unlock";
    public const string Lock = "lock";
    public const string ImageKeyManagement = "image-key-management";
    public const string Fix = "fix";
    public const string Eject = "eject";
    public const string Quit = "quit";
    public const string SnapshotCreate = "snapshot-create";
    public const string SnapshotDelete = "snapshot-delete";
    public const string SnapshotRecover = "snapshot-recover";
    public const string SnapshotList = "snapshot-list";
    public const string ManagementPlan = "management-plan";
    public const string ManagementApply = "management-apply";
    public const string VolumeVerify = "volume-verify";
    public const string VolumeResizePlan = "volume-resize-plan";
    public const string VolumeFormatPlan = "volume-format-plan";
    public const string VolumeCreatePlan = "volume-create-plan";
    public const string VolumeDeletePlan = "volume-delete-plan";
    public const string VolumeManagementApply = "volume-management-apply";
    public const string VolumeManagementCancel = "volume-management-cancel";
    public const string VolumeManagementRecover = "volume-management-recover";
}

public static class ApfsManagementOperations
{
    public const string RenameVolume = "rename-volume";
    public const string SetQuotaReserve = "set-quota-reserve";
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

[System.Text.Json.Serialization.JsonUnmappedMemberHandling(System.Text.Json.Serialization.JsonUnmappedMemberHandling.Disallow)]
public sealed record ApfsControlTarget(
    string DeviceId,
    string VolumeId,
    string? RecoveryIdentity = null,
    string? VolumeUuid = null,
    string? ContainerUuid = null,
    ulong? VolumeObjectId = null,
    string? ObservationContract = null,
    EncryptedImageProfile? RegisteredImage = null,
    FusionImageProfile? RegisteredFusion = null);

[System.Text.Json.Serialization.JsonUnmappedMemberHandling(System.Text.Json.Serialization.JsonUnmappedMemberHandling.Disallow)]
public sealed record ControlOperationRequestPayload(
    string OperationId,
    string Command,
    ApfsControlTarget? Target,
    string? RequestedMode = null,
    DateTime? ExpiresAtUtc = null,
    [property: System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)] string? SnapshotName = null,
    [property: System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)] IReadOnlyList<string>? SnapshotIdentity = null,
    [property: System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)] string? ManagementOperation = null,
    [property: System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)] string? ManagementToken = null,
    [property: System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)] string? ManagementName = null,
    [property: System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)] string? ManagementQuotaBytes = null,
    [property: System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)] string? ManagementReserveBytes = null,
    [property: System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)] string? ManagementImagePath = null,
    [property: System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)] VolumeManagementParameters? VolumeManagement = null,
    [property: System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)] string? ApprovedImageRepairPlanId = null,
    [property: System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)] ImageKeyManagementRequest? KeyManagement = null)
{
    [System.Text.Json.Serialization.JsonIgnore] public int CredentialClientProcessId { get; init; }
    [System.Text.Json.Serialization.JsonIgnore] public long CredentialClientStartTimeUtcTicks { get; init; }
}

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
    DateTime? ExpiresAtUtc = null,
    EncryptedVolumeState? EncryptionState = null,
    [property: System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)] string? SnapshotName = null,
    [property: System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)] IReadOnlyList<string>? SnapshotIdentity = null,
    [property: System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)] string? ManagementOperation = null,
    [property: System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)] string? ManagementPlanId = null,
    [property: System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)] string? ManagementToken = null,
    [property: System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)] string? ManagementObservedXid = null,
    [property: System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)] string? ManagementName = null,
    [property: System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)] string? ManagementQuotaBytes = null,
    [property: System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)] string? ManagementReserveBytes = null,
    [property: System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)] string? ManagementImagePath = null,
    [property: System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)] System.Text.Json.JsonElement? SnapshotInventory = null,
    [property: System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)] VolumeManagementParameters? VolumeManagement = null,
    [property: System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)] System.Text.Json.JsonElement? VolumeManagementReport = null,
    [property: System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)] System.Text.Json.JsonElement? VolumeVerificationReport = null,
    [property: System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)] string? ApprovedImageRepairPlanId = null,
    [property: System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)] ImageRepairOffer? ImageRepairOffer = null,
    [property: System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)] ImageRepairReceipt? ImageRepairReceipt = null,
    [property: System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)] ImageKeyManagementRequest? KeyManagement = null,
    [property: System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)] ImageKeyManagementReceipt? KeyManagementReceipt = null);

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
    string HostOwnershipState = "unknown",
    string? CatalogVolumeId = null,
    string? CatalogContainerUuid = null,
    ulong? CatalogVolumeObjectId = null,
    ApfsCapabilityDecision? CatalogDecision = null,
    IReadOnlyList<string>? CatalogReasons = null,
    bool? CatalogAutoMountAllowed = null,
    DriveLetterPreference? DriveLetterPreference = null,
    ApfsVolumeSpaceObservation? CatalogSpace = null,
    bool HasRuntimeStatus = false,
    string? CatalogVolumeUuid = null,
    bool SnapshotInventorySupported = false,
    bool SnapshotMutationSupported = false,
    bool VolumeVerificationSupported = false,
    LiveVolumeVerificationScope? VolumeVerificationScope = null,
    bool SnapshotRecoverySupported = false,
    [property: System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingDefault)]
    long HostProcessCreationTimeFileTimeUtc = 0
);
