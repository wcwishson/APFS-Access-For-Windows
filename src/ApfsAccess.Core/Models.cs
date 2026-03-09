namespace ApfsAccess.Core;

public enum MountAccessMode
{
    ReadWrite = 0,
    ReadOnly = 1,
}

public enum RuntimeState
{
    Starting = 0,
    Idle = 1,
    MountedRw = 2,
    MountedRo = 3,
    Error = 4,
    Stopping = 5,
}

public enum NativeWriteReadiness
{
    Unavailable = 0,
    BootstrapReady = 1,
    MutationReady = 2,
    CommitReady = 3,
    RecoveryMode = 4,
    Degraded = 5,
}

public enum NativeWriteSafetyState
{
    ReadOnlyFallback = 0,
    PilotReadWrite = 1,
    StableReadWrite = 2,
    RecoveryBlocked = 3,
}

public enum NativeWriteEngineState
{
    Scaffold = 0,
    Transactional = 1,
    HardwareValidated = 2,
    Stable = 3,
}

public enum NativeWriteValidationState
{
    Scaffold = 0,
    CanonicalImageValidated = 1,
    HardwarePilotValidated = 2,
    CrossOsValidated = 3,
    Stable = 4,
}

public enum NativeWriteCommitModel
{
    ScaffoldCheckpoint = 0,
    CanonicalApfsCheckpoint = 1,
}

public sealed record NativeWriteValidationEvidence(
    int CrashFaultPasses = 0,
    int CrashStageMatrixPasses = 0,
    int HardwarePilotPasses = 0,
    int HotUnplugPasses = 0,
    int MacOsValidationPasses = 0,
    int MacOsConsistencyPasses = 0,
    int PowerLossReplayPasses = 0,
    bool PowerLossPassVerified = false,
    DateTime? LastValidatedUtc = null,
    string? LastValidationProfileId = null
);

public sealed record NativeWriteDiagnostic(
    string Code,
    string Message,
    bool IsFailClosed = false,
    string Scope = "Runtime",
    string? RecoveryReason = null,
    string? RecoveryAction = null,
    NativeWriteValidationState ValidationState = NativeWriteValidationState.Scaffold,
    NativeWriteValidationState RequiredValidationState = NativeWriteValidationState.Scaffold,
    NativeWriteValidationEvidence? ValidationEvidence = null,
    string? CommitStage = null,
    string? ReplayStage = null,
    string? CommitBlobMagic = null,
    bool? CanonicalPathActive = null,
    string? DeviceProfileId = null,
    string? ValidationScenario = null,
    string? EvidenceSnapshotId = null
)
{
    public bool? ReplayCheckpointCandidatePresent { get; init; }

    public bool? ReplayCheckpointPendingWindow { get; init; }
}

public sealed record DeviceInfo(string DeviceId, string DisplayName, bool IsConnected);

public sealed record VolumeInfo(
    string VolumeId,
    string DeviceId,
    string VolumeName,
    bool SupportsReadWrite,
    bool IsEncrypted = false,
    bool SupportsExplorerMount = true,
    string? NativeVolumePath = null,
    bool SupportsNativeWrite = false,
    string? WriteBlockReason = null,
    IReadOnlyList<string>? WriteIncompatibilities = null,
    IReadOnlyList<string>? WriteUnsupportedFeatures = null,
    NativeWriteReadiness NativeWriteReadiness = NativeWriteReadiness.Unavailable
);

public sealed record MountRequest(string VolumeId, char DriveLetter, MountAccessMode AccessMode);

public sealed record MountResult(
    bool Success,
    string? MountPoint,
    string? Error,
    MountAccessMode EffectiveAccessMode,
    string? DiagnosticCode = null,
    bool IsReadOnly = false,
    bool WriteEnabled = false,
    string? SafetyGateState = null,
    string WriteBackend = "Disabled",
    NativeWriteCommitModel CommitModel = NativeWriteCommitModel.ScaffoldCheckpoint,
    NativeWriteReadiness NativeWriteReadiness = NativeWriteReadiness.Unavailable,
    NativeWriteEngineState NativeWriteEngineState = NativeWriteEngineState.Scaffold,
    NativeWriteValidationState NativeWriteValidationState = NativeWriteValidationState.Scaffold,
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

public sealed record UnmountResult(bool Success, string MountPoint, string? Error);

public sealed record MountedVolumeState(
    string VolumeId,
    string MountPoint,
    MountAccessMode AccessMode,
    string WriteBackend = "Disabled",
    NativeWriteCommitModel CommitModel = NativeWriteCommitModel.ScaffoldCheckpoint,
    NativeWriteReadiness NativeWriteReadiness = NativeWriteReadiness.Unavailable,
    NativeWriteEngineState NativeWriteEngineState = NativeWriteEngineState.Scaffold,
    NativeWriteValidationState NativeWriteValidationState = NativeWriteValidationState.Scaffold,
    bool RecoveryActive = false,
    ulong? LastCommitXid = null,
    string? RecoveryReason = null,
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
