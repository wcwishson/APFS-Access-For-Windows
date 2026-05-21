using System.Text.Json.Nodes;
using ApfsAccess.Core;

namespace ApfsAccess.Ipc;

public sealed record PipeEnvelope(string Type, string? RequestId, JsonObject? Payload);

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

public sealed record EjectRequestedPayload(string Requester, DateTime TimestampUtc, string? VolumeId = null);

public sealed record RefreshRequestedPayload(
    string Requester,
    DateTime TimestampUtc,
    bool ClearUserEjectedVolumes = false
);

public sealed record AckPayload(bool Success, string? Message);

public sealed record PingPayload(DateTime TimestampUtc);

public sealed record PongPayload(DateTime TimestampUtc);

public sealed record MountedVolumeDisplay(
    string VolumeId,
    string MountPoint,
    string VolumeName,
    string DeviceId,
    string DeviceDisplayName,
    MountAccessMode AccessMode
);
