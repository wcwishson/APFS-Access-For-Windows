using ApfsAccess.Core;
using ApfsAccess.Ipc;

namespace ApfsAccess.Service;

public sealed class RuntimeStatusPublisher
{
    private readonly object _sync = new();
    private StatusChangedPayload _latest = new(
        RuntimeState.Starting,
        Array.Empty<string>(),
        null,
        DateTime.UtcNow,
        Array.Empty<string>(),
        WriteEnabled: false,
        CompatibilityWarnings: Array.Empty<string>(),
        MountedVolumes: Array.Empty<MountedVolumeDisplay>(),
        WriteBackend: "Disabled",
        CommitModel: NativeWriteCommitModel.ScaffoldCheckpoint,
        NativeWriteReadiness: NativeWriteReadiness.Unavailable,
        NativeWriteEngineState: NativeWriteEngineState.Scaffold,
        NativeWriteValidationState: NativeWriteValidationState.Scaffold,
        RecoveryActive: false,
        RecoveryReason: null,
        LastCommitXid: null,
        NativeWriteSafetyState: NativeWriteSafetyState.ReadOnlyFallback,
        WriteIncompatibilities: Array.Empty<string>(),
        WriteUnsupportedFeatures: Array.Empty<string>(),
        LastRecoveryAction: null,
        DirtyTransactionCount: 0,
        ShutdownDrainActive: false,
        InFlightMutationCallbacks: 0,
        NativeWriteValidationEvidence: new NativeWriteValidationEvidence(),
        NativeWriteDiagnostics: Array.Empty<NativeWriteDiagnostic>()
    );

    public event Action<StatusChangedPayload>? StatusChanged;

    public StatusChangedPayload Latest
    {
        get
        {
            lock (_sync)
            {
                return _latest;
            }
        }
    }

    public void Publish(StatusChangedPayload payload)
    {
        ArgumentNullException.ThrowIfNull(payload);

        Action<StatusChangedPayload>? handlers;
        lock (_sync)
        {
            if (PayloadSemanticallyEquals(_latest, payload))
            {
                _latest = payload;
                return;
            }

            _latest = payload;
            handlers = StatusChanged;
        }

        handlers?.Invoke(payload);
    }

    private static bool PayloadSemanticallyEquals(StatusChangedPayload left, StatusChangedPayload right)
        => left.State == right.State &&
           SequenceEqualOrdinal(left.MountPoints, right.MountPoints) &&
           string.Equals(left.LastError, right.LastError, StringComparison.Ordinal) &&
           SequenceEqualOrdinal(left.Warnings, right.Warnings) &&
           left.WriteEnabled == right.WriteEnabled &&
           SequenceEqualOrdinal(left.CompatibilityWarnings, right.CompatibilityWarnings) &&
           MountedVolumesEqual(left.MountedVolumes, right.MountedVolumes) &&
           string.Equals(left.WriteBackend, right.WriteBackend, StringComparison.Ordinal) &&
           left.CommitModel == right.CommitModel &&
           left.NativeWriteReadiness == right.NativeWriteReadiness &&
           left.NativeWriteEngineState == right.NativeWriteEngineState &&
           left.NativeWriteValidationState == right.NativeWriteValidationState &&
           left.RecoveryActive == right.RecoveryActive &&
           string.Equals(left.RecoveryReason, right.RecoveryReason, StringComparison.Ordinal) &&
           left.LastCommitXid == right.LastCommitXid &&
           left.NativeWriteSafetyState == right.NativeWriteSafetyState &&
           SequenceEqualOrdinal(left.WriteIncompatibilities, right.WriteIncompatibilities) &&
           SequenceEqualOrdinal(left.WriteUnsupportedFeatures, right.WriteUnsupportedFeatures) &&
           string.Equals(left.LastRecoveryAction, right.LastRecoveryAction, StringComparison.Ordinal) &&
           left.DirtyTransactionCount == right.DirtyTransactionCount &&
           left.ShutdownDrainActive == right.ShutdownDrainActive &&
           left.InFlightMutationCallbacks == right.InFlightMutationCallbacks &&
           Equals(left.NativeWriteValidationEvidence, right.NativeWriteValidationEvidence) &&
           NativeWriteDiagnosticsEqual(left.NativeWriteDiagnostics, right.NativeWriteDiagnostics);

    private static bool SequenceEqualOrdinal(IReadOnlyList<string>? left, IReadOnlyList<string>? right)
    {
        left ??= Array.Empty<string>();
        right ??= Array.Empty<string>();
        return left.SequenceEqual(right, StringComparer.Ordinal);
    }

    private static bool MountedVolumesEqual(
        IReadOnlyList<MountedVolumeDisplay>? left,
        IReadOnlyList<MountedVolumeDisplay>? right)
    {
        left ??= Array.Empty<MountedVolumeDisplay>();
        right ??= Array.Empty<MountedVolumeDisplay>();
        return left.SequenceEqual(right);
    }

    private static bool NativeWriteDiagnosticsEqual(
        IReadOnlyList<NativeWriteDiagnostic>? left,
        IReadOnlyList<NativeWriteDiagnostic>? right)
    {
        left ??= Array.Empty<NativeWriteDiagnostic>();
        right ??= Array.Empty<NativeWriteDiagnostic>();
        return left.SequenceEqual(right);
    }
}
