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
            _latest = payload;
            handlers = StatusChanged;
        }

        handlers?.Invoke(payload);
    }
}
