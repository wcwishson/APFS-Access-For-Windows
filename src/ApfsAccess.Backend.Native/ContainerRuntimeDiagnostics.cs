using ApfsAccess.Core;

namespace ApfsAccess.Backend.Native;

internal sealed record ContainerRuntimeDiagnostics(NativeWriteCommitModel CommitModel,
    NativeWriteReadiness Readiness, NativeWriteEngineState EngineState, NativeWriteValidationState ValidationState)
{
    internal static MountedVolumeState ApplyWatermarks(MountedVolumeState current, bool known, ContainerVolumeStatus? child)
    {
        var drain = known ? child?.Drain : null;
        return current with { RuntimeWatermarksKnown = drain is not null, RuntimeMutationPending = drain?.Pending ?? true,
            DirtyTransactionCount = drain?.DirtyTransactions ?? current.DirtyTransactionCount,
            InFlightMutationCallbacks = drain?.InFlightCallbacks ?? current.InFlightMutationCallbacks,
            ShutdownDrainActive = drain?.ShutdownDrain ?? current.ShutdownDrainActive,
            WalAcceptedSequence = drain?.Accepted ?? current.WalAcceptedSequence,
            WalApfsDurableSequence = drain?.Durable ?? current.WalApfsDurableSequence,
            WalCleanupSequence = drain?.Cleanup ?? current.WalCleanupSequence };
    }
    // Runtime labels do not mint hardware or macOS acceptance evidence.
    internal static ContainerRuntimeDiagnostics Project(bool canonicalOnly, bool known, bool leaseHeld,
        bool ready, bool writable, bool recovery, bool degraded, ulong checkpointXid)
    {
        var proven = canonicalOnly && known && leaseHeld && ready && checkpointXid != 0;
        var readiness = !known || !leaseHeld || !ready ? NativeWriteReadiness.Unavailable :
            recovery ? NativeWriteReadiness.RecoveryMode : degraded ? NativeWriteReadiness.Degraded :
            proven && writable ? NativeWriteReadiness.CommitReady : NativeWriteReadiness.Unavailable;
        return new(canonicalOnly ? NativeWriteCommitModel.CanonicalApfsCheckpoint : NativeWriteCommitModel.ScaffoldCheckpoint,
            readiness,
            proven && (writable || recovery || degraded) ? NativeWriteEngineState.Transactional : NativeWriteEngineState.Scaffold,
            proven && writable && !recovery && !degraded ? NativeWriteValidationState.CanonicalImageValidated : NativeWriteValidationState.Scaffold);
    }
}
