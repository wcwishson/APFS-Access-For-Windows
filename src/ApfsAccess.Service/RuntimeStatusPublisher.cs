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

    // Installation is atomic with respect to every publisher. Defer notification so
    // callers can also release their admission lock before invoking arbitrary subscribers.
    public bool TryPublish(StatusChangedPayload expected, StatusChangedPayload payload, out Action? notification)
    {
        ArgumentNullException.ThrowIfNull(expected);
        ArgumentNullException.ThrowIfNull(payload);
        notification = null;
        lock (_sync)
        {
            if (!ReferenceEquals(_latest, expected)) return false;
            var changed = !PayloadSemanticallyEquals(_latest, payload);
            _latest = payload;
            var handlers = StatusChanged;
            if (changed && handlers is not null) notification = () => handlers(payload);
            return true;
        }
    }

    private static bool PayloadSemanticallyEquals(StatusChangedPayload left, StatusChangedPayload right)
        => left.State == right.State &&
           SequenceEqualOrdinal(left.MountPoints, right.MountPoints) &&
           string.Equals(left.LastError, right.LastError, StringComparison.Ordinal) &&
           SequenceEqualOrdinal(left.Warnings, right.Warnings) &&
           left.WriteEnabled == right.WriteEnabled &&
           SequenceEqualOrdinal(left.CompatibilityWarnings, right.CompatibilityWarnings) &&
           MountedVolumesEqual(left.MountedVolumes, right.MountedVolumes) &&
           ConnectedInventoryEqual(left.ConnectedInventory, right.ConnectedInventory) &&
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

    private static bool ConnectedInventoryEqual(
        IReadOnlyList<DeviceInventory>? left, IReadOnlyList<DeviceInventory>? right)
        => UnorderedEqual(left, right, (a, b) =>
            a.Device == b.Device && UnorderedEqual(a.Volumes, b.Volumes, InventoryVolumeEqual));

    private static bool InventoryVolumeEqual(VolumeInfo left, VolumeInfo right)
        // Records compare list references. Compare those lists by content, then let
        // record equality retain all scalar and nested value-record comparisons.
        => UnorderedEqual(left.WriteIncompatibilities, right.WriteIncompatibilities, StringEqualsOrdinal) &&
           UnorderedEqual(left.WriteUnsupportedFeatures, right.WriteUnsupportedFeatures, StringEqualsOrdinal) &&
           UnorderedEqual(left.CatalogReasons, right.CatalogReasons, StringEqualsOrdinal) &&
           left == right with
           {
               WriteIncompatibilities = left.WriteIncompatibilities,
               WriteUnsupportedFeatures = left.WriteUnsupportedFeatures,
               CatalogReasons = left.CatalogReasons,
           };

    private static bool StringEqualsOrdinal(string left, string right)
        => string.Equals(left, right, StringComparison.Ordinal);

    private static bool UnorderedEqual<T>(
        IReadOnlyList<T>? left, IReadOnlyList<T>? right, Func<T, T, bool> equals)
    {
        left ??= Array.Empty<T>();
        right ??= Array.Empty<T>();
        if (left.Count != right.Count) return false;
        // Scan order is not inventory state. Match each entry once so duplicate
        // routing identities remain observable rather than being collapsed.
        var matched = new bool[right.Count];
        foreach (var item in left)
        {
            var index = -1;
            for (var i = 0; i < right.Count; i++)
            {
                if (!matched[i] && equals(item, right[i])) { index = i; break; }
            }
            if (index < 0) return false;
            matched[index] = true;
        }
        return true;
    }

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
