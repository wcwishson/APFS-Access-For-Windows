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
           left.InventoryGeneration.HasValue == right.InventoryGeneration.HasValue &&
           (left.InventoryGeneration is > 0) == (right.InventoryGeneration is > 0) &&
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
            a.Device == b.Device && TopologyEqual(a.Topology, b.Topology) && UnorderedEqual(a.Volumes, b.Volumes, InventoryVolumeEqual));

    private static bool TopologyEqual(ApfsDiscoveryTopology? left, ApfsDiscoveryTopology? right)
    {
        if (ReferenceEquals(left, right)) return true;
        if (left is null || right is null) return false;
        if ((left.Generation > 0) != (right.Generation > 0)) return false;
        // Observation counters do not change the displayed graph. Still install the
        // latest payload so command admission can use its current generation.
        var a = left.Snapshot; var b = right.Snapshot;
        if (a is null || b is null)
            return a is null && b is null && left.DeviceId == right.DeviceId &&
                UnorderedEqual(left.DiskIds, right.DiskIds, StringEqualsOrdinal);
        return left.DeviceId == right.DeviceId &&
            UnorderedEqual(left.DiskIds, right.DiskIds, StringEqualsOrdinal) &&
            UnorderedEqual(a.Disks, b.Disks, (x, y) => x == y) &&
            UnorderedEqual(a.Partitions, b.Partitions, (x, y) => x == y) &&
            UnorderedEqual(a.Stores, b.Stores, (x, y) => x == y) &&
            UnorderedEqual(a.Containers, b.Containers, ContainerEqual) &&
            UnorderedEqual(a.Volumes, b.Volumes, CatalogVolumeEqual) &&
            UnorderedEqual(a.Groups, b.Groups, (x, y) =>
                UnorderedEqual(x.VolumeIds, y.VolumeIds, StringEqualsOrdinal) && x == y with { VolumeIds = x.VolumeIds });
    }

    private static bool ContainerEqual(ApfsContainerRecord x, ApfsContainerRecord y)
        => UnorderedEqual(x.StoreIds, y.StoreIds, StringEqualsOrdinal) &&
           UnorderedEqual(x.VolumeIds, y.VolumeIds, StringEqualsOrdinal) &&
           UnorderedEqual(x.CompatibleFeatureBits, y.CompatibleFeatureBits, StringEqualsOrdinal) &&
           UnorderedEqual(x.UnknownFeatureBits, y.UnknownFeatureBits, StringEqualsOrdinal) &&
           UnorderedEqual(x.IncompatibleFeatureBits, y.IncompatibleFeatureBits, StringEqualsOrdinal) &&
           UnorderedEqual(x.ReadonlyFeatureBits ?? [], y.ReadonlyFeatureBits ?? [], StringEqualsOrdinal) &&
           SharedSpaceEqual(x.SharedSpace, y.SharedSpace) &&
           x == y with { StoreIds = x.StoreIds, VolumeIds = x.VolumeIds,
               CompatibleFeatureBits = x.CompatibleFeatureBits, UnknownFeatureBits = x.UnknownFeatureBits,
               IncompatibleFeatureBits = x.IncompatibleFeatureBits, ReadonlyFeatureBits = x.ReadonlyFeatureBits,
               SharedSpace = x.SharedSpace };

    private static bool SharedSpaceEqual(ApfsSharedSpaceProjection? x, ApfsSharedSpaceProjection? y)
        => ReferenceEquals(x, y) || x is not null && y is not null &&
           UnorderedEqual(x.Volumes, y.Volumes, (a, b) => a == b) && x == y with { Volumes = x.Volumes };

    private static bool CatalogVolumeEqual(ApfsVolumeRecord x, ApfsVolumeRecord y)
        => UnorderedEqual(x.Roles, y.Roles, StringEqualsOrdinal) &&
           UnorderedEqual(x.CompatibleFeatureBits, y.CompatibleFeatureBits, StringEqualsOrdinal) &&
           UnorderedEqual(x.UnknownFeatureBits, y.UnknownFeatureBits, StringEqualsOrdinal) &&
           UnorderedEqual(x.IncompatibleFeatureBits, y.IncompatibleFeatureBits, StringEqualsOrdinal) &&
           UnorderedEqual(x.ReadonlyFeatureBits ?? [], y.ReadonlyFeatureBits ?? [], StringEqualsOrdinal) &&
           x == y with { Roles = x.Roles, CompatibleFeatureBits = x.CompatibleFeatureBits,
               UnknownFeatureBits = x.UnknownFeatureBits, IncompatibleFeatureBits = x.IncompatibleFeatureBits,
               ReadonlyFeatureBits = x.ReadonlyFeatureBits };

    private static bool InventoryVolumeEqual(VolumeInfo left, VolumeInfo right)
        // Records compare list references. Compare those lists by content, then let
        // record equality retain all scalar and nested value-record comparisons.
        => UnorderedEqual(left.WriteIncompatibilities ?? [], right.WriteIncompatibilities ?? [], StringEqualsOrdinal) &&
           UnorderedEqual(left.WriteUnsupportedFeatures ?? [], right.WriteUnsupportedFeatures ?? [], StringEqualsOrdinal) &&
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
        // Null graph/identity lists are malformed, not an equivalent empty list.
        // Optional capability lists retain their legacy null/empty semantics below.
        if (left is null || right is null) return left is null && right is null;
        if (left.Count != right.Count) return false;
        // Bound comparison work even when a malformed producer bypasses validation.
        // Large lists still install as a changed payload for fail-closed consumers.
        if (left.Count > 4096) return false;
        // Scan order is not inventory state. Match each entry once so duplicate
        // routing identities remain observable rather than being collapsed.
        var matched = new bool[right.Count];
        foreach (var item in left)
        {
            var index = -1;
            for (var i = 0; i < right.Count; i++)
            {
                if (!matched[i] && (item is null ? right[i] is null : right[i] is not null && equals(item, right[i])))
                { index = i; break; }
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
        => UnorderedEqual(left ?? [], right ?? [], (a, b) =>
            SequenceEqualOrdinal(a.WriteIncompatibilities, b.WriteIncompatibilities) &&
            SequenceEqualOrdinal(a.WriteUnsupportedFeatures, b.WriteUnsupportedFeatures) &&
            UnorderedEqual(a.CatalogReasons, b.CatalogReasons, StringEqualsOrdinal) &&
            NativeWriteDiagnosticsEqual(a.NativeWriteDiagnostics, b.NativeWriteDiagnostics) &&
            a == b with { WriteIncompatibilities = a.WriteIncompatibilities,
                WriteUnsupportedFeatures = a.WriteUnsupportedFeatures, CatalogReasons = a.CatalogReasons,
                NativeWriteDiagnostics = a.NativeWriteDiagnostics });

    private static bool NativeWriteDiagnosticsEqual(
        IReadOnlyList<NativeWriteDiagnostic>? left,
        IReadOnlyList<NativeWriteDiagnostic>? right)
    {
        left ??= Array.Empty<NativeWriteDiagnostic>();
        right ??= Array.Empty<NativeWriteDiagnostic>();
        return left.SequenceEqual(right);
    }
}
