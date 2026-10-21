using ApfsAccess.Core;

namespace ApfsAccess.Backend.Native;

public interface IUnmountTerminalStateBackend
{
    // A read of the selected incarnation's retained proof, never a new stop request.
    Task<UnmountResult> GetUnmountTerminalStateAsync(
        MountedVolumeState selected, CancellationToken cancellationToken);
}

public sealed partial class NativeApfsBackend : IUnmountTerminalStateBackend
{
    private const int MaxCompletedUnmountTerminalOwners = 256;
    private readonly object _unmountTerminalSync = new();
    // Unresolved entries carry only an identity and tracking key, never host resources.
    // Completed immutable proofs have a bounded FIFO; eviction remains unproven.
    private readonly Dictionary<UnmountOwnerIdentity, RetainedUnmountTerminalState> _unmountTerminalOwners = new();
    private readonly Queue<UnmountOwnerIdentity> _completedUnmountTerminalOwners = new();

    public async Task<UnmountResult> GetUnmountTerminalStateAsync(
        MountedVolumeState selected, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(selected);
        cancellationToken.ThrowIfCancellationRequested();
        using var operationLease = AcquireLifecycleOperationLease();
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            lock (_unmountTerminalSync)
            {
                if (selected.HostProcessId <= 0 || selected.HostProcessCreationTimeFileTimeUtc <= 0 ||
                    !_unmountTerminalOwners.TryGetValue(UnmountOwnerIdentity.From(selected), out var retained))
                    return new(false, selected.MountPoint,
                        "No retained terminal proof matches the original volume and host incarnation.");

                // Only the original cleanup path can publish this immutable result.
                return retained.Proof is { } completed
                    ? BuildCompletedUnmountResult(selected.MountPoint, completed)
                    : new(false, selected.MountPoint, "The original host's terminal cleanup proof is not yet available.");
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    private void RetainUnmountTerminalOwners_NoLock()
    {
        foreach (var row in _mounts.Values)
        {
            HostProcessState? owner = null;
            if (_hosts.TryGetValue(row.MountPoint, out var legacy)) owner = legacy;
            else owner = _containerGroups.Values.FirstOrDefault(group =>
                group.Members.ContainsKey(row.MountPoint))?.Owner;
            if (owner is null || owner.ProcessId <= 0 || owner.ProcessCreationTimeFileTimeUtc is not > 0 ||
                row.HostProcessId != owner.ProcessId ||
                row.HostProcessCreationTimeFileTimeUtc != 0 &&
                row.HostProcessCreationTimeFileTimeUtc != owner.ProcessCreationTimeFileTimeUtc)
                continue;

            var original = row with { HostProcessCreationTimeFileTimeUtc = owner.ProcessCreationTimeFileTimeUtc.Value };
            lock (_unmountTerminalSync)
            {
                var identity = UnmountOwnerIdentity.From(original);
                var retained = new RetainedUnmountTerminalState(owner.TrackingKey, owner.CompletedStopResult);
                if (_unmountTerminalOwners.TryAdd(identity, retained) && retained.Proof is not null)
                    BoundCompletedUnmountTerminalOwners_NoLock(identity);
            }
        }
    }

    private void PublishUnmountTerminalProof(HostProcessState owner)
    {
        lock (_unmountTerminalSync)
        {
            if (owner.CompletedStopResult is not { } completed) return;
            var pending = _unmountTerminalOwners.Where(entry =>
                entry.Value.Proof is null && entry.Value.OwnerTrackingKey == owner.TrackingKey)
                .Select(entry => entry.Key).ToArray();
            foreach (var identity in pending)
            {
                _unmountTerminalOwners[identity] = new(owner.TrackingKey, completed);
                BoundCompletedUnmountTerminalOwners_NoLock(identity);
            }
        }
    }

    private void BoundCompletedUnmountTerminalOwners_NoLock(UnmountOwnerIdentity identity)
    {
        _completedUnmountTerminalOwners.Enqueue(identity);
        while (_completedUnmountTerminalOwners.Count > MaxCompletedUnmountTerminalOwners)
            _unmountTerminalOwners.Remove(_completedUnmountTerminalOwners.Dequeue());
    }

    private sealed record RetainedUnmountTerminalState(string OwnerTrackingKey, HostStopResult? Proof);

    private readonly record struct UnmountOwnerIdentity(
        string MountPoint, string? DeviceId, string VolumeId, string? RecoveryIdentity,
        int ProcessId, long CreationTime, string? ContainerUuid, ulong? VolumeObjectId, string? VolumeUuid)
    {
        public static UnmountOwnerIdentity From(MountedVolumeState row)
            => new(row.MountPoint.ToUpperInvariant(), row.DeviceId?.ToUpperInvariant(),
                row.VolumeId.ToUpperInvariant(), row.RecoveryIdentity, row.HostProcessId,
                row.HostProcessCreationTimeFileTimeUtc, row.CatalogContainerUuid?.ToUpperInvariant(),
                row.CatalogVolumeObjectId, row.CatalogVolumeUuid?.ToUpperInvariant());
    }
}
