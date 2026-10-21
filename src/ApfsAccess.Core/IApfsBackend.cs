namespace ApfsAccess.Core;

public interface IApfsBackend
{
    Task<IReadOnlyList<DeviceInfo>> ProbeDevicesAsync(CancellationToken cancellationToken);

    Task<IReadOnlyList<VolumeInfo>> ProbeVolumesAsync(string deviceId, CancellationToken cancellationToken);

    // One complete catalog observation. Backends with discovery caches must bypass
    // them when authoritative is true; a disk layout alone cannot prove APFS UUIDs.
    // The default preserves backends whose probes already read their current inventory.
    async Task<IReadOnlyList<DeviceInventory>> ProbeInventoryAsync(bool authoritative, CancellationToken cancellationToken)
    {
        var devices = await ProbeDevicesAsync(cancellationToken).ConfigureAwait(false);
        var inventory = new List<DeviceInventory>();
        foreach (var device in devices.Where(d => d.IsConnected))
        {
            cancellationToken.ThrowIfCancellationRequested();
            inventory.Add(new(device, await ProbeVolumesAsync(device.DeviceId, cancellationToken).ConfigureAwait(false)));
        }
        cancellationToken.ThrowIfCancellationRequested();
        return inventory;
    }

    Task<MountResult> MountAsync(MountRequest request, CancellationToken cancellationToken);

    Task<UnmountResult> UnmountAsync(string mountPoint, CancellationToken cancellationToken);

    Task<IReadOnlyList<MountedVolumeState>> GetMountStateAsync(CancellationToken cancellationToken);
}

public interface IContainerMountBackend
{
    Task<IReadOnlyList<MountResult>> MountContainerAsync(
        IReadOnlyList<MountRequest> requests,
        CancellationToken cancellationToken);
}

public enum SnapshotControlAction
{
    Create,
    Delete,
    Recover,
    List,
}

public sealed record SnapshotControlResult(bool Success, string Code, LiveSnapshotInventory? Inventory = null);

public interface ISnapshotControlBackend
{
    // Sends a snapshot control request to the live container owner session
    // identified by stable container UUID and volume object ID. The backend
    // supplies the owner-held control path and token; callers never provide
    // journal paths or registry material. Extra lines carry the validated
    // snapshot parameters (create: name; delete: nine-line exact identity;
    // recover: none).
    Task<SnapshotControlResult> SendSnapshotControlAsync(
        string containerUuid,
        ulong volumeObjectId,
        SnapshotControlAction action,
        IReadOnlyList<string>? extraLines,
        CancellationToken cancellationToken);
}

public sealed record ImageVerifyResult(
    bool Supported,
    string Outcome,
    int NativeExitCode,
    int FindingCount,
    string? Detail);

public interface IVerifyBackend
{
    // Read-only offline verification of one derived scope. The scope binds
    // the exact image path, container, volume, checkpoint, and store window
    // from observed inventory records; the backend re-validates the scope
    // shape, leases the image read-only, runs the bounded native observer,
    // and verifies every report claim (exit code, scope echo, identity,
    // findings, coverage) before returning. Tool failures throw
    // (NativeVerificationExitException, FileNotFoundException, or
    // InvalidDataException on tamper); callers map those to typed
    // verify-error evidence. Never a repair authorization.
    Task<ImageVerifyResult> VerifyImageAsync(
        VerifyScope scope,
        CancellationToken cancellationToken);
}
