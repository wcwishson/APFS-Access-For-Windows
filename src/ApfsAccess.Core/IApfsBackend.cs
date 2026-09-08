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
