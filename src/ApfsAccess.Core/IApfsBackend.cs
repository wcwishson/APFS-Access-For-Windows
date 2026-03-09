namespace ApfsAccess.Core;

public interface IApfsBackend
{
    Task<IReadOnlyList<DeviceInfo>> ProbeDevicesAsync(CancellationToken cancellationToken);

    Task<IReadOnlyList<VolumeInfo>> ProbeVolumesAsync(string deviceId, CancellationToken cancellationToken);

    Task<MountResult> MountAsync(MountRequest request, CancellationToken cancellationToken);

    Task<UnmountResult> UnmountAsync(string mountPoint, CancellationToken cancellationToken);

    Task<IReadOnlyList<MountedVolumeState>> GetMountStateAsync(CancellationToken cancellationToken);
}
