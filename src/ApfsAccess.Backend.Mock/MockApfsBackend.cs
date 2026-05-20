using System.Collections.Concurrent;
using ApfsAccess.Core;

namespace ApfsAccess.Backend.Mock;

public sealed class MockApfsBackend : IApfsBackend
{
    private const string DeviceId = "mock-device-1";

    private static readonly IReadOnlyList<DeviceInfo> AttachedDevice =
    [
        new(DeviceId, "Mock APFS External SSD", true),
    ];

    private static readonly IReadOnlyList<VolumeInfo> Volumes =
    [
        new(
            "mock-volume-main",
            DeviceId,
            "APFS_Main",
            true,
            false,
            true,
            @"\\.\PhysicalDriveMock\ApfsAccess_Volumes\APFS_Main",
            SupportsNativeWrite: true,
            WriteBlockReason: null,
            NativeWriteReadiness: NativeWriteReadiness.CommitReady
        ),
        new(
            "mock-volume-archive",
            DeviceId,
            "APFS_Archive",
            false,
            false,
            true,
            @"\\.\PhysicalDriveMock\ApfsAccess_Volumes\APFS_Archive",
            SupportsNativeWrite: false,
            WriteBlockReason: "Mock archive volume is read-only in baseline profile.",
            NativeWriteReadiness: NativeWriteReadiness.Unavailable
        ),
    ];

    private readonly ConcurrentDictionary<string, MountedVolumeState> _mounts = new(StringComparer.OrdinalIgnoreCase);
    private int _probeCounter;

    public Task<IReadOnlyList<DeviceInfo>> ProbeDevicesAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Interlocked.Increment(ref _probeCounter);

        return Task.FromResult<IReadOnlyList<DeviceInfo>>(IsAttached()
            ? AttachedDevice
            : Array.Empty<DeviceInfo>());
    }

    public Task<IReadOnlyList<VolumeInfo>> ProbeVolumesAsync(string deviceId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!IsAttached() || !string.Equals(deviceId, DeviceId, StringComparison.OrdinalIgnoreCase))
        {
            return Task.FromResult<IReadOnlyList<VolumeInfo>>(Array.Empty<VolumeInfo>());
        }

        return Task.FromResult(Volumes);
    }

    public Task<MountResult> MountAsync(MountRequest request, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (!IsAttached())
        {
            return Task.FromResult(new MountResult(
                false,
                null,
                "APFS device is not attached.",
                request.AccessMode,
                "DeviceNotAttached",
                request.AccessMode == MountAccessMode.ReadOnly,
                WriteEnabled: false,
                SafetyGateState: "DeviceUnavailable"
            ));
        }

        var volume = Volumes.FirstOrDefault(x => string.Equals(x.VolumeId, request.VolumeId, StringComparison.OrdinalIgnoreCase));
        if (volume is null)
        {
            return Task.FromResult(new MountResult(
                false,
                null,
                $"Unknown volume id '{request.VolumeId}'.",
                request.AccessMode,
                "UnknownVolume",
                request.AccessMode == MountAccessMode.ReadOnly,
                WriteEnabled: false,
                SafetyGateState: "UnknownVolume"
            ));
        }

        if (request.AccessMode == MountAccessMode.ReadWrite && !volume.SupportsReadWrite)
        {
            return Task.FromResult(new MountResult(
                false,
                null,
                "Volume does not support read-write mode.",
                MountAccessMode.ReadOnly,
                "ReadWriteNotSupported",
                true,
                WriteEnabled: false,
                SafetyGateState: "VolumeCapability"
            ));
        }

        var mountPoint = $"{char.ToUpperInvariant(request.DriveLetter)}:\\";
        if (_mounts.ContainsKey(mountPoint))
        {
            return Task.FromResult(new MountResult(
                false,
                null,
                $"Mount point '{mountPoint}' is already in use.",
                request.AccessMode,
                "MountPointBusy",
                request.AccessMode == MountAccessMode.ReadOnly,
                WriteEnabled: false,
                SafetyGateState: "MountPointBusy"
            ));
        }

        var writeBackend = request.AccessMode == MountAccessMode.ReadWrite ? "Native" : "Disabled";
        var readiness = request.AccessMode == MountAccessMode.ReadWrite
            ? NativeWriteReadiness.CommitReady
            : NativeWriteReadiness.Unavailable;
        var state = new MountedVolumeState(
            volume.VolumeId,
            mountPoint,
            request.AccessMode,
            WriteBackend: writeBackend,
            NativeWriteReadiness: readiness,
            RecoveryActive: false,
            LastCommitXid: request.AccessMode == MountAccessMode.ReadWrite ? 1UL : null
        );
        if (!_mounts.TryAdd(mountPoint, state))
        {
            return Task.FromResult(new MountResult(
                false,
                null,
                $"Failed to reserve mount point '{mountPoint}'.",
                request.AccessMode,
                "MountPointReservationFailed",
                request.AccessMode == MountAccessMode.ReadOnly,
                WriteEnabled: false,
                SafetyGateState: "MountReservation"
            ));
        }

        return Task.FromResult(new MountResult(
            true,
            mountPoint,
            null,
            request.AccessMode,
            null,
            request.AccessMode == MountAccessMode.ReadOnly,
            WriteEnabled: request.AccessMode == MountAccessMode.ReadWrite,
            SafetyGateState: request.AccessMode == MountAccessMode.ReadWrite ? "Enabled" : "ReadOnly",
            WriteBackend: writeBackend,
            NativeWriteReadiness: readiness
        ));
    }

    public Task<UnmountResult> UnmountAsync(string mountPoint, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (string.IsNullOrWhiteSpace(mountPoint))
        {
            return Task.FromResult(new UnmountResult(false, mountPoint, "Mount point was not provided."));
        }

        if (_mounts.TryRemove(mountPoint, out _))
        {
            return Task.FromResult(new UnmountResult(true, mountPoint, null));
        }

        return Task.FromResult(new UnmountResult(false, mountPoint, $"Mount point '{mountPoint}' was not mounted."));
    }

    public Task<IReadOnlyList<MountedVolumeState>> GetMountStateAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (!IsAttached())
        {
            _mounts.Clear();
            return Task.FromResult<IReadOnlyList<MountedVolumeState>>(Array.Empty<MountedVolumeState>());
        }

        return Task.FromResult<IReadOnlyList<MountedVolumeState>>(_mounts.Values.OrderBy(x => x.MountPoint, StringComparer.OrdinalIgnoreCase).ToArray());
    }

    private bool IsAttached()
    {
        // 5 probe cycles attached, next 5 detached, then repeat.
        var cycleIndex = Math.Max(0, _probeCounter - 1) / 5;
        return cycleIndex % 2 == 0;
    }
}
