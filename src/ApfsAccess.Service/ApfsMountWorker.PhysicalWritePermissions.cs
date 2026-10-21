using ApfsAccess.Core;

namespace ApfsAccess.Service;

public sealed partial class ApfsMountWorker
{
    private WriteGateDecision EvaluateVolumeWriteGate(ServiceHostOptions options, VolumeInfo volume)
    {
        var resolved = _physicalWritePermissions?.Resolve(options, volume) ?? (options, volume);
        return WriteGatePolicy.EvaluateForVolume(resolved.Item1, resolved.Item2);
    }

    internal PhysicalWritePermissions.RequestPermission? BeginPhysicalWritePermission(VolumeInfo volume, CancellationToken token)
    {
        var options = _optionsMonitor.CurrentValue;
        if (_physicalWritePermissions is null || PhysicalWritePermissions.NormalizeDevice(volume.DeviceId) is null ||
            PhysicalWritePermissions.HasConfiguredRawPermission(options, volume.DeviceId)) return null;
        return _physicalWritePermissions.Begin(options, volume, token);
    }

    internal void ConfirmPhysicalWritePermission(PhysicalWritePermissions.RequestPermission permission,
        VolumeInfo current, CancellationToken token)
        => permission.Confirm(_optionsMonitor.CurrentValue, current, token);
}
