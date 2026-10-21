using System.Globalization;
using ApfsAccess.Core;

namespace ApfsAccess.Backend.Native;

public sealed partial class NativeApfsBackend : ILiveVolumeVerificationBackend
{
    public Task<LiveVolumeVerificationResult> VerifyLiveVolumeAsync(LiveVolumeVerificationScope scope, CancellationToken token)
        => VerifyLiveVolumeCoreAsync(scope, ContainerControlAction.VolumeVerify, token);

    public Task<LiveVolumeVerificationResult> VerifyLiveVolumeMetadataAsync(LiveVolumeVerificationScope scope, CancellationToken token)
        => VerifyLiveVolumeCoreAsync(scope, ContainerControlAction.VolumeVerifyMetadata, token);

    private async Task<LiveVolumeVerificationResult> VerifyLiveVolumeCoreAsync(LiveVolumeVerificationScope scope,
        ContainerControlAction action, CancellationToken token)
    {
        ArgumentNullException.ThrowIfNull(scope);
        if (!ulong.TryParse(scope.VolumeOid, NumberStyles.None, CultureInfo.InvariantCulture, out var oid) || oid == 0)
            return new(false, "VolumeVerificationScopeRequired");
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            if (!TryGetLiveContainerGroup_NoLock(scope.ContainerUuid, out var group) || group is null || group.IsPoisoned)
                return new(false, "VolumeVerificationOwnerRefused");
            var members = group.Members.Values.Where(v => v.ObjectId == oid && v.Attached).ToArray();
            if (members.Length != 1) return new(false, "VolumeVerificationOwnerRefused");
            var status = ContainerStatusReader.TryRead(group.StatusFilePath, group.ContainerUuid);
            var actual = status.IsKnown && status.LeaseHeld ? status.Volumes.SingleOrDefault(v => v.ObjectId == oid) : null;
            if (actual is not { VolumeVerificationSupported: true } || actual.VolumeVerificationScope != scope ||
                scope.StoreOffsetBytes != group.DeviceOffsetBytes.ToString(CultureInfo.InvariantCulture))
                return new(false, "VolumeVerificationScopeChanged");
            var path = group.Owner.ContainerControlFilePath; var secret = group.Owner.ContainerControlToken;
            if (string.IsNullOrWhiteSpace(path) || string.IsNullOrWhiteSpace(secret))
                return new(false, "ControlEndpointUnavailable");
            var result = await ContainerControlChannel.SendAsync(path, secret, action, oid,
                TimeSpan.FromSeconds(15), token, scope.RequestLines).ConfigureAwait(false);
            if (!result.Success || result.VerificationReport is null)
                return new(false, result.Code);
            if (result.VerificationReport.Scope != scope) return new(false, "ControlResponseInvalid");
            return new(true, result.Code, result.VerificationReport);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) when (ex is IOException or ArgumentException or InvalidOperationException)
        { return new(false, "ControlChannelFailed"); }
        finally { _gate.Release(); }
    }
}
