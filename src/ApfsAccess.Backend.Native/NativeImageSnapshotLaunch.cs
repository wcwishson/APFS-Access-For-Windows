using ApfsAccess.Core;

namespace ApfsAccess.Backend.Native;

internal static class NativeImageSnapshotLaunch
{
    internal static bool ShouldEnable(ServiceHostOptions options, WrittenContainerManifest manifest,
        VolumeInfo volume, bool writeCapable) => options.EnableImageSnapshots && writeCapable &&
        options.NativeWriteRequireCanonicalCommit && options.WriteBackendMode.Equals("Native", StringComparison.OrdinalIgnoreCase) &&
        manifest.DeviceOffsetBytes == 0 && VolumeTopologyProfile.LocalPath(manifest.Device) &&
        !volume.IsEncrypted && volume.RegisteredImage is null && CatalogMountPolicy.AllowsOrdinaryMount(volume) &&
        !(volume.WriteUnsupportedFeatures ?? []).Contains("FusionBacked", StringComparer.OrdinalIgnoreCase) &&
        manifest.Volumes.Count > 0;
}
