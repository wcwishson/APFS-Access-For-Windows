using ApfsAccess.Core;

namespace ApfsAccess.Backend.Native;

internal static class NativePhysicalSnapshotInventoryLaunch
{
    internal static bool ShouldEnable(ServiceHostOptions options, WrittenContainerManifest manifest,
        VolumeInfo volume, bool writeCapable) => options.EnableRetainedPhysicalSnapshotInventory && writeCapable &&
        options.NativeWriteAllowRawPhysicalDevices && options.NativeWriteRequireCanonicalCommit &&
        options.WriteBackendMode.Equals("Native", StringComparison.OrdinalIgnoreCase) &&
        IsPhysicalPath(manifest.Device) &&
        !volume.IsEncrypted && volume.RegisteredImage is null && CatalogMountPolicy.AllowsOrdinaryMount(volume) &&
        !(volume.WriteUnsupportedFeatures ?? []).Contains("FusionBacked", StringComparer.OrdinalIgnoreCase) &&
        manifest.Volumes.Count > 0 && manifest.Volumes.All(v => v.RequestedWrite);

    internal static bool IsPhysicalPath(string path) =>
        path.StartsWith(@"\\.\PhysicalDrive", StringComparison.OrdinalIgnoreCase) ||
        path.StartsWith(@"\\?\PhysicalDrive", StringComparison.OrdinalIgnoreCase);
}
