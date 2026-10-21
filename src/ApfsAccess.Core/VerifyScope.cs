using System.Globalization;

namespace ApfsAccess.Core;

// Task 10 Step 5: exact offline-verify scope derived from the live
// inventory row plus its admitted topology — never from caller text.
// Every field the native verifier binds (image, container, volume,
// checkpoint, store window) comes from observed records; anything
// missing, multi-store, physical, Fusion-backed, or unobservable
// refuses with a typed code before any tool runs.
public sealed record VerifyScope(
    string ImagePath,
    string ContainerId,
    string VolumeUuid,
    string VolumeObjectId,
    string CheckpointXid,
    string StoreOffsetBytes,
    string StoreSizeBytes);

public sealed record VerifyScopeVerdict(bool Ok, VerifyScope? Scope, string Code, string? Detail);

public static class VerifyScopeDerivation
{
    public const string Derived = "Derived";
    public const string InvalidTarget = "InvalidTarget";
    public const string NoTopology = "NoTopology";
    public const string PhysicalTarget = "PhysicalTarget";
    public const string NonImageTarget = "NonImageTarget";
    public const string IdentityIncomplete = "IdentityIncomplete";
    public const string ContainerUnresolved = "ContainerUnresolved";
    public const string FusionContainer = "FusionContainer";
    public const string MultiStore = "MultiStore";
    public const string StoreUnresolved = "StoreUnresolved";
    public const string InvalidGeometry = "InvalidGeometry";
    public const string UnobservableCheckpoint = "UnobservableCheckpoint";
    public const string MembershipMismatch = "MembershipMismatch";

    public static VerifyScopeVerdict TryDerive(DeviceInventory? inventory, VolumeInfo? row)
        => Derive(inventory, row, false);

    internal static VerifyScopeVerdict TryDerivePhysicalManagement(DeviceInventory? inventory, VolumeInfo? row)
        => Derive(inventory, row, true);

    private static VerifyScopeVerdict Derive(DeviceInventory? inventory, VolumeInfo? row, bool physicalManagement)
    {
        ArgumentNullException.ThrowIfNull(inventory);
        ArgumentNullException.ThrowIfNull(row);
        if (!TopologyGraphIndex.Text(row.DeviceId))
            return Fail(InvalidTarget, "The volume device identity is missing or malformed.");
        if (IsPhysicalDevice(row.DeviceId) && !physicalManagement)
            return Fail(PhysicalTarget,
                "Offline verification needs a regular image file; raw physical devices need elevation and stay with the existing guidance.");
        if (physicalManagement ? !VolumePhysicalBinding.IsDevicePath(row.DeviceId) : !IsLocalImagePath(row.DeviceId))
            return Fail(NonImageTarget,
                "Offline verification needs the exact local image path; discovery rows without one cannot be scoped.");
        if (string.IsNullOrWhiteSpace(row.CatalogContainerUuid) ||
            string.IsNullOrWhiteSpace(row.CatalogVolumeUuid) ||
            row.CatalogVolumeObjectId is not { } oid || oid == 0)
            return Fail(IdentityIncomplete,
                "Offline verification needs live container, volume, and object identity; the selected row is not container-identified.");
        // The native verifier binds a lowercase hex32 nonzero volume UUID.
        // Normalize here (fail closed) so a D-format or upper-case row
        // value can never produce a scope the tool rejects downstream.
        if (!Guid.TryParse(row.CatalogVolumeUuid, out var volumeGuid) || volumeGuid == Guid.Empty)
            return Fail(IdentityIncomplete,
                "Offline verification needs a valid nonzero volume UUID; the selected row identity is malformed.");
        var volumeUuid = volumeGuid.ToString("N", CultureInfo.InvariantCulture);
        if (inventory.Topology is null)
            return Fail(NoTopology,
                "Offline verification needs an admitted discovery topology; re-observe and try again.");
        var containers = inventory.Topology.Snapshot.Containers
            .Where(c => c is not null && TopologyAdmission.SameUuid(c.Uuid, row.CatalogContainerUuid)).ToArray();
        if (containers.Length != 1)
            return Fail(ContainerUnresolved,
                "The selected volume needs exactly one observed container; re-observe and try again.");
        var container = containers[0];
        var volumes = inventory.Topology.Snapshot.Volumes.Where(v => v.Id == row.CatalogVolumeId).ToArray();
        if (!string.Equals(inventory.Device.DeviceId, row.DeviceId, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(inventory.Topology.DeviceId, row.DeviceId, StringComparison.OrdinalIgnoreCase) ||
            inventory.Volumes.Count(v => v.VolumeId == row.VolumeId && v.DeviceId == row.DeviceId &&
                TopologyAdmission.SameUuid(v.CatalogVolumeUuid, row.CatalogVolumeUuid) &&
                TopologyAdmission.SameUuid(v.CatalogContainerUuid, row.CatalogContainerUuid) && v.CatalogVolumeObjectId == oid) != 1 ||
            volumes.Length != 1 || volumes[0].ContainerId != container.Id ||
            !TopologyAdmission.SameUuid(volumes[0].Uuid, row.CatalogVolumeUuid) ||
            volumes[0].ObjectId != oid.ToString(CultureInfo.InvariantCulture) ||
            container.VolumeIds.Count(id => id == volumes[0].Id) != 1)
            return Fail(MembershipMismatch, "The selected row does not match the observed source and container membership.");
        if (container.Fusion)
            return Fail(FusionContainer,
                $"Container '{container.Id}' is Fusion-backed; single-store verification cannot cover two tiers.");
        if (container.StoreIds is not { Count: 1 })
            return Fail(MultiStore,
                $"Container '{container.Id}' does not name exactly one store; the verify window is ambiguous.");
        var store = inventory.Topology.Snapshot.Stores
            .Where(s => s is not null && string.Equals(s.Id, container.StoreIds[0], StringComparison.Ordinal) &&
                string.Equals(s.ContainerId, container.Id, StringComparison.Ordinal))
            .ToArray();
        if (store.Length != 1)
            return Fail(StoreUnresolved,
                $"Container '{container.Id}' has no unique store backing the verify window.");
        if (store[0].OffsetBytes < 0 || store[0].SizeBytes <= 0)
            return Fail(InvalidGeometry,
                $"Container '{container.Id}' store geometry is not a positive window.");
        var scopeBytes = (ulong)store[0].SizeBytes;
        if (physicalManagement)
        {
            // Physical inventory describes the GPT partition and the APFS prefix separately.
            if (container.BlockSizeBytes != 4096 || store[0].BlockSizeBytes != container.BlockSizeBytes ||
                store[0].TotalBlocks is not { } blocks || blocks < 1048576 / 4096 ||
                blocks > VolumeTopologyProfile.MaximumStreamedImageBytes / 4096 ||
                blocks > scopeBytes / 4096)
                return Fail(InvalidGeometry, "Physical management needs exact APFS block geometry within the observed partition.");
            scopeBytes = blocks * 4096;
            if ((ulong)store[0].OffsetBytes > (ulong)long.MaxValue - scopeBytes)
                return Fail(InvalidGeometry, "Physical APFS geometry exceeds the supported source window.");
        }
        if (!ulong.TryParse(container.CheckpointXid, NumberStyles.None, CultureInfo.InvariantCulture, out var xid) ||
            xid == 0 || xid.ToString(CultureInfo.InvariantCulture) != container.CheckpointXid)
            return Fail(UnobservableCheckpoint,
                "Offline verification needs a canonical nonzero container checkpoint generation.");
        // Admitted topologies validate the container UUID, but this
        // derivation must not throw on a malformed record: fail closed.
        if (!Guid.TryParse(container.Uuid, out var containerGuid) || containerGuid == Guid.Empty)
            return Fail(ContainerUnresolved,
                "The selected volume's container identity is malformed; re-observe and try again.");
        return new VerifyScopeVerdict(true, new VerifyScope(
            row.DeviceId,
            ApfsTopology.BuildContainerId(containerGuid.ToString("N", CultureInfo.InvariantCulture)),
            volumeUuid,
            oid.ToString(CultureInfo.InvariantCulture),
            xid.ToString(CultureInfo.InvariantCulture),
            ((ulong)store[0].OffsetBytes).ToString(CultureInfo.InvariantCulture),
            scopeBytes.ToString(CultureInfo.InvariantCulture)),
            Derived, null);
    }

    internal static bool IsPhysicalDevice(string deviceId)
        => deviceId.StartsWith(@"\\.\", StringComparison.OrdinalIgnoreCase) ||
            deviceId.StartsWith(@"\\?\", StringComparison.OrdinalIgnoreCase) ||
            deviceId.StartsWith(@"\\?\GLOBALROOT", StringComparison.OrdinalIgnoreCase);

    internal static bool IsLocalImagePath(string deviceId)
    {
        if (deviceId.Length < 4 || !char.IsAsciiLetter(deviceId[0]) || deviceId[1] != ':' ||
            deviceId[2] is not ('\\' or '/') || deviceId.Contains('\0') || deviceId.IndexOf(':', 2) >= 0 ||
            deviceId[3..].Split(['\\', '/']).Any(p => p.Length == 0 || p is "." or ".." || p.EndsWith(' ') || p.EndsWith('.')))
            return false;
        return true;
    }

    private static VerifyScopeVerdict Fail(string code, string detail)
        => new(false, null, code, detail);
}
