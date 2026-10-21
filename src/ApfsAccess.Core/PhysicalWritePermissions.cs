using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;

namespace ApfsAccess.Core;

/// <summary>Exact physical-volume consent, separate from configured write policy.</summary>
public sealed class PhysicalWritePermissions
{
    private readonly PhysicalWritePermissionStore _store;
    private readonly object _sync = new();
    private readonly Dictionary<string, Observation> _observations = new(StringComparer.Ordinal);
    private readonly Dictionary<OwnerIdentity, RequestPermission> _pendingOwners = new();
    private readonly AsyncLocal<RequestPermission?> _request = new();

    public PhysicalWritePermissions(string path) => _store = new(path);

    public static string? NormalizeDevice(string? value)
    {
        if (value is null) return null;
        if (value.StartsWith(@"\\?\", StringComparison.Ordinal)) value = @"\\.\" + value[4..];
        const string prefix = @"\\.\PhysicalDrive";
        if (!value.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) ||
            !uint.TryParse(value.AsSpan(prefix.Length), NumberStyles.None, CultureInfo.InvariantCulture, out var index)) return null;
        return prefix + index.ToString(CultureInfo.InvariantCulture);
    }

    public static bool HasConfiguredRawPermission(ServiceHostOptions options, string device)
        => NormalizeDevice(device) is { } normalized && options.NativeWriteAllowRawPhysicalDevices &&
            options.NativeWriteHardwarePilotDeviceAllowList.Any(x => NormalizeDevice(x?.Trim()) == normalized);

    public void ForgetDevice(string device)
        => RetainDiscovery(device, new HashSet<string>(StringComparer.Ordinal));

    public void RetainDiscovery(string device, IReadOnlySet<string> currentVolumeIds)
    {
        if (NormalizeDevice(device) is not { } normalized) return;
        lock (_sync)
            foreach (var key in _observations.Where(p => p.Value.Identity.Device == normalized &&
                         !currentVolumeIds.Contains(p.Value.Volume.VolumeId)).Select(p => p.Key).ToArray())
                _observations.Remove(key);
    }

    // Called only with the backend's catalog-derived row, before source-policy masking.
    public void Observe(VolumeInfo unmasked, ApfsDiscoveryTopology? topology)
    {
        if (NormalizeDevice(unmasked.DeviceId) is not { } device) return;
        var key = device + "|" + unmasked.VolumeId;
        var identity = Identity(unmasked, topology);
        lock (_sync)
        {
            _observations.Remove(key);
            if (identity is not null) _observations.Add(key, new(identity, unmasked));
        }
    }

    public (ServiceHostOptions Options, VolumeInfo Volume) Resolve(ServiceHostOptions options, VolumeInfo volume)
        => Resolve(options, volume, includeRequest: true);

    public (ServiceHostOptions Options, VolumeInfo Volume) ResolveForDiscovery(ServiceHostOptions options, VolumeInfo volume)
        => Resolve(options, volume, includeRequest: false);

    private (ServiceHostOptions Options, VolumeInfo Volume) Resolve(ServiceHostOptions options, VolumeInfo volume, bool includeRequest)
    {
        var observation = Find(volume);
        if (observation is null || !PolicyAllows(options, observation, out var overlay)) return (options, volume);
        var request = includeRequest ? _request.Value : null;
        if (!_store.Contains(observation.Identity, request is { Active: true } && request.Identity == observation.Identity
                ? request.PendingId : null)) return (options, volume);
        return (overlay, Restore(volume, observation.Volume));
    }

    public void RetainOwner(VolumeInfo volume, int pid, long birth, string mountPoint)
    {
        var request = _request.Value;
        var observation = Find(volume);
        if (pid <= 0 || birth <= 0 || string.IsNullOrEmpty(mountPoint) || request is not { Active: true } ||
            observation?.Identity != request.Identity) return;
        lock (_sync) _pendingOwners[new(observation.Identity, pid, birth, mountPoint)] = request;
    }

    public (ServiceHostOptions Options, VolumeInfo Volume) ResolveForOwner(ServiceHostOptions options, VolumeInfo volume,
        int pid, long birth, string mountPoint)
    {
        var admitted = Resolve(options, volume);
        if (!ReferenceEquals(admitted.Options, options)) return admitted;
        var observation = Find(volume);
        if (observation is null || !PolicyAllows(options, observation, out var overlay)) return admitted;
        RequestPermission? request;
        lock (_sync) _pendingOwners.TryGetValue(new(observation.Identity, pid, birth, mountPoint), out request);
        if (request is not { Active: true } || !_store.Contains(observation.Identity, request.PendingId)) return admitted;
        return (overlay, Restore(volume, observation.Volume));
    }

    // A dormant context participates in the all-volume checkpoint census, never namespace activation.
    public (ServiceHostOptions Options, VolumeInfo Volume) ResolveCensus(
        ServiceHostOptions options, VolumeInfo selected, VolumeInfo peer)
    {
        var admitted = Resolve(options, selected);
        var a = Find(selected);
        var b = Find(peer);
        if (ReferenceEquals(admitted.Options, options) || a is null || b is null ||
            a.Identity.Source != b.Identity.Source || a.Identity.Container != b.Identity.Container ||
            !PolicyAllows(options, b, out _)) return Resolve(options, peer);
        return (admitted.Options, Restore(peer, b.Volume));
    }

    public RequestPermission Begin(ServiceHostOptions options, VolumeInfo volume, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        var observation = Find(volume);
        if (observation is null || !PolicyAllows(options, observation, out _))
            throw new IOException("PhysicalWritePermissionRefused: A unique supported current physical catalog identity and configured write policy are required.");
        var pending = _store.Begin(observation.Identity, token);
        var permission = new RequestPermission(this, observation.Identity, pending, _request.Value);
        _request.Value = permission;
        return permission;
    }

    private Observation? Find(VolumeInfo volume)
    {
        if (NormalizeDevice(volume.DeviceId) is not { } device) return null;
        lock (_sync)
        {
            if (!_observations.TryGetValue(device + "|" + volume.VolumeId, out var row)) return null;
            return SameVolume(row.Volume, volume) ? row : null;
        }
    }

    private static bool SameVolume(VolumeInfo a, VolumeInfo b)
        => a.VolumeId == b.VolumeId && a.CatalogVolumeId == b.CatalogVolumeId &&
            Uuid(a.CatalogContainerUuid) == Uuid(b.CatalogContainerUuid) &&
            Uuid(a.CatalogVolumeUuid) == Uuid(b.CatalogVolumeUuid) && a.CatalogVolumeObjectId == b.CatalogVolumeObjectId &&
            a.RecoveryIdentity == b.RecoveryIdentity && a.CatalogDecision == b.CatalogDecision &&
            a.IsEncrypted == b.IsEncrypted && a.CatalogAutoMountAllowed == b.CatalogAutoMountAllowed &&
            (a.CatalogReasons ?? []).SequenceEqual(b.CatalogReasons ?? []);

    private static VolumeInfo Restore(VolumeInfo current, VolumeInfo original) => current with
    {
        SupportsReadWrite = original.SupportsReadWrite,
        SupportsNativeWrite = original.SupportsNativeWrite,
        NativeWriteReadiness = original.NativeWriteReadiness,
        NativeWriteAdmissionBlockReason = original.NativeWriteAdmissionBlockReason,
        WriteBlockReason = original.WriteBlockReason,
        WriteIncompatibilities = original.WriteIncompatibilities,
        WriteUnsupportedFeatures = original.WriteUnsupportedFeatures,
    };

    private static bool PolicyAllows(ServiceHostOptions options, Observation observation, out ServiceHostOptions overlay)
    {
        overlay = options.WithPhysicalWritePermission(observation.Identity.Device);
        if (!string.Equals(options.BackendMode, "Native", StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(options.WriteBackendMode, "Native", StringComparison.OrdinalIgnoreCase) ||
            options.NativeWriteHardwarePilotDeviceAllowList.Length > 0 &&
            !options.NativeWriteHardwarePilotDeviceAllowList.Any(x => NormalizeDevice(x?.Trim()) == observation.Identity.Device)) return false;
        return WriteGatePolicy.EvaluateForVolume(overlay, observation.Volume).AllowWrite;
    }

    private static string? Uuid(string? value)
        => Guid.TryParse(value, out var id) && id != Guid.Empty ? id.ToString("N") : null;

    private static PermissionIdentity? Identity(VolumeInfo v, ApfsDiscoveryTopology? topology)
    {
        if (topology is null || NormalizeDevice(v.DeviceId) is not { } device || NormalizeDevice(topology.DeviceId) != device ||
            v.RegisteredImage is not null || v.RegisteredFusion is not null || v.BackupImageWrite is not null || v.EncryptionState is not null ||
            v.IsEncrypted || !v.SupportsExplorerMount || !v.SupportsNativeWrite || !v.SupportsReadWrite ||
            v.NativeWriteReadiness is not (NativeWriteReadiness.BootstrapReady or NativeWriteReadiness.MutationReady) ||
            v.CatalogDecision != ApfsCapabilityDecision.Writable || v.CatalogAutoMountAllowed != true ||
            v.CatalogReasons is not { Count: 0 } || !string.IsNullOrEmpty(v.NativeWriteAdmissionBlockReason) ||
            v.WriteIncompatibilities is { Count: > 0 } || v.WriteUnsupportedFeatures is { Count: > 0 } ||
            v.CatalogVolumeObjectId is null or 0 || v.CatalogVolumeId != v.VolumeId ||
            Uuid(v.CatalogContainerUuid) is not { } containerUuid || Uuid(v.CatalogVolumeUuid) is not { } volumeUuid ||
            string.IsNullOrWhiteSpace(v.RecoveryIdentity) || v.RecoveryIdentity.Length > 1024 ||
            !ApfsTopology.TryParseVolumeId(v.VolumeId, out var parsedUuid, out var oid) ||
            parsedUuid != containerUuid || oid != v.CatalogVolumeObjectId) return null;
        if (!TopologyAdmission.Validate(new(new(v.DeviceId, "physical permission observation", true), [v], topology))) return null;
        var s = topology.Snapshot;
        var disks = s.Disks.Where(d => NormalizeDevice(d.DeviceIdentifier) == device).ToArray();
        var volumes = s.Volumes.Where(x => x.Id == v.CatalogVolumeId).ToArray();
        if (s.Disks.Count != 1 || disks.Length != 1 || volumes.Length != 1 ||
            s.Volumes.Count(x => Uuid(x.Uuid) == volumeUuid) != 1) return null;
        var disk = disks[0];
        var volume = volumes[0];
        var containers = s.Containers.Where(x => x.Id == volume.ContainerId).ToArray();
        if (containers.Length != 1 || Uuid(volume.Uuid) != volumeUuid || volume.ObjectId != oid.ToString(CultureInfo.InvariantCulture) ||
            volume.Locked || volume.EncryptionMode != "none" || volume.RoleRaw is not (0 or 64) ||
            volume.GroupId is not null || volume.GroupUuid is not null) return null;
        var container = containers[0];
        if (container.Fusion || Uuid(container.Uuid) != containerUuid || container.StoreIds.Count != 1 ||
            container.VolumeIds.Count(x => x == volume.Id) != 1 ||
            ApfsVolumeCapabilities.Evaluate(volume, container) is not { Decision: ApfsCapabilityDecision.Writable, AutoMountAllowed: true }) return null;
        var stores = s.Stores.Where(x => x.Id == container.StoreIds[0] && x.ContainerId == container.Id).ToArray();
        if (stores.Length != 1) return null;
        var store = stores[0];
        var partitions = s.Partitions.Where(x => x.Id == store.PartitionId && x.DiskId == disk.Id).ToArray();
        if (partitions.Length != 1 || Uuid(disk.Uuid) is not { } diskUuid || Uuid(store.Uuid) is not { } storeUuid ||
            disk.SizeBytes <= 0 || store.SizeBytes <= 0 || store.OffsetBytes < 0 || store.BlockSizeBytes is null or <= 0 ||
            store.TotalBlocks is null or 0 || topology.DiskIds.Count != 1 || topology.DiskIds[0] != disk.Id) return null;
        var partition = partitions[0];
        if (Uuid(partition.Uuid) is not { } partitionUuid || partition.StartByte < 0 || partition.SizeBytes <= 0 ||
            Uuid(partition.TypeGuid) != "7c3457ef000011aaaa1100306543ecac" ||
            partition.StartByte > disk.SizeBytes || partition.SizeBytes > disk.SizeBytes - partition.StartByte ||
            store.OffsetBytes < partition.StartByte || store.OffsetBytes - partition.StartByte > partition.SizeBytes ||
            store.SizeBytes > partition.SizeBytes - (store.OffsetBytes - partition.StartByte)) return null;
        var source = Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(new
        {
            device, diskUuid, disk.SizeBytes, partitionUuid, partition.StartByte, PartitionSize = partition.SizeBytes,
            storeUuid, store.OffsetBytes, StoreSize = store.SizeBytes, store.BlockSizeBytes, store.TotalBlocks, containerUuid,
        })));
        return new(device, containerUuid, volumeUuid, oid, v.VolumeId, v.RecoveryIdentity, source);
    }

    private sealed record Observation(PermissionIdentity Identity, VolumeInfo Volume);
    private sealed record OwnerIdentity(PermissionIdentity Identity, int Pid, long Birth, string MountPoint);

    public sealed class RequestPermission : IDisposable
    {
        private readonly PhysicalWritePermissions _owner;
        private readonly RequestPermission? _parent;
        internal PermissionIdentity Identity { get; }
        internal Guid? PendingId { get; }
        private volatile bool _active = true;
        internal bool Active => _active;
        public bool IsNew => PendingId is not null;

        public bool RetainsOwner(int pid, long birth, string mountPoint)
        {
            lock (_owner._sync)
                return Active && _owner._pendingOwners.TryGetValue(new(Identity, pid, birth, mountPoint), out var request) &&
                    ReferenceEquals(request, this);
        }

        internal RequestPermission(PhysicalWritePermissions owner, PermissionIdentity identity, Guid? pendingId, RequestPermission? parent)
            => (_owner, Identity, PendingId, _parent) = (owner, identity, pendingId, parent);

        public void Confirm(ServiceHostOptions options, VolumeInfo current, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            var observation = _owner.Find(current);
            if (!Active || observation?.Identity != Identity || !PolicyAllows(options, observation, out _))
                throw new IOException("PhysicalWritePermissionIdentityChanged");
            _owner._store.Confirm(Identity, PendingId, token);
        }

        public void Dispose()
        {
            _active = false;
            lock (_owner._sync)
                foreach (var key in _owner._pendingOwners.Where(p => ReferenceEquals(p.Value, this)).Select(p => p.Key).ToArray())
                    _owner._pendingOwners.Remove(key);
            if (ReferenceEquals(_owner._request.Value, this)) _owner._request.Value = _parent;
            // A failed pending record is inert, including after restart. Never rewrite
            // history or hide a durable-store failure during request unwinding.
        }
    }
}

internal sealed record PermissionIdentity(string Device, string Container, string Volume, ulong Oid,
    string VolumeId, string Recovery, string Source)
{
    internal bool IsValid => PhysicalWritePermissions.NormalizeDevice(Device) == Device && Oid > 0 &&
        Guid.TryParseExact(Container, "N", out var container) && container != Guid.Empty &&
        Guid.TryParseExact(Volume, "N", out var volume) && volume != Guid.Empty &&
        ApfsTopology.TryParseVolumeId(VolumeId, out var parsed, out var oid) && parsed == Container && oid == Oid &&
        !string.IsNullOrWhiteSpace(Recovery) && Recovery.Length <= 1024 && Source is { Length: 64 } && Source.All(Uri.IsHexDigit);
}
