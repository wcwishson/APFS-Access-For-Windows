using System.Buffers.Binary;
using System.ComponentModel;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using ApfsAccess.Core;
using Microsoft.Win32.SafeHandles;

namespace ApfsAccess.Backend.Native;

internal static class NativeRecoveryStorage
{
    internal sealed record NamespaceIdentity(Guid PartitionGuid, string ContainerUuid, ulong Oid);

    internal static byte[]? BuildNamespaceMaterial(Guid? partition, string? container, ulong? oid, bool allowPartitionless)
    {
        var physical = partition.HasValue && partition.Value != Guid.Empty;
        if ((!physical && !allowPartitionless) || container is not { Length: 32 } ||
            !container.All(char.IsAsciiHexDigit) || container.All(c => c == '0') || oid is null or 0) return null;
        var bytes = new byte[42];
        bytes[0] = physical ? (byte)1 : (byte)0;
        if (physical) partition!.Value.TryWriteBytes(bytes.AsSpan(1, 16));
        Convert.FromHexString(container).CopyTo(bytes.AsSpan(17, 16));
        bytes[33] = 1;
        BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(34), oid.Value);
        return bytes;
    }

    internal static string NamespaceRecoveryIdentity(ReadOnlySpan<byte> material)
    {
        _ = DecodeNamespace(material);
        return "apfs-recovery-v1-" + Convert.ToBase64String(SHA256.HashData(material)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    private static NamespaceIdentity DecodeNamespace(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length != 42 || bytes[0] > 1 || bytes[33] != 1)
            throw new IOException("VolumeManagementNamespaceWitnessInvalid");
        var partition = new Guid(bytes.Slice(1, 16));
        var container = Convert.ToHexStringLower(bytes.Slice(17, 16));
        var oid = BinaryPrimitives.ReadUInt64LittleEndian(bytes[34..]);
        if ((bytes[0] == 0) != (partition == Guid.Empty) || container.All(c => c == '0') || oid == 0)
            throw new IOException("VolumeManagementNamespaceWitnessInvalid");
        return new(partition, container, oid);
    }

    internal static string NamespaceWitnessPath(string root, string recoveryIdentity)
    {
        _ = BuildRecoveryStorageKey(recoveryIdentity);
        return Path.Combine(root, "spool-namespace-" + recoveryIdentity[17..] + ".vks1");
    }

    internal static byte[] BuildVerifiedNamespaceMaterial(string? partitionId, string? container, ulong? oid,
        string? recoveryIdentity, bool allowPartitionless)
    {
        Guid? partition = null;
        if (!string.IsNullOrEmpty(partitionId))
        {
            if (!ApfsTopology.TryParsePartitionId(partitionId, out var parsed) || parsed == Guid.Empty)
                throw new IOException("VolumeManagementNamespacePartitionUnproved");
            partition = parsed;
        }
        var bytes = BuildNamespaceMaterial(partition, container, oid, allowPartitionless)
            ?? throw new IOException("VolumeManagementNamespaceMaterialUnproved");
        if (NamespaceRecoveryIdentity(bytes) != recoveryIdentity)
            throw new IOException("VolumeManagementNamespaceRecoveryIdentityMismatch");
        return bytes;
    }

    internal static void EnsureNamespaceWitness(string root, string? partitionId, string? container, ulong? oid,
        string? recoveryIdentity, bool allowPartitionless)
    {
        var bytes = BuildVerifiedNamespaceMaterial(partitionId, container, oid, recoveryIdentity, allowPartitionless);
        NativeApfsVolumeManagement.ValidateStoreRoot(root);
        using var directory = OpenNamespaceDirectory(root, true);
        var path = NamespaceWitnessPath(root, recoveryIdentity);
        // A torn/conflicting final is evidence. Only an absent final permits publication.
        if (!Path.Exists(path))
        {
            var temporary = path + ".tmp-" + Guid.NewGuid().ToString("N");
            using (var output = new FileStream(temporary, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None, 4096, FileOptions.WriteThrough))
            {
                output.Write(bytes); output.Flush(true);
                _ = NativeApfsVolumeManagement.SourceIdentity(output.SafeFileHandle, temporary, "0", false);
                output.Position = 0;
                var readback = new byte[42]; output.ReadExactly(readback);
                if (output.Length != 42 || !readback.AsSpan().SequenceEqual(bytes))
                    throw new IOException("VolumeManagementNamespaceWitnessWriteFailed");
            }
            if (!MoveFileEx(@"\\?\" + Path.GetFullPath(temporary), @"\\?\" + Path.GetFullPath(path), 8))
            {
                var error = Marshal.GetLastWin32Error();
                if (error is not (80 or 183)) throw new Win32Exception(error);
                // Preserve the temporary if another publisher won; it grants no authority.
            }
        }
        if (!FlushFileBuffers(directory)) throw new Win32Exception(Marshal.GetLastWin32Error(), "VolumeManagementNamespaceDirectoryFlushFailed");
        using var fence = new MarkerFence();
        var (_, persisted) = ReadNamespaceWitness(root, recoveryIdentity, fence);
        if (!persisted.AsSpan().SequenceEqual(bytes)) throw new IOException("VolumeManagementNamespaceWitnessConflict");
    }

    private static SafeFileHandle OpenNamespaceDirectory(string root, bool write)
    {
        NativeApfsVolumeManagement.ValidateStoreRoot(root);
        var handle = CreateFile(@"\\?\" + Path.GetFullPath(root), write ? 0x40000080u : 0x80u, 3, IntPtr.Zero, 3,
            0x02200000, IntPtr.Zero);
        try
        {
            if (handle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
            NativeApfsSnapshotReader.ValidateIdentity(handle, root);
            if (!GetFileInformationByHandle(handle, out var info) ||
                (info.Attributes & (uint)(FileAttributes.Directory | FileAttributes.ReparsePoint | FileAttributes.Device)) != (uint)FileAttributes.Directory)
                throw new IOException("VolumeManagementNamespaceDirectoryInvalid");
            return handle;
        }
        catch { handle.Dispose(); throw; }
    }

    private static (NamespaceIdentity Identity, byte[] Bytes) ReadNamespaceWitness(string root, string identity, MarkerFence fence)
    {
        var path = NamespaceWitnessPath(root, identity);
        try { NativeApfsSnapshotReader.ValidateLocalFile(path); }
        catch (ArgumentException error) { throw new IOException("VolumeManagementNamespaceWitnessUnavailable", error); }
        var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        fence.Files.Add(file);
        if (file.Length != 42) throw new IOException("VolumeManagementNamespaceWitnessInvalid");
        _ = NativeApfsVolumeManagement.SourceIdentity(file.SafeFileHandle, path, "0", false);
        var bytes = new byte[42]; file.ReadExactly(bytes);
        var decoded = DecodeNamespace(bytes);
        if (NamespaceRecoveryIdentity(bytes) != identity) throw new IOException("VolumeManagementNamespaceWitnessHashMismatch");
        return (decoded, bytes);
    }

    internal static bool IsForeignNamespace(NamespaceIdentity candidate, IReadOnlyList<NamespaceIdentity> known)
        => known.Count != 0 && (known.All(k => k.ContainerUuid != candidate.ContainerUuid) ||
            candidate.PartitionGuid != Guid.Empty && known.All(k => k.PartitionGuid != Guid.Empty && k.PartitionGuid != candidate.PartitionGuid));

    internal static void EnsureCurrentNamespaceWitnesses(VerifyScope scope, DeviceInventory inventory, string journalRoot)
    {
        if (!TopologyAdmission.Validate(inventory) || !string.Equals(inventory.Device.DeviceId, scope.ImagePath, StringComparison.OrdinalIgnoreCase))
            throw new IOException("VolumeManagementInventoryBindingInvalid");
        NativeApfsSnapshotReader.ValidateLocalFile(scope.ImagePath);
        var rows = inventory.Volumes.Where(v => TopologyAdmission.SameUuid(v.CatalogContainerUuid, scope.ContainerId[15..])).ToArray();
        if (rows.Length is < 1 or > 100) throw new IOException("VolumeManagementCompleteNativeCensusRequired");
        // Validate every member before publishing any namespace fact.
        var materials = rows.Select(row =>
        {
            var derived = VerifyScopeDerivation.TryDerive(inventory, row).Scope;
            if (derived is null || derived.CheckpointXid != scope.CheckpointXid || derived.StoreOffsetBytes != scope.StoreOffsetBytes ||
                derived.StoreSizeBytes != scope.StoreSizeBytes) throw new IOException("VolumeManagementSiblingScopeChanged");
            var container = inventory.Topology!.Snapshot.Containers.Single(c => c.Id == scope.ContainerId);
            var store = inventory.Topology.Snapshot.Stores.Single(s => s.Id == container.StoreIds[0]);
            var partition = string.IsNullOrEmpty(store.PartitionId) ? (Guid?)null :
                ApfsTopology.TryParsePartitionId(store.PartitionId, out var parsed) && parsed != Guid.Empty ? parsed :
                throw new IOException("VolumeManagementNamespacePartitionUnproved");
            var bytes = BuildNamespaceMaterial(partition, row.CatalogContainerUuid, row.CatalogVolumeObjectId, scope.StoreOffsetBytes == "0")
                ?? throw new IOException("VolumeManagementNamespaceMaterialUnproved");
            if (NamespaceRecoveryIdentity(bytes) != row.RecoveryIdentity) throw new IOException("VolumeManagementNamespaceRecoveryIdentityMismatch");
            return (Row: row, Partition: store.PartitionId);
        }).ToArray();
        foreach (var item in materials)
            EnsureNamespaceWitness(journalRoot, item.Partition, item.Row.CatalogContainerUuid, item.Row.CatalogVolumeObjectId,
                item.Row.RecoveryIdentity, scope.StoreOffsetBytes == "0");
    }

    // FsHost BuildRecoveryStorageKey / BuildPayloadSpoolSessionRoot use the
    // exact identity already passed in the production manifest, without hashing again.
    internal static string BuildRecoveryStorageKey(string identity)
    {
        const string prefix = "apfs-recovery-v1-";
        if (!identity.StartsWith(prefix, StringComparison.Ordinal) || identity.Length != 60 ||
            identity[17..].Any(c => !char.IsAsciiLetterOrDigit(c) && c is not ('-' or '_')) ||
            !"AEIMQUYcgkosw048".Contains(identity[^1]))
            throw new InvalidDataException("VolumeManagementCanonicalRecoveryIdentityRequired");
        return "apfs_recovery_v1_" + identity[17..];
    }
    internal static string CanonicalWal(string spool, string identity) => Path.Combine(spool, BuildRecoveryStorageKey(identity), "write-ahead.wal");
    internal static string CanonicalNativeMarker(string recovery, string identity) => Path.Combine(recovery, BuildRecoveryStorageKey(identity) + "_Native.state");

    internal static IReadOnlyList<VolumeTopologyWal> BindCensus(VerifyScope scope, DeviceInventory inventory,
        IReadOnlyList<(string Uuid, string Oid)> nativeVolumes, string spoolRoot, string recoveryRoot, string? journalRoot = null,
        Func<IReadOnlyList<HistoryMember>>? observeHistory = null)
    {
        NativeApfsVolumeManagement.ValidateStoreRoot(spoolRoot);
        NativeApfsVolumeManagement.ValidateStoreRoot(recoveryRoot);
        if (!TopologyAdmission.Validate(inventory) || !string.Equals(inventory.Device.DeviceId, scope.ImagePath, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("VolumeManagementInventoryBindingInvalid");
        var rows = inventory.Volumes.Where(v => TopologyAdmission.SameUuid(v.CatalogContainerUuid, scope.ContainerId[15..])).ToArray();
        if (nativeVolumes.Count is < 1 or > 100 || rows.Length != nativeVolumes.Count ||
            nativeVolumes.Select(v => v.Oid).Distinct().Count() != nativeVolumes.Count ||
            nativeVolumes.Select(v => v.Uuid).Distinct().Count() != nativeVolumes.Count)
            throw new InvalidDataException("VolumeManagementCompleteNativeCensusRequired");
        var census = nativeVolumes.Select(v =>
        {
            var matches = rows.Where(r => r.CatalogVolumeObjectId?.ToString(System.Globalization.CultureInfo.InvariantCulture) == v.Oid &&
                TopologyAdmission.SameUuid(r.CatalogVolumeUuid, v.Uuid)).ToArray();
            if (matches.Length != 1 || matches[0].RecoveryIdentity is null)
                throw new InvalidDataException("VolumeManagementSiblingIdentityChanged");
            var derived = VerifyScopeDerivation.TryDerive(inventory, matches[0]).Scope;
            if (derived is null || derived.CheckpointXid != scope.CheckpointXid || derived.StoreOffsetBytes != scope.StoreOffsetBytes ||
                derived.StoreSizeBytes != scope.StoreSizeBytes)
                throw new InvalidDataException("VolumeManagementSiblingScopeChanged");
            return new VolumeTopologyWal(v.Oid, v.Uuid, CanonicalWal(spoolRoot, matches[0].RecoveryIdentity!));
        }).ToArray();
        if (census.Select(w => w.Path).Distinct(StringComparer.OrdinalIgnoreCase).Count() != census.Length)
            throw new InvalidDataException("VolumeManagementSiblingStorageAlias");
        var markers = journalRoot is null || !Directory.EnumerateFileSystemEntries(recoveryRoot).Any() ? null : OriginalMarkers(journalRoot, scope.ImagePath, scope.StoreOffsetBytes,
            spoolRoot, recoveryRoot, scope.ContainerId[15..], census, scope.CheckpointXid);
        var namespaces = journalRoot is null ? null : OriginalNamespaces(journalRoot, scope.ImagePath, scope.StoreOffsetBytes,
            spoolRoot, recoveryRoot, scope.ContainerId[15..], census);
        try { using var disposition = AcquireDisposition(spoolRoot, recoveryRoot, census, null, markers, namespaces); }
        catch (IOException error) when (observeHistory is not null && journalRoot is not null &&
            (error.Message.StartsWith("VolumeManagementHistoricalOrSpoolDebtUnproved", StringComparison.Ordinal) ||
             error.Message.StartsWith("VolumeManagementRecoveryMarkerDispositionUnproved", StringComparison.Ordinal)))
        {
            var history = observeHistory();
            var ownership = NativeOrdinaryImageOwnership.Read(journalRoot, scope.ImagePath, scope.StoreOffsetBytes);
            ValidateHistoryOwnership(ownership, spoolRoot, recoveryRoot, history);
            if (census.Any(w => history.Count(h => h.ContainerUuid == scope.ContainerId[15..] && h.Wal == w && h.CheckpointXid == scope.CheckpointXid) != 1))
                throw new IOException("VolumeManagementCurrentHistoryCensusMismatch");
            var bounds = history.ToDictionary(h => CanonicalNativeMarker(recoveryRoot,
                NativeApfsBackend.BuildRecoveryIdentityFromComponents(null, h.ContainerUuid, ulong.Parse(h.Wal.Oid, CultureInfo.InvariantCulture), true)!),
                h => (ulong?)ulong.Parse(h.CheckpointXid, CultureInfo.InvariantCulture), StringComparer.OrdinalIgnoreCase);
            using var disposition = AcquireDisposition(spoolRoot, recoveryRoot, history.Select(h => h.Wal).ToArray(), null, new(bounds), namespaces);
        }
        return census;
    }

    internal sealed record HistoryMember(string ContainerUuid, VolumeTopologyWal Wal, string CheckpointXid);

    private static void ValidateHistoryOwnership(NativeOrdinaryImageOwnership.Record ownership, string spool, string recovery,
        IReadOnlyList<HistoryMember> history)
    {
        if (!ownership.FreshCopy || !string.Equals(ownership.SpoolRoot, spool, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(ownership.RecoveryRoot, recovery, StringComparison.OrdinalIgnoreCase) || history.Count is < 1 or > 100 ||
            history.Select(h => (h.ContainerUuid, h.Wal.Oid)).Distinct().Count() != history.Count ||
            history.Select(h => h.Wal.Path).Distinct(StringComparer.OrdinalIgnoreCase).Count() != history.Count)
            throw new IOException("VolumeManagementHistoryOwnershipUnproved");
        foreach (var h in history)
        {
            var bindings = ownership.LaunchBindings.Where(b => b.ContainerUuid == h.ContainerUuid && b.VolumeUuid == h.Wal.VolumeUuid &&
                b.Oid == h.Wal.Oid && string.Equals(b.Wal, h.Wal.Path, StringComparison.OrdinalIgnoreCase)).ToArray();
            var identity = NativeApfsBackend.BuildRecoveryIdentityFromComponents(null, h.ContainerUuid, ulong.Parse(h.Wal.Oid, CultureInfo.InvariantCulture), true);
            if (bindings.Length != 1 || bindings[0].RecoveryIdentity != identity ||
                !string.Equals(CanonicalWal(spool, identity!), h.Wal.Path, StringComparison.OrdinalIgnoreCase))
                throw new IOException("VolumeManagementHistoricalLaunchBindingUnproved");
        }
    }

    // This is only a managed path/marker preflight. The invocation always passes
    // both history roots to the new keeper, which proves file IDs, retirement,
    // current/preimage checkpoint bounds and complete clean WALs while held,
    // Explicit Cancel and prepared/cancelled recovery retain a separate native
    // marker fence before their early returns. That fence grants no publication
    // authority and leaves sibling WAL debt untouched. Detached observation
    // never authorizes checkpoint bounds.
    internal static IDisposable AcquireForNativeKeeper(VolumeTopologyRequest original, string recoveryRoot, string journalRoot)
    {
        if (original.PhysicalBindingHex is not null || original.Operation is not ("create" or "delete" or "grow" or "shrink" or "format" or "erase"))
            throw new IOException("VolumeManagementHeldNativeKeeperRequired");
        if (!string.Equals(original.JournalRoot, journalRoot, StringComparison.OrdinalIgnoreCase))
            throw new IOException("VolumeManagementStableRootMismatch");
        var ownership = NativeOrdinaryImageOwnership.Read(journalRoot, original.Image, original.OffsetBytes);
        var history = ownership.LaunchBindings.Select(b => new HistoryMember(b.ContainerUuid, new(b.Oid, b.VolumeUuid, b.Wal), original.PreXid)).ToArray();
        ValidateHistoryOwnership(ownership, original.SpoolRoot, recoveryRoot, history);
        var bounds = ownership.LaunchBindings.ToDictionary(b => CanonicalNativeMarker(recoveryRoot, b.RecoveryIdentity),
            _ => (ulong?)null, StringComparer.OrdinalIgnoreCase);
        var destination = original.Operation is "format" or "erase" ? original.ImageOptions?.NewVolumeWal : null;
        if (destination is not null)
        {
            NativeApfsVolumeImageManagement.ValidateRequest(original);
            var id = NativeApfsBackend.BuildRecoveryIdentityFromComponents(null, original.ImageOptions!.NewContainerUuid!, 1024, true)!;
            bounds.TryAdd(CanonicalNativeMarker(recoveryRoot, id), null);
        }
        var namespaces = OriginalNamespaces(journalRoot, original.Image, original.OffsetBytes, original.SpoolRoot, recoveryRoot,
            original.ContainerUuid, original.SiblingWals);
        if (destination is not null) namespaces = namespaces.WithDestination(original.ImageOptions!.NewContainerUuid!, destination);
        // Its sole production caller holds this fence across Execute with these
        // exact roots/source. Only native can prove continuation or typed cancel.
        return AcquireDisposition(original.SpoolRoot, recoveryRoot, history.Select(h => h.Wal).ToArray(), destination, new(bounds), namespaces,
            deferUnboundLegacyTerminal: true);
    }

    internal static void RequireDisposition(string spoolRoot, string recoveryRoot, IReadOnlyList<VolumeTopologyWal> census)
    { using var disposition = AcquireDisposition(spoolRoot, recoveryRoot, census, null, null); }

    internal static void RequireDisposition(VolumeTopologyRequest original, string recoveryRoot)
    { using var disposition = AcquireDisposition(original, recoveryRoot, null); }

    internal static IDisposable AcquireDisposition(VolumeTopologyRequest original, string recoveryRoot, string? journalRoot)
    {
        if (journalRoot is not null && !string.Equals(original.JournalRoot, journalRoot, StringComparison.OrdinalIgnoreCase))
            throw new IOException("VolumeManagementStableRootMismatch");
        string? destination = null;
        if (original.ImageOptions is not null)
        {
            NativeApfsVolumeImageManagement.ValidateRequest(original);
            if (original.Operation is "format" or "erase") destination = original.ImageOptions.NewVolumeWal;
        }
        var markers = journalRoot is null ? null : OriginalMarkers(journalRoot, original.Image, original.OffsetBytes,
            original.SpoolRoot, recoveryRoot, original.ContainerUuid, original.SiblingWals, original.PreXid);
        var namespaces = journalRoot is null ? null : OriginalNamespaces(journalRoot, original.Image, original.OffsetBytes,
            original.SpoolRoot, recoveryRoot, original.ContainerUuid, original.SiblingWals);
        if (destination is not null && namespaces is not null) namespaces = namespaces.WithDestination(original.ImageOptions!.NewContainerUuid!, destination);
        return AcquireDisposition(original.SpoolRoot, recoveryRoot, original.SiblingWals, destination, markers, namespaces);
    }

    private sealed record MarkerScope(IReadOnlyDictionary<string, ulong?> Bounds);

    private sealed record NamespaceScope(string JournalRoot, IReadOnlyList<NamespaceIdentity> Known, IReadOnlySet<string> Wals)
    {
        internal NamespaceScope WithDestination(string container, string wal)
            => this with { Known = [.. Known, new(Guid.Empty, container, 1024)],
                Wals = Wals.Append(wal).ToHashSet(StringComparer.OrdinalIgnoreCase) };
    }

    private static NamespaceScope OriginalNamespaces(string journalRoot, string image, string offset, string spool, string recovery,
        string currentContainer, IReadOnlyList<VolumeTopologyWal> current)
    {
        var ownership = NativeOrdinaryImageOwnership.Read(journalRoot, image, offset);
        var history = ownership.LaunchBindings.Select(b => new HistoryMember(b.ContainerUuid, new(b.Oid, b.VolumeUuid, b.Wal), "1")).ToArray();
        if (!ownership.FreshCopy || !string.Equals(ownership.SpoolRoot, spool, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(ownership.RecoveryRoot, recovery, StringComparison.OrdinalIgnoreCase))
            throw new IOException("VolumeManagementHistoryOwnershipUnproved");
        if (history.Length != 0) ValidateHistoryOwnership(ownership, spool, recovery, history);
        NativeApfsVolumeManagement.ValidateCensus(current);
        var currentNamespaces = current.Select(w =>
        {
            var material = BuildNamespaceMaterial(null, currentContainer, ulong.Parse(w.Oid, CultureInfo.InvariantCulture), true)
                ?? throw new IOException("VolumeManagementNamespaceMaterialUnproved");
            if (!string.Equals(w.Path, CanonicalWal(spool, NamespaceRecoveryIdentity(material)), StringComparison.OrdinalIgnoreCase))
                throw new IOException("VolumeManagementSiblingIdentityChanged");
            return DecodeNamespace(material);
        }).ToArray();
        return new(journalRoot, history.Select(h => new NamespaceIdentity(Guid.Empty, h.ContainerUuid,
            ulong.Parse(h.Wal.Oid, CultureInfo.InvariantCulture))).Concat(currentNamespaces).Distinct().ToArray(),
            history.Select(h => h.Wal.Path).Concat(current.Select(w => w.Path)).ToHashSet(StringComparer.OrdinalIgnoreCase));
    }

    private static MarkerScope OriginalMarkers(string journalRoot, string image, string offset, string spool, string recovery,
        string container, IReadOnlyList<VolumeTopologyWal> census, string checkpoint)
    {
        if (offset != "0" || !VolumeTopologyProfile.Number(checkpoint, false))
            throw new IOException("VolumeManagementRecoveryMarkerScopeUnproved");
        NativeApfsVolumeManagement.ValidateCensus(census);
        var bindings = NativeOrdinaryImageOwnership.RequireCensus(journalRoot, image, offset, spool, recovery, container, census);
        var paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var binding in bindings)
        {
            var identity = NativeApfsBackend.BuildRecoveryIdentityFromComponents(null, container,
                ulong.Parse(binding.Oid, CultureInfo.InvariantCulture), true);
            if (identity != binding.RecoveryIdentity || !paths.Add(CanonicalNativeMarker(recovery, binding.RecoveryIdentity)))
                throw new IOException("VolumeManagementRecoveryMarkerIdentityChanged");
        }
        return new(paths.ToDictionary(p => p, _ => (ulong?)ulong.Parse(checkpoint, CultureInfo.InvariantCulture), StringComparer.OrdinalIgnoreCase));
    }

    private sealed class MarkerFence : IDisposable
    {
        internal readonly List<FileStream> Files = [];
        internal readonly List<SafeFileHandle> Directories = [];
        public void Dispose()
        {
            foreach (var file in Files) file.Dispose();
            foreach (var directory in Directories) directory.Dispose();
        }
    }

    private static bool IsPhysicalLegacyMarkerName(string name)
    {
        const string prefix = "__._PhysicalDrive", ending = "_Native.state";
        if (name.Length > 255 || !name.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) || !name.EndsWith(ending, StringComparison.OrdinalIgnoreCase)) return false;
        var stem = name[prefix.Length..^ending.Length];
        var separator = stem.IndexOf('_');
        if (separator < 1 || !VolumePhysicalBinding.IsDevicePath(@"\\.\PhysicalDrive" + stem[..separator])) return false;
        var label = stem[(separator + 1)..];
        return !string.IsNullOrWhiteSpace(label) && NativeApfsVolumeRename.WellFormedUtf16(label) &&
            !label.Any(c => char.IsControl(c) || "<>:\"/\\|?*".Contains(c));
    }

    private static void FenceCleanMarker(string entry, MarkerFence fence, ulong? checkpointBound)
    {
        NativeApfsSnapshotReader.ValidateLocalFile(entry);
        var file = new FileStream(entry, FileMode.Open, FileAccess.Read, FileShare.Read);
        fence.Files.Add(file);
        _ = NativeApfsVolumeManagement.SourceIdentity(file.SafeFileHandle, entry, "0", false);
        if (file.Length is < 24 or > 43) throw new IOException("VolumeManagementRecoveryMarkerInvalid");
        var bytes = new byte[checked((int)file.Length)]; file.ReadExactly(bytes);
        var prefix = "dirty=0\nlastCommitXid="u8;
        if (!bytes.AsSpan().StartsWith(prefix) || bytes[^1] != (byte)'\n')
            throw new IOException("VolumeManagementRecoveryMarkerDirtyOrInvalid");
        var xid = Encoding.ASCII.GetString(bytes.AsSpan(prefix.Length, bytes.Length - prefix.Length - 1));
        if (!VolumeTopologyProfile.Number(xid, false) || checkpointBound is { } limit && ulong.Parse(xid, CultureInfo.InvariantCulture) > limit)
            throw new IOException("VolumeManagementRecoveryMarkerCheckpointUnproved");
    }

    private static IDisposable AcquireDisposition(string spoolRoot, string recoveryRoot, IReadOnlyList<VolumeTopologyWal> census,
        string? destination, MarkerScope? markers, NamespaceScope? namespaces = null, bool deferUnboundLegacyTerminal = false)
    {
        NativeApfsVolumeManagement.ValidateStoreRoot(spoolRoot);
        NativeApfsVolumeManagement.ValidateStoreRoot(recoveryRoot);
        // The keeper proves current canonical WAL debt while holding its leases.
        // No managed WAL/spool parser can prove historical or legacy debt clean.
        // Preserve such artifacts and refuse when there is evidence outside that fence.
        var current = census.Select(w => w.Path).ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (destination is not null) current.Add(destination);
        var currentDirectories = current.Select(p => Path.GetDirectoryName(p)!).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var knownDirectories = namespaces?.Wals.Select(p => Path.GetDirectoryName(p)!).ToHashSet(StringComparer.OrdinalIgnoreCase) ?? currentDirectories;
        var knownMarkers = namespaces?.Wals.Select(p => Path.Combine(recoveryRoot, Path.GetFileName(Path.GetDirectoryName(p)) + "_Native.state"))
            .ToHashSet(StringComparer.OrdinalIgnoreCase) ?? new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var count = 0;
        string[] Entries(string root)
        {
            var entries = new List<string>();
            foreach (var entry in Directory.EnumerateFileSystemEntries(root))
            {
                if (++count > 1024) throw new IOException("VolumeManagementRecoveryCensusTooLarge");
                entries.Add(entry);
            }
            return entries.ToArray();
        }
        var fence = new MarkerFence();
        try
        {
            var spoolEntries = Entries(spoolRoot);
            var recoveryEntries = Entries(recoveryRoot);
            // All current, retired and prepared-destination paths precede foreign classification.
            foreach (var entry in spoolEntries.Where(e => currentDirectories.Contains(e) || knownDirectories.Contains(e)))
            {
                NativeApfsVolumeManagement.ValidateStoreRoot(entry);
                if (!currentDirectories.Contains(entry)) throw new IOException("VolumeManagementHistoricalOrSpoolDebtUnproved: " + entry);
                foreach (var artifact in Entries(entry))
                {
                    var flags = File.GetAttributes(artifact);
                    if ((flags & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0)
                        throw new IOException("VolumeManagementHistoricalOrSpoolDebtUnproved: " + artifact);
                    if (Path.GetFileName(artifact) is "payload-spool.bin" or "payload-spool.idx")
                    {
                        NativeApfsSnapshotReader.ValidateLocalFile(artifact);
                        var file = new FileStream(artifact, FileMode.Open, FileAccess.Read, FileShare.Read);
                        fence.Files.Add(file);
                        NativeApfsSnapshotReader.ValidateIdentity(file.SafeFileHandle, artifact);
                        if (!GetFileInformationByHandle(file.SafeFileHandle, out var info) || info.Links != 1 ||
                            (info.Attributes & (uint)(FileAttributes.Directory | FileAttributes.Device | FileAttributes.ReparsePoint)) != 0 || file.Length != 0)
                            throw new IOException("VolumeManagementSelectedPayloadDispositionUnproved: " + artifact);
                    }
                    else if (!current.Contains(artifact) || Path.GetFileName(artifact) != "write-ahead.wal")
                        throw new IOException("VolumeManagementHistoricalOrSpoolDebtUnproved: " + artifact);
                }
            }
            foreach (var entry in recoveryEntries.Where(e => knownMarkers.Contains(e) || markers?.Bounds.ContainsKey(e) == true))
            {
                if (markers is null || !markers.Bounds.TryGetValue(entry, out var checkpointBound))
                    throw new IOException("VolumeManagementRecoveryMarkerDispositionUnproved: " + entry);
                FenceCleanMarker(entry, fence, checkpointBound);
            }
            if (namespaces is not null) fence.Directories.Add(OpenNamespaceDirectory(namespaces.JournalRoot, false));
            var classified = new HashSet<string>(StringComparer.Ordinal);
            void RequireForeign(string name, bool marker)
            {
                const string prefix = "apfs_recovery_v1_";
                const string ending = "_Native.state";
                if (marker)
                {
                    if (!name.EndsWith(ending, StringComparison.Ordinal)) throw new IOException("VolumeManagementRecoveryMarkerDispositionUnproved: " + name);
                    name = name[..^ending.Length];
                }
                if (namespaces is null || !name.StartsWith(prefix, StringComparison.Ordinal))
                    throw new IOException("VolumeManagementHistoricalOrSpoolDebtUnproved: " + name);
                var identity = "apfs-recovery-v1-" + name[prefix.Length..];
                if (BuildRecoveryStorageKey(identity) != name) throw new IOException("VolumeManagementNamespaceNameInvalid");
                if (classified.Contains(identity)) return;
                var (candidate, _) = ReadNamespaceWitness(namespaces.JournalRoot, identity, fence);
                if (!IsForeignNamespace(candidate, namespaces.Known)) throw new IOException("VolumeManagementNamespaceScopeAmbiguous");
                classified.Add(identity);
            }
            foreach (var entry in spoolEntries.Where(e => !currentDirectories.Contains(e) && !knownDirectories.Contains(e)))
            {
                var flags = File.GetAttributes(entry);
                if ((flags & FileAttributes.ReparsePoint) != 0) throw new IOException("VolumeManagementRecoveryStorageAlias");
                if ((flags & FileAttributes.Directory) == 0) throw new IOException("VolumeManagementLegacyRecoveryEvidenceUnproved");
                NativeApfsVolumeManagement.ValidateStoreRoot(entry);
                RequireForeign(Path.GetFileName(entry), false);
            }
            foreach (var entry in recoveryEntries.Where(e => !knownMarkers.Contains(e) && markers?.Bounds.ContainsKey(e) != true))
            {
                if ((File.GetAttributes(entry) & (FileAttributes.Directory | FileAttributes.ReparsePoint | FileAttributes.Device)) != 0)
                    throw new IOException("VolumeManagementRecoveryStorageAlias");
                if (deferUnboundLegacyTerminal && IsPhysicalLegacyMarkerName(Path.GetFileName(entry)))
                {
                    // Parse and fence an unbound candidate only. Its XID is never
                    // source/checkpoint authority; native must still close all debt.
                    FenceCleanMarker(entry, fence, null);
                    continue;
                }
                RequireForeign(Path.GetFileName(entry), true);
            }
            return fence;
        }
        catch { fence.Dispose(); throw; }
    }

    [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFile(string path, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", EntryPoint = "MoveFileExW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)] private static extern bool MoveFileEx(string source, string destination, uint flags);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)] private static extern bool FlushFileBuffers(SafeFileHandle handle);
    [StructLayout(LayoutKind.Sequential)] private struct FileInformation
    { public uint Attributes, CreationLow, CreationHigh, AccessLow, AccessHigh, WriteLow, WriteHigh, Serial, SizeHigh, SizeLow, Links, IndexHigh, IndexLow; }
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)] private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out FileInformation info);
}
