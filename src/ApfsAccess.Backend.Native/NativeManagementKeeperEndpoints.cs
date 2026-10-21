using System.Globalization;
using System.Security.Cryptography;
using ApfsAccess.Core;

namespace ApfsAccess.Backend.Native;

public sealed partial class NativeApfsBackend : IManagementQuotaKeeper
{
    public async Task<ManagementKeeperQuotaResult> SetQuotaReserveAsync(
        ManagementKeeperQuotaRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();
        using var operation = AcquireLifecycleOperationLease();
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _disposeCts.Token);
        try
        {
            if (!_options.EnableImageManagementMutations) throw new IOException("ImageManagementMutationsDisabled");
            if (_options.ManagementJournalRoot is not { } root ||
                !string.Equals(root, request.JournalRoot, StringComparison.OrdinalIgnoreCase))
                throw new IOException("ManagementQuotaStableRootMismatch");
            NativeApfsVolumeQuota.ValidateRequest(QuotaTransportRequest(request));

            // Discovery takes these locks in this order; retain the mount lock through commit.
            await _discoveryGate.WaitAsync(linked.Token).ConfigureAwait(false);
            try
            {
                await _gate.WaitAsync(linked.Token).ConfigureAwait(false);
                try
                {
                    return await Task.Run(() => ExecuteManagementQuota_NoLock(request, linked.Token), linked.Token).ConfigureAwait(false);
                }
                finally { _gate.Release(); }
            }
            finally { _discoveryGate.Release(); }
        }
        catch (ArgumentException error)
        { return new(false, 0, ManagementKeeperCodes.InvalidRequest, error.Message); }
        catch (IOException error) when (error.Message == "ManagementQuotaPreimageChanged")
        { return new(false, 0, ManagementKeeperCodes.StalePreimage, error.Message); }
        catch (IOException error) when (error is not NativeQuotaExitException)
        { return new(false, 0, ManagementKeeperCodes.Refused, error.Message); }
        catch (UnauthorizedAccessException error)
        { return new(false, 0, ManagementKeeperCodes.Refused, error.Message); }
    }

    internal void RequireManagementQuotaOwnerAbsence_NoLock()
    {
        if (!_hosts.IsEmpty || !_retainedStartupHosts.IsEmpty || !_containerGroups.IsEmpty || !_mounts.IsEmpty)
            throw new IOException("ManagementQuotaOwnerStillRetained");
    }

    private ManagementKeeperQuotaResult ExecuteManagementQuota_NoLock(ManagementKeeperQuotaRequest request, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        RequireManagementQuotaOwnerAbsence_NoLock();
        RequireOrdinaryImageRegistrationsConfiguration();
        var root = _options.ManagementJournalRoot!;
        var spool = Environment.GetEnvironmentVariable("APFSACCESS_SPOOL_ROOT") ?? throw new IOException("Original production spool root is not configured.");
        var recovery = Environment.GetEnvironmentVariable("APFSACCESS_RECOVERY_ROOT") ?? throw new IOException("Stable recovery root is not configured.");
        var registered = NativeOrdinaryImageOwnership.Read(root, request.ImagePath, "0");
        if (registered.FreshCopy && registered.LaunchBindings.Count == 0)
            return ExecuteFreshManagementQuota_NoLock(request, root, spool, recovery, token);
        var ownership = RequireManagementQuotaOwnership(request, root, spool, recovery);
        using var retained = new NativeOrdinaryImageOwnership.RetainedLaunch(ownership, "0");
        if (_ordinaryImageRegistrations.Length != 0)
        {
            var registrations = _ordinaryImageRegistrations.Where(r => string.Equals(r.DestinationImage, request.ImagePath, StringComparison.OrdinalIgnoreCase)).ToArray();
            if (registrations.Length != 1) throw new IOException("ManagementQuotaRegistrationMismatch");
            retained.RequireRegistration(registrations[0], root, spool, recovery);
        }
        using var original = new FileStream(ownership.CopiedFrom!, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (Convert.ToHexStringLower(SHA256.HashData(original)) != ownership.OriginalDigest)
            throw new IOException("ManagementQuotaOriginalSourceChanged");
        NativeManagementJournalAdmission.RequireImage(root, request.ImagePath, "0");
        var discovered = DiscoverUnownedDevice(request.ImagePath, true, token) ?? throw new IOException("ManagementQuotaInventoryUnavailable");
        var inventory = new DeviceInventory(new(request.ImagePath, discovered.DisplayName, true),
            discovered.Volumes.Select(v => CreateDiscoveredVolumeInfo(request.ImagePath, v)).ToArray(), discovered.Topology);
        var scope = BindManagementQuotaScope(request, inventory);
        var observed = TopologyKeeper().Observe(scope, inventory, recovery, token);
        var wallets = BindManagementQuotaObservation(request, scope, observed);
        var bindings = NativeOrdinaryImageOwnership.RequireCensus(root, request.ImagePath, "0", spool, recovery, request.ContainerUuid, observed.Volumes);
        // The quota tool has no held retired-history protocol. Do not give it that authority.
        if (ownership.LaunchBindings.Count != bindings.Count || ownership.LaunchBindings.Any(b => !bindings.Contains(b)))
            throw new IOException("ManagementQuotaHistoricalOwnershipUnsupported");
        var bound = new VolumeTopologyRequest("quota", request.ImagePath, root, "0", request.ContainerUuid,
            request.VolumeUuid, request.VolumeObjectId, request.PreimageXid, observed.SourceIdentity, spool, observed.Volumes);
        using var disposition = AcquireManagementQuotaDisposition(bound, bindings, recovery, root);
        retained.RequireBinding();
        var keeper = new NativeApfsVolumeQuota(_observerRunner, NativeApfsVolumeQuota.ResolvePackagedQuotaTool(), root);
        var result = keeper.SetQuotaReserveWithOriginalWals(request, wallets,
            ulong.Parse(observed.BlockBytes, CultureInfo.InvariantCulture), token);
        retained.RequireBinding();
        return result;
    }

    private ManagementKeeperQuotaResult ExecuteFreshManagementQuota_NoLock(ManagementKeeperQuotaRequest request,
        string root, string spool, string recovery, CancellationToken token)
    {
        var registrations = _ordinaryImageRegistrations.Where(r =>
            string.Equals(r.DestinationImage, request.ImagePath, StringComparison.OrdinalIgnoreCase)).ToArray();
        if (registrations.Length != 1) throw new IOException("ManagementQuotaFreshRegistrationRequired");
        var record = NativeOrdinaryImageOwnership.Read(root, request.ImagePath, "0");
        using var retained = new NativeOrdinaryImageOwnership.RetainedLaunch(record, "0");
        retained.RequireRegistration(registrations[0], root, spool, recovery);
        if (record.LaunchBindings.Count != 0) throw new IOException("ManagementQuotaFreshHistoryChanged");
        if (Directory.EnumerateFileSystemEntries(spool).Any() || Directory.EnumerateFileSystemEntries(recovery).Any())
            throw new IOException("ManagementQuotaPriorRuntimeEvidenceUnsupported");
        var journals = NativeApfsVolumeQuota.JournalDirFor(root, request.ImagePath);
        if (Directory.Exists(journals) || File.Exists(journals))
            throw new IOException("ManagementQuotaPriorIntentUnsupported");
        using var original = new FileStream(record.CopiedFrom!, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (Convert.ToHexStringLower(SHA256.HashData(original)) != record.OriginalDigest)
            throw new IOException("ManagementQuotaOriginalSourceChanged");
        using (var current = new FileStream(request.ImagePath, FileMode.Open, FileAccess.Read, FileShare.Read))
            if (Convert.ToHexStringLower(SHA256.HashData(current)) != record.OriginalDigest)
                throw new IOException("ManagementQuotaFreshPreimageRequired");
        NativeManagementJournalAdmission.RequireImage(root, request.ImagePath, "0");
        var discovered = DiscoverUnownedDevice(request.ImagePath, true, token) ?? throw new IOException("ManagementQuotaInventoryUnavailable");
        var inventory = new DeviceInventory(new(request.ImagePath, discovered.DisplayName, true),
            discovered.Volumes.Select(v => CreateDiscoveredVolumeInfo(request.ImagePath, v)).ToArray(), discovered.Topology);
        _ = BindManagementQuotaScope(request, inventory);
        var blockBytes = checked((ulong)inventory.Topology!.Snapshot.Containers.Single(c =>
            TopologyAdmission.SameUuid(c.Uuid, request.ContainerUuid)).BlockSizeBytes);
        retained.RequireBinding();
        // These are new journals for a proved never-launched copy, not replacement historical WALs.
        Directory.CreateDirectory(journals);
        var wallets = request.SiblingObjectIds.Append(request.VolumeObjectId).Order(StringComparer.Ordinal)
            .Select(oid => (Oid: ulong.Parse(oid, CultureInfo.InvariantCulture), Path: Path.Combine(journals, oid + ".wal"))).ToArray();
        foreach (var wallet in wallets)
        {
            token.ThrowIfCancellationRequested();
            using var wal = new FileStream(wallet.Path, FileMode.CreateNew,
                FileAccess.Write, FileShare.Read, 4096, FileOptions.WriteThrough);
            wal.Flush(true);
        }
        var keeper = new NativeApfsVolumeQuota(_observerRunner, NativeApfsVolumeQuota.ResolvePackagedQuotaTool(), root);
        var result = keeper.SetQuotaReserveWithOriginalWals(request, wallets, blockBytes, token);
        retained.RequireBinding();
        return result;
    }

    internal static IDisposable AcquireManagementQuotaDisposition(VolumeTopologyRequest bound,
        IReadOnlyList<NativeOrdinaryImageOwnership.Binding> bindings, string recovery, string root)
    {
        var fence = new ManagementQuotaMarkerFence();
        try
        {
            // Open every expected marker first; enumeration alone cannot prove missing originals.
            foreach (var binding in bindings)
            {
                var path = NativeRecoveryStorage.CanonicalNativeMarker(recovery, binding.RecoveryIdentity);
                try { NativeApfsSnapshotReader.ValidateLocalFile(path); }
                catch (ArgumentException error)
                { throw new IOException("ManagementQuotaOriginalMarkerMissingOrInvalid", error); }
                var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
                fence.Files.Add(file);
                _ = NativeApfsVolumeManagement.SourceIdentity(file.SafeFileHandle, path, "0", false);
            }
            fence.Disposition = NativeRecoveryStorage.AcquireDisposition(bound, recovery, root);
            return fence;
        }
        catch { fence.Dispose(); throw; }
    }

    private sealed class ManagementQuotaMarkerFence : IDisposable
    {
        internal readonly List<FileStream> Files = [];
        internal IDisposable? Disposition;
        public void Dispose()
        {
            Disposition?.Dispose();
            foreach (var file in Files) file.Dispose();
        }
    }

    internal static NativeOrdinaryImageOwnership.Record RequireManagementQuotaOwnership(
        ManagementKeeperQuotaRequest request, string root, string spool, string recovery)
    {
        if (!string.Equals(request.JournalRoot, root, StringComparison.OrdinalIgnoreCase))
            throw new IOException("ManagementQuotaStableRootMismatch");
        var record = NativeOrdinaryImageOwnership.Read(root, request.ImagePath, "0");
        if (!record.FreshCopy || record.LaunchBindings.Count == 0 ||
            !string.Equals(record.SpoolRoot, spool, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(record.RecoveryRoot, recovery, StringComparison.OrdinalIgnoreCase))
            throw new IOException("ManagementQuotaOriginalOwnershipUnproved");
        return record;
    }

    internal static VerifyScope BindManagementQuotaScope(ManagementKeeperQuotaRequest request, DeviceInventory inventory)
    {
        if (!TopologyAdmission.Validate(inventory) || inventory.Topology is null ||
            inventory.Volumes.Any(v => v.RegisteredImage is not null || v.IsEncrypted ||
                !TopologyAdmission.SameUuid(v.CatalogContainerUuid, request.ContainerUuid) ||
                v.CatalogDecision != ApfsCapabilityDecision.Writable || !CatalogMountPolicy.AllowsMount(v, false)))
            throw new IOException("ManagementQuotaProfileUnsupported");
        var rows = inventory.Volumes.Where(v => v.CatalogVolumeObjectId?.ToString(CultureInfo.InvariantCulture) == request.VolumeObjectId &&
            TopologyAdmission.SameUuid(v.CatalogContainerUuid, request.ContainerUuid) &&
            TopologyAdmission.SameUuid(v.CatalogVolumeUuid, request.VolumeUuid)).ToArray();
        if (rows.Length != 1) throw new IOException("ManagementQuotaSelectedIdentityChanged");
        var scope = VerifyScopeDerivation.TryDerive(inventory, rows[0]).Scope ?? throw new IOException("ManagementQuotaScopeUnproved");
        if (!string.Equals(scope.ImagePath, request.ImagePath, StringComparison.OrdinalIgnoreCase) || scope.StoreOffsetBytes != "0" ||
            !VolumeTopologyProfile.IsBounded(scope) || new FileInfo(request.ImagePath).Length.ToString(CultureInfo.InvariantCulture) != scope.StoreSizeBytes)
            throw new IOException("ManagementQuotaWholeOrdinaryImageRequired");
        if (scope.CheckpointXid != request.PreimageXid) throw new IOException("ManagementQuotaPreimageChanged");
        var siblings = inventory.Volumes.Where(v => v.CatalogVolumeObjectId != rows[0].CatalogVolumeObjectId)
            .Select(v => v.CatalogVolumeObjectId!.Value.ToString(CultureInfo.InvariantCulture)).ToHashSet(StringComparer.Ordinal);
        if (!siblings.SetEquals(request.SiblingObjectIds)) throw new IOException("ManagementQuotaSiblingCensusMismatch");
        return scope;
    }

    internal static IReadOnlyList<(ulong Oid, string Path)> BindManagementQuotaObservation(
        ManagementKeeperQuotaRequest request, VerifyScope scope, VolumeTopologyObservation observed)
    {
        NativeApfsVolumeManagement.ValidateCensus(observed.Volumes);
        if (!string.Equals(observed.Image, request.ImagePath, StringComparison.OrdinalIgnoreCase) || observed.OffsetBytes != "0" ||
            observed.ContainerUuid != request.ContainerUuid || observed.CheckpointXid != request.PreimageXid ||
            observed.StoreSizeBytes != scope.StoreSizeBytes || !VolumeTopologyProfile.Number(observed.BlockBytes, false) ||
            observed.SourceIdentity != NativeApfsVolumeManagement.SourceIdentity(request.ImagePath, "0") ||
            observed.Volumes.Count(w => w.Oid == request.VolumeObjectId && w.VolumeUuid == request.VolumeUuid) != 1 ||
            !observed.Volumes.Where(w => w.Oid != request.VolumeObjectId).Select(w => w.Oid).ToHashSet(StringComparer.Ordinal).SetEquals(request.SiblingObjectIds))
            throw new IOException("ManagementQuotaObservationBindingChanged");
        return observed.Volumes.OrderBy(w => ulong.Parse(w.Oid, CultureInfo.InvariantCulture))
            .Select(w => (ulong.Parse(w.Oid, CultureInfo.InvariantCulture), w.Path)).ToArray();
    }

    private static ApfsVolumeQuotaRequest QuotaTransportRequest(ManagementKeeperQuotaRequest request) =>
        new(request.ImagePath, request.ContainerUuid, request.VolumeUuid, request.VolumeObjectId, request.PreimageXid,
            request.QuotaBytes, request.ReserveBytes, request.SiblingObjectIds, request.JournalRoot);
}
