using ApfsAccess.Core;
using ApfsAccess.Ipc;

namespace ApfsAccess.Service;

public sealed partial class ApfsMountWorker
{
    private readonly Dictionary<string, VolumeInfo> _manualReadOnlyVolumes = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _incompleteAccessModeVolumeIds = new(StringComparer.OrdinalIgnoreCase);

    private MountAccessMode ResolveRememberedAccessMode(VolumeInfo volume, MountAccessMode? requested, MountAccessMode fallback)
        => requested ?? (_manualReadOnlyVolumes.TryGetValue(volume.VolumeId, out var original) &&
            SameAccessModeVolume(original, volume) ? MountAccessMode.ReadOnly : fallback);

    private bool RetainsManualReadOnlyMode(MountedVolumeState mount)
        => _manualReadOnlyVolumes.TryGetValue(mount.VolumeId, out var volume) && AccessModeMountMatches(volume, mount);

    // Called under the worker operation lock. A launch-bound member mode requires
    // retiring the entire owner, including proof for already-detached siblings.
    private async Task<(bool Success, string Message)?> TryTransitionSharedContainerAccessModeAsync(
        string? volumeId, string? deviceId, MountAccessMode? requestedMode, DiscoverySnapshot discovery,
        ApfsControlTarget? selectedTarget, CancellationToken token)
    {
        if (_backend is not IContainerMountBackend containerBackend) return null;
        var mounted = (await _backend.GetMountStateAsync(token).ConfigureAwait(false)).ToArray();
        var candidates = mounted.Where(m =>
            (volumeId is null || string.Equals(m.VolumeId, volumeId, StringComparison.OrdinalIgnoreCase)) &&
            (deviceId is null || string.Equals(m.DeviceId, deviceId, StringComparison.OrdinalIgnoreCase)) &&
            (selectedTarget is null || SelectedControlTarget.MatchesMount(selectedTarget, m)) &&
            (requestedMode.HasValue ? m.AccessMode != requestedMode.Value :
                IsUpgradeableOrDegradedMount(m) && !RetainsManualReadOnlyMode(m))).ToArray();
        var target = candidates.FirstOrDefault(m => mounted.Any(other => !ReferenceEquals(m, other) &&
            (m.HostProcessId > 0 && other.HostProcessId == m.HostProcessId ||
             TopologyAdmission.SameUuid(m.CatalogContainerUuid, other.CatalogContainerUuid))) ||
            discovery.Volumes.Count(v => TopologyAdmission.SameUuid(v.CatalogContainerUuid, m.CatalogContainerUuid)) > 1);
        if (target is null) return null;

        var warnings = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var touched = false;
        var batchStarted = false;
        var original = Array.Empty<MountedVolumeState>();
        var volumes = Array.Empty<VolumeInfo>();
        var plan = Array.Empty<PreparedContainerMount>();
        var receipts = new Dictionary<string, UnmountResult>(StringComparer.OrdinalIgnoreCase);
        var command = Volatile.Read(ref _mountCommandGeneration);
        var operation = _mountOperationGeneration;

        async Task<(bool, string)> FinishAsync(bool success, string message)
        {
            // A cancelled request still publishes an independent observation. Missing
            // proof never removes a captured owner from the published fallback.
            var observed = await ReconcileRemainingMountsAsync(mounted, TimeSpan.FromSeconds(5),
                System.Diagnostics.Stopwatch.GetTimestamp()).ConfigureAwait(false);
            if (!observed.Succeeded) message = AppendDiagnostic(message, observed.Diagnostic);
            if (success && (!observed.Succeeded || !AccessModeObservedPlanMatches(plan, observed.Mounts)))
            {
                success = false;
                message = "Final container owner, modes or letters changed; transition success was not proven.";
                foreach (var member in original) _incompleteAccessModeVolumeIds.Add(member.VolumeId);
            }
            if (!success) warnings.Add(message);
            PublishFromMounts(observed.Mounts, success ? null : message, warnings, []);
            return (success && observed.Succeeded, message);
        }

        try
        {
            if (!TryCaptureAccessModeCohort(discovery, mounted, target, out volumes, out original))
                return await FinishAsync(false, "Access mode transition refused: complete ordinary cohort, clean runtime and exact owner identities were not proven.").ConfigureAwait(false);

            var changedMode = requestedMode ?? MountAccessMode.ReadWrite;
            // Retire every active member of the owner, while leaving discovered
            // but unmounted siblings inactive when the replacement is launched.
            plan = volumes.Where(v => original.Any(m => AccessModeMountMatches(v, m))).Select(v =>
            {
                var owner = original.Single(m => AccessModeMountMatches(v, m));
                var mode = ReferenceEquals(owner, target) ? changedMode : owner.AccessMode;
                return new PreparedContainerMount(v, new(v.VolumeId, TryGetDriveLetter(owner)!.Value, mode),
                    mode, mode == MountAccessMode.ReadWrite, null, owner.DeviceDisplayName);
            }).ToArray();
            foreach (var item in plan)
            {
                if (item.Request.AccessMode == MountAccessMode.ReadWrite &&
                    (!EvaluateVolumeWriteGate(discovery.Options, item.Volume).AllowWrite || !ImageMutationRootReady(item.Volume.DeviceId)))
                    return await FinishAsync(false, "Access mode transition refused: a cohort member cannot retain its requested write mode.").ConfigureAwait(false);

                // Reserve every captured letter through the existing selection path;
                // settings waits may release the worker lock, so revalidate below.
                var reserved = Enumerable.Range('A', 26).Select(i => (char)i).ToHashSet();
                reserved.Remove(item.Request.DriveLetter);
                if (await SelectDriveLetterForVolumeAsync(item.Volume, reserved, discovery.Generation, token).ConfigureAwait(false) != item.Request.DriveLetter)
                    return await FinishAsync(false, "Access mode transition refused: original drive letters could not be reserved.").ConfigureAwait(false);
            }

            var fresh = await DiscoverVolumesAsync(token).ConfigureAwait(false);
            var current = await _backend.GetMountStateAsync(token).ConfigureAwait(false);
            ValidateDriveLetterSelection(discovery.Generation, command, operation, token);
            var unchanged = SameAccessModeInventory(discovery, fresh, volumes) && SamePreparedMountOwners(mounted, current) &&
                TryCaptureAccessModeCohort(fresh, current, target, out _, out _) &&
                plan.All(p => p.Request.AccessMode != MountAccessMode.ReadWrite ||
                    EvaluateVolumeWriteGate(fresh.Options, p.Volume).AllowWrite && ImageMutationRootReady(p.Volume.DeviceId)) &&
                (selectedTarget is null || SelectedControlTarget.Matches(fresh.Inventory, selectedTarget));
            if (!TryAdmitDiscovery(fresh) || !unchanged)
                return await FinishAsync(false, "Access mode transition refused: inventory, source or owner changed before stop.").ConfigureAwait(false);

            // From the first detach onward, keep absent members suppressed until an
            // exact observed restoration. A poll cannot fill a failed plan with RW.
            foreach (var member in original) _incompleteAccessModeVolumeIds.Add(member.VolumeId);
            touched = true;
            foreach (var member in original)
            {
                token.ThrowIfCancellationRequested();
                var live = await _backend.GetMountStateAsync(token).ConfigureAwait(false);
                if (!AccessModeRemainingOwnersMatch(original, receipts, live))
                    throw new InvalidOperationException("Cohort owner changed during stop.");
                var proof = await _backend.UnmountAsync(member.MountPoint, token).ConfigureAwait(false);
                receipts[member.VolumeId] = proof;
                if (!AccessModeDetachProven(member, proof))
                    throw new InvalidOperationException("Cohort stop did not prove namespace removal and durability.");
            }
            if (!await SettleAccessModeOwnerAsync(original, receipts, token).ConfigureAwait(false))
                throw new InvalidOperationException("Cohort stop did not prove every original owner released.");
            token.ThrowIfCancellationRequested();
            if (!await AccessModeSourceStillMatchesAsync(fresh, volumes, token).ConfigureAwait(false) ||
                AccessModeRelatedMounts(original, await _backend.GetMountStateAsync(token).ConfigureAwait(false)).Any())
                throw new InvalidOperationException("Cohort source or ownership changed after stop.");

            batchStarted = true;
            var results = await containerBackend.MountContainerAsync(plan.Select(p => p.Request).ToArray(), token).ConfigureAwait(false);
            var after = await _backend.GetMountStateAsync(token).ConfigureAwait(false);
            if (!AccessModeBatchMatches(plan, results, after) ||
                after.Any(m => original.Any(o => m.HostProcessId == o.HostProcessId &&
                    m.HostProcessCreationTimeFileTimeUtc == o.HostProcessCreationTimeFileTimeUtc)) ||
                !await AccessModeSourceStillMatchesAsync(fresh, volumes, token).ConfigureAwait(false))
                throw new InvalidOperationException("Container batch did not prove the complete requested modes, letters and owner.");

            foreach (var item in plan)
            {
                _userEjectedVolumeIds.Remove(item.Volume.VolumeId);
                _incompleteAccessModeVolumeIds.Remove(item.Volume.VolumeId);
                _unsafeUnmountedVolumeIds.Remove(item.Volume.VolumeId);
                _mountRetryStates.Remove(item.Volume.VolumeId);
                _missingVolumeProbeCounts.Remove(item.Volume.VolumeId);
                _mountedOnce.Add(item.Volume.VolumeId);
            }
            var changedVolume = volumes.Single(v => AccessModeMountMatches(v, target));
            if (changedMode == MountAccessMode.ReadOnly) _manualReadOnlyVolumes[target.VolumeId] = changedVolume;
            else _manualReadOnlyVolumes.Remove(target.VolumeId);
            return await FinishAsync(true, "APFS container access mode changed with its complete cohort restored.").ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested)
        {
            return await FinishAsync(false, "Access mode transition cancelled; observed mounts retained and incomplete members remain suppressed.").ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            var restored = touched && !batchStarted && !token.IsCancellationRequested &&
                await TryRestoreAccessModeCohortAsync(discovery, volumes, original, receipts, token).ConfigureAwait(false);
            return await FinishAsync(false, AppendDiagnostic(ex.Message, restored ?
                "The exact prior cohort was restored." : "Prior cohort restoration was not proven; incomplete members remain suppressed.")).ConfigureAwait(false);
        }
    }

    private bool TryCaptureAccessModeCohort(DiscoverySnapshot discovery, IReadOnlyList<MountedVolumeState> mounted,
        MountedVolumeState target, out VolumeInfo[] volumes, out MountedVolumeState[] owners)
    {
        volumes = [];
        owners = [];
        var devices = discovery.Inventory.Where(d => string.Equals(d.Device.DeviceId, target.DeviceId, StringComparison.OrdinalIgnoreCase)).ToArray();
        if (devices.Length != 1 || !TopologyAdmission.Validate(devices[0]) || VolumeIntentBlocks(devices[0].Device.DeviceId)) return false;
        volumes = devices[0].Volumes.Where(v => TopologyAdmission.SameUuid(v.CatalogContainerUuid, target.CatalogContainerUuid)).ToArray();
        if (volumes.Length < 2 || volumes.Any(v => !AccessModeTypedVolume(v) ||
            !CatalogMountPolicy.AllowsOrdinaryMount(v) || v.CatalogDecision != ApfsCapabilityDecision.Writable ||
            v.IsEncrypted || v.RegisteredImage is not null || !v.SupportsExplorerMount ||
            _unsafeUnmountedVolumeIds.Contains(v.VolumeId))) return false;
        if (volumes.Select(v => v.CatalogVolumeId).Distinct(StringComparer.Ordinal).Count() != volumes.Length ||
            volumes.Select(v => Guid.Parse(v.CatalogVolumeUuid!)).Distinct().Count() != volumes.Length) return false;
        if (devices[0].Topology is { } topology && topology.Snapshot.Volumes.Count(v =>
            ApfsTopology.TryParseVolumeId(v.Id, out var container, out _) && TopologyAdmission.SameUuid(container, target.CatalogContainerUuid)) != volumes.Length) return false;
        owners = AccessModeRelatedMounts([target], mounted).ToArray();
        var rows = volumes;
        var captured = owners;
        if (captured.Length == 0 || captured.Length > rows.Length ||
            rows.Count(v => AccessModeMountMatches(v, target)) != 1 ||
            captured.Count(m => string.Equals(m.VolumeId, target.VolumeId, StringComparison.OrdinalIgnoreCase)) != 1 ||
            captured.Any(m => rows.Count(v => AccessModeMountMatches(v, m)) != 1 || !AccessModeRuntimeClean(m) ||
                _userEjectedVolumeIds.Contains(m.VolumeId) ||
                m.HostProcessId != target.HostProcessId || m.HostProcessCreationTimeFileTimeUtc != target.HostProcessCreationTimeFileTimeUtc ||
                !TryGetDriveLetter(m).HasValue) || captured.Select(m => TryGetDriveLetter(m)).Distinct().Count() != captured.Length) return false;
        return true;
    }

    private static bool AccessModeTypedVolume(VolumeInfo v)
        => !string.IsNullOrWhiteSpace(v.NativeVolumePath) && !string.IsNullOrWhiteSpace(v.RecoveryIdentity) &&
           Guid.TryParse(v.CatalogVolumeUuid, out var uuid) && uuid != Guid.Empty &&
           ApfsTopology.TryParseVolumeId(v.CatalogVolumeId, out var container, out var oid) &&
           TopologyAdmission.SameUuid(container, v.CatalogContainerUuid) && oid > 0 && oid == v.CatalogVolumeObjectId;

    private static bool AccessModeMountMatches(VolumeInfo v, MountedVolumeState m)
        => string.Equals(v.DeviceId, m.DeviceId, StringComparison.OrdinalIgnoreCase) &&
           string.Equals(v.VolumeId, m.VolumeId, StringComparison.OrdinalIgnoreCase) &&
           string.Equals(v.CatalogVolumeId, m.CatalogVolumeId, StringComparison.Ordinal) &&
           v.RecoveryIdentity == m.RecoveryIdentity && TopologyAdmission.SameUuid(v.CatalogContainerUuid, m.CatalogContainerUuid) &&
           TopologyAdmission.SameUuid(v.CatalogVolumeUuid, m.CatalogVolumeUuid) && v.CatalogVolumeObjectId == m.CatalogVolumeObjectId;

    private static bool AccessModeRuntimeClean(MountedVolumeState m)
        => m.MountPoint is { Length: 3 } && m.MountPoint[1] == ':' && m.MountPoint[2] == '\\' &&
           char.ToUpperInvariant(m.MountPoint[0]) is >= 'A' and <= 'Z' &&
           m.MountReady && m.HostProcessId > 0 && m.HostProcessCreationTimeFileTimeUtc > 0 &&
           m.RuntimeWatermarksKnown == true && !m.RuntimeMutationPending && !m.RecoveryActive &&
           string.IsNullOrWhiteSpace(m.RecoveryReason) && m.DirtyTransactionCount == 0 && !m.ShutdownDrainActive &&
           m.InFlightMutationCallbacks == 0 && m.WalAcceptedSequence == m.WalApfsDurableSequence &&
           m.WalAcceptedSequence == m.WalCleanupSequence &&
           m.NativeWriteReadiness is not (NativeWriteReadiness.RecoveryMode or NativeWriteReadiness.Degraded) &&
           m.NativeWriteSafetyState != NativeWriteSafetyState.RecoveryBlocked &&
           (m.AccessMode == MountAccessMode.ReadOnly || m.WriteBackend == "Native" &&
            m.CommitModel == NativeWriteCommitModel.CanonicalApfsCheckpoint && m.NativeWriteReadiness == NativeWriteReadiness.CommitReady &&
            m.NativeWriteSafetyState is NativeWriteSafetyState.PilotReadWrite or NativeWriteSafetyState.StableReadWrite);

    private static bool SameAccessModeVolume(VolumeInfo a, VolumeInfo b)
        => a.DeviceId == b.DeviceId && a.VolumeId == b.VolumeId && a.NativeVolumePath == b.NativeVolumePath &&
           a.RecoveryIdentity == b.RecoveryIdentity && a.CatalogVolumeId == b.CatalogVolumeId &&
           TopologyAdmission.SameUuid(a.CatalogContainerUuid, b.CatalogContainerUuid) &&
           TopologyAdmission.SameUuid(a.CatalogVolumeUuid, b.CatalogVolumeUuid) && a.CatalogVolumeObjectId == b.CatalogVolumeObjectId &&
           a.CatalogDecision == b.CatalogDecision && a.CatalogAutoMountAllowed == b.CatalogAutoMountAllowed &&
           a.SupportsExplorerMount == b.SupportsExplorerMount && a.SupportsNativeWrite == b.SupportsNativeWrite &&
           a.SupportsReadWrite == b.SupportsReadWrite && a.WriteBlockReason == b.WriteBlockReason &&
           a.IsEncrypted == b.IsEncrypted && a.NativeWriteAdmissionBlockReason == b.NativeWriteAdmissionBlockReason &&
           (a.WriteIncompatibilities ?? []).SequenceEqual(b.WriteIncompatibilities ?? []) &&
           (a.WriteUnsupportedFeatures ?? []).SequenceEqual(b.WriteUnsupportedFeatures ?? []) &&
           (a.CatalogReasons ?? []).SequenceEqual(b.CatalogReasons ?? []);

    private static bool SameAccessModeInventory(DiscoverySnapshot original, DiscoverySnapshot fresh, VolumeInfo[] volumes)
    {
        var device = original.Inventory.Single(d => d.Device.DeviceId == volumes[0].DeviceId);
        var devices = fresh.Inventory.Where(d => d.Device.DeviceId == device.Device.DeviceId).ToArray();
        if (devices.Length != 1 || !TopologyAdmission.Validate(devices[0])) return false;
        var rows = devices[0].Volumes.Where(v => TopologyAdmission.SameUuid(v.CatalogContainerUuid, volumes[0].CatalogContainerUuid)).ToArray();
        return rows.Length == volumes.Length && volumes.All(v => rows.Count(n => SameAccessModeVolume(v, n) &&
            (device.Topology is null ? devices[0].Topology is null : devices[0].Topology is not null &&
             TopologyAdmission.Contract(device, v) == TopologyAdmission.Contract(devices[0], n))) == 1);
    }

    private async Task<bool> AccessModeSourceStillMatchesAsync(DiscoverySnapshot discovery, VolumeInfo[] volumes, CancellationToken token)
    {
        var fresh = await DiscoverVolumesAsync(token).ConfigureAwait(false);
        var unchanged = SameAccessModeInventory(discovery, fresh, volumes);
        return TryAdmitDiscovery(fresh) && unchanged;
    }

    private static IEnumerable<MountedVolumeState> AccessModeRelatedMounts(IReadOnlyList<MountedVolumeState> originals, IReadOnlyList<MountedVolumeState> current)
        => current.Where(m => originals.Any(o => TopologyAdmission.SameUuid(o.CatalogContainerUuid, m.CatalogContainerUuid) ||
            o.HostProcessId > 0 && o.HostProcessId == m.HostProcessId ||
            string.Equals(o.MountPoint, m.MountPoint, StringComparison.OrdinalIgnoreCase) ||
            string.Equals(o.VolumeId, m.VolumeId, StringComparison.OrdinalIgnoreCase)));

    private static bool AccessModeDetachProven(MountedVolumeState member, UnmountResult proof)
        => proof.Success && proof.MountRemoved && proof.PendingDurabilityCleared && string.IsNullOrWhiteSpace(proof.Error) &&
           string.Equals(member.MountPoint, proof.MountPoint, StringComparison.OrdinalIgnoreCase);

    private static bool AccessModeRemainingOwnersMatch(MountedVolumeState[] original, Dictionary<string, UnmountResult> proofs,
        IReadOnlyList<MountedVolumeState> current)
        => SamePreparedMountOwners(original.Where(m => !proofs.TryGetValue(m.VolumeId, out var p) || !p.MountRemoved).ToArray(),
            AccessModeRelatedMounts(original, current).ToArray()) && AccessModeRelatedMounts(original, current).All(AccessModeRuntimeClean);

    private async Task<bool> SettleAccessModeOwnerAsync(MountedVolumeState[] owners, Dictionary<string, UnmountResult> proofs, CancellationToken token)
    {
        for (var attempt = 0; attempt < 12; ++attempt)
        {
            if (AccessModeRelatedMounts(owners, await _backend.GetMountStateAsync(token).ConfigureAwait(false)).Any()) return false;
            foreach (var owner in owners)
            {
                if (!proofs.TryGetValue(owner.VolumeId, out var proof) || !AccessModeDetachProven(owner, proof)) return false;
                if (!IsCompleteShutdownProof(owner, proof))
                    proofs[owner.VolumeId] = await _backend.UnmountAsync(owner.MountPoint, token).ConfigureAwait(false);
            }
            if (owners.All(m => proofs.TryGetValue(m.VolumeId, out var proof) && IsCompleteShutdownProof(m, proof))) return true;
            if (attempt < 11) await Task.Delay(1000, token).ConfigureAwait(false);
        }
        return false;
    }

    private static bool AccessModeBatchMatches(PreparedContainerMount[] plan, IReadOnlyList<MountResult> results,
        IReadOnlyList<MountedVolumeState> current)
        => AccessModeBatchResultsMatch(plan, results) && AccessModeObservedPlanMatches(plan, current);

    private static bool AccessModeBatchResultsMatch(PreparedContainerMount[] plan, IReadOnlyList<MountResult> results)
        => results.Count == plan.Length && !results.Where((r, i) => !r.Success || r.EffectiveAccessMode != plan[i].Request.AccessMode ||
            !string.Equals(r.MountPoint, $"{plan[i].Request.DriveLetter}:\\", StringComparison.OrdinalIgnoreCase)).Any();

    private static bool AccessModeObservedPlanMatches(PreparedContainerMount[] plan, IReadOnlyList<MountedVolumeState> current)
    {
        var owners = current.Where(m => plan.Any(p => AccessModeMountMatches(p.Volume, m))).ToArray();
        if (owners.Length != plan.Length || plan.Any(p => owners.Count(m => AccessModeMountMatches(p.Volume, m) &&
            m.AccessMode == p.Request.AccessMode && TryGetDriveLetter(m) == p.Request.DriveLetter && AccessModeRuntimeClean(m)) != 1)) return false;
        return AccessModeRelatedMounts(owners, current).Count() == owners.Length &&
            owners.All(m => m.HostProcessId == owners[0].HostProcessId && m.HostProcessCreationTimeFileTimeUtc == owners[0].HostProcessCreationTimeFileTimeUtc);
    }

    private async Task<bool> TryRestoreAccessModeCohortAsync(DiscoverySnapshot discovery, VolumeInfo[] volumes,
        MountedVolumeState[] original, Dictionary<string, UnmountResult> proofs, CancellationToken token)
    {
        try
        {
            if (original.Length == 0 || _backend is not IContainerMountBackend backend ||
                !await AccessModeSourceStillMatchesAsync(discovery, volumes, token).ConfigureAwait(false)) return false;
            var current = await _backend.GetMountStateAsync(token).ConfigureAwait(false);
            var remaining = AccessModeRelatedMounts(original, current).ToArray();
            // Reattach only into the still-proven original cohort, or after complete
            // terminal proof. A failed new batch does not imply its owner is absent.
            if (!AccessModeRemainingOwnersMatch(original, proofs, current)) return false;
            if (remaining.Length == 0 && !original.All(m => proofs.TryGetValue(m.VolumeId, out var p) && IsCompleteShutdownProof(m, p))) return false;
            var missing = original.Where(o => !remaining.Any(m => SameShutdownOwner(o, m))).ToArray();
            if (missing.Any(m => !proofs.TryGetValue(m.VolumeId, out var p) || !AccessModeDetachProven(m, p))) return false;
            var plan = missing.Select(m => new PreparedContainerMount(volumes.Single(v => AccessModeMountMatches(v, m)),
                new(m.VolumeId, TryGetDriveLetter(m)!.Value, m.AccessMode), m.AccessMode,
                m.AccessMode == MountAccessMode.ReadWrite, null, m.DeviceDisplayName)).ToArray();
            if (plan.Length == 0) return remaining.Length == original.Length;
            var results = await backend.MountContainerAsync(plan.Select(p => p.Request).ToArray(), token).ConfigureAwait(false);
            current = await _backend.GetMountStateAsync(token).ConfigureAwait(false);
            var complete = original.Select(m => new PreparedContainerMount(volumes.Single(v => AccessModeMountMatches(v, m)),
                new(m.VolumeId, TryGetDriveLetter(m)!.Value, m.AccessMode), m.AccessMode, false, null, m.DeviceDisplayName)).ToArray();
            if (!AccessModeBatchResultsMatch(plan, results) || !AccessModeObservedPlanMatches(complete, current) ||
                remaining.Length > 0 && remaining.Any(o => !current.Any(m => SameShutdownOwner(o, m))) ||
                !await AccessModeSourceStillMatchesAsync(discovery, volumes, token).ConfigureAwait(false)) return false;
            foreach (var member in original) _incompleteAccessModeVolumeIds.Remove(member.VolumeId);
            return true;
        }
        catch (Exception) { return false; }
    }
}
