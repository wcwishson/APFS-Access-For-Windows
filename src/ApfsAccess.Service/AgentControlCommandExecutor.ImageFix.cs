using ApfsAccess.Core;
using ApfsAccess.Ipc;

namespace ApfsAccess.Service;

public sealed partial class AgentControlCommandExecutor
{
    private async Task<OperationResultPayload> ExecuteImageFixAsync(
        ControlOperationRequestPayload request, TargetResolution initial,
        DateTime requestedAtUtc, DateTime startedAtUtc, CancellationToken token)
    {
        var derived = VerifyScopeDerivation.TryDerive(initial.Inventory!, initial.Volume!);
        // Freeze selection, source window and membership even for an older caller.
        // The offline gate deliberately drains the old owner and may advance XID.
        var selection = derived.Ok ? CaptureImageFixSelection(initial, derived.Scope!) : null;
        var target = selection?.Target ?? request.Target!;
        var verifyNote = $"verify:skipped:{derived.Code}";
        var diagnostic = AppendDiagnostic(verifyNote, "ImageFixVerificationNotProven: Exact image selection is unavailable.");
        var proceed = false;
        (bool Success, string Message) operation = (false, "Fix did not receive admitted mount completion.");
        MountedVolumeState? mounted = null;
        LiveFixVerification? verified = null;
        try
        {
            if (selection is not null)
            {
                if (selection.Members.Count > 1)
                {
                    var drained = await _worker.QuiesceImageFixContainerAsync(selection.Target, selection.Members,
                        inventory => ImageFixAdmissionMatches(selection, inventory), token).ConfigureAwait(false);
                    if (!drained.Success)
                        throw new OfflineImageOperationException(ApfsOperationCodes.UnsafeOwnership, drained.Message);
                }
                var verification = await RunImageFixVerifyFirstAsync(request, selection, token).ConfigureAwait(false);
                verifyNote = verification.Note;
                if (verification.Offer is { } offer)
                    return BuildResult(request, requestedAtUtc, startedAtUtc, false, ApfsOperationCodes.BlockedRecovery,
                        "repair-confirmation-required", requestedMode: request.RequestedMode, mountProof: "absent",
                        ownershipProof: "proven", durabilityProof: "not-applicable", diagnostic: verifyNote) with { ImageRepairOffer = offer };
                diagnostic = verifyNote;
                if (verifyNote == "verify:complete")
                {
                    var drained = await ResolveTargetAsync(target, token).ConfigureAwait(false);
                    proceed = ImageFixSelectionMatches(selection, drained);
                    if (!proceed) diagnostic = AppendDiagnostic(diagnostic, "ImageFixSelectionChangedAfterOfflineVerification");
                }
            }
            if (proceed && !token.IsCancellationRequested)
            {
                // The canonical writer needs the original journals for every member,
                // including siblings that did not have an Explorer mount before Fix.
                operation = await _worker.MountImageFixContainerAsync(target.DeviceId, target.ContainerUuid!, selection!.Members,
                    inventory => ImageFixAdmissionMatches(selection, inventory), token).ConfigureAwait(false);
                var current = await ResolveTargetAsync(target, token).ConfigureAwait(false);
                var probe = await ProbeAuthoritativeMountStateAsync().ConfigureAwait(false);
                if (operation.Success && TryGetImageFixOwner(probe, selection!, out mounted) && mounted is not null &&
                    ImageFixScopeMatches(selection!, current, mounted, mounted.VolumeVerificationScope) && SnapshotFixHealthy(mounted))
                {
                    verified = await VerifyImageFixOwnerAsync(selection!, mounted, token).ConfigureAwait(false);
                    diagnostic = AppendDiagnostic(diagnostic, $"verify-after:{verified.Diagnostic}");
                }
                else diagnostic = AppendDiagnostic(diagnostic, "ImageFixFreshOwnerNotProven: A healthy retained-image owner and current scope are required.");
            }
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested)
        { diagnostic = AppendDiagnostic(diagnostic, "ImageFixCancelledBeforeTerminalProof"); }
        catch (Exception ex)
        { diagnostic = AppendDiagnostic(diagnostic, $"ImageFixFailed: {ex.Message}"); }
        diagnostic = AppendDiagnostic(diagnostic, operation.Message);

        TargetResolution? finalInventory = null;
        if (!token.IsCancellationRequested)
        {
            try { finalInventory = await ResolveTargetAsync(target, token).ConfigureAwait(false); }
            catch (Exception ex)
            { diagnostic = AppendDiagnostic(diagnostic, $"ImageFixFinalInventoryNotProven: {ex.Message}"); }
        }
        // Always reconcile mount observation independently, including cancellation.
        // It can revoke a complete report, but cannot rescue a failed operation.
        var final = await ProbeAuthoritativeMountStateAsync().ConfigureAwait(false);
        var ownerUnique = TryGetImageFixOwner(final, selection, out var observed);
        var finalProof = selection is not null && finalInventory is not null && mounted is not null && observed is not null &&
            ownerUnique && verified is { Complete: true, Report: { } report } &&
            SameImageFixProof(mounted, observed) && ImageFixScopeMatches(selection, finalInventory, observed, report.Scope);
        var cancelled = token.IsCancellationRequested;
        var success = !cancelled && proceed && operation.Success && finalProof;
        if (!success)
        {
            diagnostic = AppendDiagnostic(diagnostic,
                "ImageFixVerificationNotProven: Fresh exact owner, covered metadata verification and final inventory were not all proven.");
            if (!cancelled && OfflineRepairImageHint(request.Target) is { } hint)
                diagnostic = AppendDiagnostic(diagnostic,
                    $"For registered image file '{hint}', diagnose read-only first with APFSAccess.Cli.exe verify --help; " +
                    "bounded offline count repair is a separate repair command. Unmount all image volumes before repair; " +
                    "missing credentials, missing members or unsupported damage require copy-off and the appropriate macOS repair.");
        }
        else diagnostic = AppendDiagnostic(diagnostic,
            "Covered metadata only; whole-volume and payload hashes remain unverified. Final exact image owner, scope and membership rechecked.");
        if (cancelled) diagnostic = AppendDiagnostic(diagnostic, "Fix was cancelled; final mount observation does not prove verified success.");
        diagnostic = AppendDiagnostic(diagnostic, final.Diagnostic);
        var mountProof = !final.Succeeded || !ownerUnique ? "not-proven" : observed is null ? "absent" : "present";
        return BuildResult(request, requestedAtUtc, startedAtUtc, success,
            cancelled ? ApfsOperationCodes.OperationCancelled : success ? ApfsOperationCodes.OperationSucceeded : ApfsOperationCodes.BlockedRecovery,
            success ? "healthy-rw" : verifyNote == "verify:complete" && mountProof != "present" ? mountProof : "verification-not-complete",
            requestedMode: request.RequestedMode, effectiveMode: ToControlMode(observed?.AccessMode),
            recoveryState: GetRecoveryState(observed), recoveryActive: observed?.RecoveryActive ?? false,
            dirtyTransactionCount: observed?.DirtyTransactionCount ?? 0, pendingDurability: HasPendingDurability(observed),
            // Fix has no wire field for a verification report or released ownership.
            mountProof: mountProof, ownershipProof: success ? "not-applicable" : "not-proven",
            durabilityProof: success ? "not-applicable" : "not-proven", diagnostic: diagnostic,
            state: cancelled ? ApfsOperationStates.Cancelled : null);
    }

    private async Task<LiveFixVerification> VerifyImageFixOwnerAsync(
        ImageFixSelection selection, MountedVolumeState expected, CancellationToken token)
    {
        try
        {
            var report = await _worker.TryVerifyLiveVolumeAsync(selection.Target, token).ConfigureAwait(false);
            if (report is null || report.Scope != expected.VolumeVerificationScope)
                return new(false, null, "ImageFixVerificationScopeChanged");
            var current = await ResolveTargetAsync(selection.Target, token).ConfigureAwait(false);
            var probe = await ProbeAuthoritativeMountStateAsync().ConfigureAwait(false);
            if (!TryGetImageFixOwner(probe, selection, out var observed) || observed is null ||
                !SameImageFixProof(expected, observed) || !ImageFixScopeMatches(selection, current, observed, report.Scope))
                return new(false, null, "ImageFixOwnerChanged: Exact image owner, scope, membership or watermarks changed during verification.");
            return new(report.Complete, report, $"{report.Outcome.ToLowerInvariant()} findings={report.FindingCount}");
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested)
        { return new(false, null, "cancelled before terminal verification proof"); }
        catch (Exception ex)
        { return new(false, null, $"error: {ex.Message}"); }
    }

    private async Task<(string Note, ImageRepairOffer? Offer)> RunImageFixVerifyFirstAsync(
        ControlOperationRequestPayload request, ImageFixSelection selection, CancellationToken token)
    {
        if (!_worker.ImageFixOfflineVerificationSupported) return ("verify:unsupported", null);
        try
        {
            return await _worker.WithImageFixOfflineAsync(
                request.Target! with { RecoveryIdentity = selection.Target.RecoveryIdentity },
                selection.Target, selection.Scope, async (scope, inventory, ct) =>
            {
                var result = await _worker.VerifyImageAsync(scope, ct).ConfigureAwait(false);
                var note = result switch
            {
                null => "verify:unsupported",
                { Supported: true, Outcome: "Complete", NativeExitCode: 0, FindingCount: 0 } => "verify:complete",
                { Outcome: "Incomplete" } => $"verify:findings:{result.FindingCount}",
                { Outcome: "Refused" } => "verify:refused",
                _ => $"verify:error:unknown-outcome-{result.Outcome}",
            };
                var offer = request.ApprovedImageRepairPlanId is null && ImageRepairPreverifyAllowsPlan(result)
                    ? await TryOfferImageRepairAsync(selection, scope, inventory, ct).ConfigureAwait(false) : null;
                return (note, offer);
            }, token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested) { throw; }
        catch (OfflineImageOperationException ex) { return (ex.Message, null); }
        catch (Exception ex) { return ($"verify:error:{ex.GetType().Name}:{ex.Message}", null); }
    }

    private static bool ImageRepairPreverifyAllowsPlan(ImageVerifyResult? result)
        => result is { Supported: true, Outcome: "Complete", NativeExitCode: 0, FindingCount: 0 } or
            { Supported: true, Outcome: "Incomplete", FindingCount: 1 };

    private static bool SameImageFixProof(MountedVolumeState expected, MountedVolumeState current)
        => SameRetainedSnapshotOwner(expected, current) && SnapshotFixHealthy(current) &&
            expected.VolumeVerificationScope == current.VolumeVerificationScope &&
            expected.WalAcceptedSequence == current.WalAcceptedSequence &&
            expected.WalApfsDurableSequence == current.WalApfsDurableSequence &&
            expected.WalCleanupSequence == current.WalCleanupSequence;

    private static bool TryGetImageFixOwner(AuthoritativeMountProbe probe, ImageFixSelection? selection, out MountedVolumeState? owner)
    {
        owner = null;
        if (!probe.Succeeded || selection is null) return false;
        var target = selection.Target;
        var candidates = probe.Mounts.Where(m =>
            string.Equals(m.DeviceId, target.DeviceId, StringComparison.OrdinalIgnoreCase) ||
            string.Equals(m.VolumeId, target.VolumeId, StringComparison.OrdinalIgnoreCase) ||
            TopologyAdmission.SameUuid(m.CatalogContainerUuid, target.ContainerUuid)).ToArray();
        if (candidates.Length == 0) return true;
        var selected = candidates.Where(m => SelectedControlTarget.MatchesMount(target, m)).ToArray();
        if (selected.Length != 1 || candidates.Select(m => m.VolumeId).Distinct(StringComparer.OrdinalIgnoreCase).Count() != candidates.Length)
            return false;
        var expected = selected[0];
        foreach (var peer in candidates.Where(m => !ReferenceEquals(m, expected)))
        {
            var member = selection.Members.SingleOrDefault(v => v.VolumeId == peer.VolumeId);
            if (member is null || peer.DeviceId != member.DeviceId || peer.CatalogVolumeId != member.CatalogVolumeId ||
                peer.RecoveryIdentity != member.RecoveryIdentity || peer.CatalogVolumeObjectId != member.CatalogVolumeObjectId ||
                !TopologyAdmission.SameUuid(peer.CatalogContainerUuid, member.CatalogContainerUuid) ||
                !TopologyAdmission.SameUuid(peer.CatalogVolumeUuid, member.CatalogVolumeUuid) ||
                peer.HostProcessId != expected.HostProcessId || peer.HostProcessCreationTimeFileTimeUtc != expected.HostProcessCreationTimeFileTimeUtc ||
                peer.VolumeVerificationScope?.SourceIdentity != expected.VolumeVerificationScope?.SourceIdentity)
                return false;
        }
        owner = expected;
        return true;
    }

    private static bool ImageFixScopeMatches(ImageFixSelection selection, TargetResolution current,
        MountedVolumeState owner, LiveVolumeVerificationScope? scope)
    {
        if (scope is not { SourceKind: "retained-image" } || string.IsNullOrWhiteSpace(scope.SourceIdentity) ||
            !ImageFixSelectionMatches(selection, current) || !owner.VolumeVerificationSupported ||
            owner.VolumeVerificationScope != scope || owner.HostProcessId <= 0 || owner.HostProcessCreationTimeFileTimeUtc <= 0 ||
            !SelectedControlTarget.MatchesMount(selection.Target, owner) ||
            string.IsNullOrEmpty(owner.RecoveryIdentity) || owner.RecoveryIdentity != current.Volume!.RecoveryIdentity ||
            owner.CatalogVolumeId != current.Volume.CatalogVolumeId) return false;
        var fresh = VerifyScopeDerivation.TryDerive(current.Inventory!, current.Volume!).Scope!;
        return TopologyAdmission.SameUuid(scope.ContainerUuid, current.Volume!.CatalogContainerUuid) &&
            TopologyAdmission.SameUuid(scope.VolumeUuid, fresh.VolumeUuid) && scope.VolumeOid == fresh.VolumeObjectId &&
            scope.CheckpointXid == fresh.CheckpointXid && scope.StoreOffsetBytes == fresh.StoreOffsetBytes &&
            scope.StoreSizeBytes == fresh.StoreSizeBytes;
    }

    private static bool ImageFixSelectionMatches(ImageFixSelection selection, TargetResolution current)
    {
        if (!current.IsValid || current.Inventory is null || current.Volume is null ||
            !CatalogMountPolicy.AllowsOrdinaryMount(current.Volume) || current.Volume.IsEncrypted || current.Volume.RegisteredImage is not null ||
            SelectedControlTarget.Create(current.Inventory, current.Volume) != selection.Target) return false;
        var fresh = VerifyScopeDerivation.TryDerive(current.Inventory, current.Volume);
        return fresh is { Ok: true, Scope: { } scope } &&
            scope with { CheckpointXid = selection.Scope.CheckpointXid } == selection.Scope &&
            ImageFixCohort(current) == selection.Cohort;
    }

    private static string ImageFixCohort(TargetResolution resolution)
    {
        var inventory = resolution.Inventory!;
        var container = inventory.Topology!.Snapshot.Containers.Single(c =>
            TopologyAdmission.SameUuid(c.Uuid, resolution.Volume!.CatalogContainerUuid));
        return System.Text.Json.JsonSerializer.Serialize(new
        {
            Members = container.VolumeIds.Order(StringComparer.Ordinal).ToArray(),
            Volumes = inventory.Topology.Snapshot.Volumes.Where(v => v.ContainerId == container.Id)
                .OrderBy(v => v.Id, StringComparer.Ordinal).Select(v => new { v.Id, v.Uuid, v.ObjectId }).ToArray(),
            Rows = inventory.Volumes.Where(v => TopologyAdmission.SameUuid(v.CatalogContainerUuid, container.Uuid))
                .OrderBy(v => v.VolumeId, StringComparer.Ordinal).Select(v => new
                    { v.DeviceId, v.VolumeId, v.RecoveryIdentity, v.CatalogVolumeId, v.CatalogVolumeUuid, v.CatalogVolumeObjectId }).ToArray(),
        });
    }

    private static ImageFixSelection CaptureImageFixSelection(TargetResolution initial, VerifyScope scope)
    {
        var members = initial.Inventory!.Volumes.Where(v => TopologyAdmission.SameUuid(
            v.CatalogContainerUuid, initial.Volume!.CatalogContainerUuid)).ToArray();
        return new(SelectedControlTarget.Create(initial.Inventory, initial.Volume!), scope, ImageFixCohort(initial),
            Array.AsReadOnly(members), Array.AsReadOnly(members.Select(v => SelectedControlTarget.Create(initial.Inventory, v)).ToArray()));
    }

    private static bool ImageFixAdmissionMatches(ImageFixSelection selection, IReadOnlyList<DeviceInventory> inventory)
    {
        if (selection.MemberTargets.Any(t => !SelectedControlTarget.Matches(inventory, t))) return false;
        var device = inventory.Single(d => string.Equals(d.Device.DeviceId, selection.Target.DeviceId, StringComparison.OrdinalIgnoreCase));
        var volume = device.Volumes.Single(v => v.VolumeId == selection.Target.VolumeId);
        var members = device.Volumes.Where(v => TopologyAdmission.SameUuid(v.CatalogContainerUuid, selection.Target.ContainerUuid)).ToArray();
        return members.Length == selection.Members.Count && members.All(v => CatalogMountPolicy.AllowsOrdinaryMount(v) &&
                !v.IsEncrypted && v.RegisteredImage is null) &&
            ImageFixSelectionMatches(selection, TargetResolution.Valid(volume, device));
    }

    private sealed record ImageFixSelection(ApfsControlTarget Target, VerifyScope Scope, string Cohort,
        IReadOnlyList<VolumeInfo> Members, IReadOnlyList<ApfsControlTarget> MemberTargets);
}

public sealed partial class ApfsMountWorker
{
    internal bool ImageFixOfflineVerificationSupported => _backend is IVerifyBackend;

    internal Task<EjectOperationResult> QuiesceImageFixContainerAsync(ApfsControlTarget target,
        IReadOnlyList<VolumeInfo> originalMembers, Func<IReadOnlyList<DeviceInventory>, bool> admission, CancellationToken token)
    {
        if (!VolumeTopologyProfile.LocalPath(target.DeviceId) || originalMembers.Count < 2 ||
            originalMembers.Any(v => !CatalogMountPolicy.AllowsOrdinaryMount(v) || v.IsEncrypted || v.RegisteredImage is not null))
            throw new InvalidOperationException("A complete ordinary image cohort is required.");
        if (!ImageFixOfflineVerificationSupported || _backend is not IContainerMountBackend)
            throw new InvalidOperationException("The backend cannot verify and restore the complete image cohort.");
        return EjectContainerCoreAsync(target.DeviceId, target.ContainerUuid!, token, 0, originalMembers, admission);
    }

    internal Task<(bool Success, string Message)> MountImageFixContainerAsync(string deviceId, string containerUuid,
        IReadOnlyList<VolumeInfo> members, Func<IReadOnlyList<DeviceInventory>, bool> admission, CancellationToken token)
        => MountContainerCoreAsync(deviceId, containerUuid, members, MountAccessMode.ReadWrite, token, admission);

    internal Task<T> WithImageFixOfflineAsync<T>(ApfsControlTarget quiesceTarget,
        ApfsControlTarget selectedTarget, VerifyScope expected,
        Func<VerifyScope, DeviceInventory, CancellationToken, Task<T>> operation, CancellationToken token)
        => WithOfflineVolumeAsync(quiesceTarget, true, (scope, ct) =>
        {
            if (_admittedDiscovery?.Inventory is not { } inventory ||
                !SelectedControlTarget.Matches(inventory, selectedTarget) ||
                scope with { CheckpointXid = expected.CheckpointXid } != expected)
                throw new OfflineImageOperationException(ApfsOperationCodes.AmbiguousTarget,
                    "The selected image identity or topology changed before offline verification.");
            return operation(scope, inventory.Single(d => string.Equals(d.Device.DeviceId, scope.ImagePath, StringComparison.OrdinalIgnoreCase)), ct);
        }, token);

    internal Task<ImageVerifyResult?> VerifyImageFixOfflineAsync(ApfsControlTarget quiesceTarget,
        ApfsControlTarget selectedTarget, VerifyScope expected, CancellationToken token)
        => _backend is not IVerifyBackend ? Task.FromResult<ImageVerifyResult?>(null) :
            WithOfflineVolumeAsync(quiesceTarget, quiesceSelected: true, (scope, ct) =>
            {
                // The existing gate binds the drained owner independently. Before
                // opening the verifier, also bind its fresh scope to Fix's selection.
                if (_admittedDiscovery?.Inventory is not { } inventory ||
                    !SelectedControlTarget.Matches(inventory, selectedTarget) ||
                    scope with { CheckpointXid = expected.CheckpointXid } != expected)
                    throw new OfflineImageOperationException(ApfsOperationCodes.AmbiguousTarget,
                        "The selected image identity or topology changed before offline verification.");
                return VerifyImageAsync(scope, ct);
            }, token);
}
