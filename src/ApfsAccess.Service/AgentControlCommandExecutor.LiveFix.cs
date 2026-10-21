using ApfsAccess.Core;
using ApfsAccess.Ipc;

namespace ApfsAccess.Service;

public sealed partial class AgentControlCommandExecutor
{
    private async Task<OperationResultPayload> ExecutePhysicalLiveFixAsync(
        ControlOperationRequestPayload request, VolumeInfo volume, DateTime requestedAtUtc, DateTime startedAtUtc,
        CancellationToken token)
    {
        var target = request.Target!;
        var before = await ProbeAuthoritativeMountStateAsync().ConfigureAwait(false);
        var proceed = TryGetPhysicalFixOwner(before, target, out var original);
        var required = SelectedControlTarget.IsAdvertised(target) || HasLiveFixEvidence(original);
        var diagnostic = proceed ? null : "LiveFixOwnerNotUnique: The initial exact owner was not proven.";
        if (proceed && original is { VolumeVerificationSupported: true })
        {
            var first = await VerifyPhysicalFixOwnerAsync(target, original, token).ConfigureAwait(false);
            required = true;
            proceed = first.Complete;
            diagnostic = AppendDiagnostic(diagnostic, $"verify-first:{first.Diagnostic}");
        }
        else if (proceed)
        {
            diagnostic = original is null
                ? "verify-first:no-owner; final admitted owner verification required when supported."
                : "verify-first:unavailable: VolumeVerificationOwnerRefused; final admitted owner must supply verification capability.";
        }

        using var permission = proceed && !token.IsCancellationRequested
            ? _worker.BeginPhysicalWritePermission(volume, token) : null;
        (bool Success, string Message) operation = (false, "Fix did not receive admitted mount completion.");
        if (proceed && !token.IsCancellationRequested)
        {
            try
            {
                // Only the existing exact mount path may bootstrap or replace an owner.
                operation = await _worker.EnsureMountedExactAsync(target.DeviceId, target.VolumeId,
                    MountAccessMode.ReadWrite, token, target.RecoveryIdentity, target).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (token.IsCancellationRequested)
            { operation = (false, "Fix was cancelled before admitted mount completion."); }
            catch (Exception ex)
            { operation = (false, $"Fix mount failed: {ex.Message}"); }
        }
        diagnostic = AppendDiagnostic(diagnostic, operation.Message);

        var afterMount = await ProbeAuthoritativeMountStateAsync().ConfigureAwait(false);
        var ownerProven = TryGetPhysicalFixOwner(afterMount, target, out var mounted);
        required |= HasLiveFixEvidence(mounted);
        LiveFixVerification? verified = null;
        if (proceed && operation.Success && ownerProven && mounted is not null && required && !token.IsCancellationRequested)
        {
            // Healthy RW does not request an upgrade. An unrelated replacement there
            // cannot inherit the first owner's proof merely because it is mounted.
            var replacementAdmitted = original is null || PhysicalFixMayRemount(original) ||
                SamePhysicalFixOwner(original, mounted);
            if (!replacementAdmitted)
                diagnostic = AppendDiagnostic(diagnostic, "LiveFixOwnerChangedWithoutRemount");
            else
            {
                verified = await VerifyPhysicalFixOwnerAsync(target, mounted, token).ConfigureAwait(false);
                diagnostic = AppendDiagnostic(diagnostic, $"verify-after:{verified.Diagnostic}");
            }
        }

        // A report cannot rescue a failed operation or a changed final owner. Reconcile
        // independently even after cancellation, refusal, or a failed status probe.
        var finalTargetValid = false;
        VolumeInfo? finalVolume = null;
        if (!token.IsCancellationRequested)
        {
            try
            {
                var finalTarget = await ResolveTargetAsync(target, token).ConfigureAwait(false);
                finalTargetValid = finalTarget.IsValid;
                finalVolume = finalTarget.Volume;
                if (!finalTargetValid) diagnostic = AppendDiagnostic(diagnostic, finalTarget.Diagnostic);
            }
            catch (Exception ex)
            { diagnostic = AppendDiagnostic(diagnostic, $"LiveFixFinalTargetNotProven: {ex.Message}"); }
        }
        var final = await ProbeAuthoritativeMountStateAsync().ConfigureAwait(false);
        var finalOwnerProven = TryGetPhysicalFixOwner(final, target, out var observed);
        required |= HasLiveFixEvidence(observed);
        var healthy = observed is not null && (required ? SnapshotFixHealthy(observed) : GetFinalStatus(observed) == "healthy-rw");
        var verificationProven = verified is { Complete: true, Report: { } report } && mounted is not null &&
            observed is not null && SamePhysicalFixOwner(mounted, observed) &&
            observed.VolumeVerificationSupported && observed.VolumeVerificationScope == report.Scope &&
            finalVolume is not null && PhysicalFixScopeMatches(finalVolume, observed, report.Scope);
        var cancelled = token.IsCancellationRequested;
        var success = !cancelled && proceed && operation.Success && finalTargetValid && ownerProven && finalOwnerProven && healthy &&
            (!required || verificationProven);
        var permissionResult = await CompletePhysicalWritePermissionAsync(permission, target, success, token).ConfigureAwait(false);
        success = permissionResult.Success;
        diagnostic = AppendDiagnostic(diagnostic, permissionResult.Diagnostic);
        if (!success && permission is { IsNew: true })
        {
            final = await ProbeAuthoritativeMountStateAsync().ConfigureAwait(false);
            finalOwnerProven = TryGetPhysicalFixOwner(final, target, out observed);
            healthy = observed is not null && SnapshotFixHealthy(observed);
        }
        if (required && !verificationProven)
            diagnostic = AppendDiagnostic(diagnostic, "LiveFixVerificationNotProven: Exact final owner and covered metadata verification were not both proven.");
        if (!healthy)
            diagnostic = AppendDiagnostic(diagnostic, "Fix did not prove the exact volume reached healthy read-write state.");
        if (!required)
            diagnostic = AppendDiagnostic(diagnostic,
                "verify:skipped:PhysicalTarget; legacy owner without verification capability: metadata remains unverified.");
        if (cancelled)
            diagnostic = AppendDiagnostic(diagnostic, "Fix was cancelled; final mount observation does not prove verified success.");
        diagnostic = AppendDiagnostic(diagnostic, final.Diagnostic);
        if (success && required)
            diagnostic = AppendDiagnostic(diagnostic,
                "Covered metadata only; whole-volume and payload hashes remain unverified. Final exact owner and scope rechecked.");
        var mountProof = !final.Succeeded || !finalOwnerProven ? "not-proven" : observed is null ? "absent" : "present";
        return BuildResult(request, requestedAtUtc, startedAtUtc, success,
            cancelled ? ApfsOperationCodes.OperationCancelled : success ? ApfsOperationCodes.OperationSucceeded : ApfsOperationCodes.BlockedRecovery,
            success ? "healthy-rw" : mountProof != "present" ? mountProof : required ? "verification-not-complete" : GetFinalStatus(observed),
            requestedMode: request.RequestedMode, effectiveMode: ToControlMode(observed?.AccessMode),
            recoveryState: GetRecoveryState(observed), recoveryActive: observed?.RecoveryActive ?? false,
            dirtyTransactionCount: observed?.DirtyTransactionCount ?? 0, pendingDurability: HasPendingDurability(observed),
            // Fix's existing wire contract carries no verification report or release-ownership proof.
            mountProof: mountProof, ownershipProof: success ? "not-applicable" : "not-proven",
            durabilityProof: success ? "not-applicable" : "not-proven", diagnostic: diagnostic,
            state: cancelled ? ApfsOperationStates.Cancelled : null);
    }

    private async Task<LiveFixVerification> VerifyPhysicalFixOwnerAsync(
        ApfsControlTarget target, MountedVolumeState expected, CancellationToken token)
    {
        try
        {
            var resolution = await ResolveTargetAsync(target, token).ConfigureAwait(false);
            var scope = expected.VolumeVerificationScope;
            if (!resolution.IsValid || !PhysicalFixScopeMatches(resolution.Volume!, expected, scope))
                return new(false, null, "VolumeVerificationOwnerRefused: Exact ordinary physical owner identity or scope is unavailable.");
            var report = await _worker.TryVerifyLiveVolumeAsync(target, token, metadataOnly: true).ConfigureAwait(false);
            if (report is null || report.Scope != scope)
                return new(false, null, "VolumeVerificationScopeChanged: The report does not bind the expected retained raw owner.");
            var current = await ResolveTargetAsync(target, token).ConfigureAwait(false);
            var probe = await ProbeAuthoritativeMountStateAsync().ConfigureAwait(false);
            if (!current.IsValid || !TryGetPhysicalFixOwner(probe, target, out var observed) || observed is null ||
                !SamePhysicalFixOwner(expected, observed) || !observed.VolumeVerificationSupported ||
                observed.VolumeVerificationScope != scope || !PhysicalFixScopeMatches(current.Volume!, observed, scope))
                return new(false, null, "LiveFixOwnerChanged: The exact target, owner or scope changed during verification.");
            return new(report.Complete, report, $"{report.Outcome.ToLowerInvariant()} findings={report.FindingCount}");
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested)
        { return new(false, null, "cancelled before terminal verification proof"); }
        catch (Exception ex)
        { return new(false, null, $"error: {ex.Message}"); }
    }

    private static bool PhysicalFixScopeMatches(VolumeInfo volume, MountedVolumeState owner, LiveVolumeVerificationScope? scope)
        => scope is { SourceKind: "retained-admitted-raw" } && owner.VolumeVerificationSupported && owner.HostProcessId > 0 &&
            owner.HostProcessCreationTimeFileTimeUtc > 0 &&
            !string.IsNullOrEmpty(owner.RecoveryIdentity) && owner.RecoveryIdentity == volume.RecoveryIdentity &&
            CatalogMountPolicy.AllowsOrdinaryMount(volume) && !volume.IsEncrypted && volume.RegisteredImage is null &&
            TopologyAdmission.SameUuid(scope.ContainerUuid, volume.CatalogContainerUuid) &&
            TopologyAdmission.SameUuid(scope.VolumeUuid, volume.CatalogVolumeUuid) &&
            TopologyAdmission.SameUuid(owner.CatalogContainerUuid, volume.CatalogContainerUuid) &&
            TopologyAdmission.SameUuid(owner.CatalogVolumeUuid, volume.CatalogVolumeUuid) &&
            owner.CatalogVolumeObjectId == volume.CatalogVolumeObjectId &&
            scope.VolumeOid == volume.CatalogVolumeObjectId?.ToString(System.Globalization.CultureInfo.InvariantCulture);

    private static bool SamePhysicalFixOwner(MountedVolumeState original, MountedVolumeState current)
        => original.HostProcessId > 0 && original.HostProcessCreationTimeFileTimeUtc > 0 &&
            original.HostProcessId == current.HostProcessId &&
            original.HostProcessCreationTimeFileTimeUtc == current.HostProcessCreationTimeFileTimeUtc &&
            original.RecoveryIdentity == current.RecoveryIdentity &&
            original.CatalogVolumeObjectId == current.CatalogVolumeObjectId &&
            original.CatalogContainerUuid == current.CatalogContainerUuid && original.CatalogVolumeUuid == current.CatalogVolumeUuid &&
            original.DeviceId == current.DeviceId && original.VolumeId == current.VolumeId && original.MountPoint == current.MountPoint;

    private static bool HasLiveFixEvidence(MountedVolumeState? owner)
        => owner is not null && (owner.VolumeVerificationSupported || owner.VolumeVerificationScope is not null ||
            owner.RuntimeWatermarksKnown is not null);

    private static bool PhysicalFixMayRemount(MountedVolumeState owner)
        => owner.AccessMode == MountAccessMode.ReadOnly || owner.RecoveryActive ||
            owner.NativeWriteReadiness is NativeWriteReadiness.RecoveryMode or NativeWriteReadiness.Degraded ||
            owner.NativeWriteSafetyState is NativeWriteSafetyState.ReadOnlyFallback or NativeWriteSafetyState.RecoveryBlocked;

    private static bool TryGetPhysicalFixOwner(AuthoritativeMountProbe probe, ApfsControlTarget target, out MountedVolumeState? owner)
    {
        owner = null;
        if (!probe.Succeeded) return false;
        var candidates = probe.Mounts.Where(m => string.Equals(m.VolumeId, target.VolumeId, StringComparison.OrdinalIgnoreCase) ||
            target.VolumeObjectId is not null && m.CatalogVolumeObjectId == target.VolumeObjectId &&
            TopologyAdmission.SameUuid(m.CatalogContainerUuid, target.ContainerUuid)).ToArray();
        if (candidates.Length == 0) return true;
        if (candidates.Length != 1 || !SelectedControlTarget.MatchesMount(target, candidates[0])) return false;
        owner = candidates[0];
        return true;
    }

    private sealed record LiveFixVerification(bool Complete, LiveVolumeVerificationReport? Report, string Diagnostic);
}
