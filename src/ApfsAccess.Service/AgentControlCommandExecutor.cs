using ApfsAccess.Core;
using ApfsAccess.Ipc;

namespace ApfsAccess.Service;

public sealed partial class AgentControlCommandExecutor
{
    private static readonly TimeSpan AuthoritativeProbeTimeout = TimeSpan.FromSeconds(2);
    private readonly ApfsMountWorker _worker;
    private readonly Func<DateTime, bool> _quitMarkerWriter;
    private readonly TimeProvider _timeProvider;
    private readonly ManagementPlanRegistry _managementPlans;
    private readonly string? _managementJournalRoot;
    private readonly Func<VerifyScope, CancellationToken, Task<System.Text.Json.JsonElement>> _snapshotReader;

    public AgentControlCommandExecutor(
        ApfsMountWorker worker,
        Func<DateTime, bool>? quitMarkerWriter = null,
        TimeProvider? timeProvider = null,
        string? managementJournalRoot = null,
        Func<VerifyScope, CancellationToken, Task<System.Text.Json.JsonElement>>? snapshotReader = null)
    {
        _worker = worker ?? throw new ArgumentNullException(nameof(worker));
        _quitMarkerWriter = quitMarkerWriter ?? (timestampUtc => QuitRequestMarker.WriteMarker(timestampUtc));
        _timeProvider = timeProvider ?? TimeProvider.System;
        _managementPlans = new ManagementPlanRegistry(() => _timeProvider.GetUtcNow());
        // Null keeps keeper execution disabled: apply revalidates fully and
        // then reports keeper-unavailable. Production packaging configures
        // a durable keeper root outside any volume under management.
        _managementJournalRoot = managementJournalRoot ?? worker.ConfiguredManagementJournalRoot;
        _snapshotReader = snapshotReader ?? ReadSnapshotInventoryAsync;
    }

    public async Task<OperationResultPayload> ExecuteAsync(
        ControlOperationRequestPayload request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();

        var requestedAtUtc = _timeProvider.GetUtcNow().UtcDateTime;
        var startedAtUtc = requestedAtUtc;
        try
        {
            if (request.ApprovedImageRepairPlanId is not null &&
                (request.Command != ApfsControlCommands.Fix || !ImageRepairPersistence.Hex(request.ApprovedImageRepairPlanId) ||
                 request.Target is not { RegisteredImage: null } || !ImageRepairPersistence.LocalPath(request.Target.DeviceId) ||
                 !SelectedControlTarget.IsWellFormed(request.Target) || request.RequestedMode is not (null or ApfsControlModes.ReadWrite)))
                return BuildResult(request, requestedAtUtc, startedAtUtc, false, ApfsOperationCodes.InvalidArguments,
                    "invalid", requestedMode: request.RequestedMode, diagnostic: "Invalid ordinary image Fix approval.");
            if (request.Command is ApfsControlCommands.RegisterImage or ApfsControlCommands.Unlock or ApfsControlCommands.Lock)
                return await ExecuteEncryptionAsync(request, requestedAtUtc, startedAtUtc, cancellationToken).ConfigureAwait(false);
            if (request.Command == ApfsControlCommands.ImageKeyManagement)
                return await ExecuteKeyManagementAsync(request, requestedAtUtc, startedAtUtc, cancellationToken).ConfigureAwait(false);
            if (request.Command == ApfsControlCommands.RegisterFusion ||
                request.Command is ApfsControlCommands.Mount or ApfsControlCommands.Eject && request.Target?.RegisteredFusion is not null)
                return await ExecuteFusionAsync(request, requestedAtUtc, startedAtUtc, cancellationToken).ConfigureAwait(false);

            if (VolumeManagementParameters.IsCommand(request.Command))
            {
                try { return await _worker.WithMountOperationsPausedAsync(token => ExecuteVolumeManagementAsync(
                    request, requestedAtUtc, startedAtUtc, token), cancellationToken).ConfigureAwait(false); }
                catch (OperationCanceledException) { throw; }
                catch (Exception ex)
                {
                    var pending = request.Target is not null && _worker.VolumeIntentBlocks(request.Target.DeviceId);
                    return BuildResult(request, requestedAtUtc, startedAtUtc, false,
                        ex is OfflineImageOperationException rejected ? rejected.Code : ApfsOperationCodes.ServiceUnavailable,
                        "not-proven", pendingDurability: pending, ownershipProof: "not-proven", durabilityProof: pending ? "not-proven" : "not-applicable",
                        diagnostic: ex.Message);
                }
            }

            if (string.Equals(request.Command, ApfsControlCommands.Mount, StringComparison.OrdinalIgnoreCase))
            {
                return await ExecuteMountAsync(request, requestedAtUtc, startedAtUtc, cancellationToken)
                    .ConfigureAwait(false);
            }

            if (string.Equals(request.Command, ApfsControlCommands.ContainerMount, StringComparison.OrdinalIgnoreCase))
            {
                return await ExecuteContainerMountAsync(request, requestedAtUtc, startedAtUtc, cancellationToken)
                    .ConfigureAwait(false);
            }

            if (string.Equals(request.Command, ApfsControlCommands.ContainerUnmount, StringComparison.OrdinalIgnoreCase))
            {
                return await ExecuteContainerUnmountAsync(request, requestedAtUtc, startedAtUtc, cancellationToken)
                    .ConfigureAwait(false);
            }

            if (string.Equals(request.Command, ApfsControlCommands.DeviceEject, StringComparison.OrdinalIgnoreCase))
            {
                return await ExecuteDeviceEjectAsync(request, requestedAtUtc, startedAtUtc, cancellationToken)
                    .ConfigureAwait(false);
            }

            if (string.Equals(request.Command, ApfsControlCommands.Fix, StringComparison.OrdinalIgnoreCase))
            {
                return await ExecuteFixAsync(request, requestedAtUtc, startedAtUtc, cancellationToken)
                    .ConfigureAwait(false);
            }

            if (request.Command == ApfsControlCommands.VolumeVerify)
                return await ExecuteVolumeVerifyAsync(request, requestedAtUtc, startedAtUtc, cancellationToken).ConfigureAwait(false);
            if (request.Command == ApfsControlCommands.SnapshotList)
                return await ExecuteSnapshotListAsync(request, requestedAtUtc, startedAtUtc, cancellationToken).ConfigureAwait(false);

            if (string.Equals(request.Command, ApfsControlCommands.Eject, StringComparison.OrdinalIgnoreCase))
            {
                return await ExecuteEjectAsync(request, requestedAtUtc, startedAtUtc, cancellationToken)
                    .ConfigureAwait(false);
            }

            if (string.Equals(request.Command, ApfsControlCommands.SnapshotCreate, StringComparison.OrdinalIgnoreCase))
            {
                return await _worker.WithMountOperationsPausedAsync(token => ExecuteSnapshotControlAsync(request, requestedAtUtc, startedAtUtc,
                    SnapshotControlAction.Create, "snapshot-created", token), cancellationToken).ConfigureAwait(false);
            }

            if (string.Equals(request.Command, ApfsControlCommands.SnapshotDelete, StringComparison.OrdinalIgnoreCase))
            {
                return await _worker.WithMountOperationsPausedAsync(token => ExecuteSnapshotControlAsync(request, requestedAtUtc, startedAtUtc,
                    SnapshotControlAction.Delete, "snapshot-deleted", token), cancellationToken).ConfigureAwait(false);
            }

            if (string.Equals(request.Command, ApfsControlCommands.SnapshotRecover, StringComparison.OrdinalIgnoreCase))
            {
                return await _worker.WithMountOperationsPausedAsync(token => ExecuteSnapshotControlAsync(request, requestedAtUtc, startedAtUtc,
                    SnapshotControlAction.Recover, "snapshot-recovered", token), cancellationToken).ConfigureAwait(false);
            }

            if (string.Equals(request.Command, ApfsControlCommands.ManagementPlan, StringComparison.OrdinalIgnoreCase))
            {
                return await _worker.WithMountOperationsPausedAsync(
                    token => ExecuteManagementPlanAsync(request, requestedAtUtc, startedAtUtc, token), cancellationToken)
                    .ConfigureAwait(false);
            }

            if (string.Equals(request.Command, ApfsControlCommands.ManagementApply, StringComparison.OrdinalIgnoreCase))
            {
                return await _worker.WithMountOperationsPausedAsync(
                    token => ExecuteManagementApplyAsync(request, requestedAtUtc, startedAtUtc, token), cancellationToken)
                    .ConfigureAwait(false);
            }

            if (string.Equals(request.Command, ApfsControlCommands.Quit, StringComparison.OrdinalIgnoreCase))
            {
                return await ExecuteQuitAsync(request, requestedAtUtc, startedAtUtc, cancellationToken)
                    .ConfigureAwait(false);
            }

            return BuildResult(
                request,
                requestedAtUtc,
                startedAtUtc,
                success: false,
                code: ApfsOperationCodes.UnknownCommand,
                finalStatus: "invalid",
                diagnostic: $"Unknown control command '{request.Command}'.");
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (OfflineImageOperationException ex)
        {
            return BuildResult(request, requestedAtUtc, startedAtUtc, false, ex.Code, "not-proven",
                ownershipProof: "not-proven", diagnostic: ex.Message);
        }
        catch (Exception ex)
        {
            return BuildResult(
                request,
                requestedAtUtc,
                startedAtUtc,
                success: false,
                code: ApfsOperationCodes.OperationFailed,
                finalStatus: "failed",
                diagnostic: ex.Message);
        }
    }

    private async Task<OperationResultPayload> ExecuteMountAsync(
        ControlOperationRequestPayload request,
        DateTime requestedAtUtc,
        DateTime startedAtUtc,
        CancellationToken cancellationToken)
    {
        if (!TryParseRequestedMode(request.RequestedMode, out var requestedMode))
        {
            return BuildResult(
                request,
                requestedAtUtc,
                startedAtUtc,
                success: false,
                code: ApfsOperationCodes.InvalidArguments,
                finalStatus: "invalid",
                requestedMode: request.RequestedMode,
                diagnostic: $"Unsupported requested mode '{request.RequestedMode}'.");
        }

        var resolution = await ResolveTargetAsync(request.Target, cancellationToken).ConfigureAwait(false);
        if (!resolution.IsValid)
        {
            return BuildResult(
                request,
                requestedAtUtc,
                startedAtUtc,
                success: false,
                code: resolution.Code,
                finalStatus: "invalid",
                requestedMode: ToControlMode(requestedMode),
                diagnostic: resolution.Diagnostic);
        }

        using var permission = requestedMode == MountAccessMode.ReadWrite
            ? _worker.BeginPhysicalWritePermission(resolution.Volume!, cancellationToken) : null;
        (bool Success, string Message) operation;
        try
        {
            operation = await _worker.EnsureMountedExactAsync(
                    request.Target!.DeviceId,
                    request.Target.VolumeId,
                    requestedMode,
                    cancellationToken,
                    request.Target.RecoveryIdentity, request.Target)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            operation = (false, "The mount operation was cancelled before it returned terminal evidence.");
        }
        catch (Exception ex)
        {
            operation = (false, $"The mount operation failed: {ex.Message}");
        }

        var mountProbe = await ProbeAuthoritativeMountStateAsync().ConfigureAwait(false);
        var exactMounts = mountProbe.Succeeded
            ? FindExactMounts(mountProbe.Mounts, request.Target)
            : Array.Empty<MountedVolumeState>();
        var mount = exactMounts.Count == 1 ? exactMounts[0] : null;
        var effectiveMode = ToControlMode(mount?.AccessMode);
        var modeMatches = mountProbe.Succeeded &&
                          mount is not null &&
                          (!requestedMode.HasValue || mount.AccessMode == requestedMode.Value);
        var cancelled = cancellationToken.IsCancellationRequested;
        var success = !cancelled && operation.Success && modeMatches;
        var diagnostic = AppendDiagnostic(operation.Message, mountProbe.Diagnostic);
        var permissionResult = await CompletePhysicalWritePermissionAsync(permission, request.Target!, success, cancellationToken).ConfigureAwait(false);
        success = permissionResult.Success;
        diagnostic = AppendDiagnostic(diagnostic, permissionResult.Diagnostic);
        if (!success && permission is { IsNew: true })
        {
            mountProbe = await ProbeAuthoritativeMountStateAsync().ConfigureAwait(false);
            exactMounts = mountProbe.Succeeded ? FindExactMounts(mountProbe.Mounts, request.Target) : Array.Empty<MountedVolumeState>();
            mount = exactMounts.Count == 1 ? exactMounts[0] : null;
            effectiveMode = ToControlMode(mount?.AccessMode);
        }
        if (cancelled)
        {
            diagnostic = AppendDiagnostic(
                diagnostic,
                "The operation was cancelled after mount started; final state was reconciled independently.");
        }
        if (requestedMode == MountAccessMode.ReadWrite && mount?.AccessMode != MountAccessMode.ReadWrite)
        {
            diagnostic = AppendDiagnostic(
                diagnostic,
                mountProbe.Succeeded && mount is not null
                    ? "The requested read-write mode was not reached; the final mount is read-only."
                    : "The requested read-write mode was not reached; no final mount was proven.");
        }

        return BuildResult(
            request,
            requestedAtUtc,
            startedAtUtc,
            success,
            cancelled
                ? ApfsOperationCodes.OperationCancelled
                : success ? ApfsOperationCodes.OperationSucceeded : ApfsOperationCodes.OperationFailed,
            finalStatus: mountProbe.Succeeded ? GetFinalStatus(mount) : "not-proven",
            requestedMode: ToControlMode(requestedMode),
            effectiveMode,
            recoveryState: GetRecoveryState(mount),
            recoveryActive: mount?.RecoveryActive ?? false,
            dirtyTransactionCount: mount?.DirtyTransactionCount ?? 0,
            pendingDurability: HasPendingDurability(mount),
            mountProof: !mountProbe.Succeeded ? "not-proven" : mount is null ? "absent" : "present",
            ownershipProof: "not-applicable",
            durabilityProof: "not-applicable",
            diagnostic: diagnostic,
            state: cancelled ? ApfsOperationStates.Cancelled : null);
    }

    private async Task<OperationResultPayload> ExecuteFixAsync(
        ControlOperationRequestPayload request,
        DateTime requestedAtUtc,
        DateTime startedAtUtc,
        CancellationToken cancellationToken)
    {
        if (request.ApprovedImageRepairPlanId is not null)
            return await ExecuteApprovedImageRepairAsync(request, requestedAtUtc, startedAtUtc, cancellationToken).ConfigureAwait(false);
        var resolution = await ResolveTargetAsync(request.Target, cancellationToken).ConfigureAwait(false);
        if (!resolution.IsValid)
        {
            return BuildResult(
                request,
                requestedAtUtc,
                startedAtUtc,
                success: false,
                code: resolution.Code,
                finalStatus: "invalid",
                requestedMode: request.RequestedMode,
                diagnostic: resolution.Diagnostic);
        }

        var retainedRecovery = await TryFixRetainedSnapshotAsync(request, requestedAtUtc, startedAtUtc, cancellationToken)
            .ConfigureAwait(false);
        if (retainedRecovery is not null) return retainedRecovery;

        var scoped = VerifyScopeDerivation.TryDerive(resolution.Inventory!, resolution.Volume!);
        if (scoped.Code == VerifyScopeDerivation.PhysicalTarget)
            return await ExecutePhysicalLiveFixAsync(request, resolution.Volume!, requestedAtUtc, startedAtUtc, cancellationToken)
                .ConfigureAwait(false);
        if (scoped.Ok || OfflineRepairImageHint(request.Target) is not null)
        {
            var resumed = await TryResumeOriginalImageRepairAsync(request, requestedAtUtc, startedAtUtc, cancellationToken)
                .ConfigureAwait(false);
            if (resumed is not null) return resumed;
            return await ExecuteImageFixAsync(request, resolution, requestedAtUtc, startedAtUtc, cancellationToken)
                .ConfigureAwait(false);
        }
        var verifyNote = await RunVerifyFirstAsync(resolution, request.Target!, cancellationToken).ConfigureAwait(false);
        if (scoped.Ok && verifyNote != "verify:complete")
        {
            var probe = await ProbeAuthoritativeMountStateAsync().ConfigureAwait(false);
            var matches = probe.Succeeded ? FindExactMounts(probe.Mounts, request.Target) : [];
            var observed = matches.Count == 1 ? matches[0] : null;
            return BuildResult(request, requestedAtUtc, startedAtUtc, false, ApfsOperationCodes.BlockedRecovery,
                finalStatus: "verification-not-complete", effectiveMode: ToControlMode(observed?.AccessMode),
                mountProof: !probe.Succeeded ? "not-proven" : observed is null ? "absent" : "present",
                ownershipProof: "not-proven", durabilityProof: "not-proven",
                diagnostic: AppendDiagnostic(verifyNote,
                    $"For registered image file '{scoped.Scope!.ImagePath}', diagnose read-only first with APFSAccess.Cli.exe verify --help; " +
                    "bounded offline count repair is a separate repair command. Unmount all image volumes before repair; " +
                    "missing credentials, missing members or unsupported damage require copy-off and the appropriate macOS repair."));
        }

        (bool Success, string Message) operation;
        try
        {
            operation = await _worker.EnsureMountedExactAsync(
                    request.Target!.DeviceId,
                    request.Target.VolumeId,
                    MountAccessMode.ReadWrite,
                    cancellationToken,
                    request.Target.RecoveryIdentity, request.Target)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            operation = (false, "The fix operation was cancelled before it returned terminal evidence.");
        }

        var mountProbe = await ProbeAuthoritativeMountStateAsync().ConfigureAwait(false);
        var exactMounts = mountProbe.Succeeded
            ? FindExactMounts(mountProbe.Mounts, request.Target)
            : Array.Empty<MountedVolumeState>();
        var mount = exactMounts.Count == 1 ? exactMounts[0] : null;
        var healthyState = mountProbe.Succeeded &&
                           mount is not null &&
                           mount.AccessMode == MountAccessMode.ReadWrite &&
                           !mount.RecoveryActive &&
                           !HasPendingDurability(mount) &&
                           (mount.RuntimeWatermarksKnown is null || mount.MountReady) &&
                           mount.NativeWriteSafetyState is
                               NativeWriteSafetyState.PilotReadWrite or NativeWriteSafetyState.StableReadWrite;
        var cancelled = cancellationToken.IsCancellationRequested;
        var success = !cancelled && operation.Success && healthyState;

        var diagnostic = AppendDiagnostic(operation.Message, mountProbe.Diagnostic);
        diagnostic = AppendDiagnostic(diagnostic, verifyNote);
        if (cancelled)
        {
            diagnostic = AppendDiagnostic(
                diagnostic,
                "The operation was cancelled after fix started; final state was reconciled independently.");
        }
        if (!healthyState)
        {
            diagnostic = AppendDiagnostic(
                diagnostic,
                "Fix did not prove the exact volume reached healthy read-write state.");
            if (!cancelled && OfflineRepairImageHint(request.Target) is { } hint)
            {
                diagnostic = AppendDiagnostic(
                    diagnostic,
                    $"For registered image file '{hint}', diagnose read-only first with APFSAccess.Cli.exe verify --help; " +
                    "bounded offline count repair, if eligible, is a separate repair command that refuses anything " +
                    "outside its contract. Unmount or eject the image before any offline repair.");
            }
        }

        return BuildResult(
            request,
            requestedAtUtc,
            startedAtUtc,
            success,
            cancelled
                ? ApfsOperationCodes.OperationCancelled
                : success ? ApfsOperationCodes.OperationSucceeded : ApfsOperationCodes.BlockedRecovery,
            finalStatus: !mountProbe.Succeeded
                ? "not-proven"
                : healthyState ? "healthy-rw" : GetFinalStatus(mount),
            requestedMode: request.RequestedMode,
            effectiveMode: ToControlMode(mount?.AccessMode),
            recoveryState: GetRecoveryState(mount),
            recoveryActive: mount?.RecoveryActive ?? false,
            dirtyTransactionCount: mount?.DirtyTransactionCount ?? 0,
            pendingDurability: HasPendingDurability(mount),
            mountProof: !mountProbe.Succeeded ? "not-proven" : mount is null ? "absent" : "present",
            ownershipProof: "not-applicable",
            durabilityProof: "not-applicable",
            diagnostic: diagnostic,
            state: cancelled ? ApfsOperationStates.Cancelled : null);
    }

    private async Task<OperationResultPayload?> TryFixRetainedSnapshotAsync(
        ControlOperationRequestPayload request, DateTime requestedAtUtc, DateTime startedAtUtc,
        CancellationToken cancellationToken)
    {
        var probe = await ProbeAuthoritativeMountStateAsync().ConfigureAwait(false);
        var matches = probe.Succeeded ? FindExactMounts(probe.Mounts, request.Target) : [];
        if (matches.Count != 1 || !matches[0].SnapshotRecoverySupported ||
            (matches[0].AccessMode == MountAccessMode.ReadWrite && !matches[0].RecoveryActive &&
             matches[0].DirtyTransactionCount == 0 && !matches[0].RuntimeMutationPending &&
             matches[0].WalAcceptedSequence == matches[0].WalCleanupSequence)) return null;
        var original = matches[0];
        MountedVolumeState? recovered = null;
        var terminal = "SnapshotRecoveryOwnerChanged";
        bool nativeRecovered = false;
        LiveVolumeVerificationReport? verified = null;
        static bool InventoryMatchesOwner(TargetResolution resolution, MountedVolumeState owner)
            => resolution.IsValid &&
               string.Equals(resolution.Inventory!.Device.DeviceId, owner.DeviceId, StringComparison.OrdinalIgnoreCase) &&
               string.Equals(resolution.Volume!.DeviceId, owner.DeviceId, StringComparison.OrdinalIgnoreCase) &&
               string.Equals(resolution.Volume.VolumeId, owner.VolumeId, StringComparison.OrdinalIgnoreCase) &&
               !string.IsNullOrEmpty(owner.RecoveryIdentity) && resolution.Volume.RecoveryIdentity == owner.RecoveryIdentity &&
               TopologyAdmission.SameUuid(resolution.Volume.CatalogContainerUuid, owner.CatalogContainerUuid) &&
               TopologyAdmission.SameUuid(resolution.Volume.CatalogVolumeUuid, owner.CatalogVolumeUuid) &&
               owner.CatalogVolumeObjectId is > 0 && resolution.Volume.CatalogVolumeObjectId == owner.CatalogVolumeObjectId &&
               resolution.Volume.CatalogVolumeId == owner.CatalogVolumeId;
        try
        {
            await _worker.WithMountOperationsPausedAsync(async token =>
            {
                var resolution = await ResolveTargetAsync(request.Target, token).ConfigureAwait(false);
                var held = await ProbeAuthoritativeMountStateAsync().ConfigureAwait(false);
                var exact = held.Succeeded ? FindExactMounts(held.Mounts, request.Target) : [];
                if (!InventoryMatchesOwner(resolution, original) || exact.Count != 1 || !SameRetainedSnapshotOwner(original, exact[0]) ||
                    !exact[0].SnapshotRecoverySupported || original.HostProcessId <= 0 ||
                    original.HostProcessCreationTimeFileTimeUtc <= 0 ||
                    string.IsNullOrEmpty(original.RecoveryIdentity) || string.IsNullOrEmpty(original.CatalogContainerUuid) ||
                    original.CatalogVolumeObjectId is not > 0) return false;
                var receipt = await _worker.SendSnapshotControlAsync(original.CatalogContainerUuid,
                    original.CatalogVolumeObjectId.Value, SnapshotControlAction.Recover, [], token).ConfigureAwait(false);
                terminal = receipt.Code;
                if (!receipt.Success || receipt.Code != "SnapshotRecovered") return false;
                var fresh = await ProbeAuthoritativeMountStateAsync().ConfigureAwait(false);
                var after = fresh.Succeeded ? FindExactMounts(fresh.Mounts, request.Target) : [];
                if (after.Count != 1 || !SameRetainedSnapshotOwner(original, after[0]) || !SnapshotFixHealthy(after[0]))
                { terminal = "SnapshotRecoveryFreshRwNotProven"; return false; }
                recovered = after[0];
                nativeRecovered = true;
                return true;
            }, cancellationToken).ConfigureAwait(false);
            // This worker API owns its own pause. Keep the recovered owner and
            // exact scope across that boundary and recheck them after verification.
            if (nativeRecovered)
            {
                verified = await _worker.TryVerifyLiveVolumeAsync(request.Target!, cancellationToken).ConfigureAwait(false);
                if (!SnapshotRecoveryVerificationComplete(verified) || verified!.Scope != recovered!.VolumeVerificationScope)
                { nativeRecovered = false; terminal = "SnapshotRecoveryLiveVerificationNotProven"; }
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        { nativeRecovered = false; terminal = "SnapshotRecoveryCancelledBeforeTerminalProof"; }
        catch (Exception ex)
        { nativeRecovered = false; terminal = $"SnapshotRecoveryFailed: {ex.Message}"; }
        // Reconcile terminal observation even on refusal or cancellation. It can
        // revoke success, never rescue a failed first fresh-RW admission.
        TargetResolution? finalResolution = null;
        if (nativeRecovered && !cancellationToken.IsCancellationRequested)
        {
            try
            {
                finalResolution = await ResolveTargetAsync(request.Target, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            { nativeRecovered = false; terminal = "SnapshotRecoveryCancelledBeforeTerminalProof"; }
            catch (Exception ex)
            { nativeRecovered = false; terminal = $"SnapshotRecoveryFinalInventoryNotProven: {ex.Message}"; }
        }
        var final = await ProbeAuthoritativeMountStateAsync().ConfigureAwait(false);
        var finalMatches = final.Succeeded ? FindExactMounts(final.Mounts, request.Target) : [];
        var observed = finalMatches.Count == 1 ? finalMatches[0] : null;
        if (nativeRecovered && (observed is null || !SameRetainedSnapshotOwner(original, observed) ||
            !SnapshotFixHealthy(observed) || observed.VolumeVerificationScope != verified!.Scope ||
            finalResolution is null || !InventoryMatchesOwner(finalResolution, observed) ||
            !TopologyAdmission.SameUuid(verified.Scope.ContainerUuid, observed.CatalogContainerUuid) ||
            !TopologyAdmission.SameUuid(verified.Scope.VolumeUuid, observed.CatalogVolumeUuid) ||
            verified.Scope.VolumeOid != observed.CatalogVolumeObjectId?.ToString(System.Globalization.CultureInfo.InvariantCulture)))
        { nativeRecovered = false; terminal = "SnapshotRecoveryLiveVerificationNotProven"; }
        var mountProof = !final.Succeeded || finalMatches.Count > 1 ? "not-proven" : observed is null ? "absent" : "present";
        var cancelled = cancellationToken.IsCancellationRequested;
        var success = !cancelled && nativeRecovered && SnapshotRecoveryVerificationComplete(verified);
        return BuildResult(request, requestedAtUtc, startedAtUtc, success,
            cancelled ? ApfsOperationCodes.OperationCancelled : success ? ApfsOperationCodes.OperationSucceeded : ApfsOperationCodes.BlockedRecovery,
            success ? "healthy-rw" : mountProof != "present" ? mountProof : "snapshot-recovery-not-complete", requestedMode: request.RequestedMode,
            effectiveMode: ToControlMode(observed?.AccessMode),
            recoveryState: GetRecoveryState(observed), recoveryActive: observed?.RecoveryActive ?? false,
            dirtyTransactionCount: observed?.DirtyTransactionCount ?? 0,
            pendingDurability: !success || HasPendingDurability(observed), mountProof: mountProof,
            ownershipProof: success ? "not-applicable" : "not-proven", durabilityProof: success ? "not-applicable" : "not-proven",
            diagnostic: success ? verified!.Complete
                ? "Retained owner SnapshotRecovered, fresh healthy RW and exact-owner covered metadata verification complete. Whole-volume and payload hashes remain unverified."
                : "Retained owner SnapshotRecovered: exact native snapshot receipt publication, current roots, census, original clean WAL watermarks and marker verified. Fresh same-owner RW proven. Generic verification remains Refused for historical snapshot ownership; whole-volume and payload hashes remain unverified."
                : AppendDiagnostic(terminal, final.Diagnostic),
            state: cancelled ? ApfsOperationStates.Cancelled : null);
    }

    private static bool SameRetainedSnapshotOwner(MountedVolumeState original, MountedVolumeState current)
        => original.HostProcessId > 0 && original.HostProcessCreationTimeFileTimeUtc > 0 &&
           original.HostProcessId == current.HostProcessId &&
           original.HostProcessCreationTimeFileTimeUtc == current.HostProcessCreationTimeFileTimeUtc &&
           original.RecoveryIdentity == current.RecoveryIdentity && original.CatalogVolumeId == current.CatalogVolumeId &&
           original.CatalogVolumeObjectId == current.CatalogVolumeObjectId &&
           original.CatalogContainerUuid == current.CatalogContainerUuid && original.CatalogVolumeUuid == current.CatalogVolumeUuid &&
           original.DeviceId == current.DeviceId && original.VolumeId == current.VolumeId && original.MountPoint == current.MountPoint;

    private static bool SnapshotRecoveryVerificationComplete(LiveVolumeVerificationReport? report)
    {
        if (report is null) return false;
        if (report.Complete) return true;
        // SnapshotRecovered already requires the held native receipt verifier.
        // Preserve the generic verifier's single explicit coverage refusal;
        // every other incomplete, refused or unknown result remains blocked.
        if (report.Outcome != "Refused" || report.FindingCount != 1) return false;
        var finding = report.Json.GetProperty("findings")[0];
        return finding.GetProperty("detail").GetString() == "VerifierSnapshotReachableBlocksCheckedButHistoricalReferenceOwnershipUnproven" &&
            finding.GetProperty("code").GetInt32() == 17 && finding.GetProperty("check").GetInt32() == 13 &&
            finding.GetProperty("severity").GetInt32() == 2 &&
            report.Json.GetProperty("selected").ValueKind == System.Text.Json.JsonValueKind.Object;
    }

    private static bool SnapshotFixHealthy(MountedVolumeState mount)
        => mount.MountReady && mount.AccessMode == MountAccessMode.ReadWrite && mount.WriteBackend == "Native" &&
           !mount.RecoveryActive && mount.DirtyTransactionCount == 0 && !mount.ShutdownDrainActive &&
           mount.InFlightMutationCallbacks == 0 && mount.RuntimeWatermarksKnown == true && !mount.RuntimeMutationPending &&
           mount.WalAcceptedSequence == mount.WalApfsDurableSequence && mount.WalAcceptedSequence == mount.WalCleanupSequence &&
           mount.VolumeVerificationSupported && mount.VolumeVerificationScope is not null &&
           mount.NativeWriteSafetyState is NativeWriteSafetyState.PilotReadWrite or NativeWriteSafetyState.StableReadWrite;

    // Task 10 Step 5 verify-first helper. Derives the exact offline-verify
    // scope from the resolved inventory row and runs the read-only
    // verifier. Never throws except on caller cancellation: every other
    // failure becomes a stable token. A null inventory (unreachable
    // through valid resolution; defensive) skips the same way.
    private async Task<string> RunVerifyFirstAsync(
        TargetResolution resolution,
        ApfsControlTarget target,
        CancellationToken cancellationToken)
    {
        if (resolution.Inventory is null || resolution.Volume is null)
            return "verify:skipped:no-inventory";
        var scoped = VerifyScopeDerivation.TryDerive(resolution.Inventory, resolution.Volume);
        if (!scoped.Ok || scoped.Scope is null)
            return $"verify:skipped:{scoped.Code}";
        ImageVerifyResult? outcome;
        try
        {
            outcome = await _worker.VerifyOfflineVolumeAsync(target, quiesceSelected: true, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            if (ex is OfflineImageOperationException offline) return offline.Message;
            return $"verify:error:{ex.GetType().Name}";
        }
        if (outcome is null)
            return "verify:unsupported";
        return outcome.Outcome switch
        {
            "Complete" when outcome.Supported && outcome.NativeExitCode == 0 && outcome.FindingCount == 0 => "verify:complete",
            "Incomplete" => $"verify:findings:{outcome.FindingCount}",
            "Refused" => "verify:refused",
            _ => $"verify:error:unknown-outcome-{outcome.Outcome}",
        };
    }

    private async Task<OperationResultPayload> ExecuteVolumeVerifyAsync(ControlOperationRequestPayload request,
        DateTime requestedAtUtc, DateTime startedAtUtc, CancellationToken cancellationToken)
    {
        if (request.Target is null)
            return BuildResult(request, requestedAtUtc, startedAtUtc, false, ApfsOperationCodes.InvalidArguments, "invalid");
        var live = await _worker.TryVerifyLiveVolumeAsync(request.Target, cancellationToken).ConfigureAwait(false);
        if (live is not null)
            return BuildResult(request, requestedAtUtc, startedAtUtc, live.Complete,
                live.Complete ? ApfsOperationCodes.OperationSucceeded : ApfsOperationCodes.BlockedRecovery,
                live.Complete ? "verified-covered-scope" : "verification-not-complete", mountProof: "present",
                ownershipProof: "proven", durabilityProof: "not-applicable",
                diagnostic: $"verify:{live.Outcome.ToLowerInvariant()} findings={live.FindingCount}. Covered metadata only; whole-volume and payload hashes remain unverified.") with
                { VolumeVerificationReport = live.Json };
        var resolution = await ResolveTargetAsync(request.Target, cancellationToken).ConfigureAwait(false);
        if (!resolution.IsValid)
            return BuildResult(request, requestedAtUtc, startedAtUtc, false, resolution.Code, "invalid", diagnostic: resolution.Diagnostic);
        var verified = await _worker.VerifyOfflineVolumeAsync(request.Target!, quiesceSelected: false, cancellationToken).ConfigureAwait(false);
        var complete = verified is { Supported: true, Outcome: "Complete", NativeExitCode: 0, FindingCount: 0 };
        return BuildResult(request, requestedAtUtc, startedAtUtc, complete,
            complete ? ApfsOperationCodes.OperationSucceeded : ApfsOperationCodes.BlockedRecovery,
            complete ? "verified-covered-scope" : "verification-not-complete", mountProof: "absent",
            ownershipProof: complete ? "proven" : "not-proven", durabilityProof: "not-applicable",
            diagnostic: verified is null ? "verify:unsupported" :
                $"verify:{verified.Outcome.ToLowerInvariant()} findings={verified.FindingCount}. Covered metadata only; whole-volume and payload-hash verification are not implied. {verified.Detail}");
    }

    // Offline-repair pointer for the fix failure branch. Returns the image
    // path when the target names a local image file, else null. Physical
    // devices, UNC, ADS, relative and otherwise non-file shapes get no
    // pointer: omission is always safe (the repair tool re-validates every
    // selector), while a pointer names a command that would fail closed.
    private static string? OfflineRepairImageHint(ApfsControlTarget? target)
    {
        var candidate = target?.DeviceId;
        if (string.IsNullOrWhiteSpace(candidate)) return null;
        var flat = candidate.Replace('\\', '/');
        if (flat.StartsWith("//./", StringComparison.Ordinal) ||
            flat.StartsWith("//?/", StringComparison.Ordinal) ||
            flat.StartsWith("/??/", StringComparison.Ordinal))
            return null;
        var colon = flat.IndexOf(':');
        if (colon != 1 || !char.IsAsciiLetter(flat[0]) || flat.IndexOf(':', colon + 1) >= 0)
            return null;
        return candidate;
    }

    private async Task<OperationResultPayload> ExecuteEjectAsync(
        ControlOperationRequestPayload request,
        DateTime requestedAtUtc,
        DateTime startedAtUtc,
        CancellationToken cancellationToken,
        long encryptedGeneration = 0)
    {
        if(request.Target?.RegisteredImage is not null && encryptedGeneration==0)
            encryptedGeneration=_worker.ReserveEncryptedCommand();
        try
        {
            return await ExecuteEjectCoreAsync(request,requestedAtUtc,startedAtUtc,cancellationToken,encryptedGeneration).ConfigureAwait(false);
        }
        catch
        {
            if(encryptedGeneration!=0)
                _worker.TrySetEncryptionState(request.Target!.VolumeId,EncryptedVolumeState.Failed,encryptedGeneration);
            throw;
        }
    }

    private async Task<OperationResultPayload> ExecuteEjectCoreAsync(
        ControlOperationRequestPayload request,
        DateTime requestedAtUtc,
        DateTime startedAtUtc,
        CancellationToken cancellationToken,
        long encryptedGeneration)
    {
        if(encryptedGeneration!=0)
            await _worker.WaitForEncryptedTransitionAsync(cancellationToken).ConfigureAwait(false);
        var resolution = await ResolveTargetAsync(request.Target, cancellationToken).ConfigureAwait(false);
        if (!resolution.IsValid)
        {
            return BuildResult(
                request,
                requestedAtUtc,
                startedAtUtc,
                success: false,
                code: resolution.Code,
                finalStatus: "invalid",
                diagnostic: resolution.Diagnostic);
        }

        var before = await _worker.GetAuthoritativeMountStateAsync(cancellationToken).ConfigureAwait(false);
        var beforeMatches = FindExactMounts(before, request.Target);
        if (beforeMatches.Count == 0)
        {
            return BuildResult(
                request,
                requestedAtUtc,
                startedAtUtc,
                success: true,
                code: ApfsOperationCodes.AlreadyAchieved,
                finalStatus: "absent",
                recoveryState: "inactive",
                mountProof: "absent",
                ownershipProof: "not-proven",
                durabilityProof: "not-proven",
                diagnostic: "The exact APFS volume is not currently mounted.");
        }

        if (beforeMatches.Count != 1)
        {
            return BuildResult(
                request,
                requestedAtUtc,
                startedAtUtc,
                success: false,
                code: ApfsOperationCodes.AmbiguousTarget,
                finalStatus: "ambiguous",
                mountProof: "not-proven",
                ownershipProof: "not-proven",
                durabilityProof: "not-proven",
                diagnostic: $"The exact APFS volume has {beforeMatches.Count} matching mount entries; eject was not attempted.");
        }

        var beforeMount = beforeMatches[0];

        var operation = await _worker.EjectExactAsync(
                request.Target!.DeviceId,
                request.Target.VolumeId,
                cancellationToken,
                request.Target.RecoveryIdentity, request.Target, encryptedGeneration)
            .ConfigureAwait(false);
        var afterProbe = await ProbeAuthoritativeMountStateAsync().ConfigureAwait(false);
        var exactAfter = afterProbe.Succeeded
            ? FindExactMounts(afterProbe.Mounts, request.Target)
            : Array.Empty<MountedVolumeState>();
        var mountAbsent = afterProbe.Succeeded && exactAfter.Count == 0;
        operation.UnmountResults.TryGetValue(request.Target.VolumeId, out var unmount);
        var ownershipProven = unmount?.HostOwnershipReleased == true ||
                              (operation.Success && unmount?.ContainerMemberDetached == true);
        var durabilityProven = unmount?.PendingDurabilityCleared == true;
        var proofComplete = unmount is not null &&
                            unmount.Success &&
                            unmount.MountRemoved &&
                            ownershipProven &&
                            durabilityProven;
        var cancelled = cancellationToken.IsCancellationRequested;
        var success = !cancelled && operation.Success && mountAbsent && proofComplete;
        if (request.Target?.RegisteredImage is not null)
            _worker.TrySetEncryptionState(request.Target.VolumeId,success ? EncryptedVolumeState.Locked : EncryptedVolumeState.Failed,encryptedGeneration);
        var finalMount = exactAfter.Count == 1 ? exactAfter[0] : null;
        var diagnostic = AppendDiagnostic(operation.Message, afterProbe.Diagnostic);
        if (cancelled)
        {
            diagnostic = AppendDiagnostic(
                diagnostic,
                "The operation was cancelled after eject started; final state was reconciled independently.");
        }
        if (afterProbe.Succeeded && !mountAbsent)
        {
            diagnostic = AppendDiagnostic(diagnostic, "The exact volume is still present after eject.");
        }
        if (!proofComplete)
        {
            diagnostic = AppendDiagnostic(
                diagnostic,
                unmount?.Error ?? "Eject did not prove volume detachment or host ownership release and pending durability clearance.");
        }

        return BuildResult(
            request,
            requestedAtUtc,
            startedAtUtc,
            success,
            cancelled
                ? ApfsOperationCodes.OperationCancelled
                : success ? ApfsOperationCodes.OperationSucceeded : ApfsOperationCodes.UnsafeOwnership,
            finalStatus: afterProbe.Succeeded
                ? mountAbsent ? "absent" : GetFinalStatus(finalMount ?? beforeMount)
                : "not-proven",
            effectiveMode: ToControlMode(finalMount?.AccessMode ?? beforeMount.AccessMode),
            recoveryState: GetRecoveryState(finalMount ?? beforeMount),
            recoveryActive: (finalMount ?? beforeMount).RecoveryActive,
            dirtyTransactionCount: (finalMount ?? beforeMount).DirtyTransactionCount,
            pendingDurability: !durabilityProven || HasPendingDurability(finalMount),
            mountProof: afterProbe.Succeeded ? mountAbsent ? "absent" : "present" : "not-proven",
            ownershipProof: ownershipProven ? "proven" : "not-proven",
            durabilityProof: durabilityProven ? "proven" : "not-proven",
            diagnostic: diagnostic,
            state: cancelled ? ApfsOperationStates.Cancelled : null);
    }

    private async Task<OperationResultPayload> ExecuteQuitAsync(
        ControlOperationRequestPayload request,
        DateTime requestedAtUtc,
        DateTime startedAtUtc,
        CancellationToken cancellationToken)
    {
        var markerWritten = false;
        string? markerDiagnostic = null;
        try
        {
            markerWritten = _quitMarkerWriter(_timeProvider.GetUtcNow().UtcDateTime);
            if (!markerWritten)
            {
                markerDiagnostic = "Quit marker could not be durably written.";
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            markerDiagnostic = $"Quit marker could not be durably written: {ex.Message}";
        }

        ShutdownPreparationResult shutdown;
        try
        {
            shutdown = await _worker.PrepareFreshShutdownAttemptAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            using var shutdownProbeCts = new CancellationTokenSource(AuthoritativeProbeTimeout);
            try
            {
                shutdown = await _worker
                    .PrepareForShutdownAsync(shutdownProbeCts.Token)
                    .ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (shutdownProbeCts.IsCancellationRequested)
            {
                shutdown = new ShutdownPreparationResult(
                    CleanupCompleted: false,
                    RemainingMounts: Array.Empty<MountedVolumeState>(),
                    HostOwnershipReleased: false,
                    PendingDurabilityCleared: false,
                    Diagnostic: $"Shutdown proof reconciliation timed out after {AuthoritativeProbeTimeout.TotalSeconds:n0} seconds.");
            }
            catch (Exception ex)
            {
                shutdown = new ShutdownPreparationResult(
                    CleanupCompleted: false,
                    RemainingMounts: Array.Empty<MountedVolumeState>(),
                    HostOwnershipReleased: false,
                    PendingDurabilityCleared: false,
                    Diagnostic: $"Shutdown proof reconciliation failed: {ex.Message}");
            }
        }

        var finalProbe = await ProbeAuthoritativeMountStateAsync().ConfigureAwait(false);
        var finalMounts = finalProbe.Mounts;
        var noRemainingMounts = finalProbe.Succeeded && finalMounts.Count == 0;
        var unmountProofs = shutdown.UnmountResultsOrEmpty.Values;
        var ownershipProven = shutdown.HostOwnershipReleased &&
                              noRemainingMounts &&
                              unmountProofs.All(static result =>
                                  result.Success && result.MountRemoved && result.HostOwnershipReleased);
        var durabilityProven = shutdown.PendingDurabilityCleared &&
                               noRemainingMounts &&
                               unmountProofs.All(static result =>
                                   result.Success && result.MountRemoved && result.PendingDurabilityCleared);
        var shutdownProven = ownershipProven && durabilityProven;
        var cancelled = cancellationToken.IsCancellationRequested;
        var success = !cancelled && markerWritten && shutdownProven;
        var diagnostic = AppendDiagnostic(
            AppendDiagnostic(markerDiagnostic, shutdown.Diagnostic),
            finalProbe.Diagnostic);
        if (cancelled)
        {
            diagnostic = AppendDiagnostic(
                diagnostic,
                "The operation was cancelled after shutdown started; final state was reconciled independently.");
        }
        if (!shutdownProven)
        {
            diagnostic = AppendDiagnostic(
                diagnostic,
                "Shutdown did not prove cleanup, host ownership release, durability clearance, and zero remaining mounts.");
        }

        return BuildResult(
            request,
            requestedAtUtc,
            startedAtUtc,
            success,
            cancelled
                ? ApfsOperationCodes.OperationCancelled
                : success
                ? ApfsOperationCodes.OperationSucceeded
                : markerWritten ? ApfsOperationCodes.UnsafeOwnership : ApfsOperationCodes.OperationFailed,
            finalStatus: !finalProbe.Succeeded
                ? "not-proven"
                : noRemainingMounts && shutdown.CleanupCompleted
                    ? "shutdown-complete"
                    : "shutdown-incomplete",
            recoveryState: GetRecoveryState(finalMounts),
            recoveryActive: finalMounts.Any(static mount => mount.RecoveryActive),
            dirtyTransactionCount: finalMounts.Sum(static mount => mount.DirtyTransactionCount),
            pendingDurability: finalMounts.Any(HasPendingDurability),
            mountProof: !finalProbe.Succeeded ? "not-proven" : noRemainingMounts ? "no-mounts" : "present",
            ownershipProof: ownershipProven ? "proven" : "not-proven",
            durabilityProof: durabilityProven ? "proven" : "not-proven",
            diagnostic: diagnostic,
            quitMarkerWritten: markerWritten,
            state: cancelled ? ApfsOperationStates.Cancelled : null);
    }

    private async Task<OperationResultPayload> ExecuteSnapshotControlAsync(
        ControlOperationRequestPayload request,
        DateTime requestedAtUtc,
        DateTime startedAtUtc,
        SnapshotControlAction action,
        string successStatus,
        CancellationToken cancellationToken)
    {
        IReadOnlyList<string>? extraLines = action switch
        {
            SnapshotControlAction.Create => request.SnapshotName is {} name ? new[] { name } : null,
            SnapshotControlAction.Delete => request.SnapshotIdentity,
            _ => null,
        };
        if (!SnapshotControlParametersValid(action, request.SnapshotName, request.SnapshotIdentity))
        {
            return BuildResult(
                request,
                requestedAtUtc,
                startedAtUtc,
                success: false,
                code: ApfsOperationCodes.InvalidArguments,
                finalStatus: "invalid",
                diagnostic: action switch
                {
                    SnapshotControlAction.Create => "Snapshot create requires exactly one valid name and no identity.",
                    SnapshotControlAction.Delete => "Snapshot delete requires the nine-line exact identity and no separate name.",
                    _ => "Snapshot recover carries no snapshot parameters.",
                });
        }

        var resolution = await ResolveTargetAsync(request.Target, cancellationToken).ConfigureAwait(false);
        if (!resolution.IsValid || resolution.Volume is null)
        {
            return BuildResult(
                request,
                requestedAtUtc,
                startedAtUtc,
                success: false,
                code: resolution.Code,
                finalStatus: "invalid",
                diagnostic: resolution.Diagnostic);
        }

        // Identity binding comes from the live inventory row, never from
        // caller-supplied UUIDs: the backend addresses the owner by stable
        // container UUID and volume object ID, and the host re-verifies
        // journal ownership, census currency, and exact snapshot identity.
        var containerUuid = resolution.Volume.CatalogContainerUuid;
        var volumeObjectId = resolution.Volume.CatalogVolumeObjectId ?? 0;
        if (string.IsNullOrWhiteSpace(containerUuid) || volumeObjectId == 0)
        {
            return BuildResult(
                request,
                requestedAtUtc,
                startedAtUtc,
                success: false,
                code: ApfsOperationCodes.InvalidArguments,
                finalStatus: "invalid",
                diagnostic: "Snapshot control requires live container identity (container UUID and volume object ID); the selected volume is not container-identified.");
        }

        var mountProbe = await ProbeAuthoritativeMountStateAsync().ConfigureAwait(false);
        var exactMounts = mountProbe.Succeeded
            ? FindExactMounts(mountProbe.Mounts, request.Target)
            : Array.Empty<MountedVolumeState>();
        var mountProof = exactMounts.Count == 1 ? "present" : "absent";
        if (exactMounts.Count != 1)
        {
            return BuildResult(
                request,
                requestedAtUtc,
                startedAtUtc,
                success: false,
                code: ApfsOperationCodes.ServiceUnavailable,
                finalStatus: "invalid",
                mountProof: mountProof,
                ownershipProof: "not-proven",
                durabilityProof: "not-applicable",
                diagnostic: "Snapshot control requires the exact volume session to be mounted; the live owner session is unavailable.");
        }

        SnapshotControlResult control;
        if (action == SnapshotControlAction.Recover ? !exactMounts[0].SnapshotRecoverySupported : !exactMounts[0].SnapshotMutationSupported)
            return BuildResult(request, requestedAtUtc, startedAtUtc, false, ApfsOperationCodes.ServiceUnavailable,
                "unavailable", mountProof: "present", ownershipProof: "not-proven", durabilityProof: "not-applicable",
                diagnostic: action == SnapshotControlAction.Recover
                    ? "SnapshotRuntimeOwnerNotReady: The exact owner does not advertise snapshot recovery support."
                    : "SnapshotRuntimeOwnerNotReady: The exact owner does not advertise snapshot mutation support.");
        try
        {
            control = await _worker.SendSnapshotControlAsync(
                    containerUuid,
                    volumeObjectId,
                    action,
                    extraLines,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return BuildResult(
                request,
                requestedAtUtc,
                startedAtUtc,
                success: false,
                code: ApfsOperationCodes.OperationCancelled,
                finalStatus: "not-proven",
                diagnostic: "The snapshot operation was cancelled before the live owner returned terminal evidence.",
                state: ApfsOperationStates.Cancelled);
        }

        if (control.Success)
        {
            var expected = action switch
            {
                SnapshotControlAction.Create => control.Code == "SnapshotCreated",
                SnapshotControlAction.Delete => control.Code == "SnapshotDeleted",
                _ => control.Code is "SnapshotRecovered" or "SnapshotRecoverNoOp",
            };
            if (expected)
            {
                return BuildResult(
                    request,
                    requestedAtUtc,
                    startedAtUtc,
                    success: true,
                    code: ApfsOperationCodes.OperationSucceeded,
                    finalStatus: control.Code == "SnapshotRecoverNoOp" ? "snapshot-recover-noop" : successStatus,
                    mountProof: "present",
                    ownershipProof: "proven",
                    durabilityProof: "not-applicable",
                    snapshotName: request.SnapshotName,
                    snapshotIdentity: request.SnapshotIdentity,
                    diagnostic: $"Live owner acknowledged {control.Code} for apfs-vol:{containerUuid}:{volumeObjectId}.");
            }

            return BuildResult(
                request,
                requestedAtUtc,
                startedAtUtc,
                success: false,
                code: ApfsOperationCodes.OperationFailed,
                finalStatus: "failed",
                mountProof: "present",
                ownershipProof: "not-proven",
                durabilityProof: "not-applicable",
                diagnostic: $"Live owner returned an unexpected snapshot acknowledgement '{control.Code}'.");
        }

        var mapped = control.Code switch
        {
            "ControlEndpointUnavailable" or "VolumeNotPredeclared" => ApfsOperationCodes.ServiceUnavailable,
            "ControlResponseTimeout" or "ControlCanceledAfterPublish" => ApfsOperationCodes.Timeout,
            "SnapshotMaintenanceOwnerNotReady" or "SnapshotRuntimeOwnerNotReady" or
            "SnapshotSessionNotWritable" or "SnapshotSessionNotReady" or
            "SnapshotJournalNotCurrent" or "SnapshotMaintenanceJournalBusy" or
            "SnapshotMaintenanceAcceptedDebt" => ApfsOperationCodes.BlockedRecovery,
            _ => ApfsOperationCodes.OperationFailed,
        };
        if (mapped == ApfsOperationCodes.Timeout)
        {
            // Timeout and cancel-after-publish share the ambiguity: the owner
            // may already have committed. Report unknown completion with
            // pending durability assumed, never a terminal failure that would
            // mask a durable success (a retry then meets the created
            // snapshot instead of silently duplicating it).
            return BuildResult(
                request,
                requestedAtUtc,
                startedAtUtc,
                success: false,
                code: mapped,
                finalStatus: "not-proven",
                pendingDurability: true,
                mountProof: "not-proven",
                ownershipProof: "not-proven",
                durabilityProof: "not-proven",
                diagnostic: $"Snapshot {action} timed out waiting for the live owner; completion is unknown and pending durability is assumed.");
        }

        return BuildResult(
            request,
            requestedAtUtc,
            startedAtUtc,
            success: false,
            code: mapped,
            finalStatus: "failed",
            mountProof: mountProof,
            ownershipProof: "not-proven",
            durabilityProof: "not-applicable",
            diagnostic: $"Live owner refused snapshot {action}: {control.Code}.");
    }

    // Mirrors the wire validators in ContainerControlChannel and
    // PipeMessageCodec: anything the host would refuse is rejected here with
    // an InvalidArguments code before any owner is contacted.
    private static bool SnapshotControlParametersValid(
        SnapshotControlAction action,
        string? snapshotName,
        IReadOnlyList<string>? snapshotIdentity)
        => action switch
        {
            SnapshotControlAction.Create =>
                IsSnapshotControlName(snapshotName) && snapshotIdentity is not { Count: > 0 },
            SnapshotControlAction.Delete =>
                snapshotName is null && IsSnapshotControlIdentity(snapshotIdentity),
            _ => snapshotName is null && snapshotIdentity is not { Count: > 0 },
        };

    private static bool IsSnapshotControlName(string? value)
        => value is not null && value.Length is > 0 and <= 255 &&
            value.All(static ch => ch != '\0' && ch != '\r' && ch != '\n');

    private static bool IsSnapshotControlIdentity(IReadOnlyList<string>? identity)
    {
        if (identity is not { Count: 9 } || !IsSnapshotControlName(identity[1]))
        {
            return false;
        }

        foreach (var index in new[] { 0, 2, 3, 4, 5, 6, 7, 8 })
        {
            var text = identity[index];
            if (string.IsNullOrEmpty(text) ||
                !ulong.TryParse(
                    text,
                    System.Globalization.NumberStyles.None,
                    System.Globalization.CultureInfo.InvariantCulture,
                    out var parsed) ||
                parsed == 0 ||
                parsed.ToString(System.Globalization.CultureInfo.InvariantCulture) != text)
            {
                return false;
            }
        }

        return true;
    }

    private async Task<TargetResolution> ResolveTargetAsync(
        ApfsControlTarget? target,
        CancellationToken cancellationToken)
    {
        if (target is null ||
            string.IsNullOrWhiteSpace(target.DeviceId) ||
            string.IsNullOrWhiteSpace(target.VolumeId))
        {
            return TargetResolution.Invalid(
                ApfsOperationCodes.InvalidArguments,
                "A non-empty DeviceId and VolumeId are required.");
        }

        var inventory = await _worker.GetInventoryAsync(cancellationToken).ConfigureAwait(false);
        var matchingDevices = inventory
            .Where(item => string.Equals(item.Device.DeviceId, target.DeviceId, StringComparison.OrdinalIgnoreCase))
            .ToArray();
        var allVolumeMatches = inventory
            .SelectMany(item => item.Volumes)
            .Where(volume => string.Equals(volume.VolumeId, target.VolumeId, StringComparison.OrdinalIgnoreCase))
            .ToArray();
        var exactMatches = matchingDevices
            .SelectMany(item => item.Volumes)
            .Where(volume =>
                string.Equals(volume.VolumeId, target.VolumeId, StringComparison.OrdinalIgnoreCase) &&
                string.Equals(volume.DeviceId, target.DeviceId, StringComparison.OrdinalIgnoreCase) &&
                RecoveryIdentityMatches(volume.RecoveryIdentity, target.RecoveryIdentity))
            .ToArray();

        if (matchingDevices.Length != 1 || exactMatches.Length != 1)
        {
            var code = allVolumeMatches.Length == 0
                ? ApfsOperationCodes.MissingVolume
                : ApfsOperationCodes.AmbiguousTarget;
            var detail = matchingDevices.Length == 0
                ? $"Device '{target.DeviceId}' is not connected."
                : $"Volume '{target.VolumeId}' is not uniquely associated with device '{target.DeviceId}'.";
            return TargetResolution.Invalid(code, detail);
        }

        if (!SelectedControlTarget.Matches(inventory, target))
            return TargetResolution.Invalid(ApfsOperationCodes.AmbiguousTarget, "Selected identity or topology observation is stale, conflicting or unavailable; mutation was not attempted.");
        return TargetResolution.Valid(exactMatches[0], matchingDevices[0]);
    }

    private static IReadOnlyList<MountedVolumeState> FindExactMounts(
        IReadOnlyList<MountedVolumeState> mounts,
        ApfsControlTarget? target)
        => target is null
            ? Array.Empty<MountedVolumeState>()
            : mounts
                .Where(mount =>
                    string.Equals(mount.DeviceId, target.DeviceId, StringComparison.OrdinalIgnoreCase) &&
                    string.Equals(mount.VolumeId, target.VolumeId, StringComparison.OrdinalIgnoreCase) &&
                    SelectedControlTarget.MatchesMount(target, mount))
                .ToArray();

    private static bool RecoveryIdentityMatches(string? actual, string? requested)
        => requested is null || string.Equals(actual, requested, StringComparison.Ordinal);

    private OperationResultPayload BuildResult(
        ControlOperationRequestPayload request,
        DateTime requestedAtUtc,
        DateTime startedAtUtc,
        bool success,
        string code,
        string finalStatus,
        string? requestedMode = null,
        string? effectiveMode = null,
        string? recoveryState = null,
        bool recoveryActive = false,
        int dirtyTransactionCount = 0,
        bool pendingDurability = false,
        string? mountProof = null,
        string? ownershipProof = null,
        string? durabilityProof = null,
        string? diagnostic = null,
        bool quitMarkerWritten = false,
        string? state = null,
        string? snapshotName = null,
        IReadOnlyList<string>? snapshotIdentity = null,
        string? managementOperation = null,
        string? managementPlanId = null,
        string? managementToken = null,
        string? managementObservedXid = null,
        string? managementName = null,
        string? managementQuotaBytes = null,
        string? managementReserveBytes = null,
        string? managementImagePath = null)
        => new(
            OperationId: request.OperationId,
            Command: request.Command,
            Target: request.Target,
            Fingerprint: TryParseRequestedMode(requestedMode, out _)
                ? ApfsOperationFingerprint.Compute(request with { RequestedMode = requestedMode })
                : null,
            State: state ?? (success ? ApfsOperationStates.Succeeded : ApfsOperationStates.Failed),
            Code: code,
            Success: success,
            RequestedAtUtc: requestedAtUtc,
            StartedAtUtc: startedAtUtc,
            CompletedAtUtc: _timeProvider.GetUtcNow().UtcDateTime,
            FinalStatus: finalStatus,
            RequestedMode: requestedMode,
            EffectiveMode: effectiveMode,
            RecoveryState: recoveryState,
            RecoveryActive: recoveryActive,
            DirtyTransactionCount: dirtyTransactionCount,
            PendingDurability: pendingDurability,
            MountProof: mountProof,
            OwnershipProof: ownershipProof,
            DurabilityProof: durabilityProof,
            Diagnostic: diagnostic,
            QuitMarkerWritten: quitMarkerWritten,
            ExpiresAtUtc: request.ExpiresAtUtc,
            SnapshotName: snapshotName,
            SnapshotIdentity: snapshotIdentity,
            ManagementOperation: managementOperation,
            ManagementPlanId: managementPlanId,
            ManagementToken: managementToken,
            ManagementObservedXid: managementObservedXid,
            ManagementName: managementName,
            ManagementQuotaBytes: managementQuotaBytes,
            ManagementReserveBytes: managementReserveBytes,
            ManagementImagePath: managementImagePath, VolumeManagement: request.VolumeManagement,
            ApprovedImageRepairPlanId: request.ApprovedImageRepairPlanId, KeyManagement: request.KeyManagement);

    private async Task<AuthoritativeMountProbe> ProbeAuthoritativeMountStateAsync()
    {
        using var probeCts = new CancellationTokenSource(AuthoritativeProbeTimeout);
        try
        {
            var mounts = await _worker
                .GetAuthoritativeMountStateAsync(probeCts.Token)
                .ConfigureAwait(false);
            return new AuthoritativeMountProbe(true, mounts, null);
        }
        catch (OperationCanceledException) when (probeCts.IsCancellationRequested)
        {
            return new AuthoritativeMountProbe(
                false,
                Array.Empty<MountedVolumeState>(),
                $"Authoritative mount-state reconciliation timed out after {AuthoritativeProbeTimeout.TotalSeconds:n0} seconds.");
        }
        catch (Exception ex)
        {
            return new AuthoritativeMountProbe(
                false,
                Array.Empty<MountedVolumeState>(),
                $"Authoritative mount-state reconciliation failed: {ex.Message}");
        }
    }

    private static bool TryParseRequestedMode(string? requestedMode, out MountAccessMode? mode)
    {
        if (string.IsNullOrWhiteSpace(requestedMode))
        {
            mode = null;
            return true;
        }

        if (string.Equals(requestedMode, ApfsControlModes.ReadOnly, StringComparison.OrdinalIgnoreCase))
        {
            mode = MountAccessMode.ReadOnly;
            return true;
        }

        if (string.Equals(requestedMode, ApfsControlModes.ReadWrite, StringComparison.OrdinalIgnoreCase))
        {
            mode = MountAccessMode.ReadWrite;
            return true;
        }

        mode = null;
        return false;
    }

    private static string? ToControlMode(MountAccessMode? mode)
        => mode switch
        {
            MountAccessMode.ReadOnly => ApfsControlModes.ReadOnly,
            MountAccessMode.ReadWrite => ApfsControlModes.ReadWrite,
            _ => null,
        };

    private static string? GetRecoveryState(MountedVolumeState? mount)
        => mount is null ? null : mount.RecoveryActive ? "active" : "inactive";

    private static string? GetRecoveryState(IReadOnlyList<MountedVolumeState> mounts)
        => mounts.Count == 0
            ? "inactive"
            : mounts.Any(static mount => mount.RecoveryActive) ? "active" : "inactive";

    private static bool HasPendingDurability(MountedVolumeState? mount)
        => mount is not null &&
           (mount.DirtyTransactionCount > 0 ||
            mount.ShutdownDrainActive ||
            mount.InFlightMutationCallbacks > 0 ||
            mount.RuntimeWatermarksKnown == false ||
            mount.RuntimeMutationPending ||
            mount.WalAcceptedSequence != mount.WalApfsDurableSequence ||
            mount.WalApfsDurableSequence != mount.WalCleanupSequence);

    private static string GetFinalStatus(MountedVolumeState? mount)
    {
        if (mount is null)
        {
            return "absent";
        }

        if (mount.AccessMode == MountAccessMode.ReadWrite &&
            !mount.RecoveryActive &&
            !HasPendingDurability(mount) &&
            (mount.RuntimeWatermarksKnown is null || mount.MountReady) &&
            mount.NativeWriteSafetyState is NativeWriteSafetyState.PilotReadWrite or NativeWriteSafetyState.StableReadWrite)
        {
            return "healthy-rw";
        }

        return mount.RecoveryActive ||
               mount.NativeWriteSafetyState is NativeWriteSafetyState.ReadOnlyFallback or NativeWriteSafetyState.RecoveryBlocked
            ? "degraded"
            : mount.AccessMode == MountAccessMode.ReadWrite ? "mounted-rw" : "mounted-ro";
    }

    private static string AppendDiagnostic(string? first, string? second)
        => string.Join(
            " ",
            new[] { first, second }.Where(static value => !string.IsNullOrWhiteSpace(value)));

    private sealed record AuthoritativeMountProbe(
        bool Succeeded,
        IReadOnlyList<MountedVolumeState> Mounts,
        string? Diagnostic);

    private sealed record TargetResolution(bool IsValid, VolumeInfo? Volume, DeviceInventory? Inventory, string Code, string? Diagnostic)
    {
        public static TargetResolution Valid(VolumeInfo volume, DeviceInventory inventory)
            => new(true, volume, inventory, ApfsOperationCodes.OperationSucceeded, null);

        public static TargetResolution Invalid(string code, string diagnostic)
            => new(false, null, null, code, diagnostic);
    }
}
