using ApfsAccess.Core;
using ApfsAccess.Ipc;

namespace ApfsAccess.Service;

public sealed class AgentControlCommandExecutor
{
    private static readonly TimeSpan AuthoritativeProbeTimeout = TimeSpan.FromSeconds(2);
    private readonly ApfsMountWorker _worker;
    private readonly Func<DateTime, bool> _quitMarkerWriter;
    private readonly TimeProvider _timeProvider;

    public AgentControlCommandExecutor(
        ApfsMountWorker worker,
        Func<DateTime, bool>? quitMarkerWriter = null,
        TimeProvider? timeProvider = null)
    {
        _worker = worker ?? throw new ArgumentNullException(nameof(worker));
        _quitMarkerWriter = quitMarkerWriter ?? (timestampUtc => QuitRequestMarker.WriteMarker(timestampUtc));
        _timeProvider = timeProvider ?? TimeProvider.System;
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
            if (string.Equals(request.Command, ApfsControlCommands.Mount, StringComparison.OrdinalIgnoreCase))
            {
                return await ExecuteMountAsync(request, requestedAtUtc, startedAtUtc, cancellationToken)
                    .ConfigureAwait(false);
            }

            if (string.Equals(request.Command, ApfsControlCommands.Fix, StringComparison.OrdinalIgnoreCase))
            {
                return await ExecuteFixAsync(request, requestedAtUtc, startedAtUtc, cancellationToken)
                    .ConfigureAwait(false);
            }

            if (string.Equals(request.Command, ApfsControlCommands.Eject, StringComparison.OrdinalIgnoreCase))
            {
                return await ExecuteEjectAsync(request, requestedAtUtc, startedAtUtc, cancellationToken)
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

        (bool Success, string Message) operation;
        try
        {
            operation = await _worker.EnsureMountedExactAsync(
                    request.Target!.DeviceId,
                    request.Target.VolumeId,
                    requestedMode,
                    cancellationToken,
                    request.Target.RecoveryIdentity)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            operation = (false, "The mount operation was cancelled before it returned terminal evidence.");
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
                "The requested read-write mode was not reached; the final mount is read-only.");
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
                requestedMode: ApfsControlModes.ReadWrite,
                diagnostic: resolution.Diagnostic);
        }

        (bool Success, string Message) operation;
        try
        {
            operation = await _worker.EnsureMountedExactAsync(
                    request.Target!.DeviceId,
                    request.Target.VolumeId,
                    MountAccessMode.ReadWrite,
                    cancellationToken,
                    request.Target.RecoveryIdentity)
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
                           mount.DirtyTransactionCount == 0 &&
                           !mount.ShutdownDrainActive &&
                           mount.InFlightMutationCallbacks == 0 &&
                           mount.NativeWriteSafetyState is
                               NativeWriteSafetyState.PilotReadWrite or NativeWriteSafetyState.StableReadWrite;
        var cancelled = cancellationToken.IsCancellationRequested;
        var success = !cancelled && operation.Success && healthyState;

        var diagnostic = AppendDiagnostic(operation.Message, mountProbe.Diagnostic);
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
            requestedMode: ApfsControlModes.ReadWrite,
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

    private async Task<OperationResultPayload> ExecuteEjectAsync(
        ControlOperationRequestPayload request,
        DateTime requestedAtUtc,
        DateTime startedAtUtc,
        CancellationToken cancellationToken)
    {
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
                request.Target.RecoveryIdentity)
            .ConfigureAwait(false);
        var afterProbe = await ProbeAuthoritativeMountStateAsync().ConfigureAwait(false);
        var exactAfter = afterProbe.Succeeded
            ? FindExactMounts(afterProbe.Mounts, request.Target)
            : Array.Empty<MountedVolumeState>();
        var mountAbsent = afterProbe.Succeeded && exactAfter.Count == 0;
        operation.UnmountResults.TryGetValue(request.Target.VolumeId, out var unmount);
        var ownershipProven = unmount?.HostOwnershipReleased == true;
        var durabilityProven = unmount?.PendingDurabilityCleared == true;
        var proofComplete = unmount is not null &&
                            unmount.Success &&
                            unmount.MountRemoved &&
                            ownershipProven &&
                            durabilityProven;
        var cancelled = cancellationToken.IsCancellationRequested;
        var success = !cancelled && operation.Success && mountAbsent && proofComplete;
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
                unmount?.Error ?? "Eject did not prove host ownership release and pending durability clearance.");
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
            shutdown = await _worker.PrepareForShutdownAsync(cancellationToken).ConfigureAwait(false);
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
        var ownershipProven = shutdown.CleanupCompleted &&
                              shutdown.HostOwnershipReleased &&
                              noRemainingMounts &&
                              unmountProofs.All(static result =>
                                  result.Success && result.MountRemoved && result.HostOwnershipReleased);
        var durabilityProven = shutdown.CleanupCompleted &&
                               shutdown.PendingDurabilityCleared &&
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

        return TargetResolution.Valid(exactMatches[0]);
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
                    RecoveryIdentityMatches(mount.RecoveryIdentity, target.RecoveryIdentity))
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
        string? state = null)
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
            ExpiresAtUtc: request.ExpiresAtUtc);

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
            mount.InFlightMutationCallbacks > 0);

    private static string GetFinalStatus(MountedVolumeState? mount)
    {
        if (mount is null)
        {
            return "absent";
        }

        if (mount.AccessMode == MountAccessMode.ReadWrite &&
            !mount.RecoveryActive &&
            mount.DirtyTransactionCount == 0 &&
            !mount.ShutdownDrainActive &&
            mount.InFlightMutationCallbacks == 0 &&
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

    private sealed record TargetResolution(bool IsValid, VolumeInfo? Volume, string Code, string? Diagnostic)
    {
        public static TargetResolution Valid(VolumeInfo volume)
            => new(true, volume, ApfsOperationCodes.OperationSucceeded, null);

        public static TargetResolution Invalid(string code, string diagnostic)
            => new(false, null, code, diagnostic);
    }
}
