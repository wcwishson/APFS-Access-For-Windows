using ApfsAccess.Core;
using ApfsAccess.Ipc;

namespace ApfsAccess.Service;

// Task 12 Step 5: container-wide mount/unmount fan-out. A container request
// names a device plus a container UUID (never a volume); membership and
// eligibility are resolved against live inventory in the same operation, and
// every attempted member must reach proven terminal state for the container
// operation to succeed. Per-volume proofs are reported as stable diagnostic
// tokens (`vol:<volumeId>=mounted|absent|mode-mismatch|failed pressure` and
// `skipped:<volumeId>:ineligible`); the scalar proofs describe the container
// as a whole. Members are driven through the exact per-volume worker paths,
// bound by live recovery identity; no per-volume selected-identity contract
// is minted because container members on legacy (topology-absent) backends
// carry no observation contract, and the authoritative post-probe proves
// final state instead.
public sealed partial class AgentControlCommandExecutor
{
    private async Task<OperationResultPayload> ExecuteContainerMountAsync(
        ControlOperationRequestPayload request,
        DateTime requestedAtUtc,
        DateTime startedAtUtc,
        CancellationToken cancellationToken)
    {
        if (!TryParseRequestedMode(request.RequestedMode, out var requestedMode) || !requestedMode.HasValue)
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

        var resolution = await ResolveContainerAsync(request.Target, cancellationToken).ConfigureAwait(false);
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

        var explicitReadOnly = requestedMode == MountAccessMode.ReadOnly;
        var eligible = new List<VolumeInfo>();
        var lines = new List<string>();
        foreach (var member in resolution.Members)
        {
            if (!CatalogMountPolicy.AllowsMount(member, explicitReadOnly) &&
                !(requestedMode == MountAccessMode.ReadWrite && member.SupportsNativeWrite && BackupImageMountPolicy.HasCandidate(member)))
            {
                lines.Add($"skipped:{member.VolumeId}:ineligible");
                continue;
            }

            eligible.Add(member);
        }

        if (eligible.Count == 0)
        {
            return BuildResult(
                request,
                requestedAtUtc,
                startedAtUtc,
                success: false,
                code: ApfsOperationCodes.InvalidArguments,
                finalStatus: "invalid",
                requestedMode: ToControlMode(requestedMode),
                diagnostic: AppendDiagnostic(
                    string.Join(" ", lines),
                    "The container has no mount-eligible volumes for the requested mode; nothing was attempted."));
        }

        // Idempotency fast path: every eligible member already mounted in the
        // requested mode. (Suppressed-but-mounted bypasses are reaped by the
        // worker's enforcement cycle; an explicit mount here also clears
        // suppression below whenever work remains.)
        var current = await ProbeAuthoritativeMountStateAsync().ConfigureAwait(false);
        var (settled, verified) = VerifyContainerMounts(current, request.Target!.DeviceId, eligible, requestedMode.Value);
        if (settled)
        {
            return BuildContainerMountedResult(request, requestedAtUtc, startedAtUtc, requestedMode.Value, verified, lines);
        }

        // Reset to a clean slate, then schedule an explicit container batch to
        // launch one joint owner: per-volume fan-out cannot join a live
        // single-volume owner (the backend refuses second raw owners), so
        // partial states must be rebuilt, never patched. Eject first (dissolves
        // any single-volume owner), clear suppression for the eligible set,
        // use the requested mode, and poll for convergence.
        EjectOperationResult eject;
        try
        {
            eject = await _worker.EjectContainerAsync(
                    request.Target!.DeviceId,
                    request.Target.ContainerUuid!,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return BuildCancelledResult(request, requestedAtUtc, startedAtUtc, requestedMode.Value, lines,
                "The container mount was cancelled while resetting to a clean slate.");
        }

        try
        {
            if (!eject.Success)
                return BuildResult(request, requestedAtUtc, startedAtUtc, false,
                    ApfsOperationCodes.UnsafeOwnership, "not-proven",
                    requestedMode: ToControlMode(requestedMode), diagnostic: eject.Message);
            var scheduled = await _worker.MountContainerAsync(
                    request.Target!.DeviceId,
                    request.Target.ContainerUuid!,
                    eligible,
                    requestedMode.Value,
                    cancellationToken)
                .ConfigureAwait(false);
            if (!scheduled.Success)
                return BuildResult(request, requestedAtUtc, startedAtUtc, false,
                    ApfsOperationCodes.OperationFailed, "not-proven",
                    requestedMode: ToControlMode(requestedMode), diagnostic: scheduled.Message);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return BuildCancelledResult(request, requestedAtUtc, startedAtUtc, requestedMode.Value, lines,
                "The container mount was cancelled while scheduling the selected members.");
        }

        var pollDeadline = DateTime.UtcNow.AddSeconds(120);
        if (request.ExpiresAtUtc.HasValue && request.ExpiresAtUtc.Value < pollDeadline)
        {
            pollDeadline = request.ExpiresAtUtc.Value;
        }

        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var probe = await ProbeAuthoritativeMountStateAsync().ConfigureAwait(false);
            var (converged, observed) = VerifyContainerMounts(probe, request.Target!.DeviceId, eligible, requestedMode.Value);
            if (converged)
            {
                return BuildContainerMountedResult(request, requestedAtUtc, startedAtUtc, requestedMode.Value, observed, lines);
            }

            if (DateTime.UtcNow >= pollDeadline)
            {
                var diagnostic = AppendDiagnostic(string.Join(" ", observed), probe.Diagnostic);
                diagnostic = AppendDiagnostic(diagnostic, string.Join(" ", lines.Where(static line =>
                    line.StartsWith("skipped:", StringComparison.Ordinal))));
                diagnostic = AppendDiagnostic(diagnostic, eject.Message);
                diagnostic = AppendDiagnostic(diagnostic,
                    "The container did not converge to all members mounted in the requested mode before the deadline; retry to reconcile (already-converged members succeed immediately).");
                return BuildResult(
                    request,
                    requestedAtUtc,
                    startedAtUtc,
                    success: false,
                    code: ApfsOperationCodes.Timeout,
                    finalStatus: "not-proven",
                    requestedMode: ToControlMode(requestedMode),
                    pendingDurability: true,
                    mountProof: "not-proven",
                    ownershipProof: "not-proven",
                    durabilityProof: "not-proven",
                    diagnostic: diagnostic);
            }

            try
            {
                await Task.Delay(2000, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                return BuildCancelledResult(request, requestedAtUtc, startedAtUtc, requestedMode.Value, lines,
                    "The container mount was cancelled while waiting for convergence.");
            }
        }
    }

    private static (bool Settled, List<string> Verified) VerifyContainerMounts(
        AuthoritativeMountProbe probe,
        string deviceId,
        IReadOnlyList<VolumeInfo> eligible,
        MountAccessMode requestedMode)
    {
        var verified = new List<string>();
        var proven = 0;
        foreach (var member in eligible)
        {
            var matches = probe.Succeeded
                ? FindExactMounts(probe.Mounts, new ApfsControlTarget(
                    deviceId, member.VolumeId, member.RecoveryIdentity))
                : Array.Empty<MountedVolumeState>();
            var mount = matches.Count == 1 ? matches[0] : null;
            var ok = mount is not null && mount.AccessMode == requestedMode;
            if (ok) proven++;
            verified.Add($"vol:{member.VolumeId}={(ok ? "mounted" : mount is null ? "absent" : "mode-mismatch")}");
        }

        return (probe.Succeeded && eligible.Count > 0 && proven == eligible.Count, verified);
    }

    private OperationResultPayload BuildContainerMountedResult(
        ControlOperationRequestPayload request,
        DateTime requestedAtUtc,
        DateTime startedAtUtc,
        MountAccessMode requestedMode,
        List<string> verified,
        List<string> lines)
    {
        var diagnostic = AppendDiagnostic(string.Join(" ", verified), null);
        diagnostic = AppendDiagnostic(
            diagnostic,
            string.Join(" ", lines.Where(static line =>
                line.StartsWith("skipped:", StringComparison.Ordinal))));
        return BuildResult(
            request,
            requestedAtUtc,
            startedAtUtc,
            success: true,
            code: ApfsOperationCodes.OperationSucceeded,
            finalStatus: "container-mounted",
            requestedMode: ToControlMode(requestedMode),
            effectiveMode: ToControlMode(requestedMode),
            mountProof: "present",
            ownershipProof: "not-applicable",
            durabilityProof: "not-applicable",
            diagnostic: diagnostic);
    }

    private OperationResultPayload BuildCancelledResult(
        ControlOperationRequestPayload request,
        DateTime requestedAtUtc,
        DateTime startedAtUtc,
        MountAccessMode requestedMode,
        List<string> lines,
        string reason)
    {
        return BuildResult(
            request,
            requestedAtUtc,
            startedAtUtc,
            success: false,
            code: ApfsOperationCodes.OperationCancelled,
            finalStatus: "not-proven",
            requestedMode: ToControlMode(requestedMode),
            diagnostic: AppendDiagnostic(string.Join(" ", lines), reason),
            state: ApfsOperationStates.Cancelled);
    }

    private async Task<OperationResultPayload> ExecuteContainerUnmountAsync(
        ControlOperationRequestPayload request,
        DateTime requestedAtUtc,
        DateTime startedAtUtc,
        CancellationToken cancellationToken)
    {
        var resolution = await ResolveContainerAsync(request.Target, cancellationToken).ConfigureAwait(false);
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

        // One worker-scope batch detaches every mounted member and then lets
        // the backend stop the shared host once it is empty. Fanning out over
        // per-volume eject instead would leave every non-last member in an
        // unprovable state (mount gone, host necessarily alive for siblings).
        var before = await ProbeAuthoritativeMountStateAsync().ConfigureAwait(false);
        var memberIds = resolution.Members
            .Select(static member => member.VolumeId)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var mountedBefore = before.Succeeded
            ? before.Mounts.Where(mount =>
                string.Equals(mount.DeviceId, request.Target!.DeviceId, StringComparison.OrdinalIgnoreCase) &&
                mount.VolumeId is not null && memberIds.Contains(mount.VolumeId)).ToArray()
            : [];
        if (before.Succeeded && mountedBefore.Length == 0)
        {
            return BuildResult(
                request,
                requestedAtUtc,
                startedAtUtc,
                success: true,
                code: ApfsOperationCodes.AlreadyAchieved,
                finalStatus: "container-unmounted",
                mountProof: "absent",
                ownershipProof: "not-proven",
                durabilityProof: "not-proven",
                diagnostic: "No member of the exact APFS container is currently mounted.");
        }

        SingleContainerUnmount outcome;
        try
        {
            outcome = await UnmountSingleContainerAsync(
                    request.Target!.DeviceId,
                    request.Target.ContainerUuid!,
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
                mountProof: "not-proven",
                ownershipProof: "not-proven",
                durabilityProof: "not-proven",
                diagnostic: "The container unmount was cancelled before all members returned terminal evidence.",
                state: ApfsOperationStates.Cancelled);
        }

        if (!outcome.AttemptedAny)
        {
            return BuildResult(
                request,
                requestedAtUtc,
                startedAtUtc,
                success: outcome.WorkerSuccess,
                code: outcome.WorkerSuccess ? ApfsOperationCodes.AlreadyAchieved : ApfsOperationCodes.OperationFailed,
                finalStatus: outcome.WorkerSuccess ? "container-unmounted" : "failed",
                mountProof: outcome.WorkerSuccess ? "absent" : "not-proven",
                ownershipProof: "not-proven",
                durabilityProof: "not-proven",
                diagnostic: outcome.WorkerMessage);
        }

        var lines = outcome.Lines;
        var detached = outcome.Detached;
        var exitWitnessed = outcome.ExitWitnessed;
        var operationMessage = outcome.WorkerMessage;
        var operationSuccess = outcome.WorkerSuccess;
        var afterProbe = await ProbeAuthoritativeMountStateAsync().ConfigureAwait(false);
        var remaining = afterProbe.Succeeded
            ? afterProbe.Mounts.Count(mount =>
                string.Equals(mount.DeviceId, request.Target!.DeviceId, StringComparison.OrdinalIgnoreCase) &&
                mount.VolumeId is not null && memberIds.Contains(mount.VolumeId))
            : -1;
        var cancelled = cancellationToken.IsCancellationRequested;
        var success = !cancelled && operationSuccess && detached && exitWitnessed &&
            afterProbe.Succeeded && remaining == 0;
        var diagnostic = AppendDiagnostic(string.Join(" ", lines), afterProbe.Diagnostic);
        diagnostic = AppendDiagnostic(diagnostic, operationMessage);
        if (afterProbe.Succeeded && remaining > 0)
        {
            diagnostic = AppendDiagnostic(diagnostic, $"{remaining} member(s) are still present after unmount.");
        }
        if (!detached)
        {
            diagnostic = AppendDiagnostic(diagnostic, "Not every attempted member detached quiesced.");
        }
        else if (!exitWitnessed)
        {
            diagnostic = AppendDiagnostic(diagnostic, "No attempted member witnessed shared host exit; ownership stays unproven.");
        }

        return BuildResult(
            request,
            requestedAtUtc,
            startedAtUtc,
            success,
            cancelled
                ? ApfsOperationCodes.OperationCancelled
                : success ? ApfsOperationCodes.OperationSucceeded : ApfsOperationCodes.UnsafeOwnership,
            finalStatus: !afterProbe.Succeeded ? "not-proven" : success ? "container-unmounted" : "failed",
            mountProof: !afterProbe.Succeeded ? "not-proven" : remaining == 0 ? "absent" : "present",
            ownershipProof: success ? "proven" : "not-proven",
            durabilityProof: success ? "proven" : "not-proven",
            diagnostic: diagnostic,
            state: cancelled ? ApfsOperationStates.Cancelled : null);
    }

    private async Task<OperationResultPayload> ExecuteDeviceEjectAsync(
        ControlOperationRequestPayload request,
        DateTime requestedAtUtc,
        DateTime startedAtUtc,
        CancellationToken cancellationToken)
    {
        if (request.Target is null || string.IsNullOrWhiteSpace(request.Target.DeviceId) ||
            !string.IsNullOrWhiteSpace(request.Target.ContainerUuid) ||
            !string.IsNullOrWhiteSpace(request.Target.VolumeId))
        {
            return BuildResult(
                request,
                requestedAtUtc,
                startedAtUtc,
                success: false,
                code: ApfsOperationCodes.AmbiguousTarget,
                finalStatus: "invalid",
                diagnostic: "Device eject requires a nonblank device with no container or volume ID.");
        }

        var inventory = await _worker.GetInventoryAsync(cancellationToken).ConfigureAwait(false);
        var devices = inventory
            .Where(item => item?.Device is not null &&
                string.Equals(item.Device.DeviceId, request.Target.DeviceId, StringComparison.OrdinalIgnoreCase))
            .ToArray();
        if (devices.Length != 1 || !TopologyAdmission.Validate(devices[0]))
        {
            return BuildResult(
                request,
                requestedAtUtc,
                startedAtUtc,
                success: false,
                code: devices.Length == 0 ? ApfsOperationCodes.MissingVolume : ApfsOperationCodes.AmbiguousTarget,
                finalStatus: "invalid",
                diagnostic: devices.Length == 0
                    ? $"Device '{request.Target.DeviceId}' is not connected."
                    : "Device topology evidence is malformed or contradictory; mutation was not attempted.");
        }

        var containers = devices[0].Volumes
            .Where(static volume => volume is not null && !string.IsNullOrWhiteSpace(volume.CatalogContainerUuid))
            .Select(static volume => volume.CatalogContainerUuid!)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        var before = await ProbeAuthoritativeMountStateAsync().ConfigureAwait(false);
        var deviceMounts = before.Succeeded
            ? before.Mounts.Where(mount =>
                string.Equals(mount.DeviceId, request.Target.DeviceId, StringComparison.OrdinalIgnoreCase)).ToArray()
            : [];
        if (before.Succeeded && deviceMounts.Length == 0)
        {
            return BuildResult(
                request,
                requestedAtUtc,
                startedAtUtc,
                success: true,
                code: ApfsOperationCodes.AlreadyAchieved,
                finalStatus: "device-ejected",
                mountProof: "absent",
                ownershipProof: "not-proven",
                durabilityProof: "not-proven",
                diagnostic: "No volume on the exact device is currently mounted.");
        }

        // Mounted but unattributed volumes cannot be addressed by any
        // container batch: fail closed and name them for per-volume eject.
        var unattributed = deviceMounts
            .Where(mount => mount.VolumeId is null ||
                !devices[0].Volumes.Any(volume =>
                    string.Equals(volume.VolumeId, mount.VolumeId, StringComparison.OrdinalIgnoreCase) &&
                    !string.IsNullOrWhiteSpace(volume.CatalogContainerUuid)))
            .Select(static mount => mount.VolumeId ?? mount.MountPoint)
            .ToArray();
        if (unattributed.Length > 0)
        {
            return BuildResult(
                request,
                requestedAtUtc,
                startedAtUtc,
                success: false,
                code: ApfsOperationCodes.AmbiguousTarget,
                finalStatus: "invalid",
                mountProof: "present",
                ownershipProof: "not-proven",
                durabilityProof: "not-proven",
                diagnostic: $"Device eject cannot address mounted volumes without container identity: {string.Join(", ", unattributed)}. Eject them by exact volume first.");
        }

        var lines = new List<string>();
        var detached = true;
        var exitWitnessed = false;
        var workerSuccess = true;
        var workerMessages = new List<string>();
        var attemptedAny = false;
        try
        {
            foreach (var containerUuid in containers)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var outcome = await UnmountSingleContainerAsync(
                        request.Target.DeviceId,
                        containerUuid,
                        cancellationToken)
                    .ConfigureAwait(false);
                if (!outcome.AttemptedAny)
                {
                    continue;
                }

                attemptedAny = true;
                lines.AddRange(outcome.Lines.Select(line => $"[{containerUuid}]{line}"));
                detached = detached && outcome.Detached;
                exitWitnessed = exitWitnessed || outcome.ExitWitnessed;
                workerSuccess = workerSuccess && outcome.WorkerSuccess;
                workerMessages.Add(outcome.WorkerMessage);
            }
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
                mountProof: "not-proven",
                ownershipProof: "not-proven",
                durabilityProof: "not-proven",
                diagnostic: AppendDiagnostic(
                    string.Join(" ", lines),
                    "The device eject was cancelled before all containers returned terminal evidence."),
                state: ApfsOperationStates.Cancelled);
        }

        if (!attemptedAny)
        {
            return BuildResult(
                request,
                requestedAtUtc,
                startedAtUtc,
                success: true,
                code: ApfsOperationCodes.AlreadyAchieved,
                finalStatus: "device-ejected",
                mountProof: "absent",
                ownershipProof: "not-proven",
                durabilityProof: "not-proven",
                diagnostic: "No member of any container on the exact device is currently mounted.");
        }

        var afterProbe = await ProbeAuthoritativeMountStateAsync().ConfigureAwait(false);
        var remaining = afterProbe.Succeeded
            ? afterProbe.Mounts.Count(mount =>
                string.Equals(mount.DeviceId, request.Target.DeviceId, StringComparison.OrdinalIgnoreCase))
            : -1;
        var cancelled = cancellationToken.IsCancellationRequested;
        var success = !cancelled && workerSuccess && detached && exitWitnessed &&
            afterProbe.Succeeded && remaining == 0;
        var diagnostic = AppendDiagnostic(string.Join(" ", lines), afterProbe.Diagnostic);
        diagnostic = AppendDiagnostic(diagnostic, string.Join(" ", workerMessages));
        if (afterProbe.Succeeded && remaining > 0)
        {
            diagnostic = AppendDiagnostic(diagnostic, $"{remaining} volume(s) on the device are still present after eject.");
        }
        if (!detached)
        {
            diagnostic = AppendDiagnostic(diagnostic, "Not every attempted member detached quiesced.");
        }
        else if (!exitWitnessed)
        {
            diagnostic = AppendDiagnostic(diagnostic, "No attempted container witnessed shared host exit; ownership stays unproven.");
        }

        return BuildResult(
            request,
            requestedAtUtc,
            startedAtUtc,
            success,
            cancelled
                ? ApfsOperationCodes.OperationCancelled
                : success ? ApfsOperationCodes.OperationSucceeded : ApfsOperationCodes.UnsafeOwnership,
            finalStatus: !afterProbe.Succeeded ? "not-proven" : success ? "device-ejected" : "failed",
            mountProof: !afterProbe.Succeeded ? "not-proven" : remaining == 0 ? "absent" : "present",
            ownershipProof: success ? "proven" : "not-proven",
            durabilityProof: success ? "proven" : "not-proven",
            diagnostic: diagnostic,
            state: cancelled ? ApfsOperationStates.Cancelled : null);
    }

    private sealed record SingleContainerUnmount(
        List<string> Lines,
        bool Detached,
        bool ExitWitnessed,
        bool WorkerSuccess,
        string WorkerMessage,
        bool AttemptedAny);

    private async Task<SingleContainerUnmount> UnmountSingleContainerAsync(
        string deviceId,
        string containerUuid,
        CancellationToken cancellationToken)
    {
        var operation = await _worker.EjectContainerAsync(deviceId, containerUuid, cancellationToken).ConfigureAwait(false);
        if (operation.UnmountResults.Count == 0)
        {
            return new SingleContainerUnmount([], Detached: true, ExitWitnessed: false,
                WorkerSuccess: operation.Success, WorkerMessage: operation.Message, AttemptedAny: false);
        }

        var lines = operation.UnmountResults.Select(static entry =>
            $"vol:{entry.Key}={(entry.Value.Success && entry.Value.MountRemoved && entry.Value.PendingDurabilityCleared ? "detached" : "failed")}").ToList();
        var attempted = operation.UnmountResults.Values.ToArray();
        return new SingleContainerUnmount(
            lines,
            Detached: attempted.All(static result =>
                result.Success && result.MountRemoved && result.PendingDurabilityCleared),
            ExitWitnessed: attempted.Any(static result => result.HostOwnershipReleased),
            WorkerSuccess: operation.Success,
            WorkerMessage: operation.Message,
            AttemptedAny: true);
    }

    private async Task<ContainerResolution> ResolveContainerAsync(
        ApfsControlTarget? target,
        CancellationToken cancellationToken)
    {
        if (target is null ||
            string.IsNullOrWhiteSpace(target.DeviceId) ||
            string.IsNullOrWhiteSpace(target.ContainerUuid) ||
            !string.IsNullOrWhiteSpace(target.VolumeId))
        {
            return ContainerResolution.Invalid(
                ApfsOperationCodes.AmbiguousTarget,
                "Container mount and unmount require a nonblank device and container UUID with no volume ID.");
        }

        var inventory = await _worker.GetInventoryAsync(cancellationToken).ConfigureAwait(false);
        var devices = inventory
            .Where(item => item?.Device is not null &&
                string.Equals(item.Device.DeviceId, target.DeviceId, StringComparison.OrdinalIgnoreCase))
            .ToArray();
        if (devices.Length != 1)
        {
            return ContainerResolution.Invalid(
                devices.Length == 0 ? ApfsOperationCodes.MissingVolume : ApfsOperationCodes.AmbiguousTarget,
                devices.Length == 0
                    ? $"Device '{target.DeviceId}' is not connected."
                    : $"Device '{target.DeviceId}' is not uniquely inventoried; mutation was not attempted.");
        }

        var device = devices[0];
        if (!TopologyAdmission.Validate(device))
        {
            return ContainerResolution.Invalid(
                ApfsOperationCodes.AmbiguousTarget,
                "Container topology evidence is malformed or contradictory; mutation was not attempted.");
        }

        var members = device.Volumes
            .Where(volume => volume is not null && ApfsTopology.MatchesContainerUuid(target.ContainerUuid, volume.CatalogContainerUuid))
            .ToArray();
        if (members.Length == 0)
        {
            return ContainerResolution.Invalid(
                ApfsOperationCodes.MissingVolume,
                $"Container '{target.ContainerUuid}' has no inventoried volumes on device '{target.DeviceId}'.");
        }

        return ContainerResolution.Valid(device, members!);
    }

    private sealed record ContainerResolution(
        bool IsValid,
        DeviceInventory? Device,
        IReadOnlyList<VolumeInfo> Members,
        string Code,
        string? Diagnostic)
    {
        public static ContainerResolution Valid(DeviceInventory device, IReadOnlyList<VolumeInfo> members)
            => new(true, device, members, ApfsOperationCodes.OperationSucceeded, null);

        public static ContainerResolution Invalid(string code, string diagnostic)
            => new(false, null, Array.Empty<VolumeInfo>(), code, diagnostic);
    }
}
