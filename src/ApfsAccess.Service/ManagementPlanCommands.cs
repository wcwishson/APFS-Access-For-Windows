using ApfsAccess.Core;
using ApfsAccess.Ipc;

namespace ApfsAccess.Service;

// Task 11 Step 2 service path: verify-plan-confirm-apply for explicit
// volume management. Plans are dry-run identity+generation bindings issued
// from the live inventory row (never caller UUIDs); apply revalidates every
// field against a fresh observation and the single-use registry before any
// keeper dispatch. Quiesce rule: a live-mounted target can advance its
// checkpoint at any moment, so both plan and apply refuse mounted targets
// with quiesce-required (unmount first); probe failure fails closed.
// Keeper dispatch executes at most one planned mutation per consumed plan:
// rename and quota have keeper backends; every other operation still
// terminates at keeper-unavailable.
public sealed partial class AgentControlCommandExecutor
{
    private async Task<OperationResultPayload> ExecuteManagementPlanAsync(
        ControlOperationRequestPayload request,
        DateTime requestedAtUtc,
        DateTime startedAtUtc,
        CancellationToken cancellationToken)
    {
        if (!TryParseManagementOperation(request.ManagementOperation, out var operation))
        {
            return ManagementInvalid(request, requestedAtUtc, startedAtUtc,
                "Management plan requires exactly one supported operation.");
        }

        var resolution = await ResolveTargetAsync(request.Target, cancellationToken).ConfigureAwait(false);
        if (!resolution.IsValid || resolution.Volume is null)
        {
            return ManagementInvalid(request, requestedAtUtc, startedAtUtc,
                resolution.Diagnostic ?? "The management target is missing or ambiguous.",
                resolution.Code);
        }

        if (!TryManagementIdentity(resolution.Volume, out var containerUuid, out var volumeUuid,
            out var volumeObjectId, out var identityDiagnostic))
        {
            return ManagementInvalid(request, requestedAtUtc, startedAtUtc, identityDiagnostic ?? "Invalid management identity.");
        }

        // Task 6 Step 5: protected roles are never management targets.
        // AllowsOrdinaryMount already permits verdict-less legacy rows,
        // so no carve-out is needed here: any proven non-ordinary
        // decision — including a malformed partial row — refuses before
        // quiesce, checkpoint observation, or plan issuance.
        if (!CatalogMountPolicy.AllowsOrdinaryMount(resolution.Volume))
        {
            return ManagementInvalid(request, requestedAtUtc, startedAtUtc,
                ManagementRoleRefusal(resolution.Volume));
        }

        var quiesce = await ProbeManagementQuiesceAsync(request, resolution, requestedAtUtc, startedAtUtc, cancellationToken).ConfigureAwait(false);
        if (!quiesce.Quiesced)
        {
            return quiesce.Result!;
        }
        var verification = await VerifyManagementImageAsync(request, resolution, requestedAtUtc, startedAtUtc, cancellationToken).ConfigureAwait(false);
        if (verification is not null) return verification;

        if (!TryObserveContainerCheckpoint(resolution.Inventory, containerUuid, out var xid, out var checkpointDiagnostic))
        {
            return BuildResult(
                request, requestedAtUtc, startedAtUtc,
                success: false, code: ApfsOperationCodes.ServiceUnavailable, finalStatus: "checkpoint-unobservable",
                mountProof: "absent", ownershipProof: "proven", durabilityProof: "not-applicable",
                diagnostic: checkpointDiagnostic,
                managementOperation: request.ManagementOperation);
        }

        var issued = ManagementOperationPlans.TryIssue(
            operation, resolution.Volume.DeviceId, containerUuid, volumeUuid, volumeObjectId,
            xid, 0, _managementPlans,
            clock: () => _timeProvider.GetUtcNow());
        if (!issued.Ok || issued.Plan is null)
        {
            return MapPlanRefusal(request, requestedAtUtc, startedAtUtc, issued.Code,
                issued.Detail ?? "The management plan was refused.");
        }

        return BuildResult(
            request, requestedAtUtc, startedAtUtc,
            success: true, code: ApfsOperationCodes.OperationSucceeded, finalStatus: "management-plan-issued",
            mountProof: "absent", ownershipProof: "proven", durabilityProof: "not-applicable",
            diagnostic: $"Dry-run plan {issued.Plan.PlanId} binds {request.ManagementOperation} to the observed checkpoint; no mount or mutation was performed.",
            managementOperation: request.ManagementOperation,
            managementPlanId: issued.Plan.PlanId,
            managementToken: issued.Plan.ConfirmationToken,
            managementObservedXid: xid.ToString(System.Globalization.CultureInfo.InvariantCulture));
    }

    private async Task<OperationResultPayload> ExecuteManagementApplyAsync(
        ControlOperationRequestPayload request,
        DateTime requestedAtUtc,
        DateTime startedAtUtc,
        CancellationToken cancellationToken)
    {
        if (!TryParseManagementOperation(request.ManagementOperation, out var operation) ||
            string.IsNullOrWhiteSpace(request.ManagementToken))
        {
            return ManagementInvalid(request, requestedAtUtc, startedAtUtc,
                "Management apply requires a supported operation and a confirmation token.",
                managementOperation: request.ManagementOperation,
                managementToken: request.ManagementToken);
        }

        if (!ManagementApplyParametersValid(operation, request.ManagementName,
            request.ManagementQuotaBytes, request.ManagementReserveBytes, out var parameterDiagnostic))
        {
            return ManagementInvalid(request, requestedAtUtc, startedAtUtc, parameterDiagnostic!,
                managementOperation: request.ManagementOperation,
                managementToken: request.ManagementToken,
                managementName: request.ManagementName,
                managementQuotaBytes: request.ManagementQuotaBytes,
                managementReserveBytes: request.ManagementReserveBytes,
                managementImagePath: request.ManagementImagePath);
        }

        if (operation == ManagementOperationKind.RenameVolume &&
            string.IsNullOrWhiteSpace(request.ManagementImagePath))
        {
            return ManagementInvalid(request, requestedAtUtc, startedAtUtc,
                "Management rename requires an image path.",
                managementOperation: request.ManagementOperation,
                managementToken: request.ManagementToken,
                managementName: request.ManagementName);
        }

        var resolution = await ResolveTargetAsync(request.Target, cancellationToken).ConfigureAwait(false);
        if (!resolution.IsValid || resolution.Volume is null)
        {
            return ManagementInvalid(request, requestedAtUtc, startedAtUtc,
                resolution.Diagnostic ?? "The management target is missing or ambiguous.",
                resolution.Code,
                managementOperation: request.ManagementOperation,
                managementToken: request.ManagementToken);
        }

        if (!TryManagementIdentity(resolution.Volume, out var containerUuid, out var volumeUuid,
            out var volumeObjectId, out var identityDiagnostic))
        {
            return ManagementInvalid(request, requestedAtUtc, startedAtUtc, identityDiagnostic ?? "Invalid management identity.",
                managementOperation: request.ManagementOperation,
                managementToken: request.ManagementToken);
        }

        if (!CatalogMountPolicy.AllowsOrdinaryMount(resolution.Volume))
        {
            return ManagementInvalid(request, requestedAtUtc, startedAtUtc,
                ManagementRoleRefusal(resolution.Volume),
                managementOperation: request.ManagementOperation,
                managementToken: request.ManagementToken,
                managementName: request.ManagementName,
                managementQuotaBytes: request.ManagementQuotaBytes,
                managementReserveBytes: request.ManagementReserveBytes,
                managementImagePath: request.ManagementImagePath);
        }

        var quiesce = await ProbeManagementQuiesceAsync(request, resolution, requestedAtUtc, startedAtUtc, cancellationToken).ConfigureAwait(false);
        if (!quiesce.Quiesced)
        {
            return EchoManagement(quiesce.Result!, request);
        }
        var verification = await VerifyManagementImageAsync(request, resolution, requestedAtUtc, startedAtUtc, cancellationToken).ConfigureAwait(false);
        if (verification is not null) return verification;

        if (!TryObserveContainerCheckpoint(resolution.Inventory, containerUuid, out var xid, out var checkpointDiagnostic))
        {
            return BuildResult(
                request, requestedAtUtc, startedAtUtc,
                success: false, code: ApfsOperationCodes.ServiceUnavailable, finalStatus: "checkpoint-unobservable",
                mountProof: "absent", ownershipProof: "proven", durabilityProof: "not-applicable",
                diagnostic: checkpointDiagnostic,
                managementOperation: request.ManagementOperation,
                managementToken: request.ManagementToken,
                managementImagePath: request.ManagementImagePath);
        }

        var consumed = _managementPlans.TryConsume(new ManagementApplyRequest(
            request.ManagementToken!, resolution.Volume.DeviceId, containerUuid, volumeUuid,
            volumeObjectId, xid), operation);
        if (!consumed.Ok)
        {
            return MapApplyRefusal(request, requestedAtUtc, startedAtUtc, consumed.Code,
                consumed.Detail ?? "The confirmation token was refused.",
                xid);
        }

        // The plan revalidated exactly: identity, generation, and single use.
        // Keeper dispatch executes at most one planned mutation per
        // consumed plan; operations without a keeper backend terminate at
        // keeper-unavailable with the token burned.
        if (operation == ManagementOperationKind.RenameVolume)
        {
            return await ExecuteManagementRenameAsync(request, requestedAtUtc, startedAtUtc,
                containerUuid, volumeUuid, volumeObjectId, xid, consumed.Plan!, cancellationToken).ConfigureAwait(false);
        }

        if (operation == ManagementOperationKind.SetQuotaReserve)
        {
            return await ExecuteManagementQuotaAsync(request, requestedAtUtc, startedAtUtc,
                resolution.Inventory, containerUuid, volumeUuid, volumeObjectId, xid,
                consumed.Plan!, cancellationToken).ConfigureAwait(false);
        }

        return BuildResult(
            request, requestedAtUtc, startedAtUtc,
            success: false, code: ApfsOperationCodes.ServiceUnavailable, finalStatus: "keeper-unavailable",
            mountProof: "absent", ownershipProof: "proven", durabilityProof: "not-applicable",
            diagnostic: $"The {request.ManagementOperation} plan revalidated but no keeper backend exists; management mutations remain disabled.",
            managementOperation: request.ManagementOperation,
            managementToken: request.ManagementToken,
            managementObservedXid: xid.ToString(System.Globalization.CultureInfo.InvariantCulture),
            managementName: request.ManagementName,
            managementQuotaBytes: request.ManagementQuotaBytes,
            managementReserveBytes: request.ManagementReserveBytes,
            managementImagePath: request.ManagementImagePath);
    }

    private async Task<OperationResultPayload> ExecuteManagementRenameAsync(
        ControlOperationRequestPayload request,
        DateTime requestedAtUtc,
        DateTime startedAtUtc,
        Guid containerUuid,
        Guid volumeUuid,
        ulong volumeObjectId,
        ulong observedXid,
        ManagementOperationPlan plan,
        CancellationToken cancellationToken)
    {
        if (_managementJournalRoot is null)
        {
            return BuildResult(
                request, requestedAtUtc, startedAtUtc,
                success: false, code: ApfsOperationCodes.ServiceUnavailable, finalStatus: "keeper-unavailable",
                mountProof: "absent", ownershipProof: "proven", durabilityProof: "not-applicable",
                diagnostic: "The rename plan revalidated but no keeper journal root is configured; management execution stays disabled.",
                managementOperation: request.ManagementOperation,
                managementToken: request.ManagementToken,
                managementObservedXid: observedXid.ToString(System.Globalization.CultureInfo.InvariantCulture),
                managementName: request.ManagementName,
                managementImagePath: request.ManagementImagePath);
        }

        ManagementKeeperRenameResult kept;
        try
        {
            kept = await _worker.SendManagementRenameAsync(new ManagementKeeperRenameRequest(
                request.ManagementImagePath!,
                containerUuid.ToString("N"),
                volumeUuid.ToString("N"),
                volumeObjectId.ToString(System.Globalization.CultureInfo.InvariantCulture),
                observedXid.ToString(System.Globalization.CultureInfo.InvariantCulture),
                request.ManagementName!,
                _managementJournalRoot), cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return BuildResult(
                request, requestedAtUtc, startedAtUtc,
                success: false, code: ApfsOperationCodes.OperationCancelled, finalStatus: "not-proven",
                diagnostic: "The rename keeper was cancelled before the native tool returned terminal evidence.",
                state: ApfsOperationStates.Cancelled,
                managementOperation: request.ManagementOperation,
                managementToken: request.ManagementToken,
                managementObservedXid: observedXid.ToString(System.Globalization.CultureInfo.InvariantCulture),
                managementName: request.ManagementName,
                managementImagePath: request.ManagementImagePath);
        }

        if (kept.Code == ManagementKeeperCodes.Committed && (!kept.Committed || kept.CommittedXid <= observedXid))
            return UnprovenManagementCommit(request, requestedAtUtc, startedAtUtc);
        if (kept.Code == ManagementKeeperCodes.Unproven)
            return BuildResult(request, requestedAtUtc, startedAtUtc, false, ApfsOperationCodes.BlockedRecovery,
                "management-outcome-unproven", recoveryState: "required", pendingDurability: true,
                mountProof: "absent", ownershipProof: "not-proven", durabilityProof: "not-proven",
                diagnostic: kept.Detail ?? "The original rename journal must be inspected before another operation.",
                managementOperation: request.ManagementOperation, managementPlanId: plan.PlanId,
                managementToken: request.ManagementToken, managementName: request.ManagementName,
                managementImagePath: request.ManagementImagePath);
        var committedXid = kept.CommittedXid.ToString(System.Globalization.CultureInfo.InvariantCulture);
        return kept.Code switch
        {
            ManagementKeeperCodes.Committed => BuildResult(
                request, requestedAtUtc, startedAtUtc,
                success: true, code: ApfsOperationCodes.OperationSucceeded, finalStatus: "management-applied",
                mountProof: "absent", ownershipProof: "proven", durabilityProof: "proven",
                diagnostic: $"Renamed oid={volumeObjectId.ToString(System.Globalization.CultureInfo.InvariantCulture)} xid={committedXid}.",
                managementOperation: request.ManagementOperation,
                managementPlanId: plan.PlanId,
                managementToken: request.ManagementToken,
                managementObservedXid: committedXid,
                managementName: request.ManagementName,
                managementImagePath: request.ManagementImagePath),
            ManagementKeeperCodes.StalePreimage => BuildResult(
                request, requestedAtUtc, startedAtUtc,
                success: false, code: ApfsOperationCodes.OperationConflict, finalStatus: "stale-checkpoint",
                mountProof: "absent", ownershipProof: "proven", durabilityProof: "not-applicable",
                diagnostic: kept.Detail ?? "The image generation moved between confirmation and keeper dispatch; re-observe and re-plan.",
                managementOperation: request.ManagementOperation,
                managementToken: request.ManagementToken,
                managementObservedXid: observedXid.ToString(System.Globalization.CultureInfo.InvariantCulture),
                managementName: request.ManagementName,
                managementImagePath: request.ManagementImagePath),
            ManagementKeeperCodes.KeeperUnavailable => BuildResult(
                request, requestedAtUtc, startedAtUtc,
                success: false, code: ApfsOperationCodes.ServiceUnavailable, finalStatus: "keeper-unavailable",
                mountProof: "absent", ownershipProof: "proven", durabilityProof: "not-applicable",
                diagnostic: kept.Detail ?? "The backend has no management keeper endpoint.",
                managementOperation: request.ManagementOperation,
                managementToken: request.ManagementToken,
                managementObservedXid: observedXid.ToString(System.Globalization.CultureInfo.InvariantCulture),
                managementName: request.ManagementName,
                managementImagePath: request.ManagementImagePath),
            _ => BuildResult(
                request, requestedAtUtc, startedAtUtc,
                success: false, code: ApfsOperationCodes.OperationFailed, finalStatus: "keeper-refused",
                mountProof: "absent", ownershipProof: "proven", durabilityProof: "not-applicable",
                diagnostic: kept.Detail ?? "The rename keeper refused the operation.",
                managementOperation: request.ManagementOperation,
                managementToken: request.ManagementToken,
                managementObservedXid: observedXid.ToString(System.Globalization.CultureInfo.InvariantCulture),
                managementName: request.ManagementName,
                managementImagePath: request.ManagementImagePath),
        };
    }

    private async Task<OperationResultPayload> ExecuteManagementQuotaAsync(
        ControlOperationRequestPayload request,
        DateTime requestedAtUtc,
        DateTime startedAtUtc,
        DeviceInventory? inventory,
        Guid containerUuid,
        Guid volumeUuid,
        ulong volumeObjectId,
        ulong observedXid,
        ManagementOperationPlan plan,
        CancellationToken cancellationToken)
    {
        if (_managementJournalRoot is null)
        {
            return BuildResult(
                request, requestedAtUtc, startedAtUtc,
                success: false, code: ApfsOperationCodes.ServiceUnavailable, finalStatus: "keeper-unavailable",
                mountProof: "absent", ownershipProof: "proven", durabilityProof: "not-applicable",
                diagnostic: "The quota plan revalidated but no keeper journal root is configured; management execution stays disabled.",
                managementOperation: request.ManagementOperation,
                managementToken: request.ManagementToken,
                managementObservedXid: observedXid.ToString(System.Globalization.CultureInfo.InvariantCulture),
                managementQuotaBytes: request.ManagementQuotaBytes,
                managementReserveBytes: request.ManagementReserveBytes,
                managementImagePath: request.ManagementImagePath);
        }

        if (!TryFindContainer(inventory, containerUuid, out var container) || container is null)
        {
            return BuildResult(
                request, requestedAtUtc, startedAtUtc,
                success: false, code: ApfsOperationCodes.AmbiguousTarget, finalStatus: "invalid",
                mountProof: "absent", ownershipProof: "proven", durabilityProof: "not-applicable",
                diagnostic: "The quota sibling census needs exactly one topology container; the observation is ambiguous.",
                managementOperation: request.ManagementOperation,
                managementToken: request.ManagementToken,
                managementQuotaBytes: request.ManagementQuotaBytes,
                managementReserveBytes: request.ManagementReserveBytes,
                managementImagePath: request.ManagementImagePath);
        }

        ManagementKeeperQuotaResult kept;
        try
        {
            kept = await _worker.SendManagementQuotaAsync(new ManagementKeeperQuotaRequest(
                request.ManagementImagePath!,
                containerUuid.ToString("N"),
                volumeUuid.ToString("N"),
                volumeObjectId.ToString(System.Globalization.CultureInfo.InvariantCulture),
                observedXid.ToString(System.Globalization.CultureInfo.InvariantCulture),
                request.ManagementQuotaBytes!,
                request.ManagementReserveBytes!,
                SiblingObjectIds(container, volumeObjectId),
                _managementJournalRoot), cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return BuildResult(
                request, requestedAtUtc, startedAtUtc,
                success: false, code: ApfsOperationCodes.OperationCancelled, finalStatus: "not-proven",
                diagnostic: "The quota keeper was cancelled before the native tool returned terminal evidence.",
                state: ApfsOperationStates.Cancelled,
                managementOperation: request.ManagementOperation,
                managementToken: request.ManagementToken,
                managementObservedXid: observedXid.ToString(System.Globalization.CultureInfo.InvariantCulture),
                managementQuotaBytes: request.ManagementQuotaBytes,
                managementReserveBytes: request.ManagementReserveBytes,
                managementImagePath: request.ManagementImagePath);
        }

        if (kept.Code == ManagementKeeperCodes.Committed && (!kept.Committed || kept.CommittedXid <= observedXid))
            return UnprovenManagementCommit(request, requestedAtUtc, startedAtUtc);
        var committedXid = kept.CommittedXid.ToString(System.Globalization.CultureInfo.InvariantCulture);
        return kept.Code switch
        {
            ManagementKeeperCodes.Committed => BuildResult(
                request, requestedAtUtc, startedAtUtc,
                success: true, code: ApfsOperationCodes.OperationSucceeded, finalStatus: "management-applied",
                mountProof: "absent", ownershipProof: "proven", durabilityProof: "proven",
                diagnostic: $"Quota committed oid={volumeObjectId.ToString(System.Globalization.CultureInfo.InvariantCulture)} xid={committedXid}.",
                managementOperation: request.ManagementOperation,
                managementPlanId: plan.PlanId,
                managementToken: request.ManagementToken,
                managementObservedXid: committedXid,
                managementQuotaBytes: request.ManagementQuotaBytes,
                managementReserveBytes: request.ManagementReserveBytes,
                managementImagePath: request.ManagementImagePath),
            ManagementKeeperCodes.StalePreimage => BuildResult(
                request, requestedAtUtc, startedAtUtc,
                success: false, code: ApfsOperationCodes.OperationConflict, finalStatus: "stale-checkpoint",
                mountProof: "absent", ownershipProof: "proven", durabilityProof: "not-applicable",
                diagnostic: kept.Detail ?? "The image generation moved between confirmation and keeper dispatch; re-observe and re-plan.",
                managementOperation: request.ManagementOperation,
                managementToken: request.ManagementToken,
                managementObservedXid: observedXid.ToString(System.Globalization.CultureInfo.InvariantCulture),
                managementQuotaBytes: request.ManagementQuotaBytes,
                managementReserveBytes: request.ManagementReserveBytes,
                managementImagePath: request.ManagementImagePath),
            ManagementKeeperCodes.KeeperUnavailable => BuildResult(
                request, requestedAtUtc, startedAtUtc,
                success: false, code: ApfsOperationCodes.ServiceUnavailable, finalStatus: "keeper-unavailable",
                mountProof: "absent", ownershipProof: "proven", durabilityProof: "not-applicable",
                diagnostic: kept.Detail ?? "The backend has no management keeper endpoint.",
                managementOperation: request.ManagementOperation,
                managementToken: request.ManagementToken,
                managementObservedXid: observedXid.ToString(System.Globalization.CultureInfo.InvariantCulture),
                managementQuotaBytes: request.ManagementQuotaBytes,
                managementReserveBytes: request.ManagementReserveBytes,
                managementImagePath: request.ManagementImagePath),
            _ => BuildResult(
                request, requestedAtUtc, startedAtUtc,
                success: false, code: ApfsOperationCodes.OperationFailed, finalStatus: "keeper-refused",
                mountProof: "absent", ownershipProof: "proven", durabilityProof: "not-applicable",
                diagnostic: kept.Detail ?? "The quota keeper refused the operation.",
                managementOperation: request.ManagementOperation,
                managementToken: request.ManagementToken,
                managementObservedXid: observedXid.ToString(System.Globalization.CultureInfo.InvariantCulture),
                managementQuotaBytes: request.ManagementQuotaBytes,
                managementReserveBytes: request.ManagementReserveBytes,
                managementImagePath: request.ManagementImagePath),
        };
    }

    private OperationResultPayload UnprovenManagementCommit(ControlOperationRequestPayload request,
        DateTime requestedAtUtc, DateTime startedAtUtc)
        => BuildResult(request, requestedAtUtc, startedAtUtc, false, ApfsOperationCodes.OperationFailed,
            "not-proven", mountProof: "absent", ownershipProof: "proven", durabilityProof: "not-proven",
            diagnostic: "The management keeper returned contradictory commit evidence or no newer checkpoint. Re-observe before planning another operation.",
            managementOperation: request.ManagementOperation, managementToken: request.ManagementToken,
            managementName: request.ManagementName, managementQuotaBytes: request.ManagementQuotaBytes,
            managementReserveBytes: request.ManagementReserveBytes, managementImagePath: request.ManagementImagePath);

    private static bool TryParseManagementOperation(string? operation, out ManagementOperationKind kind)
    {
        if (string.Equals(operation, ApfsManagementOperations.RenameVolume, StringComparison.Ordinal))
        {
            kind = ManagementOperationKind.RenameVolume;
            return true;
        }

        if (string.Equals(operation, ApfsManagementOperations.SetQuotaReserve, StringComparison.Ordinal))
        {
            kind = ManagementOperationKind.SetQuotaReserve;
            return true;
        }

        kind = ManagementOperationKind.Unknown;
        return false;
    }

    private async Task<OperationResultPayload?> VerifyManagementImageAsync(ControlOperationRequestPayload request,
        TargetResolution resolution, DateTime requestedAtUtc, DateTime startedAtUtc, CancellationToken token)
    {
        // Broad identity-only plans may describe unsupported sources; the native keeper
        // still refuses them. A reachable local-image operation must pass verification.
        if (OfflineRepairImageHint(request.Target) is null) return null;
        ApfsAccess.Backend.Native.NativeManagementJournalAdmission.RequireClearRoot(_worker.ConfiguredManagementJournalRoot, true);
        if (_worker.VolumeIntentBlocks(resolution.Volume!.DeviceId))
            throw new OfflineImageOperationException(ApfsOperationCodes.BlockedRecovery, "Volume management intent requires reconciliation.");
        var scoped = VerifyScopeDerivation.TryDerive(resolution.Inventory!, resolution.Volume!);
        ImageVerifyResult? verified = null;
        string? detail = scoped.Detail;
        if (scoped.Ok && scoped.Scope is not null)
        {
            _worker.RequireNativeKeeperAdmission(scoped.Scope);
            try { verified = await _worker.VerifyImageAsync(scoped.Scope, token).ConfigureAwait(false); }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex) { detail = $"verify:error:{ex.GetType().Name}"; }
        }
        if (verified is { Supported: true, Outcome: "Complete", NativeExitCode: 0, FindingCount: 0 }) return null;
        return BuildResult(request, requestedAtUtc, startedAtUtc, false, ApfsOperationCodes.BlockedRecovery,
            "verification-not-complete", mountProof: "absent", ownershipProof: "proven", durabilityProof: "not-applicable",
            diagnostic: $"Management requires a complete covered-metadata verification of the exact offline image. " +
                $"{verified?.Outcome ?? scoped.Code} findings={verified?.FindingCount}. {detail}",
            managementOperation: request.ManagementOperation, managementToken: request.ManagementToken,
            managementName: request.ManagementName, managementQuotaBytes: request.ManagementQuotaBytes,
            managementReserveBytes: request.ManagementReserveBytes, managementImagePath: request.ManagementImagePath);
    }

    private static bool TryManagementIdentity(VolumeInfo volume, out Guid containerUuid,
        out Guid volumeUuid, out ulong volumeObjectId, out string? diagnostic)
    {
        containerUuid = Guid.Empty;
        volumeUuid = Guid.Empty;
        volumeObjectId = 0;
        diagnostic = null;
        if (!Guid.TryParse(volume.CatalogContainerUuid, out containerUuid) || containerUuid == Guid.Empty ||
            !Guid.TryParse(volume.CatalogVolumeUuid, out volumeUuid) || volumeUuid == Guid.Empty ||
            volume.CatalogVolumeObjectId is not { } oid || oid == 0)
        {
            diagnostic = "Management control requires live container identity (container UUID, volume UUID, and volume object ID); the selected volume is not container-identified.";
            return false;
        }

        volumeObjectId = oid;
        return true;
    }

    private async Task<(bool Quiesced, OperationResultPayload? Result)> ProbeManagementQuiesceAsync(
        ControlOperationRequestPayload request,
        TargetResolution resolution,
        DateTime requestedAtUtc,
        DateTime startedAtUtc,
        CancellationToken cancellationToken)
    {
        var probe = await ProbeAuthoritativeMountStateAsync().ConfigureAwait(false);
        if (!probe.Succeeded)
        {
            return (false, BuildResult(
                request, requestedAtUtc, startedAtUtc,
                success: false, code: ApfsOperationCodes.ServiceUnavailable, finalStatus: "invalid",
                mountProof: "unknown", ownershipProof: "not-proven", durabilityProof: "not-applicable",
                diagnostic: $"Management control requires authoritative mount state; {probe.Diagnostic}",
                managementOperation: request.ManagementOperation,
                managementToken: request.ManagementToken,
                managementName: request.ManagementName,
                managementQuotaBytes: request.ManagementQuotaBytes,
                managementReserveBytes: request.ManagementReserveBytes,
                managementImagePath: request.ManagementImagePath));
        }

        if (!resolution.IsValid || resolution.Inventory is null || resolution.Volume is null)
            return (false, ManagementInvalid(request, requestedAtUtc, startedAtUtc,
                resolution.Diagnostic ?? "Management identity changed during quiesce.", resolution.Code));
        if (request.ManagementImagePath is { } image &&
            !string.Equals(image, resolution.Volume.DeviceId, StringComparison.OrdinalIgnoreCase))
            return (false, ManagementInvalid(request, requestedAtUtc, startedAtUtc,
                "The management image path must be the exact observed source; a cloned image or another device is not the selected target."));
        var exactMounts = probe.Mounts.Where(m =>
            string.Equals(m.DeviceId, request.Target!.DeviceId, StringComparison.OrdinalIgnoreCase) ||
            TopologyAdmission.SameUuid(m.CatalogContainerUuid, resolution.Volume.CatalogContainerUuid)).ToArray();
        if (exactMounts.Length != 0 || _worker.HasUnsafeOfflineTeardown(resolution.Inventory))
        {
            return (false, BuildResult(
                request, requestedAtUtc, startedAtUtc,
                success: false, code: ApfsOperationCodes.ServiceUnavailable, finalStatus: "quiesce-required",
                mountProof: exactMounts.Length == 0 ? "absent" : "present", ownershipProof: "not-proven", durabilityProof: "not-applicable",
                diagnostic: "Management control requires every volume using the image or container to be unmounted first, with proven safe teardown; sibling mounts can advance the checkpoint generation.",
                managementOperation: request.ManagementOperation,
                managementToken: request.ManagementToken,
                managementName: request.ManagementName,
                managementQuotaBytes: request.ManagementQuotaBytes,
                managementReserveBytes: request.ManagementReserveBytes,
                managementImagePath: request.ManagementImagePath));
        }

        return (true, null);
    }

    private static bool TryObserveContainerCheckpoint(DeviceInventory? inventory, Guid containerUuid,
        out ulong xid, out string? diagnostic)
    {
        xid = 0;
        diagnostic = null;
        if (!TryFindContainer(inventory, containerUuid, out var container))
        {
            diagnostic = "Management control requires exactly one topology container for the selected volume; the checkpoint generation is unobservable.";
            return false;
        }

        var text = container!.CheckpointXid;
        if (!ulong.TryParse(text, System.Globalization.NumberStyles.None,
                System.Globalization.CultureInfo.InvariantCulture, out xid) ||
            xid == 0 ||
            xid.ToString(System.Globalization.CultureInfo.InvariantCulture) != text)
        {
            diagnostic = "Management control requires a canonical nonzero container checkpoint generation; the checkpoint generation is unobservable.";
            return false;
        }

        return true;
    }

    private static bool TryFindContainer(
        DeviceInventory? inventory, Guid containerUuid, out ApfsContainerRecord? container)
    {
        container = null;
        var matches = inventory?.Topology?.Snapshot.Containers
            .Where(c => TopologyAdmission.SameUuid(c.Uuid, containerUuid.ToString("N")))
            .ToArray();
        if (matches is not { Length: 1 }) return false;
        container = matches[0];
        return true;
    }

    private static IReadOnlyList<string> SiblingObjectIds(
        ApfsContainerRecord container, ulong targetObjectId)
    {
        var siblings = new List<string>();
        foreach (var volumeId in container.VolumeIds)
        {
            var separator = volumeId.LastIndexOf(':');
            if (separator < 0 || !ulong.TryParse(volumeId[(separator + 1)..],
                    System.Globalization.NumberStyles.None,
                    System.Globalization.CultureInfo.InvariantCulture, out var oid) ||
                oid == 0 || oid == targetObjectId)
            {
                continue;
            }

            var canonical = oid.ToString(System.Globalization.CultureInfo.InvariantCulture);
            if (!siblings.Contains(canonical, StringComparer.Ordinal)) siblings.Add(canonical);
        }

        return siblings;
    }

    private static bool ManagementApplyParametersValid(ManagementOperationKind operation, string? name,
        string? quotaBytes, string? reserveBytes, out string? diagnostic)
    {
        diagnostic = null;
        if (operation == ManagementOperationKind.RenameVolume)
        {
            if (name is not null && name.Length is > 0 and <= 255 &&
                name.All(static ch => ch != '\0' && ch != '\r' && ch != '\n') &&
                quotaBytes is null && reserveBytes is null)
            {
                return true;
            }

            diagnostic = "Management rename requires exactly one valid name and no quota values.";
            return false;
        }

        if (operation == ManagementOperationKind.SetQuotaReserve)
        {
            if (name is null && IsCanonicalU64(quotaBytes) && IsCanonicalU64(reserveBytes))
            {
                return true;
            }

            diagnostic = "Management quota requires canonical quota and reserve values and no name.";
            return false;
        }

        diagnostic = "The management operation is unknown.";
        return false;
    }

    private static bool IsCanonicalU64(string? value)
        => value is not null &&
            ulong.TryParse(value, System.Globalization.NumberStyles.None,
                System.Globalization.CultureInfo.InvariantCulture, out var parsed) &&
            parsed.ToString(System.Globalization.CultureInfo.InvariantCulture) == value;

    private static string ManagementRoleRefusal(VolumeInfo volume)
    {
        var detail = volume.CatalogReasons is { Count: > 0 } reasons
            ? string.Join(", ", reasons)
            : volume.CatalogDecision?.ToString() ?? "incomplete catalog";
        return $"Management control refuses volume '{volume.VolumeName}': " +
            $"catalog decision '{volume.CatalogDecision}' disallows ordinary operations ({detail}). " +
            "Protected roles are never management targets.";
    }

    private OperationResultPayload ManagementInvalid(
        ControlOperationRequestPayload request,
        DateTime requestedAtUtc,
        DateTime startedAtUtc,
        string diagnostic,
        string code = ApfsOperationCodes.InvalidArguments,
        string? managementOperation = null,
        string? managementToken = null,
        string? managementName = null,
        string? managementQuotaBytes = null,
        string? managementReserveBytes = null,
        string? managementImagePath = null)
        => BuildResult(
            request, requestedAtUtc, startedAtUtc,
            success: false, code: code, finalStatus: "invalid",
            mountProof: "unknown", ownershipProof: "not-proven", durabilityProof: "not-applicable",
            diagnostic: diagnostic,
            managementOperation: managementOperation ?? request.ManagementOperation,
            managementToken: managementToken,
            managementName: managementName,
            managementQuotaBytes: managementQuotaBytes,
            managementReserveBytes: managementReserveBytes,
            managementImagePath: managementImagePath ?? request.ManagementImagePath);

    private OperationResultPayload MapPlanRefusal(
        ControlOperationRequestPayload request,
        DateTime requestedAtUtc,
        DateTime startedAtUtc,
        string planCode,
        string detail)
    {
        var code = planCode switch
        {
            ManagementOperationPlans.RegistryFull => ApfsOperationCodes.ServiceUnavailable,
            _ => ApfsOperationCodes.InvalidArguments,
        };
        return ManagementInvalid(request, requestedAtUtc, startedAtUtc, detail, code,
            managementOperation: request.ManagementOperation);
    }

    private OperationResultPayload MapApplyRefusal(
        ControlOperationRequestPayload request,
        DateTime requestedAtUtc,
        DateTime startedAtUtc,
        string planCode,
        string detail,
        ulong observedXid)
    {
        var (code, status) = planCode switch
        {
            ManagementOperationPlans.StaleCheckpoint => (ApfsOperationCodes.OperationConflict, "stale-checkpoint"),
            ManagementOperationPlans.ExpiredPlan => (ApfsOperationCodes.Timeout, "invalid"),
            ManagementOperationPlans.IdentityMismatch => (ApfsOperationCodes.AmbiguousTarget, "invalid"),
            _ => (ApfsOperationCodes.InvalidArguments, "invalid"),
        };
        return BuildResult(
            request, requestedAtUtc, startedAtUtc,
            success: false, code: code, finalStatus: status,
            mountProof: "absent", ownershipProof: "proven", durabilityProof: "not-applicable",
            diagnostic: detail,
            managementOperation: request.ManagementOperation,
            managementToken: request.ManagementToken,
            managementObservedXid: observedXid.ToString(System.Globalization.CultureInfo.InvariantCulture),
            managementName: request.ManagementName,
            managementQuotaBytes: request.ManagementQuotaBytes,
            managementReserveBytes: request.ManagementReserveBytes,
            managementImagePath: request.ManagementImagePath);
    }

    private OperationResultPayload EchoManagement(OperationResultPayload result, ControlOperationRequestPayload request)
        => result with
        {
            ManagementOperation = request.ManagementOperation,
            ManagementToken = request.ManagementToken,
            ManagementName = request.ManagementName,
            ManagementQuotaBytes = request.ManagementQuotaBytes,
            ManagementReserveBytes = request.ManagementReserveBytes,
            ManagementImagePath = request.ManagementImagePath,
        };
}
