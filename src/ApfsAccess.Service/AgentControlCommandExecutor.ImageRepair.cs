using ApfsAccess.Backend.Native;
using ApfsAccess.Core;
using ApfsAccess.Ipc;

namespace ApfsAccess.Service;

public sealed partial class AgentControlCommandExecutor
{
    private async Task<ImageRepairOffer?> TryOfferImageRepairAsync(ImageFixSelection selection, VerifyScope scope,
        DeviceInventory inventory, CancellationToken token)
    {
        if (!_worker.ImageRepairAvailable || !ImageRepairProfile(inventory, scope)) return null;
        using var store = _worker.OpenImageRepairStore();
        var nonce = Guid.NewGuid().ToString("N");
        var root = _worker.ConfiguredManagementJournalRoot!;
        var lineage = Path.Combine(root, "repair-lineage-" + nonce);
        Directory.CreateDirectory(lineage);
        NativeApfsVolumeManagement.ValidateStoreRoot(lineage);
        var invocation = new ImageRepairInvocation(scope, root, Path.Combine(lineage, "original.rct2"), Path.Combine(lineage, "evidence"));
        var native = await _worker.RunImageRepairAsync(invocation, token).ConfigureAwait(false);
        token.ThrowIfCancellationRequested();
        if (native is not { Code: "RepairNeedsConfirmation", NativeExitCode: 3, Replayed: false, NativePostVerifyComplete: false }) return null;
        var now = _timeProvider.GetUtcNow().UtcDateTime;
        // Keep the wire expiry within five minutes of the original Fix request too.
        var binding = new ImageRepairOffer("", now.AddMinutes(2), scope, selection.Target.RecoveryIdentity!,
            selection.Target.ObservationContract!, ImageRepairPersistence.Hash(selection.Cohort), native.ExpectedCount!,
            native.SourceIdentity!, native.SourceSha256!);
        var intent = ImageRepairPersistence.Create(binding, root, nonce) with { NativeReport = native.Report };
        if (!ImageRepairPersistence.JournalUnaccepted(intent.JournalPath, root)) throw new IOException("ImageRepairDryPlanAcceptedJournalUnexpected");
        store.Save(intent);
        return intent.Offer;
    }

    private async Task<OperationResultPayload?> TryResumeOriginalImageRepairAsync(ControlOperationRequestPayload request,
        DateTime requested, DateTime started, CancellationToken token)
    {
        if (!_worker.ImageRepairAvailable) return null;
        try
        {
            string? original;
            using (var store = _worker.OpenImageRepairStore())
                original = store.ReadAll().SingleOrDefault(intent => intent.Pending &&
                    ImageRepairTargetMatches(request.Target!, intent.Offer))?.Offer.PlanId;
            if (original is null) return null;
            token.ThrowIfCancellationRequested();
            if (request.RequestedMode == ApfsControlModes.ReadOnly)
                return ImageRepairFailure(request, requested, started, "ImageRepairOriginalRecoveryRequiresWritableFix",
                    null, null, unknownDebt: true);
            return await ExecuteApprovedImageRepairAsync(request, requested, started, token, original).ConfigureAwait(false);
        }
        catch (Exception error)
        {
            return ImageRepairFailure(request, requested, started, error.Message, null, null,
                token.IsCancellationRequested ? ApfsOperationCodes.OperationCancelled : ApfsOperationCodes.BlockedRecovery,
                token.IsCancellationRequested, unknownDebt: true);
        }
    }

    private async Task<OperationResultPayload> ExecuteApprovedImageRepairAsync(ControlOperationRequestPayload request,
        DateTime requested, DateTime started, CancellationToken token, string? originalPlanId = null)
    {
        var planId = request.ApprovedImageRepairPlanId ?? originalPlanId;
        ImageRepairIntent? intent = null;
        try
        {
            using var store = _worker.OpenImageRepairStore();
            intent = store.Find(planId!) ?? throw new OfflineImageOperationException(
                ApfsOperationCodes.InvalidArguments, "ImageRepairUnknownPlan");
            if (!ImageRepairTargetMatches(request.Target!, intent.Offer))
                throw new OfflineImageOperationException(ApfsOperationCodes.AmbiguousTarget, "ImageRepairStoredSelectionChanged");
            if (!_worker.ImageRepairAvailable) throw new IOException("ImageRepairBackendUnavailable");
            if (request.ApprovedImageRepairPlanId is null && !intent.Pending)
                throw new IOException("ImageRepairPreviouslyAcceptedOriginalRequired");
            if (!intent.Pending && intent.State != "offered")
                return ImageRepairFailure(request, requested, started, "ImageRepairPlanConsumed", intent,
                    ImageRepairReceiptFor(intent, "consumed"), ApfsOperationCodes.OperationConflict);
            if (intent.State == "offered")
            {
                if (intent.Offer.ExpiresAtUtc <= _timeProvider.GetUtcNow().UtcDateTime)
                {
                    intent = intent with { State = "expired", Receipt = ImageRepairReceiptFor(intent, "expired") };
                    store.Save(intent);
                    return ImageRepairFailure(request, requested, started, "ImageRepairPlanExpired", intent, intent.Receipt,
                        ApfsOperationCodes.OperationConflict);
                }
                var selected = ImageRepairTarget(intent.Offer);
                // Resolve and freeze the exact selection before draining. An accepted
                // recovery instead uses its original native journal, even if XID advanced.
                var current = await ResolveTargetAsync(selected, token).ConfigureAwait(false);
                if (!ImageRepairSelectionMatches(current, intent.Offer, exactXid: true))
                    throw new OfflineImageOperationException(ApfsOperationCodes.AmbiguousTarget, "ImageRepairStoredSelectionChanged");
                await _worker.WithImageFixOfflineAsync(request.Target!, selected, intent.Offer.Scope, async (scope, inventory, ct) =>
                {
                    intent = store.Find(planId!) ?? throw new IOException("ImageRepairOriginalMissing");
                    if (intent.State != "offered" || !ImageRepairProfile(inventory, scope) || scope != intent.Offer.Scope ||
                        !ImageRepairSelectionMatches(TargetResolution.Valid(inventory.Volumes.Single(), inventory), intent.Offer, true))
                        throw new OfflineImageOperationException(ApfsOperationCodes.AmbiguousTarget, "ImageRepairScopeChangedAfterDrain");
                    var verify = await _worker.VerifyImageAsync(scope, ct).ConfigureAwait(false);
                    if (!ImageRepairPreverifyAllowsPlan(verify))
                        throw new IOException("ImageRepairFindingChanged");
                    var invocation = ImageRepairInvocationFor(intent, approved: false);
                    var dry = await _worker.RunImageRepairAsync(invocation, ct).ConfigureAwait(false);
                    if (dry is not { Code: "RepairNeedsConfirmation", NativeExitCode: 3, Replayed: false, NativePostVerifyComplete: false } ||
                        dry.SourceIdentity != intent.Offer.SourceIdentity || dry.SourceSha256 != intent.Offer.SourceSha256 ||
                        dry.ExpectedCount != intent.Offer.ExpectedCount || !ImageRepairPersistence.JournalUnaccepted(intent.JournalPath, intent.JournalRoot))
                        throw new IOException("ImageRepairNativePlanOrSourceChanged");
                    ct.ThrowIfCancellationRequested();
                    if (intent.Offer.ExpiresAtUtc <= _timeProvider.GetUtcNow().UtcDateTime)
                        throw new IOException("ImageRepairPlanExpiredBeforeAcceptance");
                    var accepted = intent with { State = "applying", AcceptedOperationId = request.OperationId,
                        AcceptedFingerprint = ApfsOperationFingerprint.Compute(request), Receipt = ImageRepairReceiptFor(intent, "applying") };
                    store.Save(accepted); // Must be durable before any confirmed native invocation.
                    intent = accepted;
                    intent = await ApplyOriginalImageRepairAsync(store, intent, ct).ConfigureAwait(false);
                    return true;
                }, token).ConfigureAwait(false);
            }
            else
            {
                await _worker.WithOriginalImageRepairOfflineAsync(intent, async ct =>
                {
                    intent = store.Find(planId!) ?? throw new IOException("ImageRepairOriginalMissing");
                    if (!intent.Pending) throw new IOException("ImageRepairPlanConsumed");
                    intent = await ApplyOriginalImageRepairAsync(store, intent, ct).ConfigureAwait(false);
                    return true;
                }, token).ConfigureAwait(false);
            }
            if (intent.State != "repaired")
                return ImageRepairFailure(request, requested, started, "ImageRepairNativeApplyNotVerified", intent, intent.Receipt);
            token.ThrowIfCancellationRequested();
            var after = await ResolveTargetAsync(ImageRepairTarget(intent.Offer), token).ConfigureAwait(false);
            if (!ImageRepairSelectionMatches(after, intent.Offer, exactXid: false))
                return ImageRepairFailure(request, requested, started, "ImageRepairFinalSelectionChanged", intent, intent.Receipt);
            // The native receipt does not establish service success. Reuse the full
            // offline verification, fresh owner and terminal live proof workflow.
            var result = await ExecuteImageFixAsync(request, after, requested, started, token).ConfigureAwait(false);
            return result with { ImageRepairReceipt = intent.Receipt };
        }
        catch (Exception error)
        {
            string? persistenceError = null;
            if (intent is not null)
            {
                try
                {
                    using var store = _worker.OpenImageRepairStore();
                    var durable = store.Find(intent.Offer.PlanId);
                    if (durable is { Pending: true })
                    {
                        intent = durable with { State = "recovery-required", Receipt = ImageRepairReceiptFor(durable, "recovery-required") };
                        store.Save(intent);
                    }
                    else if (durable is not null) intent = durable;
                }
                catch (Exception ex) { persistenceError = ex.Message; }
            }
            // A selector mismatch must never acquire a receipt for another target.
            var bindingMatches = intent is not null && ImageRepairTargetMatches(request.Target!, intent.Offer);
            var receipt = bindingMatches ? intent!.Receipt : null;
            return ImageRepairFailure(request, requested, started, AppendDiagnostic(error.Message, persistenceError),
                bindingMatches ? intent : null, receipt,
                token.IsCancellationRequested ? ApfsOperationCodes.OperationCancelled :
                error is OfflineImageOperationException rejected ? rejected.Code : ApfsOperationCodes.BlockedRecovery,
                token.IsCancellationRequested, persistenceError is not null);
        }
    }

    private async Task<ImageRepairIntent> ApplyOriginalImageRepairAsync(ImageRepairIntentStore store, ImageRepairIntent intent,
        CancellationToken token)
    {
        var native = await _worker.RunImageRepairAsync(ImageRepairInvocationFor(intent, true), token).ConfigureAwait(false);
        token.ThrowIfCancellationRequested();
        var repaired = native is { Code: "RepairedAndVerified", NativeExitCode: 0, NativePostVerifyComplete: true } &&
            native.SourceIdentity == intent.Offer.SourceIdentity &&
            (native.Replayed || native.SourceSha256 == intent.Offer.SourceSha256 && native.ExpectedCount == intent.Offer.ExpectedCount);
        var state = repaired ? "repaired" : native is { Code: "RepairRefused", NativeExitCode: 4 } &&
            ImageRepairPersistence.JournalUnaccepted(intent.JournalPath, intent.JournalRoot) ? "refused" : "recovery-required";
        var receipt = new ImageRepairReceipt(intent.Offer.PlanId, state, intent.Offer, intent.JournalPath,
            intent.EvidenceDirectory, native.Code, native.NativeExitCode, native.Replayed, native.NativePostVerifyComplete,
            intent.AcceptedOperationId);
        var terminal = intent with { State = state, Receipt = receipt, NativeReport = native.Report };
        store.Save(terminal);
        return terminal;
    }

    private OperationResultPayload ImageRepairFailure(ControlOperationRequestPayload request, DateTime requested, DateTime started,
        string? diagnostic, ImageRepairIntent? intent, ImageRepairReceipt? receipt, string code = ApfsOperationCodes.BlockedRecovery,
        bool cancelled = false, bool unknownDebt = false)
        => BuildResult(request, requested, started, false, code,
            intent?.Pending == true || unknownDebt ? "repair-recovery-required" : "repair-not-complete",
            requestedMode: request.RequestedMode, pendingDurability: intent?.Pending == true || unknownDebt,
            mountProof: "not-proven", ownershipProof: "not-proven", durabilityProof: "not-proven", diagnostic: diagnostic,
            state: cancelled ? ApfsOperationStates.Cancelled : null) with { ImageRepairReceipt = receipt };

    private static ImageRepairInvocation ImageRepairInvocationFor(ImageRepairIntent intent, bool approved)
        => new(intent.Offer.Scope, intent.JournalRoot, intent.JournalPath, intent.EvidenceDirectory, approved ? intent.Offer : null);
    private static ImageRepairReceipt ImageRepairReceiptFor(ImageRepairIntent intent, string state)
        => new(intent.Offer.PlanId, state, intent.Offer, intent.JournalPath, intent.EvidenceDirectory,
            OriginalAcceptedOperationId: intent.AcceptedOperationId);
    private static ApfsControlTarget ImageRepairTarget(ImageRepairOffer offer)
        => new(offer.Scope.ImagePath, ImageRepairPersistence.VolumeId(offer.Scope), offer.RecoveryIdentity,
            offer.Scope.VolumeUuid, offer.Scope.ContainerId[15..], ulong.Parse(offer.Scope.VolumeObjectId, System.Globalization.CultureInfo.InvariantCulture),
            offer.ObservationContract);
    private static bool ImageRepairTargetMatches(ApfsControlTarget target, ImageRepairOffer offer)
        => target.RegisteredImage is null && string.Equals(target.DeviceId, offer.Scope.ImagePath, StringComparison.OrdinalIgnoreCase) &&
            target.VolumeId == ImageRepairPersistence.VolumeId(offer.Scope) &&
            (target.RecoveryIdentity is null || target.RecoveryIdentity == offer.RecoveryIdentity) &&
            (!SelectedControlTarget.IsAdvertised(target) || target with { DeviceId = offer.Scope.ImagePath } == ImageRepairTarget(offer));
    private static bool ImageRepairSelectionMatches(TargetResolution current, ImageRepairOffer offer, bool exactXid)
    {
        if (!current.IsValid || current.Inventory is null || current.Volume is null ||
            SelectedControlTarget.Create(current.Inventory, current.Volume) != ImageRepairTarget(offer)) return false;
        var scope = VerifyScopeDerivation.TryDerive(current.Inventory, current.Volume).Scope;
        return scope is not null && (exactXid ? scope == offer.Scope : scope with { CheckpointXid = offer.Scope.CheckpointXid } == offer.Scope) &&
            ImageRepairProfile(current.Inventory, scope) && ImageRepairPersistence.Hash(ImageFixCohort(current)) == offer.CohortDigest;
    }

    private static bool ImageRepairProfile(DeviceInventory inventory, VerifyScope scope)
    {
        if (!ImageRepairPersistence.LocalPath(scope.ImagePath) || scope.StoreOffsetBytes != "0" || !VolumeTopologyProfile.IsBounded(scope) ||
            !TopologyAdmission.Validate(inventory) || inventory.Volumes is not { Count: 1 } || inventory.Topology is null) return false;
        var topology = inventory.Topology.Snapshot;
        var row = inventory.Volumes[0];
        return topology.Containers is [{ Fusion: false, StoreIds.Count: 1, VolumeIds.Count: 1 }] &&
            topology.Volumes is [{ RoleRaw: 64, EncryptionMode: "none", Locked: false, GroupId: null }] &&
            topology.Stores.Count == 1 && topology.Groups.Count == 0 && row.RegisteredImage is null && !row.IsEncrypted &&
            CatalogMountPolicy.AllowsOrdinaryMount(row) && row.VolumeId == ImageRepairPersistence.VolumeId(scope);
    }
}

public sealed partial class ApfsMountWorker
{
    internal bool ImageRepairAvailable => _backend is IImageRepairBackend && ImageRepairPersistence.LocalPath(ConfiguredManagementJournalRoot);
    internal ImageRepairIntentStore OpenImageRepairStore()
    {
        using var volumeStore = OpenVolumeIntentStore(); // Pins the shared root for this worker lifetime.
        return new(ConfiguredManagementJournalRoot!);
    }
    internal Task<ImageRepairNativeResult> RunImageRepairAsync(ImageRepairInvocation invocation, CancellationToken token)
        => (_backend as IImageRepairBackend ?? throw new IOException("ImageRepairBackendUnavailable")).RunImageRepairAsync(invocation, token);

    internal Task<T> WithOriginalImageRepairOfflineAsync<T>(ImageRepairIntent original,
        Func<CancellationToken, Task<T>> operation, CancellationToken token)
        => WithMountOperationsPausedAsync(async ct =>
        {
            using var store = OpenImageRepairStore();
            var durable = store.Find(original.Offer.PlanId);
            if (durable is not { Pending: true } || durable.Offer != original.Offer ||
                durable.AcceptedFingerprint != original.AcceptedFingerprint || durable.AcceptedOperationId != original.AcceptedOperationId)
                throw new IOException("ImageRepairOriginalAcceptedLineageRequired");
            using var volumes = OpenVolumeIntentStore();
            if (volumes.ReadAll().Any(r => r.Pending)) throw new IOException("ImageRepairForeignVolumeIntentPending");
            ImageRepairPersistence.RequireNoPending(ConfiguredManagementJournalRoot, original.Offer.PlanId);
            await RequireVolumeImageQuiescedAsync(original.Offer.Scope.ImagePath, original.Offer.Scope.ContainerId[15..], ct).ConfigureAwait(false);
            return await operation(ct).ConfigureAwait(false);
        }, token);
}
