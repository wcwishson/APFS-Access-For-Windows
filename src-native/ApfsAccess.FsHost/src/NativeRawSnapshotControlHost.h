#pragma once

// Callers hold the original full-cohort host gates throughout these operations.
bool RawSnapshotHostPeers(MountContext& ctx,
    apfsaccess::catalog::ContainerMountCoordinator& coordinator, bool recovery, std::string& error)
{
    if (!ctx.args.enable_raw_snapshots || !ctx.raw_snapshot_startup_admitted || !ctx.raw_snapshot_authority ||
        ctx.container_coordinator != &coordinator || !ctx.container_volume_oid ||
        ctx.container_session_contexts.empty() || ctx.container_session_contexts.size() > 100 ||
        ctx.container_session_contexts.size() != coordinator.MountedVolumeCount() ||
        !ctx.raw_snapshot_startup_evidence || !ctx.raw_snapshot_startup_evidence->VerifyMarkerOwner())
        return SnapshotRecoveryFail(error, "RawSnapshotHostOriginalCohortRequired");
    std::set<std::uint64_t> seen;
    for (auto* peer : ctx.container_session_contexts)
    {
        if (!peer || !seen.insert(peer->container_volume_oid).second ||
            !peer->args.enable_raw_snapshots || !peer->raw_snapshot_startup_admitted ||
            !peer->raw_snapshot_startup_evidence || !peer->raw_snapshot_startup_evidence->VerifyMarkerOwner() ||
            peer->raw_snapshot_authority != ctx.raw_snapshot_authority ||
            peer->container_coordinator != &coordinator || !peer->metadata_store || !peer->tx_manager ||
            peer->args.volume_object_id != peer->container_volume_oid ||
            coordinator.FindSessionStore(peer->container_volume_oid) != peer->metadata_store ||
            peer->args.device != ctx.args.device || peer->args.device_offset_bytes != ctx.args.device_offset_bytes ||
            !peer->args.readwrite || !IsWriteBackendMode(peer->args.write_backend, L"Native") ||
            peer->args.encrypted.enabled || peer->args.fusion.enabled || peer->args.snapshot_xid ||
            !peer->args.snapshot_name.empty() || HasBlockedRecoveryEvidence(*peer) ||
            !SnapshotRecoverySpoolClean(*peer) ||
            !SnapshotRecoveryOriginalStorage(*peer, coordinator, error))
            return SnapshotRecoveryFail(error, "RawSnapshotHostOriginalPeerRequired");
        const bool selected_recovery = recovery && peer == &ctx;
        if (!selected_recovery && (peer->metadata_store->IsRecoveryRequired() ||
            !peer->metadata_store->IsNativeWriteReady() ||
            (!peer->native_write_enabled && !peer->raw_snapshot_host_write_paused) ||
            peer->recovery_active || peer->write_degraded ||
            (recovery && (!SnapshotRecoveryStoreClean(*peer->metadata_store) || peer->pending_native_writes))))
            return SnapshotRecoveryFail(error, "RawSnapshotHostCleanPeerRequired");
        if (!recovery && peer->raw_snapshot_host_write_paused)
            return SnapshotRecoveryFail(error, "RawSnapshotHostCompletionPending");
    }
    for (auto* peer : ctx.container_session_contexts)
        // Staged ordinary writes must drain before admission. They are not a
        // recovery failure, and no snapshot has been accepted on this path.
        if ((!recovery && (!SnapshotRecoveryStoreClean(*peer->metadata_store) || peer->pending_native_writes)) ||
            !SnapshotRecoveryHostIdle(*peer))
            return SnapshotRecoveryFail(error, recovery
                ? "RawSnapshotHostCompletionPeersRequired" : "SnapshotControlBusy");
    return true;
}

bool InspectRawSnapshotHost(MountContext& ctx,
    apfsaccess::catalog::ContainerMountCoordinator& coordinator,
    LiveSnapshotInventory* inventory, std::string& error)
{
    if (inventory) *inventory = {};
    error.clear();
    if (!RawSnapshotHostPeers(ctx, coordinator, false, error)) return false;
    LiveSnapshotInventory observed;
    if (!apfsaccess::rw::RefreshAndInspectRawSnapshotRuntimeAuthority(ctx.raw_snapshot_authority, coordinator,
        ctx.container_volume_oid, observed.scope, inventory ? &observed.snapshots : nullptr, error)) return false;
    if (observed.snapshots.size() > 64) return SnapshotRecoveryFail(error, "SnapshotInventoryBound");
    // Engine receipts address the original handle's NX window relatively.
    // Public inventory identifies that same window in the physical device.
    observed.scope.store_offset_bytes = coordinator.Device().BaseOffsetBytes();
    for (auto& snapshot : observed.snapshots) snapshot.identity.scope = observed.scope;
    if (inventory) *inventory = std::move(observed);
    return true;
}

bool InspectRawSnapshotHostResume(MountContext& ctx,
    apfsaccess::catalog::ContainerMountCoordinator& coordinator,
    apfsaccess::catalog::ApfsSnapshotScope& scope, std::string& error)
{
    scope = {};
    error.clear();
    if ((!ctx.raw_snapshot_host_write_paused && !ctx.raw_snapshot_restart_sequence) ||
        !ctx.raw_snapshot_completion_xid || !RawSnapshotHostPeers(ctx, coordinator, true, error))
        return SnapshotRecoveryFail(error, "RawSnapshotHostResumeOwnerRequired");
    for (auto* peer : ctx.container_session_contexts)
        if (peer->native_write_enabled || (peer != &ctx && !peer->raw_snapshot_host_write_paused))
            return SnapshotRecoveryFail(error, "RawSnapshotHostResumePeersRequired");
    // This authority rechecks the complete source and every original journal.
    // Accepted debt or an engine completion latch cannot pass this branch.
    if (!apfsaccess::rw::InspectRawSnapshotRuntimeAuthority(ctx.raw_snapshot_authority, coordinator,
        ctx.container_volume_oid, scope, nullptr, error)) return false;
    if (scope.checkpoint_xid != ctx.raw_snapshot_completion_xid &&
        scope.checkpoint_xid != ctx.raw_snapshot_completion_xid - 1)
        return SnapshotRecoveryFail(error, "RawSnapshotHostResumeCheckpointChanged");
    RecoveryMarkerState marker;
    const auto status = LoadRecoveryMarkerState(ctx.recovery_marker_file, marker);
    if (status == RecoveryMarkerLoadStatus::Invalid ||
        (status == RecoveryMarkerLoadStatus::Loaded && marker.last_commit_xid &&
            *marker.last_commit_xid > scope.checkpoint_xid))
        return SnapshotRecoveryFail(error, "RawSnapshotHostResumeMarkerInvalid");
    return true;
}

bool AdmitRawSnapshotHostRecovery(MountContext& ctx,
    apfsaccess::catalog::ContainerMountCoordinator& coordinator, std::string& error)
{
    if (!RawSnapshotHostPeers(ctx, coordinator, true, error)) return false;
    const auto sequence = ctx.raw_snapshot_restart_sequence ? ctx.raw_snapshot_restart_sequence :
        ctx.tx_manager->Watermarks().accepted_sequence;
    const apfsaccess::rw::RawSnapshotRuntimeReplayParameters parameters{ctx.raw_snapshot_authority, sequence};
    if (apfsaccess::rw::AdmitRetainedRawSnapshotRecovery(coordinator, *ctx.tx_manager,
        ctx.container_volume_oid, parameters, error)) return true;
    if (ctx.raw_snapshot_restart_sequence &&
        apfsaccess::rw::AdmitRawSnapshotRestartRecovery(coordinator, *ctx.tx_manager,
            ctx.container_volume_oid, parameters, error)) return true;
    apfsaccess::catalog::ApfsSnapshotScope scope;
    if (ctx.raw_snapshot_host_write_paused || ctx.raw_snapshot_restart_sequence)
        return InspectRawSnapshotHostResume(ctx, coordinator, scope, error);
    return InspectRawSnapshotHost(ctx, coordinator, nullptr, error);
}

void PauseRawSnapshotHostWrites(MountContext& ctx)
{
    for (auto* peer : ctx.container_session_contexts)
    {
        std::lock_guard runtime(peer->runtime_state_mutex);
        if (peer->native_write_enabled) peer->raw_snapshot_host_write_paused = true;
        peer->native_write_enabled = false;
    }
}

bool CompleteRawSnapshotHostFiles(MountContext& ctx, std::string& error)
{
    const auto marks = ctx.tx_manager->Watermarks();
    const auto xid = ctx.metadata_store->CheckpointXid();
    if (!marks.accepted_sequence || marks.accepted_sequence != marks.apfs_durable_sequence ||
        !ctx.raw_snapshot_completion_xid || xid != ctx.raw_snapshot_completion_xid ||
        !SnapshotRecoveryStoreClean(*ctx.metadata_store))
        return SnapshotRecoveryFail(error, "RawSnapshotHostDurabilityRequired");
    for (auto* peer : ctx.container_session_contexts)
        if (!peer || peer->native_write_enabled || !SnapshotRecoveryHostIdle(*peer) || !SnapshotRecoverySpoolClean(*peer))
            return SnapshotRecoveryFail(error, "RawSnapshotHostCompletionPeersRequired");
    RecoveryMarkerState clean{false, *xid}, readback;
    if (!PersistRecoveryMarkerState(&ctx, ctx.recovery_marker_file, clean) ||
        LoadRecoveryMarkerState(ctx.recovery_marker_file, readback) != RecoveryMarkerLoadStatus::Loaded ||
        readback.dirty || readback.last_commit_xid != clean.last_commit_xid)
        return SnapshotRecoveryFail(error, "RawSnapshotHostMarkerCompletionFailed");
#ifdef APFSACCESS_FSHOST_UNIT_TEST
    if (ctx.test_force_snapshot_marker_readback_failure)
        return SnapshotRecoveryFail(error, "RawSnapshotHostMarkerReadbackFailed");
#endif
    return true;
}

bool RestoreRawSnapshotHostWrites(MountContext& ctx,
    apfsaccess::catalog::ContainerMountCoordinator& coordinator, std::string& error)
{
#ifdef APFSACCESS_FSHOST_UNIT_TEST
    if (ctx.test_force_snapshot_resume_failure)
        return SnapshotRecoveryFail(error, "RawSnapshotHostResumeInjectedFailure");
#endif
    apfsaccess::catalog::ApfsSnapshotScope scope;
    if (!RawSnapshotHostPeers(ctx, coordinator, true, error) ||
        !apfsaccess::rw::InspectRawSnapshotRuntimeAuthority(ctx.raw_snapshot_authority, coordinator,
            ctx.container_volume_oid, scope, nullptr, error)) return false;
    RecoveryMarkerState marker;
    if (LoadRecoveryMarkerState(ctx.recovery_marker_file, marker) != RecoveryMarkerLoadStatus::Loaded ||
        marker.dirty || marker.last_commit_xid != scope.checkpoint_xid)
        return SnapshotRecoveryFail(error, "RawSnapshotHostCleanMarkerRequired");
    for (auto* peer : ctx.container_session_contexts)
    {
        std::lock_guard runtime(peer->runtime_state_mutex);
        if (peer->raw_snapshot_host_write_paused || peer == &ctx)
            peer->native_write_enabled = true;
        peer->raw_snapshot_host_write_paused = false;
        if (peer == &ctx)
        {
            peer->pending_native_writes = false;
            peer->recovery_active = false;
            peer->write_degraded = false;
            peer->runtime_recovery_reason.clear();
            peer->runtime_last_recovery_action = L"RawSnapshotCompleted";
            peer->runtime_last_commit_xid = scope.checkpoint_xid;
            peer->raw_snapshot_restart_sequence = 0;
            peer->raw_snapshot_completion_xid = 0;
        }
    }
    return true;
}

ContainerControlActionResult RawSnapshotMutationForControl(MountContext& ctx,
    apfsaccess::catalog::ContainerMountCoordinator& coordinator,
    const ContainerControlRequest& request, bool create)
{
    std::string error;
    LiveSnapshotInventory observed;
    if (request.volume_object_id != ctx.container_volume_oid ||
        !InspectRawSnapshotHost(ctx, coordinator, &observed, error))
        return {false, error.empty() ? "SnapshotVolumeMismatch" : error};
    apfsaccess::rw::SnapshotRuntimePlan plan;
    if (create)
    {
        if (!apfsaccess::rw::PrepareSnapshotCreate(coordinator, ctx.container_volume_oid,
            request.snapshot_name, SnapshotControlTimeNs(), 0, ctx.raw_snapshot_authority, plan, error))
            return {false, error};
    }
    else
    {
        auto identity = request.snapshot_identity;
        if (request.snapshot_identity_needs_owner_scope)
        {
            // The wire carries the checkpoint and snapshot fields. Bind the
            // remaining scope to this held owner without replacing a stale XID.
            if (identity.scope.checkpoint_xid != observed.scope.checkpoint_xid)
                return {false, "SnapshotRuntimeDeleteStaleIdentity"};
            identity.scope = observed.scope;
        }
        if (!request.has_snapshot_identity || identity.scope != observed.scope ||
            std::none_of(observed.snapshots.begin(), observed.snapshots.end(), [&](const auto& snapshot) {
                return snapshot.identity == identity;
            })) return {false, "SnapshotRuntimeDeleteStaleIdentity"};
        auto relative = identity;
        relative.scope.store_offset_bytes = 0;
        if (!apfsaccess::rw::PrepareSnapshotDelete(coordinator, relative, SnapshotControlTimeNs(),
            ctx.raw_snapshot_authority, plan, error)) return {false, error};
    }
    const auto before = ctx.tx_manager->Watermarks();
    PauseRawSnapshotHostWrites(ctx);
    ctx.raw_snapshot_completion_xid = observed.scope.checkpoint_xid + 1;
    RecoveryMarkerState dirty{true, observed.scope.checkpoint_xid}, readback;
    if (!PersistRecoveryMarkerState(&ctx, ctx.recovery_marker_file, dirty) ||
        LoadRecoveryMarkerState(ctx.recovery_marker_file, readback) != RecoveryMarkerLoadStatus::Loaded ||
        !readback.dirty || readback.last_commit_xid != dirty.last_commit_xid)
    {
        RecoveryMarkerState clean{false, observed.scope.checkpoint_xid};
        if (PersistRecoveryMarkerState(&ctx, ctx.recovery_marker_file, clean) &&
            RestoreRawSnapshotHostWrites(ctx, coordinator, error))
            return {false, "RawSnapshotHostMarkerArmFailed"};
        BlockRetainedSnapshotRecovery(ctx, "RawSnapshotHostMarkerArmFailed");
        return {false, "RawSnapshotHostMarkerArmFailed"};
    }
    const auto outcome = apfsaccess::rw::ApplySnapshot(coordinator, *ctx.tx_manager, plan,
        [&](std::string& why) { return CompleteRawSnapshotHostFiles(ctx, why); });
    if (!outcome.committed || outcome.commit_recovery_required ||
        outcome.commit_status_code != static_cast<int>(apfsaccess::rw::MetadataStore::CommitStatus::Committed))
    {
        // Only pre-acceptance refusals may roll back the host's dirty marker.
        if (ctx.tx_manager->Watermarks().accepted_sequence == before.accepted_sequence &&
            ctx.tx_manager->CurrentState() == apfsaccess::rw::TransactionManager::State::Idle &&
            SnapshotRecoveryStoreClean(*ctx.metadata_store) && !coordinator.IsRecoveryRequired())
        {
            RecoveryMarkerState clean{false, observed.scope.checkpoint_xid};
            if (PersistRecoveryMarkerState(&ctx, ctx.recovery_marker_file, clean) &&
                RestoreRawSnapshotHostWrites(ctx, coordinator, error))
                return {false, outcome.error.empty() ? "RawSnapshotApplyRefused" : outcome.error};
        }
        BlockRetainedSnapshotRecovery(ctx, outcome.error.empty() ? "RawSnapshotHostCompletionPending" : outcome.error);
        return {false, outcome.error.empty() ? "RawSnapshotHostCompletionPending" : outcome.error};
    }
    if (!RestoreRawSnapshotHostWrites(ctx, coordinator, error))
    {
        BlockRetainedSnapshotRecovery(ctx, error);
        return {false, error};
    }
    return {true, create ? "SnapshotCreated" : "SnapshotDeleted"};
}

ContainerControlActionResult RawSnapshotRecoverForControl(MountContext& ctx,
    apfsaccess::catalog::ContainerMountCoordinator& coordinator)
{
    std::string error;
    if (!AdmitRawSnapshotHostRecovery(ctx, coordinator, error)) return {false, error};
    if (!ctx.raw_snapshot_restart_sequence && !ctx.raw_snapshot_host_write_paused &&
        InspectRawSnapshotHost(ctx, coordinator, nullptr, error)) return {true, "SnapshotRecoverNoOp"};
    apfsaccess::catalog::ApfsSnapshotScope clean_scope;
    if (InspectRawSnapshotHostResume(ctx, coordinator, clean_scope, error))
    {
        RecoveryMarkerState clean{false, clean_scope.checkpoint_xid}, readback;
        if (!PersistRecoveryMarkerState(&ctx, ctx.recovery_marker_file, clean) ||
            LoadRecoveryMarkerState(ctx.recovery_marker_file, readback) != RecoveryMarkerLoadStatus::Loaded ||
            readback.dirty || readback.last_commit_xid != clean.last_commit_xid ||
            !RestoreRawSnapshotHostWrites(ctx, coordinator, error))
        {
            if (error.empty()) error = "RawSnapshotHostResumeMarkerFailed";
            BlockRetainedSnapshotRecovery(ctx, error);
            return {false, error};
        }
        return {true, "SnapshotRecovered"};
    }
    PauseRawSnapshotHostWrites(ctx);
    const apfsaccess::rw::RawSnapshotRuntimeReplayParameters parameters{ctx.raw_snapshot_authority,
        ctx.raw_snapshot_restart_sequence ? ctx.raw_snapshot_restart_sequence : ctx.tx_manager->Watermarks().accepted_sequence};
    std::shared_ptr<const apfsaccess::rw::RawSnapshotRuntimeRecoveryToken> completion;
    const auto recover = ctx.raw_snapshot_restart_sequence
        ? apfsaccess::rw::RecoverRawSnapshotRestart(coordinator, *ctx.tx_manager, ctx.container_volume_oid, parameters, completion, error)
        : apfsaccess::rw::RecoverRetainedRawSnapshot(coordinator, *ctx.tx_manager, ctx.container_volume_oid, parameters, completion, error);
    if (!recover || !completion ||
        !apfsaccess::rw::CompleteRetainedRawSnapshotRecovery(coordinator, completion,
            [&](std::string& why) { return CompleteRawSnapshotHostFiles(ctx, why); }, error) ||
        !RestoreRawSnapshotHostWrites(ctx, coordinator, error))
    {
        BlockRetainedSnapshotRecovery(ctx, error);
        return {false, error.empty() ? "RawSnapshotRecoveryFailed" : error};
    }
    return {true, "SnapshotRecovered"};
}
