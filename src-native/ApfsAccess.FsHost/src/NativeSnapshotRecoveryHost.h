#pragma once
#define APFSACCESS_RETAINED_SNAPSHOT_COMPLETION 1

// Included after the host's image inspection and full-peer gate definitions.
// All functions below require the caller to hold every peer's journal gate.
struct RetainedSnapshotRecoveryProof
{
    std::optional<apfsaccess::rw::NativeSnapshotIntent> intent;
    apfsaccess::rw::BlockDevice::StableImageIdentity source;
    std::uint64_t accepted_sequence = 0;
    bool completion_retry = false;
};

bool SnapshotRecoveryFail(std::string& error, const char* code)
{
    error = code;
    return false;
}

bool SnapshotRecoveryStoreClean(const apfsaccess::rw::MetadataStore& store)
{
    return !store.IsRecoveryRequired() && store.IsNativeWriteReady() &&
        !store.HasUncommittedAllocatorState() && !store.PendingMutationCount() &&
        !store.PendingAllocationCount() && !store.PendingDeallocationCount() &&
        !store.PendingObjectMapUpdateCount() && !store.PendingBtreeRecordCount() && !store.PendingPayloadByteEstimate();
}

bool SnapshotRecoveryHostIdle(MountContext& ctx)
{
    if (ctx.mutation_admission_state.load(std::memory_order_acquire) ||
        ctx.active_foreground_mutation_callbacks.load(std::memory_order_acquire) ||
        ctx.open_write_handle_count.load(std::memory_order_acquire) ||
        ctx.compression_verification_pending.load(std::memory_order_acquire)) return false;
    std::unique_lock scheduler(ctx.deferred_commit_mutex, std::try_to_lock);
    if (!scheduler.owns_lock() || ctx.deferred_commit_requested || ctx.deferred_commit_in_flight ||
        ctx.deferred_commit_thread_stop || ctx.deferred_access_time_requested) return false;
    std::unique_lock queue(ctx.manifest_queue_mutex, std::try_to_lock);
    return queue.owns_lock() && ctx.manifest_queued_requests.empty();
}

bool SnapshotRecoverySpoolClean(const MountContext& ctx)
{
    const auto counters = SnapshotPayloadSpoolStatusCounters(ctx);
    return !counters.recovery_required && !counters.spool_bytes && !counters.dirty_range_count &&
        !counters.index_dirty && !counters.bytes_since_sync && !counters.appends_since_sync;
}

bool SnapshotRecoveryOriginalStorage(MountContext& ctx,
    apfsaccess::catalog::ContainerMountCoordinator& coordinator, std::string& error)
{
    if (!IsValidRecoveryIdentity(ctx.args.recovery_identity))
        return SnapshotRecoveryFail(error, "SnapshotRecoveryOriginalStorageRequired");
    const auto canonical = Utf8ToWide("apfs-vol:" + coordinator.ContainerUuidHex() + ":" + std::to_string(ctx.container_volume_oid));
    const auto root = BuildPayloadSpoolSessionRoot(ctx.args, apfsaccess::rw::PayloadSpool::ResolveDefaultRoot());
    if (!ctx.payload_spool || ctx.payload_spool_volume_identity != WideToUtf8(ctx.tx_manager->ConfiguredVolumeIdentity()) ||
        ctx.tx_journal_file != root / "write-ahead.wal" || ctx.payload_spool->SpoolFilePath().parent_path() != root ||
        ctx.recovery_marker_file != BuildRecoveryMarkerPath(ctx.args) ||
        !ctx.tx_manager->OwnsEnrolledCanonicalJournal(ctx.tx_journal_file.wstring(), canonical))
        return SnapshotRecoveryFail(error, "SnapshotRecoveryOriginalStorageRequired");
    return true;
}

#ifdef APFSACCESS_FSHOST_UNIT_TEST
std::function<void(MountContext&, HANDLE)> g_snapshot_terminal_wal_opened_test_hook;
std::function<void(const apfsaccess::rw::WriteAheadLog::ReadResult&)> g_snapshot_terminal_wal_decoded_test_hook;
#endif

bool SnapshotRecoveryCleanTerminalReceipt(MountContext& ctx, RetainedSnapshotRecoveryProof& proof, std::string& error,
    apfsaccess::rw::WalReadLimits limits = {64ull * 1024 * 1024, 1000000},
    std::uint64_t max_allocation_bytes = 256ull * 1024 * 1024)
{
    using Wal = apfsaccess::rw::WriteAheadLog;
    const auto marks = ctx.tx_manager->Watermarks();
    const auto identity = ctx.tx_manager->ConfiguredVolumeIdentity();
    const auto generation = ctx.tx_manager->ValidatedCleanJournalGeneration();
    if (!marks.accepted_sequence || marks.accepted_sequence != marks.apfs_durable_sequence ||
        marks.accepted_sequence != marks.cleanup_sequence || !generation ||
        !ctx.tx_manager->OwnsJournalForMaintenance(ctx.tx_journal_file.wstring(), identity))
        return SnapshotRecoveryFail(error, "SnapshotRecoveryCompletionEvidenceRequired");
    // The original terminal receipt remains in the native WAL after watermark
    // cleanup. Decode it read-only under the actual owner's unchanged lease.
    UniqueWinHandle bounded(CreateFileW(ctx.tx_journal_file.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    if (bounded.get() == INVALID_HANDLE_VALUE) return SnapshotRecoveryFail(error, "SnapshotRecoveryTerminalWalMissing");
#ifdef APFSACCESS_FSHOST_UNIT_TEST
    if (auto hook = std::exchange(g_snapshot_terminal_wal_opened_test_hook, {})) hook(ctx, bounded.get());
#endif
    const auto decoded = Wal::ReadAllEvidenceFromHeldHandle(bounded.get(), WideToUtf8(identity), limits, max_allocation_bytes);
    const bool closed = CloseHandle(bounded.release()) != FALSE;
#ifdef APFSACCESS_FSHOST_UNIT_TEST
    if (auto hook = std::exchange(g_snapshot_terminal_wal_decoded_test_hook, {})) hook(decoded);
#endif
    if (!closed || decoded.status != Wal::ReadStatus::Ok || decoded.recovered_torn_tail ||
        generation != ctx.tx_manager->ValidatedCleanJournalGeneration() ||
        !ctx.tx_manager->OwnsJournalForMaintenance(ctx.tx_journal_file.wstring(), identity))
        return SnapshotRecoveryFail(error, "SnapshotRecoveryTerminalWalInvalid");
    const Wal::Record* terminal = nullptr;
    for (const auto& record : decoded.records)
        if (record.sequence == marks.accepted_sequence && record.operation == Wal::OperationKind::TransactionMarker &&
            record.state == Wal::RecordState::Accepted && record.logical_length == 1) terminal = &record;
    if (!terminal) return SnapshotRecoveryFail(error, "SnapshotRecoveryTerminalReceiptMissing");
    const Wal::Record* mutation = nullptr;
    for (const auto& record : decoded.records)
        if (record.transaction_id == terminal->transaction_id && record.operation != Wal::OperationKind::TransactionMarker &&
            record.operation != Wal::OperationKind::DurabilityWatermark && record.operation != Wal::OperationKind::CompactionIndex)
        {
            if (mutation || record.sequence >= terminal->sequence || record.state != Wal::RecordState::Prepared)
                return SnapshotRecoveryFail(error, "SnapshotRecoveryTerminalReceiptMixed");
            mutation = &record;
        }
    apfsaccess::rw::NativeSnapshotIntent intent;
    if (!mutation || !Wal::SnapshotIntentIsConsistent(*mutation) ||
        !apfsaccess::rw::DecodeNativeSnapshotIntent(mutation->inline_payload, intent) ||
        intent.scope.volume_oid != ctx.container_volume_oid || intent.scope.checkpoint_xid == UINT64_MAX ||
        intent.scope.checkpoint_xid != terminal->object_id ||
        mutation->volume_identity != WideToUtf8(ctx.tx_manager->ConfiguredVolumeIdentity()) ||
        !ctx.metadata_store->Device().QueryHeldImageIdentity(proof.source) ||
        !apfsaccess::rw::VerifyPublishedSnapshot(*ctx.metadata_store, intent, error))
        return SnapshotRecoveryFail(error, "SnapshotRecoveryTerminalPublicationUnproven");
    proof.intent = std::move(intent);
    proof.accepted_sequence = marks.accepted_sequence;
    proof.completion_retry = true;
    return true;
}

bool AdmitRetainedImageSnapshotRecovery(MountContext& ctx,
    apfsaccess::catalog::ContainerMountCoordinator& coordinator,
    RetainedSnapshotRecoveryProof& proof, std::string& error)
{
    proof = {};
    if (HasBlockedRecoveryEvidence(ctx) || !ctx.tx_manager || !ctx.metadata_store ||
        !ctx.args.enable_image_snapshots || !SnapshotRecoveryHostIdle(ctx))
        return SnapshotRecoveryFail(error, "SnapshotRecoveryOwnerBlocked");
    const auto census = coordinator.CheckpointCensusSnapshot();
    if (census.empty() || census.size() > 100 || census.size() != ctx.container_session_contexts.size())
        return SnapshotRecoveryFail(error, "SnapshotRecoveryCensusIncomplete");
    for (const auto& entry : census)
    {
        const auto found = std::find_if(ctx.container_session_contexts.begin(), ctx.container_session_contexts.end(),
            [&](const auto* peer) { return peer && peer->container_volume_oid == entry.volume_object_id; });
        if (found == ctx.container_session_contexts.end()) return SnapshotRecoveryFail(error, "SnapshotRecoveryPeerMissing");
        auto& peer = **found;
        if (peer.container_coordinator != &coordinator || peer.args.volume_object_id != entry.volume_object_id ||
            peer.args.device != ctx.args.device || peer.args.device_offset_bytes ||
            peer.args.container_id != ctx.args.container_id || HasBlockedRecoveryEvidence(peer) ||
            !peer.tx_manager || !peer.metadata_store || !SnapshotRecoveryHostIdle(peer) ||
            !SnapshotRecoveryStoreClean(*peer.metadata_store) ||
            !apfsaccess::rw::VerifySnapshotRecoveryOwner(coordinator, entry.volume_object_id, *peer.tx_manager,
                peer.tx_journal_file.wstring(), error) ||
            peer.tx_manager->ConfiguredVolumeIdentity() != BuildWalVolumeIdentity(peer.args) ||
            peer.tx_manager->CurrentState() != apfsaccess::rw::TransactionManager::State::Idle ||
            peer.tx_manager->PendingMutationCount() || !peer.tx_manager->RecoveryStateValid())
            return SnapshotRecoveryFail(error, "SnapshotRecoveryOriginalPeerRequired");
        std::vector<std::uint64_t> pins;
        if (!peer.tx_manager->LoadRequiredCheckpointXidsSinceCleanup(pins, &error) ||
            pins != entry.required_checkpoint_xids || entry.unapplied_accepted_work != peer.tx_manager->HasUnappliedAcceptedWork())
            return SnapshotRecoveryFail(error, "SnapshotRecoveryCensusJournalMismatch");
        if (&peer != &ctx && (peer.recovery_active || peer.write_degraded || peer.pending_native_writes ||
            entry.unapplied_accepted_work || !pins.empty() || !peer.tx_manager->ValidatedCleanJournalGeneration() ||
            !SnapshotRecoverySpoolClean(peer))) return SnapshotRecoveryFail(error, "SnapshotRecoveryCleanPeerRequired");
    }

    std::vector<apfsaccess::rw::TransactionManager::AcceptedTransaction> suffix;
    if (!ctx.tx_manager->LoadAcceptedTransactionsSinceCleanup(suffix, &error)) return false;
    if (suffix.empty())
    {
        if (!ctx.snapshot_recovery_completion_intent && !ctx.native_write_enabled && ctx.recovery_active)
        {
            RecoveryMarkerState marker;
            if (!SnapshotRecoveryOriginalStorage(ctx, coordinator, error) || !SnapshotRecoverySpoolClean(ctx) ||
                !RecoveryMarkerFastPathFileIsPresent(ctx.recovery_marker_file) ||
                LoadRecoveryMarkerState(ctx.recovery_marker_file, marker) != RecoveryMarkerLoadStatus::Loaded || !marker.dirty ||
                !InspectImageSnapshotSession(ctx, coordinator, nullptr, error) ||
                !SnapshotRecoveryCleanTerminalReceipt(ctx, proof, error) ||
                (marker.last_commit_xid && *marker.last_commit_xid > proof.intent->scope.checkpoint_xid + 1))
                return SnapshotRecoveryFail(error, "SnapshotRecoveryCompletionEvidenceRequired");
            return true;
        }
        if (ctx.snapshot_recovery_completion_intent)
        {
            apfsaccess::rw::BlockDevice::StableImageIdentity held;
            const auto& original = ctx.snapshot_recovery_completion_source;
            if (!ctx.metadata_store->Device().QueryHeldImageIdentity(held) || held.volume_serial != original.volume_serial ||
                held.file_id != original.file_id || held.size_bytes != original.size_bytes || held.creation_time != original.creation_time)
                return SnapshotRecoveryFail(error, "SnapshotRecoverySourceChanged");
            const auto generation = ctx.tx_manager->ValidatedCleanJournalGeneration();
            const auto marks = ctx.tx_manager->Watermarks();
            if (!generation || generation != ctx.snapshot_recovery_completion_clean_generation ||
                !ctx.snapshot_recovery_completion_sequence || marks.accepted_sequence != ctx.snapshot_recovery_completion_sequence ||
                marks.accepted_sequence != marks.apfs_durable_sequence || marks.accepted_sequence != marks.cleanup_sequence ||
                !SnapshotRecoveryOriginalStorage(ctx, coordinator, error) || !SnapshotRecoverySpoolClean(ctx) ||
                !InspectImageSnapshotSession(ctx, coordinator, nullptr, error) ||
                !apfsaccess::rw::VerifyPublishedSnapshot(*ctx.metadata_store, *ctx.snapshot_recovery_completion_intent, error)) return false;
            proof.intent = ctx.snapshot_recovery_completion_intent;
            proof.source = ctx.snapshot_recovery_completion_source;
            proof.accepted_sequence = ctx.snapshot_recovery_completion_sequence;
            proof.completion_retry = true;
            RecoveryMarkerState marker;
            if (!RecoveryMarkerFastPathFileIsPresent(ctx.recovery_marker_file) ||
                LoadRecoveryMarkerState(ctx.recovery_marker_file, marker) != RecoveryMarkerLoadStatus::Loaded ||
                (marker.last_commit_xid && *marker.last_commit_xid > proof.intent->scope.checkpoint_xid + 1))
                return SnapshotRecoveryFail(error, "SnapshotRecoveryMarkerInvalid");
            return true;
        }
        if (!ctx.native_write_enabled || ctx.recovery_active || ctx.write_degraded || ctx.pending_native_writes ||
            !ctx.tx_manager->ValidatedCleanJournalGeneration() || !SnapshotRecoverySpoolClean(ctx))
            return SnapshotRecoveryFail(error, "SnapshotRecoveryCompletionEvidenceRequired");
        return InspectImageSnapshotSession(ctx, coordinator, nullptr, error, false, true) &&
            apfsaccess::rw::VerifySnapshotJournalCurrency(coordinator, ctx.container_volume_oid, *ctx.tx_manager, false, error);
    }
    if (suffix.size() != 1 || suffix.front().mutations.size() != 1)
        return SnapshotRecoveryFail(error, "SnapshotRuntimeReplayMixedReceipt");
    const auto& tx = suffix.front();
    const auto& record = tx.mutations.front();
    apfsaccess::rw::NativeSnapshotIntent intent;
    if (!apfsaccess::rw::WriteAheadLog::SnapshotIntentIsConsistent(record) ||
        !apfsaccess::rw::DecodeNativeSnapshotIntent(record.inline_payload, intent) ||
        intent.scope.volume_oid != ctx.container_volume_oid || intent.scope.checkpoint_xid == UINT64_MAX ||
        tx.preimage_checkpoint_xid != intent.scope.checkpoint_xid || !tx.accepted_sequence ||
        tx.accepted_sequence != ctx.tx_manager->Watermarks().accepted_sequence ||
        record.volume_identity != WideToUtf8(ctx.tx_manager->ConfiguredVolumeIdentity()))
        return SnapshotRecoveryFail(error, "SnapshotRuntimeReplayIdentity");
    LiveSnapshotInventory observed;
    if (!InspectImageSnapshotSession(ctx, coordinator, &observed, error, ctx.tx_manager->HasUnappliedAcceptedWork()) ||
        !apfsaccess::rw::VerifySnapshotJournalCurrency(coordinator, ctx.container_volume_oid, *ctx.tx_manager, false, error)) return false;
    const auto& scope = observed.scope;
    if (scope.store_offset_bytes != intent.scope.store_offset_bytes || scope.store_size_bytes != intent.scope.store_size_bytes ||
        scope.container_uuid_hex != intent.scope.container_uuid_hex || scope.volume_uuid_hex != intent.scope.volume_uuid_hex ||
        scope.volume_oid != intent.scope.volume_oid ||
        (scope.checkpoint_xid != intent.scope.checkpoint_xid && scope.checkpoint_xid != intent.scope.checkpoint_xid + 1) ||
        !ctx.metadata_store->Device().QueryHeldImageIdentity(proof.source))
        return SnapshotRecoveryFail(error, "SnapshotRecoveryHeldScopeMismatch");

    // Disabled recovery is a production-bound receipt route, never a reason/flag bypass.
    if (!ctx.native_write_enabled || IsValidRecoveryIdentity(ctx.args.recovery_identity))
    {
        if (!SnapshotRecoveryOriginalStorage(ctx, coordinator, error)) return false;
    }
    if (!SnapshotRecoverySpoolClean(ctx)) return SnapshotRecoveryFail(error, "SnapshotRecoverySpoolNotClean");
    if (!ctx.recovery_marker_file.empty())
    {
        RecoveryMarkerState marker;
        if (!RecoveryMarkerFastPathFileIsPresent(ctx.recovery_marker_file) ||
            LoadRecoveryMarkerState(ctx.recovery_marker_file, marker) != RecoveryMarkerLoadStatus::Loaded ||
            (marker.last_commit_xid && *marker.last_commit_xid > scope.checkpoint_xid))
            return SnapshotRecoveryFail(error, "SnapshotRecoveryMarkerInvalid");
    }
    proof.intent = std::move(intent);
    proof.accepted_sequence = tx.accepted_sequence;
    error.clear();
    return true;
}

bool BlockRetainedSnapshotRecovery(MountContext& ctx, const std::string& error)
{
    std::lock_guard<std::recursive_mutex> runtime(ctx.runtime_state_mutex);
    ctx.native_write_enabled = false;
    ctx.overlay_write_enabled = false;
    ctx.pending_native_writes = true;
    ctx.recovery_active = true;
    ctx.write_degraded = true;
    ctx.runtime_recovery_reason = Utf8ToWide(error);
    ctx.runtime_last_recovery_action = L"SnapshotRecoveryBlocked";
    return false;
}

bool CompleteRetainedSnapshotRecovery(MountContext& ctx,
    apfsaccess::catalog::ContainerMountCoordinator& coordinator,
    const RetainedSnapshotRecoveryProof& proof, std::string& error)
{
    const auto marks = ctx.tx_manager->Watermarks();
    std::vector<apfsaccess::rw::TransactionManager::AcceptedTransaction> suffix;
    std::vector<std::uint64_t> pins;
    if (!proof.intent || marks.accepted_sequence != proof.accepted_sequence ||
        marks.accepted_sequence != marks.apfs_durable_sequence || marks.accepted_sequence != marks.cleanup_sequence ||
        !ctx.tx_manager->ValidatedCleanJournalGeneration() || !ctx.tx_manager->CanClearRecoveryState() ||
        !ctx.tx_manager->LoadAcceptedTransactionsSinceCleanup(suffix, &error) || !suffix.empty() ||
        !ctx.tx_manager->LoadRequiredCheckpointXidsSinceCleanup(pins, &error) || !pins.empty())
        return SnapshotRecoveryFail(error, "SnapshotRecoveryJournalCompletionFailed");
    for (const auto& entry : coordinator.CheckpointCensusSnapshot())
        if (entry.unapplied_accepted_work || !entry.required_checkpoint_xids.empty())
            return SnapshotRecoveryFail(error, "SnapshotRecoveryCensusCompletionFailed");
    LiveSnapshotInventory current;
    if (!InspectImageSnapshotSession(ctx, coordinator, &current, error, false) ||
        current.scope.checkpoint_xid != proof.intent->scope.checkpoint_xid + 1 ||
        !apfsaccess::rw::VerifyPublishedSnapshot(*ctx.metadata_store, *proof.intent, error) ||
        !SnapshotRecoveryStoreClean(*ctx.metadata_store) || !SnapshotRecoveryHostIdle(ctx))
        return SnapshotRecoveryFail(error, "SnapshotRecoveryCheckpointCompletionFailed");
    apfsaccess::rw::BlockDevice::StableImageIdentity held;
    if (!ctx.metadata_store->Device().QueryHeldImageIdentity(held) || held.volume_serial != proof.source.volume_serial ||
        held.file_id != proof.source.file_id || held.size_bytes != proof.source.size_bytes || held.creation_time != proof.source.creation_time)
        return SnapshotRecoveryFail(error, "SnapshotRecoverySourceChanged");
    const auto budget = std::make_shared<apfsaccess::catalog::ApfsReadBudget>(65536, 256ull * 1024 * 1024,
        1000000, 256ull * 1024 * 1024);
    for (const auto& entry : coordinator.CheckpointCensusSnapshot())
    {
        apfsaccess::rw::NativeApfsVolumeProjection graph;
        std::wstring detail;
        if (!apfsaccess::rw::NativeApfsReader::TryLoadVolumeProjection(ctx.metadata_store->Device(), entry.volume_object_id,
            graph, detail, current.scope.checkpoint_xid, budget) || graph.volume_object_id != entry.volume_object_id ||
            graph.checkpoint_xid != current.scope.checkpoint_xid)
            return SnapshotRecoveryFail(error, "SnapshotRecoveryCurrentRootGraphUnproven");
    }
    if (!FlushPayloadSpoolDirtyStateBestEffort(&ctx, L"SnapshotRecovery") || !SnapshotRecoverySpoolClean(ctx))
        return SnapshotRecoveryFail(error, "SnapshotRecoverySpoolCompletionFailed");
    if (!ctx.recovery_marker_file.empty())
    {
        RecoveryMarkerState clean{false, current.scope.checkpoint_xid}, readback;
        if (!PersistRecoveryMarkerState(&ctx, ctx.recovery_marker_file, clean) ||
            LoadRecoveryMarkerState(ctx.recovery_marker_file, readback) != RecoveryMarkerLoadStatus::Loaded ||
            readback.dirty || readback.last_commit_xid != clean.last_commit_xid)
            return SnapshotRecoveryFail(error, "SnapshotRecoveryMarkerCompletionFailed");
#ifdef APFSACCESS_FSHOST_UNIT_TEST
        if (ctx.test_force_snapshot_marker_readback_failure)
            return SnapshotRecoveryFail(error, "SnapshotRecoveryMarkerReadbackFailed");
#endif
    }
    std::lock_guard<std::recursive_mutex> runtime(ctx.runtime_state_mutex);
    ctx.pending_native_writes = false;
    ctx.recovery_active = false;
    ctx.write_degraded = false;
    ctx.runtime_recovery_reason.clear();
    ctx.runtime_last_recovery_action = L"SnapshotRecovered";
    ctx.runtime_last_commit_xid = current.scope.checkpoint_xid;
    ctx.native_write_enabled = true;
    ctx.overlay_write_enabled = false;
    ctx.snapshot_recovery_completion_intent.reset();
    ctx.snapshot_recovery_completion_sequence = 0;
    ctx.snapshot_recovery_completion_clean_generation = 0;
    return true;
}

bool ReplayRetainedImageSnapshotForRecovery(MountContext& ctx,
    apfsaccess::catalog::ContainerMountCoordinator& coordinator,
    const RetainedSnapshotRecoveryProof& proof, std::string& error)
{
    if (!proof.intent) return true;
    // Completion is the sole writer restoration authority, including when an
    // enabled ReplayIfSafe bootstrap enters this adapter.
    ctx.native_write_enabled = false;
    ctx.overlay_write_enabled = false;
    if (!FlushPayloadSpoolDirtyStateBestEffort(&ctx, L"SnapshotRecovery"))
    { error = "SnapshotRecoverySpoolFlushFailed"; return BlockRetainedSnapshotRecovery(ctx, error); }
    bool replayed = proof.completion_retry;
    if (!proof.completion_retry)
    {
        ctx.snapshot_recovery_completion_intent = proof.intent;
        ctx.snapshot_recovery_completion_source = proof.source;
        ctx.snapshot_recovery_completion_sequence = proof.accepted_sequence;
        replayed = apfsaccess::rw::ReplaySnapshot(coordinator, *ctx.tx_manager, ctx.container_volume_oid, error).value_or(false);
        if (replayed) ctx.snapshot_recovery_completion_clean_generation = ctx.tx_manager->ValidatedCleanJournalGeneration();
    }
    if (!replayed || !CompleteRetainedSnapshotRecovery(ctx, coordinator, proof, error))
    {
        if (error.empty()) error = "SnapshotRecoverFailed";
        return BlockRetainedSnapshotRecovery(ctx, error);
    }
    return true;
}

std::optional<bool> ReplayIsolatedSnapshotAfterMetadataBootstrap(MountContext& ctx)
{
    if (!ctx.container_coordinator || !ctx.tx_manager) return std::nullopt;
    SnapshotControlLocks locks(ctx, true);
    if (!locks.acquired) { SetRuntimeRecoveryReason(ctx, L"SnapshotControlBusy"); return false; }
    std::string error;
    std::vector<apfsaccess::rw::TransactionManager::AcceptedTransaction> suffix;
    if (!ctx.tx_manager->LoadAcceptedTransactionsSinceCleanup(suffix, &error)) return false;
    bool found = false;
    for (const auto& tx : suffix) for (const auto& record : tx.mutations)
        found |= record.operation == apfsaccess::rw::WriteAheadLog::OperationKind::CreateSnapshot ||
            record.operation == apfsaccess::rw::WriteAheadLog::OperationKind::DeleteSnapshot;
    if (!found) return std::nullopt;
    if (!ctx.native_write_enabled || !IsCrashReplayModeReplayIfSafe(ctx.args.write_crash_replay_mode))
    {
        error = "SnapshotRecoveryExplicitControlRequired";
        return BlockRetainedSnapshotRecovery(ctx, error);
    }
    RetainedSnapshotRecoveryProof proof;
    if (!AdmitRetainedImageSnapshotRecovery(ctx, *ctx.container_coordinator, proof, error))
        return BlockRetainedSnapshotRecovery(ctx, error);
    return ReplayRetainedImageSnapshotForRecovery(ctx, *ctx.container_coordinator, proof, error);
}
