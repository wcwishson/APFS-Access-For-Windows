#pragma once
// Included inside the host implementation after the checkpoint/cleanup helpers.
// A clone is an isolated durable transaction. Generic replay cannot batch it or
// rebase its proof to a different checkpoint.
NTSTATUS BlockNativeCloneRecovery(MountContext& c, const wchar_t* reason)
{
    // Latch before allocating diagnostic strings or writing the marker. An
    // actual low-memory failure must still close both mutation routes.
    {
        std::lock_guard<std::recursive_mutex> runtime(c.runtime_state_mutex);
        c.native_write_enabled = false;
        c.overlay_write_enabled = false;
        c.write_degraded = true;
        c.recovery_active = true;
        c.pending_native_writes = true;
    }
    try
    {
        SetRuntimeRecoveryReason(c, reason);
        (void)UpdateRecoveryMarkerBestEffort(&c, true);
    }
    catch (...) { /* The accepted WAL remains startup recovery authority. */ }
    return STATUS_MEDIA_WRITE_PROTECTED;
}

bool VerifyAlreadyPublishedNativeClone(MountContext& c, const apfsaccess::rw::MetadataStore& live,
    const apfsaccess::rw::WriteAheadLog::Record& record, std::uint64_t preimage)
{
    // The frozen engine exposes its exact verifier through ReplayNativeClone.
    // Strictly exclude that API's only staging branch (checkpoint == preimage).
    // Called under metadata + commit ownership, so this branch cannot change
    // between the guard and replay. No store is retained beyond an owner hook.
    if (&live != c.metadata_store || live.CheckpointXid().value_or(0) <= preimage ||
        live.PendingMutationCount() != 0) return false;
    return c.metadata_store->ReplayNativeClone(record, preimage) ==
        apfsaccess::rw::MetadataStore::CloneReplay::AlreadyPublished;
}

std::optional<bool> ReplayIsolatedNativeClone(MountContext& c)
{
    using Store = apfsaccess::rw::MetadataStore;
    using Tx = apfsaccess::rw::TransactionManager;
    using Op = apfsaccess::rw::WriteAheadLog::OperationKind;
    try
    {
        std::vector<Tx::AcceptedTransaction> transactions;
        if (!c.tx_manager->LoadAcceptedTransactionsSinceCleanup(transactions))
            return std::nullopt; // Generic recovery reports invalid WAL.
        bool has_clone = false;
        for (const auto& tx : transactions)
            for (const auto& r : tx.mutations) has_clone |= r.operation == Op::CloneFile;
        if (!has_clone) return std::nullopt;
        const auto fail = [&](const wchar_t* reason) -> std::optional<bool> {
            (void)BlockNativeCloneRecovery(c, reason); return false;
        };
        if (transactions.size() != 1 ||
            transactions.front().mutations.size() != 1 ||
            c.metadata_store->PendingMutationCount() != 0)
            return fail(L"NativeCloneReplayRequiresIsolatedTransaction");
        const auto& tx = transactions.front();
        const auto& record = tx.mutations.front();
        bool published = false;
        if (IsManifestSession(&c))
        {
            // Register accepted debt before admission. Only the normal shared
            // commit owner may reload, stage or publish this volume's store.
            std::vector<std::uint64_t> pins; std::string error;
            if (!c.tx_manager->LoadRequiredCheckpointXidsSinceCleanup(pins, &error) ||
                !c.container_coordinator->UpdateRequiredCheckpointXids(c.container_volume_oid, pins, error, true))
                return fail(L"NativeCloneReplayManifestCensusFailed");
            Store::MutationRequest request;
            if (!Store::NativeCloneFromWal(record, request)) return fail(L"NativeCloneReplayManifestProofInvalid");
            std::lock_guard commit(c.commit_mutex);
            std::unique_lock reads(c.committed_read_gate);
            std::lock_guard metadata(c.metadata_mutex);
            if (!c.container_coordinator->RefreshSessionForRecovery(c.container_volume_oid, error))
                return fail(L"NativeCloneReplayManifestRefreshFailed");
            const apfsaccess::catalog::ContainerPostpublicationVerifierHook verify =
                [&](const Store& live, std::uint64_t, std::string& why) {
                    published = VerifyAlreadyPublishedNativeClone(c, live, record, tx.preimage_checkpoint_xid);
                    if (!published) why = "CloneReplayManifestPublicationUnproven";
                    return published;
                };
            if (c.metadata_store->CheckpointXid() == tx.preimage_checkpoint_xid)
            {
                const auto result = CommitManifestMutations(&c, {request}, {}, {}, true,
                    tx.preimage_checkpoint_xid, {}, verify);
                published = result.status == Store::CommitStatus::Committed && published && !result.recovery_required;
            }
            else
            {
                // Same read-only retained-history verification used by ordinary
                // startup replay, after the owner refreshed the selected store.
                // The selected metadata gate and unresolved census prohibit an
                // ordinary successor until durable cleanup releases the pins.
                published = VerifyAlreadyPublishedNativeClone(c, *c.metadata_store, record, tx.preimage_checkpoint_xid);
            }
        }
        else
        {
            std::lock_guard commit(c.commit_mutex);
            std::unique_lock reads(c.committed_read_gate);
            std::lock_guard metadata(c.metadata_mutex);
            std::vector<std::uint64_t> pins;
            std::string error;
            if (LoadDirectCheckpointPinsLocked(c, pins, error) &&
                c.metadata_store->ValidateRequiredRecoveryCheckpoints(pins, error))
            {
                const auto replay = c.metadata_store->ReplayNativeClone(record, tx.preimage_checkpoint_xid);
                published = replay == Store::CloneReplay::AlreadyPublished;
                if (replay == Store::CloneReplay::Staged)
                    published = c.metadata_store->CommitCanonicalTransaction(pins) == Store::CommitStatus::Committed &&
                        c.metadata_store->ReplayNativeClone(record, tx.preimage_checkpoint_xid) == Store::CloneReplay::AlreadyPublished;
            }
        }
        if (!published) return fail(L"NativeCloneReplayPublicationUnproven");
        // Publication or allocation failure in the host index retains the WAL
        // and checkpoint proof. Never clean evidence for an absent host target.
        if (!MergeCommittedInodeStateIntoNodeIndex(&c))
            return fail(L"NativeCloneReplayNamespacePublicationFailed");
        bool marked = false;
        {
            std::lock_guard tx_lock(c.tx_mutex);
            marked = c.tx_manager->MarkApfsDurableThrough(tx.accepted_sequence);
        }
        if (!marked) return fail(L"NativeCloneReplayDurableWatermarkFailed");
        bool cleaned = false;
        if (!CleanupDurableJournalPrefixBestEffort(c, cleaned))
            return fail(L"NativeCloneReplayCleanupFailed");
        c.runtime_last_commit_xid = c.metadata_store->LastCommittedXid();
        if (!UpdateRecoveryMarkerBestEffort(&c, false))
            return fail(L"NativeCloneReplayMarkerFailed");
        {
            std::lock_guard<std::recursive_mutex> runtime(c.runtime_state_mutex);
            c.pending_native_writes = false;
            c.recovery_active = false;
            c.write_degraded = false;
            c.runtime_recovery_reason.clear();
            c.runtime_last_recovery_action = L"NativeCloneReplayApplied";
        }
        return true;
    }
    catch (...)
    {
        (void)BlockNativeCloneRecovery(c, L"NativeCloneReplayException");
        return false;
    }
}
