#pragma once

#ifdef APFSACCESS_FSHOST_UNIT_TEST
std::function<void(MountContext*)> g_compressed_after_publication_hook;
// Runs at the actual coordinator verification boundary, before Replay reads
// native evidence. Tests may corrupt published bytes, never force a result.
#ifdef APFSACCESS_HAS_RW_ENGINE
std::function<void(const apfsaccess::rw::MetadataStore&)> g_compressed_manifest_before_verification_hook;
#endif
bool g_compressed_refuse_publication_proof = false;
#endif

// Included after the host's mutation, journal and publication helpers.
bool CanOpenNativeCompressionRewrite(MountContext* c, const std::shared_ptr<Node>& node)
{
#ifdef APFSACCESS_HAS_RW_ENGINE
    if (!c || !node || !node->file_size || !c->metadata_store || !c->tx_manager || !c->payload_spool ||
        !IsNativeWriteEnabled(c) || HasBlockedRecoveryEvidence(*c)) return false;
    const auto path = SnapshotMutationPathForNode(c, *node);
    if (path.empty()) return false;
    std::shared_lock<std::shared_mutex> gate(c->committed_read_gate);
    std::lock_guard<std::mutex> metadata(c->metadata_mutex);
    if (IsManifestSession(c))
    {
        // Open is only a bounded candidate check. Do not capture conversion
        // evidence from a borrowed store before the coordinator reloads it.
        if (!c->metadata_store->Device().IsRegularFile() ||
            node->file_size > apfsaccess::rw::CompressionRewrite::MaxLogicalBytes) return false;
        return c->metadata_store->HasSupportedCompressionRewriteHeader(node->object_id, node->file_size);
    }
    apfsaccess::rw::MetadataStore::MutationRequest proof;
    return c->metadata_store->Device().IsRegularFile() &&
        c->metadata_store->PrepareCompressionRewrite(path, proof) && proof.object_id == node->object_id;
#else
    return false;
#endif
}

NTSTATUS WriteNativeCompressedContentImpl(MountContext* c, OpenContext* o, const std::wstring& path,
    const void* bytes, std::uint64_t offset, ULONG length, PULONG done, FSP_FSCTL_FILE_INFO* info)
{
#ifdef APFSACCESS_HAS_RW_ENGINE
    using Store = apfsaccess::rw::MetadataStore;
    using Tx = apfsaccess::rw::TransactionManager;
    using Preparation = apfsaccess::fshost::NativeCompressionRewrite;
    using Replay = apfsaccess::fshost::NativeCompressionReplay;
    // CB_Write owns MutationCallbackScope throughout. Manifest preparation and
    // verification additionally run under the existing container commit owner.
    if (!c || !o || !o->node || !bytes || !length || !done || path.empty() ||
        o->named_stream || !c->metadata_store || !c->tx_manager ||
        !c->payload_spool || !IsNativeWriteEnabled(c) || HasBlockedRecoveryEvidence(*c)) return STATUS_NOT_SUPPORTED;
    *done = 0;
    if (offset > o->node->file_size || length > o->node->file_size - offset ||
        !CanOpenNativeCompressionRewrite(c, o->node)) return STATUS_NOT_SUPPORTED;
    UINT32 archive = 0;
    bool archive_changed = false;
    const auto attributes = PrepareWindowsAttributeUpdate(c, o->node, FILE_ATTRIBUTE_ARCHIVE, false, archive, archive_changed);
    if (!NT_SUCCESS(attributes)) return attributes;
    if (archive_changed) return STATUS_NOT_SUPPORTED;
    if (IsManifestSession(c))
    {
        std::optional<Store::MutationRequest> older;
        {
            std::lock_guard<std::mutex> queue(c->manifest_queue_mutex);
            // A queued Write has no caller buffer here. Its original callback
            // must bind that payload; do not drain or discard it speculatively.
            for (const auto& request : c->manifest_queued_requests)
                if (request.operation == Store::MutationOperation::Write ||
                    request.operation == Store::MutationOperation::RewriteCompressedContent) return STATUS_DEVICE_BUSY;
            if (!c->manifest_queued_requests.empty()) older = c->manifest_queued_requests.back();
        }
        if (older)
        {
            const auto kind = ManifestJournalKindForOperation(older->operation);
            if (!kind) return STATUS_NOT_SUPPORTED;
            ManifestJournalExpectation boundary;
            boundary.kind = *kind; boundary.path = older->path; boundary.secondary_path = older->secondary_path;
            boundary.offset = older->offset; boundary.length = older->length;
            boundary.replace_if_exists = older->replace_if_exists; boundary.timestamp_utc = older->timestamp_utc;
            boundary.payload = older->inline_payload.data();
            boundary.payload_bytes = static_cast<std::uint32_t>(older->inline_payload.size());
            boundary.has_payload = true;
            ManifestCommitOutcome boundary_result;
            if (!CommitQueuedManifestMutationWithWalBestEffort(c, boundary,
                    L"CompressedOlderManifestBoundary", {}, {}, false, &boundary_result, true))
            {
                if (boundary_result.clean_prepublication_refusal)
                {
                    c->manifest_preaccept_failure_status.store(STATUS_SUCCESS, std::memory_order_release);
                    return CleanManifestRefusalStatus(boundary_result);
                }
                // The older batch may now own accepted evidence. A retry latch
                // must not bypass its admission block after binding/publication.
                c->manifest_preaccept_failure_status.store(STATUS_SUCCESS, std::memory_order_release);
                return BlockNativeMutationAfterStagingFailure(c, L"CompressedOlderManifestBoundary");
            }
        }
    }
    if (!IsManifestSession(c) || HasPendingNativeMutations(c))
    {
        const auto drain = CommitNativeMutationsOnFlushBestEffort(c);
        if (!NT_SUCCESS(drain)) return drain;
        if (!FinalizeMutationJournalBestEffort(c, L"CompressedWriteBoundary")) return STATUS_IO_DEVICE_ERROR;
    }
    const auto refreshed_attributes = PrepareWindowsAttributeUpdate(
        c, o->node, FILE_ATTRIBUTE_ARCHIVE, false, archive, archive_changed);
    if (!NT_SUCCESS(refreshed_attributes)) return refreshed_attributes;
    if (archive_changed) return STATUS_NOT_SUPPORTED;
    const auto capacity = EnsurePayloadSpoolCapacityBeforeNativeWriteBestEffort(c, length);
    if (capacity != PayloadSpoolCapacityOutcome::Ready)
        return capacity == PayloadSpoolCapacityOutcome::CapacityExceeded ? STATUS_DISK_FULL : STATUS_IO_DEVICE_ERROR;

    std::optional<Preparation> prepared;
    std::uint64_t logical_eof = 0;
    Store::PayloadIdentity target;
    const auto timestamp = UtcNow();
    bool staged = false, accepted = false;
    std::uint64_t sequence = 0;
    bool verified = false;
    const auto proof = [&](const Store& store, std::string& error) {
        std::lock_guard<std::mutex> journal(c->tx_mutex);
        sequence = c->tx_manager->Watermarks().accepted_sequence;
        const auto result = Replay::Verify(store, *c->tx_manager, sequence,
            c->payload_spool.get(), c->payload_spool_volume_identity);
        verified = result == Replay::Result::Verified;
#ifdef APFSACCESS_FSHOST_UNIT_TEST
        verified = verified && !g_compressed_refuse_publication_proof;
#endif
        if (!verified) error = "CompressedPublicationProofFailed:" + std::to_string(static_cast<int>(result));
        return verified;
    };
    if (IsManifestSession(c))
    {
        // No native store reference or source proof crosses this boundary.
        // Keep WAL idle until the binder records the actual staged identities.
        {
            std::lock_guard<std::mutex> journal(c->tx_mutex);
            if (c->tx_manager->CurrentState() != Tx::State::Idle)
                return STATUS_DEVICE_BUSY;
        }
        std::optional<Store::MutationStatus> preparation_refusal;
        const apfsaccess::catalog::ContainerMutationPreparationHook prepare =
            [&](const Store& live, auto& requests, std::string& error) {
                Preparation::Admission admission;
                admission.native_writes_admitted = IsNativeWriteEnabled(c);
                admission.visibility_unresolved = c->write_degraded || c->unjournaled_native_mutation ||
                    HasBlockedRecoveryEvidence(*c);
                admission.manifest_session = true;
                admission.container_commit_owned = true;
                admission.windows_attributes_pending = archive_changed;
                admission.queued_requests = requests.size();
                admission.publication_budget_bytes = apfsaccess::rw::CompressionRewrite::MaxLogicalBytes;
                Preparation::Failure failure = Preparation::Failure::IdentityMismatch;
                std::lock_guard<std::mutex> journal(c->tx_mutex);
                const auto inode = live.LookupCommittedInodeByPath(path);
                std::optional<UINT32> live_attributes;
                if (!inode || !ReadWindowsAttributes(live.LookupCommittedExtendedAttribute(
                        inode->object_id, kWindowsAttributesName), live_attributes) ||
                    (live_attributes && !(*live_attributes & FILE_ATTRIBUTE_ARCHIVE)))
                {
                    error = "CompressedManifestArchiveUpdateRequired";
                    return false;
                }
                std::optional<Preparation> plan;
                if (inode && inode->object_id == o->node->object_id)
                    plan = Preparation::Prepare(live, *c->tx_manager, admission, path,
                        {inode->object_id, inode->xid}, offset, length, failure);
                if (!plan || plan->Revalidate(live, *c->tx_manager, admission) != Preparation::Failure::None)
                {
                    if (!plan && (failure == Preparation::Failure::SourceUnsupported ||
                        failure == Preparation::Failure::RangeUnsupported))
                        preparation_refusal = Store::MutationStatus::UnsupportedOperation;
                    error = "CompressedManifestPreparationRefused:" + std::to_string(static_cast<int>(failure));
                    return false;
                }
                // The native staging guards and source-aware WAL binder check
                // this successor against all three ACTUAL staged identities.
                target = {plan->Request().object_id, plan->PreimageCheckpoint() + 1};
                logical_eof = plan->LogicalEof();
                if (!plan->BuildRequests(EncodeContentTimes(timestamp), requests))
                {
                    error = "CompressedManifestJournalCapacity";
                    return false;
                }
                return true;
            };
        const apfsaccess::catalog::ContainerPostpublicationVerifierHook verify =
            [&](const Store& live, std::uint64_t xid, std::string& error) {
#ifdef APFSACCESS_FSHOST_UNIT_TEST
                if (g_compressed_manifest_before_verification_hook)
                    g_compressed_manifest_before_verification_hook(live);
#endif
                if (xid != target.generation) { error = "CompressedManifestPublishedIdentityMismatch"; return false; }
                return proof(live, error);
            };
        // Set the OID before entering the publication funnel. The builder does
        // not mutate host state or publish a marker, and a clean refusal below
        // can disarm this guard without touching older work.
        c->compression_verification_pending.store(o->node->object_id, std::memory_order_release);
        ManifestJournalExpectation expectation;
        expectation.path = path; expectation.offset = offset; expectation.length = length;
        expectation.payload = bytes; expectation.payload_bytes = length; expectation.has_payload = true;
        ManifestCommitOutcome manifest_result;
        accepted = CommitQueuedManifestMutationWithWalBestEffort(
            c, expectation, L"CompressedManifestWrite", prepare, verify, true, &manifest_result, false, &preparation_refusal);
        if (!accepted || !verified)
        {
            bool empty = false;
            {
                std::lock_guard<std::mutex> journal(c->tx_mutex);
                empty = c->tx_manager->RecoveryStateValid() && !c->tx_manager->HasUnappliedAcceptedWork() &&
                    c->tx_manager->CurrentState() == Tx::State::Idle && !c->tx_manager->PendingMutationCount();
            }
            if (manifest_result.clean_prepublication_refusal && empty && !HasBlockedRecoveryEvidence(*c))
            {
                c->compression_verification_pending.store(0, std::memory_order_release);
                c->manifest_preaccept_failure_status.store(STATUS_SUCCESS, std::memory_order_release);
                return CleanManifestRefusalStatus(manifest_result);
            }
            // Never let the ordinary retryable preaccept latch mask accepted
            // compression debt or a failure after actual publication.
            c->manifest_preaccept_failure_status.store(STATUS_SUCCESS, std::memory_order_release);
            return BlockNativeMutationAfterStagingFailure(c, L"CompressedManifestPublication");
        }
    }
    else
    {
    {
        std::unique_lock<std::mutex> commit(c->commit_mutex);
        std::unique_lock<std::shared_mutex> gate(c->committed_read_gate);
        std::unique_lock<std::mutex> metadata(c->metadata_mutex);
        auto& store = *c->metadata_store;
        Preparation::Admission admission;
        admission.native_writes_admitted = IsNativeWriteEnabled(c);
        admission.visibility_unresolved = c->write_degraded || c->unjournaled_native_mutation ||
            HasBlockedRecoveryEvidence(*c);
        admission.manifest_session = false;
        admission.journal_begin_deferred = true;
        admission.windows_attributes_pending = archive_changed;
        admission.publication_budget_bytes = apfsaccess::rw::CompressionRewrite::MaxLogicalBytes;
        Preparation::Failure failure;
        {
            std::lock_guard<std::mutex> journal(c->tx_mutex);
            auto& tx = *c->tx_manager;
            if (tx.CurrentState() != Tx::State::Idle) return STATUS_DEVICE_BUSY;
            const auto inode = store.LookupCommittedInodeByPath(path);
            if (inode && inode->object_id == o->node->object_id)
                prepared = Preparation::Prepare(store, tx, admission, path,
                    {inode->object_id, inode->xid}, offset, length, failure);
            if (!prepared || prepared->Revalidate(store, tx, admission) != Preparation::Failure::None)
            {
                return STATUS_NOT_SUPPORTED;
            }
        }
        std::vector<Store::MutationRequest> requests;
        if (!prepared->BuildRequests(EncodeContentTimes(timestamp), requests)) return STATUS_NOT_SUPPORTED;
        const auto admission_status = PreflightDirectCallbackLocked(c, requests);
        if (!NT_SUCCESS(admission_status))
        {
            metadata.unlock(); gate.unlock(); commit.unlock();
            return admission_status == STATUS_IO_DEVICE_ERROR
                ? BlockNativeMutationAfterStagingFailure(c, L"CompressedCapacityAdmission") : admission_status;
        }
        {
            std::lock_guard<std::mutex> journal(c->tx_mutex);
            // Revalidate the idle proof after preview rollback, before the first
            // WAL append. Begin only once the complete conversion was admitted.
            if (prepared->Revalidate(store, *c->tx_manager, admission) != Preparation::Failure::None)
                return STATUS_IO_DEVICE_ERROR;
            if (!c->tx_manager->Begin()) return STATUS_DEVICE_BUSY;
            admission.journal_begin_deferred = false;
            prepared = Preparation::Prepare(store, *c->tx_manager, admission, path,
                {requests.front().object_id, requests.front().generation}, offset, length, failure);
            if (!prepared) { (void)c->tx_manager->Abort(); return STATUS_NOT_SUPPORTED; }
        }
        if (!UpdateRecoveryMarkerBestEffort(c, true))
        {
            std::lock_guard<std::mutex> journal(c->tx_mutex);
            (void)c->tx_manager->Abort();
            return STATUS_IO_DEVICE_ERROR;
        }
        const auto& conversion = prepared->Request();
        logical_eof = prepared->LogicalEof();
        c->compression_verification_pending.store(conversion.object_id, std::memory_order_release);
        staged = store.StageMutation(conversion, &target) == Store::MutationStatus::Applied;
        const Store::PayloadIdentity source{conversion.object_id, conversion.generation};
        bool recorded = staged && RecordMutationBestEffort(c, Tx::MutationKind::RewriteCompressedContent,
            path, L"", 0, conversion.inline_payload.size(), false, 0, 0, &source, nullptr, conversion.inline_payload);
        const auto& times = requests[1];
        recorded = recorded && store.StageMutation(times) == Store::MutationStatus::Applied &&
            RecordMutationBestEffort(c, Tx::MutationKind::SetInodeMetadata, path, L"", 0,
                times.length, false, 0, 0, &target, nullptr, times.inline_payload);
        Store::MutationRequest write;
        recorded = recorded && prepared->PrepareWrite(store, target, path, offset, length, write) &&
            store.StageMutation(write) == Store::MutationStatus::Applied &&
            RecordPayloadWriteMutationBestEffort(c, path, offset, bytes, length, &target);
        if (recorded && c->payload_spool->FlushDirtyState())
        {
            std::lock_guard<std::mutex> journal(c->tx_mutex);
            accepted = c->tx_manager->Accept(prepared->PreimageCheckpoint());
            sequence = c->tx_manager->Watermarks().accepted_sequence;
        }
    }
    if (!accepted || !sequence) return BlockNativeMutationAfterStagingFailure(c, L"CompressedWrite", staged);
    const auto publication = CommitNativeMutationsBestEffort(c, L"CompressedWrite", {}, proof);
    if (!NT_SUCCESS(publication) || !verified)
    {
        (void)BlockNativeMutationAfterStagingFailure(c, L"CompressedPublicationVerification");
        return NT_SUCCESS(publication) ? STATUS_IO_DEVICE_ERROR : publication;
    }
    }
#ifdef APFSACCESS_FSHOST_UNIT_TEST
    if (g_compressed_after_publication_hook) g_compressed_after_publication_hook(c);
#endif
    InvalidatePayloadIdentityCache(c);
    InvalidateHydrationReadHandle(c);
    {
        std::lock_guard<std::mutex> lock(c->mutex);
        SetVisiblePayloadMetadataLocked(o->node, logical_eof, timestamp);
        o->node->times_generation = target.generation;
        if (o->node->shared_payload) o->node->shared_payload->materialized_generation = 0;
        MarkHydrationStaleLocked(c, o->node);
        if (info) FillInfo(*o->node, ReportsReadOnly(c), info);
    }
    // Compressed DEFAULT opens deliberately have no cache handles. Materialize
    // their ordinary payload once before admitting subsequent alias edits.
    const auto epoch = c->payload_identity_cache_epoch.load(std::memory_order_acquire);
    if (!TryHydrateFromCurrentPayloadOverlay(c, o->node, epoch, false, true))
        return BlockNativeMutationAfterStagingFailure(c, L"CompressedPayloadMaterialization");
    // Existing finalizers refuse a nonzero guard. Only this ordered callback
    // may disarm it after proof/materialization, and every failed exit rearms it.
    c->compression_verification_pending.store(0, std::memory_order_release);
    bool finalized = false;
    try { finalized = FinalizeMutationJournalBestEffort(c, L"CompressedWrite"); }
    catch (...)
    {
        c->compression_verification_pending.store(target.object_id, std::memory_order_release);
        throw;
    }
    if (!finalized)
    {
        c->compression_verification_pending.store(target.object_id, std::memory_order_release);
        return BlockNativeMutationAfterStagingFailure(c, L"CompressedJournalFinalization");
    }
    *done = length;
    MarkOpenContextMutation(o);
    return STATUS_SUCCESS;
#else
    return STATUS_NOT_SUPPORTED;
#endif
}

NTSTATUS WriteNativeCompressedContent(MountContext* c, OpenContext* o, const std::wstring& path,
    const void* bytes, std::uint64_t offset, ULONG length, PULONG done, FSP_FSCTL_FILE_INFO* info)
{
    try { return WriteNativeCompressedContentImpl(c, o, path, bytes, offset, length, done, info); }
    catch (...)
    {
        if (done) *done = 0;
#ifdef APFSACCESS_HAS_RW_ENGINE
        // No exception may cross WinFsp with a silently staged or accepted edit.
        const bool staged = c && HasPendingNativeMutations(c);
        if (staged || (c && (HasUnappliedAcceptedWorkBestEffort(c) ||
                c->compression_verification_pending.load(std::memory_order_acquire))))
            return BlockNativeMutationAfterStagingFailure(c, L"CompressedWriteException", staged);
        if (c && c->tx_manager)
        {
            std::lock_guard<std::mutex> journal(c->tx_mutex);
            if (c->tx_manager->CurrentState() == apfsaccess::rw::TransactionManager::State::Active)
                (void)c->tx_manager->Abort();
        }
#endif
        return STATUS_INSUFFICIENT_RESOURCES;
    }
}
