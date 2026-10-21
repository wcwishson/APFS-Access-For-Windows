#pragma once

constexpr std::uint64_t kFreshFileCohortLimit = 1ull << 20;

bool IsFreshFileCohortEnabled()
{
    wchar_t value[2]{};
    return IsManifestWriteBatchingEnabled() &&
        GetEnvironmentVariableW(L"APFSACCESS_DEFER_FRESH_FILE_COHORT", value, 2) == 1 && value[0] == L'1';
}

bool FreshFileCohortStoreIsClean(const apfsaccess::rw::MetadataStore& store)
{
    return store.AuthoritativeAppleCheckpointView() && store.IsNativeWriteReady() && !store.IsRecoveryRequired() &&
        store.PendingMutationCount() == 0 && store.PendingAllocationCount() == 0 &&
        store.PendingDeallocationCount() == 0 && store.PendingObjectMapUpdateCount() == 0 &&
        store.PendingBtreeRecordCount() == 0 && store.PendingPayloadByteEstimate() == 0 &&
        !store.HasUncommittedAllocatorState();
}

bool FreshFileCohortHandleEligible(MountContext* c, OpenContext* o, bool cleanup_allocation)
{
    std::lock_guard<std::mutex> lock(c->mutex);
    return o && o->node && !o->named_stream && !o->native_xattr &&
        (!o->cleanup_seen || cleanup_allocation) && o->node->node_kind == NodeKind::RegularFile &&
        !o->node->is_directory && !o->node->shared_payload && !o->node->namespace_detached &&
        !o->node->delete_pending && !o->delete_on_cleanup && !o->delete_on_close_requested &&
        !o->pending_overwrite_supersede && (cleanup_allocation || !IsHydrationStaleLocked(c, o->node));
}

ManifestWriteBatchResult AcceptQueuedFreshFileCohortWithWalBestEffort(
    MountContext* c, OpenContext* o,
    const std::vector<apfsaccess::rw::MetadataStore::MutationRequest>& expected,
    ManifestFreshFileAdmission admission, apfsaccess::rw::MetadataStore::PayloadIdentity& identity)
{
    using Result = ManifestWriteBatchResult;
    using Tx = apfsaccess::rw::TransactionManager;
    {
        std::lock_guard<std::mutex> queue(c->manifest_queue_mutex);
        if (c->manifest_queued_requests != expected) return Result::NotEligible;
    }
    // Sibling drains may need this host's outer gates. Run before taking them.
    const auto sibling = DrainManifestSiblingAcceptedWrites(c);
    if (!NT_SUCCESS(sibling))
    {
        c->manifest_preaccept_failure_status.store(sibling, std::memory_order_release);
        (void)DrainManifestRequests(c);
        return Result::Failed;
    }
    {
        std::lock_guard<std::mutex> metadata(c->metadata_mutex);
        auto& store = *c->metadata_store;
        if (admission.creating)
        {
            if (!FreshFileCohortStoreIsClean(store) || store.LookupWorkingInodeByPath(admission.cohort.path) ||
                store.LookupCommittedInodeByPath(admission.cohort.path)) return Result::NotEligible;
            // The coordinator may refresh this clean borrowed store after a
            // sibling publication. Bind the initial source in its WAL hook.
        }
        else if (!store.PendingFreshFileCohortMatches(admission.cohort)) return Result::NotEligible;
        std::lock_guard<std::mutex> tx(c->tx_mutex);
        if (c->tx_manager->CurrentState() != Tx::State::Idle || !c->tx_manager->RecoveryStateValid())
            return Result::NotEligible;
        const auto marks = c->tx_manager->Watermarks();
        if (admission.creating)
        {
            if (c->tx_manager->HasUnappliedAcceptedWork() || marks.accepted_sequence != marks.apfs_durable_sequence ||
                marks.apfs_durable_sequence != marks.cleanup_sequence) return Result::NotEligible;
        }
        else
        {
            std::vector<std::uint64_t> pins;
            std::string error;
            if (!c->tx_manager->HasUnappliedAcceptedWork() ||
                !c->tx_manager->LoadRequiredCheckpointXidsSinceCleanup(pins, &error) ||
                std::find(pins.begin(), pins.end(), admission.cohort.source_checkpoint) == pins.end())
                return Result::NotEligible;
        }
    }
    const auto result = AcceptManifestBatchWithWalBestEffort(c, DrainManifestRequests(c), 0,
        admission.creating ? L"ManifestFreshCreate" : L"ManifestFreshResize", nullptr, &identity, &admission);
    if (result == Result::Accepted && admission.creating)
    {
        admission.cohort.identity = identity;
        o->fresh_file_cohort = std::move(admission.cohort);
    }
    // Failed acceptance is never retried through synchronous fallback.
    return result;
}

ManifestWriteBatchResult AcceptQueuedFreshCreateWithWalBestEffort(
    MountContext* c, OpenContext* o, const std::wstring& path, const std::vector<std::byte>& security,
    bool attributes_changed, UINT32 attributes, const std::vector<std::byte>& times,
    std::uint64_t allocation, apfsaccess::rw::MetadataStore::PayloadIdentity& identity)
{
    using Store = apfsaccess::rw::MetadataStore;
    using Op = Store::MutationOperation;
    if (!IsFreshFileCohortEnabled() || !IsManifestSession(c) || !IsNativeWriteEnabled(c) ||
        !c->metadata_store || !c->tx_manager || !c->payload_spool ||
        allocation > kFreshFileCohortLimit || times.empty() ||
        security.size() > apfsaccess::rw::WriteAheadLog::MaxInlinePayloadBytes ||
        !FreshFileCohortHandleEligible(c, o, false)) return ManifestWriteBatchResult::NotEligible;
    ManifestFreshFileAdmission admission;
    admission.creating = true;
    admission.cohort.path = path;
    std::vector<Store::MutationRequest> expected{NativeCallbackRequest(Op::CreateFile, path)};
    if (!security.empty()) expected.push_back(NativeCallbackRequest(Op::SetExtendedAttribute, path,
        security.size(), 0, kWindowsSecurityNameWide, security));
    if (attributes_changed)
    {
        const auto payload = EncodeWindowsAttributes(attributes);
        expected.push_back(NativeCallbackRequest(Op::SetExtendedAttribute, path,
            payload.size(), 0, kWindowsAttributesNameWide, payload));
    }
    admission.cohort.initial_attributes.assign(expected.begin() + 1, expected.end());
    expected.push_back(NativeCallbackRequest(Op::SetInodeMetadata, path, times.size(), 0, L"", times));
    if (allocation) expected.push_back(NativeCallbackRequest(Op::SetAllocationSize, path, allocation));
    return AcceptQueuedFreshFileCohortWithWalBestEffort(c, o, expected, std::move(admission), identity);
}

ManifestWriteBatchResult AcceptQueuedFreshResizeWithWalBestEffort(
    MountContext* c, OpenContext* o, const std::wstring& path, std::uint64_t size,
    bool allocation, bool cleanup_allocation, bool capture_times, FILETIME timestamp,
    apfsaccess::rw::MetadataStore::PayloadIdentity& identity)
{
    using Op = apfsaccess::rw::MetadataStore::MutationOperation;
    if (!IsFreshFileCohortEnabled() || !IsManifestSession(c) || !IsNativeWriteEnabled(c) ||
        !c->metadata_store || !c->tx_manager || !c->payload_spool || !o || !o->fresh_file_cohort ||
        cleanup_allocation || size > kFreshFileCohortLimit || o->fresh_file_cohort->path != path ||
        !FreshFileCohortHandleEligible(c, o, cleanup_allocation)) return ManifestWriteBatchResult::NotEligible;
    {
        std::lock_guard<std::mutex> lock(c->mutex);
        if (o->node->object_id != o->fresh_file_cohort->identity.object_id || size < o->node->file_size)
            return ManifestWriteBatchResult::NotEligible;
    }
    auto expected = NativeContentCallbackRequests(path, false, 0, capture_times, timestamp);
    expected.push_back(NativeCallbackRequest(allocation ? Op::SetAllocationSize : Op::SetFileSize, path, size));
    return AcceptQueuedFreshFileCohortWithWalBestEffort(c, o, expected,
        ManifestFreshFileAdmission{*o->fresh_file_cohort, false}, identity);
}
