#pragma once

// Included after the ordinary Windows metadata staging helpers in main.cpp.
// Queue ownership: mutation_callback_mutex -> short mutex / metadata_mutex
// sections, released before staging or publication. Scheduler state alone uses
// deferred_commit_mutex. No retained paths or unbound durable records.
constexpr std::size_t kDeferredAccessTimeMaxInodes = 512;
constexpr std::chrono::milliseconds kDeferredAccessTimeIdleDelay{250};
constexpr std::chrono::milliseconds kDeferredAccessTimeMaximumDelay{2000};

NTSTATUS DrainDeferredAccessTimeBatch(MountContext* c)
{
#ifdef APFSACCESS_HAS_RW_ENGINE
    if (!c || c->draining_access_times || c->deferred_access_times.empty()) return STATUS_SUCCESS;
    if (!IsNativeMutationWriteEnabled(c) || HasBlockedRecoveryEvidence(*c))
    {
        std::lock_guard<std::mutex> schedule(c->deferred_commit_mutex);
        c->deferred_access_time_requested = false;
        return STATUS_MEDIA_WRITE_PROTECTED;
    }
    // Admit one bounded worker batch before staging. Stop and admission share
    // the scheduler lock: a later stop lets this batch finish, while a stop
    // that won first leaves the queue intact for the final shutdown drain.
    LatencySpan batch(TraceFor(c), "atime.batch", {c->deferred_access_times.size(),
        c->deferred_access_time_overflow, deferred_commit_worker_context == c});
    const bool worker_batch = deferred_commit_worker_context == c;
    ScopeExit release_admission{[&] {
        if (worker_batch) admitted_worker_atime_context = nullptr;
    }};
    if (worker_batch)
    {
        std::lock_guard<std::mutex> schedule(c->deferred_commit_mutex);
        if (c->deferred_commit_thread_stop) return STATUS_DEVICE_BUSY;
        admitted_worker_atime_context = c;
    }
    c->draining_access_times = true;
    ScopeExit finish{[&] { c->draining_access_times = false; }};
    const auto fail = [&](bool unjournaled = false) {
        const auto status = BlockNativeMutationAfterStagingFailure(c, L"DeferredAccessTime", unjournaled);
        if (status != STATUS_DEVICE_BUSY && status != STATUS_DISK_FULL)
        {
            // Keep both queue and visible values for diagnosis. Accepted WAL,
            // spool, census and checkpoint pins remain owned by existing code.
            std::lock_guard<std::mutex> schedule(c->deferred_commit_mutex);
            c->deferred_access_time_requested = false;
        }
        return status;
    };

    // Preserve the older data transaction's boundary before forming this batch.
    // Never append atime to an unresolved data/namespace transaction.
    if (HasPendingNativeMutations(c))
    {
        const auto status = DrainNativeMutationsByPolicy(c, L"Flush");
        if (!NT_SUCCESS(status) || !FinalizeMutationJournalBestEffort(c, L"DeferredAccessTimePrior"))
            return fail();
    }

    struct Request
    {
        std::wstring path;
        std::vector<std::byte> payload;
        std::uint64_t object = 0;
    };
    std::vector<Request> requests;
    requests.reserve(c->deferred_access_times.size());
    for (const auto& [object, entry] : c->deferred_access_times)
    {
        Request request;
        request.object = object;
        {
            std::lock_guard<std::mutex> names(c->mutex);
            if (entry.node && entry.node->object_id == object && entry.node->shared_payload == entry.owner &&
                (!entry.owner || entry.owner->object_id == object))
                request.path = CurrentDataPathForNodeLocked(c, *entry.node);
        }
        // A missing/replaced identity is not permission to restore the old
        // pathname. Normal namespace mutations drain before making any change.
        bool same_identity = false;
        if (!request.path.empty())
        {
            std::lock_guard<std::mutex> metadata(c->metadata_mutex);
            const auto inode = c->metadata_store->LookupWorkingInodeByPath(request.path);
            same_identity = inode && inode->object_id == object;
        }
        if (!same_identity)
        {
            {
                std::lock_guard<std::recursive_mutex> runtime(c->runtime_state_mutex);
                c->last_native_mutation_failure_operation = L"DeferredAccessTime";
                c->last_native_mutation_failure_path = request.path;
                c->last_native_mutation_failure_reason = L"DeferredAccessTimeIdentityMismatch";
                c->last_native_mutation_failure_status = std::to_wstring(object);
            }
            return fail();
        }
        apfsaccess::rw::InodeMetadataPatch patch;
        patch.mask = apfsaccess::rw::InodeMetadataPatch::AccessTime;
        patch.access_time_utc = entry.time;
        if (!apfsaccess::rw::EncodeInodeMetadataPatch(patch, request.payload)) return fail();
        requests.push_back(std::move(request));
    }

    const bool manifest = IsManifestSession(c);
    const auto batch_limit = WindowsAttributeBatchLimit(c, requests.size());
    bool any_staged = false;
    for (std::size_t i = 0; i != requests.size(); ++i)
    {
        const auto& request = requests[i];
        apfsaccess::rw::MetadataStore::PayloadIdentity identity{};
        bool staged = false;
        const auto recorded = RecordNativeMutationBestEffort(c,
            apfsaccess::rw::MetadataStore::MutationOperation::SetInodeMetadata,
            request.path, L"", 0, request.payload.size(), false, 0,
            &identity, &staged, nullptr, batch_limit, request.payload, i == 0);
        any_staged |= staged;
        if (!recorded) return fail(any_staged);
        if (!manifest && (identity.object_id != request.object ||
            !RecordMutationBestEffort(c,
                apfsaccess::rw::TransactionManager::MutationKind::SetInodeMetadata,
                request.path, L"", 0, request.payload.size(), false, 0, 0, &identity, nullptr, request.payload)))
            return fail(true);
    }
#ifdef APFSACCESS_FSHOST_UNIT_TEST
    if (c->test_before_deferred_atime_publish) c->test_before_deferred_atime_publish();
#endif
    if (manifest)
    {
        // The ordinary binder validates the expectation, stages EVERY queued
        // request under the container coordinator, binds each resulting inode
        // identity to WAL, durably accepts and pins the preimage before publish.
        // Calling it once is essential: calling per request republishes per read.
        const auto& last = requests.back();
        if (!RecordMutationBestEffort(c,
            apfsaccess::rw::TransactionManager::MutationKind::SetInodeMetadata,
            last.path, L"", 0, last.payload.size(), false, 0, 0, nullptr, nullptr, last.payload))
            return fail();
    }
    else
    {
        const auto status = DrainNativeMutationsByPolicy(c, L"Flush");
        if (!NT_SUCCESS(status) || !FinalizeMutationJournalBestEffort(c, L"DeferredAccessTime"))
            return fail();
    }
    {
        std::lock_guard<std::mutex> names(c->mutex);
        for (const auto& [object, entry] : c->deferred_access_times)
        {
            auto times = VisibleInodeTimes(*entry.node);
            times.access_time_utc = entry.time;
            SetVisiblePayloadMetadataLocked(entry.node, entry.node->file_size, times);
            entry.node->deferred_access_time = 0;
            if (entry.owner)
            {
                entry.owner->deferred_access_time.store(0, std::memory_order_release);
                for (const auto& weak : entry.owner->aliases)
                    if (const auto alias = weak.lock(); alias && alias->shared_payload == entry.owner)
                        alias->deferred_access_time = 0;
            }
        }
    }
    c->deferred_access_times.clear();
#endif
    return STATUS_SUCCESS;
}

NTSTATUS DrainDeferredAccessTimes(MountContext* c)
{
    LatencySpan latency(TraceFor(c), "atime.drain");
#ifdef APFSACCESS_HAS_RW_ENGINE
    if (!c || c->draining_access_times) return STATUS_SUCCESS;
    do
    {
        if (c->deferred_access_time_overflow)
        {
            // A refused full batch keeps new times on existing indexed nodes.
            // Refill bounded batches without allocating a second unbounded queue.
            std::lock_guard<std::mutex> names(c->mutex);
            c->deferred_access_time_overflow = false;
            for (const auto& [path, node] : c->nodes)
            {
                if (!node || !node->object_id) continue;
                const auto owner = node->shared_payload;
                const auto time = owner ? owner->deferred_access_time.load(std::memory_order_acquire)
                    : node->deferred_access_time;
                if (!time || c->deferred_access_times.contains(node->object_id)) continue;
                if (c->deferred_access_times.size() == kDeferredAccessTimeMaxInodes)
                {
                    c->deferred_access_time_overflow = true;
                    continue;
                }
                c->deferred_access_times.emplace(node->object_id,
                    MountContext::DeferredAccessTime{node, owner, time});
            }
        }
        const auto status = DrainDeferredAccessTimeBatch(c);
        if (!NT_SUCCESS(status)) return status;
    } while (c->deferred_access_time_overflow);
    {
        std::lock_guard<std::mutex> schedule(c->deferred_commit_mutex);
        c->deferred_access_time_requested = false;
    }
    c->deferred_commit_cv.notify_all();
#endif
    return STATUS_SUCCESS;
}

bool TryDeferAutomaticAccessTime(MountContext* c, OpenContext* o)
{
#ifdef APFSACCESS_HAS_RW_ENGINE
    // Caller owns the mutation gate and external admission. Unsupported,
    // detached, overlay, legacy and mixed file-data cases retain the old callback.
    const bool regular_file = o->node->node_kind == NodeKind::RegularFile;
    // atime.decision args: reason, same-inode writers (including aliases),
    // global writers, older pending work, inode, regular. Reasons: 0 queued,
    // 1 policy (states unsampled), 2 kind, 3 identity, 4 writer, 5 alias
    // transition, 6 queued owner mismatch, 7 unbound manifest prefix.
    // Diagnostic storage is fixed-size.
    std::uint64_t inode_writers = 0;
    bool global_writers = false, pending = false;
    auto* trace = TraceFor(c);
    const auto decision = [&](std::uint64_t reason) {
        LatencySpan latency(trace, "atime.decision",
            {reason, inode_writers, global_writers, pending, o->node->object_id, regular_file});
        return reason == 0;
    };
    if (!IsDeferCloseCommitsEnabled() || !IsNativeMutationWriteEnabled(c) ||
        !c->tx_manager || !c->payload_spool || !ShouldCaptureNativeContentTimes(c) ||
        o->node->object_id == 0) return decision(1);
    if (regular_file || trace)
    {
        global_writers = HasOpenWriteHandles(c);
        // Preserve the short-circuit cost when diagnostics are disabled.
        if (!global_writers || trace) pending = HasPendingNativeMutations(c);
    }
    const bool isolate_regular_reader = regular_file && (global_writers || pending);
    // Only the ordinary binder can give queued manifest requests identities.
    // Bound older work uses the existing drain; unbound prefixes keep fallback.
    if (isolate_regular_reader && IsManifestSession(c) && ManifestQueuedRequestCount(c) != 0)
        return decision(7);
    bool directory_reader = false;
    bool force_drain = false;
    {
        std::lock_guard<std::mutex> names(c->mutex);
        const auto& node = o->node;
        directory_reader = node->node_kind == NodeKind::Directory;
        if (!regular_file && !directory_reader) return decision(2);
        // Metadata-only atime may follow unrelated work: the drain commits
        // that older prefix before staging. Keep same-inode writers and alias
        // transitions on the original callback path.
        if (node->namespace_detached || IsDeleteBlockedStateLocked(node) ||
            (node->shared_payload && node->shared_payload->object_id != node->object_id) ||
            TryGetNodeLockedNormalized(c, node->path) != node) return decision(3);
        if (regular_file)
        {
            inode_writers = node->write_handle_count;
            if (node->shared_payload)
                for (const auto& weak : node->shared_payload->aliases)
                    if (const auto alias = weak.lock(); alias && alias != node && alias->shared_payload == node->shared_payload)
                        inode_writers += alias->write_handle_count;
            if (inode_writers != 0) return decision(4);
            if (isolate_regular_reader && !node->committed_read_path.empty()) return decision(5);
            if (isolate_regular_reader && node->shared_payload)
                for (const auto& weak : node->shared_payload->aliases)
                    if (const auto alias = weak.lock(); alias &&
                        (alias->shared_payload != node->shared_payload || alias->object_id != node->object_id ||
                            alias->namespace_detached || IsDeleteBlockedStateLocked(alias) ||
                            !alias->committed_read_path.empty() || TryGetNodeLockedNormalized(c, alias->path) != alias))
                        return decision(5);
        }
        const auto found = c->deferred_access_times.find(node->object_id);
        if (found != c->deferred_access_times.end() && found->second.owner != node->shared_payload) return decision(6);
        const auto now = ToFileTimeValue(UtcNow());
        node->deferred_access_time = now;
        if (node->shared_payload) node->shared_payload->deferred_access_time.store(now, std::memory_order_release);
        if (found != c->deferred_access_times.end() || c->deferred_access_times.size() < kDeferredAccessTimeMaxInodes)
            c->deferred_access_times.insert_or_assign(node->object_id,
                MountContext::DeferredAccessTime{node, node->shared_payload, now});
        else
        {
            c->deferred_access_time_overflow = true;
            force_drain = true;
        }
    }
    {
        std::lock_guard<std::mutex> schedule(c->deferred_commit_mutex);
        const auto now = std::chrono::steady_clock::now();
        if (!c->deferred_access_time_requested) c->deferred_access_time_first = now;
        force_drain |= now >= c->deferred_access_time_first + kDeferredAccessTimeMaximumDelay;
        c->deferred_access_time_requested = true;
        c->deferred_access_time_deadline = (directory_reader || isolate_regular_reader) && force_drain ? now :
            (std::min)(now + kDeferredAccessTimeIdleDelay,
                c->deferred_access_time_first + kDeferredAccessTimeMaximumDelay);
    }
    c->deferred_commit_cv.notify_all();
    // Directory-list and isolated-reader Cleanup only wake the bounded worker,
    // including overflow and overdue debt. Preserve the quiet-volume policy.
    if (force_drain && !directory_reader && !isolate_regular_reader) (void)DrainDeferredAccessTimes(c);
    return decision(0);
#else
    return false;
#endif
}
