#pragma once

#ifdef APFSACCESS_HAS_RW_ENGINE
struct NativeSparseRangeView
{
    apfsaccess::rw::MetadataStore::CommittedFileReadPlan plan;
    std::wstring path;
    std::uint64_t allocation = 0;
    bool can_mutate = false;
};

NTSTATUS SnapshotNativeSparseRangeView(MountContext& c, OpenContext& o, NativeSparseRangeView& view)
{
    using Store = apfsaccess::rw::MetadataStore;
    if (!c.metadata_store) return STATUS_NOT_SUPPORTED;
    view.path = SnapshotMutationPathForNode(&c, *o.node);
    if (view.path.empty()) return STATUS_FILE_DELETED;
    // Admission reads metadata itself. Resolve it before taking the read gate
    // and metadata lock used for the extent snapshot and ownership proof.
    const bool writable_image = !c.fs && !IsManifestSession(&c) &&
        IsNativeWriteEnabled(&c) && IsMutationWriteEnabled(&c) && c.tx_manager && c.payload_spool;
    std::shared_lock gate(c.committed_read_gate);
    std::lock_guard metadata(c.metadata_mutex);
    if (c.metadata_store->PendingMutationCount()) return STATUS_DEVICE_BUSY;
    const auto inode = c.metadata_store->LookupCommittedInodeByPath(view.path);
    const auto plan = c.metadata_store->SnapshotCommittedFileReadPlan(
        LowerPathKey(&c, view.path));
    if (!inode || !plan || inode->object_id != o.node->object_id ||
        inode->node_type != Store::NodeType::RegularFile || !inode->allocation_size ||
        plan->unsupported_content_transform || (!c.metadata_store->AuthoritativeAppleCheckpointView() &&
            !c.metadata_store->IsImmutableSnapshotView())) return STATUS_NOT_SUPPORTED;
    view.plan = *plan; view.allocation = *inode->allocation_size;
    const auto* checkpoint = c.metadata_store->AuthoritativeAppleCheckpointView();
    const auto block = checkpoint ? checkpoint->container.superblock.block_size : 0;
    const bool sparse = (inode->internal_flags & apfsaccess::rw::kAppleInodeSparseFlag) ||
        view.allocation < inode->logical_size;
    std::error_code error;
    // The first protocol version is an ordinary-image primitive. Container
    // manifest coordination and raw-device mutation need separate acceptance.
    if (sparse && block && writable_image &&
        !c.metadata_store->IsImmutableSnapshotView() &&
        std::filesystem::is_regular_file(c.metadata_store->Context().device_path, error) && !error)
    {
        Store::MutationRequest probe;
        probe.operation = Store::MutationOperation::SetFileSize;
        probe.path = view.path; probe.length = inode->logical_size;
        const auto status = c.metadata_store->PreflightNativeSparseMutation(probe);
        if (status == Store::MutationStatus::AllocationFailed) return STATUS_INSUFFICIENT_RESOURCES;
        view.can_mutate = status == Store::MutationStatus::Applied;
    }
    return STATUS_SUCCESS;
}

std::span<const apfsaccess::rw::MetadataStore::FileExtent> NativeSparseRangeExtents(const NativeSparseRangeView& view)
{
    if (view.plan.has_single_extent) return {&view.plan.single_extent, 1};
    if (view.plan.extents_snapshot) return *view.plan.extents_snapshot;
    return {};
}

NTSTATUS CollectNativeAllocatedRanges(const NativeSparseRangeView& view,
    const apfsaccess::fshost::sparse_control::RangeRequest& request,
    apfsaccess::fshost::sparse_control::Reply& reply)
{
    const auto end = (std::min)(view.plan.logical_size, request.offset + request.length);
    reply.file_size = view.plan.logical_size; reply.allocation_size = view.allocation;
    reply.capabilities = apfsaccess::fshost::sparse_control::CanQuery |
        (view.can_mutate ? apfsaccess::fshost::sparse_control::CanZero |
            apfsaccess::fshost::sparse_control::CanResizeSparse : 0);
    reply.next_offset = end;
    std::uint64_t prior_end = 0, allocated = 0;
    for (const auto& extent : NativeSparseRangeExtents(view))
    {
        if (!extent.bytes || extent.logical_offset < prior_end || extent.bytes > UINT64_MAX - extent.logical_offset)
            return STATUS_FILE_CORRUPT_ERROR;
        prior_end = extent.logical_offset + extent.bytes;
        if (extent.physical_address)
        {
            if (extent.bytes > UINT64_MAX - allocated) return STATUS_FILE_CORRUPT_ERROR;
            allocated += extent.bytes;
        }
        // Pagination bounds the reply, not validation of the committed graph.
        if (reply.more_ranges) continue;
        if (!extent.physical_address || prior_end <= request.offset || extent.logical_offset >= end) continue;
        const auto begin = (std::max)(request.offset, extent.logical_offset);
        const auto finish = (std::min)(end, prior_end);
        if (begin >= finish) continue;
        if (reply.range_count && reply.ranges[reply.range_count - 1].offset +
            reply.ranges[reply.range_count - 1].length == begin)
        {
            reply.ranges[reply.range_count - 1].length += finish - begin;
            continue;
        }
        if (reply.range_count == reply.ranges.size())
        {
            const auto& last = reply.ranges.back(); reply.next_offset = last.offset + last.length;
            reply.more_ranges = 1; continue;
        }
        reply.ranges[reply.range_count++] = {begin, finish - begin};
    }
    // A nonempty allocation without a complete native extent projection cannot
    // be reported as a hole or admitted to a zero operation.
    if (view.allocation && view.plan.logical_size && NativeSparseRangeExtents(view).empty()) return STATUS_NOT_SUPPORTED;
    if (allocated != view.allocation) return STATUS_FILE_CORRUPT_ERROR;
    return STATUS_SUCCESS;
}

NTSTATUS StageNativeSparseZero(MountContext& c, OpenContext& o, const NativeSparseRangeView& view,
    apfsaccess::fshost::sparse_control::Reply& reply, bool& staged)
{
    namespace protocol = apfsaccess::fshost::sparse_control;
    using Store = apfsaccess::rw::MetadataStore;
    constexpr ULONG chunk_size = 64 * 1024;
    if (reply.range_count > reply.ranges.size()) return STATUS_INVALID_PARAMETER;
    if (reply.more_ranges) return STATUS_NOT_SUPPORTED;
    std::vector<protocol::Range> pieces;
    std::uint64_t total = 0;
    for (std::uint32_t i = 0; i < reply.range_count; ++i)
    {
        auto range = reply.ranges[i];
        if (range.length > protocol::MaximumZeroBytes - total) return STATUS_NOT_SUPPORTED;
        total += range.length;
        while (range.length)
        {
            if (pieces.size() == protocol::MaximumRanges) return STATUS_NOT_SUPPORTED;
            const auto bytes = (std::min)(range.length, std::uint64_t{chunk_size});
            pieces.push_back({range.offset, bytes}); range.offset += bytes; range.length -= bytes;
        }
    }
    if (!total) { reply.range_count = 0; return STATUS_SUCCESS; }
    std::vector<std::byte> zeros(chunk_size);
    UINT32 attributes = 0; bool attributes_changed = false;
    auto status = PrepareWindowsAttributeUpdate(&c, o.node, FILE_ATTRIBUTE_ARCHIVE, false, attributes, attributes_changed);
    if (!NT_SUCCESS(status)) return status;
    const auto timestamp = UtcNow();
    auto requests = NativeContentCallbackRequests(view.path, attributes_changed, attributes, true, timestamp);
    // The engine previews the complete batch with a bounded nested undo stack.
    // Oversized zero batches are unsupported, before staging or recovery debt.
    if (requests.size() > Store::MaximumCapacityPreviewRequests ||
        pieces.size() > Store::MaximumCapacityPreviewRequests - requests.size()) return STATUS_NOT_SUPPORTED;
    for (const auto& piece : pieces)
    {
        status = PreflightNativePayloadMutation(&c, &o, view.path, Store::MutationOperation::Write, piece.offset, piece.length);
        if (!NT_SUCCESS(status)) return status;
        requests.push_back(NativeCallbackRequest(Store::MutationOperation::Write, view.path, piece.length, piece.offset));
    }
    status = PreflightDirectCallback(&c, requests);
    if (!NT_SUCCESS(status)) return status;
    const auto capacity = EnsurePayloadSpoolCapacityBeforeNativeWriteBestEffort(&c, static_cast<std::uint32_t>(total));
    if (capacity != PayloadSpoolCapacityOutcome::Ready)
        return capacity == PayloadSpoolCapacityOutcome::CapacityExceeded ? STATUS_DISK_FULL : STATUS_INSUFFICIENT_RESOURCES;
    status = EnsurePayloadHandleReadyForMutation(&c, &o);
    if (!NT_SUCCESS(status)) return status;
    const auto batch_limit = WindowsAttributeBatchLimit(&c, requests.size());
    Store::PayloadIdentity attribute_identity{}, time_identity{}, identity{};
    bool part_staged = false;
    if (attributes_changed)
    {
        const auto ok = StageWindowsAttributes(&c, view.path, attributes, batch_limit, attribute_identity, part_staged);
        staged |= part_staged;
        if (!ok) return BlockNativeMutationAfterStagingFailure(&c, L"SparseZeroAttributes", staged);
    }
    const auto times_ok = StageContentTimes(&c, view.path, timestamp, batch_limit, time_identity, part_staged, !attributes_changed);
    staged |= part_staged;
    if (!times_ok) return BlockNativeMutationAfterStagingFailure(&c, L"SparseZeroTimes", staged);
    if ((attributes_changed && !JournalWindowsAttributes(&c, view.path, attributes, attribute_identity)) ||
        !JournalContentTimes(&c, view.path, timestamp, time_identity))
        return BlockNativeMutationAfterStagingFailure(&c, L"SparseZeroMetadataJournal", staged);
    for (const auto& piece : pieces)
    {
        const auto ok = RecordNativeMutationBestEffort(&c, Store::MutationOperation::Write, view.path, L"",
            piece.offset, piece.length, false, 0, &identity, &part_staged, nullptr, batch_limit);
        staged |= part_staged;
        if (!ok || !RecordPayloadWriteMutationBestEffort(&c, view.path, piece.offset, zeros.data(),
                static_cast<ULONG>(piece.length), &identity))
            return BlockNativeMutationAfterStagingFailure(&c, L"SparseZeroPayload", staged);
        // Hardlinks share the same live stream. Mirror only allocated bytes;
        // ordinary handles can hydrate the accepted spool without a mirror.
        if (o.node->shared_payload)
        {
            OVERLAPPED at{}; at.Offset = static_cast<DWORD>(piece.offset); at.OffsetHigh = static_cast<DWORD>(piece.offset >> 32);
            DWORD written = 0;
            if (!WriteFile(o.file, zeros.data(), static_cast<DWORD>(piece.length), &written, &at) || written != piece.length)
                return BlockNativeMutationAfterStagingFailure(&c, L"SparseZeroMirror", staged);
        }
    }
    {
        std::lock_guard names(c.mutex);
        SetVisiblePayloadMetadataLocked(o.node, view.plan.logical_size, timestamp);
        SetVisibleAllocationSizeLocked(o.node, view.allocation);
        o.node->times_generation = (std::max)(o.node->times_generation, identity.generation);
        if (attributes_changed) SetVisibleWindowsAttributesLocked(o.node, attributes, identity.generation);
        if (o.node->shared_payload)
        {
            o.node->shared_payload->materialized_generation = identity.generation;
            o.node->shared_payload->visible_generation = identity.generation;
        }
        else MarkHydrationStaleLocked(&c, o.node);
    }
    MarkOpenContextMutation(&o);
    reply.zeroed_bytes = total; reply.range_count = 0;
    return STATUS_SUCCESS;
}
#endif

NTSTATUS DispatchNativeSparseControl(FSP_FILE_SYSTEM* fs, PVOID context, UINT32 code,
    PVOID input, ULONG input_size, PVOID output, ULONG output_size, PULONG transferred)
{
    namespace protocol = apfsaccess::fshost::sparse_control;
    auto* c = Ctx(fs); auto* o = static_cast<OpenContext*>(context);
    if (!c || !o || !o->node || !transferred || !input || !output) return STATUS_INVALID_PARAMETER;
    if (output_size < sizeof(protocol::Reply)) return STATUS_BUFFER_TOO_SMALL;
    protocol::RangeRequest range;
    if (input_size != sizeof(range)) return STATUS_INVALID_PARAMETER;
    memcpy(&range, input, sizeof(range));
    if (range.version != protocol::Version || range.reserved || range.offset > INT64_MAX ||
        range.length > static_cast<std::uint64_t>(INT64_MAX) - range.offset) return STATUS_INVALID_PARAMETER;
    if (o->named_stream || o->native_xattr || o->node->node_kind != NodeKind::RegularFile) return STATUS_NOT_SUPPORTED;
    if ((code == protocol::Query && !o->allow_read_data) || (code != protocol::Query && !o->allow_write_data)) return STATUS_ACCESS_DENIED;
    ExternalMutationRequestScope admission(c, code != protocol::Query);
    if (!admission.Acquired()) return STATUS_VOLUME_DISMOUNTED;
    MutationCallbackScope mutation(c);
#ifndef APFSACCESS_HAS_RW_ENGINE
    return STATUS_NOT_SUPPORTED;
#else
    bool staged = false;
    try
    {
        {
            std::lock_guard names(c->mutex);
            if (o->cleanup_seen || o->delete_on_close_requested || o->delete_on_cleanup ||
                o->node->namespace_detached || IsDeleteBlockedStateLocked(o->node)) return STATUS_FILE_DELETED;
        }
        if (code != protocol::Query)
        {
            if (c->fs) return STATUS_NOT_SUPPORTED;
            if (HasBlockedRecoveryEvidence(*c) || c->recovery_active || c->write_degraded) return STATUS_MEDIA_WRITE_PROTECTED;
            if (!IsNativeWriteEnabled(c) || !IsMutationWriteEnabled(c) || IsManifestSession(c)) return STATUS_NOT_SUPPORTED;
            const auto status = DrainNativeMutationsByPolicy(c, L"Flush");
            if (!NT_SUCCESS(status)) return status;
            if (!FinalizeMutationJournalBestEffort(c, L"SparseRangePrepare")) return STATUS_UNSUCCESSFUL;
        }
        NativeSparseRangeView view;
        auto status = SnapshotNativeSparseRangeView(*c, *o, view);
        if (!NT_SUCCESS(status)) return status;
        protocol::Reply reply;
        status = CollectNativeAllocatedRanges(view, range, reply);
        if (code == protocol::Zero)
        {
            if (!view.can_mutate || reply.more_ranges) return STATUS_NOT_SUPPORTED;
            if (!NT_SUCCESS(status)) return status;
            status = StageNativeSparseZero(*c, *o, view, reply, staged);
            if (!NT_SUCCESS(status)) return status;
            if (staged)
            {
                status = CommitNativeMutationsOnFlushBestEffort(c);
                if (!NT_SUCCESS(status)) return status;
                if (!FinalizeMutationJournalBestEffort(c, L"SparseZero")) return STATUS_UNSUCCESSFUL;
            }
        }
        else if (!NT_SUCCESS(status)) return status;
        memcpy(output, &reply, sizeof(reply)); *transferred = sizeof(reply); return status;
    }
    catch (const std::bad_alloc&) {}
    catch (const std::length_error&) {}
    return staged ? BlockNativeMutationAfterStagingFailure(c, L"SparseRangeAllocation", true) : STATUS_INSUFFICIENT_RESOURCES;
#endif
}
