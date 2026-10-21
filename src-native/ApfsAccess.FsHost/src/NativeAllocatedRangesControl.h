#pragma once
#include "NativeAllocatedRangesProtocol.h"

// Included after the host context/callback helpers. The owner's Control wrapper
// supplies its existing callback telemetry; no mutation or journal scope is used.
namespace
{
bool CanExposeNativeAllocatedRangesControl(MountContext& c)
{
#ifdef APFSACCESS_HAS_RW_ENGINE
    try
    {
        std::lock_guard metadata(c.metadata_mutex);
        if (c.args.encrypted.enabled || c.args.fusion.enabled || !c.metadata_store ||
            !c.metadata_store->AuthoritativeAppleCheckpointView()) return false;
        std::error_code error;
        return std::filesystem::is_regular_file(c.metadata_store->Context().device_path, error) && !error;
    }
    catch (...) { return false; }
#else
    (void)c;
    return false;
#endif
}

NTSTATUS DispatchNativeAllocatedRangesControl(FSP_FILE_SYSTEM* fs, PVOID context,
    PVOID input, ULONG input_size, PVOID output, ULONG output_size, PULONG transferred)
{
    namespace protocol = apfsaccess::fshost::allocated_ranges_control;
    using namespace apfsaccess::rw;
    if (transferred) *transferred = 0;
    auto* c = Ctx(fs); auto* o = static_cast<OpenContext*>(context);
    if (!c || !o || !o->node || !input || !output || !transferred || input_size != sizeof(protocol::Request))
        return STATUS_INVALID_PARAMETER;
    if (output_size < sizeof(protocol::Reply)) return STATUS_BUFFER_TOO_SMALL;
    protocol::Request request; memcpy(&request, input, sizeof(request));
    if (request.version != protocol::Version || request.reserved) return STATUS_INVALID_PARAMETER;
    if (o->named_stream || o->native_xattr || o->node->node_kind != NodeKind::RegularFile)
        return STATUS_NOT_SUPPORTED;
    if (!o->allow_read_data) return STATUS_ACCESS_DENIED;
    ExternalMutationRequestScope admission(c, false);
    if (!admission.Acquired()) return STATUS_VOLUME_DISMOUNTED;
#ifndef APFSACCESS_HAS_RW_ENGINE
    return STATUS_NOT_SUPPORTED;
#else
    try
    {
        if (!CanExposeNativeAllocatedRangesControl(*c)) return STATUS_NOT_SUPPORTED;
        {
            std::lock_guard names(c->mutex);
            if (o->cleanup_seen || o->delete_on_close_requested || o->delete_on_cleanup ||
                o->node->namespace_detached || IsDeleteBlockedStateLocked(o->node)) return STATUS_FILE_DELETED;
        }
        const auto path = SnapshotMutationPathForNode(c, *o->node);
        if (path.empty()) return STATUS_FILE_DELETED;
        std::shared_lock gate(c->committed_read_gate);
        std::lock_guard metadata(c->metadata_mutex);
        if (!c->metadata_store || c->metadata_store->PendingMutationCount()) return STATUS_DEVICE_BUSY;
        const auto inode = c->metadata_store->LookupCommittedInodeByPath(path);
        const auto plan = c->metadata_store->SnapshotCommittedFileReadPlan(LowerPathKey(c, path));
        const auto xid = c->metadata_store->CheckpointXid();
        if (!inode || !plan || !xid || inode->object_id != o->node->object_id ||
            inode->node_type != MetadataStore::NodeType::RegularFile || !inode->allocation_size ||
            plan->unsupported_content_transform) return STATUS_NOT_SUPPORTED;
        protocol::Reply reply;
        reply.observed = {inode->object_id, *xid, c->metadata_store->StateEpoch(),
            inode->logical_size, *inode->allocation_size};
        NativeAllocatedRangePage page;
        std::span<const MetadataStore::FileExtent> extents;
        if (plan->has_single_extent) extents = {&plan->single_extent, 1};
        else if (plan->extents_snapshot) extents = *plan->extents_snapshot;
        const auto status = CollectNativeAllocatedRangePage(extents, reply.observed,
            request.expected, request.offset, request.length, page);
        if (status == NativeAllocatedRangeStatus::InvalidRange) return STATUS_INVALID_PARAMETER;
        if (status == NativeAllocatedRangeStatus::StateChanged) return STATUS_RETRY;
        if (status != NativeAllocatedRangeStatus::Ok) return STATUS_FILE_CORRUPT_ERROR;
        reply.ranges = page.ranges; reply.range_count = page.count;
        reply.next_offset = page.next_offset; reply.more_ranges = page.more ? 1u : 0u;
        memcpy(output, &reply, sizeof(reply)); *transferred = sizeof(reply);
        return STATUS_SUCCESS;
    }
    catch (...) { return STATUS_INSUFFICIENT_RESOURCES; }
#endif
}
}
