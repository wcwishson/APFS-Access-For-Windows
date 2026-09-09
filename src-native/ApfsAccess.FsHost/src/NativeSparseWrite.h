#pragma once

#ifdef APFSACCESS_HAS_RW_ENGINE
NTSTATUS PreflightNativePayloadMutation(MountContext* c, OpenContext* o, const std::wstring& path,
    apfsaccess::rw::MetadataStore::MutationOperation operation, std::uint64_t offset, std::uint64_t length)
{
    using Store = apfsaccess::rw::MetadataStore;
    if (!c->metadata_store || !IsNativeWriteEnabled(c) || o->named_stream || path.empty()) return STATUS_SUCCESS;
    try
    {
    std::shared_lock<std::shared_mutex> gate(c->committed_read_gate);
    std::lock_guard<std::mutex> metadata(c->metadata_mutex);
    Store::MutationRequest request;
    request.operation = operation;
    request.path = path;
    request.offset = offset;
    request.length = length;
    auto status = c->metadata_store->PreflightNativeSparseMutation(request);
    return status == Store::MutationStatus::Applied ? STATUS_SUCCESS :
        status == Store::MutationStatus::CapacityBlocked ? STATUS_DISK_FULL :
        status == Store::MutationStatus::AllocationFailed ? STATUS_INSUFFICIENT_RESOURCES : STATUS_NOT_SUPPORTED;
    }
    catch (const std::bad_alloc&) { return STATUS_INSUFFICIENT_RESOURCES; }
    catch (const std::length_error&) { return STATUS_INSUFFICIENT_RESOURCES; }
}

std::optional<std::uint64_t> SnapshotNativePayloadAllocation(MountContext* c, OpenContext* o,
    const std::wstring& path)
{
    if (!c->metadata_store || !IsNativeWriteEnabled(c) || o->named_stream || path.empty()) return std::nullopt;
    std::shared_lock<std::shared_mutex> gate(c->committed_read_gate);
    std::lock_guard<std::mutex> metadata(c->metadata_mutex);
    return c->metadata_store->LookupWorkingAllocationByObjectId(o->node->object_id);
}
#endif
