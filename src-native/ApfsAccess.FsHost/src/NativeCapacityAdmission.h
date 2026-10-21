#pragma once

#ifdef APFSACCESS_HAS_RW_ENGINE
apfsaccess::rw::MetadataStore::MutationRequest NativeCallbackRequest(
    apfsaccess::rw::MetadataStore::MutationOperation operation, const std::wstring& path,
    std::uint64_t length = 0, std::uint64_t offset = 0,
    const std::wstring& secondary = L"", std::span<const std::byte> payload = {})
{
    apfsaccess::rw::MetadataStore::MutationRequest request;
    request.operation = operation;
    request.path = path;
    request.secondary_path = secondary;
    request.offset = offset;
    request.length = length;
    request.inline_payload.assign(payload.begin(), payload.end());
    return request;
}

// Caller owns commit_mutex, committed_read_gate and metadata_mutex in that
// order. No WAL/spool/marker ownership may change during this preview.
NTSTATUS PreflightDirectCallbackLocked(MountContext* c,
    std::span<const apfsaccess::rw::MetadataStore::MutationRequest> requests)
{
    using Store = apfsaccess::rw::MetadataStore;
    std::vector<std::uint64_t> pins;
    std::string error;
    if (!LoadDirectCheckpointPinsLocked(*c, pins, error, true)) return STATUS_IO_DEVICE_ERROR;
    const auto result = c->backup_held && c->backup_held->source
        ? c->metadata_store->PreflightBackupRetainedCapacityMutations(*c->backup_held->source, requests, pins)
        : c->metadata_store->PreflightNativeCapacityMutations(requests, pins);
    if (result == Store::MutationStatus::Applied) return STATUS_SUCCESS;
    if (result == Store::MutationStatus::CapacityBlocked) return STATUS_DISK_FULL;
    if (c->backup_held && result == Store::MutationStatus::UnsupportedOperation) return STATUS_NOT_SUPPORTED;
    if (result == Store::MutationStatus::AllocationFailed) return STATUS_INSUFFICIENT_RESOURCES;
    if (result == Store::MutationStatus::NotReady &&
        !c->metadata_store->IsRecoveryRequired() && c->metadata_store->IsCanonicalCommitReady() &&
        c->metadata_store->LastCommitStage() == "apple-plan-retention-blocked") return STATUS_DEVICE_BUSY;
    // Unknown structural failures must not be reported as clean capacity.
    return STATUS_IO_DEVICE_ERROR;
}

NTSTATUS PreflightDirectCallback(MountContext* c,
    std::span<const apfsaccess::rw::MetadataStore::MutationRequest> requests)
{
    if (!c || !c->metadata_store || !IsNativeWriteEnabled(c) || IsManifestSession(c) || requests.empty())
        return STATUS_SUCCESS;
    try
    {
        // Match the existing staging pressure boundary before previewing the
        // complete batch, so its first member cannot publish an older checkpoint
        // after admission. This drain preserves the normal accepted-work path.
        bool pressure = false;
        {
            std::lock_guard<std::mutex> metadata(c->metadata_mutex);
            pressure = c->metadata_store->PendingMutationCount() >=
                static_cast<std::size_t>((std::max)(1, c->args.write_max_dirty_transactions)) ||
                (IsDeferCloseCommitsEnabled() &&
                    (c->metadata_store->PendingPayloadDirtyByteEstimate() >= kDeferredCloseCommitPayloadBytesThreshold ||
                     c->metadata_store->PendingPayloadObjectSummaryCount() >= kDeferredCloseCommitBurstThreshold));
        }
        if (pressure)
        {
            const auto status = CommitNativeMutationsOnFlushBestEffort(c);
            if (!NT_SUCCESS(status)) return status;
            if (!FinalizeMutationJournalBestEffort(c, L"CapacityAdmissionBoundary")) return STATUS_IO_DEVICE_ERROR;
        }
        NTSTATUS status;
        {
            std::unique_lock<std::mutex> commit(c->commit_mutex);
            std::unique_lock<std::shared_mutex> gate(c->committed_read_gate);
            std::lock_guard<std::mutex> metadata(c->metadata_mutex);
            status = PreflightDirectCallbackLocked(c, requests);
        }
        if (status == STATUS_IO_DEVICE_ERROR)
            return BlockNativeMutationAfterStagingFailure(c, L"CapacityAdmission");
        return status;
    }
    catch (const std::bad_alloc&) { return STATUS_INSUFFICIENT_RESOURCES; }
    catch (const std::length_error&) { return STATUS_INSUFFICIENT_RESOURCES; }
}
#endif
