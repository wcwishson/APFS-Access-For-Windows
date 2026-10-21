#pragma once
#include "NativeSparse.h"
#include "NativeHardLinkJournal.h"

template<class Entry>
bool CaptureNativeStandardOpenEntry(MountContext& context, const OpenContext& open, Entry& entry)
{
    if (!open.node || open.named_stream || open.native_xattr || open.cleanup_seen ||
        open.node->node_kind != NodeKind::RegularFile || open.node->namespace_detached) return false;
    const auto inode = context.metadata_store->LookupCommittedInodeByPath(open.node->path);
    const auto link = context.metadata_store->LookupCommittedDirectoryLinkByPath(open.node->path);
    if (!inode || !link || inode->object_id != open.node->object_id || link->child_object_id != inode->object_id)
        return false;
    entry = {inode->object_id, inode->xid, link->parent_object_id, link->sibling_id, link->entry_name_utf8};
    return true;
}

bool RefreshNativeStandardOpenViews(MountContext& context, std::uint64_t object_id)
{
    using Store = apfsaccess::rw::MetadataStore;
    std::optional<Store::InodeRecord> inode;
    std::optional<UINT32> attributes;
    std::unordered_map<std::uint64_t, std::shared_ptr<const NativeInodeSecurity>> security;
    {
        std::lock_guard metadata(context.metadata_mutex);
        inode = context.metadata_store->LookupCommittedInodeByObjectId(object_id);
        if (!inode || inode->node_type != Store::NodeType::RegularFile ||
            !ReadWindowsAttributes(context.metadata_store->LookupCommittedExtendedAttribute(object_id, kWindowsAttributesName), attributes))
            return false;
        CaptureCommittedNativeSecurity(*context.metadata_store, *inode, security);
    }
    auto flags = attributes.value_or(FILE_ATTRIBUTE_ARCHIVE) & ~FILE_ATTRIBUTE_SPARSE_FILE;
    if (inode->internal_flags & apfsaccess::rw::kAppleInodeSparseFlag) flags |= FILE_ATTRIBUTE_SPARSE_FILE;
    std::lock_guard names(context.mutex);
    for (const auto& [key, node] : context.nodes)
    {
        (void)key;
        if (!node || node->object_id != object_id) continue;
        if (!ApplyCommittedInodeMetadataToNode(&context, *inode, UtcNow(), node, flags, security.at(object_id))) return false;
        MarkHydrationStaleLocked(&context, node);
    }
    context.namespace_checkpoint_xid = (std::max)(context.namespace_checkpoint_xid, inode->xid);
    return true;
}

NTSTATUS ExecuteNativeSparse(MountContext& context, OpenContext& open,
    const apfsaccess::rw::NativeSparseRequest& request)
{
    using Store = apfsaccess::rw::MetadataStore;
    ExternalMutationRequestScope admission(&context);
    if (!admission.Acquired()) return STATUS_VOLUME_DISMOUNTED;
    MutationCallbackScope mutation(&context);
    if (!(open.granted_access & FILE_WRITE_DATA)) return STATUS_ACCESS_DENIED;
    if (!IsNativeWriteEnabled(&context) || !IsMutationWriteEnabled(&context) || context.args.encrypted.enabled ||
        context.args.fusion.enabled || IsManifestSession(&context)) return STATUS_NOT_SUPPORTED;
    const auto atime = DrainDeferredAccessTimes(&context);
    if (!NT_SUCCESS(atime)) return atime;
    const auto drained = DrainNativeMutationsByPolicy(&context, L"NativeSparse", false, true);
    if (!NT_SUCCESS(drained)) return drained;
    if (!FinalizeMutationJournalBestEffort(&context, L"NativeSparse")) return STATUS_UNSUCCESSFUL;
    bool acceptance_started = false;
    try
    {
        Store::SparseReceipt receipt;
        Store::SparseAcceptance accepted = Store::SparseAcceptance::Refused;
        std::string error;
        {
            std::lock_guard commit(context.commit_mutex); std::unique_lock reads(context.committed_read_gate);
            std::lock_guard metadata(context.metadata_mutex); std::lock_guard journal(context.tx_mutex);
            apfsaccess::rw::NativeSparseOpenEntry entry;
            if (!CaptureNativeStandardOpenEntry(context, open, entry)) return STATUS_INVALID_HANDLE;
            if (!EnrollNativeHardLinkJournalIdentity(context)) return STATUS_NOT_SUPPORTED;
            const auto borrowed = context.metadata_store->WithNativeSparseSession(entry,
                [&](const auto& session, auto& why) {
                    acceptance_started = true;
                    accepted = context.metadata_store->AcceptNativeSparseV2(*context.tx_manager, session, request, receipt, why);
                    acceptance_started = accepted != Store::SparseAcceptance::Refused;
                    return accepted == Store::SparseAcceptance::Accepted;
                }, error);
            if (!borrowed && acceptance_started) accepted = Store::SparseAcceptance::RecoveryRequired;
        }
        if (accepted == Store::SparseAcceptance::Refused)
        {
            std::cerr << "[FsHost] Sparse request refused: " << error << std::endl;
            return STATUS_NOT_SUPPORTED;
        }
        if (accepted != Store::SparseAcceptance::Accepted) return BlockNativeCloneRecovery(context, L"NativeSparseAcceptanceAmbiguous");
        if (!UpdateRecoveryMarkerBestEffort(&context, true)) return BlockNativeCloneRecovery(context, L"NativeSparseMarkerFailed");
        Store::SparsePublication published;
        {
            std::lock_guard commit(context.commit_mutex); std::unique_lock reads(context.committed_read_gate);
            std::unique_lock metadata(context.metadata_mutex); std::lock_guard journal(context.tx_mutex);
            published = context.metadata_store->PublishOrRecoverNativeSparse(*context.tx_manager,
                [&](const Store&, std::string& why) {
                    metadata.unlock(); ScopeExit restore{[&] { metadata.lock(); }};
                    const auto ok = RefreshNativeStandardOpenViews(context, receipt.inode);
                    if (!ok) why = "NativeSparseHostViewUnproven";
                    return ok;
                }, error);
            const auto marks = context.tx_manager->Watermarks();
            if ((published != Store::SparsePublication::Published && published != Store::SparsePublication::AlreadyPublished) ||
                !context.tx_manager->RecoveryStateValid() || marks.accepted_sequence != receipt.sequence ||
                marks.apfs_durable_sequence != receipt.sequence || marks.cleanup_sequence != receipt.sequence)
                return BlockNativeCloneRecovery(context, L"NativeSparsePublicationUnproven");
        }
        {
            std::lock_guard runtime(context.runtime_state_mutex);
            context.pending_native_writes = false;
            context.runtime_last_commit_xid = context.metadata_store->LastCommittedXid();
        }
        InvalidatePayloadIdentityCache(&context);
        RefreshReportedVolumeInfoFromMetadata(context);
        if (!UpdateRecoveryMarkerBestEffort(&context, false)) return BlockNativeCloneRecovery(context, L"NativeSparseCleanupMarkerFailed");
        MarkOpenContextMutation(&open);
        return STATUS_SUCCESS;
    }
    catch (...) { return acceptance_started ? BlockNativeCloneRecovery(context, L"NativeSparseCallbackException") : STATUS_INSUFFICIENT_RESOURCES; }
}

std::optional<bool> ReplayIsolatedNativeSparse(MountContext& context)
{
    using Store = apfsaccess::rw::MetadataStore;
    using Tx = apfsaccess::rw::TransactionManager;
    std::vector<Tx::AcceptedTransaction> batches;
    try
    {
        if (!context.tx_manager->LoadAcceptedTransactionsSinceCleanup(batches)) return std::nullopt;
        bool found = false;
        for (const auto& batch : batches) for (const auto& record : batch.mutations)
            found |= static_cast<std::uint32_t>(record.operation) == apfsaccess::rw::NativeSparseOperationKind;
        if (!found) return std::nullopt;
        const auto fail = [&](const wchar_t* reason) -> std::optional<bool> { (void)BlockNativeCloneRecovery(context, reason); return false; };
        if (context.args.encrypted.enabled || context.args.fusion.enabled || IsManifestSession(&context) ||
            batches.size() != 1 || batches.front().mutations.size() != 1 || context.metadata_store->PendingMutationCount())
            return fail(L"NativeSparseReplayRequiresIsolatedOwner");
        Store::SparsePublication result;
        std::string error;
        {
            std::lock_guard commit(context.commit_mutex); std::unique_lock reads(context.committed_read_gate);
            std::unique_lock metadata(context.metadata_mutex); std::lock_guard journal(context.tx_mutex);
            if (!EnrollNativeHardLinkJournalIdentity(context)) return fail(L"NativeSparseReplayEnrollmentRefused");
            const auto inode = batches.front().mutations.front().object_id;
            result = context.metadata_store->PublishOrRecoverNativeSparse(*context.tx_manager,
                [&](const Store&, std::string& why) {
                    metadata.unlock(); ScopeExit restore{[&] { metadata.lock(); }};
                    const auto ok = RefreshNativeStandardOpenViews(context, inode);
                    if (!ok) why = "NativeSparseReplayHostViewUnproven";
                    return ok;
                }, error);
        }
        if (result != Store::SparsePublication::Published && result != Store::SparsePublication::AlreadyPublished)
            return fail(L"NativeSparseReplayPublicationUnproven");
        InvalidatePayloadIdentityCache(&context);
        {
            std::lock_guard runtime(context.runtime_state_mutex);
            context.pending_native_writes = false; context.recovery_active = false; context.write_degraded = false;
            context.runtime_last_commit_xid = context.metadata_store->LastCommittedXid();
            context.runtime_recovery_reason.clear(); context.runtime_last_recovery_action = L"NativeSparseReplayApplied";
        }
        return UpdateRecoveryMarkerBestEffort(&context, false) ? std::optional<bool>(true) : fail(L"NativeSparseReplayMarkerFailed");
    }
    catch (...) { (void)BlockNativeCloneRecovery(context, L"NativeSparseReplayException"); return false; }
}
