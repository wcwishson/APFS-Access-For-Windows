#pragma once

#ifdef APFSACCESS_HAS_RW_ENGINE
#include "NativeHardLink.h"
#include "NativeHardLinkJournal.h"

struct NativeHardLinkExecutionResult
{
    std::uint64_t object_id = 0;
    std::uint32_t links = 0;
    std::uint64_t accepted_sequence = 0;
    std::uint64_t checkpoint_xid = 0;
    // Process-local ticket retirement only; never evidence of durable completion.
    bool acceptance_observed = false;
};

bool CaptureNativeHardLinkOpenEntry(const apfsaccess::rw::MetadataStore& store,
    const std::wstring& path, apfsaccess::rw::NativeHardLinkOpenEntry& entry)
{
    const auto inode = store.LookupCommittedInodeByPath(path);
    if (!inode) return false;
    entry = {inode->object_id, inode->xid, inode->parent_object_id, 0, inode->name_utf8};
    if (path != L"\\")
    {
        const auto link = store.LookupCommittedDirectoryLinkByPath(path);
        if (!link || link->child_object_id != entry.object_id) return false;
        entry.parent_object_id = link->parent_object_id; entry.sibling_id = link->sibling_id;
        entry.name_utf8 = link->entry_name_utf8;
    }
    return true;
}

using NativeHardLinkAdmissionPolicy = bool (*)(MountContext&, const std::wstring&, const std::wstring&);
#ifdef APFSACCESS_FSHOST_UNIT_TEST
std::function<void()> g_hardlink_cache_preparation_hook;
#endif

// Caller retains both real open contexts and has checked its own access policy.
// Private Control already holds the nonrecursive foreground mutation gate.
NTSTATUS ExecuteNativeHardLinkUnderMutationGate(MountContext& c,
    const std::shared_ptr<Node>& source_node, const apfsaccess::rw::NativeHardLinkOpenEntry& source_entry,
    const std::shared_ptr<Node>& directory_node, const apfsaccess::rw::NativeHardLinkOpenEntry& directory_entry,
    std::wstring_view leaf, NativeHardLinkExecutionResult& result, NativeHardLinkAdmissionPolicy policy = nullptr)
{
    using Store = apfsaccess::rw::MetadataStore;
    result = {};
    const auto refuse = [&](const char* reason) {
        if (reason) c.hardlink_last_error = reason;
        {
            std::lock_guard<std::recursive_mutex> runtime(c.runtime_state_mutex);
            c.last_native_mutation_failure_operation = L"HardLink";
            c.last_native_mutation_failure_reason = Utf8ToWide(c.hardlink_last_error);
            c.last_native_mutation_failure_status = L"not-supported";
        }
        return STATUS_NOT_SUPPORTED;
    };
    try
    {
        if (c.args.encrypted.enabled || c.args.fusion.enabled || IsManifestSession(&c) ||
            !IsMutationWriteEnabled(&c) || !IsNativeWriteEnabled(&c) || !c.metadata_store || !c.tx_manager)
            return STATUS_NOT_SUPPORTED;
        if (HasBlockedRecoveryEvidence(c) || c.recovery_active || c.write_degraded) return STATUS_MEDIA_WRITE_PROTECTED;
        if (leaf.empty() || leaf.size() > 255 || leaf == L"." || leaf == L".." ||
            leaf.find_first_of(L"\\/:") != std::wstring_view::npos || leaf.find(L'\0') != std::wstring_view::npos ||
            !IsValidNormalizedWin32PathForMutation(L"\\" + std::wstring(leaf))) return STATUS_OBJECT_NAME_INVALID;
        std::wstring source, parent, target;
        const auto current_nodes = [&] {
            return source_node && directory_node && source_node != directory_node &&
                source_node->node_kind == NodeKind::RegularFile && !source_node->is_directory &&
                directory_node->node_kind == NodeKind::Directory && directory_node->is_directory &&
                source_node->object_id == source_entry.object_id && directory_node->object_id == directory_entry.object_id &&
                !source_node->namespace_detached && !directory_node->namespace_detached &&
                !IsDeleteBlockedStateLocked(source_node) && !IsDeleteBlockedStateLocked(directory_node) &&
                TryGetNodeLockedNormalized(&c, source_node->path) == source_node &&
                TryGetNodeLockedNormalized(&c, directory_node->path) == directory_node;
        };
        {
            std::lock_guard names(c.mutex);
            if (!current_nodes()) return STATUS_INVALID_HANDLE;
            source = source_node->path; parent = directory_node->path;
            target = parent == L"\\" ? L"\\" + std::wstring(leaf) : parent + L"\\" + std::wstring(leaf);
            if (TryGetNodeLockedNormalized(&c, target)) return STATUS_OBJECT_NAME_COLLISION;
            for (const auto& item : c.nodes)
                if (item.second && item.second->object_id == source_entry.object_id && IsDeleteBlockedStateLocked(item.second))
                    return STATUS_DELETE_PENDING;
        }
        const auto drained = DrainNativeMutationsByPolicy(&c, L"HardLinkExecute", false, true);
        if (!NT_SUCCESS(drained)) return drained;
        if (!FinalizeMutationJournalBestEffort(&c, L"HardLinkExecute")) return STATUS_UNSUCCESSFUL;
        Store::HardLinkReceipt receipt;
        Store::HardLinkAcceptance accepted;
        {
            std::lock_guard commit(c.commit_mutex); std::unique_lock reads(c.committed_read_gate);
            std::lock_guard metadata(c.metadata_mutex); std::lock_guard journal(c.tx_mutex);
            {
                std::lock_guard names(c.mutex);
                if (!current_nodes() || source_node->path != source || directory_node->path != parent)
                    return STATUS_INVALID_HANDLE;
                if (TryGetNodeLockedNormalized(&c, target)) return STATUS_OBJECT_NAME_COLLISION;
            }
            const auto same = [](const auto& a, const auto& b) {
                return a.object_id == b.object_id && a.generation == b.generation &&
                    a.parent_object_id == b.parent_object_id && a.sibling_id == b.sibling_id && a.name_utf8 == b.name_utf8;
            };
            apfsaccess::rw::NativeHardLinkOpenEntry current_source, destination;
            if (!CaptureNativeHardLinkOpenEntry(*c.metadata_store, source, current_source) ||
                !CaptureNativeHardLinkOpenEntry(*c.metadata_store, parent, destination) ||
                !same(current_source, source_entry) || !same(destination, directory_entry)) return STATUS_INVALID_HANDLE;
            if (policy && !policy(c, source, parent)) return refuse("HardLinkAncestryUnsupported");
            if (!EnrollNativeHardLinkJournalIdentity(c)) return refuse("HardLinkCanonicalEnrollmentRefused");
#ifdef APFSACCESS_FSHOST_UNIT_TEST
            if (g_hardlink_cache_preparation_hook) g_hardlink_cache_preparation_hook();
#endif
            if (!PrepareNativeHardLinkCache(c, source_node, source_entry.generation)) return refuse(nullptr);
            FILETIME now{}; GetSystemTimeAsFileTime(&now);
            const auto ticks = (static_cast<std::uint64_t>(now.dwHighDateTime) << 32) | now.dwLowDateTime;
            constexpr std::uint64_t epoch = 116444736000000000ULL;
            if (ticks <= epoch || ticks - epoch > UINT64_MAX / 100) return STATUS_INVALID_PARAMETER;
            accepted = c.metadata_store->WithNativeHardLinkSession(current_source, destination, std::wstring(leaf), (ticks - epoch) * 100,
                [&](const auto& session, auto& error) {
                    result.acceptance_observed = true;
                    const auto state = c.metadata_store->AcceptNativeHardLink(*c.tx_manager, session, receipt, error);
                    result.acceptance_observed = state != Store::HardLinkAcceptance::Refused;
                    return state;
                }, c.hardlink_last_error);
        }
        if (accepted == Store::HardLinkAcceptance::Refused) return refuse(nullptr);
        if (accepted != Store::HardLinkAcceptance::Accepted) return BlockNativeCloneRecovery(c, L"NativeHardLinkAcceptanceAmbiguous");
        if (!UpdateRecoveryMarkerBestEffort(&c, true)) return BlockNativeCloneRecovery(c, L"NativeHardLinkMarkerFailed");
        Store::HardLinkPublication publication;
        {
            std::lock_guard commit(c.commit_mutex); std::unique_lock reads(c.committed_read_gate);
            std::unique_lock metadata(c.metadata_mutex); std::lock_guard journal(c.tx_mutex);
            publication = c.metadata_store->PublishOrRecoverNativeHardLink(*c.tx_manager,
                [&](const Store&, std::string& error) {
                    metadata.unlock(); ScopeExit restore{[&] { metadata.lock(); }};
                    const auto ok = PublishNativeHardLinkNamespace(c, target, receipt.source, source_node);
                    if (!ok) error = "HardLinkHostNamespaceUnproven";
                    return ok;
                }, c.hardlink_last_error);
        }
        if (publication != Store::HardLinkPublication::Published && publication != Store::HardLinkPublication::AlreadyPublished)
            return BlockNativeCloneRecovery(c, L"NativeHardLinkPublicationRequiresRecovery");
        NativeHardLinkExecutionResult complete;
        bool verified = false;
        {
            std::lock_guard metadata(c.metadata_mutex); std::lock_guard journal(c.tx_mutex);
            const auto inode = c.metadata_store->LookupCommittedInodeByPath(target);
            const auto marks = c.tx_manager->Watermarks();
            verified = inode && inode->object_id == receipt.source && inode->link_count >= 2 &&
                marks.accepted_sequence == receipt.sequence && marks.apfs_durable_sequence == receipt.sequence &&
                marks.cleanup_sequence == receipt.sequence && c.tx_manager->RecoveryStateValid();
            if (verified) {
                complete.object_id = inode->object_id; complete.links = inode->link_count;
                complete.accepted_sequence = receipt.sequence; complete.checkpoint_xid = c.metadata_store->CheckpointXid().value_or(0);
                complete.acceptance_observed = true;
            }
        }
        if (!verified) return BlockNativeCloneRecovery(c, L"NativeHardLinkCompletionUnproven");
        { std::lock_guard<std::recursive_mutex> runtime(c.runtime_state_mutex);
            c.pending_native_writes = false; c.runtime_last_commit_xid = complete.checkpoint_xid; }
        InvalidatePayloadIdentityCache(&c);
        if (!UpdateRecoveryMarkerBestEffort(&c, false)) return BlockNativeCloneRecovery(c, L"NativeHardLinkCleanupMarkerFailed");
        result = complete;
        return STATUS_SUCCESS;
    }
    catch (...) { return result.acceptance_observed ? BlockNativeCloneRecovery(c, L"NativeHardLinkExecutionException") : STATUS_INSUFFICIENT_RESOURCES; }
}

NTSTATUS ExecuteNativeHardLink(MountContext& c,
    const std::shared_ptr<Node>& source_node, const apfsaccess::rw::NativeHardLinkOpenEntry& source_entry,
    const std::shared_ptr<Node>& directory_node, const apfsaccess::rw::NativeHardLinkOpenEntry& directory_entry,
    std::wstring_view leaf, NativeHardLinkExecutionResult& result)
{
    result = {};
    ExternalMutationRequestScope admission(&c);
    if (!admission.Acquired()) return STATUS_VOLUME_DISMOUNTED;
    MutationCallbackScope mutation(&c);
    return ExecuteNativeHardLinkUnderMutationGate(c, source_node, source_entry, directory_node, directory_entry, leaf, result);
}
#endif
