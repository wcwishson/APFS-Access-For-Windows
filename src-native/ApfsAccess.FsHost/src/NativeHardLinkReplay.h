#pragma once
#include "NativeHardLinkJournal.h"

std::optional<bool> ReplayIsolatedNativeHardLink(MountContext& c)
{
    using Store = apfsaccess::rw::MetadataStore;
    using Tx = apfsaccess::rw::TransactionManager;
    try
    {
        std::vector<Tx::AcceptedTransaction> batches;
        if (!c.tx_manager->LoadAcceptedTransactionsSinceCleanup(batches)) return std::nullopt;
        bool found = false;
        for (const auto& batch : batches) for (const auto& row : batch.mutations)
            found |= row.operation == apfsaccess::rw::WriteAheadLog::OperationKind::HardLink;
        if (!found) return std::nullopt;
        const auto fail = [&](const wchar_t* reason) -> std::optional<bool> { (void)BlockNativeCloneRecovery(c, reason); return false; };
        if (c.args.encrypted.enabled || c.args.fusion.enabled || IsManifestSession(&c) || batches.size() != 1 ||
            batches.front().mutations.size() != 1 || c.metadata_store->PendingMutationCount())
            return fail(L"NativeHardLinkReplayRequiresIsolatedOwner");
        const auto& row = batches.front().mutations.front();
        std::wstring source, target;
        if (!TryUtf8ToWideStrict(row.secondary_path_utf8, source) || !TryUtf8ToWideStrict(row.path_utf8, target))
            return fail(L"NativeHardLinkReplayOriginalPathInvalid");
        std::shared_ptr<Node> retained_source;
        { std::lock_guard names(c.mutex); retained_source = TryGetNodeLockedNormalized(&c, source); }
        Store::HardLinkPublication result;
        std::string error;
        {
            std::lock_guard commit(c.commit_mutex); std::unique_lock reads(c.committed_read_gate);
            std::unique_lock metadata(c.metadata_mutex); std::lock_guard journal(c.tx_mutex);
            if (!EnrollNativeHardLinkJournalIdentity(c)) return fail(L"NativeHardLinkReplayEnrollmentRefused");
            result = c.metadata_store->PublishOrRecoverNativeHardLink(*c.tx_manager,
                [&](const Store&, std::string& why) {
                    metadata.unlock(); ScopeExit restore{[&] { metadata.lock(); }};
                    const auto ok = PublishNativeHardLinkNamespace(c, target, row.object_id, retained_source);
                    if (!ok) why = "HardLinkReplayNamespaceUnproven";
                    return ok;
                }, error);
        }
        if (result != Store::HardLinkPublication::Published && result != Store::HardLinkPublication::AlreadyPublished)
        {
            c.hardlink_last_error = error;
            return fail(L"NativeHardLinkReplayPublicationUnproven");
        }
        InvalidatePayloadIdentityCache(&c);
        {
            std::lock_guard<std::recursive_mutex> runtime(c.runtime_state_mutex);
            c.pending_native_writes = false; c.recovery_active = false; c.write_degraded = false;
            c.runtime_last_commit_xid = c.metadata_store->LastCommittedXid();
            c.runtime_recovery_reason.clear(); c.runtime_last_recovery_action = L"NativeHardLinkReplayApplied";
        }
        if (!UpdateRecoveryMarkerBestEffort(&c, false)) return fail(L"NativeHardLinkReplayMarkerFailed");
        return true;
    }
    catch (...) { (void)BlockNativeCloneRecovery(c, L"NativeHardLinkReplayException"); return false; }
}
