#pragma once
#ifndef APFSACCESS_ENABLE_STANDARD_CLONE_RANGE
#define APFSACCESS_ENABLE_STANDARD_CLONE_RANGE 0
#endif

#if APFSACCESS_ENABLE_STANDARD_CLONE_RANGE
NTSTATUS ExecuteNativeCloneRange(MountContext& context, OpenContext& source, OpenContext& target,
    const apfsaccess::rw::NativeCloneRangeRequest& request)
{
    using Store = apfsaccess::rw::MetadataStore;
    ExternalMutationRequestScope admission(&context);
    if (!admission.Acquired()) return STATUS_VOLUME_DISMOUNTED;
    MutationCallbackScope mutation(&context);
    if (!(source.granted_access & FILE_READ_DATA) || !(target.granted_access & FILE_WRITE_DATA))
        return STATUS_ACCESS_DENIED;
    if (!IsNativeWriteEnabled(&context) || !IsMutationWriteEnabled(&context) || context.args.encrypted.enabled ||
        context.args.fusion.enabled || IsManifestSession(&context)) return STATUS_NOT_SUPPORTED;
    const auto atime = DrainDeferredAccessTimes(&context);
    if (!NT_SUCCESS(atime)) return atime;
    const auto drained = DrainNativeMutationsByPolicy(&context, L"NativeCloneRange", false, true);
    if (!NT_SUCCESS(drained)) return drained;
    if (!FinalizeMutationJournalBestEffort(&context, L"NativeCloneRange")) return STATUS_UNSUCCESSFUL;
    bool acceptance_started = false;
    try
    {
        Store::CloneRangeReceipt receipt;
        Store::CloneRangeAcceptance accepted = Store::CloneRangeAcceptance::Refused;
        std::string error;
        {
            std::lock_guard commit(context.commit_mutex); std::unique_lock reads(context.committed_read_gate);
            std::lock_guard metadata(context.metadata_mutex); std::lock_guard journal(context.tx_mutex);
            apfsaccess::rw::NativeCloneRangeOpenEntry source_entry, target_entry;
            if (!CaptureNativeStandardOpenEntry(context, source, source_entry) ||
                !CaptureNativeStandardOpenEntry(context, target, target_entry)) return STATUS_INVALID_HANDLE;
            if (!EnrollNativeHardLinkJournalIdentity(context)) return STATUS_NOT_SUPPORTED;
            const auto borrowed = context.metadata_store->WithNativeCloneRangeSession(source_entry, target_entry,
                [&](const auto& session, auto& why) {
                    acceptance_started = true;
                    accepted = context.metadata_store->AcceptNativeCloneRange(*context.tx_manager, session, request, receipt, why);
                    acceptance_started = accepted != Store::CloneRangeAcceptance::Refused;
                    return accepted == Store::CloneRangeAcceptance::Accepted;
                }, error);
            if (!borrowed && acceptance_started)
                accepted = Store::CloneRangeAcceptance::RecoveryRequired;
        }
        if (accepted == Store::CloneRangeAcceptance::Refused)
        {
            std::cerr << "[FsHost] Clone range refused: " << error << std::endl;
            return STATUS_NOT_SUPPORTED;
        }
        if (accepted != Store::CloneRangeAcceptance::Accepted)
            return BlockNativeCloneRecovery(context, L"NativeCloneRangeAcceptanceAmbiguous");
        if (!UpdateRecoveryMarkerBestEffort(&context, true))
            return BlockNativeCloneRecovery(context, L"NativeCloneRangeMarkerFailed");
        {
            std::lock_guard commit(context.commit_mutex); std::unique_lock reads(context.committed_read_gate);
            std::unique_lock metadata(context.metadata_mutex); std::lock_guard journal(context.tx_mutex);
            const auto published = context.metadata_store->PublishOrRecoverNativeCloneRange(*context.tx_manager,
                [&](const Store&, std::string& why) {
                    metadata.unlock(); ScopeExit restore{[&] { metadata.lock(); }};
                    const auto ok = RefreshNativeStandardOpenViews(context, receipt.source_inode) &&
                        RefreshNativeStandardOpenViews(context, receipt.target_inode);
                    if (!ok) why = "NativeCloneRangeHostViewUnproven";
                    return ok;
                }, error);
            const auto marks = context.tx_manager->Watermarks();
            if ((published != Store::CloneRangePublication::Published && published != Store::CloneRangePublication::AlreadyPublished) ||
                !context.tx_manager->RecoveryStateValid() || marks.accepted_sequence != receipt.sequence ||
                marks.apfs_durable_sequence != receipt.sequence || marks.cleanup_sequence != receipt.sequence)
                return BlockNativeCloneRecovery(context, L"NativeCloneRangePublicationUnproven");
        }
        {
            std::lock_guard runtime(context.runtime_state_mutex);
            context.pending_native_writes = false;
            context.runtime_last_commit_xid = context.metadata_store->LastCommittedXid();
        }
        InvalidatePayloadIdentityCache(&context);
        RefreshReportedVolumeInfoFromMetadata(context);
        if (!UpdateRecoveryMarkerBestEffort(&context, false))
            return BlockNativeCloneRecovery(context, L"NativeCloneRangeCleanupMarkerFailed");
        MarkOpenContextMutation(&target);
        return STATUS_SUCCESS;
    }
    catch (...)
    {
        return acceptance_started ? BlockNativeCloneRecovery(context, L"NativeCloneRangeCallbackException") :
            STATUS_INSUFFICIENT_RESOURCES;
    }
}

std::optional<bool> ReplayIsolatedNativeCloneRange(MountContext& context)
{
    using Store = apfsaccess::rw::MetadataStore;
    using Tx = apfsaccess::rw::TransactionManager;
    std::vector<Tx::AcceptedTransaction> batches;
    try
    {
        if (!context.tx_manager->LoadAcceptedTransactionsSinceCleanup(batches)) return std::nullopt;
        bool found = false;
        for (const auto& batch : batches) for (const auto& record : batch.mutations)
            found |= static_cast<std::uint32_t>(record.operation) == apfsaccess::rw::NativeCloneRangeOperationKind;
        if (!found) return std::nullopt;
        const auto fail = [&](const wchar_t* reason) -> std::optional<bool> {
            (void)BlockNativeCloneRecovery(context, reason); return false;
        };
        apfsaccess::rw::NativeCloneRangeProof proof;
        if (context.args.encrypted.enabled || context.args.fusion.enabled || IsManifestSession(&context) ||
            batches.size() != 1 || batches.front().mutations.size() != 1 || context.metadata_store->PendingMutationCount() ||
            !apfsaccess::rw::DecodeNativeCloneRange(batches.front().mutations.front().inline_payload, proof))
            return fail(L"NativeCloneRangeReplayRequiresIsolatedOwner");
        Store::CloneRangePublication result;
        std::string error;
        {
            std::lock_guard commit(context.commit_mutex); std::unique_lock reads(context.committed_read_gate);
            std::unique_lock metadata(context.metadata_mutex); std::lock_guard journal(context.tx_mutex);
            if (!EnrollNativeHardLinkJournalIdentity(context)) return fail(L"NativeCloneRangeReplayEnrollmentRefused");
            result = context.metadata_store->PublishOrRecoverNativeCloneRange(*context.tx_manager,
                [&](const Store&, std::string& why) {
                    metadata.unlock(); ScopeExit restore{[&] { metadata.lock(); }};
                    const auto ok = RefreshNativeStandardOpenViews(context, proof.source_inode) &&
                        RefreshNativeStandardOpenViews(context, proof.target_inode);
                    if (!ok) why = "NativeCloneRangeReplayHostViewUnproven";
                    return ok;
                }, error);
        }
        if (result != Store::CloneRangePublication::Published && result != Store::CloneRangePublication::AlreadyPublished)
            return fail(L"NativeCloneRangeReplayPublicationUnproven");
        InvalidatePayloadIdentityCache(&context);
        {
            std::lock_guard runtime(context.runtime_state_mutex);
            context.pending_native_writes = false; context.recovery_active = false; context.write_degraded = false;
            context.runtime_last_commit_xid = context.metadata_store->LastCommittedXid();
            context.runtime_recovery_reason.clear(); context.runtime_last_recovery_action = L"NativeCloneRangeReplayApplied";
        }
        return UpdateRecoveryMarkerBestEffort(&context, false) ? std::optional<bool>(true) :
            fail(L"NativeCloneRangeReplayMarkerFailed");
    }
    catch (...) { (void)BlockNativeCloneRecovery(context, L"NativeCloneRangeReplayException"); return false; }
}
#endif
