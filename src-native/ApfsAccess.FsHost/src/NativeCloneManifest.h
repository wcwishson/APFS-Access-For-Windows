#pragma once

// Called with callback admission, mutation and source-ticket ownership. The
// coordinator exclusively prepares/stages/publishes its borrowed store; hooks
// only build requests, accept their exact WAL identity, and verify native proof.
NTSTATUS ImportManifestNativeClone(MountContext& c, NativeCloneTicketState& ticket,
    const std::wstring& source, const std::wstring& target, const std::wstring& parent,
    bool& acceptance_started)
{
    using Store = apfsaccess::rw::MetadataStore;
    using Tx = apfsaccess::rw::TransactionManager;
    Store::CloneReceipt receipt;
    Store::MutationRequest prepared;
    NTSTATUS refusal = STATUS_INSUFFICIENT_RESOURCES;
    bool accepted = false, verified = false, preparation_completed = false;
    std::optional<Store::MutationStatus> preparation_refusal;
    const apfsaccess::catalog::ContainerMutationPreparationHook prepare =
        [&](const Store& live, auto& requests, std::string& error) {
            const auto inode = live.LookupCommittedInodeByPath(source);
            if (!requests.empty() || !inode || inode->object_id != ticket.object_id || inode->xid != ticket.generation)
            { refusal = STATUS_INVALID_HANDLE; error = "CloneSourceGenerationChanged"; return false; }
            if (inode->internal_flags & ~0x400ULL)
            {
                refusal = STATUS_NOT_SUPPORTED;
                error = "CloneManifestPreparationUnsupported";
                // Publish the classification after the fallible diagnostic.
                static_assert(noexcept(preparation_refusal = Store::MutationStatus::UnsupportedOperation));
                preparation_refusal = Store::MutationStatus::UnsupportedOperation;
                return false;
            }
            if (!NativeCloneAncestrySupportedLocked(c, source) || !NativeCloneAncestrySupportedLocked(c, parent) ||
                !live.PrepareNativeClone(source, target, prepared))
            { refusal = STATUS_NOT_SUPPORTED; error = "CloneManifestPreparationUnsupported"; return false; }
            requests.push_back(prepared);
            preparation_completed = true;
            return true;
        };
    const apfsaccess::catalog::ContainerPrepublicationHook bind =
        [&](const auto& requests, const auto& identities, std::uint64_t preimage,
            auto& pins, std::string& error) {
            apfsaccess::rw::NativeCloneProof proof;
            if (requests.size() != 1 || identities.size() != 1 ||
                requests[0].inline_payload != prepared.inline_payload || requests[0].path != target ||
                !apfsaccess::rw::DecodeNativeClone(prepared.inline_payload, proof) ||
                proof.checkpoint != preimage || proof.volume != c.container_volume_oid ||
                identities[0].object_id != proof.target || identities[0].generation != preimage + 1)
            { error = "CloneManifestStagedIdentityMismatch"; return false; }
            if (!UpdateRecoveryMarkerBestEffort(&c, true))
            { error = "CloneManifestRecoveryMarkerFailed"; return false; }
            std::lock_guard journal(c.tx_mutex);
            if (c.tx_manager->CurrentState() != Tx::State::Idle || !c.tx_manager->RecoveryStateValid() ||
                c.tx_manager->HasUnappliedAcceptedWork())
            { error = "CloneManifestJournalNotIdle"; return false; }
            Tx::MutationIntent intent;
            intent.kind = Tx::MutationKind::CloneFile; intent.path = prepared.path;
            intent.secondary_path = prepared.secondary_path; intent.object_id = prepared.object_id;
            intent.generation = prepared.generation; intent.length = prepared.length;
            intent.payload_length = prepared.length; intent.inline_payload = prepared.inline_payload;
            BCRYPT_ALG_HANDLE algorithm = nullptr;
            if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0)
            { error = "CloneManifestHashUnavailable"; return false; }
            const auto hashed = BCryptHash(algorithm, nullptr, 0,
                reinterpret_cast<PUCHAR>(intent.inline_payload.data()), static_cast<ULONG>(intent.inline_payload.size()),
                intent.payload_checksum.data(), 32);
            BCryptCloseAlgorithmProvider(algorithm, 0);
            if (hashed < 0) { error = "CloneManifestHashFailed"; return false; }
            acceptance_started = true;
            if (!c.tx_manager->Begin()) { error = "CloneManifestBeginFailed"; return false; }
            const auto transaction = c.tx_manager->CurrentTransactionId();
            if (!c.tx_manager->RetainAcceptedSequenceProof(transaction) || !c.tx_manager->RecordMutation(intent) ||
                !c.tx_manager->Accept(preimage))
            { error = "CloneManifestAcceptanceAmbiguous"; return false; }
            accepted = true; ticket.consumed = true;
            receipt = {transaction, c.tx_manager->Watermarks().accepted_sequence, preimage, proof.target};
            return c.tx_manager->LoadRequiredCheckpointXidsSinceCleanup(pins, &error);
        };
    const apfsaccess::catalog::ContainerPostpublicationVerifierHook verify =
        [&](const Store& live, std::uint64_t xid, std::string& error) {
            std::lock_guard journal(c.tx_mutex);
            std::vector<Tx::AcceptedTransaction> transactions;
            verified = accepted && xid == receipt.checkpoint + 1 &&
                c.tx_manager->LoadAcceptedTransactionsSinceCleanup(transactions) && transactions.size() == 1 &&
                transactions[0].mutations.size() == 1 &&
                VerifyAlreadyPublishedNativeClone(c, live, transactions[0].mutations[0], receipt.checkpoint);
            if (!verified) error = "CloneManifestPublicationUnproven";
            return verified;
        };
    ManifestCommitOutcome outcome;
    const auto status = CommitNativeMutationsBestEffort(&c, L"CloneManifestImport", bind, {}, prepare, verify,
        &outcome, false, [&] { return verified && PublishNativeCloneNamespace(c, target, receipt.target); },
        &preparation_refusal);
    if (!NT_SUCCESS(status) || !accepted || !verified)
    {
        if (!acceptance_started && outcome.clean_prepublication_refusal)
        {
            if (status == STATUS_DISK_FULL || status == STATUS_DEVICE_BUSY) return status;
            // An exception or failed invariant is not an unsupported capability
            // signal. Only our explicit admission refusal permits copy fallback.
            return preparation_completed ? STATUS_UNSUCCESSFUL : refusal;
        }
        return BlockNativeCloneRecovery(c, L"NativeCloneManifestPublicationFailed");
    }
    if (!FinalizeMutationJournalBestEffort(&c, L"CloneManifestImport"))
        return BlockNativeCloneRecovery(c, L"NativeCloneManifestCleanupFailed");
    bool cleaned = false;
    {
        std::lock_guard journal(c.tx_mutex);
        cleaned = c.tx_manager->Watermarks().cleanup_sequence >= receipt.sequence;
        if (cleaned) c.tx_manager->ReleaseAcceptedSequenceProof(receipt.transaction_id);
    }
    if (!cleaned) return BlockNativeCloneRecovery(c, L"NativeCloneManifestCleanupIncomplete");
    InvalidatePayloadIdentityCache(&c);
    return STATUS_SUCCESS;
}
