bool ApfsEncryptedImageWriteSession::RecoverAcceptedMutation(rw::TransactionManager& tx,
    rw::EncryptedPublicationJournal& journal, std::uint64_t accepted, std::span<const std::byte> payload,
    std::string& error, std::span<const std::uint64_t> required, const rw::AppleCheckpointStageHook& hook)
{
    return RecoverAcceptedMutationCore(tx, journal, accepted, payload, error, required, hook, RetainedDataRecovery::Existing);
}
bool ApfsEncryptedImageWriteSession::RecoverAcceptedMutationWithTransitionRetention(rw::TransactionManager& tx,
    rw::EncryptedPublicationJournal& journal, std::uint64_t accepted, std::span<const std::byte> payload,
    std::string& error, std::span<const std::uint64_t> required, const rw::AppleCheckpointStageHook& hook)
{
    return RecoverAcceptedMutationCore(tx, journal, accepted, payload, error, required, hook, RetainedDataRecovery::ProtectedTransitionOwners);
}

std::unique_ptr<ApfsEncryptedImageWriteSession::PreparedMutation>
ApfsEncryptedImageWriteSession::PrepareMutationWithTransitionRetention(rw::TransactionManager& tx,
    rw::EncryptedPublicationJournal& journal, std::uint64_t xid, const EncryptedMutationRequest& request,
    std::string& error, std::span<const std::uint64_t> required)
{
    std::lock_guard lock(impl_->gate); error.clear();
    const auto status = impl_->Snapshot();
    if (impl_->cancelled->load()) { error = "ImageWriterCancelled"; return {}; }
    if (status.phase != Phase::Ready || status.checkpoint_xid != xid || !impl_->key ||
        !impl_->current || !impl_->current_source || tx.ProtectedSourceBinding() != std::optional{impl_->binding}) {
        error = "ImageWriterReadyCurrentCheckpointRequired"; return {};
    }
    try {
        const auto jid = tx.ProtectedJournalIdentity();
        if (!jid) { error = "ImageWriterTransitionOriginalIdentityRequired"; return {}; }
        impl_->PhaseTo(Phase::Preparing);
        std::unique_ptr<const SoftwareVolumeRetainedOwners> owners;
        if (!journal.TryRestoreTransitionRetainedOwners(tx, *impl_->current_source, owners, error)) {
            impl_->PhaseTo(Phase::Ready); return {};
        }
        const auto read_pins = impl_->ReadPins(&request);
        auto capability = owners
            ? impl_->current->PrepareDeltaMutationWithTransitionRetention(*impl_->current_source, xid,
                request, *owners, *jid, error, required, read_pins)
            : impl_->current->PrepareDeltaMutationWithReadPins(*impl_->current_source, xid, request, error, required, read_pins);
        if (!capability || impl_->cancelled->load()) {
            if (impl_->cancelled->load()) error = "ImageWriterCancelled";
            impl_->PhaseTo(Phase::Ready); return {};
        }
        auto result = std::unique_ptr<PreparedMutation>(new PreparedMutation);
        result->source_ = impl_->current_source; result->prepared_ = std::move(capability);
        impl_->PhaseTo(Phase::Ready); return result;
    } catch (const std::exception& exception) {
        impl_->PhaseTo(Phase::Ready); error = exception.what(); return {};
    }
}
