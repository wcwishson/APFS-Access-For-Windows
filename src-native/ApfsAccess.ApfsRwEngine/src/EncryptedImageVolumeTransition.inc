bool ApfsEncryptedImageWriteSession::TransitionVolume(SoftwareVolumeMode desired,
    rw::TransactionManager& tx, rw::EncryptedPublicationJournal& journal, std::uint64_t xid,
    const crypto::SecureBytes& password, PasswordUnlockBudget& budget, std::uint64_t& accepted,
    std::string& error, const rw::AppleCheckpointStageHook& hook)
{
    std::lock_guard lock(impl_->gate); error.clear(); accepted = 0;
    const auto status = impl_->Snapshot();
    if (impl_->cancelled->load() || status.recovery_required || status.checkpoint_xid != xid ||
        (status.phase != Phase::Ready && status.phase != Phase::Locked) ||
        !password.IsLocked() || tx.ProtectedSourceBinding() != std::optional{impl_->binding}) {
        error = "ImageWriterTransitionOwnerRequired"; return false;
    }
    impl_->PruneInodes();
    if (!impl_->read_inodes.empty()) { error = "ImageWriterOpenReadInodesTransitionUnsupported"; return false; }
    bool authorization_attempted = false;
    const auto lock_for_recovery = [&] {
        impl_->Revoke(); impl_->key.xts_key.Clear(); impl_->admitted = {};
        impl_->PhaseTo(Phase::Locked, true); return false;
    };
    try {
        const auto jid = tx.ProtectedJournalIdentity();
        if (!jid) { error = "ImageWriterTransitionOriginalIdentityRequired"; return false; }
        impl_->PhaseTo(Phase::Preparing);
        auto source = impl_->NewSource();
        std::unique_ptr<const SoftwareVolumeRetainedOwners> retained;
        if (!journal.TryRestoreTransitionRetainedOwners(tx, *source, retained, error)) {
            impl_->PhaseTo(status.phase); return false;
        }
        std::vector<std::uint64_t> required;
        if (!tx.LoadRequiredCheckpointXidsSinceCleanup(required, &error)) {
            impl_->PhaseTo(status.phase); return false;
        }
        auto prepared = desired == SoftwareVolumeMode::Plain
            ? SoftwareVolumeTransition::PrepareDecryption(source, impl_->identity, source->Revision(),
                impl_->image.volume_oid, impl_->image.keybag_length, password, budget, *jid, error, required, {}, retained.get())
            : SoftwareVolumeTransition::PrepareEncryption(source, impl_->identity, source->Revision(),
                impl_->image.volume_oid, password, budget, *jid, retained.get(), error, required);
        if (!prepared) { impl_->PhaseTo(status.phase); return false; }
        if (prepared->AfterMode() != desired || prepared->BeforeMode() == desired ||
            prepared->SourceIdentity() != impl_->identity || prepared->SourceBinding() != impl_->binding ||
            prepared->OriginalJournalIdentity() != *jid || prepared->VolumeObjectId() != impl_->image.volume_oid ||
            prepared->VolumeUuid() != impl_->volume_uuid || prepared->Publication().expected_checkpoint_xid != xid) {
            error = "ImageWriterTransitionScopeMismatch"; impl_->PhaseTo(status.phase); return false;
        }
        if (impl_->cancelled->load()) { error = "ImageWriterCancelled"; impl_->PhaseTo(status.phase); return false; }
        authorization_attempted = true;
        if (!journal.AcceptTransition(tx, *prepared, accepted, error)) return lock_for_recovery();
        impl_->Revoke(); impl_->key.xts_key.Clear(); impl_->admitted = {};
        impl_->PhaseTo(Phase::Locked, true);
        if (impl_->cancelled->load()) { error = "ImageWriterCancelled"; return false; }
        if (hook && !hook("after-encrypted-original-accept")) {
            error = "ImageWriterTransitionInterruptedBeforeStage"; return false;
        }
        if (!journal.StageTransition(tx, accepted, *prepared, error)) return false;
        prepared.reset();
        return impl_->Publish(tx, journal, accepted, error, hook);
    } catch (const std::exception& ex) {
        error = ex.what();
        if (authorization_attempted) return lock_for_recovery();
        impl_->PhaseTo(status.phase); return false;
    }
}
bool ApfsEncryptedImageWriteSession::Encrypt(rw::TransactionManager& tx, rw::EncryptedPublicationJournal& journal,
    std::uint64_t xid, const crypto::SecureBytes& password, PasswordUnlockBudget& budget,
    std::uint64_t& accepted, std::string& error, const rw::AppleCheckpointStageHook& hook)
{ return TransitionVolume(SoftwareVolumeMode::OneKeyGenerationZero, tx, journal, xid, password, budget, accepted, error, hook); }
bool ApfsEncryptedImageWriteSession::Decrypt(rw::TransactionManager& tx, rw::EncryptedPublicationJournal& journal,
    std::uint64_t xid, const crypto::SecureBytes& password, PasswordUnlockBudget& budget,
    std::uint64_t& accepted, std::string& error, const rw::AppleCheckpointStageHook& hook)
{ return TransitionVolume(SoftwareVolumeMode::Plain, tx, journal, xid, password, budget, accepted, error, hook); }
bool ApfsEncryptedImageWriteSession::RecoverAcceptedTransition(rw::TransactionManager& tx,
    rw::EncryptedPublicationJournal& journal, std::uint64_t accepted, std::string& error,
    const rw::AppleCheckpointStageHook& hook)
{
    std::lock_guard lock(impl_->gate); error.clear();
    if (impl_->Snapshot().phase == Phase::Closed) { error = "ImageWriterClosed"; return false; }
    const auto failed = [&] {
        impl_->Revoke(); impl_->key.xts_key.Clear(); impl_->admitted = {};
        impl_->PhaseTo(Phase::Locked, true); return false;
    };
    try {
        if (impl_->cancelled->load() || tx.ProtectedSourceBinding() != std::optional{impl_->binding}) {
            error = "ImageWriterTransitionRecoveryOwnerRequired"; return failed();
        }
        if (!journal.RestageTransition(tx, accepted, error)) return failed();
        impl_->Revoke(); impl_->key.xts_key.Clear(); impl_->admitted = {};
        impl_->PhaseTo(Phase::Locked, true);
        return impl_->Publish(tx, journal, accepted, error, hook);
    } catch (const std::exception& ex) { error = ex.what(); return failed(); }
}
