bool ApfsEncryptedImageWriteSession::RotateVolumeKey(rw::TransactionManager& tx,
    rw::EncryptedPublicationJournal& journal, std::uint64_t xid,
    const crypto::SecureBytes& old_password, const crypto::SecureBytes& new_password,
    PasswordUnlockBudget& budget, std::uint64_t& accepted, std::string& error,
    const rw::AppleCheckpointStageHook& hook)
{
    std::lock_guard lock(impl_->gate); error.clear(); accepted = 0;
    const auto status = impl_->Snapshot();
    if (impl_->cancelled->load() || status.recovery_required || status.checkpoint_xid != xid ||
        (status.phase != Phase::Ready && status.phase != Phase::Locked) ||
        !old_password.IsLocked() || !new_password.IsLocked() ||
        tx.ProtectedSourceBinding() != std::optional{impl_->binding}) {
        error = "ImageWriterKeyRotationOwnerRequired"; return false;
    }
    impl_->PruneInodes();
    if (!impl_->read_inodes.empty()) { error = "ImageWriterOpenReadInodesKeyRotationUnsupported"; return false; }
    bool authorization_attempted = false;
    const auto failed_authorization = [&] {
        impl_->Revoke(); impl_->key.xts_key.Clear(); impl_->admitted = {};
        impl_->PhaseTo(Phase::Locked, true); return false;
    };
    try {
        const auto jid = tx.ProtectedJournalIdentity();
        if (!jid) { error = "ImageWriterKeyRotationOriginalIdentityRequired"; return false; }
        impl_->PhaseTo(Phase::Preparing);
        auto source = impl_->NewSource();
        std::unique_ptr<const SoftwareVolumeRetainedOwners> retained;
        std::vector<std::uint64_t> required;
        if (!journal.TryRestoreTransitionRetainedOwners(tx, *source, retained, error) ||
            !tx.LoadRequiredCheckpointXidsSinceCleanup(required, &error)) {
            impl_->PhaseTo(status.phase); return false;
        }
        auto prepared = SoftwareVolumeKeyRotation::Prepare(source, impl_->identity, source->Revision(),
            impl_->image.volume_oid, old_password, new_password, budget, *jid, retained.get(), error, required);
        if (!prepared) { impl_->PhaseTo(status.phase); return false; }
        if (prepared->SourceIdentity() != impl_->identity || prepared->SourceBinding() != impl_->binding ||
            prepared->OriginalJournalIdentity() != *jid || prepared->VolumeObjectId() != impl_->image.volume_oid ||
            prepared->VolumeUuid() != impl_->volume_uuid || prepared->Publication().expected_checkpoint_xid != xid) {
            error = "ImageWriterKeyRotationScopeMismatch"; impl_->PhaseTo(status.phase); return false;
        }
        if (impl_->cancelled->load()) { error = "ImageWriterCancelled"; impl_->PhaseTo(status.phase); return false; }
        authorization_attempted = true;
        if (!journal.AcceptKeyRotation(tx, *prepared, accepted, error)) return failed_authorization();
        impl_->Revoke(); impl_->key.xts_key.Clear(); impl_->admitted = {};
        impl_->PhaseTo(Phase::Locked, true);
        if (impl_->cancelled->load()) { error = "ImageWriterCancelled"; return false; }
        if (hook && !hook("after-encrypted-original-accept")) {
            error = "ImageWriterKeyRotationInterruptedBeforeStage"; return false;
        }
        if (!journal.StageKeyRotation(tx, accepted, *prepared, error)) return false;
        prepared.reset();
        return impl_->Publish(tx, journal, accepted, error, hook);
    } catch (const std::exception& ex) {
        error = ex.what();
        if (authorization_attempted) return failed_authorization();
        impl_->PhaseTo(status.phase); return false;
    }
}
bool ApfsEncryptedImageWriteSession::RecoverAcceptedKeyRotation(rw::TransactionManager& tx,
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
            error = "ImageWriterKeyRotationRecoveryOwnerRequired"; return failed();
        }
        if (!journal.RestageKeyRotation(tx, accepted, error)) return failed();
        impl_->Revoke(); impl_->key.xts_key.Clear(); impl_->admitted = {};
        impl_->PhaseTo(Phase::Locked, true);
        return impl_->Publish(tx, journal, accepted, error, hook);
    } catch (const std::exception& ex) { error = ex.what(); return failed(); }
}
