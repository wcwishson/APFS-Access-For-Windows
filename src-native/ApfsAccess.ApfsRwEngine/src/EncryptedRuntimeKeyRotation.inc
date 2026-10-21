bool EncryptedImageRuntime::RotateVolumeKey(const crypto::SecureBytes& old_password,
    const crypto::SecureBytes& new_password, PasswordUnlockBudget& budget, std::string& error,
    const r::AppleCheckpointStageHook& hook)
{
    std::lock_guard lock(impl_->gate); error.clear();
    if (impl_->closed.load()) { error = "EncryptedRuntimeClosed"; return false; }
    if (impl_->recovery.load() && !impl_->Recover(error, hook)) return false;
    const auto status = impl_->image->CachedStatus();
    if (status.recovery_required || (status.phase != Phase::Ready && status.phase != Phase::Locked)) {
        error = "EncryptedRuntimeKeyRotationOwnerRequired"; return false;
    }
    std::uint64_t accepted = 0;
    try {
        if (!impl_->transition_history_pinned && impl_->commits_since_continuation >= 8 &&
            !impl_->ContinueCleanHistory(error, hook, true)) return false;
        const auto observed_hook = [&](std::string_view stage) {
            impl_->Observe(); return !hook || hook(stage);
        };
        const auto published = impl_->image->RotateVolumeKey(*impl_->transactions, *impl_->witness,
            status.checkpoint_xid, old_password, new_password, budget, accepted, error, observed_hook);
        if (accepted) impl_->transition_history_pinned = true;
        if (!published && impl_->image->CachedStatus().recovery_required) {
            const auto marks = impl_->transactions->Watermarks();
            if (marks.accepted_sequence == marks.cleanup_sequence) impl_->owner_failed = true;
        }
        impl_->Observe();
        return published && impl_->Finish(accepted, error);
    } catch (const std::exception& ex) {
        impl_->owner_failed = true; impl_->Observe(); error = ex.what(); return false;
    }
}
