std::unique_ptr<EncryptedCowOverwrite> ApfsEncryptedReadSession::PrepareDeltaMutationWithTransitionRetention(
    const ImmutableEncryptedReadSource& source, std::uint64_t xid, const EncryptedMutationRequest& request,
    const SoftwareVolumeRetainedOwners& owners, const std::array<std::byte, 32>& original_jid,
    std::string& error, std::span<const std::uint64_t> recovery, std::span<const std::uint64_t> read_pins)
{
    std::lock_guard lock(impl_->mutex); impl_->failure = Error::None; error.clear();
    try {
        Impl::RuntimeScope scope(*impl_);
        if (!impl_->Check()) { error = "EncryptedDeltaSessionRevoked"; return {}; }
        if (&source != impl_->source.get() || xid != impl_->checkpoint.superblock.xid)
        { error = "EncryptedDeltaSourceOrCheckpointMismatch"; return {}; }
        Impl::CowPlanner planner(*impl_, error, true);
        if (!planner.BindTransitionRetention(owners, original_jid)) return {};
        auto result = planner.Prepare(request, recovery, read_pins);
        if (!result && error.empty()) error = "EncryptedDeltaTransitionPreparationFailed";
        return result;
    } catch (const std::bad_alloc&) { error = "EncryptedDeltaTransitionResourceLimit"; }
      catch (...) { error = "EncryptedDeltaTransitionPreparationException"; }
    return {};
}
