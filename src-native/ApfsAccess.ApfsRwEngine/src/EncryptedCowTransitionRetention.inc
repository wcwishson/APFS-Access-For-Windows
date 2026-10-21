// Included inside the private CowPlanner after its ordinary owner helpers.
std::unique_ptr<SoftwareEncryptedRetentionAuthority> transition_retention;

bool BindTransitionRetention(const SoftwareVolumeRetainedOwners& retained,
    const std::array<std::byte, 32>& actual_original_jid)
{
    transition_retention = SoftwareEncryptedRetentionAuthority::Bind(
        *owner.source, owner.checkpoint, owner.volume, retained, actual_original_jid, error);
    return static_cast<bool>(transition_retention);
}

SoftwareEncryptedRetentionAuthority::Admission AdmitTransitionGeneration(
    const ContainerCheckpointView& checkpoint, bool required_recovery_or_read_pin)
{
    using Admission = SoftwareEncryptedRetentionAuthority::Admission;
    if (!transition_retention) return Admission::Ordinary;
    const auto proved = transition_retention->Admit(source, checkpoint, required_recovery_or_read_pin, error);
    if (proved.admission != Admission::Opaque) return proved.admission;
    if (!proved.owners) { Fail("EncryptedCowTransitionOwnerProofMissing"); return Admission::Refused; }
    for (const auto& range : proved.owners->ranges) for (std::uint64_t i = 0; i < range.block_count; ++i) {
        auto& owned = range.kind == SoftwareVolumeOwnerKind::Payload ? payload : metadata;
        if (!Remember(owned, range.start_block + i)) return Admission::Refused;
    }
    return Admission::Opaque;
}

bool VerifyTransitionRetention(const Candidate& candidate, const rw::AppleSpacemanAllocationPlan& allocation,
    const rw::AppleCheckpointPublicationPlan& publication)
{
    return !transition_retention || transition_retention->VerifyCandidate(candidate, allocation, publication, error);
}
