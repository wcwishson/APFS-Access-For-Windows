bool BindSoftwareTransitionRetention(SnapshotPlanningSource& observed,
    const catalog::ImmutableEncryptedReadSource& source, std::shared_ptr<const catalog::SoftwareVolumeRetainedOwners> owners,
    const std::array<std::byte, 32>& jid, std::string& error)
{
    error.clear();
    if (&observed.source_ != &source || !observed.state_ || observed.state_->transition_owners || !owners ||
        !observed.state_->endpoint.empty() || owners->SourceIdentity() != source.SourceIdentity() ||
        owners->OriginalJournalIdentity() != jid)
        return Fail(error, "AppleSoftwareTransitionBindingInvalid");
    std::vector<catalog::SoftwareVolumeOwnedRange> exclusions;
    const auto revision = source.Revision();
    if (!owners->RevalidateProtectedHistory(source, jid, exclusions, error)) return false;
    auto current = catalog::LoadAppleCheckpointView(observed, 0, observed.SizeBytes(), error);
    if (!current || current->volumes.size() != 1 || current->container.superblock.block_size != 4096 ||
        current->volumes.front().superblock.object_id != owners->VolumeObjectId() ||
        current->volumes.front().superblock.uuid_hex != owners->VolumeUuid() ||
        current->volumes.front().superblock.fs_flags != catalog::kFsFlagUnencrypted)
        return Fail(error, "AppleSoftwareTransitionPlainEndpointRequired");
    for (const auto& generation : owners->Generations()) {
        std::string detail;
        auto retained = catalog::LoadContainerCheckpointView(observed, 0, observed.SizeBytes(), detail, generation.checkpoint.superblock.xid);
        if (!retained) continue; // Revalidate proved retirement through the actual successor.
        for (const auto* guards : {&generation.checkpoint_guards, &generation.graph_guards}) for (const auto& guard : *guards) {
            std::vector<std::byte> actual;
            if (!observed.Read(guard.physical_block * 4096, 4096, actual) || actual != guard.bytes)
                return Fail(error, "AppleSoftwareTransitionRetainedBytesChanged");
        }
    }
    if (source.Revision() != revision) return Fail(error, "AppleSoftwareTransitionSourceChanged");
    if (!observed.VerifyUnchanged(error)) return false;
    auto& state = *observed.state_;
    state.transition_source = &source; state.transition_revision = revision; state.transition_original_jid = jid;
    state.transition_exclusions = std::move(exclusions); state.transition_owners = std::move(owners); return true;
}

bool ConfigureSoftwareTransitionAllocation(const catalog::RandomAccessSource& source,
    const catalog::AppleCheckpointView& checkpoint, AppleSpacemanAllocationRequest& request, std::string& error)
{
    const auto* binding = SnapshotPlanningEvidenceAccess::Transition(source, error);
    if (!binding) return error.empty();
    if (checkpoint.volumes.size() != 1 || checkpoint.volumes.front().superblock.fs_flags != catalog::kFsFlagUnencrypted ||
        !VerifyAppleSpacemanOwnershipUnchanged(source, 0, source.SizeBytes(), checkpoint.container, checkpoint.spaceman, error)) return false;
    for (const auto& release : request.released_blocks) for (const auto& range : binding->transition_exclusions)
        if (release.physical_block < range.start_block + range.block_count && range.start_block < release.physical_block + release.block_count)
            return Fail(error, "AppleSoftwareTransitionRetainedOwnerRelease");
    request.reclaim_internal_pool_only = true;
    // Opaque epochs prove graph exclusions, not historical allocator snapshots.
    // Readable newer checkpoint pins retain the ordinary planner's bitmap proof.
    return true;
}

bool VerifySoftwareTransitionPublication(const catalog::RandomAccessSource& source,
    const AppleSpacemanAllocationPlan& allocation, AppleCheckpointPublicationPlan& publication, std::string& error)
{
    const auto* binding = SnapshotPlanningEvidenceAccess::Transition(source, error);
    if (!binding) return error.empty();
    for (const auto& write : publication.before_superblock_writes) for (const auto& range : binding->transition_exclusions)
        if (write.physical_block >= range.start_block && write.physical_block - range.start_block < range.block_count)
            return Fail(error, "AppleSoftwareTransitionRetainedOwnerOverwrite");
    for (const auto& range : binding->transition_exclusions)
        if (publication.superblock_write.physical_block >= range.start_block &&
            publication.superblock_write.physical_block - range.start_block < range.block_count)
            return Fail(error, "AppleSoftwareTransitionRetainedOwnerOverwrite");
    for (const auto& free : allocation.deferred_frees) for (const auto& range : binding->transition_exclusions)
        if (free.physical_block < range.start_block + range.block_count && range.start_block < free.physical_block + free.block_count)
            return Fail(error, "AppleSoftwareTransitionRetainedOwnerFree");
    class Candidate final : public catalog::ImmutableEncryptedReadSource {
        const catalog::ImmutableEncryptedReadSource& source_;
        SnapshotPublicationSource overlay_;
    public:
        Candidate(const catalog::ImmutableEncryptedReadSource& source, const AppleCheckpointPublicationPlan& plan) : source_(source), overlay_(source, plan) {}
        std::uint64_t SizeBytes() const override { return overlay_.SizeBytes(); }
        std::shared_ptr<catalog::ApfsReadBudget> ReadBudget() const override { return source_.ReadBudget(); }
        std::string SourceIdentity() const override { return source_.SourceIdentity(); }
        std::uint64_t Revision() const override { return source_.Revision(); }
        bool Read(std::uint64_t at, std::size_t count, std::vector<std::byte>& bytes) const override { return overlay_.Read(at, count, bytes); }
    } candidate(*binding->transition_source, publication);
    std::vector<catalog::SoftwareVolumeOwnedRange> retained;
    if (!binding->transition_owners->RevalidateProtectedHistory(candidate, binding->transition_original_jid, retained, error)) return false;
    for (const auto& generation : binding->transition_owners->Generations()) {
        std::string detail;
        if (!catalog::LoadContainerCheckpointView(source, 0, source.SizeBytes(), detail, generation.checkpoint.superblock.xid)) continue;
        const bool survives = catalog::LoadContainerCheckpointView(candidate, 0, candidate.SizeBytes(), detail,
            generation.checkpoint.superblock.xid).has_value();
        for (const auto* guards : {&generation.checkpoint_guards, &generation.graph_guards}) for (const auto& guard : *guards) {
            const auto rewritten = std::find_if(publication.before_superblock_writes.begin(), publication.before_superblock_writes.end(),
                [&](const auto& write) { return write.physical_block == guard.physical_block && write.bytes != guard.bytes; });
            const bool switched = publication.superblock_write.physical_block == guard.physical_block &&
                publication.superblock_write.bytes != guard.bytes;
            if (rewritten != publication.before_superblock_writes.end() || switched) {
                if (guards != &generation.checkpoint_guards || survives)
                    return Fail(error, "AppleSoftwareTransitionRetainedGuardOverwrite");
                // The full candidate proved canonical retirement above. Fresh
                // replay must separately match the exact authorized plan prefix.
                continue;
            }
            const auto existing = std::find_if(publication.guard_blocks.begin(), publication.guard_blocks.end(),
                [&](const auto& item) { return item.physical_block == guard.physical_block; });
            if (existing != publication.guard_blocks.end()) {
                if (existing->bytes != guard.bytes) return Fail(error, "AppleSoftwareTransitionGuardConflict");
            } else {
                if (!source.ReadBudget()->Materialize(1, sizeof(guard) + guard.bytes.size()))
                    return Fail(error, source.ReadBudget()->Failure());
                publication.guard_blocks.push_back(guard);
            }
        }
    }
    return true;
}
