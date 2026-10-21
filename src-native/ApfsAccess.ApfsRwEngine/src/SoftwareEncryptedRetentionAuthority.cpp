#include "SoftwareEncryptedRetentionAuthority.h"
#include <algorithm>

namespace apfsaccess::catalog
{
std::unique_ptr<SoftwareEncryptedRetentionAuthority> SoftwareEncryptedRetentionAuthority::Bind(
    const ImmutableEncryptedReadSource& source, const ContainerCheckpointView& admitted,
    const ApsbVolume& volume, const SoftwareVolumeRetainedOwners& owners,
    const std::array<std::byte, 32>& jid, std::string& error)
{
    error.clear();
    const auto revision = source.Revision();
    std::vector<SoftwareVolumeOwnedRange> exclusions;
    if (!revision || source.SourceIdentity() != owners.SourceIdentity() || owners.OriginalJournalIdentity() != jid ||
        volume.object_id != owners.VolumeObjectId() || volume.uuid_hex != owners.VolumeUuid() || volume.fs_flags != kFsFlagOneKey ||
        admitted.superblock.uuid_hex != owners.ContainerUuid() || admitted.superblock.block_size != 4096 ||
        admitted.superblock.block_count != owners.ContainerBlockCount() ||
        !owners.RevalidateProtectedHistory(source, jid, exclusions, error)) {
        if (error.empty()) error = "EncryptedCowTransitionProtectedScopeRequired";
        return {};
    }
    auto actual = LoadContainerCheckpointView(source, 0, source.SizeBytes(), error);
    auto volumes = actual ? LoadAppleReadOnlyVolumeView(source, *actual, error) : std::nullopt;
    if (!actual || actual->superblock_physical_block != admitted.superblock_physical_block ||
        actual->superblock_bytes != admitted.superblock_bytes || !volumes || volumes->volumes.size() != 1 ||
        volumes->volumes.front().superblock.object_id != volume.object_id ||
        volumes->volumes.front().superblock.uuid_hex != volume.uuid_hex ||
        volumes->volumes.front().superblock.xid != volume.xid ||
        volumes->volumes.front().superblock.fs_flags != kFsFlagOneKey || source.Revision() != revision) {
        error = "EncryptedCowTransitionCurrentAdmissionChanged"; return {};
    }
    return std::unique_ptr<SoftwareEncryptedRetentionAuthority>(
        new SoftwareEncryptedRetentionAuthority(source, owners, jid, std::move(exclusions)));
}

SoftwareEncryptedRetentionAuthority::Generation SoftwareEncryptedRetentionAuthority::Admit(
    const RandomAccessSource& observed, const ContainerCheckpointView& cp, bool pinned, std::string& error) const
{
    error.clear();
    if (source_.Revision() != revision_ || source_.SourceIdentity() != owners_.SourceIdentity() ||
        observed.SizeBytes() != source_.SizeBytes()) {
        error = "EncryptedCowTransitionSourceChanged"; return {};
    }
    const auto found = std::find_if(owners_.Generations().begin(), owners_.Generations().end(),
        [&](const auto& generation) { return generation.checkpoint.superblock.xid == cp.superblock.xid; });
    if (found == owners_.Generations().end()) return {Admission::Ordinary, nullptr};
    if (pinned) { error = "EncryptedCowTransitionOpaquePinUnsupported"; return {}; }
    if (cp.superblock.xid > owners_.MintedCheckpointXid() ||
        cp.superblock_physical_block != found->checkpoint.superblock_physical_block ||
        cp.superblock_bytes != found->checkpoint.superblock_bytes) {
        error = "EncryptedCowTransitionHistoricalCheckpointChanged"; return {};
    }
    for (const auto* guards : {&found->checkpoint_guards, &found->graph_guards}) for (const auto& guard : *guards) {
        std::vector<std::byte> actual;
        if (guard.bytes.size() != 4096 || guard.physical_block >= observed.SizeBytes() / 4096 ||
            !observed.Read(guard.physical_block * 4096, 4096, actual) || actual != guard.bytes) {
            error = "EncryptedCowTransitionHistoricalGuardChanged"; return {};
        }
    }
    if (source_.Revision() != revision_) { error = "EncryptedCowTransitionSourceChanged"; return {}; }
    return {Admission::Opaque, &*found};
}

bool SoftwareEncryptedRetentionAuthority::VerifyCandidate(const RandomAccessSource& candidate,
    const rw::AppleSpacemanAllocationPlan& allocation, const rw::AppleCheckpointPublicationPlan& publication,
    std::string& error) const
{
    error.clear();
    const auto intersects = [&](std::uint64_t block, std::uint64_t count) {
        if (!count || block > UINT64_MAX - count) return true;
        return std::any_of(exclusions_.begin(), exclusions_.end(), [&](const auto& range) {
            return range.start_block > UINT64_MAX - range.block_count ||
                (block < range.start_block + range.block_count && range.start_block < block + count);
        });
    };
    if (source_.Revision() != revision_ || candidate.SizeBytes() != source_.SizeBytes() ||
        std::any_of(publication.before_superblock_writes.begin(), publication.before_superblock_writes.end(),
            [&](const auto& write) { return intersects(write.physical_block, 1); }) ||
        intersects(publication.superblock_write.physical_block, 1) || publication.fusion_tier2_anchor_write ||
        std::any_of(allocation.deferred_frees.begin(), allocation.deferred_frees.end(),
            [&](const auto& range) { return intersects(range.physical_block, range.block_count); })) {
        error = "EncryptedCowTransitionRetainedOwnerDestinationOrFree"; return false;
    }
    class CandidateSource final : public ImmutableEncryptedReadSource
    {
        const RandomAccessSource& candidate_;
        const ImmutableEncryptedReadSource& actual_;
    public:
        CandidateSource(const RandomAccessSource& candidate, const ImmutableEncryptedReadSource& actual) : candidate_(candidate), actual_(actual) {}
        std::uint64_t SizeBytes() const override { return candidate_.SizeBytes(); }
        std::string SourceIdentity() const override { return actual_.SourceIdentity(); }
        std::uint64_t Revision() const override { return actual_.Revision(); }
        std::shared_ptr<ApfsReadBudget> ReadBudget() const override { return candidate_.ReadBudget(); }
        bool Read(std::uint64_t offset, std::size_t count, std::vector<std::byte>& bytes) const override { return candidate_.Read(offset, count, bytes); }
    } observed(candidate, source_);
    std::vector<SoftwareVolumeOwnedRange> after;
    if (!owners_.RevalidateProtectedHistory(observed, jid_, after, error)) return false;
    if (source_.Revision() != revision_) { error = "EncryptedCowTransitionSourceChanged"; return false; }
    return true;
}
}
