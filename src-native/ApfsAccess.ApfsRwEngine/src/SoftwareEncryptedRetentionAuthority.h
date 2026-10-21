#pragma once

#include "SoftwareVolumeTransition.h"
#include "AppleSpacemanAllocator.h"

namespace apfsaccess::catalog
{
// Private COW-planner proof. Opaque history never becomes a read context.
class SoftwareEncryptedRetentionAuthority final
{
public:
    enum class Admission { Ordinary, Opaque, Refused };
    struct Generation
    {
        Admission admission = Admission::Refused;
        const SoftwareVolumeRetainedGeneration* owners = nullptr;
    };
    static std::unique_ptr<SoftwareEncryptedRetentionAuthority> Bind(
        const ImmutableEncryptedReadSource& exact_source, const ContainerCheckpointView& admitted_current,
        const ApsbVolume& admitted_volume, const SoftwareVolumeRetainedOwners& protected_owners,
        const std::array<std::byte, 32>& actual_original_journal_identity, std::string& error);
    Generation Admit(const RandomAccessSource& observed, const ContainerCheckpointView& historical,
        bool required_recovery_or_read_pin, std::string& error) const;
    bool VerifyCandidate(const RandomAccessSource& candidate, const rw::AppleSpacemanAllocationPlan&,
        const rw::AppleCheckpointPublicationPlan&, std::string& error) const;
private:
    SoftwareEncryptedRetentionAuthority(const ImmutableEncryptedReadSource& source,
        const SoftwareVolumeRetainedOwners& owners, const std::array<std::byte, 32>& jid,
        std::vector<SoftwareVolumeOwnedRange> exclusions)
        : source_(source), owners_(owners), jid_(jid), revision_(source.Revision()), exclusions_(std::move(exclusions)) {}
    const ImmutableEncryptedReadSource& source_;
    const SoftwareVolumeRetainedOwners& owners_;
    const std::array<std::byte, 32> jid_;
    const std::uint64_t revision_;
    const std::vector<SoftwareVolumeOwnedRange> exclusions_;
};
}
