#pragma once

#include "SoftwareVolumeTransition.h"
#include <functional>
#include <utility>

namespace apfsaccess::rw { class SoftwareTransitionMetadataScope; }

namespace apfsaccess::catalog
{
// Only the held plain writer can construct this no-I/O reconstruction view.
// Retirement is checked against the actual successor, never the hidden NXSB.
class SoftwareTransitionCompletedProofSource final : public ImmutableEncryptedReadSource
{
    friend class rw::SoftwareTransitionMetadataScope;
    friend class SoftwareVolumeRetainedOwners;
    const RandomAccessSource& historical_;
    const ImmutableEncryptedReadSource& actual_;
    const SoftwareVolumeRetainedOwners& owners_;
    const std::uint64_t revision_, nx_block_;
    const std::vector<std::byte> nx_bytes_;
    const std::function<void(std::uint64_t, std::span<std::byte>)> overlay_;

    SoftwareTransitionCompletedProofSource(const RandomAccessSource& historical,
        const ImmutableEncryptedReadSource& actual, const SoftwareVolumeRetainedOwners& owners,
        const ContainerCheckpointView& current,
        std::function<void(std::uint64_t, std::span<std::byte>)> overlay)
        : historical_(historical), actual_(actual), owners_(owners), revision_(actual.Revision()),
          nx_block_(current.superblock_physical_block), nx_bytes_(current.superblock_bytes), overlay_(std::move(overlay)) {}

    bool ActualCheckpointUnchanged() const
    {
        std::vector<std::byte> bytes;
        return Revision() && nx_bytes_.size() == 4096 && nx_block_ < SizeBytes() / 4096 &&
            actual_.Read(nx_block_ * 4096, 4096, bytes) && bytes == nx_bytes_ && Revision();
    }
    bool ProveActualRetirement(const SoftwareVolumeRetainedOwners& owners,
        std::uint64_t xid, bool& retired, std::string& error) const
    {
        retired = false;
        if (&owners != &owners_ || !ActualCheckpointUnchanged()) {
            error = "SoftwareTransitionCompletedRetirementSourceChanged"; return false;
        }
        if (!owners.VerifyGenerationRetirement(actual_, owners.OriginalJournalIdentity(), xid, retired, error)) return false;
        if (!ActualCheckpointUnchanged()) {
            retired = false; error = "SoftwareTransitionCompletedRetirementSourceChanged"; return false;
        }
        return true;
    }
public:
    SoftwareTransitionCompletedProofSource(const SoftwareTransitionCompletedProofSource&) = delete;
    SoftwareTransitionCompletedProofSource& operator=(const SoftwareTransitionCompletedProofSource&) = delete;
    std::uint64_t SizeBytes() const override { return actual_.SizeBytes(); }
    std::string SourceIdentity() const override { return actual_.SourceIdentity(); }
    std::uint64_t Revision() const override
    { return revision_ && actual_.Revision() == revision_ && actual_.SourceIdentity() == owners_.SourceIdentity() ? revision_ : 0; }
    std::shared_ptr<ApfsReadBudget> ReadBudget() const override { return actual_.ReadBudget(); }
    bool Read(std::uint64_t at, std::size_t count, std::vector<std::byte>& bytes) const override
    {
        if (!Revision() || at > SizeBytes() || count > SizeBytes() - at ||
            !historical_.Read(at, count, bytes) || bytes.size() != count) return false;
        overlay_(at, bytes);
        return Revision() != 0;
    }
};
}
