#pragma once

#include "RandomAccessSource.h"
#include "AppleCheckpointPublisher.h"
#include "ApfsTransactionWriter.h"
#include "SoftwareVolumeTransition.h"
#include <algorithm>

namespace apfsaccess::rw {

class SnapshotPlanningEvidenceAccess;
struct AppleSnapshotRetentionView;
struct AppleSpacemanAllocationRequest;
struct AppleSpacemanAllocationPlan;

struct SnapshotRetentionCatalog {
    std::uint64_t volume_oid;
    catalog::AppleSnapshotCatalogRecords records;
    std::vector<ApplePhysicalExtentRecord> live_payload;
    std::vector<std::vector<ApplePhysicalExtentRecord>> snapshot_payloads;
    std::vector<std::pair<std::uint64_t,std::vector<std::byte>>> metadata_preimages;
};

bool LoadSnapshotPlanningRetentionCatalogs(const catalog::RandomAccessSource& source,
    const catalog::AppleCheckpointView& checkpoint, AppleSnapshotRetentionView& retention,
    std::shared_ptr<const std::vector<SnapshotRetentionCatalog>>& catalogs, std::string& error);

// Exact serialized publication view shared by the planner and its final
// census. Original reads keep their budget and source observation binding.
class SnapshotPublicationSource final : public catalog::RandomAccessSource {
public:
    SnapshotPublicationSource(const catalog::RandomAccessSource& base,
        const AppleCheckpointPublicationPlan& plan) : base_(base), plan_(plan) {}
    std::uint64_t SizeBytes() const override { return base_.SizeBytes(); }
    std::shared_ptr<catalog::ApfsReadBudget> ReadBudget() const override { return base_.ReadBudget(); }
    const catalog::RandomAccessSource& Base() const { return base_; }
    bool Read(std::uint64_t offset, std::size_t size, std::vector<std::byte>& out) const override {
        if (offset > SizeBytes() || size > SizeBytes() - offset ||
            !base_.Read(offset, size, out) || out.size() != size) return false;
        const auto end = offset + size;
        const auto apply = [&](const AppleCheckpointPlannedWrite& write) {
            if (write.physical_block > UINT64_MAX / plan_.block_size) return false;
            const auto begin = write.physical_block * plan_.block_size;
            if (begin > SizeBytes() || write.bytes.size() > SizeBytes() - begin) return false;
            const auto first = (std::max)(offset, begin);
            const auto last = (std::min)(end, begin + write.bytes.size());
            if (first < last) std::copy(write.bytes.begin() + (first - begin),
                write.bytes.begin() + (last - begin), out.begin() + (first - offset));
            return true;
        };
        if (!plan_.block_size) return false;
        for (const auto& write : plan_.before_superblock_writes) if (!apply(write)) return false;
        return apply(plan_.superblock_write);
    }
private:
    const catalog::RandomAccessSource& base_;
    const AppleCheckpointPublicationPlan& plan_;
};

// One planner invocation owns completed proofs and their exact source bytes.
// Reads still reach the original transport; changed dependencies refuse reuse.
class SnapshotPlanningSource final : public catalog::RandomAccessSource {
public:
    explicit SnapshotPlanningSource(const catalog::RandomAccessSource& source);
    ~SnapshotPlanningSource();
    std::uint64_t SizeBytes() const override;
    std::shared_ptr<catalog::ApfsReadBudget> ReadBudget() const override;
    bool Read(std::uint64_t offset, std::size_t size, std::vector<std::byte>& out) const override;
    bool VerifyUnchanged(std::string& error) const;
private:
    friend class SnapshotPlanningEvidenceAccess;
    friend bool BindSoftwareTransitionRetention(SnapshotPlanningSource&,
        const catalog::ImmutableEncryptedReadSource&, std::shared_ptr<const catalog::SoftwareVolumeRetainedOwners>,
        const std::array<std::byte, 32>&, std::string&);
    struct State;
    const catalog::RandomAccessSource& source_;
    const std::uint64_t size_;
    std::unique_ptr<State> state_;
};

bool BindSoftwareTransitionRetention(SnapshotPlanningSource&,
    const catalog::ImmutableEncryptedReadSource&, std::shared_ptr<const catalog::SoftwareVolumeRetainedOwners>,
    const std::array<std::byte, 32>& actual_original_journal_identity, std::string&);
bool ConfigureSoftwareTransitionAllocation(const catalog::RandomAccessSource&,
    const catalog::AppleCheckpointView&, AppleSpacemanAllocationRequest&, std::string&);
bool VerifySoftwareTransitionPublication(const catalog::RandomAccessSource&,
    const AppleSpacemanAllocationPlan&, AppleCheckpointPublicationPlan&, std::string&);

}
