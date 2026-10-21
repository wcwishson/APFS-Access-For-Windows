#pragma once
#include "NativeCountRepair.h"
#include "VolumeMetadata.h"
#include "ApfsVerifier.h"

namespace apfsaccess::rw
{
// Noncopyable, immutable capability bound to this live image owner. A failed
// confirmation or apply consumes it too. No arbitrary replacement metadata.
class ApfsCountRepairPlan final
{
public:
    ApfsCountRepairPlan() = default;
    static constexpr bool DataLossPossible = false;
    ApfsCountRepairPlan(const ApfsCountRepairPlan&) = delete;
    ApfsCountRepairPlan& operator=(const ApfsCountRepairPlan&) = delete;
    const NativeCountRepair& Evidence() const { return evidence_; }
    const std::string& ConfirmationToken() const { return token_; }
    const catalog::VerificationFinding& Finding() const { return finding_; }
private:
    NativeCountRepair evidence_;
    MetadataStore::MutationRequest request_;
    const catalog::ContainerMountCoordinator* owner_ = nullptr;
    std::chrono::steady_clock::time_point expires_{};
    std::string token_;
    std::string source_witness_;
    std::string image_preimage_;
    catalog::VerificationFinding finding_;
    std::atomic<bool> consumed_{false};
    std::weak_ptr<const std::uint8_t> lifetime_;
    friend bool PrepareApfsCountRepair(catalog::ContainerMountCoordinator&, std::uint64_t, ApfsCountRepairPlan&, std::string&, std::chrono::milliseconds);
    friend catalog::ContainerCommitResult ApplyApfsCountRepair(catalog::ContainerMountCoordinator&, TransactionManager&, ApfsCountRepairPlan&, std::string_view);
};
bool PrepareApfsCountRepair(catalog::ContainerMountCoordinator& owner, std::uint64_t oid,
    ApfsCountRepairPlan& out, std::string& error,
    std::chrono::milliseconds lifetime = std::chrono::minutes(5));
bool ValidateCountRepairMutation(const MetadataStore& store, const MetadataStore::MutationRequest& request, std::string& error);
bool PlanCountRepairCheckpoint(const catalog::RandomAccessSource& source, const catalog::AppleCheckpointView& checkpoint,
    const NativeCountRepair& repair, const std::vector<std::uint64_t>& pins, AppleVolumeTransactionPlan& out, std::string& error);
bool VerifyPublishedCountRepair(const MetadataStore& store, const NativeCountRepair& repair, std::string& error);
// Read-only acknowledgement of one retained, fully cleaned original RCT2.
// Caller holds the original backup lease and immutable complete approved bytes.
// The owner must retain its exclusive ordinary-image lease; no writes/finalization.
bool VerifyCompletedApfsCountRepair(catalog::ContainerMountCoordinator& owner,
    TransactionManager& journal, const std::wstring& journal_path,
    const catalog::ApfsSnapshotScope& original_scope, std::uint64_t expected_count,
    std::span<const std::byte> approved_preimage, std::string_view approved_sha256, std::string& error);
catalog::ContainerCommitResult ApplyApfsCountRepair(catalog::ContainerMountCoordinator& owner,
    TransactionManager& journal, ApfsCountRepairPlan& plan, std::string_view confirmation_token);
std::optional<bool> ReplayApfsCountRepair(catalog::ContainerMountCoordinator& owner,
    TransactionManager& journal, std::uint64_t oid, std::string& error);
}
