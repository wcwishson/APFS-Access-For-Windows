#pragma once

#include "ApfsFusionReadSession.h"
#include "ApfsFusionWriteSession.h"
#include "TransactionManager.h"
#include "ApfsFusionVolumePlan.h"
#include <mutex>

namespace apfsaccess::rw
{
struct FusionAcceptedOverwriteInspection
{
    std::uint64_t accepted_sequence = 0, transaction_id = 0;
    std::uint64_t preimage_checkpoint_xid = 0, inode = 0, offset = 0;
    std::vector<std::byte> original_payload;
};
struct FusionImageWriteStatus
{
    std::uint64_t checkpoint_xid = 0;
    unsigned unavailable_members = 0;
    bool closed = true, cancelled = false, tier_ahead = false;
};

// Exclusive regular-image ownership for the bounded clean-cache Fusion profile.
// Open establishes identity/read authority, not allocator or mutation admission.
// Canonical two-device ownership is checked separately. FusionImageRuntime
// alone can execute an original-WAL-bound publication under its journal gate.
class ApfsFusionImageWriteSession final
{
public:
    static std::unique_ptr<ApfsFusionImageWriteSession> Open(
        const catalog::FusionBindRequest&, const FusionVolumeSelection&,
        std::string& error, unsigned* unavailable_members = nullptr);
    ~ApfsFusionImageWriteSession();
    ApfsFusionImageWriteSession(const ApfsFusionImageWriteSession&) = delete;
    ApfsFusionImageWriteSession& operator=(const ApfsFusionImageWriteSession&) = delete;
    bool ReadFile(std::uint64_t inode, std::uint64_t offset, std::size_t count,
        std::vector<std::byte>& out, std::string& error);
    // Complete earliest original boundary, one existing-file inline overwrite.
    // No replacement bytes or caller-provided accepted-record objects enter.
    // This is inspection only; output is explicitly not a publication permit.
    bool InspectAcceptedOverwrite(TransactionManager&, std::uint64_t accepted_sequence,
        FusionAcceptedOverwriteInspection& out, std::string& error);
    // Uses the canonical loader on original routed bytes; never creates a
    // single-store projection to evade tier-2 ownership validation.
    bool CheckAllocatorAdmission(std::string& error);
    bool PlanVolumeTransaction(const AppleVolumeTransactionRequest& request,
        FusionVolumeTransactionPlan& out, std::string& error);
    bool CheckAvailable(std::string& error);
    void Cancel() noexcept;
    void Close() noexcept;
    FusionImageWriteStatus Status() const;
    const std::array<std::byte, 32>& SourceBinding() const noexcept { return source_binding_; }
    const std::wstring& JournalIdentity() const noexcept { return journal_identity_; }
private:
    friend class FusionImageRuntime;
    friend class FusionJournalContinuation;
    friend struct FusionImageWriteSessionTestAccess;
    ApfsFusionImageWriteSession() = default;
    static bool Identify(const catalog::FusionBindRequest&, const FusionVolumeSelection&,
        std::uint32_t, std::array<std::byte,32>&, std::wstring&, std::string&);
    static std::unique_ptr<ApfsFusionImageWriteSession> OpenInternal(
        const catalog::FusionBindRequest&, const FusionVolumeSelection&, std::string&, unsigned*,
        const std::map<std::uint64_t,std::vector<std::byte>>*);
    bool RefreshHeld(std::uint64_t xid, std::string&,
        const std::map<std::uint64_t,std::vector<std::byte>>* preimage = nullptr);
    bool Available(std::string& error);
    struct DirectoryLeases;
    std::unique_ptr<DirectoryLeases> directories_;
    std::array<std::shared_ptr<BlockDevice>, 2> devices_;
    catalog::ApfsFusionStore* store_ = nullptr; // owned by reader_
    std::unique_ptr<ApfsFusionReadSession> reader_;
    std::unique_ptr<catalog::ApfsFusionWriteSession> writer_;
    std::shared_ptr<std::atomic<bool>> cancellation_ = std::make_shared<std::atomic<bool>>(false);
    std::shared_ptr<const std::atomic<bool>> external_cancellation_;
    std::array<std::byte, 32> source_binding_{};
    std::wstring journal_identity_;
    std::uint64_t volume_oid_ = 0;
    catalog::FusionBindRequest request_;
    FusionVolumeSelection selection_;
    FusionImageWriteStatus status_;
    mutable std::mutex gate_;
};
}
