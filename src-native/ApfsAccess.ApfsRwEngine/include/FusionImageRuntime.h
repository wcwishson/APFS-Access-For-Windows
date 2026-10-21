#pragma once
#include "ApfsFusionImageWriteSession.h"
#include "FusionPublicationJournal.h"

namespace apfsaccess::rw {
class FusionJournalContinuation;
class FusionContinuationAdmission;
struct FusionRuntimeVolumeInfo {
    FusionNamespaceInfo names;
    std::string label;
    std::uint64_t total_bytes=0, free_bytes=0, checkpoint_xid=0;
};
// Owns the original journal gate and the exact two held image leases. No draft
// plan, accepted-record object, member writer or watermark mutator escapes.
// Bounded profile: 4096-byte blocks, inline writes <=256 KiB, directories and
// canonical APFS names. One unresolved boundary at a time.
// The original WAL is a private intent stream: path commits the prepared hash,
// generation pins S, and Create uses offset/secondary_path for parent/name.
// Never dispatch this stream through generic MetadataStore replay.
class FusionImageRuntime final {
public:
    // One cumulative startup walk may prove up to 64 retained original links.
    // Callers may supply a tighter budget; Open never replaces or renews it.
    static std::shared_ptr<catalog::ApfsReadBudget> CreateStartupReadBudget();
    static std::unique_ptr<FusionImageRuntime> Open(const catalog::FusionBindRequest&,
        const FusionVolumeSelection&, const std::wstring& original_journal_path, std::string&);
    ~FusionImageRuntime();
    FusionImageRuntime(const FusionImageRuntime&) = delete;
    FusionImageRuntime& operator=(const FusionImageRuntime&) = delete;
    bool Overwrite(std::uint64_t inode, std::uint64_t offset, std::span<const std::byte>,
        std::string&, const AppleCheckpointStageHook& = {});
    bool Resize(std::uint64_t inode, std::uint64_t length, std::string&,
        const AppleCheckpointStageHook& = {});
    bool CreateRegularFile(std::uint64_t parent, std::string_view name,
        std::uint64_t& created_inode, std::string&, const AppleCheckpointStageHook& = {});
    bool MakeDirectory(std::uint64_t parent, std::string_view name,
        std::uint64_t& created_inode, std::string&, const AppleCheckpointStageHook& = {});
    bool Rename(std::uint64_t inode, std::uint64_t parent, std::string_view name, std::string&);
    // The expected destination is rederived from the canonical directory tree.
    bool RenameReplacing(std::uint64_t inode, std::uint64_t parent, std::string_view name,
        std::uint64_t expected_destination, std::string&, const AppleCheckpointStageHook& = {});
    bool RenameRetainingDestination(std::uint64_t inode, std::uint64_t parent, std::string_view name,
        std::uint64_t expected_destination, std::string&, const AppleCheckpointStageHook& = {});
    bool HasRetainedFile(std::uint64_t inode) const;
    bool ReleaseRetainedFile(std::uint64_t inode, std::string&, const AppleCheckpointStageHook& = {});
    bool UnlinkRetainingFile(std::uint64_t inode, std::string&, const AppleCheckpointStageHook& = {});
    bool Unlink(std::uint64_t inode, std::string&);
    bool SetTimes(std::uint64_t inode, const std::array<std::uint64_t,4>& filetimes, std::string&);
    bool GetVolumeInfo(FusionRuntimeVolumeInfo&, std::string&);
    bool GetNamespaceInfo(FusionNamespaceInfo&, std::string&);
    bool GetMetadata(std::uint64_t, FusionNodeInfo&, std::string&);
    bool LookupEntry(std::uint64_t, std::wstring_view, MetadataStore::DirectoryLink&, std::string&);
    bool Enumerate(std::uint64_t, std::vector<MetadataStore::DirectoryLink>&, std::string&);
    bool ListXattrs(std::uint64_t, std::vector<FusionXattrInfo>&, std::string&);
    bool ReadXattr(std::uint64_t, const std::string&, std::uint64_t, std::size_t, std::vector<std::byte>&, std::string&);
    bool CheckAvailable(std::string&);
    FusionReadStatus LastStatus() const;
    unsigned UnavailableMembers() const;
    bool Recover(std::string&, const AppleCheckpointStageHook& = {});
    bool ReadFile(std::uint64_t inode, std::uint64_t offset, std::size_t,
        std::vector<std::byte>&, std::string&);
    TransactionManager::DurabilityWatermarks Watermarks() const;
    void Cancel() noexcept;
private:
    friend class FusionJournalContinuation;
    enum class PlanVersion { Invalid, InlineV1, RangeV2, ReclaimV3, PrivateV4, NamesV5, UnlinkV6,
        NamesV7, PrivateV7, UnlinkV7, NamesV8, PrivateV8, UnlinkV8 };
    static PlanVersion OriginalPlanVersion(std::string_view);
    static PlanVersion NamespaceVersion(PlanVersion);
    static std::string_view PlanCommitment(PlanVersion);
    FusionImageRuntime();
    bool Prepare(WriteAheadLog::OperationKind, std::uint64_t, std::uint64_t, std::uint64_t, std::span<const std::byte>, std::string_view,
        std::unique_ptr<FusionPreparedPublication>&, std::string&, PlanVersion = PlanVersion::NamesV8);
    bool Mutate(WriteAheadLog::OperationKind, std::uint64_t, std::uint64_t, std::uint64_t,
        std::span<const std::byte>, std::string_view, std::string&, const AppleCheckpointStageHook&, std::uint64_t* = nullptr,
        PlanVersion = PlanVersion::NamesV8);
    bool MutateLocked(WriteAheadLog::OperationKind, std::uint64_t, std::uint64_t, std::uint64_t,
        std::span<const std::byte>, std::string_view, std::string&, const AppleCheckpointStageHook&, std::uint64_t*, PlanVersion);
    bool RecoverLocked(std::string&, const AppleCheckpointStageHook&);
    bool Publish(const FusionPreparedPublication&, std::uint64_t, std::string&,
        const AppleCheckpointStageHook&, PlanVersion);
    bool Original(std::uint64_t, TransactionManager::AcceptedTransaction&, std::string&);
    bool Match(const FusionPreparedPublication&, const TransactionManager::AcceptedTransaction&, std::string&,
        std::string* verified_digest = nullptr);
    bool BindRetainedChain(const catalog::FusionBindRequest&, const FusionVolumeSelection&,
        const std::array<std::byte,32>& source, const std::wstring& journal_identity,
        const TransactionManager::RetainedAcceptedHistory&, std::string&, const FusionContinuationAdmission* = nullptr);
    bool PrepareMetadata(WriteAheadLog::OperationKind, std::uint64_t, std::uint64_t, std::uint64_t, std::string_view,
        AppleVolumeTransactionRequest&, std::string&, PlanVersion);
    bool AdoptPrivateOwnership(const TransactionManager::RetainedAcceptedHistory&, std::uint64_t, std::string&,
        const FusionContinuationAdmission* = nullptr);
    void TrackPrivateBoundary(const TransactionManager::AcceptedTransaction&);
    bool ValidatePrivateOwnership(std::string&);
    bool SealPlan(WriteAheadLog::OperationKind, std::uint64_t, std::uint64_t, std::uint64_t,
        std::span<const std::byte>, std::string_view, const AppleVolumeTransactionRequest&,
        std::unique_ptr<FusionPreparedPublication>&, std::string&, PlanVersion);
    bool RefreshVolumeInfo(std::string&);
    bool ReadReady(std::string&);
    FusionRuntimeVolumeInfo volume_info_;
    std::unique_ptr<ApfsFusionImageWriteSession> owner_;
    TransactionManager transactions_{L"strict"};
    std::unique_ptr<FusionPublicationJournal> witness_;
    std::unique_ptr<FusionPreparedPublication> recovery_;
    std::wstring journal_path_;
    std::map<std::uint64_t, std::uint64_t> retained_files_;
    bool startup_recovery_ = false;
    mutable std::mutex gate_;
};
}
