#pragma once

#include "BtreeMutationCodec.h"
#include "BlockDevice.h"
#include "CheckpointDelta.h"
#include "ExtentAllocator.h"
#include "MutationCompactor.h"

#include <atomic>
#include <cstdint>
#include <cstddef>
#include <array>
#include <deque>
#include <filesystem>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace apfsaccess::rw
{
class MetadataStore
{
public:
    enum class MutationStatus
    {
        Applied,
        NotReady,
        InvalidRequest,
        AllocationFailed,
        UnsupportedOperation,
    };

    enum class CommitStatus
    {
        Committed,
        NothingToCommit,
        NotReady,
        NotWritable,
        AllocationFailed,
        InvariantFailed,
        PersistFailed,
        FlushFailed,
    };

    enum class MutationOperation
    {
        CreateFile,
        CreateDirectory,
        Write,
        SetFileSize,
        Rename,
        Delete,
        SetBasicInfo,
    };

    enum class NativeWriteCommitModel
    {
        ScaffoldCheckpoint,
        CanonicalApfsCheckpoint,
    };

    enum class NativeWriteValidationState
    {
        Scaffold,
        CanonicalImageValidated,
        HardwarePilotValidated,
        CrossOsValidated,
        Stable,
    };

    struct MutationRequest
    {
        MutationOperation operation = MutationOperation::Write;
        std::wstring path;
        std::wstring secondary_path;
        std::uint64_t offset = 0;
        std::uint64_t length = 0;
        bool replace_if_exists = false;
        std::uint64_t timestamp_utc = 0;
        // When populated by accepted-WAL replay, these fields bind the
        // mutation to the object incarnation recorded before acceptance.
        // Ordinary foreground requests leave them zero and retain the
        // existing path-based staging behavior.
        std::uint64_t object_id = 0;
        std::uint64_t generation = 0;
    };

    struct ObjectMapUpdate
    {
        std::uint64_t object_id = 0;
        std::uint64_t physical_address = 0;
        std::uint64_t logical_size = 0;
        std::uint64_t xid = 0;
    };

    struct InodeRecord
    {
        std::uint64_t object_id = 0;
        std::uint64_t parent_object_id = 0;
        std::wstring name;
        std::wstring full_path;
        bool is_directory = false;
        std::uint64_t logical_size = 0;
        std::uint64_t data_physical_address = 0;
        std::uint64_t xid = 0;
        std::uint64_t timestamp_utc = 0;
    };

    struct CommittedInodeChange
    {
        std::uint64_t object_id = 0;
        std::wstring previous_path;
        std::optional<InodeRecord> current;
    };

    struct PayloadIdentity
    {
        std::uint64_t object_id = 0;
        std::uint64_t generation = 0;
    };

    struct DirectoryLink
    {
        std::uint64_t parent_object_id = 0;
        std::wstring entry_name;
        std::uint64_t child_object_id = 0;
        std::uint64_t xid = 0;
    };

    using SpacemanAllocation = ExtentAllocator::Extent;

    struct FileExtent
    {
        std::uint64_t logical_offset = 0;
        std::uint64_t physical_address = 0;
        std::uint64_t bytes = 0;
    };

    // A committed read plan owns the metadata needed for a device read. The
    // common single-extent shape stays inline; fragmented files retain a
    // lifetime-stable immutable extent snapshot so the caller can release the
    // metadata lock before I/O without copying on every read.
    struct CommittedFileReadPlan
    {
        std::uint64_t object_id = 0;
        std::uint64_t logical_size = 0;
        std::uint64_t data_physical_address = 0;
        FileExtent single_extent{};
        bool has_single_extent = false;
        std::shared_ptr<const std::vector<FileExtent>> extents_snapshot;
    };

    struct FileMutationExtents
    {
        std::vector<FileExtent> file_extents;
        std::vector<SpacemanAllocation> allocations;
    };

    struct VolumeContext
    {
        std::wstring device_path;
        std::wstring volume_name;
        bool allow_raw_physical_write = false;
        bool integrity_check_on_mount = true;
        std::wstring crash_replay_mode = L"FailClosed";
        bool allow_legacy_scaffold_for_fixtures = true;
        bool disallow_scaffold_commit_on_non_fixture = true;
        bool reject_scaffold_replay_blob_on_non_fixture = true;
        bool require_canonical_replay_candidate_on_non_fixture = true;
        std::uint64_t device_offset_bytes = 0;
    };

    explicit MetadataStore(VolumeContext context);

    [[nodiscard]] const VolumeContext& Context() const noexcept;
    [[nodiscard]] const BlockDevice& Device() const noexcept;
    [[nodiscard]] bool LoadContainerState();
    [[nodiscard]] bool LoadVolumeState();
    [[nodiscard]] bool LoadCanonicalState();
    [[nodiscard]] bool LoadContainerSuperblocks();
    [[nodiscard]] bool LoadObjectMap();
    [[nodiscard]] bool LoadSpacemanState();
    [[nodiscard]] bool IsContainerLoaded() const noexcept;
    [[nodiscard]] std::optional<std::uint32_t> BlockSizeBytes() const noexcept;
    [[nodiscard]] std::optional<std::uint64_t> TotalBlocks() const noexcept;
    [[nodiscard]] std::optional<std::uint64_t> TotalSizeBytes() const noexcept;
    [[nodiscard]] std::optional<std::uint64_t> FreeSizeBytes() const noexcept;
    [[nodiscard]] std::optional<std::uint64_t> CheckpointXid() const noexcept;
    [[nodiscard]] bool PrepareNativeWritePath();
    [[nodiscard]] bool IsNativeWriteReady() const noexcept;
    [[nodiscard]] bool IsCommitPathReady() const noexcept;
    [[nodiscard]] bool IsRecoveryRequired() const noexcept;
    [[nodiscard]] std::wstring RecoveryReason() const;
    [[nodiscard]] std::wstring LastIntegrityFailureReason() const;
    [[nodiscard]] std::optional<std::uint64_t> LastIntegrityFailureObjectId() const noexcept;
    [[nodiscard]] std::wstring LastMutationFailureReason() const;
    [[nodiscard]] MutationStatus StageMutation(
        const MutationRequest& request,
        PayloadIdentity* out_staged_payload_identity = nullptr);
    [[nodiscard]] MutationStatus ApplyMutation(
        const MutationRequest& request,
        PayloadIdentity* out_staged_payload_identity = nullptr);
    [[nodiscard]] CommitStatus CommitTransaction();
    [[nodiscard]] CommitStatus CommitCanonicalTransaction();
    [[nodiscard]] CommitStatus CommitPendingMutations();
    [[nodiscard]] bool ReplayOrRecover();
    [[nodiscard]] bool ReplayCanonicalCheckpoint();
    [[nodiscard]] bool VerifyIntegrity() const;
    [[nodiscard]] bool IsCanonicalCommitReady() const noexcept;
    [[nodiscard]] bool IsProductionCanonicalPathActive() const noexcept;
    [[nodiscard]] std::wstring LastCanonicalGateFailure() const;
    [[nodiscard]] std::string LastCommitStage() const;
    [[nodiscard]] std::wstring LastCommitFailureReason() const;
    [[nodiscard]] std::wstring LastCommitFailureDetail() const;
    [[nodiscard]] std::optional<std::uint64_t> LastCommitFailureObjectId() const noexcept;
    [[nodiscard]] std::string LastReplayStage() const;
    [[nodiscard]] std::string LastCommitBlobMagic() const;
    [[nodiscard]] std::string PerformanceJson() const;
    [[nodiscard]] bool LastReplayCheckpointCandidatePresent() const noexcept;
    [[nodiscard]] bool LastReplayCheckpointPendingWindow() const noexcept;
    [[nodiscard]] NativeWriteCommitModel ActiveCommitModel() const noexcept;
    [[nodiscard]] NativeWriteValidationState ValidationState() const noexcept;
    [[nodiscard]] bool IsFixtureLegacyFallbackActive() const noexcept;
    [[nodiscard]] bool IsFixtureCompatibilityPathActive() const noexcept;
    [[nodiscard]] bool UsesScaffoldCommitBlob() const noexcept;
    [[nodiscard]] std::size_t PendingMutationCount() const noexcept;
    [[nodiscard]] bool PendingMutationsAreContentWritesOnly() const noexcept;
    [[nodiscard]] bool PendingMutationsAreDeletesOnly() const noexcept;
    [[nodiscard]] bool PendingMutationsCanSkipPreflightInodeGraphValidation() const noexcept;
    [[nodiscard]] bool PendingMutationsCanSkipPreflightProjectedBtreeValidation() const noexcept;
    [[nodiscard]] bool PendingMutationsCanContinueDeferredClose() const;
    [[nodiscard]] std::size_t PendingObjectMapUpdateCount() const noexcept;
    [[nodiscard]] std::size_t PendingAllocationCount() const noexcept;
    [[nodiscard]] std::size_t PendingSpacemanAllocationIndexCount() const noexcept;
    [[nodiscard]] std::size_t PendingDeallocationCount() const noexcept;
    [[nodiscard]] std::size_t PendingBtreeRecordCount() const noexcept;
    [[nodiscard]] std::uint64_t PendingWriteCoalesceScanCount() const noexcept;
    [[nodiscard]] std::uint64_t PendingBasicInfoCoalescePathFallbackCount() const noexcept;
    [[nodiscard]] std::uint64_t PendingSetFileSizeCoalescePathFallbackCount() const noexcept;
    [[nodiscard]] std::uint64_t DirectoryRenameDescendantPathLookupCount() const noexcept;
    [[nodiscard]] std::uint64_t DirectoryRenameDescendantDirectoryLinkUpdateCount() const noexcept;
    [[nodiscard]] std::uint64_t PendingPayloadRenamePathScanCount() const noexcept;
    [[nodiscard]] std::uint64_t PendingPayloadDeletePathScanCount() const noexcept;
    [[nodiscard]] std::uint64_t PendingPayloadSummaryPathScanCount() const noexcept;
    [[nodiscard]] std::uint64_t PendingObjectMapUpdateScanCount() const noexcept;
    [[nodiscard]] std::uint64_t PendingBtreeFileMetadataScanCount() const noexcept;
    [[nodiscard]] std::uint64_t PendingCloseDelaySummaryRebuildCount() const noexcept;
    [[nodiscard]] std::uint64_t WorkingFreeExtentSanitizeCount() const noexcept;
    [[nodiscard]] std::uint64_t WorkingFreeExtentSanitizeSkipCount() const noexcept;
    [[nodiscard]] std::uint64_t FreeExtentSanitizeCount() const noexcept;
    [[nodiscard]] std::uint64_t FreeExtentSanitizeSkipCount() const noexcept;
    [[nodiscard]] std::uint64_t CommitRestoreDedupeLinearScanCount() const noexcept;
    [[nodiscard]] std::uint64_t CommitBtreeFullSnapshotCount() const noexcept;
    [[nodiscard]] std::uint64_t CommittedSpacemanFullSnapshotCount() const noexcept;
    [[nodiscard]] std::size_t PendingPayloadObjectSummaryCount() const noexcept;
    [[nodiscard]] std::uint64_t PendingPayloadByteEstimate() const;
    [[nodiscard]] std::uint64_t PendingPayloadDirtyByteEstimate() const noexcept;
    [[nodiscard]] std::uint64_t PendingPayloadRangeLocalMergeCount() const noexcept;
    [[nodiscard]] std::uint64_t PendingPayloadRangeFullMergeCount() const noexcept;
    [[nodiscard]] std::optional<std::uint64_t> LastCommittedXid() const noexcept;
    [[nodiscard]] std::size_t CommittedObjectCount() const noexcept;
    [[nodiscard]] std::size_t CommittedAllocationCount() const noexcept;
    [[nodiscard]] std::size_t CommittedFreeExtentCount() const noexcept;
    [[nodiscard]] std::size_t CommittedBtreeRecordCount() const noexcept;
    [[nodiscard]] bool PendingMutationsCanDelayClose() const;
    [[nodiscard]] std::optional<ObjectMapUpdate> LookupCommittedObject(std::uint64_t object_id) const;
    [[nodiscard]] std::size_t CommittedInodeCount() const noexcept;
    [[nodiscard]] std::optional<InodeRecord> LookupCommittedInodeByPath(const std::wstring& path) const;
    [[nodiscard]] std::optional<InodeRecord> LookupCommittedInodeByObjectId(std::uint64_t object_id) const;
    [[nodiscard]] std::optional<std::vector<InodeRecord>> SnapshotCommittedDirectoryChildInodes(std::uint64_t parent_object_id) const;
    [[nodiscard]] std::vector<InodeRecord> SnapshotCommittedInodes() const;
    [[nodiscard]] std::vector<CommittedInodeChange> SnapshotLastCommittedInodeChanges() const;
    [[nodiscard]] std::vector<CommittedInodeChange> TakeLastCommittedInodeChanges();
    [[nodiscard]] bool SetCommittedReadExtents(std::uint64_t object_id, std::vector<FileExtent> extents);
    [[nodiscard]] bool DebugMergeNativeProjectionReadExtents(std::uint64_t object_id, std::vector<FileExtent> extents);
    [[nodiscard]] std::size_t DebugWorkingDirectoryChildCount(std::uint64_t parent_object_id) const;
    [[nodiscard]] std::size_t DebugWorkingDirectoryDescendantCount(std::uint64_t parent_object_id) const;
    [[nodiscard]] std::uint64_t DebugWorkingDirectoryChildLinearScanCount() const noexcept;
    [[nodiscard]] std::size_t DebugWorkingInodeCount() const noexcept;
    [[nodiscard]] std::optional<InodeRecord> DebugLookupWorkingInodeByPath(const std::wstring& path) const;
    [[nodiscard]] CheckpointDelta DebugBuildPendingCheckpointDelta() const;
    [[nodiscard]] std::optional<PayloadIdentity> LookupWorkingPayloadIdentityByPath(const std::wstring& path) const;
    // The FsHost already owns the normalized, case-folded working path key for
    // open nodes. Avoid rebuilding it during dirty-read identity probes.
    [[nodiscard]] std::optional<PayloadIdentity> LookupWorkingPayloadIdentityByCanonicalPathKey(
        const std::wstring& canonical_path_key) const;
    [[nodiscard]] std::size_t DebugWorkingFreeExtentCount() const noexcept;
    [[nodiscard]] std::uint64_t DebugWorkingFreeExtentTotalBytes() const noexcept;
    [[nodiscard]] bool ReadCommittedFileRange(
        const std::wstring& path,
        std::uint64_t offset,
        std::size_t bytes_to_read,
        std::vector<std::byte>& out_payload) const;
    [[nodiscard]] bool ReadCommittedFileRangeInto(
        const std::wstring& path,
        std::uint64_t offset,
        std::size_t bytes_to_read,
        std::byte* destination,
        std::size_t destination_size,
        std::size_t& out_bytes_read) const;
    // The FsHost already holds a normalized, case-folded path key for open
    // nodes. Avoid rebuilding that key on every dirty small-file read.
    [[nodiscard]] bool ReadCommittedFileRangeIntoCanonicalPathKey(
        const std::wstring& canonical_path_key,
        const std::wstring& trace_path,
        std::uint64_t offset,
        std::size_t bytes_to_read,
        std::byte* destination,
        std::size_t destination_size,
        std::size_t& out_bytes_read) const;
    [[nodiscard]] std::optional<CommittedFileReadPlan> SnapshotCommittedFileReadPlan(
        const std::wstring& canonical_path_key) const;
    [[nodiscard]] bool ReadCommittedFileRangeFromPlan(
        const CommittedFileReadPlan& plan,
        const std::wstring& trace_path,
        std::uint64_t offset,
        std::size_t bytes_to_read,
        std::byte* destination,
        std::size_t destination_size,
        std::size_t& out_bytes_read) const;
    [[nodiscard]] bool WritePreparedFileRange(
        const std::wstring& path,
        std::uint64_t offset,
        std::span<const std::byte> payload);
    void SetCommitStageHook(
        std::function<bool(std::string_view stage)> hook,
        bool require_strict_verification = true);
    void SetFilePayloadProvider(
        std::function<std::optional<std::vector<std::byte>>(const std::wstring& path, std::uint64_t logical_size)> provider);
    void SetFilePayloadRangeProvider(
        std::function<bool(
            const std::wstring& path,
            PayloadIdentity identity,
            std::uint64_t offset,
            std::span<std::byte> destination)> provider);

    // Allocation/free-space primitives used by staged native mutations.
    [[nodiscard]] std::optional<std::uint64_t> AllocateExtent(std::uint64_t bytes);
    [[nodiscard]] bool FreeExtent(std::uint64_t physical_address, std::uint64_t bytes);
    [[nodiscard]] bool FreeExtent(
        std::uint64_t physical_address,
        std::uint64_t bytes,
        ExtentAllocator::AddFreeExtentUndo* undo);

private:
    struct PerfCounter
    {
        std::atomic<std::uint64_t> count{0};
        std::atomic<std::uint64_t> total_us{0};
        std::atomic<std::uint64_t> max_us{0};
        std::atomic<std::uint64_t> last_us{0};

        void Observe(std::uint64_t elapsed_us) noexcept;
    };
    struct PreparedPayloadRange
    {
        std::uint64_t offset = 0;
        std::uint64_t bytes = 0;
    };
    struct PayloadRangeByteDelta
    {
        std::uint64_t added_bytes = 0;
        std::uint64_t removed_bytes = 0;
    };
    struct PendingMutationPathKeyCacheEntry
    {
        std::wstring path;
        std::wstring secondary_path;
        std::wstring path_key;
        std::wstring secondary_path_key;
        bool path_key_valid = false;
        bool secondary_path_key_valid = false;
    };
    struct CheckpointWriteBatch
    {
        std::deque<std::vector<std::byte>> storage;
        std::vector<BlockDevice::WriteSpan> writes;
    };
    struct PreparedCheckpointSerializationBuffer
    {
        std::vector<std::byte>* bytes = nullptr;
        std::size_t original_capacity = 0;
        bool reusable = false;
    };
    struct ScopedPerfTimer;

    [[nodiscard]] static std::uint32_t ReadLe32(const std::vector<std::byte>& buffer, std::size_t offset);
    [[nodiscard]] static std::uint64_t ReadLe64(const std::vector<std::byte>& buffer, std::size_t offset);
    [[nodiscard]] static std::uint64_t StableObjectIdFromPath(const std::wstring& path);
    [[nodiscard]] static std::wstring NormalizePath(const std::wstring& path);
    [[nodiscard]] static std::wstring CanonicalPathKey(const std::wstring& normalized_path);
    [[nodiscard]] static std::wstring CanonicalPathKeyFromPath(const std::wstring& path);
    [[nodiscard]] static std::wstring CanonicalPathKeyFromNormalizedPath(const std::wstring& normalized_path);
    [[nodiscard]] static bool IsRootPath(const std::wstring& normalized_path);
    [[nodiscard]] static bool IsDescendantPath(const std::wstring& candidate_path, const std::wstring& parent_path);
    [[nodiscard]] static bool IsDescendantPathKey(const std::wstring& candidate_key, const std::wstring& parent_key);
    [[nodiscard]] static std::wstring ParentPath(const std::wstring& normalized_path);
    [[nodiscard]] static std::wstring LeafName(const std::wstring& normalized_path);
    [[nodiscard]] static bool IsLikelyRawDevicePath(const std::wstring& path);
    [[nodiscard]] static bool IsFixtureImagePath(const std::wstring& path);
    [[nodiscard]] std::uint64_t RootDirectoryObjectId() const;
    [[nodiscard]] bool IsLegacyFixtureFallbackAllowedForCurrentContext() const noexcept;
    [[nodiscard]] bool RequiresCanonicalNonFixtureCommitPath() const noexcept;
    [[nodiscard]] bool CanLoadNativeCheckpointXid(std::uint64_t persisted_xid) const noexcept;
    [[nodiscard]] std::optional<std::uint64_t> ResolveObjectBlockIndex(std::uint64_t object_or_block) const;
    [[nodiscard]] bool ReadMetadataBlock(std::uint64_t block_index, std::vector<std::byte>& out_block) const;
    [[nodiscard]] bool WriteMetadataBlock(std::uint64_t block_index, const std::vector<std::byte>& block);
    [[nodiscard]] bool WriteChunkedCheckpointBlocks(
        const std::vector<std::uint64_t>& block_indices,
        std::uint64_t target_xid,
        const std::vector<std::byte>& data);
    [[nodiscard]] bool WriteSelectedChunkedCheckpointBlocks(
        const std::vector<std::uint64_t>& selected_blocks,
        std::vector<std::byte> data);
    [[nodiscard]] bool WriteBorrowedSelectedChunkedCheckpointBlocks(
        const std::vector<std::uint64_t>& selected_blocks,
        const std::vector<std::byte>& data);
    [[nodiscard]] PreparedCheckpointSerializationBuffer PrepareCheckpointSerializationBuffer(
        std::vector<std::byte>& reusable_buffer,
        std::vector<std::byte>& local_buffer,
        std::size_t initial_size,
        std::size_t reserve_capacity);
    void ObserveCheckpointSerializationBuffer(const PreparedCheckpointSerializationBuffer& buffer) noexcept;
    [[nodiscard]] bool WritePreparedCheckpointBlocks(
        const std::vector<std::uint64_t>& selected_blocks,
        PreparedCheckpointSerializationBuffer buffer);
    [[nodiscard]] bool AppendSelectedChunkedCheckpointWriteSpans(
        const std::vector<std::uint64_t>& selected_blocks,
        const std::vector<std::byte>& data,
        const std::vector<std::byte>* shared_full_run_storage,
        std::deque<std::vector<std::byte>>& block_batch_storage,
        std::vector<BlockDevice::WriteSpan>& block_batch_writes) const;
    [[nodiscard]] bool PadCheckpointWriteDataToBlockBoundary(std::vector<std::byte>& data) const;
    [[nodiscard]] bool FlushActiveCheckpointWriteBatch();
    [[nodiscard]] std::vector<std::byte> ReadChunkedCheckpointBytes(
        const std::vector<std::uint64_t>& block_indices,
        std::uint64_t target_xid,
        const std::array<char, 12>& magic,
        std::uint32_t expected_payload_bytes) const;
    [[nodiscard]] std::vector<std::byte> ReadOrderedCheckpointWindowBytes(
        const std::vector<std::uint64_t>& ordered_blocks,
        std::size_t required_blocks) const;
    [[nodiscard]] bool IsReservedMetadataBlock(std::uint64_t block_index) const;
    [[nodiscard]] std::optional<std::uint64_t> ResolveNativeCheckpointBandStartBlock() const;
    [[nodiscard]] bool IsNativeCheckpointBandBlock(std::uint64_t block_index) const;
    [[nodiscard]] bool AreNativeCheckpointBlocksWritable(const std::vector<std::uint64_t>& block_indices) const;
    [[nodiscard]] std::vector<std::uint64_t> SelectWritableChunkedCheckpointBlocks(
        const std::vector<std::uint64_t>& block_indices,
        std::uint64_t target_xid,
        std::size_t required_blocks) const;
    [[nodiscard]] std::optional<std::uint64_t> FindCheckpointCompanionBlock(
        std::uint64_t primary_block,
        const std::vector<std::uint64_t>& disallowed_blocks) const;
    [[nodiscard]] std::vector<std::uint64_t> ResolveObjectMapCheckpointBlockIndices() const;
    [[nodiscard]] std::vector<std::uint64_t> ResolveSpacemanCheckpointBlockIndices() const;
    [[nodiscard]] std::vector<std::uint64_t> ResolveInodeCheckpointBlockIndices() const;
    [[nodiscard]] std::vector<std::uint64_t> ResolveBtreeCheckpointBlockIndices() const;
    [[nodiscard]] std::vector<std::uint64_t> ResolveReplayCheckpointBlockIndices() const;
    [[nodiscard]] bool LoadObjectMapCheckpointBlock(std::uint64_t block_index, const std::vector<std::byte>& block);
    [[nodiscard]] bool LoadSpacemanCheckpointBlock(std::uint64_t block_index, const std::vector<std::byte>& block);
    [[nodiscard]] bool LoadSpacemanChunkInfoState(std::uint64_t spaceman_block_index, const std::vector<std::byte>& block);
    [[nodiscard]] bool RefreshNativeReadExtentProjection();
    [[nodiscard]] std::optional<std::uint64_t> ResolveInodeCheckpointBlockIndex() const;
    [[nodiscard]] bool LoadInodeCheckpointBlock(std::uint64_t block_index, const std::vector<std::byte>& block);
    [[nodiscard]] bool LoadBtreeCheckpointBlock(std::uint64_t block_index, const std::vector<std::byte>& block);
    [[nodiscard]] bool LoadReplayCheckpointBlock(
        std::uint64_t block_index,
        const std::vector<std::byte>& block,
        std::uint64_t& out_target_xid,
        std::uint64_t& out_source_xid,
        std::uint64_t& out_commit_blob_address,
        std::uint64_t& out_commit_blob_bytes) const;
    [[nodiscard]] bool RebuildInodeStateFromBtreeRecords(
        const std::vector<BtreeRecord>& records,
        std::unordered_map<std::uint64_t, InodeRecord>& out_inodes,
        std::unordered_map<std::wstring, std::uint64_t>& out_path_index,
        std::vector<DirectoryLink>& out_directory_links) const;
    [[nodiscard]] bool RebuildReadExtentsFromBtreeRecords(
        const std::vector<BtreeRecord>& records,
        const std::unordered_map<std::uint64_t, InodeRecord>& inode_table,
        std::unordered_map<std::uint64_t, std::vector<FileExtent>>& out_read_extents) const;
    [[nodiscard]] bool ReadBlockByIndexDirect(std::uint64_t block_index, std::vector<std::byte>& out_block) const;
    [[nodiscard]] bool WriteBlockByIndexDirect(std::uint64_t block_index, std::vector<std::byte> block);
    [[nodiscard]] bool WriteContiguousBlocksDirect(
        std::uint64_t first_block_index,
        const std::vector<std::byte>& blocks);
    [[nodiscard]] bool EnsureRootState();
    [[nodiscard]] bool ValidateInodeGraphState(
        const std::unordered_map<std::uint64_t, InodeRecord>& inode_table,
        const std::unordered_map<std::wstring, std::uint64_t>& path_index,
        const std::vector<DirectoryLink>& directory_links,
        bool require_root_object
    ) const;
    void RefreshObjectIdAllocator();
    void SyncWorkingStateFromCommitted();
    [[nodiscard]] MutationStatus RejectMutation(std::wstring reason);
    [[nodiscard]] std::uint64_t ResolveUniqueObjectId(const std::wstring& normalized_path);
    [[nodiscard]] bool IsDirectoryInWorkingState(const std::wstring& normalized_path) const;
    [[nodiscard]] std::optional<InodeRecord> LookupWorkingInode(const std::wstring& normalized_path) const;
    [[nodiscard]] std::optional<InodeRecord> LookupWorkingInodeByCanonicalPathKey(const std::wstring& canonical_path_key) const;
    [[nodiscard]] const InodeRecord* LookupWorkingInodeByCanonicalPathKeyView(const std::wstring& canonical_path_key) const;
    [[nodiscard]] const InodeRecord* LookupCommittedInodeByPathView(const std::wstring& path) const;
    [[nodiscard]] const InodeRecord* LookupCommittedInodeByCanonicalPathKeyView(const std::wstring& canonical_path_key) const;
    struct DirectoryLinkIndexKey
    {
        std::uint64_t parent_object_id = 0;
        std::wstring entry_name;

        friend bool operator==(const DirectoryLinkIndexKey& left, const DirectoryLinkIndexKey& right) noexcept
        {
            return left.parent_object_id == right.parent_object_id &&
                   left.entry_name == right.entry_name;
        }
    };
    struct DirectoryLinkIndexKeyHash
    {
        std::size_t operator()(const DirectoryLinkIndexKey& key) const noexcept
        {
            auto seed = std::hash<std::uint64_t>{}(key.parent_object_id);
            seed ^= std::hash<std::wstring>{}(key.entry_name) + 0x9e3779b97f4a7c15ull + (seed << 6) + (seed >> 2);
            return seed;
        }
    };
    [[nodiscard]] DirectoryLinkIndexKey BuildWorkingDirectoryLinkIndexKey(std::uint64_t parent_object_id, const std::wstring& entry_name) const;
    void RebuildWorkingDirectoryIndexes();
    [[nodiscard]] bool HasWorkingChildren(std::uint64_t parent_object_id) const;
    void AddWorkingDirectoryChild(std::uint64_t parent_object_id, std::uint64_t child_object_id);
    void RemoveWorkingDirectoryChild(std::uint64_t parent_object_id, std::uint64_t child_object_id);
    [[nodiscard]] std::vector<std::uint64_t> SnapshotWorkingDirectoryChildObjectIds(std::uint64_t parent_object_id) const;
    [[nodiscard]] std::vector<std::uint64_t> SnapshotWorkingDirectoryDescendantObjectIds(std::uint64_t parent_object_id) const;
    void UpsertWorkingDirectoryLink(std::uint64_t parent_object_id, const std::wstring& entry_name, std::uint64_t child_object_id, std::uint64_t xid);
    void RemoveWorkingDirectoryLink(std::uint64_t parent_object_id, const std::wstring& entry_name);
    void ClearCommittedDirectoryLinkIndexes();
    void RebuildCommittedDirectoryLinkIndex();
    void AddCommittedDirectoryChild(std::uint64_t parent_object_id, std::uint64_t child_object_id);
    void RemoveCommittedDirectoryChild(std::uint64_t parent_object_id, std::uint64_t child_object_id);
    [[nodiscard]] bool RebuildCommittedBtreeIndex();
    [[nodiscard]] bool StageObjectMapUpdate(std::uint64_t object_id, std::uint64_t physical_address, std::uint64_t logical_size);
    void RebuildPendingObjectMapUpdateIndex();
    [[nodiscard]] bool StageSpacemanAllocation(std::uint64_t physical_address, std::uint64_t bytes);
    void RebuildPendingSpacemanAllocationIndex();
    void ErasePendingSpacemanAllocationAt(std::size_t index);
    void ResizePendingSpacemanAllocationAt(std::size_t index, std::uint64_t bytes);
    [[nodiscard]] std::optional<std::size_t> FindPendingSpacemanAllocationIndex(std::uint64_t physical_address) const;
    [[nodiscard]] bool PendingSpacemanAllocationsOverlap(std::uint64_t physical_address, std::uint64_t bytes) const;
    [[nodiscard]] bool StageSpacemanDeallocation(std::uint64_t physical_address, std::uint64_t bytes);
    [[nodiscard]] std::optional<std::vector<FileExtent>> AllocateFileExtents(std::uint64_t logical_size);
    [[nodiscard]] std::uint64_t StreamingGrowthReservationBytes(
        std::uint64_t current_aligned_bytes,
        std::uint64_t required_aligned_bytes) const noexcept;
    [[nodiscard]] std::optional<FileMutationExtents> CommittedFileExtentsForMutation(const InodeRecord& inode) const;
    [[nodiscard]] bool PendingReadExtentsCoverLogicalRange(
        std::uint64_t object_id,
        std::uint64_t offset,
        std::uint64_t length) const;
    [[nodiscard]] bool StageCommittedFileExtentDeallocations(const FileMutationExtents& extents);
    [[nodiscard]] bool HasPendingSpacemanAllocation(std::uint64_t physical_address, std::uint64_t bytes) const;
    [[nodiscard]] bool ReleasePendingSpacemanAllocation(std::uint64_t physical_address, std::uint64_t bytes);
    [[nodiscard]] bool WritePreparedFileRangeFromExtents(
        std::uint64_t object_id,
        const std::vector<FileExtent>& extents,
        std::uint64_t offset,
        std::span<const std::byte> payload);
    PayloadRangeByteDelta RememberPayloadRange(
        std::unordered_map<std::uint64_t, std::vector<PreparedPayloadRange>>& ranges_by_object,
        std::uint64_t object_id,
        std::uint64_t offset,
        std::uint64_t bytes);
    void RememberPreparedPayloadRange(std::uint64_t object_id, std::uint64_t offset, std::uint64_t bytes);
    void ClearPreparedPayloadRanges(std::uint64_t object_id);
    void RememberPendingWrittenRange(std::uint64_t object_id, std::uint64_t offset, std::uint64_t bytes);
    void ClearPendingWrittenRanges(std::uint64_t object_id);
    [[nodiscard]] static std::uint64_t SumPayloadRangeBytes(
        const std::vector<PreparedPayloadRange>& ranges) noexcept;
    void ReplacePendingWrittenRanges(
        std::uint64_t object_id,
        std::optional<std::vector<PreparedPayloadRange>> ranges);
    void RebuildPendingWriteObjectIds();
    void ClearPendingPayloadObjectSummary();
    void ClearPendingPayloadPathKeys();
    void InsertPendingPayloadPathKey(const std::wstring& path_key, std::uint64_t object_id);
    void InsertPendingPayloadPathKey(std::wstring&& path_key, std::uint64_t object_id);
    void ErasePendingPayloadPathKey(const std::wstring& path_key);
    [[nodiscard]] std::optional<std::uint64_t> LookupPendingPayloadPathObjectId(const std::wstring& path_key) const;
    void ClearPendingPayloadSummary();
    void RefreshPendingPayloadSummaryForObject(std::uint64_t object_id);
    void RemovePendingPayloadSummaryForObject(std::uint64_t object_id);
    void TrackPendingPayloadSummaryObject(std::uint64_t object_id);
    void CompactPendingPayloadSummaryObjectOrder();
    void InvalidatePendingPayloadPathKeyOrder();
    void EnsurePendingPayloadPathKeyOrder();
    void RebuildPendingPayloadSummary();
    [[nodiscard]] std::optional<std::uint64_t> AllocateExtentFromSanitizedWorkingFreeExtents(std::uint64_t bytes);
    [[nodiscard]] std::optional<std::uint64_t> AllocateExtentFromSanitizedWorkingFreeExtents(
        std::uint64_t bytes,
        ExtentAllocator::ContiguousAllocationUndo* undo);
    [[nodiscard]] const std::vector<FileExtent>* LookupSortedReadExtents(std::uint64_t object_id) const;
    void TrackPendingPayloadSummaryMutation(const MutationRequest& request);
    void TrackPendingPayloadSummaryMutation(
        const MutationRequest& request,
        const std::wstring& normalized_path,
        const std::wstring& normalized_secondary_path,
        std::optional<std::uint64_t> known_object_id = std::nullopt,
        const std::wstring* canonical_path_key = nullptr,
        const std::wstring* canonical_secondary_path_key = nullptr);
    void ClearPendingCloseDelaySummary();
    void UntrackPendingCloseDelaySummaryWriteMutation(const MutationRequest& request);
    void TrackPendingCloseDelaySummaryMutation(const MutationRequest& request);
    void TrackPendingCloseDelaySummaryMutation(
        const MutationRequest& request,
        const std::wstring& normalized_path,
        std::optional<std::uint64_t> known_object_id = std::nullopt,
        const std::wstring* canonical_path_key = nullptr);
    void RebuildPendingCloseDelaySummary();
    void ObserveCheckpointDeltaShadow(const CheckpointDelta& delta);
    [[nodiscard]] std::uint64_t EstimateFullCheckpointFamilyBytes(std::uint64_t target_xid) const;
    void RebuildPendingBasicInfoMutationIndex();
    [[nodiscard]] bool CoalescePendingSetFileSizeMutation(
        std::uint64_t object_id,
        const MutationRequest& request,
        const std::wstring* canonical_path_key = nullptr);
    [[nodiscard]] bool CoalescePendingBasicInfoMutation(
        std::uint64_t object_id,
        const MutationRequest& request,
        const std::wstring* canonical_path_key = nullptr);
    [[nodiscard]] bool CoalescePendingRenameMutation(
        std::uint64_t object_id,
        const MutationRequest& request,
        const std::wstring& source_path_key,
        const std::wstring& destination_path_key);
    [[nodiscard]] const std::wstring& CachedPendingMutationPathKey(std::size_t index);
    [[nodiscard]] const std::wstring& CachedPendingMutationSecondaryPathKey(std::size_t index);
    [[nodiscard]] bool CoalescePendingWriteMutation(std::uint64_t object_id, const MutationRequest& request);
    [[nodiscard]] bool CoalescePendingWriteMutation(
        std::uint64_t object_id,
        const MutationRequest& request,
        const std::wstring* canonical_path_key = nullptr,
        const std::wstring* normalized_path = nullptr);
    [[nodiscard]] bool PendingBtreeRecordSummaryMatchesFreshIngest() const noexcept;
    struct PendingBtreeExtentKey
    {
        std::uint64_t object_id = 0;
        std::uint64_t logical_offset = 0;

        friend bool operator==(const PendingBtreeExtentKey& left, const PendingBtreeExtentKey& right) noexcept
        {
            return left.object_id == right.object_id &&
                   left.logical_offset == right.logical_offset;
        }
    };
    struct PendingBtreeExtentKeyHash
    {
        std::size_t operator()(const PendingBtreeExtentKey& key) const noexcept
        {
            auto seed = std::hash<std::uint64_t>{}(key.object_id);
            seed ^= std::hash<std::uint64_t>{}(key.logical_offset) + 0x9e3779b97f4a7c15ull + (seed << 6) + (seed >> 2);
            return seed;
        }
    };
    struct WorkingDirectoryChildKey
    {
        std::uint64_t parent_object_id = 0;
        std::uint64_t child_object_id = 0;

        friend bool operator==(const WorkingDirectoryChildKey& left, const WorkingDirectoryChildKey& right) noexcept
        {
            return left.parent_object_id == right.parent_object_id &&
                   left.child_object_id == right.child_object_id;
        }
    };
    struct WorkingDirectoryChildKeyHash
    {
        std::size_t operator()(const WorkingDirectoryChildKey& key) const noexcept
        {
            auto seed = std::hash<std::uint64_t>{}(key.parent_object_id);
            seed ^= std::hash<std::uint64_t>{}(key.child_object_id) + 0x9e3779b97f4a7c15ull + (seed << 6) + (seed >> 2);
            return seed;
        }
    };
    void RebuildPendingBtreeFileMetadataIndex();
    void UntrackPendingBtreeRecordIndex(const BtreeRecord& record, std::size_t index);
    void TrackPendingBtreeRecordIndex(const BtreeRecord& record, std::size_t index);
    void StagePendingBtreeRecord(BtreeRecord record);
    void CoalescePendingBtreeFileMetadata(std::uint64_t object_id);
    [[nodiscard]] MutationCompactor::Summary SummarizePendingMutations() const;
    [[nodiscard]] std::uint64_t AlignExtentBytes(std::uint64_t bytes) const noexcept;
    [[nodiscard]] bool ExtentOverlapsReservedMetadata(std::uint64_t physical_address, std::uint64_t bytes) const;
    [[nodiscard]] bool ExtentOverlapsLiveAllocation(std::uint64_t physical_address, std::uint64_t bytes) const;
    [[nodiscard]] bool ExtentOverlapsEffectiveLiveAllocation(std::uint64_t physical_address, std::uint64_t bytes) const;
    [[nodiscard]] std::optional<std::uint64_t> AdvancePastReservedMetadata(
        std::uint64_t physical_address,
        std::uint64_t bytes) const;
    [[nodiscard]] std::optional<std::uint64_t> AdvancePastUnavailableExtent(
        std::uint64_t physical_address,
        std::uint64_t bytes) const;
    [[nodiscard]] bool SanitizeWorkingFreeExtents();
    [[nodiscard]] bool ValidateCommitBlobLocation(std::uint64_t physical_address, std::uint64_t bytes) const;
    [[nodiscard]] bool ValidateCommitExtentStage(std::uint64_t physical_address, std::uint64_t bytes) const;
    [[nodiscard]] bool ShouldAcceptScaffoldCommitBlobForCurrentContext() const noexcept;
    [[nodiscard]] bool ShouldUseScaffoldCommitBlobForCurrentContext() const noexcept;
    [[nodiscard]] bool ValidateReplayCommitBlobCandidate(
        std::uint64_t physical_address,
        std::uint64_t bytes,
        std::uint64_t expected_source_xid,
        std::uint64_t expected_target_xid) const;
    void SyncCommitBlobTelemetryWithMode() noexcept;
    [[nodiscard]] bool ValidatePendingCommitState(
        bool validate_inode_graphs,
        bool validate_projected_btree_state) const;
    [[nodiscard]] bool AllowCommitStage(std::string_view stage);
    void InvalidateCommittedObjectMapOrderCache() const noexcept;
    void InvalidateCommittedReadExtentSnapshotCache() const noexcept;
    void InvalidateCommittedReadExtentSnapshotCacheForObject(std::uint64_t object_id) const noexcept;
    struct CommittedObjectMapOrderEntry
    {
        std::uint64_t object_id = 0;
        const ObjectMapUpdate* update = nullptr;
    };
    [[nodiscard]] const std::vector<CommittedObjectMapOrderEntry>* OrderedCommittedObjectMapEntries() const;
    [[nodiscard]] bool TryUpdateCommittedObjectMapOrderCacheForObject(std::uint64_t object_id) const;
    void InvalidateCommittedInodeOrderCache() const noexcept;
    struct CommittedInodeOrderEntry
    {
        std::uint64_t object_id = 0;
        std::wstring path_key;
        const InodeRecord* inode = nullptr;
        bool persist_full_path = false;
        std::size_t serialized_record_bytes = 0;
    };
    [[nodiscard]] const std::vector<CommittedInodeOrderEntry>* OrderedCommittedInodeEntries() const;
    [[nodiscard]] bool TryUpdateCommittedInodeOrderCacheForObject(
        std::uint64_t object_id,
        const std::wstring* previous_path_key,
        const std::wstring* current_path_key) const;
    [[nodiscard]] std::optional<std::size_t> CommittedInodeCheckpointRequiredBytesFromCache() const;
    [[nodiscard]] bool ShouldPersistCommittedInodeFullPath(const InodeRecord& inode) const;
    void RefreshCanonicalGateState() const;
    void RecordIntegrityFailure(std::wstring reason, std::uint64_t object_id = 0) const;
    [[nodiscard]] std::wstring ResolveIntegrityCheckFailureRecoveryReason() const;
    void MarkRecoveryRequired(std::wstring reason);
    void ClearRecoveryRequired();
    [[nodiscard]] bool PersistObjectMapCheckpoint(std::uint64_t target_xid);
    [[nodiscard]] bool PersistSpacemanCheckpoint(std::uint64_t target_xid);
    [[nodiscard]] bool PersistInodeCheckpoint(std::uint64_t target_xid);
    [[nodiscard]] bool PersistBtreeCheckpoint(std::uint64_t target_xid);
    [[nodiscard]] bool PersistReplayCheckpoint(std::uint64_t target_xid, bool validate_commit_blob_candidate = true);
    [[nodiscard]] bool PersistCheckpointSuperblock(std::uint64_t target_xid);
    [[nodiscard]] bool BuildCommitBlob(std::uint64_t target_xid);
    [[nodiscard]] bool LoadPersistentState();
    [[nodiscard]] bool PersistPersistentState(std::uint64_t commit_blob_address, std::uint64_t commit_blob_bytes);
    [[nodiscard]] static std::filesystem::path BuildPersistentStatePath(const VolumeContext& context);
    static void AppendLe32(std::vector<std::byte>& blob, std::uint32_t value);
    static void AppendLe64(std::vector<std::byte>& blob, std::uint64_t value);
    static void WriteLe32(std::vector<std::byte>& buffer, std::size_t offset, std::uint32_t value);
    static void WriteLe64(std::vector<std::byte>& buffer, std::size_t offset, std::uint64_t value);

    VolumeContext context_;
    BlockDevice device_;
    bool container_loaded_ = false;
    bool object_map_loaded_ = false;
    bool spaceman_loaded_ = false;
    std::uint32_t block_size_ = 4096;
    std::uint64_t total_blocks_ = 0;
    mutable std::vector<std::uint64_t> object_map_checkpoint_block_indices_cache_;
    mutable std::vector<std::uint64_t> spaceman_checkpoint_block_indices_cache_;
    mutable std::vector<std::uint64_t> inode_checkpoint_block_indices_cache_;
    mutable std::vector<std::uint64_t> btree_checkpoint_block_indices_cache_;
    mutable std::vector<std::uint64_t> replay_checkpoint_block_indices_cache_;
    mutable std::optional<std::uint64_t> object_map_checkpoint_block_indices_cache_total_blocks_;
    mutable std::optional<std::uint64_t> spaceman_checkpoint_block_indices_cache_total_blocks_;
    mutable std::optional<std::uint64_t> inode_checkpoint_block_indices_cache_total_blocks_;
    mutable std::optional<std::uint64_t> btree_checkpoint_block_indices_cache_total_blocks_;
    mutable std::optional<std::uint64_t> replay_checkpoint_block_indices_cache_total_blocks_;
    std::uint64_t checkpoint_xid_ = 0;
    std::uint64_t loaded_superblock_checkpoint_xid_ = 0;
    std::uint64_t active_superblock_offset_ = 0;
    std::uint64_t alternate_superblock_offset_ = 0;
    std::vector<std::byte> active_superblock_bytes_;
    std::uint64_t first_superblock_block_ = 0;
    std::uint64_t first_meta_block_ = 0;
    std::uint32_t current_superblock_map_index_ = 0;
    std::uint32_t current_meta_index_ = 0;
    std::uint32_t next_meta_index_ = 0;
    std::uint64_t spaceman_object_id_ = 0;
    std::uint64_t volume_root_block_ = 0;
    std::uint64_t checkpoint_anchor_block_ = 0;
    std::optional<std::uint64_t> spaceman_free_bytes_;
    std::uint64_t next_ephemeral_extent_ = 0;
    std::uint64_t working_next_ephemeral_extent_ = 0;
    std::uint64_t next_generated_object_id_ = 1;
    bool native_write_ready_ = false;
    bool commit_path_ready_ = false;
    bool canonical_state_loaded_ = false;
    bool canonical_commit_ready_ = false;
    mutable bool production_canonical_path_active_ = false;
    bool legacy_fixture_fallback_used_ = false;
    bool uses_scaffold_commit_blob_ = false;
    mutable std::wstring last_canonical_gate_failure_;
    std::string last_commit_stage_;
    mutable std::wstring last_commit_failure_reason_;
    mutable std::wstring last_commit_failure_detail_;
    mutable std::optional<std::uint64_t> last_commit_failure_object_id_;
    std::string last_replay_stage_;
    std::string last_commit_blob_magic_ = "APFSRWCANON3";
    bool last_replay_checkpoint_candidate_present_ = false;
    bool last_replay_checkpoint_pending_window_ = false;
    std::optional<std::uint64_t> replay_checkpoint_load_xid_;
    bool write_device_allowed_ = false;
    bool recovery_required_ = false;
    std::wstring recovery_reason_;
    mutable std::wstring last_integrity_failure_reason_;
    mutable std::optional<std::uint64_t> last_integrity_failure_object_id_;
    std::wstring last_mutation_failure_reason_;
    bool persistent_state_loaded_ = false;
    std::optional<std::uint64_t> last_committed_xid_;
    std::optional<std::uint64_t> last_commit_blob_address_;
    std::optional<std::uint64_t> last_commit_blob_bytes_;
    std::unordered_map<std::uint64_t, std::uint64_t> superblock_object_block_map_;
    // Pending writes retain mutation order, but coalescing commonly removes
    // an entry from the middle. Deques avoid shifting the full tail.
    std::deque<MutationRequest> pending_mutations_;
    std::deque<PendingMutationPathKeyCacheEntry> pending_mutation_path_key_cache_;
    std::unordered_set<std::uint64_t> pending_write_object_ids_;
    std::unordered_map<std::uint64_t, std::size_t> pending_write_mutation_index_by_object_id_;
    std::unordered_map<std::uint64_t, std::size_t> pending_basic_info_mutation_index_by_object_id_;
    std::unordered_map<std::wstring, std::uint64_t> pending_payload_path_keys_;
    std::map<std::wstring, std::uint64_t> pending_payload_path_key_order_;
    bool pending_payload_path_key_order_valid_ = true;
    std::unordered_set<std::uint64_t> pending_payload_object_ids_;
    std::vector<std::uint64_t> pending_payload_object_order_;
    std::unordered_map<std::uint64_t, std::size_t> pending_payload_object_order_index_;
    std::unordered_map<std::uint64_t, std::uint64_t> pending_payload_object_bytes_by_id_;
    std::uint64_t pending_payload_total_bytes_ = 0;
    std::uint64_t pending_payload_dirty_bytes_ = 0;
    std::unordered_map<std::uint64_t, std::size_t> pending_object_map_update_index_;
    std::unordered_set<std::uint64_t> pending_close_delay_created_file_object_ids_;
    std::size_t pending_close_delay_write_count_ = 0;
    std::size_t pending_close_delay_payload_write_count_ = 0;
    std::size_t pending_close_delay_metadata_only_count_ = 0;
    bool pending_close_delay_mixed_valid_ = true;
    bool pending_close_delay_continue_valid_ = true;
    std::unordered_map<std::uint64_t, ObjectMapUpdate> committed_object_map_;
    mutable std::vector<CommittedObjectMapOrderEntry> committed_object_map_order_cache_;
    mutable bool committed_object_map_order_cache_valid_ = false;
    mutable std::uint64_t committed_object_map_order_cache_generation_ = 0;
    mutable std::uint64_t committed_object_map_order_generation_ = 0;
    std::unordered_map<std::uint64_t, InodeRecord> committed_inodes_;
    mutable std::vector<CommittedInodeOrderEntry> committed_inode_order_cache_;
    mutable bool committed_inode_order_cache_valid_ = false;
    mutable std::uint64_t committed_inode_order_cache_generation_ = 0;
    mutable std::uint64_t committed_inode_order_generation_ = 0;
    mutable std::optional<std::size_t> committed_inode_checkpoint_required_bytes_cache_;
    std::unordered_map<std::wstring, std::uint64_t> committed_path_index_;
    std::vector<CommittedInodeChange> last_committed_inode_changes_;
    std::vector<DirectoryLink> committed_directory_links_;
    std::unordered_map<std::uint64_t, std::vector<std::uint64_t>> committed_child_object_ids_by_parent_;
    std::unordered_map<WorkingDirectoryChildKey, std::size_t, WorkingDirectoryChildKeyHash> committed_child_index_by_parent_child_;
    std::unordered_map<DirectoryLinkIndexKey, std::size_t, DirectoryLinkIndexKeyHash> committed_directory_link_index_;
    std::vector<BtreeRecord> committed_btree_records_;
    std::unordered_map<std::string, std::size_t> committed_btree_index_by_key_;
    std::unordered_map<std::uint64_t, std::string> committed_btree_inode_key_by_object_id_;
    std::unordered_map<std::uint64_t, std::vector<FileExtent>> committed_read_extents_;
    struct CommittedReadExtentSnapshotCacheEntry
    {
        std::shared_ptr<const std::vector<FileExtent>> extents;
        std::uint64_t last_use = 0;
    };
    mutable std::unordered_map<std::uint64_t, CommittedReadExtentSnapshotCacheEntry>
        committed_read_extent_snapshot_cache_;
    mutable std::uint64_t committed_read_extent_snapshot_cache_use_ = 0;
    mutable std::uint64_t committed_read_extent_snapshot_cache_bytes_ = 0;
    std::unordered_map<std::uint64_t, std::vector<FileExtent>> working_read_extents_;
    std::unordered_map<std::uint64_t, std::vector<FileExtent>> pending_read_extent_updates_;
    mutable std::atomic<std::uint64_t> last_raw_mutation_count_{0};
    mutable std::atomic<std::uint64_t> last_compacted_mutation_count_{0};
    mutable std::atomic<std::uint64_t> pending_write_coalesce_scan_count_{0};
    mutable std::atomic<std::uint64_t> pending_basic_info_coalesce_path_fallback_count_{0};
    mutable std::atomic<std::uint64_t> pending_set_file_size_coalesce_path_fallback_count_{0};
    mutable std::atomic<std::uint64_t> pending_rename_path_key_cache_hit_count_{0};
    mutable std::atomic<std::uint64_t> pending_rename_path_key_cache_miss_count_{0};
    mutable std::atomic<std::uint64_t> pending_object_map_update_scan_count_{0};
    mutable std::atomic<std::uint64_t> pending_btree_file_metadata_scan_count_{0};
    mutable std::atomic<std::uint64_t> pending_btree_file_metadata_rebuild_count_{0};
    mutable std::atomic<std::uint64_t> pending_btree_file_metadata_local_erase_count_{0};
    mutable std::atomic<std::uint64_t> pending_btree_touched_inode_index_reuse_count_{0};
    mutable std::atomic<std::uint64_t> pending_btree_touched_inode_fallback_scan_count_{0};
    mutable std::atomic<std::uint64_t> commit_touched_inode_dedupe_fast_path_count_{0};
    mutable std::atomic<std::uint64_t> commit_touched_inode_sort_fallback_count_{0};
    mutable std::atomic<std::uint64_t> pending_close_delay_summary_rebuild_count_{0};
    mutable std::atomic<std::uint64_t> working_free_extent_sanitize_count_{0};
    mutable std::atomic<std::uint64_t> working_free_extent_sanitize_skip_count_{0};
    mutable std::atomic<std::uint64_t> free_extent_sanitize_count_{0};
    mutable std::atomic<std::uint64_t> free_extent_sanitize_skip_count_{0};
    mutable std::atomic<std::uint64_t> commit_restore_dedupe_linear_scan_count_{0};
    mutable std::atomic<std::uint64_t> mutation_restore_dedupe_hash_fast_path_count_{0};
    mutable std::atomic<std::uint64_t> commit_btree_full_snapshot_count_{0};
    mutable std::atomic<std::uint64_t> commit_blob_precise_reserve_count_{0};
    mutable std::atomic<std::uint64_t> commit_blob_reserve_fallback_count_{0};
    mutable std::atomic<std::uint64_t> commit_blob_direct_fill_count_{0};
    mutable std::atomic<std::uint64_t> commit_inode_graph_validation_skip_count_{0};
    mutable std::atomic<std::uint64_t> commit_projected_btree_validation_skip_count_{0};
    mutable std::atomic<std::uint64_t> commit_fresh_ingest_overlay_preflight_count_{0};
    mutable std::atomic<std::uint64_t> commit_full_object_preflight_sweep_count_{0};
    mutable std::atomic<std::uint64_t> commit_object_map_preflight_index_lookup_count_{0};
    mutable std::atomic<std::uint64_t> commit_fresh_ingest_physical_order_fast_path_count_{0};
    mutable std::atomic<std::uint64_t> commit_fresh_ingest_physical_set_fallback_count_{0};
    mutable std::atomic<std::uint64_t> commit_fresh_ingest_mapping_recheck_skip_count_{0};
    mutable std::atomic<std::uint64_t> pending_allocation_validation_sorted_count_{0};
    mutable std::atomic<std::uint64_t> pending_allocation_validation_fallback_scan_count_{0};
    mutable std::atomic<std::uint64_t> pending_allocation_validation_committed_sorted_reuse_count_{0};
    mutable std::atomic<std::uint64_t> pending_allocation_validation_committed_index_fallback_count_{0};
    mutable std::atomic<std::uint64_t> pending_allocation_validation_pending_sorted_reuse_count_{0};
    mutable std::atomic<std::uint64_t> pending_allocation_validation_pending_index_reuse_count_{0};
    mutable std::atomic<std::uint64_t> pending_allocation_validation_pending_sort_fallback_count_{0};
    mutable std::atomic<std::uint64_t> projected_spaceman_validation_fast_count_{0};
    mutable std::atomic<std::uint64_t> projected_spaceman_validation_full_count_{0};
    mutable std::atomic<std::uint64_t> pending_spaceman_allocation_index_rebuild_count_{0};
    mutable std::atomic<std::uint64_t> pending_spaceman_allocation_index_local_erase_count_{0};
    mutable std::atomic<std::uint64_t> pending_spaceman_allocation_index_local_resize_count_{0};
    mutable std::atomic<std::uint64_t> commit_extent_fast_validation_count_{0};
    mutable std::atomic<std::uint64_t> commit_extent_working_free_snapshot_count_{0};
    mutable std::atomic<std::uint64_t> commit_extent_working_free_local_rollback_count_{0};
    mutable std::atomic<std::uint64_t> mutation_working_free_snapshot_count_{0};
    mutable std::atomic<std::uint64_t> mutation_working_free_local_undo_count_{0};
    mutable std::atomic<std::uint64_t> chunked_checkpoint_selection_count_{0};
    mutable std::atomic<std::uint64_t> checkpoint_slot_validation_indexed_count_{0};
    mutable std::atomic<std::uint64_t> checkpoint_slot_validation_fallback_scan_count_{0};
    mutable std::atomic<std::uint64_t> checkpoint_block_index_cache_hit_count_{0};
    mutable std::atomic<std::uint64_t> checkpoint_block_index_cache_build_count_{0};
    mutable std::atomic<std::uint64_t> checkpoint_block_index_cache_bypass_build_count_{0};
    mutable std::atomic<std::uint64_t> checkpoint_family_batch_count_{0};
    mutable std::atomic<std::uint64_t> checkpoint_family_batch_write_count_{0};
    mutable std::atomic<std::uint64_t> checkpoint_serialization_buffer_growth_count_{0};
    mutable std::atomic<std::uint64_t> checkpoint_serialization_buffer_reuse_count_{0};
    mutable std::atomic<std::uint64_t> checkpoint_write_pad_count_{0};
    mutable std::atomic<std::uint64_t> checkpoint_write_pad_bytes_{0};
    mutable std::atomic<std::uint64_t> checkpoint_write_partial_materialization_count_{0};
    mutable std::atomic<std::uint64_t> payload_tail_zero_pad_count_{0};
    mutable std::atomic<std::uint64_t> payload_tail_zero_pad_bytes_{0};
    mutable std::atomic<std::uint64_t> payload_range_materialized_chunk_count_{0};
    mutable std::atomic<std::uint64_t> payload_range_materialized_chunk_bytes_{0};
    mutable std::atomic<std::uint64_t> payload_range_materialized_buffer_resize_count_{0};
    mutable std::atomic<std::uint64_t> payload_range_materialized_buffer_reuse_count_{0};
    mutable std::atomic<std::uint64_t> payload_window_batch_count_{0};
    mutable std::atomic<std::uint64_t> payload_window_batch_bytes_{0};
    mutable std::atomic<std::uint64_t> prepared_payload_single_extent_direct_write_count_{0};
    mutable std::atomic<std::uint64_t> committed_single_extent_read_fast_path_count_{0};
    mutable std::atomic<std::uint64_t> committed_read_extent_snapshot_cache_hit_count_{0};
    mutable std::atomic<std::uint64_t> committed_read_extent_snapshot_cache_miss_count_{0};
    mutable std::atomic<std::uint64_t> pending_payload_write_order_fast_count_{0};
    mutable std::atomic<std::uint64_t> pending_payload_write_sort_count_{0};
    mutable std::atomic<std::uint64_t> pending_payload_write_reserve_extra_pass_count_{0};
    mutable std::atomic<std::uint64_t> pending_payload_write_reserve_extra_entry_count_{0};
    mutable std::atomic<std::uint64_t> pending_payload_write_coalesce_in_place_count_{0};
    mutable std::atomic<std::uint64_t> pending_payload_write_coalesced_entry_count_{0};
    mutable std::atomic<std::uint64_t> committed_spaceman_apply_count_{0};
    mutable std::atomic<std::uint64_t> committed_spaceman_apply_local_count_{0};
    mutable std::atomic<std::uint64_t> committed_spaceman_free_apply_count_{0};
    mutable std::atomic<std::uint64_t> committed_spaceman_free_apply_local_count_{0};
    mutable std::atomic<std::uint64_t> committed_spaceman_free_apply_in_place_count_{0};
    mutable std::atomic<std::uint64_t> committed_spaceman_free_verify_full_count_{0};
    mutable std::atomic<std::uint64_t> committed_spaceman_free_verify_skip_count_{0};
    mutable std::atomic<std::uint64_t> committed_spaceman_full_snapshot_count_{0};
    mutable std::atomic<std::uint64_t> spaceman_checkpoint_fast_path_count_{0};
    mutable std::atomic<std::uint64_t> spaceman_checkpoint_normalize_fallback_count_{0};
    mutable std::atomic<std::uint64_t> committed_directory_link_index_rebuild_count_{0};
    mutable std::atomic<std::uint64_t> committed_btree_index_rebuild_count_{0};
    mutable std::atomic<std::uint64_t> checkpoint_delta_shadow_count_{0};
    mutable std::atomic<std::uint64_t> checkpoint_delta_shadow_record_count_{0};
    mutable std::atomic<std::uint64_t> checkpoint_delta_shadow_bytes_{0};
    mutable std::atomic<std::uint64_t> checkpoint_delta_shadow_full_bytes_{0};
    mutable std::atomic<std::uint64_t> object_map_checkpoint_order_rebuild_count_{0};
    mutable std::atomic<std::uint64_t> object_map_checkpoint_order_cache_hit_count_{0};
    mutable std::atomic<std::uint64_t> object_map_checkpoint_order_delta_update_count_{0};
    mutable std::atomic<std::uint64_t> object_map_checkpoint_order_delta_fallback_count_{0};
    mutable std::atomic<std::uint64_t> inode_checkpoint_order_rebuild_count_{0};
    mutable std::atomic<std::uint64_t> inode_checkpoint_order_cache_hit_count_{0};
    mutable std::atomic<std::uint64_t> inode_checkpoint_order_delta_update_count_{0};
    mutable std::atomic<std::uint64_t> inode_checkpoint_order_delta_fallback_count_{0};
    mutable std::atomic<std::uint64_t> inode_checkpoint_size_cache_hit_count_{0};
    mutable std::atomic<std::uint64_t> btree_checkpoint_size_prescan_count_{0};
    mutable std::atomic<std::uint64_t> directory_rename_descendant_path_lookup_count_{0};
    mutable std::atomic<std::uint64_t> directory_rename_descendant_directory_link_update_count_{0};
    mutable std::atomic<std::uint64_t> pending_payload_rename_path_scan_count_{0};
    mutable std::atomic<std::uint64_t> pending_payload_delete_path_scan_count_{0};
    mutable std::atomic<std::uint64_t> pending_payload_summary_path_scan_count_{0};
    mutable std::atomic<std::uint64_t> pending_payload_path_order_build_count_{0};
    mutable std::atomic<std::uint64_t> pending_payload_range_local_merge_count_{0};
    mutable std::atomic<std::uint64_t> pending_payload_range_full_merge_count_{0};
    mutable std::atomic<std::uint64_t> pending_payload_object_order_iteration_count_{0};
    mutable std::atomic<std::uint64_t> pending_payload_object_order_compaction_count_{0};
    std::unordered_map<std::uint64_t, InodeRecord> working_inodes_;
    std::unordered_map<std::wstring, std::uint64_t> working_path_index_;
    std::vector<DirectoryLink> working_directory_links_;
    std::unordered_map<std::uint64_t, std::size_t> working_child_count_by_parent_;
    std::unordered_map<std::uint64_t, std::vector<std::uint64_t>> working_child_object_ids_by_parent_;
    std::unordered_map<WorkingDirectoryChildKey, std::size_t, WorkingDirectoryChildKeyHash> working_child_index_by_parent_child_;
    std::unordered_map<DirectoryLinkIndexKey, std::size_t, DirectoryLinkIndexKeyHash> working_directory_link_index_;
    mutable std::atomic<std::uint64_t> working_directory_child_linear_scan_count_{0};
    std::vector<SpacemanAllocation> committed_spaceman_allocations_;
    std::vector<SpacemanAllocation> committed_spaceman_free_extents_;
    std::vector<SpacemanAllocation> working_spaceman_free_extents_;
    bool working_free_extents_sanitized_ = false;
    std::vector<ObjectMapUpdate> pending_object_map_updates_;
    std::vector<SpacemanAllocation> pending_spaceman_allocations_;
    std::map<std::uint64_t, std::size_t> pending_spaceman_allocation_index_;
    std::vector<SpacemanAllocation> pending_spaceman_deallocations_;
    bool tracking_spaceman_free_extent_delta_ = false;
    bool pending_spaceman_untracked_free_extent_delta_ = false;
    bool pending_spaceman_released_existing_allocation_ = false;
    std::vector<BtreeRecord> pending_btree_records_;
    std::unordered_map<std::uint64_t, std::size_t> pending_btree_inode_record_count_by_object_;
    std::unordered_map<std::uint64_t, std::size_t> pending_btree_file_inode_index_;
    std::unordered_map<PendingBtreeExtentKey, std::size_t, PendingBtreeExtentKeyHash> pending_btree_file_extent_index_;
    std::unordered_map<std::uint64_t, std::unordered_set<std::uint64_t>> pending_btree_file_extent_offsets_by_object_;
    std::unordered_map<std::uint64_t, std::size_t> pending_btree_file_extent_record_count_by_object_;
    std::unordered_map<std::uint64_t, std::size_t> pending_btree_directory_record_count_by_child_object_;
    std::size_t pending_btree_tombstone_record_count_ = 0;
    std::size_t pending_btree_directory_inode_record_count_ = 0;
    std::size_t pending_btree_untracked_record_count_ = 0;
    std::unordered_map<std::uint64_t, std::vector<PreparedPayloadRange>> prepared_payload_ranges_;
    std::unordered_map<std::uint64_t, std::vector<PreparedPayloadRange>> pending_written_ranges_;
    std::function<bool(std::string_view stage)> commit_stage_hook_;
    bool commit_stage_hook_requires_strict_verification_ = false;
    std::function<std::optional<std::vector<std::byte>>(const std::wstring&, std::uint64_t)> file_payload_provider_;
    std::function<bool(const std::wstring&, PayloadIdentity, std::uint64_t, std::span<std::byte>)> file_payload_range_provider_;
    std::vector<std::byte> object_map_checkpoint_serialization_buffer_;
    std::vector<std::byte> spaceman_checkpoint_serialization_buffer_;
    std::vector<std::byte> inode_checkpoint_serialization_buffer_;
    std::vector<std::byte> btree_checkpoint_serialization_buffer_;
    std::vector<std::byte> replay_checkpoint_serialization_buffer_;
    std::vector<std::byte> commit_blob_serialization_buffer_;
    CheckpointWriteBatch* active_checkpoint_write_batch_ = nullptr;
    std::filesystem::path persistent_state_path_;
    mutable PerfCounter apply_mutation_perf_;
    mutable PerfCounter commit_pending_perf_;
    mutable PerfCounter commit_transaction_perf_;
    mutable PerfCounter commit_canonical_perf_;
    mutable PerfCounter validate_inode_graph_perf_;
    mutable PerfCounter snapshot_committed_inodes_perf_;
    mutable PerfCounter read_committed_range_perf_;
    mutable PerfCounter allocation_lookup_perf_;
    mutable PerfCounter free_list_lookup_perf_;
    mutable PerfCounter build_commit_blob_perf_;
    mutable PerfCounter persist_object_map_checkpoint_perf_;
    mutable PerfCounter persist_spaceman_checkpoint_perf_;
    mutable PerfCounter persist_inode_checkpoint_perf_;
    mutable PerfCounter persist_btree_checkpoint_perf_;
    mutable PerfCounter persist_replay_checkpoint_perf_;
    mutable PerfCounter persist_superblock_checkpoint_perf_;
    mutable PerfCounter take_last_committed_inode_changes_perf_;
};
} // namespace apfsaccess::rw
