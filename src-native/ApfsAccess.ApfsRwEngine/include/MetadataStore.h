#pragma once

#include "BtreeMutationCodec.h"
#include "BlockDevice.h"

#include <atomic>
#include <cstdint>
#include <cstddef>
#include <array>
#include <filesystem>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
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

    struct DirectoryLink
    {
        std::uint64_t parent_object_id = 0;
        std::wstring entry_name;
        std::uint64_t child_object_id = 0;
        std::uint64_t xid = 0;
    };

    struct SpacemanAllocation
    {
        std::uint64_t physical_address = 0;
        std::uint64_t bytes = 0;
    };

    struct FileExtent
    {
        std::uint64_t logical_offset = 0;
        std::uint64_t physical_address = 0;
        std::uint64_t bytes = 0;
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
    [[nodiscard]] MutationStatus StageMutation(const MutationRequest& request);
    [[nodiscard]] MutationStatus ApplyMutation(const MutationRequest& request);
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
    [[nodiscard]] std::size_t PendingObjectMapUpdateCount() const noexcept;
    [[nodiscard]] std::size_t PendingAllocationCount() const noexcept;
    [[nodiscard]] std::size_t PendingDeallocationCount() const noexcept;
    [[nodiscard]] std::size_t PendingBtreeRecordCount() const noexcept;
    [[nodiscard]] std::uint64_t PendingPayloadByteEstimate() const;
    [[nodiscard]] std::optional<std::uint64_t> LastCommittedXid() const noexcept;
    [[nodiscard]] std::size_t CommittedObjectCount() const noexcept;
    [[nodiscard]] std::size_t CommittedAllocationCount() const noexcept;
    [[nodiscard]] std::size_t CommittedFreeExtentCount() const noexcept;
    [[nodiscard]] std::size_t CommittedBtreeRecordCount() const noexcept;
    [[nodiscard]] std::optional<ObjectMapUpdate> LookupCommittedObject(std::uint64_t object_id) const;
    [[nodiscard]] std::size_t CommittedInodeCount() const noexcept;
    [[nodiscard]] std::optional<InodeRecord> LookupCommittedInodeByPath(const std::wstring& path) const;
    [[nodiscard]] std::vector<InodeRecord> SnapshotCommittedInodes() const;
    [[nodiscard]] bool SetCommittedReadExtents(std::uint64_t object_id, std::vector<FileExtent> extents);
    [[nodiscard]] bool DebugMergeNativeProjectionReadExtents(std::uint64_t object_id, std::vector<FileExtent> extents);
    [[nodiscard]] std::size_t DebugWorkingDirectoryChildCount(std::uint64_t parent_object_id) const;
    [[nodiscard]] std::size_t DebugWorkingInodeCount() const noexcept;
    [[nodiscard]] std::optional<InodeRecord> DebugLookupWorkingInodeByPath(const std::wstring& path) const;
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
    void SetCommitStageHook(std::function<bool(std::string_view stage)> hook);
    void SetFilePayloadProvider(
        std::function<std::optional<std::vector<std::byte>>(const std::wstring& path, std::uint64_t logical_size)> provider);
    void SetFilePayloadRangeProvider(
        std::function<bool(
            const std::wstring& path,
            std::uint64_t offset,
            std::span<std::byte> destination)> provider);

    // Allocation/free-space primitives used by staged native mutations.
    [[nodiscard]] std::optional<std::uint64_t> AllocateExtent(std::uint64_t bytes);
    [[nodiscard]] bool FreeExtent(std::uint64_t physical_address, std::uint64_t bytes);

private:
    struct PerfCounter
    {
        std::atomic<std::uint64_t> count{0};
        std::atomic<std::uint64_t> total_us{0};
        std::atomic<std::uint64_t> max_us{0};
        std::atomic<std::uint64_t> last_us{0};

        void Observe(std::uint64_t elapsed_us) noexcept;
    };
    struct ScopedPerfTimer;

    [[nodiscard]] static std::uint32_t ReadLe32(const std::vector<std::byte>& buffer, std::size_t offset);
    [[nodiscard]] static std::uint64_t ReadLe64(const std::vector<std::byte>& buffer, std::size_t offset);
    [[nodiscard]] static std::uint64_t StableObjectIdFromPath(const std::wstring& path);
    [[nodiscard]] static std::wstring NormalizePath(const std::wstring& path);
    [[nodiscard]] static std::wstring CanonicalPathKey(const std::wstring& normalized_path);
    [[nodiscard]] static bool IsRootPath(const std::wstring& normalized_path);
    [[nodiscard]] static bool IsDescendantPath(const std::wstring& candidate_path, const std::wstring& parent_path);
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
    [[nodiscard]] std::vector<std::byte> ReadChunkedCheckpointBytes(
        const std::vector<std::uint64_t>& block_indices,
        std::uint64_t target_xid,
        const std::array<char, 12>& magic,
        std::uint32_t expected_payload_bytes) const;
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
    [[nodiscard]] bool WriteBlockByIndexDirect(std::uint64_t block_index, const std::vector<std::byte>& block);
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
    [[nodiscard]] std::wstring BuildWorkingDirectoryLinkIndexKey(std::uint64_t parent_object_id, const std::wstring& entry_name) const;
    void RebuildWorkingDirectoryIndexes();
    [[nodiscard]] bool HasWorkingChildren(std::uint64_t parent_object_id) const;
    void UpsertWorkingDirectoryLink(std::uint64_t parent_object_id, const std::wstring& entry_name, std::uint64_t child_object_id, std::uint64_t xid);
    void RemoveWorkingDirectoryLink(std::uint64_t parent_object_id, const std::wstring& entry_name);
    [[nodiscard]] bool StageObjectMapUpdate(std::uint64_t object_id, std::uint64_t physical_address, std::uint64_t logical_size);
    [[nodiscard]] bool StageSpacemanAllocation(std::uint64_t physical_address, std::uint64_t bytes);
    [[nodiscard]] bool StageSpacemanDeallocation(std::uint64_t physical_address, std::uint64_t bytes);
    [[nodiscard]] std::optional<std::vector<FileExtent>> AllocateFileExtents(std::uint64_t logical_size);
    [[nodiscard]] std::optional<FileMutationExtents> CommittedFileExtentsForMutation(const InodeRecord& inode) const;
    [[nodiscard]] bool PendingReadExtentsCoverLogicalRange(
        std::uint64_t object_id,
        std::uint64_t offset,
        std::uint64_t length) const;
    [[nodiscard]] bool StageCommittedFileExtentDeallocations(const FileMutationExtents& extents);
    [[nodiscard]] bool HasPendingSpacemanAllocation(std::uint64_t physical_address, std::uint64_t bytes) const;
    [[nodiscard]] bool ReleasePendingSpacemanAllocation(std::uint64_t physical_address, std::uint64_t bytes);
    void CoalescePendingWriteMutation(std::uint64_t object_id, const MutationRequest& request);
    void CoalescePendingBtreeFileMetadata(std::uint64_t object_id);
    [[nodiscard]] std::uint64_t AlignExtentBytes(std::uint64_t bytes) const noexcept;
    [[nodiscard]] bool ExtentOverlapsReservedMetadata(std::uint64_t physical_address, std::uint64_t bytes) const;
    [[nodiscard]] bool ValidateCommitBlobLocation(std::uint64_t physical_address, std::uint64_t bytes) const;
    [[nodiscard]] bool ShouldAcceptScaffoldCommitBlobForCurrentContext() const noexcept;
    [[nodiscard]] bool ShouldUseScaffoldCommitBlobForCurrentContext() const noexcept;
    [[nodiscard]] bool ValidateReplayCommitBlobCandidate(
        std::uint64_t physical_address,
        std::uint64_t bytes,
        std::uint64_t expected_source_xid,
        std::uint64_t expected_target_xid) const;
    void SyncCommitBlobTelemetryWithMode() noexcept;
    [[nodiscard]] bool ValidatePendingCommitState() const;
    [[nodiscard]] bool AllowCommitStage(std::string_view stage);
    void RefreshCanonicalGateState() const;
    void RecordIntegrityFailure(std::wstring reason, std::uint64_t object_id = 0) const;
    [[nodiscard]] std::wstring ResolveIntegrityCheckFailureRecoveryReason() const;
    void MarkRecoveryRequired(std::wstring reason);
    void ClearRecoveryRequired();
    [[nodiscard]] bool PersistObjectMapCheckpoint(std::uint64_t target_xid);
    [[nodiscard]] bool PersistSpacemanCheckpoint(std::uint64_t target_xid);
    [[nodiscard]] bool PersistInodeCheckpoint(std::uint64_t target_xid);
    [[nodiscard]] bool PersistBtreeCheckpoint(std::uint64_t target_xid);
    [[nodiscard]] bool PersistReplayCheckpoint(std::uint64_t target_xid);
    [[nodiscard]] bool PersistCheckpointSuperblock(std::uint64_t target_xid);
    [[nodiscard]] std::vector<std::byte> BuildCommitBlob(std::uint64_t target_xid);
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
    std::uint64_t checkpoint_xid_ = 0;
    std::uint64_t loaded_superblock_checkpoint_xid_ = 0;
    std::uint64_t active_superblock_offset_ = 0;
    std::uint64_t alternate_superblock_offset_ = 0;
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
    std::vector<MutationRequest> pending_mutations_;
    std::unordered_map<std::uint64_t, ObjectMapUpdate> committed_object_map_;
    std::unordered_map<std::uint64_t, InodeRecord> committed_inodes_;
    std::unordered_map<std::wstring, std::uint64_t> committed_path_index_;
    std::vector<DirectoryLink> committed_directory_links_;
    std::vector<BtreeRecord> committed_btree_records_;
    std::unordered_map<std::uint64_t, std::vector<FileExtent>> committed_read_extents_;
    std::unordered_map<std::uint64_t, std::vector<FileExtent>> working_read_extents_;
    std::unordered_map<std::uint64_t, std::vector<FileExtent>> pending_read_extent_updates_;
    std::unordered_map<std::uint64_t, InodeRecord> working_inodes_;
    std::unordered_map<std::wstring, std::uint64_t> working_path_index_;
    std::vector<DirectoryLink> working_directory_links_;
    std::unordered_map<std::uint64_t, std::size_t> working_child_count_by_parent_;
    std::unordered_map<std::wstring, std::size_t> working_directory_link_index_;
    std::vector<SpacemanAllocation> committed_spaceman_allocations_;
    std::vector<SpacemanAllocation> committed_spaceman_free_extents_;
    std::vector<SpacemanAllocation> working_spaceman_free_extents_;
    std::vector<ObjectMapUpdate> pending_object_map_updates_;
    std::vector<SpacemanAllocation> pending_spaceman_allocations_;
    std::vector<SpacemanAllocation> pending_spaceman_deallocations_;
    std::vector<BtreeRecord> pending_btree_records_;
    std::function<bool(std::string_view stage)> commit_stage_hook_;
    std::function<std::optional<std::vector<std::byte>>(const std::wstring&, std::uint64_t)> file_payload_provider_;
    std::function<bool(const std::wstring&, std::uint64_t, std::span<std::byte>)> file_payload_range_provider_;
    std::filesystem::path persistent_state_path_;
    mutable PerfCounter apply_mutation_perf_;
    mutable PerfCounter commit_pending_perf_;
    mutable PerfCounter commit_transaction_perf_;
    mutable PerfCounter commit_canonical_perf_;
    mutable PerfCounter validate_inode_graph_perf_;
    mutable PerfCounter snapshot_committed_inodes_perf_;
    mutable PerfCounter read_committed_range_perf_;
    mutable PerfCounter build_commit_blob_perf_;
    mutable PerfCounter persist_object_map_checkpoint_perf_;
    mutable PerfCounter persist_spaceman_checkpoint_perf_;
    mutable PerfCounter persist_inode_checkpoint_perf_;
    mutable PerfCounter persist_btree_checkpoint_perf_;
    mutable PerfCounter persist_replay_checkpoint_perf_;
    mutable PerfCounter persist_superblock_checkpoint_perf_;
};
} // namespace apfsaccess::rw
