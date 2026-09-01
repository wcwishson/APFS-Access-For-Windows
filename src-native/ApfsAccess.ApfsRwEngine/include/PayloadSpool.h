#pragma once

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <iosfwd>
#include <memory>
#include <mutex>
#include <span>
#include <shared_mutex>
#include <string>
#include <utility>
#include <unordered_set>
#include <unordered_map>
#include <vector>

namespace apfsaccess::rw
{
struct PayloadReadHandleState;

class PayloadSpool
{
    friend struct PayloadSpoolTestAccess;

public:
    struct Options
    {
        std::filesystem::path root;
        std::string volume_identity;
        std::uint64_t max_bytes = 512ull * 1024ull * 1024ull;
        std::uint64_t durable_flush_bytes = 64ull * 1024ull * 1024ull;
        std::uint64_t durable_flush_appends = 1024;
    };

    struct WriteRequest
    {
        std::string volume_identity;
        std::uint64_t object_id = 0;
        std::uint64_t generation = 0;
        std::uint64_t logical_offset = 0;
        std::uint64_t wal_sequence = 0;
        std::span<const std::byte> payload;
    };

    struct ReadRequest
    {
        std::string volume_identity;
        std::uint64_t object_id = 0;
        std::uint64_t generation = 0;
        std::uint64_t logical_offset = 0;
        std::span<std::byte> destination;
    };

    struct AppendResult
    {
        std::uint64_t object_id = 0;
        std::uint64_t generation = 0;
        std::uint64_t logical_offset = 0;
        std::uint64_t payload_length = 0;
        std::uint64_t spool_offset = 0;
        std::uint64_t wal_sequence = 0;
        std::uint64_t checksum = 0;
        std::array<std::uint8_t, 32> payload_sha256{};
    };

    enum class AppendStatus
    {
        Succeeded,
        InvalidRequest,
        QuotaExceeded,
        StorageFailure,
    };

    struct PersistedRangeReference
    {
        std::string volume_identity;
        std::uint64_t object_id = 0;
        std::uint64_t generation = 0;
        std::uint64_t logical_offset = 0;
        std::uint64_t payload_length = 0;
        std::uint64_t spool_offset = 0;
        std::uint64_t wal_sequence = 0;
        std::array<std::uint8_t, 32> payload_sha256{};
    };

    struct Counters
    {
        std::uint64_t spool_bytes = 0;
        std::size_t dirty_range_count = 0;
        std::uint64_t oldest_dirty_age_ms = 0;
        std::uint64_t cleanup_failures = 0;
        std::uint64_t mutex_wait_count = 0;
        std::uint64_t mutex_wait_microseconds = 0;
        std::uint64_t mutex_wait_max_microseconds = 0;
        std::uint64_t mutex_wait_p50_microseconds = 0;
        std::uint64_t mutex_wait_p95_microseconds = 0;
        std::uint64_t bytes_since_sync = 0;
        std::uint64_t appends_since_sync = 0;
        std::uint64_t append_direct_count = 0;
        std::uint64_t append_merged_count = 0;
        std::uint64_t append_stream_open_count = 0;
        std::uint64_t append_stream_flush_count = 0;
        std::uint64_t append_rollback_snapshot_count = 0;
        std::uint64_t payload_only_flush_count = 0;
        std::uint64_t payload_only_flush_microseconds = 0;
        std::uint64_t payload_only_flush_max_microseconds = 0;
        std::uint64_t durable_flush_count = 0;
        std::uint64_t durable_flush_microseconds = 0;
        std::uint64_t durable_flush_max_microseconds = 0;
        std::uint64_t spool_sync_count = 0;
        std::uint64_t spool_sync_microseconds = 0;
        std::uint64_t spool_sync_max_microseconds = 0;
        std::uint64_t spool_sync_handle_flush_count = 0;
        std::uint64_t spool_sync_reopen_count = 0;
        std::uint64_t index_persist_count = 0;
        std::uint64_t index_persist_bytes = 0;
        std::uint64_t index_persist_microseconds = 0;
        std::uint64_t index_persist_max_microseconds = 0;
        std::uint64_t index_journal_frame_count = 0;
        std::uint64_t index_journal_snapshot_count = 0;
        std::uint64_t index_journal_append_count = 0;
        std::uint64_t index_journal_handle_open_count = 0;
        std::uint64_t index_journal_handle_flush_count = 0;
        std::uint64_t range_payload_read_open_count = 0;
        std::uint64_t range_payload_positional_read_count = 0;
        std::uint64_t range_payload_cache_hit_count = 0;
        std::uint64_t range_payload_cache_fill_count = 0;
        std::uint64_t overlay_direct_destination_read_count = 0;
        std::size_t dirty_object_count = 0;
        std::uint64_t object_lookup_query_count = 0;
        std::uint64_t object_lookup_candidate_count = 0;
        std::uint64_t object_lookup_index_probe_count = 0;
        std::uint64_t cleanup_sequence_probe_count = 0;
        bool index_dirty = false;
        bool recovery_required = false;
    };

    explicit PayloadSpool(Options options);
    ~PayloadSpool();

    PayloadSpool(const PayloadSpool&) = delete;
    PayloadSpool& operator=(const PayloadSpool&) = delete;

    [[nodiscard]] bool Append(const WriteRequest& request, AppendResult* result = nullptr);
    [[nodiscard]] AppendStatus AppendWithStatus(const WriteRequest& request, AppendResult* result = nullptr);
    [[nodiscard]] AppendStatus CheckAppendCapacity(std::uint64_t payload_bytes) const;
    // Makes appended payload bytes durable while leaving the advisory range index dirty.
    // WAL acceptance must be written only after this succeeds.
    [[nodiscard]] bool FlushPayloadBytes();
    [[nodiscard]] bool FlushDirtyState();
    // Optimistic healthy-headroom probe for callers that will append under the
    // spool lock immediately afterward. Exact quota and overflow decisions
    // still fall back to the locked path.
    [[nodiscard]] AppendStatus CheckAppendCapacityFast(std::uint64_t payload_bytes) const;
    // Live references must be newer than the discard boundary. Discardable
    // references prove known spool layout but are never read as payload.
    [[nodiscard]] bool RebuildIndexFromReferences(
        std::span<const PersistedRangeReference> references,
        std::uint64_t safe_discard_sequence,
        std::span<const PersistedRangeReference> discardable_references = {});
    [[nodiscard]] bool ReadPersistedRange(
        const PersistedRangeReference& reference,
        std::vector<std::byte>& payload) const;
    [[nodiscard]] bool OverlayDirtyRanges(const ReadRequest& request, std::size_t& bytes_overlayed) const;
    // Overlay dirty bytes and return the same object's logical dirty tail
    // while holding the spool lock once.
    [[nodiscard]] bool OverlayDirtyRangesWithLogicalEnd(
        const ReadRequest& request,
        std::size_t& bytes_overlayed,
        std::uint64_t& logical_end) const;
    [[nodiscard]] bool ReadFullyCoveredRange(const ReadRequest& request, std::size_t& bytes_overlayed) const;
    [[nodiscard]] bool IsRangeFullyCovered(
        std::string_view volume_identity,
        std::uint64_t object_id,
        std::uint64_t generation,
        std::uint64_t logical_offset,
        std::uint64_t bytes) const;
    [[nodiscard]] std::uint64_t MaxDirtyRangeEnd(
        std::string_view volume_identity,
        std::uint64_t object_id,
        std::uint64_t generation) const;
    [[nodiscard]] bool CleanupThroughSequence(std::uint64_t wal_sequence);
    [[nodiscard]] bool DiscardSequence(std::uint64_t wal_sequence);
    // The caller must first prove that a valid WAL contains no accepted work.
    // Indexed or corrupt recovery evidence is never discarded by this path.
    [[nodiscard]] bool ResolveUnindexedPayloadRecovery(bool wal_proves_no_accepted_work);
    [[nodiscard]] Counters SnapshotCounters() const;
    [[nodiscard]] const std::filesystem::path& SpoolFilePath() const noexcept;
    [[nodiscard]] bool RecoveryRequired() const noexcept;

    [[nodiscard]] static std::filesystem::path ResolveDefaultRoot();

private:
    struct DirtyRange
    {
        std::uint64_t object_id = 0;
        std::uint64_t generation = 0;
        std::uint64_t logical_offset = 0;
        std::uint64_t bytes = 0;
        std::uint64_t spool_offset = 0;
        std::uint64_t wal_sequence = 0;
        std::uint64_t checksum = 0;
        std::chrono::steady_clock::time_point created_at{};
    };

    struct ValidatedPayloadCacheEntry
    {
        DirtyRange range{};
        std::shared_ptr<const std::vector<std::byte>> payload;
        std::uint64_t last_use = 0;
    };

    [[nodiscard]] bool IsVolumeMatch(std::string_view volume_identity) const noexcept;
    [[nodiscard]] bool OpenPayloadReadStream(std::ifstream& input) const;
    [[nodiscard]] std::shared_ptr<PayloadReadHandleState> EnsurePayloadReadHandleLocked() const;
    void ClosePayloadReadHandleLocked() const;
    [[nodiscard]] bool ReadRangePayloadIntoHandle(
        const std::shared_ptr<PayloadReadHandleState>& handle_state,
        const DirtyRange& range,
        std::span<std::byte> payload,
        bool validate_internal_checksum = true) const;
    [[nodiscard]] bool ReadRangePayloadIntoHandleLocked(
        const DirtyRange& range,
        std::span<std::byte> payload,
        bool validate_internal_checksum = true) const;
    [[nodiscard]] bool ReadRangePayloadFromHandleLocked(
        const DirtyRange& range,
        std::vector<std::byte>& payload,
        bool validate_internal_checksum = true) const;
    [[nodiscard]] bool ReadRangePayloadFromStream(
        std::istream& input,
        const DirtyRange& range,
        std::vector<std::byte>& payload,
        bool validate_internal_checksum = true) const;
    [[nodiscard]] bool ReadRangePayload(const DirtyRange& range, std::vector<std::byte>& payload) const;
    [[nodiscard]] std::shared_ptr<const std::vector<std::byte>> FindValidatedPayloadLocked(
        const DirtyRange& range) const;
    void RememberValidatedPayloadLocked(
        const DirtyRange& range,
        std::shared_ptr<const std::vector<std::byte>> payload) const;
    void ClearValidatedPayloadCacheLocked() const noexcept;
    [[nodiscard]] bool OverlayDirtyRangesLocked(
        const ReadRequest& request,
        std::size_t& bytes_overlayed,
        bool require_full_coverage,
        std::uint64_t* logical_end = nullptr) const;
    [[nodiscard]] bool OverlayDirtyRangesMultiRange(
        const ReadRequest& request,
        std::size_t& bytes_overlayed,
        bool require_full_coverage,
        std::uint64_t* logical_end = nullptr,
        std::unique_lock<std::mutex>* existing_lock = nullptr,
        const std::vector<std::size_t>* reused_lookup = nullptr) const;
    [[nodiscard]] bool TryOverlaySingleDirtyRange(
        const ReadRequest& request,
        std::size_t& bytes_overlayed,
        bool require_full_coverage,
        bool& handled,
        std::uint64_t* logical_end = nullptr,
        std::unique_lock<std::mutex>* existing_lock = nullptr,
        const std::vector<std::size_t>** reused_lookup = nullptr) const;
    [[nodiscard]] AppendStatus CheckAppendCapacityLocked(std::uint64_t payload_bytes) const noexcept;
    [[nodiscard]] bool AppendBytes(std::span<const std::byte> payload, std::uint64_t& out_offset);
    [[nodiscard]] bool EnsureAppendStreamLocked();
    [[nodiscard]] bool FlushAppendStreamLocked() const;
    [[nodiscard]] bool CloseAppendStreamLocked();
    [[nodiscard]] bool EnsureIndexJournalStreamLocked();
    [[nodiscard]] bool FlushIndexJournalStreamLocked() const;
    [[nodiscard]] bool CloseIndexJournalStreamLocked();
    [[nodiscard]] bool AppendIndexJournalBytesLocked(std::span<const std::byte> bytes);
    [[nodiscard]] bool FlushPayloadBytesLocked(bool observe_durable_flush);
    [[nodiscard]] bool FlushDirtyStateLocked();
    [[nodiscard]] bool TruncateSpoolFileBestEffort(std::uint64_t size);
    [[nodiscard]] bool PersistIndexLocked();
    [[nodiscard]] bool PersistLegacyIndexLocked() const;
    [[nodiscard]] bool PersistIndexSnapshotFrameLocked(bool replace_file);
    [[nodiscard]] std::vector<std::byte> BuildIndexSnapshotPayloadLocked() const;
    [[nodiscard]] std::vector<std::byte> BuildIndexJournalFrame(
        std::uint32_t frame_type,
        std::span<const std::byte> payload) const;
    [[nodiscard]] bool DecodeIndexSnapshotPayload(
        std::span<const std::byte> payload,
        std::vector<DirtyRange>& loaded,
        std::uint64_t* persisted_spool_size = nullptr) const;
    [[nodiscard]] bool LoadIndexJournal(const std::vector<std::byte>& file_bytes);
    [[nodiscard]] bool LoadIndex();
    [[nodiscard]] bool RewriteLiveRanges(std::vector<DirtyRange>& live_ranges);
    [[nodiscard]] bool ReplaceLiveRangesPreservingOffsets(std::vector<DirtyRange> live_ranges);
    [[nodiscard]] bool RangeIndexPrecedes(std::size_t lhs, std::size_t rhs) const;
    void RebuildRangeSequenceIndex();
    void UpdateMinimumDirtyWalSequence(std::uint64_t wal_sequence);
    void RebuildRangeLookup();
    void RecomputeOldestDirtyRangeLocked();
    [[nodiscard]] std::unique_lock<std::mutex> AcquireMutex() const;
    [[nodiscard]] std::uint64_t MutexWaitPercentileLocked(
        std::uint64_t numerator,
        std::uint64_t denominator) const noexcept;
    [[nodiscard]] Counters SnapshotCountersLocked() const;
    void PublishNextSpoolOffsetHintLocked() noexcept;

    struct DirtyRangeLookupKey
    {
        std::uint64_t object_id = 0;
        std::uint64_t generation = 0;
        std::uint64_t wal_sequence = 0;

        [[nodiscard]] bool operator==(const DirtyRangeLookupKey& other) const noexcept
        {
            return object_id == other.object_id &&
                   generation == other.generation &&
                   wal_sequence == other.wal_sequence;
        }
    };

    struct DirtyRangeLookupKeyHash
    {
        [[nodiscard]] std::size_t operator()(const DirtyRangeLookupKey& key) const noexcept
        {
            auto hash = static_cast<std::size_t>(key.object_id);
            hash ^= static_cast<std::size_t>(key.generation + 0x9e3779b97f4a7c15ull + (hash << 6) + (hash >> 2));
            hash ^= static_cast<std::size_t>(key.wal_sequence + 0x9e3779b97f4a7c15ull + (hash << 6) + (hash >> 2));
            return hash;
        }
    };

    struct DirtyRangeObjectKey
    {
        std::uint64_t object_id = 0;
        std::uint64_t generation = 0;

        [[nodiscard]] bool operator==(const DirtyRangeObjectKey& other) const noexcept
        {
            return object_id == other.object_id &&
                   generation == other.generation;
        }
    };

    struct DirtyRangeObjectKeyHash
    {
        [[nodiscard]] std::size_t operator()(const DirtyRangeObjectKey& key) const noexcept
        {
            auto hash = static_cast<std::size_t>(key.object_id);
            hash ^= static_cast<std::size_t>(key.generation + 0x9e3779b97f4a7c15ull + (hash << 6) + (hash >> 2));
            return hash;
        }
    };

    Options options_;
    bool perf_counters_enabled_ = false;
    std::filesystem::path spool_file_;
    std::filesystem::path index_file_;
    std::vector<DirtyRange> ranges_;
    std::unordered_set<std::uint64_t> range_sequences_;
    std::uint64_t min_dirty_wal_sequence_ = 0;
    bool min_dirty_wal_sequence_tracked_ = false;
    std::unordered_map<DirtyRangeLookupKey, std::vector<std::size_t>, DirtyRangeLookupKeyHash> range_lookup_;
    std::unordered_map<DirtyRangeObjectKey, std::vector<std::size_t>, DirtyRangeObjectKeyHash> range_object_lookup_;
    std::unordered_map<DirtyRangeObjectKey, std::uint64_t, DirtyRangeObjectKeyHash> range_object_max_end_;
    std::unordered_map<DirtyRangeObjectKey, std::uint64_t, DirtyRangeObjectKeyHash> range_object_min_offset_;
    std::uint64_t next_spool_offset_ = 0;
    mutable std::atomic<std::uint64_t> next_spool_offset_hint_{0};
    std::uint64_t bytes_since_sync_ = 0;
    std::uint64_t appends_since_sync_ = 0;
    std::uint64_t append_direct_count_ = 0;
    std::uint64_t append_merged_count_ = 0;
    std::uint64_t append_stream_open_count_ = 0;
    mutable std::uint64_t append_stream_flush_count_ = 0;
    std::uint64_t append_rollback_snapshot_count_ = 0;
    mutable std::uint64_t payload_only_flush_count_ = 0;
    mutable std::uint64_t payload_only_flush_microseconds_ = 0;
    mutable std::uint64_t payload_only_flush_max_microseconds_ = 0;
    mutable std::uint64_t durable_flush_count_ = 0;
    mutable std::uint64_t durable_flush_microseconds_ = 0;
    mutable std::uint64_t durable_flush_max_microseconds_ = 0;
    mutable std::uint64_t spool_sync_count_ = 0;
    mutable std::uint64_t spool_sync_microseconds_ = 0;
    mutable std::uint64_t spool_sync_max_microseconds_ = 0;
    mutable std::uint64_t spool_sync_handle_flush_count_ = 0;
    mutable std::uint64_t spool_sync_reopen_count_ = 0;
    mutable std::uint64_t index_persist_count_ = 0;
    mutable std::uint64_t index_persist_bytes_ = 0;
    mutable std::uint64_t index_persist_microseconds_ = 0;
    mutable std::uint64_t index_persist_max_microseconds_ = 0;
    mutable std::uint64_t index_journal_frame_count_ = 0;
    mutable std::uint64_t index_journal_snapshot_count_ = 0;
    mutable std::uint64_t index_journal_append_count_ = 0;
    mutable std::uint64_t index_journal_handle_open_count_ = 0;
    mutable std::uint64_t index_journal_handle_flush_count_ = 0;
    mutable std::uint64_t range_payload_read_open_count_ = 0;
    mutable std::uint64_t range_payload_positional_read_count_ = 0;
    mutable std::uint64_t range_payload_cache_hit_count_ = 0;
    mutable std::uint64_t range_payload_cache_fill_count_ = 0;
    mutable std::uint64_t overlay_direct_destination_read_count_ = 0;
    mutable std::uint64_t object_lookup_query_count_ = 0;
    mutable std::uint64_t object_lookup_candidate_count_ = 0;
    mutable std::uint64_t object_lookup_index_probe_count_ = 0;
    mutable std::uint64_t cleanup_sequence_probe_count_ = 0;
    static constexpr std::size_t kMutexWaitBucketCount = 32;
    mutable std::uint64_t mutex_wait_count_ = 0;
    mutable std::uint64_t mutex_wait_microseconds_ = 0;
    mutable std::uint64_t mutex_wait_max_microseconds_ = 0;
    mutable std::array<std::uint64_t, kMutexWaitBucketCount> mutex_wait_buckets_{};
    std::chrono::steady_clock::time_point oldest_dirty_range_created_at_{};
    bool oldest_dirty_range_tracked_ = false;
    bool unindexed_payload_recovery_ = false;
    std::uint64_t cleanup_failures_ = 0;
    bool root_ready_ = false;
    bool index_dirty_ = false;
    bool recovery_required_ = false;
    bool index_delta_enabled_ = true;
    bool index_journal_initialized_ = false;
    bool index_requires_snapshot_ = false;
    std::vector<DirtyRange> pending_index_additions_;
    mutable bool append_stream_dirty_ = false;
    mutable void* append_stream_handle_ = nullptr;
    mutable std::shared_ptr<PayloadReadHandleState> payload_read_handle_;
    // Append calls are serialized by mutex_; retain their bounded coalescing
    // scratch so small random writes do not allocate on every callback.
    std::vector<std::size_t> append_merge_indices_scratch_;
    std::vector<std::byte> append_merge_payload_scratch_;
    mutable std::vector<std::byte> overlay_payload_scratch_;
    mutable std::vector<std::pair<std::uint64_t, std::uint64_t>> overlay_covered_ranges_scratch_;
    // Keep ordinary oversized overlay reuse bounded; very large ranges use a
    // call-local fallback so a single file cannot pin unbounded memory.
    mutable std::vector<std::byte> overlay_oversized_payload_scratch_;
    // Cache only checksum-validated dirty payload ranges. The identity fields
    // prevent reuse after coalescing, while the bounded size prevents a large
    // write from turning random reads into unbounded resident memory.
    mutable std::vector<ValidatedPayloadCacheEntry> validated_payload_cache_;
    mutable std::uint64_t validated_payload_cache_use_ = 0;
    mutable std::uint64_t validated_payload_cache_bytes_ = 0;
    mutable void* index_journal_handle_ = nullptr;
    mutable std::uint64_t index_journal_size_ = 0;
    mutable bool index_journal_size_known_ = false;
    mutable std::shared_mutex payload_io_mutex_;
    mutable std::mutex mutex_;
};
} // namespace apfsaccess::rw
