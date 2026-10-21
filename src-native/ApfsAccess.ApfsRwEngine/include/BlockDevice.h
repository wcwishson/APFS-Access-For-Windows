#pragma once

#include <cstddef>
#include <cstdint>
#include <array>
#include <atomic>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>

#include "RawSnapshotBinding.h"

namespace apfsaccess::catalog { class ApfsEncryptedImageWriteSession; }

namespace apfsaccess::rw
{
class BlockDevice
{
    friend class catalog::ApfsEncryptedImageWriteSession;
    // Consumes a duplicated held handle. The owner retains its gate and I/O
    // mutex until this adapter and its synchronous writer have been destroyed.
    [[nodiscard]] static std::shared_ptr<BlockDevice> AdoptSoftwareTransitionImage(
        std::wstring path, HANDLE exclusive_handle, std::uint64_t offset,
        std::uint64_t container_bytes, std::uint64_t carrier_bytes, std::string& error);
public:
    struct Geometry
    {
        std::uint64_t total_bytes = 0;
        std::uint32_t logical_block_size = 4096;
        std::uint32_t physical_block_size = 4096;
    };

    explicit BlockDevice(std::wstring path, std::uint64_t base_offset_bytes = 0);
    ~BlockDevice();

    BlockDevice(const BlockDevice&) = delete;
    BlockDevice& operator=(const BlockDevice&) = delete;
    BlockDevice(BlockDevice&&) = delete;
    BlockDevice& operator=(BlockDevice&&) = delete;

    [[nodiscard]] const std::wstring& Path() const noexcept;
    [[nodiscard]] std::uint64_t BaseOffsetBytes() const noexcept { return base_offset_bytes_; }
    [[nodiscard]] Geometry GetGeometry() const;
    [[nodiscard]] bool IsRegularFile() const;
    [[nodiscard]] bool QueryRegularImageIdentity(std::string& identity) const;
    // Private offline management: share-deny-all, handle-bound regular image.
    // A duplicated handle serves the canonical writer, never a second path open.
    [[nodiscard]] static std::shared_ptr<BlockDevice> OpenExclusiveManagementImage(
        std::wstring path, std::uint64_t offset, std::string& error);
    [[nodiscard]] bool IsWritable() const;
    [[nodiscard]] bool HasWriteHandle() const noexcept;
    [[nodiscard]] static DWORD WriteHandleShareMode(std::wstring_view path) noexcept;
    // Explicit local-image lease. Never opens a writer; denies write/delete
    // sharing until destruction. General BlockDevice opens are unchanged.
    [[nodiscard]] static std::shared_ptr<BlockDevice> OpenStableReadOnlyImage(
        std::wstring path, std::string& error);
    // Command-only sole-owner lease. Takes ownership of an already exclusive,
    // ordinary file handle; duplicates that file object for the canonical writer.
    [[nodiscard]] static std::shared_ptr<BlockDevice> AdoptExclusiveRepairImage(
        std::wstring path, HANDLE handle, std::string& error);
    // Explicit operator admission for one raw APFS store range. Deny-write
    // shared writable open of a whole physical disk, GPT disk GUID plus APFS
    // partition containment binding of [base, base + limit), and a
    // container-range write limit enforced on every write funnel.
    // Default-closed everywhere; test overrides never enable this path. Limit
    // must be nonzero and 4KiB-aligned.
    [[nodiscard]] bool AdmitExclusiveRawWriter(std::uint64_t limit_bytes, std::string& error);
    [[nodiscard]] bool IsRawWriterAccepted() const noexcept;
    [[nodiscard]] std::uint64_t RawWriteLimitBytes() const noexcept;
    [[nodiscard]] const std::string& RawWriterIdentity() const noexcept;
    // For an admitted physical-disk writer, perform a bounded fresh-handle
    // media/device check. Regular image-backed devices return true without
    // opening another handle. A failed probe invalidates the current raw
    // handles so a stale PnP handle cannot continue accepting writes.
    [[nodiscard]] bool ProbeUnderlyingDevice(bool force = false) const;
    [[nodiscard]] static bool IsDeviceUnavailableError(std::uint32_t error) noexcept;
    // Pure range predicate (unit-testable): store-relative span within limit.
    [[nodiscard]] static bool RawWriteRangeAllowed(
        std::uint64_t limit_bytes, std::uint64_t offset_bytes, std::uint64_t size_bytes) noexcept;
    [[nodiscard]] bool RevalidateStableReadOnlyImage() const;
    struct StableImageIdentity
    {
        std::uint64_t volume_serial = 0;
        std::array<std::byte, 16> file_id{};
        std::uint64_t size_bytes = 0;
        std::uint64_t creation_time = 0;
        std::uint64_t write_time = 0;
        bool operator==(const StableImageIdentity&) const = default;
    };
    // Identity of the already-held read-only lease; never opens another handle.
    [[nodiscard]] bool QueryStableReadOnlyImageIdentity(StableImageIdentity& out) const;
    // Observes an already-held ordinary image handle; never opens a path.
    [[nodiscard]] bool QueryHeldImageIdentity(StableImageIdentity& out) const;

    class WriteSourceObservation
    {
    public:
        WriteSourceObservation() = default;
        WriteSourceObservation(const WriteSourceObservation&) = default;
        WriteSourceObservation& operator=(const WriteSourceObservation&) = default;
        bool operator==(const WriteSourceObservation&) const = default;

    private:
        friend class BlockDevice;

        const BlockDevice* device_ = nullptr;
        std::shared_ptr<const std::byte> lifetime_;
        HANDLE read_handle_ = INVALID_HANDLE_VALUE;
        HANDLE write_handle_ = INVALID_HANDLE_VALUE;
        std::uint64_t generation_ = 0;
        std::uint64_t base_offset_bytes_ = 0;
        std::uint64_t limit_bytes_ = 0;
        std::array<char, 256> raw_identity_{};
        std::size_t raw_identity_size_ = 0;
        StableImageIdentity image_identity_{};
    };
    // Only accepted raw writers or verified exclusive image leases qualify.
    // These observations neither open handles nor reserve against future writes.
    [[nodiscard]] std::optional<WriteSourceObservation> CaptureExclusiveWriteSourceObservation() const;
    [[nodiscard]] bool IsExclusiveWriteSourceObservationCurrent(const WriteSourceObservation& observation) const;

    class RawSnapshotLease
    {
    public:
        RawSnapshotLease() = default;
        bool operator==(const RawSnapshotLease&) const = default;

    private:
        friend class BlockDevice;
        const BlockDevice* device_ = nullptr;
        std::shared_ptr<const std::byte> lifetime_;
        HANDLE read_handle_ = INVALID_HANDLE_VALUE;
        HANDLE write_handle_ = INVALID_HANDLE_VALUE;
        std::uint64_t retirement_epoch_ = 0;
        std::uint64_t base_offset_bytes_ = 0, limit_bytes_ = 0;
    };
    // Cached continuity of the original admitted raw handle pair. No I/O,
    // reopening or write reservation; ordinary writes preserve this token.
    [[nodiscard]] std::optional<RawSnapshotLease> CaptureHeldRawSnapshotLease() const;
    [[nodiscard]] bool IsHeldRawSnapshotLeaseCurrent(const RawSnapshotLease& lease) const;
    // Bounded metadata queries on the original held reader, once per lifetime.
    // Success and refusal are cached. Qualification never enables mutation.
    [[nodiscard]] bool QueryHeldRawSnapshotDescriptors(
        const RawSnapshotLease& lease, RawSnapshotDescriptors& out, std::string& error) const;
    [[nodiscard]] bool QueryHeldRawSnapshotBinding(
        const RawSnapshotLease& lease, const RawHardwareQualification& qualification,
        RawSnapshotBinding& out, std::string& error) const;

    [[nodiscard]] bool Read(std::uint64_t offset_bytes, std::size_t size_bytes, std::vector<std::byte>& out_buffer) const;
    // Exact block-aligned reread on an already-held reader after caller flush.
    // Alignment is within a buffered image window, absolute for raw devices.
    // Bypasses only this object's read cache, not OS or hardware caches.
    [[nodiscard]] bool ReadForVerification(
        std::uint64_t offset_bytes, std::size_t size_bytes, std::vector<std::byte>& out_buffer) const;
    [[nodiscard]] bool ReadInto(
        std::uint64_t offset_bytes,
        std::byte* destination,
        std::size_t destination_size,
        std::size_t& bytes_read) const;
    void SetReadCacheMissHookForTests(std::function<void()> hook);
    void SetWriteCacheInvalidationHookForTests(std::function<void()> hook);
    [[nodiscard]] bool Write(std::uint64_t offset_bytes, std::span<const std::byte> buffer);
    [[nodiscard]] bool Write(std::uint64_t offset_bytes, const std::vector<std::byte>& buffer);
    struct WriteSpan
    {
        std::uint64_t offset_bytes = 0;
        std::span<const std::byte> buffer{};
        const void* merge_token = nullptr;
    };
    [[nodiscard]] bool WriteBatch(std::span<const WriteSpan> writes);
    [[nodiscard]] bool Flush();
    [[nodiscard]] std::string PerformanceJson() const;
    [[nodiscard]] std::uint32_t LastIoError() const noexcept
    {
        return last_io_error_.load(std::memory_order_relaxed);
    }

private:
    friend class VolumePhysicalSource;
    [[nodiscard]] bool AdmitExclusiveRawWriterImpl(std::uint64_t limit_bytes, std::string& error,
        bool qualified_interface);
    // Definition exists only in the persistence test TU, as with the engine's
    // other friend test accessors. No shipping factory or admission override.
    friend struct BlockDeviceRawSnapshotTestPeer;
    struct PerfCounter
    {
        static constexpr std::size_t kLatencyBucketCount = 32;

        std::atomic<std::uint64_t> count{0};
        std::atomic<std::uint64_t> bytes{0};
        std::atomic<std::uint64_t> total_us{0};
        std::atomic<std::uint64_t> max_us{0};
        std::atomic<std::uint64_t> last_us{0};
        std::array<std::atomic<std::uint64_t>, kLatencyBucketCount> latency_buckets{};

        void Observe(std::uint64_t elapsed_us, std::uint64_t byte_count = 0) noexcept;
        [[nodiscard]] std::uint64_t ApproxP50Us() const noexcept;
        [[nodiscard]] std::uint64_t ApproxP95Us() const noexcept;

    private:
        [[nodiscard]] std::uint64_t ApproxPercentileUs(
            std::uint64_t numerator,
            std::uint64_t denominator) const noexcept;
    };
    struct ScopedPerfTimer;
    struct WriteSourceAdmission;
    struct ReadCacheWriteAdmission;
    struct ReadCacheWriteEpoch;

    [[nodiscard]] HANDLE EnsureReadHandle() const;
    [[nodiscard]] HANDLE EnsureWriteHandle() const;
    void CloseHandlesLocked() const;
    [[nodiscard]] bool QueryGeometryLocked(HANDLE handle, Geometry& geometry) const;
    [[nodiscard]] std::uint32_t LogicalBlockSize() const;
    [[nodiscard]] bool ReadAt(HANDLE handle, std::uint64_t offset_bytes, void* buffer, DWORD bytes_to_read, DWORD& bytes_read) const;
    [[nodiscard]] bool WriteAt(HANDLE handle, std::uint64_t offset_bytes, const void* buffer, DWORD bytes_to_write, DWORD& bytes_written) const;
    [[nodiscard]] bool WriteLocked(
        HANDLE handle,
        std::uint64_t absolute_offset_bytes,
        std::span<const std::byte> buffer,
        const std::optional<std::wstring>& fault_mode,
        bool& out_was_unaligned);
    // Absolute-span containment inside the admitted raw range. Always true
    // unless raw-writer admission installed a limit.
    [[nodiscard]] bool RawWriteSpanAllowed(
        std::uint64_t absolute_offset_bytes, std::uint64_t size_bytes) const noexcept;
    [[nodiscard]] bool WaitForOverlappedCompletion(
        HANDLE handle,
        OVERLAPPED& overlapped,
        DWORD& transferred,
        DWORD& completion_error) const;
    [[nodiscard]] bool EnsureAsyncEventPool(std::size_t count);
    [[nodiscard]] bool EnsureMergedBatchScratch(std::size_t bytes, std::size_t preserve_bytes = 0);
    void CloseAsyncEventPoolLocked();
    void InvokeWriteCacheInvalidationHookForTests();
    void BeginReadCacheWriteAdmission();
    void EndReadCacheWriteAdmission() noexcept;
    void BeginWriteSourceAdmission();
    void EndWriteSourceAdmission() noexcept;
    void AdvanceWriteSourceGenerationLocked() const noexcept;
    void InvalidateWriteSourceHandlesLocked() const;
    void RetireRawSnapshotLeaseLocked() const noexcept;
    [[nodiscard]] bool IsHeldRawSnapshotLeaseCurrentLocked(const RawSnapshotLease& lease) const;
    [[nodiscard]] bool RawSnapshotIoctl(
        HANDLE handle, DWORD code, void* input, DWORD input_bytes,
        void* output, DWORD output_bytes, DWORD& returned, DWORD& error) const;
    [[nodiscard]] bool QueryRawSnapshotProperty(
        HANDLE handle, STORAGE_PROPERTY_ID property, std::vector<std::byte>& out, DWORD& error) const;
    void BeginReadCacheWriteEpoch();
    void BeginReadCacheWriteEpoch(std::span<const WriteSpan> writes);
    [[nodiscard]] bool InvalidateReadCacheRangeLocked(
        std::uint64_t absolute_offset_bytes, std::uint64_t size_bytes) const;
    void InvalidateReadCache() const;
    void EndReadCacheWriteEpoch();
    void InsertReadCacheEntryLocked(
        std::uint64_t offset_bytes,
        std::size_t size_bytes,
        std::vector<std::byte> bytes) const;

    std::wstring path_;
    std::uint64_t base_offset_bytes_ = 0;
    bool read_cache_enabled_ = false;
    std::size_t read_cache_max_entries_ = 256;
    mutable std::atomic<HANDLE> read_handle_{ INVALID_HANDLE_VALUE };
    mutable std::atomic<HANDLE> write_handle_{ INVALID_HANDLE_VALUE };
    mutable std::atomic<bool> regular_file_{ false };
    mutable std::atomic<bool> writable_{ false };
    mutable std::atomic<bool> raw_writer_accepted_{ false };
    mutable std::atomic<std::uint64_t> raw_write_limit_bytes_{ 0 };
    std::string raw_writer_identity_;
    mutable bool geometry_cached_ = false;
    mutable Geometry geometry_cache_{};
    mutable std::atomic<std::uint32_t> logical_block_size_cache_{ 0 };
    mutable PerfCounter read_perf_;
    mutable PerfCounter raw_read_perf_;
    mutable PerfCounter write_perf_;
    mutable PerfCounter unaligned_write_perf_;
    mutable PerfCounter batch_write_perf_;
    mutable PerfCounter merged_batch_write_perf_;
    mutable PerfCounter rmw_group_write_perf_;
    mutable PerfCounter contiguous_batch_write_perf_;
    mutable PerfCounter async_batch_write_perf_;
    mutable PerfCounter flush_perf_;
    mutable PerfCounter write_queue_wait_perf_;
    mutable PerfCounter flush_queue_wait_perf_;
    mutable std::atomic<std::uint64_t> batch_sort_count_{0};
    mutable std::atomic<std::uint32_t> last_io_error_{0};
    mutable std::mutex raw_presence_probe_mutex_;
    struct RawPresenceIdentity;
    std::unique_ptr<const RawPresenceIdentity> raw_presence_identity_;
    mutable std::atomic<std::uint64_t> raw_presence_probe_tick_ms_{0};
    mutable std::atomic<bool> raw_presence_probe_result_{true};
    mutable std::atomic<std::uint32_t> raw_presence_probe_error_{ERROR_SUCCESS};
    mutable std::atomic<std::uint64_t> async_max_queue_depth_{0};
    mutable std::atomic<std::uint64_t> async_event_create_count_{0};
    mutable std::atomic<std::uint64_t> async_event_pool_max_depth_{0};
    mutable std::atomic<std::uint64_t> async_wait_timeout_count_{0};
    mutable std::atomic<std::uint64_t> async_cancel_count_{0};
    mutable std::atomic<std::uint64_t> async_cancel_wait_timeout_count_{0};
    mutable std::atomic<std::uint64_t> merged_batch_direct_fill_count_{0};
    mutable std::atomic<std::uint64_t> merged_batch_direct_fill_bytes_{0};
    mutable std::atomic<std::uint64_t> merged_batch_scratch_resize_count_{0};
    mutable std::atomic<std::uint64_t> merged_batch_scratch_max_bytes_{0};
    mutable std::atomic<std::uint64_t> async_request_stack_window_count_{0};
    mutable std::atomic<std::uint64_t> async_direct_adjacent_span_count_{0};
    mutable std::atomic<std::uint64_t> async_direct_adjacent_span_bytes_{0};
    mutable std::atomic<std::uint64_t> read_scratch_resize_count_{0};
    mutable std::atomic<std::uint64_t> read_scratch_max_bytes_{0};
    mutable std::atomic<std::uint64_t> read_thread_local_scratch_use_count_{0};
    mutable std::atomic<std::uint64_t> read_cache_hit_count_{0};
    mutable std::atomic<std::uint64_t> read_cache_contained_hit_count_{0};
    mutable std::atomic<std::uint64_t> read_cache_miss_count_{0};
    mutable std::atomic<std::uint64_t> read_cache_invalidation_count_{0};
    mutable std::atomic<std::uint64_t> read_cache_bytes_{0};
    mutable std::atomic<std::uint64_t> read_cache_eviction_count_{0};
    mutable std::atomic<std::uint64_t> read_cache_evicted_bytes_{0};
    mutable std::atomic<std::uint64_t> write_scratch_resize_count_{0};
    mutable std::atomic<std::uint64_t> write_scratch_max_bytes_{0};
    mutable std::mutex handle_mutex_;
    // Leaf lock: handle_mutex_ may precede it; it never precedes cache/write locks.
    mutable std::mutex write_source_mutex_;
    const std::shared_ptr<const std::byte> write_source_lifetime_ =
        std::make_shared<const std::byte>(std::byte{0});
    mutable std::uint64_t write_source_generation_ = 0;
    mutable std::uint64_t write_source_admissions_ = 0;
    mutable bool write_source_generation_exhausted_ = false;
    mutable bool write_source_handles_retired_ = false;
    mutable std::uint64_t raw_snapshot_retirement_epoch_ = 0;
    mutable bool raw_snapshot_epoch_exhausted_ = false;
    mutable bool raw_snapshot_lease_retired_ = true;
    mutable bool raw_snapshot_descriptors_attempted_ = false;
    mutable bool raw_snapshot_descriptors_complete_ = false;
    mutable RawSnapshotDescriptors raw_snapshot_descriptors_;
    mutable std::string raw_snapshot_descriptors_error_;
    mutable bool exclusive_write_image_ = false;
    FILE_ID_INFO exclusive_write_image_identity_{};
    std::uint64_t exclusive_write_image_size_bytes_ = 0;
    std::uint64_t raw_write_source_size_bytes_ = 0;
    mutable std::mutex geometry_mutex_;
    mutable std::mutex write_epoch_mutex_;
    mutable std::mutex write_mutex_;
    mutable std::mutex read_scratch_mutex_;
    struct ReadCacheKey
    {
        std::uint64_t offset_bytes = 0;
        std::size_t size_bytes = 0;

        friend bool operator==(const ReadCacheKey& left, const ReadCacheKey& right) noexcept
        {
            return left.offset_bytes == right.offset_bytes &&
                   left.size_bytes == right.size_bytes;
        }
    };
    struct ReadCacheKeyHash
    {
        std::size_t operator()(const ReadCacheKey& key) const noexcept
        {
            auto hash = std::hash<std::uint64_t>{}(key.offset_bytes);
            hash ^= std::hash<std::size_t>{}(key.size_bytes) +
                static_cast<std::size_t>(0x9e3779b97f4a7c15ull) +
                (hash << 6) + (hash >> 2);
            return hash;
        }
    };
    struct ReadCacheEntry
    {
        std::vector<std::byte> bytes;
        std::uint64_t last_use = 0;
    };
    mutable std::mutex read_cache_mutex_;
    mutable std::unordered_map<ReadCacheKey, ReadCacheEntry, ReadCacheKeyHash> read_cache_;
    mutable std::uint64_t read_cache_use_ = 0;
    mutable std::uint64_t read_cache_generation_ = 0;
    mutable std::uint64_t read_cache_write_admissions_ = 0;
    mutable std::function<void()> read_cache_miss_hook_for_tests_;
    // Only the loopback test peer installs this; real transports use Win32 IOCTLs.
    mutable std::function<bool(DWORD&)> raw_presence_probe_hook_for_tests_;
    mutable std::function<void()> write_cache_invalidation_hook_for_tests_;
    mutable std::atomic<bool> write_cache_invalidation_hook_installed_{false};
    mutable std::mutex test_hook_mutex_;
    std::vector<HANDLE> async_event_pool_;
    std::unique_ptr<std::byte[]> merged_batch_scratch_;
    std::size_t merged_batch_scratch_capacity_ = 0;
    mutable std::vector<std::byte> read_scratch_;
    mutable std::vector<std::byte> write_scratch_;
    bool stable_read_only_image_ = false;
    FILE_ID_INFO stable_image_identity_{};
};
} // namespace apfsaccess::rw
