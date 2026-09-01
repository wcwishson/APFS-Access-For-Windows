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
#include <unordered_map>
#include <vector>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>

namespace apfsaccess::rw
{
class BlockDevice
{
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
    [[nodiscard]] Geometry GetGeometry() const;
    [[nodiscard]] bool IsWritable() const;

    [[nodiscard]] bool Read(std::uint64_t offset_bytes, std::size_t size_bytes, std::vector<std::byte>& out_buffer) const;
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
    void BeginReadCacheWriteEpoch();
    void EndReadCacheWriteEpoch();
    void InsertReadCacheEntryLocked(
        std::uint64_t offset_bytes,
        std::size_t size_bytes,
        std::vector<std::byte> bytes) const;

    std::wstring path_;
    std::uint64_t base_offset_bytes_ = 0;
    bool read_cache_enabled_ = false;
    mutable std::atomic<HANDLE> read_handle_{ INVALID_HANDLE_VALUE };
    mutable std::atomic<HANDLE> write_handle_{ INVALID_HANDLE_VALUE };
    mutable std::atomic<bool> writable_{ false };
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
    mutable std::atomic<std::uint64_t> write_scratch_resize_count_{0};
    mutable std::atomic<std::uint64_t> write_scratch_max_bytes_{0};
    mutable std::mutex handle_mutex_;
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
    mutable std::function<void()> write_cache_invalidation_hook_for_tests_;
    mutable std::atomic<bool> write_cache_invalidation_hook_installed_{false};
    mutable std::mutex test_hook_mutex_;
    std::vector<HANDLE> async_event_pool_;
    std::unique_ptr<std::byte[]> merged_batch_scratch_;
    std::size_t merged_batch_scratch_capacity_ = 0;
    mutable std::vector<std::byte> read_scratch_;
    mutable std::vector<std::byte> write_scratch_;
};
} // namespace apfsaccess::rw
