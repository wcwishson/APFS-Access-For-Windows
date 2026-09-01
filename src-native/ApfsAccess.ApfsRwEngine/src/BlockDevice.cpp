#include "BlockDevice.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdlib>
#include <cwchar>
#include <filesystem>
#include <limits>
#include <memory>
#include <memory_resource>
#include <optional>
#include <span>
#include <sstream>
#include <string_view>
#include <utility>

#include <winioctl.h>

namespace apfsaccess::rw
{
namespace
{
constexpr std::uint64_t kMaxMergedBatchBytes = 1024ull * 1024ull;
constexpr std::uint64_t kMaxDirectAsyncChunkBytes = 2ull * 1024ull * 1024ull;
constexpr std::uint64_t kMinAsyncSingleWriteBytes = 4ull * 1024ull * 1024ull;
constexpr std::uint64_t kMinAsyncDirectAdjacentSpanBytes = 64ull * 1024ull;
constexpr std::uint64_t kMaxRmwGroupBytes = 64ull * 1024ull;
constexpr std::uint64_t kMaxRmwGroupGapBytes = 16ull * 1024ull;
constexpr std::size_t kMaxRmwGroupWrites = 8;
constexpr std::size_t kDefaultAsyncBlockIoQueueDepth = 4;
constexpr std::size_t kMaxAsyncBlockIoQueueDepth = 16;
constexpr DWORD kOverlappedIoWaitTimeoutMs = 30'000;
constexpr DWORD kOverlappedIoCancelWaitTimeoutMs = 5'000;
constexpr DWORD kOverlappedIoFinalWaitTimeoutMs = 5'000;
constexpr UINT kUncancelableIoExitCode = 0xE1;
constexpr std::size_t kReadCacheMaxWindowBytes = 64 * 1024;
constexpr std::size_t kReadCacheMaxBytes = 8 * 1024 * 1024;
constexpr std::size_t kReadCacheMaxEntries = 256;
constexpr std::size_t kReadThreadLocalScratchMaxBytes = 1024 * 1024;

struct ThreadLocalOverlappedEvent
{
    ~ThreadLocalOverlappedEvent()
    {
        if (handle != nullptr)
        {
            (void)CloseHandle(handle);
        }
    }

    HANDLE Ensure()
    {
        if (handle == nullptr)
        {
            handle = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        }
        return handle;
    }

    HANDLE handle = nullptr;
};

ThreadLocalOverlappedEvent& CurrentBlockIoEvent()
{
    static thread_local ThreadLocalOverlappedEvent event;
    return event;
}

std::optional<std::wstring> ReadEnvironmentValue(const wchar_t* variable_name)
{
    if (variable_name == nullptr || *variable_name == L'\0')
    {
        return std::nullopt;
    }

    constexpr DWORD kStackBufferChars = 256;
    wchar_t stack_value[kStackBufferChars] = {};
    DWORD copied = GetEnvironmentVariableW(variable_name, stack_value, kStackBufferChars);
    if (copied == 0)
    {
        return std::nullopt;
    }

    if (copied < kStackBufferChars)
    {
        return std::wstring(stack_value, stack_value + copied);
    }

    std::wstring value;
    value.resize(copied);
    copied = GetEnvironmentVariableW(variable_name, value.data(), static_cast<DWORD>(value.size()));
    if (copied == 0 || copied >= value.size())
    {
        return std::nullopt;
    }

    value.resize(copied);
    return value;
}

[[noreturn]] void FailClosedForUncancelableIo() noexcept
{
    // Returning while the kernel still owns an overlapped caller buffer would
    // be a use-after-free risk. Terminating the FsHost is the bounded safety
    // boundary; its existing recovery marker/checkpoint protocol treats this
    // exactly like an interrupted physical I/O operation.
    OutputDebugStringW(L"[ApfsAccess] overlapped I/O could not be cancelled before its safety deadline.\n");
    if (!TerminateProcess(GetCurrentProcess(), kUncancelableIoExitCode))
    {
        ExitProcess(kUncancelableIoExitCode);
    }
    std::abort();
}

void TrimLeadingWhitespace(std::wstring& value)
{
    const auto first_non_whitespace = value.find_first_not_of(L" \t");
    if (first_non_whitespace == std::wstring::npos)
    {
        value.clear();
        return;
    }
    if (first_non_whitespace > 0)
    {
        value.erase(0, first_non_whitespace);
    }
}

bool IsFaultSwitchEnabled(const wchar_t* variable_name)
{
    auto value = ReadEnvironmentValue(variable_name);
    if (!value.has_value())
    {
        return false;
    }

    TrimLeadingWhitespace(*value);
    return !value->empty() &&
           _wcsicmp(value->c_str(), L"1") == 0 ||
           _wcsicmp(value->c_str(), L"true") == 0 ||
           _wcsicmp(value->c_str(), L"yes") == 0;
}

std::optional<std::wstring> ReadFaultMode(const wchar_t* variable_name)
{
    auto value = ReadEnvironmentValue(variable_name);
    if (!value.has_value())
    {
        return std::nullopt;
    }

    TrimLeadingWhitespace(*value);
    if (value->empty() ||
        _wcsicmp(value->c_str(), L"0") == 0 ||
        _wcsicmp(value->c_str(), L"false") == 0 ||
        _wcsicmp(value->c_str(), L"no") == 0)
    {
        return std::nullopt;
    }

    return value;
}

bool IsFaultMode(std::wstring_view actual, const wchar_t* expected)
{
    if (expected == nullptr)
    {
        return false;
    }

    const auto expected_length = std::wcslen(expected);
    return actual.size() == expected_length &&
           _wcsnicmp(actual.data(), expected, expected_length) == 0;
}

bool IsPerfCountersEnabled()
{
    static const bool enabled = []()
    {
        std::error_code ec;
        auto marker = std::filesystem::temp_directory_path(ec);
        if (!ec)
        {
            marker /= "ApfsAccess";
            marker /= "perf-counters.enabled";
            if (std::filesystem::exists(marker, ec) && !ec)
            {
                return true;
            }
        }

        wchar_t* raw_value = nullptr;
        std::size_t raw_length = 0;
        if (_wdupenv_s(&raw_value, &raw_length, L"APFSACCESS_PERF_COUNTERS") == 0 && raw_value != nullptr)
        {
            std::unique_ptr<wchar_t, decltype(&std::free)> guard(raw_value, &std::free);
            const auto* value = raw_value;
            while (*value == L' ' || *value == L'\t')
            {
                ++value;
            }

            return *value != L'\0' &&
                   _wcsicmp(value, L"0") != 0 &&
                   _wcsicmp(value, L"false") != 0 &&
                   _wcsicmp(value, L"no") != 0;
        }

        return false;
    }();
    return enabled;
}

std::size_t ReadPositiveSizeEnv(const wchar_t* variable_name, std::size_t fallback, std::size_t maximum)
{
    if (variable_name == nullptr || *variable_name == L'\0')
    {
        return fallback;
    }

    wchar_t* raw_value = nullptr;
    std::size_t raw_length = 0;
    if (_wdupenv_s(&raw_value, &raw_length, variable_name) != 0 || raw_value == nullptr)
    {
        return fallback;
    }
    std::unique_ptr<wchar_t, decltype(&std::free)> guard(raw_value, &std::free);
    wchar_t* end = nullptr;
    const auto parsed = std::wcstoull(raw_value, &end, 10);
    if (end == raw_value || parsed == 0)
    {
        return fallback;
    }

    return static_cast<std::size_t>(std::min<std::uint64_t>(parsed, maximum));
}

std::optional<std::size_t> ReadOptionalPositiveSizeEnv(
    const wchar_t* variable_name,
    std::size_t maximum)
{
    auto value = ReadEnvironmentValue(variable_name);
    if (!value.has_value())
    {
        return std::nullopt;
    }

    TrimLeadingWhitespace(*value);
    wchar_t* end = nullptr;
    const auto parsed = std::wcstoull(value->c_str(), &end, 10);
    if (end == value->c_str() || parsed == 0)
    {
        return std::nullopt;
    }

    return static_cast<std::size_t>(std::min<std::uint64_t>(parsed, maximum));
}

bool IsAsyncBlockIoEnabled()
{
    return !IsFaultSwitchEnabled(L"APFSACCESS_DISABLE_ASYNC_BLOCK_IO");
}

bool IsExperimentalBlockReadCacheEnabled()
{
    return IsFaultSwitchEnabled(L"APFSACCESS_EXPERIMENTAL_BLOCK_READ_CACHE");
}

std::size_t AsyncBlockIoQueueDepth()
{
    static const std::size_t depth = ReadPositiveSizeEnv(
        L"APFSACCESS_ASYNC_BLOCK_IO_DEPTH",
        kDefaultAsyncBlockIoQueueDepth,
        kMaxAsyncBlockIoQueueDepth);
    return std::max<std::size_t>(1, depth);
}

std::uint64_t ElapsedMicroseconds(std::chrono::steady_clock::time_point started)
{
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - started).count());
}

std::uint64_t AlignDown(std::uint64_t value, std::uint64_t alignment)
{
    if (alignment == 0)
    {
        return value;
    }

    return value - (value % alignment);
}

std::uint64_t AlignUp(std::uint64_t value, std::uint64_t alignment)
{
    if (alignment == 0)
    {
        return value;
    }
    if (value == 0)
    {
        return 0;
    }
    if (value > (std::numeric_limits<std::uint64_t>::max() - (alignment - 1)))
    {
        return 0;
    }

    return AlignDown(value + alignment - 1, alignment);
}

bool AddOffsetToPointer(const std::byte* base, std::uint64_t offset, const std::byte*& result)
{
    if (offset > static_cast<std::uint64_t>((std::numeric_limits<std::ptrdiff_t>::max)()))
    {
        return false;
    }

    result = base + static_cast<std::ptrdiff_t>(offset);
    return true;
}

void UpdateAtomicMax(std::atomic<std::uint64_t>& target, std::uint64_t value) noexcept
{
    auto current = target.load(std::memory_order_relaxed);
    while (value > current &&
           !target.compare_exchange_weak(current, value, std::memory_order_relaxed))
    {
    }
}

std::size_t LatencyBucketIndex(std::uint64_t elapsed_us, std::size_t bucket_count) noexcept
{
    if (elapsed_us == 0 || bucket_count == 0)
    {
        return 0;
    }

    std::size_t index = 1;
    std::uint64_t upper_bound = 1;
    while (elapsed_us > upper_bound && index + 1 < bucket_count)
    {
        ++index;
        if (upper_bound > (std::numeric_limits<std::uint64_t>::max() / 2))
        {
            return index;
        }
        upper_bound *= 2;
    }
    return index;
}

std::uint64_t LatencyBucketUpperBoundUs(
    std::size_t index,
    std::size_t bucket_count,
    std::uint64_t max_observed_us) noexcept
{
    if (index == 0)
    {
        return 0;
    }
    if (index + 1 >= bucket_count)
    {
        return max_observed_us;
    }
    return std::min<std::uint64_t>(1ull << (index - 1), max_observed_us);
}
} // namespace

BlockDevice::BlockDevice(std::wstring path, std::uint64_t base_offset_bytes)
    : path_(std::move(path))
    , base_offset_bytes_(base_offset_bytes)
    , read_cache_enabled_(IsExperimentalBlockReadCacheEnabled())
{
}

struct BlockDevice::ScopedPerfTimer
{
    PerfCounter& primary;
    PerfCounter* secondary = nullptr;
    std::chrono::steady_clock::time_point started{};
    std::uint64_t byte_count = 0;
    bool enabled = false;
    bool observe_secondary = false;

    ScopedPerfTimer(PerfCounter& primary_counter, std::uint64_t bytes = 0) noexcept
        : primary(primary_counter)
        , byte_count(bytes)
        , enabled(IsPerfCountersEnabled())
    {
        if (enabled)
        {
            started = std::chrono::steady_clock::now();
        }
    }

    void SetSecondary(PerfCounter& secondary_counter) noexcept
    {
        secondary = &secondary_counter;
    }

    void MarkSecondary() noexcept
    {
        observe_secondary = true;
    }

    ~ScopedPerfTimer()
    {
        if (!enabled)
        {
            return;
        }

        const auto elapsed_us = ElapsedMicroseconds(started);
        primary.Observe(elapsed_us, byte_count);
        if (observe_secondary && secondary)
        {
            secondary->Observe(elapsed_us, byte_count);
        }
    }
};

struct BlockDevice::ReadCacheWriteEpoch
{
    explicit ReadCacheWriteEpoch(BlockDevice& owner)
        : owner_(owner)
        , epoch_lock_(owner.write_epoch_mutex_)
    {
        owner_.BeginReadCacheWriteEpoch();
    }

    ~ReadCacheWriteEpoch() noexcept
    {
        owner_.EndReadCacheWriteEpoch();
    }

    ReadCacheWriteEpoch(const ReadCacheWriteEpoch&) = delete;
    ReadCacheWriteEpoch& operator=(const ReadCacheWriteEpoch&) = delete;

private:
    BlockDevice& owner_;
    std::unique_lock<std::mutex> epoch_lock_;
};

struct BlockDevice::ReadCacheWriteAdmission
{
    explicit ReadCacheWriteAdmission(BlockDevice& owner)
        : owner_(owner)
    {
        owner_.BeginReadCacheWriteAdmission();
    }

    ~ReadCacheWriteAdmission() noexcept
    {
        owner_.EndReadCacheWriteAdmission();
    }

    ReadCacheWriteAdmission(const ReadCacheWriteAdmission&) = delete;
    ReadCacheWriteAdmission& operator=(const ReadCacheWriteAdmission&) = delete;

private:
    BlockDevice& owner_;
};

void BlockDevice::PerfCounter::Observe(std::uint64_t elapsed_us, std::uint64_t byte_count) noexcept
{
    UpdateAtomicMax(max_us, elapsed_us);

    const auto bucket_index = LatencyBucketIndex(elapsed_us, latency_buckets.size());
    latency_buckets[bucket_index].fetch_add(1, std::memory_order_relaxed);
    count.fetch_add(1, std::memory_order_relaxed);
    bytes.fetch_add(byte_count, std::memory_order_relaxed);
    total_us.fetch_add(elapsed_us, std::memory_order_relaxed);
    last_us.store(elapsed_us, std::memory_order_relaxed);
}

std::uint64_t BlockDevice::PerfCounter::ApproxP50Us() const noexcept
{
    return ApproxPercentileUs(1, 2);
}

std::uint64_t BlockDevice::PerfCounter::ApproxP95Us() const noexcept
{
    return ApproxPercentileUs(95, 100);
}

std::uint64_t BlockDevice::PerfCounter::ApproxPercentileUs(
    std::uint64_t numerator,
    std::uint64_t denominator) const noexcept
{
    std::uint64_t total = 0;
    std::array<std::uint64_t, kLatencyBucketCount> snapshot{};
    for (std::size_t index = 0; index < latency_buckets.size(); ++index)
    {
        snapshot[index] = latency_buckets[index].load(std::memory_order_relaxed);
        total += snapshot[index];
    }
    if (total == 0)
    {
        return 0;
    }

    const auto whole = total / denominator;
    const auto remainder = total % denominator;
    const auto target_rank =
        (whole * numerator) +
        ((remainder * numerator + denominator - 1) / denominator);
    std::uint64_t cumulative = 0;
    const auto max_observed_us = max_us.load(std::memory_order_relaxed);
    for (std::size_t index = 0; index < snapshot.size(); ++index)
    {
        cumulative += snapshot[index];
        if (cumulative >= target_rank)
        {
            return LatencyBucketUpperBoundUs(index, snapshot.size(), max_observed_us);
        }
    }
    return max_observed_us;
}

std::string BlockDevice::PerformanceJson() const
{
    const auto append_counter = [](std::ostringstream& buffer, const char* name, const PerfCounter& counter)
    {
        const auto count = counter.count.load(std::memory_order_relaxed);
        const auto bytes = counter.bytes.load(std::memory_order_relaxed);
        const auto total_us = counter.total_us.load(std::memory_order_relaxed);
        const auto max_us = counter.max_us.load(std::memory_order_relaxed);
        const auto last_us = counter.last_us.load(std::memory_order_relaxed);
        const auto p50_us = counter.ApproxP50Us();
        const auto p95_us = counter.ApproxP95Us();
        buffer << "\"" << name << "\":{\"count\":" << count
               << ",\"bytes\":" << bytes
               << ",\"totalUs\":" << total_us
               << ",\"maxUs\":" << max_us
               << ",\"lastUs\":" << last_us
               << ",\"p50Us\":" << p50_us
               << ",\"p95Us\":" << p95_us
               << "}";
    };

    std::ostringstream buffer;
    buffer << "{";
    append_counter(buffer, "read", read_perf_);
    buffer << ",";
    append_counter(buffer, "rawRead", raw_read_perf_);
    buffer << ",";
    append_counter(buffer, "write", write_perf_);
    buffer << ",";
    append_counter(buffer, "unalignedWrite", unaligned_write_perf_);
    buffer << ",";
    append_counter(buffer, "batchWrite", batch_write_perf_);
    buffer << ",";
    append_counter(buffer, "mergedBatchWrite", merged_batch_write_perf_);
    buffer << ",";
    append_counter(buffer, "rmwGroupWrite", rmw_group_write_perf_);
    buffer << ",";
    append_counter(buffer, "contiguousBatchWrite", contiguous_batch_write_perf_);
    buffer << ",";
    append_counter(buffer, "asyncBatchWrite", async_batch_write_perf_);
    buffer << ",";
    append_counter(buffer, "flush", flush_perf_);
    buffer << ",";
    append_counter(buffer, "writeQueueWait", write_queue_wait_perf_);
    buffer << ",";
    append_counter(buffer, "flushQueueWait", flush_queue_wait_perf_);
    buffer << ",\"asyncMaxQueueDepth\":"
           << async_max_queue_depth_.load(std::memory_order_relaxed)
           << ",\"asyncEventCreateCount\":"
           << async_event_create_count_.load(std::memory_order_relaxed)
           << ",\"asyncEventPoolMaxDepth\":"
           << async_event_pool_max_depth_.load(std::memory_order_relaxed)
           << ",\"asyncWaitTimeoutCount\":"
           << async_wait_timeout_count_.load(std::memory_order_relaxed)
           << ",\"asyncCancelCount\":"
           << async_cancel_count_.load(std::memory_order_relaxed)
           << ",\"asyncCancelWaitTimeoutCount\":"
           << async_cancel_wait_timeout_count_.load(std::memory_order_relaxed)
           << ",\"mergedBatchDirectFill\":{\"count\":"
           << merged_batch_direct_fill_count_.load(std::memory_order_relaxed)
           << ",\"bytes\":"
           << merged_batch_direct_fill_bytes_.load(std::memory_order_relaxed)
           << "}"
           << ",\"mergedBatchScratch\":{\"resizeCount\":"
           << merged_batch_scratch_resize_count_.load(std::memory_order_relaxed)
           << ",\"maxBytes\":"
           << merged_batch_scratch_max_bytes_.load(std::memory_order_relaxed)
           << "}"
           << ",\"asyncRequestStackWindows\":"
           << async_request_stack_window_count_.load(std::memory_order_relaxed)
           << ",\"asyncDirectAdjacentSpans\":{\"count\":"
           << async_direct_adjacent_span_count_.load(std::memory_order_relaxed)
           << ",\"bytes\":"
           << async_direct_adjacent_span_bytes_.load(std::memory_order_relaxed)
           << "}"
           << ",\"batchSortCount\":"
           << batch_sort_count_.load(std::memory_order_relaxed)
           << ",\"scratch\":{\"readResizeCount\":"
           << read_scratch_resize_count_.load(std::memory_order_relaxed)
           << ",\"readMaxBytes\":"
           << read_scratch_max_bytes_.load(std::memory_order_relaxed)
           << ",\"readThreadLocalUseCount\":"
           << read_thread_local_scratch_use_count_.load(std::memory_order_relaxed)
           << ",\"writeResizeCount\":"
           << write_scratch_resize_count_.load(std::memory_order_relaxed)
           << ",\"writeMaxBytes\":"
           << write_scratch_max_bytes_.load(std::memory_order_relaxed)
           << "}"
           << ",\"readCache\":{\"hits\":"
           << read_cache_hit_count_.load(std::memory_order_relaxed)
           << ",\"containedHits\":"
           << read_cache_contained_hit_count_.load(std::memory_order_relaxed)
           << ",\"misses\":"
           << read_cache_miss_count_.load(std::memory_order_relaxed)
           << ",\"invalidations\":"
           << read_cache_invalidation_count_.load(std::memory_order_relaxed)
           << ",\"bytes\":"
           << read_cache_bytes_.load(std::memory_order_relaxed)
           << "},\"lastIoError\":"
           << last_io_error_.load(std::memory_order_relaxed);
    buffer << "}";
    return buffer.str();
}

BlockDevice::~BlockDevice()
{
    std::lock_guard<std::mutex> lock(handle_mutex_);
    CloseHandlesLocked();
    CloseAsyncEventPoolLocked();
}

void BlockDevice::SetReadCacheMissHookForTests(std::function<void()> hook)
{
    std::lock_guard<std::mutex> hook_lock(test_hook_mutex_);
    read_cache_miss_hook_for_tests_ = std::move(hook);
}

void BlockDevice::SetWriteCacheInvalidationHookForTests(std::function<void()> hook)
{
    std::lock_guard<std::mutex> hook_lock(test_hook_mutex_);
    write_cache_invalidation_hook_for_tests_ = std::move(hook);
    write_cache_invalidation_hook_installed_.store(
        static_cast<bool>(write_cache_invalidation_hook_for_tests_),
        std::memory_order_release);
}

void BlockDevice::InvokeWriteCacheInvalidationHookForTests()
{
    if (!write_cache_invalidation_hook_installed_.load(std::memory_order_acquire))
    {
        return;
    }

    std::function<void()> hook;
    {
        std::lock_guard<std::mutex> hook_lock(test_hook_mutex_);
        hook = write_cache_invalidation_hook_for_tests_;
    }
    if (hook)
    {
        hook();
    }
}

void BlockDevice::BeginReadCacheWriteAdmission()
{
    if (!read_cache_enabled_)
    {
        return;
    }

    std::lock_guard<std::mutex> cache_lock(read_cache_mutex_);
    ++read_cache_write_admissions_;
}

void BlockDevice::EndReadCacheWriteAdmission() noexcept
{
    if (!read_cache_enabled_)
    {
        return;
    }

    std::lock_guard<std::mutex> cache_lock(read_cache_mutex_);
    if (read_cache_write_admissions_ > 0)
    {
        --read_cache_write_admissions_;
    }
}

void BlockDevice::BeginReadCacheWriteEpoch()
{
    if (!read_cache_enabled_)
    {
        return;
    }

    std::lock_guard<std::mutex> cache_lock(read_cache_mutex_);
    ++read_cache_generation_;
    if (!read_cache_.empty())
    {
        read_cache_.clear();
        read_cache_bytes_.store(0, std::memory_order_relaxed);
        read_cache_invalidation_count_.fetch_add(1, std::memory_order_relaxed);
    }
}

void BlockDevice::EndReadCacheWriteEpoch()
{
    if (!read_cache_enabled_)
    {
        return;
    }

    std::lock_guard<std::mutex> cache_lock(read_cache_mutex_);
    ++read_cache_generation_;
}

void BlockDevice::InsertReadCacheEntryLocked(
    std::uint64_t offset_bytes,
    std::size_t size_bytes,
    std::vector<std::byte> bytes) const
{
    if (size_bytes == 0 || bytes.size() != size_bytes)
    {
        return;
    }

    const ReadCacheKey key{offset_bytes, size_bytes};
    auto existing = read_cache_.find(key);
    if (existing != read_cache_.end())
    {
        read_cache_bytes_.fetch_sub(
            static_cast<std::uint64_t>(existing->second.bytes.size()),
            std::memory_order_relaxed);
        existing->second.bytes = std::move(bytes);
        existing->second.last_use = ++read_cache_use_;
    }
    else
    {
        ReadCacheEntry entry{};
        entry.bytes = std::move(bytes);
        entry.last_use = ++read_cache_use_;
        read_cache_.emplace(key, std::move(entry));
    }
    read_cache_bytes_.fetch_add(static_cast<std::uint64_t>(size_bytes), std::memory_order_relaxed);

    while (read_cache_.size() > kReadCacheMaxEntries ||
           read_cache_bytes_.load(std::memory_order_relaxed) > kReadCacheMaxBytes)
    {
        const auto oldest = std::min_element(
            read_cache_.begin(),
            read_cache_.end(),
            [](const auto& left, const auto& right)
            {
                return left.second.last_use < right.second.last_use;
            });
        if (oldest == read_cache_.end())
        {
            break;
        }
        read_cache_bytes_.fetch_sub(
            static_cast<std::uint64_t>(oldest->second.bytes.size()),
            std::memory_order_relaxed);
        read_cache_.erase(oldest);
    }
}

const std::wstring& BlockDevice::Path() const noexcept
{
    return path_;
}

bool BlockDevice::IsWritable() const
{
    if (!writable_.load(std::memory_order_acquire))
    {
        (void)EnsureWriteHandle();
    }
    return writable_.load(std::memory_order_acquire);
}

BlockDevice::Geometry BlockDevice::GetGeometry() const
{
    std::lock_guard<std::mutex> lock(geometry_mutex_);
    if (geometry_cached_)
    {
        return geometry_cache_;
    }

    Geometry geometry{};
    HANDLE handle = EnsureReadHandle();
    if (handle == INVALID_HANDLE_VALUE)
    {
        return geometry;
    }

    if (QueryGeometryLocked(handle, geometry))
    {
        geometry_cache_ = geometry;
        geometry_cached_ = true;
        logical_block_size_cache_.store(
            (std::max)(std::uint32_t{512}, geometry.logical_block_size),
            std::memory_order_release);
    }

    return geometry_cache_;
}

bool BlockDevice::Read(std::uint64_t offset_bytes, std::size_t size_bytes, std::vector<std::byte>& out_buffer) const
{
    out_buffer.clear();
    if (size_bytes == 0)
    {
        return true;
    }
    out_buffer.resize(size_bytes);

    std::size_t bytes_read = 0;
    if (!ReadInto(offset_bytes, out_buffer.data(), out_buffer.size(), bytes_read))
    {
        out_buffer.clear();
        return false;
    }

    out_buffer.resize(bytes_read);
    return true;
}

bool BlockDevice::ReadInto(
    std::uint64_t offset_bytes,
    std::byte* destination,
    std::size_t destination_size,
    std::size_t& out_bytes_read) const
{
    ScopedPerfTimer perf_scope(read_perf_, static_cast<std::uint64_t>(destination_size));

    out_bytes_read = 0;
    if (destination_size == 0)
    {
        return true;
    }
    if (destination == nullptr)
    {
        return false;
    }
    if (destination_size > static_cast<std::size_t>(std::numeric_limits<DWORD>::max()))
    {
        return false;
    }

    HANDLE handle = EnsureReadHandle();
    if (handle == INVALID_HANDLE_VALUE)
    {
        return false;
    }

    if (offset_bytes > (std::numeric_limits<std::uint64_t>::max() - base_offset_bytes_))
    {
        return false;
    }
    offset_bytes += base_offset_bytes_;

    const auto block_size = static_cast<std::uint64_t>(LogicalBlockSize());
    const auto aligned_offset = AlignDown(offset_bytes, block_size);
    const auto prefix_bytes = static_cast<std::size_t>(offset_bytes - aligned_offset);
    if (destination_size > (std::numeric_limits<std::uint64_t>::max() - static_cast<std::uint64_t>(prefix_bytes)))
    {
        return false;
    }
    const auto requested_window = static_cast<std::uint64_t>(prefix_bytes) + static_cast<std::uint64_t>(destination_size);
    const auto aligned_size_u64 = AlignUp(requested_window, block_size);
    if (aligned_size_u64 == 0 || aligned_size_u64 > static_cast<std::uint64_t>(std::numeric_limits<DWORD>::max()))
    {
        return false;
    }
    const auto aligned_size = static_cast<std::size_t>(aligned_size_u64);
    const bool already_aligned =
        prefix_bytes == 0 &&
        static_cast<std::uint64_t>(destination_size) == aligned_size_u64;

    const bool cacheable = read_cache_enabled_ && aligned_size <= kReadCacheMaxWindowBytes;
    std::uint64_t read_cache_generation = 0;
    if (cacheable)
    {
        std::lock_guard<std::mutex> cache_lock(read_cache_mutex_);
        read_cache_generation = read_cache_generation_;
        if (read_cache_write_admissions_ == 0 &&
            (read_cache_generation & 1ull) == 0)
        {
            auto cached = read_cache_.find(ReadCacheKey{aligned_offset, aligned_size});
            std::size_t cached_offset = 0;
            bool contained_hit = false;
            if (cached == read_cache_.end())
            {
                auto best = read_cache_.end();
                std::size_t best_size = (std::numeric_limits<std::size_t>::max)();
                for (auto candidate = read_cache_.begin(); candidate != read_cache_.end(); ++candidate)
                {
                    const auto candidate_offset = candidate->first.offset_bytes;
                    const auto candidate_size = candidate->first.size_bytes;
                    if (candidate_size < aligned_size ||
                        candidate_offset > aligned_offset ||
                        candidate->second.bytes.size() != candidate_size)
                    {
                        continue;
                    }

                    const auto relative_offset = aligned_offset - candidate_offset;
                    if (relative_offset > candidate_size - aligned_size ||
                        candidate_size >= best_size)
                    {
                        continue;
                    }

                    best = candidate;
                    best_size = candidate_size;
                    cached_offset = static_cast<std::size_t>(relative_offset);
                }
                if (best != read_cache_.end())
                {
                    cached = best;
                    contained_hit = true;
                }
            }
            if (cached != read_cache_.end() &&
                cached_offset <= cached->second.bytes.size() &&
                aligned_size <= cached->second.bytes.size() - cached_offset)
            {
                cached->second.last_use = ++read_cache_use_;
                std::copy_n(
                    cached->second.bytes.data() + cached_offset + prefix_bytes,
                    destination_size,
                    destination);
                out_bytes_read = destination_size;
                read_cache_hit_count_.fetch_add(1, std::memory_order_relaxed);
                if (contained_hit)
                {
                    read_cache_contained_hit_count_.fetch_add(1, std::memory_order_relaxed);
                }
                return true;
            }
            read_cache_miss_count_.fetch_add(1, std::memory_order_relaxed);
        }
    }

    DWORD bytes_read = 0;
    if (already_aligned)
    {
        if (!ReadAt(handle, aligned_offset, destination, static_cast<DWORD>(destination_size), bytes_read))
        {
            return false;
        }
        out_bytes_read = static_cast<std::size_t>(bytes_read);
        if (cacheable && bytes_read == aligned_size)
        {
            std::function<void()> hook;
            {
                std::lock_guard<std::mutex> hook_lock(test_hook_mutex_);
                hook = read_cache_miss_hook_for_tests_;
            }
            if (hook)
            {
                hook();
            }
            std::lock_guard<std::mutex> cache_lock(read_cache_mutex_);
            if (read_cache_generation != read_cache_generation_ ||
                read_cache_write_admissions_ != 0 ||
                (read_cache_generation & 1ull) != 0)
            {
                return true;
            }
            InsertReadCacheEntryLocked(
                aligned_offset,
                aligned_size,
                std::vector<std::byte>(destination, destination + aligned_size));
        }
        return true;
    }

    std::vector<std::byte> cache_bytes;
    static thread_local std::vector<std::byte> thread_local_read_scratch;
    std::unique_lock<std::mutex> shared_scratch_lock(read_scratch_mutex_, std::defer_lock);
    auto* scratch = &thread_local_read_scratch;
    if (aligned_size <= kReadThreadLocalScratchMaxBytes)
    {
        read_thread_local_scratch_use_count_.fetch_add(1, std::memory_order_relaxed);
    }
    else
    {
        shared_scratch_lock.lock();
        scratch = &read_scratch_;
    }

    if (scratch->size() < aligned_size)
    {
        scratch->resize(aligned_size);
        read_scratch_resize_count_.fetch_add(1, std::memory_order_relaxed);
        UpdateAtomicMax(read_scratch_max_bytes_, static_cast<std::uint64_t>(scratch->size()));
    }
    if (!ReadAt(handle, aligned_offset, scratch->data(), static_cast<DWORD>(aligned_size), bytes_read))
    {
        return false;
    }
    if (bytes_read < prefix_bytes)
    {
        return false;
    }

    const auto available = static_cast<std::size_t>(bytes_read) - prefix_bytes;
    const auto bytes_to_copy = std::min(destination_size, available);
    std::copy_n(
        scratch->data() + prefix_bytes,
        bytes_to_copy,
        destination);
    out_bytes_read = bytes_to_copy;
    if (cacheable && bytes_read == aligned_size)
    {
        cache_bytes.assign(
            scratch->begin(),
            scratch->begin() + static_cast<std::ptrdiff_t>(aligned_size));
    }
    if (shared_scratch_lock.owns_lock())
    {
        shared_scratch_lock.unlock();
    }
    if (!cache_bytes.empty())
    {
        std::function<void()> hook;
        {
            std::lock_guard<std::mutex> hook_lock(test_hook_mutex_);
            hook = read_cache_miss_hook_for_tests_;
        }
        if (hook)
        {
            hook();
        }
        std::lock_guard<std::mutex> cache_lock(read_cache_mutex_);
        if (read_cache_generation != read_cache_generation_ ||
            read_cache_write_admissions_ != 0 ||
            (read_cache_generation & 1ull) != 0)
        {
            return true;
        }
        InsertReadCacheEntryLocked(aligned_offset, aligned_size, std::move(cache_bytes));
    }
    return true;
}

bool BlockDevice::Write(std::uint64_t offset_bytes, const std::vector<std::byte>& buffer)
{
    return Write(offset_bytes, std::span<const std::byte>(buffer.data(), buffer.size()));
}

bool BlockDevice::Write(std::uint64_t offset_bytes, std::span<const std::byte> buffer)
{
    ScopedPerfTimer perf_scope(write_perf_, static_cast<std::uint64_t>(buffer.size()));
    perf_scope.SetSecondary(unaligned_write_perf_);

    if (buffer.empty())
    {
        return true;
    }
    if (buffer.size() > static_cast<std::size_t>(std::numeric_limits<DWORD>::max()))
    {
        return false;
    }
    const auto fault_mode = ReadFaultMode(L"APFSACCESS_RW_FAULT_WRITE");

    if (offset_bytes > (std::numeric_limits<std::uint64_t>::max() - base_offset_bytes_))
    {
        return false;
    }
    offset_bytes += base_offset_bytes_;

    ReadCacheWriteAdmission write_admission(*this);
    InvokeWriteCacheInvalidationHookForTests();
    ReadCacheWriteEpoch write_epoch(*this);

    std::unique_lock<std::mutex> write_lock(write_mutex_, std::defer_lock);
    {
        ScopedPerfTimer queue_wait_scope(write_queue_wait_perf_);
        write_lock.lock();
    }
    HANDLE handle = EnsureWriteHandle();
    if (handle == INVALID_HANDLE_VALUE)
    {
        return false;
    }

    bool was_unaligned = false;
    const auto ok = WriteLocked(handle, offset_bytes, buffer, fault_mode, was_unaligned);
    if (was_unaligned)
    {
        perf_scope.MarkSecondary();
    }
    return ok;
}

bool BlockDevice::WriteBatch(std::span<const WriteSpan> writes)
{
    last_io_error_.store(ERROR_SUCCESS, std::memory_order_relaxed);
    std::uint64_t total_bytes = 0;
    const WriteSpan* single_non_empty_write = nullptr;
    std::size_t non_empty_write_count = 0;
    for (const auto& write : writes)
    {
        if (write.buffer.empty())
        {
            continue;
        }
        single_non_empty_write = &write;
        ++non_empty_write_count;
        if (write.buffer.size() > static_cast<std::size_t>(std::numeric_limits<DWORD>::max()) ||
            write.offset_bytes > (std::numeric_limits<std::uint64_t>::max() - base_offset_bytes_))
        {
            last_io_error_.store(ERROR_INVALID_PARAMETER, std::memory_order_relaxed);
            return false;
        }
        const auto write_bytes = static_cast<std::uint64_t>(write.buffer.size());
        if (total_bytes <= (std::numeric_limits<std::uint64_t>::max() - write_bytes))
        {
            total_bytes += write_bytes;
        }
        else
        {
            total_bytes = std::numeric_limits<std::uint64_t>::max();
        }
    }

    ScopedPerfTimer perf_scope(batch_write_perf_, total_bytes);
    if (writes.empty() || total_bytes == 0)
    {
        return true;
    }

    const auto fault_mode = ReadFaultMode(L"APFSACCESS_RW_FAULT_WRITE");
    if (fault_mode.has_value())
    {
        for (const auto& write : writes)
        {
            if (!write.buffer.empty() && !Write(write.offset_bytes, write.buffer))
            {
                return false;
            }
        }
        return true;
    }

    const bool async_block_io_enabled = IsAsyncBlockIoEnabled();
    const bool may_split_single_write_async =
        single_non_empty_write != nullptr &&
        single_non_empty_write->buffer.size() >= kMinAsyncSingleWriteBytes &&
        async_block_io_enabled;
    if (non_empty_write_count == 1 &&
        single_non_empty_write != nullptr &&
        !may_split_single_write_async)
    {
        ReadCacheWriteAdmission write_admission(*this);
        InvokeWriteCacheInvalidationHookForTests();
        ReadCacheWriteEpoch write_epoch(*this);
        std::unique_lock<std::mutex> write_lock(write_mutex_, std::defer_lock);
        {
            ScopedPerfTimer queue_wait_scope(write_queue_wait_perf_);
            write_lock.lock();
        }
        HANDLE handle = EnsureWriteHandle();
        if (handle == INVALID_HANDLE_VALUE)
        {
            const auto error = GetLastError();
            last_io_error_.store(error == ERROR_SUCCESS ? ERROR_INVALID_HANDLE : error, std::memory_order_relaxed);
            return false;
        }

        bool was_unaligned = false;
        const auto ok = WriteLocked(
            handle,
            single_non_empty_write->offset_bytes + base_offset_bytes_,
            single_non_empty_write->buffer,
            std::nullopt,
            was_unaligned);
        if (was_unaligned && IsPerfCountersEnabled())
        {
            unaligned_write_perf_.Observe(
                0,
                static_cast<std::uint64_t>(single_non_empty_write->buffer.size()));
        }
        return ok;
    }

    struct PendingWrite
    {
        std::uint64_t absolute_offset = 0;
        std::span<const std::byte> buffer{};
        const void* merge_token = nullptr;
    };
    constexpr std::size_t kInlinePendingWriteCount = 8;
    alignas(PendingWrite) std::array<std::byte, sizeof(PendingWrite) * kInlinePendingWriteCount>
        pending_inline_storage{};
    std::pmr::monotonic_buffer_resource pending_resource(
        pending_inline_storage.data(),
        pending_inline_storage.size());
    const std::pmr::polymorphic_allocator<PendingWrite> pending_allocator(&pending_resource);
    std::pmr::vector<PendingWrite> pending(pending_allocator);
    pending.reserve(non_empty_write_count);
    for (const auto& write : writes)
    {
        if (write.buffer.empty())
        {
            continue;
        }
        pending.push_back(PendingWrite{write.offset_bytes + base_offset_bytes_, write.buffer, write.merge_token});
    }
    if (pending.empty())
    {
        return true;
    }
    if (pending.size() > 1)
    {
        bool already_ordered_non_overlapping = true;
        std::uint64_t previous_end = 0;
        bool have_previous = false;
        for (const auto& write : pending)
        {
            const auto write_bytes = static_cast<std::uint64_t>(write.buffer.size());
            if (write.absolute_offset > (std::numeric_limits<std::uint64_t>::max() - write_bytes))
            {
                already_ordered_non_overlapping = false;
                break;
            }
            const auto write_end = write.absolute_offset + write_bytes;
            if (have_previous && write.absolute_offset < previous_end)
            {
                already_ordered_non_overlapping = false;
                break;
            }
            previous_end = write_end;
            have_previous = true;
        }

        if (!already_ordered_non_overlapping)
        {
            std::pmr::vector<PendingWrite> sorted_pending(pending, pending_allocator);
            std::stable_sort(
                sorted_pending.begin(),
                sorted_pending.end(),
                [](const PendingWrite& left, const PendingWrite& right)
                {
                    return left.absolute_offset < right.absolute_offset;
                });
            batch_sort_count_.fetch_add(1, std::memory_order_relaxed);

            bool can_reorder = true;
            previous_end = 0;
            have_previous = false;
            for (const auto& write : sorted_pending)
            {
                const auto write_bytes = static_cast<std::uint64_t>(write.buffer.size());
                if (write.absolute_offset > (std::numeric_limits<std::uint64_t>::max() - write_bytes))
                {
                    can_reorder = false;
                    break;
                }
                const auto write_end = write.absolute_offset + write_bytes;
                if (have_previous && write.absolute_offset < previous_end)
                {
                    can_reorder = false;
                    break;
                }
                previous_end = write_end;
                have_previous = true;
            }
            if (can_reorder)
            {
                pending = std::move(sorted_pending);
            }
        }
    }

    ReadCacheWriteAdmission write_admission(*this);
    InvokeWriteCacheInvalidationHookForTests();
    ReadCacheWriteEpoch write_epoch(*this);
    std::unique_lock<std::mutex> write_lock(write_mutex_, std::defer_lock);
    {
        ScopedPerfTimer queue_wait_scope(write_queue_wait_perf_);
        write_lock.lock();
    }
    HANDLE handle = EnsureWriteHandle();
    if (handle == INVALID_HANDLE_VALUE)
    {
        return false;
    }

    const auto try_async_batch = [&]() -> std::optional<bool>
    {
        const bool single_large_write =
            pending.size() == 1 &&
            pending.front().buffer.size() >= kMinAsyncSingleWriteBytes;
        if (!async_block_io_enabled || (pending.size() < 2 && !single_large_write))
        {
            return std::nullopt;
        }

        const auto block_size = static_cast<std::uint64_t>(LogicalBlockSize());
        std::uint64_t previous_end = 0;
        bool have_previous = false;
        for (const auto& write : pending)
        {
            const auto write_bytes = static_cast<std::uint64_t>(write.buffer.size());
            if (write_bytes == 0 ||
                write.absolute_offset % block_size != 0 ||
                write_bytes % block_size != 0 ||
                write.absolute_offset > (std::numeric_limits<std::uint64_t>::max() - write_bytes))
            {
                return std::nullopt;
            }

            const auto write_end = write.absolute_offset + write_bytes;
            if (have_previous && write.absolute_offset < previous_end)
            {
                return std::nullopt;
            }
            previous_end = write_end;
            have_previous = true;
        }

        struct AsyncChunk
        {
            std::uint64_t absolute_offset = 0;
            std::span<const std::byte> buffer{};
            bool contiguous_view = false;
            std::size_t merged_storage_offset = 0;
            std::size_t merged_storage_bytes = 0;
        };
        // All copied chunks live in one backing store until every overlapped
        // request has completed. This avoids one heap allocation per merged
        // group while keeping each outstanding request's buffer stable.
        std::size_t merged_storage_bytes = 0;
        std::vector<AsyncChunk> chunks;
        chunks.reserve(pending.size());
        for (std::size_t index = 0; index < pending.size();)
        {
            const auto& first = pending[index];
            const auto first_bytes = static_cast<std::uint64_t>(first.buffer.size());
            if (first_bytes > kMaxMergedBatchBytes)
            {
                std::uint64_t chunk_offset = 0;
                while (chunk_offset < first_bytes)
                {
                    const auto chunk_bytes_u64 = std::min<std::uint64_t>(
                        kMaxDirectAsyncChunkBytes,
                        first_bytes - chunk_offset);
                    if (chunk_bytes_u64 > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
                    {
                        return std::optional<bool>{false};
                    }
                    const auto chunk_bytes = static_cast<std::size_t>(chunk_bytes_u64);
                    const auto span_offset = static_cast<std::size_t>(chunk_offset);
                    chunks.push_back(AsyncChunk{
                        first.absolute_offset + chunk_offset,
                        first.buffer.subspan(span_offset, chunk_bytes),
                        false,
                    });
                    chunk_offset += chunk_bytes_u64;
                }
                ++index;
                continue;
            }

            auto physical_end = first.absolute_offset + first_bytes;
            std::size_t merge_end = index + 1;
            while (merge_end < pending.size())
            {
                const auto& next = pending[merge_end];
                const auto next_bytes = static_cast<std::uint64_t>(next.buffer.size());
                if (next.absolute_offset != physical_end ||
                    next_bytes > (std::numeric_limits<std::uint64_t>::max() - physical_end))
                {
                    break;
                }
                const auto next_physical_end = physical_end + next_bytes;
                if ((next_physical_end - first.absolute_offset) > kMaxMergedBatchBytes)
                {
                    break;
                }
                physical_end = next_physical_end;
                ++merge_end;
            }

            if (merge_end == index + 1)
            {
                chunks.push_back(AsyncChunk{first.absolute_offset, first.buffer, false});
                index = merge_end;
                continue;
            }

            const auto chunk_bytes_u64 = physical_end - first.absolute_offset;
            if (chunk_bytes_u64 > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
            {
                return std::optional<bool>{false};
            }
            bool can_write_adjacent_spans_directly = true;
            std::uint64_t adjacent_span_bytes = 0;
            for (std::size_t current = index; current < merge_end; ++current)
            {
                const auto span_bytes = static_cast<std::uint64_t>(pending[current].buffer.size());
                if (span_bytes < kMinAsyncDirectAdjacentSpanBytes)
                {
                    can_write_adjacent_spans_directly = false;
                    break;
                }
                adjacent_span_bytes += span_bytes;
            }
            if (can_write_adjacent_spans_directly)
            {
                for (std::size_t current = index; current < merge_end; ++current)
                {
                    chunks.push_back(AsyncChunk{pending[current].absolute_offset, pending[current].buffer, false});
                }
                async_direct_adjacent_span_count_.fetch_add(
                    static_cast<std::uint64_t>(merge_end - index),
                    std::memory_order_relaxed);
                async_direct_adjacent_span_bytes_.fetch_add(adjacent_span_bytes, std::memory_order_relaxed);
                index = merge_end;
                continue;
            }
            bool contiguous_view = false;
            if (first.merge_token != nullptr)
            {
                const auto* base_data = first.buffer.data();
                contiguous_view = base_data != nullptr;
                for (std::size_t current = index + 1; contiguous_view && current < merge_end; ++current)
                {
                    const auto expected_offset = pending[current].absolute_offset - first.absolute_offset;
                    const std::byte* expected_data = nullptr;
                    contiguous_view =
                        pending[current].merge_token == first.merge_token &&
                        AddOffsetToPointer(base_data, expected_offset, expected_data) &&
                        pending[current].buffer.data() == expected_data;
                }
            }
            if (contiguous_view)
            {
                chunks.push_back(AsyncChunk{
                    first.absolute_offset,
                    std::span<const std::byte>(first.buffer.data(), static_cast<std::size_t>(chunk_bytes_u64)),
                    true,
                });
                index = merge_end;
                continue;
            }

            const auto merged_bytes = static_cast<std::size_t>(chunk_bytes_u64);
            const auto merged_offset = merged_storage_bytes;
            if (merged_bytes > (std::numeric_limits<std::size_t>::max() - merged_offset))
            {
                return std::optional<bool>{false};
            }
            const auto required_storage_bytes = merged_offset + merged_bytes;
            if (!EnsureMergedBatchScratch(required_storage_bytes, merged_storage_bytes))
            {
                return std::optional<bool>{false};
            }
            merged_storage_bytes = required_storage_bytes;
            auto* merged = merged_batch_scratch_.get() + static_cast<std::ptrdiff_t>(merged_offset);
            std::size_t copied_bytes = 0;
            for (std::size_t current = index; current < merge_end; ++current)
            {
                const auto& source = pending[current].buffer;
                if (source.size() > (merged_bytes - copied_bytes))
                {
                    return std::optional<bool>{false};
                }

                std::copy_n(
                    source.data(),
                    source.size(),
                    merged + static_cast<std::ptrdiff_t>(copied_bytes));
                copied_bytes += source.size();
            }
            if (copied_bytes != merged_bytes)
            {
                return std::optional<bool>{false};
            }
            merged_batch_direct_fill_count_.fetch_add(1, std::memory_order_relaxed);
            merged_batch_direct_fill_bytes_.fetch_add(chunk_bytes_u64, std::memory_order_relaxed);
            chunks.push_back(AsyncChunk{
                first.absolute_offset,
                {},
                false,
                merged_offset,
                merged_bytes,
            });
            index = merge_end;
        }

        for (auto& chunk : chunks)
        {
            if (chunk.merged_storage_bytes == 0)
            {
                continue;
            }
            if (chunk.merged_storage_offset > merged_storage_bytes ||
                chunk.merged_storage_bytes > (merged_storage_bytes - chunk.merged_storage_offset))
            {
                last_io_error_.store(ERROR_INVALID_PARAMETER, std::memory_order_relaxed);
                return std::optional<bool>{false};
            }
            chunk.buffer = std::span<const std::byte>(
                merged_batch_scratch_.get() + static_cast<std::ptrdiff_t>(chunk.merged_storage_offset),
                chunk.merged_storage_bytes);
        }

        if (chunks.size() < 2)
        {
            return std::nullopt;
        }

        struct AsyncRequest
        {
            OVERLAPPED overlapped{};
            HANDLE event = INVALID_HANDLE_VALUE;
            DWORD expected_bytes = 0;
            bool issued = false;
        };

        const bool observe_perf = IsPerfCountersEnabled();
        const auto started = observe_perf ? std::chrono::steady_clock::now() : std::chrono::steady_clock::time_point{};
        std::uint64_t async_bytes = 0;
        std::uint64_t contiguous_bytes = 0;
        std::size_t max_window_depth = 0;
        std::size_t total_issued = 0;
        const auto queue_depth = AsyncBlockIoQueueDepth();
        const auto fail_after_issues = ReadOptionalPositiveSizeEnv(
            L"APFSACCESS_RW_FAULT_ASYNC_BATCH_AFTER_ISSUES",
            std::numeric_limits<std::size_t>::max());
        if (!EnsureAsyncEventPool(queue_depth))
        {
            const auto error = GetLastError();
            last_io_error_.store(error == ERROR_SUCCESS ? ERROR_NOT_ENOUGH_MEMORY : error, std::memory_order_relaxed);
            return std::optional<bool>{false};
        }
        for (std::size_t cursor = 0; cursor < chunks.size();)
        {
            const auto window_depth = std::min<std::size_t>(queue_depth, chunks.size() - cursor);
            max_window_depth = std::max(max_window_depth, window_depth);
            std::array<AsyncRequest, kMaxAsyncBlockIoQueueDepth> requests{};
            async_request_stack_window_count_.fetch_add(1, std::memory_order_relaxed);
            bool window_ok = true;
            std::size_t issued = 0;

            for (; issued < window_depth; ++issued)
            {
                if (fail_after_issues.has_value() && total_issued >= fail_after_issues.value())
                {
                    last_io_error_.store(ERROR_OPERATION_ABORTED, std::memory_order_relaxed);
                    window_ok = false;
                    break;
                }

                const auto& chunk = chunks[cursor + issued];
                if (chunk.buffer.size() > static_cast<std::size_t>(std::numeric_limits<DWORD>::max()))
                {
                    window_ok = false;
                    break;
                }

                auto& request = requests[issued];
                request.expected_bytes = static_cast<DWORD>(chunk.buffer.size());
                request.event = async_event_pool_[issued];
                if (request.event == INVALID_HANDLE_VALUE ||
                    !ResetEvent(request.event))
                {
                    const auto error = GetLastError();
                    last_io_error_.store(error == ERROR_SUCCESS ? ERROR_INVALID_HANDLE : error, std::memory_order_relaxed);
                    window_ok = false;
                    break;
                }
                request.overlapped.Offset = static_cast<DWORD>(chunk.absolute_offset & 0xffffffffull);
                request.overlapped.OffsetHigh = static_cast<DWORD>(chunk.absolute_offset >> 32);
                request.overlapped.hEvent = request.event;

                if (WriteFile(
                        handle,
                        chunk.buffer.data(),
                        request.expected_bytes,
                        nullptr,
                        &request.overlapped))
                {
                    request.issued = true;
                    ++total_issued;
                    async_bytes += request.expected_bytes;
                    if (chunk.contiguous_view)
                    {
                        contiguous_bytes += request.expected_bytes;
                    }
                    continue;
                }

                const auto error = GetLastError();
                if (error != ERROR_IO_PENDING)
                {
                    last_io_error_.store(error == ERROR_SUCCESS ? ERROR_WRITE_FAULT : error, std::memory_order_relaxed);
                    window_ok = false;
                    break;
                }

                request.issued = true;
                ++total_issued;
                async_bytes += request.expected_bytes;
                if (chunk.contiguous_view)
                {
                    contiguous_bytes += request.expected_bytes;
                }
            }

            for (std::size_t index = 0; index < issued; ++index)
            {
                auto& request = requests[index];
                DWORD bytes_written = 0;
                if (!request.issued)
                {
                    continue;
                }
                DWORD completion_error = ERROR_SUCCESS;
                if (!WaitForOverlappedCompletion(
                        handle,
                        request.overlapped,
                        bytes_written,
                        completion_error))
                {
                    last_io_error_.store(
                        completion_error == ERROR_SUCCESS ? ERROR_WRITE_FAULT : completion_error,
                        std::memory_order_relaxed);
                    window_ok = false;
                }
                else if (bytes_written != request.expected_bytes)
                {
                    last_io_error_.store(ERROR_WRITE_FAULT, std::memory_order_relaxed);
                    window_ok = false;
                }
            }

            if (!window_ok)
            {
                return std::optional<bool>{false};
            }

            cursor += window_depth;
        }

        UpdateAtomicMax(async_max_queue_depth_, static_cast<std::uint64_t>(max_window_depth));
        if (observe_perf)
        {
            async_batch_write_perf_.Observe(ElapsedMicroseconds(started), async_bytes);
        }
        if (contiguous_bytes > 0)
        {
            contiguous_batch_write_perf_.Observe(0, contiguous_bytes);
        }
        return std::optional<bool>{true};
    };

    if (auto async_result = try_async_batch())
    {
        return *async_result;
    }

    const bool observe_perf = IsPerfCountersEnabled();

    // A small group of nearby unaligned spans can share one aligned read-modify-write
    // window. The bounded window keeps read amplification predictable while applying
    // spans in caller order so overlapping writes retain last-writer-wins semantics.
    const auto try_rmw_group = [&](std::size_t begin, std::size_t& out_end) -> std::optional<bool>
    {
        out_end = begin;
        if (begin >= pending.size())
        {
            return std::nullopt;
        }

        const auto& first = pending[begin];
        const auto first_bytes = static_cast<std::uint64_t>(first.buffer.size());
        if (first_bytes == 0 ||
            first.absolute_offset > (std::numeric_limits<std::uint64_t>::max() - first_bytes))
        {
            return std::nullopt;
        }

        const auto block_size = static_cast<std::uint64_t>(LogicalBlockSize());
        const auto first_end = first.absolute_offset + first_bytes;
        const bool first_aligned =
            first.absolute_offset % block_size == 0 &&
            first_bytes % block_size == 0;
        if (first_aligned)
        {
            return std::nullopt;
        }

        auto group_start = AlignDown(first.absolute_offset, block_size);
        auto group_physical_end = AlignUp(first_end, block_size);
        if (group_physical_end == 0 || group_physical_end < group_start ||
            (group_physical_end - group_start) > kMaxRmwGroupBytes)
        {
            return std::nullopt;
        }

        auto actual_start = first.absolute_offset;
        auto actual_end = first_end;
        auto previous_write_end = first_end;
        std::uint64_t payload_bytes = first_bytes;
        std::size_t group_end = begin + 1;
        bool has_non_contiguous_span = false;
        for (; group_end < pending.size() &&
               (group_end - begin) < kMaxRmwGroupWrites;
             ++group_end)
        {
            const auto& candidate = pending[group_end];
            const auto candidate_bytes = static_cast<std::uint64_t>(candidate.buffer.size());
            if (candidate_bytes == 0 ||
                candidate.absolute_offset > (std::numeric_limits<std::uint64_t>::max() - candidate_bytes))
            {
                return std::nullopt;
            }

            const auto candidate_end = candidate.absolute_offset + candidate_bytes;
            const auto gap = candidate.absolute_offset >= actual_end
                ? candidate.absolute_offset - actual_end
                : candidate_end <= actual_start
                    ? actual_start - candidate_end
                    : 0;
            if (gap > kMaxRmwGroupGapBytes)
            {
                break;
            }

            const auto next_actual_start = (std::min)(actual_start, candidate.absolute_offset);
            const auto next_actual_end = (std::max)(actual_end, candidate_end);
            const auto next_group_start = AlignDown(next_actual_start, block_size);
            const auto next_group_end = AlignUp(next_actual_end, block_size);
            if (next_group_end == 0 || next_group_end < next_group_start ||
                (next_group_end - next_group_start) > kMaxRmwGroupBytes)
            {
                break;
            }
            if (payload_bytes > (std::numeric_limits<std::uint64_t>::max() - candidate_bytes))
            {
                return std::nullopt;
            }

            has_non_contiguous_span |= candidate.absolute_offset != previous_write_end;
            group_start = next_group_start;
            group_physical_end = next_group_end;
            actual_start = next_actual_start;
            actual_end = next_actual_end;
            previous_write_end = candidate_end;
            payload_bytes += candidate_bytes;
        }

        if (group_end == begin + 1 || !has_non_contiguous_span)
        {
            return std::nullopt;
        }

        const auto group_bytes_u64 = group_physical_end - group_start;
        if (group_bytes_u64 == 0 ||
            group_bytes_u64 > static_cast<std::uint64_t>(std::numeric_limits<DWORD>::max()) ||
            group_bytes_u64 > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
        {
            return std::nullopt;
        }
        const auto group_bytes = static_cast<std::size_t>(group_bytes_u64);
        ScopedPerfTimer rmw_perf(rmw_group_write_perf_, payload_bytes);
        if (write_scratch_.size() < group_bytes)
        {
            write_scratch_.resize(group_bytes);
            write_scratch_resize_count_.fetch_add(1, std::memory_order_relaxed);
            UpdateAtomicMax(write_scratch_max_bytes_, static_cast<std::uint64_t>(write_scratch_.size()));
        }

        DWORD bytes_read = 0;
        if (!ReadAt(handle, group_start, write_scratch_.data(), static_cast<DWORD>(group_bytes), bytes_read) ||
            bytes_read != group_bytes)
        {
            return false;
        }

        for (std::size_t current = begin; current < group_end; ++current)
        {
            const auto& write = pending[current];
            const auto write_bytes = write.buffer.size();
            if (write.absolute_offset < group_start ||
                write.absolute_offset - group_start > group_bytes_u64 ||
                write_bytes > group_bytes - static_cast<std::size_t>(write.absolute_offset - group_start))
            {
                last_io_error_.store(ERROR_INVALID_PARAMETER, std::memory_order_relaxed);
                return false;
            }
            std::copy(
                write.buffer.begin(),
                write.buffer.end(),
                write_scratch_.begin() + static_cast<std::ptrdiff_t>(write.absolute_offset - group_start));
        }

        DWORD bytes_written = 0;
        if (!WriteAt(handle, group_start, write_scratch_.data(), static_cast<DWORD>(group_bytes), bytes_written) ||
            bytes_written != group_bytes)
        {
            return false;
        }
        if (observe_perf)
        {
            unaligned_write_perf_.Observe(0, payload_bytes);
        }
        out_end = group_end;
        return true;
    };

    for (std::size_t index = 0; index < pending.size();)
    {
        std::size_t rmw_group_end = index;
        if (auto rmw_result = try_rmw_group(index, rmw_group_end))
        {
            if (!*rmw_result)
            {
                return false;
            }
            index = rmw_group_end;
            continue;
        }

        const auto& first = pending[index];
        const auto first_bytes = static_cast<std::uint64_t>(first.buffer.size());
        if (first.absolute_offset > (std::numeric_limits<std::uint64_t>::max() - first_bytes))
        {
            return false;
        }

        auto physical_end = first.absolute_offset + first_bytes;
        std::size_t merge_end = index + 1;
        while (merge_end < pending.size())
        {
            const auto& next = pending[merge_end];
            const auto next_bytes = static_cast<std::uint64_t>(next.buffer.size());
            if (next.absolute_offset != physical_end ||
                next_bytes > (std::numeric_limits<std::uint64_t>::max() - physical_end))
            {
                break;
            }
            const auto next_physical_end = physical_end + next_bytes;
            if ((next_physical_end - first.absolute_offset) > static_cast<std::uint64_t>(std::numeric_limits<DWORD>::max()))
            {
                break;
            }
            physical_end = next_physical_end;
            ++merge_end;
        }

        bool was_unaligned = false;
        if (merge_end == index + 1)
        {
            if (!WriteLocked(handle, first.absolute_offset, first.buffer, std::nullopt, was_unaligned))
            {
                return false;
            }
            if (was_unaligned && observe_perf)
            {
                unaligned_write_perf_.Observe(0, static_cast<std::uint64_t>(first.buffer.size()));
            }
            index = merge_end;
            continue;
        }

        std::size_t chunk_begin = index;
        while (chunk_begin < merge_end)
        {
            std::uint64_t chunk_bytes_u64 = 0;
            std::size_t chunk_end = chunk_begin;
            while (chunk_end < merge_end)
            {
                const auto write_bytes = static_cast<std::uint64_t>(pending[chunk_end].buffer.size());
                if (write_bytes > kMaxMergedBatchBytes)
                {
                    if (chunk_end == chunk_begin)
                    {
                        ++chunk_end;
                    }
                    break;
                }
                if (chunk_bytes_u64 > (kMaxMergedBatchBytes - write_bytes))
                {
                    break;
                }
                chunk_bytes_u64 += write_bytes;
                ++chunk_end;
            }

            if (chunk_end == chunk_begin)
            {
                return false;
            }
            if (chunk_end == chunk_begin + 1)
            {
                const auto& write = pending[chunk_begin];
                if (!WriteLocked(handle, write.absolute_offset, write.buffer, std::nullopt, was_unaligned))
                {
                    return false;
                }
                if (was_unaligned && observe_perf)
                {
                    unaligned_write_perf_.Observe(0, static_cast<std::uint64_t>(write.buffer.size()));
                }
                chunk_begin = chunk_end;
                continue;
            }
            if (chunk_bytes_u64 > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
            {
                return false;
            }

            const auto chunk_bytes = static_cast<std::size_t>(chunk_bytes_u64);
            bool contiguous_view = false;
            if (pending[chunk_begin].merge_token != nullptr)
            {
                const auto* base_data = pending[chunk_begin].buffer.data();
                contiguous_view = base_data != nullptr;
                for (std::size_t current = chunk_begin + 1; contiguous_view && current < chunk_end; ++current)
                {
                    const auto expected_offset = pending[current].absolute_offset - pending[chunk_begin].absolute_offset;
                    const std::byte* expected_data = nullptr;
                    contiguous_view =
                        pending[current].merge_token == pending[chunk_begin].merge_token &&
                        AddOffsetToPointer(base_data, expected_offset, expected_data) &&
                        pending[current].buffer.data() == expected_data;
                }
            }
            if (contiguous_view)
            {
                const auto merged_view = std::span<const std::byte>(pending[chunk_begin].buffer.data(), chunk_bytes);
                if (!WriteLocked(handle, pending[chunk_begin].absolute_offset, merged_view, std::nullopt, was_unaligned))
                {
                    return false;
                }
                if (observe_perf)
                {
                    contiguous_batch_write_perf_.Observe(0, chunk_bytes_u64);
                    if (was_unaligned)
                    {
                        unaligned_write_perf_.Observe(0, chunk_bytes_u64);
                    }
                }
                chunk_begin = chunk_end;
                continue;
            }

            if (!EnsureMergedBatchScratch(chunk_bytes))
            {
                return false;
            }

            std::size_t copied_bytes = 0;
            for (std::size_t current = chunk_begin; current < chunk_end; ++current)
            {
                const auto& source = pending[current].buffer;
                if (source.size() > (merged_batch_scratch_capacity_ - copied_bytes))
                {
                    return false;
                }

                std::copy_n(
                    source.data(),
                    source.size(),
                    merged_batch_scratch_.get() + static_cast<std::ptrdiff_t>(copied_bytes));
                copied_bytes += source.size();
            }
            if (copied_bytes != chunk_bytes ||
                !WriteLocked(
                    handle,
                    pending[chunk_begin].absolute_offset,
                    std::span<const std::byte>(merged_batch_scratch_.get(), chunk_bytes),
                    std::nullopt,
                    was_unaligned))
            {
                return false;
            }
            merged_batch_direct_fill_count_.fetch_add(1, std::memory_order_relaxed);
            merged_batch_direct_fill_bytes_.fetch_add(chunk_bytes_u64, std::memory_order_relaxed);
            if (observe_perf)
            {
                merged_batch_write_perf_.Observe(0, chunk_bytes_u64);
                if (was_unaligned)
                {
                    unaligned_write_perf_.Observe(0, chunk_bytes_u64);
                }
            }
            chunk_begin = chunk_end;
        }
        index = merge_end;
    }

    return true;
}

bool BlockDevice::Flush()
{
    ScopedPerfTimer perf_scope(flush_perf_);

    if (IsFaultSwitchEnabled(L"APFSACCESS_RW_FAULT_FLUSH"))
    {
        return false;
    }

    std::unique_lock<std::mutex> write_lock(write_mutex_, std::defer_lock);
    {
        ScopedPerfTimer queue_wait_scope(flush_queue_wait_perf_);
        write_lock.lock();
    }
    HANDLE handle = EnsureWriteHandle();
    if (handle == INVALID_HANDLE_VALUE)
    {
        const auto error = GetLastError();
        last_io_error_.store(error == ERROR_SUCCESS ? ERROR_INVALID_HANDLE : error, std::memory_order_relaxed);
        return false;
    }

    if (FlushFileBuffers(handle) == FALSE)
    {
        const auto error = GetLastError();
        last_io_error_.store(error == ERROR_SUCCESS ? ERROR_WRITE_FAULT : error, std::memory_order_relaxed);
        return false;
    }

    last_io_error_.store(ERROR_SUCCESS, std::memory_order_relaxed);
    return true;
}

bool BlockDevice::WriteLocked(
    HANDLE handle,
    std::uint64_t absolute_offset_bytes,
    std::span<const std::byte> buffer,
    const std::optional<std::wstring>& fault_mode,
    bool& out_was_unaligned)
{
    out_was_unaligned = false;
    if (handle == INVALID_HANDLE_VALUE)
    {
        last_io_error_.store(ERROR_INVALID_HANDLE, std::memory_order_relaxed);
        return false;
    }
    if (buffer.empty())
    {
        return true;
    }
    if (buffer.size() > static_cast<std::size_t>(std::numeric_limits<DWORD>::max()))
    {
        last_io_error_.store(ERROR_INVALID_PARAMETER, std::memory_order_relaxed);
        return false;
    }
    if (fault_mode.has_value() &&
        (IsFaultMode(*fault_mode, L"1") ||
         IsFaultMode(*fault_mode, L"true") ||
         IsFaultMode(*fault_mode, L"yes") ||
         IsFaultMode(*fault_mode, L"fail")))
    {
        last_io_error_.store(ERROR_WRITE_FAULT, std::memory_order_relaxed);
        return false;
    }

    const auto block_size = static_cast<std::uint64_t>(LogicalBlockSize());
    const auto aligned_offset = AlignDown(absolute_offset_bytes, block_size);
    const auto prefix_bytes = static_cast<std::size_t>(absolute_offset_bytes - aligned_offset);
    if (buffer.size() > (std::numeric_limits<std::uint64_t>::max() - static_cast<std::uint64_t>(prefix_bytes)))
    {
        last_io_error_.store(ERROR_INVALID_PARAMETER, std::memory_order_relaxed);
        return false;
    }
    const auto requested_window = static_cast<std::uint64_t>(prefix_bytes) + static_cast<std::uint64_t>(buffer.size());
    const auto aligned_size_u64 = AlignUp(requested_window, block_size);
    if (aligned_size_u64 == 0 || aligned_size_u64 > static_cast<std::uint64_t>(std::numeric_limits<DWORD>::max()))
    {
        last_io_error_.store(ERROR_INVALID_PARAMETER, std::memory_order_relaxed);
        return false;
    }
    const auto aligned_size = static_cast<std::size_t>(aligned_size_u64);

    const bool already_aligned =
        prefix_bytes == 0 &&
        static_cast<std::uint64_t>(buffer.size()) == aligned_size_u64;
    out_was_unaligned = !already_aligned;

    const auto write_once = [&](const std::byte* write_buffer, std::size_t write_size) -> bool
    {
        DWORD bytes_written = 0;
        if (!WriteAt(handle, aligned_offset, write_buffer, static_cast<DWORD>(write_size), bytes_written))
        {
            return false;
        }

        return bytes_written == write_size;
    };

    if (!fault_mode.has_value())
    {
        if (already_aligned)
        {
            return write_once(buffer.data(), buffer.size());
        }

        if (write_scratch_.size() < aligned_size)
        {
            write_scratch_.resize(aligned_size);
            write_scratch_resize_count_.fetch_add(1, std::memory_order_relaxed);
            UpdateAtomicMax(write_scratch_max_bytes_, static_cast<std::uint64_t>(write_scratch_.size()));
        }
        DWORD bytes_read = 0;
        if (!ReadAt(handle, aligned_offset, write_scratch_.data(), static_cast<DWORD>(aligned_size), bytes_read) ||
            bytes_read != aligned_size)
        {
            return false;
        }
        std::copy(buffer.begin(), buffer.end(), write_scratch_.begin() + static_cast<std::ptrdiff_t>(prefix_bytes));
        return write_once(write_scratch_.data(), aligned_size);
    }

    if (IsFaultMode(*fault_mode, L"zero-bytes"))
    {
        return false;
    }

    if (IsFaultMode(*fault_mode, L"first-sector") ||
        IsFaultMode(*fault_mode, L"first-half") ||
        IsFaultMode(*fault_mode, L"all-except-last-sector") ||
        IsFaultMode(*fault_mode, L"corrupt-one-byte"))
    {
        const std::byte* write_buffer = buffer.data();
        std::size_t write_size = buffer.size();
        if (!already_aligned)
        {
            if (write_scratch_.size() < aligned_size)
            {
                write_scratch_.resize(aligned_size);
                write_scratch_resize_count_.fetch_add(1, std::memory_order_relaxed);
                UpdateAtomicMax(write_scratch_max_bytes_, static_cast<std::uint64_t>(write_scratch_.size()));
            }
            DWORD bytes_read = 0;
            if (!ReadAt(handle, aligned_offset, write_scratch_.data(), static_cast<DWORD>(aligned_size), bytes_read) ||
                bytes_read != aligned_size)
            {
                return false;
            }
            std::copy(buffer.begin(), buffer.end(), write_scratch_.begin() + static_cast<std::ptrdiff_t>(prefix_bytes));
            write_buffer = write_scratch_.data();
            write_size = aligned_size;
        }

        std::vector<std::byte> fault_buffer(write_buffer, write_buffer + write_size);
        std::size_t fault_write_size = fault_buffer.size();
        if (IsFaultMode(*fault_mode, L"first-sector"))
        {
            fault_write_size = std::min<std::size_t>(fault_write_size, static_cast<std::size_t>(block_size));
        }
        else if (IsFaultMode(*fault_mode, L"first-half"))
        {
            fault_write_size = std::max<std::size_t>(1, fault_write_size / 2);
        }
        else if (IsFaultMode(*fault_mode, L"all-except-last-sector"))
        {
            if (fault_write_size <= static_cast<std::size_t>(block_size))
            {
                fault_write_size = 0;
            }
            else
            {
                fault_write_size -= static_cast<std::size_t>(block_size);
            }
        }
        else
        {
            fault_buffer.front() ^= std::byte{0xff};
        }

        DWORD bytes_written = 0;
        if (fault_write_size > 0 &&
            !WriteAt(handle, aligned_offset, fault_buffer.data(), static_cast<DWORD>(fault_write_size), bytes_written))
        {
            return false;
        }
        return false;
    }

    return false;
}

bool BlockDevice::EnsureMergedBatchScratch(std::size_t bytes, std::size_t preserve_bytes)
{
    if (bytes == 0)
    {
        return true;
    }
    if (merged_batch_scratch_capacity_ >= bytes && merged_batch_scratch_)
    {
        return true;
    }

    auto scratch = std::make_unique_for_overwrite<std::byte[]>(bytes);
    if (preserve_bytes > 0 && merged_batch_scratch_)
    {
        const auto bytes_to_preserve = std::min(
            preserve_bytes,
            std::min(bytes, merged_batch_scratch_capacity_));
        std::copy_n(merged_batch_scratch_.get(), bytes_to_preserve, scratch.get());
    }
    merged_batch_scratch_ = std::move(scratch);
    merged_batch_scratch_capacity_ = bytes;
    merged_batch_scratch_resize_count_.fetch_add(1, std::memory_order_relaxed);
    UpdateAtomicMax(merged_batch_scratch_max_bytes_, static_cast<std::uint64_t>(bytes));
    return true;
}

bool BlockDevice::EnsureAsyncEventPool(std::size_t count)
{
    if (count == 0)
    {
        return true;
    }

    if (async_event_pool_.size() >= count)
    {
        return true;
    }

    async_event_pool_.reserve(count);
    while (async_event_pool_.size() < count)
    {
        HANDLE event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (event == nullptr)
        {
            return false;
        }

        async_event_pool_.push_back(event);
        async_event_create_count_.fetch_add(1, std::memory_order_relaxed);
        UpdateAtomicMax(async_event_pool_max_depth_, static_cast<std::uint64_t>(async_event_pool_.size()));
    }

    return true;
}

HANDLE BlockDevice::EnsureReadHandle() const
{
    auto handle = read_handle_.load(std::memory_order_acquire);
    if (handle != INVALID_HANDLE_VALUE)
    {
        return handle;
    }

    std::lock_guard<std::mutex> lock(handle_mutex_);
    handle = read_handle_.load(std::memory_order_relaxed);
    if (handle != INVALID_HANDLE_VALUE)
    {
        return handle;
    }

    handle = CreateFileW(
        path_.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
        nullptr);
    read_handle_.store(handle, std::memory_order_release);
    return handle;
}

HANDLE BlockDevice::EnsureWriteHandle() const
{
    auto handle = write_handle_.load(std::memory_order_acquire);
    if (handle != INVALID_HANDLE_VALUE)
    {
        return handle;
    }

    std::lock_guard<std::mutex> lock(handle_mutex_);
    handle = write_handle_.load(std::memory_order_relaxed);
    if (handle != INVALID_HANDLE_VALUE)
    {
        return handle;
    }

    handle = CreateFileW(
        path_.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
        nullptr);
    write_handle_.store(handle, std::memory_order_release);
    writable_.store(handle != INVALID_HANDLE_VALUE, std::memory_order_release);
    return handle;
}

void BlockDevice::CloseAsyncEventPoolLocked()
{
    for (HANDLE event : async_event_pool_)
    {
        if (event != INVALID_HANDLE_VALUE)
        {
            CloseHandle(event);
        }
    }
    async_event_pool_.clear();
}

void BlockDevice::CloseHandlesLocked() const
{
    const auto read_handle = read_handle_.exchange(INVALID_HANDLE_VALUE, std::memory_order_acq_rel);
    if (read_handle != INVALID_HANDLE_VALUE)
    {
        CloseHandle(read_handle);
    }
    const auto write_handle = write_handle_.exchange(INVALID_HANDLE_VALUE, std::memory_order_acq_rel);
    if (write_handle != INVALID_HANDLE_VALUE)
    {
        CloseHandle(write_handle);
    }
    writable_.store(false, std::memory_order_release);
}

bool BlockDevice::QueryGeometryLocked(HANDLE handle, Geometry& geometry) const
{
    geometry = Geometry{};

    LARGE_INTEGER file_size{};
    if (GetFileSizeEx(handle, &file_size))
    {
        geometry.total_bytes = static_cast<std::uint64_t>(file_size.QuadPart);
    }

    DWORD bytes_returned = 0;
    DISK_GEOMETRY_EX disk_geometry{};
    if (DeviceIoControl(
        handle,
        IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
        nullptr,
        0,
        &disk_geometry,
        sizeof(disk_geometry),
        &bytes_returned,
        nullptr))
    {
        geometry.total_bytes = static_cast<std::uint64_t>(disk_geometry.DiskSize.QuadPart);
        geometry.logical_block_size = std::max<std::uint32_t>(512u, disk_geometry.Geometry.BytesPerSector);
        geometry.physical_block_size = geometry.logical_block_size;
        if (geometry.total_bytes > base_offset_bytes_)
        {
            geometry.total_bytes -= base_offset_bytes_;
        }
        else
        {
            geometry.total_bytes = 0;
        }
        return geometry.total_bytes > 0;
    }

    GET_LENGTH_INFORMATION length_info{};
    if (DeviceIoControl(
        handle,
        IOCTL_DISK_GET_LENGTH_INFO,
        nullptr,
        0,
        &length_info,
        sizeof(length_info),
        &bytes_returned,
        nullptr))
    {
        geometry.total_bytes = static_cast<std::uint64_t>(length_info.Length.QuadPart);
        if (geometry.total_bytes > base_offset_bytes_)
        {
            geometry.total_bytes -= base_offset_bytes_;
        }
        else
        {
            geometry.total_bytes = 0;
        }
        return geometry.total_bytes > 0;
    }

    if (geometry.total_bytes > base_offset_bytes_)
    {
        geometry.total_bytes -= base_offset_bytes_;
    }
    else
    {
        geometry.total_bytes = 0;
    }

    return geometry.total_bytes > 0;
}

std::uint32_t BlockDevice::LogicalBlockSize() const
{
    auto cached_block_size = logical_block_size_cache_.load(std::memory_order_acquire);
    if (cached_block_size != 0)
    {
        return (std::max)(std::uint32_t{512}, cached_block_size);
    }

    std::lock_guard<std::mutex> lock(geometry_mutex_);
    cached_block_size = logical_block_size_cache_.load(std::memory_order_relaxed);
    if (cached_block_size != 0)
    {
        return (std::max)(std::uint32_t{512}, cached_block_size);
    }

    if (!geometry_cached_)
    {
        Geometry geometry{};
        HANDLE handle = EnsureReadHandle();
        if (handle != INVALID_HANDLE_VALUE && QueryGeometryLocked(handle, geometry))
        {
            geometry_cache_ = geometry;
            geometry_cached_ = true;
        }
    }

    const auto block_size = (std::max)(std::uint32_t{512}, geometry_cache_.logical_block_size);
    if (geometry_cached_)
    {
        logical_block_size_cache_.store(block_size, std::memory_order_release);
    }
    return block_size;
}

bool BlockDevice::ReadAt(
    HANDLE handle,
    std::uint64_t offset_bytes,
    void* buffer,
    DWORD bytes_to_read,
    DWORD& bytes_read) const
{
    ScopedPerfTimer perf_scope(raw_read_perf_, bytes_to_read);
    bytes_read = 0;
    const auto completion_event = CurrentBlockIoEvent().Ensure();
    if (completion_event == nullptr || !ResetEvent(completion_event))
    {
        const auto error = GetLastError();
        last_io_error_.store(error == ERROR_SUCCESS ? ERROR_NOT_ENOUGH_MEMORY : error, std::memory_order_relaxed);
        return false;
    }
    OVERLAPPED overlapped{};
    overlapped.Offset = static_cast<DWORD>(offset_bytes & 0xffffffffull);
    overlapped.OffsetHigh = static_cast<DWORD>(offset_bytes >> 32);
    overlapped.hEvent = completion_event;
    if (ReadFile(handle, buffer, bytes_to_read, &bytes_read, &overlapped))
    {
        return true;
    }

    const auto error = GetLastError();
    if (error != ERROR_IO_PENDING)
    {
        last_io_error_.store(error, std::memory_order_relaxed);
        return false;
    }

    DWORD completion_error = ERROR_SUCCESS;
    const auto completed = WaitForOverlappedCompletion(
        handle,
        overlapped,
        bytes_read,
        completion_error);
    if (!completed)
    {
        last_io_error_.store(
            completion_error == ERROR_SUCCESS ? ERROR_READ_FAULT : completion_error,
            std::memory_order_relaxed);
    }
    return completed;
}

bool BlockDevice::WriteAt(
    HANDLE handle,
    std::uint64_t offset_bytes,
    const void* buffer,
    DWORD bytes_to_write,
    DWORD& bytes_written) const
{
    bytes_written = 0;
    const auto completion_event = CurrentBlockIoEvent().Ensure();
    if (completion_event == nullptr || !ResetEvent(completion_event))
    {
        const auto error = GetLastError();
        last_io_error_.store(error == ERROR_SUCCESS ? ERROR_NOT_ENOUGH_MEMORY : error, std::memory_order_relaxed);
        return false;
    }
    OVERLAPPED overlapped{};
    overlapped.Offset = static_cast<DWORD>(offset_bytes & 0xffffffffull);
    overlapped.OffsetHigh = static_cast<DWORD>(offset_bytes >> 32);
    overlapped.hEvent = completion_event;
    if (WriteFile(handle, buffer, bytes_to_write, &bytes_written, &overlapped))
    {
        if (bytes_written == bytes_to_write)
        {
            return true;
        }
        last_io_error_.store(ERROR_WRITE_FAULT, std::memory_order_relaxed);
        return false;
    }

    const auto error = GetLastError();
    if (error != ERROR_IO_PENDING)
    {
        last_io_error_.store(error, std::memory_order_relaxed);
        return false;
    }

    DWORD completion_error = ERROR_SUCCESS;
    const auto completed = WaitForOverlappedCompletion(
        handle,
        overlapped,
        bytes_written,
        completion_error);
    if (!completed)
    {
        last_io_error_.store(
            completion_error == ERROR_SUCCESS ? ERROR_WRITE_FAULT : completion_error,
            std::memory_order_relaxed);
    }
    else if (bytes_written != bytes_to_write)
    {
        last_io_error_.store(ERROR_WRITE_FAULT, std::memory_order_relaxed);
        return false;
    }
    return completed;
}

bool BlockDevice::WaitForOverlappedCompletion(
    HANDLE handle,
    OVERLAPPED& overlapped,
    DWORD& transferred,
    DWORD& completion_error) const
{
    transferred = 0;
    completion_error = ERROR_SUCCESS;

    if (GetOverlappedResultEx(
            handle,
            &overlapped,
            &transferred,
            kOverlappedIoWaitTimeoutMs,
            FALSE))
    {
        return true;
    }

    const auto wait_error = GetLastError();
    if (wait_error != WAIT_TIMEOUT && wait_error != ERROR_IO_INCOMPLETE)
    {
        completion_error = wait_error == ERROR_SUCCESS ? ERROR_OPERATION_ABORTED : wait_error;
        return false;
    }

    async_wait_timeout_count_.fetch_add(1, std::memory_order_relaxed);
    (void)CancelIoEx(handle, &overlapped);
    async_cancel_count_.fetch_add(1, std::memory_order_relaxed);

    if (GetOverlappedResultEx(
            handle,
            &overlapped,
            &transferred,
            kOverlappedIoCancelWaitTimeoutMs,
            FALSE))
    {
        return true;
    }

    const auto cancel_wait_error = GetLastError();
    if (cancel_wait_error == WAIT_TIMEOUT || cancel_wait_error == ERROR_IO_INCOMPLETE)
    {
        async_cancel_wait_timeout_count_.fetch_add(1, std::memory_order_relaxed);
        // Never return while the caller-owned buffer can still be referenced
        // by the kernel. Cancellation is requested above; this final wait is
        // the safety boundary for the buffer lifetime, not a normal path. A
        // second deadline avoids leaving the host stuck forever; if the kernel
        // still owns the buffer, fail closed at the process boundary instead
        // of returning into a potentially invalid caller buffer.
        if (GetOverlappedResultEx(
                handle,
                &overlapped,
                &transferred,
                kOverlappedIoFinalWaitTimeoutMs,
                FALSE))
        {
            completion_error = ERROR_OPERATION_ABORTED;
        }
        else
        {
            const auto final_error = GetLastError();
            if (final_error == WAIT_TIMEOUT || final_error == ERROR_IO_INCOMPLETE)
            {
                FailClosedForUncancelableIo();
            }
            completion_error = final_error == ERROR_SUCCESS
                ? ERROR_OPERATION_ABORTED
                : final_error;
        }
        return false;
    }

    completion_error = cancel_wait_error == ERROR_SUCCESS
        ? ERROR_OPERATION_ABORTED
        : cancel_wait_error;
    return false;
}
} // namespace apfsaccess::rw
