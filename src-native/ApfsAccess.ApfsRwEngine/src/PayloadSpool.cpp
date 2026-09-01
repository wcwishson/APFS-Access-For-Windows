#include "PayloadSpool.h"

#include <algorithm>
#include <cstdlib>
#include <fstream>
#include <iterator>
#include <limits>
#include <mutex>
#include <optional>
#include <string_view>
#include <utility>
#include <vector>
#include <windows.h>
#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")

namespace apfsaccess::rw
{
struct PayloadReadHandleState
{
    explicit PayloadReadHandleState(HANDLE value)
        : handle(value)
    {
    }

    ~PayloadReadHandleState()
    {
        if (handle != INVALID_HANDLE_VALUE)
        {
            (void)CloseHandle(handle);
        }
    }

    HANDLE handle = INVALID_HANDLE_VALUE;
};

namespace
{
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

ThreadLocalOverlappedEvent& CurrentPayloadReadEvent()
{
    static thread_local ThreadLocalOverlappedEvent event;
    return event;
}

constexpr std::uint64_t kIndexMagic = 0x5844494c4f4f5350ull; // "PSPOOLIDX"
constexpr std::uint32_t kIndexVersion = 1;
constexpr std::uint64_t kIndexJournalMagic = 0x314c4e4a58444950ull; // "PIDXJNL1"
constexpr std::uint32_t kIndexJournalVersion = 1;
constexpr std::uint32_t kIndexJournalSnapshotFrame = 1;
constexpr std::uint32_t kIndexJournalAppendFrame = 2;
constexpr std::size_t kIndexJournalHeaderBytes = sizeof(std::uint64_t) +
    sizeof(std::uint32_t) + sizeof(std::uint32_t) +
    sizeof(std::uint64_t) + sizeof(std::uint64_t);
constexpr std::size_t kIndexRangeBytes = 7 * sizeof(std::uint64_t);
constexpr std::uint64_t kMaxInlineCoalesceBytes = 64ull * 1024ull;
constexpr std::uint64_t kMaxDirtyFlushBytes = 512ull * 1024ull * 1024ull;
constexpr std::uint64_t kMaxDirtyFlushAppends = 8192;
constexpr std::size_t kOverlayPayloadScratchMaxBytes = 256 * 1024;
constexpr std::size_t kOverlayPayloadScratchRetainMaxBytes = 4 * 1024 * 1024;
constexpr std::size_t kOverlayRangeSnapshotRetainMaxCount = 4096;
constexpr std::size_t kValidatedPayloadCacheMaxEntries = 64;
constexpr std::uint64_t kValidatedPayloadCacheMaxBytes = 4ull * 1024ull * 1024ull;
constexpr std::size_t kAppendMergePayloadScratchRetainMaxBytes = 256 * 1024;
constexpr std::uint64_t kFnvOffsetBasis = 14695981039346656037ull;
constexpr std::uint64_t kFnvPrime = 1099511628211ull;
constexpr DWORD kPayloadReadWaitTimeoutMs = 30'000;
constexpr DWORD kPayloadReadCancelWaitTimeoutMs = 5'000;
constexpr DWORD kPayloadReadFinalWaitTimeoutMs = 5'000;
constexpr UINT kUncancelablePayloadIoExitCode = 0xE2;

[[noreturn]] void FailClosedForUncancelablePayloadIo() noexcept
{
    OutputDebugStringW(L"[ApfsAccess] payload-spool I/O could not be cancelled before its safety deadline.\n");
    if (!TerminateProcess(GetCurrentProcess(), kUncancelablePayloadIoExitCode))
    {
        ExitProcess(kUncancelablePayloadIoExitCode);
    }
    std::abort();
}

bool WaitForPayloadRead(
    HANDLE handle,
    OVERLAPPED& overlapped,
    DWORD& bytes_read)
{
    if (GetOverlappedResultEx(
            handle,
            &overlapped,
            &bytes_read,
            kPayloadReadWaitTimeoutMs,
            FALSE))
    {
        return true;
    }

    auto error = GetLastError();
    if (error != WAIT_TIMEOUT && error != ERROR_IO_INCOMPLETE)
    {
        return false;
    }

    (void)CancelIoEx(handle, &overlapped);
    if (GetOverlappedResultEx(
            handle,
            &overlapped,
            &bytes_read,
            kPayloadReadCancelWaitTimeoutMs,
            FALSE))
    {
        return true;
    }

    error = GetLastError();
    if (error != WAIT_TIMEOUT && error != ERROR_IO_INCOMPLETE)
    {
        return false;
    }

    if (GetOverlappedResultEx(
            handle,
            &overlapped,
            &bytes_read,
            kPayloadReadFinalWaitTimeoutMs,
            FALSE))
    {
        return true;
    }

    error = GetLastError();
    if (error == WAIT_TIMEOUT || error == ERROR_IO_INCOMPLETE)
    {
        FailClosedForUncancelablePayloadIo();
    }
    return false;
}

struct ScopedMicrosecondCounter
{
    std::uint64_t& count;
    std::uint64_t& total;
    std::uint64_t& maximum;
    std::chrono::steady_clock::time_point started = std::chrono::steady_clock::now();

    ~ScopedMicrosecondCounter()
    {
        const auto elapsed = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - started).count());
        ++count;
        total += elapsed;
        maximum = (std::max)(maximum, elapsed);
    }
};

struct FileHandle
{
    HANDLE value = INVALID_HANDLE_VALUE;
    ~FileHandle()
    {
        if (value != INVALID_HANDLE_VALUE)
        {
            CloseHandle(value);
        }
    }
};

std::uint64_t RangeEnd(std::uint64_t offset, std::uint64_t bytes)
{
    if (offset > (std::numeric_limits<std::uint64_t>::max)() - bytes)
    {
        return (std::numeric_limits<std::uint64_t>::max)();
    }
    return offset + bytes;
}

void UpdatePayloadHash(std::uint64_t& hash, std::span<const std::byte> payload)
{
    for (const auto byte : payload)
    {
        hash ^= static_cast<std::uint8_t>(byte);
        hash *= kFnvPrime;
    }
}

std::uint64_t HashPayload(std::span<const std::byte> payload)
{
    std::uint64_t hash = kFnvOffsetBasis;
    UpdatePayloadHash(hash, payload);
    return hash;
}

struct Sha256Provider
{
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    DWORD object_bytes = 0;

    Sha256Provider()
    {
        DWORD result_bytes = 0;
        if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0 ||
            BCryptGetProperty(
                algorithm,
                BCRYPT_OBJECT_LENGTH,
                reinterpret_cast<PUCHAR>(&object_bytes),
                sizeof(object_bytes),
                &result_bytes,
                0) < 0 ||
            object_bytes == 0)
        {
            if (algorithm)
            {
                BCryptCloseAlgorithmProvider(algorithm, 0);
                algorithm = nullptr;
            }
            object_bytes = 0;
        }
    }

    ~Sha256Provider()
    {
        if (algorithm)
        {
            BCryptCloseAlgorithmProvider(algorithm, 0);
        }
    }

    Sha256Provider(const Sha256Provider&) = delete;
    Sha256Provider& operator=(const Sha256Provider&) = delete;
};

Sha256Provider& SharedSha256Provider()
{
    static Sha256Provider provider;
    return provider;
}

struct ReusableSha256Hasher
{
    BCRYPT_HASH_HANDLE hash = nullptr;
    std::vector<std::uint8_t> hash_object;

    ReusableSha256Hasher() = default;

    ~ReusableSha256Hasher()
    {
        Reset();
    }

    ReusableSha256Hasher(const ReusableSha256Hasher&) = delete;
    ReusableSha256Hasher& operator=(const ReusableSha256Hasher&) = delete;

    bool Hash(
        std::span<const std::byte> payload,
        std::array<std::uint8_t, 32>& digest,
        std::uint64_t* checksum)
    {
        digest.fill(0);
        if (checksum)
        {
            *checksum = kFnvOffsetBasis;
        }
        if (!EnsureInitialized())
        {
            return false;
        }

        bool ok = true;
        std::size_t cursor = 0;
        while (ok && cursor < payload.size())
        {
            const auto chunk_bytes = static_cast<ULONG>((std::min)(
                payload.size() - cursor,
                static_cast<std::size_t>((std::numeric_limits<ULONG>::max)())));
            const auto chunk = payload.subspan(cursor, chunk_bytes);
            if (checksum)
            {
                UpdatePayloadHash(*checksum, chunk);
            }
            ok = BCryptHashData(
                hash,
                reinterpret_cast<PUCHAR>(const_cast<std::byte*>(chunk.data())),
                chunk_bytes,
                0) >= 0;
            cursor += chunk_bytes;
        }
        if (ok)
        {
            ok = BCryptFinishHash(hash, digest.data(), static_cast<ULONG>(digest.size()), 0) >= 0;
        }
        if (!ok)
        {
            digest.fill(0);
            if (checksum)
            {
                *checksum = 0;
            }
            Reset();
        }
        return ok;
    }

private:
    bool EnsureInitialized()
    {
        if (hash)
        {
            return true;
        }

        const auto& provider = SharedSha256Provider();
        if (!provider.algorithm || provider.object_bytes == 0)
        {
            return false;
        }
        hash_object.resize(provider.object_bytes);
        if (BCryptCreateHash(
                provider.algorithm,
                &hash,
                hash_object.data(),
                static_cast<ULONG>(hash_object.size()),
                nullptr,
                0,
                BCRYPT_HASH_REUSABLE_FLAG) < 0)
        {
            hash = nullptr;
            hash_object.clear();
            return false;
        }
        return true;
    }

    void Reset()
    {
        if (hash)
        {
            BCryptDestroyHash(hash);
            hash = nullptr;
        }
        hash_object.clear();
    }
};

bool HashPayloadDigests(
    std::span<const std::byte> payload,
    std::uint64_t* checksum,
    std::array<std::uint8_t, 32>& digest)
{
    thread_local ReusableSha256Hasher hasher;
    return hasher.Hash(payload, digest, checksum);
}

bool HashPayloadSha256(
    std::span<const std::byte> payload,
    std::array<std::uint8_t, 32>& digest)
{
    return HashPayloadDigests(payload, nullptr, digest);
}

std::uint64_t HashIndexBytes(std::span<const std::byte> bytes)
{
    return HashPayload(bytes);
}

void UpdateOldestDirtyRange(
    std::chrono::steady_clock::time_point& oldest_dirty_range_created_at,
    bool& oldest_dirty_range_tracked,
    const std::chrono::steady_clock::time_point& candidate)
{
    if (!oldest_dirty_range_tracked || candidate < oldest_dirty_range_created_at)
    {
        oldest_dirty_range_created_at = candidate;
        oldest_dirty_range_tracked = true;
    }
}

void AppendU32(std::vector<std::byte>& buffer, std::uint32_t value)
{
    for (int shift = 0; shift < 32; shift += 8)
    {
        buffer.push_back(static_cast<std::byte>((value >> shift) & 0xffu));
    }
}

void AppendU64(std::vector<std::byte>& buffer, std::uint64_t value)
{
    for (int shift = 0; shift < 64; shift += 8)
    {
        buffer.push_back(static_cast<std::byte>((value >> shift) & 0xffu));
    }
}

bool ReadU32(const std::vector<std::byte>& buffer, std::size_t& cursor, std::uint32_t& value)
{
    if (cursor > buffer.size() || buffer.size() - cursor < sizeof(std::uint32_t))
    {
        return false;
    }

    value = 0;
    for (int shift = 0; shift < 32; shift += 8)
    {
        value |= static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(buffer[cursor++])) << shift;
    }
    return true;
}

bool ReadU64(const std::vector<std::byte>& buffer, std::size_t& cursor, std::uint64_t& value)
{
    if (cursor > buffer.size() || buffer.size() - cursor < sizeof(std::uint64_t))
    {
        return false;
    }

    value = 0;
    for (int shift = 0; shift < 64; shift += 8)
    {
        value |= static_cast<std::uint64_t>(std::to_integer<std::uint8_t>(buffer[cursor++])) << shift;
    }
    return true;
}

bool FlushPathToDisk(const std::filesystem::path& path)
{
    const auto wide_path = path.wstring();
    FileHandle handle
    {
        CreateFileW(
            wide_path.c_str(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr)
    };
    return handle.value != INVALID_HANDLE_VALUE && FlushFileBuffers(handle.value) != FALSE;
}

bool MoveReplaceWriteThrough(const std::filesystem::path& from, const std::filesystem::path& to)
{
    const auto from_wide = from.wstring();
    const auto to_wide = to.wstring();
    return MoveFileExW(
        from_wide.c_str(),
        to_wide.c_str(),
        MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != FALSE;
}

std::filesystem::path ReadEnvironmentPath(const char* name)
{
    char* value = nullptr;
    std::size_t value_size = 0;
    if (_dupenv_s(&value, &value_size, name) != 0 || !value || value_size <= 1)
    {
        if (value)
        {
            std::free(value);
        }
        return {};
    }

    std::filesystem::path path(value);
    std::free(value);
    return path;
}

bool ReadEnvironmentFlag(const char* name)
{
    char* value = nullptr;
    std::size_t value_size = 0;
    if (_dupenv_s(&value, &value_size, name) != 0 || !value)
    {
        if (value)
        {
            std::free(value);
        }
        return false;
    }

    const std::string flag(value);
    std::free(value);
    return flag == "1" || flag == "true" || flag == "on";
}

bool ReadPerfCountersEnabled()
{
    char* value = nullptr;
    std::size_t value_size = 0;
    if (_dupenv_s(&value, &value_size, "APFSACCESS_PERF_COUNTERS") == 0 && value)
    {
        const bool enabled = value[0] != '\0' && value[0] != '0';
        std::free(value);
        return enabled;
    }
    if (value)
    {
        std::free(value);
    }

    std::error_code ec;
    auto marker = std::filesystem::temp_directory_path(ec);
    if (ec)
    {
        return false;
    }
    marker /= "ApfsAccess";
    marker /= "perf-counters.enabled";
    return std::filesystem::exists(marker, ec) && !ec;
}

std::uint64_t SaturatingAdd(std::uint64_t lhs, std::uint64_t rhs) noexcept
{
    return rhs > (std::numeric_limits<std::uint64_t>::max)() - lhs
        ? (std::numeric_limits<std::uint64_t>::max)()
        : lhs + rhs;
}
} // namespace

PayloadSpool::PayloadSpool(Options options)
    : options_(std::move(options))
    , perf_counters_enabled_(ReadPerfCountersEnabled())
{
    if (options_.root.empty())
    {
        options_.root = ResolveDefaultRoot();
    }
    spool_file_ = options_.root / "payload-spool.bin";
    index_file_ = options_.root / "payload-spool.idx";
    index_delta_enabled_ = !ReadEnvironmentFlag("APFSACCESS_DISABLE_INDEX_DELTA");
    const auto index_loaded = LoadIndex();
    recovery_required_ = recovery_required_ || !index_loaded;
}

std::unique_lock<std::mutex> PayloadSpool::AcquireMutex() const
{
    if (!perf_counters_enabled_)
    {
        return std::unique_lock<std::mutex>(mutex_);
    }

    const auto started = std::chrono::steady_clock::now();
    std::unique_lock<std::mutex> lock(mutex_);
    const auto elapsed = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - started).count());
    mutex_wait_count_ = SaturatingAdd(mutex_wait_count_, 1);
    mutex_wait_microseconds_ = SaturatingAdd(mutex_wait_microseconds_, elapsed);
    mutex_wait_max_microseconds_ = (std::max)(mutex_wait_max_microseconds_, elapsed);

    std::size_t bucket = 0;
    auto bucket_value = elapsed;
    while (bucket_value > 1 && bucket + 1 < kMutexWaitBucketCount)
    {
        bucket_value >>= 1;
        ++bucket;
    }
    mutex_wait_buckets_[bucket] = SaturatingAdd(mutex_wait_buckets_[bucket], 1);
    return lock;
}

std::uint64_t PayloadSpool::MutexWaitPercentileLocked(
    std::uint64_t numerator,
    std::uint64_t denominator) const noexcept
{
    if (mutex_wait_count_ == 0 || mutex_wait_max_microseconds_ == 0 ||
        numerator == 0 || numerator > denominator || denominator > 20)
    {
        return mutex_wait_max_microseconds_;
    }

    const auto target =
        (mutex_wait_count_ / denominator) * numerator +
        (((mutex_wait_count_ % denominator) * numerator + denominator - 1) / denominator);
    std::uint64_t cumulative = 0;
    for (std::size_t bucket = 0; bucket < kMutexWaitBucketCount; ++bucket)
    {
        cumulative = SaturatingAdd(cumulative, mutex_wait_buckets_[bucket]);
        if (cumulative >= target)
        {
            return (std::min)(1ull << bucket, mutex_wait_max_microseconds_);
        }
    }
    return mutex_wait_max_microseconds_;
}

PayloadSpool::~PayloadSpool()
{
    auto lock = AcquireMutex();
    (void)CloseAppendStreamLocked();
    ClosePayloadReadHandleLocked();
    (void)CloseIndexJournalStreamLocked();
}

bool PayloadSpool::Append(const WriteRequest& request, AppendResult* result)
{
    return AppendWithStatus(request, result) == AppendStatus::Succeeded;
}

PayloadSpool::AppendStatus PayloadSpool::CheckAppendCapacity(std::uint64_t payload_bytes) const
{
    auto lock = AcquireMutex();
    return CheckAppendCapacityLocked(payload_bytes);
}

PayloadSpool::AppendStatus PayloadSpool::CheckAppendCapacityFast(std::uint64_t payload_bytes) const
{
    if (payload_bytes == 0)
    {
        return AppendStatus::InvalidRequest;
    }

    const auto offset_hint = next_spool_offset_hint_.load(std::memory_order_acquire);
    if (payload_bytes <= (std::numeric_limits<std::uint64_t>::max)() - offset_hint &&
        (options_.max_bytes == 0 ||
         (offset_hint <= options_.max_bytes &&
          payload_bytes <= options_.max_bytes - offset_hint)))
    {
        return AppendStatus::Succeeded;
    }

    auto lock = AcquireMutex();
    return CheckAppendCapacityLocked(payload_bytes);
}

void PayloadSpool::PublishNextSpoolOffsetHintLocked() noexcept
{
    next_spool_offset_hint_.store(next_spool_offset_, std::memory_order_release);
}

PayloadSpool::AppendStatus PayloadSpool::AppendWithStatus(const WriteRequest& request, AppendResult* result)
{
    if (result)
    {
        *result = {};
    }
    if (!IsVolumeMatch(request.volume_identity) ||
        request.object_id == 0 ||
        request.payload.empty() ||
        request.payload.size() > static_cast<std::size_t>((std::numeric_limits<std::uint64_t>::max)() - request.logical_offset))
    {
        return AppendStatus::InvalidRequest;
    }

    auto lock = AcquireMutex();

    const auto request_begin = request.logical_offset;
    const auto request_end = request.logical_offset + static_cast<std::uint64_t>(request.payload.size());
    auto merged_begin = request_begin;
    auto merged_end = request_end;
    const DirtyRangeLookupKey lookup_key{
        request.object_id,
        request.generation,
        request.wal_sequence,
    };
    auto& merged_indices = append_merge_indices_scratch_;
    merged_indices.clear();
    auto& merged = append_merge_payload_scratch_;
    if (merged.capacity() > kAppendMergePayloadScratchRetainMaxBytes)
    {
        std::vector<std::byte>().swap(merged);
    }
    merged.clear();
    if (auto lookup = range_lookup_.find(lookup_key); lookup != range_lookup_.end())
    {
        for (const auto index : lookup->second)
        {
            if (index >= ranges_.size())
            {
                continue;
            }
            const auto& range = ranges_[index];
            const auto range_begin = range.logical_offset;
            const auto range_end = RangeEnd(range.logical_offset, range.bytes);
            const auto touches = range_begin <= merged_end && range_end >= merged_begin;
            const auto would_merge_begin = (std::min)(merged_begin, range_begin);
            const auto would_merge_end = (std::max)(merged_end, range_end);
            const auto would_merge_bytes = would_merge_end - would_merge_begin;
            if (!touches || would_merge_bytes > kMaxInlineCoalesceBytes)
            {
                continue;
            }

            merged_begin = would_merge_begin;
            merged_end = would_merge_end;
            merged_indices.push_back(index);
        }
    }

    const bool used_direct_append = merged_indices.empty();
    std::span<const std::byte> payload_to_append;
    std::uint64_t appended_logical_offset = request_begin;
    std::uint64_t appended_bytes = static_cast<std::uint64_t>(request.payload.size());
    std::uint64_t appended_checksum = 0;
    std::array<std::uint8_t, 32> appended_sha256{};
    if (used_direct_append)
    {
        payload_to_append = request.payload;
    }
    else
    {
        const auto merged_bytes_u64 = merged_end - merged_begin;
        if (merged_bytes_u64 > static_cast<std::uint64_t>((std::numeric_limits<std::size_t>::max)()))
        {
            return AppendStatus::StorageFailure;
        }
        merged.assign(static_cast<std::size_t>(merged_bytes_u64), std::byte{0});
        for (const auto range_index : merged_indices)
        {
            if (range_index >= ranges_.size())
            {
                return AppendStatus::StorageFailure;
            }
            const auto& range = ranges_[range_index];
            const auto destination_offset = static_cast<std::size_t>(range.logical_offset - merged_begin);
            if (destination_offset > merged.size() ||
                range.bytes > static_cast<std::uint64_t>(merged.size() - destination_offset))
            {
                return AppendStatus::StorageFailure;
            }
            if (!ReadRangePayloadIntoHandleLocked(
                    range,
                    std::span<std::byte>(
                        merged.data() + static_cast<std::ptrdiff_t>(destination_offset),
                        static_cast<std::size_t>(range.bytes))))
            {
                return AppendStatus::StorageFailure;
            }
        }

        const auto new_offset = static_cast<std::size_t>(request_begin - merged_begin);
        if (new_offset > merged.size() || request.payload.size() > (merged.size() - new_offset))
        {
            return AppendStatus::StorageFailure;
        }
        std::copy(
            request.payload.begin(),
            request.payload.end(),
            merged.begin() + static_cast<std::ptrdiff_t>(new_offset));
        payload_to_append = std::span<const std::byte>(merged.data(), merged.size());
        appended_logical_offset = merged_begin;
        appended_bytes = merged_bytes_u64;
    }

    if (!HashPayloadDigests(payload_to_append, &appended_checksum, appended_sha256))
    {
        return AppendStatus::StorageFailure;
    }

    const auto flush_bytes = options_.durable_flush_bytes == 0
        ? 0
        : (std::min)(options_.durable_flush_bytes, kMaxDirtyFlushBytes);
    const auto flush_appends = options_.durable_flush_appends == 0
        ? 0
        : (std::min)(options_.durable_flush_appends, kMaxDirtyFlushAppends);
    const bool should_flush_after_append =
        (flush_bytes > 0 &&
         (bytes_since_sync_ >= flush_bytes ||
          appended_bytes >= (flush_bytes - bytes_since_sync_))) ||
        (flush_appends > 0 &&
         (appends_since_sync_ >= flush_appends ||
          1 >= (flush_appends - appends_since_sync_)));
    if (!used_direct_append)
    {
        std::sort(merged_indices.begin(), merged_indices.end());
    }

    struct AppendRollbackRange
    {
        std::size_t index = 0;
        DirtyRange range{};
    };

    struct AppendRollbackGuard
    {
        std::uint64_t next_spool_offset = 0;
        std::uint64_t bytes_since_sync = 0;
        std::uint64_t appends_since_sync = 0;
        bool index_dirty = false;
        bool index_requires_snapshot = false;
        std::size_t original_range_count = 0;
        std::size_t merged_front_index = 0;
        DirtyRange replaced_range{};
        std::size_t pending_index_additions_size = 0;
        std::vector<AppendRollbackRange> removed_ranges;
    };
    std::optional<AppendRollbackGuard> rollback_guard;
    if (should_flush_after_append)
    {
        rollback_guard.emplace();
        rollback_guard->next_spool_offset = next_spool_offset_;
        rollback_guard->bytes_since_sync = bytes_since_sync_;
        rollback_guard->appends_since_sync = appends_since_sync_;
        rollback_guard->index_dirty = index_dirty_;
        rollback_guard->index_requires_snapshot = index_requires_snapshot_;
        rollback_guard->original_range_count = ranges_.size();
        rollback_guard->pending_index_additions_size = pending_index_additions_.size();
        if (!used_direct_append)
        {
            rollback_guard->merged_front_index = merged_indices.front();
            rollback_guard->replaced_range = ranges_[merged_indices.front()];
            rollback_guard->removed_ranges.reserve(merged_indices.size() - 1);
            for (std::size_t index = 1; index < merged_indices.size(); ++index)
            {
                rollback_guard->removed_ranges.push_back({
                    merged_indices[index],
                    ranges_[merged_indices[index]],
                });
            }
        }
        ++append_rollback_snapshot_count_;
    }

    std::uint64_t spool_offset = 0;
    const auto capacity_status = CheckAppendCapacityLocked(
        static_cast<std::uint64_t>(payload_to_append.size()));
    if (capacity_status != AppendStatus::Succeeded)
    {
        return capacity_status;
    }
    if (!AppendBytes(payload_to_append, spool_offset))
    {
        return AppendStatus::StorageFailure;
    }

    DirtyRange range{};
    range.object_id = request.object_id;
    range.generation = request.generation;
    range.logical_offset = appended_logical_offset;
    range.bytes = appended_bytes;
    range.spool_offset = spool_offset;
    range.wal_sequence = request.wal_sequence;
    range.checksum = appended_checksum;
    range.created_at = std::chrono::steady_clock::now();
    UpdateOldestDirtyRange(oldest_dirty_range_created_at_, oldest_dirty_range_tracked_, range.created_at);

    if (merged_indices.empty())
    {
        ranges_.push_back(range);
        const auto range_index = ranges_.size() - 1;
        range_lookup_[lookup_key].push_back(range_index);
        const auto object_key = DirtyRangeObjectKey{
            range.object_id,
            range.generation,
        };
        auto& object_indices = range_object_lookup_[object_key];
        if (object_indices.empty() || RangeIndexPrecedes(object_indices.back(), range_index))
        {
            object_indices.push_back(range_index);
        }
        else
        {
            const auto insertion = std::lower_bound(
                object_indices.begin(),
                object_indices.end(),
                range_index,
                [this](std::size_t lhs, std::size_t rhs)
                {
                    return RangeIndexPrecedes(lhs, rhs);
                });
            object_indices.insert(insertion, range_index);
        }
        const auto range_end = RangeEnd(range.logical_offset, range.bytes);
        auto& max_end = range_object_max_end_[object_key];
        if (range_end > max_end)
        {
            max_end = range_end;
        }
        auto [min_offset_it, min_offset_inserted] = range_object_min_offset_.try_emplace(object_key, range.logical_offset);
        if (!min_offset_inserted && range.logical_offset < min_offset_it->second)
        {
            min_offset_it->second = range.logical_offset;
        }
        if (index_delta_enabled_ && !index_requires_snapshot_)
        {
            pending_index_additions_.push_back(range);
        }
    }
    else
    {
        const auto first_index = merged_indices.front();
        ranges_[first_index] = range;
        std::size_t removed_index = 1;
        std::size_t write_index = first_index + 1;
        for (std::size_t read_index = first_index + 1; read_index < ranges_.size(); ++read_index)
        {
            while (removed_index < merged_indices.size() &&
                   merged_indices[removed_index] < read_index)
            {
                ++removed_index;
            }
            if (removed_index < merged_indices.size() &&
                merged_indices[removed_index] == read_index)
            {
                ++removed_index;
                continue;
            }
            if (write_index != read_index)
            {
                ranges_[write_index] = std::move(ranges_[read_index]);
            }
            ++write_index;
        }
        ranges_.resize(write_index);
        RebuildRangeLookup();
        RecomputeOldestDirtyRangeLocked();
        if (index_delta_enabled_)
        {
            index_requires_snapshot_ = true;
        }
    }
    range_sequences_.insert(range.wal_sequence);
    UpdateMinimumDirtyWalSequence(range.wal_sequence);
    index_dirty_ = true;

    const bool should_flush =
        (flush_bytes > 0 && bytes_since_sync_ >= flush_bytes) ||
        (flush_appends > 0 && appends_since_sync_ >= flush_appends);
    if (!should_flush)
    {
        if (used_direct_append)
        {
            ++append_direct_count_;
        }
        else
        {
            ++append_merged_count_;
        }
        if (result)
        {
            *result = {
                range.object_id,
                range.generation,
                range.logical_offset,
                range.bytes,
                range.spool_offset,
                range.wal_sequence,
                range.checksum,
                appended_sha256,
            };
        }
        return AppendStatus::Succeeded;
    }

    if (!FlushDirtyStateLocked())
    {
        if (rollback_guard.has_value())
        {
            auto& guard = *rollback_guard;
            bool restored_ranges = true;
            if (used_direct_append)
            {
                if (ranges_.size() == guard.original_range_count + 1)
                {
                    ranges_.resize(guard.original_range_count);
                }
                else
                {
                    restored_ranges = false;
                }
            }
            else if (ranges_.size() == guard.original_range_count - guard.removed_ranges.size() &&
                     guard.merged_front_index < ranges_.size())
            {
                ranges_[guard.merged_front_index] = guard.replaced_range;
                for (const auto& removed : guard.removed_ranges)
                {
                    if (removed.index > ranges_.size())
                    {
                        restored_ranges = false;
                        break;
                    }
                    ranges_.insert(
                        ranges_.begin() + static_cast<std::ptrdiff_t>(removed.index),
                        removed.range);
                }
            }
            else
            {
                restored_ranges = false;
            }

            if (restored_ranges)
            {
                RebuildRangeSequenceIndex();
                RebuildRangeLookup();
                RecomputeOldestDirtyRangeLocked();
            }
            else
            {
                recovery_required_ = true;
            }
            if (pending_index_additions_.size() >= guard.pending_index_additions_size)
            {
                pending_index_additions_.resize(guard.pending_index_additions_size);
            }
            else
            {
                recovery_required_ = true;
            }
            next_spool_offset_ = guard.next_spool_offset;
            bytes_since_sync_ = guard.bytes_since_sync;
            appends_since_sync_ = guard.appends_since_sync;
            index_dirty_ = guard.index_dirty;
            index_requires_snapshot_ = guard.index_requires_snapshot;
            PublishNextSpoolOffsetHintLocked();
            if (!TruncateSpoolFileBestEffort(guard.next_spool_offset))
            {
                recovery_required_ = true;
            }
        }
        return AppendStatus::StorageFailure;
    }
    if (used_direct_append)
    {
        ++append_direct_count_;
    }
    else
    {
        ++append_merged_count_;
    }
    if (result)
    {
        *result = {
            range.object_id,
            range.generation,
            range.logical_offset,
            range.bytes,
            range.spool_offset,
            range.wal_sequence,
            range.checksum,
            appended_sha256,
        };
    }
    return AppendStatus::Succeeded;
}

bool PayloadSpool::ReadPersistedRange(
    const PersistedRangeReference& reference,
    std::vector<std::byte>& payload) const
{
    payload.clear();
    if (!IsVolumeMatch(reference.volume_identity) ||
        reference.object_id == 0 ||
        reference.payload_length == 0 ||
        reference.wal_sequence == 0 ||
        std::all_of(
            reference.payload_sha256.begin(),
            reference.payload_sha256.end(),
            [](std::uint8_t byte) { return byte == 0; }))
    {
        return false;
    }

    auto lock = AcquireMutex();
    const DirtyRangeLookupKey lookup_key{
        reference.object_id,
        reference.generation,
        reference.wal_sequence,
    };
    const auto lookup = range_lookup_.find(lookup_key);
    if (lookup == range_lookup_.end())
    {
        // A raw spool offset and SHA-256 do not authenticate object identity.
        // Rebuild the index from the complete validated WAL reference set first.
        return false;
    }

    const DirtyRange* matched_range = nullptr;
    for (const auto index : lookup->second)
    {
        if (index >= ranges_.size())
        {
            return false;
        }
        const auto& range = ranges_[index];
        if (range.logical_offset == reference.logical_offset &&
            range.bytes == reference.payload_length &&
            range.spool_offset == reference.spool_offset)
        {
            if (matched_range)
            {
                return false;
            }
            matched_range = &range;
        }
    }
    if (!matched_range || !ReadRangePayloadFromHandleLocked(*matched_range, payload))
    {
        payload.clear();
        return false;
    }

    std::array<std::uint8_t, 32> actual_sha256{};
    if (!HashPayloadSha256(payload, actual_sha256) || actual_sha256 != reference.payload_sha256)
    {
        payload.clear();
        return false;
    }
    return true;
}

bool PayloadSpool::FlushDirtyState()
{
    auto lock = AcquireMutex();
    return FlushDirtyStateLocked();
}

bool PayloadSpool::FlushPayloadBytes()
{
    auto lock = AcquireMutex();
    return FlushPayloadBytesLocked(true);
}

bool PayloadSpool::RebuildIndexFromReferences(
    std::span<const PersistedRangeReference> references,
    std::uint64_t safe_discard_sequence,
    std::span<const PersistedRangeReference> discardable_references)
{
    auto lock = AcquireMutex();

    std::unordered_map<std::uint64_t, const PersistedRangeReference*> discardable_by_sequence;
    discardable_by_sequence.reserve(discardable_references.size());
    for (const auto& reference : discardable_references)
    {
        if (!IsVolumeMatch(reference.volume_identity) ||
            reference.object_id == 0 ||
            reference.payload_length == 0 ||
            reference.wal_sequence == 0 ||
            std::all_of(
                reference.payload_sha256.begin(),
                reference.payload_sha256.end(),
                [](std::uint8_t byte) { return byte == 0; }) ||
            reference.logical_offset > (std::numeric_limits<std::uint64_t>::max)() - reference.payload_length ||
            reference.spool_offset > (std::numeric_limits<std::uint64_t>::max)() - reference.payload_length ||
            !discardable_by_sequence.emplace(reference.wal_sequence, &reference).second)
        {
            return false;
        }
    }

    std::vector<DirtyRange> recovered_ranges;
    recovered_ranges.reserve(references.size());
    std::ifstream payload_input;
    std::vector<std::byte> payload;
    for (const auto& reference : references)
    {
        if (!IsVolumeMatch(reference.volume_identity) ||
            reference.object_id == 0 ||
            reference.payload_length == 0 ||
            reference.wal_sequence == 0 ||
            reference.wal_sequence <= safe_discard_sequence ||
            std::all_of(
                reference.payload_sha256.begin(),
                reference.payload_sha256.end(),
                [](std::uint8_t byte) { return byte == 0; }) ||
            reference.logical_offset > (std::numeric_limits<std::uint64_t>::max)() - reference.payload_length ||
            reference.spool_offset > (std::numeric_limits<std::uint64_t>::max)() - reference.payload_length ||
            RangeEnd(reference.spool_offset, reference.payload_length) > next_spool_offset_)
        {
            return false;
        }
        if (discardable_by_sequence.contains(reference.wal_sequence))
        {
            return false;
        }

        if (!payload_input.is_open() && !OpenPayloadReadStream(payload_input))
        {
            return false;
        }

        DirtyRange recovered{};
        recovered.object_id = reference.object_id;
        recovered.generation = reference.generation;
        recovered.logical_offset = reference.logical_offset;
        recovered.bytes = reference.payload_length;
        recovered.spool_offset = reference.spool_offset;
        recovered.wal_sequence = reference.wal_sequence;
        if (!ReadRangePayloadFromStream(payload_input, recovered, payload, false))
        {
            return false;
        }

        std::array<std::uint8_t, 32> actual_sha256{};
        if (!HashPayloadSha256(payload, actual_sha256) || actual_sha256 != reference.payload_sha256)
        {
            return false;
        }

        const auto duplicate = std::find_if(
            recovered_ranges.begin(),
            recovered_ranges.end(),
            [&](const DirtyRange& existing)
            {
                return existing.wal_sequence == recovered.wal_sequence;
            });
        if (duplicate != recovered_ranges.end())
        {
            if (duplicate->object_id != recovered.object_id ||
                duplicate->generation != recovered.generation ||
                duplicate->logical_offset != recovered.logical_offset ||
                duplicate->bytes != recovered.bytes ||
                duplicate->spool_offset != recovered.spool_offset)
            {
                return false;
            }
            continue;
        }
        recovered.checksum = HashPayload(payload);
        recovered.created_at = std::chrono::steady_clock::now();
        recovered_ranges.push_back(recovered);
    }

    bool ambiguous_existing_range = false;
    for (const auto& existing : ranges_)
    {
        if (existing.wal_sequence <= safe_discard_sequence)
        {
            continue;
        }

        const auto matching_recovered = std::find_if(
            recovered_ranges.begin(),
            recovered_ranges.end(),
            [&](const DirtyRange& recovered)
            {
                return recovered.wal_sequence == existing.wal_sequence;
            });
        if (matching_recovered == recovered_ranges.end())
        {
            const auto discardable = discardable_by_sequence.find(existing.wal_sequence);
            if (discardable == discardable_by_sequence.end())
            {
                ambiguous_existing_range = true;
                recovered_ranges.push_back(existing);
            }
            else if (discardable->second->object_id != existing.object_id ||
                     discardable->second->generation != existing.generation ||
                     discardable->second->logical_offset != existing.logical_offset ||
                     discardable->second->payload_length != existing.bytes ||
                     discardable->second->spool_offset != existing.spool_offset)
            {
                return false;
            }
        }
        else if (matching_recovered->object_id != existing.object_id ||
                 matching_recovered->generation != existing.generation ||
                 matching_recovered->logical_offset != existing.logical_offset ||
                 matching_recovered->bytes != existing.bytes ||
                 matching_recovered->spool_offset != existing.spool_offset)
        {
            return false;
        }
    }

    std::sort(
        recovered_ranges.begin(),
        recovered_ranges.end(),
        [](const DirtyRange& lhs, const DirtyRange& rhs)
        {
            if (lhs.spool_offset != rhs.spool_offset)
            {
                return lhs.spool_offset < rhs.spool_offset;
            }
            return lhs.wal_sequence < rhs.wal_sequence;
        });

    std::uint64_t indexed_end = 0;
    for (const auto& range : recovered_ranges)
    {
        indexed_end = (std::max)(indexed_end, RangeEnd(range.spool_offset, range.bytes));
    }
    bool tail_accounted_for = next_spool_offset_ == 0 ||
        (!references.empty() && indexed_end == next_spool_offset_);
    if (!tail_accounted_for)
    {
        tail_accounted_for = std::any_of(
            discardable_references.begin(),
            discardable_references.end(),
            [&](const PersistedRangeReference& reference)
            {
                return reference.spool_offset <= next_spool_offset_ &&
                       next_spool_offset_ <= RangeEnd(reference.spool_offset, reference.payload_length);
            });
    }
    const auto complete = !ambiguous_existing_range && tail_accounted_for;
    if (!complete)
    {
        return false;
    }

    if (recovered_ranges.empty() && !discardable_references.empty())
    {
        if (!ReplaceLiveRangesPreservingOffsets({}))
        {
            return false;
        }
        recovery_required_ = false;
        return true;
    }

    ranges_ = std::move(recovered_ranges);
    RebuildRangeSequenceIndex();
    RebuildRangeLookup();
    RecomputeOldestDirtyRangeLocked();
    recovery_required_ = false;
    index_dirty_ = true;
    index_requires_snapshot_ = true;
    pending_index_additions_.clear();
    return true;
}

bool PayloadSpool::TryOverlaySingleDirtyRange(
    const ReadRequest& request,
    std::size_t& bytes_overlayed,
    bool require_full_coverage,
    bool& handled,
    std::uint64_t* logical_end,
    std::unique_lock<std::mutex>* existing_lock,
    const std::vector<std::size_t>** reused_lookup) const
{
    handled = false;
    bytes_overlayed = 0;
    if (reused_lookup)
    {
        *reused_lookup = nullptr;
    }
    if (logical_end)
    {
        *logical_end = 0;
    }

    DirtyRange range{};
    std::shared_ptr<PayloadReadHandleState> handle_state;
    std::span<std::byte> direct_destination;
    std::size_t source_offset = 0;
    std::size_t destination_offset = 0;
    std::size_t copy_bytes = 0;
    bool direct_destination_read = false;
    std::shared_ptr<const std::vector<std::byte>> cached_payload;
    std::unique_lock<std::mutex> local_lock;
    auto* metadata_lock = existing_lock;
    if (!metadata_lock)
    {
        local_lock = AcquireMutex();
        metadata_lock = &local_lock;
    }

    {
        if (recovery_required_)
        {
            handled = true;
            return false;
        }

        const auto request_begin = request.logical_offset;
        const auto request_end = request.logical_offset +
            static_cast<std::uint64_t>(request.destination.size());
        const auto key = DirtyRangeObjectKey{
            request.object_id,
            request.generation,
        };

        const auto cached_max_end = range_object_max_end_.find(key);
        if (cached_max_end != range_object_max_end_.end())
        {
            if (logical_end)
            {
                *logical_end = cached_max_end->second;
            }
            if (request_begin >= cached_max_end->second)
            {
                ++object_lookup_query_count_;
                handled = true;
                return !require_full_coverage;
            }
        }
        if (const auto cached = range_object_min_offset_.find(key);
            cached != range_object_min_offset_.end() &&
            request_end <= cached->second)
        {
            ++object_lookup_query_count_;
            handled = true;
            return !require_full_coverage;
        }

        const auto lookup = range_object_lookup_.find(key);
        ++object_lookup_index_probe_count_;
        if (lookup == range_object_lookup_.end())
        {
            ++object_lookup_query_count_;
            handled = true;
            return !require_full_coverage;
        }
        if (lookup->second.size() != 1)
        {
            if (reused_lookup && existing_lock)
            {
                *reused_lookup = &lookup->second;
            }
            return false;
        }

        handled = true;
        ++object_lookup_query_count_;
        object_lookup_candidate_count_ += lookup->second.size();
        const auto index = lookup->second.front();
        if (index >= ranges_.size())
        {
            return !require_full_coverage;
        }

        range = ranges_[index];
        if (range.bytes > static_cast<std::uint64_t>((std::numeric_limits<std::size_t>::max)()))
        {
            return false;
        }
        const auto range_begin = range.logical_offset;
        const auto range_end = RangeEnd(range.logical_offset, range.bytes);
        if (logical_end && range_end > *logical_end)
        {
            *logical_end = range_end;
        }
        if (range_end <= request_begin || range_begin >= request_end)
        {
            return !require_full_coverage;
        }
        if (require_full_coverage &&
            (range_begin > request_begin || range_end < request_end))
        {
            return false;
        }

        if (range_begin >= request_begin && range_end <= request_end)
        {
            destination_offset = static_cast<std::size_t>(range_begin - request_begin);
            const auto range_bytes = static_cast<std::size_t>(range.bytes);
            if (destination_offset > request.destination.size() ||
                range_bytes > request.destination.size() - destination_offset)
            {
                return false;
            }
            direct_destination = request.destination.subspan(destination_offset, range_bytes);
            copy_bytes = range_bytes;
            direct_destination_read = true;
        }
        else
        {
            const auto copy_begin = (std::max)(request_begin, range_begin);
            const auto copy_end = (std::min)(request_end, range_end);
            if (copy_end <= copy_begin)
            {
                return !require_full_coverage;
            }
            source_offset = static_cast<std::size_t>(copy_begin - range_begin);
            destination_offset = static_cast<std::size_t>(copy_begin - request_begin);
            copy_bytes = static_cast<std::size_t>(copy_end - copy_begin);
            if (source_offset > static_cast<std::size_t>(range.bytes) ||
                copy_bytes > static_cast<std::size_t>(range.bytes) - source_offset ||
                destination_offset > request.destination.size() ||
                copy_bytes > request.destination.size() - destination_offset)
            {
                return false;
            }
        }

        if (!direct_destination_read)
        {
            cached_payload = FindValidatedPayloadLocked(range);
        }
        if (!cached_payload)
        {
            handle_state = EnsurePayloadReadHandleLocked();
            if (!handle_state)
            {
                return false;
            }
            ++range_payload_positional_read_count_;
        }
    }

    metadata_lock->unlock();
    if (cached_payload)
    {
        if (source_offset > cached_payload->size() ||
            copy_bytes > cached_payload->size() - source_offset ||
            destination_offset > request.destination.size() ||
            copy_bytes > request.destination.size() - destination_offset)
        {
            return false;
        }
        std::copy(
            cached_payload->begin() + static_cast<std::ptrdiff_t>(source_offset),
            cached_payload->begin() + static_cast<std::ptrdiff_t>(source_offset + copy_bytes),
            request.destination.begin() + static_cast<std::ptrdiff_t>(destination_offset));
        bytes_overlayed = copy_bytes;
        return true;
    }

    if (direct_destination_read)
    {
        std::shared_lock payload_io_lock(payload_io_mutex_);
        if (!ReadRangePayloadIntoHandle(handle_state, range, direct_destination))
        {
            return false;
        }
        payload_io_lock.unlock();
        bytes_overlayed = copy_bytes;
        auto lock = AcquireMutex();
        ++overlay_direct_destination_read_count_;
        return true;
    }

    std::shared_ptr<std::vector<std::byte>> owned_payload;
    std::vector<std::byte> local_payload;
    std::vector<std::byte>* payload = &local_payload;
    if (range.bytes <= kValidatedPayloadCacheMaxBytes)
    {
        owned_payload = std::make_shared<std::vector<std::byte>>(static_cast<std::size_t>(range.bytes));
        payload = owned_payload.get();
    }
    else
    {
        local_payload.resize(static_cast<std::size_t>(range.bytes));
    }

    {
        std::shared_lock payload_io_lock(payload_io_mutex_);
        if (!ReadRangePayloadIntoHandle(
                handle_state,
                range,
                std::span<std::byte>(payload->data(), payload->size())) ||
            payload->size() != range.bytes)
        {
            return false;
        }
    }

    if (source_offset > payload->size() ||
        copy_bytes > payload->size() - source_offset ||
        destination_offset > request.destination.size() ||
        copy_bytes > request.destination.size() - destination_offset)
    {
        return false;
    }

    std::copy(
        payload->begin() + static_cast<std::ptrdiff_t>(source_offset),
        payload->begin() + static_cast<std::ptrdiff_t>(source_offset + copy_bytes),
        request.destination.begin() + static_cast<std::ptrdiff_t>(destination_offset));
    if (owned_payload)
    {
        auto immutable_payload = std::shared_ptr<const std::vector<std::byte>>(std::move(owned_payload));
        auto lock = AcquireMutex();
        RememberValidatedPayloadLocked(range, std::move(immutable_payload));
    }
    bytes_overlayed = copy_bytes;
    return true;
}

bool PayloadSpool::OverlayDirtyRanges(const ReadRequest& request, std::size_t& bytes_overlayed) const
{
    bytes_overlayed = 0;
    if (!IsVolumeMatch(request.volume_identity) ||
        request.object_id == 0 ||
        request.destination.empty() ||
        request.destination.size() > static_cast<std::size_t>((std::numeric_limits<std::uint64_t>::max)() - request.logical_offset))
    {
        return false;
    }

    auto lock = AcquireMutex();
    bool handled = false;
    const std::vector<std::size_t>* reused_lookup = nullptr;
    const auto fast_result = TryOverlaySingleDirtyRange(
        request,
        bytes_overlayed,
        false,
        handled,
        nullptr,
        &lock,
        &reused_lookup);
    if (handled)
    {
        return fast_result;
    }

    return OverlayDirtyRangesMultiRange(
        request,
        bytes_overlayed,
        false,
        nullptr,
        &lock,
        reused_lookup);
}

bool PayloadSpool::OverlayDirtyRangesWithLogicalEnd(
    const ReadRequest& request,
    std::size_t& bytes_overlayed,
    std::uint64_t& logical_end) const
{
    bytes_overlayed = 0;
    logical_end = 0;
    if (!IsVolumeMatch(request.volume_identity) ||
        request.object_id == 0 ||
        request.destination.size() > static_cast<std::size_t>((std::numeric_limits<std::uint64_t>::max)() - request.logical_offset))
    {
        return false;
    }

    auto lock = AcquireMutex();
    bool handled = false;
    const std::vector<std::size_t>* reused_lookup = nullptr;
    const auto fast_result = TryOverlaySingleDirtyRange(
        request,
        bytes_overlayed,
        false,
        handled,
        &logical_end,
        &lock,
        &reused_lookup);
    if (handled)
    {
        return fast_result;
    }

    return OverlayDirtyRangesMultiRange(
        request,
        bytes_overlayed,
        false,
        &logical_end,
        &lock,
        reused_lookup);
}

bool PayloadSpool::ReadFullyCoveredRange(const ReadRequest& request, std::size_t& bytes_overlayed) const
{
    bytes_overlayed = 0;
    if (!IsVolumeMatch(request.volume_identity) ||
        request.object_id == 0 ||
        request.destination.empty() ||
        request.destination.size() > static_cast<std::size_t>((std::numeric_limits<std::uint64_t>::max)() - request.logical_offset))
    {
        return false;
    }

    auto lock = AcquireMutex();
    bool handled = false;
    const std::vector<std::size_t>* reused_lookup = nullptr;
    const auto fast_result = TryOverlaySingleDirtyRange(
        request,
        bytes_overlayed,
        true,
        handled,
        nullptr,
        &lock,
        &reused_lookup);
    if (handled)
    {
        return fast_result;
    }

    return OverlayDirtyRangesMultiRange(
        request,
        bytes_overlayed,
        true,
        nullptr,
        &lock,
        reused_lookup);
}

bool PayloadSpool::OverlayDirtyRangesMultiRange(
    const ReadRequest& request,
    std::size_t& bytes_overlayed,
    bool require_full_coverage,
    std::uint64_t* logical_end,
    std::unique_lock<std::mutex>* existing_lock,
    const std::vector<std::size_t>* reused_lookup) const
{
    bytes_overlayed = 0;
    if (logical_end && !reused_lookup)
    {
        *logical_end = 0;
    }

    static thread_local std::vector<DirtyRange> reusable_range_snapshot;
    static thread_local std::vector<std::shared_ptr<const std::vector<std::byte>>>
        reusable_payload_cache_snapshot;
    std::vector<DirtyRange> oversized_range_snapshot;
    std::vector<std::shared_ptr<const std::vector<std::byte>>> oversized_payload_cache_snapshot;
    std::vector<DirtyRange>* range_snapshot = &reusable_range_snapshot;
    auto* payload_cache_snapshot = &reusable_payload_cache_snapshot;
    std::shared_ptr<PayloadReadHandleState> handle_state;
    std::size_t covered_bytes = 0;
    std::unique_lock<std::mutex> local_lock;
    auto* metadata_lock = existing_lock;
    if (!metadata_lock)
    {
        local_lock = AcquireMutex();
        metadata_lock = &local_lock;
    }

    {
        if (recovery_required_)
        {
            return false;
        }

        const auto request_begin = request.logical_offset;
        const auto request_end = request.logical_offset +
            static_cast<std::uint64_t>(request.destination.size());
        const auto key = DirtyRangeObjectKey{
            request.object_id,
            request.generation,
        };
        const auto cached_max_end = range_object_max_end_.find(key);
        if (!reused_lookup && cached_max_end != range_object_max_end_.end())
        {
            if (logical_end)
            {
                *logical_end = cached_max_end->second;
            }
            if (request_begin >= cached_max_end->second)
            {
                return !require_full_coverage;
            }
        }
        if (!reused_lookup)
        {
            const auto cached = range_object_min_offset_.find(key);
            if (cached != range_object_min_offset_.end() &&
                request_end <= cached->second)
            {
                return !require_full_coverage;
            }
        }

        const auto* lookup_indices = reused_lookup;
        if (!lookup_indices)
        {
            const auto lookup = range_object_lookup_.find(key);
            ++object_lookup_index_probe_count_;
            if (lookup == range_object_lookup_.end())
            {
                return !require_full_coverage;
            }
            lookup_indices = &lookup->second;
        }
        ++object_lookup_query_count_;
        object_lookup_candidate_count_ += lookup_indices->size();

        if (lookup_indices->size() <= 1)
        {
            return OverlayDirtyRangesLocked(request, bytes_overlayed, require_full_coverage, logical_end);
        }

        auto& covered_ranges = overlay_covered_ranges_scratch_;
        covered_ranges.clear();
        covered_ranges.reserve(lookup_indices->size());

        if (lookup_indices->size() > kOverlayRangeSnapshotRetainMaxCount)
        {
            range_snapshot = &oversized_range_snapshot;
            payload_cache_snapshot = &oversized_payload_cache_snapshot;
        }
        else
        {
            if (reusable_range_snapshot.capacity() > kOverlayRangeSnapshotRetainMaxCount)
            {
                std::vector<DirtyRange>().swap(reusable_range_snapshot);
            }
            reusable_range_snapshot.clear();
            if (reusable_payload_cache_snapshot.capacity() > kOverlayRangeSnapshotRetainMaxCount)
            {
                std::vector<std::shared_ptr<const std::vector<std::byte>>>().swap(
                    reusable_payload_cache_snapshot);
            }
            reusable_payload_cache_snapshot.clear();
        }
        range_snapshot->reserve(lookup_indices->size());
        for (const auto index : *lookup_indices)
        {
            if (index >= ranges_.size())
            {
                if (require_full_coverage)
                {
                    return false;
                }
                continue;
            }

            const auto& range = ranges_[index];
            if (range.bytes > static_cast<std::uint64_t>((std::numeric_limits<std::size_t>::max)()))
            {
                return false;
            }
            const auto range_begin = range.logical_offset;
            const auto range_end = RangeEnd(range.logical_offset, range.bytes);
            if (logical_end && cached_max_end == range_object_max_end_.end() &&
                range_end > *logical_end)
            {
                *logical_end = range_end;
            }
            if (range_end <= request_begin || range_begin >= request_end)
            {
                continue;
            }

            const auto covered_begin = (std::max)(request_begin, range_begin);
            const auto covered_end = (std::min)(request_end, range_end);
            if (covered_begin < covered_end)
            {
                covered_ranges.emplace_back(covered_begin, covered_end);
            }
            range_snapshot->push_back(range);
        }

        // The payload ranges remain in WAL order below so overlapping writes
        // retain last-writer-wins semantics. Only the coverage union needs
        // logical ordering; sorting it once avoids quadratic insert/erase
        // work when a file has many outstanding random writes.
        if (covered_ranges.size() > 1)
        {
            std::sort(
                covered_ranges.begin(),
                covered_ranges.end(),
                [](const auto& lhs, const auto& rhs)
                {
                    return lhs.first < rhs.first ||
                           (lhs.first == rhs.first && lhs.second < rhs.second);
                });
            std::size_t merged_count = 0;
            for (const auto& range : covered_ranges)
            {
                if (merged_count == 0 || covered_ranges[merged_count - 1].second < range.first)
                {
                    covered_ranges[merged_count++] = range;
                    continue;
                }
                covered_ranges[merged_count - 1].second =
                    (std::max)(covered_ranges[merged_count - 1].second, range.second);
            }
            covered_ranges.resize(merged_count);
        }

        if (require_full_coverage &&
            (covered_ranges.size() != 1 ||
             covered_ranges.front().first > request_begin ||
             covered_ranges.front().second < request_end))
        {
            return false;
        }

        for (const auto& [begin, end] : covered_ranges)
        {
            covered_bytes += static_cast<std::size_t>(end - begin);
        }
        if (range_snapshot->empty())
        {
            return true;
        }

        payload_cache_snapshot->clear();
        payload_cache_snapshot->reserve(range_snapshot->size());
        std::size_t uncached_range_count = 0;
        for (const auto& range : *range_snapshot)
        {
            auto cached_payload = FindValidatedPayloadLocked(range);
            if (!cached_payload)
            {
                ++uncached_range_count;
            }
            payload_cache_snapshot->push_back(std::move(cached_payload));
        }

        if (uncached_range_count != 0)
        {
            handle_state = EnsurePayloadReadHandleLocked();
            if (!handle_state)
            {
                return false;
            }
            range_payload_positional_read_count_ += uncached_range_count;
        }
    }

    metadata_lock->unlock();
    std::size_t direct_reads_succeeded = 0;
    std::shared_lock payload_io_lock(payload_io_mutex_, std::defer_lock);
    const auto finish = [&](bool success)
    {
        if (payload_io_lock.owns_lock())
        {
            payload_io_lock.unlock();
        }
        if (direct_reads_succeeded != 0)
        {
            auto lock = AcquireMutex();
            overlay_direct_destination_read_count_ = SaturatingAdd(
                overlay_direct_destination_read_count_,
                static_cast<std::uint64_t>(direct_reads_succeeded));
        }
        return success;
    };

    std::vector<std::pair<DirtyRange, std::shared_ptr<const std::vector<std::byte>>>> cache_fills;
    cache_fills.reserve(payload_cache_snapshot->size());
    if (std::any_of(
            payload_cache_snapshot->begin(),
            payload_cache_snapshot->end(),
            [](const auto& cached_payload)
            {
                return cached_payload == nullptr;
            }))
    {
        payload_io_lock.lock();
    }
    static thread_local std::vector<std::byte> reusable_payload;
    std::vector<std::byte> oversized_payload;
    const auto select_payload_buffer = [&](std::uint64_t bytes) -> std::vector<std::byte>*
    {
        if (bytes <= kOverlayPayloadScratchRetainMaxBytes)
        {
            reusable_payload.clear();
            reusable_payload.resize(static_cast<std::size_t>(bytes));
            return &reusable_payload;
        }
        oversized_payload.clear();
        oversized_payload.resize(static_cast<std::size_t>(bytes));
        return &oversized_payload;
    };

    for (std::size_t range_index = 0; range_index < range_snapshot->size(); ++range_index)
    {
        const auto& range = (*range_snapshot)[range_index];
        const auto& cached_payload = (*payload_cache_snapshot)[range_index];
        const auto request_begin = request.logical_offset;
        const auto request_end = request.logical_offset +
            static_cast<std::uint64_t>(request.destination.size());
        const auto range_begin = range.logical_offset;
        const auto range_end = RangeEnd(range.logical_offset, range.bytes);
        if (range_end <= request_begin || range_begin >= request_end)
        {
            continue;
        }

        if (cached_payload)
        {
            const auto copy_begin = (std::max)(request_begin, range_begin);
            const auto copy_end = (std::min)(request_end, range_end);
            const auto source_offset = static_cast<std::size_t>(copy_begin - range_begin);
            const auto destination_offset = static_cast<std::size_t>(copy_begin - request_begin);
            const auto copy_bytes = static_cast<std::size_t>(copy_end - copy_begin);
            if (source_offset > cached_payload->size() ||
                copy_bytes > cached_payload->size() - source_offset ||
                destination_offset > request.destination.size() ||
                copy_bytes > request.destination.size() - destination_offset)
            {
                return finish(false);
            }
            std::copy(
                cached_payload->begin() + static_cast<std::ptrdiff_t>(source_offset),
                cached_payload->begin() + static_cast<std::ptrdiff_t>(source_offset + copy_bytes),
                request.destination.begin() + static_cast<std::ptrdiff_t>(destination_offset));
            continue;
        }

        if (range_begin >= request_begin && range_end <= request_end)
        {
            const auto destination_offset = static_cast<std::size_t>(range_begin - request_begin);
            const auto range_bytes = static_cast<std::size_t>(range.bytes);
            if (destination_offset > request.destination.size() ||
                range_bytes > request.destination.size() - destination_offset ||
                !ReadRangePayloadIntoHandle(
                    handle_state,
                    range,
                    request.destination.subspan(destination_offset, range_bytes)))
            {
                return finish(false);
            }
            ++direct_reads_succeeded;
            continue;
        }

        std::shared_ptr<std::vector<std::byte>> owned_payload;
        std::vector<std::byte>* payload = nullptr;
        if (range.bytes <= kValidatedPayloadCacheMaxBytes)
        {
            owned_payload = std::make_shared<std::vector<std::byte>>(static_cast<std::size_t>(range.bytes));
            payload = owned_payload.get();
        }
        else
        {
            payload = select_payload_buffer(range.bytes);
        }
        if (!ReadRangePayloadIntoHandle(
                handle_state,
                range,
                std::span<std::byte>(payload->data(), payload->size())) ||
            payload->size() != range.bytes)
        {
            return finish(false);
        }

        const auto copy_begin = (std::max)(request_begin, range_begin);
        const auto copy_end = (std::min)(request_end, range_end);
        const auto source_offset = static_cast<std::size_t>(copy_begin - range_begin);
        const auto destination_offset = static_cast<std::size_t>(copy_begin - request_begin);
        const auto copy_bytes = static_cast<std::size_t>(copy_end - copy_begin);
        if (source_offset > payload->size() ||
            copy_bytes > payload->size() - source_offset ||
            destination_offset > request.destination.size() ||
            copy_bytes > request.destination.size() - destination_offset)
        {
            return finish(false);
        }

        std::copy(
            payload->begin() + static_cast<std::ptrdiff_t>(source_offset),
            payload->begin() + static_cast<std::ptrdiff_t>(source_offset + copy_bytes),
            request.destination.begin() + static_cast<std::ptrdiff_t>(destination_offset));
        if (owned_payload)
        {
            cache_fills.emplace_back(
                range,
                std::shared_ptr<const std::vector<std::byte>>(std::move(owned_payload)));
        }
    }

    if (payload_io_lock.owns_lock())
    {
        payload_io_lock.unlock();
    }
    if (!cache_fills.empty())
    {
        auto lock = AcquireMutex();
        for (auto& [range, payload] : cache_fills)
        {
            RememberValidatedPayloadLocked(range, std::move(payload));
        }
    }
    bytes_overlayed = covered_bytes;
    return finish(true);
}

bool PayloadSpool::OverlayDirtyRangesLocked(
    const ReadRequest& request,
    std::size_t& bytes_overlayed,
    bool require_full_coverage,
    std::uint64_t* logical_end) const
{
    if (logical_end)
    {
        *logical_end = 0;
    }
    if (recovery_required_)
    {
        return false;
    }

    const auto request_begin = request.logical_offset;
    const auto request_end = request.logical_offset + static_cast<std::uint64_t>(request.destination.size());
    ++object_lookup_query_count_;
    const auto key = DirtyRangeObjectKey{
        request.object_id,
        request.generation,
    };
    const auto cached_max_end = range_object_max_end_.find(key);
    if (cached_max_end != range_object_max_end_.end())
    {
        if (logical_end)
        {
            *logical_end = cached_max_end->second;
        }
        if (request_begin >= cached_max_end->second)
        {
            return !require_full_coverage;
        }
    }
    if (const auto cached = range_object_min_offset_.find(key); cached != range_object_min_offset_.end() &&
        request_end <= cached->second)
    {
        return !require_full_coverage;
    }

    const auto lookup = range_object_lookup_.find(key);
    ++object_lookup_index_probe_count_;
    if (lookup != range_object_lookup_.end())
    {
        object_lookup_candidate_count_ += lookup->second.size();
        if (logical_end && cached_max_end == range_object_max_end_.end())
        {
            for (const auto index : lookup->second)
            {
                if (index >= ranges_.size())
                {
                    continue;
                }

                const auto range_end = RangeEnd(ranges_[index].logical_offset, ranges_[index].bytes);
                if (range_end > *logical_end)
                {
                    *logical_end = range_end;
                }
            }
        }
    }

    auto& covered_ranges = overlay_covered_ranges_scratch_;
    covered_ranges.clear();
    overlay_payload_scratch_.clear();
    std::vector<std::byte> oversized_payload;
    overlay_oversized_payload_scratch_.clear();
    const auto select_payload_buffer = [&](std::uint64_t bytes) -> std::vector<std::byte>*
    {
        if (bytes <= kOverlayPayloadScratchMaxBytes)
        {
            return &overlay_payload_scratch_;
        }
        if (bytes <= kOverlayPayloadScratchRetainMaxBytes)
        {
            return &overlay_oversized_payload_scratch_;
        }
        oversized_payload.clear();
        return &oversized_payload;
    };
    const auto add_covered_range = [&](std::uint64_t begin, std::uint64_t end)
    {
        if (begin >= end)
        {
            return;
        }

        auto insert_begin = begin;
        auto insert_end = end;
        auto it = covered_ranges.begin();
        while (it != covered_ranges.end())
        {
            if (it->second < insert_begin)
            {
                ++it;
                continue;
            }
            if (insert_end < it->first)
            {
                break;
            }

            insert_begin = (std::min)(insert_begin, it->first);
            insert_end = (std::max)(insert_end, it->second);
            it = covered_ranges.erase(it);
        }

        covered_ranges.insert(it, { insert_begin, insert_end });
    };

    if (lookup == range_object_lookup_.end())
    {
        return !require_full_coverage;
    }

    if (require_full_coverage && lookup->second.size() == 1)
    {
        const auto index = lookup->second.front();
        if (index >= ranges_.size())
        {
            return false;
        }

        const auto& range = ranges_[index];
        const auto range_begin = range.logical_offset;
        const auto range_end = RangeEnd(range.logical_offset, range.bytes);
        if (range_begin > request_begin || range_end < request_end)
        {
            return false;
        }

        if (range_begin == request_begin && range_end == request_end)
        {
            if (!ReadRangePayloadIntoHandleLocked(range, request.destination))
            {
                return false;
            }

            ++overlay_direct_destination_read_count_;
            bytes_overlayed = request.destination.size();
            return true;
        }

        auto* payload = select_payload_buffer(range.bytes);
        if (!ReadRangePayloadFromHandleLocked(range, *payload) || payload->size() != range.bytes)
        {
            return false;
        }

        const auto source_offset = static_cast<std::size_t>(request_begin - range_begin);
        if (source_offset > payload->size() ||
            request.destination.size() > payload->size() - source_offset)
        {
            return false;
        }

        std::copy(
            payload->begin() + static_cast<std::ptrdiff_t>(source_offset),
            payload->begin() + static_cast<std::ptrdiff_t>(source_offset + request.destination.size()),
            request.destination.begin());
        bytes_overlayed = request.destination.size();
        return true;
    }

    if (require_full_coverage)
    {
        for (const auto index : lookup->second)
        {
            if (index >= ranges_.size())
            {
                return false;
            }

            const auto& range = ranges_[index];
            const auto range_begin = range.logical_offset;
            const auto range_end = RangeEnd(range.logical_offset, range.bytes);
            if (range_end <= request_begin || range_begin >= request_end)
            {
                continue;
            }

            add_covered_range(
                (std::max)(request_begin, range_begin),
                (std::min)(request_end, range_end));
            if (covered_ranges.size() == 1 &&
                covered_ranges.front().first <= request_begin &&
                covered_ranges.front().second >= request_end)
            {
                break;
            }
        }

        if (covered_ranges.size() != 1 ||
            covered_ranges.front().first > request_begin ||
            covered_ranges.front().second < request_end)
        {
            return false;
        }

        covered_ranges.clear();
    }

    if (lookup->second.size() == 1)
    {
        const auto index = lookup->second.front();
        if (index >= ranges_.size())
        {
            return !require_full_coverage;
        }

        const auto& range = ranges_[index];
        const auto range_begin = range.logical_offset;
        const auto range_end = RangeEnd(range.logical_offset, range.bytes);
        if (range_end <= request_begin || range_begin >= request_end)
        {
            return true;
        }

        if (range_begin >= request_begin && range_end <= request_end)
        {
            const auto destination_offset = static_cast<std::size_t>(range_begin - request_begin);
            const auto range_bytes = static_cast<std::size_t>(range.bytes);
            if (destination_offset > request.destination.size() ||
                range_bytes > (request.destination.size() - destination_offset) ||
                !ReadRangePayloadIntoHandleLocked(
                    range,
                    request.destination.subspan(destination_offset, range_bytes)))
            {
                return false;
            }

            ++overlay_direct_destination_read_count_;
            bytes_overlayed = range_bytes;
            return true;
        }

        auto* payload = select_payload_buffer(range.bytes);
        if (!ReadRangePayloadFromHandleLocked(range, *payload) || payload->size() != range.bytes)
        {
            return false;
        }

        const auto copy_begin = (std::max)(request_begin, range_begin);
        const auto copy_end = (std::min)(request_end, range_end);
        const auto source_offset = static_cast<std::size_t>(copy_begin - range_begin);
        const auto destination_offset = static_cast<std::size_t>(copy_begin - request_begin);
        const auto copy_bytes = static_cast<std::size_t>(copy_end - copy_begin);
        if (source_offset > payload->size() ||
            copy_bytes > (payload->size() - source_offset) ||
            destination_offset > request.destination.size() ||
            copy_bytes > (request.destination.size() - destination_offset))
        {
            return false;
        }

        std::copy(
            payload->begin() + static_cast<std::ptrdiff_t>(source_offset),
            payload->begin() + static_cast<std::ptrdiff_t>(source_offset + copy_bytes),
            request.destination.begin() + static_cast<std::ptrdiff_t>(destination_offset));
        bytes_overlayed = copy_bytes;
        return true;
    }

    covered_ranges.reserve(lookup->second.size());
    for (const auto index : lookup->second)
    {
        if (index >= ranges_.size())
        {
            continue;
        }
        const auto& range = ranges_[index];
        const auto range_begin = range.logical_offset;
        const auto range_end = RangeEnd(range.logical_offset, range.bytes);
        if (range_end <= request_begin || range_begin >= request_end)
        {
            continue;
        }

        if (range_begin >= request_begin && range_end <= request_end)
        {
            const auto destination_offset = static_cast<std::size_t>(range_begin - request_begin);
            const auto range_bytes = static_cast<std::size_t>(range.bytes);
            if (destination_offset > request.destination.size() ||
                range_bytes > (request.destination.size() - destination_offset) ||
                !ReadRangePayloadIntoHandleLocked(
                    range,
                    request.destination.subspan(destination_offset, range_bytes)))
            {
                return false;
            }

            ++overlay_direct_destination_read_count_;
            add_covered_range(range_begin, range_end);
            continue;
        }

        auto* payload = select_payload_buffer(range.bytes);
        if (!ReadRangePayloadFromHandleLocked(range, *payload) || payload->size() != range.bytes)
        {
            return false;
        }

        const auto copy_begin = (std::max)(request_begin, range_begin);
        const auto copy_end = (std::min)(request_end, range_end);
        const auto source_offset = static_cast<std::size_t>(copy_begin - range_begin);
        const auto destination_offset = static_cast<std::size_t>(copy_begin - request_begin);
        const auto copy_bytes = static_cast<std::size_t>(copy_end - copy_begin);
        if (source_offset > payload->size() ||
            copy_bytes > (payload->size() - source_offset) ||
            destination_offset > request.destination.size() ||
            copy_bytes > (request.destination.size() - destination_offset))
        {
            return false;
        }

        std::copy(
            payload->begin() + static_cast<std::ptrdiff_t>(source_offset),
            payload->begin() + static_cast<std::ptrdiff_t>(source_offset + copy_bytes),
            request.destination.begin() + static_cast<std::ptrdiff_t>(destination_offset));
        add_covered_range(copy_begin, copy_end);
    }

    for (const auto& [begin, end] : covered_ranges)
    {
        bytes_overlayed += static_cast<std::size_t>(end - begin);
    }

    return true;
}

bool PayloadSpool::IsRangeFullyCovered(
    std::string_view volume_identity,
    std::uint64_t object_id,
    std::uint64_t generation,
    std::uint64_t logical_offset,
    std::uint64_t bytes) const
{
    if (bytes == 0)
    {
        return true;
    }
    if (!IsVolumeMatch(volume_identity) ||
        object_id == 0 ||
        logical_offset > (std::numeric_limits<std::uint64_t>::max)() - bytes)
    {
        return false;
    }

    auto lock = AcquireMutex();
    if (recovery_required_)
    {
        return false;
    }

    const auto key = DirtyRangeObjectKey{
        object_id,
        generation,
    };
    ++object_lookup_query_count_;
    if (const auto cached = range_object_max_end_.find(key); cached != range_object_max_end_.end() &&
        logical_offset >= cached->second)
    {
        return false;
    }
    if (const auto cached = range_object_min_offset_.find(key); cached != range_object_min_offset_.end() &&
        logical_offset + bytes <= cached->second)
    {
        return false;
    }

    const auto request_end = logical_offset + bytes;
    const auto lookup = range_object_lookup_.find(key);
    ++object_lookup_index_probe_count_;
    if (lookup == range_object_lookup_.end())
    {
        return false;
    }

    object_lookup_candidate_count_ += lookup->second.size();
    if (lookup->second.size() == 1)
    {
        const auto index = lookup->second.front();
        if (index >= ranges_.size())
        {
            return false;
        }

        const auto& range = ranges_[index];
        return range.logical_offset <= logical_offset &&
            RangeEnd(range.logical_offset, range.bytes) >= request_end;
    }

    std::vector<std::pair<std::uint64_t, std::uint64_t>> covered_ranges;
    covered_ranges.reserve(lookup->second.size());
    const auto add_covered_range = [&](std::uint64_t begin, std::uint64_t end)
    {
        if (begin >= end)
        {
            return;
        }

        auto insert_begin = begin;
        auto insert_end = end;
        auto it = covered_ranges.begin();
        while (it != covered_ranges.end())
        {
            if (it->second < insert_begin)
            {
                ++it;
                continue;
            }
            if (insert_end < it->first)
            {
                break;
            }

            insert_begin = (std::min)(insert_begin, it->first);
            insert_end = (std::max)(insert_end, it->second);
            it = covered_ranges.erase(it);
        }

        covered_ranges.insert(it, { insert_begin, insert_end });
    };

    for (const auto index : lookup->second)
    {
        if (index >= ranges_.size())
        {
            continue;
        }

        const auto& range = ranges_[index];
        const auto range_begin = range.logical_offset;
        const auto range_end = RangeEnd(range.logical_offset, range.bytes);
        if (range_end <= logical_offset || range_begin >= request_end)
        {
            continue;
        }

        add_covered_range(
            (std::max)(logical_offset, range_begin),
            (std::min)(request_end, range_end));
        if (covered_ranges.size() == 1 &&
            covered_ranges.front().first <= logical_offset &&
            covered_ranges.front().second >= request_end)
        {
            return true;
        }
    }

    return false;
}

std::uint64_t PayloadSpool::MaxDirtyRangeEnd(
    std::string_view volume_identity,
    std::uint64_t object_id,
    std::uint64_t generation) const
{
    if (!IsVolumeMatch(volume_identity) || object_id == 0)
    {
        return 0;
    }

    auto lock = AcquireMutex();
    if (recovery_required_)
    {
        return 0;
    }

    const auto key = DirtyRangeObjectKey{
        object_id,
        generation,
    };
    ++object_lookup_query_count_;
    if (const auto cached = range_object_max_end_.find(key); cached != range_object_max_end_.end())
    {
        return cached->second;
    }

    const auto lookup = range_object_lookup_.find(key);
    ++object_lookup_index_probe_count_;
    if (lookup == range_object_lookup_.end())
    {
        return 0;
    }

    object_lookup_candidate_count_ += lookup->second.size();
    std::uint64_t max_end = 0;
    for (const auto index : lookup->second)
    {
        if (index >= ranges_.size())
        {
            continue;
        }

        const auto& range = ranges_[index];
        const auto range_end = RangeEnd(range.logical_offset, range.bytes);
        if (range_end > max_end)
        {
            max_end = range_end;
        }
    }

    return max_end;
}

bool PayloadSpool::CleanupThroughSequence(std::uint64_t wal_sequence)
{
    auto lock = AcquireMutex();

    if (!min_dirty_wal_sequence_tracked_ || wal_sequence < min_dirty_wal_sequence_)
    {
        return true;
    }

    std::vector<DirtyRange> live_ranges;
    live_ranges.reserve(ranges_.size());
    for (const auto& range : ranges_)
    {
        if (range.wal_sequence > wal_sequence)
        {
            live_ranges.push_back(range);
        }
    }

    if (!live_ranges.empty() && !FlushPayloadBytesLocked(false))
    {
        ++cleanup_failures_;
        return false;
    }

    if (!ReplaceLiveRangesPreservingOffsets(std::move(live_ranges)))
    {
        ++cleanup_failures_;
        return false;
    }
    recovery_required_ = false;
    return true;
}

bool PayloadSpool::DiscardSequence(std::uint64_t wal_sequence)
{
    auto lock = AcquireMutex();

    if (range_sequences_.find(wal_sequence) == range_sequences_.end())
    {
        return true;
    }

    if (!FlushDirtyStateLocked())
    {
        ++cleanup_failures_;
        return false;
    }

    std::vector<DirtyRange> live_ranges;
    live_ranges.reserve(ranges_.size());
    for (const auto& range : ranges_)
    {
        if (range.wal_sequence != wal_sequence)
        {
            live_ranges.push_back(range);
        }
    }

    if (!ReplaceLiveRangesPreservingOffsets(std::move(live_ranges)))
    {
        ++cleanup_failures_;
        return false;
    }
    recovery_required_ = false;
    return true;
}

bool PayloadSpool::ResolveUnindexedPayloadRecovery(bool wal_proves_no_accepted_work)
{
    auto lock = AcquireMutex();
    if (!wal_proves_no_accepted_work ||
        !recovery_required_ ||
        !unindexed_payload_recovery_ ||
        !ranges_.empty() ||
        next_spool_offset_ == 0)
    {
        return false;
    }

    std::error_code ec;
    if (std::filesystem::exists(index_file_, ec) || ec)
    {
        return false;
    }

    std::vector<DirtyRange> no_live_ranges;
    if (!RewriteLiveRanges(no_live_ranges))
    {
        return false;
    }
    recovery_required_ = false;
    unindexed_payload_recovery_ = false;
    return true;
}

PayloadSpool::Counters PayloadSpool::SnapshotCounters() const
{
    auto lock = AcquireMutex();
    return SnapshotCountersLocked();
}

const std::filesystem::path& PayloadSpool::SpoolFilePath() const noexcept
{
    return spool_file_;
}

bool PayloadSpool::RecoveryRequired() const noexcept
{
    auto lock = AcquireMutex();
    return recovery_required_;
}

std::filesystem::path PayloadSpool::ResolveDefaultRoot()
{
    if (auto override_root = ReadEnvironmentPath("APFSACCESS_SPOOL_ROOT");
        !override_root.empty())
    {
        return override_root;
    }
    if (auto recovery_root = ReadEnvironmentPath("APFSACCESS_RECOVERY_ROOT");
        !recovery_root.empty())
    {
        return recovery_root / "PayloadSpool";
    }
    if (auto local_app_data = ReadEnvironmentPath("LOCALAPPDATA");
        !local_app_data.empty())
    {
        return local_app_data / "ApfsAccess" / "PayloadSpool";
    }
    return std::filesystem::temp_directory_path() / "ApfsAccess" / "PayloadSpool";
}

bool PayloadSpool::IsVolumeMatch(std::string_view volume_identity) const noexcept
{
    return !options_.volume_identity.empty() &&
           volume_identity == options_.volume_identity;
}

bool PayloadSpool::OpenPayloadReadStream(std::ifstream& input) const
{
    input.close();
    input.clear();
    input.open(spool_file_, std::ios::binary);
    if (!input.good())
    {
        return false;
    }
    ++range_payload_read_open_count_;
    return true;
}

std::shared_ptr<PayloadReadHandleState> PayloadSpool::EnsurePayloadReadHandleLocked() const
{
    if (payload_read_handle_)
    {
        return payload_read_handle_;
    }
    const auto wide_path = spool_file_.wstring();
    const auto handle = CreateFileW(
        wide_path.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_RANDOM_ACCESS | FILE_FLAG_OVERLAPPED,
        nullptr);
    if (handle == INVALID_HANDLE_VALUE)
    {
        return {};
    }

    payload_read_handle_ = std::make_shared<PayloadReadHandleState>(handle);
    ++range_payload_read_open_count_;
    return payload_read_handle_;
}

void PayloadSpool::ClosePayloadReadHandleLocked() const
{
    if (!payload_read_handle_)
    {
        return;
    }

    payload_read_handle_.reset();
}

bool PayloadSpool::ReadRangePayloadIntoHandle(
    const std::shared_ptr<PayloadReadHandleState>& handle_state,
    const DirtyRange& range,
    std::span<std::byte> payload,
    bool validate_internal_checksum) const
{
    if (range.bytes == 0 ||
        range.bytes > static_cast<std::uint64_t>((std::numeric_limits<std::size_t>::max)()) ||
        range.spool_offset > ((std::numeric_limits<std::uint64_t>::max)() - range.bytes) ||
        payload.size() != static_cast<std::size_t>(range.bytes) ||
        !handle_state)
    {
        return false;
    }

    const auto completion_event = CurrentPayloadReadEvent().Ensure();
    if (completion_event == nullptr)
    {
        return false;
    }

    auto* handle = handle_state->handle;
    auto* cursor = payload.data();
    auto remaining = payload.size();
    while (remaining > 0)
    {
        const auto requested = static_cast<DWORD>(
            (std::min)(remaining, static_cast<std::size_t>((std::numeric_limits<DWORD>::max)())));
        const auto bytes_before_chunk = payload.size() - remaining;
        if (range.spool_offset > ((std::numeric_limits<std::uint64_t>::max)() - bytes_before_chunk))
        {
            return false;
        }
        const auto chunk_offset = range.spool_offset + static_cast<std::uint64_t>(bytes_before_chunk);
        if (!ResetEvent(completion_event))
        {
            return false;
        }
        OVERLAPPED overlapped{};
        overlapped.Offset = static_cast<DWORD>(chunk_offset & 0xffffffffull);
        overlapped.OffsetHigh = static_cast<DWORD>(chunk_offset >> 32);
        overlapped.hEvent = completion_event;
        DWORD bytes_read = 0;
        if (!ReadFile(handle, cursor, requested, &bytes_read, &overlapped))
        {
            if (GetLastError() != ERROR_IO_PENDING ||
                !WaitForPayloadRead(handle, overlapped, bytes_read))
            {
                return false;
            }
        }
        if (bytes_read != requested)
        {
            return false;
        }
        cursor += bytes_read;
        remaining -= bytes_read;
    }

    if (validate_internal_checksum && HashPayload(payload) != range.checksum)
    {
        return false;
    }
    return true;
}

bool PayloadSpool::ReadRangePayloadIntoHandleLocked(
    const DirtyRange& range,
    std::span<std::byte> payload,
    bool validate_internal_checksum) const
{
    const auto handle_state = EnsurePayloadReadHandleLocked();
    if (!handle_state)
    {
        return false;
    }

    ++range_payload_positional_read_count_;
    return ReadRangePayloadIntoHandle(
        handle_state,
        range,
        payload,
        validate_internal_checksum);
}

bool PayloadSpool::ReadRangePayloadFromHandleLocked(
    const DirtyRange& range,
    std::vector<std::byte>& payload,
    bool validate_internal_checksum) const
{
    payload.clear();
    if (range.bytes == 0 ||
        range.bytes > static_cast<std::uint64_t>((std::numeric_limits<std::size_t>::max)()))
    {
        return false;
    }

    payload.resize(static_cast<std::size_t>(range.bytes));
    if (!ReadRangePayloadIntoHandleLocked(
            range,
            std::span<std::byte>(payload.data(), payload.size()),
            validate_internal_checksum))
    {
        payload.clear();
        return false;
    }
    return true;
}

bool PayloadSpool::ReadRangePayloadFromStream(
    std::istream& input,
    const DirtyRange& range,
    std::vector<std::byte>& payload,
    bool validate_internal_checksum) const
{
    payload.clear();
    if (range.bytes == 0 ||
        range.bytes > static_cast<std::uint64_t>((std::numeric_limits<std::size_t>::max)()) ||
        range.spool_offset > ((std::numeric_limits<std::uint64_t>::max)() - range.bytes))
    {
        return false;
    }

    payload.resize(static_cast<std::size_t>(range.bytes));
    input.clear();
    input.seekg(static_cast<std::streamoff>(range.spool_offset), std::ios::beg);
    if (!input.good())
    {
        payload.clear();
        return false;
    }
    input.read(reinterpret_cast<char*>(payload.data()), static_cast<std::streamsize>(payload.size()));
    if (static_cast<std::size_t>(input.gcount()) != payload.size())
    {
        payload.clear();
        return false;
    }

    if (validate_internal_checksum && HashPayload(payload) != range.checksum)
    {
        payload.clear();
        return false;
    }
    return true;
}

bool PayloadSpool::ReadRangePayload(const DirtyRange& range, std::vector<std::byte>& payload) const
{
    std::ifstream input;
    if (!OpenPayloadReadStream(input))
    {
        payload.clear();
        return false;
    }
    return ReadRangePayloadFromStream(input, range, payload);
}

std::shared_ptr<const std::vector<std::byte>> PayloadSpool::FindValidatedPayloadLocked(
    const DirtyRange& range) const
{
    for (auto& entry : validated_payload_cache_)
    {
        const auto& cached = entry.range;
        if (cached.object_id != range.object_id ||
            cached.generation != range.generation ||
            cached.logical_offset != range.logical_offset ||
            cached.bytes != range.bytes ||
            cached.spool_offset != range.spool_offset ||
            cached.wal_sequence != range.wal_sequence ||
            cached.checksum != range.checksum ||
            entry.payload == nullptr ||
            entry.payload->size() != range.bytes)
        {
            continue;
        }

        entry.last_use = ++validated_payload_cache_use_;
        ++range_payload_cache_hit_count_;
        return entry.payload;
    }
    return {};
}

void PayloadSpool::RememberValidatedPayloadLocked(
    const DirtyRange& range,
    std::shared_ptr<const std::vector<std::byte>> payload) const
{
    if (payload == nullptr ||
        payload->empty() ||
        payload->size() != range.bytes ||
        range.bytes > kValidatedPayloadCacheMaxBytes)
    {
        return;
    }

    for (auto& entry : validated_payload_cache_)
    {
        const auto& cached = entry.range;
        if (cached.object_id == range.object_id &&
            cached.generation == range.generation &&
            cached.logical_offset == range.logical_offset &&
            cached.bytes == range.bytes &&
            cached.spool_offset == range.spool_offset &&
            cached.wal_sequence == range.wal_sequence &&
            cached.checksum == range.checksum)
        {
            entry.payload = std::move(payload);
            entry.last_use = ++validated_payload_cache_use_;
            return;
        }
    }

    const auto payload_bytes = static_cast<std::uint64_t>(payload->size());
    while (!validated_payload_cache_.empty() &&
           (validated_payload_cache_.size() >= kValidatedPayloadCacheMaxEntries ||
            validated_payload_cache_bytes_ > kValidatedPayloadCacheMaxBytes - payload_bytes))
    {
        const auto oldest = std::min_element(
            validated_payload_cache_.begin(),
            validated_payload_cache_.end(),
            [](const auto& left, const auto& right)
            {
                return left.last_use < right.last_use;
            });
        if (oldest == validated_payload_cache_.end())
        {
            break;
        }
        const auto old_bytes = oldest->payload != nullptr
            ? static_cast<std::uint64_t>(oldest->payload->size())
            : 0;
        validated_payload_cache_bytes_ = old_bytes <= validated_payload_cache_bytes_
            ? validated_payload_cache_bytes_ - old_bytes
            : 0;
        validated_payload_cache_.erase(oldest);
    }

    if (validated_payload_cache_bytes_ > kValidatedPayloadCacheMaxBytes - payload_bytes)
    {
        return;
    }

    validated_payload_cache_.push_back({
        range,
        std::move(payload),
        ++validated_payload_cache_use_});
    validated_payload_cache_bytes_ += payload_bytes;
    ++range_payload_cache_fill_count_;
}

void PayloadSpool::ClearValidatedPayloadCacheLocked() const noexcept
{
    validated_payload_cache_.clear();
    validated_payload_cache_use_ = 0;
    validated_payload_cache_bytes_ = 0;
}

PayloadSpool::AppendStatus PayloadSpool::CheckAppendCapacityLocked(std::uint64_t payload_bytes) const noexcept
{
    if (payload_bytes == 0 ||
        payload_bytes > (std::numeric_limits<std::uint64_t>::max)() - next_spool_offset_)
    {
        return AppendStatus::InvalidRequest;
    }
    if (options_.max_bytes > 0 &&
        (next_spool_offset_ > options_.max_bytes ||
         payload_bytes > options_.max_bytes - next_spool_offset_))
    {
        return AppendStatus::QuotaExceeded;
    }
    return AppendStatus::Succeeded;
}

bool PayloadSpool::AppendBytes(std::span<const std::byte> payload, std::uint64_t& out_offset)
{
    if (payload.empty())
    {
        return false;
    }

    std::error_code ec;
    if (!root_ready_)
    {
        std::filesystem::create_directories(options_.root, ec);
        if (ec)
        {
            return false;
        }
        root_ready_ = true;
    }

    const auto existing_size = next_spool_offset_;
    if (options_.max_bytes > 0 &&
        (existing_size > options_.max_bytes ||
         payload.size() > options_.max_bytes - existing_size))
    {
        return false;
    }
    if (payload.size() > static_cast<std::size_t>((std::numeric_limits<std::uint64_t>::max)() - next_spool_offset_))
    {
        return false;
    }

    if (!EnsureAppendStreamLocked())
    {
        return false;
    }
    out_offset = existing_size;

    auto* handle = static_cast<HANDLE>(append_stream_handle_);
    auto* cursor = payload.data();
    auto remaining = payload.size();
    while (remaining > 0)
    {
        const auto chunk_bytes = static_cast<DWORD>(
            (std::min)(remaining, static_cast<std::size_t>((std::numeric_limits<DWORD>::max)())));
        DWORD written = 0;
        if (!WriteFile(handle, cursor, chunk_bytes, &written, nullptr) ||
            written != chunk_bytes)
        {
            (void)CloseAppendStreamLocked();
            if (!TruncateSpoolFileBestEffort(existing_size))
            {
                recovery_required_ = true;
            }
            return false;
        }
        cursor += written;
        remaining -= written;
    }
    append_stream_dirty_ = true;
    next_spool_offset_ += static_cast<std::uint64_t>(payload.size());
    PublishNextSpoolOffsetHintLocked();
    bytes_since_sync_ += static_cast<std::uint64_t>(payload.size());
    ++appends_since_sync_;
    return true;
}

bool PayloadSpool::EnsureAppendStreamLocked()
{
    if (append_stream_handle_ != nullptr)
    {
        return true;
    }

    const auto wide_path = spool_file_.wstring();
    auto* handle = CreateFileW(
        wide_path.c_str(),
        GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
        nullptr);
    if (handle == INVALID_HANDLE_VALUE)
    {
        return false;
    }

    LARGE_INTEGER target{};
    target.QuadPart = static_cast<LONGLONG>(next_spool_offset_);
    if (!SetFilePointerEx(handle, target, nullptr, FILE_BEGIN))
    {
        CloseHandle(handle);
        return false;
    }

    append_stream_handle_ = handle;
    ++append_stream_open_count_;
    return true;
}

bool PayloadSpool::FlushAppendStreamLocked() const
{
    if (append_stream_handle_ == nullptr)
    {
        append_stream_dirty_ = false;
        return true;
    }
    if (!append_stream_dirty_)
    {
        return true;
    }

    append_stream_dirty_ = false;
    ++append_stream_flush_count_;
    return true;
}

bool PayloadSpool::CloseAppendStreamLocked()
{
    if (append_stream_handle_ == nullptr)
    {
        append_stream_dirty_ = false;
        ClosePayloadReadHandleLocked();
        return true;
    }

    const auto flushed = FlushAppendStreamLocked();
    auto* handle = static_cast<HANDLE>(append_stream_handle_);
    const auto closed = CloseHandle(handle) != FALSE;
    append_stream_handle_ = nullptr;
    if (flushed)
    {
        append_stream_dirty_ = false;
    }
    ClosePayloadReadHandleLocked();
    return flushed && closed;
}

bool PayloadSpool::EnsureIndexJournalStreamLocked()
{
    if (index_journal_handle_ != nullptr)
    {
        return true;
    }

    std::error_code ec;
    if (!root_ready_)
    {
        std::filesystem::create_directories(options_.root, ec);
        if (ec)
        {
            return false;
        }
        root_ready_ = true;
    }

    const auto wide_path = index_file_.wstring();
    auto* handle = CreateFileW(
        wide_path.c_str(),
        GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    if (handle == INVALID_HANDLE_VALUE)
    {
        return false;
    }

    LARGE_INTEGER end{};
    if (!GetFileSizeEx(handle, &end) || end.QuadPart < 0 ||
        !SetFilePointerEx(handle, end, nullptr, FILE_BEGIN))
    {
        CloseHandle(handle);
        return false;
    }

    index_journal_handle_ = handle;
    index_journal_size_ = static_cast<std::uint64_t>(end.QuadPart);
    index_journal_size_known_ = true;
    ++index_journal_handle_open_count_;
    return true;
}

bool PayloadSpool::FlushIndexJournalStreamLocked() const
{
    if (index_journal_handle_ == nullptr)
    {
        return true;
    }

    if (FlushFileBuffers(static_cast<HANDLE>(index_journal_handle_)) == FALSE)
    {
        return false;
    }
    ++index_journal_handle_flush_count_;
    return true;
}

bool PayloadSpool::CloseIndexJournalStreamLocked()
{
    if (index_journal_handle_ == nullptr)
    {
        index_journal_size_known_ = false;
        return true;
    }

    auto* handle = static_cast<HANDLE>(index_journal_handle_);
    const auto closed = CloseHandle(handle) != FALSE;
    index_journal_handle_ = nullptr;
    index_journal_size_known_ = false;
    return closed;
}

bool PayloadSpool::AppendIndexJournalBytesLocked(std::span<const std::byte> bytes)
{
    if (bytes.empty())
    {
        return true;
    }
    if (!EnsureIndexJournalStreamLocked())
    {
        return false;
    }

    const auto original_size = index_journal_size_;
    auto* handle = static_cast<HANDLE>(index_journal_handle_);
    const auto* cursor = bytes.data();
    auto remaining = bytes.size();
    bool write_ok = true;
    while (remaining > 0)
    {
        const auto chunk_bytes = static_cast<DWORD>(
            (std::min)(remaining, static_cast<std::size_t>((std::numeric_limits<DWORD>::max)())));
        DWORD written = 0;
        if (!WriteFile(handle, cursor, chunk_bytes, &written, nullptr) || written != chunk_bytes)
        {
            write_ok = false;
            break;
        }
        cursor += written;
        remaining -= written;
    }

    if (write_ok)
    {
        index_journal_size_ += static_cast<std::uint64_t>(bytes.size());
        if (FlushIndexJournalStreamLocked())
        {
            return true;
        }
    }

    // A failed append must not leave an untracked journal suffix. If truncation
    // itself is unavailable, force recovery rather than trusting the index.
    LARGE_INTEGER original_position{};
    original_position.QuadPart = static_cast<LONGLONG>(original_size);
    const bool truncated =
        SetFilePointerEx(handle, original_position, nullptr, FILE_BEGIN) != FALSE &&
        SetEndOfFile(handle) != FALSE &&
        SetFilePointerEx(handle, original_position, nullptr, FILE_BEGIN) != FALSE;
    index_journal_size_ = original_size;
    index_journal_size_known_ = truncated;
    if (!truncated)
    {
        recovery_required_ = true;
    }
    return false;
}

bool PayloadSpool::FlushPayloadBytesLocked(bool observe_durable_flush)
{
    if (bytes_since_sync_ == 0 && appends_since_sync_ == 0)
    {
        return true;
    }

    const auto started = std::chrono::steady_clock::now();
    const auto finish = [&](bool success)
    {
        if (observe_durable_flush)
        {
            const auto elapsed = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now() - started).count());
            ++payload_only_flush_count_;
            payload_only_flush_microseconds_ += elapsed;
            payload_only_flush_max_microseconds_ = (std::max)(payload_only_flush_max_microseconds_, elapsed);
        }
        return success;
    };

    if (!FlushAppendStreamLocked())
    {
        return finish(false);
    }

    const bool spool_needs_sync = bytes_since_sync_ != 0 || appends_since_sync_ != 0;
    if (spool_needs_sync)
    {
        ScopedMicrosecondCounter spool_sync_timer{
            spool_sync_count_,
            spool_sync_microseconds_,
            spool_sync_max_microseconds_,
        };

        bool synced = false;
        if (append_stream_handle_ != nullptr)
        {
            synced = FlushFileBuffers(static_cast<HANDLE>(append_stream_handle_)) != FALSE;
            if (synced)
            {
                ++spool_sync_handle_flush_count_;
            }
        }
        else
        {
            std::error_code ec;
            const auto spool_exists = std::filesystem::exists(spool_file_, ec);
            if (ec)
            {
                return finish(false);
            }
            if (spool_exists)
            {
                synced = FlushPathToDisk(spool_file_);
                if (synced)
                {
                    ++spool_sync_reopen_count_;
                }
            }
            else
            {
                // Preserve the existing empty-spool behavior when a cleanup already removed the file.
                synced = true;
            }
        }
        if (!synced)
        {
            return finish(false);
        }
    }
    bytes_since_sync_ = 0;
    appends_since_sync_ = 0;
    return finish(true);
}

bool PayloadSpool::FlushDirtyStateLocked()
{
    if (!index_dirty_ &&
        bytes_since_sync_ == 0 &&
        appends_since_sync_ == 0)
    {
        return true;
    }

    ScopedMicrosecondCounter flush_timer{
        durable_flush_count_,
        durable_flush_microseconds_,
        durable_flush_max_microseconds_,
    };

    if (!FlushPayloadBytesLocked(false))
    {
        return false;
    }
    if (index_dirty_ && !PersistIndexLocked())
    {
        return false;
    }
    index_dirty_ = false;
    return true;
}

bool PayloadSpool::TruncateSpoolFileBestEffort(std::uint64_t size)
{
    std::unique_lock payload_io_lock(payload_io_mutex_);
    if (!CloseAppendStreamLocked())
    {
        return false;
    }

    std::error_code ec;
    if (!std::filesystem::exists(spool_file_, ec) || ec)
    {
        return !ec;
    }
    std::filesystem::resize_file(spool_file_, size, ec);
    return !ec;
}

std::vector<std::byte> PayloadSpool::BuildIndexSnapshotPayloadLocked() const
{
    if (options_.volume_identity.size() > (std::numeric_limits<std::uint32_t>::max)() ||
        ranges_.size() > (std::numeric_limits<std::uint64_t>::max)())
    {
        return {};
    }

    std::vector<std::byte> payload;
    AppendU64(payload, kIndexMagic);
    AppendU32(payload, kIndexVersion);
    AppendU32(payload, static_cast<std::uint32_t>(options_.volume_identity.size()));
    AppendU64(payload, static_cast<std::uint64_t>(ranges_.size()));
    for (const auto ch : options_.volume_identity)
    {
        payload.push_back(static_cast<std::byte>(static_cast<unsigned char>(ch)));
    }

    for (const auto& range : ranges_)
    {
        AppendU64(payload, range.object_id);
        AppendU64(payload, range.generation);
        AppendU64(payload, range.logical_offset);
        AppendU64(payload, range.bytes);
        AppendU64(payload, range.spool_offset);
        AppendU64(payload, range.wal_sequence);
        AppendU64(payload, range.checksum);
    }
    return payload;
}

std::vector<std::byte> PayloadSpool::BuildIndexJournalFrame(
    std::uint32_t frame_type,
    std::span<const std::byte> payload) const
{
    if (payload.size() > (std::numeric_limits<std::uint64_t>::max)() - kIndexJournalHeaderBytes)
    {
        return {};
    }

    std::vector<std::byte> frame;
    frame.reserve(kIndexJournalHeaderBytes + payload.size());
    AppendU64(frame, kIndexJournalMagic);
    AppendU32(frame, kIndexJournalVersion);
    AppendU32(frame, frame_type);
    AppendU64(frame, static_cast<std::uint64_t>(payload.size()));
    AppendU64(frame, HashIndexBytes(payload));
    frame.insert(frame.end(), payload.begin(), payload.end());
    return frame;
}

bool PayloadSpool::DecodeIndexSnapshotPayload(
    std::span<const std::byte> payload,
    std::vector<DirtyRange>& loaded,
    std::uint64_t* persisted_spool_size) const
{
    loaded.clear();
    std::vector<std::byte> bytes(payload.begin(), payload.end());
    std::size_t cursor = 0;
    std::uint64_t magic = 0;
    std::uint32_t version = 0;
    std::uint32_t volume_length = 0;
    std::uint64_t range_count = 0;
    if (!ReadU64(bytes, cursor, magic) ||
        !ReadU32(bytes, cursor, version) ||
        !ReadU32(bytes, cursor, volume_length) ||
        !ReadU64(bytes, cursor, range_count) ||
        magic != kIndexMagic ||
        version != kIndexVersion ||
        cursor > bytes.size() ||
        volume_length > bytes.size() - cursor)
    {
        return false;
    }

    std::string volume_identity;
    volume_identity.reserve(volume_length);
    for (std::uint32_t index = 0; index < volume_length; ++index)
    {
        volume_identity.push_back(static_cast<char>(std::to_integer<std::uint8_t>(bytes[cursor++])));
    }
    if (volume_identity != options_.volume_identity ||
        range_count > static_cast<std::uint64_t>((std::numeric_limits<std::size_t>::max)()) ||
        cursor > bytes.size() ||
        range_count > (bytes.size() - cursor) / kIndexRangeBytes)
    {
        return false;
    }

    loaded.reserve(static_cast<std::size_t>(range_count));
    for (std::uint64_t index = 0; index < range_count; ++index)
    {
        DirtyRange range{};
        if (!ReadU64(bytes, cursor, range.object_id) ||
            !ReadU64(bytes, cursor, range.generation) ||
            !ReadU64(bytes, cursor, range.logical_offset) ||
            !ReadU64(bytes, cursor, range.bytes) ||
            !ReadU64(bytes, cursor, range.spool_offset) ||
            !ReadU64(bytes, cursor, range.wal_sequence) ||
            !ReadU64(bytes, cursor, range.checksum) ||
            range.object_id == 0 ||
            range.bytes == 0 ||
            range.logical_offset > (std::numeric_limits<std::uint64_t>::max)() - range.bytes ||
            range.spool_offset > (std::numeric_limits<std::uint64_t>::max)() - range.bytes)
        {
            loaded.clear();
            return false;
        }
        range.created_at = std::chrono::steady_clock::now();
        loaded.push_back(range);
    }
    if (cursor == bytes.size())
    {
        if (persisted_spool_size)
        {
            *persisted_spool_size = 0;
        }
        return true;
    }
    if (!persisted_spool_size || bytes.size() - cursor != sizeof(std::uint64_t) ||
        !ReadU64(bytes, cursor, *persisted_spool_size))
    {
        return false;
    }
    return cursor == bytes.size();
}

bool PayloadSpool::PersistLegacyIndexLocked() const
{
    const auto payload = BuildIndexSnapshotPayloadLocked();
    if (payload.empty())
    {
        return false;
    }

    std::vector<std::byte> file_bytes;
    AppendU64(file_bytes, HashIndexBytes(payload));
    file_bytes.insert(file_bytes.end(), payload.begin(), payload.end());
    index_persist_bytes_ += static_cast<std::uint64_t>(file_bytes.size());

    const auto temp_file = options_.root / "payload-spool.idx.tmp";
    std::ofstream output(temp_file, std::ios::binary | std::ios::trunc);
    if (!output.good())
    {
        return false;
    }
    output.write(reinterpret_cast<const char*>(file_bytes.data()), static_cast<std::streamsize>(file_bytes.size()));
    output.flush();
    if (!output.good())
    {
        return false;
    }
    output.close();

    if (!FlushPathToDisk(temp_file) || !MoveReplaceWriteThrough(temp_file, index_file_))
    {
        return false;
    }
    return true;
}

bool PayloadSpool::PersistIndexSnapshotFrameLocked(bool replace_file)
{
    const auto payload = BuildIndexSnapshotPayloadLocked();
    if (payload.empty())
    {
        return false;
    }
    std::vector<std::byte> journal_payload = payload;
    AppendU64(journal_payload, next_spool_offset_);
    const auto frame = BuildIndexJournalFrame(
        kIndexJournalSnapshotFrame,
        std::span<const std::byte>(journal_payload.data(), journal_payload.size()));
    if (frame.empty())
    {
        return false;
    }

    if (replace_file)
    {
        if (!CloseIndexJournalStreamLocked())
        {
            return false;
        }

        const auto temp_file = options_.root / "payload-spool.idx.tmp";
        std::ofstream output(temp_file, std::ios::binary | std::ios::trunc);
        if (!output.good())
        {
            return false;
        }
        output.write(
            reinterpret_cast<const char*>(frame.data()),
            static_cast<std::streamsize>(frame.size()));
        output.flush();
        if (!output.good())
        {
            return false;
        }
        output.close();
        if (!FlushPathToDisk(temp_file) || !MoveReplaceWriteThrough(temp_file, index_file_))
        {
            return false;
        }
        index_journal_size_ = static_cast<std::uint64_t>(frame.size());
        index_journal_size_known_ = true;
    }
    else if (!AppendIndexJournalBytesLocked(std::span<const std::byte>(frame.data(), frame.size())))
    {
        return false;
    }

    index_journal_initialized_ = true;
    index_requires_snapshot_ = false;
    pending_index_additions_.clear();
    index_persist_bytes_ += static_cast<std::uint64_t>(frame.size());
    ++index_journal_frame_count_;
    ++index_journal_snapshot_count_;
    return true;
}

bool PayloadSpool::PersistIndexLocked()
{
    ScopedMicrosecondCounter persist_timer{
        index_persist_count_,
        index_persist_microseconds_,
        index_persist_max_microseconds_,
    };
    std::error_code ec;
    std::filesystem::create_directories(options_.root, ec);
    if (ec)
    {
        return false;
    }

    if (!index_delta_enabled_)
    {
        if (!CloseIndexJournalStreamLocked() || !PersistLegacyIndexLocked())
        {
            return false;
        }
        index_journal_initialized_ = false;
        index_requires_snapshot_ = false;
        pending_index_additions_.clear();
        return true;
    }

    if (!index_journal_initialized_)
    {
        return PersistIndexSnapshotFrameLocked(true);
    }
    if (index_requires_snapshot_)
    {
        return PersistIndexSnapshotFrameLocked(false);
    }
    if (pending_index_additions_.empty())
    {
        // This should be rare, but a complete snapshot is the only safe way to
        // repair an in-memory/index state mismatch.
        return PersistIndexSnapshotFrameLocked(false);
    }

    std::vector<std::byte> payload;
    if (pending_index_additions_.size() > (std::numeric_limits<std::uint64_t>::max)())
    {
        return false;
    }
    AppendU64(payload, next_spool_offset_);
    AppendU64(payload, static_cast<std::uint64_t>(pending_index_additions_.size()));
    for (const auto& range : pending_index_additions_)
    {
        AppendU64(payload, range.object_id);
        AppendU64(payload, range.generation);
        AppendU64(payload, range.logical_offset);
        AppendU64(payload, range.bytes);
        AppendU64(payload, range.spool_offset);
        AppendU64(payload, range.wal_sequence);
        AppendU64(payload, range.checksum);
    }
    const auto frame = BuildIndexJournalFrame(
        kIndexJournalAppendFrame,
        std::span<const std::byte>(payload.data(), payload.size()));
    if (frame.empty() || !AppendIndexJournalBytesLocked(std::span<const std::byte>(frame.data(), frame.size())))
    {
        return false;
    }

    index_persist_bytes_ += static_cast<std::uint64_t>(frame.size());
    ++index_journal_frame_count_;
    ++index_journal_append_count_;
    index_journal_initialized_ = true;
    pending_index_additions_.clear();
    return true;
}

bool PayloadSpool::LoadIndex()
{
    unindexed_payload_recovery_ = false;
    std::error_code ec;
    if (std::filesystem::exists(spool_file_, ec) && !ec)
    {
        next_spool_offset_ = std::filesystem::file_size(spool_file_, ec);
        if (ec)
        {
            return false;
        }
        PublishNextSpoolOffsetHintLocked();
    }
    else if (ec)
    {
        return false;
    }

    if (!std::filesystem::exists(index_file_, ec) || ec)
    {
        if (!ec && next_spool_offset_ > 0)
        {
            unindexed_payload_recovery_ = true;
        }
        ec.clear();
        return !ec && next_spool_offset_ == 0;
    }

    std::ifstream input(index_file_, std::ios::binary);
    if (!input.good())
    {
        return false;
    }

    const std::vector<char> raw_bytes(
        (std::istreambuf_iterator<char>(input)),
        std::istreambuf_iterator<char>());
    std::vector<std::byte> file_bytes;
    file_bytes.reserve(raw_bytes.size());
    for (const auto byte : raw_bytes)
    {
        file_bytes.push_back(static_cast<std::byte>(static_cast<unsigned char>(byte)));
    }
    if (file_bytes.size() < sizeof(std::uint64_t))
    {
        return false;
    }

    std::uint64_t leading_magic = 0;
    std::size_t magic_cursor = 0;
    if (!ReadU64(file_bytes, magic_cursor, leading_magic))
    {
        return false;
    }
    if (leading_magic == kIndexJournalMagic)
    {
        return LoadIndexJournal(file_bytes);
    }

    std::size_t cursor = 0;
    std::uint64_t expected_checksum = 0;
    if (!ReadU64(file_bytes, cursor, expected_checksum))
    {
        return false;
    }
    const std::span<const std::byte> payload(file_bytes.data() + cursor, file_bytes.size() - cursor);
    if (HashIndexBytes(payload) != expected_checksum)
    {
        return false;
    }

    std::vector<DirtyRange> loaded;
    if (!DecodeIndexSnapshotPayload(payload, loaded))
    {
        return false;
    }
    std::ifstream payload_input;
    std::vector<std::byte> range_payload;
    if (!loaded.empty() && !OpenPayloadReadStream(payload_input))
    {
        return false;
    }

    for (const auto& range : loaded)
    {
        if (RangeEnd(range.spool_offset, range.bytes) > next_spool_offset_ ||
            !ReadRangePayloadFromStream(payload_input, range, range_payload))
        {
            return false;
        }
    }

    recovery_required_ = !loaded.empty();
    ranges_ = std::move(loaded);
    RebuildRangeSequenceIndex();
    RebuildRangeLookup();
    RecomputeOldestDirtyRangeLocked();
    index_journal_initialized_ = false;
    index_requires_snapshot_ = false;
    pending_index_additions_.clear();
    index_journal_size_ = 0;
    index_journal_size_known_ = false;
    if (!ranges_.empty())
    {
        std::uint64_t indexed_end = 0;
        for (const auto& range : ranges_)
        {
            indexed_end = (std::max)(indexed_end, RangeEnd(range.spool_offset, range.bytes));
        }
        if (next_spool_offset_ > indexed_end)
        {
            recovery_required_ = true;
        }
    }
    else if (next_spool_offset_ > 0)
    {
        recovery_required_ = true;
    }
    return true;
}

bool PayloadSpool::RewriteLiveRanges(std::vector<DirtyRange>& live_ranges)
{
    ClearValidatedPayloadCacheLocked();
    if (!CloseAppendStreamLocked() || !CloseIndexJournalStreamLocked())
    {
        return false;
    }

    if (live_ranges.empty())
    {
        std::error_code ec;
        // Remove the identity index before its payload. If the second removal
        // is interrupted, WAL references can still rebuild the index from the
        // retained payload bytes.
        if (std::filesystem::exists(index_file_, ec))
        {
            if (ec || !std::filesystem::remove(index_file_, ec) || ec)
            {
                return false;
            }
        }
        else if (ec)
        {
            return false;
        }
        ec.clear();
        if (std::filesystem::exists(spool_file_, ec))
        {
            if (ec || !std::filesystem::remove(spool_file_, ec) || ec)
            {
                return false;
            }
        }
        else if (ec)
        {
            return false;
        }
        next_spool_offset_ = 0;
        PublishNextSpoolOffsetHintLocked();
        bytes_since_sync_ = 0;
        appends_since_sync_ = 0;
        index_dirty_ = false;
        range_lookup_.clear();
        range_object_lookup_.clear();
        range_object_max_end_.clear();
        range_object_min_offset_.clear();
        oldest_dirty_range_created_at_ = {};
        oldest_dirty_range_tracked_ = false;
        range_sequences_.clear();
        min_dirty_wal_sequence_ = 0;
        min_dirty_wal_sequence_tracked_ = false;
        index_journal_initialized_ = false;
        index_requires_snapshot_ = false;
        pending_index_additions_.clear();
        index_journal_size_ = 0;
        index_journal_size_known_ = false;
        return true;
    }

    const auto temp_spool = options_.root / "payload-spool.bin.tmp";
    std::ofstream output(temp_spool, std::ios::binary | std::ios::trunc);
    if (!output.good())
    {
        return false;
    }

    std::uint64_t next_offset = 0;
    std::ifstream payload_input;
    std::vector<std::byte> payload;
    if (!OpenPayloadReadStream(payload_input))
    {
        return false;
    }
    for (auto& range : live_ranges)
    {
        if (!ReadRangePayloadFromStream(payload_input, range, payload) || payload.size() != range.bytes)
        {
            return false;
        }
        range.spool_offset = next_offset;
        range.checksum = HashPayload(payload);
        output.write(reinterpret_cast<const char*>(payload.data()), static_cast<std::streamsize>(payload.size()));
        if (!output.good())
        {
            return false;
        }
        next_offset += static_cast<std::uint64_t>(payload.size());
    }
    payload_input.close();
    output.flush();
    if (!output.good())
    {
        return false;
    }
    output.close();

    if (!FlushPathToDisk(temp_spool))
    {
        return false;
    }

    if (!MoveReplaceWriteThrough(temp_spool, spool_file_) || !FlushPathToDisk(spool_file_))
    {
        return false;
    }

    ranges_ = live_ranges;
    next_spool_offset_ = next_offset;
    PublishNextSpoolOffsetHintLocked();
    bytes_since_sync_ = 0;
    appends_since_sync_ = 0;
    index_dirty_ = true;
    index_requires_snapshot_ = true;
    pending_index_additions_.clear();
    RebuildRangeLookup();
    RecomputeOldestDirtyRangeLocked();
    return FlushDirtyStateLocked();
}

bool PayloadSpool::ReplaceLiveRangesPreservingOffsets(std::vector<DirtyRange> live_ranges)
{
    ClearValidatedPayloadCacheLocked();
    if (live_ranges.empty())
    {
        if (!RewriteLiveRanges(live_ranges))
        {
            return false;
        }
        ranges_.clear();
        return true;
    }

    const auto previous_index_dirty = index_dirty_;
    const auto previous_index_requires_snapshot = index_requires_snapshot_;
    auto previous_pending_index_additions = std::move(pending_index_additions_);
    auto previous_ranges = std::move(ranges_);
    ranges_ = std::move(live_ranges);
    RebuildRangeSequenceIndex();
    RebuildRangeLookup();
    RecomputeOldestDirtyRangeLocked();
    index_dirty_ = true;
    if (!PersistIndexLocked())
    {
        ranges_ = std::move(previous_ranges);
        RebuildRangeSequenceIndex();
        RebuildRangeLookup();
        RecomputeOldestDirtyRangeLocked();
        index_dirty_ = previous_index_dirty;
        index_requires_snapshot_ = previous_index_requires_snapshot;
        pending_index_additions_ = std::move(previous_pending_index_additions);
        return false;
    }
    index_dirty_ = false;
    return true;
}

bool PayloadSpool::LoadIndexJournal(const std::vector<std::byte>& file_bytes)
{
    std::size_t cursor = 0;
    std::vector<DirtyRange> loaded;
    bool saw_snapshot = false;
    bool persisted_spool_size_seen = false;
    std::uint64_t persisted_spool_size = 0;
    while (cursor < file_bytes.size())
    {
        if (file_bytes.size() - cursor < kIndexJournalHeaderBytes)
        {
            return false;
        }

        std::uint64_t magic = 0;
        std::uint32_t version = 0;
        std::uint32_t frame_type = 0;
        std::uint64_t payload_size = 0;
        std::uint64_t expected_checksum = 0;
        if (!ReadU64(file_bytes, cursor, magic) ||
            !ReadU32(file_bytes, cursor, version) ||
            !ReadU32(file_bytes, cursor, frame_type) ||
            !ReadU64(file_bytes, cursor, payload_size) ||
            !ReadU64(file_bytes, cursor, expected_checksum) ||
            magic != kIndexJournalMagic ||
            version != kIndexJournalVersion ||
            payload_size > static_cast<std::uint64_t>(file_bytes.size() - cursor) ||
            payload_size > static_cast<std::uint64_t>((std::numeric_limits<std::size_t>::max)()))
        {
            return false;
        }

        const auto payload = std::span<const std::byte>(
            file_bytes.data() + cursor,
            static_cast<std::size_t>(payload_size));
        if (HashIndexBytes(payload) != expected_checksum)
        {
            return false;
        }
        cursor += static_cast<std::size_t>(payload_size);

        if (frame_type == kIndexJournalSnapshotFrame)
        {
            std::uint64_t snapshot_spool_size = 0;
            if (!DecodeIndexSnapshotPayload(payload, loaded, &snapshot_spool_size) ||
                snapshot_spool_size > next_spool_offset_)
            {
                return false;
            }
            persisted_spool_size = snapshot_spool_size;
            persisted_spool_size_seen = true;
            saw_snapshot = true;
            continue;
        }
        if (frame_type != kIndexJournalAppendFrame || !saw_snapshot)
        {
            return false;
        }

        std::vector<std::byte> append_bytes(payload.begin(), payload.end());
        std::size_t append_cursor = 0;
        std::uint64_t append_spool_size = 0;
        std::uint64_t range_count = 0;
        if (!ReadU64(append_bytes, append_cursor, append_spool_size) ||
            !ReadU64(append_bytes, append_cursor, range_count) ||
            append_spool_size > next_spool_offset_ ||
            range_count > static_cast<std::uint64_t>((std::numeric_limits<std::size_t>::max)()) ||
            append_cursor > append_bytes.size() ||
            range_count > (append_bytes.size() - append_cursor) / kIndexRangeBytes)
        {
            return false;
        }
        if (range_count > static_cast<std::uint64_t>(loaded.max_size() - loaded.size()))
        {
            return false;
        }
        for (std::uint64_t index = 0; index < range_count; ++index)
        {
            DirtyRange range{};
            if (!ReadU64(append_bytes, append_cursor, range.object_id) ||
                !ReadU64(append_bytes, append_cursor, range.generation) ||
                !ReadU64(append_bytes, append_cursor, range.logical_offset) ||
                !ReadU64(append_bytes, append_cursor, range.bytes) ||
                !ReadU64(append_bytes, append_cursor, range.spool_offset) ||
                !ReadU64(append_bytes, append_cursor, range.wal_sequence) ||
                !ReadU64(append_bytes, append_cursor, range.checksum) ||
                range.object_id == 0 ||
                range.bytes == 0 ||
                range.logical_offset > (std::numeric_limits<std::uint64_t>::max)() - range.bytes ||
                range.spool_offset > (std::numeric_limits<std::uint64_t>::max)() - range.bytes)
            {
                return false;
            }
            range.created_at = std::chrono::steady_clock::now();
            if (RangeEnd(range.spool_offset, range.bytes) > append_spool_size)
            {
                return false;
            }
            loaded.push_back(range);
        }
        if (append_cursor != append_bytes.size())
        {
            return false;
        }
        persisted_spool_size = append_spool_size;
        persisted_spool_size_seen = true;
    }

    if (!saw_snapshot || !persisted_spool_size_seen)
    {
        return false;
    }

    std::ifstream payload_input;
    std::vector<std::byte> range_payload;
    if (!loaded.empty() && !OpenPayloadReadStream(payload_input))
    {
        return false;
    }
    for (const auto& range : loaded)
    {
        if (RangeEnd(range.spool_offset, range.bytes) > next_spool_offset_ ||
            !ReadRangePayloadFromStream(payload_input, range, range_payload))
        {
            return false;
        }
    }

    recovery_required_ = !loaded.empty();
    ranges_ = std::move(loaded);
    RebuildRangeSequenceIndex();
    RebuildRangeLookup();
    RecomputeOldestDirtyRangeLocked();
    index_journal_initialized_ = true;
    index_requires_snapshot_ = false;
    pending_index_additions_.clear();
    index_journal_size_ = static_cast<std::uint64_t>(file_bytes.size());
    index_journal_size_known_ = true;
    if (next_spool_offset_ > persisted_spool_size)
    {
        recovery_required_ = true;
    }
    if (!ranges_.empty())
    {
        std::uint64_t indexed_end = 0;
        for (const auto& range : ranges_)
        {
            indexed_end = (std::max)(indexed_end, RangeEnd(range.spool_offset, range.bytes));
        }
        if (indexed_end > persisted_spool_size)
        {
            return false;
        }
    }
    else if (next_spool_offset_ > 0)
    {
        recovery_required_ = true;
    }
    return true;
}

void PayloadSpool::RebuildRangeSequenceIndex()
{
    range_sequences_.clear();
    range_sequences_.reserve(ranges_.size());
    min_dirty_wal_sequence_ = 0;
    min_dirty_wal_sequence_tracked_ = false;
    for (const auto& range : ranges_)
    {
        range_sequences_.insert(range.wal_sequence);
        UpdateMinimumDirtyWalSequence(range.wal_sequence);
    }
}

void PayloadSpool::UpdateMinimumDirtyWalSequence(std::uint64_t wal_sequence)
{
    if (!min_dirty_wal_sequence_tracked_ || wal_sequence < min_dirty_wal_sequence_)
    {
        min_dirty_wal_sequence_ = wal_sequence;
        min_dirty_wal_sequence_tracked_ = true;
    }
}

bool PayloadSpool::RangeIndexPrecedes(std::size_t lhs, std::size_t rhs) const
{
    if (lhs >= ranges_.size() || rhs >= ranges_.size())
    {
        return lhs < rhs;
    }

    const auto& left = ranges_[lhs];
    const auto& right = ranges_[rhs];
    if (left.wal_sequence != right.wal_sequence)
    {
        return left.wal_sequence < right.wal_sequence;
    }
    if (left.spool_offset != right.spool_offset)
    {
        return left.spool_offset < right.spool_offset;
    }
    return lhs < rhs;
}

void PayloadSpool::RebuildRangeLookup()
{
    range_lookup_.clear();
    range_object_lookup_.clear();
    range_object_max_end_.clear();
    range_object_min_offset_.clear();
    range_lookup_.reserve(ranges_.size());
    range_object_lookup_.reserve(ranges_.size());
    range_object_max_end_.reserve(ranges_.size());
    range_object_min_offset_.reserve(ranges_.size());
    for (std::size_t index = 0; index < ranges_.size(); ++index)
    {
        const auto& range = ranges_[index];
        const auto object_key = DirtyRangeObjectKey{
            range.object_id,
            range.generation,
        };
        range_lookup_[DirtyRangeLookupKey{
            range.object_id,
            range.generation,
            range.wal_sequence,
        }].push_back(index);
        auto& object_indices = range_object_lookup_[object_key];
        if (object_indices.empty() || RangeIndexPrecedes(object_indices.back(), index))
        {
            object_indices.push_back(index);
        }
        else
        {
            const auto insertion = std::lower_bound(
                object_indices.begin(),
                object_indices.end(),
                index,
                [this](std::size_t lhs, std::size_t rhs)
                {
                    return RangeIndexPrecedes(lhs, rhs);
                });
            object_indices.insert(insertion, index);
        }
        const auto range_end = RangeEnd(range.logical_offset, range.bytes);
        auto& max_end = range_object_max_end_[object_key];
        if (range_end > max_end)
        {
            max_end = range_end;
        }
        auto [min_offset_it, min_offset_inserted] = range_object_min_offset_.try_emplace(object_key, range.logical_offset);
        if (!min_offset_inserted && range.logical_offset < min_offset_it->second)
        {
            min_offset_it->second = range.logical_offset;
        }
    }
}

PayloadSpool::Counters PayloadSpool::SnapshotCountersLocked() const
{
    Counters counters{};
    counters.cleanup_failures = cleanup_failures_;
    counters.mutex_wait_count = mutex_wait_count_;
    counters.mutex_wait_microseconds = mutex_wait_microseconds_;
    counters.mutex_wait_max_microseconds = mutex_wait_max_microseconds_;
    counters.mutex_wait_p50_microseconds = MutexWaitPercentileLocked(1, 2);
    counters.mutex_wait_p95_microseconds = MutexWaitPercentileLocked(19, 20);
    counters.recovery_required = recovery_required_;
    counters.dirty_range_count = ranges_.size();
    counters.bytes_since_sync = bytes_since_sync_;
    counters.appends_since_sync = appends_since_sync_;
    counters.append_direct_count = append_direct_count_;
    counters.append_merged_count = append_merged_count_;
    counters.append_stream_open_count = append_stream_open_count_;
    counters.append_stream_flush_count = append_stream_flush_count_;
    counters.append_rollback_snapshot_count = append_rollback_snapshot_count_;
    counters.payload_only_flush_count = payload_only_flush_count_;
    counters.payload_only_flush_microseconds = payload_only_flush_microseconds_;
    counters.payload_only_flush_max_microseconds = payload_only_flush_max_microseconds_;
    counters.durable_flush_count = durable_flush_count_;
    counters.durable_flush_microseconds = durable_flush_microseconds_;
    counters.durable_flush_max_microseconds = durable_flush_max_microseconds_;
    counters.spool_sync_count = spool_sync_count_;
    counters.spool_sync_microseconds = spool_sync_microseconds_;
    counters.spool_sync_max_microseconds = spool_sync_max_microseconds_;
    counters.spool_sync_handle_flush_count = spool_sync_handle_flush_count_;
    counters.spool_sync_reopen_count = spool_sync_reopen_count_;
    counters.index_persist_count = index_persist_count_;
    counters.index_persist_bytes = index_persist_bytes_;
    counters.index_persist_microseconds = index_persist_microseconds_;
    counters.index_persist_max_microseconds = index_persist_max_microseconds_;
    counters.index_journal_frame_count = index_journal_frame_count_;
    counters.index_journal_snapshot_count = index_journal_snapshot_count_;
    counters.index_journal_append_count = index_journal_append_count_;
    counters.index_journal_handle_open_count = index_journal_handle_open_count_;
    counters.index_journal_handle_flush_count = index_journal_handle_flush_count_;
    counters.range_payload_read_open_count = range_payload_read_open_count_;
    counters.range_payload_positional_read_count = range_payload_positional_read_count_;
    counters.range_payload_cache_hit_count = range_payload_cache_hit_count_;
    counters.range_payload_cache_fill_count = range_payload_cache_fill_count_;
    counters.overlay_direct_destination_read_count = overlay_direct_destination_read_count_;
    counters.dirty_object_count = range_object_lookup_.size();
    counters.object_lookup_query_count = object_lookup_query_count_;
    counters.object_lookup_candidate_count = object_lookup_candidate_count_;
    counters.object_lookup_index_probe_count = object_lookup_index_probe_count_;
    counters.cleanup_sequence_probe_count = cleanup_sequence_probe_count_;
    counters.index_dirty = index_dirty_;
    std::error_code ec;
    counters.spool_bytes = next_spool_offset_;
    if (counters.spool_bytes == 0 && std::filesystem::exists(spool_file_, ec))
    {
        counters.spool_bytes = std::filesystem::file_size(spool_file_, ec);
    }
    if (ec)
    {
        counters.spool_bytes = 0;
    }

    if (oldest_dirty_range_tracked_)
    {
        const auto now = std::chrono::steady_clock::now();
        counters.oldest_dirty_age_ms = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(now - oldest_dirty_range_created_at_).count());
    }

    return counters;
}

void PayloadSpool::RecomputeOldestDirtyRangeLocked()
{
    oldest_dirty_range_tracked_ = false;
    oldest_dirty_range_created_at_ = {};
    for (const auto& range : ranges_)
    {
        UpdateOldestDirtyRange(oldest_dirty_range_created_at_, oldest_dirty_range_tracked_, range.created_at);
    }
}
} // namespace apfsaccess::rw
