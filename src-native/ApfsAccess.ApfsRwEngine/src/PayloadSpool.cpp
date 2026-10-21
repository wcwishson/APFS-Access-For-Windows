#include "PayloadSpool.h"

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iterator>
#include <limits>
#include <map>
#include <mutex>
#include <optional>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>
#include <windows.h>
#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")

namespace apfsaccess::rw
{
#ifdef APFSACCESS_PROTECTED_SPOOL_TESTING
namespace protected_spool_testing { thread_local Hooks hooks; }
#endif
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

bool ChargeStartupPayloadBytes(
    std::uint64_t bytes, std::uint64_t budget, std::uint64_t& consumed) noexcept
{
    if (budget == 0)
    {
        return true;
    }
    if (bytes > budget - consumed)
    {
        return false;
    }
    consumed += bytes;
    return true;
}

constexpr std::uint64_t kProtectedOverhead = journal::kJournalRecordHeaderBytes + crypto::kGcmTagBytes;
constexpr std::size_t kProtectedMaxRanges = 4096;
constexpr std::size_t kProtectedMaxKeyDirectoryEntries = 4096;
constexpr std::uint64_t kProtectedIndexLimit = 16ull * 1024 * 1024;
constexpr std::uint64_t kProtectedIndexMagic = 0x3158444953505041ull; // "APPSIDX1"
constexpr std::uint64_t kProtectedAnchorMagic = 0x31524f5453505041ull; // "APPSTOR1"
constexpr wchar_t kProtectedMarkerName[] = L"payload-spool.protected";
constexpr std::size_t kProtectedAnchorBytes = 16 + kProtectedOverhead;

void ProtectedPut(std::span<std::byte> bytes, std::size_t at, std::uint64_t value)
{
    for (unsigned i = 0; i < 8; ++i) bytes[at + i] = static_cast<std::byte>((value >> (8 * i)) & 255);
}

std::uint64_t ProtectedGet(std::span<const std::byte> bytes, std::size_t at)
{
    std::uint64_t value = 0;
    for (unsigned i = 0; i < 8; ++i) value |= std::to_integer<std::uint64_t>(bytes[at + i]) << (8 * i);
    return value;
}

bool ProtectedExact(HANDLE file, const std::filesystem::path& path, bool directory)
{
    BY_HANDLE_FILE_INFORMATION info{};
    if (file == INVALID_HANDLE_VALUE || GetFileType(file) != FILE_TYPE_DISK ||
        !GetFileInformationByHandle(file, &info) || (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) ||
        ((info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) != directory ||
        (!directory && info.nNumberOfLinks != 1)) return false;
    std::wstring actual(512, L'\0');
    const auto n = GetFinalPathNameByHandleW(file, actual.data(), static_cast<DWORD>(actual.size()),
        FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    if (!n || n >= actual.size()) return false;
    actual.resize(n);
    const auto expected = L"\\\\?\\" + path.wstring();
    return CompareStringOrdinal(actual.c_str(), -1, expected.c_str(), -1, TRUE) == CSTR_EQUAL;
}

bool ProtectedPath(const std::filesystem::path& path)
{
    const auto p = path.wstring();
    if (p.size() < 4 || p.size() > 210 || !((p[0] >= L'A' && p[0] <= L'Z') || (p[0] >= L'a' && p[0] <= L'z')) ||
        p[1] != L':' || p[2] != L'\\' || p.back() == L'\\' ||
        p.find_first_of(L":/*?\"<>|", 3) != p.npos || GetDriveTypeW(p.substr(0, 3).c_str()) != DRIVE_FIXED) return false;
    for (auto ch : p) if (ch < 32) return false;
    for (std::size_t at = 3; at < p.size();)
    {
        auto end = p.find(L'\\', at);
        if (end == p.npos) end = p.size();
        const auto part = p.substr(at, end - at);
        if (part.empty() || part == L"." || part == L".." || part.back() == L'.' || part.back() == L' ') return false;
        const auto stem = part.substr(0, part.find(L'.'));
        const auto is = [&](const wchar_t* name) {
            return CompareStringOrdinal(stem.c_str(), -1, name, -1, TRUE) == CSTR_EQUAL;
        };
        if (is(L"CON") || is(L"PRN") || is(L"AUX") || is(L"NUL") || is(L"CONIN$") || is(L"CONOUT$")) return false;
        if (stem.size() == 4 && (CompareStringOrdinal(stem.data(), 3, L"COM", 3, TRUE) == CSTR_EQUAL ||
            CompareStringOrdinal(stem.data(), 3, L"LPT", 3, TRUE) == CSTR_EQUAL)) return false;
        at = end + 1;
    }
    return true;
}

bool ProtectedPinDirectory(const std::filesystem::path& path, std::vector<std::unique_ptr<FileHandle>>& pins)
{
    if (!ProtectedPath(path)) return false;
    const auto p = path.wstring();
    for (std::size_t end = 2;;)
    {
        const std::filesystem::path prefix(p.substr(0, end == 2 ? 3 : end));
        auto pin = std::make_unique<FileHandle>();
        pin->value = CreateFileW(prefix.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ, nullptr,
            OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        if (!ProtectedExact(pin->value, prefix, true)) return false;
        pins.push_back(std::move(pin));
        if (end == p.size()) break;
        end = p.find(L'\\', end + 1);
        if (end == p.npos) end = p.size();
    }
    return true;
}

bool ProtectedSize(HANDLE file, std::uint64_t& bytes)
{
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(file, &size) || size.QuadPart < 0) return false;
    bytes = static_cast<std::uint64_t>(size.QuadPart);
    return true;
}

bool ProtectedIo(HANDLE file, std::uint64_t offset, std::span<std::byte> bytes, bool write)
{
    if (offset > static_cast<std::uint64_t>(INT64_MAX) || bytes.size() > MAXDWORD) return false;
    LARGE_INTEGER at{};
    at.QuadPart = static_cast<LONGLONG>(offset);
    if (!SetFilePointerEx(file, at, nullptr, FILE_BEGIN)) return false;
    DWORD transferred = 0;
    const auto count = static_cast<DWORD>(bytes.size());
    const auto ok = write ? WriteFile(file, bytes.data(), count, &transferred, nullptr)
                          : ReadFile(file, bytes.data(), count, &transferred, nullptr);
    return ok && transferred == count;
}

bool ProtectedWrite(HANDLE file, std::uint64_t offset, std::span<std::byte> bytes, bool index)
{
#ifdef APFSACCESS_PROTECTED_SPOOL_TESTING
    auto& hooks = protected_spool_testing::hooks;
    hooks.events.push_back(index ? 3u : 1u);
    const auto fault = index ? protected_spool_testing::Fault::IndexWrite : protected_spool_testing::Fault::DataWrite;
    if (hooks.fault == fault && !hooks.triggered)
    {
        hooks.triggered = true;
        (void)ProtectedIo(file, offset, bytes.first(13), true);
        return false;
    }
#else
    (void)index;
#endif
    return ProtectedIo(file, offset, bytes, true);
}

bool ProtectedFlush(HANDLE file, bool index)
{
#ifdef APFSACCESS_PROTECTED_SPOOL_TESTING
    auto& hooks = protected_spool_testing::hooks;
    hooks.events.push_back(index ? 4u : 2u);
    const auto fault = index ? protected_spool_testing::Fault::IndexFlush : protected_spool_testing::Fault::DataFlush;
    if (hooks.fault == fault && !hooks.triggered) { hooks.triggered = true; return false; }
#else
    (void)index;
#endif
    return FlushFileBuffers(file) != FALSE;
}

constexpr std::wstring_view kCleanupPrefix = L"payload-spool.cleanup.";
constexpr std::size_t kCleanupIntentBytes = 272, kCleanupCommitBytes = 64;
constexpr std::size_t kCleanupGuardBytes = 24 + kProtectedOverhead;
constexpr std::uint64_t kCleanupMagic = 0x31504e4353505041ull; // "APPSCNP1"
constexpr std::uint64_t kCleanupCommitMagic = 0x314d434353505041ull;
using CleanupProof = PayloadSpool::ProtectedCleanupProof;
using CleanupDigest = std::array<std::uint8_t, 32>;
struct CleanupIntent
{
    CleanupProof proof;
    std::uint64_t serial = 0, reset = 0, references = 0, data_bytes = 0, index_bytes = 0;
    std::uint64_t previous_reset = 0, previous_floor = 0;
    CleanupDigest refs{}, data{}, index{}, previous{};
};
bool CleanupCut(std::string_view stage)
{
#ifdef APFSACCESS_PROTECTED_SPOOL_TESTING
    auto& hooks = protected_spool_testing::hooks;
    hooks.maintenance_events.emplace_back(stage);
    if (hooks.maintenance_observer) hooks.maintenance_observer(stage);
    if (hooks.maintenance_fault == stage && !hooks.triggered) { hooks.triggered = true; return true; }
#else
    (void)stage;
#endif
    return false;
}
bool CleanupPresent(const std::filesystem::path& root)
{
    WIN32_FIND_DATAW data{};
    const auto h = FindFirstFileW((root / (std::wstring(kCleanupPrefix) + L"*")).c_str(), &data);
    if (h != INVALID_HANDLE_VALUE) { FindClose(h); return true; }
    const auto error = GetLastError();
    return error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND;
}
bool CleanupProofValid(const CleanupProof& proof, bool continued = false)
{
    return proof.wal_bytes >= 104 && proof.wal_bytes <= 64ull * 1024 * 1024 && proof.wal_records <= 65536 &&
        proof.wal_last_sequence != UINT64_MAX && (continued || (proof.wal_records == 0) == (proof.wal_last_sequence == 0)) &&
        proof.cleanup_sequence <= proof.durable_sequence && proof.durable_sequence <= proof.wal_last_sequence &&
        std::any_of(proof.wal_sha256.begin(), proof.wal_sha256.end(), [](auto b) { return b != 0; });
}
bool CleanupSameProof(const CleanupProof& a, const CleanupProof& b)
{
    return a.source_binding == b.source_binding && a.wal_sha256 == b.wal_sha256 && a.wal_bytes == b.wal_bytes &&
        a.wal_records == b.wal_records && a.wal_last_sequence == b.wal_last_sequence &&
        a.durable_sequence == b.durable_sequence && a.cleanup_sequence == b.cleanup_sequence;
}
auto CleanupEncode(const CleanupIntent& i)
{
    auto encoded = crypto::SecureBytes::Allocate(kCleanupIntentBytes);
    if (!encoded) return encoded;
    const auto b = encoded.bytes.Bytes();
    ProtectedPut(b, 0, kCleanupMagic); ProtectedPut(b, 8, 1); ProtectedPut(b, 16, i.serial); ProtectedPut(b, 24, i.reset);
    ProtectedPut(b, 32, i.proof.cleanup_sequence); ProtectedPut(b, 40, i.proof.durable_sequence);
    ProtectedPut(b, 48, i.proof.wal_bytes); ProtectedPut(b, 56, i.proof.wal_records); ProtectedPut(b, 64, i.proof.wal_last_sequence);
    ProtectedPut(b, 72, i.references); ProtectedPut(b, 80, i.data_bytes); ProtectedPut(b, 88, i.index_bytes);
    ProtectedPut(b, 96, i.previous_reset); ProtectedPut(b, 104, i.previous_floor);
    for (const auto& [at, digest] : std::array<std::pair<std::size_t, const CleanupDigest*>, 5>{
        {{112, &i.proof.wal_sha256}, {144, &i.refs}, {176, &i.data}, {208, &i.index}, {240, &i.previous}}})
        std::memcpy(b.data() + at, digest->data(), 32);
    return encoded;
}
bool CleanupDecode(std::span<const std::byte> b, const journal::JournalDigest& binding, CleanupIntent& i, bool continued = false)
{
    if (b.size() != kCleanupIntentBytes || ProtectedGet(b, 0) != kCleanupMagic || ProtectedGet(b, 8) != 1) return false;
    i.serial = ProtectedGet(b, 16); i.reset = ProtectedGet(b, 24); i.proof.source_binding = binding;
    i.proof.cleanup_sequence = ProtectedGet(b, 32); i.proof.durable_sequence = ProtectedGet(b, 40);
    i.proof.wal_bytes = ProtectedGet(b, 48); i.proof.wal_records = ProtectedGet(b, 56); i.proof.wal_last_sequence = ProtectedGet(b, 64);
    i.references = ProtectedGet(b, 72); i.data_bytes = ProtectedGet(b, 80); i.index_bytes = ProtectedGet(b, 88);
    i.previous_reset = ProtectedGet(b, 96); i.previous_floor = ProtectedGet(b, 104);
    for (const auto& [at, digest] : std::array<std::pair<std::size_t, CleanupDigest*>, 5>{
        {{112, &i.proof.wal_sha256}, {144, &i.refs}, {176, &i.data}, {208, &i.index}, {240, &i.previous}}})
        std::memcpy(digest->data(), b.data() + at, 32);
    return CleanupProofValid(i.proof, continued) && i.reset <= 1 && i.references <= kProtectedMaxRanges &&
        i.previous_reset <= i.previous_floor && i.previous_floor <= i.proof.cleanup_sequence && i.index_bytes <= kProtectedIndexLimit;
}
std::filesystem::path CleanupPath(const std::filesystem::path& root, std::uint64_t serial, bool commit)
{
    auto n = std::to_wstring(serial);
    return root / (std::wstring(kCleanupPrefix) + std::wstring(16 - n.size(), L'0') + n + (commit ? L".commit" : L".intent"));
}
bool CleanupAbsent(const std::filesystem::path& path)
{
    return GetFileAttributesW(path.c_str()) == INVALID_FILE_ATTRIBUTES && GetLastError() == ERROR_FILE_NOT_FOUND;
}
bool CleanupOpen(FileHandle& h, const std::filesystem::path& path, bool create)
{
    if (!ProtectedPath(path)) return false;
    h.value = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE | DELETE, FILE_SHARE_READ, nullptr,
        create ? CREATE_NEW : OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH, nullptr);
    return ProtectedExact(h.value, path, false);
}
bool CleanupRead(HANDLE file, std::vector<std::byte>& frame)
{
    std::uint64_t size = 0;
    if (!ProtectedSize(file, size) || size > kCleanupIntentBytes + kProtectedOverhead) return false;
    frame.resize(static_cast<std::size_t>(size));
    return ProtectedIo(file, 0, frame, false);
}
bool CleanupFileHash(HANDLE file, std::uint64_t expected, CleanupDigest& digest)
{
    std::uint64_t actual = 0;
    auto& provider = SharedSha256Provider();
    if (!ProtectedSize(file, actual) || actual != expected || !provider.algorithm) return false;
    auto object = crypto::SecureBytes::Allocate(provider.object_bytes);
    auto buffer = crypto::SecureBytes::Allocate(64 * 1024);
    if (!object || !buffer) return false;
    BCRYPT_HASH_HANDLE hash = nullptr;
    if (BCryptCreateHash(provider.algorithm, &hash, reinterpret_cast<PUCHAR>(object.bytes.Bytes().data()),
        static_cast<ULONG>(object.bytes.Size()), nullptr, 0, 0) < 0) return false;
    bool ok = true;
    for (std::uint64_t at = 0; ok && at < expected;)
    {
        const auto b = buffer.bytes.Bytes().first(static_cast<std::size_t>((std::min)(expected - at, std::uint64_t{64 * 1024})));
        ok = ProtectedIo(file, at, b, false) && BCryptHashData(hash, reinterpret_cast<PUCHAR>(b.data()), static_cast<ULONG>(b.size()), 0) >= 0;
        at += b.size();
    }
    ok = ok && BCryptFinishHash(hash, digest.data(), static_cast<ULONG>(digest.size()), 0) >= 0;
    BCryptDestroyHash(hash);
    return ok && ProtectedSize(file, actual) && actual == expected;
}
bool CleanupQuarantine(HANDLE h, const std::filesystem::path& root, std::span<const std::byte> bytes)
{
    CleanupDigest hash{}; if (!HashPayloadSha256(bytes, hash)) return false;
    constexpr wchar_t hex[] = L"0123456789abcdef";
    auto name = std::wstring(kCleanupPrefix) + L"failed.";
    for (auto b : hash) { name += hex[b >> 4]; name += hex[b & 15]; }
    for (unsigned n = 0; n < 16; ++n)
    {
        const auto path = root / (name + L"." + std::to_wstring(n));
        if (!ProtectedPath(path)) return false;
        if (!CleanupAbsent(path)) continue;
        const auto p = path.wstring();
        std::vector<std::byte> storage(sizeof(FILE_RENAME_INFO) + p.size() * sizeof(wchar_t));
        auto* info = reinterpret_cast<FILE_RENAME_INFO*>(storage.data());
        info->ReplaceIfExists = FALSE; info->RootDirectory = nullptr; info->FileNameLength = static_cast<DWORD>(p.size() * sizeof(wchar_t));
        std::memcpy(info->FileName, p.data(), info->FileNameLength);
        return !CleanupCut("cleanup-before-quarantine") &&
            SetFileInformationByHandle(h, FileRenameInfo, info, static_cast<DWORD>(storage.size())) &&
            ProtectedExact(h, path, false) && !CleanupCut("cleanup-after-quarantine") &&
            !CleanupCut("cleanup-quarantine-flush") && FlushFileBuffers(h);
    }
    return false;
}
} // namespace

struct PayloadSpool::ProtectedState
{
    std::vector<std::unique_ptr<FileHandle>> pins;
    FileHandle data, index, anchor;
    std::array<std::uint8_t, 32> anchor_digest{};
    bool anchor_ready = false;
    std::unique_ptr<journal::ProtectedJournalEpoch> epoch;
    std::uint64_t index_bytes = 0;
    // Only authenticated valid-index / absent-index cases can rebuild. Any
    // ambiguous I/O or corrupt index poisons this instance without truncation.
    bool rebuild_allowed = false;
    bool index_missing = false;
    bool maintenance_available = false, maintenance_seen = false;
    std::uint64_t cleanup_floor = 0;
    std::vector<DirtyRange> physical_ranges;
    // Only complete, authenticated and flushed receipt pairs enter this prefix.
    // Retained handles deny external writes/deletion. Reads still authenticate
    // every receipt and key slot; only a redundant durability barrier is cached.
    std::vector<std::unique_ptr<FileHandle>> durable_cleanup_receipts;
};

journal::JournalRecordContext PayloadSpool::ProtectedCleanupContext(std::uint64_t serial, bool commit) const
{
    auto context = ProtectedContext(nullptr, 0);
    if (std::all_of(context.operation.begin(), context.operation.end(), [](auto b) { return b == std::byte{}; })) return {};
    context.purpose = commit ? 0x505305u : 0x505304u;
    context.chunk = serial;
    return context;
}

journal::JournalRecordContext PayloadSpool::ContinuationSpoolContext(const ContinuationBaseline& baseline) const
{
    auto context = ProtectedContext(nullptr, 0);
    std::array<std::byte, 80> encoded{};
    std::memcpy(encoded.data(), context.operation.data(), 32);
    std::memcpy(encoded.data() + 32, baseline.certificate.data(), 32);
    ProtectedPut(encoded, 64, baseline.floor); ProtectedPut(encoded, 72, baseline.generation);
    CleanupDigest digest{};
    if (!baseline.floor || !baseline.generation || !HashPayloadSha256(encoded, digest)) return {};
    std::memcpy(context.operation.data(), digest.data(), 32);
    context.purpose = 0x505307u; context.chunk = baseline.generation;
    return context;
}

bool PayloadSpool::CaptureContinuationSpool(ContinuationLease& lease, std::string& error)
{
    lease.lock = AcquireMutex();
    const auto fail = [&] { error = "ContinuationSpoolCensusRequired"; return false; };
    if (!protected_ || !protected_->maintenance_seen || !protected_->rebuild_allowed || recovery_required_ ||
        !ProtectedAuthority() || !ranges_.empty() || !protected_->physical_ranges.empty() || next_spool_offset_ ||
        protected_->index_bytes != kCleanupGuardBytes || !protected_->cleanup_floor ||
        protected_->durable_cleanup_receipts.size() > 2048 || protected_->durable_cleanup_receipts.size() % 2) return fail();
    lease.floor = protected_->cleanup_floor;
    lease.tip = continuation_baseline_ ? continuation_baseline_->tip : CleanupDigest{};
    std::size_t found = 0;
    for (const auto& entry : std::filesystem::directory_iterator(options_.root)) {
        const auto name = entry.path().filename().wstring();
        if (name.starts_with(kCleanupPrefix)) ++found;
    }
    if (found != protected_->durable_cleanup_receipts.size()) return fail();
    for (std::size_t n = 0; n < found; ++n) {
        const auto path = CleanupPath(options_.root, n / 2 + 1, n % 2 != 0);
        auto& pin = protected_->durable_cleanup_receipts[n];
        // Reconciliation installed only flushed immutable receipt handles.
        // Keep that proof under this lock; a reopened owner must establish it
        // again before CaptureContinuationSpool can export any receipt.
        if (!pin || !ProtectedExact(pin->value, path, false)) return fail();
        lease.receipts.emplace_back(path, reinterpret_cast<std::uintptr_t>(pin->value));
        if (n + 1 == found && !CleanupFileHash(pin->value, kCleanupCommitBytes + kProtectedOverhead, lease.tip)) return fail();
    }
    return (FlushFileBuffers(protected_->data.value) && FlushFileBuffers(protected_->index.value)) || fail();
}

bool PayloadSpool::SuspendContinuationSpool(ContinuationLease& lease, std::string& error, bool require_empty)
{
    if (!lease.lock.owns_lock()) lease.lock = AcquireMutex();
    if (!protected_ || !protected_->anchor_ready || !ProtectedExact(protected_->anchor.value, protected_marker_file_, false) ||
        !ProtectedExact(protected_->data.value, spool_file_, false)) { error = "ContinuationSpoolUnavailable"; return false; }
    std::uint64_t size = 0;
    if (!ProtectedSize(protected_->data.value, size) || (require_empty && size)) { error = "ContinuationSpoolNotEmpty"; return false; }
    protected_->rebuild_allowed = false; recovery_required_ = true;
    protected_->epoch.reset();
    if (protected_->index.value != INVALID_HANDLE_VALUE) {
        if (!CloseHandle(std::exchange(protected_->index.value, INVALID_HANDLE_VALUE))) return false;
    }
    return true;
}

bool PayloadSpool::SealContinuationSpool(const ContinuationBaseline& baseline, std::vector<std::byte>& bytes, std::string& error)
{
    bytes.clear();
    if (!protected_ || !protected_->anchor_ready) return false;
    protected_->epoch.reset();
    auto epoch = journal::ProtectedJournalEpoch::AcquireWriter(options_.protected_key_directory.wstring(), options_.protected_binding);
    if (!epoch) { error = "ContinuationSpoolKeyPublicationFailed"; return false; }
    protected_->epoch = std::move(epoch.epoch);
    std::array<std::byte, 24> plain{};
    ProtectedPut(plain, 0, kCleanupCommitMagic); ProtectedPut(plain, 8, 6); ProtectedPut(plain, 16, baseline.floor);
    auto frame = protected_->epoch->Seal(ContinuationSpoolContext(baseline), plain);
    if (!frame) { error = "ContinuationSpoolSealFailed"; return false; }
    bytes.assign(frame.bytes.Bytes().begin(), frame.bytes.Bytes().end());
    return true;
}

bool PayloadSpool::InstallContinuationSpool(ContinuationLease& lease, ContinuationBaseline baseline, std::string& error)
{
    const auto fail = [&] { error = "ContinuationSpoolCheckpointInvalid"; return false; };
    if (!lease.lock.owns_lock() || !baseline.authority || !protected_ || !protected_->anchor_ready) return fail();
    if (protected_->index.value != INVALID_HANDLE_VALUE) return fail();
    protected_->index.value = CreateFileW(index_file_.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, nullptr,
        OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    std::uint64_t size = 0;
    std::array<std::byte, kCleanupGuardBytes> bytes{};
    if (!ProtectedExact(protected_->index.value, index_file_, false) || !ProtectedSize(protected_->index.value, size) ||
        size < bytes.size() || !ProtectedIo(protected_->index.value, 0, bytes, false)) return fail();
    // A later ordinary cleanup replaces this guard with its serial-bound guard.
    // Its receipt chain must then be authenticated by the original bridge.
    const bool receipts = CleanupPresent(options_.root);
    if (!receipts) {
        auto plain = journal::ProtectedJournalEpoch::Open(options_.protected_key_directory.wstring(), options_.protected_binding,
            ContinuationSpoolContext(baseline), bytes);
        if (!plain || plain.bytes.Size() != 24 || ProtectedGet(plain.bytes.Bytes(), 0) != kCleanupCommitMagic ||
            ProtectedGet(plain.bytes.Bytes(), 8) != 6 || ProtectedGet(plain.bytes.Bytes(), 16) != baseline.floor) return fail();
    }
    protected_->durable_cleanup_receipts.clear();
    continuation_baseline_ = std::move(baseline);
    protected_->cleanup_floor = continuation_baseline_->floor;
    protected_->index_bytes = size; protected_->maintenance_seen = true; protected_->maintenance_available = true;
    protected_->rebuild_allowed = false; recovery_required_ = true;
    return true;
}

void PayloadSpool::ReleaseContinuationReceipts(ContinuationLease& lease)
{
    if (lease.lock.owns_lock() && protected_) protected_->durable_cleanup_receipts.clear();
}

bool PayloadSpool::ProtectedStoreMarkerPresent() const noexcept
{
    if (GetFileAttributesW(protected_marker_file_.c_str()) != INVALID_FILE_ATTRIBUTES) return true;
    const auto error = GetLastError();
    return (error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND) || CleanupPresent(options_.root);
}

bool PayloadSpool::MutationRefused() const noexcept
{
    return protected_format_refused_ || (!options_.protected_persistence &&
        (ordinary_layout_unproven_ || ProtectedStoreMarkerPresent()));
}

journal::JournalRecordContext PayloadSpool::ProtectedContext(const DirtyRange* range, std::uint64_t offset, bool anchor) const
{
    journal::JournalRecordContext context{};
    if (!anchor && (!protected_ || !protected_->anchor_ready)) return context;
    auto encoded = crypto::SecureBytes::Allocate(64 + options_.volume_identity.size() + (anchor ? 0 : 32));
    if (!encoded) return context;
    const auto b = encoded.bytes.Bytes();
    // Fixed-width LE fields followed by exact length-delimited volume bytes.
    ProtectedPut(b, 0, range ? 0x3154414453505041ull : (anchor ? kProtectedAnchorMagic : kProtectedIndexMagic));
    ProtectedPut(b, 8, options_.volume_identity.size());
    if (range)
    {
        ProtectedPut(b, 16, range->object_id); ProtectedPut(b, 24, range->generation);
        ProtectedPut(b, 32, range->logical_offset); ProtectedPut(b, 40, range->bytes);
        ProtectedPut(b, 48, range->wal_sequence); ProtectedPut(b, 56, offset);
    }
    std::memcpy(b.data() + 64, options_.volume_identity.data(), options_.volume_identity.size());
    if (!anchor) std::memcpy(b.data() + 64 + options_.volume_identity.size(), protected_->anchor_digest.data(), 32);
    std::array<std::uint8_t, 32> digest{};
    if (!HashPayloadSha256(b, digest)) return context;
    std::memcpy(context.operation.data(), digest.data(), digest.size());
    context.purpose = range ? 0x505301u : (anchor ? 0x505303u : 0x505302u);
    context.chunk = offset;
    return context;
}

bool PayloadSpool::ProtectedAuthority() const
{
    if (!protected_ || !protected_->anchor_ready || !ProtectedExact(protected_->anchor.value, protected_marker_file_, false) ||
        (!protected_->maintenance_seen && CleanupPresent(options_.root)) ||
        !ProtectedExact(protected_->data.value, spool_file_, false) ||
        !ProtectedExact(protected_->index.value, index_file_, false)) return false;
    std::uint64_t data_size = 0, index_size = 0, anchor_size = 0;
    return ProtectedSize(protected_->anchor.value, anchor_size) && anchor_size == kProtectedAnchorBytes &&
        ProtectedSize(protected_->data.value, data_size) && data_size == next_spool_offset_ &&
        ProtectedSize(protected_->index.value, index_size) && index_size == protected_->index_bytes;
}

journal::JournalRecordResult PayloadSpool::ReadProtectedRange(const DirtyRange& range) const
{
    const auto failure = []() -> journal::JournalRecordResult {
        return {{journal::JournalError::IntegrityFailure}, {}};
    };
    if (!ProtectedAuthority() || range.object_id == 0 || range.generation == 0 || range.wal_sequence == 0 ||
        range.bytes == 0 || range.bytes > journal::kMaxJournalPlaintextBytes ||
        range.logical_offset > UINT64_MAX - range.bytes || range.spool_offset > next_spool_offset_ ||
        range.bytes + kProtectedOverhead > next_spool_offset_ - range.spool_offset) return failure();
    auto frame = crypto::SecureBytes::Allocate(static_cast<std::size_t>(range.bytes + kProtectedOverhead));
    if (!frame || !ProtectedIo(protected_->data.value, range.spool_offset, frame.bytes.Bytes(), false)) return failure();
    auto opened = journal::ProtectedJournalEpoch::Open(options_.protected_key_directory.wstring(),
        options_.protected_binding, ProtectedContext(&range, range.spool_offset), frame.bytes.Bytes());
    if (!opened || opened.bytes.Size() != range.bytes || HashPayload(opened.bytes.Bytes()) != range.checksum) return failure();
    return opened;
}

bool PayloadSpool::InitializeProtected()
{
    if (options_.volume_identity.empty() || options_.volume_identity.size() > 4096 || options_.max_bytes == 0 ||
        options_.max_bytes > kMaxDirtyFlushBytes ||
        std::all_of(options_.protected_binding.begin(), options_.protected_binding.end(), [](auto b) { return b == std::byte{}; }) ||
        !ProtectedPath(options_.root) || !ProtectedPath(options_.protected_key_directory)) return false;
    protected_ = std::make_unique<ProtectedState>();
    if (!ProtectedPinDirectory(options_.root, protected_->pins) ||
        !ProtectedPinDirectory(options_.protected_key_directory, protected_->pins)) return false;
    // Old slots remain evidence. Bound fresh epoch admission, never delete slots.
    std::size_t key_entries = 0;
    for (const auto& entry : std::filesystem::directory_iterator(options_.protected_key_directory))
    {
        (void)entry;
        if (++key_entries >= kProtectedMaxKeyDirectoryEntries) return false;
    }
    protected_->anchor.value = CreateFileW(protected_marker_file_.c_str(), GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    const bool existing_anchor = protected_->anchor.value != INVALID_HANDLE_VALUE;
    if (!existing_anchor && GetLastError() != ERROR_FILE_NOT_FOUND) return false;
    if (existing_anchor && !ProtectedExact(protected_->anchor.value, protected_marker_file_, false)) return false;
    const auto authenticate_anchor = [this]() {
        std::uint64_t size = 0;
        std::array<std::byte, kProtectedAnchorBytes> frame{};
        if (!ProtectedSize(protected_->anchor.value, size) || size != frame.size() ||
            !ProtectedIo(protected_->anchor.value, 0, frame, false)) return false;
        auto plain = journal::ProtectedJournalEpoch::Open(options_.protected_key_directory.wstring(), options_.protected_binding,
            ProtectedContext(nullptr, 0, true), frame);
        if (!plain || plain.bytes.Size() != 16 || ProtectedGet(plain.bytes.Bytes(), 0) != kProtectedAnchorMagic ||
            ProtectedGet(plain.bytes.Bytes(), 8) != 1 || !HashPayloadSha256(frame, protected_->anchor_digest)) return false;
        protected_->anchor_ready = true;
        return true;
    };
    // A foreign/corrupt anchor cannot create even an empty missing data/index file.
    if (existing_anchor && !authenticate_anchor()) return false;
    protected_->maintenance_seen = CleanupPresent(options_.root);
    if (!existing_anchor && protected_->maintenance_seen) return false;
    const auto open = [this, existing_anchor](FileHandle& file, const std::filesystem::path& path) {
        file.value = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, nullptr,
            (existing_anchor || protected_->maintenance_seen) ? OPEN_EXISTING : OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        return ProtectedExact(file.value, path, false);
    };
    if (!open(protected_->data, spool_file_) || !ProtectedSize(protected_->data.value, next_spool_offset_) ||
        next_spool_offset_ > options_.max_bytes) return false;
    // No adoption: without the durable discriminator, existing bytes have no
    // established protected-store authority, regardless of their byte prefix.
    if (!existing_anchor && next_spool_offset_ != 0) return false;
    if (!open(protected_->index, index_file_))
    {
        const auto attributes = GetFileAttributesW(index_file_.c_str());
        if (existing_anchor && !protected_->maintenance_seen && protected_->index.value == INVALID_HANDLE_VALUE &&
            attributes == INVALID_FILE_ATTRIBUTES && GetLastError() == ERROR_FILE_NOT_FOUND)
        {
            // Leave the advisory file absent until exact authenticated references
            // cover all original data. A lost cleanup guard is never rebuilt here.
            protected_->index_missing = true;
            protected_->maintenance_available = protected_->rebuild_allowed = true;
        }
        return false;
    }
    if (!ProtectedSize(protected_->index.value, protected_->index_bytes) ||
        protected_->index_bytes > kProtectedIndexLimit ||
        (options_.startup_index_max_bytes && protected_->index_bytes > options_.startup_index_max_bytes) ||
        (!existing_anchor && protected_->index_bytes != 0)) return false;
    if (!existing_anchor)
    {
        auto writer = journal::ProtectedJournalEpoch::AcquireWriter(options_.protected_key_directory.wstring(), options_.protected_binding);
        if (!writer) return false;
        protected_->epoch = std::move(writer.epoch);
        std::array<std::byte, 16> identity{};
        ProtectedPut(identity, 0, kProtectedAnchorMagic); ProtectedPut(identity, 8, 1);
        auto sealed = protected_->epoch->Seal(ProtectedContext(nullptr, 0, true), identity);
        if (!sealed) return false;
        protected_->anchor.value = CreateFileW(protected_marker_file_.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ,
            nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH, nullptr);
        if (!ProtectedExact(protected_->anchor.value, protected_marker_file_, false)) return false;
#ifdef APFSACCESS_PROTECTED_SPOOL_TESTING
        auto& hooks = protected_spool_testing::hooks;
        hooks.events.push_back(5);
        if (hooks.fault == protected_spool_testing::Fault::AnchorWrite && !hooks.triggered)
        {
            hooks.triggered = true;
            (void)ProtectedIo(protected_->anchor.value, 0, sealed.bytes.Bytes().first(13), true);
            return false;
        }
#endif
        if (!ProtectedIo(protected_->anchor.value, 0, sealed.bytes.Bytes(), true)) return false;
#ifdef APFSACCESS_PROTECTED_SPOOL_TESTING
        hooks.events.push_back(6);
        if (hooks.fault == protected_spool_testing::Fault::AnchorFlush && !hooks.triggered)
        { hooks.triggered = true; return false; }
#endif
        if (!FlushFileBuffers(protected_->anchor.value)) return false;
#ifdef APFSACCESS_PROTECTED_SPOOL_TESTING
        hooks.events.push_back(7);
        if (hooks.fault == protected_spool_testing::Fault::AnchorReadback && !hooks.triggered)
        { hooks.triggered = true; return false; }
#endif
        std::array<std::byte, kProtectedAnchorBytes> readback{};
        if (!ProtectedIo(protected_->anchor.value, 0, readback, false) ||
            !std::equal(readback.begin(), readback.end(), sealed.bytes.Bytes().begin())) return false;
#ifdef APFSACCESS_PROTECTED_SPOOL_TESTING
        hooks.events.push_back(8);
        if (hooks.fault == protected_spool_testing::Fault::AfterAnchorPublication && !hooks.triggered)
        { hooks.triggered = true; return false; }
#endif
    }
    if (!existing_anchor && !authenticate_anchor()) return false;
    protected_->maintenance_available = true;
    // Never interpret a reset endpoint or an advisory index as cleanup authority.
    // The explicit API authenticates the receipt chain and caller's original WAL.
    if (protected_->maintenance_seen) return false;
    // Check physical framing before index replay. This establishes bounds only;
    // trusted refs plus AEAD authenticate
    // an unindexed tail later. Mixed/plain/torn bytes cannot authorize writes.
    std::uint64_t physical_offset = 0;
    std::size_t physical_records = 0;
    while (physical_offset < next_spool_offset_)
    {
        std::array<std::byte, journal::kJournalRecordHeaderBytes> header{};
        if (++physical_records > kProtectedMaxRanges || next_spool_offset_ - physical_offset < header.size() ||
            !ProtectedIo(protected_->data.value, physical_offset, header, false) ||
            std::memcmp(header.data(), "APFSREC1", 8) != 0 ||
            ProtectedGet(header, 8) != (std::uint64_t{64} << 32 | 1)) return false;
        const auto size = ProtectedGet(header, 16) & 0xffffffffull;
        const auto cipher_size = ProtectedGet(header, 16) >> 32;
        if (size <= kProtectedOverhead || size > journal::kMaxJournalRecordBytes ||
            size > next_spool_offset_ - physical_offset || cipher_size != size - journal::kJournalRecordHeaderBytes ||
            std::any_of(header.begin() + 52, header.end(), [](auto b) { return b != std::byte{}; })) return false;
        physical_offset += size;
    }
    PublishNextSpoolOffsetHintLocked();
    std::uint64_t index_offset = 0;
    std::vector<DirtyRange> loaded;
    while (index_offset < protected_->index_bytes)
    {
        std::array<std::byte, journal::kJournalRecordHeaderBytes> header{};
        if (protected_->index_bytes - index_offset < header.size() ||
            !ProtectedIo(protected_->index.value, index_offset, header, false)) return false;
        const auto size = ProtectedGet(header, 16) & 0xffffffffull;
        if (size < kProtectedOverhead || size > journal::kMaxJournalRecordBytes ||
            size > protected_->index_bytes - index_offset) return false;
        auto frame = crypto::SecureBytes::Allocate(static_cast<std::size_t>(size));
        if (!frame || !ProtectedIo(protected_->index.value, index_offset, frame.bytes.Bytes(), false)) return false;
        auto plain = journal::ProtectedJournalEpoch::Open(options_.protected_key_directory.wstring(),
            options_.protected_binding, ProtectedContext(nullptr, index_offset), frame.bytes.Bytes());
        if (!plain || plain.bytes.Size() < 24) return false;
        const auto b = plain.bytes.Bytes();
        const auto end = ProtectedGet(b, 8), count = ProtectedGet(b, 16);
        if (ProtectedGet(b, 0) != kProtectedIndexMagic || count > kProtectedMaxRanges || count < loaded.size() ||
            b.size() != 24 + count * kIndexRangeBytes || end > next_spool_offset_) return false;
        std::vector<DirtyRange> snapshot;
        snapshot.reserve(static_cast<std::size_t>(count));
        std::uint64_t physical_end = 0;
        for (std::size_t i = 0; i < count; ++i)
        {
            const auto at = 24 + i * kIndexRangeBytes;
            DirtyRange range{};
            range.object_id = ProtectedGet(b, at); range.generation = ProtectedGet(b, at + 8);
            range.logical_offset = ProtectedGet(b, at + 16); range.bytes = ProtectedGet(b, at + 24);
            range.spool_offset = ProtectedGet(b, at + 32); range.wal_sequence = ProtectedGet(b, at + 40);
            range.checksum = ProtectedGet(b, at + 48);
            if (!range.object_id || !range.generation || !range.wal_sequence || !range.bytes ||
                range.bytes > journal::kMaxJournalPlaintextBytes || range.logical_offset > UINT64_MAX - range.bytes ||
                range.spool_offset != physical_end || range.bytes + kProtectedOverhead > next_spool_offset_ - physical_end) return false;
            physical_end += range.bytes + kProtectedOverhead;
            if (i < loaded.size())
            {
                const auto& old = loaded[i];
                if (old.object_id != range.object_id || old.generation != range.generation ||
                    old.logical_offset != range.logical_offset || old.bytes != range.bytes ||
                    old.spool_offset != range.spool_offset || old.wal_sequence != range.wal_sequence ||
                    old.checksum != range.checksum) return false;
            }
            range.created_at = std::chrono::steady_clock::now();
            snapshot.push_back(range);
        }
        if (physical_end != end) return false;
        loaded = std::move(snapshot);
        index_offset += size;
    }
    std::uint64_t consumed = 0;
    for (const auto& range : loaded)
    {
        if (!ChargeStartupPayloadBytes(range.bytes + kProtectedOverhead,
                options_.startup_payload_read_max_bytes, consumed) || !ReadProtectedRange(range)) return false;
    }
    if (!protected_->epoch)
    {
        auto writer = journal::ProtectedJournalEpoch::AcquireWriter(options_.protected_key_directory.wstring(), options_.protected_binding);
        if (!writer) return false;
        protected_->epoch = std::move(writer.epoch);
    }
    protected_->rebuild_allowed = true;
    protected_->physical_ranges = loaded;
    ranges_ = std::move(loaded);
    RebuildRangeSequenceIndex(); RebuildRangeLookup(); RecomputeOldestDirtyRangeLocked();
    recovery_required_ = next_spool_offset_ != 0;
    return true;
}

PayloadSpool::AppendStatus PayloadSpool::AppendProtected(const WriteRequest& request, AppendResult* result)
{
    if (!request.generation || !request.wal_sequence || (protected_ && request.wal_sequence <= protected_->cleanup_floor)) return AppendStatus::InvalidRequest;
    const auto capacity = CheckAppendCapacityLocked(request.payload.size());
    if (capacity != AppendStatus::Succeeded) return capacity;
    if (!ProtectedAuthority()) return AppendStatus::StorageFailure;
    DirtyRange range{};
    range.object_id = request.object_id; range.generation = request.generation;
    range.logical_offset = request.logical_offset; range.bytes = request.payload.size();
    range.spool_offset = next_spool_offset_; range.wal_sequence = request.wal_sequence;
    range.created_at = std::chrono::steady_clock::now();
    std::array<std::uint8_t, 32> digest{};
    if (!HashPayloadDigests(request.payload, &range.checksum, digest)) return AppendStatus::StorageFailure;
    auto frame = protected_->epoch->Seal(ProtectedContext(&range, range.spool_offset), request.payload);
    if (!frame) return AppendStatus::StorageFailure;
    // Reserve the range owner before writing; fallible lookup rebuilding after
    // publication poisons the instance and preserves all evidence on failure.
    ranges_.reserve(ranges_.size() + 1);
    protected_->physical_ranges.reserve(protected_->physical_ranges.size() + 1);
    if (!ProtectedWrite(protected_->data.value, next_spool_offset_, frame.bytes.Bytes(), false))
    {
        protected_->rebuild_allowed = false; recovery_required_ = true;
        return AppendStatus::StorageFailure;
    }
    next_spool_offset_ += frame.bytes.Size();
    PublishNextSpoolOffsetHintLocked();
    ranges_.push_back(range);
    protected_->physical_ranges.push_back(range);
    try { RebuildRangeSequenceIndex(); RebuildRangeLookup(); RecomputeOldestDirtyRangeLocked(); }
    catch (...) { protected_->rebuild_allowed = false; recovery_required_ = true; return AppendStatus::StorageFailure; }
    bytes_since_sync_ += frame.bytes.Size(); ++appends_since_sync_; index_dirty_ = true;
    const bool should_flush = (options_.durable_flush_bytes && bytes_since_sync_ >=
        (std::min)(options_.durable_flush_bytes, kMaxDirtyFlushBytes)) ||
        (options_.durable_flush_appends && appends_since_sync_ >=
            (std::min)(options_.durable_flush_appends, kMaxDirtyFlushAppends));
    if (should_flush && !FlushDirtyStateLocked())
    {
        protected_->rebuild_allowed = false; recovery_required_ = true;
        return AppendStatus::StorageFailure;
    }
    ++append_direct_count_;
    if (result) *result = {range.object_id, range.generation, range.logical_offset, range.bytes,
        range.spool_offset, range.wal_sequence, range.checksum, digest};
    return AppendStatus::Succeeded;
}

bool PayloadSpool::PersistProtectedIndex()
{
    if (!protected_ || !protected_->rebuild_allowed || recovery_required_ || !ProtectedAuthority() ||
        protected_->physical_ranges.size() > kProtectedMaxRanges) return false;
    const auto& physical = protected_->physical_ranges;
    const auto size = 24 + physical.size() * kIndexRangeBytes;
    const auto limit = options_.startup_index_max_bytes ?
        (std::min)(kProtectedIndexLimit, options_.startup_index_max_bytes) : kProtectedIndexLimit;
    if (size + kProtectedOverhead > limit || protected_->index_bytes > limit - size - kProtectedOverhead) return false;
    auto plain = crypto::SecureBytes::Allocate(size);
    if (!plain) return false;
    const auto b = plain.bytes.Bytes();
    ProtectedPut(b, 0, kProtectedIndexMagic); ProtectedPut(b, 8, next_spool_offset_); ProtectedPut(b, 16, physical.size());
    for (std::size_t i = 0; i < physical.size(); ++i)
    {
        const auto& range = physical[i]; const auto at = 24 + i * kIndexRangeBytes;
        ProtectedPut(b, at, range.object_id); ProtectedPut(b, at + 8, range.generation);
        ProtectedPut(b, at + 16, range.logical_offset); ProtectedPut(b, at + 24, range.bytes);
        ProtectedPut(b, at + 32, range.spool_offset); ProtectedPut(b, at + 40, range.wal_sequence);
        ProtectedPut(b, at + 48, range.checksum);
    }
    auto frame = protected_->epoch->Seal(ProtectedContext(nullptr, protected_->index_bytes), b);
    if (!frame) return false;
    if (!ProtectedWrite(protected_->index.value, protected_->index_bytes, frame.bytes.Bytes(), true) ||
        !ProtectedFlush(protected_->index.value, true))
    {
        protected_->rebuild_allowed = false; recovery_required_ = true;
        return false;
    }
    protected_->index_bytes += frame.bytes.Size();
    ++index_persist_count_; index_persist_bytes_ += frame.bytes.Size();
    ++index_journal_frame_count_; ++index_journal_snapshot_count_;
    return true;
}

bool PayloadSpool::RebuildProtectedIndex(std::span<const PersistedRangeReference> references,
    std::uint64_t safe_discard_sequence, std::span<const PersistedRangeReference> discardable_references) try
{
    const auto missing_authority = [this]() {
        if (!protected_ || !protected_->index_missing || continuation_baseline_ || protected_->maintenance_seen ||
            protected_->index.value != INVALID_HANDLE_VALUE || !protected_->anchor_ready || CleanupPresent(options_.root) ||
            !ProtectedExact(protected_->anchor.value, protected_marker_file_, false) ||
            !ProtectedExact(protected_->data.value, spool_file_, false)) return false;
        std::uint64_t size = 0;
        if (!ProtectedSize(protected_->data.value, size) || size != next_spool_offset_) return false;
        return GetFileAttributesW(index_file_.c_str()) == INVALID_FILE_ATTRIBUTES && GetLastError() == ERROR_FILE_NOT_FOUND;
    };
    const bool missing = missing_authority();
    if (!protected_ || !protected_->rebuild_allowed || protected_->maintenance_seen || (!ProtectedAuthority() && !missing) || safe_discard_sequence != 0 ||
        !discardable_references.empty() || references.size() > kProtectedMaxRanges) return false;
    std::vector<DirtyRange> rebuilt;
    rebuilt.reserve(references.size());
    std::uint64_t consumed = 0;
    for (const auto& reference : references)
    {
        if (!IsVolumeMatch(reference.volume_identity) || !reference.object_id || !reference.generation ||
            !reference.wal_sequence || !reference.payload_length || reference.payload_length > journal::kMaxJournalPlaintextBytes ||
            reference.logical_offset > UINT64_MAX - reference.payload_length ||
            std::all_of(reference.payload_sha256.begin(), reference.payload_sha256.end(), [](auto b) { return b == 0; })) return false;
        DirtyRange range{};
        range.object_id = reference.object_id; range.generation = reference.generation;
        range.logical_offset = reference.logical_offset; range.bytes = reference.payload_length;
        range.spool_offset = reference.spool_offset; range.wal_sequence = reference.wal_sequence;
        if (range.spool_offset > next_spool_offset_ || range.bytes + kProtectedOverhead > next_spool_offset_ - range.spool_offset ||
            !ChargeStartupPayloadBytes(range.bytes + kProtectedOverhead, options_.startup_payload_read_max_bytes, consumed)) return false;
        auto frame = crypto::SecureBytes::Allocate(static_cast<std::size_t>(range.bytes + kProtectedOverhead));
        if (!frame || !ProtectedIo(protected_->data.value, range.spool_offset, frame.bytes.Bytes(), false)) return false;
        auto plain = journal::ProtectedJournalEpoch::Open(options_.protected_key_directory.wstring(), options_.protected_binding,
            ProtectedContext(&range, range.spool_offset), frame.bytes.Bytes());
        std::array<std::uint8_t, 32> digest{};
        if (!plain || plain.bytes.Size() != range.bytes || !HashPayloadDigests(plain.bytes.Bytes(), &range.checksum, digest) ||
            digest != reference.payload_sha256) return false;
        range.created_at = std::chrono::steady_clock::now();
        rebuilt.push_back(range);
    }
    std::sort(rebuilt.begin(), rebuilt.end(), [](const auto& a, const auto& b) { return a.spool_offset < b.spool_offset; });
    std::uint64_t end = 0;
    for (std::size_t i = 0; i < rebuilt.size(); ++i)
    {
        const auto& range = rebuilt[i];
        if (range.spool_offset != end) return false;
        end += range.bytes + kProtectedOverhead;
        if (i < ranges_.size())
        {
            const auto& old = ranges_[i];
            if (old.object_id != range.object_id || old.generation != range.generation || old.logical_offset != range.logical_offset ||
                old.bytes != range.bytes || old.spool_offset != range.spool_offset || old.wal_sequence != range.wal_sequence ||
                old.checksum != range.checksum) return false;
        }
    }
    if (end != next_spool_offset_ || rebuilt.size() < ranges_.size()) return false;
    if (missing)
    {
        if (CleanupCut("rebuild-missing-index-data-flush") || !FlushFileBuffers(protected_->data.value) ||
            !missing_authority() || CleanupCut("rebuild-missing-index-before-create")) return false;
        protected_->rebuild_allowed = false;
        protected_->index.value = CreateFileW(index_file_.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ,
            nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        if (!ProtectedExact(protected_->index.value, index_file_, false) || CleanupCut("rebuild-missing-index-after-create") ||
            CleanupCut("rebuild-missing-index-flush") || !FlushFileBuffers(protected_->index.value)) return false;
        auto writer = journal::ProtectedJournalEpoch::AcquireWriter(options_.protected_key_directory.wstring(), options_.protected_binding);
        if (!writer) return false;
        protected_->epoch = std::move(writer.epoch);
        protected_->index_missing = false;
        protected_->rebuild_allowed = true;
    }
    protected_->physical_ranges = rebuilt;
    ranges_ = std::move(rebuilt);
    try { RebuildRangeSequenceIndex(); RebuildRangeLookup(); RecomputeOldestDirtyRangeLocked(); }
    catch (...) { protected_->rebuild_allowed = false; recovery_required_ = true; return false; }
    recovery_required_ = false;
    index_dirty_ = true;
    PublishNextSpoolOffsetHintLocked();
    return true;
}
catch (...)
{
    if (protected_) protected_->rebuild_allowed = false;
    recovery_required_ = true;
    return false;
}

PayloadSpool::ProtectedMaintenanceResult PayloadSpool::ReconcileProtectedHistory(
    const ProtectedCleanupProof& proof, std::span<const PersistedRangeReference> references)
{
    return ReconcileProtectedOriginalHistory(proof, references, {});
}

PayloadSpool::ProtectedMaintenanceResult PayloadSpool::ReconcileProtectedOriginalHistory(
    const ProtectedCleanupProof& proof, std::span<const PersistedRangeReference> references,
    std::span<const std::uint64_t> optional_inline_sequences)
{
    auto lock = AcquireMutex();
    bool wrote = false, protocol_started = false;
    const auto failed = [&]() {
        if ((wrote || protocol_started) && protected_) { protected_->rebuild_allowed = false; recovery_required_ = true; }
        return wrote ? ProtectedMaintenanceResult::RecoveryRequired : ProtectedMaintenanceResult::RejectedBeforeWrite;
    };
    try
    {
        if (!options_.protected_persistence || !protected_ || !protected_->maintenance_available ||
            !CleanupProofValid(proof, continuation_baseline_.has_value()) || proof.source_binding != options_.protected_binding ||
            (continuation_baseline_ && (!continuation_baseline_->authority || proof.cleanup_sequence < continuation_baseline_->floor)) ||
            !ProtectedPath(CleanupPath(options_.root, 1024, false)) || !ProtectedPath(CleanupPath(options_.root, 1024, true)) ||
            !ProtectedPath(options_.root / (std::wstring(kCleanupPrefix) + L"failed." + std::wstring(64, L'0') + L".15")) ||
            references.size() > kProtectedMaxRanges || references.size() > proof.wal_records ||
            !ProtectedExact(protected_->anchor.value, protected_marker_file_, false) ||
            !ProtectedExact(protected_->data.value, spool_file_, false) ||
            (!protected_->index_missing && !ProtectedExact(protected_->index.value, index_file_, false))) return failed();
        const bool missing_index = protected_->index_missing;
        if (missing_index && (continuation_baseline_ || protected_->maintenance_seen || CleanupPresent(options_.root))) return failed();
        std::uint64_t data_size = 0, index_size = 0, anchor_size = 0;
        if (!ProtectedSize(protected_->anchor.value, anchor_size) || anchor_size != kProtectedAnchorBytes ||
            !ProtectedSize(protected_->data.value, data_size) || data_size > options_.max_bytes ||
            (!missing_index && !ProtectedSize(protected_->index.value, index_size)) || index_size > kProtectedIndexLimit ||
            (options_.startup_index_max_bytes && index_size > options_.startup_index_max_bytes)) return failed();
        auto read_pass = journal::ProtectedJournalReadPass::Acquire(options_.protected_key_directory.wstring(), options_.protected_binding);
        if (!read_pass) return failed();

        std::vector<const PersistedRangeReference*> ordered;
        std::unordered_set<std::uint64_t> optional, sequences;
        if (optional_inline_sequences.size() > references.size()) return failed();
        for (auto sequence : optional_inline_sequences)
            if (!sequence || !optional.insert(sequence).second) return failed();
        std::size_t optional_found = 0;
        for (const auto& r : references)
        {
            if (!IsVolumeMatch(r.volume_identity) || !r.object_id || !r.generation || !r.wal_sequence || r.wal_sequence > proof.wal_last_sequence ||
                !r.payload_length || r.payload_length > journal::kMaxJournalPlaintextBytes || r.logical_offset > UINT64_MAX - r.payload_length ||
                r.spool_offset > options_.max_bytes || r.payload_length + kProtectedOverhead > options_.max_bytes - r.spool_offset ||
                std::all_of(r.payload_sha256.begin(), r.payload_sha256.end(), [](auto b) { return b == 0; })) return failed();
            if (!optional.empty() && !sequences.insert(r.wal_sequence).second) return failed();
            if (optional.contains(r.wal_sequence)) ++optional_found;
            ordered.push_back(&r);
        }
        if (optional_found != optional.size()) return failed();
        std::sort(ordered.begin(), ordered.end(), [](auto a, auto b) {
            return std::tie(a->wal_sequence, a->spool_offset) < std::tie(b->wal_sequence, b->spool_offset);
        });
        CleanupDigest refs_digest{};
        {
            auto& provider = SharedSha256Provider();
            if (!provider.algorithm || !provider.object_bytes) return failed();
            auto object = crypto::SecureBytes::Allocate(provider.object_bytes);
            auto encoded_ref = crypto::SecureBytes::Allocate(80);
            if (!object || !encoded_ref) return failed();
            struct HashOwner
            {
                BCRYPT_HASH_HANDLE value = nullptr;
                ~HashOwner() { if (value) BCryptDestroyHash(value); }
            } hash;
            if (CleanupCut("cleanup-reference-hash-create") || BCryptCreateHash(provider.algorithm, &hash.value,
                reinterpret_cast<PUCHAR>(object.bytes.Bytes().data()), static_cast<ULONG>(object.bytes.Size()), nullptr, 0, 0) < 0) return failed();
            // Same sorted 80-byte encodings and SHA-256, without a range-sized
            // locked allocation. Finish even an empty stream for wire compatibility.
            for (std::size_t n = 0; n < ordered.size(); ++n)
            {
                const auto& r = *ordered[n]; const auto b = encoded_ref.bytes.Bytes();
                if (n && ordered[n - 1]->wal_sequence == r.wal_sequence && ordered[n - 1]->spool_offset == r.spool_offset) return failed();
                ProtectedPut(b, 0, r.object_id); ProtectedPut(b, 8, r.generation); ProtectedPut(b, 16, r.logical_offset);
                ProtectedPut(b, 24, r.payload_length); ProtectedPut(b, 32, r.spool_offset); ProtectedPut(b, 40, r.wal_sequence);
                std::memcpy(b.data() + 48, r.payload_sha256.data(), 32);
                if (CleanupCut("cleanup-reference-hash-data") || BCryptHashData(hash.value,
                    reinterpret_cast<PUCHAR>(b.data()), static_cast<ULONG>(b.size()), 0) < 0) return failed();
            }
            if (CleanupCut("cleanup-reference-hash-finish") ||
                BCryptFinishHash(hash.value, refs_digest.data(), static_cast<ULONG>(refs_digest.size()), 0) < 0) return failed();
        }

        // Authenticate a contiguous bounded receipt chain. Only a final torn
        // intent/commit is eligible for caller-authorized preserved quarantine.
        std::map<std::uint64_t, unsigned> names;
        std::vector<std::unique_ptr<FileHandle>> quarantines;
        std::size_t entries = 0;
        for (const auto& entry : std::filesystem::directory_iterator(options_.root))
        {
            const auto name = entry.path().filename().wstring();
            if (name.size() < kCleanupPrefix.size() || CompareStringOrdinal(name.data(), static_cast<int>(kCleanupPrefix.size()),
                kCleanupPrefix.data(), static_cast<int>(kCleanupPrefix.size()), TRUE) != CSTR_EQUAL) continue;
            if (!name.starts_with(kCleanupPrefix)) return failed();
            if (++entries > 4096 || !ProtectedPath(entry.path())) return failed();
            const auto attributes = GetFileAttributesW(entry.path().c_str());
            if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY))) return failed();
            auto suffix = std::wstring_view(name).substr(kCleanupPrefix.size());
            if (suffix.starts_with(L"failed."))
            {
                auto h = std::make_unique<FileHandle>(); std::uint64_t size = 0;
                if (!CleanupOpen(*h, entry.path(), false) || !ProtectedSize(h->value, size) || size > kCleanupIntentBytes + kProtectedOverhead) return failed();
                quarantines.push_back(std::move(h)); continue;
            }
            if (suffix.size() != 23 || (suffix.substr(16) != L".intent" && suffix.substr(16) != L".commit")) return failed();
            std::uint64_t serial = 0;
            for (auto c : suffix.substr(0, 16)) { if (c < L'0' || c > L'9') return failed(); serial = serial * 10 + (c - L'0'); }
            if (!serial || serial > 1024) return failed();
            names[serial] |= suffix.substr(16) == L".intent" ? 1u : 2u;
        }
        CleanupDigest tip = continuation_baseline_ ? continuation_baseline_->tip : CleanupDigest{};
        std::uint64_t floor = continuation_baseline_ ? continuation_baseline_->floor : 0, reset_floor = floor, committed = 0;
        CleanupIntent intent{}, latest{};
        bool pending = false, bad_intent = false, bad_commit = false;
        std::vector<std::unique_ptr<FileHandle>> pins;
        std::vector<HANDLE> committed_handles;
        auto& durable_receipts = protected_->durable_cleanup_receipts;
        if (durable_receipts.size() > 2048 || durable_receipts.size() % 2) return failed();
        const auto durable_pairs = durable_receipts.size() / 2;
        for (std::size_t n = 1; n <= durable_pairs; ++n)
        {
            const auto name = names.find(n);
            if (name == names.end() || name->second != 3) return failed();
        }
        durable_receipts.reserve(2048);
        FileHandle* intent_handle = nullptr; FileHandle* bad_handle = nullptr;
        std::vector<std::byte> intent_frame, bad_frame;
        const auto open_receipt = [&](std::uint64_t serial, bool commit) -> FileHandle* {
            if (serial <= durable_pairs)
            {
                auto* cached = durable_receipts[static_cast<std::size_t>((serial - 1) * 2 + commit)].get();
                return cached && ProtectedExact(cached->value, CleanupPath(options_.root, serial, commit), false) ? cached : nullptr;
            }
            auto h = std::make_unique<FileHandle>();
            if (!CleanupOpen(*h, CleanupPath(options_.root, serial, commit), false)) return nullptr;
            pins.push_back(std::move(h)); return pins.back().get();
        };
        for (const auto& [serial, mask] : names)
        {
            if (serial != committed + 1 || !(mask & 1)) return failed();
            intent_handle = open_receipt(serial, false);
            if (!intent_handle || !CleanupRead(intent_handle->value, intent_frame)) return failed();
            auto opened = read_pass.reader->Open(ProtectedCleanupContext(serial, false), intent_frame);
            if (!opened || !CleanupDecode(opened.bytes.Bytes(), options_.protected_binding, intent, continuation_baseline_.has_value()))
            {
                // Missing keys, authentic-but-invalid receipts and full-length
                // tag corruption are unknown authority, never repairable tails.
                if (opened || intent_frame.size() >= kCleanupIntentBytes + kProtectedOverhead || mask != 1 || serial != names.rbegin()->first) return failed();
                bad_intent = true; bad_handle = intent_handle; bad_frame = intent_frame; break;
            }
            if (intent.serial != serial || intent.previous != tip || intent.previous_floor != floor || intent.previous_reset != reset_floor ||
                intent.data_bytes > options_.max_bytes) return failed();
            if (!(mask & 2)) { if (serial != names.rbegin()->first) return failed(); pending = true; break; }
            auto* commit_handle = open_receipt(serial, true); std::vector<std::byte> commit_frame;
            if (!commit_handle || !CleanupRead(commit_handle->value, commit_frame)) return failed();
            auto commit = read_pass.reader->Open(ProtectedCleanupContext(serial, true), commit_frame);
            CleanupDigest hash{};
            if (!HashPayloadSha256(intent_frame, hash)) return failed();
            if (!commit)
            {
                if (commit_frame.size() >= kCleanupCommitBytes + kProtectedOverhead || serial != names.rbegin()->first) return failed();
                pending = true; bad_commit = true; bad_handle = commit_handle; bad_frame = std::move(commit_frame); break;
            }
            const auto b = commit.bytes.Bytes();
            if (b.size() != kCleanupCommitBytes || ProtectedGet(b, 0) != kCleanupCommitMagic || ProtectedGet(b, 8) != 1 ||
                ProtectedGet(b, 16) != serial || std::memcmp(b.data() + 24, hash.data(), 32) || ProtectedGet(b, 56) != 0 ||
                !HashPayloadSha256(commit_frame, tip)) return failed();
            if (serial > durable_pairs)
            { committed_handles.push_back(intent_handle->value); committed_handles.push_back(commit_handle->value); }
            committed = serial; floor = intent.proof.cleanup_sequence;
            if (intent.reset) reset_floor = floor;
            latest = intent;
        }
        if (proof.cleanup_sequence < floor || (pending && (!CleanupSameProof(proof, intent.proof) || intent.refs != refs_digest || intent.references != references.size()))) return failed();

        const bool reset_endpoint = pending && intent.reset && data_size == 0;
        std::vector<DirtyRange> physical, live;
        if (!optional.empty())
        {
            if (reset_endpoint)
            {
                // The authenticated intent plus mandatory encrypted guard
                // certify the prior census after an interrupted all-clean reset.
                // Optional presence cannot be inferred anew from the zero file.
                for (auto* r : ordered)
                    if (r->wal_sequence > reset_floor && r->wal_sequence > proof.cleanup_sequence &&
                        !optional.contains(r->wal_sequence)) return failed();
            }
            else
            {
                std::unordered_set<std::uint64_t> matched;
                std::uint64_t cursor = 0, consumed = 0;
                const auto read_limit = options_.startup_payload_read_max_bytes ?
                    (std::min)(options_.startup_payload_read_max_bytes, kMaxDirtyFlushBytes) : kMaxDirtyFlushBytes;
                while (cursor < data_size)
                {
                    std::array<std::byte, journal::kJournalRecordHeaderBytes> header{};
                    if (matched.size() >= kProtectedMaxRanges || data_size - cursor < header.size() ||
                        !ProtectedIo(protected_->data.value, cursor, header, false) ||
                        std::memcmp(header.data(), "APFSREC1", 8) || ProtectedGet(header, 8) != (std::uint64_t{64} << 32 | 1)) return failed();
                    const auto size = ProtectedGet(header, 16) & 0xffffffffull;
                    if (size <= kProtectedOverhead || size > journal::kMaxJournalRecordBytes || size > data_size - cursor ||
                        ProtectedGet(header, 16) >> 32 != size - journal::kJournalRecordHeaderBytes) return failed();
                    const PersistedRangeReference* selected = nullptr;
                    DirtyRange selected_range{};
                    for (auto* r : ordered)
                    {
                        if (r->wal_sequence <= reset_floor || r->spool_offset != cursor || r->payload_length + kProtectedOverhead != size) continue;
                        if (!ChargeStartupPayloadBytes(size, read_limit, consumed)) return failed();
                        DirtyRange range{};
                        range.object_id = r->object_id; range.generation = r->generation; range.logical_offset = r->logical_offset;
                        range.bytes = r->payload_length; range.spool_offset = cursor; range.wal_sequence = r->wal_sequence;
                        range.created_at = std::chrono::steady_clock::now();
                        auto frame = crypto::SecureBytes::Allocate(static_cast<std::size_t>(size));
                        if (!frame || !ProtectedIo(protected_->data.value, cursor, frame.bytes.Bytes(), false)) return failed();
                        auto plain = read_pass.reader->Open(ProtectedContext(&range, cursor), frame.bytes.Bytes());
                        CleanupDigest digest{};
                        if (!plain || plain.bytes.Size() != range.bytes ||
                            !HashPayloadDigests(plain.bytes.Bytes(), &range.checksum, digest) || digest != r->payload_sha256) continue;
                        if (selected) return failed();
                        selected = r; selected_range = range;
                    }
                    if (!selected || !matched.insert(selected->wal_sequence).second) return failed();
                    physical.push_back(selected_range);
                    if (selected_range.wal_sequence > proof.cleanup_sequence) live.push_back(selected_range);
                    cursor += size;
                }
                for (auto* r : ordered)
                    if (r->wal_sequence > reset_floor && !optional.contains(r->wal_sequence) && !matched.contains(r->wal_sequence)) return failed();
                if (pending && data_size != intent.data_bytes) return failed();
            }
        }
        else
        {
        std::vector<const PersistedRangeReference*> physical_refs;
        for (auto* r : ordered) if (r->wal_sequence > reset_floor) physical_refs.push_back(r);
        std::sort(physical_refs.begin(), physical_refs.end(), [](auto a, auto b) { return a->spool_offset < b->spool_offset; });
        std::uint64_t physical_end = 0;
        for (auto* r : physical_refs)
        {
            if (r->spool_offset != physical_end) return failed();
            physical_end += r->payload_length + kProtectedOverhead;
        }
        if ((data_size != physical_end && !reset_endpoint) || (pending && physical_end != intent.data_bytes)) return failed();
        std::uint64_t consumed = 0;
        for (auto* r : physical_refs)
        {
            DirtyRange range{};
            range.object_id = r->object_id; range.generation = r->generation; range.logical_offset = r->logical_offset;
            range.bytes = r->payload_length; range.spool_offset = r->spool_offset; range.wal_sequence = r->wal_sequence;
            range.created_at = std::chrono::steady_clock::now();
            if (!reset_endpoint)
            {
                if (!ChargeStartupPayloadBytes(range.bytes + kProtectedOverhead, options_.startup_payload_read_max_bytes, consumed)) return failed();
                auto frame = crypto::SecureBytes::Allocate(static_cast<std::size_t>(range.bytes + kProtectedOverhead));
                if (!frame || !ProtectedIo(protected_->data.value, range.spool_offset, frame.bytes.Bytes(), false)) return failed();
                auto plain = read_pass.reader->Open(ProtectedContext(&range, range.spool_offset), frame.bytes.Bytes());
                CleanupDigest digest{};
                if (!plain || plain.bytes.Size() != range.bytes || !HashPayloadDigests(plain.bytes.Bytes(), &range.checksum, digest) || digest != r->payload_sha256) return failed();
            }
            physical.push_back(range);
            if (range.wal_sequence > proof.cleanup_sequence) live.push_back(range);
        }
        }
        CleanupDigest data_hash{}, index_hash{};
        if (missing_index)
        {
            // The complete original-derived census above includes optional
            // inline refs and authenticates every physical frame before creation.
            if (CleanupCut("rebuild-missing-index-data-flush") || !FlushFileBuffers(protected_->data.value) ||
                CleanupPresent(options_.root) || CleanupCut("rebuild-missing-index-before-create")) return failed();
            protected_->rebuild_allowed = false;
            protected_->index.value = CreateFileW(index_file_.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ,
                nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
            wrote = protected_->index.value != INVALID_HANDLE_VALUE;
            if (!ProtectedExact(protected_->index.value, index_file_, false) || CleanupCut("rebuild-missing-index-after-create") ||
                CleanupCut("rebuild-missing-index-flush") || !FlushFileBuffers(protected_->index.value)) return failed();
            protected_->index_missing = false;
        }
        if (!CleanupFileHash(protected_->data.value, data_size, data_hash) || !CleanupFileHash(protected_->index.value, index_size, index_hash)) return failed();
        if (pending && (intent.reset != static_cast<std::uint64_t>(live.empty()) || (!reset_endpoint && data_hash != intent.data))) return failed();
        const auto valid_guard = [&](std::uint64_t serial) {
            if (!serial && !continuation_baseline_) return false;
            if (index_size < kCleanupGuardBytes) return false;
            std::array<std::byte, kCleanupGuardBytes> frame{};
            auto context = serial || !continuation_baseline_ ? ProtectedCleanupContext(serial, false) : ContinuationSpoolContext(*continuation_baseline_);
            if (serial) { if (context.purpose != 0x505304u) return false; context.purpose = 0x505306u; }
            if (!ProtectedIo(protected_->index.value, 0, frame, false)) return false;
            auto plain = read_pass.reader->Open(context, frame);
            return plain && plain.bytes.Size() == 24 && ProtectedGet(plain.bytes.Bytes(), 0) == kCleanupCommitMagic &&
                ProtectedGet(plain.bytes.Bytes(), 8) == (serial ? 1 : 6) &&
                ProtectedGet(plain.bytes.Bytes(), 16) == (serial ? serial : continuation_baseline_->floor);
        };
        // The guard was durable BEFORE data reset. Its loss is unknown damage,
        // not a recoverable zero-index endpoint or permission for older writers.
        if (reset_endpoint && intent.data_bytes != 0 && !valid_guard(intent.serial)) return failed();
        const bool baseline_endpoint = continuation_baseline_ && !committed && references.empty() &&
            proof.cleanup_sequence == continuation_baseline_->floor;
        const bool idempotent = !pending && !bad_intent && data_size == 0 && index_size == kCleanupGuardBytes &&
            valid_guard(committed) && (baseline_endpoint || (committed && latest.reset &&
            CleanupSameProof(proof, latest.proof) && latest.refs == refs_digest && latest.references == references.size()));
        const auto index_limit = options_.startup_index_max_bytes ? (std::min)(kProtectedIndexLimit, options_.startup_index_max_bytes) : kProtectedIndexLimit;
        if (kCleanupGuardBytes + (live.empty() ? 0 : 24 + physical.size() * kIndexRangeBytes + kProtectedOverhead) > index_limit ||
            (!idempotent && ((!pending && committed >= 1024) || entries + (pending ? 1 : 2) > 4096))) return failed();

        // Flush the exact authenticated originals even for a freshly reopened
        // owner or zero-byte reset endpoint, before any receipt/namespace write.
        if (CleanupCut("cleanup-original-data-flush") || !FlushFileBuffers(protected_->data.value) ||
            CleanupCut("cleanup-original-index-flush") || !FlushFileBuffers(protected_->index.value) ||
            !ProtectedExact(protected_->data.value, spool_file_, false) || !ProtectedExact(protected_->index.value, index_file_, false) ||
            CleanupCut("cleanup-after-original-barrier")) return failed();
        // Complete receipt bytes may also come from an ambiguously flushed
        // owner. Durably retain the chain before referencing its tip or success.
        for (auto h : committed_handles)
            if (CleanupCut("cleanup-chain-flush") || !FlushFileBuffers(h)) return failed();
        for (const auto& h : quarantines)
            if (CleanupCut("cleanup-quarantine-flush") || !FlushFileBuffers(h->value)) return failed();
        if (CleanupCut("cleanup-after-chain-barrier")) return failed();
        // Transfer the exact handles just flushed, in contiguous pair order.
        // Failed/reopened owners start with no cached durability proof.
        for (std::size_t n = 0; n < committed_handles.size(); ++n)
        {
            if (n >= pins.size() || !pins[n] || pins[n]->value != committed_handles[n]) return failed();
            durable_receipts.push_back(std::move(pins[n]));
        }
        if (durable_receipts.size() != committed * 2) return failed();
        if (!protected_->epoch)
        {
            wrote = true; // Even a failed acquisition may leave a published slot.
            auto epoch = journal::ProtectedJournalEpoch::AcquireWriter(options_.protected_key_directory.wstring(), options_.protected_binding);
            if (!epoch) return failed(); protected_->epoch = std::move(epoch.epoch);
        }
        const auto publish_view = [&]() {
            if (live.empty()) physical.clear();
            protected_->physical_ranges = std::move(physical); ranges_ = std::move(live);
            protected_->cleanup_floor = proof.cleanup_sequence; protected_->maintenance_seen = true;
            next_spool_offset_ = ranges_.empty() ? 0 : data_size; protected_->index_bytes = kCleanupGuardBytes;
            RebuildRangeSequenceIndex(); RebuildRangeLookup(); RecomputeOldestDirtyRangeLocked(); ClearValidatedPayloadCacheLocked();
            PublishNextSpoolOffsetHintLocked(); bytes_since_sync_ = appends_since_sync_ = 0;
            recovery_required_ = false; protected_->rebuild_allowed = true; index_dirty_ = !ranges_.empty();
        };
        // A completed all-clean operation is idempotent under the SAME authority.
        if (idempotent)
        { publish_view(); return ProtectedMaintenanceResult::Succeeded; }
        if (bad_intent)
        {
            protocol_started = true;
            wrote = true;
            if (!CleanupQuarantine(bad_handle->value, options_.root, bad_frame)) return failed();
            intent_handle = nullptr;
        }
        if (!pending)
        {
            intent = {}; intent.proof = proof; intent.serial = committed + 1; intent.reset = live.empty(); intent.references = references.size();
            intent.data_bytes = data_size; intent.index_bytes = index_size; intent.previous_reset = reset_floor; intent.previous_floor = floor;
            intent.refs = refs_digest; intent.data = data_hash; intent.index = index_hash; intent.previous = tip;
            auto plain = CleanupEncode(intent); if (!plain) return failed();
            const auto context = ProtectedCleanupContext(intent.serial, false); if (context.purpose != 0x505304u) return failed();
            auto frame = protected_->epoch->Seal(context, plain.bytes.Bytes()); if (!frame) return failed();
            protocol_started = true;
            if (CleanupCut("cleanup-before-intent-create")) return failed();
            auto h = std::make_unique<FileHandle>();
            if (!CleanupOpen(*h, CleanupPath(options_.root, intent.serial, false), true)) return failed();
            intent_handle = h.get(); pins.push_back(std::move(h)); wrote = true; protected_->maintenance_seen = true;
            if (CleanupCut("cleanup-after-intent-create")) return failed();
            if (CleanupCut("cleanup-partial-intent-write")) { (void)ProtectedIo(intent_handle->value, 0, frame.bytes.Bytes().first(13), true); return failed(); }
            if (!ProtectedIo(intent_handle->value, 0, frame.bytes.Bytes(), true) || CleanupCut("cleanup-after-intent-write")) return failed();
            intent_frame.assign(frame.bytes.Bytes().begin(), frame.bytes.Bytes().end());
        }
        // A readable intent from an ambiguous prior flush is not a durable one.
        if (CleanupCut("cleanup-intent-flush") || !FlushFileBuffers(intent_handle->value) || CleanupCut("cleanup-after-intent-flush")) return failed();
        std::vector<std::byte> readback;
        if (!CleanupRead(intent_handle->value, readback) || readback != intent_frame || CleanupCut("cleanup-after-intent-readback")) return failed();
        // Publish an incompatible, authenticated guard before ANY data removal.
        // Older protected-spool binaries fail authentication instead of accepting
        // an empty store while ignoring its cleanup floor/receipt protocol.
        auto guard_plain = crypto::SecureBytes::Allocate(24);
        if (!guard_plain) return failed();
        ProtectedPut(guard_plain.bytes.Bytes(), 0, kCleanupCommitMagic); ProtectedPut(guard_plain.bytes.Bytes(), 8, 1);
        ProtectedPut(guard_plain.bytes.Bytes(), 16, intent.serial);
        auto guard_context = ProtectedCleanupContext(intent.serial, false); if (guard_context.purpose != 0x505304u) return failed();
        guard_context.purpose = 0x505306u;
        auto guard = protected_->epoch->Seal(guard_context, guard_plain.bytes.Bytes()); if (!guard) return failed();
        if (CleanupCut("cleanup-before-guard-write")) return failed();
        wrote = true;
        if (CleanupCut("cleanup-partial-guard-write")) { (void)ProtectedIo(protected_->index.value, 0, guard.bytes.Bytes().first(13), true); return failed(); }
        if (!ProtectedIo(protected_->index.value, 0, guard.bytes.Bytes(), true) || CleanupCut("cleanup-after-guard-write") ||
            CleanupCut("cleanup-guard-flush") || !FlushFileBuffers(protected_->index.value) || CleanupCut("cleanup-after-guard-flush")) return failed();
        std::array<std::byte, kCleanupGuardBytes> guard_readback{};
        if (!ProtectedIo(protected_->index.value, 0, guard_readback, false) ||
            !std::equal(guard_readback.begin(), guard_readback.end(), guard.bytes.Bytes().begin(), guard.bytes.Bytes().end()) ||
            CleanupCut("cleanup-after-guard-readback")) return failed();
        const auto truncate = [&](HANDLE h, bool data) {
            if (CleanupCut(data ? "cleanup-before-data-reset" : "cleanup-before-index-reset")) return false;
            wrote = true;
            LARGE_INTEGER end{}; end.QuadPart = data ? 0 : static_cast<LONGLONG>(kCleanupGuardBytes);
            if (!SetFilePointerEx(h, end, nullptr, FILE_BEGIN) || !SetEndOfFile(h) || CleanupCut(data ? "cleanup-after-data-reset" : "cleanup-after-index-reset")) return false;
            return !CleanupCut(data ? "cleanup-data-reset-flush" : "cleanup-index-reset-flush") && FlushFileBuffers(h) &&
                !CleanupCut(data ? "cleanup-after-data-reset-flush" : "cleanup-after-index-reset-flush");
        };
        if ((intent.reset && !truncate(protected_->data.value, true)) || !truncate(protected_->index.value, false)) return failed();
        if (bad_commit)
        {
            wrote = true;
            if (!CleanupQuarantine(bad_handle->value, options_.root, bad_frame)) return failed();
        }
        auto commit_plain = crypto::SecureBytes::Allocate(kCleanupCommitBytes); CleanupDigest intent_hash{};
        if (!commit_plain || !HashPayloadSha256(intent_frame, intent_hash)) return failed();
        const auto b = commit_plain.bytes.Bytes();
        ProtectedPut(b, 0, kCleanupCommitMagic); ProtectedPut(b, 8, 1); ProtectedPut(b, 16, intent.serial);
        std::memcpy(b.data() + 24, intent_hash.data(), 32);
        const auto context = ProtectedCleanupContext(intent.serial, true); if (context.purpose != 0x505305u) return failed();
        auto commit = protected_->epoch->Seal(context, b); if (!commit) return failed();
        protocol_started = true;
        if (CleanupCut("cleanup-before-commit-create")) return failed();
        auto commit_handle = std::make_unique<FileHandle>();
        if (!CleanupOpen(*commit_handle, CleanupPath(options_.root, intent.serial, true), true)) return failed();
        wrote = true;
        if (CleanupCut("cleanup-after-commit-create")) return failed();
        if (CleanupCut("cleanup-partial-commit-write")) { (void)ProtectedIo(commit_handle->value, 0, commit.bytes.Bytes().first(13), true); return failed(); }
        if (!ProtectedIo(commit_handle->value, 0, commit.bytes.Bytes(), true) || CleanupCut("cleanup-after-commit-write") ||
            CleanupCut("cleanup-commit-flush") || !FlushFileBuffers(commit_handle->value) || CleanupCut("cleanup-after-commit-flush") ||
            !CleanupRead(commit_handle->value, readback) || !std::equal(readback.begin(), readback.end(), commit.bytes.Bytes().begin(), commit.bytes.Bytes().end()) ||
            CleanupCut("cleanup-after-commit-readback")) return failed();
        const auto intent_pin = std::find_if(pins.begin(), pins.end(), [&](const auto& h) { return h.get() == intent_handle; });
        if (intent_pin == pins.end() || durable_receipts.size() != (intent.serial - 1) * 2) return failed();
        durable_receipts.push_back(std::move(*intent_pin)); durable_receipts.push_back(std::move(commit_handle));
        publish_view();
        return ProtectedMaintenanceResult::Succeeded;
    }
    catch (...) { return failed(); }
}

bool PayloadSpool::OverlayProtected(const ReadRequest& request, std::size_t& bytes_overlayed,
    bool require_full_coverage, std::uint64_t* logical_end) const
{
    if (recovery_required_ || !protected_ || !protected_->rebuild_allowed || !ProtectedAuthority() ||
        request.destination.size() > crypto::SecureBytes::kMaxBytes) return false;
    if (logical_end) *logical_end = 0;
    const auto lookup = range_object_lookup_.find({request.object_id, request.generation});
    if (lookup == range_object_lookup_.end()) return !require_full_coverage;
    auto staging = crypto::SecureBytes::Allocate(request.destination.size());
    if (!staging) return false;
    const auto destination = staging.bytes.Bytes();
    std::copy(request.destination.begin(), request.destination.end(), destination.begin());
    std::vector<std::pair<std::uint64_t, std::uint64_t>> covered;
    const auto end = request.logical_offset + request.destination.size();
    for (const auto i : lookup->second)
    {
        const auto& range = ranges_[i];
        const auto tail = range.logical_offset + range.bytes;
        if (logical_end) *logical_end = (std::max)(*logical_end, tail);
        const auto begin = (std::max)(request.logical_offset, range.logical_offset);
        const auto finish = (std::min)(end, tail);
        if (begin >= finish) continue;
        auto plain = ReadProtectedRange(range);
        if (!plain) return false;
        const auto source = plain.bytes.Bytes().subspan(static_cast<std::size_t>(begin - range.logical_offset), static_cast<std::size_t>(finish - begin));
        std::copy(source.begin(), source.end(), destination.begin() + static_cast<std::ptrdiff_t>(begin - request.logical_offset));
        covered.push_back({begin, finish});
    }
    std::sort(covered.begin(), covered.end());
    std::uint64_t covered_end = request.logical_offset;
    std::size_t total = 0;
    for (const auto& [begin, finish] : covered)
    {
        if (finish > covered_end) total += static_cast<std::size_t>(finish - (std::max)(begin, covered_end));
        covered_end = (std::max)(covered_end, finish);
    }
    if (require_full_coverage && total != destination.size()) return false;
    std::copy(destination.begin(), destination.end(), request.destination.begin());
    bytes_overlayed = total;
    return true;
}

PayloadSpool::PayloadSpool(Options options)
    : options_(std::move(options))
    , perf_counters_enabled_(ReadPerfCountersEnabled())
{
    if (options_.root.empty() && !options_.protected_persistence)
    {
        options_.root = ResolveDefaultRoot();
    }
    spool_file_ = options_.root / "payload-spool.bin";
    index_file_ = options_.root / "payload-spool.idx";
    protected_marker_file_ = options_.root / kProtectedMarkerName;
    if (options_.protected_persistence)
    {
        recovery_required_ = true;
        try { (void)InitializeProtected(); }
        catch (...) { if (protected_) protected_->rebuild_allowed = false; }
        return;
    }
    if (ProtectedStoreMarkerPresent())
    {
        protected_format_refused_ = true; recovery_required_ = true;
        return;
    }
    index_delta_enabled_ = !ReadEnvironmentFlag("APFSACCESS_DISABLE_INDEX_DELTA");
    const auto index_loaded = LoadIndex();
    recovery_required_ = recovery_required_ || !index_loaded;
    ordinary_layout_unproven_ = !index_loaded || (ranges_.empty() && next_spool_offset_ != 0);
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
    if (MutationRefused()) return AppendStatus::StorageFailure;
    if (options_.protected_persistence) return CheckAppendCapacity(payload_bytes);
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
    if (MutationRefused()) return AppendStatus::StorageFailure;
    if (!IsVolumeMatch(request.volume_identity) ||
        request.object_id == 0 ||
        request.payload.empty() ||
        request.payload.size() > static_cast<std::size_t>((std::numeric_limits<std::uint64_t>::max)() - request.logical_offset))
    {
        return AppendStatus::InvalidRequest;
    }

    auto lock = AcquireMutex();

    if (options_.protected_persistence)
    {
        try { return AppendProtected(request, result); }
        catch (...) { if (protected_) protected_->rebuild_allowed = false; recovery_required_ = true; return AppendStatus::StorageFailure; }
    }

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

bool PayloadSpool::WithProtectedPersistedRange(const PersistedRangeReference& reference,
    std::uint64_t max_payload_bytes, const std::function<bool(std::span<const std::byte>)>& consumer,
    std::string& error) const
{
    error.clear();
    const auto fail = [&](const char* reason) { error = reason; return false; };
    if (!options_.protected_persistence || !consumer || !max_payload_bytes ||
        max_payload_bytes > journal::kMaxJournalPlaintextBytes ||
        !reference.payload_length || reference.payload_length > max_payload_bytes ||
        !IsVolumeMatch(reference.volume_identity) || !reference.object_id || !reference.generation ||
        !reference.wal_sequence || reference.logical_offset > UINT64_MAX - reference.payload_length ||
        std::all_of(reference.payload_sha256.begin(), reference.payload_sha256.end(), [](auto b) { return b == 0; }))
        return fail("ProtectedPayloadReferenceInvalid");
    try {
        auto lock = AcquireMutex();
        if (recovery_required_ || !protected_ || !protected_->rebuild_allowed)
            return fail("ProtectedPayloadReconciliationRequired");
        const auto found = range_lookup_.find({reference.object_id, reference.generation, reference.wal_sequence});
        if (found == range_lookup_.end()) return fail("ProtectedPayloadReferenceUnavailable");
        const DirtyRange* matched = nullptr;
        for (auto index : found->second) {
            if (index >= ranges_.size()) return fail("ProtectedPayloadReferenceUnavailable");
            const auto& range = ranges_[index];
            if (range.logical_offset != reference.logical_offset || range.bytes != reference.payload_length ||
                range.spool_offset != reference.spool_offset) continue;
            if (matched) return fail("ProtectedPayloadReferenceUnavailable");
            matched = &range;
        }
        if (!matched) return fail("ProtectedPayloadReferenceUnavailable");
        auto plain = ReadProtectedRange(*matched);
        std::array<std::uint8_t, 32> digest{};
        if (!plain || plain.bytes.Size() != reference.payload_length ||
            !HashPayloadSha256(plain.bytes.Bytes(), digest) || digest != reference.payload_sha256)
            return fail("ProtectedPayloadAuthenticationFailed");
        // The sole plaintext owner stays locked until the synchronous borrow
        // returns, including consumer rejection and stack unwinding.
        if (!consumer(plain.bytes.Bytes())) return fail("ProtectedPayloadConsumerRejected");
        return true;
    } catch (...) { return fail("ProtectedPayloadConsumerOrProviderFailed"); }
}

bool PayloadSpool::ReadPersistedRange(
    const PersistedRangeReference& reference,
    std::vector<std::byte>& payload) const
{
    if (options_.protected_persistence && !payload.empty()) SecureZeroMemory(payload.data(), payload.size());
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
    if (options_.protected_persistence)
    {
        if (!matched_range || !protected_ || !protected_->rebuild_allowed) return false;
        auto plain = ReadProtectedRange(*matched_range);
        std::array<std::uint8_t, 32> digest{};
        if (!plain || !HashPayloadSha256(plain.bytes.Bytes(), digest) || digest != reference.payload_sha256) return false;
        // Caller-owned legacy vector output is intentionally outside SecureBytes.
        payload.assign(plain.bytes.Bytes().begin(), plain.bytes.Bytes().end());
        return true;
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

bool PayloadSpool::RestoreInlineRange(
    const PersistedRangeReference& reference, std::span<const std::byte> payload)
{
    if (MutationRefused()) return false;
    if (options_.protected_persistence)
    {
        auto lock = AcquireMutex();
        if (recovery_required_ || !IsVolumeMatch(reference.volume_identity) ||
            payload.size() != reference.payload_length || !protected_ || !protected_->rebuild_allowed) return false;
        for (const auto& range : ranges_)
        {
            if (range.object_id != reference.object_id || range.generation != reference.generation ||
                range.logical_offset != reference.logical_offset || range.bytes != reference.payload_length ||
                range.spool_offset != reference.spool_offset || range.wal_sequence != reference.wal_sequence) continue;
            auto plain = ReadProtectedRange(range);
            std::array<std::uint8_t, 32> digest{};
            return plain && HashPayloadSha256(plain.bytes.Bytes(), digest) && digest == reference.payload_sha256 &&
                std::equal(plain.bytes.Bytes().begin(), plain.bytes.Bytes().end(), payload.begin());
        }
        return false;
    }
    std::array<std::uint8_t, 32> sha256{};
    if (!IsVolumeMatch(reference.volume_identity) || reference.object_id == 0 ||
        reference.generation == 0 || reference.wal_sequence == 0 || payload.empty() ||
        reference.payload_length != payload.size() ||
        reference.logical_offset > UINT64_MAX - payload.size() ||
        reference.spool_offset > static_cast<std::uint64_t>(INT64_MAX) - payload.size() ||
        !HashPayloadSha256(payload, sha256) || sha256 != reference.payload_sha256) return false;
    auto lock = AcquireMutex();
    if (recovery_required_) return false;
    const auto end = reference.spool_offset + reference.payload_length;
    std::optional<std::size_t> existing;
    for (std::size_t i = 0; i < ranges_.size(); ++i)
    {
        const auto& range = ranges_[i];
        const bool overlaps = range.spool_offset < end &&
            reference.spool_offset < RangeEnd(range.spool_offset, range.bytes);
        if (!overlaps && range.wal_sequence != reference.wal_sequence) continue;
        if (existing || range.object_id != reference.object_id || range.generation != reference.generation ||
            range.wal_sequence != reference.wal_sequence || range.logical_offset != reference.logical_offset ||
            range.bytes != reference.payload_length || range.spool_offset != reference.spool_offset) return false;
        existing = i;
    }
    DirtyRange restored{};
    restored.object_id = reference.object_id; restored.generation = reference.generation;
    restored.logical_offset = reference.logical_offset; restored.bytes = reference.payload_length;
    restored.spool_offset = reference.spool_offset; restored.wal_sequence = reference.wal_sequence;
    restored.checksum = HashPayload(payload); restored.created_at = std::chrono::steady_clock::now();
    std::vector<std::byte> physical;
    if (existing && ReadRangePayloadFromHandleLocked(ranges_[*existing], physical))
        return physical.size() == payload.size() && std::equal(physical.begin(), physical.end(), payload.begin());
    const bool present = ReadRangePayloadFromHandleLocked(restored, physical) &&
        physical.size() == payload.size() && std::equal(physical.begin(), physical.end(), payload.begin());
    if (!present)
    {
        if (options_.max_bytes != 0 && end > options_.max_bytes) return false;
        if (!CloseAppendStreamLocked()) return false;
        ClearValidatedPayloadCacheLocked();
        std::unique_lock<std::shared_mutex> io_lock(payload_io_mutex_);
        std::error_code ec;
        std::filesystem::create_directories(options_.root, ec);
        if (ec) return false;
        root_ready_ = true;
        FileHandle file{CreateFileW(spool_file_.c_str(), GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_ALWAYS,
            FILE_ATTRIBUTE_NORMAL, nullptr)};
        LARGE_INTEGER position{};
        position.QuadPart = static_cast<LONGLONG>(reference.spool_offset);
        if (file.value == INVALID_HANDLE_VALUE || !SetFilePointerEx(file.value, position, nullptr, FILE_BEGIN)) return false;
        std::size_t cursor = 0;
        while (cursor != payload.size())
        {
            const auto count = static_cast<DWORD>((std::min)(payload.size() - cursor,
                static_cast<std::size_t>((std::numeric_limits<DWORD>::max)())));
            DWORD written = 0;
            if (!WriteFile(file.value, payload.data() + cursor, count, &written, nullptr) || written != count)
            { recovery_required_ = true; return false; }
            cursor += written;
        }
        if (!FlushFileBuffers(file.value)) { recovery_required_ = true; return false; }
    }
    if (existing && present) return true;
    if (existing) ranges_[*existing] = restored;
    else ranges_.push_back(restored);
    next_spool_offset_ = (std::max)(next_spool_offset_, end);
    PublishNextSpoolOffsetHintLocked();
    RebuildRangeSequenceIndex();
    RebuildRangeLookup();
    RecomputeOldestDirtyRangeLocked();
    index_dirty_ = true;
    index_requires_snapshot_ = true;
    pending_index_additions_.clear();
    return true;
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
    if (protected_format_refused_ || (!options_.protected_persistence && ProtectedStoreMarkerPresent())) return false;

    if (options_.protected_persistence) return RebuildProtectedIndex(references, safe_discard_sequence, discardable_references);

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
        ordinary_layout_unproven_ = false;
        return true;
    }

    ranges_ = std::move(recovered_ranges);
    RebuildRangeSequenceIndex();
    RebuildRangeLookup();
    RecomputeOldestDirtyRangeLocked();
    recovery_required_ = false;
    ordinary_layout_unproven_ = false;
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
    if (options_.protected_persistence) return OverlayProtected(request, bytes_overlayed, false, nullptr);
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
    if (options_.protected_persistence) return OverlayProtected(request, bytes_overlayed, false, &logical_end);
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
    if (options_.protected_persistence) return OverlayProtected(request, bytes_overlayed, true, nullptr);
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
    if (MutationRefused()) return false;

    if (options_.protected_persistence)
    {
        if (recovery_required_ || !protected_ || !protected_->rebuild_allowed || !ProtectedAuthority()) return false;
        return std::none_of(ranges_.begin(), ranges_.end(), [wal_sequence](const auto& r) { return r.wal_sequence <= wal_sequence; });
    }

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
    if (MutationRefused()) return false;

    if (options_.protected_persistence)
    {
        if (recovery_required_ || !protected_ || !protected_->rebuild_allowed || !ProtectedAuthority()) return false;
        return !range_sequences_.contains(wal_sequence);
    }

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
    if (options_.protected_persistence) return false;
    if (protected_format_refused_ || ProtectedStoreMarkerPresent()) return false;
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
    ordinary_layout_unproven_ = false;
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

bool PayloadSpool::MatchesProtectedMaintenanceAuthority(const journal::JournalDigest& binding,
    std::string_view volume, const std::filesystem::path& original_keys) const noexcept
{
    try {
        if (!options_.protected_persistence || binding != options_.protected_binding || !IsVolumeMatch(volume) ||
            !ProtectedPath(original_keys) || !ProtectedPath(options_.protected_key_directory) ||
            !ProtectedPath(CleanupPath(options_.root, 1024, false)) || !ProtectedPath(CleanupPath(options_.root, 1024, true)) ||
            !ProtectedPath(options_.root / (std::wstring(kCleanupPrefix) + L"failed." + std::wstring(64, L'0') + L".15"))) return false;
        const auto order = CompareStringOrdinal(original_keys.c_str(), -1, options_.protected_key_directory.c_str(), -1, TRUE);
        return order == CSTR_LESS_THAN || order == CSTR_GREATER_THAN;
    } catch (...) { return false; }
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
    if (MutationRefused()) return AppendStatus::StorageFailure;
    if (options_.protected_persistence)
    {
        if (!payload_bytes || payload_bytes > journal::kMaxJournalPlaintextBytes) return AppendStatus::InvalidRequest;
        if (recovery_required_ || !protected_ || !protected_->epoch || !protected_->rebuild_allowed) return AppendStatus::StorageFailure;
        if (protected_->physical_ranges.size() >= kProtectedMaxRanges) return AppendStatus::QuotaExceeded;
        const auto limit = options_.startup_index_max_bytes ?
            (std::min)(kProtectedIndexLimit, options_.startup_index_max_bytes) : kProtectedIndexLimit;
        const auto reserved = 24 + (protected_->physical_ranges.size() + 1) * kIndexRangeBytes + kProtectedOverhead;
        if (reserved > limit || protected_->index_bytes > limit - reserved || next_spool_offset_ > options_.max_bytes ||
            payload_bytes + kProtectedOverhead > options_.max_bytes - next_spool_offset_) return AppendStatus::QuotaExceeded;
        // Authority validation is performed in AppendProtected before any write.
        return AppendStatus::Succeeded;
    }
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

    if (!EnsureAppendStreamLocked() || MutationRefused())
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
    if (MutationRefused()) return false;
    if (options_.protected_persistence)
    {
        if (recovery_required_ || !protected_ || !protected_->rebuild_allowed || !ProtectedAuthority()) return false;
        if (!ProtectedFlush(protected_->data.value, false))
        {
            protected_->rebuild_allowed = false; recovery_required_ = true;
            return false;
        }
        bytes_since_sync_ = 0; appends_since_sync_ = 0;
        ++spool_sync_count_; ++spool_sync_handle_flush_count_;
        if (observe_durable_flush) ++payload_only_flush_count_;
        return true;
    }
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
    if (MutationRefused()) return false;
    if (options_.protected_persistence)
    {
        if (!FlushPayloadBytesLocked(false) || (index_dirty_ && !PersistProtectedIndex())) return false;
        index_dirty_ = false;
        ++durable_flush_count_;
        return true;
    }
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

    std::uintmax_t index_size = 0;
    if (options_.startup_index_max_bytes != 0)
    {
        index_size = std::filesystem::file_size(index_file_, ec);
        if (ec || index_size > options_.startup_index_max_bytes ||
            index_size > static_cast<std::uintmax_t>((std::numeric_limits<std::streamsize>::max)()))
        {
            return false;
        }
    }

    std::ifstream input(index_file_, std::ios::binary);
    if (!input.good())
    {
        return false;
    }

    std::vector<std::byte> file_bytes;
    if (options_.startup_index_max_bytes != 0)
    {
        if (index_size > file_bytes.max_size())
        {
            return false;
        }
        file_bytes.resize(static_cast<std::size_t>(index_size));
        input.read(reinterpret_cast<char*>(file_bytes.data()), static_cast<std::streamsize>(index_size));
        if (!input.good() || input.gcount() != static_cast<std::streamsize>(index_size) ||
            input.peek() != std::char_traits<char>::eof() || input.bad())
        {
            return false;
        }
    }
    else
    {
        const std::vector<char> raw_bytes(
            (std::istreambuf_iterator<char>(input)),
            std::istreambuf_iterator<char>());
        file_bytes.reserve(raw_bytes.size());
        for (const auto byte : raw_bytes)
        {
            file_bytes.push_back(static_cast<std::byte>(static_cast<unsigned char>(byte)));
        }
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

    std::uint64_t startup_payload_bytes_read = 0;
    for (const auto& range : loaded)
    {
        if (RangeEnd(range.spool_offset, range.bytes) > next_spool_offset_ ||
            !ChargeStartupPayloadBytes(
                range.bytes, options_.startup_payload_read_max_bytes, startup_payload_bytes_read) ||
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
    std::uint64_t startup_payload_bytes_read = 0;
    for (const auto& range : loaded)
    {
        if (RangeEnd(range.spool_offset, range.bytes) > next_spool_offset_ ||
            !ChargeStartupPayloadBytes(
                range.bytes, options_.startup_payload_read_max_bytes, startup_payload_bytes_read) ||
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
