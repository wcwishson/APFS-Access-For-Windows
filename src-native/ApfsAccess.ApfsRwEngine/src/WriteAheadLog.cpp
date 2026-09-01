#include "WriteAheadLog.h"

#include <algorithm>
#include <atomic>
#include <cstring>
#include <fstream>
#include <iterator>
#include <limits>
#include <mutex>
#include <span>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <windows.h>
#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")

namespace apfsaccess::rw
{
namespace
{
constexpr std::uint32_t kMagic = 0x574C4141; // AALW, little-endian on disk.
constexpr std::uint16_t kLegacyVersion = 1;
constexpr std::uint16_t kInlinePayloadVersion = 2;
constexpr std::uint16_t kLegacyHeaderSize = 148;
constexpr std::uint16_t kInlinePayloadHeaderSize = 152;
constexpr std::size_t kChecksumOffset = 12;
constexpr std::size_t kMaxRecordBytes = 64u * 1024u * 1024u;
constexpr std::string_view kCompactionIntentTag = "apfsaccess-wal-compaction-intent-v1";
constexpr std::uint64_t kCompactionIntentNamespaceDurableFlag = 0x1;

std::uint64_t NextWriterLeaseGeneration()
{
    static std::atomic<std::uint64_t> next_generation{1};
    auto generation = next_generation.fetch_add(1, std::memory_order_relaxed);
    if (generation == 0)
    {
        generation = next_generation.fetch_add(1, std::memory_order_relaxed);
    }
    return generation;
}

void AppendU16(std::vector<std::uint8_t>& buffer, std::uint16_t value)
{
    buffer.push_back(static_cast<std::uint8_t>(value & 0xffu));
    buffer.push_back(static_cast<std::uint8_t>((value >> 8u) & 0xffu));
}

void AppendU32(std::vector<std::uint8_t>& buffer, std::uint32_t value)
{
    for (int shift = 0; shift < 32; shift += 8)
    {
        buffer.push_back(static_cast<std::uint8_t>((value >> shift) & 0xffu));
    }
}

void AppendU64(std::vector<std::uint8_t>& buffer, std::uint64_t value)
{
    for (int shift = 0; shift < 64; shift += 8)
    {
        buffer.push_back(static_cast<std::uint8_t>((value >> shift) & 0xffu));
    }
}

std::uint16_t ReadU16(const std::vector<std::uint8_t>& buffer, std::size_t offset)
{
    return static_cast<std::uint16_t>(
        buffer[offset] |
        (static_cast<std::uint16_t>(buffer[offset + 1]) << 8u));
}

std::uint32_t ReadU32(const std::vector<std::uint8_t>& buffer, std::size_t offset)
{
    std::uint32_t value = 0;
    for (int shift = 0; shift < 32; shift += 8)
    {
        value |= static_cast<std::uint32_t>(buffer[offset++]) << shift;
    }
    return value;
}

std::uint64_t ReadU64(const std::vector<std::uint8_t>& buffer, std::size_t offset)
{
    std::uint64_t value = 0;
    for (int shift = 0; shift < 64; shift += 8)
    {
        value |= static_cast<std::uint64_t>(buffer[offset++]) << shift;
    }
    return value;
}

std::uint32_t ChecksumRecord(std::vector<std::uint8_t> buffer)
{
    if (buffer.size() >= kChecksumOffset + sizeof(std::uint32_t))
    {
        std::fill(
            buffer.begin() + kChecksumOffset,
            buffer.begin() + kChecksumOffset + sizeof(std::uint32_t),
            std::uint8_t{0});
    }

    std::uint32_t hash = 2166136261u;
    for (const auto byte : buffer)
    {
        hash ^= byte;
        hash *= 16777619u;
    }
    return hash;
}

bool ComputeSha256(
    std::span<const std::byte> payload,
    std::array<std::uint8_t, WriteAheadLog::PayloadHashSize>& digest)
{
    digest.fill(0);
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0)
    {
        return false;
    }

    const auto status = BCryptHash(
        algorithm,
        nullptr,
        0,
        reinterpret_cast<PUCHAR>(const_cast<std::byte*>(payload.data())),
        static_cast<ULONG>(payload.size()),
        digest.data(),
        static_cast<ULONG>(digest.size()));
    BCryptCloseAlgorithmProvider(algorithm, 0);
    if (status < 0)
    {
        digest.fill(0);
        return false;
    }
    return true;
}

bool InlinePayloadIsConsistentImpl(const WriteAheadLog::Record& record)
{
    if (record.inline_payload.empty())
    {
        return true;
    }
    if (record.inline_payload.size() > WriteAheadLog::MaxInlinePayloadBytes ||
        record.operation != WriteAheadLog::OperationKind::Write ||
        record.payload_length != record.inline_payload.size() ||
        record.logical_length != record.inline_payload.size())
    {
        return false;
    }

    std::array<std::uint8_t, WriteAheadLog::PayloadHashSize> digest{};
    return ComputeSha256(record.inline_payload, digest) && digest == record.payload_sha256;
}

using WalRegistry = std::unordered_map<std::wstring, std::unordered_set<WriteAheadLog*>>;

WalRegistry& GetWalRegistry()
{
    static WalRegistry registry;
    return registry;
}

std::mutex& GetWalRegistryMutex()
{
    static std::mutex mutex;
    return mutex;
}

std::wstring WalRegistryKey(const std::filesystem::path& path)
{
    if (path.empty())
    {
        return {};
    }

    std::error_code ec;
    auto normalized = std::filesystem::absolute(path, ec);
    if (ec)
    {
        normalized = path;
    }
    auto key = normalized.lexically_normal().wstring();
    if (!key.empty() && key.size() <= (std::numeric_limits<DWORD>::max)())
    {
        CharLowerBuffW(key.data(), static_cast<DWORD>(key.size()));
    }
    return key;
}

std::recursive_mutex& WalOperationMutex(const std::filesystem::path& path)
{
    constexpr std::size_t stripe_count = 64;
    static std::array<std::recursive_mutex, stripe_count> mutexes;
    const auto stripe = std::hash<std::wstring>{}(WalRegistryKey(path)) % stripe_count;
    return mutexes[stripe];
}

std::wstring WriterLeaseName(std::string_view volume_identity)
{
    if (volume_identity.empty())
    {
        return {};
    }

    std::array<std::uint8_t, WriteAheadLog::PayloadHashSize> digest{};
    const auto identity_bytes = std::as_bytes(std::span(volume_identity.data(), volume_identity.size()));
    if (!ComputeSha256(identity_bytes, digest))
    {
        return {};
    }

    constexpr wchar_t hex[] = L"0123456789abcdef";
    std::wstring name = LR"(\\.\pipe\ApfsAccess.WalWriter.)";
    name.reserve(name.size() + digest.size() * 2);
    for (const auto byte : digest)
    {
        name.push_back(hex[(byte >> 4u) & 0x0fu]);
        name.push_back(hex[byte & 0x0fu]);
    }
    return name;
}

bool TryGetPhysicalLinkCount(HANDLE handle, DWORD& link_count)
{
    BY_HANDLE_FILE_INFORMATION info{};
    if (handle == nullptr ||
        handle == INVALID_HANDLE_VALUE ||
        GetFileInformationByHandle(handle, &info) == FALSE)
    {
        return false;
    }
    link_count = info.nNumberOfLinks;
    return true;
}

bool TryGetPhysicalFileSize(HANDLE handle, std::uint64_t& size)
{
    FILE_STANDARD_INFO info{};
    if (handle == nullptr ||
        handle == INVALID_HANDLE_VALUE ||
        GetFileInformationByHandleEx(
            handle,
            FileStandardInfo,
            &info,
            sizeof(info)) == FALSE ||
        info.EndOfFile.QuadPart < 0)
    {
        return false;
    }
    size = static_cast<std::uint64_t>(info.EndOfFile.QuadPart);
    return true;
}

bool HasSinglePhysicalLink(HANDLE handle)
{
    DWORD link_count = 0;
    return TryGetPhysicalLinkCount(handle, link_count) && link_count == 1;
}

struct PhysicalFileIdentity
{
    DWORD volume_serial = 0;
    std::uint64_t file_id = 0;
};

bool TryGetPhysicalFileIdentity(HANDLE handle, PhysicalFileIdentity& identity)
{
    BY_HANDLE_FILE_INFORMATION info{};
    if (handle == nullptr ||
        handle == INVALID_HANDLE_VALUE ||
        GetFileInformationByHandle(handle, &info) == FALSE)
    {
        return false;
    }
    identity.volume_serial = info.dwVolumeSerialNumber;
    identity.file_id =
        (static_cast<std::uint64_t>(info.nFileIndexHigh) << 32u) |
        static_cast<std::uint64_t>(info.nFileIndexLow);
    return true;
}

bool IsRegularWalPathHandle(HANDLE handle)
{
    FILE_ATTRIBUTE_TAG_INFO attributes{};
    return GetFileInformationByHandleEx(
               handle,
               FileAttributeTagInfo,
               &attributes,
               sizeof(attributes)) != FALSE &&
           (attributes.FileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)) == 0;
}

bool IsSafeWalPathHandle(HANDLE handle)
{
    return IsRegularWalPathHandle(handle) && HasSinglePhysicalLink(handle);
}

bool LockWholeFileExclusive(HANDLE handle)
{
    if (handle == nullptr || handle == INVALID_HANDLE_VALUE)
    {
        return false;
    }

    OVERLAPPED range{};
    return LockFileEx(
               handle,
               LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
               0,
               MAXDWORD,
               MAXDWORD,
               &range) != FALSE;
}

std::filesystem::path CompactionPredecessorGuardPath(
    const std::filesystem::path& wal_path,
    std::uint64_t file_id)
{
    auto path = wal_path;
    path += L".compact.predecessor.";
    path += std::to_wstring(file_id);
    return path;
}

std::filesystem::path CompactionIntentPath(const std::filesystem::path& wal_path)
{
    auto path = wal_path;
    path += L".compact.intent";
    return path;
}

std::filesystem::path UniqueSiblingPath(
    const std::filesystem::path& path,
    std::wstring_view suffix)
{
    static std::atomic<std::uint64_t> next_suffix{1};
    auto unique = path;
    unique += suffix;
    unique += L".";
    unique += std::to_wstring(GetCurrentProcessId());
    unique += L".";
    unique += std::to_wstring(next_suffix.fetch_add(1, std::memory_order_relaxed));
    return unique;
}

bool ParseCanonicalPositiveDecimal(
    std::wstring_view value,
    std::uint64_t maximum,
    std::uint64_t& parsed)
{
    if (value.empty() || value.front() == L'0')
    {
        return false;
    }
    parsed = 0;
    for (const auto character : value)
    {
        if (character < L'0' || character > L'9')
        {
            return false;
        }
        const auto digit = static_cast<std::uint64_t>(character - L'0');
        if (parsed > (maximum - digit) / 10u)
        {
            return false;
        }
        parsed = parsed * 10u + digit;
    }
    return parsed != 0;
}

bool HasExactNumericPairSuffix(
    std::wstring_view filename,
    std::wstring_view prefix)
{
    if (!filename.starts_with(prefix))
    {
        return false;
    }
    const auto suffix = filename.substr(prefix.size());
    const auto separator = suffix.find(L'.');
    std::uint64_t process_id = 0;
    std::uint64_t counter = 0;
    return separator != std::wstring_view::npos &&
           suffix.find(L'.', separator + 1) == std::wstring_view::npos &&
           ParseCanonicalPositiveDecimal(
               suffix.substr(0, separator),
               (std::numeric_limits<std::uint32_t>::max)(),
               process_id) &&
           ParseCanonicalPositiveDecimal(
               suffix.substr(separator + 1),
               (std::numeric_limits<std::uint64_t>::max)(),
               counter);
}

bool MarkOpenedFileForPosixDeletion(HANDLE handle)
{
    if (handle == nullptr || handle == INVALID_HANDLE_VALUE)
    {
        return false;
    }

    FILE_DISPOSITION_INFO_EX disposition{};
    disposition.Flags =
        FILE_DISPOSITION_FLAG_DELETE |
        FILE_DISPOSITION_FLAG_POSIX_SEMANTICS;
    return SetFileInformationByHandle(
               handle,
               FileDispositionInfoEx,
               &disposition,
               sizeof(disposition)) != FALSE;
}

bool SetOpenedFileDeletePending(HANDLE handle, bool delete_pending)
{
    if (handle == nullptr || handle == INVALID_HANDLE_VALUE)
    {
        return false;
    }

    FILE_DISPOSITION_INFO disposition{};
    disposition.DeleteFile = delete_pending ? TRUE : FALSE;
    return SetFileInformationByHandle(
               handle,
               FileDispositionInfo,
               &disposition,
               sizeof(disposition)) != FALSE;
}

bool DeleteOpenedFile(HANDLE& handle)
{
    if (!MarkOpenedFileForPosixDeletion(handle))
    {
        return false;
    }

    DWORD remaining_links = 0;
    const bool no_remaining_links =
        TryGetPhysicalLinkCount(handle, remaining_links) && remaining_links == 0;
    auto* closing = handle;
    handle = INVALID_HANDLE_VALUE;
    const bool closed = CloseHandle(closing) != FALSE;
    return no_remaining_links && closed;
}

bool FlushContainingDirectory(const std::filesystem::path& path)
{
    std::error_code ec;
    const auto absolute_path = std::filesystem::absolute(path, ec).lexically_normal();
    if (ec || absolute_path.parent_path().empty())
    {
        return false;
    }

    const auto parent_wide = absolute_path.parent_path().wstring();
    auto* directory = CreateFileW(
        parent_wide.c_str(),
        GENERIC_WRITE | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
        nullptr);
    if (directory == INVALID_HANDLE_VALUE)
    {
        return false;
    }

    FILE_ATTRIBUTE_TAG_INFO attributes{};
    const bool flushed =
        GetFileInformationByHandleEx(
            directory,
            FileAttributeTagInfo,
            &attributes,
            sizeof(attributes)) != FALSE &&
        (attributes.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0 &&
        FlushFileBuffers(directory) != FALSE;
    const bool closed = CloseHandle(directory) != FALSE;
    return flushed && closed;
}

bool DeleteOpenedFileDurably(HANDLE& handle, const std::filesystem::path& path)
{
    return DeleteOpenedFile(handle) && FlushContainingDirectory(path);
}

bool PathIsAbsent(const std::filesystem::path& path)
{
    const auto attributes = GetFileAttributesW(path.wstring().c_str());
    if (attributes != INVALID_FILE_ATTRIBUTES)
    {
        return false;
    }
    const auto error = GetLastError();
    return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND;
}

bool PathMatchesPhysicalFile(
    const std::filesystem::path& path,
    const PhysicalFileIdentity& expected,
    bool require_single_link)
{
    const auto wide_path = path.wstring();
    auto* handle = CreateFileW(
        wide_path.c_str(),
        FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
        nullptr);
    PhysicalFileIdentity observed{};
    const bool matches =
        handle != INVALID_HANDLE_VALUE &&
        IsRegularWalPathHandle(handle) &&
        (!require_single_link || HasSinglePhysicalLink(handle)) &&
        TryGetPhysicalFileIdentity(handle, observed) &&
        observed.volume_serial == expected.volume_serial &&
        observed.file_id == expected.file_id;
    if (handle != INVALID_HANDLE_VALUE)
    {
        CloseHandle(handle);
    }
    return matches;
}

bool RenameOpenedFileWithoutReplacing(
    HANDLE source_handle,
    const std::filesystem::path& destination)
{
    if (source_handle == nullptr || source_handle == INVALID_HANDLE_VALUE)
    {
        return false;
    }

    std::error_code ec;
    auto absolute_destination = std::filesystem::absolute(destination, ec).lexically_normal();
    if (ec)
    {
        return false;
    }
    auto destination_wide = absolute_destination.wstring();
    if (!destination_wide.starts_with(LR"(\??\)"))
    {
        destination_wide.insert(0, LR"(\??\)");
    }
    const auto destination_bytes = destination_wide.size() * sizeof(wchar_t);
    if (destination_bytes > (std::numeric_limits<DWORD>::max)())
    {
        return false;
    }

    const auto buffer_size = sizeof(FILE_RENAME_INFO) + destination_bytes;
    std::vector<std::uint8_t> buffer(buffer_size, 0);
    auto* rename_info = reinterpret_cast<FILE_RENAME_INFO*>(buffer.data());
    rename_info->Flags = FILE_RENAME_FLAG_POSIX_SEMANTICS;
    rename_info->RootDirectory = nullptr;
    rename_info->FileNameLength = static_cast<DWORD>(destination_bytes);
    std::memcpy(rename_info->FileName, destination_wide.data(), destination_bytes);
    const bool renamed = SetFileInformationByHandle(
                             source_handle,
                             FileRenameInfoEx,
                             rename_info,
                             static_cast<DWORD>(buffer.size())) != FALSE;
    return renamed;
}

bool WriteFileBytesDurably(
    const std::filesystem::path& path,
    const std::vector<std::uint8_t>& bytes,
    HANDLE& handle,
    PhysicalFileIdentity& identity)
{
    handle = INVALID_HANDLE_VALUE;
    identity = {};
    if (bytes.empty() || bytes.size() > (std::numeric_limits<DWORD>::max)())
    {
        return false;
    }

    const auto wide_path = path.wstring();
    handle = CreateFileW(
        wide_path.c_str(),
        GENERIC_WRITE | DELETE | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        CREATE_NEW,
        FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_WRITE_THROUGH,
        nullptr);
    if (handle == INVALID_HANDLE_VALUE)
    {
        return false;
    }

    DWORD written = 0;
    const bool ok = WriteFile(
                        handle,
                        bytes.data(),
                        static_cast<DWORD>(bytes.size()),
                        &written,
                        nullptr) != FALSE &&
                    written == bytes.size() &&
                    FlushFileBuffers(handle) != FALSE &&
                    TryGetPhysicalFileIdentity(handle, identity) &&
                    IsSafeWalPathHandle(handle);
    if (!ok)
    {
        if (!DeleteOpenedFileDurably(handle, path) && handle != INVALID_HANDLE_VALUE)
        {
            CloseHandle(handle);
            handle = INVALID_HANDLE_VALUE;
        }
        return false;
    }
    return true;
}

bool WriteWalRecordsDurably(
    const std::filesystem::path& path,
    const std::vector<WriteAheadLog::Record>& records,
    HANDLE& handle,
    PhysicalFileIdentity& identity)
{
    handle = INVALID_HANDLE_VALUE;
    identity = {};
    const auto wide_path = path.wstring();
    handle = CreateFileW(
        wide_path.c_str(),
        GENERIC_WRITE | DELETE | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        CREATE_NEW,
        FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_WRITE_THROUGH | FILE_FLAG_SEQUENTIAL_SCAN,
        nullptr);
    if (handle == INVALID_HANDLE_VALUE)
    {
        return false;
    }

    bool ok = true;
    for (const auto& record : records)
    {
        const auto encoded = WriteAheadLog::EncodeForTest(record);
        if (encoded.empty())
        {
            ok = false;
            break;
        }

        const auto* cursor = encoded.data();
        auto remaining = encoded.size();
        while (remaining != 0)
        {
            const auto chunk_size = static_cast<DWORD>((std::min)(
                remaining,
                static_cast<std::size_t>((std::numeric_limits<DWORD>::max)())));
            DWORD written = 0;
            if (WriteFile(handle, cursor, chunk_size, &written, nullptr) == FALSE ||
                written == 0)
            {
                ok = false;
                break;
            }
            cursor += written;
            remaining -= written;
        }
        if (!ok)
        {
            break;
        }
    }

    ok = ok &&
         TryGetPhysicalFileIdentity(handle, identity) &&
         IsSafeWalPathHandle(handle) &&
         FlushFileBuffers(handle) != FALSE;
    if (!ok)
    {
        if (!DeleteOpenedFileDurably(handle, path) && handle != INVALID_HANDLE_VALUE)
        {
            CloseHandle(handle);
            handle = INVALID_HANDLE_VALUE;
        }
        return false;
    }
    return true;
}

bool TruncateFileHandleDurably(HANDLE handle, std::uint64_t complete_prefix_bytes)
{
    if (handle == nullptr ||
        handle == INVALID_HANDLE_VALUE ||
        complete_prefix_bytes >
            static_cast<std::uint64_t>((std::numeric_limits<LONGLONG>::max)()))
    {
        return false;
    }

    LARGE_INTEGER end{};
    end.QuadPart = static_cast<LONGLONG>(complete_prefix_bytes);
    return SetFilePointerEx(handle, end, nullptr, FILE_BEGIN) != FALSE &&
           SetEndOfFile(handle) != FALSE &&
           FlushFileBuffers(handle) != FALSE;
}

bool IsStrictCompactionIntentRecord(
    const WriteAheadLog::Record& record,
    std::string_view expected_volume_identity)
{
    return record.volume_identity == expected_volume_identity &&
           record.transaction_id == 0 &&
           record.sequence == 0 &&
           record.operation == WriteAheadLog::OperationKind::CompactionIndex &&
           (record.state == WriteAheadLog::RecordState::Prepared ||
            record.state == WriteAheadLog::RecordState::PublishArmed ||
            record.state == WriteAheadLog::RecordState::Checkpointed ||
            record.state == WriteAheadLog::RecordState::CleanupArmed ||
            record.state == WriteAheadLog::RecordState::Cleaned) &&
           record.parent_object_id <= (std::numeric_limits<DWORD>::max)() &&
           record.payload_spool_id == 0 &&
           record.payload_offset == 0 &&
           record.payload_length == 0 &&
           (record.state == WriteAheadLog::RecordState::Prepared || record.logical_offset != 0) &&
           record.logical_length == 0 &&
            (record.flags == 0 ||
             (record.state == WriteAheadLog::RecordState::Cleaned &&
              record.flags == kCompactionIntentNamespaceDurableFlag)) &&
           std::all_of(
               record.payload_sha256.begin(),
               record.payload_sha256.end(),
               [](std::uint8_t byte) { return byte == 0; }) &&
           record.inline_payload.empty() &&
           record.path_utf8 == kCompactionIntentTag &&
           record.secondary_path_utf8.empty();
}

bool IsValidCompactionIntentTransition(
    const WriteAheadLog::Record& previous,
    const WriteAheadLog::Record& next)
{
    if (previous.volume_identity != next.volume_identity ||
        previous.object_id != next.object_id ||
        previous.parent_object_id != next.parent_object_id ||
        previous.logical_offset != next.logical_offset)
    {
        return false;
    }

    using State = WriteAheadLog::RecordState;
    if (previous.state == State::Prepared)
    {
        return next.state == State::PublishArmed ||
               next.state == State::Checkpointed;
    }
    if (previous.state == State::PublishArmed)
    {
        return next.state == State::Checkpointed;
    }
    if (previous.state == State::Checkpointed)
    {
        return next.state == State::CleanupArmed && next.flags == 0;
    }
    if (previous.state == State::CleanupArmed)
    {
        return next.state == State::Cleaned && next.flags == 0;
    }
    return previous.state == State::Cleaned &&
           previous.flags == 0 &&
           next.state == State::Cleaned &&
           next.flags == kCompactionIntentNamespaceDurableFlag;
}

bool IsStrictCompactionIntentHistory(
    const std::vector<WriteAheadLog::Record>& records,
    std::string_view expected_volume_identity)
{
    if (records.empty())
    {
        return false;
    }
    for (std::size_t index = 0; index < records.size(); ++index)
    {
        if (!IsStrictCompactionIntentRecord(records[index], expected_volume_identity) ||
            (index != 0 &&
             !IsValidCompactionIntentTransition(records[index - 1], records[index])))
        {
            return false;
        }
    }
    return true;
}

void StoreU32(std::vector<std::uint8_t>& buffer, std::size_t offset, std::uint32_t value)
{
    for (int shift = 0; shift < 32; shift += 8)
    {
        buffer[offset++] = static_cast<std::uint8_t>((value >> shift) & 0xffu);
    }
}

bool FlushPathToDisk(const std::filesystem::path& path)
{
    const auto wide_path = path.wstring();
    HANDLE handle = CreateFileW(
        wide_path.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    if (handle == INVALID_HANDLE_VALUE)
    {
        return false;
    }

    const bool ok = FlushFileBuffers(handle) != FALSE;
    CloseHandle(handle);
    return ok;
}

bool ReadFileBytes(const std::filesystem::path& path, std::vector<std::uint8_t>& bytes)
{
    std::ifstream input(path, std::ios::binary);
    if (!input.good())
    {
        return false;
    }

    bytes.assign(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
    return input.good() || input.eof();
}

bool ReadPinnedIntentBytes(HANDLE handle, std::vector<std::uint8_t>& bytes)
{
    LARGE_INTEGER size{};
    LARGE_INTEGER original_position{};
    LARGE_INTEGER zero{};
    if (handle == nullptr ||
        handle == INVALID_HANDLE_VALUE ||
        GetFileSizeEx(handle, &size) == FALSE ||
        size.QuadPart < 0 ||
        static_cast<std::uint64_t>(size.QuadPart) > kMaxRecordBytes ||
        SetFilePointerEx(handle, zero, &original_position, FILE_CURRENT) == FALSE ||
        SetFilePointerEx(handle, zero, nullptr, FILE_BEGIN) == FALSE)
    {
        return false;
    }

    bytes.resize(static_cast<std::size_t>(size.QuadPart));
    auto* cursor = bytes.data();
    auto remaining = bytes.size();
    bool read_all = true;
    while (remaining != 0)
    {
        const auto chunk_size = static_cast<DWORD>((std::min)(
            remaining,
            static_cast<std::size_t>((std::numeric_limits<DWORD>::max)())));
        DWORD bytes_read = 0;
        if (ReadFile(handle, cursor, chunk_size, &bytes_read, nullptr) == FALSE ||
            bytes_read == 0)
        {
            read_all = false;
            break;
        }
        cursor += bytes_read;
        remaining -= bytes_read;
    }
    const bool position_restored =
        SetFilePointerEx(handle, original_position, nullptr, FILE_BEGIN) != FALSE;
    return read_all && position_restored;
}

bool TruncateTornTail(const std::filesystem::path& path, std::size_t complete_prefix_bytes)
{
    std::error_code ec;
    std::filesystem::resize_file(path, complete_prefix_bytes, ec);
    return !ec && FlushPathToDisk(path);
}

bool DecodeRecord(
    const std::vector<std::uint8_t>& bytes,
    std::size_t offset,
    std::size_t record_size,
    std::uint16_t version,
    const std::string& expected_volume_identity,
    WriteAheadLog::Record& record,
    WriteAheadLog::ReadStatus& status)
{
    std::vector<std::uint8_t> record_bytes(
        bytes.begin() + static_cast<std::ptrdiff_t>(offset),
        bytes.begin() + static_cast<std::ptrdiff_t>(offset + record_size));

    const auto expected_checksum = ReadU32(record_bytes, kChecksumOffset);
    if (ChecksumRecord(record_bytes) != expected_checksum)
    {
        status = WriteAheadLog::ReadStatus::ChecksumMismatch;
        return false;
    }

    std::size_t cursor = 16;
    record.transaction_id = ReadU64(record_bytes, cursor);
    cursor += sizeof(std::uint64_t);
    record.sequence = ReadU64(record_bytes, cursor);
    cursor += sizeof(std::uint64_t);
    record.operation = static_cast<WriteAheadLog::OperationKind>(ReadU32(record_bytes, cursor));
    cursor += sizeof(std::uint32_t);
    record.state = static_cast<WriteAheadLog::RecordState>(ReadU32(record_bytes, cursor));
    cursor += sizeof(std::uint32_t);
    record.object_id = ReadU64(record_bytes, cursor);
    cursor += sizeof(std::uint64_t);
    record.parent_object_id = ReadU64(record_bytes, cursor);
    cursor += sizeof(std::uint64_t);
    record.payload_spool_id = ReadU64(record_bytes, cursor);
    cursor += sizeof(std::uint64_t);
    record.payload_offset = ReadU64(record_bytes, cursor);
    cursor += sizeof(std::uint64_t);
    record.payload_length = ReadU64(record_bytes, cursor);
    cursor += sizeof(std::uint64_t);
    record.logical_offset = ReadU64(record_bytes, cursor);
    cursor += sizeof(std::uint64_t);
    record.logical_length = ReadU64(record_bytes, cursor);
    cursor += sizeof(std::uint64_t);
    record.flags = ReadU64(record_bytes, cursor);
    cursor += sizeof(std::uint64_t);
    const auto path_length = ReadU32(record_bytes, cursor);
    cursor += sizeof(std::uint32_t);
    const auto secondary_path_length = ReadU32(record_bytes, cursor);
    cursor += sizeof(std::uint32_t);
    const auto volume_identity_length = ReadU32(record_bytes, cursor);
    cursor += sizeof(std::uint32_t);
    std::uint32_t inline_payload_length = 0;
    if (version == kInlinePayloadVersion)
    {
        inline_payload_length = ReadU32(record_bytes, cursor);
        cursor += sizeof(std::uint32_t);
        if (inline_payload_length > WriteAheadLog::MaxInlinePayloadBytes)
        {
            status = WriteAheadLog::ReadStatus::Corrupt;
            return false;
        }
    }

    if (cursor + WriteAheadLog::PayloadHashSize > record_bytes.size())
    {
        status = WriteAheadLog::ReadStatus::Corrupt;
        return false;
    }
    std::copy_n(record_bytes.begin() + static_cast<std::ptrdiff_t>(cursor), WriteAheadLog::PayloadHashSize, record.payload_sha256.begin());
    cursor += WriteAheadLog::PayloadHashSize;

    const auto variable_bytes =
        static_cast<std::uint64_t>(path_length) +
        static_cast<std::uint64_t>(secondary_path_length) +
        static_cast<std::uint64_t>(volume_identity_length) +
        static_cast<std::uint64_t>(inline_payload_length);
    if (variable_bytes > record_bytes.size() ||
        cursor + static_cast<std::size_t>(variable_bytes) != record_bytes.size())
    {
        status = WriteAheadLog::ReadStatus::Corrupt;
        return false;
    }

    record.path_utf8.assign(
        reinterpret_cast<const char*>(record_bytes.data() + cursor),
        path_length);
    cursor += path_length;
    record.secondary_path_utf8.assign(
        reinterpret_cast<const char*>(record_bytes.data() + cursor),
        secondary_path_length);
    cursor += secondary_path_length;
    record.volume_identity.assign(
        reinterpret_cast<const char*>(record_bytes.data() + cursor),
        volume_identity_length);
    cursor += volume_identity_length;
    record.inline_payload.assign(
        reinterpret_cast<const std::byte*>(record_bytes.data() + cursor),
        reinterpret_cast<const std::byte*>(record_bytes.data() + cursor + inline_payload_length));

    if (!InlinePayloadIsConsistentImpl(record))
    {
        status = WriteAheadLog::ReadStatus::Corrupt;
        return false;
    }

    if (!expected_volume_identity.empty() && record.volume_identity != expected_volume_identity)
    {
        status = WriteAheadLog::ReadStatus::VolumeMismatch;
        return false;
    }

    status = WriteAheadLog::ReadStatus::Ok;
    return true;
}

WriteAheadLog::ReadResult DecodeWalBytes(
    const std::vector<std::uint8_t>& bytes,
    const std::string& expected_volume_identity,
    std::uint64_t* complete_prefix_bytes)
{
    WriteAheadLog::ReadResult result{};
    if (complete_prefix_bytes != nullptr)
    {
        *complete_prefix_bytes = 0;
    }

    std::size_t cursor = 0;
    while (cursor < bytes.size())
    {
        if (bytes.size() - cursor < kLegacyHeaderSize)
        {
            result.recovered_torn_tail = true;
            if (complete_prefix_bytes != nullptr)
            {
                *complete_prefix_bytes = static_cast<std::uint64_t>(cursor);
            }
            return result;
        }

        const auto magic = ReadU32(bytes, cursor);
        const auto version = ReadU16(bytes, cursor + 4);
        const auto header_size = ReadU16(bytes, cursor + 6);
        const auto record_size = ReadU32(bytes, cursor + 8);
        if (magic != kMagic)
        {
            result.status = WriteAheadLog::ReadStatus::Corrupt;
            return result;
        }
        if (version != kLegacyVersion && version != kInlinePayloadVersion)
        {
            result.status = WriteAheadLog::ReadStatus::VersionMismatch;
            return result;
        }
        const auto expected_header_size = version == kInlinePayloadVersion
            ? kInlinePayloadHeaderSize
            : kLegacyHeaderSize;
        if (header_size != expected_header_size ||
            record_size < expected_header_size ||
            record_size > kMaxRecordBytes)
        {
            result.status = WriteAheadLog::ReadStatus::Corrupt;
            return result;
        }
        if (bytes.size() - cursor < record_size)
        {
            result.recovered_torn_tail = true;
            if (complete_prefix_bytes != nullptr)
            {
                *complete_prefix_bytes = static_cast<std::uint64_t>(cursor);
            }
            return result;
        }

        WriteAheadLog::Record record{};
        WriteAheadLog::ReadStatus record_status = WriteAheadLog::ReadStatus::Ok;
        if (!DecodeRecord(
                bytes,
                cursor,
                record_size,
                version,
                expected_volume_identity,
                record,
                record_status))
        {
            result.status = record_status;
            return result;
        }
        result.records.push_back(std::move(record));
        cursor += record_size;
    }

    if (complete_prefix_bytes != nullptr)
    {
        *complete_prefix_bytes = static_cast<std::uint64_t>(cursor);
    }
    return result;
}
} // namespace

WriteAheadLog::WriteAheadLog(Options options)
    : options_(std::move(options))
{
    RegisterPath();
}

WriteAheadLog::~WriteAheadLog()
{
    UnregisterPath();
    (void)CloseAppendHandle();
}

void WriteAheadLog::Reconfigure(Options options)
{
    auto reconfigure = [&]()
    {
        UnregisterPath();
        (void)CloseAppendHandle();
        options_ = std::move(options);
        RegisterPath();
    };
    auto& current_mutex = WalOperationMutex(options_.path);
    auto& next_mutex = WalOperationMutex(options.path);
    if (&current_mutex == &next_mutex)
    {
        std::lock_guard<std::recursive_mutex> operation_lock(current_mutex);
        reconfigure();
    }
    else
    {
        std::scoped_lock operation_lock(current_mutex, next_mutex);
        reconfigure();
    }
}

void WriteAheadLog::RegisterPath()
{
    registered_path_ = WalRegistryKey(options_.path);
    if (registered_path_.empty())
    {
        return;
    }

    std::lock_guard<std::mutex> lock(GetWalRegistryMutex());
    GetWalRegistry()[registered_path_].insert(this);
}

void WriteAheadLog::UnregisterPath() noexcept
{
    if (registered_path_.empty())
    {
        return;
    }

    std::lock_guard<std::mutex> lock(GetWalRegistryMutex());
    const auto found = GetWalRegistry().find(registered_path_);
    if (found != GetWalRegistry().end())
    {
        found->second.erase(this);
        if (found->second.empty())
        {
            GetWalRegistry().erase(found);
        }
    }
    registered_path_.clear();
}

bool WriteAheadLog::TryTransferRegisteredHandlesForPath(
    const std::filesystem::path& path,
    const WriteAheadLog* successor)
{
    const auto key = WalRegistryKey(path);
    if (key.empty() || successor == nullptr ||
        successor->append_handle_ != nullptr || successor->writer_lease_handle_ != nullptr)
    {
        return false;
    }

    std::lock_guard<std::mutex> lock(GetWalRegistryMutex());
    const auto found = GetWalRegistry().find(key);
    if (found == GetWalRegistry().end())
    {
        return false;
    }
    for (auto* owner : found->second)
    {
        if (owner == nullptr || owner == successor ||
            owner->append_handle_ == nullptr || owner->writer_lease_handle_ == nullptr ||
            owner->options_.volume_identity != successor->options_.volume_identity)
        {
            continue;
        }

        PhysicalFileIdentity identity{};
        if (!IsSafeWalPathHandle(static_cast<HANDLE>(owner->append_handle_)) ||
            !TryGetPhysicalFileIdentity(static_cast<HANDLE>(owner->append_handle_), identity) ||
            !PathMatchesPhysicalFile(path, identity, true))
        {
            continue;
        }

        successor->append_handle_ = owner->append_handle_;
        successor->writer_lease_handle_ = owner->writer_lease_handle_;
        successor->writer_lease_name_ = std::move(owner->writer_lease_name_);
        successor->append_handle_size_ = owner->append_handle_size_;
        successor->append_handle_size_known_ = owner->append_handle_size_known_;
        ++successor->append_handle_open_count_;
        successor->writer_lease_generation_ = NextWriterLeaseGeneration();

        owner->append_handle_ = nullptr;
        owner->writer_lease_handle_ = nullptr;
        owner->append_handle_size_ = 0;
        owner->append_handle_size_known_ = false;
        owner->writer_lease_generation_ = 0;
        owner->writer_lease_name_.clear();
        return true;
    }
    return false;
}

bool WriteAheadLog::EnsureAppendHandle(
    bool resolve_compaction_intent,
    bool allow_create) const
{
    if (append_handle_ != nullptr)
    {
        return writer_lease_handle_ != nullptr;
    }
    if (!EnsureWriterLease())
    {
        return false;
    }
    if (!CleanupPreIntentCompactionOrphans())
    {
        (void)CloseWriterLeaseHandle();
        return false;
    }

    const auto wide_path = options_.path.wstring();
    const auto intent_wide = CompactionIntentPath(options_.path).wstring();
    const auto intent_attributes = GetFileAttributesW(intent_wide.c_str());
    const bool pending_compaction_intent = intent_attributes != INVALID_FILE_ATTRIBUTES;
    if (!pending_compaction_intent)
    {
        const auto intent_error = GetLastError();
        if (intent_error != ERROR_FILE_NOT_FOUND && intent_error != ERROR_PATH_NOT_FOUND)
        {
            (void)CloseWriterLeaseHandle();
            return false;
        }
    }
    HANDLE handle = INVALID_HANDLE_VALUE;
    for (int attempt = 0; attempt < 3 && handle == INVALID_HANDLE_VALUE; ++attempt)
    {
        auto* path_guard = CreateFileW(
            wide_path.c_str(),
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            nullptr);
        if (path_guard != INVALID_HANDLE_VALUE)
        {
            PhysicalFileIdentity guarded_identity{};
            if (!(pending_compaction_intent
                      ? IsRegularWalPathHandle(path_guard)
                      : IsSafeWalPathHandle(path_guard)) ||
                !TryGetPhysicalFileIdentity(path_guard, guarded_identity))
            {
                CloseHandle(path_guard);
                (void)CloseWriterLeaseHandle();
                return false;
            }

            const auto existing = ReadAllInternal(
                options_.path,
                options_.volume_identity,
                false,
                nullptr);
            if (existing.status != ReadStatus::Ok)
            {
                CloseHandle(path_guard);
                // Keep the volume writer lease while invalid WAL evidence is quarantined.
                (void)CloseAppendFileHandle();
                return false;
            }

            const auto append_share_mode =
                pending_compaction_intent && resolve_compaction_intent
                    ? FILE_SHARE_READ | FILE_SHARE_DELETE
                    : FILE_SHARE_READ;
            handle = CreateFileW(
                wide_path.c_str(),
                GENERIC_WRITE,
                append_share_mode,
                nullptr,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
                nullptr);
            PhysicalFileIdentity opened_identity{};
            const bool stable_path =
                handle != INVALID_HANDLE_VALUE &&
                TryGetPhysicalFileIdentity(handle, opened_identity) &&
                opened_identity.volume_serial == guarded_identity.volume_serial &&
                opened_identity.file_id == guarded_identity.file_id;
            CloseHandle(path_guard);
            if (!stable_path ||
                !(pending_compaction_intent
                      ? IsRegularWalPathHandle(handle)
                      : HasSinglePhysicalLink(handle)))
            {
                if (handle != INVALID_HANDLE_VALUE)
                {
                    CloseHandle(handle);
                }
                (void)CloseWriterLeaseHandle();
                return false;
            }
            break;
        }

        const auto guard_error = GetLastError();
        if (guard_error != ERROR_FILE_NOT_FOUND && guard_error != ERROR_PATH_NOT_FOUND)
        {
            (void)CloseWriterLeaseHandle();
            return false;
        }
        if (pending_compaction_intent)
        {
            if (attempt == 0 && RestoreMissingCanonicalForPublishArmedIntent())
            {
                continue;
            }
            (void)CloseWriterLeaseHandle();
            return false;
        }
        if (!allow_create)
        {
            (void)CloseWriterLeaseHandle();
            return false;
        }

        handle = CreateFileW(
            wide_path.c_str(),
            GENERIC_WRITE,
            FILE_SHARE_READ,
            nullptr,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
            nullptr);
        if (handle == INVALID_HANDLE_VALUE)
        {
            const auto create_error = GetLastError();
            if (create_error != ERROR_FILE_EXISTS && create_error != ERROR_ALREADY_EXISTS)
            {
                (void)CloseWriterLeaseHandle();
                return false;
            }
        }
    }
    if (handle == INVALID_HANDLE_VALUE)
    {
        (void)CloseWriterLeaseHandle();
        return false;
    }

    LARGE_INTEGER end{};
    if (!SetFilePointerEx(handle, {}, &end, FILE_END))
    {
        CloseHandle(handle);
        (void)CloseWriterLeaseHandle();
        return false;
    }
    if (!(pending_compaction_intent
              ? IsRegularWalPathHandle(handle)
              : HasSinglePhysicalLink(handle)))
    {
        CloseHandle(handle);
        (void)CloseWriterLeaseHandle();
        return false;
    }

    append_handle_ = handle;
    append_handle_size_ = static_cast<std::uint64_t>(end.QuadPart);
    append_handle_size_known_ = true;
    ++append_handle_open_count_;
    if (resolve_compaction_intent && !ResolvePendingCompactionIntent())
    {
        (void)CloseAppendHandle();
        return false;
    }
    if (resolve_compaction_intent && pending_compaction_intent)
    {
        if (!CloseAppendFileHandle())
        {
            (void)CloseWriterLeaseHandle();
            return false;
        }
        const bool reopened = EnsureAppendHandle(false, allow_create);
        if (!reopened ||
            append_handle_ == nullptr ||
            !IsSafeWalPathHandle(static_cast<HANDLE>(append_handle_)))
        {
            (void)CloseAppendHandle();
            return false;
        }
        return true;
    }
    return !resolve_compaction_intent || IsSafeWalPathHandle(handle);
}

bool WriteAheadLog::EnsureWriterLease() const
{
    if (writer_lease_handle_ != nullptr)
    {
        return true;
    }

    writer_lease_name_ = WriterLeaseName(options_.volume_identity);
    if (writer_lease_name_.empty())
    {
        return false;
    }

    auto* handle = CreateNamedPipeW(
        writer_lease_name_.c_str(),
        PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
        1,
        sizeof(std::uint64_t),
        sizeof(std::uint64_t),
        0,
        nullptr);
    if (handle == INVALID_HANDLE_VALUE)
    {
        writer_lease_name_.clear();
        return false;
    }

    writer_lease_handle_ = handle;
    writer_lease_generation_ = NextWriterLeaseGeneration();
    return true;
}

bool WriteAheadLog::CloseAppendFileHandle() const noexcept
{
    if (append_handle_ == nullptr)
    {
        return true;
    }

    auto* handle = static_cast<HANDLE>(append_handle_);
    append_handle_ = nullptr;
    append_handle_size_ = 0;
    append_handle_size_known_ = false;
    return CloseHandle(handle) != FALSE;
}

bool WriteAheadLog::CloseWriterLeaseHandle() const noexcept
{
    if (writer_lease_handle_ == nullptr)
    {
        writer_lease_generation_ = 0;
        return true;
    }

    auto* handle = static_cast<HANDLE>(writer_lease_handle_);
    writer_lease_handle_ = nullptr;
    writer_lease_generation_ = 0;
    const bool closed = CloseHandle(handle) != FALSE;
    writer_lease_name_.clear();
    return closed;
}

bool WriteAheadLog::CloseAppendHandle() const noexcept
{
    const bool append_closed = CloseAppendFileHandle();
    const bool lease_closed = CloseWriterLeaseHandle();
    return append_closed && lease_closed;
}

bool WriteAheadLog::PersistCompactionIntent(
    std::uint32_t volume_serial,
    std::uint64_t file_id,
    RecordState state,
    std::uint64_t replacement_file_id,
    bool* bytes_may_have_persisted,
    bool namespace_durable) const
{
    if (bytes_may_have_persisted != nullptr)
    {
        *bytes_may_have_persisted = false;
    }
    if (namespace_durable && state != RecordState::Cleaned)
    {
        return false;
    }

    Record intent{};
    intent.volume_identity = options_.volume_identity;
    intent.operation = OperationKind::CompactionIndex;
    intent.state = state;
    intent.object_id = file_id;
    intent.parent_object_id = volume_serial;
    intent.logical_offset = replacement_file_id;
    intent.flags = namespace_durable ? kCompactionIntentNamespaceDurableFlag : 0;
    intent.path_utf8 = kCompactionIntentTag;

    const auto encoded = EncodeForTest(intent);
    if (encoded.empty())
    {
        return false;
    }

    const auto intent_path = CompactionIntentPath(options_.path);
    const auto intent_wide = intent_path.wstring();
    auto* existing_handle = CreateFileW(
        intent_wide.c_str(),
        GENERIC_READ | GENERIC_WRITE | DELETE | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH,
        nullptr);
    if (existing_handle != INVALID_HANDLE_VALUE)
    {
        PhysicalFileIdentity existing_identity{};
        Record previous{};
        const bool existing_is_safe =
            LockWholeFileExclusive(existing_handle) &&
            IsSafeWalPathHandle(existing_handle) &&
            TryGetPhysicalFileIdentity(existing_handle, existing_identity) &&
            ReadLatestCompactionIntent(
                existing_handle,
                existing_identity.volume_serial,
                existing_identity.file_id,
                previous) &&
            PathMatchesPhysicalFile(intent_path, existing_identity, true);
        if (!existing_is_safe)
        {
            CloseHandle(existing_handle);
            return false;
        }

        const bool already_persisted =
            previous.volume_identity == intent.volume_identity &&
            previous.object_id == intent.object_id &&
            previous.parent_object_id == intent.parent_object_id &&
            previous.logical_offset == intent.logical_offset &&
            previous.state == intent.state &&
            previous.flags == intent.flags;
        if (already_persisted)
        {
            return CloseHandle(existing_handle) != FALSE;
        }
        if (!IsValidCompactionIntentTransition(previous, intent) ||
            (fault_injection_hook_ &&
             fault_injection_hook_("compact-intent-state-append-handoff")) ||
            !PathMatchesPhysicalFile(intent_path, existing_identity, true))
        {
            CloseHandle(existing_handle);
            return false;
        }

        LARGE_INTEGER end{};
        bool write_started = false;
        bool written = SetFilePointerEx(existing_handle, end, nullptr, FILE_END) != FALSE;
        const auto* cursor = encoded.data();
        auto remaining = encoded.size();
        while (written && remaining != 0)
        {
            const auto chunk_size = static_cast<DWORD>((std::min)(
                remaining,
                static_cast<std::size_t>((std::numeric_limits<DWORD>::max)())));
            DWORD chunk_written = 0;
            if (WriteFile(
                    existing_handle,
                    cursor,
                    chunk_size,
                    &chunk_written,
                    nullptr) == FALSE ||
                chunk_written == 0)
            {
                written = false;
                break;
            }
            write_started = true;
            cursor += chunk_written;
            remaining -= chunk_written;
        }
        const bool injected_ambiguous_append =
            written &&
            fault_injection_hook_ &&
            fault_injection_hook_("compact-intent-state-append-ambiguous");
        const bool flushed =
            written &&
            !injected_ambiguous_append &&
            FlushFileBuffers(existing_handle) != FALSE;
        const bool identity_retained =
            PathMatchesPhysicalFile(intent_path, existing_identity, true);
        const bool closed = CloseHandle(existing_handle) != FALSE;
        if ((!written || !flushed || !identity_retained || !closed) &&
            bytes_may_have_persisted != nullptr)
        {
            *bytes_may_have_persisted = write_started;
        }
        return written && flushed && identity_retained && closed;
    }
    const auto existing_error = GetLastError();
    if (existing_error != ERROR_FILE_NOT_FOUND && existing_error != ERROR_PATH_NOT_FOUND)
    {
        return false;
    }

    const auto temp_path = UniqueSiblingPath(intent_path, L".tmp");
    HANDLE temp_handle = INVALID_HANDLE_VALUE;
    PhysicalFileIdentity temp_identity{};
    if (!WriteFileBytesDurably(temp_path, encoded, temp_handle, temp_identity))
    {
        return false;
    }

    const bool injected_publication_handoff =
        fault_injection_hook_ &&
        fault_injection_hook_("compact-intent-publication-handoff");
    const bool moved =
        !injected_publication_handoff &&
        RenameOpenedFileWithoutReplacing(temp_handle, intent_path);
    const bool injected_ambiguous_publication =
        moved && fault_injection_hook_ &&
        fault_injection_hook_("compact-intent-publish-ambiguous");
    const bool intent_directory_flushed =
        moved &&
        !injected_ambiguous_publication &&
        !(fault_injection_hook_ &&
          fault_injection_hook_("compact-intent-directory-flush")) &&
        FlushContainingDirectory(intent_path);
    if (!moved || injected_ambiguous_publication || !intent_directory_flushed)
    {
        const bool published = PathMatchesPhysicalFile(intent_path, temp_identity, true);
        const bool source_retained = PathMatchesPhysicalFile(temp_path, temp_identity, true);
        bool source_removed = false;
        if (published)
        {
            source_removed = CloseHandle(temp_handle) != FALSE;
            temp_handle = INVALID_HANDLE_VALUE;
        }
        else if (source_retained)
        {
            source_removed = DeleteOpenedFileDurably(temp_handle, temp_path);
        }
        else if (temp_handle != INVALID_HANDLE_VALUE)
        {
            CloseHandle(temp_handle);
            temp_handle = INVALID_HANDLE_VALUE;
        }
        if (bytes_may_have_persisted != nullptr)
        {
            *bytes_may_have_persisted = published || !source_retained || !source_removed;
        }
        return false;
    }
    const bool published = PathMatchesPhysicalFile(intent_path, temp_identity, true);
    const bool closed = CloseHandle(temp_handle) != FALSE;
    if ((!published || !closed) && bytes_may_have_persisted != nullptr)
    {
        *bytes_may_have_persisted = true;
    }
    return published && closed && intent_directory_flushed;
}

bool WriteAheadLog::ReadLatestCompactionIntent(
    void* intent_handle,
    std::uint32_t intent_volume_serial,
    std::uint64_t intent_file_id,
    Record& latest_intent) const
{
    auto* handle = static_cast<HANDLE>(intent_handle);
    const PhysicalFileIdentity expected_identity{
        intent_volume_serial,
        intent_file_id,
    };
    if (handle == nullptr ||
        handle == INVALID_HANDLE_VALUE ||
        !IsSafeWalPathHandle(handle) ||
        !PathMatchesPhysicalFile(
            CompactionIntentPath(options_.path),
            expected_identity,
            true))
    {
        return false;
    }

    std::uint64_t complete_prefix_bytes = 0;
    std::vector<std::uint8_t> bytes;
    if (!ReadPinnedIntentBytes(handle, bytes))
    {
        return false;
    }
    auto read = DecodeWalBytes(
        bytes,
        options_.volume_identity,
        &complete_prefix_bytes);
    if (read.status != ReadStatus::Ok ||
        !IsStrictCompactionIntentHistory(read.records, options_.volume_identity) ||
        !PathMatchesPhysicalFile(
            CompactionIntentPath(options_.path),
            expected_identity,
            true))
    {
        return false;
    }
    if (read.recovered_torn_tail)
    {
        if ((fault_injection_hook_ &&
             fault_injection_hook_("compact-intent-tail-truncate")) ||
            !TruncateFileHandleDurably(handle, complete_prefix_bytes) ||
            !PathMatchesPhysicalFile(
                CompactionIntentPath(options_.path),
                expected_identity,
                true))
        {
            return false;
        }
        if (!ReadPinnedIntentBytes(handle, bytes))
        {
            return false;
        }
        read = DecodeWalBytes(bytes, options_.volume_identity, nullptr);
        if (read.status != ReadStatus::Ok ||
            read.recovered_torn_tail ||
            !IsStrictCompactionIntentHistory(read.records, options_.volume_identity))
        {
            return false;
        }
    }

    latest_intent = read.records.back();
    return PathMatchesPhysicalFile(
        CompactionIntentPath(options_.path),
        expected_identity,
        true);
}

bool WriteAheadLog::DeleteRetainedCompactionTemp(
    std::uint32_t volume_serial,
    std::uint64_t replacement_file_id) const
{
    if (replacement_file_id == 0 || options_.path.empty())
    {
        return replacement_file_id == 0;
    }

    std::error_code ec;
    const auto absolute_wal = std::filesystem::absolute(options_.path, ec).lexically_normal();
    if (ec || absolute_wal.parent_path().empty())
    {
        return false;
    }
    const auto prefix = absolute_wal.filename().wstring() + L".compact.";
    bool removed = false;
    std::filesystem::directory_iterator entry(absolute_wal.parent_path(), ec);
    const std::filesystem::directory_iterator end;
    while (!ec && entry != end)
    {
        const auto candidate = entry->path();
        const auto filename = candidate.filename().wstring();
        if (HasExactNumericPairSuffix(filename, prefix))
        {
            auto* candidate_handle = CreateFileW(
                candidate.wstring().c_str(),
                DELETE | FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ,
                nullptr,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                nullptr);
            PhysicalFileIdentity candidate_identity{};
            const bool identity_matches =
                candidate_handle != INVALID_HANDLE_VALUE &&
                IsRegularWalPathHandle(candidate_handle) &&
                TryGetPhysicalFileIdentity(candidate_handle, candidate_identity) &&
                candidate_identity.volume_serial == volume_serial &&
                candidate_identity.file_id == replacement_file_id;
            if (identity_matches)
            {
                if (!IsSafeWalPathHandle(candidate_handle) ||
                    !PathMatchesPhysicalFile(candidate, candidate_identity, true) ||
                    !SetOpenedFileDeletePending(candidate_handle, true))
                {
                    CloseHandle(candidate_handle);
                    return false;
                }
                const bool handoff_failed =
                    fault_injection_hook_ &&
                    fault_injection_hook_("compact-retained-temp-delete-handoff");
                DWORD links_at_delete = 0;
                const bool delete_is_safe =
                    !handoff_failed &&
                    TryGetPhysicalLinkCount(candidate_handle, links_at_delete) &&
                    links_at_delete == 0;
                if (!delete_is_safe)
                {
                    const bool deletion_cancelled =
                        SetOpenedFileDeletePending(candidate_handle, false);
                    const bool closed = CloseHandle(candidate_handle) != FALSE;
                    if (!deletion_cancelled || !closed)
                    {
                        return false;
                    }
                    return false;
                }
                const bool closed = CloseHandle(candidate_handle) != FALSE;
                candidate_handle = INVALID_HANDLE_VALUE;
                if (!closed || !PathIsAbsent(candidate))
                {
                    return false;
                }
                removed = true;
            }
            else if (candidate_handle != INVALID_HANDLE_VALUE)
            {
                CloseHandle(candidate_handle);
            }
        }
        entry.increment(ec);
    }
    if (ec)
    {
        return false;
    }
    return !removed || FlushContainingDirectory(absolute_wal);
}

bool WriteAheadLog::CleanupPreIntentCompactionOrphans() const
{
    if (options_.path.empty())
    {
        return true;
    }

    std::error_code ec;
    const auto absolute_wal = std::filesystem::absolute(options_.path, ec).lexically_normal();
    if (ec || absolute_wal.parent_path().empty())
    {
        return false;
    }
    const auto intent_path = CompactionIntentPath(absolute_wal);
    const auto intent_attributes = GetFileAttributesW(intent_path.wstring().c_str());
    if (intent_attributes != INVALID_FILE_ATTRIBUTES)
    {
        return true;
    }
    const auto intent_error = GetLastError();
    if (intent_error != ERROR_FILE_NOT_FOUND && intent_error != ERROR_PATH_NOT_FOUND)
    {
        return false;
    }

    const std::array prefixes{
        absolute_wal.filename().wstring() + L".compact.",
        absolute_wal.filename().wstring() + L".compact.intent.tmp.",
    };
    std::vector<std::filesystem::path> candidates;
    for (std::filesystem::directory_iterator entry(absolute_wal.parent_path(), ec), end;
         !ec && entry != end;
         entry.increment(ec))
    {
        const auto filename = entry->path().filename().wstring();
        if (std::any_of(prefixes.begin(), prefixes.end(), [&](const auto& prefix)
            {
                return HasExactNumericPairSuffix(filename, prefix);
            }))
        {
            candidates.push_back(entry->path());
        }
    }
    if (ec || candidates.empty())
    {
        return !ec;
    }

    struct PinnedCandidate
    {
        std::filesystem::path path;
        HANDLE handle = INVALID_HANDLE_VALUE;
        PhysicalFileIdentity identity{};
    };
    std::vector<PinnedCandidate> pinned;
    pinned.reserve(candidates.size());
    const auto close_pinned = [&]()
    {
        for (auto& candidate : pinned)
        {
            if (candidate.handle != INVALID_HANDLE_VALUE)
            {
                CloseHandle(candidate.handle);
                candidate.handle = INVALID_HANDLE_VALUE;
            }
        }
    };
    for (const auto& candidate : candidates)
    {
        PinnedCandidate opened{};
        opened.path = candidate;
        opened.handle = CreateFileW(
            candidate.wstring().c_str(),
            DELETE | FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            nullptr);
        if (opened.handle == INVALID_HANDLE_VALUE ||
            !IsSafeWalPathHandle(opened.handle) ||
            !TryGetPhysicalFileIdentity(opened.handle, opened.identity) ||
            !PathMatchesPhysicalFile(candidate, opened.identity, true))
        {
            if (opened.handle != INVALID_HANDLE_VALUE)
            {
                CloseHandle(opened.handle);
            }
            close_pinned();
            return false;
        }
        pinned.push_back(std::move(opened));
    }

    const auto intent_before_delete = GetFileAttributesW(intent_path.wstring().c_str());
    if (intent_before_delete != INVALID_FILE_ATTRIBUTES)
    {
        close_pinned();
        return true;
    }
    const auto intent_before_delete_error = GetLastError();
    if (intent_before_delete_error != ERROR_FILE_NOT_FOUND &&
        intent_before_delete_error != ERROR_PATH_NOT_FOUND)
    {
        close_pinned();
        return false;
    }

    bool removed = false;
    for (auto& candidate : pinned)
    {
        if (!IsSafeWalPathHandle(candidate.handle) ||
            !PathMatchesPhysicalFile(candidate.path, candidate.identity, true) ||
            !SetOpenedFileDeletePending(candidate.handle, true))
        {
            close_pinned();
            return false;
        }

        const bool handoff_failed =
            fault_injection_hook_ &&
            fault_injection_hook_("compact-orphan-delete-handoff");
        DWORD links_at_delete = 0;
        const bool delete_is_safe =
            !handoff_failed &&
            TryGetPhysicalLinkCount(candidate.handle, links_at_delete) &&
            links_at_delete == 0;
        if (!delete_is_safe)
        {
            const bool deletion_cancelled =
                SetOpenedFileDeletePending(candidate.handle, false);
            const bool closed = CloseHandle(candidate.handle) != FALSE;
            candidate.handle = INVALID_HANDLE_VALUE;
            close_pinned();
            if (!deletion_cancelled || !closed)
            {
                return false;
            }
            return false;
        }

        const bool closed = CloseHandle(candidate.handle) != FALSE;
        candidate.handle = INVALID_HANDLE_VALUE;
        if (!closed || !PathIsAbsent(candidate.path))
        {
            close_pinned();
            return false;
        }
        removed = true;
    }
    close_pinned();
    return !removed || FlushContainingDirectory(absolute_wal);
}

bool WriteAheadLog::DeleteCompletedCompactionPredecessorTombstone(
    std::uint32_t volume_serial,
    std::uint64_t predecessor_file_id) const
{
    const auto guard_path = CompactionPredecessorGuardPath(
        options_.path,
        predecessor_file_id);
    auto* guard_handle = CreateFileW(
        guard_path.wstring().c_str(),
        DELETE | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
        nullptr);
    if (guard_handle == INVALID_HANDLE_VALUE)
    {
        const auto error = GetLastError();
        return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND;
    }

    PhysicalFileIdentity identity{};
    std::uint64_t size = 0;
    const bool is_completed_tombstone =
        IsSafeWalPathHandle(guard_handle) &&
        TryGetPhysicalFileIdentity(guard_handle, identity) &&
        identity.volume_serial == volume_serial &&
        identity.file_id == predecessor_file_id &&
        TryGetPhysicalFileSize(guard_handle, size) &&
        size == 0 &&
        PathMatchesPhysicalFile(guard_path, identity, true);
    if (!is_completed_tombstone)
    {
        CloseHandle(guard_handle);
        return false;
    }
    return DeleteOpenedFileDurably(guard_handle, guard_path);
}

bool WriteAheadLog::ClearCompletedCompactionIntentForNewCompaction() const
{
    const auto intent_path = CompactionIntentPath(options_.path);
    auto* intent_handle = CreateFileW(
        intent_path.wstring().c_str(),
        GENERIC_READ | GENERIC_WRITE | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
        nullptr);
    if (intent_handle == INVALID_HANDLE_VALUE)
    {
        const auto error = GetLastError();
        return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND;
    }

    PhysicalFileIdentity intent_identity{};
    PhysicalFileIdentity current_identity{};
    Record completed{};
    const bool can_clear =
        LockWholeFileExclusive(intent_handle) &&
        IsSafeWalPathHandle(intent_handle) &&
        TryGetPhysicalFileIdentity(intent_handle, intent_identity) &&
        ReadLatestCompactionIntent(
            intent_handle,
            intent_identity.volume_serial,
            intent_identity.file_id,
            completed) &&
        completed.state == RecordState::Cleaned &&
        completed.flags == kCompactionIntentNamespaceDurableFlag &&
        append_handle_ != nullptr &&
        TryGetPhysicalFileIdentity(static_cast<HANDLE>(append_handle_), current_identity) &&
        current_identity.volume_serial ==
            static_cast<DWORD>(completed.parent_object_id) &&
        current_identity.file_id == completed.logical_offset &&
        PathMatchesPhysicalFile(options_.path, current_identity, true);
    const bool closed = CloseHandle(intent_handle) != FALSE;
    return can_clear &&
           closed &&
           DeleteCompletedCompactionPredecessorTombstone(
               static_cast<std::uint32_t>(completed.parent_object_id),
               completed.object_id) &&
           ClearCompactionIntent(
               completed,
               intent_identity.volume_serial,
               intent_identity.file_id);
}

bool WriteAheadLog::RestoreMissingCanonicalForPublishArmedIntent() const
{
    if (append_handle_ != nullptr || writer_lease_handle_ == nullptr)
    {
        return false;
    }

    const auto intent_path = CompactionIntentPath(options_.path);
    auto* intent_guard = CreateFileW(
        intent_path.wstring().c_str(),
        GENERIC_READ | GENERIC_WRITE | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
        nullptr);
    PhysicalFileIdentity intent_identity{};
    if (intent_guard == INVALID_HANDLE_VALUE ||
        !LockWholeFileExclusive(intent_guard) ||
        !IsSafeWalPathHandle(intent_guard) ||
        !TryGetPhysicalFileIdentity(intent_guard, intent_identity))
    {
        if (intent_guard != INVALID_HANDLE_VALUE)
        {
            CloseHandle(intent_guard);
        }
        return false;
    }

    Record intent{};
    const bool valid_intent =
        ReadLatestCompactionIntent(
            intent_guard,
            intent_identity.volume_serial,
            intent_identity.file_id,
            intent) &&
        intent.state == RecordState::PublishArmed &&
        intent.logical_offset != 0 &&
        PathMatchesPhysicalFile(intent_path, intent_identity, true);
    if (!valid_intent)
    {
        CloseHandle(intent_guard);
        return false;
    }

    const PhysicalFileIdentity predecessor_identity{
        static_cast<DWORD>(intent.parent_object_id),
        intent.object_id,
    };
    const auto predecessor_guard_path = CompactionPredecessorGuardPath(
        options_.path,
        predecessor_identity.file_id);
    auto* predecessor_guard = CreateFileW(
        predecessor_guard_path.wstring().c_str(),
        GENERIC_READ | DELETE | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
        nullptr);
    PhysicalFileIdentity guarded_identity{};
    const bool guarded_predecessor_is_safe =
        predecessor_guard != INVALID_HANDLE_VALUE &&
        LockWholeFileExclusive(predecessor_guard) &&
        IsSafeWalPathHandle(predecessor_guard) &&
        TryGetPhysicalFileIdentity(predecessor_guard, guarded_identity) &&
        guarded_identity.volume_serial == predecessor_identity.volume_serial &&
        guarded_identity.file_id == predecessor_identity.file_id;
    if (!guarded_predecessor_is_safe)
    {
        if (predecessor_guard != INVALID_HANDLE_VALUE)
        {
            CloseHandle(predecessor_guard);
        }
        CloseHandle(intent_guard);
        return false;
    }

    const auto canonical_wide = options_.path.wstring();
    const auto canonical_attributes = GetFileAttributesW(canonical_wide.c_str());
    const auto canonical_error =
        canonical_attributes == INVALID_FILE_ATTRIBUTES ? GetLastError() : ERROR_SUCCESS;
    const bool canonical_is_absent =
        canonical_attributes == INVALID_FILE_ATTRIBUTES &&
        (canonical_error == ERROR_FILE_NOT_FOUND || canonical_error == ERROR_PATH_NOT_FOUND);
    const bool injected_restore_failure =
        fault_injection_hook_ && fault_injection_hook_("compact-missing-canonical-restore-call");
    const bool renamed =
        canonical_is_absent &&
        !injected_restore_failure &&
        RenameOpenedFileWithoutReplacing(predecessor_guard, options_.path);
    const bool predecessor_restored =
        (renamed || PathMatchesPhysicalFile(options_.path, predecessor_identity, true)) &&
        PathMatchesPhysicalFile(options_.path, predecessor_identity, true);
    const auto guard_attributes = GetFileAttributesW(predecessor_guard_path.wstring().c_str());
    const auto guard_error = guard_attributes == INVALID_FILE_ATTRIBUTES ? GetLastError() : ERROR_SUCCESS;
    const bool guard_is_absent =
        guard_attributes == INVALID_FILE_ATTRIBUTES &&
        (guard_error == ERROR_FILE_NOT_FOUND || guard_error == ERROR_PATH_NOT_FOUND);
    const bool directory_flushed =
        predecessor_restored &&
        guard_is_absent &&
        !(fault_injection_hook_ &&
          fault_injection_hook_("compact-missing-canonical-restore-directory-flush")) &&
        FlushContainingDirectory(options_.path);
    const bool predecessor_closed = CloseHandle(predecessor_guard) != FALSE;
    const bool intent_closed = CloseHandle(intent_guard) != FALSE;
    return predecessor_restored &&
           guard_is_absent &&
           directory_flushed &&
           predecessor_closed &&
           intent_closed;
}

bool WriteAheadLog::ResolvePendingCompactionIntent() const
{
    const auto intent_path = CompactionIntentPath(options_.path);
    const auto intent_wide = intent_path.wstring();
    auto* intent_guard = CreateFileW(
        intent_wide.c_str(),
        GENERIC_READ | GENERIC_WRITE | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
        nullptr);
    if (intent_guard == INVALID_HANDLE_VALUE)
    {
        const auto error = GetLastError();
        return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND;
    }
    PhysicalFileIdentity intent_identity{};
    if (!LockWholeFileExclusive(intent_guard) ||
        !IsSafeWalPathHandle(intent_guard) ||
        !TryGetPhysicalFileIdentity(intent_guard, intent_identity))
    {
        CloseHandle(intent_guard);
        return false;
    }

    Record intent{};
    const bool valid_record =
        ReadLatestCompactionIntent(
            intent_guard,
            intent_identity.volume_serial,
            intent_identity.file_id,
            intent) &&
        PathMatchesPhysicalFile(intent_path, intent_identity, true);
    if (!valid_record || append_handle_ == nullptr)
    {
        CloseHandle(intent_guard);
        return false;
    }

    const PhysicalFileIdentity replaced_identity{
        static_cast<DWORD>(intent.parent_object_id),
        intent.object_id,
    };
    PhysicalFileIdentity current_identity{};
    const bool current_identity_valid =
        TryGetPhysicalFileIdentity(static_cast<HANDLE>(append_handle_), current_identity) &&
        current_identity.volume_serial == replaced_identity.volume_serial;
    const bool current_is_predecessor =
        current_identity_valid && current_identity.file_id == replaced_identity.file_id;
    const bool current_is_replacement =
        current_identity_valid &&
        intent.logical_offset != 0 &&
        current_identity.file_id == intent.logical_offset;
    const bool state_allows_predecessor =
        intent.state == RecordState::Prepared ||
        intent.state == RecordState::PublishArmed;
    if (!current_identity_valid ||
        (state_allows_predecessor
             ? (!current_is_predecessor && !current_is_replacement)
             : !current_is_replacement))
    {
        CloseHandle(intent_guard);
        return false;
    }

    const auto predecessor_guard_path = CompactionPredecessorGuardPath(
        options_.path,
        replaced_identity.file_id);
    const auto predecessor_guard_wide = predecessor_guard_path.wstring();
    const auto predecessor_guard_access =
        state_allows_predecessor && current_is_predecessor
            ? DELETE | FILE_READ_ATTRIBUTES
            : GENERIC_WRITE | DELETE | FILE_READ_ATTRIBUTES;
    auto* predecessor_guard = CreateFileW(
        predecessor_guard_wide.c_str(),
        predecessor_guard_access,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
        nullptr);
    if (predecessor_guard == INVALID_HANDLE_VALUE)
    {
        const auto error = GetLastError();
        const bool guard_missing =
            error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND;
        const bool canonical_is_safe =
            IsSafeWalPathHandle(static_cast<HANDLE>(append_handle_)) &&
            PathMatchesPhysicalFile(options_.path, current_identity, true);
        CloseHandle(intent_guard);
        if (!guard_missing || !canonical_is_safe)
        {
            return false;
        }
        if (intent.state == RecordState::Cleaned && current_is_replacement)
        {
            if (intent.flags == kCompactionIntentNamespaceDurableFlag)
            {
                return true;
            }
            if ((fault_injection_hook_ &&
                 fault_injection_hook_("compact-predecessor-unlink-directory-flush")) ||
                !FlushContainingDirectory(predecessor_guard_path) ||
                !PersistCompactionIntent(
                    replaced_identity.volume_serial,
                    replaced_identity.file_id,
                    RecordState::Cleaned,
                    current_identity.file_id,
                    nullptr,
                    true))
            {
                return false;
            }
            return ResolvePendingCompactionIntent();
        }
        if (state_allows_predecessor && current_is_predecessor)
        {
            const bool predecessor_directory_flushed =
                !(fault_injection_hook_ &&
                  fault_injection_hook_("compact-predecessor-unlink-directory-flush")) &&
                FlushContainingDirectory(predecessor_guard_path);
            return predecessor_directory_flushed &&
                   DeleteRetainedCompactionTemp(
                       replaced_identity.volume_serial,
                       intent.logical_offset) &&
                   ClearCompactionIntent(
                       intent,
                       intent_identity.volume_serial,
                       intent_identity.file_id);
        }
        return false;
    }

    PhysicalFileIdentity guarded_predecessor_identity{};
    DWORD predecessor_links = 0;
    DWORD current_links = 0;
    const bool cleanup_phase =
        intent.state == RecordState::Checkpointed ||
        intent.state == RecordState::CleanupArmed ||
        intent.state == RecordState::Cleaned;
    const bool predecessor_lock_held =
        !cleanup_phase || LockWholeFileExclusive(predecessor_guard);
    const bool link_counts_are_valid =
        TryGetPhysicalLinkCount(predecessor_guard, predecessor_links) &&
        TryGetPhysicalLinkCount(static_cast<HANDLE>(append_handle_), current_links) &&
        (current_is_predecessor
             ? predecessor_links == 2 && current_links == 2
             : predecessor_links == 1 && current_links == 1);
    const bool guard_is_safe =
        predecessor_lock_held &&
        IsRegularWalPathHandle(predecessor_guard) &&
        TryGetPhysicalFileIdentity(predecessor_guard, guarded_predecessor_identity) &&
        guarded_predecessor_identity.volume_serial == replaced_identity.volume_serial &&
        guarded_predecessor_identity.file_id == replaced_identity.file_id &&
        link_counts_are_valid &&
        IsRegularWalPathHandle(static_cast<HANDLE>(append_handle_));
    if (!guard_is_safe)
    {
        CloseHandle(predecessor_guard);
        CloseHandle(intent_guard);
        return false;
    }

    if (intent.state == RecordState::Checkpointed)
    {
        CloseHandle(predecessor_guard);
        CloseHandle(intent_guard);
        if (!current_is_replacement ||
            !PersistCompactionIntent(
                replaced_identity.volume_serial,
                replaced_identity.file_id,
                RecordState::CleanupArmed,
                current_identity.file_id))
        {
            return false;
        }
        if (fault_injection_hook_ && fault_injection_hook_("compact-after-cleanup-armed"))
        {
            return false;
        }
        return ResolvePendingCompactionIntent();
    }

    if (state_allows_predecessor && current_is_replacement)
    {
        const bool replacement_directory_flushed =
            !(fault_injection_hook_ &&
              fault_injection_hook_("compact-replacement-directory-flush")) &&
            FlushContainingDirectory(options_.path);
        CloseHandle(predecessor_guard);
        CloseHandle(intent_guard);
        if (!replacement_directory_flushed ||
            !PersistCompactionIntent(
                replaced_identity.volume_serial,
                replaced_identity.file_id,
                RecordState::Checkpointed,
                current_identity.file_id))
        {
            return false;
        }
        if (fault_injection_hook_ && fault_injection_hook_("compact-after-resolution-proof"))
        {
            return false;
        }
        return ResolvePendingCompactionIntent();
    }

    if (state_allows_predecessor)
    {
        if (!current_is_predecessor ||
            (fault_injection_hook_ &&
             fault_injection_hook_("compact-before-predecessor-unlink")) ||
            !MarkOpenedFileForPosixDeletion(predecessor_guard))
        {
            CloseHandle(predecessor_guard);
            CloseHandle(intent_guard);
            return false;
        }
        DWORD remaining_links = 0;
        const bool rollback_guard_removed =
            TryGetPhysicalLinkCount(predecessor_guard, remaining_links) &&
            remaining_links == 1 &&
            IsSafeWalPathHandle(static_cast<HANDLE>(append_handle_)) &&
            PathMatchesPhysicalFile(options_.path, current_identity, true);
        const bool guard_closed = CloseHandle(predecessor_guard) != FALSE;
        const bool guard_path_absent = PathIsAbsent(predecessor_guard_path);
        CloseHandle(intent_guard);
        if (!rollback_guard_removed ||
            !guard_closed ||
            !guard_path_absent ||
            !FlushContainingDirectory(predecessor_guard_path) ||
            !PathIsAbsent(predecessor_guard_path))
        {
            return false;
        }
        return DeleteRetainedCompactionTemp(
                   replaced_identity.volume_serial,
                   intent.logical_offset) &&
               ClearCompactionIntent(
                   intent,
                   intent_identity.volume_serial,
                   intent_identity.file_id);
    }

    if (intent.state == RecordState::CleanupArmed)
    {
        std::uint64_t predecessor_size = 0;
        if ((fault_injection_hook_ &&
             fault_injection_hook_("compact-before-predecessor-unlink")) ||
            !TryGetPhysicalFileSize(predecessor_guard, predecessor_size) ||
            !TruncateFileHandleDurably(predecessor_guard, 0))
        {
            CloseHandle(predecessor_guard);
            CloseHandle(intent_guard);
            return false;
        }
        if (fault_injection_hook_ &&
            fault_injection_hook_("compact-after-predecessor-disposition"))
        {
            CloseHandle(predecessor_guard);
            CloseHandle(intent_guard);
            return false;
        }
        DWORD tombstone_links = 0;
        const bool tombstone_proven =
            TryGetPhysicalFileSize(predecessor_guard, predecessor_size) &&
            predecessor_size == 0 &&
            TryGetPhysicalLinkCount(predecessor_guard, tombstone_links) &&
            tombstone_links == 1 &&
            IsSafeWalPathHandle(static_cast<HANDLE>(append_handle_)) &&
            PathMatchesPhysicalFile(options_.path, current_identity, true) &&
            PathMatchesPhysicalFile(
                predecessor_guard_path,
                guarded_predecessor_identity,
                false);
        if (!tombstone_proven ||
            (fault_injection_hook_ &&
             fault_injection_hook_("compact-after-predecessor-zero-link-proof")))
        {
            CloseHandle(predecessor_guard);
            CloseHandle(intent_guard);
            return false;
        }

        const bool intent_guard_closed = CloseHandle(intent_guard) != FALSE;
        intent_guard = INVALID_HANDLE_VALUE;
        if (!intent_guard_closed ||
            !PersistCompactionIntent(
                replaced_identity.volume_serial,
                replaced_identity.file_id,
                RecordState::Cleaned,
                current_identity.file_id))
        {
            CloseHandle(predecessor_guard);
            return false;
        }
        const bool predecessor_guard_closed = CloseHandle(predecessor_guard) != FALSE;
        if (!predecessor_guard_closed ||
            (fault_injection_hook_ &&
             fault_injection_hook_("compact-after-predecessor-unlink")))
        {
            return false;
        }
        return ResolvePendingCompactionIntent();
    }

    if (intent.state != RecordState::Cleaned)
    {
        CloseHandle(predecessor_guard);
        CloseHandle(intent_guard);
        return false;
    }

    std::uint64_t tombstone_size = 0;
    const bool tombstone_is_safe =
        TryGetPhysicalFileSize(predecessor_guard, tombstone_size) &&
        tombstone_size == 0 &&
        PathMatchesPhysicalFile(
            predecessor_guard_path,
            guarded_predecessor_identity,
            false) &&
        IsSafeWalPathHandle(static_cast<HANDLE>(append_handle_)) &&
        PathMatchesPhysicalFile(options_.path, current_identity, true);
    const bool predecessor_guard_closed = CloseHandle(predecessor_guard) != FALSE;
    const bool intent_guard_closed = CloseHandle(intent_guard) != FALSE;
    if (!tombstone_is_safe || !predecessor_guard_closed || !intent_guard_closed)
    {
        return false;
    }
    if (intent.flags == kCompactionIntentNamespaceDurableFlag)
    {
        return true;
    }
    if ((fault_injection_hook_ &&
         fault_injection_hook_("compact-predecessor-unlink-directory-flush")) ||
        !FlushContainingDirectory(predecessor_guard_path) ||
        (fault_injection_hook_ &&
         fault_injection_hook_("compact-after-predecessor-directory-flush")) ||
        !PersistCompactionIntent(
            replaced_identity.volume_serial,
            replaced_identity.file_id,
            RecordState::Cleaned,
            current_identity.file_id,
            nullptr,
            true))
    {
        return false;
    }
    return ResolvePendingCompactionIntent();
}

bool WriteAheadLog::ClearCompactionIntent(
    const Record& intent,
    std::uint32_t intent_volume_serial,
    std::uint64_t intent_file_id) const
{
    const auto intent_path = CompactionIntentPath(options_.path);
    const auto intent_wide = intent_path.wstring();
    auto* intent_handle = CreateFileW(
        intent_wide.c_str(),
        DELETE | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
        nullptr);
    PhysicalFileIdentity identity{};
    if (intent_handle == INVALID_HANDLE_VALUE ||
        !IsSafeWalPathHandle(intent_handle) ||
        !TryGetPhysicalFileIdentity(intent_handle, identity) ||
        identity.volume_serial != intent_volume_serial ||
        identity.file_id != intent_file_id)
    {
        if (intent_handle != INVALID_HANDLE_VALUE)
        {
            CloseHandle(intent_handle);
        }
        return false;
    }

    if ((fault_injection_hook_ && fault_injection_hook_("compact-before-intent-delete")) ||
        !MarkOpenedFileForPosixDeletion(intent_handle))
    {
        CloseHandle(intent_handle);
        return false;
    }
    DWORD remaining_links = 0;
    const bool zero_links =
        TryGetPhysicalLinkCount(intent_handle, remaining_links) &&
        remaining_links == 0;
    const bool closed = CloseHandle(intent_handle) != FALSE;
    intent_handle = INVALID_HANDLE_VALUE;
    const auto attributes = GetFileAttributesW(intent_wide.c_str());
    const auto error = attributes == INVALID_FILE_ATTRIBUTES ? GetLastError() : ERROR_SUCCESS;
    const bool path_absent = attributes == INVALID_FILE_ATTRIBUTES &&
                             (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND);
    const bool directory_flushed =
        !(fault_injection_hook_ &&
          fault_injection_hook_("compact-intent-clear-directory-flush")) &&
        FlushContainingDirectory(intent_path);
    const bool cleared = zero_links && closed && path_absent && directory_flushed;
    if (!cleared && path_absent)
    {
        (void)PersistCompactionIntent(
            static_cast<std::uint32_t>(intent.parent_object_id),
            intent.object_id,
            intent.state,
            intent.logical_offset);
    }
    return cleared;
}

bool WriteAheadLog::AcquireExclusiveWriterLease() const
{
    std::lock_guard<std::recursive_mutex> operation_lock(WalOperationMutex(options_.path));
    if (options_.path.empty())
    {
        return true;
    }

    if (append_handle_ != nullptr && writer_lease_handle_ != nullptr)
    {
        return true;
    }

    std::error_code ec;
    const auto parent = options_.path.parent_path();
    if (!parent.empty())
    {
        std::filesystem::create_directories(parent, ec);
        if (ec)
        {
            return false;
        }
    }
    if (TryTransferRegisteredHandlesForPath(options_.path, this))
    {
        if (!CleanupPreIntentCompactionOrphans())
        {
            (void)CloseAppendHandle();
            return false;
        }
        return true;
    }
    return EnsureAppendHandle();
}

bool WriteAheadLog::TruncateAppendHandle(std::uint64_t complete_prefix_bytes) const
{
    if (append_handle_ == nullptr ||
        complete_prefix_bytes > static_cast<std::uint64_t>((std::numeric_limits<LONGLONG>::max)()))
    {
        return false;
    }

    LARGE_INTEGER end{};
    end.QuadPart = static_cast<LONGLONG>(complete_prefix_bytes);
    auto* handle = static_cast<HANDLE>(append_handle_);
    if (SetFilePointerEx(handle, end, nullptr, FILE_BEGIN) == FALSE ||
        SetEndOfFile(handle) == FALSE ||
        FlushFileBuffers(handle) == FALSE)
    {
        return false;
    }
    append_handle_size_ = complete_prefix_bytes;
    append_handle_size_known_ = true;
    return true;
}

bool WriteAheadLog::FlushAppendHandle() const
{
    if (append_handle_ == nullptr ||
        (fault_injection_hook_ && fault_injection_hook_("durable-flush")) ||
        FlushFileBuffers(static_cast<HANDLE>(append_handle_)) == FALSE)
    {
        return false;
    }

    ++append_handle_flush_count_;
    return true;
}

WriteAheadLog::EncodedAppendResult WriteAheadLog::AppendEncoded(
    const std::vector<std::uint8_t>& encoded) const
{
    if (!EnsureAppendHandle())
    {
        return EncodedAppendResult::RejectedBeforeWrite;
    }

    auto* handle = static_cast<HANDLE>(append_handle_);
    const auto* cursor = encoded.data();
    auto remaining = encoded.size();
    std::size_t written_total = 0;
    while (remaining > 0)
    {
        const auto chunk_bytes = static_cast<DWORD>(
            (std::min)(remaining, static_cast<std::size_t>((std::numeric_limits<DWORD>::max)())));
        DWORD written = 0;
        if (!WriteFile(handle, cursor, chunk_bytes, &written, nullptr) ||
            written == 0 ||
            written != chunk_bytes)
        {
            (void)CloseAppendHandle();
            return written_total == 0 && written == 0
                ? EncodedAppendResult::RejectedBeforeWrite
                : EncodedAppendResult::BytesMayHavePersisted;
        }
        cursor += written;
        remaining -= written;
        written_total += written;
    }
    if (append_handle_size_known_ &&
        encoded.size() <= (std::numeric_limits<std::uint64_t>::max)() - append_handle_size_)
    {
        append_handle_size_ += static_cast<std::uint64_t>(encoded.size());
    }
    else
    {
        append_handle_size_known_ = false;
    }
    return EncodedAppendResult::Succeeded;
}

bool WriteAheadLog::Append(const Record& record, bool durable_flush) const
{
    return AppendWithResult(record, durable_flush, 0) == AppendResult::Succeeded;
}

WriteAheadLog::AppendResult WriteAheadLog::AppendWithResult(
    const Record& record,
    bool durable_flush,
    std::uint64_t expected_writer_generation) const
{
    std::lock_guard<std::recursive_mutex> operation_lock(WalOperationMutex(options_.path));
    if (options_.path.empty())
    {
        return AppendResult::Succeeded;
    }
    if (expected_writer_generation != 0 &&
        (writer_lease_handle_ == nullptr || writer_lease_generation_ != expected_writer_generation))
    {
        return AppendResult::RejectedBeforeWrite;
    }

    std::error_code ec;
    std::filesystem::create_directories(options_.path.parent_path(), ec);
    if (ec)
    {
        return AppendResult::RejectedBeforeWrite;
    }

    Record writable_record = record;
    if (writable_record.volume_identity.empty())
    {
        writable_record.volume_identity = options_.volume_identity;
    }
    else if (writable_record.volume_identity != options_.volume_identity)
    {
        return AppendResult::RejectedBeforeWrite;
    }
    const auto encoded = EncodeForTest(writable_record);
    if (encoded.empty())
    {
        return AppendResult::RejectedBeforeWrite;
    }
    if (options_.max_bytes > 0)
    {
        const auto existing_size = append_handle_ != nullptr && append_handle_size_known_
            ? append_handle_size_
            : (std::filesystem::exists(options_.path, ec)
                ? std::filesystem::file_size(options_.path, ec)
                : 0);
        if (ec || existing_size + encoded.size() > options_.max_bytes)
        {
            return AppendResult::RejectedBeforeWrite;
        }
    }

    const auto append_result = AppendEncoded(encoded);
    if (append_result != EncodedAppendResult::Succeeded)
    {
        return append_result == EncodedAppendResult::RejectedBeforeWrite
            ? AppendResult::RejectedBeforeWrite
            : AppendResult::BytesMayHavePersisted;
    }

    if (!durable_flush)
    {
        return AppendResult::Succeeded;
    }
    if (!FlushAppendHandle())
    {
        (void)CloseAppendHandle();
        return AppendResult::BytesMayHavePersisted;
    }
    return AppendResult::Succeeded;
}

bool WriteAheadLog::AppendBatch(const std::vector<Record>& records, bool durable_flush) const
{
    return AppendBatchWithResult(records, durable_flush, 0) == AppendResult::Succeeded;
}

WriteAheadLog::AppendResult WriteAheadLog::AppendBatchWithResult(
    const std::vector<Record>& records,
    bool durable_flush,
    std::uint64_t expected_writer_generation) const
{
    std::lock_guard<std::recursive_mutex> operation_lock(WalOperationMutex(options_.path));
    if (records.empty() || options_.path.empty())
    {
        return AppendResult::Succeeded;
    }
    if (expected_writer_generation != 0 &&
        (writer_lease_handle_ == nullptr || writer_lease_generation_ != expected_writer_generation))
    {
        return AppendResult::RejectedBeforeWrite;
    }

    std::error_code ec;
    std::filesystem::create_directories(options_.path.parent_path(), ec);
    if (ec)
    {
        return AppendResult::RejectedBeforeWrite;
    }

    std::vector<std::uint8_t> encoded_batch;
    std::uint64_t encoded_bytes = 0;
    for (const auto& record : records)
    {
        Record writable_record = record;
        if (writable_record.volume_identity.empty())
        {
            writable_record.volume_identity = options_.volume_identity;
        }
        else if (writable_record.volume_identity != options_.volume_identity)
        {
            return AppendResult::RejectedBeforeWrite;
        }
        auto encoded = EncodeForTest(writable_record);
        if (encoded.empty())
        {
            return AppendResult::RejectedBeforeWrite;
        }
        if (encoded_bytes > (std::numeric_limits<std::uint64_t>::max)() - encoded.size())
        {
            return AppendResult::RejectedBeforeWrite;
        }
        encoded_bytes += static_cast<std::uint64_t>(encoded.size());
        if (encoded.size() > (std::numeric_limits<std::size_t>::max)() - encoded_batch.size())
        {
            return AppendResult::RejectedBeforeWrite;
        }
        encoded_batch.insert(encoded_batch.end(), encoded.begin(), encoded.end());
    }

    if (options_.max_bytes > 0)
    {
        const auto existing_size = append_handle_ != nullptr && append_handle_size_known_
            ? append_handle_size_
            : (std::filesystem::exists(options_.path, ec)
                ? std::filesystem::file_size(options_.path, ec)
                : 0);
        if (ec ||
            existing_size > options_.max_bytes ||
            encoded_bytes > options_.max_bytes - existing_size)
        {
            return AppendResult::RejectedBeforeWrite;
        }
    }

    const auto append_result = AppendEncoded(encoded_batch);
    if (append_result != EncodedAppendResult::Succeeded)
    {
        return append_result == EncodedAppendResult::RejectedBeforeWrite
            ? AppendResult::RejectedBeforeWrite
            : AppendResult::BytesMayHavePersisted;
    }

    if (!durable_flush)
    {
        return AppendResult::Succeeded;
    }
    if (!FlushAppendHandle())
    {
        (void)CloseAppendHandle();
        return AppendResult::BytesMayHavePersisted;
    }
    return AppendResult::Succeeded;
}

bool WriteAheadLog::FlushPendingAppends() const
{
    std::lock_guard<std::recursive_mutex> operation_lock(WalOperationMutex(options_.path));
    if (options_.path.empty())
    {
        return true;
    }
    if (append_handle_ == nullptr || writer_lease_handle_ == nullptr)
    {
        return false;
    }
    return FlushAppendHandle();
}

bool WriteAheadLog::Compact(std::uint64_t minimum_sequence_to_keep) const
{
    return CompactWithResult(minimum_sequence_to_keep, 0) == CompactionResult::Succeeded;
}

WriteAheadLog::CompactionResult WriteAheadLog::CompactWithResult(
    std::uint64_t minimum_sequence_to_keep,
    std::uint64_t expected_writer_generation) const
{
    std::lock_guard<std::recursive_mutex> operation_lock(WalOperationMutex(options_.path));
    if (options_.path.empty())
    {
        return CompactionResult::Succeeded;
    }
    if (expected_writer_generation == 0)
    {
        if (!AcquireExclusiveWriterLease())
        {
            return CompactionResult::RejectedBeforeWrite;
        }
    }
    else if (writer_lease_handle_ == nullptr ||
             writer_lease_generation_ != expected_writer_generation)
    {
        return CompactionResult::RejectedBeforeWrite;
    }
    if (!EnsureAppendHandle() || !ResolvePendingCompactionIntent())
    {
        (void)CloseAppendHandle();
        return CompactionResult::RejectedBeforeWrite;
    }
    if (!ClearCompletedCompactionIntentForNewCompaction())
    {
        (void)CloseAppendHandle();
        return CompactionResult::RejectedBeforeWrite;
    }

    std::uint64_t complete_prefix_bytes = 0;
    auto read = ReadAllInternal(
        options_.path,
        options_.volume_identity,
        false,
        &complete_prefix_bytes);
    if (read.status != ReadStatus::Ok)
    {
        return CompactionResult::RejectedBeforeWrite;
    }
    if (read.recovered_torn_tail && !TruncateAppendHandle(complete_prefix_bytes))
    {
        (void)CloseAppendHandle();
        return CompactionResult::BytesMayHavePersisted;
    }
    if (read.recovered_torn_tail)
    {
        read = ReadAllInternal(
            options_.path,
            options_.volume_identity,
            false,
            nullptr);
        if (read.status != ReadStatus::Ok || read.recovered_torn_tail)
        {
            (void)CloseAppendHandle();
            return CompactionResult::BytesMayHavePersisted;
        }
    }
    std::vector<Record> kept;
    kept.reserve(read.records.size() + 1);
    for (const auto& record : read.records)
    {
        if (record.sequence >= minimum_sequence_to_keep ||
            record.operation == OperationKind::CompactionIndex)
        {
            kept.push_back(record);
        }
    }

    Record index{};
    index.volume_identity = options_.volume_identity;
    index.transaction_id = 0;
    index.sequence = minimum_sequence_to_keep;
    index.operation = OperationKind::CompactionIndex;
    index.state = RecordState::Cleaned;
    kept.push_back(index);

    std::error_code ec;
    std::filesystem::create_directories(options_.path.parent_path(), ec);
    if (ec)
    {
        return CompactionResult::RejectedBeforeWrite;
    }

    const auto temp_path = UniqueSiblingPath(options_.path, L".compact");
    HANDLE temp_guard = INVALID_HANDLE_VALUE;
    PhysicalFileIdentity temp_identity{};
    if (!WriteWalRecordsDurably(temp_path, kept, temp_guard, temp_identity))
    {
        return CompactionResult::RejectedBeforeWrite;
    }
    const auto abandon_temp = [&]()
    {
        if (temp_guard == INVALID_HANDLE_VALUE)
        {
            return true;
        }
        if (DeleteOpenedFileDurably(temp_guard, temp_path))
        {
            return true;
        }
        CloseHandle(temp_guard);
        temp_guard = INVALID_HANDLE_VALUE;
        return false;
    };
    const auto close_published_temp = [&]()
    {
        if (temp_guard == INVALID_HANDLE_VALUE)
        {
            return true;
        }
        const bool closed = CloseHandle(temp_guard) != FALSE;
        temp_guard = INVALID_HANDLE_VALUE;
        return closed;
    };
    if (fault_injection_hook_ && fault_injection_hook_("compact-after-temp-write"))
    {
        const bool temp_removed = abandon_temp();
        (void)CloseAppendHandle();
        return temp_removed
            ? CompactionResult::RejectedBeforeWrite
            : CompactionResult::BytesMayHavePersisted;
    }
    const auto temp_wide = temp_path.wstring();
    PhysicalFileIdentity guarded_temp_identity{};
    const bool stable_temp =
        temp_guard != INVALID_HANDLE_VALUE &&
        IsSafeWalPathHandle(temp_guard) &&
        TryGetPhysicalFileIdentity(temp_guard, guarded_temp_identity) &&
        guarded_temp_identity.volume_serial == temp_identity.volume_serial &&
        guarded_temp_identity.file_id == temp_identity.file_id &&
        PathMatchesPhysicalFile(temp_path, temp_identity, true);
    if (!stable_temp)
    {
        return abandon_temp()
            ? CompactionResult::RejectedBeforeWrite
            : CompactionResult::BytesMayHavePersisted;
    }
    const auto target_wide = options_.path.wstring();
    auto* link_guard = CreateFileW(
        target_wide.c_str(),
        GENERIC_READ | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
        nullptr);
    PhysicalFileIdentity append_identity{};
    PhysicalFileIdentity replaced_identity{};
    if (link_guard == INVALID_HANDLE_VALUE ||
        !LockWholeFileExclusive(link_guard) ||
        !IsSafeWalPathHandle(link_guard) ||
        !TryGetPhysicalFileIdentity(static_cast<HANDLE>(append_handle_), append_identity) ||
        !TryGetPhysicalFileIdentity(link_guard, replaced_identity) ||
        append_identity.volume_serial != replaced_identity.volume_serial ||
        append_identity.file_id != replaced_identity.file_id ||
        temp_identity.volume_serial != replaced_identity.volume_serial)
    {
        if (link_guard != INVALID_HANDLE_VALUE)
        {
            CloseHandle(link_guard);
        }
        const bool temp_removed = abandon_temp();
        (void)CloseAppendHandle();
        return temp_removed
            ? CompactionResult::RejectedBeforeWrite
            : CompactionResult::BytesMayHavePersisted;
    }
    bool intent_bytes_may_have_persisted = false;
    if (!PersistCompactionIntent(
            replaced_identity.volume_serial,
            replaced_identity.file_id,
            RecordState::Prepared,
            temp_identity.file_id,
            &intent_bytes_may_have_persisted))
    {
        CloseHandle(link_guard);
        const bool temp_removed = abandon_temp();
        (void)CloseAppendHandle();
        return temp_removed && !intent_bytes_may_have_persisted
            ? CompactionResult::RejectedBeforeWrite
            : CompactionResult::BytesMayHavePersisted;
    }
    if (fault_injection_hook_ && fault_injection_hook_("compact-after-intent-publish"))
    {
        CloseHandle(link_guard);
        (void)close_published_temp();
        (void)CloseAppendHandle();
        return CompactionResult::BytesMayHavePersisted;
    }
    const auto predecessor_guard_path = CompactionPredecessorGuardPath(
        options_.path,
        replaced_identity.file_id);
    const auto predecessor_guard_wide = predecessor_guard_path.wstring();
    if (CreateHardLinkW(
            predecessor_guard_wide.c_str(),
            target_wide.c_str(),
            nullptr) == FALSE)
    {
        CloseHandle(link_guard);
        const bool temp_removed = abandon_temp();
        const bool intent_resolved = ResolvePendingCompactionIntent();
        if (!intent_resolved)
        {
            (void)CloseAppendHandle();
        }
        return temp_removed && intent_resolved
            ? CompactionResult::RejectedBeforeWrite
            : CompactionResult::BytesMayHavePersisted;
    }
    if ((fault_injection_hook_ &&
         fault_injection_hook_("compact-predecessor-directory-flush")) ||
        !FlushContainingDirectory(predecessor_guard_path))
    {
        CloseHandle(link_guard);
        (void)abandon_temp();
        (void)CloseAppendHandle();
        return CompactionResult::BytesMayHavePersisted;
    }
    auto* predecessor_guard = CreateFileW(
        predecessor_guard_wide.c_str(),
        FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
        nullptr);
    PhysicalFileIdentity guarded_predecessor_identity{};
    DWORD guarded_predecessor_links = 0;
    const bool predecessor_guard_is_safe =
        predecessor_guard != INVALID_HANDLE_VALUE &&
        IsRegularWalPathHandle(predecessor_guard) &&
        TryGetPhysicalFileIdentity(predecessor_guard, guarded_predecessor_identity) &&
        guarded_predecessor_identity.volume_serial == replaced_identity.volume_serial &&
        guarded_predecessor_identity.file_id == replaced_identity.file_id &&
        TryGetPhysicalLinkCount(predecessor_guard, guarded_predecessor_links) &&
        guarded_predecessor_links == 2 &&
        FlushFileBuffers(static_cast<HANDLE>(append_handle_)) != FALSE;
    if (!predecessor_guard_is_safe)
    {
        if (predecessor_guard != INVALID_HANDLE_VALUE)
        {
            CloseHandle(predecessor_guard);
        }
        CloseHandle(link_guard);
        (void)abandon_temp();
        (void)CloseAppendHandle();
        return CompactionResult::BytesMayHavePersisted;
    }
    bool publish_armed_bytes_may_have_persisted = false;
    if (!PersistCompactionIntent(
            replaced_identity.volume_serial,
            replaced_identity.file_id,
            RecordState::PublishArmed,
            temp_identity.file_id,
            &publish_armed_bytes_may_have_persisted))
    {
        CloseHandle(predecessor_guard);
        CloseHandle(link_guard);
        (void)close_published_temp();
        (void)CloseAppendHandle();
        return CompactionResult::BytesMayHavePersisted;
    }
    if (fault_injection_hook_ && fault_injection_hook_("compact-after-publish-armed"))
    {
        CloseHandle(predecessor_guard);
        CloseHandle(link_guard);
        (void)close_published_temp();
        (void)CloseAppendHandle();
        return CompactionResult::BytesMayHavePersisted;
    }
    if (!CloseAppendFileHandle())
    {
        CloseHandle(predecessor_guard);
        CloseHandle(link_guard);
        (void)abandon_temp();
        (void)CloseWriterLeaseHandle();
        return CompactionResult::BytesMayHavePersisted;
    }
    if (fault_injection_hook_ && fault_injection_hook_("compact-before-replace"))
    {
        CloseHandle(predecessor_guard);
        CloseHandle(link_guard);
        const bool temp_removed = abandon_temp();
        const bool handle_reopened = EnsureAppendHandle(true, false);
        if (!handle_reopened)
        {
            (void)CloseAppendHandle();
        }
        return temp_removed && handle_reopened
            ? CompactionResult::RejectedBeforeWrite
            : CompactionResult::BytesMayHavePersisted;
    }
    DWORD links_before_replace = 0;
    DWORD guard_links_before_replace = 0;
    if (!IsRegularWalPathHandle(link_guard) ||
        !TryGetPhysicalLinkCount(link_guard, links_before_replace) ||
        links_before_replace != 2 ||
        !IsRegularWalPathHandle(predecessor_guard) ||
        !TryGetPhysicalLinkCount(predecessor_guard, guard_links_before_replace) ||
        guard_links_before_replace != 2 ||
        !IsSafeWalPathHandle(temp_guard) ||
        !PathMatchesPhysicalFile(options_.path, replaced_identity, false) ||
        !PathMatchesPhysicalFile(temp_path, temp_identity, true))
    {
        CloseHandle(predecessor_guard);
        CloseHandle(link_guard);
        (void)abandon_temp();
        (void)CloseAppendHandle();
        return CompactionResult::BytesMayHavePersisted;
    }
    if (fault_injection_hook_ && fault_injection_hook_("compact-replace-handoff"))
    {
        CloseHandle(predecessor_guard);
        CloseHandle(link_guard);
        const bool temp_removed = abandon_temp();
        const bool handle_reopened = EnsureAppendHandle(true, false);
        if (!handle_reopened)
        {
            (void)CloseAppendHandle();
        }
        return temp_removed && handle_reopened
            ? CompactionResult::RejectedBeforeWrite
            : CompactionResult::BytesMayHavePersisted;
    }
    DWORD links_at_replace = 0;
    DWORD guard_links_at_replace = 0;
    if (!IsRegularWalPathHandle(link_guard) ||
        !TryGetPhysicalLinkCount(link_guard, links_at_replace) ||
        links_at_replace != 2 ||
        !IsRegularWalPathHandle(predecessor_guard) ||
        !TryGetPhysicalLinkCount(predecessor_guard, guard_links_at_replace) ||
        guard_links_at_replace != 2 ||
        !IsSafeWalPathHandle(temp_guard) ||
        !PathMatchesPhysicalFile(options_.path, replaced_identity, false) ||
        !PathMatchesPhysicalFile(temp_path, temp_identity, true))
    {
        CloseHandle(predecessor_guard);
        CloseHandle(link_guard);
        (void)abandon_temp();
        (void)CloseAppendHandle();
        return CompactionResult::BytesMayHavePersisted;
    }

    const bool injected_replace_failure =
        fault_injection_hook_ && fault_injection_hook_("compact-replace-call");
    bool canonical_unlinked = false;
    if (!injected_replace_failure)
    {
        auto* unlink_guard = CreateFileW(
            target_wide.c_str(),
            DELETE | FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            nullptr);
        PhysicalFileIdentity unlink_identity{};
        DWORD unlink_links = 0;
        const bool unlink_guard_is_predecessor =
            unlink_guard != INVALID_HANDLE_VALUE &&
            IsRegularWalPathHandle(unlink_guard) &&
            TryGetPhysicalFileIdentity(unlink_guard, unlink_identity) &&
            unlink_identity.volume_serial == replaced_identity.volume_serial &&
            unlink_identity.file_id == replaced_identity.file_id &&
            TryGetPhysicalLinkCount(unlink_guard, unlink_links) &&
            unlink_links == 2;
        if (!unlink_guard_is_predecessor ||
            !MarkOpenedFileForPosixDeletion(unlink_guard))
        {
            if (unlink_guard != INVALID_HANDLE_VALUE)
            {
                CloseHandle(unlink_guard);
            }
            CloseHandle(predecessor_guard);
            CloseHandle(link_guard);
            (void)close_published_temp();
            (void)CloseAppendHandle();
            return CompactionResult::BytesMayHavePersisted;
        }
        if (fault_injection_hook_ && fault_injection_hook_("compact-after-canonical-unlink"))
        {
            CloseHandle(unlink_guard);
            CloseHandle(predecessor_guard);
            CloseHandle(link_guard);
            (void)close_published_temp();
            (void)CloseAppendHandle();
            return CompactionResult::BytesMayHavePersisted;
        }

        DWORD predecessor_links_after_unlink = 0;
        DWORD guard_links_after_unlink = 0;
        const bool predecessor_retained_after_unlink =
            IsRegularWalPathHandle(unlink_guard) &&
            IsRegularWalPathHandle(link_guard) &&
            IsRegularWalPathHandle(predecessor_guard) &&
            TryGetPhysicalLinkCount(link_guard, predecessor_links_after_unlink) &&
            TryGetPhysicalLinkCount(predecessor_guard, guard_links_after_unlink) &&
            predecessor_links_after_unlink == 1 &&
            guard_links_after_unlink == 1 &&
            PathMatchesPhysicalFile(predecessor_guard_path, replaced_identity, true);
        const bool unlink_guard_closed = CloseHandle(unlink_guard) != FALSE;
        unlink_guard = INVALID_HANDLE_VALUE;
        const auto canonical_attributes = GetFileAttributesW(target_wide.c_str());
        const auto canonical_error =
            canonical_attributes == INVALID_FILE_ATTRIBUTES ? GetLastError() : ERROR_SUCCESS;
        canonical_unlinked =
            predecessor_retained_after_unlink &&
            unlink_guard_closed &&
            canonical_attributes == INVALID_FILE_ATTRIBUTES &&
            (canonical_error == ERROR_FILE_NOT_FOUND || canonical_error == ERROR_PATH_NOT_FOUND);
        if (!canonical_unlinked ||
            (fault_injection_hook_ &&
             fault_injection_hook_("compact-canonical-unlink-directory-flush")) ||
            !FlushContainingDirectory(options_.path))
        {
            CloseHandle(predecessor_guard);
            CloseHandle(link_guard);
            (void)close_published_temp();
            (void)CloseAppendHandle();
            return CompactionResult::BytesMayHavePersisted;
        }
    }

    const bool injected_publication_handoff =
        canonical_unlinked && fault_injection_hook_ &&
        fault_injection_hook_("compact-publication-handoff");
    const bool replacement_renamed =
        canonical_unlinked &&
        !injected_publication_handoff &&
        RenameOpenedFileWithoutReplacing(temp_guard, options_.path);
    const bool injected_ambiguous_replace_result =
        replacement_renamed && fault_injection_hook_ &&
        fault_injection_hook_("compact-replace-result-ambiguous");
    if (!replacement_renamed || injected_ambiguous_replace_result)
    {
        const bool replacement_visible =
            PathMatchesPhysicalFile(options_.path, temp_identity, false);
        const bool temp_retained =
            PathMatchesPhysicalFile(temp_path, temp_identity, false);
        CloseHandle(predecessor_guard);
        CloseHandle(link_guard);
        if (replacement_visible)
        {
            (void)close_published_temp();
            (void)CloseAppendHandle();
            return CompactionResult::BytesMayHavePersisted;
        }
        if (!temp_retained)
        {
            (void)close_published_temp();
            (void)CloseAppendHandle();
            return CompactionResult::BytesMayHavePersisted;
        }
        const bool predecessor_is_still_canonical =
            !canonical_unlinked &&
            PathMatchesPhysicalFile(options_.path, replaced_identity, false);
        if (!predecessor_is_still_canonical)
        {
            (void)close_published_temp();
            (void)CloseAppendHandle();
            return CompactionResult::BytesMayHavePersisted;
        }
        const bool temp_removed = abandon_temp();
        if (!temp_removed)
        {
            (void)CloseAppendHandle();
            return CompactionResult::BytesMayHavePersisted;
        }
        const bool handle_reopened = EnsureAppendHandle(false, false);
        PhysicalFileIdentity reopened_identity{};
        const bool predecessor_preserved =
            handle_reopened &&
            TryGetPhysicalFileIdentity(static_cast<HANDLE>(append_handle_), reopened_identity) &&
            reopened_identity.volume_serial == replaced_identity.volume_serial &&
            reopened_identity.file_id == replaced_identity.file_id;
        if (!predecessor_preserved)
        {
            (void)CloseAppendHandle();
            return CompactionResult::BytesMayHavePersisted;
        }
        if (!ResolvePendingCompactionIntent())
        {
            (void)CloseAppendHandle();
            return CompactionResult::BytesMayHavePersisted;
        }
        return CompactionResult::RejectedBeforeWrite;
    }
    if ((fault_injection_hook_ &&
         fault_injection_hook_("compact-replacement-directory-flush")) ||
        !FlushContainingDirectory(options_.path))
    {
        CloseHandle(predecessor_guard);
        CloseHandle(link_guard);
        (void)close_published_temp();
        (void)CloseAppendHandle();
        return CompactionResult::BytesMayHavePersisted;
    }

    PhysicalFileIdentity moved_temp_identity{};
    DWORD predecessor_links_after_replace = 0;
    DWORD guard_links_after_replace = 0;
    const bool replacement_is_pinned =
        IsSafeWalPathHandle(temp_guard) &&
        TryGetPhysicalFileIdentity(temp_guard, moved_temp_identity) &&
        moved_temp_identity.volume_serial == temp_identity.volume_serial &&
        moved_temp_identity.file_id == temp_identity.file_id &&
        PathMatchesPhysicalFile(options_.path, temp_identity, true) &&
        FlushFileBuffers(temp_guard) != FALSE;
    const bool predecessor_is_pinned =
        IsRegularWalPathHandle(link_guard) &&
        IsRegularWalPathHandle(predecessor_guard) &&
        TryGetPhysicalLinkCount(link_guard, predecessor_links_after_replace) &&
        TryGetPhysicalLinkCount(predecessor_guard, guard_links_after_replace) &&
        predecessor_links_after_replace == 1 &&
        guard_links_after_replace == 1 &&
        PathMatchesPhysicalFile(predecessor_guard_path, replaced_identity, true);
    CloseHandle(predecessor_guard);
    CloseHandle(link_guard);
    const bool replacement_handle_closed = close_published_temp();
    if (!replacement_is_pinned || !predecessor_is_pinned || !replacement_handle_closed)
    {
        (void)CloseAppendHandle();
        return CompactionResult::BytesMayHavePersisted;
    }
    if (fault_injection_hook_ && fault_injection_hook_("compact-after-replace"))
    {
        (void)CloseAppendHandle();
        return CompactionResult::BytesMayHavePersisted;
    }
    if (!EnsureAppendHandle(false, false))
    {
        return CompactionResult::BytesMayHavePersisted;
    }
    PhysicalFileIdentity reopened_identity{};
    if (!TryGetPhysicalFileIdentity(static_cast<HANDLE>(append_handle_), reopened_identity) ||
        reopened_identity.volume_serial != temp_identity.volume_serial ||
        reopened_identity.file_id != temp_identity.file_id)
    {
        (void)CloseAppendHandle();
        return CompactionResult::BytesMayHavePersisted;
    }
    if ((fault_injection_hook_ && fault_injection_hook_("compact-target-flush")) ||
        !FlushAppendHandle())
    {
        (void)CloseAppendHandle();
        return CompactionResult::BytesMayHavePersisted;
    }
    if ((fault_injection_hook_ && fault_injection_hook_("compact-before-intent-clear")) ||
        !IsSafeWalPathHandle(static_cast<HANDLE>(append_handle_)))
    {
        (void)CloseAppendHandle();
        return CompactionResult::BytesMayHavePersisted;
    }
    if (!ResolvePendingCompactionIntent())
    {
        (void)CloseAppendHandle();
        return CompactionResult::BytesMayHavePersisted;
    }
    return CompactionResult::Succeeded;
}

WriteAheadLog::ReadResult WriteAheadLog::ReadAll() const
{
    std::lock_guard<std::recursive_mutex> operation_lock(WalOperationMutex(options_.path));
    return ReadAllInternal(options_.path, options_.volume_identity, false, nullptr);
}

WriteAheadLog::ReadResult WriteAheadLog::ReadAllWithExclusiveWriterLease() const
{
    std::lock_guard<std::recursive_mutex> operation_lock(WalOperationMutex(options_.path));
    if (!AcquireExclusiveWriterLease())
    {
        ReadResult failed{};
        failed.status = ReadStatus::IoError;
        return failed;
    }
    if (fault_injection_hook_ && fault_injection_hook_("read-all-exclusive"))
    {
        ReadResult failed{};
        failed.status = ReadStatus::IoError;
        return failed;
    }

    std::uint64_t complete_prefix_bytes = 0;
    auto inspected = ReadAllInternal(
        options_.path,
        options_.volume_identity,
        false,
        &complete_prefix_bytes);
    if (inspected.status != ReadStatus::Ok)
    {
        (void)CloseAppendFileHandle();
        return inspected;
    }
    if (inspected.recovered_torn_tail &&
        ((fault_injection_hook_ && fault_injection_hook_("read-all-exclusive-truncate")) ||
         !TruncateAppendHandle(complete_prefix_bytes)))
    {
        inspected.status = ReadStatus::IoError;
        inspected.records.clear();
        (void)CloseAppendFileHandle();
        return inspected;
    }

    auto verified = ReadAllInternal(
        options_.path,
        options_.volume_identity,
        false,
        nullptr);
    if ((fault_injection_hook_ && fault_injection_hook_("read-all-exclusive-revalidate")) ||
        verified.status != ReadStatus::Ok || verified.recovered_torn_tail)
    {
        verified.status = ReadStatus::IoError;
        verified.records.clear();
        (void)CloseAppendFileHandle();
        return verified;
    }
    verified.recovered_torn_tail = inspected.recovered_torn_tail;
    return verified;
}

WriteAheadLog::Counters WriteAheadLog::SnapshotCounters() const
{
    std::lock_guard<std::recursive_mutex> operation_lock(WalOperationMutex(options_.path));
    return {
        append_handle_open_count_,
        append_handle_flush_count_,
    };
}

bool WriteAheadLog::HasExclusiveWriterLease() const
{
    std::lock_guard<std::recursive_mutex> operation_lock(WalOperationMutex(options_.path));
    return writer_lease_handle_ != nullptr;
}

std::uint64_t WriteAheadLog::ExclusiveWriterLeaseGeneration() const
{
    std::lock_guard<std::recursive_mutex> operation_lock(WalOperationMutex(options_.path));
    return writer_lease_handle_ == nullptr ? 0 : writer_lease_generation_;
}

void WriteAheadLog::SetFaultInjectionHook(FaultInjectionHook hook)
{
    fault_injection_hook_ = std::move(hook);
}

WriteAheadLog::ReadResult WriteAheadLog::ReadAll(
    const std::filesystem::path& path,
    const std::string& expected_volume_identity)
{
    std::lock_guard<std::recursive_mutex> operation_lock(WalOperationMutex(path));
    return ReadAllInternal(path, expected_volume_identity, false, nullptr);
}

WriteAheadLog::ReadResult WriteAheadLog::ReadAllInternal(
    const std::filesystem::path& path,
    const std::string& expected_volume_identity,
    bool repair_torn_tail,
    std::uint64_t* complete_prefix_bytes)
{
    ReadResult result{};
    if (complete_prefix_bytes)
    {
        *complete_prefix_bytes = 0;
    }
    if (path.empty() || !std::filesystem::exists(path))
    {
        return result;
    }

    std::vector<std::uint8_t> bytes;
    if (!ReadFileBytes(path, bytes))
    {
        result.status = ReadStatus::IoError;
        return result;
    }

    std::size_t cursor = 0;
    while (cursor < bytes.size())
    {
        if (bytes.size() - cursor < kLegacyHeaderSize)
        {
            result.recovered_torn_tail = true;
            if (complete_prefix_bytes)
            {
                *complete_prefix_bytes = static_cast<std::uint64_t>(cursor);
            }
            if (repair_torn_tail && !TruncateTornTail(path, cursor))
            {
                result.status = ReadStatus::IoError;
            }
            return result;
        }

        const auto magic = ReadU32(bytes, cursor);
        const auto version = ReadU16(bytes, cursor + 4);
        const auto header_size = ReadU16(bytes, cursor + 6);
        const auto record_size = ReadU32(bytes, cursor + 8);

        if (magic != kMagic)
        {
            result.status = ReadStatus::Corrupt;
            return result;
        }
        if (version != kLegacyVersion && version != kInlinePayloadVersion)
        {
            result.status = ReadStatus::VersionMismatch;
            return result;
        }
        const auto expected_header_size = version == kInlinePayloadVersion
            ? kInlinePayloadHeaderSize
            : kLegacyHeaderSize;
        if (header_size != expected_header_size ||
            record_size < expected_header_size ||
            record_size > kMaxRecordBytes)
        {
            result.status = ReadStatus::Corrupt;
            return result;
        }
        if (bytes.size() - cursor < record_size)
        {
            result.recovered_torn_tail = true;
            if (complete_prefix_bytes)
            {
                *complete_prefix_bytes = static_cast<std::uint64_t>(cursor);
            }
            if (repair_torn_tail && !TruncateTornTail(path, cursor))
            {
                result.status = ReadStatus::IoError;
            }
            return result;
        }

        Record record{};
        ReadStatus record_status = ReadStatus::Ok;
        if (!DecodeRecord(bytes, cursor, record_size, version, expected_volume_identity, record, record_status))
        {
            result.status = record_status;
            return result;
        }

        result.records.push_back(std::move(record));
        cursor += record_size;
    }

    if (complete_prefix_bytes)
    {
        *complete_prefix_bytes = static_cast<std::uint64_t>(cursor);
    }

    return result;
}

std::vector<std::uint8_t> WriteAheadLog::EncodeForTest(
    const Record& record,
    std::uint16_t version_override)
{
    std::vector<std::uint8_t> buffer;
    const auto version = version_override == 0
        ? (record.inline_payload.empty() ? kLegacyVersion : kInlinePayloadVersion)
        : version_override;
    if ((!record.inline_payload.empty() && version != kInlinePayloadVersion) ||
        !InlinePayloadIsConsistentImpl(record))
    {
        return {};
    }
    const auto header_size = version == kInlinePayloadVersion
        ? kInlinePayloadHeaderSize
        : kLegacyHeaderSize;
    const auto record_size =
        static_cast<std::uint64_t>(header_size) +
        record.path_utf8.size() +
        record.secondary_path_utf8.size() +
        record.volume_identity.size() +
        record.inline_payload.size();
    if (record_size > (std::numeric_limits<std::uint32_t>::max)())
    {
        return {};
    }

    buffer.reserve(static_cast<std::size_t>(record_size));
    AppendU32(buffer, kMagic);
    AppendU16(buffer, version);
    AppendU16(buffer, header_size);
    AppendU32(buffer, static_cast<std::uint32_t>(record_size));
    AppendU32(buffer, 0);
    AppendU64(buffer, record.transaction_id);
    AppendU64(buffer, record.sequence);
    AppendU32(buffer, static_cast<std::uint32_t>(record.operation));
    AppendU32(buffer, static_cast<std::uint32_t>(record.state));
    AppendU64(buffer, record.object_id);
    AppendU64(buffer, record.parent_object_id);
    AppendU64(buffer, record.payload_spool_id);
    AppendU64(buffer, record.payload_offset);
    AppendU64(buffer, record.payload_length);
    AppendU64(buffer, record.logical_offset);
    AppendU64(buffer, record.logical_length);
    AppendU64(buffer, record.flags);
    AppendU32(buffer, static_cast<std::uint32_t>(record.path_utf8.size()));
    AppendU32(buffer, static_cast<std::uint32_t>(record.secondary_path_utf8.size()));
    AppendU32(buffer, static_cast<std::uint32_t>(record.volume_identity.size()));
    if (version == kInlinePayloadVersion)
    {
        AppendU32(buffer, static_cast<std::uint32_t>(record.inline_payload.size()));
    }
    buffer.insert(buffer.end(), record.payload_sha256.begin(), record.payload_sha256.end());
    buffer.insert(buffer.end(), record.path_utf8.begin(), record.path_utf8.end());
    buffer.insert(buffer.end(), record.secondary_path_utf8.begin(), record.secondary_path_utf8.end());
    buffer.insert(buffer.end(), record.volume_identity.begin(), record.volume_identity.end());
    if (!record.inline_payload.empty())
    {
        buffer.insert(
            buffer.end(),
            reinterpret_cast<const std::uint8_t*>(record.inline_payload.data()),
            reinterpret_cast<const std::uint8_t*>(record.inline_payload.data() + record.inline_payload.size()));
    }

    StoreU32(buffer, kChecksumOffset, ChecksumRecord(buffer));
    return buffer;
}

bool WriteAheadLog::InlinePayloadIsConsistent(const Record& record)
{
    return InlinePayloadIsConsistentImpl(record);
}
} // namespace apfsaccess::rw
