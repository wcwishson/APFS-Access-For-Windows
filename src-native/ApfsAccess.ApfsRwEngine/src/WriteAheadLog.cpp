#include "WriteAheadLog.h"
#include "FusionOriginalContinuation.h"
#include "InodeMetadataPatch.h"
#include "CompressionRewrite.h"
#include "NativeClone.h"
#include "NativeHardLink.h"
#include "NativeSparse.h"
#include "NativeSparseV2.h"
#include "NativeCloneRange.h"
#include "NativeVolumeRename.h"
#include "NativeSnapshotIntent.h"
#include "NativeCountRepair.h"
#include "ProtectedJournalEpoch.h"

#include <algorithm>
#include <atomic>
#include <cstring>
#include <exception>
#include <fstream>
#include <iterator>
#include <limits>
#include <mutex>
#include <new>
#include <span>
#include <stdexcept>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <windows.h>
#include <bcrypt.h>

#undef CreateFile
#undef CreateDirectory

#pragma comment(lib, "bcrypt.lib")

namespace apfsaccess::rw
{
namespace
{
constexpr std::uint32_t kMagic = 0x574C4141; // AALW, little-endian on disk.
constexpr std::uint16_t kLegacyVersion = 1;
constexpr std::uint16_t kInlinePayloadVersion = 2;
constexpr std::uint16_t kUnlinkOutcomeVersion = 3;
constexpr std::uint16_t kLegacyHeaderSize = 148;
constexpr std::uint16_t kInlinePayloadHeaderSize = 152;
constexpr std::uint16_t kUnlinkOutcomeHeaderSize = 192;
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

template<class Buffer> void AppendU16(Buffer& buffer, std::uint16_t value)
{
    buffer.push_back(static_cast<std::uint8_t>(value & 0xffu));
    buffer.push_back(static_cast<std::uint8_t>((value >> 8u) & 0xffu));
}

template<class Buffer> void AppendU32(Buffer& buffer, std::uint32_t value)
{
    for (int shift = 0; shift < 32; shift += 8)
    {
        buffer.push_back(static_cast<std::uint8_t>((value >> shift) & 0xffu));
    }
}

template<class Buffer> void AppendU64(Buffer& buffer, std::uint64_t value)
{
    for (int shift = 0; shift < 64; shift += 8)
    {
        buffer.push_back(static_cast<std::uint8_t>((value >> shift) & 0xffu));
    }
}

std::uint16_t ReadU16(std::span<const std::uint8_t> buffer, std::size_t offset)
{
    return static_cast<std::uint16_t>(
        buffer[offset] |
        (static_cast<std::uint16_t>(buffer[offset + 1]) << 8u));
}

std::uint32_t ReadU32(std::span<const std::uint8_t> buffer, std::size_t offset)
{
    std::uint32_t value = 0;
    for (int shift = 0; shift < 32; shift += 8)
    {
        value |= static_cast<std::uint32_t>(buffer[offset++]) << shift;
    }
    return value;
}

std::uint64_t ReadU64(std::span<const std::uint8_t> buffer, std::size_t offset)
{
    std::uint64_t value = 0;
    for (int shift = 0; shift < 64; shift += 8)
    {
        value |= static_cast<std::uint64_t>(buffer[offset++]) << shift;
    }
    return value;
}

template<class Buffer> std::uint32_t ChecksumRecord(const Buffer& buffer)
{
    std::uint32_t hash = 2166136261u;
    for (std::size_t i = 0; i < buffer.size(); ++i)
    {
        const auto byte = buffer.size() >= 16 && i >= 12 && i < 16 ? std::uint8_t{0} : buffer[i];
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

bool IsStrictUtf8(std::string_view value)
{
    if (value.empty() || value.size() > static_cast<std::size_t>((std::numeric_limits<int>::max)()))
    {
        return false;
    }
    return MultiByteToWideChar(
        CP_UTF8,
        MB_ERR_INVALID_CHARS,
        value.data(),
        static_cast<int>(value.size()),
        nullptr,
        0) > 0;
}

bool InlinePayloadIsConsistentImpl(const WriteAheadLog::Record& record)
{
    if (record.operation == WriteAheadLog::OperationKind::CloneRange)
        return NativeCloneRangeWalIsConsistent(record) && IsStrictUtf8(record.path_utf8) && IsStrictUtf8(record.secondary_path_utf8);
    if (record.operation == WriteAheadLog::OperationKind::NativeSparse)
        return (NativeSparseWalIsConsistent(record) || NativeSparseV2WalIsConsistent(record)) && IsStrictUtf8(record.path_utf8);
    if (record.operation == WriteAheadLog::OperationKind::HardLink)
        return NativeHardLinkWalIsConsistent(record) &&
            IsStrictUtf8(record.path_utf8) && IsStrictUtf8(record.secondary_path_utf8);
    if (record.operation == WriteAheadLog::OperationKind::CreateSnapshot || record.operation == WriteAheadLog::OperationKind::DeleteSnapshot)
    {
        NativeSnapshotIntent intent; std::array<std::uint8_t,32> digest{};
        return DecodeNativeSnapshotIntent(record.inline_payload, intent) &&
            (!intent.raw_receipt || record.volume_identity == intent.raw_receipt->selected_journal_identity) &&
            intent.create == (record.operation == WriteAheadLog::OperationKind::CreateSnapshot) &&
            record.object_id == intent.scope.volume_oid && record.parent_object_id == intent.scope.checkpoint_xid + 1 &&
            record.payload_length == record.inline_payload.size() && record.path_utf8 == "\\" &&
            record.secondary_path_utf8.empty() && !record.flags && !record.unlink_outcome &&
            !record.logical_offset && !record.logical_length && !record.payload_offset && !record.payload_spool_id &&
            ComputeSha256(record.inline_payload,digest) && digest == record.payload_sha256;
    }
    if (record.operation == WriteAheadLog::OperationKind::RepairVolumeFileCount)
    {
        NativeCountRepair repair;
        std::array<std::uint8_t, 32> digest{};
        return DecodeNativeCountRepair(record.inline_payload, repair) &&
            record.volume_identity == CountRepairJournalIdentity(repair) &&
            record.object_id == repair.volume && record.parent_object_id == repair.checkpoint + 1 &&
            record.payload_length == record.inline_payload.size() && record.path_utf8 == "\\" &&
            record.secondary_path_utf8.empty() && !record.flags && !record.unlink_outcome &&
            !record.logical_offset && !record.logical_length && !record.payload_offset && !record.payload_spool_id &&
            ComputeSha256(record.inline_payload, digest) && digest == record.payload_sha256;
    }
    if (record.operation == WriteAheadLog::OperationKind::SetVolumeQuotaReserve)
    {
        NativeVolumeQuotaReserve rename;
        std::array<std::uint8_t, 32> digest{};
        return DecodeNativeVolumeQuotaReserve(record.inline_payload, rename) &&
            record.object_id == rename.volume && record.parent_object_id == rename.checkpoint + 1 &&
            record.payload_length == record.inline_payload.size() && record.path_utf8 == "\\" &&
            record.secondary_path_utf8.empty() && !record.flags && !record.unlink_outcome &&
            !record.logical_offset && !record.logical_length && !record.payload_offset && !record.payload_spool_id &&
            ComputeSha256(record.inline_payload, digest) && digest == record.payload_sha256;
    }
    if (record.operation == WriteAheadLog::OperationKind::RenameVolume)
    {
        NativeVolumeRename rename;
        std::array<std::uint8_t, 32> digest{};
        return DecodeNativeVolumeRename(record.inline_payload, rename) &&
            record.object_id == rename.volume && record.parent_object_id == rename.checkpoint + 1 &&
            record.payload_length == record.inline_payload.size() && record.path_utf8 == "\\" &&
            record.secondary_path_utf8.empty() && !record.flags && !record.unlink_outcome &&
            !record.logical_offset && !record.logical_length && !record.payload_offset && !record.payload_spool_id &&
            ComputeSha256(record.inline_payload, digest) && digest == record.payload_sha256;
    }
    if (record.operation == WriteAheadLog::OperationKind::CloneFile)
    {
        NativeCloneProof p; std::array<std::uint8_t,32> digest{};
        return DecodeNativeClone(record.inline_payload,p) && record.object_id==p.target &&
            record.parent_object_id==p.checkpoint+1 && record.payload_length==record.inline_payload.size() &&
            IsStrictUtf8(record.path_utf8) && IsStrictUtf8(record.secondary_path_utf8) &&
            record.path_utf8.find('\0')==std::string::npos && record.secondary_path_utf8.find('\0')==std::string::npos &&
            record.path_utf8!=record.secondary_path_utf8 && !record.flags && !record.unlink_outcome &&
            !record.logical_offset && !record.logical_length && !record.payload_offset && !record.payload_spool_id &&
            ComputeSha256(record.inline_payload,digest) && digest==record.payload_sha256;
    }
    if (record.operation == WriteAheadLog::OperationKind::RewriteCompressedContent)
    {
        CompressionRewrite proof;
        std::array<std::uint8_t, WriteAheadLog::PayloadHashSize> digest{};
        return DecodeCompressionRewrite(record.inline_payload, proof) &&
            record.object_id == proof.object && record.parent_object_id == proof.generation &&
            record.payload_length == record.inline_payload.size() &&
            !record.path_utf8.empty() && IsStrictUtf8(record.path_utf8) &&
            record.path_utf8.find('\0') == std::string::npos && record.secondary_path_utf8.empty() &&
            record.flags == 0 && !record.unlink_outcome && record.logical_offset == 0 &&
            record.logical_length == 0 && record.payload_offset == 0 && record.payload_spool_id == 0 &&
            ComputeSha256(record.inline_payload, digest) && digest == record.payload_sha256;
    }
    if (record.operation == WriteAheadLog::OperationKind::SetInodeMetadata)
    {
        InodeMetadataPatch patch{};
        std::array<std::uint8_t, WriteAheadLog::PayloadHashSize> digest{};
        return record.payload_length == record.inline_payload.size() &&
            DecodeInodeMetadataPatch(record.inline_payload, patch) &&
            ComputeSha256(record.inline_payload, digest) && digest == record.payload_sha256;
    }
    if (record.operation == WriteAheadLog::OperationKind::SetExtendedAttribute)
    {
        if (record.inline_payload.size() > WriteAheadLog::MaxExtendedAttributePayloadBytes ||
            record.payload_length != record.inline_payload.size())
        {
            return false;
        }

        std::array<std::uint8_t, WriteAheadLog::PayloadHashSize> digest{};
        return ComputeSha256(record.inline_payload, digest) && digest == record.payload_sha256;
    }
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

bool IsKnownOperation(WriteAheadLog::OperationKind operation)
{
    switch (operation)
    {
    case WriteAheadLog::OperationKind::CreateFile:
    case WriteAheadLog::OperationKind::CreateDirectory:
    case WriteAheadLog::OperationKind::Write:
    case WriteAheadLog::OperationKind::SetFileSize:
    case WriteAheadLog::OperationKind::Rename:
    case WriteAheadLog::OperationKind::Delete:
    case WriteAheadLog::OperationKind::SetBasicInfo:
    case WriteAheadLog::OperationKind::SetSymbolicLinkTarget:
    case WriteAheadLog::OperationKind::RemoveSymbolicLinkTarget:
    case WriteAheadLog::OperationKind::SetExtendedAttribute:
    case WriteAheadLog::OperationKind::RemoveExtendedAttribute:
    case WriteAheadLog::OperationKind::SetInodeMetadata:
    case WriteAheadLog::OperationKind::SetAllocationSize:
    case WriteAheadLog::OperationKind::RestoreDirectoryFromSymbolicLink:
    case WriteAheadLog::OperationKind::CloneFile:
    case WriteAheadLog::OperationKind::HardLink:
    case WriteAheadLog::OperationKind::NativeSparse:
    case WriteAheadLog::OperationKind::CloneRange:
    case WriteAheadLog::OperationKind::CreateSnapshot:
    case WriteAheadLog::OperationKind::DeleteSnapshot:
    case WriteAheadLog::OperationKind::SetVolumeQuotaReserve:
    case WriteAheadLog::OperationKind::RenameVolume:
    case WriteAheadLog::OperationKind::RepairVolumeFileCount:
    case WriteAheadLog::OperationKind::RewriteCompressedContent:
    case WriteAheadLog::OperationKind::TransactionMarker:
    case WriteAheadLog::OperationKind::CompactionIndex:
    case WriteAheadLog::OperationKind::DurabilityWatermark:
        return true;
    default:
        return false;
    }
}

bool ExtendedAttributeMutationIsConsistentImpl(const WriteAheadLog::Record& record)
{
    const bool set = record.operation == WriteAheadLog::OperationKind::SetExtendedAttribute;
    const bool remove = record.operation == WriteAheadLog::OperationKind::RemoveExtendedAttribute;
    if (!set && !remove)
    {
        return true;
    }

    const bool has_valid_name = !record.secondary_path_utf8.empty() &&
        record.secondary_path_utf8.size() <= WriteAheadLog::MaxExtendedAttributeNameBytes &&
        record.secondary_path_utf8.find('\0') == std::string::npos &&
        IsStrictUtf8(record.secondary_path_utf8);
    const bool has_valid_identity = record.object_id != 0 &&
        record.parent_object_id != 0 &&
        !record.path_utf8.empty() &&
        record.path_utf8.find('\0') == std::string::npos &&
        IsStrictUtf8(record.path_utf8);
    if (!has_valid_name || !has_valid_identity || record.unlink_outcome || record.flags != 0 ||
        record.payload_spool_id != 0 || record.payload_offset != 0 ||
        record.logical_offset != 0 || record.logical_length != 0)
    {
        return false;
    }

    if (set)
    {
        return InlinePayloadIsConsistentImpl(record);
    }

    return record.payload_length == 0 && record.inline_payload.empty() &&
        std::all_of(
            record.payload_sha256.begin(),
            record.payload_sha256.end(),
            [](std::uint8_t byte) { return byte == 0; });
}

bool AllocationSizeMutationIsConsistentImpl(const WriteAheadLog::Record& record)
{
    if (record.operation != WriteAheadLog::OperationKind::SetAllocationSize) return true;
    return record.object_id != 0 && record.parent_object_id != 0 &&
        record.logical_length <= static_cast<std::uint64_t>((std::numeric_limits<std::int64_t>::max)()) &&
        !record.path_utf8.empty() && IsStrictUtf8(record.path_utf8) &&
        record.path_utf8.find('\0') == std::string::npos &&
        record.secondary_path_utf8.empty() && !record.unlink_outcome && record.flags == 0 &&
        record.logical_offset == 0 && record.payload_spool_id == 0 &&
        record.payload_offset == 0 && record.payload_length == 0 && record.inline_payload.empty() &&
        std::all_of(record.payload_sha256.begin(), record.payload_sha256.end(),
            [](std::uint8_t byte) { return byte == 0; });
}

bool DirectoryRestoreMutationIsConsistentImpl(const WriteAheadLog::Record& record)
{
    if (record.operation != WriteAheadLog::OperationKind::RestoreDirectoryFromSymbolicLink) return true;
    return record.object_id != 0 && record.parent_object_id != 0 &&
        IsStrictUtf8(record.path_utf8) && record.path_utf8.find('\0') == std::string::npos &&
        record.secondary_path_utf8.empty() && !record.unlink_outcome && record.flags == 0 &&
        record.logical_offset == 0 && record.logical_length == 0 &&
        record.payload_spool_id == 0 && record.payload_offset == 0 && record.payload_length == 0 &&
        record.inline_payload.empty() &&
        std::all_of(record.payload_sha256.begin(), record.payload_sha256.end(),
            [](std::uint8_t byte) { return byte == 0; });
}

bool InodeMetadataMutationIsConsistentImpl(const WriteAheadLog::Record& record)
{
    if (record.operation != WriteAheadLog::OperationKind::SetInodeMetadata) return true;
    return record.object_id != 0 && record.parent_object_id != 0 &&
        IsStrictUtf8(record.path_utf8) && record.path_utf8.find('\0') == std::string::npos &&
        record.secondary_path_utf8.empty() && !record.unlink_outcome && record.flags == 0 &&
        record.payload_spool_id == 0 && record.payload_offset == 0 &&
        record.logical_offset == 0 && record.logical_length == 0 &&
        InlinePayloadIsConsistentImpl(record);
}

bool UnlinkOutcomeIsConsistentImpl(const WriteAheadLog::Record& record)
{
    if (!record.unlink_outcome) return true;
    const auto& outcome = *record.unlink_outcome;
    return record.operation == WriteAheadLog::OperationKind::Delete &&
        outcome.object_id != 0 && outcome.object_id == record.object_id &&
        outcome.generation_before != 0 && outcome.generation_before == record.parent_object_id &&
        outcome.generation_after >= outcome.generation_before && outcome.parent_object_id != 0 &&
        outcome.links_before != 0 && outcome.links_after == outcome.links_before - 1 &&
        outcome.path_utf8 == record.path_utf8 && outcome.path_utf8.size() > 1 &&
        outcome.path_utf8.size() <= 65536 && outcome.path_utf8.front() == '\\' &&
        outcome.path_utf8.find('\0') == std::string::npos &&
        record.secondary_path_utf8.empty() && record.inline_payload.empty() && record.flags == 0 &&
        record.payload_spool_id == 0 && record.payload_offset == 0 && record.payload_length == 0 &&
        record.logical_offset == 0 && record.logical_length == 0 &&
        std::all_of(record.payload_sha256.begin(), record.payload_sha256.end(),
            [](std::uint8_t byte) { return byte == 0; });
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

bool HasUnsupportedWalUncComponent(const std::filesystem::path& path)
{
    auto preferred = path;
    preferred.make_preferred();
    const auto& wide = preferred.native();
    if (!wide.starts_with(LR"(\\)") || wide.starts_with(LR"(\\?\)") ||
        wide.starts_with(LR"(\\.\)")) return false;
    for (const auto& component : preferred.relative_path())
    {
        if (component.has_root_path() || component.native().find(L':') != std::wstring::npos)
            return true;
    }
    return false;
}

std::filesystem::path NormalizeWalFilesystemPath(const std::filesystem::path& path)
{
    auto preferred = path;
    preferred.make_preferred();
    const auto& wide = preferred.native();
    if (!wide.starts_with(LR"(\\)") || wide.starts_with(LR"(\\?\)") ||
        wide.starts_with(LR"(\\.\)")) return path.lexically_normal();
    // Appending a drive-like UNC component can replace the accumulated path.
    if (HasUnsupportedWalUncComponent(preferred)) return path;

    const auto relative = preferred.relative_path();
    auto component = relative.begin();
    if (component == relative.end() || component->empty() || *component == L"." || *component == L"..")
        return path;
    const auto share = *component++;
    // C++ treats the share as relative; Win32's .. floor is server AND share.
    std::filesystem::path rooted_tail(L"\\");
    for (; component != relative.end(); ++component) rooted_tail /= *component;
    return preferred.root_path() / share / rooted_tail.lexically_normal().relative_path();
}

std::filesystem::path AbsoluteWalFilesystemPath(const std::filesystem::path& path, std::error_code& error)
{
    if (HasUnsupportedWalUncComponent(path))
    {
        error.clear();
        return path;
    }
    const auto absolute = std::filesystem::absolute(path, error);
    return error ? absolute : NormalizeWalFilesystemPath(absolute);
}

std::filesystem::path WalIoPath(const std::filesystem::path& path)
{
    if (HasUnsupportedWalUncComponent(path)) return path;
    const auto& original = path.native();
    if (original.size() < MAX_PATH - 12 || !path.is_absolute() ||
        original.starts_with(LR"(\\?\)") || original.starts_with(LR"(\\.\)") ||
        original.starts_with(LR"(\??\)")) return path;

    auto normalized = NormalizeWalFilesystemPath(path);
    normalized.make_preferred();
    const auto& wide = normalized.native();
    if (wide.starts_with(LR"(\\?\)") || wide.starts_with(LR"(\\.\)") ||
        wide.starts_with(LR"(\??\)")) return path;
    // Extended syntax must not turn Win32 trimmed/device names into different files.
    for (const auto& component : normalized.relative_path())
    {
        const auto name = component.wstring();
        if (name.empty()) continue;
        if (name.back() == L'.' || name.back() == L' ' || name.find(L':') != std::wstring::npos)
            return path;
        auto base = name.substr(0, name.find(L'.'));
        while (!base.empty() && base.back() == L' ') base.pop_back();
        if (_wcsicmp(base.c_str(), L"CON") == 0 || _wcsicmp(base.c_str(), L"PRN") == 0 ||
            _wcsicmp(base.c_str(), L"AUX") == 0 || _wcsicmp(base.c_str(), L"NUL") == 0 ||
            (base.size() == 4 &&
             (_wcsnicmp(base.c_str(), L"COM", 3) == 0 || _wcsnicmp(base.c_str(), L"LPT", 3) == 0) &&
             ((base[3] >= L'1' && base[3] <= L'9') || base[3] == 0xb9 || base[3] == 0xb2 || base[3] == 0xb3)))
            return path;
    }
    if (wide.size() >= 3 && wide[1] == L':' && wide[2] == L'\\')
        return std::filesystem::path(LR"(\\?\)" + wide);
    if (wide.starts_with(LR"(\\)"))
        return std::filesystem::path(LR"(\\?\UNC\)" + wide.substr(2));
    return path;
}

HANDLE OpenWalFile(const std::filesystem::path& path, DWORD access, DWORD sharing,
    LPSECURITY_ATTRIBUTES security, DWORD disposition, DWORD attributes, HANDLE template_file)
{
    return CreateFileW(WalIoPath(path).c_str(), access, sharing, security, disposition, attributes, template_file);
}

DWORD WalFileAttributes(const std::filesystem::path& path)
{
    return GetFileAttributesW(WalIoPath(path).c_str());
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
    const auto absolute_path = AbsoluteWalFilesystemPath(path, ec);
    if (ec || absolute_path.parent_path().empty())
    {
        return false;
    }

    const auto parent_wide = absolute_path.parent_path().wstring();
    auto* directory = OpenWalFile(
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
    const auto attributes = WalFileAttributes(path.wstring().c_str());
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
    auto* handle = OpenWalFile(
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

std::wstring WalRenameDestinationPath(const std::filesystem::path& destination)
{
    std::error_code ec;
    auto absolute_destination = AbsoluteWalFilesystemPath(destination, ec);
    if (ec)
    {
        return {};
    }
    auto destination_wide = WalIoPath(absolute_destination).wstring();
    if (destination_wide.starts_with(LR"(\\?\)"))
    {
        destination_wide.replace(0, 4, LR"(\??\)");
    }
    else if (destination_wide.starts_with(LR"(\\)"))
    {
        destination_wide = LR"(\??\UNC\)" + destination_wide.substr(2);
    }
    else if (!destination_wide.starts_with(LR"(\??\)"))
    {
        destination_wide.insert(0, LR"(\??\)");
    }
    return destination_wide;
}

bool RenameOpenedFileWithoutReplacing(
    HANDLE source_handle,
    const std::filesystem::path& destination)
{
    if (source_handle == nullptr || source_handle == INVALID_HANDLE_VALUE)
    {
        return false;
    }
    const auto destination_wide = WalRenameDestinationPath(destination);
    if (destination_wide.empty()) return false;
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
    handle = OpenWalFile(
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
    handle = OpenWalFile(
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

template<class Buffer> void StoreU32(Buffer& buffer, std::size_t offset, std::uint32_t value)
{
    for (int shift = 0; shift < 32; shift += 8)
    {
        buffer[offset++] = static_cast<std::uint8_t>((value >> shift) & 0xffu);
    }
}

bool FlushPathToDisk(const std::filesystem::path& path)
{
    const auto wide_path = path.wstring();
    HANDLE handle = OpenWalFile(
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

bool ReadFileBytes(const std::filesystem::path& path, std::vector<std::uint8_t>& bytes,
    std::uint64_t limit, bool& limited)
{
    limited = false;
    bytes.clear();
    std::ifstream input(WalIoPath(path), std::ios::binary);
    if (!input.good())
    {
        return false;
    }

    if (limit != UINT64_MAX)
    {
        input.seekg(0, std::ios::end);
        const auto length = input.tellg();
        if (length < 0) return false;
        const auto size = static_cast<std::uint64_t>(length);
        if (size > limit || size > SIZE_MAX || size > static_cast<std::uint64_t>((std::numeric_limits<std::streamsize>::max)()))
        { limited = true; return false; }
        input.seekg(0, std::ios::beg);
        bytes.resize(static_cast<std::size_t>(size));
        if (size) input.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(size));
        if (!input.good() || input.peek() != std::char_traits<char>::eof()) { bytes.clear(); return false; }
        return true;
    }
    bytes.assign(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
    return input.good() || input.eof();
}

bool ReadPinnedIntentBytes(HANDLE handle, std::vector<std::uint8_t>& bytes,
    std::optional<std::uint64_t> expected_size = {})
{
    LARGE_INTEGER size{};
    LARGE_INTEGER original_position{};
    LARGE_INTEGER zero{};
    if (handle == nullptr ||
        handle == INVALID_HANDLE_VALUE ||
        GetFileSizeEx(handle, &size) == FALSE ||
        size.QuadPart < 0 ||
        static_cast<std::uint64_t>(size.QuadPart) > kMaxRecordBytes ||
        (expected_size && static_cast<std::uint64_t>(size.QuadPart) != *expected_size))
    {
        return false;
    }

    bytes.resize(static_cast<std::size_t>(size.QuadPart));
    if (SetFilePointerEx(handle, zero, &original_position, FILE_CURRENT) == FALSE ||
        SetFilePointerEx(handle, zero, nullptr, FILE_BEGIN) == FALSE) return false;
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
    std::filesystem::resize_file(WalIoPath(path), complete_prefix_bytes, ec);
    return !ec && FlushPathToDisk(path);
}

bool DecodeRecord(
    std::span<const std::uint8_t> bytes,
    std::size_t offset,
    std::size_t record_size,
    std::uint16_t version,
    const std::string& expected_volume_identity,
    WriteAheadLog::Record& record,
    WriteAheadLog::ReadStatus& status)
{
    const auto record_bytes = bytes.subspan(offset, record_size);

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
    std::uint32_t unlink_path_length = 0;
    record.unlink_outcome.reset();
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
    else if (version == kUnlinkOutcomeVersion)
    {
        auto& outcome = record.unlink_outcome.emplace();
        outcome.object_id = ReadU64(record_bytes, cursor); cursor += 8;
        outcome.generation_before = ReadU64(record_bytes, cursor); cursor += 8;
        outcome.generation_after = ReadU64(record_bytes, cursor); cursor += 8;
        outcome.parent_object_id = ReadU64(record_bytes, cursor); cursor += 8;
        outcome.links_before = ReadU32(record_bytes, cursor); cursor += 4;
        outcome.links_after = ReadU32(record_bytes, cursor); cursor += 4;
        unlink_path_length = ReadU32(record_bytes, cursor); cursor += 4;
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
        static_cast<std::uint64_t>(inline_payload_length) +
        static_cast<std::uint64_t>(unlink_path_length);
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
    cursor += inline_payload_length;
    if (record.unlink_outcome)
    {
        record.unlink_outcome->path_utf8.assign(
            reinterpret_cast<const char*>(record_bytes.data() + cursor), unlink_path_length);
    }

    const bool extended_attribute_version_is_valid =
        (record.operation != WriteAheadLog::OperationKind::SetExtendedAttribute ||
            version == kInlinePayloadVersion) &&
        (record.operation != WriteAheadLog::OperationKind::RemoveExtendedAttribute ||
            version == kLegacyVersion);
    if (!IsKnownOperation(record.operation) || !extended_attribute_version_is_valid ||
        ((record.operation == WriteAheadLog::OperationKind::RewriteCompressedContent || record.operation == WriteAheadLog::OperationKind::CloneFile || record.operation == WriteAheadLog::OperationKind::HardLink || record.operation == WriteAheadLog::OperationKind::NativeSparse || record.operation == WriteAheadLog::OperationKind::CloneRange || record.operation == WriteAheadLog::OperationKind::SetVolumeQuotaReserve || record.operation == WriteAheadLog::OperationKind::RenameVolume || record.operation == WriteAheadLog::OperationKind::CreateSnapshot || record.operation == WriteAheadLog::OperationKind::DeleteSnapshot || record.operation == WriteAheadLog::OperationKind::RepairVolumeFileCount) && version != kInlinePayloadVersion) ||
        (record.operation == WriteAheadLog::OperationKind::SetInodeMetadata && version != kInlinePayloadVersion) ||
        !InlinePayloadIsConsistentImpl(record) ||
        !ExtendedAttributeMutationIsConsistentImpl(record) ||
        !InodeMetadataMutationIsConsistentImpl(record) ||
        !AllocationSizeMutationIsConsistentImpl(record) ||
        !DirectoryRestoreMutationIsConsistentImpl(record) ||
        !UnlinkOutcomeIsConsistentImpl(record))
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

bool IsProtectedWalPrefix(std::span<const std::uint8_t> bytes)
{
    constexpr std::string_view magic = "\xe4" "APFSWAL";
    const auto prefix = (std::min)(magic.size(), bytes.size());
    return prefix && std::memcmp(bytes.data(), magic.data(), prefix) == 0;
}

struct WalFrameHeader
{
    std::uint16_t version = 0;
    std::uint32_t bytes = 0;
};

WriteAheadLog::ReadStatus DecodeWalFrameHeader(
    std::span<const std::uint8_t> bytes, WalFrameHeader& frame)
{
    using Status = WriteAheadLog::ReadStatus;
    if (bytes.size() < 12 || ReadU32(bytes, 0) != kMagic) return Status::Corrupt;
    frame.version = ReadU16(bytes, 4);
    if (frame.version != kLegacyVersion && frame.version != kInlinePayloadVersion &&
        frame.version != kUnlinkOutcomeVersion) return Status::VersionMismatch;
    const auto expected = frame.version == kUnlinkOutcomeVersion ? kUnlinkOutcomeHeaderSize :
        frame.version == kInlinePayloadVersion ? kInlinePayloadHeaderSize : kLegacyHeaderSize;
    frame.bytes = ReadU32(bytes, 8);
    return ReadU16(bytes, 6) == expected && frame.bytes >= expected && frame.bytes <= kMaxRecordBytes
        ? Status::Ok : Status::Corrupt;
}

WriteAheadLog::ReadResult DecodeWalBytes(
    const std::vector<std::uint8_t>& bytes,
    const std::string& expected_volume_identity,
    std::uint64_t* complete_prefix_bytes,
    WalReadLimits limits = {},
    std::optional<std::size_t> evidence_record_count = {})
{
    WriteAheadLog::ReadResult result{};
    if (complete_prefix_bytes != nullptr)
    {
        *complete_prefix_bytes = 0;
    }
    if (bytes.size() > limits.bytes)
    {
        result.status = WriteAheadLog::ReadStatus::ResourceLimit;
        return result;
    }
    // A bounded held-handle framing pass supplies the exact reservation. Legacy
    // readers keep their existing incremental allocation and torn-tail behavior.
    if (evidence_record_count)
    {
        if (*evidence_record_count > limits.records)
        {
            result.status = WriteAheadLog::ReadStatus::ResourceLimit;
            return result;
        }
        result.records.reserve(*evidence_record_count);
    }

    std::size_t cursor = 0;
    while (cursor < bytes.size())
    {
        // A protected anchor is shorter than a legacy header. Detect its domain
        // BEFORE legacy torn-tail handling, including a partially written magic.
        if (IsProtectedWalPrefix(std::span(bytes).subspan(cursor)))
        {
            result.status = WriteAheadLog::ReadStatus::VersionMismatch;
            result.records.clear();
            return result;
        }
        if (result.records.size() >= evidence_record_count.value_or(limits.records))
        {
            result.records.clear();
            result.status = WriteAheadLog::ReadStatus::ResourceLimit;
            return result;
        }
        if (bytes.size() - cursor < kLegacyHeaderSize)
        {
            result.recovered_torn_tail = true;
            if (complete_prefix_bytes != nullptr)
            {
                *complete_prefix_bytes = static_cast<std::uint64_t>(cursor);
            }
            return result;
        }

        WalFrameHeader frame;
        const auto frame_status = DecodeWalFrameHeader(std::span(bytes).subspan(cursor, 12), frame);
        if (frame_status != WriteAheadLog::ReadStatus::Ok)
        {
            result.status = frame_status;
            return result;
        }
        if (bytes.size() - cursor < frame.bytes)
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
                frame.bytes,
                frame.version,
                expected_volume_identity,
                record,
                record_status))
        {
            result.status = record_status;
            return result;
        }
        result.records.push_back(std::move(record));
        cursor += frame.bytes;
    }

    if (evidence_record_count && result.records.size() != *evidence_record_count)
    {
        result.records.clear();
        result.status = WriteAheadLog::ReadStatus::Corrupt;
        return result;
    }
    if (complete_prefix_bytes != nullptr)
    {
        *complete_prefix_bytes = static_cast<std::uint64_t>(cursor);
    }
    return result;
}
namespace jc = apfsaccess::journal;
namespace cc = apfsaccess::crypto;
constexpr std::size_t kProtectedAnchorBytes = 104, kProtectedBatchRecords = 8;
constexpr std::array<std::uint8_t, 16> kProtectedWalHeader{0xe4, 'A', 'P', 'F', 'S', 'W', 'A', 'L', 1, 0, 0, 0, 16, 0, 0, 0};
constexpr std::string_view kProtectedAnchor = "WALROOT1";
struct ProtectedPosition
{
    std::uint64_t offset = 0, ordinal = 0, sequence = 0;
    std::array<std::uint8_t, 32> previous{};
};
cc::CryptoResult EncodeProtectedWalRecord(const WriteAheadLog::Record& record);
using ProtectedHead = WriteAheadLog::ProtectedHistoryHead;
struct ProtectedCheckpoint
{
    ProtectedHead previous;
    std::uint64_t floor = 0, retained = 0;
    std::array<std::uint8_t, 32> semantic{};
};
constexpr std::size_t kCheckpointPlainBytes = 112;
bool ProtectedHeadValid(const ProtectedHead& h, bool continued = false)
{
    return h.bytes >= kProtectedAnchorBytes && h.bytes <= (64ull << 20) && h.records <= 65536 &&
        h.last_sequence != UINT64_MAX && (h.records == 0 ? (continued || h.last_sequence == 0) : h.last_sequence != 0) &&
        std::any_of(h.sha256.begin(), h.sha256.end(), [](auto b) { return b != 0; });
}
bool ProtectedSemanticStart(std::array<std::uint8_t, 32>& digest)
{
    constexpr std::string_view domain = "APFS-WAL-RETAIN1";
    return ComputeSha256(std::as_bytes(std::span(domain.data(), domain.size())), digest);
}
bool ProtectedSemanticStep(std::array<std::uint8_t, 32>& digest, std::span<const std::byte> plain)
{
    std::array<std::uint8_t, 64> combined{};
    std::copy(digest.begin(), digest.end(), combined.begin());
    std::array<std::uint8_t, 32> part{};
    if (!ComputeSha256(plain, part)) return false;
    std::copy(part.begin(), part.end(), combined.begin() + 32);
    return ComputeSha256(std::as_bytes(std::span(combined)), digest);
}
void ProtectedPut64(std::span<std::byte> b, std::size_t at, std::uint64_t n)
{ for (unsigned i = 0; i < 8; ++i) b[at + i] = std::byte((n >> (i * 8)) & 255); }
bool ProtectedCheckpointDecode(std::span<const std::byte> b, ProtectedCheckpoint& c)
{
    if (b.size() != kCheckpointPlainBytes || std::memcmp(b.data(), "WALCP001", 8)) return false;
    const auto data = std::span(reinterpret_cast<const std::uint8_t*>(b.data()), b.size());
    std::memcpy(c.previous.sha256.data(), b.data() + 8, 32);
    c.previous.bytes = ReadU64(data, 40); c.previous.records = ReadU64(data, 48);
    c.previous.last_sequence = ReadU64(data, 56); c.floor = ReadU64(data, 64); c.retained = ReadU64(data, 72);
    std::memcpy(c.semantic.data(), b.data() + 80, 32);
    return ProtectedHeadValid(c.previous) && c.floor && c.floor <= c.previous.last_sequence + 1 &&
        c.retained <= c.previous.records && ((c.retained == 0) == (c.previous.records == 0));
}
std::array<std::byte, kCheckpointPlainBytes> ProtectedCheckpointEncode(const ProtectedCheckpoint& c)
{
    std::array<std::byte, kCheckpointPlainBytes> b{};
    std::memcpy(b.data(), "WALCP001", 8); std::memcpy(b.data() + 8, c.previous.sha256.data(), 32);
    ProtectedPut64(b, 40, c.previous.bytes); ProtectedPut64(b, 48, c.previous.records);
    ProtectedPut64(b, 56, c.previous.last_sequence); ProtectedPut64(b, 64, c.floor); ProtectedPut64(b, 72, c.retained);
    std::memcpy(b.data() + 80, c.semantic.data(), 32); return b;
}
void WipeRecord(WriteAheadLog::Record& r) noexcept
{
    const auto wipe = [](auto& b) { if (!b.empty()) SecureZeroMemory(b.data(), b.size() * sizeof(b[0])); b.clear(); };
    wipe(r.volume_identity); wipe(r.path_utf8); wipe(r.secondary_path_utf8); wipe(r.inline_payload);
    if (r.unlink_outcome) { wipe(r.unlink_outcome->path_utf8); r.unlink_outcome.reset(); }
    SecureZeroMemory(r.payload_sha256.data(), r.payload_sha256.size());
}
void WipeRecords(std::vector<WriteAheadLog::Record>& records) noexcept
{ for (auto& r : records) WipeRecord(r); records.clear(); }
struct ProtectedReadExceptionCleanup
{
    WriteAheadLog::ReadResult& result;
    int exceptions = std::uncaught_exceptions();
    ~ProtectedReadExceptionCleanup()
    { if (std::uncaught_exceptions() > exceptions) WipeRecords(result.records); }
};
struct ProtectedHandle
{
    HANDLE value = INVALID_HANDLE_VALUE;
    explicit ProtectedHandle(HANDLE h = INVALID_HANDLE_VALUE) noexcept : value(h) {}
    ~ProtectedHandle() { if (value != INVALID_HANDLE_VALUE) CloseHandle(value); }
    ProtectedHandle(const ProtectedHandle&) = delete;
    ProtectedHandle(ProtectedHandle&& h) noexcept : value(std::exchange(h.value, INVALID_HANDLE_VALUE)) {}
};
bool ProtectedPathSyntax(const std::filesystem::path& p)
{
    const auto s = p.wstring();
    if (s.size() < 4 || s.size() > 240 || !((s[0] >= L'A' && s[0] <= L'Z') || (s[0] >= L'a' && s[0] <= L'z')) ||
        s[1] != L':' || s[2] != L'\\' || s.back() == L'\\' || s.find_first_of(L":/*?\"<>|", 3) != s.npos) return false;
    for (auto c : s) if (c < 32) return false;
    for (std::size_t at = 3; at < s.size();)
    {
        auto end = s.find(L'\\', at); if (end == s.npos) end = s.size();
        const auto part = s.substr(at, end - at);
        if (part.empty() || part == L"." || part == L".." || part.back() == L'.' || part.back() == L' ') return false;
        const auto stem = part.substr(0, part.find(L'.'));
        const auto equal = [&](const wchar_t* reserved) {
            return CompareStringOrdinal(stem.c_str(), -1, reserved, -1, TRUE) == CSTR_EQUAL;
        };
        if (equal(L"CON") || equal(L"PRN") || equal(L"AUX") || equal(L"NUL") || equal(L"CONIN$") || equal(L"CONOUT$") ||
            (stem.size() == 4 && (CompareStringOrdinal(stem.data(), 3, L"COM", 3, TRUE) == CSTR_EQUAL ||
                CompareStringOrdinal(stem.data(), 3, L"LPT", 3, TRUE) == CSTR_EQUAL))) return false;
        at = end + 1;
    }
    return true;
}
bool ProtectedExactHandle(HANDLE h, const std::filesystem::path& path, bool directory)
{
    FILE_ATTRIBUTE_TAG_INFO info{};
    if (GetFileType(h) != FILE_TYPE_DISK || !GetFileInformationByHandleEx(h, FileAttributeTagInfo, &info, sizeof(info)) ||
        (info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) || ((info.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) != directory ||
        (!directory && !HasSinglePhysicalLink(h))) return false;
    wchar_t resolved[512]{};
    const auto n = GetFinalPathNameByHandleW(h, resolved, 512, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    const auto expected = L"\\\\?\\" + path.wstring();
    return n && n < 512 && CompareStringOrdinal(resolved, -1, expected.c_str(), -1, TRUE) == CSTR_EQUAL;
}
struct ProtectedPins
{
    std::vector<ProtectedHandle> handles;
    bool Pin(const std::filesystem::path& path)
    {
        if (!ProtectedPathSyntax(path)) return false;
        const auto text = path.wstring();
        if (GetDriveTypeW(text.substr(0, 3).c_str()) != DRIVE_FIXED) return false;
        for (std::size_t end = 2;;)
        {
            const auto prefix = text.substr(0, end == 2 ? 3 : end);
            ProtectedHandle h(CreateFileW(prefix.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
            if (h.value == INVALID_HANDLE_VALUE || !ProtectedExactHandle(h.value, prefix, true)) return false;
            handles.push_back(std::move(h));
            if (end == text.size()) break;
            end = text.find(L'\\', end + 1); if (end == text.npos) end = text.size();
        }
        return true;
    }
};
bool ProtectedConfigValid(const WriteAheadLog::Options& o)
{
    if (!o.protected_persistence) return false;
    const auto& p = *o.protected_persistence;
    const auto nonzero = [](auto& d) { return std::any_of(d.begin(), d.end(), [](auto b) { return b != std::byte{}; }); };
    return ProtectedPathSyntax(o.path) && ProtectedPathSyntax(p.key_directory) && !o.volume_identity.empty() &&
        o.volume_identity.size() <= 4096 && o.volume_identity.find('\0') == o.volume_identity.npos &&
        nonzero(p.source_binding) && nonzero(p.journal_identity) &&
        o.max_bytes >= 512 && o.max_bytes <= p.read_limits.bytes && p.read_limits.bytes <= (64ull << 20) &&
        p.read_limits.records > 0 && p.read_limits.records <= 65536 &&
        p.max_allocation_bytes > 0 && p.max_allocation_bytes <= (256ull << 20) &&
        WalRegistryKey(o.path.parent_path()) != WalRegistryKey(p.key_directory);
}
bool ProtectedContext(const WriteAheadLog::Options& o, const ProtectedPosition& at, jc::JournalRecordContext& context)
{
    std::array<std::byte, 128> bytes{};
    std::memcpy(bytes.data(), "APFS-WAL-CONTEXT1", 17);
    std::memcpy(bytes.data() + 24, o.protected_persistence->journal_identity.data(), 32);
    std::array<std::uint8_t, 32> volume{};
    if (!ComputeSha256(std::as_bytes(std::span(o.volume_identity.data(), o.volume_identity.size())), volume)) return false;
    // Hash fixed-width components, then bind physical position, ordinal, prior
    // authenticated WAL sequence and complete previous ciphertext hash.
    std::memcpy(bytes.data() + 56, volume.data(), 32);
    for (unsigned i = 0; i < 8; ++i)
    {
        bytes[88 + i] = std::byte((at.offset >> (8 * i)) & 255);
        bytes[96 + i] = std::byte((at.ordinal >> (8 * i)) & 255);
        bytes[104 + i] = std::byte((at.sequence >> (8 * i)) & 255);
    }
    std::array<std::byte, 160> complete{};
    std::memcpy(complete.data(), bytes.data(), bytes.size());
    std::memcpy(complete.data() + 128, at.previous.data(), 32);
    std::array<std::uint8_t, 32> digest{};
    if (!ComputeSha256(complete, digest)) return false;
    context.purpose = at.ordinal == 0 ? 0x57414c01U : 0x57414c02U;
    context.chunk = at.ordinal;
    std::memcpy(context.operation.data(), digest.data(), 32);
    return true;
}
bool ProtectedAdvance(ProtectedPosition& at, std::span<const std::byte> frame, std::uint64_t sequence)
{
    if (!ComputeSha256(frame, at.previous)) return false;
    at.offset += frame.size(); ++at.ordinal; at.sequence = sequence;
    return true;
}
bool DerivedWitnessNamespaceSettled(const std::filesystem::path& path)
{
    if (path.empty()) return true;
    const auto absent = [&](const wchar_t* suffix) {
        WIN32_FIND_DATAW found{};
        const auto search = FindFirstFileW(WalIoPath(path.wstring() + suffix).c_str(), &found);
        if (search != INVALID_HANDLE_VALUE) { FindClose(search); return false; }
        const auto error = GetLastError();
        return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND;
    };
    if (!absent(L".wreset*")) return false;
    if (PathIsAbsent(path))
        for (auto suffix : {L".wrsaved.*", L".wrdone.*", L".wrfail.*"}) if (!absent(suffix)) return false;
    return true;
}
bool ContinuationNamespaceAbsent(const std::filesystem::path& path)
{
    if (path.empty()) return true;
    WIN32_FIND_DATAW data{};
    const auto search = FindFirstFileW((path.wstring() + L".jcont*").c_str(), &data);
    if (search != INVALID_HANDLE_VALUE) { FindClose(search); return false; }
    const auto error = GetLastError();
    return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND;
}
WriteAheadLog::ReadStatus ProtectedError(const jc::JournalStatus& s)
{
    if (s.error == jc::JournalError::ResourceLimit || s.crypto_error == cc::CryptoError::ResourceLimit ||
        s.crypto_error == cc::CryptoError::AllocationFailed || s.crypto_error == cc::CryptoError::MemoryLockFailed)
        return WriteAheadLog::ReadStatus::ResourceLimit;
    if (s.error == jc::JournalError::BindingMismatch) return WriteAheadLog::ReadStatus::VolumeMismatch;
    if (s.error == jc::JournalError::IntegrityFailure) return WriteAheadLog::ReadStatus::ChecksumMismatch;
    return WriteAheadLog::ReadStatus::IoError;
}
WriteAheadLog::ReadResult DecodeProtectedWal(std::span<const std::uint8_t> bytes, const WriteAheadLog::Options& o,
    WalReadLimits limits, std::uint64_t allocation, ProtectedPosition& position, ProtectedCheckpoint* checkpoint = nullptr,
    jc::ProtectedJournalReadPass* reader = nullptr, std::span<const std::byte> continuation_anchor = {},
    std::uint64_t continuation_sequence = 0)
{
    using Wal = WriteAheadLog;
    Wal::ReadResult result{};
    ProtectedReadExceptionCleanup replay_cleanup{result};
    position = {};
    const auto fail = [&](Wal::ReadStatus status) {
        WipeRecords(result.records); result.status = status; return std::move(result);
    };
    if (bytes.size() < kProtectedAnchorBytes || !std::equal(kProtectedWalHeader.begin(), kProtectedWalHeader.end(), bytes.begin()))
        return fail(Wal::ReadStatus::Corrupt);
    if (bytes.size() > limits.bytes || bytes.size() > allocation / 4) return fail(Wal::ReadStatus::ResourceLimit);
    position.offset = kProtectedWalHeader.size();
    ProtectedCheckpoint proof{};
    std::array<std::uint8_t, 32> semantic{};
    if (!ProtectedSemanticStart(semantic)) return fail(Wal::ReadStatus::IoError);
    while (position.offset < bytes.size())
    {
        const auto left = bytes.subspan(static_cast<std::size_t>(position.offset));
        if (left.size() < 80 || std::memcmp(left.data(), "APFSREC1", 8) || ReadU32(left, 8) != 1 || ReadU32(left, 12) != 64)
            return fail(Wal::ReadStatus::Corrupt);
        const auto length = ReadU32(left, 16);
        if (length < 80 || length > jc::kMaxJournalRecordBytes || length > left.size()) return fail(Wal::ReadStatus::Corrupt);
        if (position.ordinal && (result.records.size() >= limits.records ||
            result.records.size() >= (allocation - bytes.size() * 4) / (2 * sizeof(Wal::Record) + 4)))
            return fail(Wal::ReadStatus::ResourceLimit);
        jc::JournalRecordContext context{};
        if (!ProtectedContext(o, position, context)) return fail(Wal::ReadStatus::IoError);
        const auto frame = std::as_bytes(left.first(length));
        auto plain = reader ? reader->Open(context, frame) :
            jc::ProtectedJournalEpoch::Open(o.protected_persistence->key_directory.wstring(),
                o.protected_persistence->source_binding, context, frame);
        if (!plain) return fail(ProtectedError(plain.status));
        auto sequence = position.sequence;
        if (position.ordinal == 0)
        {
            if (!continuation_anchor.empty())
            {
                if (continuation_anchor.size() != 192 || plain.bytes.Size() != continuation_anchor.size() ||
                    std::memcmp(plain.bytes.Bytes().data(), continuation_anchor.data(), continuation_anchor.size()))
                    return fail(Wal::ReadStatus::Corrupt);
                sequence = continuation_sequence;
            }
            else if (plain.bytes.Size() == kProtectedAnchor.size())
            {
                if (std::memcmp(plain.bytes.Bytes().data(), kProtectedAnchor.data(), kProtectedAnchor.size())) return fail(Wal::ReadStatus::Corrupt);
            }
            else if (!ProtectedCheckpointDecode(plain.bytes.Bytes(), proof)) return fail(Wal::ReadStatus::Corrupt);
        }
        else
        {
            const auto data = std::span(reinterpret_cast<const std::uint8_t*>(plain.bytes.Bytes().data()), plain.bytes.Size());
            if (data.size() < kLegacyHeaderSize || ReadU32(data, 0) != kMagic || ReadU32(data, 8) != data.size())
                return fail(Wal::ReadStatus::Corrupt);
            const auto version = ReadU16(data, 4);
            const std::size_t header = version == 1 ? kLegacyHeaderSize : version == 2 ? kInlinePayloadHeaderSize : version == 3 ? kUnlinkOutcomeHeaderSize : 0;
            if (!header || ReadU16(data, 6) != header || data.size() < header) return fail(Wal::ReadStatus::VersionMismatch);
            Wal::Record record{};
            struct Cleanup { Wal::Record& r; ~Cleanup() { WipeRecord(r); } } cleanup{record};
            Wal::ReadStatus status{};
            if (!DecodeRecord(data, 0, data.size(), version, o.volume_identity, record, status)) return fail(status);
            if (!record.sequence || record.sequence == UINT64_MAX || record.sequence <= sequence ||
                record.operation == Wal::OperationKind::CompactionIndex ||
                record.state < Wal::RecordState::Prepared || record.state > Wal::RecordState::CleanupArmed)
                return fail(Wal::ReadStatus::Corrupt);
            sequence = record.sequence;
            if (proof.floor && result.records.size() < proof.retained)
            {
                if (!ProtectedSemanticStep(semantic, plain.bytes.Bytes())) return fail(Wal::ReadStatus::IoError);
                if (result.records.size() + 1 == proof.retained &&
                    (semantic != proof.semantic || sequence != proof.previous.last_sequence)) return fail(Wal::ReadStatus::Corrupt);
            }
            result.records.push_back(std::move(record));
        }
        if (!ProtectedAdvance(position, frame, sequence)) return fail(Wal::ReadStatus::IoError);
    }
    if (proof.floor && (result.records.size() < proof.retained || (!proof.retained && semantic != proof.semantic)))
        return fail(Wal::ReadStatus::Corrupt);
    if (checkpoint) *checkpoint = proof;
    return result;
}
} // namespace

struct WriteAheadLog::ProtectedState
{
    ProtectedPins wal_pins, key_pins;
    std::unique_ptr<jc::ProtectedJournalEpoch> epoch;
    ProtectedPosition position;
    bool verified = false, poisoned = false, write_pending = false, head_mismatch = false;
};

// Pure observations for focused tests; no filesystem access or public header API.
std::array<std::wstring, 4> InspectWalPathsForTest(
    const std::filesystem::path& path, std::string_view volume_identity)
{
    return {WalIoPath(path).wstring(), WalRenameDestinationPath(path),
        WalRegistryKey(path), WriterLeaseName(volume_identity)};
}

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

bool WriteAheadLog::ProtectedMaintenanceAbsent() const
{
    if (!DerivedWitnessNamespaceSettled(options_.path)) return false;
    if (!continuation_admission_ && !ContinuationNamespaceAbsent(options_.path)) return false;
    // Completed certificates are immutable retained authority. Require the exact
    // namespace admitted by that capability, including missing/foreign evidence.
    if (continuation_admission_)
    {
        const auto& expected = continuation_admission_->immutable_siblings;
        if (!continuation_authority_ || !continuation_admission_->validate_authority ||
            !continuation_admission_->validate_authority() || expected.size() > 512) return false;
        if (expected.empty()) { if (!ContinuationNamespaceAbsent(options_.path)) return false; }
        else {
        WIN32_FIND_DATAW entry{}; std::size_t count = 0;
        const auto h = FindFirstFileW((options_.path.wstring() + L".jcont*").c_str(), &entry);
        if (h == INVALID_HANDLE_VALUE) return false;
        bool valid = true;
        do
        {
            ++count;
            if (count > expected.size() || (entry.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) ||
                std::none_of(expected.begin(), expected.end(), [&](const auto& name) {
                    return CompareStringOrdinal(entry.cFileName, -1, name.c_str(), -1, TRUE) == CSTR_EQUAL;
                })) { valid = false; break; }
        } while (FindNextFileW(h, &entry));
        const auto error = GetLastError(); FindClose(h);
        if (!valid || error != ERROR_NO_MORE_FILES || count != expected.size()) return false;
        }
    }
    WIN32_FIND_DATAW found{};
    const auto pattern = options_.path.wstring() + L".compact*";
    auto search = FindFirstFileW(WalIoPath(pattern).c_str(), &found);
    if (search != INVALID_HANDLE_VALUE) { FindClose(search); return false; }
    if (GetLastError() != ERROR_FILE_NOT_FOUND) return false;
    if (PathIsAbsent(options_.path))
    {
        for (auto suffix : {L".pcold.*", L".pcfailed.*"})
        {
            search = FindFirstFileW((options_.path.wstring() + suffix).c_str(), &found);
            if (search != INVALID_HANDLE_VALUE) { FindClose(search); return false; }
            if (GetLastError() != ERROR_FILE_NOT_FOUND) return false;
        }
    }
    return true;
}

bool WriteAheadLog::EnsureProtectedState() const
{ return EnsureProtectedState(false); }

bool WriteAheadLog::EnsureProtectedState(bool allow_pending) const
{
    try
    {
        if (!ProtectedConfigValid(options_)) return false;
        if (!protected_state_)
        {
            auto state = std::make_unique<ProtectedState>();
            if (!state->wal_pins.Pin(options_.path.parent_path()) ||
                !state->key_pins.Pin(options_.protected_persistence->key_directory)) return false;
            protected_state_ = std::move(state);
        }
        return allow_pending || ProtectedMaintenanceAbsent();
    }
    catch (...) { return false; }
}

WriteAheadLog::ReadResult WriteAheadLog::ReadProtected(WalReadLimits limits,
    std::uint64_t allocation, bool retain_writer) const
{
    ReadResult failed{}; failed.status = ReadStatus::IoError;
    try
    {
        if (!EnsureProtectedState() || (retain_writer && !EnsureWriterLease())) return failed;
        const auto& protection = *options_.protected_persistence;
        limits.bytes = (std::min)(limits.bytes, (std::min)(protection.read_limits.bytes, options_.max_bytes));
        limits.records = (std::min)(limits.records, protection.read_limits.records);
        allocation = (std::min)(allocation, protection.max_allocation_bytes);
        ProtectedHandle opened;
        auto handle = static_cast<HANDLE>(append_handle_);
        if (!handle)
        {
            opened.value = OpenWalFile(options_.path, retain_writer ? GENERIC_READ | GENERIC_WRITE : GENERIC_READ,
                retain_writer ? FILE_SHARE_READ : FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
            handle = opened.value;
            if (handle == INVALID_HANDLE_VALUE)
            {
                // No journal, no epoch slot and no maintenance writes. The pipe
                // lease is retained when the instance requested exclusive replay.
                if (GetLastError() == ERROR_FILE_NOT_FOUND) return {};
                return failed;
            }
        }
        if (!ProtectedExactHandle(handle, options_.path, false)) return failed;
        BY_HANDLE_FILE_INFORMATION before{}, after{};
        if (!GetFileInformationByHandle(handle, &before)) return failed;
        const auto size = (std::uint64_t(before.nFileSizeHigh) << 32) | before.nFileSizeLow;
        if (size > limits.bytes || size > allocation / 4)
        { failed.status = ReadStatus::ResourceLimit; return failed; }
        std::vector<std::uint8_t> bytes;
        if (!ReadPinnedIntentBytes(handle, bytes, size)) return failed;
        ProtectedPosition position;
        auto reader = jc::ProtectedJournalReadPass::Acquire(protection.key_directory.wstring(), protection.source_binding);
        if (!reader) { failed.status = ProtectedError(reader.status); return failed; }
        auto decoded = DecodeProtectedWal(bytes, options_, limits, allocation, position, nullptr, reader.reader.get(),
            continuation_admission_ ? std::span<const std::byte>(continuation_admission_->anchor) : std::span<const std::byte>{},
            continuation_admission_ ? continuation_admission_->last_sequence : 0);
        ProtectedReadExceptionCleanup cleanup{decoded};
        const bool stable = GetFileInformationByHandle(handle, &after) &&
            before.dwVolumeSerialNumber == after.dwVolumeSerialNumber && before.nFileIndexHigh == after.nFileIndexHigh &&
            before.nFileIndexLow == after.nFileIndexLow && before.nFileSizeHigh == after.nFileSizeHigh &&
            before.nFileSizeLow == after.nFileSizeLow && CompareFileTime(&before.ftLastWriteTime, &after.ftLastWriteTime) == 0 &&
            ProtectedExactHandle(handle, options_.path, false) && ProtectedMaintenanceAbsent();
        if (!stable) { WipeRecords(decoded.records); return failed; }
        if (decoded.status != ReadStatus::Ok) return decoded;
        if (retain_writer)
        {
            if (!SetFilePointerEx(handle, {}, nullptr, FILE_END)) { WipeRecords(decoded.records); return failed; }
            if (!append_handle_) { append_handle_ = std::exchange(opened.value, INVALID_HANDLE_VALUE); ++append_handle_open_count_; }
            append_handle_size_ = size; append_handle_size_known_ = true;
            protected_state_->position = position;
            protected_state_->verified = true;
        }
        return decoded;
    }
    catch (const std::bad_alloc&) { failed.status = ReadStatus::ResourceLimit; return failed; }
    catch (const std::length_error&) { failed.status = ReadStatus::ResourceLimit; return failed; }
    catch (...) { return failed; }
}

bool WriteAheadLog::EnsureProtectedAppendHandle(bool allow_create) const
{
    if (!EnsureProtectedState() || protected_state_->poisoned || protected_state_->head_mismatch || !EnsureWriterLease()) return false;
    if (append_handle_) return protected_state_->verified && ValidatedAppendLeaseGeneration() != 0;
    auto replay = ReadProtected(options_.protected_persistence->read_limits,
        options_.protected_persistence->max_allocation_bytes, true);
    const bool good = replay.status == ReadStatus::Ok;
    WipeRecords(replay.records);
    if (!good || append_handle_) return good && append_handle_;
    if (!allow_create) return false;
    if (!protected_state_->epoch)
    {
        auto epoch = jc::ProtectedJournalEpoch::AcquireWriter(options_.protected_persistence->key_directory.wstring(),
            options_.protected_persistence->source_binding);
        if (!epoch) return false;
        protected_state_->epoch = std::move(epoch.epoch);
    }
    ProtectedPosition start;
    start.offset = kProtectedWalHeader.size();
    jc::JournalRecordContext context{};
    if (!ProtectedContext(options_, start, context)) return false;
    auto anchor = protected_state_->epoch->Seal(context,
        std::as_bytes(std::span(kProtectedAnchor.data(), kProtectedAnchor.size())));
    if (!anchor) return false;
    const auto bytes = anchor.bytes.Bytes();
    std::vector<std::uint8_t> encoded(kProtectedWalHeader.begin(), kProtectedWalHeader.end());
    encoded.insert(encoded.end(), reinterpret_cast<const std::uint8_t*>(bytes.data()),
        reinterpret_cast<const std::uint8_t*>(bytes.data() + bytes.size()));
    auto handle = OpenWalFile(options_.path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, nullptr,
        CREATE_NEW, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH, nullptr);
    if (handle == INVALID_HANDLE_VALUE) return false;
    append_handle_ = handle; ++append_handle_open_count_;
    append_handle_size_ = 0; append_handle_size_known_ = true;
    protected_state_->position = start; protected_state_->verified = ProtectedExactHandle(handle, options_.path, false);
    protected_state_->write_pending = true;
    if (!protected_state_->verified || AppendEncoded(encoded) != EncodedAppendResult::Succeeded || !FlushAppendHandle() ||
        !ProtectedAdvance(protected_state_->position, bytes, 0))
    {
        protected_state_->poisoned = true;
        (void)CloseAppendHandle();
        return false;
    }
    protected_state_->write_pending = false;
    return true;
}

WriteAheadLog::AppendResult WriteAheadLog::AppendProtected(std::span<const Record> records,
    bool durable_flush, std::uint64_t expected_writer_generation) const
{
    bool materialized = false;
    try
    {
        if (!EnsureProtectedState() || protected_state_->poisoned || protected_state_->head_mismatch || records.size() > kProtectedBatchRecords ||
            (expected_writer_generation && (!writer_lease_handle_ || writer_lease_generation_ != expected_writer_generation)))
            return AppendResult::RejectedBeforeWrite;
        if (records.empty()) return AppendResult::Succeeded;
        std::vector<cc::SecureBytes> plaintexts;
        std::uint64_t added = 0, sequence = 0;
        for (const auto& record : records)
        {
            if ((!record.volume_identity.empty() && record.volume_identity != options_.volume_identity) ||
                !IsKnownOperation(record.operation) || !record.sequence || record.sequence == UINT64_MAX || record.sequence <= sequence ||
                record.operation == OperationKind::CompactionIndex || record.state < RecordState::Prepared || record.state > RecordState::CleanupArmed)
                return AppendResult::RejectedBeforeWrite;
            Record writable = record;
            struct Cleanup { Record& r; ~Cleanup() { WipeRecord(r); } } cleanup{writable};
            if (writable.volume_identity.empty()) writable.volume_identity = options_.volume_identity;
            auto plain = EncodeProtectedWalRecord(writable);
            if (!plain) return AppendResult::RejectedBeforeWrite;
            added += plain.bytes.Size() + 80;
            plaintexts.push_back(std::move(plain.bytes)); sequence = record.sequence;
        }
        if (!EnsureWriterLease()) return AppendResult::RejectedBeforeWrite;
        if (!append_handle_)
        {
            auto replay = ReadProtected(options_.protected_persistence->read_limits,
                options_.protected_persistence->max_allocation_bytes, true);
            const bool good = replay.status == ReadStatus::Ok;
            WipeRecords(replay.records);
            if (!good) return AppendResult::RejectedBeforeWrite;
        }
        const auto& p = *options_.protected_persistence;
        const auto& at = protected_state_->position;
        const auto base = append_handle_ ? at.offset : kProtectedAnchorBytes;
        const auto count = at.ordinal ? at.ordinal - 1 : 0;
        if (records.front().sequence <= at.sequence || base > options_.max_bytes || added > options_.max_bytes - base ||
            count > p.read_limits.records || records.size() > p.read_limits.records - count ||
            base + added > p.max_allocation_bytes / 4 ||
            count + records.size() > (p.max_allocation_bytes - (base + added) * 4) / (2 * sizeof(Record) + 4))
            return AppendResult::RejectedBeforeWrite;
        const bool absent = !append_handle_;
        if (!EnsureProtectedAppendHandle(true))
            return protected_state_->poisoned ? AppendResult::BytesMayHavePersisted : AppendResult::RejectedBeforeWrite;
        materialized = absent;
        if (!protected_state_->epoch)
        {
            auto epoch = jc::ProtectedJournalEpoch::AcquireWriter(p.key_directory.wstring(), p.source_binding);
            if (!epoch) return absent ? AppendResult::BytesMayHavePersisted : AppendResult::RejectedBeforeWrite;
            protected_state_->epoch = std::move(epoch.epoch);
        }
        auto position = protected_state_->position;
        std::vector<std::uint8_t> encrypted;
        encrypted.reserve(static_cast<std::size_t>(added));
        for (std::size_t i = 0; i < records.size(); ++i)
        {
            jc::JournalRecordContext context{};
            if (!ProtectedContext(options_, position, context)) return absent ? AppendResult::BytesMayHavePersisted : AppendResult::RejectedBeforeWrite;
            auto frame = protected_state_->epoch->Seal(context, plaintexts[i].Bytes());
            if (!frame) return absent ? AppendResult::BytesMayHavePersisted : AppendResult::RejectedBeforeWrite;
            const auto b = frame.bytes.Bytes();
            encrypted.insert(encrypted.end(), reinterpret_cast<const std::uint8_t*>(b.data()), reinterpret_cast<const std::uint8_t*>(b.data() + b.size()));
            if (!ProtectedAdvance(position, b, records[i].sequence)) return absent ? AppendResult::BytesMayHavePersisted : AppendResult::RejectedBeforeWrite;
        }
        if (fault_injection_hook_ && fault_injection_hook_("protected-before-write"))
            return absent ? AppendResult::BytesMayHavePersisted : AppendResult::RejectedBeforeWrite;
        protected_state_->write_pending = true;
        const auto result = AppendEncoded(encrypted);
        if (result != EncodedAppendResult::Succeeded)
        {
            protected_state_->poisoned = true; (void)CloseAppendHandle();
            return result == EncodedAppendResult::BytesMayHavePersisted || absent ? AppendResult::BytesMayHavePersisted : AppendResult::RejectedBeforeWrite;
        }
        protected_state_->position = position;
        if (durable_flush && !FlushAppendHandle())
        {
            protected_state_->poisoned = true; (void)CloseAppendHandle();
            return AppendResult::BytesMayHavePersisted;
        }
        protected_state_->write_pending = false;
        return AppendResult::Succeeded;
    }
    catch (...)
    {
        if (protected_state_ && protected_state_->write_pending)
        { protected_state_->poisoned = true; (void)CloseAppendHandle(); }
        if (materialized || (protected_state_ && protected_state_->poisoned)) return AppendResult::BytesMayHavePersisted;
        return AppendResult::RejectedBeforeWrite;
    }
}

namespace
{
struct ProtectedRecordCleanup
{
    WriteAheadLog::ReadResult& result;
    ~ProtectedRecordCleanup() { WipeRecords(result.records); }
};
bool ProtectedHeadOf(std::span<const std::uint8_t> bytes, const WriteAheadLog::ReadResult& decoded, ProtectedHead& head)
{
    head = {}; head.bytes = bytes.size(); head.records = decoded.records.size();
    head.last_sequence = decoded.records.empty() ? 0 : decoded.records.back().sequence;
    return decoded.status == WriteAheadLog::ReadStatus::Ok && ComputeSha256(std::as_bytes(bytes), head.sha256) && ProtectedHeadValid(head);
}
bool ProtectedReadBounded(HANDLE h, std::vector<std::uint8_t>& bytes, std::uint64_t limit)
{
    std::uint64_t size = 0;
    return TryGetPhysicalFileSize(h, size) && size <= limit && ReadPinnedIntentBytes(h, bytes, size);
}
bool ProtectedReadBlob(HANDLE h, const std::filesystem::path& path, const WriteAheadLog::Options& o,
    std::vector<std::uint8_t>& bytes, WriteAheadLog::ReadResult& decoded, ProtectedHead& head, ProtectedCheckpoint& proof)
{
    if (!ProtectedExactHandle(h, path, false) || !ProtectedReadBounded(h, bytes, o.max_bytes)) return false;
    ProtectedPosition position;
    decoded = DecodeProtectedWal(bytes, o, o.protected_persistence->read_limits,
        o.protected_persistence->max_allocation_bytes, position, &proof);
    return ProtectedHeadOf(bytes, decoded, head) && ProtectedExactHandle(h, path, false);
}
std::vector<std::uint8_t> ProtectedRetention(const std::vector<WriteAheadLog::Record>& records, std::uint64_t floor)
{
    std::uint64_t maximum_id = 0;
    for (const auto& r : records) maximum_id = (std::max)(maximum_id, r.transaction_id);
    std::unordered_set<std::uint64_t> transactions;
    for (const auto& r : records)
        if (!r.transaction_id || r.sequence >= floor || r.state != WriteAheadLog::RecordState::Prepared ||
            r.operation == WriteAheadLog::OperationKind::TransactionMarker || r.operation == WriteAheadLog::OperationKind::DurabilityWatermark ||
            r.transaction_id == maximum_id || &r == &records.back()) transactions.insert(r.transaction_id);
    std::vector<std::uint8_t> keep; keep.reserve(records.size());
    for (const auto& r : records) keep.push_back(static_cast<std::uint8_t>(transactions.contains(r.transaction_id)));
    return keep;
}
template<class F> bool ProtectedWalkKept(const WriteAheadLog::Options& o, std::span<const std::uint8_t> bytes,
    const std::vector<WriteAheadLog::Record>& records, const std::vector<std::uint8_t>& keep, F f)
{
    ProtectedPosition at; at.offset = kProtectedWalHeader.size();
    std::size_t index = 0;
    while (at.offset < bytes.size())
    {
        const auto left = bytes.subspan(static_cast<std::size_t>(at.offset));
        if (left.size() < 80) return false;
        const auto length = ReadU32(left, 16);
        if (length < 80 || length > left.size()) return false;
        const auto frame = std::as_bytes(left.first(length));
        auto sequence = at.sequence;
        if (at.ordinal)
        {
            if (index >= records.size()) return false;
            if (keep[index])
            {
                jc::JournalRecordContext context{};
                if (!ProtectedContext(o, at, context)) return false;
                auto plain = jc::ProtectedJournalEpoch::Open(o.protected_persistence->key_directory.wstring(),
                    o.protected_persistence->source_binding, context, frame);
                if (!plain || !f(plain.bytes.Bytes())) return false;
            }
            sequence = records[index++].sequence;
        }
        if (!ProtectedAdvance(at, frame, sequence)) return false;
    }
    return index == records.size();
}
std::filesystem::path ProtectedSibling(const std::filesystem::path& path, const wchar_t* suffix)
{ return std::filesystem::path(path.wstring() + suffix); }
std::filesystem::path ProtectedArchive(const std::filesystem::path& path, const wchar_t* suffix, const std::array<std::uint8_t, 32>& digest)
{
    constexpr wchar_t hex[] = L"0123456789abcdef";
    auto name = path.wstring() + suffix;
    for (auto b : digest) { name.push_back(hex[b >> 4]); name.push_back(hex[b & 15]); }
    return std::filesystem::path(name);
}
bool ProtectedPendingKnown(const std::filesystem::path& path)
{
    WIN32_FIND_DATAW data{};
    const auto search = FindFirstFileW((path.wstring() + L".compact*").c_str(), &data);
    if (search == INVALID_HANDLE_VALUE) return GetLastError() == ERROR_FILE_NOT_FOUND;
    const auto next = path.filename().wstring() + L".compact.pnext", old = path.filename().wstring() + L".compact.pold";
    bool valid = true;
    do
    {
        if (CompareStringOrdinal(data.cFileName, -1, next.c_str(), -1, TRUE) != CSTR_EQUAL &&
            CompareStringOrdinal(data.cFileName, -1, old.c_str(), -1, TRUE) != CSTR_EQUAL) valid = false;
    } while (FindNextFileW(search, &data));
    const auto error = GetLastError(); FindClose(search);
    return valid && error == ERROR_NO_MORE_FILES;
}
ProtectedHandle ProtectedOpenMaintenance(const std::filesystem::path& path, bool& valid)
{
    const auto h = OpenWalFile(path, GENERIC_READ | GENERIC_WRITE | DELETE, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH, nullptr);
    if (h == INVALID_HANDLE_VALUE) { if (GetLastError() != ERROR_FILE_NOT_FOUND) valid = false; }
    else if (!ProtectedExactHandle(h, path, false)) valid = false;
    return ProtectedHandle(h);
}
}

bool WriteAheadLog::CaptureProtectedHistoryHead(ProtectedHistoryHead& head) const
{
    std::lock_guard<std::recursive_mutex> lock(WalOperationMutex(options_.path)); head = {};
    if (!options_.protected_persistence) return false;
    try
    {
        auto decoded = ReadProtected(options_.protected_persistence->read_limits, options_.protected_persistence->max_allocation_bytes, true);
        ProtectedRecordCleanup cleanup{decoded}; std::vector<std::uint8_t> bytes;
        ProtectedHead captured;
        if (!append_handle_ || decoded.status != ReadStatus::Ok ||
            !ProtectedReadBounded(static_cast<HANDLE>(append_handle_), bytes, options_.max_bytes) || !ProtectedHeadOf(bytes, decoded, captured)) return false;
        if (continuation_admission_ && decoded.records.empty()) captured.last_sequence = continuation_admission_->last_sequence;
        head = captured; return true;
    }
    catch (...) { head = {}; return false; }
}

bool WriteAheadLog::VerifyProtectedHistoryPrefix(const ProtectedHistoryHead& expected) const
{
    std::lock_guard<std::recursive_mutex> lock(WalOperationMutex(options_.path));
    if (!options_.protected_persistence || !HasExclusiveWriterLease()) return false;
    auto read = ReadProtected(options_.protected_persistence->read_limits,
        options_.protected_persistence->max_allocation_bytes, true);
    ProtectedRecordCleanup cleanup{read};
    if (read.status != ReadStatus::Ok || read.recovered_torn_tail) return false;
    if (!expected.bytes) return !expected.records && !expected.last_sequence && expected.sha256 == ProtectedHistoryHead{}.sha256;
    std::vector<std::uint8_t> bytes;
    ProtectedHead prefix;
    if (!append_handle_ || !ProtectedReadBounded(static_cast<HANDLE>(append_handle_), bytes, options_.max_bytes) ||
        expected.bytes > bytes.size() || expected.records > read.records.size()) return false;
    bytes.resize(static_cast<std::size_t>(expected.bytes));
    for (std::size_t n = static_cast<std::size_t>(expected.records); n < read.records.size(); ++n) WipeRecord(read.records[n]);
    read.records.resize(static_cast<std::size_t>(expected.records));
    if (!ProtectedHeadOf(bytes, read, prefix)) return false;
    if (continuation_admission_ && read.records.empty()) prefix.last_sequence = continuation_admission_->last_sequence;
    return prefix == expected;
}

bool WriteAheadLog::ProtectedAppendCapacityAvailable(std::span<const Record> records) const
{
    std::lock_guard<std::recursive_mutex> lock(WalOperationMutex(options_.path));
    if (!options_.protected_persistence || !HasExclusiveWriterLease()) return false;
    const auto& p = *options_.protected_persistence;
    auto read = ReadProtected(p.read_limits, p.max_allocation_bytes, true); ProtectedRecordCleanup cleanup{read};
    if (read.status != ReadStatus::Ok || read.recovered_torn_tail) return false;
    std::uint64_t bytes = 4096, count = read.records.size();
    if (append_handle_ && !TryGetPhysicalFileSize(static_cast<HANDLE>(append_handle_), bytes)) return false;
    const auto limit = (std::min)({options_.max_bytes, p.read_limits.bytes, p.max_allocation_bytes / 4});
    const auto record_limit = p.read_limits.records;
    if (bytes > limit || count > record_limit || records.size() > record_limit - count) return false;
    for (const auto& row : records) {
        auto encoded = EncodeForTest(row);
        const auto additional = encoded.size() + jc::kJournalRecordHeaderBytes + crypto::kGcmTagBytes;
        if (encoded.empty() || additional > limit - bytes) return false;
        bytes += additional; ++count;
    }
    return count <= (p.max_allocation_bytes - bytes * 4) / (2 * sizeof(Record) + 4);
}

bool WriteAheadLog::DecodeCertifiedOriginalRecord(std::span<const std::uint8_t> bytes,
    const std::string& identity, Record& record)
{
    if (bytes.size() < kLegacyHeaderSize || bytes.size() > 16384 || ReadU32(bytes, 0) != kMagic || ReadU32(bytes, 8) != bytes.size()) return false;
    const auto version = ReadU16(bytes, 4);
    const auto header = version == 1 ? kLegacyHeaderSize : version == 2 ? kInlinePayloadHeaderSize : version == 3 ? kUnlinkOutcomeHeaderSize : 0;
    ReadStatus status{};
    const bool valid = header && ReadU16(bytes, 6) == header && bytes.size() >= header && DecodeRecord(bytes, 0, bytes.size(), version, identity, record, status);
    if (!valid) WipeRecord(record);
    return valid;
}

bool WriteAheadLog::SealContinuationAnchor(const ContinuationAdmission& admission,
    jc::ProtectedJournalEpoch& epoch, std::vector<std::uint8_t>& encrypted) const
{
    return SealContinuationRecords(admission, {}, epoch, encrypted);
}

bool WriteAheadLog::SealContinuationRecords(const ContinuationAdmission& admission, std::span<const Record> records,
    jc::ProtectedJournalEpoch& epoch, std::vector<std::uint8_t>& encrypted) const
{
    encrypted.clear();
    if (!ProtectedConfigValid(options_) || admission.last_sequence == UINT64_MAX ||
        std::memcmp(admission.anchor.data(), "WALCONT1", 8)) return false;
    const auto a = std::span(reinterpret_cast<const std::uint8_t*>(admission.anchor.data()), admission.anchor.size());
    const auto role = ReadU64(a, 24);
    if (ReadU64(a, 8) != 6 || !ReadU64(a, 16) || (role != 1 && role != 2) ||
        ReadU64(a, 96) != admission.last_sequence || (role == 1 && !admission.last_sequence) ||
        !ReadU64(a, 104) || !ReadU64(a, 112) || ReadU64(a, 112) != ReadU64(a, 120) ||
        ReadU64(a, 112) != ReadU64(a, 128) || !ReadU64(a, 168) || ReadU64(a, 176) || ReadU64(a, 184) ||
        records.size() > options_.protected_persistence->read_limits.records) return false;
    ProtectedPosition at; at.offset = kProtectedWalHeader.size();
    encrypted.assign(kProtectedWalHeader.begin(), kProtectedWalHeader.end());
    const auto seal = [&](std::span<const std::byte> bytes, std::uint64_t sequence) {
        jc::JournalRecordContext context{};
        if (!ProtectedContext(options_, at, context)) return false;
        auto frame = epoch.Seal(context, bytes);
        if (!frame || frame.bytes.Size() > options_.max_bytes - encrypted.size()) return false;
        const auto b = frame.bytes.Bytes();
        encrypted.insert(encrypted.end(), reinterpret_cast<const std::uint8_t*>(b.data()),
            reinterpret_cast<const std::uint8_t*>(b.data() + b.size()));
        return ProtectedAdvance(at, b, sequence);
    };
    if (!seal(admission.anchor, admission.last_sequence)) { encrypted.clear(); return false; }
    for (const auto& record : records) {
        // Certified witness groups retain their original, potentially separated
        // positions. Original records keep their consecutive sequence contract.
        const bool ordered = role == 2 ? record.sequence > at.sequence :
            at.sequence != UINT64_MAX && record.sequence == at.sequence + 1;
        if (!ordered || record.sequence == UINT64_MAX || record.volume_identity != options_.volume_identity) {
            encrypted.clear(); return false;
        }
        auto plain = EncodeProtectedWalRecord(record);
        if (!plain || !seal(plain.bytes.Bytes(), record.sequence)) { encrypted.clear(); return false; }
    }
    return true;
}

WriteAheadLog::ReadResult WriteAheadLog::DecodeContinuationEvidence(std::span<const std::uint8_t> bytes,
    const std::optional<ContinuationAdmission>& admission, ProtectedHistoryHead& head) const
{
    head = {};
    ReadResult failed; failed.status = ReadStatus::Corrupt;
    if (!ProtectedConfigValid(options_)) return failed;
    auto pass = jc::ProtectedJournalReadPass::Acquire(options_.protected_persistence->key_directory.wstring(),
        options_.protected_persistence->source_binding);
    if (!pass) { failed.status = ProtectedError(pass.status); return failed; }
    ProtectedPosition position;
    auto decoded = DecodeProtectedWal(bytes, options_, options_.protected_persistence->read_limits,
        options_.protected_persistence->max_allocation_bytes, position, nullptr, pass.reader.get(),
        admission ? std::span<const std::byte>(admission->anchor) : std::span<const std::byte>{},
        admission ? admission->last_sequence : 0);
    if (decoded.status == ReadStatus::Ok && ComputeSha256(std::as_bytes(bytes), head.sha256))
    {
        head.bytes = bytes.size(); head.records = decoded.records.size(); head.last_sequence = position.sequence;
        if (ProtectedHeadValid(head, admission.has_value())) return decoded;
    }
    WipeRecords(decoded.records); head = {}; return failed;
}

bool WriteAheadLog::InstallContinuationAdmission(const ContinuationAdmission& admission,
    std::shared_ptr<void> retained_authority) const
{
    std::lock_guard<std::recursive_mutex> lock(WalOperationMutex(options_.path));
    if (!retained_authority || !ProtectedConfigValid(options_) ||
        std::memcmp(admission.anchor.data(), "WALCONT1", 8) ||
        admission.last_sequence == UINT64_MAX || !EnsureWriterLease(true) || !CloseAppendFileHandle()) return false;
    continuation_admission_ = admission; continuation_authority_ = std::move(retained_authority);
    if (protected_state_)
    {
        protected_state_->poisoned = false; protected_state_->head_mismatch = false;
        protected_state_->write_pending = false;
    }
    auto read = ReadProtected(options_.protected_persistence->read_limits,
        options_.protected_persistence->max_allocation_bytes, true);
    const bool valid = read.status == ReadStatus::Ok && !read.recovered_torn_tail;
    WipeRecords(read.records);
    if (!valid) { continuation_admission_.reset(); continuation_authority_.reset(); }
    return valid;
}

WriteAheadLog::ReadResult WriteAheadLog::ReadAllAtProtectedHead(const ProtectedHistoryHead& expected) const
{
    std::lock_guard<std::recursive_mutex> lock(WalOperationMutex(options_.path));
    ReadResult failed{}; failed.status = ReadStatus::Corrupt;
    if (!options_.protected_persistence || !ProtectedHeadValid(expected, continuation_admission_.has_value())) return failed;
    try
    {
        auto decoded = ReadProtected(options_.protected_persistence->read_limits, options_.protected_persistence->max_allocation_bytes, true);
        ProtectedReadExceptionCleanup cleanup{decoded}; std::vector<std::uint8_t> bytes; ProtectedHead head;
        if (append_handle_ && decoded.status == ReadStatus::Ok &&
            ProtectedReadBounded(static_cast<HANDLE>(append_handle_), bytes, options_.max_bytes) && ProtectedHeadOf(bytes, decoded, head) &&
            (continuation_admission_ && decoded.records.empty() ? (head.last_sequence = continuation_admission_->last_sequence, true) : true) && head == expected)
        {
            protected_state_->head_mismatch = false; return decoded;
        }
        WipeRecords(decoded.records);
        if (protected_state_) { protected_state_->head_mismatch = true; (void)CloseAppendFileHandle(); }
        return failed;
    }
    catch (...)
    {
        if (protected_state_) { protected_state_->head_mismatch = true; (void)CloseAppendFileHandle(); }
        return failed;
    }
}

WriteAheadLog::CompactionResult WriteAheadLog::CompactProtectedWithResult(std::uint64_t floor,
    const ProtectedHistoryHead& expected, ProtectedHistoryHead& replacement, std::uint64_t generation) const
{
    std::lock_guard<std::recursive_mutex> lock(WalOperationMutex(options_.path)); replacement = {};
    bool wrote = false;
    const auto cut = [&](std::string_view stage) { return fault_injection_hook_ && fault_injection_hook_(stage); };
    const auto failed = [&]() {
        if (wrote && protected_state_) { protected_state_->poisoned = true; (void)CloseAppendFileHandle(); }
        return wrote ? CompactionResult::BytesMayHavePersisted : CompactionResult::RejectedBeforeWrite;
    };
    try
    {
        if (continuation_admission_ || !options_.protected_persistence || !ProtectedHeadValid(expected) || !floor || floor > expected.last_sequence + 1 ||
            !EnsureProtectedState() || protected_state_->poisoned || protected_state_->head_mismatch || !EnsureWriterLease() ||
            (generation && generation != writer_lease_generation_)) return failed();
        auto records = ReadProtected(options_.protected_persistence->read_limits, options_.protected_persistence->max_allocation_bytes, true);
        ProtectedRecordCleanup cleanup{records}; std::vector<std::uint8_t> original; ProtectedHead actual;
        if (!append_handle_ || records.status != ReadStatus::Ok ||
            !ProtectedReadBounded(static_cast<HANDLE>(append_handle_), original, options_.max_bytes) ||
            !ProtectedHeadOf(original, records, actual) || actual != expected) return failed();
        const auto pending = ProtectedSibling(options_.path, L".compact.pnext");
        const auto old = ProtectedSibling(options_.path, L".compact.pold");
        const auto archive = ProtectedArchive(options_.path, L".pcold.", expected.sha256);
        if (!ProtectedPathSyntax(pending) || !ProtectedPathSyntax(old) || !ProtectedPathSyntax(archive) ||
            !PathIsAbsent(pending) || !PathIsAbsent(old) || !PathIsAbsent(archive)) return failed();
        // Readable deferred/reopened bytes do not prove durability. The replacement
        // receipt depends on this exact original surviving every later rename cut.
        if (cut("pcompact-original-flush") || !ProtectedExactHandle(static_cast<HANDLE>(append_handle_), options_.path, false) ||
            !FlushAppendHandle() || !ProtectedExactHandle(static_cast<HANDLE>(append_handle_), options_.path, false) ||
            cut("pcompact-after-original-flush")) return failed();
        const auto keep = ProtectedRetention(records.records, floor);
        ProtectedCheckpoint proof; proof.previous = expected; proof.floor = floor;
        proof.retained = static_cast<std::uint64_t>(std::count(keep.begin(), keep.end(), std::uint8_t{1}));
        if (!ProtectedSemanticStart(proof.semantic) || !ProtectedWalkKept(options_, original, records.records, keep,
            [&](auto plain) { return ProtectedSemanticStep(proof.semantic, plain); })) return failed();
        std::uint64_t size = 16 + kCheckpointPlainBytes + 80;
        if (!ProtectedWalkKept(options_, original, records.records, keep, [&](auto plain) { size += plain.size() + 80; return true; }) ||
            size > options_.max_bytes || original.size() + size > options_.protected_persistence->max_allocation_bytes / 8 ||
            records.records.size() + proof.retained > (options_.protected_persistence->max_allocation_bytes - (original.size() + size) * 8) / (2 * sizeof(Record) + 64)) return failed();
        if (cut("pcompact-before-reseal")) return failed();
        if (!protected_state_->epoch)
        {
            auto epoch = jc::ProtectedJournalEpoch::AcquireWriter(options_.protected_persistence->key_directory.wstring(), options_.protected_persistence->source_binding);
            if (!epoch) return failed(); protected_state_->epoch = std::move(epoch.epoch);
        }
        std::vector<std::uint8_t> encrypted(kProtectedWalHeader.begin(), kProtectedWalHeader.end()); encrypted.reserve(static_cast<std::size_t>(size));
        ProtectedPosition at; at.offset = 16;
        const auto seal = [&](std::span<const std::byte> plain, std::uint64_t sequence) {
            jc::JournalRecordContext context{}; if (!ProtectedContext(options_, at, context)) return false;
            auto frame = protected_state_->epoch->Seal(context, plain); if (!frame) return false;
            const auto b = frame.bytes.Bytes(); encrypted.insert(encrypted.end(), reinterpret_cast<const std::uint8_t*>(b.data()), reinterpret_cast<const std::uint8_t*>(b.data() + b.size()));
            return ProtectedAdvance(at, b, sequence);
        };
        auto anchor = ProtectedCheckpointEncode(proof);
        const bool sealed_anchor = seal(anchor, 0); SecureZeroMemory(anchor.data(), anchor.size());
        if (!sealed_anchor) return failed();
        std::size_t index = 0;
        if (!ProtectedWalkKept(options_, original, records.records, keep, [&](auto plain) {
            while (index < keep.size() && !keep[index]) ++index;
            return index < keep.size() && seal(plain, records.records[index++].sequence);
        }) || encrypted.size() != size || cut("pcompact-before-create")) return failed();
        ProtectedHandle candidate(OpenWalFile(pending, GENERIC_READ | GENERIC_WRITE | DELETE, FILE_SHARE_READ, nullptr, CREATE_NEW,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH, nullptr));
        if (candidate.value == INVALID_HANDLE_VALUE) return failed(); wrote = true;
        if (!ProtectedExactHandle(candidate.value, pending, false) || cut("pcompact-after-create")) return failed();
        DWORD written = 0;
        if (cut("pcompact-partial-write")) { (void)WriteFile(candidate.value, encrypted.data(), 13, &written, nullptr); return failed(); }
        if (!WriteFile(candidate.value, encrypted.data(), static_cast<DWORD>(encrypted.size()), &written, nullptr) || written != encrypted.size() ||
            cut("pcompact-after-write") || cut("pcompact-flush") || !FlushFileBuffers(candidate.value) || cut("pcompact-after-flush")) return failed();
        std::vector<std::uint8_t> readback; ReadResult verified; ProtectedRecordCleanup verified_cleanup{verified}; ProtectedHead new_head; ProtectedCheckpoint checked;
        if (!ProtectedReadBlob(candidate.value, pending, options_, readback, verified, new_head, checked) || readback != encrypted ||
            checked.previous != expected || cut("pcompact-after-readback")) return failed();
        CloseHandle(std::exchange(candidate.value, INVALID_HANDLE_VALUE));
        const auto result = RecoverProtectedCompaction(expected, floor, ProtectedRecoveryChoice::PromoteReplacement, replacement);
        return result == CompactionResult::RejectedBeforeWrite ? failed() : result;
    }
    catch (...) { return failed(); }
}

WriteAheadLog::CompactionResult WriteAheadLog::RecoverProtectedCompaction(const ProtectedHistoryHead& previous,
    std::uint64_t floor, ProtectedRecoveryChoice choice, ProtectedHistoryHead& recovered) const
{
    std::lock_guard<std::recursive_mutex> lock(WalOperationMutex(options_.path)); recovered = {};
    bool wrote = false;
    const auto cut = [&](std::string_view stage) { return fault_injection_hook_ && fault_injection_hook_(stage); };
    const auto failed = [&]() {
        if (wrote && protected_state_) { protected_state_->poisoned = true; (void)CloseAppendFileHandle(); }
        return wrote ? CompactionResult::BytesMayHavePersisted : CompactionResult::RejectedBeforeWrite;
    };
    try
    {
        if (!options_.protected_persistence || !ProtectedHeadValid(previous) || !floor || floor > previous.last_sequence + 1 ||
            (choice != ProtectedRecoveryChoice::RetainOriginal && choice != ProtectedRecoveryChoice::PromoteReplacement) ||
            !EnsureProtectedState(true) || !EnsureWriterLease(true) || !ProtectedPendingKnown(options_.path) ||
            !DerivedWitnessNamespaceSettled(options_.path)) return failed();
        (void)CloseAppendFileHandle();
        const auto pending = ProtectedSibling(options_.path, L".compact.pnext"), old = ProtectedSibling(options_.path, L".compact.pold");
        const auto archive = ProtectedArchive(options_.path, L".pcold.", previous.sha256);
        if (!ProtectedPathSyntax(pending) || !ProtectedPathSyntax(old) || !ProtectedPathSyntax(archive)) return failed();
        bool valid = true;
        auto canonical = ProtectedOpenMaintenance(options_.path, valid);
        auto predecessor = ProtectedOpenMaintenance(old, valid);
        auto candidate = ProtectedOpenMaintenance(pending, valid);
        if (!valid) return failed();
        std::uint64_t total_bytes = 0;
        for (auto h : {canonical.value, predecessor.value, candidate.value})
            if (h != INVALID_HANDLE_VALUE)
            {
                std::uint64_t size = 0;
                if (!TryGetPhysicalFileSize(h, size) || size > options_.max_bytes) return failed();
                total_bytes += size;
            }
        if (total_bytes > options_.protected_persistence->max_allocation_bytes / 8) return failed();
        ReadResult current_records, old_records, next_records;
        ProtectedRecordCleanup c1{current_records}, c2{old_records}, c3{next_records};
        std::vector<std::uint8_t> current_bytes, old_bytes, next_bytes;
        ProtectedHead current_head, old_head, next_head; ProtectedCheckpoint current_proof, old_proof, next_proof;
        if (canonical.value != INVALID_HANDLE_VALUE && !ProtectedReadBlob(canonical.value, options_.path, options_, current_bytes, current_records, current_head, current_proof)) return failed();
        if (predecessor.value != INVALID_HANDLE_VALUE && !ProtectedReadBlob(predecessor.value, old, options_, old_bytes, old_records, old_head, old_proof)) return failed();
        if (predecessor.value != INVALID_HANDLE_VALUE && (old_head != previous || current_head == previous)) return failed();
        const bool original_canonical = canonical.value != INVALID_HANDLE_VALUE && current_head == previous;
        // Also required for explicit recovery and a no-op RetainOriginal: the
        // reopened handle has no reliable knowledge of earlier owners' flushes.
        const auto flush_original_canonical = [&]() {
            return !original_canonical || (!cut("precover-original-flush") &&
                ProtectedExactHandle(canonical.value, options_.path, false) && FlushFileBuffers(canonical.value) &&
                ProtectedExactHandle(canonical.value, options_.path, false) && !cut("precover-after-original-flush"));
        };
        if (choice == ProtectedRecoveryChoice::RetainOriginal)
        {
            if (!PathIsAbsent(archive)) return failed();
            if (canonical.value != INVALID_HANDLE_VALUE && !original_canonical) return failed();
            if (!original_canonical && predecessor.value == INVALID_HANDLE_VALUE) return failed();
            if (!flush_original_canonical()) return failed();
            if (candidate.value != INVALID_HANDLE_VALUE)
            {
                if (!ProtectedReadBounded(candidate.value, next_bytes, options_.max_bytes)) return failed();
                std::array<std::uint8_t, 32> hash{};
                if (!ComputeSha256(std::as_bytes(std::span(next_bytes)), hash)) return failed();
                auto quarantine = ProtectedArchive(options_.path, L".pcfailed.", hash);
                for (unsigned n = 0; !PathIsAbsent(quarantine) && n < 16; ++n)
                    quarantine = std::filesystem::path(ProtectedArchive(options_.path, L".pcfailed.", hash).wstring() + L"." + std::to_wstring(n));
                if (!ProtectedPathSyntax(quarantine) || !PathIsAbsent(quarantine) || cut("pcompact-before-quarantine")) return failed();
                if (!RenameOpenedFileWithoutReplacing(candidate.value, quarantine)) return failed(); wrote = true;
                if (!ProtectedExactHandle(candidate.value, quarantine, false) || cut("pcompact-after-quarantine") || !FlushFileBuffers(candidate.value)) return failed();
            }
            if (!original_canonical)
            {
                if (cut("pcompact-before-restore")) return failed();
                if (!RenameOpenedFileWithoutReplacing(predecessor.value, options_.path)) return failed(); wrote = true;
                if (!ProtectedExactHandle(predecessor.value, options_.path, false) || cut("pcompact-after-restore") || !FlushFileBuffers(predecessor.value)) return failed();
            }
        }
        else
        {
            ProtectedHandle archived;
            if (!original_canonical && predecessor.value == INVALID_HANDLE_VALUE)
            {
                archived.value = OpenWalFile(archive, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
                std::uint64_t archive_size = 0;
                if (archived.value == INVALID_HANDLE_VALUE || !TryGetPhysicalFileSize(archived.value, archive_size) || archive_size > options_.max_bytes ||
                    total_bytes + archive_size > options_.protected_persistence->max_allocation_bytes / 8 ||
                    !ProtectedReadBlob(archived.value, archive, options_, old_bytes, old_records, old_head, old_proof) || old_head != previous) return failed();
            }
            if (candidate.value != INVALID_HANDLE_VALUE)
            {
                if (canonical.value != INVALID_HANDLE_VALUE && !original_canonical) return failed();
                if (!ProtectedReadBlob(candidate.value, pending, options_, next_bytes, next_records, next_head, next_proof)) return failed();
            }
            else
            {
                if (canonical.value == INVALID_HANDLE_VALUE || original_canonical) return failed();
                next_proof = current_proof; next_head = current_head;
            }
            const auto& proof = next_proof;
            if (proof.previous != previous || proof.floor != floor || proof.retained != (candidate.value != INVALID_HANDLE_VALUE ? next_records.records.size() : current_records.records.size())) return failed();
            const auto& source_records = original_canonical ? current_records.records : old_records.records;
            const auto& source_bytes = original_canonical ? current_bytes : old_bytes;
            const auto keep = ProtectedRetention(source_records, floor);
            std::array<std::uint8_t, 32> digest{};
            if (static_cast<std::uint64_t>(std::count(keep.begin(), keep.end(), std::uint8_t{1})) != proof.retained ||
                !ProtectedSemanticStart(digest) || !ProtectedWalkKept(options_, source_bytes, source_records, keep,
                    [&](auto plain) { return ProtectedSemanticStep(digest, plain); }) || digest != proof.semantic) return failed();
            if (predecessor.value != INVALID_HANDLE_VALUE || original_canonical)
                if (!PathIsAbsent(archive)) return failed();
            if (!flush_original_canonical()) return failed();
            if (original_canonical)
            {
                if (cut("pcompact-before-old-rename")) return failed();
                if (!RenameOpenedFileWithoutReplacing(canonical.value, old)) return failed(); wrote = true;
                if (!ProtectedExactHandle(canonical.value, old, false) || cut("pcompact-after-old-rename") || cut("pcompact-old-flush") || !FlushFileBuffers(canonical.value)) return failed();
            }
            if (candidate.value != INVALID_HANDLE_VALUE)
            {
                if (cut("pcompact-before-new-rename")) return failed();
                if (!RenameOpenedFileWithoutReplacing(candidate.value, options_.path)) return failed(); wrote = true;
                if (!ProtectedExactHandle(candidate.value, options_.path, false) || cut("pcompact-after-new-rename") || cut("pcompact-new-flush") || !FlushFileBuffers(candidate.value)) return failed();
            }
            const auto old_handle = original_canonical ? canonical.value : predecessor.value;
            if (old_handle != INVALID_HANDLE_VALUE)
            {
                if (cut("pcompact-before-archive")) return failed();
                if (!RenameOpenedFileWithoutReplacing(old_handle, archive)) return failed(); wrote = true;
                if (!ProtectedExactHandle(old_handle, archive, false) || cut("pcompact-after-archive") || cut("pcompact-archive-flush") || !FlushFileBuffers(old_handle)) return failed();
            }
        }
        for (auto* h : {&canonical.value, &predecessor.value, &candidate.value})
            if (*h != INVALID_HANDLE_VALUE) CloseHandle(std::exchange(*h, INVALID_HANDLE_VALUE));
        if (cut("pcompact-before-reopen")) return failed();
        protected_state_->poisoned = false; protected_state_->head_mismatch = false;
        if (!CaptureProtectedHistoryHead(recovered)) return failed();
        return CompactionResult::Succeeded;
    }
    catch (...) { return failed(); }
}

namespace
{
constexpr std::size_t kDerivedBodyLimit = 900 * 1024, kDerivedReceiptBytes = 512;
constexpr std::size_t kDerivedReceiptFrame = kDerivedReceiptBytes + 80;
constexpr std::string_view kDerivedChunkPath = "\\encrypted-publication-chunk-v2";
constexpr std::string_view kDerivedEndPath = "\\encrypted-publication-end-v2";
struct DerivedInspection
{
    ProtectedPosition position;
    std::uint64_t matched = 0;
};
struct DerivedReceipt
{
    std::array<std::byte, 264> authority{};
    PhysicalFileIdentity old_id{}, candidate_id{};
    std::uint64_t old_bytes = 0, records = 0;
    std::array<std::uint8_t, 32> old_hash{}, semantic{};
    DerivedInspection stop;
    ProtectedHead candidate;
};
template<class T> bool DerivedNonzero(const T& bytes)
{ return std::any_of(bytes.begin(), bytes.end(), [](auto b) { return b != decltype(b){}; }); }
bool DerivedSameId(const PhysicalFileIdentity& a, const PhysicalFileIdentity& b)
{ return a.volume_serial == b.volume_serial && a.file_id == b.file_id; }
bool DerivedHashFile(HANDLE h, std::uint64_t cap, std::uint64_t& size,
    std::array<std::uint8_t, 32>& digest, PhysicalFileIdentity& id)
{
    if (!TryGetPhysicalFileSize(h, size) || size > cap || !TryGetPhysicalFileIdentity(h, id)) return false;
    DWORD object_bytes = 0, got = 0;
    if (BCryptGetProperty(BCRYPT_SHA256_ALG_HANDLE, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&object_bytes),
        sizeof(object_bytes), &got, 0) < 0 || got != sizeof(object_bytes) || !object_bytes) return false;
    auto object = cc::SecureBytes::Allocate(object_bytes), buffer = cc::SecureBytes::Allocate(64 * 1024);
    if (!object || !buffer) return false;
    struct Hash { BCRYPT_HASH_HANDLE h = nullptr; ~Hash() { if (h) BCryptDestroyHash(h); } } hash;
    if (BCryptCreateHash(BCRYPT_SHA256_ALG_HANDLE, &hash.h, reinterpret_cast<PUCHAR>(object.bytes.Bytes().data()),
        static_cast<ULONG>(object.bytes.Size()), nullptr, 0, 0) < 0 || !SetFilePointerEx(h, {}, nullptr, FILE_BEGIN)) return false;
    for (std::uint64_t at = 0; at < size;)
    {
        const auto n = static_cast<DWORD>((std::min)(size - at, std::uint64_t{64 * 1024})); DWORD read = 0;
        if (!ReadFile(h, buffer.bytes.Bytes().data(), n, &read, nullptr) || read != n ||
            BCryptHashData(hash.h, reinterpret_cast<PUCHAR>(buffer.bytes.Bytes().data()), n, 0) < 0) return false;
        at += n;
    }
    std::uint64_t after = 0; PhysicalFileIdentity identity{};
    return BCryptFinishHash(hash.h, digest.data(), static_cast<ULONG>(digest.size()), 0) >= 0 &&
        TryGetPhysicalFileSize(h, after) && after == size && TryGetPhysicalFileIdentity(h, identity) && DerivedSameId(identity, id);
}
bool DerivedRecordsDigest(std::span<const WriteAheadLog::Record> records, std::array<std::uint8_t, 32>& digest)
{
    constexpr std::string_view domain = "APFS-DERIVED-WITNESS-RECORDS1";
    if (!ComputeSha256(std::as_bytes(std::span(domain)), digest)) return false;
    for (const auto& r : records) {
        auto plain = EncodeProtectedWalRecord(r);
        if (!plain || !ProtectedSemanticStep(digest, plain.bytes.Bytes())) return false;
    }
    return true;
}
bool DerivedReceiptContext(const WriteAheadLog::Options& o, jc::JournalRecordContext& context)
{
    context = {}; std::array<std::byte, 128> b{};
    constexpr std::string_view domain = "APFS-DERIVED-WITNESS-RESET1";
    std::memcpy(b.data(), domain.data(), domain.size());
    std::memcpy(b.data() + 32, o.protected_persistence->journal_identity.data(), 32);
    std::array<std::uint8_t, 32> volume{};
    if (!ComputeSha256(std::as_bytes(std::span(o.volume_identity)), volume)) return false;
    std::memcpy(b.data() + 64, volume.data(), 32); std::array<std::uint8_t, 32> digest{};
    if (!ComputeSha256(b, digest)) return false;
    std::memcpy(context.operation.data(), digest.data(), 32); context.purpose = 0x57414c03u;
    return true;
}
cc::CryptoResult DerivedEncodeReceipt(const DerivedReceipt& r)
{
    auto encoded = cc::SecureBytes::Allocate(kDerivedReceiptBytes); if (!encoded) return encoded;
    auto b = encoded.bytes.Bytes(); std::memcpy(b.data(), r.authority.data(), 224);
    std::memcpy(b.data() + 464, r.authority.data() + 224, 40);
    ProtectedPut64(b, 224, r.old_id.volume_serial); ProtectedPut64(b, 232, r.old_id.file_id);
    ProtectedPut64(b, 240, r.old_bytes); std::memcpy(b.data() + 248, r.old_hash.data(), 32);
    ProtectedPut64(b, 280, r.stop.position.offset); ProtectedPut64(b, 288, r.stop.matched);
    ProtectedPut64(b, 296, r.stop.position.ordinal); ProtectedPut64(b, 304, r.stop.position.sequence);
    std::memcpy(b.data() + 312, r.stop.position.previous.data(), 32); ProtectedPut64(b, 344, 1);
    std::memcpy(b.data() + 352, r.semantic.data(), 32); ProtectedPut64(b, 384, r.records);
    ProtectedPut64(b, 392, r.candidate_id.volume_serial); ProtectedPut64(b, 400, r.candidate_id.file_id);
    std::memcpy(b.data() + 408, r.candidate.sha256.data(), 32);
    ProtectedPut64(b, 440, r.candidate.bytes); ProtectedPut64(b, 448, r.candidate.records); ProtectedPut64(b, 456, r.candidate.last_sequence);
    return encoded;
}
bool DerivedDecodeReceipt(std::span<const std::byte> plain, DerivedReceipt& r)
{
    if (plain.size() != kDerivedReceiptBytes || std::memcmp(plain.data(), "WRSTV001", 8)) return false;
    const auto b = std::span(reinterpret_cast<const std::uint8_t*>(plain.data()), plain.size());
    if (ReadU64(b, 8) != 1 || ReadU64(b, 344) != 1 ||
        std::any_of(plain.begin() + 504, plain.end(), [](auto v) { return v != std::byte{}; }) ||
        ReadU64(b, 464) < 88 || ReadU64(b, 464) > 4096) return false;
    std::memcpy(r.authority.data(), plain.data(), 224); std::memcpy(r.authority.data() + 224, plain.data() + 464, 40);
    if (ReadU64(b, 224) > UINT32_MAX || ReadU64(b, 392) > UINT32_MAX) return false;
    r.old_id.volume_serial = static_cast<std::uint32_t>(ReadU64(b, 224)); r.old_id.file_id = ReadU64(b, 232);
    r.old_bytes = ReadU64(b, 240); std::memcpy(r.old_hash.data(), b.data() + 248, 32);
    r.stop.position.offset = ReadU64(b, 280); r.stop.matched = ReadU64(b, 288);
    r.stop.position.ordinal = ReadU64(b, 296); r.stop.position.sequence = ReadU64(b, 304);
    std::memcpy(r.stop.position.previous.data(), b.data() + 312, 32);
    std::memcpy(r.semantic.data(), b.data() + 352, 32); r.records = ReadU64(b, 384);
    r.candidate_id.volume_serial = static_cast<std::uint32_t>(ReadU64(b, 392)); r.candidate_id.file_id = ReadU64(b, 400);
    std::memcpy(r.candidate.sha256.data(), b.data() + 408, 32);
    r.candidate.bytes = ReadU64(b, 440); r.candidate.records = ReadU64(b, 448); r.candidate.last_sequence = ReadU64(b, 456);
    // v8 receipts count the retained predecessors as well as the selected packet.
    return r.old_bytes > kProtectedAnchorBytes && r.old_bytes <= (64ull << 20) && r.stop.position.offset >= kProtectedAnchorBytes &&
        r.stop.position.offset < r.old_bytes && r.records >= 2 && r.records <= 4096 && r.stop.matched && r.stop.matched < r.records &&
        r.stop.position.ordinal && r.stop.position.ordinal <= 4097 && r.stop.position.sequence < UINT64_MAX &&
        DerivedNonzero(r.old_hash) && DerivedNonzero(r.semantic) && ProtectedHeadValid(r.candidate) &&
        r.candidate.records == r.records && r.candidate.last_sequence == r.records;
}
bool DerivedPartialHeader(std::span<const std::uint8_t> bytes, std::uint64_t expected, bool wal_header = false)
{
    if (wal_header) return bytes.size() < kProtectedWalHeader.size() &&
        std::equal(bytes.begin(), bytes.end(), kProtectedWalHeader.begin());
    if (bytes.empty() || bytes.size() >= expected || expected > jc::kMaxJournalRecordBytes) return false;
    std::array<std::byte, 64> header{};
    std::memcpy(header.data(), "APFSREC1", 8); ProtectedPut64(header, 8, (std::uint64_t{64} << 32) | 1);
    ProtectedPut64(header, 16, ((expected - 64) << 32) | expected);
    if (!std::equal(bytes.begin(), bytes.begin() + (std::min)(bytes.size(), std::size_t{24}),
        reinterpret_cast<const std::uint8_t*>(header.data()))) return false;
    for (auto i = std::size_t{52}; i < (std::min)(bytes.size(), std::size_t{64}); ++i) if (bytes[i]) return false;
    return true;
}
bool DerivedInspect(const WriteAheadLog::Options& o, std::span<const std::uint8_t> bytes,
    std::span<const WriteAheadLog::Record> expected,
    const std::function<bool(std::span<const WriteAheadLog::Record>)>& typed, DerivedInspection& inspection)
{
    using Wal = WriteAheadLog;
    if (bytes.size() < kProtectedAnchorBytes || !std::equal(kProtectedWalHeader.begin(), kProtectedWalHeader.end(), bytes.begin())) return false;
    std::size_t stop = 16;
    while (stop < bytes.size()) {
        const auto left = bytes.subspan(stop);
        if (left.size() < 80) break;
        if (std::memcmp(left.data(), "APFSREC1", 8) || ReadU32(left, 8) != 1 || ReadU32(left, 12) != 64) return false;
        const auto n = ReadU32(left, 16); if (n < 80 || n > jc::kMaxJournalRecordBytes) return false;
        if (n > left.size()) break; stop += n;
    }
    if (stop < kProtectedAnchorBytes || stop == bytes.size()) return false;
    ProtectedPosition at; ProtectedCheckpoint checkpoint;
    auto decoded = DecodeProtectedWal(bytes.first(stop), o, {o.protected_persistence->read_limits.bytes,
        (std::min)(std::size_t{4096}, o.protected_persistence->read_limits.records)}, o.protected_persistence->max_allocation_bytes, at, &checkpoint);
    ProtectedRecordCleanup wipe{decoded};
    if (decoded.status != Wal::ReadStatus::Ok || checkpoint.floor) return false;
    std::size_t selected = 0; const auto accepted = expected.front().parent_object_id;
    for (std::size_t n = 0; n < decoded.records.size(); ++n) {
        const auto& r = decoded.records[n];
        if (r.sequence != n + 1 || !r.parent_object_id || r.parent_object_id > accepted ||
            (selected && r.parent_object_id != accepted)) return false;
        if (r.parent_object_id == accepted) {
            if (selected >= expected.size()) return false;
            auto row = expected[selected++]; struct Wipe { Wal::Record& r; ~Wipe() { WipeRecord(r); } } guard{row};
            row.sequence = r.sequence;
            auto a = EncodeProtectedWalRecord(r), b = EncodeProtectedWalRecord(row);
            if (!a || !b || a.bytes.Size() != b.bytes.Size() || !std::equal(a.bytes.Bytes().begin(), a.bytes.Bytes().end(), b.bytes.Bytes().begin())) return false;
        }
    }
    if (!selected || selected >= expected.size() || at.sequence == UINT64_MAX - 1 || !typed(decoded.records)) return false;
    auto next = expected[selected]; struct Wipe { Wal::Record& r; ~Wipe() { WipeRecord(r); } } guard{next};
    next.sequence = at.sequence + 1; auto plain = EncodeProtectedWalRecord(next);
    if (!plain || !DerivedPartialHeader(bytes.subspan(stop), plain.bytes.Size() + 80)) return false;
    // Once the whole epoch ID is physically present, use the accepted Open path
    // to distinguish a valid bound immutable slot from missing/corrupt keys. The
    // probe never supplies records or publishes any plaintext result.
    if (bytes.size() - stop >= 40) {
        std::vector<std::uint8_t> probe(plain.bytes.Size() + 80);
        std::memcpy(probe.data(), bytes.data() + stop, (std::min)(bytes.size() - stop, std::size_t{64}));
        jc::JournalRecordContext context{}; if (!ProtectedContext(o, at, context)) return false;
        auto result = jc::ProtectedJournalEpoch::Open(o.protected_persistence->key_directory.wstring(),
            o.protected_persistence->source_binding, context, std::as_bytes(std::span(probe)));
        if (!result && result.status.error != jc::JournalError::IntegrityFailure) return false;
    }
    inspection = {at, selected}; return true;
}
struct DerivedFile
{
    std::filesystem::path path;
    ProtectedHandle handle;
    std::uint64_t bytes = 0;
    PhysicalFileIdentity id{};
    std::array<std::uint8_t, 32> hash{};
};
bool DerivedRefresh(DerivedFile& file, std::uint64_t cap)
{ return ProtectedExactHandle(file.handle.value, file.path, false) && DerivedHashFile(file.handle.value, cap, file.bytes, file.hash, file.id); }
bool DerivedReadReceipt(DerivedFile& file, const WriteAheadLog::Options& o, DerivedReceipt& receipt)
{
    if (file.bytes != kDerivedReceiptFrame) return false;
    std::vector<std::uint8_t> b; if (!ProtectedReadBounded(file.handle.value, b, kDerivedReceiptFrame)) return false;
    jc::JournalRecordContext context{}; if (!DerivedReceiptContext(o, context)) return false;
    auto result = jc::ProtectedJournalEpoch::Open(o.protected_persistence->key_directory.wstring(),
        o.protected_persistence->source_binding, context, std::as_bytes(std::span(b)));
    return result && DerivedDecodeReceipt(result.bytes.Bytes(), receipt);
}
bool DerivedCandidate(DerivedFile& file, const WriteAheadLog::Options& o, std::span<const WriteAheadLog::Record> expected,
    const std::array<std::uint8_t, 32>& semantic, ProtectedHead& head)
{
    std::vector<std::uint8_t> b; WriteAheadLog::ReadResult result; ProtectedRecordCleanup wipe{result}; ProtectedCheckpoint proof;
    std::array<std::uint8_t, 32> digest{};
    return ProtectedReadBlob(file.handle.value, file.path, o, b, result, head, proof) && !proof.floor &&
        result.records.size() == expected.size() && DerivedRecordsDigest(result.records, digest) && digest == semantic;
}
}

WriteAheadLog::CompactionResult WriteAheadLog::RebuildDerivedWitnessV4(
    std::span<const Record> expected, const DerivedWitnessAuthorizer& authorize,
    const std::function<bool()>& original_barrier, ProtectedHistoryHead& replacement) const
{ return RebuildDerivedWitness(4, expected, authorize, original_barrier, replacement); }

WriteAheadLog::CompactionResult WriteAheadLog::RebuildDerivedWitnessV8(
    std::span<const Record> expected, const DerivedWitnessAuthorizer& authorize,
    const std::function<bool()>& original_barrier, ProtectedHistoryHead& replacement) const
{ return RebuildDerivedWitness(8, expected, authorize, original_barrier, replacement); }

WriteAheadLog::CompactionResult WriteAheadLog::RebuildDerivedWitness(
    std::uint64_t expected_version, std::span<const Record> expected, const DerivedWitnessAuthorizer& authorize,
    const std::function<bool()>& original_barrier, ProtectedHistoryHead& replacement) const
{
    std::lock_guard<std::recursive_mutex> lock(WalOperationMutex(options_.path)); replacement = {};
    bool wrote = false;
    const auto cut = [&](std::string_view stage) { return fault_injection_hook_ && fault_injection_hook_(stage); };
    const auto failed = [&]() {
        replacement = {};
        if (wrote && protected_state_) { protected_state_->poisoned = true; (void)CloseAppendFileHandle(); }
        return wrote ? CompactionResult::BytesMayHavePersisted : CompactionResult::RejectedBeforeWrite;
    };
    try
    {
        if ((expected_version != 4 && expected_version != 8) || continuation_admission_ || !options_.protected_persistence || !authorize || !original_barrier || !ProtectedConfigValid(options_) || expected.size() < 2 || expected.size() > 226 ||
            expected.size() > options_.protected_persistence->read_limits.records) return failed();
        DerivedWitnessResetAuthority a;
        a.source_binding = options_.protected_persistence->source_binding;
        a.accepted_sequence = expected.front().parent_object_id; a.transaction_id = expected.front().transaction_id; a.inode = expected.front().object_id;
        if (expected.front().inline_payload.size() < 88 || expected.back().inline_payload.size() != 88) return failed();
        const auto first = std::span(reinterpret_cast<const std::uint8_t*>(expected.front().inline_payload.data()), expected.front().inline_payload.size());
        const auto terminal = std::span(reinterpret_cast<const std::uint8_t*>(expected.back().inline_payload.data()), expected.back().inline_payload.size());
        a.template_bytes = ReadU64(first, 40); a.body_bytes = ReadU64(terminal, 40);
        if (ReadU64(first, 48) != 32) return failed();
        std::memcpy(a.template_sha256.data(), first.data() + 56, 32); std::memcpy(a.body_sha256.data(), terminal.data() + 56, 32);
        if (!a.accepted_sequence || a.accepted_sequence == UINT64_MAX || !a.transaction_id || a.transaction_id == UINT64_MAX || a.inode < 16 ||
            !a.template_bytes || a.template_bytes > kDerivedBodyLimit || a.body_bytes < 88 || a.body_bytes > kDerivedBodyLimit ||
            !DerivedNonzero(a.template_sha256) || !DerivedNonzero(a.body_sha256)) return failed();
        const auto next_path = ProtectedSibling(options_.path, L".wreset.next"), intent_path = ProtectedSibling(options_.path, L".wreset.intent");
        const auto old_path = ProtectedSibling(options_.path, L".wreset.old");
        std::array<std::uint8_t, 32> dummy{};
        if (!ProtectedPathSyntax(next_path) || !ProtectedPathSyntax(intent_path) || !ProtectedPathSyntax(old_path) ||
            !ProtectedPathSyntax(ProtectedArchive(options_.path, L".wrsaved.", dummy)) ||
            !ProtectedPathSyntax(ProtectedArchive(options_.path, L".wrdone.", dummy)) ||
            !ProtectedPathSyntax(std::filesystem::path(ProtectedArchive(options_.path, L".wrfail.", dummy).wstring() + L".15"))) return failed();
        std::vector<std::byte> body;
        struct BodyCleanup { std::vector<std::byte>& bytes; ~BodyCleanup() { if (!bytes.empty()) SecureZeroMemory(bytes.data(), bytes.size()); } } body_cleanup{body};
        body.reserve(static_cast<std::size_t>(a.body_bytes));
        std::uint64_t candidate_bytes = kProtectedAnchorBytes;
        for (std::size_t n = 0; n < expected.size(); ++n)
        {
            const auto& r = expected[n];
            if (r.volume_identity != options_.volume_identity || r.sequence != n + 1 || r.operation != OperationKind::Write ||
                r.state != RecordState::Prepared || r.parent_object_id != a.accepted_sequence || r.transaction_id != a.transaction_id ||
                r.object_id != a.inode || r.flags || r.payload_spool_id || r.payload_offset || r.unlink_outcome ||
                !r.secondary_path_utf8.empty() || r.inline_payload.empty() || r.inline_payload.size() > 4096 || !InlinePayloadIsConsistent(r)) return failed();
            if (n + 1 < expected.size()) {
                if (r.path_utf8 != kDerivedChunkPath || r.logical_offset != body.size() ||
                    body.size() >= a.body_bytes || r.inline_payload.size() != (std::min)(std::uint64_t{4096}, a.body_bytes - body.size())) return failed();
                body.insert(body.end(), r.inline_payload.begin(), r.inline_payload.end());
            } else {
                const auto b = std::span(reinterpret_cast<const std::uint8_t*>(r.inline_payload.data()), r.inline_payload.size());
                if (r.path_utf8 != kDerivedEndPath || r.logical_offset || b.size() != 88 || ReadU64(b, 0) != 2 ||
                    ReadU64(b, 8) != a.accepted_sequence || ReadU64(b, 16) != a.transaction_id || ReadU64(b, 24) != a.inode ||
                    ReadU64(b, 32) != expected.size() - 1 || ReadU64(b, 40) != a.body_bytes || ReadU64(b, 48) != 32 ||
                    std::memcmp(b.data() + 56, a.body_sha256.data(), 32)) return failed();
            }
            auto plain = EncodeProtectedWalRecord(r); if (!plain || plain.bytes.Size() > UINT64_MAX - candidate_bytes - 80) return failed();
            candidate_bytes += plain.bytes.Size() + 80;
        }
        std::array<std::uint8_t, 32> body_hash{}, semantic{};
        if (body.size() != a.body_bytes || ReadU64(std::span(reinterpret_cast<const std::uint8_t*>(body.data()), body.size()), 0) != expected_version ||
            ReadU64(std::span(reinterpret_cast<const std::uint8_t*>(body.data()), body.size()), 8) != a.accepted_sequence ||
            ReadU64(std::span(reinterpret_cast<const std::uint8_t*>(body.data()), body.size()), 16) != a.transaction_id ||
            ReadU64(std::span(reinterpret_cast<const std::uint8_t*>(body.data()), body.size()), 24) != a.inode ||
            !ComputeSha256(body, body_hash) || body_hash != a.body_sha256 || !DerivedRecordsDigest(expected, semantic)) return failed();
        const auto& limits = *options_.protected_persistence;
        if (candidate_bytes > options_.max_bytes || candidate_bytes > limits.read_limits.bytes ||
            !EnsureProtectedState(true) || !EnsureWriterLease(true) || !CloseAppendFileHandle()) return failed();
        // A reset cannot adopt or resolve any ordinary/protected compaction debt.
        WIN32_FIND_DATAW found{};
        auto search = FindFirstFileW((options_.path.wstring() + L".compact*").c_str(), &found);
        if (search != INVALID_HANDLE_VALUE) { FindClose(search); return failed(); }
        if (GetLastError() != ERROR_FILE_NOT_FOUND) return failed();
        std::array<std::byte, 264> authority{};
        bool valid = true;
        const auto open = [&](const std::filesystem::path& path, std::uint64_t cap) {
            auto f = std::make_unique<DerivedFile>(); f->path = path;
            auto opened = ProtectedOpenMaintenance(path, valid); f->handle.value = std::exchange(opened.value, INVALID_HANDLE_VALUE);
            if (f->handle.value == INVALID_HANDLE_VALUE) return std::unique_ptr<DerivedFile>{};
            if (!DerivedRefresh(*f, cap)) valid = false;
            return f;
        };
        auto canonical = open(options_.path, options_.max_bytes);
        std::vector<std::unique_ptr<DerivedFile>> files;
        DerivedFile* next = nullptr; DerivedFile* intent = nullptr; DerivedFile* old = nullptr; DerivedFile* done = nullptr;
        std::uint64_t all_bytes = canonical ? canonical->bytes : 0; unsigned failed_files = 0, archive_files = 0;
        DerivedReceipt receipt{}; bool have_receipt = false;
        search = FindFirstFileW((options_.path.wstring() + L".wr*").c_str(), &found);
        if (search != INVALID_HANDLE_VALUE)
        {
            struct Find { HANDLE h; ~Find() { FindClose(h); } } close{search};
            do {
                if (files.size() >= 67 || (found.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT))) return failed();
                const auto path = options_.path.parent_path() / found.cFileName;
                if (!ProtectedPathSyntax(path)) return failed();
                const auto name = path.wstring(); const auto base = options_.path.wstring();
                const bool pending = name == next_path.wstring() || name == intent_path.wstring() || name == old_path.wstring();
                const bool saved = name.starts_with(base + L".wrsaved."), completed = name.starts_with(base + L".wrdone.");
                const bool failed_artifact = name.starts_with(base + L".wrfail.");
                if (!pending && !saved && !completed && !failed_artifact) return failed();
                const auto cap = name == intent_path.wstring() || completed ? kDerivedReceiptFrame : options_.max_bytes;
                auto f = open(path, cap); if (!valid || !f) return failed(); all_bytes += f->bytes;
                if (all_bytes > limits.read_limits.bytes) return failed();
                if (name == next_path.wstring()) next = f.get();
                else if (name == intent_path.wstring()) intent = f.get();
                else if (name == old_path.wstring()) old = f.get();
                else {
                    if (++archive_files > 64 || (failed_artifact && ++failed_files > 32)) return failed();
                    const auto prefix = saved ? L".wrsaved." : completed ? L".wrdone." : L".wrfail.";
                    const auto exact = ProtectedArchive(options_.path, prefix, f->hash).wstring();
                    bool named = name == exact && !failed_artifact;
                    if (failed_artifact) for (unsigned n = 0; n < 16; ++n) named |= name == exact + L"." + std::to_wstring(n);
                    if (!named || (saved && f->bytes <= kProtectedAnchorBytes)) return failed();
                    if (completed) {
                        DerivedReceipt prior; if (!DerivedReadReceipt(*f, options_, prior)) return failed();
                        const auto scope = std::span(reinterpret_cast<const std::uint8_t*>(prior.authority.data()), prior.authority.size());
                        const bool selected_v8 = expected_version == 8 && ReadU64(scope, 112) == a.accepted_sequence &&
                            ReadU64(scope, 120) == a.transaction_id && ReadU64(scope, 136) == a.inode &&
                            ReadU64(scope, 144) == a.template_bytes && ReadU64(scope, 152) == a.body_bytes &&
                            std::memcmp(scope.data() + 160, a.template_sha256.data(), 32) == 0 &&
                            std::memcmp(scope.data() + 192, a.body_sha256.data(), 32) == 0;
                        if (selected_v8 || (expected_version == 4 && prior.semantic == semantic &&
                            prior.records == expected.size() && prior.candidate.bytes == candidate_bytes)) {
                            if (done) return failed(); done = f.get(); receipt = prior;
                        }
                    }
                }
                files.push_back(std::move(f));
            } while (FindNextFileW(search, &found));
            if (GetLastError() != ERROR_NO_MORE_FILES) return failed();
        }
        else if (GetLastError() != ERROR_FILE_NOT_FOUND) return failed();
        if (!valid) return failed();
        wrote = next || intent || old;
        const auto held_bytes = (canonical ? canonical->bytes : 0) + (next ? next->bytes : 0) + (old ? old->bytes : 0);
        const auto conservative = held_bytes + candidate_bytes + a.template_bytes + a.body_bytes + kDerivedReceiptFrame;
        const auto record_cap = (std::min)(std::size_t{4096}, limits.read_limits.records);
        if (conservative > limits.max_allocation_bytes / 16 ||
            record_cap + expected.size() > (limits.max_allocation_bytes - conservative * 16) / (2 * sizeof(Record) + 64)) return failed();
        if (intent && intent->bytes == kDerivedReceiptFrame) {
            if (!DerivedReadReceipt(*intent, options_, receipt) || done) return failed();
            have_receipt = true;
        } else if (done) {
            if (next || intent || old) return failed();
            have_receipt = true;
        }
        DerivedFile* raw = nullptr; DerivedFile* replacement_file = nullptr;
        DerivedInspection inspection;
        const auto matches_raw = [&](DerivedFile* f) {
            return f && DerivedSameId(f->id, receipt.old_id) && f->bytes == receipt.old_bytes && f->hash == receipt.old_hash;
        };
        if (have_receipt) {
            const auto archive_path = ProtectedArchive(options_.path, L".wrsaved.", receipt.old_hash);
            DerivedFile* archive = nullptr;
            for (auto& f : files) if (f->path == archive_path) archive = f.get();
            for (auto* f : {canonical.get(), old, archive}) if (matches_raw(f)) { if (raw) return failed(); raw = f; }
            if (!raw || (old && raw != old) || (archive && raw != archive)) return failed();
            if (raw == canonical.get()) { if (!next || done) return failed(); replacement_file = next; }
            else {
                if (canonical && next) return failed(); replacement_file = canonical ? canonical.get() : next;
                if (!replacement_file || (done && !canonical)) return failed();
            }
            if (!DerivedSameId(replacement_file->id, receipt.candidate_id)) return failed();
        } else {
            if (!canonical || old || archive_files > 62 || failed_files + static_cast<unsigned>(!!next) + static_cast<unsigned>(!!intent) > 32) return failed();
            raw = canonical.get();
            if (!PathIsAbsent(ProtectedArchive(options_.path, L".wrsaved.", raw->hash))) return failed();
        }
        unsigned key_entries = 0;
        for (const auto& entry : std::filesystem::directory_iterator(limits.key_directory)) {
            if (++key_entries >= 4096) return failed();
            const auto attributes = GetFileAttributesW(entry.path().c_str());
            if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT))) return failed();
        }
        std::vector<std::uint8_t> raw_bytes;
        std::vector<Record> candidate_records(expected.begin(), expected.end());
        struct CandidateCleanup {
            std::vector<Record>& records;
            ~CandidateCleanup() { for (auto& record : records) WipeRecord(record); }
        } candidate_cleanup{candidate_records};
        const auto typed = [&](std::span<const Record> prefix) {
            DerivedWitnessResetAuthority minted;
            if (!authorize(prefix, minted) || minted.source_binding != a.source_binding || !DerivedNonzero(minted.original_journal_identity) ||
                !DerivedNonzero(minted.scope_binding) || minted.accepted_sequence != a.accepted_sequence || minted.transaction_id != a.transaction_id ||
                !minted.preimage_xid || minted.preimage_xid == UINT64_MAX || minted.inode != a.inode || minted.template_bytes != a.template_bytes ||
                minted.template_sha256 != a.template_sha256 || minted.body_bytes != a.body_bytes || minted.body_sha256 != a.body_sha256 ||
                minted.authorization_bytes != expected.front().inline_payload.size() || minted.authorization_sha256 != expected.front().payload_sha256) return false;
            // v8 retained owners and spent-authorization receipts remain live
            // authority on restart. Keep their exact authenticated records.
            if (expected_version == 8) {
                const auto selected = std::find_if(prefix.begin(), prefix.end(),
                    [&](const auto& record) { return record.parent_object_id == a.accepted_sequence; });
                const auto prior = static_cast<std::size_t>(selected - prefix.begin());
                if (prior > 4096 - expected.size()) return false;
                for (auto& record : candidate_records) WipeRecord(record);
                candidate_records.assign(prefix.begin(), selected);
                for (const auto& record : expected) {
                    candidate_records.push_back(record);
                    candidate_records.back().sequence = candidate_records.size();
                }
                candidate_bytes = kProtectedAnchorBytes;
                for (const auto& record : candidate_records) {
                    auto plain = EncodeProtectedWalRecord(record);
                    if (!plain || plain.bytes.Size() > UINT64_MAX - candidate_bytes - 80) return false;
                    candidate_bytes += plain.bytes.Size() + 80;
                }
                if (candidate_records.size() > limits.read_limits.records || candidate_bytes > options_.max_bytes ||
                    candidate_bytes > limits.read_limits.bytes || !DerivedRecordsDigest(candidate_records, semantic)) return false;
                const auto held = held_bytes + candidate_bytes + a.template_bytes + a.body_bytes + kDerivedReceiptFrame;
                if (held > limits.max_allocation_bytes / 16 || record_cap + candidate_records.size() >
                    (limits.max_allocation_bytes - held * 16) / (2 * sizeof(Record) + 64)) return false;
            }
            a = minted;
            std::memcpy(authority.data(), "WRSTV001", 8); ProtectedPut64(authority, 8, 1);
            std::memcpy(authority.data() + 16, a.source_binding.data(), 32); std::memcpy(authority.data() + 48, a.original_journal_identity.data(), 32);
            std::memcpy(authority.data() + 80, a.scope_binding.data(), 32); ProtectedPut64(authority, 112, a.accepted_sequence);
            ProtectedPut64(authority, 120, a.transaction_id); ProtectedPut64(authority, 128, a.preimage_xid); ProtectedPut64(authority, 136, a.inode);
            ProtectedPut64(authority, 144, a.template_bytes); ProtectedPut64(authority, 152, a.body_bytes);
            std::memcpy(authority.data() + 160, a.template_sha256.data(), 32); std::memcpy(authority.data() + 192, a.body_sha256.data(), 32);
            ProtectedPut64(authority, 224, a.authorization_bytes); std::memcpy(authority.data() + 232, a.authorization_sha256.data(), 32);
            return true;
        };
        if (!ProtectedReadBounded(raw->handle.value, raw_bytes, options_.max_bytes) || !DerivedInspect(options_, raw_bytes, expected, typed, inspection)) return failed();
        if (have_receipt) {
            ProtectedHead head;
            if (receipt.semantic != semantic || receipt.records != candidate_records.size() || receipt.candidate.bytes != candidate_bytes ||
                !DerivedCandidate(*replacement_file, options_, candidate_records, semantic, head) || head != receipt.candidate) return failed();
        }
        if (have_receipt && (receipt.authority != authority || receipt.stop.matched != inspection.matched || receipt.stop.position.offset != inspection.position.offset ||
            receipt.stop.position.ordinal != inspection.position.ordinal || receipt.stop.position.sequence != inspection.position.sequence ||
            receipt.stop.position.previous != inspection.position.previous)) return failed();
        if (!have_receipt) {
            for (auto* f : {next, intent}) if (f) {
                std::vector<std::uint8_t> b; if (!ProtectedReadBounded(f->handle.value, b, f == intent ? kDerivedReceiptFrame : candidate_bytes)) return failed();
                if (f == intent) { if (!b.empty() && !DerivedPartialHeader(b, kDerivedReceiptFrame)) return failed(); }
                else if (b.size() == candidate_bytes) { ProtectedHead h; if (!DerivedCandidate(*f, options_, candidate_records, semantic, h)) return failed(); }
                else if (b.size() > candidate_bytes || !std::equal(b.begin(), b.begin() + (std::min)(b.size(), kProtectedWalHeader.size()), kProtectedWalHeader.begin())) return failed();
            }
        }
        // These barriers are unconditional on every entry, including reopened
        // complete receipts/candidates and already-durable original acceptance.
        if (cut("wreset-before-original-barrier") || !original_barrier() || cut("wreset-after-original-barrier") ||
            cut("wreset-raw-flush") || !FlushFileBuffers(raw->handle.value) || !DerivedRefresh(*raw, options_.max_bytes) ||
            raw->bytes != raw_bytes.size() || !ComputeSha256(std::as_bytes(std::span(raw_bytes)), body_hash) || raw->hash != body_hash ||
            cut("wreset-after-raw-flush")) return failed();
        for (auto& f : files) if (!FlushFileBuffers(f->handle.value)) return failed();
        if (!have_receipt)
        {
            for (auto* f : {next, intent}) if (f) {
                std::filesystem::path quarantine;
                for (unsigned n = 0; n < 16; ++n) {
                    auto p = std::filesystem::path(ProtectedArchive(options_.path, L".wrfail.", f->hash).wstring() + L"." + std::to_wstring(n));
                    if (PathIsAbsent(p)) { quarantine = std::move(p); break; }
                }
                if (quarantine.empty() || !ProtectedPathSyntax(quarantine) || cut("wreset-before-quarantine") ||
                    !RenameOpenedFileWithoutReplacing(f->handle.value, quarantine)) return failed();
                wrote = true; f->path = quarantine;
                if (!ProtectedExactHandle(f->handle.value, f->path, false) || cut("wreset-after-quarantine") ||
                    cut("wreset-quarantine-flush") || !FlushFileBuffers(f->handle.value)) return failed();
            }
            next = intent = nullptr;
            if (cut("wreset-before-epoch")) return failed();
            wrote = true; // Slot publication can persist even on a failed acquisition.
            auto epoch = jc::ProtectedJournalEpoch::AcquireWriter(limits.key_directory.wstring(), limits.source_binding);
            if (!epoch || cut("wreset-after-epoch")) return failed();
            std::vector<std::uint8_t> encrypted(kProtectedWalHeader.begin(), kProtectedWalHeader.end()); encrypted.reserve(static_cast<std::size_t>(candidate_bytes));
            ProtectedPosition position; position.offset = 16;
            const auto seal = [&](std::span<const std::byte> plain, std::uint64_t sequence) {
                jc::JournalRecordContext context{}; if (!ProtectedContext(options_, position, context)) return false;
                auto frame = epoch.epoch->Seal(context, plain); if (!frame) return false;
                const auto b = frame.bytes.Bytes(); encrypted.insert(encrypted.end(), reinterpret_cast<const std::uint8_t*>(b.data()), reinterpret_cast<const std::uint8_t*>(b.data() + b.size()));
                return ProtectedAdvance(position, b, sequence);
            };
            if (!seal(std::as_bytes(std::span(kProtectedAnchor)), 0)) return failed();
            for (const auto& r : candidate_records) { auto plain = EncodeProtectedWalRecord(r); if (!plain || !seal(plain.bytes.Bytes(), r.sequence)) return failed(); }
            if (encrypted.size() != candidate_bytes) return failed();
            const auto create = [&](const std::filesystem::path& path) {
                auto f = std::make_unique<DerivedFile>(); f->path = path;
                f->handle.value = OpenWalFile(path, GENERIC_READ | GENERIC_WRITE | DELETE, FILE_SHARE_READ, nullptr, CREATE_NEW,
                    FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH, nullptr);
                if (f->handle.value == INVALID_HANDLE_VALUE || !ProtectedExactHandle(f->handle.value, path, false)) return std::unique_ptr<DerivedFile>{};
                return f;
            };
            const auto write = [&](DerivedFile& f, std::span<const std::uint8_t> b, bool partial) {
                DWORD written = 0; const auto n = static_cast<DWORD>(partial ? (std::min)(b.size(), std::size_t{13}) : b.size());
                return WriteFile(f.handle.value, b.data(), n, &written, nullptr) && written == n;
            };
            if (cut("wreset-before-candidate-create")) return failed();
            auto candidate = create(next_path); if (!candidate) return failed(); next = candidate.get(); files.push_back(std::move(candidate));
            if (cut("wreset-after-candidate-create")) return failed();
            if (cut("wreset-partial-candidate-write")) { (void)write(*next, encrypted, true); return failed(); }
            if (!write(*next, encrypted, false) || cut("wreset-after-candidate-write") || cut("wreset-candidate-flush") ||
                !FlushFileBuffers(next->handle.value) || cut("wreset-after-candidate-flush") || !DerivedRefresh(*next, options_.max_bytes)) return failed();
            ProtectedHead head;
            if (!DerivedCandidate(*next, options_, candidate_records, semantic, head) || cut("wreset-after-candidate-readback")) return failed();
            receipt.authority = authority; receipt.old_id = raw->id; receipt.old_bytes = raw->bytes; receipt.old_hash = raw->hash;
            receipt.stop = inspection; receipt.semantic = semantic; receipt.records = candidate_records.size(); receipt.candidate_id = next->id; receipt.candidate = head;
            auto plain = DerivedEncodeReceipt(receipt); if (!plain) return failed();
            jc::JournalRecordContext context{}; if (!DerivedReceiptContext(options_, context)) return failed();
            auto sealed = epoch.epoch->Seal(context, plain.bytes.Bytes()); if (!sealed || sealed.bytes.Size() != kDerivedReceiptFrame) return failed();
            if (cut("wreset-before-receipt-create")) return failed();
            auto receipt_file = create(intent_path); if (!receipt_file) return failed(); intent = receipt_file.get(); files.push_back(std::move(receipt_file));
            if (cut("wreset-after-receipt-create")) return failed();
            const auto bytes = std::span(reinterpret_cast<const std::uint8_t*>(sealed.bytes.Bytes().data()), sealed.bytes.Size());
            if (cut("wreset-partial-receipt-write")) { (void)write(*intent, bytes, true); return failed(); }
            if (!write(*intent, bytes, false) || cut("wreset-after-receipt-write") || cut("wreset-receipt-flush") ||
                !FlushFileBuffers(intent->handle.value) || cut("wreset-after-receipt-flush") || !DerivedRefresh(*intent, kDerivedReceiptFrame)) return failed();
            DerivedReceipt checked;
            if (!DerivedReadReceipt(*intent, options_, checked) || checked.authority != authority || checked.candidate != head ||
                cut("wreset-after-receipt-readback")) return failed();
            replacement_file = next; have_receipt = true;
        }
        if (!have_receipt || !replacement_file) return failed();
        if (intent && !PathIsAbsent(ProtectedArchive(options_.path, L".wrdone.", intent->hash))) return failed();
        if (intent && !FlushFileBuffers(intent->handle.value)) return failed();
        if (cut("wreset-ready-candidate-flush") || !FlushFileBuffers(replacement_file->handle.value)) return failed();
        const auto move = [&](DerivedFile& f, const std::filesystem::path& destination, std::string_view before,
            std::string_view after, std::string_view flush) {
            if (!PathIsAbsent(destination) || cut(before) || !RenameOpenedFileWithoutReplacing(f.handle.value, destination)) return false;
            wrote = true; f.path = destination;
            return ProtectedExactHandle(f.handle.value, f.path, false) && !cut(after) && !cut(flush) && FlushFileBuffers(f.handle.value);
        };
        if (raw->path == options_.path && !move(*raw, old_path, "wreset-before-save", "wreset-after-save", "wreset-saved-flush")) return failed();
        if (replacement_file->path != options_.path && !move(*replacement_file, options_.path,
            "wreset-before-promote", "wreset-after-promote", "wreset-promoted-flush")) return failed();
        ProtectedHead checked;
        if (!DerivedCandidate(*replacement_file, options_, candidate_records, semantic, checked) || checked != receipt.candidate ||
            cut("wreset-after-promoted-readback")) return failed();
        const auto archive_path = ProtectedArchive(options_.path, L".wrsaved.", receipt.old_hash);
        if (raw->path != archive_path && !move(*raw, archive_path, "wreset-before-archive", "wreset-after-archive", "wreset-archive-flush")) return failed();
        if (!DerivedRefresh(*raw, options_.max_bytes) || !matches_raw(raw) || cut("wreset-after-archive-readback")) return failed();
        if (intent) {
            const auto settled = ProtectedArchive(options_.path, L".wrdone.", intent->hash);
            if (!move(*intent, settled, "wreset-before-settle", "wreset-after-settle", "wreset-settled-flush")) return failed();
            DerivedReceipt proof; if (!DerivedReadReceipt(*intent, options_, proof) || proof.authority != authority || proof.candidate != checked) return failed();
        }
        if (cut("wreset-before-reopen")) return failed();
        canonical.reset(); files.clear();
        protected_state_->poisoned = false; protected_state_->head_mismatch = false;
        if (!CaptureProtectedHistoryHead(replacement) || replacement != receipt.candidate || cut("wreset-after-reopen")) return failed();
        return CompactionResult::Succeeded;
    }
    catch (...) { return failed(); }
}

void WriteAheadLog::Reconfigure(Options options)
{
    auto reconfigure = [&]()
    {
        UnregisterPath();
        (void)CloseAppendHandle();
        protected_state_.reset();
        continuation_admission_.reset(); continuation_authority_.reset();
        options_ = std::move(options);
        startup_journal_state_ = StartupJournalState::Unobserved;
        startup_writer_lease_generation_ = 0;
        startup_evidence_valid_ = false;
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

bool WriteAheadLog::AnotherStartupEvidenceOwnerForPath() const
{
    const auto key = WalRegistryKey(options_.path);
    std::lock_guard<std::mutex> lock(GetWalRegistryMutex());
    const auto found = GetWalRegistry().find(key);
    if (found == GetWalRegistry().end()) return false;
    return std::any_of(found->second.begin(), found->second.end(), [&](const auto* owner)
    {
        return owner != nullptr && owner != this && owner->preserve_startup_evidence_;
    });
}

bool WriteAheadLog::TryTransferRegisteredHandlesForPath(
    const std::filesystem::path& path,
    const WriteAheadLog* successor)
{
    const auto key = WalRegistryKey(path);
    if (key.empty() || successor == nullptr || successor->options_.protected_persistence ||
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
    if (std::any_of(found->second.begin(), found->second.end(), [&](const auto* owner)
        { return owner != nullptr && owner != successor && owner->preserve_startup_evidence_; }))
        return false;
    for (auto* owner : found->second)
    {
        if (owner == nullptr || owner == successor || owner->options_.protected_persistence || owner->preserve_startup_evidence_ ||
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
    if (options_.protected_persistence) return EnsureProtectedAppendHandle(allow_create);
    if (preserve_startup_evidence_)
        return append_handle_ != nullptr && startup_evidence_valid_ &&
            writer_lease_handle_ != nullptr && writer_lease_generation_ == startup_writer_lease_generation_ &&
            ValidatedAppendLeaseGeneration(true) != 0 && StartupCompactionNamespaceIsProven();
    if (append_handle_ != nullptr)
    {
        return writer_lease_handle_ != nullptr;
    }
    if (AnotherStartupEvidenceOwnerForPath()) return false;
    if (!EnsureWriterLease())
    {
        return false;
    }
    if (preserve_startup_evidence_ && !StartupCompactionNamespaceIsProven())
    {
        (void)CloseWriterLeaseHandle();
        return false;
    }

    const auto wide_path = options_.path.wstring();
    const auto intent_wide = CompactionIntentPath(options_.path).wstring();
    const auto intent_attributes = WalFileAttributes(intent_wide.c_str());
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
        auto* path_guard = OpenWalFile(
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
            handle = OpenWalFile(
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
            if (!preserve_startup_evidence_ && attempt == 0 && RestoreMissingCanonicalForPublishArmedIntent())
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

        handle = OpenWalFile(
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
    // A competing RID can obtain its own pipe lease. Namespace cleanup therefore
    // also requires ownership of the validated canonical file's write handle.
    if (!preserve_startup_evidence_ && !CleanupPreIntentCompactionOrphans())
    {
        (void)CloseAppendHandle();
        return false;
    }
    if (resolve_compaction_intent && !preserve_startup_evidence_ && !ResolvePendingCompactionIntent())
    {
        (void)CloseAppendHandle();
        return false;
    }
    if (resolve_compaction_intent && !preserve_startup_evidence_ && pending_compaction_intent)
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
{ return EnsureWriterLease(false); }

bool WriteAheadLog::EnsureWriterLease(bool allow_protected_maintenance) const
{
    if (!allow_protected_maintenance && !DerivedWitnessNamespaceSettled(options_.path)) return false;
    if (!allow_protected_maintenance && !continuation_admission_ && !ContinuationNamespaceAbsent(options_.path)) return false;
    if (options_.protected_persistence && !EnsureProtectedState(allow_protected_maintenance)) return false;
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
    if (protected_state_)
    {
        protected_state_->verified = false;
        protected_state_->position = {};
        protected_state_->epoch.reset();
    }
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
    if (protected_state_) protected_state_->epoch.reset();
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
    auto* existing_handle = OpenWalFile(
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
    const auto absolute_wal = AbsoluteWalFilesystemPath(options_.path, ec);
    if (ec || absolute_wal.parent_path().empty())
    {
        return false;
    }
    const auto prefix = absolute_wal.filename().wstring() + L".compact.";
    bool removed = false;
    std::filesystem::directory_iterator entry(WalIoPath(absolute_wal.parent_path()), ec);
    const std::filesystem::directory_iterator end;
    while (!ec && entry != end)
    {
        const auto candidate = absolute_wal.parent_path() / entry->path().filename();
        const auto filename = candidate.filename().wstring();
        if (HasExactNumericPairSuffix(filename, prefix))
        {
            auto* candidate_handle = OpenWalFile(
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
    const auto absolute_wal = AbsoluteWalFilesystemPath(options_.path, ec);
    if (ec || absolute_wal.parent_path().empty())
    {
        return false;
    }
    const auto intent_path = CompactionIntentPath(absolute_wal);
    const auto intent_attributes = WalFileAttributes(intent_path.wstring().c_str());
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
    for (std::filesystem::directory_iterator entry(WalIoPath(absolute_wal.parent_path()), ec), end;
         !ec && entry != end;
         entry.increment(ec))
    {
        const auto filename = entry->path().filename().wstring();
        if (std::any_of(prefixes.begin(), prefixes.end(), [&](const auto& prefix)
            {
                return HasExactNumericPairSuffix(filename, prefix);
            }))
        {
            candidates.push_back(absolute_wal.parent_path() / entry->path().filename());
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
        opened.handle = OpenWalFile(
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

    const auto intent_before_delete = WalFileAttributes(intent_path.wstring().c_str());
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
    auto* guard_handle = OpenWalFile(
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
    auto* intent_handle = OpenWalFile(
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
    auto* intent_guard = OpenWalFile(
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
    auto* predecessor_guard = OpenWalFile(
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
    const auto canonical_attributes = WalFileAttributes(canonical_wide.c_str());
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
    const auto guard_attributes = WalFileAttributes(predecessor_guard_path.wstring().c_str());
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
    auto* intent_guard = OpenWalFile(
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
    auto* predecessor_guard = OpenWalFile(
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
    auto* intent_handle = OpenWalFile(
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
    const auto attributes = WalFileAttributes(intent_wide.c_str());
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

bool WriteAheadLog::AcquireExistingRepairLease(std::string& error) const
{
    if (options_.protected_persistence) { error = "Protected journal repair is unsupported; evidence retained."; return false; }
    std::lock_guard<std::recursive_mutex> lock(WalOperationMutex(options_.path));
    const auto fail = [&](const char* why) { error = why; return false; };
    if (options_.path.empty() || append_handle_ || !EnsureWriterLease())
        return fail("The canonical journal has an active owner or invalid path.");
    // The normal WAL opener may repair compaction receipts/tails. This admission
    // deliberately never enters that path. Any receipt belongs to its original owner.
    WIN32_FIND_DATAW found{};
    const auto pattern = options_.path.wstring() + L".compact*";
    HANDLE search = FindFirstFileW(WalIoPath(pattern).c_str(), &found);
    if (search != INVALID_HANDLE_VALUE) {
        FindClose(search); return fail("Existing compaction evidence requires its original recovery owner.");
    }
    if (GetLastError() != ERROR_FILE_NOT_FOUND)
        return fail("Cannot verify the journal receipt namespace.");
    HANDLE handle = OpenWalFile(options_.path.c_str(), GENERIC_WRITE, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (handle == INVALID_HANDLE_VALUE) return fail("Existing canonical journal writer lease unavailable.");
    if (!IsSafeWalPathHandle(handle)) {
        CloseHandle(handle); return fail("Journal must be an ordinary single-link file without compaction debt.");
    }
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(handle, &size) || size.QuadPart < 0 || size.QuadPart > 8ll * 1024 * 1024) {
        CloseHandle(handle); return fail("Journal exceeds the bounded 8 MiB command profile.");
    }
    if (!SetFilePointerEx(handle, {}, nullptr, FILE_END)) {
        CloseHandle(handle); return fail("Cannot position existing journal at EOF.");
    }
    append_handle_ = handle; append_handle_size_ = size.QuadPart;
    append_handle_size_known_ = true; ++append_handle_open_count_;
    const auto read = ReadAllInternal(options_.path, options_.volume_identity, false, nullptr,
        {8ull * 1024 * 1024, 65536});
    if (read.status != ReadStatus::Ok || read.recovered_torn_tail)
        return fail("Malformed, incomplete or conflicting canonical journal; evidence retained unchanged.");
    return true;
}

bool WriteAheadLog::AcquireExclusiveWriterLease() const
{
    std::lock_guard<std::recursive_mutex> operation_lock(WalOperationMutex(options_.path));
    if (options_.protected_persistence)
    {
        if (protected_state_ && protected_state_->poisoned) return false;
        auto read = ReadProtected(options_.protected_persistence->read_limits,
            options_.protected_persistence->max_allocation_bytes, true);
        const bool ok = read.status == ReadStatus::Ok; WipeRecords(read.records); return ok;
    }
    if (preserve_startup_evidence_) return EnsureAppendHandle();
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
        std::filesystem::create_directories(WalIoPath(parent), ec);
        if (ec)
        {
            return false;
        }
    }
    if (TryTransferRegisteredHandlesForPath(options_.path, this))
    {
        if (preserve_startup_evidence_ ? !StartupCompactionNamespaceIsProven() : !CleanupPreIntentCompactionOrphans())
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
    if (options_.protected_persistence && fault_injection_hook_ && fault_injection_hook_("protected-partial-write"))
    {
        DWORD written = 0;
        (void)WriteFile(handle, encoded.data(), static_cast<DWORD>((std::min)(encoded.size(), std::size_t{13})), &written, nullptr);
        (void)CloseAppendHandle();
        return EncodedAppendResult::BytesMayHavePersisted;
    }
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
            return !options_.protected_persistence && written_total == 0 && written == 0
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
    if (options_.protected_persistence) return AppendProtected(std::span(&record, 1), durable_flush, expected_writer_generation);
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
    if (preserve_startup_evidence_ && !EnsureAppendHandle()) return AppendResult::RejectedBeforeWrite;
    if (!preserve_startup_evidence_)
        std::filesystem::create_directories(WalIoPath(options_.path.parent_path()), ec);
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
            : (std::filesystem::exists(WalIoPath(options_.path), ec)
                ? std::filesystem::file_size(WalIoPath(options_.path), ec)
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
    if (options_.protected_persistence) return AppendProtected(records, durable_flush, expected_writer_generation);
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
    if (preserve_startup_evidence_ && !EnsureAppendHandle()) return AppendResult::RejectedBeforeWrite;
    if (!preserve_startup_evidence_)
        std::filesystem::create_directories(WalIoPath(options_.path.parent_path()), ec);
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
            : (std::filesystem::exists(WalIoPath(options_.path), ec)
                ? std::filesystem::file_size(WalIoPath(options_.path), ec)
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
    if (options_.protected_persistence)
    {
        if (!ValidatedAppendLeaseGeneration() || !protected_state_ || protected_state_->poisoned) return false;
        if (FlushAppendHandle()) return true;
        protected_state_->poisoned = true; (void)CloseAppendHandle(); return false;
    }
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
    return CompactOrdinaryWithResult(minimum_sequence_to_keep, expected_writer_generation, nullptr);
}

#include "WriteAheadLogFusionContinuation.inc"

WriteAheadLog::CompactionResult WriteAheadLog::CompactOrdinaryWithResult(
    std::uint64_t minimum_sequence_to_keep,
    std::uint64_t expected_writer_generation,
    const FusionCertifiedPredecessor* predecessor) const
{
    std::lock_guard<std::recursive_mutex> operation_lock(WalOperationMutex(options_.path));
    if (predecessor && (!predecessor->original || !predecessor->revalidate ||
        predecessor->original->floor != minimum_sequence_to_keep ||
        predecessor->original->writer_generation != expected_writer_generation ||
        !MatchesFusionOriginalForContinuation(*predecessor->original) || !predecessor->revalidate()))
        return CompactionResult::RejectedBeforeWrite;
    struct RestoreFusionEvidencePolicy {
        bool& policy; bool previous;
        ~RestoreFusionEvidencePolicy() { policy = previous; }
    } restore_fusion_policy{preserve_startup_evidence_, preserve_startup_evidence_};
    if (predecessor) preserve_startup_evidence_ = false;
    if (options_.protected_persistence) return CompactionResult::RejectedBeforeWrite;
    if (preserve_startup_evidence_ && !EnsureAppendHandle()) return CompactionResult::RejectedBeforeWrite;
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
        if ((record.sequence >= minimum_sequence_to_keep &&
             (!predecessor || record.operation != OperationKind::CompactionIndex)) ||
            (!predecessor && record.operation == OperationKind::CompactionIndex))
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
    std::filesystem::create_directories(WalIoPath(options_.path.parent_path()), ec);
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
    auto* link_guard = OpenWalFile(
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
            WalIoPath(predecessor_guard_wide).c_str(),
            WalIoPath(target_wide).c_str(),
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
    auto* predecessor_guard = OpenWalFile(
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
        auto* unlink_guard = OpenWalFile(
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
        const auto canonical_attributes = WalFileAttributes(target_wide.c_str());
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
    if (options_.protected_persistence) return ReadProtected(options_.protected_persistence->read_limits,
        options_.protected_persistence->max_allocation_bytes, false);
    return ReadAllInternal(options_.path, options_.volume_identity, false, nullptr);
}

bool WriteAheadLog::StartupCompactionNamespaceIsProven() const
{
    if (options_.protected_persistence) return EnsureProtectedState();
    std::vector<std::wstring> allowed;
    if (append_handle_ != nullptr)
    {
        const auto intent = CompactionIntentPath(options_.path);
        auto receipt = OpenWalFile(intent, GENERIC_READ, FILE_SHARE_READ, nullptr,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        if (receipt != INVALID_HANDLE_VALUE)
        {
            const auto history = ReadAllEvidenceFromHeldHandle(receipt, options_.volume_identity,
                {1ull << 20, 8}, 8ull << 20);
            const bool closed = CloseHandle(receipt) != FALSE;
            if (!closed || history.status != ReadStatus::Ok ||
                !IsStrictCompactionIntentHistory(history.records, options_.volume_identity) ||
                !ValidatedAppendLeaseGeneration(true)) return false;
            allowed.push_back(intent.filename().wstring());
            allowed.push_back(CompactionPredecessorGuardPath(options_.path,
                history.records.back().object_id).filename().wstring());
        }
        else
        {
            const auto error = GetLastError();
            if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND) return false;
        }
    }
    WIN32_FIND_DATAW found{};
    auto search = FindFirstFileW(WalIoPath(options_.path.wstring() + L".compact*").c_str(), &found);
    if (search == INVALID_HANDLE_VALUE)
    {
        const auto error = GetLastError();
        return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND;
    }
    bool valid = true;
    unsigned count = 0;
    do
    {
        if (++count > 2 ||
            (found.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) ||
            std::find(allowed.begin(), allowed.end(), found.cFileName) == allowed.end())
        {
            valid = false;
            break;
        }
    } while (FindNextFileW(search, &found));
    const auto error = GetLastError();
    const bool closed = FindClose(search) != FALSE;
    return valid && error == ERROR_NO_MORE_FILES && closed;
}

bool WriteAheadLog::MaterializeAbsentStartupJournal() const
{
    std::lock_guard<std::recursive_mutex> operation_lock(WalOperationMutex(options_.path));
    if (options_.protected_persistence) return false;
    if (!preserve_startup_evidence_ || startup_journal_state_ != StartupJournalState::Absent ||
        !startup_evidence_valid_ || append_handle_ != nullptr || writer_lease_handle_ == nullptr ||
        startup_writer_lease_generation_ == 0 || writer_lease_generation_ != startup_writer_lease_generation_ ||
        writer_lease_name_ != WriterLeaseName(options_.volume_identity) ||
        options_.volume_identity.empty() || !options_.path.is_absolute()) return false;
    startup_evidence_valid_ = false;
    if (!StartupCompactionNamespaceIsProven()) return false;
    // Ancestors are already pinned by the caller. Never retry an existing leaf.
    auto handle = OpenWalFile(options_.path, GENERIC_WRITE, FILE_SHARE_READ, nullptr,
        CREATE_NEW, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (handle == INVALID_HANDLE_VALUE) return false;
    append_handle_ = handle;
    ++append_handle_open_count_;
    startup_journal_state_ = StartupJournalState::Materialized;
    PhysicalFileIdentity created{};
    std::uint64_t size = 0;
    const bool valid = IsSafeWalPathHandle(handle) && TryGetPhysicalFileIdentity(handle, created) &&
        TryGetPhysicalFileSize(handle, size) && size == 0 && PathMatchesPhysicalFile(options_.path, created, true);
    append_handle_size_ = size;
    append_handle_size_known_ = valid;
    startup_evidence_valid_ = valid;
    if (!valid || !StartupCompactionNamespaceIsProven() || !ValidatedAppendLeaseGeneration(true))
    {
        startup_evidence_valid_ = false;
        return false;
    }
    return true;
}

WriteAheadLog::ReadResult WriteAheadLog::ReadStartupEvidence(
    WalReadLimits limits, std::uint64_t max_allocation_bytes) const
{
    std::lock_guard<std::recursive_mutex> operation_lock(WalOperationMutex(options_.path));
    if (options_.protected_persistence)
    {
        preserve_startup_evidence_ = true;
        startup_evidence_valid_ = false;
        auto result = ReadProtected(limits, max_allocation_bytes, true);
        if (result.status != ReadStatus::Ok || !writer_lease_handle_ ||
            (startup_writer_lease_generation_ && startup_writer_lease_generation_ != writer_lease_generation_))
        { if (result.status == ReadStatus::Ok) result.status = ReadStatus::IoError; return result; }
        startup_writer_lease_generation_ = writer_lease_generation_;
        if (append_handle_) startup_journal_state_ = StartupJournalState::Present;
        else if (PathIsAbsent(options_.path)) startup_journal_state_ = StartupJournalState::Absent;
        else { result.status = ReadStatus::IoError; return result; }
        startup_evidence_valid_ = true;
        return result;
    }
    preserve_startup_evidence_ = true;
    startup_evidence_valid_ = false;
    ReadResult failed{};
    failed.status = ReadStatus::IoError;
    limits.bytes = (std::min)(limits.bytes, 64ull << 20);
    limits.records = (std::min)(limits.records, std::size_t{1000000});
    if (options_.path.empty() || options_.volume_identity.empty() ||
        (startup_writer_lease_generation_ != 0 && (writer_lease_handle_ == nullptr ||
            writer_lease_generation_ != startup_writer_lease_generation_)) || !EnsureWriterLease()) return failed;
    if (startup_writer_lease_generation_ == 0) startup_writer_lease_generation_ = writer_lease_generation_;
    auto reader = OpenWalFile(options_.path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (reader == INVALID_HANDLE_VALUE)
    {
        const auto error = GetLastError();
        if (append_handle_ == nullptr && (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) &&
            (startup_journal_state_ == StartupJournalState::Unobserved || startup_journal_state_ == StartupJournalState::Absent))
        {
            startup_journal_state_ = StartupJournalState::Absent;
            if (!StartupCompactionNamespaceIsProven()) return failed;
            startup_evidence_valid_ = true;
            return {};
        }
        return failed;
    }
    if (startup_journal_state_ == StartupJournalState::Absent)
    {
        CloseHandle(reader);
        return failed;
    }
    if (startup_journal_state_ == StartupJournalState::Unobserved) startup_journal_state_ = StartupJournalState::Present;
    PhysicalFileIdentity original{}, owned{};
    std::uint64_t size = 0;
    bool valid = IsSafeWalPathHandle(reader) && TryGetPhysicalFileIdentity(reader, original) &&
        TryGetPhysicalFileSize(reader, size) && PathMatchesPhysicalFile(options_.path, original, true);
    if (valid && append_handle_ == nullptr)
    {
        auto writer = OpenWalFile(options_.path, GENERIC_WRITE, FILE_SHARE_READ, nullptr,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        valid = writer != INVALID_HANDLE_VALUE && IsSafeWalPathHandle(writer) &&
            TryGetPhysicalFileIdentity(writer, owned) && owned.volume_serial == original.volume_serial &&
            owned.file_id == original.file_id && SetFilePointerEx(writer, {}, nullptr, FILE_END);
        if (valid)
        {
            append_handle_ = writer;
            append_handle_size_ = size;
            append_handle_size_known_ = true;
            ++append_handle_open_count_;
        }
        else if (writer != INVALID_HANDLE_VALUE) CloseHandle(writer);
    }
    if (valid)
    {
        valid = TryGetPhysicalFileIdentity(static_cast<HANDLE>(append_handle_), owned) &&
            owned.volume_serial == original.volume_serial && owned.file_id == original.file_id &&
            append_handle_size_known_ && append_handle_size_ == size;
    }
    auto result = valid ? ReadAllEvidenceFromHeldHandle(reader, options_.volume_identity,
        limits, max_allocation_bytes) : failed;
    valid = CloseHandle(reader) != FALSE && valid;
    // Authenticate the retained file and receipt before publishing append trust.
    startup_evidence_valid_ = valid;
    if (!valid || !StartupCompactionNamespaceIsProven() || !ValidatedAppendLeaseGeneration(true))
    {
        startup_evidence_valid_ = false;
        return failed;
    }
    startup_evidence_valid_ = result.status == ReadStatus::Ok && !result.recovered_torn_tail;
    return result;
}

WriteAheadLog::ReadResult WriteAheadLog::ReadAllWithExclusiveWriterLease(WalReadLimits limits) const
{
    std::lock_guard<std::recursive_mutex> operation_lock(WalOperationMutex(options_.path));
    if (options_.protected_persistence) return ReadProtected(limits, options_.protected_persistence->max_allocation_bytes, true);
    if (preserve_startup_evidence_) return ReadStartupEvidence(limits, 256ull << 20);
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
        &complete_prefix_bytes, limits);
    if (inspected.status != ReadStatus::Ok)
    {
        if (inspected.status != ReadStatus::ResourceLimit) (void)CloseAppendFileHandle();
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
        nullptr, limits);
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

std::uint64_t WriteAheadLog::ValidatedAppendLeaseGeneration(bool bounded_evidence) const
{
    std::lock_guard<std::recursive_mutex> operation_lock(WalOperationMutex(options_.path));
    if (options_.protected_persistence)
    {
        std::uint64_t size = 0;
        return EnsureProtectedState() && protected_state_->verified && !protected_state_->poisoned && !protected_state_->head_mismatch &&
            writer_lease_handle_ && append_handle_ && append_handle_size_known_ &&
            TryGetPhysicalFileSize(static_cast<HANDLE>(append_handle_), size) && size == append_handle_size_ &&
            ProtectedExactHandle(static_cast<HANDLE>(append_handle_), options_.path, false) ? writer_lease_generation_ : 0;
    }
    if (preserve_startup_evidence_ && (!startup_evidence_valid_ ||
        writer_lease_generation_ != startup_writer_lease_generation_)) return 0;
    if (writer_lease_handle_ == nullptr || append_handle_ == nullptr ||
        !append_handle_size_known_) return 0;
    auto handle = static_cast<HANDLE>(append_handle_);
    std::uint64_t size = 0;
    PhysicalFileIdentity owned{}, current{};
    if (!IsSafeWalPathHandle(handle) || !TryGetPhysicalFileSize(handle, size) ||
        size != append_handle_size_ || !TryGetPhysicalFileIdentity(handle, owned)) return 0;
    const auto intent = CompactionIntentPath(options_.path);
    auto receipt = OpenWalFile(intent.c_str(), GENERIC_READ | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ, nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (receipt != INVALID_HANDLE_VALUE)
    {
        PhysicalFileIdentity receipt_identity{};
        std::vector<std::uint8_t> bytes;
        bool completed = IsSafeWalPathHandle(receipt) &&
            TryGetPhysicalFileIdentity(receipt, receipt_identity) &&
            PathMatchesPhysicalFile(intent, receipt_identity, true);
        if (completed)
        {
            auto history = bounded_evidence
                ? ReadAllEvidenceFromHeldHandle(receipt, options_.volume_identity,
                    {1ull << 20, 8}, 8ull << 20)
                : (ReadPinnedIntentBytes(receipt, bytes)
                    ? DecodeWalBytes(bytes, options_.volume_identity, nullptr) : ReadResult{});
            if (!bounded_evidence && bytes.empty()) history.status = ReadStatus::IoError;
            completed = history.status == ReadStatus::Ok && !history.recovered_torn_tail &&
                IsStrictCompactionIntentHistory(history.records, options_.volume_identity);
            if (completed)
            {
                const auto& terminal = history.records.back();
                completed = terminal.state == RecordState::Cleaned &&
                    terminal.flags == kCompactionIntentNamespaceDurableFlag &&
                    terminal.parent_object_id == owned.volume_serial && terminal.logical_offset == owned.file_id;
                if (completed)
                {
                    const auto predecessor = CompactionPredecessorGuardPath(options_.path, terminal.object_id);
                    auto tombstone = OpenWalFile(predecessor.c_str(), GENERIC_READ | FILE_READ_ATTRIBUTES,
                        FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
                    if (tombstone == INVALID_HANDLE_VALUE)
                    {
                        const auto error = GetLastError();
                        completed = error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND;
                    }
                    else
                    {
                        PhysicalFileIdentity identity{};
                        std::uint64_t predecessor_size = 0;
                        completed = IsSafeWalPathHandle(tombstone) &&
                            TryGetPhysicalFileIdentity(tombstone, identity) &&
                            identity.volume_serial == owned.volume_serial && identity.file_id == terminal.object_id &&
                            TryGetPhysicalFileSize(tombstone, predecessor_size) && predecessor_size == 0 &&
                            PathMatchesPhysicalFile(predecessor, identity, true);
                        completed = CloseHandle(tombstone) != FALSE && completed;
                    }
                }
            }
        }
        completed = PathMatchesPhysicalFile(intent, receipt_identity, true) && completed;
        const bool closed = CloseHandle(receipt) != FALSE;
        if (!completed || !closed) return 0;
    }
    else
    {
        const auto error = GetLastError();
        if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND) return 0;
    }
    auto path_handle = OpenWalFile(options_.path.c_str(), FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (path_handle == INVALID_HANDLE_VALUE) return 0;
    const bool retained = IsSafeWalPathHandle(path_handle) &&
        TryGetPhysicalFileIdentity(path_handle, current) &&
        owned.volume_serial == current.volume_serial && owned.file_id == current.file_id;
    const bool closed = CloseHandle(path_handle) != FALSE;
    return retained && closed ? writer_lease_generation_ : 0;
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

namespace
{
bool EvidenceInputSizeFits(std::uint64_t size, WalReadLimits limits, std::uint64_t allocation)
{
    return limits.bytes != UINT64_MAX && limits.records != SIZE_MAX && allocation != UINT64_MAX &&
        size <= limits.bytes && size <= kMaxRecordBytes && size <= SIZE_MAX && size <= allocation / 4;
}

bool EvidenceSizeFits(std::uint64_t size, std::size_t records,
    WalReadLimits limits, std::uint64_t allocation)
{
    // Keep the byte-buffer/variable-data allowance. The framing pass permits one
    // exact vector reservation, with no geometric growth or second record array.
    return EvidenceInputSizeFits(size, limits, allocation) && records <= limits.records &&
        records <= (allocation - size * 4) / (sizeof(WriteAheadLog::Record) + 4ull);
}

WriteAheadLog::ReadStatus CountEvidenceFrames(HANDLE handle, std::uint64_t size,
    WalReadLimits limits, std::uint64_t allocation, std::size_t& count)
{
    using Status = WriteAheadLog::ReadStatus;
    count = 0;
    if (!EvidenceInputSizeFits(size, limits, allocation)) return Status::ResourceLimit;
    LARGE_INTEGER original{}, zero{};
    if (!SetFilePointerEx(handle, zero, &original, FILE_CURRENT)) return Status::IoError;
    const auto finish = [&](Status status) {
        return SetFilePointerEx(handle, original, nullptr, FILE_BEGIN) ? status : Status::IoError;
    };
    std::array<std::uint8_t, 64u << 10> window{};
    std::uint64_t window_start = 0;
    std::size_t window_bytes = 0;
    std::uint64_t cursor = 0;
    while (cursor < size)
    {
        const auto remaining = size - cursor;
        const auto needed = static_cast<std::size_t>((std::min)(remaining, std::uint64_t{12}));
        const auto offset = cursor - window_start;
        if (offset > window_bytes || needed > window_bytes - static_cast<std::size_t>(offset))
        {
            LARGE_INTEGER position{}; position.QuadPart = static_cast<LONGLONG>(cursor);
            const auto wanted = static_cast<DWORD>((std::min)(remaining, std::uint64_t{window.size()}));
            DWORD read = 0;
            if (!SetFilePointerEx(handle, position, nullptr, FILE_BEGIN) ||
                !ReadFile(handle, window.data(), wanted, &read, nullptr) || read != wanted)
                return finish(Status::IoError);
            window_start = cursor; window_bytes = read;
        }
        const auto header = std::span(window).subspan(static_cast<std::size_t>(cursor - window_start), needed);
        if (IsProtectedWalPrefix(header)) return finish(Status::VersionMismatch);
        if (count >= limits.records) return finish(Status::ResourceLimit);
        if (remaining < kLegacyHeaderSize) return finish(Status::Corrupt);
        WalFrameHeader frame;
        const auto status = DecodeWalFrameHeader(header, frame);
        if (status != Status::Ok) return finish(status);
        if (frame.bytes > remaining) return finish(Status::Corrupt);
        ++count;
        if (!EvidenceSizeFits(size, count, limits, allocation)) return finish(Status::ResourceLimit);
        cursor += frame.bytes;
    }
    return finish(Status::Ok);
}
}

bool WriteAheadLog::EvidenceAppendCapacityAvailable(const std::vector<Record>& records,
    WalReadLimits limits, std::uint64_t allocation) const
{
    std::lock_guard<std::recursive_mutex> operation_lock(WalOperationMutex(options_.path));
    if (options_.protected_persistence)
    {
        if (records.empty() || records.size() > kProtectedBatchRecords || !ValidatedAppendLeaseGeneration()) return false;
        const auto& p = *options_.protected_persistence;
        std::uint64_t size = append_handle_size_, sequence = protected_state_->position.sequence;
        for (const auto& r : records)
        {
            if ((!r.volume_identity.empty() && r.volume_identity != options_.volume_identity) || !r.sequence || r.sequence <= sequence || r.sequence == UINT64_MAX ||
                !IsKnownOperation(r.operation) || r.operation == OperationKind::CompactionIndex ||
                r.state < RecordState::Prepared || r.state > RecordState::CleanupArmed) return false;
            Record writable = r;
            struct Cleanup { Record& r; ~Cleanup() { WipeRecord(r); } } cleanup{writable};
            if (writable.volume_identity.empty()) writable.volume_identity = options_.volume_identity;
            auto encoded = EncodeProtectedWalRecord(writable);
            if (!encoded) return false;
            size += encoded.bytes.Size() + 80; sequence = r.sequence;
        }
        const auto count = protected_state_->position.ordinal - 1 + records.size();
        allocation = (std::min)(allocation, p.max_allocation_bytes);
        return size <= options_.max_bytes && size <= limits.bytes && size <= p.read_limits.bytes && size <= allocation / 4 &&
            count <= limits.records && count <= p.read_limits.records && count <= (allocation - size * 4) / (2 * sizeof(Record) + 4);
    }
    if (records.empty() || records.size() > 8) return false;
    const auto generation = ValidatedAppendLeaseGeneration(true);
    if (!generation) return false;
    std::uint64_t size = append_handle_size_;
    for (const auto& record : records)
    {
        const auto encoded = EncodeForTest(record);
        if (encoded.empty() || encoded.size() > UINT64_MAX - size) return false;
        size += encoded.size();
    }
    if ((options_.max_bytes && size > options_.max_bytes) ||
        !EvidenceInputSizeFits(size, limits, allocation)) return false;
    auto reader = OpenWalFile(options_.path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (reader == INVALID_HANDLE_VALUE) return false;
    BY_HANDLE_FILE_INFORMATION before{}, after{}, owned{};
    bool valid = IsSafeWalPathHandle(reader) && GetFileInformationByHandle(reader, &before) &&
        GetFileInformationByHandle(static_cast<HANDLE>(append_handle_), &owned) &&
        before.dwVolumeSerialNumber == owned.dwVolumeSerialNumber &&
        before.nFileIndexHigh == owned.nFileIndexHigh && before.nFileIndexLow == owned.nFileIndexLow &&
        ((static_cast<std::uint64_t>(before.nFileSizeHigh) << 32u) | before.nFileSizeLow) == append_handle_size_;
    std::size_t count = 0;
    valid = valid && CountEvidenceFrames(reader, append_handle_size_, limits, allocation, count) == ReadStatus::Ok &&
        count <= SIZE_MAX - records.size() && EvidenceSizeFits(size, count + records.size(), limits, allocation) &&
        IsSafeWalPathHandle(reader) && GetFileInformationByHandle(reader, &after) &&
        before.dwVolumeSerialNumber == after.dwVolumeSerialNumber &&
        before.nFileIndexHigh == after.nFileIndexHigh && before.nFileIndexLow == after.nFileIndexLow &&
        before.nFileSizeHigh == after.nFileSizeHigh && before.nFileSizeLow == after.nFileSizeLow &&
        CompareFileTime(&before.ftCreationTime, &after.ftCreationTime) == 0 &&
        CompareFileTime(&before.ftLastWriteTime, &after.ftLastWriteTime) == 0;
    const bool closed = CloseHandle(reader) != FALSE;
    return valid && closed && ValidatedAppendLeaseGeneration(true) == generation;
}

WriteAheadLog::ReadResult WriteAheadLog::ReadAllEvidenceFromHeldHandle(
    void* held_handle,
    const std::string& expected_volume_identity,
    WalReadLimits limits,
    std::uint64_t max_allocation_bytes)
{
    ReadResult failed{};
    failed.status = ReadStatus::IoError;
    const auto handle = static_cast<HANDLE>(held_handle);
    BY_HANDLE_FILE_INFORMATION before{}, after{};
    if (handle == nullptr || handle == INVALID_HANDLE_VALUE ||
        GetFileType(handle) != FILE_TYPE_DISK || !IsSafeWalPathHandle(handle) ||
        !GetFileInformationByHandle(handle, &before)) return failed;

    const auto size = (static_cast<std::uint64_t>(before.nFileSizeHigh) << 32u) | before.nFileSizeLow;
    // Bound input first; a constant-space framing pass then budgets the exact
    // record reservation before allocating bytes or decoded variable data.
    if (!EvidenceInputSizeFits(size, limits, max_allocation_bytes))
    {
        failed.status = ReadStatus::ResourceLimit;
        return failed;
    }
    const auto unchanged = [&]()
    {
        return IsSafeWalPathHandle(handle) && GetFileInformationByHandle(handle, &after) &&
            before.dwVolumeSerialNumber == after.dwVolumeSerialNumber &&
            before.nFileIndexHigh == after.nFileIndexHigh && before.nFileIndexLow == after.nFileIndexLow &&
            before.nFileSizeHigh == after.nFileSizeHigh && before.nFileSizeLow == after.nFileSizeLow &&
            CompareFileTime(&before.ftCreationTime, &after.ftCreationTime) == 0 &&
            CompareFileTime(&before.ftLastWriteTime, &after.ftLastWriteTime) == 0;
    };
    try
    {
        std::size_t record_count = 0;
        failed.status = CountEvidenceFrames(handle, size, limits, max_allocation_bytes, record_count);
        if (!unchanged()) { failed.status = ReadStatus::IoError; return failed; }
        if (failed.status != ReadStatus::Ok) return failed;
        failed.status = ReadStatus::IoError;
        std::vector<std::uint8_t> bytes;
        if (!ReadPinnedIntentBytes(handle, bytes, size) || bytes.size() != size || !unchanged()) return failed;
        auto decoded = DecodeWalBytes(bytes, expected_volume_identity, nullptr, limits, record_count);
        if (!unchanged()) return failed;
        if (decoded.recovered_torn_tail && decoded.status == ReadStatus::Ok)
            decoded.status = ReadStatus::Corrupt;
        if (decoded.status != ReadStatus::Ok) decoded.records.clear();
        return decoded;
    }
    catch (const std::bad_alloc&)
    {
        failed.status = ReadStatus::ResourceLimit;
        return failed;
    }
    catch (const std::length_error&)
    {
        failed.status = ReadStatus::ResourceLimit;
        return failed;
    }
}

WriteAheadLog::ReadResult WriteAheadLog::ReadAllInternal(
    const std::filesystem::path& path,
    const std::string& expected_volume_identity,
    bool repair_torn_tail,
    std::uint64_t* complete_prefix_bytes,
    WalReadLimits limits)
{
    ReadResult result{};
    if (complete_prefix_bytes)
    {
        *complete_prefix_bytes = 0;
    }
    if (!DerivedWitnessNamespaceSettled(path) || !ContinuationNamespaceAbsent(path)) { result.status = ReadStatus::IoError; return result; }
    if (path.empty() || !std::filesystem::exists(WalIoPath(path)))
    {
        return result;
    }

    std::vector<std::uint8_t> bytes;
    bool limited = false;
    if (!ReadFileBytes(path, bytes, limits.bytes, limited))
    {
        result.status = limited ? ReadStatus::ResourceLimit : ReadStatus::IoError;
        return result;
    }

    std::uint64_t prefix = 0;
    auto* decoded_prefix = complete_prefix_bytes ? complete_prefix_bytes : &prefix;
    result = DecodeWalBytes(bytes, expected_volume_identity, decoded_prefix, limits);
    if (result.recovered_torn_tail && repair_torn_tail &&
        !TruncateTornTail(path, static_cast<std::size_t>(*decoded_prefix)))
        result.status = ReadStatus::IoError;
    return result;
}

namespace
{
template<class Buffer> bool EncodeWalRecord(const WriteAheadLog::Record& record,
    std::uint16_t version_override, Buffer& buffer)
{
    using OperationKind = WriteAheadLog::OperationKind;
    const auto version = version_override == 0
        ? (record.unlink_outcome ? kUnlinkOutcomeVersion :
            record.operation == OperationKind::SetExtendedAttribute || !record.inline_payload.empty()
                ? kInlinePayloadVersion
                : kLegacyVersion)
        : version_override;
    if ((record.operation == OperationKind::SetExtendedAttribute && version != kInlinePayloadVersion) ||
        ((record.operation == OperationKind::RewriteCompressedContent || record.operation == OperationKind::CloneFile || record.operation == OperationKind::HardLink || record.operation == OperationKind::NativeSparse || record.operation == OperationKind::CloneRange || record.operation == OperationKind::SetVolumeQuotaReserve || record.operation == OperationKind::RenameVolume || record.operation == OperationKind::CreateSnapshot || record.operation == OperationKind::DeleteSnapshot || record.operation == OperationKind::RepairVolumeFileCount) && version != kInlinePayloadVersion) ||
        (record.operation == OperationKind::RemoveExtendedAttribute && version != kLegacyVersion) ||
        (!record.inline_payload.empty() && version != kInlinePayloadVersion) ||
        (record.unlink_outcome.has_value() != (version == kUnlinkOutcomeVersion)) ||
        !InodeMetadataMutationIsConsistentImpl(record) ||
        !AllocationSizeMutationIsConsistentImpl(record) ||
        !DirectoryRestoreMutationIsConsistentImpl(record) ||
        !InlinePayloadIsConsistentImpl(record) ||
        !ExtendedAttributeMutationIsConsistentImpl(record) ||
        !UnlinkOutcomeIsConsistentImpl(record))
    {
        return {};
    }
    const auto header_size = version == kUnlinkOutcomeVersion
        ? kUnlinkOutcomeHeaderSize
        : version == kInlinePayloadVersion ? kInlinePayloadHeaderSize : kLegacyHeaderSize;
    const auto record_size =
        static_cast<std::uint64_t>(header_size) +
        record.path_utf8.size() +
        record.secondary_path_utf8.size() +
        record.volume_identity.size() +
        record.inline_payload.size() +
        (record.unlink_outcome ? record.unlink_outcome->path_utf8.size() : 0);
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
    else if (record.unlink_outcome)
    {
        const auto& outcome = *record.unlink_outcome;
        AppendU64(buffer, outcome.object_id);
        AppendU64(buffer, outcome.generation_before);
        AppendU64(buffer, outcome.generation_after);
        AppendU64(buffer, outcome.parent_object_id);
        AppendU32(buffer, outcome.links_before);
        AppendU32(buffer, outcome.links_after);
        AppendU32(buffer, static_cast<std::uint32_t>(outcome.path_utf8.size()));
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
    if (record.unlink_outcome)
    {
        const auto& path = record.unlink_outcome->path_utf8;
        buffer.insert(buffer.end(), path.begin(), path.end());
    }

    StoreU32(buffer, kChecksumOffset, ChecksumRecord(buffer));
    return true;
}

// The common serializer writes directly into this locked owner; no temporary
// plaintext vector or checksum copy is needed for protected persistence.
struct SecureWalEncoding
{
    cc::SecureBytes bytes;
    std::size_t used = 0;
    cc::CryptoError error = cc::CryptoError::None;
    std::uint32_t os_status = 0;
    void reserve(std::size_t size)
    {
        if (size > jc::kMaxJournalPlaintextBytes) { error = cc::CryptoError::ResourceLimit; throw std::length_error("Protected WAL record limit"); }
        auto result = cc::SecureBytes::Allocate(size);
        if (!result) { error = result.error; os_status = result.os_status; throw std::bad_alloc(); }
        bytes = std::move(result.bytes);
    }
    void push_back(std::uint8_t v) noexcept { (*this)[used++] = v; }
    std::uint8_t& operator[](std::size_t at) noexcept { return reinterpret_cast<std::uint8_t*>(bytes.Bytes().data())[at]; }
    std::uint8_t operator[](std::size_t at) const noexcept { return reinterpret_cast<const std::uint8_t*>(bytes.Bytes().data())[at]; }
    std::size_t size() const noexcept { return used; }
    std::uint8_t* end() noexcept { return reinterpret_cast<std::uint8_t*>(bytes.Bytes().data()) + used; }
    template<class It> void insert(std::uint8_t*, It first, It last) noexcept
    { for (; first != last; ++first) push_back(static_cast<std::uint8_t>(*first)); }
};
cc::CryptoResult EncodeProtectedWalRecord(const WriteAheadLog::Record& record)
{
    SecureWalEncoding encoded;
    try
    {
        if (!EncodeWalRecord(record, 0, encoded)) return {cc::CryptoError::InvalidArgument, 0, {}};
        return {cc::CryptoError::None, 0, std::move(encoded.bytes)};
    }
    catch (...) { return {encoded.error == cc::CryptoError::None ? cc::CryptoError::AllocationFailed : encoded.error, encoded.os_status, {}}; }
}
} // namespace

std::vector<std::uint8_t> WriteAheadLog::EncodeForTest(const Record& record, std::uint16_t version_override)
{
    std::vector<std::uint8_t> bytes;
    if (!EncodeWalRecord(record, version_override, bytes)) return {};
    return bytes;
}

bool WriteAheadLog::InlinePayloadIsConsistent(const Record& record)
{
    return InlinePayloadIsConsistentImpl(record);
}

bool WriteAheadLog::AllocationSizeMutationIsConsistent(const Record& record)
{
    return AllocationSizeMutationIsConsistentImpl(record);
}

bool WriteAheadLog::DirectoryRestoreMutationIsConsistent(const Record& record)
{
    return DirectoryRestoreMutationIsConsistentImpl(record);
}

bool WriteAheadLog::InodeMetadataMutationIsConsistent(const Record& record)
{
    return InodeMetadataMutationIsConsistentImpl(record);
}

bool WriteAheadLog::NativeCloneIsConsistent(const Record& record)
{ return record.operation != OperationKind::CloneFile || InlinePayloadIsConsistentImpl(record); }
bool WriteAheadLog::NativeHardLinkIsConsistent(const Record& record)
{ return record.operation != OperationKind::HardLink || InlinePayloadIsConsistentImpl(record); }
bool WriteAheadLog::NativeSparseIsConsistent(const Record& record)
{ return record.operation != OperationKind::NativeSparse || InlinePayloadIsConsistentImpl(record); }
bool WriteAheadLog::NativeCloneRangeIsConsistent(const Record& record)
{ return record.operation != OperationKind::CloneRange || InlinePayloadIsConsistentImpl(record); }
bool WriteAheadLog::SnapshotIntentIsConsistent(const Record& record)
{ return (record.operation != OperationKind::CreateSnapshot && record.operation != OperationKind::DeleteSnapshot) || InlinePayloadIsConsistentImpl(record); }

bool WriteAheadLog::VolumeRenameIsConsistent(const Record& record)
{ return record.operation != OperationKind::RenameVolume || InlinePayloadIsConsistentImpl(record); }
bool WriteAheadLog::CountRepairIsConsistent(const Record& record)
{ return record.operation != OperationKind::RepairVolumeFileCount || InlinePayloadIsConsistentImpl(record); }

bool WriteAheadLog::CompressionRewriteIsConsistent(const Record& record)
{
    return record.operation != OperationKind::RewriteCompressedContent || InlinePayloadIsConsistentImpl(record);
}

bool WriteAheadLog::ExtendedAttributeMutationIsConsistent(const Record& record)
{
    return ExtendedAttributeMutationIsConsistentImpl(record);
}

bool WriteAheadLog::UnlinkOutcomeIsConsistent(const Record& record)
{
    return UnlinkOutcomeIsConsistentImpl(record);
}
} // namespace apfsaccess::rw

namespace apfsaccess::rw { bool WriteAheadLog::VolumeQuotaReserveIsConsistent(const Record& record)
{ return record.operation != OperationKind::SetVolumeQuotaReserve || InlinePayloadIsConsistentImpl(record); } }

#include "WriteAheadLogProtectedStartup.inc"
