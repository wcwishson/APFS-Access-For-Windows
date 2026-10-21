#include "VolumeKeeperAdmission.h"
#include "ApfsFormat.h"
#include "BlockDevice.h"
#include "AppleTransactionCommit.h"
#include "VolumeFormatEvidence.h"
#include "VolumePhysicalBindingCodec.h"
#include "VolumePhysicalMediaInternal.h"
#include "VolumePhysicalInstanceInternal.h"
#include "VolumeGptGeometry.h"
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <bcrypt.h>
#include <algorithm>
#include <array>
#include <charconv>
#include <cwctype>
#include <set>
#include <map>
#include <sstream>
#include <stdexcept>

namespace apfsaccess::rw
{
namespace
{
using Bytes = std::vector<std::byte>;
constexpr std::uint64_t ImageLimit = 256ull * 1024 * 1024, JournalLimit = ImageLimit + 1024 * 1024;
void Need(bool ok, const char* error) { if (!ok) throw std::runtime_error(error); }
bool HexValid(std::string_view s, std::size_t size)
{ return s.size() == size && std::all_of(s.begin(), s.end(), [](char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); }); }
bool Uuid(std::string_view s) { return HexValid(s, 32) && s != std::string(32, '0'); }
std::uint64_t HexNumber(std::string_view s)
{
    std::uint64_t value{}; const auto result = std::from_chars(s.data(), s.data() + s.size(), value, 16);
    Need(result.ec == std::errc{} && result.ptr == s.data() + s.size(), "KeeperIdentityHexInvalid"); return value;
}
std::string Hex(std::span<const std::byte> b)
{
    std::string s; constexpr char digits[] = "0123456789abcdef";
    for (auto byte : b) { const auto n = std::to_integer<unsigned>(byte); s += digits[n >> 4]; s += digits[n & 15]; } return s;
}
void Number(Bytes& b, std::uint64_t value)
{ for (unsigned i = 0; i < 8; ++i) b.push_back(std::byte((value >> (8 * i)) & 255)); }
std::array<std::byte, 32> Hash(std::span<const std::byte> b)
{
    BCRYPT_ALG_HANDLE algorithm{}; std::array<std::byte, 32> result{};
    Need(b.size() <= ULONG_MAX && BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) >= 0, "KeeperHashUnavailable");
    const auto status = BCryptHash(algorithm, nullptr, 0, reinterpret_cast<PUCHAR>(const_cast<std::byte*>(b.data())),
        static_cast<ULONG>(b.size()), reinterpret_cast<PUCHAR>(result.data()), 32);
    BCryptCloseAlgorithmProvider(algorithm, 0); Need(status >= 0, "KeeperHashUnavailable"); return result;
}
std::wstring Wide(std::string_view s)
{
    Need(s.find('\0') == std::string_view::npos, "KeeperStringContainsNul"); if (s.empty()) return {};
    const auto n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()), nullptr, 0);
    Need(n > 0, "KeeperStringUnicodeInvalid"); std::wstring w(n, L' ');
    Need(MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()), w.data(), n) == n, "KeeperStringUnicodeInvalid"); return w;
}
std::string Utf8(std::wstring_view s)
{
    if (s.empty()) return {};
    const auto n = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()), nullptr, 0, nullptr, nullptr);
    Need(n > 0, "KeeperStringUnicodeInvalid"); std::string result(n, ' ');
    Need(WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()), result.data(), n, nullptr, nullptr) == n,
        "KeeperStringUnicodeInvalid"); return result;
}
std::wstring Extended(const std::filesystem::path& path) { return L"\\\\?\\" + path.wstring(); }
std::filesystem::path Local(const std::filesystem::path& input, bool inspect_parents)
{
    const auto s = input.wstring();
    (void)Utf8(s);
    Need(s.size() >= 3 && s.size() < 32000 && std::iswalpha(s[0]) && s[1] == L':' && (s[2] == L'\\' || s[2] == L'/') &&
        s.find(L':', 2) == std::wstring::npos && s.find(L'\0') == std::wstring::npos, "KeeperAbsoluteLocalPathRequired");
    auto result = input.lexically_normal(); result.make_preferred();
    if (inspect_parents) for (auto at = result; at != at.root_path() && !at.empty(); at = at.parent_path()) {
        const auto attributes = GetFileAttributesW(Extended(at).c_str());
        Need(attributes != INVALID_FILE_ATTRIBUTES && !(attributes & FILE_ATTRIBUTE_REPARSE_POINT), "KeeperPathUnavailableOrReparse");
    }
    return result;
}
std::wstring PathKey(const std::filesystem::path& path)
{
    auto key = path.wstring(); std::transform(key.begin(), key.end(), key.begin(), [](auto c) { return std::towlower(c); }); return key;
}
struct File
{
    HANDLE handle = INVALID_HANDLE_VALUE;
    File() = default; File(const File&) = delete; File& operator=(const File&) = delete;
    ~File() { if (handle != INVALID_HANDLE_VALUE) CloseHandle(handle); }
    bool Open(const std::filesystem::path& path, bool directory = false, bool may_be_absent = false)
    {
        handle = CreateFileW(Extended(path).c_str(), directory ? FILE_READ_ATTRIBUTES : GENERIC_READ,
            directory ? FILE_SHARE_READ | FILE_SHARE_WRITE : FILE_SHARE_READ, nullptr, OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | (directory ? FILE_FLAG_BACKUP_SEMANTICS : 0), nullptr);
        if (handle == INVALID_HANDLE_VALUE && may_be_absent && GetLastError() == ERROR_FILE_NOT_FOUND) return false;
        Need(handle != INVALID_HANDLE_VALUE, "KeeperEvidenceBusyOrUnavailable");
        FILE_STANDARD_INFO standard{}; FILE_ATTRIBUTE_TAG_INFO attributes{};
        Need(GetFileType(handle) == FILE_TYPE_DISK && GetFileInformationByHandleEx(handle, FileStandardInfo, &standard, sizeof(standard)) &&
            !!standard.Directory == directory && !standard.DeletePending && (directory || standard.NumberOfLinks == 1) &&
            GetFileInformationByHandleEx(handle, FileAttributeTagInfo, &attributes, sizeof(attributes)) &&
            !(attributes.FileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DEVICE)), "KeeperOrdinarySingleLinkFileRequired"); return true;
    }
    Bytes Read()
    {
        LARGE_INTEGER size{}; Need(GetFileSizeEx(handle, &size) && size.QuadPart >= 0 && std::uint64_t(size.QuadPart) <= JournalLimit, "KeeperFrameSizeInvalid");
        Bytes result(static_cast<std::size_t>(size.QuadPart)); DWORD read{};
        Need(ReadFile(handle, result.data(), static_cast<DWORD>(result.size()), &read, nullptr) && read == result.size(), "KeeperFrameReadFailed"); return result;
    }
};
struct Reader
{
    std::span<const std::byte> bytes; std::size_t at = 0, string_limit = 131072;
    std::uint64_t Number()
    {
        Need(at <= bytes.size() && bytes.size() - at >= 8, "KeeperFrameTruncated");
        const auto n = catalog::ReadU64LE(bytes, at).value(); at += 8; return n;
    }
    std::string Text()
    {
        const auto count = Number(); Need(count <= string_limit && count <= bytes.size() - at, "KeeperFrameStringInvalid");
        std::string text(reinterpret_cast<const char*>(bytes.data() + at), static_cast<std::size_t>(count)); at += count; (void)Wide(text); return text;
    }
    std::filesystem::path Path() { return Local(Wide(Text()), false); }
};
struct Search
{
    HANDLE handle = INVALID_HANDLE_VALUE;
    ~Search() { if (handle != INVALID_HANDLE_VALUE) FindClose(handle); }
};
struct JournalScope
{
    std::string locator;
    std::uint64_t begin = 0, end = 0;
};
std::string JournalStem(std::string_view locator)
{
    Bytes name; Number(name, locator.size());
    for (unsigned char c : locator) name.push_back(std::byte(c)); return Hex(Hash(name));
}
JournalScope ValidateBody(std::span<const std::byte> body, bool image, const std::filesystem::path& root, std::string_view locator,
    std::string_view archive_token, VolumeKeeperHistoryBinding* history = nullptr, bool streamed = false, bool erase = false, bool resize = false,
    bool relocation = false, bool physical = false, volume_physical::Envelope* physical_binding = nullptr,
    bool geometry = false, volume_geometry::Plan* geometry_plan = nullptr, std::uint64_t magic = 0)
{
    Reader in{body, 0, image ? 131072u : 65536u}; const auto op = in.Number();
    Need(op >= 1 && op <= (image ? 4u : 2u), "KeeperOperationInvalid");
    const bool flagged = image && (magic == format_evidence::FlaggedImageMagic || magic == format_evidence::FlaggedStreamedMagic || magic == volume_physical::FlaggedFormatMagic);
    Need(!flagged || op >= 3, "KeeperFlaggedFormatProfileInvalid");
    const bool physical_snapshot = !image && (magic == volume_physical::PhysicalSnapshotImageMagic || magic == volume_physical::PhysicalSnapshotManagementMagic);
    Need(!physical_snapshot || op == 1, "KeeperSnapshotPolicyInvalid");
    const auto source_path = physical ? std::filesystem::path(Wide(in.Text())) : in.Path(); const auto stored_root = in.Path();
    Need(PathKey(stored_root) == PathKey(root), "KeeperJournalRootMismatch");
    auto offset = image ? 0 : in.Number(); const auto container = in.Text(), volume = in.Text();
    const auto oid = in.Number(), xid = in.Number();
    Need(Uuid(container) && Uuid(volume) && oid && xid && offset % 4096 == 0, "KeeperRequestIdentityInvalid");
    std::uint64_t expected = 0, target = 0, quota = 0, reserve = 0, sensitive = 0;
    std::string name, new_container, new_volume; std::filesystem::path new_wal;
    if (image) {
        expected = in.Number(); target = in.Number(); new_container = in.Text(); new_volume = in.Text(); name = in.Text(); sensitive = in.Number();
        const auto destination = in.Text(); if (!destination.empty()) new_wal = Local(Wide(destination), false);
        const auto limit = streamed ? format_evidence::Maximum : ImageLimit;
        Need(!streamed || ((geometry ? op <= 2 : physical ? op >= 3 : resize ? op <= 2 : op == (erase ? 4u : 3u)) &&
            (physical || expected > ImageLimit || target > ImageLimit)),
            "KeeperStreamedFormatOperationInvalid");
        Need(expected >= 1048576 && target >= 1048576 && expected <= limit && target <= limit &&
            expected % 4096 == 0 && target % 4096 == 0, "KeeperCapacityInvalid");
        if (op <= 2) Need((op == 1 ? target > expected : target < expected) && new_container.empty() && new_volume.empty() &&
            name.empty() && !sensitive && new_wal.empty(), "KeeperResizeOptionsInvalid");
        else Need(target == expected && Uuid(new_container) && Uuid(new_volume) && new_container != container && new_volume != volume &&
            !name.empty() && name.size() < 256 && !new_wal.empty(), "KeeperFormatOptionsInvalid");
    } else {
        name = in.Text(); quota = in.Number(); reserve = in.Number(); sensitive = in.Number();
        Need(op == 1 ? (!name.empty() && name.size() < 256 && (!quota || reserve <= quota)) :
            (name.empty() && !quota && !reserve && !sensitive), "KeeperManagementOptionsInvalid");
    }
    Need(sensitive <= 1, "KeeperCaseModeInvalid");
    const auto count = in.Number(); Need(count <= 100 && (!image || count > 0), "KeeperCensusInvalid");
    std::set<std::uint64_t> oids; std::set<std::wstring> paths;
    std::map<std::uint64_t, std::filesystem::path> wals;
    for (auto i = 0ull; i < count; ++i) {
        const auto id = in.Number(); const auto path = in.Path();
        Need(id && oids.insert(id).second && paths.insert(PathKey(path)).second && PathKey(path) != PathKey(source_path), "KeeperCensusInvalid");
        wals.emplace(id, path);
    }
    if (!new_wal.empty()) Need(paths.insert(PathKey(new_wal)).second && PathKey(new_wal) != PathKey(source_path), "KeeperCensusInvalid");
    const auto identity = in.Text(), token = in.Text(), census = in.Text(); const auto expiry = in.Number();
    if (relocation) Need(image && op == 2 && in.Number() == magic, "KeeperRelocationProfileInvalid");
    if (geometry) {
        Need(image && streamed && op<=2 && in.Number()==magic,"KeeperGeometryModeInvalid");
        const auto relocated=in.Number();Need(relocated<=(magic == volume_geometry::Version2Magic ? 2u : 1u) && (!relocated || op==2),"KeeperGeometryRelocationInvalid");
        const auto length=in.Number();Need(length<=(3u<<20) && length<=body.size()-in.at,"KeeperGeometryEvidenceBounds");
        const auto plan=volume_geometry::Decode(body.subspan(in.at,static_cast<std::size_t>(length)));in.at+=length;
        Need(volume_geometry::MagicOf(plan) == magic, "KeeperGeometryModeInvalid");
        const auto& binding=plan.snapshot.original;
        Need(source_path.wstring()==binding.instance && expected==binding.binding.media.limit_bytes && target==plan.snapshot.target_bytes &&
            identity==VolumePhysicalIdentity(binding.binding,binding.instance),"KeeperGeometryBindingMismatch");
        offset=binding.binding.media.base_offset_bytes;
        if(physical_binding)*physical_binding=binding;
        if(geometry_plan)*geometry_plan=plan;
    } else if (physical) {
        const bool management = !image && volume_physical::IsManagementMagic(magic);
        Need((management || (image && streamed && !relocation && op >= 3)) &&
            in.Number() == magic, "KeeperPhysicalModeInvalid");
        const auto length = in.Number(); Need(length <= 4096 && length <= body.size() - in.at, "KeeperPhysicalBindingSize");
        const auto binding = volume_physical::Decode(body.subspan(in.at, static_cast<std::size_t>(length))); in.at += length;
        Need(source_path.wstring() == binding.instance &&
            (management ? offset == binding.binding.media.base_offset_bytes : expected == binding.binding.media.limit_bytes) &&
            identity == VolumePhysicalIdentity(binding.binding, binding.instance), "KeeperPhysicalBindingMismatch");
        offset = binding.binding.media.base_offset_bytes;
        if (management) {
            expected = binding.binding.media.limit_bytes;
            const auto destination = in.Text();
            if (!destination.empty()) new_wal = Local(Wide(destination), false);
            Need(op == 1 ? !new_wal.empty() && paths.insert(PathKey(new_wal)).second && PathKey(new_wal) != PathKey(source_path) :
                new_wal.empty(), "KeeperPhysicalDestinationInvalid");
        }
        if (physical_binding) *physical_binding = binding;
    }
    if (flagged && !physical) Need(in.Number() == magic, "KeeperFlaggedFormatProfileInvalid");
    if (physical_snapshot && !physical) Need(in.Number() == magic, "KeeperSnapshotPolicyInvalid");
    const auto size = in.Number();
    Need(HexValid(identity, 80) && (locator.empty() || identity.substr(0, 64) == locator) && HexNumber(std::string_view(identity).substr(48, 16)) == offset,
        "KeeperStoredSourceLocatorMismatch");
    const auto original_size = streamed ? expected : size;
    Need(HexValid(token, 64) && HexValid(census, 64) && expiry && size && size <= (streamed ? JournalLimit : ImageLimit) && size == body.size() - in.at &&
        offset <= UINT64_MAX - original_size && HexNumber(std::string_view(identity).substr(64)) == offset + original_size &&
        (!image || streamed || size == expected) && (!physical || image || size == expected),
        "KeeperOriginalBindingInvalid");
    Need(archive_token.empty() || token == archive_token, "KeeperArchiveTokenMismatch");
    const auto original = body.subspan(in.at, size);
    std::unique_ptr<catalog::RandomAccessSource> storage;
    std::optional<format_evidence::Original> evidence;
    if (streamed) { evidence = format_evidence::Decode(original, expected); storage = std::make_unique<format_evidence::Snapshot>(*evidence); }
    else storage = std::make_unique<catalog::VectorRandomAccessSource>(Bytes(original.begin(), original.end()));
    const auto& source = *storage;
    Bytes header; Need(source.Read(0, 4096, header), "KeeperOriginalHeaderInvalid");
    const auto block_size = catalog::ReadU32LE(header, 0x24).value_or(0);
    Need(block_size >= 4096 && block_size <= 65536 && block_size <= original_size, "KeeperOriginalHeaderInvalid");
    Bytes block; Need(source.Read(0, block_size, block), "KeeperOriginalHeaderInvalid"); const auto nx = catalog::ParseNxSuperblock(block);
    Need(nx && nx->uuid_hex == container && nx->xid <= xid && nx->block_count == original_size / block_size && original_size % block_size == 0,
        "KeeperOriginalHeaderInvalid");
    std::string error;
    const auto checkpoint = catalog::LoadAppleCheckpointView(source, 0, original_size, error);
    Need(checkpoint && checkpoint->container.superblock.xid == xid && checkpoint->container.superblock.uuid_hex == container,
        "KeeperOriginalCheckpointMismatch");
    // Original frames are independent recovery authorities. Refuse opaque
    // snapshot history even when the later live image has no public snapshots.
    AppleSnapshotRetentionView snapshots;
    Need(LoadAppleSnapshotRetention(source, *checkpoint, snapshots, error) && snapshots.identities.empty() &&
        !checkpoint->container_object_map.snapshot_tree_oid, "KeeperOriginalSnapshotHistoryAuthorityUnproven");
    std::vector<std::uint64_t> metadata; std::vector<ApplePhysicalExtentRecord> payload;
    Need(LoadAppleSnapshotCheckpointOwners(source, *checkpoint, metadata, payload, error) && !metadata.empty(),
        "KeeperOriginalSnapshotHistoryAuthorityUnproven");
    // The complete owner census also contains headerless allocation bitmaps.
    // Their allocation bits are not APSB/OMAP object fields.
    std::set<std::uint64_t> raw_bitmaps;
    for (const auto& chunk : checkpoint->spaceman.chunks)
        if (chunk.bitmap_block) raw_bitmaps.insert(chunk.bitmap_block);
    for (const auto& bitmap : checkpoint->spaceman.internal_pool.active_bitmaps)
        raw_bitmaps.insert(bitmap.physical_block);
    for (const auto physical_block : metadata) {
        if (raw_bitmaps.contains(physical_block)) continue;
        Bytes bytes; Need(source.Read(physical_block * block_size, block_size, bytes), "KeeperOriginalOwnerUnreadable");
        const auto type = catalog::ReadU32LE(bytes, 0x18).value_or(0) & catalog::kObjectTypeMask;
        if (type == catalog::kObjectTypeFs)
            Need(catalog::ReadU64LE(bytes, 0xd8).value_or(UINT64_MAX) == 0, "KeeperOriginalSnapshotHistoryAuthorityUnproven");
        if (type == catalog::kObjectTypeOmap)
            Need(catalog::ReadU32LE(bytes, 0x24).value_or(UINT32_MAX) == 0 &&
                catalog::ReadU64LE(bytes, 0x38).value_or(UINT64_MAX) == 0, "KeeperOriginalSnapshotHistoryAuthorityUnproven");
    }
    Need(checkpoint->volumes.size() == oids.size(), "KeeperOriginalCensusMismatch");
    bool selected = false;
    for (const auto& v : checkpoint->volumes) {
        Need(oids.contains(v.superblock.object_id), "KeeperOriginalCensusMismatch");
        selected |= v.superblock.object_id == oid && v.superblock.uuid_hex == volume;
        if (!image && op == 1) Need(v.superblock.object_id != oid && v.superblock.uuid_hex != volume, "KeeperCreateIdentityReused");
        if (image && op >= 3) Need(v.superblock.uuid_hex != new_volume, "KeeperFormatIdentityReused");
    }
    Need(!image && op == 1 ? oid == checkpoint->container.superblock.next_oid : selected, "KeeperOriginalVolumeMismatch");
    if (history) {
        history->image_family = image; history->operation = op;
        history->source_identity = identity; history->token = token; history->image = source_path;
        history->census_digest = census;
        history->pre_xid = xid; history->post_xid = checkpoint->container.superblock.next_xid;
        Need(history->post_xid > xid, "KeeperHistoryPostXidInvalid");
        for (const auto& v : checkpoint->volumes)
            history->before.push_back({container, v.superblock.uuid_hex, v.superblock.object_id, wals.at(v.superblock.object_id)});
        history->after = history->before;
        if (image && op >= 3) {
            history->after = {{new_container, new_volume, 1024, new_wal}};
            // Destination storage is fenced before accepting a format operation.
            history->before.push_back(history->after.front());
        } else if (!image && op == 2) {
            std::erase_if(history->after, [&](const auto& member) { return member.oid == oid; });
        } else if (!image && op == 1) {
            history->after.push_back({container, volume, oid, new_wal});
            if (physical) history->before.push_back(history->after.back());
        }
    }
    return {identity.substr(0, 64), offset, offset + original_size};
}
struct DecodedJournal
{
    VolumeKeeperJournalState state;
    JournalScope source;
};
DecodedJournal Decode(const Bytes& bytes, bool image, const std::filesystem::path& root, std::string_view locator,
    std::string_view archive_token, VolumeKeeperHistoryBinding* history = nullptr, volume_physical::Envelope* physical_binding = nullptr,
    volume_geometry::Plan* geometry_plan = nullptr)
{
    Reader in{bytes}; const auto magic = in.Number();const bool geometry=image && volume_geometry::IsMagic(magic);
    const bool physical = image ? (volume_physical::IsFormatMagic(magic) || geometry) : volume_physical::IsManagementMagic(magic);
    const bool erase = image && (magic == format_evidence::EraseMagic ||
        (magic == format_evidence::FlaggedStreamedMagic && catalog::ReadU64LE(bytes, 48).value_or(0) == 4) ||
        (physical && catalog::ReadU64LE(bytes, 48).value_or(0) == 4));
    const bool relocation = image && (magic == format_evidence::RelocationMagic || magic == volume_geometry::PhysicalSnapshotRelocationMagic);
    const bool resize = image && (magic == format_evidence::ResizeMagic || relocation || geometry);
    const bool streamed = image && (magic == format_evidence::Magic || magic == format_evidence::FlaggedStreamedMagic || erase || resize || physical);
    Need(streamed || (!image && (physical || volume_physical::IsManagementImageMagic(magic))) || (image && magic == format_evidence::FlaggedImageMagic) || (image && magic == 0x3146495653465041ull), "KeeperFrameMagicInvalid");
    const auto size = in.Number(); Need(bytes.size() >= 48 && size <= bytes.size() - 48, "KeeperFrameLengthInvalid");
    std::array<std::byte, 32> digest{}; std::copy_n(bytes.begin() + 16, 32, digest.begin());
    const auto body = std::span<const std::byte>(bytes).subspan(48, size); Need(Hash(body) == digest, "KeeperFrameChecksumInvalid");
    const auto source = ValidateBody(body, image, root, locator, archive_token, history, streamed, erase, resize, relocation, physical, physical_binding,geometry,geometry_plan,magic);
    if (history) history->frame_digest = Hex(digest);
    std::uint64_t state = 0, cursor = 0; std::size_t at = 48 + size;
    const auto chunks = (source.end - source.begin + format_evidence::Chunk - 1) / format_evidence::Chunk;
    while (at != bytes.size()) {
        Need(bytes.size() - at >= 40, "KeeperReceiptTorn"); const auto next = catalog::ReadU64LE(bytes, at).value();
        const bool allowed = erase ? format_evidence::EraseTransition(static_cast<unsigned>(state), cursor, next, chunks) :
            image ? ((state == 0 && (next == 1 || next == 4)) || (state == 1 && next == 2) || (state == 2 && next == 3)) :
            ((state == 0 && (next == 1 || next == 3)) || (state == 1 && next == 2));
        Need(allowed, "KeeperReceiptTransitionInvalid"); Bytes binding(digest.begin(), digest.end()); Number(binding, next);
        const auto hash = Hash(binding); Need(std::equal(hash.begin(), hash.end(), bytes.begin() + at + 8), "KeeperReceiptChecksumInvalid");
        if (erase && (next & format_evidence::CursorTag)) cursor = next & ~format_evidence::CursorTag;
        else state = next;
        at += 40;
    }
    if (!state) return {VolumeKeeperJournalState::Prepared, source};
    if (state == 1) return {VolumeKeeperJournalState::Accepted, source};
    if (image && state == 2) return {VolumeKeeperJournalState::AnchorDurable, source};
    return {state == (image ? 3u : 2u) ? VolumeKeeperJournalState::Completed : VolumeKeeperJournalState::Cancelled, source};
}
const char* StateName(VolumeKeeperJournalState state)
{
    switch (state) {
    case VolumeKeeperJournalState::Missing: return "missing";
    case VolumeKeeperJournalState::Prepared: return "prepared";
    case VolumeKeeperJournalState::Accepted: return "accepted";
    case VolumeKeeperJournalState::AnchorDurable: return "anchor-durable";
    case VolumeKeeperJournalState::Completed: return "completed";
    case VolumeKeeperJournalState::Cancelled: return "cancelled";
    default: return "invalid";
    }
}
bool Terminal(VolumeKeeperJournalState state)
{ return state == VolumeKeeperJournalState::Missing || state == VolumeKeeperJournalState::Completed || state == VolumeKeeperJournalState::Cancelled; }
std::string Quote(std::string_view s)
{
    std::string out = "\""; constexpr char digits[] = "0123456789abcdef";
    for (unsigned char c : s) {
        if (c == '"' || c == '\\') { out += '\\'; out += char(c); }
        else if (c < 32) { out += "\\u00"; out += digits[c >> 4]; out += digits[c & 15]; }
        else out += char(c);
    }
    return out + '"';
}
}
VolumeKeeperHistoryBinding DecodeVolumeKeeperHistoryBinding(std::span<const std::byte> bytes,
    const std::filesystem::path& journal, const std::filesystem::path& trusted_root, std::string_view held_identity)
{
    Need(bytes.size() <= JournalLimit && HexValid(held_identity, 80), "KeeperHistoryFrameBoundsInvalid");
    const auto root = Local(trusted_root, true), path = Local(journal, false);
    Need(PathKey(path.parent_path()) == PathKey(root), "KeeperHistoryRootMismatch");
    const auto name = Utf8(path.filename().wstring());
    Need(name.size() == 69 || name.size() == 144, "KeeperHistoryJournalNameInvalid");
    const auto stem = JournalStem(held_identity.substr(0, 64));
    Need(name.starts_with(stem) && (name.substr(64, 5) == ".vmt1" || name.substr(64, 5) == ".vif1"), "KeeperHistoryJournalNameInvalid");
    std::string archive;
    if (name.size() == 144) {
        Need(name[69] == '.' && name.substr(134) == ".completed" && HexValid(name.substr(70, 64), 64), "KeeperHistoryArchiveInvalid");
        archive = name.substr(70, 64);
    }
    VolumeKeeperHistoryBinding binding; binding.journal = path;
    binding.state = Decode(Bytes(bytes.begin(), bytes.end()), name.substr(64, 5) == ".vif1", root,
        held_identity.substr(0, 64), archive, &binding).state;
    return binding;
}
RawSnapshotBinding DecodeVolumeKeeperPhysicalBinding(std::span<const std::byte> bytes)
{
    const auto magic=catalog::ReadU64LE(bytes,0).value_or(0);
    Need(bytes.size() <= JournalLimit && (volume_physical::IsFormatMagic(magic) || volume_physical::IsManagementMagic(magic) || volume_geometry::IsMagic(magic)),
        "KeeperPhysicalModeRequired");
    // Root/path validation is performed by the normal history decoder. Here the
    // entire immutable body is decoded again against the independently held cap.
    Reader header{bytes}; (void)header.Number(); const auto length = header.Number();
    Need(bytes.size() >= 48 && length <= bytes.size() - 48, "KeeperFrameLengthInvalid");
    const auto body = bytes.subspan(48, static_cast<std::size_t>(length));
    const auto digest = Hash(body); Need(std::equal(digest.begin(), digest.end(), bytes.begin() + 16), "KeeperFrameChecksumInvalid");
    Reader request{body}; (void)request.Number(); (void)request.Text(); const auto root = request.Path();
    volume_physical::Envelope binding;
    (void)Decode(Bytes(bytes.begin(), bytes.end()), !volume_physical::IsManagementMagic(magic), root, {}, {}, nullptr, &binding);
    return binding.binding;
}
volume_geometry::Plan DecodeVolumeKeeperGeometryPlan(std::span<const std::byte> bytes)
{
    Need(bytes.size()<=JournalLimit && volume_geometry::IsMagic(catalog::ReadU64LE(bytes,0).value_or(0)),"KeeperGeometryModeRequired");
    Reader header{bytes};(void)header.Number();const auto length=header.Number();
    Need(bytes.size()>=48 && length<=bytes.size()-48,"KeeperFrameLengthInvalid");
    Reader request{bytes.subspan(48,static_cast<std::size_t>(length))};(void)request.Number();(void)request.Text();const auto root=request.Path();
    volume_geometry::Plan plan;(void)Decode(Bytes(bytes.begin(),bytes.end()),true,root,{},{},nullptr,nullptr,&plan);return plan;
}
void ValidateVolumeKeeperPhysicalFrame(std::span<const std::byte> bytes, const VolumePhysicalSource& source)
{
    const auto binding = DecodeVolumeKeeperPhysicalBinding(bytes);
    Need(binding == source.Binding() && VolumePhysicalIdentity(binding, source.InstanceId()) == source.Identity() && source.Revalidate(),
        "KeeperPhysicalHeldBindingMismatch");
}
VolumeKeeperAdmission InspectHeldVolumeKeeperJournals(const std::filesystem::path& trusted_root,
    std::string_view held_identity, VolumeKeeperAdmissionScope scope)
{
    VolumeKeeperAdmission result; result.source_identity = held_identity;
    try {
        Need(scope == VolumeKeeperAdmissionScope::All || scope == VolumeKeeperAdmissionScope::ForeignToManagement ||
            scope == VolumeKeeperAdmissionScope::ForeignToImage, "KeeperAdmissionScopeInvalid");
        Need(HexValid(held_identity, 80), "KeeperHeldIdentityInvalid"); result.locator = held_identity.substr(0, 64);
        const auto begin = HexNumber(held_identity.substr(48, 16)), end = HexNumber(held_identity.substr(64, 16));
        Need(begin % 4096 == 0 && begin < end, "KeeperHeldGeometryInvalid");
        const auto root = Local(trusted_root, true); File directory; directory.Open(root, true);
        const auto stem = JournalStem(result.locator);
        result.admitted = true;
        const auto inspect = [&](bool image, const std::filesystem::path& path, bool archive, bool other_scope) {
            VolumeKeeperJournalEvidence evidence; evidence.family = image ? "vif1" : "vmt1"; evidence.path = path;
            try {
                const auto filename = Utf8(path.filename().wstring());
                Need(filename.size() >= 69 && HexValid(filename.substr(0, 64), 64) && filename.substr(64, 5) == "." + evidence.family,
                    "KeeperEvidenceNameInvalid");
                std::string archive_token;
                if (archive) {
                    Need(filename.size() == 144 && filename[69] == '.', "KeeperEvidenceNameInvalid");
                    const auto suffix = filename.substr(70);
                    Need(suffix.substr(64) == ".completed" && HexValid(suffix.substr(0, 64), 64), "KeeperEvidenceNameInvalid");
                    archive_token = suffix.substr(0, 64);
                }
                File file;
                if (file.Open(path, false, !archive && !other_scope)) {
                    const auto decoded = Decode(file.Read(), image, root, other_scope ? std::string_view{} : result.locator, archive_token);
                    Need(JournalStem(decoded.source.locator) == filename.substr(0, 64), "KeeperEvidenceLocatorNameMismatch");
                    if (other_scope) {
                        if (decoded.source.locator.substr(0, 48) != held_identity.substr(0, 48)) return;
                        // VIF owns file geometry. VMT owns its original suffix;
                        // changed file length cannot establish disjoint ownership.
                        const bool overlaps = image || decoded.source.end != end ||
                            (begin < decoded.source.end && decoded.source.begin < end);
                        if (!overlaps) return;
                    }
                    evidence.state = decoded.state;
                } else evidence.state = VolumeKeeperJournalState::Missing;
            } catch (const std::exception& ex) { evidence.state = VolumeKeeperJournalState::Invalid; evidence.error = ex.what(); }
            if (!Terminal(evidence.state)) {
                result.admitted = false;
                if (result.error.empty()) result.error = "VolumeKeeperAdmissionBlocked:" + evidence.family + ":" + StateName(evidence.state) +
                    (evidence.error.empty() ? "" : ":" + evidence.error);
            }
            result.journals.push_back(std::move(evidence));
        };
        for (bool image : {false, true}) {
            const bool own = (!image && scope == VolumeKeeperAdmissionScope::ForeignToManagement) || (image && scope == VolumeKeeperAdmissionScope::ForeignToImage);
            const auto family = image ? ".vif1" : ".vmt1";
            if (!own) inspect(image, root / (stem + family), false, false);
            WIN32_FIND_DATAW found{}; const auto pattern = Extended(root / (std::string("*") + family + "*"));
            Search search; search.handle = FindFirstFileW(pattern.c_str(), &found);
            if (search.handle == INVALID_HANDLE_VALUE) { Need(GetLastError() == ERROR_FILE_NOT_FOUND, "KeeperEvidenceEnumerationFailed"); continue; }
            unsigned count = 0; DWORD error = ERROR_SUCCESS;
            do {
                if (++count > 1024) { error = ERROR_TOO_MANY_NAMES; break; }
                const auto filename = Utf8(found.cFileName);
                const bool exact_scope = filename.starts_with(stem + family);
                if (exact_scope && (own || filename == stem + family)) continue;
                inspect(image, root / found.cFileName, filename.size() != 69, !exact_scope);
            } while (FindNextFileW(search.handle, &found));
            if (!error) error = GetLastError();
            Need(error == ERROR_NO_MORE_FILES, "KeeperEvidenceEnumerationFailedOrLimit");
        }
    } catch (const std::exception& ex) { result.admitted = false; result.error = ex.what(); }
    return result;
}
VolumeKeeperAdmission InspectVolumeKeeperImage(const std::filesystem::path& input, std::uint64_t offset, const std::filesystem::path& root)
{
    VolumeKeeperAdmission result;
    try {
        Need(offset % 4096 == 0, "KeeperOffsetUnaligned"); const auto path = Local(input, true); File image; image.Open(path);
        FILE_ID_INFO id{}; LARGE_INTEGER size{};
        Need(GetFileInformationByHandleEx(image.handle, FileIdInfo, &id, sizeof(id)) && GetFileSizeEx(image.handle, &size) &&
            size.QuadPart > 0 && offset < std::uint64_t(size.QuadPart), "KeeperImageIdentityUnavailable");
        std::ostringstream identity; identity << std::hex; identity.fill('0'); identity.width(16); identity << id.VolumeSerialNumber;
        identity << Hex(std::span(reinterpret_cast<const std::byte*>(id.FileId.Identifier), 16));
        identity.width(16); identity << offset; identity.width(16); identity << std::uint64_t(size.QuadPart);
        result = InspectHeldVolumeKeeperJournals(root, identity.str());
    } catch (const std::exception& ex) { result.error = ex.what(); }
    return result;
}
VolumeKeeperAdmission InspectHeldVolumeKeeperImage(const BlockDevice& source,
    const std::filesystem::path& root, bool historical_source)
{
    VolumeKeeperAdmission result;
    try {
        Need(!root.empty(), "VolumeKeeperJournalRootRequired");
        Need(!historical_source, "VolumeKeeperHistoricalSourceAmbiguous");
        BlockDevice::StableImageIdentity before{}, after{};
        Need(source.HasWriteHandle() && !source.IsRawWriterAccepted() && source.QueryHeldImageIdentity(before),
            "VolumeKeeperRetainedWritableImageRequired");
        const auto offset = source.BaseOffsetBytes();
        Need(offset % 4096 == 0 && before.size_bytes > offset, "VolumeKeeperHeldGeometryUnproven");
        std::ostringstream identity; identity << std::hex; identity.fill('0'); identity.width(16); identity << before.volume_serial;
        identity << Hex(before.file_id); identity.width(16); identity << offset; identity.width(16); identity << before.size_bytes;
        result = InspectHeldVolumeKeeperJournals(root, identity.str());
        Need(source.QueryHeldImageIdentity(after) && after == before, "VolumeKeeperHeldSourceChanged");
    } catch (const std::exception& ex) { result.admitted = false; result.error = ex.what(); }
    return result;
}
VolumeKeeperAdmission InspectHeldVolumeKeeperRaw(const BlockDevice& source,
    const std::filesystem::path& root)
{
    VolumeKeeperAdmission result;
    try {
        Need(!root.empty(), "VolumeKeeperJournalRootRequired");
        Need(source.IsRawWriterAccepted() && source.HasWriteHandle(), "VolumeKeeperRetainedRawWriterRequired");
        const auto lease = source.CaptureHeldRawSnapshotLease();
        const auto original = source.CaptureExclusiveWriteSourceObservation();
        Need(lease.has_value() && original.has_value(), "VolumeKeeperRetainedRawWriterRequired");
        RawSnapshotDescriptors descriptors, current;
        std::string error;
        Need(source.QueryHeldRawSnapshotDescriptors(*lease, descriptors, error), "VolumeKeeperHeldRawDescriptorsUnproven");
        Need(ValidateRawSnapshotMediaBinding(descriptors.media, error) &&
            descriptors.media.base_offset_bytes == source.BaseOffsetBytes() &&
            descriptors.media.limit_bytes == source.RawWriteLimitBytes() &&
            raw_snapshot_detail::CanonicalText(descriptors.device.serial) &&
            raw_snapshot_detail::NonGenericText(descriptors.device.serial), "VolumeKeeperHeldRawBindingUnproven");
        std::wstring instance, current_instance;
        Need(physical_instance::Selected(source.Path(), instance), "VolumeKeeperHeldRawInstanceUnproven");
        // Only the serial and window enter this codec. Keep kind Unavailable:
        // observing a source never creates operator qualification or a writer.
        RawSnapshotBinding identity_source;
        identity_source.hardware.serial = descriptors.device.serial;
        identity_source.media = descriptors.media;
        const auto identity = VolumePhysicalIdentity(identity_source, instance);
        result = InspectHeldVolumeKeeperJournals(root, identity);
        Need(physical_instance::Selected(source.Path(), current_instance) && current_instance == instance &&
            source.QueryHeldRawSnapshotDescriptors(*lease, current, error) && current == descriptors &&
            source.IsExclusiveWriteSourceObservationCurrent(*original) && source.IsHeldRawSnapshotLeaseCurrent(*lease),
            "VolumeKeeperHeldRawSourceChanged");
    } catch (const std::exception& ex) { result.admitted = false; result.error = ex.what(); }
    return result;
}
std::string VolumeKeeperAdmissionJson(const VolumeKeeperAdmission& result)
{
    std::ostringstream out; out << "{\"schemaVersion\":1,\"admitted\":" << (result.admitted ? "true" : "false") <<
        ",\"error\":" << Quote(result.error) << ",\"sourceIdentity\":" << Quote(result.source_identity) << ",\"locator\":" << Quote(result.locator) << ",\"journals\":[";
    bool first = true; for (const auto& journal : result.journals) {
        if (!first) out << ','; first = false;
        std::string path;
        try { path = Utf8(journal.path.wstring()); } catch (const std::exception&) { path = "<invalid UTF-16 path>"; }
        out << "{\"family\":" << Quote(journal.family) << ",\"path\":" << Quote(path) <<
            ",\"state\":" << Quote(StateName(journal.state)) << ",\"error\":" << Quote(journal.error) << '}';
    }
    out << "]}"; return out.str();
}
}
