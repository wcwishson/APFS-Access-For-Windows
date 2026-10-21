#include "VolumeResizeInternal.h"
#include "VolumeKeeperAdmission.h"
#include "VolumeKeeperWal.h"
#include "TransactionManager.h"
#include "VolumeFormatEvidence.h"
#include "VolumeResizeRelocation.h"
#include "VolumePhysicalKeeper.h"
#include "VolumePhysicalBindingCodec.h"
#include "VolumePhysicalGeometryInternal.h"
#include <Windows.h>
#include <winioctl.h>
#include <bcrypt.h>
#include <algorithm>
#include <chrono>
#include <cwctype>
#include <optional>
#include <sstream>

namespace apfsaccess::rw::volume_image
{
namespace
{
constexpr std::uint64_t MaxJournal = Limit + 1024 * 1024;
std::string Utf8(std::wstring_view s)
{
    if (s.empty()) return {};
    const auto n = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()), nullptr, 0, nullptr, nullptr);
    Require(n > 0, "VolumeImageUnicodeInvalid"); std::string result(n, ' ');
    Require(WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()), result.data(), n, nullptr, nullptr) == n,
        "VolumeImageUnicodeInvalid"); return result;
}
std::wstring Wide(std::string_view s)
{
    if (s.empty()) return {};
    const auto n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()), nullptr, 0);
    Require(n > 0, "VolumeImageUnicodeInvalid"); std::wstring result(n, L' ');
    Require(MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()), result.data(), n) == n,
        "VolumeImageUnicodeInvalid"); return result;
}
std::wstring Extended(const std::filesystem::path& p) { return L"\\\\?\\" + p.wstring(); }
std::filesystem::path Local(const std::filesystem::path& raw)
{
    const auto s = raw.wstring(); Require(s.size() >= 3 && s.size() < 32000 && std::iswalpha(s[0]) && s[1] == L':' &&
        (s[2] == L'\\' || s[2] == L'/') && s.find(L':', 2) == std::wstring::npos, "VolumeImageAbsoluteLocalPathRequired");
    auto p = raw.lexically_normal(); p.make_preferred();
    for (auto at = p; !at.empty() && at != at.root_path(); at = at.parent_path()) {
        const auto attrs = GetFileAttributesW(Extended(at).c_str());
        Require(attrs == INVALID_FILE_ATTRIBUTES || !(attrs & FILE_ATTRIBUTE_REPARSE_POINT), "VolumeImageReparsePathRefused");
    }
    return p;
}
bool Exists(const std::filesystem::path& p)
{
    const auto attrs = GetFileAttributesW(Extended(p).c_str());
    if (attrs != INVALID_FILE_ATTRIBUTES) return true;
    Require(GetLastError() == ERROR_FILE_NOT_FOUND || GetLastError() == ERROR_PATH_NOT_FOUND, "VolumeImagePathInspectionFailed"); return false;
}
std::array<std::byte, 32> Hash(std::span<const std::byte> b)
{
    BCRYPT_ALG_HANDLE alg{}; std::array<std::byte, 32> out{};
    Require(b.size() <= ULONG_MAX && BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) >= 0, "VolumeImageHashFailed");
    const auto status = BCryptHash(alg, nullptr, 0, reinterpret_cast<PUCHAR>(const_cast<std::byte*>(b.data())),
        static_cast<ULONG>(b.size()), reinterpret_cast<PUCHAR>(out.data()), 32);
    BCryptCloseAlgorithmProvider(alg, 0); Require(status >= 0, "VolumeImageHashFailed"); return out;
}
std::string Hex(std::span<const std::byte> b)
{
    std::string out; const char* h = "0123456789abcdef";
    for (auto v : b) { const auto c = std::to_integer<unsigned>(v); out += h[c >> 4]; out += h[c & 15]; } return out;
}
void Number(Bytes& b, std::uint64_t n) { const auto at = b.size(); b.resize(at + 8); Put(b, at, n); }
void Text(Bytes& b, std::string_view s)
{ Number(b, s.size()); for (unsigned char c : s) b.push_back(std::byte(c)); }
struct Reader
{
    std::span<const std::byte> b; std::size_t at = 0;
    std::uint64_t Number() { Require(at <= b.size() && b.size() - at >= 8, "VolumeImageJournalTruncated");
        const auto n = catalog::ReadU64LE(b, at).value(); at += 8; return n; }
    std::string Text() { const auto n = Number(); Require(n <= 131072 && n <= b.size() - at, "VolumeImageJournalStringInvalid");
        std::string s(reinterpret_cast<const char*>(b.data() + at), n); at += n; return s; }
};
std::uint64_t Now() { return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count(); }
bool Streamed(const VolumeImageRequest& r)
{ return r.expected_bytes > Limit || r.target_bytes > Limit; }
ImageAdmission StreamAdmission(const VolumeImageRequest& r)
{ return !IsFormat(r.operation) ? ImageAdmission::StreamedResize :
    r.operation == VolumeImageOperation::Erase ? ImageAdmission::StreamedErase : ImageAdmission::StreamedFormat; }
VolumeImageRequest Normalize(VolumeImageRequest r, bool physical = false, bool geometry = false)
{
    Require(!physical || (geometry ? !IsFormat(r.operation) : IsFormat(r.operation)), "VolumePhysicalOperationUnproved");
    ValidateRequest(r, physical || Streamed(r) ? StreamAdmission(r) : ImageAdmission::BoundedImage);
    if (!physical) r.image = Local(r.image);
    r.journal_directory = Local(r.journal_directory);
    if (!r.history_context.spool_root.empty()) r.history_context.spool_root = Local(r.history_context.spool_root);
    if (!r.history_context.recovery_root.empty()) r.history_context.recovery_root = Local(r.history_context.recovery_root);
    Require(!r.sibling_wals.empty() && r.sibling_wals.size() <= 100, "VolumeImageWalCensusRequired");
    for (auto& [id, path] : r.sibling_wals) { Require(id != 0, "VolumeImageWalOidInvalid"); path = Local(path); }
    if (IsFormat(r.operation)) r.new_volume_wal = Local(r.new_volume_wal);
    return r;
}
Bytes Encode(const VolumeImageRequest& r)
{
    Bytes b; Number(b, static_cast<unsigned>(r.operation)); Text(b, Utf8(r.image.wstring())); Text(b, Utf8(r.journal_directory.wstring()));
    Text(b, r.container_uuid); Text(b, r.volume_uuid); Number(b, r.volume_oid); Number(b, r.checkpoint_xid);
    Number(b, r.expected_bytes); Number(b, r.target_bytes); Text(b, r.new_container_uuid); Text(b, r.new_volume_uuid);
    Text(b, r.name_utf8); Number(b, r.case_sensitive); Text(b, Utf8(r.new_volume_wal.wstring())); Number(b, r.sibling_wals.size());
    for (const auto& [id, path] : r.sibling_wals) { Number(b, id); Text(b, Utf8(path.wstring())); } return b;
}
VolumeImageRequest DecodeRequest(Reader& in, bool streamed = false, bool physical = false)
{
    VolumeImageRequest r; const auto op = in.Number(); Require(op >= 1 && op <= 4, "VolumeImageJournalOperationInvalid");
    r.operation = static_cast<VolumeImageOperation>(op); r.image = Wide(in.Text()); r.journal_directory = Wide(in.Text());
    r.container_uuid = in.Text(); r.volume_uuid = in.Text(); r.volume_oid = in.Number(); r.checkpoint_xid = in.Number();
    r.expected_bytes = in.Number(); r.target_bytes = in.Number(); r.new_container_uuid = in.Text(); r.new_volume_uuid = in.Text();
    r.name_utf8 = in.Text(); const auto cs = in.Number(); Require(cs <= 1, "VolumeImageJournalCaseInvalid"); r.case_sensitive = cs != 0;
    r.new_volume_wal = Wide(in.Text()); const auto n = in.Number(); Require(n > 0 && n <= 100, "VolumeImageJournalCensusInvalid");
    for (auto i = 0ull; i < n; ++i) { const auto oid = in.Number(); auto path = Wide(in.Text());
        Require(r.sibling_wals.emplace(oid, path).second, "VolumeImageJournalDuplicateWal"); }
    Require(!streamed || physical || Streamed(r), "VolumeImageJournalStreamedProfileInvalid");
    ValidateRequest(r, streamed ? StreamAdmission(r) : ImageAdmission::BoundedImage); return r;
}
class File : public AppleCheckpointWriteTarget
{
public:
    HANDLE h = INVALID_HANDLE_VALUE;
    std::filesystem::path file_path;
    File() = default; File(const File&) = delete; File& operator=(const File&) = delete;
    ~File() { Close(); }
    void Close() { if (h != INVALID_HANDLE_VALUE) { CloseHandle(h); h = INVALID_HANDLE_VALUE; } }
    void Open(const std::filesystem::path& p, DWORD access, DWORD share, DWORD disposition, bool directory = false)
    {
        file_path = p;
        h = CreateFileW(Extended(p).c_str(), access, share, nullptr, disposition,
            FILE_FLAG_OPEN_REPARSE_POINT | (directory ? FILE_FLAG_BACKUP_SEMANTICS : FILE_FLAG_WRITE_THROUGH), nullptr);
        Require(h != INVALID_HANDLE_VALUE, "VolumeImageFileBusyOrUnavailable:" + std::to_string(GetLastError()));
        FILE_STANDARD_INFO si{}; FILE_ATTRIBUTE_TAG_INFO ai{};
        Require(GetFileType(h) == FILE_TYPE_DISK && GetFileInformationByHandleEx(h, FileStandardInfo, &si, sizeof(si)) &&
            !!si.Directory == directory && !si.DeletePending && (directory || si.NumberOfLinks == 1) &&
            GetFileInformationByHandleEx(h, FileAttributeTagInfo, &ai, sizeof(ai)) &&
            !(ai.FileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DEVICE)), "VolumeImageOrdinarySingleLinkFileRequired");
    }
    std::uint64_t Size() const
    { LARGE_INTEGER n{}; Require(GetFileSizeEx(h, &n) && n.QuadPart >= 0, "VolumeImageSizeUnavailable"); return n.QuadPart; }
    std::string Identity() const
    {
        FILE_ID_INFO id{}; Require(GetFileInformationByHandleEx(h, FileIdInfo, &id, sizeof(id)), "VolumeImageIdentityUnavailable");
        std::ostringstream o; o << std::hex; o.width(16); o.fill('0'); o << id.VolumeSerialNumber;
        o << Hex(std::span(reinterpret_cast<const std::byte*>(id.FileId.Identifier), 16));
        o << std::string(16, '0'); o.width(16); o << Size(); return o.str();
    }
    Bytes ReadAll(std::uint64_t limit = MaxJournal)
    {
        const auto n = Size(); Require(n <= limit, "VolumeImageBoundedFileExceeded"); Bytes b(n);
        LARGE_INTEGER zero{}; DWORD got{}; Require(SetFilePointerEx(h, zero, nullptr, FILE_BEGIN) &&
            ReadFile(h, b.data(), static_cast<DWORD>(b.size()), &got, nullptr) && got == b.size(), "VolumeImageReadFailed"); return b;
    }
    bool ReadRange(std::uint64_t offset, std::size_t size, Bytes& bytes) const
    {
        bytes.clear(); const auto length = Size();
        if (offset > length || size > length - offset || size > MAXDWORD) return false;
        LARGE_INTEGER at{}; at.QuadPart = offset; DWORD got{}; bytes.resize(size);
        if (!SetFilePointerEx(h, at, nullptr, FILE_BEGIN) ||
            !ReadFile(h, bytes.data(), static_cast<DWORD>(size), &got, nullptr) || got != size) { bytes.clear(); return false; }
        return true;
    }
    bool ReadBlock(std::uint64_t block, std::uint32_t bs, Bytes& b) override
    {
        LARGE_INTEGER at{}; at.QuadPart = block * bs; DWORD got{}; b.resize(bs);
        return SetFilePointerEx(h, at, nullptr, FILE_BEGIN) && ReadFile(h, b.data(), bs, &got, nullptr) && got == bs;
    }
    bool WriteBlock(std::uint64_t block, std::span<const std::byte> b) override
    {
        LARGE_INTEGER at{}; at.QuadPart = block * Block; DWORD written{};
        return b.size() <= MAXDWORD && SetFilePointerEx(h, at, nullptr, FILE_BEGIN) &&
            WriteFile(h, b.data(), static_cast<DWORD>(b.size()), &written, nullptr) && written == b.size();
    }
    bool Flush() override { return FlushFileBuffers(h) != FALSE; }
    bool ZeroRange(std::uint64_t offset, std::size_t size)
    {
        if (offset % Block || size % Block || size > format_evidence::Chunk || offset > Size() || size > Size() - offset) return false;
        FILE_ATTRIBUTE_TAG_INFO info{};
        if (!GetFileInformationByHandleEx(h, FileAttributeTagInfo, &info, sizeof(info))) return false;
        if (info.FileAttributes & FILE_ATTRIBUTE_SPARSE_FILE) {
            FILE_ZERO_DATA_INFORMATION range{}; range.FileOffset.QuadPart = offset; range.BeyondFinalZero.QuadPart = offset + size;
            DWORD returned{}; return DeviceIoControl(h, FSCTL_SET_ZERO_DATA, &range, sizeof(range), nullptr, 0, &returned, nullptr) != FALSE;
        }
        return WriteBlock(offset / Block, Bytes(size));
    }
    void Append(const Bytes& b)
    {
        LARGE_INTEGER zero{}; DWORD n{};
        Require(b.size() <= MAXDWORD && SetFilePointerEx(h, zero, nullptr, FILE_END) &&
            WriteFile(h, b.data(), static_cast<DWORD>(b.size()), &n, nullptr) && n == b.size() && Flush(), "VolumeImageJournalDurabilityFailed");
    }
    void Resize(std::uint64_t size)
    { LARGE_INTEGER at{}; at.QuadPart = size; Require(SetFilePointerEx(h, at, nullptr, FILE_BEGIN) && SetEndOfFile(h) && Flush(), "VolumeImageLengthDurabilityFailed"); }
};
class KeeperTarget final : public File
{
public:
    std::shared_ptr<VolumePhysicalSource> physical;
    std::shared_ptr<VolumePhysicalGeometrySource> geometry;
    std::uint64_t logical_size = 0;
    const RawSnapshotBinding* PhysicalBinding() const { return geometry ? &geometry->OriginalBinding() : physical ? &physical->Binding() : nullptr; }
    std::uint64_t Size() const { return geometry ? logical_size : physical ? physical->SizeBytes() : File::Size(); }
    std::string Identity() const { return geometry ? VolumePhysicalIdentity(geometry->OriginalBinding(),geometry->InstanceId()) : physical ? physical->Identity() : File::Identity(); }
    bool ReadRange(std::uint64_t offset, std::size_t size, Bytes& out) const
    { return geometry ? offset<=logical_size && size<=logical_size-offset && VolumePhysicalGeometryAccess::ReadWindow(*geometry,offset,size,out) :
        physical ? physical->Read(offset, size, out) : File::ReadRange(offset, size, out); }
    bool ReadBlock(std::uint64_t block, std::uint32_t size, Bytes& out) override
    { return geometry ? size==Block && block<logical_size/Block && ReadRange(block*Block,size,out) : physical ? physical->ReadBlock(block, size, out) : File::ReadBlock(block, size, out); }
    bool ReadBlockRangeForVerification(std::uint64_t block, std::uint32_t size, std::size_t maximum, Bytes& out) override
    { return geometry ? maximum && ReadBlock(block,size,out) : physical ? physical->ReadBlockRangeForVerification(block, size, maximum, out) :
        File::ReadBlockRangeForVerification(block, size, maximum, out); }
    bool WriteBlock(std::uint64_t block, std::span<const std::byte> bytes) override
    { return geometry ? VolumePhysicalGeometryAccess::WriteWindow(*geometry,block,bytes) : physical ? physical->WriteBlock(block, bytes) : File::WriteBlock(block, bytes); }
    bool Flush() override { return geometry ? VolumePhysicalGeometryAccess::Flush(*geometry) : physical ? physical->Flush() : File::Flush(); }
    bool ZeroRange(std::uint64_t offset, std::size_t size)
    { return geometry ? VolumePhysicalGeometryAccess::ZeroWindow(*geometry,offset,size) : physical ? physical->ZeroRange(offset, size) : File::ZeroRange(offset, size); }
    Bytes ReadAll(std::uint64_t limit = MaxJournal)
    { Require(!physical && !geometry, "VolumePhysicalWholeBufferRefused"); return File::ReadAll(limit); }
    void Resize(std::uint64_t size)
    { if(geometry) {logical_size=size;return;} Require(!physical, "VolumePhysicalLengthChangeRefused"); File::Resize(size); }
};
struct Journal
{
    VolumeImageRequest request; std::string identity, token, census; std::uint64_t expiry = 0;
    Bytes original; std::array<std::byte, 32> digest{};
    std::optional<format_evidence::Original> evidence;
    std::optional<volume_physical::Envelope> physical;
    std::optional<volume_geometry::Plan> geometry;
    bool relocation = false;
    bool physical_snapshot_relocation = false;
    bool flagged_format = false;
    std::uint64_t erase_cursor = 0;
    // 0 prepared, 1 accepted, 2 anchor durable, 3 complete, 4 cancelled.
    unsigned state = 0; bool partial = false; std::size_t valid_bytes = 0;
};
Bytes Frame(const Journal& j)
{
    auto b = Encode(j.request); Text(b, j.identity); Text(b, j.token); Text(b, j.census); Number(b, j.expiry);
    if (j.geometry) {
        Require(j.evidence && !j.physical && !IsFormat(j.request.operation),"VolumeGeometryJournalModeInvalid");
        Require(!j.physical_snapshot_relocation || volume_geometry::MagicOf(*j.geometry) == volume_geometry::Version2Magic,
            "VolumeGeometryRelocationVersionInvalid");
        const auto bytes=volume_geometry::Encode(*j.geometry);Number(b,volume_geometry::MagicOf(*j.geometry));
        Number(b,j.physical_snapshot_relocation ? 2 : j.relocation ? 1 : 0);Number(b,bytes.size());b.insert(b.end(),bytes.begin(),bytes.end());
    }
    if (j.relocation && !j.geometry) { Require(j.evidence && j.request.operation == VolumeImageOperation::Shrink, "VolumeImageRelocationProfileInvalid");
        Number(b, j.physical_snapshot_relocation ? volume_geometry::PhysicalSnapshotRelocationMagic : format_evidence::RelocationMagic); }
    if (j.physical) {
        Require(j.evidence && !j.relocation && IsFormat(j.request.operation), "VolumePhysicalJournalProfileInvalid");
        const auto binding = volume_physical::Encode(j.physical->binding, j.physical->instance);
        Number(b, j.flagged_format ? volume_physical::FlaggedFormatMagic : volume_physical::Magic); Number(b, binding.size()); b.insert(b.end(), binding.begin(), binding.end());
    }
    if (j.flagged_format && !j.physical) Number(b, j.evidence ? format_evidence::FlaggedStreamedMagic : format_evidence::FlaggedImageMagic);
    Bytes encoded; if (j.evidence) encoded = format_evidence::Encode(*j.evidence);
    const auto& original = j.evidence ? encoded : j.original;
    Number(b, original.size()); b.insert(b.end(), original.begin(), original.end());
    const bool erase = j.evidence && j.request.operation == VolumeImageOperation::Erase;
    Bytes out; Number(out, j.evidence ? (j.geometry ? volume_geometry::MagicOf(*j.geometry) : j.physical ? volume_physical::Magic :
        j.physical_snapshot_relocation ? volume_geometry::PhysicalSnapshotRelocationMagic : j.relocation ? format_evidence::RelocationMagic : !IsFormat(j.request.operation) ? format_evidence::ResizeMagic :
        erase ? format_evidence::EraseMagic : format_evidence::Magic) : 0x3146495653465041ull);
    if (j.flagged_format) {
        Require(IsFormat(j.request.operation) && !j.geometry && !j.relocation, "VolumeImageFlaggedFormatProfileInvalid");
        Put(out, 0, j.physical ? volume_physical::FlaggedFormatMagic : j.evidence ? format_evidence::FlaggedStreamedMagic : format_evidence::FlaggedImageMagic);
    }
    Number(out, b.size()); const auto hash = Hash(b);
    out.insert(out.end(), hash.begin(), hash.end()); out.insert(out.end(), b.begin(), b.end());
    const auto cursors = erase ? (j.request.expected_bytes + format_evidence::Chunk - 1) / format_evidence::Chunk : 0;
    Require(out.size() + 120 + cursors * 40 <= MaxJournal, "VolumeImageJournalCapacityExceeded"); return out;
}
Bytes Receipt(const std::array<std::byte, 32>& digest, std::uint64_t state)
{
    Bytes b(digest.begin(), digest.end()); Number(b, state); const auto hash = Hash(b);
    Bytes out; Number(out, state); out.insert(out.end(), hash.begin(), hash.end()); return out;
}
Journal Decode(const Bytes& b)
{
    Reader in{b}; const auto magic = in.Number(); const bool geometry=volume_geometry::IsMagic(magic);const bool physical = volume_physical::IsFormatMagic(magic);
    const bool flagged = magic == format_evidence::FlaggedImageMagic || magic == format_evidence::FlaggedStreamedMagic || magic == volume_physical::FlaggedFormatMagic;
    bool erase = magic == format_evidence::EraseMagic || ((magic == format_evidence::FlaggedStreamedMagic || physical) && catalog::ReadU64LE(b, 48).value_or(0) == 4);
    const bool relocation = magic == format_evidence::RelocationMagic || magic == volume_geometry::PhysicalSnapshotRelocationMagic;
    const bool resize = magic == format_evidence::ResizeMagic || relocation || geometry;
    const bool streamed = magic == format_evidence::Magic || magic == format_evidence::FlaggedStreamedMagic || erase || resize || physical;
    Require(streamed || magic == format_evidence::FlaggedImageMagic || magic == 0x3146495653465041ull, "VolumeImageJournalMagicInvalid"); const auto n = in.Number();
    Require(b.size() >= 48 && n <= b.size() - 48, "VolumeImageJournalLengthInvalid");
    Journal j; std::copy_n(b.begin() + 16, 32, j.digest.begin()); const auto body = std::span<const std::byte>(b).subspan(48, n);
    Require(Hash(body) == j.digest, "VolumeImageJournalChecksumInvalid"); Reader data{body}; j.request = DecodeRequest(data, streamed, physical || geometry);
    Require(!flagged || IsFormat(j.request.operation), "VolumeImageFlaggedFormatProfileInvalid"); j.flagged_format = flagged;
    Require(!streamed || (physical ? IsFormat(j.request.operation) : resize ? !IsFormat(j.request.operation) :
        erase ? j.request.operation == VolumeImageOperation::Erase : j.request.operation == VolumeImageOperation::Format),
        "VolumeImageJournalStreamedProfileInvalid");
    j.identity = data.Text(); j.token = data.Text(); j.census = data.Text(); j.expiry = data.Number(); j.relocation = relocation;
    j.physical_snapshot_relocation = magic == volume_geometry::PhysicalSnapshotRelocationMagic;
    if(geometry) {
        Require(data.Number()==magic,"VolumeGeometryJournalModeInvalid");const auto relocate=data.Number(),size=data.Number();
        Require(relocate<=(magic == volume_geometry::Version2Magic ? 2u : 1u) && (!relocate || j.request.operation==VolumeImageOperation::Shrink) && size<=(3u<<20) && size<=body.size()-data.at,"VolumeGeometryJournalSizeInvalid");
        j.geometry=volume_geometry::Decode(body.subspan(data.at,static_cast<std::size_t>(size)));data.at+=size;j.relocation=relocate!=0;
        j.physical_snapshot_relocation = relocate == 2;
        Require(volume_geometry::MagicOf(*j.geometry) == magic, "VolumeGeometryJournalModeInvalid");
        const auto& g=*j.geometry;
        Require(j.request.image.wstring()==g.snapshot.original.instance && j.request.expected_bytes==g.snapshot.original.binding.media.limit_bytes &&
            j.request.target_bytes==g.snapshot.target_bytes && j.identity==VolumePhysicalIdentity(g.snapshot.original.binding,g.snapshot.original.instance),"VolumeGeometryJournalScopeMismatch");
    }
    if (relocation) Require(j.request.operation == VolumeImageOperation::Shrink && data.Number() == magic,
        "VolumeImageRelocationProfileInvalid");
    if (physical) {
        Require(data.Number() == magic, "VolumePhysicalJournalProfileInvalid"); const auto size = data.Number();
        Require(size <= 4096 && size <= body.size() - data.at, "VolumePhysicalBindingSize");
        j.physical = volume_physical::Decode(body.subspan(data.at, static_cast<std::size_t>(size))); data.at += size;
        Require(j.request.image.wstring() == j.physical->instance && j.request.expected_bytes == j.physical->binding.media.limit_bytes &&
            j.identity == VolumePhysicalIdentity(j.physical->binding, j.physical->instance), "VolumePhysicalJournalBindingMismatch");
        erase = j.request.operation == VolumeImageOperation::Erase;
    }
    if (flagged && !physical) Require(data.Number() == magic, "VolumeImageFlaggedFormatProfileInvalid");
    const auto bytes = data.Number();
    Require(bytes == body.size() - data.at && j.token.size() == 64, "VolumeImageJournalOriginalInvalid");
    if (streamed) j.evidence = format_evidence::Decode(body.subspan(data.at), j.request.expected_bytes);
    else { Require(bytes == j.request.expected_bytes && bytes <= Limit, "VolumeImageJournalOriginalInvalid");
        j.original.assign(body.begin() + data.at, body.end()); }
    std::size_t at = 48 + n;
    const auto allowed = [&](std::uint64_t next) {
        if (erase) return format_evidence::EraseTransition(j.state, j.erase_cursor, next, j.evidence->digests.size());
        return (j.state == 0 && (next == 1 || next == 4)) || (j.state == 1 && next == 2) || (j.state == 2 && next == 3);
    };
    while (b.size() - at >= 40) {
        const auto next = catalog::ReadU64LE(b, at).value_or(99); Require(allowed(next), "VolumeImageReceiptStateInvalid");
        const auto receipt = Receipt(j.digest, next);
        Require(std::equal(receipt.begin(), receipt.end(), b.begin() + at), "VolumeImageReceiptChecksumInvalid");
        if (next & format_evidence::CursorTag) j.erase_cursor = next & ~format_evidence::CursorTag;
        else j.state = static_cast<unsigned>(next);
        at += 40;
    }
    j.valid_bytes = at;
    if (at != b.size()) {
        bool legal = false; for (unsigned next = 1; next <= 4; ++next) if (allowed(next)) {
            const auto receipt = Receipt(j.digest, next); legal |= std::equal(b.begin() + at, b.end(), receipt.begin()); }
        const auto next = format_evidence::CursorTag | (j.erase_cursor + 1);
        if (erase && allowed(next)) { const auto receipt = Receipt(j.digest, next);
            legal |= std::equal(b.begin() + at, b.end(), receipt.begin()); }
        Require(legal, "VolumeImageReceiptTailInvalid"); j.partial = true;
    }
    return j;
}
void Transition(File& f, Journal& j, unsigned next) { f.Append(Receipt(j.digest, next)); j.state = next; }
Bytes HistoryFrame(File& file, const Journal& journal)
{ auto bytes = file.ReadAll(); bytes.resize(journal.valid_bytes); return bytes; }
}
struct Session
{
    VolumeImageRequest r; File directory; KeeperTarget image; std::string identity; std::filesystem::path journal;
    std::vector<std::unique_ptr<WriteAheadLog>> leases;
    std::vector<std::unique_ptr<File>> fences;
    std::optional<std::string> held_census;
    Bytes held_checkpoint;
    std::unique_ptr<VolumeKeeperHistoryLease> history;
    std::unique_ptr<VolumeKeeperCancellationFence> cancellation;
    std::vector<VolumeKeeperHeldWal> HeldWals() const
    {
        std::vector<VolumeKeeperHeldWal> result;
        for (const auto& file : fences) result.push_back({file->file_path, file->h});
        return result;
    }
    void HoldHistory(const catalog::AppleCheckpointView& cp, const Bytes& current, File& prepared)
    {
        std::vector<VolumeKeeperHistoryMember> members;
        for (const auto& v : cp.volumes)
            members.push_back({cp.container.superblock.uuid_hex, v.superblock.uuid_hex, v.superblock.object_id,
                r.sibling_wals.at(v.superblock.object_id)});
        history = AcquireVolumeKeeperHistory(identity, current, r.journal_directory, members, HeldWals(),
            journal, prepared.ReadAll(), r.history_context);
    }
    void HoldStreamHistory(const catalog::RandomAccessSource& source, const std::vector<VolumeKeeperHistoryMember>& members,
        std::span<const std::byte> frame, bool terminal = false)
    {
        history = image.geometry ? AcquireVolumeKeeperGeometryHistory(image.geometry, source, r.journal_directory, members,
            HeldWals(),journal,frame,r.history_context,terminal) : image.physical ? AcquireVolumeKeeperPhysicalHistory(image.physical, source, r.journal_directory, members,
            HeldWals(), journal, frame, r.history_context, terminal) :
            AcquireVolumeKeeperHistory(identity, source, r.journal_directory, members, HeldWals(), journal, frame, r.history_context, terminal);
    }
    void HoldCancellation(const catalog::RandomAccessSource& source, std::span<const std::byte> frame)
    {
        cancellation = image.geometry ? AcquireVolumeKeeperGeometryCancellationMarkers(image.geometry,source,journal,frame,r.history_context) : image.physical ? AcquireVolumeKeeperPhysicalCancellationMarkers(image.physical, source, journal, frame, r.history_context) :
            AcquireVolumeKeeperCancellationMarkers(identity, source, journal, frame, r.history_context);
    }
    Session(const VolumeImageRequest& input, std::shared_ptr<VolumePhysicalSource> physical = {},std::shared_ptr<VolumePhysicalGeometrySource> geometry = {}) : r(Normalize(input, !!physical || !!geometry,!!geometry))
    {
        directory.Open(r.journal_directory, GENERIC_WRITE | FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE, OPEN_EXISTING, true);
        if(geometry) {
            Require(r.image.wstring()==geometry->InstanceId() && r.expected_bytes==geometry->OriginalBinding().media.limit_bytes && geometry->Revalidate(),"VolumeGeometryHeldAuthorityMismatch");
            image.geometry=std::move(geometry);image.logical_size=r.expected_bytes;
        } else if (physical) {
            Require(r.image.wstring() == physical->InstanceId() && r.expected_bytes == physical->SizeBytes() && physical->Revalidate(),
                "VolumePhysicalHeldAuthorityMismatch"); image.physical = std::move(physical);
        } else image.Open(r.image, GENERIC_READ | GENERIC_WRITE, 0, OPEN_EXISTING);
        Require(image.Size() > 0 && image.Size() <= (image.PhysicalBinding() || Streamed(r) ? StreamedFormatLimit : Limit), "VolumeImageBoundedFileExceeded"); identity = image.Identity();
        Require(identity.size() == 80, "VolumeImageIdentityShapeInvalid");
        Bytes key; Text(key, identity.substr(0, 64)); const auto stem = Hex(Hash(key)); journal = r.journal_directory / (stem + ".vif1");
        const auto admission = InspectHeldVolumeKeeperJournals(r.journal_directory, identity, VolumeKeeperAdmissionScope::ForeignToImage);
        Require(admission.admitted, admission.error);
    }
    std::string Census(const catalog::AppleCheckpointView& cp, bool create = false)
    {
        if (held_census) {
            Require(cp.container.superblock_bytes == held_checkpoint &&
                fences.size() == r.sibling_wals.size() + IsFormat(r.operation), "VolumeImageHeldCensusBindingMismatch");
            return *held_census;
        }
        Require(cp.volumes.size() == r.sibling_wals.size(), "VolumeImageCompleteWalCensusRequired");
        Bytes binding; std::set<std::wstring> paths; std::set<std::string> file_ids;
        const auto acquire = [&](const std::filesystem::path& path, const std::string& container, const std::string& volume, std::uint64_t oid, bool destination = false) {
            auto folded = path.wstring(); std::transform(folded.begin(), folded.end(), folded.begin(), [](auto c) { return std::towlower(c); });
            Require(paths.insert(folded).second && _wcsicmp(path.c_str(), r.image.c_str()) && _wcsicmp(path.c_str(), journal.c_str()), "VolumeImageWalPathAlias");
            const auto identities = image.PhysicalBinding() ? AcquireVolumeKeeperPhysicalWalLeases(path, *image.PhysicalBinding(), container, oid, leases, "VolumeImage") :
                AcquireVolumeKeeperWalLeases(path, container, oid, leases, "VolumeImage");
            if (create && !r.history_context.spool_root.empty()) {
                const auto canonical = r.history_context.spool_root / ("apfs_recovery_v1_" + identities.production.substr(17)) / "write-ahead.wal";
                if (_wcsicmp(path.c_str(), canonical.c_str()) == 0)
                    PersistVolumeKeeperNamespaceWitness(r.journal_directory,
                        BuildVolumeKeeperNamespaceMaterial(container, oid, image.PhysicalBinding()));
            }
            WIN32_FIND_DATAW found{}; const auto pattern = Extended(path) + L".compact*";
            auto search = FindFirstFileW(pattern.c_str(), &found);
            if (search != INVALID_HANDLE_VALUE) { FindClose(search); throw std::runtime_error("VolumeImageWalCompactionEvidence"); }
            Require(GetLastError() == ERROR_FILE_NOT_FOUND, "VolumeImageWalCompactionCensusFailed");
            const bool bootstrap = create && (destination || r.history_context.spool_root.empty());
            auto file = std::make_unique<File>(); file->Open(path, GENERIC_READ, FILE_SHARE_READ, bootstrap ? OPEN_ALWAYS : OPEN_EXISTING);
            if (destination) Require(file->ReadAll().empty(), "VolumeImageDestinationWalNotEmpty");
            const auto id = file->Identity().substr(0, 48);
            Require(id != identity.substr(0, 48) && file_ids.insert(id).second, "VolumeImageWalFileAlias");
            const auto watermarks = InspectVolumeKeeperWal(std::filesystem::path(Extended(path)), identities, "VolumeImage", "WalDebtOrPins");
            Text(binding, identities.canonical); Text(binding, volume); Text(binding, Utf8(path.wstring())); Text(binding, id);
            Number(binding, watermarks.accepted_sequence); Number(binding, watermarks.apfs_durable_sequence); Number(binding, watermarks.cleanup_sequence);
            Text(binding, Hex(Hash(file->ReadAll()))); fences.push_back(std::move(file));
        };
        for (const auto& v : cp.volumes) {
            const auto oid = v.superblock.object_id; Require(r.sibling_wals.contains(oid), "VolumeImageSiblingWalMissing");
            acquire(r.sibling_wals.at(oid), r.container_uuid, v.superblock.uuid_hex, oid);
        }
        if (IsFormat(r.operation)) acquire(r.new_volume_wal, r.new_container_uuid, r.new_volume_uuid, 1024, true);
        held_checkpoint = cp.container.superblock_bytes;
        held_census = Hex(Hash(binding)); return *held_census;
    }
    Plan Build(const Journal& j, bool create, bool completed_history = false)
    {
        Require(!completed_history || (!create && j.state == 3), "VolumeImageCompletedHistoryRequired");
        Require(Encode(j.request) == Encode(r) && j.identity.substr(0, 64) == identity.substr(0, 64),
            "VolumeImageJournalBindingMismatch");
        const auto cp = Admit(j.original, r);
        catalog::VectorRandomAccessSource source(j.original); AppleSnapshotRetentionView snapshots; std::string e;
        Require(LoadAppleSnapshotRetention(source, cp, snapshots, e), e);
        Require(snapshots.identities.empty() && !cp.container_object_map.snapshot_tree_oid,
            "VolumeImageSnapshotHistoryAuthorityUnproven");
        const auto census = completed_history ? j.census : Census(cp, create);
        const auto clean_boundary = [&](const std::filesystem::path& path, std::uint64_t oid,
            const std::string& container) {
            const VolumeKeeperWalIdentities ids{"apfs-vol:" + container + ":" + std::to_string(oid),
                DerivePartitionlessVolumeRecoveryIdentity(container, oid)};
            const auto marks = InspectVolumeKeeperWal(std::filesystem::path(Extended(path)), ids,
                "VolumeImage", "WalDebtOrPins");
            const auto records = WriteAheadLog::ReadAll(std::filesystem::path(Extended(path)), "");
            Require(records.status == WriteAheadLog::ReadStatus::Ok && !records.recovered_torn_tail,
                "VolumeImageWalReadOnlyInspectionFailed");
            Require(VolumeKeeperWalHasCleanBoundary(records.records, marks.cleanup_sequence), "VolumeImageWalDebtOrPins");
        };
        if (!completed_history) {
            for (const auto& [oid, path] : r.sibling_wals) clean_boundary(path, oid, r.container_uuid);
            if (IsFormat(r.operation)) clean_boundary(r.new_volume_wal, 1024, r.new_container_uuid);
        }
        const CleanImageHistoryAuthority authority(j.original, r, cp.container.superblock.xid, identity, census);
        return IsFormat(r.operation) ? (j.flagged_format ? PlanFormatV2(j.original, r, &authority) : PlanFormat(j.original, r, &authority)) : PlanResize(j.original, r, &authority);
    }
};
namespace
{
#include "VolumeFormatStreamedKeeper.inc"
Plan Rebuild(const Journal& j, Session& s, bool create = false, bool completed_history = false)
{ return s.Build(j, create, completed_history); }
void Fill(VolumeImageResult& result, const Session& s, const Journal& j, const Plan& p)
{
    result.source_identity = s.identity; result.journal = s.journal; result.pre_xid = p.before.container.superblock.xid;
    result.post_xid = p.after.container.superblock.xid; result.expires_unix_seconds = j.expiry;
    result.free_blocks_before = p.before.spaceman.devices[0].free_count; result.free_blocks_after = p.after.spaceman.devices[0].free_count;
}
void Stage(const AppleCheckpointStageHook& hook, std::string_view stage)
{ Require(!hook || hook(stage), "VolumeImageInterrupted:" + std::string(stage)); }
void CompareRecovery(const Bytes& current, const Journal& j, const Plan& p)
{
    Require(current.size() == j.request.expected_bytes || current.size() == j.request.target_bytes, "VolumeImageRecoveryLengthConflict");
    const auto check_nx = [&](std::uint64_t block) {
        Require(block < current.size() / Block, "VolumeImageRecoveryCheckpointBounds");
        Bytes bytes(current.begin() + block * Block, current.begin() + (block + 1) * Block);
        const auto nx = catalog::ParseNxSuperblock(bytes);
        const auto original = Bytes(j.original.begin() + block * Block, j.original.begin() + (block + 1) * Block);
        const auto& expected = block == 0 ? p.anchor : p.publication.superblock_write.bytes;
        Require(!nx || bytes == original || bytes == expected, "VolumeImageRecoveryForeignCheckpoint");
    };
    check_nx(0); check_nx(p.publication.superblock_write.physical_block);
    for (std::size_t at = 0; at < current.size(); at += Block) {
        if (p.destinations.contains(at / Block)) continue;
        Require(at < j.original.size() && std::equal(current.begin() + at, current.begin() + at + Block, j.original.begin() + at),
            "VolumeImageRecoveryUnrelatedBytesChanged");
    }
}
}
VolumeImageResult Prepare(const VolumeImageRequest& input, bool format)
{
    VolumeImageResult result;
    try {
        Require(IsFormat(input.operation) == format, "VolumeImageEntrypointMismatch");
        if (Streamed(input)) return PrepareStreamed(input);
        Session s(input);
        result.journal = s.journal; result.source_identity = s.identity;
        if (Exists(s.journal)) {
            File old; old.Open(s.journal, GENERIC_READ | GENERIC_WRITE, 0, OPEN_EXISTING); const auto prior = Decode(old.ReadAll());
            Require(!prior.partial && (prior.state == 3 || prior.state == 4), "VolumeImageUnfinishedJournal");
            old.Close(); auto archive = s.journal; archive += L"." + Wide(prior.token) + L".completed";
            Require(MoveFileExW(Extended(s.journal).c_str(), Extended(archive).c_str(), MOVEFILE_WRITE_THROUGH) != FALSE,
                "VolumeImageArchiveFailed:" + std::to_string(GetLastError()));
            Require(s.directory.Flush(), "VolumeImageDirectoryFlushFailed");
        }
        Journal j; j.request = s.r; j.identity = s.identity; j.flagged_format = IsFormat(s.r.operation); j.original = s.image.ReadAll(Limit); const auto p = Rebuild(j, s, true);
        j.census = s.Census(p.before, true); std::array<std::byte, 32> random{};
        Require(BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(random.data()), 32, BCRYPT_USE_SYSTEM_PREFERRED_RNG) >= 0,
            "VolumeImageRandomFailed"); j.token = Hex(random); j.expiry = Now() + 300;
        File file; file.Open(s.journal, GENERIC_READ | GENERIC_WRITE, 0, CREATE_NEW); file.Append(Frame(j));
        Require(s.directory.Flush(), "VolumeImageDirectoryFlushFailed");
        Require(Decode(file.ReadAll()).original == j.original, "VolumeImagePreparedReadbackFailed");
        s.HoldHistory(p.before, j.original, file);
        Fill(result, s, j, p); result.token = j.token; result.outcome = VolumeImageOutcome::Prepared;
    } catch (const std::exception& ex) { result.error = ex.what(); }
    return result;
}
VolumeImageResult Run(const VolumeImageRequest& input, std::string_view token, bool format, bool recovery, bool cancel,
    const AppleCheckpointStageHook& hook)
{
    VolumeImageResult result; bool accepted = recovery;
    try {
        Require(IsFormat(input.operation) == format, "VolumeImageEntrypointMismatch");
        if (Streamed(input)) return RunStreamed(input, token, recovery, cancel, hook);
        Session s(input);
        result.journal = s.journal; result.source_identity = s.identity;
        File file; file.Open(s.journal, GENERIC_READ | GENERIC_WRITE, 0, OPEN_EXISTING); auto j = Decode(file.ReadAll());
        Require(j.identity.substr(0, 64) == s.identity.substr(0, 64) && Encode(j.request) == Encode(s.r), "VolumeImageJournalBindingMismatch");
        if (!recovery) {
            Require(j.state == 0 && !j.partial, "VolumeImageConfirmationConsumed");
            if (token != j.token || Now() >= j.expiry || cancel) {
                s.cancellation = AcquireVolumeKeeperCancellationMarkers(s.identity, s.image.ReadAll(Limit), s.journal,
                    HistoryFrame(file, j), s.r.history_context);
                Transition(file, j, 4); Require(token == j.token, "VolumeImageConfirmationMismatch"); Require(Now() < j.expiry, "VolumeImageConfirmationExpired");
                result.outcome = VolumeImageOutcome::Cancelled; return result;
            }
        } else Require(j.state <= 4, "VolumeImageNoAcceptedIntent");
        const auto p = Rebuild(j, s, false, recovery && j.state == 3); Fill(result, s, j, p); const auto current = s.image.ReadAll(Limit);
        if (recovery && j.state == 3) {
            catalog::VectorRandomAccessSource source(current); std::string error;
            const auto checkpoint = catalog::LoadAppleCheckpointView(source, 0, current.size(), error);
            if (checkpoint && checkpoint->container.superblock.xid > p.after.container.superblock.xid) {
                s.history = AcquireVolumeKeeperHistory(s.identity, current, s.r.journal_directory, {}, s.HeldWals(),
                    s.journal, HistoryFrame(file, j), s.r.history_context, true);
                result.outcome = VolumeImageOutcome::Committed; return result;
            }
        }
        if (recovery && j.state == 3) {
            Require(current == p.postimage, "VolumeImageCompletedSourceChanged"); Verify(current, p.after);
            s.history = AcquireVolumeKeeperHistory(s.identity, current, s.r.journal_directory, {}, s.HeldWals(),
                s.journal, HistoryFrame(file, j), s.r.history_context, true);
            result.outcome = VolumeImageOutcome::Committed; return result;
        }
        if (recovery && (j.state == 0 || j.state == 4))
            s.cancellation = AcquireVolumeKeeperCancellationMarkers(s.identity, current, s.journal,
                HistoryFrame(file, j), s.r.history_context);
        if (recovery && (j.state == 0 || j.state == 4)) {
            Require(current == j.original, "VolumeImageUnacceptedSourceChanged");
            Require(s.Census(p.before) == j.census, "VolumeImageStaleWalCensus");
            if (j.state == 0) {
                if (j.partial) file.Resize(j.valid_bytes);
                Transition(file, j, 4);
            }
            result.outcome = VolumeImageOutcome::Cancelled; return result;
        }
        if (!recovery && current != j.original) { Transition(file, j, 4); throw std::runtime_error("VolumeImageStaleSource"); }
        const auto census = s.Census(p.before);
        if (census != j.census) { if (!recovery) Transition(file, j, 4); throw std::runtime_error("VolumeImageStaleWalCensus"); }
        CompareRecovery(current, j, p);
        if (recovery) {
            std::vector<VolumeKeeperHistoryMember> members;
            for (const auto& v : p.before.volumes)
                members.push_back({p.before.container.superblock.uuid_hex, v.superblock.uuid_hex, v.superblock.object_id,
                    s.r.sibling_wals.at(v.superblock.object_id)});
            s.history = AcquireVolumeKeeperHistory(s.identity, j.original, s.r.journal_directory, members, s.HeldWals(),
                s.journal, HistoryFrame(file, j), s.r.history_context);
        }
        if (j.partial) file.Resize(j.valid_bytes);
        if (!recovery) {
            if (hook && !hook("before-image-accept")) {
                s.cancellation = AcquireVolumeKeeperCancellationMarkers(s.identity, current, s.journal,
                    HistoryFrame(file, j), s.r.history_context);
                Transition(file, j, 4); result.outcome = VolumeImageOutcome::Cancelled; return result;
            }
            std::vector<VolumeKeeperHistoryMember> members;
            for (const auto& v : p.before.volumes)
                members.push_back({p.before.container.superblock.uuid_hex, v.superblock.uuid_hex, v.superblock.object_id,
                    s.r.sibling_wals.at(v.superblock.object_id)});
            s.history = AcquireVolumeKeeperHistory(s.identity, current, s.r.journal_directory, members, s.HeldWals(),
                s.journal, HistoryFrame(file, j), s.r.history_context);
            PersistVolumeKeeperHistoryProof(s.journal, HistoryFrame(file, j), s.identity, s.HeldWals(), hook);
            accepted = true; Transition(file, j, 1);
        }
        Stage(hook, "after-image-accept");
        if (s.image.Size() < s.r.target_bytes) s.image.Resize(s.r.target_bytes);
        if (s.r.operation == VolumeImageOperation::Grow) {
            // An interrupted extension may already have its final length. The
            // entire new range still belongs to this intent and must be replayed.
            Bytes zeros(Block); for (auto block = s.r.expected_bytes / Block; block < s.r.target_bytes / Block; ++block)
                Require(s.image.WriteBlock(block, zeros), "VolumeImageGrowthZeroFailed");
            Require(s.image.Flush(), "VolumeImageGrowthFlushFailed");
        }
        Stage(hook, "after-image-grow");
        auto publication = p.publication;
        if (recovery) for (auto& guard : publication.guard_blocks) if (p.destinations.contains(guard.physical_block))
            Require(s.image.ReadBlock(guard.physical_block, Block, guard.bytes), "VolumeImageRecoveryGuardReadFailed");
        std::string e; Require(ExecuteAppleCheckpointPublication(s.image, publication, e, hook), e);
        Stage(hook, "before-image-anchor");
        Require(s.image.WriteBlock(0, p.anchor) && s.image.Flush(), "VolumeImageAnchorDurabilityFailed");
        Bytes anchor; Require(s.image.ReadBlock(0, Block, anchor) && anchor == p.anchor, "VolumeImageAnchorReadbackFailed");
        if (j.state == 1) Transition(file, j, 2);
        Stage(hook, "after-image-anchor");
        for (const auto& w : p.cleanup) Require(s.image.WriteBlock(w.physical_block, w.bytes), "VolumeImageEraseWriteFailed");
        Require(s.image.Flush(), "VolumeImageCleanupFlushFailed"); Stage(hook, "after-image-cleanup");
        if (s.image.Size() > s.r.target_bytes) s.image.Resize(s.r.target_bytes);
        Stage(hook, "after-image-truncate");
        const auto final = s.image.ReadAll(Limit); Require(final == p.postimage, "VolumeImagePostimageMismatch"); Verify(final, p.after);
        Stage(hook, "before-image-complete"); Transition(file, j, 3); result.outcome = VolumeImageOutcome::Committed;
    } catch (const std::exception& ex) {
        result.error = ex.what(); result.outcome = accepted ? VolumeImageOutcome::RecoveryRequired : VolumeImageOutcome::Refused;
    }
    return result;
}
namespace
{
std::string Quote(std::string_view s)
{
    std::string out = "\""; const char* h = "0123456789abcdef";
    for (unsigned char c : s) {
        if (c == '"' || c == '\\') { out += '\\'; out += char(c); }
        else if (c < 32) { out += "\\u00"; out += h[c >> 4]; out += h[c & 15]; }
        else out += char(c);
    }
    return out + '"';
}
}
}
namespace apfsaccess::rw
{
VolumeImageResult PrepareVolumePhysicalFormat(const std::shared_ptr<VolumePhysicalSource>& source, const VolumeImageRequest& request)
{
    if (!source) { VolumeImageResult result; result.error = "VolumePhysicalHeldSourceRequired"; return result; }
    return volume_image::PrepareStreamed(request, source);
}
VolumeImageResult ApplyVolumePhysicalFormat(const std::shared_ptr<VolumePhysicalSource>& source, const VolumeImageRequest& request,
    std::string_view token, const AppleCheckpointStageHook& hook)
{
    if (!source) { VolumeImageResult result; result.error = "VolumePhysicalHeldSourceRequired"; return result; }
    return volume_image::RunStreamed(request, token, false, false, hook, source);
}
VolumeImageResult RecoverVolumePhysicalFormat(const std::shared_ptr<VolumePhysicalSource>& source, const VolumeImageRequest& request,
    const AppleCheckpointStageHook& hook)
{
    if (!source) { VolumeImageResult result; result.error = "VolumePhysicalHeldSourceRequired"; return result; }
    return volume_image::RunStreamed(request, {}, true, false, hook, source);
}
VolumeImageResult CancelVolumePhysicalFormat(const std::shared_ptr<VolumePhysicalSource>& source, const VolumeImageRequest& request,
    std::string_view token)
{
    if (!source) { VolumeImageResult result; result.error = "VolumePhysicalHeldSourceRequired"; return result; }
    return volume_image::RunStreamed(request, token, false, true, {}, source);
}
VolumeImageResult PrepareVolumePhysicalResize(const std::shared_ptr<VolumePhysicalGeometrySource>& source,const VolumeImageRequest& request)
{
    if(!source){VolumeImageResult result;result.error="VolumeGeometryHeldSourceRequired";return result;}
    return volume_image::PrepareStreamed(request,{},source);
}
namespace {
VolumeImageResult RunPhysicalResize(const std::shared_ptr<VolumePhysicalGeometrySource>& source,const VolumeImageRequest& request,
    std::string_view token,bool recovery,bool cancel,const AppleCheckpointStageHook& hook,std::shared_ptr<VolumePhysicalSource>* rebound)
{
    if(rebound)rebound->reset();
    if(!source){VolumeImageResult result;result.error="VolumeGeometryHeldSourceRequired";return result;}
    auto result=volume_image::RunStreamed(request,token,recovery,cancel,hook,{},source);
    if(result.outcome==VolumeImageOutcome::Committed && rebound){
        try{
            std::string error;auto fixed=VolumePhysicalGeometryAccess::Rebind(source,error);
            auto history=AcquireVolumeKeeperPhysicalHistory(fixed,*fixed,request.journal_directory,{}, {}, {}, {},request.history_context,true);
            *rebound=std::move(fixed);
        }
        catch(const std::exception& ex){result.outcome=VolumeImageOutcome::RecoveryRequired;result.error=ex.what();}
    }
    return result;
}
}
VolumeImageResult ApplyVolumePhysicalResize(const std::shared_ptr<VolumePhysicalGeometrySource>& source,const VolumeImageRequest& request,
    std::string_view token,const AppleCheckpointStageHook& hook,std::shared_ptr<VolumePhysicalSource>* rebound)
{return RunPhysicalResize(source,request,token,false,false,hook,rebound);}
VolumeImageResult RecoverVolumePhysicalResize(const std::shared_ptr<VolumePhysicalGeometrySource>& source,const VolumeImageRequest& request,
    const AppleCheckpointStageHook& hook,std::shared_ptr<VolumePhysicalSource>* rebound)
{return RunPhysicalResize(source,request,{},true,false,hook,rebound);}
VolumeImageResult CancelVolumePhysicalResize(const std::shared_ptr<VolumePhysicalGeometrySource>& source,const VolumeImageRequest& request,std::string_view token)
{return RunPhysicalResize(source,request,token,false,true,{},nullptr);}
std::string VolumeImageJson(const VolumeImageRequest& r, const VolumeImageResult& result)
{
    using namespace volume_image;
    const char* ops[] = {"invalid", "grow", "shrink", "format", "erase"};
    const char* outcomes[] = {"refused", "prepared", "committed", "cancelled", "recovery-required"};
    const auto operation = static_cast<unsigned>(r.operation);
    std::ostringstream out; out << "{\"schemaVersion\":1,\"operation\":" << Quote(ops[operation <= 4 ? operation : 0])
        << ",\"outcome\":" << Quote(outcomes[static_cast<unsigned>(result.outcome)]) << ",\"error\":" << Quote(result.error)
        << ",\"image\":" << Quote(Utf8(r.image.wstring())) << ",\"journal\":" << Quote(Utf8(result.journal.wstring()))
        << ",\"sourceIdentity\":" << Quote(result.source_identity) << ",\"containerUuid\":" << Quote(r.container_uuid)
        << ",\"volumeUuid\":" << Quote(r.volume_uuid) << ",\"volumeOid\":" << Quote(std::to_string(r.volume_oid))
        << ",\"expectedBytes\":" << Quote(std::to_string(r.expected_bytes)) << ",\"targetBytes\":" << Quote(std::to_string(r.target_bytes))
        << ",\"preXid\":" << Quote(std::to_string(result.pre_xid)) << ",\"postXid\":" << Quote(std::to_string(result.post_xid))
        << ",\"freeBlocksBefore\":" << Quote(std::to_string(result.free_blocks_before))
        << ",\"freeBlocksAfter\":" << Quote(std::to_string(result.free_blocks_after))
        << ",\"expiresUnixSeconds\":" << Quote(std::to_string(result.expires_unix_seconds)) << ",\"confirmationToken\":" << Quote(result.token)
        << ",\"newContainerUuid\":" << Quote(r.new_container_uuid) << ",\"newVolumeUuid\":" << Quote(r.new_volume_uuid)
        << ",\"newVolumeOid\":" << Quote(IsFormat(r.operation) ? "1024" : "0")
        << ",\"newVolumeWal\":" << Quote(Utf8(r.new_volume_wal.wstring())) << ",\"name\":" << Quote(r.name_utf8)
        << ",\"caseSensitive\":" << (r.case_sensitive ? "true" : "false") << ",\"siblingWals\":[";
    bool first = true;
    for (const auto& [id, path] : r.sibling_wals) { if (!first) out << ','; first = false;
        out << "{\"oid\":" << Quote(std::to_string(id)) << ",\"path\":" << Quote(Utf8(path.wstring())) << '}'; }
    out << "]}"; return out.str();
}
}
