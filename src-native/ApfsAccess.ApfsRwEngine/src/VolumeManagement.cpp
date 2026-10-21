#include "VolumeManagementInternal.h"
#include "VolumeKeeperAdmission.h"
#include "VolumeKeeperWal.h"
#include "VolumePhysicalBindingCodec.h"
#include "BlockDevice.h"
#include "TransactionManager.h"
#include "NativeVolumeRename.h"
#include <bcrypt.h>
#include <wincrypt.h>
#include <charconv>
#include <algorithm>
#include <chrono>
#include <cstring>
#include <cwctype>
#include <set>
#include <sstream>
#pragma comment(lib, "crypt32.lib")

namespace apfsaccess::rw
{
namespace
{
using namespace volume_management;
constexpr std::uint64_t MaxImage = 256ull * 1024 * 1024;
constexpr std::uint64_t MaxJournal = MaxImage + 1024 * 1024;
using Bytes = std::vector<std::byte>;
void Require(bool b, const std::string& why) { if (!b) throw std::runtime_error(why); }
std::string Utf8(std::wstring_view t)
{
    if (t.empty()) return {};
    const int n = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, t.data(), static_cast<int>(t.size()), nullptr, 0, nullptr, nullptr);
    Require(n > 0, "VolumeManagementInvalidUnicode"); std::string s(n, ' ');
    Require(WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, t.data(), static_cast<int>(t.size()), s.data(), n, nullptr, nullptr) == n,
        "VolumeManagementInvalidUnicode"); return s;
}
std::wstring Wide(std::string_view t)
{
    if (t.empty()) return {};
    const int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, t.data(), static_cast<int>(t.size()), nullptr, 0);
    Require(n > 0, "VolumeManagementInvalidUnicode"); std::wstring s(n, L' ');
    Require(MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, t.data(), static_cast<int>(t.size()), s.data(), n) == n,
        "VolumeManagementInvalidUnicode"); return s;
}
std::wstring ExtendedPath(const std::filesystem::path& path);
std::filesystem::path Local(const std::filesystem::path& input)
{
    const auto s = input.wstring();
    Require(s.size() >= 3 && std::iswalpha(s[0]) && s[1] == L':' && (s[2] == L'/' || s[2] == L'\\') &&
        s.find(L':', 2) == std::wstring::npos, "VolumeManagementAbsoluteLocalPathRequired");
    auto p = input.lexically_normal();
    for (auto at = p; !at.empty() && at != at.root_path(); at = at.parent_path()) {
        const auto a = GetFileAttributesW(ExtendedPath(at).c_str());
        Require(a == INVALID_FILE_ATTRIBUTES || !(a & FILE_ATTRIBUTE_REPARSE_POINT), "VolumeManagementReparsePathRefused");
    }
    return p;
}
std::wstring ExtendedPath(const std::filesystem::path& path)
{
    auto value = path.wstring();
    std::replace(value.begin(), value.end(), L'/', L'\\');
    return L"\\\\?\\" + value;
}
std::array<std::byte, 32> Hash(std::span<const std::byte> bytes)
{
    BCRYPT_ALG_HANDLE alg = nullptr; std::array<std::byte, 32> hash{};
    Require(bytes.size() <= ULONG_MAX && BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) >= 0,
        "VolumeManagementHashFailed");
    const auto status = BCryptHash(alg, nullptr, 0, reinterpret_cast<PUCHAR>(const_cast<std::byte*>(bytes.data())),
        static_cast<ULONG>(bytes.size()), reinterpret_cast<PUCHAR>(hash.data()), 32);
    BCryptCloseAlgorithmProvider(alg, 0); Require(status >= 0, "VolumeManagementHashFailed"); return hash;
}
std::string Hex(std::span<const std::byte> bytes)
{
    std::string s; const char* h = "0123456789abcdef";
    for (auto b : bytes) { const auto n = std::to_integer<unsigned>(b); s += h[n >> 4]; s += h[n & 15]; } return s;
}
void Number(Bytes& b, std::uint64_t n) { for (unsigned i = 0; i < 8; ++i) b.push_back(std::byte((n >> (8 * i)) & 255)); }
void Text(Bytes& b, std::string_view s)
{ Number(b, s.size()); for (unsigned char c : s) b.push_back(std::byte(c)); }
struct Reader
{
    std::span<const std::byte> b; std::size_t at = 0;
    std::uint64_t Number() { Require(at <= b.size() && b.size() - at >= 8, "VolumeManagementJournalTruncated");
        std::uint64_t n = 0; for (unsigned i = 0; i < 8; ++i) n |= std::uint64_t(std::to_integer<unsigned>(b[at++])) << (8 * i); return n; }
    std::string Text() { const auto n = Number(); Require(n <= 65536 && n <= b.size() - at, "VolumeManagementJournalStringInvalid");
        std::string s(reinterpret_cast<const char*>(b.data() + at), static_cast<std::size_t>(n)); at += n; return s; }
};
std::uint64_t Now()
{ return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count(); }
VolumeManagementRequest Normalize(VolumeManagementRequest r, const std::shared_ptr<VolumePhysicalSource>& physical = {})
{
    if (physical) {
        Require(physical->Revalidate() && r.image.wstring() == physical->InstanceId() &&
            r.offset_bytes == physical->Binding().media.base_offset_bytes &&
            !r.history_context.spool_root.empty() && !r.history_context.recovery_root.empty(),
            "VolumeManagementPhysicalHeldScopeMismatch");
    } else r.image = Local(r.image);
    r.journal_directory = Local(r.journal_directory);
    Require(std::filesystem::is_directory(ExtendedPath(r.journal_directory)), "VolumeManagementJournalDirectoryMissing");
    Require(r.offset_bytes % 4096 == 0, "VolumeManagementOffsetUnaligned");
    Require(r.sibling_wals.size() <= 100, "VolumeManagementCensusTooLarge");
    for (auto& [id, path] : r.sibling_wals) {
        Require(id != 0, "VolumeManagementZeroWalOid"); path = Local(path);
        Require(std::filesystem::is_directory(ExtendedPath(path.parent_path())), "VolumeManagementWalDirectoryMissing");
    }
    return r;
}
Bytes EncodeRequest(const VolumeManagementRequest& r)
{
    Bytes b; Number(b, static_cast<unsigned>(r.operation)); Text(b, Utf8(r.image.wstring())); Text(b, Utf8(r.journal_directory.wstring()));
    Number(b, r.offset_bytes); Text(b, r.container_uuid); Text(b, r.volume_uuid); Number(b, r.volume_oid); Number(b, r.checkpoint_xid);
    Text(b, r.name_utf8); Number(b, r.quota_blocks); Number(b, r.reserve_blocks); Number(b, r.case_sensitive);
    Number(b, r.sibling_wals.size()); for (const auto& [id, path] : r.sibling_wals) { Number(b, id); Text(b, Utf8(path.wstring())); } return b;
}
VolumeManagementRequest DecodeRequest(Reader& in)
{
    VolumeManagementRequest r; const auto op = in.Number(); Require(op == 1 || op == 2, "VolumeManagementJournalOperationInvalid");
    r.operation = static_cast<VolumeManagementOperation>(op); r.image = Wide(in.Text()); r.journal_directory = Wide(in.Text());
    r.offset_bytes = in.Number(); r.container_uuid = in.Text(); r.volume_uuid = in.Text(); r.volume_oid = in.Number(); r.checkpoint_xid = in.Number();
    r.name_utf8 = in.Text(); r.quota_blocks = in.Number(); r.reserve_blocks = in.Number();
    const auto cs = in.Number(); Require(cs <= 1, "VolumeManagementJournalCaseModeInvalid"); r.case_sensitive = cs != 0;
    const auto count = in.Number(); Require(count <= 100, "VolumeManagementJournalCensusInvalid");
    for (auto i = 0ull; i < count; ++i) { const auto id = in.Number(); auto path = Wide(in.Text());
        Require(r.sibling_wals.emplace(id, path).second, "VolumeManagementJournalDuplicateWal"); }
    return r;
}
class File
{
public:
    HANDLE h = INVALID_HANDLE_VALUE;
    std::filesystem::path wal_path;
    ~File() { Close(); }
    void Close() { if (h != INVALID_HANDLE_VALUE) { CloseHandle(h); h = INVALID_HANDLE_VALUE; } }
    void OpenDirectory(const std::filesystem::path& p)
    {
        h = CreateFileW(ExtendedPath(p).c_str(), GENERIC_WRITE | FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        Require(h != INVALID_HANDLE_VALUE, "VolumeManagementJournalDirectoryUnavailable");
        FILE_ATTRIBUTE_TAG_INFO ai{};
        Require(GetFileInformationByHandleEx(h, FileAttributeTagInfo, &ai, sizeof(ai)) &&
            (ai.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) && !(ai.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT),
            "VolumeManagementJournalDirectoryInvalid");
    }
    void FlushDirectory()
    { Require(FlushFileBuffers(h) != FALSE, "VolumeManagementJournalDirectoryDurabilityFailed"); }
    void Open(const std::filesystem::path& p, DWORD disposition)
    {
        h = CreateFileW(ExtendedPath(p).c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, disposition,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH, nullptr);
        Require(h != INVALID_HANDLE_VALUE, "VolumeManagementJournalBusyOrUnavailable");
        FILE_STANDARD_INFO si{}; FILE_ATTRIBUTE_TAG_INFO ai{};
        Require(GetFileType(h) == FILE_TYPE_DISK && GetFileInformationByHandleEx(h, FileStandardInfo, &si, sizeof(si)) &&
            !si.Directory && !si.DeletePending && si.NumberOfLinks == 1 &&
            GetFileInformationByHandleEx(h, FileAttributeTagInfo, &ai, sizeof(ai)) && !(ai.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT),
            "VolumeManagementJournalNotOrdinaryFile");
    }
    void FenceWal(const std::filesystem::path& p)
    {
        wal_path = p;
        h = CreateFileW(ExtendedPath(p).c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        Require(h != INVALID_HANDLE_VALUE, "VolumeManagementWalFileBusy");
        FILE_STANDARD_INFO si{}; FILE_ATTRIBUTE_TAG_INFO ai{};
        Require(GetFileType(h) == FILE_TYPE_DISK && GetFileInformationByHandleEx(h, FileStandardInfo, &si, sizeof(si)) &&
            !si.Directory && !si.DeletePending && si.NumberOfLinks == 1 &&
            GetFileInformationByHandleEx(h, FileAttributeTagInfo, &ai, sizeof(ai)) && !(ai.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT),
            "VolumeManagementWalNotOrdinaryFile");
    }
    void ObserveImage(const std::filesystem::path& p)
    {
        h = CreateFileW(ExtendedPath(p).c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        Require(h != INVALID_HANDLE_VALUE, "VolumeManagementObservationImageUnavailable");
        FILE_STANDARD_INFO si{}; FILE_ATTRIBUTE_TAG_INFO ai{};
        Require(GetFileType(h) == FILE_TYPE_DISK && GetFileInformationByHandleEx(h, FileStandardInfo, &si, sizeof(si)) &&
            !si.Directory && !si.DeletePending && si.NumberOfLinks == 1 &&
            GetFileInformationByHandleEx(h, FileAttributeTagInfo, &ai, sizeof(ai)) &&
            !(ai.FileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DEVICE)),
            "VolumeManagementObservationImageNotOrdinary");
        std::wstring name(32768, L'\0');
        const auto n = GetFinalPathNameByHandleW(h, name.data(), static_cast<DWORD>(name.size()), FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
        Require(n && n < name.size(), "VolumeManagementObservationImagePathUnavailable");
        name.resize(n);
        Require(_wcsicmp(name.c_str(), ExtendedPath(p).c_str()) == 0, "VolumeManagementObservationImageAlias");
    }
    Bytes Read()
    {
        LARGE_INTEGER size{}, zero{}; Require(GetFileSizeEx(h, &size) && size.QuadPart >= 0 &&
            std::uint64_t(size.QuadPart) <= MaxJournal && SetFilePointerEx(h, zero, nullptr, FILE_BEGIN), "VolumeManagementJournalSizeInvalid");
        Bytes b(static_cast<std::size_t>(size.QuadPart)); DWORD got = 0;
        Require(ReadFile(h, b.data(), static_cast<DWORD>(b.size()), &got, nullptr) && got == b.size(), "VolumeManagementJournalReadFailed"); return b;
    }
    void Append(std::span<const std::byte> b)
    {
        LARGE_INTEGER zero{}; DWORD written = 0;
        Require(b.size() <= MAXDWORD && SetFilePointerEx(h, zero, nullptr, FILE_END) &&
            WriteFile(h, b.data(), static_cast<DWORD>(b.size()), &written, nullptr) && written == b.size() && FlushFileBuffers(h),
            "VolumeManagementJournalDurabilityFailed");
    }
    void TrimIncompleteReceipt(std::uint64_t size)
    {
        LARGE_INTEGER end{}; end.QuadPart = static_cast<LONGLONG>(size);
        Require(SetFilePointerEx(h, end, nullptr, FILE_BEGIN) && SetEndOfFile(h) && FlushFileBuffers(h),
            "VolumeManagementJournalTailRepairFailed");
    }
};
struct Journal
{
    VolumeManagementRequest request;
    std::string identity, token, census;
    std::uint64_t expires = 0;
    Bytes preimage;
    std::optional<volume_physical::Envelope> physical;
    std::filesystem::path destination_wal;
    // 0 prepared, 1 accepted, 2 committed, 3 cancelled.
    std::uint64_t state = 0;
    std::uint64_t valid_bytes = 0;
    bool incomplete_receipt = false;
    bool physical_snapshot_tree = false;
    std::array<std::byte, 32> digest{};
};
Bytes Frame(const Journal& j)
{
    const auto magic = j.physical_snapshot_tree ? (j.physical ? volume_physical::PhysicalSnapshotManagementMagic : volume_physical::PhysicalSnapshotImageMagic) :
        (j.physical ? volume_physical::ManagementMagic : 0x31544d5653465041ull);
    auto data = EncodeRequest(j.request); Text(data, j.identity); Text(data, j.token); Text(data, j.census);
    Number(data, j.expires);
    if (j.physical) {
        Number(data, magic);
        const auto envelope = volume_physical::Encode(j.physical->binding, j.physical->instance);
        Number(data, envelope.size()); data.insert(data.end(), envelope.begin(), envelope.end());
        Text(data, Utf8(j.destination_wal.wstring()));
    }
    if (j.physical_snapshot_tree && !j.physical) Number(data, magic);
    Number(data, j.preimage.size()); data.insert(data.end(), j.preimage.begin(), j.preimage.end());
    Bytes out; Number(out, magic); Number(out, data.size()); const auto hash = Hash(data);
    out.insert(out.end(), hash.begin(), hash.end()); out.insert(out.end(), data.begin(), data.end()); return out;
}
Bytes StateRecord(const Journal& j, std::uint64_t state)
{
    Bytes b(j.digest.begin(), j.digest.end()); Number(b, state); const auto hash = Hash(b);
    Bytes record; Number(record, state); record.insert(record.end(), hash.begin(), hash.end()); return record;
}
Journal Decode(const Bytes& bytes)
{
    Reader in{bytes}; const auto magic = in.Number();
    Require(volume_physical::IsManagementImageMagic(magic) || volume_physical::IsManagementMagic(magic), "VolumeManagementJournalMagicInvalid");
    const auto length = in.Number(); Require(length <= MaxJournal - 128 && bytes.size() >= 48 && length <= bytes.size() - 48,
        "VolumeManagementJournalLengthInvalid");
    Journal j; std::copy_n(bytes.begin() + 16, 32, j.digest.begin());
    const auto body = std::span<const std::byte>(bytes).subspan(48, length);
    Require(Hash(body) == j.digest, "VolumeManagementJournalChecksumInvalid");
    Reader data{body}; j.request = DecodeRequest(data); j.identity = data.Text(); j.token = data.Text(); j.census = data.Text();
    j.expires = data.Number();
    j.physical_snapshot_tree = magic == volume_physical::PhysicalSnapshotImageMagic || magic == volume_physical::PhysicalSnapshotManagementMagic;
    Require(!j.physical_snapshot_tree || j.request.operation == VolumeManagementOperation::Create, "VolumeManagementSnapshotPolicyMismatch");
    if (volume_physical::IsManagementMagic(magic)) {
        Require(data.Number() == magic, "VolumeManagementPhysicalModeMismatch");
        const auto n = data.Number(); Require(n <= 4096 && n <= body.size() - data.at, "VolumeManagementPhysicalBindingSize");
        j.physical = volume_physical::Decode(body.subspan(data.at, static_cast<std::size_t>(n))); data.at += n;
        const auto destination = data.Text(); if (!destination.empty()) j.destination_wal = Local(Wide(destination));
        Require(j.request.image.wstring() == j.physical->instance &&
            j.request.offset_bytes == j.physical->binding.media.base_offset_bytes &&
            j.identity == VolumePhysicalIdentity(j.physical->binding, j.physical->instance) &&
            (j.request.operation == VolumeManagementOperation::Create ? !j.destination_wal.empty() : j.destination_wal.empty()),
            "VolumeManagementPhysicalBindingMismatch");
    }
    if (j.physical_snapshot_tree && !j.physical) Require(data.Number() == magic, "VolumeManagementSnapshotPolicyMismatch");
    const auto size = data.Number();
    Require(size && size <= MaxImage && size == body.size() - data.at && j.token.size() == 64,
        "VolumeManagementJournalPreimageInvalid");
    Require(!j.physical || size == j.physical->binding.media.limit_bytes, "VolumeManagementPhysicalSizeMismatch");
    j.preimage.assign(body.begin() + data.at, body.end());
    // Each state is an append-only checksum-bound receipt. An incomplete tail
    // never authorizes mutation. Accepted intent remains available for recovery.
    std::size_t at = 48 + length;
    while (bytes.size() - at >= 40) {
        Reader r{std::span<const std::byte>(bytes).subspan(at, 40)}; const auto state = r.Number();
        const auto record = StateRecord(j, state);
        Require(std::equal(record.begin(), record.end(), bytes.begin() + at), "VolumeManagementJournalStateChecksumInvalid");
        Require((j.state == 0 && (state == 1 || state == 3)) || (j.state == 1 && state == 2), "VolumeManagementJournalStateInvalid");
        j.state = state; at += 40;
    }
    j.valid_bytes = at;
    if (at != bytes.size()) {
        Require(j.state == 0 || j.state == 1, "VolumeManagementJournalUnexpectedTail");
        // Only a prefix of a legal next receipt is recoverable. Arbitrary
        // trailing corruption cannot silently authorize a state transition.
        const auto matches = [&](std::uint64_t state) {
            const auto candidate = StateRecord(j, state);
            return std::equal(bytes.begin() + at, bytes.end(), candidate.begin());
        };
        Require(j.state == 0 ? (matches(1) || matches(3)) : matches(2), "VolumeManagementJournalInvalidTail");
        j.incomplete_receipt = true;
    }
    return j;
}
void Transition(File& f, Journal& j, std::uint64_t state)
{ const auto record = StateRecord(j, state); f.Append(record); j.state = state; }
Bytes HistoryFrame(File& file, const Journal& journal)
{ auto bytes = file.Read(); bytes.resize(static_cast<std::size_t>(journal.valid_bytes)); return bytes; }

struct Session
{
    VolumeManagementRequest request;
    std::shared_ptr<BlockDevice> device;
    std::shared_ptr<VolumePhysicalSource> physical;
    std::string identity;
    std::filesystem::path journal_path;
    File journal_directory;
    std::vector<std::unique_ptr<WriteAheadLog>> leases;
    std::vector<std::unique_ptr<File>> wal_files;
    std::unique_ptr<VolumeKeeperHistoryLease> history;
    std::unique_ptr<VolumeKeeperCancellationFence> cancellation;
    explicit Session(const VolumeManagementRequest& r, std::shared_ptr<VolumePhysicalSource> held = {})
        : request(Normalize(r, held)), physical(std::move(held))
    {
        journal_directory.OpenDirectory(request.journal_directory);
        std::uint64_t bytes = 0;
        if (physical) { identity = physical->Identity(); bytes = physical->SizeBytes(); }
        else {
            std::string e; device = BlockDevice::OpenExclusiveManagementImage(request.image.wstring(), request.offset_bytes, e);
            Require(!!device, e); Require(device->QueryRegularImageIdentity(identity), "VolumeManagementImageIdentityUnavailable");
            bytes = device->GetGeometry().total_bytes;
        }
        Require(bytes && bytes <= MaxImage, "VolumeManagementBoundedImageSizeExceeded");
        // Keep the locator stable if file length changes. Full size remains in
        // the journal binding, so growth cannot hide an accepted old intent.
        Require(identity.size() == 80, "VolumeManagementImageIdentityShapeInvalid");
        const auto admission = InspectHeldVolumeKeeperJournals(request.journal_directory, identity, VolumeKeeperAdmissionScope::ForeignToManagement);
        Require(admission.admitted, admission.error);
        Bytes name; Text(name, identity.substr(0, 64));
        journal_path = request.journal_directory / (Hex(Hash(name)) + ".vmt1");
    }
    Bytes Image() const
    {
        if (physical) {
            Require(physical->Revalidate(), "VolumeManagementPhysicalSourceChanged");
            Bytes result; result.reserve(static_cast<std::size_t>(physical->SizeBytes()));
            for (std::uint64_t at = 0; at < physical->SizeBytes();) {
                const auto n = static_cast<std::size_t>((std::min<std::uint64_t>)(4u << 20, physical->SizeBytes() - at));
                Bytes block; Require(physical->Read(at, n, block) && block.size() == n, "VolumeManagementPhysicalReadFailed");
                result.insert(result.end(), block.begin(), block.end()); at += n;
            }
            Require(physical->Revalidate(), "VolumeManagementPhysicalSourceChanged"); return result;
        }
        Bytes b; const auto size = device->GetGeometry().total_bytes;
        Require(device->Read(0, static_cast<std::size_t>(size), b) && b.size() == size, "VolumeManagementImageReadFailed"); return b;
    }
    bool Publish(const AppleCheckpointPublicationPlan& plan, std::string& error, const AppleCheckpointStageHook& hook) const
    {
        if (physical) return ExecuteAppleCheckpointPublication(*physical, plan, error, hook);
        return ExecuteAppleCheckpointPublication(*device, plan, error, hook);
    }
    bool Flush() const { return physical ? physical->Flush() : device->Flush(); }
    std::filesystem::path DestinationWal() const
    {
        if (!physical || request.operation != VolumeManagementOperation::Create) return {};
        const auto root = Local(request.history_context.spool_root);
        Require(std::filesystem::is_directory(ExtendedPath(root)), "VolumeManagementSpoolRootMissing");
        const auto production_identity = DeriveVolumePhysicalRecoveryIdentity(physical->Binding(), request.container_uuid, request.volume_oid);
        return root / ("apfs_recovery_v1_" + production_identity.substr(17)) / "write-ahead.wal";
    }
    std::vector<VolumeKeeperHeldWal> HeldWals() const
    {
        std::vector<VolumeKeeperHeldWal> held;
        for (const auto& file : wal_files) held.push_back({file->wal_path, file->h});
        return held;
    }
    void HoldHistory(const catalog::AppleCheckpointView& cp, const Bytes& current, std::span<const std::byte> frame = {})
    {
        std::vector<VolumeKeeperHistoryMember> members;
        for (const auto& v : cp.volumes)
            members.push_back({cp.container.superblock.uuid_hex, v.superblock.uuid_hex, v.superblock.object_id,
                request.sibling_wals.at(v.superblock.object_id)});
        history = History(current, members, frame.empty() ? std::filesystem::path{} : journal_path, frame);
    }
    std::unique_ptr<VolumeKeeperHistoryLease> History(const Bytes& current,
        const std::vector<VolumeKeeperHistoryMember>& members, const std::filesystem::path& journal = {},
        std::span<const std::byte> frame = {}, bool terminal = false)
    {
        if (physical) {
            catalog::VectorRandomAccessSource original(current);
            return AcquireVolumeKeeperPhysicalHistory(physical, original, request.journal_directory, members,
                HeldWals(), journal, frame, request.history_context, terminal);
        }
        return AcquireVolumeKeeperHistory(identity, current, request.journal_directory, members, HeldWals(), journal,
            frame, request.history_context, terminal);
    }
    std::unique_ptr<VolumeKeeperCancellationFence> Cancellation(const Bytes& current,
        std::span<const std::byte> frame)
    {
        if (physical) {
            catalog::VectorRandomAccessSource original(current);
            return AcquireVolumeKeeperPhysicalCancellationMarkers(physical, original, journal_path, frame, request.history_context);
        }
        return AcquireVolumeKeeperCancellationMarkers(identity, current, journal_path, frame, request.history_context);
    }
    std::string PhysicalCensus(const catalog::AppleCheckpointView& cp, bool create)
    {
        Require(physical && physical->Revalidate() && cp.volumes.size() == request.sibling_wals.size(),
            "VolumeManagementCompleteWalCensusRequired");
        Bytes binding; Text(binding, "wal-file-identity-v1");
        std::set<std::wstring> paths; std::set<std::string> files;
        const auto acquire = [&](const std::filesystem::path& path, const std::string& uuid, std::uint64_t oid, bool destination) {
            const auto local = Local(path); auto folded = local.wstring();
            std::transform(folded.begin(), folded.end(), folded.begin(), [](auto c) { return std::towlower(c); });
            Require(paths.insert(folded).second && _wcsicmp(local.c_str(), journal_path.c_str()), "VolumeManagementWalPathAlias");
            const auto ids = AcquireVolumeKeeperPhysicalWalLeases(local, physical->Binding(), request.container_uuid, oid, leases, "VolumeManagement");
            if (create)
                PersistVolumeKeeperNamespaceWitness(request.journal_directory,
                    BuildVolumeKeeperNamespaceMaterial(request.container_uuid, oid, &physical->Binding()));
            if (destination && create) {
                const auto parent = Local(local.parent_path());
                const auto made = CreateDirectoryW(ExtendedPath(parent).c_str(), nullptr);
                Require(made || GetLastError() == ERROR_ALREADY_EXISTS, "VolumeManagementDestinationWalDirectoryFailed");
                (void)Local(parent);
                File directory; directory.OpenDirectory(parent);
                File root; root.OpenDirectory(parent.parent_path());
                File empty; empty.Open(local, OPEN_ALWAYS);
                Require(FlushFileBuffers(empty.h) != FALSE, "VolumeManagementDestinationWalFlushFailed");
                empty.Close(); directory.FlushDirectory(); root.FlushDirectory();
            }
            WIN32_FIND_DATAW found{}; const auto search = FindFirstFileW((ExtendedPath(local) + L".compact*").c_str(), &found);
            const auto search_error = GetLastError();
            if (search != INVALID_HANDLE_VALUE) { FindClose(search); throw std::runtime_error("VolumeManagementWalCompactionEvidence"); }
            Require(search_error == ERROR_FILE_NOT_FOUND, "VolumeManagementWalCompactionCensusFailed");
            auto fence = std::make_unique<File>(); fence->FenceWal(local);
            const auto id = VolumeKeeperWalFileIdentity({local, fence->h});
            Require(files.insert(id).second, "VolumeManagementWalHardlinkAlias");
            const auto marks = InspectVolumeKeeperWal(local, ids, "VolumeManagement", "WalDebtOrRecoveryPins");
            const auto records = WriteAheadLog::ReadAll(local, "");
            Require(records.status == WriteAheadLog::ReadStatus::Ok && !records.recovered_torn_tail &&
                VolumeKeeperWalHasCleanBoundary(records.records, marks.cleanup_sequence), "VolumeManagementWalDebtOrRecoveryPins");
            Number(binding, oid); Text(binding, uuid); Text(binding, Utf8(local.wstring())); Text(binding, id);
            Number(binding, marks.accepted_sequence); Number(binding, marks.apfs_durable_sequence); Number(binding, marks.cleanup_sequence);
            Text(binding, Hex(Hash(fence->Read()))); wal_files.push_back(std::move(fence));
        };
        for (const auto& v : cp.volumes) {
            const auto oid = v.superblock.object_id;
            Require(request.sibling_wals.contains(oid), "VolumeManagementSiblingWalMissing");
            const auto expected = Local(request.history_context.spool_root) /
                ("apfs_recovery_v1_" + DeriveVolumePhysicalRecoveryIdentity(physical->Binding(), request.container_uuid, oid).substr(17)) / "write-ahead.wal";
            Require(_wcsicmp(expected.c_str(), request.sibling_wals.at(oid).c_str()) == 0, "VolumeManagementPhysicalWalNamespaceMismatch");
            acquire(expected, v.superblock.uuid_hex, oid, false);
        }
        if (request.operation == VolumeManagementOperation::Create) acquire(DestinationWal(), request.volume_uuid, request.volume_oid, true);
        Require(physical->Revalidate(), "VolumeManagementPhysicalSourceChanged"); return Hex(Hash(binding));
    }
    std::string original_census;
    std::string Census(const catalog::AppleCheckpointView& cp, bool create = false)
    {
        if (physical) return PhysicalCensus(cp, create);
        Require(request.offset_bytes == 0, "VolumeManagementProductionWalScopeUnproven");
        Require(cp.volumes.size() == request.sibling_wals.size(), "VolumeManagementCompleteWalCensusRequired");
        Bytes binding, legacy; Text(binding, "wal-file-identity-v1"); std::set<std::wstring> paths;
        for (const auto& v : cp.volumes) {
            const auto id = v.superblock.object_id;
            Require(request.sibling_wals.contains(id), "VolumeManagementSiblingWalMissing");
            const auto& p = request.sibling_wals.at(id); auto folded = p.wstring();
            std::transform(folded.begin(), folded.end(), folded.begin(), [](auto c) { return std::towlower(c); });
            Require(paths.insert(folded).second && _wcsicmp(p.c_str(), request.image.c_str()) != 0 &&
                _wcsicmp(p.c_str(), journal_path.c_str()) != 0, "VolumeManagementWalPathAlias");
            if (std::filesystem::exists(ExtendedPath(p))) {
                Require(!std::filesystem::equivalent(ExtendedPath(p), ExtendedPath(request.image)), "VolumeManagementWalImageAlias");
                for (const auto& [other_id, other] : request.sibling_wals)
                    if (other_id < id && std::filesystem::exists(ExtendedPath(other))) Require(!std::filesystem::equivalent(ExtendedPath(p), ExtendedPath(other)), "VolumeManagementWalHardlinkAlias");
            }
            const auto identities = AcquireVolumeKeeperWalLeases(p, cp.container.superblock.uuid_hex, id, leases, "VolumeManagement");
            // Compaction receipts and predecessor files remain owned by the
            // original WAL recovery path even when the canonical WAL is empty.
            WIN32_FIND_DATAW found{};
            const auto pattern = ExtendedPath(p) + L".compact*";
            const auto search = FindFirstFileW(pattern.c_str(), &found);
            const auto search_error = GetLastError();
            if (search != INVALID_HANDLE_VALUE) {
                FindClose(search); throw std::runtime_error("VolumeManagementWalCompactionEvidence");
            }
            Require(search_error == ERROR_FILE_NOT_FOUND, "VolumeManagementWalCompactionCensusFailed");
            auto fence = std::make_unique<File>(); fence->FenceWal(p);
            const auto wal_bytes = fence->Read();
            const auto w = InspectVolumeKeeperWal(p, identities, "VolumeManagement", "WalDebtOrRecoveryPins");
            Bytes member; Number(member, id); Text(member, v.superblock.uuid_hex); Text(member, Utf8(p.wstring()));
            legacy.insert(legacy.end(), member.begin(), member.end()); binding.insert(binding.end(), member.begin(), member.end());
            Text(binding, VolumeKeeperWalFileIdentity({p, fence->h}));
            Bytes marks; Number(marks, w.accepted_sequence); Number(marks, w.apfs_durable_sequence); Number(marks, w.cleanup_sequence);
            Text(marks, Hex(Hash(wal_bytes)));
            legacy.insert(legacy.end(), marks.begin(), marks.end()); binding.insert(binding.end(), marks.begin(), marks.end());
            wal_files.push_back(std::move(fence));
        }
        // Legacy exact redo retains its original census contract. It cannot
        // create or validate the new terminal history identity proof.
        const auto legacy_digest = Hex(Hash(legacy));
        if (!original_census.empty() && original_census == legacy_digest) return legacy_digest;
        return Hex(Hash(binding));
    }
};
void Fill(VolumeManagementResult& result, const Session& s, const Journal& j, const TopologyPlan& p)
{
    result.source_identity = s.identity; result.journal_path = s.journal_path; result.pre_xid = p.before.container.superblock.xid;
    result.post_xid = p.after.container.superblock.xid; result.block_size = p.publication.block_size;
    result.free_blocks_before = p.before.spaceman.devices[0].free_count; result.free_blocks_after = p.after.spaceman.devices[0].free_count;
    result.allocated_blocks = p.allocation.allocated_main_blocks.size(); result.deferred_blocks = p.released_blocks;
    result.expires_unix_seconds = j.expires;
}
bool Interrupted(const AppleCheckpointStageHook& hook, std::string_view stage)
{ return hook && !hook(stage); }

// Reconstruct the redo from the checksummed original and typed request. No
// serialized physical-write list is accepted as authority from a caller/WAL.
TopologyPlan Rebuild(const Journal& j)
{
    catalog::VectorRandomAccessSource source(j.preimage); TopologyPlan p; std::string e;
    Require(j.physical_snapshot_tree ? PlanTopologyV2(source, j.request, p, e) : PlanTopology(source, j.request, p, e), e); return p;
}
void VerifyResult(Session& s, const TopologyPlan& p)
{
    const auto image = s.Image(); catalog::VectorRandomAccessSource source(image); std::string e;
    auto cp = catalog::LoadAppleCheckpointView(source, 0, source.SizeBytes(), e);
    Require(cp && cp->container.superblock.xid == p.publication.transaction_xid &&
        cp->container.superblock_bytes == p.publication.superblock_write.bytes, "VolumeManagementPublishedCheckpointMismatch");
    Require(VerifyTopology(source, *cp, e), e);
}
VolumeManagementResult Prepare(const VolumeManagementRequest& r, VolumeManagementOperation op,
    const std::shared_ptr<VolumePhysicalSource>& physical = {})
{
    VolumeManagementResult result;
    try {
        Require(r.operation == op, "VolumeManagementOperationMismatch"); Session s(r, physical);
        result.source_identity = s.identity; result.journal_path = s.journal_path;
        if (std::filesystem::exists(ExtendedPath(s.journal_path))) {
            File old; old.Open(s.journal_path, OPEN_EXISTING); const auto prior = Decode(old.Read());
            Require(!prior.incomplete_receipt && (prior.state == 2 || prior.state == 3), "VolumeManagementUnfinishedJournal");
            old.Close(); auto archive = s.journal_path; archive += L"." + Wide(prior.token) + L".completed";
            Require(MoveFileExW(ExtendedPath(s.journal_path).c_str(), ExtendedPath(archive).c_str(),
                MOVEFILE_WRITE_THROUGH) != FALSE, "VolumeManagementJournalArchiveFailed");
            s.journal_directory.FlushDirectory();
        }
        Journal j; j.request = s.request; j.identity = s.identity; j.preimage = s.Image();
        j.physical_snapshot_tree = op == VolumeManagementOperation::Create;
        if (physical) { j.physical = volume_physical::Envelope{physical->Binding(), physical->InstanceId()}; j.destination_wal = s.DestinationWal(); }
        const auto p = Rebuild(j); j.census = s.Census(p.before, !!physical);
        if (!physical) s.HoldHistory(p.before, j.preimage);
        std::array<std::byte, 32> random{};
        Require(BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(random.data()), 32, BCRYPT_USE_SYSTEM_PREFERRED_RNG) >= 0,
            "VolumeManagementRandomFailed");
        j.token = Hex(random); j.expires = Now() + 300;
        const auto encoded = Frame(j);
        Require(encoded.size() <= MaxJournal, "VolumeManagementJournalSizeExceeded");
        File file; file.Open(s.journal_path, CREATE_NEW); file.Append(encoded);
        s.journal_directory.FlushDirectory();
        const auto readback = Decode(file.Read());
        Require(readback.preimage == j.preimage, "VolumeManagementPreparedReadbackFailed");
        j.digest = readback.digest;
        if (physical) {
            try { s.HoldHistory(p.before, j.preimage, encoded); }
            catch (...) {
                PersistVolumeKeeperHistoryProof(s.journal_path, encoded, s.identity, s.HeldWals());
                Transition(file, j, 3);
                throw;
            }
            PersistVolumeKeeperHistoryProof(s.journal_path, encoded, s.identity, s.HeldWals());
        }
        Fill(result, s, j, p); result.confirmation_token = j.token; result.outcome = VolumeManagementOutcome::Prepared;
    } catch (const std::exception& ex) { result.error = ex.what(); }
    return result;
}
VolumeManagementResult Run(const VolumeManagementRequest& r, std::string_view confirmation,
    bool recovery, bool cancel, const AppleCheckpointStageHook& hook,
    const std::shared_ptr<VolumePhysicalSource>& physical = {})
{
    VolumeManagementResult result; bool accepted = false;
    try {
        Session s(r, physical); result.source_identity = s.identity; result.journal_path = s.journal_path;
        File file; file.Open(s.journal_path, OPEN_EXISTING); auto j = Decode(file.Read());
        s.original_census = j.census;
        Require(j.identity == s.identity && EncodeRequest(j.request) == EncodeRequest(s.request), "VolumeManagementJournalBindingMismatch");
        Require(!!physical == j.physical.has_value(), "VolumeManagementPhysicalModeMismatch");
        if (physical) {
            Require(j.physical->binding == physical->Binding() && j.physical->instance == physical->InstanceId() &&
                j.destination_wal == s.DestinationWal() && physical->Revalidate(), "VolumeManagementPhysicalHeldScopeMismatch");
            Require(FlushFileBuffers(file.h) != FALSE, "VolumeManagementOriginalEvidenceFlushFailed");
        }
        if (!recovery) {
            Require(j.state == 0 && !j.incomplete_receipt, "VolumeManagementConfirmationConsumed");
            if (confirmation != j.token || Now() >= j.expires || cancel) {
                s.cancellation = s.Cancellation(s.Image(), HistoryFrame(file, j));
                Transition(file, j, 3);
                Require(confirmation == j.token, "VolumeManagementConfirmationMismatch");
                Require(Now() < j.expires, "VolumeManagementConfirmationExpired");
                result.outcome = VolumeManagementOutcome::Cancelled; return result;
            }
        } else {
            accepted = j.state == 1;
        }
        const auto p = Rebuild(j); Fill(result, s, j, p);
        const auto current = s.Image();
        if (recovery && j.state == 2 && current != j.preimage) {
            // A completed request may be observed after genuine later commits.
            // Original accepted redo is never published over that generation.
            catalog::VectorRandomAccessSource source(current); std::string error;
            const auto checkpoint = catalog::LoadAppleCheckpointView(source, 0, current.size(), error);
            if (checkpoint && checkpoint->container.superblock.xid > p.after.container.superblock.xid) {
                s.history = s.History(current, {}, s.journal_path, HistoryFrame(file, j), true);
                if (physical) Require(s.Flush(), "VolumeManagementRecoveryFlushFailed");
                result.outcome = VolumeManagementOutcome::Committed; return result;
            }
        }
        if (recovery && (j.state == 0 || j.state == 3)) {
            Require(current == j.preimage, "VolumeManagementUnacceptedImageChanged");
            Require(s.Census(p.before) == j.census, "VolumeManagementStaleWalCensus");
            s.cancellation = s.Cancellation(current, HistoryFrame(file, j));
            if (j.state == 0) {
                if (j.incomplete_receipt) file.TrimIncompleteReceipt(j.valid_bytes);
                Transition(file, j, 3);
            }
            result.post_xid = result.pre_xid;
            result.free_blocks_after = result.free_blocks_before;
            result.allocated_blocks = result.deferred_blocks = 0;
            result.outcome = VolumeManagementOutcome::Cancelled; return result;
        }
        if (!recovery && current != j.preimage) {
            Transition(file, j, 3); throw std::runtime_error("VolumeManagementStalePreimage");
        }
        if (recovery) {
            const auto at = p.publication.superblock_write.physical_block * p.publication.block_size;
            Bytes raw(current.begin() + at, current.begin() + at + p.publication.block_size);
            const auto nx = catalog::ParseNxSuperblock(raw);
            Require(!nx || nx->xid <= p.publication.expected_checkpoint_xid || raw == p.publication.superblock_write.bytes,
                "VolumeManagementRecoveryConflictingCheckpoint");
        }
        const auto census = s.Census(p.before);
        if (census != j.census) {
            if (!recovery) Transition(file, j, 3);
            throw std::runtime_error("VolumeManagementStaleWalCensus");
        }
        // All bytes outside the deterministic COW destinations must still be
        // exactly the accepted preimage. Only those destinations may be torn.
        auto expected = j.preimage;
        std::set<std::uint64_t> destinations;
        const auto overlay = [&](const auto& w) {
            Require(w.bytes.size() == p.publication.block_size && w.physical_block < expected.size() / p.publication.block_size,
                "VolumeManagementRedoBoundsInvalid");
            Require(destinations.insert(w.physical_block).second, "VolumeManagementRedoOverlap");
            std::copy(w.bytes.begin(), w.bytes.end(), expected.begin() + w.physical_block * p.publication.block_size);
        };
        for (const auto& w : p.publication.before_superblock_writes) overlay(w);
        overlay(p.publication.superblock_write);
        Require(current.size() == expected.size(), "VolumeManagementRecoverySizeChanged");
        for (std::size_t at = 0; at < current.size(); at += p.publication.block_size) {
            const auto count = (std::min<std::size_t>)(p.publication.block_size, current.size() - at);
            if (destinations.contains(at / p.publication.block_size)) continue;
            Require(std::equal(current.begin() + at, current.begin() + at + count, j.preimage.begin() + at),
                "VolumeManagementRecoveryUnrelatedBytesChanged");
        }
        if (physical && recovery) for (const auto block : destinations) {
            const auto at = block * p.publication.block_size;
            const Bytes raw(current.begin() + at, current.begin() + at + p.publication.block_size);
            if (catalog::ParseNxSuperblock(raw))
                Require(std::equal(raw.begin(), raw.end(), j.preimage.begin() + at) ||
                    std::equal(raw.begin(), raw.end(), expected.begin() + at), "VolumeManagementRecoveryConflictingCheckpoint");
        }
        if (j.state == 2) {
            Require(current == expected, "VolumeManagementCompletedImageChanged"); VerifyResult(s, p);
            if (physical || s.request.operation == VolumeManagementOperation::Delete)
                s.history = s.History(current, {}, s.journal_path, HistoryFrame(file, j), true);
            if (physical) Require(s.Flush(), "VolumeManagementRecoveryFlushFailed");
            result.outcome = VolumeManagementOutcome::Committed; return result;
        }
        if (recovery) {
            std::vector<VolumeKeeperHistoryMember> members;
            for (const auto& v : p.before.volumes)
                members.push_back({p.before.container.superblock.uuid_hex, v.superblock.uuid_hex, v.superblock.object_id,
                    s.request.sibling_wals.at(v.superblock.object_id)});
            s.history = s.History(j.preimage, members, s.journal_path, HistoryFrame(file, j));
        }
        if (j.incomplete_receipt) file.TrimIncompleteReceipt(j.valid_bytes);
        if (!recovery) {
            if (Interrupted(hook, "before-volume-management-accept")) {
                s.cancellation = s.Cancellation(current, HistoryFrame(file, j));
                Transition(file, j, 3); result.outcome = VolumeManagementOutcome::Cancelled; return result;
            }
            // From the start of receipt I/O onward report recovery uncertainty.
            std::vector<VolumeKeeperHistoryMember> members;
            for (const auto& v : p.before.volumes)
                members.push_back({p.before.container.superblock.uuid_hex, v.superblock.uuid_hex, v.superblock.object_id,
                    s.request.sibling_wals.at(v.superblock.object_id)});
            s.history = s.History(current, members, s.journal_path, HistoryFrame(file, j));
            PersistVolumeKeeperHistoryProof(s.journal_path, HistoryFrame(file, j), s.identity, s.HeldWals(), hook);
            accepted = true; Transition(file, j, 1);
        }
        if (physical && recovery) ConfirmVolumeKeeperHistoryProof(s.journal_path, HistoryFrame(file, j), s.identity, s.HeldWals());
        Require(!Interrupted(hook, "after-volume-management-accept"), "VolumeManagementInterrupted");
        if (current != expected) {
            auto publication = p.publication;
            if (recovery) {
                // Existing executor checks guards twice. Authorized destination
                // guards are rebound to the already observed torn/pre-switch
                // bytes; all stable guards retain their original proof.
                for (auto& g : publication.guard_blocks) if (destinations.contains(g.physical_block)) {
                    const auto at = g.physical_block * publication.block_size;
                    g.bytes.assign(current.begin() + at, current.begin() + at + publication.block_size);
                }
            }
            std::string e; Require(s.Publish(publication, e, hook), e);
        } else Require(s.Flush(), "VolumeManagementRecoveryFlushFailed");
        Require(s.Image() == expected, "VolumeManagementPostimageMismatch"); VerifyResult(s, p);
        Require(!Interrupted(hook, "before-volume-management-complete"), "VolumeManagementInterrupted");
        Transition(file, j, 2); accepted = false; result.outcome = VolumeManagementOutcome::Committed;
    } catch (const std::exception& ex) {
        result.error = ex.what(); result.outcome = accepted ? VolumeManagementOutcome::RecoveryRequired : VolumeManagementOutcome::Refused;
    }
    return result;
}
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
std::string DerivePartitionlessVolumeRecoveryIdentity(std::string_view uuid, std::uint64_t oid)
{
    Require(ValidRenameUuid(uuid) && oid, "VolumeManagementRecoveryIdentityInvalid");
    std::array<std::byte, 42> material{};
    for (std::size_t i = 0; i < 16; ++i) {
        unsigned value = 0;
        const auto [end, ec] = std::from_chars(uuid.data() + 2 * i, uuid.data() + 2 * i + 2, value, 16);
        Require(ec == std::errc{} && end == uuid.data() + 2 * i + 2, "VolumeManagementRecoveryIdentityInvalid");
        material[17 + i] = std::byte(value);
    }
    material[33] = std::byte{1};
    for (unsigned i = 0; i < 8; ++i) material[34 + i] = std::byte((oid >> (8 * i)) & 255);
    const auto digest = Hash(material);
    DWORD length = 0;
    constexpr DWORD flags = CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF;
    Require(CryptBinaryToStringA(reinterpret_cast<const BYTE*>(digest.data()), static_cast<DWORD>(digest.size()), flags, nullptr, &length),
        "VolumeManagementRecoveryIdentityEncodingFailed");
    std::string encoded(length, '\0');
    Require(CryptBinaryToStringA(reinterpret_cast<const BYTE*>(digest.data()), static_cast<DWORD>(digest.size()), flags, encoded.data(), &length),
        "VolumeManagementRecoveryIdentityEncodingFailed");
    encoded.resize(length);
    if (!encoded.empty() && encoded.back() == '\0') encoded.pop_back();
    while (!encoded.empty() && encoded.back() == '=') encoded.pop_back();
    std::replace(encoded.begin(), encoded.end(), '+', '-'); std::replace(encoded.begin(), encoded.end(), '/', '_');
    Require(encoded.size() == 43, "VolumeManagementRecoveryIdentityEncodingFailed");
    return "apfs-recovery-v1-" + encoded;
}
VolumeManagementResult PrepareVolumeCreate(const VolumeManagementRequest& r) { return Prepare(r, VolumeManagementOperation::Create); }
VolumeManagementResult PrepareVolumeDelete(const VolumeManagementRequest& r) { return Prepare(r, VolumeManagementOperation::Delete); }
VolumeManagementResult ApplyVolumeManagement(const VolumeManagementRequest& r, std::string_view token, const AppleCheckpointStageHook& hook)
{ return Run(r, token, false, false, hook); }
VolumeManagementResult CancelVolumeManagement(const VolumeManagementRequest& r, std::string_view token) { return Run(r, token, false, true, {}); }
VolumeManagementResult RecoverVolumeManagement(const VolumeManagementRequest& r, const AppleCheckpointStageHook& hook)
{ return Run(r, {}, true, false, hook); }
VolumeManagementResult PrepareVolumePhysicalCreate(const std::shared_ptr<VolumePhysicalSource>& source, const VolumeManagementRequest& r)
{ if (!source) return {VolumeManagementOutcome::Refused, "VolumeManagementPhysicalHeldSourceRequired"}; return Prepare(r, VolumeManagementOperation::Create, source); }
VolumeManagementResult PrepareVolumePhysicalDelete(const std::shared_ptr<VolumePhysicalSource>& source, const VolumeManagementRequest& r)
{ if (!source) return {VolumeManagementOutcome::Refused, "VolumeManagementPhysicalHeldSourceRequired"}; return Prepare(r, VolumeManagementOperation::Delete, source); }
VolumeManagementResult ApplyVolumePhysicalManagement(const std::shared_ptr<VolumePhysicalSource>& source,
    const VolumeManagementRequest& r, std::string_view token, const AppleCheckpointStageHook& hook)
{ if (!source) return {VolumeManagementOutcome::Refused, "VolumeManagementPhysicalHeldSourceRequired"}; return Run(r, token, false, false, hook, source); }
VolumeManagementResult CancelVolumePhysicalManagement(const std::shared_ptr<VolumePhysicalSource>& source,
    const VolumeManagementRequest& r, std::string_view token)
{ if (!source) return {VolumeManagementOutcome::Refused, "VolumeManagementPhysicalHeldSourceRequired"}; return Run(r, token, false, true, {}, source); }
VolumeManagementResult RecoverVolumePhysicalManagement(const std::shared_ptr<VolumePhysicalSource>& source,
    const VolumeManagementRequest& r, const AppleCheckpointStageHook& hook)
{ if (!source) return {VolumeManagementOutcome::Refused, "VolumeManagementPhysicalHeldSourceRequired"}; return Run(r, {}, true, false, hook, source); }
VolumeManagementObservation ObserveVolumeManagement(const VolumeManagementObservationRequest& r)
{
    VolumeManagementObservation result;
    try {
        const auto image = Local(r.image);
        Require(r.offset_bytes % 4096 == 0, "VolumeManagementOffsetUnaligned");
        File fence; fence.ObserveImage(image);
        std::string e;
        auto device = BlockDevice::OpenStableReadOnlyImage(image.wstring(), e);
        Require(!!device, e);
        const auto size = device->GetGeometry().total_bytes;
        Require(r.offset_bytes < size && size - r.offset_bytes <= (r.offset_bytes ? MaxImage : (1ull << 40)),
            "VolumeManagementBoundedImageSizeExceeded");
        result.store_size_bytes = size - r.offset_bytes;
        Require(device->QueryRegularImageIdentity(result.source_identity) && result.source_identity.size() == 80,
            "VolumeManagementImageIdentityUnavailable");
        // The existing stable reader holds the whole file at base zero. Bind
        // its held identity to this explicit store offset, as the keeper does.
        std::ostringstream offset; offset << std::hex;
        offset.width(16); offset.fill('0'); offset << r.offset_bytes;
        result.source_identity.replace(48, 16, offset.str());
        class HeldSource final : public catalog::RandomAccessSource {
        public:
            HeldSource(const BlockDevice& device, std::uint64_t offset, std::uint64_t size) : device_(device), offset_(offset), size_(size) {}
            std::uint64_t SizeBytes() const override { return size_; }
            bool Read(std::uint64_t offset, std::size_t size, Bytes& out) const override {
                out.clear(); return offset <= size_ && size <= size_ - offset && size <= 4ull * 1024 * 1024 &&
                    device_.Read(offset_ + offset, size, out);
            }
        private:
            const BlockDevice& device_; std::uint64_t offset_, size_;
        } source(*device, r.offset_bytes, result.store_size_bytes);
        const auto cp = catalog::LoadAppleCheckpointView(source, 0, source.SizeBytes(), e);
        Require(!!cp, e);
        const auto& nx = cp->container.superblock;
        Require(nx.block_size && nx.block_count && nx.block_count == result.store_size_bytes / nx.block_size &&
            result.store_size_bytes % nx.block_size == 0 && r.offset_bytes % nx.block_size == 0,
            "VolumeManagementObservationStoreGeometryMismatch");
        Require(ValidRenameUuid(nx.uuid_hex) && nx.xid && nx.next_oid && !cp->volumes.empty() && cp->volumes.size() <= 100,
            "VolumeManagementObservationCatalogIdentityInvalid");
        Require(VerifyTopology(source, *cp, e), e);
        std::set<std::string> uuids; std::set<std::uint64_t> oids;
        for (const auto& v : cp->volumes) {
            Require(ValidRenameUuid(v.superblock.uuid_hex) && v.superblock.object_id &&
                uuids.insert(v.superblock.uuid_hex).second && oids.insert(v.superblock.object_id).second,
                "VolumeManagementObservationDuplicateVolumeIdentity");
            Require(CheckAppleVolumeWriteFeatures(nx, v.superblock, e), e);
            result.volumes.push_back({v.superblock.uuid_hex, v.superblock.object_id});
        }
        Require(device->RevalidateStableReadOnlyImage() && !device->HasWriteHandle(), "VolumeManagementObservationImageChanged");
        result.container_uuid = nx.uuid_hex; result.checkpoint_xid = nx.xid;
        result.block_size = nx.block_size; result.next_oid = nx.next_oid;
        result.complete = true;
    } catch (const std::exception& ex) { result.error = ex.what(); result.volumes.clear(); }
    return result;
}
std::string VolumeManagementObservationJson(const VolumeManagementObservationRequest& r,
    const VolumeManagementObservation& result)
{
    std::ostringstream o;
    o << "{\"schemaVersion\":1,\"operation\":\"volume-management-observe\",\"readOnly\":true,\"image\":"
      << Quote(Utf8(r.image.wstring())) << ",\"offsetBytes\":" << Quote(std::to_string(r.offset_bytes))
      << ",\"storeSizeBytes\":" << Quote(std::to_string(result.store_size_bytes))
      << ",\"sourceIdentity\":" << Quote(result.source_identity) << ",\"containerUuid\":" << Quote(result.container_uuid)
      << ",\"checkpointXid\":" << Quote(std::to_string(result.checkpoint_xid))
      << ",\"blockBytes\":" << Quote(std::to_string(result.block_size)) << ",\"nextOid\":" << Quote(std::to_string(result.next_oid))
      << ",\"volumes\":[";
    bool first = true;
    for (const auto& v : result.volumes) {
        if (!first) o << ','; first = false;
        o << "{\"volumeUuid\":" << Quote(v.volume_uuid) << ",\"oid\":" << Quote(std::to_string(v.oid)) << '}';
    }
    o << ']';
    if (!result.complete) o << ",\"outcome\":\"refused\",\"error\":" << Quote(result.error);
    o << '}'; return o.str();
}
std::string VolumeManagementJson(const VolumeManagementRequest& r, const VolumeManagementResult& result)
{
    const char* outcomes[] = {"invalid", "prepared", "committed", "cancelled", "refused", "recovery-required"};
    std::ostringstream o;
    o << "{\"schemaVersion\":1,\"operation\":" << Quote(r.operation == VolumeManagementOperation::Create ? "volume-create" : "volume-delete")
      << ",\"outcome\":" << Quote(outcomes[static_cast<unsigned>(result.outcome)])
      << ",\"error\":" << Quote(result.error) << ",\"image\":" << Quote(Utf8(r.image.wstring()))
      << ",\"sourceIdentity\":" << Quote(result.source_identity) << ",\"journal\":" << Quote(Utf8(result.journal_path.wstring()))
      << ",\"containerUuid\":" << Quote(r.container_uuid) << ",\"volumeUuid\":" << Quote(r.volume_uuid)
      << ",\"volumeOid\":" << Quote(std::to_string(r.volume_oid)) << ",\"offsetBytes\":" << Quote(std::to_string(r.offset_bytes))
      << ",\"preXid\":" << Quote(std::to_string(result.pre_xid)) << ",\"postXid\":" << Quote(std::to_string(result.post_xid))
      << ",\"blockBytes\":" << Quote(std::to_string(result.block_size))
      << ",\"freeBlocksBefore\":" << Quote(std::to_string(result.free_blocks_before))
      << ",\"freeBlocksAfter\":" << Quote(std::to_string(result.free_blocks_after))
      << ",\"allocatedBlocks\":" << Quote(std::to_string(result.allocated_blocks))
      << ",\"deferredBlocks\":" << Quote(std::to_string(result.deferred_blocks))
      << ",\"expiresUnixSeconds\":" << Quote(std::to_string(result.expires_unix_seconds))
      << ",\"confirmationToken\":" << Quote(result.confirmation_token) << ",\"siblingWals\":[";
    bool first = true;
    for (const auto& [id, path] : r.sibling_wals) { if (!first) o << ','; first = false;
        o << "{\"oid\":" << Quote(std::to_string(id)) << ",\"path\":" << Quote(Utf8(path.wstring())) << '}'; }
    o << "],\"name\":" << Quote(r.name_utf8) << ",\"quotaBlocks\":" << Quote(std::to_string(r.quota_blocks))
      << ",\"reserveBlocks\":" << Quote(std::to_string(r.reserve_blocks)) << ",\"caseSensitive\":" << (r.case_sensitive ? "true" : "false") << '}';
    return o.str();
}
}
