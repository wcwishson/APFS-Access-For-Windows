#include "VolumeKeeperHistory.h"
#include "VolumeKeeperWal.h"
#include "BlockDevice.h"
#include "VolumeManagementInternal.h"
#include "VolumePhysicalMedia.h"
#include "VolumePhysicalBindingCodec.h"
#include "VolumePhysicalGeometryInternal.h"
#include "VolumeFormatEvidence.h"
#include <bcrypt.h>
#include <wincrypt.h>
#include <algorithm>
#include <charconv>
#include <cwctype>
#include <map>
#include <set>
#include <sstream>

namespace apfsaccess::rw
{
namespace
{
using Bytes = std::vector<std::byte>;
constexpr std::uint64_t ProofLimit = 1024 * 1024, WalLimit = 64ull * 1024 * 1024;
constexpr std::uint64_t JournalLimit = 257ull * 1024 * 1024;
void Need(bool ok, const std::string& error) { if (!ok) throw std::runtime_error("KeeperHistory" + error); }
std::wstring Key(const std::filesystem::path& p)
{
    auto s = p.lexically_normal().wstring();
    std::transform(s.begin(), s.end(), s.begin(), [](auto c) { return c == L'/' ? L'\\' : static_cast<wchar_t>(std::towlower(c)); }); return s;
}
std::filesystem::path Local(const std::filesystem::path& p)
{
    const auto s = p.wstring();
    Need(s.size() >= 3 && s.size() < 32000 && std::iswalpha(s[0]) && s[1] == L':' &&
        (s[2] == L'/' || s[2] == L'\\') && s.find(L':', 2) == std::wstring::npos &&
        s.find(L'\0') == std::wstring::npos, "LocalPathRequired");
    auto q = p.lexically_normal(); q.make_preferred();
    for (auto at = q.parent_path(); !at.empty() && at != at.root_path(); at = at.parent_path()) {
        const auto flags = GetFileAttributesW(at.c_str());
        Need(flags != INVALID_FILE_ATTRIBUTES && (flags & FILE_ATTRIBUTE_DIRECTORY) && !(flags & FILE_ATTRIBUTE_REPARSE_POINT), "PathAliasOrUnavailable");
    }
    return q;
}
std::wstring Extended(const std::filesystem::path& p) { return L"\\\\?\\" + p.wstring(); }
std::string Hex(std::span<const std::byte> bytes)
{
    std::string s; constexpr char h[] = "0123456789abcdef";
    for (auto b : bytes) { const auto n = std::to_integer<unsigned>(b); s += h[n >> 4]; s += h[n & 15]; } return s;
}
std::string Hash(std::span<const std::byte> bytes)
{
    BCRYPT_ALG_HANDLE alg{}; std::array<std::byte, 32> hash{};
    Need(bytes.size() <= ULONG_MAX && BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) >= 0, "HashFailed");
    const auto status = BCryptHash(alg, nullptr, 0, reinterpret_cast<PUCHAR>(const_cast<std::byte*>(bytes.data())),
        static_cast<ULONG>(bytes.size()), reinterpret_cast<PUCHAR>(hash.data()), 32);
    BCryptCloseAlgorithmProvider(alg, 0); Need(status >= 0, "HashFailed"); return Hex(hash);
}
void Number(Bytes& b, std::uint64_t n) { for (unsigned i = 0; i < 8; ++i) b.push_back(std::byte((n >> (8 * i)) & 255)); }
void Text(Bytes& b, std::string_view s) { Number(b, s.size()); for (auto c : s) b.push_back(std::byte(c)); }
struct Reader
{
    std::span<const std::byte> b; std::size_t at = 0;
    std::uint64_t Number() { Need(at <= b.size() && b.size() - at >= 8, "ProofTruncated"); const auto n = catalog::ReadU64LE(b, at).value(); at += 8; return n; }
    std::string Text() { const auto n = Number(); Need(n <= 128 && n <= b.size() - at, "ProofTextInvalid");
        std::string s(reinterpret_cast<const char*>(b.data() + at), static_cast<std::size_t>(n)); at += n; return s; }
};
std::string FileIdentity(HANDLE h, const std::filesystem::path& p)
{
    FILE_ID_INFO id{}; FILE_STANDARD_INFO si{}; FILE_ATTRIBUTE_TAG_INFO ai{};
    Need(GetFileType(h) == FILE_TYPE_DISK && GetFileInformationByHandleEx(h, FileStandardInfo, &si, sizeof(si)) &&
        !si.Directory && !si.DeletePending && si.NumberOfLinks == 1 &&
        GetFileInformationByHandleEx(h, FileAttributeTagInfo, &ai, sizeof(ai)) &&
        !(ai.FileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DEVICE)) &&
        GetFileInformationByHandleEx(h, FileIdInfo, &id, sizeof(id)), "OrdinarySingleLinkFileRequired");
    std::wstring name(32768, L'\0');
    const auto n = GetFinalPathNameByHandleW(h, name.data(), static_cast<DWORD>(name.size()), FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    Need(n && n < name.size(), "FinalPathUnavailable"); name.resize(n);
    Need(_wcsicmp(name.c_str(), Extended(Local(p)).c_str()) == 0, "FileAlias");
    std::ostringstream out; out << std::hex; out.width(16); out.fill('0'); out << id.VolumeSerialNumber;
    out << Hex(std::span(reinterpret_cast<const std::byte*>(id.FileId.Identifier), 16)); return out.str();
}
Bytes Read(HANDLE h, std::uint64_t limit)
{
    LARGE_INTEGER size{}, zero{}; Need(GetFileSizeEx(h, &size) && size.QuadPart >= 0 && std::uint64_t(size.QuadPart) <= limit &&
        SetFilePointerEx(h, zero, nullptr, FILE_BEGIN), "FileBoundsInvalid");
    Bytes b(static_cast<std::size_t>(size.QuadPart)); DWORD got{};
    Need(ReadFile(h, b.data(), static_cast<DWORD>(b.size()), &got, nullptr) && got == b.size(), "ReadFailed"); return b;
}
struct File
{
    HANDLE h = INVALID_HANDLE_VALUE;
    ~File() { if (h != INVALID_HANDLE_VALUE) CloseHandle(h); }
    bool Empty() const
    {
        LARGE_INTEGER size{}; Need(GetFileSizeEx(h, &size) && size.QuadPart >= 0, "FileBoundsInvalid");
        return size.QuadPart == 0;
    }
    void Open(const std::filesystem::path& raw, bool create = false, bool durable = false)
    {
        const auto path = Local(raw);
        h = CreateFileW(Extended(path).c_str(), create || durable ? GENERIC_READ | GENERIC_WRITE : GENERIC_READ,
            create || durable ? 0 : FILE_SHARE_READ, nullptr, create ? CREATE_NEW : OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH, nullptr);
        Need(h != INVALID_HANDLE_VALUE, create ? "ProofCreateFailed" : "EvidenceMissingOrBusy"); (void)FileIdentity(h, path);
    }
    void Directory(const std::filesystem::path& raw)
    {
        const auto path = Local(raw);
        h = CreateFileW(Extended(path).c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
            OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, nullptr);
        FILE_ATTRIBUTE_TAG_INFO info{};
        Need(h != INVALID_HANDLE_VALUE && GetFileInformationByHandleEx(h, FileAttributeTagInfo, &info, sizeof(info)) &&
            (info.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) && !(info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT), "DirectoryAliasOrUnavailable");
        std::wstring name(32768, L'\0');
        const auto n = GetFinalPathNameByHandleW(h, name.data(), static_cast<DWORD>(name.size()), FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
        Need(n && n < name.size(), "DirectoryPathUnavailable"); name.resize(n);
        Need(_wcsicmp(name.c_str(), Extended(path).c_str()) == 0, "DirectoryAlias");
    }
};
std::string MemberKey(const VolumeKeeperHistoryMember& m)
{ return m.container_uuid + ":" + std::to_string(m.oid) + ":" + m.volume_uuid; }
using MemberMap = std::map<std::string, VolumeKeeperHistoryMember>;
MemberMap Map(const std::vector<VolumeKeeperHistoryMember>& members)
{
    MemberMap map;
    for (const auto& member : members) Need(map.emplace(MemberKey(member), member).second, "DuplicateMember"); return map;
}
bool SameTopology(const std::vector<VolumeKeeperHistoryMember>& a, const std::vector<VolumeKeeperHistoryMember>& b)
{
    const auto am = Map(a), bm = Map(b);
    if (am.size() != bm.size()) return false;
    for (const auto& [key, _] : am) if (!bm.contains(key)) return false; return true;
}
std::filesystem::path ProofPath(const VolumeKeeperHistoryBinding& binding)
{ return binding.journal.parent_path() / ("wal-history-" + binding.frame_digest + ".vkh1"); }
struct WalProof { std::string file_id, digest; std::uint64_t cleanup = 0; };
std::string Utf8(const std::filesystem::path& path)
{
    const auto wide = path.wstring();
    const auto size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide.data(), static_cast<int>(wide.size()), nullptr, 0, nullptr, nullptr);
    Need(size > 0, "PathUnicodeInvalid"); std::string text(size, ' ');
    Need(WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide.data(), static_cast<int>(wide.size()), text.data(), size, nullptr, nullptr) == size, "PathUnicodeInvalid");
    return text;
}
std::string OriginalCensus(const VolumeKeeperHistoryBinding& binding, const std::map<std::string, WalProof>& proofs)
{
    Bytes bytes;
    if (!binding.image_family) Text(bytes, "wal-file-identity-v1");
    for (const auto& member : binding.before) {
        const auto& proof = proofs.at(MemberKey(member));
        if (binding.image_family) Text(bytes, "apfs-vol:" + member.container_uuid + ":" + std::to_string(member.oid));
        else Number(bytes, member.oid);
        Text(bytes, member.volume_uuid); Text(bytes, Utf8(member.wal)); Text(bytes, proof.file_id);
        Number(bytes, proof.cleanup); Number(bytes, proof.cleanup); Number(bytes, proof.cleanup); Text(bytes, proof.digest);
    }
    return Hash(bytes);
}
TransactionManager::DurabilityWatermarks Clean(const VolumeKeeperHistoryMember& m, std::uint64_t xid, const RawSnapshotBinding* physical = nullptr)
{
    const VolumeKeeperWalIdentities ids{"apfs-vol:" + m.container_uuid + ":" + std::to_string(m.oid),
        physical ? DeriveVolumePhysicalRecoveryIdentity(*physical, m.container_uuid, m.oid) : DerivePartitionlessVolumeRecoveryIdentity(m.container_uuid, m.oid)};
    const auto marks = InspectVolumeKeeperWal(m.wal, ids, "KeeperHistory", "WalDebt");
    const auto records = WriteAheadLog::ReadAll(m.wal, "");
    Need(records.status == WriteAheadLog::ReadStatus::Ok && !records.recovered_torn_tail, "WalReadFailed");
    Need(VolumeKeeperWalHasCleanBoundary(records.records, marks.cleanup_sequence), "WalDebt");
    for (const auto& record : records.records) {
        if (record.operation == WriteAheadLog::OperationKind::TransactionMarker && record.state == WriteAheadLog::RecordState::Accepted)
            Need(record.object_id && record.object_id <= xid, "WalCheckpointUnproved");
    }
    WIN32_FIND_DATAW found{};
    const auto search = FindFirstFileW((Extended(Local(m.wal)) + L".compact*").c_str(), &found);
    const auto error = GetLastError();
    if (search != INVALID_HANDLE_VALUE) { FindClose(search); Need(false, "WalCompactionEvidence"); }
    Need(error == ERROR_FILE_NOT_FOUND, "WalCompactionEnumerationFailed"); return marks;
}
std::map<std::string, WalProof> DecodeProof(const Bytes& bytes, const VolumeKeeperHistoryBinding& binding)
{
    Reader in{bytes}; Need(in.Number() == 0x31484b5653465041ull, "ProofMagicInvalid");
    const auto digest = in.Text(); const auto body = std::span(bytes).subspan(in.at);
    Need(Hash(body) == digest, "ProofChecksumInvalid"); Reader r{body};
    Need(r.Text() == binding.frame_digest && r.Text() == binding.token && r.Text() == binding.source_identity, "ProofJournalBindingMismatch");
    Need(r.Number() == binding.before.size(), "ProofCensusMismatch");
    std::map<std::string, WalProof> result;
    for (const auto& member : binding.before) {
        WalProof p{r.Text(), r.Text(), r.Number()};
        const auto hex = [](const auto& value) { return value.find_first_not_of("0123456789abcdef") == std::string::npos; };
        Need(p.file_id.size() == 48 && p.digest.size() == 64 && hex(p.file_id) && hex(p.digest) &&
            result.emplace(MemberKey(member), p).second, "ProofMemberInvalid");
    }
    Need(r.at == body.size(), "ProofTrailingBytes");
    Need(OriginalCensus(binding, result) == binding.census_digest, "OriginalFileIdentityCensusUnproved"); return result;
}
struct NamespaceScope
{
    std::array<std::byte, 42> material{};
    std::string container, suffix;
};
std::uint64_t StrictCleanMarker(std::span<const std::byte> bytes)
{
    Need(bytes.size() >= 24 && bytes.size() <= 43, "MarkerDirtyOrInvalid");
    const std::string_view text(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    constexpr std::string_view prefix = "dirty=0\nlastCommitXid=";
    Need(text.starts_with(prefix) && text.ends_with('\n'), "MarkerDirtyOrInvalid");
    const auto number = text.substr(prefix.size(), text.size() - prefix.size() - 1);
    std::uint64_t xid{}; const auto parsed = std::from_chars(number.data(), number.data() + number.size(), xid);
    Need(parsed.ec == std::errc{} && parsed.ptr == number.data() + number.size() && xid && std::to_string(xid) == number,
        "MarkerCheckpointUnproved"); return xid;
}
bool LegacyPhysicalMarkerName(std::wstring_view name)
{
    constexpr std::wstring_view prefix = L"__._PhysicalDrive", ending = L"_Native.state";
    if (name.size() > 260 || name.size() <= prefix.size() + ending.size() ||
        _wcsnicmp(name.data(), prefix.data(), prefix.size()) ||
        _wcsnicmp(name.data() + name.size() - ending.size(), ending.data(), ending.size())) return false;
    const auto middle = name.substr(prefix.size(), name.size() - prefix.size() - ending.size());
    const auto divider = middle.find(L'_');
    if (!divider || divider == std::wstring_view::npos || divider > 8 || divider + 1 == middle.size() ||
        (divider > 1 && middle[0] == L'0')) return false;
    for (const auto c : middle.substr(0, divider)) if (c < L'0' || c > L'9') return false;
    for (const auto c : middle.substr(divider + 1))
        if (c < 0x20 || std::wstring_view(L"<>:\"/\\|?*").find(c) != std::wstring_view::npos) return false;
    return true;
}
NamespaceScope DecodeNamespace(std::span<const std::byte> bytes)
{
    Need(bytes.size() == 42 && (bytes[0] == std::byte{0} || bytes[0] == std::byte{1}) &&
        bytes[33] == std::byte{1} && catalog::ReadU64LE(bytes, 34).value_or(0), "NamespaceMaterialInvalid");
    const auto nonzero = [](auto range) { return std::any_of(range.begin(), range.end(), [](auto b) { return b != std::byte{}; }); };
    Need(nonzero(bytes.subspan(1, 16)) == (bytes[0] == std::byte{1}) && nonzero(bytes.subspan(17, 16)), "NamespaceMaterialInvalid");
    NamespaceScope result; std::copy(bytes.begin(), bytes.end(), result.material.begin());
    result.container = Hex(bytes.subspan(17, 16));
    const auto digest = format_evidence::Hash(bytes);
    DWORD length{};
    const auto flags = CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF;
    Need(CryptBinaryToStringA(reinterpret_cast<const BYTE*>(digest.data()), static_cast<DWORD>(digest.size()), flags, nullptr, &length), "NamespaceEncodingFailed");
    result.suffix.resize(length);
    Need(CryptBinaryToStringA(reinterpret_cast<const BYTE*>(digest.data()), static_cast<DWORD>(digest.size()), flags, result.suffix.data(), &length), "NamespaceEncodingFailed");
    while (!result.suffix.empty() && (result.suffix.back() == '\0' || result.suffix.back() == '=')) result.suffix.pop_back();
    std::replace(result.suffix.begin(), result.suffix.end(), '+', '-');
    std::replace(result.suffix.begin(), result.suffix.end(), '/', '_');
    Need(result.suffix.size() == 43, "NamespaceEncodingFailed"); return result;
}
std::filesystem::path NamespacePath(const std::filesystem::path& root, std::string_view suffix)
{
    Need(suffix.size() == 43 && suffix.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_") == std::string_view::npos &&
        std::string_view("AEIMQUYcgkosw048").find(suffix.back()) != std::string_view::npos, "NamespaceNameInvalid");
    return Local(root) / ("spool-namespace-" + std::string(suffix) + ".vks1");
}
void FlushNamespaceDirectory(const std::filesystem::path& root)
{
    const auto directory = Local(root);
    const auto handle = CreateFileW(Extended(directory).c_str(), GENERIC_WRITE | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    Need(handle != INVALID_HANDLE_VALUE, "NamespaceDirectoryUnavailable");
    const auto flushed = FlushFileBuffers(handle); CloseHandle(handle);
    Need(flushed != FALSE, "NamespaceDirectoryDurabilityFailed");
}
std::filesystem::path CanonicalWal(const VolumeKeeperHistoryContext& context, const VolumeKeeperHistoryMember& member,
    const RawSnapshotBinding* physical = nullptr)
{
    Need(!context.spool_root.empty(), "CurrentWalBindingMissing");
    const auto identity = physical ? DeriveVolumePhysicalRecoveryIdentity(*physical, member.container_uuid, member.oid) :
        DerivePartitionlessVolumeRecoveryIdentity(member.container_uuid, member.oid);
    return context.spool_root / ("apfs_recovery_v1_" + identity.substr(17)) / "write-ahead.wal";
}
}

std::string VolumeKeeperWalFileIdentity(const VolumeKeeperHeldWal& wal) { return FileIdentity(wal.handle, wal.path); }

std::array<std::byte, 42> BuildVolumeKeeperNamespaceMaterial(std::string_view container, std::uint64_t oid,
    const RawSnapshotBinding* physical)
{
    Need(container.size() == 32 && container.find_first_not_of("0123456789abcdef") == std::string_view::npos && oid,
        "NamespaceMaterialInvalid");
    std::array<std::byte, 42> result{};
    if (physical) {
        std::string error; Need(ValidateRawSnapshotMediaBinding(physical->media, error), "NamespacePhysicalBindingInvalid");
        result[0] = std::byte{1};
        constexpr std::array<unsigned, 16> order{3, 2, 1, 0, 5, 4, 7, 6, 8, 9, 10, 11, 12, 13, 14, 15};
        for (std::size_t i = 0; i < order.size(); ++i) result[1 + i] = physical->media.partition_guid[order[i]];
    }
    for (std::size_t i = 0; i < 16; ++i) {
        unsigned value{}; const auto parsed = std::from_chars(container.data() + 2 * i, container.data() + 2 * i + 2, value, 16);
        Need(parsed.ec == std::errc{}, "NamespaceMaterialInvalid"); result[17 + i] = std::byte(value);
    }
    result[33] = std::byte{1};
    for (unsigned i = 0; i < 8; ++i) result[34 + i] = std::byte((oid >> (8 * i)) & 255);
    (void)DecodeNamespace(result); return result;
}

void PersistVolumeKeeperNamespaceWitness(const std::filesystem::path& root, std::span<const std::byte> material)
{
    const auto scope = DecodeNamespace(material); File directory; directory.Directory(root);
    const auto target = NamespacePath(root, scope.suffix);
    const auto flags = GetFileAttributesW(Extended(target).c_str());
    if (flags == INVALID_FILE_ATTRIBUTES) {
        Need(GetLastError() == ERROR_FILE_NOT_FOUND, "NamespaceWitnessUnavailable");
        std::array<std::byte, 16> nonce{};
        Need(BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(nonce.data()), static_cast<ULONG>(nonce.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG) >= 0,
            "NamespaceRandomFailed");
        auto temporary = target; temporary += L".tmp-" + std::to_wstring(GetCurrentProcessId()) + L"-" + std::filesystem::path(Hex(nonce)).wstring();
        {
            File file; file.Open(temporary, true, true); DWORD written{};
            Need(WriteFile(file.h, material.data(), static_cast<DWORD>(material.size()), &written, nullptr) &&
                written == material.size() && FlushFileBuffers(file.h) && Read(file.h, 42) == Bytes(material.begin(), material.end()),
                "NamespaceWitnessWriteFailed");
        }
        if (!MoveFileExW(Extended(temporary).c_str(), Extended(target).c_str(), MOVEFILE_WRITE_THROUGH)) {
            const auto error = GetLastError();
            Need(error == ERROR_ALREADY_EXISTS || error == ERROR_FILE_EXISTS, "NamespaceWitnessPublishFailed");
            // A racing complete publisher may win. Retain the uniquely named
            // temporary evidence rather than delete a path after losing ownership.
        }
    }
    File file; file.Open(target);
    Need(Read(file.h, 42) == Bytes(material.begin(), material.end()), "NamespaceWitnessConflict");
    FlushNamespaceDirectory(root);
}

void PersistVolumeKeeperHistoryProof(const std::filesystem::path& journal, std::span<const std::byte> frame,
    std::string_view identity, const std::vector<VolumeKeeperHeldWal>& wals,
    const std::function<bool(std::string_view)>& hook)
{
    const auto b = DecodeVolumeKeeperHistoryBinding(frame, journal, journal.parent_path(), identity);
    const auto magic=catalog::ReadU64LE(frame,0).value_or(0);
    const auto physical = (volume_physical::IsFormatMagic(magic) || volume_physical::IsManagementMagic(magic) || volume_geometry::IsMagic(magic)) ?
        std::optional<RawSnapshotBinding>(DecodeVolumeKeeperPhysicalBinding(frame)) : std::nullopt;
    Need(b.state == VolumeKeeperJournalState::Prepared && b.source_identity == identity, "ProofRequiresOriginalPreparedSource");
    Need(wals.size() == b.before.size(), "ProofCompleteOriginalCensusRequired");
    Bytes body; Text(body, b.frame_digest); Text(body, b.token); Text(body, b.source_identity); Number(body, b.before.size());
    std::set<std::string> file_ids;
    for (const auto& member : b.before) {
        const auto wal = std::find_if(wals.begin(), wals.end(), [&](const auto& w) { return Key(w.path) == Key(member.wal); });
        Need(wal != wals.end(), "ProofOriginalWalMissing");
        const auto id = FileIdentity(wal->handle, member.wal); const auto bytes = Read(wal->handle, WalLimit);
        Need(id != identity.substr(0, 48) && file_ids.insert(id).second, "WalFileAlias");
        const auto marks = Clean(member, b.pre_xid, physical ? &*physical : nullptr);
        Text(body, id); Text(body, Hash(bytes)); Number(body, marks.cleanup_sequence);
    }
    Bytes encoded; Number(encoded, 0x31484b5653465041ull); Text(encoded, Hash(body)); encoded.insert(encoded.end(), body.begin(), body.end());
    (void)DecodeProof(encoded, b);
    const auto path = ProofPath(b);
    const bool exists = std::filesystem::exists(path); File proof; proof.Open(path, !exists, true);
    if (exists) Need(Read(proof.h, ProofLimit) == encoded, "ExistingProofChanged");
    else {
        DWORD written{};
        Need(WriteFile(proof.h, encoded.data(), static_cast<DWORD>(encoded.size()), &written, nullptr) && written == encoded.size(), "ProofWriteFailed");
    }
    Need((!hook || hook("before-history-proof-file-flush")) && FlushFileBuffers(proof.h) &&
        Read(proof.h, ProofLimit) == encoded, "ProofDurabilityFailed");
    const auto dir = Local(journal.parent_path());
    const auto h = CreateFileW(Extended(dir).c_str(), GENERIC_WRITE | FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    Need(h != INVALID_HANDLE_VALUE, "ProofDirectoryUnavailable");
    const auto flushed = (!hook || hook("before-history-proof-directory-flush")) && FlushFileBuffers(h); CloseHandle(h);
    Need(flushed != FALSE, "ProofDirectoryDurabilityFailed");
}

void ConfirmVolumeKeeperHistoryProof(const std::filesystem::path& journal, std::span<const std::byte> frame,
    std::string_view identity, const std::vector<VolumeKeeperHeldWal>& wals)
{
    const auto b = DecodeVolumeKeeperHistoryBinding(frame, journal, journal.parent_path(), identity);
    const auto magic=catalog::ReadU64LE(frame,0).value_or(0);
    const auto physical = (volume_physical::IsFormatMagic(magic) || volume_physical::IsManagementMagic(magic) || volume_geometry::IsMagic(magic)) ?
        std::optional<RawSnapshotBinding>(DecodeVolumeKeeperPhysicalBinding(frame)) : std::nullopt;
    Need((b.state == VolumeKeeperJournalState::Accepted || b.state == VolumeKeeperJournalState::AnchorDurable) &&
        b.source_identity == identity && wals.size() == b.before.size(), "ReplayOriginalCertificateRequired");
    File file; file.Open(ProofPath(b), false, true); const auto proof = DecodeProof(Read(file.h, ProofLimit), b);
    for (const auto& member : b.before) {
        const auto wal = std::find_if(wals.begin(), wals.end(), [&](const auto& w) { return Key(w.path) == Key(member.wal); });
        Need(wal != wals.end(), "ProofOriginalWalMissing"); const auto& p = proof.at(MemberKey(member));
        const auto marks = Clean(member, b.pre_xid, physical ? &*physical : nullptr);
        Need(FileIdentity(wal->handle, member.wal) == p.file_id && Hash(Read(wal->handle, WalLimit)) == p.digest &&
            marks.cleanup_sequence == p.cleanup, "ReplayOriginalCertificateMismatch");
    }
    Need(FlushFileBuffers(file.h) != FALSE, "ProofDurabilityFailed");
    const auto h = CreateFileW(Extended(Local(journal.parent_path())).c_str(), GENERIC_WRITE | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    Need(h != INVALID_HANDLE_VALUE, "ProofDirectoryUnavailable");
    const auto flushed = FlushFileBuffers(h); CloseHandle(h); Need(flushed != FALSE, "ProofDirectoryDurabilityFailed");
}

struct VolumeKeeperHistoryLease::Impl
{
    std::shared_ptr<VolumePhysicalSource> physical;
    std::shared_ptr<VolumePhysicalGeometrySource> geometry;
    std::vector<std::unique_ptr<File>> files;
    std::vector<std::unique_ptr<WriteAheadLog>> leases;
    std::vector<VolumeKeeperHistoryMember> members;
    std::uint64_t xid = 0;
    std::map<std::string, std::uint64_t> marker_xids;
};
VolumeKeeperHistoryLease::VolumeKeeperHistoryLease(std::unique_ptr<Impl> p) : impl_(std::move(p)) {}
VolumeKeeperHistoryLease::~VolumeKeeperHistoryLease() = default;
std::uint64_t VolumeKeeperHistoryLease::CheckpointXid() const { return impl_->xid; }
const std::vector<VolumeKeeperHistoryMember>& VolumeKeeperHistoryLease::Members() const { return impl_->members; }
std::uint64_t VolumeKeeperHistoryLease::MarkerCheckpointXid(const VolumeKeeperHistoryMember& m) const { return impl_->marker_xids.at(MemberKey(m)); }

namespace
{
enum class HistoryPurpose { Continuation, CancellationMarkers };
std::unique_ptr<VolumeKeeperHistoryLease> AcquireHistory(std::string_view identity,
    const catalog::RandomAccessSource& source, const std::filesystem::path& root,
    const std::vector<VolumeKeeperHistoryMember>& supplied, const std::vector<VolumeKeeperHeldWal>& borrowed,
    const std::filesystem::path& held_journal, std::span<const std::byte> held_bytes,
    const VolumeKeeperHistoryContext& context, bool require_terminal, bool detached_observation, HistoryPurpose purpose,
    const std::shared_ptr<VolumePhysicalSource>& physical = {}, const std::shared_ptr<VolumePhysicalGeometrySource>& geometry = {})
{
    const auto geometry_plan=geometry?VolumePhysicalGeometryAccess::BoundPlan(geometry):std::nullopt;
    const auto* media=physical?&physical->Binding():geometry?&geometry->OriginalBinding():nullptr;
    Need(identity.size() == 80 && (geometry ? identity==VolumePhysicalIdentity(*media,geometry->InstanceId()) && geometry->Revalidate() &&
        (source.SizeBytes()==media->media.limit_bytes || (geometry_plan && source.SizeBytes()==geometry_plan->snapshot.target_bytes)) :
        physical ? identity == physical->Identity() && physical->Revalidate() &&
        source.SizeBytes() == physical->SizeBytes() : identity.substr(48, 16) == std::string(16, '0')) &&
        source.SizeBytes() && source.SizeBytes() <= (1ull << 40), "HeldSourceRequired");
    auto result = std::make_unique<VolumeKeeperHistoryLease::Impl>(); result->physical = physical;result->geometry=geometry;
    const auto hold_directory = [&](const std::filesystem::path& path) {
        auto directory = std::make_unique<File>(); directory->Directory(path); result->files.push_back(std::move(directory));
    };
    hold_directory(root);
    std::string error;
    const auto checkpoint = catalog::LoadAppleCheckpointView(source, 0, source.SizeBytes(), error);
    Need(checkpoint.has_value(), "CurrentCheckpointInvalid:" + error);
    Need(volume_management::VerifyTopology(source, *checkpoint, error), "CurrentVerificationFailed:" + error);
    result->xid = checkpoint->container.superblock.xid;
    std::vector<VolumeKeeperHistoryMember> live;
    for (const auto& volume : checkpoint->volumes)
        live.push_back({checkpoint->container.superblock.uuid_hex, volume.superblock.uuid_hex, volume.superblock.object_id, {}});
    Bytes name; Text(name, identity.substr(0, 64)); const auto stem = Hash(name);
    std::vector<VolumeKeeperHistoryBinding> history, cancelled_destinations;
    struct PhysicalRecord { RawSnapshotBinding before;std::optional<volume_geometry::Plan> plan; bool creates_destination = false; };
    std::map<std::string,PhysicalRecord> physical_records;std::size_t geometry_bytes=0;
    MemberMap destinations;
    unsigned count = 0;
    for (const auto& entry : std::filesystem::directory_iterator(Local(root))) {
        Need(++count <= 1024, "EvidenceLimit"); const auto filename = entry.path().filename().string();
        if (!filename.starts_with(stem + ".vmt1") && !filename.starts_with(stem + ".vif1")) continue;
        Bytes bytes;
        if (!held_journal.empty() && Key(held_journal) == Key(entry.path())) bytes.assign(held_bytes.begin(), held_bytes.end());
        else { auto file = std::make_unique<File>(); file->Open(entry.path()); bytes = Read(file->h, JournalLimit); result->files.push_back(std::move(file)); }
        const auto b = DecodeVolumeKeeperHistoryBinding(bytes, entry.path(), root, identity);
        if (media) {
            PhysicalRecord record{DecodeVolumeKeeperPhysicalBinding(bytes),{}};
            record.creates_destination = volume_physical::IsManagementMagic(catalog::ReadU64LE(bytes, 0).value_or(0)) && b.operation == 1;
            if(volume_geometry::IsMagic(catalog::ReadU64LE(bytes,0).value_or(0))){
                record.plan=DecodeVolumeKeeperGeometryPlan(bytes);geometry_bytes+=volume_geometry::Encode(*record.plan).size();
                Need(geometry_bytes<=(32u<<20),"GeometryHistoryQuota");
            }
            Need(physical_records.emplace(b.frame_digest,std::move(record)).second,"DuplicatePhysicalFrame");
        }
        if (b.state == VolumeKeeperJournalState::Completed) history.push_back(b);
        else {
            const bool held = !held_journal.empty() && Key(held_journal) == Key(entry.path());
            Need(held || b.state == VolumeKeeperJournalState::Cancelled ||
                (detached_observation && b.state == VolumeKeeperJournalState::Prepared), "UnfinishedJournal");
            if (b.state == VolumeKeeperJournalState::Cancelled && ((b.image_family && b.operation >= 3) ||
                (physical_records.contains(b.frame_digest) && physical_records.at(b.frame_digest).creates_destination)))
                cancelled_destinations.push_back(b);
            if (held && ((b.image_family && b.operation >= 3) ||
                (volume_physical::IsManagementMagic(catalog::ReadU64LE(bytes, 0).value_or(0)) && b.operation == 1))) {
                Need(b.pre_xid == result->xid, "DestinationOriginalCheckpointRequired");
                destinations.emplace(MemberKey(b.before.back()), b.before.back());
            }
        }
    }
    Need(!require_terminal || !history.empty(), "TerminalJournalRequired");
    std::sort(history.begin(), history.end(), [](const auto& a, const auto& b) { return a.pre_xid < b.pre_xid; });
    if(media) {
        const RawSnapshotBinding expected=geometry_plan && source.SizeBytes()==geometry_plan->snapshot.target_bytes?geometry_plan->after:*media;
        auto cursor=history.empty()?expected:physical_records.at(history.front().frame_digest).before;
        std::vector<RawSnapshotBinding> allowed{cursor};const volume_geometry::Plan* latest=nullptr;
        for(const auto& b:history){const auto& record=physical_records.at(b.frame_digest);
            Need(record.before==cursor,"GeometryHistoryChainMismatch");
            if(record.plan){Need(!latest || volume_geometry::Follows(*latest,*record.plan),"GeometryGptHistoryMismatch");
                cursor=record.plan->after;latest=&*record.plan;allowed.push_back(cursor);}
        }
        Need(cursor==expected,"GeometryCurrentBindingUnproved");
        for(const auto& [_,record]:physical_records)Need(std::find(allowed.begin(),allowed.end(),record.before)!=allowed.end(),"PhysicalHistoryBindingUnproved");
        if(latest){
            const auto held=std::find_if(physical_records.begin(),physical_records.end(),[&](const auto& pair){
                return geometry_plan && pair.second.plan && volume_geometry::Encode(*pair.second.plan)==volume_geometry::Encode(*geometry_plan);});
            const bool pending=geometry_plan && held!=physical_records.end() && latest!=&*held->second.plan;
            if(pending)Need(volume_geometry::Follows(*latest,*geometry_plan),"GeometrySelectedGptHistoryMismatch");
            else if(physical){std::string detail;Need(physical->VerifyCompletedGeometry(volume_geometry::Encode(*latest),detail),"CompletedGptUnproved:"+detail);}
            else volume_geometry::Verify(*geometry,*latest,3);
        }
    }
    for (std::size_t i = 0; i < history.size(); ++i) {
        Need(history[i].post_xid <= result->xid, "TerminalAheadOfCurrent");
        auto original = history[i].before;
        if ((history[i].image_family && history[i].operation >= 3) ||
            (physical_records.contains(history[i].frame_digest) && physical_records.at(history[i].frame_digest).creates_destination)) original.pop_back();
        if (i) Need(history[i].pre_xid >= history[i - 1].post_xid && SameTopology(original, history[i - 1].after), "TopologyChainUnproved");
    }
    if (!history.empty()) Need(SameTopology(history.back().after, live), "CurrentTopologyMismatchOrOidReuse");
    MemberMap members = Map(supplied);
    std::map<std::string, std::vector<WalProof>> proofs;
    std::map<std::string, std::uint64_t> retired_at;
    for (const auto& b : history) {
        auto file = std::make_unique<File>(); file->Open(ProofPath(b));
        const auto proof = DecodeProof(Read(file->h, ProofLimit), b); result->files.push_back(std::move(file));
        for (const auto& m : b.before) {
            const auto key = MemberKey(m);
            if (members.contains(key)) Need(Key(members.at(key).wal) == Key(m.wal), "WalPathBindingMismatch");
            else members.emplace(key, m);
            proofs[key].push_back(proof.at(key));
            if (!Map(b.after).contains(key)) retired_at[key] = b.pre_xid;
        }
        for (const auto& m : b.after) if (!m.wal.empty() && !members.contains(MemberKey(m))) members.emplace(MemberKey(m), m);
    }
    const auto live_map = Map(live);
    for (const auto& [key, member] : destinations) {
        Need(!members.contains(key) && !live_map.contains(key), "DestinationIdentityReused");
        members.emplace(key, member);
    }
    for (auto& m : live) {
        const auto key = MemberKey(m);
        if (!members.contains(key)) { m.wal = CanonicalWal(context, m, media); members.emplace(key, m); }
    }
    Need(members.size() <= 100, "MemberLimit");
    std::set<std::wstring> paths; std::set<std::string> file_ids, required_marker_members;
    for (const auto& [key, m] : members) {
        const bool retired = !live_map.contains(key) && !destinations.contains(key);
        Need(!retired || (proofs.contains(key) && retired_at.contains(key)), "RetirementUnproved");
        for (const auto& current_member : live)
            Need(current_member.container_uuid != m.container_uuid || current_member.oid != m.oid || current_member.volume_uuid == m.volume_uuid, "OidReused");
        Need(paths.insert(Key(m.wal)).second, "WalPathAlias");
        if (purpose == HistoryPurpose::CancellationMarkers) {
            result->members.push_back(m);
            result->marker_xids[key] = retired ? retired_at.at(key) : result->xid;
            continue;
        }
        HANDLE h = INVALID_HANDLE_VALUE;
        const auto supplied_fence = std::find_if(borrowed.begin(), borrowed.end(), [&](const auto& w) { return Key(w.path) == Key(m.wal); });
        if (supplied_fence != borrowed.end()) h = supplied_fence->handle;
        else {
            if (media) (void)AcquireVolumeKeeperPhysicalWalLeases(m.wal, *media, m.container_uuid, m.oid, result->leases, "KeeperHistory");
            else (void)AcquireVolumeKeeperWalLeases(m.wal, m.container_uuid, m.oid, result->leases, "KeeperHistory");
            auto file = std::make_unique<File>(); file->Open(m.wal); h = file->h; result->files.push_back(std::move(file));
        }
        const auto file_id = FileIdentity(h, m.wal); const auto bytes = Read(h, WalLimit); const auto digest = Hash(bytes);
        Need(file_id != identity.substr(0, 48) && file_ids.insert(file_id).second, "WalFileAlias");
        const auto marks = Clean(m, result->xid, media);
        if (proofs.contains(key)) for (const auto& p : proofs.at(key)) {
            Need(p.file_id == file_id, "WalReplaced");
            Need(marks.cleanup_sequence >= p.cleanup, "WalHistoryRegressed");
        }
        if (retired) {
            const auto& p = proofs.at(key).back();
            Need(p.digest == digest && p.cleanup == marks.cleanup_sequence, "RetiredWalChanged");
        }
        const bool certified_empty = bytes.empty() && proofs.contains(key) &&
            std::any_of(proofs.at(key).begin(), proofs.at(key).end(), [&](const auto& p) {
                return p.file_id == file_id && p.cleanup == 0 && p.digest == digest;
            });
        if (!destinations.contains(key) && !certified_empty) required_marker_members.insert(key);
        result->members.push_back(m);
        result->marker_xids[key] = retired ? retired_at.at(key) : result->xid;
    }
    if (!context.recovery_root.empty()) {
        hold_directory(context.spool_root); hold_directory(context.recovery_root);
        std::set<std::string> source_containers;
        for (const auto& [_, member] : members) source_containers.insert(member.container_uuid);
        for (const auto& b : cancelled_destinations) for (const auto& m : b.before) source_containers.insert(m.container_uuid);
        std::map<std::wstring, WalProof> reserved;
        if (purpose == HistoryPurpose::Continuation) for (const auto& b : cancelled_destinations) {
            Need(!b.before.empty() && b.pre_xid <= result->xid, "CancelledReservationBindingInvalid");
            const auto& m = b.before.back(); const auto key = Key(m.wal);
            if (paths.contains(key)) continue;
            Need(key == Key(CanonicalWal(context, m, media)), "CancelledReservationPathMismatch");
            const auto attributes = GetFileAttributesW(Extended(m.wal).c_str());
            if (attributes == INVALID_FILE_ATTRIBUTES) {
                Need(GetLastError() == ERROR_FILE_NOT_FOUND || GetLastError() == ERROR_PATH_NOT_FOUND, "CancelledReservationUnavailable");
                continue;
            }
            // Only the original certificate can discharge an unused reservation.
            // The namespace witness never supplies file identity or cleanliness.
            const auto proof_path = ProofPath(b);
            if (GetFileAttributesW(Extended(proof_path).c_str()) == INVALID_FILE_ATTRIBUTES) {
                Need(GetLastError() == ERROR_FILE_NOT_FOUND, "CancelledReservationProofUnavailable");
                continue;
            }
            auto proof_file = std::make_unique<File>(); proof_file->Open(proof_path);
            const auto proof = DecodeProof(Read(proof_file->h, ProofLimit), b).at(MemberKey(m));
            Need(proof.cleanup == 0 && proof.digest == Hash({}), "CancelledReservationNotEmpty");
            result->files.push_back(std::move(proof_file));
            if (reserved.contains(key)) {
                const auto& prior = reserved.at(key);
                Need(prior.file_id == proof.file_id && prior.digest == proof.digest && prior.cleanup == proof.cleanup,
                    "CancelledReservationIdentityChanged"); continue;
            }
            const auto ids = media ? AcquireVolumeKeeperPhysicalWalLeases(m.wal, *media, m.container_uuid, m.oid, result->leases, "KeeperHistory") :
                AcquireVolumeKeeperWalLeases(m.wal, m.container_uuid, m.oid, result->leases, "KeeperHistory");
            auto file = std::make_unique<File>(); file->Open(m.wal);
            const auto id = FileIdentity(file->h, m.wal);
            Need(id == proof.file_id && id != identity.substr(0, 48) && file_ids.insert(id).second && file->Empty(),
                "CancelledReservationOriginalChanged");
            const auto marks = InspectVolumeKeeperWal(m.wal, ids, "KeeperHistory", "CancelledReservationDebt");
            Need(marks.accepted_sequence == 0 && marks.apfs_durable_sequence == 0 && marks.cleanup_sequence == 0,
                "CancelledReservationDebt");
            result->files.push_back(std::move(file)); reserved.emplace(key, proof);
        }
        const auto foreign_namespace = [&](std::string_view suffix) {
            const auto path = NamespacePath(root, suffix);
            if (GetFileAttributesW(Extended(path).c_str()) == INVALID_FILE_ATTRIBUTES) {
                Need(GetLastError() == ERROR_FILE_NOT_FOUND, "NamespaceWitnessUnavailable"); return false;
            }
            auto file = std::make_unique<File>(); file->Open(path);
            const auto scope = DecodeNamespace(Read(file->h, 42));
            Need(scope.suffix == suffix, "NamespaceWitnessHashMismatch");
            bool other_partition = false;
            if (media && scope.material[0] == std::byte{1}) {
                const auto selected = BuildVolumeKeeperNamespaceMaterial(live.front().container_uuid, live.front().oid, media);
                other_partition = !std::equal(scope.material.begin() + 1, scope.material.begin() + 17, selected.begin() + 1);
            }
            const bool foreign = other_partition || !source_containers.contains(scope.container);
            result->files.push_back(std::move(file)); return foreign;
        };
        std::map<std::wstring, std::uint64_t> markers;
        std::set<std::wstring> required_markers, seen_markers;
        for (const auto& m : result->members) {
            Need(Key(m.wal) == Key(CanonicalWal(context, m, media)), "ProductionWalPathMismatch");
            const auto id = media ? DeriveVolumePhysicalRecoveryIdentity(*media, m.container_uuid, m.oid) :
                DerivePartitionlessVolumeRecoveryIdentity(m.container_uuid, m.oid);
            const auto key = MemberKey(m);
            const auto marker = Key(context.recovery_root / ("apfs_recovery_v1_" + id.substr(17) + "_Native.state"));
            markers.emplace(marker, result->marker_xids.at(key));
            if (required_marker_members.contains(key)) required_markers.insert(marker);
        }
        if (purpose == HistoryPurpose::Continuation) for (const auto& directory : std::filesystem::directory_iterator(Local(context.spool_root))) {
            Need(++count <= 1024, "StorageLimit");
            const auto flags = GetFileAttributesW(directory.path().c_str());
            Need(flags != INVALID_FILE_ATTRIBUTES && (flags & FILE_ATTRIBUTE_DIRECTORY) && !(flags & FILE_ATTRIBUTE_REPARSE_POINT), "SpoolAliasOrLegacyEvidence");
            hold_directory(directory.path());
            const auto wal = Key(directory.path() / "write-ahead.wal");
            const bool known = paths.contains(wal) || reserved.contains(wal);
            if (!known && !std::filesystem::is_empty(directory.path())) {
                const auto entry_name = directory.path().filename().string();
                constexpr std::string_view prefix = "apfs_recovery_v1_";
                Need(entry_name.starts_with(prefix) && foreign_namespace(std::string_view(entry_name).substr(prefix.size())), "UnknownSpoolEvidence");
                continue;
            }
            for (const auto& entry : std::filesystem::directory_iterator(directory.path())) {
                Need(++count <= 1024, "StorageLimit");
                if (paths.contains(Key(entry.path())) || reserved.contains(Key(entry.path()))) continue;
                const auto entry_name = entry.path().filename().string();
                Need(known && paths.contains(wal) && (entry_name == "payload-spool.bin" || entry_name == "payload-spool.idx"), "UnknownSpoolEvidence");
                auto file = std::make_unique<File>(); file->Open(entry.path());
                const auto id = FileIdentity(file->h, entry.path());
                Need(id != identity.substr(0, 48) && file_ids.insert(id).second && file->Empty(), "PayloadSpoolUnsettled");
                result->files.push_back(std::move(file));
            }
        }
        bool retained_legacy_terminal = false;
        for (const auto& entry : std::filesystem::directory_iterator(Local(context.recovery_root))) {
            Need(++count <= 1024, "StorageLimit");
            const auto flags = GetFileAttributesW(Extended(entry.path()).c_str());
            Need(flags != INVALID_FILE_ATTRIBUTES && !(flags & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)), "MarkerAliasOrUnavailable");
            if (!markers.contains(Key(entry.path()))) {
                if (LegacyPhysicalMarkerName(entry.path().filename().wstring())) {
                    auto file = std::make_unique<File>(); file->Open(entry.path());
                    (void)StrictCleanMarker(Read(file->h, 43));
                    // This fenced terminal has no proved owner. It changes no
                    // member, WAL, checkpoint, or retirement evidence.
                    result->files.push_back(std::move(file)); retained_legacy_terminal = true;
                    continue;
                }
                const auto entry_name = entry.path().filename().string();
                constexpr std::string_view prefix = "apfs_recovery_v1_", ending = "_Native.state";
                Need(entry_name.starts_with(prefix) && entry_name.ends_with(ending) && entry_name.size() > prefix.size() + ending.size() &&
                    foreign_namespace(std::string_view(entry_name).substr(prefix.size(), entry_name.size() - prefix.size() - ending.size())), "MarkerIdentityUnproved");
                continue;
            }
            auto file = std::make_unique<File>(); file->Open(entry.path());
            Need(StrictCleanMarker(Read(file->h, 43)) <= markers.at(Key(entry.path())), "MarkerCheckpointUnproved");
            seen_markers.insert(Key(entry.path())); result->files.push_back(std::move(file));
        }
        if (retained_legacy_terminal && purpose == HistoryPurpose::Continuation)
            for (const auto& marker : required_markers) Need(seen_markers.contains(marker), "CurrentMarkerMissingWithLegacyTerminal");
        if (retained_legacy_terminal && purpose == HistoryPurpose::CancellationMarkers) {
            // The public wrapper exposes only a cancellation fence. It can
            // close this unaccepted intent, never publish or clean WAL debt.
            const auto b = DecodeVolumeKeeperHistoryBinding(held_bytes, held_journal, root, identity);
            Need(b.state == VolumeKeeperJournalState::Prepared || b.state == VolumeKeeperJournalState::Cancelled,
                "LegacyTerminalRequiresUnacceptedCancellation");
        }
    }
    Need(!physical || physical->Revalidate(), "PhysicalHeldSourceChanged");
    Need(!geometry || geometry->Revalidate(),"GeometryHeldSourceChanged");
    return std::make_unique<VolumeKeeperHistoryLease>(std::move(result));
}
}

std::unique_ptr<VolumeKeeperHistoryLease> AcquireVolumeKeeperHistory(std::string_view identity,
    std::span<const std::byte> current, const std::filesystem::path& root,
    const std::vector<VolumeKeeperHistoryMember>& supplied, const std::vector<VolumeKeeperHeldWal>& borrowed,
    const std::filesystem::path& held_journal, std::span<const std::byte> held_bytes,
    const VolumeKeeperHistoryContext& context, bool require_terminal, bool detached_observation)
{
    Need(current.size() <= 256ull * 1024 * 1024, "HeldSourceRequired");
    catalog::VectorRandomAccessSource source(Bytes(current.begin(), current.end()));
    return AcquireHistory(identity, source, root, supplied, borrowed, held_journal, held_bytes, context,
        require_terminal, detached_observation, HistoryPurpose::Continuation);
}

std::unique_ptr<VolumeKeeperHistoryLease> AcquireVolumeKeeperHistory(std::string_view identity,
    const catalog::RandomAccessSource& source, const std::filesystem::path& root,
    const std::vector<VolumeKeeperHistoryMember>& supplied, const std::vector<VolumeKeeperHeldWal>& borrowed,
    const std::filesystem::path& held_journal, std::span<const std::byte> held_bytes,
    const VolumeKeeperHistoryContext& context, bool require_terminal, bool detached_observation)
{
    return AcquireHistory(identity, source, root, supplied, borrowed, held_journal, held_bytes, context,
        require_terminal, detached_observation, HistoryPurpose::Continuation);
}

std::unique_ptr<VolumeKeeperCancellationFence> AcquireVolumeKeeperCancellationMarkers(std::string_view identity,
    std::span<const std::byte> current, const std::filesystem::path& journal, std::span<const std::byte> frame,
    const VolumeKeeperHistoryContext& context)
{
    Need(current.size() <= 256ull * 1024 * 1024, "HeldSourceRequired");
    catalog::VectorRandomAccessSource source(Bytes(current.begin(), current.end()));
    return AcquireVolumeKeeperCancellationMarkers(identity, source, journal, frame, context);
}

std::unique_ptr<VolumeKeeperCancellationFence> AcquireVolumeKeeperCancellationMarkers(std::string_view identity,
    const catalog::RandomAccessSource& current, const std::filesystem::path& journal, std::span<const std::byte> frame,
    const VolumeKeeperHistoryContext& context)
{
    const auto binding = DecodeVolumeKeeperHistoryBinding(frame, journal, journal.parent_path(), identity);
    Need(binding.state == VolumeKeeperJournalState::Prepared || binding.state == VolumeKeeperJournalState::Cancelled,
        "UnacceptedJournalRequired");
    auto members = binding.before;
    if (binding.image_family && binding.operation >= 3) members.pop_back();
    return std::make_unique<VolumeKeeperCancellationFence>(AcquireHistory(identity, current, journal.parent_path(),
        members, {}, journal, frame, context, false, false, HistoryPurpose::CancellationMarkers));
}

std::unique_ptr<VolumeKeeperHistoryLease> AcquireVolumeKeeperPhysicalHistory(
    const std::shared_ptr<VolumePhysicalSource>& physical, const catalog::RandomAccessSource& current,
    const std::filesystem::path& root, const std::vector<VolumeKeeperHistoryMember>& members,
    const std::vector<VolumeKeeperHeldWal>& borrowed, const std::filesystem::path& journal,
    std::span<const std::byte> frame, const VolumeKeeperHistoryContext& context, bool terminal)
{
    Need(!!physical, "PhysicalHeldSourceRequired");
    return AcquireHistory(physical->Identity(), current, root, members, borrowed, journal, frame, context,
        terminal, false, HistoryPurpose::Continuation, physical);
}

std::unique_ptr<VolumeKeeperCancellationFence> AcquireVolumeKeeperPhysicalCancellationMarkers(
    const std::shared_ptr<VolumePhysicalSource>& physical, const catalog::RandomAccessSource& current,
    const std::filesystem::path& journal, std::span<const std::byte> frame, const VolumeKeeperHistoryContext& context)
{
    Need(!!physical, "PhysicalHeldSourceRequired"); ValidateVolumeKeeperPhysicalFrame(frame, *physical);
    const auto binding = DecodeVolumeKeeperHistoryBinding(frame, journal, journal.parent_path(), physical->Identity());
    Need(binding.state == VolumeKeeperJournalState::Prepared || binding.state == VolumeKeeperJournalState::Cancelled,
        "UnacceptedJournalRequired");
    auto members = binding.before;
    const bool management = volume_physical::IsManagementMagic(catalog::ReadU64LE(frame, 0).value_or(0));
    Need(!members.empty() && (management || binding.image_family && binding.operation >= 3), "PhysicalKeeperProfileRequired");
    if (!management || binding.operation == 1) members.pop_back();
    return std::make_unique<VolumeKeeperCancellationFence>(AcquireHistory(physical->Identity(), current, journal.parent_path(),
        members, {}, journal, frame, context, false, false, HistoryPurpose::CancellationMarkers, physical));
}

std::unique_ptr<VolumeKeeperHistoryLease> AcquireVolumeKeeperGeometryHistory(
    const std::shared_ptr<VolumePhysicalGeometrySource>& source,const catalog::RandomAccessSource& current,
    const std::filesystem::path& root,const std::vector<VolumeKeeperHistoryMember>& members,
    const std::vector<VolumeKeeperHeldWal>& borrowed,const std::filesystem::path& journal,std::span<const std::byte> frame,
    const VolumeKeeperHistoryContext& context,bool terminal)
{
    Need(!!source,"GeometryHeldSourceRequired");
    return AcquireHistory(VolumePhysicalIdentity(source->OriginalBinding(),source->InstanceId()),current,root,members,borrowed,
        journal,frame,context,terminal,false,HistoryPurpose::Continuation,{},source);
}
std::unique_ptr<VolumeKeeperCancellationFence> AcquireVolumeKeeperGeometryCancellationMarkers(
    const std::shared_ptr<VolumePhysicalGeometrySource>& source,const catalog::RandomAccessSource& current,
    const std::filesystem::path& journal,std::span<const std::byte> frame,const VolumeKeeperHistoryContext& context)
{
    Need(!!source,"GeometryHeldSourceRequired");const auto identity=VolumePhysicalIdentity(source->OriginalBinding(),source->InstanceId());
    const auto binding=DecodeVolumeKeeperHistoryBinding(frame,journal,journal.parent_path(),identity);
    Need(binding.image_family && binding.operation<=2 && (binding.state==VolumeKeeperJournalState::Prepared ||
        binding.state==VolumeKeeperJournalState::Cancelled),"UnacceptedGeometryJournalRequired");
    return std::make_unique<VolumeKeeperCancellationFence>(AcquireHistory(identity,current,journal.parent_path(),binding.before,{},
        journal,frame,context,false,false,HistoryPurpose::CancellationMarkers,{},source));
}
std::string ObserveVolumeKeeperHistoryJson(const std::filesystem::path& image, const std::filesystem::path& root,
    const VolumeKeeperHistoryContext& context, bool& admitted)
{
    const auto quote = [](std::string_view s) {
        std::string out = "\""; constexpr char digits[] = "0123456789abcdef";
        for (unsigned char c : s) {
            if (c == '"' || c == '\\') { out += '\\'; out += char(c); }
            else if (c < 32) { out += "\\u00"; out += digits[c >> 4]; out += digits[c & 15]; }
            else out += char(c);
        }
        return out + '"';
    };
    const auto utf8 = [](const std::filesystem::path& p) {
        const auto s = p.wstring(); const auto n = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()), nullptr, 0, nullptr, nullptr);
        Need(n > 0, "PathUnicodeInvalid"); std::string out(n, ' ');
        Need(WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()), out.data(), n, nullptr, nullptr) == n, "PathUnicodeInvalid"); return out;
    };
    admitted = false; std::string identity, error; std::uint64_t xid = 0; std::string members = "[]";
    try {
        auto source = BlockDevice::OpenExclusiveManagementImage(Local(image).wstring(), 0, error);
        Need(!!source && source->QueryRegularImageIdentity(identity), "ObservationSourceUnavailable:" + error);
        class HeldSource final : public catalog::RandomAccessSource {
        public:
            explicit HeldSource(const BlockDevice& device) : device_(device) {}
            std::uint64_t SizeBytes() const override { return device_.GetGeometry().total_bytes; }
            bool Read(std::uint64_t offset, std::size_t size, Bytes& out) const override { return device_.Read(offset, size, out); }
        private:
            const BlockDevice& device_;
        } current(*source);
        auto lease = AcquireVolumeKeeperHistory(identity, current, root, {}, {}, {}, {}, context, false, true);
        xid = lease->CheckpointXid(); members = "[";
        bool first = true;
        for (const auto& m : lease->Members()) {
            if (!first) members += ','; first = false;
            members += "{\"containerUuid\":" + quote(m.container_uuid) + ",\"volumeUuid\":" + quote(m.volume_uuid) +
                ",\"oid\":" + quote(std::to_string(m.oid)) + ",\"path\":" + quote(utf8(m.wal)) +
                ",\"markerCheckpointXid\":" + quote(std::to_string(lease->MarkerCheckpointXid(m))) + "}";
        }
        members += ']'; admitted = true; error.clear();
    } catch (const std::exception& ex) { error = ex.what(); }
    return "{\"schemaVersion\":1,\"operation\":\"volume-history-observe\",\"admitted\":" + std::string(admitted ? "true" : "false") +
        ",\"error\":" + quote(error) + ",\"sourceIdentity\":" + quote(identity) + ",\"checkpointXid\":" + quote(std::to_string(xid)) +
        ",\"members\":" + members + "}";
}
}
