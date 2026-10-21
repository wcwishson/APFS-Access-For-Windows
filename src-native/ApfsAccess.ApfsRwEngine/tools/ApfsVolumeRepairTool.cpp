// Offline bounded RCT2 (APSB regular-file count) repair tool. See
// ApfsVolumeRepairTool.h for the contract. Drives the production
// Prepare/Apply/Replay engine APIs around one ordinary single-store image
// with an exclusive writable lease, exactly like the in-engine gates do,
// then proves the result with an independent file-level verification.
// Fusion/encrypted/whole-volume/payload-hash shapes refuse before any
// handle that could mutate is used for planning.
#include "ApfsVolumeRepairTool.h"

#ifndef APFS_VOLUME_REPAIR_TOOL_TESTING
#endif

#include "ApfsContainerCatalog.h"
#include "ApfsFormat.h"
#include "ApfsRepair.h"
#include "ApfsVerifier.h"
#include "ContainerMountCoordinator.h"
#include "TransactionManager.h"
#include <bcrypt.h>

#include <algorithm>
#include <array>
#include <charconv>
#include <climits>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <set>
#include <utility>

namespace
{
namespace fsys = std::filesystem;
using apfsaccess::catalog::ApfsContainerCatalog;
using apfsaccess::catalog::ApfsVerifier;
using apfsaccess::catalog::CatalogLoadPolicy;
using apfsaccess::catalog::ResolvedMountVolume;
using apfsaccess::catalog::VerificationOutcome;
using apfsaccess::catalog::VerificationReport;
using apfsaccess::catalog::VerificationScope;
using apfsaccess::rw::ApfsCountRepairPlan;
using Owner = apfsaccess::catalog::ContainerMountCoordinator;
using Tx = apfsaccess::rw::TransactionManager;

constexpr std::uint64_t kMaxRepairImageBytes = 256ULL * 1024 * 1024;

bool RepairTextIsUtf8(std::string_view text)
{
    return apfsaccess::catalog::IsValidUtf8(reinterpret_cast<const std::byte*>(text.data()), text.size());
}

fsys::path RepairUtf8Path(std::string_view text)
{
    if (text.find('\0') != std::string_view::npos || !RepairTextIsUtf8(text))
        throw ToolArgumentError("repair paths require valid UTF-8 without NUL");
    return fsys::u8path(text.begin(), text.end());
}

std::string RepairPathUtf8(const fsys::path& path)
{
    const auto text = path.u8string();
    return {reinterpret_cast<const char*>(text.data()), text.size()};
}

void ValidateRepairPaths(const VolumeRepairToolOptions& options)
{
    for (const auto* path : {&options.image, &options.journal_path, &options.evidence_dir, &options.out_path})
        (void)RepairUtf8Path(*path);
}

#if defined(_WIN32)
std::string RepairArgumentUtf8(std::wstring_view text)
{
    if (text.empty()) return {};
    if (text.size() > static_cast<std::size_t>(INT_MAX) || text.find(L'\0') != std::wstring_view::npos)
        throw ToolArgumentError("invalid UTF-16 argument");
    const auto count = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()),
        nullptr, 0, nullptr, nullptr);
    if (!count) throw ToolArgumentError("invalid UTF-16 argument");
    std::string result(static_cast<std::size_t>(count), '\0');
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()),
        result.data(), count, nullptr, nullptr) != count) throw ToolArgumentError("invalid UTF-16 argument");
    return result;
}
#endif

class ExclusiveReportFile
{
    HANDLE handle_ = INVALID_HANDLE_VALUE;
public:
    ~ExclusiveReportFile() { if (handle_ != INVALID_HANDLE_VALUE) CloseHandle(handle_); }
    ExclusiveReportFile() = default;
    ExclusiveReportFile(const ExclusiveReportFile&) = delete;
    ExclusiveReportFile& operator=(const ExclusiveReportFile&) = delete;

    bool Open(const VolumeRepairToolOptions& options, std::string& error)
    {
        if (options.out_path.empty()) return true;
        std::string flat = options.out_path;
        std::replace(flat.begin(), flat.end(), '\\', '/');
        const auto colon = flat.find(':');
        if (flat.starts_with("//") || flat.starts_with("/??/") ||
            (colon != std::string::npos && (colon != 1 ||
                !((flat[0] >= 'a' && flat[0] <= 'z') || (flat[0] >= 'A' && flat[0] <= 'Z')) ||
                flat.find(':', colon + 1) != std::string::npos)))
        { error = "report output must be an ordinary local file"; return false; }
        std::error_code ec;
        const auto path = fsys::absolute(RepairUtf8Path(options.out_path), ec).lexically_normal();
        if (ec) { error = "cannot resolve report output"; return false; }
        const auto journal = fsys::absolute(RepairUtf8Path(options.journal_path), ec).lexically_normal();
        if (ec || _wcsicmp(path.c_str(), journal.c_str()) == 0)
        { error = "report output must differ from the repair journal"; return false; }
        fsys::create_directories(path.parent_path(), ec);
        if (ec) { error = "cannot create report output directory"; return false; }
        // Reserve the new file before repair. CREATE_NEW also rejects hard-link
        // and reparse aliases; keep this handle so later writes cannot retarget.
        handle_ = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        if (handle_ == INVALID_HANDLE_VALUE)
        { error = "report output already exists or cannot be created exclusively"; return false; }
        if (GetFileType(handle_) != FILE_TYPE_DISK)
        { error = "report output is not a regular disk file"; return false; }
        return true;
    }

    void Write(const std::string& json)
    {
        if (handle_ == INVALID_HANDLE_VALUE) return;
        const auto bytes = json + "\n";
        std::size_t offset = 0;
        while (offset < bytes.size())
        {
            const auto count = static_cast<DWORD>((std::min)(bytes.size() - offset,
                static_cast<std::size_t>(MAXDWORD)));
            DWORD written = 0;
            if (!WriteFile(handle_, bytes.data() + offset, count, &written, nullptr) || !written)
                throw std::runtime_error("report write failed; operation result: " + json);
            offset += written;
        }
        if (!FlushFileBuffers(handle_))
            throw std::runtime_error("report flush failed; operation result: " + json);
    }
};

[[noreturn]] void FailOptions(const std::string& message) { throw ToolArgumentError(message); }

void JsonEscape(std::string& out, const std::string& value)
{
    const bool utf8 = RepairTextIsUtf8(value);
    for (const char ch : value)
    {
        switch (ch)
        {
        case '"': out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default:
            // Unknown diagnostic encodings are escaped as bytes, never emitted
            // as malformed UTF-8 or guessed through the active ANSI code page.
            if (static_cast<unsigned char>(ch) < 0x20 || (!utf8 && static_cast<unsigned char>(ch) >= 0x80))
            {
                char hex[7];
                std::snprintf(hex, sizeof(hex), "\\u%04x", static_cast<unsigned char>(ch));
                out += hex;
            }
            else out += ch;
        }
    }
}

std::uint64_t ExactDecimal(const std::string& value, const char* flag)
{
    std::uint64_t number = 0;
    const auto parsed = std::from_chars(value.data(), value.data() + value.size(), number);
    if (parsed.ec != std::errc{} || parsed.ptr != value.data() + value.size() ||
        !number || value != std::to_string(number))
        FailOptions(std::string(flag) + " must be a canonical decimal uint64 greater than zero");
    return number;
}

std::uint64_t ExactDecimalAllowZero(const std::string& value, const char* flag)
{
    std::uint64_t number = 0;
    const auto parsed = std::from_chars(value.data(), value.data() + value.size(), number);
    if (parsed.ec != std::errc{} || parsed.ptr != value.data() + value.size() ||
        value != std::to_string(number))
        FailOptions(std::string(flag) + " must be a canonical decimal uint64");
    return number;
}

void RequireHex32(const std::string& value, const char* flag)
{
    if (value.size() != 32 || value.find_first_not_of("0123456789abcdef") != std::string::npos ||
        value == std::string(32, '0'))
        FailOptions(std::string(flag) + " must be a nonzero lowercase 32-digit hex UUID");
}

void ValidateSourceApprovalOptions(const VolumeRepairToolOptions& options)
{
    const bool supplied = !options.approved_source_identity.empty() || !options.approved_source_sha256.empty();
    if (!options.exact_source_approval && supplied)
        FailOptions("source approval requires --approval-mode exact-source-v1");
    if (!options.exact_source_approval) return;
    if (!options.confirm)
    {
        if (supplied || options.expected_count != 0)
            FailOptions("source approval and expected count require --confirm");
        return;
    }
    const auto& identity = options.approved_source_identity;
    constexpr std::string_view prefix = "windows-image-v1:";
    if (!identity.starts_with(prefix) || identity.size() <= prefix.size() + 81 ||
        identity.substr(prefix.size(), 80).find_first_not_of("0123456789abcdef") != std::string::npos ||
        identity[prefix.size() + 80] != ':')
        FailOptions("confirmation requires a canonical approved source identity");
    ExactDecimalAllowZero(identity.substr(prefix.size() + 81), "approved source creation time");
    if (options.approved_source_sha256.size() != 64 ||
        options.approved_source_sha256.find_first_not_of("0123456789abcdef") != std::string::npos)
        FailOptions("confirmation requires a lowercase 64-digit approved source SHA-256");
}

struct RepairSourceBinding
{
    std::string identity, sha256;
};

std::string RepairImageSha256(const std::vector<std::byte>& bytes)
{
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    std::array<unsigned char, 32> digest{};
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0)
        throw std::runtime_error("repair SHA-256 provider failed");
    const auto status = BCryptHash(algorithm, nullptr, 0,
        reinterpret_cast<PUCHAR>(const_cast<std::byte*>(bytes.data())), static_cast<ULONG>(bytes.size()),
        digest.data(), static_cast<ULONG>(digest.size()));
    BCryptCloseAlgorithmProvider(algorithm, 0);
    if (status < 0) throw std::runtime_error("repair SHA-256 failed");
    std::string result;
    for (const auto byte : digest)
    {
        result += "0123456789abcdef"[byte >> 4];
        result += "0123456789abcdef"[byte & 15];
    }
    return result;
}

bool ReadHeldRepairImage(const apfsaccess::rw::BlockDevice& device, std::vector<std::byte>& bytes,
    RepairSourceBinding& binding, std::string& error)
{
    bytes.clear(); binding = {};
    apfsaccess::rw::BlockDevice::StableImageIdentity before{}, after{};
    std::string identity;
    if (!device.QueryHeldImageIdentity(before) || !device.QueryRegularImageIdentity(identity) ||
        !before.size_bytes || before.size_bytes > kMaxRepairImageBytes ||
        device.BaseOffsetBytes() != 0 || device.GetGeometry().total_bytes != before.size_bytes)
    { error = "repair requires an exact ordinary image of at most 256MiB"; return false; }
    // Bypass BlockDevice's read cache. These exact leased bytes, including
    // payload and unused regions, are the public approval preimage.
    if (!device.ReadForVerification(0, static_cast<std::size_t>(before.size_bytes), bytes) ||
        bytes.size() != before.size_bytes || !device.QueryHeldImageIdentity(after) || before != after)
    { bytes.clear(); error = "repair held preimage read or identity changed"; return false; }
    binding.identity = "windows-image-v1:" + identity + ":" + std::to_string(before.creation_time);
    binding.sha256 = RepairImageSha256(bytes);
    return true;
}

void RequireOrdinaryInputFile(const std::string& path, const char* what)
{
    if (path.empty()) FailOptions(std::string(what) + " path is required");
    std::string flat = path;
    std::replace(flat.begin(), flat.end(), '\\', '/');
    if (flat.starts_with("//./") || flat.starts_with("//?/") || flat.starts_with("/??/"))
        FailOptions(std::string(what) + " cannot use a device namespace");
    const auto colon = flat.find(':');
    if (colon != std::string::npos && (colon != 1 ||
        !((flat[0] >= 'a' && flat[0] <= 'z') || (flat[0] >= 'A' && flat[0] <= 'Z')) ||
        flat.find(':', colon + 1) != std::string::npos))
        FailOptions(std::string(what) + " cannot use an alternate data stream");
    std::error_code ec;
    if (!fsys::is_regular_file(RepairUtf8Path(path), ec) || ec)
        FailOptions(std::string(what) + " must be a regular file");
}

std::vector<std::byte> ReadBoundedRepairBytes(std::istream& input, std::uint64_t size, std::string& error)
{
    error.clear();
    if (size > kMaxRepairImageBytes)
    { error = "repair image exceeds the 256MiB offline bound"; return {}; }
    std::vector<std::byte> bytes(static_cast<std::size_t>(size));
    std::size_t offset = 0;
    while (offset < bytes.size())
    {
        const auto count = (std::min)(bytes.size() - offset, std::size_t{65536});
        input.read(reinterpret_cast<char*>(bytes.data() + offset), static_cast<std::streamsize>(count));
        if (input.gcount() != static_cast<std::streamsize>(count))
        { error = "repair image changed or could not be read completely"; return {}; }
        offset += count;
    }
    char extra;
    if (input.get(extra) || !input.eof())
    { error = "repair image grew or could not be read completely"; return {}; }
    return bytes;
}

std::vector<std::byte> ReadAllBytes(const std::string& path, std::string& error)
{
    std::ifstream in(RepairUtf8Path(path), std::ios::binary);
    if (!in) { error = "cannot open input for reading"; return {}; }
    in.seekg(0, std::ios::end);
    const auto size = in.tellg();
    if (size < 0) { error = "cannot determine repair input size"; return {}; }
    in.seekg(0);
    if (!in) { error = "cannot seek repair input"; return {}; }
    return ReadBoundedRepairBytes(in, static_cast<std::uint64_t>(size), error);
}

class VectorSource final : public apfsaccess::catalog::RandomAccessSource
{
public:
    explicit VectorSource(const std::vector<std::byte>& bytes) : bytes_(bytes) {}
    std::uint64_t SizeBytes() const override { return bytes_.size(); }
    bool Read(std::uint64_t offset, std::size_t size, std::vector<std::byte>& out) const override
    {
        out.clear();
        if (offset > bytes_.size() || size > bytes_.size() - offset) return false;
        out.assign(bytes_.begin() + offset, bytes_.begin() + offset + size);
        return true;
    }

private:
    const std::vector<std::byte>& bytes_;
};

std::wstring AsciiWiden(const std::string& narrow)
{
    for (const char ch : narrow)
        if (static_cast<unsigned char>(ch) > 0x7F) return L"";
    return std::wstring(narrow.begin(), narrow.end());
}

struct LiveIdentities
{
    std::string container_uuid;
    std::string volume_uuid;
    std::uint64_t checkpoint_xid = 0;
};

bool ResolveLiveIdentities(const std::vector<std::byte>& image, const VolumeRepairToolOptions& options,
    LiveIdentities& out, std::vector<std::uint64_t>& out_volume_oids, std::string& error)
{
    VectorSource source(image);
    ApfsContainerCatalog catalog;
    if (!ApfsContainerCatalog::TryLoadImage(source, "repair-tool", options.image,
            catalog, error, CatalogLoadPolicy::StrictApple))
    {
        error = "repair catalog failed: " + error;
        return false;
    }
    const apfsaccess::catalog::ApfsContainerDescriptor* container = nullptr;
    for (const auto& item : catalog.Containers())
    {
        if (item.container_uuid_hex != options.container_uuid) continue;
        if (container)
        {
            error = "ambiguous repair container";
            return false;
        }
        container = &item;
    }
    if (!container)
    {
        error = "repair container not found";
        return false;
    }
    if (container->fusion || container->member_store_ids.size() != 1)
    {
        error = "repair requires an exact single-store container: FusionUnsupported";
        return false;
    }
    ResolvedMountVolume selected;
    if (!catalog.TryResolveVolume(options.container_uuid, options.volume_oid, selected, error))
    {
        error = "repair volume selection failed: " + error;
        return false;
    }
    out.container_uuid = container->container_uuid_hex;
    out.volume_uuid = selected.volume_uuid_hex;
    for (const auto& volume : container->volumes)
    {
        if (volume.object_id == options.volume_oid && !volume.volume_uuid_hex.empty())
        {
            out.volume_uuid = volume.volume_uuid_hex;
            break;
        }
    }
    std::string view_error;
    const auto view = apfsaccess::catalog::LoadAppleCheckpointView(
        source, 0, source.SizeBytes(), view_error);
    if (!view)
    {
        error = "repair checkpoint unloadable: " + view_error;
        return false;
    }
    out.checkpoint_xid = view->container.superblock.xid;
    out_volume_oids.clear();
    for (const auto& volume : container->volumes) out_volume_oids.push_back(volume.object_id);
    return true;
}

std::string FindingJson(const apfsaccess::catalog::VerificationFinding& finding)
{
    std::string json = "{";
    json += "\"code\":" + std::to_string(static_cast<unsigned>(finding.code)) + ",";
    json += "\"severity\":" + std::to_string(static_cast<unsigned>(finding.severity)) + ",";
    json += "\"check\":" + std::to_string(static_cast<unsigned>(finding.check)) + ",";
    json += "\"detail\":\"";
    JsonEscape(json, finding.detail);
    json += "\"}";
    return json;
}

std::string ResultJson(const VolumeRepairToolOptions& options, const RepairSourceBinding& source,
    int exit_code, const std::string& code,
    const std::string& error, const std::vector<std::byte>& preimage,
    const apfsaccess::catalog::VerificationFinding* finding, bool finding_present,
    std::uint64_t expected_count, bool has_plan, bool applied, bool replayed,
    const VerificationReport* post_verify, const std::string& journal_path,
    const std::string& backup_path, bool bytes_unchanged_known, bool bytes_unchanged)
{
    std::string json = "{\"format\":\"apfs-access-repair\",\"version\":" +
        std::string(options.exact_source_approval ? "2," : "1,");
    json += "\"command\":\"repair\",\"success\":" + std::string(exit_code == 0 ? "true" : "false") + ",";
    json += "\"exitCode\":" + std::to_string(exit_code) + ",\"code\":\"";
    JsonEscape(json, code);
    json += "\",\"error\":";
    if (error.empty()) json += "null";
    else { json += "\""; JsonEscape(json, error); json += "\""; }
    json += ",\"image\":{\"path\":\"";
    JsonEscape(json, options.image);
    json += "\",\"sizeBytes\":" + std::to_string(preimage.size()) + "},";
    json += "\"scope\":{\"containerUuid\":\"";
    JsonEscape(json, options.container_uuid);
    json += "\",\"volumeUuid\":\"";
    JsonEscape(json, options.volume_uuid);
    json += "\",\"volumeOid\":" + std::to_string(options.volume_oid) +
        ",\"checkpointXid\":" + std::to_string(options.checkpoint_xid) +
        ",\"storeOffsetBytes\":" + std::to_string(options.store_offset_bytes) +
        ",\"storeSizeBytes\":" + std::to_string(options.store_size_bytes) + "},";
    if (options.exact_source_approval)
    {
        json += "\"source\":";
        if (source.identity.empty()) json += "null,";
        else
        {
            json += "{\"identity\":\""; JsonEscape(json, source.identity);
            json += "\",\"sha256\":\"" + source.sha256 + "\"},";
        }
    }
    json += "\"finding\":";
    json += finding_present && finding ? FindingJson(*finding) : "null";
    json += ",\"plan\":";
    if (has_plan) json += "{\"expectedCount\":" + std::to_string(expected_count) + "}";
    else json += "null";
    json += ",\"applied\":" + std::string(applied ? "true" : "false");
    json += ",\"replayed\":" + std::string(replayed ? "true" : "false");
    json += ",\"postVerify\":";
    if (post_verify)
    {
        json += "{\"outcome\":" +
            std::to_string(static_cast<unsigned>(post_verify->outcome)) + ",\"findings\":" +
            std::to_string(post_verify->findings.size()) + "}";
    }
    else json += "null";
    json += ",\"journal\":\"";
    JsonEscape(json, journal_path);
    json += "\",\"backup\":";
    if (backup_path.empty()) json += "null";
    else { json += "\""; JsonEscape(json, backup_path); json += "\""; }
    json += ",\"bytesUnchanged\":";
    if (!bytes_unchanged_known) json += "null";
    else json += bytes_unchanged ? "true" : "false";
    json += "}";
    return json;
}

bool TestHooksEnabled()
{
    const char* flag = std::getenv("APFS_REPAIR_TEST_HOOKS");
    return flag && std::string(flag) == "1";
}

bool OpenSessionOwner(const std::string& image_path,
    const std::vector<std::uint64_t>& volume_oids, const std::string& container_uuid,
    std::unique_ptr<Owner>& out_owner, std::string& error,
    const std::shared_ptr<apfsaccess::rw::BlockDevice>& held_image = {})
{
    auto owner = held_image ? Owner::OpenRepairImage(held_image, error) :
        Owner::Open(image_path, 0, error, CatalogLoadPolicy::StrictApple, true, true);
    if (!owner)
    {
        error = "repair owner open failed: " + error;
        return false;
    }
    apfsaccess::rw::MetadataStore::VolumeContext context;
    std::vector<apfsaccess::catalog::VolumeCheckpointPins> census;
    for (const auto oid : volume_oids)
    {
        apfsaccess::catalog::ContainerVolumeSession session;
        session.volume_object_id = oid;
        session.container_uuid_hex = container_uuid;
        session.requested_write = true;
        session.use_canonical_transaction = true;
        session.recovery_identity = "apfs-volume-repair-tool-" + std::to_string(oid);
        session.metadata_context = context;
        session.metadata_context.device_path = RepairUtf8Path(image_path).wstring();
        session.metadata_context.volume_object_id = oid;
        session.metadata_context.container_uuid_hex = container_uuid;
        session.metadata_context.allow_legacy_scaffold_for_fixtures = false;
        if (!owner->MountVolume(session, error))
        {
            error = "repair volume mount failed: " + error;
            return false;
        }
        apfsaccess::catalog::VolumeCheckpointPins pins;
        pins.volume_object_id = oid;
        census.push_back(pins);
    }
    if (!owner->InitializeRequiredCheckpointCensus(census, error))
    {
        error = "repair census failed: " + error;
        return false;
    }
    out_owner = std::move(owner);
    return true;
}

bool VerifyImageBytes(const std::vector<std::byte>& image, const VolumeRepairToolOptions& options,
    VerificationReport& out_report, std::string& error)
{
    VectorSource source(image);
    VerificationScope scope;
    scope.source_identity = "repair-tool-verify";
    scope.exact = {options.store_offset_bytes, options.store_size_bytes, options.container_uuid,
        options.volume_uuid, options.volume_oid, options.checkpoint_xid};
    out_report = ApfsVerifier::Verify(source, scope);
    if (out_report.outcome != VerificationOutcome::Complete)
    {
        error = "post-repair verification not complete";
        return false;
    }
    if (!out_report.findings.empty())
    {
        error = "post-repair verification has findings";
        return false;
    }
    return true;
}

std::vector<std::byte> ReadImageBytes(const std::string& path)
{
    std::string ignored;
    return ReadAllBytes(path, ignored);
}
} // namespace

static VolumeRepairToolResult RunVolumeRepairImpl(const VolumeRepairToolOptions& options);

std::string VolumeRepairUsage()
{
    return "usage: ApfsVolumeRepairTool --image <file> --container-uuid <hex32> --volume-uuid <hex32> "
        "--volume-oid <uint64> --checkpoint-xid <uint64> --store-offset-bytes <uint64> --store-size-bytes <uint64> "
        "--journal <new-file> --evidence-dir <dir> [--expected-count <uint64> --confirm] [--out <new-file>] "
        "[--approval-mode exact-source-v1 [--approved-source-identity <identity> --approved-source-sha256 <hex64>]]";
}

VolumeRepairToolOptions ParseVolumeRepairArguments(const std::vector<std::string>& argv)
{
    VolumeRepairToolOptions options;
    bool has_image = false, has_container = false, has_volume_uuid = false, has_oid = false, has_xid = false,
         has_offset = false, has_size = false, has_journal = false, has_evidence = false, has_expected = false;
    std::set<std::string> flags;
    bool duplicate = false;
    for (std::size_t i = 0; i < argv.size(); ++i)
    {
        const auto& arg = argv[i];
        duplicate |= !flags.insert(arg).second;
        auto need_value = [&](const char* flag) -> std::string {
            if (++i >= argv.size() || argv[i].starts_with("--")) FailOptions("missing value");
            if (argv[i].empty() && (std::string_view(flag) == "--approved-source-identity" ||
                std::string_view(flag) == "--approved-source-sha256"))
                FailOptions(std::string(flag) + " must not be empty");
            return argv[i];
        };
        if (arg == "--image") { options.image = need_value("--image"); has_image = true; }
        else if (arg == "--container-uuid") { options.container_uuid = need_value("--container-uuid"); has_container = true; }
        else if (arg == "--volume-uuid") { options.volume_uuid = need_value("--volume-uuid"); has_volume_uuid = true; }
        else if (arg == "--volume-oid") { options.volume_oid = ExactDecimal(need_value("--volume-oid"), "--volume-oid"); has_oid = true; }
        else if (arg == "--checkpoint-xid") { options.checkpoint_xid = ExactDecimal(need_value("--checkpoint-xid"), "--checkpoint-xid"); has_xid = true; }
        else if (arg == "--store-offset-bytes") { options.store_offset_bytes = ExactDecimalAllowZero(need_value("--store-offset-bytes"), "--store-offset-bytes"); has_offset = true; }
        else if (arg == "--store-size-bytes") { options.store_size_bytes = ExactDecimal(need_value("--store-size-bytes"), "--store-size-bytes"); has_size = true; }
        else if (arg == "--expected-count") { options.expected_count = ExactDecimalAllowZero(need_value("--expected-count"), "--expected-count"); has_expected = true; }
        else if (arg == "--journal") { options.journal_path = need_value("--journal"); has_journal = true; }
        else if (arg == "--evidence-dir") { options.evidence_dir = need_value("--evidence-dir"); has_evidence = true; }
        else if (arg == "--out") { options.out_path = need_value("--out"); }
        else if (arg == "--confirm") { options.confirm = true; }
        else if (arg == "--approval-mode")
        {
            if (need_value("--approval-mode") != "exact-source-v1") FailOptions("unknown approval mode");
            options.exact_source_approval = true;
        }
        else if (arg == "--approved-source-identity") options.approved_source_identity = need_value("--approved-source-identity");
        else if (arg == "--approved-source-sha256") options.approved_source_sha256 = need_value("--approved-source-sha256");
        else if (arg == "--test-abort-stage")
        {
            if (!TestHooksEnabled()) FailOptions("test hook not enabled");
            options.test_abort_stage = need_value("--test-abort-stage");
            if (options.test_abort_stage != "before-apple-publish")
                FailOptions("--test-abort-stage supports only before-apple-publish");
        }
        else FailOptions("unknown argument: " + arg);
    }
    if (!options.exact_source_approval &&
        (flags.contains("--approved-source-identity") || flags.contains("--approved-source-sha256")))
        FailOptions("source approval flags require --approval-mode exact-source-v1");
    if (!has_image || !has_container || !has_volume_uuid || !has_oid || !has_xid || !has_offset || !has_size ||
        !has_journal || !has_evidence)
        FailOptions("missing required repair selectors; " + VolumeRepairUsage());
    RequireHex32(options.container_uuid, "--container-uuid");
    RequireHex32(options.volume_uuid, "--volume-uuid");
    RequireOrdinaryInputFile(options.image, "repair input");
    if (options.confirm && !has_expected)
        FailOptions("--confirm requires an exact --expected-count intent");
    if (options.exact_source_approval && (duplicate || (!options.confirm && has_expected)))
        FailOptions("exact source approval rejects duplicate flags and unconfirmed count intent");
    ValidateSourceApprovalOptions(options);
    return options;
}

VolumeRepairToolResult RunVolumeRepair(const VolumeRepairToolOptions& options)
{
    try
    {
        ValidateRepairPaths(options);
        ValidateSourceApprovalOptions(options);
        return RunVolumeRepairImpl(options);
    }
    catch (const ToolArgumentError& error)
    {
        VolumeRepairToolResult result;
        result.exit_code = 2;
        result.json = "{\"format\":\"apfs-access-repair\",\"version\":" +
            std::string(options.exact_source_approval ? "2" : "1") +
            ",\"command\":\"repair\",\"success\":false,\"exitCode\":2,\"code\":\"InvalidArguments\",\"error\":\"";
        JsonEscape(result.json, error.what()); result.json += "\"}";
        return result;
    }
    catch (const std::exception& error)
    {
        VolumeRepairToolResult result;
        result.exit_code = 5;
        result.json =
            "{\"format\":\"apfs-access-repair\",\"version\":" + std::string(options.exact_source_approval ? "2" : "1") +
            ",\"command\":\"repair\","
            "\"success\":false,\"exitCode\":5,\"code\":\"RepairFailed\",\"error\":\"";
        JsonEscape(result.json, error.what());
        result.json += "\"}";
        return result;
    }
}

static VolumeRepairToolResult RunVolumeRepairImpl(const VolumeRepairToolOptions& options)
{
    VolumeRepairToolResult result;
    RepairSourceBinding source_binding;
    const auto ResultJson = [&](const VolumeRepairToolOptions& selectors, auto&&... fields) {
        return ::ResultJson(selectors, source_binding, std::forward<decltype(fields)>(fields)...);
    };
    ExclusiveReportFile report;
    std::string report_error;
    if (!report.Open(options, report_error))
    {
        result.exit_code = 4;
        result.json = ResultJson(options, 4, "RepairRefused", report_error, std::vector<std::byte>{},
            nullptr, false, 0, false, false, false, nullptr, options.journal_path, "", true, true);
        return result;
    }
    auto finish = [&](int exit_code, const std::string& json) {
        result.exit_code = exit_code;
        result.json = json;
        report.Write(json);
        return result;
    };
    std::string error;
    std::error_code ec;
    std::shared_ptr<apfsaccess::rw::BlockDevice> held_image;
    std::vector<std::byte> preimage;
    if (options.exact_source_approval)
    {
        held_image = apfsaccess::rw::BlockDevice::OpenExclusiveManagementImage(
            fsys::absolute(RepairUtf8Path(options.image)).wstring(), 0, error);
        if (!held_image || !ReadHeldRepairImage(*held_image, preimage, source_binding, error))
            return finish(4, ResultJson(options, 4, "RepairRefused", error, preimage,
                nullptr, false, 0, false, false, false, nullptr, options.journal_path, "", true, true));
    }
    else preimage = ReadAllBytes(options.image, error);
    const auto ReadImageBytes = [&](const std::string& path) {
        if (!held_image) return ::ReadImageBytes(path);
        std::vector<std::byte> bytes;
        RepairSourceBinding ignored;
        std::string read_error;
        if (!ReadHeldRepairImage(*held_image, bytes, ignored, read_error))
            throw std::runtime_error(read_error);
        return bytes;
    };
    if (preimage.empty() && !error.empty())
    {
        const int code = error.starts_with("repair image ") ? 4 : 5;
        return finish(code, ResultJson(options, code, code == 4 ? "RepairRefused" : "RepairFailed",
            "cannot read repair input: " + error, preimage,
            nullptr, false, 0, false, false, false, nullptr, options.journal_path, "", true, true));
    }
    if (preimage.size() > kMaxRepairImageBytes)
    {
        return finish(4, ResultJson(options, 4, "RepairRefused", "repair image exceeds the 256MiB offline bound",
            preimage, nullptr, false, 0, false, false, false, nullptr, options.journal_path, "", true, true));
    }
    // The store window binds the image geometry: this whole-image tool only
    // repairs offset zero, and the file size must equal the selected size.
    // Growth, truncation, or window drift refuses before any owner opens.
    if (options.store_offset_bytes != 0)
    {
        return finish(4, ResultJson(options, 4, "RepairRefused", "repair repairs whole-image scope only",
            preimage, nullptr, false, 0, false, false, false, nullptr, options.journal_path, "", true, true));
    }
    if (preimage.size() != options.store_size_bytes)
    {
        return finish(4, ResultJson(options, 4, "RepairRefused", "image size does not match selected store window",
            preimage, nullptr, false, 0, false, false, false, nullptr, options.journal_path, "", true, true));
    }
    fsys::create_directories(RepairUtf8Path(options.evidence_dir), ec);
    if (ec)
    {
        return finish(5, ResultJson(options, 5, "RepairFailed", "cannot create evidence directory",
            preimage, nullptr, false, 0, false, false, false, nullptr, options.journal_path, "", true, true));
    }
    const bool journal_exists = fsys::exists(RepairUtf8Path(options.journal_path), ec);
    if (ec)
    {
        return finish(5, ResultJson(options, 5, "RepairFailed", "cannot stat repair journal path",
            preimage, nullptr, false, 0, false, false, false, nullptr, options.journal_path, "", true, true));
    }
    // Authority lives in journal content, never the filename: an empty file
    // stages nothing and is treated exactly like a fresh path. Only
    // non-empty journals take the replay-only resumption branch below.
    bool journal_has_content = false;
    if (journal_exists)
    {
        std::error_code size_ec;
        const auto journal_size = fsys::file_size(RepairUtf8Path(options.journal_path), size_ec);
        if (size_ec)
        {
            return finish(5, ResultJson(options, 5, "RepairFailed", "cannot stat repair journal content",
                preimage, nullptr, false, 0, false, false, false, nullptr, options.journal_path, "", true, true));
        }
        journal_has_content = journal_size > 0;
    }
    LiveIdentities live;
    std::vector<std::uint64_t> volume_oids;
    if (!ResolveLiveIdentities(preimage, options, live, volume_oids, error))
    {
        const bool unchanged = ReadImageBytes(options.image) == preimage;
        return finish(4, ResultJson(options, 4, "RepairRefused", error, preimage, nullptr, false, 0, false,
            false, false, nullptr, options.journal_path, "", true, unchanged));
    }
    const bool completed_candidate = options.exact_source_approval && options.confirm && journal_has_content &&
        live.checkpoint_xid > options.checkpoint_xid;
    if (live.container_uuid != options.container_uuid || live.volume_uuid != options.volume_uuid ||
        (live.checkpoint_xid != options.checkpoint_xid && !completed_candidate))
    {
        const bool unchanged = ReadImageBytes(options.image) == preimage;
        return finish(4, ResultJson(options, 4, "RepairRefused", "repair selectors do not match live image identity",
            preimage, nullptr, false, 0, false, false, false, nullptr, options.journal_path, "", true, unchanged));
    }
    if (completed_candidate && source_binding.identity != options.approved_source_identity)
        return finish(4, ResultJson(options, 4, "RepairRefused", "completed repair requires the exact original image identity",
            preimage, nullptr, false, 0, false, false, false, nullptr, options.journal_path, "", true, true));
    const bool found_oid = std::find(volume_oids.begin(), volume_oids.end(), options.volume_oid) != volume_oids.end();
    if (!found_oid)
    {
        return finish(4, ResultJson(options, 4, "RepairRefused", "repair volume OID is not in the live container",
            preimage, nullptr, false, 0, false, false, false, nullptr, options.journal_path, "", true, true));
    }
    std::unique_ptr<Owner> owner;
    if (!OpenSessionOwner(options.image, volume_oids, live.container_uuid, owner, error, held_image))
    {
        const bool unchanged = ReadImageBytes(options.image) == preimage;
        return finish(5, ResultJson(options, 5, "RepairFailed", error, preimage, nullptr, false, 0, false,
            false, false, nullptr, options.journal_path, "", true, unchanged));
    }
    if (!options.exact_source_approval)
    {
        std::vector<std::byte> owned_preimage;
        RepairSourceBinding ignored;
        if (!ReadHeldRepairImage(owner->Device(), owned_preimage, ignored, error) || owned_preimage != preimage)
            return finish(4, ResultJson(options, 4, "RepairRefused", "initial repair preimage differs from held owner: " + error,
                preimage, nullptr, false, 0, false, false, false, nullptr, options.journal_path, "", true,
                owned_preimage == preimage));
    }
    if (options.exact_source_approval && options.confirm && !journal_has_content &&
        (source_binding.identity != options.approved_source_identity ||
         source_binding.sha256 != options.approved_source_sha256))
        return finish(4, ResultJson(options, 4, "RepairRefused", "approved source preimage does not match held image",
            preimage, nullptr, false, 0, false, false, false, nullptr, options.journal_path, "", true,
            ReadImageBytes(options.image) == preimage));
    Tx journal(L"Strict");
    const auto volume_identity = AsciiWiden(
        "apfs-vol:" + live.container_uuid + ":" + std::to_string(options.volume_oid));
    if (volume_identity.empty())
    {
        const bool unchanged = ReadImageBytes(options.image) == preimage;
        return finish(5, ResultJson(options, 5, "RepairFailed", "repair identity is not ASCII-representable",
            preimage, nullptr, false, 0, false, false, false, nullptr, options.journal_path, "", true, unchanged));
    }
    if (completed_candidate)
    {
        const auto journal_path = fsys::absolute(RepairUtf8Path(options.journal_path)).wstring();
        const auto backup_path = RepairPathUtf8(RepairUtf8Path(options.evidence_dir) /
            ("repair-backup-" + std::to_string(options.volume_oid) + "-" +
                std::to_string(options.checkpoint_xid) + ".apfs"));
        const auto refuse = [&](const std::string& why) {
            return finish(4, ResultJson(options, 4, "RepairRefused", why, preimage, nullptr, false, 0,
                false, false, false, nullptr, options.journal_path, backup_path, true, ReadImageBytes(options.image) == preimage));
        };
        if (!journal.OpenExistingRepairJournal(journal_path, volume_identity, error)) return refuse(error);
        auto backup = apfsaccess::rw::BlockDevice::OpenStableReadOnlyImage(fsys::absolute(RepairUtf8Path(backup_path)).wstring(), error);
        std::vector<std::byte> approved_preimage;
        RepairSourceBinding backup_binding;
        if (!backup || !ReadHeldRepairImage(*backup, approved_preimage, backup_binding, error))
            return refuse("completed repair requires its held original approved backup: " + error);
        const apfsaccess::catalog::ApfsSnapshotScope original{options.store_offset_bytes, options.store_size_bytes,
            options.container_uuid, options.volume_uuid, options.volume_oid, options.checkpoint_xid};
        if (!apfsaccess::rw::VerifyCompletedApfsCountRepair(*owner, journal, journal_path, original, options.expected_count,
            approved_preimage, options.approved_source_sha256, error)) return refuse(error);
        std::vector<std::byte> current;
        RepairSourceBinding current_binding;
        VerificationReport post;
        auto current_options = options;
        current_options.checkpoint_xid = live.checkpoint_xid;
        if (!backup->RevalidateStableReadOnlyImage() || !ReadHeldRepairImage(*held_image, current, current_binding, error) ||
            current != preimage || current_binding.identity != options.approved_source_identity ||
            !VerifyImageBytes(current, current_options, post, error)) return refuse("completed repair current proof failed: " + error);
        return finish(0, ResultJson(options, 0, "RepairedAndVerified", "", preimage, nullptr, false, 0,
            false, true, true, &post, options.journal_path, backup_path, true, true));
    }
    journal.SetJournalPath(fsys::absolute(RepairUtf8Path(options.journal_path)).wstring());
    journal.SetVolumeIdentity(volume_identity);
    if (journal_has_content)
    {
        // A pre-existing journal is never adopted as planning authority: the
        // only legal resumption is replaying this volume's accepted repair
        // (checkpoint/XID/source-identity matched by the engine), then
        // post-verifying. Anything else refuses with bytes unchanged.
        if (!journal.HasUnappliedAcceptedWork())
        {
            const bool unchanged = ReadImageBytes(options.image) == preimage;
            return finish(4, ResultJson(options, 4, "RepairRefused",
                "repair journal exists without replayable accepted work: refusing foreign authority",
                preimage, nullptr, false, 0, false, false, false, nullptr, options.journal_path, "", true,
                unchanged));
        }
        std::string replay_error;
        const auto replayed = ReplayApfsCountRepair(*owner, journal, options.volume_oid, replay_error);
        if (!replayed.has_value() || !*replayed)
        {
            const bool unchanged = ReadImageBytes(options.image) == preimage;
            return finish(5, ResultJson(options, 5, "RepairFailed",
                "journal work is not a replayable repair: " + replay_error, preimage, nullptr, false,
                0, false, false, false, nullptr, options.journal_path, "", true, unchanged));
        }
        VerificationReport post;
        if (!VerifyImageBytes(ReadImageBytes(options.image), options, post, error))
        {
            return finish(5, ResultJson(options, 5, "RepairFailed",
                "replayed repair did not verify: " + error, preimage, nullptr, false, 0, false, false,
                true, nullptr, options.journal_path, "", false, false));
        }
        return finish(0, ResultJson(options, 0, "RepairedAndVerified", "", preimage, nullptr, false, 0,
            false, true, true, &post, options.journal_path, "", false, false));
    }
    // Accepted original-journal replay above remains engine-bound recovery.
    // Fresh approval was checked on this exclusive file object before the WAL
    // was opened; the engine binds its own plan to these unchanged bytes.
    ApfsCountRepairPlan plan;
    if (!PrepareApfsCountRepair(*owner, options.volume_oid, plan, error))
    {
        const bool no_finding = error == "CountRepairNoFinding";
        const bool unchanged = ReadImageBytes(options.image) == preimage;
        if (no_finding)
        {
            VerificationReport post;
            if (!VerifyImageBytes(ReadImageBytes(options.image), options, post, error))
            {
                return finish(5, ResultJson(options, 5, "RepairFailed",
                    "healthy image did not verify: " + error, preimage, nullptr, false, 0, false, false,
                    false, nullptr, options.journal_path, "", true, unchanged));
            }
            return finish(0, ResultJson(options, 0, "RepairHealthyNoFinding", "", preimage, nullptr, false,
                0, false, false, false, &post, options.journal_path, "", true, unchanged));
        }
        return finish(4, ResultJson(options, 4, "RepairRefused", error, preimage, nullptr, false, 0, false,
            false, false, nullptr, options.journal_path, "", true, unchanged));
    }
    const auto& evidence = plan.Evidence();
    const auto& finding = plan.Finding();
    if (!options.confirm)
    {
        const bool unchanged = ReadImageBytes(options.image) == preimage;
        return finish(3, ResultJson(options, 3, "RepairNeedsConfirmation", "", preimage, &finding, true,
            evidence.expected_count, true, false, false, nullptr, options.journal_path, "", true, unchanged));
    }
    if (options.expected_count != evidence.expected_count)
    {
        const bool unchanged = ReadImageBytes(options.image) == preimage;
        return finish(4, ResultJson(options, 4, "RepairRefused", "confirmation intent does not match prepared expected count",
            preimage, &finding, true, evidence.expected_count, true, false, false, nullptr, options.journal_path,
            "", true, unchanged));
    }
    const auto backup_path = RepairPathUtf8(
        RepairUtf8Path(options.evidence_dir) / ("repair-backup-" + std::to_string(options.volume_oid) + "-" +
            std::to_string(live.checkpoint_xid) + ".apfs"));
    if (fsys::exists(RepairUtf8Path(backup_path), ec) || ec)
    {
        return finish(4, ResultJson(options, 4, "RepairRefused", "pre-repair backup already exists: refusing evidence collision",
            preimage, &finding, true, evidence.expected_count, true, false, false, nullptr,
            options.journal_path, "", true, ReadImageBytes(options.image) == preimage));
    }
    {
        std::ofstream backup(RepairUtf8Path(backup_path), std::ios::binary | std::ios::trunc);
        if (!backup)
        {
            return finish(5, ResultJson(options, 5, "RepairFailed", "cannot write pre-repair backup",
                preimage, &finding, true, evidence.expected_count, true, false, false, nullptr,
                options.journal_path, "", true, ReadImageBytes(options.image) == preimage));
        }
        backup.write(reinterpret_cast<const char*>(preimage.data()), static_cast<std::streamsize>(preimage.size()));
        if (!backup)
        {
            return finish(5, ResultJson(options, 5, "RepairFailed", "cannot write pre-repair backup",
                preimage, &finding, true, evidence.expected_count, true, false, false, nullptr,
                options.journal_path, "", true, ReadImageBytes(options.image) == preimage));
        }
    }
    if (!options.test_abort_stage.empty())
    {
        if (!TestHooksEnabled())
        {
            return finish(2, ResultJson(options, 2, "InvalidArguments", "test hook not enabled",
                preimage, &finding, true, evidence.expected_count, true, false, false, nullptr,
                options.journal_path, backup_path, true, ReadImageBytes(options.image) == preimage));
        }
        auto* session = owner->FindSessionStore(options.volume_oid);
        if (!session)
        {
            return finish(5, ResultJson(options, 5, "RepairFailed", "repair session missing for test hook",
                preimage, &finding, true, evidence.expected_count, true, false, false, nullptr,
                options.journal_path, backup_path, true, ReadImageBytes(options.image) == preimage));
        }
        session->SetCommitStageHook([](std::string_view stage) { return stage != "before-apple-publish"; });
    }
    if (options.exact_source_approval)
    {
        std::vector<std::byte> fresh;
        RepairSourceBinding binding;
        if (!ReadHeldRepairImage(*held_image, fresh, binding, error) ||
            binding.identity != options.approved_source_identity || binding.sha256 != options.approved_source_sha256)
            return finish(4, ResultJson(options, 4, "RepairRefused", "approved source changed before apply: " + error,
                preimage, &finding, true, evidence.expected_count, true, false, false, nullptr,
                options.journal_path, backup_path, true, fresh == preimage));
    }
    const auto apply_result = ApplyApfsCountRepair(*owner, journal, plan, plan.ConfirmationToken());
    if (!apply_result.committed || apply_result.commit_recovery_required)
    {
        return finish(5, ResultJson(options, 5, apply_result.commit_recovery_required ? "RepairRecoveryRequired" : "RepairFailed",
            apply_result.error.empty() ? "repair apply did not commit" : apply_result.error, preimage, &finding,
            true, evidence.expected_count, true, false, false, nullptr, options.journal_path, backup_path,
            false, false));
    }
    VerificationReport post;
    if (!VerifyImageBytes(ReadImageBytes(options.image), options, post, error))
    {
        return finish(5, ResultJson(options, 5, "RepairFailed", "repaired image did not verify: " + error,
            preimage, &finding, true, evidence.expected_count, true, true, false, nullptr, options.journal_path,
            backup_path, false, false));
    }
    return finish(0, ResultJson(options, 0, "RepairedAndVerified", "", preimage, &finding, true,
        evidence.expected_count, true, true, false, &post, options.journal_path, backup_path, false, false));
}

template<class Arguments>
int VolumeRepairToolEntry(Arguments&& arguments)
{
    try
    {
        auto options = ParseVolumeRepairArguments(arguments());
        const auto result = RunVolumeRepair(options);
        std::cout << result.json << "\n";
        return result.exit_code;
    }
    catch (const ToolArgumentError& error)
    {
        std::cout << "{\"format\":\"apfs-access-repair\",\"version\":1,\"command\":\"repair\","
                     "\"success\":false,\"exitCode\":2,\"code\":\"InvalidArguments\",\"error\":\"";
        std::string escaped;
        JsonEscape(escaped, error.what());
        std::cout << escaped << "\"}\n";
        return 2;
    }
    catch (const std::exception& error)
    {
        std::cout << "{\"format\":\"apfs-access-repair\",\"version\":1,\"command\":\"repair\","
                     "\"success\":false,\"exitCode\":5,\"code\":\"RepairFailed\",\"error\":\"";
        std::string escaped;
        JsonEscape(escaped, error.what());
        std::cout << escaped << "\"}\n";
        return 5;
    }
}

#ifndef APFS_VOLUME_REPAIR_TOOL_TESTING
#if defined(_WIN32)
int wmain(int argc, wchar_t** argv)
{
    return VolumeRepairToolEntry([&] {
        std::vector<std::string> args;
        for (int i = 1; i < argc; ++i) args.push_back(RepairArgumentUtf8(argv[i]));
        return args;
    });
}
#else
int main(int argc, char** argv)
{
    return VolumeRepairToolEntry([&] { return std::vector<std::string>(argv + 1, argv + argc); });
}
#endif
#endif
