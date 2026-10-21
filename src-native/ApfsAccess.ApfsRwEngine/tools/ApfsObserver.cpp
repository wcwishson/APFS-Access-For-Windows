// ApfsObserver: the fixed repo-owned read-only APFS observer.
//
// Reads a fixture image, a two-store Fusion pair, or a raw device through the
// authoritative native catalog and emits one C0a evidence record
// (apfs-access-raw-evidence v1) as JSON. It never writes to the observed
// bytes, never follows symlink inputs, and exits nonzero (fail-closed) on any
// structural problem. Unknown feature bits are reported, never fatal.

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifdef _WIN32
#include <Windows.h>
#include "WindowsImageLease.h"
#endif
#ifndef _WIN32
#include <unistd.h>
#endif

#include "ApfsContainerCatalog.h"
#include "ApfsFormat.h"
#include "ApfsSnapshotStore.h"
#include "ApfsSpaceAccounting.h"
#include "ApfsVerifier.h"
#include "ApfsVerificationJson.h"
#include "ApfsVerifierEncryptedSource.h"
#include "ApfsFusionStore.h"
#ifdef _WIN32
#include "EncryptedReadTransport.h"
#endif
#include <set>
#ifdef _WIN32
#include "BlockDevice.h"
#endif
#include "RandomAccessSource.h"
#include "Sha256.h"

#include <atomic>
#include <chrono>
#include <charconv>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <string>
#include <string_view>
#include <vector>

namespace
{
constexpr char kFormat[] = "apfs-access-raw-evidence";
constexpr int kVersion = 1;
constexpr char kObserverId[] = "apfs-access-owned-raw-observer";
constexpr char kObserverVersion[] = "1.1.0";

int Usage()
{
    std::cerr << "Usage:\n"
              << "  ApfsObserver --image <file> --profile <name> --mode collect "
                 "[--device-id <slug>] [--out <file>]\n"
              << "  ApfsObserver --store-a <file> --store-b <file> --profile <name> "
                 "--mode fusion [--device-id <slug>] [--out <file>]\n"
              << "  ApfsObserver --device <path> --profile <name> --mode collect "
                 "[--device-id <slug>] [--out <file>]\n"
              << "  ApfsObserver --image <file> --mode snapshots --container-uuid <hex32> "
                 "--volume-oid <decimal> [--out <file>]\n"
              << "  ApfsObserver --image <file> --mode verify --container-uuid <hex32> "
                 "--volume-uuid <hex32> --volume-oid <decimal> --checkpoint-xid <decimal> "
                 "--store-offset-bytes <decimal> --store-size-bytes <decimal> "
                 "[--require-whole-volume] [--require-payload-content-hashes] [--account-retained-ownership] [--out <file>]\n"
              << "  ApfsObserver --image <file> --mode verify-history --container-uuid <hex32> "
                 "--volume-uuid <hex32> --volume-oid <decimal> --checkpoint-xid <decimal> "
                 "--retained-from-xid <older-decimal> --store-offset-bytes <decimal> --store-size-bytes <decimal> [--out <file>]\n"
              << "  ApfsObserver --image <file> --mode snapshot-space --container-uuid <hex32> "
                 "--volume-uuid <hex32> --volume-oid <decimal> --checkpoint-xid <decimal> "
                 "--store-offset-bytes <decimal> --store-size-bytes <decimal> [--out <file>]\n"
              << "  ApfsObserver --image <file> --mode snapshot-attribution --container-uuid <hex32> "
                 "--volume-uuid <hex32> --volume-oid <decimal> --checkpoint-xid <decimal> "
                 "--store-offset-bytes <decimal> --store-size-bytes <decimal> [--out <file>]\n"
              << "  ApfsObserver --help\n";
    return 2;
}

[[noreturn]] void Fail(const std::string& message)
{
    std::cerr << "error: " << message << "\n";
    std::exit(2);
}

int WriteStdoutEvidence(const std::string& text, int semantic_exit_code)
{
    std::cout << text << '\n';
    std::cout.flush();
    // Check the synchronized CRT buffer too, before process teardown hides errors.
    const int flush_result = std::fflush(stdout);
    if (!std::cout.good() || flush_result != 0 || std::ferror(stdout) != 0)
    {
        std::cerr << "error: observer stdout transport failed\n" << std::flush;
        return 5;
    }
    return semantic_exit_code;
}

bool IsSlugChar(char ch)
{
    return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
        (ch >= '0' && ch <= '9') || ch == '_' || ch == '.' || ch == '-';
}

bool IsValidSlug(const std::string& slug)
{
    if (slug.empty() || slug.size() > 128)
    {
        return false;
    }
    for (char ch : slug)
    {
        if (!IsSlugChar(ch))
        {
            return false;
        }
    }
    return true;
}

#ifdef _WIN32
std::string ToUtf8(std::wstring_view text)
{
    if (text.empty()) return {};
    if (text.size() > static_cast<std::size_t>((std::numeric_limits<int>::max)()))
        Fail("argument is too long");
    const auto length = static_cast<int>(text.size());
    const int needed = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
        text.data(), length, nullptr, 0, nullptr, nullptr);
    if (needed <= 0) Fail("argument is not valid UTF-16");
    std::string utf8(static_cast<std::size_t>(needed), '\0');
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(), length,
            utf8.data(), needed, nullptr, nullptr) != needed)
        Fail("argument is not valid UTF-16");
    return utf8;
}

std::wstring ToWide(const std::string& text)
{
    if (text.empty())
    {
        return std::wstring{};
    }
    if (text.size() > static_cast<std::size_t>((std::numeric_limits<int>::max)()))
        Fail("device path is too long");
    const auto length = static_cast<int>(text.size());
    const int needed = MultiByteToWideChar(
        CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), length, nullptr, 0);
    if (needed <= 0)
    {
        Fail("device path is not valid UTF-8");
    }
    std::wstring wide(static_cast<std::size_t>(needed), L'\0');
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), length,
            wide.data(), needed) != needed)
        Fail("device path is not valid UTF-8");
    return wide;
}
#endif

std::filesystem::path ObserverPath(const std::string& text)
{
#ifdef _WIN32
    return std::filesystem::path(ToWide(text));
#else
    return std::filesystem::path(text);
#endif
}

std::string PathUtf8(const std::filesystem::path& path)
{
    const auto utf8 = path.u8string();
    return std::string(utf8.begin(), utf8.end());
}

void RequireRegularInputFile(const std::string& path, const std::string& what)
{
    namespace fs = std::filesystem;
    std::error_code code;
    const auto native_path = ObserverPath(path);
    if (fs::is_symlink(native_path, code) && !code)
    {
        Fail(std::string("refusing symlinked observer input: ") + what);
    }
    if (!fs::is_regular_file(native_path, code) || code)
    {
        Fail(std::string("observer input is not a regular file: ") + what);
    }
}

// True when both paths name the same file. Errors (e.g. missing files)
// report false and let the later open/parse stages fail with context.
bool SameFile(const std::string& first, const std::string& second)
{
    std::error_code code;
    const bool same = std::filesystem::equivalent(ObserverPath(first), ObserverPath(second), code);
    return !code && same;
}

namespace
{
std::atomic<std::uint64_t> g_publish_counter{0};
}

// Atomically publishes evidence text: never overwrites inputs or existing
// outputs, never follows a symlinked --out path or parent directory, and
// never leaves a partial file behind (temp + rename; any failure removes
// the temp file and exits nonzero).
void PublishEvidence(
    const std::string& text,
    const std::string& out_path,
    const std::vector<std::string>& input_paths)
{
    namespace fs = std::filesystem;
    std::error_code code;
    const auto output_path = ObserverPath(out_path);
    for (const std::string& input : input_paths)
    {
        if (fs::equivalent(output_path, ObserverPath(input), code) && !code)
        {
            Fail("refusing to overwrite observer input: " + out_path);
        }
        code.clear();
    }
    if (fs::symlink_status(output_path, code).type() == fs::file_type::symlink && !code)
    {
        Fail("refusing symlinked --out path: " + out_path);
    }
    code.clear();
    if (fs::exists(output_path, code) && !code)
    {
        Fail("--out already exists (delete first to re-run): " + out_path);
    }
    code.clear();
    fs::path parent = output_path.parent_path();
    if (parent.empty())
    {
        parent = ".";
    }
    // N1: walk every ancestor (not just the immediate parent) without
    // following anything; a symlinked grandparent redirects the atomic
    // rename just as fatally as a symlinked parent.
    {
        fs::path ancestor = parent;
        for (int depth = 0; depth < 64; ++depth)
        {
            const fs::file_type kind = fs::symlink_status(ancestor, code).type();
            if (code || kind == fs::file_type::symlink)
            {
                Fail("refusing --out under a symlinked or unreadable directory: " +
                    PathUtf8(ancestor));
            }
            if (kind == fs::file_type::not_found)
            {
                Fail("--out directory does not exist: " + PathUtf8(ancestor));
            }
            const fs::path up = ancestor.parent_path();
            if (up.empty() || up == ancestor)
            {
                break;
            }
            ancestor = up;
        }
    }
    if (!fs::is_directory(parent, code) || code)
    {
        Fail("--out directory does not exist: " + PathUtf8(parent));
    }
#ifdef _WIN32
    const std::uint64_t process_id = static_cast<std::uint64_t>(GetCurrentProcessId());
#else
    const std::uint64_t process_id = static_cast<std::uint64_t>(::getpid());
#endif
    const std::uint64_t stamp =
        static_cast<std::uint64_t>(std::chrono::steady_clock::now().time_since_epoch().count());
    for (int attempt = 0; attempt < 10; ++attempt)
    {
        // N2: the process id joins the temp name so two observer processes
        // can never deterministically collide (the pre-exists check still
        // guards planted names).
        const std::string temp = out_path + ".tmp-" + std::to_string(process_id) + "-" +
            std::to_string(stamp) + "-" +
            std::to_string(g_publish_counter.fetch_add(1));
        const auto temp_path = ObserverPath(temp);
        if (fs::symlink_status(temp_path, code).type() != fs::file_type::not_found)
        {
            code.clear();
            continue;
        }
        {
            std::ofstream out(temp_path, std::ios::out | std::ios::binary | std::ios::trunc);
            if (!out.is_open())
            {
                Fail("cannot open --out temp file: " + temp);
            }
            out << text << "\n";
            out.close();
            if (!out.good())
            {
                std::error_code remove_code;
                fs::remove(temp_path, remove_code);
                Fail("writing --out temp file failed: " + temp);
            }
        }
        fs::rename(temp_path, output_path, code);
        if (code)
        {
            std::error_code remove_code;
            fs::remove(temp_path, remove_code);
            Fail("atomic --out publish failed: " + out_path);
        }
        return;
    }
    Fail("could not pick a fresh --out temp name beside: " + out_path);
}

struct SourceHash
{
    std::string hex; // "" when unhashed
    std::uint64_t size_bytes = 0;
};

// Streams SHA-256 over one held source in 1 MiB chunks through the
// platform-selected implementation (CNG on Windows, portable elsewhere).
// The SAME open handle feeds both hashing and parsing; callers re-verify
// the source identity afterwards.
SourceHash HashHeldSource(const apfsaccess::catalog::HeldFileSource& source, const std::string& path)
{
    SourceHash out;
    out.size_bytes = source.SizeBytes();
    std::string error;
    auto hash = apfsaccess::observer::Sha256Stream::Create(error);
    if (!hash)
    {
        Fail("hash init failed for " + path + ": " + error);
    }
    bool failed = false;
    std::vector<std::byte> chunk;
    for (std::uint64_t offset = 0; offset < out.size_bytes;)
    {
        const std::size_t want = static_cast<std::size_t>(
            (std::min)(out.size_bytes - offset, static_cast<std::uint64_t>(1024 * 1024)));
        if (!source.Read(offset, want, chunk) || chunk.size() != want)
        {
            failed = true;
            break;
        }
        if (!hash->Update(chunk.data(), chunk.size()))
        {
            failed = true;
            break;
        }
        offset += want;
    }
    if (failed || !hash->FinalHex(out.hex))
    {
        Fail("hashing observer input failed: " + path);
    }
    return out;
}

// Minimal JSON writer: objects/arrays, exact key order, strict string
// escaping. Volume names arrive as validated UTF-8 (or empty); paths use the
// platform byte string with JSON-special escaping.
class JsonWriter
{
public:
    void BeginObject()
    {
        EmitValuePrefix();
        buffer_ += '{';
        stack_.push_back(Context{true, true, false});
    }

    void EndObject()
    {
        buffer_ += '}';
        stack_.pop_back();
        MarkValueWritten();
    }

    void BeginArray()
    {
        EmitValuePrefix();
        buffer_ += '[';
        stack_.push_back(Context{false, true, false});
    }

    void EndArray()
    {
        buffer_ += ']';
        stack_.pop_back();
        MarkValueWritten();
    }

    void Key(const char* key)
    {
        EmitComma();
        WriteString(key);
        buffer_ += ": ";
        stack_.back().first = false;
        stack_.back().after_key = true;
    }

    void String(const std::string& value)
    {
        EmitValuePrefix();
        WriteString(value.c_str());
        MarkValueWritten();
    }

    void Integer(std::uint64_t value)
    {
        EmitValuePrefix();
        char text[24];
        std::snprintf(text, sizeof(text), "%llu", static_cast<unsigned long long>(value));
        buffer_ += text;
        MarkValueWritten();
    }

    void Bool(bool value)
    {
        EmitValuePrefix();
        buffer_ += value ? "true" : "false";
        MarkValueWritten();
    }

    void Null()
    {
        EmitValuePrefix();
        buffer_ += "null";
        MarkValueWritten();
    }

    [[nodiscard]] const std::string& Text() const noexcept
    {
        return buffer_;
    }

private:
    struct Context
    {
        bool object = false;
        bool first = true;
        bool after_key = false;
    };

    void EmitComma()
    {
        if (!stack_.empty() && !stack_.back().first)
        {
            buffer_ += ", ";
        }
    }

    void EmitValuePrefix()
    {
        if (!stack_.empty() && !stack_.back().after_key)
        {
            EmitComma();
        }
    }

    void MarkValueWritten()
    {
        if (!stack_.empty())
        {
            stack_.back().first = false;
            stack_.back().after_key = false;
        }
    }

    void WriteString(const char* text)
    {
        buffer_ += '"';
        for (const unsigned char* p = reinterpret_cast<const unsigned char*>(text); *p; ++p)
        {
            switch (*p)
            {
            case '"': buffer_ += "\\\""; break;
            case '\\': buffer_ += "\\\\"; break;
            case '\b': buffer_ += "\\b"; break;
            case '\f': buffer_ += "\\f"; break;
            case '\n': buffer_ += "\\n"; break;
            case '\r': buffer_ += "\\r"; break;
            case '\t': buffer_ += "\\t"; break;
            default:
                if (*p < 0x20)
                {
                    char escape[8];
                    std::snprintf(escape, sizeof(escape), "\\u%04x", *p);
                    buffer_ += escape;
                }
                else
                {
                    buffer_ += static_cast<char>(*p);
                }
                break;
            }
        }
        buffer_ += '"';
    }

    std::string buffer_;
    std::vector<Context> stack_;
};

void WriteStringList(JsonWriter& json, const std::vector<std::string>& items)
{
    json.BeginArray();
    for (const std::string& item : items)
    {
        json.String(item);
    }
    json.EndArray();
}

void WriteSource(JsonWriter& json, const std::string& kind, const std::string& path,
    std::uint64_t size_bytes, const std::string& hash_scope, const std::string& sha256)
{
    json.BeginObject();
    json.Key("kind");
    json.String(kind);
    json.Key("path");
    json.String(path);
    json.Key("sizeBytes");
    json.Integer(size_bytes);
    json.Key("hashScope");
    json.String(hash_scope);
    json.Key("sha256");
    if (sha256.empty())
    {
        json.Null();
    }
    else
    {
        json.String(sha256);
    }
    json.EndObject();
}

void WriteDisk(JsonWriter& json, const std::string& disk_id,
    const std::string& device_identifier, const std::string& disk_uuid, std::uint64_t disk_size)
{
    json.BeginObject();
    json.Key("id");
    json.String("apfs-disk:" + disk_id);
    json.Key("deviceIdentifier");
    json.String(device_identifier);
    json.Key("uuid");
    if (disk_uuid.empty())
    {
        json.Null();
    }
    else
    {
        json.String(disk_uuid);
    }
    json.Key("sizeBytes");
    json.Integer(disk_size);
    json.EndObject();
}

void WritePartition(JsonWriter& json, const std::string& disk_id,
    const apfsaccess::catalog::GptPartitionDescriptor& partition)
{
    json.BeginObject();
    json.Key("id");
    json.String(partition.stable_partition_id);
    json.Key("uuid");
    json.String(partition.partition_guid);
    json.Key("diskId");
    json.String("apfs-disk:" + disk_id);
    json.Key("index");
    json.Integer(partition.partition_number);
    json.Key("startByte");
    json.Integer(partition.offset_bytes);
    json.Key("sizeBytes");
    json.Integer(partition.length_bytes);
    json.Key("typeGuid");
    json.String(partition.type_guid);
    json.Key("usage");
    json.String(partition.usage);
    json.EndObject();
}

void WriteStore(JsonWriter& json, const apfsaccess::catalog::ApfsPhysicalStoreDescriptor& store)
{
    json.BeginObject();
    json.Key("id");
    json.String(store.stable_store_id);
    json.Key("uuid");
    json.String(store.container_uuid_hex);
    json.Key("partitionId");
    json.String(store.partition_id);
    json.Key("containerId");
    json.String("apfs-container:" + store.container_uuid_hex);
    json.Key("offsetBytes");
    json.Integer(store.offset_bytes);
    json.Key("sizeBytes");
    json.Integer(store.size_bytes);
    json.Key("blockSizeBytes");
    json.Integer(store.block_size_bytes);
    json.Key("totalBlocks");
    json.Integer(store.total_blocks);
    json.EndObject();
}

void WriteAmount(JsonWriter& json, const apfsaccess::catalog::ApfsSpaceAmount& amount)
{
    json.BeginObject();
    json.Key("blocks"); json.String(std::to_string(amount.blocks));
    json.Key("bytes"); json.String(std::to_string(amount.bytes));
    json.EndObject();
}

void WriteOptionalAmount(JsonWriter& json,
    const std::optional<apfsaccess::catalog::ApfsSpaceAmount>& amount)
{
    if (amount) WriteAmount(json, *amount);
    else json.Null();
}

void WriteSharedSpace(JsonWriter& json, const apfsaccess::catalog::ApfsSharedSpaceProjection& space)
{
    json.BeginObject();
    json.Key("containerId"); json.String("apfs-container:" + space.container_uuid_hex);
    json.Key("checkpointXid"); json.String(std::to_string(space.checkpoint_xid));
    json.Key("allocationUnitBytes"); json.Integer(space.allocation_unit_bytes);
    json.Key("total"); WriteAmount(json, space.total);
    json.Key("free"); WriteAmount(json, space.free);
    json.Key("used"); WriteAmount(json, space.used);
    json.Key("volumes"); json.BeginArray();
    for (const auto& volume : space.volumes)
    {
        json.BeginObject();
        json.Key("volumeId"); json.String("apfs-vol:" + space.container_uuid_hex + ":" + std::to_string(volume.object_id));
        json.Key("objectId"); json.String(std::to_string(volume.object_id));
        json.Key("allocated"); WriteAmount(json, volume.allocated);
        json.Key("reserve"); WriteOptionalAmount(json, volume.reserve);
        json.Key("quota"); WriteOptionalAmount(json, volume.quota);
        json.Key("siblingReserveRemaining"); WriteAmount(json, volume.sibling_reserve_remaining);
        json.Key("available"); WriteAmount(json, volume.available);
        json.Key("snapshot"); WriteOptionalAmount(json, volume.snapshot);
        json.Key("purgeable"); WriteOptionalAmount(json, volume.purgeable);
        json.EndObject();
    }
    json.EndArray();
    json.EndObject();
}

void WriteContainer(JsonWriter& json, const apfsaccess::catalog::ApfsContainerDescriptor& container,
    const apfsaccess::catalog::ApfsContainerCatalog* catalog = nullptr)
{
    json.BeginObject();
    json.Key("id");
    json.String("apfs-container:" + container.container_uuid_hex);
    json.Key("uuid");
    json.String(container.container_uuid_hex);
    json.Key("blockSizeBytes");
    json.Integer(container.block_size);
    json.Key("storeIds");
    WriteStringList(json, container.member_store_ids);
    json.Key("volumeIds");
    json.BeginArray();
    for (const auto& volume : container.volumes)
    {
        json.String("apfs-vol:" + container.container_uuid_hex + ":" +
            std::to_string(volume.object_id));
    }
    json.EndArray();
    json.Key("fusion");
    json.Bool(container.fusion);
    json.Key("checkpointXid");
    json.String(std::to_string(container.checkpoint_xid));
    json.Key("compatibleFeatureBits");
    WriteStringList(json, container.compatible_bits);
    json.Key("readonlyFeatureBits");
    WriteStringList(json, container.readonly_bits);
    json.Key("unknownFeatureBits");
    WriteStringList(json, container.unknown_bits);
    json.Key("incompatibleFeatureBits");
    WriteStringList(json, container.incompatible_bits);
    json.Key("sharedSpace");
    apfsaccess::catalog::ApfsSharedSpaceProjection space;
    std::string space_error;
    // Failure/unsupported accounting is unknown, never a zero-capacity claim.
    // Fusion has no single verified shared projection in this version.
    if (catalog && !container.fusion && catalog->TryProjectSharedSpace(container.container_uuid_hex, space, space_error))
        WriteSharedSpace(json, space);
    else json.Null();
    json.EndObject();
}

std::string FindGroupId(
    const apfsaccess::catalog::ApfsContainerDescriptor& container, const std::string& volume_id)
{
    for (const auto& group : container.groups)
    {
        for (const auto& member : group.member_volume_ids)
        {
            if (member == volume_id)
            {
                return "apfs-group:" + group.group_uuid_hex;
            }
        }
    }
    return "";
}

void WriteVolume(JsonWriter& json, const std::string& container_uuid,
    const apfsaccess::catalog::ApfsVolumeDescriptor& volume, const std::string& group_id)
{
    json.BeginObject();
    json.Key("id");
    json.String("apfs-vol:" + container_uuid + ":" + std::to_string(volume.object_id));
    json.Key("uuid");
    json.String(volume.volume_uuid_hex);
    json.Key("objectId");
    json.String(std::to_string(volume.object_id));
    json.Key("containerId");
    json.String("apfs-container:" + container_uuid);
    json.Key("name");
    json.String(volume.name_utf8);
    json.Key("nameUtf8Valid");
    json.Bool(volume.name_valid);
    json.Key("roles");
    WriteStringList(json, volume.roles);
    json.Key("roleRaw");
    json.Integer(volume.role_raw);
    json.Key("roleName"); json.String(volume.role_name);
    json.Key("groupUuid");
    if (volume.group_uuid_hex.empty()) json.Null();
    else json.String(volume.group_uuid_hex);
    json.Key("groupMetadataValid"); json.Bool(volume.group_metadata_valid);
    json.Key("groupAssociationStatus"); json.String(volume.group_association_status);
    json.Key("groupId");
    if (group_id.empty())
    {
        json.Null();
    }
    else
    {
        json.String(group_id);
    }
    json.Key("caseMode");
    json.String(volume.case_mode);
    json.Key("encryptionMode");
    json.String(volume.encryption_mode);
    json.Key("locked");
    json.Bool(volume.locked);
    json.Key("compatibleFeatureBits");
    WriteStringList(json, volume.compatible_bits);
    json.Key("readonlyFeatureBits");
    WriteStringList(json, volume.readonly_bits);
    json.Key("unknownFeatureBits");
    WriteStringList(json, volume.unknown_bits);
    json.Key("incompatibleFeatureBits");
    WriteStringList(json, volume.incompatible_bits);
    json.Key("superblockBlock");
    json.String(std::to_string(volume.superblock_block));
    json.Key("superblockXid");
    json.String(std::to_string(volume.superblock_xid));
    json.EndObject();
}

void WriteGroup(JsonWriter& json, const apfsaccess::catalog::ApfsVolumeGroupDescriptor& group)
{
    json.BeginObject();
    json.Key("id");
    json.String("apfs-group:" + group.group_uuid_hex);
    json.Key("uuid");
    json.String(group.group_uuid_hex);
    json.Key("volumeIds");
    WriteStringList(json, group.member_volume_ids);
    json.Key("containerId"); json.String("apfs-container:" + group.container_uuid_hex);
    json.Key("associationStatus"); json.String(group.association_status);
    json.Key("systemVolumeId");
    if (group.system_volume_id.empty()) json.Null();
    else json.String(group.system_volume_id);
    json.Key("dataVolumeId");
    if (group.data_volume_id.empty()) json.Null();
    else json.String(group.data_volume_id);
    json.EndObject();
}

void WriteTopology(JsonWriter& json, const apfsaccess::catalog::ApfsContainerCatalog& catalog,
    const std::string& disk_id, const std::string& device_identifier, std::uint64_t disk_size,
    const std::string& disk_uuid)
{
    json.BeginObject();
    json.Key("disks");
    json.BeginArray();
    WriteDisk(json, disk_id, device_identifier, disk_uuid, disk_size);
    json.EndArray();

    json.Key("partitions");
    json.BeginArray();
    for (const auto& partition : catalog.Partitions())
    {
        WritePartition(json, disk_id, partition);
    }
    json.EndArray();

    json.Key("stores");
    json.BeginArray();
    for (const auto& store : catalog.Stores())
    {
        WriteStore(json, store);
    }
    json.EndArray();

    json.Key("containers");
    json.BeginArray();
    for (const auto& container : catalog.Containers())
    {
        WriteContainer(json, container, &catalog);
    }
    json.EndArray();

    json.Key("volumes");
    json.BeginArray();
    for (const auto& container : catalog.Containers())
    {
        for (const auto& volume : container.volumes)
        {
            const std::string volume_id = "apfs-vol:" + container.container_uuid_hex + ":" +
                std::to_string(volume.object_id);
            WriteVolume(json, container.container_uuid_hex, volume,
                FindGroupId(container, volume_id));
        }
    }
    json.EndArray();

    json.Key("groups");
    json.BeginArray();
    for (const auto& container : catalog.Containers())
    {
        for (const auto& group : container.groups)
        {
            WriteGroup(json, group);
        }
    }
    json.EndArray();
    json.EndObject();
}

// Merges two single-container catalogs that describe the same container
// (verified by the caller) into one fused container descriptor.
apfsaccess::catalog::ApfsContainerDescriptor MergeFusionContainer(
    const apfsaccess::catalog::ApfsContainerDescriptor& primary,
    const apfsaccess::catalog::ApfsContainerDescriptor& secondary)
{
    if (primary.container_uuid_hex != secondary.container_uuid_hex ||
        primary.checkpoint_xid != secondary.checkpoint_xid ||
        primary.block_size != secondary.block_size ||
        primary.compatible_features != secondary.compatible_features ||
        primary.readonly_features != secondary.readonly_features ||
        primary.incompatible_features != secondary.incompatible_features ||
        primary.volumes.size() != secondary.volumes.size())
    {
        Fail("fusion members disagree on container identity");
    }
    for (const auto& volume : primary.volumes)
    {
        bool matched = false;
        for (const auto& other : secondary.volumes)
        {
            if (other.object_id == volume.object_id && other.name_utf8 == volume.name_utf8 &&
                other.volume_uuid_hex == volume.volume_uuid_hex &&
                other.role_raw == volume.role_raw && other.role_name == volume.role_name &&
                other.roles == volume.roles && other.group_uuid_hex == volume.group_uuid_hex &&
                other.group_metadata_valid == volume.group_metadata_valid &&
                other.group_association_status == volume.group_association_status &&
                other.superblock_xid == volume.superblock_xid)
            {
                matched = true;
                break;
            }
        }
        if (!matched)
        {
            Fail("fusion members disagree on volume membership");
        }
    }
    apfsaccess::catalog::ApfsContainerDescriptor merged = primary;
    for (const auto& store_id : secondary.member_store_ids)
    {
        bool present = false;
        for (const auto& existing : merged.member_store_ids)
        {
            if (existing == store_id)
            {
                present = true;
                break;
            }
        }
        if (!present)
        {
            merged.member_store_ids.push_back(store_id);
        }
    }
    merged.fusion = true;
    return merged;
}

void WriteFusionTopology(JsonWriter& json,
    const apfsaccess::catalog::ApfsContainerCatalog& primary, const std::string& primary_disk,
    const std::string& primary_device, std::uint64_t primary_size,
    const apfsaccess::catalog::ApfsContainerCatalog& secondary, const std::string& secondary_disk,
    const std::string& secondary_device, std::uint64_t secondary_size,
    const apfsaccess::catalog::ApfsContainerDescriptor& merged)
{
    json.BeginObject();
    json.Key("disks");
    json.BeginArray();
    WriteDisk(json, primary_disk, primary_device, primary.DiskGuid(), primary_size);
    WriteDisk(json, secondary_disk, secondary_device, secondary.DiskGuid(), secondary_size);
    json.EndArray();

    json.Key("partitions");
    json.BeginArray();
    for (const auto& partition : primary.Partitions())
    {
        WritePartition(json, primary_disk, partition);
    }
    for (const auto& partition : secondary.Partitions())
    {
        WritePartition(json, secondary_disk, partition);
    }
    json.EndArray();

    json.Key("stores");
    json.BeginArray();
    for (const auto& store : primary.Stores())
    {
        WriteStore(json, store);
    }
    for (const auto& store : secondary.Stores())
    {
        WriteStore(json, store);
    }
    json.EndArray();

    json.Key("containers");
    json.BeginArray();
    WriteContainer(json, merged);
    json.EndArray();

    json.Key("volumes");
    json.BeginArray();
    for (const auto& volume : merged.volumes)
    {
        const std::string volume_id = "apfs-vol:" + merged.container_uuid_hex + ":" +
            std::to_string(volume.object_id);
        WriteVolume(json, merged.container_uuid_hex, volume, FindGroupId(merged, volume_id));
    }
    json.EndArray();

    json.Key("groups");
    json.BeginArray();
    for (const auto& group : merged.groups)
    {
        WriteGroup(json, group);
    }
    json.EndArray();
    json.EndObject();
}

struct ObserverOptions
{
    std::string image;
    std::string store_a;
    std::string store_b;
    std::string device;
    std::string profile;
    std::string mode;
    std::string device_id;
    std::string out_path;
    std::string container_uuid;
    std::string volume_oid;
    std::string volume_uuid, checkpoint_xid, store_offset_bytes, store_size_bytes;
    std::string retained_from_xid;
    std::string verification_profile, tier2_offset, tier2_size, fusion_uuid, fusion_convention;
    std::string expected_main_identity, expected_tier2_identity;
    bool credential_stdin = false;
    bool require_whole_volume = false, require_payload_content_hashes = false;
    bool account_retained_ownership = false;
    bool duplicate_option = false;
};

ObserverOptions ParseOptions(int argc, char** argv)
{
    ObserverOptions options;
    std::set<std::string> seen;
    for (int index = 1; index < argc; ++index)
    {
        const std::string arg = argv[index];
        if (!seen.insert(arg).second) options.duplicate_option = true;
        auto need_value = [&](const char* flag) -> std::string {
            if (index + 1 >= argc)
            {
                Fail(std::string("missing value for ") + flag);
            }
            return argv[++index];
        };
        if (arg == "--image")
        {
            options.image = need_value("--image");
        }
        else if (arg == "--store-a")
        {
            options.store_a = need_value("--store-a");
        }
        else if (arg == "--store-b")
        {
            options.store_b = need_value("--store-b");
        }
        else if (arg == "--device")
        {
            options.device = need_value("--device");
        }
        else if (arg == "--profile")
        {
            options.profile = need_value("--profile");
        }
        else if (arg == "--mode")
        {
            options.mode = need_value("--mode");
        }
        else if (arg == "--device-id")
        {
            options.device_id = need_value("--device-id");
        }
        else if (arg == "--out")
        {
            options.out_path = need_value("--out");
        }
        else if (arg == "--container-uuid")
        {
            options.container_uuid = need_value("--container-uuid");
        }
        else if (arg == "--volume-oid")
        {
            options.volume_oid = need_value("--volume-oid");
        }
        else if (arg == "--volume-uuid") options.volume_uuid = need_value("--volume-uuid");
        else if (arg == "--checkpoint-xid") options.checkpoint_xid = need_value("--checkpoint-xid");
        else if (arg == "--retained-from-xid") options.retained_from_xid = need_value("--retained-from-xid");
        else if (arg == "--store-offset-bytes") options.store_offset_bytes = need_value("--store-offset-bytes");
        else if (arg == "--store-size-bytes") options.store_size_bytes = need_value("--store-size-bytes");
        else if (arg == "--require-whole-volume") options.require_whole_volume = true;
        else if (arg == "--require-payload-content-hashes") options.require_payload_content_hashes = true;
        else if (arg == "--account-retained-ownership") options.account_retained_ownership = true;
        else if (arg == "--verification-profile") options.verification_profile = need_value("--verification-profile");
        else if (arg == "--tier2-offset-bytes") options.tier2_offset = need_value("--tier2-offset-bytes");
        else if (arg == "--tier2-size-bytes") options.tier2_size = need_value("--tier2-size-bytes");
        else if (arg == "--fusion-uuid") options.fusion_uuid = need_value("--fusion-uuid");
        else if (arg == "--fusion-role-convention") options.fusion_convention = need_value("--fusion-role-convention");
        else if (arg == "--expected-main-identity") options.expected_main_identity = need_value("--expected-main-identity");
        else if (arg == "--expected-tier2-identity") options.expected_tier2_identity = need_value("--expected-tier2-identity");
        else if (arg == "--credential-stdin") options.credential_stdin = true;
        else if (arg == "--help" || arg == "-h" || arg == "/?")
        {
            std::exit(Usage());
        }
        else
        {
            Fail("unknown argument: " + arg);
        }
    }
    return options;
}

std::uint64_t ExactDecimal(const std::string& value, const char* flag, bool allow_zero = false)
{
    std::uint64_t number = 0;
    const auto parsed = std::from_chars(value.data(), value.data() + value.size(), number);
    if (parsed.ec != std::errc{} || parsed.ptr != value.data() + value.size() ||
        (!allow_zero && !number) || value != std::to_string(number))
        Fail(std::string(flag) + " must be a canonical decimal uint64" + (allow_zero ? "" : " greater than zero"));
    return number;
}

void ValidateOptions(const ObserverOptions& options)
{
    const bool has_image = !options.image.empty();
    const bool has_fusion = !options.store_a.empty() || !options.store_b.empty();
    const bool has_device = !options.device.empty();
    const int sources = (has_image ? 1 : 0) + (has_fusion ? 1 : 0) + (has_device ? 1 : 0);
    if (sources != 1)
    {
        Fail("exactly one of --image, --store-a/--store-b, or --device is required");
    }
    if (has_fusion && (options.store_a.empty() || options.store_b.empty()))
    {
        Fail("fusion mode requires both --store-a and --store-b");
    }
    if (options.mode == "verify-profile" || options.mode == "verify-profile-history" || options.mode == "verify-profile-snapshots")
    {
        const bool fusion = options.verification_profile == "fusion-clean-cache";
        const bool encrypted = options.verification_profile == "encrypted-onekey-generation-zero";
        if ((!fusion && !encrypted) || has_device || options.duplicate_option || !options.profile.empty() || !options.device_id.empty() ||
            (fusion ? (!has_fusion || has_image || options.credential_stdin || options.fusion_convention != "linux-apfs-last-byte-low-bit") :
                (!has_image || has_fusion || !options.credential_stdin || !options.fusion_uuid.empty() || !options.fusion_convention.empty() ||
                 !options.tier2_offset.empty() || !options.tier2_size.empty() || !options.expected_tier2_identity.empty())))
            Fail("verify-profile requires exact supported profile/source selectors and encrypted credential pipe or explicit Fusion role convention");
        for (const auto* uuid : {&options.container_uuid, &options.volume_uuid})
            if (uuid->size() != 32 || uuid->find_first_not_of("0123456789abcdef") != std::string::npos || *uuid == std::string(32, '0'))
                Fail("profile UUIDs must be nonzero lowercase hex32");
        (void)ExactDecimal(options.volume_oid, "--volume-oid");
        (void)ExactDecimal(options.checkpoint_xid, "--checkpoint-xid");
        (void)ExactDecimal(options.store_offset_bytes, "--store-offset-bytes", true);
        (void)ExactDecimal(options.store_size_bytes, "--store-size-bytes");
        if (!options.retained_from_xid.empty()) (void)ExactDecimal(options.retained_from_xid, "--retained-from-xid");
        if (options.mode == "verify-profile-history" && (options.retained_from_xid.empty() ||
            ExactDecimal(options.retained_from_xid, "--retained-from-xid") >= ExactDecimal(options.checkpoint_xid, "--checkpoint-xid")))
            Fail("verify-profile-history requires an earlier explicit --retained-from-xid");
        if (options.mode == "verify-profile-snapshots" && !options.retained_from_xid.empty() &&
            ExactDecimal(options.retained_from_xid, "--retained-from-xid") >= ExactDecimal(options.checkpoint_xid, "--checkpoint-xid"))
            Fail("verify-profile-snapshots requires an earlier explicit --retained-from-xid when provided");
        if (fusion)
        {
            if (options.fusion_uuid.size() != 32 || options.fusion_uuid.find_first_not_of("0123456789abcdef") != std::string::npos || options.fusion_uuid == std::string(32, '0'))
                Fail("explicit Fusion UUID required");
            (void)ExactDecimal(options.tier2_offset, "--tier2-offset-bytes", true);
            (void)ExactDecimal(options.tier2_size, "--tier2-size-bytes");
        }
        return;
    }
    if (!options.verification_profile.empty() || !options.tier2_offset.empty() || !options.tier2_size.empty() ||
        !options.fusion_uuid.empty() || !options.fusion_convention.empty() || options.credential_stdin ||
        !options.expected_main_identity.empty() || !options.expected_tier2_identity.empty())
        Fail("current profile selectors require --mode verify-profile");
    const bool history = options.mode == "verify-history";
    const bool snapshot_query = options.mode == "snapshot-space" || options.mode == "snapshot-attribution" ||
        options.mode == "marked-reference-space" || options.mode == "marked-owner-space";
    if (options.account_retained_ownership && options.mode != "verify")
        Fail("--account-retained-ownership requires --mode verify");
    if (!history && options.mode != "marked-owner-space" && !options.retained_from_xid.empty()) Fail("--retained-from-xid requires --mode verify-history");
    if (options.mode == "marked-owner-space" && !options.retained_from_xid.empty() &&
        ExactDecimal(options.retained_from_xid, "--retained-from-xid") >= ExactDecimal(options.checkpoint_xid, "--checkpoint-xid"))
        Fail("marked-owner-space requires an earlier explicit retained checkpoint");
    if (options.profile.empty() && options.mode != "snapshots" && options.mode != "verify" && !snapshot_query && !history)
    {
        Fail("--profile is required");
    }
    if (options.mode != "collect" && options.mode != "fusion" && options.mode != "snapshots" &&
        options.mode != "verify" && !snapshot_query && !history)
    {
        Fail("--mode must be collect, fusion, snapshots, verify, verify-history, snapshot-space, or snapshot-attribution");
    }
    if (has_fusion && options.mode != "fusion")
    {
        Fail("two-store inputs require --mode fusion");
    }
    if ((has_image || has_device) && options.mode != "collect" && options.mode != "snapshots" &&
        options.mode != "verify" && !snapshot_query && !history)
    {
        Fail("single inputs require --mode collect");
    }
    if (!options.device_id.empty() && !IsValidSlug(options.device_id))
    {
        Fail("--device-id must match [A-Za-z0-9_.-]{1,128}");
    }
    if (options.mode == "verify" || snapshot_query || history)
    {
        if (snapshot_query && (options.require_whole_volume || options.require_payload_content_hashes))
            Fail("snapshot space query does not accept broader verification requests");
        if (!has_image || has_fusion || has_device) Fail("verification requires one regular --image input");
        std::string regular_path = options.image;
        std::replace(regular_path.begin(), regular_path.end(), '\\', '/');
        if (regular_path.starts_with("//./") || regular_path.starts_with("//?/") || regular_path.starts_with("/??/"))
            Fail("verification image cannot use a device namespace");
        const auto colon = regular_path.find(':');
        if (colon != std::string::npos && (colon != 1 ||
            !((regular_path[0] >= 'a' && regular_path[0] <= 'z') || (regular_path[0] >= 'A' && regular_path[0] <= 'Z')) ||
            regular_path.find(':', colon + 1) != std::string::npos))
            Fail("verification image cannot use an alternate data stream");
        if (options.duplicate_option) Fail("duplicate verification option");
        if (!options.profile.empty() || !options.device_id.empty()) Fail("verification does not accept profile or device selectors");
        for (const auto* uuid : {&options.container_uuid, &options.volume_uuid})
            if (uuid->size() != 32 || uuid->find_first_not_of("0123456789abcdef") != std::string::npos || *uuid == std::string(32, '0'))
                Fail("verification UUIDs must be nonzero lowercase 32-digit hex UUIDs");
        (void)ExactDecimal(options.volume_oid, "--volume-oid");
        (void)ExactDecimal(options.checkpoint_xid, "--checkpoint-xid");
        if (history)
        {
            if (options.require_whole_volume || options.require_payload_content_hashes)
                Fail("requested history cannot be combined with whole-volume or content-hash verification");
            if (ExactDecimal(options.retained_from_xid, "--retained-from-xid") >=
                ExactDecimal(options.checkpoint_xid, "--checkpoint-xid"))
                Fail("--retained-from-xid must precede the exact selected checkpoint");
        }
        (void)ExactDecimal(options.store_offset_bytes, "--store-offset-bytes", true);
        (void)ExactDecimal(options.store_size_bytes, "--store-size-bytes");
    }
    else if (options.mode == "snapshots")
    {
        if (!has_image || has_fusion || has_device)
            Fail("snapshot inventory requires one regular --image input");
        if (options.container_uuid.size() != 32 ||
            options.container_uuid.find_first_not_of("0123456789abcdef") != std::string::npos ||
            options.container_uuid == std::string(32, '0'))
            Fail("--container-uuid must be a nonzero lowercase 32-digit hex UUID");
        std::uint64_t oid = 0;
        const auto parsed = std::from_chars(options.volume_oid.data(),
            options.volume_oid.data() + options.volume_oid.size(), oid);
        if (parsed.ec != std::errc{} || parsed.ptr != options.volume_oid.data() + options.volume_oid.size() ||
            oid == 0 || options.volume_oid != std::to_string(oid))
            Fail("--volume-oid must be a nonzero canonical decimal object ID");
    }
    else if (!options.container_uuid.empty() || !options.volume_oid.empty())
        Fail("identity selectors require --mode snapshots or verify");
    if (options.mode != "verify" && !snapshot_query && !history && (!options.volume_uuid.empty() || !options.checkpoint_xid.empty() ||
        !options.store_offset_bytes.empty() || !options.store_size_bytes.empty() ||
        options.require_whole_volume || options.require_payload_content_hashes))
        Fail("exact verification selectors require --mode verify");
}

#ifdef _WIN32
// Common regular-image verification lease, also used by the encrypted reader.
class VerificationImageLease final : public apfsaccess::catalog::RandomAccessSource
{
public:
    explicit VerificationImageLease(const std::string& path)
        try : lease_(ToWide(path)) {}
        catch (const std::runtime_error& error) {
            if (std::string(error.what()) == "RegularImageRequired")
                Fail("verification lease requires a regular non-reparse image file");
            Fail("cannot acquire read-only verification image lease");
        }
    std::uint64_t SizeBytes() const override { return lease_.SizeBytes(); }
    std::string Identity() const { return lease_.Identity(); }
    bool VerifyUnchanged() const { return lease_.VerifyUnchanged(); }
    bool Read(std::uint64_t offset, std::size_t size, std::vector<std::byte>& bytes) const override
        { return lease_.Read(offset, size, bytes); }
private:
    apfsaccess::transport::WindowsImageLease lease_;
};
#endif

std::string VerificationJson(const apfsaccess::catalog::VerificationReport& report, const std::string& image_path)
{
    using namespace apfsaccess::catalog;
    if (report.requested_scope.retained_from_xid || report.requested_history)
        throw std::length_error("requested history requires its explicit report transport");
    if (report.requested_scope.observe_payload_content)
    {
        std::string output;
        payload::Reason failure;
        if (!SerializeImageVerificationReport(report, image_path, [] { return true; },
                MaxImageVerificationJsonBytes, output, failure))
            throw std::length_error("verification report cannot be serialized");
        return output;
    }
    // Reserve the Windows stdout CRLF within the shared 64 MiB byte limit.
    constexpr std::size_t max_json_bytes = 64ull * 1024 * 1024 - 2;
    JsonWriter json;
    const auto number = [&](std::uint64_t n) { json.String(std::to_string(n)); };
    const auto optional = [&](const std::optional<std::uint64_t>& n) { if (n) number(*n); else json.Null(); };
    const auto identity = [&](const ApfsSnapshotScope& scope) {
        json.Key("containerUuid"); json.String(scope.container_uuid_hex);
        json.Key("volumeUuid"); json.String(scope.volume_uuid_hex);
        json.Key("volumeOid"); number(scope.volume_oid);
        json.Key("checkpointXid"); number(scope.checkpoint_xid);
        json.Key("storeOffsetBytes"); number(scope.store_offset_bytes);
        json.Key("storeSizeBytes"); number(scope.store_size_bytes);
    };
    json.BeginObject();
    json.Key("format"); json.String("apfs-access-verification");
    json.Key("version"); json.Integer(2);
    json.Key("readOnly"); json.Bool(true);
    json.Key("source"); json.BeginObject();
    json.Key("kind"); json.String("image");
    json.Key("path"); json.String(image_path);
    json.Key("identity"); json.String(report.requested_scope.source_identity);
    json.Key("lease"); json.String("windows-read-deny-write-delete");
    json.EndObject();
    json.Key("requestedScope"); json.BeginObject(); identity(report.requested_scope.exact);
    json.Key("maxReads"); number(report.requested_scope.max_reads);
    json.Key("maxReadBytes"); number(report.requested_scope.max_read_bytes);
    json.Key("maxRecords"); number(report.requested_scope.max_records);
    json.Key("maxRecordBytes"); number(report.requested_scope.max_record_bytes);
    json.Key("requireWholeVolume"); json.Bool(report.requested_scope.require_whole_volume);
    json.Key("requirePayloadContentHashes"); json.Bool(report.requested_scope.require_payload_content_hashes);
    json.EndObject();
    json.Key("selected");
    if (report.selected)
    {
        const auto& selected = *report.selected;
        json.BeginObject(); identity(selected.exact);
        json.Key("checkpointPhysicalBlock"); number(selected.checkpoint_physical_block);
        json.Key("volumeSuperblockPhysicalBlock"); number(selected.volume_superblock_physical_block);
        json.Key("volumeSuperblockXid"); number(selected.volume_superblock_xid);
        json.Key("rootOid"); number(selected.root_oid);
        json.Key("rootPhysicalBlock"); number(selected.root_physical_block);
        json.EndObject();
    }
    else json.Null();
    json.Key("outcome"); json.Integer(static_cast<unsigned>(report.outcome));
    json.Key("outcomeName"); json.String(report.outcome == VerificationOutcome::Complete ? "Complete" :
        report.outcome == VerificationOutcome::Refused ? "Refused" : "Incomplete");
    json.Key("wholeVolumeVerified"); json.Bool(report.whole_volume_verified);
    json.Key("payloadContentHashesVerified"); json.Bool(report.payload_content_hashes_verified);
    json.Key("sourceReads"); number(report.source_reads);
    json.Key("sourceReadBytes"); number(report.source_read_bytes);
    json.Key("coveredFilesystemRecords"); number(report.covered_filesystem_records);
    json.Key("coveredPhysicalExtents"); number(report.covered_physical_extents);
    // These are observations of the admitted current graph, never reclaim candidates.
    json.Key("allocationCensus");
    if (report.allocation_census)
    {
        const auto& census = *report.allocation_census;
        json.BeginObject();
        json.Key("blockSizeBytes"); number(census.block_size_bytes);
        json.Key("containerBlockCount"); number(census.container_block_count);
        json.Key("currentMetadataBlocks"); number(census.current_metadata_blocks);
        json.Key("currentPayloadBlocks"); number(census.current_payload_blocks);
        json.Key("unattributedMainBlocks"); number(census.unattributed_main_blocks);
        json.Key("unattributedInternalBlocks"); number(census.unattributed_internal_blocks);
        const auto ranges = [&](const char* key, const auto& values) {
            json.Key(key); json.BeginArray();
            for (const auto& range : values)
            {
                json.BeginObject();
                json.Key("physicalBlock"); number(range.physical_block);
                json.Key("blockCount"); number(range.block_count);
                json.EndObject();
                if (json.Text().size() > max_json_bytes)
                    throw std::length_error("verification report exceeds transport limit");
            }
            json.EndArray();
        };
        ranges("unattributedMainRanges", census.unattributed_main_ranges);
        ranges("unattributedInternalRanges", census.unattributed_internal_ranges);
        json.EndObject();
    }
    else json.Null();
    json.Key("findings"); json.BeginArray();
    for (const auto& finding : report.findings)
    {
        json.BeginObject();
        json.Key("code"); json.Integer(static_cast<unsigned>(finding.code));
        json.Key("severity"); json.Integer(static_cast<unsigned>(finding.severity));
        json.Key("check"); json.Integer(static_cast<unsigned>(finding.check));
        json.Key("volumeOid"); optional(finding.volume_oid);
        json.Key("objectId"); optional(finding.object_id);
        json.Key("physicalBlock"); optional(finding.physical_block);
        json.Key("checkpointXid"); optional(finding.checkpoint_xid);
        json.Key("failedSourceOffsetBytes"); optional(finding.failed_source_offset_bytes);
        json.Key("detail"); json.String(finding.detail);
        json.EndObject();
    }
    json.EndArray();
    json.Key("coverage"); json.BeginArray();
    for (const auto& coverage : report.coverage)
    {
        json.BeginObject();
        json.Key("check"); json.Integer(static_cast<unsigned>(coverage.check));
        json.Key("implemented"); json.Bool(coverage.implemented);
        json.Key("required"); json.Bool(coverage.required);
        json.Key("state"); json.Integer(static_cast<unsigned>(coverage.state));
        json.Key("scopeDetail"); json.String(coverage.scope_detail);
        json.EndObject();
    }
    json.EndArray();
    json.Key("repair"); json.BeginObject();
    json.Key("planId"); json.String(report.repair.plan_id);
    json.Key("refusal"); json.Integer(static_cast<unsigned>(report.repair.refusal));
    json.Key("nextActionableCandidate"); json.Null();
    json.EndObject(); json.EndObject();
    if (json.Text().size() > max_json_bytes)
        throw std::length_error("verification report exceeds transport limit");
    return json.Text();
}

#ifdef _WIN32
class ObservedImageVerificationSource final : public apfsaccess::catalog::RandomAccessSource
{
public:
    ObservedImageVerificationSource(const VerificationImageLease& lease,
        const apfsaccess::catalog::VerificationScope& scope, const std::function<bool()>& within_deadline)
        : lease_(lease), within_deadline_(within_deadline), budget_(std::make_shared<apfsaccess::catalog::ApfsReadBudget>(
            scope.max_reads, scope.max_read_bytes, scope.max_records, scope.max_record_bytes)) {}
    std::uint64_t SizeBytes() const override { return lease_.SizeBytes(); }
    std::shared_ptr<apfsaccess::catalog::ApfsReadBudget> ReadBudget() const override { return budget_; }
    bool Read(std::uint64_t offset, std::size_t size, std::vector<std::byte>& bytes) const override
    {
        bytes.clear();
        if (!within_deadline_ || !within_deadline_()) return budget_->Refuse("ImageVerificationTimeLimit");
        if (!budget_->Read(size)) return false;
        const bool read = lease_.Read(offset, size, bytes) && bytes.size() == size;
        if (!within_deadline_()) { bytes.clear(); return budget_->Refuse("ImageVerificationTimeLimit"); }
        return read;
    }
private:
    const VerificationImageLease& lease_;
    const std::function<bool()>& within_deadline_;
    std::shared_ptr<apfsaccess::catalog::ApfsReadBudget> budget_;
};

// The lease remains held across verification, response materialization and the
// final identity check. Engine-owned store views perform the sole base translation.
bool BuildObservedImageVerification(const VerificationImageLease& source,
    apfsaccess::catalog::VerificationScope scope, const std::string& image_path,
    const std::function<bool()>& within_deadline, std::size_t response_limit,
    apfsaccess::catalog::VerificationReport& report, std::string& json, apfsaccess::catalog::payload::Reason& failure)
{
    using namespace apfsaccess::catalog;
    json.clear();
    if (!source.VerifyUnchanged() || scope.source_identity != source.Identity())
    { failure = payload::Reason::InvalidBinding; return false; }
    scope.observe_payload_content = !scope.retained_from_xid.has_value();
    ObservedImageVerificationSource bounded(source, scope, within_deadline);
    report = ApfsVerifier::VerifyReadOnly(bounded, scope, within_deadline);
    const bool serialized = scope.retained_from_xid
        ? SerializeProtectedHistoryVerificationReport(report, image_path, within_deadline, response_limit, json, failure)
        : SerializeImageVerificationReport(report, image_path, within_deadline, response_limit, json, failure);
    if (!serialized) return false;
    if (!source.VerifyUnchanged())
    { json.clear(); failure = payload::Reason::InvalidBinding; return false; }
    return true;
}
#endif

#include "ObserverProfileVerification.h"

int ObserveVerification(const ObserverOptions& options)
{
#ifdef _WIN32
    using namespace apfsaccess::catalog;
    RequireRegularInputFile(options.image, "verification input");
    VerificationImageLease source(options.image);
    VerificationScope scope;
    scope.source_identity = source.Identity();
    scope.exact = {ExactDecimal(options.store_offset_bytes, "--store-offset-bytes", true),
        ExactDecimal(options.store_size_bytes, "--store-size-bytes"), options.container_uuid, options.volume_uuid,
        ExactDecimal(options.volume_oid, "--volume-oid"), ExactDecimal(options.checkpoint_xid, "--checkpoint-xid")};
    scope.require_whole_volume = options.require_whole_volume;
    scope.require_payload_content_hashes = options.require_payload_content_hashes;
    scope.account_retained_ownership = options.account_retained_ownership;
    if (options.mode == "verify-history")
        scope.retained_from_xid = ExactDecimal(options.retained_from_xid, "--retained-from-xid");
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(60);
    const auto within_deadline = [deadline] { return std::chrono::steady_clock::now() < deadline; };
    VerificationReport report;
    std::string json;
    payload::Reason failure;
    try {
        if (!BuildObservedImageVerification(source, scope, options.image, within_deadline,
                MaxImageVerificationJsonBytes, report, json, failure))
            Fail("verification response refused: " + std::string(payload::Name(failure)));
    }
    catch (const std::length_error&) { Fail("verification report exceeds transport limit"); }
    catch (const std::bad_alloc&) { Fail("cannot materialize verification report"); }
    const int semantic_exit_code = report.outcome == VerificationOutcome::Complete ? 0 : report.outcome == VerificationOutcome::Refused ? 4 : 3;
    if (options.out_path.empty()) return WriteStdoutEvidence(json, semantic_exit_code);
    else PublishEvidence(json, options.out_path, {options.image});
    return semantic_exit_code;
#else
    (void)options;
    Fail("verification requires the Windows stable image lease implementation");
#endif
}

// Explicit query only: regular catalog inventory never invokes this census.
int ObserveSnapshotSpace(const ObserverOptions& options)
{
#ifdef _WIN32
    using namespace apfsaccess::catalog;
    VerificationImageLease source(options.image);
    VerificationScope scope;
    scope.source_identity = source.Identity();
    scope.exact = {ExactDecimal(options.store_offset_bytes, "--store-offset-bytes", true),
        ExactDecimal(options.store_size_bytes, "--store-size-bytes"), options.container_uuid,
        options.volume_uuid, ExactDecimal(options.volume_oid, "--volume-oid"),
        ExactDecimal(options.checkpoint_xid, "--checkpoint-xid")};
    std::optional<ApfsSnapshotPayloadSpaceObservation> observation;
    std::string error;
    const bool observed = TryObserveAppleSnapshotPayloadSpace(source, scope, observation, error);
    if (!source.VerifyUnchanged()) Fail("snapshot space input changed during observation");

    JsonWriter json;
    json.BeginObject();
    json.Key("format"); json.String("apfs-access-snapshot-payload-space");
    json.Key("version"); json.Integer(1);
    json.Key("readOnly"); json.Bool(true);
    json.Key("status"); json.String(observed ? "observed" : "unknown");
    json.Key("accountingScope"); json.String("snapshot-payload-only");
    json.Key("source"); json.BeginObject();
    json.Key("kind"); json.String("image");
    json.Key("path"); json.String(options.image);
    json.Key("identity"); json.String(scope.source_identity);
    json.EndObject();
    json.Key("requested"); json.BeginObject();
    json.Key("containerUuid"); json.String(scope.exact.container_uuid_hex);
    json.Key("volumeUuid"); json.String(scope.exact.volume_uuid_hex);
    json.Key("volumeOid"); json.String(options.volume_oid);
    json.Key("checkpointXid"); json.String(options.checkpoint_xid);
    json.Key("storeOffsetBytes"); json.String(options.store_offset_bytes);
    json.Key("storeSizeBytes"); json.String(options.store_size_bytes);
    json.EndObject();
    json.Key("allocationUnitBytes");
    if (observation) json.Integer(observation->allocation_unit_bytes); else json.Null();
    json.Key("snapshotCount");
    if (observation) json.String(std::to_string(observation->snapshot_count)); else json.Null();
    json.Key("snapshotPayloadReferenced");
    if (observation) WriteAmount(json, observation->referenced_payload); else json.Null();
    json.Key("snapshotPayloadSharedWithLive");
    if (observation) WriteAmount(json, observation->shared_with_live_payload); else json.Null();
    json.Key("snapshotPayloadAbsentFromLive");
    if (observation) WriteAmount(json, observation->absent_from_live_payload); else json.Null();
    // Payload reachability supplies no authority for any of these totals.
    json.Key("snapshot"); json.Null();
    json.Key("purgeable"); json.Null();
    json.Key("reclaimable"); json.Null();
    json.Key("reason"); if (observed) json.Null(); else json.String(error);
    json.EndObject();
    const int semantic_exit = observed ? 0 : 3;
    if (options.out_path.empty()) return WriteStdoutEvidence(json.Text(), semantic_exit);
    PublishEvidence(json.Text(), options.out_path, {options.image});
    return semantic_exit;
#else
    (void)options;
    Fail("snapshot space observation requires the Windows stable image lease implementation");
#endif
}

int ObserveSnapshotAttribution(const ObserverOptions& options, bool marked_references = false, bool marked_owners = false)
{
#ifdef _WIN32
    using namespace apfsaccess::catalog;
    VerificationImageLease source(options.image);
    VerificationScope scope;
    scope.source_identity = source.Identity();
    scope.exact = {ExactDecimal(options.store_offset_bytes, "--store-offset-bytes", true),
        ExactDecimal(options.store_size_bytes, "--store-size-bytes"), options.container_uuid,
        options.volume_uuid, ExactDecimal(options.volume_oid, "--volume-oid"),
        ExactDecimal(options.checkpoint_xid, "--checkpoint-xid")};
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(60);
    const auto within_deadline = [deadline] { return std::chrono::steady_clock::now() < deadline; };
    std::optional<ApfsSnapshotSpaceAttribution> observation;
    std::optional<ApfsMarkedReferenceSpaceObservation> marked;
    std::optional<ApfsMarkedOwnerSpaceAttribution> owners;
    const auto from = options.retained_from_xid.empty() ? std::optional<std::uint64_t>{} :
        std::optional<std::uint64_t>{ExactDecimal(options.retained_from_xid, "--retained-from-xid")};
    std::string error, text;
    payload::Reason failure;
    const bool observed = marked_owners ?
        TryAttributeAppleMarkedOwnerSpaceReadOnly(source, scope, from, owners, error, within_deadline) : marked_references ?
        TryObserveAppleMarkedReferenceSpaceReadOnly(source, scope, marked, error, within_deadline) :
        TryAttributeAppleSnapshotSpaceReadOnly(source, scope, observation, error, within_deadline);
    if (observed)
    {
        const bool encoded = marked_owners ?
            SerializeMarkedOwnerSpaceAttribution(owners, scope, from, options.image, within_deadline,
                MaxSnapshotSpaceAttributionJsonBytes, text, failure) : marked_references ?
            SerializeMarkedReferenceSpace(marked, scope, options.image, within_deadline,
                MaxSnapshotSpaceAttributionJsonBytes, text, failure) :
            SerializeSnapshotSpaceAttribution(observation, scope, options.image, within_deadline,
                MaxSnapshotSpaceAttributionJsonBytes, text, failure);
        if (!encoded)
            Fail("snapshot attribution response refused: " + std::string(payload::Name(failure)));
    }
    else
    {
        JsonWriter json;
        json.BeginObject();
        json.Key("format"); json.String(marked_owners ? "apfs-access-marked-owner-space-attribution" : marked_references ? "apfs-access-marked-reference-space" : "apfs-access-snapshot-space-attribution");
        json.Key("version"); json.Integer(marked_owners ? 1 : marked_references ? MarkedReferenceSpaceVersion : SnapshotSpaceAttributionVersion);
        json.Key("readOnly"); json.Bool(true);
        json.Key("complete"); json.Bool(false);
        if (marked_owners) { json.Key("fromXid"); if (from) json.String(options.retained_from_xid); else json.Null(); }
        json.Key("source"); json.BeginObject();
        json.Key("path"); json.String(options.image);
        json.Key("identity"); json.String(scope.source_identity);
        json.EndObject();
        json.Key("scope"); json.BeginObject();
        json.Key("containerUuid"); json.String(options.container_uuid);
        json.Key("volumeUuid"); json.String(options.volume_uuid);
        json.Key("volumeOid"); json.String(options.volume_oid);
        json.Key("checkpointXid"); json.String(options.checkpoint_xid);
        json.Key("storeOffsetBytes"); json.String(options.store_offset_bytes);
        json.Key("storeSizeBytes"); json.String(options.store_size_bytes);
        json.EndObject();
        json.Key("reason"); json.String(error.empty() ? "SnapshotAttributionIncomplete" : error);
        json.EndObject();
        text = json.Text();
    }
    if (!source.VerifyUnchanged()) Fail("snapshot attribution input changed during observation");
    const int semantic_exit = observed ? 0 : 3;
    if (options.out_path.empty()) return WriteStdoutEvidence(text, semantic_exit);
    PublishEvidence(text, options.out_path, {options.image});
    return semantic_exit;
#else
    (void)options;
    Fail("snapshot attribution requires the Windows stable image lease implementation");
#endif
}

int ObserveSnapshots(const ObserverOptions& options)
{
    using namespace apfsaccess::catalog;
    RequireRegularInputFile(options.image, "snapshot input");
    HeldFileSource source(options.image);
    if (!source.IsOpen()) Fail("cannot open snapshot input");
    const auto digest = HashHeldSource(source, options.image);
    auto budget = std::make_shared<ApfsReadBudget>(65536, 256ull * 1024 * 1024,
        1024 * 1024, 256ull * 1024 * 1024);
    BudgetedRandomAccessSource bounded(source, budget);
    ApfsContainerCatalog catalog;
    std::string error;
    if (!ApfsContainerCatalog::TryLoadImage(bounded, "snapshot-inventory", options.image,
            catalog, error, CatalogLoadPolicy::StrictApple))
        Fail("snapshot catalog failed: " + error);
    std::uint64_t oid = 0;
    std::from_chars(options.volume_oid.data(), options.volume_oid.data() + options.volume_oid.size(), oid);
    ResolvedMountVolume volume;
    if (!catalog.TryResolveVolume(options.container_uuid, oid, volume, error))
        Fail("snapshot volume selection failed: " + error);
    const ApfsContainerDescriptor* container = nullptr;
    const ApfsPhysicalStoreDescriptor* store = nullptr;
    for (const auto& item : catalog.Containers())
    {
        if (item.container_uuid_hex != options.container_uuid) continue;
        if (container) Fail("ambiguous snapshot container");
        container = &item;
    }
    if (!container || container->fusion || container->member_store_ids.size() != 1)
        Fail("snapshot inventory requires an exact single-store container");
    for (const auto& item : catalog.Stores())
    {
        if (item.stable_store_id != container->member_store_ids.front()) continue;
        if (store || item.container_uuid_hex != options.container_uuid)
            Fail("ambiguous snapshot store");
        store = &item;
    }
    if (!store) Fail("snapshot store is absent");
    const ApfsSnapshotScope scope{store->offset_bytes, store->size_bytes,
        options.container_uuid, volume.volume_uuid_hex, oid, container->checkpoint_xid};
    std::vector<ApfsSnapshotInfo> snapshots;
    if (!ApfsSnapshotStore::Enumerate(bounded, scope, snapshots, error))
        Fail("snapshot enumeration failed: " + error);
    if (!source.VerifyUnchanged(error)) Fail("snapshot input changed: " + error);

    JsonWriter json;
    json.BeginObject();
    json.Key("format"); json.String("apfs-access-snapshot-inventory");
    json.Key("version"); json.Integer(1);
    json.Key("readOnly"); json.Bool(true);
    json.Key("source"); WriteSource(json, "image", options.image, digest.size_bytes, "full", digest.hex);
    json.Key("containerUuid"); json.String(scope.container_uuid_hex);
    json.Key("volumeUuid"); json.String(scope.volume_uuid_hex);
    json.Key("volumeId"); json.String("apfs-vol:" + scope.container_uuid_hex + ":" + options.volume_oid);
    // Identities and nanosecond counters stay exact in JavaScript JSON consumers.
    json.Key("volumeOid"); json.String(options.volume_oid);
    json.Key("checkpointXid"); json.String(std::to_string(scope.checkpoint_xid));
    json.Key("storeOffsetBytes"); json.String(std::to_string(scope.store_offset_bytes));
    json.Key("storeSizeBytes"); json.String(std::to_string(scope.store_size_bytes));
    json.Key("snapshots"); json.BeginArray();
    for (const auto& snapshot : snapshots)
    {
        const auto& id = snapshot.identity;
        json.BeginObject();
        json.Key("xid"); json.String(std::to_string(id.snapshot_xid));
        json.Key("name"); json.String(id.name_utf8);
        json.Key("uuid");
        if (snapshot.snapshot_uuid_hex) json.String(*snapshot.snapshot_uuid_hex);
        else json.Null();
        json.Key("createTimeNs"); json.String(std::to_string(snapshot.metadata.create_time_ns));
        json.Key("superblockPhysicalBlock"); json.String(std::to_string(id.superblock_physical_block));
        json.Key("omapPhysicalBlock"); json.String(std::to_string(id.omap_physical_block));
        json.Key("omapTreePhysicalBlock"); json.String(std::to_string(id.omap_tree_physical_block));
        json.Key("rootOid"); json.String(std::to_string(id.root_oid));
        json.Key("rootPhysicalBlock"); json.String(std::to_string(id.root_physical_block));
        json.Key("extentrefPhysicalBlock"); json.String(std::to_string(id.extentref_physical_block));
        json.EndObject();
    }
    json.EndArray(); json.EndObject();
    if (options.out_path.empty()) return WriteStdoutEvidence(json.Text(), 0);
    else PublishEvidence(json.Text(), options.out_path, {options.image});
    return 0;
}

std::string DefaultDeviceId(const std::string& path, const std::string& fallback)
{
    const std::size_t slash = path.find_last_of("/\\");
    std::string base = slash == std::string::npos ? path : path.substr(slash + 1);
    std::string slug;
    for (char ch : base)
    {
        slug.push_back(IsSlugChar(ch) ? ch : '-');
    }
    while (!slug.empty() && slug.front() == '-')
    {
        slug.erase(slug.begin());
    }
    if (slug.empty() || !IsValidSlug(slug))
    {
        return fallback;
    }
    return slug;
}

} // namespace

// Existing consumer tests include this file with main renamed. Keep that
// narrow UTF-8 entry for them and for non-Windows builds.
#if defined(_WIN32) && !defined(main)
int ObserverUtf8Main(int argc, char** argv)
#else
int main(int argc, char** argv)
#endif
{
    if (argc <= 1)
    {
        return Usage();
    }
    const ObserverOptions options = ParseOptions(argc, argv);
    ValidateOptions(options);
    if (options.mode == "verify-profile") return ObserveCurrentProfile(options);
    if (options.mode == "verify-profile-history") return ObserveCurrentProfile(options, true);
    if (options.mode == "verify-profile-snapshots") return ObserveCurrentProfile(options, false, true);
    if (options.mode == "snapshot-space") return ObserveSnapshotSpace(options);
    if (options.mode == "snapshot-attribution") return ObserveSnapshotAttribution(options);
    if (options.mode == "marked-reference-space") return ObserveSnapshotAttribution(options, true);
    if (options.mode == "marked-owner-space") return ObserveSnapshotAttribution(options, false, true);
    if (options.mode == "snapshots") return ObserveSnapshots(options);
    if (options.mode == "verify" || options.mode == "verify-history") return ObserveVerification(options);

    using apfsaccess::catalog::ApfsContainerCatalog;
    using apfsaccess::catalog::HeldFileSource;

    JsonWriter json;
    json.BeginObject();
    json.Key("format");
    json.String(kFormat);
    json.Key("version");
    json.Integer(kVersion);
    json.Key("topologyMetadataVersion");
    json.Integer(1);
    json.Key("observerId");
    json.String(kObserverId);
    json.Key("observerVersion");
    json.String(kObserverVersion);
    json.Key("mode");
    json.String(options.mode);
    json.Key("profile");
    json.String(options.profile);
    json.Key("synthetic");
    json.Bool(false);

    const std::string primary_path = !options.image.empty()
        ? options.image
        : (!options.store_a.empty() ? options.store_a : options.device);
    const std::string disk_id = options.device_id.empty()
        ? DefaultDeviceId(primary_path, "observed")
        : options.device_id;

    if (!options.device.empty())
    {
#ifdef _WIN32
        apfsaccess::rw::BlockDevice device(ToWide(options.device));
        ApfsContainerCatalog catalog;
        std::wstring werror;
        if (!ApfsContainerCatalog::TryLoadDevice(device, catalog, werror))
        {
            std::string narrow;
            for (wchar_t ch : werror)
            {
                narrow.push_back(ch < 0x80 ? static_cast<char>(ch) : '?');
            }
            Fail("device catalog failed: " + narrow);
        }
        const std::uint64_t size = device.GetGeometry().total_bytes;
        json.Key("source");
        WriteSource(json, "device", options.device, size, "none", "");
        json.Key("secondarySources");
        json.BeginArray();
        json.EndArray();
        json.Key("topology");
        WriteTopology(json, catalog, disk_id, options.device, size, catalog.DiskGuid());
#else
        Fail("--device requires a Windows observer build");
#endif
    }
    else
    {
        if (!options.store_b.empty() && SameFile(options.store_a, options.store_b))
        {
            Fail("fusion inputs are hard-link aliases of the same file");
        }
        // One held handle feeds hashing AND parsing for each input; the
        // identity is re-verified afterwards, closing the open-hash-parse
        // replacement window to a same-size same-mtime swap (documented
        // residual in HeldFileSource).
        RequireRegularInputFile(primary_path, "primary input");
        HeldFileSource primary_source(primary_path);
        if (!primary_source.IsOpen())
        {
            Fail("cannot open observer input: " + primary_path);
        }
        const SourceHash primary_hash = HashHeldSource(primary_source, primary_path);
        ApfsContainerCatalog primary_catalog;
        std::string error;
        if (!ApfsContainerCatalog::TryLoadImage(
                primary_source, disk_id, primary_path, primary_catalog, error,
                apfsaccess::catalog::CatalogLoadPolicy::StrictApple))
        {
            Fail("primary input catalog failed: " + error);
        }
        if (!primary_source.VerifyUnchanged(error))
        {
            Fail("primary input changed during observation: " + error);
        }
        json.Key("source");
        WriteSource(json, "image", primary_path, primary_hash.size_bytes, "full", primary_hash.hex);
        // F1: store B is opened, hashed, parsed, and verified EXACTLY ONCE
        // here; the validated catalog and digest below feed BOTH the
        // secondarySources entry and the merge, so no second handle can
        // bind a different byte generation to the recorded hash.
        ApfsContainerCatalog second_catalog;
        SourceHash second_hash;
        std::string second_disk;
        const bool is_fusion = !options.store_b.empty();
        if (is_fusion)
        {
            RequireRegularInputFile(options.store_b, "fusion store B");
            HeldFileSource second_source(options.store_b);
            if (!second_source.IsOpen())
            {
                Fail("cannot open observer input: " + options.store_b);
            }
            second_hash = HashHeldSource(second_source, options.store_b);
            second_disk = disk_id + "-b";
            std::string second_error;
            if (!ApfsContainerCatalog::TryLoadImage(
                    second_source, second_disk, options.store_b, second_catalog, second_error,
                    apfsaccess::catalog::CatalogLoadPolicy::StrictApple))
            {
                Fail("fusion store B catalog failed: " + second_error);
            }
            if (!second_source.VerifyUnchanged(second_error))
            {
                Fail("fusion store B changed during observation: " + second_error);
            }
        }
        json.Key("secondarySources");
        json.BeginArray();
        if (is_fusion)
        {
            WriteSource(json, "image", options.store_b,
                second_hash.size_bytes, "full", second_hash.hex);
        }
        json.EndArray();
        json.Key("topology");
        if (!is_fusion)
        {
            WriteTopology(json, primary_catalog, disk_id, primary_path,
                primary_hash.size_bytes, primary_catalog.DiskGuid());
        }
        else
        {
            // Fusion: the two inputs must each contribute exactly one member
            // store of the same container, with disjoint partition identities.
            if (primary_catalog.Containers().size() != 1 ||
                second_catalog.Containers().size() != 1)
            {
                Fail("fusion inputs must each describe exactly one container");
            }
            if (primary_catalog.Stores().size() != 1 || second_catalog.Stores().size() != 1)
            {
                Fail("fusion inputs must each contribute exactly one member store");
            }
            if (primary_catalog.Partitions().empty() || second_catalog.Partitions().empty())
            {
                Fail("fusion inputs must be GPT-partitioned images with distinct partition GUIDs");
            }
            for (const auto& first_partition : primary_catalog.Partitions())
            {
                for (const auto& second_partition : second_catalog.Partitions())
                {
                    if (first_partition.partition_guid == second_partition.partition_guid)
                    {
                        Fail("fusion inputs share a partition identity");
                    }
                }
            }
            const auto merged = MergeFusionContainer(
                primary_catalog.Containers()[0], second_catalog.Containers()[0]);
            WriteFusionTopology(json, primary_catalog, disk_id, primary_path,
                primary_hash.size_bytes, second_catalog, second_disk, options.store_b,
                second_hash.size_bytes, merged);
        }
    }
    json.EndObject();
    const std::string text = json.Text();

    if (!options.out_path.empty())
    {
        std::vector<std::string> inputs{primary_path};
        if (!options.store_b.empty())
        {
            inputs.push_back(options.store_b);
        }
        PublishEvidence(text, options.out_path, inputs);
        return 0;
    }
    return WriteStdoutEvidence(text, 0);
}

#if defined(_WIN32) && !defined(main)
int wmain(int argc, wchar_t** argv)
{
    std::vector<std::string> arguments;
    arguments.reserve(static_cast<std::size_t>(argc));
    for (int index = 0; index < argc; ++index) arguments.push_back(ToUtf8(argv[index]));
    std::vector<char*> utf8_argv;
    utf8_argv.reserve(arguments.size() + 1);
    for (auto& argument : arguments) utf8_argv.push_back(argument.data());
    utf8_argv.push_back(nullptr);
    return ObserverUtf8Main(argc, utf8_argv.data());
}
#endif
