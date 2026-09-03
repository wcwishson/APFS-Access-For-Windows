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
#include <Windows.h>
#include <bcrypt.h>

#include "ApfsContainerCatalog.h"
#include "ApfsFormat.h"
#include "BlockDevice.h"
#include "RandomAccessSource.h"

#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

namespace
{
constexpr char kFormat[] = "apfs-access-raw-evidence";
constexpr int kVersion = 1;
constexpr char kObserverId[] = "apfs-access-owned-raw-observer";
constexpr char kObserverVersion[] = "1.0.0";

int Usage()
{
    std::cerr << "Usage:\n"
              << "  ApfsObserver --image <file> --profile <name> --mode collect "
                 "[--device-id <slug>] [--out <file>]\n"
              << "  ApfsObserver --store-a <file> --store-b <file> --profile <name> "
                 "--mode fusion [--device-id <slug>] [--out <file>]\n"
              << "  ApfsObserver --device <path> --profile <name> --mode collect "
                 "[--device-id <slug>] [--out <file>]\n"
              << "  ApfsObserver --help\n";
    return 2;
}

[[noreturn]] void Fail(const std::string& message)
{
    std::cerr << "error: " << message << "\n";
    std::exit(2);
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

std::wstring ToWide(const std::string& text)
{
    if (text.empty())
    {
        return std::wstring{};
    }
    const int needed = MultiByteToWideChar(
        CP_UTF8, MB_ERR_INVALID_CHARS, text.c_str(), -1, nullptr, 0);
    if (needed <= 1)
    {
        Fail("device path is not valid UTF-8");
    }
    std::wstring wide(static_cast<std::size_t>(needed) - 1, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, text.c_str(), -1, wide.data(), needed);
    return wide;
}

void RequireRegularInputFile(const std::string& path, const std::string& what)
{
    namespace fs = std::filesystem;
    std::error_code code;
    if (fs::is_symlink(path, code) && !code)
    {
        Fail(std::string("refusing symlinked observer input: ") + what);
    }
    if (!fs::is_regular_file(path, code) || code)
    {
        Fail(std::string("observer input is not a regular file: ") + what);
    }
}

struct SourceHash
{
    std::string hex; // "" when unhashed
    std::uint64_t size_bytes = 0;
};

// Streams SHA-256 over an image file in 1 MiB chunks (CNG, per plan crypto).
SourceHash HashImageFile(const std::string& path)
{
    SourceHash out;
    apfsaccess::catalog::FileRandomAccessSource source(path);
    if (!source.IsOpen())
    {
        Fail("cannot open observer input for hashing: " + path);
    }
    out.size_bytes = source.SizeBytes();
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0)
    {
        Fail("CNG SHA-256 provider unavailable");
    }
    if (BCryptCreateHash(algorithm, &hash, nullptr, 0, nullptr, 0, 0) != 0)
    {
        BCryptCloseAlgorithmProvider(algorithm, 0);
        Fail("CNG SHA-256 init failed");
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
        if (BCryptHashData(
                hash, reinterpret_cast<PUCHAR>(chunk.data()), static_cast<ULONG>(want), 0) != 0)
        {
            failed = true;
            break;
        }
        offset += want;
    }
    unsigned char digest[32] = {};
    if (!failed && BCryptFinishHash(hash, digest, sizeof(digest), 0) != 0)
    {
        failed = true;
    }
    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(algorithm, 0);
    if (failed)
    {
        Fail("hashing observer input failed: " + path);
    }
    static constexpr char kHex[] = "0123456789abcdef";
    for (unsigned char byte : digest)
    {
        out.hex.push_back(kHex[(byte >> 4) & 0xF]);
        out.hex.push_back(kHex[byte & 0xF]);
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
    json.String("apfs");
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
    json.EndObject();
}

void WriteContainer(JsonWriter& json, const apfsaccess::catalog::ApfsContainerDescriptor& container)
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
        WriteContainer(json, container);
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
                other.volume_uuid_hex == volume.volume_uuid_hex)
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
};

ObserverOptions ParseOptions(int argc, char** argv)
{
    ObserverOptions options;
    for (int index = 1; index < argc; ++index)
    {
        const std::string arg = argv[index];
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
    if (options.profile.empty())
    {
        Fail("--profile is required");
    }
    if (options.mode != "collect" && options.mode != "fusion")
    {
        Fail("--mode must be collect or fusion");
    }
    if (has_fusion && options.mode != "fusion")
    {
        Fail("two-store inputs require --mode fusion");
    }
    if ((has_image || has_device) && options.mode != "collect")
    {
        Fail("single inputs require --mode collect");
    }
    if (!options.device_id.empty() && !IsValidSlug(options.device_id))
    {
        Fail("--device-id must match [A-Za-z0-9_.-]{1,128}");
    }
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

int main(int argc, char** argv)
{
    if (argc <= 1)
    {
        return Usage();
    }
    const ObserverOptions options = ParseOptions(argc, argv);
    ValidateOptions(options);

    using apfsaccess::catalog::ApfsContainerCatalog;
    using apfsaccess::catalog::FileRandomAccessSource;

    JsonWriter json;
    json.BeginObject();
    json.Key("format");
    json.String(kFormat);
    json.Key("version");
    json.Integer(kVersion);
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
        apfsaccess::rw::BlockDevice device(ToWide(options.device));
        ApfsContainerCatalog catalog;
        std::wstring error;
        if (!ApfsContainerCatalog::TryLoadDevice(device, catalog, error))
        {
            std::string narrow;
            for (wchar_t ch : error)
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
    }
    else
    {
        RequireRegularInputFile(primary_path, "primary input");
        const SourceHash primary_hash = HashImageFile(primary_path);
        FileRandomAccessSource primary_source(primary_path);
        ApfsContainerCatalog primary_catalog;
        std::string error;
        if (!ApfsContainerCatalog::TryLoadImage(
                primary_source, disk_id, primary_path, primary_catalog, error))
        {
            Fail("primary input catalog failed: " + error);
        }
        json.Key("source");
        WriteSource(json, "image", primary_path, primary_hash.size_bytes, "full", primary_hash.hex);
        json.Key("secondarySources");
        json.BeginArray();
        std::vector<std::pair<std::string, SourceHash>> secondary;
        if (!options.store_b.empty())
        {
            RequireRegularInputFile(options.store_b, "fusion store B");
            secondary.emplace_back(options.store_b, HashImageFile(options.store_b));
        }
        for (const auto& [path, hash] : secondary)
        {
            WriteSource(json, "image", path, hash.size_bytes, "full", hash.hex);
        }
        json.EndArray();
        json.Key("topology");
        if (options.store_b.empty())
        {
            WriteTopology(json, primary_catalog, disk_id, primary_path,
                primary_hash.size_bytes, primary_catalog.DiskGuid());
        }
        else
        {
            // Fusion: the two inputs must describe the same container; the
            // merged view carries both member stores under one container.
            FileRandomAccessSource second_source(options.store_b);
            ApfsContainerCatalog second_catalog;
            const std::string second_disk = disk_id + "-b";
            if (!ApfsContainerCatalog::TryLoadImage(
                    second_source, second_disk, options.store_b, second_catalog, error))
            {
                Fail("fusion store B catalog failed: " + error);
            }
            if (primary_catalog.Containers().size() != 1 ||
                second_catalog.Containers().size() != 1)
            {
                Fail("fusion inputs must each describe exactly one container");
            }
            if (primary_catalog.Partitions().empty() || second_catalog.Partitions().empty())
            {
                Fail("fusion inputs must be GPT-partitioned images with distinct partition GUIDs");
            }
            const auto merged = MergeFusionContainer(
                primary_catalog.Containers()[0], second_catalog.Containers()[0]);
            const SourceHash& second_hash = secondary.front().second;
            WriteFusionTopology(json, primary_catalog, disk_id, primary_path,
                primary_hash.size_bytes, second_catalog, second_disk, options.store_b,
                second_hash.size_bytes, merged);
        }
    }
    json.EndObject();
    const std::string text = json.Text();

    if (!options.out_path.empty())
    {
        std::ofstream out(options.out_path, std::ios::out | std::ios::binary | std::ios::trunc);
        if (!out.is_open())
        {
            Fail("cannot open --out file: " + options.out_path);
        }
        out << text << "\n";
        out.close();
        if (!out.good())
        {
            Fail("writing --out file failed: " + options.out_path);
        }
        return 0;
    }
    std::cout << text << "\n";
    return 0;
}
