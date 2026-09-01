#include "MetadataStore.h"
#include "TransactionManager.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <crtdbg.h>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>
#include <windows.h>

namespace
{
constexpr std::size_t kContainerBytes = 4 * 1024 * 1024;
constexpr std::uint32_t kBlockSize = 4096;
constexpr std::uint64_t kTotalBlocks = 1024;
constexpr std::uint64_t kInitialCheckpointXid = 7;
constexpr std::uint64_t kSpacemanObjectId = 0x2A;
constexpr std::uint64_t kVolumeRootObject = 0x54;
constexpr std::uint32_t kNxsbMagic = 0x4253584E; // NXSB
constexpr std::uint32_t kChecksumSeed = 2166136261u;
constexpr std::uint32_t kChecksumPrime = 16777619u;

void WriteLe32(std::vector<std::byte>& buffer, std::size_t offset, std::uint32_t value)
{
    if (offset + 4 > buffer.size())
    {
        return;
    }

    buffer[offset + 0] = static_cast<std::byte>(value & 0xffu);
    buffer[offset + 1] = static_cast<std::byte>((value >> 8) & 0xffu);
    buffer[offset + 2] = static_cast<std::byte>((value >> 16) & 0xffu);
    buffer[offset + 3] = static_cast<std::byte>((value >> 24) & 0xffu);
}

void WriteLe64(std::vector<std::byte>& buffer, std::size_t offset, std::uint64_t value)
{
    if (offset + 8 > buffer.size())
    {
        return;
    }

    for (int i = 0; i < 8; ++i)
    {
        buffer[offset + static_cast<std::size_t>(i)] = static_cast<std::byte>((value >> (i * 8)) & 0xffu);
    }
}

std::uint32_t ReadLe32(const std::vector<std::byte>& buffer, std::size_t offset)
{
    if (offset + 4 > buffer.size())
    {
        return 0;
    }

    std::uint32_t value = 0;
    for (std::size_t index = 0; index < 4; ++index)
    {
        value |= static_cast<std::uint32_t>(
            std::to_integer<unsigned char>(buffer[offset + index])) << (index * 8);
    }
    return value;
}

std::uint64_t ReadLe64(const std::vector<std::byte>& buffer, std::size_t offset)
{
    if (offset + 8 > buffer.size())
    {
        return 0;
    }

    std::uint64_t value = 0;
    for (std::size_t index = 0; index < 8; ++index)
    {
        value |= static_cast<std::uint64_t>(
            std::to_integer<unsigned char>(buffer[offset + index])) << (index * 8);
    }
    return value;
}

std::uint32_t UpdateChecksum(std::uint32_t hash, const std::byte* bytes, std::size_t length)
{
    for (std::size_t index = 0; index < length; ++index)
    {
        hash ^= static_cast<std::uint32_t>(std::to_integer<unsigned char>(bytes[index]));
        hash *= kChecksumPrime;
    }
    return hash;
}

bool CreateSyntheticContainerWithSize(const std::filesystem::path& image_path, std::size_t container_bytes)
{
    if (container_bytes == 0 || (container_bytes % kBlockSize) != 0)
    {
        return false;
    }

    const auto total_blocks = static_cast<std::uint64_t>(container_bytes / kBlockSize);
    std::vector<std::byte> bytes(container_bytes, std::byte{0});
    const auto write_superblock = [&](std::size_t base_offset, std::uint64_t checkpoint_xid)
    {
        WriteLe64(bytes, base_offset + 0x10, checkpoint_xid);
        WriteLe32(bytes, base_offset + 0x20, kNxsbMagic);
        WriteLe32(bytes, base_offset + 0x24, kBlockSize);
        WriteLe64(bytes, base_offset + 0x28, total_blocks);
        WriteLe64(bytes, base_offset + 0x98, kSpacemanObjectId);
        WriteLe64(bytes, base_offset + 0xA0, kVolumeRootObject);
    };

    write_superblock(0, kInitialCheckpointXid);
    write_superblock(static_cast<std::size_t>(kBlockSize), kInitialCheckpointXid);

    std::ofstream out(image_path, std::ios::binary | std::ios::trunc);
    if (!out.good())
    {
        return false;
    }

    out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    return out.good();
}

bool CreateSyntheticContainer(const std::filesystem::path& image_path)
{
    return CreateSyntheticContainerWithSize(image_path, kContainerBytes);
}

bool ReadBytesFromImage(
    const std::filesystem::path& image_path,
    std::uint64_t offset_bytes,
    std::size_t size_bytes,
    std::vector<std::byte>& out)
{
    out.assign(size_bytes, std::byte{0});
    if (size_bytes == 0)
    {
        return true;
    }

    std::ifstream input(image_path, std::ios::binary);
    if (!input.good())
    {
        out.clear();
        return false;
    }

    input.seekg(static_cast<std::streamoff>(offset_bytes), std::ios::beg);
    if (!input.good())
    {
        out.clear();
        return false;
    }

    input.read(reinterpret_cast<char*>(out.data()), static_cast<std::streamsize>(size_bytes));
    if (static_cast<std::size_t>(input.gcount()) != size_bytes)
    {
        out.clear();
        return false;
    }

    return true;
}

bool WriteBytesToImage(
    const std::filesystem::path& image_path,
    std::uint64_t offset_bytes,
    const std::vector<std::byte>& bytes)
{
    if (bytes.empty())
    {
        return true;
    }

    std::fstream io(image_path, std::ios::binary | std::ios::in | std::ios::out);
    if (!io.good())
    {
        return false;
    }

    io.seekp(static_cast<std::streamoff>(offset_bytes), std::ios::beg);
    if (!io.good())
    {
        return false;
    }

    io.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    return io.good();
}

bool CorruptHighestCommitBlobNonAnchorExtentWithValidChecksum(
    const std::filesystem::path& image_path,
    std::uint64_t object_id,
    std::uint64_t malformed_physical_address)
{
    constexpr std::array<unsigned char, 13> kCanonicalMagic =
    {
        'A', 'P', 'F', 'S', 'R', 'W', 'C', 'A', 'N', 'O', 'N', '3', '\0'
    };
    constexpr std::array<unsigned char, 13> kScaffoldMagic =
    {
        'A', 'P', 'F', 'S', 'R', 'W', 'S', 'C', 'A', 'F', 'F', '3', '\0'
    };
    constexpr std::size_t kChecksumOffset = 13 + 8 + 8 + 4 + 4 + 4 + 4 + 4;
    constexpr std::size_t kPayloadOffset = kChecksumOffset + sizeof(std::uint32_t);

    std::error_code ec;
    const auto image_bytes = std::filesystem::file_size(image_path, ec);
    if (ec || image_bytes < kBlockSize ||
        image_bytes > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()) ||
        malformed_physical_address == 0 ||
        (malformed_physical_address % kBlockSize) != 0 ||
        malformed_physical_address > (image_bytes - kBlockSize))
    {
        return false;
    }

    std::vector<std::byte> image;
    if (!ReadBytesFromImage(image_path, 0, static_cast<std::size_t>(image_bytes), image))
    {
        return false;
    }

    struct Candidate
    {
        std::uint64_t target_xid = 0;
        std::size_t offset = 0;
        std::size_t payload_end = 0;
    };
    std::optional<Candidate> selected;
    const auto matches_magic = [&](std::size_t offset, const auto& magic)
    {
        if (offset > image.size() || magic.size() > (image.size() - offset))
        {
            return false;
        }
        for (std::size_t index = 0; index < magic.size(); ++index)
        {
            if (std::to_integer<unsigned char>(image[offset + index]) != magic[index])
            {
                return false;
            }
        }
        return true;
    };

    for (std::size_t offset = 0; offset + kPayloadOffset <= image.size(); ++offset)
    {
        if (!matches_magic(offset, kCanonicalMagic) &&
            !matches_magic(offset, kScaffoldMagic))
        {
            continue;
        }

        const auto target_xid = ReadLe64(image, offset + 21);
        const auto object_map_updates = ReadLe32(image, offset + 33);
        const auto allocations = ReadLe32(image, offset + 37);
        const auto deallocations = ReadLe32(image, offset + 41);
        const auto btree_records = ReadLe32(image, offset + 45);
        auto cursor = offset + kPayloadOffset;
        const auto advance = [&](std::uint64_t bytes)
        {
            if (bytes > static_cast<std::uint64_t>(image.size() - cursor))
            {
                return false;
            }
            cursor += static_cast<std::size_t>(bytes);
            return true;
        };
        if (target_xid == 0 ||
            !advance(static_cast<std::uint64_t>(object_map_updates) * 32ull) ||
            !advance(static_cast<std::uint64_t>(allocations) * 16ull) ||
            !advance(static_cast<std::uint64_t>(deallocations) * 16ull))
        {
            continue;
        }

        bool valid = true;
        for (std::uint32_t index = 0; index < btree_records; ++index)
        {
            if (cursor > image.size() || 16 > (image.size() - cursor))
            {
                valid = false;
                break;
            }
            const auto key_size = ReadLe32(image, cursor + 8);
            const auto value_size = ReadLe32(image, cursor + 12);
            cursor += 16;
            if (!advance(static_cast<std::uint64_t>(key_size) + value_size))
            {
                valid = false;
                break;
            }
        }
        if (valid && (!selected.has_value() || target_xid > selected->target_xid))
        {
            selected = Candidate{ target_xid, offset, cursor };
        }
    }
    if (!selected.has_value())
    {
        return false;
    }

    const auto object_map_updates = ReadLe32(image, selected->offset + 33);
    const auto allocations = ReadLe32(image, selected->offset + 37);
    const auto deallocations = ReadLe32(image, selected->offset + 41);
    const auto btree_records = ReadLe32(image, selected->offset + 45);
    const auto fixed_payload_bytes =
        static_cast<std::uint64_t>(object_map_updates) * 32ull +
        static_cast<std::uint64_t>(allocations) * 16ull +
        static_cast<std::uint64_t>(deallocations) * 16ull;
    if (fixed_payload_bytes > static_cast<std::uint64_t>(selected->payload_end - selected->offset - kPayloadOffset))
    {
        return false;
    }
    auto cursor = selected->offset + kPayloadOffset + static_cast<std::size_t>(fixed_payload_bytes);
    bool mutated = false;
    for (std::uint32_t index = 0; index < btree_records; ++index)
    {
        if (cursor > selected->payload_end || 16 > (selected->payload_end - cursor))
        {
            return false;
        }
        const auto kind = ReadLe32(image, cursor + 0);
        const auto tombstone = ReadLe32(image, cursor + 4);
        const auto key_size = ReadLe32(image, cursor + 8);
        const auto value_size = ReadLe32(image, cursor + 12);
        cursor += 16;
        if (key_size > (selected->payload_end - cursor) ||
            value_size > (selected->payload_end - cursor - key_size))
        {
            return false;
        }

        const auto key_offset = cursor;
        const auto value_offset = key_offset + key_size;
        if (!mutated &&
            kind == static_cast<std::uint32_t>(apfsaccess::rw::BtreeRecordKind::FileExtent) &&
            tombstone == 0 && key_size == 17 && value_size == 25 &&
            ReadLe64(image, key_offset + 1) == object_id &&
            ReadLe64(image, key_offset + 9) != 0)
        {
            WriteLe64(image, value_offset + 8, malformed_physical_address);
            mutated = true;
        }
        cursor = value_offset + value_size;
    }
    if (!mutated || cursor != selected->payload_end)
    {
        return false;
    }

    const auto payload_start = selected->offset + kPayloadOffset;
    const auto checksum = UpdateChecksum(
        kChecksumSeed,
        image.data() + static_cast<std::vector<std::byte>::difference_type>(payload_start),
        selected->payload_end - payload_start);
    WriteLe32(image, selected->offset + kChecksumOffset, checksum);
    return WriteBytesToImage(image_path, 0, image);
}

std::vector<std::byte> BuildPatternPayload(std::size_t bytes, unsigned char seed)
{
    std::vector<std::byte> payload(bytes, std::byte{0});
    for (std::size_t i = 0; i < payload.size(); ++i)
    {
        payload[i] = static_cast<std::byte>((seed + static_cast<unsigned char>(i & 0xffu)) & 0xffu);
    }
    return payload;
}

bool Require(bool condition, const std::string& message)
{
    if (!condition)
    {
        std::cerr << "[FAIL] " << message << std::endl;
        return false;
    }
    return true;
}

std::optional<std::uint64_t> ExtractPerfCounterCount(const std::string& json, const std::string& counter_name)
{
    const auto key = "\"" + counter_name + "\":{\"count\":";
    auto pos = json.find(key);
    if (pos == std::string::npos)
    {
        return std::nullopt;
    }

    pos += key.size();
    auto end = pos;
    while (end < json.size() && json[end] >= '0' && json[end] <= '9')
    {
        ++end;
    }
    if (end == pos)
    {
        return std::nullopt;
    }

    return std::stoull(json.substr(pos, end - pos));
}

std::optional<std::uint64_t> ExtractNestedPerfCounterCount(
    const std::string& json,
    const std::string& object_name,
    const std::string& counter_name)
{
    const auto object_key = "\"" + object_name + "\":{";
    auto object_pos = json.find(object_key);
    if (object_pos == std::string::npos)
    {
        return std::nullopt;
    }

    const auto key = "\"" + counter_name + "\":{\"count\":";
    auto pos = json.find(key, object_pos + object_key.size());
    if (pos == std::string::npos)
    {
        return std::nullopt;
    }

    pos += key.size();
    auto end = pos;
    while (end < json.size() && json[end] >= '0' && json[end] <= '9')
    {
        ++end;
    }
    if (end == pos)
    {
        return std::nullopt;
    }

    return std::stoull(json.substr(pos, end - pos));
}

std::optional<std::uint64_t> ExtractNestedUnsignedValue(
    const std::string& json,
    const std::string& object_name,
    const std::string& value_name)
{
    const auto object_key = "\"" + object_name + "\":{";
    auto object_pos = json.find(object_key);
    if (object_pos == std::string::npos)
    {
        return std::nullopt;
    }

    const auto key = "\"" + value_name + "\":";
    auto pos = json.find(key, object_pos + object_key.size());
    if (pos == std::string::npos)
    {
        return std::nullopt;
    }

    pos += key.size();
    auto end = pos;
    while (end < json.size() && json[end] >= '0' && json[end] <= '9')
    {
        ++end;
    }
    if (end == pos)
    {
        return std::nullopt;
    }

    return std::stoull(json.substr(pos, end - pos));
}

class ScopedEnvironmentVariable
{
public:
    ScopedEnvironmentVariable(const wchar_t* name, const wchar_t* value)
        : name_(name == nullptr ? L"" : name)
    {
        if (name_.empty())
        {
            return;
        }

        const auto required_chars = GetEnvironmentVariableW(name_.c_str(), nullptr, 0);
        if (required_chars > 0)
        {
            previous_value_.resize(required_chars);
            const auto copied_chars = GetEnvironmentVariableW(
                name_.c_str(),
                previous_value_.data(),
                required_chars);
            if (copied_chars > 0 && copied_chars < required_chars)
            {
                previous_value_.resize(copied_chars);
                had_previous_value_ = true;
            }
            else
            {
                previous_value_.clear();
            }
        }

        (void)_wputenv_s(name_.c_str(), value == nullptr ? L"" : value);
    }

    ~ScopedEnvironmentVariable()
    {
        if (name_.empty())
        {
            return;
        }

        if (had_previous_value_)
        {
            (void)_wputenv_s(name_.c_str(), previous_value_.c_str());
        }
        else
        {
            (void)_wputenv_s(name_.c_str(), L"");
        }
    }

    ScopedEnvironmentVariable(const ScopedEnvironmentVariable&) = delete;
    ScopedEnvironmentVariable& operator=(const ScopedEnvironmentVariable&) = delete;

private:
    std::wstring name_;
    std::wstring previous_value_;
    bool had_previous_value_ = false;
};

const char* MutationStatusToString(apfsaccess::rw::MetadataStore::MutationStatus status)
{
    using MutationStatus = apfsaccess::rw::MetadataStore::MutationStatus;
    switch (status)
    {
    case MutationStatus::Applied:
        return "Applied";
    case MutationStatus::NotReady:
        return "NotReady";
    case MutationStatus::InvalidRequest:
        return "InvalidRequest";
    case MutationStatus::AllocationFailed:
        return "AllocationFailed";
    case MutationStatus::UnsupportedOperation:
        return "UnsupportedOperation";
    default:
        return "Unknown";
    }
}

const char* CommitStatusToString(apfsaccess::rw::MetadataStore::CommitStatus status)
{
    using CommitStatus = apfsaccess::rw::MetadataStore::CommitStatus;
    switch (status)
    {
    case CommitStatus::Committed:
        return "Committed";
    case CommitStatus::NothingToCommit:
        return "NothingToCommit";
    case CommitStatus::NotReady:
        return "NotReady";
    case CommitStatus::NotWritable:
        return "NotWritable";
    case CommitStatus::AllocationFailed:
        return "AllocationFailed";
    case CommitStatus::InvariantFailed:
        return "InvariantFailed";
    case CommitStatus::PersistFailed:
        return "PersistFailed";
    case CommitStatus::FlushFailed:
        return "FlushFailed";
    default:
        return "Unknown";
    }
}

bool ExpectMutationStatus(
    apfsaccess::rw::MetadataStore& store,
    const apfsaccess::rw::MetadataStore::MutationRequest& request,
    apfsaccess::rw::MetadataStore::MutationStatus expected,
    const std::string& message)
{
    const auto status = store.ApplyMutation(request);
    if (status != expected)
    {
        std::cerr << "[DEBUG] mutation status for '" << message << "': "
                  << MutationStatusToString(status) << std::endl;
        return Require(false, message);
    }
    return true;
}

bool ExpectCommitStatus(
    apfsaccess::rw::MetadataStore& store,
    apfsaccess::rw::MetadataStore::CommitStatus expected,
    const std::string& message)
{
    const auto status = store.CommitPendingMutations();
    if (status != expected)
    {
        std::cerr << "[DEBUG] commit status for '" << message << "': "
                  << CommitStatusToString(status) << std::endl;
        std::cerr << "[DEBUG] commit stage for '" << message << "': "
                  << store.LastCommitStage() << std::endl;
        const auto commit_failure_reason = store.LastCommitFailureReason();
        if (!commit_failure_reason.empty())
        {
            std::wcerr << L"[DEBUG] commit failure reason: " << commit_failure_reason << std::endl;
        }
        if (const auto commit_failure_object_id = store.LastCommitFailureObjectId();
            commit_failure_object_id.has_value())
        {
            std::cerr << "[DEBUG] commit failure object id: "
                      << commit_failure_object_id.value() << std::endl;
        }
        const auto recovery_reason = store.RecoveryReason();
        if (!recovery_reason.empty())
        {
            std::wcerr << L"[DEBUG] recovery reason: " << recovery_reason << std::endl;
        }
        return Require(false, message);
    }
    return true;
}

void ConfigurePayloadProvider(
    apfsaccess::rw::MetadataStore& store,
    std::unordered_map<std::wstring, std::vector<std::byte>>& staged_payloads)
{
    store.SetFilePayloadProvider(
        [&staged_payloads](const std::wstring& path, std::uint64_t logical_size) -> std::optional<std::vector<std::byte>>
        {
            auto pending = staged_payloads.find(path);
            if (pending == staged_payloads.end())
            {
                return std::nullopt;
            }

            auto payload = pending->second;
            if (logical_size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
            {
                return std::nullopt;
            }

            const auto target_size = static_cast<std::size_t>(logical_size);
            if (payload.size() < target_size)
            {
                payload.resize(target_size, std::byte{0});
            }
            else if (payload.size() > target_size)
            {
                payload.resize(target_size);
            }

            return payload;
        });
}

bool CreateAndCommitFile(
    apfsaccess::rw::MetadataStore& store,
    std::unordered_map<std::wstring, std::vector<std::byte>>& staged_payloads,
    const std::wstring& path,
    std::size_t payload_bytes,
    unsigned char payload_seed,
    const std::string& label)
{
    apfsaccess::rw::MetadataStore::MutationRequest create_file{};
    create_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
    create_file.path = path;
    if (!ExpectMutationStatus(
            store,
            create_file,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            label + ": create file should apply"))
    {
        return false;
    }

    apfsaccess::rw::MetadataStore::MutationRequest write_file{};
    write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
    write_file.path = path;
    write_file.length = static_cast<std::uint64_t>(payload_bytes);
    if (!ExpectMutationStatus(
            store,
            write_file,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            label + ": write file should apply"))
    {
        return false;
    }

    staged_payloads[path] = BuildPatternPayload(payload_bytes, payload_seed);
    return ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        label + ": commit should succeed");
}

bool InstallFragmentedReadExtents(
    apfsaccess::rw::MetadataStore& store,
    const std::wstring& path,
    std::uint64_t first_extent_address,
    const std::string& label)
{
    auto inode = store.LookupCommittedInodeByPath(path);
    if (!Require(inode.has_value(), label + ": committed inode should exist"))
    {
        return false;
    }

    return Require(
        store.SetCommittedReadExtents(
            inode->object_id,
            {
                { 0, first_extent_address, 4096 },
                { 4096, first_extent_address + (2ull * kBlockSize), 4096 },
                { 8192, first_extent_address + (4ull * kBlockSize), 4096 },
            }),
        label + ": committed read extents should be installed");
}

bool TestPendingCheckpointDeltaBuilderConformance(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "pending_checkpoint_delta.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "PendingCheckpointDelta: unable to create synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"PendingCheckpointDelta",
    };
    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "PendingCheckpointDelta: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "PendingCheckpointDelta: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "PendingCheckpointDelta: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "PendingCheckpointDelta: PrepareNativeWritePath should succeed");

    apfsaccess::rw::MetadataStore::MutationRequest create_file{};
    create_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
    create_file.path = L"\\delta.bin";
    ok &= ExpectMutationStatus(
        store,
        create_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "PendingCheckpointDelta: create file should apply");

    apfsaccess::rw::MetadataStore::MutationRequest write_file{};
    write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
    write_file.path = L"\\delta.bin";
    write_file.offset = 0;
    write_file.length = 4096;
    ok &= ExpectMutationStatus(
        store,
        write_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "PendingCheckpointDelta: write file should apply");

    const auto inode = store.DebugLookupWorkingInodeByPath(L"\\delta.bin");
    if (!Require(inode.has_value(), "PendingCheckpointDelta: working inode should exist"))
    {
        return false;
    }

    const auto base_xid = store.CheckpointXid().value_or(0);
    auto delta = store.DebugBuildPendingCheckpointDelta();
    ok &= Require(delta.base_xid == base_xid, "PendingCheckpointDelta: base xid should match store");
    ok &= Require(delta.target_xid == base_xid + 1, "PendingCheckpointDelta: target xid should advance one step");
    ok &= Require(!delta.volume_identity.empty(), "PendingCheckpointDelta: volume identity should be present");
    ok &= Require(delta.object_map_updates.size() == 1, "PendingCheckpointDelta: one object-map update expected");
    ok &= Require(delta.inode_updates.size() == 1, "PendingCheckpointDelta: one inode update expected");
    ok &= Require(delta.directory_link_updates.size() == 1, "PendingCheckpointDelta: one directory-link update expected");
    ok &= Require(delta.btree_records.size() >= 3, "PendingCheckpointDelta: inode/directory/extent btree records expected");
    ok &= Require(delta.object_map_updates.front().object_id == inode->object_id, "PendingCheckpointDelta: object-map object id should match inode");
    ok &= Require(!delta.object_map_updates.front().tombstone, "PendingCheckpointDelta: object-map update should be live");
    ok &= Require(delta.inode_updates.front().full_path == L"\\delta.bin", "PendingCheckpointDelta: inode full path should match");
    ok &= Require(delta.directory_link_updates.front().entry_name == L"delta.bin", "PendingCheckpointDelta: directory link name should match");

    apfsaccess::rw::CheckpointDeltaState state;
    state.volume_identity = delta.volume_identity;
    state.checkpoint_xid = base_xid;
    const auto apply_status = apfsaccess::rw::CheckpointDeltaCodec::ApplyDelta(state, delta);
    ok &= Require(
        apply_status == apfsaccess::rw::CheckpointDeltaParseStatus::Ok,
        "PendingCheckpointDelta: delta should apply to base state");
    ok &= Require(state.checkpoint_xid == delta.target_xid, "PendingCheckpointDelta: applied xid should advance");
    ok &= Require(state.object_map.contains(inode->object_id), "PendingCheckpointDelta: applied object map should contain file");
    ok &= Require(state.inodes.contains(inode->object_id), "PendingCheckpointDelta: applied inode map should contain file");
    ok &= Require(
        state.directory_links.contains(std::to_wstring(inode->parent_object_id) + L":delta.bin"),
        "PendingCheckpointDelta: applied directory link should contain file");

    const std::vector<apfsaccess::rw::CheckpointDelta> chain{ delta };
    const auto bytes = apfsaccess::rw::CheckpointDeltaCodec::EncodeChain(chain, delta.volume_identity, base_xid);
    const auto parsed = apfsaccess::rw::CheckpointDeltaCodec::DecodeChain(bytes, delta.volume_identity, base_xid);
    ok &= Require(!bytes.empty(), "PendingCheckpointDelta: encoded chain should not be empty");
    ok &= Require(
        parsed.status == apfsaccess::rw::CheckpointDeltaParseStatus::Ok,
        "PendingCheckpointDelta: encoded chain should round-trip");
    ok &= Require(parsed.deltas.size() == 1, "PendingCheckpointDelta: one chain delta should round-trip");
    return ok;
}

bool TestCheckpointDeltaShadowTelemetryConformance(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "checkpoint_delta_shadow_telemetry.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "CheckpointDeltaShadowTelemetry: unable to create synthetic container");
    }

    wchar_t previous_perf_value[256]{};
    const auto previous_perf_chars = GetEnvironmentVariableW(
        L"APFSACCESS_PERF_COUNTERS",
        previous_perf_value,
        static_cast<DWORD>(std::size(previous_perf_value)));
    const bool had_previous_perf =
        previous_perf_chars > 0 &&
        previous_perf_chars < static_cast<DWORD>(std::size(previous_perf_value));
    SetEnvironmentVariableW(L"APFSACCESS_PERF_COUNTERS", L"1");

    wchar_t previous_shadow_value[256]{};
    const auto previous_shadow_chars = GetEnvironmentVariableW(
        L"APFSACCESS_CHECKPOINT_DELTA_SHADOW",
        previous_shadow_value,
        static_cast<DWORD>(std::size(previous_shadow_value)));
    const bool had_previous_shadow =
        previous_shadow_chars > 0 &&
        previous_shadow_chars < static_cast<DWORD>(std::size(previous_shadow_value));
    SetEnvironmentVariableW(L"APFSACCESS_CHECKPOINT_DELTA_SHADOW", nullptr);

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"CheckpointDeltaShadowTelemetry",
    };
    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "CheckpointDeltaShadowTelemetry: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "CheckpointDeltaShadowTelemetry: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "CheckpointDeltaShadowTelemetry: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "CheckpointDeltaShadowTelemetry: PrepareNativeWritePath should succeed");

    std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
    ConfigurePayloadProvider(store, staged_payloads);

    constexpr std::size_t kFileCount = 24;
    for (std::size_t index = 0; index < kFileCount; ++index)
    {
        const auto path = L"\\shadow-" + std::to_wstring(index) + L".bin";

        apfsaccess::rw::MetadataStore::MutationRequest create_file{};
        create_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
        create_file.path = path;
        ok &= ExpectMutationStatus(
            store,
            create_file,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "CheckpointDeltaShadowTelemetry: create file should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_file{};
        write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_file.path = path;
        write_file.length = 1024;
        ok &= ExpectMutationStatus(
            store,
            write_file,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "CheckpointDeltaShadowTelemetry: write file should apply");
        staged_payloads[path] = BuildPatternPayload(1024, static_cast<unsigned char>(0x25 + index));
    }

    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "CheckpointDeltaShadowTelemetry: initial batch commit should succeed");

    const auto before_json = store.PerformanceJson();
    const auto before_count = ExtractNestedUnsignedValue(before_json, "checkpointDeltaShadow", "count");
    ok &= Require(
        before_count.has_value(),
        "CheckpointDeltaShadowTelemetry: checkpoint delta shadow counters should exist");
    if (before_count.has_value())
    {
        ok &= Require(
            before_count.value() == 0,
            "CheckpointDeltaShadowTelemetry: shadow delta should stay off by default");
    }

    apfsaccess::rw::MetadataStore::MutationRequest set_basic_info{};
    set_basic_info.operation = apfsaccess::rw::MetadataStore::MutationOperation::SetBasicInfo;
    set_basic_info.path = L"\\shadow-7.bin";
    set_basic_info.timestamp_utc = 515151;
    ok &= ExpectMutationStatus(
        store,
        set_basic_info,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "CheckpointDeltaShadowTelemetry: metadata-only update should apply");

    SetEnvironmentVariableW(L"APFSACCESS_CHECKPOINT_DELTA_SHADOW", L"1");
    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "CheckpointDeltaShadowTelemetry: opt-in metadata-only commit should succeed");

    const auto after_json = store.PerformanceJson();
    const auto after_count = ExtractNestedUnsignedValue(after_json, "checkpointDeltaShadow", "count");
    const auto records = ExtractNestedUnsignedValue(after_json, "checkpointDeltaShadow", "records");
    const auto delta_bytes = ExtractNestedUnsignedValue(after_json, "checkpointDeltaShadow", "bytes");
    const auto full_bytes = ExtractNestedUnsignedValue(after_json, "checkpointDeltaShadow", "fullCheckpointBytes");
    const auto ratio_x1000 = ExtractNestedUnsignedValue(after_json, "checkpointDeltaShadow", "ratioTimes1000");
    ok &= Require(
        after_count.has_value() &&
            records.has_value() &&
            delta_bytes.has_value() &&
            full_bytes.has_value() &&
            ratio_x1000.has_value(),
        "CheckpointDeltaShadowTelemetry: checkpoint delta shadow fields should exist after commit");
    if (before_count.has_value() && after_count.has_value())
    {
        ok &= Require(
            after_count.value() == before_count.value() + 1,
            "CheckpointDeltaShadowTelemetry: metadata-only commit should record one shadow delta observation");
    }
    if (records.has_value() && delta_bytes.has_value() && full_bytes.has_value() && ratio_x1000.has_value())
    {
        ok &= Require(records.value() > 0, "CheckpointDeltaShadowTelemetry: shadow delta should report changed records");
        ok &= Require(delta_bytes.value() > 0, "CheckpointDeltaShadowTelemetry: shadow delta should report encoded bytes");
        ok &= Require(full_bytes.value() > 0, "CheckpointDeltaShadowTelemetry: full checkpoint estimate should report bytes");
        ok &= Require(
            delta_bytes.value() < full_bytes.value(),
            "CheckpointDeltaShadowTelemetry: metadata-only delta should be smaller than full checkpoint families");
        ok &= Require(
            ratio_x1000.value() < 1000,
            "CheckpointDeltaShadowTelemetry: metadata-only delta ratio should be below full checkpoint cost");
    }

    const auto committed = store.LookupCommittedInodeByPath(L"\\shadow-7.bin");
    ok &= Require(
        committed.has_value() && committed->timestamp_utc == 515151,
        "CheckpointDeltaShadowTelemetry: metadata-only commit should preserve updated timestamp");

    {
        apfsaccess::rw::MetadataStore remounted(context);
        ok &= Require(
            remounted.LoadContainerSuperblocks(),
            "CheckpointDeltaShadowTelemetry: remount LoadContainerSuperblocks should succeed");
        ok &= Require(
            remounted.PrepareNativeWritePath(),
            "CheckpointDeltaShadowTelemetry: remount PrepareNativeWritePath should succeed");
        const auto remounted_inode = remounted.LookupCommittedInodeByPath(L"\\shadow-7.bin");
        ok &= Require(
            remounted_inode.has_value() && remounted_inode->timestamp_utc == 515151,
            "CheckpointDeltaShadowTelemetry: remount should preserve updated timestamp");
    }

    SetEnvironmentVariableW(
        L"APFSACCESS_PERF_COUNTERS",
        had_previous_perf ? previous_perf_value : nullptr);
    SetEnvironmentVariableW(
        L"APFSACCESS_CHECKPOINT_DELTA_SHADOW",
        had_previous_shadow ? previous_shadow_value : nullptr);

    return ok;
}

bool TestRenameReplaceConformance(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "rename_replace.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "TestRenameReplaceConformance: unable to create synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"RenameReplace",
    };
    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "RenameReplace: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "RenameReplace: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "RenameReplace: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "RenameReplace: PrepareNativeWritePath should succeed");

    std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
    store.SetFilePayloadProvider(
        [&staged_payloads](const std::wstring& path, std::uint64_t logical_size) -> std::optional<std::vector<std::byte>>
        {
            auto pending = staged_payloads.find(path);
            if (pending == staged_payloads.end())
            {
                return std::nullopt;
            }

            auto payload = pending->second;
            if (logical_size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
            {
                return std::nullopt;
            }

            const auto target_size = static_cast<std::size_t>(logical_size);
            if (payload.size() < target_size)
            {
                payload.resize(target_size, std::byte{0});
            }
            else if (payload.size() > target_size)
            {
                payload.resize(target_size);
            }

            return payload;
        });

    apfsaccess::rw::MetadataStore::MutationRequest create_dir{};
    create_dir.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateDirectory;
    create_dir.path = L"\\docs";
    ok &= ExpectMutationStatus(
        store,
        create_dir,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "RenameReplace: CreateDirectory docs should apply");

    apfsaccess::rw::MetadataStore::MutationRequest create_source{};
    create_source.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
    create_source.path = L"\\docs\\source.txt";
    ok &= ExpectMutationStatus(
        store,
        create_source,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "RenameReplace: CreateFile source should apply");

    apfsaccess::rw::MetadataStore::MutationRequest write_source{};
    write_source.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
    write_source.path = L"\\docs\\source.txt";
    write_source.offset = 0;
    write_source.length = 2048;
    ok &= ExpectMutationStatus(
        store,
        write_source,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "RenameReplace: Write source should apply");

    apfsaccess::rw::MetadataStore::MutationRequest create_target{};
    create_target.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
    create_target.path = L"\\docs\\target.txt";
    ok &= ExpectMutationStatus(
        store,
        create_target,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "RenameReplace: CreateFile target should apply");

    apfsaccess::rw::MetadataStore::MutationRequest write_target{};
    write_target.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
    write_target.path = L"\\docs\\target.txt";
    write_target.offset = 0;
    write_target.length = 1024;
    ok &= ExpectMutationStatus(
        store,
        write_target,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "RenameReplace: Write target should apply");

    const auto source_payload = BuildPatternPayload(2048, 0x31);
    const auto target_payload = BuildPatternPayload(1024, 0x89);
    staged_payloads[L"\\docs\\source.txt"] = source_payload;
    staged_payloads[L"\\docs\\target.txt"] = target_payload;

    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "RenameReplace: first commit should succeed");

    const auto source_before = store.LookupCommittedInodeByPath(L"\\docs\\source.txt");
    const auto target_before = store.LookupCommittedInodeByPath(L"\\docs\\target.txt");
    ok &= Require(source_before.has_value(), "RenameReplace: source inode should exist after first commit");
    ok &= Require(target_before.has_value(), "RenameReplace: target inode should exist after first commit");
    if (!source_before.has_value() || !target_before.has_value())
    {
        return false;
    }
    const auto source_before_object_id = source_before->object_id;
    const auto target_before_object_id = target_before->object_id;

    apfsaccess::rw::MetadataStore::MutationRequest rename_without_replace{};
    rename_without_replace.operation = apfsaccess::rw::MetadataStore::MutationOperation::Rename;
    rename_without_replace.path = L"\\docs\\source.txt";
    rename_without_replace.secondary_path = L"\\docs\\target.txt";
    rename_without_replace.replace_if_exists = false;
    ok &= ExpectMutationStatus(
        store,
        rename_without_replace,
        apfsaccess::rw::MetadataStore::MutationStatus::InvalidRequest,
        "RenameReplace: rename collision without replace should fail");

    apfsaccess::rw::MetadataStore::MutationRequest rename_with_replace = rename_without_replace;
    rename_with_replace.replace_if_exists = true;
    ok &= ExpectMutationStatus(
        store,
        rename_with_replace,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "RenameReplace: rename collision with replace should apply");

    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "RenameReplace: second commit should succeed");

    ok &= Require(
        !store.LookupCommittedInodeByPath(L"\\docs\\source.txt").has_value(),
        "RenameReplace: source path should be absent after replacement rename");

    const auto target_after = store.LookupCommittedInodeByPath(L"\\docs\\target.txt");
    ok &= Require(target_after.has_value(), "RenameReplace: target path should exist after replacement rename");
    if (!target_after.has_value())
    {
        return false;
    }

    ok &= Require(
        target_after->object_id == source_before_object_id,
        "RenameReplace: target path should now reference the source inode object");
    ok &= Require(
        target_after->object_id != target_before_object_id,
        "RenameReplace: original target inode object should be replaced");
    ok &= Require(
        target_after->logical_size == static_cast<std::uint64_t>(source_payload.size()),
        "RenameReplace: replacement target logical size should match source payload");
    ok &= Require(
        store.CommittedFreeExtentCount() > 0,
        "RenameReplace: replacing target should free at least one previously allocated extent");

    std::vector<std::byte> persisted_payload;
    ok &= Require(
        ReadBytesFromImage(
            image_path,
            target_after->data_physical_address,
            source_payload.size(),
            persisted_payload),
        "RenameReplace: replacement target payload should be readable");
    ok &= Require(
        persisted_payload == source_payload,
        "RenameReplace: replacement target payload should match source payload bytes");

    return ok;
}

bool TestDirectoryAndDeleteConformance(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "directory_delete.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "TestDirectoryAndDeleteConformance: unable to create synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"DirectoryDelete",
    };
    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "DirectoryDelete: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "DirectoryDelete: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "DirectoryDelete: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "DirectoryDelete: PrepareNativeWritePath should succeed");

    apfsaccess::rw::MetadataStore::MutationRequest create_tree{};
    create_tree.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateDirectory;
    create_tree.path = L"\\tree";
    ok &= ExpectMutationStatus(
        store,
        create_tree,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "DirectoryDelete: CreateDirectory tree should apply");

    apfsaccess::rw::MetadataStore::MutationRequest create_leaf = create_tree;
    create_leaf.path = L"\\tree\\leaf";
    ok &= ExpectMutationStatus(
        store,
        create_leaf,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "DirectoryDelete: CreateDirectory tree\\leaf should apply");

    apfsaccess::rw::MetadataStore::MutationRequest delete_non_empty{};
    delete_non_empty.operation = apfsaccess::rw::MetadataStore::MutationOperation::Delete;
    delete_non_empty.path = L"\\tree";
    ok &= ExpectMutationStatus(
        store,
        delete_non_empty,
        apfsaccess::rw::MetadataStore::MutationStatus::InvalidRequest,
        "DirectoryDelete: deleting non-empty directory should fail");

    apfsaccess::rw::MetadataStore::MutationRequest rename_cycle{};
    rename_cycle.operation = apfsaccess::rw::MetadataStore::MutationOperation::Rename;
    rename_cycle.path = L"\\tree";
    rename_cycle.secondary_path = L"\\tree\\leaf\\tree";
    ok &= ExpectMutationStatus(
        store,
        rename_cycle,
        apfsaccess::rw::MetadataStore::MutationStatus::InvalidRequest,
        "DirectoryDelete: renaming directory into descendant should fail");

    apfsaccess::rw::MetadataStore::MutationRequest create_empty_a = create_tree;
    create_empty_a.path = L"\\emptyA";
    ok &= ExpectMutationStatus(
        store,
        create_empty_a,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "DirectoryDelete: CreateDirectory emptyA should apply");

    apfsaccess::rw::MetadataStore::MutationRequest create_empty_b = create_tree;
    create_empty_b.path = L"\\emptyB";
    ok &= ExpectMutationStatus(
        store,
        create_empty_b,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "DirectoryDelete: CreateDirectory emptyB should apply");

    apfsaccess::rw::MetadataStore::MutationRequest rename_collision{};
    rename_collision.operation = apfsaccess::rw::MetadataStore::MutationOperation::Rename;
    rename_collision.path = L"\\emptyA";
    rename_collision.secondary_path = L"\\emptyB";
    rename_collision.replace_if_exists = false;
    ok &= ExpectMutationStatus(
        store,
        rename_collision,
        apfsaccess::rw::MetadataStore::MutationStatus::InvalidRequest,
        "DirectoryDelete: rename collision without replace should fail");

    rename_collision.replace_if_exists = true;
    ok &= ExpectMutationStatus(
        store,
        rename_collision,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "DirectoryDelete: rename collision with replace should apply");

    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "DirectoryDelete: commit should succeed");

    ok &= Require(
        !store.LookupCommittedInodeByPath(L"\\emptyA").has_value(),
        "DirectoryDelete: emptyA should be absent after replacement rename");
    const auto empty_b = store.LookupCommittedInodeByPath(L"\\emptyB");
    ok &= Require(empty_b.has_value(), "DirectoryDelete: emptyB should exist after replacement rename");
    if (empty_b.has_value())
    {
        ok &= Require(empty_b->is_directory, "DirectoryDelete: emptyB should remain a directory");
    }

    return ok;
}

bool TestWorkingDirectoryIndexConformance(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "directory_index.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "TestWorkingDirectoryIndexConformance: unable to create synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"DirectoryIndex",
    };
    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "DirectoryIndex: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "DirectoryIndex: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "DirectoryIndex: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "DirectoryIndex: PrepareNativeWritePath should succeed");

    const auto root = store.LookupCommittedInodeByPath(L"\\");
    if (!Require(root.has_value(), "DirectoryIndex: root inode should exist"))
    {
        return false;
    }
    ok &= Require(store.DebugWorkingDirectoryChildCount(root->object_id) == 0, "DirectoryIndex: root should start with no children");

    apfsaccess::rw::MetadataStore::MutationRequest create_dir{};
    create_dir.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateDirectory;
    create_dir.path = L"\\Parent";
    ok &= ExpectMutationStatus(
        store,
        create_dir,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "DirectoryIndex: create parent should apply");

    const auto parent = store.LookupCommittedInodeByPath(L"\\Parent");
    ok &= Require(!parent.has_value(), "DirectoryIndex: uncommitted parent should not appear in committed view");
    ok &= Require(store.DebugWorkingDirectoryChildCount(root->object_id) == 1, "DirectoryIndex: root child count should include staged parent");

    apfsaccess::rw::MetadataStore::MutationRequest create_child = create_dir;
    create_child.path = L"\\Parent\\Child";
    ok &= ExpectMutationStatus(
        store,
        create_child,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "DirectoryIndex: create child should apply");

    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "DirectoryIndex: initial commit should succeed");

    const auto committed_parent = store.LookupCommittedInodeByPath(L"\\Parent");
    if (!Require(committed_parent.has_value(), "DirectoryIndex: committed parent should exist"))
    {
        return false;
    }
    ok &= Require(store.DebugWorkingDirectoryChildCount(root->object_id) == 1, "DirectoryIndex: root count should survive commit sync");
    ok &= Require(store.DebugWorkingDirectoryChildCount(committed_parent->object_id) == 1, "DirectoryIndex: parent count should survive commit sync");

    apfsaccess::rw::MetadataStore::MutationRequest replace_parent{};
    replace_parent.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateDirectory;
    replace_parent.path = L"\\Parent";
    replace_parent.replace_if_exists = true;
    ok &= ExpectMutationStatus(
        store,
        replace_parent,
        apfsaccess::rw::MetadataStore::MutationStatus::InvalidRequest,
        "DirectoryIndex: replacing non-empty parent should fail");
    ok &= Require(store.DebugWorkingDirectoryChildCount(committed_parent->object_id) == 1, "DirectoryIndex: failed replace should preserve parent count");

    apfsaccess::rw::MetadataStore::MutationRequest delete_child{};
    delete_child.operation = apfsaccess::rw::MetadataStore::MutationOperation::Delete;
    delete_child.path = L"\\Parent\\Child";
    ok &= ExpectMutationStatus(
        store,
        delete_child,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "DirectoryIndex: delete child should apply");
    ok &= Require(store.DebugWorkingDirectoryChildCount(committed_parent->object_id) == 0, "DirectoryIndex: parent count should drop after child delete");

    ok &= ExpectMutationStatus(
        store,
        replace_parent,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "DirectoryIndex: replacing empty parent should apply");
    ok &= Require(store.DebugWorkingDirectoryChildCount(root->object_id) == 1, "DirectoryIndex: root count should remain stable after replace");

    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "DirectoryIndex: final commit should succeed");

    const auto remounted_parent = store.LookupCommittedInodeByPath(L"\\Parent");
    if (remounted_parent.has_value())
    {
        ok &= Require(store.DebugWorkingDirectoryChildCount(remounted_parent->object_id) == 0, "DirectoryIndex: committed replacement parent should be empty");
    }
    return ok;
}

bool TestWorkingDirectoryChildIndexAvoidsSiblingScansConformance(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "directory_child_index_siblings.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "DirectoryChildIndexScans: unable to create synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"DirectoryChildIndexScans",
    };
    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "DirectoryChildIndexScans: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "DirectoryChildIndexScans: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "DirectoryChildIndexScans: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "DirectoryChildIndexScans: PrepareNativeWritePath should succeed");

    apfsaccess::rw::MetadataStore::MutationRequest create_dir{};
    create_dir.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateDirectory;
    create_dir.path = L"\\Bulk";
    ok &= ExpectMutationStatus(
        store,
        create_dir,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "DirectoryChildIndexScans: create bulk directory should apply");

    constexpr int kSiblingCount = 128;
    apfsaccess::rw::MetadataStore::MutationRequest create_file{};
    create_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
    for (int index = 0; index < kSiblingCount; ++index)
    {
        create_file.path = L"\\Bulk\\file" + std::to_wstring(index) + L".bin";
        ok &= ExpectMutationStatus(
            store,
            create_file,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "DirectoryChildIndexScans: sibling file create should apply");
    }

    const auto bulk_before_delete = store.DebugLookupWorkingInodeByPath(L"\\Bulk");
    if (!Require(bulk_before_delete.has_value(), "DirectoryChildIndexScans: working bulk directory should exist"))
    {
        return false;
    }
    ok &= Require(
        store.DebugWorkingDirectoryChildCount(bulk_before_delete->object_id) == static_cast<std::size_t>(kSiblingCount),
        "DirectoryChildIndexScans: child index should track all siblings before delete");

    apfsaccess::rw::MetadataStore::MutationRequest delete_file{};
    delete_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Delete;
    for (int index = 0; index < kSiblingCount; ++index)
    {
        delete_file.path = L"\\Bulk\\file" + std::to_wstring(index) + L".bin";
        ok &= ExpectMutationStatus(
            store,
            delete_file,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "DirectoryChildIndexScans: sibling file delete should apply");
    }

    ok &= Require(
        store.DebugWorkingDirectoryChildCount(bulk_before_delete->object_id) == 0,
        "DirectoryChildIndexScans: child index should drop all siblings after delete");
    ok &= Require(
        store.DebugWorkingDirectoryChildLinearScanCount() == 0,
        "DirectoryChildIndexScans: sibling create/delete should not use linear child scans");

    return ok;
}

bool TestDirectorySubtreeDeleteConformance(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "directory_subtree_delete.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "TestDirectorySubtreeDeleteConformance: unable to create synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"DirectorySubtreeDelete",
    };
    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "DirectorySubtreeDelete: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "DirectorySubtreeDelete: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "DirectorySubtreeDelete: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "DirectorySubtreeDelete: PrepareNativeWritePath should succeed");

    std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
    ConfigurePayloadProvider(store, staged_payloads);

    apfsaccess::rw::MetadataStore::MutationRequest create_directory{};
    create_directory.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateDirectory;
    create_directory.path = L"\\tree";
    ok &= ExpectMutationStatus(
        store,
        create_directory,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "DirectorySubtreeDelete: create tree should apply");

    create_directory.path = L"\\tree\\child";
    ok &= ExpectMutationStatus(
        store,
        create_directory,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "DirectorySubtreeDelete: create child directory should apply");

    const auto payload = BuildPatternPayload(2048, 0x52);
    if (!CreateAndCommitFile(
            store,
            staged_payloads,
            L"\\tree\\child\\payload.bin",
            payload.size(),
            0x52,
            "DirectorySubtreeDelete"))
    {
        return false;
    }

    apfsaccess::rw::MetadataStore::MutationRequest delete_tree_first{};
    delete_tree_first.operation = apfsaccess::rw::MetadataStore::MutationOperation::Delete;
    delete_tree_first.path = L"\\tree";
    ok &= ExpectMutationStatus(
        store,
        delete_tree_first,
        apfsaccess::rw::MetadataStore::MutationStatus::InvalidRequest,
        "DirectorySubtreeDelete: deleting parent before children should fail");

    apfsaccess::rw::MetadataStore::MutationRequest delete_payload{};
    delete_payload.operation = apfsaccess::rw::MetadataStore::MutationOperation::Delete;
    delete_payload.path = L"\\tree\\child\\payload.bin";
    ok &= ExpectMutationStatus(
        store,
        delete_payload,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "DirectorySubtreeDelete: child payload delete should apply");
    staged_payloads.erase(L"\\tree\\child\\payload.bin");

    apfsaccess::rw::MetadataStore::MutationRequest delete_child{};
    delete_child.operation = apfsaccess::rw::MetadataStore::MutationOperation::Delete;
    delete_child.path = L"\\tree\\child";
    ok &= ExpectMutationStatus(
        store,
        delete_child,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "DirectorySubtreeDelete: child directory delete after payload should apply");

    apfsaccess::rw::MetadataStore::MutationRequest delete_tree{};
    delete_tree.operation = apfsaccess::rw::MetadataStore::MutationOperation::Delete;
    delete_tree.path = L"\\tree";
    ok &= ExpectMutationStatus(
        store,
        delete_tree,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "DirectorySubtreeDelete: parent directory delete after children should apply");

    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "DirectorySubtreeDelete: bottom-up subtree delete commit should succeed");

    ok &= Require(
        !store.LookupCommittedInodeByPath(L"\\tree").has_value() &&
        !store.LookupCommittedInodeByPath(L"\\tree\\child").has_value() &&
        !store.LookupCommittedInodeByPath(L"\\tree\\child\\payload.bin").has_value(),
        "DirectorySubtreeDelete: committed view should remove the whole subtree");

    return ok;
}

bool TestTruncateConformance(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "truncate.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "TestTruncateConformance: unable to create synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"Truncate",
    };
    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "Truncate: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "Truncate: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "Truncate: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "Truncate: PrepareNativeWritePath should succeed");

    std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
    store.SetFilePayloadProvider(
        [&staged_payloads](const std::wstring& path, std::uint64_t logical_size) -> std::optional<std::vector<std::byte>>
        {
            auto pending = staged_payloads.find(path);
            if (pending == staged_payloads.end())
            {
                return std::nullopt;
            }

            auto payload = pending->second;
            if (logical_size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
            {
                return std::nullopt;
            }

            const auto target_size = static_cast<std::size_t>(logical_size);
            if (payload.size() < target_size)
            {
                payload.resize(target_size, std::byte{0});
            }
            else if (payload.size() > target_size)
            {
                payload.resize(target_size);
            }
            return payload;
        });

    apfsaccess::rw::MetadataStore::MutationRequest create_file{};
    create_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
    create_file.path = L"\\truncate.bin";
    ok &= ExpectMutationStatus(
        store,
        create_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "Truncate: CreateFile truncate.bin should apply");

    apfsaccess::rw::MetadataStore::MutationRequest write_file{};
    write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
    write_file.path = L"\\truncate.bin";
    write_file.offset = 0;
    write_file.length = 3072;
    ok &= ExpectMutationStatus(
        store,
        write_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "Truncate: Write truncate.bin should apply");

    const auto initial_payload = BuildPatternPayload(3072, 0x4D);
    staged_payloads[L"\\truncate.bin"] = initial_payload;
    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "Truncate: initial commit should succeed");

    const auto truncate_before = store.LookupCommittedInodeByPath(L"\\truncate.bin");
    ok &= Require(truncate_before.has_value(), "Truncate: truncate.bin should exist after initial commit");
    if (!truncate_before.has_value())
    {
        return false;
    }
    ok &= Require(
        truncate_before->logical_size == static_cast<std::uint64_t>(initial_payload.size()),
        "Truncate: logical size should match initial payload");
    const auto free_extents_before = store.CommittedFreeExtentCount();

    apfsaccess::rw::MetadataStore::MutationRequest truncate_file{};
    truncate_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::SetFileSize;
    truncate_file.path = L"\\truncate.bin";
    truncate_file.length = 0;
    ok &= ExpectMutationStatus(
        store,
        truncate_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "Truncate: SetFileSize to zero should apply");

    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "Truncate: truncate commit should succeed");

    const auto truncate_after = store.LookupCommittedInodeByPath(L"\\truncate.bin");
    ok &= Require(truncate_after.has_value(), "Truncate: truncate.bin should persist after truncate");
    if (truncate_after.has_value())
    {
        ok &= Require(truncate_after->logical_size == 0, "Truncate: logical size should be zero after truncate");
        ok &= Require(truncate_after->data_physical_address == 0, "Truncate: physical extent should clear after truncate");
    }
    ok &= Require(
        store.CommittedFreeExtentCount() > free_extents_before,
        "Truncate: truncate should increase committed free extent count");

    return ok;
}

bool TestDirectorySubtreeRenameObjectMapConformance(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "directory_subtree_rename.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "TestDirectorySubtreeRenameObjectMapConformance: unable to create synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"DirectorySubtreeRename",
    };
    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "DirectorySubtreeRename: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "DirectorySubtreeRename: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "DirectorySubtreeRename: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "DirectorySubtreeRename: PrepareNativeWritePath should succeed");

    std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
    ConfigurePayloadProvider(store, staged_payloads);

    apfsaccess::rw::MetadataStore::MutationRequest create_directory{};
    create_directory.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateDirectory;
    create_directory.path = L"\\A";
    ok &= ExpectMutationStatus(
        store,
        create_directory,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "DirectorySubtreeRename: create \\A should apply");

    create_directory.path = L"\\A\\B";
    ok &= ExpectMutationStatus(
        store,
        create_directory,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "DirectorySubtreeRename: create \\A\\B should apply");

    apfsaccess::rw::MetadataStore::MutationRequest create_leaf{};
    create_leaf.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
    create_leaf.path = L"\\A\\B\\leaf.bin";
    ok &= ExpectMutationStatus(
        store,
        create_leaf,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "DirectorySubtreeRename: create leaf should apply");

    apfsaccess::rw::MetadataStore::MutationRequest write_leaf{};
    write_leaf.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
    write_leaf.path = L"\\A\\B\\leaf.bin";
    write_leaf.length = 1536;
    ok &= ExpectMutationStatus(
        store,
        write_leaf,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "DirectorySubtreeRename: write leaf should apply");

    const auto leaf_payload = BuildPatternPayload(1536, 0x6B);
    staged_payloads[L"\\A\\B\\leaf.bin"] = leaf_payload;

    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "DirectorySubtreeRename: baseline commit should succeed");

    const auto baseline_xid = store.LastCommittedXid().value_or(0);
    ok &= Require(
        baseline_xid == (kInitialCheckpointXid + 1),
        "DirectorySubtreeRename: baseline commit should advance xid");

    const auto a_before = store.LookupCommittedInodeByPath(L"\\A");
    const auto b_before = store.LookupCommittedInodeByPath(L"\\A\\B");
    const auto leaf_before = store.LookupCommittedInodeByPath(L"\\A\\B\\leaf.bin");
    ok &= Require(a_before.has_value(), "DirectorySubtreeRename: \\A inode should exist after baseline commit");
    ok &= Require(b_before.has_value(), "DirectorySubtreeRename: \\A\\B inode should exist after baseline commit");
    ok &= Require(leaf_before.has_value(), "DirectorySubtreeRename: leaf inode should exist after baseline commit");
    if (!a_before.has_value() || !b_before.has_value() || !leaf_before.has_value())
    {
        return false;
    }

    const auto leaf_object_before = store.LookupCommittedObject(leaf_before->object_id);
    ok &= Require(
        leaf_object_before.has_value(),
        "DirectorySubtreeRename: leaf object-map entry should exist after baseline commit");
    if (leaf_object_before.has_value())
    {
        ok &= Require(
            leaf_object_before->xid == baseline_xid,
            "DirectorySubtreeRename: leaf object-map xid should match baseline xid");
    }

    apfsaccess::rw::MetadataStore::MutationRequest rename_subtree{};
    rename_subtree.operation = apfsaccess::rw::MetadataStore::MutationOperation::Rename;
    rename_subtree.path = L"\\A";
    rename_subtree.secondary_path = L"\\RenamedA";
    ok &= ExpectMutationStatus(
        store,
        rename_subtree,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "DirectorySubtreeRename: subtree rename should apply");

    staged_payloads[L"\\RenamedA\\B\\leaf.bin"] = leaf_payload;
    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "DirectorySubtreeRename: subtree rename commit should succeed");

    const auto rename_xid = store.LastCommittedXid().value_or(0);
    ok &= Require(
        rename_xid == (baseline_xid + 1),
        "DirectorySubtreeRename: rename commit should advance xid");

    ok &= Require(
        !store.LookupCommittedInodeByPath(L"\\A").has_value() &&
            !store.LookupCommittedInodeByPath(L"\\A\\B").has_value() &&
            !store.LookupCommittedInodeByPath(L"\\A\\B\\leaf.bin").has_value(),
        "DirectorySubtreeRename: old subtree paths should be absent after rename");

    const auto a_after = store.LookupCommittedInodeByPath(L"\\RenamedA");
    const auto b_after = store.LookupCommittedInodeByPath(L"\\RenamedA\\B");
    const auto leaf_after = store.LookupCommittedInodeByPath(L"\\RenamedA\\B\\leaf.bin");
    ok &= Require(a_after.has_value(), "DirectorySubtreeRename: renamed root inode should exist");
    ok &= Require(b_after.has_value(), "DirectorySubtreeRename: renamed child directory inode should exist");
    ok &= Require(leaf_after.has_value(), "DirectorySubtreeRename: renamed leaf inode should exist");
    if (!a_after.has_value() || !b_after.has_value() || !leaf_after.has_value())
    {
        return false;
    }

    ok &= Require(
        a_after->object_id == a_before->object_id &&
            b_after->object_id == b_before->object_id &&
            leaf_after->object_id == leaf_before->object_id,
        "DirectorySubtreeRename: subtree rename should preserve inode object ids");

    const auto leaf_object_after = store.LookupCommittedObject(leaf_after->object_id);
    ok &= Require(!store.LookupCommittedObject(a_after->object_id).has_value(), "DirectorySubtreeRename: renamed root directory should not consume a physical object-map slot");
    ok &= Require(!store.LookupCommittedObject(b_after->object_id).has_value(), "DirectorySubtreeRename: renamed child directory should not consume a physical object-map slot");
    ok &= Require(leaf_object_after.has_value(), "DirectorySubtreeRename: renamed leaf object-map entry should exist");
    if (leaf_object_after.has_value())
    {
        ok &= Require(
            leaf_object_after->xid == rename_xid,
            "DirectorySubtreeRename: renamed file object-map xid projection should match rename commit xid");
    }

    std::vector<std::byte> persisted_leaf_payload;
    ok &= Require(
        store.ReadCommittedFileRange(
            L"\\RenamedA\\B\\leaf.bin",
            0,
            leaf_payload.size(),
            persisted_leaf_payload),
        "DirectorySubtreeRename: renamed leaf payload should be readable");
    ok &= Require(
        persisted_leaf_payload == leaf_payload,
        "DirectorySubtreeRename: renamed leaf payload should remain unchanged");

    return ok;
}

bool TestDirectorySubtreeRenameChildIndexConformance(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "directory_subtree_rename_child_index.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "SubtreeRenameChildIndex: unable to create synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"SubtreeRenameChildIndex",
    };
    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "SubtreeRenameChildIndex: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "SubtreeRenameChildIndex: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "SubtreeRenameChildIndex: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "SubtreeRenameChildIndex: PrepareNativeWritePath should succeed");

    apfsaccess::rw::MetadataStore::MutationRequest create_directory{};
    create_directory.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateDirectory;
    create_directory.path = L"\\IndexedRoot";
    ok &= ExpectMutationStatus(
        store,
        create_directory,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "SubtreeRenameChildIndex: create root should apply");

    apfsaccess::rw::MetadataStore::MutationRequest create_file{};
    create_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
    constexpr int kBranchCount = 6;
    for (int branch = 0; branch < kBranchCount; ++branch)
    {
        const auto branch_name = L"Dir" + std::to_wstring(branch);
        create_directory.path = L"\\IndexedRoot\\" + branch_name;
        ok &= ExpectMutationStatus(
            store,
            create_directory,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "SubtreeRenameChildIndex: create branch should apply");

        create_directory.path = L"\\IndexedRoot\\" + branch_name + L"\\Nested";
        ok &= ExpectMutationStatus(
            store,
            create_directory,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "SubtreeRenameChildIndex: create nested branch should apply");

        create_file.path = L"\\IndexedRoot\\" + branch_name + L"\\Nested\\leaf" + std::to_wstring(branch) + L".txt";
        ok &= ExpectMutationStatus(
            store,
            create_file,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "SubtreeRenameChildIndex: create leaf should apply");
    }

    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "SubtreeRenameChildIndex: baseline commit should succeed");

    const auto root_before = store.LookupCommittedInodeByPath(L"\\IndexedRoot");
    if (!Require(root_before.has_value(), "SubtreeRenameChildIndex: committed root should exist"))
    {
        return false;
    }

    constexpr std::size_t kExpectedDescendants = static_cast<std::size_t>(kBranchCount * 3);
    ok &= Require(
        store.DebugWorkingDirectoryChildCount(root_before->object_id) == static_cast<std::size_t>(kBranchCount),
        "SubtreeRenameChildIndex: root child index should track direct branches");
    ok &= Require(
        store.DebugWorkingDirectoryDescendantCount(root_before->object_id) == kExpectedDescendants,
        "SubtreeRenameChildIndex: root descendant index should track the whole subtree");
    const auto descendant_path_lookups_before = store.DirectoryRenameDescendantPathLookupCount();
    const auto descendant_directory_link_updates_before =
        store.DirectoryRenameDescendantDirectoryLinkUpdateCount();

    apfsaccess::rw::MetadataStore::MutationRequest rename_subtree{};
    rename_subtree.operation = apfsaccess::rw::MetadataStore::MutationOperation::Rename;
    rename_subtree.path = L"\\IndexedRoot";
    rename_subtree.secondary_path = L"\\IndexedRenamed";
    ok &= ExpectMutationStatus(
        store,
        rename_subtree,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "SubtreeRenameChildIndex: indexed subtree rename should apply");

    const auto root_after_stage = store.DebugLookupWorkingInodeByPath(L"\\IndexedRenamed");
    if (!Require(root_after_stage.has_value(), "SubtreeRenameChildIndex: staged renamed root should exist"))
    {
        return false;
    }
    ok &= Require(
        store.DebugWorkingDirectoryChildCount(root_after_stage->object_id) == static_cast<std::size_t>(kBranchCount),
        "SubtreeRenameChildIndex: renamed root child index should retain direct branches");
    ok &= Require(
        store.DebugWorkingDirectoryDescendantCount(root_after_stage->object_id) == kExpectedDescendants,
        "SubtreeRenameChildIndex: renamed root descendant index should retain the whole subtree");
    ok &= Require(
        !store.DebugLookupWorkingInodeByPath(L"\\IndexedRoot\\Dir0\\Nested\\leaf0.txt").has_value(),
        "SubtreeRenameChildIndex: old staged descendant path should be absent");
    ok &= Require(
        store.DebugLookupWorkingInodeByPath(L"\\IndexedRenamed\\Dir0\\Nested\\leaf0.txt").has_value(),
        "SubtreeRenameChildIndex: new staged descendant path should exist");
    ok &= Require(
        store.DirectoryRenameDescendantPathLookupCount() == descendant_path_lookups_before,
        "SubtreeRenameChildIndex: descendant remap should not look up old paths");
    ok &= Require(
        store.DirectoryRenameDescendantDirectoryLinkUpdateCount() == descendant_directory_link_updates_before,
        "SubtreeRenameChildIndex: descendant remap should not rewrite unchanged directory links");

    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "SubtreeRenameChildIndex: rename commit should succeed");
    ok &= Require(
        !store.LookupCommittedInodeByPath(L"\\IndexedRoot\\Dir5\\Nested\\leaf5.txt").has_value(),
        "SubtreeRenameChildIndex: old committed descendant path should be absent");
    ok &= Require(
        store.LookupCommittedInodeByPath(L"\\IndexedRenamed\\Dir5\\Nested\\leaf5.txt").has_value(),
        "SubtreeRenameChildIndex: new committed descendant path should exist");

    return ok;
}

bool TestDirectorySubtreeRenameMatchesSourceCaseInsensitivelyConformance(
    const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "directory_subtree_rename_source_case.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "SubtreeRenameSourceCase: unable to create synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"SubtreeRenameSourceCase",
    };
    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "SubtreeRenameSourceCase: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "SubtreeRenameSourceCase: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "SubtreeRenameSourceCase: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "SubtreeRenameSourceCase: PrepareNativeWritePath should succeed");

    apfsaccess::rw::MetadataStore::MutationRequest create_directory{};
    create_directory.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateDirectory;
    create_directory.path = L"\\CaseSource";
    ok &= ExpectMutationStatus(
        store,
        create_directory,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "SubtreeRenameSourceCase: create source should apply");

    create_directory.path = L"\\CaseSource\\Child";
    ok &= ExpectMutationStatus(
        store,
        create_directory,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "SubtreeRenameSourceCase: create child should apply");
    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "SubtreeRenameSourceCase: baseline commit should succeed");

    apfsaccess::rw::MetadataStore::MutationRequest rename_directory{};
    rename_directory.operation = apfsaccess::rw::MetadataStore::MutationOperation::Rename;
    rename_directory.path = L"\\CASESOURCE";
    rename_directory.secondary_path = L"\\Moved";
    ok &= ExpectMutationStatus(
        store,
        rename_directory,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "SubtreeRenameSourceCase: mixed-case source rename should apply");

    const auto staged_child = store.DebugLookupWorkingInodeByPath(L"\\Moved\\Child");
    ok &= Require(
        staged_child.has_value() && staged_child->full_path == L"\\Moved\\Child",
        "SubtreeRenameSourceCase: staged child should follow the renamed directory with preserved child casing");
    ok &= Require(
        !store.DebugLookupWorkingInodeByPath(L"\\CaseSource\\Child").has_value(),
        "SubtreeRenameSourceCase: old staged child path should be absent");
    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "SubtreeRenameSourceCase: mixed-case source rename commit should succeed");
    ok &= Require(
        store.LookupCommittedInodeByPath(L"\\Moved\\Child").has_value(),
        "SubtreeRenameSourceCase: renamed child should persist");

    return ok;
}

bool TestPendingWriteDirectoryRenamePersistenceConformance(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "pending_write_directory_rename.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "PendingWriteDirectoryRename: unable to create synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"PendingWriteDirectoryRename",
    };
    bool ok = true;
    const auto baseline_payload = BuildPatternPayload(1024, 0x34);
    const auto renamed_payload = BuildPatternPayload(2048, 0x9A);

    {
        apfsaccess::rw::MetadataStore store(context);
        ok &= Require(store.LoadContainerSuperblocks(), "PendingWriteDirectoryRename: LoadContainerSuperblocks should succeed");
        ok &= Require(store.LoadObjectMap(), "PendingWriteDirectoryRename: LoadObjectMap should succeed");
        ok &= Require(store.LoadSpacemanState(), "PendingWriteDirectoryRename: LoadSpacemanState should succeed");
        ok &= Require(store.PrepareNativeWritePath(), "PendingWriteDirectoryRename: PrepareNativeWritePath should succeed");

        std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
        ConfigurePayloadProvider(store, staged_payloads);

        apfsaccess::rw::MetadataStore::MutationRequest create_directory{};
        create_directory.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateDirectory;
        create_directory.path = L"\\Source";
        ok &= ExpectMutationStatus(
            store,
            create_directory,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "PendingWriteDirectoryRename: create \\Source should apply");

        create_directory.path = L"\\Source\\Nested";
        ok &= ExpectMutationStatus(
            store,
            create_directory,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "PendingWriteDirectoryRename: create nested directory should apply");

        apfsaccess::rw::MetadataStore::MutationRequest create_file{};
        create_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
        create_file.path = L"\\Source\\Nested\\dirty.bin";
        ok &= ExpectMutationStatus(
            store,
            create_file,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "PendingWriteDirectoryRename: create dirty file should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_file{};
        write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_file.path = L"\\Source\\Nested\\dirty.bin";
        write_file.length = baseline_payload.size();
        ok &= ExpectMutationStatus(
            store,
            write_file,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "PendingWriteDirectoryRename: initial write should apply");
        staged_payloads[L"\\Source\\Nested\\dirty.bin"] = baseline_payload;

        ok &= ExpectCommitStatus(
            store,
            apfsaccess::rw::MetadataStore::CommitStatus::Committed,
            "PendingWriteDirectoryRename: baseline commit should succeed");

        staged_payloads.clear();
        write_file.length = renamed_payload.size();
        ok &= ExpectMutationStatus(
            store,
            write_file,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "PendingWriteDirectoryRename: overwrite before rename should apply");
        staged_payloads[L"\\Source\\Nested\\dirty.bin"] = renamed_payload;

        apfsaccess::rw::MetadataStore::MutationRequest rename_directory{};
        rename_directory.operation = apfsaccess::rw::MetadataStore::MutationOperation::Rename;
        rename_directory.path = L"\\Source";
        rename_directory.secondary_path = L"\\Moved";
        ok &= ExpectMutationStatus(
            store,
            rename_directory,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "PendingWriteDirectoryRename: directory rename should apply");

        staged_payloads[L"\\Moved\\Nested\\dirty.bin"] = renamed_payload;
        staged_payloads.erase(L"\\Source\\Nested\\dirty.bin");

        ok &= ExpectCommitStatus(
            store,
            apfsaccess::rw::MetadataStore::CommitStatus::Committed,
            "PendingWriteDirectoryRename: rename commit should succeed");

        ok &= Require(
            !store.LookupCommittedInodeByPath(L"\\Source\\Nested\\dirty.bin").has_value(),
            "PendingWriteDirectoryRename: old path should be absent after rename commit");
        auto renamed_inode = store.LookupCommittedInodeByPath(L"\\Moved\\Nested\\dirty.bin");
        ok &= Require(renamed_inode.has_value(), "PendingWriteDirectoryRename: renamed file should exist after commit");
        if (renamed_inode.has_value())
        {
            ok &= Require(
                renamed_inode->logical_size == renamed_payload.size(),
                "PendingWriteDirectoryRename: renamed file logical size should match overwrite");
        }

        std::vector<std::byte> committed_payload;
        ok &= Require(
            store.ReadCommittedFileRange(
                L"\\Moved\\Nested\\dirty.bin",
                0,
                renamed_payload.size(),
                committed_payload),
            "PendingWriteDirectoryRename: committed payload should be readable after rename");
        ok &= Require(
            committed_payload == renamed_payload,
            "PendingWriteDirectoryRename: committed payload should follow renamed descendant");
    }

    {
        apfsaccess::rw::MetadataStore remounted(context);
        ok &= Require(remounted.LoadContainerSuperblocks(), "PendingWriteDirectoryRename: remount LoadContainerSuperblocks should succeed");
        ok &= Require(remounted.PrepareNativeWritePath(), "PendingWriteDirectoryRename: remount PrepareNativeWritePath should succeed");
        ok &= Require(!remounted.IsRecoveryRequired(), "PendingWriteDirectoryRename: remount should not require recovery");
        ok &= Require(remounted.IsCommitPathReady(), "PendingWriteDirectoryRename: remount commit path should remain ready");
        ok &= Require(
            !remounted.LookupCommittedInodeByPath(L"\\Source\\Nested\\dirty.bin").has_value(),
            "PendingWriteDirectoryRename: remount old path should stay absent");
        auto remounted_inode = remounted.LookupCommittedInodeByPath(L"\\Moved\\Nested\\dirty.bin");
        ok &= Require(remounted_inode.has_value(), "PendingWriteDirectoryRename: remount renamed file should exist");
        if (remounted_inode.has_value())
        {
            ok &= Require(
                remounted_inode->logical_size == renamed_payload.size(),
                "PendingWriteDirectoryRename: remount logical size should match overwrite");
        }

        std::vector<std::byte> remounted_payload;
        ok &= Require(
            remounted.ReadCommittedFileRange(
                L"\\Moved\\Nested\\dirty.bin",
                0,
                renamed_payload.size(),
                remounted_payload),
            "PendingWriteDirectoryRename: remount payload should be readable");
        ok &= Require(
            remounted_payload == renamed_payload,
            "PendingWriteDirectoryRename: remount payload should preserve renamed descendant bytes");
    }

    return ok;
}

bool TestInterleavedRenameChainsCoalescePendingMutationsConformance(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "interleaved_rename_chain_coalesce.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "InterleavedRenameChainCoalesce: unable to create synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"InterleavedRenameChainCoalesce",
    };
    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "InterleavedRenameChainCoalesce: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "InterleavedRenameChainCoalesce: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "InterleavedRenameChainCoalesce: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "InterleavedRenameChainCoalesce: PrepareNativeWritePath should succeed");

    std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
    ConfigurePayloadProvider(store, staged_payloads);

    ok &= CreateAndCommitFile(
        store,
        staged_payloads,
        L"\\alpha.bin",
        4096,
        0x41,
        "InterleavedRenameChainCoalesce alpha");
    ok &= CreateAndCommitFile(
        store,
        staged_payloads,
        L"\\bravo.bin",
        4096,
        0x42,
        "InterleavedRenameChainCoalesce bravo");

    const auto alpha_payload = staged_payloads[L"\\alpha.bin"];
    const auto bravo_payload = staged_payloads[L"\\bravo.bin"];

    apfsaccess::rw::MetadataStore::MutationRequest alpha_first{};
    alpha_first.operation = apfsaccess::rw::MetadataStore::MutationOperation::Rename;
    alpha_first.path = L"\\alpha.bin";
    alpha_first.secondary_path = L"\\alpha.tmp";
    ok &= ExpectMutationStatus(
        store,
        alpha_first,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "InterleavedRenameChainCoalesce: first alpha rename should apply");
    const auto pending_after_alpha_first = store.PendingMutationCount();

    apfsaccess::rw::MetadataStore::MutationRequest bravo_rename{};
    bravo_rename.operation = apfsaccess::rw::MetadataStore::MutationOperation::Rename;
    bravo_rename.path = L"\\bravo.bin";
    bravo_rename.secondary_path = L"\\bravo.final";
    ok &= ExpectMutationStatus(
        store,
        bravo_rename,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "InterleavedRenameChainCoalesce: interleaved bravo rename should apply");
    const auto close_delay_rebuilds_before_alpha_second = store.PendingCloseDelaySummaryRebuildCount();
    const auto cache_before_alpha_second = store.PerformanceJson();
    const auto cache_hits_before_alpha_second = ExtractNestedUnsignedValue(
        cache_before_alpha_second,
        "pendingRenamePathKeyCache",
        "hits");
    const auto cache_misses_before_alpha_second = ExtractNestedUnsignedValue(
        cache_before_alpha_second,
        "pendingRenamePathKeyCache",
        "misses");
    ok &= Require(
        cache_hits_before_alpha_second.has_value() &&
            cache_misses_before_alpha_second.has_value(),
        "InterleavedRenameChainCoalesce: pending rename key-cache counters should exist");

    apfsaccess::rw::MetadataStore::MutationRequest alpha_second{};
    alpha_second.operation = apfsaccess::rw::MetadataStore::MutationOperation::Rename;
    alpha_second.path = L"\\alpha.tmp";
    alpha_second.secondary_path = L"\\alpha.final";
    ok &= ExpectMutationStatus(
        store,
        alpha_second,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "InterleavedRenameChainCoalesce: second alpha rename should apply");
    ok &= Require(
        store.PendingMutationCount() == pending_after_alpha_first + 1,
        "InterleavedRenameChainCoalesce: interleaved rename chains should retain one pending rename per source object");
    ok &= Require(
        store.PendingCloseDelaySummaryRebuildCount() == close_delay_rebuilds_before_alpha_second,
        "InterleavedRenameChainCoalesce: rename-chain coalescing should not rebuild the close-delay summary");
    const auto cache_after_alpha_second = store.PerformanceJson();
    const auto cache_hits_after_alpha_second = ExtractNestedUnsignedValue(
        cache_after_alpha_second,
        "pendingRenamePathKeyCache",
        "hits");
    const auto cache_misses_after_alpha_second = ExtractNestedUnsignedValue(
        cache_after_alpha_second,
        "pendingRenamePathKeyCache",
        "misses");
    ok &= Require(
        cache_hits_after_alpha_second.has_value() &&
            cache_misses_after_alpha_second.has_value(),
        "InterleavedRenameChainCoalesce: pending rename key-cache counters should still exist after alpha chain");
    if (cache_hits_before_alpha_second.has_value() &&
        cache_hits_after_alpha_second.has_value() &&
        cache_misses_before_alpha_second.has_value() &&
        cache_misses_after_alpha_second.has_value())
    {
        ok &= Require(
            cache_hits_after_alpha_second.value() > cache_hits_before_alpha_second.value(),
            "InterleavedRenameChainCoalesce: repeated pending rename scans should reuse cached path keys");
        ok &= Require(
            cache_misses_after_alpha_second.value() >= cache_misses_before_alpha_second.value(),
            "InterleavedRenameChainCoalesce: cache misses should remain monotonic");
    }

    apfsaccess::rw::MetadataStore::MutationRequest bravo_second{};
    bravo_second.operation = apfsaccess::rw::MetadataStore::MutationOperation::Rename;
    bravo_second.path = L"\\bravo.final";
    bravo_second.secondary_path = L"\\bravo.done";
    ok &= ExpectMutationStatus(
        store,
        bravo_second,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "InterleavedRenameChainCoalesce: second bravo rename should apply");
    ok &= Require(
        store.PendingMutationCount() == pending_after_alpha_first + 1,
        "InterleavedRenameChainCoalesce: second interleaved rename should keep one pending rename per source object");
    const auto cache_after_bravo_second = store.PerformanceJson();
    const auto cache_hits_after_bravo_second = ExtractNestedUnsignedValue(
        cache_after_bravo_second,
        "pendingRenamePathKeyCache",
        "hits");
    if (cache_hits_after_alpha_second.has_value() &&
        cache_hits_after_bravo_second.has_value())
    {
        ok &= Require(
            cache_hits_after_bravo_second.value() > cache_hits_after_alpha_second.value(),
            "InterleavedRenameChainCoalesce: later interleaved chain should keep reusing cached path keys");
    }

    staged_payloads.erase(L"\\alpha.bin");
    staged_payloads.erase(L"\\bravo.bin");
    staged_payloads[L"\\alpha.final"] = alpha_payload;
    staged_payloads[L"\\bravo.done"] = bravo_payload;

    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "InterleavedRenameChainCoalesce: compacted rename batch commit should succeed");

    std::vector<std::byte> alpha_committed;
    ok &= Require(
        store.ReadCommittedFileRange(L"\\alpha.final", 0, alpha_payload.size(), alpha_committed),
        "InterleavedRenameChainCoalesce: alpha payload should be readable at final path");
    ok &= Require(
        alpha_committed == alpha_payload,
        "InterleavedRenameChainCoalesce: alpha payload should survive compacted rename chain");
    std::vector<std::byte> bravo_committed;
    ok &= Require(
        store.ReadCommittedFileRange(L"\\bravo.done", 0, bravo_payload.size(), bravo_committed),
        "InterleavedRenameChainCoalesce: bravo payload should be readable at final path");
    ok &= Require(
        bravo_committed == bravo_payload,
        "InterleavedRenameChainCoalesce: bravo payload should survive interleaved rename");

    return ok;
}

bool TestPendingPayloadByteEstimateTracksFinalSetFileSizeConformance(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "pending_payload_estimate.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "PendingPayloadEstimate: unable to create synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"PendingPayloadEstimate",
    };

    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "PendingPayloadEstimate: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "PendingPayloadEstimate: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "PendingPayloadEstimate: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "PendingPayloadEstimate: PrepareNativeWritePath should succeed");

    apfsaccess::rw::MetadataStore::MutationRequest create_file{};
    create_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
    create_file.path = L"\\installer.exe";
    ok &= ExpectMutationStatus(
        store,
        create_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "PendingPayloadEstimate: create file should apply");

    constexpr std::uint64_t payload_bytes = 512ull * 1024ull;
    apfsaccess::rw::MetadataStore::MutationRequest set_size{};
    set_size.operation = apfsaccess::rw::MetadataStore::MutationOperation::SetFileSize;
    set_size.path = L"\\installer.exe";
    set_size.length = payload_bytes;
    ok &= ExpectMutationStatus(
        store,
        set_size,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "PendingPayloadEstimate: SetFileSize should apply");
    ok &= Require(
        store.PendingPayloadByteEstimate() == payload_bytes,
        "PendingPayloadEstimate: pending payload estimate should include final logical file size");

    apfsaccess::rw::MetadataStore::MutationRequest truncate_zero{};
    truncate_zero.operation = apfsaccess::rw::MetadataStore::MutationOperation::SetFileSize;
    truncate_zero.path = L"\\installer.exe";
    truncate_zero.length = 0;
    ok &= ExpectMutationStatus(
        store,
        truncate_zero,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "PendingPayloadEstimate: zero-length SetFileSize should apply");
    ok &= Require(
        store.PendingPayloadByteEstimate() == 0,
        "PendingPayloadEstimate: pending payload estimate should drop files truncated to zero");

    return ok;
}

bool TestPendingPayloadByteEstimateTracksRepeatedSizeGrowthConformance(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "pending_payload_repeated_growth.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "PendingPayloadRepeatedGrowth: unable to create synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"PendingPayloadRepeatedGrowth",
    };

    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "PendingPayloadRepeatedGrowth: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "PendingPayloadRepeatedGrowth: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "PendingPayloadRepeatedGrowth: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "PendingPayloadRepeatedGrowth: PrepareNativeWritePath should succeed");

    apfsaccess::rw::MetadataStore::MutationRequest create_file{};
    create_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
    create_file.path = L"\\grow.bin";
    ok &= ExpectMutationStatus(
        store,
        create_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "PendingPayloadRepeatedGrowth: create file should apply");

    apfsaccess::rw::MetadataStore::MutationRequest set_size{};
    set_size.operation = apfsaccess::rw::MetadataStore::MutationOperation::SetFileSize;
    set_size.path = L"\\grow.bin";

    set_size.length = 64ull * 1024ull;
    ok &= ExpectMutationStatus(
        store,
        set_size,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "PendingPayloadRepeatedGrowth: first SetFileSize should apply");
    ok &= Require(
        store.PendingPayloadByteEstimate() == set_size.length,
        "PendingPayloadRepeatedGrowth: first size should update cached estimate");
    const auto pending_count_after_first_size = store.PendingMutationCount();

    const auto path_fallbacks_before_second_size =
        store.PendingSetFileSizeCoalescePathFallbackCount();
    set_size.length = 256ull * 1024ull;
    ok &= ExpectMutationStatus(
        store,
        set_size,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "PendingPayloadRepeatedGrowth: second SetFileSize should apply");
    ok &= Require(
        store.PendingPayloadByteEstimate() == set_size.length,
        "PendingPayloadRepeatedGrowth: second size should replace cached estimate");
    ok &= Require(
        store.PendingMutationCount() == pending_count_after_first_size,
        "PendingPayloadRepeatedGrowth: consecutive SetFileSize should replace the older pending size mutation");
    ok &= Require(
        store.PendingSetFileSizeCoalescePathFallbackCount() == path_fallbacks_before_second_size,
        "PendingPayloadRepeatedGrowth: consecutive SetFileSize should reuse the staged canonical path key");

    const auto path_fallbacks_before_shrink =
        store.PendingSetFileSizeCoalescePathFallbackCount();
    set_size.length = 32ull * 1024ull;
    ok &= ExpectMutationStatus(
        store,
        set_size,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "PendingPayloadRepeatedGrowth: shrinking SetFileSize should apply");
    ok &= Require(
        store.PendingPayloadByteEstimate() == set_size.length,
        "PendingPayloadRepeatedGrowth: shrinking size should replace cached estimate");
    ok &= Require(
        store.PendingMutationCount() == pending_count_after_first_size,
        "PendingPayloadRepeatedGrowth: shrinking consecutive SetFileSize should keep one pending size mutation");
    ok &= Require(
        store.PendingSetFileSizeCoalescePathFallbackCount() == path_fallbacks_before_shrink,
        "PendingPayloadRepeatedGrowth: shrinking SetFileSize should reuse the staged canonical path key");

    return ok;
}

bool TestRepeatedSetFileSizeReusesPendingExtentConformance(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "repeated_set_file_size_reuses_pending_extent.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "RepeatedSetFileSizeReuse: unable to create synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"RepeatedSetFileSizeReuse",
    };

    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "RepeatedSetFileSizeReuse: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "RepeatedSetFileSizeReuse: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "RepeatedSetFileSizeReuse: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "RepeatedSetFileSizeReuse: PrepareNativeWritePath should succeed");

    apfsaccess::rw::MetadataStore::MutationRequest create_file{};
    create_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
    create_file.path = L"\\resize-burst.bin";
    ok &= ExpectMutationStatus(
        store,
        create_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "RepeatedSetFileSizeReuse: create file should apply");

    apfsaccess::rw::MetadataStore::MutationRequest set_size{};
    set_size.operation = apfsaccess::rw::MetadataStore::MutationOperation::SetFileSize;
    set_size.path = L"\\resize-burst.bin";
    set_size.length = 256ull * 1024ull;
    ok &= ExpectMutationStatus(
        store,
        set_size,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "RepeatedSetFileSizeReuse: first SetFileSize should preallocate");

    const auto inode_after_first = store.DebugLookupWorkingInodeByPath(L"\\resize-burst.bin");
    ok &= Require(
        inode_after_first.has_value() && inode_after_first->data_physical_address != 0,
        "RepeatedSetFileSizeReuse: first preallocation should assign physical storage");
    const auto first_physical = inode_after_first.value().data_physical_address;
    const auto allocations_after_first = store.PendingAllocationCount();
    const auto deallocations_after_first = store.PendingDeallocationCount();
    const auto allocation_index_after_first = store.PendingSpacemanAllocationIndexCount();
    const auto free_bytes_after_first = store.DebugWorkingFreeExtentTotalBytes();

    set_size.length = 128ull * 1024ull;
    ok &= ExpectMutationStatus(
        store,
        set_size,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "RepeatedSetFileSizeReuse: smaller SetFileSize should reuse pending allocation");

    const auto inode_after_second = store.DebugLookupWorkingInodeByPath(L"\\resize-burst.bin");
    ok &= Require(
        inode_after_second.has_value(),
        "RepeatedSetFileSizeReuse: inode should remain visible after second SetFileSize");
    ok &= Require(
        inode_after_second->data_physical_address == first_physical,
        "RepeatedSetFileSizeReuse: second SetFileSize should keep the existing physical allocation");
    ok &= Require(
        store.PendingAllocationCount() == allocations_after_first,
        "RepeatedSetFileSizeReuse: second SetFileSize should not add pending allocations");
    ok &= Require(
        store.PendingDeallocationCount() == deallocations_after_first,
        "RepeatedSetFileSizeReuse: second SetFileSize should not add pending deallocations");
    ok &= Require(
        store.PendingSpacemanAllocationIndexCount() == allocation_index_after_first,
        "RepeatedSetFileSizeReuse: pending allocation index should stay stable");
    ok &= Require(
        store.DebugWorkingFreeExtentTotalBytes() == free_bytes_after_first,
        "RepeatedSetFileSizeReuse: pending resize should not churn working free extents");
    ok &= Require(
        store.PendingPayloadByteEstimate() == set_size.length,
        "RepeatedSetFileSizeReuse: pending payload estimate should reflect the final logical size");

    return ok;
}

bool TestCommittedSameSizeResizePreservesExtentsConformance(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "committed_same_size_resize_preserves_extents.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "CommittedSameSizeResize: unable to create synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"CommittedSameSizeResize",
    };

    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "CommittedSameSizeResize: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "CommittedSameSizeResize: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "CommittedSameSizeResize: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "CommittedSameSizeResize: PrepareNativeWritePath should succeed");

    const std::wstring path = L"\\same-size.bin";
    const auto payload = BuildPatternPayload(64 * 1024, 0x67);
    std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
    ConfigurePayloadProvider(store, staged_payloads);
    if (!CreateAndCommitFile(
            store,
            staged_payloads,
            path,
            payload.size(),
            0x67,
            "CommittedSameSizeResize: seed file"))
    {
        return false;
    }

    const auto committed_before = store.LookupCommittedInodeByPath(path);
    ok &= Require(
        committed_before.has_value() && committed_before->logical_size == payload.size(),
        "CommittedSameSizeResize: seeded file should be committed at the expected size");
    if (!committed_before.has_value())
    {
        return false;
    }

    std::uint64_t provider_calls = 0;
    std::uint64_t provider_bytes = 0;
    store.SetFilePayloadProvider(
        [&staged_payloads, &provider_calls, &provider_bytes](
            const std::wstring& requested_path,
            std::uint64_t logical_size) -> std::optional<std::vector<std::byte>>
        {
            ++provider_calls;
            provider_bytes += logical_size;
            auto payload_it = staged_payloads.find(requested_path);
            if (payload_it == staged_payloads.end())
            {
                return std::nullopt;
            }
            return payload_it->second;
        });

    const auto before_json = store.PerformanceJson();
    const auto before_payload_writes = ExtractNestedPerfCounterCount(before_json, "blockDevice", "write");
    const auto before_pending_allocations = store.PendingAllocationCount();
    const auto before_pending_deallocations = store.PendingDeallocationCount();
    const auto before_free_extents = store.CommittedFreeExtentCount();

    apfsaccess::rw::MetadataStore::MutationRequest same_size{};
    same_size.operation = apfsaccess::rw::MetadataStore::MutationOperation::SetFileSize;
    same_size.path = path;
    same_size.length = payload.size();
    ok &= ExpectMutationStatus(
        store,
        same_size,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "CommittedSameSizeResize: same-size SetFileSize should apply");

    const auto working_after = store.DebugLookupWorkingInodeByPath(path);
    ok &= Require(
        working_after.has_value() &&
            working_after->data_physical_address == committed_before->data_physical_address,
        "CommittedSameSizeResize: same-size SetFileSize should preserve the physical extent before commit");
    ok &= Require(
        store.PendingAllocationCount() == before_pending_allocations &&
            store.PendingDeallocationCount() == before_pending_deallocations,
        "CommittedSameSizeResize: same-size SetFileSize should not churn pending allocations");

    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "CommittedSameSizeResize: same-size commit should succeed");

    const auto committed_after = store.LookupCommittedInodeByPath(path);
    ok &= Require(
        committed_after.has_value() &&
            committed_after->data_physical_address == committed_before->data_physical_address &&
            committed_after->logical_size == committed_before->logical_size &&
            committed_after->xid > committed_before->xid,
        "CommittedSameSizeResize: commit should preserve extent and size while advancing inode XID");
    ok &= Require(
        provider_calls == 0 && provider_bytes == 0,
        "CommittedSameSizeResize: same-size commit should not materialize the existing payload");
    ok &= Require(
        store.CommittedFreeExtentCount() == before_free_extents,
        "CommittedSameSizeResize: same-size commit should not change committed free extents");

    if (before_payload_writes.has_value())
    {
        const auto after_payload_writes = ExtractNestedPerfCounterCount(store.PerformanceJson(), "blockDevice", "write");
        ok &= Require(
            after_payload_writes.has_value() && after_payload_writes.value() >= before_payload_writes.value(),
            "CommittedSameSizeResize: block-device write counter should remain readable");
    }

    std::vector<std::byte> committed_payload;
    ok &= Require(
        store.ReadCommittedFileRange(path, 0, payload.size(), committed_payload),
        "CommittedSameSizeResize: committed payload should remain readable");
    ok &= Require(
        committed_payload == payload,
        "CommittedSameSizeResize: committed payload should remain byte-identical");

    {
        apfsaccess::rw::MetadataStore remounted(context);
        ok &= Require(
            remounted.LoadContainerSuperblocks(),
            "CommittedSameSizeResize: remount LoadContainerSuperblocks should succeed");
        ok &= Require(
            remounted.PrepareNativeWritePath(),
            "CommittedSameSizeResize: remount PrepareNativeWritePath should succeed");
        const auto remounted_inode = remounted.LookupCommittedInodeByPath(path);
        ok &= Require(
            remounted_inode.has_value() &&
                remounted_inode->data_physical_address == committed_before->data_physical_address &&
                remounted_inode->logical_size == payload.size(),
            "CommittedSameSizeResize: remount should preserve the original extent and size");
        std::vector<std::byte> remounted_payload;
        ok &= Require(
            remounted.ReadCommittedFileRange(path, 0, payload.size(), remounted_payload),
            "CommittedSameSizeResize: remounted payload should be readable");
        ok &= Require(
            remounted_payload == payload,
            "CommittedSameSizeResize: remounted payload should remain byte-identical");
    }

    return ok;
}

bool TestMutationAllocationUsesLocalWorkingFreeUndoConformance(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "mutation_allocation_local_working_free_undo.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "MutationWorkingFreeUndo: unable to create synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"MutationWorkingFreeUndo",
    };

    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "MutationWorkingFreeUndo: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "MutationWorkingFreeUndo: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "MutationWorkingFreeUndo: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "MutationWorkingFreeUndo: PrepareNativeWritePath should succeed");

    std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
    ConfigurePayloadProvider(store, staged_payloads);

    const auto before_json = store.PerformanceJson();
    const auto before_snapshots = ExtractNestedUnsignedValue(
        before_json,
        "mutationWorkingFreeRollback",
        "workingFreeSnapshots");
    ok &= Require(
        before_snapshots.has_value(),
        "MutationWorkingFreeUndo: perf JSON should expose snapshot counter");

    apfsaccess::rw::MetadataStore::MutationRequest create_file{};
    create_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
    create_file.path = L"\\local-undo.bin";
    ok &= ExpectMutationStatus(
        store,
        create_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "MutationWorkingFreeUndo: create file should apply");

    apfsaccess::rw::MetadataStore::MutationRequest set_size{};
    set_size.operation = apfsaccess::rw::MetadataStore::MutationOperation::SetFileSize;
    set_size.path = L"\\local-undo.bin";
    set_size.length = 512ull * 1024ull;
    staged_payloads[set_size.path] = BuildPatternPayload(static_cast<std::size_t>(set_size.length), 0x5A);
    ok &= ExpectMutationStatus(
        store,
        set_size,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "MutationWorkingFreeUndo: SetFileSize should allocate");

    const auto after_json = store.PerformanceJson();
    const auto after_snapshots = ExtractNestedUnsignedValue(
        after_json,
        "mutationWorkingFreeRollback",
        "workingFreeSnapshots");
    ok &= Require(
        after_snapshots.has_value() && after_snapshots.value() == before_snapshots.value(),
        "MutationWorkingFreeUndo: ordinary single-extent allocation should avoid full working free snapshot");
    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "MutationWorkingFreeUndo: commit should succeed");

    return ok;
}

bool TestSetFileSizeZeroReleasesPendingPreallocationConformance(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "set_file_size_zero_releases_pending_preallocation.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "ZeroPendingPreallocation: unable to create synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"ZeroPendingPreallocation",
    };

    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "ZeroPendingPreallocation: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "ZeroPendingPreallocation: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "ZeroPendingPreallocation: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "ZeroPendingPreallocation: PrepareNativeWritePath should succeed");

    apfsaccess::rw::MetadataStore::MutationRequest create_file{};
    create_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
    create_file.path = L"\\cancelled-copy.bin";
    ok &= ExpectMutationStatus(
        store,
        create_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "ZeroPendingPreallocation: create file should apply");

    apfsaccess::rw::MetadataStore::MutationRequest set_size{};
    set_size.operation = apfsaccess::rw::MetadataStore::MutationOperation::SetFileSize;
    set_size.path = L"\\cancelled-copy.bin";
    set_size.length = 512ull * 1024ull;
    ok &= ExpectMutationStatus(
        store,
        set_size,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "ZeroPendingPreallocation: SetFileSize should preallocate");

    const auto inode_after_preallocate = store.DebugLookupWorkingInodeByPath(L"\\cancelled-copy.bin");
    ok &= Require(
        inode_after_preallocate.has_value() && inode_after_preallocate->data_physical_address != 0,
        "ZeroPendingPreallocation: preallocation should assign physical storage");
    ok &= Require(
        store.PendingAllocationCount() > 0,
        "ZeroPendingPreallocation: preallocation should stage pending allocation");
    const auto deallocations_after_preallocate = store.PendingDeallocationCount();
    const auto free_bytes_after_preallocate = store.DebugWorkingFreeExtentTotalBytes();

    set_size.length = 0;
    ok &= ExpectMutationStatus(
        store,
        set_size,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "ZeroPendingPreallocation: zero SetFileSize should apply");

    const auto inode_after_zero = store.DebugLookupWorkingInodeByPath(L"\\cancelled-copy.bin");
    ok &= Require(
        inode_after_zero.has_value(),
        "ZeroPendingPreallocation: inode should remain visible after zero truncate");
    if (inode_after_zero.has_value())
    {
        ok &= Require(
            inode_after_zero->logical_size == 0,
            "ZeroPendingPreallocation: logical size should be zero");
        ok &= Require(
            inode_after_zero->data_physical_address == 0,
            "ZeroPendingPreallocation: physical address should clear");
    }
    ok &= Require(
        store.PendingAllocationCount() == 0,
        "ZeroPendingPreallocation: pending allocation should be released");
    ok &= Require(
        store.PendingSpacemanAllocationIndexCount() == 0,
        "ZeroPendingPreallocation: pending allocation index should clear");
    ok &= Require(
        store.PendingDeallocationCount() == deallocations_after_preallocate,
        "ZeroPendingPreallocation: never-committed allocation should not stage deallocation");
    ok &= Require(
        store.DebugWorkingFreeExtentTotalBytes() > free_bytes_after_preallocate,
        "ZeroPendingPreallocation: released preallocation should return to working free space");
    ok &= Require(
        store.PendingPayloadByteEstimate() == 0,
        "ZeroPendingPreallocation: pending payload estimate should be zero");
    ok &= Require(
        store.PendingPayloadObjectSummaryCount() == 0,
        "ZeroPendingPreallocation: pending payload object summary should clear");

    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "ZeroPendingPreallocation: zero-size file transaction should commit");
    const auto committed_inode = store.LookupCommittedInodeByPath(L"\\cancelled-copy.bin");
    ok &= Require(
        committed_inode.has_value(),
        "ZeroPendingPreallocation: zero-size file should exist after commit");
    if (committed_inode.has_value())
    {
        ok &= Require(
            committed_inode->logical_size == 0,
            "ZeroPendingPreallocation: committed logical size should be zero");
        ok &= Require(
            committed_inode->data_physical_address == 0,
            "ZeroPendingPreallocation: committed physical address should be zero");
    }

    return ok;
}

bool TestPendingPayloadByteEstimateTracksCachedRenameDeleteConformance(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "pending_payload_cached_summary.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "PendingPayloadCachedSummary: unable to create synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"PendingPayloadCachedSummary",
    };

    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "PendingPayloadCachedSummary: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "PendingPayloadCachedSummary: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "PendingPayloadCachedSummary: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "PendingPayloadCachedSummary: PrepareNativeWritePath should succeed");

    apfsaccess::rw::MetadataStore::MutationRequest create_dir{};
    create_dir.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateDirectory;
    create_dir.path = L"\\source";
    ok &= ExpectMutationStatus(
        store,
        create_dir,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "PendingPayloadCachedSummary: create source directory should apply");

    apfsaccess::rw::MetadataStore::MutationRequest create_file{};
    create_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
    create_file.path = L"\\source\\payload.bin";
    ok &= ExpectMutationStatus(
        store,
        create_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "PendingPayloadCachedSummary: create payload file should apply");

    constexpr std::uint64_t payload_bytes = 32ull * 1024ull;
    apfsaccess::rw::MetadataStore::MutationRequest write_file{};
    write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
    write_file.path = L"\\source\\payload.bin";
    write_file.length = payload_bytes;
    ok &= ExpectMutationStatus(
        store,
        write_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "PendingPayloadCachedSummary: write payload should apply");
    ok &= Require(
        store.PendingPayloadByteEstimate() == payload_bytes,
        "PendingPayloadCachedSummary: write should add payload bytes to cached estimate");
    ok &= Require(
        store.PendingPayloadObjectSummaryCount() == 1,
        "PendingPayloadCachedSummary: write should add one payload object summary");

    apfsaccess::rw::MetadataStore::MutationRequest set_basic{};
    set_basic.operation = apfsaccess::rw::MetadataStore::MutationOperation::SetBasicInfo;
    set_basic.path = L"\\source\\payload.bin";
    set_basic.timestamp_utc = 0x1234;
    ok &= ExpectMutationStatus(
        store,
        set_basic,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "PendingPayloadCachedSummary: SetBasicInfo should apply");
    ok &= Require(
        store.PendingPayloadByteEstimate() == payload_bytes,
        "PendingPayloadCachedSummary: SetBasicInfo should not change cached payload estimate");

    apfsaccess::rw::MetadataStore::MutationRequest rename_dir{};
    rename_dir.operation = apfsaccess::rw::MetadataStore::MutationOperation::Rename;
    rename_dir.path = L"\\source";
    rename_dir.secondary_path = L"\\renamed";
    ok &= ExpectMutationStatus(
        store,
        rename_dir,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "PendingPayloadCachedSummary: directory rename should apply");
    ok &= Require(
        store.PendingPayloadByteEstimate() == payload_bytes,
        "PendingPayloadCachedSummary: directory rename should keep payload estimate on remapped path");
    ok &= Require(
        store.PendingPayloadObjectSummaryCount() == 1,
        "PendingPayloadCachedSummary: directory rename should keep one payload object summary");

    apfsaccess::rw::MetadataStore::MutationRequest rename_file{};
    rename_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Rename;
    rename_file.path = L"\\renamed\\payload.bin";
    rename_file.secondary_path = L"\\renamed\\final.bin";
    ok &= ExpectMutationStatus(
        store,
        rename_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "PendingPayloadCachedSummary: file rename should apply");
    ok &= Require(
        store.PendingPayloadByteEstimate() == payload_bytes,
        "PendingPayloadCachedSummary: file rename should keep payload estimate on final path");
    ok &= Require(
        store.PendingPayloadObjectSummaryCount() == 1,
        "PendingPayloadCachedSummary: file rename should keep one payload object summary");

    apfsaccess::rw::MetadataStore::MutationRequest truncate_zero{};
    truncate_zero.operation = apfsaccess::rw::MetadataStore::MutationOperation::SetFileSize;
    truncate_zero.path = L"\\renamed\\final.bin";
    truncate_zero.length = 0;
    ok &= ExpectMutationStatus(
        store,
        truncate_zero,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "PendingPayloadCachedSummary: truncate final file to zero should apply");
    ok &= Require(
        store.PendingPayloadByteEstimate() == 0,
        "PendingPayloadCachedSummary: zero truncate should remove payload estimate");
    ok &= Require(
        store.PendingPayloadObjectSummaryCount() == 0,
        "PendingPayloadCachedSummary: zero truncate should remove payload object summary");

    write_file.path = L"\\renamed\\final.bin";
    write_file.length = payload_bytes;
    ok &= ExpectMutationStatus(
        store,
        write_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "PendingPayloadCachedSummary: rewrite after truncate should apply");
    ok &= Require(
        store.PendingPayloadByteEstimate() == payload_bytes,
        "PendingPayloadCachedSummary: rewrite should restore payload estimate");
    ok &= Require(
        store.PendingPayloadObjectSummaryCount() == 1,
        "PendingPayloadCachedSummary: rewrite should restore one payload object summary");

    apfsaccess::rw::MetadataStore::MutationRequest delete_file{};
    delete_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Delete;
    delete_file.path = L"\\renamed\\final.bin";
    ok &= ExpectMutationStatus(
        store,
        delete_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "PendingPayloadCachedSummary: delete final file should apply");
    ok &= Require(
        store.PendingPayloadByteEstimate() == 0,
        "PendingPayloadCachedSummary: delete should remove cached payload estimate");
    ok &= Require(
        store.PendingPayloadObjectSummaryCount() == 0,
        "PendingPayloadCachedSummary: delete should remove payload object summary");
    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "PendingPayloadCachedSummary: cached-summary transaction should commit");
    ok &= Require(
        store.PendingPayloadByteEstimate() == 0,
        "PendingPayloadCachedSummary: committed transaction should clear cached payload estimate");

    return ok;
}

bool TestPendingPayloadFileDeleteAvoidsUnrelatedPathScanConformance(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "pending_payload_file_delete_scan.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "PendingPayloadFileDeleteScan: unable to create synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"PendingPayloadFileDeleteScan",
    };

    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "PendingPayloadFileDeleteScan: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "PendingPayloadFileDeleteScan: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "PendingPayloadFileDeleteScan: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "PendingPayloadFileDeleteScan: PrepareNativeWritePath should succeed");

    apfsaccess::rw::MetadataStore::MutationRequest create_file{};
    create_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
    apfsaccess::rw::MetadataStore::MutationRequest write_file{};
    write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
    write_file.length = 4096;
    constexpr int kFileCount = 8;
    for (int index = 0; index < kFileCount; ++index)
    {
        const auto path = L"\\delete-scan-" + std::to_wstring(index) + L".bin";
        create_file.path = path;
        ok &= ExpectMutationStatus(
            store,
            create_file,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "PendingPayloadFileDeleteScan: create dirty file should apply");
        write_file.path = path;
        ok &= ExpectMutationStatus(
            store,
            write_file,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "PendingPayloadFileDeleteScan: write dirty file should apply");
    }

    ok &= Require(
        store.PendingPayloadObjectSummaryCount() == static_cast<std::size_t>(kFileCount),
        "PendingPayloadFileDeleteScan: all dirty files should be tracked before delete");
    const auto delete_scans_before = store.PendingPayloadDeletePathScanCount();

    apfsaccess::rw::MetadataStore::MutationRequest delete_file{};
    delete_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Delete;
    delete_file.path = L"\\delete-scan-3.bin";
    ok &= ExpectMutationStatus(
        store,
        delete_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "PendingPayloadFileDeleteScan: file delete should apply");

    ok &= Require(
        store.PendingPayloadObjectSummaryCount() == static_cast<std::size_t>(kFileCount - 1),
        "PendingPayloadFileDeleteScan: file delete should remove only the deleted object's payload summary");
    ok &= Require(
        store.PendingPayloadByteEstimate() == static_cast<std::uint64_t>(kFileCount - 1) * write_file.length,
        "PendingPayloadFileDeleteScan: file delete should subtract only the deleted file bytes");
    ok &= Require(
        store.PendingPayloadDeletePathScanCount() == delete_scans_before,
        "PendingPayloadFileDeleteScan: file delete should not scan unrelated pending payload paths");

    return ok;
}

bool TestPendingPayloadFileRenameAvoidsUnrelatedPathScanConformance(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "pending_payload_file_rename_scan.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "PendingPayloadFileRenameScan: unable to create synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"PendingPayloadFileRenameScan",
    };

    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "PendingPayloadFileRenameScan: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "PendingPayloadFileRenameScan: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "PendingPayloadFileRenameScan: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "PendingPayloadFileRenameScan: PrepareNativeWritePath should succeed");

    apfsaccess::rw::MetadataStore::MutationRequest create_file{};
    create_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
    apfsaccess::rw::MetadataStore::MutationRequest write_file{};
    write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
    write_file.length = 4096;
    constexpr int kFileCount = 8;
    for (int index = 0; index < kFileCount; ++index)
    {
        const auto path = L"\\rename-scan-" + std::to_wstring(index) + L".bin";
        create_file.path = path;
        ok &= ExpectMutationStatus(
            store,
            create_file,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "PendingPayloadFileRenameScan: create dirty file should apply");
        write_file.path = path;
        ok &= ExpectMutationStatus(
            store,
            write_file,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "PendingPayloadFileRenameScan: write dirty file should apply");
    }

    ok &= Require(
        store.PendingPayloadObjectSummaryCount() == static_cast<std::size_t>(kFileCount),
        "PendingPayloadFileRenameScan: all dirty files should be tracked before rename");
    ok &= Require(
        store.PendingPayloadByteEstimate() == static_cast<std::uint64_t>(kFileCount) * write_file.length,
        "PendingPayloadFileRenameScan: all dirty files should contribute bytes before rename");
    const auto rename_scans_before = store.PendingPayloadRenamePathScanCount();

    apfsaccess::rw::MetadataStore::MutationRequest rename_file{};
    rename_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Rename;
    rename_file.path = L"\\rename-scan-3.bin";
    rename_file.secondary_path = L"\\rename-scan-final.bin";
    ok &= ExpectMutationStatus(
        store,
        rename_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "PendingPayloadFileRenameScan: file rename should apply");

    ok &= Require(
        store.PendingPayloadObjectSummaryCount() == static_cast<std::size_t>(kFileCount),
        "PendingPayloadFileRenameScan: file rename should keep all payload objects tracked");
    ok &= Require(
        store.PendingPayloadByteEstimate() == static_cast<std::uint64_t>(kFileCount) * write_file.length,
        "PendingPayloadFileRenameScan: file rename should preserve pending payload byte estimate");
    ok &= Require(
        store.PendingPayloadRenamePathScanCount() == rename_scans_before,
        "PendingPayloadFileRenameScan: file rename should not scan unrelated pending payload paths");

    return ok;
}

bool TestPendingPayloadDirectoryRenameUsesPrefixIndexConformance(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "pending_payload_directory_rename_prefix.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "PendingPayloadDirectoryRenamePrefix: unable to create synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"PendingPayloadDirectoryRenamePrefix",
    };

    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "PendingPayloadDirectoryRenamePrefix: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "PendingPayloadDirectoryRenamePrefix: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "PendingPayloadDirectoryRenamePrefix: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "PendingPayloadDirectoryRenamePrefix: PrepareNativeWritePath should succeed");

    apfsaccess::rw::MetadataStore::MutationRequest create_dir{};
    create_dir.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateDirectory;
    create_dir.path = L"\\source";
    ok &= ExpectMutationStatus(
        store,
        create_dir,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "PendingPayloadDirectoryRenamePrefix: source directory should apply");
    create_dir.path = L"\\source\\nested";
    ok &= ExpectMutationStatus(
        store,
        create_dir,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "PendingPayloadDirectoryRenamePrefix: nested directory should apply");

    apfsaccess::rw::MetadataStore::MutationRequest create_file{};
    create_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
    apfsaccess::rw::MetadataStore::MutationRequest write_file{};
    write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
    write_file.length = 4096;
    constexpr int kSourceFileCount = 3;
    constexpr int kUnrelatedFileCount = 5;
    for (int index = 0; index < kSourceFileCount; ++index)
    {
        const auto path = L"\\source\\nested\\dirty-" + std::to_wstring(index) + L".bin";
        create_file.path = path;
        ok &= ExpectMutationStatus(
            store,
            create_file,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "PendingPayloadDirectoryRenamePrefix: create source dirty file should apply");
        write_file.path = path;
        ok &= ExpectMutationStatus(
            store,
            write_file,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "PendingPayloadDirectoryRenamePrefix: write source dirty file should apply");
    }
    for (int index = 0; index < kUnrelatedFileCount; ++index)
    {
        const auto path = L"\\unrelated-" + std::to_wstring(index) + L".bin";
        create_file.path = path;
        ok &= ExpectMutationStatus(
            store,
            create_file,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "PendingPayloadDirectoryRenamePrefix: create unrelated dirty file should apply");
        write_file.path = path;
        ok &= ExpectMutationStatus(
            store,
            write_file,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "PendingPayloadDirectoryRenamePrefix: write unrelated dirty file should apply");
    }

    ok &= Require(
        store.PendingPayloadObjectSummaryCount() == static_cast<std::size_t>(kSourceFileCount + kUnrelatedFileCount),
        "PendingPayloadDirectoryRenamePrefix: all dirty files should be tracked before directory rename");
    const auto rename_scans_before = store.PendingPayloadRenamePathScanCount();
    const auto summary_scans_before = store.PendingPayloadSummaryPathScanCount();
    const auto before_json = store.PerformanceJson();
    const auto before_path_order_builds = ExtractNestedUnsignedValue(
        before_json,
        "pendingPayloadPathOrder",
        "builds");
    const auto before_path_order_ordered_paths = ExtractNestedUnsignedValue(
        before_json,
        "pendingPayloadPathOrder",
        "orderedPaths");
    ok &= Require(
        before_path_order_builds.has_value() &&
            before_path_order_ordered_paths.has_value(),
        "PendingPayloadDirectoryRenamePrefix: path order counters should exist before rename");
    if (before_path_order_ordered_paths.has_value())
    {
        ok &= Require(
            before_path_order_ordered_paths.value() == 0,
            "PendingPayloadDirectoryRenamePrefix: dirty writes should not build prefix path order before subtree rename");
    }

    apfsaccess::rw::MetadataStore::MutationRequest rename_dir{};
    rename_dir.operation = apfsaccess::rw::MetadataStore::MutationOperation::Rename;
    rename_dir.path = L"\\source";
    rename_dir.secondary_path = L"\\renamed";
    ok &= ExpectMutationStatus(
        store,
        rename_dir,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "PendingPayloadDirectoryRenamePrefix: directory rename should apply");

    ok &= Require(
        store.PendingPayloadObjectSummaryCount() == static_cast<std::size_t>(kSourceFileCount + kUnrelatedFileCount),
        "PendingPayloadDirectoryRenamePrefix: directory rename should keep all dirty payload objects tracked");
    ok &= Require(
        store.PendingPayloadByteEstimate() ==
            static_cast<std::uint64_t>(kSourceFileCount + kUnrelatedFileCount) * write_file.length,
        "PendingPayloadDirectoryRenamePrefix: directory rename should preserve pending payload bytes");
    ok &= Require(
        store.PendingPayloadRenamePathScanCount() == rename_scans_before + kSourceFileCount,
        "PendingPayloadDirectoryRenamePrefix: directory rename should scan only matching subtree payload paths");
    ok &= Require(
        store.PendingPayloadSummaryPathScanCount() == summary_scans_before,
        "PendingPayloadDirectoryRenamePrefix: directory rename should not rebuild the whole payload summary");
    const auto after_json = store.PerformanceJson();
    const auto after_path_order_builds = ExtractNestedUnsignedValue(
        after_json,
        "pendingPayloadPathOrder",
        "builds");
    if (before_path_order_builds.has_value() && after_path_order_builds.has_value())
    {
        ok &= Require(
            after_path_order_builds.value() == before_path_order_builds.value() + 1,
            "PendingPayloadDirectoryRenamePrefix: subtree rename should lazily build the prefix path order once");
    }

    return ok;
}

bool TestPendingPayloadNestedFileDeleteUsesExactIndexConformance(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "pending_payload_nested_file_delete_exact.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "PendingPayloadNestedFileDeleteExact: unable to create synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"PendingPayloadNestedFileDeleteExact",
    };

    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "PendingPayloadNestedFileDeleteExact: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "PendingPayloadNestedFileDeleteExact: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "PendingPayloadNestedFileDeleteExact: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "PendingPayloadNestedFileDeleteExact: PrepareNativeWritePath should succeed");

    apfsaccess::rw::MetadataStore::MutationRequest create_dir{};
    create_dir.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateDirectory;
    create_dir.path = L"\\delete-prefix";
    ok &= ExpectMutationStatus(
        store,
        create_dir,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "PendingPayloadNestedFileDeleteExact: directory should apply");

    apfsaccess::rw::MetadataStore::MutationRequest create_file{};
    create_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
    apfsaccess::rw::MetadataStore::MutationRequest write_file{};
    write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
    write_file.length = 4096;
    constexpr int kFileCount = 6;
    for (int index = 0; index < kFileCount; ++index)
    {
        const auto path = index == 2
            ? std::wstring(L"\\delete-prefix\\target.bin")
            : L"\\unrelated-delete-" + std::to_wstring(index) + L".bin";
        create_file.path = path;
        ok &= ExpectMutationStatus(
            store,
            create_file,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "PendingPayloadNestedFileDeleteExact: create dirty file should apply");
        write_file.path = path;
        ok &= ExpectMutationStatus(
            store,
            write_file,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "PendingPayloadNestedFileDeleteExact: write dirty file should apply");
    }

    ok &= Require(
        store.PendingPayloadObjectSummaryCount() == static_cast<std::size_t>(kFileCount),
        "PendingPayloadNestedFileDeleteExact: all dirty files should be tracked before delete");
    const auto delete_scans_before = store.PendingPayloadDeletePathScanCount();
    const auto summary_scans_before = store.PendingPayloadSummaryPathScanCount();

    apfsaccess::rw::MetadataStore::MutationRequest delete_file{};
    delete_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Delete;
    delete_file.path = L"\\delete-prefix\\target.bin";
    ok &= ExpectMutationStatus(
        store,
        delete_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "PendingPayloadNestedFileDeleteExact: delete nested dirty file should apply");

    ok &= Require(
        store.PendingPayloadObjectSummaryCount() == static_cast<std::size_t>(kFileCount - 1),
        "PendingPayloadNestedFileDeleteExact: delete should remove only matching dirty payload object");
    ok &= Require(
        store.PendingPayloadByteEstimate() == static_cast<std::uint64_t>(kFileCount - 1) * write_file.length,
        "PendingPayloadNestedFileDeleteExact: delete should preserve unrelated dirty payload bytes");
    ok &= Require(
        store.PendingPayloadDeletePathScanCount() == delete_scans_before,
        "PendingPayloadNestedFileDeleteExact: known-object nested file delete should stay on exact fast path");
    ok &= Require(
        store.PendingPayloadSummaryPathScanCount() == summary_scans_before,
        "PendingPayloadNestedFileDeleteExact: delete should not rebuild the whole payload summary");

    return ok;
}

bool TestPendingPayloadSummaryDropsDirtyReplaceTargetConformance(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "pending_payload_replace_target.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "PendingPayloadReplaceTarget: unable to create synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"PendingPayloadReplaceTarget",
    };

    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "PendingPayloadReplaceTarget: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "PendingPayloadReplaceTarget: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "PendingPayloadReplaceTarget: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "PendingPayloadReplaceTarget: PrepareNativeWritePath should succeed");

    std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
    ConfigurePayloadProvider(store, staged_payloads);

    apfsaccess::rw::MetadataStore::MutationRequest create_source{};
    create_source.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
    create_source.path = L"\\source.bin";
    ok &= ExpectMutationStatus(
        store,
        create_source,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "PendingPayloadReplaceTarget: create committed source should apply");

    constexpr std::uint64_t source_bytes = 4096;
    apfsaccess::rw::MetadataStore::MutationRequest write_source{};
    write_source.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
    write_source.path = L"\\source.bin";
    write_source.length = source_bytes;
    ok &= ExpectMutationStatus(
        store,
        write_source,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "PendingPayloadReplaceTarget: write committed source should apply");
    staged_payloads[L"\\source.bin"] = BuildPatternPayload(source_bytes, 0x3A);

    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "PendingPayloadReplaceTarget: source commit should succeed");

    apfsaccess::rw::MetadataStore::MutationRequest create_target{};
    create_target.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
    create_target.path = L"\\target.bin";
    ok &= ExpectMutationStatus(
        store,
        create_target,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "PendingPayloadReplaceTarget: create dirty target should apply");

    constexpr std::uint64_t target_bytes = 8192;
    apfsaccess::rw::MetadataStore::MutationRequest write_target{};
    write_target.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
    write_target.path = L"\\target.bin";
    write_target.length = target_bytes;
    ok &= ExpectMutationStatus(
        store,
        write_target,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "PendingPayloadReplaceTarget: write dirty target should apply");
    ok &= Require(
        store.PendingPayloadObjectSummaryCount() == 1,
        "PendingPayloadReplaceTarget: dirty target should be tracked before replacement");
    ok &= Require(
        store.PendingPayloadByteEstimate() == target_bytes,
        "PendingPayloadReplaceTarget: dirty target should contribute pending payload bytes");
    const auto rename_scans_before = store.PendingPayloadRenamePathScanCount();

    apfsaccess::rw::MetadataStore::MutationRequest rename_replace{};
    rename_replace.operation = apfsaccess::rw::MetadataStore::MutationOperation::Rename;
    rename_replace.path = L"\\source.bin";
    rename_replace.secondary_path = L"\\target.bin";
    rename_replace.replace_if_exists = true;
    ok &= ExpectMutationStatus(
        store,
        rename_replace,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "PendingPayloadReplaceTarget: clean source should replace dirty target");
    ok &= Require(
        store.PendingPayloadObjectSummaryCount() == 0,
        "PendingPayloadReplaceTarget: dirty replaced target should clear payload object summary");
    ok &= Require(
        store.PendingPayloadByteEstimate() == 0,
        "PendingPayloadReplaceTarget: clean replacement should not request payload bytes");
    ok &= Require(
        store.PendingPayloadRenamePathScanCount() == rename_scans_before,
        "PendingPayloadReplaceTarget: file replace should not scan unrelated pending payload paths");
    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "PendingPayloadReplaceTarget: replacement commit should not require target payload provider");

    return ok;
}

bool TestPendingPayloadSummaryDropsDirtyCreateReplaceTargetConformance(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "pending_payload_create_replace_target.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "PendingPayloadCreateReplaceTarget: unable to create synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"PendingPayloadCreateReplaceTarget",
    };

    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "PendingPayloadCreateReplaceTarget: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "PendingPayloadCreateReplaceTarget: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "PendingPayloadCreateReplaceTarget: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "PendingPayloadCreateReplaceTarget: PrepareNativeWritePath should succeed");

    constexpr std::uint64_t target_bytes = 8192;
    constexpr std::uint64_t unrelated_bytes = 4096;
    constexpr int unrelated_file_count = 4;
    for (int index = 0; index < unrelated_file_count; ++index)
    {
        const auto path = L"\\unrelated-" + std::to_wstring(index) + L".bin";
        apfsaccess::rw::MetadataStore::MutationRequest create_unrelated{};
        create_unrelated.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
        create_unrelated.path = path;
        ok &= ExpectMutationStatus(
            store,
            create_unrelated,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "PendingPayloadCreateReplaceTarget: create unrelated dirty file should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_unrelated{};
        write_unrelated.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_unrelated.path = path;
        write_unrelated.length = unrelated_bytes;
        ok &= ExpectMutationStatus(
            store,
            write_unrelated,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "PendingPayloadCreateReplaceTarget: write unrelated dirty file should apply");
    }

    apfsaccess::rw::MetadataStore::MutationRequest create_target{};
    create_target.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
    create_target.path = L"\\target.bin";
    ok &= ExpectMutationStatus(
        store,
        create_target,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "PendingPayloadCreateReplaceTarget: create dirty target should apply");

    apfsaccess::rw::MetadataStore::MutationRequest write_target{};
    write_target.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
    write_target.path = L"\\target.bin";
    write_target.length = target_bytes;
    ok &= ExpectMutationStatus(
        store,
        write_target,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "PendingPayloadCreateReplaceTarget: write dirty target should apply");
    ok &= Require(
        store.PendingPayloadObjectSummaryCount() == static_cast<std::size_t>(unrelated_file_count + 1),
        "PendingPayloadCreateReplaceTarget: dirty target and unrelated files should be tracked before create-replace");
    ok &= Require(
        store.PendingPayloadByteEstimate() ==
            (target_bytes + (unrelated_bytes * static_cast<std::uint64_t>(unrelated_file_count))),
        "PendingPayloadCreateReplaceTarget: dirty target and unrelated files should contribute pending payload bytes");
    const auto summary_scans_before = store.PendingPayloadSummaryPathScanCount();

    apfsaccess::rw::MetadataStore::MutationRequest replace_target{};
    replace_target.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
    replace_target.path = L"\\target.bin";
    replace_target.replace_if_exists = true;
    ok &= ExpectMutationStatus(
        store,
        replace_target,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "PendingPayloadCreateReplaceTarget: create-replace should apply");
    ok &= Require(
        store.PendingPayloadObjectSummaryCount() == static_cast<std::size_t>(unrelated_file_count),
        "PendingPayloadCreateReplaceTarget: create-replace should clear only the replaced dirty payload object summary");
    ok &= Require(
        store.PendingPayloadByteEstimate() == (unrelated_bytes * static_cast<std::uint64_t>(unrelated_file_count)),
        "PendingPayloadCreateReplaceTarget: create-replace should keep unrelated cached payload bytes");
    ok &= Require(
        store.PendingPayloadSummaryPathScanCount() == summary_scans_before,
        "PendingPayloadCreateReplaceTarget: create-replace should not rescan unrelated pending payload paths");

    return ok;
}

bool TestPendingPayloadSummaryKeepsDirtyReplaceSourceConformance(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "pending_payload_replace_source.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "PendingPayloadReplaceSource: unable to create synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"PendingPayloadReplaceSource",
    };

    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "PendingPayloadReplaceSource: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "PendingPayloadReplaceSource: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "PendingPayloadReplaceSource: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "PendingPayloadReplaceSource: PrepareNativeWritePath should succeed");

    std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
    ConfigurePayloadProvider(store, staged_payloads);

    apfsaccess::rw::MetadataStore::MutationRequest create_source{};
    create_source.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
    create_source.path = L"\\source.bin";
    ok &= ExpectMutationStatus(
        store,
        create_source,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "PendingPayloadReplaceSource: create dirty source should apply");

    constexpr std::uint64_t source_bytes = 4096;
    apfsaccess::rw::MetadataStore::MutationRequest write_source{};
    write_source.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
    write_source.path = L"\\source.bin";
    write_source.length = source_bytes;
    ok &= ExpectMutationStatus(
        store,
        write_source,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "PendingPayloadReplaceSource: write dirty source should apply");

    apfsaccess::rw::MetadataStore::MutationRequest create_target{};
    create_target.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
    create_target.path = L"\\target.bin";
    ok &= ExpectMutationStatus(
        store,
        create_target,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "PendingPayloadReplaceSource: create dirty target should apply");

    constexpr std::uint64_t target_bytes = 8192;
    apfsaccess::rw::MetadataStore::MutationRequest write_target{};
    write_target.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
    write_target.path = L"\\target.bin";
    write_target.length = target_bytes;
    ok &= ExpectMutationStatus(
        store,
        write_target,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "PendingPayloadReplaceSource: write dirty target should apply");
    ok &= Require(
        store.PendingPayloadObjectSummaryCount() == 2,
        "PendingPayloadReplaceSource: dirty source and target should both be tracked before replacement");
    ok &= Require(
        store.PendingPayloadByteEstimate() == (source_bytes + target_bytes),
        "PendingPayloadReplaceSource: both dirty files should contribute pending payload bytes");
    const auto rename_scans_before = store.PendingPayloadRenamePathScanCount();

    apfsaccess::rw::MetadataStore::MutationRequest rename_replace{};
    rename_replace.operation = apfsaccess::rw::MetadataStore::MutationOperation::Rename;
    rename_replace.path = L"\\source.bin";
    rename_replace.secondary_path = L"\\target.bin";
    rename_replace.replace_if_exists = true;
    ok &= ExpectMutationStatus(
        store,
        rename_replace,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "PendingPayloadReplaceSource: dirty source should replace dirty target");
    ok &= Require(
        store.PendingPayloadObjectSummaryCount() == 1,
        "PendingPayloadReplaceSource: replacement should keep only dirty source payload object");
    ok &= Require(
        store.PendingPayloadByteEstimate() == source_bytes,
        "PendingPayloadReplaceSource: replacement should estimate only dirty source payload bytes");
    ok &= Require(
        store.PendingPayloadRenamePathScanCount() == rename_scans_before,
        "PendingPayloadReplaceSource: file replace should not scan unrelated pending payload paths");

    const auto source_payload = BuildPatternPayload(source_bytes, 0x4C);
    staged_payloads[L"\\target.bin"] = source_payload;
    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "PendingPayloadReplaceSource: replacement commit should use remapped source payload");

    std::vector<std::byte> committed_payload;
    ok &= Require(
        store.ReadCommittedFileRange(L"\\target.bin", 0, source_payload.size(), committed_payload),
        "PendingPayloadReplaceSource: committed replacement payload should be readable");
    ok &= Require(
        committed_payload == source_payload,
        "PendingPayloadReplaceSource: committed replacement payload should match dirty source bytes");

    return ok;
}

bool TestPendingPayloadSummaryKeepsCaseOnlyReplaceRenameConformance(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "pending_payload_case_only_replace.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "PendingPayloadCaseOnlyReplace: unable to create synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"PendingPayloadCaseOnlyReplace",
    };

    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "PendingPayloadCaseOnlyReplace: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "PendingPayloadCaseOnlyReplace: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "PendingPayloadCaseOnlyReplace: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "PendingPayloadCaseOnlyReplace: PrepareNativeWritePath should succeed");

    std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
    ConfigurePayloadProvider(store, staged_payloads);

    apfsaccess::rw::MetadataStore::MutationRequest create_file{};
    create_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
    create_file.path = L"\\Case.bin";
    ok &= ExpectMutationStatus(
        store,
        create_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "PendingPayloadCaseOnlyReplace: create file should apply");

    constexpr std::uint64_t payload_bytes = 4096;
    apfsaccess::rw::MetadataStore::MutationRequest write_file{};
    write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
    write_file.path = L"\\Case.bin";
    write_file.length = payload_bytes;
    ok &= ExpectMutationStatus(
        store,
        write_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "PendingPayloadCaseOnlyReplace: write file should apply");
    ok &= Require(
        store.PendingPayloadObjectSummaryCount() == 1,
        "PendingPayloadCaseOnlyReplace: mixed-case write should add one payload object summary");
    ok &= Require(
        store.PendingPayloadByteEstimate() == payload_bytes,
        "PendingPayloadCaseOnlyReplace: mixed-case write should add pending payload bytes");

    apfsaccess::rw::MetadataStore::MutationRequest grow_case_variant{};
    grow_case_variant.operation = apfsaccess::rw::MetadataStore::MutationOperation::SetFileSize;
    grow_case_variant.path = L"\\CASE.BIN";
    grow_case_variant.length = payload_bytes * 2;
    ok &= ExpectMutationStatus(
        store,
        grow_case_variant,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "PendingPayloadCaseOnlyReplace: mixed-case SetFileSize should apply");
    ok &= Require(
        store.PendingPayloadObjectSummaryCount() == 1,
        "PendingPayloadCaseOnlyReplace: mixed-case SetFileSize should keep one payload object summary");
    ok &= Require(
        store.PendingPayloadByteEstimate() == payload_bytes * 2,
        "PendingPayloadCaseOnlyReplace: mixed-case SetFileSize should update pending payload bytes");

    write_file.path = L"\\CASE.BIN";
    write_file.length = payload_bytes * 2;
    ok &= ExpectMutationStatus(
        store,
        write_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "PendingPayloadCaseOnlyReplace: mixed-case grown write should apply");
    ok &= Require(
        store.PendingPayloadObjectSummaryCount() == 1,
        "PendingPayloadCaseOnlyReplace: mixed-case grown write should keep one payload object summary");
    ok &= Require(
        store.PendingPayloadByteEstimate() == payload_bytes * 2,
        "PendingPayloadCaseOnlyReplace: mixed-case grown write should keep pending payload bytes");
    const auto rename_scans_before = store.PendingPayloadRenamePathScanCount();

    apfsaccess::rw::MetadataStore::MutationRequest rename_case{};
    rename_case.operation = apfsaccess::rw::MetadataStore::MutationOperation::Rename;
    rename_case.path = L"\\Case.bin";
    rename_case.secondary_path = L"\\case.bin";
    rename_case.replace_if_exists = true;
    ok &= ExpectMutationStatus(
        store,
        rename_case,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "PendingPayloadCaseOnlyReplace: case-only replace rename should apply");
    ok &= Require(
        store.PendingPayloadObjectSummaryCount() == 1,
        "PendingPayloadCaseOnlyReplace: case-only replace rename should keep dirty payload object");
    ok &= Require(
        store.PendingPayloadByteEstimate() == payload_bytes * 2,
        "PendingPayloadCaseOnlyReplace: case-only replace rename should keep pending payload bytes");
    ok &= Require(
        store.PendingPayloadRenamePathScanCount() == rename_scans_before,
        "PendingPayloadCaseOnlyReplace: case-only file replace should not scan pending payload paths");

    const auto payload = BuildPatternPayload(payload_bytes * 2, 0x71);
    staged_payloads[L"\\case.bin"] = payload;
    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "PendingPayloadCaseOnlyReplace: case-only replacement commit should use remapped payload");

    std::vector<std::byte> committed_payload;
    ok &= Require(
        store.ReadCommittedFileRange(L"\\case.bin", 0, payload.size(), committed_payload),
        "PendingPayloadCaseOnlyReplace: committed payload should be readable after case-only rename");
    ok &= Require(
        committed_payload == payload,
        "PendingPayloadCaseOnlyReplace: committed payload should match dirty source bytes");

    return ok;
}

bool TestLargeSetFileSizeUsesFragmentedFreeExtentsConformance(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "large_fragmented_preallocation.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "LargeFragmentedPreallocation: unable to create synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"LargeFragmentedPreallocation",
    };
    context.allow_raw_physical_write = true;

    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "LargeFragmentedPreallocation: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "LargeFragmentedPreallocation: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "LargeFragmentedPreallocation: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "LargeFragmentedPreallocation: PrepareNativeWritePath should succeed");

    apfsaccess::rw::MetadataStore::MutationRequest create_earlier_file{};
    create_earlier_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
    create_earlier_file.path = L"\\earlier-pending.bin";
    ok &= ExpectMutationStatus(
        store,
        create_earlier_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "LargeFragmentedPreallocation: earlier pending file create should apply");

    apfsaccess::rw::MetadataStore::MutationRequest size_earlier_file{};
    size_earlier_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::SetFileSize;
    size_earlier_file.path = L"\\earlier-pending.bin";
    size_earlier_file.length = kBlockSize;
    ok &= ExpectMutationStatus(
        store,
        size_earlier_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "LargeFragmentedPreallocation: earlier pending file should allocate from the normal append area");
    const auto earlier_inode = store.DebugLookupWorkingInodeByPath(L"\\earlier-pending.bin");
    ok &= Require(
        earlier_inode.has_value() && earlier_inode->data_physical_address != 0,
        "LargeFragmentedPreallocation: earlier pending file should have physical storage");

    constexpr std::uint64_t first_lower_extent = 160ull * kBlockSize;
    constexpr std::uint64_t second_lower_extent = 164ull * kBlockSize;
    ok &= Require(
        store.FreeExtent(first_lower_extent, 2ull * kBlockSize),
        "LargeFragmentedPreallocation: first lower free extent should stage after earlier high allocation");
    ok &= Require(
        store.FreeExtent(second_lower_extent, 2ull * kBlockSize),
        "LargeFragmentedPreallocation: second lower free extent should stage after earlier high allocation");

    apfsaccess::rw::MetadataStore::MutationRequest create_file{};
    create_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
    create_file.path = L"\\large-fragmented.bin";
    ok &= ExpectMutationStatus(
        store,
        create_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "LargeFragmentedPreallocation: create file should apply");

    apfsaccess::rw::MetadataStore::MutationRequest set_size{};
    set_size.operation = apfsaccess::rw::MetadataStore::MutationOperation::SetFileSize;
    set_size.path = L"\\large-fragmented.bin";
    set_size.length = 4ull * kBlockSize;
    ok &= ExpectMutationStatus(
        store,
        set_size,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "LargeFragmentedPreallocation: SetFileSize should use fragmented free extents when no single extent is large enough");
    ok &= Require(
        store.PendingAllocationCount() >= 3,
        "LargeFragmentedPreallocation: setup should have earlier high allocation plus lower fragmented allocations");
    ok &= Require(
        store.PendingSpacemanAllocationIndexCount() == store.PendingAllocationCount(),
        "LargeFragmentedPreallocation: pending allocation index should mirror staged extents");
    const auto fragmented_inode = store.DebugLookupWorkingInodeByPath(L"\\large-fragmented.bin");
    ok &= Require(
        earlier_inode.has_value() &&
            fragmented_inode.has_value() &&
            fragmented_inode->data_physical_address < earlier_inode->data_physical_address,
        "LargeFragmentedPreallocation: pending allocation vector should be out of physical order");

    const auto before_json = store.PerformanceJson();
    const auto before_pending_index_reuse = ExtractNestedUnsignedValue(
        before_json,
        "pendingAllocationValidation",
        "pendingIndexReuse");
    const auto before_pending_sort_fallbacks = ExtractNestedUnsignedValue(
        before_json,
        "pendingAllocationValidation",
        "pendingSortFallbacks");
    ok &= Require(
        before_pending_index_reuse.has_value() && before_pending_sort_fallbacks.has_value(),
        "LargeFragmentedPreallocation: pending allocation validation counters should exist before commit");

    std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
    ConfigurePayloadProvider(store, staged_payloads);
    staged_payloads[L"\\earlier-pending.bin"] = BuildPatternPayload(
        static_cast<std::size_t>(size_earlier_file.length),
        0x9C);
    staged_payloads[L"\\large-fragmented.bin"] = BuildPatternPayload(static_cast<std::size_t>(set_size.length), 0xA4);
    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "LargeFragmentedPreallocation: fragmented file commit should succeed");
    ok &= Require(
        store.PendingSpacemanAllocationIndexCount() == 0,
        "LargeFragmentedPreallocation: pending allocation index should clear after commit");

    auto fragmented_overwrite_payload = staged_payloads[L"\\large-fragmented.bin"];
    const auto fragmented_overwrite_bytes = BuildPatternPayload(
        static_cast<std::size_t>(kBlockSize),
        0xBC);
    std::copy(
        fragmented_overwrite_bytes.begin(),
        fragmented_overwrite_bytes.end(),
        fragmented_overwrite_payload.begin() + static_cast<std::ptrdiff_t>(kBlockSize));
    staged_payloads[L"\\large-fragmented.bin"] = fragmented_overwrite_payload;

    apfsaccess::rw::MetadataStore::MutationRequest fragmented_overwrite{};
    fragmented_overwrite.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
    fragmented_overwrite.path = L"\\large-fragmented.bin";
    fragmented_overwrite.offset = kBlockSize;
    fragmented_overwrite.length = kBlockSize;
    ok &= ExpectMutationStatus(
        store,
        fragmented_overwrite,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "LargeFragmentedPreallocation: interior overwrite should apply after fragmented commit");
    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "LargeFragmentedPreallocation: interior overwrite should accept pending replacement allocation");
    std::vector<std::byte> fragmented_overwrite_result;
    ok &= Require(
        store.ReadCommittedFileRange(
            L"\\large-fragmented.bin",
            0,
            fragmented_overwrite_payload.size(),
            fragmented_overwrite_result),
        "LargeFragmentedPreallocation: fragmented overwrite should remain readable");
    ok &= Require(
        fragmented_overwrite_result == fragmented_overwrite_payload,
        "LargeFragmentedPreallocation: fragmented overwrite should preserve untouched bytes");

    const auto after_json = store.PerformanceJson();
    const auto after_pending_index_reuse = ExtractNestedUnsignedValue(
        after_json,
        "pendingAllocationValidation",
        "pendingIndexReuse");
    const auto after_pending_sort_fallbacks = ExtractNestedUnsignedValue(
        after_json,
        "pendingAllocationValidation",
        "pendingSortFallbacks");
    ok &= Require(
        after_pending_index_reuse.has_value() && after_pending_sort_fallbacks.has_value(),
        "LargeFragmentedPreallocation: pending allocation validation counters should exist after commit");
    if (before_pending_index_reuse.has_value() && after_pending_index_reuse.has_value())
    {
        ok &= Require(
            after_pending_index_reuse.value() == before_pending_index_reuse.value() + 1,
            "LargeFragmentedPreallocation: out-of-order pending allocations should reuse the allocation index");
    }
    if (before_pending_sort_fallbacks.has_value() && after_pending_sort_fallbacks.has_value())
    {
        ok &= Require(
            after_pending_sort_fallbacks.value() == before_pending_sort_fallbacks.value(),
            "LargeFragmentedPreallocation: out-of-order pending allocations should avoid copy-sort fallback");
    }

    apfsaccess::rw::MetadataStore remounted(context);
    ok &= Require(remounted.LoadContainerSuperblocks(), "LargeFragmentedPreallocation: remount LoadContainerSuperblocks should succeed");
    ok &= Require(remounted.LoadObjectMap(), "LargeFragmentedPreallocation: remount LoadObjectMap should succeed");
    ok &= Require(remounted.LoadSpacemanState(), "LargeFragmentedPreallocation: remount LoadSpacemanState should succeed");
    ok &= Require(
        remounted.PrepareNativeWritePath(),
        "LargeFragmentedPreallocation: remount should restore fragmented read extents before integrity validation");
    auto remounted_inode = remounted.LookupCommittedInodeByPath(L"\\large-fragmented.bin");
    ok &= Require(
        remounted_inode.has_value(),
        "LargeFragmentedPreallocation: remount should expose committed inode");
    if (remounted_inode.has_value())
    {
        ok &= Require(
            remounted.DebugMergeNativeProjectionReadExtents(
                remounted_inode->object_id,
                {
                    { 0, remounted_inode->data_physical_address, remounted_inode->logical_size },
                }),
            "LargeFragmentedPreallocation: full read projection should be accepted without replacing btree extents");
        ok &= Require(
            remounted.VerifyIntegrity(),
            "LargeFragmentedPreallocation: conflicting full read projection should not poison canonical btree validation");

        std::vector<std::byte> remounted_payload;
        ok &= Require(
            remounted.ReadCommittedFileRange(
                L"\\large-fragmented.bin",
                0,
                staged_payloads[L"\\large-fragmented.bin"].size(),
                remounted_payload),
            "LargeFragmentedPreallocation: remounted fragmented file should remain readable after projection refresh");
        ok &= Require(
            remounted_payload == staged_payloads[L"\\large-fragmented.bin"],
            "LargeFragmentedPreallocation: projection refresh should not collapse fragmented reads");
    }

    return ok;
}

bool TestFragmentedCommittedFileAllowsLaterUnrelatedMutationConformance(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "fragmented_later_mutation.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "FragmentedLaterMutation: unable to create synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"FragmentedLaterMutation",
    };

    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "FragmentedLaterMutation: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "FragmentedLaterMutation: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "FragmentedLaterMutation: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "FragmentedLaterMutation: PrepareNativeWritePath should succeed");

    constexpr std::uint64_t first_extent = 300ull * kBlockSize;
    constexpr std::uint64_t second_extent = 304ull * kBlockSize;
    ok &= Require(store.FreeExtent(first_extent, 2ull * kBlockSize), "FragmentedLaterMutation: first free extent should stage");
    ok &= Require(store.FreeExtent(second_extent, 2ull * kBlockSize), "FragmentedLaterMutation: second free extent should stage");

    std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
    ConfigurePayloadProvider(store, staged_payloads);

    apfsaccess::rw::MetadataStore::MutationRequest create_large{};
    create_large.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
    create_large.path = L"\\large-fragmented.bin";
    ok &= ExpectMutationStatus(
        store,
        create_large,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "FragmentedLaterMutation: large create should apply");

    apfsaccess::rw::MetadataStore::MutationRequest grow_large{};
    grow_large.operation = apfsaccess::rw::MetadataStore::MutationOperation::SetFileSize;
    grow_large.path = L"\\large-fragmented.bin";
    grow_large.length = 4ull * kBlockSize;
    ok &= ExpectMutationStatus(
        store,
        grow_large,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "FragmentedLaterMutation: large fragmented SetFileSize should apply");
    staged_payloads[L"\\large-fragmented.bin"] = BuildPatternPayload(static_cast<std::size_t>(grow_large.length), 0xA4);
    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "FragmentedLaterMutation: large fragmented commit should succeed");

    apfsaccess::rw::MetadataStore::MutationRequest create_small{};
    create_small.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
    create_small.path = L"\\small-after-large.bin";
    ok &= ExpectMutationStatus(
        store,
        create_small,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "FragmentedLaterMutation: later small create should apply");

    apfsaccess::rw::MetadataStore::MutationRequest write_small{};
    write_small.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
    write_small.path = L"\\small-after-large.bin";
    write_small.length = kBlockSize;
    ok &= ExpectMutationStatus(
        store,
        write_small,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "FragmentedLaterMutation: later small write should apply");
    staged_payloads[L"\\small-after-large.bin"] = BuildPatternPayload(static_cast<std::size_t>(write_small.length), 0x5D);

    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "FragmentedLaterMutation: later unrelated commit should not fail committed fragmented allocation validation");

    std::vector<std::byte> large_payload;
    ok &= Require(
        store.ReadCommittedFileRange(
            L"\\large-fragmented.bin",
            0,
            staged_payloads[L"\\large-fragmented.bin"].size(),
            large_payload),
        "FragmentedLaterMutation: large fragmented file should stay readable");
    ok &= Require(
        large_payload == staged_payloads[L"\\large-fragmented.bin"],
        "FragmentedLaterMutation: large fragmented payload should survive later mutation");
    ok &= Require(
        store.LookupCommittedInodeByPath(L"\\small-after-large.bin").has_value(),
        "FragmentedLaterMutation: later small file should persist");

    return ok;
}

bool TestPendingCloseDelayClassificationConformance(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "pending_close_delay.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "PendingCloseDelay: unable to create synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"PendingCloseDelay",
    };

    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "PendingCloseDelay: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "PendingCloseDelay: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "PendingCloseDelay: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "PendingCloseDelay: PrepareNativeWritePath should succeed");
    std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
    ConfigurePayloadProvider(store, staged_payloads);

    apfsaccess::rw::MetadataStore::MutationRequest create_file{};
    create_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
    create_file.path = L"\\new-file.bin";
    ok &= ExpectMutationStatus(
        store,
        create_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "PendingCloseDelay: create file should apply");
    ok &= Require(
        !store.PendingMutationsCanDelayClose(),
        "PendingCloseDelay: create without payload should not delay close");

    apfsaccess::rw::MetadataStore::MutationRequest set_size{};
    set_size.operation = apfsaccess::rw::MetadataStore::MutationOperation::SetFileSize;
    set_size.path = L"\\new-file.bin";
    set_size.length = 8192;
    ok &= ExpectMutationStatus(
        store,
        set_size,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "PendingCloseDelay: new file size should apply");
    ok &= Require(
        !store.PendingMutationsCanDelayClose(),
        "PendingCloseDelay: new file size without payload should not delay close");

    apfsaccess::rw::MetadataStore::MutationRequest write_file{};
    write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
    write_file.path = L"\\new-file.bin";
    write_file.offset = 0;
    write_file.length = 8192;
    ok &= ExpectMutationStatus(
        store,
        write_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "PendingCloseDelay: new file write should apply");
    staged_payloads[L"\\new-file.bin"] = BuildPatternPayload(8192, 0x71);
    ok &= Require(
        store.PendingMutationsCanDelayClose(),
        "PendingCloseDelay: create-size-write batch should delay close");
    ok &= Require(
        store.PendingMutationsCanContinueDeferredClose(),
        "PendingCloseDelay: create-size-write batch should continue an existing deferred close batch");
    ok &= Require(
        store.PendingCloseDelaySummaryRebuildCount() == 0,
        "PendingCloseDelay: continue check should use the incremental summary for create-size-write");

    apfsaccess::rw::MetadataStore::MutationRequest duplicate_write{};
    duplicate_write.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
    duplicate_write.path = L"\\new-file.bin";
    duplicate_write.offset = 4096;
    duplicate_write.length = 4096;
    ok &= ExpectMutationStatus(
        store,
        duplicate_write,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "PendingCloseDelay: coalesced second file write should apply");
    ok &= Require(
        store.PendingMutationsCanDelayClose(),
        "PendingCloseDelay: coalesced second file write should remain delayable");
    ok &= Require(
        store.PendingMutationsCanContinueDeferredClose(),
        "PendingCloseDelay: coalesced second file write should continue deferred close");
    ok &= Require(
        store.PendingCloseDelaySummaryRebuildCount() == 0,
        "PendingCloseDelay: coalesced write should update the incremental summary");

    apfsaccess::rw::MetadataStore::MutationRequest set_basic{};
    set_basic.operation = apfsaccess::rw::MetadataStore::MutationOperation::SetBasicInfo;
    set_basic.path = L"\\new-file.bin";
    set_basic.timestamp_utc = 1234;
    ok &= ExpectMutationStatus(
        store,
        set_basic,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "PendingCloseDelay: new file timestamp should apply");
    ok &= Require(
        store.PendingMutationsCanDelayClose(),
        "PendingCloseDelay: create-size-write-timestamp batch should delay close");
    ok &= Require(
        store.PendingMutationsCanContinueDeferredClose(),
        "PendingCloseDelay: create-size-write-timestamp batch should continue deferred close");
    ok &= Require(
        store.PendingCloseDelaySummaryRebuildCount() == 0,
        "PendingCloseDelay: close-delay checks should use the incremental summary for new-file ingest");

    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "PendingCloseDelay: new file delayable batch commit should succeed");
    ok &= Require(
        !store.PendingMutationsCanDelayClose(),
        "PendingCloseDelay: clean store should not delay close");

    apfsaccess::rw::MetadataStore::MutationRequest existing_basic_info{};
    existing_basic_info.operation = apfsaccess::rw::MetadataStore::MutationOperation::SetBasicInfo;
    existing_basic_info.path = L"\\new-file.bin";
    existing_basic_info.timestamp_utc = 2345;
    ok &= ExpectMutationStatus(
        store,
        existing_basic_info,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "PendingCloseDelay: existing file timestamp should apply");
    ok &= Require(
        store.PendingMutationsCanDelayClose(),
        "PendingCloseDelay: existing file timestamp-only metadata should delay close");
    ok &= Require(
        store.PendingMutationsCanContinueDeferredClose(),
        "PendingCloseDelay: existing timestamp-only metadata should continue deferred close");
    ok &= Require(
        store.PendingCloseDelaySummaryRebuildCount() == 0,
        "PendingCloseDelay: continue check should use the incremental summary for metadata-only updates");
    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "PendingCloseDelay: existing timestamp commit should succeed");
    ok &= Require(
        !store.PendingMutationsCanDelayClose(),
        "PendingCloseDelay: clean store after timestamp commit should not delay close");

    apfsaccess::rw::MetadataStore::MutationRequest create_case_file{};
    create_case_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
    create_case_file.path = L"\\CaseDelay.bin";
    ok &= ExpectMutationStatus(
        store,
        create_case_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "PendingCloseDelay: mixed-case create should apply");

    apfsaccess::rw::MetadataStore::MutationRequest set_case_size{};
    set_case_size.operation = apfsaccess::rw::MetadataStore::MutationOperation::SetFileSize;
    set_case_size.path = L"\\CASEDELAY.BIN";
    set_case_size.length = 4096;
    ok &= ExpectMutationStatus(
        store,
        set_case_size,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "PendingCloseDelay: mixed-case size should apply");

    apfsaccess::rw::MetadataStore::MutationRequest write_case_file{};
    write_case_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
    write_case_file.path = L"\\casedelay.bin";
    write_case_file.offset = 0;
    write_case_file.length = 4096;
    ok &= ExpectMutationStatus(
        store,
        write_case_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "PendingCloseDelay: mixed-case write should apply");
    ok &= Require(
        store.PendingMutationsCanDelayClose(),
        "PendingCloseDelay: object-id summary should delay close for mixed-case create-size-write");
    ok &= Require(
        store.PendingMutationsCanContinueDeferredClose(),
        "PendingCloseDelay: object-id summary should continue deferred close for mixed-case create-size-write");
    ok &= Require(
        store.PendingCloseDelaySummaryRebuildCount() == 0,
        "PendingCloseDelay: mixed-case object-id summary should stay incremental");
    staged_payloads[L"\\CaseDelay.bin"] = BuildPatternPayload(4096, 0x74);
    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "PendingCloseDelay: mixed-case delayable batch commit should succeed");

    apfsaccess::rw::MetadataStore::MutationRequest existing_resize{};
    existing_resize.operation = apfsaccess::rw::MetadataStore::MutationOperation::SetFileSize;
    existing_resize.path = L"\\new-file.bin";
    existing_resize.length = 4096;
    ok &= ExpectMutationStatus(
        store,
        existing_resize,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "PendingCloseDelay: existing file resize should apply");
    ok &= Require(
        !store.PendingMutationsCanDelayClose(),
        "PendingCloseDelay: existing file resize should not delay close");
    ok &= Require(
        !store.PendingMutationsCanContinueDeferredClose(),
        "PendingCloseDelay: existing file resize should not continue deferred close");
    ok &= Require(
        store.PendingCloseDelaySummaryRebuildCount() == 0,
        "PendingCloseDelay: resize continue rejection should not rebuild the pending mutation summary");

    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "PendingCloseDelay: existing resize commit should succeed");

    apfsaccess::rw::MetadataStore::MutationRequest create_directory{};
    create_directory.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateDirectory;
    create_directory.path = L"\\dir";
    ok &= ExpectMutationStatus(
        store,
        create_directory,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "PendingCloseDelay: directory create should apply");
    ok &= Require(
        store.PendingMutationsCanDelayClose(),
        "PendingCloseDelay: directory create should delay close");
    ok &= Require(
        store.PendingMutationsCanContinueDeferredClose(),
        "PendingCloseDelay: directory create should continue deferred close");
    ok &= Require(
        store.PendingCloseDelaySummaryRebuildCount() == 0,
        "PendingCloseDelay: directory close-delay checks should not rebuild the pending mutation summary");
    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "PendingCloseDelay: delayed directory create commit should succeed");

    apfsaccess::rw::MetadataStore::MutationRequest rename_file{};
    rename_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Rename;
    rename_file.path = L"\\new-file.bin";
    rename_file.secondary_path = L"\\new-file-renamed.bin";
    ok &= ExpectMutationStatus(
        store,
        rename_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "PendingCloseDelay: rename should apply");
    ok &= Require(
        !store.PendingMutationsCanDelayClose(),
        "PendingCloseDelay: rename alone should not start a deferred close batch");
    ok &= Require(
        store.PendingMutationsCanContinueDeferredClose(),
        "PendingCloseDelay: rename should continue an existing deferred close batch");
    ok &= Require(
        store.PendingCloseDelaySummaryRebuildCount() == 0,
        "PendingCloseDelay: rename continue check should use the incremental summary");
    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "PendingCloseDelay: rename commit should succeed");

    return ok;
}

bool TestSequentialWriteBurstCoalescesPendingMetadataConformance(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "sequential_write_burst.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "SequentialWriteBurst: unable to create synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"SequentialWriteBurst",
    };

    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "SequentialWriteBurst: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "SequentialWriteBurst: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "SequentialWriteBurst: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "SequentialWriteBurst: PrepareNativeWritePath should succeed");

    const auto payload = BuildPatternPayload(128 * 4096, 0x7B);
    std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
    ConfigurePayloadProvider(store, staged_payloads);

    apfsaccess::rw::MetadataStore::MutationRequest create_file{};
    create_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
    create_file.path = L"\\large-copy.bin";
    ok &= ExpectMutationStatus(
        store,
        create_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "SequentialWriteBurst: create large-copy file should apply");

    apfsaccess::rw::MetadataStore::MutationRequest set_size{};
    set_size.operation = apfsaccess::rw::MetadataStore::MutationOperation::SetFileSize;
    set_size.path = L"\\large-copy.bin";
    set_size.length = payload.size();
    ok &= ExpectMutationStatus(
        store,
        set_size,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "SequentialWriteBurst: initial final-size preallocation should apply");

    apfsaccess::rw::MetadataStore::MutationRequest write_file{};
    write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
    write_file.path = L"\\large-copy.bin";
    write_file.length = 4096;
    for (std::size_t offset = 0; offset < payload.size(); offset += 4096)
    {
        write_file.offset = offset;
        ok &= ExpectMutationStatus(
            store,
            write_file,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "SequentialWriteBurst: staged sequential write chunk should apply");
    }
    staged_payloads[L"\\large-copy.bin"] = payload;

    ok &= Require(
        store.PendingMutationCount() < 16,
        "SequentialWriteBurst: chunked writes should coalesce below the dirty transaction limit");
    ok &= Require(
        store.PendingObjectMapUpdateCount() == 1,
        "SequentialWriteBurst: chunked writes should keep one pending object-map update for the target file");
    ok &= Require(
        store.PendingAllocationCount() <= 2,
        "SequentialWriteBurst: chunked writes should not allocate a fresh full-file extent for every chunk");
    ok &= Require(
        store.PendingSpacemanAllocationIndexCount() == store.PendingAllocationCount(),
        "SequentialWriteBurst: pending allocation index should mirror staged extents");
    ok &= Require(
        store.PendingDeallocationCount() == 0,
        "SequentialWriteBurst: chunked writes inside preallocated size should not stage extent churn deallocations");
    ok &= Require(
        store.PendingBtreeRecordCount() < 16,
        "SequentialWriteBurst: chunked writes should keep pending btree metadata compact");

    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "SequentialWriteBurst: coalesced burst commit should succeed");
    ok &= Require(
        store.PendingSpacemanAllocationIndexCount() == 0,
        "SequentialWriteBurst: pending allocation index should clear after commit");

    std::vector<std::byte> committed_payload;
    ok &= Require(
        store.ReadCommittedFileRange(
            L"\\large-copy.bin",
            0,
            payload.size(),
            committed_payload),
        "SequentialWriteBurst: committed payload should be readable");
    ok &= Require(
        committed_payload == payload,
        "SequentialWriteBurst: committed payload should match staged large copy");

    return ok;
}

bool TestStreamingLargeCopyWithoutPreallocationCoalescesPendingMetadataConformance(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "streaming_large_copy.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "StreamingLargeCopy: unable to create synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"StreamingLargeCopy",
    };

    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "StreamingLargeCopy: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "StreamingLargeCopy: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "StreamingLargeCopy: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "StreamingLargeCopy: PrepareNativeWritePath should succeed");

    const auto payload = BuildPatternPayload(128 * 4096, 0x91);
    std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
    ConfigurePayloadProvider(store, staged_payloads);

    apfsaccess::rw::MetadataStore::MutationRequest create_file{};
    create_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
    create_file.path = L"\\streamed-installer.exe";
    ok &= ExpectMutationStatus(
        store,
        create_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "StreamingLargeCopy: create streamed file should apply");

    apfsaccess::rw::MetadataStore::MutationRequest write_file{};
    write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
    write_file.path = L"\\streamed-installer.exe";
    write_file.length = 4096;
    for (std::size_t offset = 0; offset < payload.size(); offset += 4096)
    {
        write_file.offset = offset;
        ok &= ExpectMutationStatus(
            store,
            write_file,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "StreamingLargeCopy: staged streaming write chunk should apply");
    }
    staged_payloads[L"\\streamed-installer.exe"] = payload;

    ok &= Require(
        store.PendingMutationCount() < 16,
        "StreamingLargeCopy: streamed writes should coalesce below the dirty transaction limit");
    ok &= Require(
        store.PendingObjectMapUpdateCount() == 1,
        "StreamingLargeCopy: streamed writes should keep one pending object-map update for the target file");
    ok &= Require(
        store.PendingAllocationCount() <= 2,
        "StreamingLargeCopy: streamed growth should not retain every intermediate file extent allocation");
    ok &= Require(
        store.PendingDeallocationCount() == 0,
        "StreamingLargeCopy: intermediate uncommitted growth extents should be released without staged deallocation churn");
    ok &= Require(
        store.PendingBtreeRecordCount() < 16,
        "StreamingLargeCopy: streamed writes should keep pending btree metadata compact");

    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "StreamingLargeCopy: coalesced streaming copy commit should succeed");

    std::vector<std::byte> committed_payload;
    ok &= Require(
        store.ReadCommittedFileRange(
            L"\\streamed-installer.exe",
            0,
            payload.size(),
            committed_payload),
        "StreamingLargeCopy: committed payload should be readable");
    ok &= Require(
        committed_payload == payload,
        "StreamingLargeCopy: committed payload should match staged streaming copy");

    return ok;
}

bool TestLongStreamingWriteKeepsPendingBtreeIndexesStableConformance(
    const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "long_streaming_btree_index.apfs.img";
    if (!CreateSyntheticContainerWithSize(image_path, 32 * 1024 * 1024))
    {
        return Require(false, "LongStreamingBtreeIndex: unable to create synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"LongStreamingBtreeIndex",
    };
    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "LongStreamingBtreeIndex: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "LongStreamingBtreeIndex: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "LongStreamingBtreeIndex: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "LongStreamingBtreeIndex: PrepareNativeWritePath should succeed");

    constexpr std::size_t kChunkBytes = 4096;
    constexpr std::size_t kChunkCount = 2048;
    const auto payload = BuildPatternPayload(kChunkBytes * kChunkCount, 0xA7);
    std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
    ConfigurePayloadProvider(store, staged_payloads);

    apfsaccess::rw::MetadataStore::MutationRequest create_file{};
    create_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
    create_file.path = L"\\long-stream.bin";
    ok &= ExpectMutationStatus(
        store,
        create_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "LongStreamingBtreeIndex: create should apply");

    apfsaccess::rw::MetadataStore::MutationRequest write_file{};
    write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
    write_file.path = L"\\long-stream.bin";
    write_file.length = kChunkBytes;
    for (std::size_t chunk = 0; chunk < kChunkCount; ++chunk)
    {
        write_file.offset = chunk * kChunkBytes;
        if (!ExpectMutationStatus(
                store,
                write_file,
                apfsaccess::rw::MetadataStore::MutationStatus::Applied,
                "LongStreamingBtreeIndex: streaming write should apply"))
        {
            return false;
        }
    }
    staged_payloads[L"\\long-stream.bin"] = payload;

    ok &= Require(
        store.PendingBtreeRecordCount() < 16,
        "LongStreamingBtreeIndex: repeated replacement should keep pending B-tree metadata compact");
    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "LongStreamingBtreeIndex: commit should succeed");

    std::vector<std::byte> committed_payload;
    ok &= Require(
        store.ReadCommittedFileRange(L"\\long-stream.bin", 0, payload.size(), committed_payload),
        "LongStreamingBtreeIndex: committed payload should be readable");
    ok &= Require(
        committed_payload == payload,
        "LongStreamingBtreeIndex: committed payload should match the stream");
    return ok;
}

bool TestSmallFilePendingWriteCoalescingAvoidsFirstWriteScansConformance(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "small_file_pending_write_coalescing.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "SmallFilePendingWriteCoalescing: unable to create synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"SmallFilePendingWriteCoalescing",
    };

    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "SmallFilePendingWriteCoalescing: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "SmallFilePendingWriteCoalescing: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "SmallFilePendingWriteCoalescing: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "SmallFilePendingWriteCoalescing: PrepareNativeWritePath should succeed");

    std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
    ConfigurePayloadProvider(store, staged_payloads);

    constexpr int kFileCount = 128;
    for (int index = 0; index < kFileCount; ++index)
    {
        const auto path = L"\\small-" + std::to_wstring(index) + L".bin";
        apfsaccess::rw::MetadataStore::MutationRequest create_file{};
        create_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
        create_file.path = path;
        ok &= ExpectMutationStatus(
            store,
            create_file,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "SmallFilePendingWriteCoalescing: create small file should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_file{};
        write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_file.path = path;
        write_file.length = 1024;
        ok &= ExpectMutationStatus(
            store,
            write_file,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "SmallFilePendingWriteCoalescing: first small-file write should apply");
        staged_payloads[path] = BuildPatternPayload(1024, static_cast<unsigned char>(index));
    }

    ok &= Require(
        store.PendingWriteCoalesceScanCount() == 0,
        "SmallFilePendingWriteCoalescing: first writes to distinct files should not scan pending mutations");
    ok &= Require(
        store.PendingObjectMapUpdateScanCount() == 0,
        "SmallFilePendingWriteCoalescing: first writes to distinct files should not scan pending object-map updates");
    ok &= Require(
        store.PendingBtreeFileMetadataScanCount() == 0,
        "SmallFilePendingWriteCoalescing: first writes to distinct files should not scan pending btree file metadata");

    apfsaccess::rw::MetadataStore::MutationRequest second_write{};
    second_write.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
    second_write.path = L"\\small-0.bin";
    second_write.length = 1024;
    ok &= ExpectMutationStatus(
        store,
        second_write,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "SmallFilePendingWriteCoalescing: repeated write should apply");
    ok &= Require(
        store.PendingWriteCoalesceScanCount() == 0,
        "SmallFilePendingWriteCoalescing: repeated write to same file should use the pending write index");
    ok &= Require(
        store.PendingObjectMapUpdateScanCount() == 0,
        "SmallFilePendingWriteCoalescing: repeated object-map update should use the pending update index");
    ok &= Require(
        store.PendingBtreeFileMetadataScanCount() == 0,
        "SmallFilePendingWriteCoalescing: repeated write should use the pending btree file metadata index");
    ok &= Require(
        store.PendingCloseDelaySummaryRebuildCount() == 0,
        "SmallFilePendingWriteCoalescing: repeated write coalescing should update the close-delay summary incrementally");

    const auto pending_count_after_repeated_write = store.PendingMutationCount();
    apfsaccess::rw::MetadataStore::MutationRequest tail_write{};
    tail_write.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
    tail_write.path = L"\\small-0.bin";
    tail_write.length = 1024;
    ok &= ExpectMutationStatus(
        store,
        tail_write,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "SmallFilePendingWriteCoalescing: tail repeated write should apply");
    ok &= Require(
        store.PendingMutationCount() == pending_count_after_repeated_write,
        "SmallFilePendingWriteCoalescing: tail repeated write should replace the pending write in place");
    ok &= Require(
        store.PendingWriteCoalesceScanCount() == 0,
        "SmallFilePendingWriteCoalescing: tail repeated write should use the pending write index");
    ok &= Require(
        store.PendingBtreeFileMetadataScanCount() == 0,
        "SmallFilePendingWriteCoalescing: tail repeated write should keep using the pending btree file metadata index");
    ok &= Require(
        store.PendingCloseDelaySummaryRebuildCount() == 0,
        "SmallFilePendingWriteCoalescing: tail repeated write should keep the close-delay summary incremental");

    return ok;
}

bool TestInterleavedSetBasicInfoCoalescesPendingMutationConformance(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "interleaved_set_basic_info_coalesce.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "InterleavedSetBasicInfo: unable to create synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"InterleavedSetBasicInfo",
    };

    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "InterleavedSetBasicInfo: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "InterleavedSetBasicInfo: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "InterleavedSetBasicInfo: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "InterleavedSetBasicInfo: PrepareNativeWritePath should succeed");

    std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
    ConfigurePayloadProvider(store, staged_payloads);

    const std::wstring path = L"\\interleaved.bin";
    const auto payload = BuildPatternPayload(8192, 0x7D);

    apfsaccess::rw::MetadataStore::MutationRequest create_file{};
    create_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
    create_file.path = path;
    ok &= ExpectMutationStatus(
        store,
        create_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "InterleavedSetBasicInfo: create file should apply");

    apfsaccess::rw::MetadataStore::MutationRequest set_size{};
    set_size.operation = apfsaccess::rw::MetadataStore::MutationOperation::SetFileSize;
    set_size.path = path;
    set_size.length = payload.size();
    ok &= ExpectMutationStatus(
        store,
        set_size,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "InterleavedSetBasicInfo: set file size should apply");

    apfsaccess::rw::MetadataStore::MutationRequest first_write{};
    first_write.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
    first_write.path = path;
    first_write.offset = 0;
    first_write.length = 4096;
    ok &= ExpectMutationStatus(
        store,
        first_write,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "InterleavedSetBasicInfo: first write should apply");

    apfsaccess::rw::MetadataStore::MutationRequest first_timestamp{};
    first_timestamp.operation = apfsaccess::rw::MetadataStore::MutationOperation::SetBasicInfo;
    first_timestamp.path = path;
    first_timestamp.timestamp_utc = 111;
    ok &= ExpectMutationStatus(
        store,
        first_timestamp,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "InterleavedSetBasicInfo: first timestamp should apply");

    apfsaccess::rw::MetadataStore::MutationRequest second_write{};
    second_write.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
    second_write.path = path;
    second_write.offset = 4096;
    second_write.length = 4096;
    ok &= ExpectMutationStatus(
        store,
        second_write,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "InterleavedSetBasicInfo: second write should apply");

    const auto pending_count_before_final_timestamp = store.PendingMutationCount();
    const auto basic_info_path_fallbacks_before_final_timestamp =
        store.PendingBasicInfoCoalescePathFallbackCount();
    apfsaccess::rw::MetadataStore::MutationRequest final_timestamp{};
    final_timestamp.operation = apfsaccess::rw::MetadataStore::MutationOperation::SetBasicInfo;
    final_timestamp.path = path;
    final_timestamp.timestamp_utc = 222;
    ok &= ExpectMutationStatus(
        store,
        final_timestamp,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "InterleavedSetBasicInfo: final timestamp should apply");

    staged_payloads[path] = payload;
    ok &= Require(
        store.PendingMutationCount() == pending_count_before_final_timestamp,
        "InterleavedSetBasicInfo: final timestamp should replace the older pending timestamp instead of growing the mutation log");
    ok &= Require(
        store.PendingCloseDelaySummaryRebuildCount() == 0,
        "InterleavedSetBasicInfo: timestamp coalescing should keep close-delay summary incremental");
    ok &= Require(
        store.PendingBasicInfoCoalescePathFallbackCount() == basic_info_path_fallbacks_before_final_timestamp,
        "InterleavedSetBasicInfo: final timestamp should reuse the staged canonical path key");
    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "InterleavedSetBasicInfo: coalesced batch commit should succeed");

    const auto committed = store.LookupCommittedInodeByPath(path);
    ok &= Require(
        committed.has_value() && committed->timestamp_utc == final_timestamp.timestamp_utc,
        "InterleavedSetBasicInfo: committed inode should keep the final timestamp");

    std::vector<std::byte> committed_payload;
    ok &= Require(
        store.ReadCommittedFileRange(path, 0, payload.size(), committed_payload),
        "InterleavedSetBasicInfo: committed payload should be readable");
    ok &= Require(
        committed_payload == payload,
        "InterleavedSetBasicInfo: committed payload should match staged bytes");

    return ok;
}

bool TestCommitSkipsDuplicatePostAllocationGraphValidationConformance(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "commit_skips_duplicate_graph_validation.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "CommitGraphValidation: unable to create synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"CommitGraphValidation",
    };

    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "CommitGraphValidation: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "CommitGraphValidation: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "CommitGraphValidation: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "CommitGraphValidation: PrepareNativeWritePath should succeed");

    apfsaccess::rw::MetadataStore::MutationRequest create_directory{};
    create_directory.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateDirectory;
    create_directory.path = L"\\graph-validation-dir";
    ok &= ExpectMutationStatus(
        store,
        create_directory,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "CommitGraphValidation: directory create should apply");
    ok &= Require(
        !store.PendingMutationsCanSkipPreflightInodeGraphValidation(),
        "CommitGraphValidation: directory create should keep full inode graph validation");

    wchar_t previous_perf_value[256]{};
    const auto previous_perf_chars = GetEnvironmentVariableW(
        L"APFSACCESS_PERF_COUNTERS",
        previous_perf_value,
        static_cast<DWORD>(std::size(previous_perf_value)));
    const bool had_previous_perf =
        previous_perf_chars > 0 &&
        previous_perf_chars < static_cast<DWORD>(std::size(previous_perf_value));
    SetEnvironmentVariableW(L"APFSACCESS_PERF_COUNTERS", L"1");

    const auto before_count = ExtractPerfCounterCount(store.PerformanceJson(), "validateInodeGraph");
    ok &= Require(
        before_count.has_value(),
        "CommitGraphValidation: validateInodeGraph counter should exist before commit");
    const auto sanitizer_count_before_commit = store.WorkingFreeExtentSanitizeCount();

    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "CommitGraphValidation: commit should succeed");

    const auto after_count = ExtractPerfCounterCount(store.PerformanceJson(), "validateInodeGraph");
    ok &= Require(
        after_count.has_value(),
        "CommitGraphValidation: validateInodeGraph counter should exist after commit");
    if (before_count.has_value() && after_count.has_value())
    {
        const auto delta = after_count.value() - before_count.value();
        ok &= Require(
            delta == 2,
            "CommitGraphValidation: commit should validate committed and working inode graphs once, not again after commit-extent allocation; delta=" +
                std::to_string(delta));
    }
    const auto sanitizer_delta = store.WorkingFreeExtentSanitizeCount() - sanitizer_count_before_commit;
    ok &= Require(
        sanitizer_delta == 1,
        "CommitGraphValidation: commit should rely on commit-extent fast validation after staging the commit blob; sanitizer delta=" +
            std::to_string(sanitizer_delta));

    SetEnvironmentVariableW(
        L"APFSACCESS_PERF_COUNTERS",
        had_previous_perf ? previous_perf_value : nullptr);

    return ok;
}

bool TestContentOnlyCommitSkipsInodeGraphValidationConformance(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "content_only_commit_skips_inode_graph_validation.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "ContentOnlyCommitGraphValidation: unable to create synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"ContentOnlyCommitGraphValidation",
    };

    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "ContentOnlyCommitGraphValidation: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "ContentOnlyCommitGraphValidation: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "ContentOnlyCommitGraphValidation: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "ContentOnlyCommitGraphValidation: PrepareNativeWritePath should succeed");

    std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
    ConfigurePayloadProvider(store, staged_payloads);

    if (!CreateAndCommitFile(
            store,
            staged_payloads,
            L"\\content-only.bin",
            4096,
            0x6A,
            "ContentOnlyCommitGraphValidation: seed file"))
    {
        return false;
    }

    const auto committed_inode = store.LookupCommittedInodeByPath(L"\\content-only.bin");
    ok &= Require(committed_inode.has_value(), "ContentOnlyCommitGraphValidation: committed inode should exist after seed commit");

    wchar_t previous_perf_value[256]{};
    const auto previous_perf_chars = GetEnvironmentVariableW(
        L"APFSACCESS_PERF_COUNTERS",
        previous_perf_value,
        static_cast<DWORD>(std::size(previous_perf_value)));
    const bool had_previous_perf =
        previous_perf_chars > 0 &&
        previous_perf_chars < static_cast<DWORD>(std::size(previous_perf_value));
    SetEnvironmentVariableW(L"APFSACCESS_PERF_COUNTERS", L"1");

    const auto before_count = ExtractPerfCounterCount(store.PerformanceJson(), "validateInodeGraph");
    const auto before_projected_btree_skips =
        ExtractNestedUnsignedValue(store.PerformanceJson(), "commitPreflight", "projectedBtreeStateSkips");
    ok &= Require(
        before_count.has_value() && before_projected_btree_skips.has_value(),
        "ContentOnlyCommitGraphValidation: preflight counters should exist before content-only commit");

    apfsaccess::rw::MetadataStore::MutationRequest write_file{};
    write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
    write_file.path = L"\\content-only.bin";
    write_file.offset = 0;
    write_file.length = 4096;
    ok &= ExpectMutationStatus(
        store,
        write_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "ContentOnlyCommitGraphValidation: write file should apply");
    ok &= Require(
        store.PendingMutationsAreContentWritesOnly(),
        "ContentOnlyCommitGraphValidation: write-only batch should be classified as content writes only");
    staged_payloads[write_file.path] = BuildPatternPayload(4096, 0x6B);

    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "ContentOnlyCommitGraphValidation: content-only commit should succeed");

    const auto after_count = ExtractPerfCounterCount(store.PerformanceJson(), "validateInodeGraph");
    const auto after_projected_btree_skips =
        ExtractNestedUnsignedValue(store.PerformanceJson(), "commitPreflight", "projectedBtreeStateSkips");
    ok &= Require(
        after_count.has_value() && after_projected_btree_skips.has_value(),
        "ContentOnlyCommitGraphValidation: preflight counters should exist after content-only commit");
    if (before_count.has_value() && after_count.has_value())
    {
        ok &= Require(
            after_count.value() == before_count.value(),
            "ContentOnlyCommitGraphValidation: content-only commit should skip inode graph validation; delta=" +
                std::to_string(after_count.value() - before_count.value()));
    }
    if (before_projected_btree_skips.has_value() && after_projected_btree_skips.has_value())
    {
        ok &= Require(
            after_projected_btree_skips.value() == before_projected_btree_skips.value(),
            "ContentOnlyCommitGraphValidation: existing-file content commit should keep full projected B-tree validation");
    }

    std::vector<std::byte> committed_payload;
    ok &= Require(
        store.ReadCommittedFileRange(L"\\content-only.bin", 0, 4096, committed_payload),
        "ContentOnlyCommitGraphValidation: committed payload should be readable");
    ok &= Require(
        committed_payload == staged_payloads[L"\\content-only.bin"],
        "ContentOnlyCommitGraphValidation: committed payload should match staged bytes");

    SetEnvironmentVariableW(
        L"APFSACCESS_PERF_COUNTERS",
        had_previous_perf ? previous_perf_value : nullptr);

    return ok;
}

bool TestFreshIngestCommitSkipsInodeGraphValidationConformance(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "fresh_ingest_commit_skips_inode_graph_validation.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "FreshIngestCommitGraphValidation: unable to create synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"FreshIngestCommitGraphValidation",
    };

    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "FreshIngestCommitGraphValidation: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "FreshIngestCommitGraphValidation: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "FreshIngestCommitGraphValidation: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "FreshIngestCommitGraphValidation: PrepareNativeWritePath should succeed");

    std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
    ConfigurePayloadProvider(store, staged_payloads);

    wchar_t previous_perf_value[256]{};
    const auto previous_perf_chars = GetEnvironmentVariableW(
        L"APFSACCESS_PERF_COUNTERS",
        previous_perf_value,
        static_cast<DWORD>(std::size(previous_perf_value)));
    const bool had_previous_perf =
        previous_perf_chars > 0 &&
        previous_perf_chars < static_cast<DWORD>(std::size(previous_perf_value));
    SetEnvironmentVariableW(L"APFSACCESS_PERF_COUNTERS", L"1");

    const auto before_json = store.PerformanceJson();
    const auto before_graph_count = ExtractPerfCounterCount(before_json, "validateInodeGraph");
    const auto before_skips = ExtractNestedUnsignedValue(before_json, "commitPreflight", "inodeGraphSkips");
    const auto before_projected_btree_skips =
        ExtractNestedUnsignedValue(before_json, "commitPreflight", "projectedBtreeStateSkips");
    const auto before_overlay_only =
        ExtractNestedUnsignedValue(before_json, "commitPreflight", "freshIngestOverlayOnly");
    const auto before_full_sweeps =
        ExtractNestedUnsignedValue(before_json, "commitPreflight", "fullObjectSweeps");
    const auto before_object_map_index_lookups =
        ExtractNestedUnsignedValue(before_json, "commitPreflight", "objectMapIndexLookups");
    const auto before_physical_order_fast_paths =
        ExtractNestedUnsignedValue(before_json, "commitPreflight", "freshIngestPhysicalOrderFastPaths");
    const auto before_physical_set_fallbacks =
        ExtractNestedUnsignedValue(before_json, "commitPreflight", "freshIngestPhysicalSetFallbacks");
    const auto before_mapping_recheck_skips =
        ExtractNestedUnsignedValue(before_json, "commitPreflight", "freshIngestMappingRecheckSkips");
    ok &= Require(
        before_graph_count.has_value() &&
            before_skips.has_value() &&
            before_projected_btree_skips.has_value() &&
            before_overlay_only.has_value() &&
            before_full_sweeps.has_value() &&
            before_object_map_index_lookups.has_value() &&
            before_physical_order_fast_paths.has_value() &&
            before_physical_set_fallbacks.has_value() &&
            before_mapping_recheck_skips.has_value(),
        "FreshIngestCommitGraphValidation: graph and preflight skip counters should exist before commit");

    apfsaccess::rw::MetadataStore::MutationRequest create_file{};
    create_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
    create_file.path = L"\\fresh-ingest.bin";
    ok &= ExpectMutationStatus(
        store,
        create_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "FreshIngestCommitGraphValidation: create file should apply");

    apfsaccess::rw::MetadataStore::MutationRequest set_size{};
    set_size.operation = apfsaccess::rw::MetadataStore::MutationOperation::SetFileSize;
    set_size.path = create_file.path;
    set_size.length = 8192;
    ok &= ExpectMutationStatus(
        store,
        set_size,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "FreshIngestCommitGraphValidation: set size should apply");

    apfsaccess::rw::MetadataStore::MutationRequest write_file{};
    write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
    write_file.path = create_file.path;
    write_file.length = set_size.length;
    ok &= ExpectMutationStatus(
        store,
        write_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "FreshIngestCommitGraphValidation: write file should apply");
    staged_payloads[write_file.path] = BuildPatternPayload(static_cast<std::size_t>(write_file.length), 0xD4);

    apfsaccess::rw::MetadataStore::MutationRequest set_basic{};
    set_basic.operation = apfsaccess::rw::MetadataStore::MutationOperation::SetBasicInfo;
    set_basic.path = create_file.path;
    set_basic.timestamp_utc = 7777;
    ok &= ExpectMutationStatus(
        store,
        set_basic,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "FreshIngestCommitGraphValidation: set basic info should apply");

    ok &= Require(
        store.PendingMutationsCanDelayClose(),
        "FreshIngestCommitGraphValidation: fresh ingest batch should be delayable");
    ok &= Require(
        store.PendingMutationsCanSkipPreflightInodeGraphValidation(),
        "FreshIngestCommitGraphValidation: fresh ingest batch should skip preflight inode graph validation");
    ok &= Require(
        store.PendingMutationsCanSkipPreflightProjectedBtreeValidation(),
        "FreshIngestCommitGraphValidation: fresh ingest batch should skip full projected B-tree validation");
    const auto fresh_ingest_pending_index_json = store.PerformanceJson();
    const auto tracked_directory_children = ExtractNestedUnsignedValue(
        fresh_ingest_pending_index_json,
        "pendingBtreeFileMetadataIndex",
        "trackedDirectoryChildren");
    const auto pending_btree_tombstones = ExtractNestedUnsignedValue(
        fresh_ingest_pending_index_json,
        "pendingBtreeFileMetadataIndex",
        "tombstones");
    const auto pending_btree_untracked = ExtractNestedUnsignedValue(
        fresh_ingest_pending_index_json,
        "pendingBtreeFileMetadataIndex",
        "untrackedRecords");
    ok &= Require(
        tracked_directory_children.has_value() &&
            tracked_directory_children.value() == 1 &&
            pending_btree_tombstones.has_value() &&
            pending_btree_tombstones.value() == 0 &&
            pending_btree_untracked.has_value() &&
            pending_btree_untracked.value() == 0,
        "FreshIngestCommitGraphValidation: fresh ingest B-tree summary should track directory children without untracked records");

    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "FreshIngestCommitGraphValidation: fresh ingest commit should succeed");

    const auto after_ingest_json = store.PerformanceJson();
    const auto after_ingest_graph_count = ExtractPerfCounterCount(after_ingest_json, "validateInodeGraph");
    const auto after_ingest_skips = ExtractNestedUnsignedValue(after_ingest_json, "commitPreflight", "inodeGraphSkips");
    const auto after_ingest_projected_btree_skips =
        ExtractNestedUnsignedValue(after_ingest_json, "commitPreflight", "projectedBtreeStateSkips");
    const auto after_ingest_overlay_only =
        ExtractNestedUnsignedValue(after_ingest_json, "commitPreflight", "freshIngestOverlayOnly");
    const auto after_ingest_full_sweeps =
        ExtractNestedUnsignedValue(after_ingest_json, "commitPreflight", "fullObjectSweeps");
    const auto after_ingest_object_map_index_lookups =
        ExtractNestedUnsignedValue(after_ingest_json, "commitPreflight", "objectMapIndexLookups");
    const auto after_ingest_physical_order_fast_paths =
        ExtractNestedUnsignedValue(after_ingest_json, "commitPreflight", "freshIngestPhysicalOrderFastPaths");
    const auto after_ingest_physical_set_fallbacks =
        ExtractNestedUnsignedValue(after_ingest_json, "commitPreflight", "freshIngestPhysicalSetFallbacks");
    const auto after_ingest_mapping_recheck_skips =
        ExtractNestedUnsignedValue(after_ingest_json, "commitPreflight", "freshIngestMappingRecheckSkips");
    ok &= Require(
        after_ingest_graph_count.has_value() &&
            after_ingest_skips.has_value() &&
            after_ingest_projected_btree_skips.has_value() &&
            after_ingest_overlay_only.has_value() &&
            after_ingest_full_sweeps.has_value() &&
            after_ingest_object_map_index_lookups.has_value() &&
            after_ingest_physical_order_fast_paths.has_value() &&
            after_ingest_physical_set_fallbacks.has_value() &&
            after_ingest_mapping_recheck_skips.has_value(),
        "FreshIngestCommitGraphValidation: graph and preflight skip counters should exist after ingest commit");
    if (before_graph_count.has_value() && after_ingest_graph_count.has_value())
    {
        ok &= Require(
            after_ingest_graph_count.value() == before_graph_count.value(),
            "FreshIngestCommitGraphValidation: fresh ingest commit should skip full inode graph validation; delta=" +
                std::to_string(after_ingest_graph_count.value() - before_graph_count.value()));
    }
    if (before_skips.has_value() && after_ingest_skips.has_value())
    {
        ok &= Require(
            after_ingest_skips.value() == before_skips.value() + 1,
            "FreshIngestCommitGraphValidation: fresh ingest commit should record one preflight skip");
    }
    if (before_projected_btree_skips.has_value() && after_ingest_projected_btree_skips.has_value())
    {
        ok &= Require(
            after_ingest_projected_btree_skips.value() == before_projected_btree_skips.value() + 1,
            "FreshIngestCommitGraphValidation: fresh ingest commit should record one projected B-tree validation skip");
    }
    if (before_overlay_only.has_value() && after_ingest_overlay_only.has_value())
    {
        ok &= Require(
            after_ingest_overlay_only.value() == before_overlay_only.value() + 1,
            "FreshIngestCommitGraphValidation: fresh ingest commit should validate only pending object-map overlay");
    }
    if (before_full_sweeps.has_value() && after_ingest_full_sweeps.has_value())
    {
        ok &= Require(
            after_ingest_full_sweeps.value() == before_full_sweeps.value(),
            "FreshIngestCommitGraphValidation: fresh ingest commit should skip full object preflight sweep");
    }
    if (before_object_map_index_lookups.has_value() && after_ingest_object_map_index_lookups.has_value())
    {
        ok &= Require(
            after_ingest_object_map_index_lookups.value() == before_object_map_index_lookups.value(),
            "FreshIngestCommitGraphValidation: fresh ingest commit should validate pending object-map updates directly");
    }
    if (before_physical_order_fast_paths.has_value() && after_ingest_physical_order_fast_paths.has_value())
    {
        ok &= Require(
            after_ingest_physical_order_fast_paths.value() == before_physical_order_fast_paths.value() + 1,
            "FreshIngestCommitGraphValidation: fresh ingest commit should use ordered physical-address validation");
    }
    if (before_physical_set_fallbacks.has_value() && after_ingest_physical_set_fallbacks.has_value())
    {
        ok &= Require(
            after_ingest_physical_set_fallbacks.value() == before_physical_set_fallbacks.value(),
            "FreshIngestCommitGraphValidation: ordered fresh ingest commit should not allocate the physical-address set fallback");
    }
    if (before_mapping_recheck_skips.has_value() && after_ingest_mapping_recheck_skips.has_value())
    {
        ok &= Require(
            after_ingest_mapping_recheck_skips.value() == before_mapping_recheck_skips.value() + 1,
            "FreshIngestCommitGraphValidation: fresh ingest commit should skip duplicate object-map mapping recheck");
    }

    std::vector<std::byte> committed_payload;
    ok &= Require(
        store.ReadCommittedFileRange(L"\\fresh-ingest.bin", 0, 8192, committed_payload),
        "FreshIngestCommitGraphValidation: committed payload should be readable");
    ok &= Require(
        committed_payload == staged_payloads[L"\\fresh-ingest.bin"],
        "FreshIngestCommitGraphValidation: committed payload should match staged bytes");

    apfsaccess::rw::MetadataStore::MutationRequest rename_file{};
    rename_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Rename;
    rename_file.path = L"\\fresh-ingest.bin";
    rename_file.secondary_path = L"\\fresh-ingest-renamed.bin";
    ok &= ExpectMutationStatus(
        store,
        rename_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "FreshIngestCommitGraphValidation: rename should apply");
    ok &= Require(
        !store.PendingMutationsCanSkipPreflightInodeGraphValidation(),
        "FreshIngestCommitGraphValidation: namespace rename should keep full inode graph validation");
    ok &= Require(
        !store.PendingMutationsCanSkipPreflightProjectedBtreeValidation(),
        "FreshIngestCommitGraphValidation: namespace rename should keep full projected B-tree validation");

    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "FreshIngestCommitGraphValidation: rename commit should succeed");

    const auto after_rename_json = store.PerformanceJson();
    const auto after_rename_graph_count = ExtractPerfCounterCount(after_rename_json, "validateInodeGraph");
    const auto after_rename_skips = ExtractNestedUnsignedValue(after_rename_json, "commitPreflight", "inodeGraphSkips");
    const auto after_rename_projected_btree_skips =
        ExtractNestedUnsignedValue(after_rename_json, "commitPreflight", "projectedBtreeStateSkips");
    const auto after_rename_overlay_only =
        ExtractNestedUnsignedValue(after_rename_json, "commitPreflight", "freshIngestOverlayOnly");
    const auto after_rename_full_sweeps =
        ExtractNestedUnsignedValue(after_rename_json, "commitPreflight", "fullObjectSweeps");
    const auto after_rename_object_map_index_lookups =
        ExtractNestedUnsignedValue(after_rename_json, "commitPreflight", "objectMapIndexLookups");
    const auto after_rename_physical_order_fast_paths =
        ExtractNestedUnsignedValue(after_rename_json, "commitPreflight", "freshIngestPhysicalOrderFastPaths");
    const auto after_rename_physical_set_fallbacks =
        ExtractNestedUnsignedValue(after_rename_json, "commitPreflight", "freshIngestPhysicalSetFallbacks");
    const auto after_rename_mapping_recheck_skips =
        ExtractNestedUnsignedValue(after_rename_json, "commitPreflight", "freshIngestMappingRecheckSkips");
    ok &= Require(
        after_rename_graph_count.has_value() &&
            after_rename_skips.has_value() &&
            after_rename_projected_btree_skips.has_value() &&
            after_rename_overlay_only.has_value() &&
            after_rename_full_sweeps.has_value() &&
            after_rename_object_map_index_lookups.has_value() &&
            after_rename_physical_order_fast_paths.has_value() &&
            after_rename_physical_set_fallbacks.has_value() &&
            after_rename_mapping_recheck_skips.has_value(),
        "FreshIngestCommitGraphValidation: graph and preflight skip counters should exist after rename commit");
    if (after_ingest_graph_count.has_value() && after_rename_graph_count.has_value())
    {
        ok &= Require(
            after_rename_graph_count.value() == after_ingest_graph_count.value() + 2,
            "FreshIngestCommitGraphValidation: rename commit should validate committed and working inode graphs");
    }
    if (after_ingest_skips.has_value() && after_rename_skips.has_value())
    {
        ok &= Require(
            after_rename_skips.value() == after_ingest_skips.value(),
            "FreshIngestCommitGraphValidation: rename commit should not record another preflight skip");
    }
    if (after_ingest_projected_btree_skips.has_value() && after_rename_projected_btree_skips.has_value())
    {
        ok &= Require(
            after_rename_projected_btree_skips.value() == after_ingest_projected_btree_skips.value(),
            "FreshIngestCommitGraphValidation: rename commit should not record another projected B-tree validation skip");
    }
    if (after_ingest_overlay_only.has_value() && after_rename_overlay_only.has_value())
    {
        ok &= Require(
            after_rename_overlay_only.value() == after_ingest_overlay_only.value(),
            "FreshIngestCommitGraphValidation: rename commit should not use fresh-ingest overlay-only validation");
    }
    if (after_ingest_full_sweeps.has_value() && after_rename_full_sweeps.has_value())
    {
        ok &= Require(
            after_rename_full_sweeps.value() == after_ingest_full_sweeps.value() + 1,
            "FreshIngestCommitGraphValidation: rename commit should keep full object preflight sweep");
    }
    if (after_ingest_object_map_index_lookups.has_value() && after_rename_object_map_index_lookups.has_value())
    {
        ok &= Require(
            after_rename_object_map_index_lookups.value() > after_ingest_object_map_index_lookups.value(),
            "FreshIngestCommitGraphValidation: full preflight should reuse the pending object-map index for lookups");
    }
    if (after_ingest_physical_order_fast_paths.has_value() && after_rename_physical_order_fast_paths.has_value())
    {
        ok &= Require(
            after_rename_physical_order_fast_paths.value() == after_ingest_physical_order_fast_paths.value(),
            "FreshIngestCommitGraphValidation: rename commit should not record another fresh-ingest physical-address fast path");
    }
    if (after_ingest_physical_set_fallbacks.has_value() && after_rename_physical_set_fallbacks.has_value())
    {
        ok &= Require(
            after_rename_physical_set_fallbacks.value() == after_ingest_physical_set_fallbacks.value(),
            "FreshIngestCommitGraphValidation: rename commit should not use the fresh-ingest physical-address set fallback");
    }
    if (after_ingest_mapping_recheck_skips.has_value() && after_rename_mapping_recheck_skips.has_value())
    {
        ok &= Require(
            after_rename_mapping_recheck_skips.value() == after_ingest_mapping_recheck_skips.value(),
            "FreshIngestCommitGraphValidation: rename commit should not skip full object-map mapping validation");
    }

    {
        apfsaccess::rw::MetadataStore remounted(context);
        ok &= Require(
            remounted.LoadContainerSuperblocks(),
            "FreshIngestCommitGraphValidation: remount LoadContainerSuperblocks should succeed");
        ok &= Require(
            remounted.PrepareNativeWritePath(),
            "FreshIngestCommitGraphValidation: remount PrepareNativeWritePath should succeed");
        std::vector<std::byte> remounted_payload;
        ok &= Require(
            remounted.ReadCommittedFileRange(L"\\fresh-ingest-renamed.bin", 0, 8192, remounted_payload),
            "FreshIngestCommitGraphValidation: remounted renamed payload should be readable");
        ok &= Require(
            remounted_payload == staged_payloads[L"\\fresh-ingest.bin"],
            "FreshIngestCommitGraphValidation: remounted renamed payload should match staged bytes");
    }

    SetEnvironmentVariableW(
        L"APFSACCESS_PERF_COUNTERS",
        had_previous_perf ? previous_perf_value : nullptr);

    return ok;
}

bool TestStreamingGrowthUsesReservedExtentSlackConformance(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "streaming_growth_slack.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "StreamingGrowthSlack: unable to create synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"StreamingGrowthSlack",
    };

    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "StreamingGrowthSlack: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "StreamingGrowthSlack: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "StreamingGrowthSlack: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "StreamingGrowthSlack: PrepareNativeWritePath should succeed");

    const auto payload = BuildPatternPayload(96 * 4096, 0x39);
    std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
    ConfigurePayloadProvider(store, staged_payloads);

    apfsaccess::rw::MetadataStore::MutationRequest create_file{};
    create_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
    create_file.path = L"\\streaming-slack.bin";
    ok &= ExpectMutationStatus(
        store,
        create_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "StreamingGrowthSlack: create streamed file should apply");

    apfsaccess::rw::MetadataStore::MutationRequest write_file{};
    write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
    write_file.path = L"\\streaming-slack.bin";
    write_file.length = 4096;
    std::uint64_t first_physical_address = 0;
    const auto before_index_json = store.PerformanceJson();
    const auto before_index_rebuilds = ExtractNestedUnsignedValue(
        before_index_json,
        "pendingSpacemanAllocationIndex",
        "rebuilds");
    const auto before_local_resizes = ExtractNestedUnsignedValue(
        before_index_json,
        "pendingSpacemanAllocationIndex",
        "localResizes");
    ok &= Require(
        before_index_rebuilds.has_value() && before_local_resizes.has_value(),
        "StreamingGrowthSlack: pending allocation index counters should exist before streaming writes");
    for (std::size_t offset = 0; offset < payload.size(); offset += 4096)
    {
        write_file.offset = offset;
        ok &= ExpectMutationStatus(
            store,
            write_file,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "StreamingGrowthSlack: staged streaming write chunk should apply");
        ok &= Require(
            store.PendingAllocationCount() <= 1,
            "StreamingGrowthSlack: growing streamed file should keep one reserved pending allocation");
        ok &= Require(
            store.PendingSpacemanAllocationIndexCount() == store.PendingAllocationCount(),
            "StreamingGrowthSlack: pending allocation index should mirror staged extents");
        ok &= Require(
            store.PendingDeallocationCount() == 0,
            "StreamingGrowthSlack: growing streamed file should not churn deallocations");
        const auto current_inode = store.DebugLookupWorkingInodeByPath(L"\\streaming-slack.bin");
        ok &= Require(current_inode.has_value(), "StreamingGrowthSlack: working inode should exist after each chunk");
        if (current_inode.has_value())
        {
            if (first_physical_address == 0)
            {
                first_physical_address = current_inode->data_physical_address;
            }
            ok &= Require(
                current_inode->data_physical_address == first_physical_address,
                "StreamingGrowthSlack: streamed growth should extend the first pending extent instead of moving it");
        }
    }
    const auto after_index_json = store.PerformanceJson();
    const auto after_index_rebuilds = ExtractNestedUnsignedValue(
        after_index_json,
        "pendingSpacemanAllocationIndex",
        "rebuilds");
    const auto after_local_resizes = ExtractNestedUnsignedValue(
        after_index_json,
        "pendingSpacemanAllocationIndex",
        "localResizes");
    ok &= Require(
        after_index_rebuilds.has_value() && after_local_resizes.has_value(),
        "StreamingGrowthSlack: pending allocation index counters should exist after streaming writes");
    if (before_index_rebuilds.has_value() && after_index_rebuilds.has_value())
    {
        ok &= Require(
            after_index_rebuilds.value() == before_index_rebuilds.value(),
            "StreamingGrowthSlack: pending extent growth should not rebuild the allocation index");
    }
    if (before_local_resizes.has_value() && after_local_resizes.has_value())
    {
        ok &= Require(
            after_local_resizes.value() > before_local_resizes.value(),
            "StreamingGrowthSlack: pending extent growth should use local allocation index resize updates");
    }
    staged_payloads[L"\\streaming-slack.bin"] = payload;

    const auto working_inode = store.DebugLookupWorkingInodeByPath(L"\\streaming-slack.bin");
    ok &= Require(working_inode.has_value(), "StreamingGrowthSlack: working inode should exist");
    if (working_inode.has_value())
    {
        ok &= Require(
            working_inode->logical_size == payload.size(),
            "StreamingGrowthSlack: working logical size should match written bytes");
    }

    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "StreamingGrowthSlack: coalesced streaming slack commit should succeed");

    auto committed_inode = store.LookupCommittedInodeByPath(L"\\streaming-slack.bin");
    ok &= Require(committed_inode.has_value(), "StreamingGrowthSlack: committed inode should exist");
    if (committed_inode.has_value())
    {
        ok &= Require(
            committed_inode->logical_size == payload.size(),
            "StreamingGrowthSlack: committed logical size should not expose reserved slack");
    }

    std::vector<std::byte> committed_payload;
    ok &= Require(
        store.ReadCommittedFileRange(
            L"\\streaming-slack.bin",
            0,
            payload.size(),
            committed_payload),
        "StreamingGrowthSlack: committed payload should be readable");
    ok &= Require(
        committed_payload == payload,
        "StreamingGrowthSlack: committed payload should match staged streaming copy");

    return ok;
}

bool TestStreamingSlackDeleteReplayConformance(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "streaming_slack_delete_replay.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "StreamingSlackDeleteReplay: unable to create synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"StreamingSlackDeleteReplay",
    };
    context.crash_replay_mode = L"ReplayIfSafe";

    const auto payload = BuildPatternPayload(20 * 4096, 0x6D);
    bool ok = true;
    {
        apfsaccess::rw::MetadataStore store(context);
        ok &= Require(store.LoadContainerSuperblocks(), "StreamingSlackDeleteReplay: LoadContainerSuperblocks should succeed");
        ok &= Require(store.LoadObjectMap(), "StreamingSlackDeleteReplay: LoadObjectMap should succeed");
        ok &= Require(store.LoadSpacemanState(), "StreamingSlackDeleteReplay: LoadSpacemanState should succeed");
        ok &= Require(store.PrepareNativeWritePath(), "StreamingSlackDeleteReplay: PrepareNativeWritePath should succeed");

        std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
        ConfigurePayloadProvider(store, staged_payloads);

        apfsaccess::rw::MetadataStore::MutationRequest create_file{};
        create_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
        create_file.path = L"\\streaming-slack-delete.bin";
        ok &= ExpectMutationStatus(
            store,
            create_file,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "StreamingSlackDeleteReplay: create streamed file should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_file{};
        write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_file.path = L"\\streaming-slack-delete.bin";
        write_file.length = 4096;
        for (std::size_t offset = 0; offset < payload.size(); offset += 4096)
        {
            write_file.offset = offset;
            ok &= ExpectMutationStatus(
                store,
                write_file,
                apfsaccess::rw::MetadataStore::MutationStatus::Applied,
                "StreamingSlackDeleteReplay: streaming chunk should apply");
        }
        staged_payloads[L"\\streaming-slack-delete.bin"] = payload;

        ok &= Require(
            store.PendingAllocationCount() == 1,
            "StreamingSlackDeleteReplay: streamed file should have one reserved pending allocation before commit");
        ok &= ExpectCommitStatus(
            store,
            apfsaccess::rw::MetadataStore::CommitStatus::Committed,
            "StreamingSlackDeleteReplay: baseline streamed file commit should succeed");

        const auto committed_allocation_count = store.CommittedAllocationCount();
        auto committed_inode = store.LookupCommittedInodeByPath(L"\\streaming-slack-delete.bin");
        ok &= Require(committed_inode.has_value(), "StreamingSlackDeleteReplay: streamed file should exist after baseline commit");
        if (committed_inode.has_value())
        {
            ok &= Require(
                committed_inode->logical_size == payload.size(),
                "StreamingSlackDeleteReplay: committed logical size should not expose reserved slack");
        }

        apfsaccess::rw::MetadataStore::MutationRequest delete_file{};
        delete_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Delete;
        delete_file.path = L"\\streaming-slack-delete.bin";
        ok &= ExpectMutationStatus(
            store,
            delete_file,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "StreamingSlackDeleteReplay: delete should apply");
        staged_payloads.erase(L"\\streaming-slack-delete.bin");

        ok &= Require(
            store.PendingDeallocationCount() == 1,
            "StreamingSlackDeleteReplay: delete should stage one full reserved extent deallocation");

        store.SetCommitStageHook([](std::string_view stage)
        {
            return stage != "before-checkpoint-switch";
        });
        ok &= ExpectCommitStatus(
            store,
            apfsaccess::rw::MetadataStore::CommitStatus::PersistFailed,
            "StreamingSlackDeleteReplay: interrupted delete commit should fail at before-checkpoint-switch");
        ok &= Require(
            store.CommittedAllocationCount() <= committed_allocation_count,
            "StreamingSlackDeleteReplay: interrupted delete should remove the reserved allocation from committed projection");
        ok &= Require(
            store.IsRecoveryRequired(),
            "StreamingSlackDeleteReplay: interrupted delete should latch recovery-required state");
    }

    {
        apfsaccess::rw::MetadataStore remounted(context);
        ok &= Require(
            remounted.LoadContainerSuperblocks(),
            "StreamingSlackDeleteReplay: remount LoadContainerSuperblocks should succeed");
        ok &= Require(
            remounted.PrepareNativeWritePath(),
            "StreamingSlackDeleteReplay: remount PrepareNativeWritePath should succeed");
        ok &= Require(
            remounted.IsRecoveryRequired(),
            "StreamingSlackDeleteReplay: remount should require recovery before replay");
        ok &= Require(
            remounted.ReplayOrRecover(),
            "StreamingSlackDeleteReplay: remount replay should succeed for full reserved extent tombstone/deallocation");
        ok &= Require(
            !remounted.IsRecoveryRequired(),
            "StreamingSlackDeleteReplay: remount should clear recovery state after replay");
        ok &= Require(
            !remounted.LookupCommittedInodeByPath(L"\\streaming-slack-delete.bin").has_value(),
            "StreamingSlackDeleteReplay: committed view should keep streamed file deleted after replay");
    }

    return ok;
}

bool TestPendingStreamingTailDeleteReleasesReservedSlackConformance(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "pending_streaming_tail_delete.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "PendingStreamingTailDelete: unable to create synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"PendingStreamingTailDelete",
    };

    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "PendingStreamingTailDelete: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "PendingStreamingTailDelete: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "PendingStreamingTailDelete: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "PendingStreamingTailDelete: PrepareNativeWritePath should succeed");

    std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
    ConfigurePayloadProvider(store, staged_payloads);

    constexpr std::uint64_t kPayloadBytes = 77777;
    apfsaccess::rw::MetadataStore::MutationRequest create_file{};
    create_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
    create_file.path = L"\\delete-tail.bin";
    ok &= ExpectMutationStatus(
        store,
        create_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "PendingStreamingTailDelete: create file should apply");

    apfsaccess::rw::MetadataStore::MutationRequest first_write{};
    first_write.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
    first_write.path = L"\\delete-tail.bin";
    first_write.offset = 0;
    first_write.length = 65536;
    ok &= ExpectMutationStatus(
        store,
        first_write,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "PendingStreamingTailDelete: first streaming chunk should apply");

    apfsaccess::rw::MetadataStore::MutationRequest tail_write{};
    tail_write.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
    tail_write.path = L"\\delete-tail.bin";
    tail_write.offset = 65536;
    tail_write.length = kPayloadBytes - 65536;
    ok &= ExpectMutationStatus(
        store,
        tail_write,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "PendingStreamingTailDelete: tail streaming chunk should apply");
    staged_payloads[L"\\delete-tail.bin"] = BuildPatternPayload(static_cast<std::size_t>(kPayloadBytes), 0x33);

    ok &= Require(
        store.PendingAllocationCount() == 1,
        "PendingStreamingTailDelete: tail growth should keep one reserved pending allocation");

    apfsaccess::rw::MetadataStore::MutationRequest delete_file{};
    delete_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Delete;
    delete_file.path = L"\\delete-tail.bin";
    ok &= ExpectMutationStatus(
        store,
        delete_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "PendingStreamingTailDelete: delete before commit should apply");
    staged_payloads.erase(L"\\delete-tail.bin");

    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "PendingStreamingTailDelete: delete should commit without pending allocation/deallocation partial overlap");
    ok &= Require(
        !store.LookupCommittedInodeByPath(L"\\delete-tail.bin").has_value(),
        "PendingStreamingTailDelete: deleted file should not appear in committed view");

    return ok;
}

bool TestPendingPreallocationWriteBurstReusesExtentsConformance(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "pending_preallocation_reuse.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "PendingPreallocationReuse: unable to create synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"PendingPreallocationReuse",
    };

    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "PendingPreallocationReuse: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "PendingPreallocationReuse: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "PendingPreallocationReuse: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "PendingPreallocationReuse: PrepareNativeWritePath should succeed");

    const auto payload = BuildPatternPayload(64 * 4096, 0x4E);
    std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
    ConfigurePayloadProvider(store, staged_payloads);

    apfsaccess::rw::MetadataStore::MutationRequest create_file{};
    create_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
    create_file.path = L"\\burst.bin";
    ok &= ExpectMutationStatus(
        store,
        create_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "PendingPreallocationReuse: create file should apply");

    apfsaccess::rw::MetadataStore::MutationRequest set_size{};
    set_size.operation = apfsaccess::rw::MetadataStore::MutationOperation::SetFileSize;
    set_size.path = L"\\burst.bin";
    set_size.length = payload.size();
    ok &= ExpectMutationStatus(
        store,
        set_size,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "PendingPreallocationReuse: SetFileSize should preallocate the final extent");
    const auto pending_allocations_after_preallocate = store.PendingAllocationCount();
    const auto pending_btree_after_preallocate = store.PendingBtreeRecordCount();
    ok &= Require(
        store.PendingSpacemanAllocationIndexCount() == pending_allocations_after_preallocate,
        "PendingPreallocationReuse: pending allocation index should mirror preallocated extents");

    apfsaccess::rw::MetadataStore::MutationRequest write_file{};
    write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
    write_file.path = L"\\burst.bin";
    write_file.length = 4096;
    for (std::size_t offset = 0; offset < payload.size(); offset += 4096)
    {
        write_file.offset = offset;
        ok &= ExpectMutationStatus(
            store,
            write_file,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "PendingPreallocationReuse: staged write chunk should reuse pending extents");
        ok &= Require(
            store.PendingAllocationCount() == pending_allocations_after_preallocate,
            "PendingPreallocationReuse: writes inside final size should not churn pending allocations");
        ok &= Require(
            store.PendingSpacemanAllocationIndexCount() == store.PendingAllocationCount(),
            "PendingPreallocationReuse: pending allocation index should mirror reused extents");
    }

    ok &= Require(
        store.PendingBtreeRecordCount() <= pending_btree_after_preallocate + 2,
        "PendingPreallocationReuse: writes inside final size should keep pending btree metadata compact");
    staged_payloads[L"\\burst.bin"] = payload;
    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "PendingPreallocationReuse: commit should succeed");
    ok &= Require(
        store.PendingSpacemanAllocationIndexCount() == 0,
        "PendingPreallocationReuse: pending allocation index should clear after commit");

    std::vector<std::byte> committed_payload;
    ok &= Require(
        store.ReadCommittedFileRange(L"\\burst.bin", 0, payload.size(), committed_payload),
        "PendingPreallocationReuse: committed payload should be readable");
    ok &= Require(
        committed_payload == payload,
        "PendingPreallocationReuse: committed payload should match written burst");

    return ok;
}

bool TestPayloadRangeProviderAvoidsWholeFileProviderConformance(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "payload_range_provider.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "PayloadRangeProvider: unable to create synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"PayloadRangeProvider",
    };

    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "PayloadRangeProvider: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "PayloadRangeProvider: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "PayloadRangeProvider: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "PayloadRangeProvider: PrepareNativeWritePath should succeed");

    const auto payload = BuildPatternPayload(96 * 1024, 0xB2);
    bool whole_file_provider_called = false;
    std::uint64_t range_bytes_requested = 0;
    store.SetFilePayloadProvider(
        [&whole_file_provider_called](const std::wstring&, std::uint64_t) -> std::optional<std::vector<std::byte>>
        {
            whole_file_provider_called = true;
            return std::nullopt;
        });
    store.SetFilePayloadRangeProvider(
        [&payload, &range_bytes_requested](
            const std::wstring& path,
            apfsaccess::rw::MetadataStore::PayloadIdentity,
            std::uint64_t offset,
            std::span<std::byte> destination) -> bool
        {
            if (path != L"\\range.bin" ||
                offset > payload.size() ||
                destination.size() > (payload.size() - static_cast<std::size_t>(offset)))
            {
                return false;
            }

            std::copy_n(
                payload.data() + static_cast<std::ptrdiff_t>(offset),
                destination.size(),
                destination.data());
            range_bytes_requested += destination.size();
            return true;
        });

    apfsaccess::rw::MetadataStore::MutationRequest create_file{};
    create_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
    create_file.path = L"\\range.bin";
    ok &= ExpectMutationStatus(
        store,
        create_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "PayloadRangeProvider: create file should apply");

    apfsaccess::rw::MetadataStore::MutationRequest set_size{};
    set_size.operation = apfsaccess::rw::MetadataStore::MutationOperation::SetFileSize;
    set_size.path = L"\\range.bin";
    set_size.length = payload.size();
    ok &= ExpectMutationStatus(
        store,
        set_size,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "PayloadRangeProvider: SetFileSize should apply");

    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "PayloadRangeProvider: commit should succeed through range provider");
    ok &= Require(
        !whole_file_provider_called,
        "PayloadRangeProvider: whole-file payload provider should not be called when range provider is available");
    ok &= Require(
        range_bytes_requested == payload.size(),
        "PayloadRangeProvider: range provider should read exactly the committed payload bytes");

    std::vector<std::byte> committed_payload;
    ok &= Require(
        store.ReadCommittedFileRange(L"\\range.bin", 0, payload.size(), committed_payload),
        "PayloadRangeProvider: committed payload should be readable");
    ok &= Require(
        committed_payload == payload,
        "PayloadRangeProvider: committed payload should match range-provided bytes");

    return ok;
}

bool TestLargeRangePayloadUsesBoundedMaterializationConformance(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "large_range_payload_bounded.apfs.img";
    if (!CreateSyntheticContainerWithSize(image_path, 128 * 1024 * 1024))
    {
        return Require(false, "LargeRangePayloadBounded: unable to create synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"LargeRangePayloadBounded",
    };

    constexpr std::uint64_t kPayloadBytes = 72ull * 1024ull * 1024ull;
    constexpr auto kPath = L"\\large-range.bin";
    const auto payload_byte = [](std::uint64_t offset) -> std::byte
    {
        return static_cast<std::byte>((0xB5u + static_cast<unsigned int>(offset & 0xffu)) & 0xffu);
    };
    const auto expect_sample =
        [&](apfsaccess::rw::MetadataStore& store, std::uint64_t offset, std::size_t bytes, const char* label) -> bool
    {
        std::vector<std::byte> committed_payload;
        if (!Require(
                store.ReadCommittedFileRange(kPath, offset, bytes, committed_payload),
                std::string(label) + ": sample should be readable") ||
            !Require(
                committed_payload.size() == bytes,
                std::string(label) + ": sample size should match"))
        {
            return false;
        }
        for (std::size_t index = 0; index < committed_payload.size(); ++index)
        {
            if (committed_payload[index] != payload_byte(offset + static_cast<std::uint64_t>(index)))
            {
                return Require(false, std::string(label) + ": sample bytes should match range provider");
            }
        }
        return true;
    };

    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "LargeRangePayloadBounded: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "LargeRangePayloadBounded: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "LargeRangePayloadBounded: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "LargeRangePayloadBounded: PrepareNativeWritePath should succeed");

    bool whole_file_provider_called = false;
    std::uint64_t range_bytes_requested = 0;
    store.SetFilePayloadProvider(
        [&whole_file_provider_called](const std::wstring&, std::uint64_t) -> std::optional<std::vector<std::byte>>
        {
            whole_file_provider_called = true;
            return std::nullopt;
        });
    store.SetFilePayloadRangeProvider(
        [&](const std::wstring& path,
            apfsaccess::rw::MetadataStore::PayloadIdentity,
            std::uint64_t offset,
            std::span<std::byte> destination) -> bool
        {
            if (path != kPath ||
                offset > kPayloadBytes ||
                destination.size() > static_cast<std::size_t>(kPayloadBytes - offset))
            {
                return false;
            }

            for (std::size_t index = 0; index < destination.size(); ++index)
            {
                destination[index] = payload_byte(offset + static_cast<std::uint64_t>(index));
            }
            range_bytes_requested += static_cast<std::uint64_t>(destination.size());
            return true;
        });

    apfsaccess::rw::MetadataStore::MutationRequest create_file{};
    create_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
    create_file.path = kPath;
    ok &= ExpectMutationStatus(
        store,
        create_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "LargeRangePayloadBounded: create file should apply");

    apfsaccess::rw::MetadataStore::MutationRequest set_size{};
    set_size.operation = apfsaccess::rw::MetadataStore::MutationOperation::SetFileSize;
    set_size.path = kPath;
    set_size.length = kPayloadBytes;
    ok &= ExpectMutationStatus(
        store,
        set_size,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "LargeRangePayloadBounded: SetFileSize should apply");

    const auto before_json = store.PerformanceJson();
    const auto before_chunks = ExtractNestedUnsignedValue(before_json, "payloadWriteAlignment", "rangeMaterializedChunks");
    const auto before_chunk_bytes = ExtractNestedUnsignedValue(before_json, "payloadWriteAlignment", "rangeMaterializedChunkBytes");
    const auto before_buffer_resizes = ExtractNestedUnsignedValue(before_json, "payloadWriteAlignment", "rangeMaterializedBufferResizes");
    const auto before_buffer_reuses = ExtractNestedUnsignedValue(before_json, "payloadWriteAlignment", "rangeMaterializedBufferReuses");
    const auto before_windows = ExtractNestedUnsignedValue(before_json, "payloadWriteAlignment", "windowBatches");
    const auto before_window_bytes = ExtractNestedUnsignedValue(before_json, "payloadWriteAlignment", "windowBatchBytes");
    ok &= Require(
        before_chunks.has_value() &&
            before_chunk_bytes.has_value() &&
            before_buffer_resizes.has_value() &&
            before_buffer_reuses.has_value() &&
            before_windows.has_value() &&
            before_window_bytes.has_value(),
        "LargeRangePayloadBounded: payload materialization counters should exist before commit");

    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "LargeRangePayloadBounded: commit should succeed");
    ok &= Require(
        !whole_file_provider_called,
        "LargeRangePayloadBounded: commit should not use whole-file fallback");
    ok &= Require(
        range_bytes_requested == kPayloadBytes,
        "LargeRangePayloadBounded: range provider should provide exactly the payload bytes");

    const auto after_json = store.PerformanceJson();
    const auto after_chunks = ExtractNestedUnsignedValue(after_json, "payloadWriteAlignment", "rangeMaterializedChunks");
    const auto after_chunk_bytes = ExtractNestedUnsignedValue(after_json, "payloadWriteAlignment", "rangeMaterializedChunkBytes");
    const auto after_buffer_resizes = ExtractNestedUnsignedValue(after_json, "payloadWriteAlignment", "rangeMaterializedBufferResizes");
    const auto after_buffer_reuses = ExtractNestedUnsignedValue(after_json, "payloadWriteAlignment", "rangeMaterializedBufferReuses");
    const auto after_windows = ExtractNestedUnsignedValue(after_json, "payloadWriteAlignment", "windowBatches");
    const auto after_window_bytes = ExtractNestedUnsignedValue(after_json, "payloadWriteAlignment", "windowBatchBytes");
    ok &= Require(
        after_chunks.has_value() &&
            after_chunk_bytes.has_value() &&
            after_buffer_resizes.has_value() &&
            after_buffer_reuses.has_value() &&
            after_windows.has_value() &&
            after_window_bytes.has_value(),
        "LargeRangePayloadBounded: payload materialization counters should exist after commit");
    if (before_chunks.has_value() && after_chunks.has_value())
    {
        ok &= Require(
            after_chunks.value() > before_chunks.value(),
            "LargeRangePayloadBounded: commit should materialize large range payload in chunks");
    }
    if (before_chunk_bytes.has_value() && after_chunk_bytes.has_value())
    {
        ok &= Require(
            after_chunk_bytes.value() == before_chunk_bytes.value() + kPayloadBytes,
            "LargeRangePayloadBounded: chunked materialization should cover the payload exactly");
    }
    if (before_buffer_reuses.has_value() && after_buffer_reuses.has_value())
    {
        constexpr std::uint64_t kExpectedChunkBytes = 1024ull * 1024ull;
        constexpr std::uint64_t kExpectedWindowBytes = 8ull * 1024ull * 1024ull;
        constexpr std::uint64_t kExpectedChunks = kPayloadBytes / kExpectedChunkBytes;
        constexpr std::uint64_t kExpectedWindowChunks = kExpectedWindowBytes / kExpectedChunkBytes;
        ok &= Require(
            after_buffer_reuses.value() >= before_buffer_reuses.value() + (kExpectedChunks - kExpectedWindowChunks),
            "LargeRangePayloadBounded: bounded materialization should reuse chunk buffers after the first window");
    }
    if (before_buffer_resizes.has_value() && after_buffer_resizes.has_value())
    {
        constexpr std::uint64_t kExpectedWindowChunks = 8;
        ok &= Require(
            after_buffer_resizes.value() <= before_buffer_resizes.value() + kExpectedWindowChunks,
            "LargeRangePayloadBounded: bounded materialization should resize only the reusable window buffers");
    }
    if (before_windows.has_value() && after_windows.has_value())
    {
        ok &= Require(
            after_windows.value() > before_windows.value(),
            "LargeRangePayloadBounded: commit should write chunked payload windows");
    }
    if (before_window_bytes.has_value() && after_window_bytes.has_value())
    {
        ok &= Require(
            after_window_bytes.value() == before_window_bytes.value() + kPayloadBytes,
            "LargeRangePayloadBounded: window batches should cover the payload exactly");
    }

    ok &= expect_sample(store, 0, 4096, "LargeRangePayloadBounded: start");
    ok &= expect_sample(store, (kPayloadBytes / 2) - 2048, 4096, "LargeRangePayloadBounded: middle");
    ok &= expect_sample(store, kPayloadBytes - 4096, 4096, "LargeRangePayloadBounded: tail");

    {
        apfsaccess::rw::MetadataStore remounted(context);
        ok &= Require(
            remounted.LoadContainerSuperblocks(),
            "LargeRangePayloadBounded: remount LoadContainerSuperblocks should succeed");
        ok &= Require(
            remounted.PrepareNativeWritePath(),
            "LargeRangePayloadBounded: remount PrepareNativeWritePath should succeed");
        ok &= expect_sample(remounted, 0, 4096, "LargeRangePayloadBounded: remounted start");
        ok &= expect_sample(remounted, kPayloadBytes - 4096, 4096, "LargeRangePayloadBounded: remounted tail");
    }

    return ok;
}

bool TestPreallocatedPartialWriteCommitRequestsOnlyWrittenRangesConformance(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "preallocated_partial_write_ranges.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "PreallocatedPartialWriteRanges: unable to create synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"PreallocatedPartialWriteRanges",
    };

    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "PreallocatedPartialWriteRanges: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "PreallocatedPartialWriteRanges: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "PreallocatedPartialWriteRanges: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "PreallocatedPartialWriteRanges: PrepareNativeWritePath should succeed");

    constexpr std::uint64_t logical_size = 256ull * 1024ull;
    constexpr std::uint64_t first_offset = 0;
    constexpr std::uint64_t tail_offset = logical_size - (16ull * 1024ull);
    const auto first_payload = BuildPatternPayload(32 * 1024, 0x21);
    const auto tail_payload = BuildPatternPayload(16 * 1024, 0xA8);

    bool whole_file_provider_called = false;
    std::uint64_t range_bytes_requested = 0;
    std::vector<std::pair<std::uint64_t, std::size_t>> requested_ranges;
    store.SetFilePayloadProvider(
        [&whole_file_provider_called](const std::wstring&, std::uint64_t) -> std::optional<std::vector<std::byte>>
        {
            whole_file_provider_called = true;
            return std::nullopt;
        });
    store.SetFilePayloadRangeProvider(
        [&](
            const std::wstring& path,
            apfsaccess::rw::MetadataStore::PayloadIdentity,
            std::uint64_t offset,
            std::span<std::byte> destination) -> bool
        {
            if (path != L"\\partial-preallocated.bin")
            {
                return false;
            }

            requested_ranges.push_back({ offset, destination.size() });
            range_bytes_requested += destination.size();
            if (offset == first_offset && destination.size() == first_payload.size())
            {
                std::copy(first_payload.begin(), first_payload.end(), destination.begin());
                return true;
            }
            if (offset == tail_offset && destination.size() == tail_payload.size())
            {
                std::copy(tail_payload.begin(), tail_payload.end(), destination.begin());
                return true;
            }
            return false;
        });

    apfsaccess::rw::MetadataStore::MutationRequest create_file{};
    create_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
    create_file.path = L"\\partial-preallocated.bin";
    ok &= ExpectMutationStatus(
        store,
        create_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "PreallocatedPartialWriteRanges: create file should apply");

    apfsaccess::rw::MetadataStore::MutationRequest set_size{};
    set_size.operation = apfsaccess::rw::MetadataStore::MutationOperation::SetFileSize;
    set_size.path = L"\\partial-preallocated.bin";
    set_size.length = logical_size;
    ok &= ExpectMutationStatus(
        store,
        set_size,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "PreallocatedPartialWriteRanges: SetFileSize should preallocate final size");
    apfsaccess::rw::MetadataStore::MutationRequest write_first{};
    write_first.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
    write_first.path = L"\\partial-preallocated.bin";
    write_first.offset = first_offset;
    write_first.length = first_payload.size();
    ok &= ExpectMutationStatus(
        store,
        write_first,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "PreallocatedPartialWriteRanges: first written range should apply");
    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "PreallocatedPartialWriteRanges: first payload commit should succeed before the later payload write");
    ok &= Require(
        range_bytes_requested == first_payload.size(),
        "PreallocatedPartialWriteRanges: first commit should request only the first written range");
    requested_ranges.clear();
    range_bytes_requested = 0;

    apfsaccess::rw::MetadataStore::MutationRequest write_tail{};
    write_tail.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
    write_tail.path = L"\\partial-preallocated.bin";
    write_tail.offset = tail_offset;
    write_tail.length = tail_payload.size();
    ok &= ExpectMutationStatus(
        store,
        write_tail,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "PreallocatedPartialWriteRanges: tail written range should apply");

    const auto before_json = store.PerformanceJson();
    const auto before_ordered_fast_paths =
        ExtractNestedUnsignedValue(before_json, "payloadWriteAlignment", "orderedFastPaths");
    const auto before_sorts =
        ExtractNestedUnsignedValue(before_json, "payloadWriteAlignment", "sorts");
    const auto before_reserve_extra_passes =
        ExtractNestedUnsignedValue(before_json, "payloadWriteAlignment", "writeViewReserveExtraPasses");
    const auto before_reserve_extra_entries =
        ExtractNestedUnsignedValue(before_json, "payloadWriteAlignment", "writeViewReserveExtraEntries");
    ok &= Require(
        before_ordered_fast_paths.has_value() &&
            before_sorts.has_value() &&
            before_reserve_extra_passes.has_value() &&
            before_reserve_extra_entries.has_value(),
        "PreallocatedPartialWriteRanges: payload write order counters should exist before commit");

    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "PreallocatedPartialWriteRanges: commit should not require unwritten preallocation gaps");
    ok &= Require(
        !whole_file_provider_called,
        "PreallocatedPartialWriteRanges: commit should not use whole-file fallback");
    ok &= Require(
        range_bytes_requested == tail_payload.size(),
        "PreallocatedPartialWriteRanges: later commit should request only the later written bytes");
    ok &= Require(
        requested_ranges.size() == 1 &&
            requested_ranges.front().first == tail_offset &&
            requested_ranges.front().second == tail_payload.size(),
        "PreallocatedPartialWriteRanges: later commit should request exactly the later written range");

    const auto after_json = store.PerformanceJson();
    const auto after_ordered_fast_paths =
        ExtractNestedUnsignedValue(after_json, "payloadWriteAlignment", "orderedFastPaths");
    const auto after_sorts =
        ExtractNestedUnsignedValue(after_json, "payloadWriteAlignment", "sorts");
    const auto after_reserve_extra_passes =
        ExtractNestedUnsignedValue(after_json, "payloadWriteAlignment", "writeViewReserveExtraPasses");
    const auto after_reserve_extra_entries =
        ExtractNestedUnsignedValue(after_json, "payloadWriteAlignment", "writeViewReserveExtraEntries");
    ok &= Require(
        after_ordered_fast_paths.has_value() &&
            after_sorts.has_value() &&
            after_reserve_extra_passes.has_value() &&
            after_reserve_extra_entries.has_value(),
        "PreallocatedPartialWriteRanges: payload write order counters should exist after commit");
    if (before_ordered_fast_paths.has_value() && after_ordered_fast_paths.has_value())
    {
        ok &= Require(
            after_ordered_fast_paths.value() == before_ordered_fast_paths.value() + 1,
            "PreallocatedPartialWriteRanges: ordered payload writes should skip the sort path");
    }
    if (before_sorts.has_value() && after_sorts.has_value())
    {
        ok &= Require(
            after_sorts.value() == before_sorts.value(),
            "PreallocatedPartialWriteRanges: already ordered payload writes should not be sorted");
    }
    if (before_reserve_extra_passes.has_value() && after_reserve_extra_passes.has_value())
    {
        ok &= Require(
            after_reserve_extra_passes.value() == before_reserve_extra_passes.value() + 1,
            "PreallocatedPartialWriteRanges: sparse written ranges should reserve extra payload write views");
    }
    if (before_reserve_extra_entries.has_value() && after_reserve_extra_entries.has_value())
    {
        ok &= Require(
            after_reserve_extra_entries.value() >= before_reserve_extra_entries.value() + 1,
            "PreallocatedPartialWriteRanges: reserve estimate should account for both written ranges");
    }

    std::vector<std::byte> committed_payload;
    ok &= Require(
        store.ReadCommittedFileRange(L"\\partial-preallocated.bin", 0, logical_size, committed_payload),
        "PreallocatedPartialWriteRanges: committed file should be readable");
    ok &= Require(
        committed_payload.size() == static_cast<std::size_t>(logical_size),
        "PreallocatedPartialWriteRanges: committed file should keep logical size");
    if (committed_payload.size() == static_cast<std::size_t>(logical_size))
    {
        ok &= Require(
            std::equal(first_payload.begin(), first_payload.end(), committed_payload.begin()),
            "PreallocatedPartialWriteRanges: first range should match");
        ok &= Require(
            std::equal(tail_payload.begin(), tail_payload.end(), committed_payload.begin() + static_cast<std::ptrdiff_t>(tail_offset)),
            "PreallocatedPartialWriteRanges: tail range should match");
        ok &= Require(
            std::all_of(
                committed_payload.begin() + static_cast<std::ptrdiff_t>(first_payload.size()),
                committed_payload.begin() + static_cast<std::ptrdiff_t>(tail_offset),
                [](std::byte value) { return value == std::byte{0}; }),
            "PreallocatedPartialWriteRanges: unwritten gap should read as zeros");
    }

    return ok;
}

bool TestOutOfOrderPendingWrittenRangesMergeConformance(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "out_of_order_pending_ranges.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "OutOfOrderPendingRanges: unable to create synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"OutOfOrderPendingRanges",
    };

    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "OutOfOrderPendingRanges: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "OutOfOrderPendingRanges: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "OutOfOrderPendingRanges: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "OutOfOrderPendingRanges: PrepareNativeWritePath should succeed");

    constexpr std::uint64_t logical_size = 16ull * 1024ull;
    constexpr std::uint64_t requested_payload_bytes = 12ull * 1024ull;
    const auto payload = BuildPatternPayload(static_cast<std::size_t>(requested_payload_bytes), 0x52);
    bool whole_file_provider_called = false;
    std::vector<std::pair<std::uint64_t, std::size_t>> requested_ranges;
    store.SetFilePayloadProvider(
        [&whole_file_provider_called](const std::wstring&, std::uint64_t) -> std::optional<std::vector<std::byte>>
        {
            whole_file_provider_called = true;
            return std::nullopt;
        });
    store.SetFilePayloadRangeProvider(
        [&](const std::wstring& path,
            apfsaccess::rw::MetadataStore::PayloadIdentity,
            std::uint64_t offset,
            std::span<std::byte> destination) -> bool
        {
            if (path != L"\\out-of-order.bin" ||
                offset > static_cast<std::uint64_t>(payload.size()) ||
                destination.size() > (payload.size() - static_cast<std::size_t>(offset)))
            {
                return false;
            }

            requested_ranges.push_back({ offset, destination.size() });
            std::copy(
                payload.begin() + static_cast<std::ptrdiff_t>(offset),
                payload.begin() + static_cast<std::ptrdiff_t>(offset + destination.size()),
                destination.begin());
            return true;
        });

    apfsaccess::rw::MetadataStore::MutationRequest create_file{};
    create_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
    create_file.path = L"\\out-of-order.bin";
    ok &= ExpectMutationStatus(
        store,
        create_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "OutOfOrderPendingRanges: create file should apply");

    apfsaccess::rw::MetadataStore::MutationRequest set_size{};
    set_size.operation = apfsaccess::rw::MetadataStore::MutationOperation::SetFileSize;
    set_size.path = create_file.path;
    set_size.length = logical_size;
    ok &= ExpectMutationStatus(
        store,
        set_size,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "OutOfOrderPendingRanges: SetFileSize should preallocate final size");

    const auto local_range_merges_before = store.PendingPayloadRangeLocalMergeCount();
    const auto full_range_merges_before = store.PendingPayloadRangeFullMergeCount();

    apfsaccess::rw::MetadataStore::MutationRequest write_tail{};
    write_tail.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
    write_tail.path = create_file.path;
    write_tail.offset = 8ull * 1024ull;
    write_tail.length = 4ull * 1024ull;
    ok &= ExpectMutationStatus(
        store,
        write_tail,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "OutOfOrderPendingRanges: tail write should apply first");
    ok &= Require(
        store.PendingPayloadDirtyByteEstimate() == write_tail.length,
        "OutOfOrderPendingRanges: dirty estimate should include the first written range");

    apfsaccess::rw::MetadataStore::MutationRequest write_head{};
    write_head.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
    write_head.path = create_file.path;
    write_head.offset = 0;
    write_head.length = 4ull * 1024ull;
    ok &= ExpectMutationStatus(
        store,
        write_head,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "OutOfOrderPendingRanges: head write should apply second");
    ok &= Require(
        store.PendingPayloadDirtyByteEstimate() == write_head.length + write_tail.length,
        "OutOfOrderPendingRanges: dirty estimate should sum disjoint written ranges");

    apfsaccess::rw::MetadataStore::MutationRequest write_bridge{};
    write_bridge.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
    write_bridge.path = create_file.path;
    write_bridge.offset = 4ull * 1024ull;
    write_bridge.length = 8ull * 1024ull;
    ok &= ExpectMutationStatus(
        store,
        write_bridge,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "OutOfOrderPendingRanges: bridge write should merge pending ranges");
    ok &= Require(
        store.PendingPayloadDirtyByteEstimate() == requested_payload_bytes,
        "OutOfOrderPendingRanges: dirty estimate should count merged coverage once");

    ok &= Require(
        store.PendingPayloadRangeLocalMergeCount() >= local_range_merges_before + 3,
        "OutOfOrderPendingRanges: out-of-order dirty ranges should use local range merge");
    ok &= Require(
        store.PendingPayloadRangeFullMergeCount() == full_range_merges_before,
        "OutOfOrderPendingRanges: out-of-order dirty ranges should not require full range rebuild");

    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "OutOfOrderPendingRanges: commit should succeed");
    ok &= Require(
        store.PendingPayloadDirtyByteEstimate() == 0,
        "OutOfOrderPendingRanges: commit should clear the dirty estimate");
    ok &= Require(
        !whole_file_provider_called,
        "OutOfOrderPendingRanges: commit should not fall back to the whole-file provider");
    ok &= Require(
        requested_ranges.size() == 1 &&
            requested_ranges[0].first == 0 &&
            requested_ranges[0].second == static_cast<std::size_t>(requested_payload_bytes),
        "OutOfOrderPendingRanges: commit should request one merged written range");

    std::vector<std::byte> committed_payload;
    ok &= Require(
        store.ReadCommittedFileRange(L"\\out-of-order.bin", 0, logical_size, committed_payload),
        "OutOfOrderPendingRanges: committed file should be readable");
    if (committed_payload.size() == static_cast<std::size_t>(logical_size))
    {
        ok &= Require(
            std::equal(payload.begin(), payload.end(), committed_payload.begin()),
            "OutOfOrderPendingRanges: merged written bytes should match");
        ok &= Require(
            std::all_of(
                committed_payload.begin() + static_cast<std::ptrdiff_t>(requested_payload_bytes),
                committed_payload.end(),
                [](std::byte value) { return value == std::byte{0}; }),
            "OutOfOrderPendingRanges: unwritten tail should read as zeros");
    }

    return ok;
}

bool TestAdjacentSplitExtentsUseOnePayloadRangeProviderReadConformance(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "adjacent_split_extent_payload_read.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "AdjacentSplitExtentPayloadRead: unable to create synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"AdjacentSplitExtentPayloadRead",
    };

    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "AdjacentSplitExtentPayloadRead: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "AdjacentSplitExtentPayloadRead: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "AdjacentSplitExtentPayloadRead: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "AdjacentSplitExtentPayloadRead: PrepareNativeWritePath should succeed");

    std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
    ConfigurePayloadProvider(store, staged_payloads);

    constexpr std::uint64_t logical_size = 12ull * 1024ull;
    const auto original_payload = BuildPatternPayload(static_cast<std::size_t>(logical_size), 0x34);
    staged_payloads[L"\\split-adjacent.bin"] = original_payload;

    apfsaccess::rw::MetadataStore::MutationRequest create_file{};
    create_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
    create_file.path = L"\\split-adjacent.bin";
    ok &= ExpectMutationStatus(
        store,
        create_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "AdjacentSplitExtentPayloadRead: create file should apply");

    apfsaccess::rw::MetadataStore::MutationRequest write_file{};
    write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
    write_file.path = create_file.path;
    write_file.length = logical_size;
    ok &= ExpectMutationStatus(
        store,
        write_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "AdjacentSplitExtentPayloadRead: initial write should apply");
    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "AdjacentSplitExtentPayloadRead: initial commit should succeed");

    const auto inode = store.LookupCommittedInodeByPath(L"\\split-adjacent.bin");
    ok &= Require(
        inode.has_value(),
        "AdjacentSplitExtentPayloadRead: committed inode should exist");
    if (!inode.has_value())
    {
        return false;
    }

    ok &= Require(
        store.SetCommittedReadExtents(
            inode->object_id,
            {
                { 0, inode->data_physical_address, 4096 },
                { 4096, inode->data_physical_address + 4096, 4096 },
                { 8192, inode->data_physical_address + 8192, 4096 },
            }),
        "AdjacentSplitExtentPayloadRead: adjacent split read extents should be installed");

    const auto rewritten_payload = BuildPatternPayload(static_cast<std::size_t>(logical_size), 0x7D);
    bool whole_file_provider_called = false;
    std::vector<std::pair<std::uint64_t, std::size_t>> requested_ranges;
    store.SetFilePayloadProvider(
        [&whole_file_provider_called](const std::wstring&, std::uint64_t) -> std::optional<std::vector<std::byte>>
        {
            whole_file_provider_called = true;
            return std::nullopt;
        });
    store.SetFilePayloadRangeProvider(
        [&](const std::wstring& path,
            apfsaccess::rw::MetadataStore::PayloadIdentity identity,
            std::uint64_t offset,
            std::span<std::byte> destination) -> bool
        {
            if (path != L"\\split-adjacent.bin" ||
                identity.object_id != inode->object_id ||
                offset > static_cast<std::uint64_t>(rewritten_payload.size()) ||
                destination.size() > (rewritten_payload.size() - static_cast<std::size_t>(offset)))
            {
                return false;
            }

            requested_ranges.push_back({ offset, destination.size() });
            std::copy(
                rewritten_payload.begin() + static_cast<std::ptrdiff_t>(offset),
                rewritten_payload.begin() + static_cast<std::ptrdiff_t>(offset + destination.size()),
                destination.begin());
            return true;
        });

    write_file.offset = 0;
    write_file.length = logical_size;
    ok &= ExpectMutationStatus(
        store,
        write_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "AdjacentSplitExtentPayloadRead: rewrite should apply");
    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "AdjacentSplitExtentPayloadRead: rewrite commit should succeed");
    ok &= Require(
        !whole_file_provider_called,
        "AdjacentSplitExtentPayloadRead: commit should not fall back to whole-file provider");
    ok &= Require(
        requested_ranges.size() == 1 &&
            requested_ranges[0].first == 0 &&
            requested_ranges[0].second == static_cast<std::size_t>(logical_size),
        "AdjacentSplitExtentPayloadRead: adjacent split extents should use one materialization read");

    std::vector<std::byte> committed_payload;
    ok &= Require(
        store.ReadCommittedFileRange(L"\\split-adjacent.bin", 0, static_cast<std::size_t>(logical_size), committed_payload),
        "AdjacentSplitExtentPayloadRead: committed payload should be readable");
    ok &= Require(
        committed_payload == rewritten_payload,
        "AdjacentSplitExtentPayloadRead: committed payload should match rewritten bytes");

    return ok;
}

bool TestExistingFileRewriteMaterializesCommittedBytesConformance(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "existing_rewrite_materializes_committed.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "ExistingRewriteMaterializes: unable to create synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"ExistingRewriteMaterializes",
    };

    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "ExistingRewriteMaterializes: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "ExistingRewriteMaterializes: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "ExistingRewriteMaterializes: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "ExistingRewriteMaterializes: PrepareNativeWritePath should succeed");

    std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
    ConfigurePayloadProvider(store, staged_payloads);

    const auto initial_payload = BuildPatternPayload(64 * 1024, 0x34);
    staged_payloads[L"\\rewrite.bin"] = initial_payload;

    apfsaccess::rw::MetadataStore::MutationRequest create_file{};
    create_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
    create_file.path = L"\\rewrite.bin";
    ok &= ExpectMutationStatus(
        store,
        create_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "ExistingRewriteMaterializes: create file should apply");

    apfsaccess::rw::MetadataStore::MutationRequest set_size{};
    set_size.operation = apfsaccess::rw::MetadataStore::MutationOperation::SetFileSize;
    set_size.path = L"\\rewrite.bin";
    set_size.length = initial_payload.size();
    ok &= ExpectMutationStatus(
        store,
        set_size,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "ExistingRewriteMaterializes: initial size should apply");

    apfsaccess::rw::MetadataStore::MutationRequest write_initial{};
    write_initial.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
    write_initial.path = L"\\rewrite.bin";
    write_initial.offset = 0;
    write_initial.length = initial_payload.size();
    ok &= ExpectMutationStatus(
        store,
        write_initial,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "ExistingRewriteMaterializes: initial write should apply");
    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "ExistingRewriteMaterializes: initial commit should succeed");

    auto final_payload = initial_payload;
    final_payload.resize(96 * 1024, std::byte{0});
    const auto rewritten_tail = BuildPatternPayload(16 * 1024, 0x91);
    const auto tail_offset = static_cast<std::uint64_t>(80 * 1024);
    std::copy(
        rewritten_tail.begin(),
        rewritten_tail.end(),
        final_payload.begin() + static_cast<std::ptrdiff_t>(tail_offset));
    staged_payloads[L"\\rewrite.bin"] = final_payload;

    apfsaccess::rw::MetadataStore::MutationRequest write_tail{};
    write_tail.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
    write_tail.path = L"\\rewrite.bin";
    write_tail.offset = tail_offset;
    write_tail.length = rewritten_tail.size();
    ok &= ExpectMutationStatus(
        store,
        write_tail,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "ExistingRewriteMaterializes: tail rewrite should apply");

    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "ExistingRewriteMaterializes: rewrite commit should succeed");

    std::vector<std::byte> committed_payload;
    ok &= Require(
        store.ReadCommittedFileRange(L"\\rewrite.bin", 0, final_payload.size(), committed_payload),
        "ExistingRewriteMaterializes: committed rewrite should be readable");
    ok &= Require(
        committed_payload == final_payload,
        "ExistingRewriteMaterializes: committed rewrite should preserve old bytes and new tail");

    return ok;
}

bool TestCommittedInBodyOverwriteUsesWrittenRangeOnlyConformance(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "committed_in_body_overwrite_written_range.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "CommittedInBodyOverwriteRange: unable to create synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"CommittedInBodyOverwriteRange",
    };

    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "CommittedInBodyOverwriteRange: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "CommittedInBodyOverwriteRange: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "CommittedInBodyOverwriteRange: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "CommittedInBodyOverwriteRange: PrepareNativeWritePath should succeed");

    constexpr std::uint64_t kBlockBytes = 4096;
    constexpr std::uint64_t kLogicalSize = 4 * kBlockBytes;
    constexpr std::uint64_t kRewriteOffset = kBlockBytes;
    constexpr std::uint64_t kRewriteBytes = kBlockBytes;
    constexpr auto kPath = L"\\committed-in-body.bin";

    const auto baseline_payload = BuildPatternPayload(static_cast<std::size_t>(kLogicalSize), 0x2C);
    auto final_payload = baseline_payload;
    const auto rewritten_payload = BuildPatternPayload(static_cast<std::size_t>(kRewriteBytes), 0xD7);
    std::copy(
        rewritten_payload.begin(),
        rewritten_payload.end(),
        final_payload.begin() + static_cast<std::ptrdiff_t>(kRewriteOffset));

    bool restrict_to_rewrite = false;
    std::vector<std::pair<std::uint64_t, std::size_t>> requested_ranges;
    store.SetFilePayloadRangeProvider(
        [&](const std::wstring& path,
            apfsaccess::rw::MetadataStore::PayloadIdentity,
            std::uint64_t offset,
            std::span<std::byte> destination) -> bool
        {
            if (path != kPath ||
                offset > final_payload.size() ||
                destination.size() > (final_payload.size() - static_cast<std::size_t>(offset)))
            {
                return false;
            }

            const auto requested_end = offset + static_cast<std::uint64_t>(destination.size());
            if (restrict_to_rewrite &&
                (offset < kRewriteOffset ||
                 requested_end > (kRewriteOffset + kRewriteBytes)))
            {
                return false;
            }

            requested_ranges.emplace_back(offset, destination.size());
            std::copy_n(
                final_payload.data() + static_cast<std::ptrdiff_t>(offset),
                destination.size(),
                destination.data());
            return true;
        });

    apfsaccess::rw::MetadataStore::MutationRequest create_file{};
    create_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
    create_file.path = kPath;
    ok &= ExpectMutationStatus(
        store,
        create_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "CommittedInBodyOverwriteRange: create file should apply");

    apfsaccess::rw::MetadataStore::MutationRequest set_size{};
    set_size.operation = apfsaccess::rw::MetadataStore::MutationOperation::SetFileSize;
    set_size.path = kPath;
    set_size.length = kLogicalSize;
    ok &= ExpectMutationStatus(
        store,
        set_size,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "CommittedInBodyOverwriteRange: pre-sized file should apply");

    apfsaccess::rw::MetadataStore::MutationRequest initial_write{};
    initial_write.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
    initial_write.path = kPath;
    initial_write.offset = 0;
    initial_write.length = kLogicalSize;
    ok &= ExpectMutationStatus(
        store,
        initial_write,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "CommittedInBodyOverwriteRange: initial write should apply");
    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "CommittedInBodyOverwriteRange: initial commit should succeed");

    requested_ranges.clear();
    restrict_to_rewrite = true;
    apfsaccess::rw::MetadataStore::MutationRequest rewrite{};
    rewrite.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
    rewrite.path = kPath;
    rewrite.offset = kRewriteOffset;
    rewrite.length = kRewriteBytes;
    ok &= ExpectMutationStatus(
        store,
        rewrite,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "CommittedInBodyOverwriteRange: committed in-body overwrite should apply");
    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "CommittedInBodyOverwriteRange: committed in-body overwrite should not materialize old ranges");
    ok &= Require(
        !requested_ranges.empty(),
        "CommittedInBodyOverwriteRange: overwrite commit should request the dirty range");
    for (const auto& [offset, bytes] : requested_ranges)
    {
        const auto end = offset + static_cast<std::uint64_t>(bytes);
        ok &= Require(
            offset >= kRewriteOffset && end <= (kRewriteOffset + kRewriteBytes),
            "CommittedInBodyOverwriteRange: overwrite commit requested an old committed range");
    }

    std::vector<std::byte> committed_payload;
    ok &= Require(
        store.ReadCommittedFileRange(kPath, 0, baseline_payload.size(), committed_payload),
        "CommittedInBodyOverwriteRange: final file should be readable");
    ok &= Require(
        committed_payload == final_payload,
        "CommittedInBodyOverwriteRange: final file should preserve untouched committed bytes");

    return ok;
}

bool TestDisjointPartialOverwritesPreserveCommittedBytesOnInterruptedCommitConformance(
    const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "disjoint_partial_overwrite_interrupted_commit.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "DisjointPartialOverwriteCOW: unable to create synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"DisjointPartialOverwriteCOW",
    };
    context.crash_replay_mode = L"ReplayIfSafe";

    bool ok = true;
    std::uint64_t baseline_object_id = 0;
    std::uint64_t baseline_physical_address = 0;
    std::uint64_t other_inode_physical_address = 0;
    std::size_t expected_committed_allocation_count = 0;
    std::size_t expected_committed_free_extent_count = 0;
    std::optional<std::uint64_t> expected_free_size;

    constexpr std::size_t kBlockBytes = 4096;
    constexpr std::size_t kLogicalBytes = 3 * kBlockBytes;
    constexpr auto kPath = L"\\disjoint-partial-overwrite.bin";
    const auto baseline_payload = BuildPatternPayload(kLogicalBytes, 0x31);
    auto final_payload = baseline_payload;
    {
        apfsaccess::rw::MetadataStore store(context);
        ok &= Require(store.LoadContainerSuperblocks(), "DisjointPartialOverwriteCOW: LoadContainerSuperblocks should succeed");
        ok &= Require(store.LoadObjectMap(), "DisjointPartialOverwriteCOW: LoadObjectMap should succeed");
        ok &= Require(store.LoadSpacemanState(), "DisjointPartialOverwriteCOW: LoadSpacemanState should succeed");
        ok &= Require(store.PrepareNativeWritePath(), "DisjointPartialOverwriteCOW: PrepareNativeWritePath should succeed");

        std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
        ConfigurePayloadProvider(store, staged_payloads);

        ok &= CreateAndCommitFile(
            store,
            staged_payloads,
            L"\\other-owner.bin",
            kBlockBytes,
            0x19,
            "DisjointPartialOverwriteCOW/other-owner");
        const auto other_inode = store.LookupCommittedInodeByPath(L"\\other-owner.bin");
        ok &= Require(
            other_inode.has_value() && other_inode->data_physical_address != 0,
            "DisjointPartialOverwriteCOW: other inode should expose committed storage");
        if (other_inode.has_value())
        {
            other_inode_physical_address = other_inode->data_physical_address;
        }

        apfsaccess::rw::MetadataStore::MutationRequest create_file{};
        create_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
        create_file.path = kPath;
        ok &= ExpectMutationStatus(
            store,
            create_file,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "DisjointPartialOverwriteCOW: create file should apply");

        apfsaccess::rw::MetadataStore::MutationRequest initial_write{};
        initial_write.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        initial_write.path = kPath;
        initial_write.length = kLogicalBytes;
        staged_payloads[kPath] = baseline_payload;
        ok &= ExpectMutationStatus(
            store,
            initial_write,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "DisjointPartialOverwriteCOW: initial write should apply");
        ok &= ExpectCommitStatus(
            store,
            apfsaccess::rw::MetadataStore::CommitStatus::Committed,
            "DisjointPartialOverwriteCOW: baseline commit should succeed");

        const auto baseline_inode = store.LookupCommittedInodeByPath(kPath);
        ok &= Require(
            baseline_inode.has_value() && baseline_inode->data_physical_address != 0,
            "DisjointPartialOverwriteCOW: baseline inode should expose committed storage");
        if (baseline_inode.has_value())
        {
            baseline_object_id = baseline_inode->object_id;
            baseline_physical_address = baseline_inode->data_physical_address;
        }

        const auto pending_allocations_before_overwrites = store.PendingAllocationCount();
        const auto pending_deallocations_before_overwrites = store.PendingDeallocationCount();
        const auto middle_replacement = BuildPatternPayload(kBlockBytes, 0xA4);
        std::copy(
            middle_replacement.begin(),
            middle_replacement.end(),
            final_payload.begin() + static_cast<std::ptrdiff_t>(kBlockBytes));
        apfsaccess::rw::MetadataStore::MutationRequest overwrite_middle{};
        overwrite_middle.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        overwrite_middle.path = kPath;
        overwrite_middle.offset = kBlockBytes;
        overwrite_middle.length = kBlockBytes;
        ok &= ExpectMutationStatus(
            store,
            overwrite_middle,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "DisjointPartialOverwriteCOW: middle overwrite should apply");
        ok &= Require(
            store.PendingAllocationCount() == pending_allocations_before_overwrites + 1 &&
                store.PendingDeallocationCount() == pending_deallocations_before_overwrites + 1,
            "DisjointPartialOverwriteCOW: first committed slice should add exactly one allocation and deallocation");

        const auto first_replacement = BuildPatternPayload(kBlockBytes, 0xD2);
        std::copy(first_replacement.begin(), first_replacement.end(), final_payload.begin());
        apfsaccess::rw::MetadataStore::MutationRequest overwrite_first{};
        overwrite_first.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        overwrite_first.path = kPath;
        overwrite_first.offset = 0;
        overwrite_first.length = kBlockBytes;
        ok &= ExpectMutationStatus(
            store,
            overwrite_first,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "DisjointPartialOverwriteCOW: first overwrite should apply");
        ok &= Require(
            store.PendingAllocationCount() == pending_allocations_before_overwrites + 2 &&
                store.PendingDeallocationCount() == pending_deallocations_before_overwrites + 2,
            "DisjointPartialOverwriteCOW: retained pending replacement should not add an extra deallocation");
        staged_payloads[kPath] = final_payload;

        store.SetCommitStageHook([](std::string_view stage)
        {
            return stage != "before-checkpoint-switch";
        });
        ok &= ExpectCommitStatus(
            store,
            apfsaccess::rw::MetadataStore::CommitStatus::PersistFailed,
            "DisjointPartialOverwriteCOW: commit should stop before checkpoint publication");
        ok &= Require(
            store.PendingDeallocationCount() == pending_deallocations_before_overwrites + 2,
            "DisjointPartialOverwriteCOW: interrupted commit should retain exactly the two replaced-slice deallocations");

        expected_committed_allocation_count = store.CommittedAllocationCount();
        expected_committed_free_extent_count = store.CommittedFreeExtentCount();
        expected_free_size = store.FreeSizeBytes();

        std::vector<std::byte> committed_baseline;
        ok &= Require(
            baseline_physical_address != 0 &&
                ReadBytesFromImage(image_path, baseline_physical_address, kLogicalBytes, committed_baseline),
            "DisjointPartialOverwriteCOW: old committed payload should remain readable");
        ok &= Require(
            committed_baseline == baseline_payload,
            "DisjointPartialOverwriteCOW: interrupted commit must not modify old committed bytes");
    }

    const auto valid_interrupted_image = run_root / "disjoint_partial_overwrite_interrupted_commit.valid.apfs.img";
    std::error_code copy_ec;
    std::filesystem::copy_file(
        image_path,
        valid_interrupted_image,
        std::filesystem::copy_options::overwrite_existing,
        copy_ec);
    ok &= Require(
        !copy_ec,
        "DisjointPartialOverwriteCOW: interrupted image backup should succeed");
    const auto expect_malformed_replay_rejected = [&]
        (std::uint64_t malformed_physical_address,
         const std::wstring& expected_reason,
         std::string_view expected_stage,
         const std::string& label)
    {
        std::error_code restore_ec;
        std::filesystem::copy_file(
            valid_interrupted_image,
            image_path,
            std::filesystem::copy_options::overwrite_existing,
            restore_ec);
        bool malformed_ok = Require(!restore_ec, label + ": valid interrupted image restore should succeed");
        malformed_ok &= Require(
            baseline_object_id != 0 &&
                CorruptHighestCommitBlobNonAnchorExtentWithValidChecksum(
                    image_path,
                    baseline_object_id,
                    malformed_physical_address),
            label + ": malformed split extent fixture should preserve commit-blob checksum");

        apfsaccess::rw::MetadataStore malformed(context);
        malformed_ok &= Require(
            malformed.LoadContainerSuperblocks(),
            label + ": malformed remount LoadContainerSuperblocks should succeed");
        malformed_ok &= Require(
            malformed.PrepareNativeWritePath(),
            label + ": malformed remount PrepareNativeWritePath should succeed");
        malformed_ok &= Require(
            malformed.IsRecoveryRequired(),
            label + ": malformed remount should require recovery");
        malformed_ok &= Require(
            !malformed.ReplayOrRecover(),
            label + ": replay must reject malformed fragmented extent ownership");
        if (malformed.RecoveryReason() != expected_reason ||
            malformed.LastReplayStage() != expected_stage)
        {
            std::wcerr << L"[DEBUG] " << std::wstring(label.begin(), label.end())
                       << L" replay reason: " << malformed.RecoveryReason() << std::endl;
            std::cerr << "[DEBUG] " << label
                      << " replay stage: " << malformed.LastReplayStage() << std::endl;
        }
        malformed_ok &= Require(
            malformed.RecoveryReason() == expected_reason &&
                malformed.LastReplayStage() == expected_stage,
            label + ": replay should report the specific fragmented-extent failure");
        return malformed_ok;
    };

    ok &= expect_malformed_replay_rejected(
        kBlockSize,
        L"ReplayExtentAllocationOwnershipInvalid",
        "validate-replay-fragmented-extent-ownership",
        "DisjointPartialOverwriteCOW/unallocated-retained-alias");
    ok &= expect_malformed_replay_rejected(
        baseline_physical_address + (2ull * kBlockSize),
        L"ReplayExtentPhysicalOverlap",
        "validate-replay-fragmented-extent-overlap",
        "DisjointPartialOverwriteCOW/same-inode-alias");
    ok &= expect_malformed_replay_rejected(
        other_inode_physical_address,
        L"ReplayExtentAllocationOwnershipInvalid",
        "validate-replay-fragmented-extent-ownership",
        "DisjointPartialOverwriteCOW/other-inode-alias");
    copy_ec.clear();
    std::filesystem::copy_file(
        valid_interrupted_image,
        image_path,
        std::filesystem::copy_options::overwrite_existing,
        copy_ec);
    ok &= Require(
        !copy_ec,
        "DisjointPartialOverwriteCOW: valid interrupted image restore should succeed");

    {
        apfsaccess::rw::MetadataStore remounted(context);
        ok &= Require(
            remounted.LoadContainerSuperblocks(),
            "DisjointPartialOverwriteCOW: remount LoadContainerSuperblocks should succeed");
        ok &= Require(
            remounted.PrepareNativeWritePath(),
            "DisjointPartialOverwriteCOW: remount PrepareNativeWritePath should succeed");
        ok &= Require(
            remounted.IsRecoveryRequired(),
            "DisjointPartialOverwriteCOW: remount should require recovery before replay");
        const auto replayed = remounted.ReplayOrRecover();
        if (!replayed)
        {
            std::cerr << "[DEBUG] DisjointPartialOverwriteCOW replay stage: "
                      << remounted.LastReplayStage() << std::endl;
            std::wcerr << L"[DEBUG] DisjointPartialOverwriteCOW replay reason: "
                       << remounted.RecoveryReason() << std::endl;
        }
        ok &= Require(
            replayed,
            "DisjointPartialOverwriteCOW: ReplayIfSafe remount should replay the interrupted commit");
        ok &= Require(
            !remounted.IsRecoveryRequired() && remounted.IsCommitPathReady(),
            "DisjointPartialOverwriteCOW: replay should clear recovery and restore commit readiness");

        std::vector<std::byte> committed_payload;
        ok &= Require(
            remounted.ReadCommittedFileRange(kPath, 0, kLogicalBytes, committed_payload),
            "DisjointPartialOverwriteCOW: replayed final payload should be readable");
        ok &= Require(
            committed_payload == final_payload,
            "DisjointPartialOverwriteCOW: replayed final payload should preserve both disjoint replacements");
        ok &= Require(
            remounted.PendingAllocationCount() == 0 && remounted.PendingDeallocationCount() == 0,
            "DisjointPartialOverwriteCOW: replay should clear pending allocation and deallocation accounting");
        ok &= Require(
            remounted.CommittedAllocationCount() == expected_committed_allocation_count &&
                remounted.CommittedFreeExtentCount() == expected_committed_free_extent_count,
            "DisjointPartialOverwriteCOW: replayed spaceman allocation accounting should match the interrupted commit");
        if (expected_free_size.has_value())
        {
            const auto remounted_free_size = remounted.FreeSizeBytes();
            ok &= Require(
                remounted_free_size.has_value() && remounted_free_size.value() == expected_free_size.value(),
                "DisjointPartialOverwriteCOW: replayed free-byte accounting should match the interrupted commit");
        }
    }

    return ok;
}

enum class PartialOverwriteFollowup
{
    Delete,
    Truncate,
    Extend,
    UnalignedFallback,
};

bool RunPartialOverwriteFollowupOwnershipCase(
    const std::filesystem::path& run_root,
    PartialOverwriteFollowup followup,
    std::string_view case_name)
{
    const auto image_path = run_root / ("partial_overwrite_followup_" + std::string(case_name) + ".apfs.img");
    const auto label = "PartialOverwriteFollowup/" + std::string(case_name);
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, label + ": unable to create synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        std::wstring(case_name.begin(), case_name.end()),
    };
    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), label + ": LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), label + ": LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), label + ": LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), label + ": PrepareNativeWritePath should succeed");

    constexpr std::size_t kBlockBytes = 4096;
    constexpr std::size_t kLogicalBytes = 3 * kBlockBytes;
    constexpr auto kPath = L"\\followup.bin";
    std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
    ConfigurePayloadProvider(store, staged_payloads);
    auto final_payload = BuildPatternPayload(kLogicalBytes, 0x42);
    ok &= CreateAndCommitFile(
        store,
        staged_payloads,
        kPath,
        final_payload.size(),
        0x42,
        label + "/baseline");

    const auto baseline_allocations = store.CommittedAllocationCount();
    const auto baseline_free_size = store.FreeSizeBytes();
    ok &= Require(
        baseline_allocations > 0 && baseline_free_size.has_value(),
        label + ": baseline allocator accounting should be available");

    const auto middle_replacement = BuildPatternPayload(kBlockBytes, 0xA7);
    std::copy(
        middle_replacement.begin(),
        middle_replacement.end(),
        final_payload.begin() + static_cast<std::ptrdiff_t>(kBlockBytes));
    staged_payloads[kPath] = final_payload;
    apfsaccess::rw::MetadataStore::MutationRequest partial_overwrite{};
    partial_overwrite.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
    partial_overwrite.path = kPath;
    partial_overwrite.offset = kBlockBytes;
    partial_overwrite.length = kBlockBytes;
    ok &= ExpectMutationStatus(
        store,
        partial_overwrite,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        label + ": partial overwrite should apply");
    ok &= Require(
        store.PendingAllocationCount() == 1 && store.PendingDeallocationCount() == 1,
        label + ": partial overwrite should stage one replacement allocation and deallocation");

    switch (followup)
    {
    case PartialOverwriteFollowup::Delete:
    {
        apfsaccess::rw::MetadataStore::MutationRequest request{};
        request.operation = apfsaccess::rw::MetadataStore::MutationOperation::Delete;
        request.path = kPath;
        ok &= ExpectMutationStatus(
            store,
            request,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            label + ": delete after partial overwrite should apply");
        break;
    }
    case PartialOverwriteFollowup::Truncate:
    {
        apfsaccess::rw::MetadataStore::MutationRequest request{};
        request.operation = apfsaccess::rw::MetadataStore::MutationOperation::SetFileSize;
        request.path = kPath;
        request.length = 0;
        staged_payloads[kPath].clear();
        ok &= ExpectMutationStatus(
            store,
            request,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            label + ": truncate after partial overwrite should apply");
        break;
    }
    case PartialOverwriteFollowup::Extend:
    {
        const auto appended = BuildPatternPayload(kBlockBytes, 0xD4);
        final_payload.insert(final_payload.end(), appended.begin(), appended.end());
        staged_payloads[kPath] = final_payload;
        apfsaccess::rw::MetadataStore::MutationRequest request{};
        request.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        request.path = kPath;
        request.offset = kLogicalBytes;
        request.length = kBlockBytes;
        ok &= ExpectMutationStatus(
            store,
            request,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            label + ": extension after partial overwrite should apply");
        break;
    }
    case PartialOverwriteFollowup::UnalignedFallback:
    {
        constexpr std::size_t kUnalignedOffset = 137;
        constexpr std::size_t kUnalignedBytes = 29;
        const auto replacement = BuildPatternPayload(kUnalignedBytes, 0xEE);
        std::copy(
            replacement.begin(),
            replacement.end(),
            final_payload.begin() + static_cast<std::ptrdiff_t>(kUnalignedOffset));
        staged_payloads[kPath] = final_payload;
        apfsaccess::rw::MetadataStore::MutationRequest request{};
        request.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        request.path = kPath;
        request.offset = kUnalignedOffset;
        request.length = kUnalignedBytes;
        ok &= ExpectMutationStatus(
            store,
            request,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            label + ": unaligned overwrite fallback should apply");
        break;
    }
    }

    const bool removes_file_storage =
        followup == PartialOverwriteFollowup::Delete ||
        followup == PartialOverwriteFollowup::Truncate;
    ok &= Require(
        store.PendingAllocationCount() == (removes_file_storage ? 0u : 1u) &&
            store.PendingDeallocationCount() == 3,
        label + ": follow-up should cancel only pending storage and retire all three committed slices");
    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        label + ": follow-up commit should succeed");

    const auto committed_inode = store.LookupCommittedInodeByPath(kPath);
    if (followup == PartialOverwriteFollowup::Delete)
    {
        ok &= Require(!committed_inode.has_value(), label + ": deleted inode should be absent");
    }
    else if (followup == PartialOverwriteFollowup::Truncate)
    {
        ok &= Require(
            committed_inode.has_value() &&
                committed_inode->logical_size == 0 &&
                committed_inode->data_physical_address == 0,
            label + ": truncated inode should retain no storage");
    }
    else
    {
        std::vector<std::byte> committed_payload;
        ok &= Require(
            committed_inode.has_value() &&
                store.ReadCommittedFileRange(kPath, 0, final_payload.size(), committed_payload),
            label + ": final payload should be readable");
        ok &= Require(
            committed_payload == final_payload &&
                !committed_payload.empty() &&
                committed_payload.back() == final_payload.back(),
            label + ": final payload, including its last byte, should match");
    }

    const auto final_free_size = store.FreeSizeBytes();
    if (baseline_free_size.has_value())
    {
        constexpr std::uint64_t kCommitRecordBytes = kBlockSize;
        const auto expected_free_size = removes_file_storage
            ? baseline_free_size.value() + kLogicalBytes - kCommitRecordBytes
            : baseline_free_size.value() - kCommitRecordBytes -
                (followup == PartialOverwriteFollowup::Extend ? kBlockBytes : 0u);
        ok &= Require(
            final_free_size.has_value() && final_free_size.value() == expected_free_size,
            label + ": committed free-byte accounting should be exact");
    }
    ok &= Require(
        store.CommittedAllocationCount() == baseline_allocations,
        label + ": committed allocation count should be exact");
    return ok;
}

bool TestPartialOverwriteFollowupOwnershipConformance(const std::filesystem::path& run_root)
{
    bool ok = true;
    ok &= RunPartialOverwriteFollowupOwnershipCase(
        run_root,
        PartialOverwriteFollowup::Delete,
        "delete");
    ok &= RunPartialOverwriteFollowupOwnershipCase(
        run_root,
        PartialOverwriteFollowup::Truncate,
        "truncate");
    ok &= RunPartialOverwriteFollowupOwnershipCase(
        run_root,
        PartialOverwriteFollowup::Extend,
        "extend");
    ok &= RunPartialOverwriteFollowupOwnershipCase(
        run_root,
        PartialOverwriteFollowup::UnalignedFallback,
        "unaligned");
    return ok;
}

bool TestOverlappingPartialOverwritesReplayAndAccountingConformance(
    const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "overlapping_partial_overwrite_replay.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "OverlappingPartialOverwrite: unable to create synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"OverlappingPartialOverwrite",
    };
    context.crash_replay_mode = L"ReplayIfSafe";

    constexpr std::size_t kBlockBytes = 4096;
    constexpr std::size_t kLogicalBytes = 3 * kBlockBytes;
    constexpr auto kPath = L"\\overlapping-partial.bin";
    auto final_payload = BuildPatternPayload(kLogicalBytes, 0x26);
    bool ok = true;
    std::size_t expected_committed_allocation_count = 0;
    std::optional<std::uint64_t> expected_free_size;
    {
        apfsaccess::rw::MetadataStore store(context);
        ok &= Require(store.LoadContainerSuperblocks(), "OverlappingPartialOverwrite: LoadContainerSuperblocks should succeed");
        ok &= Require(store.LoadObjectMap(), "OverlappingPartialOverwrite: LoadObjectMap should succeed");
        ok &= Require(store.LoadSpacemanState(), "OverlappingPartialOverwrite: LoadSpacemanState should succeed");
        ok &= Require(store.PrepareNativeWritePath(), "OverlappingPartialOverwrite: PrepareNativeWritePath should succeed");

        std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
        ConfigurePayloadProvider(store, staged_payloads);
        ok &= CreateAndCommitFile(
            store,
            staged_payloads,
            kPath,
            final_payload.size(),
            0x26,
            "OverlappingPartialOverwrite/baseline");
        const auto middle = BuildPatternPayload(kBlockBytes, 0x91);
        std::copy(
            middle.begin(),
            middle.end(),
            final_payload.begin() + static_cast<std::ptrdiff_t>(kBlockBytes));
        apfsaccess::rw::MetadataStore::MutationRequest first{};
        first.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        first.path = kPath;
        first.offset = kBlockBytes;
        first.length = kBlockBytes;
        ok &= ExpectMutationStatus(
            store,
            first,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "OverlappingPartialOverwrite: first middle overwrite should apply");

        const auto overlapping = BuildPatternPayload(2 * kBlockBytes, 0xC3);
        std::copy(overlapping.begin(), overlapping.end(), final_payload.begin());
        staged_payloads[kPath] = final_payload;
        apfsaccess::rw::MetadataStore::MutationRequest second{};
        second.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        second.path = kPath;
        second.offset = 0;
        second.length = 2 * kBlockBytes;
        ok &= ExpectMutationStatus(
            store,
            second,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "OverlappingPartialOverwrite: overlapping overwrite should apply");
        ok &= Require(
            store.PendingAllocationCount() == 2 && store.PendingDeallocationCount() == 2,
            "OverlappingPartialOverwrite: overlap should retain the first pending range and replace two committed slices exactly once");

        store.SetCommitStageHook([](std::string_view stage)
        {
            return stage != "before-checkpoint-switch";
        });
        ok &= ExpectCommitStatus(
            store,
            apfsaccess::rw::MetadataStore::CommitStatus::PersistFailed,
            "OverlappingPartialOverwrite: commit should stop before checkpoint publication");
        expected_committed_allocation_count = store.CommittedAllocationCount();
        expected_free_size = store.FreeSizeBytes();
        ok &= Require(
            expected_committed_allocation_count > 0 && expected_free_size.has_value(),
            "OverlappingPartialOverwrite: interrupted allocator and free-byte ledgers should be available");
    }

    apfsaccess::rw::MetadataStore remounted(context);
    ok &= Require(remounted.LoadContainerSuperblocks(), "OverlappingPartialOverwrite: remount should load container");
    ok &= Require(remounted.PrepareNativeWritePath(), "OverlappingPartialOverwrite: remount should prepare native writes");
    ok &= Require(remounted.IsRecoveryRequired(), "OverlappingPartialOverwrite: interrupted remount should require replay");
    ok &= Require(remounted.ReplayOrRecover(), "OverlappingPartialOverwrite: interrupted replay should converge");
    std::vector<std::byte> replayed_payload;
    ok &= Require(
        remounted.ReadCommittedFileRange(kPath, 0, final_payload.size(), replayed_payload),
        "OverlappingPartialOverwrite: replayed fragmented payload should be readable");
    ok &= Require(
        replayed_payload == final_payload &&
            !replayed_payload.empty() &&
            replayed_payload[kBlockBytes - 1] == final_payload[kBlockBytes - 1] &&
            replayed_payload[kBlockBytes] == final_payload[kBlockBytes] &&
            replayed_payload.back() == final_payload.back(),
        "OverlappingPartialOverwrite: replay should preserve every boundary and the final byte");
    ok &= Require(
        remounted.CommittedAllocationCount() == expected_committed_allocation_count,
        "OverlappingPartialOverwrite: replayed allocation count should exactly match the interrupted ledger");
    const auto replayed_free_size = remounted.FreeSizeBytes();
    ok &= Require(
        expected_free_size.has_value() &&
            replayed_free_size.has_value() &&
            replayed_free_size.value() == expected_free_size.value(),
        "OverlappingPartialOverwrite: replayed free-byte accounting should exactly match the interrupted ledger");
    return ok;
}

bool TestPartialOverwriteMidMultiRangeAllocationFailureRollsBackConformance(
    const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "partial_overwrite_mid_multi_range_failure.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "PartialOverwriteMidFailure: unable to create synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"PartialOverwriteMidFailure",
    };
    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "PartialOverwriteMidFailure: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "PartialOverwriteMidFailure: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "PartialOverwriteMidFailure: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "PartialOverwriteMidFailure: PrepareNativeWritePath should succeed");

    constexpr std::size_t kBlockBytes = 4096;
    constexpr std::size_t kLogicalBytes = 3 * kBlockBytes;
    constexpr auto kPath = L"\\mid-failure.bin";
    std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
    ConfigurePayloadProvider(store, staged_payloads);
    ok &= CreateAndCommitFile(
        store,
        staged_payloads,
        kPath,
        kLogicalBytes,
        0x35,
        "PartialOverwriteMidFailure/baseline");
    ok &= InstallFragmentedReadExtents(
        store,
        kPath,
        440ull * kBlockSize,
        "PartialOverwriteMidFailure");

    std::vector<std::uint64_t> consumed_blocks;
    while (store.AllocateExtent(64ull * kBlockSize).has_value())
    {
    }
    while (const auto allocation = store.AllocateExtent(kBlockSize))
    {
        consumed_blocks.push_back(allocation.value());
    }
    ok &= Require(
        consumed_blocks.size() >= 3,
        "PartialOverwriteMidFailure: setup should reserve at least three final allocator blocks");
    if (consumed_blocks.size() < 3)
    {
        return false;
    }
    const auto first_available = consumed_blocks.back();
    consumed_blocks.pop_back();
    ok &= Require(
        store.FreeExtent(first_available, kBlockSize),
        "PartialOverwriteMidFailure: setup should expose exactly one replacement block");

    const auto before_delta = apfsaccess::rw::CheckpointDeltaCodec::Encode(store.DebugBuildPendingCheckpointDelta());
    const auto before_pending_mutations = store.PendingMutationCount();
    const auto before_pending_allocations = store.PendingAllocationCount();
    const auto before_pending_deallocations = store.PendingDeallocationCount();
    const auto before_pending_btree = store.PendingBtreeRecordCount();
    const auto before_free_count = store.DebugWorkingFreeExtentCount();
    const auto before_free_bytes = store.DebugWorkingFreeExtentTotalBytes();
    const auto before_inode = store.DebugLookupWorkingInodeByPath(kPath);

    staged_payloads[kPath] = BuildPatternPayload(kLogicalBytes, 0xDA);
    apfsaccess::rw::MetadataStore::MutationRequest overwrite{};
    overwrite.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
    overwrite.path = kPath;
    overwrite.offset = 0;
    overwrite.length = kLogicalBytes;
    ok &= ExpectMutationStatus(
        store,
        overwrite,
        apfsaccess::rw::MetadataStore::MutationStatus::AllocationFailed,
        "PartialOverwriteMidFailure: second replacement range should fail after the first stages");

    const auto after_delta = apfsaccess::rw::CheckpointDeltaCodec::Encode(store.DebugBuildPendingCheckpointDelta());
    const auto after_inode = store.DebugLookupWorkingInodeByPath(kPath);
    ok &= Require(
        store.PendingMutationCount() == before_pending_mutations &&
            store.PendingAllocationCount() == before_pending_allocations &&
            store.PendingDeallocationCount() == before_pending_deallocations &&
            store.PendingBtreeRecordCount() == before_pending_btree &&
            store.DebugWorkingFreeExtentCount() == before_free_count &&
            store.DebugWorkingFreeExtentTotalBytes() == before_free_bytes &&
            after_delta == before_delta,
        "PartialOverwriteMidFailure: failed staging should restore allocator, B-tree, and checkpoint delta exactly");
    ok &= Require(
        before_inode.has_value() && after_inode.has_value() &&
            before_inode->logical_size == after_inode->logical_size &&
            before_inode->data_physical_address == after_inode->data_physical_address &&
            before_inode->xid == after_inode->xid,
        "PartialOverwriteMidFailure: failed staging should restore inode and extent anchor state");

    const auto second_available = consumed_blocks.back();
    consumed_blocks.pop_back();
    const auto third_available = consumed_blocks.back();
    ok &= Require(
        store.FreeExtent(second_available, kBlockSize) &&
            store.FreeExtent(third_available, kBlockSize),
        "PartialOverwriteMidFailure: retry setup should expose the remaining replacement blocks");
    ok &= ExpectMutationStatus(
        store,
        overwrite,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "PartialOverwriteMidFailure: retry should use the fully restored fragmented source state");
    ok &= Require(
        store.PendingAllocationCount() == 3 && store.PendingDeallocationCount() == 3,
        "PartialOverwriteMidFailure: successful retry should stage all three replacement ranges exactly once");
    return ok;
}

bool TestCommittedSpoolStyleWriteThenRenameConformance(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "committed_spool_style_rename.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "CommittedSpoolStyleRename: unable to create synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"CommittedSpoolStyleRename",
    };

    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "CommittedSpoolStyleRename: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "CommittedSpoolStyleRename: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "CommittedSpoolStyleRename: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "CommittedSpoolStyleRename: PrepareNativeWritePath should succeed");

    const auto payload = BuildPatternPayload(512 * 1024, 0x5D);
    store.SetFilePayloadRangeProvider(
        [&payload](
            const std::wstring& path,
            apfsaccess::rw::MetadataStore::PayloadIdentity,
            std::uint64_t offset,
            std::span<std::byte> destination) -> bool
        {
            if (path != L"\\beta\\direct-write.bin" &&
                path != L"\\beta\\renamed direct write.bin" &&
                path != L"\\gamma nested\\moved direct write.bin")
            {
                return false;
            }
            if (offset > payload.size() ||
                destination.size() > (payload.size() - static_cast<std::size_t>(offset)))
            {
                return false;
            }

            std::copy(
                payload.begin() + static_cast<std::ptrdiff_t>(offset),
                payload.begin() + static_cast<std::ptrdiff_t>(offset + destination.size()),
                destination.begin());
            return true;
        });

    apfsaccess::rw::MetadataStore::MutationRequest create_beta{};
    create_beta.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateDirectory;
    create_beta.path = L"\\beta";
    ok &= ExpectMutationStatus(
        store,
        create_beta,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "CommittedSpoolStyleRename: create beta should apply");

    apfsaccess::rw::MetadataStore::MutationRequest create_gamma{};
    create_gamma.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateDirectory;
    create_gamma.path = L"\\gamma nested";
    ok &= ExpectMutationStatus(
        store,
        create_gamma,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "CommittedSpoolStyleRename: create gamma should apply");

    apfsaccess::rw::MetadataStore::MutationRequest create_file{};
    create_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
    create_file.path = L"\\beta\\direct-write.bin";
    ok &= ExpectMutationStatus(
        store,
        create_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "CommittedSpoolStyleRename: create direct file should apply");

    for (std::uint64_t offset = 0; offset < payload.size(); offset += 65536)
    {
        apfsaccess::rw::MetadataStore::MutationRequest write{};
        write.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write.path = L"\\beta\\direct-write.bin";
        write.offset = offset;
        write.length = std::min<std::uint64_t>(65536, payload.size() - offset);
        ok &= ExpectMutationStatus(
            store,
            write,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "CommittedSpoolStyleRename: chunk write should apply");
    }

    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "CommittedSpoolStyleRename: write commit should succeed");

    apfsaccess::rw::MetadataStore::MutationRequest rename{};
    rename.operation = apfsaccess::rw::MetadataStore::MutationOperation::Rename;
    rename.path = L"\\beta\\direct-write.bin";
    rename.secondary_path = L"\\beta\\renamed direct write.bin";
    ok &= ExpectMutationStatus(
        store,
        rename,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "CommittedSpoolStyleRename: first rename should apply");
    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "CommittedSpoolStyleRename: first rename commit should succeed");

    rename.path = L"\\beta\\renamed direct write.bin";
    rename.secondary_path = L"\\gamma nested\\moved direct write.bin";
    ok &= ExpectMutationStatus(
        store,
        rename,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "CommittedSpoolStyleRename: move rename should apply");
    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "CommittedSpoolStyleRename: move rename commit should succeed");

    std::vector<std::byte> committed_payload;
    ok &= Require(
        store.ReadCommittedFileRange(
            L"\\gamma nested\\moved direct write.bin",
            0,
            payload.size(),
            committed_payload),
        "CommittedSpoolStyleRename: moved payload should be readable");
    ok &= Require(
        committed_payload == payload,
        "CommittedSpoolStyleRename: moved payload should match original bytes");

    return ok;
}

bool TestPreparedPayloadWriteThroughSkipsCommittedRangesConformance(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "prepared_payload_write_through.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "PreparedPayloadWriteThrough: unable to create synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"PreparedPayloadWriteThrough",
    };

    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "PreparedPayloadWriteThrough: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "PreparedPayloadWriteThrough: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "PreparedPayloadWriteThrough: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "PreparedPayloadWriteThrough: PrepareNativeWritePath should succeed");

    bool whole_file_provider_called = false;
    std::unordered_map<std::wstring, std::vector<std::byte>> range_payloads;
    std::unordered_map<std::wstring, std::uint64_t> range_bytes_requested;
    store.SetFilePayloadProvider(
        [&whole_file_provider_called](const std::wstring&, std::uint64_t) -> std::optional<std::vector<std::byte>>
        {
            whole_file_provider_called = true;
            return std::nullopt;
        });
    store.SetFilePayloadRangeProvider(
        [&range_payloads, &range_bytes_requested](
            const std::wstring& path,
            apfsaccess::rw::MetadataStore::PayloadIdentity,
            std::uint64_t offset,
            std::span<std::byte> destination) -> bool
        {
            auto payload_it = range_payloads.find(path);
            if (payload_it == range_payloads.end() ||
                offset > payload_it->second.size() ||
                destination.size() > (payload_it->second.size() - static_cast<std::size_t>(offset)))
            {
                return false;
            }

            std::copy_n(
                payload_it->second.data() + static_cast<std::ptrdiff_t>(offset),
                destination.size(),
                destination.data());
            range_bytes_requested[path] += destination.size();
            return true;
        });

    const auto payload = BuildPatternPayload(64 * 1024, 0xC3);
    const auto prepared_bytes = payload.size() / 2;
    range_payloads[L"\\prepared.bin"] = payload;

    apfsaccess::rw::MetadataStore::MutationRequest create_file{};
    create_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
    create_file.path = L"\\prepared.bin";
    ok &= ExpectMutationStatus(
        store,
        create_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "PreparedPayloadWriteThrough: create prepared file should apply");

    apfsaccess::rw::MetadataStore::MutationRequest set_size{};
    set_size.operation = apfsaccess::rw::MetadataStore::MutationOperation::SetFileSize;
    set_size.path = L"\\prepared.bin";
    set_size.length = payload.size();
    ok &= ExpectMutationStatus(
        store,
        set_size,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "PreparedPayloadWriteThrough: SetFileSize should allocate prepared file extents");
    ok &= Require(
        store.WritePreparedFileRange(
            L"\\prepared.bin",
            0,
            std::span<const std::byte>(payload.data(), prepared_bytes)),
        "PreparedPayloadWriteThrough: prepared first half should write through");

    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "PreparedPayloadWriteThrough: prepared-range commit should succeed");
    ok &= Require(
        !whole_file_provider_called,
        "PreparedPayloadWriteThrough: commit should use range provider, not whole-file provider");
    ok &= Require(
        range_bytes_requested[L"\\prepared.bin"] == payload.size() - prepared_bytes,
        "PreparedPayloadWriteThrough: commit should request only bytes not already prepared");

    std::vector<std::byte> committed_payload;
    ok &= Require(
        store.ReadCommittedFileRange(L"\\prepared.bin", 0, payload.size(), committed_payload),
        "PreparedPayloadWriteThrough: committed prepared payload should be readable");
    ok &= Require(
        committed_payload == payload,
        "PreparedPayloadWriteThrough: committed prepared payload should match");

    const auto small_payload = BuildPatternPayload(8 * 1024, 0x29);
    const auto grown_payload = BuildPatternPayload(16 * 1024, 0xD4);
    range_payloads[L"\\reallocated.bin"] = grown_payload;
    range_bytes_requested[L"\\reallocated.bin"] = 0;

    apfsaccess::rw::MetadataStore::MutationRequest create_reallocated = create_file;
    create_reallocated.path = L"\\reallocated.bin";
    ok &= ExpectMutationStatus(
        store,
        create_reallocated,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "PreparedPayloadWriteThrough: create reallocated file should apply");

    apfsaccess::rw::MetadataStore::MutationRequest set_small = set_size;
    set_small.path = L"\\reallocated.bin";
    set_small.length = small_payload.size();
    ok &= ExpectMutationStatus(
        store,
        set_small,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "PreparedPayloadWriteThrough: initial small allocation should apply");
    ok &= Require(
        store.WritePreparedFileRange(
            L"\\reallocated.bin",
            0,
            std::span<const std::byte>(small_payload.data(), small_payload.size())),
        "PreparedPayloadWriteThrough: stale small range should write through before reallocation");

    apfsaccess::rw::MetadataStore::MutationRequest grow_file = set_size;
    grow_file.path = L"\\reallocated.bin";
    grow_file.length = grown_payload.size();
    ok &= ExpectMutationStatus(
        store,
        grow_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "PreparedPayloadWriteThrough: growth should reallocate and clear prepared ranges");
    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "PreparedPayloadWriteThrough: reallocated commit should succeed");
    ok &= Require(
        range_bytes_requested[L"\\reallocated.bin"] == grown_payload.size(),
        "PreparedPayloadWriteThrough: reallocation should clear stale prepared ranges");

    std::vector<std::byte> reallocated_payload;
    ok &= Require(
        store.ReadCommittedFileRange(L"\\reallocated.bin", 0, grown_payload.size(), reallocated_payload),
        "PreparedPayloadWriteThrough: reallocated payload should be readable");
    ok &= Require(
        reallocated_payload == grown_payload,
        "PreparedPayloadWriteThrough: reallocated payload should match grown payload");

    const auto prepared_inode = store.LookupCommittedInodeByPath(L"\\prepared.bin");
    ok &= Require(
        prepared_inode.has_value() && prepared_inode->data_physical_address != 0,
        "PreparedPayloadWriteThrough: committed file should expose a physical extent");
    if (prepared_inode.has_value() && prepared_inode->data_physical_address != 0)
    {
        constexpr std::size_t kFragmentBytes = 16 * 1024;
        std::vector<apfsaccess::rw::MetadataStore::FileExtent> fragmented_extents;
        for (std::size_t logical_offset = 0; logical_offset < payload.size(); logical_offset += kFragmentBytes)
        {
            fragmented_extents.push_back({
                static_cast<std::uint64_t>(logical_offset),
                prepared_inode->data_physical_address + static_cast<std::uint64_t>(logical_offset),
                std::min(kFragmentBytes, payload.size() - logical_offset),
            });
        }
        ok &= Require(
            store.SetCommittedReadExtents(prepared_inode->object_id, std::move(fragmented_extents)),
            "PreparedPayloadWriteThrough: fragmented extent projection should install");

        const auto replacement = BuildPatternPayload(prepared_bytes, 0x6A);
        const auto before_fragmented_write = store.PerformanceJson();
        const auto before_fragmented_batch_writes =
            ExtractNestedPerfCounterCount(before_fragmented_write, "blockDevice", "batchWrite");
        ok &= Require(
            store.WritePreparedFileRange(
                L"\\prepared.bin",
                0,
                std::span<const std::byte>(replacement.data(), replacement.size())),
            "PreparedPayloadWriteThrough: fragmented prepared write should succeed");
        const auto after_fragmented_write = store.PerformanceJson();
        const auto after_fragmented_batch_writes =
            ExtractNestedPerfCounterCount(after_fragmented_write, "blockDevice", "batchWrite");
        ok &= Require(
            before_fragmented_batch_writes.has_value() && after_fragmented_batch_writes.has_value() &&
                after_fragmented_batch_writes.value() >= before_fragmented_batch_writes.value() + 1,
            "PreparedPayloadWriteThrough: fragmented extents should use one raw write batch");

        std::vector<std::byte> fragmented_readback;
        ok &= Require(
            store.ReadCommittedFileRange(L"\\prepared.bin", 0, payload.size(), fragmented_readback),
            "PreparedPayloadWriteThrough: fragmented prepared write should remain readable");
        auto expected_fragmented_payload = payload;
        std::copy(replacement.begin(), replacement.end(), expected_fragmented_payload.begin());
        ok &= Require(
            fragmented_readback == expected_fragmented_payload,
            "PreparedPayloadWriteThrough: fragmented prepared write should preserve all bytes");
    }

    return ok;
}

bool TestBtreeCanonicalizationConformance(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "btree_canonical.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "TestBtreeCanonicalizationConformance: unable to create synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"BtreeCanonical",
    };
    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "BtreeCanonical: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "BtreeCanonical: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "BtreeCanonical: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "BtreeCanonical: PrepareNativeWritePath should succeed");

    std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
    ConfigurePayloadProvider(store, staged_payloads);

    apfsaccess::rw::MetadataStore::MutationRequest create_file{};
    create_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
    create_file.path = L"\\canonical.txt";
    ok &= ExpectMutationStatus(
        store,
        create_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "BtreeCanonical: create file should apply");

    apfsaccess::rw::MetadataStore::MutationRequest write_file{};
    write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
    write_file.path = L"\\canonical.txt";
    write_file.length = 640;
    ok &= ExpectMutationStatus(
        store,
        write_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "BtreeCanonical: write file should apply");
    staged_payloads[L"\\canonical.txt"] = BuildPatternPayload(640, 0x5C);

    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "BtreeCanonical: initial commit should succeed");
    const auto record_count_after_create = store.CommittedBtreeRecordCount();
    ok &= Require(record_count_after_create > 0, "BtreeCanonical: initial commit should persist btree records");

    apfsaccess::rw::MetadataStore::MutationRequest set_basic_info{};
    set_basic_info.operation = apfsaccess::rw::MetadataStore::MutationOperation::SetBasicInfo;
    set_basic_info.path = L"\\canonical.txt";
    for (std::uint64_t timestamp : { 101ull, 202ull, 303ull })
    {
        set_basic_info.timestamp_utc = timestamp;
        ok &= ExpectMutationStatus(
            store,
            set_basic_info,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "BtreeCanonical: set basic info should apply");
    }
    ok &= Require(
        store.PendingBtreeRecordCount() == 1,
        "BtreeCanonical: repeated set basic info should keep one pending inode record");
    ok &= Require(
        store.PendingMutationCount() == 1,
        "BtreeCanonical: repeated set basic info should keep one pending mutation");
    ok &= Require(
        store.PendingObjectMapUpdateCount() == 0,
        "BtreeCanonical: repeated set basic info should not stage object-map updates");
    ok &= Require(
        store.PendingBtreeFileMetadataScanCount() == 0,
        "BtreeCanonical: repeated set basic info should use the pending btree file metadata index");
    const auto before_set_basic_btree_index_rebuilds = ExtractNestedUnsignedValue(
        store.PerformanceJson(),
        "committedBtreeIndex",
        "rebuilds");
    ok &= Require(
        before_set_basic_btree_index_rebuilds.has_value(),
        "BtreeCanonical: committed btree index rebuild counter should exist before metadata commit");
    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "BtreeCanonical: set basic info commit should succeed");
    const auto after_set_basic_btree_index_rebuilds = ExtractNestedUnsignedValue(
        store.PerformanceJson(),
        "committedBtreeIndex",
        "rebuilds");
    ok &= Require(
        after_set_basic_btree_index_rebuilds.has_value(),
        "BtreeCanonical: committed btree index rebuild counter should exist after metadata commit");
    if (before_set_basic_btree_index_rebuilds.has_value() &&
        after_set_basic_btree_index_rebuilds.has_value())
    {
        ok &= Require(
            after_set_basic_btree_index_rebuilds.value() == before_set_basic_btree_index_rebuilds.value(),
            "BtreeCanonical: same-key metadata commit should not rebuild the full committed btree index");
    }
    ok &= Require(
        store.CommittedBtreeRecordCount() == record_count_after_create,
        "BtreeCanonical: set basic info should overwrite existing inode key rather than grow canonical record set");
    auto canonical_after_set_basic = store.LookupCommittedInodeByPath(L"\\canonical.txt");
    ok &= Require(
        canonical_after_set_basic.has_value() && canonical_after_set_basic->timestamp_utc == 303ull,
        "BtreeCanonical: repeated set basic info should persist the latest timestamp");

    apfsaccess::rw::MetadataStore::MutationRequest rename_file{};
    rename_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Rename;
    rename_file.path = L"\\canonical.txt";
    rename_file.secondary_path = L"\\renamed-canonical.txt";
    ok &= ExpectMutationStatus(
        store,
        rename_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "BtreeCanonical: rename should apply");
    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "BtreeCanonical: rename commit should succeed");
    const auto record_count_after_rename = store.CommittedBtreeRecordCount();
    ok &= Require(
        record_count_after_rename == record_count_after_create,
        "BtreeCanonical: rename should maintain canonical btree cardinality");

    apfsaccess::rw::MetadataStore::MutationRequest delete_file{};
    delete_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Delete;
    delete_file.path = L"\\renamed-canonical.txt";
    ok &= ExpectMutationStatus(
        store,
        delete_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "BtreeCanonical: delete should apply");
    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "BtreeCanonical: delete commit should succeed");
    ok &= Require(
        store.CommittedBtreeRecordCount() < record_count_after_rename,
        "BtreeCanonical: delete tombstones should compact canonical btree record set");
    ok &= Require(
        !store.LookupCommittedInodeByPath(L"\\canonical.txt").has_value() &&
            !store.LookupCommittedInodeByPath(L"\\renamed-canonical.txt").has_value(),
        "BtreeCanonical: deleted file path should not remain in committed inode projection");

    return ok;
}

bool TestBtreeCheckpointUsesSingleWritableSelectionConformance(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "btree_checkpoint_selection.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "BtreeCheckpointSelection: unable to create synthetic container");
    }

    wchar_t previous_perf_value[256]{};
    const auto previous_perf_chars = GetEnvironmentVariableW(
        L"APFSACCESS_PERF_COUNTERS",
        previous_perf_value,
        static_cast<DWORD>(std::size(previous_perf_value)));
    const bool had_previous_perf =
        previous_perf_chars > 0 &&
        previous_perf_chars < static_cast<DWORD>(std::size(previous_perf_value));
    SetEnvironmentVariableW(L"APFSACCESS_PERF_COUNTERS", L"1");

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"BtreeCheckpointSelection",
    };
    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "BtreeCheckpointSelection: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "BtreeCheckpointSelection: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "BtreeCheckpointSelection: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "BtreeCheckpointSelection: PrepareNativeWritePath should succeed");

    std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
    ConfigurePayloadProvider(store, staged_payloads);

    constexpr std::size_t kFileCount = 32;
    for (std::size_t index = 0; index < kFileCount; ++index)
    {
        const auto path = L"\\indexed-" + std::to_wstring(index) + L".bin";

        apfsaccess::rw::MetadataStore::MutationRequest create_file{};
        create_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
        create_file.path = path;
        ok &= ExpectMutationStatus(
            store,
            create_file,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "BtreeCheckpointSelection: create file should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_file{};
        write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_file.path = path;
        write_file.length = 1024;
        ok &= ExpectMutationStatus(
            store,
            write_file,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "BtreeCheckpointSelection: write file should apply");
        staged_payloads[path] = BuildPatternPayload(1024, static_cast<unsigned char>(0x40 + index));
    }

    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "BtreeCheckpointSelection: initial file batch commit should succeed");

    const auto before_json = store.PerformanceJson();
    const auto before_selections = ExtractNestedUnsignedValue(before_json, "chunkedCheckpointSelection", "attempts");
    const auto before_indexed_writable_checks =
        ExtractNestedUnsignedValue(before_json, "chunkedCheckpointSelection", "indexedWritableChecks");
    const auto before_fallback_writable_checks =
        ExtractNestedUnsignedValue(before_json, "chunkedCheckpointSelection", "fallbackWritableChecks");
    const auto before_checkpoint_block_cache_hits =
        ExtractNestedUnsignedValue(before_json, "checkpointBlockIndices", "cacheHits");
    const auto before_checkpoint_block_cache_builds =
        ExtractNestedUnsignedValue(before_json, "checkpointBlockIndices", "cacheBuilds");
    const auto before_checkpoint_block_bypass_builds =
        ExtractNestedUnsignedValue(before_json, "checkpointBlockIndices", "bypassBuilds");
    const auto before_block_reads = ExtractNestedPerfCounterCount(before_json, "blockDevice", "read");
    const auto before_btree_size_prescans = ExtractNestedUnsignedValue(before_json, "btreeCheckpoint", "sizePreScans");
    ok &= Require(
        before_selections.has_value() &&
            before_indexed_writable_checks.has_value() &&
            before_fallback_writable_checks.has_value() &&
            before_checkpoint_block_cache_hits.has_value() &&
            before_checkpoint_block_cache_builds.has_value() &&
            before_checkpoint_block_bypass_builds.has_value() &&
            before_block_reads.has_value() &&
            before_btree_size_prescans.has_value(),
        "BtreeCheckpointSelection: checkpoint selection and block read counters should exist");

    apfsaccess::rw::MetadataStore::MutationRequest set_basic_info{};
    set_basic_info.operation = apfsaccess::rw::MetadataStore::MutationOperation::SetBasicInfo;
    set_basic_info.path = L"\\indexed-7.bin";
    set_basic_info.timestamp_utc = 9090;
    ok &= ExpectMutationStatus(
        store,
        set_basic_info,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "BtreeCheckpointSelection: metadata-only update should apply");
    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "BtreeCheckpointSelection: metadata-only commit should succeed");

    const auto after_json = store.PerformanceJson();
    const auto after_selections = ExtractNestedUnsignedValue(after_json, "chunkedCheckpointSelection", "attempts");
    const auto after_indexed_writable_checks =
        ExtractNestedUnsignedValue(after_json, "chunkedCheckpointSelection", "indexedWritableChecks");
    const auto after_fallback_writable_checks =
        ExtractNestedUnsignedValue(after_json, "chunkedCheckpointSelection", "fallbackWritableChecks");
    const auto after_checkpoint_block_cache_hits =
        ExtractNestedUnsignedValue(after_json, "checkpointBlockIndices", "cacheHits");
    const auto after_checkpoint_block_cache_builds =
        ExtractNestedUnsignedValue(after_json, "checkpointBlockIndices", "cacheBuilds");
    const auto after_checkpoint_block_bypass_builds =
        ExtractNestedUnsignedValue(after_json, "checkpointBlockIndices", "bypassBuilds");
    const auto after_block_reads = ExtractNestedPerfCounterCount(after_json, "blockDevice", "read");
    const auto after_btree_size_prescans = ExtractNestedUnsignedValue(after_json, "btreeCheckpoint", "sizePreScans");
    ok &= Require(
        after_selections.has_value() &&
            after_indexed_writable_checks.has_value() &&
            after_fallback_writable_checks.has_value() &&
            after_checkpoint_block_cache_hits.has_value() &&
            after_checkpoint_block_cache_builds.has_value() &&
            after_checkpoint_block_bypass_builds.has_value() &&
            after_block_reads.has_value() &&
            after_btree_size_prescans.has_value(),
        "BtreeCheckpointSelection: checkpoint selection and block read counters should exist after metadata commit");
    if (before_selections.has_value() && after_selections.has_value())
    {
        ok &= Require(
            after_selections.value() == before_selections.value() + 4,
            "BtreeCheckpointSelection: one commit should select checkpoint windows once per full checkpoint family");
    }
    wchar_t disable_checkpoint_slot_index[8]{};
    const auto disable_checkpoint_slot_index_chars = GetEnvironmentVariableW(
        L"APFSACCESS_DISABLE_CHECKPOINT_SLOT_INDEX",
        disable_checkpoint_slot_index,
        static_cast<DWORD>(std::size(disable_checkpoint_slot_index)));
    const bool checkpoint_slot_index_disabled =
        disable_checkpoint_slot_index_chars > 0 &&
        disable_checkpoint_slot_index[0] != L'\0' &&
        disable_checkpoint_slot_index[0] != L'0';
    if (before_indexed_writable_checks.has_value() &&
        after_indexed_writable_checks.has_value() &&
        before_fallback_writable_checks.has_value() &&
        after_fallback_writable_checks.has_value())
    {
        if (checkpoint_slot_index_disabled)
        {
            ok &= Require(
                after_indexed_writable_checks.value() == before_indexed_writable_checks.value() &&
                    after_fallback_writable_checks.value() >= before_fallback_writable_checks.value() + 4,
                "BtreeCheckpointSelection: kill switch should restore writable-slot allocation scans");
        }
        else
        {
            ok &= Require(
                after_indexed_writable_checks.value() >= before_indexed_writable_checks.value() + 4 &&
                    after_fallback_writable_checks.value() == before_fallback_writable_checks.value(),
                "BtreeCheckpointSelection: canonical allocation state should use indexed writable-slot checks");
        }
    }
    wchar_t disable_checkpoint_block_index_cache[8]{};
    const auto disable_checkpoint_block_index_cache_chars = GetEnvironmentVariableW(
        L"APFSACCESS_DISABLE_CHECKPOINT_BLOCK_INDEX_CACHE",
        disable_checkpoint_block_index_cache,
        static_cast<DWORD>(std::size(disable_checkpoint_block_index_cache)));
    const bool checkpoint_block_index_cache_disabled =
        disable_checkpoint_block_index_cache_chars > 0 &&
        disable_checkpoint_block_index_cache[0] != L'\0' &&
        disable_checkpoint_block_index_cache[0] != L'0';
    if (before_checkpoint_block_cache_hits.has_value() &&
        after_checkpoint_block_cache_hits.has_value() &&
        before_checkpoint_block_cache_builds.has_value() &&
        after_checkpoint_block_cache_builds.has_value() &&
        before_checkpoint_block_bypass_builds.has_value() &&
        after_checkpoint_block_bypass_builds.has_value())
    {
        if (checkpoint_block_index_cache_disabled)
        {
            ok &= Require(
                after_checkpoint_block_cache_hits.value() == before_checkpoint_block_cache_hits.value() &&
                    after_checkpoint_block_cache_builds.value() == before_checkpoint_block_cache_builds.value() &&
                    after_checkpoint_block_bypass_builds.value() >= before_checkpoint_block_bypass_builds.value() + 4,
                "BtreeCheckpointSelection: block-index cache kill switch should rebuild checkpoint lists");
        }
        else
        {
            ok &= Require(
                after_checkpoint_block_cache_hits.value() >= before_checkpoint_block_cache_hits.value() + 4 &&
                    after_checkpoint_block_cache_builds.value() == before_checkpoint_block_cache_builds.value() &&
                    after_checkpoint_block_bypass_builds.value() == before_checkpoint_block_bypass_builds.value(),
                "BtreeCheckpointSelection: repeated commits should reuse checkpoint block-index lists");
        }
    }
    if (before_block_reads.has_value() && after_block_reads.has_value())
    {
        ok &= Require(
            after_block_reads.value() == before_block_reads.value(),
            "BtreeCheckpointSelection: metadata-only superblock switch should not add block-device reads");
    }
    if (before_btree_size_prescans.has_value() && after_btree_size_prescans.has_value())
    {
        ok &= Require(
            after_btree_size_prescans.value() == before_btree_size_prescans.value(),
            "BtreeCheckpointSelection: metadata-only btree checkpoint should build without a size prescan");
    }

    const auto committed = store.LookupCommittedInodeByPath(L"\\indexed-7.bin");
    ok &= Require(
        committed.has_value() && committed->timestamp_utc == 9090,
        "BtreeCheckpointSelection: metadata-only commit should persist the updated timestamp");

    {
        apfsaccess::rw::MetadataStore remounted(context);
        ok &= Require(
            remounted.LoadContainerSuperblocks(),
            "BtreeCheckpointSelection: remount LoadContainerSuperblocks should succeed");
        ok &= Require(
            remounted.PrepareNativeWritePath(),
            "BtreeCheckpointSelection: remount PrepareNativeWritePath should succeed");
        ok &= Require(
            !remounted.IsRecoveryRequired(),
            "BtreeCheckpointSelection: remount should not require recovery");

        const auto remounted_metadata = remounted.LookupCommittedInodeByPath(L"\\indexed-7.bin");
        ok &= Require(
            remounted_metadata.has_value() && remounted_metadata->timestamp_utc == 9090,
            "BtreeCheckpointSelection: remount should preserve updated timestamp");
        ok &= Require(
            remounted.LookupCommittedInodeByPath(L"\\indexed-13.bin").has_value(),
            "BtreeCheckpointSelection: remount should preserve unchanged sampled file");
    }

    SetEnvironmentVariableW(
        L"APFSACCESS_PERF_COUNTERS",
        had_previous_perf ? previous_perf_value : nullptr);

    return ok;
}

bool TestMetadataOnlyCommitUsesLocalSpacemanApplyConformance(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "metadata_only_spaceman_apply.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "MetadataOnlySpacemanApply: unable to create synthetic container");
    }

    wchar_t previous_perf_value[256]{};
    const auto previous_perf_chars = GetEnvironmentVariableW(
        L"APFSACCESS_PERF_COUNTERS",
        previous_perf_value,
        static_cast<DWORD>(std::size(previous_perf_value)));
    const bool had_previous_perf =
        previous_perf_chars > 0 &&
        previous_perf_chars < static_cast<DWORD>(std::size(previous_perf_value));
    SetEnvironmentVariableW(L"APFSACCESS_PERF_COUNTERS", L"1");

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"MetadataOnlySpacemanApply",
    };
    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "MetadataOnlySpacemanApply: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "MetadataOnlySpacemanApply: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "MetadataOnlySpacemanApply: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "MetadataOnlySpacemanApply: PrepareNativeWritePath should succeed");

    std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
    ConfigurePayloadProvider(store, staged_payloads);
    ok &= CreateAndCommitFile(
        store,
        staged_payloads,
        L"\\metadata-only.bin",
        2048,
        0x72,
        "MetadataOnlySpacemanApply");

    const auto before_json = store.PerformanceJson();
    const auto before_full = ExtractNestedUnsignedValue(before_json, "committedSpacemanApply", "full");
    const auto before_local = ExtractNestedUnsignedValue(before_json, "committedSpacemanApply", "local");
    const auto before_checkpoint_fast = ExtractNestedUnsignedValue(before_json, "spacemanCheckpoint", "fastPath");
    const auto before_checkpoint_fallback =
        ExtractNestedUnsignedValue(before_json, "spacemanCheckpoint", "normalizeFallback");
    const auto before_object_map_rebuilds =
        ExtractNestedUnsignedValue(before_json, "objectMapCheckpoint", "orderRebuilds");
    const auto before_object_map_hits =
        ExtractNestedUnsignedValue(before_json, "objectMapCheckpoint", "orderCacheHits");
    const auto before_inode_rebuilds =
        ExtractNestedUnsignedValue(before_json, "inodeCheckpoint", "orderRebuilds");
    const auto before_inode_hits =
        ExtractNestedUnsignedValue(before_json, "inodeCheckpoint", "orderCacheHits");
    const auto before_inode_size_hits =
        ExtractNestedUnsignedValue(before_json, "inodeCheckpoint", "sizeCacheHits");
    ok &= Require(
        before_full.has_value() &&
            before_local.has_value() &&
            before_checkpoint_fast.has_value() &&
            before_checkpoint_fallback.has_value() &&
            before_object_map_rebuilds.has_value() &&
            before_object_map_hits.has_value() &&
            before_inode_rebuilds.has_value() &&
            before_inode_hits.has_value() &&
            before_inode_size_hits.has_value(),
        "MetadataOnlySpacemanApply: committed spaceman apply counters should exist");

    apfsaccess::rw::MetadataStore::MutationRequest set_basic_info{};
    set_basic_info.operation = apfsaccess::rw::MetadataStore::MutationOperation::SetBasicInfo;
    set_basic_info.path = L"\\metadata-only.bin";
    set_basic_info.timestamp_utc = 424242;
    ok &= ExpectMutationStatus(
        store,
        set_basic_info,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "MetadataOnlySpacemanApply: metadata-only update should apply");
    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "MetadataOnlySpacemanApply: metadata-only commit should succeed");

    const auto after_json = store.PerformanceJson();
    const auto after_full = ExtractNestedUnsignedValue(after_json, "committedSpacemanApply", "full");
    const auto after_local = ExtractNestedUnsignedValue(after_json, "committedSpacemanApply", "local");
    const auto after_checkpoint_fast = ExtractNestedUnsignedValue(after_json, "spacemanCheckpoint", "fastPath");
    const auto after_checkpoint_fallback =
        ExtractNestedUnsignedValue(after_json, "spacemanCheckpoint", "normalizeFallback");
    const auto after_object_map_rebuilds =
        ExtractNestedUnsignedValue(after_json, "objectMapCheckpoint", "orderRebuilds");
    const auto after_object_map_hits =
        ExtractNestedUnsignedValue(after_json, "objectMapCheckpoint", "orderCacheHits");
    const auto after_inode_rebuilds =
        ExtractNestedUnsignedValue(after_json, "inodeCheckpoint", "orderRebuilds");
    const auto after_inode_hits =
        ExtractNestedUnsignedValue(after_json, "inodeCheckpoint", "orderCacheHits");
    const auto after_inode_size_hits =
        ExtractNestedUnsignedValue(after_json, "inodeCheckpoint", "sizeCacheHits");
    ok &= Require(
        after_full.has_value() &&
            after_local.has_value() &&
            after_checkpoint_fast.has_value() &&
            after_checkpoint_fallback.has_value() &&
            after_object_map_rebuilds.has_value() &&
            after_object_map_hits.has_value() &&
            after_inode_rebuilds.has_value() &&
            after_inode_hits.has_value() &&
            after_inode_size_hits.has_value(),
        "MetadataOnlySpacemanApply: committed spaceman apply counters should exist after metadata commit");
    if (before_full.has_value() && after_full.has_value())
    {
        ok &= Require(
            after_full.value() == before_full.value(),
            "MetadataOnlySpacemanApply: metadata-only commit should not run full committed spaceman apply");
    }
    if (before_local.has_value() && after_local.has_value())
    {
        ok &= Require(
            after_local.value() == before_local.value() + 1,
            "MetadataOnlySpacemanApply: metadata-only commit should record one local spaceman apply");
    }
    if (before_checkpoint_fast.has_value() && after_checkpoint_fast.has_value())
    {
        ok &= Require(
            after_checkpoint_fast.value() == before_checkpoint_fast.value() + 1,
            "MetadataOnlySpacemanApply: metadata-only commit should persist spaceman checkpoint without copy-normalize");
    }
    if (before_checkpoint_fallback.has_value() && after_checkpoint_fallback.has_value())
    {
        ok &= Require(
            after_checkpoint_fallback.value() == before_checkpoint_fallback.value(),
            "MetadataOnlySpacemanApply: normalized spaceman checkpoint should avoid fallback copy-normalize");
    }
    if (before_object_map_rebuilds.has_value() && after_object_map_rebuilds.has_value())
    {
        ok &= Require(
            after_object_map_rebuilds.value() == before_object_map_rebuilds.value(),
            "MetadataOnlySpacemanApply: unchanged object-map membership should avoid order rebuild");
    }
    if (before_object_map_hits.has_value() && after_object_map_hits.has_value())
    {
        ok &= Require(
            after_object_map_hits.value() > before_object_map_hits.value(),
            "MetadataOnlySpacemanApply: unchanged object-map membership should reuse cached order");
    }
    if (before_inode_rebuilds.has_value() && after_inode_rebuilds.has_value())
    {
        ok &= Require(
            after_inode_rebuilds.value() == before_inode_rebuilds.value(),
            "MetadataOnlySpacemanApply: metadata-only commit should not rebuild the inode order cache");
    }
    if (before_inode_hits.has_value() && after_inode_hits.has_value())
    {
        ok &= Require(
            after_inode_hits.value() > before_inode_hits.value(),
            "MetadataOnlySpacemanApply: metadata-only commit should reuse the inode order cache");
    }
    if (before_inode_size_hits.has_value() && after_inode_size_hits.has_value())
    {
        ok &= Require(
            after_inode_size_hits.value() > before_inode_size_hits.value(),
            "MetadataOnlySpacemanApply: metadata-only commit should reuse the cached inode checkpoint size");
    }

    const auto committed = store.LookupCommittedInodeByPath(L"\\metadata-only.bin");
    ok &= Require(
        committed.has_value() && committed->timestamp_utc == 424242,
        "MetadataOnlySpacemanApply: metadata-only commit should persist timestamp");

    {
        apfsaccess::rw::MetadataStore remounted(context);
        ok &= Require(
            remounted.LoadContainerSuperblocks(),
            "MetadataOnlySpacemanApply: remount LoadContainerSuperblocks should succeed");
        ok &= Require(
            remounted.PrepareNativeWritePath(),
            "MetadataOnlySpacemanApply: remount PrepareNativeWritePath should succeed");
        const auto remounted_inode = remounted.LookupCommittedInodeByPath(L"\\metadata-only.bin");
        ok &= Require(
            remounted_inode.has_value() && remounted_inode->timestamp_utc == 424242,
            "MetadataOnlySpacemanApply: remount should preserve timestamp");
    }

    SetEnvironmentVariableW(
        L"APFSACCESS_PERF_COUNTERS",
        had_previous_perf ? previous_perf_value : nullptr);

    return ok;
}

bool TestObjectMapOrderCacheUpdatesForSingleCreateConformance(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "object_map_order_cache_single_create.apfs.img";
    if (!CreateSyntheticContainerWithSize(image_path, 64 * 1024 * 1024))
    {
        return Require(false, "ObjectMapOrderCacheDelta: unable to create synthetic container");
    }

    wchar_t previous_perf_value[256]{};
    const auto previous_perf_chars = GetEnvironmentVariableW(
        L"APFSACCESS_PERF_COUNTERS",
        previous_perf_value,
        static_cast<DWORD>(std::size(previous_perf_value)));
    const bool had_previous_perf =
        previous_perf_chars > 0 &&
        previous_perf_chars < static_cast<DWORD>(std::size(previous_perf_value));
    SetEnvironmentVariableW(L"APFSACCESS_PERF_COUNTERS", L"1");

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"ObjectMapOrderCacheDelta",
    };
    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "ObjectMapOrderCacheDelta: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "ObjectMapOrderCacheDelta: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "ObjectMapOrderCacheDelta: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "ObjectMapOrderCacheDelta: PrepareNativeWritePath should succeed");

    std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
    ConfigurePayloadProvider(store, staged_payloads);

    constexpr std::size_t kWarmFileCount = 16;
    const auto before_working_free_sanitizes = store.WorkingFreeExtentSanitizeCount();
    const auto before_working_free_sanitize_skips = store.WorkingFreeExtentSanitizeSkipCount();
    for (std::size_t index = 0; index < kWarmFileCount; ++index)
    {
        ok &= CreateAndCommitFile(
            store,
            staged_payloads,
            L"\\warm-" + std::to_wstring(index) + L".bin",
            2048,
            static_cast<unsigned char>(0x35 + (index % 19)),
            "ObjectMapOrderCacheDelta");
    }

    const auto before_json = store.PerformanceJson();
    const auto before_rebuilds =
        ExtractNestedUnsignedValue(before_json, "objectMapCheckpoint", "orderRebuilds");
    const auto before_delta_updates =
        ExtractNestedUnsignedValue(before_json, "objectMapCheckpoint", "orderDeltaUpdates");
    const auto before_delta_fallbacks =
        ExtractNestedUnsignedValue(before_json, "objectMapCheckpoint", "orderDeltaFallbacks");
    const auto before_inode_rebuilds =
        ExtractNestedUnsignedValue(before_json, "inodeCheckpoint", "orderRebuilds");
    const auto before_inode_delta_updates =
        ExtractNestedUnsignedValue(before_json, "inodeCheckpoint", "orderDeltaUpdates");
    const auto before_inode_delta_fallbacks =
        ExtractNestedUnsignedValue(before_json, "inodeCheckpoint", "orderDeltaFallbacks");
    ok &= Require(
        before_rebuilds.has_value() &&
            before_delta_updates.has_value() &&
            before_delta_fallbacks.has_value() &&
            before_inode_rebuilds.has_value() &&
            before_inode_delta_updates.has_value() &&
            before_inode_delta_fallbacks.has_value(),
        "ObjectMapOrderCacheDelta: object-map order counters should exist before create");

    ok &= CreateAndCommitFile(
        store,
        staged_payloads,
        L"\\fresh-after-warm.bin",
        4096,
        0x7b,
        "ObjectMapOrderCacheDelta");

    const auto working_free_sanitize_delta =
        store.WorkingFreeExtentSanitizeCount() - before_working_free_sanitizes;
    const auto working_free_sanitize_skip_delta =
        store.WorkingFreeExtentSanitizeSkipCount() - before_working_free_sanitize_skips;
    ok &= Require(
        working_free_sanitize_delta == 1,
        "ObjectMapOrderCacheDelta: repeated commits should establish the working free-list once; delta=" +
            std::to_string(working_free_sanitize_delta));
    ok &= Require(
        working_free_sanitize_skip_delta >= kWarmFileCount,
        "ObjectMapOrderCacheDelta: repeated commits should reuse the working free-list; skips=" +
            std::to_string(working_free_sanitize_skip_delta));

    const auto after_json = store.PerformanceJson();
    const auto checkpoint_buffer_growths =
        ExtractNestedUnsignedValue(after_json, "checkpointSerializationBuffers", "growths");
    const auto checkpoint_buffer_reuses =
        ExtractNestedUnsignedValue(after_json, "checkpointSerializationBuffers", "reuses");
    const auto checkpoint_buffer_capacity =
        ExtractNestedUnsignedValue(after_json, "checkpointSerializationBuffers", "capacityBytes");
    wchar_t disable_buffer_reuse[8]{};
    const auto disable_buffer_reuse_chars = GetEnvironmentVariableW(
        L"APFSACCESS_DISABLE_CHECKPOINT_SERIALIZATION_BUFFER_REUSE",
        disable_buffer_reuse,
        static_cast<DWORD>(std::size(disable_buffer_reuse)));
    const bool buffer_reuse_disabled =
        disable_buffer_reuse_chars > 0 &&
        disable_buffer_reuse[0] != L'\0' &&
        disable_buffer_reuse[0] != L'0';
    if (buffer_reuse_disabled)
    {
        ok &= Require(
            checkpoint_buffer_growths.has_value() && checkpoint_buffer_growths.value() == 0 &&
                checkpoint_buffer_reuses.has_value() && checkpoint_buffer_reuses.value() == 0 &&
                checkpoint_buffer_capacity.has_value() && checkpoint_buffer_capacity.value() == 0,
            "ObjectMapOrderCacheDelta: the kill switch should restore local checkpoint serialization buffers");
    }
    else
    {
        ok &= Require(
            checkpoint_buffer_growths.has_value() &&
                checkpoint_buffer_growths.value() > 0 &&
                checkpoint_buffer_reuses.has_value() &&
                checkpoint_buffer_reuses.value() >= kWarmFileCount &&
                checkpoint_buffer_capacity.has_value() &&
                checkpoint_buffer_capacity.value() > 0,
            "ObjectMapOrderCacheDelta: repeated commits should retain checkpoint serialization capacity");
    }
    const auto after_rebuilds =
        ExtractNestedUnsignedValue(after_json, "objectMapCheckpoint", "orderRebuilds");
    const auto after_delta_updates =
        ExtractNestedUnsignedValue(after_json, "objectMapCheckpoint", "orderDeltaUpdates");
    const auto after_delta_fallbacks =
        ExtractNestedUnsignedValue(after_json, "objectMapCheckpoint", "orderDeltaFallbacks");
    const auto after_inode_rebuilds =
        ExtractNestedUnsignedValue(after_json, "inodeCheckpoint", "orderRebuilds");
    const auto after_inode_delta_updates =
        ExtractNestedUnsignedValue(after_json, "inodeCheckpoint", "orderDeltaUpdates");
    const auto after_inode_delta_fallbacks =
        ExtractNestedUnsignedValue(after_json, "inodeCheckpoint", "orderDeltaFallbacks");
    if (before_rebuilds.has_value() && after_rebuilds.has_value())
    {
        ok &= Require(
            after_rebuilds.value() == before_rebuilds.value(),
            "ObjectMapOrderCacheDelta: single create should update cached object-map order without full rebuild");
    }
    if (before_delta_updates.has_value() && after_delta_updates.has_value())
    {
        ok &= Require(
            after_delta_updates.value() == before_delta_updates.value() + 1,
            "ObjectMapOrderCacheDelta: single create should record one object-map order delta update");
    }
    if (before_delta_fallbacks.has_value() && after_delta_fallbacks.has_value())
    {
        ok &= Require(
            after_delta_fallbacks.value() == before_delta_fallbacks.value(),
            "ObjectMapOrderCacheDelta: single create should not fall back to object-map order rebuild");
    }
    if (before_inode_rebuilds.has_value() && after_inode_rebuilds.has_value())
    {
        ok &= Require(
            after_inode_rebuilds.value() == before_inode_rebuilds.value(),
            "ObjectMapOrderCacheDelta: single create should update cached inode order without full rebuild");
    }
    if (before_inode_delta_updates.has_value() && after_inode_delta_updates.has_value())
    {
        ok &= Require(
            after_inode_delta_updates.value() == before_inode_delta_updates.value() + 1,
            "ObjectMapOrderCacheDelta: single create should record one inode order delta update");
    }
    if (before_inode_delta_fallbacks.has_value() && after_inode_delta_fallbacks.has_value())
    {
        ok &= Require(
            after_inode_delta_fallbacks.value() == before_inode_delta_fallbacks.value(),
            "ObjectMapOrderCacheDelta: single create should not fall back to inode order rebuild");
    }

    std::vector<std::byte> committed_payload;
    ok &= Require(
        store.ReadCommittedFileRange(L"\\fresh-after-warm.bin", 0, 4096, committed_payload),
        "ObjectMapOrderCacheDelta: committed new payload should be readable");
    ok &= Require(
        committed_payload == staged_payloads[L"\\fresh-after-warm.bin"],
        "ObjectMapOrderCacheDelta: committed new payload should match");

    apfsaccess::rw::MetadataStore remounted(context);
    ConfigurePayloadProvider(remounted, staged_payloads);
    ok &= Require(remounted.LoadContainerSuperblocks(), "ObjectMapOrderCacheDelta: remount LoadContainerSuperblocks should succeed");
    ok &= Require(remounted.PrepareNativeWritePath(), "ObjectMapOrderCacheDelta: remount PrepareNativeWritePath should succeed");
    ok &= Require(!remounted.IsRecoveryRequired(), "ObjectMapOrderCacheDelta: remount should not require recovery");
    committed_payload.clear();
    ok &= Require(
        remounted.ReadCommittedFileRange(L"\\fresh-after-warm.bin", 0, 4096, committed_payload),
        "ObjectMapOrderCacheDelta: remounted new payload should be readable");
    ok &= Require(
        committed_payload == staged_payloads[L"\\fresh-after-warm.bin"],
        "ObjectMapOrderCacheDelta: remounted new payload should match");

    SetEnvironmentVariableW(
        L"APFSACCESS_PERF_COUNTERS",
        had_previous_perf ? previous_perf_value : nullptr);

    return ok;
}

bool TestOrderCachesUpdateManyCreatesConformance(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "order_cache_many_creates.apfs.img";
    if (!CreateSyntheticContainerWithSize(image_path, 64 * 1024 * 1024))
    {
        return Require(false, "OrderCacheManyCreates: unable to create synthetic container");
    }

    wchar_t previous_perf_value[256]{};
    const auto previous_perf_chars = GetEnvironmentVariableW(
        L"APFSACCESS_PERF_COUNTERS",
        previous_perf_value,
        static_cast<DWORD>(std::size(previous_perf_value)));
    const bool had_previous_perf =
        previous_perf_chars > 0 &&
        previous_perf_chars < static_cast<DWORD>(std::size(previous_perf_value));
    SetEnvironmentVariableW(L"APFSACCESS_PERF_COUNTERS", L"1");

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"OrderCacheManyCreates",
    };
    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "OrderCacheManyCreates: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "OrderCacheManyCreates: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "OrderCacheManyCreates: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "OrderCacheManyCreates: PrepareNativeWritePath should succeed");

    std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
    ConfigurePayloadProvider(store, staged_payloads);
    ok &= CreateAndCommitFile(
        store,
        staged_payloads,
        L"\\warm-cache.bin",
        4096,
        0x68,
        "OrderCacheManyCreates");

    const auto before_json = store.PerformanceJson();
    const auto before_object_map_rebuilds =
        ExtractNestedUnsignedValue(before_json, "objectMapCheckpoint", "orderRebuilds");
    const auto before_object_map_delta_updates =
        ExtractNestedUnsignedValue(before_json, "objectMapCheckpoint", "orderDeltaUpdates");
    const auto before_object_map_delta_fallbacks =
        ExtractNestedUnsignedValue(before_json, "objectMapCheckpoint", "orderDeltaFallbacks");
    const auto before_inode_rebuilds =
        ExtractNestedUnsignedValue(before_json, "inodeCheckpoint", "orderRebuilds");
    const auto before_inode_delta_updates =
        ExtractNestedUnsignedValue(before_json, "inodeCheckpoint", "orderDeltaUpdates");
    const auto before_inode_delta_fallbacks =
        ExtractNestedUnsignedValue(before_json, "inodeCheckpoint", "orderDeltaFallbacks");
    ok &= Require(
        before_object_map_rebuilds.has_value() &&
            before_object_map_delta_updates.has_value() &&
            before_object_map_delta_fallbacks.has_value() &&
            before_inode_rebuilds.has_value() &&
            before_inode_delta_updates.has_value() &&
            before_inode_delta_fallbacks.has_value(),
        "OrderCacheManyCreates: order cache counters should exist before burst");

    constexpr std::size_t kFileCount = 24;
    constexpr std::size_t kPayloadBytes = 4096;
    for (std::size_t index = 0; index < kFileCount; ++index)
    {
        const auto path = L"\\burst-cache-" + std::to_wstring(index) + L".bin";

        apfsaccess::rw::MetadataStore::MutationRequest create_file{};
        create_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
        create_file.path = path;
        ok &= ExpectMutationStatus(
            store,
            create_file,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "OrderCacheManyCreates: create should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_file{};
        write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_file.path = path;
        write_file.length = kPayloadBytes;
        ok &= ExpectMutationStatus(
            store,
            write_file,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "OrderCacheManyCreates: write should apply");

        staged_payloads[path] = BuildPatternPayload(
            kPayloadBytes,
            static_cast<unsigned char>(0x31 + (index % 37)));
    }

    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "OrderCacheManyCreates: burst commit should succeed");

    const auto after_json = store.PerformanceJson();
    const auto after_object_map_rebuilds =
        ExtractNestedUnsignedValue(after_json, "objectMapCheckpoint", "orderRebuilds");
    const auto after_object_map_delta_updates =
        ExtractNestedUnsignedValue(after_json, "objectMapCheckpoint", "orderDeltaUpdates");
    const auto after_object_map_delta_fallbacks =
        ExtractNestedUnsignedValue(after_json, "objectMapCheckpoint", "orderDeltaFallbacks");
    const auto after_inode_rebuilds =
        ExtractNestedUnsignedValue(after_json, "inodeCheckpoint", "orderRebuilds");
    const auto after_inode_delta_updates =
        ExtractNestedUnsignedValue(after_json, "inodeCheckpoint", "orderDeltaUpdates");
    const auto after_inode_delta_fallbacks =
        ExtractNestedUnsignedValue(after_json, "inodeCheckpoint", "orderDeltaFallbacks");

    if (before_object_map_rebuilds.has_value() && after_object_map_rebuilds.has_value())
    {
        ok &= Require(
            after_object_map_rebuilds.value() == before_object_map_rebuilds.value(),
            "OrderCacheManyCreates: burst create should avoid object-map order rebuild");
    }
    if (before_object_map_delta_updates.has_value() && after_object_map_delta_updates.has_value())
    {
        ok &= Require(
            after_object_map_delta_updates.value() >= before_object_map_delta_updates.value() + kFileCount,
            "OrderCacheManyCreates: burst create should update object-map order cache per file");
    }
    if (before_object_map_delta_fallbacks.has_value() && after_object_map_delta_fallbacks.has_value())
    {
        ok &= Require(
            after_object_map_delta_fallbacks.value() == before_object_map_delta_fallbacks.value(),
            "OrderCacheManyCreates: burst create should not fall back from object-map order delta updates");
    }
    if (before_inode_rebuilds.has_value() && after_inode_rebuilds.has_value())
    {
        ok &= Require(
            after_inode_rebuilds.value() == before_inode_rebuilds.value(),
            "OrderCacheManyCreates: burst create should avoid inode order rebuild");
    }
    if (before_inode_delta_updates.has_value() && after_inode_delta_updates.has_value())
    {
        ok &= Require(
            after_inode_delta_updates.value() >= before_inode_delta_updates.value() + kFileCount,
            "OrderCacheManyCreates: burst create should update inode order cache per file");
    }
    if (before_inode_delta_fallbacks.has_value() && after_inode_delta_fallbacks.has_value())
    {
        ok &= Require(
            after_inode_delta_fallbacks.value() == before_inode_delta_fallbacks.value(),
            "OrderCacheManyCreates: burst create should not fall back from inode order delta updates");
    }

    std::vector<std::byte> committed_payload;
    ok &= Require(
        store.ReadCommittedFileRange(L"\\burst-cache-17.bin", 0, kPayloadBytes, committed_payload),
        "OrderCacheManyCreates: sampled committed file should be readable");
    ok &= Require(
        committed_payload == staged_payloads[L"\\burst-cache-17.bin"],
        "OrderCacheManyCreates: sampled committed payload should match");

    apfsaccess::rw::MetadataStore remounted(context);
    ConfigurePayloadProvider(remounted, staged_payloads);
    ok &= Require(remounted.LoadContainerSuperblocks(), "OrderCacheManyCreates: remount LoadContainerSuperblocks should succeed");
    ok &= Require(remounted.PrepareNativeWritePath(), "OrderCacheManyCreates: remount PrepareNativeWritePath should succeed");
    ok &= Require(!remounted.IsRecoveryRequired(), "OrderCacheManyCreates: remount should not require recovery");
    committed_payload.clear();
    ok &= Require(
        remounted.ReadCommittedFileRange(L"\\burst-cache-17.bin", 0, kPayloadBytes, committed_payload),
        "OrderCacheManyCreates: remounted sampled file should be readable");
    ok &= Require(
        committed_payload == staged_payloads[L"\\burst-cache-17.bin"],
        "OrderCacheManyCreates: remounted sampled payload should match");

    SetEnvironmentVariableW(
        L"APFSACCESS_PERF_COUNTERS",
        had_previous_perf ? previous_perf_value : nullptr);

    return ok;
}

bool TestDeleteBatchUsesLocalSpacemanApplyConformance(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "delete_batch_spaceman_apply.apfs.img";
    if (!CreateSyntheticContainerWithSize(image_path, 64 * 1024 * 1024))
    {
        return Require(false, "DeleteBatchSpacemanApply: unable to create synthetic container");
    }

    wchar_t previous_perf_value[256]{};
    const auto previous_perf_chars = GetEnvironmentVariableW(
        L"APFSACCESS_PERF_COUNTERS",
        previous_perf_value,
        static_cast<DWORD>(std::size(previous_perf_value)));
    const bool had_previous_perf =
        previous_perf_chars > 0 &&
        previous_perf_chars < static_cast<DWORD>(std::size(previous_perf_value));
    SetEnvironmentVariableW(L"APFSACCESS_PERF_COUNTERS", L"1");

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"DeleteBatchSpacemanApply",
    };
    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "DeleteBatchSpacemanApply: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "DeleteBatchSpacemanApply: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "DeleteBatchSpacemanApply: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "DeleteBatchSpacemanApply: PrepareNativeWritePath should succeed");

    std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
    ConfigurePayloadProvider(store, staged_payloads);

    constexpr std::size_t kFileCount = 32;
    for (std::size_t index = 0; index < kFileCount; ++index)
    {
        ok &= CreateAndCommitFile(
            store,
            staged_payloads,
            L"\\delete-batch-" + std::to_wstring(index) + L".bin",
            4096,
            static_cast<unsigned char>(0x41 + (index % 23)),
            "DeleteBatchSpacemanApply");
    }

    const auto before_json = store.PerformanceJson();
    const auto before_full = ExtractNestedUnsignedValue(before_json, "committedSpacemanApply", "full");
    const auto before_local = ExtractNestedUnsignedValue(before_json, "committedSpacemanApply", "local");
    const auto before_free_full = ExtractNestedUnsignedValue(before_json, "committedSpacemanApply", "freeFull");
    const auto before_free_local = ExtractNestedUnsignedValue(before_json, "committedSpacemanApply", "freeLocal");
    const auto before_free_in_place =
        ExtractNestedUnsignedValue(before_json, "committedSpacemanApply", "freeLocalInPlace");
    const auto before_free_full_verifies =
        ExtractNestedUnsignedValue(before_json, "committedSpacemanApply", "freeFullVerifies");
    const auto before_free_full_verify_skips =
        ExtractNestedUnsignedValue(before_json, "committedSpacemanApply", "freeFullVerifySkips");
    ok &= Require(
        before_full.has_value() &&
            before_local.has_value() &&
            before_free_full.has_value() &&
            before_free_local.has_value() &&
            before_free_in_place.has_value() &&
            before_free_full_verifies.has_value() &&
            before_free_full_verify_skips.has_value(),
        "DeleteBatchSpacemanApply: committed spaceman apply counters should exist");

    for (std::size_t index = 0; index < kFileCount; ++index)
    {
        const auto path = L"\\delete-batch-" + std::to_wstring(index) + L".bin";
        apfsaccess::rw::MetadataStore::MutationRequest delete_file{};
        delete_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Delete;
        delete_file.path = path;
        ok &= ExpectMutationStatus(
            store,
            delete_file,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "DeleteBatchSpacemanApply: delete should apply");
        staged_payloads.erase(path);
    }

    ok &= Require(
        store.PendingDeallocationCount() >= kFileCount,
        "DeleteBatchSpacemanApply: delete batch should stage committed deallocations");
    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "DeleteBatchSpacemanApply: delete batch commit should succeed");

    const auto after_json = store.PerformanceJson();
    const auto after_full = ExtractNestedUnsignedValue(after_json, "committedSpacemanApply", "full");
    const auto after_local = ExtractNestedUnsignedValue(after_json, "committedSpacemanApply", "local");
    const auto after_free_full = ExtractNestedUnsignedValue(after_json, "committedSpacemanApply", "freeFull");
    const auto after_free_local = ExtractNestedUnsignedValue(after_json, "committedSpacemanApply", "freeLocal");
    const auto after_free_in_place =
        ExtractNestedUnsignedValue(after_json, "committedSpacemanApply", "freeLocalInPlace");
    const auto after_free_full_verifies =
        ExtractNestedUnsignedValue(after_json, "committedSpacemanApply", "freeFullVerifies");
    const auto after_free_full_verify_skips =
        ExtractNestedUnsignedValue(after_json, "committedSpacemanApply", "freeFullVerifySkips");
    ok &= Require(
        after_full.has_value() &&
            after_local.has_value() &&
            after_free_full.has_value() &&
            after_free_local.has_value() &&
            after_free_in_place.has_value() &&
            after_free_full_verifies.has_value() &&
            after_free_full_verify_skips.has_value(),
        "DeleteBatchSpacemanApply: committed spaceman apply counters should exist after delete commit");
    if (before_full.has_value() && after_full.has_value())
    {
        ok &= Require(
            after_full.value() == before_full.value(),
            "DeleteBatchSpacemanApply: delete batch should avoid full committed spaceman apply");
    }
    if (before_local.has_value() && after_local.has_value())
    {
        ok &= Require(
            after_local.value() == before_local.value() + 1,
            "DeleteBatchSpacemanApply: delete batch should record one local committed spaceman apply");
    }
    if (before_free_full.has_value() && after_free_full.has_value())
    {
        ok &= Require(
            after_free_full.value() == before_free_full.value(),
            "DeleteBatchSpacemanApply: delete batch should avoid full committed free-list replacement");
    }
    if (before_free_local.has_value() && after_free_local.has_value())
    {
        ok &= Require(
            after_free_local.value() == before_free_local.value() + 1,
            "DeleteBatchSpacemanApply: delete batch should update committed free-list with local deltas");
    }
    if (before_free_in_place.has_value() && after_free_in_place.has_value())
    {
        ok &= Require(
            after_free_in_place.value() == before_free_in_place.value() + 1,
            "DeleteBatchSpacemanApply: delete batch should update committed free-list in place");
    }
    if (before_free_full_verifies.has_value() && after_free_full_verifies.has_value())
    {
        ok &= Require(
            after_free_full_verifies.value() == before_free_full_verifies.value(),
            "DeleteBatchSpacemanApply: normal local delta should avoid full free-list compare");
    }
    if (before_free_full_verify_skips.has_value() && after_free_full_verify_skips.has_value())
    {
        ok &= Require(
            after_free_full_verify_skips.value() == before_free_full_verify_skips.value() + 1,
            "DeleteBatchSpacemanApply: normal local delta should record skipped full free-list compare");
    }

    ok &= Require(
        !store.LookupCommittedInodeByPath(L"\\delete-batch-7.bin").has_value(),
        "DeleteBatchSpacemanApply: deleted file should be absent from committed state");

    {
        apfsaccess::rw::MetadataStore remounted(context);
        ok &= Require(
            remounted.LoadContainerSuperblocks(),
            "DeleteBatchSpacemanApply: remount LoadContainerSuperblocks should succeed");
        ok &= Require(
            remounted.PrepareNativeWritePath(),
            "DeleteBatchSpacemanApply: remount PrepareNativeWritePath should succeed");
        ok &= Require(
            !remounted.IsRecoveryRequired(),
            "DeleteBatchSpacemanApply: remount should not require recovery");
        ok &= Require(
            !remounted.LookupCommittedInodeByPath(L"\\delete-batch-7.bin").has_value(),
            "DeleteBatchSpacemanApply: remount should preserve deletion");
    }

    SetEnvironmentVariableW(
        L"APFSACCESS_PERF_COUNTERS",
        had_previous_perf ? previous_perf_value : nullptr);

    return ok;
}

bool TestManyCreatesUseLocalSpacemanApplyConformance(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "many_creates_spaceman_apply.apfs.img";
    if (!CreateSyntheticContainerWithSize(image_path, 64 * 1024 * 1024))
    {
        return Require(false, "ManyCreatesSpacemanApply: unable to create synthetic container");
    }

    wchar_t previous_perf_value[256]{};
    const auto previous_perf_chars = GetEnvironmentVariableW(
        L"APFSACCESS_PERF_COUNTERS",
        previous_perf_value,
        static_cast<DWORD>(std::size(previous_perf_value)));
    const bool had_previous_perf =
        previous_perf_chars > 0 &&
        previous_perf_chars < static_cast<DWORD>(std::size(previous_perf_value));
    SetEnvironmentVariableW(L"APFSACCESS_PERF_COUNTERS", L"1");

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"ManyCreatesSpacemanApply",
    };
    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "ManyCreatesSpacemanApply: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "ManyCreatesSpacemanApply: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "ManyCreatesSpacemanApply: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "ManyCreatesSpacemanApply: PrepareNativeWritePath should succeed");

    std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
    ConfigurePayloadProvider(store, staged_payloads);

    constexpr std::size_t kFileCount = 32;
    constexpr std::size_t kPayloadBytes = 4096;
    const auto before_working_free_sanitizes = store.WorkingFreeExtentSanitizeCount();
    const auto before_working_free_sanitize_skips = store.WorkingFreeExtentSanitizeSkipCount();
    for (std::size_t index = 0; index < kFileCount; ++index)
    {
        const auto path = L"\\create-burst-" + std::to_wstring(index) + L".bin";

        apfsaccess::rw::MetadataStore::MutationRequest create_file{};
        create_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
        create_file.path = path;
        ok &= ExpectMutationStatus(
            store,
            create_file,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "ManyCreatesSpacemanApply: create should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_file{};
        write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_file.path = path;
        write_file.length = kPayloadBytes;
        ok &= ExpectMutationStatus(
            store,
            write_file,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "ManyCreatesSpacemanApply: write should apply");

        staged_payloads[path] = BuildPatternPayload(kPayloadBytes, static_cast<unsigned char>(0x21 + (index % 61)));
    }

    const auto before_json = store.PerformanceJson();
    const auto before_full = ExtractNestedUnsignedValue(before_json, "committedSpacemanApply", "full");
    const auto before_local = ExtractNestedUnsignedValue(before_json, "committedSpacemanApply", "local");
    const auto before_projected_fast = ExtractNestedUnsignedValue(
        before_json,
        "projectedSpacemanValidation",
        "fast");
    const auto before_projected_full = ExtractNestedUnsignedValue(
        before_json,
        "projectedSpacemanValidation",
        "full");
    const auto before_commit_blob_precise_reserve = ExtractNestedUnsignedValue(
        before_json,
        "commitBlobReserve",
        "precise");
    const auto before_commit_blob_reserve_fallback = ExtractNestedUnsignedValue(
        before_json,
        "commitBlobReserve",
        "fallback");
    const auto before_commit_blob_direct_fill = ExtractNestedUnsignedValue(
        before_json,
        "commitBlobReserve",
        "directFill");
    const auto before_payload_order_iterations = ExtractNestedUnsignedValue(
        before_json,
        "pendingPayloadObjectOrder",
        "orderedIterations");
    const auto before_payload_order_compactions = ExtractNestedUnsignedValue(
        before_json,
        "pendingPayloadObjectOrder",
        "compactions");
    const auto before_payload_order_tracked_objects = ExtractNestedUnsignedValue(
        before_json,
        "pendingPayloadObjectOrder",
        "trackedObjects");
    const auto before_payload_path_order_builds = ExtractNestedUnsignedValue(
        before_json,
        "pendingPayloadPathOrder",
        "builds");
    const auto before_payload_path_order_tracked_paths = ExtractNestedUnsignedValue(
        before_json,
        "pendingPayloadPathOrder",
        "trackedPaths");
    const auto before_payload_path_order_ordered_paths = ExtractNestedUnsignedValue(
        before_json,
        "pendingPayloadPathOrder",
        "orderedPaths");
    const auto before_payload_coalesce_passes = ExtractNestedUnsignedValue(
        before_json,
        "payloadWriteAlignment",
        "coalesceInPlacePasses");
    const auto before_payload_coalesced_entries = ExtractNestedUnsignedValue(
        before_json,
        "payloadWriteAlignment",
        "coalescedEntries");
    const auto before_full_snapshots = store.CommittedSpacemanFullSnapshotCount();
    ok &= Require(
        before_full.has_value() &&
            before_local.has_value() &&
            before_projected_fast.has_value() &&
            before_projected_full.has_value() &&
            before_commit_blob_precise_reserve.has_value() &&
            before_commit_blob_reserve_fallback.has_value() &&
            before_commit_blob_direct_fill.has_value() &&
            before_payload_order_iterations.has_value() &&
            before_payload_order_compactions.has_value() &&
            before_payload_order_tracked_objects.has_value() &&
            before_payload_path_order_builds.has_value() &&
            before_payload_path_order_tracked_paths.has_value() &&
            before_payload_path_order_ordered_paths.has_value() &&
            before_payload_coalesce_passes.has_value() &&
            before_payload_coalesced_entries.has_value(),
        "ManyCreatesSpacemanApply: committed spaceman apply counters should exist before commit");
    if (before_payload_order_tracked_objects.has_value())
    {
        ok &= Require(
            before_payload_order_tracked_objects.value() == kFileCount,
            "ManyCreatesSpacemanApply: pending payload object order should track every staged file");
    }
    if (before_payload_path_order_tracked_paths.has_value())
    {
        ok &= Require(
            before_payload_path_order_tracked_paths.value() == kFileCount,
            "ManyCreatesSpacemanApply: pending payload path tracker should track every staged file");
    }
    if (before_payload_path_order_ordered_paths.has_value())
    {
        ok &= Require(
            before_payload_path_order_ordered_paths.value() == 0,
            "ManyCreatesSpacemanApply: plain writes should not eagerly build the pending payload path order");
    }

    store.SetCommitStageHook([](std::string_view stage)
    {
        return stage != "before-state-persist";
    });
    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::PersistFailed,
        "ManyCreatesSpacemanApply: interrupted create batch should fail before state persist");
    store.SetCommitStageHook({});

    ok &= Require(
        store.CommittedSpacemanFullSnapshotCount() == before_full_snapshots,
        "ManyCreatesSpacemanApply: failed create batch should not take full spaceman snapshots");
    ok &= Require(
        !store.LookupCommittedInodeByPath(L"\\create-burst-17.bin").has_value(),
        "ManyCreatesSpacemanApply: failed create batch should not publish sampled file");

    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "ManyCreatesSpacemanApply: retry create batch should succeed");

    const auto working_free_sanitize_delta =
        store.WorkingFreeExtentSanitizeCount() - before_working_free_sanitizes;
    const auto working_free_sanitize_skip_delta =
        store.WorkingFreeExtentSanitizeSkipCount() - before_working_free_sanitize_skips;
    ok &= Require(
        working_free_sanitize_delta == 1,
            "ManyCreatesSpacemanApply: the first commit should sanitize once and its retry should reuse the valid working free-list; delta=" +
            std::to_string(working_free_sanitize_delta));
    ok &= Require(
        working_free_sanitize_skip_delta >= 1,
        "ManyCreatesSpacemanApply: the retry should record a working free-list sanitizer skip; skips=" +
            std::to_string(working_free_sanitize_skip_delta));

    const auto after_json = store.PerformanceJson();
    const auto after_full = ExtractNestedUnsignedValue(after_json, "committedSpacemanApply", "full");
    const auto after_local = ExtractNestedUnsignedValue(after_json, "committedSpacemanApply", "local");
    const auto after_projected_fast = ExtractNestedUnsignedValue(
        after_json,
        "projectedSpacemanValidation",
        "fast");
    const auto after_projected_full = ExtractNestedUnsignedValue(
        after_json,
        "projectedSpacemanValidation",
        "full");
    const auto after_commit_blob_precise_reserve = ExtractNestedUnsignedValue(
        after_json,
        "commitBlobReserve",
        "precise");
    const auto after_commit_blob_reserve_fallback = ExtractNestedUnsignedValue(
        after_json,
        "commitBlobReserve",
        "fallback");
    const auto after_commit_blob_direct_fill = ExtractNestedUnsignedValue(
        after_json,
        "commitBlobReserve",
        "directFill");
    const auto after_payload_order_iterations = ExtractNestedUnsignedValue(
        after_json,
        "pendingPayloadObjectOrder",
        "orderedIterations");
    const auto after_payload_order_compactions = ExtractNestedUnsignedValue(
        after_json,
        "pendingPayloadObjectOrder",
        "compactions");
    const auto after_payload_order_tracked_objects = ExtractNestedUnsignedValue(
        after_json,
        "pendingPayloadObjectOrder",
        "trackedObjects");
    const auto after_payload_path_order_builds = ExtractNestedUnsignedValue(
        after_json,
        "pendingPayloadPathOrder",
        "builds");
    const auto after_payload_path_order_tracked_paths = ExtractNestedUnsignedValue(
        after_json,
        "pendingPayloadPathOrder",
        "trackedPaths");
    const auto after_payload_coalesce_passes = ExtractNestedUnsignedValue(
        after_json,
        "payloadWriteAlignment",
        "coalesceInPlacePasses");
    const auto after_payload_coalesced_entries = ExtractNestedUnsignedValue(
        after_json,
        "payloadWriteAlignment",
        "coalescedEntries");
    if (before_full.has_value() && after_full.has_value())
    {
        ok &= Require(
            after_full.value() == before_full.value(),
            "ManyCreatesSpacemanApply: allocation-only create batch should avoid full committed spaceman apply");
    }
    if (before_local.has_value() && after_local.has_value())
    {
        ok &= Require(
            after_local.value() >= before_local.value() + 2,
            "ManyCreatesSpacemanApply: failed and retried create batch should use local committed spaceman apply");
    }
    if (before_projected_fast.has_value() && after_projected_fast.has_value())
    {
        ok &= Require(
            after_projected_fast.value() >= before_projected_fast.value() + 2,
            "ManyCreatesSpacemanApply: failed and retried create batch should use projected spaceman fast validation");
    }
    if (before_projected_full.has_value() && after_projected_full.has_value())
    {
        ok &= Require(
            after_projected_full.value() == before_projected_full.value(),
            "ManyCreatesSpacemanApply: allocation-only create batch should avoid full projected spaceman materialization");
    }
    if (before_commit_blob_precise_reserve.has_value() && after_commit_blob_precise_reserve.has_value())
    {
        ok &= Require(
            after_commit_blob_precise_reserve.value() >= before_commit_blob_precise_reserve.value() + 2,
            "ManyCreatesSpacemanApply: failed and retried create batch should reserve commit blob precisely");
    }
    if (before_commit_blob_reserve_fallback.has_value() && after_commit_blob_reserve_fallback.has_value())
    {
        ok &= Require(
            after_commit_blob_reserve_fallback.value() == before_commit_blob_reserve_fallback.value(),
            "ManyCreatesSpacemanApply: ordinary create batch should avoid commit blob reserve fallback");
    }
    if (before_commit_blob_direct_fill.has_value() && after_commit_blob_direct_fill.has_value())
    {
        ok &= Require(
            after_commit_blob_direct_fill.value() >= before_commit_blob_direct_fill.value() + 2,
            "ManyCreatesSpacemanApply: failed and retried create batch should direct-fill commit blobs");
    }
    if (before_payload_order_iterations.has_value() && after_payload_order_iterations.has_value())
    {
        ok &= Require(
            after_payload_order_iterations.value() >= before_payload_order_iterations.value() + 2,
            "ManyCreatesSpacemanApply: failed and retried create batch should iterate the ordered pending payload view");
    }
    if (before_payload_order_compactions.has_value() && after_payload_order_compactions.has_value())
    {
        ok &= Require(
            after_payload_order_compactions.value() == before_payload_order_compactions.value(),
            "ManyCreatesSpacemanApply: ordinary create batch should not compact pending payload object order");
    }
    if (after_payload_order_tracked_objects.has_value())
    {
        ok &= Require(
            after_payload_order_tracked_objects.value() == 0,
            "ManyCreatesSpacemanApply: successful commit should clear pending payload object order");
    }
    if (before_payload_path_order_builds.has_value() && after_payload_path_order_builds.has_value())
    {
        ok &= Require(
            after_payload_path_order_builds.value() == before_payload_path_order_builds.value(),
            "ManyCreatesSpacemanApply: create/write burst should not build the subtree path prefix index");
    }
    if (after_payload_path_order_tracked_paths.has_value())
    {
        ok &= Require(
            after_payload_path_order_tracked_paths.value() == 0,
            "ManyCreatesSpacemanApply: successful commit should clear pending payload path tracking");
    }
    if (before_payload_coalesce_passes.has_value() && after_payload_coalesce_passes.has_value())
    {
        ok &= Require(
            after_payload_coalesce_passes.value() >= before_payload_coalesce_passes.value() + 2,
            "ManyCreatesSpacemanApply: failed and retried create batch should compact payload writes in place");
    }
    if (before_payload_coalesced_entries.has_value() && after_payload_coalesced_entries.has_value())
    {
        ok &= Require(
            after_payload_coalesced_entries.value() == before_payload_coalesced_entries.value(),
            "ManyCreatesSpacemanApply: separate file writes should not merge payload write entries");
    }
    ok &= Require(
        store.CommittedSpacemanFullSnapshotCount() == before_full_snapshots,
        "ManyCreatesSpacemanApply: successful retry should not take full spaceman snapshots");

    std::vector<std::byte> committed_payload;
    ok &= Require(
        store.ReadCommittedFileRange(L"\\create-burst-17.bin", 0, kPayloadBytes, committed_payload),
        "ManyCreatesSpacemanApply: sampled committed file should be readable");
    ok &= Require(
        committed_payload == staged_payloads[L"\\create-burst-17.bin"],
        "ManyCreatesSpacemanApply: sampled committed payload should match");

    apfsaccess::rw::MetadataStore remounted(context);
    ConfigurePayloadProvider(remounted, staged_payloads);
    ok &= Require(remounted.LoadContainerSuperblocks(), "ManyCreatesSpacemanApply: remount LoadContainerSuperblocks should succeed");
    ok &= Require(remounted.PrepareNativeWritePath(), "ManyCreatesSpacemanApply: remount PrepareNativeWritePath should succeed");
    ok &= Require(!remounted.IsRecoveryRequired(), "ManyCreatesSpacemanApply: remount should not require recovery");
    committed_payload.clear();
    ok &= Require(
        remounted.ReadCommittedFileRange(L"\\create-burst-17.bin", 0, kPayloadBytes, committed_payload),
        "ManyCreatesSpacemanApply: remounted sampled file should be readable");
    ok &= Require(
        committed_payload == staged_payloads[L"\\create-burst-17.bin"],
        "ManyCreatesSpacemanApply: remounted sampled payload should match");

    SetEnvironmentVariableW(
        L"APFSACCESS_PERF_COUNTERS",
        had_previous_perf ? previous_perf_value : nullptr);

    return ok;
}

bool TestCommitStageHookKeepsFreeListFullCompareConformance(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "hook_free_list_compare.apfs.img";
    if (!CreateSyntheticContainerWithSize(image_path, 64 * 1024 * 1024))
    {
        return Require(false, "HookFreeListCompare: unable to create synthetic container");
    }

    wchar_t previous_perf_value[256]{};
    const auto previous_perf_chars = GetEnvironmentVariableW(
        L"APFSACCESS_PERF_COUNTERS",
        previous_perf_value,
        static_cast<DWORD>(std::size(previous_perf_value)));
    const bool had_previous_perf =
        previous_perf_chars > 0 &&
        previous_perf_chars < static_cast<DWORD>(std::size(previous_perf_value));
    SetEnvironmentVariableW(L"APFSACCESS_PERF_COUNTERS", L"1");

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"HookFreeListCompare",
    };
    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "HookFreeListCompare: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "HookFreeListCompare: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "HookFreeListCompare: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "HookFreeListCompare: PrepareNativeWritePath should succeed");

    std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
    ConfigurePayloadProvider(store, staged_payloads);

    constexpr std::size_t kFileCount = 4;
    for (std::size_t index = 0; index < kFileCount; ++index)
    {
        ok &= CreateAndCommitFile(
            store,
            staged_payloads,
            L"\\hook-delete-" + std::to_wstring(index) + L".bin",
            4096,
            static_cast<unsigned char>(0x61 + index),
            "HookFreeListCompare");
    }

    const auto before_json = store.PerformanceJson();
    const auto before_full_verifies =
        ExtractNestedUnsignedValue(before_json, "committedSpacemanApply", "freeFullVerifies");
    const auto before_verify_skips =
        ExtractNestedUnsignedValue(before_json, "committedSpacemanApply", "freeFullVerifySkips");
    const auto before_checkpoint_buffer_growths =
        ExtractNestedUnsignedValue(before_json, "checkpointSerializationBuffers", "growths");
    const auto before_checkpoint_buffer_reuses =
        ExtractNestedUnsignedValue(before_json, "checkpointSerializationBuffers", "reuses");
    const auto before_checkpoint_batches =
        ExtractNestedUnsignedValue(before_json, "checkpointFamilyBatch", "count");
    ok &= Require(
        before_full_verifies.has_value() &&
            before_verify_skips.has_value() &&
            before_checkpoint_buffer_growths.has_value() &&
            before_checkpoint_buffer_reuses.has_value() &&
            before_checkpoint_batches.has_value(),
        "HookFreeListCompare: verification and checkpoint-buffer counters should exist before delete");

    store.SetCommitStageHook([](std::string_view)
    {
        return true;
    });

    for (std::size_t index = 0; index < kFileCount; ++index)
    {
        const auto path = L"\\hook-delete-" + std::to_wstring(index) + L".bin";
        apfsaccess::rw::MetadataStore::MutationRequest delete_file{};
        delete_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Delete;
        delete_file.path = path;
        ok &= ExpectMutationStatus(
            store,
            delete_file,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "HookFreeListCompare: delete should apply");
        staged_payloads.erase(path);
    }

    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "HookFreeListCompare: hooked delete batch commit should succeed");

    const auto after_json = store.PerformanceJson();
    const auto after_full_verifies =
        ExtractNestedUnsignedValue(after_json, "committedSpacemanApply", "freeFullVerifies");
    const auto after_verify_skips =
        ExtractNestedUnsignedValue(after_json, "committedSpacemanApply", "freeFullVerifySkips");
    const auto after_checkpoint_buffer_growths =
        ExtractNestedUnsignedValue(after_json, "checkpointSerializationBuffers", "growths");
    const auto after_checkpoint_buffer_reuses =
        ExtractNestedUnsignedValue(after_json, "checkpointSerializationBuffers", "reuses");
    const auto after_checkpoint_batches =
        ExtractNestedUnsignedValue(after_json, "checkpointFamilyBatch", "count");
    ok &= Require(
        after_full_verifies.has_value() &&
            after_verify_skips.has_value() &&
            after_checkpoint_buffer_growths.has_value() &&
            after_checkpoint_buffer_reuses.has_value() &&
            after_checkpoint_batches.has_value(),
        "HookFreeListCompare: verification and checkpoint-buffer counters should exist after delete");
    if (before_full_verifies.has_value() && after_full_verifies.has_value())
    {
        ok &= Require(
            after_full_verifies.value() == before_full_verifies.value() + 1,
            "HookFreeListCompare: commit-stage hook should keep full free-list compare");
    }
    if (before_verify_skips.has_value() && after_verify_skips.has_value())
    {
        ok &= Require(
            after_verify_skips.value() == before_verify_skips.value(),
            "HookFreeListCompare: commit-stage hook should not skip full free-list compare");
    }
    if (before_checkpoint_batches.has_value() && after_checkpoint_batches.has_value())
    {
        ok &= Require(
            after_checkpoint_batches.value() == before_checkpoint_batches.value(),
            "HookFreeListCompare: strict commit-stage hook should keep checkpoint-family batching disabled");
    }
    if (before_checkpoint_buffer_growths.has_value() &&
        after_checkpoint_buffer_growths.has_value() &&
        before_checkpoint_buffer_reuses.has_value() &&
        after_checkpoint_buffer_reuses.has_value())
    {
        ok &= Require(
            after_checkpoint_buffer_growths.value() == before_checkpoint_buffer_growths.value() &&
                after_checkpoint_buffer_reuses.value() == before_checkpoint_buffer_reuses.value(),
            "HookFreeListCompare: strict round-trip commits should keep local checkpoint serialization buffers");
    }

    ok &= Require(
        !store.LookupCommittedInodeByPath(L"\\hook-delete-2.bin").has_value(),
        "HookFreeListCompare: hooked delete batch should remove committed file");

    SetEnvironmentVariableW(
        L"APFSACCESS_PERF_COUNTERS",
        had_previous_perf ? previous_perf_value : nullptr);

    return ok;
}

bool TestSpacemanRollbackAvoidsFullSnapshotConformance(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "spaceman_rollback_delta.apfs.img";
    if (!CreateSyntheticContainerWithSize(image_path, 64 * 1024 * 1024))
    {
        return Require(false, "SpacemanRollbackDelta: unable to create synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"SpacemanRollbackDelta",
    };
    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "SpacemanRollbackDelta: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "SpacemanRollbackDelta: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "SpacemanRollbackDelta: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "SpacemanRollbackDelta: PrepareNativeWritePath should succeed");

    std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
    ConfigurePayloadProvider(store, staged_payloads);

    constexpr std::size_t kFileCount = 8;
    for (std::size_t index = 0; index < kFileCount; ++index)
    {
        ok &= CreateAndCommitFile(
            store,
            staged_payloads,
            L"\\rollback-delete-" + std::to_wstring(index) + L".bin",
            4096,
            static_cast<unsigned char>(0x51 + index),
            "SpacemanRollbackDelta");
    }

    const auto before_allocations = store.CommittedAllocationCount();
    const auto before_free_extents = store.CommittedFreeExtentCount();
    const auto before_full_snapshots = store.CommittedSpacemanFullSnapshotCount();
    ok &= Require(
        store.LookupCommittedInodeByPath(L"\\rollback-delete-3.bin").has_value(),
        "SpacemanRollbackDelta: sampled committed file should exist before delete");

    for (std::size_t index = 0; index < kFileCount; ++index)
    {
        const auto path = L"\\rollback-delete-" + std::to_wstring(index) + L".bin";
        apfsaccess::rw::MetadataStore::MutationRequest delete_file{};
        delete_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Delete;
        delete_file.path = path;
        ok &= ExpectMutationStatus(
            store,
            delete_file,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "SpacemanRollbackDelta: delete should apply");
        staged_payloads.erase(path);
    }

    store.SetCommitStageHook([](std::string_view stage)
    {
        return stage != "before-state-persist";
    });
    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::PersistFailed,
        "SpacemanRollbackDelta: commit should fail before state persist");
    store.SetCommitStageHook({});

    ok &= Require(
        store.LookupCommittedInodeByPath(L"\\rollback-delete-3.bin").has_value(),
        "SpacemanRollbackDelta: failed delete commit should not publish deletion");
    ok &= Require(
        store.CommittedAllocationCount() == before_allocations,
        "SpacemanRollbackDelta: committed allocations should roll back after failure");
    ok &= Require(
        store.CommittedFreeExtentCount() == before_free_extents,
        "SpacemanRollbackDelta: committed free-list should roll back after failure");
    ok &= Require(
        store.CommittedSpacemanFullSnapshotCount() == before_full_snapshots,
        "SpacemanRollbackDelta: rollback should not use full spaceman snapshots");

    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "SpacemanRollbackDelta: retry delete commit should succeed");
    ok &= Require(
        !store.LookupCommittedInodeByPath(L"\\rollback-delete-3.bin").has_value(),
        "SpacemanRollbackDelta: retry should publish deletion");
    ok &= Require(
        store.CommittedSpacemanFullSnapshotCount() == before_full_snapshots,
        "SpacemanRollbackDelta: successful retry should not use full spaceman snapshots");

    return ok;
}

bool TestExtentShapeTelemetryConformance(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "extent_shape_telemetry.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "ExtentShapeTelemetry: unable to create synthetic container");
    }

    wchar_t previous_perf_value[256]{};
    const auto previous_perf_chars = GetEnvironmentVariableW(
        L"APFSACCESS_PERF_COUNTERS",
        previous_perf_value,
        static_cast<DWORD>(std::size(previous_perf_value)));
    const bool had_previous_perf =
        previous_perf_chars > 0 &&
        previous_perf_chars < static_cast<DWORD>(std::size(previous_perf_value));
    SetEnvironmentVariableW(L"APFSACCESS_PERF_COUNTERS", L"1");

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"ExtentShapeTelemetry",
    };
    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "ExtentShapeTelemetry: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "ExtentShapeTelemetry: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "ExtentShapeTelemetry: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "ExtentShapeTelemetry: PrepareNativeWritePath should succeed");

    std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
    ConfigurePayloadProvider(store, staged_payloads);

    ok &= CreateAndCommitFile(
        store,
        staged_payloads,
        L"\\single-extent.bin",
        4096,
        0x42,
        "ExtentShapeTelemetry");
    ok &= CreateAndCommitFile(
        store,
        staged_payloads,
        L"\\fragmented-extent.bin",
        8192,
        0x58,
        "ExtentShapeTelemetry");

    const auto fragmented_inode = store.LookupCommittedInodeByPath(L"\\fragmented-extent.bin");
    ok &= Require(
        fragmented_inode.has_value(),
        "ExtentShapeTelemetry: fragmented inode should exist");
    if (fragmented_inode.has_value())
    {
        ok &= Require(
            store.SetCommittedReadExtents(
                fragmented_inode->object_id,
                {
                    { 0, 700ull * kBlockSize, 4096 },
                    { 4096, 704ull * kBlockSize, 4096 },
                }),
            "ExtentShapeTelemetry: committed read extents should accept fragmented projection");
    }

    const auto perf = store.PerformanceJson();
    const auto allocation_count = ExtractPerfCounterCount(perf, "allocationLookup");
    const auto free_list_count = ExtractPerfCounterCount(perf, "freeListLookup");
    ok &= Require(
        allocation_count.has_value() && allocation_count.value() >= 2,
        "ExtentShapeTelemetry: allocation lookup counter should track file allocations");
    ok &= Require(
        free_list_count.has_value() && free_list_count.value() >= 2,
        "ExtentShapeTelemetry: free-list lookup counter should track allocator searches");

    const auto file_count = ExtractNestedUnsignedValue(perf, "committedExtentShape", "files");
    const auto extent_count = ExtractNestedUnsignedValue(perf, "committedExtentShape", "extents");
    const auto average_x1000 = ExtractNestedUnsignedValue(perf, "committedExtentShape", "averageExtentsPerFileTimes1000");
    const auto fragmentation_score = ExtractNestedUnsignedValue(perf, "committedExtentShape", "fragmentationScore");
    const auto max_extents = ExtractNestedUnsignedValue(perf, "committedExtentShape", "maxExtentsPerFile");
    ok &= Require(
        file_count.has_value() &&
            extent_count.has_value() &&
            average_x1000.has_value() &&
            fragmentation_score.has_value() &&
            max_extents.has_value(),
        "ExtentShapeTelemetry: committed extent shape counters should exist");
    if (file_count.has_value() &&
        extent_count.has_value() &&
        average_x1000.has_value() &&
        fragmentation_score.has_value() &&
        max_extents.has_value())
    {
        ok &= Require(file_count.value() == 2, "ExtentShapeTelemetry: file count should include tracked data files");
        ok &= Require(extent_count.value() == 3, "ExtentShapeTelemetry: extent count should include fragmented file extents");
        ok &= Require(
            average_x1000.value() == 1500,
            "ExtentShapeTelemetry: average extents per file should be scaled by 1000");
        ok &= Require(
            fragmentation_score.value() == 1,
            "ExtentShapeTelemetry: fragmentation score should count extra extents beyond one per file");
        ok &= Require(
            max_extents.value() == 2,
            "ExtentShapeTelemetry: max extents per file should expose worst fragmented file");
    }

    SetEnvironmentVariableW(
        L"APFSACCESS_PERF_COUNTERS",
        had_previous_perf ? previous_perf_value : nullptr);

    return ok;
}

bool TestCommitRestoreDedupeAvoidsLinearScansConformance(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "commit_restore_dedupe.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "CommitRestoreDedupe: unable to create synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"CommitRestoreDedupe",
    };
    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "CommitRestoreDedupe: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "CommitRestoreDedupe: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "CommitRestoreDedupe: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "CommitRestoreDedupe: PrepareNativeWritePath should succeed");

    std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
    ConfigurePayloadProvider(store, staged_payloads);

    constexpr std::size_t kFileCount = 96;
    constexpr std::size_t kPayloadBytes = 1536;
    for (std::size_t index = 0; index < kFileCount; ++index)
    {
        const auto path = L"\\small-" + std::to_wstring(index) + L".bin";

        apfsaccess::rw::MetadataStore::MutationRequest create_file{};
        create_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
        create_file.path = path;
        ok &= ExpectMutationStatus(
            store,
            create_file,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "CommitRestoreDedupe: create file should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_file{};
        write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_file.path = path;
        write_file.length = kPayloadBytes;
        ok &= ExpectMutationStatus(
            store,
            write_file,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "CommitRestoreDedupe: write file should apply");
        staged_payloads[path] = BuildPatternPayload(kPayloadBytes, static_cast<unsigned char>(0x31 + index));
    }

    const auto before_json = store.PerformanceJson();
    const auto before_scans = ExtractNestedUnsignedValue(before_json, "commitRestoreDedupe", "linearScans");
    ok &= Require(
        before_scans.has_value(),
        "CommitRestoreDedupe: commit restore dedupe counter should exist");

    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "CommitRestoreDedupe: many-small-file commit should succeed");

    const auto after_json = store.PerformanceJson();
    const auto after_scans = ExtractNestedUnsignedValue(after_json, "commitRestoreDedupe", "linearScans");
    ok &= Require(
        after_scans.has_value(),
        "CommitRestoreDedupe: commit restore dedupe counter should exist after commit");
    if (before_scans.has_value() && after_scans.has_value())
    {
        ok &= Require(
            after_scans.value() == before_scans.value(),
            "CommitRestoreDedupe: many-small-file commit should not need linear restore dedupe scans");
    }

    std::vector<std::byte> committed_payload;
    ok &= Require(
        store.ReadCommittedFileRange(L"\\small-37.bin", 0, kPayloadBytes, committed_payload),
        "CommitRestoreDedupe: sampled committed payload should be readable");
    ok &= Require(
        committed_payload == staged_payloads[L"\\small-37.bin"],
        "CommitRestoreDedupe: sampled committed payload should be intact");

    return ok;
}

bool TestMutationRestoreDedupeUsesHashForLargeSubtreeRenameConformance(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "mutation_restore_dedupe_subtree_rename.apfs.img";
    if (!CreateSyntheticContainerWithSize(image_path, 64 * 1024 * 1024))
    {
        return Require(false, "MutationRestoreDedupe: unable to create synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"MutationRestoreDedupe",
    };
    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "MutationRestoreDedupe: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "MutationRestoreDedupe: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "MutationRestoreDedupe: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "MutationRestoreDedupe: PrepareNativeWritePath should succeed");

    std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
    ConfigurePayloadProvider(store, staged_payloads);

    apfsaccess::rw::MetadataStore::MutationRequest create_directory{};
    create_directory.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateDirectory;
    create_directory.path = L"\\parent";
    ok &= ExpectMutationStatus(
        store,
        create_directory,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "MutationRestoreDedupe: create parent should apply");

    constexpr std::size_t kChildCount = 40;
    constexpr std::size_t kPayloadBytes = 1024;
    for (std::size_t index = 0; index < kChildCount; ++index)
    {
        const auto path = L"\\parent\\child-" + std::to_wstring(index) + L".bin";
        apfsaccess::rw::MetadataStore::MutationRequest create_child{};
        create_child.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
        create_child.path = path;
        ok &= ExpectMutationStatus(
            store,
            create_child,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "MutationRestoreDedupe: create child should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_child{};
        write_child.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_child.path = path;
        write_child.length = kPayloadBytes;
        ok &= ExpectMutationStatus(
            store,
            write_child,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "MutationRestoreDedupe: write child should apply");
        staged_payloads[path] = BuildPatternPayload(kPayloadBytes, static_cast<unsigned char>(0x40 + index));
    }

    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "MutationRestoreDedupe: baseline commit should succeed");

    const auto before_json = store.PerformanceJson();
    const auto before_hash_fast_paths = ExtractNestedUnsignedValue(
        before_json,
        "mutationRestoreDedupe",
        "hashFastPaths");
    ok &= Require(
        before_hash_fast_paths.has_value(),
        "MutationRestoreDedupe: hash fast-path counter should exist");

    apfsaccess::rw::MetadataStore::MutationRequest rename_parent{};
    rename_parent.operation = apfsaccess::rw::MetadataStore::MutationOperation::Rename;
    rename_parent.path = L"\\parent";
    rename_parent.secondary_path = L"\\renamed-parent";
    ok &= ExpectMutationStatus(
        store,
        rename_parent,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "MutationRestoreDedupe: large subtree rename should apply");

    const auto after_rename_json = store.PerformanceJson();
    const auto after_hash_fast_paths = ExtractNestedUnsignedValue(
        after_rename_json,
        "mutationRestoreDedupe",
        "hashFastPaths");
    ok &= Require(
        after_hash_fast_paths.has_value(),
        "MutationRestoreDedupe: hash fast-path counter should exist after rename");
    if (before_hash_fast_paths.has_value() && after_hash_fast_paths.has_value())
    {
        ok &= Require(
            after_hash_fast_paths.value() > before_hash_fast_paths.value(),
            "MutationRestoreDedupe: large subtree rename should use hash-backed restore dedupe");
    }

    for (std::size_t index = 0; index < kChildCount; ++index)
    {
        const auto old_path = L"\\parent\\child-" + std::to_wstring(index) + L".bin";
        const auto new_path = L"\\renamed-parent\\child-" + std::to_wstring(index) + L".bin";
        staged_payloads[new_path] = staged_payloads[old_path];
        staged_payloads.erase(old_path);
    }

    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "MutationRestoreDedupe: rename commit should succeed");

    std::vector<std::byte> committed_payload;
    ok &= Require(
        store.ReadCommittedFileRange(L"\\renamed-parent\\child-37.bin", 0, kPayloadBytes, committed_payload),
        "MutationRestoreDedupe: sampled renamed child payload should be readable");
    ok &= Require(
        committed_payload == staged_payloads[L"\\renamed-parent\\child-37.bin"],
        "MutationRestoreDedupe: sampled renamed child payload should be intact");
    ok &= Require(
        !store.LookupCommittedInodeByPath(L"\\parent\\child-37.bin").has_value(),
        "MutationRestoreDedupe: old sampled child path should be absent");

    return ok;
}

bool TestCommitBlobSharesPayloadBatchConformance(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "commit_blob_payload_batch.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "CommitBlobPayloadBatch: unable to create synthetic container");
    }

    wchar_t previous_perf_value[256]{};
    const auto previous_perf_chars = GetEnvironmentVariableW(
        L"APFSACCESS_PERF_COUNTERS",
        previous_perf_value,
        static_cast<DWORD>(std::size(previous_perf_value)));
    const bool had_previous_perf =
        previous_perf_chars > 0 &&
        previous_perf_chars < static_cast<DWORD>(std::size(previous_perf_value));
    SetEnvironmentVariableW(L"APFSACCESS_PERF_COUNTERS", L"1");

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"CommitBlobPayloadBatch",
    };
    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "CommitBlobPayloadBatch: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "CommitBlobPayloadBatch: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "CommitBlobPayloadBatch: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "CommitBlobPayloadBatch: PrepareNativeWritePath should succeed");

    std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
    ConfigurePayloadProvider(store, staged_payloads);

    constexpr std::size_t kPayloadBytes = 8192;
    const auto path = L"\\batch-commit.bin";

    apfsaccess::rw::MetadataStore::MutationRequest create_file{};
    create_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
    create_file.path = path;
    ok &= ExpectMutationStatus(
        store,
        create_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "CommitBlobPayloadBatch: create file should apply");

    apfsaccess::rw::MetadataStore::MutationRequest write_file{};
    write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
    write_file.path = path;
    write_file.length = kPayloadBytes;
    ok &= ExpectMutationStatus(
        store,
        write_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "CommitBlobPayloadBatch: write file should apply");
    staged_payloads[path] = BuildPatternPayload(kPayloadBytes, 0x91);

    std::size_t observed_commit_stages = 0;
    store.SetCommitStageHook(
        [&observed_commit_stages](std::string_view)
        {
            ++observed_commit_stages;
            return true;
        },
        false);

    const auto before_json = store.PerformanceJson();
    const auto before_batch_writes = ExtractNestedPerfCounterCount(before_json, "blockDevice", "batchWrite");
    const auto before_direct_writes = ExtractNestedPerfCounterCount(before_json, "blockDevice", "write");
    const auto before_checkpoint_batches = ExtractNestedUnsignedValue(before_json, "checkpointFamilyBatch", "count");
    const auto before_checkpoint_batch_writes = ExtractNestedUnsignedValue(before_json, "checkpointFamilyBatch", "writes");
    const auto before_checkpoint_pads = ExtractNestedUnsignedValue(before_json, "checkpointWritePadding", "pads");
    const auto before_checkpoint_pad_bytes = ExtractNestedUnsignedValue(before_json, "checkpointWritePadding", "padBytes");
    const auto before_checkpoint_partial_materializations =
        ExtractNestedUnsignedValue(before_json, "checkpointWritePadding", "partialMaterializations");
    ok &= Require(
        before_batch_writes.has_value() &&
            before_direct_writes.has_value() &&
            before_checkpoint_batches.has_value() &&
            before_checkpoint_batch_writes.has_value() &&
            before_checkpoint_pads.has_value() &&
            before_checkpoint_pad_bytes.has_value() &&
            before_checkpoint_partial_materializations.has_value(),
        "CommitBlobPayloadBatch: block device and checkpoint batch counters should exist before commit");

    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "CommitBlobPayloadBatch: content commit should succeed");
    ok &= Require(
        observed_commit_stages > 0,
        "CommitBlobPayloadBatch: non-strict commit-stage hook should still observe commit stages");

    const auto after_json = store.PerformanceJson();
    const auto after_batch_writes = ExtractNestedPerfCounterCount(after_json, "blockDevice", "batchWrite");
    const auto after_direct_writes = ExtractNestedPerfCounterCount(after_json, "blockDevice", "write");
    const auto after_checkpoint_batches = ExtractNestedUnsignedValue(after_json, "checkpointFamilyBatch", "count");
    const auto after_checkpoint_batch_writes = ExtractNestedUnsignedValue(after_json, "checkpointFamilyBatch", "writes");
    const auto after_checkpoint_pads = ExtractNestedUnsignedValue(after_json, "checkpointWritePadding", "pads");
    const auto after_checkpoint_pad_bytes = ExtractNestedUnsignedValue(after_json, "checkpointWritePadding", "padBytes");
    const auto after_checkpoint_partial_materializations =
        ExtractNestedUnsignedValue(after_json, "checkpointWritePadding", "partialMaterializations");
    ok &= Require(
        after_batch_writes.has_value() &&
            after_direct_writes.has_value() &&
            after_checkpoint_batches.has_value() &&
            after_checkpoint_batch_writes.has_value() &&
            after_checkpoint_pads.has_value() &&
            after_checkpoint_pad_bytes.has_value() &&
            after_checkpoint_partial_materializations.has_value(),
        "CommitBlobPayloadBatch: block device and checkpoint batch counters should exist after commit");
    if (before_batch_writes.has_value() && after_batch_writes.has_value())
    {
        ok &= Require(
            after_batch_writes.value() >= before_batch_writes.value() + 2,
            "CommitBlobPayloadBatch: payload/commit blob and checkpoint families should use batch writes");
    }
    if (before_checkpoint_batches.has_value() && after_checkpoint_batches.has_value())
    {
        ok &= Require(
            after_checkpoint_batches.value() == before_checkpoint_batches.value() + 1,
            "CommitBlobPayloadBatch: full checkpoint families should be written in one normal-path batch");
    }
    if (before_checkpoint_batch_writes.has_value() && after_checkpoint_batch_writes.has_value())
    {
        ok &= Require(
            after_checkpoint_batch_writes.value() >= before_checkpoint_batch_writes.value() + 5,
            "CommitBlobPayloadBatch: checkpoint family batch should include object-map, spaceman, inode, btree, and replay writes");
    }
    if (before_checkpoint_pads.has_value() && after_checkpoint_pads.has_value())
    {
        ok &= Require(
            after_checkpoint_pads.value() >= before_checkpoint_pads.value() + 4,
            "CommitBlobPayloadBatch: chunked checkpoint families should be padded before batching");
    }
    if (before_checkpoint_pad_bytes.has_value() && after_checkpoint_pad_bytes.has_value())
    {
        ok &= Require(
            after_checkpoint_pad_bytes.value() > before_checkpoint_pad_bytes.value(),
            "CommitBlobPayloadBatch: checkpoint padding should add block-tail bytes");
    }
    if (before_checkpoint_partial_materializations.has_value() &&
        after_checkpoint_partial_materializations.has_value())
    {
        ok &= Require(
            after_checkpoint_partial_materializations.value() == before_checkpoint_partial_materializations.value(),
            "CommitBlobPayloadBatch: padded checkpoint writes should avoid partial-tail materialization");
    }
    if (before_direct_writes.has_value() && after_direct_writes.has_value())
    {
        ok &= Require(
            (after_direct_writes.value() - before_direct_writes.value()) <= 2,
            "CommitBlobPayloadBatch: commit blob should not add a separate direct block write");
    }

    std::vector<std::byte> committed_payload;
    ok &= Require(
        store.ReadCommittedFileRange(path, 0, kPayloadBytes, committed_payload),
        "CommitBlobPayloadBatch: committed payload should be readable");
    ok &= Require(
        committed_payload == staged_payloads[path],
        "CommitBlobPayloadBatch: committed payload should match staged bytes");

    {
        apfsaccess::rw::MetadataStore remounted(context);
        ok &= Require(
            remounted.LoadContainerSuperblocks(),
            "CommitBlobPayloadBatch: remount LoadContainerSuperblocks should succeed");
        ok &= Require(
            remounted.PrepareNativeWritePath(),
            "CommitBlobPayloadBatch: remount PrepareNativeWritePath should succeed");
        std::vector<std::byte> remounted_payload;
        ok &= Require(
            remounted.ReadCommittedFileRange(path, 0, kPayloadBytes, remounted_payload),
            "CommitBlobPayloadBatch: remounted payload should be readable");
        ok &= Require(
            remounted_payload == staged_payloads[path],
            "CommitBlobPayloadBatch: remounted payload should match staged bytes");
    }

    SetEnvironmentVariableW(
        L"APFSACCESS_PERF_COUNTERS",
        had_previous_perf ? previous_perf_value : nullptr);

    return ok;
}

bool TestNonStrictCommitStageHookStillInterruptsCommitConformance(
    const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "non_strict_commit_stage_interrupt.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "NonStrictCommitStageInterrupt: unable to create synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"NonStrictCommitStageInterrupt",
    };
    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "NonStrictCommitStageInterrupt: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "NonStrictCommitStageInterrupt: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "NonStrictCommitStageInterrupt: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "NonStrictCommitStageInterrupt: PrepareNativeWritePath should succeed");

    std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
    ConfigurePayloadProvider(store, staged_payloads);

    apfsaccess::rw::MetadataStore::MutationRequest create_file{};
    create_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
    create_file.path = L"\\timeout.bin";
    ok &= ExpectMutationStatus(
        store,
        create_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "NonStrictCommitStageInterrupt: create should apply");

    apfsaccess::rw::MetadataStore::MutationRequest write_file{};
    write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
    write_file.path = create_file.path;
    write_file.length = 4096;
    ok &= ExpectMutationStatus(
        store,
        write_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "NonStrictCommitStageInterrupt: write should apply");
    staged_payloads[create_file.path] = BuildPatternPayload(4096, 0xA7);

    bool reached_checkpoint_batch = false;
    store.SetCommitStageHook(
        [&reached_checkpoint_batch](std::string_view stage)
        {
            if (stage == "before-checkpoint-batch-persist")
            {
                reached_checkpoint_batch = true;
                return false;
            }
            return true;
        },
        false);

    const auto commit = store.CommitPendingMutations();
    ok &= Require(
        reached_checkpoint_batch,
        "NonStrictCommitStageInterrupt: non-strict hook should observe the checkpoint-batch boundary");
    ok &= Require(
        commit == apfsaccess::rw::MetadataStore::CommitStatus::PersistFailed,
        "NonStrictCommitStageInterrupt: rejected checkpoint batch should fail the commit");
    ok &= Require(
        store.IsRecoveryRequired() &&
            store.RecoveryReason() == L"CommitInterruptedBeforeCheckpointBatchPersist",
        "NonStrictCommitStageInterrupt: rejected checkpoint batch should fail closed for recovery");
    return ok;
}

bool TestCheckpointBatchHookFailureRetainsRecoveryAcrossRemountConformance(
    const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "checkpoint_batch_hook_retained.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "CheckpointBatchHookRetained: unable to create synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"CheckpointBatchHookRetained",
    };
    bool ok = true;
    const auto baseline_payload = BuildPatternPayload(4096, 0x5B);
    {
        apfsaccess::rw::MetadataStore store(context);
        ok &= Require(store.LoadContainerSuperblocks(), "CheckpointBatchHookRetained: LoadContainerSuperblocks should succeed");
        ok &= Require(store.LoadObjectMap(), "CheckpointBatchHookRetained: LoadObjectMap should succeed");
        ok &= Require(store.LoadSpacemanState(), "CheckpointBatchHookRetained: LoadSpacemanState should succeed");
        ok &= Require(store.PrepareNativeWritePath(), "CheckpointBatchHookRetained: PrepareNativeWritePath should succeed");

        std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
        ConfigurePayloadProvider(store, staged_payloads);

        apfsaccess::rw::MetadataStore::MutationRequest create_baseline{};
        create_baseline.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
        create_baseline.path = L"\\baseline.bin";
        apfsaccess::rw::MetadataStore::MutationRequest write_baseline{};
        write_baseline.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_baseline.path = create_baseline.path;
        write_baseline.length = 4096;
        staged_payloads[create_baseline.path] = baseline_payload;
        ok &= Require(
            store.ApplyMutation(create_baseline) == apfsaccess::rw::MetadataStore::MutationStatus::Applied &&
                store.ApplyMutation(write_baseline) == apfsaccess::rw::MetadataStore::MutationStatus::Applied &&
                store.CommitPendingMutations() == apfsaccess::rw::MetadataStore::CommitStatus::Committed,
            "CheckpointBatchHookRetained: baseline");
        std::vector<std::byte> baseline_committed;
        ok &= Require(
            store.ReadCommittedFileRange(L"\\baseline.bin", 0, baseline_payload.size(), baseline_committed) &&
                baseline_committed == baseline_payload,
            "CheckpointBatchHookRetained: baseline payload should round-trip before the interruption");

        apfsaccess::rw::MetadataStore::MutationRequest create_interrupted{};
        create_interrupted.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
        create_interrupted.path = L"\\interrupted.bin";
        ok &= ExpectMutationStatus(
            store,
            create_interrupted,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "CheckpointBatchHookRetained: interrupted create should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_interrupted{};
        write_interrupted.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_interrupted.path = create_interrupted.path;
        write_interrupted.length = 4096;
        ok &= ExpectMutationStatus(
            store,
            write_interrupted,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "CheckpointBatchHookRetained: interrupted write should apply");
        staged_payloads[create_interrupted.path] = BuildPatternPayload(4096, 0xC4);

        bool reached_checkpoint_batch = false;
        store.SetCommitStageHook(
            [&reached_checkpoint_batch](std::string_view stage)
            {
                if (stage == "before-checkpoint-batch-persist")
                {
                    reached_checkpoint_batch = true;
                    return false;
                }
                return true;
            },
            false);

        const auto commit = store.CommitPendingMutations();
        ok &= Require(
            reached_checkpoint_batch,
            "CheckpointBatchHookRetained: hook rejection should block the commit path");
        ok &= Require(
            commit == apfsaccess::rw::MetadataStore::CommitStatus::PersistFailed,
            "CheckpointBatchHookRetained: hook-rejected checkpoint batch should fail the commit");
        ok &= Require(
            store.IsRecoveryRequired() &&
                store.RecoveryReason() == L"CommitInterruptedBeforeCheckpointBatchPersist",
            "CheckpointBatchHookRetained: hook rejection should fail closed for recovery");

        apfsaccess::rw::MetadataStore::MutationRequest later{};
        later.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
        later.path = L"\\later.bin";
        ok &= Require(
            store.ApplyMutation(later) != apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "CheckpointBatchHookRetained: retained recovery should keep mutations blocked");
        ok &= Require(
            store.CommitPendingMutations() != apfsaccess::rw::MetadataStore::CommitStatus::Committed,
            "CheckpointBatchHookRetained: retained recovery should keep the commit path blocked");
    }

    {
        apfsaccess::rw::MetadataStore remounted(context);
        ok &= Require(remounted.LoadContainerSuperblocks(), "CheckpointBatchHookRetained: remount LoadContainerSuperblocks should succeed");
        ok &= Require(remounted.PrepareNativeWritePath(), "CheckpointBatchHookRetained: remount PrepareNativeWritePath should succeed");
        ok &= Require(
            remounted.CheckpointXid().value_or(0) == kInitialCheckpointXid + 1,
            "CheckpointBatchHookRetained: remount should roll back to the previous complete checkpoint");
        ok &= Require(
            !remounted.LookupCommittedInodeByPath(L"\\interrupted.bin").has_value(),
            "CheckpointBatchHookRetained: remount should roll back the interrupted file");
        ok &= Require(
            remounted.LookupCommittedInodeByPath(L"\\baseline.bin").has_value(),
            "CheckpointBatchHookRetained: remount should retain the baseline file");
        std::vector<std::byte> remounted_baseline;
        ok &= Require(
            remounted.ReadCommittedFileRange(L"\\baseline.bin", 0, baseline_payload.size(), remounted_baseline) &&
                remounted_baseline == baseline_payload,
            "CheckpointBatchHookRetained: remount should retain the baseline payload byte-identical");

        std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
        ConfigurePayloadProvider(remounted, staged_payloads);
        apfsaccess::rw::MetadataStore::MutationRequest create_interrupted{};
        create_interrupted.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
        create_interrupted.path = L"\\interrupted.bin";
        ok &= ExpectMutationStatus(
            remounted,
            create_interrupted,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "CheckpointBatchHookRetained: remounted interrupted create should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_interrupted{};
        write_interrupted.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_interrupted.path = create_interrupted.path;
        write_interrupted.length = 4096;
        ok &= ExpectMutationStatus(
            remounted,
            write_interrupted,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "CheckpointBatchHookRetained: remounted interrupted write should apply");
        staged_payloads[create_interrupted.path] = BuildPatternPayload(4096, 0xC4);
        ok &= Require(
            remounted.CommitPendingMutations() == apfsaccess::rw::MetadataStore::CommitStatus::Committed,
            "CheckpointBatchHookRetained: remounted commit should succeed");
        std::vector<std::byte> remounted_payload;
        ok &= Require(
            remounted.ReadCommittedFileRange(L"\\interrupted.bin", 0, 4096, remounted_payload) &&
                remounted_payload == BuildPatternPayload(4096, 0xC4),
            "CheckpointBatchHookRetained: remounted interrupted payload should round-trip");
    }
    return ok;
}

bool TestCheckpointBatchTornWriteRemountFallsBack(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "checkpoint_batch_torn_write.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "CheckpointBatchTornWrite: unable to create synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"CheckpointBatchTornWrite",
    };
    bool ok = true;
    const auto baseline_payload = BuildPatternPayload(4096, 0x6E);
    {
        apfsaccess::rw::MetadataStore store(context);
        ok &= Require(store.LoadContainerSuperblocks(), "CheckpointBatchTornWrite: LoadContainerSuperblocks should succeed");
        ok &= Require(store.LoadObjectMap(), "CheckpointBatchTornWrite: LoadObjectMap should succeed");
        ok &= Require(store.LoadSpacemanState(), "CheckpointBatchTornWrite: LoadSpacemanState should succeed");
        ok &= Require(store.PrepareNativeWritePath(), "CheckpointBatchTornWrite: PrepareNativeWritePath should succeed");

        std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
        ConfigurePayloadProvider(store, staged_payloads);

        apfsaccess::rw::MetadataStore::MutationRequest create_baseline{};
        create_baseline.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
        create_baseline.path = L"\\baseline.bin";
        apfsaccess::rw::MetadataStore::MutationRequest write_baseline{};
        write_baseline.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_baseline.path = create_baseline.path;
        write_baseline.length = 4096;
        staged_payloads[create_baseline.path] = baseline_payload;
        ok &= Require(
            store.ApplyMutation(create_baseline) == apfsaccess::rw::MetadataStore::MutationStatus::Applied &&
                store.ApplyMutation(write_baseline) == apfsaccess::rw::MetadataStore::MutationStatus::Applied &&
                store.CommitPendingMutations() == apfsaccess::rw::MetadataStore::CommitStatus::Committed,
            "CheckpointBatchTornWrite: baseline");
        std::vector<std::byte> baseline_committed;
        ok &= Require(
            store.ReadCommittedFileRange(L"\\baseline.bin", 0, baseline_payload.size(), baseline_committed) &&
                baseline_committed == baseline_payload,
            "CheckpointBatchTornWrite: baseline payload should round-trip before the fault");

        apfsaccess::rw::MetadataStore::MutationRequest create_torn{};
        create_torn.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
        create_torn.path = L"\\torn.bin";
        ok &= ExpectMutationStatus(
            store,
            create_torn,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "CheckpointBatchTornWrite: torn create should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_torn{};
        write_torn.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_torn.path = create_torn.path;
        write_torn.length = 4096;
        ok &= ExpectMutationStatus(
            store,
            write_torn,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "CheckpointBatchTornWrite: torn write should apply");
        staged_payloads[create_torn.path] = BuildPatternPayload(4096, 0xD1);

        wchar_t previous_fault_value[64]{};
        const auto previous_fault_chars = GetEnvironmentVariableW(
            L"APFSACCESS_RW_FAULT_WRITE",
            previous_fault_value,
            static_cast<DWORD>(std::size(previous_fault_value)));
        const bool had_previous_fault =
            previous_fault_chars > 0 &&
            previous_fault_chars < static_cast<DWORD>(std::size(previous_fault_value));

        bool armed_fault = false;
        store.SetCommitStageHook(
            [&armed_fault](std::string_view stage)
            {
                if (!armed_fault && stage == "before-checkpoint-batch-persist")
                {
                    SetEnvironmentVariableW(L"APFSACCESS_RW_FAULT_WRITE", L"first-half");
                    armed_fault = true;
                }
                return true;
            },
            false);

        const auto commit = store.CommitPendingMutations();
        ok &= Require(
            armed_fault,
            "CheckpointBatchTornWrite: torn checkpoint batch should block the commit path");
        ok &= Require(
            commit == apfsaccess::rw::MetadataStore::CommitStatus::PersistFailed,
            "CheckpointBatchTornWrite: torn batch commit should fail at the device level");
        ok &= Require(
            store.IsRecoveryRequired() &&
                store.RecoveryReason() == L"CommitCheckpointBatchPersistFailed",
            "CheckpointBatchTornWrite: torn checkpoint batch should fail closed for recovery");

        if (had_previous_fault)
        {
            SetEnvironmentVariableW(L"APFSACCESS_RW_FAULT_WRITE", previous_fault_value);
        }
        else
        {
            SetEnvironmentVariableW(L"APFSACCESS_RW_FAULT_WRITE", nullptr);
        }

        apfsaccess::rw::MetadataStore::MutationRequest later{};
        later.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
        later.path = L"\\later.bin";
        ok &= Require(
            store.ApplyMutation(later) != apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "CheckpointBatchTornWrite: retained recovery should keep mutations blocked");
        ok &= Require(
            store.CommitPendingMutations() != apfsaccess::rw::MetadataStore::CommitStatus::Committed,
            "CheckpointBatchTornWrite: retained recovery should keep the commit path blocked");
    }

    {
        apfsaccess::rw::MetadataStore remounted(context);
        ok &= Require(remounted.LoadContainerSuperblocks(), "CheckpointBatchTornWrite: remount LoadContainerSuperblocks should succeed");
        ok &= Require(remounted.PrepareNativeWritePath(), "CheckpointBatchTornWrite: remount PrepareNativeWritePath should succeed");
        ok &= Require(
            remounted.CheckpointXid().value_or(0) == kInitialCheckpointXid + 1,
            "CheckpointBatchTornWrite: remount should fall back to the previous complete slot pair");
        ok &= Require(
            !remounted.LookupCommittedInodeByPath(L"\\torn.bin").has_value(),
            "CheckpointBatchTornWrite: remount should roll back the torn file");
        ok &= Require(
            remounted.LookupCommittedInodeByPath(L"\\baseline.bin").has_value(),
            "CheckpointBatchTornWrite: remount should retain the baseline file");
        std::vector<std::byte> remounted_baseline;
        ok &= Require(
            remounted.ReadCommittedFileRange(L"\\baseline.bin", 0, baseline_payload.size(), remounted_baseline) &&
                remounted_baseline == baseline_payload,
            "CheckpointBatchTornWrite: remount should retain the baseline payload byte-identical");

        std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
        ConfigurePayloadProvider(remounted, staged_payloads);
        apfsaccess::rw::MetadataStore::MutationRequest create_torn{};
        create_torn.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
        create_torn.path = L"\\torn.bin";
        ok &= ExpectMutationStatus(
            remounted,
            create_torn,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "CheckpointBatchTornWrite: remounted torn create should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_torn{};
        write_torn.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_torn.path = create_torn.path;
        write_torn.length = 4096;
        ok &= ExpectMutationStatus(
            remounted,
            write_torn,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "CheckpointBatchTornWrite: remounted torn write should apply");
        staged_payloads[create_torn.path] = BuildPatternPayload(4096, 0xD1);
        ok &= Require(
            remounted.CommitPendingMutations() == apfsaccess::rw::MetadataStore::CommitStatus::Committed,
            "CheckpointBatchTornWrite: remounted commit should succeed on the alternate slot pair");
        std::vector<std::byte> remounted_payload;
        ok &= Require(
            remounted.ReadCommittedFileRange(L"\\torn.bin", 0, 4096, remounted_payload) &&
                remounted_payload == BuildPatternPayload(4096, 0xD1),
            "CheckpointBatchTornWrite: remounted torn payload should round-trip");
    }
    return ok;
}

bool TestFreshPayloadTailWriteAvoidsReadModifyWriteConformance(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "fresh_payload_tail_alignment.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "FreshPayloadTailAlignment: unable to create synthetic container");
    }

    wchar_t previous_perf_value[256]{};
    const auto previous_perf_chars = GetEnvironmentVariableW(
        L"APFSACCESS_PERF_COUNTERS",
        previous_perf_value,
        static_cast<DWORD>(std::size(previous_perf_value)));
    const bool had_previous_perf =
        previous_perf_chars > 0 &&
        previous_perf_chars < static_cast<DWORD>(std::size(previous_perf_value));
    SetEnvironmentVariableW(L"APFSACCESS_PERF_COUNTERS", L"1");

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"FreshPayloadTailAlignment",
    };
    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "FreshPayloadTailAlignment: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "FreshPayloadTailAlignment: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "FreshPayloadTailAlignment: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "FreshPayloadTailAlignment: PrepareNativeWritePath should succeed");

    std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
    ConfigurePayloadProvider(store, staged_payloads);

    constexpr std::size_t kPayloadBytes = 2048;
    constexpr std::uint64_t kExpectedZeroPadBytes = 2048;
    const auto path = L"\\tail.bin";

    apfsaccess::rw::MetadataStore::MutationRequest create_file{};
    create_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
    create_file.path = path;
    ok &= ExpectMutationStatus(
        store,
        create_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "FreshPayloadTailAlignment: create file should apply");

    apfsaccess::rw::MetadataStore::MutationRequest write_file{};
    write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
    write_file.path = path;
    write_file.length = kPayloadBytes;
    ok &= ExpectMutationStatus(
        store,
        write_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "FreshPayloadTailAlignment: write file should apply");
    staged_payloads[path] = BuildPatternPayload(kPayloadBytes, 0x4E);

    const auto before_json = store.PerformanceJson();
    const auto before_unaligned = ExtractNestedPerfCounterCount(before_json, "blockDevice", "unalignedWrite");
    const auto before_tail_pads = ExtractNestedUnsignedValue(before_json, "payloadWriteAlignment", "tailZeroPads");
    const auto before_tail_pad_bytes = ExtractNestedUnsignedValue(before_json, "payloadWriteAlignment", "tailZeroPadBytes");
    ok &= Require(
        before_unaligned.has_value() &&
            before_tail_pads.has_value() &&
            before_tail_pad_bytes.has_value(),
        "FreshPayloadTailAlignment: alignment counters should exist before commit");

    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "FreshPayloadTailAlignment: content commit should succeed");

    const auto after_json = store.PerformanceJson();
    const auto after_unaligned = ExtractNestedPerfCounterCount(after_json, "blockDevice", "unalignedWrite");
    const auto after_tail_pads = ExtractNestedUnsignedValue(after_json, "payloadWriteAlignment", "tailZeroPads");
    const auto after_tail_pad_bytes = ExtractNestedUnsignedValue(after_json, "payloadWriteAlignment", "tailZeroPadBytes");
    ok &= Require(
        after_unaligned.has_value() &&
            after_tail_pads.has_value() &&
            after_tail_pad_bytes.has_value(),
        "FreshPayloadTailAlignment: alignment counters should exist after commit");
    if (before_unaligned.has_value() && after_unaligned.has_value())
    {
        ok &= Require(
            after_unaligned.value() == before_unaligned.value(),
            "FreshPayloadTailAlignment: fresh payload tail should not add a read-modify-write");
    }
    if (before_tail_pads.has_value() && after_tail_pads.has_value())
    {
        ok &= Require(
            after_tail_pads.value() == before_tail_pads.value() + 1,
            "FreshPayloadTailAlignment: fresh payload tail should be zero-padded once");
    }
    if (before_tail_pad_bytes.has_value() && after_tail_pad_bytes.has_value())
    {
        ok &= Require(
            after_tail_pad_bytes.value() == before_tail_pad_bytes.value() + kExpectedZeroPadBytes,
            "FreshPayloadTailAlignment: zero-padding byte counter should match block tail");
    }

    std::vector<std::byte> committed_payload;
    ok &= Require(
        store.ReadCommittedFileRange(path, 0, kPayloadBytes, committed_payload),
        "FreshPayloadTailAlignment: committed payload should be readable");
    ok &= Require(
        committed_payload == staged_payloads[path],
        "FreshPayloadTailAlignment: committed payload should match staged bytes");

    {
        apfsaccess::rw::MetadataStore remounted(context);
        ok &= Require(
            remounted.LoadContainerSuperblocks(),
            "FreshPayloadTailAlignment: remount LoadContainerSuperblocks should succeed");
        ok &= Require(
            remounted.PrepareNativeWritePath(),
            "FreshPayloadTailAlignment: remount PrepareNativeWritePath should succeed");
        std::vector<std::byte> remounted_payload;
        ok &= Require(
            remounted.ReadCommittedFileRange(path, 0, kPayloadBytes, remounted_payload),
            "FreshPayloadTailAlignment: remounted payload should be readable");
        ok &= Require(
            remounted_payload == staged_payloads[path],
            "FreshPayloadTailAlignment: remounted payload should match staged bytes");
    }

    SetEnvironmentVariableW(
        L"APFSACCESS_PERF_COUNTERS",
        had_previous_perf ? previous_perf_value : nullptr);

    return ok;
}

bool TestCommittedDirectoryLinkIndexAvoidsFullRebuildConformance(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "committed_directory_link_index.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "CommittedDirectoryLinkIndex: unable to create synthetic container");
    }

    wchar_t previous_perf_value[16] = {};
    const auto previous_perf_chars = GetEnvironmentVariableW(
        L"APFSACCESS_PERF_COUNTERS",
        previous_perf_value,
        static_cast<DWORD>(std::size(previous_perf_value)));
    const bool had_previous_perf =
        previous_perf_chars > 0 &&
        previous_perf_chars < static_cast<DWORD>(std::size(previous_perf_value));
    SetEnvironmentVariableW(L"APFSACCESS_PERF_COUNTERS", L"1");

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"CommittedDirectoryLinkIndex",
    };
    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "CommittedDirectoryLinkIndex: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "CommittedDirectoryLinkIndex: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "CommittedDirectoryLinkIndex: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "CommittedDirectoryLinkIndex: PrepareNativeWritePath should succeed");

    std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
    ConfigurePayloadProvider(store, staged_payloads);

    constexpr std::size_t kFileCount = 96;
    constexpr std::size_t kPayloadBytes = 1024;
    for (std::size_t index = 0; index < kFileCount; ++index)
    {
        const auto path = L"\\dir-" + std::to_wstring(index) + L".bin";

        apfsaccess::rw::MetadataStore::MutationRequest create_file{};
        create_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
        create_file.path = path;
        ok &= ExpectMutationStatus(
            store,
            create_file,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "CommittedDirectoryLinkIndex: create file should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_file{};
        write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_file.path = path;
        write_file.length = kPayloadBytes;
        ok &= ExpectMutationStatus(
            store,
            write_file,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "CommittedDirectoryLinkIndex: write file should apply");
        staged_payloads[path] = BuildPatternPayload(kPayloadBytes, static_cast<unsigned char>(0x41 + index));
    }

    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "CommittedDirectoryLinkIndex: baseline commit should succeed");

    const auto baseline_json = store.PerformanceJson();
    const auto baseline_rebuilds = ExtractNestedUnsignedValue(
        baseline_json,
        "committedDirectoryLinkIndex",
        "rebuilds");
    ok &= Require(
        baseline_rebuilds.has_value(),
        "CommittedDirectoryLinkIndex: rebuild counter should exist after baseline commit");

    const auto delete_path = L"\\dir-17.bin";
    apfsaccess::rw::MetadataStore::MutationRequest delete_file{};
    delete_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Delete;
    delete_file.path = delete_path;
    ok &= ExpectMutationStatus(
        store,
        delete_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "CommittedDirectoryLinkIndex: delete should apply");

    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "CommittedDirectoryLinkIndex: delete commit should succeed");

    const auto after_json = store.PerformanceJson();
    const auto after_rebuilds = ExtractNestedUnsignedValue(
        after_json,
        "committedDirectoryLinkIndex",
        "rebuilds");
    const auto tracked_links = ExtractNestedUnsignedValue(
        after_json,
        "committedDirectoryLinkIndex",
        "trackedLinks");
    ok &= Require(
        after_rebuilds.has_value(),
        "CommittedDirectoryLinkIndex: rebuild counter should exist after delete commit");
    ok &= Require(
        tracked_links.has_value(),
        "CommittedDirectoryLinkIndex: tracked link counter should exist after delete commit");
    if (baseline_rebuilds.has_value() && after_rebuilds.has_value())
    {
        ok &= Require(
            after_rebuilds.value() == baseline_rebuilds.value(),
            "CommittedDirectoryLinkIndex: delete commit should not rebuild the full committed directory-link index");
    }
    if (tracked_links.has_value())
    {
        ok &= Require(
            tracked_links.value() + 1 == kFileCount,
            "CommittedDirectoryLinkIndex: delete commit should remove exactly one committed directory link");
    }

    std::vector<std::byte> remaining_payload;
    ok &= Require(
        store.ReadCommittedFileRange(L"\\dir-34.bin", 0, kPayloadBytes, remaining_payload),
        "CommittedDirectoryLinkIndex: remaining payload should stay readable");
    ok &= Require(
        remaining_payload == staged_payloads[L"\\dir-34.bin"],
        "CommittedDirectoryLinkIndex: remaining payload should remain unchanged");
    ok &= Require(
        !store.LookupCommittedInodeByPath(delete_path).has_value(),
        "CommittedDirectoryLinkIndex: deleted file should be absent after commit");

    SetEnvironmentVariableW(
        L"APFSACCESS_PERF_COUNTERS",
        had_previous_perf ? previous_perf_value : nullptr);

    return ok;
}

bool TestPendingWriteCoalesceUsesNormalizedPathHintConformance(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "pending_write_coalesce_path_hint.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "PendingWriteCoalescePathHint: unable to create synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"PendingWriteCoalescePathHint",
    };
    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "PendingWriteCoalescePathHint: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "PendingWriteCoalescePathHint: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "PendingWriteCoalescePathHint: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "PendingWriteCoalescePathHint: PrepareNativeWritePath should succeed");

    std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
    ConfigurePayloadProvider(store, staged_payloads);

    apfsaccess::rw::MetadataStore::MutationRequest create_file{};
    create_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
    create_file.path = L"\\coalesce-hint.bin";
    ok &= ExpectMutationStatus(
        store,
        create_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "PendingWriteCoalescePathHint: create should apply");

    apfsaccess::rw::MetadataStore::MutationRequest write_file{};
    write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
    write_file.path = L"\\coalesce-hint.bin";
    write_file.length = 4096;
    ok &= ExpectMutationStatus(
        store,
        write_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "PendingWriteCoalescePathHint: write should apply");
    staged_payloads[L"\\coalesce-hint.bin"] = BuildPatternPayload(4096, 0x52);

    const auto before_json = store.PerformanceJson();
    const auto before_scans = ExtractNestedUnsignedValue(before_json, "pendingWriteCoalesce", "scans");
    ok &= Require(before_scans.has_value(), "PendingWriteCoalescePathHint: scan counter should exist before coalesce");

    apfsaccess::rw::MetadataStore::MutationRequest second_write{};
    second_write.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
    second_write.path = L"\\coalesce-hint.bin";
    second_write.length = 4096;
    ok &= ExpectMutationStatus(
        store,
        second_write,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "PendingWriteCoalescePathHint: second write should apply");
    staged_payloads[L"\\coalesce-hint.bin"] = BuildPatternPayload(4096, 0x53);

    const auto after_json = store.PerformanceJson();
    const auto after_scans = ExtractNestedUnsignedValue(after_json, "pendingWriteCoalesce", "scans");
    ok &= Require(after_scans.has_value(), "PendingWriteCoalescePathHint: scan counter should exist after coalesce");
    if (before_scans.has_value() && after_scans.has_value())
    {
        ok &= Require(
            after_scans.value() == before_scans.value(),
            "PendingWriteCoalescePathHint: second write should use the cached pending-write index without rebuild");
    }

    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "PendingWriteCoalescePathHint: commit should succeed");

    std::vector<std::byte> committed_payload;
    ok &= Require(
        store.ReadCommittedFileRange(L"\\coalesce-hint.bin", 0, 4096, committed_payload),
        "PendingWriteCoalescePathHint: committed payload should be readable");
    ok &= Require(
        committed_payload == staged_payloads[L"\\coalesce-hint.bin"],
        "PendingWriteCoalescePathHint: committed payload should match staged payload");

    return ok;
}

bool TestCommitBtreeRollbackAvoidsFullSnapshotConformance(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "commit_btree_rollback_delta.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "CommitBtreeRollbackDelta: unable to create synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"CommitBtreeRollbackDelta",
    };
    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "CommitBtreeRollbackDelta: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "CommitBtreeRollbackDelta: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "CommitBtreeRollbackDelta: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "CommitBtreeRollbackDelta: PrepareNativeWritePath should succeed");

    std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
    ConfigurePayloadProvider(store, staged_payloads);
    ok &= CreateAndCommitFile(
        store,
        staged_payloads,
        L"\\btree-rollback.bin",
        4096,
        0x63,
        "CommitBtreeRollbackDelta");

    const auto before_inode = store.LookupCommittedInodeByPath(L"\\btree-rollback.bin");
    ok &= Require(before_inode.has_value(), "CommitBtreeRollbackDelta: committed inode should exist");
    const auto before_timestamp = before_inode.has_value() ? before_inode->timestamp_utc : 0;
    const auto before_btree_records = store.CommittedBtreeRecordCount();
    const auto before_full_snapshots = store.CommitBtreeFullSnapshotCount();

    apfsaccess::rw::MetadataStore::MutationRequest set_basic_info{};
    set_basic_info.operation = apfsaccess::rw::MetadataStore::MutationOperation::SetBasicInfo;
    set_basic_info.path = L"\\btree-rollback.bin";
    set_basic_info.timestamp_utc = before_timestamp + 777;
    ok &= ExpectMutationStatus(
        store,
        set_basic_info,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "CommitBtreeRollbackDelta: metadata update should apply");

    store.SetCommitStageHook([](std::string_view stage)
    {
        return stage != "before-state-persist";
    });
    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::PersistFailed,
        "CommitBtreeRollbackDelta: commit should fail before state persist");
    store.SetCommitStageHook({});

    const auto rolled_back_inode = store.LookupCommittedInodeByPath(L"\\btree-rollback.bin");
    ok &= Require(
        rolled_back_inode.has_value() && rolled_back_inode->timestamp_utc == before_timestamp,
        "CommitBtreeRollbackDelta: committed inode timestamp should roll back");
    ok &= Require(
        store.CommittedBtreeRecordCount() == before_btree_records,
        "CommitBtreeRollbackDelta: committed btree record count should roll back");
    ok &= Require(
        store.CommitBtreeFullSnapshotCount() == before_full_snapshots,
        "CommitBtreeRollbackDelta: rollback should not use a full btree snapshot");

    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "CommitBtreeRollbackDelta: retry commit should succeed");
    const auto committed_inode = store.LookupCommittedInodeByPath(L"\\btree-rollback.bin");
    ok &= Require(
        committed_inode.has_value() && committed_inode->timestamp_utc == before_timestamp + 777,
        "CommitBtreeRollbackDelta: retry should persist updated timestamp");
    ok &= Require(
        store.CommitBtreeFullSnapshotCount() == before_full_snapshots,
        "CommitBtreeRollbackDelta: successful retry should not use a full btree snapshot");

    return ok;
}

bool TestCommittedReadExtentsConformance(const std::filesystem::path& run_root)
{
    ScopedEnvironmentVariable read_cache_opt_out(
        L"APFSACCESS_EXPERIMENTAL_BLOCK_READ_CACHE",
        L"");
    const auto image_path = run_root / "read_extents.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "ReadExtents: unable to create synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"ReadExtents",
    };
    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "ReadExtents: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "ReadExtents: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "ReadExtents: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "ReadExtents: PrepareNativeWritePath should succeed");

    std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
    ConfigurePayloadProvider(store, staged_payloads);

    apfsaccess::rw::MetadataStore::MutationRequest create_file{};
    create_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
    create_file.path = L"\\fragmented.bin";
    ok &= ExpectMutationStatus(
        store,
        create_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "ReadExtents: create file should apply");

    apfsaccess::rw::MetadataStore::MutationRequest write_file{};
    write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
    write_file.path = L"\\fragmented.bin";
    write_file.length = 8192;
    ok &= ExpectMutationStatus(
        store,
        write_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "ReadExtents: write file should apply");

    const auto placeholder_payload = BuildPatternPayload(8192, 0x8A);
    staged_payloads[L"\\fragmented.bin"] = placeholder_payload;
    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "ReadExtents: commit should succeed");

    auto inode = store.LookupCommittedInodeByPath(L"\\fragmented.bin");
    ok &= Require(inode.has_value(), "ReadExtents: committed inode should exist");
    if (!inode.has_value())
    {
        return false;
    }

    const auto single_extent_read_before = ExtractPerfCounterCount(
        store.PerformanceJson(),
        "committedSingleExtentReadFastPath");
    std::vector<std::byte> single_extent_window;
    ok &= Require(
        store.ReadCommittedFileRange(L"\\fragmented.bin", 0, 512, single_extent_window),
        "ReadExtents: ordinary single-extent read should succeed");
    ok &= Require(
        single_extent_window.size() == 512,
        "ReadExtents: ordinary single-extent read should preserve its requested length");
    const auto single_extent_read_after = ExtractPerfCounterCount(
        store.PerformanceJson(),
        "committedSingleExtentReadFastPath");
    ok &= Require(
        single_extent_read_before.has_value() &&
            single_extent_read_after.has_value() &&
            single_extent_read_after.value() == single_extent_read_before.value() + 1,
        "ReadExtents: ordinary single-extent read should use the direct fast path");

    constexpr std::uint64_t first_extent_address = 700ull * kBlockSize;
    constexpr std::uint64_t second_extent_address = 702ull * kBlockSize;
    const auto first_payload = BuildPatternPayload(1024, 0x10);
    const auto second_payload = BuildPatternPayload(2048, 0x70);
    ok &= Require(
        WriteBytesToImage(image_path, first_extent_address, first_payload),
        "ReadExtents: first payload extent should be written to fixture");
    ok &= Require(
        WriteBytesToImage(image_path, second_extent_address, second_payload),
        "ReadExtents: second payload extent should be written to fixture");
    ok &= Require(
        store.SetCommittedReadExtents(
            inode->object_id,
            {
                { 0, first_extent_address, first_payload.size() },
                { 0, first_extent_address, first_payload.size() },
                { 4096, second_extent_address, second_payload.size() },
            }),
        "ReadExtents: committed read extent table should accept sorted fragments and exact duplicates");

    const auto first_fragmented_plan = store.SnapshotCommittedFileReadPlan(L"\\fragmented.bin");
    const auto second_fragmented_plan = store.SnapshotCommittedFileReadPlan(L"\\fragmented.bin");
    ok &= Require(
        first_fragmented_plan.has_value() &&
            second_fragmented_plan.has_value() &&
            first_fragmented_plan->extents_snapshot != nullptr &&
            first_fragmented_plan->extents_snapshot == second_fragmented_plan->extents_snapshot,
        "ReadExtents: repeated fragmented snapshots should reuse one immutable extent vector");

    std::vector<std::byte> whole;
    ok &= Require(
        store.ReadCommittedFileRange(L"\\fragmented.bin", 0, 6144, whole),
        "ReadExtents: fragmented range should read successfully");
    ok &= Require(whole.size() == 6144, "ReadExtents: fragmented read should preserve requested logical length");
    ok &= Require(
        std::equal(first_payload.begin(), first_payload.end(), whole.begin()),
        "ReadExtents: first extent bytes should match");
    ok &= Require(
        std::all_of(whole.begin() + 1024, whole.begin() + 4096, [](std::byte value)
        {
            return value == std::byte{0};
        }),
        "ReadExtents: sparse gap should be zero-filled");
    ok &= Require(
        std::equal(second_payload.begin(), second_payload.end(), whole.begin() + 4096),
        "ReadExtents: second extent bytes should match");

    std::vector<std::byte> whole_direct(6144, std::byte{0x5A});
    std::size_t whole_direct_bytes = 0;
    ok &= Require(
        store.ReadCommittedFileRangeInto(
            L"\\fragmented.bin",
            0,
            whole_direct.size(),
            whole_direct.data(),
            whole_direct.size(),
            whole_direct_bytes),
        "ReadExtents: direct fragmented range should read successfully");
    ok &= Require(whole_direct_bytes == whole.size(), "ReadExtents: direct read should report requested logical length");
    ok &= Require(
        std::equal(whole.begin(), whole.end(), whole_direct.begin()),
        "ReadExtents: direct read bytes should match vector read");

    std::vector<std::byte> second_window;
    ok &= Require(
        store.ReadCommittedFileRange(L"\\fragmented.bin", 4608, 512, second_window),
        "ReadExtents: read wholly inside second extent should succeed");
    ok &= Require(
        second_window.size() == 512 &&
            std::equal(second_window.begin(), second_window.end(), second_payload.begin() + 512),
        "ReadExtents: second extent window should match");

    std::vector<std::byte> eof_window;
    ok &= Require(
        store.ReadCommittedFileRange(L"\\fragmented.bin", 6144, 4096, eof_window),
        "ReadExtents: EOF-clamped fragmented read should succeed");
    ok &= Require(eof_window.size() == 2048, "ReadExtents: EOF read should clamp to logical file size");
    ok &= Require(
        std::all_of(eof_window.begin(), eof_window.end(), [](std::byte value)
        {
            return value == std::byte{0};
        }),
        "ReadExtents: missing tail extent should zero-fill within logical size");

    constexpr std::uint64_t adjacent_extent_address = 706ull * kBlockSize;
    const auto adjacent_payload = BuildPatternPayload(3072, 0xC4);
    ok &= Require(
        WriteBytesToImage(image_path, adjacent_extent_address, adjacent_payload),
        "ReadExtents: adjacent extent payload should be written to fixture");
    const auto raw_reads_before_adjacent = ExtractNestedUnsignedValue(
        store.Device().PerformanceJson(),
        "rawRead",
        "count");
    const bool adjacent_extents_installed = store.SetCommittedReadExtents(
        inode->object_id,
        {
            { 0, adjacent_extent_address, 1024 },
            { 1024, adjacent_extent_address + 1024, 2048 },
        });
    ok &= Require(
        adjacent_extents_installed,
        "ReadExtents: adjacent split extents should be installed");
    if (adjacent_extents_installed)
    {
        const auto adjacent_fragmented_plan = store.SnapshotCommittedFileReadPlan(L"\\fragmented.bin");
        ok &= Require(
            adjacent_fragmented_plan.has_value() &&
                adjacent_fragmented_plan->extents_snapshot != nullptr &&
                (!first_fragmented_plan.has_value() ||
                 adjacent_fragmented_plan->extents_snapshot != first_fragmented_plan->extents_snapshot),
            "ReadExtents: changing committed extents should invalidate the previous snapshot");

        std::vector<std::byte> adjacent_read;
        ok &= Require(
            store.ReadCommittedFileRange(L"\\fragmented.bin", 0, adjacent_payload.size(), adjacent_read),
            "ReadExtents: adjacent split range should read successfully");
        ok &= Require(
            adjacent_read == adjacent_payload,
            "ReadExtents: adjacent split range should preserve payload bytes");

        const auto raw_reads_after_adjacent = ExtractNestedUnsignedValue(
            store.Device().PerformanceJson(),
            "rawRead",
            "count");
        ok &= Require(
            raw_reads_before_adjacent.has_value() &&
                raw_reads_after_adjacent.has_value() &&
                raw_reads_after_adjacent.value() == raw_reads_before_adjacent.value() + 1,
            "ReadExtents: adjacent split range should use one raw device read");

        ok &= Require(
            store.SetCommittedReadExtents(
                inode->object_id,
                {
                    { 0, first_extent_address, first_payload.size() },
                    { 0, first_extent_address, first_payload.size() },
                    { 4096, second_extent_address, second_payload.size() },
                }),
            "ReadExtents: original sparse extent projection should be restored");
    }

    std::array<std::byte, 16> too_small_destination{};
    std::size_t too_small_bytes = 0;
    ok &= Require(
        !store.ReadCommittedFileRangeInto(
            L"\\fragmented.bin",
            0,
            32,
            too_small_destination.data(),
            too_small_destination.size(),
            too_small_bytes),
        "ReadExtents: direct read should reject destination smaller than request");
    ok &= Require(too_small_bytes == 0, "ReadExtents: rejected direct read should report zero bytes");
    ok &= Require(
        store.VerifyIntegrity(),
        "ReadExtents: sparse read projection should not poison committed integrity validation");

    return ok;
}

bool TestCommittedZeroReadExtentConformance(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "zero_read_extents.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "ZeroReadExtents: unable to create synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"ZeroReadExtents",
    };
    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "ZeroReadExtents: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "ZeroReadExtents: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "ZeroReadExtents: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "ZeroReadExtents: PrepareNativeWritePath should succeed");

    std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
    ConfigurePayloadProvider(store, staged_payloads);

    apfsaccess::rw::MetadataStore::MutationRequest create_file{};
    create_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
    create_file.path = L"\\zero-backed.bin";
    ok &= ExpectMutationStatus(
        store,
        create_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "ZeroReadExtents: create file should apply");

    apfsaccess::rw::MetadataStore::MutationRequest write_file{};
    write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
    write_file.path = L"\\zero-backed.bin";
    write_file.length = 4096;
    ok &= ExpectMutationStatus(
        store,
        write_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "ZeroReadExtents: write file should apply");

    staged_payloads[L"\\zero-backed.bin"] = BuildPatternPayload(4096, 0x11);
    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "ZeroReadExtents: commit should succeed");

    auto inode = store.LookupCommittedInodeByPath(L"\\zero-backed.bin");
    ok &= Require(inode.has_value(), "ZeroReadExtents: committed inode should exist");
    if (!inode.has_value())
    {
        return false;
    }

    ok &= Require(
        store.SetCommittedReadExtents(
            inode->object_id,
            {
                { 0, 0, 4096 },
            }),
        "ZeroReadExtents: committed read extent table should accept zero physical address extents");

    std::vector<std::byte> payload;
    ok &= Require(
        store.ReadCommittedFileRange(L"\\zero-backed.bin", 0, 4096, payload),
        "ZeroReadExtents: zero physical extent should read successfully");
    ok &= Require(payload.size() == 4096, "ZeroReadExtents: zero extent should preserve logical length");
    ok &= Require(
        std::all_of(payload.begin(), payload.end(), [](std::byte value)
        {
            return value == std::byte{0};
        }),
        "ZeroReadExtents: zero physical extent should return zero-filled bytes");

    std::vector<std::byte> direct_payload(4096, std::byte{0x7F});
    std::size_t direct_payload_bytes = 0;
    ok &= Require(
        store.ReadCommittedFileRangeInto(
            L"\\zero-backed.bin",
            0,
            direct_payload.size(),
            direct_payload.data(),
            direct_payload.size(),
            direct_payload_bytes),
        "ZeroReadExtents: direct zero physical extent should read successfully");
    ok &= Require(direct_payload_bytes == 4096, "ZeroReadExtents: direct zero extent should report logical length");
    ok &= Require(
        std::all_of(direct_payload.begin(), direct_payload.end(), [](std::byte value)
        {
            return value == std::byte{0};
        }),
        "ZeroReadExtents: direct zero physical extent should return zero-filled bytes");

    return ok;
}

bool TestFragmentedReadExtentMutationAccountingConformance(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "fragmented_extent_accounting.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "FragmentedExtentAccounting: unable to create synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"FragmentedExtentAccounting",
        true,
    };
    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "FragmentedExtentAccounting: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "FragmentedExtentAccounting: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "FragmentedExtentAccounting: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "FragmentedExtentAccounting: PrepareNativeWritePath should succeed");

    std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
    ConfigurePayloadProvider(store, staged_payloads);

    ok &= CreateAndCommitFile(
        store,
        staged_payloads,
        L"\\fragmented-delete.bin",
        12288,
        0x51,
        "FragmentedExtentAccounting/delete");
    ok &= InstallFragmentedReadExtents(
        store,
        L"\\fragmented-delete.bin",
        400ull * kBlockSize,
        "FragmentedExtentAccounting/delete");

    apfsaccess::rw::MetadataStore::MutationRequest delete_file{};
    delete_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Delete;
    delete_file.path = L"\\fragmented-delete.bin";
    ok &= ExpectMutationStatus(
        store,
        delete_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "FragmentedExtentAccounting: delete should apply");
    ok &= Require(
        store.PendingDeallocationCount() >= 3,
        "FragmentedExtentAccounting: delete should stage every committed read extent for deallocation");
    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "FragmentedExtentAccounting: delete commit should succeed");
    ok &= Require(
        !store.LookupCommittedInodeByPath(L"\\fragmented-delete.bin").has_value(),
        "FragmentedExtentAccounting: deleted file should leave committed inode view");

    ok &= CreateAndCommitFile(
        store,
        staged_payloads,
        L"\\fragmented-overwrite.bin",
        12288,
        0x61,
        "FragmentedExtentAccounting/overwrite");
    ok &= InstallFragmentedReadExtents(
        store,
        L"\\fragmented-overwrite.bin",
        420ull * kBlockSize,
        "FragmentedExtentAccounting/overwrite");
    const auto dealloc_before_overwrite = store.PendingDeallocationCount();
    apfsaccess::rw::MetadataStore::MutationRequest overwrite_file{};
    overwrite_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
    overwrite_file.path = L"\\fragmented-overwrite.bin";
    overwrite_file.length = 12288;
    ok &= ExpectMutationStatus(
        store,
        overwrite_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "FragmentedExtentAccounting: overwrite should apply");
    ok &= Require(
        store.PendingDeallocationCount() >= dealloc_before_overwrite + 3,
        "FragmentedExtentAccounting: overwrite should stage every old committed read extent for deallocation");
    staged_payloads[L"\\fragmented-overwrite.bin"] = BuildPatternPayload(12288, 0x71);
    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "FragmentedExtentAccounting: overwrite commit should succeed");
    ok &= Require(
        store.LookupCommittedInodeByPath(L"\\fragmented-overwrite.bin").has_value(),
        "FragmentedExtentAccounting: overwritten file should stay visible");

    ok &= CreateAndCommitFile(
        store,
        staged_payloads,
        L"\\fragmented-partial-overwrite.bin",
        12288,
        0x75,
        "FragmentedExtentAccounting/partial-overwrite");
    ok &= InstallFragmentedReadExtents(
        store,
        L"\\fragmented-partial-overwrite.bin",
        430ull * kBlockSize,
        "FragmentedExtentAccounting/partial-overwrite");
    const auto dealloc_before_partial_overwrite = store.PendingDeallocationCount();
    staged_payloads[L"\\fragmented-partial-overwrite.bin"] = BuildPatternPayload(12288, 0x76);
    apfsaccess::rw::MetadataStore::MutationRequest partial_overwrite{};
    partial_overwrite.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
    partial_overwrite.path = L"\\fragmented-partial-overwrite.bin";
    partial_overwrite.offset = 4096;
    partial_overwrite.length = 4096;
    ok &= ExpectMutationStatus(
        store,
        partial_overwrite,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "FragmentedExtentAccounting: partial overwrite should apply");
    ok &= Require(
        store.PendingDeallocationCount() == dealloc_before_partial_overwrite + 1,
        "FragmentedExtentAccounting: partial overwrite should deallocate only the replaced physical extent");
    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "FragmentedExtentAccounting: partial overwrite commit should succeed");

    ok &= CreateAndCommitFile(
        store,
        staged_payloads,
        L"\\fragmented-truncate.bin",
        12288,
        0x81,
        "FragmentedExtentAccounting/truncate");
    ok &= InstallFragmentedReadExtents(
        store,
        L"\\fragmented-truncate.bin",
        440ull * kBlockSize,
        "FragmentedExtentAccounting/truncate");
    const auto dealloc_before_truncate = store.PendingDeallocationCount();
    apfsaccess::rw::MetadataStore::MutationRequest truncate_file{};
    truncate_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::SetFileSize;
    truncate_file.path = L"\\fragmented-truncate.bin";
    truncate_file.length = 0;
    ok &= ExpectMutationStatus(
        store,
        truncate_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "FragmentedExtentAccounting: truncate should apply");
    ok &= Require(
        store.PendingDeallocationCount() >= dealloc_before_truncate + 3,
        "FragmentedExtentAccounting: truncate should stage every old committed read extent for deallocation");
    staged_payloads.erase(L"\\fragmented-truncate.bin");
    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "FragmentedExtentAccounting: truncate commit should succeed");
    const auto truncated = store.LookupCommittedInodeByPath(L"\\fragmented-truncate.bin");
    ok &= Require(
        truncated.has_value() &&
            truncated->logical_size == 0 &&
            truncated->data_physical_address == 0,
        "FragmentedExtentAccounting: truncated file should be zero-sized and extentless");

    ok &= CreateAndCommitFile(
        store,
        staged_payloads,
        L"\\fragmented-destination.bin",
        12288,
        0x91,
        "FragmentedExtentAccounting/rename-destination");
    ok &= InstallFragmentedReadExtents(
        store,
        L"\\fragmented-destination.bin",
        460ull * kBlockSize,
        "FragmentedExtentAccounting/rename-destination");
    ok &= CreateAndCommitFile(
        store,
        staged_payloads,
        L"\\fragmented-source.bin",
        4096,
        0xA1,
        "FragmentedExtentAccounting/rename-source");
    const auto dealloc_before_rename_replace = store.PendingDeallocationCount();
    apfsaccess::rw::MetadataStore::MutationRequest rename_replace{};
    rename_replace.operation = apfsaccess::rw::MetadataStore::MutationOperation::Rename;
    rename_replace.path = L"\\fragmented-source.bin";
    rename_replace.secondary_path = L"\\fragmented-destination.bin";
    rename_replace.replace_if_exists = true;
    ok &= ExpectMutationStatus(
        store,
        rename_replace,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "FragmentedExtentAccounting: rename replace should apply");
    ok &= Require(
        store.PendingDeallocationCount() >= dealloc_before_rename_replace + 3,
        "FragmentedExtentAccounting: rename replace should stage every replaced read extent for deallocation");
    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "FragmentedExtentAccounting: rename replace commit should succeed");
    ok &= Require(
        !store.LookupCommittedInodeByPath(L"\\fragmented-source.bin").has_value() &&
            store.LookupCommittedInodeByPath(L"\\fragmented-destination.bin").has_value(),
        "FragmentedExtentAccounting: rename replace namespace should persist");

    return ok;
}

bool TestRecycleBinRestoreRenameConformance(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "recycle_bin_restore_rename.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "RecycleBinRestoreRename: unable to create synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"RecycleBinRestoreRename",
    };
    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "RecycleBinRestoreRename: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "RecycleBinRestoreRename: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "RecycleBinRestoreRename: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "RecycleBinRestoreRename: PrepareNativeWritePath should succeed");

    std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
    ConfigurePayloadProvider(store, staged_payloads);

    const auto create_and_commit_directory = [&](const std::wstring& path, const std::string& label)
    {
        apfsaccess::rw::MetadataStore::MutationRequest create_directory{};
        create_directory.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateDirectory;
        create_directory.path = path;
        if (!ExpectMutationStatus(
                store,
                create_directory,
                apfsaccess::rw::MetadataStore::MutationStatus::Applied,
                label + ": create directory should apply"))
        {
            return false;
        }

        return ExpectCommitStatus(
            store,
            apfsaccess::rw::MetadataStore::CommitStatus::Committed,
            label + ": directory commit should succeed");
    };

    ok &= create_and_commit_directory(L"\\workflow", "RecycleBinRestoreRename/workflow");
    ok &= create_and_commit_directory(L"\\workflow\\recycle", "RecycleBinRestoreRename/recycle");
    ok &= create_and_commit_directory(L"\\workflow\\$RECYCLE.BIN", "RecycleBinRestoreRename/recycle-bin");
    ok &= create_and_commit_directory(
        L"\\workflow\\$RECYCLE.BIN\\S-1-5-21-1000-1000-1000-1001",
        "RecycleBinRestoreRename/recycle-sid");

    ok &= CreateAndCommitFile(
        store,
        staged_payloads,
        L"\\workflow\\recycle\\recycle-me.bin",
        262144,
        0x55,
        "RecycleBinRestoreRename/source");
    ok &= CreateAndCommitFile(
        store,
        staged_payloads,
        L"\\workflow\\$RECYCLE.BIN\\S-1-5-21-1000-1000-1000-1001\\$ICODEX01.bin",
        42,
        0x19,
        "RecycleBinRestoreRename/info");

    apfsaccess::rw::MetadataStore::MutationRequest move_to_recycle{};
    move_to_recycle.operation = apfsaccess::rw::MetadataStore::MutationOperation::Rename;
    move_to_recycle.path = L"\\workflow\\recycle\\recycle-me.bin";
    move_to_recycle.secondary_path = L"\\workflow\\$RECYCLE.BIN\\S-1-5-21-1000-1000-1000-1001\\$RCODEX01.bin";
    ok &= ExpectMutationStatus(
        store,
        move_to_recycle,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "RecycleBinRestoreRename: move-to-recycle rename should apply");
    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "RecycleBinRestoreRename: move-to-recycle commit should succeed");

    apfsaccess::rw::MetadataStore::MutationRequest restore{};
    restore.operation = apfsaccess::rw::MetadataStore::MutationOperation::Rename;
    restore.path = L"\\workflow\\$RECYCLE.BIN\\S-1-5-21-1000-1000-1000-1001\\$RCODEX01.bin";
    restore.secondary_path = L"\\workflow\\recycle\\recycle-restored.bin";
    ok &= ExpectMutationStatus(
        store,
        restore,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "RecycleBinRestoreRename: restore rename should apply");
    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "RecycleBinRestoreRename: restore commit should succeed");
    ok &= Require(
        store.LookupCommittedInodeByPath(L"\\workflow\\recycle\\recycle-restored.bin").has_value(),
        "RecycleBinRestoreRename: restored file should be committed");
    ok &= Require(
        !store.LookupCommittedInodeByPath(L"\\workflow\\$RECYCLE.BIN\\S-1-5-21-1000-1000-1000-1001\\$RCODEX01.bin").has_value(),
        "RecycleBinRestoreRename: recycle payload should be absent after restore");

    return ok;
}

bool TestStaleFreeExtentOverlapSanitizedConformance(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "stale_free_extent_overlap.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "StaleFreeExtentOverlap: unable to create synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"StaleFreeExtentOverlap",
    };
    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "StaleFreeExtentOverlap: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "StaleFreeExtentOverlap: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "StaleFreeExtentOverlap: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "StaleFreeExtentOverlap: PrepareNativeWritePath should succeed");

    std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
    ConfigurePayloadProvider(store, staged_payloads);

    ok &= CreateAndCommitFile(
        store,
        staged_payloads,
        L"\\live.bin",
        4096,
        0xA7,
        "StaleFreeExtentOverlap/live");

    const auto live_inode = store.LookupCommittedInodeByPath(L"\\live.bin");
    ok &= Require(live_inode.has_value(), "StaleFreeExtentOverlap: live file should be committed");
    if (!live_inode.has_value())
    {
        return ok;
    }

    const auto sanitizer_count_before_stale_free = store.FreeExtentSanitizeCount();
    ok &= Require(
        store.FreeExtent(live_inode->data_physical_address, 4ull * kBlockSize),
        "StaleFreeExtentOverlap: stale reusable range should be sanitized instead of poisoning the ledger");
    ok &= Require(
        store.FreeExtentSanitizeCount() > sanitizer_count_before_stale_free,
        "StaleFreeExtentOverlap: stale reusable range should force full free-extent sanitizer");

    ok &= CreateAndCommitFile(
        store,
        staged_payloads,
        L"\\after-stale-free.bin",
        1024,
        0xB8,
        "StaleFreeExtentOverlap/after-stale-free");

    ok &= Require(
        store.LookupCommittedInodeByPath(L"\\live.bin").has_value() &&
            store.LookupCommittedInodeByPath(L"\\after-stale-free.bin").has_value(),
        "StaleFreeExtentOverlap: both live and new files should remain committed");

    return ok;
}

bool TestEphemeralTailAllocationRemovesOverlappingFreeLedgerConformance(
    const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "ephemeral_tail_removes_overlapping_free_ledger.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "EphemeralTailFreeLedger: unable to create synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"EphemeralTailFreeLedger",
    };
    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "EphemeralTailFreeLedger: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "EphemeralTailFreeLedger: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "EphemeralTailFreeLedger: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "EphemeralTailFreeLedger: PrepareNativeWritePath should succeed");

    std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
    ConfigurePayloadProvider(store, staged_payloads);

    apfsaccess::rw::MetadataStore::MutationRequest create_directory{};
    create_directory.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateDirectory;
    create_directory.path = L"\\cache-warm";
    ok &= ExpectMutationStatus(
        store,
        create_directory,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "EphemeralTailFreeLedger: cache-warming directory create should apply");
    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "EphemeralTailFreeLedger: cache-warming commit should succeed");

    constexpr std::uint64_t injected_free_address = 300ull * kBlockSize;
    ok &= Require(
        store.FreeExtent(injected_free_address, kBlockSize),
        "EphemeralTailFreeLedger: injected free extent should be accepted");

    constexpr std::uint64_t payload_bytes = 512ull * 1024ull;
    const std::wstring path = L"\\tail-allocation.bin";
    apfsaccess::rw::MetadataStore::MutationRequest create_file{};
    create_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
    create_file.path = path;
    ok &= ExpectMutationStatus(
        store,
        create_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "EphemeralTailFreeLedger: file create should apply");

    apfsaccess::rw::MetadataStore::MutationRequest set_size{};
    set_size.operation = apfsaccess::rw::MetadataStore::MutationOperation::SetFileSize;
    set_size.path = path;
    set_size.length = payload_bytes;
    staged_payloads[path] = BuildPatternPayload(static_cast<std::size_t>(payload_bytes), 0xC3);
    ok &= ExpectMutationStatus(
        store,
        set_size,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "EphemeralTailFreeLedger: large SetFileSize should allocate through the ephemeral tail");

    const auto working_inode = store.DebugLookupWorkingInodeByPath(path);
    ok &= Require(
        working_inode.has_value() &&
            working_inode->data_physical_address <= injected_free_address &&
            injected_free_address < working_inode->data_physical_address + working_inode->logical_size,
        "EphemeralTailFreeLedger: tail allocation should span the injected free extent");
    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "EphemeralTailFreeLedger: commit should preserve the projected spaceman invariant");
    ok &= Require(
        store.LastCommitFailureReason() != L"ProjectedSpacemanInvalid" &&
            !store.LastCommitFailureObjectId().has_value(),
        "EphemeralTailFreeLedger: commit should not report an overlapping free extent");

    std::vector<std::byte> committed_payload;
    ok &= Require(
        store.ReadCommittedFileRange(path, 0, payload_bytes, committed_payload),
        "EphemeralTailFreeLedger: committed payload should be readable");
    ok &= Require(
        committed_payload == staged_payloads[path],
        "EphemeralTailFreeLedger: committed payload should remain byte-identical");

    return ok;
}

bool TestObjectMapDeltaCanonicalizationConformance(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "object_map_delta_canonical.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "TestObjectMapDeltaCanonicalizationConformance: unable to create synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"ObjectMapDeltaCanonical",
    };
    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "ObjectMapDelta: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "ObjectMapDelta: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "ObjectMapDelta: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "ObjectMapDelta: PrepareNativeWritePath should succeed");

    std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
    ConfigurePayloadProvider(store, staged_payloads);

    apfsaccess::rw::MetadataStore::MutationRequest create_file{};
    create_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
    create_file.path = L"\\delta.bin";
    ok &= ExpectMutationStatus(
        store,
        create_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "ObjectMapDelta: create file should apply");

    apfsaccess::rw::MetadataStore::MutationRequest write_file{};
    write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
    write_file.path = L"\\delta.bin";
    write_file.length = 1024;
    ok &= ExpectMutationStatus(
        store,
        write_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "ObjectMapDelta: initial write should apply");
    staged_payloads[L"\\delta.bin"] = BuildPatternPayload(1024, 0x63);

    apfsaccess::rw::MetadataStore::MutationRequest resize_file{};
    resize_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::SetFileSize;
    resize_file.path = L"\\delta.bin";
    resize_file.length = 2048;
    ok &= ExpectMutationStatus(
        store,
        resize_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "ObjectMapDelta: resize should apply");
    staged_payloads[L"\\delta.bin"] = BuildPatternPayload(2048, 0x71);

    apfsaccess::rw::MetadataStore::MutationRequest set_basic_info{};
    set_basic_info.operation = apfsaccess::rw::MetadataStore::MutationOperation::SetBasicInfo;
    set_basic_info.path = L"\\delta.bin";
    ok &= ExpectMutationStatus(
        store,
        set_basic_info,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "ObjectMapDelta: set basic info should apply");

    ok &= Require(
        store.PendingObjectMapUpdateCount() == 1,
        "ObjectMapDelta: pending object-map updates should be canonicalized to one entry per object");

    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "ObjectMapDelta: commit should succeed");

    const auto committed = store.LookupCommittedInodeByPath(L"\\delta.bin");
    ok &= Require(committed.has_value(), "ObjectMapDelta: committed inode should exist");
    if (committed.has_value())
    {
        ok &= Require(
            committed->logical_size == 2048,
            "ObjectMapDelta: committed inode size should match final resize");
    }

    return ok;
}

bool TestObjectMapCheckpointHandlesManySmallFilesConformance(const std::filesystem::path& run_root)
{
    constexpr std::size_t kLargeObjectMapContainerBytes = 96 * 1024 * 1024;
    constexpr std::size_t kFileCount = 4200;
    constexpr std::uint64_t kPayloadBytes = 4096;

    const auto image_path = run_root / "object_map_many_small_files.apfs.img";
    if (!CreateSyntheticContainerWithSize(image_path, kLargeObjectMapContainerBytes))
    {
        return Require(false, "ObjectMapManySmallFiles: unable to create synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"ObjectMapManySmallFiles",
    };
    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "ObjectMapManySmallFiles: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "ObjectMapManySmallFiles: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "ObjectMapManySmallFiles: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "ObjectMapManySmallFiles: PrepareNativeWritePath should succeed");

    std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
    ConfigurePayloadProvider(store, staged_payloads);

    for (std::size_t index = 0; index < kFileCount; ++index)
    {
        const auto path = L"\\many-small-" + std::to_wstring(index) + L".bin";

        apfsaccess::rw::MetadataStore::MutationRequest create_file{};
        create_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
        create_file.path = path;
        if (!ExpectMutationStatus(
                store,
                create_file,
                apfsaccess::rw::MetadataStore::MutationStatus::Applied,
                "ObjectMapManySmallFiles: create file should apply"))
        {
            return false;
        }

        apfsaccess::rw::MetadataStore::MutationRequest write_file{};
        write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_file.path = path;
        write_file.length = kPayloadBytes;
        if (!ExpectMutationStatus(
                store,
                write_file,
                apfsaccess::rw::MetadataStore::MutationStatus::Applied,
                "ObjectMapManySmallFiles: write file should apply"))
        {
            return false;
        }

        staged_payloads[path] = BuildPatternPayload(
            static_cast<std::size_t>(kPayloadBytes),
            static_cast<unsigned char>(0x40u + (index % 0x40u)));
    }

    ok &= Require(
        store.PendingObjectMapUpdateCount() > 2600,
        "ObjectMapManySmallFiles: pending object-map entries should exceed legacy checkpoint capacity");

    wchar_t previous_perf_value[256]{};
    const auto previous_perf_chars = GetEnvironmentVariableW(
        L"APFSACCESS_PERF_COUNTERS",
        previous_perf_value,
        static_cast<DWORD>(std::size(previous_perf_value)));
    const bool had_previous_perf =
        previous_perf_chars > 0 &&
        previous_perf_chars < static_cast<DWORD>(std::size(previous_perf_value));
    SetEnvironmentVariableW(L"APFSACCESS_PERF_COUNTERS", L"1");

    store.SetCommitStageHook([](std::string_view)
    {
        return true;
    });

    const auto before_read_count = ExtractNestedPerfCounterCount(store.PerformanceJson(), "blockDevice", "read");
    ok &= Require(
        before_read_count.has_value(),
        "ObjectMapManySmallFiles: blockDevice read counter should exist before commit");
    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "ObjectMapManySmallFiles: commit should persist expanded object map checkpoint");
    const auto after_read_count = ExtractNestedPerfCounterCount(store.PerformanceJson(), "blockDevice", "read");
    ok &= Require(
        after_read_count.has_value(),
        "ObjectMapManySmallFiles: blockDevice read counter should exist after commit");
    if (before_read_count.has_value() && after_read_count.has_value())
    {
        const auto read_delta = after_read_count.value() - before_read_count.value();
        ok &= Require(
            read_delta <= 64,
            "ObjectMapManySmallFiles: strict checkpoint roundtrip should coalesce chunked readback; blockDevice.read delta=" +
                std::to_string(read_delta));
    }

    SetEnvironmentVariableW(
        L"APFSACCESS_PERF_COUNTERS",
        had_previous_perf ? previous_perf_value : nullptr);

    ok &= Require(
        store.CommittedObjectCount() > 2600,
        "ObjectMapManySmallFiles: committed object map should exceed legacy checkpoint capacity");
    ok &= Require(
        store.CommittedBtreeRecordCount() > 10000,
        "ObjectMapManySmallFiles: committed b-tree records should exceed legacy checkpoint pressure");

    apfsaccess::rw::MetadataStore remounted(context);
    ok &= Require(
        remounted.LoadContainerSuperblocks(),
        "ObjectMapManySmallFiles: remount LoadContainerSuperblocks should succeed");
    ok &= Require(
        remounted.PrepareNativeWritePath(),
        "ObjectMapManySmallFiles: remount PrepareNativeWritePath should succeed");

    for (const auto index : { std::size_t{0}, kFileCount / 2, kFileCount - 1 })
    {
        const auto path = L"\\many-small-" + std::to_wstring(index) + L".bin";
        ok &= Require(
            remounted.LookupCommittedInodeByPath(path).has_value(),
            "ObjectMapManySmallFiles: remounted file should exist");
    }

    return ok;
}

bool TestPendingCommitValidationOverlaysLargeCommittedStateConformance(const std::filesystem::path& run_root)
{
    constexpr std::size_t kLargeObjectMapContainerBytes = 96 * 1024 * 1024;
    constexpr std::size_t kFileCount = 1800;
    constexpr std::uint64_t kPayloadBytes = 4096;

    const auto image_path = run_root / "pending_validation_overlay.apfs.img";
    if (!CreateSyntheticContainerWithSize(image_path, kLargeObjectMapContainerBytes))
    {
        return Require(false, "PendingValidationOverlay: unable to create synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"PendingValidationOverlay",
    };
    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "PendingValidationOverlay: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "PendingValidationOverlay: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "PendingValidationOverlay: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "PendingValidationOverlay: PrepareNativeWritePath should succeed");

    std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
    ConfigurePayloadProvider(store, staged_payloads);

    for (std::size_t index = 0; index < kFileCount; ++index)
    {
        const auto path = L"\\baseline-" + std::to_wstring(index) + L".bin";

        apfsaccess::rw::MetadataStore::MutationRequest create_file{};
        create_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
        create_file.path = path;
        if (!ExpectMutationStatus(
                store,
                create_file,
                apfsaccess::rw::MetadataStore::MutationStatus::Applied,
                "PendingValidationOverlay: baseline create should apply"))
        {
            return false;
        }

        apfsaccess::rw::MetadataStore::MutationRequest write_file{};
        write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_file.path = path;
        write_file.length = kPayloadBytes;
        if (!ExpectMutationStatus(
                store,
                write_file,
                apfsaccess::rw::MetadataStore::MutationStatus::Applied,
                "PendingValidationOverlay: baseline write should apply"))
        {
            return false;
        }

        staged_payloads[path] = BuildPatternPayload(
            static_cast<std::size_t>(kPayloadBytes),
            static_cast<unsigned char>(0x55u + (index % 0x40u)));
    }

    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "PendingValidationOverlay: baseline commit should succeed");
    ok &= Require(
        store.CommittedObjectCount() >= kFileCount,
        "PendingValidationOverlay: baseline commit should populate committed object map");

    const auto existing_path = L"\\baseline-" + std::to_wstring(kFileCount / 2) + L".bin";
    const auto new_path = L"\\overlay-new.bin";
    const auto new_payload = BuildPatternPayload(2048, 0xB7);

    apfsaccess::rw::MetadataStore::MutationRequest create_new{};
    create_new.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
    create_new.path = new_path;
    ok &= ExpectMutationStatus(
        store,
        create_new,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "PendingValidationOverlay: new create should apply");

    apfsaccess::rw::MetadataStore::MutationRequest write_new{};
    write_new.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
    write_new.path = new_path;
    write_new.length = new_payload.size();
    ok &= ExpectMutationStatus(
        store,
        write_new,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "PendingValidationOverlay: new write should apply");
    staged_payloads[new_path] = new_payload;

    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "PendingValidationOverlay: tiny overlay commit should succeed");

    std::vector<std::byte> existing_payload;
    ok &= Require(
        store.ReadCommittedFileRange(existing_path, 0, kPayloadBytes, existing_payload),
        "PendingValidationOverlay: existing committed payload should be readable");
    ok &= Require(
        existing_payload == staged_payloads[existing_path],
        "PendingValidationOverlay: existing committed payload should stay intact");

    std::vector<std::byte> committed_new_payload;
    ok &= Require(
        store.ReadCommittedFileRange(new_path, 0, new_payload.size(), committed_new_payload),
        "PendingValidationOverlay: new committed payload should be readable");
    ok &= Require(
        committed_new_payload == new_payload,
        "PendingValidationOverlay: new committed payload should match");

    apfsaccess::rw::MetadataStore remounted(context);
    ok &= Require(
        remounted.LoadContainerSuperblocks(),
        "PendingValidationOverlay: remount LoadContainerSuperblocks should succeed");
    ok &= Require(
        remounted.PrepareNativeWritePath(),
        "PendingValidationOverlay: remount PrepareNativeWritePath should succeed");
    ok &= Require(
        remounted.LookupCommittedInodeByPath(existing_path).has_value(),
        "PendingValidationOverlay: remounted existing file should exist");
    ok &= Require(
        remounted.LookupCommittedInodeByPath(new_path).has_value(),
        "PendingValidationOverlay: remounted new file should exist");

    std::vector<std::byte> remounted_new_payload;
    ok &= Require(
        remounted.ReadCommittedFileRange(new_path, 0, new_payload.size(), remounted_new_payload),
        "PendingValidationOverlay: remounted new payload should be readable");
    ok &= Require(
        remounted_new_payload == new_payload,
        "PendingValidationOverlay: remounted new payload should match");

    return ok;
}

bool TestPendingCommitValidationUsesSortedAllocationChecksConformance(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "pending_validation_sorted_allocations.apfs.img";
    if (!CreateSyntheticContainerWithSize(image_path, 64 * 1024 * 1024))
    {
        return Require(false, "PendingValidationSortedAllocations: unable to create synthetic container");
    }

    wchar_t previous_perf_value[256]{};
    const auto previous_perf_chars = GetEnvironmentVariableW(
        L"APFSACCESS_PERF_COUNTERS",
        previous_perf_value,
        static_cast<DWORD>(std::size(previous_perf_value)));
    const bool had_previous_perf =
        previous_perf_chars > 0 &&
        previous_perf_chars < static_cast<DWORD>(std::size(previous_perf_value));
    SetEnvironmentVariableW(L"APFSACCESS_PERF_COUNTERS", L"1");

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"PendingValidationSortedAllocations",
    };
    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(
        store.LoadContainerSuperblocks(),
        "PendingValidationSortedAllocations: LoadContainerSuperblocks should succeed");
    ok &= Require(
        store.LoadObjectMap(),
        "PendingValidationSortedAllocations: LoadObjectMap should succeed");
    ok &= Require(
        store.LoadSpacemanState(),
        "PendingValidationSortedAllocations: LoadSpacemanState should succeed");
    ok &= Require(
        store.PrepareNativeWritePath(),
        "PendingValidationSortedAllocations: PrepareNativeWritePath should succeed");

    std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
    ConfigurePayloadProvider(store, staged_payloads);

    constexpr std::size_t kFileCount = 160;
    constexpr std::size_t kPayloadBytes = 2048;
    for (std::size_t index = 0; index < kFileCount; ++index)
    {
        const auto path = L"\\pending-" + std::to_wstring(index) + L".bin";

        apfsaccess::rw::MetadataStore::MutationRequest create_file{};
        create_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
        create_file.path = path;
        if (!ExpectMutationStatus(
                store,
                create_file,
                apfsaccess::rw::MetadataStore::MutationStatus::Applied,
                "PendingValidationSortedAllocations: create file should apply"))
        {
            SetEnvironmentVariableW(
                L"APFSACCESS_PERF_COUNTERS",
                had_previous_perf ? previous_perf_value : nullptr);
            return false;
        }

        apfsaccess::rw::MetadataStore::MutationRequest write_file{};
        write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_file.path = path;
        write_file.length = kPayloadBytes;
        if (!ExpectMutationStatus(
                store,
                write_file,
                apfsaccess::rw::MetadataStore::MutationStatus::Applied,
                "PendingValidationSortedAllocations: write file should apply"))
        {
            SetEnvironmentVariableW(
                L"APFSACCESS_PERF_COUNTERS",
                had_previous_perf ? previous_perf_value : nullptr);
            return false;
        }

        staged_payloads[path] = BuildPatternPayload(
            kPayloadBytes,
            static_cast<unsigned char>(0x60u + (index % 0x20u)));
    }

    const auto before_json = store.PerformanceJson();
    const auto before_sorted = ExtractNestedUnsignedValue(
        before_json,
        "pendingAllocationValidation",
        "sortedPasses");
    const auto before_fallback = ExtractNestedUnsignedValue(
        before_json,
        "pendingAllocationValidation",
        "fallbackScans");
    const auto before_committed_sorted_reuse = ExtractNestedUnsignedValue(
        before_json,
        "pendingAllocationValidation",
        "committedSortedReuse");
    const auto before_committed_index_fallbacks = ExtractNestedUnsignedValue(
        before_json,
        "pendingAllocationValidation",
        "committedIndexFallbacks");
    const auto before_pending_sorted_reuse = ExtractNestedUnsignedValue(
        before_json,
        "pendingAllocationValidation",
        "pendingSortedReuse");
    const auto before_pending_sort_fallbacks = ExtractNestedUnsignedValue(
        before_json,
        "pendingAllocationValidation",
        "pendingSortFallbacks");
    const auto before_commit_extent_fast = ExtractNestedUnsignedValue(
        before_json,
        "pendingAllocationValidation",
        "commitExtentFast");
    ok &= Require(
        before_sorted.has_value() &&
            before_fallback.has_value() &&
            before_committed_sorted_reuse.has_value() &&
            before_committed_index_fallbacks.has_value() &&
            before_pending_sorted_reuse.has_value() &&
            before_pending_sort_fallbacks.has_value() &&
            before_commit_extent_fast.has_value(),
        "PendingValidationSortedAllocations: validation counters should exist before commit");

    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "PendingValidationSortedAllocations: many-file commit should succeed");

    const auto after_json = store.PerformanceJson();
    const auto after_sorted = ExtractNestedUnsignedValue(
        after_json,
        "pendingAllocationValidation",
        "sortedPasses");
    const auto after_fallback = ExtractNestedUnsignedValue(
        after_json,
        "pendingAllocationValidation",
        "fallbackScans");
    const auto after_committed_sorted_reuse = ExtractNestedUnsignedValue(
        after_json,
        "pendingAllocationValidation",
        "committedSortedReuse");
    const auto after_committed_index_fallbacks = ExtractNestedUnsignedValue(
        after_json,
        "pendingAllocationValidation",
        "committedIndexFallbacks");
    const auto after_pending_sorted_reuse = ExtractNestedUnsignedValue(
        after_json,
        "pendingAllocationValidation",
        "pendingSortedReuse");
    const auto after_pending_sort_fallbacks = ExtractNestedUnsignedValue(
        after_json,
        "pendingAllocationValidation",
        "pendingSortFallbacks");
    const auto after_commit_extent_fast = ExtractNestedUnsignedValue(
        after_json,
        "pendingAllocationValidation",
        "commitExtentFast");
    ok &= Require(
        after_sorted.has_value() &&
            after_fallback.has_value() &&
            after_committed_sorted_reuse.has_value() &&
            after_committed_index_fallbacks.has_value() &&
            after_pending_sorted_reuse.has_value() &&
            after_pending_sort_fallbacks.has_value() &&
            after_commit_extent_fast.has_value(),
        "PendingValidationSortedAllocations: validation counters should exist after commit");
    if (before_sorted.has_value() && after_sorted.has_value())
    {
        ok &= Require(
            after_sorted.value() == before_sorted.value() + 1,
            "PendingValidationSortedAllocations: commit should run full sorted pending allocation validation once");
    }
    if (before_fallback.has_value() && after_fallback.has_value())
    {
        ok &= Require(
            after_fallback.value() == before_fallback.value(),
            "PendingValidationSortedAllocations: valid batch should avoid fallback pairwise allocation scans");
    }
    if (before_committed_sorted_reuse.has_value() && after_committed_sorted_reuse.has_value())
    {
        ok &= Require(
            after_committed_sorted_reuse.value() == before_committed_sorted_reuse.value() + 1,
            "PendingValidationSortedAllocations: committed allocation validation should reuse canonical sorted state");
    }
    if (before_committed_index_fallbacks.has_value() && after_committed_index_fallbacks.has_value())
    {
        ok &= Require(
            after_committed_index_fallbacks.value() == before_committed_index_fallbacks.value(),
            "PendingValidationSortedAllocations: canonical committed allocations should avoid map-index fallback");
    }
    if (before_pending_sorted_reuse.has_value() && after_pending_sorted_reuse.has_value())
    {
        ok &= Require(
            after_pending_sorted_reuse.value() == before_pending_sorted_reuse.value() + 1,
            "PendingValidationSortedAllocations: pending allocations should reuse canonical sorted order");
    }
    if (before_pending_sort_fallbacks.has_value() && after_pending_sort_fallbacks.has_value())
    {
        ok &= Require(
            after_pending_sort_fallbacks.value() == before_pending_sort_fallbacks.value(),
            "PendingValidationSortedAllocations: canonical pending allocations should avoid sort fallback");
    }
    if (before_commit_extent_fast.has_value() && after_commit_extent_fast.has_value())
    {
        ok &= Require(
            after_commit_extent_fast.value() == before_commit_extent_fast.value() + 1,
            "PendingValidationSortedAllocations: commit blob allocation should use focused fast validation");
    }

    std::vector<std::byte> committed_payload;
    ok &= Require(
        store.ReadCommittedFileRange(L"\\pending-73.bin", 0, kPayloadBytes, committed_payload),
        "PendingValidationSortedAllocations: sampled payload should be readable");
    ok &= Require(
        committed_payload == staged_payloads[L"\\pending-73.bin"],
        "PendingValidationSortedAllocations: sampled payload should match");

    SetEnvironmentVariableW(
        L"APFSACCESS_PERF_COUNTERS",
        had_previous_perf ? previous_perf_value : nullptr);

    return ok;
}

bool TestEphemeralCreateDeleteConformance(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "ephemeral_create_delete.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "TestEphemeralCreateDeleteConformance: unable to create synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"EphemeralCreateDelete",
    };
    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "EphemeralCreateDelete: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "EphemeralCreateDelete: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "EphemeralCreateDelete: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "EphemeralCreateDelete: PrepareNativeWritePath should succeed");

    std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
    ConfigurePayloadProvider(store, staged_payloads);

    apfsaccess::rw::MetadataStore::MutationRequest create_file{};
    create_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
    create_file.path = L"\\ephemeral.bin";
    ok &= ExpectMutationStatus(
        store,
        create_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "EphemeralCreateDelete: create file should apply");

    apfsaccess::rw::MetadataStore::MutationRequest write_file{};
    write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
    write_file.path = L"\\ephemeral.bin";
    write_file.length = 4096;
    ok &= ExpectMutationStatus(
        store,
        write_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "EphemeralCreateDelete: write file should apply");
    staged_payloads[L"\\ephemeral.bin"] = BuildPatternPayload(4096, 0x2C);

    apfsaccess::rw::MetadataStore::MutationRequest delete_file{};
    delete_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Delete;
    delete_file.path = L"\\ephemeral.bin";
    ok &= ExpectMutationStatus(
        store,
        delete_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "EphemeralCreateDelete: delete file should apply");
    staged_payloads.erase(L"\\ephemeral.bin");

    ok &= Require(
        store.PendingAllocationCount() == 0,
        "EphemeralCreateDelete: never-committed file allocation should be released before commit");
    ok &= Require(
        store.PendingSpacemanAllocationIndexCount() == 0,
        "EphemeralCreateDelete: released never-committed allocation should leave no pending allocation index entry");
    ok &= Require(
        store.PendingDeallocationCount() == 0,
        "EphemeralCreateDelete: never-committed file delete should not stage a media deallocation");

    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "EphemeralCreateDelete: commit should succeed");
    ok &= Require(
        !store.LookupCommittedInodeByPath(L"\\ephemeral.bin").has_value(),
        "EphemeralCreateDelete: committed view should not contain ephemeral file");

    return ok;
}

bool TestEphemeralDeleteUsesLocalPendingAllocationEraseConformance(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "ephemeral_delete_local_allocation_erase.apfs.img";
    if (!CreateSyntheticContainerWithSize(image_path, 64 * 1024 * 1024))
    {
        return Require(false, "EphemeralDeleteLocalAllocationErase: unable to create synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"EphemeralDeleteLocalAllocationErase",
    };
    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(
        store.LoadContainerSuperblocks(),
        "EphemeralDeleteLocalAllocationErase: LoadContainerSuperblocks should succeed");
    ok &= Require(
        store.LoadObjectMap(),
        "EphemeralDeleteLocalAllocationErase: LoadObjectMap should succeed");
    ok &= Require(
        store.LoadSpacemanState(),
        "EphemeralDeleteLocalAllocationErase: LoadSpacemanState should succeed");
    ok &= Require(
        store.PrepareNativeWritePath(),
        "EphemeralDeleteLocalAllocationErase: PrepareNativeWritePath should succeed");

    std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
    ConfigurePayloadProvider(store, staged_payloads);

    constexpr std::size_t kFileCount = 24;
    constexpr std::size_t kPayloadBytes = 4096;
    for (std::size_t index = 0; index < kFileCount; ++index)
    {
        const auto path = L"\\burst-" + std::to_wstring(index) + L".bin";

        apfsaccess::rw::MetadataStore::MutationRequest create_file{};
        create_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
        create_file.path = path;
        ok &= ExpectMutationStatus(
            store,
            create_file,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "EphemeralDeleteLocalAllocationErase: create file should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_file{};
        write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_file.path = path;
        write_file.length = kPayloadBytes;
        ok &= ExpectMutationStatus(
            store,
            write_file,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "EphemeralDeleteLocalAllocationErase: write file should apply");

        staged_payloads[path] = BuildPatternPayload(
            kPayloadBytes,
            static_cast<unsigned char>(0x31u + (index % 0x40u)));
    }

    const auto pending_allocations_before_delete = store.PendingAllocationCount();
    ok &= Require(
        pending_allocations_before_delete >= kFileCount,
        "EphemeralDeleteLocalAllocationErase: setup should stage one pending allocation per file");
    ok &= Require(
        store.PendingSpacemanAllocationIndexCount() == pending_allocations_before_delete,
        "EphemeralDeleteLocalAllocationErase: setup allocation index should match pending allocations");

    const auto before_json = store.PerformanceJson();
    const auto before_rebuilds = ExtractNestedUnsignedValue(
        before_json,
        "pendingSpacemanAllocationIndex",
        "rebuilds");
    const auto before_local_erases = ExtractNestedUnsignedValue(
        before_json,
        "pendingSpacemanAllocationIndex",
        "localErases");
    const auto before_btree_rebuilds = ExtractNestedUnsignedValue(
        before_json,
        "pendingBtreeFileMetadataIndex",
        "rebuilds");
    const auto before_btree_local_erases = ExtractNestedUnsignedValue(
        before_json,
        "pendingBtreeFileMetadataIndex",
        "localErases");
    ok &= Require(
        before_rebuilds.has_value() &&
            before_local_erases.has_value() &&
            before_btree_rebuilds.has_value() &&
            before_btree_local_erases.has_value(),
        "EphemeralDeleteLocalAllocationErase: pending allocation index counters should exist before delete");

    const auto delete_path = std::wstring(L"\\burst-7.bin");
    apfsaccess::rw::MetadataStore::MutationRequest delete_file{};
    delete_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Delete;
    delete_file.path = delete_path;
    ok &= ExpectMutationStatus(
        store,
        delete_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "EphemeralDeleteLocalAllocationErase: delete file should apply");
    staged_payloads.erase(delete_path);

    ok &= Require(
        store.PendingAllocationCount() == pending_allocations_before_delete - 1,
        "EphemeralDeleteLocalAllocationErase: delete should release exactly one pending allocation");
    ok &= Require(
        store.PendingSpacemanAllocationIndexCount() == store.PendingAllocationCount(),
        "EphemeralDeleteLocalAllocationErase: delete should keep allocation index in sync");

    const auto after_json = store.PerformanceJson();
    const auto after_rebuilds = ExtractNestedUnsignedValue(
        after_json,
        "pendingSpacemanAllocationIndex",
        "rebuilds");
    const auto after_local_erases = ExtractNestedUnsignedValue(
        after_json,
        "pendingSpacemanAllocationIndex",
        "localErases");
    const auto after_btree_rebuilds = ExtractNestedUnsignedValue(
        after_json,
        "pendingBtreeFileMetadataIndex",
        "rebuilds");
    const auto after_btree_local_erases = ExtractNestedUnsignedValue(
        after_json,
        "pendingBtreeFileMetadataIndex",
        "localErases");
    ok &= Require(
        after_rebuilds.has_value() &&
            after_local_erases.has_value() &&
            after_btree_rebuilds.has_value() &&
            after_btree_local_erases.has_value(),
        "EphemeralDeleteLocalAllocationErase: pending allocation index counters should exist after delete");
    if (before_rebuilds.has_value() && after_rebuilds.has_value())
    {
        ok &= Require(
            after_rebuilds.value() == before_rebuilds.value(),
            "EphemeralDeleteLocalAllocationErase: delete should not rebuild the whole pending allocation index");
    }
    if (before_local_erases.has_value() && after_local_erases.has_value())
    {
        ok &= Require(
            after_local_erases.value() == before_local_erases.value() + 1,
            "EphemeralDeleteLocalAllocationErase: delete should use one local pending allocation erase");
    }
    if (before_btree_rebuilds.has_value() && after_btree_rebuilds.has_value())
    {
        ok &= Require(
            after_btree_rebuilds.value() == before_btree_rebuilds.value(),
            "EphemeralDeleteLocalAllocationErase: delete should not rebuild the whole pending B-tree metadata index");
    }
    if (before_btree_local_erases.has_value() && after_btree_local_erases.has_value())
    {
        ok &= Require(
            after_btree_local_erases.value() == before_btree_local_erases.value() + 1,
            "EphemeralDeleteLocalAllocationErase: delete should use one local pending B-tree extent erase");
    }

    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "EphemeralDeleteLocalAllocationErase: commit should succeed");
    ok &= Require(
        !store.LookupCommittedInodeByPath(delete_path).has_value(),
        "EphemeralDeleteLocalAllocationErase: deleted file should not exist after commit");

    std::vector<std::byte> committed_payload;
    ok &= Require(
        store.ReadCommittedFileRange(L"\\burst-23.bin", 0, kPayloadBytes, committed_payload),
        "EphemeralDeleteLocalAllocationErase: retained file payload should be readable");
    ok &= Require(
        committed_payload == staged_payloads[L"\\burst-23.bin"],
        "EphemeralDeleteLocalAllocationErase: retained file payload should match");

    return ok;
}

bool TestCommitTouchedInodesUsesPendingBtreeIndexConformance(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "commit_touched_inodes_pending_btree_index.apfs.img";
    if (!CreateSyntheticContainerWithSize(image_path, 64 * 1024 * 1024))
    {
        return Require(false, "CommitTouchedInodeIndex: unable to create synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"CommitTouchedInodeIndex",
    };
    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "CommitTouchedInodeIndex: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "CommitTouchedInodeIndex: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "CommitTouchedInodeIndex: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "CommitTouchedInodeIndex: PrepareNativeWritePath should succeed");

    std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
    ConfigurePayloadProvider(store, staged_payloads);

    constexpr std::size_t kFileCount = 32;
    constexpr std::size_t kPayloadBytes = 4096;
    for (std::size_t index = 0; index < kFileCount; ++index)
    {
        const auto path = L"\\touch-" + std::to_wstring(index) + L".bin";

        apfsaccess::rw::MetadataStore::MutationRequest create_file{};
        create_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
        create_file.path = path;
        ok &= ExpectMutationStatus(
            store,
            create_file,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "CommitTouchedInodeIndex: create file should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_file{};
        write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_file.path = path;
        write_file.length = kPayloadBytes;
        ok &= ExpectMutationStatus(
            store,
            write_file,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "CommitTouchedInodeIndex: write file should apply");

        staged_payloads[path] = BuildPatternPayload(
            kPayloadBytes,
            static_cast<unsigned char>(0x21u + (index % 0x5fu)));
    }

    const auto before_json = store.PerformanceJson();
    const auto before_reuse = ExtractNestedUnsignedValue(
        before_json,
        "pendingBtreeFileMetadataIndex",
        "touchedInodeIndexReuse");
    const auto before_fallbacks = ExtractNestedUnsignedValue(
        before_json,
        "pendingBtreeFileMetadataIndex",
        "touchedInodeFallbackScans");
    const auto before_dedupe_fast_paths = ExtractNestedUnsignedValue(
        before_json,
        "pendingBtreeFileMetadataIndex",
        "touchedInodeDedupeFastPaths");
    const auto before_sort_fallbacks = ExtractNestedUnsignedValue(
        before_json,
        "pendingBtreeFileMetadataIndex",
        "touchedInodeSortFallbacks");
    const auto tracked_touched_inodes = ExtractNestedUnsignedValue(
        before_json,
        "pendingBtreeFileMetadataIndex",
        "trackedTouchedInodes");
    ok &= Require(
        before_reuse.has_value() &&
            before_fallbacks.has_value() &&
            before_dedupe_fast_paths.has_value() &&
            before_sort_fallbacks.has_value() &&
            tracked_touched_inodes.has_value(),
        "CommitTouchedInodeIndex: touched-inode counters should exist");
    if (tracked_touched_inodes.has_value())
    {
        ok &= Require(
            tracked_touched_inodes.value() >= kFileCount,
            "CommitTouchedInodeIndex: pending B-tree index should track staged file inodes");
    }

    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "CommitTouchedInodeIndex: commit should succeed");

    const auto after_json = store.PerformanceJson();
    const auto after_reuse = ExtractNestedUnsignedValue(
        after_json,
        "pendingBtreeFileMetadataIndex",
        "touchedInodeIndexReuse");
    const auto after_fallbacks = ExtractNestedUnsignedValue(
        after_json,
        "pendingBtreeFileMetadataIndex",
        "touchedInodeFallbackScans");
    const auto after_dedupe_fast_paths = ExtractNestedUnsignedValue(
        after_json,
        "pendingBtreeFileMetadataIndex",
        "touchedInodeDedupeFastPaths");
    const auto after_sort_fallbacks = ExtractNestedUnsignedValue(
        after_json,
        "pendingBtreeFileMetadataIndex",
        "touchedInodeSortFallbacks");
    if (before_reuse.has_value() && after_reuse.has_value())
    {
        ok &= Require(
            after_reuse.value() == before_reuse.value() + 1,
            "CommitTouchedInodeIndex: commit should reuse pending B-tree touched-inode index");
    }
    if (before_fallbacks.has_value() && after_fallbacks.has_value())
    {
        ok &= Require(
            after_fallbacks.value() == before_fallbacks.value(),
            "CommitTouchedInodeIndex: commit should avoid scanning all pending B-tree records for touched inodes");
    }
    if (before_dedupe_fast_paths.has_value() && after_dedupe_fast_paths.has_value())
    {
        ok &= Require(
            after_dedupe_fast_paths.value() == before_dedupe_fast_paths.value() + 1,
            "CommitTouchedInodeIndex: commit should avoid touched-inode sort/unique for indexed create burst");
    }
    if (before_sort_fallbacks.has_value() && after_sort_fallbacks.has_value())
    {
        ok &= Require(
            after_sort_fallbacks.value() == before_sort_fallbacks.value(),
            "CommitTouchedInodeIndex: indexed create burst should not use touched-inode sort fallback");
    }

    std::vector<std::byte> committed_payload;
    ok &= Require(
        store.ReadCommittedFileRange(L"\\touch-17.bin", 0, kPayloadBytes, committed_payload),
        "CommitTouchedInodeIndex: sampled committed payload should be readable");
    ok &= Require(
        committed_payload == staged_payloads[L"\\touch-17.bin"],
        "CommitTouchedInodeIndex: sampled committed payload should match");

    apfsaccess::rw::MetadataStore remounted(context);
    ConfigurePayloadProvider(remounted, staged_payloads);
    ok &= Require(remounted.LoadContainerSuperblocks(), "CommitTouchedInodeIndex: remount LoadContainerSuperblocks should succeed");
    ok &= Require(remounted.PrepareNativeWritePath(), "CommitTouchedInodeIndex: remount PrepareNativeWritePath should succeed");
    ok &= Require(!remounted.IsRecoveryRequired(), "CommitTouchedInodeIndex: remount should not require recovery");
    committed_payload.clear();
    ok &= Require(
        remounted.ReadCommittedFileRange(L"\\touch-17.bin", 0, kPayloadBytes, committed_payload),
        "CommitTouchedInodeIndex: remounted payload should be readable");
    ok &= Require(
        committed_payload == staged_payloads[L"\\touch-17.bin"],
        "CommitTouchedInodeIndex: remounted payload should match");

    return ok;
}

bool TestObjectIdMonotonicAllocationConformance(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "object_id_monotonic.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "TestObjectIdMonotonicAllocationConformance: unable to create synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"ObjectIdMonotonic",
    };
    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "ObjectIdMonotonic: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "ObjectIdMonotonic: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "ObjectIdMonotonic: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "ObjectIdMonotonic: PrepareNativeWritePath should succeed");

    apfsaccess::rw::MetadataStore::MutationRequest create_file{};
    create_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
    create_file.path = L"\\monotonic.txt";
    ok &= ExpectMutationStatus(
        store,
        create_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "ObjectIdMonotonic: first create should apply");
    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "ObjectIdMonotonic: first create commit should succeed");

    const auto first_inode = store.LookupCommittedInodeByPath(L"\\monotonic.txt");
    ok &= Require(first_inode.has_value(), "ObjectIdMonotonic: first inode should exist");

    apfsaccess::rw::MetadataStore::MutationRequest delete_file{};
    delete_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Delete;
    delete_file.path = L"\\monotonic.txt";
    ok &= ExpectMutationStatus(
        store,
        delete_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "ObjectIdMonotonic: delete should apply");
    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "ObjectIdMonotonic: delete commit should succeed");
    ok &= Require(
        !store.LookupCommittedInodeByPath(L"\\monotonic.txt").has_value(),
        "ObjectIdMonotonic: file should be absent after delete commit");

    ok &= ExpectMutationStatus(
        store,
        create_file,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "ObjectIdMonotonic: second create should apply");
    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "ObjectIdMonotonic: second create commit should succeed");

    const auto second_inode = store.LookupCommittedInodeByPath(L"\\monotonic.txt");
    ok &= Require(second_inode.has_value(), "ObjectIdMonotonic: second inode should exist");
    if (first_inode.has_value() && second_inode.has_value())
    {
        ok &= Require(
            second_inode->object_id != first_inode->object_id,
            "ObjectIdMonotonic: recreated file should not reuse deleted inode object id");
        ok &= Require(
            second_inode->object_id > first_inode->object_id,
            "ObjectIdMonotonic: recreated file should allocate a monotonically increasing object id");
    }

    return ok;
}

bool TestEphemeralReplayRecoveryConformance(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "ephemeral_replay_recovery.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "TestEphemeralReplayRecoveryConformance: unable to create synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"EphemeralReplayRecovery",
    };
    context.crash_replay_mode = L"ReplayIfSafe";

    bool ok = true;
    {
        apfsaccess::rw::MetadataStore store(context);
        ok &= Require(store.LoadContainerSuperblocks(), "EphemeralReplayRecovery: LoadContainerSuperblocks should succeed");
        ok &= Require(store.LoadObjectMap(), "EphemeralReplayRecovery: LoadObjectMap should succeed");
        ok &= Require(store.LoadSpacemanState(), "EphemeralReplayRecovery: LoadSpacemanState should succeed");
        ok &= Require(store.PrepareNativeWritePath(), "EphemeralReplayRecovery: PrepareNativeWritePath should succeed");

        std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
        ConfigurePayloadProvider(store, staged_payloads);

        apfsaccess::rw::MetadataStore::MutationRequest create_file{};
        create_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
        create_file.path = L"\\ephemeral_replay.bin";
        ok &= ExpectMutationStatus(
            store,
            create_file,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "EphemeralReplayRecovery: create file should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_file{};
        write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_file.path = L"\\ephemeral_replay.bin";
        write_file.length = 4096;
        ok &= ExpectMutationStatus(
            store,
            write_file,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "EphemeralReplayRecovery: write file should apply");
        staged_payloads[L"\\ephemeral_replay.bin"] = BuildPatternPayload(4096, 0x3F);

        apfsaccess::rw::MetadataStore::MutationRequest delete_file{};
        delete_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Delete;
        delete_file.path = L"\\ephemeral_replay.bin";
        ok &= ExpectMutationStatus(
            store,
            delete_file,
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "EphemeralReplayRecovery: delete file should apply");
        staged_payloads.erase(L"\\ephemeral_replay.bin");

        ok &= Require(
            store.PendingAllocationCount() == 0,
            "EphemeralReplayRecovery: never-committed file allocation should be released before interrupted commit");
        ok &= Require(
            store.PendingSpacemanAllocationIndexCount() == 0,
            "EphemeralReplayRecovery: released never-committed allocation should leave no pending allocation index entry");
        ok &= Require(
            store.PendingDeallocationCount() == 0,
            "EphemeralReplayRecovery: never-committed file delete should not stage media deallocation before interrupted commit");

        store.SetCommitStageHook([](const auto& stage)
        {
            return stage != "before-checkpoint-switch";
        });

        ok &= ExpectCommitStatus(
            store,
            apfsaccess::rw::MetadataStore::CommitStatus::PersistFailed,
            "EphemeralReplayRecovery: interrupted commit should fail at before-checkpoint-switch");
        ok &= Require(
            store.IsRecoveryRequired(),
            "EphemeralReplayRecovery: interrupted commit should latch recovery-required state");
        ok &= Require(
            store.RecoveryReason() == L"CommitInterruptedBeforeCheckpointSwitch",
            "EphemeralReplayRecovery: interrupted commit should store checkpoint-switch recovery reason");
    }

    {
        apfsaccess::rw::MetadataStore remounted(context);
        ok &= Require(
            remounted.LoadContainerSuperblocks(),
            "EphemeralReplayRecovery: remount LoadContainerSuperblocks should succeed");
        ok &= Require(
            remounted.PrepareNativeWritePath(),
            "EphemeralReplayRecovery: remount PrepareNativeWritePath should succeed");
        ok &= Require(
            remounted.IsRecoveryRequired(),
            "EphemeralReplayRecovery: remount should require recovery before replay");
        ok &= Require(
            remounted.ReplayOrRecover(),
            "EphemeralReplayRecovery: remount replay should succeed for no-op media delta semantics");
        ok &= Require(
            !remounted.IsRecoveryRequired(),
            "EphemeralReplayRecovery: remount should clear recovery state after replay");
        ok &= Require(
            remounted.IsCommitPathReady(),
            "EphemeralReplayRecovery: remount should restore commit path after replay");
        ok &= Require(
            !remounted.LookupCommittedInodeByPath(L"\\ephemeral_replay.bin").has_value(),
            "EphemeralReplayRecovery: committed view should remain without ephemeral file after replay");
    }

    return ok;
}

bool TestNamespaceReplayIdentityBindingConformance(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "namespace_replay_identity.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "NamespaceReplayIdentity: unable to create synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context{
        image_path.wstring(),
        L"NamespaceReplayIdentity",
    };
    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "NamespaceReplayIdentity: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "NamespaceReplayIdentity: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "NamespaceReplayIdentity: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "NamespaceReplayIdentity: PrepareNativeWritePath should succeed");

    apfsaccess::rw::MetadataStore::MutationRequest create{};
    create.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
    create.path = L"\\identity-source.txt";
    ok &= ExpectMutationStatus(
        store,
        create,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "NamespaceReplayIdentity: create should apply");
    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "NamespaceReplayIdentity: create commit should succeed");

    const auto source_inode = store.LookupCommittedInodeByPath(create.path);
    ok &= Require(source_inode.has_value(), "NamespaceReplayIdentity: committed source should exist");
    if (!source_inode.has_value())
    {
        return false;
    }

    apfsaccess::rw::MetadataStore::MutationRequest rename{};
    rename.operation = apfsaccess::rw::MetadataStore::MutationOperation::Rename;
    rename.path = create.path;
    rename.secondary_path = L"\\identity-renamed.txt";
    rename.object_id = source_inode->object_id;
    const auto committed_xid = store.LastCommittedXid().value_or(0);
    ok &= Require(committed_xid != 0, "NamespaceReplayIdentity: committed XID should be available");
    rename.generation = committed_xid + 2;
    ok &= ExpectMutationStatus(
        store,
        rename,
        apfsaccess::rw::MetadataStore::MutationStatus::InvalidRequest,
        "NamespaceReplayIdentity: rename should reject the wrong staged generation");
    ok &= Require(
        store.LastMutationFailureReason() == L"ReplayRenameIdentityMismatch",
        "NamespaceReplayIdentity: wrong rename generation should report identity mismatch");
    ok &= Require(
        store.LookupCommittedInodeByPath(create.path).has_value(),
        "NamespaceReplayIdentity: rejected rename should preserve the source");

    rename.generation = store.LastCommittedXid().value_or(0) + 1;
    apfsaccess::rw::MetadataStore::PayloadIdentity rename_identity{};
    ok &= Require(
        store.StageMutation(rename, &rename_identity) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "NamespaceReplayIdentity: identity-bound rename should apply");
    ok &= Require(
        rename_identity.object_id == source_inode->object_id &&
            rename_identity.generation == rename.generation,
        "NamespaceReplayIdentity: rename should return the staged object generation");
    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "NamespaceReplayIdentity: rename commit should succeed");

    const auto renamed_inode = store.LookupCommittedInodeByPath(rename.secondary_path);
    ok &= Require(renamed_inode.has_value(), "NamespaceReplayIdentity: renamed inode should exist");
    if (!renamed_inode.has_value())
    {
        return false;
    }

    apfsaccess::rw::MetadataStore::MutationRequest delete_file{};
    delete_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Delete;
    delete_file.path = rename.secondary_path;
    delete_file.object_id = renamed_inode->object_id;
    delete_file.generation = renamed_inode->xid + 1;
    ok &= ExpectMutationStatus(
        store,
        delete_file,
        apfsaccess::rw::MetadataStore::MutationStatus::InvalidRequest,
        "NamespaceReplayIdentity: delete should reject the wrong pre-mutation generation");
    ok &= Require(
        store.LastMutationFailureReason() == L"ReplayDeleteIdentityMismatch",
        "NamespaceReplayIdentity: wrong delete generation should report identity mismatch");

    delete_file.generation = renamed_inode->xid == 0
        ? renamed_inode->object_id
        : renamed_inode->xid;
    apfsaccess::rw::MetadataStore::PayloadIdentity delete_identity{};
    ok &= Require(
        store.StageMutation(delete_file, &delete_identity) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "NamespaceReplayIdentity: identity-bound delete should apply");
    ok &= Require(
        delete_identity.object_id == renamed_inode->object_id &&
            delete_identity.generation == delete_file.generation,
        "NamespaceReplayIdentity: delete should return the pre-mutation object generation");
    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "NamespaceReplayIdentity: delete commit should succeed");
    ok &= Require(
        !store.LookupCommittedInodeByPath(delete_file.path).has_value(),
        "NamespaceReplayIdentity: committed delete should remove the recorded inode");

    return ok;
}

bool TestNamespaceReplayWalIdentityPropagationConformance(const std::filesystem::path& run_root)
{
    const auto image_path = run_root / "namespace_replay_wal_identity.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        return Require(false, "NamespaceReplayWalIdentity: unable to create synthetic container");
    }

    apfsaccess::rw::MetadataStore::VolumeContext context{
        image_path.wstring(),
        L"NamespaceReplayWalIdentity",
    };
    apfsaccess::rw::MetadataStore store(context);
    bool ok = true;
    ok &= Require(store.LoadContainerSuperblocks(), "NamespaceReplayWalIdentity: LoadContainerSuperblocks should succeed");
    ok &= Require(store.LoadObjectMap(), "NamespaceReplayWalIdentity: LoadObjectMap should succeed");
    ok &= Require(store.LoadSpacemanState(), "NamespaceReplayWalIdentity: LoadSpacemanState should succeed");
    ok &= Require(store.PrepareNativeWritePath(), "NamespaceReplayWalIdentity: PrepareNativeWritePath should succeed");

    apfsaccess::rw::MetadataStore::MutationRequest create{};
    create.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
    create.path = L"\\wal-identity-source.txt";
    ok &= ExpectMutationStatus(
        store,
        create,
        apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "NamespaceReplayWalIdentity: create should apply");
    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "NamespaceReplayWalIdentity: create commit should succeed");

    const auto source_inode = store.LookupCommittedInodeByPath(create.path);
    if (!Require(source_inode.has_value(), "NamespaceReplayWalIdentity: source inode should exist"))
    {
        return false;
    }

    apfsaccess::rw::MetadataStore::MutationRequest rename{};
    rename.operation = apfsaccess::rw::MetadataStore::MutationOperation::Rename;
    rename.path = create.path;
    rename.secondary_path = L"\\wal-identity-renamed.txt";
    rename.object_id = source_inode->object_id;
    rename.generation = store.LastCommittedXid().value_or(0) + 1;
    apfsaccess::rw::MetadataStore::PayloadIdentity rename_identity{};
    ok &= Require(
        store.StageMutation(rename, &rename_identity) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "NamespaceReplayWalIdentity: identity-bound rename should stage");

    const auto rename_wal = run_root / "namespace-rename.wal";
    apfsaccess::rw::TransactionManager rename_tx(L"NamespaceReplayWalIdentity");
    rename_tx.SetVolumeIdentity(L"namespace-replay-wal-identity");
    rename_tx.SetJournalPath(rename_wal.wstring());
    apfsaccess::rw::TransactionManager::MutationIntent rename_intent{};
    rename_intent.kind = apfsaccess::rw::TransactionManager::MutationKind::Rename;
    rename_intent.path = rename.path;
    rename_intent.secondary_path = rename.secondary_path;
    rename_intent.object_id = rename_identity.object_id;
    rename_intent.generation = rename_identity.generation;
    ok &= Require(rename_tx.Begin(), "NamespaceReplayWalIdentity: rename transaction should begin");
    ok &= Require(rename_tx.RecordMutation(rename_intent), "NamespaceReplayWalIdentity: rename intent should record");
    ok &= Require(rename_tx.Accept(), "NamespaceReplayWalIdentity: rename transaction should accept");

    std::vector<apfsaccess::rw::TransactionManager::AcceptedTransaction> accepted_rename;
    std::string rename_failure;
    ok &= Require(
        rename_tx.LoadAcceptedTransactionsSinceCleanup(accepted_rename, &rename_failure),
        "NamespaceReplayWalIdentity: accepted rename WAL should load");
    ok &= Require(
        accepted_rename.size() == 1 && accepted_rename.front().mutations.size() == 1,
        "NamespaceReplayWalIdentity: accepted rename WAL should contain one mutation");
    if (!accepted_rename.empty() && !accepted_rename.front().mutations.empty())
    {
        const auto& record = accepted_rename.front().mutations.front();
        ok &= Require(
            record.object_id == rename_identity.object_id &&
                record.parent_object_id == rename_identity.generation,
            "NamespaceReplayWalIdentity: rename WAL should retain staged object and generation");
    }
    // The writer lease is volume-scoped, so release this fixture before opening a second WAL.
    rename_tx.SetJournalPath({});

    ok &= ExpectCommitStatus(
        store,
        apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "NamespaceReplayWalIdentity: rename commit should succeed");
    const auto renamed_inode = store.LookupCommittedInodeByPath(rename.secondary_path);
    if (!Require(renamed_inode.has_value(), "NamespaceReplayWalIdentity: renamed inode should exist"))
    {
        return false;
    }

    apfsaccess::rw::MetadataStore::MutationRequest delete_file{};
    delete_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Delete;
    delete_file.path = rename.secondary_path;
    delete_file.object_id = renamed_inode->object_id;
    delete_file.generation = renamed_inode->xid == 0
        ? renamed_inode->object_id
        : renamed_inode->xid;
    apfsaccess::rw::MetadataStore::PayloadIdentity delete_identity{};
    ok &= Require(
        store.StageMutation(delete_file, &delete_identity) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "NamespaceReplayWalIdentity: identity-bound delete should stage");

    const auto delete_wal = run_root / "namespace-delete.wal";
    apfsaccess::rw::TransactionManager delete_tx(L"NamespaceReplayWalIdentity");
    delete_tx.SetVolumeIdentity(L"namespace-replay-wal-identity");
    delete_tx.SetJournalPath(delete_wal.wstring());
    apfsaccess::rw::TransactionManager::MutationIntent delete_intent{};
    delete_intent.kind = apfsaccess::rw::TransactionManager::MutationKind::Delete;
    delete_intent.path = delete_file.path;
    delete_intent.object_id = delete_identity.object_id;
    delete_intent.generation = delete_identity.generation;
    ok &= Require(delete_tx.Begin(), "NamespaceReplayWalIdentity: delete transaction should begin");
    ok &= Require(delete_tx.RecordMutation(delete_intent), "NamespaceReplayWalIdentity: delete intent should record");
    ok &= Require(delete_tx.Accept(), "NamespaceReplayWalIdentity: delete transaction should accept");

    std::vector<apfsaccess::rw::TransactionManager::AcceptedTransaction> accepted_delete;
    std::string delete_failure;
    ok &= Require(
        delete_tx.LoadAcceptedTransactionsSinceCleanup(accepted_delete, &delete_failure),
        "NamespaceReplayWalIdentity: accepted delete WAL should load");
    ok &= Require(
        accepted_delete.size() == 1 && accepted_delete.front().mutations.size() == 1,
        "NamespaceReplayWalIdentity: accepted delete WAL should contain one mutation");
    if (!accepted_delete.empty() && !accepted_delete.front().mutations.empty())
    {
        const auto& record = accepted_delete.front().mutations.front();
        ok &= Require(
            record.object_id == delete_identity.object_id &&
                record.parent_object_id == delete_identity.generation,
            "NamespaceReplayWalIdentity: delete WAL should retain staged object and generation");
    }

    return ok;
}
} // namespace

int main(int argc, char** argv)
{
#if defined(_DEBUG)
    _CrtSetReportMode(_CRT_ASSERT, _CRTDBG_MODE_FILE);
    _CrtSetReportFile(_CRT_ASSERT, _CRTDBG_FILE_STDERR);
#endif
    SetEnvironmentVariableW(L"APFSACCESS_PERF_COUNTERS", L"1");

    bool ok = true;
    std::error_code ec;
    const auto unique_id = std::chrono::steady_clock::now().time_since_epoch().count();
    const auto run_root = std::filesystem::temp_directory_path(ec) /
        ("ApfsAccessRwEngineConformance_" +
         std::to_string(GetCurrentProcessId()) +
         "_" +
         std::to_string(unique_id));
    if (ec)
    {
        std::cerr << "[FAIL] unable to access temporary directory for conformance tests" << std::endl;
        return 1;
    }

    std::filesystem::remove_all(run_root, ec);
    ec.clear();
    std::filesystem::create_directories(run_root, ec);
    if (ec)
    {
        std::cerr << "[FAIL] unable to create conformance run directory" << std::endl;
        return 1;
    }

    const auto run_selected = [&](std::string_view selector) -> bool
    {
        if (selector == "interleaved-rename-chain-coalesces-pending-mutations")
        {
            return TestInterleavedRenameChainsCoalescePendingMutationsConformance(run_root);
        }
        if (selector == "committed-same-size-resize-preserves-extents")
        {
            return TestCommittedSameSizeResizePreservesExtentsConformance(run_root);
        }
        if (selector == "pending-close-delay-classification")
        {
            return TestPendingCloseDelayClassificationConformance(run_root);
        }
        if (selector == "ephemeral-create-delete-releases-pending-allocation")
        {
            return TestEphemeralCreateDeleteConformance(run_root);
        }
        if (selector == "ephemeral-delete-uses-local-pending-allocation-erase")
        {
            return TestEphemeralDeleteUsesLocalPendingAllocationEraseConformance(run_root);
        }
        if (selector == "commit-touched-inodes-use-pending-btree-index")
        {
            return TestCommitTouchedInodesUsesPendingBtreeIndexConformance(run_root);
        }
        if (selector == "object-map-order-cache-updates-single-create")
        {
            return TestObjectMapOrderCacheUpdatesForSingleCreateConformance(run_root);
        }
        if (selector == "checkpoint-slot-validation-uses-indexed-allocations")
        {
            return TestBtreeCheckpointUsesSingleWritableSelectionConformance(run_root);
        }
        if (selector == "order-caches-update-many-creates")
        {
            return TestOrderCachesUpdateManyCreatesConformance(run_root);
        }
        if (selector == "metadata-only-commit-uses-cached-inode-checkpoint-size")
        {
            return TestMetadataOnlyCommitUsesLocalSpacemanApplyConformance(run_root);
        }
        if (selector == "streaming-growth-uses-local-pending-allocation-resize")
        {
            return TestStreamingGrowthUsesReservedExtentSlackConformance(run_root);
        }
        if (selector == "streaming-slack-delete-replay")
        {
            return TestStreamingSlackDeleteReplayConformance(run_root);
        }
        if (selector == "long-streaming-write-keeps-pending-btree-indexes-stable")
        {
            return TestLongStreamingWriteKeepsPendingBtreeIndexesStableConformance(run_root);
        }
        if (selector == "out-of-order-pending-ranges-use-local-merge")
        {
            return TestOutOfOrderPendingWrittenRangesMergeConformance(run_root);
        }
        if (selector == "preallocated-partial-write-ranges")
        {
            return TestPreallocatedPartialWriteCommitRequestsOnlyWrittenRangesConformance(run_root);
        }
        if (selector == "large-range-payload-uses-bounded-materialization")
        {
            return TestLargeRangePayloadUsesBoundedMaterializationConformance(run_root);
        }
        if (selector == "adjacent-split-extents-use-one-payload-read")
        {
            return TestAdjacentSplitExtentsUseOnePayloadRangeProviderReadConformance(run_root);
        }
        if (selector == "prepared-payload-write-through-skips-committed-ranges")
        {
            return TestPreparedPayloadWriteThroughSkipsCommittedRangesConformance(run_root);
        }
        if (selector == "committed-in-body-overwrite-uses-written-range-only")
        {
            return TestCommittedInBodyOverwriteUsesWrittenRangeOnlyConformance(run_root);
        }
        if (selector == "disjoint-partial-overwrites-preserve-committed-bytes-on-interrupted-commit")
        {
            return TestDisjointPartialOverwritesPreserveCommittedBytesOnInterruptedCommitConformance(run_root);
        }
        if (selector == "partial-overwrite-followup-ownership")
        {
            return TestPartialOverwriteFollowupOwnershipConformance(run_root);
        }
        if (selector == "overlapping-partial-overwrites-replay-and-accounting")
        {
            return TestOverlappingPartialOverwritesReplayAndAccountingConformance(run_root);
        }
        if (selector == "partial-overwrite-mid-multi-range-allocation-failure-rolls-back")
        {
            return TestPartialOverwriteMidMultiRangeAllocationFailureRollsBackConformance(run_root);
        }
        if (selector == "fragmented-read-extent-mutation-accounting")
        {
            return TestFragmentedReadExtentMutationAccountingConformance(run_root);
        }
        if (selector == "mutation-allocation-uses-local-working-free-undo")
        {
            return TestMutationAllocationUsesLocalWorkingFreeUndoConformance(run_root);
        }
        if (selector == "fragmented-pending-validation-uses-allocation-index")
        {
            return TestLargeSetFileSizeUsesFragmentedFreeExtentsConformance(run_root);
        }
        if (selector == "pending-validation-overlay-large-committed-state")
        {
            return TestPendingCommitValidationOverlaysLargeCommittedStateConformance(run_root);
        }
        if (selector == "committed-free-list-local-delta-skips-full-compare")
        {
            return TestDeleteBatchUsesLocalSpacemanApplyConformance(run_root);
        }
        if (selector == "many-creates-use-local-spaceman-apply")
        {
            return TestManyCreatesUseLocalSpacemanApplyConformance(run_root);
        }
        if (selector == "commit-stage-hook-keeps-free-list-full-compare")
        {
            return TestCommitStageHookKeepsFreeListFullCompareConformance(run_root);
        }
        if (selector == "checkpoint-family-writes-use-padded-shared-spans")
        {
            return TestCommitBlobSharesPayloadBatchConformance(run_root);
        }
        if (selector == "non-strict-commit-stage-hook-still-interrupts")
        {
            return TestNonStrictCommitStageHookStillInterruptsCommitConformance(run_root);
        }
        if (selector == "checkpoint-batch-hook-failure-recovery-retained")
        {
            return TestCheckpointBatchHookFailureRetainsRecoveryAcrossRemountConformance(run_root);
        }
        if (selector == "checkpoint-batch-torn-write-remount-falls-back")
        {
            return TestCheckpointBatchTornWriteRemountFallsBack(run_root);
        }
        if (selector == "spaceman-rollback-avoids-full-snapshot")
        {
            return TestSpacemanRollbackAvoidsFullSnapshotConformance(run_root);
        }
        if (selector == "commit-btree-rollback-avoids-full-snapshot")
        {
            return TestCommitBtreeRollbackAvoidsFullSnapshotConformance(run_root);
        }
        if (selector == "mutation-restore-dedupe-uses-hash-for-large-subtree-rename")
        {
            return TestMutationRestoreDedupeUsesHashForLargeSubtreeRenameConformance(run_root);
        }
        if (selector == "directory-subtree-rename-source-case-insensitive")
        {
            return TestDirectorySubtreeRenameMatchesSourceCaseInsensitivelyConformance(run_root);
        }
        if (selector == "fresh-ingest-commit-skips-inode-graph-validation")
        {
            return TestFreshIngestCommitSkipsInodeGraphValidationConformance(run_root);
        }
        if (selector == "pending-payload-directory-rename-uses-prefix-index")
        {
            return TestPendingPayloadDirectoryRenameUsesPrefixIndexConformance(run_root);
        }
        if (selector == "pending-payload-nested-file-delete-uses-exact-index")
        {
            return TestPendingPayloadNestedFileDeleteUsesExactIndexConformance(run_root);
        }
        if (selector == "committed-directory-link-index-avoids-full-rebuild")
        {
            return TestCommittedDirectoryLinkIndexAvoidsFullRebuildConformance(run_root);
        }
        if (selector == "checkpoint-delta-shadow-telemetry")
        {
            return TestCheckpointDeltaShadowTelemetryConformance(run_root);
        }
        if (selector == "pending-checkpoint-delta-builder")
        {
            return TestPendingCheckpointDeltaBuilderConformance(run_root);
        }
        if (selector == "namespace-replay-identity-binding")
        {
            return TestNamespaceReplayIdentityBindingConformance(run_root);
        }
        if (selector == "namespace-replay-wal-identity-propagation")
        {
            return TestNamespaceReplayWalIdentityPropagationConformance(run_root);
        }
        if (selector == "ephemeral-tail-allocation-removes-overlapping-free-ledger")
        {
            return TestEphemeralTailAllocationRemovesOverlappingFreeLedgerConformance(run_root);
        }
        if (selector == "committed-read-extent-snapshot-cache")
        {
            return TestCommittedReadExtentsConformance(run_root);
        }

        std::cerr << "[FAIL] unknown MetadataStoreConformanceTests selector: " << selector << std::endl;
        return false;
    };

    if (argc > 1)
    {
        bool selected_ok = true;
        for (int index = 1; index < argc; ++index)
        {
            selected_ok &= run_selected(argv[index] == nullptr ? std::string_view{} : std::string_view{argv[index]});
        }
        std::filesystem::remove_all(run_root, ec);
        if (!selected_ok)
        {
            return 1;
        }

        std::cout << "[PASS] MetadataStoreConformanceTests selected" << std::endl;
        return 0;
    }

    ok &= TestPendingCheckpointDeltaBuilderConformance(run_root);
    ok &= TestNamespaceReplayIdentityBindingConformance(run_root);
    ok &= TestNamespaceReplayWalIdentityPropagationConformance(run_root);
    ok &= TestCheckpointDeltaShadowTelemetryConformance(run_root);
    ok &= TestRenameReplaceConformance(run_root);
    ok &= TestDirectoryAndDeleteConformance(run_root);
    ok &= TestWorkingDirectoryIndexConformance(run_root);
    ok &= TestWorkingDirectoryChildIndexAvoidsSiblingScansConformance(run_root);
    ok &= TestDirectorySubtreeDeleteConformance(run_root);
    ok &= TestTruncateConformance(run_root);
    ok &= TestDirectorySubtreeRenameObjectMapConformance(run_root);
    ok &= TestDirectorySubtreeRenameChildIndexConformance(run_root);
    ok &= TestDirectorySubtreeRenameMatchesSourceCaseInsensitivelyConformance(run_root);
    ok &= TestPendingWriteDirectoryRenamePersistenceConformance(run_root);
    ok &= TestInterleavedRenameChainsCoalescePendingMutationsConformance(run_root);
    ok &= TestPendingPayloadByteEstimateTracksFinalSetFileSizeConformance(run_root);
    ok &= TestPendingPayloadByteEstimateTracksRepeatedSizeGrowthConformance(run_root);
    ok &= TestRepeatedSetFileSizeReusesPendingExtentConformance(run_root);
    ok &= TestCommittedSameSizeResizePreservesExtentsConformance(run_root);
    ok &= TestSetFileSizeZeroReleasesPendingPreallocationConformance(run_root);
    ok &= TestPendingPayloadByteEstimateTracksCachedRenameDeleteConformance(run_root);
    ok &= TestPendingPayloadFileDeleteAvoidsUnrelatedPathScanConformance(run_root);
    ok &= TestPendingPayloadFileRenameAvoidsUnrelatedPathScanConformance(run_root);
    ok &= TestPendingPayloadDirectoryRenameUsesPrefixIndexConformance(run_root);
    ok &= TestPendingPayloadNestedFileDeleteUsesExactIndexConformance(run_root);
    ok &= TestPendingPayloadSummaryDropsDirtyReplaceTargetConformance(run_root);
    ok &= TestPendingPayloadSummaryDropsDirtyCreateReplaceTargetConformance(run_root);
    ok &= TestPendingPayloadSummaryKeepsDirtyReplaceSourceConformance(run_root);
    ok &= TestPendingPayloadSummaryKeepsCaseOnlyReplaceRenameConformance(run_root);
    ok &= TestPendingCloseDelayClassificationConformance(run_root);
    ok &= TestLargeSetFileSizeUsesFragmentedFreeExtentsConformance(run_root);
    ok &= TestFragmentedCommittedFileAllowsLaterUnrelatedMutationConformance(run_root);
    ok &= TestSequentialWriteBurstCoalescesPendingMetadataConformance(run_root);
    ok &= TestInterleavedSetBasicInfoCoalescesPendingMutationConformance(run_root);
    ok &= TestStreamingLargeCopyWithoutPreallocationCoalescesPendingMetadataConformance(run_root);
    ok &= TestLongStreamingWriteKeepsPendingBtreeIndexesStableConformance(run_root);
    ok &= TestSmallFilePendingWriteCoalescingAvoidsFirstWriteScansConformance(run_root);
    ok &= TestCommitSkipsDuplicatePostAllocationGraphValidationConformance(run_root);
    ok &= TestStreamingGrowthUsesReservedExtentSlackConformance(run_root);
    ok &= TestStreamingSlackDeleteReplayConformance(run_root);
    ok &= TestPendingStreamingTailDeleteReleasesReservedSlackConformance(run_root);
    ok &= TestPendingPreallocationWriteBurstReusesExtentsConformance(run_root);
    ok &= TestPayloadRangeProviderAvoidsWholeFileProviderConformance(run_root);
    ok &= TestLargeRangePayloadUsesBoundedMaterializationConformance(run_root);
    ok &= TestPreallocatedPartialWriteCommitRequestsOnlyWrittenRangesConformance(run_root);
    ok &= TestOutOfOrderPendingWrittenRangesMergeConformance(run_root);
    ok &= TestAdjacentSplitExtentsUseOnePayloadRangeProviderReadConformance(run_root);
    ok &= TestExistingFileRewriteMaterializesCommittedBytesConformance(run_root);
    ok &= TestCommittedSpoolStyleWriteThenRenameConformance(run_root);
    ok &= TestPreparedPayloadWriteThroughSkipsCommittedRangesConformance(run_root);
    ok &= TestCommittedInBodyOverwriteUsesWrittenRangeOnlyConformance(run_root);
    ok &= TestDisjointPartialOverwritesPreserveCommittedBytesOnInterruptedCommitConformance(run_root);
    ok &= TestPartialOverwriteFollowupOwnershipConformance(run_root);
    ok &= TestOverlappingPartialOverwritesReplayAndAccountingConformance(run_root);
    ok &= TestPartialOverwriteMidMultiRangeAllocationFailureRollsBackConformance(run_root);
    ok &= TestBtreeCanonicalizationConformance(run_root);
    ok &= TestBtreeCheckpointUsesSingleWritableSelectionConformance(run_root);
    ok &= TestMetadataOnlyCommitUsesLocalSpacemanApplyConformance(run_root);
    ok &= TestDeleteBatchUsesLocalSpacemanApplyConformance(run_root);
    ok &= TestManyCreatesUseLocalSpacemanApplyConformance(run_root);
    ok &= TestSpacemanRollbackAvoidsFullSnapshotConformance(run_root);
    ok &= TestExtentShapeTelemetryConformance(run_root);
    ok &= TestCommitRestoreDedupeAvoidsLinearScansConformance(run_root);
    ok &= TestMutationRestoreDedupeUsesHashForLargeSubtreeRenameConformance(run_root);
    ok &= TestCommitBlobSharesPayloadBatchConformance(run_root);
    ok &= TestNonStrictCommitStageHookStillInterruptsCommitConformance(run_root);
    ok &= TestCheckpointBatchHookFailureRetainsRecoveryAcrossRemountConformance(run_root);
    ok &= TestCheckpointBatchTornWriteRemountFallsBack(run_root);
    ok &= TestFreshPayloadTailWriteAvoidsReadModifyWriteConformance(run_root);
    ok &= TestCommittedDirectoryLinkIndexAvoidsFullRebuildConformance(run_root);
    ok &= TestPendingWriteCoalesceUsesNormalizedPathHintConformance(run_root);
    ok &= TestCommitBtreeRollbackAvoidsFullSnapshotConformance(run_root);
    ok &= TestCommittedReadExtentsConformance(run_root);
    ok &= TestCommittedZeroReadExtentConformance(run_root);
    ok &= TestFragmentedReadExtentMutationAccountingConformance(run_root);
    ok &= TestRecycleBinRestoreRenameConformance(run_root);
    ok &= TestStaleFreeExtentOverlapSanitizedConformance(run_root);
    ok &= TestEphemeralTailAllocationRemovesOverlappingFreeLedgerConformance(run_root);
    ok &= TestObjectMapDeltaCanonicalizationConformance(run_root);
    ok &= TestObjectMapCheckpointHandlesManySmallFilesConformance(run_root);
    ok &= TestPendingCommitValidationOverlaysLargeCommittedStateConformance(run_root);
    ok &= TestPendingCommitValidationUsesSortedAllocationChecksConformance(run_root);
    ok &= TestContentOnlyCommitSkipsInodeGraphValidationConformance(run_root);
    ok &= TestFreshIngestCommitSkipsInodeGraphValidationConformance(run_root);
    ok &= TestEphemeralCreateDeleteConformance(run_root);
    ok &= TestEphemeralDeleteUsesLocalPendingAllocationEraseConformance(run_root);
    ok &= TestCommitTouchedInodesUsesPendingBtreeIndexConformance(run_root);
    ok &= TestObjectMapOrderCacheUpdatesForSingleCreateConformance(run_root);
    ok &= TestOrderCachesUpdateManyCreatesConformance(run_root);
    ok &= TestObjectIdMonotonicAllocationConformance(run_root);
    ok &= TestEphemeralReplayRecoveryConformance(run_root);

    std::filesystem::remove_all(run_root, ec);
    if (!ok)
    {
        return 1;
    }

    std::cout << "[PASS] MetadataStoreConformanceTests" << std::endl;
    return 0;
}
