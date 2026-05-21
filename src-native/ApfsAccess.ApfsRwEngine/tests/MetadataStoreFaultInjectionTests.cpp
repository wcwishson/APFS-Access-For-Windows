#include "MetadataStore.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <cwctype>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace
{
constexpr std::size_t kContainerBytes = 4 * 1024 * 1024;
constexpr std::uint32_t kBlockSize = 4096;
constexpr std::uint64_t kTotalBlocks = 1024;
constexpr std::uint64_t kInitialCheckpointXid = 7;
constexpr std::uint64_t kSpacemanObjectId = 0x2A;
constexpr std::uint64_t kVolumeRootObject = 0x54;
constexpr std::uint32_t kNxsbMagic = 0x4253584E; // NXSB

constexpr std::size_t kCheckpointHeaderBytes = 32;
constexpr std::size_t kCheckpointChecksumOffset = 28;
constexpr std::uint32_t kCheckpointChecksumSeed = 2166136261u;
constexpr std::uint32_t kCheckpointChecksumPrime = 16777619u;

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
    for (std::size_t i = 0; i < 4; ++i)
    {
        value |= static_cast<std::uint32_t>(std::to_integer<unsigned char>(buffer[offset + i])) << (i * 8);
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
    for (std::size_t i = 0; i < 8; ++i)
    {
        value |= static_cast<std::uint64_t>(std::to_integer<unsigned char>(buffer[offset + i])) << (i * 8);
    }
    return value;
}

std::uint32_t UpdateFnv1a(std::uint32_t hash, const std::byte* bytes, std::size_t length)
{
    for (std::size_t index = 0; index < length; ++index)
    {
        hash ^= static_cast<std::uint32_t>(std::to_integer<unsigned char>(bytes[index]));
        hash *= kCheckpointChecksumPrime;
    }
    return hash;
}

bool CreateSyntheticContainer(const std::filesystem::path& image_path)
{
    std::vector<std::byte> bytes(kContainerBytes, std::byte{0});
    const auto write_superblock = [&](std::size_t base_offset, std::uint64_t checkpoint_xid)
    {
        WriteLe64(bytes, base_offset + 0x10, checkpoint_xid);
        WriteLe32(bytes, base_offset + 0x20, kNxsbMagic);
        WriteLe32(bytes, base_offset + 0x24, kBlockSize);
        WriteLe64(bytes, base_offset + 0x28, kTotalBlocks);
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

std::optional<std::uint64_t> ReadLe64FromImage(
    const std::filesystem::path& image_path,
    std::uint64_t offset_bytes)
{
    std::array<unsigned char, 8> raw{};
    std::ifstream input(image_path, std::ios::binary);
    if (!input.good())
    {
        return std::nullopt;
    }

    input.seekg(static_cast<std::streamoff>(offset_bytes), std::ios::beg);
    if (!input.good())
    {
        return std::nullopt;
    }

    input.read(reinterpret_cast<char*>(raw.data()), static_cast<std::streamsize>(raw.size()));
    if (static_cast<std::size_t>(input.gcount()) != raw.size())
    {
        return std::nullopt;
    }

    std::uint64_t value = 0;
    for (std::size_t i = 0; i < raw.size(); ++i)
    {
        value |= static_cast<std::uint64_t>(raw[i]) << (i * 8);
    }

    return value;
}

bool CorruptSuperblockCheckpointXids(
    const std::filesystem::path& image_path,
    std::uint64_t replacement_xid,
    std::size_t& corrupted_superblocks)
{
    corrupted_superblocks = 0;

    std::ifstream input(image_path, std::ios::binary);
    if (!input.good())
    {
        return false;
    }

    input.seekg(0, std::ios::end);
    if (!input.good())
    {
        return false;
    }

    const auto file_size = input.tellg();
    if (file_size <= 0)
    {
        return false;
    }

    const auto bytes_size = static_cast<std::size_t>(file_size);
    std::vector<std::byte> bytes(bytes_size, std::byte{0});
    input.seekg(0, std::ios::beg);
    if (!input.good())
    {
        return false;
    }

    input.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    if (static_cast<std::size_t>(input.gcount()) != bytes.size())
    {
        return false;
    }

    const auto try_corrupt_superblock = [&](std::size_t base_offset)
    {
        constexpr std::size_t kCheckpointXidOffset = 0x10;
        constexpr std::size_t kMagicOffset = 0x20;
        constexpr std::size_t kBlockSizeOffset = 0x24;
        constexpr std::size_t kHeaderBytes = 0x28;
        if (base_offset > (std::numeric_limits<std::size_t>::max() - kHeaderBytes) ||
            (base_offset + kHeaderBytes) > bytes.size())
        {
            return;
        }

        if (ReadLe32(bytes, base_offset + kMagicOffset) != kNxsbMagic ||
            ReadLe32(bytes, base_offset + kBlockSizeOffset) != kBlockSize)
        {
            return;
        }

        WriteLe64(bytes, base_offset + kCheckpointXidOffset, replacement_xid);
        ++corrupted_superblocks;
    };

    try_corrupt_superblock(0);
    try_corrupt_superblock(static_cast<std::size_t>(kBlockSize));
    if (corrupted_superblocks == 0)
    {
        return false;
    }

    std::ofstream output(image_path, std::ios::binary | std::ios::trunc);
    if (!output.good())
    {
        return false;
    }

    output.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    return output.good();
}

bool ReadBytesFromImage(
    const std::filesystem::path& image_path,
    std::uint64_t offset_bytes,
    std::size_t bytes_to_read,
    std::vector<std::byte>& out_bytes)
{
    out_bytes.clear();
    if (bytes_to_read == 0 ||
        offset_bytes > static_cast<std::uint64_t>(std::numeric_limits<std::streamoff>::max()))
    {
        return false;
    }

    std::ifstream input(image_path, std::ios::binary);
    if (!input.good())
    {
        return false;
    }

    input.seekg(static_cast<std::streamoff>(offset_bytes), std::ios::beg);
    if (!input.good())
    {
        return false;
    }

    out_bytes.resize(bytes_to_read);
    input.read(reinterpret_cast<char*>(out_bytes.data()), static_cast<std::streamsize>(out_bytes.size()));
    if (static_cast<std::size_t>(input.gcount()) != out_bytes.size())
    {
        out_bytes.clear();
        return false;
    }

    return true;
}

std::uint64_t StableObjectIdFromPath(std::wstring_view path)
{
    constexpr std::uint64_t kFnvOffset = 1469598103934665603ull;
    constexpr std::uint64_t kFnvPrime = 1099511628211ull;

    std::uint64_t hash = kFnvOffset;
    for (const auto ch : path)
    {
        const auto lower = static_cast<std::uint16_t>(std::towlower(ch));
        const auto lo = static_cast<std::uint8_t>(lower & 0xffu);
        const auto hi = static_cast<std::uint8_t>((lower >> 8) & 0xffu);
        hash ^= lo;
        hash *= kFnvPrime;
        hash ^= hi;
        hash *= kFnvPrime;
    }

    return hash == 0 ? 1 : hash;
}

std::filesystem::path BuildPersistentStatePath(const std::wstring& device_path, const std::wstring& volume_name)
{
    std::error_code ec;
    auto root = std::filesystem::temp_directory_path(ec);
    if (ec)
    {
        return {};
    }

    root /= "ApfsAccess";
    root /= "rw-state";
    const auto key = device_path + L"|" + volume_name;
    const auto stable_id = StableObjectIdFromPath(key);
    return root / (std::to_wstring(stable_id) + L".bin");
}

struct PersistentStateLayout
{
    std::unordered_map<std::uint64_t, std::size_t> object_logical_size_offsets;
    std::unordered_map<std::uint64_t, std::uint64_t> object_physical_addresses;
    std::vector<std::pair<std::uint64_t, std::size_t>> allocation_physical_offsets;
    std::unordered_map<std::wstring, std::uint64_t> inode_object_ids_by_path;
};

bool TryReadLe32(const std::vector<std::byte>& buffer, std::size_t offset, std::uint32_t& value)
{
    if (offset > (std::numeric_limits<std::size_t>::max() - sizeof(std::uint32_t)) ||
        (offset + sizeof(std::uint32_t)) > buffer.size())
    {
        return false;
    }

    value = static_cast<std::uint32_t>(std::to_integer<unsigned char>(buffer[offset + 0])) |
            (static_cast<std::uint32_t>(std::to_integer<unsigned char>(buffer[offset + 1])) << 8) |
            (static_cast<std::uint32_t>(std::to_integer<unsigned char>(buffer[offset + 2])) << 16) |
            (static_cast<std::uint32_t>(std::to_integer<unsigned char>(buffer[offset + 3])) << 24);
    return true;
}

bool TryReadLe64(const std::vector<std::byte>& buffer, std::size_t offset, std::uint64_t& value)
{
    if (offset > (std::numeric_limits<std::size_t>::max() - sizeof(std::uint64_t)) ||
        (offset + sizeof(std::uint64_t)) > buffer.size())
    {
        return false;
    }

    value = 0;
    for (std::size_t i = 0; i < sizeof(std::uint64_t); ++i)
    {
        value |= static_cast<std::uint64_t>(std::to_integer<unsigned char>(buffer[offset + i])) << (i * 8);
    }
    return true;
}

bool LoadPersistentStateBytes(
    const std::filesystem::path& persistent_state_path,
    std::vector<std::byte>& out_bytes)
{
    out_bytes.clear();

    std::ifstream input(persistent_state_path, std::ios::binary);
    if (!input.good())
    {
        return false;
    }

    input.seekg(0, std::ios::end);
    if (!input.good())
    {
        return false;
    }

    const auto total_bytes = static_cast<std::size_t>(input.tellg());
    input.seekg(0, std::ios::beg);
    if (!input.good())
    {
        return false;
    }

    out_bytes.resize(total_bytes);
    if (!out_bytes.empty())
    {
        input.read(reinterpret_cast<char*>(out_bytes.data()), static_cast<std::streamsize>(out_bytes.size()));
        if (static_cast<std::size_t>(input.gcount()) != out_bytes.size())
        {
            out_bytes.clear();
            return false;
        }
    }

    return true;
}

bool SavePersistentStateBytes(
    const std::filesystem::path& persistent_state_path,
    const std::vector<std::byte>& bytes)
{
    auto normalized = bytes;
    if (normalized.size() >= (16 + sizeof(std::uint32_t)))
    {
        const auto version = ReadLe32(normalized, 16);
        if (version >= 6)
        {
            constexpr std::size_t kPersistentStateChecksumOffset = 20;
            constexpr std::size_t kPersistentStateChecksumBytes = 4;
            if (normalized.size() < (kPersistentStateChecksumOffset + kPersistentStateChecksumBytes))
            {
                return false;
            }

            auto checksum = kCheckpointChecksumSeed;
            checksum = UpdateFnv1a(checksum, normalized.data(), kPersistentStateChecksumOffset);
            if (normalized.size() > (kPersistentStateChecksumOffset + kPersistentStateChecksumBytes))
            {
                checksum = UpdateFnv1a(
                    checksum,
                    normalized.data() + static_cast<std::vector<std::byte>::difference_type>(
                        kPersistentStateChecksumOffset + kPersistentStateChecksumBytes),
                    normalized.size() - (kPersistentStateChecksumOffset + kPersistentStateChecksumBytes));
            }
            WriteLe32(normalized, kPersistentStateChecksumOffset, checksum);
        }
    }

    std::ofstream output(persistent_state_path, std::ios::binary | std::ios::trunc);
    if (!output.good())
    {
        return false;
    }

    if (!normalized.empty())
    {
        output.write(reinterpret_cast<const char*>(normalized.data()), static_cast<std::streamsize>(normalized.size()));
    }
    return output.good();
}

bool ParsePersistentStateLayout(
    const std::vector<std::byte>& bytes,
    PersistentStateLayout& layout)
{
    layout.object_logical_size_offsets.clear();
    layout.object_physical_addresses.clear();
    layout.allocation_physical_offsets.clear();
    layout.inode_object_ids_by_path.clear();

    constexpr std::array<char, 16> kExpectedMagic =
    {
        'A', 'P', 'F', 'S', 'R', 'W', 'S', 'T', 'A', 'T', 'E', '2', '\0', '\0', '\0', '\0'
    };
    if (bytes.size() < kExpectedMagic.size())
    {
        return false;
    }

    for (std::size_t i = 0; i < kExpectedMagic.size(); ++i)
    {
        if (std::to_integer<unsigned char>(bytes[i]) != static_cast<unsigned char>(kExpectedMagic[i]))
        {
            return false;
        }
    }

    std::size_t cursor = kExpectedMagic.size();
    auto read_u32 = [&bytes, &cursor](std::uint32_t& value) -> bool
    {
        if (!TryReadLe32(bytes, cursor, value))
        {
            return false;
        }
        cursor += sizeof(std::uint32_t);
        return true;
    };
    auto read_u64 = [&bytes, &cursor](std::uint64_t& value) -> bool
    {
        if (!TryReadLe64(bytes, cursor, value))
        {
            return false;
        }
        cursor += sizeof(std::uint64_t);
        return true;
    };
    auto read_wstring = [&bytes, &cursor](std::uint32_t length, std::wstring& value) -> bool
    {
        value.clear();
        if (length == 0)
        {
            return true;
        }

        if (length > (std::numeric_limits<std::uint32_t>::max() / sizeof(wchar_t)))
        {
            return false;
        }
        const auto bytes_to_read = static_cast<std::size_t>(length) * sizeof(wchar_t);
        if (cursor > (std::numeric_limits<std::size_t>::max() - bytes_to_read) ||
            (cursor + bytes_to_read) > bytes.size())
        {
            return false;
        }

        value.assign(length, L'\0');
        std::memcpy(value.data(), bytes.data() + cursor, bytes_to_read);
        cursor += bytes_to_read;
        return true;
    };

    std::uint32_t version = 0;
    std::uint32_t persisted_state_checksum = 0;
    std::uint64_t persisted_checkpoint_xid = 0;
    std::uint64_t persisted_last_commit_xid = 0;
    std::uint64_t persisted_next_extent = 0;
    std::uint64_t persisted_next_object_id = 0;
    std::uint64_t persisted_last_commit_blob_address = 0;
    std::uint64_t persisted_last_commit_blob_bytes = 0;
    std::uint32_t object_count = 0;
    std::uint32_t allocation_count = 0;
    std::uint32_t inode_count = 0;
    std::uint32_t btree_record_count = 0;
    std::uint32_t free_extent_count = 0;
    if (!read_u32(version))
    {
        return false;
    }
    if (version >= 6 && !read_u32(persisted_state_checksum))
    {
        return false;
    }
    if (!read_u64(persisted_checkpoint_xid) ||
        !read_u64(persisted_last_commit_xid) ||
        !read_u64(persisted_next_extent) ||
        !read_u64(persisted_last_commit_blob_address) ||
        !read_u64(persisted_last_commit_blob_bytes) ||
        !read_u32(object_count) ||
        !read_u32(allocation_count))
    {
        return false;
    }
    if (version != 1 &&
        version != 2 &&
        version != 3 &&
        version != 4 &&
        version != 5 &&
        version != 6 &&
        version != 7)
    {
        return false;
    }
    if (version >= 2 && !read_u32(inode_count))
    {
        return false;
    }
    if (version >= 3 && !read_u32(btree_record_count))
    {
        return false;
    }
    if (version >= 4 && !read_u32(free_extent_count))
    {
        return false;
    }
    if (version >= 5 && !read_u64(persisted_next_object_id))
    {
        return false;
    }
    (void)persisted_state_checksum;

    for (std::uint32_t index = 0; index < object_count; ++index)
    {
        const auto entry_offset = cursor;
        std::uint64_t object_id = 0;
        std::uint64_t physical_address = 0;
        std::uint64_t logical_size = 0;
        std::uint64_t xid = 0;
        if (!read_u64(object_id) ||
            !read_u64(physical_address) ||
            !read_u64(logical_size) ||
            !read_u64(xid))
        {
            return false;
        }
        if (object_id == 0)
        {
            return false;
        }
        if (!layout.object_logical_size_offsets.emplace(object_id, entry_offset + 16).second)
        {
            return false;
        }
        if (!layout.object_physical_addresses.emplace(object_id, physical_address).second)
        {
            return false;
        }
    }

    for (std::uint32_t index = 0; index < allocation_count; ++index)
    {
        const auto entry_offset = cursor;
        std::uint64_t physical_address = 0;
        std::uint64_t allocation_bytes = 0;
        if (!read_u64(physical_address) ||
            !read_u64(allocation_bytes))
        {
            return false;
        }
        if (physical_address == 0 || allocation_bytes == 0)
        {
            return false;
        }
        layout.allocation_physical_offsets.emplace_back(physical_address, entry_offset);
    }

    if (version >= 2)
    {
        for (std::uint32_t index = 0; index < inode_count; ++index)
        {
            std::uint64_t object_id = 0;
            std::uint64_t parent_object_id = 0;
            std::uint64_t logical_size = 0;
            std::uint64_t data_physical_address = 0;
            std::uint64_t xid = 0;
            std::uint64_t timestamp_utc = 0;
            std::uint32_t flags = 0;
            std::uint32_t name_length = 0;
            std::uint32_t path_length = 0;
            std::wstring name;
            std::wstring path;
            if (!read_u64(object_id) ||
                !read_u64(parent_object_id) ||
                !read_u64(logical_size) ||
                !read_u64(data_physical_address) ||
                !read_u64(xid) ||
                (version >= 7 && !read_u64(timestamp_utc)) ||
                !read_u32(flags) ||
                !read_u32(name_length) ||
                !read_u32(path_length) ||
                !read_wstring(name_length, name) ||
                !read_wstring(path_length, path))
            {
                return false;
            }
            (void)parent_object_id;
            (void)logical_size;
            (void)data_physical_address;
            (void)xid;
            (void)timestamp_utc;
            (void)flags;
            (void)name;
            if (object_id == 0 || path.empty())
            {
                return false;
            }
            if (!layout.inode_object_ids_by_path.emplace(path, object_id).second)
            {
                return false;
            }
        }
    }

    if (version >= 3)
    {
        for (std::uint32_t index = 0; index < btree_record_count; ++index)
        {
            std::uint32_t kind = 0;
            std::uint32_t tombstone = 0;
            std::uint32_t key_size = 0;
            std::uint32_t value_size = 0;
            if (!read_u32(kind) ||
                !read_u32(tombstone) ||
                !read_u32(key_size) ||
                !read_u32(value_size))
            {
                return false;
            }
            (void)kind;
            (void)tombstone;
            const auto total_bytes = static_cast<std::uint64_t>(key_size) + static_cast<std::uint64_t>(value_size);
            if (total_bytes > (std::numeric_limits<std::size_t>::max() - cursor))
            {
                return false;
            }
            const auto payload_bytes = static_cast<std::size_t>(total_bytes);
            if (cursor > (std::numeric_limits<std::size_t>::max() - payload_bytes) ||
                (cursor + payload_bytes) > bytes.size())
            {
                return false;
            }
            cursor += payload_bytes;
        }
    }

    if (version >= 4)
    {
        for (std::uint32_t index = 0; index < free_extent_count; ++index)
        {
            std::uint64_t free_extent_address = 0;
            std::uint64_t free_extent_bytes = 0;
            if (!read_u64(free_extent_address) ||
                !read_u64(free_extent_bytes))
            {
                return false;
            }
        }
    }

    return cursor <= bytes.size();
}

bool CorruptPersistentStateObjectMapLogicalSizeForPath(
    const std::filesystem::path& persistent_state_path,
    const std::wstring& target_path,
    std::uint64_t logical_size)
{
    std::vector<std::byte> persistent_state;
    if (!LoadPersistentStateBytes(persistent_state_path, persistent_state))
    {
        return false;
    }

    PersistentStateLayout layout;
    if (!ParsePersistentStateLayout(persistent_state, layout))
    {
        return false;
    }

    auto inode_it = layout.inode_object_ids_by_path.find(target_path);
    if (inode_it == layout.inode_object_ids_by_path.end())
    {
        return false;
    }

    auto object_it = layout.object_logical_size_offsets.find(inode_it->second);
    if (object_it == layout.object_logical_size_offsets.end())
    {
        return false;
    }

    WriteLe64(persistent_state, object_it->second, logical_size);
    return SavePersistentStateBytes(persistent_state_path, persistent_state);
}

bool CorruptPersistentStateSpacemanAllocationForPath(
    const std::filesystem::path& persistent_state_path,
    const std::wstring& target_path,
    std::uint64_t mutated_physical_address)
{
    if (mutated_physical_address == 0)
    {
        return false;
    }

    std::vector<std::byte> persistent_state;
    if (!LoadPersistentStateBytes(persistent_state_path, persistent_state))
    {
        return false;
    }

    PersistentStateLayout layout;
    if (!ParsePersistentStateLayout(persistent_state, layout))
    {
        return false;
    }

    auto inode_it = layout.inode_object_ids_by_path.find(target_path);
    if (inode_it == layout.inode_object_ids_by_path.end())
    {
        return false;
    }

    auto object_it = layout.object_physical_addresses.find(inode_it->second);
    if (object_it == layout.object_physical_addresses.end())
    {
        return false;
    }

    if (mutated_physical_address == object_it->second)
    {
        return false;
    }

    for (const auto& [allocation_address, _] : layout.allocation_physical_offsets)
    {
        if (allocation_address == mutated_physical_address)
        {
            return false;
        }
    }

    for (const auto& [allocation_address, offset] : layout.allocation_physical_offsets)
    {
        if (allocation_address != object_it->second)
        {
            continue;
        }

        WriteLe64(persistent_state, offset, mutated_physical_address);
        return SavePersistentStateBytes(persistent_state_path, persistent_state);
    }

    return false;
}

bool OverridePersistentStateCommitBlobMetadata(
    const std::filesystem::path& persistent_state_path,
    std::uint64_t persisted_last_commit_xid,
    std::uint64_t persisted_commit_blob_address,
    std::uint64_t persisted_commit_blob_bytes)
{
    std::vector<std::byte> persistent_state;
    if (!LoadPersistentStateBytes(persistent_state_path, persistent_state))
    {
        return false;
    }

    constexpr std::array<char, 16> kExpectedMagic =
    {
        'A', 'P', 'F', 'S', 'R', 'W', 'S', 'T', 'A', 'T', 'E', '2', '\0', '\0', '\0', '\0'
    };
    if (persistent_state.size() < (kExpectedMagic.size() + sizeof(std::uint32_t) + (8 + 8 + 8 + 8 + 8)))
    {
        return false;
    }
    for (std::size_t i = 0; i < kExpectedMagic.size(); ++i)
    {
        if (std::to_integer<unsigned char>(persistent_state[i]) != static_cast<unsigned char>(kExpectedMagic[i]))
        {
            return false;
        }
    }

    const auto version = ReadLe32(persistent_state, kExpectedMagic.size());
    const auto header_base_offset = kExpectedMagic.size() +
        sizeof(std::uint32_t) +
        (version >= 6 ? sizeof(std::uint32_t) : 0);
    constexpr std::size_t kPersistedLastCommitXidRelativeOffset = 8;
    constexpr std::size_t kPersistedLastCommitBlobAddressRelativeOffset = 24;
    constexpr std::size_t kPersistedLastCommitBlobBytesRelativeOffset = 32;
    const auto kPersistedLastCommitXidOffset = header_base_offset + kPersistedLastCommitXidRelativeOffset;
    const auto kPersistedLastCommitBlobAddressOffset = header_base_offset + kPersistedLastCommitBlobAddressRelativeOffset;
    const auto kPersistedLastCommitBlobBytesOffset = header_base_offset + kPersistedLastCommitBlobBytesRelativeOffset;
    if (persistent_state.size() < (kPersistedLastCommitBlobBytesOffset + sizeof(std::uint64_t)))
    {
        return false;
    }
    WriteLe64(persistent_state, kPersistedLastCommitXidOffset, persisted_last_commit_xid);
    WriteLe64(persistent_state, kPersistedLastCommitBlobAddressOffset, persisted_commit_blob_address);
    WriteLe64(persistent_state, kPersistedLastCommitBlobBytesOffset, persisted_commit_blob_bytes);
    return SavePersistentStateBytes(persistent_state_path, persistent_state);
}

bool CorruptPersistentStateMagic(const std::filesystem::path& persistent_state_path)
{
    std::vector<std::byte> persistent_state;
    if (!LoadPersistentStateBytes(persistent_state_path, persistent_state) ||
        persistent_state.empty())
    {
        return false;
    }

    persistent_state[0] = static_cast<std::byte>(0x00);
    return SavePersistentStateBytes(persistent_state_path, persistent_state);
}

bool CorruptPersistentStateChecksum(
    const std::filesystem::path& persistent_state_path,
    std::uint32_t mutated_checksum)
{
    std::vector<std::byte> persistent_state;
    if (!LoadPersistentStateBytes(persistent_state_path, persistent_state))
    {
        return false;
    }

    constexpr std::size_t kVersionOffset = 16;
    constexpr std::size_t kChecksumOffset = 20;
    constexpr std::size_t kHeaderBytes = 24;
    if (persistent_state.size() < kHeaderBytes)
    {
        return false;
    }

    const auto version = ReadLe32(persistent_state, kVersionOffset);
    if (version < 6)
    {
        return false;
    }

    WriteLe32(persistent_state, kChecksumOffset, mutated_checksum);

    std::ofstream output(persistent_state_path, std::ios::binary | std::ios::trunc);
    if (!output.good())
    {
        return false;
    }

    output.write(
        reinterpret_cast<const char*>(persistent_state.data()),
        static_cast<std::streamsize>(persistent_state.size()));
    return output.good();
}

bool CorruptPersistentStateFirstInodePathLength(
    const std::filesystem::path& persistent_state_path,
    std::uint32_t mutated_path_length)
{
    std::vector<std::byte> persistent_state;
    if (!LoadPersistentStateBytes(persistent_state_path, persistent_state))
    {
        return false;
    }

    constexpr std::array<char, 16> kExpectedMagic =
    {
        'A', 'P', 'F', 'S', 'R', 'W', 'S', 'T', 'A', 'T', 'E', '2', '\0', '\0', '\0', '\0'
    };
    if (persistent_state.size() < (kExpectedMagic.size() + 8 + 8 + 8 + 8 + 8))
    {
        return false;
    }
    for (std::size_t i = 0; i < kExpectedMagic.size(); ++i)
    {
        if (std::to_integer<unsigned char>(persistent_state[i]) != static_cast<unsigned char>(kExpectedMagic[i]))
        {
            return false;
        }
    }

    std::size_t cursor = kExpectedMagic.size();
    auto read_u32 = [&persistent_state, &cursor](std::uint32_t& value) -> bool
    {
        if (!TryReadLe32(persistent_state, cursor, value))
        {
            return false;
        }
        cursor += sizeof(std::uint32_t);
        return true;
    };
    auto read_u64 = [&persistent_state, &cursor](std::uint64_t& value) -> bool
    {
        if (!TryReadLe64(persistent_state, cursor, value))
        {
            return false;
        }
        cursor += sizeof(std::uint64_t);
        return true;
    };

    std::uint32_t version = 0;
    std::uint32_t persisted_state_checksum = 0;
    std::uint64_t persisted_checkpoint_xid = 0;
    std::uint64_t persisted_last_commit_xid = 0;
    std::uint64_t persisted_next_extent = 0;
    std::uint64_t persisted_next_object_id = 0;
    std::uint64_t persisted_last_commit_blob_address = 0;
    std::uint64_t persisted_last_commit_blob_bytes = 0;
    std::uint32_t object_count = 0;
    std::uint32_t allocation_count = 0;
    std::uint32_t inode_count = 0;
    std::uint32_t btree_record_count = 0;
    std::uint32_t free_extent_count = 0;
    if (!read_u32(version))
    {
        return false;
    }
    if (version >= 6 && !read_u32(persisted_state_checksum))
    {
        return false;
    }
    if (!read_u64(persisted_checkpoint_xid) ||
        !read_u64(persisted_last_commit_xid) ||
        !read_u64(persisted_next_extent) ||
        !read_u64(persisted_last_commit_blob_address) ||
        !read_u64(persisted_last_commit_blob_bytes) ||
        !read_u32(object_count) ||
        !read_u32(allocation_count))
    {
        return false;
    }
    if (version < 2 || version > 7 || !read_u32(inode_count))
    {
        return false;
    }
    if (version >= 3 && !read_u32(btree_record_count))
    {
        return false;
    }
    if (version >= 4 && !read_u32(free_extent_count))
    {
        return false;
    }
    if (version >= 5 && !read_u64(persisted_next_object_id))
    {
        return false;
    }
    (void)persisted_checkpoint_xid;
    (void)persisted_last_commit_xid;
    (void)persisted_next_extent;
    (void)persisted_next_object_id;
    (void)persisted_state_checksum;
    (void)persisted_last_commit_blob_address;
    (void)persisted_last_commit_blob_bytes;
    (void)btree_record_count;
    (void)free_extent_count;

    if (inode_count == 0)
    {
        return false;
    }

    constexpr std::size_t kObjectRecordBytes = (sizeof(std::uint64_t) * 4);
    constexpr std::size_t kAllocationRecordBytes = (sizeof(std::uint64_t) * 2);
    const auto kInodePathLengthOffset =
        ((version >= 7 ? 6u : 5u) * sizeof(std::uint64_t)) +
        sizeof(std::uint32_t) +
        sizeof(std::uint32_t);

    const auto object_section_bytes = static_cast<std::uint64_t>(object_count) * static_cast<std::uint64_t>(kObjectRecordBytes);
    const auto allocation_section_bytes = static_cast<std::uint64_t>(allocation_count) * static_cast<std::uint64_t>(kAllocationRecordBytes);
    if (object_section_bytes > (std::numeric_limits<std::size_t>::max() - cursor))
    {
        return false;
    }
    cursor += static_cast<std::size_t>(object_section_bytes);
    if (cursor > persistent_state.size())
    {
        return false;
    }

    if (allocation_section_bytes > (std::numeric_limits<std::size_t>::max() - cursor))
    {
        return false;
    }
    cursor += static_cast<std::size_t>(allocation_section_bytes);
    if (cursor > persistent_state.size())
    {
        return false;
    }

    if (kInodePathLengthOffset > (std::numeric_limits<std::size_t>::max() - cursor) ||
        (cursor + kInodePathLengthOffset + sizeof(std::uint32_t)) > persistent_state.size())
    {
        return false;
    }

    WriteLe32(persistent_state, cursor + kInodePathLengthOffset, mutated_path_length);
    return SavePersistentStateBytes(persistent_state_path, persistent_state);
}

bool CorruptBlocksWithMagicPrefix(
    const std::filesystem::path& image_path,
    const std::array<char, 12>& magic_prefix,
    std::size_t mutate_offset,
    std::byte mutate_value,
    std::size_t& out_corrupted_blocks)
{
    out_corrupted_blocks = 0;
    if (mutate_offset >= kBlockSize)
    {
        return false;
    }

    std::ifstream input(image_path, std::ios::binary);
    if (!input.good())
    {
        return false;
    }

    input.seekg(0, std::ios::end);
    if (!input.good())
    {
        return false;
    }
    const auto total_bytes = static_cast<std::size_t>(input.tellg());
    input.seekg(0, std::ios::beg);
    if (!input.good())
    {
        return false;
    }

    std::vector<std::byte> image(total_bytes);
    if (!image.empty())
    {
        input.read(reinterpret_cast<char*>(image.data()), static_cast<std::streamsize>(image.size()));
        if (static_cast<std::size_t>(input.gcount()) != image.size())
        {
            return false;
        }
    }

    const auto total_blocks = image.size() / kBlockSize;
    for (std::size_t block_index = 0; block_index < total_blocks; ++block_index)
    {
        const auto block_offset = block_index * kBlockSize;
        if ((block_offset + magic_prefix.size()) > image.size())
        {
            break;
        }

        bool magic_matches = true;
        for (std::size_t byte_index = 0; byte_index < magic_prefix.size(); ++byte_index)
        {
            if (std::to_integer<unsigned char>(image[block_offset + byte_index]) !=
                static_cast<unsigned char>(magic_prefix[byte_index]))
            {
                magic_matches = false;
                break;
            }
        }
        if (!magic_matches)
        {
            continue;
        }

        image[block_offset + mutate_offset] = mutate_value;
        ++out_corrupted_blocks;
    }

    if (out_corrupted_blocks == 0)
    {
        return false;
    }

    std::ofstream output(image_path, std::ios::binary | std::ios::trunc);
    if (!output.good())
    {
        return false;
    }
    if (!image.empty())
    {
        output.write(reinterpret_cast<const char*>(image.data()), static_cast<std::streamsize>(image.size()));
    }
    return output.good();
}

bool CorruptReplayCheckpointXidWindow(
    const std::filesystem::path& image_path,
    std::uint64_t mutated_source_xid,
    std::uint64_t mutated_target_xid,
    std::size_t& out_corrupted_blocks)
{
    out_corrupted_blocks = 0;
    constexpr std::array<char, 12> kReplayCheckpointMagic =
    {
        'A', 'P', 'F', 'S', 'R', 'W', 'R', 'P', 'L', '1', '\0', '\0'
    };
    constexpr std::size_t kReplayPayloadBytes = 24;

    std::ifstream input(image_path, std::ios::binary);
    if (!input.good())
    {
        return false;
    }

    input.seekg(0, std::ios::end);
    if (!input.good())
    {
        return false;
    }
    const auto total_bytes = static_cast<std::size_t>(input.tellg());
    input.seekg(0, std::ios::beg);
    if (!input.good())
    {
        return false;
    }

    std::vector<std::byte> image(total_bytes);
    if (!image.empty())
    {
        input.read(reinterpret_cast<char*>(image.data()), static_cast<std::streamsize>(image.size()));
        if (static_cast<std::size_t>(input.gcount()) != image.size())
        {
            return false;
        }
    }

    const auto total_blocks = image.size() / kBlockSize;
    for (std::size_t block_index = 0; block_index < total_blocks; ++block_index)
    {
        const auto block_offset = block_index * kBlockSize;
        if ((block_offset + kReplayCheckpointMagic.size()) > image.size())
        {
            break;
        }

        bool magic_matches = true;
        for (std::size_t byte_index = 0; byte_index < kReplayCheckpointMagic.size(); ++byte_index)
        {
            if (std::to_integer<unsigned char>(image[block_offset + byte_index]) !=
                static_cast<unsigned char>(kReplayCheckpointMagic[byte_index]))
            {
                magic_matches = false;
                break;
            }
        }
        if (!magic_matches)
        {
            continue;
        }

        const auto payload_bytes = static_cast<std::size_t>(ReadLe32(image, block_offset + 24));
        if (payload_bytes < kReplayPayloadBytes ||
            payload_bytes > (kBlockSize - kCheckpointHeaderBytes))
        {
            continue;
        }

        WriteLe64(image, block_offset + 12, mutated_target_xid);
        WriteLe64(image, block_offset + kCheckpointHeaderBytes + 0, mutated_source_xid);
        WriteLe32(image, block_offset + kCheckpointChecksumOffset, 0);

        auto hash = UpdateFnv1a(
            kCheckpointChecksumSeed,
            image.data() + static_cast<std::vector<std::byte>::difference_type>(block_offset),
            kCheckpointChecksumOffset);
        if (payload_bytes > 0)
        {
            hash = UpdateFnv1a(
                hash,
                image.data() + static_cast<std::vector<std::byte>::difference_type>(block_offset + kCheckpointHeaderBytes),
                payload_bytes);
        }
        WriteLe32(image, block_offset + kCheckpointChecksumOffset, hash);
        ++out_corrupted_blocks;
    }

    if (out_corrupted_blocks == 0)
    {
        return false;
    }

    std::ofstream output(image_path, std::ios::binary | std::ios::trunc);
    if (!output.good())
    {
        return false;
    }
    if (!image.empty())
    {
        output.write(reinterpret_cast<const char*>(image.data()), static_cast<std::streamsize>(image.size()));
    }
    return output.good();
}

bool CorruptReplayCheckpointPayloadBytes(
    const std::filesystem::path& image_path,
    std::uint32_t mutated_payload_bytes,
    std::size_t& out_corrupted_blocks)
{
    out_corrupted_blocks = 0;
    constexpr std::array<char, 12> kReplayCheckpointMagic =
    {
        'A', 'P', 'F', 'S', 'R', 'W', 'R', 'P', 'L', '1', '\0', '\0'
    };

    std::ifstream input(image_path, std::ios::binary);
    if (!input.good())
    {
        return false;
    }

    input.seekg(0, std::ios::end);
    if (!input.good())
    {
        return false;
    }
    const auto total_bytes = static_cast<std::size_t>(input.tellg());
    input.seekg(0, std::ios::beg);
    if (!input.good())
    {
        return false;
    }

    std::vector<std::byte> image(total_bytes);
    if (!image.empty())
    {
        input.read(reinterpret_cast<char*>(image.data()), static_cast<std::streamsize>(image.size()));
        if (static_cast<std::size_t>(input.gcount()) != image.size())
        {
            return false;
        }
    }

    const auto total_blocks = image.size() / kBlockSize;
    for (std::size_t block_index = 0; block_index < total_blocks; ++block_index)
    {
        const auto block_offset = block_index * kBlockSize;
        if ((block_offset + kReplayCheckpointMagic.size()) > image.size())
        {
            break;
        }

        bool magic_matches = true;
        for (std::size_t byte_index = 0; byte_index < kReplayCheckpointMagic.size(); ++byte_index)
        {
            if (std::to_integer<unsigned char>(image[block_offset + byte_index]) !=
                static_cast<unsigned char>(kReplayCheckpointMagic[byte_index]))
            {
                magic_matches = false;
                break;
            }
        }
        if (!magic_matches)
        {
            continue;
        }

        if (mutated_payload_bytes > (kBlockSize - kCheckpointHeaderBytes))
        {
            return false;
        }

        WriteLe32(image, block_offset + 24, mutated_payload_bytes);
        WriteLe32(image, block_offset + kCheckpointChecksumOffset, 0);

        auto hash = UpdateFnv1a(
            kCheckpointChecksumSeed,
            image.data() + static_cast<std::vector<std::byte>::difference_type>(block_offset),
            kCheckpointChecksumOffset);
        if (mutated_payload_bytes > 0)
        {
            hash = UpdateFnv1a(
                hash,
                image.data() + static_cast<std::vector<std::byte>::difference_type>(block_offset + kCheckpointHeaderBytes),
                mutated_payload_bytes);
        }
        WriteLe32(image, block_offset + kCheckpointChecksumOffset, hash);
        ++out_corrupted_blocks;
    }

    if (out_corrupted_blocks == 0)
    {
        return false;
    }

    std::ofstream output(image_path, std::ios::binary | std::ios::trunc);
    if (!output.good())
    {
        return false;
    }
    if (!image.empty())
    {
        output.write(reinterpret_cast<const char*>(image.data()), static_cast<std::streamsize>(image.size()));
    }
    return output.good();
}

bool CorruptReplayCheckpointTrailingBytes(
    const std::filesystem::path& image_path,
    std::byte mutate_value,
    std::size_t& out_corrupted_blocks)
{
    out_corrupted_blocks = 0;
    constexpr std::array<char, 12> kReplayCheckpointMagic =
    {
        'A', 'P', 'F', 'S', 'R', 'W', 'R', 'P', 'L', '1', '\0', '\0'
    };
    constexpr std::size_t kReplayPayloadBytes = 24;
    const auto trailing_offset = kCheckpointHeaderBytes + kReplayPayloadBytes;
    if constexpr (kCheckpointHeaderBytes + kReplayPayloadBytes >= kBlockSize)
    {
        return false;
    }

    std::ifstream input(image_path, std::ios::binary);
    if (!input.good())
    {
        return false;
    }

    input.seekg(0, std::ios::end);
    if (!input.good())
    {
        return false;
    }
    const auto total_bytes = static_cast<std::size_t>(input.tellg());
    input.seekg(0, std::ios::beg);
    if (!input.good())
    {
        return false;
    }

    std::vector<std::byte> image(total_bytes);
    if (!image.empty())
    {
        input.read(reinterpret_cast<char*>(image.data()), static_cast<std::streamsize>(image.size()));
        if (static_cast<std::size_t>(input.gcount()) != image.size())
        {
            return false;
        }
    }

    const auto total_blocks = image.size() / kBlockSize;
    for (std::size_t block_index = 0; block_index < total_blocks; ++block_index)
    {
        const auto block_offset = block_index * kBlockSize;
        if ((block_offset + kReplayCheckpointMagic.size()) > image.size())
        {
            break;
        }

        bool magic_matches = true;
        for (std::size_t byte_index = 0; byte_index < kReplayCheckpointMagic.size(); ++byte_index)
        {
            if (std::to_integer<unsigned char>(image[block_offset + byte_index]) !=
                static_cast<unsigned char>(kReplayCheckpointMagic[byte_index]))
            {
                magic_matches = false;
                break;
            }
        }
        if (!magic_matches)
        {
            continue;
        }

        image[block_offset + trailing_offset] = mutate_value;
        ++out_corrupted_blocks;
    }

    if (out_corrupted_blocks == 0)
    {
        return false;
    }

    std::ofstream output(image_path, std::ios::binary | std::ios::trunc);
    if (!output.good())
    {
        return false;
    }
    if (!image.empty())
    {
        output.write(reinterpret_cast<const char*>(image.data()), static_cast<std::streamsize>(image.size()));
    }
    return output.good();
}

bool CorruptReplayCheckpointChecksum(
    const std::filesystem::path& image_path,
    std::uint32_t mutated_checksum,
    std::size_t& out_corrupted_blocks)
{
    out_corrupted_blocks = 0;
    constexpr std::array<char, 12> kReplayCheckpointMagic =
    {
        'A', 'P', 'F', 'S', 'R', 'W', 'R', 'P', 'L', '1', '\0', '\0'
    };

    std::ifstream input(image_path, std::ios::binary);
    if (!input.good())
    {
        return false;
    }

    input.seekg(0, std::ios::end);
    if (!input.good())
    {
        return false;
    }
    const auto total_bytes = static_cast<std::size_t>(input.tellg());
    input.seekg(0, std::ios::beg);
    if (!input.good())
    {
        return false;
    }

    std::vector<std::byte> image(total_bytes);
    if (!image.empty())
    {
        input.read(reinterpret_cast<char*>(image.data()), static_cast<std::streamsize>(image.size()));
        if (static_cast<std::size_t>(input.gcount()) != image.size())
        {
            return false;
        }
    }

    const auto total_blocks = image.size() / kBlockSize;
    for (std::size_t block_index = 0; block_index < total_blocks; ++block_index)
    {
        const auto block_offset = block_index * kBlockSize;
        if ((block_offset + kReplayCheckpointMagic.size()) > image.size())
        {
            break;
        }

        bool magic_matches = true;
        for (std::size_t byte_index = 0; byte_index < kReplayCheckpointMagic.size(); ++byte_index)
        {
            if (std::to_integer<unsigned char>(image[block_offset + byte_index]) !=
                static_cast<unsigned char>(kReplayCheckpointMagic[byte_index]))
            {
                magic_matches = false;
                break;
            }
        }
        if (!magic_matches)
        {
            continue;
        }

        WriteLe32(image, block_offset + kCheckpointChecksumOffset, mutated_checksum);
        ++out_corrupted_blocks;
    }

    if (out_corrupted_blocks == 0)
    {
        return false;
    }

    std::ofstream output(image_path, std::ios::binary | std::ios::trunc);
    if (!output.good())
    {
        return false;
    }
    if (!image.empty())
    {
        output.write(reinterpret_cast<const char*>(image.data()), static_cast<std::streamsize>(image.size()));
    }
    return output.good();
}

bool CorruptReplayCheckpointCommitBlobAddress(
    const std::filesystem::path& image_path,
    std::uint64_t mutated_commit_blob_address,
    std::size_t& out_corrupted_blocks)
{
    out_corrupted_blocks = 0;
    if (mutated_commit_blob_address == 0)
    {
        return false;
    }

    constexpr std::array<char, 12> kReplayCheckpointMagic =
    {
        'A', 'P', 'F', 'S', 'R', 'W', 'R', 'P', 'L', '1', '\0', '\0'
    };

    std::ifstream input(image_path, std::ios::binary);
    if (!input.good())
    {
        return false;
    }

    input.seekg(0, std::ios::end);
    if (!input.good())
    {
        return false;
    }
    const auto total_bytes = static_cast<std::size_t>(input.tellg());
    input.seekg(0, std::ios::beg);
    if (!input.good())
    {
        return false;
    }

    std::vector<std::byte> image(total_bytes);
    if (!image.empty())
    {
        input.read(reinterpret_cast<char*>(image.data()), static_cast<std::streamsize>(image.size()));
        if (static_cast<std::size_t>(input.gcount()) != image.size())
        {
            return false;
        }
    }

    const auto total_blocks = image.size() / kBlockSize;
    for (std::size_t block_index = 0; block_index < total_blocks; ++block_index)
    {
        const auto block_offset = block_index * kBlockSize;
        if ((block_offset + kReplayCheckpointMagic.size()) > image.size())
        {
            break;
        }

        bool magic_matches = true;
        for (std::size_t byte_index = 0; byte_index < kReplayCheckpointMagic.size(); ++byte_index)
        {
            if (std::to_integer<unsigned char>(image[block_offset + byte_index]) !=
                static_cast<unsigned char>(kReplayCheckpointMagic[byte_index]))
            {
                magic_matches = false;
                break;
            }
        }
        if (!magic_matches)
        {
            continue;
        }

        const auto payload_bytes = static_cast<std::size_t>(ReadLe32(image, block_offset + 24));
        if (payload_bytes < 24 || payload_bytes > (kBlockSize - kCheckpointHeaderBytes))
        {
            continue;
        }

        WriteLe64(image, block_offset + kCheckpointHeaderBytes + 8, mutated_commit_blob_address);
        WriteLe32(image, block_offset + kCheckpointChecksumOffset, 0);

        auto hash = UpdateFnv1a(
            kCheckpointChecksumSeed,
            image.data() + static_cast<std::vector<std::byte>::difference_type>(block_offset),
            kCheckpointChecksumOffset);
        if (payload_bytes > 0)
        {
            hash = UpdateFnv1a(
                hash,
                image.data() + static_cast<std::vector<std::byte>::difference_type>(block_offset + kCheckpointHeaderBytes),
                payload_bytes);
        }
        WriteLe32(image, block_offset + kCheckpointChecksumOffset, hash);
        ++out_corrupted_blocks;
    }

    if (out_corrupted_blocks == 0)
    {
        return false;
    }

    std::ofstream output(image_path, std::ios::binary | std::ios::trunc);
    if (!output.good())
    {
        return false;
    }
    if (!image.empty())
    {
        output.write(reinterpret_cast<const char*>(image.data()), static_cast<std::streamsize>(image.size()));
    }
    return output.good();
}

bool CorruptHighestReplayCheckpointCommitBlobAddress(
    const std::filesystem::path& image_path,
    std::uint64_t mutated_commit_blob_address,
    std::size_t& out_corrupted_blocks)
{
    out_corrupted_blocks = 0;
    if (mutated_commit_blob_address == 0)
    {
        return false;
    }

    constexpr std::array<char, 12> kReplayCheckpointMagic =
    {
        'A', 'P', 'F', 'S', 'R', 'W', 'R', 'P', 'L', '1', '\0', '\0'
    };

    std::ifstream input(image_path, std::ios::binary);
    if (!input.good())
    {
        return false;
    }

    input.seekg(0, std::ios::end);
    if (!input.good())
    {
        return false;
    }
    const auto total_bytes = static_cast<std::size_t>(input.tellg());
    input.seekg(0, std::ios::beg);
    if (!input.good())
    {
        return false;
    }

    std::vector<std::byte> image(total_bytes);
    if (!image.empty())
    {
        input.read(reinterpret_cast<char*>(image.data()), static_cast<std::streamsize>(image.size()));
        if (static_cast<std::size_t>(input.gcount()) != image.size())
        {
            return false;
        }
    }

    std::optional<std::size_t> selected_block_offset;
    std::optional<std::size_t> selected_payload_bytes;
    std::uint64_t selected_target_xid = 0;

    const auto total_blocks = image.size() / kBlockSize;
    for (std::size_t block_index = 0; block_index < total_blocks; ++block_index)
    {
        const auto block_offset = block_index * kBlockSize;
        if ((block_offset + kReplayCheckpointMagic.size()) > image.size())
        {
            break;
        }

        bool magic_matches = true;
        for (std::size_t byte_index = 0; byte_index < kReplayCheckpointMagic.size(); ++byte_index)
        {
            if (std::to_integer<unsigned char>(image[block_offset + byte_index]) !=
                static_cast<unsigned char>(kReplayCheckpointMagic[byte_index]))
            {
                magic_matches = false;
                break;
            }
        }
        if (!magic_matches)
        {
            continue;
        }

        const auto payload_bytes = static_cast<std::size_t>(ReadLe32(image, block_offset + 24));
        if (payload_bytes < 24 || payload_bytes > (kBlockSize - kCheckpointHeaderBytes))
        {
            continue;
        }

        const auto candidate_target_xid = ReadLe64(image, block_offset + 12);
        const auto candidate_commit_blob_address = ReadLe64(image, block_offset + kCheckpointHeaderBytes + 8);
        const auto candidate_commit_blob_bytes = ReadLe64(image, block_offset + kCheckpointHeaderBytes + 16);
        if (candidate_target_xid == 0 ||
            candidate_commit_blob_address == 0 ||
            candidate_commit_blob_bytes == 0)
        {
            continue;
        }

        if (!selected_block_offset.has_value() ||
            candidate_target_xid > selected_target_xid)
        {
            selected_target_xid = candidate_target_xid;
            selected_block_offset = block_offset;
            selected_payload_bytes = payload_bytes;
        }
    }

    if (!selected_block_offset.has_value() || !selected_payload_bytes.has_value())
    {
        return false;
    }

    const auto block_offset = selected_block_offset.value();
    const auto payload_bytes = selected_payload_bytes.value();

    WriteLe64(image, block_offset + kCheckpointHeaderBytes + 8, mutated_commit_blob_address);
    WriteLe32(image, block_offset + kCheckpointChecksumOffset, 0);

    auto hash = UpdateFnv1a(
        kCheckpointChecksumSeed,
        image.data() + static_cast<std::vector<std::byte>::difference_type>(block_offset),
        kCheckpointChecksumOffset);
    if (payload_bytes > 0)
    {
        hash = UpdateFnv1a(
            hash,
            image.data() + static_cast<std::vector<std::byte>::difference_type>(block_offset + kCheckpointHeaderBytes),
            payload_bytes);
    }
    WriteLe32(image, block_offset + kCheckpointChecksumOffset, hash);
    out_corrupted_blocks = 1;

    std::ofstream output(image_path, std::ios::binary | std::ios::trunc);
    if (!output.good())
    {
        return false;
    }
    if (!image.empty())
    {
        output.write(reinterpret_cast<const char*>(image.data()), static_cast<std::streamsize>(image.size()));
    }
    return output.good();
}

bool CorruptPendingReplayCheckpointCommitBlobAddresses(
    const std::filesystem::path& image_path,
    std::uint64_t pending_source_xid,
    std::uint64_t pending_target_xid,
    std::uint64_t applied_target_xid,
    std::uint64_t mutated_commit_blob_address,
    std::size_t& out_corrupted_blocks,
    std::size_t& out_applied_window_blocks)
{
    out_corrupted_blocks = 0;
    out_applied_window_blocks = 0;
    if (mutated_commit_blob_address == 0)
    {
        return false;
    }

    constexpr std::array<char, 12> kReplayCheckpointMagic =
    {
        'A', 'P', 'F', 'S', 'R', 'W', 'R', 'P', 'L', '1', '\0', '\0'
    };

    std::ifstream input(image_path, std::ios::binary);
    if (!input.good())
    {
        return false;
    }

    input.seekg(0, std::ios::end);
    if (!input.good())
    {
        return false;
    }
    const auto total_bytes = static_cast<std::size_t>(input.tellg());
    input.seekg(0, std::ios::beg);
    if (!input.good())
    {
        return false;
    }

    std::vector<std::byte> image(total_bytes);
    if (!image.empty())
    {
        input.read(reinterpret_cast<char*>(image.data()), static_cast<std::streamsize>(image.size()));
        if (static_cast<std::size_t>(input.gcount()) != image.size())
        {
            return false;
        }
    }

    const auto total_blocks = image.size() / kBlockSize;
    for (std::size_t block_index = 0; block_index < total_blocks; ++block_index)
    {
        const auto block_offset = block_index * kBlockSize;
        if ((block_offset + kReplayCheckpointMagic.size()) > image.size())
        {
            break;
        }

        bool magic_matches = true;
        for (std::size_t byte_index = 0; byte_index < kReplayCheckpointMagic.size(); ++byte_index)
        {
            if (std::to_integer<unsigned char>(image[block_offset + byte_index]) !=
                static_cast<unsigned char>(kReplayCheckpointMagic[byte_index]))
            {
                magic_matches = false;
                break;
            }
        }
        if (!magic_matches)
        {
            continue;
        }

        const auto payload_bytes = static_cast<std::size_t>(ReadLe32(image, block_offset + 24));
        if (payload_bytes < 24 || payload_bytes > (kBlockSize - kCheckpointHeaderBytes))
        {
            continue;
        }

        const auto candidate_target_xid = ReadLe64(image, block_offset + 12);
        const auto candidate_source_xid = ReadLe64(image, block_offset + kCheckpointHeaderBytes + 0);
        if (candidate_target_xid == applied_target_xid)
        {
            ++out_applied_window_blocks;
        }

        if (candidate_source_xid != pending_source_xid ||
            candidate_target_xid != pending_target_xid)
        {
            continue;
        }

        WriteLe64(image, block_offset + kCheckpointHeaderBytes + 8, mutated_commit_blob_address);
        WriteLe32(image, block_offset + kCheckpointChecksumOffset, 0);

        auto hash = UpdateFnv1a(
            kCheckpointChecksumSeed,
            image.data() + static_cast<std::vector<std::byte>::difference_type>(block_offset),
            kCheckpointChecksumOffset);
        if (payload_bytes > 0)
        {
            hash = UpdateFnv1a(
                hash,
                image.data() + static_cast<std::vector<std::byte>::difference_type>(block_offset + kCheckpointHeaderBytes),
                payload_bytes);
        }
        WriteLe32(image, block_offset + kCheckpointChecksumOffset, hash);
        ++out_corrupted_blocks;
    }

    if (out_corrupted_blocks == 0 || out_applied_window_blocks == 0)
    {
        return false;
    }

    std::ofstream output(image_path, std::ios::binary | std::ios::trunc);
    if (!output.good())
    {
        return false;
    }
    if (!image.empty())
    {
        output.write(reinterpret_cast<const char*>(image.data()), static_cast<std::streamsize>(image.size()));
    }
    return output.good();
}

bool PromotePendingReplayCommitBlobMagicToCanonicalV3(
    const std::filesystem::path& image_path,
    std::uint64_t pending_source_xid,
    std::uint64_t pending_target_xid,
    std::size_t& out_promoted_blocks)
{
    out_promoted_blocks = 0;

    constexpr std::array<char, 12> kReplayCheckpointMagic =
    {
        'A', 'P', 'F', 'S', 'R', 'W', 'R', 'P', 'L', '1', '\0', '\0'
    };
    constexpr std::array<char, 13> kCommitBlobMagicCanonicalV3 =
    {
        'A', 'P', 'F', 'S', 'R', 'W', 'C', 'A', 'N', 'O', 'N', '3', '\0'
    };
    constexpr std::array<char, 13> kCommitBlobMagicScaffoldV3 =
    {
        'A', 'P', 'F', 'S', 'R', 'W', 'S', 'C', 'A', 'F', 'F', '3', '\0'
    };

    std::ifstream input(image_path, std::ios::binary);
    if (!input.good())
    {
        return false;
    }

    input.seekg(0, std::ios::end);
    if (!input.good())
    {
        return false;
    }
    const auto total_bytes = static_cast<std::size_t>(input.tellg());
    input.seekg(0, std::ios::beg);
    if (!input.good())
    {
        return false;
    }

    std::vector<std::byte> image(total_bytes);
    if (!image.empty())
    {
        input.read(reinterpret_cast<char*>(image.data()), static_cast<std::streamsize>(image.size()));
        if (static_cast<std::size_t>(input.gcount()) != image.size())
        {
            return false;
        }
    }

    bool image_changed = false;
    const auto total_blocks = image.size() / kBlockSize;
    for (std::size_t block_index = 0; block_index < total_blocks; ++block_index)
    {
        const auto block_offset = block_index * kBlockSize;
        if ((block_offset + kReplayCheckpointMagic.size()) > image.size())
        {
            break;
        }

        bool magic_matches = true;
        for (std::size_t byte_index = 0; byte_index < kReplayCheckpointMagic.size(); ++byte_index)
        {
            if (std::to_integer<unsigned char>(image[block_offset + byte_index]) !=
                static_cast<unsigned char>(kReplayCheckpointMagic[byte_index]))
            {
                magic_matches = false;
                break;
            }
        }
        if (!magic_matches)
        {
            continue;
        }

        const auto payload_bytes = static_cast<std::size_t>(ReadLe32(image, block_offset + 24));
        if (payload_bytes < 24 || payload_bytes > (kBlockSize - kCheckpointHeaderBytes))
        {
            continue;
        }

        const auto candidate_target_xid = ReadLe64(image, block_offset + 12);
        const auto candidate_source_xid = ReadLe64(image, block_offset + kCheckpointHeaderBytes + 0);
        if (candidate_source_xid != pending_source_xid ||
            candidate_target_xid != pending_target_xid)
        {
            continue;
        }

        const auto commit_blob_address = ReadLe64(image, block_offset + kCheckpointHeaderBytes + 8);
        const auto commit_blob_bytes = ReadLe64(image, block_offset + kCheckpointHeaderBytes + 16);
        if (commit_blob_address == 0 ||
            commit_blob_bytes < kCommitBlobMagicCanonicalV3.size() ||
            commit_blob_address > static_cast<std::uint64_t>(image.size()) ||
            commit_blob_bytes > static_cast<std::uint64_t>(image.size()) ||
            commit_blob_address > (static_cast<std::uint64_t>(image.size()) - commit_blob_bytes))
        {
            continue;
        }

        const auto commit_blob_offset = static_cast<std::size_t>(commit_blob_address);
        bool scaffold_magic = true;
        bool canonical_magic = true;
        for (std::size_t byte_index = 0; byte_index < kCommitBlobMagicCanonicalV3.size(); ++byte_index)
        {
            const auto byte_value = std::to_integer<unsigned char>(image[commit_blob_offset + byte_index]);
            if (byte_value != static_cast<unsigned char>(kCommitBlobMagicScaffoldV3[byte_index]))
            {
                scaffold_magic = false;
            }
            if (byte_value != static_cast<unsigned char>(kCommitBlobMagicCanonicalV3[byte_index]))
            {
                canonical_magic = false;
            }
        }
        if (!scaffold_magic && !canonical_magic)
        {
            continue;
        }
        if (canonical_magic)
        {
            ++out_promoted_blocks;
            continue;
        }

        for (std::size_t byte_index = 0; byte_index < kCommitBlobMagicCanonicalV3.size(); ++byte_index)
        {
            image[commit_blob_offset + byte_index] = std::byte{static_cast<unsigned char>(kCommitBlobMagicCanonicalV3[byte_index])};
        }
        image_changed = true;
        ++out_promoted_blocks;
    }

    if (out_promoted_blocks == 0)
    {
        return false;
    }

    if (!image_changed)
    {
        return true;
    }

    std::ofstream output(image_path, std::ios::binary | std::ios::trunc);
    if (!output.good())
    {
        return false;
    }
    if (!image.empty())
    {
        output.write(reinterpret_cast<const char*>(image.data()), static_cast<std::streamsize>(image.size()));
    }
    return output.good();
}

bool CorruptReplayCheckpointCommitBlobBytes(
    const std::filesystem::path& image_path,
    std::uint64_t mutated_commit_blob_bytes,
    std::size_t& out_corrupted_blocks)
{
    out_corrupted_blocks = 0;
    if (mutated_commit_blob_bytes == 0)
    {
        return false;
    }

    constexpr std::array<char, 12> kReplayCheckpointMagic =
    {
        'A', 'P', 'F', 'S', 'R', 'W', 'R', 'P', 'L', '1', '\0', '\0'
    };

    std::ifstream input(image_path, std::ios::binary);
    if (!input.good())
    {
        return false;
    }

    input.seekg(0, std::ios::end);
    if (!input.good())
    {
        return false;
    }
    const auto total_bytes = static_cast<std::size_t>(input.tellg());
    input.seekg(0, std::ios::beg);
    if (!input.good())
    {
        return false;
    }

    std::vector<std::byte> image(total_bytes);
    if (!image.empty())
    {
        input.read(reinterpret_cast<char*>(image.data()), static_cast<std::streamsize>(image.size()));
        if (static_cast<std::size_t>(input.gcount()) != image.size())
        {
            return false;
        }
    }

    const auto total_blocks = image.size() / kBlockSize;
    for (std::size_t block_index = 0; block_index < total_blocks; ++block_index)
    {
        const auto block_offset = block_index * kBlockSize;
        if ((block_offset + kReplayCheckpointMagic.size()) > image.size())
        {
            break;
        }

        bool magic_matches = true;
        for (std::size_t byte_index = 0; byte_index < kReplayCheckpointMagic.size(); ++byte_index)
        {
            if (std::to_integer<unsigned char>(image[block_offset + byte_index]) !=
                static_cast<unsigned char>(kReplayCheckpointMagic[byte_index]))
            {
                magic_matches = false;
                break;
            }
        }
        if (!magic_matches)
        {
            continue;
        }

        const auto payload_bytes = static_cast<std::size_t>(ReadLe32(image, block_offset + 24));
        if (payload_bytes < 24 || payload_bytes > (kBlockSize - kCheckpointHeaderBytes))
        {
            continue;
        }

        WriteLe64(image, block_offset + kCheckpointHeaderBytes + 16, mutated_commit_blob_bytes);
        WriteLe32(image, block_offset + kCheckpointChecksumOffset, 0);

        auto hash = UpdateFnv1a(
            kCheckpointChecksumSeed,
            image.data() + static_cast<std::vector<std::byte>::difference_type>(block_offset),
            kCheckpointChecksumOffset);
        if (payload_bytes > 0)
        {
            hash = UpdateFnv1a(
                hash,
                image.data() + static_cast<std::vector<std::byte>::difference_type>(block_offset + kCheckpointHeaderBytes),
                payload_bytes);
        }
        WriteLe32(image, block_offset + kCheckpointChecksumOffset, hash);
        ++out_corrupted_blocks;
    }

    if (out_corrupted_blocks == 0)
    {
        return false;
    }

    std::ofstream output(image_path, std::ios::binary | std::ios::trunc);
    if (!output.good())
    {
        return false;
    }
    if (!image.empty())
    {
        output.write(reinterpret_cast<const char*>(image.data()), static_cast<std::streamsize>(image.size()));
    }
    return output.good();
}

bool CorruptHighestReplayCheckpointReferencedCommitBlobDuplicateObjectMapIdWithValidChecksum(
    const std::filesystem::path& image_path,
    std::size_t& out_corrupted_blocks)
{
    out_corrupted_blocks = 0;
    constexpr std::array<char, 12> kReplayCheckpointMagic =
    {
        'A', 'P', 'F', 'S', 'R', 'W', 'R', 'P', 'L', '1', '\0', '\0'
    };
    constexpr std::array<unsigned char, 13> kCommitBlobMagicV3 =
    {
        'A', 'P', 'F', 'S', 'R', 'W', 'S', 'C', 'A', 'F', 'F', '3', '\0'
    };
    constexpr std::size_t kCommitBlobBaseHeaderBytes = 13 + 8 + 8 + 4 + 4 + 4 + 4 + 4;
    constexpr std::size_t kCommitBlobChecksumOffset = kCommitBlobBaseHeaderBytes;
    constexpr std::size_t kCommitBlobPayloadOffset = kCommitBlobChecksumOffset + 4;

    std::ifstream input(image_path, std::ios::binary);
    if (!input.good())
    {
        return false;
    }

    input.seekg(0, std::ios::end);
    if (!input.good())
    {
        return false;
    }
    const auto total_bytes = static_cast<std::size_t>(input.tellg());
    input.seekg(0, std::ios::beg);
    if (!input.good())
    {
        return false;
    }

    std::vector<std::byte> image(total_bytes);
    if (!image.empty())
    {
        input.read(reinterpret_cast<char*>(image.data()), static_cast<std::streamsize>(image.size()));
        if (static_cast<std::size_t>(input.gcount()) != image.size())
        {
            return false;
        }
    }

    struct ReplayReference
    {
        std::uint64_t target_xid = 0;
        std::uint64_t commit_blob_address = 0;
        std::uint64_t commit_blob_bytes = 0;
    };
    std::optional<ReplayReference> selected_reference;

    const auto total_blocks = image.size() / kBlockSize;
    for (std::size_t block_index = 0; block_index < total_blocks; ++block_index)
    {
        const auto block_offset = block_index * kBlockSize;
        if ((block_offset + kReplayCheckpointMagic.size()) > image.size())
        {
            break;
        }

        bool magic_matches = true;
        for (std::size_t byte_index = 0; byte_index < kReplayCheckpointMagic.size(); ++byte_index)
        {
            if (std::to_integer<unsigned char>(image[block_offset + byte_index]) !=
                static_cast<unsigned char>(kReplayCheckpointMagic[byte_index]))
            {
                magic_matches = false;
                break;
            }
        }
        if (!magic_matches)
        {
            continue;
        }

        const auto payload_bytes = static_cast<std::size_t>(ReadLe32(image, block_offset + 24));
        if (payload_bytes < 24 || payload_bytes > (kBlockSize - kCheckpointHeaderBytes))
        {
            continue;
        }

        const auto target_xid = ReadLe64(image, block_offset + 12);
        const auto commit_blob_address = ReadLe64(image, block_offset + kCheckpointHeaderBytes + 8);
        const auto commit_blob_bytes = ReadLe64(image, block_offset + kCheckpointHeaderBytes + 16);
        if (target_xid == 0 || commit_blob_address == 0 || commit_blob_bytes == 0)
        {
            continue;
        }
        if (commit_blob_address > static_cast<std::uint64_t>(image.size()) ||
            commit_blob_bytes > static_cast<std::uint64_t>(image.size()) ||
            commit_blob_address > (std::numeric_limits<std::uint64_t>::max() - commit_blob_bytes) ||
            (commit_blob_address + commit_blob_bytes) > static_cast<std::uint64_t>(image.size()))
        {
            continue;
        }

        if (!selected_reference.has_value() || target_xid > selected_reference->target_xid)
        {
            selected_reference = ReplayReference
            {
                target_xid,
                commit_blob_address,
                commit_blob_bytes,
            };
        }
    }

    if (!selected_reference.has_value())
    {
        return false;
    }

    const auto commit_blob_offset = static_cast<std::size_t>(selected_reference->commit_blob_address);
    const auto commit_blob_bytes = static_cast<std::size_t>(selected_reference->commit_blob_bytes);
    if (commit_blob_bytes < kCommitBlobPayloadOffset ||
        commit_blob_offset > image.size() ||
        commit_blob_bytes > (image.size() - commit_blob_offset))
    {
        return false;
    }

    bool magic_matches = true;
    for (std::size_t index = 0; index < kCommitBlobMagicV3.size(); ++index)
    {
        if (std::to_integer<unsigned char>(image[commit_blob_offset + index]) != kCommitBlobMagicV3[index])
        {
            magic_matches = false;
            break;
        }
    }
    if (!magic_matches)
    {
        return false;
    }

    const auto object_map_updates = ReadLe32(image, commit_blob_offset + 33);
    const auto spaceman_allocations = ReadLe32(image, commit_blob_offset + 37);
    const auto spaceman_deallocations = ReadLe32(image, commit_blob_offset + 41);
    const auto btree_records = ReadLe32(image, commit_blob_offset + 45);
    if (object_map_updates < 2)
    {
        return false;
    }

    const auto commit_blob_end = commit_blob_offset + commit_blob_bytes;
    std::size_t cursor = commit_blob_offset + kCommitBlobPayloadOffset;
    const auto advance = [&](std::uint64_t bytes) -> bool
    {
        if (bytes > (std::numeric_limits<std::size_t>::max() - cursor))
        {
            return false;
        }
        const auto next = cursor + static_cast<std::size_t>(bytes);
        if (next > commit_blob_end)
        {
            return false;
        }
        cursor = next;
        return true;
    };

    const auto object_map_bytes = static_cast<std::uint64_t>(object_map_updates) * 32ull;
    const auto object_map_start = cursor;
    if (!advance(object_map_bytes) ||
        !advance(static_cast<std::uint64_t>(spaceman_allocations) * 16ull) ||
        !advance(static_cast<std::uint64_t>(spaceman_deallocations) * 16ull))
    {
        return false;
    }

    for (std::uint32_t index = 0; index < btree_records; ++index)
    {
        if (cursor > commit_blob_end || 16 > (commit_blob_end - cursor))
        {
            return false;
        }
        const auto key_size = ReadLe32(image, cursor + 8);
        const auto value_size = ReadLe32(image, cursor + 12);
        cursor += 16;
        if (!advance(static_cast<std::uint64_t>(key_size) + static_cast<std::uint64_t>(value_size)))
        {
            return false;
        }
    }

    const auto payload_end = cursor;
    if (payload_end > commit_blob_end ||
        object_map_start > payload_end ||
        (object_map_start + 64) > payload_end)
    {
        return false;
    }

    const auto first_object_id = ReadLe64(image, object_map_start);
    if (first_object_id == 0)
    {
        return false;
    }

    WriteLe64(image, object_map_start + 32, first_object_id);

    const auto payload_bytes = payload_end - (commit_blob_offset + kCommitBlobPayloadOffset);
    const auto payload_checksum = UpdateFnv1a(
        kCheckpointChecksumSeed,
        image.data() + static_cast<std::vector<std::byte>::difference_type>(commit_blob_offset + kCommitBlobPayloadOffset),
        payload_bytes);
    WriteLe32(image, commit_blob_offset + kCommitBlobChecksumOffset, payload_checksum);

    std::ofstream output(image_path, std::ios::binary | std::ios::trunc);
    if (!output.good())
    {
        return false;
    }
    if (!image.empty())
    {
        output.write(reinterpret_cast<const char*>(image.data()), static_cast<std::streamsize>(image.size()));
    }
    if (!output.good())
    {
        return false;
    }

    out_corrupted_blocks = 1;
    return true;
}

bool CorruptFirstMagicOccurrence(
    const std::filesystem::path& image_path,
    const std::vector<unsigned char>& magic,
    std::size_t mutate_offset,
    std::byte mutate_value,
    std::size_t& out_magic_offset)
{
    out_magic_offset = 0;
    if (magic.empty())
    {
        return false;
    }

    std::ifstream input(image_path, std::ios::binary);
    if (!input.good())
    {
        return false;
    }

    input.seekg(0, std::ios::end);
    if (!input.good())
    {
        return false;
    }
    const auto total_bytes = static_cast<std::size_t>(input.tellg());
    input.seekg(0, std::ios::beg);
    if (!input.good())
    {
        return false;
    }

    std::vector<std::byte> image(total_bytes);
    if (!image.empty())
    {
        input.read(reinterpret_cast<char*>(image.data()), static_cast<std::streamsize>(image.size()));
        if (static_cast<std::size_t>(input.gcount()) != image.size())
        {
            return false;
        }
    }

    if (image.size() < magic.size())
    {
        return false;
    }

    for (std::size_t offset = 0; offset <= (image.size() - magic.size()); ++offset)
    {
        bool magic_matches = true;
        for (std::size_t index = 0; index < magic.size(); ++index)
        {
            if (std::to_integer<unsigned char>(image[offset + index]) != magic[index])
            {
                magic_matches = false;
                break;
            }
        }
        if (!magic_matches)
        {
            continue;
        }

        const auto mutate_target = offset + mutate_offset;
        if (mutate_target >= image.size())
        {
            return false;
        }

        image[mutate_target] = mutate_value;
        out_magic_offset = offset;

        std::ofstream output(image_path, std::ios::binary | std::ios::trunc);
        if (!output.good())
        {
            return false;
        }
        if (!image.empty())
        {
            output.write(reinterpret_cast<const char*>(image.data()), static_cast<std::streamsize>(image.size()));
        }
        return output.good();
    }

    return false;
}

bool CorruptCommitBlobObjectMapLogicalSizeWithValidChecksum(
    const std::filesystem::path& image_path,
    std::uint64_t logical_size,
    std::size_t& out_magic_offset)
{
    out_magic_offset = 0;
    constexpr std::array<unsigned char, 13> kCommitBlobMagic =
    {
        'A', 'P', 'F', 'S', 'R', 'W', 'S', 'C', 'A', 'F', 'F', '3', '\0'
    };
    constexpr std::size_t kCommitBlobBaseHeaderBytes = 13 + 8 + 8 + 4 + 4 + 4 + 4 + 4;
    constexpr std::size_t kCommitBlobChecksumOffset = kCommitBlobBaseHeaderBytes;
    constexpr std::size_t kCommitBlobPayloadOffset = kCommitBlobChecksumOffset + 4;

    std::ifstream input(image_path, std::ios::binary);
    if (!input.good())
    {
        return false;
    }

    input.seekg(0, std::ios::end);
    if (!input.good())
    {
        return false;
    }
    const auto total_bytes = static_cast<std::size_t>(input.tellg());
    input.seekg(0, std::ios::beg);
    if (!input.good())
    {
        return false;
    }

    std::vector<std::byte> image(total_bytes);
    if (!image.empty())
    {
        input.read(reinterpret_cast<char*>(image.data()), static_cast<std::streamsize>(image.size()));
        if (static_cast<std::size_t>(input.gcount()) != image.size())
        {
            return false;
        }
    }

    if (image.size() < (kCommitBlobPayloadOffset + 32))
    {
        return false;
    }

    for (std::size_t offset = 0; offset <= (image.size() - kCommitBlobMagic.size()); ++offset)
    {
        bool magic_matches = true;
        for (std::size_t index = 0; index < kCommitBlobMagic.size(); ++index)
        {
            if (std::to_integer<unsigned char>(image[offset + index]) != kCommitBlobMagic[index])
            {
                magic_matches = false;
                break;
            }
        }
        if (!magic_matches)
        {
            continue;
        }

        const auto object_map_updates = ReadLe32(image, offset + 33);
        const auto spaceman_allocations = ReadLe32(image, offset + 37);
        const auto spaceman_deallocations = ReadLe32(image, offset + 41);
        const auto btree_records = ReadLe32(image, offset + 45);
        if (object_map_updates == 0)
        {
            continue;
        }

        std::size_t cursor = offset + kCommitBlobPayloadOffset;
        const auto advance = [&](std::uint64_t bytes) -> bool
        {
            if (bytes > (std::numeric_limits<std::size_t>::max() - cursor))
            {
                return false;
            }
            const auto next = cursor + static_cast<std::size_t>(bytes);
            if (next > image.size())
            {
                return false;
            }
            cursor = next;
            return true;
        };

        if (!advance(static_cast<std::uint64_t>(object_map_updates) * 32ull) ||
            !advance(static_cast<std::uint64_t>(spaceman_allocations) * 16ull) ||
            !advance(static_cast<std::uint64_t>(spaceman_deallocations) * 16ull))
        {
            continue;
        }
        for (std::uint32_t index = 0; index < btree_records; ++index)
        {
            if (cursor > image.size() || 16 > (image.size() - cursor))
            {
                return false;
            }
            const auto key_size = ReadLe32(image, cursor + 8);
            const auto value_size = ReadLe32(image, cursor + 12);
            cursor += 16;
            const auto payload_size = static_cast<std::uint64_t>(key_size) + static_cast<std::uint64_t>(value_size);
            if (!advance(payload_size))
            {
                return false;
            }
        }

        const auto first_object_map_update = offset + kCommitBlobPayloadOffset;
        const auto logical_size_offset = first_object_map_update + 16;
        if ((logical_size_offset + sizeof(std::uint64_t)) > image.size())
        {
            return false;
        }
        WriteLe64(image, logical_size_offset, logical_size);

        const auto payload_bytes = cursor - (offset + kCommitBlobPayloadOffset);
        const auto payload_checksum = UpdateFnv1a(
            kCheckpointChecksumSeed,
            image.data() + static_cast<std::vector<std::byte>::difference_type>(offset + kCommitBlobPayloadOffset),
            payload_bytes);
        WriteLe32(image, offset + kCommitBlobChecksumOffset, payload_checksum);

        std::ofstream output(image_path, std::ios::binary | std::ios::trunc);
        if (!output.good())
        {
            return false;
        }
        if (!image.empty())
        {
            output.write(reinterpret_cast<const char*>(image.data()), static_cast<std::streamsize>(image.size()));
        }
        if (!output.good())
        {
            return false;
        }

        out_magic_offset = offset;
        return true;
    }

    return false;
}

bool CorruptCommitBlobDuplicateFirstObjectMapUpdateWithValidChecksum(
    const std::filesystem::path& image_path,
    std::size_t& out_magic_offset)
{
    out_magic_offset = 0;
    constexpr std::array<unsigned char, 13> kCommitBlobMagic =
    {
        'A', 'P', 'F', 'S', 'R', 'W', 'S', 'C', 'A', 'F', 'F', '3', '\0'
    };
    constexpr std::size_t kCommitBlobBaseHeaderBytes = 13 + 8 + 8 + 4 + 4 + 4 + 4 + 4;
    constexpr std::size_t kCommitBlobChecksumOffset = kCommitBlobBaseHeaderBytes;
    constexpr std::size_t kCommitBlobPayloadOffset = kCommitBlobChecksumOffset + 4;
    constexpr std::size_t kObjectMapCountOffsetFromMagic = 33;
    constexpr std::size_t kObjectMapRecordBytes = 32;

    std::ifstream input(image_path, std::ios::binary);
    if (!input.good())
    {
        return false;
    }

    input.seekg(0, std::ios::end);
    if (!input.good())
    {
        return false;
    }
    const auto total_bytes = static_cast<std::size_t>(input.tellg());
    input.seekg(0, std::ios::beg);
    if (!input.good())
    {
        return false;
    }

    std::vector<std::byte> image(total_bytes);
    if (!image.empty())
    {
        input.read(reinterpret_cast<char*>(image.data()), static_cast<std::streamsize>(image.size()));
        if (static_cast<std::size_t>(input.gcount()) != image.size())
        {
            return false;
        }
    }

    if (image.size() < (kCommitBlobPayloadOffset + kObjectMapRecordBytes))
    {
        return false;
    }

    for (std::size_t offset = 0; offset <= (image.size() - kCommitBlobMagic.size()); ++offset)
    {
        bool magic_matches = true;
        for (std::size_t index = 0; index < kCommitBlobMagic.size(); ++index)
        {
            if (std::to_integer<unsigned char>(image[offset + index]) != kCommitBlobMagic[index])
            {
                magic_matches = false;
                break;
            }
        }
        if (!magic_matches)
        {
            continue;
        }

        const auto object_map_updates = ReadLe32(image, offset + kObjectMapCountOffsetFromMagic);
        const auto spaceman_allocations = ReadLe32(image, offset + 37);
        const auto spaceman_deallocations = ReadLe32(image, offset + 41);
        const auto btree_records = ReadLe32(image, offset + 45);
        if (object_map_updates == 0)
        {
            continue;
        }
        if (object_map_updates == std::numeric_limits<std::uint32_t>::max())
        {
            return false;
        }

        std::size_t cursor = offset + kCommitBlobPayloadOffset;
        const auto advance = [&](std::uint64_t bytes) -> bool
        {
            if (bytes > (std::numeric_limits<std::size_t>::max() - cursor))
            {
                return false;
            }
            const auto next = cursor + static_cast<std::size_t>(bytes);
            if (next > image.size())
            {
                return false;
            }
            cursor = next;
            return true;
        };

        const auto object_map_start = cursor;
        const auto object_map_bytes = static_cast<std::uint64_t>(object_map_updates) * kObjectMapRecordBytes;
        if (!advance(object_map_bytes))
        {
            continue;
        }
        const auto object_map_end = cursor;
        if ((object_map_start + kObjectMapRecordBytes) > object_map_end ||
            object_map_end > image.size())
        {
            continue;
        }

        if (!advance(static_cast<std::uint64_t>(spaceman_allocations) * 16ull) ||
            !advance(static_cast<std::uint64_t>(spaceman_deallocations) * 16ull))
        {
            continue;
        }

        for (std::uint32_t index = 0; index < btree_records; ++index)
        {
            if (cursor > image.size() || 16 > (image.size() - cursor))
            {
                return false;
            }
            const auto key_size = ReadLe32(image, cursor + 8);
            const auto value_size = ReadLe32(image, cursor + 12);
            cursor += 16;
            const auto payload_size = static_cast<std::uint64_t>(key_size) + static_cast<std::uint64_t>(value_size);
            if (!advance(payload_size))
            {
                return false;
            }
        }

        const auto payload_end = cursor;
        if (payload_end < (offset + kCommitBlobPayloadOffset) || payload_end > image.size())
        {
            return false;
        }

        std::array<std::byte, kObjectMapRecordBytes> duplicated_record{};
        std::copy_n(
            image.begin() + static_cast<std::vector<std::byte>::difference_type>(object_map_start),
            duplicated_record.size(),
            duplicated_record.begin());

        image.insert(
            image.begin() + static_cast<std::vector<std::byte>::difference_type>(object_map_start + kObjectMapRecordBytes),
            duplicated_record.begin(),
            duplicated_record.end());

        WriteLe32(
            image,
            offset + kObjectMapCountOffsetFromMagic,
            object_map_updates + 1);

        const auto new_payload_end = payload_end + kObjectMapRecordBytes;
        const auto payload_bytes = new_payload_end - (offset + kCommitBlobPayloadOffset);
        const auto payload_checksum = UpdateFnv1a(
            kCheckpointChecksumSeed,
            image.data() + static_cast<std::vector<std::byte>::difference_type>(offset + kCommitBlobPayloadOffset),
            payload_bytes);
        WriteLe32(image, offset + kCommitBlobChecksumOffset, payload_checksum);

        std::ofstream output(image_path, std::ios::binary | std::ios::trunc);
        if (!output.good())
        {
            return false;
        }
        if (!image.empty())
        {
            output.write(reinterpret_cast<const char*>(image.data()), static_cast<std::streamsize>(image.size()));
        }
        if (!output.good())
        {
            return false;
        }

        out_magic_offset = offset;
        return true;
    }

    return false;
}

bool CorruptCommitBlobDirectoryTombstoneChildWithValidChecksum(
    const std::filesystem::path& image_path,
    std::size_t& out_magic_offset)
{
    out_magic_offset = 0;
    constexpr std::array<unsigned char, 13> kCommitBlobMagic =
    {
        'A', 'P', 'F', 'S', 'R', 'W', 'S', 'C', 'A', 'F', 'F', '3', '\0'
    };
    constexpr std::size_t kCommitBlobBaseHeaderBytes = 13 + 8 + 8 + 4 + 4 + 4 + 4 + 4;
    constexpr std::size_t kCommitBlobChecksumOffset = kCommitBlobBaseHeaderBytes;
    constexpr std::size_t kCommitBlobPayloadOffset = kCommitBlobChecksumOffset + 4;
    constexpr std::uint32_t kDirectoryRecordKind = 2;

    std::ifstream input(image_path, std::ios::binary);
    if (!input.good())
    {
        return false;
    }

    input.seekg(0, std::ios::end);
    if (!input.good())
    {
        return false;
    }
    const auto total_bytes = static_cast<std::size_t>(input.tellg());
    input.seekg(0, std::ios::beg);
    if (!input.good())
    {
        return false;
    }

    std::vector<std::byte> image(total_bytes);
    if (!image.empty())
    {
        input.read(reinterpret_cast<char*>(image.data()), static_cast<std::streamsize>(image.size()));
        if (static_cast<std::size_t>(input.gcount()) != image.size())
        {
            return false;
        }
    }

    if (image.size() < (kCommitBlobPayloadOffset + 32))
    {
        return false;
    }

    for (std::size_t offset = 0; offset <= (image.size() - kCommitBlobMagic.size()); ++offset)
    {
        bool magic_matches = true;
        for (std::size_t index = 0; index < kCommitBlobMagic.size(); ++index)
        {
            if (std::to_integer<unsigned char>(image[offset + index]) != kCommitBlobMagic[index])
            {
                magic_matches = false;
                break;
            }
        }
        if (!magic_matches)
        {
            continue;
        }

        const auto object_map_updates = ReadLe32(image, offset + 33);
        const auto spaceman_allocations = ReadLe32(image, offset + 37);
        const auto spaceman_deallocations = ReadLe32(image, offset + 41);
        const auto btree_records = ReadLe32(image, offset + 45);
        if (btree_records == 0)
        {
            continue;
        }

        std::size_t cursor = offset + kCommitBlobPayloadOffset;
        const auto advance = [&](std::uint64_t bytes) -> bool
        {
            if (bytes > (std::numeric_limits<std::size_t>::max() - cursor))
            {
                return false;
            }
            const auto next = cursor + static_cast<std::size_t>(bytes);
            if (next > image.size())
            {
                return false;
            }
            cursor = next;
            return true;
        };

        if (!advance(static_cast<std::uint64_t>(object_map_updates) * 32ull) ||
            !advance(static_cast<std::uint64_t>(spaceman_allocations) * 16ull) ||
            !advance(static_cast<std::uint64_t>(spaceman_deallocations) * 16ull))
        {
            continue;
        }

        bool mutated = false;
        for (std::uint32_t index = 0; index < btree_records; ++index)
        {
            if (cursor > image.size() || 16 > (image.size() - cursor))
            {
                return false;
            }

            const auto kind = ReadLe32(image, cursor + 0);
            const auto tombstone = ReadLe32(image, cursor + 4);
            const auto key_size = ReadLe32(image, cursor + 8);
            const auto value_size = ReadLe32(image, cursor + 12);
            cursor += 16;

            const auto payload_size = static_cast<std::uint64_t>(key_size) + static_cast<std::uint64_t>(value_size);
            if (payload_size > (std::numeric_limits<std::size_t>::max() - cursor) ||
                (cursor + static_cast<std::size_t>(payload_size)) > image.size())
            {
                return false;
            }

            const auto value_offset = cursor + static_cast<std::size_t>(key_size);
            if (!mutated &&
                kind == kDirectoryRecordKind &&
                tombstone != 0 &&
                value_size == (8 + 8 + 1))
            {
                if ((value_offset + 17) > image.size())
                {
                    return false;
                }

                auto child_object_id = ReadLe64(image, value_offset + 8);
                if (child_object_id == 0)
                {
                    child_object_id = 1;
                }
                const auto mutated_child_id =
                    child_object_id == std::numeric_limits<std::uint64_t>::max()
                        ? (child_object_id - 1)
                        : (child_object_id + 1);
                if (mutated_child_id == 0 || mutated_child_id == child_object_id)
                {
                    return false;
                }

                WriteLe64(image, value_offset + 8, mutated_child_id);
                mutated = true;
            }

            cursor += static_cast<std::size_t>(payload_size);
        }

        if (!mutated)
        {
            continue;
        }

        const auto payload_bytes = cursor - (offset + kCommitBlobPayloadOffset);
        const auto payload_checksum = UpdateFnv1a(
            kCheckpointChecksumSeed,
            image.data() + static_cast<std::vector<std::byte>::difference_type>(offset + kCommitBlobPayloadOffset),
            payload_bytes);
        WriteLe32(image, offset + kCommitBlobChecksumOffset, payload_checksum);

        std::ofstream output(image_path, std::ios::binary | std::ios::trunc);
        if (!output.good())
        {
            return false;
        }
        if (!image.empty())
        {
            output.write(reinterpret_cast<const char*>(image.data()), static_cast<std::streamsize>(image.size()));
        }
        if (!output.good())
        {
            return false;
        }

        out_magic_offset = offset;
        return true;
    }

    return false;
}

bool CorruptCommitBlobHeaderField(
    const std::filesystem::path& image_path,
    std::size_t field_offset_from_magic,
    std::uint32_t field_value,
    std::size_t& out_magic_offset)
{
    out_magic_offset = 0;
    constexpr std::array<unsigned char, 13> kCommitBlobMagic =
    {
        'A', 'P', 'F', 'S', 'R', 'W', 'S', 'C', 'A', 'F', 'F', '3', '\0'
    };

    std::ifstream input(image_path, std::ios::binary);
    if (!input.good())
    {
        return false;
    }

    input.seekg(0, std::ios::end);
    if (!input.good())
    {
        return false;
    }
    const auto total_bytes = static_cast<std::size_t>(input.tellg());
    input.seekg(0, std::ios::beg);
    if (!input.good())
    {
        return false;
    }

    std::vector<std::byte> image(total_bytes);
    if (!image.empty())
    {
        input.read(reinterpret_cast<char*>(image.data()), static_cast<std::streamsize>(image.size()));
        if (static_cast<std::size_t>(input.gcount()) != image.size())
        {
            return false;
        }
    }

    if (image.size() < (kCommitBlobMagic.size() + field_offset_from_magic + sizeof(std::uint32_t)))
    {
        return false;
    }

    for (std::size_t offset = 0; offset <= (image.size() - kCommitBlobMagic.size()); ++offset)
    {
        bool magic_matches = true;
        for (std::size_t index = 0; index < kCommitBlobMagic.size(); ++index)
        {
            if (std::to_integer<unsigned char>(image[offset + index]) != kCommitBlobMagic[index])
            {
                magic_matches = false;
                break;
            }
        }
        if (!magic_matches)
        {
            continue;
        }

        const auto field_offset = offset + field_offset_from_magic;
        if ((field_offset + sizeof(std::uint32_t)) > image.size())
        {
            return false;
        }

        WriteLe32(image, field_offset, field_value);

        std::ofstream output(image_path, std::ios::binary | std::ios::trunc);
        if (!output.good())
        {
            return false;
        }
        if (!image.empty())
        {
            output.write(reinterpret_cast<const char*>(image.data()), static_cast<std::streamsize>(image.size()));
        }
        if (!output.good())
        {
            return false;
        }

        out_magic_offset = offset;
        return true;
    }

    return false;
}

bool CorruptCommitBlobMutationCount(
    const std::filesystem::path& image_path,
    std::uint32_t mutation_count,
    std::size_t& out_magic_offset)
{
    constexpr std::size_t kMutationCountOffsetFromMagic = 29;
    return CorruptCommitBlobHeaderField(
        image_path,
        kMutationCountOffsetFromMagic,
        mutation_count,
        out_magic_offset);
}

bool CorruptCommitBlobBtreeRecordCount(
    const std::filesystem::path& image_path,
    std::uint32_t btree_record_count,
    std::size_t& out_magic_offset)
{
    constexpr std::size_t kBtreeRecordCountOffsetFromMagic = 45;
    return CorruptCommitBlobHeaderField(
        image_path,
        kBtreeRecordCountOffsetFromMagic,
        btree_record_count,
        out_magic_offset);
}

bool CorruptCommitBlobDropLastBtreeRecordWithValidChecksum(
    const std::filesystem::path& image_path,
    std::size_t& out_magic_offset)
{
    out_magic_offset = 0;
    constexpr std::array<unsigned char, 13> kCommitBlobMagic =
    {
        'A', 'P', 'F', 'S', 'R', 'W', 'S', 'C', 'A', 'F', 'F', '3', '\0'
    };
    constexpr std::size_t kCommitBlobBaseHeaderBytes = 13 + 8 + 8 + 4 + 4 + 4 + 4 + 4;
    constexpr std::size_t kCommitBlobChecksumOffset = kCommitBlobBaseHeaderBytes;
    constexpr std::size_t kCommitBlobPayloadOffset = kCommitBlobChecksumOffset + 4;

    std::ifstream input(image_path, std::ios::binary);
    if (!input.good())
    {
        return false;
    }

    input.seekg(0, std::ios::end);
    if (!input.good())
    {
        return false;
    }
    const auto total_bytes = static_cast<std::size_t>(input.tellg());
    input.seekg(0, std::ios::beg);
    if (!input.good())
    {
        return false;
    }

    std::vector<std::byte> image(total_bytes);
    if (!image.empty())
    {
        input.read(reinterpret_cast<char*>(image.data()), static_cast<std::streamsize>(image.size()));
        if (static_cast<std::size_t>(input.gcount()) != image.size())
        {
            return false;
        }
    }

    if (image.size() < (kCommitBlobPayloadOffset + 64))
    {
        return false;
    }

    for (std::size_t offset = 0; offset <= (image.size() - kCommitBlobMagic.size()); ++offset)
    {
        bool magic_matches = true;
        for (std::size_t index = 0; index < kCommitBlobMagic.size(); ++index)
        {
            if (std::to_integer<unsigned char>(image[offset + index]) != kCommitBlobMagic[index])
            {
                magic_matches = false;
                break;
            }
        }
        if (!magic_matches)
        {
            continue;
        }

        const auto object_map_updates = ReadLe32(image, offset + 33);
        const auto spaceman_allocations = ReadLe32(image, offset + 37);
        const auto spaceman_deallocations = ReadLe32(image, offset + 41);
        const auto btree_records = ReadLe32(image, offset + 45);
        if (btree_records == 0)
        {
            continue;
        }

        std::size_t cursor = offset + kCommitBlobPayloadOffset;
        const auto advance = [&](std::uint64_t bytes) -> bool
        {
            if (bytes > (std::numeric_limits<std::size_t>::max() - cursor))
            {
                return false;
            }
            const auto next = cursor + static_cast<std::size_t>(bytes);
            if (next > image.size())
            {
                return false;
            }
            cursor = next;
            return true;
        };

        if (!advance(static_cast<std::uint64_t>(object_map_updates) * 32ull) ||
            !advance(static_cast<std::uint64_t>(spaceman_allocations) * 16ull) ||
            !advance(static_cast<std::uint64_t>(spaceman_deallocations) * 16ull))
        {
            continue;
        }

        const auto btree_records_start = cursor;
        std::vector<std::size_t> btree_record_end_offsets;
        btree_record_end_offsets.reserve(btree_records);
        for (std::uint32_t index = 0; index < btree_records; ++index)
        {
            if (cursor > image.size() || 16 > (image.size() - cursor))
            {
                return false;
            }

            const auto key_size = ReadLe32(image, cursor + 8);
            const auto value_size = ReadLe32(image, cursor + 12);
            cursor += 16;

            const auto payload_size = static_cast<std::uint64_t>(key_size) + static_cast<std::uint64_t>(value_size);
            if (payload_size > (std::numeric_limits<std::size_t>::max() - cursor) ||
                (cursor + static_cast<std::size_t>(payload_size)) > image.size())
            {
                return false;
            }

            cursor += static_cast<std::size_t>(payload_size);
            btree_record_end_offsets.push_back(cursor);
        }

        if (btree_record_end_offsets.empty())
        {
            continue;
        }

        const auto updated_btree_records = btree_records - 1;
        WriteLe32(image, offset + 45, updated_btree_records);
        const auto new_payload_end = updated_btree_records == 0
            ? btree_records_start
            : btree_record_end_offsets[updated_btree_records - 1];
        if (new_payload_end < (offset + kCommitBlobPayloadOffset) || new_payload_end > image.size())
        {
            return false;
        }

        const auto payload_bytes = new_payload_end - (offset + kCommitBlobPayloadOffset);
        const auto payload_checksum = UpdateFnv1a(
            kCheckpointChecksumSeed,
            image.data() + static_cast<std::vector<std::byte>::difference_type>(offset + kCommitBlobPayloadOffset),
            payload_bytes);
        WriteLe32(image, offset + kCommitBlobChecksumOffset, payload_checksum);

        std::ofstream output(image_path, std::ios::binary | std::ios::trunc);
        if (!output.good())
        {
            return false;
        }
        if (!image.empty())
        {
            output.write(reinterpret_cast<const char*>(image.data()), static_cast<std::streamsize>(image.size()));
        }
        if (!output.good())
        {
            return false;
        }

        out_magic_offset = offset;
        return true;
    }

    return false;
}

bool CorruptCommitBlobPaddingByte(
    const std::filesystem::path& image_path,
    std::byte mutate_value,
    std::size_t& out_magic_offset)
{
    out_magic_offset = 0;
    constexpr std::array<unsigned char, 13> kCommitBlobMagic =
    {
        'A', 'P', 'F', 'S', 'R', 'W', 'S', 'C', 'A', 'F', 'F', '3', '\0'
    };
    constexpr std::size_t kCommitBlobBaseHeaderBytes = 13 + 8 + 8 + 4 + 4 + 4 + 4 + 4;
    constexpr std::size_t kCommitBlobPayloadOffset = kCommitBlobBaseHeaderBytes + 4;

    std::ifstream input(image_path, std::ios::binary);
    if (!input.good())
    {
        return false;
    }

    input.seekg(0, std::ios::end);
    if (!input.good())
    {
        return false;
    }
    const auto total_bytes = static_cast<std::size_t>(input.tellg());
    input.seekg(0, std::ios::beg);
    if (!input.good())
    {
        return false;
    }

    std::vector<std::byte> image(total_bytes);
    if (!image.empty())
    {
        input.read(reinterpret_cast<char*>(image.data()), static_cast<std::streamsize>(image.size()));
        if (static_cast<std::size_t>(input.gcount()) != image.size())
        {
            return false;
        }
    }

    if (image.size() < (kCommitBlobPayloadOffset + 64))
    {
        return false;
    }

    for (std::size_t offset = 0; offset <= (image.size() - kCommitBlobMagic.size()); ++offset)
    {
        bool magic_matches = true;
        for (std::size_t index = 0; index < kCommitBlobMagic.size(); ++index)
        {
            if (std::to_integer<unsigned char>(image[offset + index]) != kCommitBlobMagic[index])
            {
                magic_matches = false;
                break;
            }
        }
        if (!magic_matches)
        {
            continue;
        }

        const auto object_map_updates = ReadLe32(image, offset + 33);
        const auto spaceman_allocations = ReadLe32(image, offset + 37);
        const auto spaceman_deallocations = ReadLe32(image, offset + 41);
        const auto btree_records = ReadLe32(image, offset + 45);

        std::size_t cursor = offset + kCommitBlobPayloadOffset;
        const auto advance = [&](std::uint64_t bytes) -> bool
        {
            if (bytes > (std::numeric_limits<std::size_t>::max() - cursor))
            {
                return false;
            }
            const auto next = cursor + static_cast<std::size_t>(bytes);
            if (next > image.size())
            {
                return false;
            }
            cursor = next;
            return true;
        };

        if (!advance(static_cast<std::uint64_t>(object_map_updates) * 32ull) ||
            !advance(static_cast<std::uint64_t>(spaceman_allocations) * 16ull) ||
            !advance(static_cast<std::uint64_t>(spaceman_deallocations) * 16ull))
        {
            continue;
        }

        for (std::uint32_t index = 0; index < btree_records; ++index)
        {
            if (cursor > image.size() || 16 > (image.size() - cursor))
            {
                return false;
            }
            const auto key_size = ReadLe32(image, cursor + 8);
            const auto value_size = ReadLe32(image, cursor + 12);
            cursor += 16;
            const auto payload_size = static_cast<std::uint64_t>(key_size) + static_cast<std::uint64_t>(value_size);
            if (!advance(payload_size))
            {
                return false;
            }
        }

        if (cursor >= image.size())
        {
            continue;
        }

        image[cursor] = mutate_value;

        std::ofstream output(image_path, std::ios::binary | std::ios::trunc);
        if (!output.good())
        {
            return false;
        }
        if (!image.empty())
        {
            output.write(reinterpret_cast<const char*>(image.data()), static_cast<std::streamsize>(image.size()));
        }
        if (!output.good())
        {
            return false;
        }

        out_magic_offset = offset;
        return true;
    }

    return false;
}

bool CorruptCommitBlobTombstoneKeyPrefixWithValidChecksum(
    const std::filesystem::path& image_path,
    std::size_t& out_magic_offset)
{
    out_magic_offset = 0;
    constexpr std::array<unsigned char, 13> kCommitBlobMagic =
    {
        'A', 'P', 'F', 'S', 'R', 'W', 'S', 'C', 'A', 'F', 'F', '3', '\0'
    };
    constexpr std::size_t kCommitBlobBaseHeaderBytes = 13 + 8 + 8 + 4 + 4 + 4 + 4 + 4;
    constexpr std::size_t kCommitBlobChecksumOffset = kCommitBlobBaseHeaderBytes;
    constexpr std::size_t kCommitBlobPayloadOffset = kCommitBlobChecksumOffset + 4;

    std::ifstream input(image_path, std::ios::binary);
    if (!input.good())
    {
        return false;
    }

    input.seekg(0, std::ios::end);
    if (!input.good())
    {
        return false;
    }
    const auto total_bytes = static_cast<std::size_t>(input.tellg());
    input.seekg(0, std::ios::beg);
    if (!input.good())
    {
        return false;
    }

    std::vector<std::byte> image(total_bytes);
    if (!image.empty())
    {
        input.read(reinterpret_cast<char*>(image.data()), static_cast<std::streamsize>(image.size()));
        if (static_cast<std::size_t>(input.gcount()) != image.size())
        {
            return false;
        }
    }

    if (image.size() < (kCommitBlobPayloadOffset + 64))
    {
        return false;
    }

    for (std::size_t offset = 0; offset <= (image.size() - kCommitBlobMagic.size()); ++offset)
    {
        bool magic_matches = true;
        for (std::size_t index = 0; index < kCommitBlobMagic.size(); ++index)
        {
            if (std::to_integer<unsigned char>(image[offset + index]) != kCommitBlobMagic[index])
            {
                magic_matches = false;
                break;
            }
        }
        if (!magic_matches)
        {
            continue;
        }

        const auto object_map_updates = ReadLe32(image, offset + 33);
        const auto spaceman_allocations = ReadLe32(image, offset + 37);
        const auto spaceman_deallocations = ReadLe32(image, offset + 41);
        const auto btree_records = ReadLe32(image, offset + 45);
        if (btree_records == 0)
        {
            continue;
        }

        std::size_t cursor = offset + kCommitBlobPayloadOffset;
        const auto advance = [&](std::uint64_t bytes) -> bool
        {
            if (bytes > (std::numeric_limits<std::size_t>::max() - cursor))
            {
                return false;
            }
            const auto next = cursor + static_cast<std::size_t>(bytes);
            if (next > image.size())
            {
                return false;
            }
            cursor = next;
            return true;
        };

        if (!advance(static_cast<std::uint64_t>(object_map_updates) * 32ull) ||
            !advance(static_cast<std::uint64_t>(spaceman_allocations) * 16ull) ||
            !advance(static_cast<std::uint64_t>(spaceman_deallocations) * 16ull))
        {
            continue;
        }

        bool mutated = false;
        for (std::uint32_t index = 0; index < btree_records; ++index)
        {
            if (cursor > image.size() || 16 > (image.size() - cursor))
            {
                return false;
            }
            const auto kind = ReadLe32(image, cursor + 0);
            const auto tombstone = ReadLe32(image, cursor + 4);
            const auto key_size = ReadLe32(image, cursor + 8);
            const auto value_size = ReadLe32(image, cursor + 12);
            cursor += 16;

            const auto payload_size = static_cast<std::uint64_t>(key_size) + static_cast<std::uint64_t>(value_size);
            if (payload_size > (std::numeric_limits<std::size_t>::max() - cursor) ||
                (cursor + static_cast<std::size_t>(payload_size)) > image.size())
            {
                return false;
            }

            if (!mutated &&
                tombstone != 0 &&
                key_size > 0 &&
                kind >= 1 &&
                kind <= 3)
            {
                const auto key_offset = cursor;
                const auto current_prefix = std::to_integer<unsigned char>(image[key_offset]);
                unsigned char mutated_prefix = current_prefix;
                if (current_prefix == static_cast<unsigned char>(kind))
                {
                    mutated_prefix = static_cast<unsigned char>((kind % 3u) + 1u);
                }
                if (mutated_prefix != current_prefix)
                {
                    image[key_offset] = static_cast<std::byte>(mutated_prefix);
                    mutated = true;
                }
            }

            cursor += static_cast<std::size_t>(payload_size);
        }

        if (!mutated)
        {
            continue;
        }

        const auto payload_bytes = cursor - (offset + kCommitBlobPayloadOffset);
        const auto payload_checksum = UpdateFnv1a(
            kCheckpointChecksumSeed,
            image.data() + static_cast<std::vector<std::byte>::difference_type>(offset + kCommitBlobPayloadOffset),
            payload_bytes);
        WriteLe32(image, offset + kCommitBlobChecksumOffset, payload_checksum);

        std::ofstream output(image_path, std::ios::binary | std::ios::trunc);
        if (!output.good())
        {
            return false;
        }
        if (!image.empty())
        {
            output.write(reinterpret_cast<const char*>(image.data()), static_cast<std::streamsize>(image.size()));
        }
        if (!output.good())
        {
            return false;
        }

        out_magic_offset = offset;
        return true;
    }

    return false;
}

bool CorruptCommitBlobDuplicateFirstDeallocationWithValidChecksum(
    const std::filesystem::path& image_path,
    std::size_t& out_magic_offset)
{
    out_magic_offset = 0;
    constexpr std::array<unsigned char, 13> kCommitBlobMagic =
    {
        'A', 'P', 'F', 'S', 'R', 'W', 'S', 'C', 'A', 'F', 'F', '3', '\0'
    };
    constexpr std::size_t kCommitBlobBaseHeaderBytes = 13 + 8 + 8 + 4 + 4 + 4 + 4 + 4;
    constexpr std::size_t kCommitBlobChecksumOffset = kCommitBlobBaseHeaderBytes;
    constexpr std::size_t kCommitBlobPayloadOffset = kCommitBlobChecksumOffset + 4;
    constexpr std::size_t kSpacemanDeallocationCountOffsetFromMagic = 41;
    constexpr std::size_t kExtentRecordBytes = 16;

    std::ifstream input(image_path, std::ios::binary);
    if (!input.good())
    {
        return false;
    }

    input.seekg(0, std::ios::end);
    if (!input.good())
    {
        return false;
    }
    const auto total_bytes = static_cast<std::size_t>(input.tellg());
    input.seekg(0, std::ios::beg);
    if (!input.good())
    {
        return false;
    }

    std::vector<std::byte> image(total_bytes);
    if (!image.empty())
    {
        input.read(reinterpret_cast<char*>(image.data()), static_cast<std::streamsize>(image.size()));
        if (static_cast<std::size_t>(input.gcount()) != image.size())
        {
            return false;
        }
    }

    if (image.size() < (kCommitBlobPayloadOffset + 64))
    {
        return false;
    }

    for (std::size_t offset = 0; offset <= (image.size() - kCommitBlobMagic.size()); ++offset)
    {
        bool magic_matches = true;
        for (std::size_t index = 0; index < kCommitBlobMagic.size(); ++index)
        {
            if (std::to_integer<unsigned char>(image[offset + index]) != kCommitBlobMagic[index])
            {
                magic_matches = false;
                break;
            }
        }
        if (!magic_matches)
        {
            continue;
        }

        const auto object_map_updates = ReadLe32(image, offset + 33);
        const auto spaceman_allocations = ReadLe32(image, offset + 37);
        const auto spaceman_deallocations = ReadLe32(image, offset + kSpacemanDeallocationCountOffsetFromMagic);
        const auto btree_records = ReadLe32(image, offset + 45);
        if (spaceman_deallocations == 0)
        {
            continue;
        }
        if (spaceman_deallocations == std::numeric_limits<std::uint32_t>::max())
        {
            return false;
        }

        std::size_t cursor = offset + kCommitBlobPayloadOffset;
        const auto advance = [&](std::uint64_t bytes) -> bool
        {
            if (bytes > (std::numeric_limits<std::size_t>::max() - cursor))
            {
                return false;
            }
            const auto next = cursor + static_cast<std::size_t>(bytes);
            if (next > image.size())
            {
                return false;
            }
            cursor = next;
            return true;
        };

        if (!advance(static_cast<std::uint64_t>(object_map_updates) * 32ull) ||
            !advance(static_cast<std::uint64_t>(spaceman_allocations) * 16ull))
        {
            continue;
        }

        const auto deallocation_start = cursor;
        const auto deallocation_bytes = static_cast<std::uint64_t>(spaceman_deallocations) * kExtentRecordBytes;
        if (!advance(deallocation_bytes))
        {
            continue;
        }
        const auto deallocation_end = cursor;
        if ((deallocation_start + kExtentRecordBytes) > deallocation_end ||
            deallocation_end > image.size())
        {
            continue;
        }

        for (std::uint32_t index = 0; index < btree_records; ++index)
        {
            if (cursor > image.size() || 16 > (image.size() - cursor))
            {
                return false;
            }
            const auto key_size = ReadLe32(image, cursor + 8);
            const auto value_size = ReadLe32(image, cursor + 12);
            cursor += 16;
            const auto payload_size = static_cast<std::uint64_t>(key_size) + static_cast<std::uint64_t>(value_size);
            if (!advance(payload_size))
            {
                return false;
            }
        }

        const auto payload_end = cursor;
        if (payload_end < (offset + kCommitBlobPayloadOffset) || payload_end > image.size())
        {
            return false;
        }

        std::array<std::byte, kExtentRecordBytes> duplicated_record{};
        std::copy_n(
            image.begin() + static_cast<std::vector<std::byte>::difference_type>(deallocation_start),
            duplicated_record.size(),
            duplicated_record.begin());

        image.insert(
            image.begin() + static_cast<std::vector<std::byte>::difference_type>(deallocation_start + kExtentRecordBytes),
            duplicated_record.begin(),
            duplicated_record.end());

        WriteLe32(
            image,
            offset + kSpacemanDeallocationCountOffsetFromMagic,
            spaceman_deallocations + 1);

        const auto new_payload_end = payload_end + kExtentRecordBytes;
        const auto payload_bytes = new_payload_end - (offset + kCommitBlobPayloadOffset);
        const auto payload_checksum = UpdateFnv1a(
            kCheckpointChecksumSeed,
            image.data() + static_cast<std::vector<std::byte>::difference_type>(offset + kCommitBlobPayloadOffset),
            payload_bytes);
        WriteLe32(image, offset + kCommitBlobChecksumOffset, payload_checksum);

        std::ofstream output(image_path, std::ios::binary | std::ios::trunc);
        if (!output.good())
        {
            return false;
        }
        if (!image.empty())
        {
            output.write(reinterpret_cast<const char*>(image.data()), static_cast<std::streamsize>(image.size()));
        }
        if (!output.good())
        {
            return false;
        }

        out_magic_offset = offset;
        return true;
    }

    return false;
}

bool CorruptCommitBlobDuplicateFirstAllocationWithValidChecksum(
    const std::filesystem::path& image_path,
    std::size_t& out_magic_offset)
{
    out_magic_offset = 0;
    constexpr std::array<unsigned char, 13> kCommitBlobMagic =
    {
        'A', 'P', 'F', 'S', 'R', 'W', 'S', 'C', 'A', 'F', 'F', '3', '\0'
    };
    constexpr std::size_t kCommitBlobBaseHeaderBytes = 13 + 8 + 8 + 4 + 4 + 4 + 4 + 4;
    constexpr std::size_t kCommitBlobChecksumOffset = kCommitBlobBaseHeaderBytes;
    constexpr std::size_t kCommitBlobPayloadOffset = kCommitBlobChecksumOffset + 4;
    constexpr std::size_t kSpacemanAllocationCountOffsetFromMagic = 37;
    constexpr std::size_t kExtentRecordBytes = 16;

    std::ifstream input(image_path, std::ios::binary);
    if (!input.good())
    {
        return false;
    }

    input.seekg(0, std::ios::end);
    if (!input.good())
    {
        return false;
    }
    const auto total_bytes = static_cast<std::size_t>(input.tellg());
    input.seekg(0, std::ios::beg);
    if (!input.good())
    {
        return false;
    }

    std::vector<std::byte> image(total_bytes);
    if (!image.empty())
    {
        input.read(reinterpret_cast<char*>(image.data()), static_cast<std::streamsize>(image.size()));
        if (static_cast<std::size_t>(input.gcount()) != image.size())
        {
            return false;
        }
    }

    if (image.size() < (kCommitBlobPayloadOffset + 64))
    {
        return false;
    }

    for (std::size_t offset = 0; offset <= (image.size() - kCommitBlobMagic.size()); ++offset)
    {
        bool magic_matches = true;
        for (std::size_t index = 0; index < kCommitBlobMagic.size(); ++index)
        {
            if (std::to_integer<unsigned char>(image[offset + index]) != kCommitBlobMagic[index])
            {
                magic_matches = false;
                break;
            }
        }
        if (!magic_matches)
        {
            continue;
        }

        const auto object_map_updates = ReadLe32(image, offset + 33);
        const auto spaceman_allocations = ReadLe32(image, offset + kSpacemanAllocationCountOffsetFromMagic);
        const auto spaceman_deallocations = ReadLe32(image, offset + 41);
        const auto btree_records = ReadLe32(image, offset + 45);
        if (spaceman_allocations == 0)
        {
            continue;
        }
        if (spaceman_allocations == std::numeric_limits<std::uint32_t>::max())
        {
            return false;
        }

        std::size_t cursor = offset + kCommitBlobPayloadOffset;
        const auto advance = [&](std::uint64_t bytes) -> bool
        {
            if (bytes > (std::numeric_limits<std::size_t>::max() - cursor))
            {
                return false;
            }
            const auto next = cursor + static_cast<std::size_t>(bytes);
            if (next > image.size())
            {
                return false;
            }
            cursor = next;
            return true;
        };

        if (!advance(static_cast<std::uint64_t>(object_map_updates) * 32ull))
        {
            continue;
        }

        const auto allocation_start = cursor;
        const auto allocation_bytes = static_cast<std::uint64_t>(spaceman_allocations) * kExtentRecordBytes;
        if (!advance(allocation_bytes))
        {
            continue;
        }
        const auto allocation_end = cursor;
        if ((allocation_start + kExtentRecordBytes) > allocation_end ||
            allocation_end > image.size())
        {
            continue;
        }

        if (!advance(static_cast<std::uint64_t>(spaceman_deallocations) * 16ull))
        {
            continue;
        }

        for (std::uint32_t index = 0; index < btree_records; ++index)
        {
            if (cursor > image.size() || 16 > (image.size() - cursor))
            {
                return false;
            }
            const auto key_size = ReadLe32(image, cursor + 8);
            const auto value_size = ReadLe32(image, cursor + 12);
            cursor += 16;
            const auto payload_size = static_cast<std::uint64_t>(key_size) + static_cast<std::uint64_t>(value_size);
            if (!advance(payload_size))
            {
                return false;
            }
        }

        const auto payload_end = cursor;
        if (payload_end < (offset + kCommitBlobPayloadOffset) || payload_end > image.size())
        {
            return false;
        }

        std::array<std::byte, kExtentRecordBytes> duplicated_record{};
        std::copy_n(
            image.begin() + static_cast<std::vector<std::byte>::difference_type>(allocation_start),
            duplicated_record.size(),
            duplicated_record.begin());

        image.insert(
            image.begin() + static_cast<std::vector<std::byte>::difference_type>(allocation_start + kExtentRecordBytes),
            duplicated_record.begin(),
            duplicated_record.end());

        WriteLe32(
            image,
            offset + kSpacemanAllocationCountOffsetFromMagic,
            spaceman_allocations + 1);

        const auto new_payload_end = payload_end + kExtentRecordBytes;
        const auto payload_bytes = new_payload_end - (offset + kCommitBlobPayloadOffset);
        const auto payload_checksum = UpdateFnv1a(
            kCheckpointChecksumSeed,
            image.data() + static_cast<std::vector<std::byte>::difference_type>(offset + kCommitBlobPayloadOffset),
            payload_bytes);
        WriteLe32(image, offset + kCommitBlobChecksumOffset, payload_checksum);

        std::ofstream output(image_path, std::ios::binary | std::ios::trunc);
        if (!output.good())
        {
            return false;
        }
        if (!image.empty())
        {
            output.write(reinterpret_cast<const char*>(image.data()), static_cast<std::streamsize>(image.size()));
        }
        if (!output.good())
        {
            return false;
        }

        out_magic_offset = offset;
        return true;
    }

    return false;
}

bool CorruptCommitBlobOverlappingAllocationsWithValidChecksum(
    const std::filesystem::path& image_path,
    std::size_t& out_magic_offset)
{
    out_magic_offset = 0;
    constexpr std::array<unsigned char, 13> kCommitBlobMagic =
    {
        'A', 'P', 'F', 'S', 'R', 'W', 'S', 'C', 'A', 'F', 'F', '3', '\0'
    };
    constexpr std::size_t kCommitBlobBaseHeaderBytes = 13 + 8 + 8 + 4 + 4 + 4 + 4 + 4;
    constexpr std::size_t kCommitBlobChecksumOffset = kCommitBlobBaseHeaderBytes;
    constexpr std::size_t kCommitBlobPayloadOffset = kCommitBlobChecksumOffset + 4;
    constexpr std::size_t kExtentRecordBytes = 16;
    constexpr std::uint64_t kBlockSizeBytes = 4096;

    std::ifstream input(image_path, std::ios::binary);
    if (!input.good())
    {
        return false;
    }

    input.seekg(0, std::ios::end);
    if (!input.good())
    {
        return false;
    }
    const auto total_bytes = static_cast<std::size_t>(input.tellg());
    input.seekg(0, std::ios::beg);
    if (!input.good())
    {
        return false;
    }

    std::vector<std::byte> image(total_bytes);
    if (!image.empty())
    {
        input.read(reinterpret_cast<char*>(image.data()), static_cast<std::streamsize>(image.size()));
        if (static_cast<std::size_t>(input.gcount()) != image.size())
        {
            return false;
        }
    }

    if (image.size() < (kCommitBlobPayloadOffset + 64))
    {
        return false;
    }

    for (std::size_t offset = 0; offset <= (image.size() - kCommitBlobMagic.size()); ++offset)
    {
        bool magic_matches = true;
        for (std::size_t index = 0; index < kCommitBlobMagic.size(); ++index)
        {
            if (std::to_integer<unsigned char>(image[offset + index]) != kCommitBlobMagic[index])
            {
                magic_matches = false;
                break;
            }
        }
        if (!magic_matches)
        {
            continue;
        }

        const auto object_map_updates = ReadLe32(image, offset + 33);
        const auto spaceman_allocations = ReadLe32(image, offset + 37);
        const auto spaceman_deallocations = ReadLe32(image, offset + 41);
        const auto btree_records = ReadLe32(image, offset + 45);
        if (spaceman_allocations < 2)
        {
            continue;
        }

        std::size_t cursor = offset + kCommitBlobPayloadOffset;
        const auto advance = [&](std::uint64_t bytes) -> bool
        {
            if (bytes > (std::numeric_limits<std::size_t>::max() - cursor))
            {
                return false;
            }
            const auto next = cursor + static_cast<std::size_t>(bytes);
            if (next > image.size())
            {
                return false;
            }
            cursor = next;
            return true;
        };

        if (!advance(static_cast<std::uint64_t>(object_map_updates) * 32ull))
        {
            continue;
        }

        const auto allocations_start = cursor;
        const auto allocation_span_bytes = static_cast<std::uint64_t>(spaceman_allocations) * kExtentRecordBytes;
        if (!advance(allocation_span_bytes))
        {
            continue;
        }

        const auto first_offset = allocations_start;
        const auto second_offset = allocations_start + kExtentRecordBytes;
        if ((second_offset + kExtentRecordBytes) > cursor || cursor > image.size())
        {
            continue;
        }

        const auto first_physical = ReadLe64(image, first_offset + 0);
        const auto first_bytes = ReadLe64(image, first_offset + 8);
        if (first_physical == 0 || first_bytes < (2 * kBlockSizeBytes) ||
            (first_physical % kBlockSizeBytes) != 0 || (first_bytes % kBlockSizeBytes) != 0)
        {
            continue;
        }

        const auto mutated_physical = first_physical + kBlockSizeBytes;
        const auto mutated_bytes = first_bytes - kBlockSizeBytes;
        if (mutated_bytes == 0 || (mutated_bytes % kBlockSizeBytes) != 0)
        {
            continue;
        }

        WriteLe64(image, second_offset + 0, mutated_physical);
        WriteLe64(image, second_offset + 8, mutated_bytes);

        if (!advance(static_cast<std::uint64_t>(spaceman_deallocations) * 16ull))
        {
            return false;
        }

        for (std::uint32_t index = 0; index < btree_records; ++index)
        {
            if (cursor > image.size() || 16 > (image.size() - cursor))
            {
                return false;
            }
            const auto key_size = ReadLe32(image, cursor + 8);
            const auto value_size = ReadLe32(image, cursor + 12);
            cursor += 16;
            const auto payload_size = static_cast<std::uint64_t>(key_size) + static_cast<std::uint64_t>(value_size);
            if (!advance(payload_size))
            {
                return false;
            }
        }

        const auto payload_end = cursor;
        if (payload_end < (offset + kCommitBlobPayloadOffset) || payload_end > image.size())
        {
            return false;
        }

        const auto payload_bytes = payload_end - (offset + kCommitBlobPayloadOffset);
        const auto payload_checksum = UpdateFnv1a(
            kCheckpointChecksumSeed,
            image.data() + static_cast<std::vector<std::byte>::difference_type>(offset + kCommitBlobPayloadOffset),
            payload_bytes);
        WriteLe32(image, offset + kCommitBlobChecksumOffset, payload_checksum);

        std::ofstream output(image_path, std::ios::binary | std::ios::trunc);
        if (!output.good())
        {
            return false;
        }
        if (!image.empty())
        {
            output.write(reinterpret_cast<const char*>(image.data()), static_cast<std::streamsize>(image.size()));
        }
        if (!output.good())
        {
            return false;
        }

        out_magic_offset = offset;
        return true;
    }

    return false;
}

bool CorruptCommitBlobAllocationDeallocationOverlapWithValidChecksum(
    const std::filesystem::path& image_path,
    std::size_t& out_magic_offset)
{
    out_magic_offset = 0;
    constexpr std::array<unsigned char, 13> kCommitBlobMagic =
    {
        'A', 'P', 'F', 'S', 'R', 'W', 'S', 'C', 'A', 'F', 'F', '3', '\0'
    };
    constexpr std::size_t kCommitBlobBaseHeaderBytes = 13 + 8 + 8 + 4 + 4 + 4 + 4 + 4;
    constexpr std::size_t kCommitBlobChecksumOffset = kCommitBlobBaseHeaderBytes;
    constexpr std::size_t kCommitBlobPayloadOffset = kCommitBlobChecksumOffset + 4;
    constexpr std::size_t kExtentRecordBytes = 16;
    constexpr std::uint64_t kBlockSizeBytes = 4096;

    std::ifstream input(image_path, std::ios::binary);
    if (!input.good())
    {
        return false;
    }

    input.seekg(0, std::ios::end);
    if (!input.good())
    {
        return false;
    }
    const auto total_bytes = static_cast<std::size_t>(input.tellg());
    input.seekg(0, std::ios::beg);
    if (!input.good())
    {
        return false;
    }

    std::vector<std::byte> image(total_bytes);
    if (!image.empty())
    {
        input.read(reinterpret_cast<char*>(image.data()), static_cast<std::streamsize>(image.size()));
        if (static_cast<std::size_t>(input.gcount()) != image.size())
        {
            return false;
        }
    }

    if (image.size() < (kCommitBlobPayloadOffset + 64))
    {
        return false;
    }

    for (std::size_t offset = 0; offset <= (image.size() - kCommitBlobMagic.size()); ++offset)
    {
        bool magic_matches = true;
        for (std::size_t index = 0; index < kCommitBlobMagic.size(); ++index)
        {
            if (std::to_integer<unsigned char>(image[offset + index]) != kCommitBlobMagic[index])
            {
                magic_matches = false;
                break;
            }
        }
        if (!magic_matches)
        {
            continue;
        }

        const auto object_map_updates = ReadLe32(image, offset + 33);
        const auto spaceman_allocations = ReadLe32(image, offset + 37);
        const auto spaceman_deallocations = ReadLe32(image, offset + 41);
        const auto btree_records = ReadLe32(image, offset + 45);
        if (spaceman_allocations == 0 || spaceman_deallocations == 0)
        {
            continue;
        }

        std::size_t cursor = offset + kCommitBlobPayloadOffset;
        const auto advance = [&](std::uint64_t bytes) -> bool
        {
            if (bytes > (std::numeric_limits<std::size_t>::max() - cursor))
            {
                return false;
            }
            const auto next = cursor + static_cast<std::size_t>(bytes);
            if (next > image.size())
            {
                return false;
            }
            cursor = next;
            return true;
        };

        if (!advance(static_cast<std::uint64_t>(object_map_updates) * 32ull))
        {
            continue;
        }

        const auto allocations_start = cursor;
        const auto allocation_span_bytes = static_cast<std::uint64_t>(spaceman_allocations) * kExtentRecordBytes;
        if (!advance(allocation_span_bytes))
        {
            continue;
        }
        if ((allocations_start + kExtentRecordBytes) > cursor)
        {
            continue;
        }

        const auto first_allocation_physical = ReadLe64(image, allocations_start + 0);
        const auto first_allocation_bytes = ReadLe64(image, allocations_start + 8);
        if (first_allocation_physical == 0 || first_allocation_bytes < (2 * kBlockSizeBytes) ||
            (first_allocation_physical % kBlockSizeBytes) != 0 ||
            (first_allocation_bytes % kBlockSizeBytes) != 0)
        {
            continue;
        }

        const auto deallocations_start = cursor;
        const auto deallocation_span_bytes = static_cast<std::uint64_t>(spaceman_deallocations) * kExtentRecordBytes;
        if (!advance(deallocation_span_bytes))
        {
            continue;
        }
        if ((deallocations_start + kExtentRecordBytes) > cursor)
        {
            continue;
        }

        const auto mutated_deallocation_physical = first_allocation_physical + kBlockSizeBytes;
        const auto mutated_deallocation_bytes = first_allocation_bytes - kBlockSizeBytes;
        if (mutated_deallocation_bytes == 0 || (mutated_deallocation_bytes % kBlockSizeBytes) != 0)
        {
            continue;
        }

        WriteLe64(image, deallocations_start + 0, mutated_deallocation_physical);
        WriteLe64(image, deallocations_start + 8, mutated_deallocation_bytes);

        for (std::uint32_t index = 0; index < btree_records; ++index)
        {
            if (cursor > image.size() || 16 > (image.size() - cursor))
            {
                return false;
            }
            const auto key_size = ReadLe32(image, cursor + 8);
            const auto value_size = ReadLe32(image, cursor + 12);
            cursor += 16;
            const auto payload_size = static_cast<std::uint64_t>(key_size) + static_cast<std::uint64_t>(value_size);
            if (!advance(payload_size))
            {
                return false;
            }
        }

        const auto payload_end = cursor;
        if (payload_end < (offset + kCommitBlobPayloadOffset) || payload_end > image.size())
        {
            return false;
        }

        const auto payload_bytes = payload_end - (offset + kCommitBlobPayloadOffset);
        const auto payload_checksum = UpdateFnv1a(
            kCheckpointChecksumSeed,
            image.data() + static_cast<std::vector<std::byte>::difference_type>(offset + kCommitBlobPayloadOffset),
            payload_bytes);
        WriteLe32(image, offset + kCommitBlobChecksumOffset, payload_checksum);

        std::ofstream output(image_path, std::ios::binary | std::ios::trunc);
        if (!output.good())
        {
            return false;
        }
        if (!image.empty())
        {
            output.write(reinterpret_cast<const char*>(image.data()), static_cast<std::streamsize>(image.size()));
        }
        if (!output.good())
        {
            return false;
        }

        out_magic_offset = offset;
        return true;
    }

    return false;
}

bool CorruptCommitBlobOverlappingDeallocationsWithValidChecksum(
    const std::filesystem::path& image_path,
    std::size_t& out_magic_offset)
{
    out_magic_offset = 0;
    constexpr std::array<unsigned char, 13> kCommitBlobMagic =
    {
        'A', 'P', 'F', 'S', 'R', 'W', 'S', 'C', 'A', 'F', 'F', '3', '\0'
    };
    constexpr std::size_t kCommitBlobBaseHeaderBytes = 13 + 8 + 8 + 4 + 4 + 4 + 4 + 4;
    constexpr std::size_t kCommitBlobChecksumOffset = kCommitBlobBaseHeaderBytes;
    constexpr std::size_t kCommitBlobPayloadOffset = kCommitBlobChecksumOffset + 4;
    constexpr std::size_t kExtentRecordBytes = 16;
    constexpr std::uint64_t kBlockSizeBytes = 4096;

    std::ifstream input(image_path, std::ios::binary);
    if (!input.good())
    {
        return false;
    }

    input.seekg(0, std::ios::end);
    if (!input.good())
    {
        return false;
    }
    const auto total_bytes = static_cast<std::size_t>(input.tellg());
    input.seekg(0, std::ios::beg);
    if (!input.good())
    {
        return false;
    }

    std::vector<std::byte> image(total_bytes);
    if (!image.empty())
    {
        input.read(reinterpret_cast<char*>(image.data()), static_cast<std::streamsize>(image.size()));
        if (static_cast<std::size_t>(input.gcount()) != image.size())
        {
            return false;
        }
    }

    if (image.size() < (kCommitBlobPayloadOffset + 64))
    {
        return false;
    }

    for (std::size_t offset = 0; offset <= (image.size() - kCommitBlobMagic.size()); ++offset)
    {
        bool magic_matches = true;
        for (std::size_t index = 0; index < kCommitBlobMagic.size(); ++index)
        {
            if (std::to_integer<unsigned char>(image[offset + index]) != kCommitBlobMagic[index])
            {
                magic_matches = false;
                break;
            }
        }
        if (!magic_matches)
        {
            continue;
        }

        const auto object_map_updates = ReadLe32(image, offset + 33);
        const auto spaceman_allocations = ReadLe32(image, offset + 37);
        const auto spaceman_deallocations = ReadLe32(image, offset + 41);
        const auto btree_records = ReadLe32(image, offset + 45);
        if (spaceman_deallocations < 2)
        {
            continue;
        }

        std::size_t cursor = offset + kCommitBlobPayloadOffset;
        const auto advance = [&](std::uint64_t bytes) -> bool
        {
            if (bytes > (std::numeric_limits<std::size_t>::max() - cursor))
            {
                return false;
            }
            const auto next = cursor + static_cast<std::size_t>(bytes);
            if (next > image.size())
            {
                return false;
            }
            cursor = next;
            return true;
        };

        if (!advance(static_cast<std::uint64_t>(object_map_updates) * 32ull) ||
            !advance(static_cast<std::uint64_t>(spaceman_allocations) * 16ull))
        {
            continue;
        }

        const auto deallocations_start = cursor;
        const auto deallocation_span_bytes = static_cast<std::uint64_t>(spaceman_deallocations) * kExtentRecordBytes;
        if (!advance(deallocation_span_bytes))
        {
            continue;
        }

        const auto first_offset = deallocations_start;
        const auto second_offset = deallocations_start + kExtentRecordBytes;
        if ((second_offset + kExtentRecordBytes) > cursor || cursor > image.size())
        {
            continue;
        }

        const auto first_physical = ReadLe64(image, first_offset + 0);
        const auto first_bytes = ReadLe64(image, first_offset + 8);
        if (first_physical == 0 || first_bytes < (2 * kBlockSizeBytes) ||
            (first_physical % kBlockSizeBytes) != 0 || (first_bytes % kBlockSizeBytes) != 0)
        {
            continue;
        }

        const auto mutated_physical = first_physical + kBlockSizeBytes;
        const auto mutated_bytes = first_bytes - kBlockSizeBytes;
        if (mutated_bytes == 0 || (mutated_bytes % kBlockSizeBytes) != 0)
        {
            continue;
        }

        WriteLe64(image, second_offset + 0, mutated_physical);
        WriteLe64(image, second_offset + 8, mutated_bytes);

        for (std::uint32_t index = 0; index < btree_records; ++index)
        {
            if (cursor > image.size() || 16 > (image.size() - cursor))
            {
                return false;
            }
            const auto key_size = ReadLe32(image, cursor + 8);
            const auto value_size = ReadLe32(image, cursor + 12);
            cursor += 16;
            const auto payload_size = static_cast<std::uint64_t>(key_size) + static_cast<std::uint64_t>(value_size);
            if (!advance(payload_size))
            {
                return false;
            }
        }

        const auto payload_end = cursor;
        if (payload_end < (offset + kCommitBlobPayloadOffset) || payload_end > image.size())
        {
            return false;
        }

        const auto payload_bytes = payload_end - (offset + kCommitBlobPayloadOffset);
        const auto payload_checksum = UpdateFnv1a(
            kCheckpointChecksumSeed,
            image.data() + static_cast<std::vector<std::byte>::difference_type>(offset + kCommitBlobPayloadOffset),
            payload_bytes);
        WriteLe32(image, offset + kCommitBlobChecksumOffset, payload_checksum);

        std::ofstream output(image_path, std::ios::binary | std::ios::trunc);
        if (!output.good())
        {
            return false;
        }
        if (!image.empty())
        {
            output.write(reinterpret_cast<const char*>(image.data()), static_cast<std::streamsize>(image.size()));
        }
        if (!output.good())
        {
            return false;
        }

        out_magic_offset = offset;
        return true;
    }

    return false;
}

bool CorruptCommitBlobShiftFirstDeallocationWithValidChecksum(
    const std::filesystem::path& image_path,
    std::size_t& out_magic_offset)
{
    out_magic_offset = 0;
    constexpr std::array<unsigned char, 13> kCommitBlobMagic =
    {
        'A', 'P', 'F', 'S', 'R', 'W', 'S', 'C', 'A', 'F', 'F', '3', '\0'
    };
    constexpr std::size_t kCommitBlobBaseHeaderBytes = 13 + 8 + 8 + 4 + 4 + 4 + 4 + 4;
    constexpr std::size_t kCommitBlobChecksumOffset = kCommitBlobBaseHeaderBytes;
    constexpr std::size_t kCommitBlobPayloadOffset = kCommitBlobChecksumOffset + 4;
    constexpr std::size_t kExtentRecordBytes = 16;
    constexpr std::uint64_t kBlockSizeBytes = 4096;

    std::ifstream input(image_path, std::ios::binary);
    if (!input.good())
    {
        return false;
    }

    input.seekg(0, std::ios::end);
    if (!input.good())
    {
        return false;
    }
    const auto total_bytes = static_cast<std::size_t>(input.tellg());
    input.seekg(0, std::ios::beg);
    if (!input.good())
    {
        return false;
    }

    std::vector<std::byte> image(total_bytes);
    if (!image.empty())
    {
        input.read(reinterpret_cast<char*>(image.data()), static_cast<std::streamsize>(image.size()));
        if (static_cast<std::size_t>(input.gcount()) != image.size())
        {
            return false;
        }
    }

    if (image.size() < (kCommitBlobPayloadOffset + 64))
    {
        return false;
    }

    for (std::size_t offset = 0; offset <= (image.size() - kCommitBlobMagic.size()); ++offset)
    {
        bool magic_matches = true;
        for (std::size_t index = 0; index < kCommitBlobMagic.size(); ++index)
        {
            if (std::to_integer<unsigned char>(image[offset + index]) != kCommitBlobMagic[index])
            {
                magic_matches = false;
                break;
            }
        }
        if (!magic_matches)
        {
            continue;
        }

        const auto object_map_updates = ReadLe32(image, offset + 33);
        const auto spaceman_allocations = ReadLe32(image, offset + 37);
        const auto spaceman_deallocations = ReadLe32(image, offset + 41);
        const auto btree_records = ReadLe32(image, offset + 45);
        if (spaceman_deallocations == 0)
        {
            continue;
        }

        std::size_t cursor = offset + kCommitBlobPayloadOffset;
        const auto advance = [&](std::uint64_t bytes) -> bool
        {
            if (bytes > (std::numeric_limits<std::size_t>::max() - cursor))
            {
                return false;
            }
            const auto next = cursor + static_cast<std::size_t>(bytes);
            if (next > image.size())
            {
                return false;
            }
            cursor = next;
            return true;
        };

        if (!advance(static_cast<std::uint64_t>(object_map_updates) * 32ull) ||
            !advance(static_cast<std::uint64_t>(spaceman_allocations) * 16ull))
        {
            continue;
        }

        const auto first_deallocation_offset = cursor;
        const auto deallocation_span_bytes = static_cast<std::uint64_t>(spaceman_deallocations) * kExtentRecordBytes;
        if (!advance(deallocation_span_bytes))
        {
            continue;
        }
        if ((first_deallocation_offset + kExtentRecordBytes) > cursor || cursor > image.size())
        {
            continue;
        }

        const auto first_physical = ReadLe64(image, first_deallocation_offset + 0);
        const auto first_bytes = ReadLe64(image, first_deallocation_offset + 8);
        if (first_physical == 0 || first_bytes < (2 * kBlockSizeBytes) ||
            (first_physical % kBlockSizeBytes) != 0 || (first_bytes % kBlockSizeBytes) != 0)
        {
            continue;
        }

        const auto shifted_physical = first_physical + kBlockSizeBytes;
        const auto shifted_bytes = first_bytes - kBlockSizeBytes;
        if (shifted_bytes == 0 || (shifted_bytes % kBlockSizeBytes) != 0)
        {
            continue;
        }

        WriteLe64(image, first_deallocation_offset + 0, shifted_physical);
        WriteLe64(image, first_deallocation_offset + 8, shifted_bytes);

        for (std::uint32_t index = 0; index < btree_records; ++index)
        {
            if (cursor > image.size() || 16 > (image.size() - cursor))
            {
                return false;
            }
            const auto key_size = ReadLe32(image, cursor + 8);
            const auto value_size = ReadLe32(image, cursor + 12);
            cursor += 16;
            const auto payload_size = static_cast<std::uint64_t>(key_size) + static_cast<std::uint64_t>(value_size);
            if (!advance(payload_size))
            {
                return false;
            }
        }

        const auto payload_end = cursor;
        if (payload_end < (offset + kCommitBlobPayloadOffset) || payload_end > image.size())
        {
            return false;
        }

        const auto payload_bytes = payload_end - (offset + kCommitBlobPayloadOffset);
        const auto payload_checksum = UpdateFnv1a(
            kCheckpointChecksumSeed,
            image.data() + static_cast<std::vector<std::byte>::difference_type>(offset + kCommitBlobPayloadOffset),
            payload_bytes);
        WriteLe32(image, offset + kCommitBlobChecksumOffset, payload_checksum);

        std::ofstream output(image_path, std::ios::binary | std::ios::trunc);
        if (!output.good())
        {
            return false;
        }
        if (!image.empty())
        {
            output.write(reinterpret_cast<const char*>(image.data()), static_cast<std::streamsize>(image.size()));
        }
        if (!output.good())
        {
            return false;
        }

        out_magic_offset = offset;
        return true;
    }

    return false;
}

bool CorruptObjectMapCheckpointLogicalSize(
    const std::filesystem::path& image_path,
    std::uint64_t logical_size,
    std::size_t& out_corrupted_blocks)
{
    out_corrupted_blocks = 0;
    constexpr std::array<char, 12> kObjectMapMagic =
    {
        'A', 'P', 'F', 'S', 'R', 'W', 'O', 'M', 'A', 'P', '3', '\0'
    };
    constexpr std::size_t kObjectMapEntryBytes = 32;
    constexpr std::size_t kObjectMapEntryLogicalSizeOffset = 16;

    std::ifstream input(image_path, std::ios::binary);
    if (!input.good())
    {
        return false;
    }

    input.seekg(0, std::ios::end);
    if (!input.good())
    {
        return false;
    }
    const auto total_bytes = static_cast<std::size_t>(input.tellg());
    input.seekg(0, std::ios::beg);
    if (!input.good())
    {
        return false;
    }

    std::vector<std::byte> image(total_bytes);
    if (!image.empty())
    {
        input.read(reinterpret_cast<char*>(image.data()), static_cast<std::streamsize>(image.size()));
        if (static_cast<std::size_t>(input.gcount()) != image.size())
        {
            return false;
        }
    }

    const auto total_blocks = image.size() / kBlockSize;
    for (std::size_t block_index = 0; block_index < total_blocks; ++block_index)
    {
        const auto block_offset = block_index * kBlockSize;
        if ((block_offset + kObjectMapMagic.size()) > image.size())
        {
            break;
        }

        bool magic_matches = true;
        for (std::size_t byte_index = 0; byte_index < kObjectMapMagic.size(); ++byte_index)
        {
            if (std::to_integer<unsigned char>(image[block_offset + byte_index]) !=
                static_cast<unsigned char>(kObjectMapMagic[byte_index]))
            {
                magic_matches = false;
                break;
            }
        }
        if (!magic_matches)
        {
            continue;
        }

        const auto entry_count = ReadLe32(image, block_offset + 20);
        if (entry_count == 0)
        {
            continue;
        }

        const auto payload_bytes = static_cast<std::uint64_t>(entry_count) * static_cast<std::uint64_t>(kObjectMapEntryBytes);
        if (payload_bytes > (kBlockSize - kCheckpointHeaderBytes))
        {
            continue;
        }

        const auto logical_size_offset = block_offset + kCheckpointHeaderBytes + kObjectMapEntryLogicalSizeOffset;
        if (logical_size_offset > (std::numeric_limits<std::size_t>::max() - sizeof(std::uint64_t)) ||
            (logical_size_offset + sizeof(std::uint64_t)) > image.size())
        {
            continue;
        }

        WriteLe64(image, logical_size_offset, logical_size);

        WriteLe32(image, block_offset + kCheckpointChecksumOffset, 0);
        auto hash = UpdateFnv1a(
            kCheckpointChecksumSeed,
            image.data() + static_cast<std::vector<std::byte>::difference_type>(block_offset),
            kCheckpointChecksumOffset);
        if (payload_bytes > 0)
        {
            hash = UpdateFnv1a(
                hash,
                image.data() + static_cast<std::vector<std::byte>::difference_type>(block_offset + kCheckpointHeaderBytes),
                static_cast<std::size_t>(payload_bytes));
        }
        WriteLe32(image, block_offset + kCheckpointChecksumOffset, hash);
        ++out_corrupted_blocks;
    }

    if (out_corrupted_blocks == 0)
    {
        return false;
    }

    std::ofstream output(image_path, std::ios::binary | std::ios::trunc);
    if (!output.good())
    {
        return false;
    }
    if (!image.empty())
    {
        output.write(reinterpret_cast<const char*>(image.data()), static_cast<std::streamsize>(image.size()));
    }
    return output.good();
}

bool CorruptSpacemanCheckpointAllocationPhysical(
    const std::filesystem::path& image_path,
    std::uint64_t physical_address,
    std::size_t& out_corrupted_blocks)
{
    out_corrupted_blocks = 0;
    constexpr std::array<char, 12> kSpacemanMagic =
    {
        'A', 'P', 'F', 'S', 'R', 'W', 'S', 'P', 'M', '3', '\0', '\0'
    };
    constexpr std::size_t kSpacemanEntryBytes = 16;

    std::ifstream input(image_path, std::ios::binary);
    if (!input.good())
    {
        return false;
    }

    input.seekg(0, std::ios::end);
    if (!input.good())
    {
        return false;
    }
    const auto total_bytes = static_cast<std::size_t>(input.tellg());
    input.seekg(0, std::ios::beg);
    if (!input.good())
    {
        return false;
    }

    std::vector<std::byte> image(total_bytes);
    if (!image.empty())
    {
        input.read(reinterpret_cast<char*>(image.data()), static_cast<std::streamsize>(image.size()));
        if (static_cast<std::size_t>(input.gcount()) != image.size())
        {
            return false;
        }
    }

    const auto total_blocks = image.size() / kBlockSize;
    for (std::size_t block_index = 0; block_index < total_blocks; ++block_index)
    {
        const auto block_offset = block_index * kBlockSize;
        if ((block_offset + kSpacemanMagic.size()) > image.size())
        {
            break;
        }

        bool magic_matches = true;
        for (std::size_t byte_index = 0; byte_index < kSpacemanMagic.size(); ++byte_index)
        {
            if (std::to_integer<unsigned char>(image[block_offset + byte_index]) !=
                static_cast<unsigned char>(kSpacemanMagic[byte_index]))
            {
                magic_matches = false;
                break;
            }
        }
        if (!magic_matches)
        {
            continue;
        }

        const auto allocation_count = ReadLe32(image, block_offset + 20);
        const auto free_extent_count = ReadLe32(image, block_offset + 24);
        if (allocation_count == 0)
        {
            continue;
        }

        const auto payload_bytes =
            (static_cast<std::uint64_t>(allocation_count) + static_cast<std::uint64_t>(free_extent_count)) *
            static_cast<std::uint64_t>(kSpacemanEntryBytes);
        if (payload_bytes > (kBlockSize - kCheckpointHeaderBytes))
        {
            continue;
        }

        for (std::uint32_t index = 0; index < allocation_count; ++index)
        {
            const auto entry_offset = block_offset + kCheckpointHeaderBytes +
                                      static_cast<std::size_t>(index) * kSpacemanEntryBytes;
            if (entry_offset > (std::numeric_limits<std::size_t>::max() - sizeof(std::uint64_t)) ||
                (entry_offset + sizeof(std::uint64_t)) > image.size())
            {
                return false;
            }

            WriteLe64(image, entry_offset, physical_address);
        }

        WriteLe32(image, block_offset + kCheckpointChecksumOffset, 0);
        auto hash = UpdateFnv1a(
            kCheckpointChecksumSeed,
            image.data() + static_cast<std::vector<std::byte>::difference_type>(block_offset),
            kCheckpointChecksumOffset);
        if (payload_bytes > 0)
        {
            hash = UpdateFnv1a(
                hash,
                image.data() + static_cast<std::vector<std::byte>::difference_type>(block_offset + kCheckpointHeaderBytes),
                static_cast<std::size_t>(payload_bytes));
        }
        WriteLe32(image, block_offset + kCheckpointChecksumOffset, hash);
        ++out_corrupted_blocks;
    }

    if (out_corrupted_blocks == 0)
    {
        return false;
    }

    std::ofstream output(image_path, std::ios::binary | std::ios::trunc);
    if (!output.good())
    {
        return false;
    }
    if (!image.empty())
    {
        output.write(reinterpret_cast<const char*>(image.data()), static_cast<std::streamsize>(image.size()));
    }
    return output.good();
}

class ScopedEnvironmentVariable
{
public:
    ScopedEnvironmentVariable(std::wstring variable, std::wstring value)
        : variable_(std::move(variable))
    {
        wchar_t* current_raw = nullptr;
        std::size_t current_length = 0;
        if (_wdupenv_s(&current_raw, &current_length, variable_.c_str()) == 0 &&
            current_raw != nullptr)
        {
            previous_value_ = std::wstring(current_raw);
            std::free(current_raw);
        }
        (void)_wputenv_s(variable_.c_str(), value.c_str());
    }

    ~ScopedEnvironmentVariable()
    {
        if (previous_value_.has_value())
        {
            (void)_wputenv_s(variable_.c_str(), previous_value_->c_str());
            return;
        }
        (void)_wputenv_s(variable_.c_str(), L"");
    }

    ScopedEnvironmentVariable(const ScopedEnvironmentVariable&) = delete;
    ScopedEnvironmentVariable& operator=(const ScopedEnvironmentVariable&) = delete;

private:
    std::wstring variable_;
    std::optional<std::wstring> previous_value_;
};

bool Require(bool condition, const std::string& message)
{
    if (!condition)
    {
        std::cerr << "[FAIL] " << message << std::endl;
        return false;
    }

    return true;
}

std::vector<std::byte> BuildRepeatedPayload(std::size_t bytes, unsigned char value)
{
    return std::vector<std::byte>(bytes, static_cast<std::byte>(value));
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

            if (logical_size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
            {
                return std::nullopt;
            }

            auto payload = pending->second;
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

bool IsReplayCommitBlobRejectedReason(const std::wstring& reason)
{
    return reason == L"ScaffoldCommitBlobActive" ||
           reason == L"ReplayCommitBlobInvalid" ||
           reason == L"ReplayXidWindowInvalid" ||
           reason == L"ReplayIntegrityCheckFailed" ||
           reason == L"RecoveryCommitBlobUnavailable" ||
           reason == L"ReplayMetadataStateMissing" ||
           reason == L"ReplayCanonicalCandidateMissing" ||
           reason == L"ReplayCheckpointNotPendingWindow";
}
} // namespace

int main()
{
    std::error_code ec;
    const auto unique_id = std::chrono::steady_clock::now().time_since_epoch().count();
    const auto run_root = std::filesystem::temp_directory_path(ec) / ("ApfsAccessRwFaultTests_" + std::to_string(unique_id));
    if (ec)
    {
        std::cerr << "[FAIL] unable to access temporary directory" << std::endl;
        return 1;
    }

    std::filesystem::remove_all(run_root, ec);
    ec.clear();
    std::filesystem::create_directories(run_root, ec);
    if (ec)
    {
        std::cerr << "[FAIL] unable to create test directory" << std::endl;
        return 1;
    }

    const auto image_path = run_root / "container.apfs.img";
    if (!CreateSyntheticContainer(image_path))
    {
        std::cerr << "[FAIL] unable to create synthetic APFS container image" << std::endl;
        return 1;
    }

    constexpr std::uint64_t kCheckpointXidOffset = 0x10;
    constexpr std::uint64_t kSecondaryCheckpointXidOffset =
        static_cast<std::uint64_t>(kBlockSize) + kCheckpointXidOffset;

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"Faults",
    };

    bool ok = true;
    const auto cow_overwrite_image_path = run_root / "container_cow_overwrite.apfs.img";
    if (!CreateSyntheticContainer(cow_overwrite_image_path))
    {
        std::cerr << "[FAIL] unable to create synthetic APFS container image for COW overwrite scenario" << std::endl;
        return 1;
    }

    apfsaccess::rw::MetadataStore::VolumeContext cow_overwrite_context
    {
        cow_overwrite_image_path.wstring(),
        L"CowOverwrite",
    };
    {
        constexpr auto kCowOverwritePath = L"\\cow-overwrite.bin";
        const auto baseline_payload = BuildRepeatedPayload(4096, 0x5A);
        const auto rewritten_payload = BuildRepeatedPayload(4096, 0xA5);
        std::uint64_t baseline_physical_address = 0;
        std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;

        apfsaccess::rw::MetadataStore store(cow_overwrite_context);
        ok &= Require(store.LoadContainerSuperblocks(), "COW overwrite: LoadContainerSuperblocks should succeed");
        ok &= Require(store.LoadObjectMap(), "COW overwrite: LoadObjectMap should succeed");
        ok &= Require(store.LoadSpacemanState(), "COW overwrite: LoadSpacemanState should succeed");
        ok &= Require(store.PrepareNativeWritePath(), "COW overwrite: PrepareNativeWritePath should succeed");
        ConfigurePayloadProvider(store, staged_payloads);

        apfsaccess::rw::MetadataStore::MutationRequest create_file{};
        create_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
        create_file.path = kCowOverwritePath;
        ok &= Require(
            store.ApplyMutation(create_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "COW overwrite: create file should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_file{};
        write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_file.path = kCowOverwritePath;
        write_file.length = static_cast<std::uint64_t>(baseline_payload.size());
        ok &= Require(
            store.ApplyMutation(write_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "COW overwrite: initial write should apply");
        staged_payloads[kCowOverwritePath] = baseline_payload;
        ok &= Require(
            store.CommitPendingMutations() == apfsaccess::rw::MetadataStore::CommitStatus::Committed,
            "COW overwrite: baseline commit should succeed");
        const auto baseline_inode = store.LookupCommittedInodeByPath(kCowOverwritePath);
        ok &= Require(
            baseline_inode.has_value() && baseline_inode->data_physical_address != 0,
            "COW overwrite: baseline inode should have a committed physical extent");
        if (baseline_inode.has_value())
        {
            baseline_physical_address = baseline_inode->data_physical_address;
        }

        write_file.length = static_cast<std::uint64_t>(rewritten_payload.size());
        ok &= Require(
            store.ApplyMutation(write_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "COW overwrite: same-size rewrite should apply");
        staged_payloads[kCowOverwritePath] = rewritten_payload;
        store.SetCommitStageHook([](std::string_view stage)
        {
            return stage != "before-checkpoint-switch";
        });

        const auto interrupted_commit = store.CommitPendingMutations();
        ok &= Require(
            interrupted_commit == apfsaccess::rw::MetadataStore::CommitStatus::PersistFailed,
            "COW overwrite: interrupted rewrite should fail before checkpoint switch");
        ok &= Require(
            store.IsRecoveryRequired(),
            "COW overwrite: interrupted rewrite should latch recovery-required state");

        std::vector<std::byte> old_extent_bytes_after_interruption;
        ok &= Require(
            ReadBytesFromImage(
                cow_overwrite_image_path,
                baseline_physical_address,
                baseline_payload.size(),
                old_extent_bytes_after_interruption),
            "COW overwrite: old committed extent should still be readable after interrupted rewrite");
        ok &= Require(
            old_extent_bytes_after_interruption == baseline_payload,
            "COW overwrite: interrupted same-size rewrite must not overwrite the old committed extent");
    }

    {
        apfsaccess::rw::MetadataStore store(context);
        ok &= Require(store.LoadContainerSuperblocks(), "LoadContainerSuperblocks should succeed");
        ok &= Require(store.LoadObjectMap(), "LoadObjectMap should succeed");
        ok &= Require(store.LoadSpacemanState(), "LoadSpacemanState should succeed");
        ok &= Require(store.PrepareNativeWritePath(), "PrepareNativeWritePath should succeed");
        std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
        store.SetFilePayloadProvider(
            [&staged_payloads](const std::wstring& path, std::uint64_t logical_size) -> std::optional<std::vector<std::byte>>
            {
                auto pending = staged_payloads.find(path);
                if (pending == staged_payloads.end())
                {
                    return std::nullopt;
                }

                if (logical_size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
                {
                    return std::nullopt;
                }

                auto payload = pending->second;
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

        apfsaccess::rw::MetadataStore::MutationRequest create_first{};
        create_first.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
        create_first.path = L"\\first.bin";
        ok &= Require(
            store.ApplyMutation(create_first) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Create first file should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_first{};
        write_first.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_first.path = L"\\first.bin";
        write_first.length = 1400;
        ok &= Require(
            store.ApplyMutation(write_first) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Write first file should apply");
        staged_payloads[L"\\first.bin"] = std::vector<std::byte>(1400, static_cast<std::byte>(0x11));

        const auto pending_alloc_before_write_fault = store.PendingAllocationCount();
        store.SetCommitStageHook([](std::string_view stage)
        {
            return stage != "before-device-write";
        });

        const auto write_fault_commit = store.CommitPendingMutations();
        ok &= Require(
            write_fault_commit == apfsaccess::rw::MetadataStore::CommitStatus::PersistFailed,
            "Commit should fail with PersistFailed at before-device-write stage");
        ok &= Require(
            store.PendingAllocationCount() == pending_alloc_before_write_fault,
            "Pending allocation count should roll back after before-device-write failure");
        ok &= Require(
            store.LastCommittedXid().value_or(0) == 0,
            "No commit xid should be recorded after failed first commit");
        ok &= Require(
            !store.LookupCommittedInodeByPath(L"\\first.bin").has_value(),
            "Failed first commit should not publish first file");

        store.SetCommitStageHook({});
        const auto first_success = store.CommitPendingMutations();
        ok &= Require(
            first_success == apfsaccess::rw::MetadataStore::CommitStatus::Committed,
            "Retry commit after before-device-write fault should succeed");
        ok &= Require(
            store.LastCommittedXid().value_or(0) == (kInitialCheckpointXid + 1),
            "First successful commit should advance xid by one");
        ok &= Require(
            store.LookupCommittedInodeByPath(L"\\first.bin").has_value(),
            "First file should be committed after successful retry");

        apfsaccess::rw::MetadataStore::MutationRequest create_second{};
        create_second.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
        create_second.path = L"\\second.bin";
        ok &= Require(
            store.ApplyMutation(create_second) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Create second file should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_second{};
        write_second.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_second.path = L"\\second.bin";
        write_second.length = 700;
        ok &= Require(
            store.ApplyMutation(write_second) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Write second file should apply");
        staged_payloads[L"\\second.bin"] = std::vector<std::byte>(700, static_cast<std::byte>(0x22));

        const auto pending_alloc_before_persist_fault = store.PendingAllocationCount();
        store.SetCommitStageHook([](std::string_view stage)
        {
            return stage != "before-state-persist";
        });

        const auto persist_fault_commit = store.CommitPendingMutations();
        ok &= Require(
            persist_fault_commit == apfsaccess::rw::MetadataStore::CommitStatus::PersistFailed,
            "Commit should fail with PersistFailed at before-state-persist stage");
        ok &= Require(
            store.PendingAllocationCount() == pending_alloc_before_persist_fault,
            "Pending allocation count should roll back after before-state-persist failure");
        ok &= Require(
            store.LastCommittedXid().value_or(0) == (kInitialCheckpointXid + 1),
            "Failed second commit should not advance xid");
        ok &= Require(
            !store.LookupCommittedInodeByPath(L"\\second.bin").has_value(),
            "Failed second commit should not publish second file");

        store.SetCommitStageHook({});
        const auto second_success = store.CommitPendingMutations();
        ok &= Require(
            second_success == apfsaccess::rw::MetadataStore::CommitStatus::Committed,
            "Retry commit after before-state-persist fault should succeed");
        ok &= Require(
            store.LastCommittedXid().value_or(0) == (kInitialCheckpointXid + 2),
            "Second successful commit should advance xid by one");
        ok &= Require(
            store.LookupCommittedInodeByPath(L"\\second.bin").has_value(),
            "Second file should be committed after successful retry");

        apfsaccess::rw::MetadataStore::MutationRequest create_third{};
        create_third.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
        create_third.path = L"\\third.bin";
        ok &= Require(
            store.ApplyMutation(create_third) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Create third file should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_third{};
        write_third.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_third.path = L"\\third.bin";
        write_third.length = 1111;
        ok &= Require(
            store.ApplyMutation(write_third) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Write third file should apply");
        staged_payloads[L"\\third.bin"] = std::vector<std::byte>(1111, static_cast<std::byte>(0x33));

        const auto pending_alloc_before_preflight_fault = store.PendingAllocationCount();
        store.SetCommitStageHook([](std::string_view stage)
        {
            return stage != "before-preflight";
        });

        const auto preflight_fault_commit = store.CommitPendingMutations();
        ok &= Require(
            preflight_fault_commit == apfsaccess::rw::MetadataStore::CommitStatus::InvariantFailed,
            "Commit should fail with InvariantFailed at before-preflight stage");
        ok &= Require(
            store.PendingAllocationCount() == pending_alloc_before_preflight_fault,
            "Pending allocation count should remain unchanged after before-preflight failure");
        ok &= Require(
            store.LastCommittedXid().value_or(0) == (kInitialCheckpointXid + 2),
            "Preflight failure should not advance xid");
        ok &= Require(
            !store.LookupCommittedInodeByPath(L"\\third.bin").has_value(),
            "Failed third commit should not publish third file");

        store.SetCommitStageHook({});
        const auto third_success = store.CommitPendingMutations();
        ok &= Require(
            third_success == apfsaccess::rw::MetadataStore::CommitStatus::Committed,
            "Retry commit after before-preflight fault should succeed");
        ok &= Require(
            store.LastCommittedXid().value_or(0) == (kInitialCheckpointXid + 3),
            "Third successful commit should advance xid by one");
        ok &= Require(
            store.LookupCommittedInodeByPath(L"\\third.bin").has_value(),
            "Third file should be committed after successful retry");

        apfsaccess::rw::MetadataStore::MutationRequest create_fourth{};
        create_fourth.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
        create_fourth.path = L"\\fourth.bin";
        ok &= Require(
            store.ApplyMutation(create_fourth) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Create fourth file should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_fourth{};
        write_fourth.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_fourth.path = L"\\fourth.bin";
        write_fourth.length = 2048;
        ok &= Require(
            store.ApplyMutation(write_fourth) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Write fourth file should apply");
        staged_payloads[L"\\fourth.bin"] = std::vector<std::byte>(2048, static_cast<std::byte>(0x44));

        store.SetCommitStageHook([](std::string_view stage)
        {
            return stage != "before-checkpoint-switch";
        });

        const auto checkpoint_switch_fault_commit = store.CommitPendingMutations();
        ok &= Require(
            checkpoint_switch_fault_commit == apfsaccess::rw::MetadataStore::CommitStatus::PersistFailed,
            "Commit should fail with PersistFailed at before-checkpoint-switch stage");
        ok &= Require(
            store.LastCommittedXid().value_or(0) == (kInitialCheckpointXid + 4),
            "Checkpoint-switch stage failure should retain promoted xid");
        ok &= Require(
            store.LookupCommittedInodeByPath(L"\\fourth.bin").has_value(),
            "Checkpoint-switch stage failure should retain committed fourth file in current state");
        ok &= Require(
            store.PendingMutationCount() > 0,
            "Checkpoint-switch stage failure should keep pending mutations for conservative recovery handling");
        ok &= Require(
            store.IsRecoveryRequired(),
            "Checkpoint-switch stage failure should latch recovery-required state in-session");
        ok &= Require(
            !store.IsCommitPathReady(),
            "Checkpoint-switch stage failure should block commit path in-session");
        ok &= Require(
            store.RecoveryReason() == L"CommitInterruptedBeforeCheckpointSwitch",
            "Checkpoint-switch stage failure should set in-session recovery reason");
        const auto blocked_retry_after_checkpoint_switch = store.CommitPendingMutations();
        ok &= Require(
            blocked_retry_after_checkpoint_switch == apfsaccess::rw::MetadataStore::CommitStatus::NotWritable,
            "Recovery-latched checkpoint-switch failure should fail-closed on retry");
    }

    {
        apfsaccess::rw::MetadataStore remounted(context);
        ok &= Require(remounted.LoadContainerSuperblocks(), "Remount LoadContainerSuperblocks should succeed");
        ok &= Require(remounted.PrepareNativeWritePath(), "Remount PrepareNativeWritePath should succeed");
        ok &= Require(remounted.IsRecoveryRequired(), "Remount should require recovery after checkpoint-switch interruption");
        ok &= Require(!remounted.IsCommitPathReady(), "Remount commit path should be blocked while recovery is required");
        ok &= Require(
            remounted.RecoveryReason() == L"PersistentStateAheadOfSuperblock",
            "Recovery reason should indicate persistent state ahead of superblock checkpoint");
        ok &= Require(
            remounted.LastCommittedXid().value_or(0) == (kInitialCheckpointXid + 4),
            "Remount should preserve xid after successful retries");
        ok &= Require(remounted.LookupCommittedInodeByPath(L"\\first.bin").has_value(), "Remount should preserve first file");
        ok &= Require(remounted.LookupCommittedInodeByPath(L"\\second.bin").has_value(), "Remount should preserve second file");
        ok &= Require(remounted.LookupCommittedInodeByPath(L"\\third.bin").has_value(), "Remount should preserve third file");
        ok &= Require(remounted.LookupCommittedInodeByPath(L"\\fourth.bin").has_value(), "Remount should preserve fourth file");
    }

    const auto replay_fault_image_path = run_root / "container_replay_fault.apfs.img";
    if (!CreateSyntheticContainer(replay_fault_image_path))
    {
        std::cerr << "[FAIL] unable to create synthetic APFS container image for replay-fault scenario" << std::endl;
        return 1;
    }

    apfsaccess::rw::MetadataStore::VolumeContext replay_fault_context
    {
        replay_fault_image_path.wstring(),
        L"ReplayFaults",
    };
    replay_fault_context.crash_replay_mode = L"ReplayIfSafe";
    {
        apfsaccess::rw::MetadataStore store(replay_fault_context);
        ok &= Require(store.LoadContainerSuperblocks(), "Replay-fault LoadContainerSuperblocks should succeed");
        ok &= Require(store.LoadObjectMap(), "Replay-fault LoadObjectMap should succeed");
        ok &= Require(store.LoadSpacemanState(), "Replay-fault LoadSpacemanState should succeed");
        ok &= Require(store.PrepareNativeWritePath(), "Replay-fault PrepareNativeWritePath should succeed");
        std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
        store.SetFilePayloadProvider(
            [&staged_payloads](const std::wstring& path, std::uint64_t logical_size) -> std::optional<std::vector<std::byte>>
            {
                auto pending = staged_payloads.find(path);
                if (pending == staged_payloads.end())
                {
                    return std::nullopt;
                }

                if (logical_size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
                {
                    return std::nullopt;
                }

                auto payload = pending->second;
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
        create_file.path = L"\\replay.bin";
        ok &= Require(
            store.ApplyMutation(create_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-fault create file should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_file{};
        write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_file.path = L"\\replay.bin";
        write_file.length = 2304;
        ok &= Require(
            store.ApplyMutation(write_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-fault write file should apply");
        staged_payloads[L"\\replay.bin"] = std::vector<std::byte>(2304, static_cast<std::byte>(0x5A));

        store.SetCommitStageHook([](std::string_view stage)
        {
            return stage != "before-checkpoint-switch";
        });

        const auto replay_fault_commit = store.CommitPendingMutations();
        ok &= Require(
            replay_fault_commit == apfsaccess::rw::MetadataStore::CommitStatus::PersistFailed,
            "Replay-fault commit should fail at before-checkpoint-switch stage");
        ok &= Require(
            store.IsRecoveryRequired(),
            "Replay-fault should require recovery after interrupted checkpoint switch");
        ok &= Require(
            store.RecoveryReason() == L"CommitInterruptedBeforeCheckpointSwitch",
            "Replay-fault should store in-session recovery reason");
        ok &= Require(
            store.LastCommittedXid().value_or(0) == (kInitialCheckpointXid + 1),
            "Replay-fault should retain promoted xid after checkpoint-switch interruption");
    }

    const auto primary_before_replay = ReadLe64FromImage(replay_fault_image_path, kCheckpointXidOffset);
    const auto secondary_before_replay = ReadLe64FromImage(replay_fault_image_path, kSecondaryCheckpointXidOffset);
    ok &= Require(
        primary_before_replay.has_value() && secondary_before_replay.has_value(),
        "Replay-fault should read checkpoint xids before replay");
    if (primary_before_replay.has_value() && secondary_before_replay.has_value())
    {
        ok &= Require(
            std::max(primary_before_replay.value(), secondary_before_replay.value()) == kInitialCheckpointXid,
            "Replay-fault should keep on-disk checkpoint xid unchanged before replay");
    }

    {
        apfsaccess::rw::MetadataStore remounted(replay_fault_context);
        ok &= Require(remounted.LoadContainerSuperblocks(), "Replay-fault remount LoadContainerSuperblocks should succeed");
        ok &= Require(remounted.PrepareNativeWritePath(), "Replay-fault remount PrepareNativeWritePath should succeed");
        ok &= Require(remounted.IsRecoveryRequired(), "Replay-fault remount should require recovery");
        ok &= Require(
            remounted.RecoveryReason() == L"PersistentStateAheadOfSuperblock",
            "Replay-fault remount should detect persistent state ahead of superblock");
        ok &= Require(remounted.ReplayOrRecover(), "Replay-fault remount should replay safely");
        ok &= Require(!remounted.IsRecoveryRequired(), "Replay-fault remount should clear recovery after replay");
        ok &= Require(remounted.IsCommitPathReady(), "Replay-fault remount should re-enable commit path after replay");
        ok &= Require(
            remounted.CheckpointXid().value_or(0) == (kInitialCheckpointXid + 1),
            "Replay-fault remount should expose recovered checkpoint xid");
    }

    {
        apfsaccess::rw::MetadataStore remounted_after_replay(replay_fault_context);
        ok &= Require(
            remounted_after_replay.LoadContainerSuperblocks(),
            "Replay-fault post-replay remount LoadContainerSuperblocks should succeed");
        ok &= Require(
            remounted_after_replay.PrepareNativeWritePath(),
            "Replay-fault post-replay remount PrepareNativeWritePath should succeed");
        ok &= Require(
            !remounted_after_replay.IsRecoveryRequired(),
            "Replay-fault post-replay remount should not require recovery once replay has completed");
        ok &= Require(
            remounted_after_replay.IsCommitPathReady(),
            "Replay-fault post-replay remount should keep commit path ready");
        ok &= Require(
            remounted_after_replay.CheckpointXid().value_or(0) == (kInitialCheckpointXid + 1),
            "Replay-fault post-replay remount should keep recovered checkpoint xid");
    }

    const auto primary_after_replay = ReadLe64FromImage(replay_fault_image_path, kCheckpointXidOffset);
    const auto secondary_after_replay = ReadLe64FromImage(replay_fault_image_path, kSecondaryCheckpointXidOffset);
    ok &= Require(
        primary_after_replay.has_value() && secondary_after_replay.has_value(),
        "Replay-fault should read checkpoint xids after replay");
    if (primary_after_replay.has_value() && secondary_after_replay.has_value())
    {
        ok &= Require(
            std::max(primary_after_replay.value(), secondary_after_replay.value()) == (kInitialCheckpointXid + 1),
            "Replay-fault should persist recovered checkpoint xid to disk");
    }

    const auto replay_missing_state_image_path = run_root / "container_replay_missing_state.apfs.img";
    if (!CreateSyntheticContainer(replay_missing_state_image_path))
    {
        std::cerr << "[FAIL] unable to create synthetic APFS container image for replay-missing-state scenario" << std::endl;
        return 1;
    }

    apfsaccess::rw::MetadataStore::VolumeContext replay_missing_state_context
    {
        replay_missing_state_image_path.wstring(),
        L"ReplayMissingState",
    };
    replay_missing_state_context.crash_replay_mode = L"ReplayIfSafe";
    {
        apfsaccess::rw::MetadataStore store(replay_missing_state_context);
        ok &= Require(store.LoadContainerSuperblocks(), "Replay-missing-state LoadContainerSuperblocks should succeed");
        ok &= Require(store.LoadObjectMap(), "Replay-missing-state LoadObjectMap should succeed");
        ok &= Require(store.LoadSpacemanState(), "Replay-missing-state LoadSpacemanState should succeed");
        ok &= Require(store.PrepareNativeWritePath(), "Replay-missing-state PrepareNativeWritePath should succeed");
        std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
        store.SetFilePayloadProvider(
            [&staged_payloads](const std::wstring& path, std::uint64_t logical_size) -> std::optional<std::vector<std::byte>>
            {
                auto pending = staged_payloads.find(path);
                if (pending == staged_payloads.end())
                {
                    return std::nullopt;
                }

                if (logical_size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
                {
                    return std::nullopt;
                }

                auto payload = pending->second;
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
        create_file.path = L"\\replay_missing_state.bin";
        ok &= Require(
            store.ApplyMutation(create_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-missing-state create file should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_file{};
        write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_file.path = L"\\replay_missing_state.bin";
        write_file.length = 2048;
        ok &= Require(
            store.ApplyMutation(write_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-missing-state write file should apply");
        staged_payloads[L"\\replay_missing_state.bin"] = std::vector<std::byte>(2048, static_cast<std::byte>(0x76));

        store.SetCommitStageHook([](std::string_view stage)
        {
            return stage != "before-checkpoint-switch";
        });

        const auto interrupted_commit = store.CommitPendingMutations();
        ok &= Require(
            interrupted_commit == apfsaccess::rw::MetadataStore::CommitStatus::PersistFailed,
            "Replay-missing-state setup commit should fail at before-checkpoint-switch stage");
        ok &= Require(
            store.IsRecoveryRequired(),
            "Replay-missing-state setup should require recovery");
    }

    {
        const auto persistent_state_path = BuildPersistentStatePath(
            replay_missing_state_context.device_path,
            replay_missing_state_context.volume_name);
        if (!persistent_state_path.empty())
        {
            std::filesystem::remove(persistent_state_path, ec);
        }
    }

    {
        apfsaccess::rw::MetadataStore remounted(replay_missing_state_context);
        ok &= Require(remounted.LoadContainerSuperblocks(), "Replay-missing-state remount LoadContainerSuperblocks should succeed");
        ok &= Require(remounted.PrepareNativeWritePath(), "Replay-missing-state remount PrepareNativeWritePath should succeed");
        ok &= Require(remounted.IsRecoveryRequired(), "Replay-missing-state remount should require recovery");
        ok &= Require(
            remounted.RecoveryReason() == L"PersistentStateAheadOfSuperblock",
            "Replay-missing-state remount should detect metadata ahead of superblock without persistent state");
        ok &= Require(remounted.ReplayOrRecover(), "Replay-missing-state remount replay should succeed from on-disk replay metadata");
        ok &= Require(!remounted.IsRecoveryRequired(), "Replay-missing-state remount should clear recovery after replay");
        ok &= Require(remounted.IsCommitPathReady(), "Replay-missing-state remount should restore commit path readiness after replay");
        ok &= Require(
            remounted.CheckpointXid().value_or(0) == (kInitialCheckpointXid + 1),
            "Replay-missing-state remount should publish recovered checkpoint xid");
    }

    const auto replay_prefer_checkpoint_image_path = run_root / "container_replay_prefer_checkpoint.apfs.img";
    if (!CreateSyntheticContainer(replay_prefer_checkpoint_image_path))
    {
        std::cerr << "[FAIL] unable to create synthetic APFS container image for replay-prefer-checkpoint scenario" << std::endl;
        return 1;
    }

    apfsaccess::rw::MetadataStore::VolumeContext replay_prefer_checkpoint_context
    {
        replay_prefer_checkpoint_image_path.wstring(),
        L"ReplayPreferCheckpoint",
    };
    replay_prefer_checkpoint_context.crash_replay_mode = L"ReplayIfSafe";
    {
        apfsaccess::rw::MetadataStore store(replay_prefer_checkpoint_context);
        ok &= Require(store.LoadContainerSuperblocks(), "Replay-prefer-checkpoint LoadContainerSuperblocks should succeed");
        ok &= Require(store.LoadObjectMap(), "Replay-prefer-checkpoint LoadObjectMap should succeed");
        ok &= Require(store.LoadSpacemanState(), "Replay-prefer-checkpoint LoadSpacemanState should succeed");
        ok &= Require(store.PrepareNativeWritePath(), "Replay-prefer-checkpoint PrepareNativeWritePath should succeed");
        std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
        store.SetFilePayloadProvider(
            [&staged_payloads](const std::wstring& path, std::uint64_t logical_size) -> std::optional<std::vector<std::byte>>
            {
                auto pending = staged_payloads.find(path);
                if (pending == staged_payloads.end())
                {
                    return std::nullopt;
                }

                if (logical_size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
                {
                    return std::nullopt;
                }

                auto payload = pending->second;
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
        create_file.path = L"\\replay_prefer_checkpoint.bin";
        ok &= Require(
            store.ApplyMutation(create_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-prefer-checkpoint create file should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_file{};
        write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_file.path = L"\\replay_prefer_checkpoint.bin";
        write_file.length = 2048;
        ok &= Require(
            store.ApplyMutation(write_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-prefer-checkpoint write file should apply");
        staged_payloads[L"\\replay_prefer_checkpoint.bin"] = std::vector<std::byte>(2048, static_cast<std::byte>(0x78));

        store.SetCommitStageHook([](std::string_view stage)
        {
            return stage != "before-checkpoint-switch";
        });

        const auto interrupted_commit = store.CommitPendingMutations();
        ok &= Require(
            interrupted_commit == apfsaccess::rw::MetadataStore::CommitStatus::PersistFailed,
            "Replay-prefer-checkpoint setup commit should fail at before-checkpoint-switch stage");
        ok &= Require(
            store.IsRecoveryRequired(),
            "Replay-prefer-checkpoint setup should require recovery");
    }

    {
        const auto persistent_state_path = BuildPersistentStatePath(
            replay_prefer_checkpoint_context.device_path,
            replay_prefer_checkpoint_context.volume_name);
        ok &= Require(
            OverridePersistentStateCommitBlobMetadata(
                persistent_state_path,
                /*persisted_last_commit_xid=*/kInitialCheckpointXid,
                /*persisted_commit_blob_address=*/static_cast<std::uint64_t>(kBlockSize),
                /*persisted_commit_blob_bytes=*/static_cast<std::uint64_t>(kBlockSize)),
            "Replay-prefer-checkpoint should inject stale persistent-state commit-blob metadata");
    }

    {
        apfsaccess::rw::MetadataStore remounted(replay_prefer_checkpoint_context);
        ok &= Require(remounted.LoadContainerSuperblocks(), "Replay-prefer-checkpoint remount LoadContainerSuperblocks should succeed");
        ok &= Require(remounted.PrepareNativeWritePath(), "Replay-prefer-checkpoint remount PrepareNativeWritePath should succeed");
        ok &= Require(remounted.IsRecoveryRequired(), "Replay-prefer-checkpoint remount should require recovery");
        ok &= Require(
            remounted.RecoveryReason() == L"PersistentStateAheadOfSuperblock",
            "Replay-prefer-checkpoint remount should detect metadata ahead of superblock");
        ok &= Require(remounted.ReplayOrRecover(), "Replay-prefer-checkpoint remount should prefer on-disk replay metadata over stale persistent commit-blob metadata");
        ok &= Require(!remounted.IsRecoveryRequired(), "Replay-prefer-checkpoint remount should clear recovery after replay");
        ok &= Require(remounted.IsCommitPathReady(), "Replay-prefer-checkpoint remount should restore commit path readiness after replay");
        ok &= Require(
            remounted.CheckpointXid().value_or(0) == (kInitialCheckpointXid + 1),
            "Replay-prefer-checkpoint remount should publish recovered checkpoint xid");
    }

    const auto replay_invalid_persistent_commit_blob_image_path = run_root / "container_replay_invalid_persistent_commit_blob.apfs.img";
    if (!CreateSyntheticContainer(replay_invalid_persistent_commit_blob_image_path))
    {
        std::cerr << "[FAIL] unable to create synthetic APFS container image for replay-invalid-persistent-commit-blob scenario" << std::endl;
        return 1;
    }

    apfsaccess::rw::MetadataStore::VolumeContext replay_invalid_persistent_commit_blob_context
    {
        replay_invalid_persistent_commit_blob_image_path.wstring(),
        L"ReplayInvalidPersistentCommitBlob",
    };
    replay_invalid_persistent_commit_blob_context.crash_replay_mode = L"ReplayIfSafe";
    {
        apfsaccess::rw::MetadataStore store(replay_invalid_persistent_commit_blob_context);
        ok &= Require(store.LoadContainerSuperblocks(), "Replay-invalid-persistent-commit-blob LoadContainerSuperblocks should succeed");
        ok &= Require(store.LoadObjectMap(), "Replay-invalid-persistent-commit-blob LoadObjectMap should succeed");
        ok &= Require(store.LoadSpacemanState(), "Replay-invalid-persistent-commit-blob LoadSpacemanState should succeed");
        ok &= Require(store.PrepareNativeWritePath(), "Replay-invalid-persistent-commit-blob PrepareNativeWritePath should succeed");
        std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
        store.SetFilePayloadProvider(
            [&staged_payloads](const std::wstring& path, std::uint64_t logical_size) -> std::optional<std::vector<std::byte>>
            {
                auto pending = staged_payloads.find(path);
                if (pending == staged_payloads.end())
                {
                    return std::nullopt;
                }

                if (logical_size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
                {
                    return std::nullopt;
                }

                auto payload = pending->second;
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
        create_file.path = L"\\replay_invalid_persistent_commit_blob.bin";
        ok &= Require(
            store.ApplyMutation(create_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-invalid-persistent-commit-blob create file should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_file{};
        write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_file.path = L"\\replay_invalid_persistent_commit_blob.bin";
        write_file.length = 2048;
        ok &= Require(
            store.ApplyMutation(write_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-invalid-persistent-commit-blob write file should apply");
        staged_payloads[L"\\replay_invalid_persistent_commit_blob.bin"] = std::vector<std::byte>(2048, static_cast<std::byte>(0x7B));

        store.SetCommitStageHook([](std::string_view stage)
        {
            return stage != "before-checkpoint-switch";
        });

        const auto interrupted_commit = store.CommitPendingMutations();
        ok &= Require(
            interrupted_commit == apfsaccess::rw::MetadataStore::CommitStatus::PersistFailed,
            "Replay-invalid-persistent-commit-blob setup commit should fail at before-checkpoint-switch stage");
        ok &= Require(
            store.IsRecoveryRequired(),
            "Replay-invalid-persistent-commit-blob setup should require recovery");
    }

    {
        const auto persistent_state_path = BuildPersistentStatePath(
            replay_invalid_persistent_commit_blob_context.device_path,
            replay_invalid_persistent_commit_blob_context.volume_name);
        ok &= Require(
            OverridePersistentStateCommitBlobMetadata(
                persistent_state_path,
                /*persisted_last_commit_xid=*/kInitialCheckpointXid + 1,
                /*persisted_commit_blob_address=*/3,
                /*persisted_commit_blob_bytes=*/static_cast<std::uint64_t>(kBlockSize)),
            "Replay-invalid-persistent-commit-blob should inject malformed persistent commit-blob metadata");
    }

    {
        apfsaccess::rw::MetadataStore remounted(replay_invalid_persistent_commit_blob_context);
        ok &= Require(remounted.LoadContainerSuperblocks(), "Replay-invalid-persistent-commit-blob remount LoadContainerSuperblocks should succeed");
        ok &= Require(remounted.PrepareNativeWritePath(), "Replay-invalid-persistent-commit-blob remount PrepareNativeWritePath should succeed");
        ok &= Require(remounted.IsRecoveryRequired(), "Replay-invalid-persistent-commit-blob remount should require recovery");
        ok &= Require(
            remounted.RecoveryReason() == L"PersistentStateAheadOfSuperblock",
            "Replay-invalid-persistent-commit-blob remount should detect persistent state ahead of superblock");
        ok &= Require(
            remounted.ReplayOrRecover(),
            "Replay-invalid-persistent-commit-blob remount should prefer valid replay-checkpoint metadata over malformed persistent commit-blob metadata");
        ok &= Require(!remounted.IsRecoveryRequired(), "Replay-invalid-persistent-commit-blob remount should clear recovery after replay");
        ok &= Require(remounted.IsCommitPathReady(), "Replay-invalid-persistent-commit-blob remount should restore commit path readiness");
        ok &= Require(
            remounted.CheckpointXid().value_or(0) == (kInitialCheckpointXid + 1),
            "Replay-invalid-persistent-commit-blob remount should publish recovered checkpoint xid");
    }

    const auto replay_unaligned_persistent_commit_blob_image_path = run_root / "container_replay_unaligned_persistent_commit_blob.apfs.img";
    if (!CreateSyntheticContainer(replay_unaligned_persistent_commit_blob_image_path))
    {
        std::cerr << "[FAIL] unable to create synthetic APFS container image for replay-unaligned-persistent-commit-blob scenario" << std::endl;
        return 1;
    }

    apfsaccess::rw::MetadataStore::VolumeContext replay_unaligned_persistent_commit_blob_context
    {
        replay_unaligned_persistent_commit_blob_image_path.wstring(),
        L"ReplayUnalignedPersistentCommitBlob",
    };
    replay_unaligned_persistent_commit_blob_context.crash_replay_mode = L"ReplayIfSafe";
    {
        apfsaccess::rw::MetadataStore store(replay_unaligned_persistent_commit_blob_context);
        ok &= Require(store.LoadContainerSuperblocks(), "Replay-unaligned-persistent-commit-blob LoadContainerSuperblocks should succeed");
        ok &= Require(store.LoadObjectMap(), "Replay-unaligned-persistent-commit-blob LoadObjectMap should succeed");
        ok &= Require(store.LoadSpacemanState(), "Replay-unaligned-persistent-commit-blob LoadSpacemanState should succeed");
        ok &= Require(store.PrepareNativeWritePath(), "Replay-unaligned-persistent-commit-blob PrepareNativeWritePath should succeed");
        std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
        store.SetFilePayloadProvider(
            [&staged_payloads](const std::wstring& path, std::uint64_t logical_size) -> std::optional<std::vector<std::byte>>
            {
                auto pending = staged_payloads.find(path);
                if (pending == staged_payloads.end())
                {
                    return std::nullopt;
                }

                if (logical_size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
                {
                    return std::nullopt;
                }

                auto payload = pending->second;
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
        create_file.path = L"\\replay_unaligned_persistent_commit_blob.bin";
        ok &= Require(
            store.ApplyMutation(create_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-unaligned-persistent-commit-blob create file should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_file{};
        write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_file.path = L"\\replay_unaligned_persistent_commit_blob.bin";
        write_file.length = 2048;
        ok &= Require(
            store.ApplyMutation(write_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-unaligned-persistent-commit-blob write file should apply");
        staged_payloads[L"\\replay_unaligned_persistent_commit_blob.bin"] = std::vector<std::byte>(2048, static_cast<std::byte>(0x31));

        store.SetCommitStageHook([](std::string_view stage)
        {
            return stage != "before-checkpoint-switch";
        });

        const auto interrupted_commit = store.CommitPendingMutations();
        ok &= Require(
            interrupted_commit == apfsaccess::rw::MetadataStore::CommitStatus::PersistFailed,
            "Replay-unaligned-persistent-commit-blob setup commit should fail at before-checkpoint-switch stage");
        ok &= Require(
            store.IsRecoveryRequired(),
            "Replay-unaligned-persistent-commit-blob setup should require recovery");
    }

    {
        const auto persistent_state_path = BuildPersistentStatePath(
            replay_unaligned_persistent_commit_blob_context.device_path,
            replay_unaligned_persistent_commit_blob_context.volume_name);
        ok &= Require(
            OverridePersistentStateCommitBlobMetadata(
                persistent_state_path,
                /*persisted_last_commit_xid=*/kInitialCheckpointXid + 1,
                /*persisted_commit_blob_address=*/static_cast<std::uint64_t>(kBlockSize * 2),
                /*persisted_commit_blob_bytes=*/static_cast<std::uint64_t>(kBlockSize - 1)),
            "Replay-unaligned-persistent-commit-blob should inject non-aligned persistent commit-blob bytes");
    }

    {
        apfsaccess::rw::MetadataStore remounted(replay_unaligned_persistent_commit_blob_context);
        ok &= Require(remounted.LoadContainerSuperblocks(), "Replay-unaligned-persistent-commit-blob remount LoadContainerSuperblocks should succeed");
        ok &= Require(remounted.PrepareNativeWritePath(), "Replay-unaligned-persistent-commit-blob remount PrepareNativeWritePath should succeed");
        ok &= Require(remounted.IsRecoveryRequired(), "Replay-unaligned-persistent-commit-blob remount should require recovery");
        ok &= Require(
            remounted.RecoveryReason() == L"PersistentStateAheadOfSuperblock",
            "Replay-unaligned-persistent-commit-blob remount should detect persistent state ahead of superblock");
        ok &= Require(
            remounted.ReplayOrRecover(),
            "Replay-unaligned-persistent-commit-blob remount should ignore non-aligned persistent commit-blob metadata and recover");
        ok &= Require(!remounted.IsRecoveryRequired(), "Replay-unaligned-persistent-commit-blob remount should clear recovery after replay");
        ok &= Require(remounted.IsCommitPathReady(), "Replay-unaligned-persistent-commit-blob remount should restore commit path readiness");
        ok &= Require(
            remounted.CheckpointXid().value_or(0) == (kInitialCheckpointXid + 1),
            "Replay-unaligned-persistent-commit-blob remount should publish recovered checkpoint xid");
    }

    const auto replay_tied_xid_prefer_checkpoint_image_path = run_root / "container_replay_tied_xid_prefer_checkpoint.apfs.img";
    if (!CreateSyntheticContainer(replay_tied_xid_prefer_checkpoint_image_path))
    {
        std::cerr << "[FAIL] unable to create synthetic APFS container image for replay-tied-xid-prefer-checkpoint scenario" << std::endl;
        return 1;
    }

    apfsaccess::rw::MetadataStore::VolumeContext replay_tied_xid_prefer_checkpoint_context
    {
        replay_tied_xid_prefer_checkpoint_image_path.wstring(),
        L"ReplayTiedXidPreferCheckpoint",
    };
    replay_tied_xid_prefer_checkpoint_context.crash_replay_mode = L"ReplayIfSafe";
    {
        apfsaccess::rw::MetadataStore store(replay_tied_xid_prefer_checkpoint_context);
        ok &= Require(store.LoadContainerSuperblocks(), "Replay-tied-xid-prefer-checkpoint LoadContainerSuperblocks should succeed");
        ok &= Require(store.LoadObjectMap(), "Replay-tied-xid-prefer-checkpoint LoadObjectMap should succeed");
        ok &= Require(store.LoadSpacemanState(), "Replay-tied-xid-prefer-checkpoint LoadSpacemanState should succeed");
        ok &= Require(store.PrepareNativeWritePath(), "Replay-tied-xid-prefer-checkpoint PrepareNativeWritePath should succeed");
        std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
        store.SetFilePayloadProvider(
            [&staged_payloads](const std::wstring& path, std::uint64_t logical_size) -> std::optional<std::vector<std::byte>>
            {
                auto pending = staged_payloads.find(path);
                if (pending == staged_payloads.end())
                {
                    return std::nullopt;
                }

                if (logical_size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
                {
                    return std::nullopt;
                }

                auto payload = pending->second;
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
        create_file.path = L"\\replay_tied_xid_prefer_checkpoint.bin";
        ok &= Require(
            store.ApplyMutation(create_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-tied-xid-prefer-checkpoint create file should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_file{};
        write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_file.path = L"\\replay_tied_xid_prefer_checkpoint.bin";
        write_file.length = 2048;
        ok &= Require(
            store.ApplyMutation(write_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-tied-xid-prefer-checkpoint write file should apply");
        staged_payloads[L"\\replay_tied_xid_prefer_checkpoint.bin"] = std::vector<std::byte>(2048, static_cast<std::byte>(0x7F));

        store.SetCommitStageHook([](std::string_view stage)
        {
            return stage != "before-checkpoint-switch";
        });

        const auto interrupted_commit = store.CommitPendingMutations();
        ok &= Require(
            interrupted_commit == apfsaccess::rw::MetadataStore::CommitStatus::PersistFailed,
            "Replay-tied-xid-prefer-checkpoint setup commit should fail at before-checkpoint-switch stage");
        ok &= Require(
            store.IsRecoveryRequired(),
            "Replay-tied-xid-prefer-checkpoint setup should require recovery");
    }

    {
        const auto persistent_state_path = BuildPersistentStatePath(
            replay_tied_xid_prefer_checkpoint_context.device_path,
            replay_tied_xid_prefer_checkpoint_context.volume_name);
        ok &= Require(
            OverridePersistentStateCommitBlobMetadata(
                persistent_state_path,
                /*persisted_last_commit_xid=*/kInitialCheckpointXid + 1,
                /*persisted_commit_blob_address=*/static_cast<std::uint64_t>(900ull * static_cast<std::uint64_t>(kBlockSize)),
                /*persisted_commit_blob_bytes=*/static_cast<std::uint64_t>(kBlockSize)),
            "Replay-tied-xid-prefer-checkpoint should inject same-xid persistent commit-blob metadata with mismatched location");
    }

    {
        apfsaccess::rw::MetadataStore remounted(replay_tied_xid_prefer_checkpoint_context);
        ok &= Require(remounted.LoadContainerSuperblocks(), "Replay-tied-xid-prefer-checkpoint remount LoadContainerSuperblocks should succeed");
        ok &= Require(remounted.PrepareNativeWritePath(), "Replay-tied-xid-prefer-checkpoint remount PrepareNativeWritePath should succeed");
        ok &= Require(remounted.IsRecoveryRequired(), "Replay-tied-xid-prefer-checkpoint remount should require recovery");
        ok &= Require(
            remounted.RecoveryReason() == L"PersistentStateAheadOfSuperblock",
            "Replay-tied-xid-prefer-checkpoint remount should detect persistent state ahead of superblock");
        ok &= Require(
            remounted.ReplayOrRecover(),
            "Replay-tied-xid-prefer-checkpoint remount should prefer replay-checkpoint commit metadata on xid ties");
        ok &= Require(!remounted.IsRecoveryRequired(), "Replay-tied-xid-prefer-checkpoint remount should clear recovery after replay");
        ok &= Require(remounted.IsCommitPathReady(), "Replay-tied-xid-prefer-checkpoint remount should restore commit path readiness");
        ok &= Require(
            remounted.CheckpointXid().value_or(0) == (kInitialCheckpointXid + 1),
            "Replay-tied-xid-prefer-checkpoint remount should publish recovered checkpoint xid");
    }

    const auto replay_invalid_checkpoint_commit_blob_image_path = run_root / "container_replay_invalid_checkpoint_commit_blob.apfs.img";
    if (!CreateSyntheticContainer(replay_invalid_checkpoint_commit_blob_image_path))
    {
        std::cerr << "[FAIL] unable to create synthetic APFS container image for replay-invalid-checkpoint-commit-blob scenario" << std::endl;
        return 1;
    }

    apfsaccess::rw::MetadataStore::VolumeContext replay_invalid_checkpoint_commit_blob_context
    {
        replay_invalid_checkpoint_commit_blob_image_path.wstring(),
        L"ReplayInvalidCheckpointCommitBlob",
    };
    replay_invalid_checkpoint_commit_blob_context.crash_replay_mode = L"ReplayIfSafe";
    {
        apfsaccess::rw::MetadataStore store(replay_invalid_checkpoint_commit_blob_context);
        ok &= Require(store.LoadContainerSuperblocks(), "Replay-invalid-checkpoint-commit-blob LoadContainerSuperblocks should succeed");
        ok &= Require(store.LoadObjectMap(), "Replay-invalid-checkpoint-commit-blob LoadObjectMap should succeed");
        ok &= Require(store.LoadSpacemanState(), "Replay-invalid-checkpoint-commit-blob LoadSpacemanState should succeed");
        ok &= Require(store.PrepareNativeWritePath(), "Replay-invalid-checkpoint-commit-blob PrepareNativeWritePath should succeed");
        std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
        store.SetFilePayloadProvider(
            [&staged_payloads](const std::wstring& path, std::uint64_t logical_size) -> std::optional<std::vector<std::byte>>
            {
                auto pending = staged_payloads.find(path);
                if (pending == staged_payloads.end())
                {
                    return std::nullopt;
                }

                if (logical_size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
                {
                    return std::nullopt;
                }

                auto payload = pending->second;
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
        create_file.path = L"\\replay_invalid_checkpoint_commit_blob.bin";
        ok &= Require(
            store.ApplyMutation(create_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-invalid-checkpoint-commit-blob create file should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_file{};
        write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_file.path = L"\\replay_invalid_checkpoint_commit_blob.bin";
        write_file.length = 2048;
        ok &= Require(
            store.ApplyMutation(write_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-invalid-checkpoint-commit-blob write file should apply");
        staged_payloads[L"\\replay_invalid_checkpoint_commit_blob.bin"] = std::vector<std::byte>(2048, static_cast<std::byte>(0x61));

        store.SetCommitStageHook([](std::string_view stage)
        {
            return stage != "before-checkpoint-switch";
        });

        const auto interrupted_commit = store.CommitPendingMutations();
        ok &= Require(
            interrupted_commit == apfsaccess::rw::MetadataStore::CommitStatus::PersistFailed,
            "Replay-invalid-checkpoint-commit-blob setup commit should fail at before-checkpoint-switch stage");
        ok &= Require(
            store.IsRecoveryRequired(),
            "Replay-invalid-checkpoint-commit-blob setup should require recovery");
    }

    std::size_t corrupted_replay_commit_blob_address_blocks = 0;
    ok &= Require(
        CorruptReplayCheckpointCommitBlobAddress(
            replay_invalid_checkpoint_commit_blob_image_path,
            static_cast<std::uint64_t>(900ull * static_cast<std::uint64_t>(kBlockSize)),
            corrupted_replay_commit_blob_address_blocks),
        "Replay-invalid-checkpoint-commit-blob should corrupt replay-checkpoint commit-blob pointers");
    ok &= Require(
        corrupted_replay_commit_blob_address_blocks >= 1,
        "Replay-invalid-checkpoint-commit-blob should corrupt at least one replay checkpoint block");

    {
        apfsaccess::rw::MetadataStore remounted(replay_invalid_checkpoint_commit_blob_context);
        ok &= Require(remounted.LoadContainerSuperblocks(), "Replay-invalid-checkpoint-commit-blob remount LoadContainerSuperblocks should succeed");
        ok &= Require(remounted.PrepareNativeWritePath(), "Replay-invalid-checkpoint-commit-blob remount PrepareNativeWritePath should succeed");
        ok &= Require(remounted.IsRecoveryRequired(), "Replay-invalid-checkpoint-commit-blob remount should require recovery");
        ok &= Require(
            remounted.RecoveryReason() == L"PersistentStateAheadOfSuperblock",
            "Replay-invalid-checkpoint-commit-blob remount should detect persistent state ahead of superblock");
        ok &= Require(
            remounted.ReplayOrRecover(),
            "Replay-invalid-checkpoint-commit-blob remount should ignore replay-checkpoint entries whose commit blobs fail candidate validation");
        ok &= Require(!remounted.IsRecoveryRequired(), "Replay-invalid-checkpoint-commit-blob remount should clear recovery after replay");
        ok &= Require(remounted.IsCommitPathReady(), "Replay-invalid-checkpoint-commit-blob remount should restore commit path readiness");
        ok &= Require(
            remounted.CheckpointXid().value_or(0) == (kInitialCheckpointXid + 1),
            "Replay-invalid-checkpoint-commit-blob remount should keep recovered checkpoint xid");
    }

    const auto replay_unaligned_checkpoint_commit_blob_image_path = run_root / "container_replay_unaligned_checkpoint_commit_blob.apfs.img";
    if (!CreateSyntheticContainer(replay_unaligned_checkpoint_commit_blob_image_path))
    {
        std::cerr << "[FAIL] unable to create synthetic APFS container image for replay-unaligned-checkpoint-commit-blob scenario" << std::endl;
        return 1;
    }

    apfsaccess::rw::MetadataStore::VolumeContext replay_unaligned_checkpoint_commit_blob_context
    {
        replay_unaligned_checkpoint_commit_blob_image_path.wstring(),
        L"ReplayUnalignedCheckpointCommitBlob",
    };
    replay_unaligned_checkpoint_commit_blob_context.crash_replay_mode = L"ReplayIfSafe";
    {
        apfsaccess::rw::MetadataStore store(replay_unaligned_checkpoint_commit_blob_context);
        ok &= Require(store.LoadContainerSuperblocks(), "Replay-unaligned-checkpoint-commit-blob LoadContainerSuperblocks should succeed");
        ok &= Require(store.LoadObjectMap(), "Replay-unaligned-checkpoint-commit-blob LoadObjectMap should succeed");
        ok &= Require(store.LoadSpacemanState(), "Replay-unaligned-checkpoint-commit-blob LoadSpacemanState should succeed");
        ok &= Require(store.PrepareNativeWritePath(), "Replay-unaligned-checkpoint-commit-blob PrepareNativeWritePath should succeed");
        std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
        store.SetFilePayloadProvider(
            [&staged_payloads](const std::wstring& path, std::uint64_t logical_size) -> std::optional<std::vector<std::byte>>
            {
                auto pending = staged_payloads.find(path);
                if (pending == staged_payloads.end())
                {
                    return std::nullopt;
                }

                if (logical_size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
                {
                    return std::nullopt;
                }

                auto payload = pending->second;
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
        create_file.path = L"\\replay_unaligned_checkpoint_commit_blob.bin";
        ok &= Require(
            store.ApplyMutation(create_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-unaligned-checkpoint-commit-blob create file should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_file{};
        write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_file.path = L"\\replay_unaligned_checkpoint_commit_blob.bin";
        write_file.length = 2048;
        ok &= Require(
            store.ApplyMutation(write_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-unaligned-checkpoint-commit-blob write file should apply");
        staged_payloads[L"\\replay_unaligned_checkpoint_commit_blob.bin"] = std::vector<std::byte>(2048, static_cast<std::byte>(0x35));

        store.SetCommitStageHook([](std::string_view stage)
        {
            return stage != "before-checkpoint-switch";
        });

        const auto interrupted_commit = store.CommitPendingMutations();
        ok &= Require(
            interrupted_commit == apfsaccess::rw::MetadataStore::CommitStatus::PersistFailed,
            "Replay-unaligned-checkpoint-commit-blob setup commit should fail at before-checkpoint-switch stage");
        ok &= Require(
            store.IsRecoveryRequired(),
            "Replay-unaligned-checkpoint-commit-blob setup should require recovery");
    }

    std::size_t corrupted_unaligned_replay_commit_blob_bytes_blocks = 0;
    ok &= Require(
        CorruptReplayCheckpointCommitBlobBytes(
            replay_unaligned_checkpoint_commit_blob_image_path,
            static_cast<std::uint64_t>(kBlockSize - 1),
            corrupted_unaligned_replay_commit_blob_bytes_blocks),
        "Replay-unaligned-checkpoint-commit-blob should corrupt replay-checkpoint commit-blob byte size");
    ok &= Require(
        corrupted_unaligned_replay_commit_blob_bytes_blocks >= 1,
        "Replay-unaligned-checkpoint-commit-blob should corrupt at least one replay checkpoint block");

    {
        apfsaccess::rw::MetadataStore remounted(replay_unaligned_checkpoint_commit_blob_context);
        ok &= Require(remounted.LoadContainerSuperblocks(), "Replay-unaligned-checkpoint-commit-blob remount LoadContainerSuperblocks should succeed");
        ok &= Require(remounted.PrepareNativeWritePath(), "Replay-unaligned-checkpoint-commit-blob remount PrepareNativeWritePath should succeed");
        ok &= Require(remounted.IsRecoveryRequired(), "Replay-unaligned-checkpoint-commit-blob remount should require recovery");
        ok &= Require(
            remounted.RecoveryReason() == L"PersistentStateAheadOfSuperblock",
            "Replay-unaligned-checkpoint-commit-blob remount should detect persistent state ahead of superblock");
        ok &= Require(
            remounted.ReplayOrRecover(),
            "Replay-unaligned-checkpoint-commit-blob remount should ignore replay-checkpoint entries with non-aligned commit-blob size");
        ok &= Require(!remounted.IsRecoveryRequired(), "Replay-unaligned-checkpoint-commit-blob remount should clear recovery after replay");
        ok &= Require(remounted.IsCommitPathReady(), "Replay-unaligned-checkpoint-commit-blob remount should restore commit path readiness");
        ok &= Require(
            remounted.CheckpointXid().value_or(0) == (kInitialCheckpointXid + 1),
            "Replay-unaligned-checkpoint-commit-blob remount should keep recovered checkpoint xid");
    }

    const auto replay_semantic_invalid_checkpoint_commit_blob_image_path =
        run_root / "container_replay_semantic_invalid_checkpoint_commit_blob.apfs.img";
    if (!CreateSyntheticContainer(replay_semantic_invalid_checkpoint_commit_blob_image_path))
    {
        std::cerr
            << "[FAIL] unable to create synthetic APFS container image for replay-semantic-invalid-checkpoint-commit-blob scenario"
            << std::endl;
        return 1;
    }

    apfsaccess::rw::MetadataStore::VolumeContext replay_semantic_invalid_checkpoint_commit_blob_context
    {
        replay_semantic_invalid_checkpoint_commit_blob_image_path.wstring(),
        L"ReplaySemanticInvalidCheckpointCommitBlob",
    };
    replay_semantic_invalid_checkpoint_commit_blob_context.crash_replay_mode = L"ReplayIfSafe";
    {
        apfsaccess::rw::MetadataStore store(replay_semantic_invalid_checkpoint_commit_blob_context);
        ok &= Require(
            store.LoadContainerSuperblocks(),
            "Replay-semantic-invalid-checkpoint-commit-blob LoadContainerSuperblocks should succeed");
        ok &= Require(
            store.LoadObjectMap(),
            "Replay-semantic-invalid-checkpoint-commit-blob LoadObjectMap should succeed");
        ok &= Require(
            store.LoadSpacemanState(),
            "Replay-semantic-invalid-checkpoint-commit-blob LoadSpacemanState should succeed");
        ok &= Require(
            store.PrepareNativeWritePath(),
            "Replay-semantic-invalid-checkpoint-commit-blob PrepareNativeWritePath should succeed");
        std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
        store.SetFilePayloadProvider(
            [&staged_payloads](const std::wstring& path, std::uint64_t logical_size) -> std::optional<std::vector<std::byte>>
            {
                auto pending = staged_payloads.find(path);
                if (pending == staged_payloads.end())
                {
                    return std::nullopt;
                }

                if (logical_size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
                {
                    return std::nullopt;
                }

                auto payload = pending->second;
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

        apfsaccess::rw::MetadataStore::MutationRequest create_first_file{};
        create_first_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
        create_first_file.path = L"\\replay_semantic_invalid_checkpoint_commit_blob_a.bin";
        ok &= Require(
            store.ApplyMutation(create_first_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-semantic-invalid-checkpoint-commit-blob baseline create file should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_first_file{};
        write_first_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_first_file.path = L"\\replay_semantic_invalid_checkpoint_commit_blob_a.bin";
        write_first_file.length = 2048;
        ok &= Require(
            store.ApplyMutation(write_first_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-semantic-invalid-checkpoint-commit-blob baseline write file should apply");
        staged_payloads[L"\\replay_semantic_invalid_checkpoint_commit_blob_a.bin"] =
            std::vector<std::byte>(2048, static_cast<std::byte>(0x58));

        const auto baseline_commit = store.CommitPendingMutations();
        ok &= Require(
            baseline_commit == apfsaccess::rw::MetadataStore::CommitStatus::Committed,
            "Replay-semantic-invalid-checkpoint-commit-blob baseline commit should succeed");
        ok &= Require(
            !store.IsRecoveryRequired(),
            "Replay-semantic-invalid-checkpoint-commit-blob baseline commit should not require recovery");

        apfsaccess::rw::MetadataStore::MutationRequest create_second_file{};
        create_second_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
        create_second_file.path = L"\\replay_semantic_invalid_checkpoint_commit_blob_b.bin";
        ok &= Require(
            store.ApplyMutation(create_second_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-semantic-invalid-checkpoint-commit-blob staged create file should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_second_file{};
        write_second_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_second_file.path = L"\\replay_semantic_invalid_checkpoint_commit_blob_b.bin";
        write_second_file.length = 3072;
        ok &= Require(
            store.ApplyMutation(write_second_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-semantic-invalid-checkpoint-commit-blob staged write file should apply");
        staged_payloads[L"\\replay_semantic_invalid_checkpoint_commit_blob_b.bin"] =
            std::vector<std::byte>(3072, static_cast<std::byte>(0x67));

        apfsaccess::rw::MetadataStore::MutationRequest create_third_file{};
        create_third_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
        create_third_file.path = L"\\replay_semantic_invalid_checkpoint_commit_blob_c.bin";
        ok &= Require(
            store.ApplyMutation(create_third_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-semantic-invalid-checkpoint-commit-blob staged second create file should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_third_file{};
        write_third_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_third_file.path = L"\\replay_semantic_invalid_checkpoint_commit_blob_c.bin";
        write_third_file.length = 1536;
        ok &= Require(
            store.ApplyMutation(write_third_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-semantic-invalid-checkpoint-commit-blob staged second write file should apply");
        staged_payloads[L"\\replay_semantic_invalid_checkpoint_commit_blob_c.bin"] =
            std::vector<std::byte>(1536, static_cast<std::byte>(0x6B));

        store.SetCommitStageHook([](std::string_view stage)
        {
            return stage != "before-state-persist";
        });

        const auto interrupted_commit = store.CommitPendingMutations();
        ok &= Require(
            interrupted_commit == apfsaccess::rw::MetadataStore::CommitStatus::PersistFailed,
            "Replay-semantic-invalid-checkpoint-commit-blob staged commit should fail at before-state-persist stage");
    }

    std::size_t corrupted_semantic_replay_checkpoint_blocks = 0;
    ok &= Require(
        CorruptHighestReplayCheckpointReferencedCommitBlobDuplicateObjectMapIdWithValidChecksum(
            replay_semantic_invalid_checkpoint_commit_blob_image_path,
            corrupted_semantic_replay_checkpoint_blocks),
        "Replay-semantic-invalid-checkpoint-commit-blob should corrupt highest replay-checkpoint-referenced commit blob");
    ok &= Require(
        corrupted_semantic_replay_checkpoint_blocks >= 1,
        "Replay-semantic-invalid-checkpoint-commit-blob should corrupt at least one replay-checkpoint-referenced commit blob");

    {
        apfsaccess::rw::MetadataStore remounted(replay_semantic_invalid_checkpoint_commit_blob_context);
        ok &= Require(
            remounted.LoadContainerSuperblocks(),
            "Replay-semantic-invalid-checkpoint-commit-blob remount LoadContainerSuperblocks should succeed");
        ok &= Require(
            remounted.PrepareNativeWritePath(),
            "Replay-semantic-invalid-checkpoint-commit-blob remount PrepareNativeWritePath should succeed");
        ok &= Require(
            !remounted.IsRecoveryRequired(),
            "Replay-semantic-invalid-checkpoint-commit-blob remount should ignore semantically invalid replay candidates and remain at persistent checkpoint state");
        ok &= Require(
            remounted.ReplayOrRecover(),
            "Replay-semantic-invalid-checkpoint-commit-blob remount replay should succeed via persistent metadata");
        ok &= Require(
            !remounted.IsRecoveryRequired(),
            "Replay-semantic-invalid-checkpoint-commit-blob remount should keep recovery cleared");
        ok &= Require(
            remounted.IsCommitPathReady(),
            "Replay-semantic-invalid-checkpoint-commit-blob remount should keep commit path ready");
        ok &= Require(
            remounted.CheckpointXid().value_or(0) == (kInitialCheckpointXid + 1),
            "Replay-semantic-invalid-checkpoint-commit-blob remount should keep baseline checkpoint xid");
    }

    const auto replay_invalid_xid_window_image_path = run_root / "container_replay_invalid_xid_window.apfs.img";
    if (!CreateSyntheticContainer(replay_invalid_xid_window_image_path))
    {
        std::cerr << "[FAIL] unable to create synthetic APFS container image for replay-invalid-xid-window scenario" << std::endl;
        return 1;
    }

    apfsaccess::rw::MetadataStore::VolumeContext replay_invalid_xid_window_context
    {
        replay_invalid_xid_window_image_path.wstring(),
        L"ReplayInvalidXidWindow",
    };
    replay_invalid_xid_window_context.crash_replay_mode = L"ReplayIfSafe";
    {
        apfsaccess::rw::MetadataStore store(replay_invalid_xid_window_context);
        ok &= Require(store.LoadContainerSuperblocks(), "Replay-invalid-xid-window LoadContainerSuperblocks should succeed");
        ok &= Require(store.LoadObjectMap(), "Replay-invalid-xid-window LoadObjectMap should succeed");
        ok &= Require(store.LoadSpacemanState(), "Replay-invalid-xid-window LoadSpacemanState should succeed");
        ok &= Require(store.PrepareNativeWritePath(), "Replay-invalid-xid-window PrepareNativeWritePath should succeed");
        std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
        store.SetFilePayloadProvider(
            [&staged_payloads](const std::wstring& path, std::uint64_t logical_size) -> std::optional<std::vector<std::byte>>
            {
                auto pending = staged_payloads.find(path);
                if (pending == staged_payloads.end())
                {
                    return std::nullopt;
                }

                if (logical_size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
                {
                    return std::nullopt;
                }

                auto payload = pending->second;
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
        create_file.path = L"\\replay_invalid_xid_window.bin";
        ok &= Require(
            store.ApplyMutation(create_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-invalid-xid-window create file should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_file{};
        write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_file.path = L"\\replay_invalid_xid_window.bin";
        write_file.length = 2048;
        ok &= Require(
            store.ApplyMutation(write_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-invalid-xid-window write file should apply");
        staged_payloads[L"\\replay_invalid_xid_window.bin"] = std::vector<std::byte>(2048, static_cast<std::byte>(0x7A));

        store.SetCommitStageHook([](std::string_view stage)
        {
            return stage != "before-checkpoint-switch";
        });

        const auto interrupted_commit = store.CommitPendingMutations();
        ok &= Require(
            interrupted_commit == apfsaccess::rw::MetadataStore::CommitStatus::PersistFailed,
            "Replay-invalid-xid-window setup commit should fail at before-checkpoint-switch stage");
        ok &= Require(
            store.IsRecoveryRequired(),
            "Replay-invalid-xid-window setup should require recovery");
    }

    const auto replay_invalid_xid_window_non_fixture_sidecar_fallback_path =
        run_root / "container_replay_invalid_xid_window_non_fixture_sidecar_fallback.bin";
    ec.clear();
    std::filesystem::copy_file(
        replay_invalid_xid_window_image_path,
        replay_invalid_xid_window_non_fixture_sidecar_fallback_path,
        std::filesystem::copy_options::overwrite_existing,
        ec);
    ok &= Require(
        !ec,
        "Replay-invalid-xid-window non-fixture sidecar-fallback scenario should copy fixture image");

    apfsaccess::rw::MetadataStore::VolumeContext replay_invalid_xid_window_non_fixture_sidecar_fallback_context
    {
        replay_invalid_xid_window_non_fixture_sidecar_fallback_path.wstring(),
        L"ReplayInvalidXidWindowNonFixtureSidecarFallback",
    };
    replay_invalid_xid_window_non_fixture_sidecar_fallback_context.crash_replay_mode = L"ReplayIfSafe";

    {
        const auto fixture_persistent_state_path = BuildPersistentStatePath(
            replay_invalid_xid_window_context.device_path,
            replay_invalid_xid_window_context.volume_name);
        const auto non_fixture_persistent_state_path = BuildPersistentStatePath(
            replay_invalid_xid_window_non_fixture_sidecar_fallback_context.device_path,
            replay_invalid_xid_window_non_fixture_sidecar_fallback_context.volume_name);
        ok &= Require(
            !fixture_persistent_state_path.empty() && !non_fixture_persistent_state_path.empty(),
            "Replay-invalid-xid-window non-fixture sidecar-fallback scenario should resolve persistent-state paths");
        if (!fixture_persistent_state_path.empty() && !non_fixture_persistent_state_path.empty())
        {
            std::filesystem::create_directories(non_fixture_persistent_state_path.parent_path(), ec);
            ec.clear();
            std::filesystem::copy_file(
                fixture_persistent_state_path,
                non_fixture_persistent_state_path,
                std::filesystem::copy_options::overwrite_existing,
                ec);
            ok &= Require(
                !ec,
                "Replay-invalid-xid-window non-fixture sidecar-fallback scenario should copy baseline pending sidecar metadata");
        }
    }

    std::size_t corrupted_sidecar_fallback_replay_blocks = 0;
    ok &= Require(
        CorruptReplayCheckpointXidWindow(
            replay_invalid_xid_window_non_fixture_sidecar_fallback_path,
            /*mutated_source_xid=*/kInitialCheckpointXid + 5,
            /*mutated_target_xid=*/kInitialCheckpointXid + 6,
            corrupted_sidecar_fallback_replay_blocks),
        "Replay-invalid-xid-window non-fixture sidecar-fallback scenario should corrupt replay checkpoint xid window");
    ok &= Require(
        corrupted_sidecar_fallback_replay_blocks >= 1,
        "Replay-invalid-xid-window non-fixture sidecar-fallback scenario should corrupt at least one replay checkpoint block");

    {
        apfsaccess::rw::MetadataStore remounted(replay_invalid_xid_window_non_fixture_sidecar_fallback_context);
        ok &= Require(remounted.LoadContainerSuperblocks(), "Replay-invalid-xid-window non-fixture sidecar-fallback remount LoadContainerSuperblocks should succeed");
        ok &= Require(remounted.PrepareNativeWritePath(), "Replay-invalid-xid-window non-fixture sidecar-fallback remount PrepareNativeWritePath should succeed");
        ok &= Require(
            !remounted.LastReplayCheckpointPendingWindow(),
            "Replay-invalid-xid-window non-fixture sidecar-fallback remount should treat replay metadata as outside pending window");
        ok &= Require(
            !remounted.IsRecoveryRequired(),
            "Replay-invalid-xid-window non-fixture sidecar-fallback remount should ignore sidecar drift when replay metadata is non-pending");
        ok &= Require(
            remounted.ReplayOrRecover(),
            "Replay-invalid-xid-window non-fixture sidecar-fallback remount should complete replay evaluation without fail-closed downgrade");
        ok &= Require(!remounted.IsRecoveryRequired(), "Replay-invalid-xid-window non-fixture sidecar-fallback remount should remain recovery-clear");
        ok &= Require(remounted.IsCommitPathReady(), "Replay-invalid-xid-window non-fixture sidecar-fallback remount should keep commit path ready");
    }

    {
        const auto persistent_state_path = BuildPersistentStatePath(
            replay_invalid_xid_window_context.device_path,
            replay_invalid_xid_window_context.volume_name);
        ok &= Require(
            OverridePersistentStateCommitBlobMetadata(
                persistent_state_path,
                /*persisted_last_commit_xid=*/kInitialCheckpointXid + 2,
                /*persisted_commit_blob_address=*/static_cast<std::uint64_t>(kBlockSize * 2),
                /*persisted_commit_blob_bytes=*/static_cast<std::uint64_t>(kBlockSize)),
            "Replay-invalid-xid-window should inject out-of-window persistent xid metadata");
    }

    const auto replay_invalid_xid_window_non_fixture_path = run_root / "container_replay_invalid_xid_window_non_fixture.bin";
    ec.clear();
    std::filesystem::copy_file(
        replay_invalid_xid_window_image_path,
        replay_invalid_xid_window_non_fixture_path,
        std::filesystem::copy_options::overwrite_existing,
        ec);
    ok &= Require(
        !ec,
        "Replay-invalid-xid-window non-fixture scenario should copy fixture image to non-fixture path");

    apfsaccess::rw::MetadataStore::VolumeContext replay_invalid_xid_window_non_fixture_context
    {
        replay_invalid_xid_window_non_fixture_path.wstring(),
        L"ReplayInvalidXidWindowNonFixture",
    };
    replay_invalid_xid_window_non_fixture_context.crash_replay_mode = L"ReplayIfSafe";

    {
        const auto fixture_persistent_state_path = BuildPersistentStatePath(
            replay_invalid_xid_window_context.device_path,
            replay_invalid_xid_window_context.volume_name);
        const auto non_fixture_persistent_state_path = BuildPersistentStatePath(
            replay_invalid_xid_window_non_fixture_context.device_path,
            replay_invalid_xid_window_non_fixture_context.volume_name);
        ok &= Require(
            !fixture_persistent_state_path.empty() && !non_fixture_persistent_state_path.empty(),
            "Replay-invalid-xid-window non-fixture scenario should resolve persistent-state paths");
        if (!fixture_persistent_state_path.empty() && !non_fixture_persistent_state_path.empty())
        {
            std::filesystem::create_directories(non_fixture_persistent_state_path.parent_path(), ec);
            ec.clear();
            std::filesystem::copy_file(
                fixture_persistent_state_path,
                non_fixture_persistent_state_path,
                std::filesystem::copy_options::overwrite_existing,
                ec);
            ok &= Require(
                !ec,
                "Replay-invalid-xid-window non-fixture scenario should copy stale persistent metadata");
        }
    }

    const auto replay_invalid_xid_window_non_fixture_missing_candidate_path =
        run_root / "container_replay_invalid_xid_window_non_fixture_missing_candidate.bin";
    ec.clear();
    std::filesystem::copy_file(
        replay_invalid_xid_window_image_path,
        replay_invalid_xid_window_non_fixture_missing_candidate_path,
        std::filesystem::copy_options::overwrite_existing,
        ec);
    ok &= Require(
        !ec,
        "Replay-invalid-xid-window non-fixture missing-candidate scenario should copy fixture image");

    apfsaccess::rw::MetadataStore::VolumeContext replay_invalid_xid_window_non_fixture_missing_candidate_context
    {
        replay_invalid_xid_window_non_fixture_missing_candidate_path.wstring(),
        L"ReplayInvalidXidWindowNonFixtureMissingCandidate",
    };
    replay_invalid_xid_window_non_fixture_missing_candidate_context.crash_replay_mode = L"ReplayIfSafe";

    {
        const auto fixture_persistent_state_path = BuildPersistentStatePath(
            replay_invalid_xid_window_context.device_path,
            replay_invalid_xid_window_context.volume_name);
        const auto non_fixture_persistent_state_path = BuildPersistentStatePath(
            replay_invalid_xid_window_non_fixture_missing_candidate_context.device_path,
            replay_invalid_xid_window_non_fixture_missing_candidate_context.volume_name);
        ok &= Require(
            !fixture_persistent_state_path.empty() && !non_fixture_persistent_state_path.empty(),
            "Replay-invalid-xid-window non-fixture missing-candidate scenario should resolve persistent-state paths");
        if (!fixture_persistent_state_path.empty() && !non_fixture_persistent_state_path.empty())
        {
            std::filesystem::create_directories(non_fixture_persistent_state_path.parent_path(), ec);
            ec.clear();
            std::filesystem::copy_file(
                fixture_persistent_state_path,
                non_fixture_persistent_state_path,
                std::filesystem::copy_options::overwrite_existing,
                ec);
            ok &= Require(
                !ec,
                "Replay-invalid-xid-window non-fixture missing-candidate scenario should copy stale persistent metadata");
        }
    }

    std::size_t corrupted_missing_candidate_replay_blocks = 0;
    ok &= Require(
        CorruptReplayCheckpointXidWindow(
            replay_invalid_xid_window_non_fixture_missing_candidate_path,
            /*mutated_source_xid=*/kInitialCheckpointXid + 5,
            /*mutated_target_xid=*/kInitialCheckpointXid + 6,
            corrupted_missing_candidate_replay_blocks),
        "Replay-invalid-xid-window non-fixture missing-candidate scenario should corrupt replay checkpoint xid window");
    ok &= Require(
        corrupted_missing_candidate_replay_blocks >= 1,
        "Replay-invalid-xid-window non-fixture missing-candidate scenario should corrupt at least one replay checkpoint block");

    {
        apfsaccess::rw::MetadataStore remounted(replay_invalid_xid_window_non_fixture_missing_candidate_context);
        ok &= Require(remounted.LoadContainerSuperblocks(), "Replay-invalid-xid-window non-fixture missing-candidate remount LoadContainerSuperblocks should succeed");
        ok &= Require(remounted.PrepareNativeWritePath(), "Replay-invalid-xid-window non-fixture missing-candidate remount PrepareNativeWritePath should succeed");
        ok &= Require(
            !remounted.LastReplayCheckpointPendingWindow(),
            "Replay-invalid-xid-window non-fixture missing-candidate remount should not expose a pending replay window");
        ok &= Require(
            !remounted.IsRecoveryRequired(),
            "Replay-invalid-xid-window non-fixture missing-candidate remount should not force recovery when no pending replay candidate exists");
        ok &= Require(
            remounted.ReplayOrRecover(),
            "Replay-invalid-xid-window non-fixture missing-candidate remount should complete replay evaluation without fail-closed downgrade");
        ok &= Require(!remounted.IsRecoveryRequired(), "Replay-invalid-xid-window non-fixture missing-candidate remount should remain recovery-clear");
        ok &= Require(remounted.IsCommitPathReady(), "Replay-invalid-xid-window non-fixture missing-candidate remount should keep commit path ready");
    }

    {
        apfsaccess::rw::MetadataStore remounted(replay_invalid_xid_window_non_fixture_context);
        ok &= Require(remounted.LoadContainerSuperblocks(), "Replay-invalid-xid-window non-fixture remount LoadContainerSuperblocks should succeed");
        ok &= Require(remounted.PrepareNativeWritePath(), "Replay-invalid-xid-window non-fixture remount PrepareNativeWritePath should succeed");
        ok &= Require(
            !remounted.LastReplayCheckpointPendingWindow(),
            "Replay-invalid-xid-window non-fixture remount should not expose a pending replay window");
        ok &= Require(
            !remounted.IsRecoveryRequired(),
            "Replay-invalid-xid-window non-fixture remount should ignore non-pending metadata without forcing recovery");
        ok &= Require(
            remounted.ReplayOrRecover(),
            "Replay-invalid-xid-window non-fixture remount should complete replay evaluation without fail-closed downgrade");
        ok &= Require(!remounted.IsRecoveryRequired(), "Replay-invalid-xid-window non-fixture remount should remain recovery-clear");
        ok &= Require(remounted.IsCommitPathReady(), "Replay-invalid-xid-window non-fixture remount should keep commit path ready");
    }

    {
        apfsaccess::rw::MetadataStore remounted(replay_invalid_xid_window_context);
        ok &= Require(remounted.LoadContainerSuperblocks(), "Replay-invalid-xid-window remount LoadContainerSuperblocks should succeed");
        ok &= Require(remounted.PrepareNativeWritePath(), "Replay-invalid-xid-window remount PrepareNativeWritePath should succeed");
        ok &= Require(remounted.IsRecoveryRequired(), "Replay-invalid-xid-window remount should require recovery");
        ok &= Require(
            remounted.RecoveryReason() == L"PersistentStateAheadOfSuperblock",
            "Replay-invalid-xid-window remount should detect persistent state ahead of superblock");
        ok &= Require(
            remounted.ReplayOrRecover(),
            "Replay-invalid-xid-window remount should ignore invalid persistent xid metadata and recover from replay-checkpoint metadata");
        ok &= Require(!remounted.IsRecoveryRequired(), "Replay-invalid-xid-window remount should clear recovery after replay");
        ok &= Require(remounted.IsCommitPathReady(), "Replay-invalid-xid-window remount should restore commit path readiness");
        ok &= Require(
            remounted.CheckpointXid().value_or(0) == (kInitialCheckpointXid + 1),
            "Replay-invalid-xid-window remount should publish recovered checkpoint xid");
    }

    const auto replay_non_fixture_disk_present_sidecar_ignored_image_path =
        run_root / "container_replay_non_fixture_disk_present_sidecar_ignored.apfs.img";
    if (!CreateSyntheticContainer(replay_non_fixture_disk_present_sidecar_ignored_image_path))
    {
        std::cerr << "[FAIL] unable to create synthetic APFS container image for replay-non-fixture-disk-present-sidecar-ignored scenario" << std::endl;
        return 1;
    }

    apfsaccess::rw::MetadataStore::VolumeContext replay_non_fixture_disk_present_sidecar_ignored_context
    {
        replay_non_fixture_disk_present_sidecar_ignored_image_path.wstring(),
        L"ReplayNonFixtureDiskPresentSidecarIgnored",
    };
    replay_non_fixture_disk_present_sidecar_ignored_context.crash_replay_mode = L"ReplayIfSafe";
    {
        apfsaccess::rw::MetadataStore store(replay_non_fixture_disk_present_sidecar_ignored_context);
        ok &= Require(store.LoadContainerSuperblocks(), "Replay-non-fixture-disk-present-sidecar-ignored LoadContainerSuperblocks should succeed");
        ok &= Require(store.LoadObjectMap(), "Replay-non-fixture-disk-present-sidecar-ignored LoadObjectMap should succeed");
        ok &= Require(store.LoadSpacemanState(), "Replay-non-fixture-disk-present-sidecar-ignored LoadSpacemanState should succeed");
        ok &= Require(store.PrepareNativeWritePath(), "Replay-non-fixture-disk-present-sidecar-ignored PrepareNativeWritePath should succeed");
        std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
        store.SetFilePayloadProvider(
            [&staged_payloads](const std::wstring& path, std::uint64_t logical_size) -> std::optional<std::vector<std::byte>>
            {
                auto pending = staged_payloads.find(path);
                if (pending == staged_payloads.end())
                {
                    return std::nullopt;
                }

                if (logical_size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
                {
                    return std::nullopt;
                }

                auto payload = pending->second;
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

        apfsaccess::rw::MetadataStore::MutationRequest create_first_file{};
        create_first_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
        create_first_file.path = L"\\replay_non_fixture_disk_present_sidecar_ignored_a.bin";
        ok &= Require(
            store.ApplyMutation(create_first_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-non-fixture-disk-present-sidecar-ignored first create should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_first_file{};
        write_first_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_first_file.path = L"\\replay_non_fixture_disk_present_sidecar_ignored_a.bin";
        write_first_file.length = 1024;
        ok &= Require(
            store.ApplyMutation(write_first_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-non-fixture-disk-present-sidecar-ignored first write should apply");
        staged_payloads[L"\\replay_non_fixture_disk_present_sidecar_ignored_a.bin"] =
            std::vector<std::byte>(1024, static_cast<std::byte>(0x41));

        const auto first_commit = store.CommitPendingMutations();
        ok &= Require(
            first_commit == apfsaccess::rw::MetadataStore::CommitStatus::Committed,
            "Replay-non-fixture-disk-present-sidecar-ignored first commit should persist");
        ok &= Require(
            !store.IsRecoveryRequired(),
            "Replay-non-fixture-disk-present-sidecar-ignored first commit should not latch recovery");
        ok &= Require(
            store.CheckpointXid().value_or(0) == (kInitialCheckpointXid + 1),
            "Replay-non-fixture-disk-present-sidecar-ignored first commit should advance checkpoint xid");

        apfsaccess::rw::MetadataStore::MutationRequest create_second_file{};
        create_second_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
        create_second_file.path = L"\\replay_non_fixture_disk_present_sidecar_ignored_b.bin";
        ok &= Require(
            store.ApplyMutation(create_second_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-non-fixture-disk-present-sidecar-ignored second create should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_second_file{};
        write_second_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_second_file.path = L"\\replay_non_fixture_disk_present_sidecar_ignored_b.bin";
        write_second_file.length = 2048;
        ok &= Require(
            store.ApplyMutation(write_second_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-non-fixture-disk-present-sidecar-ignored second write should apply");
        staged_payloads[L"\\replay_non_fixture_disk_present_sidecar_ignored_b.bin"] =
            std::vector<std::byte>(2048, static_cast<std::byte>(0x53));

        store.SetCommitStageHook([](std::string_view stage)
        {
            return stage != "before-checkpoint-switch";
        });

        const auto interrupted_commit = store.CommitPendingMutations();
        ok &= Require(
            interrupted_commit == apfsaccess::rw::MetadataStore::CommitStatus::PersistFailed,
            "Replay-non-fixture-disk-present-sidecar-ignored second commit should fail at before-checkpoint-switch");
        ok &= Require(
            store.IsRecoveryRequired(),
            "Replay-non-fixture-disk-present-sidecar-ignored second commit should require recovery");
    }

    const auto replay_non_fixture_disk_present_sidecar_ignored_non_fixture_path =
        run_root / "container_replay_disk_present_sidecar_ignored_physical.bin";
    ec.clear();
    std::filesystem::copy_file(
        replay_non_fixture_disk_present_sidecar_ignored_image_path,
        replay_non_fixture_disk_present_sidecar_ignored_non_fixture_path,
        std::filesystem::copy_options::overwrite_existing,
        ec);
    ok &= Require(
        !ec,
        "Replay-non-fixture-disk-present-sidecar-ignored non-fixture scenario should copy fixture image");

    apfsaccess::rw::MetadataStore::VolumeContext replay_non_fixture_disk_present_sidecar_ignored_non_fixture_context
    {
        replay_non_fixture_disk_present_sidecar_ignored_non_fixture_path.wstring(),
        L"ReplayNonFixtureDiskPresentSidecarIgnoredNonFixture",
    };
    replay_non_fixture_disk_present_sidecar_ignored_non_fixture_context.crash_replay_mode = L"ReplayIfSafe";

    const auto replay_non_fixture_pending_window_latch_path =
        run_root / "container_replay_pending_window_latch_non_fixture.bin";
    ec.clear();
    std::filesystem::copy_file(
        replay_non_fixture_disk_present_sidecar_ignored_image_path,
        replay_non_fixture_pending_window_latch_path,
        std::filesystem::copy_options::overwrite_existing,
        ec);
    ok &= Require(
        !ec,
        "Replay-pending-window-latch non-fixture scenario should copy fixture image");
    std::size_t promoted_pending_replay_commit_blobs = 0;
    ok &= Require(
        PromotePendingReplayCommitBlobMagicToCanonicalV3(
            replay_non_fixture_pending_window_latch_path,
            /*pending_source_xid=*/kInitialCheckpointXid + 1,
            /*pending_target_xid=*/kInitialCheckpointXid + 2,
            promoted_pending_replay_commit_blobs),
        "Replay-pending-window-latch non-fixture scenario should promote pending replay commit blobs to canonical magic");
    ok &= Require(
        promoted_pending_replay_commit_blobs >= 1,
        "Replay-pending-window-latch non-fixture scenario should promote at least one pending replay commit blob");

    apfsaccess::rw::MetadataStore::VolumeContext replay_non_fixture_pending_window_latch_context
    {
        replay_non_fixture_pending_window_latch_path.wstring(),
        L"ReplayNonFixturePendingWindowLatch",
    };
    replay_non_fixture_pending_window_latch_context.crash_replay_mode = L"ReplayIfSafe";
    replay_non_fixture_pending_window_latch_context.integrity_check_on_mount = false;
    {
        const auto persistent_state_path = BuildPersistentStatePath(
            replay_non_fixture_pending_window_latch_context.device_path,
            replay_non_fixture_pending_window_latch_context.volume_name);
        if (!persistent_state_path.empty())
        {
            std::filesystem::remove(persistent_state_path, ec);
        }
    }
    {
        apfsaccess::rw::MetadataStore remounted(replay_non_fixture_pending_window_latch_context);
        ok &= Require(remounted.LoadContainerSuperblocks(), "Replay-pending-window-latch non-fixture remount LoadContainerSuperblocks should succeed");
        ok &= Require(remounted.PrepareNativeWritePath(), "Replay-pending-window-latch non-fixture remount PrepareNativeWritePath should succeed");
        ok &= Require(remounted.IsRecoveryRequired(), "Replay-pending-window-latch non-fixture remount should require recovery");
        ok &= Require(
            remounted.RecoveryReason() == L"ReplayCheckpointPendingWindow",
            "Replay-pending-window-latch non-fixture remount should surface pending-window recovery reason");
        ok &= Require(
            remounted.LastReplayCheckpointCandidatePresent(),
            "Replay-pending-window-latch non-fixture remount should report replay-checkpoint candidate presence");
        ok &= Require(
            remounted.LastReplayCheckpointPendingWindow(),
            "Replay-pending-window-latch non-fixture remount should report pending replay-checkpoint window");
        ok &= Require(
            !remounted.IsCommitPathReady(),
            "Replay-pending-window-latch non-fixture remount should keep commit path blocked before replay");
        ok &= Require(
            remounted.ReplayOrRecover(),
            "Replay-pending-window-latch non-fixture remount should replay successfully");
        ok &= Require(!remounted.IsRecoveryRequired(), "Replay-pending-window-latch non-fixture remount should clear recovery after replay");
        ok &= Require(remounted.IsCommitPathReady(), "Replay-pending-window-latch non-fixture remount should restore commit path readiness");
        ok &= Require(
            remounted.CheckpointXid().value_or(0) == (kInitialCheckpointXid + 2),
            "Replay-pending-window-latch non-fixture remount should publish replayed checkpoint xid");
        ok &= Require(
            remounted.LookupCommittedInodeByPath(L"\\replay_non_fixture_disk_present_sidecar_ignored_a.bin").has_value(),
            "Replay-pending-window-latch non-fixture remount should preserve first committed file");
        ok &= Require(
            remounted.LookupCommittedInodeByPath(L"\\replay_non_fixture_disk_present_sidecar_ignored_b.bin").has_value(),
            "Replay-pending-window-latch non-fixture remount should recover interrupted committed file");
    }

    {
        const auto fixture_persistent_state_path = BuildPersistentStatePath(
            replay_non_fixture_disk_present_sidecar_ignored_context.device_path,
            replay_non_fixture_disk_present_sidecar_ignored_context.volume_name);
        const auto non_fixture_persistent_state_path = BuildPersistentStatePath(
            replay_non_fixture_disk_present_sidecar_ignored_non_fixture_context.device_path,
            replay_non_fixture_disk_present_sidecar_ignored_non_fixture_context.volume_name);
        ok &= Require(
            !fixture_persistent_state_path.empty() && !non_fixture_persistent_state_path.empty(),
            "Replay-non-fixture-disk-present-sidecar-ignored non-fixture scenario should resolve persistent-state paths");
        if (!fixture_persistent_state_path.empty() && !non_fixture_persistent_state_path.empty())
        {
            std::filesystem::create_directories(non_fixture_persistent_state_path.parent_path(), ec);
            ec.clear();
            std::filesystem::copy_file(
                fixture_persistent_state_path,
                non_fixture_persistent_state_path,
                std::filesystem::copy_options::overwrite_existing,
                ec);
            ok &= Require(
                !ec,
                "Replay-non-fixture-disk-present-sidecar-ignored non-fixture scenario should copy stale pending sidecar metadata");
        }
    }

    std::size_t corrupted_replay_blocks_non_fixture_disk_present_sidecar_ignored = 0;
    std::size_t applied_window_replay_blocks_non_fixture_disk_present_sidecar_ignored = 0;
    ok &= Require(
        CorruptPendingReplayCheckpointCommitBlobAddresses(
            replay_non_fixture_disk_present_sidecar_ignored_non_fixture_path,
            /*pending_source_xid=*/kInitialCheckpointXid + 1,
            /*pending_target_xid=*/kInitialCheckpointXid + 2,
            /*applied_target_xid=*/kInitialCheckpointXid + 1,
            /*mutated_commit_blob_address=*/3,
            corrupted_replay_blocks_non_fixture_disk_present_sidecar_ignored,
            applied_window_replay_blocks_non_fixture_disk_present_sidecar_ignored),
        "Replay-non-fixture-disk-present-sidecar-ignored non-fixture scenario should corrupt all pending replay-checkpoint candidates while keeping applied-window candidates");
    ok &= Require(
        corrupted_replay_blocks_non_fixture_disk_present_sidecar_ignored >= 1,
        "Replay-non-fixture-disk-present-sidecar-ignored non-fixture scenario should corrupt at least one pending replay checkpoint block");
    ok &= Require(
        applied_window_replay_blocks_non_fixture_disk_present_sidecar_ignored >= 1,
        "Replay-non-fixture-disk-present-sidecar-ignored non-fixture scenario should keep at least one applied-window replay checkpoint block");

    {
        apfsaccess::rw::MetadataStore remounted(replay_non_fixture_disk_present_sidecar_ignored_non_fixture_context);
        ok &= Require(remounted.LoadContainerSuperblocks(), "Replay-non-fixture-disk-present-sidecar-ignored non-fixture remount LoadContainerSuperblocks should succeed");
        ok &= Require(remounted.PrepareNativeWritePath(), "Replay-non-fixture-disk-present-sidecar-ignored non-fixture remount PrepareNativeWritePath should succeed");
        ok &= Require(
            !remounted.LastReplayCheckpointPendingWindow(),
            "Replay-non-fixture-disk-present-sidecar-ignored non-fixture remount should treat replay metadata as non-pending window");
        ok &= Require(
            !remounted.IsRecoveryRequired(),
            "Replay-non-fixture-disk-present-sidecar-ignored non-fixture remount should ignore sidecar pending metadata when replay metadata is non-pending");
        ok &= Require(
            remounted.ReplayOrRecover(),
            "Replay-non-fixture-disk-present-sidecar-ignored non-fixture remount should complete replay evaluation without fail-closed downgrade");
        ok &= Require(!remounted.IsRecoveryRequired(), "Replay-non-fixture-disk-present-sidecar-ignored non-fixture remount should remain recovery-clear");
        ok &= Require(remounted.IsCommitPathReady(), "Replay-non-fixture-disk-present-sidecar-ignored non-fixture remount should keep commit path ready");
    }

    const auto replay_non_fixture_disk_present_sidecar_missing_path =
        run_root / "container_replay_disk_present_sidecar_missing_physical.bin";
    ec.clear();
    std::filesystem::copy_file(
        replay_non_fixture_disk_present_sidecar_ignored_image_path,
        replay_non_fixture_disk_present_sidecar_missing_path,
        std::filesystem::copy_options::overwrite_existing,
        ec);
    ok &= Require(
        !ec,
        "Replay-non-fixture-disk-present-sidecar-missing non-fixture scenario should copy fixture image");

    apfsaccess::rw::MetadataStore::VolumeContext replay_non_fixture_disk_present_sidecar_missing_context
    {
        replay_non_fixture_disk_present_sidecar_missing_path.wstring(),
        L"ReplayNonFixtureDiskPresentSidecarMissingNonFixture",
    };
    replay_non_fixture_disk_present_sidecar_missing_context.crash_replay_mode = L"ReplayIfSafe";
    replay_non_fixture_disk_present_sidecar_missing_context.integrity_check_on_mount = false;

    std::size_t corrupted_replay_blocks_non_fixture_disk_present_sidecar_missing = 0;
    std::size_t applied_window_replay_blocks_non_fixture_disk_present_sidecar_missing = 0;
    ok &= Require(
        CorruptPendingReplayCheckpointCommitBlobAddresses(
            replay_non_fixture_disk_present_sidecar_missing_path,
            /*pending_source_xid=*/kInitialCheckpointXid + 1,
            /*pending_target_xid=*/kInitialCheckpointXid + 2,
            /*applied_target_xid=*/kInitialCheckpointXid + 1,
            /*mutated_commit_blob_address=*/3,
            corrupted_replay_blocks_non_fixture_disk_present_sidecar_missing,
            applied_window_replay_blocks_non_fixture_disk_present_sidecar_missing),
        "Replay-non-fixture-disk-present-sidecar-missing non-fixture scenario should corrupt all pending replay-checkpoint candidates while keeping applied-window candidates");
    ok &= Require(
        corrupted_replay_blocks_non_fixture_disk_present_sidecar_missing >= 1,
        "Replay-non-fixture-disk-present-sidecar-missing non-fixture scenario should corrupt at least one pending replay checkpoint block");
    ok &= Require(
        applied_window_replay_blocks_non_fixture_disk_present_sidecar_missing >= 1,
        "Replay-non-fixture-disk-present-sidecar-missing non-fixture scenario should keep at least one applied-window replay checkpoint block");

    {
        const auto persistent_state_path = BuildPersistentStatePath(
            replay_non_fixture_disk_present_sidecar_missing_context.device_path,
            replay_non_fixture_disk_present_sidecar_missing_context.volume_name);
        if (!persistent_state_path.empty())
        {
            std::filesystem::remove(persistent_state_path, ec);
        }
    }

    {
        apfsaccess::rw::MetadataStore remounted(replay_non_fixture_disk_present_sidecar_missing_context);
        ok &= Require(remounted.LoadContainerSuperblocks(), "Replay-non-fixture-disk-present-sidecar-missing non-fixture remount LoadContainerSuperblocks should succeed");
        ok &= Require(remounted.PrepareNativeWritePath(), "Replay-non-fixture-disk-present-sidecar-missing non-fixture remount PrepareNativeWritePath should succeed");
        ok &= Require(
            !remounted.LastReplayCheckpointPendingWindow(),
            "Replay-non-fixture-disk-present-sidecar-missing non-fixture remount should treat replay metadata as non-pending window");
        ok &= Require(
            remounted.IsRecoveryRequired(),
            "Replay-non-fixture-disk-present-sidecar-missing non-fixture remount should require recovery when canonical committed xid remains ahead");
        ok &= Require(
            remounted.RecoveryReason() == L"PersistentStateAheadOfSuperblock",
            "Replay-non-fixture-disk-present-sidecar-missing non-fixture remount should report canonical committed-xid drift");
        ok &= Require(
            !remounted.ReplayOrRecover(),
            "Replay-non-fixture-disk-present-sidecar-missing non-fixture remount should fail closed when replay metadata is non-pending and canonical replay cannot proceed");
        ok &= Require(remounted.IsRecoveryRequired(), "Replay-non-fixture-disk-present-sidecar-missing non-fixture remount should remain recovery-required");
        ok &= Require(!remounted.IsCommitPathReady(), "Replay-non-fixture-disk-present-sidecar-missing non-fixture remount should keep commit path blocked");
        ok &= Require(
            remounted.RecoveryReason() == L"ReplayCheckpointNotPendingWindow" ||
            remounted.RecoveryReason() == L"ReplayCanonicalCandidateMissing",
            "Replay-non-fixture-disk-present-sidecar-missing non-fixture remount should report non-pending replay-window fail-closed reason");
    }

    const auto replay_corrupt_persistent_state_image_path = run_root / "container_replay_corrupt_persistent_state.apfs.img";
    if (!CreateSyntheticContainer(replay_corrupt_persistent_state_image_path))
    {
        std::cerr << "[FAIL] unable to create synthetic APFS container image for replay-corrupt-persistent-state scenario" << std::endl;
        return 1;
    }

    apfsaccess::rw::MetadataStore::VolumeContext replay_corrupt_persistent_state_context
    {
        replay_corrupt_persistent_state_image_path.wstring(),
        L"ReplayCorruptPersistentState",
    };
    replay_corrupt_persistent_state_context.crash_replay_mode = L"ReplayIfSafe";
    {
        apfsaccess::rw::MetadataStore store(replay_corrupt_persistent_state_context);
        ok &= Require(store.LoadContainerSuperblocks(), "Replay-corrupt-persistent-state LoadContainerSuperblocks should succeed");
        ok &= Require(store.LoadObjectMap(), "Replay-corrupt-persistent-state LoadObjectMap should succeed");
        ok &= Require(store.LoadSpacemanState(), "Replay-corrupt-persistent-state LoadSpacemanState should succeed");
        ok &= Require(store.PrepareNativeWritePath(), "Replay-corrupt-persistent-state PrepareNativeWritePath should succeed");
        std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
        store.SetFilePayloadProvider(
            [&staged_payloads](const std::wstring& path, std::uint64_t logical_size) -> std::optional<std::vector<std::byte>>
            {
                auto pending = staged_payloads.find(path);
                if (pending == staged_payloads.end())
                {
                    return std::nullopt;
                }

                if (logical_size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
                {
                    return std::nullopt;
                }

                auto payload = pending->second;
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
        create_file.path = L"\\replay_corrupt_persistent_state.bin";
        ok &= Require(
            store.ApplyMutation(create_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-corrupt-persistent-state create file should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_file{};
        write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_file.path = L"\\replay_corrupt_persistent_state.bin";
        write_file.length = 2048;
        ok &= Require(
            store.ApplyMutation(write_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-corrupt-persistent-state write file should apply");
        staged_payloads[L"\\replay_corrupt_persistent_state.bin"] = std::vector<std::byte>(2048, static_cast<std::byte>(0x79));

        store.SetCommitStageHook([](std::string_view stage)
        {
            return stage != "before-checkpoint-switch";
        });

        const auto interrupted_commit = store.CommitPendingMutations();
        ok &= Require(
            interrupted_commit == apfsaccess::rw::MetadataStore::CommitStatus::PersistFailed,
            "Replay-corrupt-persistent-state setup commit should fail at before-checkpoint-switch stage");
        ok &= Require(
            store.IsRecoveryRequired(),
            "Replay-corrupt-persistent-state setup should require recovery");
    }

    {
        const auto persistent_state_path = BuildPersistentStatePath(
            replay_corrupt_persistent_state_context.device_path,
            replay_corrupt_persistent_state_context.volume_name);
        ok &= Require(
            CorruptPersistentStateMagic(persistent_state_path),
            "Replay-corrupt-persistent-state should corrupt persistent-state magic for fallback validation");
    }

    {
        apfsaccess::rw::MetadataStore remounted(replay_corrupt_persistent_state_context);
        ok &= Require(remounted.LoadContainerSuperblocks(), "Replay-corrupt-persistent-state remount LoadContainerSuperblocks should succeed");
        ok &= Require(remounted.PrepareNativeWritePath(), "Replay-corrupt-persistent-state remount PrepareNativeWritePath should succeed");
        ok &= Require(remounted.IsRecoveryRequired(), "Replay-corrupt-persistent-state remount should require recovery");
        ok &= Require(
            remounted.RecoveryReason() == L"PersistentStateAheadOfSuperblock",
            "Replay-corrupt-persistent-state remount should recover from corrupt persistent state via disk/replay metadata");
        ok &= Require(remounted.ReplayOrRecover(), "Replay-corrupt-persistent-state remount replay should succeed after persistent-state fallback");
        ok &= Require(!remounted.IsRecoveryRequired(), "Replay-corrupt-persistent-state remount should clear recovery after replay");
        ok &= Require(remounted.IsCommitPathReady(), "Replay-corrupt-persistent-state remount should restore commit path readiness after replay");
    }

    const auto replay_checksum_tampered_persistent_state_image_path =
        run_root / "container_replay_checksum_tampered_persistent_state.apfs.img";
    if (!CreateSyntheticContainer(replay_checksum_tampered_persistent_state_image_path))
    {
        std::cerr << "[FAIL] unable to create synthetic APFS container image for replay-checksum-tampered-persistent-state scenario" << std::endl;
        return 1;
    }

    apfsaccess::rw::MetadataStore::VolumeContext replay_checksum_tampered_persistent_state_context
    {
        replay_checksum_tampered_persistent_state_image_path.wstring(),
        L"ReplayChecksumTamperedPersistentState",
    };
    replay_checksum_tampered_persistent_state_context.crash_replay_mode = L"ReplayIfSafe";
    {
        apfsaccess::rw::MetadataStore store(replay_checksum_tampered_persistent_state_context);
        ok &= Require(store.LoadContainerSuperblocks(), "Replay-checksum-tampered-persistent-state LoadContainerSuperblocks should succeed");
        ok &= Require(store.LoadObjectMap(), "Replay-checksum-tampered-persistent-state LoadObjectMap should succeed");
        ok &= Require(store.LoadSpacemanState(), "Replay-checksum-tampered-persistent-state LoadSpacemanState should succeed");
        ok &= Require(store.PrepareNativeWritePath(), "Replay-checksum-tampered-persistent-state PrepareNativeWritePath should succeed");
        std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
        store.SetFilePayloadProvider(
            [&staged_payloads](const std::wstring& path, std::uint64_t logical_size) -> std::optional<std::vector<std::byte>>
            {
                auto pending = staged_payloads.find(path);
                if (pending == staged_payloads.end())
                {
                    return std::nullopt;
                }

                if (logical_size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
                {
                    return std::nullopt;
                }

                auto payload = pending->second;
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
        create_file.path = L"\\replay_checksum_tampered_persistent_state.bin";
        ok &= Require(
            store.ApplyMutation(create_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-checksum-tampered-persistent-state create file should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_file{};
        write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_file.path = L"\\replay_checksum_tampered_persistent_state.bin";
        write_file.length = 2048;
        ok &= Require(
            store.ApplyMutation(write_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-checksum-tampered-persistent-state write file should apply");
        staged_payloads[L"\\replay_checksum_tampered_persistent_state.bin"] =
            std::vector<std::byte>(2048, static_cast<std::byte>(0x5A));

        store.SetCommitStageHook([](std::string_view stage)
        {
            return stage != "before-checkpoint-switch";
        });

        const auto interrupted_commit = store.CommitPendingMutations();
        ok &= Require(
            interrupted_commit == apfsaccess::rw::MetadataStore::CommitStatus::PersistFailed,
            "Replay-checksum-tampered-persistent-state setup commit should fail at before-checkpoint-switch stage");
        ok &= Require(
            store.IsRecoveryRequired(),
            "Replay-checksum-tampered-persistent-state setup should require recovery");
    }

    {
        const auto persistent_state_path = BuildPersistentStatePath(
            replay_checksum_tampered_persistent_state_context.device_path,
            replay_checksum_tampered_persistent_state_context.volume_name);
        ok &= Require(
            CorruptPersistentStateChecksum(persistent_state_path, /*mutated_checksum=*/0u),
            "Replay-checksum-tampered-persistent-state should corrupt persistent-state checksum");
    }

    {
        apfsaccess::rw::MetadataStore remounted(replay_checksum_tampered_persistent_state_context);
        ok &= Require(remounted.LoadContainerSuperblocks(), "Replay-checksum-tampered-persistent-state remount LoadContainerSuperblocks should succeed");
        ok &= Require(remounted.PrepareNativeWritePath(), "Replay-checksum-tampered-persistent-state remount PrepareNativeWritePath should succeed");
        ok &= Require(remounted.IsRecoveryRequired(), "Replay-checksum-tampered-persistent-state remount should require recovery");
        ok &= Require(
            remounted.RecoveryReason() == L"PersistentStateAheadOfSuperblock",
            "Replay-checksum-tampered-persistent-state remount should ignore checksum-tampered persistent state");
        ok &= Require(
            remounted.ReplayOrRecover(),
            "Replay-checksum-tampered-persistent-state remount replay should succeed after persistent-state checksum rejection");
        ok &= Require(!remounted.IsRecoveryRequired(), "Replay-checksum-tampered-persistent-state remount should clear recovery after replay");
        ok &= Require(remounted.IsCommitPathReady(), "Replay-checksum-tampered-persistent-state remount should restore commit path readiness after replay");
    }

    const auto replay_oversized_path_persistent_state_image_path = run_root / "container_replay_oversized_path_persistent_state.apfs.img";
    if (!CreateSyntheticContainer(replay_oversized_path_persistent_state_image_path))
    {
        std::cerr << "[FAIL] unable to create synthetic APFS container image for replay-oversized-path-persistent-state scenario" << std::endl;
        return 1;
    }

    apfsaccess::rw::MetadataStore::VolumeContext replay_oversized_path_persistent_state_context
    {
        replay_oversized_path_persistent_state_image_path.wstring(),
        L"ReplayOversizedPathPersistentState",
    };
    replay_oversized_path_persistent_state_context.crash_replay_mode = L"ReplayIfSafe";
    {
        apfsaccess::rw::MetadataStore store(replay_oversized_path_persistent_state_context);
        ok &= Require(store.LoadContainerSuperblocks(), "Replay-oversized-path-persistent-state LoadContainerSuperblocks should succeed");
        ok &= Require(store.LoadObjectMap(), "Replay-oversized-path-persistent-state LoadObjectMap should succeed");
        ok &= Require(store.LoadSpacemanState(), "Replay-oversized-path-persistent-state LoadSpacemanState should succeed");
        ok &= Require(store.PrepareNativeWritePath(), "Replay-oversized-path-persistent-state PrepareNativeWritePath should succeed");
        std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
        store.SetFilePayloadProvider(
            [&staged_payloads](const std::wstring& path, std::uint64_t logical_size) -> std::optional<std::vector<std::byte>>
            {
                auto pending = staged_payloads.find(path);
                if (pending == staged_payloads.end())
                {
                    return std::nullopt;
                }

                if (logical_size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
                {
                    return std::nullopt;
                }

                auto payload = pending->second;
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
        create_file.path = L"\\replay_oversized_path_persistent_state.bin";
        ok &= Require(
            store.ApplyMutation(create_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-oversized-path-persistent-state create file should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_file{};
        write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_file.path = L"\\replay_oversized_path_persistent_state.bin";
        write_file.length = 2048;
        ok &= Require(
            store.ApplyMutation(write_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-oversized-path-persistent-state write file should apply");
        staged_payloads[L"\\replay_oversized_path_persistent_state.bin"] = std::vector<std::byte>(2048, static_cast<std::byte>(0x7A));

        store.SetCommitStageHook([](std::string_view stage)
        {
            return stage != "before-checkpoint-switch";
        });

        const auto interrupted_commit = store.CommitPendingMutations();
        ok &= Require(
            interrupted_commit == apfsaccess::rw::MetadataStore::CommitStatus::PersistFailed,
            "Replay-oversized-path-persistent-state setup commit should fail at before-checkpoint-switch stage");
        ok &= Require(
            store.IsRecoveryRequired(),
            "Replay-oversized-path-persistent-state setup should require recovery");
    }

    {
        const auto persistent_state_path = BuildPersistentStatePath(
            replay_oversized_path_persistent_state_context.device_path,
            replay_oversized_path_persistent_state_context.volume_name);
        ok &= Require(
            CorruptPersistentStateFirstInodePathLength(
                persistent_state_path,
                /*mutated_path_length=*/0x01000000u),
            "Replay-oversized-path-persistent-state should corrupt persistent-state inode path length");
    }

    {
        apfsaccess::rw::MetadataStore remounted(replay_oversized_path_persistent_state_context);
        ok &= Require(remounted.LoadContainerSuperblocks(), "Replay-oversized-path-persistent-state remount LoadContainerSuperblocks should succeed");
        ok &= Require(remounted.PrepareNativeWritePath(), "Replay-oversized-path-persistent-state remount PrepareNativeWritePath should succeed");
        ok &= Require(remounted.IsRecoveryRequired(), "Replay-oversized-path-persistent-state remount should require recovery");
        ok &= Require(
            remounted.RecoveryReason() == L"PersistentStateAheadOfSuperblock",
            "Replay-oversized-path-persistent-state remount should fall back to disk/replay metadata after parser rejection");
        ok &= Require(remounted.ReplayOrRecover(), "Replay-oversized-path-persistent-state remount replay should succeed after persistent-state parser fallback");
        ok &= Require(!remounted.IsRecoveryRequired(), "Replay-oversized-path-persistent-state remount should clear recovery after replay");
        ok &= Require(remounted.IsCommitPathReady(), "Replay-oversized-path-persistent-state remount should restore commit path readiness after replay");
    }

    const auto replay_missing_replay_checkpoint_image_path = run_root / "container_replay_missing_replay_checkpoint.apfs.img";
    if (!CreateSyntheticContainer(replay_missing_replay_checkpoint_image_path))
    {
        std::cerr << "[FAIL] unable to create synthetic APFS container image for replay-missing-replay-checkpoint scenario" << std::endl;
        return 1;
    }

    apfsaccess::rw::MetadataStore::VolumeContext replay_missing_replay_checkpoint_context
    {
        replay_missing_replay_checkpoint_image_path.wstring(),
        L"ReplayMissingReplayCheckpoint",
    };
    replay_missing_replay_checkpoint_context.crash_replay_mode = L"ReplayIfSafe";
    {
        apfsaccess::rw::MetadataStore store(replay_missing_replay_checkpoint_context);
        ok &= Require(store.LoadContainerSuperblocks(), "Replay-missing-replay-checkpoint LoadContainerSuperblocks should succeed");
        ok &= Require(store.LoadObjectMap(), "Replay-missing-replay-checkpoint LoadObjectMap should succeed");
        ok &= Require(store.LoadSpacemanState(), "Replay-missing-replay-checkpoint LoadSpacemanState should succeed");
        ok &= Require(store.PrepareNativeWritePath(), "Replay-missing-replay-checkpoint PrepareNativeWritePath should succeed");
        std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
        store.SetFilePayloadProvider(
            [&staged_payloads](const std::wstring& path, std::uint64_t logical_size) -> std::optional<std::vector<std::byte>>
            {
                auto pending = staged_payloads.find(path);
                if (pending == staged_payloads.end())
                {
                    return std::nullopt;
                }

                if (logical_size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
                {
                    return std::nullopt;
                }

                auto payload = pending->second;
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
        create_file.path = L"\\replay_missing_replay_checkpoint.bin";
        ok &= Require(
            store.ApplyMutation(create_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-missing-replay-checkpoint create file should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_file{};
        write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_file.path = L"\\replay_missing_replay_checkpoint.bin";
        write_file.length = 2048;
        ok &= Require(
            store.ApplyMutation(write_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-missing-replay-checkpoint write file should apply");
        staged_payloads[L"\\replay_missing_replay_checkpoint.bin"] = std::vector<std::byte>(2048, static_cast<std::byte>(0x77));

        store.SetCommitStageHook([](std::string_view stage)
        {
            return stage != "before-checkpoint-switch";
        });

        const auto interrupted_commit = store.CommitPendingMutations();
        ok &= Require(
            interrupted_commit == apfsaccess::rw::MetadataStore::CommitStatus::PersistFailed,
            "Replay-missing-replay-checkpoint setup commit should fail at before-checkpoint-switch stage");
        ok &= Require(
            store.IsRecoveryRequired(),
            "Replay-missing-replay-checkpoint setup should require recovery");
    }

    {
        const auto persistent_state_path = BuildPersistentStatePath(
            replay_missing_replay_checkpoint_context.device_path,
            replay_missing_replay_checkpoint_context.volume_name);
        if (!persistent_state_path.empty())
        {
            std::filesystem::remove(persistent_state_path, ec);
        }
    }

    constexpr std::array<char, 12> kReplayCheckpointMagic =
    {
        'A', 'P', 'F', 'S', 'R', 'W', 'R', 'P', 'L', '1', '\0', '\0'
    };
    std::size_t corrupted_replay_checkpoint_blocks = 0;
    ok &= Require(
        CorruptBlocksWithMagicPrefix(
            replay_missing_replay_checkpoint_image_path,
            kReplayCheckpointMagic,
            /*mutate_offset=*/0,
            static_cast<std::byte>(0x00),
            corrupted_replay_checkpoint_blocks),
        "Replay-missing-replay-checkpoint should corrupt persisted replay checkpoint blocks");
    ok &= Require(
        corrupted_replay_checkpoint_blocks >= 1,
        "Replay-missing-replay-checkpoint should corrupt at least one replay checkpoint block");

    {
        apfsaccess::rw::MetadataStore remounted(replay_missing_replay_checkpoint_context);
        ok &= Require(remounted.LoadContainerSuperblocks(), "Replay-missing-replay-checkpoint remount LoadContainerSuperblocks should succeed");
        ok &= Require(remounted.PrepareNativeWritePath(), "Replay-missing-replay-checkpoint remount PrepareNativeWritePath should succeed");
        ok &= Require(remounted.IsRecoveryRequired(), "Replay-missing-replay-checkpoint remount should require recovery");
        ok &= Require(
            remounted.RecoveryReason() == L"PersistentStateAheadOfSuperblock",
            "Replay-missing-replay-checkpoint remount should detect metadata ahead of superblock");
        ok &= Require(!remounted.ReplayOrRecover(), "Replay-missing-replay-checkpoint remount replay should fail without replay checkpoint metadata");
        ok &= Require(remounted.IsRecoveryRequired(), "Replay-missing-replay-checkpoint remount should remain recovery-required");
        ok &= Require(!remounted.IsCommitPathReady(), "Replay-missing-replay-checkpoint remount should keep commit path blocked");
        ok &= Require(
            remounted.RecoveryReason() == L"ReplayMetadataStateMissing",
            "Replay-missing-replay-checkpoint remount should report ReplayMetadataStateMissing");
    }

    const auto replay_invalid_payload_checkpoint_image_path = run_root / "container_replay_invalid_payload_checkpoint.apfs.img";
    if (!CreateSyntheticContainer(replay_invalid_payload_checkpoint_image_path))
    {
        std::cerr << "[FAIL] unable to create synthetic APFS container image for replay-invalid-payload-checkpoint scenario" << std::endl;
        return 1;
    }

    apfsaccess::rw::MetadataStore::VolumeContext replay_invalid_payload_checkpoint_context
    {
        replay_invalid_payload_checkpoint_image_path.wstring(),
        L"ReplayInvalidPayloadCheckpoint",
    };
    replay_invalid_payload_checkpoint_context.crash_replay_mode = L"ReplayIfSafe";
    {
        apfsaccess::rw::MetadataStore store(replay_invalid_payload_checkpoint_context);
        ok &= Require(store.LoadContainerSuperblocks(), "Replay-invalid-payload-checkpoint LoadContainerSuperblocks should succeed");
        ok &= Require(store.LoadObjectMap(), "Replay-invalid-payload-checkpoint LoadObjectMap should succeed");
        ok &= Require(store.LoadSpacemanState(), "Replay-invalid-payload-checkpoint LoadSpacemanState should succeed");
        ok &= Require(store.PrepareNativeWritePath(), "Replay-invalid-payload-checkpoint PrepareNativeWritePath should succeed");
        std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
        store.SetFilePayloadProvider(
            [&staged_payloads](const std::wstring& path, std::uint64_t logical_size) -> std::optional<std::vector<std::byte>>
            {
                auto pending = staged_payloads.find(path);
                if (pending == staged_payloads.end())
                {
                    return std::nullopt;
                }

                if (logical_size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
                {
                    return std::nullopt;
                }

                auto payload = pending->second;
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
        create_file.path = L"\\replay_invalid_payload_checkpoint.bin";
        ok &= Require(
            store.ApplyMutation(create_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-invalid-payload-checkpoint create file should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_file{};
        write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_file.path = L"\\replay_invalid_payload_checkpoint.bin";
        write_file.length = 2048;
        ok &= Require(
            store.ApplyMutation(write_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-invalid-payload-checkpoint write file should apply");
        staged_payloads[L"\\replay_invalid_payload_checkpoint.bin"] = std::vector<std::byte>(2048, static_cast<std::byte>(0x7C));

        store.SetCommitStageHook([](std::string_view stage)
        {
            return stage != "before-checkpoint-switch";
        });

        const auto interrupted_commit = store.CommitPendingMutations();
        ok &= Require(
            interrupted_commit == apfsaccess::rw::MetadataStore::CommitStatus::PersistFailed,
            "Replay-invalid-payload-checkpoint setup commit should fail at before-checkpoint-switch stage");
        ok &= Require(
            store.IsRecoveryRequired(),
            "Replay-invalid-payload-checkpoint setup should require recovery");
    }

    std::size_t corrupted_replay_payload_blocks = 0;
    ok &= Require(
        CorruptReplayCheckpointPayloadBytes(
            replay_invalid_payload_checkpoint_image_path,
            /*mutated_payload_bytes=*/32,
            corrupted_replay_payload_blocks),
        "Replay-invalid-payload-checkpoint should corrupt replay checkpoint payload length");
    ok &= Require(
        corrupted_replay_payload_blocks >= 1,
        "Replay-invalid-payload-checkpoint should corrupt at least one replay checkpoint block");

    {
        apfsaccess::rw::MetadataStore remounted(replay_invalid_payload_checkpoint_context);
        ok &= Require(remounted.LoadContainerSuperblocks(), "Replay-invalid-payload-checkpoint remount LoadContainerSuperblocks should succeed");
        ok &= Require(remounted.PrepareNativeWritePath(), "Replay-invalid-payload-checkpoint remount PrepareNativeWritePath should succeed");
        ok &= Require(remounted.IsRecoveryRequired(), "Replay-invalid-payload-checkpoint remount should require recovery");
        ok &= Require(
            remounted.RecoveryReason() == L"PersistentStateAheadOfSuperblock",
            "Replay-invalid-payload-checkpoint remount should detect persistent state ahead of superblock");
        ok &= Require(
            remounted.ReplayOrRecover(),
            "Replay-invalid-payload-checkpoint remount should ignore malformed replay-checkpoint payload-length metadata and recover");
        ok &= Require(!remounted.IsRecoveryRequired(), "Replay-invalid-payload-checkpoint remount should clear recovery after replay");
        ok &= Require(remounted.IsCommitPathReady(), "Replay-invalid-payload-checkpoint remount should restore commit path readiness");
        ok &= Require(
            remounted.CheckpointXid().value_or(0) == (kInitialCheckpointXid + 1),
            "Replay-invalid-payload-checkpoint remount should keep recovered checkpoint xid");
    }

    const auto replay_zero_checksum_checkpoint_image_path = run_root / "container_replay_zero_checksum_checkpoint.apfs.img";
    if (!CreateSyntheticContainer(replay_zero_checksum_checkpoint_image_path))
    {
        std::cerr << "[FAIL] unable to create synthetic APFS container image for replay-zero-checksum-checkpoint scenario" << std::endl;
        return 1;
    }

    apfsaccess::rw::MetadataStore::VolumeContext replay_zero_checksum_checkpoint_context
    {
        replay_zero_checksum_checkpoint_image_path.wstring(),
        L"ReplayZeroChecksumCheckpoint",
    };
    replay_zero_checksum_checkpoint_context.crash_replay_mode = L"ReplayIfSafe";
    {
        apfsaccess::rw::MetadataStore store(replay_zero_checksum_checkpoint_context);
        ok &= Require(store.LoadContainerSuperblocks(), "Replay-zero-checksum-checkpoint LoadContainerSuperblocks should succeed");
        ok &= Require(store.LoadObjectMap(), "Replay-zero-checksum-checkpoint LoadObjectMap should succeed");
        ok &= Require(store.LoadSpacemanState(), "Replay-zero-checksum-checkpoint LoadSpacemanState should succeed");
        ok &= Require(store.PrepareNativeWritePath(), "Replay-zero-checksum-checkpoint PrepareNativeWritePath should succeed");
        std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
        store.SetFilePayloadProvider(
            [&staged_payloads](const std::wstring& path, std::uint64_t logical_size) -> std::optional<std::vector<std::byte>>
            {
                auto pending = staged_payloads.find(path);
                if (pending == staged_payloads.end())
                {
                    return std::nullopt;
                }

                if (logical_size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
                {
                    return std::nullopt;
                }

                auto payload = pending->second;
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
        create_file.path = L"\\replay_zero_checksum_checkpoint.bin";
        ok &= Require(
            store.ApplyMutation(create_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-zero-checksum-checkpoint create file should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_file{};
        write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_file.path = L"\\replay_zero_checksum_checkpoint.bin";
        write_file.length = 2048;
        ok &= Require(
            store.ApplyMutation(write_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-zero-checksum-checkpoint write file should apply");
        staged_payloads[L"\\replay_zero_checksum_checkpoint.bin"] = std::vector<std::byte>(2048, static_cast<std::byte>(0x7E));

        store.SetCommitStageHook([](std::string_view stage)
        {
            return stage != "before-checkpoint-switch";
        });

        const auto interrupted_commit = store.CommitPendingMutations();
        ok &= Require(
            interrupted_commit == apfsaccess::rw::MetadataStore::CommitStatus::PersistFailed,
            "Replay-zero-checksum-checkpoint setup commit should fail at before-checkpoint-switch stage");
        ok &= Require(
            store.IsRecoveryRequired(),
            "Replay-zero-checksum-checkpoint setup should require recovery");
    }

    std::size_t corrupted_replay_zero_checksum_blocks = 0;
    ok &= Require(
        CorruptReplayCheckpointChecksum(
            replay_zero_checksum_checkpoint_image_path,
            /*mutated_checksum=*/0u,
            corrupted_replay_zero_checksum_blocks),
        "Replay-zero-checksum-checkpoint should zero replay-checkpoint checksums");
    ok &= Require(
        corrupted_replay_zero_checksum_blocks >= 1,
        "Replay-zero-checksum-checkpoint should corrupt at least one replay checkpoint block");

    {
        apfsaccess::rw::MetadataStore remounted(replay_zero_checksum_checkpoint_context);
        ok &= Require(remounted.LoadContainerSuperblocks(), "Replay-zero-checksum-checkpoint remount LoadContainerSuperblocks should succeed");
        ok &= Require(remounted.PrepareNativeWritePath(), "Replay-zero-checksum-checkpoint remount PrepareNativeWritePath should succeed");
        ok &= Require(remounted.IsRecoveryRequired(), "Replay-zero-checksum-checkpoint remount should require recovery");
        ok &= Require(
            remounted.RecoveryReason() == L"PersistentStateAheadOfSuperblock",
            "Replay-zero-checksum-checkpoint remount should detect persistent state ahead of superblock");
        ok &= Require(
            remounted.ReplayOrRecover(),
            "Replay-zero-checksum-checkpoint remount should ignore zero-checksum replay checkpoint metadata and recover");
        ok &= Require(!remounted.IsRecoveryRequired(), "Replay-zero-checksum-checkpoint remount should clear recovery after replay");
        ok &= Require(remounted.IsCommitPathReady(), "Replay-zero-checksum-checkpoint remount should restore commit path readiness");
        ok &= Require(
            remounted.CheckpointXid().value_or(0) == (kInitialCheckpointXid + 1),
            "Replay-zero-checksum-checkpoint remount should keep recovered checkpoint xid");
    }

    const auto replay_trailing_tamper_checkpoint_image_path = run_root / "container_replay_trailing_tamper_checkpoint.apfs.img";
    if (!CreateSyntheticContainer(replay_trailing_tamper_checkpoint_image_path))
    {
        std::cerr << "[FAIL] unable to create synthetic APFS container image for replay-trailing-tamper-checkpoint scenario" << std::endl;
        return 1;
    }

    apfsaccess::rw::MetadataStore::VolumeContext replay_trailing_tamper_checkpoint_context
    {
        replay_trailing_tamper_checkpoint_image_path.wstring(),
        L"ReplayTrailingTamperCheckpoint",
    };
    replay_trailing_tamper_checkpoint_context.crash_replay_mode = L"ReplayIfSafe";
    {
        apfsaccess::rw::MetadataStore store(replay_trailing_tamper_checkpoint_context);
        ok &= Require(store.LoadContainerSuperblocks(), "Replay-trailing-tamper-checkpoint LoadContainerSuperblocks should succeed");
        ok &= Require(store.LoadObjectMap(), "Replay-trailing-tamper-checkpoint LoadObjectMap should succeed");
        ok &= Require(store.LoadSpacemanState(), "Replay-trailing-tamper-checkpoint LoadSpacemanState should succeed");
        ok &= Require(store.PrepareNativeWritePath(), "Replay-trailing-tamper-checkpoint PrepareNativeWritePath should succeed");
        std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
        store.SetFilePayloadProvider(
            [&staged_payloads](const std::wstring& path, std::uint64_t logical_size) -> std::optional<std::vector<std::byte>>
            {
                auto pending = staged_payloads.find(path);
                if (pending == staged_payloads.end())
                {
                    return std::nullopt;
                }

                if (logical_size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
                {
                    return std::nullopt;
                }

                auto payload = pending->second;
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
        create_file.path = L"\\replay_trailing_tamper_checkpoint.bin";
        ok &= Require(
            store.ApplyMutation(create_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-trailing-tamper-checkpoint create file should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_file{};
        write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_file.path = L"\\replay_trailing_tamper_checkpoint.bin";
        write_file.length = 2048;
        ok &= Require(
            store.ApplyMutation(write_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-trailing-tamper-checkpoint write file should apply");
        staged_payloads[L"\\replay_trailing_tamper_checkpoint.bin"] = std::vector<std::byte>(2048, static_cast<std::byte>(0x7D));

        store.SetCommitStageHook([](std::string_view stage)
        {
            return stage != "before-checkpoint-switch";
        });

        const auto interrupted_commit = store.CommitPendingMutations();
        ok &= Require(
            interrupted_commit == apfsaccess::rw::MetadataStore::CommitStatus::PersistFailed,
            "Replay-trailing-tamper-checkpoint setup commit should fail at before-checkpoint-switch stage");
        ok &= Require(
            store.IsRecoveryRequired(),
            "Replay-trailing-tamper-checkpoint setup should require recovery");
    }

    std::size_t corrupted_replay_trailing_blocks = 0;
    ok &= Require(
        CorruptReplayCheckpointTrailingBytes(
            replay_trailing_tamper_checkpoint_image_path,
            static_cast<std::byte>(0x5Au),
            corrupted_replay_trailing_blocks),
        "Replay-trailing-tamper-checkpoint should corrupt replay-checkpoint trailing bytes");
    ok &= Require(
        corrupted_replay_trailing_blocks >= 1,
        "Replay-trailing-tamper-checkpoint should corrupt at least one replay checkpoint block");

    {
        apfsaccess::rw::MetadataStore remounted(replay_trailing_tamper_checkpoint_context);
        ok &= Require(remounted.LoadContainerSuperblocks(), "Replay-trailing-tamper-checkpoint remount LoadContainerSuperblocks should succeed");
        ok &= Require(remounted.PrepareNativeWritePath(), "Replay-trailing-tamper-checkpoint remount PrepareNativeWritePath should succeed");
        ok &= Require(remounted.IsRecoveryRequired(), "Replay-trailing-tamper-checkpoint remount should require recovery");
        ok &= Require(
            remounted.RecoveryReason() == L"PersistentStateAheadOfSuperblock",
            "Replay-trailing-tamper-checkpoint remount should detect persistent state ahead of superblock");
        ok &= Require(
            remounted.ReplayOrRecover(),
            "Replay-trailing-tamper-checkpoint remount should ignore replay-checkpoint trailing-byte tamper and recover");
        ok &= Require(!remounted.IsRecoveryRequired(), "Replay-trailing-tamper-checkpoint remount should clear recovery after replay");
        ok &= Require(remounted.IsCommitPathReady(), "Replay-trailing-tamper-checkpoint remount should restore commit path readiness");
        ok &= Require(
            remounted.CheckpointXid().value_or(0) == (kInitialCheckpointXid + 1),
            "Replay-trailing-tamper-checkpoint remount should keep recovered checkpoint xid");
    }

    const auto replay_out_of_window_checkpoint_image_path = run_root / "container_replay_out_of_window_checkpoint.apfs.img";
    if (!CreateSyntheticContainer(replay_out_of_window_checkpoint_image_path))
    {
        std::cerr << "[FAIL] unable to create synthetic APFS container image for replay-out-of-window-checkpoint scenario" << std::endl;
        return 1;
    }

    apfsaccess::rw::MetadataStore::VolumeContext replay_out_of_window_checkpoint_context
    {
        replay_out_of_window_checkpoint_image_path.wstring(),
        L"ReplayOutOfWindowCheckpoint",
    };
    replay_out_of_window_checkpoint_context.crash_replay_mode = L"ReplayIfSafe";
    {
        apfsaccess::rw::MetadataStore store(replay_out_of_window_checkpoint_context);
        ok &= Require(store.LoadContainerSuperblocks(), "Replay-out-of-window-checkpoint LoadContainerSuperblocks should succeed");
        ok &= Require(store.LoadObjectMap(), "Replay-out-of-window-checkpoint LoadObjectMap should succeed");
        ok &= Require(store.LoadSpacemanState(), "Replay-out-of-window-checkpoint LoadSpacemanState should succeed");
        ok &= Require(store.PrepareNativeWritePath(), "Replay-out-of-window-checkpoint PrepareNativeWritePath should succeed");
        std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
        store.SetFilePayloadProvider(
            [&staged_payloads](const std::wstring& path, std::uint64_t logical_size) -> std::optional<std::vector<std::byte>>
            {
                auto pending = staged_payloads.find(path);
                if (pending == staged_payloads.end())
                {
                    return std::nullopt;
                }

                if (logical_size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
                {
                    return std::nullopt;
                }

                auto payload = pending->second;
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
        create_file.path = L"\\replay_out_of_window_checkpoint.bin";
        ok &= Require(
            store.ApplyMutation(create_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-out-of-window-checkpoint create file should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_file{};
        write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_file.path = L"\\replay_out_of_window_checkpoint.bin";
        write_file.length = 2048;
        ok &= Require(
            store.ApplyMutation(write_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-out-of-window-checkpoint write file should apply");
        staged_payloads[L"\\replay_out_of_window_checkpoint.bin"] = std::vector<std::byte>(2048, static_cast<std::byte>(0x79));

        store.SetCommitStageHook([](std::string_view stage)
        {
            return stage != "before-checkpoint-switch";
        });

        const auto interrupted_commit = store.CommitPendingMutations();
        ok &= Require(
            interrupted_commit == apfsaccess::rw::MetadataStore::CommitStatus::PersistFailed,
            "Replay-out-of-window-checkpoint setup commit should fail at before-checkpoint-switch stage");
        ok &= Require(
            store.IsRecoveryRequired(),
            "Replay-out-of-window-checkpoint setup should require recovery");
    }

    std::size_t corrupted_replay_window_blocks = 0;
    ok &= Require(
        CorruptReplayCheckpointXidWindow(
            replay_out_of_window_checkpoint_image_path,
            /*mutated_source_xid=*/kInitialCheckpointXid + 1,
            /*mutated_target_xid=*/kInitialCheckpointXid + 2,
            corrupted_replay_window_blocks),
        "Replay-out-of-window-checkpoint should corrupt replay checkpoint xid window");
    ok &= Require(
        corrupted_replay_window_blocks >= 1,
        "Replay-out-of-window-checkpoint should corrupt at least one replay checkpoint block");

    {
        apfsaccess::rw::MetadataStore remounted(replay_out_of_window_checkpoint_context);
        ok &= Require(remounted.LoadContainerSuperblocks(), "Replay-out-of-window-checkpoint remount LoadContainerSuperblocks should succeed");
        ok &= Require(remounted.PrepareNativeWritePath(), "Replay-out-of-window-checkpoint remount PrepareNativeWritePath should succeed");
        ok &= Require(remounted.IsRecoveryRequired(), "Replay-out-of-window-checkpoint remount should require recovery");
        ok &= Require(
            remounted.RecoveryReason() == L"PersistentStateAheadOfSuperblock",
            "Replay-out-of-window-checkpoint remount should keep persistent-state ahead-of-superblock recovery reason");
        ok &= Require(
            remounted.ReplayOrRecover(),
            "Replay-out-of-window-checkpoint remount should ignore out-of-window replay checkpoint metadata and recover");
        ok &= Require(!remounted.IsRecoveryRequired(), "Replay-out-of-window-checkpoint remount should clear recovery after replay");
        ok &= Require(remounted.IsCommitPathReady(), "Replay-out-of-window-checkpoint remount should restore commit path readiness");
        ok &= Require(
            remounted.CheckpointXid().value_or(0) == (kInitialCheckpointXid + 1),
            "Replay-out-of-window-checkpoint remount should keep recovered checkpoint xid");
    }

    const auto replay_interrupt_switch_image_path = run_root / "container_replay_interrupt_switch.apfs.img";
    if (!CreateSyntheticContainer(replay_interrupt_switch_image_path))
    {
        std::cerr << "[FAIL] unable to create synthetic APFS container image for replay-interrupt-switch scenario" << std::endl;
        return 1;
    }

    apfsaccess::rw::MetadataStore::VolumeContext replay_interrupt_switch_context
    {
        replay_interrupt_switch_image_path.wstring(),
        L"ReplayInterruptSwitch",
    };
    replay_interrupt_switch_context.crash_replay_mode = L"ReplayIfSafe";
    {
        apfsaccess::rw::MetadataStore store(replay_interrupt_switch_context);
        ok &= Require(store.LoadContainerSuperblocks(), "Replay-interrupt-switch LoadContainerSuperblocks should succeed");
        ok &= Require(store.LoadObjectMap(), "Replay-interrupt-switch LoadObjectMap should succeed");
        ok &= Require(store.LoadSpacemanState(), "Replay-interrupt-switch LoadSpacemanState should succeed");
        ok &= Require(store.PrepareNativeWritePath(), "Replay-interrupt-switch PrepareNativeWritePath should succeed");
        std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
        store.SetFilePayloadProvider(
            [&staged_payloads](const std::wstring& path, std::uint64_t logical_size) -> std::optional<std::vector<std::byte>>
            {
                auto pending = staged_payloads.find(path);
                if (pending == staged_payloads.end())
                {
                    return std::nullopt;
                }

                if (logical_size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
                {
                    return std::nullopt;
                }

                auto payload = pending->second;
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
        create_file.path = L"\\replay_switch.bin";
        ok &= Require(
            store.ApplyMutation(create_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-interrupt-switch create file should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_file{};
        write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_file.path = L"\\replay_switch.bin";
        write_file.length = 1792;
        ok &= Require(
            store.ApplyMutation(write_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-interrupt-switch write file should apply");
        staged_payloads[L"\\replay_switch.bin"] = std::vector<std::byte>(1792, static_cast<std::byte>(0x63));

        store.SetCommitStageHook([](std::string_view stage)
        {
            return stage != "before-checkpoint-switch";
        });

        const auto interrupted_commit = store.CommitPendingMutations();
        ok &= Require(
            interrupted_commit == apfsaccess::rw::MetadataStore::CommitStatus::PersistFailed,
            "Replay-interrupt-switch setup commit should fail at before-checkpoint-switch stage");
        ok &= Require(
            store.IsRecoveryRequired(),
            "Replay-interrupt-switch setup should require recovery");
        ok &= Require(
            store.RecoveryReason() == L"CommitInterruptedBeforeCheckpointSwitch",
            "Replay-interrupt-switch setup should store interrupted checkpoint-switch recovery reason");
    }

    {
        apfsaccess::rw::MetadataStore remounted(replay_interrupt_switch_context);
        ok &= Require(remounted.LoadContainerSuperblocks(), "Replay-interrupt-switch remount LoadContainerSuperblocks should succeed");
        ok &= Require(remounted.PrepareNativeWritePath(), "Replay-interrupt-switch remount PrepareNativeWritePath should succeed");
        ok &= Require(remounted.IsRecoveryRequired(), "Replay-interrupt-switch remount should require recovery");
        ok &= Require(
            remounted.RecoveryReason() == L"PersistentStateAheadOfSuperblock",
            "Replay-interrupt-switch remount should detect persistent state ahead of superblock");
        remounted.SetCommitStageHook([](std::string_view stage)
        {
            return stage != "replay-before-checkpoint-switch";
        });
        ok &= Require(!remounted.ReplayOrRecover(), "Replay-interrupt-switch remount replay should fail at replay-before-checkpoint-switch");
        ok &= Require(remounted.IsRecoveryRequired(), "Replay-interrupt-switch remount should remain recovery-required after replay interruption");
        ok &= Require(!remounted.IsCommitPathReady(), "Replay-interrupt-switch remount should keep commit path blocked after replay interruption");
        ok &= Require(
            remounted.RecoveryReason() == L"ReplayInterruptedBeforeCheckpointSwitch",
            "Replay-interrupt-switch remount should report replay-before-checkpoint-switch interruption");
    }

    const auto replay_interrupt_flush_image_path = run_root / "container_replay_interrupt_flush.apfs.img";
    if (!CreateSyntheticContainer(replay_interrupt_flush_image_path))
    {
        std::cerr << "[FAIL] unable to create synthetic APFS container image for replay-interrupt-flush scenario" << std::endl;
        return 1;
    }

    apfsaccess::rw::MetadataStore::VolumeContext replay_interrupt_flush_context
    {
        replay_interrupt_flush_image_path.wstring(),
        L"ReplayInterruptFlush",
    };
    replay_interrupt_flush_context.crash_replay_mode = L"ReplayIfSafe";
    {
        apfsaccess::rw::MetadataStore store(replay_interrupt_flush_context);
        ok &= Require(store.LoadContainerSuperblocks(), "Replay-interrupt-flush LoadContainerSuperblocks should succeed");
        ok &= Require(store.LoadObjectMap(), "Replay-interrupt-flush LoadObjectMap should succeed");
        ok &= Require(store.LoadSpacemanState(), "Replay-interrupt-flush LoadSpacemanState should succeed");
        ok &= Require(store.PrepareNativeWritePath(), "Replay-interrupt-flush PrepareNativeWritePath should succeed");
        std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
        store.SetFilePayloadProvider(
            [&staged_payloads](const std::wstring& path, std::uint64_t logical_size) -> std::optional<std::vector<std::byte>>
            {
                auto pending = staged_payloads.find(path);
                if (pending == staged_payloads.end())
                {
                    return std::nullopt;
                }

                if (logical_size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
                {
                    return std::nullopt;
                }

                auto payload = pending->second;
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
        create_file.path = L"\\replay_flush.bin";
        ok &= Require(
            store.ApplyMutation(create_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-interrupt-flush create file should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_file{};
        write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_file.path = L"\\replay_flush.bin";
        write_file.length = 2048;
        ok &= Require(
            store.ApplyMutation(write_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-interrupt-flush write file should apply");
        staged_payloads[L"\\replay_flush.bin"] = std::vector<std::byte>(2048, static_cast<std::byte>(0x64));

        store.SetCommitStageHook([](std::string_view stage)
        {
            return stage != "before-checkpoint-switch";
        });

        const auto interrupted_commit = store.CommitPendingMutations();
        ok &= Require(
            interrupted_commit == apfsaccess::rw::MetadataStore::CommitStatus::PersistFailed,
            "Replay-interrupt-flush setup commit should fail at before-checkpoint-switch stage");
        ok &= Require(
            store.IsRecoveryRequired(),
            "Replay-interrupt-flush setup should require recovery");
        ok &= Require(
            store.RecoveryReason() == L"CommitInterruptedBeforeCheckpointSwitch",
            "Replay-interrupt-flush setup should store interrupted checkpoint-switch recovery reason");
    }

    {
        apfsaccess::rw::MetadataStore remounted(replay_interrupt_flush_context);
        ok &= Require(remounted.LoadContainerSuperblocks(), "Replay-interrupt-flush remount LoadContainerSuperblocks should succeed");
        ok &= Require(remounted.PrepareNativeWritePath(), "Replay-interrupt-flush remount PrepareNativeWritePath should succeed");
        ok &= Require(remounted.IsRecoveryRequired(), "Replay-interrupt-flush remount should require recovery");
        ok &= Require(
            remounted.RecoveryReason() == L"PersistentStateAheadOfSuperblock",
            "Replay-interrupt-flush remount should detect persistent state ahead of superblock");
        remounted.SetCommitStageHook([](std::string_view stage)
        {
            return stage != "replay-before-checkpoint-flush";
        });
        ok &= Require(!remounted.ReplayOrRecover(), "Replay-interrupt-flush remount replay should fail at replay-before-checkpoint-flush");
        ok &= Require(remounted.IsRecoveryRequired(), "Replay-interrupt-flush remount should remain recovery-required after replay interruption");
        ok &= Require(!remounted.IsCommitPathReady(), "Replay-interrupt-flush remount should keep commit path blocked after replay interruption");
        ok &= Require(
            remounted.RecoveryReason() == L"ReplayInterruptedBeforeCheckpointFlush",
            "Replay-interrupt-flush remount should report replay-before-checkpoint-flush interruption");
    }

    const auto replay_checkpoint_write_fail_image_path = run_root / "container_replay_checkpoint_write_fail.apfs.img";
    if (!CreateSyntheticContainer(replay_checkpoint_write_fail_image_path))
    {
        std::cerr << "[FAIL] unable to create synthetic APFS container image for replay-checkpoint-write-fail scenario" << std::endl;
        return 1;
    }

    apfsaccess::rw::MetadataStore::VolumeContext replay_checkpoint_write_fail_context
    {
        replay_checkpoint_write_fail_image_path.wstring(),
        L"ReplayCheckpointWriteFail",
    };
    replay_checkpoint_write_fail_context.crash_replay_mode = L"ReplayIfSafe";
    {
        apfsaccess::rw::MetadataStore store(replay_checkpoint_write_fail_context);
        ok &= Require(store.LoadContainerSuperblocks(), "Replay-checkpoint-write-fail LoadContainerSuperblocks should succeed");
        ok &= Require(store.LoadObjectMap(), "Replay-checkpoint-write-fail LoadObjectMap should succeed");
        ok &= Require(store.LoadSpacemanState(), "Replay-checkpoint-write-fail LoadSpacemanState should succeed");
        ok &= Require(store.PrepareNativeWritePath(), "Replay-checkpoint-write-fail PrepareNativeWritePath should succeed");
        std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
        store.SetFilePayloadProvider(
            [&staged_payloads](const std::wstring& path, std::uint64_t logical_size) -> std::optional<std::vector<std::byte>>
            {
                auto pending = staged_payloads.find(path);
                if (pending == staged_payloads.end())
                {
                    return std::nullopt;
                }

                if (logical_size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
                {
                    return std::nullopt;
                }

                auto payload = pending->second;
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
        create_file.path = L"\\replay_write_fail.bin";
        ok &= Require(
            store.ApplyMutation(create_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-checkpoint-write-fail create file should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_file{};
        write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_file.path = L"\\replay_write_fail.bin";
        write_file.length = 2048;
        ok &= Require(
            store.ApplyMutation(write_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-checkpoint-write-fail write file should apply");
        staged_payloads[L"\\replay_write_fail.bin"] = std::vector<std::byte>(2048, static_cast<std::byte>(0x71));

        store.SetCommitStageHook([](std::string_view stage)
        {
            return stage != "before-checkpoint-switch";
        });

        const auto interrupted_commit = store.CommitPendingMutations();
        ok &= Require(
            interrupted_commit == apfsaccess::rw::MetadataStore::CommitStatus::PersistFailed,
            "Replay-checkpoint-write-fail setup commit should fail at before-checkpoint-switch stage");
        ok &= Require(
            store.IsRecoveryRequired(),
            "Replay-checkpoint-write-fail setup should require recovery");
    }

    {
        apfsaccess::rw::MetadataStore remounted(replay_checkpoint_write_fail_context);
        ok &= Require(remounted.LoadContainerSuperblocks(), "Replay-checkpoint-write-fail remount LoadContainerSuperblocks should succeed");
        ok &= Require(remounted.PrepareNativeWritePath(), "Replay-checkpoint-write-fail remount PrepareNativeWritePath should succeed");
        ok &= Require(remounted.IsRecoveryRequired(), "Replay-checkpoint-write-fail remount should require recovery");
        ok &= Require(
            remounted.RecoveryReason() == L"PersistentStateAheadOfSuperblock",
            "Replay-checkpoint-write-fail remount should detect persistent state ahead of superblock");

        ScopedEnvironmentVariable write_fault(L"APFSACCESS_RW_FAULT_WRITE", L"1");
        ok &= Require(!remounted.ReplayOrRecover(), "Replay-checkpoint-write-fail remount replay should fail with device write fault");
        ok &= Require(remounted.IsRecoveryRequired(), "Replay-checkpoint-write-fail remount should remain recovery-required");
        ok &= Require(!remounted.IsCommitPathReady(), "Replay-checkpoint-write-fail remount should keep commit path blocked");
        ok &= Require(
            remounted.RecoveryReason() == L"ReplayCheckpointWriteFailed",
            "Replay-checkpoint-write-fail remount should report ReplayCheckpointWriteFailed");
    }

    const auto replay_checkpoint_flush_fail_image_path = run_root / "container_replay_checkpoint_flush_fail.apfs.img";
    if (!CreateSyntheticContainer(replay_checkpoint_flush_fail_image_path))
    {
        std::cerr << "[FAIL] unable to create synthetic APFS container image for replay-checkpoint-flush-fail scenario" << std::endl;
        return 1;
    }

    apfsaccess::rw::MetadataStore::VolumeContext replay_checkpoint_flush_fail_context
    {
        replay_checkpoint_flush_fail_image_path.wstring(),
        L"ReplayCheckpointFlushFail",
    };
    replay_checkpoint_flush_fail_context.crash_replay_mode = L"ReplayIfSafe";
    {
        apfsaccess::rw::MetadataStore store(replay_checkpoint_flush_fail_context);
        ok &= Require(store.LoadContainerSuperblocks(), "Replay-checkpoint-flush-fail LoadContainerSuperblocks should succeed");
        ok &= Require(store.LoadObjectMap(), "Replay-checkpoint-flush-fail LoadObjectMap should succeed");
        ok &= Require(store.LoadSpacemanState(), "Replay-checkpoint-flush-fail LoadSpacemanState should succeed");
        ok &= Require(store.PrepareNativeWritePath(), "Replay-checkpoint-flush-fail PrepareNativeWritePath should succeed");
        std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
        store.SetFilePayloadProvider(
            [&staged_payloads](const std::wstring& path, std::uint64_t logical_size) -> std::optional<std::vector<std::byte>>
            {
                auto pending = staged_payloads.find(path);
                if (pending == staged_payloads.end())
                {
                    return std::nullopt;
                }

                if (logical_size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
                {
                    return std::nullopt;
                }

                auto payload = pending->second;
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
        create_file.path = L"\\replay_flush_fail.bin";
        ok &= Require(
            store.ApplyMutation(create_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-checkpoint-flush-fail create file should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_file{};
        write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_file.path = L"\\replay_flush_fail.bin";
        write_file.length = 2048;
        ok &= Require(
            store.ApplyMutation(write_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-checkpoint-flush-fail write file should apply");
        staged_payloads[L"\\replay_flush_fail.bin"] = std::vector<std::byte>(2048, static_cast<std::byte>(0x72));

        store.SetCommitStageHook([](std::string_view stage)
        {
            return stage != "before-checkpoint-switch";
        });

        const auto interrupted_commit = store.CommitPendingMutations();
        ok &= Require(
            interrupted_commit == apfsaccess::rw::MetadataStore::CommitStatus::PersistFailed,
            "Replay-checkpoint-flush-fail setup commit should fail at before-checkpoint-switch stage");
        ok &= Require(
            store.IsRecoveryRequired(),
            "Replay-checkpoint-flush-fail setup should require recovery");
    }

    {
        apfsaccess::rw::MetadataStore remounted(replay_checkpoint_flush_fail_context);
        ok &= Require(remounted.LoadContainerSuperblocks(), "Replay-checkpoint-flush-fail remount LoadContainerSuperblocks should succeed");
        ok &= Require(remounted.PrepareNativeWritePath(), "Replay-checkpoint-flush-fail remount PrepareNativeWritePath should succeed");
        ok &= Require(remounted.IsRecoveryRequired(), "Replay-checkpoint-flush-fail remount should require recovery");
        ok &= Require(
            remounted.RecoveryReason() == L"PersistentStateAheadOfSuperblock",
            "Replay-checkpoint-flush-fail remount should detect persistent state ahead of superblock");

        ScopedEnvironmentVariable flush_fault(L"APFSACCESS_RW_FAULT_FLUSH", L"1");
        ok &= Require(!remounted.ReplayOrRecover(), "Replay-checkpoint-flush-fail remount replay should fail with device flush fault");
        ok &= Require(remounted.IsRecoveryRequired(), "Replay-checkpoint-flush-fail remount should remain recovery-required");
        ok &= Require(!remounted.IsCommitPathReady(), "Replay-checkpoint-flush-fail remount should keep commit path blocked");
        ok &= Require(
            remounted.RecoveryReason() == L"ReplayCheckpointFlushFailed",
            "Replay-checkpoint-flush-fail remount should report ReplayCheckpointFlushFailed");
    }

    const auto replay_corrupt_object_map_image_path = run_root / "container_replay_corrupt_object_map.apfs.img";
    if (!CreateSyntheticContainer(replay_corrupt_object_map_image_path))
    {
        std::cerr << "[FAIL] unable to create synthetic APFS container image for replay-corrupt-object-map scenario" << std::endl;
        return 1;
    }

    apfsaccess::rw::MetadataStore::VolumeContext replay_corrupt_object_map_context
    {
        replay_corrupt_object_map_image_path.wstring(),
        L"ReplayCorruptObjectMap",
    };
    replay_corrupt_object_map_context.crash_replay_mode = L"ReplayIfSafe";
    {
        apfsaccess::rw::MetadataStore store(replay_corrupt_object_map_context);
        ok &= Require(store.LoadContainerSuperblocks(), "Replay-corrupt-object-map LoadContainerSuperblocks should succeed");
        ok &= Require(store.LoadObjectMap(), "Replay-corrupt-object-map LoadObjectMap should succeed");
        ok &= Require(store.LoadSpacemanState(), "Replay-corrupt-object-map LoadSpacemanState should succeed");
        ok &= Require(store.PrepareNativeWritePath(), "Replay-corrupt-object-map PrepareNativeWritePath should succeed");
        std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
        store.SetFilePayloadProvider(
            [&staged_payloads](const std::wstring& path, std::uint64_t logical_size) -> std::optional<std::vector<std::byte>>
            {
                auto pending = staged_payloads.find(path);
                if (pending == staged_payloads.end())
                {
                    return std::nullopt;
                }
                if (logical_size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
                {
                    return std::nullopt;
                }

                auto payload = pending->second;
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
        create_file.path = L"\\replay_corrupt_omap.bin";
        ok &= Require(
            store.ApplyMutation(create_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-corrupt-object-map create file should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_file{};
        write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_file.path = L"\\replay_corrupt_omap.bin";
        write_file.length = 2048;
        ok &= Require(
            store.ApplyMutation(write_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-corrupt-object-map write file should apply");
        staged_payloads[L"\\replay_corrupt_omap.bin"] = std::vector<std::byte>(2048, static_cast<std::byte>(0x73));

        store.SetCommitStageHook([](std::string_view stage)
        {
            return stage != "before-checkpoint-switch";
        });

        const auto interrupted_commit = store.CommitPendingMutations();
        ok &= Require(
            interrupted_commit == apfsaccess::rw::MetadataStore::CommitStatus::PersistFailed,
            "Replay-corrupt-object-map setup commit should fail at before-checkpoint-switch stage");
        ok &= Require(
            store.IsRecoveryRequired(),
            "Replay-corrupt-object-map setup should require recovery");
    }

    {
        const auto persistent_state_path = BuildPersistentStatePath(
            replay_corrupt_object_map_context.device_path,
            replay_corrupt_object_map_context.volume_name);
        ok &= Require(
            CorruptPersistentStateObjectMapLogicalSizeForPath(
                persistent_state_path,
                L"\\replay_corrupt_omap.bin",
                /*logical_size=*/0),
            "Replay-corrupt-object-map should mutate persistent-state object-map semantics");
    }

    {
        auto replay_corrupt_object_map_recovery_context = replay_corrupt_object_map_context;
        replay_corrupt_object_map_recovery_context.integrity_check_on_mount = false;
        apfsaccess::rw::MetadataStore remounted(replay_corrupt_object_map_recovery_context);
        ok &= Require(remounted.LoadContainerSuperblocks(), "Replay-corrupt-object-map remount LoadContainerSuperblocks should succeed");
        ok &= Require(remounted.PrepareNativeWritePath(), "Replay-corrupt-object-map remount PrepareNativeWritePath should succeed");
        ok &= Require(remounted.IsRecoveryRequired(), "Replay-corrupt-object-map remount should require recovery");
        ok &= Require(
            remounted.RecoveryReason() == L"PersistentStateAheadOfSuperblock",
            "Replay-corrupt-object-map remount should detect persistent state ahead of superblock");
        ok &= Require(!remounted.ReplayOrRecover(), "Replay-corrupt-object-map remount replay should fail integrity checks");
        ok &= Require(remounted.IsRecoveryRequired(), "Replay-corrupt-object-map remount should remain recovery-required");
        ok &= Require(!remounted.IsCommitPathReady(), "Replay-corrupt-object-map remount should keep commit path blocked");
        ok &= Require(
            remounted.RecoveryReason() == L"ReplayIntegrityCheckFailed",
            "Replay-corrupt-object-map remount should report ReplayIntegrityCheckFailed");
    }

    const auto replay_corrupt_spaceman_image_path = run_root / "container_replay_corrupt_spaceman.apfs.img";
    if (!CreateSyntheticContainer(replay_corrupt_spaceman_image_path))
    {
        std::cerr << "[FAIL] unable to create synthetic APFS container image for replay-corrupt-spaceman scenario" << std::endl;
        return 1;
    }

    apfsaccess::rw::MetadataStore::VolumeContext replay_corrupt_spaceman_context
    {
        replay_corrupt_spaceman_image_path.wstring(),
        L"ReplayCorruptSpaceman",
    };
    replay_corrupt_spaceman_context.crash_replay_mode = L"ReplayIfSafe";
    {
        apfsaccess::rw::MetadataStore store(replay_corrupt_spaceman_context);
        ok &= Require(store.LoadContainerSuperblocks(), "Replay-corrupt-spaceman LoadContainerSuperblocks should succeed");
        ok &= Require(store.LoadObjectMap(), "Replay-corrupt-spaceman LoadObjectMap should succeed");
        ok &= Require(store.LoadSpacemanState(), "Replay-corrupt-spaceman LoadSpacemanState should succeed");
        ok &= Require(store.PrepareNativeWritePath(), "Replay-corrupt-spaceman PrepareNativeWritePath should succeed");
        std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
        store.SetFilePayloadProvider(
            [&staged_payloads](const std::wstring& path, std::uint64_t logical_size) -> std::optional<std::vector<std::byte>>
            {
                auto pending = staged_payloads.find(path);
                if (pending == staged_payloads.end())
                {
                    return std::nullopt;
                }
                if (logical_size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
                {
                    return std::nullopt;
                }

                auto payload = pending->second;
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
        create_file.path = L"\\replay_corrupt_spaceman.bin";
        ok &= Require(
            store.ApplyMutation(create_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-corrupt-spaceman create file should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_file{};
        write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_file.path = L"\\replay_corrupt_spaceman.bin";
        write_file.length = 2048;
        ok &= Require(
            store.ApplyMutation(write_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-corrupt-spaceman write file should apply");
        staged_payloads[L"\\replay_corrupt_spaceman.bin"] = std::vector<std::byte>(2048, static_cast<std::byte>(0x74));

        store.SetCommitStageHook([](std::string_view stage)
        {
            return stage != "before-checkpoint-switch";
        });

        const auto interrupted_commit = store.CommitPendingMutations();
        ok &= Require(
            interrupted_commit == apfsaccess::rw::MetadataStore::CommitStatus::PersistFailed,
            "Replay-corrupt-spaceman setup commit should fail at before-checkpoint-switch stage");
        ok &= Require(
            store.IsRecoveryRequired(),
            "Replay-corrupt-spaceman setup should require recovery");
    }

    {
        const auto persistent_state_path = BuildPersistentStatePath(
            replay_corrupt_spaceman_context.device_path,
            replay_corrupt_spaceman_context.volume_name);
        ok &= Require(
            CorruptPersistentStateSpacemanAllocationForPath(
                persistent_state_path,
                L"\\replay_corrupt_spaceman.bin",
                /*mutated_physical_address=*/0x0000FFFF00000000ull),
            "Replay-corrupt-spaceman should mutate persistent-state spaceman semantics");
    }

    {
        auto replay_corrupt_spaceman_recovery_context = replay_corrupt_spaceman_context;
        replay_corrupt_spaceman_recovery_context.integrity_check_on_mount = false;
        apfsaccess::rw::MetadataStore remounted(replay_corrupt_spaceman_recovery_context);
        ok &= Require(remounted.LoadContainerSuperblocks(), "Replay-corrupt-spaceman remount LoadContainerSuperblocks should succeed");
        ok &= Require(remounted.PrepareNativeWritePath(), "Replay-corrupt-spaceman remount PrepareNativeWritePath should succeed");
        ok &= Require(remounted.IsRecoveryRequired(), "Replay-corrupt-spaceman remount should require recovery");
        ok &= Require(
            remounted.RecoveryReason() == L"PersistentStateAheadOfSuperblock",
            "Replay-corrupt-spaceman remount should detect persistent state ahead of superblock");
        ok &= Require(remounted.ReplayOrRecover(), "Replay-corrupt-spaceman remount replay should recover through persistent-state parser fallback");
        ok &= Require(!remounted.IsRecoveryRequired(), "Replay-corrupt-spaceman remount should clear recovery after fallback replay");
        ok &= Require(remounted.IsCommitPathReady(), "Replay-corrupt-spaceman remount should restore commit path readiness after fallback replay");
    }

    const auto object_map_persist_fault_image_path = run_root / "container_object_map_persist_fault.apfs.img";
    if (!CreateSyntheticContainer(object_map_persist_fault_image_path))
    {
        std::cerr << "[FAIL] unable to create synthetic APFS container image for object-map persist fault scenario" << std::endl;
        return 1;
    }

    apfsaccess::rw::MetadataStore::VolumeContext object_map_persist_fault_context
    {
        object_map_persist_fault_image_path.wstring(),
        L"ObjectMapPersistFaults",
    };
    {
        apfsaccess::rw::MetadataStore store(object_map_persist_fault_context);
        ok &= Require(store.LoadContainerSuperblocks(), "Object-map persist fault LoadContainerSuperblocks should succeed");
        ok &= Require(store.LoadObjectMap(), "Object-map persist fault LoadObjectMap should succeed");
        ok &= Require(store.LoadSpacemanState(), "Object-map persist fault LoadSpacemanState should succeed");
        ok &= Require(store.PrepareNativeWritePath(), "Object-map persist fault PrepareNativeWritePath should succeed");
        std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
        store.SetFilePayloadProvider(
            [&staged_payloads](const std::wstring& path, std::uint64_t logical_size) -> std::optional<std::vector<std::byte>>
            {
                auto pending = staged_payloads.find(path);
                if (pending == staged_payloads.end())
                {
                    return std::nullopt;
                }

                if (logical_size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
                {
                    return std::nullopt;
                }

                auto payload = pending->second;
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
        create_file.path = L"\\omapfault.bin";
        ok &= Require(
            store.ApplyMutation(create_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Object-map persist fault create file should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_file{};
        write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_file.path = L"\\omapfault.bin";
        write_file.length = 896;
        ok &= Require(
            store.ApplyMutation(write_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Object-map persist fault write file should apply");
        staged_payloads[L"\\omapfault.bin"] = std::vector<std::byte>(896, static_cast<std::byte>(0x3F));

        store.SetCommitStageHook([](std::string_view stage)
        {
            return stage != "before-object-map-persist";
        });

        const auto object_map_persist_fault_commit = store.CommitPendingMutations();
        ok &= Require(
            object_map_persist_fault_commit == apfsaccess::rw::MetadataStore::CommitStatus::PersistFailed,
            "Object-map persist fault commit should fail with PersistFailed");
        ok &= Require(
            store.LastCommittedXid().value_or(0) == (kInitialCheckpointXid + 1),
            "Object-map persist fault should retain promoted xid");
        ok &= Require(
            store.IsRecoveryRequired(),
            "Object-map persist fault should latch recovery-required state");
        ok &= Require(
            store.RecoveryReason() == L"CommitInterruptedBeforeObjectMapPersist",
            "Object-map persist fault should set recovery reason");
        ok &= Require(
            !store.IsCommitPathReady(),
            "Object-map persist fault should block commit path");
        const auto blocked_retry_after_object_map_persist_fault = store.CommitPendingMutations();
        ok &= Require(
            blocked_retry_after_object_map_persist_fault == apfsaccess::rw::MetadataStore::CommitStatus::NotWritable,
            "Object-map persist fault should fail-closed on retry");
    }

    const auto spaceman_persist_fault_image_path = run_root / "container_spaceman_persist_fault.apfs.img";
    if (!CreateSyntheticContainer(spaceman_persist_fault_image_path))
    {
        std::cerr << "[FAIL] unable to create synthetic APFS container image for spaceman persist fault scenario" << std::endl;
        return 1;
    }

    apfsaccess::rw::MetadataStore::VolumeContext spaceman_persist_fault_context
    {
        spaceman_persist_fault_image_path.wstring(),
        L"SpacemanPersistFaults",
    };
    {
        apfsaccess::rw::MetadataStore store(spaceman_persist_fault_context);
        ok &= Require(store.LoadContainerSuperblocks(), "Spaceman persist fault LoadContainerSuperblocks should succeed");
        ok &= Require(store.LoadObjectMap(), "Spaceman persist fault LoadObjectMap should succeed");
        ok &= Require(store.LoadSpacemanState(), "Spaceman persist fault LoadSpacemanState should succeed");
        ok &= Require(store.PrepareNativeWritePath(), "Spaceman persist fault PrepareNativeWritePath should succeed");
        std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
        store.SetFilePayloadProvider(
            [&staged_payloads](const std::wstring& path, std::uint64_t logical_size) -> std::optional<std::vector<std::byte>>
            {
                auto pending = staged_payloads.find(path);
                if (pending == staged_payloads.end())
                {
                    return std::nullopt;
                }

                if (logical_size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
                {
                    return std::nullopt;
                }

                auto payload = pending->second;
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
        create_file.path = L"\\spmfault.bin";
        ok &= Require(
            store.ApplyMutation(create_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Spaceman persist fault create file should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_file{};
        write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_file.path = L"\\spmfault.bin";
        write_file.length = 1152;
        ok &= Require(
            store.ApplyMutation(write_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Spaceman persist fault write file should apply");
        staged_payloads[L"\\spmfault.bin"] = std::vector<std::byte>(1152, static_cast<std::byte>(0x64));

        store.SetCommitStageHook([](std::string_view stage)
        {
            return stage != "before-spaceman-persist";
        });

        const auto spaceman_persist_fault_commit = store.CommitPendingMutations();
        ok &= Require(
            spaceman_persist_fault_commit == apfsaccess::rw::MetadataStore::CommitStatus::PersistFailed,
            "Spaceman persist fault commit should fail with PersistFailed");
        ok &= Require(
            store.LastCommittedXid().value_or(0) == (kInitialCheckpointXid + 1),
            "Spaceman persist fault should retain promoted xid");
        ok &= Require(
            store.IsRecoveryRequired(),
            "Spaceman persist fault should latch recovery-required state");
        ok &= Require(
            store.RecoveryReason() == L"CommitInterruptedBeforeSpacemanPersist",
            "Spaceman persist fault should set recovery reason");
        ok &= Require(
            !store.IsCommitPathReady(),
            "Spaceman persist fault should block commit path");
        const auto blocked_retry_after_spaceman_persist_fault = store.CommitPendingMutations();
        ok &= Require(
            blocked_retry_after_spaceman_persist_fault == apfsaccess::rw::MetadataStore::CommitStatus::NotWritable,
            "Spaceman persist fault should fail-closed on retry");
    }

    const auto inode_persist_fault_image_path = run_root / "container_inode_persist_fault.apfs.img";
    if (!CreateSyntheticContainer(inode_persist_fault_image_path))
    {
        std::cerr << "[FAIL] unable to create synthetic APFS container image for inode persist fault scenario" << std::endl;
        return 1;
    }

    apfsaccess::rw::MetadataStore::VolumeContext inode_persist_fault_context
    {
        inode_persist_fault_image_path.wstring(),
        L"InodePersistFaults",
    };
    {
        apfsaccess::rw::MetadataStore store(inode_persist_fault_context);
        ok &= Require(store.LoadContainerSuperblocks(), "Inode persist fault LoadContainerSuperblocks should succeed");
        ok &= Require(store.LoadObjectMap(), "Inode persist fault LoadObjectMap should succeed");
        ok &= Require(store.LoadSpacemanState(), "Inode persist fault LoadSpacemanState should succeed");
        ok &= Require(store.PrepareNativeWritePath(), "Inode persist fault PrepareNativeWritePath should succeed");
        std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
        store.SetFilePayloadProvider(
            [&staged_payloads](const std::wstring& path, std::uint64_t logical_size) -> std::optional<std::vector<std::byte>>
            {
                auto pending = staged_payloads.find(path);
                if (pending == staged_payloads.end())
                {
                    return std::nullopt;
                }

                if (logical_size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
                {
                    return std::nullopt;
                }

                auto payload = pending->second;
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
        create_file.path = L"\\inodefault.bin";
        ok &= Require(
            store.ApplyMutation(create_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Inode persist fault create file should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_file{};
        write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_file.path = L"\\inodefault.bin";
        write_file.length = 1280;
        ok &= Require(
            store.ApplyMutation(write_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Inode persist fault write file should apply");
        staged_payloads[L"\\inodefault.bin"] = std::vector<std::byte>(1280, static_cast<std::byte>(0x79));

        store.SetCommitStageHook([](std::string_view stage)
        {
            return stage != "before-inode-persist";
        });

        const auto inode_persist_fault_commit = store.CommitPendingMutations();
        ok &= Require(
            inode_persist_fault_commit == apfsaccess::rw::MetadataStore::CommitStatus::PersistFailed,
            "Inode persist fault commit should fail with PersistFailed");
        ok &= Require(
            store.LastCommittedXid().value_or(0) == (kInitialCheckpointXid + 1),
            "Inode persist fault should retain promoted xid");
        ok &= Require(
            store.IsRecoveryRequired(),
            "Inode persist fault should latch recovery-required state");
        ok &= Require(
            store.RecoveryReason() == L"CommitInterruptedBeforeInodePersist",
            "Inode persist fault should set recovery reason");
        ok &= Require(
            !store.IsCommitPathReady(),
            "Inode persist fault should block commit path");
        const auto blocked_retry_after_inode_persist_fault = store.CommitPendingMutations();
        ok &= Require(
            blocked_retry_after_inode_persist_fault == apfsaccess::rw::MetadataStore::CommitStatus::NotWritable,
            "Inode persist fault should fail-closed on retry");
    }

    const auto btree_persist_fault_image_path = run_root / "container_btree_persist_fault.apfs.img";
    if (!CreateSyntheticContainer(btree_persist_fault_image_path))
    {
        std::cerr << "[FAIL] unable to create synthetic APFS container image for btree persist fault scenario" << std::endl;
        return 1;
    }

    apfsaccess::rw::MetadataStore::VolumeContext btree_persist_fault_context
    {
        btree_persist_fault_image_path.wstring(),
        L"BtreePersistFaults",
    };
    {
        apfsaccess::rw::MetadataStore store(btree_persist_fault_context);
        ok &= Require(store.LoadContainerSuperblocks(), "Btree persist fault LoadContainerSuperblocks should succeed");
        ok &= Require(store.LoadObjectMap(), "Btree persist fault LoadObjectMap should succeed");
        ok &= Require(store.LoadSpacemanState(), "Btree persist fault LoadSpacemanState should succeed");
        ok &= Require(store.PrepareNativeWritePath(), "Btree persist fault PrepareNativeWritePath should succeed");
        std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
        store.SetFilePayloadProvider(
            [&staged_payloads](const std::wstring& path, std::uint64_t logical_size) -> std::optional<std::vector<std::byte>>
            {
                auto pending = staged_payloads.find(path);
                if (pending == staged_payloads.end())
                {
                    return std::nullopt;
                }

                if (logical_size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
                {
                    return std::nullopt;
                }

                auto payload = pending->second;
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
        create_file.path = L"\\btreefault.bin";
        ok &= Require(
            store.ApplyMutation(create_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Btree persist fault create file should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_file{};
        write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_file.path = L"\\btreefault.bin";
        write_file.length = 1664;
        ok &= Require(
            store.ApplyMutation(write_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Btree persist fault write file should apply");
        staged_payloads[L"\\btreefault.bin"] = std::vector<std::byte>(1664, static_cast<std::byte>(0x55));

        store.SetCommitStageHook([](std::string_view stage)
        {
            return stage != "before-btree-persist";
        });

        const auto btree_persist_fault_commit = store.CommitPendingMutations();
        ok &= Require(
            btree_persist_fault_commit == apfsaccess::rw::MetadataStore::CommitStatus::PersistFailed,
            "Btree persist fault commit should fail with PersistFailed");
        ok &= Require(
            store.LastCommittedXid().value_or(0) == (kInitialCheckpointXid + 1),
            "Btree persist fault should retain promoted xid");
        ok &= Require(
            store.IsRecoveryRequired(),
            "Btree persist fault should latch recovery-required state");
        ok &= Require(
            store.RecoveryReason() == L"CommitInterruptedBeforeBtreePersist",
            "Btree persist fault should set recovery reason");
        ok &= Require(
            !store.IsCommitPathReady(),
            "Btree persist fault should block commit path");
        const auto blocked_retry_after_btree_persist_fault = store.CommitPendingMutations();
        ok &= Require(
            blocked_retry_after_btree_persist_fault == apfsaccess::rw::MetadataStore::CommitStatus::NotWritable,
            "Btree persist fault should fail-closed on retry");
    }

    const auto replay_roundtrip_fault_image_path = run_root / "container_replay_roundtrip_fault.apfs.img";
    if (!CreateSyntheticContainer(replay_roundtrip_fault_image_path))
    {
        std::cerr << "[FAIL] unable to create synthetic APFS container image for replay-roundtrip fault scenario" << std::endl;
        return 1;
    }

    apfsaccess::rw::MetadataStore::VolumeContext replay_roundtrip_fault_context
    {
        replay_roundtrip_fault_image_path.wstring(),
        L"ReplayRoundTripFaults",
    };
    {
        apfsaccess::rw::MetadataStore store(replay_roundtrip_fault_context);
        ok &= Require(store.LoadContainerSuperblocks(), "Replay-roundtrip fault LoadContainerSuperblocks should succeed");
        ok &= Require(store.LoadObjectMap(), "Replay-roundtrip fault LoadObjectMap should succeed");
        ok &= Require(store.LoadSpacemanState(), "Replay-roundtrip fault LoadSpacemanState should succeed");
        ok &= Require(store.PrepareNativeWritePath(), "Replay-roundtrip fault PrepareNativeWritePath should succeed");
        std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
        store.SetFilePayloadProvider(
            [&staged_payloads](const std::wstring& path, std::uint64_t logical_size) -> std::optional<std::vector<std::byte>>
            {
                auto pending = staged_payloads.find(path);
                if (pending == staged_payloads.end())
                {
                    return std::nullopt;
                }

                if (logical_size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
                {
                    return std::nullopt;
                }

                auto payload = pending->second;
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
        create_file.path = L"\\replayroundtrip.bin";
        ok &= Require(
            store.ApplyMutation(create_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-roundtrip fault create file should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_file{};
        write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_file.path = L"\\replayroundtrip.bin";
        write_file.length = 1728;
        ok &= Require(
            store.ApplyMutation(write_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-roundtrip fault write file should apply");
        staged_payloads[L"\\replayroundtrip.bin"] = std::vector<std::byte>(1728, static_cast<std::byte>(0x5A));

        bool replay_roundtrip_tamper_attempted = false;
        bool replay_roundtrip_tamper_succeeded = false;
        std::size_t replay_roundtrip_corrupted_blocks = 0;
        store.SetCommitStageHook([&](std::string_view stage)
        {
            if (stage == "before-replay-roundtrip-verify")
            {
                replay_roundtrip_tamper_attempted = true;
                std::size_t corrupted_blocks = 0;
                replay_roundtrip_tamper_succeeded =
                    CorruptReplayCheckpointPayloadBytes(
                        replay_roundtrip_fault_image_path,
                        /*mutated_payload_bytes=*/16,
                        corrupted_blocks);
                replay_roundtrip_corrupted_blocks = corrupted_blocks;
            }
            return true;
        });

        const auto replay_roundtrip_fault_commit = store.CommitPendingMutations();
        ok &= Require(
            replay_roundtrip_tamper_attempted,
            "Replay-roundtrip fault should execute tamper hook before replay round-trip verification");
        ok &= Require(
            replay_roundtrip_tamper_succeeded,
            "Replay-roundtrip fault should tamper replay checkpoint payload bytes");
        ok &= Require(
            replay_roundtrip_corrupted_blocks >= 1,
            "Replay-roundtrip fault should corrupt at least one replay checkpoint block");
        ok &= Require(
            replay_roundtrip_fault_commit == apfsaccess::rw::MetadataStore::CommitStatus::PersistFailed,
            "Replay-roundtrip fault commit should fail with PersistFailed");
        ok &= Require(
            store.LastCommittedXid().value_or(0) == (kInitialCheckpointXid + 1),
            "Replay-roundtrip fault should retain promoted xid");
        ok &= Require(
            store.IsRecoveryRequired(),
            "Replay-roundtrip fault should latch recovery-required state");
        ok &= Require(
            store.RecoveryReason() == L"CommitReplayRoundTripFailed",
            "Replay-roundtrip fault should set replay round-trip recovery reason");
        ok &= Require(
            !store.IsCommitPathReady(),
            "Replay-roundtrip fault should block commit path");
        const auto blocked_retry_after_replay_roundtrip_fault = store.CommitPendingMutations();
        ok &= Require(
            blocked_retry_after_replay_roundtrip_fault == apfsaccess::rw::MetadataStore::CommitStatus::NotWritable,
            "Replay-roundtrip fault should fail-closed on retry");
    }

    const auto checkpoint_roundtrip_interrupt_image_path = run_root / "container_checkpoint_roundtrip_interrupt.apfs.img";
    if (!CreateSyntheticContainer(checkpoint_roundtrip_interrupt_image_path))
    {
        std::cerr << "[FAIL] unable to create synthetic APFS container image for checkpoint-roundtrip interruption scenario" << std::endl;
        return 1;
    }

    apfsaccess::rw::MetadataStore::VolumeContext checkpoint_roundtrip_interrupt_context
    {
        checkpoint_roundtrip_interrupt_image_path.wstring(),
        L"CheckpointRoundTripInterrupt",
    };
    {
        apfsaccess::rw::MetadataStore store(checkpoint_roundtrip_interrupt_context);
        ok &= Require(store.LoadContainerSuperblocks(), "Checkpoint-roundtrip interrupt LoadContainerSuperblocks should succeed");
        ok &= Require(store.LoadObjectMap(), "Checkpoint-roundtrip interrupt LoadObjectMap should succeed");
        ok &= Require(store.LoadSpacemanState(), "Checkpoint-roundtrip interrupt LoadSpacemanState should succeed");
        ok &= Require(store.PrepareNativeWritePath(), "Checkpoint-roundtrip interrupt PrepareNativeWritePath should succeed");
        std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
        store.SetFilePayloadProvider(
            [&staged_payloads](const std::wstring& path, std::uint64_t logical_size) -> std::optional<std::vector<std::byte>>
            {
                auto pending = staged_payloads.find(path);
                if (pending == staged_payloads.end())
                {
                    return std::nullopt;
                }

                if (logical_size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
                {
                    return std::nullopt;
                }

                auto payload = pending->second;
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
        create_file.path = L"\\checkpointroundtripinterrupt.bin";
        ok &= Require(
            store.ApplyMutation(create_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Checkpoint-roundtrip interrupt create file should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_file{};
        write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_file.path = L"\\checkpointroundtripinterrupt.bin";
        write_file.length = 1664;
        ok &= Require(
            store.ApplyMutation(write_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Checkpoint-roundtrip interrupt write file should apply");
        staged_payloads[L"\\checkpointroundtripinterrupt.bin"] =
            std::vector<std::byte>(1664, static_cast<std::byte>(0x4C));

        store.SetCommitStageHook([](std::string_view stage)
        {
            return stage != "before-checkpoint-roundtrip-verify";
        });

        const auto checkpoint_roundtrip_interrupt_commit = store.CommitPendingMutations();
        ok &= Require(
            checkpoint_roundtrip_interrupt_commit == apfsaccess::rw::MetadataStore::CommitStatus::PersistFailed,
            "Checkpoint-roundtrip interrupt commit should fail with PersistFailed");
        ok &= Require(
            store.LastCommittedXid().value_or(0) == (kInitialCheckpointXid + 1),
            "Checkpoint-roundtrip interrupt should retain promoted xid");
        ok &= Require(
            store.IsRecoveryRequired(),
            "Checkpoint-roundtrip interrupt should latch recovery-required state");
        ok &= Require(
            store.RecoveryReason() == L"CommitInterruptedBeforeCheckpointRoundTripVerify",
            "Checkpoint-roundtrip interrupt should set checkpoint round-trip interruption recovery reason");
        ok &= Require(
            !store.IsCommitPathReady(),
            "Checkpoint-roundtrip interrupt should block commit path");
        const auto blocked_retry_after_checkpoint_roundtrip_interrupt = store.CommitPendingMutations();
        ok &= Require(
            blocked_retry_after_checkpoint_roundtrip_interrupt == apfsaccess::rw::MetadataStore::CommitStatus::NotWritable,
            "Checkpoint-roundtrip interrupt should fail-closed on retry");
    }

    const auto checkpoint_roundtrip_fault_image_path = run_root / "container_checkpoint_roundtrip_fault.apfs.img";
    if (!CreateSyntheticContainer(checkpoint_roundtrip_fault_image_path))
    {
        std::cerr << "[FAIL] unable to create synthetic APFS container image for checkpoint-roundtrip fault scenario" << std::endl;
        return 1;
    }

    apfsaccess::rw::MetadataStore::VolumeContext checkpoint_roundtrip_fault_context
    {
        checkpoint_roundtrip_fault_image_path.wstring(),
        L"CheckpointRoundTripFaults",
    };
    {
        apfsaccess::rw::MetadataStore store(checkpoint_roundtrip_fault_context);
        ok &= Require(store.LoadContainerSuperblocks(), "Checkpoint-roundtrip fault LoadContainerSuperblocks should succeed");
        ok &= Require(store.LoadObjectMap(), "Checkpoint-roundtrip fault LoadObjectMap should succeed");
        ok &= Require(store.LoadSpacemanState(), "Checkpoint-roundtrip fault LoadSpacemanState should succeed");
        ok &= Require(store.PrepareNativeWritePath(), "Checkpoint-roundtrip fault PrepareNativeWritePath should succeed");
        std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
        store.SetFilePayloadProvider(
            [&staged_payloads](const std::wstring& path, std::uint64_t logical_size) -> std::optional<std::vector<std::byte>>
            {
                auto pending = staged_payloads.find(path);
                if (pending == staged_payloads.end())
                {
                    return std::nullopt;
                }

                if (logical_size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
                {
                    return std::nullopt;
                }

                auto payload = pending->second;
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
        create_file.path = L"\\checkpointroundtripfault.bin";
        ok &= Require(
            store.ApplyMutation(create_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Checkpoint-roundtrip fault create file should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_file{};
        write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_file.path = L"\\checkpointroundtripfault.bin";
        write_file.length = 1792;
        ok &= Require(
            store.ApplyMutation(write_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Checkpoint-roundtrip fault write file should apply");
        staged_payloads[L"\\checkpointroundtripfault.bin"] = std::vector<std::byte>(1792, static_cast<std::byte>(0x63));

        bool checkpoint_roundtrip_tamper_attempted = false;
        bool checkpoint_roundtrip_tamper_succeeded = false;
        std::size_t checkpoint_roundtrip_corrupted_superblocks = 0;
        store.SetCommitStageHook([&](std::string_view stage)
        {
            if (stage == "before-checkpoint-roundtrip-verify")
            {
                checkpoint_roundtrip_tamper_attempted = true;
                std::size_t corrupted_superblocks = 0;
                checkpoint_roundtrip_tamper_succeeded = CorruptSuperblockCheckpointXids(
                    checkpoint_roundtrip_fault_image_path,
                    /*replacement_xid=*/0,
                    corrupted_superblocks);
                checkpoint_roundtrip_corrupted_superblocks = corrupted_superblocks;
            }
            return true;
        });

        const auto checkpoint_roundtrip_fault_commit = store.CommitPendingMutations();
        ok &= Require(
            checkpoint_roundtrip_tamper_attempted,
            "Checkpoint-roundtrip fault should execute tamper hook before checkpoint round-trip verification");
        ok &= Require(
            checkpoint_roundtrip_tamper_succeeded,
            "Checkpoint-roundtrip fault should tamper checkpoint superblock xid");
        ok &= Require(
            checkpoint_roundtrip_corrupted_superblocks >= 1,
            "Checkpoint-roundtrip fault should corrupt at least one superblock");
        ok &= Require(
            checkpoint_roundtrip_fault_commit == apfsaccess::rw::MetadataStore::CommitStatus::PersistFailed,
            "Checkpoint-roundtrip fault commit should fail with PersistFailed");
        ok &= Require(
            store.LastCommittedXid().value_or(0) == (kInitialCheckpointXid + 1),
            "Checkpoint-roundtrip fault should retain promoted xid");
        ok &= Require(
            store.IsRecoveryRequired(),
            "Checkpoint-roundtrip fault should latch recovery-required state");
        ok &= Require(
            store.RecoveryReason() == L"CommitCheckpointRoundTripFailed",
            "Checkpoint-roundtrip fault should set checkpoint round-trip recovery reason");
        ok &= Require(
            !store.IsCommitPathReady(),
            "Checkpoint-roundtrip fault should block commit path");
        const auto blocked_retry_after_checkpoint_roundtrip_fault = store.CommitPendingMutations();
        ok &= Require(
            blocked_retry_after_checkpoint_roundtrip_fault == apfsaccess::rw::MetadataStore::CommitStatus::NotWritable,
            "Checkpoint-roundtrip fault should fail-closed on retry");
    }

    const auto flush_fault_image_path = run_root / "container_flush_fault.apfs.img";
    if (!CreateSyntheticContainer(flush_fault_image_path))
    {
        std::cerr << "[FAIL] unable to create synthetic APFS container image for flush-fault scenario" << std::endl;
        return 1;
    }

    apfsaccess::rw::MetadataStore::VolumeContext flush_fault_context
    {
        flush_fault_image_path.wstring(),
        L"FlushFaults",
    };
    {
        apfsaccess::rw::MetadataStore store(flush_fault_context);
        ok &= Require(store.LoadContainerSuperblocks(), "Flush-fault LoadContainerSuperblocks should succeed");
        ok &= Require(store.LoadObjectMap(), "Flush-fault LoadObjectMap should succeed");
        ok &= Require(store.LoadSpacemanState(), "Flush-fault LoadSpacemanState should succeed");
        ok &= Require(store.PrepareNativeWritePath(), "Flush-fault PrepareNativeWritePath should succeed");
        std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
        store.SetFilePayloadProvider(
            [&staged_payloads](const std::wstring& path, std::uint64_t logical_size) -> std::optional<std::vector<std::byte>>
            {
                auto pending = staged_payloads.find(path);
                if (pending == staged_payloads.end())
                {
                    return std::nullopt;
                }

                if (logical_size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
                {
                    return std::nullopt;
                }

                auto payload = pending->second;
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
        create_file.path = L"\\flush.bin";
        ok &= Require(
            store.ApplyMutation(create_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Flush-fault create file should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_file{};
        write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_file.path = L"\\flush.bin";
        write_file.length = 1536;
        ok &= Require(
            store.ApplyMutation(write_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Flush-fault write file should apply");
        staged_payloads[L"\\flush.bin"] = std::vector<std::byte>(1536, static_cast<std::byte>(0x7A));

        store.SetCommitStageHook([](std::string_view stage)
        {
            return stage != "before-checkpoint-flush";
        });

        const auto flush_stage_fault_commit = store.CommitPendingMutations();
        ok &= Require(
            flush_stage_fault_commit == apfsaccess::rw::MetadataStore::CommitStatus::FlushFailed,
            "Commit should fail with FlushFailed at before-checkpoint-flush stage");
        ok &= Require(
            store.LastCommittedXid().value_or(0) == (kInitialCheckpointXid + 1),
            "Flush-stage failure should retain promoted xid");
        ok &= Require(
            store.IsRecoveryRequired(),
            "Flush-stage failure should latch recovery-required state in-session");
        ok &= Require(
            !store.IsCommitPathReady(),
            "Flush-stage failure should block commit path in-session");
        ok &= Require(
            store.RecoveryReason() == L"CommitInterruptedBeforeCheckpointFlush",
            "Flush-stage failure should set in-session recovery reason");
        ok &= Require(
            store.PendingMutationCount() > 0,
            "Flush-stage failure should retain pending mutations for conservative handling");
        const auto blocked_retry_after_flush_stage = store.CommitPendingMutations();
        ok &= Require(
            blocked_retry_after_flush_stage == apfsaccess::rw::MetadataStore::CommitStatus::NotWritable,
            "Recovery-latched flush-stage failure should fail-closed on retry");
    }

    const auto btree_corrupt_mount_image_path = run_root / "container_btree_corrupt_mount.apfs.img";
    if (!CreateSyntheticContainer(btree_corrupt_mount_image_path))
    {
        std::cerr << "[FAIL] unable to create synthetic APFS container image for btree corruption mount scenario" << std::endl;
        return 1;
    }

    apfsaccess::rw::MetadataStore::VolumeContext btree_corrupt_mount_context
    {
        btree_corrupt_mount_image_path.wstring(),
        L"BtreeCorruptMount",
    };
    {
        apfsaccess::rw::MetadataStore store(btree_corrupt_mount_context);
        ok &= Require(store.LoadContainerSuperblocks(), "Btree corruption mount LoadContainerSuperblocks should succeed");
        ok &= Require(store.LoadObjectMap(), "Btree corruption mount LoadObjectMap should succeed");
        ok &= Require(store.LoadSpacemanState(), "Btree corruption mount LoadSpacemanState should succeed");
        ok &= Require(store.PrepareNativeWritePath(), "Btree corruption mount PrepareNativeWritePath should succeed");
        std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
        store.SetFilePayloadProvider(
            [&staged_payloads](const std::wstring& path, std::uint64_t logical_size) -> std::optional<std::vector<std::byte>>
            {
                auto pending = staged_payloads.find(path);
                if (pending == staged_payloads.end())
                {
                    return std::nullopt;
                }

                if (logical_size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
                {
                    return std::nullopt;
                }

                auto payload = pending->second;
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
        create_file.path = L"\\corrupt.bin";
        ok &= Require(
            store.ApplyMutation(create_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Btree corruption mount create file should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_file{};
        write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_file.path = L"\\corrupt.bin";
        write_file.length = 2048;
        ok &= Require(
            store.ApplyMutation(write_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Btree corruption mount write file should apply");
        staged_payloads[L"\\corrupt.bin"] = std::vector<std::byte>(2048, static_cast<std::byte>(0x61));

        const auto commit_result = store.CommitPendingMutations();
        ok &= Require(
            commit_result == apfsaccess::rw::MetadataStore::CommitStatus::Committed,
            "Btree corruption mount setup commit should succeed");
        ok &= Require(
            store.CommittedBtreeRecordCount() > 0,
            "Btree corruption mount setup should persist btree records");
        ok &= Require(
            store.LastCommittedXid().value_or(0) == (kInitialCheckpointXid + 1),
            "Btree corruption mount setup commit should promote xid");
    }

    {
        const auto persistent_state_path = BuildPersistentStatePath(
            btree_corrupt_mount_context.device_path,
            btree_corrupt_mount_context.volume_name);
        if (!persistent_state_path.empty())
        {
            std::filesystem::remove(persistent_state_path, ec);
        }
    }

    constexpr std::array<char, 12> kBtreeCheckpointMagic =
    {
        'A', 'P', 'F', 'S', 'R', 'W', 'B', 'T', 'R', '5', '\0', '\0'
    };
    std::size_t corrupted_blocks = 0;
    ok &= Require(
        CorruptBlocksWithMagicPrefix(
            btree_corrupt_mount_image_path,
            kBtreeCheckpointMagic,
            /*mutate_offset=*/0,
            static_cast<std::byte>(0x00),
            corrupted_blocks),
        "Btree corruption mount should locate and corrupt persisted btree checkpoint blocks");
    ok &= Require(
        corrupted_blocks >= 1,
        "Btree corruption mount should corrupt at least one btree checkpoint block");

    {
        apfsaccess::rw::MetadataStore remounted(btree_corrupt_mount_context);
        ok &= Require(
            remounted.LoadContainerSuperblocks(),
            "Btree corruption remount LoadContainerSuperblocks should succeed");
        ok &= Require(
            !remounted.PrepareNativeWritePath(),
            "Btree corruption remount should fail native-write preparation (fail-closed)");
        ok &= Require(
            !remounted.IsNativeWriteReady(),
            "Btree corruption remount should leave native-write readiness disabled");
        ok &= Require(
            !remounted.IsCommitPathReady(),
            "Btree corruption remount should keep commit path blocked");
        ok &= Require(
            remounted.IsRecoveryRequired(),
            "Btree corruption remount should latch recovery-required state");
        ok &= Require(
            remounted.RecoveryReason() == L"IntegrityCheckFailedOnMount",
            "Btree corruption remount should report integrity-check recovery reason");
    }

    const auto object_map_corrupt_mount_image_path = run_root / "container_object_map_corrupt_mount.apfs.img";
    if (!CreateSyntheticContainer(object_map_corrupt_mount_image_path))
    {
        std::cerr << "[FAIL] unable to create synthetic APFS container image for object-map corruption mount scenario" << std::endl;
        return 1;
    }

    apfsaccess::rw::MetadataStore::VolumeContext object_map_corrupt_mount_context
    {
        object_map_corrupt_mount_image_path.wstring(),
        L"ObjectMapCorruptMount",
    };
    {
        apfsaccess::rw::MetadataStore store(object_map_corrupt_mount_context);
        ok &= Require(store.LoadContainerSuperblocks(), "Object-map corruption mount LoadContainerSuperblocks should succeed");
        ok &= Require(store.LoadObjectMap(), "Object-map corruption mount LoadObjectMap should succeed");
        ok &= Require(store.LoadSpacemanState(), "Object-map corruption mount LoadSpacemanState should succeed");
        ok &= Require(store.PrepareNativeWritePath(), "Object-map corruption mount PrepareNativeWritePath should succeed");
        std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
        store.SetFilePayloadProvider(
            [&staged_payloads](const std::wstring& path, std::uint64_t logical_size) -> std::optional<std::vector<std::byte>>
            {
                auto pending = staged_payloads.find(path);
                if (pending == staged_payloads.end())
                {
                    return std::nullopt;
                }

                if (logical_size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
                {
                    return std::nullopt;
                }

                auto payload = pending->second;
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
        create_file.path = L"\\omap.bin";
        ok &= Require(
            store.ApplyMutation(create_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Object-map corruption mount create file should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_file{};
        write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_file.path = L"\\omap.bin";
        write_file.length = 1536;
        ok &= Require(
            store.ApplyMutation(write_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Object-map corruption mount write file should apply");
        staged_payloads[L"\\omap.bin"] = std::vector<std::byte>(1536, static_cast<std::byte>(0x28));

        const auto commit_result = store.CommitPendingMutations();
        ok &= Require(
            commit_result == apfsaccess::rw::MetadataStore::CommitStatus::Committed,
            "Object-map corruption mount setup commit should succeed");
        ok &= Require(
            store.CommittedObjectCount() > 0,
            "Object-map corruption mount setup should persist object-map records");
    }

    {
        const auto persistent_state_path = BuildPersistentStatePath(
            object_map_corrupt_mount_context.device_path,
            object_map_corrupt_mount_context.volume_name);
        if (!persistent_state_path.empty())
        {
            std::filesystem::remove(persistent_state_path, ec);
        }
    }

    std::size_t corrupted_object_map_blocks = 0;
    ok &= Require(
        CorruptObjectMapCheckpointLogicalSize(
            object_map_corrupt_mount_image_path,
            /*logical_size=*/0,
            corrupted_object_map_blocks),
        "Object-map corruption mount should locate and mutate persisted object-map checkpoints");
    ok &= Require(
        corrupted_object_map_blocks >= 1,
        "Object-map corruption mount should mutate at least one object-map checkpoint block");

    {
        apfsaccess::rw::MetadataStore remounted(object_map_corrupt_mount_context);
        ok &= Require(
            remounted.LoadContainerSuperblocks(),
            "Object-map corruption remount LoadContainerSuperblocks should succeed");
        ok &= Require(
            !remounted.PrepareNativeWritePath(),
            "Object-map corruption remount should fail native-write preparation (fail-closed)");
        ok &= Require(
            !remounted.IsNativeWriteReady(),
            "Object-map corruption remount should leave native-write readiness disabled");
        ok &= Require(
            !remounted.IsCommitPathReady(),
            "Object-map corruption remount should keep commit path blocked");
        ok &= Require(
            remounted.IsRecoveryRequired(),
            "Object-map corruption remount should latch recovery-required state");
        ok &= Require(
            remounted.RecoveryReason() == L"IntegrityCheckFailedOnMount",
            "Object-map corruption remount should report integrity-check recovery reason");
    }

    const auto replay_blob_invalid_image_path = run_root / "container_replay_blob_invalid.apfs.img";
    if (!CreateSyntheticContainer(replay_blob_invalid_image_path))
    {
        std::cerr << "[FAIL] unable to create synthetic APFS container image for replay-blob-invalid scenario" << std::endl;
        return 1;
    }

    apfsaccess::rw::MetadataStore::VolumeContext replay_blob_invalid_context
    {
        replay_blob_invalid_image_path.wstring(),
        L"ReplayBlobInvalid",
    };
    replay_blob_invalid_context.crash_replay_mode = L"ReplayIfSafe";
    {
        apfsaccess::rw::MetadataStore store(replay_blob_invalid_context);
        ok &= Require(store.LoadContainerSuperblocks(), "Replay-blob-invalid LoadContainerSuperblocks should succeed");
        ok &= Require(store.LoadObjectMap(), "Replay-blob-invalid LoadObjectMap should succeed");
        ok &= Require(store.LoadSpacemanState(), "Replay-blob-invalid LoadSpacemanState should succeed");
        ok &= Require(store.PrepareNativeWritePath(), "Replay-blob-invalid PrepareNativeWritePath should succeed");
        std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
        store.SetFilePayloadProvider(
            [&staged_payloads](const std::wstring& path, std::uint64_t logical_size) -> std::optional<std::vector<std::byte>>
            {
                auto pending = staged_payloads.find(path);
                if (pending == staged_payloads.end())
                {
                    return std::nullopt;
                }

                if (logical_size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
                {
                    return std::nullopt;
                }

                auto payload = pending->second;
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
        create_file.path = L"\\replayblob.bin";
        ok &= Require(
            store.ApplyMutation(create_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-blob-invalid create file should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_file{};
        write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_file.path = L"\\replayblob.bin";
        write_file.length = 2048;
        ok &= Require(
            store.ApplyMutation(write_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-blob-invalid write file should apply");
        staged_payloads[L"\\replayblob.bin"] = std::vector<std::byte>(2048, static_cast<std::byte>(0x42));

        store.SetCommitStageHook([](std::string_view stage)
        {
            return stage != "before-checkpoint-switch";
        });

        const auto interrupted_commit = store.CommitPendingMutations();
        ok &= Require(
            interrupted_commit == apfsaccess::rw::MetadataStore::CommitStatus::PersistFailed,
            "Replay-blob-invalid commit should fail at before-checkpoint-switch stage");
        ok &= Require(
            store.IsRecoveryRequired(),
            "Replay-blob-invalid should require recovery after interrupted checkpoint switch");
    }

    constexpr std::array<unsigned char, 13> kCommitBlobMagic =
    {
        'A', 'P', 'F', 'S', 'R', 'W', 'S', 'C', 'A', 'F', 'F', '3', '\0'
    };
    std::size_t corrupted_magic_offset = 0;
    ok &= Require(
        CorruptFirstMagicOccurrence(
            replay_blob_invalid_image_path,
            std::vector<unsigned char>(kCommitBlobMagic.begin(), kCommitBlobMagic.end()),
            /*mutate_offset=*/0,
            static_cast<std::byte>(0x00),
            corrupted_magic_offset),
        "Replay-blob-invalid should locate and corrupt commit-blob magic");

    {
        apfsaccess::rw::MetadataStore remounted(replay_blob_invalid_context);
        ok &= Require(remounted.LoadContainerSuperblocks(), "Replay-blob-invalid remount LoadContainerSuperblocks should succeed");
        ok &= Require(remounted.PrepareNativeWritePath(), "Replay-blob-invalid remount PrepareNativeWritePath should succeed");
        ok &= Require(remounted.IsRecoveryRequired(), "Replay-blob-invalid remount should require recovery before replay");
        ok &= Require(!remounted.ReplayOrRecover(), "Replay-blob-invalid remount replay should fail");
        ok &= Require(remounted.IsRecoveryRequired(), "Replay-blob-invalid remount should remain recovery-required after replay failure");
        ok &= Require(!remounted.IsCommitPathReady(), "Replay-blob-invalid remount should keep commit path blocked");
        ok &= Require(
            IsReplayCommitBlobRejectedReason(remounted.RecoveryReason()),
            "Replay-blob-invalid remount should report replay commit-blob rejection reason");
    }

    const auto replay_blob_checksum_invalid_image_path = run_root / "container_replay_blob_checksum_invalid.apfs.img";
    if (!CreateSyntheticContainer(replay_blob_checksum_invalid_image_path))
    {
        std::cerr << "[FAIL] unable to create synthetic APFS container image for replay-blob-checksum-invalid scenario" << std::endl;
        return 1;
    }

    apfsaccess::rw::MetadataStore::VolumeContext replay_blob_checksum_invalid_context
    {
        replay_blob_checksum_invalid_image_path.wstring(),
        L"ReplayBlobChecksumInvalid",
    };
    replay_blob_checksum_invalid_context.crash_replay_mode = L"ReplayIfSafe";
    {
        apfsaccess::rw::MetadataStore store(replay_blob_checksum_invalid_context);
        ok &= Require(store.LoadContainerSuperblocks(), "Replay-blob-checksum-invalid LoadContainerSuperblocks should succeed");
        ok &= Require(store.LoadObjectMap(), "Replay-blob-checksum-invalid LoadObjectMap should succeed");
        ok &= Require(store.LoadSpacemanState(), "Replay-blob-checksum-invalid LoadSpacemanState should succeed");
        ok &= Require(store.PrepareNativeWritePath(), "Replay-blob-checksum-invalid PrepareNativeWritePath should succeed");
        std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
        store.SetFilePayloadProvider(
            [&staged_payloads](const std::wstring& path, std::uint64_t logical_size) -> std::optional<std::vector<std::byte>>
            {
                auto pending = staged_payloads.find(path);
                if (pending == staged_payloads.end())
                {
                    return std::nullopt;
                }

                if (logical_size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
                {
                    return std::nullopt;
                }

                auto payload = pending->second;
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
        create_file.path = L"\\replayblobchecksum.bin";
        ok &= Require(
            store.ApplyMutation(create_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-blob-checksum-invalid create file should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_file{};
        write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_file.path = L"\\replayblobchecksum.bin";
        write_file.length = 2048;
        ok &= Require(
            store.ApplyMutation(write_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-blob-checksum-invalid write file should apply");
        staged_payloads[L"\\replayblobchecksum.bin"] = std::vector<std::byte>(2048, static_cast<std::byte>(0x43));

        store.SetCommitStageHook([](std::string_view stage)
        {
            return stage != "before-checkpoint-switch";
        });

        const auto interrupted_commit = store.CommitPendingMutations();
        ok &= Require(
            interrupted_commit == apfsaccess::rw::MetadataStore::CommitStatus::PersistFailed,
            "Replay-blob-checksum-invalid commit should fail at before-checkpoint-switch stage");
        ok &= Require(
            store.IsRecoveryRequired(),
            "Replay-blob-checksum-invalid should require recovery after interrupted checkpoint switch");
    }

    std::size_t corrupted_payload_offset = 0;
    ok &= Require(
        CorruptFirstMagicOccurrence(
            replay_blob_checksum_invalid_image_path,
            std::vector<unsigned char>(kCommitBlobMagic.begin(), kCommitBlobMagic.end()),
            /*mutate_offset=*/64,
            static_cast<std::byte>(0xA5),
            corrupted_payload_offset),
        "Replay-blob-checksum-invalid should locate and corrupt commit-blob payload");

    {
        apfsaccess::rw::MetadataStore remounted(replay_blob_checksum_invalid_context);
        ok &= Require(remounted.LoadContainerSuperblocks(), "Replay-blob-checksum-invalid remount LoadContainerSuperblocks should succeed");
        ok &= Require(remounted.PrepareNativeWritePath(), "Replay-blob-checksum-invalid remount PrepareNativeWritePath should succeed");
        ok &= Require(remounted.IsRecoveryRequired(), "Replay-blob-checksum-invalid remount should require recovery before replay");
        ok &= Require(!remounted.ReplayOrRecover(), "Replay-blob-checksum-invalid remount replay should fail");
        ok &= Require(remounted.IsRecoveryRequired(), "Replay-blob-checksum-invalid remount should remain recovery-required after replay failure");
        ok &= Require(!remounted.IsCommitPathReady(), "Replay-blob-checksum-invalid remount should keep commit path blocked");
        ok &= Require(
            IsReplayCommitBlobRejectedReason(remounted.RecoveryReason()),
            "Replay-blob-checksum-invalid remount should report replay commit-blob rejection reason");
    }

    const auto replay_blob_semantic_invalid_image_path = run_root / "container_replay_blob_semantic_invalid.apfs.img";
    if (!CreateSyntheticContainer(replay_blob_semantic_invalid_image_path))
    {
        std::cerr << "[FAIL] unable to create synthetic APFS container image for replay-blob-semantic-invalid scenario" << std::endl;
        return 1;
    }

    apfsaccess::rw::MetadataStore::VolumeContext replay_blob_semantic_invalid_context
    {
        replay_blob_semantic_invalid_image_path.wstring(),
        L"ReplayBlobSemanticInvalid",
    };
    replay_blob_semantic_invalid_context.crash_replay_mode = L"ReplayIfSafe";
    {
        apfsaccess::rw::MetadataStore store(replay_blob_semantic_invalid_context);
        ok &= Require(store.LoadContainerSuperblocks(), "Replay-blob-semantic-invalid LoadContainerSuperblocks should succeed");
        ok &= Require(store.LoadObjectMap(), "Replay-blob-semantic-invalid LoadObjectMap should succeed");
        ok &= Require(store.LoadSpacemanState(), "Replay-blob-semantic-invalid LoadSpacemanState should succeed");
        ok &= Require(store.PrepareNativeWritePath(), "Replay-blob-semantic-invalid PrepareNativeWritePath should succeed");
        std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
        store.SetFilePayloadProvider(
            [&staged_payloads](const std::wstring& path, std::uint64_t logical_size) -> std::optional<std::vector<std::byte>>
            {
                auto pending = staged_payloads.find(path);
                if (pending == staged_payloads.end())
                {
                    return std::nullopt;
                }

                if (logical_size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
                {
                    return std::nullopt;
                }

                auto payload = pending->second;
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
        create_file.path = L"\\replayblobsemantic.bin";
        ok &= Require(
            store.ApplyMutation(create_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-blob-semantic-invalid create file should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_file{};
        write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_file.path = L"\\replayblobsemantic.bin";
        write_file.length = 2048;
        ok &= Require(
            store.ApplyMutation(write_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-blob-semantic-invalid write file should apply");
        staged_payloads[L"\\replayblobsemantic.bin"] = std::vector<std::byte>(2048, static_cast<std::byte>(0x44));

        store.SetCommitStageHook([](std::string_view stage)
        {
            return stage != "before-checkpoint-switch";
        });

        const auto interrupted_commit = store.CommitPendingMutations();
        ok &= Require(
            interrupted_commit == apfsaccess::rw::MetadataStore::CommitStatus::PersistFailed,
            "Replay-blob-semantic-invalid commit should fail at before-checkpoint-switch stage");
        ok &= Require(
            store.IsRecoveryRequired(),
            "Replay-blob-semantic-invalid should require recovery after interrupted checkpoint switch");
    }

    std::size_t corrupted_semantic_offset = 0;
    ok &= Require(
        CorruptCommitBlobObjectMapLogicalSizeWithValidChecksum(
            replay_blob_semantic_invalid_image_path,
            /*logical_size=*/1,
            corrupted_semantic_offset),
        "Replay-blob-semantic-invalid should corrupt commit-blob object-map update while preserving checksum");

    {
        apfsaccess::rw::MetadataStore remounted(replay_blob_semantic_invalid_context);
        ok &= Require(remounted.LoadContainerSuperblocks(), "Replay-blob-semantic-invalid remount LoadContainerSuperblocks should succeed");
        ok &= Require(remounted.PrepareNativeWritePath(), "Replay-blob-semantic-invalid remount PrepareNativeWritePath should succeed");
        ok &= Require(remounted.IsRecoveryRequired(), "Replay-blob-semantic-invalid remount should require recovery before replay");
        ok &= Require(!remounted.ReplayOrRecover(), "Replay-blob-semantic-invalid remount replay should fail semantic checks");
        ok &= Require(remounted.IsRecoveryRequired(), "Replay-blob-semantic-invalid remount should remain recovery-required after replay failure");
        ok &= Require(!remounted.IsCommitPathReady(), "Replay-blob-semantic-invalid remount should keep commit path blocked");
        ok &= Require(
            IsReplayCommitBlobRejectedReason(remounted.RecoveryReason()),
            "Replay-blob-semantic-invalid remount should report replay commit-blob rejection reason");
    }

    const auto replay_blob_duplicate_object_map_invalid_image_path =
        run_root / "container_replay_blob_duplicate_object_map_invalid.apfs.img";
    if (!CreateSyntheticContainer(replay_blob_duplicate_object_map_invalid_image_path))
    {
        std::cerr
            << "[FAIL] unable to create synthetic APFS container image for replay-blob-duplicate-object-map-invalid scenario"
            << std::endl;
        return 1;
    }

    apfsaccess::rw::MetadataStore::VolumeContext replay_blob_duplicate_object_map_invalid_context
    {
        replay_blob_duplicate_object_map_invalid_image_path.wstring(),
        L"ReplayBlobDuplicateObjectMapInvalid",
    };
    replay_blob_duplicate_object_map_invalid_context.crash_replay_mode = L"ReplayIfSafe";
    {
        apfsaccess::rw::MetadataStore store(replay_blob_duplicate_object_map_invalid_context);
        ok &= Require(
            store.LoadContainerSuperblocks(),
            "Replay-blob-duplicate-object-map-invalid LoadContainerSuperblocks should succeed");
        ok &= Require(
            store.LoadObjectMap(),
            "Replay-blob-duplicate-object-map-invalid LoadObjectMap should succeed");
        ok &= Require(
            store.LoadSpacemanState(),
            "Replay-blob-duplicate-object-map-invalid LoadSpacemanState should succeed");
        ok &= Require(
            store.PrepareNativeWritePath(),
            "Replay-blob-duplicate-object-map-invalid PrepareNativeWritePath should succeed");
        std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
        store.SetFilePayloadProvider(
            [&staged_payloads](const std::wstring& path, std::uint64_t logical_size) -> std::optional<std::vector<std::byte>>
            {
                auto pending = staged_payloads.find(path);
                if (pending == staged_payloads.end())
                {
                    return std::nullopt;
                }

                if (logical_size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
                {
                    return std::nullopt;
                }

                auto payload = pending->second;
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

        constexpr auto kReplayBlobDuplicateObjectMapPath = L"\\replayblobomapduplicate.bin";

        apfsaccess::rw::MetadataStore::MutationRequest create_file{};
        create_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
        create_file.path = kReplayBlobDuplicateObjectMapPath;
        ok &= Require(
            store.ApplyMutation(create_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-blob-duplicate-object-map-invalid create file should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_file{};
        write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_file.path = kReplayBlobDuplicateObjectMapPath;
        write_file.length = 3072;
        ok &= Require(
            store.ApplyMutation(write_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-blob-duplicate-object-map-invalid write file should apply");
        staged_payloads[kReplayBlobDuplicateObjectMapPath] =
            std::vector<std::byte>(3072, static_cast<std::byte>(0x62));

        store.SetCommitStageHook([](std::string_view stage)
        {
            return stage != "before-checkpoint-switch";
        });

        const auto interrupted_commit = store.CommitPendingMutations();
        ok &= Require(
            interrupted_commit == apfsaccess::rw::MetadataStore::CommitStatus::PersistFailed,
            "Replay-blob-duplicate-object-map-invalid commit should fail at before-checkpoint-switch stage");
        ok &= Require(
            store.IsRecoveryRequired(),
            "Replay-blob-duplicate-object-map-invalid should require recovery after interrupted checkpoint switch");
    }

    std::size_t corrupted_duplicate_object_map_offset = 0;
    ok &= Require(
        CorruptCommitBlobDuplicateFirstObjectMapUpdateWithValidChecksum(
            replay_blob_duplicate_object_map_invalid_image_path,
            corrupted_duplicate_object_map_offset),
        "Replay-blob-duplicate-object-map-invalid should duplicate first object-map update while preserving checksum");

    {
        apfsaccess::rw::MetadataStore remounted(replay_blob_duplicate_object_map_invalid_context);
        ok &= Require(
            remounted.LoadContainerSuperblocks(),
            "Replay-blob-duplicate-object-map-invalid remount LoadContainerSuperblocks should succeed");
        ok &= Require(
            remounted.PrepareNativeWritePath(),
            "Replay-blob-duplicate-object-map-invalid remount PrepareNativeWritePath should succeed");
        ok &= Require(
            remounted.IsRecoveryRequired(),
            "Replay-blob-duplicate-object-map-invalid remount should require recovery before replay");
        ok &= Require(
            !remounted.ReplayOrRecover(),
            "Replay-blob-duplicate-object-map-invalid remount replay should fail semantic checks");
        ok &= Require(
            remounted.IsRecoveryRequired(),
            "Replay-blob-duplicate-object-map-invalid remount should remain recovery-required after replay failure");
        ok &= Require(
            !remounted.IsCommitPathReady(),
            "Replay-blob-duplicate-object-map-invalid remount should keep commit path blocked");
        ok &= Require(
            IsReplayCommitBlobRejectedReason(remounted.RecoveryReason()),
            "Replay-blob-duplicate-object-map-invalid remount should report replay commit-blob rejection reason");
    }

    const auto replay_blob_tombstone_invalid_image_path = run_root / "container_replay_blob_tombstone_invalid.apfs.img";
    if (!CreateSyntheticContainer(replay_blob_tombstone_invalid_image_path))
    {
        std::cerr << "[FAIL] unable to create synthetic APFS container image for replay-blob-tombstone-invalid scenario" << std::endl;
        return 1;
    }

    apfsaccess::rw::MetadataStore::VolumeContext replay_blob_tombstone_invalid_context
    {
        replay_blob_tombstone_invalid_image_path.wstring(),
        L"ReplayBlobTombstoneInvalid",
    };
    replay_blob_tombstone_invalid_context.crash_replay_mode = L"ReplayIfSafe";
    {
        apfsaccess::rw::MetadataStore store(replay_blob_tombstone_invalid_context);
        ok &= Require(store.LoadContainerSuperblocks(), "Replay-blob-tombstone-invalid LoadContainerSuperblocks should succeed");
        ok &= Require(store.LoadObjectMap(), "Replay-blob-tombstone-invalid LoadObjectMap should succeed");
        ok &= Require(store.LoadSpacemanState(), "Replay-blob-tombstone-invalid LoadSpacemanState should succeed");
        ok &= Require(store.PrepareNativeWritePath(), "Replay-blob-tombstone-invalid PrepareNativeWritePath should succeed");

        std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
        store.SetFilePayloadProvider(
            [&staged_payloads](const std::wstring& path, std::uint64_t logical_size) -> std::optional<std::vector<std::byte>>
            {
                auto pending = staged_payloads.find(path);
                if (pending == staged_payloads.end())
                {
                    return std::nullopt;
                }

                if (logical_size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
                {
                    return std::nullopt;
                }

                auto payload = pending->second;
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

        constexpr auto kReplayBlobTombstoneFilePath = L"\\replayblobtombstone.bin";

        apfsaccess::rw::MetadataStore::MutationRequest create_file{};
        create_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
        create_file.path = kReplayBlobTombstoneFilePath;
        ok &= Require(
            store.ApplyMutation(create_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-blob-tombstone-invalid create file should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_file{};
        write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_file.path = kReplayBlobTombstoneFilePath;
        write_file.length = 1536;
        ok &= Require(
            store.ApplyMutation(write_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-blob-tombstone-invalid write file should apply");
        staged_payloads[kReplayBlobTombstoneFilePath] = std::vector<std::byte>(1536, static_cast<std::byte>(0x45));

        const auto first_commit = store.CommitPendingMutations();
        ok &= Require(
            first_commit == apfsaccess::rw::MetadataStore::CommitStatus::Committed,
            "Replay-blob-tombstone-invalid baseline commit should succeed");
        ok &= Require(
            !store.IsRecoveryRequired(),
            "Replay-blob-tombstone-invalid baseline commit should not require recovery");

        apfsaccess::rw::MetadataStore::MutationRequest delete_file{};
        delete_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Delete;
        delete_file.path = kReplayBlobTombstoneFilePath;
        ok &= Require(
            store.ApplyMutation(delete_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-blob-tombstone-invalid delete file should apply");
        staged_payloads.erase(kReplayBlobTombstoneFilePath);

        store.SetCommitStageHook([](std::string_view stage)
        {
            return stage != "before-checkpoint-switch";
        });

        const auto interrupted_commit = store.CommitPendingMutations();
        ok &= Require(
            interrupted_commit == apfsaccess::rw::MetadataStore::CommitStatus::PersistFailed,
            "Replay-blob-tombstone-invalid commit should fail at before-checkpoint-switch stage");
        ok &= Require(
            store.IsRecoveryRequired(),
            "Replay-blob-tombstone-invalid should require recovery after interrupted checkpoint switch");
    }

    std::size_t corrupted_tombstone_offset = 0;
    ok &= Require(
        CorruptCommitBlobDirectoryTombstoneChildWithValidChecksum(
            replay_blob_tombstone_invalid_image_path,
            corrupted_tombstone_offset),
        "Replay-blob-tombstone-invalid should corrupt directory tombstone linkage while preserving checksum");

    {
        apfsaccess::rw::MetadataStore remounted(replay_blob_tombstone_invalid_context);
        ok &= Require(remounted.LoadContainerSuperblocks(), "Replay-blob-tombstone-invalid remount LoadContainerSuperblocks should succeed");
        ok &= Require(remounted.PrepareNativeWritePath(), "Replay-blob-tombstone-invalid remount PrepareNativeWritePath should succeed");
        ok &= Require(remounted.IsRecoveryRequired(), "Replay-blob-tombstone-invalid remount should require recovery before replay");
        ok &= Require(!remounted.ReplayOrRecover(), "Replay-blob-tombstone-invalid remount replay should fail semantic checks");
        ok &= Require(remounted.IsRecoveryRequired(), "Replay-blob-tombstone-invalid remount should remain recovery-required after replay failure");
        ok &= Require(!remounted.IsCommitPathReady(), "Replay-blob-tombstone-invalid remount should keep commit path blocked");
        ok &= Require(
            IsReplayCommitBlobRejectedReason(remounted.RecoveryReason()),
            "Replay-blob-tombstone-invalid remount should report replay commit-blob rejection reason");
    }

    const auto replay_blob_header_invalid_image_path = run_root / "container_replay_blob_header_invalid.apfs.img";
    if (!CreateSyntheticContainer(replay_blob_header_invalid_image_path))
    {
        std::cerr << "[FAIL] unable to create synthetic APFS container image for replay-blob-header-invalid scenario" << std::endl;
        return 1;
    }

    apfsaccess::rw::MetadataStore::VolumeContext replay_blob_header_invalid_context
    {
        replay_blob_header_invalid_image_path.wstring(),
        L"ReplayBlobHeaderInvalid",
    };
    replay_blob_header_invalid_context.crash_replay_mode = L"ReplayIfSafe";
    {
        apfsaccess::rw::MetadataStore store(replay_blob_header_invalid_context);
        ok &= Require(store.LoadContainerSuperblocks(), "Replay-blob-header-invalid LoadContainerSuperblocks should succeed");
        ok &= Require(store.LoadObjectMap(), "Replay-blob-header-invalid LoadObjectMap should succeed");
        ok &= Require(store.LoadSpacemanState(), "Replay-blob-header-invalid LoadSpacemanState should succeed");
        ok &= Require(store.PrepareNativeWritePath(), "Replay-blob-header-invalid PrepareNativeWritePath should succeed");
        std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
        store.SetFilePayloadProvider(
            [&staged_payloads](const std::wstring& path, std::uint64_t logical_size) -> std::optional<std::vector<std::byte>>
            {
                auto pending = staged_payloads.find(path);
                if (pending == staged_payloads.end())
                {
                    return std::nullopt;
                }

                if (logical_size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
                {
                    return std::nullopt;
                }

                auto payload = pending->second;
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
        create_file.path = L"\\replayblobheader.bin";
        ok &= Require(
            store.ApplyMutation(create_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-blob-header-invalid create file should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_file{};
        write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_file.path = L"\\replayblobheader.bin";
        write_file.length = 1024;
        ok &= Require(
            store.ApplyMutation(write_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-blob-header-invalid write file should apply");
        staged_payloads[L"\\replayblobheader.bin"] = std::vector<std::byte>(1024, static_cast<std::byte>(0x57));

        store.SetCommitStageHook([](std::string_view stage)
        {
            return stage != "before-checkpoint-switch";
        });

        const auto interrupted_commit = store.CommitPendingMutations();
        ok &= Require(
            interrupted_commit == apfsaccess::rw::MetadataStore::CommitStatus::PersistFailed,
            "Replay-blob-header-invalid commit should fail at before-checkpoint-switch stage");
        ok &= Require(
            store.IsRecoveryRequired(),
            "Replay-blob-header-invalid should require recovery after interrupted checkpoint switch");
    }

    std::size_t corrupted_header_offset = 0;
    ok &= Require(
        CorruptCommitBlobMutationCount(
            replay_blob_header_invalid_image_path,
            /*mutation_count=*/0,
            corrupted_header_offset),
        "Replay-blob-header-invalid should corrupt commit-blob mutation count");

    {
        apfsaccess::rw::MetadataStore remounted(replay_blob_header_invalid_context);
        ok &= Require(remounted.LoadContainerSuperblocks(), "Replay-blob-header-invalid remount LoadContainerSuperblocks should succeed");
        ok &= Require(remounted.PrepareNativeWritePath(), "Replay-blob-header-invalid remount PrepareNativeWritePath should succeed");
        ok &= Require(remounted.IsRecoveryRequired(), "Replay-blob-header-invalid remount should require recovery before replay");
        ok &= Require(!remounted.ReplayOrRecover(), "Replay-blob-header-invalid remount replay should fail semantic checks");
        ok &= Require(remounted.IsRecoveryRequired(), "Replay-blob-header-invalid remount should remain recovery-required after replay failure");
        ok &= Require(!remounted.IsCommitPathReady(), "Replay-blob-header-invalid remount should keep commit path blocked");
        ok &= Require(
            IsReplayCommitBlobRejectedReason(remounted.RecoveryReason()),
            "Replay-blob-header-invalid remount should report replay commit-blob rejection reason");
    }

    const auto replay_blob_count_overflow_invalid_image_path =
        run_root / "container_replay_blob_count_overflow_invalid.apfs.img";
    if (!CreateSyntheticContainer(replay_blob_count_overflow_invalid_image_path))
    {
        std::cerr << "[FAIL] unable to create synthetic APFS container image for replay-blob-count-overflow-invalid scenario" << std::endl;
        return 1;
    }

    apfsaccess::rw::MetadataStore::VolumeContext replay_blob_count_overflow_invalid_context
    {
        replay_blob_count_overflow_invalid_image_path.wstring(),
        L"ReplayBlobCountOverflowInvalid",
    };
    replay_blob_count_overflow_invalid_context.crash_replay_mode = L"ReplayIfSafe";
    {
        apfsaccess::rw::MetadataStore store(replay_blob_count_overflow_invalid_context);
        ok &= Require(store.LoadContainerSuperblocks(), "Replay-blob-count-overflow-invalid LoadContainerSuperblocks should succeed");
        ok &= Require(store.LoadObjectMap(), "Replay-blob-count-overflow-invalid LoadObjectMap should succeed");
        ok &= Require(store.LoadSpacemanState(), "Replay-blob-count-overflow-invalid LoadSpacemanState should succeed");
        ok &= Require(store.PrepareNativeWritePath(), "Replay-blob-count-overflow-invalid PrepareNativeWritePath should succeed");

        apfsaccess::rw::MetadataStore::MutationRequest create_file{};
        create_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
        create_file.path = L"\\replayblobcountoverflow.bin";
        ok &= Require(
            store.ApplyMutation(create_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-blob-count-overflow-invalid create file should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_file{};
        write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_file.path = L"\\replayblobcountoverflow.bin";
        write_file.length = 1024;
        ok &= Require(
            store.ApplyMutation(write_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-blob-count-overflow-invalid write file should apply");

        std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
        staged_payloads[L"\\replayblobcountoverflow.bin"] = std::vector<std::byte>(1024, static_cast<std::byte>(0x6A));
        store.SetFilePayloadProvider(
            [&staged_payloads](const std::wstring& path, std::uint64_t logical_size) -> std::optional<std::vector<std::byte>>
            {
                auto pending = staged_payloads.find(path);
                if (pending == staged_payloads.end())
                {
                    return std::nullopt;
                }

                if (logical_size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
                {
                    return std::nullopt;
                }

                auto payload = pending->second;
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

        store.SetCommitStageHook([](std::string_view stage)
        {
            return stage != "before-checkpoint-switch";
        });

        const auto interrupted_commit = store.CommitPendingMutations();
        ok &= Require(
            interrupted_commit == apfsaccess::rw::MetadataStore::CommitStatus::PersistFailed,
            "Replay-blob-count-overflow-invalid commit should fail at before-checkpoint-switch stage");
        ok &= Require(
            store.IsRecoveryRequired(),
            "Replay-blob-count-overflow-invalid should require recovery after interrupted checkpoint switch");
    }

    std::size_t corrupted_count_overflow_offset = 0;
    ok &= Require(
        CorruptCommitBlobBtreeRecordCount(
            replay_blob_count_overflow_invalid_image_path,
            std::numeric_limits<std::uint32_t>::max(),
            corrupted_count_overflow_offset),
        "Replay-blob-count-overflow-invalid should corrupt btree record count");

    {
        apfsaccess::rw::MetadataStore remounted(replay_blob_count_overflow_invalid_context);
        ok &= Require(remounted.LoadContainerSuperblocks(), "Replay-blob-count-overflow-invalid remount LoadContainerSuperblocks should succeed");
        ok &= Require(remounted.PrepareNativeWritePath(), "Replay-blob-count-overflow-invalid remount PrepareNativeWritePath should succeed");
        ok &= Require(remounted.IsRecoveryRequired(), "Replay-blob-count-overflow-invalid remount should require recovery before replay");
        ok &= Require(!remounted.ReplayOrRecover(), "Replay-blob-count-overflow-invalid remount replay should fail semantic checks");
        ok &= Require(remounted.IsRecoveryRequired(), "Replay-blob-count-overflow-invalid remount should remain recovery-required after replay failure");
        ok &= Require(!remounted.IsCommitPathReady(), "Replay-blob-count-overflow-invalid remount should keep commit path blocked");
        ok &= Require(
            IsReplayCommitBlobRejectedReason(remounted.RecoveryReason()),
            "Replay-blob-count-overflow-invalid remount should report replay commit-blob rejection reason");
    }

    const auto replay_blob_missing_directory_image_path = run_root / "container_replay_blob_missing_directory.apfs.img";
    if (!CreateSyntheticContainer(replay_blob_missing_directory_image_path))
    {
        std::cerr << "[FAIL] unable to create synthetic APFS container image for replay-blob-missing-directory scenario" << std::endl;
        return 1;
    }

    apfsaccess::rw::MetadataStore::VolumeContext replay_blob_missing_directory_context
    {
        replay_blob_missing_directory_image_path.wstring(),
        L"ReplayBlobMissingDirectory",
    };
    replay_blob_missing_directory_context.crash_replay_mode = L"ReplayIfSafe";
    {
        apfsaccess::rw::MetadataStore store(replay_blob_missing_directory_context);
        ok &= Require(store.LoadContainerSuperblocks(), "Replay-blob-missing-directory LoadContainerSuperblocks should succeed");
        ok &= Require(store.LoadObjectMap(), "Replay-blob-missing-directory LoadObjectMap should succeed");
        ok &= Require(store.LoadSpacemanState(), "Replay-blob-missing-directory LoadSpacemanState should succeed");
        ok &= Require(store.PrepareNativeWritePath(), "Replay-blob-missing-directory PrepareNativeWritePath should succeed");

        apfsaccess::rw::MetadataStore::MutationRequest create_file{};
        create_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
        create_file.path = L"\\replayblobmissingdir.bin";
        ok &= Require(
            store.ApplyMutation(create_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-blob-missing-directory create file should apply");

        store.SetCommitStageHook([](std::string_view stage)
        {
            return stage != "before-checkpoint-switch";
        });

        const auto interrupted_commit = store.CommitPendingMutations();
        ok &= Require(
            interrupted_commit == apfsaccess::rw::MetadataStore::CommitStatus::PersistFailed,
            "Replay-blob-missing-directory commit should fail at before-checkpoint-switch stage");
        ok &= Require(
            store.IsRecoveryRequired(),
            "Replay-blob-missing-directory should require recovery after interrupted checkpoint switch");
    }

    std::size_t corrupted_missing_directory_offset = 0;
    ok &= Require(
        CorruptCommitBlobDropLastBtreeRecordWithValidChecksum(
            replay_blob_missing_directory_image_path,
            corrupted_missing_directory_offset),
        "Replay-blob-missing-directory should drop trailing btree record while preserving checksum");

    {
        apfsaccess::rw::MetadataStore remounted(replay_blob_missing_directory_context);
        ok &= Require(remounted.LoadContainerSuperblocks(), "Replay-blob-missing-directory remount LoadContainerSuperblocks should succeed");
        ok &= Require(remounted.PrepareNativeWritePath(), "Replay-blob-missing-directory remount PrepareNativeWritePath should succeed");
        ok &= Require(remounted.IsRecoveryRequired(), "Replay-blob-missing-directory remount should require recovery before replay");
        ok &= Require(!remounted.ReplayOrRecover(), "Replay-blob-missing-directory remount replay should fail semantic checks");
        ok &= Require(remounted.IsRecoveryRequired(), "Replay-blob-missing-directory remount should remain recovery-required after replay failure");
        ok &= Require(!remounted.IsCommitPathReady(), "Replay-blob-missing-directory remount should keep commit path blocked");
        ok &= Require(
            IsReplayCommitBlobRejectedReason(remounted.RecoveryReason()),
            "Replay-blob-missing-directory remount should report replay commit-blob rejection reason");
    }

    const auto replay_blob_missing_inode_image_path = run_root / "container_replay_blob_missing_inode.apfs.img";
    if (!CreateSyntheticContainer(replay_blob_missing_inode_image_path))
    {
        std::cerr << "[FAIL] unable to create synthetic APFS container image for replay-blob-missing-inode scenario" << std::endl;
        return 1;
    }

    apfsaccess::rw::MetadataStore::VolumeContext replay_blob_missing_inode_context
    {
        replay_blob_missing_inode_image_path.wstring(),
        L"ReplayBlobMissingInode",
    };
    replay_blob_missing_inode_context.crash_replay_mode = L"ReplayIfSafe";
    {
        apfsaccess::rw::MetadataStore store(replay_blob_missing_inode_context);
        ok &= Require(store.LoadContainerSuperblocks(), "Replay-blob-missing-inode LoadContainerSuperblocks should succeed");
        ok &= Require(store.LoadObjectMap(), "Replay-blob-missing-inode LoadObjectMap should succeed");
        ok &= Require(store.LoadSpacemanState(), "Replay-blob-missing-inode LoadSpacemanState should succeed");
        ok &= Require(store.PrepareNativeWritePath(), "Replay-blob-missing-inode PrepareNativeWritePath should succeed");
        std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
        store.SetFilePayloadProvider(
            [&staged_payloads](const std::wstring& path, std::uint64_t logical_size) -> std::optional<std::vector<std::byte>>
            {
                auto pending = staged_payloads.find(path);
                if (pending == staged_payloads.end())
                {
                    return std::nullopt;
                }

                if (logical_size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
                {
                    return std::nullopt;
                }

                auto payload = pending->second;
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

        constexpr auto kReplayBlobMissingInodePath = L"\\replayblobmissinginode.bin";

        apfsaccess::rw::MetadataStore::MutationRequest create_file{};
        create_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
        create_file.path = kReplayBlobMissingInodePath;
        ok &= Require(
            store.ApplyMutation(create_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-blob-missing-inode create file should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_file{};
        write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_file.path = kReplayBlobMissingInodePath;
        write_file.length = 2048;
        ok &= Require(
            store.ApplyMutation(write_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-blob-missing-inode write file should apply");
        staged_payloads[kReplayBlobMissingInodePath] = std::vector<std::byte>(2048, static_cast<std::byte>(0x58));

        const auto baseline_commit = store.CommitPendingMutations();
        ok &= Require(
            baseline_commit == apfsaccess::rw::MetadataStore::CommitStatus::Committed,
            "Replay-blob-missing-inode baseline commit should succeed");
        ok &= Require(
            !store.IsRecoveryRequired(),
            "Replay-blob-missing-inode baseline commit should not require recovery");

        apfsaccess::rw::MetadataStore::MutationRequest truncate_file{};
        truncate_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::SetFileSize;
        truncate_file.path = kReplayBlobMissingInodePath;
        truncate_file.length = 0;
        ok &= Require(
            store.ApplyMutation(truncate_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-blob-missing-inode truncate should apply");
        staged_payloads.erase(kReplayBlobMissingInodePath);

        store.SetCommitStageHook([](std::string_view stage)
        {
            return stage != "before-checkpoint-switch";
        });

        const auto interrupted_commit = store.CommitPendingMutations();
        ok &= Require(
            interrupted_commit == apfsaccess::rw::MetadataStore::CommitStatus::PersistFailed,
            "Replay-blob-missing-inode commit should fail at before-checkpoint-switch stage");
        ok &= Require(
            store.IsRecoveryRequired(),
            "Replay-blob-missing-inode should require recovery after interrupted checkpoint switch");
    }

    std::size_t corrupted_missing_inode_offset = 0;
    ok &= Require(
        CorruptCommitBlobDropLastBtreeRecordWithValidChecksum(
            replay_blob_missing_inode_image_path,
            corrupted_missing_inode_offset),
        "Replay-blob-missing-inode should drop trailing btree record while preserving checksum");

    {
        apfsaccess::rw::MetadataStore remounted(replay_blob_missing_inode_context);
        ok &= Require(remounted.LoadContainerSuperblocks(), "Replay-blob-missing-inode remount LoadContainerSuperblocks should succeed");
        ok &= Require(remounted.PrepareNativeWritePath(), "Replay-blob-missing-inode remount PrepareNativeWritePath should succeed");
        ok &= Require(remounted.IsRecoveryRequired(), "Replay-blob-missing-inode remount should require recovery before replay");
        ok &= Require(!remounted.ReplayOrRecover(), "Replay-blob-missing-inode remount replay should fail semantic checks");
        ok &= Require(remounted.IsRecoveryRequired(), "Replay-blob-missing-inode remount should remain recovery-required after replay failure");
        ok &= Require(!remounted.IsCommitPathReady(), "Replay-blob-missing-inode remount should keep commit path blocked");
        ok &= Require(
            IsReplayCommitBlobRejectedReason(remounted.RecoveryReason()),
            "Replay-blob-missing-inode remount should report replay commit-blob rejection reason");
    }

    const auto replay_blob_padding_invalid_image_path = run_root / "container_replay_blob_padding_invalid.apfs.img";
    if (!CreateSyntheticContainer(replay_blob_padding_invalid_image_path))
    {
        std::cerr << "[FAIL] unable to create synthetic APFS container image for replay-blob-padding-invalid scenario" << std::endl;
        return 1;
    }

    apfsaccess::rw::MetadataStore::VolumeContext replay_blob_padding_invalid_context
    {
        replay_blob_padding_invalid_image_path.wstring(),
        L"ReplayBlobPaddingInvalid",
    };
    replay_blob_padding_invalid_context.crash_replay_mode = L"ReplayIfSafe";
    {
        apfsaccess::rw::MetadataStore store(replay_blob_padding_invalid_context);
        ok &= Require(store.LoadContainerSuperblocks(), "Replay-blob-padding-invalid LoadContainerSuperblocks should succeed");
        ok &= Require(store.LoadObjectMap(), "Replay-blob-padding-invalid LoadObjectMap should succeed");
        ok &= Require(store.LoadSpacemanState(), "Replay-blob-padding-invalid LoadSpacemanState should succeed");
        ok &= Require(store.PrepareNativeWritePath(), "Replay-blob-padding-invalid PrepareNativeWritePath should succeed");
        std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
        store.SetFilePayloadProvider(
            [&staged_payloads](const std::wstring& path, std::uint64_t logical_size) -> std::optional<std::vector<std::byte>>
            {
                auto pending = staged_payloads.find(path);
                if (pending == staged_payloads.end())
                {
                    return std::nullopt;
                }

                if (logical_size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
                {
                    return std::nullopt;
                }

                auto payload = pending->second;
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
        create_file.path = L"\\replayblobpadding.bin";
        ok &= Require(
            store.ApplyMutation(create_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-blob-padding-invalid create file should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_file{};
        write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_file.path = L"\\replayblobpadding.bin";
        write_file.length = 2048;
        ok &= Require(
            store.ApplyMutation(write_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-blob-padding-invalid write file should apply");
        staged_payloads[L"\\replayblobpadding.bin"] = std::vector<std::byte>(2048, static_cast<std::byte>(0x59));

        store.SetCommitStageHook([](std::string_view stage)
        {
            return stage != "before-checkpoint-switch";
        });

        const auto interrupted_commit = store.CommitPendingMutations();
        ok &= Require(
            interrupted_commit == apfsaccess::rw::MetadataStore::CommitStatus::PersistFailed,
            "Replay-blob-padding-invalid commit should fail at before-checkpoint-switch stage");
        ok &= Require(
            store.IsRecoveryRequired(),
            "Replay-blob-padding-invalid should require recovery after interrupted checkpoint switch");
    }

    std::size_t corrupted_padding_offset = 0;
    ok &= Require(
        CorruptCommitBlobPaddingByte(
            replay_blob_padding_invalid_image_path,
            static_cast<std::byte>(0xA7),
            corrupted_padding_offset),
        "Replay-blob-padding-invalid should mutate commit-blob trailing padding byte");

    {
        apfsaccess::rw::MetadataStore remounted(replay_blob_padding_invalid_context);
        ok &= Require(remounted.LoadContainerSuperblocks(), "Replay-blob-padding-invalid remount LoadContainerSuperblocks should succeed");
        ok &= Require(remounted.PrepareNativeWritePath(), "Replay-blob-padding-invalid remount PrepareNativeWritePath should succeed");
        ok &= Require(remounted.IsRecoveryRequired(), "Replay-blob-padding-invalid remount should require recovery before replay");
        ok &= Require(!remounted.ReplayOrRecover(), "Replay-blob-padding-invalid remount replay should fail semantic checks");
        ok &= Require(remounted.IsRecoveryRequired(), "Replay-blob-padding-invalid remount should remain recovery-required after replay failure");
        ok &= Require(!remounted.IsCommitPathReady(), "Replay-blob-padding-invalid remount should keep commit path blocked");
        ok &= Require(
            IsReplayCommitBlobRejectedReason(remounted.RecoveryReason()),
            "Replay-blob-padding-invalid remount should report replay commit-blob rejection reason");
    }

    const auto replay_blob_tombstone_key_invalid_image_path = run_root / "container_replay_blob_tombstone_key_invalid.apfs.img";
    if (!CreateSyntheticContainer(replay_blob_tombstone_key_invalid_image_path))
    {
        std::cerr << "[FAIL] unable to create synthetic APFS container image for replay-blob-tombstone-key-invalid scenario" << std::endl;
        return 1;
    }

    apfsaccess::rw::MetadataStore::VolumeContext replay_blob_tombstone_key_invalid_context
    {
        replay_blob_tombstone_key_invalid_image_path.wstring(),
        L"ReplayBlobTombstoneKeyInvalid",
    };
    replay_blob_tombstone_key_invalid_context.crash_replay_mode = L"ReplayIfSafe";
    {
        apfsaccess::rw::MetadataStore store(replay_blob_tombstone_key_invalid_context);
        ok &= Require(store.LoadContainerSuperblocks(), "Replay-blob-tombstone-key-invalid LoadContainerSuperblocks should succeed");
        ok &= Require(store.LoadObjectMap(), "Replay-blob-tombstone-key-invalid LoadObjectMap should succeed");
        ok &= Require(store.LoadSpacemanState(), "Replay-blob-tombstone-key-invalid LoadSpacemanState should succeed");
        ok &= Require(store.PrepareNativeWritePath(), "Replay-blob-tombstone-key-invalid PrepareNativeWritePath should succeed");
        std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
        store.SetFilePayloadProvider(
            [&staged_payloads](const std::wstring& path, std::uint64_t logical_size) -> std::optional<std::vector<std::byte>>
            {
                auto pending = staged_payloads.find(path);
                if (pending == staged_payloads.end())
                {
                    return std::nullopt;
                }

                if (logical_size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
                {
                    return std::nullopt;
                }

                auto payload = pending->second;
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

        constexpr auto kReplayBlobTombstoneKeyPath = L"\\replayblobtombstonekey.bin";

        apfsaccess::rw::MetadataStore::MutationRequest create_file{};
        create_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
        create_file.path = kReplayBlobTombstoneKeyPath;
        ok &= Require(
            store.ApplyMutation(create_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-blob-tombstone-key-invalid create file should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_file{};
        write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_file.path = kReplayBlobTombstoneKeyPath;
        write_file.length = 1024;
        ok &= Require(
            store.ApplyMutation(write_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-blob-tombstone-key-invalid write file should apply");
        staged_payloads[kReplayBlobTombstoneKeyPath] = std::vector<std::byte>(1024, static_cast<std::byte>(0x5A));

        const auto baseline_commit = store.CommitPendingMutations();
        ok &= Require(
            baseline_commit == apfsaccess::rw::MetadataStore::CommitStatus::Committed,
            "Replay-blob-tombstone-key-invalid baseline commit should succeed");
        ok &= Require(
            !store.IsRecoveryRequired(),
            "Replay-blob-tombstone-key-invalid baseline commit should not require recovery");

        apfsaccess::rw::MetadataStore::MutationRequest delete_file{};
        delete_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Delete;
        delete_file.path = kReplayBlobTombstoneKeyPath;
        ok &= Require(
            store.ApplyMutation(delete_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-blob-tombstone-key-invalid delete should apply");
        staged_payloads.erase(kReplayBlobTombstoneKeyPath);

        store.SetCommitStageHook([](std::string_view stage)
        {
            return stage != "before-checkpoint-switch";
        });

        const auto interrupted_commit = store.CommitPendingMutations();
        ok &= Require(
            interrupted_commit == apfsaccess::rw::MetadataStore::CommitStatus::PersistFailed,
            "Replay-blob-tombstone-key-invalid commit should fail at before-checkpoint-switch stage");
        ok &= Require(
            store.IsRecoveryRequired(),
            "Replay-blob-tombstone-key-invalid should require recovery after interrupted checkpoint switch");
    }

    std::size_t corrupted_tombstone_key_offset = 0;
    ok &= Require(
        CorruptCommitBlobTombstoneKeyPrefixWithValidChecksum(
            replay_blob_tombstone_key_invalid_image_path,
            corrupted_tombstone_key_offset),
        "Replay-blob-tombstone-key-invalid should mutate tombstone key kind prefix while preserving checksum");

    {
        apfsaccess::rw::MetadataStore remounted(replay_blob_tombstone_key_invalid_context);
        ok &= Require(remounted.LoadContainerSuperblocks(), "Replay-blob-tombstone-key-invalid remount LoadContainerSuperblocks should succeed");
        ok &= Require(remounted.PrepareNativeWritePath(), "Replay-blob-tombstone-key-invalid remount PrepareNativeWritePath should succeed");
        ok &= Require(remounted.IsRecoveryRequired(), "Replay-blob-tombstone-key-invalid remount should require recovery before replay");
        ok &= Require(!remounted.ReplayOrRecover(), "Replay-blob-tombstone-key-invalid remount replay should fail semantic checks");
        ok &= Require(remounted.IsRecoveryRequired(), "Replay-blob-tombstone-key-invalid remount should remain recovery-required after replay failure");
        ok &= Require(!remounted.IsCommitPathReady(), "Replay-blob-tombstone-key-invalid remount should keep commit path blocked");
        ok &= Require(
            IsReplayCommitBlobRejectedReason(remounted.RecoveryReason()),
            "Replay-blob-tombstone-key-invalid remount should report replay commit-blob rejection reason");
    }

    const auto replay_blob_duplicate_allocation_invalid_image_path =
        run_root / "container_replay_blob_duplicate_allocation_invalid.apfs.img";
    if (!CreateSyntheticContainer(replay_blob_duplicate_allocation_invalid_image_path))
    {
        std::cerr
            << "[FAIL] unable to create synthetic APFS container image for replay-blob-duplicate-allocation-invalid scenario"
            << std::endl;
        return 1;
    }

    apfsaccess::rw::MetadataStore::VolumeContext replay_blob_duplicate_allocation_invalid_context
    {
        replay_blob_duplicate_allocation_invalid_image_path.wstring(),
        L"ReplayBlobDuplicateAllocationInvalid",
    };
    replay_blob_duplicate_allocation_invalid_context.crash_replay_mode = L"ReplayIfSafe";
    {
        apfsaccess::rw::MetadataStore store(replay_blob_duplicate_allocation_invalid_context);
        ok &= Require(
            store.LoadContainerSuperblocks(),
            "Replay-blob-duplicate-allocation-invalid LoadContainerSuperblocks should succeed");
        ok &= Require(
            store.LoadObjectMap(),
            "Replay-blob-duplicate-allocation-invalid LoadObjectMap should succeed");
        ok &= Require(
            store.LoadSpacemanState(),
            "Replay-blob-duplicate-allocation-invalid LoadSpacemanState should succeed");
        ok &= Require(
            store.PrepareNativeWritePath(),
            "Replay-blob-duplicate-allocation-invalid PrepareNativeWritePath should succeed");
        std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
        store.SetFilePayloadProvider(
            [&staged_payloads](const std::wstring& path, std::uint64_t logical_size) -> std::optional<std::vector<std::byte>>
            {
                auto pending = staged_payloads.find(path);
                if (pending == staged_payloads.end())
                {
                    return std::nullopt;
                }

                if (logical_size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
                {
                    return std::nullopt;
                }

                auto payload = pending->second;
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

        constexpr auto kReplayBlobDuplicateAllocationPath = L"\\replayblobduplicateallocation.bin";

        apfsaccess::rw::MetadataStore::MutationRequest create_file{};
        create_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
        create_file.path = kReplayBlobDuplicateAllocationPath;
        ok &= Require(
            store.ApplyMutation(create_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-blob-duplicate-allocation-invalid create file should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_file{};
        write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_file.path = kReplayBlobDuplicateAllocationPath;
        write_file.length = 2560;
        ok &= Require(
            store.ApplyMutation(write_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-blob-duplicate-allocation-invalid write file should apply");
        staged_payloads[kReplayBlobDuplicateAllocationPath] =
            std::vector<std::byte>(2560, static_cast<std::byte>(0x52));

        store.SetCommitStageHook([](std::string_view stage)
        {
            return stage != "before-checkpoint-switch";
        });

        const auto interrupted_commit = store.CommitPendingMutations();
        ok &= Require(
            interrupted_commit == apfsaccess::rw::MetadataStore::CommitStatus::PersistFailed,
            "Replay-blob-duplicate-allocation-invalid commit should fail at before-checkpoint-switch stage");
        ok &= Require(
            store.IsRecoveryRequired(),
            "Replay-blob-duplicate-allocation-invalid should require recovery after interrupted checkpoint switch");
    }

    std::size_t corrupted_duplicate_allocation_offset = 0;
    ok &= Require(
        CorruptCommitBlobDuplicateFirstAllocationWithValidChecksum(
            replay_blob_duplicate_allocation_invalid_image_path,
            corrupted_duplicate_allocation_offset),
        "Replay-blob-duplicate-allocation-invalid should duplicate first allocation while preserving checksum");

    {
        apfsaccess::rw::MetadataStore remounted(replay_blob_duplicate_allocation_invalid_context);
        ok &= Require(
            remounted.LoadContainerSuperblocks(),
            "Replay-blob-duplicate-allocation-invalid remount LoadContainerSuperblocks should succeed");
        ok &= Require(
            remounted.PrepareNativeWritePath(),
            "Replay-blob-duplicate-allocation-invalid remount PrepareNativeWritePath should succeed");
        ok &= Require(
            remounted.IsRecoveryRequired(),
            "Replay-blob-duplicate-allocation-invalid remount should require recovery before replay");
        ok &= Require(
            !remounted.ReplayOrRecover(),
            "Replay-blob-duplicate-allocation-invalid remount replay should fail semantic checks");
        ok &= Require(
            remounted.IsRecoveryRequired(),
            "Replay-blob-duplicate-allocation-invalid remount should remain recovery-required after replay failure");
        ok &= Require(
            !remounted.IsCommitPathReady(),
            "Replay-blob-duplicate-allocation-invalid remount should keep commit path blocked");
        ok &= Require(
            IsReplayCommitBlobRejectedReason(remounted.RecoveryReason()),
            "Replay-blob-duplicate-allocation-invalid remount should report replay commit-blob rejection reason");
    }

    const auto replay_blob_overlapping_allocation_invalid_image_path =
        run_root / "container_replay_blob_overlapping_allocation_invalid.apfs.img";
    if (!CreateSyntheticContainer(replay_blob_overlapping_allocation_invalid_image_path))
    {
        std::cerr
            << "[FAIL] unable to create synthetic APFS container image for replay-blob-overlapping-allocation-invalid scenario"
            << std::endl;
        return 1;
    }

    apfsaccess::rw::MetadataStore::VolumeContext replay_blob_overlapping_allocation_invalid_context
    {
        replay_blob_overlapping_allocation_invalid_image_path.wstring(),
        L"ReplayBlobOverlappingAllocationInvalid",
    };
    replay_blob_overlapping_allocation_invalid_context.crash_replay_mode = L"ReplayIfSafe";
    {
        apfsaccess::rw::MetadataStore store(replay_blob_overlapping_allocation_invalid_context);
        ok &= Require(
            store.LoadContainerSuperblocks(),
            "Replay-blob-overlapping-allocation-invalid LoadContainerSuperblocks should succeed");
        ok &= Require(
            store.LoadObjectMap(),
            "Replay-blob-overlapping-allocation-invalid LoadObjectMap should succeed");
        ok &= Require(
            store.LoadSpacemanState(),
            "Replay-blob-overlapping-allocation-invalid LoadSpacemanState should succeed");
        ok &= Require(
            store.PrepareNativeWritePath(),
            "Replay-blob-overlapping-allocation-invalid PrepareNativeWritePath should succeed");
        std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
        store.SetFilePayloadProvider(
            [&staged_payloads](const std::wstring& path, std::uint64_t logical_size) -> std::optional<std::vector<std::byte>>
            {
                auto pending = staged_payloads.find(path);
                if (pending == staged_payloads.end())
                {
                    return std::nullopt;
                }

                if (logical_size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
                {
                    return std::nullopt;
                }

                auto payload = pending->second;
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

        constexpr auto kReplayBlobOverlappingAllocationPathA = L"\\replaybloboverlapallocA.bin";
        constexpr auto kReplayBlobOverlappingAllocationPathB = L"\\replaybloboverlapallocB.bin";

        apfsaccess::rw::MetadataStore::MutationRequest create_file_a{};
        create_file_a.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
        create_file_a.path = kReplayBlobOverlappingAllocationPathA;
        ok &= Require(
            store.ApplyMutation(create_file_a) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-blob-overlapping-allocation-invalid create file A should apply");

        apfsaccess::rw::MetadataStore::MutationRequest create_file_b{};
        create_file_b.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
        create_file_b.path = kReplayBlobOverlappingAllocationPathB;
        ok &= Require(
            store.ApplyMutation(create_file_b) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-blob-overlapping-allocation-invalid create file B should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_file_a{};
        write_file_a.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_file_a.path = kReplayBlobOverlappingAllocationPathA;
        write_file_a.length = 12288;
        ok &= Require(
            store.ApplyMutation(write_file_a) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-blob-overlapping-allocation-invalid write file A should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_file_b{};
        write_file_b.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_file_b.path = kReplayBlobOverlappingAllocationPathB;
        write_file_b.length = 16384;
        ok &= Require(
            store.ApplyMutation(write_file_b) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-blob-overlapping-allocation-invalid write file B should apply");

        staged_payloads[kReplayBlobOverlappingAllocationPathA] =
            std::vector<std::byte>(12288, static_cast<std::byte>(0x4C));
        staged_payloads[kReplayBlobOverlappingAllocationPathB] =
            std::vector<std::byte>(16384, static_cast<std::byte>(0x4D));

        store.SetCommitStageHook([](std::string_view stage)
        {
            return stage != "before-checkpoint-switch";
        });

        const auto interrupted_commit = store.CommitPendingMutations();
        ok &= Require(
            interrupted_commit == apfsaccess::rw::MetadataStore::CommitStatus::PersistFailed,
            "Replay-blob-overlapping-allocation-invalid commit should fail at before-checkpoint-switch stage");
        ok &= Require(
            store.IsRecoveryRequired(),
            "Replay-blob-overlapping-allocation-invalid should require recovery after interrupted checkpoint switch");
    }

    std::size_t corrupted_overlapping_allocation_offset = 0;
    ok &= Require(
        CorruptCommitBlobOverlappingAllocationsWithValidChecksum(
            replay_blob_overlapping_allocation_invalid_image_path,
            corrupted_overlapping_allocation_offset),
        "Replay-blob-overlapping-allocation-invalid should create overlapping allocation extents while preserving checksum");

    {
        apfsaccess::rw::MetadataStore remounted(replay_blob_overlapping_allocation_invalid_context);
        ok &= Require(
            remounted.LoadContainerSuperblocks(),
            "Replay-blob-overlapping-allocation-invalid remount LoadContainerSuperblocks should succeed");
        ok &= Require(
            remounted.PrepareNativeWritePath(),
            "Replay-blob-overlapping-allocation-invalid remount PrepareNativeWritePath should succeed");
        ok &= Require(
            remounted.IsRecoveryRequired(),
            "Replay-blob-overlapping-allocation-invalid remount should require recovery before replay");
        ok &= Require(
            !remounted.ReplayOrRecover(),
            "Replay-blob-overlapping-allocation-invalid remount replay should fail semantic checks");
        ok &= Require(
            remounted.IsRecoveryRequired(),
            "Replay-blob-overlapping-allocation-invalid remount should remain recovery-required after replay failure");
        ok &= Require(
            !remounted.IsCommitPathReady(),
            "Replay-blob-overlapping-allocation-invalid remount should keep commit path blocked");
        ok &= Require(
            IsReplayCommitBlobRejectedReason(remounted.RecoveryReason()),
            "Replay-blob-overlapping-allocation-invalid remount should report replay commit-blob rejection reason");
    }

    const auto replay_blob_alloc_dealloc_overlap_invalid_image_path =
        run_root / "container_replay_blob_alloc_dealloc_overlap_invalid.apfs.img";
    if (!CreateSyntheticContainer(replay_blob_alloc_dealloc_overlap_invalid_image_path))
    {
        std::cerr
            << "[FAIL] unable to create synthetic APFS container image for replay-blob-alloc-dealloc-overlap-invalid scenario"
            << std::endl;
        return 1;
    }

    apfsaccess::rw::MetadataStore::VolumeContext replay_blob_alloc_dealloc_overlap_invalid_context
    {
        replay_blob_alloc_dealloc_overlap_invalid_image_path.wstring(),
        L"ReplayBlobAllocDeallocOverlapInvalid",
    };
    replay_blob_alloc_dealloc_overlap_invalid_context.crash_replay_mode = L"ReplayIfSafe";
    {
        apfsaccess::rw::MetadataStore store(replay_blob_alloc_dealloc_overlap_invalid_context);
        ok &= Require(
            store.LoadContainerSuperblocks(),
            "Replay-blob-alloc-dealloc-overlap-invalid LoadContainerSuperblocks should succeed");
        ok &= Require(
            store.LoadObjectMap(),
            "Replay-blob-alloc-dealloc-overlap-invalid LoadObjectMap should succeed");
        ok &= Require(
            store.LoadSpacemanState(),
            "Replay-blob-alloc-dealloc-overlap-invalid LoadSpacemanState should succeed");
        ok &= Require(
            store.PrepareNativeWritePath(),
            "Replay-blob-alloc-dealloc-overlap-invalid PrepareNativeWritePath should succeed");
        std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
        store.SetFilePayloadProvider(
            [&staged_payloads](const std::wstring& path, std::uint64_t logical_size) -> std::optional<std::vector<std::byte>>
            {
                auto pending = staged_payloads.find(path);
                if (pending == staged_payloads.end())
                {
                    return std::nullopt;
                }

                if (logical_size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
                {
                    return std::nullopt;
                }

                auto payload = pending->second;
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

        constexpr auto kReplayBlobAllocDeallocOverlapPath = L"\\replaybloballocdeacoverlap.bin";

        apfsaccess::rw::MetadataStore::MutationRequest create_file{};
        create_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
        create_file.path = kReplayBlobAllocDeallocOverlapPath;
        ok &= Require(
            store.ApplyMutation(create_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-blob-alloc-dealloc-overlap-invalid create file should apply");

        apfsaccess::rw::MetadataStore::MutationRequest initial_write{};
        initial_write.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        initial_write.path = kReplayBlobAllocDeallocOverlapPath;
        initial_write.length = 12288;
        ok &= Require(
            store.ApplyMutation(initial_write) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-blob-alloc-dealloc-overlap-invalid initial write should apply");
        staged_payloads[kReplayBlobAllocDeallocOverlapPath] =
            std::vector<std::byte>(12288, static_cast<std::byte>(0x50));

        const auto baseline_commit = store.CommitPendingMutations();
        ok &= Require(
            baseline_commit == apfsaccess::rw::MetadataStore::CommitStatus::Committed,
            "Replay-blob-alloc-dealloc-overlap-invalid baseline commit should succeed");
        ok &= Require(
            !store.IsRecoveryRequired(),
            "Replay-blob-alloc-dealloc-overlap-invalid baseline commit should not require recovery");

        apfsaccess::rw::MetadataStore::MutationRequest rewrite_file{};
        rewrite_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        rewrite_file.path = kReplayBlobAllocDeallocOverlapPath;
        rewrite_file.length = 16384;
        ok &= Require(
            store.ApplyMutation(rewrite_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-blob-alloc-dealloc-overlap-invalid rewrite should apply");
        staged_payloads[kReplayBlobAllocDeallocOverlapPath] =
            std::vector<std::byte>(16384, static_cast<std::byte>(0x51));

        store.SetCommitStageHook([](std::string_view stage)
        {
            return stage != "before-checkpoint-switch";
        });

        const auto interrupted_commit = store.CommitPendingMutations();
        ok &= Require(
            interrupted_commit == apfsaccess::rw::MetadataStore::CommitStatus::PersistFailed,
            "Replay-blob-alloc-dealloc-overlap-invalid commit should fail at before-checkpoint-switch stage");
        ok &= Require(
            store.IsRecoveryRequired(),
            "Replay-blob-alloc-dealloc-overlap-invalid should require recovery after interrupted checkpoint switch");
    }

    std::size_t corrupted_alloc_dealloc_overlap_offset = 0;
    ok &= Require(
        CorruptCommitBlobAllocationDeallocationOverlapWithValidChecksum(
            replay_blob_alloc_dealloc_overlap_invalid_image_path,
            corrupted_alloc_dealloc_overlap_offset),
        "Replay-blob-alloc-dealloc-overlap-invalid should create allocation/deallocation overlap while preserving checksum");

    {
        apfsaccess::rw::MetadataStore remounted(replay_blob_alloc_dealloc_overlap_invalid_context);
        ok &= Require(
            remounted.LoadContainerSuperblocks(),
            "Replay-blob-alloc-dealloc-overlap-invalid remount LoadContainerSuperblocks should succeed");
        ok &= Require(
            remounted.PrepareNativeWritePath(),
            "Replay-blob-alloc-dealloc-overlap-invalid remount PrepareNativeWritePath should succeed");
        ok &= Require(
            remounted.IsRecoveryRequired(),
            "Replay-blob-alloc-dealloc-overlap-invalid remount should require recovery before replay");
        ok &= Require(
            !remounted.ReplayOrRecover(),
            "Replay-blob-alloc-dealloc-overlap-invalid remount replay should fail semantic checks");
        ok &= Require(
            remounted.IsRecoveryRequired(),
            "Replay-blob-alloc-dealloc-overlap-invalid remount should remain recovery-required after replay failure");
        ok &= Require(
            !remounted.IsCommitPathReady(),
            "Replay-blob-alloc-dealloc-overlap-invalid remount should keep commit path blocked");
        ok &= Require(
            IsReplayCommitBlobRejectedReason(remounted.RecoveryReason()),
            "Replay-blob-alloc-dealloc-overlap-invalid remount should report replay commit-blob rejection reason");
    }

    const auto replay_blob_deallocation_source_invalid_image_path =
        run_root / "container_replay_blob_deallocation_source_invalid.apfs.img";
    if (!CreateSyntheticContainer(replay_blob_deallocation_source_invalid_image_path))
    {
        std::cerr
            << "[FAIL] unable to create synthetic APFS container image for replay-blob-deallocation-source-invalid scenario"
            << std::endl;
        return 1;
    }

    apfsaccess::rw::MetadataStore::VolumeContext replay_blob_deallocation_source_invalid_context
    {
        replay_blob_deallocation_source_invalid_image_path.wstring(),
        L"ReplayBlobDeallocationSourceInvalid",
    };
    replay_blob_deallocation_source_invalid_context.crash_replay_mode = L"ReplayIfSafe";
    {
        apfsaccess::rw::MetadataStore store(replay_blob_deallocation_source_invalid_context);
        ok &= Require(
            store.LoadContainerSuperblocks(),
            "Replay-blob-deallocation-source-invalid LoadContainerSuperblocks should succeed");
        ok &= Require(
            store.LoadObjectMap(),
            "Replay-blob-deallocation-source-invalid LoadObjectMap should succeed");
        ok &= Require(
            store.LoadSpacemanState(),
            "Replay-blob-deallocation-source-invalid LoadSpacemanState should succeed");
        ok &= Require(
            store.PrepareNativeWritePath(),
            "Replay-blob-deallocation-source-invalid PrepareNativeWritePath should succeed");
        std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
        store.SetFilePayloadProvider(
            [&staged_payloads](const std::wstring& path, std::uint64_t logical_size) -> std::optional<std::vector<std::byte>>
            {
                auto pending = staged_payloads.find(path);
                if (pending == staged_payloads.end())
                {
                    return std::nullopt;
                }

                if (logical_size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
                {
                    return std::nullopt;
                }

                auto payload = pending->second;
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

        constexpr auto kReplayBlobDeallocationSourcePath = L"\\replayblobdeallocsource.bin";

        apfsaccess::rw::MetadataStore::MutationRequest create_file{};
        create_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
        create_file.path = kReplayBlobDeallocationSourcePath;
        ok &= Require(
            store.ApplyMutation(create_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-blob-deallocation-source-invalid create file should apply");

        apfsaccess::rw::MetadataStore::MutationRequest initial_write{};
        initial_write.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        initial_write.path = kReplayBlobDeallocationSourcePath;
        initial_write.length = 16384;
        ok &= Require(
            store.ApplyMutation(initial_write) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-blob-deallocation-source-invalid initial write should apply");
        staged_payloads[kReplayBlobDeallocationSourcePath] =
            std::vector<std::byte>(16384, static_cast<std::byte>(0x33));

        const auto baseline_commit = store.CommitPendingMutations();
        ok &= Require(
            baseline_commit == apfsaccess::rw::MetadataStore::CommitStatus::Committed,
            "Replay-blob-deallocation-source-invalid baseline commit should succeed");
        ok &= Require(
            !store.IsRecoveryRequired(),
            "Replay-blob-deallocation-source-invalid baseline commit should not require recovery");

        apfsaccess::rw::MetadataStore::MutationRequest truncate_zero{};
        truncate_zero.operation = apfsaccess::rw::MetadataStore::MutationOperation::SetFileSize;
        truncate_zero.path = kReplayBlobDeallocationSourcePath;
        truncate_zero.length = 0;
        ok &= Require(
            store.ApplyMutation(truncate_zero) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-blob-deallocation-source-invalid truncate should apply");
        staged_payloads.erase(kReplayBlobDeallocationSourcePath);

        store.SetCommitStageHook([](std::string_view stage)
        {
            return stage != "before-checkpoint-switch";
        });

        const auto interrupted_commit = store.CommitPendingMutations();
        ok &= Require(
            interrupted_commit == apfsaccess::rw::MetadataStore::CommitStatus::PersistFailed,
            "Replay-blob-deallocation-source-invalid commit should fail at before-checkpoint-switch stage");
        ok &= Require(
            store.IsRecoveryRequired(),
            "Replay-blob-deallocation-source-invalid should require recovery after interrupted checkpoint switch");
    }

    std::size_t corrupted_deallocation_source_offset = 0;
    ok &= Require(
        CorruptCommitBlobShiftFirstDeallocationWithValidChecksum(
            replay_blob_deallocation_source_invalid_image_path,
            corrupted_deallocation_source_offset),
        "Replay-blob-deallocation-source-invalid should shift first deallocation while preserving checksum");

    {
        apfsaccess::rw::MetadataStore remounted(replay_blob_deallocation_source_invalid_context);
        ok &= Require(
            remounted.LoadContainerSuperblocks(),
            "Replay-blob-deallocation-source-invalid remount LoadContainerSuperblocks should succeed");
        ok &= Require(
            remounted.PrepareNativeWritePath(),
            "Replay-blob-deallocation-source-invalid remount PrepareNativeWritePath should succeed");
        ok &= Require(
            remounted.IsRecoveryRequired(),
            "Replay-blob-deallocation-source-invalid remount should require recovery before replay");
        ok &= Require(
            !remounted.ReplayOrRecover(),
            "Replay-blob-deallocation-source-invalid remount replay should fail semantic checks");
        ok &= Require(
            remounted.IsRecoveryRequired(),
            "Replay-blob-deallocation-source-invalid remount should remain recovery-required after replay failure");
        ok &= Require(
            !remounted.IsCommitPathReady(),
            "Replay-blob-deallocation-source-invalid remount should keep commit path blocked");
        ok &= Require(
            IsReplayCommitBlobRejectedReason(remounted.RecoveryReason()),
            "Replay-blob-deallocation-source-invalid remount should report replay commit-blob rejection reason");
    }

    const auto replay_blob_duplicate_deallocation_invalid_image_path =
        run_root / "container_replay_blob_duplicate_deallocation_invalid.apfs.img";
    if (!CreateSyntheticContainer(replay_blob_duplicate_deallocation_invalid_image_path))
    {
        std::cerr
            << "[FAIL] unable to create synthetic APFS container image for replay-blob-duplicate-deallocation-invalid scenario"
            << std::endl;
        return 1;
    }

    apfsaccess::rw::MetadataStore::VolumeContext replay_blob_duplicate_deallocation_invalid_context
    {
        replay_blob_duplicate_deallocation_invalid_image_path.wstring(),
        L"ReplayBlobDuplicateDeallocationInvalid",
    };
    replay_blob_duplicate_deallocation_invalid_context.crash_replay_mode = L"ReplayIfSafe";
    {
        apfsaccess::rw::MetadataStore store(replay_blob_duplicate_deallocation_invalid_context);
        ok &= Require(
            store.LoadContainerSuperblocks(),
            "Replay-blob-duplicate-deallocation-invalid LoadContainerSuperblocks should succeed");
        ok &= Require(
            store.LoadObjectMap(),
            "Replay-blob-duplicate-deallocation-invalid LoadObjectMap should succeed");
        ok &= Require(
            store.LoadSpacemanState(),
            "Replay-blob-duplicate-deallocation-invalid LoadSpacemanState should succeed");
        ok &= Require(
            store.PrepareNativeWritePath(),
            "Replay-blob-duplicate-deallocation-invalid PrepareNativeWritePath should succeed");
        std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
        store.SetFilePayloadProvider(
            [&staged_payloads](const std::wstring& path, std::uint64_t logical_size) -> std::optional<std::vector<std::byte>>
            {
                auto pending = staged_payloads.find(path);
                if (pending == staged_payloads.end())
                {
                    return std::nullopt;
                }

                if (logical_size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
                {
                    return std::nullopt;
                }

                auto payload = pending->second;
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

        constexpr auto kReplayBlobDuplicateDeallocationPath = L"\\replayblobduplicatedeallocation.bin";

        apfsaccess::rw::MetadataStore::MutationRequest create_file{};
        create_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
        create_file.path = kReplayBlobDuplicateDeallocationPath;
        ok &= Require(
            store.ApplyMutation(create_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-blob-duplicate-deallocation-invalid create file should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_file{};
        write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_file.path = kReplayBlobDuplicateDeallocationPath;
        write_file.length = 2304;
        ok &= Require(
            store.ApplyMutation(write_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-blob-duplicate-deallocation-invalid write file should apply");
        staged_payloads[kReplayBlobDuplicateDeallocationPath] =
            std::vector<std::byte>(2304, static_cast<std::byte>(0x6A));

        const auto baseline_commit = store.CommitPendingMutations();
        ok &= Require(
            baseline_commit == apfsaccess::rw::MetadataStore::CommitStatus::Committed,
            "Replay-blob-duplicate-deallocation-invalid baseline commit should succeed");
        ok &= Require(
            !store.IsRecoveryRequired(),
            "Replay-blob-duplicate-deallocation-invalid baseline commit should not require recovery");

        apfsaccess::rw::MetadataStore::MutationRequest truncate_zero{};
        truncate_zero.operation = apfsaccess::rw::MetadataStore::MutationOperation::SetFileSize;
        truncate_zero.path = kReplayBlobDuplicateDeallocationPath;
        truncate_zero.length = 0;
        ok &= Require(
            store.ApplyMutation(truncate_zero) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-blob-duplicate-deallocation-invalid truncate should apply");
        staged_payloads.erase(kReplayBlobDuplicateDeallocationPath);

        store.SetCommitStageHook([](std::string_view stage)
        {
            return stage != "before-checkpoint-switch";
        });

        const auto interrupted_commit = store.CommitPendingMutations();
        ok &= Require(
            interrupted_commit == apfsaccess::rw::MetadataStore::CommitStatus::PersistFailed,
            "Replay-blob-duplicate-deallocation-invalid commit should fail at before-checkpoint-switch stage");
        ok &= Require(
            store.IsRecoveryRequired(),
            "Replay-blob-duplicate-deallocation-invalid should require recovery after interrupted checkpoint switch");
    }

    std::size_t corrupted_duplicate_deallocation_offset = 0;
    ok &= Require(
        CorruptCommitBlobDuplicateFirstDeallocationWithValidChecksum(
            replay_blob_duplicate_deallocation_invalid_image_path,
            corrupted_duplicate_deallocation_offset),
        "Replay-blob-duplicate-deallocation-invalid should duplicate first deallocation while preserving checksum");

    {
        apfsaccess::rw::MetadataStore remounted(replay_blob_duplicate_deallocation_invalid_context);
        ok &= Require(
            remounted.LoadContainerSuperblocks(),
            "Replay-blob-duplicate-deallocation-invalid remount LoadContainerSuperblocks should succeed");
        ok &= Require(
            remounted.PrepareNativeWritePath(),
            "Replay-blob-duplicate-deallocation-invalid remount PrepareNativeWritePath should succeed");
        ok &= Require(
            remounted.IsRecoveryRequired(),
            "Replay-blob-duplicate-deallocation-invalid remount should require recovery before replay");
        ok &= Require(
            !remounted.ReplayOrRecover(),
            "Replay-blob-duplicate-deallocation-invalid remount replay should fail semantic checks");
        ok &= Require(
            remounted.IsRecoveryRequired(),
            "Replay-blob-duplicate-deallocation-invalid remount should remain recovery-required after replay failure");
        ok &= Require(
            !remounted.IsCommitPathReady(),
            "Replay-blob-duplicate-deallocation-invalid remount should keep commit path blocked");
        ok &= Require(
            IsReplayCommitBlobRejectedReason(remounted.RecoveryReason()),
            "Replay-blob-duplicate-deallocation-invalid remount should report replay commit-blob rejection reason");
    }

    const auto replay_blob_overlapping_deallocation_invalid_image_path =
        run_root / "container_replay_blob_overlapping_deallocation_invalid.apfs.img";
    if (!CreateSyntheticContainer(replay_blob_overlapping_deallocation_invalid_image_path))
    {
        std::cerr
            << "[FAIL] unable to create synthetic APFS container image for replay-blob-overlapping-deallocation-invalid scenario"
            << std::endl;
        return 1;
    }

    apfsaccess::rw::MetadataStore::VolumeContext replay_blob_overlapping_deallocation_invalid_context
    {
        replay_blob_overlapping_deallocation_invalid_image_path.wstring(),
        L"ReplayBlobOverlappingDeallocationInvalid",
    };
    replay_blob_overlapping_deallocation_invalid_context.crash_replay_mode = L"ReplayIfSafe";
    {
        apfsaccess::rw::MetadataStore store(replay_blob_overlapping_deallocation_invalid_context);
        ok &= Require(
            store.LoadContainerSuperblocks(),
            "Replay-blob-overlapping-deallocation-invalid LoadContainerSuperblocks should succeed");
        ok &= Require(
            store.LoadObjectMap(),
            "Replay-blob-overlapping-deallocation-invalid LoadObjectMap should succeed");
        ok &= Require(
            store.LoadSpacemanState(),
            "Replay-blob-overlapping-deallocation-invalid LoadSpacemanState should succeed");
        ok &= Require(
            store.PrepareNativeWritePath(),
            "Replay-blob-overlapping-deallocation-invalid PrepareNativeWritePath should succeed");
        std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
        store.SetFilePayloadProvider(
            [&staged_payloads](const std::wstring& path, std::uint64_t logical_size) -> std::optional<std::vector<std::byte>>
            {
                auto pending = staged_payloads.find(path);
                if (pending == staged_payloads.end())
                {
                    return std::nullopt;
                }

                if (logical_size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
                {
                    return std::nullopt;
                }

                auto payload = pending->second;
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

        constexpr auto kReplayBlobOverlappingDeallocationPathA = L"\\replaybloboverlapA.bin";
        constexpr auto kReplayBlobOverlappingDeallocationPathB = L"\\replaybloboverlapB.bin";

        apfsaccess::rw::MetadataStore::MutationRequest create_file_a{};
        create_file_a.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
        create_file_a.path = kReplayBlobOverlappingDeallocationPathA;
        ok &= Require(
            store.ApplyMutation(create_file_a) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-blob-overlapping-deallocation-invalid create file A should apply");

        apfsaccess::rw::MetadataStore::MutationRequest create_file_b{};
        create_file_b.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
        create_file_b.path = kReplayBlobOverlappingDeallocationPathB;
        ok &= Require(
            store.ApplyMutation(create_file_b) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-blob-overlapping-deallocation-invalid create file B should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_file_a{};
        write_file_a.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_file_a.path = kReplayBlobOverlappingDeallocationPathA;
        write_file_a.length = 12288;
        ok &= Require(
            store.ApplyMutation(write_file_a) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-blob-overlapping-deallocation-invalid write file A should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_file_b{};
        write_file_b.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_file_b.path = kReplayBlobOverlappingDeallocationPathB;
        write_file_b.length = 16384;
        ok &= Require(
            store.ApplyMutation(write_file_b) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-blob-overlapping-deallocation-invalid write file B should apply");

        staged_payloads[kReplayBlobOverlappingDeallocationPathA] =
            std::vector<std::byte>(12288, static_cast<std::byte>(0x41));
        staged_payloads[kReplayBlobOverlappingDeallocationPathB] =
            std::vector<std::byte>(16384, static_cast<std::byte>(0x42));

        const auto baseline_commit = store.CommitPendingMutations();
        ok &= Require(
            baseline_commit == apfsaccess::rw::MetadataStore::CommitStatus::Committed,
            "Replay-blob-overlapping-deallocation-invalid baseline commit should succeed");
        ok &= Require(
            !store.IsRecoveryRequired(),
            "Replay-blob-overlapping-deallocation-invalid baseline commit should not require recovery");

        apfsaccess::rw::MetadataStore::MutationRequest truncate_a{};
        truncate_a.operation = apfsaccess::rw::MetadataStore::MutationOperation::SetFileSize;
        truncate_a.path = kReplayBlobOverlappingDeallocationPathA;
        truncate_a.length = 0;
        ok &= Require(
            store.ApplyMutation(truncate_a) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-blob-overlapping-deallocation-invalid truncate file A should apply");

        apfsaccess::rw::MetadataStore::MutationRequest truncate_b{};
        truncate_b.operation = apfsaccess::rw::MetadataStore::MutationOperation::SetFileSize;
        truncate_b.path = kReplayBlobOverlappingDeallocationPathB;
        truncate_b.length = 0;
        ok &= Require(
            store.ApplyMutation(truncate_b) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-blob-overlapping-deallocation-invalid truncate file B should apply");

        staged_payloads.erase(kReplayBlobOverlappingDeallocationPathA);
        staged_payloads.erase(kReplayBlobOverlappingDeallocationPathB);

        store.SetCommitStageHook([](std::string_view stage)
        {
            return stage != "before-checkpoint-switch";
        });

        const auto interrupted_commit = store.CommitPendingMutations();
        ok &= Require(
            interrupted_commit == apfsaccess::rw::MetadataStore::CommitStatus::PersistFailed,
            "Replay-blob-overlapping-deallocation-invalid commit should fail at before-checkpoint-switch stage");
        ok &= Require(
            store.IsRecoveryRequired(),
            "Replay-blob-overlapping-deallocation-invalid should require recovery after interrupted checkpoint switch");
    }

    std::size_t corrupted_overlapping_deallocation_offset = 0;
    ok &= Require(
        CorruptCommitBlobOverlappingDeallocationsWithValidChecksum(
            replay_blob_overlapping_deallocation_invalid_image_path,
            corrupted_overlapping_deallocation_offset),
        "Replay-blob-overlapping-deallocation-invalid should create overlapping deallocation extents while preserving checksum");

    {
        apfsaccess::rw::MetadataStore remounted(replay_blob_overlapping_deallocation_invalid_context);
        ok &= Require(
            remounted.LoadContainerSuperblocks(),
            "Replay-blob-overlapping-deallocation-invalid remount LoadContainerSuperblocks should succeed");
        ok &= Require(
            remounted.PrepareNativeWritePath(),
            "Replay-blob-overlapping-deallocation-invalid remount PrepareNativeWritePath should succeed");
        ok &= Require(
            remounted.IsRecoveryRequired(),
            "Replay-blob-overlapping-deallocation-invalid remount should require recovery before replay");
        ok &= Require(
            !remounted.ReplayOrRecover(),
            "Replay-blob-overlapping-deallocation-invalid remount replay should fail semantic checks");
        ok &= Require(
            remounted.IsRecoveryRequired(),
            "Replay-blob-overlapping-deallocation-invalid remount should remain recovery-required after replay failure");
        ok &= Require(
            !remounted.IsCommitPathReady(),
            "Replay-blob-overlapping-deallocation-invalid remount should keep commit path blocked");
        ok &= Require(
            IsReplayCommitBlobRejectedReason(remounted.RecoveryReason()),
            "Replay-blob-overlapping-deallocation-invalid remount should report replay commit-blob rejection reason");
    }

    const auto replay_fail_closed_image_path = run_root / "container_replay_fail_closed.apfs.img";
    if (!CreateSyntheticContainer(replay_fail_closed_image_path))
    {
        std::cerr << "[FAIL] unable to create synthetic APFS container image for replay-fail-closed scenario" << std::endl;
        return 1;
    }

    apfsaccess::rw::MetadataStore::VolumeContext replay_fail_closed_context
    {
        replay_fail_closed_image_path.wstring(),
        L"ReplayFailClosed",
    };
    replay_fail_closed_context.crash_replay_mode = L"FailClosed";
    {
        apfsaccess::rw::MetadataStore store(replay_fail_closed_context);
        ok &= Require(store.LoadContainerSuperblocks(), "Replay-fail-closed LoadContainerSuperblocks should succeed");
        ok &= Require(store.LoadObjectMap(), "Replay-fail-closed LoadObjectMap should succeed");
        ok &= Require(store.LoadSpacemanState(), "Replay-fail-closed LoadSpacemanState should succeed");
        ok &= Require(store.PrepareNativeWritePath(), "Replay-fail-closed PrepareNativeWritePath should succeed");
        std::unordered_map<std::wstring, std::vector<std::byte>> staged_payloads;
        store.SetFilePayloadProvider(
            [&staged_payloads](const std::wstring& path, std::uint64_t logical_size) -> std::optional<std::vector<std::byte>>
            {
                auto pending = staged_payloads.find(path);
                if (pending == staged_payloads.end())
                {
                    return std::nullopt;
                }

                if (logical_size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
                {
                    return std::nullopt;
                }

                auto payload = pending->second;
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
        create_file.path = L"\\replayfailclosed.bin";
        ok &= Require(
            store.ApplyMutation(create_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-fail-closed create file should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_file{};
        write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_file.path = L"\\replayfailclosed.bin";
        write_file.length = 1536;
        ok &= Require(
            store.ApplyMutation(write_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Replay-fail-closed write file should apply");
        staged_payloads[L"\\replayfailclosed.bin"] = std::vector<std::byte>(1536, static_cast<std::byte>(0x31));

        store.SetCommitStageHook([](std::string_view stage)
        {
            return stage != "before-checkpoint-switch";
        });

        const auto interrupted_commit = store.CommitPendingMutations();
        ok &= Require(
            interrupted_commit == apfsaccess::rw::MetadataStore::CommitStatus::PersistFailed,
            "Replay-fail-closed commit should fail at before-checkpoint-switch stage");
        ok &= Require(
            store.IsRecoveryRequired(),
            "Replay-fail-closed should require recovery after interrupted checkpoint switch");
    }

    {
        apfsaccess::rw::MetadataStore remounted(replay_fail_closed_context);
        ok &= Require(remounted.LoadContainerSuperblocks(), "Replay-fail-closed remount LoadContainerSuperblocks should succeed");
        ok &= Require(remounted.PrepareNativeWritePath(), "Replay-fail-closed remount PrepareNativeWritePath should succeed");
        ok &= Require(remounted.IsRecoveryRequired(), "Replay-fail-closed remount should require recovery");
        ok &= Require(
            remounted.RecoveryReason() == L"PersistentStateAheadOfSuperblock",
            "Replay-fail-closed remount should detect persistent state ahead of superblock");
        ok &= Require(!remounted.ReplayOrRecover(), "Replay-fail-closed remount should skip replay under FailClosed mode");
        ok &= Require(remounted.IsRecoveryRequired(), "Replay-fail-closed remount should remain recovery-required after skipped replay");
        ok &= Require(!remounted.IsCommitPathReady(), "Replay-fail-closed remount should keep commit path blocked");
        ok &= Require(
            remounted.RecoveryReason() == L"PersistentStateAheadOfSuperblock",
            "Replay-fail-closed remount should preserve fail-closed recovery reason");
    }

    std::filesystem::remove_all(run_root, ec);
    if (!ok)
    {
        return 1;
    }

    std::cout << "[PASS] MetadataStoreFaultInjectionTests" << std::endl;
    return 0;
}
