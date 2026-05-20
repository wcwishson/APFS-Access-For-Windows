#include "MetadataStore.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cwctype>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>
#include <windows.h>

namespace
{
constexpr std::size_t kContainerBytes = 16 * 1024 * 1024;
constexpr std::uint32_t kBlockSize = 4096;
constexpr std::uint64_t kTotalBlocks = kContainerBytes / kBlockSize;
constexpr std::uint64_t kInitialCheckpointXid = 7;
constexpr std::uint64_t kSpacemanObjectId = 0x2A;
constexpr std::uint64_t kVolumeRootObject = 0x54;
constexpr std::uint32_t kNxsbMagic = 0x4253584E; // NXSB
constexpr std::uint64_t kNativeCheckpointBandBlocks = 128;
constexpr std::uint64_t kNativeCheckpointBandStart = kTotalBlocks - kNativeCheckpointBandBlocks;
constexpr std::uint64_t kNativeObjectMapCheckpointOffset = 0;
constexpr std::uint64_t kNativeSpacemanCheckpointOffset = 4;
constexpr std::uint64_t kNativeInodeCheckpointOffset = 8;
constexpr std::uint64_t kNativeBtreeCheckpointOffset = 24;
constexpr std::uint64_t kNativeReplayCheckpointOffset = 64;
constexpr std::uint64_t kNativeOverflowCheckpointOffset = kNativeReplayCheckpointOffset + 2;
constexpr std::uint64_t kNativeObjectMapOverflowBlocks = 16;
constexpr std::uint64_t kNativeInodeOverflowOffset = kNativeOverflowCheckpointOffset + kNativeObjectMapOverflowBlocks;
constexpr std::uint64_t kNativeCheckpointExtensionBlocks = 192;
constexpr std::uint64_t kNativeBtreeExtensionOffset = 0;

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

std::vector<std::byte> BuildPatternPayload(std::size_t bytes, unsigned char seed)
{
    std::vector<std::byte> payload(bytes, std::byte{0});
    for (std::size_t i = 0; i < payload.size(); ++i)
    {
        payload[i] = static_cast<std::byte>((seed + static_cast<unsigned char>(i & 0xffu)) & 0xffu);
    }
    return payload;
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

std::optional<std::uint32_t> ReadLe32FromBytes(const std::vector<std::byte>& bytes, std::size_t offset)
{
    if (offset + sizeof(std::uint32_t) > bytes.size())
    {
        return std::nullopt;
    }

    std::uint32_t value = 0;
    for (std::size_t i = 0; i < sizeof(std::uint32_t); ++i)
    {
        value |= static_cast<std::uint32_t>(std::to_integer<unsigned char>(bytes[offset + i])) << (i * 8);
    }
    return value;
}

std::optional<std::uint64_t> ReadLe64FromBytes(const std::vector<std::byte>& bytes, std::size_t offset)
{
    if (offset + sizeof(std::uint64_t) > bytes.size())
    {
        return std::nullopt;
    }

    std::uint64_t value = 0;
    for (std::size_t i = 0; i < sizeof(std::uint64_t); ++i)
    {
        value |= static_cast<std::uint64_t>(std::to_integer<unsigned char>(bytes[offset + i])) << (i * 8);
    }
    return value;
}

std::optional<std::uint64_t> ReadLe64FromImage(const std::filesystem::path& image_path, std::uint64_t offset_bytes)
{
    std::vector<std::byte> bytes;
    if (!ReadBytesFromImage(image_path, offset_bytes, sizeof(std::uint64_t), bytes) ||
        bytes.size() != sizeof(std::uint64_t))
    {
        return std::nullopt;
    }

    std::uint64_t value = 0;
    for (std::size_t i = 0; i < sizeof(std::uint64_t); ++i)
    {
        value |= static_cast<std::uint64_t>(std::to_integer<unsigned char>(bytes[i])) << (i * 8);
    }
    return value;
}

struct ObjectMapCheckpointSummary
{
    std::uint64_t checkpoint_xid = 0;
    std::uint32_t entry_count = 0;
};

struct SpacemanCheckpointSummary
{
    std::uint64_t checkpoint_xid = 0;
    std::uint32_t allocation_count = 0;
    std::uint32_t free_extent_count = 0;
};

struct InodeCheckpointSummary
{
    std::uint64_t checkpoint_xid = 0;
    std::uint32_t inode_count = 0;
};

struct BtreeCheckpointSummary
{
    std::uint64_t checkpoint_xid = 0;
    std::uint32_t record_count = 0;
};

std::optional<ObjectMapCheckpointSummary> ReadObjectMapCheckpointSummary(
    const std::filesystem::path& image_path,
    std::uint64_t block_index)
{
    constexpr std::array<char, 12> kMagic =
    {
        'A', 'P', 'F', 'S', 'R', 'W', 'O', 'M', 'A', 'P', '3', '\0'
    };

    std::vector<std::byte> block;
    if (!ReadBytesFromImage(image_path, block_index * static_cast<std::uint64_t>(kBlockSize), kBlockSize, block))
    {
        return std::nullopt;
    }

    if (block.size() < 32)
    {
        return std::nullopt;
    }

    for (std::size_t index = 0; index < kMagic.size(); ++index)
    {
        if (std::to_integer<unsigned char>(block[index]) != static_cast<unsigned char>(kMagic[index]))
        {
            return std::nullopt;
        }
    }

    auto xid = ReadLe64FromBytes(block, 12);
    auto entry_count = ReadLe32FromBytes(block, 20);
    if (!xid.has_value() || !entry_count.has_value())
    {
        return std::nullopt;
    }

    return ObjectMapCheckpointSummary
    {
        xid.value(),
        entry_count.value()
    };
}

std::optional<SpacemanCheckpointSummary> ReadSpacemanCheckpointSummary(
    const std::filesystem::path& image_path,
    std::uint64_t block_index)
{
    constexpr std::array<char, 12> kMagic =
    {
        'A', 'P', 'F', 'S', 'R', 'W', 'S', 'P', 'M', '3', '\0', '\0'
    };

    std::vector<std::byte> block;
    if (!ReadBytesFromImage(image_path, block_index * static_cast<std::uint64_t>(kBlockSize), kBlockSize, block))
    {
        return std::nullopt;
    }

    if (block.size() < 32)
    {
        return std::nullopt;
    }

    for (std::size_t index = 0; index < kMagic.size(); ++index)
    {
        if (std::to_integer<unsigned char>(block[index]) != static_cast<unsigned char>(kMagic[index]))
        {
            return std::nullopt;
        }
    }

    auto xid = ReadLe64FromBytes(block, 12);
    auto allocation_count = ReadLe32FromBytes(block, 20);
    auto free_extent_count = ReadLe32FromBytes(block, 24);
    if (!xid.has_value() || !allocation_count.has_value() || !free_extent_count.has_value())
    {
        return std::nullopt;
    }

    return SpacemanCheckpointSummary
    {
        xid.value(),
        allocation_count.value(),
        free_extent_count.value()
    };
}

std::optional<InodeCheckpointSummary> ReadInodeCheckpointSummary(
    const std::filesystem::path& image_path,
    std::uint64_t block_index)
{
    constexpr std::array<char, 12> kMagicV4 =
    {
        'A', 'P', 'F', 'S', 'R', 'W', 'I', 'N', 'O', 'D', '4', '\0'
    };
    constexpr std::array<char, 12> kMagicV5 =
    {
        'A', 'P', 'F', 'S', 'R', 'W', 'I', 'N', 'O', 'D', '5', '\0'
    };
    constexpr std::array<char, 12> kMagicV6 =
    {
        'A', 'P', 'F', 'S', 'R', 'W', 'I', 'N', 'O', 'D', '6', '\0'
    };

    std::vector<std::byte> block;
    if (!ReadBytesFromImage(image_path, block_index * static_cast<std::uint64_t>(kBlockSize), kBlockSize, block))
    {
        return std::nullopt;
    }

    if (block.size() < 32)
    {
        return std::nullopt;
    }

    const auto matches_magic = [&](const std::array<char, 12>& magic)
    {
        for (std::size_t index = 0; index < magic.size(); ++index)
        {
            if (std::to_integer<unsigned char>(block[index]) != static_cast<unsigned char>(magic[index]))
            {
                return false;
            }
        }
        return true;
    };
    if (!matches_magic(kMagicV4) && !matches_magic(kMagicV5) && !matches_magic(kMagicV6))
    {
        return std::nullopt;
    }

    auto xid = ReadLe64FromBytes(block, 12);
    auto inode_count = ReadLe32FromBytes(block, 20);
    if (!xid.has_value() || !inode_count.has_value())
    {
        return std::nullopt;
    }

    return InodeCheckpointSummary
    {
        xid.value(),
        inode_count.value()
    };
}

std::optional<BtreeCheckpointSummary> ReadBtreeCheckpointSummary(
    const std::filesystem::path& image_path,
    std::uint64_t block_index)
{
    constexpr std::array<char, 12> kMagic =
    {
        'A', 'P', 'F', 'S', 'R', 'W', 'B', 'T', 'R', '5', '\0', '\0'
    };

    std::vector<std::byte> block;
    if (!ReadBytesFromImage(image_path, block_index * static_cast<std::uint64_t>(kBlockSize), kBlockSize, block))
    {
        return std::nullopt;
    }

    if (block.size() < 32)
    {
        return std::nullopt;
    }

    for (std::size_t index = 0; index < kMagic.size(); ++index)
    {
        if (std::to_integer<unsigned char>(block[index]) != static_cast<unsigned char>(kMagic[index]))
        {
            return std::nullopt;
        }
    }

    auto xid = ReadLe64FromBytes(block, 12);
    auto record_count = ReadLe32FromBytes(block, 20);
    if (!xid.has_value() || !record_count.has_value())
    {
        return std::nullopt;
    }

    return BtreeCheckpointSummary
    {
        xid.value(),
        record_count.value()
    };
}

template <typename Summary, typename Reader>
std::vector<std::pair<std::uint64_t, Summary>> CollectCheckpointSummaries(
    const std::filesystem::path& image_path,
    std::uint64_t first_block,
    std::uint64_t last_block,
    Reader reader)
{
    std::vector<std::pair<std::uint64_t, Summary>> results;
    if (first_block > last_block)
    {
        return results;
    }

    for (std::uint64_t block = first_block; block <= last_block; ++block)
    {
        auto summary = reader(image_path, block);
        if (summary.has_value())
        {
            results.emplace_back(block, summary.value());
        }
        if (block == std::numeric_limits<std::uint64_t>::max())
        {
            break;
        }
    }

    return results;
}

template <typename Summary, typename Reader>
void AppendCheckpointSummaries(
    std::vector<std::pair<std::uint64_t, Summary>>& summaries,
    const std::filesystem::path& image_path,
    std::uint64_t first_block,
    std::uint64_t last_block,
    Reader reader)
{
    auto next = CollectCheckpointSummaries<Summary>(
        image_path,
        first_block,
        last_block,
        reader);
    summaries.insert(summaries.end(), next.begin(), next.end());
}

std::vector<std::pair<std::uint64_t, ObjectMapCheckpointSummary>> CollectObjectMapCheckpointSummaries(
    const std::filesystem::path& image_path,
    std::uint64_t total_blocks)
{
    std::vector<std::pair<std::uint64_t, ObjectMapCheckpointSummary>> summaries;
    if (total_blocks == 0)
    {
        return summaries;
    }

    const auto band_start = total_blocks > kNativeCheckpointBandBlocks
        ? total_blocks - kNativeCheckpointBandBlocks
        : 0;
    AppendCheckpointSummaries(
        summaries,
        image_path,
        band_start + kNativeObjectMapCheckpointOffset,
        std::min<std::uint64_t>(total_blocks - 1, band_start + kNativeSpacemanCheckpointOffset - 1),
        ReadObjectMapCheckpointSummary);
    AppendCheckpointSummaries(
        summaries,
        image_path,
        band_start + kNativeOverflowCheckpointOffset,
        std::min<std::uint64_t>(total_blocks - 1, band_start + kNativeOverflowCheckpointOffset + kNativeObjectMapOverflowBlocks - 1),
        ReadObjectMapCheckpointSummary);
    return summaries;
}

std::vector<std::pair<std::uint64_t, InodeCheckpointSummary>> CollectInodeCheckpointSummaries(
    const std::filesystem::path& image_path,
    std::uint64_t total_blocks,
    std::uint64_t fallback_start)
{
    std::vector<std::pair<std::uint64_t, InodeCheckpointSummary>> summaries;
    if (total_blocks == 0)
    {
        return summaries;
    }

    if (total_blocks > kNativeCheckpointBandBlocks)
    {
        const auto band_start = total_blocks - kNativeCheckpointBandBlocks;
        AppendCheckpointSummaries(
            summaries,
            image_path,
            band_start + kNativeInodeCheckpointOffset,
            std::min<std::uint64_t>(total_blocks - 1, band_start + kNativeBtreeCheckpointOffset - 1),
            ReadInodeCheckpointSummary);
        AppendCheckpointSummaries(
            summaries,
            image_path,
            band_start + kNativeInodeOverflowOffset,
            std::min<std::uint64_t>(total_blocks - 1, band_start + kNativeCheckpointBandBlocks - 1),
            ReadInodeCheckpointSummary);
    }
    else
    {
        AppendCheckpointSummaries(
            summaries,
            image_path,
            fallback_start,
            std::min<std::uint64_t>(total_blocks - 1, fallback_start + 11),
            ReadInodeCheckpointSummary);
    }
    return summaries;
}

std::vector<std::pair<std::uint64_t, BtreeCheckpointSummary>> CollectBtreeCheckpointSummaries(
    const std::filesystem::path& image_path,
    std::uint64_t total_blocks)
{
    std::vector<std::pair<std::uint64_t, BtreeCheckpointSummary>> summaries;
    if (total_blocks <= kNativeCheckpointBandBlocks)
    {
        return summaries;
    }

    const auto band_start = total_blocks - kNativeCheckpointBandBlocks;
    AppendCheckpointSummaries(
        summaries,
        image_path,
        band_start + kNativeBtreeCheckpointOffset,
        std::min<std::uint64_t>(total_blocks - 1, band_start + kNativeReplayCheckpointOffset - 1),
        ReadBtreeCheckpointSummary);
    if (band_start >= kNativeCheckpointExtensionBlocks)
    {
        const auto extension_start = band_start - kNativeCheckpointExtensionBlocks;
        AppendCheckpointSummaries(
            summaries,
            image_path,
            extension_start + kNativeBtreeExtensionOffset,
            std::min<std::uint64_t>(band_start - 1, extension_start + kNativeCheckpointExtensionBlocks - 1),
            ReadBtreeCheckpointSummary);
    }

    return summaries;
}

template <typename Summary, typename XidAccessor>
std::optional<std::pair<std::uint64_t, Summary>> SelectLatestCheckpointSummary(
    const std::vector<std::pair<std::uint64_t, Summary>>& summaries,
    XidAccessor xid_accessor)
{
    if (summaries.empty())
    {
        return std::nullopt;
    }

    auto latest = summaries.front();
    auto latest_xid = xid_accessor(latest.second);
    for (std::size_t index = 1; index < summaries.size(); ++index)
    {
        const auto candidate_xid = xid_accessor(summaries[index].second);
        if (candidate_xid > latest_xid)
        {
            latest = summaries[index];
            latest_xid = candidate_xid;
        }
    }
    return latest;
}

bool CorruptInodeCheckpointBlocks(
    const std::filesystem::path& image_path,
    std::uint64_t volume_root_block,
    std::uint64_t total_blocks,
    std::size_t& out_corrupted_blocks)
{
    out_corrupted_blocks = 0;
    if (volume_root_block == 0 || total_blocks == 0)
    {
        return false;
    }

    const auto fallback_start = std::min<std::uint64_t>(total_blocks - 1, volume_root_block + 1);
    auto inode_checkpoints = CollectInodeCheckpointSummaries(
        image_path,
        total_blocks,
        fallback_start);
    if (inode_checkpoints.empty())
    {
        return false;
    }

    for (const auto& [block_index, _] : inode_checkpoints)
    {
        std::vector<std::byte> block;
        if (!ReadBytesFromImage(
                image_path,
                block_index * static_cast<std::uint64_t>(kBlockSize),
                kBlockSize,
                block))
        {
            continue;
        }
        if (block.empty())
        {
            continue;
        }

        block[0] = static_cast<std::byte>(0x00);
        if (WriteBytesToImage(
                image_path,
                block_index * static_cast<std::uint64_t>(kBlockSize),
                block))
        {
            ++out_corrupted_blocks;
        }
    }

    return out_corrupted_blocks > 0;
}

bool CorruptLatestObjectMapCheckpointBlocks(
    const std::filesystem::path& image_path,
    std::uint64_t total_blocks,
    std::size_t& out_corrupted_blocks,
    std::uint64_t& out_corrupted_xid)
{
    out_corrupted_blocks = 0;
    out_corrupted_xid = 0;
    if (total_blocks == 0)
    {
        return false;
    }

    auto object_map_checkpoints = CollectObjectMapCheckpointSummaries(
        image_path,
        total_blocks);
    auto latest = SelectLatestCheckpointSummary(
        object_map_checkpoints,
        [](const ObjectMapCheckpointSummary& summary)
        {
            return summary.checkpoint_xid;
        });
    if (!latest.has_value() || latest->second.checkpoint_xid == 0)
    {
        return false;
    }

    out_corrupted_xid = latest->second.checkpoint_xid;
    for (const auto& [block_index, summary] : object_map_checkpoints)
    {
        if (summary.checkpoint_xid != out_corrupted_xid)
        {
            continue;
        }

        std::vector<std::byte> block;
        if (!ReadBytesFromImage(
                image_path,
                block_index * static_cast<std::uint64_t>(kBlockSize),
                kBlockSize,
                block) ||
            block.empty())
        {
            continue;
        }

        block[0] = static_cast<std::byte>(0x00);
        if (WriteBytesToImage(
                image_path,
                block_index * static_cast<std::uint64_t>(kBlockSize),
                block))
        {
            ++out_corrupted_blocks;
        }
    }

    return out_corrupted_blocks > 0;
}

bool WriteRootOnlyInodeCheckpointBlocks(
    const std::filesystem::path& image_path,
    std::uint64_t volume_root_object_id,
    std::uint64_t total_blocks,
    std::size_t& out_rewritten_blocks)
{
    out_rewritten_blocks = 0;
    if (volume_root_object_id == 0 || total_blocks == 0)
    {
        return false;
    }

    const auto fallback_start = std::min<std::uint64_t>(total_blocks - 1, volume_root_object_id + 1);
    auto inode_checkpoints = CollectInodeCheckpointSummaries(
        image_path,
        total_blocks,
        fallback_start);
    if (inode_checkpoints.empty())
    {
        return false;
    }

    constexpr std::array<char, 12> kMagic =
    {
        'A', 'P', 'F', 'S', 'R', 'W', 'I', 'N', 'O', 'D', '4', '\0'
    };
    constexpr std::size_t kHeaderBytes = 32;
    constexpr std::size_t kRecordFixedBytes = 52;
    constexpr std::uint32_t kDirectoryFlag = 0x1u;

    for (const auto& [block_index, summary] : inode_checkpoints)
    {
        std::vector<std::byte> block(kBlockSize, std::byte{0});
        for (std::size_t index = 0; index < kMagic.size(); ++index)
        {
            block[index] = static_cast<std::byte>(kMagic[index]);
        }

        const auto payload_bytes = static_cast<std::uint32_t>(kRecordFixedBytes + sizeof(wchar_t));
        WriteLe64(block, 12, summary.checkpoint_xid);
        WriteLe32(block, 20, 1);
        WriteLe32(block, 24, payload_bytes);

        std::size_t cursor = kHeaderBytes;
        WriteLe64(block, cursor + 0, volume_root_object_id);
        WriteLe64(block, cursor + 8, volume_root_object_id);
        WriteLe64(block, cursor + 16, 0);
        WriteLe64(block, cursor + 24, 0);
        WriteLe64(block, cursor + 32, summary.checkpoint_xid);
        WriteLe32(block, cursor + 40, kDirectoryFlag);
        WriteLe32(block, cursor + 44, 0);
        WriteLe32(block, cursor + 48, 1);
        cursor += kRecordFixedBytes;

        const wchar_t root_path_char = L'\\';
        const auto* root_path_bytes = reinterpret_cast<const unsigned char*>(&root_path_char);
        for (std::size_t index = 0; index < sizeof(wchar_t); ++index)
        {
            block[cursor + index] = static_cast<std::byte>(root_path_bytes[index]);
        }

        if (WriteBytesToImage(
                image_path,
                block_index * static_cast<std::uint64_t>(kBlockSize),
                block))
        {
            ++out_rewritten_blocks;
        }
    }

    return out_rewritten_blocks > 0;
}

std::uint64_t StableObjectIdFromPathForState(const std::wstring& path)
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

std::filesystem::path BuildPersistentStatePathForTest(const apfsaccess::rw::MetadataStore::VolumeContext& context)
{
    std::error_code ec;
    auto root = std::filesystem::temp_directory_path(ec);
    if (ec)
    {
        return {};
    }

    root /= "ApfsAccess";
    root /= "rw-state";
    const auto key = context.device_path + L"|" + context.volume_name;
    const auto stable_id = StableObjectIdFromPathForState(key);
    return root / (std::to_wstring(stable_id) + L".bin");
}

std::optional<std::uint64_t> ResolveInodeCheckpointBlockForTest(
    std::uint64_t volume_root_block,
    std::uint64_t spaceman_block,
    std::uint64_t total_blocks)
{
    if (volume_root_block == 0)
    {
        return std::nullopt;
    }

    for (std::uint64_t delta = 1; delta <= 32; ++delta)
    {
        if (volume_root_block > (std::numeric_limits<std::uint64_t>::max() - delta))
        {
            return std::nullopt;
        }

        const auto candidate = volume_root_block + delta;
        if (candidate == 0 || candidate == volume_root_block || candidate == spaceman_block)
        {
            continue;
        }
        if (total_blocks != 0 && candidate >= total_blocks)
        {
            break;
        }
        return candidate;
    }

    return std::nullopt;
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
} // namespace

int main()
{
    std::error_code ec;
    const auto run_root = std::filesystem::temp_directory_path(ec) / ("ApfsAccessRwEngineTests_" + std::to_string(GetCurrentProcessId()));
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

    apfsaccess::rw::MetadataStore::VolumeContext context
    {
        image_path.wstring(),
        L"Main",
    };
    const auto persistent_state_path = BuildPersistentStatePathForTest(context);
    if (!persistent_state_path.empty())
    {
        std::error_code remove_ec;
        std::filesystem::remove(persistent_state_path, remove_ec);
    }
    constexpr std::uint64_t kCheckpointXidOffset = 0x10;
    constexpr std::uint64_t kSecondaryCheckpointXidOffset = kBlockSize + kCheckpointXidOffset;
    constexpr std::uint64_t kRenamedTimestampUtc = 133444736000000000ull;
    const auto renamed_payload = BuildPatternPayload(8192, 0x21);
    const auto reuse_payload = BuildPatternPayload(777, 0x57);
    const auto resized_reuse_payload = BuildPatternPayload(1024, 0x7C);

    bool ok = true;
    std::uint64_t final_committed_xid = 0;
    std::uint64_t previous_committed_xid = 0;
    {
        apfsaccess::rw::MetadataStore store(context);
        ok &= Require(store.LoadContainerSuperblocks(), "LoadContainerSuperblocks should succeed");
        ok &= Require(store.LoadObjectMap(), "LoadObjectMap should succeed");
        ok &= Require(store.LoadSpacemanState(), "LoadSpacemanState should succeed");
        ok &= Require(store.PrepareNativeWritePath(), "PrepareNativeWritePath should succeed");
        ok &= Require(
            !store.FreeExtent(static_cast<std::uint64_t>(kBlockSize), static_cast<std::uint64_t>(kBlockSize)),
            "FreeExtent should reject ranges that overlap reserved metadata blocks");
        ok &= Require(
            !store.FreeExtent(static_cast<std::uint64_t>(kBlockSize) + 1, static_cast<std::uint64_t>(kBlockSize)),
            "FreeExtent should reject non-aligned physical offsets");
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

        apfsaccess::rw::MetadataStore::MutationRequest create_request{};
        create_request.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateDirectory;
        create_request.path = L"\\docs";
        ok &= Require(
            store.ApplyMutation(create_request) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "CreateDirectory mutation should apply");

        create_request.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateDirectory;
        create_request.path = L"\\docs\\nested";
        ok &= Require(
            store.ApplyMutation(create_request) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Nested directory create mutation should apply");

        apfsaccess::rw::MetadataStore::MutationRequest invalid_cycle_rename{};
        invalid_cycle_rename.operation = apfsaccess::rw::MetadataStore::MutationOperation::Rename;
        invalid_cycle_rename.path = L"\\docs";
        invalid_cycle_rename.secondary_path = L"\\docs\\nested\\docs";
        ok &= Require(
            store.ApplyMutation(invalid_cycle_rename) == apfsaccess::rw::MetadataStore::MutationStatus::InvalidRequest,
            "Renaming directory into its own descendant should be rejected");

        create_request.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
        create_request.path = L"\\docs\\smoke.txt";
        ok &= Require(
            store.ApplyMutation(create_request) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "CreateFile mutation should apply");

        apfsaccess::rw::MetadataStore::MutationRequest duplicate_case_create{};
        duplicate_case_create.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
        duplicate_case_create.path = L"\\DOCS\\SMOKE.TXT";
        ok &= Require(
            store.ApplyMutation(duplicate_case_create) == apfsaccess::rw::MetadataStore::MutationStatus::InvalidRequest,
            "Case-insensitive duplicate create should be rejected");

        apfsaccess::rw::MetadataStore::MutationRequest write_request{};
        write_request.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_request.path = L"\\DOCS\\SMOKE.TXT";
        write_request.offset = 0;
        write_request.length = 8192;
        ok &= Require(
            store.ApplyMutation(write_request) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Write mutation should apply");

        apfsaccess::rw::MetadataStore::MutationRequest rename_request{};
        rename_request.operation = apfsaccess::rw::MetadataStore::MutationOperation::Rename;
        rename_request.path = L"\\DoCs\\SmOkE.TxT";
        rename_request.secondary_path = L"\\docs\\renamed.txt";
        ok &= Require(
            store.ApplyMutation(rename_request) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Rename mutation should apply");

        apfsaccess::rw::MetadataStore::MutationRequest case_only_rename{};
        case_only_rename.operation = apfsaccess::rw::MetadataStore::MutationOperation::Rename;
        case_only_rename.path = L"\\docs\\renamed.txt";
        case_only_rename.secondary_path = L"\\DOCS\\RENAMED.TXT";
        ok &= Require(
            store.ApplyMutation(case_only_rename) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Case-only rename mutation should apply");

        apfsaccess::rw::MetadataStore::MutationRequest set_basic_info{};
        set_basic_info.operation = apfsaccess::rw::MetadataStore::MutationOperation::SetBasicInfo;
        set_basic_info.path = L"\\DOCS\\RENAMED.TXT";
        set_basic_info.timestamp_utc = kRenamedTimestampUtc;
        ok &= Require(
            store.ApplyMutation(set_basic_info) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "SetBasicInfo mutation should apply to renamed file");

        apfsaccess::rw::MetadataStore::MutationRequest scratch_file{};
        scratch_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
        scratch_file.path = L"\\scratch.tmp";
        ok &= Require(
            store.ApplyMutation(scratch_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Scratch create mutation should apply");

        apfsaccess::rw::MetadataStore::MutationRequest delete_request{};
        delete_request.operation = apfsaccess::rw::MetadataStore::MutationOperation::Delete;
        delete_request.path = L"\\scratch.tmp";
        ok &= Require(
            store.ApplyMutation(delete_request) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Delete mutation should apply");
        ok &= Require(store.PendingBtreeRecordCount() > 0, "Pending btree records should be staged before commit");
        staged_payloads[L"\\docs\\renamed.txt"] = renamed_payload;
        staged_payloads[L"\\DOCS\\RENAMED.TXT"] = renamed_payload;

        const auto first_commit = store.CommitPendingMutations();
        if (first_commit != apfsaccess::rw::MetadataStore::CommitStatus::Committed)
        {
            std::cerr << "[DEBUG] first commit status: " << CommitStatusToString(first_commit) << std::endl;
        }
        ok &= Require(
            first_commit == apfsaccess::rw::MetadataStore::CommitStatus::Committed,
            "CommitPendingMutations should commit");
        ok &= Require(store.LastCommittedXid().has_value(), "LastCommittedXid should be set");
        ok &= Require(store.LastCommittedXid().value_or(0) == (kInitialCheckpointXid + 1), "Committed xid should advance");
        ok &= Require(store.CommittedObjectCount() > 0, "Committed object map should have entries");
        ok &= Require(store.CommittedAllocationCount() > 0, "Committed allocations should have entries");
        const auto committed_allocations_after_first_commit = store.CommittedAllocationCount();
        ok &= Require(store.CommittedInodeCount() >= 4, "Committed inode table should include root/docs/nested/renamed");
        ok &= Require(store.PendingBtreeRecordCount() == 0, "Pending btree records should be cleared after commit");
        ok &= Require(store.CommittedBtreeRecordCount() > 0, "Committed btree record list should have entries");
        ok &= Require(!store.LookupCommittedInodeByPath(L"\\docs\\smoke.txt").has_value(), "Original pre-rename path should not exist");
        auto renamed = store.LookupCommittedInodeByPath(L"\\docs\\renamed.txt");
        ok &= Require(renamed.has_value(), "Renamed file path should exist");
        ok &= Require(
            store.LookupCommittedInodeByPath(L"\\DOCS\\RENAMED.TXT").has_value(),
            "LookupCommittedInodeByPath should be case-insensitive");
        ok &= Require(
            renamed->full_path == L"\\DOCS\\RENAMED.TXT",
            "Case-only rename should preserve requested destination casing");
        ok &= Require(!renamed->is_directory, "Renamed entry should be file inode");
        ok &= Require(renamed->logical_size >= 8192, "Renamed file logical size should persist");
        ok &= Require(
            renamed->timestamp_utc == kRenamedTimestampUtc,
            "SetBasicInfo timestamp should persist in committed inode state");
        {
            std::vector<std::byte> persisted_payload;
            ok &= Require(
                ReadBytesFromImage(image_path, renamed->data_physical_address, renamed_payload.size(), persisted_payload),
                "Renamed file payload should be readable from committed extent");
            ok &= Require(
                persisted_payload == renamed_payload,
                "Renamed file payload bytes should persist in committed extent");
        }
        {
            const auto committed_snapshot = store.SnapshotCommittedInodes();
            ok &= Require(
                std::any_of(
                    committed_snapshot.begin(),
                    committed_snapshot.end(),
                    [](const apfsaccess::rw::MetadataStore::InodeRecord& inode)
                    {
                        return inode.full_path == L"\\DOCS\\RENAMED.TXT" && !inode.is_directory;
                    }),
                "Committed inode snapshot should include renamed file");

            std::vector<std::byte> payload_window;
            ok &= Require(
                store.ReadCommittedFileRange(L"\\docs\\renamed.txt", 1024, 2048, payload_window),
                "ReadCommittedFileRange should succeed for renamed file window");
            ok &= Require(payload_window.size() == 2048, "ReadCommittedFileRange should return requested window size");
            ok &= Require(
                std::equal(payload_window.begin(), payload_window.end(), renamed_payload.begin() + 1024),
                "ReadCommittedFileRange window should match persisted renamed payload bytes");

            std::vector<std::byte> beyond_eof;
            ok &= Require(
                store.ReadCommittedFileRange(L"\\docs\\renamed.txt", 999999, 64, beyond_eof),
                "ReadCommittedFileRange should succeed past EOF with empty payload");
            ok &= Require(beyond_eof.empty(), "ReadCommittedFileRange past EOF should return empty payload");
        }
        ok &= Require(!store.LookupCommittedInodeByPath(L"\\scratch.tmp").has_value(), "Deleted scratch path should not exist");

        apfsaccess::rw::MetadataStore::MutationRequest ephemeral_create{};
        ephemeral_create.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
        ephemeral_create.path = L"\\temp.bin";
        ok &= Require(
            store.ApplyMutation(ephemeral_create) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Ephemeral file create mutation should apply");

        apfsaccess::rw::MetadataStore::MutationRequest ephemeral_write{};
        ephemeral_write.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        ephemeral_write.path = L"\\temp.bin";
        ephemeral_write.offset = 0;
        ephemeral_write.length = 1234;
        ok &= Require(
            store.ApplyMutation(ephemeral_write) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Ephemeral file write mutation should apply");

        apfsaccess::rw::MetadataStore::MutationRequest ephemeral_delete{};
        ephemeral_delete.operation = apfsaccess::rw::MetadataStore::MutationOperation::Delete;
        ephemeral_delete.path = L"\\temp.bin";
        ok &= Require(
            store.ApplyMutation(ephemeral_delete) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Ephemeral file delete mutation should apply");
        ok &= Require(store.PendingDeallocationCount() > 0, "Pending deallocations should be staged before second commit");
        staged_payloads[L"\\temp.bin"] = BuildPatternPayload(1234, 0x33);

        const auto second_commit = store.CommitPendingMutations();
        if (second_commit != apfsaccess::rw::MetadataStore::CommitStatus::Committed)
        {
            std::cerr << "[DEBUG] second commit status: " << CommitStatusToString(second_commit) << std::endl;
        }
        ok &= Require(
            second_commit == apfsaccess::rw::MetadataStore::CommitStatus::Committed,
            "Second CommitPendingMutations should commit");
        ok &= Require(
            store.CommittedAllocationCount() == committed_allocations_after_first_commit + 1,
            "Second commit should only add commit-blob allocation after deallocating ephemeral file extent");
        ok &= Require(store.CommittedFreeExtentCount() > 0, "Second commit should track at least one reusable free extent");
        ok &= Require(!store.LookupCommittedInodeByPath(L"\\temp.bin").has_value(), "Ephemeral file should not persist after delete");

        const auto free_extents_after_second_commit = store.CommittedFreeExtentCount();

        apfsaccess::rw::MetadataStore::MutationRequest reuse_create{};
        reuse_create.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
        reuse_create.path = L"\\reuse.bin";
        ok &= Require(
            store.ApplyMutation(reuse_create) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Reuse file create mutation should apply");

        apfsaccess::rw::MetadataStore::MutationRequest reuse_write{};
        reuse_write.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        reuse_write.path = L"\\reuse.bin";
        reuse_write.offset = 0;
        reuse_write.length = 777;
        ok &= Require(
            store.ApplyMutation(reuse_write) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Reuse file write mutation should apply");
        staged_payloads[L"\\reuse.bin"] = reuse_payload;

        const auto third_commit = store.CommitPendingMutations();
        if (third_commit != apfsaccess::rw::MetadataStore::CommitStatus::Committed)
        {
            std::cerr << "[DEBUG] third commit status: " << CommitStatusToString(third_commit) << std::endl;
        }
        ok &= Require(
            third_commit == apfsaccess::rw::MetadataStore::CommitStatus::Committed,
            "Third CommitPendingMutations should commit");
        ok &= Require(
            store.CommittedAllocationCount() > 0,
            "Third commit should keep committed allocation coverage after coalescing records");
        ok &= Require(
            store.CommittedFreeExtentCount() < free_extents_after_second_commit,
            "Third commit should consume a previously free extent");
        auto reuse_inode = store.LookupCommittedInodeByPath(L"\\reuse.bin");
        ok &= Require(reuse_inode.has_value(), "Reuse file should persist");
        ok &= Require(reuse_inode->logical_size >= 777, "Reuse file logical size should persist");
        {
            std::vector<std::byte> persisted_payload;
            ok &= Require(
                ReadBytesFromImage(image_path, reuse_inode->data_physical_address, reuse_payload.size(), persisted_payload),
                "Reuse file payload should be readable from committed extent");
        ok &= Require(
            persisted_payload == reuse_payload,
            "Reuse file payload bytes should persist in committed extent");
        }

        for (int index = 0; index < 760; ++index)
        {
            auto path = L"\\storm-" + std::to_wstring(index) + L".bin";
            auto payload = BuildPatternPayload(static_cast<std::size_t>((index % 512) + 1), static_cast<unsigned char>(0x40 + (index % 127)));

            apfsaccess::rw::MetadataStore::MutationRequest storm_create{};
            storm_create.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
            storm_create.path = path;
            ok &= Require(
                store.ApplyMutation(storm_create) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
                "Storm create mutation should apply");

            apfsaccess::rw::MetadataStore::MutationRequest storm_write{};
            storm_write.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
            storm_write.path = path;
            storm_write.offset = 0;
            storm_write.length = static_cast<std::uint64_t>(payload.size());
            ok &= Require(
                store.ApplyMutation(storm_write) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
                "Storm write mutation should apply");
            staged_payloads[path] = std::move(payload);

            const auto storm_commit = store.CommitPendingMutations();
            if (storm_commit != apfsaccess::rw::MetadataStore::CommitStatus::Committed)
            {
                std::cerr << "[DEBUG] storm commit " << index << " status: " << CommitStatusToString(storm_commit) << std::endl;
            }
            ok &= Require(
                storm_commit == apfsaccess::rw::MetadataStore::CommitStatus::Committed,
                "Storm CommitPendingMutations should commit past compact checkpoint capacity");
        }
        ok &= Require(
            store.CommittedAllocationCount() < 128,
            "Storm adjacent allocations should coalesce before spaceman checkpoint persistence");
        const auto free_size_after_storm = store.FreeSizeBytes();
        ok &= Require(
            free_size_after_storm.has_value(),
            "Storm FreeSizeBytes should remain available for Explorer volume info");
        ok &= Require(
            free_size_after_storm.value_or(0) > (kContainerBytes / 2),
            "Storm FreeSizeBytes should report remaining container headroom, not only reusable freed extents");

        apfsaccess::rw::MetadataStore::MutationRequest resize_reuse{};
        resize_reuse.operation = apfsaccess::rw::MetadataStore::MutationOperation::SetFileSize;
        resize_reuse.path = L"\\reuse.bin";
        resize_reuse.length = static_cast<std::uint64_t>(resized_reuse_payload.size());
        ok &= Require(
            store.ApplyMutation(resize_reuse) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Reuse file resize mutation should apply");
        staged_payloads[L"\\reuse.bin"] = resized_reuse_payload;

        const auto fourth_commit = store.CommitPendingMutations();
        if (fourth_commit != apfsaccess::rw::MetadataStore::CommitStatus::Committed)
        {
            std::cerr << "[DEBUG] fourth commit status: " << CommitStatusToString(fourth_commit) << std::endl;
        }
        ok &= Require(
            fourth_commit == apfsaccess::rw::MetadataStore::CommitStatus::Committed,
            "Fourth CommitPendingMutations should commit");
        final_committed_xid = store.LastCommittedXid().value_or(0);
        previous_committed_xid = final_committed_xid > 0 ? final_committed_xid - 1 : 0;
        auto resized_reuse_inode = store.LookupCommittedInodeByPath(L"\\reuse.bin");
        ok &= Require(resized_reuse_inode.has_value(), "Resized reuse file should persist");
        ok &= Require(
            resized_reuse_inode->logical_size == static_cast<std::uint64_t>(resized_reuse_payload.size()),
            "Resized reuse file logical size should persist");
        {
            std::vector<std::byte> persisted_payload;
            ok &= Require(
                ReadBytesFromImage(
                    image_path,
                    resized_reuse_inode->data_physical_address,
                    resized_reuse_payload.size(),
                    persisted_payload),
                "Resized reuse payload should be readable from committed extent");
            ok &= Require(
                persisted_payload == resized_reuse_payload,
                "Resized reuse payload bytes should persist in committed extent");
        }

        const auto object_map_checkpoints = CollectObjectMapCheckpointSummaries(
            image_path,
            kTotalBlocks);
        ok &= Require(
            !object_map_checkpoints.empty(),
            "Object-map checkpoint block should be persisted to the native checkpoint band");
        auto object_map_latest = SelectLatestCheckpointSummary(
            object_map_checkpoints,
            [](const ObjectMapCheckpointSummary& summary)
            {
                return summary.checkpoint_xid;
            });
        ok &= Require(object_map_latest.has_value(), "Object-map latest checkpoint should be discoverable");
        if (object_map_latest.has_value())
        {
            ok &= Require(
                object_map_latest->second.checkpoint_xid == store.LastCommittedXid().value_or(0),
                "Object-map checkpoint xid should match last committed xid");
            ok &= Require(
                object_map_latest->second.entry_count == static_cast<std::uint32_t>(store.CommittedObjectCount()),
                "Object-map checkpoint entry count should match committed object map size");
        }
        ok &= Require(
            object_map_checkpoints.size() >= 1,
            "Object-map checkpoint slot rotation should persist latest slot copy");
        if (object_map_latest.has_value() && object_map_latest->second.checkpoint_xid > 0)
        {
            bool has_previous_slot = false;
            for (const auto& checkpoint : object_map_checkpoints)
            {
                if (checkpoint.second.checkpoint_xid + 1 == object_map_latest->second.checkpoint_xid)
                {
                    has_previous_slot = true;
                    break;
                }
            }
            ok &= Require(
                has_previous_slot,
                "Object-map checkpoint slot rotation should retain previous xid copy");
        }

        const auto spaceman_scan_end = std::min<std::uint64_t>(kTotalBlocks - 1, kNativeCheckpointBandStart + kNativeInodeCheckpointOffset - 1);
        const auto spaceman_checkpoints = CollectCheckpointSummaries<SpacemanCheckpointSummary>(
            image_path,
            kNativeCheckpointBandStart + kNativeSpacemanCheckpointOffset,
            spaceman_scan_end,
            ReadSpacemanCheckpointSummary);
        ok &= Require(
            !spaceman_checkpoints.empty(),
            "Spaceman checkpoint block should be persisted to the native checkpoint band");
        auto spaceman_latest = SelectLatestCheckpointSummary(
            spaceman_checkpoints,
            [](const SpacemanCheckpointSummary& summary)
            {
                return summary.checkpoint_xid;
            });
        ok &= Require(spaceman_latest.has_value(), "Spaceman latest checkpoint should be discoverable");
        if (spaceman_latest.has_value())
        {
            ok &= Require(
                spaceman_latest->second.checkpoint_xid == store.LastCommittedXid().value_or(0),
                "Spaceman checkpoint xid should match last committed xid");
            ok &= Require(
                spaceman_latest->second.allocation_count == static_cast<std::uint32_t>(store.CommittedAllocationCount()),
                "Spaceman checkpoint allocation count should match committed allocation list");
            ok &= Require(
                spaceman_latest->second.free_extent_count == static_cast<std::uint32_t>(store.CommittedFreeExtentCount()),
                "Spaceman checkpoint free extent count should match committed free extent list");
        }
        ok &= Require(
            spaceman_checkpoints.size() >= 1,
            "Spaceman checkpoint slot rotation should persist latest slot copy");

        const auto inode_checkpoints = CollectInodeCheckpointSummaries(
            image_path,
            kTotalBlocks,
            kVolumeRootObject + 1);
        ok &= Require(
            !inode_checkpoints.empty(),
            "Inode checkpoint block should be persisted to the native checkpoint band");
        auto inode_latest = SelectLatestCheckpointSummary(
            inode_checkpoints,
            [](const InodeCheckpointSummary& summary)
            {
                return summary.checkpoint_xid;
            });
        ok &= Require(inode_latest.has_value(), "Inode latest checkpoint should be discoverable");
        if (inode_latest.has_value())
        {
            ok &= Require(
                inode_latest->second.checkpoint_xid == store.LastCommittedXid().value_or(0),
                "Inode checkpoint xid should match last committed xid");
            ok &= Require(
                inode_latest->second.inode_count == static_cast<std::uint32_t>(store.CommittedInodeCount()),
                "Inode checkpoint count should match committed inode table size");
        }
        ok &= Require(
            inode_checkpoints.size() >= 1,
            "Inode checkpoint slot rotation should persist latest slot copy");

        const auto btree_checkpoints = CollectBtreeCheckpointSummaries(
            image_path,
            kTotalBlocks);
        ok &= Require(
            !btree_checkpoints.empty(),
            "Btree checkpoint block should be persisted to the native checkpoint band");
        auto btree_latest = SelectLatestCheckpointSummary(
            btree_checkpoints,
            [](const BtreeCheckpointSummary& summary)
            {
                return summary.checkpoint_xid;
            });
        ok &= Require(btree_latest.has_value(), "Btree latest checkpoint should be discoverable");
        if (btree_latest.has_value())
        {
            ok &= Require(
                btree_latest->second.checkpoint_xid == store.LastCommittedXid().value_or(0),
                "Btree checkpoint xid should match last committed xid");
            ok &= Require(
                btree_latest->second.record_count == static_cast<std::uint32_t>(store.CommittedBtreeRecordCount()),
                "Btree checkpoint record count should match committed btree record list size");
        }
        ok &= Require(
            btree_checkpoints.size() >= 1,
            "Btree checkpoint slot rotation should persist latest slot copy");
    }

    {
        apfsaccess::rw::MetadataStore remounted(context);
        ok &= Require(remounted.LoadContainerSuperblocks(), "Remount LoadContainerSuperblocks should succeed");
        ok &= Require(remounted.PrepareNativeWritePath(), "Remount PrepareNativeWritePath should succeed");
        ok &= Require(!remounted.IsRecoveryRequired(), "Remount should not require recovery in clean path");
        ok &= Require(remounted.IsCommitPathReady(), "Remount commit path should remain ready in clean path");
        ok &= Require(remounted.LastCommittedXid().has_value(), "Remount should load committed xid");
        ok &= Require(remounted.LastCommittedXid().value_or(0) == final_committed_xid, "Remount xid should persist");
        ok &= Require(remounted.CommittedObjectCount() > 0, "Remount object map state should persist");
        ok &= Require(remounted.CommittedAllocationCount() > 0, "Remount spaceman state should persist");
        ok &= Require(remounted.CommittedInodeCount() >= 4, "Remount inode table should persist");
        ok &= Require(remounted.CommittedBtreeRecordCount() > 0, "Remount btree record list should persist");
        ok &= Require(!remounted.LookupCommittedInodeByPath(L"\\docs\\smoke.txt").has_value(), "Remount old pre-rename path should stay absent");
        auto remounted_renamed = remounted.LookupCommittedInodeByPath(L"\\docs\\renamed.txt");
        ok &= Require(remounted_renamed.has_value(), "Remount renamed file path should persist");
        ok &= Require(
            remounted.LookupCommittedInodeByPath(L"\\DOCS\\RENAMED.TXT").has_value(),
            "Remount case-insensitive lookup for renamed file should succeed");
        ok &= Require(
            remounted_renamed->full_path == L"\\DOCS\\RENAMED.TXT",
            "Remount should preserve case-only rename destination casing");
        ok &= Require(
            remounted_renamed->timestamp_utc == kRenamedTimestampUtc,
            "Remount should preserve SetBasicInfo timestamp");
        auto remounted_reuse = remounted.LookupCommittedInodeByPath(L"\\reuse.bin");
        ok &= Require(remounted_reuse.has_value(), "Remount reuse file should persist");
        {
            auto committed_snapshot = remounted.SnapshotCommittedInodes();
            ok &= Require(
                !committed_snapshot.empty(),
                "Remount committed inode snapshot should not be empty");
            ok &= Require(
                std::any_of(
                    committed_snapshot.begin(),
                    committed_snapshot.end(),
                    [](const apfsaccess::rw::MetadataStore::InodeRecord& inode)
                    {
                        return inode.full_path == L"\\DOCS\\RENAMED.TXT";
                    }),
                "Remount committed inode snapshot should include renamed file");
        }
        {
            std::vector<std::byte> persisted_payload;
            ok &= Require(
                ReadBytesFromImage(image_path, remounted_renamed->data_physical_address, renamed_payload.size(), persisted_payload),
                "Remount renamed payload should be readable from committed extent");
            ok &= Require(
                persisted_payload == renamed_payload,
                "Remount renamed payload bytes should remain intact");
        }
        {
            std::vector<std::byte> remounted_window;
            ok &= Require(
                remounted.ReadCommittedFileRange(L"\\docs\\renamed.txt", 512, 1536, remounted_window),
                "Remount ReadCommittedFileRange should succeed for renamed file");
            ok &= Require(remounted_window.size() == 1536, "Remount ReadCommittedFileRange should return requested window size");
            ok &= Require(
                std::equal(remounted_window.begin(), remounted_window.end(), renamed_payload.begin() + 512),
                "Remount ReadCommittedFileRange bytes should match renamed payload window");
        }
        {
            std::vector<std::byte> persisted_payload;
            ok &= Require(
                ReadBytesFromImage(image_path, remounted_reuse->data_physical_address, resized_reuse_payload.size(), persisted_payload),
                "Remount reuse payload should be readable from committed extent");
            ok &= Require(
                persisted_payload == resized_reuse_payload,
                "Remount reuse payload bytes should reflect resized payload");
        }
        ok &= Require(!remounted.LookupCommittedInodeByPath(L"\\scratch.tmp").has_value(), "Remount deleted file path should stay absent");
        ok &= Require(!remounted.LookupCommittedInodeByPath(L"\\temp.bin").has_value(), "Remount ephemeral file path should stay absent");
        ok &= Require(
            remounted.CheckpointXid().has_value() &&
                remounted.CheckpointXid().value_or(0) == final_committed_xid,
            "Remount checkpoint xid should persist");
        auto raw_checkpoint_xid = ReadLe64FromImage(image_path, kCheckpointXidOffset);
        ok &= Require(raw_checkpoint_xid.has_value(), "Checkpoint xid should be readable from container image");
        auto raw_checkpoint_xid_secondary = ReadLe64FromImage(image_path, kSecondaryCheckpointXidOffset);
        ok &= Require(raw_checkpoint_xid_secondary.has_value(), "Secondary checkpoint xid should be readable from container image");
        ok &= Require(
            std::max(raw_checkpoint_xid.value_or(0), raw_checkpoint_xid_secondary.value_or(0)) == final_committed_xid,
            "Highest container superblock checkpoint xid should be updated on commit");
        ok &= Require(
            std::min(raw_checkpoint_xid.value_or(0), raw_checkpoint_xid_secondary.value_or(0)) == previous_committed_xid,
            "Checkpoint switch scaffold should alternate superblock slots");
    }

    const auto disk_state_only_image_path = run_root / "container_disk_state_only.apfs.img";
    if (!CreateSyntheticContainer(disk_state_only_image_path))
    {
        std::cerr << "[FAIL] unable to create synthetic APFS container image for disk-state-only scenario" << std::endl;
        return 1;
    }

    apfsaccess::rw::MetadataStore::VolumeContext disk_state_only_context
    {
        disk_state_only_image_path.wstring(),
        L"DiskStateOnly",
    };
    std::size_t disk_state_only_committed_object_count = 0;
    std::size_t disk_state_only_committed_allocation_count = 0;
    std::size_t disk_state_only_committed_free_extent_count = 0;
    std::size_t disk_state_only_committed_inode_count = 0;
    std::size_t disk_state_only_committed_btree_count = 0;
    const auto disk_state_only_payload = BuildPatternPayload(1024, 0xB4);
    {
        apfsaccess::rw::MetadataStore store(disk_state_only_context);
        ok &= Require(store.LoadContainerSuperblocks(), "Disk-state-only LoadContainerSuperblocks should succeed");
        ok &= Require(store.LoadObjectMap(), "Disk-state-only LoadObjectMap should succeed");
        ok &= Require(store.LoadSpacemanState(), "Disk-state-only LoadSpacemanState should succeed");
        ok &= Require(store.PrepareNativeWritePath(), "Disk-state-only PrepareNativeWritePath should succeed");

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
        create_file.path = L"\\diskonly.bin";
        ok &= Require(
            store.ApplyMutation(create_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Disk-state-only create file should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_file{};
        write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_file.path = L"\\diskonly.bin";
        write_file.length = 1024;
        ok &= Require(
            store.ApplyMutation(write_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Disk-state-only write file should apply");
        staged_payloads[L"\\diskonly.bin"] = disk_state_only_payload;

        const auto disk_state_only_commit = store.CommitPendingMutations();
        ok &= Require(
            disk_state_only_commit == apfsaccess::rw::MetadataStore::CommitStatus::Committed,
            "Disk-state-only commit should succeed");
        ok &= Require(
            store.LastCommittedXid().value_or(0) == (kInitialCheckpointXid + 1),
            "Disk-state-only commit should advance xid");

        disk_state_only_committed_object_count = store.CommittedObjectCount();
        disk_state_only_committed_allocation_count = store.CommittedAllocationCount();
        disk_state_only_committed_free_extent_count = store.CommittedFreeExtentCount();
        disk_state_only_committed_inode_count = store.CommittedInodeCount();
        disk_state_only_committed_btree_count = store.CommittedBtreeRecordCount();
    }

    const auto disk_state_only_path = BuildPersistentStatePathForTest(disk_state_only_context);
    if (!disk_state_only_path.empty())
    {
        std::error_code remove_ec;
        std::filesystem::remove(disk_state_only_path, remove_ec);
    }

    {
        apfsaccess::rw::MetadataStore remounted_disk_state_only(disk_state_only_context);
        ok &= Require(remounted_disk_state_only.LoadContainerSuperblocks(), "Disk-state-only remount LoadContainerSuperblocks should succeed");
        ok &= Require(remounted_disk_state_only.PrepareNativeWritePath(), "Disk-state-only remount PrepareNativeWritePath should succeed");
        ok &= Require(!remounted_disk_state_only.IsRecoveryRequired(), "Disk-state-only remount should not require recovery");
        ok &= Require(remounted_disk_state_only.IsCommitPathReady(), "Disk-state-only remount commit path should remain ready");
        ok &= Require(
            remounted_disk_state_only.LastCommittedXid().value_or(0) == (kInitialCheckpointXid + 1),
            "Disk-state-only remount should preserve xid from on-disk checkpoints");
        ok &= Require(
            remounted_disk_state_only.CommittedObjectCount() == disk_state_only_committed_object_count,
            "Disk-state-only remount should preserve committed object-map count from checkpoint block");
        ok &= Require(
            remounted_disk_state_only.CommittedAllocationCount() == disk_state_only_committed_allocation_count,
            "Disk-state-only remount should preserve committed allocation count from checkpoint block");
        ok &= Require(
            remounted_disk_state_only.CommittedFreeExtentCount() == disk_state_only_committed_free_extent_count,
            "Disk-state-only remount should preserve committed free-extent count from checkpoint block");
        ok &= Require(
            remounted_disk_state_only.CommittedInodeCount() == disk_state_only_committed_inode_count,
            "Disk-state-only remount should preserve committed inode count from checkpoint block");
        ok &= Require(
            remounted_disk_state_only.CommittedBtreeRecordCount() == disk_state_only_committed_btree_count,
            "Disk-state-only remount should preserve committed btree record count from checkpoint block");
        auto disk_state_only_inode = remounted_disk_state_only.LookupCommittedInodeByPath(L"\\diskonly.bin");
        ok &= Require(
            disk_state_only_inode.has_value(),
            "Disk-state-only remount should preserve inode path exposure from checkpoint block");
        if (disk_state_only_inode.has_value())
        {
            std::vector<std::byte> disk_state_only_window;
            ok &= Require(
                remounted_disk_state_only.ReadCommittedFileRange(L"\\diskonly.bin", 0, disk_state_only_payload.size(), disk_state_only_window),
                "Disk-state-only remount should read persisted payload range");
            ok &= Require(
                disk_state_only_window == disk_state_only_payload,
                "Disk-state-only remount payload should match committed bytes");
        }
    }

    const auto canonical_non_fixture_disk_authoritative_fixture_image_path =
        run_root / "container_canonical_nonfixture_disk_authoritative_fixture.apfs.img";
    if (!CreateSyntheticContainer(canonical_non_fixture_disk_authoritative_fixture_image_path))
    {
        std::cerr << "[FAIL] unable to create synthetic APFS container image for canonical-nonfixture-disk-authoritative scenario" << std::endl;
        return 1;
    }

    apfsaccess::rw::MetadataStore::VolumeContext canonical_non_fixture_disk_authoritative_fixture_context
    {
        canonical_non_fixture_disk_authoritative_fixture_image_path.wstring(),
        L"CanonicalNonFixtureDiskAuthoritativeFixture",
    };
    const auto canonical_non_fixture_first_payload = BuildPatternPayload(768, 0x93);
    const auto canonical_non_fixture_second_payload = BuildPatternPayload(1536, 0xA6);
    const auto canonical_non_fixture_sidecar_snapshot_path =
        run_root / "canonical_nonfixture_disk_authoritative_stale_state.bin";

    {
        apfsaccess::rw::MetadataStore store(canonical_non_fixture_disk_authoritative_fixture_context);
        ok &= Require(
            store.LoadContainerSuperblocks(),
            "Canonical-nonfixture-disk-authoritative fixture LoadContainerSuperblocks should succeed");
        ok &= Require(
            store.LoadObjectMap(),
            "Canonical-nonfixture-disk-authoritative fixture LoadObjectMap should succeed");
        ok &= Require(
            store.LoadSpacemanState(),
            "Canonical-nonfixture-disk-authoritative fixture LoadSpacemanState should succeed");
        ok &= Require(
            store.PrepareNativeWritePath(),
            "Canonical-nonfixture-disk-authoritative fixture PrepareNativeWritePath should succeed");

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

        apfsaccess::rw::MetadataStore::MutationRequest create_first{};
        create_first.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
        create_first.path = L"\\first.bin";
        ok &= Require(
            store.ApplyMutation(create_first) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Canonical-nonfixture-disk-authoritative first create should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_first{};
        write_first.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_first.path = L"\\first.bin";
        write_first.length = static_cast<std::uint64_t>(canonical_non_fixture_first_payload.size());
        ok &= Require(
            store.ApplyMutation(write_first) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Canonical-nonfixture-disk-authoritative first write should apply");
        staged_payloads[L"\\first.bin"] = canonical_non_fixture_first_payload;

        const auto first_commit = store.CommitPendingMutations();
        ok &= Require(
            first_commit == apfsaccess::rw::MetadataStore::CommitStatus::Committed,
            "Canonical-nonfixture-disk-authoritative first commit should succeed");

        const auto fixture_sidecar_path =
            BuildPersistentStatePathForTest(canonical_non_fixture_disk_authoritative_fixture_context);
        ok &= Require(
            !fixture_sidecar_path.empty(),
            "Canonical-nonfixture-disk-authoritative should resolve fixture sidecar path");
        if (!fixture_sidecar_path.empty())
        {
            std::error_code snapshot_ec;
            std::filesystem::copy_file(
                fixture_sidecar_path,
                canonical_non_fixture_sidecar_snapshot_path,
                std::filesystem::copy_options::overwrite_existing,
                snapshot_ec);
            ok &= Require(
                !snapshot_ec,
                "Canonical-nonfixture-disk-authoritative should snapshot stale sidecar after first commit");
        }

        apfsaccess::rw::MetadataStore::MutationRequest create_second{};
        create_second.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
        create_second.path = L"\\second.bin";
        ok &= Require(
            store.ApplyMutation(create_second) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Canonical-nonfixture-disk-authoritative second create should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_second{};
        write_second.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_second.path = L"\\second.bin";
        write_second.length = static_cast<std::uint64_t>(canonical_non_fixture_second_payload.size());
        ok &= Require(
            store.ApplyMutation(write_second) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Canonical-nonfixture-disk-authoritative second write should apply");
        staged_payloads[L"\\second.bin"] = canonical_non_fixture_second_payload;

        const auto second_commit = store.CommitPendingMutations();
        ok &= Require(
            second_commit == apfsaccess::rw::MetadataStore::CommitStatus::Committed,
            "Canonical-nonfixture-disk-authoritative second commit should succeed");
        ok &= Require(
            store.LastCommittedXid().value_or(0) == (kInitialCheckpointXid + 2),
            "Canonical-nonfixture-disk-authoritative second commit should advance xid");
    }

    const auto canonical_non_fixture_disk_authoritative_non_fixture_image_path =
        run_root / "container_canonical_nonfixture_disk_authoritative.bin";
    {
        std::error_code copy_ec;
        std::filesystem::copy_file(
            canonical_non_fixture_disk_authoritative_fixture_image_path,
            canonical_non_fixture_disk_authoritative_non_fixture_image_path,
            std::filesystem::copy_options::overwrite_existing,
            copy_ec);
        ok &= Require(
            !copy_ec,
            "Canonical-nonfixture-disk-authoritative should copy fixture image to non-fixture path");
    }

    apfsaccess::rw::MetadataStore::VolumeContext canonical_non_fixture_disk_authoritative_non_fixture_context
    {
        canonical_non_fixture_disk_authoritative_non_fixture_image_path.wstring(),
        L"CanonicalNonFixtureDiskAuthoritative",
    };
    std::filesystem::path canonical_non_fixture_injected_sidecar_path;
    {
        const auto non_fixture_sidecar_path =
            BuildPersistentStatePathForTest(canonical_non_fixture_disk_authoritative_non_fixture_context);
        canonical_non_fixture_injected_sidecar_path = non_fixture_sidecar_path;
        ok &= Require(
            !non_fixture_sidecar_path.empty(),
            "Canonical-nonfixture-disk-authoritative should resolve non-fixture sidecar path");
        if (!non_fixture_sidecar_path.empty())
        {
            std::error_code copy_sidecar_ec;
            std::filesystem::create_directories(non_fixture_sidecar_path.parent_path(), copy_sidecar_ec);
            copy_sidecar_ec.clear();
            std::filesystem::copy_file(
                canonical_non_fixture_sidecar_snapshot_path,
                non_fixture_sidecar_path,
                std::filesystem::copy_options::overwrite_existing,
                copy_sidecar_ec);
            ok &= Require(
                !copy_sidecar_ec,
                "Canonical-nonfixture-disk-authoritative should inject stale sidecar into non-fixture context");

            std::ofstream corrupt_sidecar(non_fixture_sidecar_path, std::ios::binary | std::ios::trunc);
            ok &= Require(
                corrupt_sidecar.good(),
                "Canonical-nonfixture-disk-authoritative should open non-fixture sidecar for corruption test");
            if (corrupt_sidecar.good())
            {
                constexpr std::array<char, 16> kCorruptMagic =
                {
                    'N', 'O', 'T', '_', 'A', 'P', 'F', 'S',
                    '_', 'S', 'T', 'A', 'T', 'E', '_', 'X',
                };
                corrupt_sidecar.write(kCorruptMagic.data(), static_cast<std::streamsize>(kCorruptMagic.size()));
                ok &= Require(
                    corrupt_sidecar.good(),
                    "Canonical-nonfixture-disk-authoritative should persist corrupted sidecar magic");
            }
        }
    }

    {
        apfsaccess::rw::MetadataStore remounted(canonical_non_fixture_disk_authoritative_non_fixture_context);
        ok &= Require(
            remounted.LoadContainerSuperblocks(),
            "Canonical-nonfixture-disk-authoritative remount LoadContainerSuperblocks should succeed");
        ok &= Require(
            remounted.PrepareNativeWritePath(),
            "Canonical-nonfixture-disk-authoritative remount PrepareNativeWritePath should succeed");
        ok &= Require(
            !remounted.IsRecoveryRequired(),
            "Canonical-nonfixture-disk-authoritative remount should ignore stale sidecar-behind state");
        ok &= Require(
            remounted.IsCommitPathReady(),
            "Canonical-nonfixture-disk-authoritative remount should keep commit path ready");
        ok &= Require(
            remounted.LastCommittedXid().value_or(0) == (kInitialCheckpointXid + 2),
            "Canonical-nonfixture-disk-authoritative remount should keep on-disk xid");
        ok &= Require(
            remounted.LookupCommittedInodeByPath(L"\\first.bin").has_value(),
            "Canonical-nonfixture-disk-authoritative remount should keep first committed file");
        ok &= Require(
            remounted.LookupCommittedInodeByPath(L"\\second.bin").has_value(),
            "Canonical-nonfixture-disk-authoritative remount should keep second committed file from disk checkpoints");
        std::vector<std::byte> second_payload_window;
        ok &= Require(
            remounted.ReadCommittedFileRange(
                L"\\second.bin",
                0,
                canonical_non_fixture_second_payload.size(),
                second_payload_window),
            "Canonical-nonfixture-disk-authoritative remount should read second file payload");
        ok &= Require(
            second_payload_window == canonical_non_fixture_second_payload,
            "Canonical-nonfixture-disk-authoritative remount should use disk-checkpoint payload, not stale sidecar snapshot");

        if (!canonical_non_fixture_injected_sidecar_path.empty())
        {
            std::error_code sidecar_ec;
            ok &= Require(
                std::filesystem::exists(canonical_non_fixture_injected_sidecar_path, sidecar_ec),
                "Canonical-nonfixture-disk-authoritative remount should not consume non-fixture sidecar file");
            auto corrupt_suffix = canonical_non_fixture_injected_sidecar_path;
            corrupt_suffix += L".corrupt";
            sidecar_ec.clear();
            ok &= Require(
                !std::filesystem::exists(corrupt_suffix, sidecar_ec),
                "Canonical-nonfixture-disk-authoritative remount should not create .corrupt sidecar marker for non-fixture path");
        }
    }

    const auto coherent_rollback_fixture_image_path =
        run_root / "container_coherent_checkpoint_rollback_fixture.apfs.img";
    if (!CreateSyntheticContainer(coherent_rollback_fixture_image_path))
    {
        std::cerr << "[FAIL] unable to create synthetic APFS container image for coherent-checkpoint rollback scenario" << std::endl;
        return 1;
    }

    apfsaccess::rw::MetadataStore::VolumeContext coherent_rollback_fixture_context
    {
        coherent_rollback_fixture_image_path.wstring(),
        L"CoherentCheckpointRollbackFixture",
    };
    const auto coherent_rollback_first_payload = BuildPatternPayload(640, 0x4A);
    const auto coherent_rollback_second_payload = BuildPatternPayload(896, 0x6E);
    {
        const auto fixture_sidecar_path = BuildPersistentStatePathForTest(coherent_rollback_fixture_context);
        if (!fixture_sidecar_path.empty())
        {
            std::error_code remove_ec;
            std::filesystem::remove(fixture_sidecar_path, remove_ec);
        }
    }
    {
        apfsaccess::rw::MetadataStore store(coherent_rollback_fixture_context);
        ok &= Require(store.LoadContainerSuperblocks(), "Coherent-rollback setup LoadContainerSuperblocks should succeed");
        ok &= Require(store.LoadObjectMap(), "Coherent-rollback setup LoadObjectMap should succeed");
        ok &= Require(store.LoadSpacemanState(), "Coherent-rollback setup LoadSpacemanState should succeed");
        ok &= Require(store.PrepareNativeWritePath(), "Coherent-rollback setup PrepareNativeWritePath should succeed");

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

        apfsaccess::rw::MetadataStore::MutationRequest create_first{};
        create_first.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
        create_first.path = L"\\first_only_after_rollback.bin";
        ok &= Require(
            store.ApplyMutation(create_first) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Coherent-rollback first create should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_first{};
        write_first.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_first.path = L"\\first_only_after_rollback.bin";
        write_first.length = static_cast<std::uint64_t>(coherent_rollback_first_payload.size());
        ok &= Require(
            store.ApplyMutation(write_first) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Coherent-rollback first write should apply");
        staged_payloads[L"\\first_only_after_rollback.bin"] = coherent_rollback_first_payload;

        const auto first_commit = store.CommitPendingMutations();
        ok &= Require(
            first_commit == apfsaccess::rw::MetadataStore::CommitStatus::Committed,
            "Coherent-rollback first commit should succeed");
        ok &= Require(
            store.LastCommittedXid().value_or(0) == (kInitialCheckpointXid + 1),
            "Coherent-rollback first commit should advance xid");

        apfsaccess::rw::MetadataStore::MutationRequest create_second{};
        create_second.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
        create_second.path = L"\\lost_latest_generation.bin";
        ok &= Require(
            store.ApplyMutation(create_second) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Coherent-rollback second create should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_second{};
        write_second.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_second.path = L"\\lost_latest_generation.bin";
        write_second.length = static_cast<std::uint64_t>(coherent_rollback_second_payload.size());
        ok &= Require(
            store.ApplyMutation(write_second) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Coherent-rollback second write should apply");
        staged_payloads[L"\\lost_latest_generation.bin"] = coherent_rollback_second_payload;

        const auto second_commit = store.CommitPendingMutations();
        ok &= Require(
            second_commit == apfsaccess::rw::MetadataStore::CommitStatus::Committed,
            "Coherent-rollback second commit should succeed");
        ok &= Require(
            store.LastCommittedXid().value_or(0) == (kInitialCheckpointXid + 2),
            "Coherent-rollback second commit should advance xid");
    }

    std::size_t coherent_rollback_corrupted_blocks = 0;
    std::uint64_t coherent_rollback_corrupted_xid = 0;
    ok &= Require(
        CorruptLatestObjectMapCheckpointBlocks(
            coherent_rollback_fixture_image_path,
            kTotalBlocks,
            coherent_rollback_corrupted_blocks,
            coherent_rollback_corrupted_xid),
        "Coherent-rollback should corrupt latest object-map checkpoint block");
    ok &= Require(
        coherent_rollback_corrupted_blocks >= 1,
        "Coherent-rollback should corrupt at least one object-map checkpoint block");
    ok &= Require(
        coherent_rollback_corrupted_xid == (kInitialCheckpointXid + 2),
        "Coherent-rollback should target latest xid object-map checkpoint");

    const auto coherent_rollback_non_fixture_image_path =
        run_root / "container_coherent_checkpoint_rollback.bin";
    {
        std::error_code copy_ec;
        std::filesystem::copy_file(
            coherent_rollback_fixture_image_path,
            coherent_rollback_non_fixture_image_path,
            std::filesystem::copy_options::overwrite_existing,
            copy_ec);
        ok &= Require(
            !copy_ec,
            "Coherent-rollback should copy corrupted fixture image to non-fixture path");
    }

    apfsaccess::rw::MetadataStore::VolumeContext coherent_rollback_non_fixture_context
    {
        coherent_rollback_non_fixture_image_path.wstring(),
        L"CoherentCheckpointRollback",
    };
    {
        const auto non_fixture_sidecar_path = BuildPersistentStatePathForTest(coherent_rollback_non_fixture_context);
        if (!non_fixture_sidecar_path.empty())
        {
            std::error_code remove_ec;
            std::filesystem::remove(non_fixture_sidecar_path, remove_ec);
        }
    }
    {
        apfsaccess::rw::MetadataStore remounted(coherent_rollback_non_fixture_context);
        ok &= Require(
            remounted.LoadContainerSuperblocks(),
            "Coherent-rollback remount LoadContainerSuperblocks should succeed");
        ok &= Require(
            remounted.PrepareNativeWritePath(),
            "Coherent-rollback remount PrepareNativeWritePath should succeed after rolling back to prior coherent xid");
        ok &= Require(
            !remounted.IsRecoveryRequired(),
            "Coherent-rollback remount should not require recovery after selecting prior coherent xid");
        ok &= Require(
            remounted.IsCommitPathReady(),
            "Coherent-rollback remount should keep commit path ready after coherent rollback");
        ok &= Require(
            remounted.LastCommittedXid().value_or(0) == (kInitialCheckpointXid + 1),
            "Coherent-rollback remount should roll back to previous coherent xid");
        ok &= Require(
            remounted.LookupCommittedInodeByPath(L"\\first_only_after_rollback.bin").has_value(),
            "Coherent-rollback remount should preserve prior coherent file");
        ok &= Require(
            !remounted.LookupCommittedInodeByPath(L"\\lost_latest_generation.bin").has_value(),
            "Coherent-rollback remount should not expose latest-generation inode without matching object map");

        std::vector<std::byte> first_window;
        ok &= Require(
            remounted.ReadCommittedFileRange(
                L"\\first_only_after_rollback.bin",
                0,
                coherent_rollback_first_payload.size(),
                first_window),
            "Coherent-rollback remount should read prior coherent payload");
        ok &= Require(
            first_window == coherent_rollback_first_payload,
            "Coherent-rollback remount prior coherent payload should match");
    }

    const auto btree_rebuild_image_path = run_root / "container_btree_rebuild_inode_state.apfs.img";
    if (!CreateSyntheticContainer(btree_rebuild_image_path))
    {
        std::cerr << "[FAIL] unable to create synthetic APFS container image for btree-rebuild scenario" << std::endl;
        return 1;
    }

    apfsaccess::rw::MetadataStore::VolumeContext btree_rebuild_context
    {
        btree_rebuild_image_path.wstring(),
        L"BtreeRebuildInodeState",
    };
    const auto btree_rebuild_state_path = BuildPersistentStatePathForTest(btree_rebuild_context);
    if (!btree_rebuild_state_path.empty())
    {
        std::error_code remove_ec;
        std::filesystem::remove(btree_rebuild_state_path, remove_ec);
    }

    const auto btree_rebuild_payload = BuildPatternPayload(1536, 0xD2);
    std::size_t btree_rebuild_expected_inodes = 0;
    std::size_t btree_rebuild_expected_btree_records = 0;
    {
        apfsaccess::rw::MetadataStore store(btree_rebuild_context);
        ok &= Require(store.LoadContainerSuperblocks(), "Btree-rebuild LoadContainerSuperblocks should succeed");
        ok &= Require(store.LoadObjectMap(), "Btree-rebuild LoadObjectMap should succeed");
        ok &= Require(store.LoadSpacemanState(), "Btree-rebuild LoadSpacemanState should succeed");
        ok &= Require(store.PrepareNativeWritePath(), "Btree-rebuild PrepareNativeWritePath should succeed");

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
        create_dir.path = L"\\rebuild";
        ok &= Require(
            store.ApplyMutation(create_dir) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Btree-rebuild directory create should apply");

        apfsaccess::rw::MetadataStore::MutationRequest create_file{};
        create_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
        create_file.path = L"\\rebuild\\from_btree.bin";
        ok &= Require(
            store.ApplyMutation(create_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Btree-rebuild file create should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_file{};
        write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_file.path = L"\\rebuild\\from_btree.bin";
        write_file.length = static_cast<std::uint64_t>(btree_rebuild_payload.size());
        ok &= Require(
            store.ApplyMutation(write_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Btree-rebuild file write should apply");
        staged_payloads[L"\\rebuild\\from_btree.bin"] = btree_rebuild_payload;

        const auto commit_status = store.CommitPendingMutations();
        ok &= Require(
            commit_status == apfsaccess::rw::MetadataStore::CommitStatus::Committed,
            "Btree-rebuild setup commit should succeed");

        btree_rebuild_expected_inodes = store.CommittedInodeCount();
        btree_rebuild_expected_btree_records = store.CommittedBtreeRecordCount();
    }

    if (!btree_rebuild_state_path.empty())
    {
        std::error_code remove_ec;
        std::filesystem::remove(btree_rebuild_state_path, remove_ec);
    }

    std::size_t corrupted_inode_checkpoint_blocks = 0;
    ok &= Require(
        CorruptInodeCheckpointBlocks(
            btree_rebuild_image_path,
            kVolumeRootObject,
            kTotalBlocks,
            corrupted_inode_checkpoint_blocks),
        "Btree-rebuild scenario should locate inode checkpoint blocks for corruption");
    ok &= Require(
        corrupted_inode_checkpoint_blocks >= 1,
        "Btree-rebuild scenario should corrupt at least one inode checkpoint block");

    {
        apfsaccess::rw::MetadataStore remounted_btree_rebuild(btree_rebuild_context);
        ok &= Require(remounted_btree_rebuild.LoadContainerSuperblocks(), "Btree-rebuild remount LoadContainerSuperblocks should succeed");
        ok &= Require(remounted_btree_rebuild.PrepareNativeWritePath(), "Btree-rebuild remount PrepareNativeWritePath should succeed");
        ok &= Require(!remounted_btree_rebuild.IsRecoveryRequired(), "Btree-rebuild remount should remain clean (no recovery)");
        ok &= Require(remounted_btree_rebuild.IsCommitPathReady(), "Btree-rebuild remount should keep commit path ready");
        ok &= Require(
            remounted_btree_rebuild.CommittedInodeCount() == btree_rebuild_expected_inodes,
            "Btree-rebuild remount should reconstruct inode count from btree checkpoint records");
        ok &= Require(
            remounted_btree_rebuild.CommittedBtreeRecordCount() == btree_rebuild_expected_btree_records,
            "Btree-rebuild remount should preserve btree checkpoint record count");
        ok &= Require(
            remounted_btree_rebuild.LookupCommittedInodeByPath(L"\\REBUILD\\FROM_BTREE.BIN").has_value(),
            "Btree-rebuild remount should expose reconstructed path case-insensitively");

        std::vector<std::byte> rebuilt_window;
        ok &= Require(
            remounted_btree_rebuild.ReadCommittedFileRange(
                L"\\rebuild\\from_btree.bin",
                0,
                btree_rebuild_payload.size(),
                rebuilt_window),
            "Btree-rebuild remount should read payload via reconstructed inode state");
        ok &= Require(
            rebuilt_window == btree_rebuild_payload,
            "Btree-rebuild remount payload should match committed bytes");
    }

    const auto btree_rebuild_partial_inode_image_path = run_root / "container_btree_rebuild_partial_inode_state.apfs.img";
    if (!CreateSyntheticContainer(btree_rebuild_partial_inode_image_path))
    {
        std::cerr << "[FAIL] unable to create synthetic APFS container image for partial-inode btree-rebuild scenario" << std::endl;
        return 1;
    }

    apfsaccess::rw::MetadataStore::VolumeContext btree_rebuild_partial_inode_context
    {
        btree_rebuild_partial_inode_image_path.wstring(),
        L"BtreeRebuildPartialInodeState",
    };
    const auto btree_rebuild_partial_inode_state_path = BuildPersistentStatePathForTest(btree_rebuild_partial_inode_context);
    if (!btree_rebuild_partial_inode_state_path.empty())
    {
        std::error_code remove_ec;
        std::filesystem::remove(btree_rebuild_partial_inode_state_path, remove_ec);
    }

    const auto btree_rebuild_partial_inode_payload = BuildPatternPayload(2048, 0xB4);
    std::size_t btree_rebuild_partial_inode_expected_inodes = 0;
    std::size_t btree_rebuild_partial_inode_expected_btree_records = 0;
    {
        apfsaccess::rw::MetadataStore store(btree_rebuild_partial_inode_context);
        ok &= Require(store.LoadContainerSuperblocks(), "Partial-inode btree-rebuild LoadContainerSuperblocks should succeed");
        ok &= Require(store.LoadObjectMap(), "Partial-inode btree-rebuild LoadObjectMap should succeed");
        ok &= Require(store.LoadSpacemanState(), "Partial-inode btree-rebuild LoadSpacemanState should succeed");
        ok &= Require(store.PrepareNativeWritePath(), "Partial-inode btree-rebuild PrepareNativeWritePath should succeed");

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
        create_dir.path = L"\\partial";
        ok &= Require(
            store.ApplyMutation(create_dir) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Partial-inode btree-rebuild directory create should apply");

        apfsaccess::rw::MetadataStore::MutationRequest create_file{};
        create_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
        create_file.path = L"\\partial\\from_btree.bin";
        ok &= Require(
            store.ApplyMutation(create_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Partial-inode btree-rebuild file create should apply");

        apfsaccess::rw::MetadataStore::MutationRequest write_file{};
        write_file.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write_file.path = L"\\partial\\from_btree.bin";
        write_file.length = static_cast<std::uint64_t>(btree_rebuild_partial_inode_payload.size());
        ok &= Require(
            store.ApplyMutation(write_file) == apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Partial-inode btree-rebuild file write should apply");
        staged_payloads[L"\\partial\\from_btree.bin"] = btree_rebuild_partial_inode_payload;

        const auto commit_status = store.CommitPendingMutations();
        ok &= Require(
            commit_status == apfsaccess::rw::MetadataStore::CommitStatus::Committed,
            "Partial-inode btree-rebuild setup commit should succeed");

        btree_rebuild_partial_inode_expected_inodes = store.CommittedInodeCount();
        btree_rebuild_partial_inode_expected_btree_records = store.CommittedBtreeRecordCount();
    }

    if (!btree_rebuild_partial_inode_state_path.empty())
    {
        std::error_code remove_ec;
        std::filesystem::remove(btree_rebuild_partial_inode_state_path, remove_ec);
    }

    std::size_t rewritten_root_only_inode_checkpoint_blocks = 0;
    ok &= Require(
        WriteRootOnlyInodeCheckpointBlocks(
            btree_rebuild_partial_inode_image_path,
            kVolumeRootObject,
            kTotalBlocks,
            rewritten_root_only_inode_checkpoint_blocks),
        "Partial-inode btree-rebuild scenario should rewrite inode checkpoints to root-only state");
    ok &= Require(
        rewritten_root_only_inode_checkpoint_blocks >= 1,
        "Partial-inode btree-rebuild scenario should rewrite at least one inode checkpoint");

    {
        apfsaccess::rw::MetadataStore remounted_btree_rebuild(btree_rebuild_partial_inode_context);
        ok &= Require(remounted_btree_rebuild.LoadContainerSuperblocks(), "Partial-inode btree-rebuild remount LoadContainerSuperblocks should succeed");
        ok &= Require(remounted_btree_rebuild.PrepareNativeWritePath(), "Partial-inode btree-rebuild remount PrepareNativeWritePath should succeed");
        ok &= Require(!remounted_btree_rebuild.IsRecoveryRequired(), "Partial-inode btree-rebuild remount should remain clean (no recovery)");
        ok &= Require(remounted_btree_rebuild.IsCommitPathReady(), "Partial-inode btree-rebuild remount should keep commit path ready");
        ok &= Require(
            remounted_btree_rebuild.CommittedInodeCount() == btree_rebuild_partial_inode_expected_inodes,
            "Partial-inode btree-rebuild remount should replace root-only inode checkpoint with btree reconstruction");
        ok &= Require(
            remounted_btree_rebuild.CommittedBtreeRecordCount() == btree_rebuild_partial_inode_expected_btree_records,
            "Partial-inode btree-rebuild remount should preserve btree checkpoint record count");
        ok &= Require(
            remounted_btree_rebuild.LookupCommittedInodeByPath(L"\\PARTIAL\\FROM_BTREE.BIN").has_value(),
            "Partial-inode btree-rebuild remount should expose reconstructed path case-insensitively");

        std::vector<std::byte> rebuilt_window;
        ok &= Require(
            remounted_btree_rebuild.ReadCommittedFileRange(
                L"\\partial\\from_btree.bin",
                0,
                btree_rebuild_partial_inode_payload.size(),
                rebuilt_window),
            "Partial-inode btree-rebuild remount should read payload via reconstructed inode state");
        ok &= Require(
            rebuilt_window == btree_rebuild_partial_inode_payload,
            "Partial-inode btree-rebuild remount payload should match committed bytes");
    }

    if (!persistent_state_path.empty())
    {
        std::error_code remove_ec;
        std::filesystem::remove(persistent_state_path, remove_ec);
    }
    std::filesystem::remove_all(run_root, ec);
    if (!ok)
    {
        return 1;
    }

    std::cout << "[PASS] MetadataStorePersistenceTests" << std::endl;
    return 0;
}
