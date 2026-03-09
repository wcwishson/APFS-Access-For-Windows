#include "ApfsSpacemanStore.h"

#include <algorithm>
#include <array>
#include <limits>
#include <optional>

namespace apfsaccess::rw
{
namespace
{
constexpr std::size_t kCheckpointHeaderBytes = 32;
constexpr std::size_t kCheckpointChecksumOffset = 28;
constexpr std::uint32_t kCheckpointChecksumSeed = 2166136261u;
constexpr std::uint32_t kCheckpointChecksumPrime = 16777619u;
constexpr std::size_t kRecordBytes = 16;

std::uint64_t ReadLe64(const std::vector<std::byte>& buffer, std::size_t offset)
{
    return static_cast<std::uint64_t>(std::to_integer<unsigned char>(buffer[offset + 0])) |
           (static_cast<std::uint64_t>(std::to_integer<unsigned char>(buffer[offset + 1])) << 8) |
           (static_cast<std::uint64_t>(std::to_integer<unsigned char>(buffer[offset + 2])) << 16) |
           (static_cast<std::uint64_t>(std::to_integer<unsigned char>(buffer[offset + 3])) << 24) |
           (static_cast<std::uint64_t>(std::to_integer<unsigned char>(buffer[offset + 4])) << 32) |
           (static_cast<std::uint64_t>(std::to_integer<unsigned char>(buffer[offset + 5])) << 40) |
           (static_cast<std::uint64_t>(std::to_integer<unsigned char>(buffer[offset + 6])) << 48) |
           (static_cast<std::uint64_t>(std::to_integer<unsigned char>(buffer[offset + 7])) << 56);
}

std::uint32_t ReadLe32(const std::vector<std::byte>& buffer, std::size_t offset)
{
    return static_cast<std::uint32_t>(std::to_integer<unsigned char>(buffer[offset + 0])) |
           (static_cast<std::uint32_t>(std::to_integer<unsigned char>(buffer[offset + 1])) << 8) |
           (static_cast<std::uint32_t>(std::to_integer<unsigned char>(buffer[offset + 2])) << 16) |
           (static_cast<std::uint32_t>(std::to_integer<unsigned char>(buffer[offset + 3])) << 24);
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

std::uint32_t ComputeCheckpointChecksum(const std::vector<std::byte>& block, std::size_t payload_bytes)
{
    if (block.size() < kCheckpointHeaderBytes || payload_bytes > (block.size() - kCheckpointHeaderBytes))
    {
        return 0;
    }

    auto hash = UpdateFnv1a(kCheckpointChecksumSeed, block.data(), kCheckpointChecksumOffset);
    if (payload_bytes > 0)
    {
        hash = UpdateFnv1a(hash, block.data() + kCheckpointHeaderBytes, payload_bytes);
    }
    return hash;
}
} // namespace

bool ApfsSpacemanStore::TryParseCheckpointV3(
    const std::vector<std::byte>& checkpoint_block,
    std::vector<ApfsExtent>& out_allocations,
    std::vector<ApfsExtent>& out_free_extents,
    std::uint64_t& out_checkpoint_xid) const
{
    out_allocations.clear();
    out_free_extents.clear();
    out_checkpoint_xid = 0;

    constexpr std::array<char, 12> kMagic =
    {
        'A', 'P', 'F', 'S', 'R', 'W', 'S', 'P', 'M', '3', '\0', '\0'
    };

    if (checkpoint_block.size() < kCheckpointHeaderBytes)
    {
        return false;
    }

    for (std::size_t index = 0; index < kMagic.size(); ++index)
    {
        if (std::to_integer<unsigned char>(checkpoint_block[index]) != static_cast<unsigned char>(kMagic[index]))
        {
            return false;
        }
    }

    const auto xid = ReadLe64(checkpoint_block, 12);
    const auto allocation_count = ReadLe32(checkpoint_block, 20);
    const auto free_count = ReadLe32(checkpoint_block, 24);

    const auto total_records = static_cast<std::uint64_t>(allocation_count) + static_cast<std::uint64_t>(free_count);
    if (total_records > (std::numeric_limits<std::size_t>::max() / kRecordBytes))
    {
        return false;
    }
    const auto payload_bytes = static_cast<std::size_t>(total_records) * kRecordBytes;
    const auto required_bytes = kCheckpointHeaderBytes + payload_bytes;
    if (required_bytes > checkpoint_block.size())
    {
        return false;
    }
    const auto persisted_checksum = ReadLe32(checkpoint_block, kCheckpointChecksumOffset);
    if (persisted_checksum != 0 &&
        persisted_checksum != ComputeCheckpointChecksum(checkpoint_block, payload_bytes))
    {
        return false;
    }

    out_allocations.reserve(allocation_count);
    out_free_extents.reserve(free_count);

    std::size_t cursor = kCheckpointHeaderBytes;
    const auto read_extent = [&](ApfsExtent& extent) -> bool
    {
        if (cursor > checkpoint_block.size() || kRecordBytes > (checkpoint_block.size() - cursor))
        {
            return false;
        }
        extent.physical_address = ReadLe64(checkpoint_block, cursor + 0);
        extent.bytes = ReadLe64(checkpoint_block, cursor + 8);
        cursor += kRecordBytes;
        return extent.physical_address != 0 && extent.bytes != 0;
    };

    for (std::uint32_t index = 0; index < allocation_count; ++index)
    {
        ApfsExtent extent{};
        if (!read_extent(extent))
        {
            return false;
        }
        out_allocations.push_back(extent);
    }

    for (std::uint32_t index = 0; index < free_count; ++index)
    {
        ApfsExtent extent{};
        if (!read_extent(extent))
        {
            return false;
        }
        out_free_extents.push_back(extent);
    }

    out_checkpoint_xid = xid;
    return ValidateState(out_allocations, out_free_extents);
}

bool ApfsSpacemanStore::ValidateState(
    const std::vector<ApfsExtent>& allocations,
    const std::vector<ApfsExtent>& free_extents) const
{
    const auto build_normalized = [](const std::vector<ApfsExtent>& source, std::vector<ApfsExtent>& normalized) -> bool
    {
        normalized = source;
        std::sort(
            normalized.begin(),
            normalized.end(),
            [](const ApfsExtent& lhs, const ApfsExtent& rhs)
            {
                if (lhs.physical_address == rhs.physical_address)
                {
                    return lhs.bytes < rhs.bytes;
                }
                return lhs.physical_address < rhs.physical_address;
            });

        std::optional<std::uint64_t> previous_end;
        for (const auto& extent : normalized)
        {
            if (extent.physical_address == 0 || extent.bytes == 0)
            {
                return false;
            }
            if (extent.physical_address > (std::numeric_limits<std::uint64_t>::max() - extent.bytes))
            {
                return false;
            }

            const auto extent_end = extent.physical_address + extent.bytes;
            if (previous_end.has_value() && extent.physical_address < previous_end.value())
            {
                return false;
            }
            previous_end = extent_end;
        }

        return true;
    };

    std::vector<ApfsExtent> normalized_allocations;
    std::vector<ApfsExtent> normalized_free_extents;
    if (!build_normalized(allocations, normalized_allocations) ||
        !build_normalized(free_extents, normalized_free_extents))
    {
        return false;
    }

    std::size_t allocation_index = 0;
    std::size_t free_index = 0;
    while (allocation_index < normalized_allocations.size() &&
           free_index < normalized_free_extents.size())
    {
        const auto& allocation = normalized_allocations[allocation_index];
        const auto& free_extent = normalized_free_extents[free_index];
        const auto allocation_end = allocation.physical_address + allocation.bytes;
        const auto free_end = free_extent.physical_address + free_extent.bytes;

        if (allocation_end <= free_extent.physical_address)
        {
            ++allocation_index;
            continue;
        }
        if (free_end <= allocation.physical_address)
        {
            ++free_index;
            continue;
        }

        if (allocation.physical_address < free_end &&
            free_extent.physical_address < allocation_end)
        {
            return false;
        }
    }

    return true;
}
} // namespace apfsaccess::rw
