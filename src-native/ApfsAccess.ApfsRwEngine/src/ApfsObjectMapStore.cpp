#include "ApfsObjectMapStore.h"

#include <algorithm>
#include <array>
#include <limits>
#include <unordered_set>

namespace apfsaccess::rw
{
namespace
{
constexpr std::size_t kCheckpointHeaderBytes = 32;
constexpr std::size_t kCheckpointChecksumOffset = 28;
constexpr std::uint32_t kCheckpointChecksumSeed = 2166136261u;
constexpr std::uint32_t kCheckpointChecksumPrime = 16777619u;
constexpr std::size_t kRecordBytes = 32;

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

bool ApfsObjectMapStore::TryParseCheckpointV3(
    const std::vector<std::byte>& checkpoint_block,
    std::vector<ApfsObjectMapEntry>& out_entries,
    std::uint64_t& out_checkpoint_xid) const
{
    out_entries.clear();
    out_checkpoint_xid = 0;

    constexpr std::array<char, 12> kMagic =
    {
        'A', 'P', 'F', 'S', 'R', 'W', 'O', 'M', 'A', 'P', '3', '\0'
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
    const auto entry_count = ReadLe32(checkpoint_block, 20);
    const auto payload_bytes = static_cast<std::size_t>(ReadLe32(checkpoint_block, 24));
    const auto required_bytes = kCheckpointHeaderBytes + payload_bytes;
    if (required_bytes > checkpoint_block.size())
    {
        return false;
    }

    if ((payload_bytes % kRecordBytes) != 0)
    {
        return false;
    }

    const auto expected_count = payload_bytes / kRecordBytes;
    if (expected_count != entry_count)
    {
        return false;
    }

    const auto persisted_checksum = ReadLe32(checkpoint_block, kCheckpointChecksumOffset);
    if (persisted_checksum != 0 &&
        persisted_checksum != ComputeCheckpointChecksum(checkpoint_block, payload_bytes))
    {
        return false;
    }

    if (entry_count > static_cast<std::uint32_t>(std::numeric_limits<std::size_t>::max()))
    {
        return false;
    }

    out_entries.reserve(entry_count);
    std::size_t cursor = kCheckpointHeaderBytes;
    for (std::uint32_t index = 0; index < entry_count; ++index)
    {
        if (cursor > checkpoint_block.size() || kRecordBytes > (checkpoint_block.size() - cursor))
        {
            return false;
        }

        ApfsObjectMapEntry entry{};
        entry.object_id = ReadLe64(checkpoint_block, cursor + 0);
        entry.physical_address = ReadLe64(checkpoint_block, cursor + 8);
        entry.logical_size = ReadLe64(checkpoint_block, cursor + 16);
        entry.xid = ReadLe64(checkpoint_block, cursor + 24);
        out_entries.push_back(entry);
        cursor += kRecordBytes;
    }

    out_checkpoint_xid = xid;
    return ValidateEntries(out_entries);
}

bool ApfsObjectMapStore::ValidateEntries(const std::vector<ApfsObjectMapEntry>& entries) const
{
    std::unordered_set<std::uint64_t> seen_ids;
    seen_ids.reserve(entries.size());
    std::unordered_set<std::uint64_t> seen_nonzero_physical_addresses;
    seen_nonzero_physical_addresses.reserve(entries.size());

    for (const auto& entry : entries)
    {
        if (entry.object_id == 0)
        {
            return false;
        }
        if (!seen_ids.insert(entry.object_id).second)
        {
            return false;
        }
        if ((entry.physical_address == 0) != (entry.logical_size == 0))
        {
            return false;
        }
        if (entry.physical_address != 0 &&
            !seen_nonzero_physical_addresses.insert(entry.physical_address).second)
        {
            return false;
        }
        if (entry.xid == 0)
        {
            return false;
        }
    }

    return true;
}
} // namespace apfsaccess::rw
