#include "ApfsFormat.h"

#include <algorithm>
#include <array>
#include <cstdio>
#include <limits>
#include <queue>
#include <unordered_map>
#include <unordered_set>

namespace apfsaccess::catalog
{
namespace
{

constexpr std::uint64_t kFletcherModulus = 0xFFFFFFFFull;
constexpr std::uint32_t kMaxBtreeRecords = 100000;
constexpr std::size_t kMaxVisitedBlocks = 4096;
constexpr std::uint64_t kMaxGptEntries = 512;
constexpr std::size_t kMaxFsOidSlots = 100;

bool Materialize(const RandomAccessSource& source, std::uint64_t count, std::uint64_t bytes)
{
    const auto budget = source.ReadBudget();
    return !budget || budget->Materialize(count, bytes);
}

struct BudgetErrorScope
{
    const RandomAccessSource& source;
    std::string& error;
    ~BudgetErrorScope()
    {
        const auto budget = source.ReadBudget();
        if (budget && budget->Failed()) error = budget->Failure();
    }
};

bool ReadInto(const RandomAccessSource& source, std::uint64_t offset, std::size_t size, std::vector<std::byte>& out)
{
    out.clear();
    if (size == 0)
    {
        return true;
    }
    return source.Read(offset, size, out) && out.size() == size;
}

std::string ToLowerHexByte(unsigned char value)
{
    static constexpr char kDigits[] = "0123456789abcdef";
    std::string text;
    text.push_back(kDigits[(value >> 4) & 0xF]);
    text.push_back(kDigits[value & 0xF]);
    return text;
}

} // namespace

std::optional<std::uint16_t> ReadU16LE(const std::vector<std::byte>& buffer, std::size_t offset)
{
    if (offset + sizeof(std::uint16_t) > buffer.size())
    {
        return std::nullopt;
    }
    const auto lo = static_cast<std::uint16_t>(std::to_integer<unsigned char>(buffer[offset]));
    const auto hi = static_cast<std::uint16_t>(std::to_integer<unsigned char>(buffer[offset + 1]));
    return static_cast<std::uint16_t>(lo | (hi << 8));
}

std::optional<std::uint32_t> ReadU32LE(const std::vector<std::byte>& buffer, std::size_t offset)
{
    if (offset + sizeof(std::uint32_t) > buffer.size())
    {
        return std::nullopt;
    }
    std::uint32_t value = 0;
    for (int index = 0; index < 4; ++index)
    {
        value |= static_cast<std::uint32_t>(
                     std::to_integer<unsigned char>(buffer[offset + static_cast<std::size_t>(index)]))
            << (index * 8);
    }
    return value;
}

std::optional<std::uint64_t> ReadU64LE(const std::vector<std::byte>& buffer, std::size_t offset)
{
    if (offset + sizeof(std::uint64_t) > buffer.size())
    {
        return std::nullopt;
    }
    std::uint64_t value = 0;
    for (int index = 0; index < 8; ++index)
    {
        value |= static_cast<std::uint64_t>(
                     std::to_integer<unsigned char>(buffer[offset + static_cast<std::size_t>(index)]))
            << (index * 8);
    }
    return value;
}

std::optional<std::uint64_t> Fletcher64(const std::byte* data, std::size_t size)
{
    if (data == nullptr || size == 0 || size % sizeof(std::uint32_t) != 0)
    {
        return std::nullopt;
    }
    std::uint64_t sum1 = 0;
    std::uint64_t sum2 = 0;
    for (std::size_t offset = 0; offset < size; offset += sizeof(std::uint32_t))
    {
        std::uint32_t word = 0;
        for (int index = 0; index < 4; ++index)
        {
            word |= static_cast<std::uint32_t>(std::to_integer<unsigned char>(data[offset + static_cast<std::size_t>(index)]))
                << (index * 8);
        }
        sum1 += word;
        sum2 += sum1;
    }
    const std::uint64_t low = kFletcherModulus - ((sum1 + sum2) % kFletcherModulus);
    const std::uint64_t high = kFletcherModulus - ((sum1 + low) % kFletcherModulus);
    return (high << 32) | low;
}

bool VerifyObjectChecksum(const std::vector<std::byte>& block, std::size_t block_size)
{
    if (block_size < 12 || block.size() < block_size || (block_size - 8) % sizeof(std::uint32_t) != 0)
    {
        return false;
    }
    const auto stored = ReadU64LE(block, 0).value_or(0);
    if (stored == 0 || stored == 0xFFFFFFFFFFFFFFFFull)
    {
        return false;
    }
    const auto computed = Fletcher64(block.data() + 8, block_size - 8);
    return computed.has_value() && computed.value() == stored;
}

std::uint32_t Crc32(const std::byte* data, std::size_t size)
{
    std::uint32_t crc = 0xFFFFFFFFu;
    for (std::size_t offset = 0; offset < size; ++offset)
    {
        crc ^= static_cast<std::uint32_t>(std::to_integer<unsigned char>(data[offset]));
        for (int bit = 0; bit < 8; ++bit)
        {
            const std::uint32_t mask = 0xEDB88320u & (0u - (crc & 1u));
            crc = (crc >> 1) ^ mask;
        }
    }
    return ~crc;
}

std::string GuidToStringLower(const std::byte* sixteen_bytes)
{
    // Mixed-endian GPT layout: Data1/Data2/Data3 little-endian, Data4 raw.
    std::string text;
    for (int index = 3; index >= 0; --index)
    {
        text += ToLowerHexByte(std::to_integer<unsigned char>(sixteen_bytes[index]));
    }
    text.push_back('-');
    for (int index = 5; index >= 4; --index)
    {
        text += ToLowerHexByte(std::to_integer<unsigned char>(sixteen_bytes[index]));
    }
    text.push_back('-');
    for (int index = 7; index >= 6; --index)
    {
        text += ToLowerHexByte(std::to_integer<unsigned char>(sixteen_bytes[index]));
    }
    text.push_back('-');
    for (int index = 8; index < 10; ++index)
    {
        text += ToLowerHexByte(std::to_integer<unsigned char>(sixteen_bytes[index]));
    }
    text.push_back('-');
    for (int index = 10; index < 16; ++index)
    {
        text += ToLowerHexByte(std::to_integer<unsigned char>(sixteen_bytes[index]));
    }
    return text;
}

std::string BytesToHexLower(const std::byte* data, std::size_t size)
{
    std::string text;
    for (std::size_t index = 0; index < size; ++index)
    {
        text += ToLowerHexByte(std::to_integer<unsigned char>(data[index]));
    }
    return text;
}

namespace
{

bool BytesEqual(const std::vector<std::byte>& buffer, std::size_t offset, const char* text, std::size_t size)
{
    if (offset + size > buffer.size())
    {
        return false;
    }
    for (std::size_t index = 0; index < size; ++index)
    {
        if (buffer[offset + index] != static_cast<std::byte>(text[index]))
        {
            return false;
        }
    }
    return true;
}

bool ReadBlockAt(
    const RandomAccessSource& source,
    std::uint64_t offset_bytes,
    std::uint32_t block_size,
    std::vector<std::byte>& out_block)
{
    out_block.clear();
    if (block_size == 0)
    {
        return false;
    }
    return ReadInto(source, offset_bytes, block_size, out_block);
}

} // namespace

std::optional<GptLayout> ParseGpt(
    const RandomAccessSource& source, std::uint64_t base_offset, std::uint64_t size_bytes)
{
    constexpr std::uint64_t kProbeSectors[2] = {512, 4096};
    for (const std::uint64_t sector_size : kProbeSectors)
    {
        std::vector<std::byte> header;
        if (!ReadInto(source, base_offset + sector_size, static_cast<std::size_t>(sector_size), header) ||
            header.size() < 92 || !BytesEqual(header, 0, "EFI PART", 8))
        {
            continue;
        }
        const auto header_size = ReadU32LE(header, 12).value_or(0);
        const auto stored_crc = ReadU32LE(header, 16).value_or(0);
        const auto entry_count = ReadU32LE(header, 80).value_or(0);
        const auto entry_size = ReadU32LE(header, 84).value_or(0);
        const auto entries_lba = ReadU64LE(header, 72).value_or(0);
        if (header_size < 92 || header_size > header.size() || stored_crc == 0 ||
            entry_count == 0 || entry_count > kMaxGptEntries || entry_size != 128)
        {
            continue;
        }
        if (!Materialize(source, 0, header_size)) return std::nullopt;
        std::vector<std::byte> header_copy(header.begin(), header.begin() + header_size);
        for (int index = 0; index < 4; ++index)
        {
            header_copy[16 + static_cast<std::size_t>(index)] = std::byte{0};
        }
        if (Crc32(header_copy.data(), header_copy.size()) != stored_crc)
        {
            continue;
        }
        const auto entries_bytes = static_cast<std::uint64_t>(entry_count) * 128ull;
        if (entries_lba > (0xFFFFFFFFFFFFFFFFull - entries_bytes) / sector_size)
        {
            continue;
        }
        const std::uint64_t entries_offset = base_offset + entries_lba * sector_size;
        std::vector<std::byte> entries;
        if (!ReadInto(source, entries_offset, static_cast<std::size_t>(entries_bytes), entries))
        {
            continue;
        }
        const auto stored_entries_crc = ReadU32LE(header, 88).value_or(0);
        if (stored_entries_crc == 0 || Crc32(entries.data(), entries.size()) != stored_entries_crc)
        {
            continue;
        }

        GptLayout layout;
        layout.sector_size = sector_size;
        layout.disk_guid = GuidToStringLower(header.data() + 56);
        const std::uint64_t disk_end = base_offset + size_bytes;
        const std::uint64_t first_usable_lba = ReadU64LE(header, 40).value_or(0);
        const std::uint64_t last_usable_lba = ReadU64LE(header, 48).value_or(0);
        if (first_usable_lba == 0 || last_usable_lba < first_usable_lba)
        {
            continue;
        }
        std::vector<std::pair<std::uint64_t, std::uint64_t>> accepted_ranges;
        for (std::uint32_t index = 0; index < entry_count; ++index)
        {
            const std::size_t base = static_cast<std::size_t>(index) * 128;
            bool has_type = false;
            for (int b = 0; b < 16; ++b)
            {
                if (entries[base + static_cast<std::size_t>(b)] != std::byte{0})
                {
                    has_type = true;
                    break;
                }
            }
            if (!has_type)
            {
                continue;
            }
            const auto start_lba = ReadU64LE(entries, base + 32).value_or(0);
            const auto end_lba = ReadU64LE(entries, base + 40).value_or(0);
            if (start_lba == 0 || end_lba < start_lba)
            {
                continue;
            }
            if (start_lba < first_usable_lba || end_lba > last_usable_lba)
            {
                return std::nullopt;
            }
            if (start_lba > (0xFFFFFFFFFFFFFFFFull - base_offset) / sector_size)
            {
                continue;
            }
            const std::uint64_t start_bytes = base_offset + start_lba * sector_size;
            const std::uint64_t span_sectors = end_lba - start_lba + 1;
            if (span_sectors > (0xFFFFFFFFFFFFFFFFull - start_bytes) / sector_size ||
                start_bytes >= disk_end)
            {
                continue;
            }
            std::uint64_t span_bytes = span_sectors * sector_size;
            if (start_bytes + span_bytes > disk_end)
            {
                span_bytes = disk_end - start_bytes;
            }
            if (span_bytes == 0)
            {
                continue;
            }
            const std::uint64_t range_end = start_bytes + span_bytes;
            for (const auto& accepted : accepted_ranges)
            {
                if (start_bytes < accepted.second && accepted.first < range_end)
                {
                    return std::nullopt;
                }
            }
            if (!Materialize(source, 1, sizeof(GptPartition) + 128)) return std::nullopt;
            accepted_ranges.emplace_back(start_bytes, range_end);
            GptPartition partition;
            partition.number = index + 1;
            partition.type_guid = GuidToStringLower(entries.data() + base);
            partition.unique_guid = GuidToStringLower(entries.data() + base + 16);
            partition.start_bytes = start_bytes;
            partition.size_bytes = span_bytes;
            // UTF-16LE name, best effort ASCII projection.
            std::string name;
            for (int c = 0; c < 36; ++c)
            {
                const auto unit = ReadU16LE(entries, base + 56 + static_cast<std::size_t>(c) * 2).value_or(0);
                if (unit == 0)
                {
                    break;
                }
                name.push_back(unit < 0x80 ? static_cast<char>(unit) : '?');
            }
            partition.name_utf8 = std::move(name);
            layout.partitions.push_back(std::move(partition));
        }
        return layout;
    }
    return std::nullopt;
}

std::optional<NxSuperblock> ParseNxSuperblock(const std::vector<std::byte>& block)
{
    if (block.size() < 0xC0 || !BytesEqual(block, 0x20, "NXSB", 4))
    {
        return std::nullopt;
    }
    const std::uint32_t block_size = ReadU32LE(block, 0x24).value_or(0);
    if (block_size < 4096 || block_size > 65536 ||
        (block_size & (block_size - 1)) != 0 || block.size() < block_size)
    {
        return std::nullopt;
    }
    if (!VerifyObjectChecksum(block, block_size))
    {
        return std::nullopt;
    }
    const std::uint64_t total_blocks = ReadU64LE(block, 0x28).value_or(0);
    if (total_blocks == 0)
    {
        return std::nullopt;
    }
    bool uuid_nonzero = false;
    for (int index = 0; index < 16; ++index)
    {
        if (block[0x48 + static_cast<std::size_t>(index)] != std::byte{0})
        {
            uuid_nonzero = true;
            break;
        }
    }
    if (!uuid_nonzero)
    {
        return std::nullopt;
    }
    NxSuperblock out;
    out.object_id = ReadU64LE(block, 0x08).value_or(0);
    out.xid = ReadU64LE(block, 0x10).value_or(0);
    if (out.object_id != 1 || out.xid == 0 ||
        (ReadU32LE(block, 0x18).value_or(0) & kObjectTypeMask) != kNxSuperblockObjectType)
    {
        return std::nullopt;
    }
    out.block_size = block_size;
    out.block_count = total_blocks;
    out.features = ReadU64LE(block, 0x30).value_or(0);
    out.readonly_features = ReadU64LE(block, 0x38).value_or(0);
    out.incompatible_features = ReadU64LE(block, 0x40).value_or(0);
    out.uuid_hex = BytesToHexLower(block.data() + 0x48, 16);
    out.next_oid = ReadU64LE(block, 0x58).value_or(0);
    out.next_xid = ReadU64LE(block, 0x60).value_or(0);
    out.xp_desc_blocks_raw = ReadU32LE(block, 0x68).value_or(0);
    out.xp_data_blocks_raw = ReadU32LE(block, 0x6C).value_or(0);
    out.xp_desc_noncontiguous = (out.xp_desc_blocks_raw & 0x80000000u) != 0;
    out.xp_data_noncontiguous = (out.xp_data_blocks_raw & 0x80000000u) != 0;
    out.xp_desc_block_count = out.xp_desc_blocks_raw & 0x7FFFFFFFu;
    out.xp_data_block_count = out.xp_data_blocks_raw & 0x7FFFFFFFu;
    out.xp_desc_base_block = ReadU64LE(block, 0x70).value_or(0);
    out.xp_data_base_block = ReadU64LE(block, 0x78).value_or(0);
    out.xp_desc_next = ReadU32LE(block, 0x80).value_or(0);
    out.xp_data_next = ReadU32LE(block, 0x84).value_or(0);
    out.xp_desc_index = ReadU32LE(block, 0x88).value_or(0);
    out.xp_desc_len = ReadU32LE(block, 0x8C).value_or(0);
    out.xp_data_index = ReadU32LE(block, 0x90).value_or(0);
    out.xp_data_len = ReadU32LE(block, 0x94).value_or(0);
    out.spaceman_oid = ReadU64LE(block, 0x98).value_or(0);
    out.omap_oid = ReadU64LE(block, 0xA0).value_or(0);
    out.reaper_oid = ReadU64LE(block, 0xA8).value_or(0);
    if (out.omap_oid == 0)
    {
        return std::nullopt;
    }
    if (out.xp_desc_block_count != 0 && out.xp_desc_base_block == 0)
    {
        return std::nullopt;
    }
    if (out.xp_data_block_count != 0 && out.xp_data_base_block == 0)
    {
        return std::nullopt;
    }
    const auto max_file_systems = ReadU32LE(block, 0xB4).value_or(0);
    constexpr std::size_t kFsOidOffset = 0xB8;
    constexpr std::size_t kFsOidBytes = kMaxFsOidSlots * sizeof(std::uint64_t);
    if (max_file_systems == 0 || max_file_systems > kMaxFsOidSlots ||
        block_size < kFsOidOffset + kFsOidBytes)
    {
        return std::nullopt;
    }
    for (std::size_t slot = 0; slot < kMaxFsOidSlots; ++slot)
    {
        const auto oid = ReadU64LE(block, kFsOidOffset + slot * sizeof(std::uint64_t)).value_or(0);
        if (oid != 0)
        {
            if (slot >= max_file_systems)
            {
                return std::nullopt;
            }
            out.fs_oids.push_back(oid);
        }
    }
    return out;
}

namespace
{

constexpr std::uint32_t kCheckpointMapLast = 0x00000001;
constexpr std::uint32_t kMaxCheckpointAreaBlocks = 65536;
constexpr std::size_t kCheckpointMappingBytes = 0x28;

bool TryBlockOffset(
    std::uint64_t store_offset,
    std::uint64_t block_number,
    std::uint32_t block_size,
    std::uint64_t& out_offset)
{
    if (block_size == 0 ||
        block_number > (std::numeric_limits<std::uint64_t>::max() - store_offset) / block_size)
    {
        return false;
    }
    out_offset = store_offset + block_number * static_cast<std::uint64_t>(block_size);
    return true;
}

bool AreaFitsStore(
    std::uint64_t base,
    std::uint32_t count,
    const NxSuperblock& superblock,
    std::uint64_t store_size_bytes)
{
    if (count == 0)
    {
        return base == 0;
    }
    if (base == 0 || base >= superblock.block_count ||
        count > superblock.block_count - base)
    {
        return false;
    }
    const auto end_block = base + count;
    return end_block <= store_size_bytes / superblock.block_size;
}

bool RingFieldsValid(std::uint32_t index, std::uint32_t length,
    std::uint32_t next, std::uint32_t count)
{
    if (count == 0)
    {
        return index == 0 && length == 0 && next == 0;
    }
    if (index >= count || length > count || next >= count)
    {
        return false;
    }
    return next == static_cast<std::uint32_t>(
        (static_cast<std::uint64_t>(index) + length) % count);
}

bool RingContainsRange(
    std::uint32_t index,
    std::uint32_t length,
    std::uint32_t count,
    std::uint32_t candidate_index,
    std::uint32_t candidate_length)
{
    if (count == 0 || candidate_length == 0 || candidate_length > length)
    {
        return false;
    }
    for (std::uint32_t outer = 0; outer < length; ++outer)
    {
        const auto expected = static_cast<std::uint32_t>(
            (static_cast<std::uint64_t>(index) + outer) % count);
        if (expected != candidate_index)
        {
            continue;
        }
        for (std::uint32_t inner = 0; inner < candidate_length; ++inner)
        {
            const auto actual = static_cast<std::uint32_t>(
                (static_cast<std::uint64_t>(candidate_index) + inner) % count);
            const auto allowed = static_cast<std::uint32_t>(
                (static_cast<std::uint64_t>(index) + outer + inner) % count);
            if (actual != allowed || outer + inner >= length)
            {
                return false;
            }
        }
        return true;
    }
    return false;
}

bool VerifyMappedObjectChecksum(
    const RandomAccessSource& source,
    std::uint64_t store_offset,
    const NxSuperblock& superblock,
    std::uint32_t first_relative_block,
    std::uint32_t object_blocks)
{
    constexpr std::uint64_t kModulus = 0xFFFFFFFFull;
    std::uint64_t stored = 0;
    std::uint64_t sum1 = 0;
    std::uint64_t sum2 = 0;
    for (std::uint32_t ordinal = 0; ordinal < object_blocks; ++ordinal)
    {
        const auto relative = static_cast<std::uint32_t>(
            (static_cast<std::uint64_t>(first_relative_block) + ordinal) %
            superblock.xp_data_block_count);
        std::uint64_t offset = 0;
        std::vector<std::byte> block;
        if (!TryBlockOffset(store_offset,
                superblock.xp_data_base_block + relative,
                superblock.block_size, offset) ||
            !ReadInto(source, offset, superblock.block_size, block))
        {
            return false;
        }
        if (ordinal == 0)
        {
            stored = ReadU64LE(block, 0).value_or(0);
            if (stored == 0 || stored == std::numeric_limits<std::uint64_t>::max())
            {
                return false;
            }
        }
        const std::size_t start = ordinal == 0 ? sizeof(std::uint64_t) : 0;
        for (std::size_t position = start; position < block.size(); position += 4)
        {
            const auto word = ReadU32LE(block, position).value_or(0);
            sum1 = (sum1 + word) % kModulus;
            sum2 = (sum2 + sum1) % kModulus;
        }
    }
    const auto low = kModulus - ((sum1 + sum2) % kModulus);
    const auto high = kModulus - ((sum1 + low) % kModulus);
    return ((high << 32) | low) == stored;
}

bool ParseCheckpointMapBlock(
    const std::vector<std::byte>& block,
    std::uint64_t expected_xid,
    std::uint64_t expected_physical_block,
    std::vector<CheckpointMapping>& out_mappings,
    bool& out_last,
    const RandomAccessSource& source)
{
    out_mappings.clear();
    out_last = false;
    if (!VerifyObjectChecksum(block, block.size()) ||
        ReadU64LE(block, 0x08).value_or(0) != expected_physical_block ||
        ReadU64LE(block, 0x10).value_or(0) != expected_xid ||
        ReadU32LE(block, 0x18).value_or(0) !=
            (kObjectPhysical | kObjectTypeCheckpointMap) ||
        ReadU32LE(block, 0x1C).value_or(0) != 0)
    {
        return false;
    }
    const auto flags = ReadU32LE(block, 0x20).value_or(0);
    if ((flags & ~kCheckpointMapLast) != 0)
    {
        return false;
    }
    out_last = (flags & kCheckpointMapLast) != 0;
    const auto count = ReadU32LE(block, 0x24).value_or(0);
    if (count > (block.size() - 0x28) / kCheckpointMappingBytes)
    {
        return false;
    }
    if (!Materialize(source, count, static_cast<std::uint64_t>(count) * sizeof(CheckpointMapping))) return false;
    out_mappings.reserve(count);
    for (std::uint32_t index = 0; index < count; ++index)
    {
        const auto offset = 0x28 + static_cast<std::size_t>(index) * kCheckpointMappingBytes;
        CheckpointMapping mapping;
        mapping.type = ReadU32LE(block, offset).value_or(0);
        mapping.subtype = ReadU32LE(block, offset + 0x04).value_or(0);
        mapping.size_bytes = ReadU32LE(block, offset + 0x08).value_or(0);
        mapping.file_system_oid = ReadU64LE(block, offset + 0x10).value_or(0);
        mapping.object_id = ReadU64LE(block, offset + 0x18).value_or(0);
        mapping.physical_block = ReadU64LE(block, offset + 0x20).value_or(0);
        if (ReadU32LE(block, offset + 0x0C).value_or(0) != 0 ||
            (mapping.type & kObjectStorageTypeMask) != kObjectEphemeral ||
            (mapping.subtype & kObjectStorageTypeMask) != 0 ||
            mapping.size_bytes == 0 || mapping.object_id == 0 || mapping.physical_block == 0)
        {
            return false;
        }
        out_mappings.push_back(mapping);
    }
    return true;
}

bool ValidateMappedObject(
    const RandomAccessSource& source,
    std::uint64_t store_offset,
    std::uint64_t store_size_bytes,
    const NxSuperblock& superblock,
    const CheckpointMapping& mapping)
{
    if (mapping.size_bytes % superblock.block_size != 0 ||
        superblock.xp_data_block_count == 0)
    {
        return false;
    }
    const auto object_blocks = mapping.size_bytes / superblock.block_size;
    if (object_blocks == 0 || object_blocks > superblock.xp_data_block_count ||
        mapping.physical_block < superblock.xp_data_base_block)
    {
        return false;
    }
    const auto relative = mapping.physical_block - superblock.xp_data_base_block;
    if (relative >= superblock.xp_data_block_count ||
        !RingContainsRange(superblock.xp_data_index, superblock.xp_data_len,
            superblock.xp_data_block_count, static_cast<std::uint32_t>(relative), object_blocks))
    {
        return false;
    }
    std::uint64_t object_offset = 0;
    if (!TryBlockOffset(store_offset, mapping.physical_block,
            superblock.block_size, object_offset) ||
        object_offset < store_offset ||
        superblock.block_size > store_size_bytes - (object_offset - store_offset))
    {
        return false;
    }
    if ((mapping.type & kObjectNoHeader) != 0)
    {
        return true;
    }
    std::vector<std::byte> header;
    if (!ReadInto(source, object_offset, 32, header) ||
        ReadU64LE(header, 0x08).value_or(0) != mapping.object_id ||
        ReadU64LE(header, 0x10).value_or(0) != superblock.xid ||
        ReadU32LE(header, 0x18).value_or(0) != mapping.type ||
        ReadU32LE(header, 0x1C).value_or(0) != mapping.subtype)
    {
        return false;
    }
    return VerifyMappedObjectChecksum(source, store_offset, superblock,
        static_cast<std::uint32_t>(relative), object_blocks);
}

bool SameCheckpointGeometry(const NxSuperblock& left, const NxSuperblock& right)
{
    return left.uuid_hex == right.uuid_hex &&
        left.block_size == right.block_size &&
        left.block_count == right.block_count &&
        left.xp_desc_blocks_raw == right.xp_desc_blocks_raw &&
        left.xp_data_blocks_raw == right.xp_data_blocks_raw &&
        left.xp_desc_base_block == right.xp_desc_base_block &&
        left.xp_data_base_block == right.xp_data_base_block;
}

std::optional<ContainerCheckpointView> BuildCheckpointCandidate(
    const RandomAccessSource& source,
    std::uint64_t store_offset,
    std::uint64_t store_size_bytes,
    const NxSuperblock& anchor,
    const std::vector<std::vector<std::byte>>& descriptor_blocks,
    std::uint32_t candidate_index)
{
    if (!Materialize(source, 0, sizeof(NxSuperblock) + kMaxFsOidSlots * sizeof(std::uint64_t) + 64))
        return std::nullopt;
    auto candidate = ParseNxSuperblock(descriptor_blocks[candidate_index]);
    if (!candidate.has_value() || !SameCheckpointGeometry(anchor, candidate.value()) ||
        !RingFieldsValid(candidate->xp_desc_index, candidate->xp_desc_len,
            candidate->xp_desc_next, candidate->xp_desc_block_count) ||
        candidate->xp_desc_len == 0 ||
        candidate_index != (candidate->xp_desc_next + candidate->xp_desc_block_count - 1) %
            candidate->xp_desc_block_count ||
        !RingFieldsValid(candidate->xp_data_index, candidate->xp_data_len,
            candidate->xp_data_next, candidate->xp_data_block_count))
    {
        return std::nullopt;
    }

    ContainerCheckpointView view;
    view.superblock = candidate.value();
    view.superblock_physical_block =
        candidate->xp_desc_base_block + candidate_index;
    if (!Materialize(source, 1, descriptor_blocks[candidate_index].size())) return std::nullopt;
    view.superblock_bytes = descriptor_blocks[candidate_index];
    std::unordered_set<std::uint64_t> mapped_oids;
    const auto map_block_count = candidate->xp_desc_len - 1;
    for (std::uint32_t offset = 0; offset < map_block_count; ++offset)
    {
        const auto ring_index = static_cast<std::uint32_t>(
            (static_cast<std::uint64_t>(candidate->xp_desc_index) + offset) %
            candidate->xp_desc_block_count);
        std::vector<CheckpointMapping> block_mappings;
        bool is_last = false;
        const auto physical_block = candidate->xp_desc_base_block + ring_index;
        if (!ParseCheckpointMapBlock(
                descriptor_blocks[ring_index], candidate->xid, physical_block,
                block_mappings, is_last, source) ||
            is_last != (offset + 1 == map_block_count))
        {
            return std::nullopt;
        }
        if (!Materialize(source, 0, sizeof(std::uint64_t))) return std::nullopt;
        view.checkpoint_map_blocks.push_back(candidate->xp_desc_base_block + ring_index);
        for (const auto& mapping : block_mappings)
        {
            if (!Materialize(source, 0, sizeof(std::uint64_t)) ||
                !mapped_oids.insert(mapping.object_id).second ||
                !ValidateMappedObject(source, store_offset, store_size_bytes,
                    candidate.value(), mapping))
            {
                return std::nullopt;
            }
            if (!Materialize(source, 1, sizeof(mapping))) return std::nullopt;
            view.mappings.push_back(mapping);
        }
    }
    const auto has_mapping = [&](std::uint64_t object_id) {
        return object_id == 0 || mapped_oids.find(object_id) != mapped_oids.end();
    };
    if (!has_mapping(candidate->spaceman_oid) || !has_mapping(candidate->reaper_oid))
    {
        return std::nullopt;
    }
    return view;
}

std::optional<ContainerCheckpointView> LoadLegacySyntheticCheckpoint(
    const RandomAccessSource& source,
    std::uint64_t store_offset_bytes,
    std::uint64_t store_size_bytes,
    const NxSuperblock& primary,
    const std::vector<std::byte>& primary_bytes)
{
    ContainerCheckpointView selected;
    if (!Materialize(source, 0, primary_bytes.size() + kMaxFsOidSlots * sizeof(std::uint64_t) + 64))
        return std::nullopt;
    selected.superblock = primary;
    selected.superblock_bytes = primary_bytes;
    if (store_size_bytes < static_cast<std::uint64_t>(primary.block_size) * 2)
    {
        return selected;
    }
    std::vector<std::byte> second;
    std::uint64_t second_offset = 0;
    if (!TryBlockOffset(store_offset_bytes, 1, primary.block_size, second_offset) ||
        !ReadBlockAt(source, second_offset, primary.block_size, second))
    {
        return selected;
    }
    auto secondary = ParseNxSuperblock(second);
    if (!secondary.has_value())
    {
        return selected;
    }
    if (!SameCheckpointGeometry(primary, secondary.value()))
    {
        return std::nullopt;
    }
    if (secondary->xid > primary.xid)
    {
        selected.superblock = secondary.value();
        selected.superblock_physical_block = 1;
        selected.superblock_bytes = std::move(second);
    }
    return selected;
}

} // namespace

std::optional<ContainerCheckpointView> LoadContainerCheckpointView(
    const RandomAccessSource& source,
    std::uint64_t store_offset_bytes,
    std::uint64_t store_size_bytes,
    std::string& out_error,
    std::optional<std::uint64_t> exact_checkpoint_xid)
{
    BudgetErrorScope budget_error{source, out_error};
    out_error.clear();
    if (exact_checkpoint_xid == 0)
    {
        out_error = "CheckpointExactXidInvalid";
        return std::nullopt;
    }
    std::vector<std::byte> probe;
    if (!ReadInto(source, store_offset_bytes, 4096, probe))
    {
        out_error = "CheckpointBlockZeroUnreadable";
        return std::nullopt;
    }
    const std::uint32_t block_size = ReadU32LE(probe, 0x24).value_or(0);
    if (block_size < 4096 || block_size > 65536 ||
        (block_size & (block_size - 1)) != 0)
    {
        out_error = "CheckpointBlockSizeInvalid";
        return std::nullopt;
    }
    std::vector<std::byte> block_zero;
    if (!ReadBlockAt(source, store_offset_bytes, block_size, block_zero))
    {
        out_error = "CheckpointBlockZeroUnreadable";
        return std::nullopt;
    }
    if (!Materialize(source, 0, sizeof(NxSuperblock) + kMaxFsOidSlots * sizeof(std::uint64_t) + 64))
        return std::nullopt;
    auto anchor = ParseNxSuperblock(block_zero);
    if (!anchor.has_value())
    {
        if (exact_checkpoint_xid.has_value())
        {
            out_error = "CheckpointBlockZeroInvalid";
            return std::nullopt;
        }
        // Compatibility for the pre-catalog synthetic fixtures only. A real
        // APFS mount cannot recover descriptor geometry without block zero.
        std::vector<std::byte> synthetic_second;
        std::uint64_t second_offset = 0;
        if (TryBlockOffset(store_offset_bytes, 1, block_size, second_offset) &&
            ReadBlockAt(source, second_offset, block_size, synthetic_second))
        {
            auto secondary = ParseNxSuperblock(synthetic_second);
            if (secondary.has_value() && secondary->xp_desc_block_count == 0 &&
                secondary->spaceman_oid == 0)
            {
                ContainerCheckpointView synthetic;
                synthetic.superblock = secondary.value();
                synthetic.superblock_physical_block = 1;
                synthetic.superblock_bytes = std::move(synthetic_second);
                return synthetic;
            }
        }
        out_error = "CheckpointBlockZeroInvalid";
        return std::nullopt;
    }
    if (anchor->block_size != block_size ||
        anchor->block_count > store_size_bytes / block_size)
    {
        out_error = "CheckpointBlockZeroInvalid";
        return std::nullopt;
    }
    if (anchor->xp_desc_noncontiguous)
    {
        out_error = "CheckpointDescriptorTreeUnsupported";
        return std::nullopt;
    }
    if (anchor->xp_data_noncontiguous)
    {
        out_error = "CheckpointDataTreeUnsupported";
        return std::nullopt;
    }
    if (anchor->xp_desc_block_count == 0)
    {
        if (exact_checkpoint_xid.has_value())
        {
            out_error = "CheckpointExactGenerationUnavailable";
            return std::nullopt;
        }
        auto legacy = LoadLegacySyntheticCheckpoint(
            source, store_offset_bytes, store_size_bytes, anchor.value(), block_zero);
        if (source.ReadBudget() && source.ReadBudget()->Failed()) return std::nullopt;
        if (!legacy.has_value())
        {
            out_error = "CheckpointSyntheticCopiesConflict";
        }
        return legacy;
    }
    if (anchor->xp_desc_block_count > kMaxCheckpointAreaBlocks ||
        anchor->xp_data_block_count > kMaxCheckpointAreaBlocks ||
        !AreaFitsStore(anchor->xp_desc_base_block, anchor->xp_desc_block_count,
            anchor.value(), store_size_bytes) ||
        !AreaFitsStore(anchor->xp_data_base_block, anchor->xp_data_block_count,
            anchor.value(), store_size_bytes))
    {
        out_error = "CheckpointAreaGeometryInvalid";
        return std::nullopt;
    }

    if (!Materialize(source, anchor->xp_desc_block_count,
            static_cast<std::uint64_t>(anchor->xp_desc_block_count) * sizeof(std::vector<std::byte>)))
        return std::nullopt;
    std::vector<std::vector<std::byte>> descriptor_blocks(anchor->xp_desc_block_count);
    for (std::uint32_t index = 0; index < anchor->xp_desc_block_count; ++index)
    {
        std::uint64_t offset = 0;
        if (!TryBlockOffset(store_offset_bytes, anchor->xp_desc_base_block + index,
                block_size, offset) ||
            !ReadBlockAt(source, offset, block_size, descriptor_blocks[index]))
        {
            out_error = "CheckpointDescriptorAreaUnreadable";
            return std::nullopt;
        }
    }

    std::optional<ContainerCheckpointView> best;
    for (std::uint32_t index = 0; index < anchor->xp_desc_block_count; ++index)
    {
        auto candidate = BuildCheckpointCandidate(source, store_offset_bytes,
            store_size_bytes, anchor.value(), descriptor_blocks, index);
        if (source.ReadBudget() && source.ReadBudget()->Failed()) return std::nullopt;
        if (exact_checkpoint_xid.has_value())
        {
            if (!candidate.has_value() || candidate->superblock.xid != *exact_checkpoint_xid ||
                candidate->checkpoint_map_blocks.empty() || candidate->superblock.spaceman_oid == 0)
            {
                continue;
            }
            if (best.has_value())
            {
                out_error = "CheckpointExactGenerationAmbiguous";
                return std::nullopt;
            }
        }
        if (candidate.has_value() &&
            (!best.has_value() || candidate->superblock.xid > best->superblock.xid))
        {
            best = std::move(candidate);
        }
    }
    if (best.has_value())
    {
        return best;
    }
    if (exact_checkpoint_xid.has_value())
    {
        out_error = "CheckpointExactGenerationUnavailable";
        return std::nullopt;
    }

    // Old synthetic fixtures used a descriptor-area shape without a spaceman
    // or actual checkpoint maps. Keep that shape readable in tests only; a
    // production APFS container always carries an ephemeral spaceman mapping.
    if (anchor->spaceman_oid == 0)
    {
        ContainerCheckpointView synthetic;
        synthetic.superblock = anchor.value();
        synthetic.superblock_bytes = std::move(block_zero);
        return synthetic;
    }
    out_error = "CheckpointNoCompleteGeneration";
    return std::nullopt;
}

std::optional<NxSuperblock> SelectContainerCheckpoint(
    const RandomAccessSource& source,
    std::uint64_t store_offset_bytes,
    std::uint64_t store_size_bytes)
{
    std::string error;
    auto view = LoadContainerCheckpointView(
        source, store_offset_bytes, store_size_bytes, error);
    if (!view.has_value())
    {
        return std::nullopt;
    }
    return view->superblock;
}

bool ReadBtreeLeafRecords(
    const RandomAccessSource& source,
    std::uint32_t block_size,
    std::uint64_t root_block,
    bool child_addresses_are_physical,
    std::uint64_t child_object_map_oid,
    std::uint64_t max_xid_hint,
    std::vector<BtreeRecord>& out_records,
    std::string& out_error)
{
    return ReadBtreeLeafRecords(source, block_size, root_block,
        child_addresses_are_physical, child_object_map_oid, max_xid_hint,
        BtreeReadPolicy{}, out_records, out_error);
}

bool ReadBtreeLeafRecords(
    const RandomAccessSource& source,
    std::uint32_t block_size,
    std::uint64_t root_block,
    bool child_addresses_are_physical,
    std::uint64_t child_object_map_oid,
    std::uint64_t max_xid_hint,
    const BtreeReadPolicy& policy,
    std::vector<BtreeRecord>& out_records,
    std::string& out_error)
{
    BudgetErrorScope budget_error{source, out_error};
    bool complete = false;
    struct ClearIncomplete
    {
        bool& complete;
        std::vector<BtreeRecord>& records;
        std::vector<std::uint64_t>* visited;
        ~ClearIncomplete() { if (!complete) { records.clear(); if (visited) visited->clear(); } }
    } clear_incomplete{complete, out_records, policy.visited_physical_blocks};
    out_records.clear();
    out_error.clear();
    if (policy.visited_physical_blocks != nullptr)
    {
        policy.visited_physical_blocks->clear();
    }
    if (block_size == 0 || root_block == 0)
    {
        out_error = "CatalogBtreeRootInvalid";
        return false;
    }
    struct PendingNode
    {
        std::uint64_t physical_block = 0;
        std::uint64_t object_id = 0;
        bool root = false;
        std::optional<std::uint16_t> expected_level;
        std::optional<std::uint64_t> mapping_xid;
    };
    std::queue<PendingNode> pending;
    if (!Materialize(source, 0, sizeof(PendingNode))) return false;
    pending.push({root_block, policy.root_object_id, true, std::nullopt, std::nullopt});
    std::unordered_set<std::uint64_t> visited;
    if (!source.ReadBudget()) visited.reserve(kMaxVisitedBlocks);
    std::vector<std::byte> block;
    bool root_layout_seen = false;
    std::uint32_t tree_key_size = 0;
    std::uint32_t tree_value_size = 0;
    std::uint64_t declared_key_count = 0;
    std::uint64_t declared_node_count = 0;
    while (!pending.empty())
    {
        const PendingNode current = pending.front();
        pending.pop();
        const std::uint64_t block_index = current.physical_block;
        if (!Materialize(source, 0, sizeof(std::uint64_t))) return false;
        if (!visited.insert(block_index).second)
        {
            if (policy.require_complete_traversal)
            {
                out_error = "CatalogBtreeRepeatedNode";
                return false;
            }
            continue;
        }
        if (visited.size() > kMaxVisitedBlocks)
        {
            out_error = "CatalogBtreeCycle";
            return false;
        }
        if (block_size != 0 && block_index > (0xFFFFFFFFFFFFFFFFull / block_size))
        {
            out_error = "CatalogBtreeBlockOverflow";
            return false;
        }
        if (!ReadBlockAt(source, block_index * block_size, block_size, block))
        {
            out_error = "CatalogBtreeBlockUnreadable";
            return false;
        }
        if (!VerifyObjectChecksum(block, block_size))
        {
            out_error = "CatalogBtreeChecksumInvalid";
            return false;
        }
        if (max_xid_hint != 0 || current.mapping_xid)
        {
            const std::uint64_t node_xid = ReadU64LE(block, 0x10).value_or(0xFFFFFFFFFFFFFFFFull);
            if ((max_xid_hint != 0 && node_xid > max_xid_hint) ||
                (current.mapping_xid && node_xid > *current.mapping_xid))
            {
                out_error = "CatalogBtreeFutureXid";
                return false;
            }
        }
        const std::uint64_t object_id = ReadU64LE(block, 0x08).value_or(0);
        const std::uint32_t full_object_type = ReadU32LE(block, 0x18).value_or(0xFFFFFFFFu);
        const std::uint32_t object_type = full_object_type & kObjectTypeMask;
        if (object_type != kObjectTypeBtree && object_type != kObjectTypeBtreeNode)
        {
            out_error = "CatalogBtreeNotABtree";
            return false;
        }
        if (policy.enforce_object_identity)
        {
            if (object_id != current.object_id)
            {
                out_error = "CatalogBtreeObjectIdMismatch";
                return false;
            }
            const auto expected_base_type = current.root
                ? kObjectTypeBtree
                : kObjectTypeBtreeNode;
            if (object_type != expected_base_type)
            {
                out_error = "CatalogBtreeNodeTypeMismatch";
                return false;
            }
            if ((full_object_type & kObjectStorageTypeMask) !=
                    (policy.storage_type & kObjectStorageTypeMask))
            {
                out_error = "CatalogBtreeStorageTypeMismatch";
                return false;
            }
            if (ReadU32LE(block, 0x1C).value_or(0xFFFFFFFFu) != policy.subtype)
            {
                out_error = "CatalogBtreeSubtypeMismatch";
                return false;
            }
        }
        if (policy.visited_physical_blocks != nullptr)
        {
            if (!Materialize(source, 0, sizeof(std::uint64_t))) return false;
            policy.visited_physical_blocks->push_back(block_index);
        }
        const std::uint16_t flags = ReadU16LE(block, 0x20).value_or(0);
        if (policy.reject_unsupported_flags &&
            ((full_object_type & ~(kObjectStorageTypeMask | kObjectTypeMask)) != 0 ||
             (flags & ~0x0007u) != 0 || ReadU64LE(block, 0x10).value_or(0) == 0))
        {
            out_error = "CatalogBtreeUnsupportedFlagsOrZeroXid";
            return false;
        }
        const std::uint16_t level = ReadU16LE(block, 0x22).value_or(0xFFFFu);
        const std::uint32_t key_count = ReadU32LE(block, 0x24).value_or(kMaxBtreeRecords + 1);
        const std::uint16_t table_offset = ReadU16LE(block, 0x28).value_or(0xFFFFu);
        const std::uint16_t table_length = ReadU16LE(block, 0x2A).value_or(0xFFFFu);
        const std::uint16_t free_offset = ReadU16LE(block, 0x2C).value_or(0xFFFFu);
        const std::uint16_t free_length = ReadU16LE(block, 0x2E).value_or(0xFFFFu);
        if (policy.require_complete_traversal &&
            ((current.expected_level && level != *current.expected_level) || (level != 0 && key_count == 0)))
        {
            out_error = "CatalogBtreeLevelInvalid";
            return false;
        }
        if (level == 0xFFFFu || key_count > kMaxBtreeRecords || table_offset == 0xFFFFu ||
            table_length == 0xFFFFu || free_offset == 0xFFFFu || free_length == 0xFFFFu)
        {
            out_error = "CatalogBtreeHeaderInvalid";
            return false;
        }
        const bool fixed_kv = (flags & 0x0004u) != 0;
        const bool is_root = (flags & 0x0001u) != 0;
        const bool is_leaf = (flags & 0x0002u) != 0;
        if (policy.enforce_object_identity && is_root != current.root)
        {
            out_error = "CatalogBtreeRootFlagMismatch";
            return false;
        }
        if (is_leaf != (level == 0) || (flags & 0x8000u) != 0)
        {
            out_error = "CatalogBtreeNodeFlagsInvalid";
            return false;
        }
        if (is_root && block.size() < 40)
        {
            out_error = "CatalogBtreeInfoInvalid";
            return false;
        }
        const std::size_t info_start = is_root ? (block.size() - 40) : block.size();
        if (is_root)
        {
            if (policy.reject_unsupported_flags)
            {
                const auto tree_flags = ReadU32LE(block, info_start).value_or(~0u);
                const auto storage = full_object_type & kObjectStorageTypeMask;
                // Accept the understood persistent layouts and hints.
                // NONPERSISTENT, hashes, no-header, and actual ghost records
                // are not supported by this strict on-disk traversal.
                if ((tree_flags & ~0x7Fu) != 0 || (tree_flags & 0x20u) != 0 ||
                    ((tree_flags & 0x10u) != 0) != (storage == kObjectPhysical) ||
                    ((tree_flags & 0x08u) != 0) != (storage == kObjectEphemeral))
                {
                    out_error = "CatalogBtreeUnsupportedTreeFlags";
                    return false;
                }
                declared_key_count = ReadU64LE(block, info_start + 24).value_or(~0ull);
                declared_node_count = ReadU64LE(block, info_start + 32).value_or(0);
            }
            const auto node_size = ReadU32LE(block, info_start + 4).value_or(0);
            tree_key_size = ReadU32LE(block, info_start + 8).value_or(0);
            tree_value_size = ReadU32LE(block, info_start + 12).value_or(0);
            if (node_size != block_size)
            {
                out_error = "CatalogBtreeInfoInvalid";
                return false;
            }
            root_layout_seen = true;
        }
        else if (!root_layout_seen)
        {
            out_error = "CatalogBtreeRootInfoMissing";
            return false;
        }
        const bool expected_fixed_kv = tree_key_size != 0 &&
            (level != 0 || tree_value_size != 0);
        if (fixed_kv != expected_fixed_kv)
        {
            out_error = "CatalogBtreeNodeLayoutMismatch";
            return false;
        }
        const std::size_t entry_size = fixed_kv ? 4 : 8;
        const std::size_t table_start = 0x38 + table_offset;
        const std::size_t key_area_start = table_start + table_length;
        const std::size_t free_start = key_area_start + free_offset;
        const std::size_t value_area_start = free_start + free_length;
        const std::size_t value_area_end = info_start;
        if (key_count > 100000 || table_start > block.size() ||
            key_area_start > block.size() || value_area_start > block.size() ||
            value_area_end > block.size() || value_area_start > value_area_end ||
            static_cast<std::uint64_t>(key_count) * entry_size > (block.size() - table_start))
        {
            out_error = "CatalogBtreeBoundsInvalid";
            return false;
        }
        if (policy.require_complete_traversal &&
            static_cast<std::uint64_t>(key_count) * entry_size > table_length)
        {
            out_error = "CatalogBtreeTableInvalid";
            return false;
        }
        for (std::uint32_t index = 0; index < key_count; ++index)
        {
            const std::size_t entry_offset = table_start + static_cast<std::size_t>(index) * entry_size;
            std::uint16_t key_offset = 0;
            std::uint16_t key_length = 0;
            std::uint16_t value_offset = 0;
            std::uint16_t value_length = 0;
            if (fixed_kv)
            {
                key_offset = ReadU16LE(block, entry_offset).value_or(0xFFFFu);
                value_offset = ReadU16LE(block, entry_offset + 2).value_or(0xFFFFu);
                if (tree_key_size > std::numeric_limits<std::uint16_t>::max() ||
                    (level == 0 && tree_value_size > std::numeric_limits<std::uint16_t>::max()))
                {
                    out_error = "CatalogBtreeFixedSizeInvalid";
                    return false;
                }
                key_length = static_cast<std::uint16_t>(tree_key_size);
                value_length = static_cast<std::uint16_t>(
                    level == 0 ? tree_value_size : sizeof(std::uint64_t));
            }
            else
            {
                key_offset = ReadU16LE(block, entry_offset).value_or(0xFFFFu);
                key_length = ReadU16LE(block, entry_offset + 2).value_or(0xFFFFu);
                value_offset = ReadU16LE(block, entry_offset + 4).value_or(0xFFFFu);
                value_length = ReadU16LE(block, entry_offset + 6).value_or(0xFFFFu);
                if ((tree_key_size != 0 && key_length != tree_key_size) ||
                    (level == 0 && tree_value_size != 0 && value_length != tree_value_size))
                {
                    out_error = "CatalogBtreeEntrySizeMismatch";
                    return false;
                }
            }
            const bool ghost = level == 0 && value_offset == 0xFFFFu;
            if (policy.require_complete_traversal && (key_offset == 0xFFFFu || ghost || key_length == 0))
            {
                out_error = "CatalogBtreeMissingEntry";
                return false;
            }
            if (key_offset == 0xFFFFu || (ghost && !policy.include_ghost_records))
            {
                continue;
            }
            if ((!ghost && value_offset == 0xFFFFu) ||
                key_area_start + key_offset > block.size() ||
                key_length > block.size() - (key_area_start + key_offset) ||
                (!ghost && (value_offset > value_area_end ||
                    value_length > value_area_end ||
                    value_area_end - value_offset > block.size() ||
                    value_length > block.size() - (value_area_end - value_offset))))
            {
                out_error = "CatalogBtreeEntryInvalid";
                return false;
            }
            const std::size_t key_start = key_area_start + key_offset;
            const std::size_t value_start = ghost ? value_area_end :
                value_area_end - value_offset;
            if (policy.require_complete_traversal &&
                (key_start > free_start || key_length > free_start - key_start ||
                    value_start < value_area_start || value_length > value_area_end - value_start))
            {
                out_error = "CatalogBtreeEntryRegionInvalid";
                return false;
            }
            if (level == 0)
            {
                if (!Materialize(source, 1, sizeof(BtreeRecord) +
                        static_cast<std::uint64_t>(key_length) + (ghost ? 0 : value_length))) return false;
                BtreeRecord record;
                record.key.assign(
                    block.begin() + static_cast<std::vector<std::byte>::difference_type>(key_start),
                    block.begin() + static_cast<std::vector<std::byte>::difference_type>(key_start + key_length));
                if (!ghost)
                {
                    record.value.assign(
                        block.begin() + static_cast<std::vector<std::byte>::difference_type>(value_start),
                        block.begin() + static_cast<std::vector<std::byte>::difference_type>(value_start + value_length));
                }
                out_records.push_back(std::move(record));
                continue;
            }
            if (value_length < sizeof(std::uint64_t))
            {
                out_error = "CatalogBtreeChildInvalid";
                return false;
            }
            if (policy.reject_unsupported_flags && value_length != sizeof(std::uint64_t))
            {
                out_error = "CatalogBtreeUnsupportedChildValue";
                return false;
            }
            std::uint64_t child_object_id = 0;
            for (int b = 0; b < 8; ++b)
            {
                child_object_id |= static_cast<std::uint64_t>(std::to_integer<unsigned char>(
                    block[value_start + static_cast<std::size_t>(b)])) << (b * 8);
            }
            std::uint64_t child_block = child_object_id;
            std::optional<std::uint64_t> child_mapping_xid;
            if (policy.require_complete_traversal && child_object_id == 0)
            {
                out_error = "CatalogBtreeChildInvalid";
                return false;
            }
            if (!child_addresses_are_physical)
            {
                if (policy.virtual_child_resolver)
                {
                    const auto mapped = policy.virtual_child_resolver(child_object_id, out_error);
                    if (!mapped || mapped->physical_block == 0) return false;
                    child_block = mapped->physical_block;
                    child_mapping_xid = mapped->xid;
                }
                else if (policy.ephemeral_checkpoint != nullptr &&
                    (policy.storage_type & kObjectStorageTypeMask) == kObjectEphemeral)
                {
                    const auto& mappings = policy.ephemeral_checkpoint->mappings;
                    const auto mapped = std::find_if(mappings.begin(), mappings.end(),
                        [child_object_id](const CheckpointMapping& mapping) {
                            return mapping.object_id == child_object_id;
                        });
                    if (mapped == mappings.end() || mapped->file_system_oid != 0 ||
                        mapped->physical_block == 0 || mapped->size_bytes != block_size ||
                        mapped->type != (kObjectEphemeral | kObjectTypeBtreeNode) ||
                        mapped->subtype != policy.subtype)
                    {
                        out_error = "CatalogBtreeChildCheckpointMappingInvalid";
                        return false;
                    }
                    child_block = mapped->physical_block;
                }
                else
                {
                    auto mapped = ResolveOmapValue(
                        source, block_size, child_object_map_oid, child_block, max_xid_hint, out_error);
                    if (!mapped.has_value() || mapped->physical_block == 0)
                    {
                        out_error = "CatalogBtreeChildUnmapped";
                        return false;
                    }
                    child_block = mapped->physical_block;
                }
            }
            if (child_block != 0)
            {
                if (!Materialize(source, 0, sizeof(PendingNode))) return false;
                pending.push({child_block, child_object_id, false,
                    static_cast<std::uint16_t>(level - 1), child_mapping_xid});
            }
        }
    }
    if (policy.reject_unsupported_flags &&
        (declared_key_count != out_records.size() || declared_node_count != visited.size()))
    {
        out_error = "CatalogBtreeDeclaredCountsMismatch";
        return false;
    }
    complete = true;
    return true;
}

std::optional<OmapValue> ResolveOmapValue(
    const RandomAccessSource& source,
    std::uint32_t block_size,
    std::uint64_t map_oid,
    std::uint64_t oid,
    std::uint64_t max_xid,
    std::string& out_error)
{
    BudgetErrorScope budget_error{source, out_error};
    out_error.clear();
    if (block_size == 0 || map_oid == 0 || oid == 0)
    {
        out_error = "CatalogOmapRequestInvalid";
        return std::nullopt;
    }
    if (map_oid > (0xFFFFFFFFFFFFFFFFull / block_size))
    {
        out_error = "CatalogOmapBlockOverflow";
        return std::nullopt;
    }
    std::vector<std::byte> omap;
    if (!ReadBlockAt(source, map_oid * block_size, block_size, omap))
    {
        out_error = "CatalogOmapUnreadable";
        return std::nullopt;
    }
    if (!VerifyObjectChecksum(omap, block_size))
    {
        out_error = "CatalogOmapChecksumInvalid";
        return std::nullopt;
    }
    const std::uint32_t omap_type = ReadU32LE(omap, 0x18).value_or(0xFFFFFFFFu);
    if ((omap_type & kObjectTypeMask) != kObjectTypeOmap)
    {
        out_error = "CatalogOmapNotAnOmap";
        return std::nullopt;
    }
    if (max_xid != 0)
    {
        const std::uint64_t omap_xid = ReadU64LE(omap, 0x10).value_or(0xFFFFFFFFFFFFFFFFull);
        if (omap_xid > max_xid)
        {
            out_error = "CatalogOmapFutureXid";
            return std::nullopt;
        }
    }
    const std::uint64_t tree_oid = ReadU64LE(omap, 0x30).value_or(0);
    if (tree_oid == 0)
    {
        out_error = "CatalogOmapTreeMissing";
        return std::nullopt;
    }
    std::vector<BtreeRecord> records;
    const std::uint32_t tree_type = ReadU32LE(omap, 0x28).value_or(0);
    const bool has_strict_identity =
        (omap_type & kObjectStorageTypeMask) == kObjectPhysical &&
        (tree_type & kObjectStorageTypeMask) == kObjectPhysical &&
        (tree_type & kObjectTypeMask) == kObjectTypeBtree;
    BtreeReadPolicy policy;
    policy.require_complete_traversal = true;
    if (has_strict_identity)
    {
        if (ReadU64LE(omap, 0x08).value_or(0) != map_oid)
        {
            out_error = "CatalogOmapObjectIdMismatch";
            return std::nullopt;
        }
        policy.enforce_object_identity = true;
        policy.root_object_id = tree_oid;
        policy.storage_type = kObjectPhysical;
        policy.subtype = kObjectTypeOmap;
    }
    if (!ReadBtreeLeafRecords(source, block_size, tree_oid, true, 0, max_xid,
            policy, records, out_error))
    {
        return std::nullopt;
    }
    std::optional<OmapValue> selected;
    bool newest_is_tombstone = false;
    std::unordered_map<std::uint64_t, std::unordered_set<std::uint64_t>> seen_xids;
    for (const auto& record : records)
    {
        if (record.key.size() != 16 || record.value.size() != 16)
        {
            out_error = "CatalogOmapRecordSizeInvalid";
            return std::nullopt;
        }
        const auto candidate_oid = ReadU64LE(record.key, 0).value_or(0xFFFFFFFFFFFFFFFFull);
        const auto candidate_xid = ReadU64LE(record.key, 8).value_or(0xFFFFFFFFFFFFFFFFull);
        if (!Materialize(source, 0, 2 * sizeof(std::uint64_t))) return std::nullopt;
        if (!seen_xids[candidate_oid].insert(candidate_xid).second)
        {
            out_error = "CatalogOmapKeyDuplicate";
            return std::nullopt;
        }
        if (candidate_oid != oid || candidate_xid > max_xid)
        {
            continue;
        }
        OmapValue value;
        value.flags = ReadU32LE(record.value, 0).value_or(0xFFFFFFFFu);
        value.size = ReadU32LE(record.value, 4).value_or(0);
        value.physical_block = ReadU64LE(record.value, 8).value_or(0);
        value.xid = candidate_xid;
        if (!selected.has_value() || value.xid > selected->xid)
        {
            selected = value;
            newest_is_tombstone = value.flags == 0xFFFFFFFFu ||
                (value.flags & 0x1u) != 0 || value.physical_block == 0;
        }
    }
    if (!selected.has_value())
    {
        out_error = "CatalogOmapValueMissing";
        return std::nullopt;
    }
    if (newest_is_tombstone)
    {
        out_error = "CatalogOmapValueDeleted";
        return std::nullopt;
    }
    return selected;
}

std::optional<ApsbVolume> ParseApsb(const std::vector<std::byte>& block)
{
    if (block.size() < 0x414 || !BytesEqual(block, 0x20, "APSB", 4))
    {
        return std::nullopt;
    }
    if ((ReadU32LE(block, 0x18).value_or(0xFFFFFFFFu) & kObjectTypeMask) != kObjectTypeFs)
    {
        return std::nullopt;
    }
    // Callers pass exactly one block; verify the whole buffer as the block.
    if (!VerifyObjectChecksum(block, block.size()))
    {
        return std::nullopt;
    }
    ApsbVolume out;
    // Apple File System Reference, apfs_superblock_t: original fields
    // apfs_fs_reserve_block_count, apfs_fs_quota_block_count, apfs_fs_alloc_count.
    out.space.reserve_block_count = ReadU64LE(block, 0x48).value();
    out.space.quota_block_count = ReadU64LE(block, 0x50).value();
    out.space.allocated_block_count = ReadU64LE(block, 0x58).value();
    out.object_id = ReadU64LE(block, 0x08).value_or(0);
    out.xid = ReadU64LE(block, 0x10).value_or(0);
    out.root_tree_type = ReadU32LE(block, 0x74).value_or(0);
    out.extentref_tree_type = ReadU32LE(block, 0x78).value_or(0);
    out.snap_meta_tree_type = ReadU32LE(block, 0x7C).value_or(0);
    out.omap_oid = ReadU64LE(block, 0x80).value_or(0);
    out.root_oid = ReadU64LE(block, 0x88).value_or(0);
    out.extentref_tree_oid = ReadU64LE(block, 0x90).value_or(0);
    out.snap_meta_tree_oid = ReadU64LE(block, 0x98).value_or(0);
    out.fext_tree_oid = ReadU64LE(block, 0x408).value_or(0);
    out.fext_tree_type = ReadU32LE(block, 0x410).value_or(0);
    out.file_count = ReadU64LE(block, 0xB8).value_or(0);
    out.next_object_id = ReadU64LE(block, 0xB0).value_or(0);
    out.directory_count = ReadU64LE(block, 0xC0).value_or(0);
    out.features = ReadU64LE(block, 0x28).value_or(0);
    out.readonly_features = ReadU64LE(block, 0x30).value_or(0);
    out.incompatible_features = ReadU64LE(block, 0x38).value_or(0);
    if (out.object_id == 0 || out.omap_oid == 0 || out.root_oid == 0)
    {
        return std::nullopt;
    }
    bool uuid_nonzero = false;
    for (int index = 0; index < 16; ++index)
    {
        if (block[0xF0 + static_cast<std::size_t>(index)] != std::byte{0})
        {
            uuid_nonzero = true;
            break;
        }
    }
    out.uuid_hex = uuid_nonzero ? BytesToHexLower(block.data() + 0xF0, 16) : std::string{};
    out.fs_flags = ReadU64LE(block, 0x108).value_or(0);
    // Volume name: strict UTF-8, NUL-terminated within the 256-byte field.
    std::size_t name_end = 0;
    bool terminated = false;
    for (std::size_t index = 0; index < 256; ++index)
    {
        if (block[0x2C0 + index] == std::byte{0})
        {
            terminated = true;
            break;
        }
        ++name_end;
    }
    out.name_valid = terminated && IsValidUtf8(block.data() + 0x2C0, name_end);
    out.name_utf8.clear();
    if (out.name_valid)
    {
        for (std::size_t index = 0; index < name_end; ++index)
        {
            out.name_utf8.push_back(static_cast<char>(block[0x2C0 + index]));
        }
    }
    out.role_raw = ReadU16LE(block, 0x3C4).value_or(0);
    bool group_nonzero = false;
    for (int index = 0; index < 16; ++index)
    {
        if (block[0x3F0 + static_cast<std::size_t>(index)] != std::byte{0})
        {
            group_nonzero = true;
            break;
        }
    }
    out.group_hex = group_nonzero ? BytesToHexLower(block.data() + 0x3F0, 16) : std::string{};
    return out;
}

namespace
{

bool ReadAppleObject(
    const RandomAccessSource& source,
    std::uint32_t block_size,
    std::uint64_t physical_block,
    std::uint32_t size_bytes,
    std::uint64_t expected_object_id,
    std::uint64_t max_xid,
    std::uint32_t expected_storage_type,
    std::uint32_t expected_base_type,
    std::optional<std::uint32_t> expected_subtype,
    const std::string& error_prefix,
    AppleObjectLocation& out_location,
    std::vector<std::byte>& out_bytes,
    std::string& out_error)
{
    out_location = AppleObjectLocation{};
    out_bytes.clear();
    if (block_size == 0 || physical_block == 0 || size_bytes < 32 ||
        size_bytes % block_size != 0 ||
        physical_block > (0xFFFFFFFFFFFFFFFFull / block_size))
    {
        out_error = error_prefix + "LocationInvalid";
        return false;
    }
    const std::uint64_t byte_offset = physical_block * block_size;
    if (!source.Read(byte_offset, size_bytes, out_bytes) || out_bytes.size() != size_bytes)
    {
        out_error = error_prefix + "Unreadable";
        return false;
    }
    if (!VerifyObjectChecksum(out_bytes, size_bytes))
    {
        out_error = error_prefix + "ChecksumInvalid";
        return false;
    }
    const std::uint64_t object_id = ReadU64LE(out_bytes, 0x08).value_or(0);
    const std::uint64_t xid = ReadU64LE(out_bytes, 0x10).value_or(
        0xFFFFFFFFFFFFFFFFull);
    const std::uint32_t type = ReadU32LE(out_bytes, 0x18).value_or(0xFFFFFFFFu);
    const std::uint32_t subtype = ReadU32LE(out_bytes, 0x1C).value_or(0xFFFFFFFFu);
    if (object_id != expected_object_id)
    {
        out_error = error_prefix + "ObjectIdMismatch";
        return false;
    }
    if (max_xid != 0 && xid > max_xid)
    {
        out_error = error_prefix + "FutureXid";
        return false;
    }
    if ((type & kObjectStorageTypeMask) !=
            (expected_storage_type & kObjectStorageTypeMask))
    {
        out_error = error_prefix + "StorageTypeMismatch";
        return false;
    }
    if ((type & kObjectTypeMask) != expected_base_type)
    {
        out_error = error_prefix + "TypeMismatch";
        return false;
    }
    if (expected_subtype.has_value() && subtype != expected_subtype.value())
    {
        out_error = error_prefix + "SubtypeMismatch";
        return false;
    }
    out_location.object_id = object_id;
    out_location.xid = xid;
    out_location.physical_block = physical_block;
    out_location.type = type;
    out_location.subtype = subtype;
    out_location.size_bytes = size_bytes;
    return true;
}

const CheckpointMapping* FindCheckpointMapping(
    const ContainerCheckpointView& checkpoint,
    std::uint64_t object_id)
{
    const auto found = std::find_if(checkpoint.mappings.begin(), checkpoint.mappings.end(),
        [object_id](const CheckpointMapping& mapping) {
            return mapping.object_id == object_id;
        });
    return found == checkpoint.mappings.end() ? nullptr : &*found;
}

bool LoadAppleOmap(
    const RandomAccessSource& source,
    std::uint32_t block_size,
    std::uint64_t omap_oid,
    std::uint64_t max_xid,
    const std::string& error_prefix,
    AppleOmapView& out_view,
    std::string& out_error)
{
    out_view = AppleOmapView{};
    std::vector<std::byte> omap_bytes;
    if (!ReadAppleObject(source, block_size, omap_oid, block_size,
            omap_oid, max_xid, kObjectPhysical, kObjectTypeOmap, std::nullopt,
            error_prefix, out_view.object, omap_bytes, out_error))
    {
        return false;
    }
    out_view.flags = ReadU32LE(omap_bytes, 0x20).value_or(0);
    out_view.tree_type = ReadU32LE(omap_bytes, 0x28).value_or(0);
    out_view.snapshot_tree_type = ReadU32LE(omap_bytes, 0x2C).value_or(0);
    const std::uint64_t tree_oid = ReadU64LE(omap_bytes, 0x30).value_or(0);
    out_view.snapshot_tree_oid = ReadU64LE(omap_bytes, 0x38).value_or(0);
    if (tree_oid == 0 ||
        (out_view.tree_type & kObjectTypeMask) != kObjectTypeBtree ||
        (out_view.tree_type & kObjectStorageTypeMask) != kObjectPhysical)
    {
        out_error = error_prefix + "TreeTypeInvalid";
        return false;
    }
    std::vector<std::byte> tree_bytes;
    return ReadAppleObject(source, block_size, tree_oid, block_size,
        tree_oid, max_xid, kObjectPhysical, kObjectTypeBtree,
        kObjectTypeOmap, error_prefix + "Tree", out_view.tree,
        tree_bytes, out_error);
}

std::optional<OmapValue> ResolveAppleOmapValue(
    const RandomAccessSource& source,
    std::uint32_t block_size,
    const AppleOmapView& map,
    std::uint64_t oid,
    std::uint64_t max_xid,
    const std::string& error_prefix,
    std::string& out_error,
    std::uint64_t tree_max_xid = 0,
    bool strict_snapshot = false)
{
    std::vector<BtreeRecord> records;
    BtreeReadPolicy policy;
    policy.enforce_object_identity = true;
    policy.root_object_id = map.tree.object_id;
    policy.storage_type = kObjectPhysical;
    policy.subtype = kObjectTypeOmap;
    policy.require_complete_traversal = true;
    policy.reject_unsupported_flags = strict_snapshot;
    std::string tree_error;
    if (!ReadBtreeLeafRecords(source, block_size, map.tree.physical_block,
            true, 0, tree_max_xid == 0 ? max_xid : tree_max_xid, policy, records, tree_error))
    {
        out_error = error_prefix + "TreeInvalid:" + tree_error;
        return std::nullopt;
    }
    std::optional<OmapValue> selected;
    bool newest_is_tombstone = false;
    std::unordered_map<std::uint64_t, std::unordered_set<std::uint64_t>> seen_xids;
    for (const auto& record : records)
    {
        if (record.key.size() != 16 || record.value.size() != 16)
        {
            out_error = error_prefix + "RecordSizeInvalid";
            return std::nullopt;
        }
        const auto candidate_oid = ReadU64LE(record.key, 0).value_or(
            0xFFFFFFFFFFFFFFFFull);
        const auto candidate_xid = ReadU64LE(record.key, 8).value_or(
            0xFFFFFFFFFFFFFFFFull);
        if (strict_snapshot && (candidate_oid == 0 || candidate_xid == 0 ||
            candidate_xid > tree_max_xid ||
            (ReadU32LE(record.value, 0).value() & ~0x3u) != 0))
        {
            out_error = error_prefix + "UnsupportedRecordFlagsOrXid";
            return std::nullopt;
        }
        if (!Materialize(source, 0, 2 * sizeof(std::uint64_t))) return std::nullopt;
        if (!seen_xids[candidate_oid].insert(candidate_xid).second)
        {
            out_error = error_prefix + "KeyDuplicate";
            return std::nullopt;
        }
        if (candidate_oid != oid || candidate_xid > max_xid)
        {
            continue;
        }
        OmapValue value;
        value.flags = ReadU32LE(record.value, 0).value_or(0xFFFFFFFFu);
        value.size = ReadU32LE(record.value, 4).value_or(0);
        value.physical_block = ReadU64LE(record.value, 8).value_or(0);
        value.xid = candidate_xid;
        if (!selected.has_value() || value.xid > selected->xid)
        {
            selected = value;
            newest_is_tombstone = value.flags == 0xFFFFFFFFu ||
                (value.flags & 0x1u) != 0 || value.physical_block == 0;
        }
    }
    if (!selected.has_value())
    {
        out_error = error_prefix + "ValueMissing";
        return std::nullopt;
    }
    if (newest_is_tombstone)
    {
        out_error = error_prefix + "ValueDeleted";
        return std::nullopt;
    }
    if (selected->size < block_size || selected->size % block_size != 0)
    {
        out_error = error_prefix + "ValueSizeInvalid";
        return std::nullopt;
    }
    return selected;
}

bool ResolveAppleTreeRoot(
    const RandomAccessSource& source,
    const ContainerCheckpointView& checkpoint,
    const AppleOmapView& volume_omap,
    std::uint64_t volume_oid,
    std::uint64_t tree_oid,
    std::uint32_t tree_type,
    std::uint32_t expected_subtype,
    AppleObjectLocation& out_location,
    std::string& out_error)
{
    if (tree_oid == 0 || (tree_type & kObjectTypeMask) != kObjectTypeBtree)
    {
        out_error = "AppleTreeTypeInvalid";
        return false;
    }
    const std::uint32_t storage_type = tree_type & kObjectStorageTypeMask;
    std::uint64_t physical_block = 0;
    std::uint32_t object_size = checkpoint.superblock.block_size;
    if (storage_type == kObjectPhysical)
    {
        physical_block = tree_oid;
    }
    else if (storage_type == 0)
    {
        auto mapping = ResolveAppleOmapValue(source, checkpoint.superblock.block_size,
            volume_omap, tree_oid, checkpoint.superblock.xid,
            "AppleVolumeOmap", out_error);
        if (!mapping.has_value())
        {
            return false;
        }
        physical_block = mapping->physical_block;
        object_size = mapping->size;
    }
    else if (storage_type == kObjectEphemeral)
    {
        const CheckpointMapping* mapping = FindCheckpointMapping(checkpoint, tree_oid);
        if (mapping == nullptr || mapping->file_system_oid != volume_oid)
        {
            out_error = "AppleTreeEphemeralMappingMissing";
            return false;
        }
        if (mapping->type != tree_type || mapping->subtype != expected_subtype)
        {
            out_error = "AppleTreeEphemeralMappingMismatch";
            return false;
        }
        physical_block = mapping->physical_block;
        object_size = mapping->size_bytes;
    }
    else
    {
        out_error = "AppleTreeStorageTypeInvalid";
        return false;
    }
    std::vector<std::byte> tree_bytes;
    return ReadAppleObject(source, checkpoint.superblock.block_size,
        physical_block, object_size, tree_oid, checkpoint.superblock.xid,
        storage_type, kObjectTypeBtree, expected_subtype, "AppleTree",
        out_location, tree_bytes, out_error);
}

bool ByteRangeFits(
    std::size_t offset,
    std::size_t count,
    std::size_t width,
    std::size_t limit)
{
    return width != 0 && offset <= limit && count <= (limit - offset) / width;
}

bool BlockRangeFits(
    std::uint64_t start,
    std::uint64_t count,
    std::uint64_t limit)
{
    return start <= limit && count <= limit - start;
}

bool ReadRawAppleBlock(
    const RandomAccessSource& source,
    std::uint32_t block_size,
    std::uint64_t block_count,
    std::uint64_t physical_block,
    std::vector<std::byte>& out_bytes)
{
    if (physical_block >= block_count ||
        physical_block > std::numeric_limits<std::uint64_t>::max() / block_size)
    {
        return false;
    }
    return source.Read(physical_block * static_cast<std::uint64_t>(block_size),
        block_size, out_bytes) && out_bytes.size() == block_size;
}

bool BitmapBitSet(const std::vector<std::byte>& bitmap, std::uint64_t bit)
{
    const std::uint64_t byte_index = bit / 8;
    return byte_index < bitmap.size() &&
        (std::to_integer<unsigned int>(bitmap[static_cast<std::size_t>(byte_index)]) &
            (1u << (bit % 8))) != 0;
}

std::uint32_t CountBitmapBits(
    const std::vector<std::byte>& bitmap,
    std::uint32_t bit_count)
{
    std::uint32_t count = 0;
    for (std::uint32_t bit = 0; bit < bit_count; ++bit)
    {
        if (BitmapBitSet(bitmap, bit))
        {
            ++count;
        }
    }
    return count;
}

bool InternalPoolMarksAllocated(
    const AppleSpacemanInternalPoolView& pool,
    std::uint32_t block_size,
    std::uint64_t physical_block)
{
    if (!BlockRangeFits(pool.base_block, pool.block_count,
            std::numeric_limits<std::uint64_t>::max()) ||
        physical_block < pool.base_block ||
        physical_block - pool.base_block >= pool.block_count)
    {
        return false;
    }
    const std::uint64_t relative = physical_block - pool.base_block;
    const std::uint64_t bits_per_bitmap =
        static_cast<std::uint64_t>(block_size) * 8;
    const std::size_t bitmap_index =
        static_cast<std::size_t>(relative / bits_per_bitmap);
    return bitmap_index < pool.active_bitmaps.size() &&
        BitmapBitSet(pool.active_bitmaps[bitmap_index].bytes,
            relative % bits_per_bitmap);
}

bool LoadAppleSpacemanOwnershipViewImpl(
    const RandomAccessSource& source,
    const ContainerCheckpointView& checkpoint,
    AppleSpacemanView& out_view,
    std::string& out_error)
{
    out_view = AppleSpacemanView{};
    const auto& nxsb = checkpoint.superblock;
    if (nxsb.block_size < 4096 || nxsb.block_count == 0 ||
        nxsb.spaceman_oid == 0 || nxsb.xid == 0)
    {
        out_error = "AppleSpacemanCheckpointInvalid";
        return false;
    }
    const CheckpointMapping* spaceman_mapping =
        FindCheckpointMapping(checkpoint, nxsb.spaceman_oid);
    if (spaceman_mapping == nullptr)
    {
        out_error = "AppleSpacemanUnmapped";
        return false;
    }
    if (spaceman_mapping->file_system_oid != 0 ||
        spaceman_mapping->type != (kObjectEphemeral | kObjectTypeSpaceman) ||
        spaceman_mapping->subtype != 0)
    {
        out_error = "AppleSpacemanMappingInvalid";
        return false;
    }
    if (!ReadAppleObject(source, nxsb.block_size,
            spaceman_mapping->physical_block, spaceman_mapping->size_bytes,
            nxsb.spaceman_oid, nxsb.xid, kObjectEphemeral,
            kObjectTypeSpaceman, 0, "AppleSpaceman", out_view.object,
            out_view.bytes, out_error))
    {
        return false;
    }
    if (out_view.bytes.size() < 0x158 ||
        ReadU32LE(out_view.bytes, 0x20).value_or(0) != nxsb.block_size)
    {
        out_error = "AppleSpacemanBlockSizeMismatch";
        return false;
    }

    out_view.blocks_per_chunk = ReadU32LE(out_view.bytes, 0x24).value_or(0);
    out_view.chunks_per_cib = ReadU32LE(out_view.bytes, 0x28).value_or(0);
    out_view.cibs_per_cab = ReadU32LE(out_view.bytes, 0x2C).value_or(0);
    out_view.flags = ReadU32LE(out_view.bytes, 0x90).value_or(0xFFFFFFFFu);
    out_view.internal_pool_bitmap_transaction_multiplier =
        ReadU32LE(out_view.bytes, 0x94).value_or(0);
    out_view.version = ReadU32LE(out_view.bytes, 0x150).value_or(0);
    out_view.structure_size = ReadU32LE(out_view.bytes, 0x154).value_or(0);
    const std::uint64_t bitmap_capacity =
        static_cast<std::uint64_t>(nxsb.block_size) * 8;
    const std::uint32_t max_chunks_per_cib =
        (nxsb.block_size - 0x28u) / 0x20u;
    const std::uint32_t max_cibs_per_cab =
        (nxsb.block_size - 0x28u) / sizeof(std::uint64_t);
    if (out_view.blocks_per_chunk == 0 ||
        out_view.blocks_per_chunk > bitmap_capacity ||
        out_view.chunks_per_cib == 0 ||
        out_view.chunks_per_cib > max_chunks_per_cib ||
        out_view.cibs_per_cab == 0 ||
        out_view.cibs_per_cab > max_cibs_per_cab ||
        (out_view.flags & ~1u) != 0 ||
        out_view.structure_size < 0x158 ||
        out_view.structure_size > out_view.bytes.size())
    {
        out_error = "AppleSpacemanGeometryInvalid";
        return false;
    }

    for (std::size_t device_index = 0; device_index < out_view.devices.size(); ++device_index)
    {
        auto& device = out_view.devices[device_index];
        const std::size_t base = 0x30 + device_index * 0x30;
        device.block_count = ReadU64LE(out_view.bytes, base).value_or(0);
        device.chunk_count = ReadU64LE(out_view.bytes, base + 0x08).value_or(0);
        device.cib_count = ReadU32LE(out_view.bytes, base + 0x10).value_or(0);
        device.cab_count = ReadU32LE(out_view.bytes, base + 0x14).value_or(0);
        device.free_count = ReadU64LE(out_view.bytes, base + 0x18).value_or(0);
        device.address_offset = ReadU32LE(out_view.bytes, base + 0x20).value_or(0);
    }
    const auto& tier2 = out_view.devices[1];
    if (tier2.block_count != 0 || tier2.chunk_count != 0 ||
        tier2.cib_count != 0 || tier2.cab_count != 0 ||
        tier2.free_count != 0)
    {
        out_error = "AppleSpacemanTier2Unsupported";
        return false;
    }
    auto& main_device = out_view.devices[0];
    const std::uint64_t expected_chunk_count =
        (main_device.block_count + out_view.blocks_per_chunk - 1) /
            out_view.blocks_per_chunk;
    const std::uint64_t expected_cib_count =
        (expected_chunk_count + out_view.chunks_per_cib - 1) /
            out_view.chunks_per_cib;
    if (main_device.block_count != nxsb.block_count ||
        main_device.chunk_count != expected_chunk_count ||
        main_device.cib_count != expected_cib_count ||
        main_device.cib_count == 0 || main_device.free_count > main_device.block_count)
    {
        out_error = "AppleSpacemanDeviceGeometryInvalid";
        return false;
    }

    auto& pool = out_view.internal_pool;
    pool.block_count = ReadU64LE(out_view.bytes, 0x98).value_or(0);
    pool.bitmap_size_blocks = ReadU32LE(out_view.bytes, 0xA0).value_or(0);
    pool.bitmap_block_count = ReadU32LE(out_view.bytes, 0xA4).value_or(0);
    pool.bitmap_base_block = ReadU64LE(out_view.bytes, 0xA8).value_or(0);
    pool.base_block = ReadU64LE(out_view.bytes, 0xB0).value_or(0);
    pool.bitmap_free_head = ReadU16LE(out_view.bytes, 0x140).value_or(0xFFFFu);
    pool.bitmap_free_tail = ReadU16LE(out_view.bytes, 0x142).value_or(0xFFFFu);
    pool.bitmap_xid_offset = ReadU32LE(out_view.bytes, 0x144).value_or(0);
    pool.bitmap_index_offset = ReadU32LE(out_view.bytes, 0x148).value_or(0);
    pool.bitmap_free_next_offset = ReadU32LE(out_view.bytes, 0x14C).value_or(0);
    const std::uint64_t expected_bitmap_size =
        (pool.block_count + bitmap_capacity - 1) / bitmap_capacity;
    const std::uint64_t expected_rotation_blocks = expected_bitmap_size *
        out_view.internal_pool_bitmap_transaction_multiplier;
    if (pool.block_count == 0 || pool.bitmap_size_blocks == 0 ||
        pool.bitmap_size_blocks != expected_bitmap_size ||
        pool.bitmap_block_count == 0 || pool.bitmap_block_count > 0xFFFEu ||
        expected_rotation_blocks != pool.bitmap_block_count ||
        !BlockRangeFits(pool.base_block, pool.block_count, main_device.block_count) ||
        !BlockRangeFits(pool.bitmap_base_block, pool.bitmap_block_count,
            main_device.block_count) ||
        !ByteRangeFits(pool.bitmap_xid_offset, pool.bitmap_size_blocks,
            sizeof(std::uint64_t), out_view.bytes.size()) ||
        !ByteRangeFits(pool.bitmap_index_offset, pool.bitmap_size_blocks,
            sizeof(std::uint16_t), out_view.bytes.size()) ||
        !ByteRangeFits(pool.bitmap_free_next_offset, pool.bitmap_block_count,
            sizeof(std::uint16_t), out_view.bytes.size()))
    {
        out_error = "AppleSpacemanInternalPoolGeometryInvalid";
        return false;
    }

    std::unordered_set<std::uint16_t> active_bitmap_indices;
    for (std::uint32_t index = 0; index < pool.bitmap_size_blocks; ++index)
    {
        if (!Materialize(source, 1, sizeof(AppleSpacemanInternalPoolBitmapView) + sizeof(std::uint16_t))) return false;
        AppleSpacemanInternalPoolBitmapView bitmap;
        bitmap.xid = ReadU64LE(out_view.bytes,
            pool.bitmap_xid_offset + static_cast<std::size_t>(index) * 8).value_or(
                std::numeric_limits<std::uint64_t>::max());
        bitmap.rotation_index = ReadU16LE(out_view.bytes,
            pool.bitmap_index_offset + static_cast<std::size_t>(index) * 2).value_or(0xFFFFu);
        if (bitmap.xid == 0 || bitmap.xid > nxsb.xid ||
            bitmap.rotation_index >= pool.bitmap_block_count ||
            !active_bitmap_indices.insert(bitmap.rotation_index).second)
        {
            out_error = "AppleSpacemanInternalPoolActiveBitmapInvalid";
            return false;
        }
        bitmap.physical_block = pool.bitmap_base_block + bitmap.rotation_index;
        if (!ReadRawAppleBlock(source, nxsb.block_size, main_device.block_count,
                bitmap.physical_block, bitmap.bytes))
        {
            out_error = "AppleSpacemanInternalPoolBitmapUnreadable";
            return false;
        }
        pool.active_bitmaps.push_back(std::move(bitmap));
    }

    if (!Materialize(source, pool.bitmap_block_count,
            static_cast<std::uint64_t>(pool.bitmap_block_count) * 2 * sizeof(std::uint16_t))) return false;
    pool.bitmap_free_next.reserve(pool.bitmap_block_count);
    for (std::uint32_t index = 0; index < pool.bitmap_block_count; ++index)
    {
        pool.bitmap_free_next.push_back(ReadU16LE(out_view.bytes,
            pool.bitmap_free_next_offset + static_cast<std::size_t>(index) * 2).value_or(0xFFFFu));
    }
    for (const auto index : active_bitmap_indices)
    {
        if (pool.bitmap_free_next[index] != 0xFFFFu)
        {
            out_error = "AppleSpacemanInternalPoolActiveBitmapLinked";
            return false;
        }
    }
    std::unordered_set<std::uint16_t> free_bitmap_indices;
    std::uint16_t cursor = pool.bitmap_free_head;
    std::uint16_t last = 0xFFFFu;
    while (cursor != 0xFFFFu)
    {
        if (cursor >= pool.bitmap_block_count ||
            active_bitmap_indices.find(cursor) != active_bitmap_indices.end() ||
            !free_bitmap_indices.insert(cursor).second)
        {
            out_error = "AppleSpacemanInternalPoolFreeListInvalid";
            return false;
        }
        last = cursor;
        cursor = pool.bitmap_free_next[cursor];
    }
    if ((free_bitmap_indices.empty() &&
            (pool.bitmap_free_head != 0xFFFFu || pool.bitmap_free_tail != 0xFFFFu)) ||
        (!free_bitmap_indices.empty() && last != pool.bitmap_free_tail) ||
        free_bitmap_indices.size() + active_bitmap_indices.size() !=
            pool.bitmap_block_count)
    {
        out_error = "AppleSpacemanInternalPoolFreeListIncomplete";
        return false;
    }

    constexpr std::size_t kFreeQueueBase = 0xC8;
    constexpr std::size_t kFreeQueueSize = 0x28;
    for (std::size_t index = 0; index < out_view.free_queues.size(); ++index)
    {
        auto& queue = out_view.free_queues[index];
        const std::size_t base = kFreeQueueBase + index * kFreeQueueSize;
        queue.block_count = ReadU64LE(out_view.bytes, base).value_or(0);
        queue.tree_oid = ReadU64LE(out_view.bytes, base + 0x08).value_or(0);
        queue.oldest_xid = ReadU64LE(out_view.bytes, base + 0x10).value_or(0);
        queue.tree_node_limit = ReadU16LE(out_view.bytes, base + 0x18).value_or(0);
        out_view.free_queue_oids[index] = queue.tree_oid;
        if (queue.tree_oid == 0)
        {
            if (queue.block_count != 0 || queue.oldest_xid != 0)
            {
                out_error = "AppleSpacemanFreeQueueDescriptorInvalid";
                return false;
            }
            continue;
        }
        if (queue.oldest_xid > nxsb.xid || queue.tree_node_limit == 0)
        {
            out_error = "AppleSpacemanFreeQueueDescriptorInvalid";
            return false;
        }
        const CheckpointMapping* mapping = FindCheckpointMapping(checkpoint, queue.tree_oid);
        if (mapping == nullptr)
        {
            out_error = "AppleSpacemanFreeQueueUnmapped";
            return false;
        }
        if (mapping->file_system_oid != 0 ||
            mapping->type != (kObjectEphemeral | kObjectTypeBtree) ||
            mapping->subtype != kObjectTypeSpacemanFreeQueue)
        {
            out_error = "AppleSpacemanFreeQueueMappingInvalid";
            return false;
        }
        std::vector<std::byte> queue_bytes;
        if (!ReadAppleObject(source, nxsb.block_size, mapping->physical_block,
                mapping->size_bytes, queue.tree_oid, nxsb.xid,
                kObjectEphemeral, kObjectTypeBtree,
                kObjectTypeSpacemanFreeQueue, "AppleSpacemanFreeQueue",
                queue.root, queue_bytes, out_error))
        {
            return false;
        }
        constexpr std::uint32_t kSupportedBtreeFlags =
            0x00000001u | 0x00000002u | 0x00000004u | 0x00000008u |
            0x00000010u | 0x00000040u;
        const std::size_t tree_info = queue_bytes.size() - 40;
        queue.tree_flags = ReadU32LE(queue_bytes, tree_info).value_or(0);
        queue.fixed_key_size = ReadU32LE(queue_bytes, tree_info + 0x08).value_or(0);
        queue.fixed_value_size = ReadU32LE(queue_bytes, tree_info + 0x0C).value_or(0);
        queue.longest_key = ReadU32LE(queue_bytes, tree_info + 0x10).value_or(0);
        queue.longest_value = ReadU32LE(queue_bytes, tree_info + 0x14).value_or(0);
        if (ReadU32LE(queue_bytes, tree_info + 0x04).value_or(0) !=
             nxsb.block_size ||
            (queue.tree_flags & ~kSupportedBtreeFlags) != 0 ||
            (queue.tree_flags & 0x0000000Eu) != 0x0000000Eu ||
            (queue.tree_flags & 0x00000010u) != 0 ||
            queue.fixed_key_size != 16 || queue.fixed_value_size != 8 ||
            queue.longest_key < 16 || queue.longest_value < 8)
        {
            out_error = "AppleSpacemanFreeQueueTreeInfoInvalid";
            return false;
        }
        BtreeReadPolicy queue_policy;
        queue_policy.enforce_object_identity = true;
        queue_policy.root_object_id = queue.tree_oid;
        queue_policy.storage_type = kObjectEphemeral;
        queue_policy.subtype = kObjectTypeSpacemanFreeQueue;
        queue_policy.include_ghost_records = true;
        queue_policy.ephemeral_checkpoint = &checkpoint;
        queue_policy.visited_physical_blocks = &queue.tree_blocks;
        std::vector<BtreeRecord> queue_records;
        if (!ReadBtreeLeafRecords(source, nxsb.block_size,
                mapping->physical_block, false, 0, nxsb.xid, queue_policy,
                queue_records, out_error))
        {
            out_error = "AppleSpacemanFreeQueueTreeInvalid:" + out_error;
            return false;
        }
        if (queue.tree_blocks.empty() ||
            queue.tree_blocks.size() > queue.tree_node_limit)
        {
            out_error = "AppleSpacemanFreeQueueNodeLimitInvalid";
            return false;
        }
        std::uint64_t queued_block_count = 0;
        std::pair<std::uint64_t, std::uint64_t> previous_key{};
        bool have_previous = false;
        for (const auto& record : queue_records)
        {
            if (record.key.size() != 16 ||
                (!record.value.empty() && record.value.size() != 8))
            {
                out_error = "AppleSpacemanFreeQueueRecordInvalid";
                return false;
            }
            AppleSpacemanFreeQueueEntry entry;
            entry.xid = ReadU64LE(record.key, 0).value_or(0);
            entry.physical_block = ReadU64LE(record.key, 8).value_or(0);
            entry.block_count = record.value.empty()
                ? 1
                : ReadU64LE(record.value, 0).value_or(0);
            const auto key = std::make_pair(entry.xid, entry.physical_block);
            if (entry.xid == 0 || entry.xid > nxsb.xid ||
                entry.physical_block == 0 || entry.block_count == 0 ||
                (!record.value.empty() && entry.block_count <= 1) ||
                (have_previous && !(previous_key < key)) ||
                entry.block_count > std::numeric_limits<std::uint64_t>::max() -
                    queued_block_count)
            {
                out_error = "AppleSpacemanFreeQueueRecordInvalid";
                return false;
            }
            queued_block_count += entry.block_count;
            previous_key = key;
            have_previous = true;
            if (!Materialize(source, 1, sizeof(entry))) return false;
            queue.entries.push_back(entry);
        }
        if (queued_block_count != queue.block_count)
        {
            out_error = "AppleSpacemanFreeQueueCountMismatch";
            return false;
        }
        if ((queue.entries.empty() && queue.oldest_xid != 0) ||
            (!queue.entries.empty() &&
                queue.oldest_xid != queue.entries.front().xid))
        {
            out_error = "AppleSpacemanFreeQueueOldestXidMismatch";
            return false;
        }
        if (!Materialize(source, 1, sizeof(queue.root))) return false;
        out_view.free_queue_roots.push_back(queue.root);
    }

    std::unordered_set<std::uint64_t> ownership_blocks;
    if (!Materialize(source, 0, sizeof(std::uint64_t))) return false;
    ownership_blocks.insert(out_view.object.physical_block);
    for (const auto& queue : out_view.free_queues)
    {
        for (const auto block : queue.tree_blocks)
        {
            if (!Materialize(source, 0, sizeof(std::uint64_t))) return false;
            if (!ownership_blocks.insert(block).second)
            {
                out_error = "AppleSpacemanOwnershipOverlap";
                return false;
            }
        }
    }

    std::vector<std::uint64_t> cib_blocks;
    if (!Materialize(source, main_device.cib_count,
            static_cast<std::uint64_t>(main_device.cib_count) * sizeof(std::uint64_t))) return false;
    if (main_device.cab_count == 0)
    {
        if (!ByteRangeFits(main_device.address_offset, main_device.cib_count,
                sizeof(std::uint64_t), out_view.bytes.size()))
        {
            out_error = "AppleSpacemanCibAddressTableInvalid";
            return false;
        }
        cib_blocks.reserve(main_device.cib_count);
        for (std::uint32_t index = 0; index < main_device.cib_count; ++index)
        {
            cib_blocks.push_back(ReadU64LE(out_view.bytes,
                main_device.address_offset + static_cast<std::size_t>(index) * 8).value_or(0));
        }
    }
    else
    {
        const std::uint64_t expected_cab_count =
            (static_cast<std::uint64_t>(main_device.cib_count) +
                out_view.cibs_per_cab - 1) / out_view.cibs_per_cab;
        if (main_device.cab_count != expected_cab_count ||
            !ByteRangeFits(main_device.address_offset, main_device.cab_count,
                sizeof(std::uint64_t), out_view.structure_size))
        {
            out_error = "AppleSpacemanCabAddressTableInvalid";
            return false;
        }
        cib_blocks.reserve(main_device.cib_count);
        for (std::uint32_t cab_index = 0; cab_index < main_device.cab_count; ++cab_index)
        {
            if (!Materialize(source, 1, sizeof(AppleSpacemanCabView) + sizeof(std::uint64_t))) return false;
            const auto cab_block = ReadU64LE(out_view.bytes,
                main_device.address_offset + static_cast<std::size_t>(cab_index) * 8).value_or(0);
            if (cab_block == 0 || !ownership_blocks.insert(cab_block).second)
            {
                out_error = "AppleSpacemanCabAddressInvalid";
                return false;
            }
            AppleSpacemanCabView cab;
            if (!ReadAppleObject(source, nxsb.block_size, cab_block,
                    nxsb.block_size, cab_block, nxsb.xid, kObjectPhysical,
                    kObjectTypeSpacemanCab, 0, "AppleSpacemanCab",
                    cab.object, cab.bytes, out_error))
            {
                return false;
            }
            cab.index = ReadU32LE(cab.bytes, 0x20).value_or(0xFFFFFFFFu);
            const std::uint32_t count = ReadU32LE(cab.bytes, 0x24).value_or(0);
            const std::uint32_t expected_count = static_cast<std::uint32_t>(
                (std::min)(static_cast<std::uint64_t>(out_view.cibs_per_cab),
                    static_cast<std::uint64_t>(main_device.cib_count) -
                        cib_blocks.size()));
            if (cab.index != cab_index || count == 0 || count != expected_count ||
                !ByteRangeFits(0x28, count, sizeof(std::uint64_t), cab.bytes.size()))
            {
                out_error = "AppleSpacemanCabGeometryInvalid";
                return false;
            }
            for (std::uint32_t index = 0; index < count; ++index)
            {
                if (!Materialize(source, 0, sizeof(std::uint64_t))) return false;
                const auto cib_block = ReadU64LE(cab.bytes,
                    0x28 + static_cast<std::size_t>(index) * 8).value_or(0);
                cab.cib_blocks.push_back(cib_block);
                cib_blocks.push_back(cib_block);
            }
            main_device.cabs.push_back(std::move(cab));
        }
    }
    if (cib_blocks.size() != main_device.cib_count)
    {
        out_error = "AppleSpacemanCibAddressCountInvalid";
        return false;
    }

    std::uint64_t expected_chunk_start = 0;
    std::uint64_t total_free_count = 0;
    for (std::uint32_t cib_index = 0; cib_index < main_device.cib_count; ++cib_index)
    {
        if (!Materialize(source, 1, sizeof(AppleSpacemanCibView) + sizeof(std::uint64_t))) return false;
        const auto cib_block = cib_blocks[cib_index];
        if (cib_block == 0 || !ownership_blocks.insert(cib_block).second)
        {
            out_error = "AppleSpacemanCibAddressInvalid";
            return false;
        }
        AppleSpacemanCibView cib;
        if (!ReadAppleObject(source, nxsb.block_size, cib_block, nxsb.block_size,
                cib_block, nxsb.xid, kObjectPhysical,
                kObjectTypeSpacemanCib, 0, "AppleSpacemanCib", cib.object,
                cib.bytes, out_error))
        {
            return false;
        }
        cib.index = ReadU32LE(cib.bytes, 0x20).value_or(0xFFFFFFFFu);
        const std::uint32_t chunk_count = ReadU32LE(cib.bytes, 0x24).value_or(0);
        const std::uint64_t remaining_chunks =
            main_device.chunk_count - out_view.chunks.size();
        const std::uint32_t expected_in_cib = static_cast<std::uint32_t>(
            (std::min)(remaining_chunks,
                static_cast<std::uint64_t>(out_view.chunks_per_cib)));
        if (cib.index != cib_index || chunk_count == 0 ||
            chunk_count != expected_in_cib ||
            !ByteRangeFits(0x28, chunk_count, 0x20, cib.bytes.size()))
        {
            out_error = "AppleSpacemanCibGeometryInvalid";
            return false;
        }
        for (std::uint32_t chunk_index = 0; chunk_index < chunk_count; ++chunk_index)
        {
            if (!Materialize(source, 1, sizeof(AppleSpacemanChunkView) +
                    sizeof(std::size_t) + sizeof(std::uint64_t))) return false;
            const std::size_t base = 0x28 + static_cast<std::size_t>(chunk_index) * 0x20;
            AppleSpacemanChunkView chunk;
            chunk.xid = ReadU64LE(cib.bytes, base).value_or(0);
            chunk.start_block = ReadU64LE(cib.bytes, base + 0x08).value_or(0);
            chunk.block_count = ReadU32LE(cib.bytes, base + 0x10).value_or(0);
            chunk.free_count = ReadU32LE(cib.bytes, base + 0x14).value_or(0);
            chunk.bitmap_block = ReadU64LE(cib.bytes, base + 0x18).value_or(0);
            chunk.device_index = 0;
            chunk.cib_index = cib_index;
            chunk.index_in_cib = chunk_index;
            const std::uint32_t expected_blocks = static_cast<std::uint32_t>(
                (std::min)(static_cast<std::uint64_t>(out_view.blocks_per_chunk),
                    main_device.block_count - expected_chunk_start));
            if (chunk.xid == 0 || chunk.xid > nxsb.xid ||
                chunk.start_block != expected_chunk_start ||
                chunk.block_count != expected_blocks ||
                chunk.free_count > chunk.block_count)
            {
                out_error = "AppleSpacemanChunkGeometryInvalid";
                return false;
            }
            if (chunk.bitmap_block == 0)
            {
                if (chunk.free_count != chunk.block_count)
                {
                    out_error = "AppleSpacemanAllFreeChunkCountInvalid";
                    return false;
                }
            }
            else
            {
                if (!ownership_blocks.insert(chunk.bitmap_block).second ||
                    !ReadRawAppleBlock(source, nxsb.block_size,
                        main_device.block_count, chunk.bitmap_block,
                        chunk.allocation_bitmap))
                {
                    out_error = "AppleSpacemanChunkBitmapInvalid";
                    return false;
                }
                const std::uint32_t allocated =
                    CountBitmapBits(chunk.allocation_bitmap, chunk.block_count);
                if (allocated != chunk.block_count - chunk.free_count)
                {
                    out_error = "AppleSpacemanChunkFreeCountMismatch";
                    return false;
                }
            }
            total_free_count += chunk.free_count;
            expected_chunk_start += chunk.block_count;
            cib.chunk_indices.push_back(out_view.chunks.size());
            out_view.chunks.push_back(std::move(chunk));
        }
        main_device.cibs.push_back(std::move(cib));
    }
    if (expected_chunk_start != main_device.block_count ||
        out_view.chunks.size() != main_device.chunk_count ||
        total_free_count != main_device.free_count)
    {
        out_error = "AppleSpacemanDeviceFreeCountMismatch";
        return false;
    }
    std::vector<std::pair<std::uint64_t, std::uint64_t>> queued_ranges;
    for (std::size_t queue_index = 0;
         queue_index < out_view.free_queues.size(); ++queue_index)
    {
        for (const auto& entry : out_view.free_queues[queue_index].entries)
        {
            if (entry.physical_block >
                    std::numeric_limits<std::uint64_t>::max() - entry.block_count ||
                !BlockRangeFits(entry.physical_block, entry.block_count,
                    main_device.block_count))
            {
                out_error = "AppleSpacemanFreeQueueRangeInvalid";
                return false;
            }
            const std::uint64_t range_end = entry.physical_block + entry.block_count;
            const bool in_internal_pool =
                entry.physical_block >= pool.base_block &&
                range_end <= pool.base_block + pool.block_count;
            if ((queue_index == 0 && !in_internal_pool) ||
                (queue_index == 1 && in_internal_pool) || queue_index == 2)
            {
                out_error = "AppleSpacemanFreeQueuePoolMismatch";
                return false;
            }
            for (std::uint64_t block = entry.physical_block;
                 block < range_end; ++block)
            {
                bool marked_allocated = false;
                if (queue_index == 0)
                {
                    marked_allocated = InternalPoolMarksAllocated(
                        pool, nxsb.block_size, block);
                }
                else
                {
                    const auto chunk = std::find_if(out_view.chunks.begin(),
                        out_view.chunks.end(), [block](const auto& candidate) {
                            return block >= candidate.start_block &&
                                block - candidate.start_block <
                                    candidate.block_count;
                        });
                    marked_allocated = chunk != out_view.chunks.end() &&
                        !chunk->allocation_bitmap.empty() &&
                        BitmapBitSet(chunk->allocation_bitmap,
                            block - chunk->start_block);
                }
                if (!marked_allocated || ownership_blocks.find(block) !=
                        ownership_blocks.end())
                {
                    out_error = "AppleSpacemanFreeQueueOwnershipMismatch";
                    return false;
                }
            }
            if (!Materialize(source, 0, 2 * sizeof(std::uint64_t))) return false;
            queued_ranges.emplace_back(entry.physical_block, range_end);
        }
    }
    std::sort(queued_ranges.begin(), queued_ranges.end());
    for (std::size_t index = 1; index < queued_ranges.size(); ++index)
    {
        if (queued_ranges[index].first < queued_ranges[index - 1].second)
        {
            out_error = "AppleSpacemanFreeQueueOverlap";
            return false;
        }
    }
    for (const std::uint64_t block : ownership_blocks)
    {
        if (block >= pool.base_block && block - pool.base_block < pool.block_count &&
            !InternalPoolMarksAllocated(pool, nxsb.block_size, block))
        {
            out_error = "AppleSpacemanInternalPoolOwnershipMismatch";
            return false;
        }
    }
    return true;
}

} // namespace

bool LoadAppleSpacemanOwnershipView(
    const RandomAccessSource& source,
    const ContainerCheckpointView& checkpoint,
    AppleSpacemanView& out_view,
    std::string& out_error)
{
    BudgetErrorScope budget_error{source, out_error};
    out_error.clear();
    if (!LoadAppleSpacemanOwnershipViewImpl(source, checkpoint, out_view, out_error))
    {
        out_view = {};
        return false;
    }
    return true;
}

std::optional<AppleCheckpointView> LoadAppleCheckpointView(
    const RandomAccessSource& source,
    std::uint64_t store_offset_bytes,
    std::uint64_t store_size_bytes,
    std::string& out_error,
    std::optional<std::uint64_t> exact_checkpoint_xid)
{
    BudgetErrorScope budget_error{source, out_error};
    out_error.clear();
    if (store_size_bytes == 0 || store_offset_bytes > source.SizeBytes() ||
        store_size_bytes > source.SizeBytes() - store_offset_bytes)
    {
        out_error = "AppleCheckpointStoreBoundsInvalid";
        return std::nullopt;
    }
    OffsetRandomAccessSource store(&source, store_offset_bytes, store_size_bytes);
    std::string checkpoint_error;
    auto checkpoint = LoadContainerCheckpointView(
        store, 0, store_size_bytes, checkpoint_error, exact_checkpoint_xid);
    if (!checkpoint.has_value())
    {
        out_error = "AppleCheckpointInvalid:" + checkpoint_error;
        return std::nullopt;
    }
    if (checkpoint->checkpoint_map_blocks.empty() ||
        checkpoint->superblock.spaceman_oid == 0)
    {
        out_error = "AppleCheckpointLegacySyntheticRejected";
        return std::nullopt;
    }

    AppleCheckpointView view;
    view.container = std::move(checkpoint.value());
    const auto& nxsb = view.container.superblock;
    if (!LoadAppleOmap(store, nxsb.block_size, nxsb.omap_oid, nxsb.xid,
            "AppleContainerOmap", view.container_object_map, out_error))
    {
        return std::nullopt;
    }

    if (!LoadAppleSpacemanOwnershipViewImpl(
            store, view.container, view.spaceman, out_error))
    {
        return std::nullopt;
    }

    std::unordered_set<std::uint64_t> seen_volume_oids;
    for (const std::uint64_t volume_oid : nxsb.fs_oids)
    {
        if (!Materialize(source, 0, sizeof(std::uint64_t))) return std::nullopt;
        if (volume_oid == 0 || !seen_volume_oids.insert(volume_oid).second)
        {
            out_error = "AppleVolumeOidInvalid";
            return std::nullopt;
        }
        auto mapping = ResolveAppleOmapValue(store, nxsb.block_size,
            view.container_object_map, volume_oid, nxsb.xid,
            "AppleContainerOmap", out_error);
        if (!mapping.has_value())
        {
            return std::nullopt;
        }
        AppleVolumeCheckpointView volume_view;
        std::vector<std::byte> apsb_bytes;
        if (!ReadAppleObject(store, nxsb.block_size, mapping->physical_block,
                mapping->size, volume_oid, nxsb.xid, 0, kObjectTypeFs,
                std::nullopt, "AppleVolumeSuperblock",
                volume_view.superblock_object, apsb_bytes, out_error))
        {
            return std::nullopt;
        }
        if (!Materialize(source, 0, sizeof(ApsbVolume) + 384)) return std::nullopt;
        auto apsb = ParseApsb(apsb_bytes);
        if (!apsb.has_value())
        {
            out_error = "AppleVolumeSuperblockInvalid";
            return std::nullopt;
        }
        volume_view.superblock = std::move(apsb.value());
        if (!LoadAppleOmap(store, nxsb.block_size, volume_view.superblock.omap_oid,
                nxsb.xid, "AppleVolumeOmap", volume_view.object_map, out_error))
        {
            return std::nullopt;
        }
        if (!ResolveAppleTreeRoot(store, view.container, volume_view.object_map,
                volume_oid, volume_view.superblock.root_oid,
                volume_view.superblock.root_tree_type, kObjectTypeFsTree,
                volume_view.root_tree, out_error))
        {
            return std::nullopt;
        }
        if (volume_view.superblock.extentref_tree_oid != 0)
        {
            AppleObjectLocation location;
            if (!ResolveAppleTreeRoot(store, view.container, volume_view.object_map,
                    volume_oid, volume_view.superblock.extentref_tree_oid,
                    volume_view.superblock.extentref_tree_type,
                    kObjectTypeBlockRefTree, location, out_error))
            {
                return std::nullopt;
            }
            volume_view.extentref_tree = location;
        }
        if (volume_view.superblock.snap_meta_tree_oid != 0)
        {
            AppleObjectLocation location;
            if (!ResolveAppleTreeRoot(store, view.container, volume_view.object_map,
                    volume_oid, volume_view.superblock.snap_meta_tree_oid,
                    volume_view.superblock.snap_meta_tree_type,
                    kObjectTypeSnapMetaTree, location, out_error))
            {
                return std::nullopt;
            }
            volume_view.snapshot_metadata_tree = location;
        }
        if (volume_view.superblock.fext_tree_oid != 0)
        {
            AppleObjectLocation location;
            if (!ResolveAppleTreeRoot(store, view.container, volume_view.object_map,
                    volume_oid, volume_view.superblock.fext_tree_oid,
                    volume_view.superblock.fext_tree_type,
                    kObjectTypeFileExtentTree, location, out_error))
            {
                return std::nullopt;
            }
            volume_view.file_extent_tree = location;
        }
        if (!Materialize(source, 1, sizeof(AppleVolumeCheckpointView))) return std::nullopt;
        view.volumes.push_back(std::move(volume_view));
    }
    if (view.volumes.empty())
    {
        out_error = "AppleCheckpointNoVolumes";
        return std::nullopt;
    }
    return view;
}

namespace
{
bool SnapshotVolumeSupported(const std::vector<std::byte>& bytes,
    const ApsbVolume& volume, std::string& error)
{
    if (volume.uuid_hex.empty() || !volume.name_valid || volume.xid == 0)
    {
        error = "SnapshotVolumeIdentityInvalid";
        return false;
    }
    if (volume.fs_flags != kFsFlagUnencrypted ||
        (volume.features & ~kVolumeKnownOptionalFeaturesMask) != 0 ||
        volume.readonly_features != 0 ||
        (volume.incompatible_features & ~kVolumeSupportedIncompatibleFeaturesMask) != 0)
    {
        error = "SnapshotVolumeFeaturesUnsupported";
        return false;
    }
    // [APPLE] apfs_superblock_t: revert, encryption state, extended snapshot
    // metadata, sealed integrity/fext, and reserved tail fields. These need
    // their own semantics; an unsupported layout must never look empty.
    if (ReadU64LE(bytes, 0x3E8).value_or(~0ull) != 0)
    {
        error = "SnapshotExtendedMetadataUnsupported";
        return false;
    }
    if (ReadU64LE(bytes, 0xA0).value_or(~0ull) != 0 ||
        ReadU64LE(bytes, 0xA8).value_or(~0ull) != 0 ||
        ReadU16LE(bytes, 0x3C6).value_or(~0u) != 0 ||
        ReadU64LE(bytes, 0x3C8).value_or(~0ull) != 0 ||
        ReadU64LE(bytes, 0x3D0).value_or(~0ull) != 0 ||
        ReadU64LE(bytes, 0x400).value_or(~0ull) != 0 ||
        volume.fext_tree_oid != 0 || volume.fext_tree_type != 0 ||
        ReadU32LE(bytes, 0x414).value_or(~0u) != 0 ||
        ReadU64LE(bytes, 0x418).value_or(~0ull) != 0)
    {
        error = "SnapshotVolumeStateOrReservedFieldsUnsupported";
        return false;
    }
    return true;
}

bool SnapshotName(const std::vector<std::byte>& bytes, std::size_t offset,
    std::uint16_t length, std::string& name)
{
    if (length < 2 || offset > bytes.size() || length != bytes.size() - offset ||
        bytes.back() != std::byte{0} ||
        std::find(bytes.begin() + offset, bytes.end() - 1, std::byte{0}) != bytes.end() - 1 ||
        !IsValidUtf8(bytes.data() + offset, length - 1)) return false;
    name.assign(reinterpret_cast<const char*>(bytes.data() + offset), length - 1);
    return true;
}

// Reuse the authoritative tree reader, including its cycle, region, checksum,
// identity, and shared resource-budget checks. Virtual child lookup is pinned
// to the snapshot XID while the OMAP itself belongs to the selected checkpoint.
bool ReadSnapshotTree(const RandomAccessSource& source, std::uint32_t block_size,
    const AppleObjectLocation& tree, const AppleOmapView& omap,
    std::uint64_t tree_xid, std::uint64_t checkpoint_xid,
    std::vector<BtreeRecord>& records, std::string& error)
{
    const auto storage = tree.type & kObjectStorageTypeMask;
    if (storage != 0 && storage != kObjectPhysical)
    {
        error = "SnapshotEphemeralTreeUnsupported";
        return false;
    }
    BtreeReadPolicy policy;
    policy.enforce_object_identity = true;
    policy.require_complete_traversal = true;
    policy.reject_unsupported_flags = true;
    policy.root_object_id = tree.object_id;
    policy.storage_type = storage;
    policy.subtype = tree.subtype;
    policy.virtual_child_resolver = [&](std::uint64_t oid, std::string& child_error)
        -> std::optional<BtreeVirtualChildMapping> {
        const auto value = ResolveAppleOmapValue(source, block_size, omap, oid,
            tree_xid, "SnapshotChildOmap", child_error, checkpoint_xid, true);
        if (!value) return std::nullopt;
        if (value->size != block_size)
        {
            child_error = "SnapshotMultiBlockNodeUnsupported";
            return std::nullopt;
        }
        return BtreeVirtualChildMapping{value->physical_block, value->xid};
    };
    return ReadBtreeLeafRecords(source, block_size, tree.physical_block,
        storage == kObjectPhysical, omap.object.object_id, tree_xid,
        policy, records, error);
}

bool SnapshotOmapSupported(const RandomAccessSource& source, std::uint32_t block_size,
    const AppleOmapView& map, std::uint64_t checkpoint_xid,
    bool container, std::vector<std::uint64_t>& snapshot_xids, std::string& error)
{
    snapshot_xids.clear();
    std::vector<std::byte> bytes;
    if (!source.Read(map.object.physical_block * block_size, block_size, bytes) ||
        !VerifyObjectChecksum(bytes, block_size))
    {
        error = "SnapshotOmapUnreadableOrChecksum";
        return false;
    }
    if (map.object.type != (kObjectPhysical | kObjectTypeOmap) ||
        map.object.subtype != 0 || map.object.xid == 0 ||
        map.tree_type != (kObjectPhysical | kObjectTypeBtree) ||
        (container ? map.flags != 1u : map.flags != 0) ||
        ReadU64LE(bytes, 0x48).value_or(~0ull) != 0 ||
        ReadU64LE(bytes, 0x50).value_or(~0ull) != 0)
    {
        error = "SnapshotOmapFlagsOrRevertUnsupported";
        return false;
    }
    // Force a complete, strict scan even when the volume has zero snapshots.
    // The existing resolver validates all record sizes, duplicate keys, flags
    // and XIDs before returning the requested mapping (or ValueMissing).
    std::string scan_error;
    (void)ResolveAppleOmapValue(source, block_size, map, ~0ull, checkpoint_xid,
        "SnapshotOmap", scan_error, checkpoint_xid, true);
    if (!scan_error.empty() && scan_error != "SnapshotOmapValueMissing")
    {
        error = scan_error;
        return false;
    }
    const auto count = ReadU32LE(bytes, 0x24).value();
    const auto recent = ReadU64LE(bytes, 0x40).value();
    if (map.snapshot_tree_oid == 0)
    {
        if (count != 0 || recent != 0 ||
            (map.snapshot_tree_type != 0 && map.snapshot_tree_type != (kObjectPhysical | kObjectTypeBtree)))
        {
            error = "SnapshotOmapSnapshotRootMissing";
            return false;
        }
        return true;
    }
    if (container || map.snapshot_tree_type != (kObjectPhysical | kObjectTypeBtree))
    {
        error = "SnapshotOmapSnapshotTreeTypeUnsupported";
        return false;
    }
    AppleObjectLocation location;
    if (!ReadAppleObject(source, block_size, map.snapshot_tree_oid, block_size,
        map.snapshot_tree_oid, checkpoint_xid, kObjectPhysical, kObjectTypeBtree,
        0x13u, "SnapshotOmapSnapshots", location, bytes, error)) return false;
    std::vector<BtreeRecord> records;
    if (!ReadSnapshotTree(source, block_size, location, map, checkpoint_xid,
        checkpoint_xid, records, error)) return false;
    std::unordered_set<std::uint64_t> seen;
    for (const auto& record : records)
    {
        if (record.key.size() != 8 || record.value.size() != 16)
        {
            error = "SnapshotOmapSnapshotRecordMalformed";
            return false;
        }
        const auto xid = ReadU64LE(record.key, 0).value();
        if (ReadU32LE(record.value, 0).value() != 0 ||
            ReadU32LE(record.value, 4).value() != 0 || ReadU64LE(record.value, 8).value() != 0)
        {
            error = "SnapshotOmapDeletedRevertedOrReservedUnsupported";
            return false;
        }
        if (xid == 0 || xid > checkpoint_xid || !seen.insert(xid).second)
        {
            error = "SnapshotOmapSnapshotXidInvalid";
            return false;
        }
        if (!Materialize(source, 1, 2 * sizeof(std::uint64_t))) return false;
        snapshot_xids.push_back(xid);
    }
    std::sort(snapshot_xids.begin(), snapshot_xids.end());
    if (snapshot_xids.size() != count ||
        recent != (snapshot_xids.empty() ? 0 : snapshot_xids.back()))
    {
        error = "SnapshotOmapSnapshotCountOrRecentMismatch";
        return false;
    }
    return true;
}
} // namespace

bool LoadAppleSnapshotRecords(const RandomAccessSource& source,
    const AppleCheckpointView& checkpoint, std::uint64_t volume_oid,
    std::vector<AppleSnapshotRecord>& out_records, std::string& out_error)
{
    AppleSnapshotTreeRecords ignored;
    return LoadAppleSnapshotRecords(source, checkpoint, volume_oid,
        out_records, out_error, 0, ignored);
}

bool LoadAppleSnapshotRecords(const RandomAccessSource& source,
    const AppleCheckpointView& checkpoint, std::uint64_t volume_oid,
    std::vector<AppleSnapshotRecord>& out_records, std::string& out_error,
    std::uint64_t exact_snapshot_xid, AppleSnapshotTreeRecords& out_trees)
{
    BudgetErrorScope budget_error{source, out_error};
    out_records.clear();
    out_trees = {};
    AppleSnapshotTreeRecords selected_trees;
    bool selected = false;
    out_error.clear();
    const auto fail = [&](const char* reason) { out_error = reason; return false; };
    const auto& nx = checkpoint.container.superblock;
    if (nx.block_size == 0 || nx.block_count > source.SizeBytes() / nx.block_size ||
        nx.xid == 0 || (nx.features & ~kNxKnownOptionalFeaturesMask) != 0 ||
        nx.readonly_features != 0 ||
        (nx.incompatible_features & ~kNxSupportedIncompatibleFeaturesMask) != 0)
        return fail("SnapshotContainerGeometryOrFeaturesUnsupported");
    if ((ReadU32LE(checkpoint.container.superblock_bytes, 0x18).value_or(~0u) &
            ~(kObjectStorageTypeMask | kObjectTypeMask)) != 0 ||
        ReadU32LE(checkpoint.container.superblock_bytes, 0x1C).value_or(~0u) != 0)
        return fail("SnapshotContainerObjectFlagsUnsupported");
    // Even if the enclosing source includes trailing bytes, references cannot
    // escape the container's declared physical block range.
    OffsetRandomAccessSource store(&source, 0, nx.block_count * nx.block_size);
    const AppleVolumeCheckpointView* live = nullptr;
    for (const auto& volume : checkpoint.volumes)
        if (volume.superblock.object_id == volume_oid)
        {
            if (live) return fail("SnapshotVolumeAmbiguous");
            live = &volume;
        }
    if (!live) return fail("SnapshotVolumeMissing");
    std::vector<std::byte> bytes;
    AppleObjectLocation live_location;
    if (!ReadAppleObject(store, nx.block_size, live->superblock_object.physical_block,
        nx.block_size, volume_oid, nx.xid, 0, kObjectTypeFs, 0,
        "SnapshotLiveApsb", live_location, bytes, out_error)) return false;
    if (live_location.type != kObjectTypeFs ||
        !SnapshotVolumeSupported(bytes, live->superblock, out_error))
        return out_error.empty() ? fail("SnapshotLiveApsbFlagsUnsupported") : false;
    const auto count = ReadU64LE(bytes, 0xD8).value();
    std::vector<std::uint64_t> ignored, live_omap_xids;
    if (!SnapshotOmapSupported(store, nx.block_size, checkpoint.container_object_map,
        nx.xid, true, ignored, out_error) ||
        !SnapshotOmapSupported(store, nx.block_size, live->object_map,
        nx.xid, false, live_omap_xids, out_error)) return false;
    if (!live->snapshot_metadata_tree || live->superblock.snap_meta_tree_oid == 0)
        return fail("SnapshotMetadataRootMissing");
    if (live->superblock.snap_meta_tree_type != live->snapshot_metadata_tree->type)
        return fail("SnapshotMetadataTreeTypeMismatch");
    std::vector<BtreeRecord> records;
    if (live->superblock.root_tree_type != live->root_tree.type || !live->extentref_tree ||
        live->superblock.extentref_tree_type != live->extentref_tree->type)
        return fail("SnapshotLiveRootMissingOrTypeMismatch");
    if (!ReadSnapshotTree(store, nx.block_size, live->root_tree, live->object_map,
        nx.xid, nx.xid, records, out_error) ||
        !ReadSnapshotTree(store, nx.block_size, *live->extentref_tree, live->object_map,
            nx.xid, nx.xid, records, out_error)) return false;
    if (!ReadSnapshotTree(store, nx.block_size, *live->snapshot_metadata_tree,
        live->object_map, nx.xid, nx.xid, records, out_error)) return false;
    struct Parsed { AppleSnapshotRecord record; std::uint64_t apsb, extent; std::uint32_t extent_type; };
    std::vector<Parsed> parsed;
    std::unordered_map<std::string, std::uint64_t> names;
    std::unordered_set<std::uint64_t> xids;
    std::unordered_set<std::string> metadata_names;
    constexpr std::uint64_t id_mask = 0x0FFFFFFFFFFFFFFFull;
    for (const auto& raw : records)
    {
        if (raw.key.size() < 8) return fail("SnapshotRecordKeyMalformed");
        const auto key = ReadU64LE(raw.key, 0).value();
        const auto kind = key >> 60;
        if (kind == 1)
        {
            if (raw.key.size() != 8 || raw.value.size() < 50)
                return fail("SnapshotMetadataRecordMalformed");
            Parsed item{};
            item.record.xid = key & id_mask;
            item.extent = ReadU64LE(raw.value, 0).value();
            item.apsb = ReadU64LE(raw.value, 8).value();
            item.record.create_time_ns = ReadU64LE(raw.value, 16).value();
            item.record.change_time_ns = ReadU64LE(raw.value, 24).value();
            item.record.inum = ReadU64LE(raw.value, 32).value();
            item.extent_type = ReadU32LE(raw.value, 40).value();
            item.record.flags = ReadU32LE(raw.value, 44).value();
            if (item.record.flags != 0) return fail("SnapshotMetadataFlagsUnsupported");
            if (!SnapshotName(raw.value, 50, ReadU16LE(raw.value, 48).value(), item.record.name_utf8))
                return fail("SnapshotMetadataNameMalformed");
            if (item.record.xid == 0 || item.record.xid > nx.xid ||
                !xids.insert(item.record.xid).second) return fail("SnapshotXidInvalidOrDuplicate");
            if (!metadata_names.insert(item.record.name_utf8).second)
                return fail("SnapshotNameAmbiguous");
            if (item.apsb == 0 || item.extent == 0) return fail("SnapshotReferencedRootMissing");
            if (item.extent_type != (kObjectPhysical | kObjectTypeBtree))
                return fail("SnapshotExtentTreeTypeUnsupported");
            if (!Materialize(source, 1, sizeof(Parsed) + 2 * item.record.name_utf8.size())) return false;
            parsed.push_back(std::move(item));
        }
        else if (kind == 11)
        {
            if ((key & id_mask) != id_mask || raw.key.size() < 10 || raw.value.size() != 8)
                return fail("SnapshotNameRecordMalformed");
            std::string name;
            if (!SnapshotName(raw.key, 10, ReadU16LE(raw.key, 8).value(), name))
                return fail("SnapshotNameRecordMalformed");
            if (!Materialize(source, 1, name.size() + sizeof(std::uint64_t))) return false;
            if (!names.emplace(name, ReadU64LE(raw.value, 0).value()).second)
                return fail("SnapshotNameAmbiguous");
        }
        else return fail("SnapshotRecordTypeUnsupported");
    }
    if (parsed.size() != count || names.size() != parsed.size() ||
        live_omap_xids.size() != parsed.size()) return fail("SnapshotInventoryCountMismatch");
    std::sort(parsed.begin(), parsed.end(), [](const auto& a, const auto& b) {
        return a.record.xid < b.record.xid;
    });
    std::vector<AppleSnapshotRecord> result;
    for (auto& item : parsed)
    {
        auto& snapshot = item.record;
        const auto name = names.find(snapshot.name_utf8);
        if (name == names.end() || name->second != snapshot.xid ||
            !std::binary_search(live_omap_xids.begin(), live_omap_xids.end(), snapshot.xid))
            return fail("SnapshotNameOrOmapIdentityMismatch");
        if (!ReadAppleObject(store, nx.block_size, item.apsb, nx.block_size,
            item.apsb, nx.xid, kObjectPhysical, kObjectTypeFs, 0,
            "SnapshotApsb", snapshot.volume.superblock_object, bytes, out_error)) return false;
        const auto apsb = ParseApsb(bytes);
        if (!apsb || apsb->xid != snapshot.xid || apsb->uuid_hex != live->superblock.uuid_hex ||
            snapshot.volume.superblock_object.type != (kObjectPhysical | kObjectTypeFs))
            return fail("SnapshotApsbIdentityMismatch");
        if (!SnapshotVolumeSupported(bytes, *apsb, out_error)) return false;
        snapshot.volume.superblock = *apsb;
        if (apsb->extentref_tree_oid != item.extent || apsb->extentref_tree_type != item.extent_type)
            return fail("SnapshotExtentRootIdentityMismatch");
        if (!LoadAppleOmap(store, nx.block_size, apsb->omap_oid, nx.xid,
            "SnapshotApsbOmap", snapshot.volume.object_map, out_error)) return false;
        if (!SnapshotOmapSupported(store, nx.block_size, snapshot.volume.object_map,
            nx.xid, false, ignored, out_error)) return false;
        if (apsb->root_tree_type != kObjectTypeBtree &&
            apsb->root_tree_type != (kObjectPhysical | kObjectTypeBtree))
            return fail("SnapshotFsTreeTypeUnsupported");
        auto root_block = apsb->root_oid;
        auto root_max_xid = snapshot.xid;
        if (apsb->root_tree_type == kObjectTypeBtree)
        {
            const auto mapping = ResolveAppleOmapValue(store, nx.block_size,
                snapshot.volume.object_map, apsb->root_oid, snapshot.xid,
                "SnapshotRootOmap", out_error, nx.xid, true);
            if (!mapping) return false;
            if (mapping->size != nx.block_size) return fail("SnapshotMultiBlockNodeUnsupported");
            root_block = mapping->physical_block;
            root_max_xid = mapping->xid;
        }
        if (!ReadAppleObject(store, nx.block_size, root_block, nx.block_size,
            apsb->root_oid, root_max_xid, apsb->root_tree_type, kObjectTypeBtree,
            kObjectTypeFsTree, "SnapshotFsTree", snapshot.volume.root_tree, bytes, out_error)) return false;
        AppleObjectLocation extent;
        if (!ReadAppleObject(store, nx.block_size, item.extent, nx.block_size,
            item.extent, snapshot.xid, kObjectPhysical, kObjectTypeBtree,
            kObjectTypeBlockRefTree, "SnapshotExtentTree", extent, bytes, out_error)) return false;
        snapshot.volume.extentref_tree = extent;
        // Validate complete referenced trees now; no validated descriptor may
        // hide a malformed/cyclic child behind a superficially valid root.
        if (!ReadSnapshotTree(store, nx.block_size, snapshot.volume.root_tree,
            snapshot.volume.object_map, snapshot.xid, nx.xid, records, out_error)) return false;
        if (snapshot.xid == exact_snapshot_xid)
        {
            selected = true;
            selected_trees.filesystem = std::move(records);
        }
        if (!ReadSnapshotTree(store, nx.block_size, extent, snapshot.volume.object_map,
            snapshot.xid, nx.xid, records, out_error)) return false;
        if (snapshot.xid == exact_snapshot_xid) selected_trees.extentref = std::move(records);
        if (!Materialize(source, 1, sizeof(AppleSnapshotRecord))) return false;
        result.push_back(std::move(snapshot));
    }
    if (exact_snapshot_xid != 0 && !selected) return fail("SnapshotExactXidMissing");
    out_records = std::move(result);
    out_trees = std::move(selected_trees);
    return true;
}

std::vector<std::string> HexBits(std::uint64_t mask)
{
    std::vector<std::string> out;
    for (int bit = 0; bit < 64; ++bit)
    {
        if ((mask & (1ULL << bit)) != 0ULL)
        {
            char text[20];
            std::snprintf(text, sizeof(text), "0x%llx", static_cast<unsigned long long>(1ULL << bit));
            out.emplace_back(text);
        }
    }
    return out;
}

std::vector<std::string> UnknownBits(std::uint64_t value, std::uint64_t known_mask)
{
    return HexBits(value & ~known_mask);
}

std::string CaseModeFor(std::uint64_t incompatible_features)
{
    return (incompatible_features & kIncompatCaseInsensitive) != 0 ? "insensitive" : "sensitive";
}

std::string EncryptionModeFor(std::uint64_t fs_flags)
{
    const bool unencrypted = (fs_flags & kFsFlagUnencrypted) != 0;
    const bool one_key = (fs_flags & kFsFlagOneKey) != 0;
    if (one_key && !unencrypted)
    {
        return "password";
    }
    if (unencrypted && !one_key)
    {
        return "none";
    }
    if (fs_flags != 0)
    {
        return "unknown";
    }
    return "none";
}

std::string RoleNameFor(std::uint16_t role_raw)
{
    switch (role_raw)
    {
    case 0x0000:
        return "none";
    case 0x0040:
        return {"data"};
    case 0x0001:
        return {"system"};
    case 0x0002:
        return {"user"};
    case 0x0004:
        return {"recovery"};
    case 0x0008:
        return {"vm"};
    case 0x0010:
        return {"preboot"};
    case 0x0020:
        return {"installer"};
    case 0x0080:
        return {"baseband"};
    case 0x00C0:
        return {"update"};
    case 0x0100:
        return {"xart"};
    case 0x0140:
        return {"hardware"};
    case 0x0180:
        return {"backup"};
    case 0x0240:
        return {"enterprise"};
    case 0x02C0:
        return {"prelogin"};
    default:
        return {"unknown"};
    }
}

std::vector<std::string> RolesFor(std::uint16_t role_raw)
{
    return {role_raw == 0 ? "data" : RoleNameFor(role_raw)};
}

bool IsValidUtf8(const std::byte* data, std::size_t size)
{
    if (data == nullptr)
    {
        return size == 0;
    }
    std::size_t index = 0;
    while (index < size)
    {
        const unsigned char lead = std::to_integer<unsigned char>(data[index]);
        std::size_t length = 0;
        std::uint32_t codepoint = 0;
        if (lead < 0x80)
        {
            length = 1;
            codepoint = lead;
        }
        else if ((lead & 0xE0) == 0xC0)
        {
            length = 2;
            codepoint = lead & 0x1F;
        }
        else if ((lead & 0xF0) == 0xE0)
        {
            length = 3;
            codepoint = lead & 0x0F;
        }
        else if ((lead & 0xF8) == 0xF0)
        {
            length = 4;
            codepoint = lead & 0x07;
        }
        else
        {
            return false;
        }
        if (index + length > size)
        {
            return false;
        }
        for (std::size_t cont = 1; cont < length; ++cont)
        {
            const unsigned char unit =
                std::to_integer<unsigned char>(data[index + cont]);
            if ((unit & 0xC0) != 0x80)
            {
                return false;
            }
            codepoint = (codepoint << 6) | (unit & 0x3F);
        }
        // Reject overlongs, surrogates, and out-of-range codepoints.
        if ((length == 2 && codepoint < 0x80) ||
            (length == 3 && codepoint < 0x800) ||
            (length == 4 && codepoint < 0x10000) || codepoint > 0x10FFFF ||
            (codepoint >= 0xD800 && codepoint <= 0xDFFF))
        {
            return false;
        }
        index += length;
    }
    return true;
}

} // namespace apfsaccess::catalog
