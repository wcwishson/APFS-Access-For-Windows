#include "ApfsFormat.h"

#include <array>
#include <cstdio>
#include <queue>
#include <unordered_set>

namespace apfsaccess::catalog
{
namespace
{

constexpr std::uint64_t kFletcherModulus = 0xFFFFFFFFull;
constexpr std::uint32_t kMaxBtreeRecords = 100000;
constexpr std::size_t kMaxVisitedBlocks = 4096;
constexpr std::uint64_t kMaxGptEntries = 512;
constexpr std::size_t kMaxFsOidSlots = 128;

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
    if (block_size < 512 || block_size > (1u << 20) || block.size() < block_size)
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
    out.block_size = block_size;
    out.block_count = total_blocks;
    out.features = ReadU64LE(block, 0x30).value_or(0);
    out.readonly_features = ReadU64LE(block, 0x38).value_or(0);
    out.incompatible_features = ReadU64LE(block, 0x40).value_or(0);
    out.uuid_hex = BytesToHexLower(block.data() + 0x48, 16);
    out.omap_oid = ReadU64LE(block, 0xA0).value_or(0);
    if (out.omap_oid == 0)
    {
        return std::nullopt;
    }
    const std::size_t slot_count = (std::min)(
        kMaxFsOidSlots, (block_size - 0xB8) / sizeof(std::uint64_t));
    for (std::size_t slot = 0; slot < slot_count; ++slot)
    {
        const auto oid = ReadU64LE(block, 0xB8 + slot * sizeof(std::uint64_t)).value_or(0);
        if (oid != 0)
        {
            out.fs_oids.push_back(oid);
        }
    }
    return out;
}

std::optional<NxSuperblock> SelectContainerCheckpoint(
    const RandomAccessSource& source,
    std::uint64_t store_offset_bytes,
    std::uint64_t store_size_bytes)
{
    std::vector<std::byte> probe;
    if (!ReadInto(source, store_offset_bytes, 4096, probe))
    {
        return std::nullopt;
    }
    const std::uint32_t block_size = ReadU32LE(probe, 0x24).value_or(0);
    if (block_size < 512 || block_size > (1u << 20))
    {
        return std::nullopt;
    }
    if (store_size_bytes < static_cast<std::uint64_t>(block_size) * 2)
    {
        return std::nullopt;
    }
    std::vector<std::byte> first, second;
    if (!ReadBlockAt(source, store_offset_bytes, block_size, first) ||
        !ReadBlockAt(source, store_offset_bytes + block_size, block_size, second))
    {
        return std::nullopt;
    }
    auto primary = ParseNxSuperblock(first);
    auto secondary = ParseNxSuperblock(second);
    if (!primary.has_value())
    {
        return secondary;
    }
    if (!secondary.has_value())
    {
        return primary;
    }
    if (secondary->uuid_hex != primary->uuid_hex ||
        secondary->block_size != primary->block_size ||
        secondary->block_count != primary->block_count)
    {
        return std::nullopt;
    }
    if (secondary->xid > primary->xid)
    {
        return secondary;
    }
    return primary;
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
    (void)max_xid_hint;
    out_records.clear();
    out_error.clear();
    if (block_size == 0 || root_block == 0)
    {
        out_error = "CatalogBtreeRootInvalid";
        return false;
    }
    std::queue<std::uint64_t> pending;
    pending.push(root_block);
    std::unordered_set<std::uint64_t> visited;
    visited.reserve(kMaxVisitedBlocks);
    std::vector<std::byte> block;
    while (!pending.empty())
    {
        const std::uint64_t block_index = pending.front();
        pending.pop();
        if (!visited.insert(block_index).second)
        {
            continue;
        }
        if (visited.size() > kMaxVisitedBlocks)
        {
            out_error = "CatalogBtreeCycle";
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
        const std::uint32_t object_type = ReadU32LE(block, 0x18).value_or(0xFFFFFFFFu) & kObjectTypeMask;
        if (object_type != kObjectTypeBtree && object_type != kObjectTypeBtreeNode)
        {
            out_error = "CatalogBtreeNotABtree";
            return false;
        }
        const std::uint16_t flags = ReadU16LE(block, 0x20).value_or(0);
        const std::uint16_t level = ReadU16LE(block, 0x22).value_or(0xFFFFu);
        const std::uint32_t key_count = ReadU32LE(block, 0x24).value_or(kMaxBtreeRecords + 1);
        const std::uint16_t table_offset = ReadU16LE(block, 0x28).value_or(0xFFFFu);
        const std::uint16_t table_length = ReadU16LE(block, 0x2A).value_or(0xFFFFu);
        const std::uint16_t free_offset = ReadU16LE(block, 0x2C).value_or(0xFFFFu);
        const std::uint16_t free_length = ReadU16LE(block, 0x2E).value_or(0xFFFFu);
        if (level == 0xFFFFu || key_count > kMaxBtreeRecords || table_offset == 0xFFFFu ||
            table_length == 0xFFFFu || free_offset == 0xFFFFu || free_length == 0xFFFFu)
        {
            out_error = "CatalogBtreeHeaderInvalid";
            return false;
        }
        const bool fixed_kv = (flags & 0x0004u) != 0;
        const bool is_root = (flags & 0x0001u) != 0;
        const std::size_t info_start = is_root ? (block.size() - 40) : block.size();
        const std::uint32_t key_size = is_root ? ReadU32LE(block, info_start + 8).value_or(0) : 0;
        const std::uint32_t value_size = is_root ? ReadU32LE(block, info_start + 12).value_or(0) : 0;
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
                key_length = static_cast<std::uint16_t>(key_size);
                value_length = static_cast<std::uint16_t>(value_size != 0 ? value_size : sizeof(std::uint64_t));
            }
            else
            {
                key_offset = ReadU16LE(block, entry_offset).value_or(0xFFFFu);
                key_length = ReadU16LE(block, entry_offset + 2).value_or(0xFFFFu);
                value_offset = ReadU16LE(block, entry_offset + 4).value_or(0xFFFFu);
                value_length = ReadU16LE(block, entry_offset + 6).value_or(0xFFFFu);
            }
            if (key_offset == 0xFFFFu || value_offset == 0xFFFFu)
            {
                continue;
            }
            if (key_area_start + key_offset > block.size() ||
                key_length > block.size() - (key_area_start + key_offset) ||
                value_offset > value_area_end || value_length > value_area_end ||
                value_area_end - value_offset > block.size() ||
                value_length > block.size() - (value_area_end - value_offset))
            {
                out_error = "CatalogBtreeEntryInvalid";
                return false;
            }
            const std::size_t key_start = key_area_start + key_offset;
            const std::size_t value_start = value_area_end - value_offset;
            if (level == 0)
            {
                BtreeRecord record;
                record.key.assign(
                    block.begin() + static_cast<std::vector<std::byte>::difference_type>(key_start),
                    block.begin() + static_cast<std::vector<std::byte>::difference_type>(key_start + key_length));
                record.value.assign(
                    block.begin() + static_cast<std::vector<std::byte>::difference_type>(value_start),
                    block.begin() + static_cast<std::vector<std::byte>::difference_type>(value_start + value_length));
                out_records.push_back(std::move(record));
                continue;
            }
            if (value_length < sizeof(std::uint64_t))
            {
                out_error = "CatalogBtreeChildInvalid";
                return false;
            }
            std::uint64_t child_block = 0;
            for (int b = 0; b < 8; ++b)
            {
                child_block |= static_cast<std::uint64_t>(std::to_integer<unsigned char>(
                    block[value_start + static_cast<std::size_t>(b)])) << (b * 8);
            }
            if (!child_addresses_are_physical)
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
            if (child_block != 0)
            {
                pending.push(child_block);
            }
        }
    }
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
    if ((ReadU32LE(omap, 0x18).value_or(0xFFFFFFFFu) & kObjectTypeMask) != kObjectTypeOmap)
    {
        out_error = "CatalogOmapNotAnOmap";
        return std::nullopt;
    }
    const std::uint64_t tree_oid = ReadU64LE(omap, 0x30).value_or(0);
    if (tree_oid == 0)
    {
        out_error = "CatalogOmapTreeMissing";
        return std::nullopt;
    }
    std::vector<BtreeRecord> records;
    if (!ReadBtreeLeafRecords(source, block_size, tree_oid, true, 0, max_xid, records, out_error))
    {
        return std::nullopt;
    }
    std::optional<OmapValue> selected;
    for (const auto& record : records)
    {
        if (record.key.size() < 16 || record.value.size() < 16)
        {
            continue;
        }
        const auto candidate_oid = ReadU64LE(record.key, 0).value_or(0xFFFFFFFFFFFFFFFFull);
        const auto candidate_xid = ReadU64LE(record.key, 8).value_or(0xFFFFFFFFFFFFFFFFull);
        if (candidate_oid != oid || candidate_xid > max_xid)
        {
            continue;
        }
        OmapValue value;
        value.flags = ReadU32LE(record.value, 0).value_or(0xFFFFFFFFu);
        value.size = ReadU32LE(record.value, 4).value_or(0);
        value.physical_block = ReadU64LE(record.value, 8).value_or(0);
        value.xid = candidate_xid;
        if (value.flags == 0xFFFFFFFFu || (value.flags & 0x1u) != 0 || value.physical_block == 0)
        {
            continue;
        }
        if (!selected.has_value() || value.xid > selected->xid)
        {
            selected = value;
        }
    }
    if (!selected.has_value())
    {
        out_error = "CatalogOmapValueMissing";
    }
    return selected;
}

std::optional<ApsbVolume> ParseApsb(const std::vector<std::byte>& block)
{
    if (block.size() < 0x410 || !BytesEqual(block, 0x20, "APSB", 4))
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
    out.object_id = ReadU64LE(block, 0x08).value_or(0);
    out.xid = ReadU64LE(block, 0x10).value_or(0);
    out.omap_oid = ReadU64LE(block, 0x80).value_or(0);
    out.root_oid = ReadU64LE(block, 0x88).value_or(0);
    out.extent_tree_oid = ReadU64LE(block, 0x408).value_or(0);
    out.file_count = ReadU64LE(block, 0xB8).value_or(0);
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
        if (block[0x120 + index] == std::byte{0})
        {
            terminated = true;
            break;
        }
        ++name_end;
    }
    out.name_valid = terminated && IsValidUtf8(block.data() + 0x120, name_end);
    out.name_utf8.clear();
    if (out.name_valid)
    {
        for (std::size_t index = 0; index < name_end; ++index)
        {
            out.name_utf8.push_back(static_cast<char>(block[0x120 + index]));
        }
    }
    out.role_raw = ReadU16LE(block, 0x224).value_or(0);
    bool group_nonzero = false;
    for (int index = 0; index < 16; ++index)
    {
        if (block[0x228 + static_cast<std::size_t>(index)] != std::byte{0})
        {
            group_nonzero = true;
            break;
        }
    }
    out.group_hex = group_nonzero ? BytesToHexLower(block.data() + 0x228, 16) : std::string{};
    return out;
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
    if ((fs_flags & kFsFlagOneKey) != 0)
    {
        return "password";
    }
    if ((fs_flags & kFsFlagEffaceable) != 0)
    {
        return "hardware-bound";
    }
    if ((fs_flags & ~kFsFlagUnencrypted) != 0)
    {
        return "unknown";
    }
    return "none";
}

std::vector<std::string> RolesFor(std::uint16_t role_raw)
{
    if (role_raw == 0)
    {
        return {"data"};
    }
    static constexpr std::uint16_t kBits[] = {
        0x0001, 0x0002, 0x0004, 0x0008, 0x0010, 0x0020, 0x0040, 0x0080,
        0x0100, 0x0200, 0x0400, 0x0800, 0x1000, 0x2000, 0x4000,
    };
    static constexpr const char* kNames[] = {
        "system", "recovery", "vm", "preboot", "installer", "data",
        "baseband", "ts", "update", "xart", "hardware", "backup",
        "enterprise", "prelogin", "image",
    };
    std::vector<std::string> out;
    std::uint16_t known = 0;
    for (std::size_t index = 0; index < 15; ++index)
    {
        if ((role_raw & kBits[index]) != 0)
        {
            out.emplace_back(kNames[index]);
        }
        known = static_cast<std::uint16_t>(known | kBits[index]);
    }
    if ((role_raw & static_cast<std::uint16_t>(~known)) != 0)
    {
        out.emplace_back("unknown");
    }
    if (out.empty())
    {
        out.emplace_back("unknown");
    }
    return out;
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