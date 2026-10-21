#include "ApfsFormat.h"
#include "ApfsReadOnlyMetadataAdmission.h"
#include "ApfsEncryptedSnapshotReadContext.h"
#include "ApfsFusionSnapshotCatalog.h"
#include "ApfsFusionSpaceman.h"
#include "ApfsTransactionWriter.h"
#include "ApfsNameCodec.h"

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

struct OmapLookupEntry
{
    std::uint64_t object_id = 0;
    OmapValue value;
};

// Owned by one tree traversal, so no mapping survives a publication or a new
// source observation. Populate only after the complete OMAP passes validation.
bool LoadOmapLookup(const RandomAccessSource& source, std::uint32_t block_size,
    std::uint64_t map_oid, std::uint64_t max_xid, bool strict,
    std::vector<OmapLookupEntry>& entries, std::string& error);
std::optional<OmapValue> SelectOmapLookup(const std::vector<OmapLookupEntry>& entries,
    std::uint64_t object_id, std::uint64_t max_xid, std::string& error,
    std::string_view prefix = "CatalogOmap");

bool BuildOmapLookup(const RandomAccessSource& source, const std::vector<BtreeRecord>& records,
    bool strict_identity, bool strict_snapshot, bool strict_order,
    std::uint64_t tree_max_xid, const std::string& prefix,
    std::vector<OmapLookupEntry>& entries, std::string& error, bool encrypted_metadata = false)
{
    entries.clear();
    bool complete = false;
    struct ClearIncomplete
    {
        std::vector<OmapLookupEntry>& entries;
        bool& complete;
        ~ClearIncomplete() { if (!complete) entries.clear(); }
    } clear_incomplete{entries, complete};
    std::pair<std::uint64_t, std::uint64_t> previous{};
    bool have_previous = false;
    for (const auto& record : records)
    {
        if (record.key.size() != 16 || record.value.size() != 16)
        { error = prefix + "RecordSizeInvalid"; return false; }
        const auto oid = ReadU64LE(record.key, 0).value();
        const auto xid = ReadU64LE(record.key, 8).value();
        const auto key = std::make_pair(oid, xid);
        if (strict_order && have_previous && key <= previous)
        { error = prefix + "KeyOrderInvalid"; return false; }
        previous = key; have_previous = true;
        if (strict_snapshot && (oid == 0 || xid == 0 || xid > tree_max_xid ||
            (ReadU32LE(record.value, 0).value() & ~(encrypted_metadata ? 0x7u : 0x3u)) != 0))
        { error = prefix + "UnsupportedRecordFlagsOrXid"; return false; }
        if (strict_identity && (oid == 0 || xid == 0))
        { error = prefix + "RecordIdentityInvalid"; return false; }
        if (!Materialize(source, 0, sizeof(OmapLookupEntry))) return false;
        entries.push_back({oid, {ReadU32LE(record.value, 0).value(),
            ReadU32LE(record.value, 4).value(), ReadU64LE(record.value, 8).value(), xid}});
    }
    std::sort(entries.begin(), entries.end(), [](const auto& left, const auto& right) {
        return std::make_pair(left.object_id, left.value.xid) <
            std::make_pair(right.object_id, right.value.xid);
    });
    for (std::size_t index = 1; index < entries.size(); ++index)
        if (entries[index - 1].object_id == entries[index].object_id &&
            entries[index - 1].value.xid == entries[index].value.xid)
        { error = prefix + "KeyDuplicate"; return false; }
    complete = true;
    return true;
}

bool ReadInto(const RandomAccessSource& source, std::uint64_t offset, std::size_t size, std::vector<std::byte>& out)
{
    out.clear();
    if (size == 0)
    {
        return true;
    }
    return source.Read(offset, size, out) && out.size() == size;
}

// Only the opt-in node context owns decrypted parser materializations.
// Preserve the existing ordinary parser's allocation and cleanup policy.
void WipeBtreeRecord(BtreeRecord& record) noexcept
{
    for (auto* bytes : {&record.key, &record.value})
    {
        volatile std::byte* data = bytes->data();
        for (std::size_t i = 0; i < bytes->size(); ++i) data[i] = std::byte{};
    }
}

// Routing retains copies beyond the provider's node lease. Own their cleanup,
// including queue copies, reassignment and comparator/allocation exceptions.
// Ordinary traversal retains its existing non-wiping policy.
struct BtreeRoutingBytes : std::vector<std::byte>
{
    using Bytes = std::vector<std::byte>;
    bool wipe = false;
    explicit BtreeRoutingBytes(bool wipe = false) : wipe(wipe) {}
    BtreeRoutingBytes(const BtreeRoutingBytes& other) : Bytes(other), wipe(other.wipe) {}
    BtreeRoutingBytes(BtreeRoutingBytes&& other) noexcept
        : Bytes(std::move(other)), wipe(other.wipe) {}
    BtreeRoutingBytes& operator=(const BtreeRoutingBytes& other)
    {
        if (this != &other) { ClearOwned(); Bytes::operator=(other); wipe = other.wipe; }
        return *this;
    }
    BtreeRoutingBytes& operator=(BtreeRoutingBytes&& other) noexcept
    {
        if (this != &other) { ClearOwned(); Bytes::operator=(std::move(other)); wipe = other.wipe; }
        return *this;
    }
    ~BtreeRoutingBytes() { ClearOwned(); }
    void ClearOwned() noexcept
    {
        if (!wipe) return;
        volatile std::byte* bytes = data();
        for (std::size_t i = 0; i < size(); ++i) bytes[i] = std::byte{};
    }
};

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
    return ReadU16LE(std::span<const std::byte>(buffer), offset);
}

std::optional<std::uint16_t> ReadU16LE(std::span<const std::byte> buffer, std::size_t offset)
{
    if (offset > buffer.size() || sizeof(std::uint16_t) > buffer.size() - offset)
    {
        return std::nullopt;
    }
    const auto lo = static_cast<std::uint16_t>(std::to_integer<unsigned char>(buffer[offset]));
    const auto hi = static_cast<std::uint16_t>(std::to_integer<unsigned char>(buffer[offset + 1]));
    return static_cast<std::uint16_t>(lo | (hi << 8));
}

std::optional<std::uint32_t> ReadU32LE(const std::vector<std::byte>& buffer, std::size_t offset)
{
    return ReadU32LE(std::span<const std::byte>(buffer), offset);
}

std::optional<std::uint32_t> ReadU32LE(std::span<const std::byte> buffer, std::size_t offset)
{
    if (offset > buffer.size() || sizeof(std::uint32_t) > buffer.size() - offset)
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
    return ReadU64LE(std::span<const std::byte>(buffer), offset);
}

std::optional<std::uint64_t> ReadU64LE(std::span<const std::byte> buffer, std::size_t offset)
{
    if (offset > buffer.size() || sizeof(std::uint64_t) > buffer.size() - offset)
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
    const auto word_count = size / sizeof(std::uint32_t);
    std::size_t index = 0;
    while (index + 4 <= word_count)
    {
        std::uint32_t w0, w1, w2, w3;
        std::memcpy(&w0, data + (index + 0) * sizeof(std::uint32_t), sizeof(std::uint32_t));
        std::memcpy(&w1, data + (index + 1) * sizeof(std::uint32_t), sizeof(std::uint32_t));
        std::memcpy(&w2, data + (index + 2) * sizeof(std::uint32_t), sizeof(std::uint32_t));
        std::memcpy(&w3, data + (index + 3) * sizeof(std::uint32_t), sizeof(std::uint32_t));

        sum1 += w0; sum2 += sum1;
        sum1 += w1; sum2 += sum1;
        sum1 += w2; sum2 += sum1;
        sum1 += w3; sum2 += sum1;
        index += 4;
    }
    while (index < word_count)
    {
        std::uint32_t word = 0;
        std::memcpy(&word, data + index * sizeof(std::uint32_t), sizeof(std::uint32_t));
        sum1 += word;
        sum2 += sum1;
        ++index;
    }
    const std::uint64_t low = kFletcherModulus - ((sum1 + sum2) % kFletcherModulus);
    const std::uint64_t high = kFletcherModulus - ((sum1 + low) % kFletcherModulus);
    return (high << 32) | low;
}

bool VerifyObjectChecksum(const std::vector<std::byte>& block, std::size_t block_size)
{
    return VerifyObjectChecksum(std::span<const std::byte>(block), block_size);
}

bool VerifyObjectChecksum(std::span<const std::byte> block, std::size_t block_size)
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
    std::copy_n(block.begin() + 0x500, 16, out.fusion_uuid.begin());
    out.fusion_middle_tree_oid = ReadU64LE(block, 0x548).value();
    out.fusion_writeback_oid = ReadU64LE(block, 0x550).value();
    out.fusion_writeback_start = ReadU64LE(block, 0x558).value();
    out.fusion_writeback_blocks = ReadU64LE(block, 0x560).value();
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
    std::uint32_t candidate_index,
    std::optional<std::uint64_t> exact_checkpoint_xid)
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

    if (exact_checkpoint_xid && candidate->xid != *exact_checkpoint_xid)
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
            store_size_bytes, anchor.value(), descriptor_blocks, index, exact_checkpoint_xid);
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
    return ReadBtreeLeafRecords(source, block_size, root_block, child_addresses_are_physical,
        child_object_map_oid, max_xid_hint, policy, BtreeRoutingPolicy{}, out_records, out_error, nullptr);
}

static bool ReadBtreeLeafRecordsImpl(const RandomAccessSource& source, std::uint32_t block_size,
    std::uint64_t root_block, bool child_addresses_are_physical, std::uint64_t child_object_map_oid,
    std::uint64_t max_xid_hint, const BtreeReadPolicy& policy, const BtreeRoutingPolicy& routing,
    std::vector<BtreeRecord>& out_records, std::string& out_error, BtreeNodeReadContext* node_context,
    std::vector<BtreeNodeIdentity>* identities, std::optional<std::uint64_t> root_mapping_xid,
    bool protected_identity_capture);

bool ReadBtreeLeafRecords(
    const RandomAccessSource& source, std::uint32_t block_size,
    std::uint64_t root_block, bool child_addresses_are_physical,
    std::uint64_t child_object_map_oid, std::uint64_t max_xid_hint,
    const BtreeReadPolicy& policy, std::vector<BtreeRecord>& out_records,
    std::string& out_error, BtreeNodeReadContext* node_context)
{
    return ReadBtreeLeafRecords(source, block_size, root_block, child_addresses_are_physical,
        child_object_map_oid, max_xid_hint, policy, BtreeRoutingPolicy{}, out_records, out_error, node_context);
}

bool ReadBtreeLeafRecords(
    const RandomAccessSource& source, std::uint32_t block_size,
    std::uint64_t root_block, bool child_addresses_are_physical,
    std::uint64_t child_object_map_oid, std::uint64_t max_xid_hint,
    const BtreeReadPolicy& policy, const BtreeRoutingPolicy& routing,
    std::vector<BtreeRecord>& out_records, std::string& out_error)
{
    return ReadBtreeLeafRecords(source, block_size, root_block, child_addresses_are_physical,
        child_object_map_oid, max_xid_hint, policy, routing, out_records, out_error, nullptr);
}

bool ReadBtreeLeafRecords(
    const RandomAccessSource& source, std::uint32_t block_size,
    std::uint64_t root_block, bool child_addresses_are_physical,
    std::uint64_t child_object_map_oid, std::uint64_t max_xid_hint,
    const BtreeReadPolicy& policy, const BtreeRoutingPolicy& routing,
    std::vector<BtreeRecord>& out_records, std::string& out_error, BtreeNodeReadContext* node_context)
{
    return ReadBtreeLeafRecords(source, block_size, root_block, child_addresses_are_physical,
        child_object_map_oid, max_xid_hint, policy, routing, out_records, out_error,
        node_context, nullptr, std::nullopt);
}

bool ReadBtreeLeafRecords(
    const RandomAccessSource& source, std::uint32_t block_size,
    std::uint64_t root_block, bool child_addresses_are_physical,
    std::uint64_t child_object_map_oid, std::uint64_t max_xid_hint,
    const BtreeReadPolicy& policy, const BtreeRoutingPolicy& routing,
    std::vector<BtreeRecord>& out_records, std::string& out_error, BtreeNodeReadContext* node_context,
    std::vector<BtreeNodeIdentity>* identities, std::optional<std::uint64_t> root_mapping_xid)
{
    return ReadBtreeLeafRecordsImpl(source, block_size, root_block, child_addresses_are_physical,
        child_object_map_oid, max_xid_hint, policy, routing, out_records, out_error,
        node_context, identities, root_mapping_xid, false);
}

static bool ReadBtreeLeafRecordsImpl(const RandomAccessSource& source, std::uint32_t block_size,
    std::uint64_t root_block, bool child_addresses_are_physical, std::uint64_t child_object_map_oid,
    std::uint64_t max_xid_hint, const BtreeReadPolicy& policy, const BtreeRoutingPolicy& routing,
    std::vector<BtreeRecord>& out_records, std::string& out_error, BtreeNodeReadContext* node_context,
    std::vector<BtreeNodeIdentity>* identities, std::optional<std::uint64_t> root_mapping_xid,
    bool protected_identity_capture)
{
    BudgetErrorScope budget_error{source, out_error};
    bool complete = false;
    struct ClearIncomplete
    {
        bool& complete;
        std::vector<BtreeRecord>& records;
        std::vector<std::uint64_t>* visited;
        std::vector<BtreeNodeIdentity>* identities;
        bool wipe;
        ~ClearIncomplete()
        {
            if (!complete)
            {
                if (wipe) for (auto& record : records) WipeBtreeRecord(record);
                records.clear();
                if (visited) visited->clear();
                if (identities) identities->clear();
            }
        }
    } clear_incomplete{complete, out_records, policy.visited_physical_blocks, identities, node_context != nullptr};
    if (identities) identities->clear();
    out_records.clear();
    out_error.clear();
    if (policy.visited_physical_blocks != nullptr)
    {
        policy.visited_physical_blocks->clear();
    }
    if (identities && ((node_context && (!protected_identity_capture || !routing.compare_keys)) ||
        !policy.enforce_object_identity || !policy.require_complete_traversal ||
        !policy.reject_unsupported_flags || !max_xid_hint ||
        (child_addresses_are_physical ? root_mapping_xid.has_value() :
            (!root_mapping_xid || !policy.virtual_child_resolver))))
    { out_error = "CatalogBtreeIdentityCaptureRequiresStrictSelection"; return false; }
    if (routing.compare_keys && !policy.require_complete_traversal)
    { out_error = "CatalogBtreeRoutingRequiresCompleteTraversal"; return false; }
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
        BtreeRoutingBytes lower, upper;
    };
    // Preserve the legacy logical budget charge when routing is not requested.
    // The added vectors are empty and allocate no buffers on that path.
    const auto pending_charge = routing.compare_keys ? sizeof(PendingNode) :
        sizeof(PendingNode) - 2 * sizeof(BtreeRoutingBytes);
    std::queue<PendingNode> pending;
    if (!Materialize(source, 0, pending_charge)) return false;
    pending.push({root_block, policy.root_object_id, true, std::nullopt, root_mapping_xid,
        BtreeRoutingBytes(node_context != nullptr), BtreeRoutingBytes(node_context != nullptr)});
    std::unordered_set<std::uint64_t> visited;
    if (!source.ReadBudget()) visited.reserve(kMaxVisitedBlocks);
    std::vector<std::byte> ordinary_block;
    std::span<const std::byte> block;
    bool root_layout_seen = false;
    std::uint32_t tree_key_size = 0;
    std::uint32_t tree_value_size = 0;
    std::uint64_t declared_key_count = 0;
    std::uint64_t declared_node_count = 0;
    std::optional<std::vector<OmapLookupEntry>> child_omap;
    while (!pending.empty())
    {
        struct ReleaseNode
        {
            BtreeNodeReadContext* context;
            ~ReleaseNode() { if (context) context->ReleaseNode(); }
        } release_node{node_context};
        const PendingNode current = std::move(pending.front());
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
        std::optional<BtreeVirtualChildMapping> selected_mapping;
        // The existing resolver contract is child-only. Root contexts resolve
        // their own complete bound mapping, as before this additive boundary.
        if (node_context && policy.virtual_child_resolver && !current.root)
        {
            selected_mapping = policy.virtual_child_resolver(current.object_id, out_error);
            if (!selected_mapping || selected_mapping->physical_block != block_index ||
                (current.mapping_xid && selected_mapping->xid != *current.mapping_xid))
            { out_error = "CatalogBtreeMappedNodeMismatch"; return false; }
        }
        const bool read_ok = node_context
            ? (selected_mapping ? node_context->ReadMappedNode(current.object_id, *selected_mapping,
                    current.root, block, out_error)
                : node_context->ReadNode(current.object_id, block_index, current.root, block, out_error))
            : ReadBlockAt(source, block_index * block_size, block_size, ordinary_block);
        if (!node_context) block = ordinary_block;
        if (!read_ok || block.size() != block_size)
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
            ((full_object_type & ~(kObjectStorageTypeMask | kObjectTypeMask |
                (node_context ? 0x10000000u : 0u))) != 0 ||
             (flags & ~0x0007u) != 0 || ReadU64LE(block, 0x10).value_or(0) == 0))
        {
            out_error = "CatalogBtreeUnsupportedFlagsOrZeroXid";
            return false;
        }
        const std::uint16_t level = ReadU16LE(block, 0x22).value_or(0xFFFFu);
        if (identities)
        {
            if (!Materialize(source, 1, sizeof(BtreeNodeIdentity))) return false;
            identities->push_back({object_id, ReadU64LE(block, 0x10).value(), block_index,
                full_object_type, ReadU32LE(block, 0x1C).value(), current.mapping_xid});
        }
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
                // NONPERSISTENT, hashes and no-header are unsupported. Ghosts
                // require an explicit routing policy and include_ghost_records
                // (used for authoritative spaceman singleton queue entries).
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
        std::vector<PendingNode> children;
        BtreeRoutingBytes previous_key(node_context != nullptr);
        if (routing.compare_keys && !current.root && key_count == 0)
        { out_error = "CatalogBtreeRoutingEmptyChild"; return false; }
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
            if (policy.require_complete_traversal && (key_offset == 0xFFFFu ||
                (ghost && !(routing.compare_keys && policy.include_ghost_records)) || key_length == 0))
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
                    (!ghost && (value_start < value_area_start || value_length > value_area_end - value_start))))
            {
                out_error = "CatalogBtreeEntryRegionInvalid";
                return false;
            }
            BtreeRoutingBytes routing_key(node_context != nullptr);
            if (routing.compare_keys)
            {
                // Charge retained keys and temporary comparison/queue copies.
                if (!Materialize(source, 0, 8ull * key_length +
                        4ull * (current.lower.size() + current.upper.size()))) return false;
                routing_key.assign(block.begin() + key_start, block.begin() + key_start + key_length);
                const auto valid = routing.compare_keys(routing_key, routing_key, out_error);
                if (!valid) return false;
                if (*valid != 0) { out_error = "CatalogBtreeRoutingComparatorInvalid"; return false; }
                if (!previous_key.empty())
                {
                    const auto order = routing.compare_keys(previous_key, routing_key, out_error);
                    if (!order) return false;
                    if (*order >= 0)
                    { out_error = level ? "CatalogBtreeRoutingSeparatorOrder" : "CatalogBtreeLeafKeyOrder"; return false; }
                }
                if (!current.lower.empty())
                {
                    const auto order = routing.compare_keys(routing_key, current.lower, out_error);
                    if (!order) return false;
                    if (*order < 0 || (index == 0 && *order != 0))
                    { out_error = "CatalogBtreeRoutingChildMinimumMismatch"; return false; }
                }
                if (!current.upper.empty())
                {
                    const auto order = routing.compare_keys(routing_key, current.upper, out_error);
                    if (!order) return false;
                    if (*order >= 0)
                    { out_error = "CatalogBtreeRoutingChildUpperBound"; return false; }
                }
                if (!children.empty()) children.back().upper = routing_key;
                previous_key = routing_key;
            }
            if (level == 0)
            {
                if (!Materialize(source, 1, sizeof(BtreeRecord) +
                        static_cast<std::uint64_t>(key_length) + (ghost ? 0 : value_length))) return false;
                BtreeRecord record;
                struct ClearUnpublishedRecord
                {
                    BtreeRecord& record;
                    bool wipe;
                    ~ClearUnpublishedRecord() { if (wipe) WipeBtreeRecord(record); }
                } clear_record{record, node_context != nullptr};
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
                    if (child_block == 0)
                    {
                        out_error = "CatalogBtreeChildUnmapped";
                        return false;
                    }
                    if (!child_omap)
                    {
                        child_omap.emplace();
                        if (!LoadOmapLookup(source, block_size, child_object_map_oid,
                                max_xid_hint, false, *child_omap, out_error))
                            return false;
                    }
                    auto mapped = SelectOmapLookup(*child_omap, child_block,
                        max_xid_hint, out_error);
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
                if (!Materialize(source, 0, pending_charge)) return false;
                PendingNode child{child_block, child_object_id, false,
                    static_cast<std::uint16_t>(level - 1), child_mapping_xid,
                    std::move(routing_key), current.upper};
                if (routing.compare_keys) children.push_back(std::move(child));
                else pending.push(std::move(child));
            }
        }
        for (auto& child : children) pending.push(std::move(child));
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
    return ResolveOmapValue(source, block_size, map_oid, oid, max_xid, out_error, false);
}

std::optional<OmapValue> ResolveOmapValue(
    const RandomAccessSource& source,
    std::uint32_t block_size,
    std::uint64_t map_oid,
    std::uint64_t oid,
    std::uint64_t max_xid,
    std::string& out_error, bool strict)
{
    BudgetErrorScope budget_error{source, out_error};
    out_error.clear();
    std::vector<OmapLookupEntry> entries;
    if (oid == 0)
    {
        out_error = "CatalogOmapRequestInvalid";
        return std::nullopt;
    }
    if (!LoadOmapLookup(source, block_size, map_oid, max_xid, strict, entries, out_error))
        return std::nullopt;
    return SelectOmapLookup(entries, oid, max_xid, out_error);
}

namespace
{
bool LoadOmapLookup(const RandomAccessSource& source, std::uint32_t block_size,
    std::uint64_t map_oid, std::uint64_t max_xid, bool strict,
    std::vector<OmapLookupEntry>& entries, std::string& out_error)
{
    entries.clear();
    bool complete = false;
    struct ClearIncomplete
    {
        std::vector<OmapLookupEntry>& entries;
        bool& complete;
        ~ClearIncomplete() { if (!complete) entries.clear(); }
    } clear_incomplete{entries, complete};
    BudgetErrorScope budget_error{source, out_error};
    out_error.clear();
    if (block_size == 0 || map_oid == 0)
    {
        out_error = "CatalogOmapRequestInvalid";
        return false;
    }
    if (map_oid > (0xFFFFFFFFFFFFFFFFull / block_size))
    {
        out_error = "CatalogOmapBlockOverflow";
        return false;
    }
    std::vector<std::byte> omap;
    if (!ReadBlockAt(source, map_oid * block_size, block_size, omap))
    {
        out_error = "CatalogOmapUnreadable";
        return false;
    }
    if (!VerifyObjectChecksum(omap, block_size))
    {
        out_error = "CatalogOmapChecksumInvalid";
        return false;
    }
    const std::uint32_t omap_type = ReadU32LE(omap, 0x18).value_or(0xFFFFFFFFu);
    if ((omap_type & kObjectTypeMask) != kObjectTypeOmap)
    {
        out_error = "CatalogOmapNotAnOmap";
        return false;
    }
    if (max_xid != 0)
    {
        const std::uint64_t omap_xid = ReadU64LE(omap, 0x10).value_or(0xFFFFFFFFFFFFFFFFull);
        if (omap_xid > max_xid)
        {
            out_error = "CatalogOmapFutureXid";
            return false;
        }
    }
    const std::uint64_t tree_oid = ReadU64LE(omap, 0x30).value_or(0);
    if (tree_oid == 0)
    {
        out_error = "CatalogOmapTreeMissing";
        return false;
    }
    std::vector<BtreeRecord> records;
    const std::uint32_t tree_type = ReadU32LE(omap, 0x28).value_or(0);
    const bool has_strict_identity =
        (omap_type & kObjectStorageTypeMask) == kObjectPhysical &&
        (tree_type & kObjectStorageTypeMask) == kObjectPhysical &&
        (tree_type & kObjectTypeMask) == kObjectTypeBtree;
    if (strict && (!has_strict_identity || omap_type != (kObjectPhysical | kObjectTypeOmap) ||
        tree_type != (kObjectPhysical | kObjectTypeBtree) || ReadU32LE(omap, 28) != 0u ||
        ReadU64LE(omap, 16).value_or(0) == 0 || ReadU32LE(omap, 32) != 0u))
    {
        out_error = "CatalogOmapUnsupportedProfile";
        return false;
    }
    BtreeReadPolicy policy;
    policy.reject_unsupported_flags = strict;
    policy.require_complete_traversal = true;
    if (has_strict_identity)
    {
        if (ReadU64LE(omap, 0x08).value_or(0) != map_oid)
        {
            out_error = "CatalogOmapObjectIdMismatch";
            return false;
        }
        policy.enforce_object_identity = true;
        policy.root_object_id = tree_oid;
        policy.storage_type = kObjectPhysical;
        policy.subtype = kObjectTypeOmap;
    }
    if (!ReadBtreeLeafRecords(source, block_size, tree_oid, true, 0, max_xid,
            policy, records, out_error))
    {
        return false;
    }
    if (!BuildOmapLookup(source, records, strict, false, false, 0,
            "CatalogOmap", entries, out_error)) return false;
    complete = true;
    return true;
}

std::optional<OmapValue> SelectOmapLookup(const std::vector<OmapLookupEntry>& entries,
    std::uint64_t object_id, std::uint64_t max_xid, std::string& out_error,
    std::string_view prefix)
{
    const auto after = std::upper_bound(entries.begin(), entries.end(),
        std::make_pair(object_id, max_xid), [](const auto& key, const auto& entry) {
            return key < std::make_pair(entry.object_id, entry.value.xid);
        });
    if (after == entries.begin() || std::prev(after)->object_id != object_id)
    {
        out_error = std::string(prefix) + "ValueMissing";
        return std::nullopt;
    }
    const auto& selected = std::prev(after)->value;
    if (selected.flags == 0xFFFFFFFFu || (selected.flags & 0x1u) != 0 ||
        selected.physical_block == 0)
    {
        out_error = std::string(prefix) + "ValueDeleted";
        return std::nullopt;
    }
    return selected;
}
} // namespace

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
    out.snap_meta_ext_oid = ReadU64LE(block, 0x3E8).value();
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
    std::string& out_error, bool strict_header = false,
    BtreeNodeReadContext* node_context = nullptr, const OmapValue* mapping = nullptr)
{
    struct Release { BtreeNodeReadContext* context; ~Release() { if (context) context->ReleaseNode(); } } release{node_context};
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
    std::span<const std::byte> parsed;
    if (node_context)
    {
        if (!mapping || mapping->physical_block != physical_block || mapping->size != size_bytes ||
            !node_context->ReadMappedNode(expected_object_id,
                {physical_block, mapping->xid, mapping->flags, mapping->size}, true, parsed, out_error) ||
            parsed.size() != size_bytes)
        { if (out_error.empty()) out_error = error_prefix + "ContextReadFailed"; return false; }
    }
    else if (!source.Read(byte_offset, size_bytes, out_bytes) || out_bytes.size() != size_bytes)
    {
        out_error = error_prefix + "Unreadable";
        return false;
    }
    if (!node_context) parsed = out_bytes;
    if (!VerifyObjectChecksum(parsed, size_bytes))
    {
        out_error = error_prefix + "ChecksumInvalid";
        return false;
    }
    const std::uint64_t object_id = ReadU64LE(parsed, 0x08).value_or(0);
    const std::uint64_t xid = ReadU64LE(parsed, 0x10).value_or(
        0xFFFFFFFFFFFFFFFFull);
    const std::uint32_t type = ReadU32LE(parsed, 0x18).value_or(0xFFFFFFFFu);
    const std::uint32_t subtype = ReadU32LE(parsed, 0x1C).value_or(0xFFFFFFFFu);
    if (strict_header && (xid == 0 ||
        (type & ~(kObjectStorageTypeMask | kObjectTypeMask | (node_context ? 0x10000000u : 0u))) != 0))
    { out_error = error_prefix + "UnsupportedObjectFlagsOrZeroXid"; return false; }
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
    std::string& out_error, bool strict_header = false)
{
    out_view = AppleOmapView{};
    std::vector<std::byte> omap_bytes;
    if (!ReadAppleObject(source, block_size, omap_oid, block_size,
            omap_oid, max_xid, kObjectPhysical, kObjectTypeOmap, std::nullopt,
            error_prefix, out_view.object, omap_bytes, out_error, strict_header))
    {
        return false;
    }
    out_view.flags = ReadU32LE(omap_bytes, 0x20).value_or(0);
    out_view.tree_type = ReadU32LE(omap_bytes, 0x28).value_or(0);
    out_view.snapshot_tree_type = ReadU32LE(omap_bytes, 0x2C).value_or(0);
    const std::uint64_t tree_oid = ReadU64LE(omap_bytes, 0x30).value_or(0);
    out_view.snapshot_tree_oid = ReadU64LE(omap_bytes, 0x38).value_or(0);
    if (strict_header && (out_view.object.subtype != 0 || (out_view.flags & ~1u) != 0 ||
        out_view.tree_type != (kObjectPhysical | kObjectTypeBtree) ||
        ReadU64LE(omap_bytes, 0x48).value_or(~0ull) != 0 ||
        ReadU64LE(omap_bytes, 0x50).value_or(~0ull) != 0))
    { out_error = error_prefix + "CryptoOrRevertStateUnsupported"; return false; }

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
        tree_bytes, out_error, strict_header);
}

bool LoadAppleOmapLookup(
    const RandomAccessSource& source,
    std::uint32_t block_size,
    const AppleOmapView& map,
    std::uint64_t max_xid,
    const std::string& error_prefix,
    std::vector<OmapLookupEntry>& entries,
    std::string& out_error,
    std::uint64_t tree_max_xid = 0,
    bool strict_snapshot = false, bool strict_order = false, bool encrypted_metadata = false)
{
    entries.clear();
    out_error.clear();
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
        return false;
    }
    return BuildOmapLookup(source, records, false, strict_snapshot, strict_order,
        tree_max_xid, error_prefix, entries, out_error, encrypted_metadata);
}

std::optional<OmapValue> SelectAppleOmapLookup(const std::vector<OmapLookupEntry>& entries,
    std::uint64_t oid, std::uint64_t max_xid, std::uint32_t block_size,
    const std::string& error_prefix, std::string& out_error)
{
    const auto selected = SelectOmapLookup(entries, oid, max_xid, out_error, error_prefix);
    if (!selected) return std::nullopt;
    if (selected->size < block_size || selected->size % block_size != 0)
    {
        out_error = error_prefix + "ValueSizeInvalid";
        return std::nullopt;
    }
    return selected;
}

std::optional<OmapValue> ResolveAppleOmapValue(
    const RandomAccessSource& source, std::uint32_t block_size,
    const AppleOmapView& map, std::uint64_t oid, std::uint64_t max_xid,
    const std::string& error_prefix, std::string& out_error,
    std::uint64_t tree_max_xid = 0,
    bool strict_snapshot = false, bool strict_order = false, bool encrypted_metadata = false)
{
    std::vector<OmapLookupEntry> entries;
    if (!LoadAppleOmapLookup(source, block_size, map, max_xid, error_prefix,
            entries, out_error, tree_max_xid, strict_snapshot, strict_order, encrypted_metadata)) return std::nullopt;
    return SelectAppleOmapLookup(entries, oid, max_xid, block_size, error_prefix, out_error);
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
    std::string& out_error, bool strict_readonly = false,
    BtreeNodeReadContext* node_context = nullptr, std::uint64_t volume_xid = 0,
    bool encrypted_volume_map = false)
{
    // A declared encrypted/headerless tree is not an ordinary tree even if
    // its referenced bytes happen to contain a valid plaintext object header.
    if (strict_readonly && (tree_type & ~(kObjectStorageTypeMask | kObjectTypeMask)) != 0)
    { out_error = "AppleTreeObjectFlagsUnsupported"; return false; }
    if (tree_oid == 0 || (tree_type & kObjectTypeMask) != kObjectTypeBtree)
    {
        out_error = "AppleTreeTypeInvalid";
        return false;
    }
    const std::uint32_t storage_type = tree_type & kObjectStorageTypeMask;
    std::uint64_t physical_block = 0;
    std::uint32_t object_size = checkpoint.superblock.block_size;
    auto object_max_xid = checkpoint.superblock.xid;
    std::optional<OmapValue> selected_mapping;
    if (node_context && (storage_type != 0 || expected_subtype != kObjectTypeFsTree))
    { out_error = "AppleEncryptedTreeProfileUnsupported"; return false; }
    if (storage_type == kObjectPhysical)
    {
        physical_block = tree_oid;
    }
    else if (storage_type == 0)
    {
        auto mapping = ResolveAppleOmapValue(source, checkpoint.superblock.block_size,
            volume_omap, tree_oid, node_context ? volume_xid : checkpoint.superblock.xid,
            "AppleVolumeOmap", out_error, checkpoint.superblock.xid, strict_readonly, strict_readonly,
            node_context != nullptr || encrypted_volume_map);
        if (!mapping.has_value())
        {
            return false;
        }
        object_max_xid = strict_readonly ? mapping->xid : object_max_xid;
        physical_block = mapping->physical_block;
        object_size = mapping->size;
        selected_mapping = mapping;
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
        physical_block, object_size, tree_oid, object_max_xid,
        storage_type, kObjectTypeBtree, expected_subtype, "AppleTree",
        out_location, tree_bytes, out_error, strict_readonly, node_context,
        selected_mapping ? &*selected_mapping : nullptr);
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

#include "ApfsSpacemanOwnershipParser.inc"

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

bool LoadFusionSpacemanAllocationView(const ApfsFusionStore& store,
    AppleSpacemanView& out_view, std::string& out_error)
{
    BudgetErrorScope budget_error{store, out_error};
    out_view = {};
    FusionSpacemanOwnership geometry;
    if (!LoadFusionSpacemanOwnership(store, geometry, out_error)) return false;
    std::vector<std::byte> anchor;
    if (store.TierAheadSkewTolerated() ||
        !store.Read(0, geometry.block_size, anchor) || anchor != store.Checkpoint().superblock_bytes)
    { out_error = "FusionAllocationCheckpointRebindRequired"; return false; }
    if (!LoadAppleSpacemanOwnershipViewImpl(store, store.Checkpoint(), out_view, out_error, &store) ||
        !store.CheckAvailable(out_error))
    { out_view = {}; return false; }
    return true;
}

bool LoadFusionPlanningAllocation(const ApfsFusionStore& binding,
    const RandomAccessSource& staged, const ContainerCheckpointView& checkpoint,
    AppleSpacemanView& view, std::string& error)
{
    view = {};
    BudgetErrorScope budget_error{staged, error};
    const auto& a = binding.Checkpoint().superblock;
    const auto& b = checkpoint.superblock;
    if (a.uuid_hex != b.uuid_hex || a.fusion_uuid != b.fusion_uuid ||
        a.block_size != b.block_size || a.block_count != b.block_count ||
        a.xp_desc_base_block != b.xp_desc_base_block || a.xp_desc_block_count != b.xp_desc_block_count ||
        a.xp_data_base_block != b.xp_data_base_block || a.xp_data_block_count != b.xp_data_block_count ||
        a.fusion_middle_tree_oid != b.fusion_middle_tree_oid ||
        a.fusion_writeback_start != b.fusion_writeback_start ||
        a.fusion_writeback_blocks != b.fusion_writeback_blocks ||
        !binding.CheckAvailable(error))
    { error = "FusionPlanningGeometryChanged"; return false; }
    if (!LoadAppleSpacemanOwnershipViewImpl(staged, checkpoint, view, error, &binding))
    { view = {}; return false; }
    return true;
}

bool LoadAppleSpacemanRetentionBitmaps(const RandomAccessSource& source,
    const ContainerCheckpointView& checkpoint, AppleSpacemanInternalPoolView& out_pool, std::string& error)
{
    out_pool = {};
    AppleSpacemanView historical;
    const bool complete = LoadAppleSpacemanOwnershipViewImpl(source, checkpoint, historical, error);
    if (!complete && error != "AppleSpacemanCibFutureXid") return false;
    if (const auto budget = source.ReadBudget(); budget && budget->Failed()) return false;
    // CIB validation follows the complete internal-pool geometry, active bitmap
    // and free-list checks. No device ownership/counters escape this boundary.
    out_pool = std::move(historical.internal_pool);
    error.clear();
    return true;
}

namespace
{
enum class InactiveFileExtentAdmission { Opaque, PlainTransition };
std::optional<AppleReadOnlyVolumeView> LoadAppleVolumeViewImpl(
    const RandomAccessSource& source, ContainerCheckpointView checkpoint,
    std::string& out_error, bool strict_readonly, AppleSpacemanView* spaceman,
    const ApsbVolume* encrypted_volume = nullptr, BtreeNodeReadContext* node_context = nullptr,
    InactiveFileExtentAdmission inactive_file_extent = InactiveFileExtentAdmission::Opaque)
{
    BudgetErrorScope budget_error{source, out_error};
    out_error.clear();
    if (checkpoint.checkpoint_map_blocks.empty() || checkpoint.superblock.spaceman_oid == 0 ||
        checkpoint.superblock.xid == 0 || checkpoint.superblock.block_size == 0)
    { out_error = "AppleReadOnlyCheckpointInvalid"; return std::nullopt; }
    AppleReadOnlyVolumeView view;
    view.container = std::move(checkpoint);
    const auto& nxsb = view.container.superblock;
    if (!LoadAppleOmap(source, nxsb.block_size, nxsb.omap_oid, nxsb.xid,
            "AppleContainerOmap", view.container_object_map, out_error, strict_readonly))
    {
        return std::nullopt;
    }

    if (spaceman && !LoadAppleSpacemanOwnershipViewImpl(source, view.container, *spaceman, out_error))
        return std::nullopt;

    std::unordered_set<std::uint64_t> seen_volume_oids;
    for (const std::uint64_t volume_oid : nxsb.fs_oids)
    {
        if (!Materialize(source, 0, sizeof(std::uint64_t))) return std::nullopt;
        if (volume_oid == 0 || !seen_volume_oids.insert(volume_oid).second)
        {
            out_error = "AppleVolumeOidInvalid";
            return std::nullopt;
        }
        auto mapping = ResolveAppleOmapValue(source, nxsb.block_size,
            view.container_object_map, volume_oid, nxsb.xid,
            "AppleContainerOmap", out_error, nxsb.xid, strict_readonly, strict_readonly);
        if (!mapping.has_value())
        {
            return std::nullopt;
        }
        AppleVolumeCheckpointView volume_view;
        std::vector<std::byte> apsb_bytes;
        if (!ReadAppleObject(source, nxsb.block_size, mapping->physical_block,
                mapping->size, volume_oid, strict_readonly ? mapping->xid : nxsb.xid, 0, kObjectTypeFs,
                strict_readonly ? std::optional<std::uint32_t>(0) : std::nullopt, "AppleVolumeSuperblock",
                volume_view.superblock_object, apsb_bytes, out_error, strict_readonly))
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
        if (strict_readonly && (apsb->uuid_hex.empty() || !apsb->name_valid ||
            apsb->xid == 0 || apsb->omap_oid == 0 || apsb->root_oid == 0))
        { out_error = "AppleReadOnlyVolumeIdentityInvalid"; return std::nullopt; }
        volume_view.superblock = std::move(apsb.value());
        const bool encrypted = encrypted_volume && volume_oid == encrypted_volume->object_id;
        if (encrypted && (volume_view.superblock.uuid_hex != encrypted_volume->uuid_hex ||
            volume_view.superblock.xid != encrypted_volume->xid ||
            volume_view.superblock.omap_oid != encrypted_volume->omap_oid ||
            volume_view.superblock.root_oid != encrypted_volume->root_oid ||
            volume_view.superblock.root_tree_type != encrypted_volume->root_tree_type ||
            volume_view.superblock.features != encrypted_volume->features ||
            volume_view.superblock.readonly_features != encrypted_volume->readonly_features ||
            volume_view.superblock.incompatible_features != encrypted_volume->incompatible_features ||
            volume_view.superblock.fext_tree_oid != 0 ||
            volume_view.superblock.fext_tree_type != encrypted_volume->fext_tree_type ||
            ReadU64LE(apsb_bytes, 0x3D0).value_or(~0ULL) != 0 ||
            volume_view.superblock.fs_flags != kFsFlagOneKey))
        { out_error = "AppleEncryptedVolumeBindingMismatch"; return std::nullopt; }
        // Catalog the authoritative APSB even when this readonly reader cannot
        // interpret its filesystem. No encrypted metadata probing or fallback.
        const bool plain_inactive_file_extent = inactive_file_extent == InactiveFileExtentAdmission::PlainTransition &&
            volume_view.superblock.fs_flags == kFsFlagUnencrypted && volume_view.superblock.fext_tree_oid == 0 &&
            volume_view.superblock.fext_tree_type == (kObjectPhysical | kObjectTypeBtree);
        if (strict_readonly && !encrypted && (volume_view.superblock.fs_flags != kFsFlagUnencrypted ||
            (volume_view.superblock.features & ~kVolumeKnownOptionalFeaturesMask) ||
            volume_view.superblock.readonly_features ||
            (volume_view.superblock.incompatible_features & ~kVolumeSupportedIncompatibleFeaturesMask) ||
            volume_view.superblock.fext_tree_oid || (volume_view.superblock.fext_tree_type && !plain_inactive_file_extent)))
        {
            if (!Materialize(source, 1, sizeof(AppleVolumeCheckpointView))) return std::nullopt;
            view.volumes.push_back(std::move(volume_view));
            continue;
        }
        if (!LoadAppleOmap(source, nxsb.block_size, volume_view.superblock.omap_oid,
                nxsb.xid, "AppleVolumeOmap", volume_view.object_map, out_error, strict_readonly))
        {
            return std::nullopt;
        }
        if (!ResolveAppleTreeRoot(source, view.container, volume_view.object_map,
                volume_oid, volume_view.superblock.root_oid,
                volume_view.superblock.root_tree_type, kObjectTypeFsTree,
                volume_view.root_tree, out_error, strict_readonly,
                encrypted ? node_context : nullptr, volume_view.superblock.xid))
        {
            return std::nullopt;
        }
        if (volume_view.superblock.extentref_tree_oid != 0)
        {
            AppleObjectLocation location;
            if (!ResolveAppleTreeRoot(source, view.container, volume_view.object_map,
                    volume_oid, volume_view.superblock.extentref_tree_oid,
                    volume_view.superblock.extentref_tree_type,
                    kObjectTypeBlockRefTree, location, out_error, strict_readonly,
                    nullptr, 0, encrypted))
            {
                return std::nullopt;
            }
            volume_view.extentref_tree = location;
        }
        if (volume_view.superblock.snap_meta_tree_oid != 0)
        {
            AppleObjectLocation location;
            if (!ResolveAppleTreeRoot(source, view.container, volume_view.object_map,
                    volume_oid, volume_view.superblock.snap_meta_tree_oid,
                    volume_view.superblock.snap_meta_tree_type,
                    kObjectTypeSnapMetaTree, location, out_error, strict_readonly,
                    nullptr, 0, encrypted))
            {
                return std::nullopt;
            }
            volume_view.snapshot_metadata_tree = location;
        }
        if (volume_view.superblock.fext_tree_oid != 0)
        {
            AppleObjectLocation location;
            if (!ResolveAppleTreeRoot(source, view.container, volume_view.object_map,
                    volume_oid, volume_view.superblock.fext_tree_oid,
                    volume_view.superblock.fext_tree_type,
                    kObjectTypeFileExtentTree, location, out_error, strict_readonly,
                    nullptr, 0, encrypted))
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
} // namespace

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

    // Ordinary admission retains the complete allocator gate and bounded source.
    AppleSpacemanView spaceman;
    auto readonly = LoadAppleVolumeViewImpl(store, std::move(*checkpoint), out_error, false, &spaceman);
    if (!readonly) return std::nullopt;
    AppleCheckpointView view;
    view.container = std::move(readonly->container);
    view.container_object_map = std::move(readonly->container_object_map);
    view.volumes = std::move(readonly->volumes);
    view.spaceman = std::move(spaceman);
    return view;
}

std::optional<AppleOmapView> LoadAppleContainerObjectMapView(
    const RandomAccessSource& source, const ContainerCheckpointView& checkpoint,
    std::string& out_error)
{
    BudgetErrorScope budget_error{source, out_error};
    out_error.clear();
    const auto& nxsb = checkpoint.superblock;
    if (checkpoint.checkpoint_map_blocks.empty() || nxsb.spaceman_oid == 0 ||
        nxsb.xid == 0 || nxsb.block_size < 4096 || nxsb.block_size > 65536 ||
        (nxsb.block_size & (nxsb.block_size - 1)) != 0 || nxsb.block_count == 0 ||
        nxsb.block_count > source.SizeBytes() / nxsb.block_size)
    { out_error = "AppleReadOnlyCheckpointInvalid"; return std::nullopt; }
    AppleOmapView view;
    if (!LoadAppleOmap(source, nxsb.block_size, nxsb.omap_oid, nxsb.xid,
            "AppleContainerOmap", view, out_error, true)) return std::nullopt;
    return view;
}

std::optional<AppleReadOnlyVolumeView> LoadAppleReadOnlyVolumeView(
    const RandomAccessSource& source, const ContainerCheckpointView& checkpoint,
    std::string& out_error)
{
    BudgetErrorScope budget_error{source, out_error};
    if (!Materialize(source, 1, sizeof(ContainerCheckpointView) + checkpoint.superblock_bytes.size() +
        checkpoint.mappings.size() * sizeof(CheckpointMapping) +
        checkpoint.checkpoint_map_blocks.size() * sizeof(std::uint64_t) +
        checkpoint.superblock.fs_oids.size() * sizeof(std::uint64_t) + 128)) return std::nullopt;
    return LoadAppleVolumeViewImpl(source, checkpoint, out_error, true, nullptr);
}

std::optional<AppleReadOnlyVolumeView> LoadApplePlainTransitionVolumeView(
    const RandomAccessSource& source, const ContainerCheckpointView& checkpoint,
    std::string& out_error)
{
    BudgetErrorScope budget_error{source, out_error};
    if (!Materialize(source, 1, sizeof(ContainerCheckpointView) + checkpoint.superblock_bytes.size() +
        checkpoint.mappings.size() * sizeof(CheckpointMapping) +
        checkpoint.checkpoint_map_blocks.size() * sizeof(std::uint64_t) +
        checkpoint.superblock.fs_oids.size() * sizeof(std::uint64_t) + 128)) return std::nullopt;
    auto view = LoadAppleVolumeViewImpl(source, checkpoint, out_error, true, nullptr, nullptr, nullptr,
        InactiveFileExtentAdmission::PlainTransition);
    if (view && (view->volumes.size() != 1 || view->volumes.front().superblock.fs_flags != kFsFlagUnencrypted ||
        !view->volumes.front().root_tree.object_id))
    { out_error = "ApplePlainTransitionVolumeProfileUnsupported"; return std::nullopt; }
    return view;
}

std::optional<AppleCheckpointView> AppleEncryptedMetadataReadContext::LoadCanonical(
    const RandomAccessSource& source, const ContainerCheckpointView& checkpoint,
    const ApsbVolume& volume, BtreeNodeReadContext& nodes, std::string& error, bool load_allocator)
{
    AppleSpacemanView spaceman;
    auto loaded = LoadAppleVolumeViewImpl(source, checkpoint, error, true,
        load_allocator ? &spaceman : nullptr, &volume, &nodes);
    if (!loaded) return {};
    for (const auto& item : loaded->volumes)
        if (!item.root_tree.object_id)
        { error = "AppleEncryptedOtherVolumeProfileUnsupported"; return {}; }
    AppleCheckpointView result;
    result.container = std::move(loaded->container);
    result.container_object_map = std::move(loaded->container_object_map);
    result.volumes = std::move(loaded->volumes);
    result.spaceman = std::move(spaceman);
    return result;
}

namespace
{
enum class SnapshotMetadataAdmission { Strict, ReadOnlyInactiveTreeDefaults, EncryptedReadOnly };
using SnapshotNodeFactory = std::function<std::unique_ptr<BtreeNodeReadContext>(
    const AppleVolumeCheckpointView&, std::uint64_t, std::string&)>;

void WipeSnapshotRecords(std::vector<BtreeRecord>& records)
{
    for (auto& record : records)
        for (auto* bytes : {&record.key, &record.value})
            for (auto& byte : *bytes) { volatile auto* p = &byte; *p = std::byte{0}; }
    records.clear();
}
struct SnapshotRecordGuard
{
    bool sensitive;
    std::vector<BtreeRecord>& records;
    ~SnapshotRecordGuard() { if (sensitive) WipeSnapshotRecords(records); }
};
struct SnapshotCatalogGuard
{
    bool sensitive;
    AppleSnapshotCatalogRecords& catalog;
    ~SnapshotCatalogGuard()
    {
        if (!sensitive) return;
        WipeSnapshotRecords(catalog.live.filesystem);
        for (auto& tree : catalog.snapshots) WipeSnapshotRecords(tree.filesystem);
    }
};

BtreeRoutingPolicy SnapshotFileSystemRouting(const RandomAccessSource& source, const ApsbVolume& volume)
{
    const auto order = rw::ApfsNamePolicy::FromIncompatibleFeatures(volume.incompatible_features).UsesHashedDirectoryKeys()
        ? rw::AppleBtreeKeyOrder::FileSystemHashedDirectory : rw::AppleBtreeKeyOrder::FileSystemCaseSensitive;
    return {[&source, order](const auto& left, const auto& right, std::string& detail) -> std::optional<int> {
        if (!Materialize(source, 2, 2 * sizeof(BtreeRecord) + left.size() + right.size()))
        { detail = source.ReadBudget()->Failure(); return {}; }
        std::vector<BtreeRecord> keys(2);
        SnapshotRecordGuard clear{true, keys};
        keys[0].key = left; keys[1].key = right;
        if (!rw::SortAppleBtreeRecords(keys, order, detail))
        {
            if (detail != "AppleBtreeDuplicateKey") return {};
            detail.clear(); return 0;
        }
        return keys.front().key == left ? -1 : 1;
    }};
}

bool SnapshotVolumeSupported(const std::vector<std::byte>& bytes,
    const ApsbVolume& volume, std::string& error,
    SnapshotMetadataAdmission admission = SnapshotMetadataAdmission::Strict)
{
    if (volume.uuid_hex.empty() || !volume.name_valid || volume.xid == 0)
    {
        error = "SnapshotVolumeIdentityInvalid";
        return false;
    }
    if (volume.fs_flags != (admission == SnapshotMetadataAdmission::EncryptedReadOnly ? kFsFlagOneKey : kFsFlagUnencrypted) ||
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
        volume.fext_tree_oid != 0 || ReadU64LE(bytes, 0x418).value_or(~0ull) != 0)
    {
        error = "SnapshotVolumeStateOrReservedFieldsUnsupported";
        return false;
    }
    if (admission == SnapshotMetadataAdmission::EncryptedReadOnly)
        return CheckAppleReadOnlyOneKeyInactiveTreeDefaults(bytes, volume, error);
    if (admission == SnapshotMetadataAdmission::ReadOnlyInactiveTreeDefaults)
        return CheckAppleReadOnlyInactiveTreeDefaults(bytes, volume, error);
    if (volume.fext_tree_type != 0 || ReadU32LE(bytes, 0x414).value_or(~0u) != 0)
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

bool AppendSnapshotOwner(const RandomAccessSource& source,
    std::vector<AppleSnapshotMetadataClaim>* owners, std::uint64_t volume_oid,
    std::uint64_t map_oid, std::uint64_t view_xid, std::uint64_t selection_xid,
    const AppleObjectLocation& object, AppleSnapshotMetadataClass metadata_class,
    std::optional<std::uint64_t> mapping_xid = std::nullopt)
{
    if (!owners) return true;
    if (!Materialize(source, 1, sizeof(AppleSnapshotMetadataClaim))) return false;
    owners->push_back({volume_oid, map_oid, view_xid, selection_xid,
        object.object_id, object.xid, object.physical_block, 1,
        object.type, object.subtype, mapping_xid, metadata_class});
    return true;
}

// Reuse the authoritative tree reader, including its cycle, region, checksum,
// identity, and shared resource-budget checks. Virtual child lookup is pinned
// to the snapshot XID while the OMAP itself belongs to the selected checkpoint.
bool ReadSnapshotTree(const RandomAccessSource& source, std::uint32_t block_size,
    const AppleObjectLocation& tree, const AppleOmapView& omap,
    std::uint64_t tree_xid, std::uint64_t checkpoint_xid,
    std::vector<BtreeRecord>& records, std::string& error, bool strict_omap_order = false,
    std::vector<std::uint64_t>* metadata_blocks = nullptr,
    std::vector<std::uint64_t>* exact_blocks = nullptr,
    std::vector<AppleSnapshotMetadataClaim>* owners = nullptr,
    std::uint64_t owner_volume = 0, std::uint64_t view_xid = 0,
    AppleSnapshotMetadataClass metadata_class = AppleSnapshotMetadataClass::FileSystemNode,
    BtreeNodeReadContext* node_context = nullptr, const BtreeRoutingPolicy& routing = {},
    bool encrypted_volume_map = false)
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
    std::vector<std::uint64_t> visited;
    if (metadata_blocks || exact_blocks) policy.visited_physical_blocks = &visited;
    policy.storage_type = storage;
    policy.subtype = tree.subtype;
    std::optional<std::vector<OmapLookupEntry>> child_omap;
    policy.virtual_child_resolver = [&](std::uint64_t oid, std::string& child_error)
        -> std::optional<BtreeVirtualChildMapping> {
        if (!child_omap)
        {
            child_omap.emplace();
            if (!LoadAppleOmapLookup(source, block_size, omap, tree_xid,
                    "SnapshotChildOmap", *child_omap, child_error, checkpoint_xid,
                    true, strict_omap_order, node_context != nullptr || encrypted_volume_map)) return std::nullopt;
        }
        const auto value = SelectAppleOmapLookup(*child_omap, oid, tree_xid,
            block_size, "SnapshotChildOmap", child_error);
        if (!value) return std::nullopt;
        if (encrypted_volume_map && !node_context && (value->flags & 4u) != 0)
        { child_error = "SnapshotPlainMetadataMappingFlagsUnsupported"; return std::nullopt; }
        if (value->size != block_size)
        {
            child_error = "SnapshotMultiBlockNodeUnsupported";
            return std::nullopt;
        }
        return BtreeVirtualChildMapping{value->physical_block, value->xid, value->flags, value->size};
    };
    std::optional<std::uint64_t> root_mapping_xid;
    if (owners && storage == 0)
    {
        const auto root = policy.virtual_child_resolver(tree.object_id, error);
        if (!root) return false;
        if (root->physical_block != tree.physical_block || tree.xid > root->xid)
        { error = "SnapshotOwnerRootMappingIdentityMismatch"; return false; }
        root_mapping_xid = root->xid;
    }
    std::vector<BtreeNodeIdentity> identities;
    if (!ReadBtreeLeafRecordsImpl(source, block_size, tree.physical_block,
        storage == kObjectPhysical, omap.object.object_id, tree_xid,
        policy, routing, records, error, node_context,
        owners ? &identities : nullptr, root_mapping_xid, encrypted_volume_map && node_context)) return false;
    for (const auto& node : identities)
    {
        AppleObjectLocation object{node.object_id, node.xid, node.physical_block,
            node.type, node.subtype, block_size};
        if (!AppendSnapshotOwner(source, owners, owner_volume, omap.object.object_id,
            view_xid, tree_xid, object, metadata_class, node.mapping_xid)) return false;
    }
    if (metadata_blocks) {
        if (!Materialize(source, visited.size(), visited.size() * sizeof(std::uint64_t))) return false;
        metadata_blocks->insert(metadata_blocks->end(), visited.begin(), visited.end());
    }
    if (exact_blocks) *exact_blocks = std::move(visited);
    return true;
}

bool SnapshotOmapSupported(const RandomAccessSource& source, std::uint32_t block_size,
    const AppleOmapView& map, std::uint64_t checkpoint_xid,
    bool container, std::vector<std::uint64_t>& snapshot_xids, std::string& error,
    std::vector<std::uint64_t>* metadata_blocks = nullptr,
    std::vector<AppleSnapshotMetadataClaim>* owners = nullptr,
    std::uint64_t owner_volume = 0, std::uint64_t view_xid = 0,
    bool encrypted_volume_map = false)
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
        "SnapshotOmap", scan_error, checkpoint_xid, true, encrypted_volume_map, encrypted_volume_map);
    if (!scan_error.empty() && scan_error != "SnapshotOmapValueMissing")
    {
        error = scan_error;
        return false;
    }
    if (metadata_blocks) {
        if (!Materialize(source, 1, sizeof(std::uint64_t))) return false;
        metadata_blocks->push_back(map.object.physical_block);
        if (!AppendSnapshotOwner(source, owners, owner_volume, map.object.object_id,
            view_xid, checkpoint_xid, map.object, AppleSnapshotMetadataClass::OmapObject)) return false;
        std::vector<BtreeRecord> map_records;
        if (!ReadSnapshotTree(source, block_size, map.tree, map, checkpoint_xid,
            checkpoint_xid, map_records, error, true, metadata_blocks, nullptr,
            owners, owner_volume, view_xid, AppleSnapshotMetadataClass::OmapNode)) return false;
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
        checkpoint_xid, records, error, false, metadata_blocks, nullptr,
        owners, owner_volume, view_xid, AppleSnapshotMetadataClass::OmapSnapshotNode)) return false;
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

bool ReadAppleVolumeFileSystemRecords(const RandomAccessSource& source,
    const ContainerCheckpointView& checkpoint, const AppleVolumeCheckpointView& volume,
    std::vector<BtreeRecord>& records, std::string& error)
{
    records.clear();
    return ReadSnapshotTree(source, checkpoint.superblock.block_size, volume.root_tree,
        volume.object_map, checkpoint.superblock.xid, checkpoint.superblock.xid, records, error, true);
}

bool AppleEncryptedMetadataReadContext::ReadCanonical(const RandomAccessSource& source,
    const ContainerCheckpointView& checkpoint, const AppleVolumeCheckpointView& volume,
    BtreeNodeReadContext& nodes, std::vector<BtreeRecord>& records, std::string& error)
{
    // Re-resolve all supplied locations on the original source before parsing.
    auto loaded = LoadAppleVolumeViewImpl(source, checkpoint, error, true, nullptr, &volume.superblock, &nodes);
    if (!loaded) return false;
    const auto found = std::find_if(loaded->volumes.begin(), loaded->volumes.end(), [&](const auto& item) {
        return item.superblock.object_id == volume.superblock.object_id;
    });
    const auto same = [](const AppleObjectLocation& a, const AppleObjectLocation& b) {
        return a.object_id == b.object_id && a.xid == b.xid && a.physical_block == b.physical_block &&
            a.type == b.type && a.subtype == b.subtype && a.size_bytes == b.size_bytes;
    };
    if (found == loaded->volumes.end() || !same(found->root_tree, volume.root_tree) ||
        !same(found->superblock_object, volume.superblock_object) ||
        !same(found->object_map.object, volume.object_map.object) || !same(found->object_map.tree, volume.object_map.tree))
    { error = "AppleEncryptedTreeBindingMismatch"; return false; }
    const auto routing = SnapshotFileSystemRouting(source, found->superblock);
    return ReadSnapshotTree(source, checkpoint.superblock.block_size, found->root_tree,
        found->object_map, found->superblock.xid, checkpoint.superblock.xid, records, error, true,
        nullptr, nullptr, nullptr, 0, 0, AppleSnapshotMetadataClass::FileSystemNode, &nodes, routing);
}

bool LoadAppleSnapshotRecords(const RandomAccessSource& source,
    const AppleCheckpointView& checkpoint, std::uint64_t volume_oid,
    std::vector<AppleSnapshotRecord>& out_records, std::string& out_error)
{
    AppleSnapshotTreeRecords ignored;
    return LoadAppleSnapshotRecords(source, checkpoint, volume_oid,
        out_records, out_error, 0, ignored);
}

static bool LoadAppleSnapshotRecordsImpl(const RandomAccessSource& source,
    const AppleCheckpointView& checkpoint, std::uint64_t volume_oid,
    std::vector<AppleSnapshotRecord>& out_records, std::string& out_error,
    std::uint64_t exact_snapshot_xid, AppleSnapshotTreeRecords& out_trees,
    AppleSnapshotCatalogRecords* out_catalog, std::uint64_t descriptor_block = 0,
    std::uint64_t filesystem_xid = 0,
    std::vector<AppleSnapshotMetadataClaim>* out_owners = nullptr,
    SnapshotMetadataAdmission admission = SnapshotMetadataAdmission::Strict,
    const SnapshotNodeFactory& node_factory = {}, const ApfsFusionStore* fusion = nullptr)
{
    BudgetErrorScope budget_error{source, out_error};
    out_records.clear();
    out_trees = {};
    AppleSnapshotTreeRecords selected_trees;
    SnapshotRecordGuard clear_selected{admission == SnapshotMetadataAdmission::EncryptedReadOnly, selected_trees.filesystem};
    AppleSnapshotCatalogRecords catalog;
    const bool encrypted = admission == SnapshotMetadataAdmission::EncryptedReadOnly;
    SnapshotCatalogGuard clear_catalog{encrypted, catalog};
    std::vector<AppleSnapshotMetadataClaim> owner_claims;
    auto* owners = out_owners ? &owner_claims : nullptr;
    if (out_owners) out_owners->clear();
    auto* footprint = out_catalog ? &catalog.metadata_blocks : exact_snapshot_xid ? &selected_trees.metadata_blocks : nullptr;
    bool selected = false;
    out_error.clear();
    const auto fail = [&](const char* reason) { out_error = reason; return false; };
    const auto& nx = checkpoint.container.superblock;
    if (encrypted && (!node_factory || descriptor_block || nx.block_size != 4096))
        return fail("SnapshotEncryptedContextProfileUnsupported");
    if (fusion && (&source != static_cast<const RandomAccessSource*>(fusion) || encrypted || descriptor_block || !nx.block_size ||
        admission != SnapshotMetadataAdmission::ReadOnlyInactiveTreeDefaults ||
        nx.incompatible_features != (kNxIncompatFusion | kNxSupportedIncompatibleFeaturesMask) ||
        nx.block_size != fusion->Checkpoint().superblock.block_size ||
        nx.block_count != fusion->CapacityBytes() / nx.block_size))
        return fail("SnapshotFusionBoundProfileUnsupported");
    if (nx.block_size == 0 || nx.block_count > source.SizeBytes() / nx.block_size ||
        nx.xid == 0 || (nx.features & ~kNxKnownOptionalFeaturesMask) != 0 ||
        nx.readonly_features != 0 ||
        (nx.incompatible_features & ~(kNxSupportedIncompatibleFeaturesMask | (fusion ? kNxIncompatFusion : 0))) != 0)
        return fail("SnapshotContainerGeometryOrFeaturesUnsupported");
    if ((ReadU32LE(checkpoint.container.superblock_bytes, 0x18).value_or(~0u) &
            ~(kObjectStorageTypeMask | kObjectTypeMask)) != 0 ||
        ReadU32LE(checkpoint.container.superblock_bytes, 0x1C).value_or(~0u) != 0)
        return fail("SnapshotContainerObjectFlagsUnsupported");
    // Ordinary stores are contiguous. The explicit Fusion store instead keeps
    // its encoded span and checks each read against the two real member windows.
    OffsetRandomAccessSource ordinary_store(&source, 0, nx.block_count * nx.block_size);
    const RandomAccessSource& store = fusion ? source : ordinary_store;
    const AppleVolumeCheckpointView* live = nullptr;
    for (const auto& volume : checkpoint.volumes)
        if (volume.superblock.object_id == volume_oid)
        {
            if (live) return fail("SnapshotVolumeAmbiguous");
            live = &volume;
        }
    if (!live) return fail("SnapshotVolumeMissing");
    std::vector<std::byte> bytes;
    AppleVolumeCheckpointView descriptor;
    if (descriptor_block) {
        if (!filesystem_xid || filesystem_xid > nx.xid ||
            !ReadAppleObject(store, nx.block_size, descriptor_block, nx.block_size, descriptor_block,
                nx.xid, kObjectPhysical, kObjectTypeFs, 0, "SnapshotDescriptorApsb",
                descriptor.superblock_object, bytes, out_error)) return false;
        const auto apsb = ParseApsb(bytes);
        if (!apsb || apsb->uuid_hex != live->superblock.uuid_hex || apsb->xid < filesystem_xid ||
            descriptor.superblock_object.type != (kObjectPhysical | kObjectTypeFs))
            return fail("SnapshotDescriptorIdentityMismatch");
        descriptor.superblock = *apsb;
        const auto descriptor_snapshot_count = ReadU64LE(bytes, 0xD8).value_or(~0ull);
        if (!SnapshotVolumeSupported(bytes, *apsb, out_error, admission) ||
            !LoadAppleOmap(store, nx.block_size, apsb->omap_oid, nx.xid,
                "SnapshotDescriptorOmap", descriptor.object_map, out_error)) return false;
        const auto root = [&](std::uint64_t oid, std::uint32_t type, std::uint32_t subtype,
                std::uint64_t selection, AppleObjectLocation& location) {
            auto block = oid, mapping_xid = selection;
            if (type == kObjectTypeBtree) {
                const auto mapping = ResolveAppleOmapValue(store, nx.block_size, descriptor.object_map,
                    oid, selection, "SnapshotDescriptorRootOmap", out_error, nx.xid, true);
                if (!mapping) return false;
                if (mapping->size != nx.block_size) return fail("SnapshotMultiBlockNodeUnsupported");
                block = mapping->physical_block; mapping_xid = mapping->xid;
            } else if (type != (kObjectPhysical | kObjectTypeBtree))
                return fail("SnapshotDescriptorTreeTypeUnsupported");
            return ReadAppleObject(store, nx.block_size, block, nx.block_size, oid, mapping_xid,
                type, kObjectTypeBtree, subtype, "SnapshotDescriptorTree", location, bytes, out_error);
        };
        AppleObjectLocation extent, inventory;
        if (!root(apsb->root_oid, apsb->root_tree_type, kObjectTypeFsTree, filesystem_xid, descriptor.root_tree) ||
            !root(apsb->extentref_tree_oid, apsb->extentref_tree_type, kObjectTypeBlockRefTree, apsb->xid, extent)) return false;
        descriptor.extentref_tree = extent;
        if (apsb->snap_meta_tree_oid) {
            if (!root(apsb->snap_meta_tree_oid, apsb->snap_meta_tree_type, kObjectTypeSnapMetaTree, apsb->xid, inventory)) return false;
            descriptor.snapshot_metadata_tree = inventory;
        } else if (descriptor_snapshot_count != 0)
            return fail("SnapshotMetadataRootMissing");
        live = &descriptor;
    }
    const auto fs_xid = descriptor_block ? filesystem_xid : encrypted ? live->superblock.xid : nx.xid;
    const auto descriptor_xid = descriptor_block ? descriptor.superblock.xid : nx.xid;
    AppleObjectLocation live_location;
    if (!ReadAppleObject(store, nx.block_size, live->superblock_object.physical_block,
        nx.block_size, descriptor_block ? descriptor_block : volume_oid, nx.xid,
        descriptor_block ? kObjectPhysical : 0, kObjectTypeFs, 0,
        "SnapshotLiveApsb", live_location, bytes, out_error)) return false;
    if (live_location.type != (descriptor_block ? kObjectPhysical | kObjectTypeFs : kObjectTypeFs) ||
        !SnapshotVolumeSupported(bytes, live->superblock, out_error, admission))
        return out_error.empty() ? fail("SnapshotLiveApsbFlagsUnsupported") : false;
    // Apple wrapped_meta_crypto_state_t is the 20-byte descriptor before the
    // root-tree type. This read-only capability supports only its parent's era.
    std::array<std::byte, 0x14> metadata_crypto{};
    if (encrypted) std::copy_n(bytes.begin() + 0x60, metadata_crypto.size(), metadata_crypto.begin());
    if (owners)
    {
        const auto mapping = ResolveAppleOmapValue(store, nx.block_size, checkpoint.container_object_map,
            volume_oid, nx.xid, "SnapshotOwnerLiveApsbOmap", out_error, nx.xid, true);
        if (!mapping) return false;
        if (mapping->physical_block != live_location.physical_block || mapping->size != nx.block_size ||
            live_location.xid > mapping->xid)
            return fail("SnapshotOwnerLiveApsbMappingIdentityMismatch");
        if (!AppendSnapshotOwner(source, owners, volume_oid, checkpoint.container_object_map.object.object_id,
            nx.xid, nx.xid, live_location, AppleSnapshotMetadataClass::VolumeSuperblock, mapping->xid)) return false;
    }
    if (footprint) {
        if (!Materialize(source, 1, sizeof(std::uint64_t))) return false;
        footprint->push_back(live_location.physical_block);
    }
    const auto count = ReadU64LE(bytes, 0xD8).value();
    std::vector<std::uint64_t> ignored, live_omap_xids;
    if (!SnapshotOmapSupported(store, nx.block_size, checkpoint.container_object_map,
        nx.xid, true, ignored, out_error, footprint, owners, 0, nx.xid) ||
        !SnapshotOmapSupported(store, nx.block_size, live->object_map,
        nx.xid, false, live_omap_xids, out_error, footprint, owners, volume_oid, nx.xid, encrypted)) return false;
    if ((!live->snapshot_metadata_tree || live->superblock.snap_meta_tree_oid == 0) &&
        (count != 0 || (!descriptor_block && admission == SnapshotMetadataAdmission::Strict) ||
            live->snapshot_metadata_tree || live->superblock.snap_meta_tree_oid || !live_omap_xids.empty()))
        return fail("SnapshotMetadataRootMissing");
    if (live->snapshot_metadata_tree && live->superblock.snap_meta_tree_type != live->snapshot_metadata_tree->type)
        return fail("SnapshotMetadataTreeTypeMismatch");
    std::vector<BtreeRecord> records;
    SnapshotRecordGuard clear_records{encrypted, records};
    if ((live->superblock.root_tree_type | (encrypted ? 0x10000000u : 0u)) != live->root_tree.type || !live->extentref_tree ||
        live->superblock.extentref_tree_type != live->extentref_tree->type)
        return fail("SnapshotLiveRootMissingOrTypeMismatch");
    std::unique_ptr<BtreeNodeReadContext> live_nodes;
    auto live_tree = live->root_tree;
    if (encrypted)
    {
        live_nodes = node_factory(*live, fs_xid, out_error);
        if (!live_nodes || !ResolveAppleTreeRoot(store, checkpoint.container, live->object_map, volume_oid,
            live->superblock.root_oid, live->superblock.root_tree_type, kObjectTypeFsTree,
            live_tree, out_error, true, live_nodes.get(), fs_xid)) return false;
    }
    if (!ReadSnapshotTree(store, nx.block_size, live_tree, live->object_map,
        fs_xid, nx.xid, records, out_error, false, footprint,
        out_catalog ? &catalog.live.filesystem_blocks : nullptr,
        owners, volume_oid, nx.xid, AppleSnapshotMetadataClass::FileSystemNode, live_nodes.get(),
        encrypted ? SnapshotFileSystemRouting(source, live->superblock) : BtreeRoutingPolicy{}, encrypted)) return false;
    if (out_catalog) catalog.live.filesystem = std::move(records);
    else if (encrypted) WipeSnapshotRecords(records);
    if (!ReadSnapshotTree(store, nx.block_size, *live->extentref_tree, live->object_map,
        descriptor_xid, nx.xid, records, out_error, false, footprint,
        out_catalog ? &catalog.live.extentref_blocks : nullptr,
        owners, volume_oid, nx.xid, AppleSnapshotMetadataClass::ExtentReferenceNode, nullptr, {}, encrypted)) return false;
    if (out_catalog) catalog.live.extentref = std::move(records);
    records.clear();
    if (live->snapshot_metadata_tree && !ReadSnapshotTree(store, nx.block_size, *live->snapshot_metadata_tree,
        live->object_map, descriptor_xid, nx.xid, records, out_error, false, footprint, nullptr,
        owners, volume_oid, nx.xid, AppleSnapshotMetadataClass::SnapshotInventoryNode, nullptr, {}, encrypted)) return false;
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
            if (item.record.xid == 0 || item.record.xid > descriptor_xid ||
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
        (!descriptor_block && live_omap_xids.size() != parsed.size())) return fail("SnapshotInventoryCountMismatch");
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
        // Deletion can COW reference metadata without changing the file view.
        if (!apsb || apsb->xid < snapshot.xid || apsb->uuid_hex != live->superblock.uuid_hex ||
            snapshot.volume.superblock_object.type != (kObjectPhysical | kObjectTypeFs))
            return fail("SnapshotApsbIdentityMismatch");
        if (encrypted && !std::equal(metadata_crypto.begin(), metadata_crypto.end(), bytes.begin() + 0x60))
            return fail("SnapshotMetadataCryptoStateChanged");
        if (!SnapshotVolumeSupported(bytes, *apsb, out_error, admission)) return false;
        snapshot.volume.superblock = *apsb;
        if (!AppendSnapshotOwner(source, owners, volume_oid, apsb->omap_oid,
            snapshot.xid, nx.xid, snapshot.volume.superblock_object,
            AppleSnapshotMetadataClass::VolumeSuperblock)) return false;
        if (footprint) {
            if (!Materialize(source, 1, sizeof(std::uint64_t))) return false;
            footprint->push_back(snapshot.volume.superblock_object.physical_block);
        }
        if (apsb->extentref_tree_oid != item.extent || apsb->extentref_tree_type != item.extent_type)
            return fail("SnapshotExtentRootIdentityMismatch");
        if (!LoadAppleOmap(store, nx.block_size, apsb->omap_oid, nx.xid,
            "SnapshotApsbOmap", snapshot.volume.object_map, out_error)) return false;
        if (!SnapshotOmapSupported(store, nx.block_size, snapshot.volume.object_map,
            nx.xid, false, ignored, out_error, footprint, owners, volume_oid, snapshot.xid, encrypted)) return false;
        std::unique_ptr<BtreeNodeReadContext> snapshot_nodes;
        if (encrypted)
        {
            snapshot_nodes = node_factory(snapshot.volume, snapshot.xid, out_error);
            if (!snapshot_nodes || !ResolveAppleTreeRoot(store, checkpoint.container, snapshot.volume.object_map, volume_oid,
                apsb->root_oid, apsb->root_tree_type, kObjectTypeFsTree, snapshot.volume.root_tree,
                out_error, true, snapshot_nodes.get(), snapshot.xid)) return false;
        }
        else
        {
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
        }
        AppleObjectLocation extent;
        if (!ReadAppleObject(store, nx.block_size, item.extent, nx.block_size,
            item.extent, apsb->xid, kObjectPhysical, kObjectTypeBtree,
            kObjectTypeBlockRefTree, "SnapshotExtentTree", extent, bytes, out_error)) return false;
        snapshot.volume.extentref_tree = extent;
        // Validate complete referenced trees now; no validated descriptor may
        // hide a malformed/cyclic child behind a superficially valid root.
        AppleSnapshotTreeRecords snapshot_trees;
        SnapshotRecordGuard clear_snapshot{encrypted, snapshot_trees.filesystem};
        auto* captured = out_catalog ? &snapshot_trees : snapshot.xid == exact_snapshot_xid ? &selected_trees : nullptr;
        if (!ReadSnapshotTree(store, nx.block_size, snapshot.volume.root_tree,
            snapshot.volume.object_map, snapshot.xid, nx.xid, records, out_error, false, footprint,
            captured ? &captured->filesystem_blocks : nullptr,
            owners, volume_oid, snapshot.xid, AppleSnapshotMetadataClass::FileSystemNode, snapshot_nodes.get(),
            encrypted ? SnapshotFileSystemRouting(source, *apsb) : BtreeRoutingPolicy{}, encrypted)) return false;
        if (snapshot.xid == exact_snapshot_xid)
        {
            selected = true;
        }
        if (captured) captured->filesystem = std::move(records);
        else if (encrypted) WipeSnapshotRecords(records);
        if (!ReadSnapshotTree(store, nx.block_size, extent, snapshot.volume.object_map,
            apsb->xid, nx.xid, records, out_error, false, footprint,
            captured ? &captured->extentref_blocks : nullptr,
            owners, volume_oid, snapshot.xid, AppleSnapshotMetadataClass::ExtentReferenceNode, nullptr, {}, encrypted)) return false;
        if (captured) captured->extentref = std::move(records);
        if (out_catalog) {
            if (!Materialize(source, 1, sizeof(AppleSnapshotTreeRecords))) return false;
            catalog.snapshots.push_back(std::move(snapshot_trees));
        }
        if (!Materialize(source, 1, sizeof(AppleSnapshotRecord))) return false;
        result.push_back(std::move(snapshot));
    }
    if (exact_snapshot_xid != 0 && !selected) return fail("SnapshotExactXidMissing");
    if (footprint) {
        std::sort(footprint->begin(), footprint->end());
        footprint->erase(std::unique(footprint->begin(), footprint->end()), footprint->end());
    }
    out_records = std::move(result);
    out_trees = std::move(selected_trees);
    if (out_catalog) *out_catalog = std::move(catalog);
    if (out_owners) *out_owners = std::move(owner_claims);
    return true;
}

bool AppleEncryptedSnapshotReadContext::LoadCatalogCanonical(const RandomAccessSource& source,
    const AppleCheckpointView& checkpoint, std::uint64_t volume_oid, AppleEncryptedSnapshotReadContext& context,
    AppleSnapshotCatalogRecords& output, std::vector<AppleSnapshotMetadataClaim>& owners, std::string& error)
{
    AppleSnapshotTreeRecords ignored;
    std::vector<AppleSnapshotRecord> inventory;
    const SnapshotNodeFactory factory = [&](const AppleVolumeCheckpointView& volume, std::uint64_t selection, std::string& detail) {
        return context.CreateCanonicalNodeReader(source, checkpoint.container, volume, selection, detail);
    };
    if (!LoadAppleSnapshotRecordsImpl(source, checkpoint, volume_oid, inventory, error, 0, ignored,
        &output, 0, 0, &owners, SnapshotMetadataAdmission::EncryptedReadOnly, factory)) return false;
    output.inventory = std::move(inventory);
    return true;
}

std::optional<OmapValue> AppleEncryptedSnapshotReadContext::ResolveCanonicalMapping(const RandomAccessSource& source,
    const ContainerCheckpointView& checkpoint, const AppleVolumeCheckpointView& volume,
    std::uint64_t selection, std::uint64_t oid, std::string& error)
{
    const auto mapping = ResolveAppleOmapValue(source, checkpoint.superblock.block_size, volume.object_map,
        oid, selection, "SnapshotEncryptedFsOmap", error, checkpoint.superblock.xid, true, true, true);
    if (!mapping) return {};
    if (mapping->flags != 4 || mapping->size != 4096 || !mapping->xid || mapping->xid > selection ||
        mapping->physical_block >= checkpoint.superblock.block_count)
    { error = "SnapshotEncryptedFsMappingUnsupported"; return {}; }
    return mapping;
}

bool LoadAppleFusionReadOnlySnapshotCatalog(const ApfsFusionStore& source,
    std::uint64_t exact_checkpoint_xid, std::uint64_t volume_oid, const std::string& volume_uuid_hex,
    AppleSnapshotCatalogRecords& output, std::vector<AppleSnapshotMetadataClaim>& owners, std::string& error)
{
    output = {}; owners.clear(); error.clear();
    BudgetErrorScope budget_error{source, error};
    const auto& bound = source.Checkpoint().superblock;
    if (!exact_checkpoint_xid || exact_checkpoint_xid > bound.xid || !volume_oid || volume_uuid_hex.empty() ||
        !source.CheckAvailable(error))
    { if (error.empty()) error = "SnapshotFusionExactSelectionRequired"; return false; }
    auto checkpoint = LoadContainerCheckpointView(source, 0, source.CapacityBytes(), error, exact_checkpoint_xid);
    if (!checkpoint) return false;
    const auto& nx = checkpoint->superblock;
    if (nx.uuid_hex != bound.uuid_hex || nx.fusion_uuid != bound.fusion_uuid ||
        nx.block_size != bound.block_size || nx.block_count != bound.block_count ||
        nx.xp_desc_base_block != bound.xp_desc_base_block || nx.xp_desc_block_count != bound.xp_desc_block_count ||
        nx.xp_data_base_block != bound.xp_data_base_block || nx.xp_data_block_count != bound.xp_data_block_count ||
        nx.fusion_middle_tree_oid != bound.fusion_middle_tree_oid || nx.fusion_writeback_start != bound.fusion_writeback_start ||
        nx.fusion_writeback_blocks != bound.fusion_writeback_blocks ||
        (nx.xid == bound.xid && checkpoint->superblock_bytes != source.Checkpoint().superblock_bytes))
    { error = "SnapshotFusionCheckpointBindingMismatch"; return false; }
    auto read = LoadAppleReadOnlyVolumeView(source, std::move(*checkpoint), error);
    if (!read) return false;
    const auto matches = std::count_if(read->volumes.begin(), read->volumes.end(), [&](const auto& volume) {
        return volume.superblock.object_id == volume_oid && volume.superblock.uuid_hex == volume_uuid_hex;
    });
    if (matches != 1 || std::count_if(read->volumes.begin(), read->volumes.end(), [&](const auto& volume) {
        return volume.superblock.uuid_hex == volume_uuid_hex;
    }) != 1) { error = "SnapshotFusionVolumeBindingMismatch"; return false; }
    AppleCheckpointView canonical;
    canonical.container = std::move(read->container); canonical.container_object_map = std::move(read->container_object_map);
    canonical.volumes = std::move(read->volumes);
    AppleSnapshotCatalogRecords result;
    std::vector<AppleSnapshotRecord> inventory;
    AppleSnapshotTreeRecords unused;
    std::vector<AppleSnapshotMetadataClaim> claims;
    if (!LoadAppleSnapshotRecordsImpl(source, canonical, volume_oid, inventory, error, 0, unused, &result,
        0, 0, &claims, SnapshotMetadataAdmission::ReadOnlyInactiveTreeDefaults, {}, &source) ||
        !source.CheckAvailable(error)) return false;
    result.inventory = std::move(inventory);
    output = std::move(result); owners = std::move(claims);
    return true;
}

bool LoadAppleSnapshotRecords(const RandomAccessSource& source,
    const AppleCheckpointView& checkpoint, std::uint64_t volume_oid,
    std::vector<AppleSnapshotRecord>& out_records, std::string& out_error,
    std::uint64_t exact_snapshot_xid, AppleSnapshotTreeRecords& out_trees) {
    return LoadAppleSnapshotRecordsImpl(source, checkpoint, volume_oid,
        out_records, out_error, exact_snapshot_xid, out_trees, nullptr, 0, 0, nullptr,
        SnapshotMetadataAdmission::Strict);
}

bool LoadAppleSnapshotCatalog(const RandomAccessSource& source,
    const AppleCheckpointView& checkpoint, std::uint64_t volume_oid,
    AppleSnapshotCatalogRecords& out_catalog, std::string& out_error) {
    out_catalog = {};
    AppleSnapshotCatalogRecords catalog;
    std::vector<AppleSnapshotRecord> inventory;
    AppleSnapshotTreeRecords ignored;
    if (!LoadAppleSnapshotRecordsImpl(source, checkpoint, volume_oid,
            inventory, out_error, 0, ignored, &catalog, 0, 0, nullptr,
            SnapshotMetadataAdmission::Strict)) return false;
    catalog.inventory = std::move(inventory);
    out_catalog = std::move(catalog);
    return true;
}

bool LoadAppleSnapshotCatalog(const RandomAccessSource& source,
    const AppleCheckpointView& checkpoint, std::uint64_t volume_oid,
    AppleSnapshotCatalogRecords& out_catalog,
    std::vector<AppleSnapshotMetadataClaim>& out_owners, std::string& out_error)
{
    out_catalog = {}; out_owners.clear();
    AppleSnapshotCatalogRecords catalog;
    std::vector<AppleSnapshotMetadataClaim> owners;
    std::vector<AppleSnapshotRecord> inventory;
    AppleSnapshotTreeRecords ignored;
    if (!LoadAppleSnapshotRecordsImpl(source, checkpoint, volume_oid,
        inventory, out_error, 0, ignored, &catalog, 0, 0, &owners,
        SnapshotMetadataAdmission::Strict)) return false;
    catalog.inventory = std::move(inventory);
    out_catalog = std::move(catalog);
    out_owners = std::move(owners);
    return true;
}

bool LoadAppleSnapshotDescriptorCatalog(const RandomAccessSource& source,
    const AppleCheckpointView& checkpoint, std::uint64_t owner_volume_oid,
    std::uint64_t descriptor_block, std::uint64_t filesystem_xid,
    AppleSnapshotCatalogRecords& out_catalog, std::string& out_error) {
    out_catalog = {};
    if (!descriptor_block || !filesystem_xid) { out_error = "SnapshotDescriptorIdentityMissing"; return false; }
    AppleSnapshotCatalogRecords catalog;
    std::vector<AppleSnapshotRecord> inventory;
    AppleSnapshotTreeRecords ignored;
    if (!LoadAppleSnapshotRecordsImpl(source, checkpoint, owner_volume_oid, inventory, out_error,
            0, ignored, &catalog, descriptor_block, filesystem_xid, nullptr,
            SnapshotMetadataAdmission::Strict)) return false;
    catalog.inventory = std::move(inventory);
    out_catalog = std::move(catalog);
    return true;
}

bool LoadAppleReadOnlySnapshotCatalog(const RandomAccessSource& source,
    const AppleCheckpointView& checkpoint, std::uint64_t volume_oid,
    AppleSnapshotCatalogRecords& out_catalog, std::string& out_error)
{
    out_catalog = {};
    AppleSnapshotCatalogRecords catalog;
    std::vector<AppleSnapshotRecord> inventory;
    AppleSnapshotTreeRecords ignored;
    if (!LoadAppleSnapshotRecordsImpl(source, checkpoint, volume_oid,
        inventory, out_error, 0, ignored, &catalog, 0, 0, nullptr,
        SnapshotMetadataAdmission::ReadOnlyInactiveTreeDefaults)) return false;
    catalog.inventory = std::move(inventory);
    out_catalog = std::move(catalog);
    return true;
}

bool LoadAppleReadOnlySnapshotCatalog(const RandomAccessSource& source,
    const AppleCheckpointView& checkpoint, std::uint64_t volume_oid,
    AppleSnapshotCatalogRecords& out_catalog,
    std::vector<AppleSnapshotMetadataClaim>& out_owners, std::string& out_error)
{
    out_catalog = {}; out_owners.clear();
    AppleSnapshotCatalogRecords catalog;
    std::vector<AppleSnapshotMetadataClaim> owners;
    std::vector<AppleSnapshotRecord> inventory;
    AppleSnapshotTreeRecords ignored;
    if (!LoadAppleSnapshotRecordsImpl(source, checkpoint, volume_oid,
        inventory, out_error, 0, ignored, &catalog, 0, 0, &owners,
        SnapshotMetadataAdmission::ReadOnlyInactiveTreeDefaults)) return false;
    catalog.inventory = std::move(inventory);
    out_catalog = std::move(catalog);
    out_owners = std::move(owners);
    return true;
}

bool LoadAppleReadOnlySnapshotDescriptorCatalog(const RandomAccessSource& source,
    const AppleCheckpointView& checkpoint, std::uint64_t owner_volume_oid,
    std::uint64_t descriptor_block, std::uint64_t filesystem_xid,
    AppleSnapshotCatalogRecords& out_catalog, std::string& out_error)
{
    out_catalog = {};
    if (!descriptor_block || !filesystem_xid) { out_error = "SnapshotDescriptorIdentityMissing"; return false; }
    AppleSnapshotCatalogRecords catalog;
    std::vector<AppleSnapshotRecord> inventory;
    AppleSnapshotTreeRecords ignored;
    if (!LoadAppleSnapshotRecordsImpl(source, checkpoint, owner_volume_oid, inventory, out_error,
        0, ignored, &catalog, descriptor_block, filesystem_xid, nullptr,
        SnapshotMetadataAdmission::ReadOnlyInactiveTreeDefaults)) return false;
    catalog.inventory = std::move(inventory);
    out_catalog = std::move(catalog);
    return true;
}

bool ReadAppleSnapshotTree(const RandomAccessSource& source, std::uint32_t block_size,
    const AppleObjectLocation& tree, const AppleOmapView& omap,
    std::uint64_t tree_xid, std::uint64_t checkpoint_xid,
    std::vector<BtreeRecord>& records, std::vector<std::uint64_t>& blocks, std::string& error) {
    records.clear(); blocks.clear();
    if (ReadSnapshotTree(source, block_size, tree, omap, tree_xid, checkpoint_xid,
            records, error, false, nullptr, &blocks)) return true;
    records.clear(); blocks.clear(); return false;
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
