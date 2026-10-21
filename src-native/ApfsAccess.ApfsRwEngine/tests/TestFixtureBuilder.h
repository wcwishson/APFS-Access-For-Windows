// Shared synthetic APFS fixture builder (test-only writer, never a parser).
// Used by ApfsCompatibilityTests and FsHostSemanticsTests. Keep C++17-clean:
// the FsHost tree builds at C++17 while the engine tests build at C++20.
#pragma once

#include "ApfsFormat.h"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <string>
#include <utility>
#include <vector>

namespace apfsaccess::testfixture
{
inline void PutU16LE(std::vector<std::byte>& buffer, std::size_t offset, std::uint16_t value)
{
    buffer[offset] = static_cast<std::byte>(value & 0xffu);
    buffer[offset + 1] = static_cast<std::byte>((value >> 8) & 0xffu);
}

inline void PutU32LE(std::vector<std::byte>& buffer, std::size_t offset, std::uint32_t value)
{
    for (int index = 0; index < 4; ++index)
    {
        buffer[offset + static_cast<std::size_t>(index)] =
            static_cast<std::byte>((value >> (index * 8)) & 0xffu);
    }
}

inline void PutU64LE(std::vector<std::byte>& buffer, std::size_t offset, std::uint64_t value)
{
    for (int index = 0; index < 8; ++index)
    {
        buffer[offset + static_cast<std::size_t>(index)] =
            static_cast<std::byte>((value >> (index * 8)) & 0xffu);
    }
}

inline void PutBytes(std::vector<std::byte>& buffer, std::size_t offset, const char* text, std::size_t size)
{
    for (std::size_t index = 0; index < size; ++index)
    {
        buffer[offset + index] = static_cast<std::byte>(text[index]);
    }
}

inline std::vector<std::byte> HexToBytes(const std::string& hex)
{
    std::vector<std::byte> out;
    for (std::size_t index = 0; index + 1 < hex.size(); index += 2)
    {
        const auto nibble = [](char ch) -> unsigned {
            if (ch >= '0' && ch <= '9') return static_cast<unsigned>(ch - '0');
            if (ch >= 'a' && ch <= 'f') return static_cast<unsigned>(ch - 'a' + 10);
            return static_cast<unsigned>(ch - 'A' + 10);
        };
        out.push_back(static_cast<std::byte>((nibble(hex[index]) << 4) | nibble(hex[index + 1])));
    }
    return out;
}

// Mixed-endian GUID bytes from canonical "dddddddd-dddd-dddd-dddd-dddddddddddd"
// (matches System.Guid(byte[]) first-field LE interpretation).
inline std::vector<std::byte> GuidToMixedEndian(const std::string& guid)
{
    std::string hex;
    for (char ch : guid)
    {
        if (ch != '-')
        {
            hex.push_back(ch);
        }
    }
    std::vector<std::byte> raw = HexToBytes(hex);
    // Swap to mixed-endian: Data1[0:4], Data2[4:6], Data3[6:8] little-endian.
    std::reverse(raw.begin(), raw.begin() + 4);
    std::reverse(raw.begin() + 4, raw.begin() + 6);
    std::reverse(raw.begin() + 6, raw.begin() + 8);
    return raw;
}

// ---- synthetic image builder (test-only writer, never a parser) -------------

struct OmapRecordSpec
{
    std::uint64_t oid = 101;
    std::uint64_t paddr = 4; // == kFirstVolumeBlock below
    std::uint32_t flags = 0;
    std::uint64_t xid = 7;
};

struct CheckpointMappingSpec
{
    std::uint32_t type = 0x80000005; // OBJ_EPHEMERAL | OBJECT_TYPE_SPACEMAN
    std::uint32_t subtype = 0;
    std::uint32_t size = 4096;
    std::uint64_t file_system_oid = 0;
    std::uint64_t object_id = 1024;
    std::uint64_t physical_block = 0;
};

struct BuilderVolume
{
    std::uint64_t oid = 101;
    std::string name = "Data";
    std::string uuid_hex; // "" = deterministic filler
    std::uint16_t role = 0x40;
    std::uint64_t reserve_block_count = 0;
    std::uint64_t quota_block_count = 0;
    std::uint64_t fs_flags = 0x1;
    std::uint64_t features = 0x1;
    std::uint64_t ro_features = 0;
    std::uint64_t incompat = 0;
    std::int64_t xid_offset = 0; // added to container xid (stale vector)
    std::string group_hex; // "" = zero
    bool bad_checksum = false;
    std::uint64_t root_oid_override = 0; // 0 = default 0x2000+oid scheme
    std::uint32_t root_tree_type = 0x00000002;
    std::uint32_t extentref_tree_type = 0x40000002;
    std::uint32_t snap_meta_tree_type = 0x00000002;
    std::uint64_t extentref_tree_oid = 0;
    std::uint64_t snap_meta_tree_oid = 0;
    std::uint64_t fext_tree_oid = 0;
    std::uint32_t fext_tree_type = 0;
    std::uint64_t file_system_allocated_blocks = 0;
    std::uint64_t next_object_id = 0;
    std::uint64_t total_blocks_allocated = 0;
    std::uint64_t total_blocks_freed = 0;
    std::uint64_t decoy_root_block = 0; // 0 = none; else plants a copy of this
        // volume's APSB with the default root OID at the given block
    bool projectable = false; // emit a real volume omap + root tree so the
        // native reader can project this volume end to end
    std::uint64_t vol_omap_oid_override = 0; // 0 = default 0x1000+oid scheme.
        // Informational for non-projectable volumes; projectable volumes are
        // always rewired to their layout block (legacy OID==block addressing).
    std::vector<apfsaccess::catalog::BtreeRecord> filesystem_records;
    std::vector<apfsaccess::catalog::BtreeRecord> extentref_records;
    std::uint64_t additional_file_system_allocated_blocks = 0;
};

struct BuilderStore
{
    std::string uuid_hex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    std::uint64_t xid = 7;
    std::uint64_t next_oid = 0x5000;
    std::uint64_t next_xid = 0; // zero derives xid + 1 for each emitted NXSB
    std::uint32_t block_size = 4096;
    std::uint64_t block_count = 64;
    std::vector<BuilderVolume> volumes{ BuilderVolume{} };
    bool dual_checkpoint = true;
    std::uint64_t second_xid_offset = 0; // 0 = same xid on block 1
    std::string second_uuid_hex; // "" = same uuid
    std::uint64_t xp_desc_base_blocks = 0; // 0 = no descriptor area
    std::uint32_t xp_desc_blocks = 0;
    std::uint64_t xp_data_base_blocks = 0;
    std::uint32_t xp_data_blocks = 0;
    std::uint32_t xp_desc_next = 0;
    std::uint32_t xp_data_next = 0;
    std::uint32_t xp_desc_index = 0;
    std::uint32_t xp_desc_len = 0;
    std::uint32_t xp_data_index = 0;
    std::uint32_t xp_data_len = 0;
    std::vector<OmapRecordSpec> extra_omap_records; // appended verbatim
    // Opt-in spaceman anchor for MetadataStore sessions (container-session
    // fixtures): writes the NXSB spaceman OID, maps it to a zero block via
    // the container omap (mirrors the scaffold zero-block shape the store
    // accepts). Zero (default) preserves current behavior exactly.
    std::uint64_t spaceman_oid = 0;
    std::uint64_t spaceman_block = 0;
    bool authoritative_checkpoint = false;
    std::uint32_t authoritative_checkpoint_ring_blocks = 8;
    std::uint64_t authoritative_internal_pool_blocks = 4;
    // Test-only pressure control for authoritative fixtures. Zero preserves
    // the naturally derived free-space bitmap; nonzero leaves at most this
    // many main-device blocks free after all fixture structures are reserved.
    std::uint64_t authoritative_main_free_blocks = 0;
    std::vector<std::pair<std::uint64_t, std::vector<std::byte>>>
        authoritative_seeded_main_blocks;
};

struct BuilderImage
{
    bool gpt = true;
    std::uint64_t sector_size = 512;
    std::vector<BuilderStore> stores{ BuilderStore{} };
    bool bad_gpt_header_crc = false;
    bool bad_gpt_entries_crc = false;
    std::uint64_t truncate_bytes = 0; // 0 = no truncation
    bool zero_nxsb_magic = false;
    // Extra GPT entries without store content (non-APFS usage coverage).
    std::vector<std::string> extra_partition_type_guids;
};

constexpr std::uint64_t kOmapOid = 2;
constexpr std::uint64_t kBtreeBlock = 3;
constexpr std::uint64_t kFirstVolumeBlock = 4;

inline std::uint64_t FletcherForBlock(std::vector<std::byte>& block, std::size_t size)
{
    const auto checksum =
        apfsaccess::catalog::Fletcher64(block.data() + 8, size - 8).value();
    for (int index = 0; index < 8; ++index)
    {
        block[static_cast<std::size_t>(index)] =
            static_cast<std::byte>((checksum >> (index * 8)) & 0xffu);
    }
    return checksum;
}

inline std::vector<std::byte> BuildApsb(
    const BuilderVolume& spec, std::uint64_t container_xid, std::size_t block_size)
{
    std::vector<std::byte> block(block_size, std::byte{0});
    const std::uint64_t xid = container_xid + static_cast<std::uint64_t>(spec.xid_offset);
    PutU64LE(block, 0x08, spec.oid);
    PutU64LE(block, 0x10, xid);
    PutU32LE(block, 0x18, 0x0000000D);
    PutU32LE(block, 0x20, 0x42535041);
    PutU32LE(block, 0x24, 1);
    PutU64LE(block, 0x58, spec.file_system_allocated_blocks);
    PutU64LE(block, 0x48, spec.reserve_block_count);
    PutU64LE(block, 0x50, spec.quota_block_count);
    PutU64LE(block, 0x28, spec.features);
    PutU64LE(block, 0x30, spec.ro_features);
    PutU64LE(block, 0x38, spec.incompat);
    PutU32LE(block, 0x74, spec.root_tree_type);
    PutU32LE(block, 0x78, spec.extentref_tree_type);
    PutU32LE(block, 0x7C, spec.snap_meta_tree_type);
    PutU64LE(block, 0x80,
        spec.vol_omap_oid_override != 0 ? spec.vol_omap_oid_override : (0x1000 + spec.oid));
    PutU64LE(block, 0x88, spec.root_oid_override != 0 ? spec.root_oid_override : (0x2000 + spec.oid));
    PutU64LE(block, 0x90, spec.extentref_tree_oid);
    PutU64LE(block, 0x98, spec.snap_meta_tree_oid);
    PutU64LE(block, 0xB0, spec.next_object_id);
    PutU64LE(block, 0xB8, 11);
    PutU64LE(block, 0xC0, 3);
    PutU64LE(block, 0xE0, spec.total_blocks_allocated);
    PutU64LE(block, 0xE8, spec.total_blocks_freed);
    // Default filler UUIDs embed the volume OID so distinct volumes never
    // collide unless a spec explicitly repeats a UUID.
    std::vector<std::byte> uuid_storage;
    if (spec.uuid_hex.empty())
    {
        uuid_storage = HexToBytes("50000000000040008000000000000000");
        for (int i = 0; i < 8; ++i)
        {
            uuid_storage[8 + static_cast<std::size_t>(i)] =
                static_cast<std::byte>((spec.oid >> (i * 8)) & 0xffu);
        }
    }
    else
    {
        uuid_storage = HexToBytes(spec.uuid_hex);
    }
    const auto& uuid = uuid_storage;
    for (std::size_t i = 0; i < 16 && i < uuid.size(); ++i)
    {
        block[0xF0 + i] = uuid[i];
    }
    PutU64LE(block, 0x108, spec.fs_flags);
    const std::size_t name_len = (std::min)(spec.name.size(), static_cast<std::size_t>(255));
    for (std::size_t i = 0; i < name_len; ++i)
    {
        block[0x2C0 + i] = static_cast<std::byte>(spec.name[i]);
    }
    PutU16LE(block, 0x3C4, spec.role);
    const auto group = spec.group_hex.empty() ? std::vector<std::byte>(16, std::byte{0}) : HexToBytes(spec.group_hex);
    for (std::size_t i = 0; i < 16 && i < group.size(); ++i)
    {
        block[0x3F0 + i] = group[i];
    }
    PutU64LE(block, 0x408, spec.fext_tree_oid);
    PutU32LE(block, 0x410, spec.fext_tree_type);
    FletcherForBlock(block, block_size);
    if (spec.bad_checksum)
    {
        block[0] = static_cast<std::byte>(static_cast<unsigned char>(block[0]) ^ 0xFFu);
    }
    return block;
}

inline std::vector<std::byte> BuildRawLeafNode(
    const std::vector<std::vector<std::byte>>& keys,
    const std::vector<std::vector<std::byte>>& values,
    std::uint64_t xid,
    std::size_t block_size,
    std::uint64_t node_xid_override = 0,
    std::uint64_t object_id = 0,
    std::uint32_t object_type = 0x00000002,
    std::uint32_t object_subtype = 0)
{
    std::vector<std::byte> block(block_size, std::byte{0});
    PutU64LE(block, 0x08, object_id);
    PutU64LE(block, 0x10, node_xid_override != 0 ? node_xid_override : xid);
    PutU32LE(block, 0x18, object_type);
    PutU32LE(block, 0x1C, object_subtype);
    PutU16LE(block, 0x20, 0x0003); // root | leaf
    PutU16LE(block, 0x22, 0); // level 0
    const auto count = static_cast<std::uint32_t>(keys.size());
    PutU32LE(block, 0x24, count);
    PutU16LE(block, 0x28, 0); // table_offset
    PutU16LE(block, 0x2A, static_cast<std::uint16_t>(count * 8)); // table_length
    const std::size_t table_start = 0x38;
    std::size_t key_cursor = 0;
    std::size_t value_prefix = 0;
    for (std::uint32_t i = 0; i < count; ++i)
    {
        value_prefix += values[i].size();
        PutU16LE(block, table_start + i * 8, static_cast<std::uint16_t>(key_cursor));
        PutU16LE(block, table_start + i * 8 + 2, static_cast<std::uint16_t>(keys[i].size()));
        PutU16LE(block, table_start + i * 8 + 4,
            static_cast<std::uint16_t>(value_prefix));
        PutU16LE(block, table_start + i * 8 + 6, static_cast<std::uint16_t>(values[i].size()));
        key_cursor += keys[i].size();
    }
    const std::size_t key_area = table_start + count * 8;
    const std::size_t info_start = block_size - 40;
    const std::size_t value_end = info_start;
    std::size_t key_write = key_area;
    for (std::uint32_t i = 0; i < count; ++i)
    {
        for (std::size_t b = 0; b < keys[i].size(); ++b)
        {
            block[key_write + b] = keys[i][b];
        }
        key_write += keys[i].size();
    }
    // Values pack backward from the end of the value area, so entry i reads
    // its value at (value_end - value_offset) with value_offset measured as
    // the distance from the end to the value START. Entry offsets above are
    // cumulative sizes, which equal end-relative starts only for the layout
    // below: value i occupies [value_end - prefix(i+1), value_end - prefix(i)).
    std::size_t prefix = 0;
    for (std::uint32_t i = 0; i < count; ++i)
    {
        prefix += values[i].size();
        const std::size_t value_start = value_end - prefix;
        for (std::size_t b = 0; b < values[i].size(); ++b)
        {
            block[value_start + b] = values[i][b];
        }
    }
    const std::size_t keys_end = key_write;
    const std::size_t values_start = value_end - prefix;
    PutU16LE(block, 0x2C, static_cast<std::uint16_t>(keys_end - key_area));
    PutU16LE(block, 0x2E, static_cast<std::uint16_t>(values_start - keys_end));
    PutU16LE(block, 0x30, 0xffffu);
    PutU16LE(block, 0x34, 0xffffu);
    const auto storage_type = object_type & 0xC0000000u;
    PutU32LE(block, info_start,
        storage_type == 0x40000000u ? 0x00000010u | 0x00000040u :
        storage_type == 0x80000000u ? 0x00000008u | 0x00000040u : 0x00000040u);
    PutU32LE(block, info_start + 4, static_cast<std::uint32_t>(block_size));
    std::size_t longest_key = 0;
    std::size_t longest_value = 0;
    for (std::uint32_t i = 0; i < count; ++i)
    {
        longest_key = (std::max)(longest_key, keys[i].size());
        longest_value = (std::max)(longest_value, values[i].size());
    }
    PutU32LE(block, info_start + 16, static_cast<std::uint32_t>(longest_key));
    PutU32LE(block, info_start + 20, static_cast<std::uint32_t>(longest_value));
    PutU64LE(block, info_start + 24, count);
    PutU64LE(block, info_start + 32, 1);
    FletcherForBlock(block, block_size);
    return block;
}

inline std::vector<std::byte> BuildBtreeNode(
    const std::vector<OmapRecordSpec>& records,
    std::uint64_t xid,
    std::size_t block_size,
    std::uint64_t node_xid_override = 0,
    std::uint64_t object_id = 0,
    std::uint32_t object_type = 0x00000002,
    std::uint32_t object_subtype = 0)
{
    std::vector<std::vector<std::byte>> keys;
    std::vector<std::vector<std::byte>> values;
    for (const auto& record : records)
    {
        std::vector<std::byte> key(16, std::byte{0});
        std::vector<std::byte> value(16, std::byte{0});
        for (int b = 0; b < 8; ++b)
        {
            key[static_cast<std::size_t>(b)] =
                static_cast<std::byte>((record.oid >> (b * 8)) & 0xffu);
            key[8 + static_cast<std::size_t>(b)] =
                static_cast<std::byte>((record.xid >> (b * 8)) & 0xffu);
            value[8 + static_cast<std::size_t>(b)] =
                static_cast<std::byte>((record.paddr >> (b * 8)) & 0xffu);
        }
        for (int b = 0; b < 4; ++b)
        {
            value[static_cast<std::size_t>(b)] =
                static_cast<std::byte>((record.flags >> (b * 8)) & 0xffu);
        }
        PutU32LE(value, 4, static_cast<std::uint32_t>(block_size));
        keys.push_back(std::move(key));
        values.push_back(std::move(value));
    }
    return BuildRawLeafNode(keys, values, xid, block_size, node_xid_override,
        object_id, object_type, object_subtype);
}

inline std::vector<std::byte> BuildBtreeNode(
    const std::vector<std::pair<std::uint64_t, std::uint64_t>>& oid_to_block,
    std::uint64_t xid,
    std::size_t block_size)
{
    std::vector<OmapRecordSpec> records;
    for (const auto& [oid, paddr] : oid_to_block)
    {
        records.push_back(OmapRecordSpec{oid, paddr, 0, xid});
    }
    return BuildBtreeNode(records, xid, block_size);
}

inline std::vector<std::byte> BuildOmap(std::uint64_t tree_block, std::uint64_t xid, std::size_t block_size,
    std::uint64_t omap_oid = kOmapOid,
    std::uint32_t object_type = 0x0000000B,
    std::uint32_t tree_type = 0,
    std::uint32_t omap_flags = 0)
{
    std::vector<std::byte> block(block_size, std::byte{0});
    PutU64LE(block, 0x08, omap_oid);
    PutU64LE(block, 0x10, xid);
    PutU32LE(block, 0x18, object_type);
    PutU32LE(block, 0x20, omap_flags);
    PutU32LE(block, 0x28, tree_type);
    PutU64LE(block, 0x30, tree_block);
    FletcherForBlock(block, block_size);
    return block;
}

// Minimal root-directory inode value (type-3 record payload): parent, private
// id, timestamp, directory mode, zero logical size. Enough for the native
// reader to project a single-root tree.
inline std::vector<std::byte> BuildRootInodeValue(std::uint64_t parent_id, std::uint64_t private_id)
{
    std::vector<std::byte> value(0x60, std::byte{0});
    for (int b = 0; b < 8; ++b)
    {
        value[static_cast<std::size_t>(b)] =
            static_cast<std::byte>((parent_id >> (b * 8)) & 0xffu);
        value[8 + static_cast<std::size_t>(b)] =
            static_cast<std::byte>((private_id >> (b * 8)) & 0xffu);
    }
    value[0x50] = std::byte{0xED};
    value[0x51] = std::byte{0x41};
    return value;
}

inline std::vector<std::byte> BuildRootFsLeaf(
    std::uint64_t xid,
    std::size_t block_size,
    std::uint64_t object_id = 0,
    std::uint32_t object_type = 0x00000002,
    std::uint32_t object_subtype = 0)
{
    constexpr std::uint64_t kRootInodeKey = 2 | (3ull << 60);
    std::vector<std::byte> key(8, std::byte{0});
    for (int b = 0; b < 8; ++b)
    {
        key[static_cast<std::size_t>(b)] =
            static_cast<std::byte>((kRootInodeKey >> (b * 8)) & 0xffu);
    }
    return BuildRawLeafNode({key}, {BuildRootInodeValue(2, 9)}, xid, block_size,
        0, object_id, object_type, object_subtype);
}

inline std::vector<std::byte> BuildNxsb(
    const BuilderStore& spec, std::uint64_t xid, const std::string& uuid_hex, std::size_t min_bytes)
{
    const std::size_t block_size = spec.block_size;
    std::vector<std::byte> block((std::max)(block_size, min_bytes), std::byte{0});
    PutU64LE(block, 0x08, 1);
    PutU64LE(block, 0x10, xid);
    PutU32LE(block, 0x18, 0x00000001);
    PutU32LE(block, 0x20, 0x4253584E);
    PutU32LE(block, 0x24, spec.block_size);
    PutU64LE(block, 0x28, spec.block_count);
    PutU64LE(block, 0x30, 0x1);
    PutU32LE(block, 0x68, spec.xp_desc_blocks);
    PutU32LE(block, 0x6C, spec.xp_data_blocks);
    PutU64LE(block, 0x70, spec.xp_desc_base_blocks);
    PutU64LE(block, 0x78, spec.xp_data_base_blocks);
    PutU32LE(block, 0x80, spec.xp_desc_next);
    PutU32LE(block, 0x84, spec.xp_data_next);
    PutU32LE(block, 0x88, spec.xp_desc_index);
    PutU32LE(block, 0x8C, spec.xp_desc_len);
    PutU32LE(block, 0x90, spec.xp_data_index);
    PutU32LE(block, 0x94, spec.xp_data_len);
    const auto uuid = HexToBytes(uuid_hex.empty() ? spec.uuid_hex : uuid_hex);
    for (std::size_t i = 0; i < 16 && i < uuid.size(); ++i)
    {
        block[0x48 + i] = uuid[i];
    }
    PutU64LE(block, 0x58, spec.next_oid);
    PutU64LE(block, 0x60, spec.next_xid == 0 ? xid + 1 : spec.next_xid);
    PutU64LE(block, 0xA0, kOmapOid);
    if (spec.spaceman_oid != 0)
    {
        PutU64LE(block, 0x98, spec.spaceman_oid);
    }
    const auto max_file_systems = spec.volumes.size() > 100
        ? 101u
        : static_cast<std::uint32_t>((std::max)(std::size_t{1}, spec.volumes.size()));
    PutU32LE(block, 0xB4, max_file_systems);
    for (std::size_t i = 0; i < (std::min)(std::size_t{100}, spec.volumes.size()); ++i)
    {
        PutU64LE(block, 0xB8 + i * 8, spec.volumes[i].oid);
    }
    FletcherForBlock(block, block_size);
    return block;
}

inline std::vector<std::byte> BuildEmptyFreeQueueNode(
    std::uint64_t xid,
    std::size_t block_size,
    std::uint64_t object_id)
{
    auto block = BuildRawLeafNode({}, {}, xid, block_size, 0, object_id,
        0x80000002, 0x00000009);
    PutU16LE(block, 0x20, 0x0007); // root | leaf | fixed key/value
    const std::size_t info_start = block_size - 40;
    PutU32LE(block, info_start, 0x0000000F); // uint64 | sequential | ghosts | ephemeral
    PutU32LE(block, info_start + 8, 16);
    PutU32LE(block, info_start + 12, 8);
    PutU32LE(block, info_start + 16, 16);
    PutU32LE(block, info_start + 20, 8);
    FletcherForBlock(block, block_size);
    return block;
}

inline std::vector<std::byte> BuildCheckpointMap(
    std::uint64_t xid,
    const std::vector<CheckpointMappingSpec>& mappings,
    std::size_t block_size,
    std::uint64_t physical_block,
    bool last = true)
{
    std::vector<std::byte> block(block_size, std::byte{0});
    PutU64LE(block, 0x08, physical_block);
    PutU64LE(block, 0x10, xid);
    PutU32LE(block, 0x18, 0x4000000C);
    PutU32LE(block, 0x20, last ? 1u : 0u);
    PutU32LE(block, 0x24, static_cast<std::uint32_t>(mappings.size()));
    constexpr std::size_t kEntryBytes = 0x28;
    for (std::size_t index = 0; index < mappings.size(); ++index)
    {
        const auto offset = 0x28 + index * kEntryBytes;
        if (offset + kEntryBytes > block.size())
        {
            break;
        }
        const auto& mapping = mappings[index];
        PutU32LE(block, offset + 0x00, mapping.type);
        PutU32LE(block, offset + 0x04, mapping.subtype);
        PutU32LE(block, offset + 0x08, mapping.size);
        PutU64LE(block, offset + 0x10, mapping.file_system_oid);
        PutU64LE(block, offset + 0x18, mapping.object_id);
        PutU64LE(block, offset + 0x20, mapping.physical_block);
    }
    FletcherForBlock(block, block_size);
    return block;
}

inline std::vector<std::byte> BuildEphemeralObject(
    std::uint64_t object_id,
    std::uint64_t xid,
    std::uint32_t type,
    std::uint32_t subtype,
    std::size_t object_size)
{
    std::vector<std::byte> object(object_size, std::byte{0});
    PutU64LE(object, 0x08, object_id);
    PutU64LE(object, 0x10, xid);
    PutU32LE(object, 0x18, type);
    PutU32LE(object, 0x1C, subtype);
    FletcherForBlock(object, object_size);
    return object;
}

inline std::uint64_t EffectiveStoreBlockCount(const BuilderStore& spec)
{
    if (!spec.authoritative_checkpoint)
    {
        return spec.block_count;
    }
    const auto required =
        4ull + static_cast<std::uint64_t>(spec.volumes.size()) * 7ull + 36ull;
    return (std::max)(spec.block_count, required);
}

inline std::vector<std::byte> BuildAuthoritativeStoreImage(const BuilderStore& spec);

inline std::vector<std::byte> BuildStoreImage(const BuilderStore& spec)
{
    if (spec.authoritative_checkpoint)
    {
        return BuildAuthoritativeStoreImage(spec);
    }
    const std::size_t bs = spec.block_size;
    const std::size_t total = static_cast<std::size_t>(spec.block_count) * bs;
    std::vector<std::byte> image(total, std::byte{0});
    auto put_block = [&](std::uint64_t index, const std::vector<std::byte>& block) {
        const std::size_t offset = static_cast<std::size_t>(index) * bs;
        if (offset >= total)
        {
            return;
        }
        const std::size_t count = (std::min)(block.size(), total - offset);
        for (std::size_t i = 0; i < count; ++i)
        {
            image[offset + i] = block[i];
        }
    };
    put_block(0, BuildNxsb(spec, spec.xid, "", bs));
    if (spec.dual_checkpoint)
    {
        put_block(1, BuildNxsb(
            spec, spec.xid + static_cast<std::uint64_t>(spec.second_xid_offset),
            spec.second_uuid_hex, bs));
    }
    // OMAP_MANUALLY_MANAGED is mandatory only for the container object map.
    put_block(kOmapOid, BuildOmap(kBtreeBlock, spec.xid, bs, kOmapOid,
        0x0000000B, 0, 1));
    std::vector<OmapRecordSpec> mappings;
    for (std::size_t i = 0; i < spec.volumes.size(); ++i)
    {
        OmapRecordSpec record;
        record.oid = spec.volumes[i].oid;
        record.paddr = kFirstVolumeBlock + i;
        record.flags = 0;
        record.xid = spec.xid;
        mappings.push_back(record);
    }
    for (const auto& extra : spec.extra_omap_records)
    {
        mappings.push_back(extra);
    }
    if (spec.spaceman_oid != 0)
    {
        OmapRecordSpec spaceman_mapping;
        spaceman_mapping.oid = spec.spaceman_oid;
        spaceman_mapping.paddr = spec.spaceman_block;
        spaceman_mapping.flags = 0;
        spaceman_mapping.xid = spec.xid;
        mappings.push_back(spaceman_mapping);
    }
    // btree node xid tracks the container xid so node-freshness checks pass.
    put_block(kBtreeBlock, BuildBtreeNode(mappings, spec.xid, bs));
    for (std::size_t i = 0; i < spec.volumes.size(); ++i)
    {
        BuilderVolume vol = spec.volumes[i];
        std::uint64_t omap_block = 0;
        std::uint64_t omap_tree_block = 0;
        std::uint64_t root_block = 0;
        std::uint64_t vol_xid = 0;
        if (vol.projectable)
        {
            // The legacy reader addresses omap objects by block index, so the
            // volume omap OID must equal its layout block. The override field
            // is informational only and is rewired here.
            omap_block = 32 + i * 3;
            omap_tree_block = 33 + i * 3;
            root_block = 34 + i * 3;
            vol.vol_omap_oid_override = omap_block;
            vol_xid = spec.xid + static_cast<std::uint64_t>(vol.xid_offset);
        }
        const auto apsb = BuildApsb(vol, spec.xid, bs);
        put_block(kFirstVolumeBlock + i, apsb);
        if (vol.decoy_root_block != 0)
        {
            // Decoy copy of this volume's APSB with the default (resolvable)
            // root OID, planted for proximity-scan adversarial coverage.
            auto decoy = apsb;
            PutU64LE(decoy, 0x88, 0x2000 + vol.oid);
            FletcherForBlock(decoy, bs);
            put_block(vol.decoy_root_block, decoy);
        }
        if (vol.projectable)
        {
            // The volume omap tree maps only the default root OID; an
            // overridden (garbage) primary root stays unresolvable while the
            // decoy copy resolves through the default mapping.
            put_block(omap_block, BuildOmap(omap_tree_block, vol_xid, bs, omap_block));
            OmapRecordSpec root_mapping;
            root_mapping.oid = 0x2000 + vol.oid;
            root_mapping.paddr = root_block;
            root_mapping.flags = 0;
            root_mapping.xid = vol_xid;
            put_block(omap_tree_block,
                BuildBtreeNode({root_mapping}, vol_xid, bs, vol_xid));
            put_block(root_block, BuildRootFsLeaf(vol_xid, bs));
        }
    }
    return image;
}

inline std::vector<std::byte> BuildAuthoritativeStoreImage(const BuilderStore& input)
{
    BuilderStore spec = input;
    spec.block_count = EffectiveStoreBlockCount(input);
    spec.dual_checkpoint = false;
    const std::size_t bs = spec.block_size;
    const std::size_t total = static_cast<std::size_t>(spec.block_count) * bs;
    std::vector<std::byte> image(total, std::byte{0});
    auto put_block = [&](std::uint64_t index, const std::vector<std::byte>& block) {
        const std::size_t offset = static_cast<std::size_t>(index) * bs;
        if (offset >= total)
        {
            return;
        }
        const std::size_t count = (std::min)(block.size(), total - offset);
        std::copy_n(block.begin(), count,
            image.begin() + static_cast<std::vector<std::byte>::difference_type>(offset));
    };
    const auto split_records = [](const auto& records, auto& keys, auto& values) {
        keys.clear();
        values.clear();
        keys.reserve(records.size());
        values.reserve(records.size());
        for (const auto& record : records)
        {
            keys.push_back(record.key);
            values.push_back(record.value);
        }
    };

    const std::uint64_t volume_layout_base = 4 + spec.volumes.size();
    const std::uint64_t descriptor_base =
        volume_layout_base + static_cast<std::uint64_t>(spec.volumes.size()) * 6;
    const auto checkpoint_ring_blocks = spec.authoritative_checkpoint_ring_blocks;
    constexpr std::uint32_t ip_bitmap_rotation_count = 16;
    const auto ip_block_count = spec.authoritative_internal_pool_blocks;
    const std::uint64_t data_base = descriptor_base + checkpoint_ring_blocks;
    const std::uint64_t ip_bitmap_base =
        data_base + checkpoint_ring_blocks;
    const std::uint64_t ip_base =
        ip_bitmap_base + ip_bitmap_rotation_count;
    constexpr std::uint64_t kSpacemanOid = 0x4000;
    constexpr std::uint64_t kFreeQueueOid = 0x4001;
    constexpr std::uint64_t kMainFreeQueueOid = 0x4002;
    spec.xp_desc_base_blocks = descriptor_base;
    spec.xp_desc_blocks = checkpoint_ring_blocks;
    spec.xp_data_base_blocks = data_base;
    spec.xp_data_blocks = checkpoint_ring_blocks;
    spec.spaceman_oid = kSpacemanOid;
    spec.spaceman_block = data_base;

    BuilderStore anchor = spec;
    anchor.xp_desc_index = 0;
    anchor.xp_desc_len = 0;
    anchor.xp_desc_next = 0;
    anchor.xp_data_index = 0;
    anchor.xp_data_len = 0;
    anchor.xp_data_next = 0;
    put_block(0, BuildNxsb(anchor, spec.xid == 0 ? 0 : spec.xid - 1, "", bs));

    std::vector<OmapRecordSpec> container_records;
    for (std::size_t index = 0; index < spec.volumes.size(); ++index)
    {
        container_records.push_back({spec.volumes[index].oid,
            kFirstVolumeBlock + index, 0,
            spec.xid + static_cast<std::uint64_t>(spec.volumes[index].xid_offset)});
    }
    for (const auto& extra : spec.extra_omap_records)
    {
        container_records.push_back(extra);
    }
    put_block(kOmapOid, BuildOmap(kBtreeBlock, spec.xid, bs, kOmapOid,
        0x4000000B, 0x40000002, 1));
    put_block(kBtreeBlock, BuildBtreeNode(container_records, spec.xid, bs, 0,
        kBtreeBlock, 0x40000002, 0x0000000B));

    for (std::size_t index = 0; index < spec.volumes.size(); ++index)
    {
        BuilderVolume volume = spec.volumes[index];
        const std::uint64_t layout = volume_layout_base + index * 6;
        const std::uint64_t volume_omap = layout;
        const std::uint64_t volume_omap_tree = layout + 1;
        const std::uint64_t root_block = layout + 2;
        const std::uint64_t extentref_block = layout + 3;
        const std::uint64_t snapshot_block = layout + 4;
        const std::uint64_t fext_block = layout + 5;
        const std::uint64_t root_oid = volume.root_oid_override != 0
            ? volume.root_oid_override
            : 0x2000 + volume.oid;
        const std::uint64_t snapshot_oid = volume.snap_meta_tree_oid != 0
            ? volume.snap_meta_tree_oid
            : 0x3000 + volume.oid;
        const std::uint64_t volume_xid =
            spec.xid + static_cast<std::uint64_t>(volume.xid_offset);
        volume.vol_omap_oid_override = volume_omap;
        volume.root_oid_override = root_oid;
        volume.root_tree_type = 0x00000002;
        volume.extentref_tree_type = 0x40000002;
        volume.extentref_tree_oid = extentref_block;
        volume.snap_meta_tree_type = 0x00000002;
        volume.snap_meta_tree_oid = snapshot_oid;
        if (volume.fext_tree_oid != 0)
        {
            volume.fext_tree_type = 0x40000002;
            volume.fext_tree_oid = fext_block;
        }
        volume.file_system_allocated_blocks =
            (volume.fext_tree_oid != 0 ? 7 : 6) +
            volume.additional_file_system_allocated_blocks;
        volume.next_object_id = 0x6000;
        volume.total_blocks_allocated =
            volume.file_system_allocated_blocks;
        put_block(kFirstVolumeBlock + index, BuildApsb(volume, spec.xid, bs));
        put_block(volume_omap, BuildOmap(volume_omap_tree, volume_xid, bs,
            volume_omap, 0x4000000B, 0x40000002));
        put_block(volume_omap_tree, BuildBtreeNode({
                OmapRecordSpec{root_oid, root_block, 0, volume_xid},
                OmapRecordSpec{snapshot_oid, snapshot_block, 0, volume_xid}},
            volume_xid, bs, 0, volume_omap_tree, 0x40000002, 0x0000000B));
        if (volume.filesystem_records.empty())
        {
            put_block(root_block, BuildRootFsLeaf(volume_xid, bs,
                root_oid, 0x00000002, 0x0000000E));
        }
        else
        {
            std::vector<std::vector<std::byte>> keys;
            std::vector<std::vector<std::byte>> values;
            split_records(volume.filesystem_records, keys, values);
            put_block(root_block, BuildRawLeafNode(keys, values, volume_xid,
                bs, 0, root_oid, 0x00000002, 0x0000000E));
        }
        std::vector<std::vector<std::byte>> extentref_keys;
        std::vector<std::vector<std::byte>> extentref_values;
        split_records(volume.extentref_records,
            extentref_keys, extentref_values);
        put_block(extentref_block, BuildRawLeafNode(extentref_keys,
            extentref_values, volume_xid, bs, 0, extentref_block,
            0x40000002, 0x0000000F));
        put_block(snapshot_block, BuildRawLeafNode({}, {}, volume_xid, bs, 0,
            snapshot_oid, 0x00000002, 0x00000010));
        if (volume.fext_tree_oid != 0)
        {
            put_block(fext_block, BuildRawLeafNode({}, {}, volume_xid, bs, 0,
                fext_block, 0x40000002, 0x0000001F));
        }
    }

    BuilderStore selected = spec;
    selected.xp_desc_index = 0;
    selected.xp_desc_len = 2;
    selected.xp_desc_next = 2;
    selected.xp_data_index = 0;
    selected.xp_data_len = 3;
    selected.xp_data_next = 3;
    CheckpointMappingSpec spaceman;
    spaceman.type = 0x80000005;
    spaceman.size = spec.block_size;
    spaceman.object_id = kSpacemanOid;
    spaceman.physical_block = data_base;
    CheckpointMappingSpec free_queue;
    free_queue.type = 0x80000002;
    free_queue.subtype = 0x00000009;
    free_queue.size = spec.block_size;
    free_queue.object_id = kFreeQueueOid;
    free_queue.physical_block = data_base + 1;
    CheckpointMappingSpec main_free_queue = free_queue;
    main_free_queue.object_id = kMainFreeQueueOid;
    main_free_queue.physical_block = data_base + 2;
    put_block(descriptor_base,
        BuildCheckpointMap(spec.xid,
            {spaceman, free_queue, main_free_queue}, bs,
            descriptor_base));
    put_block(descriptor_base + 1, BuildNxsb(selected, spec.xid, "", bs));
    put_block(data_base + 1,
        BuildEmptyFreeQueueNode(spec.xid, bs, kFreeQueueOid));
    put_block(data_base + 2,
        BuildEmptyFreeQueueNode(spec.xid, bs, kMainFreeQueueOid));
    for (const auto& [block, bytes] : spec.authoritative_seeded_main_blocks)
    {
        put_block(block, bytes);
    }

    const std::uint64_t cib_block = ip_base;
    const std::uint64_t chunk_bitmap_block = ip_base + 1;
    const auto set_bit = [](std::vector<std::byte>& bitmap, std::uint64_t bit) {
        bitmap[static_cast<std::size_t>(bit / 8)] |=
            static_cast<std::byte>(1u << (bit % 8));
    };
    std::vector<std::byte> chunk_bitmap(bs, std::byte{0});
    for (std::uint64_t block = 0; block < spec.block_count; ++block)
    {
        const auto offset = static_cast<std::size_t>(block) * bs;
        const bool populated = std::any_of(
            image.begin() + static_cast<std::vector<std::byte>::difference_type>(offset),
            image.begin() + static_cast<std::vector<std::byte>::difference_type>(offset + bs),
            [](std::byte value) { return value != std::byte{0}; });
        if (populated)
        {
            set_bit(chunk_bitmap, block);
        }
    }
    for (std::uint64_t block = descriptor_base;
         block < descriptor_base + checkpoint_ring_blocks; ++block)
    {
        set_bit(chunk_bitmap, block);
    }
    for (std::uint64_t block = data_base;
         block < data_base + checkpoint_ring_blocks; ++block)
    {
        set_bit(chunk_bitmap, block);
    }
    for (std::uint64_t block = ip_bitmap_base;
         block < ip_bitmap_base + ip_bitmap_rotation_count; ++block)
    {
        set_bit(chunk_bitmap, block);
    }
    for (std::uint64_t block = ip_base;
         block < ip_base + ip_block_count; ++block)
    {
        set_bit(chunk_bitmap, block);
    }
    if (spec.authoritative_main_free_blocks != 0)
    {
        const auto is_set = [&chunk_bitmap](std::uint64_t block) {
            return (std::to_integer<unsigned int>(chunk_bitmap[block / 8]) &
                (1u << (block % 8))) != 0;
        };
        std::uint64_t free_blocks = 0;
        for (std::uint64_t block = 0; block < spec.block_count; ++block)
        {
            free_blocks += is_set(block) ? 0 : 1;
        }
        std::uint64_t blocks_to_reserve = free_blocks >
                spec.authoritative_main_free_blocks
            ? free_blocks - spec.authoritative_main_free_blocks
            : 0;
        for (std::uint64_t block = 0;
             block < spec.block_count && blocks_to_reserve != 0; ++block)
        {
            if (!is_set(block))
            {
                set_bit(chunk_bitmap, block);
                --blocks_to_reserve;
            }
        }
    }
    std::uint64_t allocated_blocks = 0;
    for (std::uint64_t block = 0; block < spec.block_count; ++block)
    {
        if ((std::to_integer<unsigned int>(chunk_bitmap[block / 8]) &
                (1u << (block % 8))) != 0)
        {
            ++allocated_blocks;
        }
    }
    put_block(chunk_bitmap_block, chunk_bitmap);

    std::vector<std::byte> ip_bitmap(bs, std::byte{0});
    set_bit(ip_bitmap, cib_block - ip_base);
    set_bit(ip_bitmap, chunk_bitmap_block - ip_base);
    put_block(ip_bitmap_base, ip_bitmap);

    auto cib = BuildEphemeralObject(cib_block, spec.xid,
        apfsaccess::catalog::kObjectPhysical |
            apfsaccess::catalog::kObjectTypeSpacemanCib,
        0, bs);
    PutU32LE(cib, 0x20, 0);
    PutU32LE(cib, 0x24, 1);
    PutU64LE(cib, 0x28, spec.xid);
    PutU64LE(cib, 0x30, 0);
    PutU32LE(cib, 0x38, static_cast<std::uint32_t>(spec.block_count));
    PutU32LE(cib, 0x3C,
        static_cast<std::uint32_t>(spec.block_count - allocated_blocks));
    PutU64LE(cib, 0x40, chunk_bitmap_block);
    FletcherForBlock(cib, bs);
    put_block(cib_block, cib);

    auto spaceman_object = BuildEphemeralObject(kSpacemanOid, spec.xid,
        spaceman.type, spaceman.subtype, bs);
    PutU32LE(spaceman_object, 0x20, spec.block_size);
    PutU32LE(spaceman_object, 0x24,
        static_cast<std::uint32_t>(spec.block_size * 8));
    PutU32LE(spaceman_object, 0x28,
        static_cast<std::uint32_t>((spec.block_size - 0x28) / 0x20));
    PutU32LE(spaceman_object, 0x2C,
        static_cast<std::uint32_t>((spec.block_size - 0x28) / 8));
    PutU64LE(spaceman_object, 0x30, spec.block_count);
    PutU64LE(spaceman_object, 0x38, 1);
    PutU32LE(spaceman_object, 0x40, 1);
    PutU64LE(spaceman_object, 0x48, spec.block_count - allocated_blocks);
    PutU32LE(spaceman_object, 0x50, 0x600);
    PutU32LE(spaceman_object, 0x94, ip_bitmap_rotation_count);
    PutU64LE(spaceman_object, 0x98, ip_block_count);
    PutU32LE(spaceman_object, 0xA0, 1);
    PutU32LE(spaceman_object, 0xA4, ip_bitmap_rotation_count);
    PutU64LE(spaceman_object, 0xA8, ip_bitmap_base);
    PutU64LE(spaceman_object, 0xB0, ip_base);
    PutU64LE(spaceman_object, 0xC0, 0xDEADBEEFDEADBEEFull);
    PutU64LE(spaceman_object, 0xD0, kFreeQueueOid);
    PutU16LE(spaceman_object, 0xE0, 64);
    PutU64LE(spaceman_object, 0xF8, kMainFreeQueueOid);
    PutU16LE(spaceman_object, 0x108, 64);
    PutU16LE(spaceman_object, 0x140, 1);
    PutU16LE(spaceman_object, 0x142,
        static_cast<std::uint16_t>(ip_bitmap_rotation_count - 1));
    PutU32LE(spaceman_object, 0x144, 0x700);
    PutU32LE(spaceman_object, 0x148, 0x708);
    PutU32LE(spaceman_object, 0x14C, 0x720);
    PutU32LE(spaceman_object, 0x150, 1);
    PutU32LE(spaceman_object, 0x154, 0x800);
    PutU64LE(spaceman_object, 0x600, cib_block);
    PutU64LE(spaceman_object, 0x700, spec.xid);
    PutU16LE(spaceman_object, 0x708, 0);
    PutU16LE(spaceman_object, 0x720, 0xFFFF);
    for (std::uint16_t index = 1; index < ip_bitmap_rotation_count; ++index)
    {
        PutU16LE(spaceman_object, 0x720 + index * 2,
            index + 1 == ip_bitmap_rotation_count
                ? 0xFFFF
                : static_cast<std::uint16_t>(index + 1));
    }
    FletcherForBlock(spaceman_object, bs);
    put_block(data_base, spaceman_object);
    return image;
}

inline std::vector<std::byte> BuildGptImage(const BuilderImage& spec)
{
    const std::uint64_t kSector = spec.sector_size;
    constexpr std::uint64_t kLegacyStoreBytes = 64 * 4096;
    const std::uint64_t first_lba = 40;
    std::uint64_t total_sectors = first_lba;
    for (const auto& store : spec.stores)
    {
        total_sectors += EffectiveStoreBlockCount(store) * store.block_size / kSector;
    }
    for (std::size_t i = 0; i < spec.extra_partition_type_guids.size(); ++i)
    {
        total_sectors += kLegacyStoreBytes / kSector;
    }
    total_sectors += 33;
    std::vector<std::byte> image(static_cast<std::size_t>(total_sectors) * kSector, std::byte{0});

    std::vector<std::byte> header(kSector, std::byte{0});
    PutBytes(header, 0, "EFI PART", 8);
    PutU32LE(header, 8, 0x00010000);
    PutU32LE(header, 12, 92);
    PutU64LE(header, 24, 1);
    PutU64LE(header, 32, total_sectors - 1);
    PutU64LE(header, 40, 34);
    PutU64LE(header, 48, total_sectors - 34);
    const auto disk_guid = GuidToMixedEndian("11111111-2222-3333-4444-555555555555");
    for (std::size_t i = 0; i < 16; ++i)
    {
        header[56 + i] = disk_guid[i];
    }
    PutU64LE(header, 72, 2);
    PutU32LE(header, 80, 128);
    PutU32LE(header, 84, 128);

    std::vector<std::byte> entries(128 * 128, std::byte{0});
    std::uint64_t lba = first_lba;
    std::size_t entry_index = 0;
    auto write_entry = [&](const std::vector<std::byte>& type_guid, const std::string& unique_text,
        std::uint64_t sectors)
    {
        const auto unique_guid = GuidToMixedEndian(unique_text);
        const std::size_t base = entry_index * 128;
        for (std::size_t b = 0; b < 16; ++b)
        {
            entries[base + b] = type_guid[b];
            entries[base + 16 + b] = unique_guid[b];
        }
        PutU64LE(entries, base + 32, lba);
        PutU64LE(entries, base + 40, lba + sectors - 1);
        const wchar_t* label = L"APFS";
        for (int c = 0; c < 4; ++c)
        {
            PutU16LE(entries, base + 56 + static_cast<std::size_t>(c) * 2,
                static_cast<std::uint16_t>(label[c]));
        }
        lba += sectors;
        ++entry_index;
    };
    const auto apfs_type = GuidToMixedEndian("7C3457EF-0000-11AA-AA11-00306543ECAC");
    for (std::size_t i = 0; i < spec.stores.size(); ++i)
    {
        char unique[64];
        std::snprintf(unique, sizeof(unique), "20000000-0000-4000-8000-%012zu", i + 1);
        const std::uint64_t store_lba = lba;
        const auto store_sectors = EffectiveStoreBlockCount(spec.stores[i]) *
            spec.stores[i].block_size / kSector;
        write_entry(apfs_type, unique, store_sectors);
        const auto store_image = BuildStoreImage(spec.stores[i]);
        const std::size_t store_offset = static_cast<std::size_t>(store_lba) * kSector;
        for (std::size_t b = 0; b < store_image.size() && store_offset + b < image.size(); ++b)
        {
            image[store_offset + b] = store_image[b];
        }
    }
    for (std::size_t i = 0; i < spec.extra_partition_type_guids.size(); ++i)
    {
        char unique[64];
        std::snprintf(unique, sizeof(unique), "30000000-0000-4000-8000-%012zu", i + 1);
        write_entry(GuidToMixedEndian(spec.extra_partition_type_guids[i]), unique,
            kLegacyStoreBytes / kSector);
    }
    const auto entries_crc = apfsaccess::catalog::Crc32(entries.data(), entries.size());
    PutU32LE(header, 88, entries_crc);
    auto header_crc = apfsaccess::catalog::Crc32(header.data(), 92);
    if (spec.bad_gpt_header_crc)
    {
        header_crc ^= 0xFFFFFFFFu;
    }
    PutU32LE(header, 16, header_crc);
    if (spec.bad_gpt_entries_crc)
    {
        entries[0] = static_cast<std::byte>(static_cast<unsigned char>(entries[0]) ^ 0xFFu);
    }
    for (std::size_t i = 0; i < kSector; ++i)
    {
        image[kSector + i] = header[i];
    }
    const std::size_t entries_offset = 2 * static_cast<std::size_t>(kSector);
    for (std::size_t i = 0; i < entries.size(); ++i)
    {
        image[entries_offset + i] = entries[i];
    }
    if (spec.truncate_bytes != 0 && spec.truncate_bytes < image.size())
    {
        image.resize(static_cast<std::size_t>(spec.truncate_bytes));
    }
    return image;
}

inline std::vector<std::byte> BuildTestImage(const BuilderImage& spec)
{
    if (spec.gpt)
    {
        return BuildGptImage(spec);
    }
    auto image = BuildStoreImage(spec.stores.front());
    if (spec.truncate_bytes != 0 && spec.truncate_bytes < image.size())
    {
        image.resize(static_cast<std::size_t>(spec.truncate_bytes));
    }
    if (spec.zero_nxsb_magic)
    {
        PutU32LE(image, 0x20, 0);
    }
    return image;
}

// ---- GPT post-patch helpers (adversarial vectors) ----------------------------

inline void RecomputeGptCrcs(std::vector<std::byte>& image, std::uint64_t sector)
{
    std::vector<std::byte> entries(128 * 128, std::byte{0});
    for (std::size_t i = 0; i < entries.size(); ++i)
    {
        entries[i] = image[2 * static_cast<std::size_t>(sector) + i];
    }
    PutU32LE(image, static_cast<std::size_t>(sector) + 88,
        apfsaccess::catalog::Crc32(entries.data(), entries.size()));
    std::vector<std::byte> header(92, std::byte{0});
    for (std::size_t i = 0; i < 92; ++i)
    {
        header[i] = image[static_cast<std::size_t>(sector) + i];
    }
    PutU32LE(header, 16, 0);
    PutU32LE(image, static_cast<std::size_t>(sector) + 16,
        apfsaccess::catalog::Crc32(header.data(), header.size()));
}
} // namespace apfsaccess::testfixture
