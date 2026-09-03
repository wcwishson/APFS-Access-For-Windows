// Task 1 compatibility vectors: portable format primitives, GPT/container/
// volume parsing, and catalog topology over synthetic images.
//
// The synthetic builder below writes the exact byte contract from
// task-1-interface-freeze.md section 5; the parser under test must read it
// back. A second builder lives in managed SyntheticApfsTestImage (test-only
// fixture writer, never a parser); the fixed repo-owned observer
// cross-validates both.

#include "ApfsContainerCatalog.h"
#include "ApfsFormat.h"
#include "RandomAccessSource.h"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

namespace
{
int g_failures = 0;

bool Require(bool condition, const std::string& message)
{
    if (!condition)
    {
        std::cerr << "[FAIL] " << message << std::endl;
        ++g_failures;
        return false;
    }
    return true;
}

void PutU16LE(std::vector<std::byte>& buffer, std::size_t offset, std::uint16_t value)
{
    buffer[offset] = static_cast<std::byte>(value & 0xffu);
    buffer[offset + 1] = static_cast<std::byte>((value >> 8) & 0xffu);
}

void PutU32LE(std::vector<std::byte>& buffer, std::size_t offset, std::uint32_t value)
{
    for (int index = 0; index < 4; ++index)
    {
        buffer[offset + static_cast<std::size_t>(index)] =
            static_cast<std::byte>((value >> (index * 8)) & 0xffu);
    }
}

void PutU64LE(std::vector<std::byte>& buffer, std::size_t offset, std::uint64_t value)
{
    for (int index = 0; index < 8; ++index)
    {
        buffer[offset + static_cast<std::size_t>(index)] =
            static_cast<std::byte>((value >> (index * 8)) & 0xffu);
    }
}

void PutBytes(std::vector<std::byte>& buffer, std::size_t offset, const char* text, std::size_t size)
{
    for (std::size_t index = 0; index < size; ++index)
    {
        buffer[offset + index] = static_cast<std::byte>(text[index]);
    }
}

std::vector<std::byte> HexToBytes(const std::string& hex)
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
std::vector<std::byte> GuidToMixedEndian(const std::string& guid)
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

struct BuilderVolume
{
    std::uint64_t oid = 101;
    std::string name = "Data";
    std::string uuid_hex; // "" = deterministic filler
    std::uint16_t role = 32;
    std::uint64_t fs_flags = 0x1;
    std::uint64_t features = 0x1;
    std::uint64_t ro_features = 0;
    std::uint64_t incompat = 0;
    std::int64_t xid_offset = 0; // added to container xid (stale vector)
    std::string group_hex; // "" = zero
    bool bad_checksum = false;
};

struct BuilderStore
{
    std::string uuid_hex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    std::uint64_t xid = 7;
    std::uint32_t block_size = 4096;
    std::uint64_t block_count = 64;
    std::vector<BuilderVolume> volumes{ BuilderVolume{} };
    bool dual_checkpoint = true;
    std::uint64_t second_xid_offset = 0; // 0 = same xid on block 1
    std::string second_uuid_hex; // "" = same uuid
};

struct BuilderImage
{
    bool gpt = true;
    std::vector<BuilderStore> stores{ BuilderStore{} };
    bool bad_gpt_header_crc = false;
    bool bad_gpt_entries_crc = false;
    std::uint64_t truncate_bytes = 0; // 0 = no truncation
    bool zero_nxsb_magic = false;
};

constexpr std::uint64_t kOmapOid = 2;
constexpr std::uint64_t kBtreeBlock = 3;
constexpr std::uint64_t kFirstVolumeBlock = 4;

std::uint64_t FletcherForBlock(std::vector<std::byte>& block, std::size_t size)
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

std::vector<std::byte> BuildApsb(
    const BuilderVolume& spec, std::uint64_t container_xid, std::size_t block_size)
{
    std::vector<std::byte> block(block_size, std::byte{0});
    const std::uint64_t xid = container_xid + static_cast<std::uint64_t>(spec.xid_offset);
    PutU64LE(block, 0x08, spec.oid);
    PutU64LE(block, 0x10, xid);
    PutU32LE(block, 0x18, 0x0000000D);
    PutU32LE(block, 0x20, 0x42535041);
    PutU32LE(block, 0x24, 1);
    PutU64LE(block, 0x28, spec.features);
    PutU64LE(block, 0x30, spec.ro_features);
    PutU64LE(block, 0x38, spec.incompat);
    PutU64LE(block, 0x80, 0x1000 + spec.oid);
    PutU64LE(block, 0x88, 0x2000 + spec.oid);
    PutU64LE(block, 0x90, 0);
    PutU64LE(block, 0xB8, 11);
    PutU64LE(block, 0xC0, 3);
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
        block[0x120 + i] = static_cast<std::byte>(spec.name[i]);
    }
    PutU16LE(block, 0x224, spec.role);
    const auto group = spec.group_hex.empty() ? std::vector<std::byte>(16, std::byte{0}) : HexToBytes(spec.group_hex);
    for (std::size_t i = 0; i < 16 && i < group.size(); ++i)
    {
        block[0x228 + i] = group[i];
    }
    FletcherForBlock(block, block_size);
    if (spec.bad_checksum)
    {
        block[0] = static_cast<std::byte>(static_cast<unsigned char>(block[0]) ^ 0xFFu);
    }
    return block;
}

std::vector<std::byte> BuildBtreeNode(
    const std::vector<std::pair<std::uint64_t, std::uint64_t>>& oid_to_block,
    std::uint64_t xid,
    std::size_t block_size)
{
    std::vector<std::byte> block(block_size, std::byte{0});
    PutU64LE(block, 0x10, xid);
    PutU32LE(block, 0x18, 0x00000002);
    PutU16LE(block, 0x20, 0x0003); // root | leaf
    PutU16LE(block, 0x22, 0); // level 0
    const auto count = static_cast<std::uint32_t>(oid_to_block.size());
    PutU32LE(block, 0x24, count);
    PutU16LE(block, 0x28, 0); // table_offset
    PutU16LE(block, 0x2A, static_cast<std::uint16_t>(count * 8)); // table_length
    const std::size_t table_start = 0x38;
    const std::size_t key_area = table_start + count * 8;
    const std::size_t info_start = block_size - 40;
    const std::size_t value_end = info_start;
    for (std::uint32_t i = 0; i < count; ++i)
    {
        PutU16LE(block, table_start + i * 8, static_cast<std::uint16_t>(i * 16));
        PutU16LE(block, table_start + i * 8 + 2, 16);
        PutU16LE(block, table_start + i * 8 + 4, static_cast<std::uint16_t>((i + 1) * 16));
        PutU16LE(block, table_start + i * 8 + 6, 16);
        PutU64LE(block, key_area + i * 16, oid_to_block[i].first);
        PutU64LE(block, key_area + i * 16 + 8, xid);
        const std::size_t value_start = value_end - (i + 1) * 16;
        PutU32LE(block, value_start, 0); // flags
        PutU32LE(block, value_start + 4, 4096); // size
        PutU64LE(block, value_start + 8, oid_to_block[i].second); // paddr
    }
    const std::size_t keys_end = key_area + count * 16;
    const std::size_t values_start = value_end - count * 16;
    PutU16LE(block, 0x2C, static_cast<std::uint16_t>(keys_end - key_area)); // free_offset
    PutU16LE(block, 0x2E, static_cast<std::uint16_t>(values_start - keys_end)); // free_length
    PutU32LE(block, info_start + 8, 16);
    PutU32LE(block, info_start + 12, 16);
    FletcherForBlock(block, block_size);
    return block;
}

std::vector<std::byte> BuildOmap(std::uint64_t tree_block, std::uint64_t xid, std::size_t block_size)
{
    std::vector<std::byte> block(block_size, std::byte{0});
    PutU64LE(block, 0x08, kOmapOid);
    PutU64LE(block, 0x10, xid);
    PutU32LE(block, 0x18, 0x0000000B);
    PutU64LE(block, 0x30, tree_block);
    FletcherForBlock(block, block_size);
    return block;
}

std::vector<std::byte> BuildNxsb(
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
    const auto uuid = HexToBytes(uuid_hex.empty() ? spec.uuid_hex : uuid_hex);
    for (std::size_t i = 0; i < 16 && i < uuid.size(); ++i)
    {
        block[0x48 + i] = uuid[i];
    }
    PutU64LE(block, 0xA0, kOmapOid);
    for (std::size_t i = 0; i < spec.volumes.size(); ++i)
    {
        PutU64LE(block, 0xB8 + i * 8, spec.volumes[i].oid);
    }
    FletcherForBlock(block, block_size);
    return block;
}

std::vector<std::byte> BuildStoreImage(const BuilderStore& spec)
{
    const std::size_t bs = spec.block_size;
    const std::size_t total = static_cast<std::size_t>(spec.block_count) * bs;
    std::vector<std::byte> image(total, std::byte{0});
    auto put_block = [&](std::uint64_t index, const std::vector<std::byte>& block) {
        const std::size_t offset = static_cast<std::size_t>(index) * bs;
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
    put_block(kOmapOid, BuildOmap(kBtreeBlock, spec.xid, bs));
    std::vector<std::pair<std::uint64_t, std::uint64_t>> mappings;
    for (std::size_t i = 0; i < spec.volumes.size(); ++i)
    {
        mappings.emplace_back(spec.volumes[i].oid, kFirstVolumeBlock + i);
    }
    put_block(kBtreeBlock, BuildBtreeNode(mappings, spec.xid, bs));
    for (std::size_t i = 0; i < spec.volumes.size(); ++i)
    {
        put_block(kFirstVolumeBlock + i, BuildApsb(spec.volumes[i], spec.xid, bs));
    }
    return image;
}

std::vector<std::byte> BuildGptImage(const BuilderImage& spec)
{
    constexpr std::uint64_t kSector = 512;
    constexpr std::uint64_t kStoreBlocks = 64;
    constexpr std::uint64_t kStoreBytes = kStoreBlocks * 4096;
    const std::uint64_t first_lba = 40;
    std::uint64_t total_sectors = first_lba;
    for (std::size_t i = 0; i < spec.stores.size(); ++i)
    {
        total_sectors += kStoreBytes / kSector;
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
    for (std::size_t i = 0; i < spec.stores.size(); ++i)
    {
        const auto type_guid = GuidToMixedEndian("7C3457EF-0000-11AA-AA11-00306543ECAC");
        char unique[64];
        std::snprintf(unique, sizeof(unique), "20000000-0000-4000-8000-%012zu", i + 1);
        const auto unique_guid = GuidToMixedEndian(unique);
        const std::size_t base = i * 128;
        for (std::size_t b = 0; b < 16; ++b)
        {
            entries[base + b] = type_guid[b];
            entries[base + 16 + b] = unique_guid[b];
        }
        const std::uint64_t sectors = kStoreBytes / kSector;
        PutU64LE(entries, base + 32, lba);
        PutU64LE(entries, base + 40, lba + sectors - 1);
        const wchar_t* label = L"APFS";
        for (int c = 0; c < 4; ++c)
        {
            PutU16LE(entries, base + 56 + static_cast<std::size_t>(c) * 2,
                static_cast<std::uint16_t>(label[c]));
        }
        const auto store_image = BuildStoreImage(spec.stores[i]);
        const std::size_t store_offset = static_cast<std::size_t>(lba) * kSector;
        for (std::size_t b = 0; b < store_image.size() && store_offset + b < image.size(); ++b)
        {
            image[store_offset + b] = store_image[b];
        }
        lba += sectors;
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

std::vector<std::byte> BuildTestImage(const BuilderImage& spec)
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

// ---- primitive tests ---------------------------------------------------------

bool TestLeReaders()
{
    bool ok = true;
    const std::vector<std::byte> bytes = {
        std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04},
        std::byte{0x05}, std::byte{0x06}, std::byte{0x07}, std::byte{0x08},
    };
    using apfsaccess::catalog::ReadU16LE;
    using apfsaccess::catalog::ReadU32LE;
    using apfsaccess::catalog::ReadU64LE;
    ok &= Require(ReadU16LE(bytes, 0).value_or(0) == 0x0201, "le16 basic");
    ok &= Require(ReadU32LE(bytes, 0).value_or(0) == 0x04030201u, "le32 basic");
    ok &= Require(ReadU64LE(bytes, 0).value_or(0) == 0x0807060504030201ull, "le64 basic");
    ok &= Require(!ReadU16LE(bytes, 7).has_value(), "le16 past end");
    ok &= Require(!ReadU32LE(bytes, 5).has_value(), "le32 past end");
    ok &= Require(!ReadU64LE(bytes, 1).has_value(), "le64 past end");
    ok &= Require(ReadU16LE(bytes, 6).value_or(0) == 0x0807, "le16 exact end");
    return ok;
}

bool TestFletcher64()
{
    using apfsaccess::catalog::Fletcher64;
    using apfsaccess::catalog::VerifyObjectChecksum;
    bool ok = true;
    // Known answer cross-checked with an independent Python implementation of
    // NativeApfsBackend.ComputeApfsObjectChecksum over bytes 1..56.
    std::vector<std::byte> payload(56, std::byte{0});
    for (std::size_t i = 0; i < payload.size(); ++i)
    {
        payload[i] = static_cast<std::byte>(i + 1);
    }
    const auto digest = Fletcher64(payload.data(), payload.size());
    ok &= Require(digest.has_value() && digest.value() == 0xC85EF58D920980F6ull,
        "fletcher64 known answer");
    ok &= Require(!Fletcher64(payload.data(), 55).has_value(), "fletcher64 rejects odd size");
    ok &= Require(!Fletcher64(payload.data(), 0).has_value(), "fletcher64 rejects empty");

    std::vector<std::byte> block(64, std::byte{0});
    for (std::size_t i = 8; i < block.size(); ++i)
    {
        block[i] = static_cast<std::byte>(i - 7);
    }
    FletcherForBlock(block, block.size());
    ok &= Require(VerifyObjectChecksum(block, block.size()), "object checksum round trip");
    block[20] = static_cast<std::byte>(static_cast<unsigned char>(block[20]) ^ 0x01u);
    ok &= Require(!VerifyObjectChecksum(block, block.size()), "object checksum bit flip");
    for (int i = 0; i < 8; ++i)
    {
        block[static_cast<std::size_t>(i)] = std::byte{0};
    }
    ok &= Require(!VerifyObjectChecksum(block, block.size()), "object checksum zero rejected");
    for (int i = 0; i < 8; ++i)
    {
        block[static_cast<std::size_t>(i)] = std::byte{0xFF};
    }
    ok &= Require(!VerifyObjectChecksum(block, block.size()), "object checksum ones rejected");
    return ok;
}

bool TestCrc32()
{
    using apfsaccess::catalog::Crc32;
    bool ok = true;
    const char* text = "123456789";
    std::vector<std::byte> bytes(9, std::byte{0});
    for (std::size_t i = 0; i < 9; ++i)
    {
        bytes[i] = static_cast<std::byte>(text[i]);
    }
    ok &= Require(Crc32(bytes.data(), bytes.size()) == 0xCBF43926u, "crc32 check value");
    ok &= Require(Crc32(bytes.data(), 0) == 0u, "crc32 empty");
    return ok;
}

bool TestGuidStrings()
{
    using apfsaccess::catalog::BytesToHexLower;
    using apfsaccess::catalog::GuidToStringLower;
    bool ok = true;
    const auto guid_bytes = GuidToMixedEndian("7C3457EF-0000-11AA-AA11-00306543ECAC");
    const std::array<std::byte, 16> expected = {
        std::byte{0xEF}, std::byte{0x57}, std::byte{0x34}, std::byte{0x7C},
        std::byte{0x00}, std::byte{0x00}, std::byte{0xAA}, std::byte{0x11},
        std::byte{0xAA}, std::byte{0x11}, std::byte{0x00}, std::byte{0x30},
        std::byte{0x65}, std::byte{0x43}, std::byte{0xEC}, std::byte{0xAC},
    };
    ok &= Require(guid_bytes.size() == 16, "guid byte count");
    for (std::size_t i = 0; i < 16 && ok; ++i)
    {
        ok &= Require(guid_bytes[i] == expected[i], "guid mixed-endian bytes");
    }
    ok &= Require(GuidToStringLower(expected.data()) == "7c3457ef-0000-11aa-aa11-00306543ecac",
        "guid round trip");
    ok &= Require(BytesToHexLower(expected.data(), 4) == "ef57347c", "hex lower");
    return ok;
}

bool TestGptRoundTrip()
{
    using apfsaccess::catalog::ParseGpt;
    using apfsaccess::catalog::VectorRandomAccessSource;
    bool ok = true;
    BuilderImage spec;
    spec.stores.resize(2);
    const auto image = BuildTestImage(spec);
    VectorRandomAccessSource source(image);
    const auto layout = ParseGpt(source, 0, image.size());
    ok &= Require(layout.has_value(), "gpt parses");
    if (!layout.has_value())
    {
        return false;
    }
    ok &= Require(layout->sector_size == 512, "gpt sector size");
    ok &= Require(layout->partitions.size() == 2, "gpt partition count");
    if (layout->partitions.size() == 2)
    {
        ok &= Require(layout->partitions[0].number == 1, "gpt partition number");
        ok &= Require(layout->partitions[0].type_guid == "7c3457ef-0000-11aa-aa11-00306543ecac",
            "gpt apfs type guid");
        ok &= Require(layout->partitions[0].start_bytes == 40 * 512, "gpt start offset");
        ok &= Require(layout->partitions[0].size_bytes == 64 * 4096, "gpt size");
        ok &= Require(layout->partitions[1].number == 2, "gpt second number");
    }
    return ok;
}

bool TestGptRejections()
{
    using apfsaccess::catalog::ParseGpt;
    using apfsaccess::catalog::VectorRandomAccessSource;
    bool ok = true;
    {
        BuilderImage spec;
        spec.bad_gpt_header_crc = true;
        const auto image = BuildTestImage(spec);
        VectorRandomAccessSource source(image);
        ok &= Require(!ParseGpt(source, 0, image.size()).has_value(), "gpt bad header crc");
    }
    {
        BuilderImage spec;
        spec.bad_gpt_entries_crc = true;
        const auto image = BuildTestImage(spec);
        VectorRandomAccessSource source(image);
        ok &= Require(!ParseGpt(source, 0, image.size()).has_value(), "gpt bad entries crc");
    }
    {
        BuilderImage spec;
        spec.truncate_bytes = 4 * 512;
        const auto image = BuildTestImage(spec);
        VectorRandomAccessSource source(image);
        ok &= Require(!ParseGpt(source, 0, image.size()).has_value(), "gpt truncated");
    }
    {
        // Zero sector: neither GPT nor NXSB.
        const std::vector<std::byte> zeros(8192, std::byte{0});
        VectorRandomAccessSource source(zeros);
        ok &= Require(!ParseGpt(source, 0, zeros.size()).has_value(), "gpt blank");
    }
    return ok;
}

bool TestNxsbRoundTrip()
{
    using apfsaccess::catalog::ParseNxSuperblock;
    using apfsaccess::catalog::SelectContainerCheckpoint;
    using apfsaccess::catalog::VectorRandomAccessSource;
    bool ok = true;
    BuilderStore store;
    store.uuid_hex = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    store.xid = 9;
    {
        const auto block = BuildNxsb(store, store.xid, "", store.block_size);
        const auto parsed = ParseNxSuperblock(block);
        ok &= Require(parsed.has_value(), "nxsb parses");
        if (parsed.has_value())
        {
            ok &= Require(parsed->xid == 9, "nxsb xid");
            ok &= Require(parsed->block_size == 4096, "nxsb block size");
            ok &= Require(parsed->block_count == 64, "nxsb block count");
            ok &= Require(parsed->uuid_hex == "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "nxsb uuid");
            ok &= Require(parsed->omap_oid == kOmapOid, "nxsb omap");
            ok &= Require(parsed->fs_oids.size() == 1 && parsed->fs_oids[0] == 101, "nxsb fs oids");
        }
    }
    {
        // Newest checkpoint wins between blocks 0 and 1.
        BuilderStore newer = store;
        newer.second_xid_offset = 3;
        auto image = BuildStoreImage(newer);
        VectorRandomAccessSource source(image);
        const auto selected = SelectContainerCheckpoint(source, 0, image.size());
        ok &= Require(selected.has_value() && selected->xid == 12, "checkpoint newest wins");
    }
    {
        // Mismatched container UUIDs across the two blocks fail closed.
        BuilderStore mixed = store;
        mixed.second_uuid_hex = "cccccccccccccccccccccccccccccccc";
        auto image = BuildStoreImage(mixed);
        VectorRandomAccessSource source(image);
        ok &= Require(!SelectContainerCheckpoint(source, 0, image.size()).has_value(),
            "checkpoint uuid mismatch");
    }
    {
        // Corrupt primary is tolerated when the secondary validates.
        auto image = BuildStoreImage(store);
        for (int i = 0; i < 8; ++i)
        {
            image[static_cast<std::size_t>(i)] = std::byte{0xFF};
        }
        VectorRandomAccessSource source(image);
        const auto selected = SelectContainerCheckpoint(source, 0, image.size());
        ok &= Require(selected.has_value() && selected->xid == 9, "checkpoint secondary fallback");
    }
    {
        auto block = BuildNxsb(store, store.xid, "", store.block_size);
        PutU32LE(block, 0x24, 0);
        ok &= Require(!ParseNxSuperblock(block).has_value(), "nxsb zero block size");
    }
    return ok;
}

bool TestApsbRoundTrip()
{
    using apfsaccess::catalog::ParseApsb;
    bool ok = true;
    BuilderVolume spec;
    spec.oid = 4242;
    spec.name = "Café Data";
    spec.uuid_hex = "1234567890abcdef1234567890abcdef";
    spec.role = 32;
    spec.fs_flags = 0x1;
    spec.features = 0x3;
    spec.group_hex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1";
    const auto image = BuildApsb(spec, 7, 4096);
    const auto parsed = ParseApsb(image);
    ok &= Require(parsed.has_value(), "apsb parses");
    if (parsed.has_value())
    {
        ok &= Require(parsed->object_id == 4242, "apsb oid");
        ok &= Require(parsed->xid == 7, "apsb xid");
        ok &= Require(parsed->omap_oid == 0x1000 + 4242, "apsb omap");
        ok &= Require(parsed->root_oid == 0x2000 + 4242, "apsb root");
        ok &= Require(parsed->uuid_hex == "1234567890abcdef1234567890abcdef", "apsb uuid");
        ok &= Require(parsed->name_valid && parsed->name_utf8 == "Café Data", "apsb name");
        ok &= Require(parsed->fs_flags == 0x1, "apsb flags");
        ok &= Require(parsed->role_raw == 32, "apsb role");
        ok &= Require(parsed->group_hex == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1", "apsb group");
        ok &= Require(parsed->features == 0x3, "apsb features");
    }
    {
        auto bad = image;
        PutU32LE(bad, 0x20, 0xDEADBEEFu);
        ok &= Require(!ParseApsb(bad).has_value(), "apsb bad magic");
    }
    {
        auto bad = image;
        bad[8] = static_cast<std::byte>(0xFF);
        bad[9] = static_cast<std::byte>(0xFF);
        bad[10] = static_cast<std::byte>(0xFF);
        bad[11] = static_cast<std::byte>(0xFF);
        bad[12] = static_cast<std::byte>(0xFF);
        bad[13] = static_cast<std::byte>(0xFF);
        bad[14] = static_cast<std::byte>(0xFF);
        bad[15] = static_cast<std::byte>(0xFF);
        ok &= Require(!ParseApsb(bad).has_value(), "apsb zero oid");
    }
    {
        // Non-UTF8 names are reported, not trusted.
        BuilderVolume evil = spec;
        evil.name = std::string("bad\xff\xfe");
        const auto evil_image = BuildApsb(evil, 7, 4096);
        const auto evil_parsed = ParseApsb(evil_image);
        ok &= Require(evil_parsed.has_value() && !evil_parsed->name_valid &&
            evil_parsed->name_utf8.empty(), "apsb invalid name");
    }
    return ok;
}

bool TestOmapResolve()
{
    using apfsaccess::catalog::ResolveOmapValue;
    using apfsaccess::catalog::VectorRandomAccessSource;
    bool ok = true;
    BuilderStore store;
    store.volumes = {BuilderVolume{}, BuilderVolume{}, BuilderVolume{}};
    store.volumes[0].oid = 101;
    store.volumes[1].oid = 102;
    store.volumes[2].oid = 103;
    auto image = BuildStoreImage(store);
    VectorRandomAccessSource source(image);
    std::string error;
    const auto hit = ResolveOmapValue(source, 4096, kOmapOid, 102, store.xid, error);
    ok &= Require(hit.has_value() && hit->physical_block == kFirstVolumeBlock + 1,
        "omap resolves oid");
    ok &= Require(!ResolveOmapValue(source, 4096, kOmapOid, 9999, store.xid, error).has_value(),
        "omap missing oid");
    // Newer-than-max xid entries are invisible (stale record filtering).
    auto future = BuildBtreeNode({{101, 40}}, store.xid + 100, 4096);
    std::vector<std::byte> patched = image;
    for (std::size_t i = 0; i < future.size(); ++i)
    {
        patched[3 * 4096 + i] = future[i];
    }
    VectorRandomAccessSource patched_source(patched);
    ok &= Require(!ResolveOmapValue(patched_source, 4096, kOmapOid, 101, store.xid, error).has_value(),
        "omap future xid hidden");
    // Truncated btree fails instead of returning partial maps.
    std::vector<std::byte> cut(image.begin(), image.begin() + 3 * 4096 + 100);
    VectorRandomAccessSource cut_source(cut);
    ok &= Require(!ResolveOmapValue(cut_source, 4096, kOmapOid, 101, store.xid, error).has_value(),
        "omap truncated btree");
    return ok;
}

bool TestInterpretation()
{
    using apfsaccess::catalog::CaseModeFor;
    using apfsaccess::catalog::EncryptionModeFor;
    using apfsaccess::catalog::HexBits;
    using apfsaccess::catalog::RolesFor;
    using apfsaccess::catalog::UnknownBits;
    bool ok = true;
    ok &= Require(CaseModeFor(0x10) == "insensitive", "case insensitive bit");
    ok &= Require(CaseModeFor(0x0) == "sensitive", "case sensitive default");
    ok &= Require(EncryptionModeFor(0x0) == "none", "encryption zero");
    ok &= Require(EncryptionModeFor(0x1) == "none", "encryption unencrypted bit");
    ok &= Require(EncryptionModeFor(0x8) == "password", "encryption onekey");
    ok &= Require(EncryptionModeFor(0x2) == "hardware-bound", "encryption effaceable");
    ok &= Require(EncryptionModeFor(0x40) == "unknown", "encryption unknown pattern");
    ok &= Require(RolesFor(0) == std::vector<std::string>{"data"}, "role zero is data");
    ok &= Require(RolesFor(1) == std::vector<std::string>{"system"}, "role system");
    ok &= Require(RolesFor(64) == std::vector<std::string>{"baseband"}, "role baseband");
    ok &= Require(RolesFor(2048) == std::vector<std::string>{"backup"}, "role backup");
    ok &= Require(RolesFor(0x8000).size() == 1 && RolesFor(0x8000)[0] == "unknown",
        "role unknown bit");
    const auto bits = HexBits(0x8000000000000001ull);
    ok &= Require(bits.size() == 2 && bits[0] == "0x1" && bits[1] == "0x8000000000000000",
        "hex bits span 64 bits");
    const auto unknown = UnknownBits(0x13, 0x10);
    ok &= Require(unknown.size() == 2 && unknown[0] == "0x1" && unknown[1] == "0x2",
        "unknown bits mask");
    return ok;
}

// ---- catalog tests ------------------------------------------------------------

bool LoadCatalog(const std::vector<std::byte>& image, apfsaccess::catalog::ApfsContainerCatalog& catalog,
    std::string& error, const std::string& disk = "test")
{
    apfsaccess::catalog::VectorRandomAccessSource source(image);
    return apfsaccess::catalog::ApfsContainerCatalog::TryLoadImage(
        source, disk, disk, catalog, error);
}

bool TestCatalogSingleVolume()
{
    using apfsaccess::catalog::ApfsContainerCatalog;
    bool ok = true;
    BuilderImage spec;
    spec.stores.front().uuid_hex = "dddddddddddddddddddddddddddddddd";
    spec.stores.front().volumes.front().name = "Main";
    const auto image = BuildTestImage(spec);
    ApfsContainerCatalog catalog;
    std::string error;
    ok &= Require(LoadCatalog(image, catalog, error), "catalog loads: " + error);
    if (!ok)
    {
        return false;
    }
    ok &= Require(catalog.DiskId() == "apfs-disk:test", "catalog disk id");
    ok &= Require(catalog.Partitions().size() == 1, "catalog one partition");
    ok &= Require(catalog.Stores().size() == 1, "catalog one store");
    ok &= Require(catalog.Containers().size() == 1, "catalog one container");
    const auto& container = catalog.Containers().front();
    ok &= Require(container.container_uuid_hex == "dddddddddddddddddddddddddddddddd",
        "catalog container uuid");
    ok &= Require(!container.fusion, "catalog not fusion");
    ok &= Require(container.checkpoint_xid == 7, "catalog xid");
    ok &= Require(container.volumes.size() == 1, "catalog one volume");
    if (!container.volumes.empty())
    {
        const auto& volume = container.volumes.front();
        ok &= Require(volume.object_id == 101, "catalog volume oid");
        ok &= Require(volume.name_utf8 == "Main" && volume.name_valid, "catalog volume name");
        ok &= Require(volume.roles.size() == 1 && volume.roles[0] == "data", "catalog role");
        ok &= Require(volume.case_mode == "sensitive", "catalog case mode");
        ok &= Require(volume.encryption_mode == "none" && !volume.locked, "catalog unlocked");
        ok &= Require(volume.superblock_block == kFirstVolumeBlock, "catalog volume block");
    }
    ok &= Require(catalog.Stores().front().stable_store_id ==
        "apfs-store:" + catalog.Partitions().front().partition_guid, "catalog store id");
    ok &= Require(catalog.Stores().front().partition_id ==
        catalog.Partitions().front().stable_partition_id, "catalog store edge");
    return ok;
}

bool TestCatalogPartitionless()
{
    using apfsaccess::catalog::ApfsContainerCatalog;
    bool ok = true;
    BuilderImage spec;
    spec.gpt = false;
    const auto image = BuildTestImage(spec);
    ApfsContainerCatalog catalog;
    std::string error;
    ok &= Require(LoadCatalog(image, catalog, error), "partitionless loads: " + error);
    if (!ok)
    {
        return false;
    }
    ok &= Require(catalog.Partitions().empty(), "partitionless has no partitions");
    ok &= Require(catalog.Stores().size() == 1, "partitionless one store");
    ok &= Require(catalog.Stores().front().stable_store_id == "apfs-store:raw",
        "partitionless store id");
    ok &= Require(catalog.Containers().size() == 1 &&
        catalog.Containers().front().volumes.size() == 1, "partitionless volume");
    return ok;
}

bool TestCatalogNoGptNoNxsb()
{
    using apfsaccess::catalog::ApfsContainerCatalog;
    bool ok = true;
    const std::vector<std::byte> zeros(65536, std::byte{0});
    ApfsContainerCatalog catalog;
    std::string error;
    apfsaccess::catalog::VectorRandomAccessSource source(zeros);
    ok &= Require(!ApfsContainerCatalog::TryLoadImage(source, "x", "x", catalog, error),
        "blank image fails");
    ok &= Require(!error.empty(), "blank image names an error");
    return ok;
}

bool TestCatalogMultiContainer()
{
    using apfsaccess::catalog::ApfsContainerCatalog;
    bool ok = true;
    BuilderImage spec;
    spec.stores.resize(2);
    spec.stores[0].uuid_hex = "11111111111111111111111111111111";
    spec.stores[1].uuid_hex = "22222222222222222222222222222222";
    spec.stores[0].volumes.front().name = "Alpha";
    spec.stores[1].volumes.front().name = "Beta";
    const auto image = BuildTestImage(spec);
    ApfsContainerCatalog catalog;
    std::string error;
    ok &= Require(LoadCatalog(image, catalog, error), "multi-container loads: " + error);
    if (!ok)
    {
        return false;
    }
    ok &= Require(catalog.Partitions().size() == 2, "two partitions");
    ok &= Require(catalog.Containers().size() == 2, "two containers");
    if (catalog.Containers().size() == 2)
    {
        ok &= Require(catalog.Containers()[0].volumes.front().name_utf8 == "Alpha", "first volume");
        ok &= Require(catalog.Containers()[1].volumes.front().name_utf8 == "Beta", "second volume");
        ok &= Require(catalog.Containers()[0].member_store_ids !=
            catalog.Containers()[1].member_store_ids, "distinct member stores");
    }
    return ok;
}

bool TestCatalogTwoVolumes()
{
    using apfsaccess::catalog::ApfsContainerCatalog;
    bool ok = true;
    BuilderImage spec;
    spec.stores.front().volumes.push_back(BuilderVolume{});
    spec.stores.front().volumes[0].oid = 101;
    spec.stores.front().volumes[0].name = "One";
    spec.stores.front().volumes[1].oid = 102;
    spec.stores.front().volumes[1].name = "Two";
    const auto image = BuildTestImage(spec);
    ApfsContainerCatalog catalog;
    std::string error;
    ok &= Require(LoadCatalog(image, catalog, error), "two volumes load: " + error);
    if (!ok)
    {
        return false;
    }
    const auto& volumes = catalog.Containers().front().volumes;
    ok &= Require(volumes.size() == 2, "two volumes enumerated");
    apfsaccess::catalog::ResolvedMountVolume resolved;
    ok &= Require(catalog.TryResolveVolumeByOid(102, resolved, error) &&
        resolved.name_utf8 == "Two", "resolve by oid: " + error);
    ok &= Require(catalog.TryResolveVolumeByName("One", resolved, error) &&
        resolved.object_id == 101, "resolve by name: " + error);
    ok &= Require(!catalog.TryResolveVolumeByOid(0, resolved, error), "oid zero rejected");
    ok &= Require(!catalog.TryResolveVolumeByOid(9999, resolved, error), "oid missing rejected");
    return ok;
}

bool TestCatalogSameNameVolumes()
{
    using apfsaccess::catalog::ApfsContainerCatalog;
    bool ok = true;
    BuilderImage spec;
    spec.stores.resize(2);
    spec.stores[0].uuid_hex = "33333333333333333333333333333333";
    spec.stores[1].uuid_hex = "44444444444444444444444444444444";
    spec.stores[0].volumes.front().oid = 101;
    spec.stores[0].volumes.front().name = "Data";
    spec.stores[1].volumes.front().oid = 101;
    spec.stores[1].volumes.front().name = "Data";
    const auto image = BuildTestImage(spec);
    ApfsContainerCatalog catalog;
    std::string error;
    ok &= Require(LoadCatalog(image, catalog, error), "same-name loads: " + error);
    if (!ok)
    {
        return false;
    }
    // Same name across containers is representable...
    apfsaccess::catalog::ResolvedMountVolume resolved;
    // ...but name resolution must refuse the ambiguity instead of guessing.
    ok &= Require(!catalog.TryResolveVolumeByName("Data", resolved, error), "ambiguous name fails");
    ok &= Require(error.find("Ambiguous") != std::string::npos, "ambiguity named: " + error);
    // ...while OID resolution stays exact.
    ok &= Require(catalog.TryResolveVolumeByOid(101, resolved, error), "oid still resolves");
    return ok;
}

bool TestCatalogUnknownBits()
{
    using apfsaccess::catalog::ApfsContainerCatalog;
    bool ok = true;
    BuilderImage spec;
    // 0x10 (case-insensitive) is known-benign; 0x8000 is unknown.
    spec.stores.front().volumes.front().incompat = 0x8010;
    const auto image = BuildTestImage(spec);
    ApfsContainerCatalog catalog;
    std::string error;
    ok &= Require(LoadCatalog(image, catalog, error), "unknown bits load: " + error);
    if (!ok)
    {
        return false;
    }
    const auto& volume = catalog.Containers().front().volumes.front();
    ok &= Require(volume.case_mode == "insensitive", "case bit honored");
    const auto& unknown = volume.unknown_bits;
    ok &= Require(unknown.size() == 1 && unknown[0] == "0x8000", "unknown carved to 0x8000");
    const auto& incompat = volume.incompatible_bits;
    ok &= Require(incompat.size() == 1 && incompat[0] == "0x8000", "incompat carved");
    return ok;
}

bool TestCatalogStaleXid()
{
    using apfsaccess::catalog::ApfsContainerCatalog;
    bool ok = true;
    BuilderImage spec;
    spec.stores.front().volumes.front().xid_offset = 5;
    const auto image = BuildTestImage(spec);
    ApfsContainerCatalog catalog;
    std::string error;
    ok &= Require(!LoadCatalog(image, catalog, error), "stale xid fails");
    ok &= Require(error.find("StaleXid") != std::string::npos, "stale xid named: " + error);
    return ok;
}

bool TestCatalogCorruptVolume()
{
    using apfsaccess::catalog::ApfsContainerCatalog;
    bool ok = true;
    BuilderImage spec;
    spec.stores.front().volumes.front().bad_checksum = true;
    const auto image = BuildTestImage(spec);
    ApfsContainerCatalog catalog;
    std::string error;
    ok &= Require(!LoadCatalog(image, catalog, error), "corrupt volume fails");
    return ok;
}

bool TestCatalogDuplicateOid()
{
    using apfsaccess::catalog::ApfsContainerCatalog;
    bool ok = true;
    BuilderImage spec;
    spec.stores.front().volumes.push_back(BuilderVolume{});
    spec.stores.front().volumes[0].oid = 101;
    spec.stores.front().volumes[1].oid = 101;
    const auto image = BuildTestImage(spec);
    ApfsContainerCatalog catalog;
    std::string error;
    ok &= Require(!LoadCatalog(image, catalog, error), "duplicate oid fails");
    ok &= Require(error.find("DuplicateVolumeOid") != std::string::npos,
        "duplicate oid named: " + error);
    return ok;
}

bool TestCatalogDuplicateVolumeUuid()
{
    using apfsaccess::catalog::ApfsContainerCatalog;
    bool ok = true;
    BuilderImage spec;
    spec.stores.front().volumes.push_back(BuilderVolume{});
    spec.stores.front().volumes[0].oid = 101;
    spec.stores.front().volumes[1].oid = 102;
    spec.stores.front().volumes[0].uuid_hex = "66666666666666666666666666666666";
    spec.stores.front().volumes[1].uuid_hex = "66666666666666666666666666666666";
    const auto image = BuildTestImage(spec);
    ApfsContainerCatalog catalog;
    std::string error;
    ok &= Require(!LoadCatalog(image, catalog, error), "duplicate uuid fails");
    ok &= Require(error.find("DuplicateVolumeUuid") != std::string::npos,
        "duplicate uuid named: " + error);
    return ok;
}

bool TestCatalogMissingVolume()
{
    using apfsaccess::catalog::ApfsContainerCatalog;
    bool ok = true;
    BuilderImage spec;
    spec.stores.front().volumes.push_back(BuilderVolume{});
    spec.stores.front().volumes[0].oid = 101;
    spec.stores.front().volumes[1].oid = 7777; // listed but unmapped
    const auto image = BuildTestImage(spec);
    // Erase the second mapping from the omap btree.
    auto patched = image;
    const std::size_t btree_offset = 40 * 512 + 3 * 4096;
    PutU32LE(patched, btree_offset + 0x24, 1);
    PutU16LE(patched, btree_offset + 0x2A, 8);
    ApfsContainerCatalog catalog;
    std::string error;
    apfsaccess::catalog::VectorRandomAccessSource source(patched);
    ok &= Require(!ApfsContainerCatalog::TryLoadImage(source, "t", "t", catalog, error),
        "unmapped listed volume fails");
    return ok;
}

bool TestCatalogTruncated()
{
    using apfsaccess::catalog::ApfsContainerCatalog;
    bool ok = true;
    BuilderImage spec;
    spec.truncate_bytes = 40 * 512 + 2 * 4096;
    const auto image = BuildTestImage(spec);
    ApfsContainerCatalog catalog;
    std::string error;
    ok &= Require(!LoadCatalog(image, catalog, error), "truncated image fails");
    return ok;
}

bool TestCatalogVolumeGroups()
{
    using apfsaccess::catalog::ApfsContainerCatalog;
    bool ok = true;
    BuilderImage spec;
    spec.stores.front().volumes.push_back(BuilderVolume{});
    spec.stores.front().volumes[0].oid = 101;
    spec.stores.front().volumes[0].role = 1;
    spec.stores.front().volumes[0].name = "System";
    spec.stores.front().volumes[0].group_hex = "77777777777777777777777777777777";
    spec.stores.front().volumes[1].oid = 102;
    spec.stores.front().volumes[1].role = 32;
    spec.stores.front().volumes[1].name = "Data";
    spec.stores.front().volumes[1].group_hex = "77777777777777777777777777777777";
    const auto image = BuildTestImage(spec);
    ApfsContainerCatalog catalog;
    std::string error;
    ok &= Require(LoadCatalog(image, catalog, error), "groups load: " + error);
    if (!ok)
    {
        return false;
    }
    const auto& container = catalog.Containers().front();
    ok &= Require(container.groups.size() == 1, "one group emitted");
    if (!container.groups.empty())
    {
        ok &= Require(container.groups[0].member_volume_ids.size() == 2, "two members");
    }
    // A lone group UUID must not emit a group node.
    BuilderImage solo = spec;
    solo.stores.front().volumes[1].group_hex.clear();
    const auto solo_image = BuildTestImage(solo);
    ApfsContainerCatalog solo_catalog;
    ok &= Require(LoadCatalog(solo_image, solo_catalog, error), "solo group loads");
    if (ok)
    {
        ok &= Require(solo_catalog.Containers().front().groups.empty(), "no lone group");
    }
    return ok;
}

bool TestCatalogFusionStores()
{
    using apfsaccess::catalog::ApfsContainerCatalog;
    bool ok = true;
    BuilderImage spec;
    spec.stores.resize(2);
    spec.stores[0].uuid_hex = "88888888888888888888888888888888";
    spec.stores[1].uuid_hex = "88888888888888888888888888888888";
    const auto image = BuildTestImage(spec);
    ApfsContainerCatalog catalog;
    std::string error;
    ok &= Require(LoadCatalog(image, catalog, error), "fusion loads: " + error);
    if (!ok)
    {
        return false;
    }
    ok &= Require(catalog.Containers().size() == 1, "one fused container");
    if (!catalog.Containers().empty())
    {
        const auto& container = catalog.Containers().front();
        ok &= Require(container.fusion, "fusion flagged");
        ok &= Require(container.member_store_ids.size() == 2, "two member stores");
    }
    return ok;
}

bool TestSourceBounds()
{
    using apfsaccess::catalog::FileRandomAccessSource;
    using apfsaccess::catalog::VectorRandomAccessSource;
    bool ok = true;
    const std::vector<std::byte> bytes(16, std::byte{0xAB});
    VectorRandomAccessSource memory(bytes);
    std::vector<std::byte> out;
    ok &= Require(memory.Read(0, 16, out) && out.size() == 16, "vector full read");
    ok &= Require(!memory.Read(0, 17, out), "vector overread");
    ok &= Require(!memory.Read(16, 1, out), "vector edge overread");
    ok &= Require(memory.Read(16, 0, out), "vector empty read at end");
    FileRandomAccessSource missing("Z:\\definitely\\not\\here\\apfs-task1-test.bin");
    ok &= Require(!missing.IsOpen(), "missing file closed");
    ok &= Require(!missing.Read(0, 1, out), "missing file unreadable");
    return ok;
}

} // namespace

int main(int argc, char** argv)
{
    if (argc == 3 && std::string(argv[1]) == "--emit-fusion-pair")
    {
        // Test-only Fusion pair: two single-partition images sharing one
        // container UUID with distinct partition GUIDs and one shared volume.
        // Writes <dir>/fusion-a.img and <dir>/fusion-b.img.
        const std::string dir = argv[2];
        const std::string shared_uuid = "99999999999999999999999999999999";
        for (int side = 0; side < 2; ++side)
        {
            BuilderImage spec;
            spec.stores.front().uuid_hex = shared_uuid;
            spec.stores.front().volumes.front().oid = 101;
            spec.stores.front().volumes.front().name = "Shared";
            spec.stores.front().volumes.front().uuid_hex =
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1";
            auto image = BuildTestImage(spec);
            // Distinct partition GUID per side (builder derives it from the
            // store index only, so patch the second image's entry GUID).
            if (side == 1)
            {
                auto guid_b = GuidToMixedEndian("bbbbbbbb-0000-4000-8000-000000000002");
                for (std::size_t b = 0; b < 16; ++b)
                {
                    image[2 * 512 + 16 + b] = guid_b[b];
                }
                // Recompute the GPT entries CRC after patching, then refresh
                // the header CRC which covers the entries-CRC field.
                std::vector<std::byte> entry_bytes(
                    image.begin() + static_cast<std::vector<std::byte>::difference_type>(2 * 512),
                    image.begin() + static_cast<std::vector<std::byte>::difference_type>(2 * 512 + 128 * 128));
                PutU32LE(image, 512 + 88,
                    apfsaccess::catalog::Crc32(entry_bytes.data(), entry_bytes.size()));
                std::vector<std::byte> header_bytes(
                    image.begin() + static_cast<std::vector<std::byte>::difference_type>(512),
                    image.begin() + static_cast<std::vector<std::byte>::difference_type>(512 + 92));
                PutU32LE(header_bytes, 16, 0);
                PutU32LE(image, 512 + 16,
                    apfsaccess::catalog::Crc32(header_bytes.data(), header_bytes.size()));
            }
            const std::string path =
                dir + (side == 0 ? "/fusion-a.img" : "/fusion-b.img");
            std::FILE* out = std::fopen(path.c_str(), "wb");
            if (out == nullptr)
            {
                std::cerr << "[FAIL] cannot open fixture output: " << path << std::endl;
                return 1;
            }
            const std::size_t written = std::fwrite(image.data(), 1, image.size(), out);
            std::fclose(out);
            if (written != image.size())
            {
                std::cerr << "[FAIL] short fixture write: " << path << std::endl;
                return 1;
            }
            std::cout << "fusion fixture bytes=" << image.size() << " path=" << path << std::endl;
        }
        return 0;
    }
    if (argc == 3 && std::string(argv[1]) == "--emit-fixture")
    {
        // Test-only fixture writer: two GPT partitions, two containers,
        // two volumes in the first. Refuses to overwrite existing files.
        BuilderImage spec;
        spec.stores.resize(2);
        spec.stores[0].uuid_hex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        spec.stores[0].volumes.clear();
        BuilderVolume first;
        first.oid = 101;
        first.name = "Alpha";
        first.uuid_hex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1";
        BuilderVolume second = first;
        second.oid = 102;
        second.name = "Beta";
        second.uuid_hex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2";
        spec.stores[0].volumes.push_back(first);
        spec.stores[0].volumes.push_back(second);
        spec.stores[1].uuid_hex = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        spec.stores[1].volumes.front().oid = 201;
        spec.stores[1].volumes.front().name = "Gamma";
        spec.stores[1].volumes.front().uuid_hex = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb1";
        const auto image = BuildTestImage(spec);
        const std::string path = argv[2];
        std::FILE* existing = std::fopen(path.c_str(), "rb");
        if (existing != nullptr)
        {
            std::fclose(existing);
            std::cerr << "[FAIL] refusing to overwrite fixture: " << path << std::endl;
            return 1;
        }
        std::FILE* out = std::fopen(path.c_str(), "wb");
        if (out == nullptr)
        {
            std::cerr << "[FAIL] cannot open fixture output: " << path << std::endl;
            return 1;
        }
        const std::size_t written =
            std::fwrite(image.data(), 1, image.size(), out);
        std::fclose(out);
        if (written != image.size())
        {
            std::cerr << "[FAIL] short fixture write: " << path << std::endl;
            return 1;
        }
        std::cout << "fixture bytes=" << image.size() << " path=" << path << std::endl;
        return 0;
    }
    bool ok = true;
    ok &= TestLeReaders();
    ok &= TestFletcher64();
    ok &= TestCrc32();
    ok &= TestGuidStrings();
    ok &= TestGptRoundTrip();
    ok &= TestGptRejections();
    ok &= TestNxsbRoundTrip();
    ok &= TestApsbRoundTrip();
    ok &= TestOmapResolve();
    ok &= TestInterpretation();
    ok &= TestCatalogSingleVolume();
    ok &= TestCatalogPartitionless();
    ok &= TestCatalogNoGptNoNxsb();
    ok &= TestCatalogMultiContainer();
    ok &= TestCatalogTwoVolumes();
    ok &= TestCatalogSameNameVolumes();
    ok &= TestCatalogUnknownBits();
    ok &= TestCatalogStaleXid();
    ok &= TestCatalogCorruptVolume();
    ok &= TestCatalogDuplicateOid();
    ok &= TestCatalogDuplicateVolumeUuid();
    ok &= TestCatalogMissingVolume();
    ok &= TestCatalogTruncated();
    ok &= TestCatalogVolumeGroups();
    ok &= TestCatalogFusionStores();
    ok &= TestSourceBounds();
    if (ok)
    {
        std::cout << "APFS COMPATIBILITY PASS" << std::endl;
        return 0;
    }
    std::cerr << "APFS COMPATIBILITY FAIL: " << g_failures << " check(s)" << std::endl;
    return 1;
}