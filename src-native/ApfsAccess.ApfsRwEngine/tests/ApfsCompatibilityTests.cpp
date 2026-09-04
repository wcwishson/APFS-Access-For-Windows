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
#include "BlockDevice.h"
#include "MetadataStore.h"
#include "NativeApfsReader.h"
#include "RandomAccessSource.h"
#include "TestFixtureBuilder.h"
#include "../tools/Sha256.h"
#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
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

using namespace apfsaccess::testfixture;

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
    {
        auto block = BuildNxsb(store, store.xid, "", store.block_size);
        PutU32LE(block, 0xB4, 100);
        PutU64LE(block, 0x3D8, 0x123456789ABCDEF0ull);
        FletcherForBlock(block, store.block_size);
        const auto parsed = ParseNxSuperblock(block);
        ok &= Require(
            parsed.has_value() && parsed->fs_oids.size() == 1 && parsed->fs_oids[0] == 101,
            "nxsb counters are not volume oids");
    }
    {
        auto block = BuildNxsb(store, store.xid, "", store.block_size);
        PutU32LE(block, 0xB4, 101);
        FletcherForBlock(block, store.block_size);
        ok &= Require(!ParseNxSuperblock(block).has_value(), "nxsb max filesystems bounded");
    }
    return ok;
}

void PutFixtureBlock(
    std::vector<std::byte>& image,
    std::uint64_t block_number,
    std::uint32_t block_size,
    const std::vector<std::byte>& block)
{
    const auto offset = static_cast<std::size_t>(block_number) * block_size;
    if (offset >= image.size())
    {
        return;
    }
    const auto count = (std::min)(block.size(), image.size() - offset);
    std::copy_n(block.begin(), count, image.begin() + static_cast<std::ptrdiff_t>(offset));
}

BuilderStore CheckpointViewStore()
{
    BuilderStore store;
    store.dual_checkpoint = false;
    store.block_count = 96;
    store.xp_desc_base_blocks = 80;
    store.xp_desc_blocks = 4;
    store.xp_data_base_blocks = 84;
    store.xp_data_blocks = 4;
    store.spaceman_oid = 1024;
    return store;
}

bool TestCheckpointViewWrapsAndValidatesMappings()
{
    using apfsaccess::catalog::LoadContainerCheckpointView;
    using apfsaccess::catalog::VectorRandomAccessSource;
    bool ok = true;
    auto store = CheckpointViewStore();
    auto image = BuildStoreImage(store);

    BuilderStore selected = store;
    selected.xid = 20;
    selected.xp_desc_index = 3;
    selected.xp_desc_len = 2;
    selected.xp_desc_next = 1;
    selected.xp_data_index = 0;
    selected.xp_data_len = 1;
    selected.xp_data_next = 1;
    CheckpointMappingSpec mapping;
    mapping.physical_block = store.xp_data_base_blocks;
    PutFixtureBlock(image, 83, store.block_size,
        BuildCheckpointMap(selected.xid, {mapping}, store.block_size, 83));
    PutFixtureBlock(image, 80, store.block_size,
        BuildNxsb(selected, selected.xid, "", store.block_size));
    PutFixtureBlock(image, mapping.physical_block, store.block_size,
        BuildEphemeralObject(mapping.object_id, selected.xid, mapping.type,
            mapping.subtype, mapping.size));

    VectorRandomAccessSource source(image);
    std::string error;
    const auto view = LoadContainerCheckpointView(source, 0, image.size(), error);
    ok &= Require(view.has_value(), "wrapped checkpoint view loads: " + error);
    if (view.has_value())
    {
        ok &= Require(view->superblock.xid == selected.xid, "wrapped checkpoint xid");
        ok &= Require(view->superblock_physical_block == 80, "wrapped checkpoint nxsb block");
        ok &= Require(view->checkpoint_map_blocks.size() == 1 &&
            view->checkpoint_map_blocks[0] == 83, "wrapped checkpoint map block");
        ok &= Require(view->mappings.size() == 1, "wrapped checkpoint mapping count");
        if (view->mappings.size() == 1)
        {
            ok &= Require(view->mappings[0].object_id == mapping.object_id,
                "wrapped checkpoint mapping oid");
            ok &= Require(view->mappings[0].physical_block == mapping.physical_block,
                "wrapped checkpoint mapping paddr");
        }
    }
    return ok;
}

bool TestCheckpointViewFallsBackFromMalformedNewest()
{
    using apfsaccess::catalog::LoadContainerCheckpointView;
    using apfsaccess::catalog::VectorRandomAccessSource;
    bool ok = true;
    auto store = CheckpointViewStore();
    store.xp_desc_blocks = 6;
    store.xp_data_base_blocks = 86;
    auto image = BuildStoreImage(store);

    CheckpointMappingSpec old_mapping;
    old_mapping.physical_block = 86;
    BuilderStore older = store;
    older.xid = 20;
    older.xp_desc_index = 0;
    older.xp_desc_len = 2;
    older.xp_desc_next = 2;
    older.xp_data_index = 0;
    older.xp_data_len = 1;
    older.xp_data_next = 1;
    PutFixtureBlock(image, 80, store.block_size,
        BuildCheckpointMap(older.xid, {old_mapping}, store.block_size, 80));
    PutFixtureBlock(image, 81, store.block_size,
        BuildNxsb(older, older.xid, "", store.block_size));
    PutFixtureBlock(image, old_mapping.physical_block, store.block_size,
        BuildEphemeralObject(old_mapping.object_id, older.xid, old_mapping.type,
            old_mapping.subtype, old_mapping.size));

    CheckpointMappingSpec new_mapping = old_mapping;
    new_mapping.physical_block = 87;
    BuilderStore newer = store;
    newer.xid = 21;
    newer.xp_desc_index = 2;
    newer.xp_desc_len = 2;
    newer.xp_desc_next = 4;
    newer.xp_data_index = 1;
    newer.xp_data_len = 1;
    newer.xp_data_next = 2;
    PutFixtureBlock(image, 82, store.block_size,
        BuildCheckpointMap(newer.xid, {new_mapping}, store.block_size, 82));
    PutFixtureBlock(image, 83, store.block_size,
        BuildNxsb(newer, newer.xid, "", store.block_size));
    auto corrupt = BuildEphemeralObject(new_mapping.object_id, newer.xid,
        new_mapping.type, new_mapping.subtype, new_mapping.size);
    corrupt[64] ^= std::byte{0x5A};
    PutFixtureBlock(image, new_mapping.physical_block, store.block_size, corrupt);

    VectorRandomAccessSource source(image);
    std::string error;
    const auto view = LoadContainerCheckpointView(source, 0, image.size(), error);
    ok &= Require(view.has_value(), "older complete checkpoint survives: " + error);
    ok &= Require(view.has_value() && view->superblock.xid == older.xid,
        "malformed newest checkpoint rejected");
    return ok;
}

bool TestCheckpointViewRejectsDecoysAndUnsupportedLayout()
{
    using apfsaccess::catalog::LoadContainerCheckpointView;
    using apfsaccess::catalog::ParseNxSuperblock;
    using apfsaccess::catalog::VectorRandomAccessSource;
    bool ok = true;
    auto store = CheckpointViewStore();
    store.dual_checkpoint = true;
    store.second_xid_offset = 999;
    auto image = BuildStoreImage(store);

    BuilderStore selected = store;
    selected.xid = 20;
    selected.xp_desc_index = 0;
    selected.xp_desc_len = 2;
    selected.xp_desc_next = 2;
    selected.xp_data_index = 0;
    selected.xp_data_len = 1;
    selected.xp_data_next = 1;
    CheckpointMappingSpec mapping;
    mapping.physical_block = 84;
    PutFixtureBlock(image, 80, store.block_size,
        BuildCheckpointMap(selected.xid, {mapping}, store.block_size, 80));
    PutFixtureBlock(image, 81, store.block_size,
        BuildNxsb(selected, selected.xid, "", store.block_size));
    PutFixtureBlock(image, mapping.physical_block, store.block_size,
        BuildEphemeralObject(mapping.object_id, selected.xid, mapping.type,
            mapping.subtype, mapping.size));

    VectorRandomAccessSource source(image);
    std::string error;
    const auto view = LoadContainerCheckpointView(source, 0, image.size(), error);
    ok &= Require(view.has_value() && view->superblock.xid == selected.xid,
        "block-one high-xid decoy ignored");

    auto noncontiguous = store;
    noncontiguous.dual_checkpoint = false;
    noncontiguous.xp_desc_blocks |= 0x80000000u;
    const auto block = BuildNxsb(noncontiguous, noncontiguous.xid, "",
        noncontiguous.block_size);
    const auto parsed = ParseNxSuperblock(block);
    ok &= Require(parsed.has_value() && parsed->xp_desc_noncontiguous &&
        parsed->xp_desc_block_count == 4, "noncontiguous descriptor flag parsed");
    auto unsupported_image = BuildStoreImage(noncontiguous);
    VectorRandomAccessSource unsupported_source(unsupported_image);
    error.clear();
    ok &= Require(!LoadContainerCheckpointView(
            unsupported_source, 0, unsupported_image.size(), error).has_value() &&
        error == "CheckpointDescriptorTreeUnsupported",
        "noncontiguous descriptor tree fails closed");
    return ok;
}

struct AuthoritativeCheckpointFixture
{
    std::vector<std::byte> image;
    std::uint64_t checkpoint_xid = 20;
    std::uint64_t volume_oid = 101;
    std::uint64_t volume_root_oid = 0x2065;
    std::uint64_t snapshot_root_oid = 0x3065;
    std::uint64_t spaceman_oid = 1024;
    std::uint64_t free_queue_oid = 1025;
    std::uint64_t main_free_queue_oid = 1026;
};

AuthoritativeCheckpointFixture BuildAuthoritativeCheckpointFixture(
    bool map_free_queue = true)
{
    constexpr std::uint32_t kBlockSize = 4096;
    constexpr std::uint64_t kContainerOmapBlock = 2;
    constexpr std::uint64_t kContainerOmapTreeBlock = 3;
    constexpr std::uint64_t kVolumeSuperblockBlock = 4;
    constexpr std::uint64_t kVolumeOmapBlock = 32;
    constexpr std::uint64_t kVolumeOmapTreeBlock = 33;
    constexpr std::uint64_t kVolumeRootBlock = 34;
    constexpr std::uint64_t kSnapshotRootBlock = 35;
    constexpr std::uint64_t kExtentrefRootBlock = 40;
    constexpr std::uint64_t kFextRootBlock = 41;
    constexpr std::uint64_t kCheckpointMapBlock = 80;
    constexpr std::uint64_t kCheckpointNxsbBlock = 81;
    constexpr std::uint64_t kSpacemanBlock = 88;
    constexpr std::uint64_t kFreeQueueBlock = 89;
    constexpr std::uint64_t kMainFreeQueueBlock = 90;
    constexpr std::uint64_t kCibBlock = 102;
    constexpr std::uint64_t kChunkZeroBitmapBlock = 104;
    constexpr std::uint64_t kChunkOneBitmapBlock = 105;
    constexpr std::uint64_t kIpBitmapBase = 64;
    constexpr std::uint64_t kIpBase = 100;
    constexpr std::uint64_t kIpBlockCount = 8;

    AuthoritativeCheckpointFixture fixture;
    BuilderStore store;
    store.dual_checkpoint = false;
    store.block_count = 128;
    store.xid = 7;
    store.xp_desc_base_blocks = 80;
    store.xp_desc_blocks = 8;
    store.xp_data_base_blocks = 88;
    store.xp_data_blocks = 8;
    store.spaceman_oid = fixture.spaceman_oid;
    store.volumes.clear();
    BuilderVolume volume;
    volume.oid = fixture.volume_oid;
    volume.name = "Authoritative";
    volume.vol_omap_oid_override = kVolumeOmapBlock;
    volume.root_oid_override = fixture.volume_root_oid;
    volume.root_tree_type = 0x00000002;
    volume.extentref_tree_type = 0x40000002;
    volume.extentref_tree_oid = kExtentrefRootBlock;
    volume.snap_meta_tree_type = 0x00000002;
    volume.snap_meta_tree_oid = fixture.snapshot_root_oid;
    volume.fext_tree_type = 0x40000002;
    volume.fext_tree_oid = kFextRootBlock;
    volume.file_system_allocated_blocks = 4;
    volume.total_blocks_allocated = 4;
    store.volumes.push_back(volume);
    fixture.image = BuildStoreImage(store);

    BuilderStore selected = store;
    selected.xp_desc_index = 0;
    selected.xp_desc_len = 2;
    selected.xp_desc_next = 2;
    selected.xp_data_index = 0;
    selected.xp_data_len = 3;
    selected.xp_data_next = 3;

    CheckpointMappingSpec spaceman;
    spaceman.type = 0x80000005;
    spaceman.object_id = fixture.spaceman_oid;
    spaceman.physical_block = kSpacemanBlock;
    CheckpointMappingSpec free_queue;
    free_queue.type = 0x80000002;
    free_queue.subtype = 0x00000009;
    free_queue.object_id = fixture.free_queue_oid;
    free_queue.physical_block = kFreeQueueBlock;
    CheckpointMappingSpec main_free_queue = free_queue;
    main_free_queue.object_id = fixture.main_free_queue_oid;
    main_free_queue.physical_block = kMainFreeQueueBlock;
    std::vector<CheckpointMappingSpec> mappings{spaceman};
    if (map_free_queue)
    {
        mappings.push_back(free_queue);
        mappings.push_back(main_free_queue);
    }
    PutFixtureBlock(fixture.image, kCheckpointMapBlock, kBlockSize,
        BuildCheckpointMap(fixture.checkpoint_xid, mappings, kBlockSize,
            kCheckpointMapBlock));
    PutFixtureBlock(fixture.image, kCheckpointNxsbBlock, kBlockSize,
        BuildNxsb(selected, fixture.checkpoint_xid, "", kBlockSize));

    const auto set_bit = [](std::vector<std::byte>& bitmap, std::uint64_t bit) {
        bitmap[static_cast<std::size_t>(bit / 8)] |=
            static_cast<std::byte>(1u << (bit % 8));
    };
    const auto count_bits = [](const std::vector<std::byte>& bitmap,
                               std::uint32_t bit_count) {
        std::uint32_t count = 0;
        for (std::uint32_t bit = 0; bit < bit_count; ++bit)
        {
            if ((std::to_integer<unsigned int>(bitmap[bit / 8]) &
                    (1u << (bit % 8))) != 0)
            {
                ++count;
            }
        }
        return count;
    };
    std::vector<std::byte> chunk_zero_bitmap(kBlockSize, std::byte{0});
    for (const std::uint64_t block : {0ull, 1ull, 2ull, 3ull, 4ull, 32ull,
             33ull, 34ull, 35ull, 40ull, 41ull})
    {
        set_bit(chunk_zero_bitmap, block);
    }
    std::vector<std::byte> chunk_one_bitmap(kBlockSize, std::byte{0});
    for (std::uint64_t block = 64; block <= 95; ++block)
    {
        set_bit(chunk_one_bitmap, block - 64);
    }
    for (std::uint64_t block = kIpBase; block < kIpBase + kIpBlockCount; ++block)
    {
        set_bit(chunk_one_bitmap, block - 64);
    }
    PutFixtureBlock(fixture.image, kChunkZeroBitmapBlock, kBlockSize,
        chunk_zero_bitmap);
    PutFixtureBlock(fixture.image, kChunkOneBitmapBlock, kBlockSize,
        chunk_one_bitmap);

    std::vector<std::byte> ip_bitmap(kBlockSize, std::byte{0});
    for (const std::uint64_t block :
         {kCibBlock, kChunkZeroBitmapBlock, kChunkOneBitmapBlock})
    {
        set_bit(ip_bitmap, block - kIpBase);
    }
    PutFixtureBlock(fixture.image, kIpBitmapBase, kBlockSize, ip_bitmap);

    auto cib = BuildEphemeralObject(kCibBlock, fixture.checkpoint_xid,
        apfsaccess::catalog::kObjectPhysical |
            apfsaccess::catalog::kObjectTypeSpacemanCib,
        0, kBlockSize);
    PutU32LE(cib, 0x20, 0);
    PutU32LE(cib, 0x24, 2);
    PutU64LE(cib, 0x28, fixture.checkpoint_xid);
    PutU64LE(cib, 0x30, 0);
    PutU32LE(cib, 0x38, 64);
    PutU32LE(cib, 0x3C, 64 - count_bits(chunk_zero_bitmap, 64));
    PutU64LE(cib, 0x40, kChunkZeroBitmapBlock);
    PutU64LE(cib, 0x48, fixture.checkpoint_xid);
    PutU64LE(cib, 0x50, 64);
    PutU32LE(cib, 0x58, 64);
    PutU32LE(cib, 0x5C, 64 - count_bits(chunk_one_bitmap, 64));
    PutU64LE(cib, 0x60, kChunkOneBitmapBlock);
    FletcherForBlock(cib, kBlockSize);
    PutFixtureBlock(fixture.image, kCibBlock, kBlockSize, cib);

    auto spaceman_object = BuildEphemeralObject(fixture.spaceman_oid,
        fixture.checkpoint_xid, spaceman.type, spaceman.subtype, kBlockSize);
    PutU32LE(spaceman_object, 0x20, kBlockSize);
    PutU32LE(spaceman_object, 0x24, 64);
    PutU32LE(spaceman_object, 0x28, 2);
    PutU32LE(spaceman_object, 0x2C, 64);
    PutU64LE(spaceman_object, 0x30, 128);
    PutU64LE(spaceman_object, 0x38, 2);
    PutU32LE(spaceman_object, 0x40, 1);
    PutU64LE(spaceman_object, 0x48,
        static_cast<std::uint64_t>(64 - count_bits(chunk_zero_bitmap, 64)) +
        static_cast<std::uint64_t>(64 - count_bits(chunk_one_bitmap, 64)));
    PutU32LE(spaceman_object, 0x50, 0x600);
    PutU32LE(spaceman_object, 0x94, 16);
    PutU64LE(spaceman_object, 0x98, kIpBlockCount);
    PutU32LE(spaceman_object, 0xA0, 1);
    PutU32LE(spaceman_object, 0xA4, 16);
    PutU64LE(spaceman_object, 0xA8, kIpBitmapBase);
    PutU64LE(spaceman_object, 0xB0, kIpBase);
    PutU64LE(spaceman_object, 0xC0, 0xDEADBEEFDEADBEEFull);
    PutU64LE(spaceman_object, 0xD0, fixture.free_queue_oid);
    PutU16LE(spaceman_object, 0xE0, 64);
    PutU64LE(spaceman_object, 0xF8, fixture.main_free_queue_oid);
    PutU16LE(spaceman_object, 0x108, 64);
    PutU16LE(spaceman_object, 0x140, 1);
    PutU16LE(spaceman_object, 0x142, 15);
    PutU32LE(spaceman_object, 0x144, 0x700);
    PutU32LE(spaceman_object, 0x148, 0x708);
    PutU32LE(spaceman_object, 0x14C, 0x720);
    PutU32LE(spaceman_object, 0x150, 1);
    PutU32LE(spaceman_object, 0x154, 0x800);
    PutU64LE(spaceman_object, 0x600, kCibBlock);
    PutU64LE(spaceman_object, 0x700, fixture.checkpoint_xid);
    PutU16LE(spaceman_object, 0x708, 0);
    PutU16LE(spaceman_object, 0x720, 0xFFFF);
    for (std::uint16_t index = 1; index < 16; ++index)
    {
        PutU16LE(spaceman_object, 0x720 + index * 2,
            index == 15 ? 0xFFFF : static_cast<std::uint16_t>(index + 1));
    }
    FletcherForBlock(spaceman_object, kBlockSize);
    PutFixtureBlock(fixture.image, kSpacemanBlock, kBlockSize, spaceman_object);
    PutFixtureBlock(fixture.image, kFreeQueueBlock, kBlockSize,
        BuildEmptyFreeQueueNode(
            fixture.checkpoint_xid, kBlockSize, fixture.free_queue_oid));
    PutFixtureBlock(fixture.image, kMainFreeQueueBlock, kBlockSize,
        BuildEmptyFreeQueueNode(
            fixture.checkpoint_xid, kBlockSize,
            fixture.main_free_queue_oid));

    PutFixtureBlock(fixture.image, kContainerOmapBlock, kBlockSize,
        BuildOmap(kContainerOmapTreeBlock, fixture.checkpoint_xid, kBlockSize,
            kContainerOmapBlock, 0x4000000B, 0x40000002));
    PutFixtureBlock(fixture.image, kContainerOmapTreeBlock, kBlockSize,
        BuildBtreeNode({OmapRecordSpec{fixture.volume_oid,
            kVolumeSuperblockBlock, 0, fixture.checkpoint_xid}},
            fixture.checkpoint_xid, kBlockSize, 0, kContainerOmapTreeBlock,
            0x40000002, 0x0000000B));
    PutFixtureBlock(fixture.image, kVolumeSuperblockBlock, kBlockSize,
        BuildApsb(volume, fixture.checkpoint_xid, kBlockSize));
    PutFixtureBlock(fixture.image, kVolumeOmapBlock, kBlockSize,
        BuildOmap(kVolumeOmapTreeBlock, fixture.checkpoint_xid, kBlockSize,
            kVolumeOmapBlock, 0x4000000B, 0x40000002));
    PutFixtureBlock(fixture.image, kVolumeOmapTreeBlock, kBlockSize,
        BuildBtreeNode({
            OmapRecordSpec{fixture.volume_root_oid, kVolumeRootBlock, 0,
                fixture.checkpoint_xid},
            OmapRecordSpec{fixture.snapshot_root_oid, kSnapshotRootBlock, 0,
                fixture.checkpoint_xid}},
            fixture.checkpoint_xid, kBlockSize, 0, kVolumeOmapTreeBlock,
            0x40000002, 0x0000000B));
    PutFixtureBlock(fixture.image, kVolumeRootBlock, kBlockSize,
        BuildRootFsLeaf(fixture.checkpoint_xid, kBlockSize,
            fixture.volume_root_oid, 0x00000002, 0x0000000E));
    PutFixtureBlock(fixture.image, kSnapshotRootBlock, kBlockSize,
        BuildRawLeafNode({}, {}, fixture.checkpoint_xid, kBlockSize, 0,
            fixture.snapshot_root_oid, 0x00000002, 0x00000010));
    PutFixtureBlock(fixture.image, kExtentrefRootBlock, kBlockSize,
        BuildRawLeafNode({}, {}, fixture.checkpoint_xid, kBlockSize, 0,
            kExtentrefRootBlock, 0x40000002, 0x0000000F));
    PutFixtureBlock(fixture.image, kFextRootBlock, kBlockSize,
        BuildRawLeafNode({}, {}, fixture.checkpoint_xid, kBlockSize, 0,
            kFextRootBlock, 0x40000002, 0x0000001F));
    return fixture;
}

bool PhysicalAllocatorMetadataOutsideCheckpointRings(
    const apfsaccess::catalog::AppleCheckpointView& view)
{
    const auto& nxsb = view.container.superblock;
    const auto in_checkpoint_area = [&nxsb](std::uint64_t block) {
        const auto in_area = [block](std::uint64_t base, std::uint32_t count) {
            return block >= base && block - base < count;
        };
        return in_area(nxsb.xp_desc_base_block, nxsb.xp_desc_block_count) ||
            in_area(nxsb.xp_data_base_block, nxsb.xp_data_block_count);
    };
    for (const auto& cib : view.spaceman.devices[0].cibs)
    {
        if (in_checkpoint_area(cib.object.physical_block))
        {
            return false;
        }
    }
    for (const auto& chunk : view.spaceman.chunks)
    {
        if (in_checkpoint_area(chunk.bitmap_block))
        {
            return false;
        }
    }
    for (const auto& bitmap : view.spaceman.internal_pool.active_bitmaps)
    {
        if (in_checkpoint_area(bitmap.physical_block))
        {
            return false;
        }
    }
    for (std::uint64_t block = view.spaceman.internal_pool.base_block;
         block < view.spaceman.internal_pool.base_block +
             view.spaceman.internal_pool.block_count;
         ++block)
    {
        if (in_checkpoint_area(block))
        {
            return false;
        }
    }
    return true;
}

bool TestAppleCheckpointViewBindsOneTransaction()
{
    using apfsaccess::catalog::LoadAppleCheckpointView;
    using apfsaccess::catalog::VectorRandomAccessSource;
    bool ok = true;
    const auto fixture = BuildAuthoritativeCheckpointFixture();
    VectorRandomAccessSource source(fixture.image);
    std::string error;
    const auto view = LoadAppleCheckpointView(source, 0, fixture.image.size(), error);
    ok &= Require(view.has_value(), "authoritative Apple checkpoint loads: " + error);
    if (!view.has_value())
    {
        return false;
    }
    ok &= Require(view->container.superblock.xid == fixture.checkpoint_xid,
        "Apple checkpoint xid bound");
    ok &= Require(view->container_object_map.object.physical_block == 2 &&
        view->container_object_map.tree.physical_block == 3,
        "container omap and tree bound");
    ok &= Require(view->spaceman.object.physical_block == 88 &&
            view->spaceman.free_queue_roots.size() == 2 &&
            view->spaceman.free_queue_roots[0].physical_block == 89,
        "spaceman and free queue bound");
    ok &= Require(view->spaceman.chunks.size() == 2 &&
            view->spaceman.devices[0].cibs.size() == 1 &&
            view->spaceman.internal_pool.active_bitmaps.size() == 1,
        "spaceman allocator ownership retained in checkpoint view");
    ok &= Require(PhysicalAllocatorMetadataOutsideCheckpointRings(*view),
        "physical allocator metadata stays outside both checkpoint rings");
    ok &= Require(view->volumes.size() == 1, "all listed volumes bound");
    if (view->volumes.size() == 1)
    {
        const auto& volume = view->volumes.front();
        ok &= Require(volume.superblock.object_id == fixture.volume_oid &&
            volume.superblock_object.physical_block == 4,
            "APSB bound through container omap");
        ok &= Require(volume.object_map.object.physical_block == 32 &&
            volume.object_map.tree.physical_block == 33,
            "volume omap and tree bound");
        ok &= Require(volume.root_tree.physical_block == 34 &&
            volume.extentref_tree.has_value() &&
            volume.extentref_tree->physical_block == 40 &&
            volume.snapshot_metadata_tree.has_value() &&
            volume.snapshot_metadata_tree->physical_block == 35 &&
            volume.file_extent_tree.has_value() &&
            volume.file_extent_tree->physical_block == 41,
            "all volume roots bound from declared storage types");
    }
    return ok;
}

bool TestAppleSpacemanAcceptsEmptyTier2DescriptorOffset()
{
    using apfsaccess::catalog::LoadAppleCheckpointView;
    using apfsaccess::catalog::VectorRandomAccessSource;
    constexpr std::uint64_t kSpacemanBlock = 88;
    constexpr std::uint32_t kBlockSize = 4096;
    constexpr std::size_t kTier2AddressOffset = 0x80;

    auto fixture = BuildAuthoritativeCheckpointFixture();
    PutU32LE(fixture.image,
        static_cast<std::size_t>(kSpacemanBlock * kBlockSize) +
            kTier2AddressOffset,
        0xA10);
    PutU32LE(fixture.image,
        static_cast<std::size_t>(kSpacemanBlock * kBlockSize) + 0x154,
        0x9D8);
    std::vector<std::byte> spaceman(
        fixture.image.begin() + kSpacemanBlock * kBlockSize,
        fixture.image.begin() + (kSpacemanBlock + 1) * kBlockSize);
    FletcherForBlock(spaceman, spaceman.size());
    PutFixtureBlock(fixture.image, kSpacemanBlock, kBlockSize, spaceman);

    VectorRandomAccessSource source(fixture.image);
    std::string error;
    const auto view = LoadAppleCheckpointView(
        source, 0, fixture.image.size(), error);
    return Require(view.has_value() &&
            view->spaceman.devices[1].block_count == 0 &&
            view->spaceman.devices[1].chunk_count == 0 &&
            view->spaceman.devices[1].address_offset == 0xA10,
        "empty Apple tier-2 descriptor may retain its address offset: " + error);
}

bool TestAppleSpacemanAcceptsVariableArraysAfterFixedStructure()
{
    using apfsaccess::catalog::LoadAppleCheckpointView;
    using apfsaccess::catalog::VectorRandomAccessSource;
    constexpr std::uint64_t kSpacemanBlock = 88;
    constexpr std::uint32_t kBlockSize = 4096;
    constexpr std::size_t kFixedStructureSize = 0x9D8;
    constexpr std::size_t kXidOffset = kFixedStructureSize;
    constexpr std::size_t kIndexOffset = 0x9E0;
    constexpr std::size_t kFreeNextOffset = 0x9E8;

    auto fixture = BuildAuthoritativeCheckpointFixture();
    std::vector<std::byte> spaceman(
        fixture.image.begin() + kSpacemanBlock * kBlockSize,
        fixture.image.begin() + (kSpacemanBlock + 1) * kBlockSize);
    std::copy_n(spaceman.begin() + 0x700, 8,
        spaceman.begin() + kXidOffset);
    std::copy_n(spaceman.begin() + 0x708, 2,
        spaceman.begin() + kIndexOffset);
    std::copy_n(spaceman.begin() + 0x720, 16 * 2,
        spaceman.begin() + kFreeNextOffset);
    PutU32LE(spaceman, 0x144, static_cast<std::uint32_t>(kXidOffset));
    PutU32LE(spaceman, 0x148, static_cast<std::uint32_t>(kIndexOffset));
    PutU32LE(spaceman, 0x14C, static_cast<std::uint32_t>(kFreeNextOffset));
    PutU32LE(spaceman, 0x154,
        static_cast<std::uint32_t>(kFixedStructureSize));
    FletcherForBlock(spaceman, spaceman.size());
    PutFixtureBlock(fixture.image, kSpacemanBlock, kBlockSize, spaceman);

    VectorRandomAccessSource source(fixture.image);
    std::string error;
    const auto view = LoadAppleCheckpointView(
        source, 0, fixture.image.size(), error);
    return Require(view.has_value() &&
            view->spaceman.internal_pool.bitmap_xid_offset == kXidOffset &&
            view->spaceman.internal_pool.bitmap_index_offset == kIndexOffset &&
            view->spaceman.internal_pool.bitmap_free_next_offset == kFreeNextOffset,
        "Apple spaceman variable arrays may follow the fixed structure: " + error);
}

bool TestAppleSpacemanAcceptsPairKeyFreeQueueFlags()
{
    using apfsaccess::catalog::LoadAppleCheckpointView;
    using apfsaccess::catalog::VectorRandomAccessSource;
    constexpr std::uint64_t kFreeQueueBlock = 89;
    constexpr std::uint32_t kBlockSize = 4096;

    auto fixture = BuildAuthoritativeCheckpointFixture();
    std::vector<std::byte> queue(
        fixture.image.begin() + kFreeQueueBlock * kBlockSize,
        fixture.image.begin() + (kFreeQueueBlock + 1) * kBlockSize);
    PutU32LE(queue, queue.size() - 40, 0x0000000E);
    FletcherForBlock(queue, queue.size());
    PutFixtureBlock(fixture.image, kFreeQueueBlock, kBlockSize, queue);

    VectorRandomAccessSource source(fixture.image);
    std::string error;
    const auto view = LoadAppleCheckpointView(
        source, 0, fixture.image.size(), error);
    return Require(view.has_value() &&
            view->spaceman.free_queues[0].tree_flags == 0x0000000E,
        "Apple free queue accepts fixed pair-key flags: " + error);
}

bool TestAppleSpacemanAcceptsCibTableAfterFixedStructure()
{
    using apfsaccess::catalog::LoadAppleCheckpointView;
    using apfsaccess::catalog::VectorRandomAccessSource;
    constexpr std::uint64_t kSpacemanBlock = 88;
    constexpr std::uint32_t kBlockSize = 4096;
    constexpr std::size_t kCibAddressOffset = 0xA08;

    auto fixture = BuildAuthoritativeCheckpointFixture();
    std::vector<std::byte> spaceman(
        fixture.image.begin() + kSpacemanBlock * kBlockSize,
        fixture.image.begin() + (kSpacemanBlock + 1) * kBlockSize);
    std::copy_n(spaceman.begin() + 0x600, 8,
        spaceman.begin() + kCibAddressOffset);
    PutU32LE(spaceman, 0x50,
        static_cast<std::uint32_t>(kCibAddressOffset));
    PutU32LE(spaceman, 0x154, 0x9D8);
    FletcherForBlock(spaceman, spaceman.size());
    PutFixtureBlock(fixture.image, kSpacemanBlock, kBlockSize, spaceman);

    VectorRandomAccessSource source(fixture.image);
    std::string error;
    const auto view = LoadAppleCheckpointView(
        source, 0, fixture.image.size(), error);
    return Require(view.has_value() &&
            view->spaceman.devices[0].address_offset == kCibAddressOffset &&
            view->spaceman.devices[0].cibs.size() == 1,
        "Apple CIB address table may follow the fixed structure: " + error);
}

bool TestAuthoritativeBuilderSeparatesCheckpointAndAllocatorAreas()
{
    using apfsaccess::catalog::LoadAppleCheckpointView;
    using apfsaccess::catalog::VectorRandomAccessSource;
    BuilderStore store;
    store.authoritative_checkpoint = true;
    const auto image = BuildStoreImage(store);
    VectorRandomAccessSource source(image);
    std::string error;
    const auto view = LoadAppleCheckpointView(source, 0, image.size(), error);
    bool ok = Require(view.has_value(),
        "shared authoritative fixture loads: " + error);
    if (view.has_value())
    {
        ok &= Require(PhysicalAllocatorMetadataOutsideCheckpointRings(*view),
            "shared authoritative fixture keeps allocator metadata out of checkpoint rings");
        ok &= Require(view->spaceman.free_queues[1].tree_oid != 0 &&
                view->spaceman.free_queues[1].tree_node_limit == 64 &&
                view->spaceman.free_queues[1].root.object_id ==
                    view->spaceman.free_queues[1].tree_oid,
            "shared authoritative fixture binds the main-pool free queue");
    }
    return ok;
}

bool TestAppleCheckpointViewRejectsMixedGenerationAndTypeDecoys()
{
    using apfsaccess::catalog::LoadAppleCheckpointView;
    using apfsaccess::catalog::VectorRandomAccessSource;
    bool ok = true;
    const auto rejects = [&](std::vector<std::byte> image,
                             const std::string& expected_error,
                             const std::string& label) {
        VectorRandomAccessSource source(std::move(image));
        std::string error;
        const auto view = LoadAppleCheckpointView(source, 0, source.SizeBytes(), error);
        return Require(!view.has_value() && error == expected_error,
            label + ": " + error);
    };
    {
        auto fixture = BuildAuthoritativeCheckpointFixture();
        PutU64LE(fixture.image, 4 * 4096 + 0x10, fixture.checkpoint_xid + 1);
        std::vector<std::byte> block(fixture.image.begin() + 4 * 4096,
            fixture.image.begin() + 5 * 4096);
        FletcherForBlock(block, block.size());
        PutFixtureBlock(fixture.image, 4, 4096, block);
        ok &= rejects(std::move(fixture.image),
            "AppleVolumeSuperblockFutureXid", "future APSB rejected");
    }
    {
        auto fixture = BuildAuthoritativeCheckpointFixture();
        std::vector<std::byte> block(fixture.image.begin() + 34 * 4096,
            fixture.image.begin() + 35 * 4096);
        PutU32LE(block, 0x1C, 0x0000000F);
        FletcherForBlock(block, block.size());
        PutFixtureBlock(fixture.image, 34, 4096, block);
        ok &= rejects(std::move(fixture.image),
            "AppleTreeSubtypeMismatch", "filesystem root subtype decoy rejected");
    }
    {
        auto fixture = BuildAuthoritativeCheckpointFixture();
        std::vector<std::byte> block(fixture.image.begin() + 34 * 4096,
            fixture.image.begin() + 35 * 4096);
        PutU64LE(block, 0x08, fixture.volume_root_oid + 1);
        FletcherForBlock(block, block.size());
        PutFixtureBlock(fixture.image, 34, 4096, block);
        ok &= rejects(std::move(fixture.image),
            "AppleTreeObjectIdMismatch", "filesystem root oid decoy rejected");
    }
    {
        auto fixture = BuildAuthoritativeCheckpointFixture(false);
        ok &= rejects(std::move(fixture.image),
            "AppleSpacemanFreeQueueUnmapped", "unmapped free queue rejected");
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
    spec.role = 0x40;
    spec.fs_flags = 0x1;
    spec.features = 0x3;
    spec.group_hex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1";
    spec.root_tree_type = 0x00000002;
    spec.extentref_tree_type = 0x40000002;
    spec.snap_meta_tree_type = 0x00000002;
    spec.extentref_tree_oid = 0x3010;
    spec.snap_meta_tree_oid = 0x3020;
    spec.fext_tree_oid = 0x3030;
    spec.fext_tree_type = 0x40000002;
    const auto image = BuildApsb(spec, 7, 4096);
    const auto parsed = ParseApsb(image);
    ok &= Require(parsed.has_value(), "apsb parses");
    if (parsed.has_value())
    {
        ok &= Require(parsed->object_id == 4242, "apsb oid");
        ok &= Require(parsed->xid == 7, "apsb xid");
        ok &= Require(parsed->omap_oid == 0x1000 + 4242, "apsb omap");
        ok &= Require(parsed->root_oid == 0x2000 + 4242, "apsb root");
        ok &= Require(parsed->root_tree_type == 0x00000002, "apsb root tree type");
        ok &= Require(parsed->extentref_tree_type == 0x40000002, "apsb extentref tree type");
        ok &= Require(parsed->snap_meta_tree_type == 0x00000002, "apsb snapshot tree type");
        ok &= Require(parsed->extentref_tree_oid == 0x3010, "apsb extentref tree oid");
        ok &= Require(parsed->snap_meta_tree_oid == 0x3020, "apsb snapshot tree oid");
        ok &= Require(parsed->fext_tree_oid == 0x3030, "apsb sealed fext tree oid");
        ok &= Require(parsed->fext_tree_type == 0x40000002, "apsb sealed fext tree type");
        ok &= Require(parsed->uuid_hex == "1234567890abcdef1234567890abcdef", "apsb uuid");
        ok &= Require(parsed->name_valid && parsed->name_utf8 == "Café Data", "apsb name");
        ok &= Require(parsed->fs_flags == 0x1, "apsb flags");
        ok &= Require(parsed->role_raw == 0x40, "apsb role");
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
        // Decoys at the old, incorrect offsets must not be treated as volume
        // identity fields.
        auto layout = image;
        const char old_name[] = "wrong-name";
        std::memcpy(layout.data() + 0x120, old_name, sizeof(old_name));
        PutU16LE(layout, 0x224, 0x1);
        const auto old_group = HexToBytes("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        std::copy(old_group.begin(), old_group.end(), layout.begin() + 0x228);
        FletcherForBlock(layout, layout.size());
        const auto layout_parsed = ParseApsb(layout);
        ok &= Require(layout_parsed.has_value() &&
            layout_parsed->name_utf8 == "Caf\xC3\xA9 Data" &&
            layout_parsed->role_raw == 0x40 &&
            layout_parsed->group_hex == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1",
            "apsb uses Apple field offsets, not legacy decoys");
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
    {
        auto truncated = image;
        truncated.resize(0x410);
        FletcherForBlock(truncated, truncated.size());
        ok &= Require(!ParseApsb(truncated).has_value(),
            "apsb rejects a buffer truncated before the fext tree type");
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
    auto future = BuildBtreeNode(
        std::vector<std::pair<std::uint64_t, std::uint64_t>>{{101, 40}}, store.xid + 100, 4096);
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
    ok &= Require(CaseModeFor(0x1) == "insensitive", "case insensitive bit");
    ok &= Require(CaseModeFor(0x10) == "sensitive", "incomplete-restore bit is not case mode");
    ok &= Require(CaseModeFor(0x0) == "sensitive", "case sensitive default");
    ok &= Require(EncryptionModeFor(0x0) == "none", "encryption zero");
    ok &= Require(EncryptionModeFor(0x1) == "none", "encryption unencrypted bit");
    ok &= Require(EncryptionModeFor(0x8) == "password", "encryption onekey");
    ok &= Require(EncryptionModeFor(0x2) == "unknown", "reserved crypto flag is not hardware-bound");
    ok &= Require(EncryptionModeFor(0x41) == "none", "non-crypto flags preserve unencrypted state");
    ok &= Require(EncryptionModeFor(0x40) == "unknown", "encryption unknown pattern");
    ok &= Require(RolesFor(0) == std::vector<std::string>{"data"}, "role zero is data");
    ok &= Require(RolesFor(1) == std::vector<std::string>{"system"}, "role system");
    ok &= Require(RolesFor(2) == std::vector<std::string>{"user"}, "role user");
    ok &= Require(RolesFor(4) == std::vector<std::string>{"recovery"}, "role recovery");
    ok &= Require(RolesFor(0x40) == std::vector<std::string>{"data"}, "role data");
    ok &= Require(RolesFor(0x80) == std::vector<std::string>{"baseband"}, "role baseband");
    ok &= Require(RolesFor(0x180) == std::vector<std::string>{"backup"}, "role backup");
    ok &= Require(RolesFor(0x2C0) == std::vector<std::string>{"prelogin"}, "role prelogin");
    ok &= Require(RolesFor(3) == std::vector<std::string>{"unknown"}, "combined role value rejected");
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
        source, disk, disk, catalog, error,
        apfsaccess::catalog::CatalogLoadPolicy::AllowLegacySynthetic);
}

bool TestCatalogStrictCheckpointAuthority()
{
    using apfsaccess::catalog::ApfsContainerCatalog;
    using apfsaccess::catalog::CatalogLoadPolicy;
    using apfsaccess::catalog::VectorRandomAccessSource;
    bool ok = true;

    BuilderImage strict_spec;
    strict_spec.stores.front().authoritative_checkpoint = true;
    strict_spec.stores.front().uuid_hex = "dddddddddddddddddddddddddddddddd";
    strict_spec.stores.front().volumes.front().name = "Strict";
    const auto strict_image = BuildTestImage(strict_spec);
    VectorRandomAccessSource strict_source(strict_image);
    ApfsContainerCatalog strict_catalog;
    std::string error;
    ok &= Require(ApfsContainerCatalog::TryLoadImage(
        strict_source, "strict", "strict", strict_catalog, error,
        CatalogLoadPolicy::StrictApple), "strict catalog loads: " + error);
    if (!ok || strict_catalog.Stores().empty())
    {
        return false;
    }
    const auto* checkpoint = strict_catalog.TryGetAppleCheckpointView(
        strict_catalog.Stores().front().stable_store_id);
    ok &= Require(checkpoint != nullptr, "strict catalog retains checkpoint authority");
    if (checkpoint != nullptr)
    {
        ok &= Require(checkpoint->container.superblock.xid == 7,
            "strict catalog checkpoint xid");
        ok &= Require(checkpoint->volumes.size() == 1 &&
            checkpoint->volumes.front().root_tree.subtype ==
                apfsaccess::catalog::kObjectTypeFsTree,
            "strict catalog retains typed filesystem root");
        ok &= Require(checkpoint->spaceman.free_queue_roots.size() == 2,
            "strict catalog retains both mapped free queue roots");
    }

    BuilderImage legacy_spec;
    const auto legacy_image = BuildTestImage(legacy_spec);
    VectorRandomAccessSource legacy_source(legacy_image);
    ApfsContainerCatalog rejected_catalog;
    error.clear();
    ok &= Require(!ApfsContainerCatalog::TryLoadImage(
        legacy_source, "legacy", "legacy", rejected_catalog, error,
        CatalogLoadPolicy::StrictApple) &&
        error.find("AppleCheckpointLegacySyntheticRejected") != std::string::npos,
        "strict catalog rejects descriptor-less synthetic checkpoint");
    return ok;
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
    // 0x1 (case-insensitive) is known-benign; 0x8000 is unknown.
    spec.stores.front().volumes.front().incompat = 0x8001;
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

namespace
{
// NIST vectors shared by every Sha256Stream implementation (CNG on Windows,
// portable everywhere else): identical input must yield identical digests.
struct Sha256Vector
{
    const char* input;
    std::size_t repeat;
    const char* expected_hex;
};
constexpr Sha256Vector kSha256Vectors[] = {
    {"", 0, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
    {"abc", 1, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
    {"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 1,
     "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"},
    {"a", 1000000, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"},
};
} // namespace

bool TestPortableSha256Vectors()
{
    bool ok = true;
    for (const auto& vector : kSha256Vectors)
    {
        std::string error;
        auto stream = apfsaccess::observer::Sha256Stream::Create(error);
        if (!Require(stream != nullptr, "sha256 stream creates: " + error))
        {
            return false;
        }
        const std::size_t input_length = std::strlen(vector.input);
        std::vector<std::byte> chunk(input_length, std::byte{0});
        for (std::size_t i = 0; i < input_length; ++i)
        {
            chunk[i] = static_cast<std::byte>(vector.input[i]);
        }
        // Feed in odd-sized pieces to cover partial-block buffering.
        std::size_t remaining = vector.repeat == 0 ? 0 : vector.repeat;
        if (vector.repeat != 0 && input_length == 0)
        {
            ok &= Require(false, "sha256 vector needs input bytes to repeat");
            continue;
        }
        bool fed = true;
        if (vector.repeat == 0)
        {
            fed = stream->Update(nullptr, 0);
        }
        std::size_t piece = 1;
        while (remaining > 0 && fed)
        {
            const std::size_t take = (std::min)(remaining, piece);
            for (std::size_t r = 0; r < take && fed; ++r)
            {
                fed = stream->Update(chunk.data(), chunk.size());
            }
            remaining -= take;
            piece = piece * 2 + 1;
        }
        std::string digest;
        ok &= Require(fed && stream->FinalHex(digest), "sha256 streams to completion");
        ok &= Require(digest == vector.expected_hex, "sha256 NIST vector matches");
        std::string second;
        ok &= Require(!stream->FinalHex(second), "sha256 rejects double-finalize");
    }
    return ok;
}

// ---- hardening vectors (Phase A) ----------------------------------------------

bool TestOmapTombstonePrecedence()
{
    using apfsaccess::catalog::ResolveOmapValue;
    using apfsaccess::catalog::VectorRandomAccessSource;
    bool ok = true;
    // A newer DELETED record must shadow an older live mapping (no fallback).
    BuilderStore store;
    store.volumes = {BuilderVolume{}};
    store.volumes[0].oid = 101;
    auto image = BuildStoreImage(store);
    auto tombstoned = BuildBtreeNode(
        {OmapRecordSpec{101, kFirstVolumeBlock, 0, 7},
         OmapRecordSpec{101, 0, 1, 9}},
        7, 4096);
    for (std::size_t i = 0; i < tombstoned.size(); ++i)
    {
        image[3 * 4096 + i] = tombstoned[i];
    }
    VectorRandomAccessSource source(image);
    std::string error;
    ok &= Require(!ResolveOmapValue(source, 4096, kOmapOid, 101, 9, error).has_value(),
        "tombstone shadows live mapping");
    // Same tree at an older xid still resolves through the live record.
    ok &= Require(ResolveOmapValue(source, 4096, kOmapOid, 101, 7, error).has_value() &&
        ResolveOmapValue(source, 4096, kOmapOid, 101, 7, error)->physical_block ==
            kFirstVolumeBlock,
        "live mapping visible at older xid");
    return ok;
}

bool TestBtreeNodeFutureXidFails()
{
    using apfsaccess::catalog::ApfsContainerCatalog;
    bool ok = true;
    BuilderStore store;
    auto image = BuildStoreImage(store);
    // Rewrite the btree node with a future object xid.
    auto future = BuildBtreeNode({{101, kFirstVolumeBlock}}, store.xid, 4096, store.xid + 50);
    for (std::size_t i = 0; i < future.size(); ++i)
    {
        image[3 * 4096 + i] = future[i];
    }
    ApfsContainerCatalog catalog;
    std::string error;
    apfsaccess::catalog::VectorRandomAccessSource source(image);
    ok &= Require(!ApfsContainerCatalog::TryLoadImage(source, "t", "t", catalog, error),
        "future node xid fails");
    return ok;
}

bool TestVolumeBlockOutsideStoreFails()
{
    using apfsaccess::catalog::ApfsContainerCatalog;
    bool ok = true;
    BuilderStore store;
    auto image = BuildStoreImage(store);
    // Point the omap record far outside the store.
    auto evil = BuildBtreeNode(
        std::vector<std::pair<std::uint64_t, std::uint64_t>>{{101, 0xFFFFFFFFFFFFull}},
        store.xid, 4096);
    for (std::size_t i = 0; i < evil.size(); ++i)
    {
        image[3 * 4096 + i] = evil[i];
    }
    ApfsContainerCatalog catalog;
    std::string error;
    apfsaccess::catalog::VectorRandomAccessSource source(image);
    ok &= Require(!ApfsContainerCatalog::TryLoadImage(source, "t", "t", catalog, error),
        "out-of-store volume block fails");
    return ok;
}

bool TestLargeBlockSize()
{
    using apfsaccess::catalog::ApfsContainerCatalog;
    bool ok = true;
    BuilderImage spec;
    spec.gpt = false;
    spec.stores.front().block_size = 8192;
    spec.stores.front().block_count = 32;
    const auto image = BuildTestImage(spec);
    ApfsContainerCatalog catalog;
    std::string error;
    ok &= Require(LoadCatalog(image, catalog, error), "8k blocks load: " + error);
    if (ok)
    {
        ok &= Require(catalog.Containers().front().block_size == 8192, "8k block size kept");
        ok &= Require(catalog.Containers().front().volumes.size() == 1, "8k volume found");
    }
    return ok;
}

bool TestSector4096Gpt()
{
    using apfsaccess::catalog::ApfsContainerCatalog;
    bool ok = true;
    BuilderImage spec;
    spec.sector_size = 4096;
    const auto image = BuildTestImage(spec);
    ApfsContainerCatalog catalog;
    std::string error;
    ok &= Require(LoadCatalog(image, catalog, error), "4k-sector GPT loads: " + error);
    if (ok)
    {
        ok &= Require(catalog.Partitions().size() == 1, "4k-sector partition found");
        ok &= Require(catalog.Containers().front().volumes.size() == 1, "4k-sector volume found");
    }
    return ok;
}

bool TestGptOverlappingPartitionsFail()
{
    using apfsaccess::catalog::ApfsContainerCatalog;
    bool ok = true;
    BuilderImage spec;
    spec.stores.resize(2);
    auto image = BuildTestImage(spec);
    // Slide the second entry back over the first, then repair CRCs.
    for (int i = 0; i < 8; ++i)
    {
        image[2 * 512 + 128 + 32 + static_cast<std::size_t>(i)] =
            image[2 * 512 + 32 + static_cast<std::size_t>(i)];
    }
    RecomputeGptCrcs(image, 512);
    ApfsContainerCatalog catalog;
    std::string error;
    ok &= Require(!LoadCatalog(image, catalog, error), "overlapping GPT fails");
    return ok;
}

bool TestGptEntryOutsideUsableRangeFails()
{
    using apfsaccess::catalog::ApfsContainerCatalog;
    bool ok = true;
    BuilderImage spec;
    spec.stores.resize(2);
    auto image = BuildTestImage(spec);
    // Extend the second entry past the last usable LBA, then repair CRCs.
    PutU64LE(image, 2 * 512 + 128 + 40, 0xFFFFFFFFFFFFull);
    RecomputeGptCrcs(image, 512);
    ApfsContainerCatalog catalog;
    std::string error;
    ok &= Require(!LoadCatalog(image, catalog, error), "out-of-range GPT entry fails");
    return ok;
}

bool TestGptEntriesLbaOutsideDiskFails()
{
    using apfsaccess::catalog::ApfsContainerCatalog;
    bool ok = true;
    BuilderImage spec;
    auto image = BuildTestImage(spec);
    PutU64LE(image, 512 + 72, 0x00FFFFFFFFFFFFFFull);
    // Repair only the header CRC so the entries read itself must fail.
    std::vector<std::byte> header(92, std::byte{0});
    for (std::size_t i = 0; i < 92; ++i)
    {
        header[i] = image[512 + i];
    }
    PutU32LE(header, 16, 0);
    PutU32LE(image, 512 + 16,
        apfsaccess::catalog::Crc32(header.data(), header.size()));
    ApfsContainerCatalog catalog;
    std::string error;
    ok &= Require(!LoadCatalog(image, catalog, error), "wild entries LBA fails");
    return ok;
}

bool TestEmptyVolumeSetFails()
{
    using apfsaccess::catalog::ApfsContainerCatalog;
    bool ok = true;
    BuilderImage spec;
    spec.stores.front().volumes.clear();
    const auto image = BuildTestImage(spec);
    ApfsContainerCatalog catalog;
    std::string error;
    ok &= Require(!LoadCatalog(image, catalog, error), "empty volume set fails");
    return ok;
}

bool TestTooManyVolumesFail()
{
    using apfsaccess::catalog::ApfsContainerCatalog;
    bool ok = true;
    BuilderImage spec;
    spec.gpt = false;
    for (int i = 0; i < 130; ++i)
    {
        BuilderVolume extra;
        extra.oid = static_cast<std::uint64_t>(200 + i);
        extra.name = "vol" + std::to_string(i);
        spec.stores.front().volumes.push_back(extra);
    }
    const auto image = BuildTestImage(spec);
    ApfsContainerCatalog catalog;
    std::string error;
    apfsaccess::catalog::VectorRandomAccessSource source(image);
    ok &= Require(!ApfsContainerCatalog::TryLoadImage(source, "t", "t", catalog, error),
        "oversized volume set fails");
    return ok;
}

bool TestSameOidDifferentContainers()
{
    using apfsaccess::catalog::ApfsContainerCatalog;
    bool ok = true;
    BuilderImage spec;
    spec.stores.resize(2);
    spec.stores[0].uuid_hex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    spec.stores[1].uuid_hex = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    spec.stores[0].volumes.front().oid = 101;
    spec.stores[0].volumes.front().name = "Alpha";
    spec.stores[1].volumes.front().oid = 101;
    spec.stores[1].volumes.front().name = "Beta";
    const auto image = BuildTestImage(spec);
    ApfsContainerCatalog catalog;
    std::string error;
    ok &= Require(LoadCatalog(image, catalog, error), "shared-OID containers load: " + error);
    if (!ok)
    {
        return false;
    }
    // One OID in two containers: independent resolution by (container, name).
    apfsaccess::catalog::ResolvedMountVolume resolved;
    ok &= Require(catalog.TryResolveVolumeByName("Alpha", resolved, error) &&
        resolved.object_id == 101, "alpha resolves: " + error);
    ok &= Require(catalog.TryResolveVolumeByName("Beta", resolved, error) &&
        resolved.object_id == 101, "beta resolves: " + error);
    ok &= Require(catalog.Containers()[0].volumes.front().name_utf8 == "Alpha", "alpha kept");
    ok &= Require(catalog.Containers()[1].volumes.front().name_utf8 == "Beta", "beta kept");
    return ok;
}

bool TestCheckpointAreaNewerWins()
{
    using apfsaccess::catalog::ApfsContainerCatalog;
    bool ok = true;
    BuilderImage spec;
    spec.gpt = false;
    spec.stores.front().xp_desc_base_blocks = 48;
    spec.stores.front().xp_desc_blocks = 4;
    auto image = BuildStoreImage(spec.stores.front());
    // Plant a newer NXSB copy in the descriptor area.
    BuilderStore newer = spec.stores.front();
    newer.xid = spec.stores.front().xid + 10;
    newer.xp_desc_index = 0;
    newer.xp_desc_len = 1;
    newer.xp_desc_next = 1;
    const auto newer_block = BuildNxsb(newer, newer.xid, "", newer.block_size);
    const std::size_t area_off = static_cast<std::size_t>(48) * newer.block_size;
    for (std::size_t i = 0; i < newer_block.size() && area_off + i < image.size(); ++i)
    {
        image[area_off + i] = newer_block[i];
    }
    ApfsContainerCatalog catalog;
    std::string error;
    apfsaccess::catalog::VectorRandomAccessSource source(image);
    ok &= Require(ApfsContainerCatalog::TryLoadImage(source, "t", "t", catalog, error),
        "area checkpoint loads: " + error);
    if (ok)
    {
        ok &= Require(catalog.Containers().front().checkpoint_xid ==
            spec.stores.front().xid + 10, "area checkpoint wins");
    }
    return ok;
}

bool TestCheckpointAreaGarbageIgnored()
{
    using apfsaccess::catalog::ApfsContainerCatalog;
    bool ok = true;
    BuilderImage spec;
    spec.gpt = false;
    spec.stores.front().xp_desc_base_blocks = 48;
    spec.stores.front().xp_desc_blocks = 4;
    auto image = BuildStoreImage(spec.stores.front());
    // Garbage area must not disturb blocks-0/1 selection.
    for (std::size_t i = 0; i < 4 * 4096; ++i)
    {
        image[static_cast<std::size_t>(48) * 4096 + i] = std::byte{0xA5};
    }
    ApfsContainerCatalog catalog;
    std::string error;
    apfsaccess::catalog::VectorRandomAccessSource source(image);
    ok &= Require(ApfsContainerCatalog::TryLoadImage(source, "t", "t", catalog, error),
        "garbage area loads: " + error);
    if (ok)
    {
        ok &= Require(catalog.Containers().front().checkpoint_xid == spec.stores.front().xid,
            "blocks still selected");
    }
    return ok;
}

bool TestNonApfsPartitionSurfaced()
{
    using apfsaccess::catalog::ApfsContainerCatalog;
    bool ok = true;
    BuilderImage spec;
    spec.extra_partition_type_guids.push_back("C12A7328-F81F-11D2-BA4B-00A0C93EC93B");
    const auto image = BuildTestImage(spec);
    ApfsContainerCatalog catalog;
    std::string error;
    ok &= Require(LoadCatalog(image, catalog, error), "mixed partitions load: " + error);
    if (!ok)
    {
        return false;
    }
    ok &= Require(catalog.Partitions().size() == 2, "both partitions listed");
    ok &= Require(catalog.Stores().size() == 1, "only the APFS store parsed");
    if (catalog.Partitions().size() == 2)
    {
        ok &= Require(catalog.Partitions()[1].type_guid == "c12a7328-f81f-11d2-ba4b-00a0c93ec93b",
            "EFI type GUID surfaced");
        ok &= Require(catalog.Partitions()[0].usage == "apfs", "APFS partition usage surfaced");
        ok &= Require(catalog.Partitions()[1].usage == "other", "non-APFS partition usage surfaced");
    }
    return ok;
}

namespace
{
std::atomic<std::uint64_t> g_temp_image_counter{0};
}

// RAII temp fixture file (BlockDevice-backed reader tests). Removed on scope
// exit so failing tests leave no residue.
struct TempImageFile
{
    std::filesystem::path path;
    explicit TempImageFile(
        const std::vector<std::byte>& image,
        const std::string& tag,
        const std::string& extension = ".img")
    {
        const auto stamp = std::chrono::steady_clock::now().time_since_epoch().count();
        const auto name = "apfs-compat-reader-" + tag + "-" +
            std::to_string(static_cast<unsigned long long>(stamp)) + "-" +
            std::to_string(g_temp_image_counter.fetch_add(1)) + extension;
        path = std::filesystem::temp_directory_path() / name;
        std::ofstream out(path, std::ios::binary | std::ios::trunc);
        out.write(reinterpret_cast<const char*>(image.data()),
            static_cast<std::streamsize>(image.size()));
        out.close();
    }
    ~TempImageFile()
    {
        std::error_code ec;
        std::filesystem::remove(path, ec);
    }
    TempImageFile(const TempImageFile&) = delete;
    TempImageFile& operator=(const TempImageFile&) = delete;
};

bool TestMetadataStoreUsesAuthoritativeCheckpointView()
{
    const auto fixture = BuildAuthoritativeCheckpointFixture();
    TempImageFile file(fixture.image, "metadata-store-checkpoint-view");
    apfsaccess::rw::MetadataStore::VolumeContext context;
    context.device_path = file.path.wstring();
    context.volume_object_id = fixture.volume_oid;
    apfsaccess::rw::MetadataStore metadata(std::move(context));
    bool ok = true;
    ok &= Require(metadata.LoadContainerSuperblocks(),
        "metadata store authoritative checkpoint loads");
    ok &= Require(metadata.CheckpointXid().value_or(0) == fixture.checkpoint_xid,
        "metadata store selects descriptor-ring checkpoint");
    const auto* checkpoint = metadata.AuthoritativeAppleCheckpointView();
    ok &= Require(checkpoint != nullptr && checkpoint->volumes.size() == 1 &&
        checkpoint->volumes.front().root_tree.object_id == fixture.volume_root_oid,
        "metadata store retains the full typed Apple checkpoint view");
    return ok;
}

bool TestMetadataStoreProjectsAuthoritativeRegularImage()
{
    const auto fixture = BuildAuthoritativeCheckpointFixture();
    TempImageFile file(fixture.image, "metadata-store-regular-image", ".raw");
    apfsaccess::rw::MetadataStore::VolumeContext context;
    context.device_path = file.path.wstring();
    context.volume_object_id = fixture.volume_oid;
    context.allow_legacy_scaffold_for_fixtures = false;
    apfsaccess::rw::MetadataStore metadata(std::move(context));
    bool ok = true;
    ok &= Require(metadata.LoadContainerSuperblocks(),
        "regular image authoritative checkpoint loads");
    ok &= Require(metadata.LoadObjectMap(),
        "regular image projects through the authoritative reader");
    ok &= Require(metadata.CommittedInodeCount() == 1,
        "regular image projection contains the root inode");
    const auto root = metadata.LookupCommittedInodeByObjectId(2);
    ok &= Require(root.has_value() && root->is_directory && root->full_path == L"\\",
        "regular image projection exposes the root directory");
    return ok;
}

bool TestMetadataStoreCommitsAppleFileToAuthoritativeImage()
{
    const auto fixture = BuildAuthoritativeCheckpointFixture();
    TempImageFile file(fixture.image, "metadata-store-apple-commit", ".raw");
    apfsaccess::rw::MetadataStore::VolumeContext context;
    context.device_path = file.path.wstring();
    context.volume_object_id = fixture.volume_oid;
    context.allow_legacy_scaffold_for_fixtures = false;
    context.integrity_check_on_mount = false;

    std::vector<std::byte> payload(7000);
    for (std::size_t index = 0; index < payload.size(); ++index)
    {
        payload[index] = static_cast<std::byte>((index * 29u + 17u) & 0xffu);
    }

    apfsaccess::rw::MetadataStore metadata(context);
    metadata.SetFilePayloadProvider(
        [&payload](const std::wstring& path, std::uint64_t logical_size)
            -> std::optional<std::vector<std::byte>>
        {
            if (path != L"\\apple.bin" || logical_size != payload.size())
            {
                return std::nullopt;
            }
            return payload;
        });

    bool ok = true;
    const auto prepared = metadata.PrepareNativeWritePath();
    if (!prepared)
    {
        std::wcerr << L"[DETAIL] Apple writer preparation: "
                   << metadata.RecoveryReason() << std::endl;
    }
    ok &= Require(prepared, "authoritative image prepares the Apple writer");
    apfsaccess::rw::MetadataStore::MutationRequest create;
    create.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
    create.path = L"\\apple.bin";
    ok &= Require(metadata.StageMutation(create) ==
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "Apple create stages");
    apfsaccess::rw::MetadataStore::MutationRequest write;
    write.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
    write.path = create.path;
    write.length = payload.size();
    ok &= Require(metadata.StageMutation(write) ==
            apfsaccess::rw::MetadataStore::MutationStatus::Applied,
        "Apple payload stages");
    const auto commit_status = metadata.CommitPendingMutations();
    if (commit_status != apfsaccess::rw::MetadataStore::CommitStatus::Committed)
    {
        std::wcerr << L"[DETAIL] Apple commit status="
                   << static_cast<int>(commit_status)
                   << L" stage=" << metadata.LastCommitStage().c_str()
                   << L" reason=" << metadata.LastCommitFailureReason()
                   << L" detail=" << metadata.LastCommitFailureDetail()
                   << std::endl;
        if (const auto* view = metadata.AuthoritativeAppleCheckpointView();
            view != nullptr)
        {
            const auto& queue = view->spaceman.free_queues[1];
            std::cerr << "[DETAIL] checkpoint block="
                      << view->container.superblock.block_size
                      << " nextXid=" << view->container.superblock.next_xid
                      << " queueOid=" << queue.tree_oid
                      << " flags=" << queue.tree_flags
                      << " fixedKey=" << queue.fixed_key_size
                      << " fixedValue=" << queue.fixed_value_size
                      << " nodeLimit=" << queue.tree_node_limit
                      << std::endl;
        }
    }
    ok &= Require(commit_status ==
            apfsaccess::rw::MetadataStore::CommitStatus::Committed,
        "Apple transaction commits");

    apfsaccess::rw::MetadataStore reopened(context);
    ok &= Require(reopened.LoadCanonicalState(),
        "Apple transaction reopens through canonical state");
    const auto inode = reopened.LookupCommittedInodeByPath(L"\\apple.bin");
    ok &= Require(inode.has_value() && inode->logical_size == payload.size(),
        "reopened Apple inode has the committed size");
    std::vector<std::byte> actual;
    ok &= Require(reopened.ReadCommittedFileRange(
            L"\\apple.bin", 0, payload.size(), actual) && actual == payload,
        "reopened Apple payload is byte exact");

    std::ifstream input(file.path, std::ios::binary);
    std::vector<char> bytes(
        (std::istreambuf_iterator<char>(input)),
        std::istreambuf_iterator<char>());
    constexpr std::string_view private_magic = "APFSRW";
    ok &= Require(std::search(bytes.begin(), bytes.end(),
            private_magic.begin(), private_magic.end()) == bytes.end(),
        "Apple transaction contains no private APFSRW marker");
    return ok;
}

bool TestMetadataStoreAppleTransactionLifecycle()
{
    const auto fixture = BuildAuthoritativeCheckpointFixture();
    TempImageFile file(fixture.image, "metadata-store-apple-lifecycle", ".raw");
    apfsaccess::rw::MetadataStore::VolumeContext context;
    context.device_path = file.path.wstring();
    context.volume_object_id = fixture.volume_oid;
    context.allow_legacy_scaffold_for_fixtures = false;
    context.integrity_check_on_mount = false;

    std::vector<std::byte> initial_payload(7000);
    std::vector<std::byte> replacement_payload(9137);
    for (std::size_t index = 0; index < initial_payload.size(); ++index)
    {
        initial_payload[index] = static_cast<std::byte>((index * 29u + 17u) & 0xffu);
    }
    for (std::size_t index = 0; index < replacement_payload.size(); ++index)
    {
        replacement_payload[index] = static_cast<std::byte>((index * 43u + 11u) & 0xffu);
    }

    const auto configure_payload = [](
        apfsaccess::rw::MetadataStore& store,
        const std::wstring& expected_path,
        const std::vector<std::byte>& expected_payload)
    {
        store.SetFilePayloadProvider(
            [expected_path, &expected_payload](
                const std::wstring& path,
                std::uint64_t logical_size) -> std::optional<std::vector<std::byte>>
            {
                if (path != expected_path || logical_size != expected_payload.size())
                {
                    return std::nullopt;
                }
                return expected_payload;
            });
    };
    const auto commit = [](apfsaccess::rw::MetadataStore& store, const char* operation)
    {
        const auto status = store.CommitPendingMutations();
        if (status != apfsaccess::rw::MetadataStore::CommitStatus::Committed)
        {
            std::wcerr << L"[DETAIL] Apple lifecycle " << operation
                       << L" status=" << static_cast<int>(status)
                       << L" stage=" << store.LastCommitStage().c_str()
                       << L" reason=" << store.LastCommitFailureReason()
                       << L" detail=" << store.LastCommitFailureDetail()
                       << std::endl;
        }
        return status == apfsaccess::rw::MetadataStore::CommitStatus::Committed;
    };
    const auto payload_matches = [](
        apfsaccess::rw::MetadataStore& store,
        const std::wstring& path,
        const std::vector<std::byte>& expected)
    {
        std::vector<std::byte> actual;
        return store.ReadCommittedFileRange(path, 0, expected.size(), actual) &&
            actual == expected;
    };

    bool ok = true;
    {
        apfsaccess::rw::MetadataStore store(context);
        configure_payload(store, L"\\apple.bin", initial_payload);
        ok &= Require(store.PrepareNativeWritePath(),
            "Apple lifecycle create prepares");
        apfsaccess::rw::MetadataStore::MutationRequest create;
        create.operation = apfsaccess::rw::MetadataStore::MutationOperation::CreateFile;
        create.path = L"\\apple.bin";
        ok &= Require(store.StageMutation(create) ==
                apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Apple lifecycle create stages");
        apfsaccess::rw::MetadataStore::MutationRequest write;
        write.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write.path = create.path;
        write.length = initial_payload.size();
        ok &= Require(store.StageMutation(write) ==
                apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Apple lifecycle initial payload stages");
        ok &= Require(commit(store, "create"), "Apple lifecycle create commits");
    }

    {
        apfsaccess::rw::MetadataStore store(context);
        ok &= Require(store.PrepareNativeWritePath(),
            "Apple lifecycle rename remounts");
        ok &= Require(payload_matches(store, L"\\apple.bin", initial_payload),
            "Apple lifecycle initial payload survives remount");
        apfsaccess::rw::MetadataStore::MutationRequest rename;
        rename.operation = apfsaccess::rw::MetadataStore::MutationOperation::Rename;
        rename.path = L"\\apple.bin";
        rename.secondary_path = L"\\renamed.bin";
        ok &= Require(store.StageMutation(rename) ==
                apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Apple lifecycle rename stages");
        ok &= Require(commit(store, "rename"), "Apple lifecycle rename commits");
    }

    {
        apfsaccess::rw::MetadataStore store(context);
        configure_payload(store, L"\\renamed.bin", replacement_payload);
        ok &= Require(store.PrepareNativeWritePath(),
            "Apple lifecycle rewrite remounts");
        ok &= Require(!store.LookupCommittedInodeByPath(L"\\apple.bin").has_value(),
            "Apple lifecycle old name is absent after remount");
        ok &= Require(payload_matches(store, L"\\renamed.bin", initial_payload),
            "Apple lifecycle rename preserves payload");
        apfsaccess::rw::MetadataStore::MutationRequest resize;
        resize.operation = apfsaccess::rw::MetadataStore::MutationOperation::SetFileSize;
        resize.path = L"\\renamed.bin";
        resize.length = replacement_payload.size();
        ok &= Require(store.StageMutation(resize) ==
                apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Apple lifecycle resize stages");
        apfsaccess::rw::MetadataStore::MutationRequest write;
        write.operation = apfsaccess::rw::MetadataStore::MutationOperation::Write;
        write.path = resize.path;
        write.length = replacement_payload.size();
        ok &= Require(store.StageMutation(write) ==
                apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Apple lifecycle replacement payload stages");
        ok &= Require(commit(store, "rewrite"), "Apple lifecycle rewrite commits");
    }

    {
        apfsaccess::rw::MetadataStore store(context);
        ok &= Require(store.PrepareNativeWritePath(),
            "Apple lifecycle delete remounts");
        const auto inode = store.LookupCommittedInodeByPath(L"\\renamed.bin");
        ok &= Require(inode.has_value() &&
                inode->logical_size == replacement_payload.size(),
            "Apple lifecycle replacement size survives remount");
        ok &= Require(payload_matches(store, L"\\renamed.bin", replacement_payload),
            "Apple lifecycle replacement payload survives remount");
        apfsaccess::rw::MetadataStore::MutationRequest remove;
        remove.operation = apfsaccess::rw::MetadataStore::MutationOperation::Delete;
        remove.path = L"\\renamed.bin";
        ok &= Require(store.StageMutation(remove) ==
                apfsaccess::rw::MetadataStore::MutationStatus::Applied,
            "Apple lifecycle delete stages");
        ok &= Require(commit(store, "delete"), "Apple lifecycle delete commits");
    }

    {
        apfsaccess::rw::MetadataStore store(context);
        ok &= Require(store.LoadCanonicalState(),
            "Apple lifecycle final image reopens");
        ok &= Require(!store.LookupCommittedInodeByPath(L"\\renamed.bin").has_value(),
            "Apple lifecycle deleted file stays absent after remount");
        ok &= Require(store.CommittedInodeCount() == 1,
            "Apple lifecycle returns to the root-only inode graph");
    }

    std::ifstream input(file.path, std::ios::binary);
    std::vector<char> bytes(
        (std::istreambuf_iterator<char>(input)),
        std::istreambuf_iterator<char>());
    constexpr std::string_view private_magic = "APFSRW";
    ok &= Require(std::search(bytes.begin(), bytes.end(),
            private_magic.begin(), private_magic.end()) == bytes.end(),
        "Apple lifecycle contains no private APFSRW marker");
    return ok;
}

bool TestReaderCatalogTombstoneShadows()
{
    // Newer tombstone (xid 9) shadows the live record (xid 7) once the
    // selected checkpoint (xid 12) can see it. The legacy block-0 projection
    // cannot see the tombstone and succeeds.
    BuilderStore store;
    store.second_xid_offset = 5;
    store.volumes[0].projectable = true;
    OmapRecordSpec tombstone;
    tombstone.oid = 101;
    tombstone.paddr = kFirstVolumeBlock;
    tombstone.flags = 1;
    tombstone.xid = 9;
    store.extra_omap_records.push_back(tombstone);
    const auto image = BuildStoreImage(store);
    TempImageFile file(image, "tombstone");
    apfsaccess::rw::BlockDevice device(file.path.wstring(), 0);
    apfsaccess::rw::NativeApfsVolumeProjection projection{};
    std::wstring error;
    const bool loaded = apfsaccess::rw::NativeApfsReader::TryLoadVolumeProjection(
        device, 101, projection, error);
    return Require(!loaded, "catalog-authority reader must honor the newer tombstone");
}

bool TestReaderSelectsNewestCheckpoint()
{
    // Block zero is only the xid-7 geometry anchor. The complete descriptor
    // generation at xid 20 is the sole authority used by the reader.
    const auto fixture = BuildAuthoritativeCheckpointFixture();
    TempImageFile file(fixture.image, "authoritative-newest");
    apfsaccess::rw::BlockDevice device(file.path.wstring(), 0);
    apfsaccess::rw::NativeApfsVolumeProjection projection{};
    std::wstring error;
    const bool loaded = apfsaccess::rw::NativeApfsReader::TryLoadVolumeProjection(
        device, fixture.volume_oid, projection, error);
    bool ok = Require(loaded,
        "reader projects authoritative descriptor generation");
    if (loaded)
    {
        ok &= Require(projection.checkpoint_xid == fixture.checkpoint_xid,
            "projection uses descriptor-ring checkpoint");
        ok &= Require(projection.volume_object_id == fixture.volume_oid,
            "projection targets selected volume");
        ok &= Require(!projection.inodes.empty(), "projection carries inodes");
    }
    return ok;
}

bool TestReaderRejectsProximityScan()
{
    // Primary APSB carries an unresolvable root OID while a fully valid decoy
    // copy of the same volume sits 16 blocks away. Legacy proximity scanning
    // finds the decoy and succeeds; catalog authority must fail instead.
    BuilderStore store;
    store.volumes[0].projectable = true;
    store.volumes[0].root_oid_override = 0xFFFF;
    store.volumes[0].decoy_root_block = 20;
    const auto image = BuildStoreImage(store);
    TempImageFile file(image, "noscan");
    apfsaccess::rw::BlockDevice device(file.path.wstring(), 0);
    apfsaccess::rw::NativeApfsVolumeProjection projection{};
    std::wstring error;
    const bool loaded = apfsaccess::rw::NativeApfsReader::TryLoadVolumeProjection(
        device, 101, projection, error);
    return Require(!loaded, "catalog-authority reader must not proximity-scan");
}

bool TestCatalogResolveVolumeContainerQualified()
{
    using apfsaccess::catalog::ApfsContainerCatalog;
    bool ok = true;
    BuilderImage spec;
    spec.stores.resize(2);
    spec.stores[0].uuid_hex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    spec.stores[1].uuid_hex = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    spec.stores[0].volumes.front().oid = 101;
    spec.stores[0].volumes.front().name = "Alpha";
    spec.stores[1].volumes.front().oid = 101;
    spec.stores[1].volumes.front().name = "Beta";
    const auto image = BuildTestImage(spec);
    ApfsContainerCatalog catalog;
    std::string error;
    ok &= Require(LoadCatalog(image, catalog, error), "shared-OID catalog loads: " + error);
    if (!ok)
    {
        return false;
    }
    apfsaccess::catalog::ResolvedMountVolume resolved;
    ok &= Require(catalog.TryResolveVolume(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 101, resolved, error) &&
        resolved.name_utf8 == "Alpha", "container A resolves Alpha: " + error);
    ok &= Require(catalog.TryResolveVolume(
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 101, resolved, error) &&
        resolved.name_utf8 == "Beta", "container B resolves Beta: " + error);
    ok &= Require(!catalog.TryResolveVolume(
        "cccccccccccccccccccccccccccccccc", 101, resolved, error),
        "unknown container fails");
    ok &= Require(!catalog.TryResolveVolume(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 999, resolved, error),
        "unknown OID fails");
    ok &= Require(!catalog.TryResolveVolume("", 101, resolved, error),
        "empty container fails");
    return ok;
}

bool TestCatalogResolveVolumeByNameInScopedContainer()
{
    using apfsaccess::catalog::ApfsContainerCatalog;
    bool ok = true;
    BuilderImage spec;
    spec.stores.resize(2);
    spec.stores[0].uuid_hex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    spec.stores[1].uuid_hex = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    spec.stores[0].volumes.front().oid = 101;
    spec.stores[0].volumes.front().name = "Data";
    spec.stores[1].volumes.front().oid = 102;
    spec.stores[1].volumes.front().name = "Data";
    const auto image = BuildTestImage(spec);
    ApfsContainerCatalog catalog;
    std::string error;
    ok &= Require(LoadCatalog(image, catalog, error), "same-name catalog loads: " + error);
    if (!ok)
    {
        return false;
    }
    apfsaccess::catalog::ResolvedMountVolume resolved;
    ok &= Require(!catalog.TryResolveVolumeByName("Data", resolved, error),
        "unscoped duplicate name fails");
    ok &= Require(catalog.TryResolveVolumeByNameInContainer(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "Data", resolved, error) &&
        resolved.object_id == 101, "scoped container A resolves: " + error);
    ok &= Require(catalog.TryResolveVolumeByNameInContainer(
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "Data", resolved, error) &&
        resolved.object_id == 102, "scoped container B resolves: " + error);
    ok &= Require(!catalog.TryResolveVolumeByNameInContainer(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "Missing", resolved, error),
        "scoped missing name fails");
    return ok;
}

} // namespace

int main(int argc, char** argv)
{
    auto run = [&](const char* name, bool (*fn)())
    {
        std::cout << "[RUN] " << name << std::endl;
        const bool result = fn();
        std::cout << (result ? "[PASS] " : "[DONE-FAIL] ") << name << std::endl;
        return result;
    };
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
            spec.stores.front().authoritative_checkpoint = true;
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
        for (auto& store : spec.stores)
        {
            store.authoritative_checkpoint = true;
        }
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
    ok &= run("TestLeReaders", TestLeReaders);
    ok &= run("TestFletcher64", TestFletcher64);
    ok &= run("TestCrc32", TestCrc32);
    ok &= run("TestGuidStrings", TestGuidStrings);
    ok &= run("TestGptRoundTrip", TestGptRoundTrip);
    ok &= run("TestGptRejections", TestGptRejections);
    ok &= run("TestNxsbRoundTrip", TestNxsbRoundTrip);
    ok &= run("TestCheckpointViewWrapsAndValidatesMappings", TestCheckpointViewWrapsAndValidatesMappings);
    ok &= run("TestCheckpointViewFallsBackFromMalformedNewest", TestCheckpointViewFallsBackFromMalformedNewest);
    ok &= run("TestCheckpointViewRejectsDecoysAndUnsupportedLayout", TestCheckpointViewRejectsDecoysAndUnsupportedLayout);
    ok &= run("TestAppleCheckpointViewBindsOneTransaction", TestAppleCheckpointViewBindsOneTransaction);
    ok &= run("TestAppleSpacemanAcceptsEmptyTier2DescriptorOffset", TestAppleSpacemanAcceptsEmptyTier2DescriptorOffset);
    ok &= run("TestAppleSpacemanAcceptsVariableArraysAfterFixedStructure", TestAppleSpacemanAcceptsVariableArraysAfterFixedStructure);
    ok &= run("TestAppleSpacemanAcceptsPairKeyFreeQueueFlags", TestAppleSpacemanAcceptsPairKeyFreeQueueFlags);
    ok &= run("TestAppleSpacemanAcceptsCibTableAfterFixedStructure", TestAppleSpacemanAcceptsCibTableAfterFixedStructure);
    ok &= run("TestAuthoritativeBuilderSeparatesCheckpointAndAllocatorAreas", TestAuthoritativeBuilderSeparatesCheckpointAndAllocatorAreas);
    ok &= run("TestAppleCheckpointViewRejectsMixedGenerationAndTypeDecoys", TestAppleCheckpointViewRejectsMixedGenerationAndTypeDecoys);
    ok &= run("TestApsbRoundTrip", TestApsbRoundTrip);
    ok &= run("TestOmapResolve", TestOmapResolve);
    ok &= run("TestInterpretation", TestInterpretation);
    ok &= run("TestCatalogStrictCheckpointAuthority", TestCatalogStrictCheckpointAuthority);
    ok &= run("TestCatalogSingleVolume", TestCatalogSingleVolume);
    ok &= run("TestCatalogPartitionless", TestCatalogPartitionless);
    ok &= run("TestCatalogNoGptNoNxsb", TestCatalogNoGptNoNxsb);
    ok &= run("TestCatalogMultiContainer", TestCatalogMultiContainer);
    ok &= run("TestCatalogTwoVolumes", TestCatalogTwoVolumes);
    ok &= run("TestCatalogSameNameVolumes", TestCatalogSameNameVolumes);
    ok &= run("TestCatalogUnknownBits", TestCatalogUnknownBits);
    ok &= run("TestCatalogStaleXid", TestCatalogStaleXid);
    ok &= run("TestCatalogCorruptVolume", TestCatalogCorruptVolume);
    ok &= run("TestCatalogDuplicateOid", TestCatalogDuplicateOid);
    ok &= run("TestCatalogDuplicateVolumeUuid", TestCatalogDuplicateVolumeUuid);
    ok &= run("TestCatalogMissingVolume", TestCatalogMissingVolume);
    ok &= run("TestCatalogTruncated", TestCatalogTruncated);
    ok &= run("TestCatalogVolumeGroups", TestCatalogVolumeGroups);
    ok &= run("TestCatalogFusionStores", TestCatalogFusionStores);
    ok &= run("TestSourceBounds", TestSourceBounds);
    ok &= run("TestOmapTombstonePrecedence", TestOmapTombstonePrecedence);
    ok &= run("TestBtreeNodeFutureXidFails", TestBtreeNodeFutureXidFails);
    ok &= run("TestVolumeBlockOutsideStoreFails", TestVolumeBlockOutsideStoreFails);
    ok &= run("TestLargeBlockSize", TestLargeBlockSize);
    ok &= run("TestSector4096Gpt", TestSector4096Gpt);
    ok &= run("TestGptOverlappingPartitionsFail", TestGptOverlappingPartitionsFail);
    ok &= run("TestGptEntryOutsideUsableRangeFails", TestGptEntryOutsideUsableRangeFails);
    ok &= run("TestGptEntriesLbaOutsideDiskFails", TestGptEntriesLbaOutsideDiskFails);
    ok &= run("TestEmptyVolumeSetFails", TestEmptyVolumeSetFails);
    ok &= run("TestTooManyVolumesFail", TestTooManyVolumesFail);
    ok &= run("TestSameOidDifferentContainers", TestSameOidDifferentContainers);
    ok &= run("TestCheckpointAreaNewerWins", TestCheckpointAreaNewerWins);
    ok &= run("TestCheckpointAreaGarbageIgnored", TestCheckpointAreaGarbageIgnored);
    ok &= run("TestNonApfsPartitionSurfaced", TestNonApfsPartitionSurfaced);
    ok &= run("TestMetadataStoreUsesAuthoritativeCheckpointView", TestMetadataStoreUsesAuthoritativeCheckpointView);
    ok &= run("TestMetadataStoreProjectsAuthoritativeRegularImage", TestMetadataStoreProjectsAuthoritativeRegularImage);
    ok &= run("TestMetadataStoreCommitsAppleFileToAuthoritativeImage", TestMetadataStoreCommitsAppleFileToAuthoritativeImage);
    ok &= run("TestMetadataStoreAppleTransactionLifecycle", TestMetadataStoreAppleTransactionLifecycle);
    ok &= run("TestReaderCatalogTombstoneShadows", TestReaderCatalogTombstoneShadows);
    ok &= run("TestReaderSelectsNewestCheckpoint", TestReaderSelectsNewestCheckpoint);
    ok &= run("TestReaderRejectsProximityScan", TestReaderRejectsProximityScan);
    ok &= run("TestCatalogResolveVolumeContainerQualified", TestCatalogResolveVolumeContainerQualified);
    ok &= run("TestCatalogResolveVolumeByNameInScopedContainer", TestCatalogResolveVolumeByNameInScopedContainer);
    ok &= run("TestPortableSha256Vectors", TestPortableSha256Vectors);
    if (ok)
    {
        std::cout << "APFS COMPATIBILITY PASS" << std::endl;
        return 0;
    }
    std::cerr << "APFS COMPATIBILITY FAIL: " << g_failures << " check(s)" << std::endl;
    return 1;
}
