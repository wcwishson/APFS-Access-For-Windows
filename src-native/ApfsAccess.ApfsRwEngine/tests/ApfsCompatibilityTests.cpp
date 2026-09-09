// Task 1 compatibility vectors: portable format primitives, GPT/container/
// volume parsing, and catalog topology over synthetic images.
//
// The synthetic builder below writes the exact byte contract from
// task-1-interface-freeze.md section 5; the parser under test must read it
// back. A second builder lives in managed SyntheticApfsTestImage (test-only
// fixture writer, never a parser); the fixed repo-owned observer
// cross-validates both.

#include "ApfsContainerCatalog.h"
#include "ApfsReadBudgetTests.h"
#include "ApfsRecoveryBudgetTests.h"
#include "ApfsFormat.h"
#include "ApfsExtendedRecordCodec.h"
#include "ApfsNameCodec.h"
#include "ApfsTransactionWriter.h"
#include "AppleVolumeTransaction.h"
#include "BlockDevice.h"
#include "MetadataStore.h"
#include "WriteAheadLog.h"
#include "TransactionManager.h"
#include "InodeMetadataPatch.h"
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
#include <map>
#include <set>
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
    // Root, extent-reference, snapshot, and fext trees plus the volume object
    // map object and its tree are all allocated to this volume.
    volume.file_system_allocated_blocks = 6;
    volume.total_blocks_allocated = 6;
    volume.next_object_id = 0x6000;
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

AuthoritativeCheckpointFixture BuildRetainedCheckpointFixture(
    std::uint64_t newer_xid = 21)
{
    auto fixture = BuildAuthoritativeCheckpointFixture();
    constexpr std::uint32_t block_size = 4096;
    const auto read_block = [&](std::uint64_t block) {
        const auto begin = fixture.image.begin() + block * block_size;
        return std::vector<std::byte>(begin, begin + block_size);
    };

    // Reserve both generations' physical metadata in the shared allocation map.
    auto bitmap = read_block(104);
    for (const auto block : {36u, 37u, 38u, 39u, 42u, 43u})
    {
        bitmap[block / 8] |= static_cast<std::byte>(1u << (block % 8));
    }
    PutFixtureBlock(fixture.image, 104, block_size, bitmap);
    auto cib = read_block(102);
    PutU32LE(cib, 0x3C, apfsaccess::catalog::ReadU32LE(cib, 0x3C).value() - 6);
    FletcherForBlock(cib, block_size);
    PutFixtureBlock(fixture.image, 102, block_size, cib);
    auto spaceman = read_block(88);
    PutU64LE(spaceman, 0x48,
        apfsaccess::catalog::ReadU64LE(spaceman, 0x48).value() - 6);
    FletcherForBlock(spaceman, block_size);
    PutFixtureBlock(fixture.image, 88, block_size, spaceman);

    std::vector<CheckpointMappingSpec> mappings;
    for (std::uint64_t ordinal = 0; ordinal < 3; ++ordinal)
    {
        auto object = read_block(88 + ordinal);
        PutU64LE(object, 0x10, newer_xid);
        FletcherForBlock(object, block_size);
        PutFixtureBlock(fixture.image, 91 + ordinal, block_size, object);
        CheckpointMappingSpec mapping;
        mapping.object_id = fixture.spaceman_oid + ordinal;
        mapping.type = ordinal == 0 ? 0x80000005 : 0x80000002;
        mapping.subtype = ordinal == 0 ? 0 : 0x00000009;
        mapping.physical_block = 91 + ordinal;
        mappings.push_back(mapping);
    }
    PutFixtureBlock(fixture.image, 82, block_size,
        BuildCheckpointMap(newer_xid, mappings, block_size, 82));
    auto nxsb = read_block(81);
    PutU64LE(nxsb, 0x10, newer_xid);
    PutU64LE(nxsb, 0x60, newer_xid + 1);
    PutU32LE(nxsb, 0x80, 4);
    PutU32LE(nxsb, 0x84, 6);
    PutU32LE(nxsb, 0x88, 2);
    PutU32LE(nxsb, 0x90, 3);
    PutU64LE(nxsb, 0xA0, 42);
    FletcherForBlock(nxsb, block_size);
    PutFixtureBlock(fixture.image, 83, block_size, nxsb);

    PutFixtureBlock(fixture.image, 42, block_size,
        BuildOmap(43, newer_xid, block_size, 42, 0x4000000B, 0x40000002));
    PutFixtureBlock(fixture.image, 43, block_size,
        BuildBtreeNode({OmapRecordSpec{fixture.volume_oid, 39, 0, newer_xid}},
            newer_xid, block_size, 0, 43, 0x40000002, 0x0000000B));
    auto apsb = read_block(4);
    PutU64LE(apsb, 0x10, newer_xid);
    PutU64LE(apsb, 0x80, 37);
    FletcherForBlock(apsb, block_size);
    PutFixtureBlock(fixture.image, 39, block_size, apsb);
    PutFixtureBlock(fixture.image, 37, block_size,
        BuildOmap(38, newer_xid, block_size, 37, 0x4000000B, 0x40000002));
    PutFixtureBlock(fixture.image, 38, block_size,
        BuildBtreeNode({
            OmapRecordSpec{fixture.volume_root_oid, 36, 0, newer_xid},
            OmapRecordSpec{fixture.snapshot_root_oid, 35, 0, 20}},
            newer_xid, block_size, 0, 38, 0x40000002, 0x0000000B));
    PutFixtureBlock(fixture.image, 36, block_size,
        BuildRootFsLeaf(newer_xid, block_size,
            fixture.volume_root_oid, 0x00000002, 0x0000000E));
    return fixture;
}

bool TestExactCheckpointSelectsRetainedGeneration()
{
    using namespace apfsaccess::catalog;
    const auto fixture = BuildRetainedCheckpointFixture();
    VectorRandomAccessSource source(fixture.image);
    bool ok = true;
    for (const std::optional<std::uint64_t> target :
         {std::optional<std::uint64_t>{}, std::optional<std::uint64_t>{20},
             std::optional<std::uint64_t>{21}})
    {
        const bool older = target == 20;
        std::string error = "stale error";
        const auto container = target.has_value()
            ? LoadContainerCheckpointView(source, 0, source.SizeBytes(), error, target)
            : LoadContainerCheckpointView(source, 0, source.SizeBytes(), error);
        ok &= Require(container.has_value() && error.empty(),
            "latest or exact container checkpoint loads: " + error);
        if (container.has_value())
        {
            ok &= Require(container->superblock.xid == (older ? 20u : 21u) &&
                container->superblock_physical_block == (older ? 81u : 83u) &&
                container->checkpoint_map_blocks ==
                    std::vector<std::uint64_t>{older ? 80u : 82u},
                "checkpoint selection binds the requested descriptor generation");
        }
        error = "stale error";
        const auto apple = target.has_value()
            ? LoadAppleCheckpointView(source, 0, source.SizeBytes(), error, target)
            : LoadAppleCheckpointView(source, 0, source.SizeBytes(), error);
        ok &= Require(apple.has_value() && error.empty(),
            "latest or exact Apple checkpoint loads: " + error);
        if (!apple.has_value() || !Require(apple->volumes.size() == 1,
                "exact Apple checkpoint retains its volume"))
        {
            ok = false;
            continue;
        }
        const auto& volume = apple->volumes.front();
        ok &= Require(apple->container.superblock.xid == (older ? 20u : 21u) &&
            apple->container_object_map.object.physical_block == (older ? 2u : 42u) &&
            apple->spaceman.object.physical_block == (older ? 88u : 91u) &&
            volume.superblock_object.physical_block == (older ? 4u : 39u) &&
            volume.object_map.object.physical_block == (older ? 32u : 37u) &&
            volume.root_tree.physical_block == (older ? 34u : 36u) &&
            volume.root_tree.xid == (older ? 20u : 21u),
            "exact Apple roots come from the selected generation, not latest");
        ok &= Require(volume.extentref_tree.has_value() &&
            volume.extentref_tree->physical_block == 40 &&
            volume.snapshot_metadata_tree.has_value() &&
            volume.snapshot_metadata_tree->physical_block == 35 &&
            volume.file_extent_tree.has_value() &&
            volume.file_extent_tree->physical_block == 41,
            "exact Apple checkpoint resolves all shared optional roots");
    }
    return ok;
}

bool TestExactCheckpointRejectsUnavailableAndCorruptGeneration()
{
    using namespace apfsaccess::catalog;
    const auto fixture = BuildRetainedCheckpointFixture();
    VectorRandomAccessSource source(fixture.image);
    bool ok = true;
    for (const auto target : {0ull, 7ull, 19ull, 22ull})
    {
        std::string error;
        ok &= Require(!LoadContainerCheckpointView(
                source, 0, source.SizeBytes(), error, target).has_value() && !error.empty(),
            "exact container rejects zero, anchor-only, missing or future XID");
        error.clear();
        ok &= Require(!LoadAppleCheckpointView(
                source, 0, source.SizeBytes(), error, target).has_value() && !error.empty(),
            "exact Apple rejects zero, anchor-only, missing or future XID");
    }
    for (const auto block : {80u, 81u, 88u, 2u, 4u, 32u, 34u, 82u, 83u, 91u})
    {
        auto image = fixture.image;
        image[static_cast<std::size_t>(block) * 4096 + 64] ^= std::byte{0x5A};
        VectorRandomAccessSource corrupt_source(image);
        const bool newest_corrupt = block == 82 || block == 83 || block == 91;
        const bool container_corrupt = block >= 80;
        const std::uint64_t target = newest_corrupt ? 21 : 20;
        const auto label = " at block " + std::to_string(block);
        std::string error;
        const auto container = LoadContainerCheckpointView(
            corrupt_source, 0, image.size(), error, target);
        ok &= Require(container.has_value() != container_corrupt,
            "exact container applies complete-generation validation" + label);
        error.clear();
        ok &= Require(!LoadAppleCheckpointView(
                corrupt_source, 0, image.size(), error, target).has_value() && !error.empty(),
            "exact Apple rejects corrupt target without another-generation fallback" + label);
        const auto latest = LoadAppleCheckpointView(corrupt_source, 0, image.size(), error);
        ok &= Require(latest.has_value() &&
            latest->container.superblock.xid == (newest_corrupt ? 20u : 21u),
            "ordinary latest selection retains its existing fallback behavior" + label);
    }
    return ok;
}

bool TestExactCheckpointRejectsLegacyAndAmbiguousGeneration()
{
    using namespace apfsaccess::catalog;
    bool ok = true;
    for (const auto shape : {0, 1, 2})
    {
        BuilderStore store;
        if (shape == 2)
        {
            store = CheckpointViewStore();
            store.spaceman_oid = 0;
        }
        auto image = BuildStoreImage(store);
        if (shape == 1) image[64] ^= std::byte{0x5A};
        VectorRandomAccessSource source(image);
        std::string error;
        const auto latest = LoadContainerCheckpointView(source, 0, image.size(), error);
        ok &= Require(latest.has_value() && latest->superblock.xid == 7,
            "ordinary latest still reads legacy fixture shape " + std::to_string(shape));
        ok &= Require(!LoadContainerCheckpointView(source, 0, image.size(), error, 7).has_value() &&
            !error.empty(), "exact container never falls back to legacy fixture");
        error.clear();
        ok &= Require(!LoadAppleCheckpointView(source, 0, image.size(), error, 7).has_value() &&
            !error.empty(), "exact Apple never falls back to legacy fixture");
    }
    const auto fixture = BuildRetainedCheckpointFixture(20);
    VectorRandomAccessSource source(fixture.image);
    std::string error;
    const auto latest = LoadAppleCheckpointView(source, 0, source.SizeBytes(), error);
    ok &= Require(latest.has_value() && latest->container.superblock_physical_block == 81,
        "ordinary latest same-XID tie behavior remains unchanged");
    ok &= Require(!LoadContainerCheckpointView(source, 0, source.SizeBytes(), error, 20).has_value() &&
        !error.empty(), "exact container rejects two complete same-XID candidates");
    error.clear();
    ok &= Require(!LoadAppleCheckpointView(source, 0, source.SizeBytes(), error, 20).has_value() &&
        !error.empty(), "exact Apple rejects two complete same-XID candidates");
    return ok;
}

bool TestExactCheckpointRejectsDuplicateOmapMappings()
{
    using namespace apfsaccess::catalog;
    const auto fixture = BuildRetainedCheckpointFixture();
    constexpr std::uint32_t block_size = 4096;
    bool ok = true;
    for (const bool volume_map : {false, true})
    {
        const std::uint64_t tree_block = volume_map ? 38 : 43;
        const std::uint64_t oid = volume_map ? fixture.volume_root_oid : fixture.volume_oid;
        for (const bool unrelated : {false, true})
        {
            for (const bool tombstone : {false, true})
            {
                for (const bool reverse : {false, true})
                {
                    const auto duplicate_oid = unrelated ? oid + 1 : oid;
                    std::vector<OmapRecordSpec> records{
                        {duplicate_oid, volume_map ? 36ull : 39ull, 0, 21},
                        {duplicate_oid, tombstone ? 0ull : (volume_map ? 34ull : 4ull),
                            tombstone ? 1u : 0u, 21}};
                    if (reverse) std::reverse(records.begin(), records.end());
                    if (unrelated)
                    {
                        records.insert(records.begin(), {oid, volume_map ? 36ull : 39ull, 0, 21});
                    }
                    if (volume_map)
                    {
                        records.push_back({fixture.snapshot_root_oid, 35, 0, 20});
                    }
                    auto image = fixture.image;
                    PutFixtureBlock(image, tree_block, block_size,
                        BuildBtreeNode(records, 21, block_size, 0, tree_block,
                            0x40000002, 0x0000000B));
                    VectorRandomAccessSource source(image);
                    std::string error;
                    const auto view = LoadAppleCheckpointView(source, 0, image.size(), error, 21);
                    const std::string label = std::string(volume_map ? "volume" : "container") +
                        (unrelated ? " unrelated OID" : " matching OID") +
                        (tombstone ? " tombstone/value" : " different-value") +
                        (reverse ? " reversed" : " forward");
                    ok &= Require(!view.has_value() && !error.empty(),
                        "exact Apple rejects duplicate (oid,xid) OMAP mappings: " + label);
                    error.clear();
                    const auto mapping = ResolveOmapValue(
                        source, block_size, volume_map ? 37 : 42, oid, 21, error);
                    ok &= Require(!mapping.has_value() && !error.empty(),
                        "generic resolver rejects duplicate (oid,xid) OMAP mappings: " + label);
                }
            }
        }
    }
    return ok;
}

bool TestExactCheckpointRejectsMalformedOmapRecords()
{
    using namespace apfsaccess::catalog;
    const auto fixture = BuildRetainedCheckpointFixture();
    constexpr std::uint32_t block_size = 4096;
    bool ok = true;
    for (const bool volume_map : {false, true})
    {
        const std::uint64_t tree_block = volume_map ? 38 : 43;
        const std::uint64_t oid = volume_map ? fixture.volume_root_oid : fixture.volume_oid;
        for (const bool unrelated : {false, true})
        {
            for (const bool key_field : {false, true})
            {
                for (const std::size_t field_size : {15u, 17u})
                {
                    std::vector<std::vector<std::byte>> keys(
                        volume_map ? 3 : 2, std::vector<std::byte>(16, std::byte{0}));
                    auto values = keys;
                    PutU64LE(keys[0], 0, oid);
                    PutU64LE(keys[0], 8, 21);
                    PutU32LE(values[0], 4, block_size);
                    PutU64LE(values[0], 8, volume_map ? 36 : 39);
                    keys[1] = keys[0];
                    values[1] = values[0];
                    PutU64LE(keys[1], 0, unrelated ? oid + 1 : oid);
                    PutU64LE(keys[1], 8, 20);
                    (key_field ? keys[1] : values[1]).resize(field_size, std::byte{0});
                    if (volume_map)
                    {
                        PutU64LE(keys[2], 0, fixture.snapshot_root_oid);
                        PutU64LE(keys[2], 8, 20);
                        PutU32LE(values[2], 4, block_size);
                        PutU64LE(values[2], 8, 35);
                    }
                    auto image = fixture.image;
                    PutFixtureBlock(image, tree_block, block_size,
                        BuildRawLeafNode(keys, values, 21, block_size, 0, tree_block,
                            0x40000002, 0x0000000B));
                    VectorRandomAccessSource source(image);
                    std::string error;
                    const auto view = LoadAppleCheckpointView(source, 0, image.size(), error, 21);
                    const std::string label = std::string(volume_map ? "volume" : "container") +
                        (unrelated ? " unrelated OID" : " matching OID") +
                        (key_field ? " key " : " value ") + std::to_string(field_size);
                    ok &= Require(!view.has_value() && !error.empty(),
                        "exact Apple rejects malformed OMAP record: " + label);
                    error.clear();
                    const auto mapping = ResolveOmapValue(
                        source, block_size, volume_map ? 37 : 42, oid, 21, error);
                    ok &= Require(!mapping.has_value() && !error.empty(),
                        "generic resolver rejects malformed OMAP record: " + label);
                }
            }
        }
    }
    return ok;
}

bool TestExactCheckpointOmapDistinctXidSelection()
{
    using namespace apfsaccess::catalog;
    auto fixture = BuildRetainedCheckpointFixture();
    constexpr std::uint32_t block_size = 4096;
    for (const std::uint64_t xid : {20ull, 21ull})
    {
        const std::uint64_t container_tree = xid == 20 ? 3 : 43;
        const std::uint64_t volume_tree = xid == 20 ? 33 : 38;
        PutFixtureBlock(fixture.image, container_tree, block_size,
            BuildBtreeNode({
                OmapRecordSpec{fixture.volume_oid, 4, 0, 20},
                OmapRecordSpec{fixture.volume_oid, 39, 0, 21}},
                xid, block_size, 0, container_tree, 0x40000002, 0x0000000B));
        PutFixtureBlock(fixture.image, volume_tree, block_size,
            BuildBtreeNode({
                OmapRecordSpec{fixture.volume_root_oid, 34, 0, 20},
                OmapRecordSpec{fixture.volume_root_oid, 36, 0, 21},
                OmapRecordSpec{fixture.snapshot_root_oid, 35, 0, 20}},
                xid, block_size, 0, volume_tree, 0x40000002, 0x0000000B));
    }
    VectorRandomAccessSource source(fixture.image);
    bool ok = true;
    for (const std::uint64_t xid : {20ull, 21ull})
    {
        std::string error;
        const auto view = LoadAppleCheckpointView(source, 0, source.SizeBytes(), error, xid);
        ok &= Require(view.has_value() && error.empty() && view->volumes.size() == 1 &&
            view->container.superblock.xid == xid &&
            view->volumes.front().superblock_object.physical_block == (xid == 20 ? 4u : 39u) &&
            view->volumes.front().root_tree.physical_block == (xid == 20 ? 34u : 36u),
            "exact Apple selects newest distinct-XID OMAP value at or before " +
                std::to_string(xid) + ": " + error);
        for (const bool volume_map : {false, true})
        {
            const std::uint64_t map_oid = volume_map ? (xid == 20 ? 32 : 37) :
                (xid == 20 ? 2 : 42);
            const std::uint64_t oid = volume_map ? fixture.volume_root_oid : fixture.volume_oid;
            const std::uint64_t expected_block = volume_map ? (xid == 20 ? 34 : 36) :
                (xid == 20 ? 4 : 39);
            const auto mapping = ResolveOmapValue(source, block_size, map_oid, oid, xid, error);
            ok &= Require(mapping.has_value() && error.empty() && mapping->xid == xid &&
                mapping->physical_block == expected_block,
                "generic resolver preserves distinct-XID selection at " + std::to_string(xid));
        }
    }
    return ok;
}

std::vector<std::byte> BuildPhysicalOmapTraversalNode(
    const std::vector<OmapRecordSpec>& records, std::uint64_t block, bool branch)
{
    auto node = BuildBtreeNode(records, 21, 4096, 0, block,
        branch ? 0x40000002 : 0x40000003, 0x0000000B);
    PutU16LE(node, 0x20, branch ? 1 : 2);
    PutU16LE(node, 0x22, branch ? 1 : 0);
    for (std::size_t index = 0; index < records.size(); ++index)
    {
        const auto entry = 0x38 + index * 8;
        const auto offset = apfsaccess::catalog::ReadU16LE(node, entry + 4).value();
        // Branch values are child paddrs; non-root leaves have no 40-byte footer.
        PutU16LE(node, entry + 4, static_cast<std::uint16_t>(branch ? offset - 8 : offset + 40));
        PutU16LE(node, entry + 6, branch ? 8 : 16);
    }
    FletcherForBlock(node, 4096);
    return node;
}

bool TestExactCheckpointAcceptsMultilevelPhysicalOmap()
{
    using namespace apfsaccess::catalog;
    bool ok = true;
    for (const bool volume_map : {false, true})
    {
        auto fixture = BuildRetainedCheckpointFixture();
        const std::uint64_t tree = volume_map ? 38 : 43;
        const std::uint64_t child = volume_map ? 33 : 3;
        const std::uint64_t oid = volume_map ? fixture.volume_root_oid : fixture.volume_oid;
        const std::uint64_t paddr = volume_map ? 36 : 39;
        std::vector<OmapRecordSpec> records{{oid, paddr, 0, 21}};
        if (volume_map) records.push_back({fixture.snapshot_root_oid, 35, 0, 20});
        PutFixtureBlock(fixture.image, child, 4096,
            BuildPhysicalOmapTraversalNode(records, child, false));
        PutFixtureBlock(fixture.image, tree, 4096,
            BuildPhysicalOmapTraversalNode({{oid, child, 0, 21}}, tree, true));
        VectorRandomAccessSource source(fixture.image);
        std::string error;
        const auto view = LoadAppleCheckpointView(source, 0, source.SizeBytes(), error, 21);
        ok &= Require(view.has_value() && error.empty() && view->volumes.size() == 1 &&
            view->volumes.front().superblock_object.physical_block == 39 &&
            view->volumes.front().root_tree.physical_block == 36,
            "exact Apple accepts valid multilevel physical OMAP: " + error);
        const auto mapping = ResolveOmapValue(source, 4096, volume_map ? 37 : 42, oid, 21, error);
        ok &= Require(mapping.has_value() && error.empty() && mapping->physical_block == paddr,
            "generic resolver accepts valid multilevel physical OMAP: " + error);
    }
    return ok;
}

bool TestExactCheckpointRejectsIncompleteOmapTraversal()
{
    using namespace apfsaccess::catalog;
    bool ok = true;
    for (const bool volume_map : {false, true})
    {
        for (const std::string shape : {"keyless-first", "keyless-last", "ghost-first",
                 "ghost-last", "null-child", "duplicate-child", "cycle", "level-gap",
                 "table-underflow", "key-region", "value-region"})
        {
            auto fixture = BuildRetainedCheckpointFixture();
            const std::uint64_t tree = volume_map ? 38 : 43;
            const std::uint64_t child = volume_map ? 33 : 3;
            const std::uint64_t oid = volume_map ? fixture.volume_root_oid : fixture.volume_oid;
            const OmapRecordSpec live{oid, volume_map ? 36ull : 39ull, 0, 21};
            std::vector<OmapRecordSpec> records{live};
            const bool keyless = shape.find("keyless") == 0;
            const bool ghost = shape.find("ghost") == 0;
            if (keyless || ghost) records.push_back(live);
            if (volume_map) records.push_back({fixture.snapshot_root_oid, 35, 0, 20});
            const bool branch = shape == "null-child" || shape == "duplicate-child" ||
                shape == "cycle" || shape == "level-gap";
            std::vector<std::byte> node;
            if (branch)
            {
                PutFixtureBlock(fixture.image, child, 4096,
                    BuildPhysicalOmapTraversalNode(records, child, false));
                std::vector<OmapRecordSpec> edges{{oid, child, 0, 21}};
                if (shape != "level-gap")
                {
                    edges.push_back({oid + 1, shape == "null-child" ? 0 :
                        (shape == "cycle" ? tree : child), 0, 21});
                }
                node = BuildPhysicalOmapTraversalNode(edges, tree, true);
                if (shape == "level-gap") PutU16LE(node, 0x22, 2);
            }
            else
            {
                node = BuildBtreeNode(records, 21, 4096, 0, tree, 0x40000002, 0x0000000B);
                if (keyless || ghost)
                {
                    const auto entry = 0x38 + (shape.find("last") != std::string::npos ? 8 : 0);
                    PutU16LE(node, entry + (ghost ? 4 : 0), 0xFFFF);
                }
                else if (shape == "table-underflow")
                {
                    PutU16LE(node, 0x2A, static_cast<std::uint16_t>(records.size() * 8 - 1));
                    for (std::size_t index = 0; index < records.size(); ++index)
                    {
                        const auto entry = 0x38 + index * 8;
                        PutU16LE(node, entry, ReadU16LE(node, entry).value() + 1);
                    }
                    PutU16LE(node, 0x2C, ReadU16LE(node, 0x2C).value() + 1);
                }
                else if (shape == "key-region")
                {
                    PutU16LE(node, 0x2C, ReadU16LE(node, 0x2C).value() - 1);
                    PutU16LE(node, 0x2E, ReadU16LE(node, 0x2E).value() + 1);
                }
                else if (shape == "value-region")
                {
                    PutU16LE(node, 0x2E, ReadU16LE(node, 0x2E).value() + 1);
                }
            }
            FletcherForBlock(node, 4096);
            PutFixtureBlock(fixture.image, tree, 4096, node);
            VectorRandomAccessSource source(fixture.image);
            const std::string label = std::string(volume_map ? "volume " : "container ") + shape;
            ok &= Require(VerifyObjectChecksum(node, 4096), "checksum-valid traversal fixture: " + label);
            std::string error;
            std::vector<BtreeRecord> ordinary_records;
            ok &= Require(ReadBtreeLeafRecords(source, 4096, tree, true, 0, 21,
                    ordinary_records, error) && error.empty() && !ordinary_records.empty(),
                "ordinary traversal retains existing permissive behavior: " + label);
            const auto view = LoadAppleCheckpointView(source, 0, source.SizeBytes(), error, 21);
            ok &= Require(!view.has_value() && !error.empty(),
                "exact Apple rejects incomplete OMAP traversal: " + label);
            error.clear();
            const auto mapping = ResolveOmapValue(source, 4096, volume_map ? 37 : 42, oid, 21, error);
            ok &= Require(!mapping.has_value() && !error.empty(),
                "generic resolver rejects incomplete OMAP traversal: " + label);
        }
    }
    return ok;
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

    for (const std::uint32_t block_size : {8192u, 16384u})
    {
        using namespace apfsaccess::catalog;
        BuilderStore store;
        store.authoritative_checkpoint = true;
        store.block_size = block_size;
        store.volumes.resize(2);
        store.volumes[1].oid = 102;
        store.volumes[1].name = "Sibling";
        const auto strict_image = BuildStoreImage(store);
        VectorRandomAccessSource source(strict_image);
        ApfsContainerCatalog strict_catalog;
        error.clear();
        const auto label = std::to_string(block_size) + "-byte authoritative fixture";
        const bool loaded = ApfsContainerCatalog::TryLoadImage(
            source, "large", "large", strict_catalog, error, CatalogLoadPolicy::StrictApple);
        ok &= Require(loaded, label + " loads: " + error);
        if (!loaded || !Require(strict_catalog.Stores().size() == 1 &&
                strict_catalog.Containers().size() == 1, label + " retains one store/container"))
        {
            return false;
        }
        const auto* checkpoint = strict_catalog.TryGetAppleCheckpointView(
            strict_catalog.Stores().front().stable_store_id);
        if (!Require(checkpoint != nullptr && checkpoint->volumes.size() == 2,
                label + " retains both authoritative volumes"))
        {
            return false;
        }
        // Two APSBs at 4/5, then six metadata blocks per volume at 6/12.
        constexpr std::uint64_t descriptor_block = 18;
        ok &= Require(checkpoint->container.superblock.xid == store.xid &&
            checkpoint->container.superblock.block_size == block_size &&
            checkpoint->container.superblock_physical_block == descriptor_block + 1 &&
            checkpoint->container.checkpoint_map_blocks ==
                std::vector<std::uint64_t>{descriptor_block} &&
            strict_catalog.Containers().front().checkpoint_xid == store.xid &&
            strict_catalog.Containers().front().volumes.size() == 2,
            label + " selects the descriptor generation instead of the older anchor");
        for (std::size_t index = 0; index < 2; ++index)
        {
            const auto& volume = checkpoint->volumes[index];
            const auto root_oid = 0x2000 + store.volumes[index].oid;
            ok &= Require(volume.superblock_object.object_id == store.volumes[index].oid &&
                volume.superblock_object.physical_block == 4 + index &&
                volume.superblock_object.size_bytes == block_size &&
                volume.root_tree.object_id == root_oid &&
                volume.root_tree.physical_block == 8 + index * 6 &&
                volume.root_tree.xid == store.xid &&
                volume.root_tree.size_bytes == block_size &&
                volume.root_tree.subtype == kObjectTypeFsTree &&
                volume.snapshot_metadata_tree.has_value() &&
                volume.snapshot_metadata_tree->size_bytes == block_size,
                label + " resolves volume " + std::to_string(index) + " and its real roots");
            BtreeReadPolicy policy;
            policy.enforce_object_identity = true;
            policy.root_object_id = root_oid;
            policy.subtype = kObjectTypeFsTree;
            policy.require_complete_traversal = true;
            std::vector<BtreeRecord> records;
            error.clear();
            const bool root_read = ReadBtreeLeafRecords(source, block_size,
                volume.root_tree.physical_block, false, volume.object_map.object.physical_block,
                store.xid, policy, records, error);
            ok &= Require(root_read && records.size() == 1 &&
                ReadU64LE(records.front().key, 0).value_or(0) == (2 | (3ull << 60)) &&
                records.front().value == BuildRootInodeValue(2, 9),
                label + " reads root-directory inode " + std::to_string(index) + ": " + error);
        }

        // Independently regress all three checkpoint sizes and all six OMAP
        // sizes. Rechecksum each mutation so rejection must concern size.
        for (std::size_t field = 0; field < 9; ++field)
        {
            const bool checkpoint_mapping = field < 3;
            const auto omap_index = checkpoint_mapping ? 0 : (field - 3) / 2;
            const std::uint64_t block = checkpoint_mapping ? descriptor_block :
                (omap_index == 0 ? 3 : 7 + (omap_index - 1) * 6);
            const auto begin = strict_image.begin() + block * block_size;
            std::vector<std::byte> object(begin, begin + block_size);
            const std::size_t offset = checkpoint_mapping ? 0x30 + field * 0x28 :
                block_size - 40 - ReadU16LE(object, 0x38 + ((field - 3) % 2) * 8 + 4).value() + 4;
            ok &= Require(ReadU32LE(object, offset).value_or(0) == block_size,
                label + " advertises actual size in field " + std::to_string(field));
            PutU32LE(object, offset, 4096);
            FletcherForBlock(object, block_size);
            ok &= Require(VerifyObjectChecksum(object, block_size),
                label + " malformed size control remains checksum-valid");
            auto malformed = strict_image;
            PutFixtureBlock(malformed, block, block_size, object);
            VectorRandomAccessSource malformed_source(malformed);
            ApfsContainerCatalog rejected;
            error.clear();
            const bool accepted = ApfsContainerCatalog::TryLoadImage(malformed_source,
                "large-bad-size", "large-bad-size", rejected, error, CatalogLoadPolicy::StrictApple);
            const auto expected_error = checkpoint_mapping ? "CheckpointNoCompleteGeneration" :
                (omap_index == 0 ? "AppleContainerOmapValueSizeInvalid" :
                    "AppleVolumeOmapValueSizeInvalid");
            ok &= Require(!accepted && error.find(expected_error) != std::string::npos,
                label + " rejects malformed size field " + std::to_string(field) + ": " + error);
        }
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

bool TestMetadataStoreReportsSharedVolumeCapacity()
{
    BuilderStore spec;
    spec.authoritative_checkpoint = true;
    spec.block_count = 256;
    spec.volumes.resize(2);
    spec.volumes[0].oid = 101;
    spec.volumes[1].oid = 102;
    spec.volumes[0].quota_block_count = 10;
    spec.volumes[1].reserve_block_count = 20;
    bool ok = true;
    for (const auto mode : {0, 1, 2, 3, 4})
    {
        auto variant = spec;
        if (mode == 1) variant.volumes[0].quota_block_count = 5;
        if (mode == 2) variant.volumes[0].quota_block_count = 0;
        if (mode == 3) variant.volumes[1].reserve_block_count = 257;
        const auto bytes = BuildStoreImage(variant);
        TempImageFile file(bytes, "shared-capacity", ".raw");
        apfsaccess::rw::MetadataStore::VolumeContext context;
        context.device_path = file.path.wstring();
        context.volume_object_id = mode == 4 ? 999 : 101;
        context.allow_legacy_scaffold_for_fixtures = false;
        apfsaccess::rw::MetadataStore store(context);
        if (!Require(store.LoadContainerSuperblocks(), "capacity reads the strict shared checkpoint")) return false;
        const auto* view = store.AuthoritativeAppleCheckpointView();
        if (!Require(view && view->volumes.size() == 2 &&
                view->volumes[0].superblock.space.allocated_block_count == 6 &&
                view->volumes[1].superblock.space.allocated_block_count == 6,
                "capacity fixture independently binds six allocated blocks per volume")) return false;
        const auto free = store.FreeSizeBytes();
        if (mode == 0) ok &= Require(free == 4 * 4096, "volume quota limits free space even in a larger shared pool");
        if (mode == 1) ok &= Require(free == 0, "already exceeded quota reports zero usable free space");
        if (mode == 2) ok &= Require(free == (view->spaceman.devices[0].free_count - 14) * 4096,
            "unset quota preserves fourteen blocks of sibling unmet reserve");
        if (mode >= 3) ok &= Require(!free, "invalid reserve or missing selected volume cannot reuse container free space");
        ok &= Require(store.TotalSizeBytes() == 256 * 4096, "shared total remains the container capacity");
        apfsaccess::rw::BlockDevice verify(file.path.wstring());
        std::vector<std::byte> actual;
        ok &= Require(verify.Read(0, bytes.size(), actual) && actual == bytes,
            "capacity queries leave every image byte unchanged");
    }
    return ok;
}

bool TestMetadataStoreQuotaRefusalPreservesPendingRetry()
{
    using apfsaccess::rw::MetadataStore;
    BuilderStore spec;
    spec.authoritative_checkpoint = true;
    spec.block_count = 256;
    spec.authoritative_internal_pool_blocks = 16;
    spec.authoritative_checkpoint_ring_blocks = 16;
    spec.volumes[0].oid = 101;
    spec.volumes[0].incompat = apfsaccess::catalog::kIncompatCaseInsensitive;
    spec.volumes[0].quota_block_count = 6;
    const auto bytes = BuildStoreImage(spec);
    TempImageFile file(bytes, "quota-retry", ".raw");
    MetadataStore::VolumeContext context;
    context.device_path = file.path.wstring();
    context.volume_object_id = 101;
    context.allow_legacy_scaffold_for_fixtures = false;
    context.integrity_check_on_mount = false;
    MetadataStore store(context);
    if (!Require(store.PrepareNativeWritePath(), "quota image prepares canonical writer")) return false;
    const auto initial_xid = store.CheckpointXid();
    const std::vector<std::byte> payload(16384, std::byte{0x5a});
    unsigned payload_reads = 0;
    store.SetFilePayloadProvider([&](const std::wstring& path, std::uint64_t length)
        -> std::optional<std::vector<std::byte>> {
        ++payload_reads;
        if (path != L"\\quota.bin" || length > payload.size()) return std::nullopt;
        return std::vector<std::byte>(payload.begin(), payload.begin() + static_cast<std::ptrdiff_t>(length));
    });
    MetadataStore::MutationRequest create;
    create.operation = MetadataStore::MutationOperation::CreateFile;
    create.path = L"\\quota.bin";
    MetadataStore::MutationRequest write;
    write.operation = MetadataStore::MutationOperation::Write;
    write.path = create.path;
    write.length = payload.size();
    if (!Require(store.StageMutation(create) == MetadataStore::MutationStatus::Applied,
            "quota test stages a real file")) return false;
    const auto before_preview = store.PendingMutationCount();
    unsigned publication_hooks = 0;
    store.SetCommitStageHook([&](std::string_view) { ++publication_hooks; return false; });
    for (int attempt = 0; attempt != 2; ++attempt)
    {
        const auto preview = store.PreflightNativeCapacityMutation(write);
        const auto pending = store.LookupWorkingInodeByPath(create.path);
        if (!Require(preview == MetadataStore::MutationStatus::CapacityBlocked && pending &&
                pending->logical_size == 0 && store.PendingMutationCount() == before_preview &&
                store.CheckpointXid() == initial_xid && payload_reads == 0 && publication_hooks == 0,
                "capacity preview rolls back the proposed write without reading payload or invoking publication")) return false;
    }
    store.SetCommitStageHook({});
    if (!Require(store.StageMutation(write) == MetadataStore::MutationStatus::Applied,
            "engine test independently retains already accepted payload for retry")) return false;
    const auto pending_count = store.PendingMutationCount();
    for (int retry = 0; retry != 2; ++retry)
    {
        const auto result = store.CommitPendingMutations();
        if (!Require(result == MetadataStore::CommitStatus::CapacityBlocked,
                "quota refusal returns a distinct full-volume status: " + std::to_string(static_cast<int>(result))) ||
            !Require(store.IsCommitPathReady() && !store.IsRecoveryRequired() &&
                store.PendingMutationCount() == pending_count && store.CheckpointXid() == initial_xid,
                "quota refusal retains pending mutations and write readiness")) return false;
        const auto pending = store.LookupWorkingInodeByPath(create.path);
        if (!Require(pending && pending->logical_size == payload.size(),
                "refused commit retains the full staged file size")) return false;
        apfsaccess::rw::BlockDevice verify(file.path.wstring());
        std::vector<std::byte> actual;
        if (!Require(verify.Read(0, bytes.size(), actual) && actual == bytes,
                "quota refusal publishes no image bytes on repeated retries")) return false;
    }
    MetadataStore::MutationRequest shrink;
    shrink.operation = MetadataStore::MutationOperation::SetFileSize;
    shrink.path = create.path;
    shrink.length = 0;
    if (!Require(store.StageMutation(shrink) == MetadataStore::MutationStatus::Applied,
            "explicit shrink is accepted under quota pressure")) return false;
    const auto result = store.CommitPendingMutations();
    if (!Require(result == MetadataStore::CommitStatus::Committed,
            "explicit shrink lets retained work commit: " + std::to_string(static_cast<int>(result))) ||
        !Require(store.PendingMutationCount() == 0 && !store.IsRecoveryRequired(),
            "successful retry releases pending work without a recovery fault")) return false;
    MetadataStore reopened(context);
    if (!Require(reopened.LoadCanonicalState(), "quota retry remounts the canonical checkpoint")) return false;
    const auto inode = reopened.LookupCommittedInodeByPath(create.path);
    return Require(inode && inode->logical_size == 0, "reopened file contains the explicitly requested empty result");
}

bool TestNativeCapacityPreviewRollback()
{
    using Store = apfsaccess::rw::MetadataStore;
    const auto same_requests = [](const auto& a, const auto& b) {
        return a.size() == b.size() && std::equal(a.begin(), a.end(), b.begin(), [](const auto& x, const auto& y) {
            return x.operation == y.operation && x.path == y.path && x.secondary_path == y.secondary_path &&
                x.offset == y.offset && x.length == y.length && x.inline_payload == y.inline_payload &&
                x.timestamp_utc == y.timestamp_utc && x.replace_if_exists == y.replace_if_exists &&
                x.object_id == y.object_id && x.generation == y.generation &&
                x.expected_unlink_outcome == y.expected_unlink_outcome;
        });
    };
    for (const auto quota : {0ULL, 8ULL}) for (const bool interposed : {false, true})
    {
        BuilderStore spec;
        spec.authoritative_checkpoint = true;
        spec.block_count = 256;
        spec.authoritative_internal_pool_blocks = 16;
        spec.authoritative_checkpoint_ring_blocks = 16;
        spec.volumes[0].oid = 101;
        spec.volumes[0].incompat = apfsaccess::catalog::kIncompatCaseInsensitive;
        spec.volumes[0].quota_block_count = quota;
        const auto bytes = BuildStoreImage(spec);
        TempImageFile file(bytes, "preview-rollback", ".raw");
        Store::VolumeContext context;
        context.device_path = file.path.wstring();
        context.volume_object_id = 101;
        context.allow_legacy_scaffold_for_fixtures = false;
        context.integrity_check_on_mount = false;
        Store store(context);
        if (!Require(store.PrepareNativeWritePath(), "preview rollback fixture prepares")) return false;
        Store::MutationRequest create;
        create.operation = Store::MutationOperation::CreateFile;
        create.path = L"\\quota.bin";
        auto write = create;
        write.operation = Store::MutationOperation::Write;
        write.length = 4096;
        if (!Require(store.StageMutation(create) == Store::MutationStatus::Applied &&
                store.StageMutation(write) == Store::MutationStatus::Applied, "preview starts with earlier pending content")) return false;
        if (interposed)
        {
            auto attr = create;
            attr.operation = Store::MutationOperation::SetExtendedAttribute;
            attr.secondary_path = L"user.preview";
            attr.length = 1;
            attr.inline_payload = {std::byte{0x23}};
            if (!Require(store.StageMutation(attr) == Store::MutationStatus::Applied, "interposed metadata stages")) return false;
        }
        const auto before = store.DebugSnapshotPendingMutations();
        const auto delta = apfsaccess::rw::CheckpointDeltaCodec::Encode(store.DebugBuildPendingCheckpointDelta());
        const auto free_bytes = store.DebugWorkingFreeExtentTotalBytes();
        const auto free_count = store.DebugWorkingFreeExtentCount();
        const auto unchanged_allocator = [&]() {
            return free_bytes == store.DebugWorkingFreeExtentTotalBytes() &&
                free_count == store.DebugWorkingFreeExtentCount();
        };
        auto growth = write;
        growth.offset = 4096;
        growth.length = 16384;
        for (int repeat = 0; repeat != 12; ++repeat)
            if (!Require(store.PreflightNativeCapacityMutation(growth) == (quota ? Store::MutationStatus::CapacityBlocked : Store::MutationStatus::Applied) &&
                    same_requests(before, store.DebugSnapshotPendingMutations()) &&
                    unchanged_allocator() &&
                    delta == apfsaccess::rw::CheckpointDeltaCodec::Encode(store.DebugBuildPendingCheckpointDelta()),
                    "admitted/refused preview restores allocator, requests, order and checkpoint delta")) return false;
        auto missing = write;
        missing.path = L"\\missing.bin";
        const std::array<Store::MutationRequest, 2> invalid_batch{growth, missing};
        if (!Require(store.PreflightNativeCapacityMutations(invalid_batch) == Store::MutationStatus::InvalidRequest &&
                unchanged_allocator() && same_requests(before, store.DebugSnapshotPendingMutations()),
                "later invalid request restores preceding growth allocation")) return false;
        auto shrink = write;
        shrink.operation = Store::MutationOperation::SetFileSize;
        shrink.length = 0;
        std::array<Store::MutationRequest, 2> batch{shrink, write};
        if (!Require(store.PreflightNativeCapacityMutations(batch) == Store::MutationStatus::Applied &&
                unchanged_allocator() &&
                same_requests(before, store.DebugSnapshotPendingMutations()) &&
                delta == apfsaccess::rw::CheckpointDeltaCodec::Encode(store.DebugBuildPendingCheckpointDelta()),
                "admitted multi-operation preview restores the complete earlier request stream")) return false;
        std::array<Store::MutationRequest, Store::MaximumCapacityPreviewRequests> maximum_batch;
        maximum_batch.fill(write);
        if (!Require(store.PreflightNativeCapacityMutations(maximum_batch) == Store::MutationStatus::Applied &&
                unchanged_allocator() &&
                same_requests(before, store.DebugSnapshotPendingMutations()),
                "maximum callback preview depth remains bounded and restores coalesced requests")) return false;
        std::vector<Store::MutationRequest> excessive(Store::MaximumCapacityPreviewRequests + 1, write);
        if (!Require(store.PreflightNativeCapacityMutations(excessive) == Store::MutationStatus::UnsupportedOperation &&
                unchanged_allocator() &&
                same_requests(before, store.DebugSnapshotPendingMutations()),
                "oversized callback batch is refused before staging")) return false;
        TempImageFile control_file(bytes, "preview-allocator-control", ".raw");
        auto control_context = context;
        control_context.device_path = control_file.path.wstring();
        Store control(control_context);
        if (!Require(control.PrepareNativeWritePath(), "preview control prepares")) return false;
        for (const auto& request : before)
            if (!Require(control.StageMutation(request) == Store::MutationStatus::Applied,
                    "control stages the earlier real request stream")) return false;
        auto rename = write;
        rename.operation = Store::MutationOperation::Rename;
        rename.secondary_path = L"\\renamed.bin";
        auto changed = write;
        changed.path = L"\\RENAMED.BIN";
        changed.offset = 1024;
        changed.length = 1024;
        for (const auto& request : {shrink, write, rename, changed})
            if (!Require(store.StageMutation(request) == Store::MutationStatus::Applied &&
                    control.StageMutation(request) == Store::MutationStatus::Applied,
                    "real mutations after previews match an untouched control")) return false;
        const bool equal_free = store.DebugWorkingFreeExtentTotalBytes() == control.DebugWorkingFreeExtentTotalBytes();
        const bool equal_requests = same_requests(store.DebugSnapshotPendingMutations(), control.DebugSnapshotPendingMutations());
        const auto actual_delta_state = store.DebugBuildPendingCheckpointDelta();
        auto control_delta_state = control.DebugBuildPendingCheckpointDelta();
        // These otherwise identical fixtures have distinct backing-file identities.
        control_delta_state.volume_identity = actual_delta_state.volume_identity;
        const auto actual_delta = apfsaccess::rw::CheckpointDeltaCodec::Encode(actual_delta_state);
        const auto control_delta = apfsaccess::rw::CheckpointDeltaCodec::Encode(control_delta_state);
        if (!Require(equal_free && equal_requests && actual_delta == control_delta,
                "previews preserve future allocation geometry and checkpoint delta"))
        {
            const auto mismatch = std::mismatch(actual_delta.begin(), actual_delta.end(), control_delta.begin(), control_delta.end());
            std::cerr << "quota=" << quota << " interposed=" << interposed << " equal_free=" << equal_free
                      << " equal_requests=" << equal_requests << " delta_sizes=" << actual_delta.size() << ',' << control_delta.size()
                      << " first_delta_mismatch=" << (mismatch.first - actual_delta.begin()) << '\n';
            return false;
        }
        apfsaccess::rw::BlockDevice source(file.path.wstring());
        std::vector<std::byte> actual;
        if (!Require(source.Read(0, bytes.size(), actual) && actual == bytes, "previews never change image bytes")) return false;
    }

    BuilderStore spec;
    spec.authoritative_checkpoint = true;
    spec.block_count = 256;
    spec.authoritative_internal_pool_blocks = 16;
    spec.authoritative_checkpoint_ring_blocks = 16;
    spec.volumes[0].oid = 101;
    spec.volumes[0].incompat = apfsaccess::catalog::kIncompatCaseInsensitive;
    const auto bytes = BuildStoreImage(spec);
    TempImageFile first(bytes, "preview-id", ".raw"), second(bytes, "preview-id-control", ".raw");
    Store::VolumeContext context;
    context.device_path = first.path.wstring();
    context.volume_object_id = 101;
    context.allow_legacy_scaffold_for_fixtures = false;
    context.integrity_check_on_mount = false;
    Store first_store(context);
    context.device_path = second.path.wstring();
    Store control(context);
    if (!Require(first_store.PrepareNativeWritePath() && control.PrepareNativeWritePath(), "preview identity pair prepares")) return false;
    Store::MutationRequest create;
    create.operation = Store::MutationOperation::CreateFile;
    create.path = L"\\identity.bin";
    for (int i = 0; i != 3; ++i)
        if (!Require(first_store.PreflightNativeCapacityMutation(create) == Store::MutationStatus::Applied,
                "unlimited-volume create preview is admitted")) return false;
    Store::PayloadIdentity actual_id{}, control_id{};
    if (!Require(first_store.StageMutation(create, &actual_id) == Store::MutationStatus::Applied &&
            control.StageMutation(create, &control_id) == Store::MutationStatus::Applied &&
            actual_id.object_id == control_id.object_id && actual_id.generation == control_id.generation,
            "previews do not consume future inode identities")) return false;

    spec.authoritative_main_free_blocks = 5;
    const auto tight_bytes = BuildStoreImage(spec);
    TempImageFile tight(tight_bytes, "preview-main-full", ".raw");
    context.device_path = tight.path.wstring();
    Store full(context);
    if (!Require(full.PrepareNativeWritePath() &&
            full.PreflightNativeCapacityMutation(create) == Store::MutationStatus::CapacityBlocked &&
            full.PendingMutationCount() == 0 && full.IsCanonicalCommitReady() && !full.IsRecoveryRequired(),
            "ordinary main-pool exhaustion is refused before acceptance without disabling writes")) return false;
    return true;
}

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

bool TestNativeWriterFeatureAdmission()
{
    using namespace apfsaccess::rw;
    using namespace apfsaccess::catalog;
    struct Case
    {
        const char* name;
        std::uint32_t magic;
        std::size_t offset;
        std::uint64_t value;
        bool allowed;
    };
    const Case cases[] = {
        {"nx-supported", kNxsbMagic, 0x40, kNxSupportedIncompatibleFeaturesMask, true},
        {"nx-readonly", kNxsbMagic, 0x38, 1, false},
        {"nx-unknown", kNxsbMagic, 0x40, 1ull << 63, false},
        {"nx-legacy", kNxsbMagic, 0x40, 1, false},
        {"nx-fusion", kNxsbMagic, 0x40, 0x100, false},
        {"apsb-readonly", kApsbMagic, 0x30, 1, false},
        {"apsb-unknown", kApsbMagic, 0x38, 1ull << 63, false},
        {"apsb-encrypted", kApsbMagic, 0x108, 0, false},
    };
    bool ok = true;
    for (const auto& entry : cases)
    {
        auto fixture = BuildAuthoritativeCheckpointFixture();
        std::size_t patched = 0;
        for (std::size_t offset = 0; offset + 4096 <= fixture.image.size(); offset += 4096)
        {
            if (ReadU32LE(fixture.image, offset + 0x20) != entry.magic)
            {
                continue;
            }
            std::vector<std::byte> block(fixture.image.begin() + offset,
                fixture.image.begin() + offset + 4096);
            PutU64LE(block, entry.offset, entry.value);
            FletcherForBlock(block, 4096);
            PutFixtureBlock(fixture.image, offset / 4096, 4096, block);
            ++patched;
        }
        if (!Require(patched > 0, std::string(entry.name) + " patches real checksummed objects"))
        {
            return false;
        }
        TempImageFile file(fixture.image, entry.name, ".raw");
        MetadataStore::VolumeContext context;
        context.device_path = file.path.wstring();
        context.volume_object_id = fixture.volume_oid;
        context.allow_legacy_scaffold_for_fixtures = false;
        context.integrity_check_on_mount = false;
        {
            MetadataStore metadata(context);
            ok &= Require(metadata.LoadContainerSuperblocks(),
                std::string(entry.name) + " remains parseable before write admission");
            ok &= Require(metadata.PrepareNativeWritePath() == entry.allowed,
                std::string(entry.name) + " native admission matches supported feature set");
            ok &= Require(metadata.IsCommitPathReady() == entry.allowed,
                std::string(entry.name) + " effective commit readiness matches admission");
            if (!entry.allowed)
            {
                MetadataStore::MutationRequest create;
                create.operation = MetadataStore::MutationOperation::CreateFile;
                create.path = L"\\must-not-exist";
                const auto staged = metadata.StageMutation(create);
                const auto committed = metadata.CommitPendingMutations();
                ok &= Require(staged != MetadataStore::MutationStatus::Applied &&
                    committed != MetadataStore::CommitStatus::Committed,
                    std::string(entry.name) + " refused writer cannot stage and commit");
            }
        }

        VectorRandomAccessSource source(fixture.image);
        std::string error;
        auto checkpoint = LoadAppleCheckpointView(source, 0, fixture.image.size(), error);
        if (!Require(checkpoint.has_value(), std::string(entry.name) + " has a complete checkpoint: " + error))
        {
            return false;
        }
        AppleInodeRecord root;
        root.object_id = root.parent_id = root.private_id = 2;
        root.mode = 0040755;
        AppleVolumeTransactionRequest request;
        request.volume_object_id = fixture.volume_oid;
        request.filesystem_records.resize(1);
        if (!Require(EncodeAppleInodeRecord(root, request.filesystem_records.front(), error),
                "feature test encodes a valid root inode"))
        {
            return false;
        }
        AppleVolumeTransactionPlan plan;
        ok &= Require(PlanAppleVolumeTransaction(source, *checkpoint, request, plan, error) == entry.allowed,
            std::string(entry.name) + " direct native planner enforces the same feature gate: " + error);
        BlockDevice verify(file.path.wstring());
        std::vector<std::byte> actual;
        ok &= Require(verify.Read(0, fixture.image.size(), actual) && actual == fixture.image,
            std::string(entry.name) + " admission/refusal leaves the whole image byte-identical");
    }
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

bool TestAppleCommitRangeProviderRefusalIsAuthoritative()
{
    using MetadataStore = apfsaccess::rw::MetadataStore;
    enum class ProviderMode
    {
        FullOnly,
        RangeSucceeds,
        RangeRefuses,
    };

    std::vector<std::byte> authoritative_payload(7000);
    std::vector<std::byte> path_only_payload(7000);
    for (std::size_t index = 0; index < authoritative_payload.size(); ++index)
    {
        authoritative_payload[index] = static_cast<std::byte>((index * 31u + 7u) & 0xffu);
        path_only_payload[index] = static_cast<std::byte>((index * 47u + 23u) & 0xffu);
    }

    const auto run_case = [&](ProviderMode mode, const std::string& tag) -> bool
    {
        const auto fixture = BuildAuthoritativeCheckpointFixture();
        TempImageFile file(fixture.image, tag, ".raw");
        MetadataStore::VolumeContext context;
        context.device_path = file.path.wstring();
        context.volume_object_id = fixture.volume_oid;
        context.allow_legacy_scaffold_for_fixtures = false;
        context.integrity_check_on_mount = false;

        MetadataStore metadata(context);
        if (!Require(metadata.PrepareNativeWritePath(), tag + " prepares the Apple writer"))
        {
            return false;
        }
        MetadataStore::MutationRequest create;
        create.operation = MetadataStore::MutationOperation::CreateFile;
        create.path = L"\\identity-bound.bin";
        if (!Require(metadata.StageMutation(create) == MetadataStore::MutationStatus::Applied,
                tag + " create stages"))
        {
            return false;
        }
        MetadataStore::MutationRequest write;
        write.operation = MetadataStore::MutationOperation::Write;
        write.path = create.path;
        write.length = authoritative_payload.size();
        MetadataStore::PayloadIdentity staged_identity{};
        if (!Require(metadata.StageMutation(write, &staged_identity) == MetadataStore::MutationStatus::Applied &&
                staged_identity.object_id != 0 && staged_identity.generation != 0,
                tag + " payload stages with an identity"))
        {
            return false;
        }

        std::size_t full_provider_calls = 0;
        std::size_t range_provider_calls = 0;
        bool range_refused_for_identity_mismatch = false;
        std::wstring observed_path;
        MetadataStore::PayloadIdentity observed_identity{};
        std::uint64_t observed_offset = 0;
        std::size_t observed_size = 0;
        const auto* full_payload = mode == ProviderMode::FullOnly
            ? &authoritative_payload
            : &path_only_payload;
        metadata.SetFilePayloadProvider(
            [&, full_payload](const std::wstring& path, std::uint64_t logical_size)
                -> std::optional<std::vector<std::byte>>
            {
                ++full_provider_calls;
                if (path != create.path || logical_size != full_payload->size())
                {
                    return std::nullopt;
                }
                return *full_payload;
            });

        if (mode != ProviderMode::FullOnly)
        {
            auto range_owner_identity = staged_identity;
            if (mode == ProviderMode::RangeRefuses)
            {
                ++range_owner_identity.object_id;
            }
            metadata.SetFilePayloadRangeProvider(
                [&, range_owner_identity](
                    const std::wstring& path,
                    MetadataStore::PayloadIdentity identity,
                    std::uint64_t offset,
                    std::span<std::byte> destination)
                {
                    ++range_provider_calls;
                    observed_path = path;
                    observed_identity = identity;
                    observed_offset = offset;
                    observed_size = destination.size();
                    const bool identity_matches_owner =
                        identity.object_id == range_owner_identity.object_id &&
                        identity.generation == range_owner_identity.generation;
                    if (!identity_matches_owner)
                    {
                        range_refused_for_identity_mismatch = true;
                        return false;
                    }
                    if (path != create.path || offset != 0 ||
                        destination.size() != authoritative_payload.size())
                    {
                        return false;
                    }
                    std::copy(
                        authoritative_payload.begin(),
                        authoritative_payload.end(),
                        destination.begin());
                    return true;
                });
        }

        const auto commit_status = metadata.CommitPendingMutations();
        bool case_ok = true;
        if (mode == ProviderMode::RangeRefuses)
        {
            case_ok &= Require(commit_status == MetadataStore::CommitStatus::PersistFailed &&
                    metadata.LastCommitStage() == "apple-payload-unavailable" &&
                    metadata.LastCommitFailureReason() == L"AppleCommitPayloadUnavailable" &&
                    metadata.LastCommitFailureDetail() == create.path,
                tag + " treats identity-bearing range refusal as authoritative");
            case_ok &= Require(range_provider_calls == 1 && full_provider_calls == 0 &&
                    range_refused_for_identity_mismatch && observed_path == create.path &&
                    observed_identity.object_id == staged_identity.object_id &&
                    observed_identity.generation == staged_identity.generation &&
                    observed_offset == 0 && observed_size == authoritative_payload.size(),
                tag + " refuses the staged identity without calling the plausible path-only provider");
            std::error_code size_error;
            const auto image_size = std::filesystem::file_size(file.path, size_error);
            apfsaccess::rw::BlockDevice verify(file.path.wstring());
            std::vector<std::byte> actual_image;
            case_ok &= Require(!size_error && image_size == fixture.image.size() &&
                    verify.Read(0, fixture.image.size(), actual_image) && actual_image == fixture.image,
                tag + " refusal publishes no raw image bytes");
            return case_ok;
        }

        case_ok &= Require(commit_status == MetadataStore::CommitStatus::Committed,
            tag + " commits");
        case_ok &= Require(
            mode == ProviderMode::FullOnly
                ? full_provider_calls == 1 && range_provider_calls == 0
                : range_provider_calls == 1 && full_provider_calls == 0,
            tag + " uses only the configured authoritative provider path");
        MetadataStore reopened(context);
        std::vector<std::byte> actual_payload;
        case_ok &= Require(reopened.LoadCanonicalState() &&
                reopened.ReadCommittedFileRange(
                    create.path, 0, authoritative_payload.size(), actual_payload) &&
                actual_payload == authoritative_payload,
            tag + " publishes the expected payload bytes");
        return case_ok;
    };

    bool ok = true;
    ok &= run_case(ProviderMode::FullOnly, "apple-payload-full-provider-only");
    ok &= run_case(ProviderMode::RangeSucceeds, "apple-payload-range-provider-success");
    ok &= run_case(ProviderMode::RangeRefuses, "apple-payload-range-provider-refusal");
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

bool BuildUnicodeProjectionRecords(
    std::uint64_t incompatible_features,
    bool corrupt_hash,
    std::vector<apfsaccess::catalog::BtreeRecord>& out_records)
{
    using namespace apfsaccess::rw;
    out_records.clear();
    std::string error;
    apfsaccess::catalog::BtreeRecord root_record;
    AppleInodeRecord root;
    root.object_id = 2;
    root.parent_id = 2;
    root.private_id = 2;
    root.children_or_links = 1;
    root.write_generation = 1;
    root.mode = 0040755;
    if (!EncodeAppleInodeRecord(root, root_record, error))
    {
        return false;
    }

    apfsaccess::catalog::BtreeRecord child_record;
    AppleInodeRecord child;
    child.object_id = 17;
    child.parent_id = 2;
    child.private_id = 17;
    child.children_or_links = 1;
    child.write_generation = 1;
    child.mode = 0100644;
    if (!EncodeAppleInodeRecord(child, child_record, error))
    {
        return false;
    }

    apfsaccess::catalog::BtreeRecord directory_record;
    AppleDirectoryRecord directory;
    directory.parent_id = 2;
    directory.file_id = 17;
    directory.date_added = 500;
    directory.flags = 8;
    directory.name_utf8 = std::string("\xc3\xa9", 2);
    const auto policy = ApfsNamePolicy::FromIncompatibleFeatures(
        incompatible_features);
    if (!EncodeAppleDirectoryRecord(
            directory, policy, directory_record, error))
    {
        return false;
    }
    if (corrupt_hash)
    {
        if (!policy.UsesHashedDirectoryKeys() || directory_record.key.size() < 12)
        {
            return false;
        }
        directory_record.key[10] = static_cast<std::byte>(
            std::to_integer<unsigned int>(directory_record.key[10]) ^ 0x04u);
    }

    out_records = {
        std::move(root_record),
        std::move(directory_record),
        std::move(child_record),
    };
    return true;
}

bool TestReaderProjectsNormalizationInsensitiveUnicodeName()
{
    constexpr std::uint64_t kNormalizationInsensitive = 0x8;
    BuilderStore store;
    store.authoritative_checkpoint = true;
    store.volumes[0].incompat = kNormalizationInsensitive;
    if (!Require(BuildUnicodeProjectionRecords(
            kNormalizationInsensitive, false,
            store.volumes[0].filesystem_records),
        "Unicode projection fixture records encode"))
    {
        return false;
    }

    TempImageFile file(BuildStoreImage(store), "unicode-name-reader");
    apfsaccess::rw::BlockDevice device(file.path.wstring(), 0);
    apfsaccess::rw::NativeApfsVolumeProjection projection{};
    std::wstring error;
    const bool loaded = apfsaccess::rw::NativeApfsReader::TryLoadVolumeProjection(
        device, 101, projection, error);
    bool ok = Require(loaded,
        "normalization-insensitive projection loads a hashed directory key");
    if (!loaded)
    {
        return false;
    }
    const auto child = std::find_if(
        projection.inodes.begin(), projection.inodes.end(),
        [](const auto& inode) { return inode.object_id == 17; });
    ok &= Require(child != projection.inodes.end(),
        "Unicode child is reachable from its directory record");
    if (child != projection.inodes.end())
    {
        ok &= Require(child->name == L"\u00e9",
            "reader exposes the exact Unicode name instead of lossy substitution");
    }
    return ok;
}

bool TestReaderRejectsMismatchedDirectoryHash()
{
    constexpr std::uint64_t kCaseInsensitive = 0x1;
    BuilderStore store;
    store.authoritative_checkpoint = true;
    store.volumes[0].incompat = kCaseInsensitive;
    if (!Require(BuildUnicodeProjectionRecords(
            kCaseInsensitive, true,
            store.volumes[0].filesystem_records),
        "corrupt hash fixture records encode"))
    {
        return false;
    }

    TempImageFile file(BuildStoreImage(store), "bad-name-hash-reader");
    apfsaccess::rw::BlockDevice device(file.path.wstring(), 0);
    apfsaccess::rw::NativeApfsVolumeProjection projection{};
    std::wstring error;
    const bool loaded = apfsaccess::rw::NativeApfsReader::TryLoadVolumeProjection(
        device, 101, projection, error);
    return Require(!loaded,
        "reader fails closed when a hashed directory key does not match its name");
}

bool TestReaderRejectsDirectoryKeyTrailingBytes()
{
    constexpr std::uint64_t kNormalizationInsensitive = 0x8;
    BuilderStore store;
    store.authoritative_checkpoint = true;
    store.volumes[0].incompat = kNormalizationInsensitive;
    if (!Require(BuildUnicodeProjectionRecords(
            kNormalizationInsensitive, false,
            store.volumes[0].filesystem_records),
        "trailing-byte fixture records encode"))
    {
        return false;
    }
    store.volumes[0].filesystem_records[1].key.push_back(std::byte{0x5a});

    TempImageFile file(BuildStoreImage(store), "trailing-name-key-reader");
    apfsaccess::rw::BlockDevice device(file.path.wstring(), 0);
    apfsaccess::rw::NativeApfsVolumeProjection projection{};
    std::wstring error;
    const bool loaded = apfsaccess::rw::NativeApfsReader::TryLoadVolumeProjection(
        device, 101, projection, error);
    return Require(!loaded,
        "reader rejects trailing bytes outside the serialized directory name");
}

bool TestReaderProjectsHardLinksAsOneInodeWithTwoLinks()
{
    using namespace apfsaccess::rw;
    BuilderStore store;
    store.authoritative_checkpoint = true;
    store.volumes[0].incompat = 0;

    std::string error;
    std::vector<apfsaccess::catalog::BtreeRecord> records;
    AppleInodeRecord root;
    root.object_id = 2;
    root.parent_id = 2;
    root.private_id = 2;
    root.children_or_links = 2;
    root.mode = 0040755;
    apfsaccess::catalog::BtreeRecord encoded;
    bool ok = Require(
        EncodeAppleInodeRecord(root, encoded, error),
        "hard-link fixture root encodes: " + error);
    if (ok)
    {
        records.push_back(std::move(encoded));
    }

    AppleInodeRecord file;
    file.object_id = 17;
    file.parent_id = 2;
    file.private_id = 117;
    file.create_time = 1'000;
    file.modification_time = 2'000;
    file.change_time = 3'000;
    file.access_time = 4'000;
    file.children_or_links = 2;
    file.default_protection_class = 7;
    file.write_generation = 9;
    file.bsd_flags = 0x8002;
    file.owner = 501;
    file.group = 20;
    file.mode = 0100470;
    file.reserved_pad = 0x55aa;
    const std::string primary_name = "primary.bin";
    AppleExtendedField name_field;
    name_field.type = 4;
    name_field.data.assign(
        reinterpret_cast<const std::byte*>(primary_name.data()),
        reinterpret_cast<const std::byte*>(primary_name.data() + primary_name.size()));
    name_field.data.push_back(std::byte{0});
    file.extended_fields.push_back(std::move(name_field));
    encoded = {};
    ok &= Require(
        EncodeAppleInodeRecord(file, encoded, error),
        "hard-link fixture inode encodes: " + error);
    if (ok)
    {
        records.push_back(std::move(encoded));
    }

    const auto add_link = [&](const char* name, std::uint64_t sibling_id)
    {
        AppleDirectoryRecord drec;
        drec.parent_id = 2;
        drec.file_id = 17;
        drec.date_added = 500 + sibling_id;
        drec.flags = 8;
        drec.name_utf8 = name;
        apfsaccess::catalog::BtreeRecord drec_record;
        if (!EncodeAppleDirectoryRecord(drec, drec_record, error))
        {
            return false;
        }
        records.push_back(std::move(drec_record));

        AppleSiblingLinkRecord link{17, sibling_id, 2, name};
        apfsaccess::catalog::BtreeRecord link_record;
        if (!EncodeAppleSiblingLinkRecord(link, link_record, error))
        {
            return false;
        }
        records.push_back(std::move(link_record));

        AppleSiblingMapRecord map{sibling_id, 17};
        apfsaccess::catalog::BtreeRecord map_record;
        if (!EncodeAppleSiblingMapRecord(map, map_record, error))
        {
            return false;
        }
        records.push_back(std::move(map_record));
        return true;
    };
    ok &= Require(add_link("primary.bin", 700), "primary sibling records encode: " + error);
    ok &= Require(add_link("alias.bin", 701), "alias sibling records encode: " + error);
    if (!ok)
    {
        return false;
    }
    store.volumes[0].filesystem_records = std::move(records);

    TempImageFile image(BuildStoreImage(store), "hard-link-reader");
    BlockDevice device(image.path.wstring(), 0);
    NativeApfsVolumeProjection projection{};
    std::wstring wide_error;
    const bool loaded = NativeApfsReader::TryLoadVolumeProjection(
        device, 101, projection, wide_error);
    ok &= Require(loaded, "hard-link projection loads");
    if (!loaded)
    {
        return false;
    }

    const auto inode_count = std::count_if(
        projection.inodes.begin(), projection.inodes.end(),
        [](const auto& inode) { return inode.object_id == 17; });
    ok &= Require(inode_count == 1, "hard-linked object projects as one inode");
    const auto inode = std::find_if(
        projection.inodes.begin(), projection.inodes.end(),
        [](const auto& value) { return value.object_id == 17; });
    if (inode != projection.inodes.end())
    {
        constexpr std::uint64_t kFileTimeEpoch = 116444736000000000ull;
        ok &= Require(inode->private_id == 117, "private stream identity preserved");
        ok &= Require(inode->link_count == 2, "APFS link count preserved");
        ok &= Require(inode->owner == 501 && inode->group == 20, "POSIX ownership preserved");
        ok &= Require(inode->mode == 0100470 && inode->bsd_flags == 0x8002,
            "POSIX mode and BSD flags preserved");
        ok &= Require(inode->create_time_utc == kFileTimeEpoch + 10,
            "create time preserved");
        ok &= Require(inode->modification_time_utc == kFileTimeEpoch + 20,
            "modification time preserved");
        ok &= Require(inode->change_time_utc == kFileTimeEpoch + 30,
            "change time preserved");
        ok &= Require(inode->access_time_utc == kFileTimeEpoch + 40,
            "access time preserved");
    }

    std::vector<MetadataStore::DirectoryLink> links;
    std::copy_if(
        projection.directory_links.begin(), projection.directory_links.end(),
        std::back_inserter(links),
        [](const auto& link) { return link.child_object_id == 17; });
    std::sort(links.begin(), links.end(), [](const auto& left, const auto& right)
    {
        return left.sibling_id < right.sibling_id;
    });
    ok &= Require(links.size() == 2, "both hard-link directory entries preserved");
    if (links.size() == 2)
    {
        ok &= Require(links[0].sibling_id == 700 && links[0].entry_name_utf8 == "primary.bin",
            "primary sibling identity preserved");
        ok &= Require(links[1].sibling_id == 701 && links[1].entry_name_utf8 == "alias.bin",
            "alias sibling identity preserved");
    }

    MetadataStore::VolumeContext context;
    context.device_path = image.path.wstring();
    context.volume_object_id = 101;
    context.allow_legacy_scaffold_for_fixtures = false;
    context.integrity_check_on_mount = true;
    MetadataStore metadata(context);
    const auto canonical_loaded = metadata.LoadCanonicalState();
    if (!canonical_loaded)
    {
        std::wcerr << L"[DETAIL] hard-link canonical import reason="
                   << metadata.RecoveryReason() << std::endl;
    }
    ok &= Require(canonical_loaded,
        "hard-link projection imports into canonical metadata state");
    const auto primary = metadata.LookupCommittedInodeByPath(L"\\primary.bin");
    const auto alias = metadata.LookupCommittedInodeByPath(L"\\alias.bin");
    ok &= Require(primary.has_value() && alias.has_value(),
        "both hard-link paths resolve after canonical import");
    if (primary.has_value() && alias.has_value())
    {
        ok &= Require(primary->object_id == 17 && alias->object_id == primary->object_id,
            "both hard-link paths retain one inode identity");
    }
    const auto children = metadata.SnapshotCommittedDirectoryChildInodes(2);
    ok &= Require(children.has_value() && children->size() == 2,
        "directory enumeration retains both hard-link entries");
    if (children.has_value())
    {
        std::vector<std::wstring> child_names;
        child_names.reserve(children->size());
        for (const auto& child : *children)
        {
            child_names.push_back(child.name);
        }
        std::sort(child_names.begin(), child_names.end());
        ok &= Require(child_names == std::vector<std::wstring>{L"alias.bin", L"primary.bin"},
            "directory enumeration projects each link name");
    }

    const auto prepared = metadata.PrepareNativeWritePath();
    if (!prepared)
    {
        std::wcerr << L"[DETAIL] hard-link write preparation reason="
                   << metadata.RecoveryReason() << std::endl;
    }
    ok &= Require(prepared, "hard-link image prepares the Apple writer");
    MetadataStore::MutationRequest unlink_alias;
    unlink_alias.operation = MetadataStore::MutationOperation::Delete;
    unlink_alias.path = L"\\alias.bin";
    if (!primary || !metadata.CheckpointXid()) return false;
    const UnlinkOutcome expected{17, primary->xid, *metadata.CheckpointXid() + 1, 2, 2, 1, "\\alias.bin"};
    std::optional<UnlinkOutcome> unlink_outcome;
    auto invalid_unlink = unlink_alias;
    invalid_unlink.object_id = expected.object_id;
    invalid_unlink.generation = expected.generation_before;
    invalid_unlink.expected_unlink_outcome = expected;
    invalid_unlink.expected_unlink_outcome->links_after = 0;
    if (!Require(metadata.StageMutation(invalid_unlink, nullptr, &unlink_outcome) ==
            MetadataStore::MutationStatus::InvalidRequest && !unlink_outcome &&
            metadata.PendingMutationCount() == 0 &&
            metadata.DebugLookupWorkingInodeByPath(L"\\alias.bin").has_value(),
            "replay's wrong unlink outcome refuses without changing either alias")) return false;
    ok &= Require(metadata.StageMutation(unlink_alias, nullptr, &unlink_outcome) == MetadataStore::MutationStatus::Applied,
        "unlinking one hard-link alias stages");
    ok &= Require(unlink_outcome == expected,
        "native staging returns the exact bound unlink outcome separately from payload identity");
    const auto working_primary = metadata.DebugLookupWorkingInodeByPath(L"\\primary.bin");
    ok &= Require(working_primary.has_value() && working_primary->link_count == 1,
        "unlink decrements the inode link count without deleting the inode");
    ok &= Require(!metadata.DebugLookupWorkingInodeByPath(L"\\alias.bin").has_value(),
        "unlinked alias leaves the working namespace");
    const auto unlink_commit = metadata.CommitPendingMutations();
    if (unlink_commit != MetadataStore::CommitStatus::Committed)
    {
        std::wcerr << L"[DETAIL] hard-link unlink commit stage="
                   << metadata.LastCommitStage().c_str()
                   << L" reason=" << metadata.LastCommitFailureReason()
                   << L" detail=" << metadata.LastCommitFailureDetail() << std::endl;
    }
    ok &= Require(unlink_commit == MetadataStore::CommitStatus::Committed,
        "unlinking one hard-link alias commits");

    MetadataStore remounted(context);
    ok &= Require(remounted.LoadCanonicalState(),
        "hard-link unlink result remounts");
    const auto remounted_primary = remounted.LookupCommittedInodeByPath(L"\\primary.bin");
    ok &= Require(remounted_primary.has_value() && remounted_primary->object_id == 17 &&
            remounted_primary->link_count == 1,
        "remaining hard link and inode survive remount");
    ok &= Require(!remounted.LookupCommittedInodeByPath(L"\\alias.bin").has_value(),
        "unlinked alias stays absent after remount");

    TempImageFile rename_image(BuildStoreImage(store), "hard-link-rename");
    auto rename_context = context;
    rename_context.device_path = rename_image.path.wstring();
    MetadataStore rename_store(rename_context);
    ok &= Require(rename_store.PrepareNativeWritePath(),
        "hard-link rename image prepares the Apple writer");
    MetadataStore::MutationRequest rename_alias;
    rename_alias.operation = MetadataStore::MutationOperation::Rename;
    rename_alias.path = L"\\alias.bin";
    rename_alias.secondary_path = L"\\renamed.bin";
    ok &= Require(rename_store.StageMutation(rename_alias) == MetadataStore::MutationStatus::Applied,
        "renaming one hard-link alias stages");
    const auto renamed_working = rename_store.DebugLookupWorkingInodeByPath(L"\\renamed.bin");
    ok &= Require(rename_store.DebugLookupWorkingInodeByPath(L"\\primary.bin").has_value() &&
            !rename_store.DebugLookupWorkingInodeByPath(L"\\alias.bin").has_value() &&
            renamed_working.has_value() && renamed_working->object_id == 17 &&
            renamed_working->link_count == 2,
        "rename moves only the selected link");
    const auto rename_commit = rename_store.CommitPendingMutations();
    if (rename_commit != MetadataStore::CommitStatus::Committed)
    {
        std::wcerr << L"[DETAIL] hard-link rename commit stage="
                   << rename_store.LastCommitStage().c_str()
                   << L" reason=" << rename_store.LastCommitFailureReason()
                   << L" detail=" << rename_store.LastCommitFailureDetail() << std::endl;
    }
    ok &= Require(rename_commit == MetadataStore::CommitStatus::Committed,
        "renaming one hard-link alias commits");
    MetadataStore renamed_remount(rename_context);
    ok &= Require(renamed_remount.LoadCanonicalState() &&
            renamed_remount.LookupCommittedInodeByPath(L"\\primary.bin").has_value() &&
            renamed_remount.LookupCommittedInodeByPath(L"\\renamed.bin").has_value() &&
            !renamed_remount.LookupCommittedInodeByPath(L"\\alias.bin").has_value(),
        "renamed hard-link namespace survives remount");

    TempImageFile write_image(BuildStoreImage(store), "hard-link-write");
    auto write_context = context;
    write_context.device_path = write_image.path.wstring();
    MetadataStore write_store(write_context);
    std::vector<std::byte> payload(5000);
    for (std::size_t index = 0; index < payload.size(); ++index)
    {
        payload[index] = static_cast<std::byte>((index * 37u + 19u) & 0xffu);
    }
    write_store.SetFilePayloadProvider(
        [&payload](const std::wstring&, std::uint64_t logical_size)
            -> std::optional<std::vector<std::byte>>
        {
            return logical_size == payload.size()
                ? std::optional<std::vector<std::byte>>(payload)
                : std::nullopt;
        });
    ok &= Require(write_store.PrepareNativeWritePath(),
        "hard-link write image prepares the Apple writer");
    MetadataStore::MutationRequest resize_alias;
    resize_alias.operation = MetadataStore::MutationOperation::SetFileSize;
    resize_alias.path = L"\\alias.bin";
    resize_alias.length = payload.size();
    ok &= Require(write_store.StageMutation(resize_alias) == MetadataStore::MutationStatus::Applied,
        "resizing through a hard-link alias stages");
    MetadataStore::MutationRequest write_alias;
    write_alias.operation = MetadataStore::MutationOperation::Write;
    write_alias.path = L"\\alias.bin";
    write_alias.length = payload.size();
    ok &= Require(write_store.StageMutation(write_alias) == MetadataStore::MutationStatus::Applied,
        "writing through a hard-link alias stages");
    const auto write_commit = write_store.CommitPendingMutations();
    if (write_commit != MetadataStore::CommitStatus::Committed)
    {
        std::wcerr << L"[DETAIL] hard-link write commit stage="
                   << write_store.LastCommitStage().c_str()
                   << L" reason=" << write_store.LastCommitFailureReason()
                   << L" detail=" << write_store.LastCommitFailureDetail() << std::endl;
    }
    ok &= Require(write_commit == MetadataStore::CommitStatus::Committed,
        "writing through a hard-link alias commits");
    MetadataStore write_remount(write_context);
    ok &= Require(write_remount.LoadCanonicalState(),
        "hard-link payload remounts");
    std::vector<std::byte> primary_payload;
    std::vector<std::byte> alias_payload;
    ok &= Require(write_remount.ReadCommittedFileRange(
            L"\\primary.bin", 0, payload.size(), primary_payload) &&
            write_remount.ReadCommittedFileRange(
                L"\\alias.bin", 0, payload.size(), alias_payload) &&
            primary_payload == payload && alias_payload == payload,
        "writes through one hard link are visible through both names");

    BlockDevice sealed_source(write_image.path.wstring());
    std::vector<std::byte> sealed_image;
    if (!Require(sealed_source.Read(0,
            static_cast<std::size_t>(sealed_source.GetGeometry().total_bytes), sealed_image),
            "hard-link replacement fixture captures committed payload bytes"))
    {
        return false;
    }
    for (const auto* replaced_path : {L"\\alias.bin", L"\\primary.bin"})
    for (const int dirty_mode : {0, 1, 2})
    {
        TempImageFile replacement_image(sealed_image, "hard-link-replacement");
        auto replacement_context = context;
        replacement_context.device_path = replacement_image.path.wstring();
        MetadataStore replacement(replacement_context);
        ok &= Require(replacement.PrepareNativeWritePath(), "replacement image prepares");
        const std::wstring remaining_path = std::wstring(replaced_path) == L"\\alias.bin"
            ? L"\\primary.bin" : L"\\alias.bin";

        MetadataStore::MutationRequest same_inode;
        same_inode.operation = MetadataStore::MutationOperation::Rename;
        same_inode.path = remaining_path;
        same_inode.secondary_path = replaced_path;
        same_inode.replace_if_exists = true;
        ok &= Require(replacement.StageMutation(same_inode) == MetadataStore::MutationStatus::Applied,
            "rename between distinct names of the same inode succeeds as a no-op");
        const auto unchanged_source = replacement.DebugLookupWorkingInodeByPath(remaining_path);
        const auto unchanged_destination = replacement.DebugLookupWorkingInodeByPath(replaced_path);
        ok &= Require(unchanged_source && unchanged_destination &&
                unchanged_source->object_id == 17 && unchanged_destination->object_id == 17 &&
                unchanged_source->link_count == 2 && unchanged_destination->link_count == 2,
            "same-inode rename preserves both directory links and link count");

        MetadataStore::MutationRequest supersede;
        supersede.operation = MetadataStore::MutationOperation::CreateFile;
        supersede.path = replaced_path;
        supersede.replace_if_exists = true;
        ok &= Require(replacement.StageMutation(supersede) == MetadataStore::MutationStatus::UnsupportedOperation,
            "shared-inode supersede refuses until replacement replay can bind both identities");
        const auto preserved_source = replacement.DebugLookupWorkingInodeByPath(remaining_path);
        const auto preserved_destination = replacement.DebugLookupWorkingInodeByPath(replaced_path);
        ok &= Require(preserved_source && preserved_destination &&
                preserved_source->object_id == 17 && preserved_destination->object_id == 17 &&
                preserved_source->link_count == 2 && preserved_destination->link_count == 2,
            "refused supersede preserves both names and the shared inode");

        std::vector<std::byte> source_payload(6000, std::byte{0x5a});
        replacement.SetFilePayloadProvider(
            [&source_payload](const std::wstring& path, std::uint64_t length)
                -> std::optional<std::vector<std::byte>>
            {
                return path == L"\\source.bin" && length == source_payload.size()
                    ? std::optional<std::vector<std::byte>>(source_payload) : std::nullopt;
            });
        MetadataStore::MutationRequest create_source;
        create_source.operation = MetadataStore::MutationOperation::CreateFile;
        create_source.path = L"\\source.bin";
        ok &= Require(replacement.StageMutation(create_source) == MetadataStore::MutationStatus::Applied,
            "independent rename source creates");
        auto write_source = create_source;
        write_source.operation = MetadataStore::MutationOperation::Write;
        write_source.length = source_payload.size();
        ok &= Require(replacement.StageMutation(write_source) == MetadataStore::MutationStatus::Applied &&
                replacement.CommitPendingMutations() == MetadataStore::CommitStatus::Committed,
            "independent rename source payload commits");
        const auto source_inode = replacement.LookupCommittedInodeByPath(L"\\source.bin");
        for (const auto operation : {MetadataStore::MutationOperation::Delete,
                                    MetadataStore::MutationOperation::Rename})
        {
            std::size_t failpoint_hits = 0;
            replacement.SetAfterUnlinkHookForTests([&]()
            {
                ++failpoint_hits;
                ok &= Require(!replacement.DebugLookupWorkingInodeByPath(replaced_path),
                    "unlink failure is injected after the selected namespace entry is removed");
                return false;
            });
            MetadataStore::MutationRequest failed_unlink;
            failed_unlink.operation = operation;
            failed_unlink.path = operation == MetadataStore::MutationOperation::Delete
                ? replaced_path : L"\\source.bin";
            failed_unlink.secondary_path = replaced_path;
            failed_unlink.replace_if_exists = true;
            const auto failed_status = replacement.StageMutation(failed_unlink);
            replacement.SetAfterUnlinkHookForTests({});
            ok &= Require(failed_status == MetadataStore::MutationStatus::AllocationFailed && failpoint_hits == 1,
                "post-unlink failure is observed exactly once");
            const auto restored = replacement.DebugLookupWorkingInodeByPath(replaced_path);
            ok &= Require(restored && restored->object_id == 17 && restored->link_count == 2 &&
                    replacement.DebugLookupWorkingInodeByPath(remaining_path) &&
                    replacement.DebugLookupWorkingInodeByPath(L"\\source.bin") &&
                    replacement.PendingMutationCount() == 0 && replacement.PendingDeallocationCount() == 0,
                "failed unlink restores all names without pending mutation or deallocation");

            MetadataStore::MutationRequest touch;
            touch.operation = MetadataStore::MutationOperation::SetBasicInfo;
            touch.path = remaining_path;
            touch.timestamp_utc = 116444736000000001ull;
            ok &= Require(replacement.StageMutation(touch) == MetadataStore::MutationStatus::Applied &&
                    replacement.CommitPendingMutations() == MetadataStore::CommitStatus::Committed,
                "a later unrelated mutation commits after rollback");
            BlockDevice rolled_back_device(replacement_image.path.wstring());
            NativeApfsVolumeProjection rolled_back_projection;
            ok &= Require(NativeApfsReader::TryLoadVolumeProjection(
                    rolled_back_device, 101, rolled_back_projection, wide_error),
                "rollback metadata can be read from the published Apple tree");
            for (const auto& expected_link : links)
            {
                const auto actual = std::find_if(rolled_back_projection.directory_links.begin(),
                    rolled_back_projection.directory_links.end(), [&](const auto& value)
                    {
                        return value.child_object_id == 17 && value.entry_name_utf8 == expected_link.entry_name_utf8;
                    });
                ok &= Require(actual != rolled_back_projection.directory_links.end() &&
                        actual->parent_object_id == expected_link.parent_object_id &&
                        actual->sibling_id == expected_link.sibling_id &&
                        actual->date_added == expected_link.date_added && actual->flags == expected_link.flags,
                    "rollback preserves exact sibling identity, date-added and directory flags after commit");
            }
        }
        auto surviving_payload = payload;
        if (dirty_mode != 0)
        {
            std::fill(surviving_payload.begin() + 31, surviving_payload.begin() + 83, std::byte{0xda});
            replacement.SetFilePayloadRangeProvider([&](const std::wstring&, MetadataStore::PayloadIdentity identity,
                    std::uint64_t offset, std::span<std::byte> destination) {
                const auto* bytes = identity.object_id == 17 ? &surviving_payload :
                    source_inode && identity.object_id == source_inode->object_id ? &source_payload : nullptr;
                if (!bytes || offset > bytes->size() || destination.size() > bytes->size() - offset) return false;
                std::copy_n(bytes->begin() + static_cast<std::ptrdiff_t>(offset), destination.size(), destination.begin());
                return true;
            });
            MetadataStore::MutationRequest dirty;
            dirty.operation = MetadataStore::MutationOperation::Write;
            dirty.path = replaced_path;
            dirty.offset = 31;
            dirty.length = 52;
            ok &= Require(replacement.StageMutation(dirty) == MetadataStore::MutationStatus::Applied &&
                    replacement.PendingPayloadObjectSummaryCount() == 1,
                "hard-link replacement starts with an uncommitted write to its destination inode");
        }
        MetadataStore::MutationRequest replace_alias;
        replace_alias.operation = MetadataStore::MutationOperation::Rename;
        replace_alias.path = L"\\source.bin";
        replace_alias.secondary_path = replaced_path;
        replace_alias.replace_if_exists = true;
        ok &= Require(replacement.StageMutation(replace_alias) == MetadataStore::MutationStatus::Applied,
            "rename over the selected hard-link destination stages");
        const auto surviving = replacement.DebugLookupWorkingInodeByPath(remaining_path);
        const auto replaced = replacement.DebugLookupWorkingInodeByPath(replaced_path);
        ok &= Require(surviving && surviving->object_id == 17 && surviving->link_count == 1 &&
                replaced && source_inode && replaced->object_id == source_inode->object_id &&
                !replacement.DebugLookupWorkingInodeByPath(L"\\source.bin"),
            "replacement unlinks only its exact destination and retains the other inode");
        if (dirty_mode != 0)
        {
            ok &= Require(replacement.PendingPayloadObjectSummaryCount() == 1,
                "rename replacement retains the surviving inode's pending payload summary");
            if (dirty_mode == 2)
            {
                unsigned failures = 0;
                replacement.SetAfterUnlinkHookForTests([&]() { ++failures; return false; });
                MetadataStore::MutationRequest failed;
                failed.operation = MetadataStore::MutationOperation::Delete;
                failed.path = remaining_path;
                const auto rejected = replacement.StageMutation(failed);
                replacement.SetAfterUnlinkHookForTests({});
                const auto restored = replacement.DebugLookupWorkingInodeByPath(remaining_path);
                ok &= Require(rejected == MetadataStore::MutationStatus::AllocationFailed && failures == 1 &&
                        replacement.PendingPayloadObjectSummaryCount() == 1 &&
                        restored && restored->object_id == 17,
                    "post-replacement rollback rebuilds dirty accounting without rebinding a reused name");
                std::fill(source_payload.begin() + 211, source_payload.begin() + 248, std::byte{0x36});
                std::fill(surviving_payload.begin() + 347, surviving_payload.begin() + 376, std::byte{0xb7});
                MetadataStore::MutationRequest followup;
                followup.operation = MetadataStore::MutationOperation::Write;
                followup.path = replaced_path;
                followup.offset = 211;
                followup.length = 37;
                ok &= Require(replacement.StageMutation(followup) == MetadataStore::MutationStatus::Applied,
                    "the new owner of the reused pathname accepts a subsequent write after rollback");
                followup.path = remaining_path;
                followup.offset = 347;
                followup.length = 29;
                ok &= Require(replacement.StageMutation(followup) == MetadataStore::MutationStatus::Applied &&
                        replacement.PendingPayloadObjectSummaryCount() == 2,
                    "the surviving old inode accepts a subsequent write with both payload owners tracked");
            }
        }
        ok &= Require(replacement.CommitPendingMutations() == MetadataStore::CommitStatus::Committed,
            "hard-link replacement commits");
        MetadataStore replacement_remount(replacement_context);
        ok &= Require(replacement_remount.PrepareNativeWritePath(), "replacement remount prepares");
        std::vector<std::byte> surviving_bytes;
        std::vector<std::byte> replaced_bytes;
        ok &= Require(replacement_remount.ReadCommittedFileRange(remaining_path, 0, payload.size(), surviving_bytes) &&
                surviving_bytes == surviving_payload &&
                replacement_remount.ReadCommittedFileRange(replaced_path, 0, source_payload.size(), replaced_bytes) &&
                replaced_bytes == source_payload,
            "remount preserves the two distinct payloads byte-for-byte after replacement");
        MetadataStore::MutationRequest final_unlink;
        final_unlink.operation = MetadataStore::MutationOperation::Delete;
        final_unlink.path = remaining_path;
        ok &= Require(replacement_remount.StageMutation(final_unlink) == MetadataStore::MutationStatus::Applied &&
                replacement_remount.CommitPendingMutations() == MetadataStore::CommitStatus::Committed,
            "final unlink of the old inode commits");
        MetadataStore final_remount(replacement_context);
        replaced_bytes.clear();
        ok &= Require(final_remount.LoadCanonicalState() &&
                !final_remount.LookupCommittedInodeByPath(remaining_path) &&
                final_remount.ReadCommittedFileRange(replaced_path, 0, source_payload.size(), replaced_bytes) &&
                replaced_bytes == source_payload,
            "final unlink and remount leave the replacement inode and payload intact");
    }
    return ok;
}

bool TestReaderProjectsSymbolicLinkTargetWithoutResolvingIt()
{
    using namespace apfsaccess::rw;
    BuilderStore store;
    store.authoritative_checkpoint = true;
    store.volumes[0].incompat = 0;

    std::string error;
    std::vector<apfsaccess::catalog::BtreeRecord> records;
    const auto append = [&](bool encoded, apfsaccess::catalog::BtreeRecord& record,
                            const std::string& message)
    {
        if (!Require(encoded, message + ": " + error))
        {
            return false;
        }
        records.push_back(std::move(record));
        return true;
    };

    AppleInodeRecord root;
    root.object_id = 2;
    root.parent_id = 2;
    root.private_id = 2;
    root.children_or_links = 1;
    root.mode = 0040755;
    apfsaccess::catalog::BtreeRecord encoded;
    if (!append(EncodeAppleInodeRecord(root, encoded, error), encoded,
            "symlink fixture root encodes"))
    {
        return false;
    }

    AppleInodeRecord link;
    link.object_id = 23;
    link.parent_id = 2;
    link.private_id = 23;
    link.children_or_links = 1;
    link.mode = 0120777;
    link.uncompressed_size = 17;
    encoded = {};
    if (!append(EncodeAppleInodeRecord(link, encoded, error), encoded,
            "symlink fixture inode encodes"))
    {
        return false;
    }

    AppleDirectoryRecord drec;
    drec.parent_id = 2;
    drec.file_id = 23;
    drec.date_added = 500;
    drec.flags = 10;
    drec.name_utf8 = "broken-link";
    encoded = {};
    if (!append(EncodeAppleDirectoryRecord(drec, encoded, error), encoded,
            "symlink fixture directory record encodes"))
    {
        return false;
    }

    constexpr char kTarget[] = "../missing-target";
    AppleXattrRecord target;
    target.object_id = 23;
    target.name_utf8 = "com.apple.fs.symlink";
    target.flags = kAppleXattrDataEmbedded;
    target.data.assign(
        reinterpret_cast<const std::byte*>(kTarget),
        reinterpret_cast<const std::byte*>(kTarget + sizeof(kTarget) - 1));
    encoded = {};
    if (!append(EncodeAppleXattrRecord(target, encoded, error), encoded,
            "symlink target xattr encodes"))
    {
        return false;
    }
    store.volumes[0].filesystem_records = std::move(records);

    TempImageFile image(BuildStoreImage(store), "symlink-reader");
    for (const bool external_attribute : {false, true})
    {
        auto protected_store = store;
        AppleXattrRecord unrelated;
        unrelated.object_id = 23; unrelated.name_utf8 = "com.example.preserve";
        unrelated.flags = kAppleXattrDataEmbedded; unrelated.data = {std::byte{0x32}, std::byte{0x91}};
        if (external_attribute)
        {
            unrelated.flags = kAppleXattrDataStream;
            unrelated.data.assign(48, std::byte{0});
            PutU64LE(unrelated.data, 0, 777);
            if (!Require(EncodeAppleDataStreamIdRecord({777, 1}, encoded, error), "external attribute reference encodes")) return false;
            protected_store.volumes[0].filesystem_records.push_back(std::move(encoded));
        }
        if (!Require(EncodeAppleXattrRecord(unrelated, encoded, error), "protected symlink attribute encodes")) return false;
        protected_store.volumes[0].filesystem_records.push_back(std::move(encoded));
        const auto protected_bytes = BuildStoreImage(protected_store);
        TempImageFile protected_image(protected_bytes, "symlink-content-guard");
        MetadataStore::VolumeContext protected_context;
        protected_context.device_path = protected_image.path.wstring();
        protected_context.volume_object_id = 101;
        protected_context.allow_legacy_scaffold_for_fixtures = false;
        MetadataStore protected_metadata(protected_context);
        MetadataStore::MutationRequest remove;
        remove.operation = MetadataStore::MutationOperation::RemoveSymbolicLinkTarget;
        remove.path = L"\\broken-link";
        MetadataStore::MutationRequest write;
        write.operation = MetadataStore::MutationOperation::Write; write.path = remove.path; write.length = 4;
        protected_metadata.SetFilePayloadProvider([](const auto&, auto) -> std::optional<std::vector<std::byte>> {
            return std::vector<std::byte>(4, std::byte{0x5a});
        });
        std::vector<std::byte> after;
        if (!Require(protected_metadata.PrepareNativeWritePath() &&
                protected_metadata.StageMutation(remove) == MetadataStore::MutationStatus::Applied &&
                protected_metadata.StageMutation(write) == MetadataStore::MutationStatus::Applied,
                "symlink conversion with another attribute stages")) return false;
        if (external_attribute)
        {
            if (!Require(protected_metadata.CommitPendingMutations() == MetadataStore::CommitStatus::InvariantFailed &&
                    protected_metadata.LastCommitFailureReason() == L"AppleCommitContentExtendedRecordsUnsupported" &&
                    protected_metadata.Device().Read(0, protected_bytes.size(), after) && after == protected_bytes,
                    "symlink conversion cannot discard an external attribute during a content write")) return false;
        }
        else
        {
            if (!Require(protected_metadata.CommitPendingMutations() == MetadataStore::CommitStatus::Committed,
                    "symlink conversion preserves an ordinary embedded attribute")) return false;
            MetadataStore reopened(protected_context);
            if (!Require(reopened.PrepareNativeWritePath(), "converted symlink checkpoint reopens")) return false;
            const auto preserved = reopened.LookupCommittedExtendedAttribute(23, unrelated.name_utf8);
            const auto converted = reopened.LookupCommittedInodeByPath(write.path);
            if (!Require(preserved && preserved->flags == unrelated.flags && preserved->data == unrelated.data &&
                    converted && converted->object_id == 23 && converted->node_type == MetadataStore::NodeType::RegularFile &&
                    !reopened.LookupCommittedExtendedAttribute(23, "com.apple.fs.symlink") &&
                    reopened.ReadCommittedFileRange(write.path, 0, 4, after) &&
                    after == std::vector<std::byte>(4, std::byte{0x5a}),
                    "fresh conversion keeps the attribute, inode identity and exact content without the old symlink target")) return false;
        }
    }
    BlockDevice device(image.path.wstring(), 0);
    NativeApfsVolumeProjection projection{};
    std::wstring wide_error;
    bool ok = Require(NativeApfsReader::TryLoadVolumeProjection(
            device, 101, projection, wide_error),
        "reader accepts a broken symbolic link without resolving its target");
    if (!ok)
    {
        return false;
    }

    const auto inode = std::find_if(
        projection.inodes.begin(), projection.inodes.end(),
        [](const auto& value) { return value.object_id == 23; });
    ok &= Require(inode != projection.inodes.end(),
        "symbolic-link inode is reachable from its directory record");
    if (inode != projection.inodes.end())
    {
        ok &= Require(inode->node_type == MetadataStore::NodeType::SymbolicLink,
            "symbolic-link mode is not projected as a regular file");
        ok &= Require(inode->symlink_target_utf8 == kTarget,
            "relative symbolic-link target bytes are preserved exactly");
        ok &= Require(inode->logical_size == sizeof(kTarget) - 1,
            "symbolic-link logical size matches its target bytes");
    }

    MetadataStore::VolumeContext context;
    context.device_path = image.path.wstring();
    context.volume_object_id = 101;
    context.allow_legacy_scaffold_for_fixtures = false;
    context.integrity_check_on_mount = false;
    MetadataStore metadata(context);
    ok &= Require(metadata.LoadCanonicalState(),
        "symbolic-link projection imports into canonical metadata state");
    const auto imported = metadata.LookupCommittedInodeByPath(L"\\broken-link");
    ok &= Require(imported.has_value() &&
            imported->node_type == MetadataStore::NodeType::SymbolicLink &&
            imported->symlink_target_utf8 == kTarget,
        "canonical metadata retains the unresolved symbolic-link target");

    ok &= Require(metadata.PrepareNativeWritePath(),
        "symbolic-link image prepares the Apple writer");
    MetadataStore::MutationRequest replace_target;
    replace_target.operation = MetadataStore::MutationOperation::SetSymbolicLinkTarget;
    replace_target.path = L"\\broken-link";
    replace_target.secondary_path = L"/Volumes/Other/target";
    ok &= Require(metadata.StageMutation(replace_target) ==
            MetadataStore::MutationStatus::Applied,
        "replacing a symbolic-link target stages");
    ok &= Require(metadata.CommitPendingMutations() ==
            MetadataStore::CommitStatus::Committed,
        "replacing a symbolic-link target commits");
    MetadataStore replaced(context);
    ok &= Require(replaced.LoadCanonicalState(),
        "replaced symbolic-link target remounts");
    const auto replaced_inode = replaced.LookupCommittedInodeByPath(L"\\broken-link");
    ok &= Require(replaced_inode.has_value() &&
            replaced_inode->node_type == MetadataStore::NodeType::SymbolicLink &&
            replaced_inode->symlink_target_utf8 == "/Volumes/Other/target",
        "absolute symbolic-link target survives canonical remount exactly");

    ok &= Require(replaced.PrepareNativeWritePath(),
        "replaced symbolic-link image prepares a second transaction");
    MetadataStore::MutationRequest remove_target;
    remove_target.operation = MetadataStore::MutationOperation::RemoveSymbolicLinkTarget;
    remove_target.path = L"\\broken-link";
    ok &= Require(replaced.StageMutation(remove_target) ==
            MetadataStore::MutationStatus::Applied,
        "removing a symbolic-link target stages");
    ok &= Require(replaced.CommitPendingMutations() ==
            MetadataStore::CommitStatus::Committed,
        "removing a symbolic-link target commits");
    MetadataStore removed(context);
    ok &= Require(removed.LoadCanonicalState(),
        "removed symbolic-link target remounts");
    const auto regular = removed.LookupCommittedInodeByPath(L"\\broken-link");
    ok &= Require(regular.has_value() &&
            regular->node_type == MetadataStore::NodeType::RegularFile &&
            regular->symlink_target_utf8.empty() && regular->logical_size == 0,
        "removing the reparse target leaves a safe empty regular inode");

    const auto check_raw_kind = [&](std::uint64_t object_id, std::uint16_t expected_type,
                                    const std::string& expected_target)
    {
        using namespace apfsaccess::catalog;
        HeldFileSource source(image.path.string());
        std::string raw_error;
        const auto checkpoint = LoadAppleCheckpointView(source, 0, source.SizeBytes(), raw_error);
        if (!Require(checkpoint.has_value(), "kind transition checkpoint reloads: " + raw_error))
        {
            return false;
        }
        const auto& volume = checkpoint->volumes.front();
        std::vector<apfsaccess::catalog::BtreeRecord> raw_records;
        if (!Require(ReadBtreeLeafRecords(source, checkpoint->container.superblock.block_size,
                volume.root_tree.physical_block, false, volume.superblock.omap_oid,
                checkpoint->container.superblock.xid, raw_records, raw_error),
                "kind transition raw filesystem tree reloads: " + raw_error))
        {
            return false;
        }
        bool valid = true;
        std::size_t inode_count = 0, drec_count = 0, target_count = 0;
        for (const auto& record : raw_records)
        {
            AppleInodeRecord raw_inode;
            if (ApfsExtendedRecordCodec::DecodeInode(record, raw_inode, raw_error) && raw_inode.object_id == object_id)
            {
                ++inode_count;
                valid &= Require((raw_inode.mode >> 12) == expected_type,
                    "raw inode mode matches the committed node kind");
            }
            if ((ReadU64LE(record.key, 0).value_or(0) >> 60) == 9 &&
                ReadU64LE(record.value, 0) == object_id)
            {
                ++drec_count;
                valid &= Require((ReadU16LE(record.value, 16).value_or(0) & 0xF) == expected_type,
                    "every raw directory record agrees with the committed inode mode");
            }
            AppleXattrRecord raw_target;
            if (ApfsExtendedRecordCodec::DecodeXattr(record, raw_target, raw_error) &&
                raw_target.object_id == object_id && raw_target.name_utf8 == "com.apple.fs.symlink")
            {
                ++target_count;
                valid &= Require(raw_target.data.size() == expected_target.size() &&
                    std::memcmp(raw_target.data.data(), expected_target.data(), expected_target.size()) == 0,
                    "raw symlink target bytes match without resolving or rewriting the target");
            }
        }
        valid &= Require(inode_count == 1 && drec_count == 1 &&
            target_count == (expected_target.empty() ? 0u : 1u),
            "kind transition keeps one inode/link and exactly the required symlink xattr");
        return valid;
    };
    ok &= check_raw_kind(23, 8, "");
    ok &= Require(removed.PrepareNativeWritePath(), "regular-to-link image prepares");
    MetadataStore::MutationRequest create_regular;
    create_regular.operation = MetadataStore::MutationOperation::CreateFile;
    create_regular.path = L"\\new-link";
    ok &= Require(removed.StageMutation(create_regular) == MetadataStore::MutationStatus::Applied &&
        removed.CommitPendingMutations() == MetadataStore::CommitStatus::Committed,
        "regular-to-link starts from a separately committed regular file");
    const auto new_inode = removed.LookupCommittedInodeByPath(create_regular.path);
    if (!Require(new_inode.has_value(), "new regular inode is present")) return false;
    ok &= check_raw_kind(new_inode->object_id, 8, "");
    replace_target.path = create_regular.path;
    ok &= Require(removed.StageMutation(replace_target) == MetadataStore::MutationStatus::Applied &&
        removed.CommitPendingMutations() == MetadataStore::CommitStatus::Committed,
        "separately committed regular file converts to a symlink");
    ok &= check_raw_kind(new_inode->object_id, 10, "/Volumes/Other/target");
    return ok;
}

bool TestEmptyDirectorySymbolicLinkConversion(
    bool restore_directory = false, std::uint16_t permissions = 02751, bool remove_to_regular = false)
{
    using namespace apfsaccess::rw;
    using namespace apfsaccess::catalog;
    using apfsaccess::catalog::BtreeRecord;
    BuilderStore fixture;
    fixture.authoritative_checkpoint = true;
    fixture.volumes[0].incompat = 0;
    auto& records = fixture.volumes[0].filesystem_records;
    std::string error;
    BtreeRecord encoded;
    AppleInodeRecord original;
    original.object_id = original.private_id = 23; original.parent_id = 2;
    original.mode = static_cast<std::uint16_t>(0040000 | permissions);
    original.owner = 501; original.group = 20;
    original.create_time = 1'037; original.modification_time = 2'053;
    original.change_time = 3'071; original.access_time = 4'099;
    for (const auto type : {3, 4, 7})
    {
        AppleExtendedField field;
        field.type = static_cast<std::uint8_t>(type);
        field.data.assign(type == 3 ? 4 : type == 4 ? 6 : 32, std::byte{0});
        if (type == 4) std::memcpy(field.data.data(), "empty", 5);
        else field.data[0] = std::byte{0x31};
        original.extended_fields.push_back(field);
    }
    for (const auto id : {2ULL, 23ULL, 24ULL})
    {
        auto inode = original;
        inode.object_id = inode.private_id = id;
        if (id != 23) { inode.mode = 0040755; inode.children_or_links = id == 2 ? 2 : 0; inode.extended_fields.clear(); }
        if (!Require(EncodeAppleInodeRecord(inode, encoded, error), "directory conversion inode encodes")) return false;
        records.push_back(encoded);
        if (id == 2) continue;
        AppleDirectoryRecord drec;
        drec.parent_id = 2; drec.file_id = id; drec.flags = 4;
        drec.name_utf8 = id == 23 ? "empty" : "target";
        if (!Require(EncodeAppleDirectoryRecord(drec, encoded, error), "directory conversion DREC encodes")) return false;
        records.push_back(encoded);
    }
    std::vector<BtreeRecord> attributes;
    for (const auto* name : {"com.example.opaque", "com.apple.system.Security"})
    {
        AppleXattrRecord attr;
        attr.object_id = 23; attr.name_utf8 = name; attr.flags = kAppleXattrDataEmbedded;
        attr.data = {std::byte{0}, std::byte{0xff}, std::byte{0x51}};
        if (attr.name_utf8 == "com.apple.system.Security")
        {
            AppleSecurityRecord security;
            security.no_acl = true;
            if (!Require(ApfsExtendedRecordCodec::EncodeSecurity(security, attr.data, error), "directory security encodes")) return false;
        }
        if (!Require(EncodeAppleXattrRecord(attr, encoded, error), "directory conversion attribute encodes")) return false;
        attributes.push_back(encoded); records.push_back(encoded);
    }
    const auto bytes = BuildStoreImage(fixture);
    TempImageFile image(bytes, "empty-directory-link", ".raw");
    MetadataStore::VolumeContext context;
    context.device_path = image.path.wstring(); context.volume_object_id = 101;
    context.allow_legacy_scaffold_for_fixtures = false;
    MetadataStore metadata(context);
    if (!Require(metadata.PrepareNativeWritePath(), "safe empty directory premise prepares Apple writer")) return false;
    const auto before = metadata.LookupCommittedInodeByPath(L"\\empty");
    if (!Require(before && before->is_directory && before->directory_entry_count == 0 &&
            before->object_id == 23 && before->private_id == 23 && before->logical_size == 0,
            "conversion premise is the exact empty directory")) return false;
    std::size_t payload_requests = 0;
    metadata.SetFilePayloadProvider([&](const auto&, auto) -> std::optional<std::vector<std::byte>> {
        ++payload_requests;
        return std::nullopt;
    });
    MetadataStore::MutationRequest request;
    request.operation = MetadataStore::MutationOperation::SetSymbolicLinkTarget;
    request.path = L"\\empty"; request.object_id = 23; request.secondary_path = L"./target";
    request.generation = metadata.LastCommittedXid().value() + 1;
    if (!Require(metadata.StageMutation(request) == MetadataStore::MutationStatus::Applied,
            "safe empty directory converts to ordinary symbolic link"))
    {
        std::wcerr << L"conversion reason: " << metadata.LastMutationFailureReason() << std::endl;
        return false;
    }
    const auto pending = metadata.PendingMutationCount();
    metadata.SetCommitStageHook([](std::string_view stage) { return stage != "before-apple-publish"; });
    std::vector<std::byte> after;
    bool ok = Require(metadata.CommitPendingMutations() == MetadataStore::CommitStatus::PersistFailed &&
        metadata.PendingMutationCount() == pending && pending == 1 &&
        metadata.Device().Read(0, bytes.size(), after) && after == bytes,
        "directory conversion rejection publishes nothing and retains retry");
    const auto unchanged = metadata.LookupCommittedInodeByPath(L"\\empty");
    ok &= Require(unchanged && unchanged->is_directory, "rejected conversion leaves committed directory intact");
    metadata.SetCommitStageHook({});
    if (!Require(metadata.CommitPendingMutations() == MetadataStore::CommitStatus::Committed,
            "directory conversion retry commits")) return false;
    ok &= Require(payload_requests == 0, "directory conversion never requests file payload");

    bool restored = false;
    bool removed_to_regular = false;
    // Use the same strict checkpoint/raw-tree path as the existing kind-transition checker.
    const auto check_raw = [&](const std::string& name, bool present)
    {
        HeldFileSource source(image.path.string());
        const auto checkpoint = LoadAppleCheckpointView(source, 0, source.SizeBytes(), error);
        if (!Require(checkpoint.has_value(), "directory conversion raw checkpoint loads")) return false;
        const auto& volume = checkpoint->volumes.front();
        std::vector<BtreeRecord> raw;
        if (!Require(ReadBtreeLeafRecords(source, checkpoint->container.superblock.block_size,
                volume.root_tree.physical_block, false, volume.superblock.omap_oid,
                checkpoint->container.superblock.xid, raw, error), "directory conversion raw tree loads")) return false;
        bool valid = true;
        std::size_t inodes = 0, links = 0, targets = 0;
        for (const auto& record : raw)
        {
            const auto key = ReadU64LE(record.key, 0).value_or(0);
            AppleInodeRecord inode;
            if (ApfsExtendedRecordCodec::DecodeInode(record, inode, error) && inode.object_id == 23)
            {
                ++inodes;
                valid &= Require(inode.private_id == 23 && inode.parent_id == 2 &&
                    inode.mode == ((restored ? 0040000 : removed_to_regular ? 0100000 : 0120000) | permissions) &&
                    inode.owner == original.owner && inode.group == original.group &&
                    inode.children_or_links == (restored ? 0 : 1) &&
                    inode.create_time == original.create_time && inode.modification_time == original.modification_time &&
                    inode.change_time == original.change_time && inode.access_time == original.access_time &&
                    std::none_of(inode.extended_fields.begin(), inode.extended_fields.end(),
                        [](const auto& field) { return field.type == 8; }),
                    "raw converted inode preserves identity, permissions and nanoseconds without a data stream");
                for (auto expected : original.extended_fields)
                {
                    if (expected.type == 4)
                    {
                        expected.data.assign(name.size() + 1, std::byte{0});
                        std::memcpy(expected.data.data(), name.data(), name.size());
                    }
                    valid &= Require(std::count_if(inode.extended_fields.begin(), inode.extended_fields.end(),
                        [&](const auto& field) { return field.type == expected.type &&
                            field.flags == expected.flags && field.data == expected.data; }) == 1,
                        "safe name, document ID and FinderInfo fields survive conversion and rename");
                }
            }
            valid &= Require(!((key >> 60) == 8 && (key & 0x0fffffffffffffffULL) == 23),
                "converted directory has no file extents");
            if ((key >> 60) == 9 && ReadU64LE(record.value, 0) == 23)
            {
                ++links;
                AppleDirectoryRecord expected;
                expected.parent_id = 2; expected.file_id = 23;
                expected.flags = restored ? 4 : removed_to_regular ? 8 : 10; expected.name_utf8 = name;
                if (!Require(EncodeAppleDirectoryRecord(expected, encoded, error), "converted DREC expectation encodes")) return false;
                valid &= Require(record.key == encoded.key && record.value == encoded.value,
                    "converted raw name and DREC type are exact");
            }
            AppleXattrRecord attr;
            if (ApfsExtendedRecordCodec::DecodeXattr(record, attr, error) && attr.object_id == 23 &&
                attr.name_utf8 == "com.apple.fs.symlink")
            {
                ++targets;
                valid &= Require(attr.flags == kAppleXattrDataEmbedded && attr.data.size() == 8 &&
                    std::memcmp(attr.data.data(), "./target", 8) == 0, "raw relative target is exact and embedded");
            }
        }
        for (const auto& attr : attributes)
            valid &= Require(std::count_if(raw.begin(), raw.end(), [&](const auto& record) {
                return record.key == attr.key && record.value == attr.value;
            }) == (present ? 1 : 0), "opaque and security attributes preserved until unlink");
        for (const auto& record : records)
            if ((ReadU64LE(record.key, 0).value_or(0) & 0x0fffffffffffffffULL) == 24 ||
                ((ReadU64LE(record.key, 0).value_or(0) >> 60) == 9 && ReadU64LE(record.value, 0) == 24))
                valid &= Require(std::count_if(raw.begin(), raw.end(), [&](const auto& item) {
                    return item.key == record.key && item.value == record.value;
                }) == 1, "target inode and namespace remain byte-identical");
        return Require(inodes == (present ? 1u : 0u) && links == inodes &&
            targets == (present && !restored && !removed_to_regular ? 1u : 0u),
            "raw conversion namespace and target counts agree") && valid;
    };
    ok &= check_raw("empty", true);
    MetadataStore reopened(context);
    if (!Require(reopened.PrepareNativeWritePath(), "converted directory reopens")) return false;
    const auto link = reopened.LookupCommittedInodeByPath(L"\\empty");
    if (!Require(link && link->object_id == 23 && link->private_id == 23 && !link->is_directory &&
        link->node_type == MetadataStore::NodeType::SymbolicLink && link->symlink_target_utf8 == "./target" &&
        link->logical_size == 8 && link->data_physical_address == 0,
        "reopened inode is an ordinary payload-free symbolic link")) return false;
    if (remove_to_regular)
    {
        request = {}; request.operation = MetadataStore::MutationOperation::RemoveSymbolicLinkTarget;
        request.path = L"\\empty"; request.object_id = 23;
        request.generation = reopened.LastCommittedXid().value() + 1;
        if (!Require(reopened.StageMutation(request) == MetadataStore::MutationStatus::Applied &&
                reopened.CommitPendingMutations() == MetadataStore::CommitStatus::Committed,
                "op9 removes the target from an explicitly permissioned symbolic link")) return false;
        MetadataStore independent(context);
        if (!Require(independent.PrepareNativeWritePath(), "op9 regular inode reopens independently")) return false;
        const auto regular = independent.LookupCommittedInodeByPath(request.path);
        ok &= Require(regular && regular->object_id == 23 && regular->private_id == 23 &&
            regular->node_type == MetadataStore::NodeType::RegularFile && !regular->is_directory &&
            regular->symlink_target_utf8.empty() && regular->logical_size == 0,
            "op9 retains identity and leaves an empty regular inode");
        removed_to_regular = true;
        return check_raw("empty", true) && ok;
    }
    if (restore_directory)
    {
        request = {}; request.operation = MetadataStore::MutationOperation::RestoreDirectoryFromSymbolicLink;
        request.path = L"\\empty"; request.object_id = 23;
        request.generation = reopened.LastCommittedXid().value() + 1;
        std::vector<std::byte> before_restore, after_restore;
        if (!Require(reopened.Device().Read(0, bytes.size(), before_restore),
                "restoration preimage reads")) return false;
        for (unsigned bad_field = 0; bad_field != 8; ++bad_field)
        {
            auto bad = request;
            const wchar_t* reason = L"DirectoryRestoreRequestInvalid";
            switch (bad_field)
            {
            case 0: bad.offset = 1; break;
            case 1: bad.length = 1; break;
            case 2: bad.secondary_path = L"other"; break;
            case 3: bad.replace_if_exists = true; break;
            case 4: bad.timestamp_utc = 1; break;
            case 5: ++bad.object_id; reason = L"ReplayDirectoryRestoreIdentityMismatch"; break;
            case 6: ++bad.generation; reason = L"ReplayDirectoryRestoreIdentityMismatch"; break;
            case 7: bad.inline_payload = {std::byte{1}}; reason = L"AttributePayloadOnOtherMutation"; break;
            }
            if (!Require(reopened.StageMutation(bad) != MetadataStore::MutationStatus::Applied &&
                    reopened.LastMutationFailureReason() == reason && reopened.PendingMutationCount() == 0 &&
                    reopened.Device().Read(0, bytes.size(), after_restore) && after_restore == before_restore,
                    "malformed directory restoration rejects before staging or publication")) return false;
        }
        if (!Require(reopened.StageMutation(request) == MetadataStore::MutationStatus::Applied,
                "typed restoration stages the same symbolic link as a directory")) return false;
        unsigned interruptions = 0;
        reopened.SetCommitStageHook([&](std::string_view stage) {
            if (stage != "before-apple-publish") return true;
            ++interruptions;
            return false;
        });
        if (!Require(reopened.CommitPendingMutations() == MetadataStore::CommitStatus::PersistFailed &&
                interruptions == 1 && reopened.PendingMutationCount() == 1 &&
                reopened.Device().Read(0, bytes.size(), after_restore) && after_restore == before_restore &&
                reopened.LookupCommittedInodeByPath(request.path)->node_type == MetadataStore::NodeType::SymbolicLink,
                "restoration interruption preserves link and pending mutation")) return false;
        reopened.SetCommitStageHook({});
        if (!Require(reopened.CommitPendingMutations() == MetadataStore::CommitStatus::Committed,
                "restoration retry commits")) return false;
        MetadataStore independent(context);
        if (!Require(independent.PrepareNativeWritePath(), "restored directory reopens independently")) return false;
        const auto directory = independent.LookupCommittedInodeByPath(request.path);
        if (!Require(directory && directory->object_id == 23 && directory->private_id == 23 &&
                directory->node_type == MetadataStore::NodeType::Directory && directory->is_directory &&
                directory->symlink_target_utf8.empty() && directory->logical_size == 0 &&
                directory->data_physical_address == 0 && directory->directory_entry_count == 0,
                "restoration retains empty directory identity and zero storage")) return false;
        restored = true;
        ok &= check_raw("empty", true);
        request.generation = independent.LastCommittedXid().value() + 1;
        ok &= Require(independent.StageMutation(request) != MetadataStore::MutationStatus::Applied &&
            independent.PendingMutationCount() == 0,
            "restoration cannot be applied again to a directory");
    }
    request = {}; request.operation = MetadataStore::MutationOperation::Rename;
    request.path = L"\\empty"; request.secondary_path = L"\\renamed"; request.object_id = 23;
    request.generation = reopened.LastCommittedXid().value() + 1;
    if (!Require(reopened.StageMutation(request) == MetadataStore::MutationStatus::Applied &&
            reopened.CommitPendingMutations() == MetadataStore::CommitStatus::Committed, "directory link rename commits")) return false;
    ok &= check_raw("renamed", true);
    request = {}; request.operation = MetadataStore::MutationOperation::Delete;
    request.path = L"\\renamed"; request.object_id = 23;
    request.generation = reopened.LookupCommittedInodeByPath(L"\\renamed")->xid;
    if (!Require(reopened.StageMutation(request) == MetadataStore::MutationStatus::Applied &&
            reopened.CommitPendingMutations() == MetadataStore::CommitStatus::Committed, "directory link unlink commits")) return false;
    ok &= check_raw("renamed", false);
    MetadataStore final(context);
    ok &= Require(final.PrepareNativeWritePath() && !final.LookupCommittedInodeByPath(L"\\empty") &&
        !final.LookupCommittedInodeByPath(L"\\renamed") && final.LookupCommittedInodeByPath(L"\\target"),
        "unlink reopens without removing the target");
    return ok;
}

bool TestDirectorySymbolicLinkConversionRejectsUnsafeState(bool restore = false)
{
    using namespace apfsaccess::rw;
    bool ok = true;
    for (const auto* scenario : {"root", "child", "pending-child", "identity", "directory-stats",
            "mounted-uuid", "unknown-field", "maintain-stats", "stats-origin", "directory-dstream",
            "external-xattr", "extent", "pending-fork"})
    {
        const std::string label = scenario;
        if (restore && (label == "root" || label == "child" || label == "pending-child")) continue;
        if (!restore && (label == "external-xattr" || label == "extent" || label == "pending-fork")) continue;
        BuilderStore fixture;
        fixture.authoritative_checkpoint = true; fixture.volumes[0].incompat = 0;
        auto& records = fixture.volumes[0].filesystem_records;
        std::string error;
        apfsaccess::catalog::BtreeRecord encoded;
        for (const auto id : {2ULL, 23ULL})
        {
            AppleInodeRecord inode;
            inode.object_id = inode.private_id = id; inode.parent_id = 2; inode.mode = 0040755;
            inode.children_or_links = id == 2 ? 1 : 0;
            if (restore && id == 23)
            {
                inode.mode = 0120755; inode.children_or_links = 1;
                inode.uncompressed_size = 3; // Embedded target "./x" is three bytes.
            }
            if (id == 23 && (label == "maintain-stats" || label == "stats-origin"))
                inode.internal_flags = label == "maintain-stats" ? 0x2 : 0x4;
            if (id == 23 && (label == "directory-stats" || label == "mounted-uuid" ||
                    label == "unknown-field" || label == "directory-dstream"))
            {
                AppleExtendedField field;
                field.type = label == "directory-stats" ? 10 : label == "mounted-uuid" ? 11 :
                    label == "directory-dstream" ? 8 : 0xfe;
                field.data.assign(label == "mounted-uuid" ? 16 : label == "directory-dstream" ? 40 : 8, std::byte{0});
                if (label != "directory-dstream") PutU64LE(field.data, 0, 23);
                inode.extended_fields.push_back(field);
            }
            if (!Require(EncodeAppleInodeRecord(inode, encoded, error), label + " inode encodes")) return false;
            records.push_back(encoded);
        }
        AppleDirectoryRecord drec;
        drec.parent_id = 2; drec.file_id = 23; drec.flags = 4; drec.name_utf8 = "empty";
        if (restore) drec.flags = 10;
        if (!Require(EncodeAppleDirectoryRecord(drec, encoded, error), label + " DREC encodes")) return false;
        records.push_back(encoded);
        if (restore)
        {
            AppleXattrRecord target{23, "com.apple.fs.symlink", kAppleXattrDataEmbedded,
                {std::byte{'.'}, std::byte{'/'}, std::byte{'x'}}};
            if (!Require(EncodeAppleXattrRecord(target, encoded, error), label + " target encodes")) return false;
            records.push_back(encoded);
            if (label == "external-xattr")
            {
                std::vector<std::byte> descriptor(kAppleXattrDataStreamBytes, std::byte{0});
                PutU64LE(descriptor, 0, 777);
                AppleXattrRecord external{23, "user.external", kAppleXattrDataStream, descriptor};
                if (!Require(EncodeAppleXattrRecord(external, encoded, error), "external attribute encodes")) return false;
                records.push_back(encoded);
                if (!Require(EncodeAppleDataStreamIdRecord({777, 1}, encoded, error), "external stream encodes")) return false;
                records.push_back(encoded);
            }
            if (label == "extent")
            {
                if (!Require(EncodeAppleFileExtentRecord({23, 0, 4096, 52, 0, 4096}, encoded, error),
                        "symlink extent encodes")) return false;
                records.push_back(encoded);
            }
        }
        const auto image_bytes = BuildStoreImage(fixture);
        TempImageFile image(image_bytes, "unsafe-directory-link", ".raw");
        MetadataStore::VolumeContext context;
        context.device_path = image.path.wstring(); context.volume_object_id = 101;
        context.allow_legacy_scaffold_for_fixtures = false;
        MetadataStore metadata(context);
        if (!metadata.PrepareNativeWritePath())
        {
            const auto reason = metadata.RecoveryReason();
            if (!Require(restore && (label == "extent" || label == "external-xattr" || label == "directory-dstream"),
                    label + " only storage-bearing malformed imports may reject before staging: " +
                        std::string(reason.begin(), reason.end()))) return false;
            std::wcerr << L"[INFO] expected unsafe import refusal: " << reason << std::endl;
            apfsaccess::catalog::HeldFileSource source(image.path.string());
            std::vector<std::byte> unchanged;
            if (!Require(metadata.PendingMutationCount() == 0 &&
                    source.Read(0, image_bytes.size(), unchanged) && unchanged == image_bytes,
                    label + " rejected import leaves image unchanged")) return false;
            continue;
        }
        MetadataStore::MutationRequest request;
        if (label == "pending-fork")
        {
            request.operation = MetadataStore::MutationOperation::SetExtendedAttribute;
            request.path = L"\\empty"; request.secondary_path = L"com.apple.ResourceFork";
            request.inline_payload = {std::byte{0x51}}; request.length = 1;
            if (!Require(metadata.StageMutation(request) == MetadataStore::MutationStatus::UnsupportedOperation &&
                    metadata.PendingMutationCount() == 0 &&
                    !metadata.LookupWorkingExtendedAttribute(23, "com.apple.ResourceFork"),
                    "symlink ResourceFork creation refuses before staging")) return false;
            request.operation = MetadataStore::MutationOperation::RemoveExtendedAttribute;
            request.inline_payload.clear(); request.length = 0;
            std::vector<std::byte> unchanged;
            if (!Require(metadata.StageMutation(request) == MetadataStore::MutationStatus::UnsupportedOperation &&
                    metadata.PendingMutationCount() == 0 &&
                    metadata.Device().Read(0, image_bytes.size(), unchanged) && unchanged == image_bytes,
                    "symlink fork removal refuses without changing the image")) return false;
            continue;
        }
        if (label == "child" || label == "pending-child")
        {
            request.operation = MetadataStore::MutationOperation::CreateFile; request.path = L"\\empty\\child";
            if (!Require(metadata.StageMutation(request) == MetadataStore::MutationStatus::Applied,
                    label + " child premise stages")) return false;
            if (label == "child" && !Require(metadata.CommitPendingMutations() == MetadataStore::CommitStatus::Committed,
                    "nonempty directory premise commits")) return false;
        }
        const auto pending = metadata.PendingMutationCount();
        std::vector<std::byte> before, after;
        const auto size = static_cast<std::size_t>(std::filesystem::file_size(image.path));
        if (!Require(metadata.Device().Read(0, size, before), label + " image snapshot reads")) return false;
        request = {}; request.operation = MetadataStore::MutationOperation::SetSymbolicLinkTarget;
        if (restore) request.operation = MetadataStore::MutationOperation::RestoreDirectoryFromSymbolicLink;
        request.path = label == "root" ? L"\\" : L"\\empty";
        request.object_id = label == "root" ? 2 : label == "identity" ? 24 : 23;
        request.generation = metadata.LastCommittedXid().value() + 1;
        if (!restore) request.secondary_path = L"../target";
        ok &= Require(metadata.StageMutation(request) != MetadataStore::MutationStatus::Applied &&
            metadata.LastMutationFailureReason() == (restore ? (label == "identity"
                ? L"ReplayDirectoryRestoreIdentityMismatch" : L"DirectoryRestoreUnsafeMetadata") : (label == "identity"
                ? L"ReplaySetSymbolicLinkTargetIdentityMismatch" : L"SetSymbolicLinkTargetUnsafeDirectory")) &&
            metadata.PendingMutationCount() == pending && metadata.Device().Read(0, size, after) && before == after,
            label + " conversion refuses without staging or publication");
        const auto directory = metadata.LookupWorkingInodeByPath(request.path);
        ok &= Require(directory && directory->object_id == request.object_id - (label == "identity" ? 1 : 0) &&
            (restore ? directory->node_type == MetadataStore::NodeType::SymbolicLink &&
                directory->symlink_target_utf8 == "./x" : directory->is_directory && directory->symlink_target_utf8.empty()),
            label + " rejected transition preserves inode identity and kind");
        if (label == "child" || label == "pending-child")
            ok &= Require(metadata.LookupWorkingInodeByPath(L"\\empty\\child").has_value(),
                label + " rejection preserves child");
    }
    return ok;
}

bool TestDirectorySymbolicLinkPendingTransitions(const std::string& restore_scenario = {})
{
    using namespace apfsaccess::rw;
    bool ok = true;
    for (const auto* scenario : {"replacement", "fresh", "last-child", "resource-fork",
            "set-restore", "restore-child", "rename-restore-set-rename"})
    {
        const std::string label = scenario;
        const bool restoring = label == "set-restore" || label == "restore-child" || label == "rename-restore-set-rename";
        if (restore_scenario.empty() ? restoring : label != restore_scenario) continue;
        BuilderStore fixture;
        fixture.authoritative_checkpoint = true; fixture.volumes[0].incompat = 0;
        auto& records = fixture.volumes[0].filesystem_records;
        std::string error;
        apfsaccess::catalog::BtreeRecord encoded;
        for (const auto id : {2ULL, 23ULL})
        {
            if (id == 23 && label == "fresh") continue;
            AppleInodeRecord inode;
            inode.object_id = inode.private_id = id; inode.parent_id = 2; inode.mode = 0040755;
            inode.children_or_links = id == 2 && label != "fresh" ? 1 : 0;
            if (id == 23 && restoring && label != "set-restore")
            {
                inode.mode = 0120755; inode.children_or_links = 1;
                inode.uncompressed_size = 3; // Embedded target "./x" is three bytes.
            }
            if (id == 23 && label == "replacement")
            {
                AppleExtendedField mounted_uuid;
                mounted_uuid.type = 11; mounted_uuid.data.assign(16, std::byte{0x31});
                inode.extended_fields.push_back(mounted_uuid);
            }
            if (!Require(EncodeAppleInodeRecord(inode, encoded, error), label + " transition inode encodes")) return false;
            records.push_back(encoded);
            if (id == 2) continue;
            AppleDirectoryRecord drec;
            drec.parent_id = 2; drec.file_id = 23; drec.flags = 4; drec.name_utf8 = "dir";
            if (restoring && label != "set-restore") drec.flags = 10;
            if (!Require(EncodeAppleDirectoryRecord(drec, encoded, error), label + " transition DREC encodes")) return false;
            records.push_back(encoded);
            if (restoring && label != "set-restore")
            {
                AppleXattrRecord target{23, "com.apple.fs.symlink", kAppleXattrDataEmbedded,
                    {std::byte{'.'}, std::byte{'/'}, std::byte{'x'}}};
                if (!Require(EncodeAppleXattrRecord(target, encoded, error), "pending restore target encodes")) return false;
                records.push_back(encoded);
            }
        }
        TempImageFile image(BuildStoreImage(fixture), "directory-link-transitions", ".raw");
        MetadataStore::VolumeContext context;
        context.device_path = image.path.wstring(); context.volume_object_id = 101;
        context.allow_legacy_scaffold_for_fixtures = false;
        MetadataStore metadata(context);
        const bool prepared = metadata.PrepareNativeWritePath();
        const auto prepare_reason = metadata.RecoveryReason();
        if (!Require(prepared, label + " transition premise prepares: " +
                std::string(prepare_reason.begin(), prepare_reason.end()))) return false;
        MetadataStore::MutationRequest request;
        if (restoring)
        {
            using Op = MetadataStore::MutationOperation;
            std::size_t staged = 0;
            const auto stage = [&](Op operation, const std::wstring& path, const std::wstring& secondary = L"")
            {
                MetadataStore::MutationRequest mutation;
                mutation.operation = operation; mutation.path = path; mutation.secondary_path = secondary;
                if (operation != Op::CreateFile)
                {
                    mutation.object_id = 23; mutation.generation = metadata.LastCommittedXid().value() + 1;
                }
                return Require(metadata.StageMutation(mutation) == MetadataStore::MutationStatus::Applied &&
                    metadata.PendingMutationCount() == ++staged, label + " ordered mutation remains queued");
            };
            if (label == "set-restore" && !stage(Op::SetSymbolicLinkTarget, L"\\dir", L"./x")) return false;
            if (label == "rename-restore-set-rename" && !stage(Op::Rename, L"\\dir", L"\\b")) return false;
            const auto restored_path = label == "rename-restore-set-rename" ? L"\\b" : L"\\dir";
            if (!stage(Op::RestoreDirectoryFromSymbolicLink, restored_path)) return false;
            const auto restored = metadata.LookupWorkingInodeByPath(restored_path);
            if (!Require(restored && restored->object_id == 23 && restored->is_directory &&
                    !metadata.PendingMutationsCanDelayClose() && !metadata.PendingMutationsCanContinueDeferredClose(),
                    label + " restoration is visible in order and refuses deferred close")) return false;
            if (label == "restore-child" && !stage(Op::CreateFile, L"\\dir\\child")) return false;
            if (label == "rename-restore-set-rename" &&
                (!stage(Op::SetSymbolicLinkTarget, L"\\b", L"./x") || !stage(Op::Rename, L"\\b", L"\\c"))) return false;
            if (!Require(!metadata.PendingMutationsCanDelayClose() && !metadata.PendingMutationsCanContinueDeferredClose() &&
                    metadata.CommitPendingMutations() == MetadataStore::CommitStatus::Committed,
                    label + " ordered batch commits without close deferral")) return false;
            MetadataStore reopened(context);
            if (!Require(reopened.PrepareNativeWritePath(), label + " ordered batch reopens")) return false;
            const bool final_link = label == "rename-restore-set-rename";
            const auto final = reopened.LookupCommittedInodeByPath(final_link ? L"\\c" : L"\\dir");
            ok &= Require(final && final->object_id == 23 && final->private_id == 23 &&
                final->node_type == (final_link ? MetadataStore::NodeType::SymbolicLink : MetadataStore::NodeType::Directory) &&
                final->symlink_target_utf8 == (final_link ? "./x" : "") &&
                !reopened.LookupCommittedInodeByPath(L"\\b") &&
                (!final_link || !reopened.LookupCommittedInodeByPath(L"\\dir")) &&
                reopened.LookupCommittedInodeByPath(L"\\dir\\child").has_value() == (label == "restore-child"),
                label + " reopened type identity and namespace preserve batch ordering");
            continue;
        }
        if (label == "replacement" || label == "fresh")
        {
            if (label == "replacement")
            {
                const auto original = metadata.LookupCommittedInodeByPath(L"\\dir");
                if (!Require(original && original->object_id == 23 && original->is_directory &&
                        !original->directory_symlink_metadata_safe,
                        "replacement starts from reader-proven unsafe committed directory")) return false;
            }
            request.operation = MetadataStore::MutationOperation::CreateDirectory;
            request.path = L"\\dir"; request.replace_if_exists = label == "replacement";
            if (!Require(metadata.StageMutation(request) == MetadataStore::MutationStatus::Applied,
                    label + " directory creation stages")) return false;
        }
        if (label == "last-child")
        {
            request.operation = MetadataStore::MutationOperation::CreateFile; request.path = L"\\dir\\child";
            if (!Require(metadata.StageMutation(request) == MetadataStore::MutationStatus::Applied &&
                    metadata.CommitPendingMutations() == MetadataStore::CommitStatus::Committed &&
                    metadata.LookupCommittedInodeByPath(request.path).has_value(),
                    "last-child premise commits a nonempty directory")) return false;
            request = {}; request.operation = MetadataStore::MutationOperation::Delete; request.path = L"\\dir\\child";
            if (!Require(metadata.StageMutation(request) == MetadataStore::MutationStatus::Applied &&
                    !metadata.LookupWorkingInodeByPath(request.path) && metadata.LookupCommittedInodeByPath(request.path),
                    "last child is absent only from working namespace")) return false;
        }
        const auto directory = metadata.LookupWorkingInodeByPath(L"\\dir");
        if (!Require(directory && directory->is_directory &&
                (label != "replacement" || directory->object_id == 23),
                label + " working directory retains expected identity")) return false;
        MetadataStore::MutationRequest set;
        set.operation = MetadataStore::MutationOperation::SetSymbolicLinkTarget;
        set.path = L"\\dir"; set.secondary_path = L"../target";
        if (label == "resource-fork")
        {
            if (!Require(!metadata.LookupCommittedExtendedAttribute(directory->object_id, "com.apple.ResourceFork"),
                    "resource-fork premise has no committed protected attribute")) return false;
            request = {}; request.operation = MetadataStore::MutationOperation::SetExtendedAttribute;
            request.path = set.path; request.secondary_path = L"com.apple.ResourceFork";
            request.inline_payload = {std::byte{0x51}}; request.length = request.inline_payload.size();
            const auto pending = metadata.PendingMutationCount();
            if (!Require(metadata.StageMutation(request) == MetadataStore::MutationStatus::UnsupportedOperation &&
                    metadata.PendingMutationCount() == pending &&
                    !metadata.LookupWorkingExtendedAttribute(directory->object_id, "com.apple.ResourceFork"),
                    "directory ResourceFork creation refuses without a pending value")) return false;
            request.operation = MetadataStore::MutationOperation::RemoveExtendedAttribute;
            request.inline_payload.clear(); request.length = 0;
            if (!Require(metadata.StageMutation(request) == MetadataStore::MutationStatus::UnsupportedOperation &&
                    metadata.PendingMutationCount() == pending,
                    "directory ResourceFork removal also refuses before staging")) return false;
        }
        if (label == "replacement")
        {
            std::vector<std::byte> before, after;
            const auto size = static_cast<std::size_t>(std::filesystem::file_size(image.path));
            if (!Require(metadata.Device().Read(0, size, before), label + " rejection snapshot reads")) return false;
            const auto pending = metadata.PendingMutationCount();
            ok &= Require(metadata.StageMutation(set) != MetadataStore::MutationStatus::Applied &&
                metadata.LastMutationFailureReason() == L"SetSymbolicLinkTargetUnsafeDirectory" &&
                metadata.PendingMutationCount() == pending && metadata.Device().Read(0, size, after) && before == after,
                label + " SET rejects exact UnsafeDirectory without changing pending count or image");
            const auto unchanged = metadata.LookupWorkingInodeByPath(set.path);
            ok &= Require(unchanged && unchanged->object_id == directory->object_id && unchanged->is_directory &&
                unchanged->symlink_target_utf8.empty(), label + " refusal preserves working directory");
            continue;
        }
        if (!Require(metadata.StageMutation(set) == MetadataStore::MutationStatus::Applied &&
                metadata.CommitPendingMutations() == MetadataStore::CommitStatus::Committed,
                label + " same-batch directory conversion commits")) return false;
        MetadataStore reopened(context);
        if (!Require(reopened.PrepareNativeWritePath(), label + " transition reopens")) return false;
        const auto link = reopened.LookupCommittedInodeByPath(set.path);
        ok &= Require(link && link->object_id == directory->object_id && !link->is_directory &&
            link->node_type == MetadataStore::NodeType::SymbolicLink && link->symlink_target_utf8 == "../target" &&
            !reopened.LookupCommittedInodeByPath(L"\\dir\\child") &&
            !reopened.LookupCommittedExtendedAttribute(directory->object_id, "com.apple.ResourceFork"),
            label + " reopen retains link identity and target without deleted child or resource fork");
    }
    return ok;
}

constexpr std::uint32_t kExternalXattrBlockSize = 4096;
constexpr std::uint64_t kExternalXattrStreamId = 777;
constexpr std::uint64_t kEmptyExternalXattrStreamId = 778;
constexpr std::uint64_t kExternalXattrFirstBlock = 52;
constexpr std::uint64_t kExternalXattrSecondBlock = 55;

struct ExternalXattrFixtureSpec
{
    std::uint64_t block_count = 64;
    std::string attribute_name = "user.external";
    std::uint32_t owner_bsd_flags = 0;
    std::uint64_t owner_logical_size = 0;
    bool owner_decmpfs = false;
    std::uint64_t attribute_owner_inode = 2;
    bool share_external_with_root = false;
    bool second_file_alias = false;
    std::uint64_t logical_size = 5000;
    std::uint64_t allocated_size = 2 * kExternalXattrBlockSize;
    std::uint64_t descriptor_crypto_id = 0;
    bool truncate_descriptor = false;
    bool include_stream_reference = true;
    std::uint32_t stream_reference_count = 1;
    bool high_extent_length_flags = false;
    bool duplicate_extent_record = false;
    bool add_private_id_alias = false;
    bool include_embedded_and_empty = false;
    std::uint64_t high_inode_id = 0;
    std::vector<apfsaccess::rw::AppleFileExtentRecord> extents{
        {kExternalXattrStreamId, 0, kExternalXattrBlockSize,
            kExternalXattrFirstBlock, 0, kExternalXattrBlockSize},
        {kExternalXattrStreamId, kExternalXattrBlockSize,
            kExternalXattrBlockSize, kExternalXattrSecondBlock, 0,
            kExternalXattrBlockSize},
    };
    std::vector<apfsaccess::rw::ApplePhysicalExtentRecord> physical_extents{
        {kExternalXattrFirstBlock, 1,
            apfsaccess::rw::kApplePhysicalExtentKindNew,
            kExternalXattrStreamId, 1},
        {kExternalXattrSecondBlock, 1,
            apfsaccess::rw::kApplePhysicalExtentKindNew,
            kExternalXattrStreamId, 1},
    };
};

std::vector<std::byte> ExternalXattrPayloadBlock(unsigned int multiplier, unsigned int addend)
{
    std::vector<std::byte> payload(kExternalXattrBlockSize);
    for (std::size_t index = 0; index < payload.size(); ++index)
    {
        payload[index] = static_cast<std::byte>((index * multiplier + addend) & 0xffu);
    }
    return payload;
}

std::vector<std::byte> BuildExternalXattrRangeImage(
    const ExternalXattrFixtureSpec& spec,
    std::vector<std::byte>& out_descriptor)
{
    using namespace apfsaccess::rw;
    BuilderStore store;
    store.authoritative_checkpoint = true;
    store.block_count = spec.block_count;
    store.volumes[0].incompat = 0;
    auto& volume = store.volumes[0];
    std::string error;
    const auto append = [&](bool encoded,
                            apfsaccess::catalog::BtreeRecord& record,
                            const std::string& message)
    {
        if (!Require(encoded, message + ": " + error)) return false;
        volume.filesystem_records.push_back(std::move(record));
        return true;
    };

    AppleInodeRecord root;
    root.object_id = 2;
    root.parent_id = 2;
    root.private_id = 2;
    root.children_or_links = spec.add_private_id_alias || spec.high_inode_id != 0
        ? (spec.second_file_alias ? 2 : 1) : 0;
    root.mode = 0040755;
    apfsaccess::catalog::BtreeRecord encoded;
    if (!append(EncodeAppleInodeRecord(root, encoded, error), encoded,
            "external xattr root inode encodes")) return {};

    if (spec.add_private_id_alias || spec.high_inode_id != 0)
    {
        AppleInodeRecord alias;
        alias.object_id = spec.high_inode_id == 0 ? 17 : spec.high_inode_id;
        alias.parent_id = 2;
        alias.private_id = spec.add_private_id_alias ? kExternalXattrStreamId : alias.object_id;
        alias.children_or_links = spec.second_file_alias ? 2 : 1;
        alias.mode = 0100644;
        alias.uncompressed_size = spec.owner_logical_size;
        if (alias.object_id == spec.attribute_owner_inode) alias.bsd_flags = spec.owner_bsd_flags;
        encoded = {};
        if (!append(EncodeAppleInodeRecord(alias, encoded, error), encoded,
                "external xattr private-ID alias inode encodes")) return {};
        AppleDirectoryRecord link;
        link.parent_id = 2;
        link.file_id = alias.object_id;
        link.flags = 8;
        link.name_utf8 = "alias.bin";
        encoded = {};
        if (!append(EncodeAppleDirectoryRecord(link, encoded, error), encoded,
                "external xattr private-ID alias link encodes")) return {};
        if (spec.second_file_alias)
        {
            link.name_utf8 = "second.bin";
            if (!append(EncodeAppleDirectoryRecord(link, encoded, error), encoded,
                    "external owner second link encodes")) return {};
            for (const auto& [name, sibling] :
                {std::pair{"alias.bin", 700ULL}, std::pair{"second.bin", 701ULL}})
            {
                if (!append(EncodeAppleSiblingLinkRecord({alias.object_id, sibling, 2, name}, encoded, error),
                        encoded, "external owner sibling link encodes") ||
                    !append(EncodeAppleSiblingMapRecord({sibling, alias.object_id}, encoded, error),
                        encoded, "external owner sibling map encodes")) return {};
            }
        }
    }

    out_descriptor.assign(kAppleXattrDataStreamBytes, std::byte{0});
    PutU64LE(out_descriptor, 0, kExternalXattrStreamId);
    PutU64LE(out_descriptor, 8, spec.logical_size);
    PutU64LE(out_descriptor, 16, spec.allocated_size);
    PutU64LE(out_descriptor, 24, spec.descriptor_crypto_id);
    PutU64LE(out_descriptor, 32, spec.logical_size);
    PutU64LE(out_descriptor, 40, 0);
    AppleXattrRecord external{spec.attribute_owner_inode, spec.attribute_name, kAppleXattrDataStream,
        out_descriptor};
    encoded = {};
    if (!EncodeAppleXattrRecord(external, encoded, error))
    {
        Require(false, "external xattr descriptor encodes: " + error);
        return {};
    }
    if (spec.truncate_descriptor)
    {
        encoded.value.pop_back();
        out_descriptor.pop_back();
    }
    if (!append(true, encoded, "external xattr descriptor appends")) return {};
    if (spec.owner_decmpfs)
    {
        AppleXattrRecord marker{spec.attribute_owner_inode, "com.apple.decmpfs", kAppleXattrDataEmbedded, {}};
        if (!append(EncodeAppleXattrRecord(marker, encoded, error), encoded,
                "opaque compression marker encodes")) return {};
    }

    if (spec.share_external_with_root)
    {
        auto shared = external;
        shared.object_id = 2;
        shared.name_utf8 = "user.shared-external";
        if (!append(EncodeAppleXattrRecord(shared, encoded, error), encoded,
                "shared external xattr descriptor encodes")) return {};
    }

    if (spec.include_stream_reference)
    {
        encoded = {};
        if (!append(EncodeAppleDataStreamIdRecord(
                {kExternalXattrStreamId, spec.stream_reference_count},
                encoded, error), encoded,
                "external xattr dstream reference encodes")) return {};
    }
    for (std::size_t index = 0; index < spec.extents.size(); ++index)
    {
        encoded = {};
        if (!EncodeAppleFileExtentRecord(spec.extents[index], encoded, error))
        {
            Require(false, "external xattr file extent encodes: " + error);
            return {};
        }
        if (spec.high_extent_length_flags && index == 0)
        {
            PutU64LE(encoded.value, 0,
                spec.extents[index].length_bytes | (1ull << 63));
        }
        volume.filesystem_records.push_back(std::move(encoded));
    }

    if (spec.include_embedded_and_empty)
    {
        AppleXattrRecord embedded{2, "user.embedded", kAppleXattrDataEmbedded,
            {std::byte{0}, std::byte{0xff}, std::byte{0x41},
                std::byte{0}, std::byte{0x80}}};
        encoded = {};
        if (!append(EncodeAppleXattrRecord(embedded, encoded, error), encoded,
                "embedded binary xattr encodes")) return {};
        std::vector<std::byte> empty_descriptor(
            kAppleXattrDataStreamBytes, std::byte{0});
        PutU64LE(empty_descriptor, 0, kEmptyExternalXattrStreamId);
        AppleXattrRecord empty{2, "user.empty-external",
            kAppleXattrDataStream, std::move(empty_descriptor)};
        encoded = {};
        if (!append(EncodeAppleXattrRecord(empty, encoded, error), encoded,
                "empty external xattr encodes")) return {};
        encoded = {};
        if (!append(EncodeAppleDataStreamIdRecord(
                {kEmptyExternalXattrStreamId, 1}, encoded, error), encoded,
                "empty external xattr dstream reference encodes")) return {};
    }

    if (!Require(SortAppleBtreeRecords(volume.filesystem_records,
            AppleBtreeKeyOrder::FileSystemCaseSensitive, error),
            "external xattr filesystem records sort: " + error)) return {};
    if (spec.duplicate_extent_record)
    {
        const auto duplicate = std::find_if(volume.filesystem_records.begin(),
            volume.filesystem_records.end(), [](const auto& record) {
                return record.key.size() == 16 &&
                    (apfsaccess::catalog::ReadU64LE(record.key, 0).value_or(0) >> 60) == 8 &&
                    apfsaccess::catalog::ReadU64LE(record.key, 8).value_or(1) == 0;
            });
        if (!Require(duplicate != volume.filesystem_records.end(),
                "external xattr duplicate extent source exists")) return {};
        const auto duplicate_record = *duplicate;
        volume.filesystem_records.insert(duplicate + 1, duplicate_record);
    }
    for (const auto& extent : spec.physical_extents)
    {
        volume.additional_file_system_allocated_blocks += extent.block_count;
        encoded = {};
        if (!Require(EncodeApplePhysicalExtentRecord(extent, encoded, error),
                "external xattr physical extent encodes: " + error)) return {};
        volume.extentref_records.push_back(std::move(encoded));
    }
    if (!Require(SortAppleBtreeRecords(volume.extentref_records,
            AppleBtreeKeyOrder::PhysicalExtent, error),
            "external xattr extentref records sort: " + error)) return {};

    store.authoritative_seeded_main_blocks = {
        {kExternalXattrFirstBlock, ExternalXattrPayloadBlock(17, 3)},
        {kExternalXattrFirstBlock + 1, ExternalXattrPayloadBlock(19, 5)},
        {kExternalXattrSecondBlock, ExternalXattrPayloadBlock(29, 0x80)},
    };
    return BuildStoreImage(store);
}

bool RequireExternalXattrRead(
    const apfsaccess::rw::MetadataStore& metadata,
    const std::string& name, std::uint64_t offset,
    std::size_t destination_size, const std::vector<std::byte>& expected,
    const std::string& message)
{
    std::vector<std::byte> destination(destination_size, std::byte{0xa5});
    std::size_t bytes_read = static_cast<std::size_t>(-1);
    const bool read = metadata.ReadCommittedExtendedAttributeRange(
        2, name, offset, destination, bytes_read);
    return Require(read && bytes_read == expected.size() &&
            std::equal(expected.begin(), expected.end(), destination.begin()) &&
            std::all_of(destination.begin() +
                    static_cast<std::vector<std::byte>::difference_type>(bytes_read),
                destination.end(), [](std::byte value) {
                    return value == std::byte{0xa5};
                }), message);
}

bool TestCommittedExtendedAttributeRangeReads()
{
    using namespace apfsaccess::rw;
    ExternalXattrFixtureSpec spec;
    spec.include_embedded_and_empty = true;
    std::vector<std::byte> descriptor;
    const auto image_bytes = BuildExternalXattrRangeImage(spec, descriptor);
    if (!Require(!image_bytes.empty(), "external xattr range image builds")) return false;
    TempImageFile image(image_bytes, "external-xattr-ranges", ".raw");
    MetadataStore::VolumeContext context;
    context.device_path = image.path.wstring();
    context.volume_object_id = 101;
    context.allow_legacy_scaffold_for_fixtures = false;
    bool ok = true;
    {
        MetadataStore initial(context);
        if (!Require(initial.LoadContainerSuperblocks() && initial.LoadObjectMap(),
                "external xattr initial projection loads")) return false;
        const auto raw = initial.LookupCommittedExtendedAttribute(2, "user.external");
        ok &= Require(raw && raw->flags == kAppleXattrDataStream &&
            raw->data == descriptor,
            "external xattr initial projection retains the raw descriptor");
    }

    MetadataStore reopened(context);
    if (!Require(reopened.LoadContainerSuperblocks() && reopened.LoadObjectMap(),
            "external xattr fresh reopen loads")) return false;
    const auto first = ExternalXattrPayloadBlock(17, 3);
    const auto second = ExternalXattrPayloadBlock(29, 0x80);
    std::vector<std::byte> crossing(first.end() - 6, first.end());
    crossing.insert(crossing.end(), second.begin(), second.begin() + 14);
    ok &= RequireExternalXattrRead(reopened, "user.external", 4090, 20,
        crossing, "external xattr range crosses a physical discontinuity");
    std::vector<std::byte> short_eof(second.begin() + 900,
        second.begin() + 904);
    ok &= RequireExternalXattrRead(reopened, "user.external", 4996, 16,
        short_eof, "external xattr range stops at logical EOF");
    ok &= RequireExternalXattrRead(reopened, "user.external", 5000, 8, {},
        "external xattr exact EOF succeeds with zero bytes");
    ok &= RequireExternalXattrRead(reopened, "user.embedded", 1, 8,
        {std::byte{0xff}, std::byte{0x41}, std::byte{0}, std::byte{0x80}},
        "embedded binary xattr range preserves zero and high bytes");
    ok &= RequireExternalXattrRead(reopened, "user.empty-external", 0, 8, {},
        "valid empty external xattr reads as an empty stream");
    std::array<std::byte, 4> exact_name_buffer{};
    std::size_t exact_name_bytes = 99;
    ok &= Require(!reopened.ReadCommittedExtendedAttributeRange(
            2, "user.external.extra", 0, exact_name_buffer, exact_name_bytes) &&
            exact_name_bytes == 0,
        "external xattr range lookup requires the exact attribute name");
    return ok;
}

bool TestCommittedExternalAttributeRangeRejectsInvalidStreams()
{
    using namespace apfsaccess::rw;
    enum class Invalidity
    {
        TruncatedDescriptor,
        LogicalExceedsAllocation,
        UnalignedAllocation,
        AllocationExtentMismatch,
        DescriptorCrypto,
        ExtentCrypto,
        MissingStreamReference,
        StreamReferenceMismatch,
        MissingExtent,
        OverlappingExtents,
        DuplicateExtent,
        HighLengthFlags,
        MissingPhysicalReference,
        WrongPhysicalOwner,
        ExtentOutsideSource,
        OrdinaryPrivateIdAlias,
        MetadataBlock,
        FreeBlock,
    };
    struct Case
    {
        Invalidity invalidity;
        const char* tag;
    };
    const Case cases[] = {
        {Invalidity::TruncatedDescriptor, "truncated-descriptor"},
        {Invalidity::LogicalExceedsAllocation, "logical-exceeds-allocation"},
        {Invalidity::UnalignedAllocation, "unaligned-allocation"},
        {Invalidity::AllocationExtentMismatch, "allocation-extent-mismatch"},
        {Invalidity::DescriptorCrypto, "descriptor-crypto"},
        {Invalidity::ExtentCrypto, "extent-crypto"},
        {Invalidity::MissingStreamReference, "missing-dstream-ref"},
        {Invalidity::StreamReferenceMismatch, "dstream-ref-mismatch"},
        {Invalidity::MissingExtent, "missing-extent"},
        {Invalidity::OverlappingExtents, "overlapping-extents"},
        {Invalidity::DuplicateExtent, "duplicate-extent"},
        {Invalidity::HighLengthFlags, "high-length-flags"},
        {Invalidity::MissingPhysicalReference, "missing-physical-ref"},
        {Invalidity::WrongPhysicalOwner, "wrong-physical-owner"},
        {Invalidity::ExtentOutsideSource, "extent-outside-source"},
        {Invalidity::OrdinaryPrivateIdAlias, "ordinary-private-id-alias"},
        {Invalidity::MetadataBlock, "metadata-block"},
        {Invalidity::FreeBlock, "free-block"},
    };

    bool ok = true;
    for (const auto& entry : cases)
    {
        ExternalXattrFixtureSpec spec;
        switch (entry.invalidity)
        {
        case Invalidity::TruncatedDescriptor:
            spec.truncate_descriptor = true;
            break;
        case Invalidity::LogicalExceedsAllocation:
            spec.logical_size = spec.allocated_size + 1;
            break;
        case Invalidity::UnalignedAllocation:
            spec.allocated_size -= 1;
            break;
        case Invalidity::AllocationExtentMismatch:
            spec.allocated_size += kExternalXattrBlockSize;
            break;
        case Invalidity::DescriptorCrypto:
            spec.descriptor_crypto_id = 1;
            break;
        case Invalidity::ExtentCrypto:
            spec.extents[0].crypto_id = 1;
            break;
        case Invalidity::MissingStreamReference:
            spec.include_stream_reference = false;
            break;
        case Invalidity::StreamReferenceMismatch:
            spec.stream_reference_count = 2;
            break;
        case Invalidity::MissingExtent:
            spec.extents.pop_back();
            spec.physical_extents.pop_back();
            break;
        case Invalidity::OverlappingExtents:
            spec.extents[0].length_bytes = 2 * kExternalXattrBlockSize;
            spec.physical_extents[0].block_count = 2;
            spec.extents[1].logical_address = kExternalXattrBlockSize;
            break;
        case Invalidity::DuplicateExtent:
            spec.duplicate_extent_record = true;
            spec.physical_extents[0].reference_count = 2;
            break;
        case Invalidity::HighLengthFlags:
            spec.high_extent_length_flags = true;
            break;
        case Invalidity::MissingPhysicalReference:
            spec.physical_extents.pop_back();
            break;
        case Invalidity::WrongPhysicalOwner:
            spec.physical_extents[0].owning_object_id =
                kExternalXattrStreamId + 1;
            break;
        case Invalidity::ExtentOutsideSource:
            spec.extents[1].physical_block = 64;
            spec.physical_extents[1].physical_block = 64;
            break;
        case Invalidity::OrdinaryPrivateIdAlias:
            spec.add_private_id_alias = true;
            break;
        case Invalidity::MetadataBlock:
        case Invalidity::FreeBlock:
            spec.logical_size = spec.allocated_size = kExternalXattrBlockSize;
            spec.extents.resize(1);
            spec.physical_extents.resize(1);
            spec.extents[0].physical_block = entry.invalidity == Invalidity::MetadataBlock ? 4 : 54;
            spec.physical_extents[0].physical_block = spec.extents[0].physical_block;
            break;
        }

        std::vector<std::byte> descriptor;
        const auto fixture = BuildExternalXattrRangeImage(spec, descriptor);
        if (!Require(!fixture.empty(), std::string(entry.tag) +
                " external xattr fixture builds")) return false;
        TempImageFile image(fixture, entry.tag, ".raw");
        MetadataStore::VolumeContext context;
        context.device_path = image.path.wstring();
        context.volume_object_id = 101;
        context.allow_legacy_scaffold_for_fixtures = false;
        MetadataStore reopened(context);
        const auto container_loaded = reopened.LoadContainerSuperblocks();
        const auto projection_loaded = container_loaded && reopened.LoadObjectMap();
        if (entry.invalidity == Invalidity::TruncatedDescriptor &&
            container_loaded && !projection_loaded)
        {
            continue;
        }
        if (!Require(projection_loaded,
                std::string(entry.tag) + " projection remains readable"))
        {
            return false;
        }
        const auto raw = reopened.LookupCommittedExtendedAttribute(
            2, "user.external");
        std::array<std::byte, 16> destination;
        destination.fill(std::byte{0xa5});
        std::size_t bytes_read = 99;
        const auto read = reopened.ReadCommittedExtendedAttributeRange(
            2, "user.external", 0, destination, bytes_read);
        ok &= Require(raw && raw->flags == kAppleXattrDataStream &&
                raw->data == descriptor && !read && bytes_read == 0 &&
                std::all_of(destination.begin(), destination.end(),
                    [](std::byte value) { return value == std::byte{0xa5}; }),
            std::string(entry.tag) +
                " suppresses range bytes but preserves the raw descriptor");
    }
    return ok;
}

bool TestCreationPreservesExternalAttributeStream()
{
    using namespace apfsaccess::rw;
    ExternalXattrFixtureSpec spec;
    spec.high_inode_id = kExternalXattrStreamId - 1;
    std::vector<std::byte> descriptor;
    TempImageFile image(BuildExternalXattrRangeImage(spec, descriptor), "external-stream-creation", ".raw");
    MetadataStore::VolumeContext context;
    context.device_path = image.path.wstring();
    context.volume_object_id = 101;
    context.allow_legacy_scaffold_for_fixtures = false;
    MetadataStore metadata(context);
    if (!Require(metadata.PrepareNativeWritePath(), "external stream allocation fixture is writable")) return false;
    const auto block = ExternalXattrPayloadBlock(17, 3);
    const std::vector<std::byte> expected(block.begin(), block.begin() + 16);
    bool ok = RequireExternalXattrRead(metadata, "user.external", 0, 16, expected,
        "external data readable before file creation");
    MetadataStore::MutationRequest create;
    create.operation = MetadataStore::MutationOperation::CreateFile;
    create.path = L"\\new.bin";
    if (!Require(metadata.StageMutation(create) == MetadataStore::MutationStatus::Applied,
            "file beside external attribute stages")) return false;
    const auto created = metadata.DebugLookupWorkingInodeByPath(create.path);
    if (!Require(created && created->object_id >= 0x6000 && created->object_id != kExternalXattrStreamId,
            "new inode respects APSB object-ID floor instead of reusing an attribute stream")) return false;
    if (!Require(metadata.CommitPendingMutations() == MetadataStore::CommitStatus::Committed,
            "new file commits without capturing external stream")) return false;
    MetadataStore reopened(context);
    if (!Require(reopened.PrepareNativeWritePath(), "external attribute allocation image reopens")) return false;
    ok &= RequireExternalXattrRead(reopened, "user.external", 0, 16, expected,
        "external data preserved after creating a file and reopening");
    MetadataStore::MutationRequest remove;
    remove.operation = MetadataStore::MutationOperation::Delete;
    remove.path = create.path;
    if (!Require(reopened.StageMutation(remove) == MetadataStore::MutationStatus::Applied &&
            reopened.CommitPendingMutations() == MetadataStore::CommitStatus::Committed,
            "deleting new inode leaves unrelated attribute blocks allocated")) return false;
    MetadataStore final(context);
    if (!Require(final.LoadContainerSuperblocks() && final.LoadObjectMap(),
            "external attribute allocation deletion reopens")) return false;
    return RequireExternalXattrRead(final, "user.external", 0, 16, expected,
        "external data preserved after new file deletion and reopen") && ok;
}

bool TestExternalAttributePartitionOffsets()
{
    using namespace apfsaccess::rw;
    std::vector<std::byte> descriptor;
    const auto store = BuildExternalXattrRangeImage({}, descriptor);
    auto disk = BuildTestImage({});
    apfsaccess::catalog::VectorRandomAccessSource source(disk);
    const auto gpt = apfsaccess::catalog::ParseGpt(source, 0, disk.size());
    if (!Require(gpt && gpt->partitions.size() == 1 && gpt->partitions[0].size_bytes == store.size(),
            "external attribute disk wrapper has the exact partition size")) return false;
    const auto offset = gpt->partitions[0].start_bytes;
    std::copy(store.begin(), store.end(), disk.begin() + offset);
    TempImageFile image(disk, "external-stream-partition-offset", ".raw");
    BlockDevice device(image.path.wstring());
    NativeApfsVolumeProjection projection;
    std::wstring error;
    if (!Require(NativeApfsReader::TryLoadVolumeProjection(device, 101, projection, error),
            "external attributes project from a whole GPT image")) return false;
    const auto extents = projection.attribute_stream_extents.find(kExternalXattrStreamId);
    if (!Require(extents != projection.attribute_stream_extents.end() && extents->second->size() == 2 &&
            extents->second->front().physical_address == offset + kExternalXattrFirstBlock * kExternalXattrBlockSize,
            "whole-disk attribute extents include the partition offset exactly once")) return false;
    std::vector<std::byte> actual;
    const auto first = ExternalXattrPayloadBlock(17, 3);
    bool ok = Require(device.Read(extents->second->front().physical_address, first.size(), actual) && actual == first,
        "whole-disk projected address reads the actual external payload");
    MetadataStore::VolumeContext context;
    context.device_path = image.path.wstring();
    context.device_offset_bytes = offset;
    context.volume_object_id = 101;
    context.allow_legacy_scaffold_for_fixtures = false;
    MetadataStore metadata(context);
    if (!Require(metadata.LoadContainerSuperblocks() && metadata.LoadObjectMap(),
            "partition-offset metadata store loads")) return false;
    const auto second = ExternalXattrPayloadBlock(29, 0x80);
    std::vector<std::byte> expected(first.end() - 6, first.end());
    expected.insert(expected.end(), second.begin(), second.begin() + 14);
    return RequireExternalXattrRead(metadata, "user.external", 4090, 20, expected,
        "base-offset device does not apply the partition offset twice") && ok;
}

bool TestAppleObjectIdFloorBounds()
{
    using namespace apfsaccess::rw;
    bool ok = true;
    for (const std::uint64_t floor : {0ull, 2ull, 3ull, 15ull, 777ull, 0x1000000000000000ull, 0x7000ull})
    {
        std::vector<std::byte> descriptor;
        auto bytes = BuildExternalXattrRangeImage({}, descriptor);
        const auto begin = bytes.begin() + 4 * kExternalXattrBlockSize;
        std::vector<std::byte> apsb(begin, begin + kExternalXattrBlockSize);
        PutU64LE(apsb, 0xB0, floor);
        FletcherForBlock(apsb, apsb.size());
        std::copy(apsb.begin(), apsb.end(), begin);
        TempImageFile image(bytes, "object-id-floor", ".raw");
        MetadataStore::VolumeContext context;
        context.device_path = image.path.wstring();
        context.volume_object_id = 101;
        context.allow_legacy_scaffold_for_fixtures = false;
        MetadataStore metadata(context);
        if (!Require(metadata.PrepareNativeWritePath(), "allocation floor image imports without allocating")) return false;
        const auto* view = metadata.AuthoritativeAppleCheckpointView();
        ok &= Require(view && view->volumes[0].superblock.next_object_id == floor,
            "APSB parser retains the exact volume object-ID floor");
        MetadataStore::MutationRequest create;
        create.operation = MetadataStore::MutationOperation::CreateFile;
        create.path = L"\\floor.bin";
        const auto status = metadata.StageMutation(create);
        const auto staged = metadata.DebugLookupWorkingInodeByPath(create.path);
        if (floor == 0x7000)
            ok &= Require(status == MetadataStore::MutationStatus::Applied && staged && staged->object_id == floor,
                "allocator follows a different authoritative floor");
        else
            ok &= Require(status != MetadataStore::MutationStatus::Applied && !staged && metadata.PendingMutationCount() == 0,
                "invalid or exhausted APFS ID floor cannot wrap to a path hash or low inode ID");
        std::ifstream input(image.path, std::ios::binary);
        const std::vector<char> unchanged((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
        ok &= Require(unchanged.size() == bytes.size() &&
            std::memcmp(unchanged.data(), bytes.data(), bytes.size()) == 0,
            "allocation admission alone changes no image bytes");
    }
    return ok;
}

std::vector<std::byte> BuildFileContentAttributeImage(
    apfsaccess::rw::AppleXattrRecord attribute, std::uint64_t block_count = 64,
    std::uint16_t owner_mode = 0100644, std::uint32_t owner_flags = 0,
    std::optional<std::vector<std::byte>> decmpfs = std::nullopt,
    std::uint64_t logical_size = 0, bool sparse_extent = false)
{
    using namespace apfsaccess::rw;
    BuilderStore fixture;
    fixture.block_count = block_count;
    fixture.authoritative_checkpoint = true;
    fixture.volumes[0].incompat = 0;
    auto& records = fixture.volumes[0].filesystem_records;
    std::string error;
    apfsaccess::catalog::BtreeRecord encoded;
    AppleInodeRecord root;
    root.object_id = root.parent_id = root.private_id = 2;
    root.children_or_links = 1; root.mode = 0040755;
    if (!Require(EncodeAppleInodeRecord(root, encoded, error), "content attribute root encodes")) return {};
    records.push_back(std::move(encoded));
    AppleInodeRecord file;
    file.object_id = file.private_id = 17; file.parent_id = 2;
    file.children_or_links = (owner_mode & 0170000) == 0040000 ? 0 : 1;
    file.mode = owner_mode; file.bsd_flags = owner_flags;
    file.uncompressed_size = logical_size;
    if (logical_size != 0 && (owner_flags & kAppleBsdCompressedFlag) == 0 &&
        attribute.name_utf8 != "com.apple.decmpfs" && !decmpfs)
    {
        AppleExtendedField stream;
        stream.type = 8;
        stream.data.assign(40, std::byte{0});
        PutU64LE(stream.data, 0, logical_size);
        file.extended_fields.push_back(std::move(stream));
    }
    if ((owner_mode & 0170000) == 0120000) file.uncompressed_size = 3;
    if (!Require(EncodeAppleInodeRecord(file, encoded, error), "content attribute inode encodes")) return {};
    records.push_back(std::move(encoded));
    AppleDirectoryRecord link;
    link.parent_id = 2; link.file_id = 17; link.flags = owner_mode >> 12; link.name_utf8 = "original";
    if (!Require(EncodeAppleDirectoryRecord(link, encoded, error), "content attribute link encodes")) return {};
    records.push_back(std::move(encoded));
    attribute.object_id = 17;
    if (sparse_extent)
    {
        if (!Require(EncodeAppleFileExtentRecord({17, 0, 4096, 0, 0, 4096}, encoded, error),
                "content sparse extent encodes")) return {};
        records.push_back(std::move(encoded));
        if (!Require(EncodeAppleDataStreamIdRecord({17, 1}, encoded, error),
                "sparse logical stream reference encodes")) return {};
        records.push_back(std::move(encoded));
    }
    if (!attribute.name_utf8.empty())
    {
        const auto flags = attribute.flags;
        // The writer rejects unknown flags; inject them into an otherwise valid fixture record.
        attribute.flags &= ~0x8000;
        if (!Require(EncodeAppleXattrRecord(attribute, encoded, error), "content attribute encodes")) return {};
        PutU16LE(encoded.value, 0, flags);
        records.push_back(std::move(encoded));
    }
    if (attribute.flags == kAppleXattrDataStream)
    {
        if (!Require(EncodeAppleDataStreamIdRecord({777, 1}, encoded, error), "content attribute stream encodes")) return {};
        records.push_back(std::move(encoded));
    }
    if ((owner_mode & 0170000) == 0120000)
    {
        if (!Require(EncodeAppleXattrRecord({17, "com.apple.fs.symlink", kAppleXattrDataEmbedded,
                {std::byte{'.'}, std::byte{'/'}, std::byte{'x'}}}, encoded, error), "fork fixture symlink encodes")) return {};
        records.push_back(std::move(encoded));
    }
    if (decmpfs)
    {
        if (!Require(EncodeAppleXattrRecord({17, "com.apple.decmpfs", kAppleXattrDataEmbedded, *decmpfs},
                encoded, error), "fork fixture compression marker encodes")) return {};
        records.push_back(std::move(encoded));
    }
    return BuildStoreImage(fixture);
}

// Native-image compression fixtures are writers only. Expected decoded bytes
// and the frozen .NET ZLibStream vectors are independent of the decoder.
std::vector<std::byte> NativeCompressionHex(const std::string& text)
{
    std::vector<std::byte> bytes;
    for (std::size_t at = 0; at < text.size(); at += 2)
        bytes.push_back(static_cast<std::byte>(std::stoul(text.substr(at, 2), nullptr, 16)));
    return bytes;
}

std::vector<std::byte> NativeCompressionAttribute(std::uint32_t type, std::uint64_t size,
    const std::vector<std::byte>& payload = {})
{
    std::vector<std::byte> attribute(16);
    PutU32LE(attribute, 0, 0x636d7066);
    PutU32LE(attribute, 4, type);
    PutU64LE(attribute, 8, size);
    attribute.insert(attribute.end(), payload.begin(), payload.end());
    return attribute;
}

const auto kNativeCompressionHello = NativeCompressionHex("78DACB48CDC9C90700062C0215");
const auto kNativeCompressionA64k = NativeCompressionHex(
    "78DAEDC181000000008020B6FDA516A90A0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006A1E8703D0");

std::vector<std::byte> NativeCompressionResource(const std::vector<std::vector<std::byte>>& blocks)
{
    const auto big = [](auto& bytes, std::size_t at, std::uint32_t value) {
        for (unsigned i = 0; i < 4; ++i) bytes[at + i] = static_cast<std::byte>(value >> (24 - i * 8));
    };
    std::vector<std::byte> fork(0x108 + blocks.size() * 8);
    big(fork, 0, 0x100);
    big(fork, 12, 50);
    PutU32LE(fork, 0x104, static_cast<std::uint32_t>(blocks.size()));
    for (std::size_t i = 0; i < blocks.size(); ++i)
    {
        PutU32LE(fork, 0x108 + 8 * i, static_cast<std::uint32_t>(fork.size() - 0x104));
        PutU32LE(fork, 0x10c + 8 * i, static_cast<std::uint32_t>(blocks[i].size()));
        fork.insert(fork.end(), blocks[i].begin(), blocks[i].end());
    }
    big(fork, 4, static_cast<std::uint32_t>(fork.size()));
    big(fork, 8, static_cast<std::uint32_t>(fork.size() - 0x100));
    big(fork, 0x100, static_cast<std::uint32_t>(fork.size() - 0x104));
    const auto map = NativeCompressionHex(
        "000000000000000000000000000000000000000000000000"
        "001c003200000000636d70660000000a0001ffff000000000000");
    fork.insert(fork.end(), map.begin(), map.end());
    return fork;
}

struct NativeCompressionFixture
{
    std::vector<std::byte> decmpfs;
    std::optional<std::vector<std::byte>> resource;
    std::uint64_t inode_size = 5;
    bool external_decmpfs = false;
    bool external_resource = false;
    bool compressed_flag = true;
    bool uncompressed_size_flag = true;
    bool omit_decmpfs = false;
    bool wrong_reference_count = false;
    bool omit_default_dstream = false;
    bool rewrite_alias_fixture = false;
};

std::vector<std::byte> BuildNativeCompressionImage(const NativeCompressionFixture& spec)
{
    using namespace apfsaccess::rw;
    BuilderStore fixture;
    fixture.block_count = 512;
    fixture.authoritative_checkpoint = true;
    auto& volume = fixture.volumes[0];
    volume.incompat = 0;
    std::string error;
    apfsaccess::catalog::BtreeRecord encoded;
    auto append = [&](bool ok) {
        if (!Require(ok, "native compression fixture encodes: " + error)) return false;
        volume.filesystem_records.push_back(std::move(encoded));
        return true;
    };
    AppleInodeRecord root;
    root.object_id = root.parent_id = root.private_id = 2;
    root.mode = 0040755; root.children_or_links = spec.rewrite_alias_fixture ? 3 : 2;
    if (!append(EncodeAppleInodeRecord(root, encoded, error))) return {};
    for (const bool neighbor : {false, true})
    {
        AppleInodeRecord inode;
        inode.object_id = neighbor ? 18 : 17;
        inode.private_id = neighbor ? 118 : 117;
        inode.parent_id = 2; inode.children_or_links = 1; inode.mode = 0100644;
        inode.uncompressed_size = neighbor ? 4 : spec.inode_size;
        if (!neighbor && spec.uncompressed_size_flag)
            inode.internal_flags |= kAppleInodeHasUncompressedSize;
        inode.bsd_flags = !neighbor && spec.compressed_flag ? kAppleBsdCompressedFlag : 0;
        if (!neighbor && spec.rewrite_alias_fixture)
        { inode.children_or_links = 2; inode.owner = 501; inode.group = 20; inode.mode = 0100640; }
        AppleExtendedField stream;
        stream.type = 8; stream.data.resize(40);
        // The compressed native dstream is zero, even for nonempty content.
        PutU64LE(stream.data, 0, neighbor ? 4 : 0);
        PutU64LE(stream.data, 8, neighbor ? 4096 : 0);
        if (neighbor || !spec.omit_default_dstream)
            inode.extended_fields.push_back(std::move(stream));
        if (!append(EncodeAppleInodeRecord(inode, encoded, error))) return {};
        AppleDirectoryRecord link;
        link.parent_id = 2; link.file_id = inode.object_id; link.flags = 8;
        link.name_utf8 = neighbor ? "neighbor" : "original";
        if (!append(EncodeAppleDirectoryRecord(link, encoded, error))) return {};
    }
    auto payload = [&](std::uint64_t id, const std::vector<std::byte>& bytes, std::uint64_t first) {
        if (!append(EncodeAppleDataStreamIdRecord({id,
                spec.wrong_reference_count && id == 777 ? 2u : 1u}, encoded, error))) return false;
        for (std::size_t at = 0; at < bytes.size(); at += 4096)
        {
            const auto physical = first + (at / 4096) * 2;
            if (!append(EncodeAppleFileExtentRecord({id, at, 4096, physical, 0, 4096}, encoded, error)))
                return false;
            if (!Require(EncodeApplePhysicalExtentRecord({physical, 1, kApplePhysicalExtentKindNew, id, 1},
                    encoded, error), "native compression physical ownership encodes")) return false;
            volume.extentref_records.push_back(std::move(encoded));
            ++volume.additional_file_system_allocated_blocks;
            std::vector<std::byte> block(4096);
            std::copy_n(bytes.begin() + at, (std::min)(std::size_t{4096}, bytes.size() - at), block.begin());
            fixture.authoritative_seeded_main_blocks.push_back({physical, std::move(block)});
        }
        return true;
    };
    auto attribute = [&](const std::string& name, const auto& bytes, bool external, std::uint64_t id,
                         std::uint64_t physical) {
        AppleXattrRecord raw{17, name, kAppleXattrDataEmbedded, bytes};
        if (external)
        {
            raw.flags = kAppleXattrDataStream;
            raw.data.assign(kAppleXattrDataStreamBytes, std::byte{0});
            PutU64LE(raw.data, 0, id);
            PutU64LE(raw.data, 8, bytes.size());
            PutU64LE(raw.data, 16, ((bytes.size() + 4095) / 4096) * 4096);
            if (!payload(id, bytes, physical)) return false;
        }
        return append(EncodeAppleXattrRecord(raw, encoded, error));
    };
    if (!payload(118, NativeCompressionHex("6e00ff72"), 52)) return {};
    if (!spec.omit_decmpfs && !attribute("com.apple.decmpfs", spec.decmpfs, spec.external_decmpfs, 777, 64)) return {};
    if (spec.resource && !attribute("com.apple.ResourceFork", *spec.resource, spec.external_resource, 778, 80)) return {};
    if (spec.rewrite_alias_fixture)
    {
        AppleDirectoryRecord alias;
        alias.parent_id = 2; alias.file_id = 17; alias.flags = 8; alias.name_utf8 = "alias";
        if (!append(EncodeAppleDirectoryRecord(alias, encoded, error))) return {};
        for (const auto& [name, sibling] : std::vector<std::pair<std::string, std::uint64_t>>{{"original", 700}, {"alias", 701}})
        {
            if (!append(EncodeAppleSiblingLinkRecord({17, sibling, 2, name}, encoded, error)) ||
                !append(EncodeAppleSiblingMapRecord({sibling, 17}, encoded, error))) return {};
        }
        AppleSecurityRecord security;
        std::vector<std::byte> security_bytes;
        if (!Require(ApfsExtendedRecordCodec::EncodeSecurity(security, security_bytes, error), "rewrite ACL encodes") ||
            !attribute("com.apple.FinderInfo", std::vector<std::byte>(32, std::byte{0x35}), false, 0, 0) ||
            !attribute("com.apple.system.Security", security_bytes, false, 0, 0)) return {};
    }
    if (!Require(SortAppleBtreeRecords(volume.filesystem_records, AppleBtreeKeyOrder::FileSystemCaseSensitive, error) &&
            SortAppleBtreeRecords(volume.extentref_records, AppleBtreeKeyOrder::PhysicalExtent, error),
            "native compression records sort")) return {};
    return BuildStoreImage(fixture);
}

apfsaccess::rw::MetadataStore::VolumeContext NativeCompressionContext(const TempImageFile& image)
{
    apfsaccess::rw::MetadataStore::VolumeContext context;
    context.device_path = image.path.wstring(); context.volume_object_id = 101;
    context.allow_legacy_scaffold_for_fixtures = false;
    return context;
}

bool RequireNativeCompressionRange(apfsaccess::rw::MetadataStore& metadata,
    const apfsaccess::rw::MetadataStore::CommittedFileReadPlan& plan, std::uint64_t offset,
    std::size_t requested, const std::vector<std::byte>& expected)
{
    std::vector<std::byte> destination(requested + 7, std::byte{0xa6});
    std::size_t read = 99;
    return Require(metadata.ReadCommittedFileRangeFromPlan(plan, L"\\original", offset, requested,
            destination.data(), destination.size(), read) && read == expected.size() &&
            std::equal(expected.begin(), expected.end(), destination.begin()) &&
            std::all_of(destination.begin() + read, destination.end(), [](auto b) { return b == std::byte{0xa6}; }),
        "native compression exact range and untouched tail");
}

bool TestNativeCompressionRewrite(bool faults = false, bool content_times = false, bool modern = false,
    bool remaining = false)
{
    using namespace apfsaccess::rw;
    const auto types = remaining ? std::vector<unsigned>{9, 10, 13, 14} :
        modern ? std::vector<unsigned>{7, 8, 11, 12} : std::vector<unsigned>{1, 3, 4};
    for (const auto type : types) for (const auto boundary : {0, 1, 2})
    for (const bool times_first : {false, true})
    {
        if (!content_times && times_first) continue;
        if ((!faults && boundary != 0) || (faults && ((!modern && !remaining && type != 4) || boundary == 0))) continue;
        const bool resource_backed = type == 4 || type == 8 || type == 10 || type == 12 || type == 14;
        NativeCompressionFixture spec;
        spec.rewrite_alias_fixture = true;
        const auto payload = type == 1 ? NativeCompressionHex("68656c6c6f") :
            type == 7 || type == 8 ? NativeCompressionHex("e568656c6c6f0600000000000000") :
            type == 9 || type == 10 ? NativeCompressionHex("cc68656c6c6f") :
            type == 13 || type == 14 ? NativeCompressionHex("5a424d090b000005000068656c6c6f060000000000") :
            type == 11 || type == 12 ? NativeCompressionHex("6276782d0500000068656c6c6f62767824") : kNativeCompressionHello;
        spec.decmpfs = NativeCompressionAttribute(type, 5, resource_backed ? std::vector<std::byte>{} : payload);
        spec.resource = type == 4 ? NativeCompressionResource({payload}) : NativeCompressionHex("007f8022");
        if (type == 8 || type == 10 || type == 12 || type == 14)
        {
            spec.resource = std::vector<std::byte>(8);
            PutU32LE(*spec.resource, 0, 8);
            PutU32LE(*spec.resource, 4, static_cast<std::uint32_t>(8 + payload.size()));
            spec.resource->insert(spec.resource->end(), payload.begin(), payload.end());
        }
        spec.external_resource = true; spec.external_decmpfs = resource_backed;
        TempImageFile image(BuildNativeCompressionImage(spec), "native-compression-rewrite");
        const auto context = NativeCompressionContext(image);
        MetadataStore metadata(context);
        if (!Require(metadata.PrepareNativeWritePath(), "rewrite source prepares")) return false;
        const auto before = metadata.LookupCommittedInodeByPath(L"\\original");
        const auto security_before = metadata.LookupCommittedExtendedAttribute(17, "com.apple.system.Security");
        const auto old_xid = metadata.CheckpointXid();
        std::vector<std::byte> source_before;
        {
            apfsaccess::catalog::HeldFileSource source(image.path.string());
            if (!Require(source.Read(0, static_cast<std::size_t>(source.SizeBytes()), source_before), "capture authoritative source image")) return false;
        }
        MetadataStore::MutationRequest conversion;
        if (!Require(before && metadata.PrepareCompressionRewrite(L"\\alias", conversion), "complete source validates before mutation")) return false;
        auto invalid = conversion; ++invalid.generation;
        if (!Require(metadata.StageMutation(invalid) == MetadataStore::MutationStatus::InvalidRequest &&
                metadata.PendingMutationCount() == 0 && metadata.PendingAllocationCount() == 0,
                "stale incarnation refuses without allocation")) return false;
        invalid = conversion; invalid.inline_payload.back() ^= std::byte{1};
        if (!Require(metadata.StageMutation(invalid) == MetadataStore::MutationStatus::InvalidRequest &&
                metadata.PendingMutationCount() == 0, "changed exact representation refuses")) return false;

        // Journal the native request, round-trip it through accepted WAL loading,
        // and construct the staged operation from those durable bytes.
        auto wal_path = image.path; wal_path += L".rewrite.wal";
        TransactionManager transactions(L"Strict");
        transactions.SetJournalPath(wal_path.wstring()); transactions.SetVolumeIdentity(L"compression-rewrite-fixture");
        TransactionManager::MutationIntent intent;
        intent.kind = TransactionManager::MutationKind::RewriteCompressedContent; intent.path = conversion.path;
        intent.object_id = conversion.object_id; intent.generation = conversion.generation;
        intent.inline_payload = conversion.inline_payload; intent.length = intent.payload_length = intent.inline_payload.size();
        std::string error, hex;
        auto digest = apfsaccess::observer::Sha256Stream::Create(error);
        if (!Require(digest && digest->Update(intent.inline_payload.data(), intent.inline_payload.size()) && digest->FinalHex(hex),
                "rewrite evidence hashes")) return false;
        for (std::size_t i = 0; i != intent.payload_checksum.size(); ++i)
            intent.payload_checksum[i] = static_cast<std::uint8_t>(std::stoul(hex.substr(i*2, 2), nullptr, 16));
        if (!Require(transactions.Begin() && transactions.RecordMutation(intent), "conversion prepares in WAL")) return false;
        InodeMetadataPatch times;
        // UpdateWindowsBasicMetadata omits unchanged fields; CB_Write sends
        // both content times. Cover each canonical host mask through WAL.
        times.mask = type == 1 ? InodeMetadataPatch::ModificationTime : type == 3 ? InodeMetadataPatch::ChangeTime :
            InodeMetadataPatch::ModificationTime | InodeMetadataPatch::ChangeTime;
        const auto now = InodeMetadataPatch::UnixEpochTicks + 123456789;
        if (times.mask & InodeMetadataPatch::ModificationTime) times.modification_time_utc = now;
        if (times.mask & InodeMetadataPatch::ChangeTime) times.change_time_utc = now;
        TransactionManager::MutationIntent time_intent;
        time_intent.kind = TransactionManager::MutationKind::SetInodeMetadata; time_intent.path = L"\\alias";
        time_intent.object_id = conversion.object_id; time_intent.generation = *old_xid + 1;
        if (content_times)
        {
            if (!Require(EncodeInodeMetadataPatch(times, time_intent.inline_payload), "canonical host content times encode")) return false;
            time_intent.length = time_intent.payload_length = time_intent.inline_payload.size();
            digest = apfsaccess::observer::Sha256Stream::Create(error);
            if (!Require(digest && digest->Update(time_intent.inline_payload.data(), time_intent.inline_payload.size()) &&
                    digest->FinalHex(hex), "content time WAL evidence hashes")) return false;
            for (std::size_t i = 0; i != time_intent.payload_checksum.size(); ++i)
                time_intent.payload_checksum[i] = static_cast<std::uint8_t>(std::stoul(hex.substr(i*2, 2), nullptr, 16));
            if (times_first && !Require(transactions.RecordMutation(time_intent), "content times journal before write")) return false;
        }
        TransactionManager::MutationIntent edit;
        edit.kind = TransactionManager::MutationKind::Write; edit.path = L"\\original";
        edit.object_id = conversion.object_id; edit.generation = *old_xid+1;
        edit.offset = 1; edit.length = edit.payload_length = 1; edit.inline_payload = {std::byte{0x58}};
        digest = apfsaccess::observer::Sha256Stream::Create(error);
        if (!Require(digest && digest->Update(edit.inline_payload.data(), 1) && digest->FinalHex(hex), "edit hashes")) return false;
        for (std::size_t i = 0; i != edit.payload_checksum.size(); ++i)
            edit.payload_checksum[i] = static_cast<std::uint8_t>(std::stoul(hex.substr(i*2, 2), nullptr, 16));
        if (!Require(transactions.RecordMutation(edit) &&
                (!content_times || times_first || transactions.RecordMutation(time_intent)) && transactions.Accept(*old_xid),
                "conversion, actual edit and optional content times accept together against the original checkpoint")) return false;
        std::vector<TransactionManager::AcceptedTransaction> accepted;
        if (!Require(transactions.LoadUnappliedAcceptedTransactions(accepted) && accepted.size() == 1 &&
                accepted[0].preimage_checkpoint_xid == *old_xid &&
                accepted[0].mutations.size() == (content_times ? 3u : 2u) &&
                MetadataStore::CompressionRewriteFromWal(accepted[0].mutations[0], conversion) &&
                WriteAheadLog::EncodeForTest(accepted[0].mutations[0], 1).empty(),
                "accepted versioned conversion reconstructs and old WAL version refuses")) return false;
        auto malformed = accepted[0].mutations[0]; malformed.parent_object_id = 0;
        if (!Require(WriteAheadLog::EncodeForTest(malformed).empty() &&
                !MetadataStore::CompressionRewriteFromWal(malformed, invalid), "invalid WAL incarnation fails closed")) return false;
        malformed = accepted[0].mutations[0]; malformed.inline_payload.pop_back();
        if (!Require(WriteAheadLog::EncodeForTest(malformed).empty(), "truncated source evidence fails closed")) return false;
        const auto compacted = MutationCompactor::Summarize({
            {MutationCompactor::MutationKind::Write, L"\\alias", {}, 1},
            {MutationCompactor::MutationKind::RewriteCompressedContent, L"\\alias", {}, conversion.length},
            {MutationCompactor::MutationKind::Write, L"\\alias", {}, 1}});
        if (!Require(compacted.compacted_mutation_count == 3, "conversion is a compaction barrier")) return false;
        MetadataStore::PayloadIdentity identity;
        if (!Require(metadata.StageMutation(conversion, &identity) == MetadataStore::MutationStatus::Applied,
                "journaled conversion stages")) return false;
        const auto stage_times = [&] {
            const auto& saved = accepted[0].mutations[times_first ? 1 : 2];
            MetadataStore::MutationRequest request;
            request.operation = MetadataStore::MutationOperation::SetInodeMetadata; request.path = time_intent.path;
            request.object_id = saved.object_id; request.generation = saved.parent_object_id;
            request.inline_payload = saved.inline_payload; request.length = request.inline_payload.size();
            MetadataStore::PayloadIdentity time_identity;
            return Require(saved.operation == WriteAheadLog::OperationKind::SetInodeMetadata &&
                saved.object_id == identity.object_id && saved.parent_object_id == identity.generation &&
                saved.inline_payload == time_intent.inline_payload &&
                metadata.StageMutation(request, &time_identity) == MetadataStore::MutationStatus::Applied &&
                time_identity.object_id == identity.object_id && time_identity.generation == identity.generation,
                "accepted content times stage with the conversion's target identity");
        };
        if (content_times && times_first && !stage_times()) return false;
        const auto expected = NativeCompressionHex("68586c6c6f");
        metadata.SetFilePayloadRangeProvider([&](const auto&, auto owner, auto offset, std::span<std::byte> bytes) {
            if (owner.object_id != identity.object_id || owner.generation != identity.generation ||
                offset > expected.size() || bytes.size() > expected.size()-offset) return false;
            std::copy_n(expected.begin()+offset, bytes.size(), bytes.begin()); return true;
        });
        MetadataStore::MutationRequest write;
        write.operation = MetadataStore::MutationOperation::Write; write.path = L"\\original"; write.offset = 1; write.length = 1;
        if (!Require(metadata.StageMutation(write) == MetadataStore::MutationStatus::Applied,
                "actual partial edit stages in conversion transaction")) return false;
        if (content_times && !times_first && !stage_times()) return false;
        if (content_times)
        {
            MetadataStore::MutationRequest proof;
            if (!Require(metadata.PrepareCompressionRewrite(L"\\original", proof) &&
                    proof.object_id == conversion.object_id && proof.generation == conversion.generation &&
                    proof.inline_payload == conversion.inline_payload,
                    "content times and writes retain the immutable original descriptor and preimage proof")) return false;
        }
        bool reached = false;
        if (boundary) metadata.SetCommitStageHook([&](std::string_view stage) {
            const auto target = boundary == 1 ? "before-apple-checkpoint-switch" : "after-apple-publish";
            if (stage != target) return true; reached = true; return false;
        });
        const auto status = metadata.CommitPendingMutations();
        if (status != MetadataStore::CommitStatus::Committed && !reached)
            std::wcerr << L"Compression rewrite type " << type << L" boundary " << boundary
                << L": " << metadata.LastCommitFailureReason() << L" / "
                << metadata.LastCommitFailureDetail() << L"\n";
        if (!Require(boundary ? status != MetadataStore::CommitStatus::Committed && reached &&
                metadata.IsRecoveryRequired() && metadata.PendingMutationCount() != 0 && transactions.HasUnappliedAcceptedWork() :
                status == MetadataStore::CommitStatus::Committed,
                "publication result and pending/recovery state are truthful")) return false;
        if (boundary)
        {
            apfsaccess::catalog::HeldFileSource source(image.path.string());
            std::vector<std::byte> changed;
            if (!Require(source.Read(0, source_before.size(), changed) && changed != source_before,
                    "failure boundary follows actual source-image writes")) return false;
        }
        MetadataStore reopened(context);
        if (!Require(reopened.PrepareNativeWritePath(), "independent canonical reopen")) return false;
        std::vector<std::byte> bytes;
        const bool old = boundary == 1;
        if (!Require(reopened.CheckpointXid() == (old ? old_xid : std::optional(*old_xid+1)) &&
                reopened.ReadCommittedFileRange(L"\\original", 0, 5, bytes) && bytes == (old ? NativeCompressionHex("68656c6c6f") : expected) &&
                reopened.ReadCommittedFileRange(L"\\alias", 0, 5, bytes) && bytes == (old ? NativeCompressionHex("68656c6c6f") : expected),
                "old/new canonical checkpoint exposes exact bytes through both aliases")) return false;
        const auto after = reopened.LookupCommittedInodeByPath(L"\\alias");
        if (content_times && !Require(after &&
                after->modification_time_utc == (!old && times.modification_time_utc ? now : before->modification_time_utc) &&
                after->change_time_utc == (!old && times.change_time_utc ? now : before->change_time_utc) &&
                after->timestamp_utc == after->modification_time_utc &&
                after->create_time_utc == before->create_time_utc && after->access_time_utc == before->access_time_utc &&
                after->private_id == before->private_id && after->logical_size == before->logical_size &&
                after->allocation_size == (old ? before->allocation_size : std::optional<std::uint64_t>{4096}) &&
                after->bsd_flags == (old ? before->bsd_flags : before->bsd_flags & ~kAppleBsdCompressedFlag),
                "fresh checkpoint publishes exact content times and full EOF allocation while preserving other inode fields")) return false;
        if (!Require(after && after->object_id == before->object_id && after->owner == before->owner &&
                after->group == before->group && after->mode == before->mode && after->link_count == 2 &&
                ((after->bsd_flags & kAppleBsdCompressedFlag) != 0) == old &&
                reopened.LookupCommittedExtendedAttribute(17, "com.apple.decmpfs").has_value() == old &&
                reopened.LookupCommittedExtendedAttribute(17, "com.apple.ResourceFork").has_value() == (old || !resource_backed) &&
                reopened.LookupCommittedExtendedAttribute(17, "com.apple.FinderInfo")->data == std::vector<std::byte>(32, std::byte{0x35}) &&
                security_before && reopened.LookupCommittedExtendedAttribute(17, "com.apple.system.Security")->data == security_before->data,
                "compression ownership changes preserve unrelated Mac metadata")) return false;
        if (!resource_backed)
        {
            std::array<std::byte, 4> fork{}; std::size_t read = 0;
            if (!Require(reopened.ReadCommittedExtendedAttributeRange(17, "com.apple.ResourceFork", 0, fork, read) &&
                    read == 4 && std::equal(fork.begin(), fork.end(), spec.resource->begin()), "independent external fork survives")) return false;
        }
    }
    return true;
}

bool TestNativeCompressionRewriteTimestampRefusals()
{
    using namespace apfsaccess::rw;
    NativeCompressionFixture spec;
    spec.rewrite_alias_fixture = true;
    spec.decmpfs = NativeCompressionAttribute(4, 5);
    spec.resource = NativeCompressionResource({kNativeCompressionHello});
    spec.external_decmpfs = spec.external_resource = true;
    TempImageFile image(BuildNativeCompressionImage(spec), "native-compression-timestamp-refusals");
    const auto context = NativeCompressionContext(image);
    MetadataStore metadata(context);
    if (!Require(metadata.PrepareNativeWritePath(), "timestamp refusal source prepares")) return false;
    MetadataStore::MutationRequest conversion;
    if (!Require(metadata.PrepareCompressionRewrite(L"\\original", conversion), "capture original compression preimage")) return false;
    const auto preimage = metadata.CheckpointXid();
    InodeMetadataPatch times;
    times.mask = InodeMetadataPatch::ModificationTime | InodeMetadataPatch::ChangeTime;
    times.modification_time_utc = times.change_time_utc = InodeMetadataPatch::UnixEpochTicks + 987654321;
    MetadataStore::MutationRequest request;
    request.operation = MetadataStore::MutationOperation::SetInodeMetadata; request.path = L"\\alias";
    if (!Require(EncodeInodeMetadataPatch(times, request.inline_payload), "host timestamp request encodes")) return false;
    request.length = request.inline_payload.size();
    {
        MetadataStore wrong_order(context);
        if (!Require(wrong_order.PrepareNativeWritePath() &&
                wrong_order.StageMutation(request) == MetadataStore::MutationStatus::Applied &&
                wrong_order.StageMutation(conversion) == MetadataStore::MutationStatus::InvalidRequest &&
                wrong_order.PendingMutationCount() == 1 && wrong_order.PendingAllocationCount() == 0,
                "even canonical content times cannot precede conversion")) return false;
    }
    MetadataStore::PayloadIdentity identity;
    if (!Require(metadata.StageMutation(conversion, &identity) == MetadataStore::MutationStatus::Applied,
            "valid conversion stages before refusal probes")) return false;
    const auto staged = metadata.LookupWorkingInodeByPath(L"\\original").value();
    const auto pending = metadata.PendingMutationCount(), allocations = metadata.PendingAllocationCount();
    const auto refuse = [&](const MetadataStore::MutationRequest& invalid, const char* reason) {
        const auto status = metadata.StageMutation(invalid);
        const auto current = metadata.LookupWorkingInodeByPath(L"\\alias");
        return Require(status == MetadataStore::MutationStatus::InvalidRequest &&
            metadata.PendingMutationCount() == pending && metadata.PendingAllocationCount() == allocations &&
            metadata.CheckpointXid() == preimage && current && current->object_id == staged.object_id &&
            current->xid == staged.xid && current->private_id == staged.private_id &&
            current->owner == staged.owner && current->group == staged.group && current->mode == staged.mode &&
            current->bsd_flags == staged.bsd_flags && current->logical_size == staged.logical_size &&
            current->allocation_size == staged.allocation_size && current->link_count == staged.link_count &&
            current->timestamp_utc == staged.timestamp_utc && current->create_time_utc == staged.create_time_utc &&
            current->modification_time_utc == staged.modification_time_utc &&
            current->change_time_utc == staged.change_time_utc && current->access_time_utc == staged.access_time_utc,
            reason);
    };
    for (const auto field : {InodeMetadataPatch::Owner, InodeMetadataPatch::Group, InodeMetadataPatch::Mode,
            InodeMetadataPatch::BsdFlags, InodeMetadataPatch::CreateTime, InodeMetadataPatch::AccessTime})
    {
        auto patch = times; patch.mask |= field;
        if (field == InodeMetadataPatch::Owner) patch.owner = staged.owner + 1;
        if (field == InodeMetadataPatch::Group) patch.group = staged.group + 1;
        if (field == InodeMetadataPatch::Mode) patch.mode = 0600;
        if (field == InodeMetadataPatch::BsdFlags) patch.bsd_flags = staged.bsd_flags | kAppleBsdCompressedFlag;
        if (field == InodeMetadataPatch::CreateTime) patch.create_time_utc = times.modification_time_utc;
        if (field == InodeMetadataPatch::AccessTime) patch.access_time_utc = times.modification_time_utc;
        auto invalid = request;
        if (!Require(EncodeInodeMetadataPatch(patch, invalid.inline_payload), "valid but forbidden mixed metadata encodes")) return false;
        invalid.length = invalid.inline_payload.size();
        if (!refuse(invalid, "content time patch cannot smuggle other inode fields or compression ownership")) return false;
    }
    auto invalid = request; invalid.path = L"\\neighbor";
    if (!refuse(invalid, "another inode's unbound content times refuse")) return false;
    invalid = request; invalid.object_id = 18; invalid.generation = identity.generation;
    if (!refuse(invalid, "foreign timestamp identity cannot use the converted owner's alias")) return false;
    for (const auto generation : {conversion.generation, identity.generation + 1, std::uint64_t{0}})
    {
        invalid = request; invalid.object_id = identity.object_id; invalid.generation = generation;
        if (!refuse(invalid, "source incarnation, future generation and incomplete timestamp identity refuse")) return false;
    }
    invalid = request; invalid.generation = identity.generation;
    if (!refuse(invalid, "generation without timestamp owner refuses")) return false;
    invalid = request; invalid.inline_payload[18] = std::byte{1};
    if (!refuse(invalid, "noncanonical timestamp reserved bytes refuse")) return false;
    invalid = request; invalid.inline_payload[8] = std::byte{1};
    if (!refuse(invalid, "unmasked timestamp owner bytes refuse")) return false;
    for (const auto envelope : {0, 1, 2, 3, 4})
    {
        invalid = request;
        if (envelope == 0) invalid.offset = 1;
        if (envelope == 1) --invalid.length;
        if (envelope == 2) invalid.timestamp_utc = times.modification_time_utc;
        if (envelope == 3) invalid.replace_if_exists = true;
        if (envelope == 4) invalid.secondary_path = L"\\neighbor";
        if (!refuse(invalid, "noncanonical timestamp envelope refuses")) return false;
    }
    for (const auto name : {L"com.apple.decmpfs", L"com.apple.ResourceFork", L"com.apple.FinderInfo"})
    for (const auto operation : {MetadataStore::MutationOperation::SetExtendedAttribute,
            MetadataStore::MutationOperation::RemoveExtendedAttribute})
    {
        invalid = {}; invalid.operation = operation; invalid.path = request.path; invalid.secondary_path = name;
        if (operation == MetadataStore::MutationOperation::SetExtendedAttribute)
        {
            invalid.inline_payload = {std::byte{0x35}}; invalid.length = 1;
        }
        if (!refuse(invalid, "compression-owned and independent xattr changes cannot join conversion")) return false;
    }
    for (const auto operation : {MetadataStore::MutationOperation::SetFileSize, MetadataStore::MutationOperation::SetAllocationSize,
            MetadataStore::MutationOperation::Rename, MetadataStore::MutationOperation::Delete,
            MetadataStore::MutationOperation::SetBasicInfo, MetadataStore::MutationOperation::CreateFile})
    {
        invalid = {}; invalid.operation = operation; invalid.path = request.path; invalid.length = 8192;
        if (operation == MetadataStore::MutationOperation::Rename) invalid.secondary_path = L"\\renamed";
        if (!refuse(invalid, "EOF, allocation and alias changes cannot join conversion")) return false;
    }
    for (const auto kind : {0, 1, 2})
    {
        invalid = {}; invalid.operation = MetadataStore::MutationOperation::Write;
        invalid.path = kind == 0 ? L"\\neighbor" : request.path;
        invalid.offset = kind == 0 ? 0 : kind == 1 ? staged.logical_size : UINT64_MAX; invalid.length = 1;
        if (!refuse(invalid, "timestamps do not authorize foreign, EOF-extending or overflowing writes")) return false;
    }
    if (!refuse(conversion, "a second conversion cannot replace original ownership proof")) return false;
    MetadataStore::MutationRequest proof;
    if (!Require(metadata.PrepareCompressionRewrite(request.path, proof) && proof.inline_payload == conversion.inline_payload &&
            proof.generation == conversion.generation, "refusals preserve exact original compression evidence")) return false;
    MetadataStore reopened(context);
    std::vector<std::byte> bytes;
    if (!Require(reopened.PrepareNativeWritePath() && reopened.CheckpointXid() == preimage &&
            reopened.ReadCommittedFileRange(L"\\original", 0, 5, bytes) && bytes == NativeCompressionHex("68656c6c6f") &&
            reopened.LookupCommittedExtendedAttribute(17, "com.apple.decmpfs").has_value() &&
            reopened.LookupCommittedExtendedAttribute(17, "com.apple.ResourceFork").has_value(),
            "refused metadata publishes neither content nor compression ownership")) return false;
    MetadataStore::PayloadIdentity time_identity;
    return Require(metadata.StageMutation(request, &time_identity) == MetadataStore::MutationStatus::Applied &&
        time_identity.object_id == identity.object_id && time_identity.generation == identity.generation &&
        metadata.LookupWorkingInodeByPath(L"\\original")->modification_time_utc == times.modification_time_utc &&
        metadata.LookupWorkingInodeByPath(L"\\original")->change_time_utc == times.change_time_utc,
        "normal unbound host content times still resolve to the same owner after every refusal");
}

bool TestNativeCompressionRewriteRefusals()
{
    using namespace apfsaccess::rw;
    for (const auto kind : {0, 1, 2, 3})
    {
        NativeCompressionFixture spec;
        spec.inode_size = 65541;
        auto tail = kNativeCompressionHello;
        if (kind == 0) tail.back() ^= std::byte{1};
        spec.decmpfs = NativeCompressionAttribute(kind == 1 ? 8 : 4, spec.inode_size);
        spec.resource = NativeCompressionResource({kNativeCompressionA64k, tail});
        spec.external_decmpfs = spec.external_resource = true;
        spec.wrong_reference_count = kind == 2;
        TempImageFile image(BuildNativeCompressionImage(spec), "native-compression-rewrite-refusal");
        MetadataStore metadata(NativeCompressionContext(image));
        if (!Require(metadata.PrepareNativeWritePath(), "refusal source remains inspectable")) return false;
        MetadataStore::MutationRequest request;
        if (kind == 3)
        {
            if (!Require(metadata.PrepareCompressionRewrite(L"\\original", request), "capture exact source checkpoint")) return false;
            MetadataStore::MutationRequest neighbor;
            neighbor.operation = MetadataStore::MutationOperation::CreateFile; neighbor.path = L"\\new";
            if (!Require(metadata.StageMutation(neighbor) == MetadataStore::MutationStatus::Applied &&
                    metadata.CommitPendingMutations() == MetadataStore::CommitStatus::Committed &&
                    metadata.StageMutation(request) == MetadataStore::MutationStatus::InvalidRequest &&
                    metadata.PendingMutationCount() == 0, "stale source checkpoint refuses even with retained compression bytes")) return false;
            continue;
        }
        if (!Require(!metadata.PrepareCompressionRewrite(L"\\original", request) && metadata.PendingMutationCount() == 0 &&
                metadata.PendingAllocationCount() == 0 && metadata.HasUnsupportedContentTransform(17),
                "late corrupt block, unsupported type, or ambiguous ownership refuses before mutation")) return false;
    }
    return true;
}

bool TestNativeRemainingCompressionReads()
{
    using namespace apfsaccess::rw;
    const auto plain = NativeCompressionHex("68656c6c6f");
    for (const unsigned type : {9u, 10u, 13u, 14u})
    for (const bool external : {false, true})
    {
        const bool resource = type == 10 || type == 14;
        const auto payload = NativeCompressionHex(type == 9 || type == 10 ?
            "cc68656c6c6f" : "5a424d090b000005000068656c6c6f060000000000");
        NativeCompressionFixture spec;
        spec.decmpfs = NativeCompressionAttribute(type, plain.size(), resource ? std::vector<std::byte>{} : payload);
        spec.external_decmpfs = external;
        spec.inode_size = plain.size();
        spec.compressed_flag = true;
        if (resource)
        {
            spec.resource = std::vector<std::byte>(8);
            PutU32LE(*spec.resource, 0, 8);
            PutU32LE(*spec.resource, 4, static_cast<std::uint32_t>(8 + payload.size()));
            spec.resource->insert(spec.resource->end(), payload.begin(), payload.end());
            spec.external_resource = external;
        }
        const auto image_before = BuildNativeCompressionImage(spec);
        TempImageFile image(image_before, "native-remaining-compression");
        MetadataStore store(NativeCompressionContext(image));
        if (!Require(store.PrepareNativeWritePath(), "remaining codec native projection loads")) return false;
        std::vector<std::byte> actual, image_after;
        if (!Require(store.ReadCommittedFileRange(L"\\original", 0, 20, actual) && actual == plain &&
                store.ReadCommittedFileRange(L"\\original", 1, 3, actual) && actual == NativeCompressionHex("656c6c") &&
                store.ReadCommittedFileRange(L"\\original", UINT64_MAX, 8, actual) && actual.empty() &&
                store.PendingMutationCount() == 0 &&
                store.Device().Read(0, image_before.size(), image_after) && image_after == image_before,
                "inline and external remaining codecs return exact ranges without native mutation")) return false;
    }
    return true;
}

bool TestNativeCompressionInlineReads()
{
    using namespace apfsaccess::rw;
    for (const auto type : {1u, 3u})
    for (const bool raw : {false, true})
    for (const bool external : {false, true})
    {
        const auto plain = NativeCompressionHex(type == 1 && raw ? "00ff800141" : "68656c6c6f");
        auto encoded = type == 1 || raw ? plain : kNativeCompressionHello;
        if (type == 3 && raw) encoded.insert(encoded.begin(), std::byte{0xff});
        NativeCompressionFixture spec;
        spec.decmpfs = NativeCompressionAttribute(type, plain.size(), encoded);
        spec.external_decmpfs = external;
        // Embedded descriptors can supply size even without UF_COMPRESSED or
        // inode size. External values use authoritative nonzero inode evidence.
        spec.inode_size = external ? plain.size() : 0;
        spec.compressed_flag = external;
        TempImageFile image(BuildNativeCompressionImage(spec), "native-compression-inline");
        MetadataStore metadata(NativeCompressionContext(image));
        if (!Require(metadata.LoadContainerSuperblocks() && metadata.LoadObjectMap(), "native inline projection loads")) return false;
        const auto key = ApfsNameCodec::CanonicalWindowsPathKey(L"\\original", ApfsNamePolicy::FromIncompatibleFeatures(0));
        if (!Require(key.ok(), "native compression canonical key")) return false;
        const auto plan = metadata.SnapshotCommittedFileReadPlan(*key.value);
        const auto inode = metadata.LookupCommittedInodeByPath(L"\\original");
        if (!Require(plan && plan->HasCompressionReadCandidate() && inode && inode->logical_size == 5 &&
                plan->logical_size == 5 && metadata.HasUnsupportedContentTransform(17),
                "zero native dstream retains exact decoded size and write guard")) return false;
        if (!RequireNativeCompressionRange(metadata, *plan, 0, 20, plain) ||
            !RequireNativeCompressionRange(metadata, *plan, 1, 3, std::vector<std::byte>(plain.begin() + 1, plain.begin() + 4)) ||
            !RequireNativeCompressionRange(metadata, *plan, UINT64_MAX, 8, {}) ||
            !RequireNativeCompressionRange(metadata, *plan, 0, 0, {})) return false;
        std::vector<std::byte> bytes;
        if (!Require(metadata.ReadCommittedFileRange(L"\\original", 0, 20, bytes) && bytes == plain,
                "native inline vector entry point decodes")) return false;
        bytes.resize(spec.decmpfs.size());
        std::size_t read = 0;
        if (!Require(metadata.ReadCommittedExtendedAttributeRange(17, "com.apple.decmpfs", 0, bytes, read) &&
                read == bytes.size() && bytes == spec.decmpfs, "raw embedded/external decmpfs remains exact")) return false;
        if (!Require(metadata.ReadCommittedFileRange(L"\\neighbor", 0, 8, bytes) && bytes == NativeCompressionHex("6e00ff72"),
                "ordinary backed neighbor remains exact")) return false;
    }
    for (const auto type : {1u, 3u})
    {
        NativeCompressionFixture spec;
        spec.inode_size = 0;
        spec.decmpfs = NativeCompressionAttribute(type, 0,
            type == 3 ? NativeCompressionHex("789C030000000001") : std::vector<std::byte>{});
        TempImageFile image(BuildNativeCompressionImage(spec), "native-compression-empty");
        MetadataStore metadata(NativeCompressionContext(image));
        if (!Require(metadata.LoadContainerSuperblocks() && metadata.LoadObjectMap(), "empty compression loads")) return false;
        std::vector<std::byte> bytes(4, std::byte{0xab});
        if (!Require(metadata.ReadCommittedFileRange(L"\\original", 0, 4, bytes) && bytes.empty(),
                "validated empty compression succeeds at EOF")) return false;
    }
    return true;
}

bool TestNativeCompressionResourceReads()
{
    using namespace apfsaccess::rw;
    for (const bool external : {false, true})
    {
        // Embedded uses two small zlib streams. External includes a full raw
        // 64 KiB block crossing many physically discontinuous xattr extents.
        std::vector<std::byte> raw(65537, std::byte{'B'}); raw[0] = std::byte{0xff};
        NativeCompressionFixture spec;
        spec.inode_size = 2 * 65536 + 5;
        spec.decmpfs = NativeCompressionAttribute(4, spec.inode_size);
        spec.resource = NativeCompressionResource({kNativeCompressionA64k,
            external ? raw : kNativeCompressionA64k, kNativeCompressionHello});
        spec.external_decmpfs = external; spec.external_resource = external;
        TempImageFile image(BuildNativeCompressionImage(spec), "native-compression-resource");
        MetadataStore metadata(NativeCompressionContext(image));
        if (!Require(metadata.LoadContainerSuperblocks() && metadata.LoadObjectMap(), "native resource projection loads")) return false;
        const auto key = ApfsNameCodec::CanonicalWindowsPathKey(L"\\original", ApfsNamePolicy::FromIncompatibleFeatures(0));
        if (!Require(key.ok(), "resource key")) return false;
        const auto plan = metadata.SnapshotCommittedFileReadPlan(*key.value);
        if (!Require(plan && plan->HasCompressionReadCandidate() && plan->logical_size == spec.inode_size,
                "resource candidate captures logical size")) return false;
        const auto middle = external ? std::byte{'B'} : std::byte{'A'};
        auto expected = std::vector<std::byte>(4, std::byte{'A'});
        expected.insert(expected.end(), 6, middle);
        if (!RequireNativeCompressionRange(metadata, *plan, 65532, 10, expected)) return false;
        expected.assign(4, middle);
        const auto hello = NativeCompressionHex("68656c6c6f");
        expected.insert(expected.end(), hello.begin(), hello.end());
        if (!RequireNativeCompressionRange(metadata, *plan, 131068, 20, expected) ||
            !RequireNativeCompressionRange(metadata, *plan, spec.inode_size, 10, {})) return false;
        std::vector<std::byte> raw_fork(spec.resource->size());
        std::size_t read = 0;
        if (!Require(metadata.ReadCommittedExtendedAttributeRange(17, "com.apple.ResourceFork", 0, raw_fork, read) &&
                read == raw_fork.size() && raw_fork == *spec.resource, "raw fork spans exact external extents")) return false;
    }
    return true;
}

bool TestNativeCompressionMalformedReads()
{
    using namespace apfsaccess::rw;
    for (unsigned probe = 0; probe != 22; ++probe)
    {
        NativeCompressionFixture spec;
        spec.decmpfs = NativeCompressionAttribute(3, 5, kNativeCompressionHello);
        switch (probe)
        {
        case 0: spec.omit_decmpfs = true; spec.inode_size = 0; break; // Flag only; no successful EOF.
        case 1: spec.decmpfs.resize(15); break;
        case 2: spec.decmpfs[0] = std::byte{0}; break;
        case 3: PutU32LE(spec.decmpfs, 4, 7); break; // LZVN is not supported.
        case 4: PutU32LE(spec.decmpfs, 4, 0x80000001); break; // Dataless.
        case 5: spec.inode_size = 6; break;
        case 6: spec.decmpfs.pop_back(); break; // Truncated zlib.
        case 7: spec.decmpfs.back() ^= std::byte{1}; break; // Checksum.
        case 8: spec.decmpfs.push_back(std::byte{0}); break; // Trailing bytes.
        case 9: spec.decmpfs = NativeCompressionAttribute(1, 6, NativeCompressionHex("68656c6c6f")); break;
        case 10: spec.decmpfs.resize(3803); spec.external_decmpfs = true; break; // Raw attr budget.
        case 11: spec.decmpfs = NativeCompressionAttribute(3, 65537, kNativeCompressionA64k);
            spec.inode_size = 65537; break; // Inline decoded budget.
        case 12: spec.external_decmpfs = true; spec.wrong_reference_count = true; break;
        case 13: spec.external_decmpfs = true; spec.inode_size = 0; break; // Unresolved external size.
        case 14: spec.decmpfs = NativeCompressionAttribute(4, 5); break; // Missing fork.
        case 15: spec.decmpfs = NativeCompressionAttribute(4, 5);
            spec.resource = NativeCompressionResource({kNativeCompressionHello});
            spec.resource->pop_back(); spec.external_resource = true; break;
        case 16: spec.decmpfs = NativeCompressionAttribute(4, 5);
            spec.resource = NativeCompressionResource({kNativeCompressionHello});
            PutU32LE(*spec.resource, 0x104, 2); break; // Count disagrees with logical size.
        case 17: spec.inode_size = 65541; spec.decmpfs = NativeCompressionAttribute(4, spec.inode_size);
            spec.resource = NativeCompressionResource({kNativeCompressionA64k, kNativeCompressionHello});
            PutU32LE(*spec.resource, 0x110, 20); break; // Second block aliases first.
        case 18: spec.inode_size = (1ULL << 40) + 1;
            spec.decmpfs = NativeCompressionAttribute(4, spec.inode_size); break; // Logical file limit.
        case 19: PutU32LE(spec.decmpfs, 4, 42); break;
        case 20: spec.inode_size = 6; PutU64LE(spec.decmpfs, 8, 6); break; // Underproduction.
        case 21: spec.inode_size = 4; PutU64LE(spec.decmpfs, 8, 4); break; // Overproduction.
        }
        TempImageFile image(BuildNativeCompressionImage(spec), "native-compression-malformed");
        MetadataStore metadata(NativeCompressionContext(image));
        if (!Require(metadata.LoadContainerSuperblocks() && metadata.LoadObjectMap(),
                "malformed compression stays inspectable, probe=" + std::to_string(probe))) return false;
        const auto key = ApfsNameCodec::CanonicalWindowsPathKey(L"\\original", ApfsNamePolicy::FromIncompatibleFeatures(0));
        if (!Require(key.ok(), "malformed canonical key")) return false;
        const auto plan = metadata.SnapshotCommittedFileReadPlan(*key.value);
        if (!Require(plan && plan->unsupported_content_transform, "malformed compression evidence survives")) return false;
        for (const auto offset : std::array<std::uint64_t, 3>{0, plan->logical_size, UINT64_MAX})
        {
            std::vector<std::byte> destination(32, std::byte{0xa6});
            std::size_t read = 99;
            if (!Require(!metadata.ReadCommittedFileRangeFromPlan(*plan, {}, offset, 16,
                    destination.data(), destination.size(), read) && read == 0 &&
                    destination == std::vector<std::byte>(32, std::byte{0xa6}),
                    "malformed range/EOF failure preserves caller bytes, probe=" + std::to_string(probe))) return false;
        }
        std::vector<std::byte> bytes(4, std::byte{0xe1});
        const auto original_data = bytes.data(); const auto capacity = bytes.capacity();
        if (!Require(!metadata.ReadCommittedFileRange(L"\\original", 0, 4, bytes) && bytes.data() == original_data &&
                bytes.capacity() == capacity && bytes == std::vector<std::byte>(4, std::byte{0xe1}),
                "compressed vector failure preserves contents and allocation")) return false;
        if (!Require(metadata.ReadCommittedFileRange(L"\\neighbor", 0, 8, bytes) && bytes == NativeCompressionHex("6e00ff72"),
                "malformed owner does not contaminate ordinary neighbor")) return false;
    }
    // A later failing block must not leak a successfully decoded first block.
    NativeCompressionFixture spec;
    spec.inode_size = 65541;
    spec.decmpfs = NativeCompressionAttribute(4, spec.inode_size);
    auto broken = kNativeCompressionHello; broken.back() ^= std::byte{1};
    spec.resource = NativeCompressionResource({kNativeCompressionA64k, broken});
    spec.external_resource = true;
    TempImageFile image(BuildNativeCompressionImage(spec), "native-compression-late-failure");
    MetadataStore metadata(NativeCompressionContext(image));
    if (!Require(metadata.LoadContainerSuperblocks() && metadata.LoadObjectMap(), "late failure image loads")) return false;
    std::vector<std::byte> first;
    if (!Require(metadata.ReadCommittedFileRange(L"\\original", 0, 1, first) && first == std::vector<std::byte>{std::byte{'A'}},
            "range reader does not decode a corrupt unselected resource block")) return false;
    std::vector<std::byte> bytes(20, std::byte{0xba}); std::size_t read = 99;
    return Require(!metadata.ReadCommittedFileRangeInto(L"\\original", 65530, 20, bytes.data(), bytes.size(), read) &&
        read == 0 && bytes == std::vector<std::byte>(20, std::byte{0xba}), "late resource decode failure is atomic to caller");
}

bool TestNativeCompressionUnflaggedPadding()
{
    using namespace apfsaccess::rw;
    for (const bool external : {false, true})
    for (const bool omit_stream : {false, true}) {
        NativeCompressionFixture spec;
        spec.uncompressed_size_flag = false;
        spec.external_decmpfs = external;
        spec.inode_size = UINT64_MAX;
        spec.omit_default_dstream = omit_stream;
        spec.decmpfs = NativeCompressionAttribute(3, 5, kNativeCompressionHello);
        TempImageFile image(BuildNativeCompressionImage(spec), "native-compression-padding");
        MetadataStore metadata(NativeCompressionContext(image));
        if (!Require(metadata.LoadContainerSuperblocks() && metadata.LoadObjectMap(),
                "legacy compressed padding stays opaque")) return false;
        const auto inode = metadata.LookupCommittedInodeByPath(L"\\original");
        std::vector<std::byte> bytes;
        if (!Require(inode && inode->logical_size == 5 &&
                metadata.ReadCommittedFileRange(L"\\original", 0, 10, bytes) &&
                bytes == NativeCompressionHex("68656c6c6f"),
                "legacy decoded EOF comes from validated decmpfs, not padding")) return false;
    }
    return true;
}

bool TestNativeCompressionReadBudgets()
{
    using namespace apfsaccess::rw;
    NativeCompressionFixture spec;
    // 32 MiB + 64 KiB logically, represented by a small external fork. Reading
    // its final byte must not decode the whole file (32 MiB work budget).
    spec.inode_size = 513ULL * 65536;
    spec.decmpfs = NativeCompressionAttribute(4, spec.inode_size);
    spec.resource = NativeCompressionResource(std::vector<std::vector<std::byte>>(513, kNativeCompressionA64k));
    spec.external_resource = true;
    TempImageFile image(BuildNativeCompressionImage(spec), "native-compression-budgets");
    MetadataStore metadata(NativeCompressionContext(image));
    if (!Require(metadata.LoadContainerSuperblocks() && metadata.LoadObjectMap(), "budget fixture loads")) return false;
    std::vector<std::byte> bytes;
    if (!Require(metadata.ReadCommittedFileRange(L"\\original", spec.inode_size - 1, 1, bytes) &&
            bytes == std::vector<std::byte>{std::byte{'A'}}, "large fork range decodes only selected block")) return false;
    const auto before = bytes.data(); const auto capacity = bytes.capacity();
    return Require(!metadata.ReadCommittedFileRange(L"\\original", 0, static_cast<std::size_t>(spec.inode_size), bytes) &&
        bytes.data() == before && bytes.capacity() == capacity && bytes == std::vector<std::byte>{std::byte{'A'}},
        "native output budget rejects before caller allocation or data changes");
}

bool TestNativeCompressionExactCheckpointSizes()
{
    using namespace apfsaccess::rw;
    NativeCompressionFixture spec;
    spec.inode_size = 513ULL * 65536;
    spec.decmpfs = NativeCompressionAttribute(4, spec.inode_size);
    spec.resource = NativeCompressionResource(std::vector<std::vector<std::byte>>(513, kNativeCompressionA64k));
    spec.external_resource = true;
    const auto checkpoint_xid = BuilderStore{}.xid;
    for (const bool omit_stream : {false, true})
    for (const bool compressed_flag : {false, true})
    {
        spec.omit_default_dstream = omit_stream;
        spec.compressed_flag = compressed_flag;
        const auto image_bytes = BuildNativeCompressionImage(spec);
        if (!Require(image_bytes.size() == 512ULL * 4096 && spec.inode_size > image_bytes.size() &&
                spec.resource->size() < image_bytes.size(),
                "exact compression fixture has decoded EOF above container and a small backed fork")) return false;
        TempImageFile image(image_bytes, "native-compression-exact-size");
        BlockDevice device(image.path.wstring(), 0);
        for (const bool exact : {false, true})
        {
            NativeApfsVolumeProjection projection;
            std::wstring error;
            if (!Require(NativeApfsReader::TryLoadVolumeProjection(device, 101, projection, error,
                    exact ? std::optional<std::uint64_t>(checkpoint_xid) : std::nullopt),
                    "large compressed projection loads: exact=" + std::to_string(exact) +
                    ", omit_dstream=" + std::to_string(omit_stream) +
                    ", bsd_flag=" + std::to_string(compressed_flag))) return false;
            const auto inode = std::find_if(projection.inodes.begin(), projection.inodes.end(),
                [](const auto& value) { return value.object_id == 17; });
            const auto fork = projection.attribute_stream_extents.find(778);
            if (!Require(projection.checkpoint_xid == checkpoint_xid && inode != projection.inodes.end() &&
                    inode->logical_size == spec.inode_size && inode->allocation_size == 0 &&
                    fork != projection.attribute_stream_extents.end() && fork->second && !fork->second->empty(),
                    "current exact XID preserves decoded EOF and validated external resource backing")) return false;
        }
        MetadataStore metadata(NativeCompressionContext(image));
        if (!Require(metadata.LoadContainerSuperblocks() && metadata.LoadObjectMap(),
                "large exact-checkpoint fixture also loads through metadata")) return false;
        std::vector<std::byte> bytes;
        if (!Require(metadata.ReadCommittedFileRange(L"\\original", spec.inode_size - 1, 1, bytes) &&
                bytes == std::vector<std::byte>{std::byte{'A'}} && metadata.HasUnsupportedContentTransform(17),
                "large fixture final byte decodes while compression mutation guard remains")) return false;
    }

    // Keep the same valid external ResourceFork and oversized inode, removing
    // only compression evidence. A resource fork alone must not exempt an
    // ordinary inode without a default dstream from exact namespace validation.
    spec.omit_default_dstream = true;
    spec.compressed_flag = false;
    spec.omit_decmpfs = true;
    TempImageFile ordinary(BuildNativeCompressionImage(spec), "native-ordinary-exact-oversized");
    BlockDevice device(ordinary.path.wstring(), 0);
    NativeApfsVolumeProjection projection;
    std::wstring error;
    return Require(!NativeApfsReader::TryLoadVolumeProjection(device, 101, projection, error, checkpoint_xid) &&
        error == L"NativeApfsRootTreeProjectionFailed",
        "ordinary oversized no-dstream inode with only a resource fork is still refused at exact XID");
}

bool TestNativeCompressionSnapshotIdentityAndPublication()
{
    using namespace apfsaccess::rw;
    NativeCompressionFixture spec;
    spec.decmpfs = NativeCompressionAttribute(4, 5);
    spec.resource = NativeCompressionResource({kNativeCompressionHello});
    spec.external_decmpfs = spec.external_resource = true;
    TempImageFile image(BuildNativeCompressionImage(spec), "native-compression-retained");
    const auto context = NativeCompressionContext(image);
    MetadataStore metadata(context);
    if (!Require(metadata.PrepareNativeWritePath(), "compressed native write preparation")) return false;
    const auto key = ApfsNameCodec::CanonicalWindowsPathKey(L"\\original", ApfsNamePolicy::FromIncompatibleFeatures(0));
    if (!Require(key.ok(), "retained canonical key")) return false;
    const auto plan = metadata.SnapshotCommittedFileReadPlan(*key.value);
    if (!Require(plan && plan->HasCompressionReadCandidate(), "retained external candidate")) return false;
    for (const auto operation : {MetadataStore::MutationOperation::Write,
            MetadataStore::MutationOperation::SetFileSize, MetadataStore::MutationOperation::SetAllocationSize})
    {
        MetadataStore::MutationRequest request;
        request.operation = operation; request.path = L"\\original";
        request.length = operation == MetadataStore::MutationOperation::SetAllocationSize ? 4096 : 2;
        MetadataStore::PayloadIdentity identity;
        const auto free = metadata.DebugWorkingFreeExtentTotalBytes();
        if (!Require(metadata.StageMutation(request, &identity) == MetadataStore::MutationStatus::UnsupportedOperation &&
                identity.object_id == 0 && metadata.HasUnsupportedContentTransform(17) &&
                metadata.LastMutationFailureReason() == L"UnsupportedContentTransform" &&
                metadata.PendingMutationCount() == 0 && metadata.PendingBtreeRecordCount() == 0 &&
                metadata.PendingAllocationCount() == 0 && metadata.PendingDeallocationCount() == 0 &&
                metadata.PendingPayloadDirtyByteEstimate() == 0 && metadata.DebugWorkingFreeExtentTotalBytes() == free,
                "supported decoding never authorizes compressed mutations or staging")) return false;
    }
    MetadataStore::MutationRequest rename;
    rename.operation = MetadataStore::MutationOperation::Rename;
    rename.path = L"\\original"; rename.secondary_path = L"\\renamed";
    MetadataStore::MutationRequest write;
    write.operation = MetadataStore::MutationOperation::Write; write.path = L"\\neighbor"; write.length = 4;
    const auto replacement = NativeCompressionHex("7700fe21");
    metadata.SetFilePayloadProvider([&](const auto& path, auto size) -> std::optional<std::vector<std::byte>> {
        return path == write.path && size == replacement.size() ? std::optional(replacement) : std::nullopt;
    });
    if (!Require(metadata.StageMutation(rename) == MetadataStore::MutationStatus::Applied &&
            metadata.StageMutation(write) == MetadataStore::MutationStatus::Applied &&
            metadata.CommitPendingMutations() == MetadataStore::CommitStatus::Committed,
            "unrelated neighbor payload and compressed rename publish")) return false;
    const auto hello = NativeCompressionHex("68656c6c6f");
    if (!RequireNativeCompressionRange(metadata, *plan, 0, 8, hello)) return false;
    std::vector<std::byte> bytes;
    if (!Require(!metadata.LookupCommittedInodeByPath(L"\\original") &&
            metadata.ReadCommittedFileRange(L"\\renamed", 0, 8, bytes) && bytes == hello &&
            metadata.ReadCommittedFileRange(L"\\neighbor", 0, 8, bytes) && bytes == replacement,
            "publication preserves compressed bytes and ordinary write")) return false;
    auto wrong_owner = *plan; wrong_owner.object_id = 18;
    auto wrong_size = *plan; ++wrong_size.logical_size;
    for (const auto& wrong : {wrong_owner, wrong_size})
    {
        bytes.assign(8, std::byte{0xaa}); std::size_t read = 99;
        if (!Require(!metadata.ReadCommittedFileRangeFromPlan(wrong, {}, 0, 8, bytes.data(), bytes.size(), read) &&
                read == 0 && bytes == std::vector<std::byte>(8, std::byte{0xaa}),
                "retained snapshot enforces exact owner and logical size")) return false;
    }
    MetadataStore reopened(context);
    if (!Require(reopened.PrepareNativeWritePath(), "compressed publication reopens")) return false;
    bytes.assign(8, std::byte{0xaa}); std::size_t read = 99;
    if (!Require(!reopened.ReadCommittedFileRangeFromPlan(*plan, {}, 0, 8, bytes.data(), bytes.size(), read) &&
            read == 0 && bytes == std::vector<std::byte>(8, std::byte{0xaa}), "snapshot cannot be redirected to another store")) return false;
    return Require(reopened.ReadCommittedFileRange(L"\\renamed", 0, 8, bytes) && bytes == hello &&
        reopened.HasUnsupportedContentTransform(17), "fresh read uses persisted compressed snapshot and retains write guard");
}

bool TestCompressionDefaultDataAdmission()
{
    using namespace apfsaccess::rw;
    // Real native records: nonempty owners, with either no extents or an
    // ordinary sparse extent which previously fabricated successful zero data.
    for (unsigned marker = 0; marker != 5; ++marker)
    for (const bool sparse : {false, true})
    {
        const bool compressed = marker != 0 && marker != 4;
        AppleXattrRecord attribute{17, marker == 4 ? "com.apple.ResourceFork" :
            marker >= 2 ? "com.apple.decmpfs" : "user.inspect",
            kAppleXattrDataEmbedded, marker == 2 ? std::vector<std::byte>{} :
                std::vector<std::byte>{std::byte{0xff}}};
        if (marker == 4)
        {
            attribute.data.resize(4);
            PutU32LE(attribute.data, 0, 0x636d7066); // Independent fork magic is not owner evidence.
        }
        TempImageFile image(BuildFileContentAttributeImage(attribute, 64, 0100644,
            marker == 1 ? kAppleBsdCompressedFlag : 0, std::nullopt, 32, sparse), "compression-read-admission");
        MetadataStore::VolumeContext context;
        context.device_path = image.path.wstring(); context.volume_object_id = 101;
        context.allow_legacy_scaffold_for_fixtures = false;
        MetadataStore metadata(context);
        if (!metadata.PrepareNativeWritePath())
        {
            std::wcerr << L"compression prepare: " << metadata.RecoveryReason() << std::endl;
            return Require(false, "compression fixture remains mountable, marker=" +
                std::to_string(marker) + ", sparse=" + std::to_string(sparse));
        }
        const auto inode = metadata.LookupCommittedInodeByPath(L"\\original");
        const auto key = ApfsNameCodec::CanonicalWindowsPathKey(L"\\original", ApfsNamePolicy::FromIncompatibleFeatures(0));
        if (!Require(key.ok(), "compression path key encodes")) return false;
        const auto plan = metadata.SnapshotCommittedFileReadPlan(*key.value);
        if (!Require(inode && inode->logical_size == 32 && plan &&
                plan->unsupported_content_transform == compressed,
                "nonempty native owner captures representation evidence")) return false;
        std::vector<std::byte> destination(8, std::byte{0x6a});
        std::size_t count = 99;
        const bool read = metadata.ReadCommittedFileRangeFromPlan(*plan, L"\\original", 0,
            destination.size(), destination.data(), destination.size(), count);
        if (!Require(read == (!compressed && sparse), "default data refuses compressed or missing extents")) return false;
        if (compressed && !Require(count == 0 && destination == std::vector<std::byte>(8, std::byte{0x6a}),
                "compression refusal returns no bytes and leaves destination untouched")) return false;
        if (compressed)
        {
            std::vector<std::byte> default_data{std::byte{0x6a}};
            if (!Require(!metadata.ReadCommittedFileRange(L"\\original", 0, 8, default_data) &&
                    default_data == std::vector<std::byte>{std::byte{0x6a}},
                    "public compressed-data wrapper refuses and preserves output")) return false;
        }
        if (!compressed && sparse && !Require(count == 8 && destination == std::vector<std::byte>(8),
                "ordinary sparse data remains zero filled")) return false;
        if (!compressed && sparse && !Require(metadata.ReadCommittedFileRangeFromPlan(*plan, {}, 30, 8,
                destination.data(), 8, count) && count == 2, "ordinary sparse read clamps at EOF")) return false;
        if (!Require(metadata.ReadCommittedFileRangeFromPlan(*plan, {}, 32, 8, destination.data(), 8, count) == !compressed &&
                count == 0 && metadata.ReadCommittedFileRangeFromPlan(*plan, {}, 0, 0, nullptr, 0, count) == !compressed,
                "ordinary EOF succeeds; malformed compression fails even at EOF or zero length")) return false;
        std::vector<std::byte> raw(8);
        if (!Require(metadata.ReadCommittedExtendedAttributeRange(17, attribute.name_utf8, 0, raw, count) &&
                count == attribute.data.size() && std::equal(attribute.data.begin(), attribute.data.end(), raw.begin()),
                "raw embedded metadata stays inspectable")) return false;
        if (!compressed)
        {
            if (marker == 4)
            {
                MetadataStore::MutationRequest write;
                write.operation = MetadataStore::MutationOperation::Write; write.path = L"\\original"; write.length = 4;
                if (!Require(metadata.StageMutation(write) == MetadataStore::MutationStatus::Applied,
                        "ordinary independent fork magic permits default payload staging")) return false;
            }
            continue;
        }
        for (const auto operation : {MetadataStore::MutationOperation::Write,
                MetadataStore::MutationOperation::SetFileSize, MetadataStore::MutationOperation::SetAllocationSize})
        {
            MetadataStore::MutationRequest request;
            request.operation = operation; request.path = L"\\original";
            request.length = operation == MetadataStore::MutationOperation::Write ? 4 : 0;
            const auto free_bytes = metadata.DebugWorkingFreeExtentTotalBytes();
            MetadataStore::PayloadIdentity identity;
            if (!Require(metadata.StageMutation(request, &identity) == MetadataStore::MutationStatus::UnsupportedOperation &&
                    metadata.LastMutationFailureReason() == L"UnsupportedContentTransform" && identity.object_id == 0 &&
                    metadata.PendingMutationCount() == 0 && metadata.PendingAllocationCount() == 0 &&
                    metadata.PendingDeallocationCount() == 0 && metadata.PendingBtreeRecordCount() == 0 &&
                    metadata.PendingPayloadDirtyByteEstimate() == 0 &&
                    metadata.DebugWorkingFreeExtentTotalBytes() == free_bytes &&
                    metadata.LookupWorkingInodeByPath(request.path)->logical_size == 32,
                    "compressed payload admission refuses before dirty state or allocation")) return false;
        }
        MetadataStore::MutationRequest ordinary;
        ordinary.operation = MetadataStore::MutationOperation::CreateFile; ordinary.path = L"\\ordinary";
        if (!Require(metadata.IsNativeWriteReady() && !metadata.IsRecoveryRequired() &&
                metadata.StageMutation(ordinary) == MetadataStore::MutationStatus::Applied,
                "compression rejection leaves ordinary namespace admission available")) return false;
        ordinary.operation = MetadataStore::MutationOperation::Write; ordinary.length = 4;
        const std::vector<std::byte> ordinary_payload{
            std::byte{0x61}, std::byte{0}, std::byte{0xff}, std::byte{0x7e}};
        metadata.SetFilePayloadProvider([&](const auto& path, auto size) -> std::optional<std::vector<std::byte>> {
            if (path == ordinary.path && size == ordinary_payload.size()) return ordinary_payload;
            return std::nullopt;
        });
        if (!Require(metadata.StageMutation(ordinary) == MetadataStore::MutationStatus::Applied,
                "another ordinary file on the same volume still accepts payload")) return false;
        if (metadata.CommitPendingMutations() != MetadataStore::CommitStatus::Committed)
        {
            std::wcerr << L"compression neighbor commit: " << metadata.LastCommitFailureReason()
                << L" integrity=" << metadata.LastIntegrityFailureReason() << std::endl;
            return Require(false, "ordinary content publishes alongside an unsupported compressed owner, marker=" +
                std::to_string(marker) + ", sparse=" + std::to_string(sparse));
        }
        MetadataStore reopened(context);
        std::vector<std::byte> ordinary_bytes;
        if (!Require(reopened.PrepareNativeWritePath() &&
                reopened.ReadCommittedFileRange(ordinary.path, 0, 4, ordinary_bytes) &&
                ordinary_bytes == ordinary_payload &&
                reopened.HasUnsupportedContentTransform(17),
                "fresh checkpoint keeps both ordinary data and compressed evidence")) return false;
        const auto preserved = reopened.LookupCommittedExtendedAttribute(17, attribute.name_utf8);
        if (!Require(preserved && preserved->flags == attribute.flags && preserved->data == attribute.data,
                "ordinary publication preserves compressed raw attribute bytes")) return false;
    }
    return true;
}

bool TestCompressionPendingAndOriginalAdmission()
{
    using namespace apfsaccess::rw;
    for (const bool original_compressed : {false, true})
    {
        TempImageFile image(BuildFileContentAttributeImage({}, 64, 0100644,
            original_compressed ? kAppleBsdCompressedFlag : 0, std::nullopt, 32, true), "compression-pending-admission");
        MetadataStore::VolumeContext context;
        context.device_path = image.path.wstring(); context.volume_object_id = 101;
        context.allow_legacy_scaffold_for_fixtures = false;
        MetadataStore metadata(context);
        if (!Require(metadata.PrepareNativeWritePath(), "compression transition fixture prepares")) return false;
        const auto key = ApfsNameCodec::CanonicalWindowsPathKey(L"\\original", ApfsNamePolicy::FromIncompatibleFeatures(0));
        if (!Require(key.ok(), "compression transition path key encodes")) return false;
        const auto plan = metadata.SnapshotCommittedFileReadPlan(*key.value);
        InodeMetadataPatch patch;
        patch.mask = InodeMetadataPatch::BsdFlags;
        patch.bsd_flags = original_compressed ? 0 : kAppleBsdCompressedFlag;
        MetadataStore::MutationRequest flags;
        flags.operation = MetadataStore::MutationOperation::SetInodeMetadata; flags.path = L"\\original";
        if (!Require(EncodeInodeMetadataPatch(patch, flags.inline_payload), "compression flag patch encodes")) return false;
        flags.length = flags.inline_payload.size();
        if (!Require(metadata.StageMutation(flags) == MetadataStore::MutationStatus::UnsupportedOperation &&
                metadata.PendingMutationCount() == 0 && metadata.PendingAllocationCount() == 0,
                "generic metadata cannot change compression representation in either direction")) return false;
        patch.bsd_flags = (original_compressed ? kAppleBsdCompressedFlag : 0) | 0x8000;
        if (!Require(EncodeInodeMetadataPatch(patch, flags.inline_payload), "neutral BSD flag patch encodes")) return false;
        flags.length = flags.inline_payload.size();
        if (!Require(metadata.StageMutation(flags) == MetadataStore::MutationStatus::Applied,
                "other BSD metadata remains independently mutable while preserving compression")) return false;
        const auto records = metadata.PendingBtreeRecordCount();
        if (original_compressed)
        {
            for (const auto operation : {MetadataStore::MutationOperation::Write, MetadataStore::MutationOperation::SetFileSize})
            {
                auto request = MetadataStore::MutationRequest{};
                request.operation = operation; request.path = flags.path; request.length = 4;
                if (!Require(metadata.StageMutation(request) == MetadataStore::MutationStatus::UnsupportedOperation &&
                        metadata.PendingMutationCount() == 1 && metadata.PendingBtreeRecordCount() == records &&
                        metadata.PendingAllocationCount() == 0 && metadata.PendingPayloadDirtyByteEstimate() == 0,
                        "original compression vetoes payload staging without discarding neutral metadata")) return false;
            }
        }
        else
        {
            MetadataStore::MutationRequest write;
            write.operation = MetadataStore::MutationOperation::Write; write.path = flags.path; write.length = 4;
            if (!Require(metadata.StageMutation(write) == MetadataStore::MutationStatus::Applied,
                    "ordinary pending payload remains writable")) return false;
            const auto pending = metadata.PendingMutationCount();
            patch.bsd_flags |= kAppleBsdCompressedFlag;
            if (!Require(EncodeInodeMetadataPatch(patch, flags.inline_payload), "late compression flag patch encodes")) return false;
            flags.length = flags.inline_payload.size();
            if (!Require(metadata.StageMutation(flags) == MetadataStore::MutationStatus::UnsupportedOperation &&
                    metadata.PendingMutationCount() == pending,
                    "later metadata cannot turn accepted ordinary payload into unsupported compressed data")) return false;
        }
        std::vector<std::byte> data(4, std::byte{0x55});
        std::size_t count = 99;
        if (!Require(plan && metadata.ReadCommittedFileRangeFromPlan(*plan, {}, 0, 4, data.data(), 4, count) ==
                !original_compressed && count == (original_compressed ? 0 : 4),
                "retained committed representation is independent of pending flag changes")) return false;
    }
    return true;
}

bool TestSparseRecordPreservationAndRewrite()
{
    using namespace apfsaccess::rw;
    for (const bool remove : {false, true})
    {
        TempImageFile image(BuildFileContentAttributeImage({}, 64, 0100644, 0,
            std::nullopt, 32, true), "sparse-record-rewrite");
        MetadataStore::VolumeContext context;
        context.device_path = image.path.wstring(); context.volume_object_id = 101;
        context.allow_legacy_scaffold_for_fixtures = false;
        MetadataStore metadata(context);
        std::vector<std::byte> bytes;
        if (!Require(metadata.PrepareNativeWritePath() &&
                metadata.ReadCommittedFileRange(L"\\original", 0, 32, bytes) && bytes == std::vector<std::byte>(32),
                "imported sparse owner reads actual logical zeros")) return false;
        MetadataStore::MutationRequest request;
        request.path = L"\\original";
        std::vector<std::byte> payload(32);
        payload[5] = std::byte{0x81}; payload[6] = std::byte{0}; payload[7] = std::byte{0xff};
        metadata.SetFilePayloadProvider([&](const auto& path, auto size) -> std::optional<std::vector<std::byte>> {
            if (path == request.path && size == payload.size()) return payload;
            return std::nullopt;
        });
        request.operation = remove ? MetadataStore::MutationOperation::Delete : MetadataStore::MutationOperation::Write;
        request.offset = remove ? 0 : 5; request.length = remove ? 0 : 3;
        if (!Require(metadata.StageMutation(request) == MetadataStore::MutationStatus::Applied &&
                metadata.CommitPendingMutations() == MetadataStore::CommitStatus::Committed,
                "sparse rewrite or unlink never releases block zero")) return false;
        MetadataStore reopened(context);
        if (!Require(reopened.PrepareNativeWritePath() && reopened.VerifyIntegrity(),
                "sparse mutation leaves a valid fresh checkpoint")) return false;
        if (remove)
        {
            if (!Require(!reopened.LookupCommittedInodeByPath(request.path),
                    "sparse final unlink persists")) return false;
        }
        else if (!Require(reopened.ReadCommittedFileRange(request.path, 0, 32, bytes) && bytes == payload,
                "sparse materialization preserves untouched zeros and exact new bytes")) return false;
    }
    return true;
}

bool TestCompressionExternalRawAttributeAdmission()
{
    using namespace apfsaccess::rw;
    for (const bool external_decmpfs : {false, true})
    {
        ExternalXattrFixtureSpec spec;
        spec.high_inode_id = spec.attribute_owner_inode = 17;
        spec.owner_logical_size = 32;
        spec.attribute_name = external_decmpfs ? "com.apple.decmpfs" : "com.apple.ResourceFork";
        spec.owner_bsd_flags = external_decmpfs ? 0 : kAppleBsdCompressedFlag;
        std::vector<std::byte> descriptor;
        TempImageFile image(BuildExternalXattrRangeImage(spec, descriptor), "compression-raw-external");
        MetadataStore::VolumeContext context;
        context.device_path = image.path.wstring(); context.volume_object_id = 101;
        context.allow_legacy_scaffold_for_fixtures = false;
        MetadataStore metadata(context);
        if (!metadata.PrepareNativeWritePath())
        {
            std::wcerr << L"external compression prepare: " << metadata.RecoveryReason() << std::endl;
            return Require(false, "external compressed owner remains inspectable");
        }
        std::vector<std::byte> data(16);
        std::size_t count = 99;
        const auto key = ApfsNameCodec::CanonicalWindowsPathKey(L"\\alias.bin", ApfsNamePolicy::FromIncompatibleFeatures(0));
        if (!Require(key.ok(), "external compression path key encodes")) return false;
        const auto plan = metadata.SnapshotCommittedFileReadPlan(*key.value);
        if (!Require(plan && plan->unsupported_content_transform &&
                !metadata.ReadCommittedFileRangeFromPlan(*plan, {}, 0, 16, data.data(), 16, count) && count == 0 &&
                metadata.ReadCommittedExtendedAttributeRange(17, spec.attribute_name, 0, data, count) && count == 16,
                "default data protection preserves explicit external decmpfs and fork reads")) return false;
        const auto expected = ExternalXattrPayloadBlock(17, 3);
        if (!Require(std::equal(data.begin(), data.end(), expected.begin()),
                "external raw reader returns actual fork or decmpfs bytes")) return false;
        MetadataStore::MutationRequest request;
        request.operation = MetadataStore::MutationOperation::Write; request.path = L"\\alias.bin"; request.length = 4;
        if (!Require(metadata.StageMutation(request) == MetadataStore::MutationStatus::UnsupportedOperation &&
                metadata.PendingMutationCount() == 0 && metadata.PendingAllocationCount() == 0,
                "external compression metadata vetoes content admission")) return false;
        for (const auto operation : {MetadataStore::MutationOperation::SetExtendedAttribute,
                MetadataStore::MutationOperation::RemoveExtendedAttribute})
        {
            request.operation = operation;
            request.secondary_path = L"com.apple.decmpfs"; request.length = 0;
            if (!Require(metadata.StageMutation(request) == MetadataStore::MutationStatus::InvalidRequest &&
                    metadata.PendingMutationCount() == 0,
                    "decmpfs cannot be introduced or removed through pending generic xattrs")) return false;
        }
    }
    return true;
}

bool TestOrdinaryEmbeddedAttributesSurviveContentWrites()
{
    using namespace apfsaccess::rw;
    const AppleXattrRecord preserved{17, "user.preserved", kAppleXattrDataEmbedded,
        {std::byte{0}, std::byte{0xff}, std::byte{0x43}}};
    const auto bytes = BuildFileContentAttributeImage(preserved);
    if (!Require(!bytes.empty(), "ordinary content attribute fixture builds")) return false;
    TempImageFile image(bytes, "ordinary-content-attributes");
    MetadataStore::VolumeContext context;
    context.device_path = image.path.wstring(); context.volume_object_id = 101;
    context.allow_legacy_scaffold_for_fixtures = false;
    std::vector<std::byte> payload{std::byte{0x51}, std::byte{0}, std::byte{0xff}, std::byte{0x19}};
    const std::vector<std::byte> added{std::byte{0xff}, std::byte{0}, std::byte{0x71}};
    for (unsigned int phase = 0; phase != 3; ++phase)
    {
        MetadataStore metadata(context);
        if (!Require(metadata.PrepareNativeWritePath(), "ordinary content image prepares")) return false;
        if (phase == 1) payload.resize(2);
        if (phase == 2) payload.resize(9, std::byte{0});
        metadata.SetFilePayloadProvider([&](const auto&, auto) -> std::optional<std::vector<std::byte>> {
            return payload;
        });
        MetadataStore::MutationRequest content;
        content.path = L"\\original"; content.length = payload.size();
        content.operation = phase == 0 ? MetadataStore::MutationOperation::Write :
            MetadataStore::MutationOperation::SetFileSize;
        MetadataStore::PayloadIdentity attribute_identity;
        if (phase == 0)
        {
            MetadataStore::MutationRequest set;
            set.operation = MetadataStore::MutationOperation::SetExtendedAttribute;
            set.path = content.path; set.secondary_path = L"user.binary";
            set.inline_payload = added; set.length = added.size();
            if (!Require(metadata.StageMutation(set, &attribute_identity) == MetadataStore::MutationStatus::Applied &&
                    !metadata.LookupCommittedExtendedAttribute(17, "user.binary"),
                    "ordinary attribute is accepted but unpublished before content write")) return false;
        }
        MetadataStore::PayloadIdentity content_identity;
        if (!Require(metadata.StageMutation(content, &content_identity) == MetadataStore::MutationStatus::Applied,
                "ordinary attribute owner stages content write or resize")) return false;
        if (phase == 0 && !Require(attribute_identity.object_id == content_identity.object_id &&
                attribute_identity.generation == content_identity.generation,
                "attribute and content share the accepted inode generation")) return false;
        if (!Require(metadata.CommitPendingMutations() == MetadataStore::CommitStatus::Committed,
                "ordinary embedded attributes permit content publication")) return false;
        MetadataStore reopened(context);
        if (!Require(reopened.PrepareNativeWritePath(), "ordinary content checkpoint reopens")) return false;
        const auto original = reopened.LookupCommittedExtendedAttribute(17, preserved.name_utf8);
        const auto binary = reopened.LookupCommittedExtendedAttribute(17, "user.binary");
        const auto inode = reopened.LookupCommittedInodeByPath(content.path);
        std::vector<std::byte> actual;
        if (!Require(original && original->flags == preserved.flags && original->data == preserved.data &&
                binary && binary->flags == kAppleXattrDataEmbedded && binary->data == added &&
                inode && inode->logical_size == payload.size() &&
                reopened.ReadCommittedFileRange(content.path, 0, payload.size(), actual) && actual == payload,
                "fresh reopen preserves binary attributes and exact written or resized content")) return false;
    }
    return true;
}

bool TestContentWritesRefuseProtectedAttributes()
{
    using namespace apfsaccess::rw;
    const std::vector<AppleXattrRecord> attributes{
        {17, "com.apple.decmpfs", kAppleXattrDataEmbedded, {std::byte{0}}},
        {17, "com.apple.ResourceFork", static_cast<std::uint16_t>(kAppleXattrDataEmbedded | kAppleXattrFileSystemOwned), {std::byte{0xff}}},
        {17, "com.apple.fs.private", kAppleXattrDataEmbedded, {std::byte{0x19}}},
        {17, "user.filesystem-owned", static_cast<std::uint16_t>(kAppleXattrDataEmbedded | kAppleXattrFileSystemOwned), {std::byte{0x51}}},
        {17, "user.unknown-flags", static_cast<std::uint16_t>(kAppleXattrDataEmbedded | 0x8000), {std::byte{0x43}}},
    };
    for (const auto& attribute : attributes)
    {
        const auto bytes = BuildFileContentAttributeImage(attribute);
        if (!Require(!bytes.empty(), "protected content attribute fixture builds")) return false;
        TempImageFile image(bytes, "protected-content-attributes");
        MetadataStore::VolumeContext context;
        context.device_path = image.path.wstring(); context.volume_object_id = 101;
        context.allow_legacy_scaffold_for_fixtures = false;
        MetadataStore metadata(context);
        if (!Require(metadata.PrepareNativeWritePath(), "protected content image prepares")) return false;
        metadata.SetFilePayloadProvider([](const auto&, auto) -> std::optional<std::vector<std::byte>> {
            return std::vector<std::byte>(4, std::byte{0x5a});
        });
        MetadataStore::MutationRequest write;
        write.operation = MetadataStore::MutationOperation::Write;
        write.path = L"\\original"; write.length = 4;
        std::vector<std::byte> after;
        if (attribute.name_utf8 == "com.apple.decmpfs")
        {
            if (!Require(metadata.StageMutation(write) == MetadataStore::MutationStatus::UnsupportedOperation &&
                    metadata.PendingMutationCount() == 0 && metadata.Device().Read(0, bytes.size(), after) && after == bytes,
                    "decmpfs now refuses before staging and publication")) return false;
        }
        else if (!Require(metadata.StageMutation(write) == MetadataStore::MutationStatus::Applied &&
                metadata.CommitPendingMutations() == MetadataStore::CommitStatus::InvariantFailed &&
                metadata.LastCommitFailureReason() == L"AppleCommitContentExtendedRecordsUnsupported" &&
                metadata.PendingMutationCount() == 1 &&
                metadata.Device().Read(0, bytes.size(), after) && after == bytes,
                "protected attribute refuses content publication without disk changes: " + attribute.name_utf8)) return false;
        MetadataStore reopened(context);
        if (!Require(reopened.PrepareNativeWritePath(), "refused content image reopens")) return false;
        const auto fresh = reopened.LookupCommittedExtendedAttribute(17, attribute.name_utf8);
        const auto inode = reopened.LookupCommittedInodeByPath(write.path);
        if (!Require(fresh && fresh->flags == attribute.flags && fresh->data == attribute.data &&
                inode && inode->logical_size == 0,
                "refused content keeps durable attribute and file size: " + attribute.name_utf8)) return false;
    }
    return true;
}

bool TestExternalAttributesSurviveContentWrites(bool resource_fork = false)
{
    using namespace apfsaccess::rw;
    const auto attribute_name = resource_fork ? "com.apple.ResourceFork" : "user.external";
    for (const bool shared : {false, true})
    {
        ExternalXattrFixtureSpec spec;
        spec.attribute_name = attribute_name;
        spec.block_count = 1024;
        spec.high_inode_id = spec.attribute_owner_inode = 17;
        spec.share_external_with_root = shared;
        spec.stream_reference_count = shared ? 2 : 1;
        std::vector<std::byte> descriptor;
        TempImageFile image(BuildExternalXattrRangeImage(spec, descriptor), "external-content-preservation");
        MetadataStore::VolumeContext context;
        context.device_path = image.path.wstring(); context.volume_object_id = 101;
        context.allow_legacy_scaffold_for_fixtures = false;
        const auto raw_stream = [&]()
        {
            std::vector<std::pair<std::vector<std::byte>, std::vector<std::byte>>> result;
            apfsaccess::catalog::HeldFileSource source(image.path.string());
            std::string error;
            const auto view = LoadAppleCheckpointView(source, 0, source.SizeBytes(), error);
            if (!Require(view.has_value(), "external preservation raw checkpoint loads")) return result;
            const auto& volume = view->volumes.front();
            std::vector<apfsaccess::catalog::BtreeRecord> records;
            if (!Require(apfsaccess::catalog::ReadBtreeLeafRecords(source, view->container.superblock.block_size,
                    volume.root_tree.physical_block, false, volume.superblock.omap_oid,
                    view->container.superblock.xid, records, error), "external preservation raw tree loads")) return result;
            for (const auto& record : records)
            {
                const auto key = apfsaccess::catalog::ReadU64LE(record.key, 0).value_or(0);
                const auto type = key >> 60;
                if (type == 4 || ((type == 6 || type == 8) && (key & 0x0fffffffffffffffULL) == kExternalXattrStreamId))
                    result.emplace_back(record.key, record.value);
            }
            return result;
        };
        const auto original_records = raw_stream();
        if (!Require(original_records.size() == (shared ? 5 : 4), "external preservation binds descriptor, reference and both extents")) return false;
        std::vector<std::byte> external(static_cast<std::size_t>(spec.logical_size));
        {
            MetadataStore initial(context);
            std::size_t read = 0;
            if (!Require(initial.PrepareNativeWritePath() &&
                    initial.ReadCommittedExtendedAttributeRange(17, attribute_name, 0, external, read) && read == external.size(),
                    "external preservation reads independently allocated original stream")) return false;
        }
        std::vector<std::byte> payload(9000);
        for (std::size_t i = 0; i < payload.size(); ++i) payload[i] = static_cast<std::byte>((i * 7 + 5) % 251);
        for (unsigned phase = 0; phase != 4; ++phase)
        {
            MetadataStore metadata(context);
            if (!Require(metadata.PrepareNativeWritePath(), "external content checkpoint prepares")) return false;
            if (phase == 1) payload.resize(2048);
            if (phase == 2) payload.resize(12000, std::byte{0});
            if (phase == 3) payload.clear();
            metadata.SetFilePayloadProvider([&](const auto&, auto) -> std::optional<std::vector<std::byte>> { return payload; });
            MetadataStore::MutationRequest request;
            request.path = L"\\alias.bin";
            request.operation = phase == 0 ? MetadataStore::MutationOperation::Write : MetadataStore::MutationOperation::SetFileSize;
            request.length = payload.size();
            if (!Require(metadata.StageMutation(request) == MetadataStore::MutationStatus::Applied,
                    "external owner content stages")) return false;
            std::vector<std::byte> before, after;
            if (phase == 0)
            {
                if (!Require(metadata.Device().Read(0, static_cast<std::size_t>(std::filesystem::file_size(image.path)), before),
                        "external preservation preimage reads")) return false;
                metadata.SetCommitStageHook([](std::string_view stage) { return stage != "before-apple-publish"; });
                const auto interrupted = metadata.CommitPendingMutations();
                if (!Require(interrupted == MetadataStore::CommitStatus::PersistFailed &&
                        metadata.LastCommitFailureReason() == L"AppleCommitInterruptedBeforePublish" &&
                        metadata.Device().Read(0, before.size(), after) && before == after,
                        "external preservation publication interruption keeps original image"))
                {
                    std::wcerr << L"External preservation status=" << static_cast<unsigned>(interrupted)
                        << L" reason=" << metadata.LastCommitFailureReason() << L" detail=" << metadata.LastCommitFailureDetail() << '\n';
                    return false;
                }
                metadata.SetCommitStageHook({});
            }
            if (!Require(metadata.CommitPendingMutations() == MetadataStore::CommitStatus::Committed,
                    "content publication preserves validated external attribute")) return false;
            MetadataStore reopened(context);
            if (!Require(reopened.PrepareNativeWritePath(), "external content fresh reopen")) return false;
            std::vector<std::byte> actual;
            std::vector<std::byte> actual_external(external.size());
            std::size_t read = 0;
            const auto attribute = reopened.LookupCommittedExtendedAttribute(17, attribute_name);
            const auto inode = reopened.LookupCommittedInodeByPath(request.path);
            if (!Require(inode && inode->object_id == 17 && inode->logical_size == payload.size() &&
                    attribute && attribute->data == descriptor && attribute->flags == kAppleXattrDataStream &&
                    reopened.ReadCommittedFileRange(request.path, 0, payload.size(), actual) && actual == payload &&
                    reopened.ReadCommittedExtendedAttributeRange(17, attribute_name, 0, actual_external, read) &&
                    read == external.size() && actual_external == external && raw_stream() == original_records,
                    "main content, external bytes, stream ownership and exact raw records survive reopen")) return false;
            if (shared)
            {
                std::fill(actual_external.begin(), actual_external.end(), std::byte{0});
                if (!Require(reopened.ReadCommittedExtendedAttributeRange(2, "user.shared-external", 0, actual_external, read) &&
                        read == external.size() && actual_external == external,
                        "second attribute owner retains the same shared stream")) return false;
            }
        }
    }
    return true;
}

bool TestExternalAttributeRemovalRetiresOnlyLastOwner(bool resource_fork = false)
{
    using namespace apfsaccess::rw;
    const auto attribute_name = resource_fork ? "com.apple.ResourceFork" : "user.external";
    const auto attribute_wname = resource_fork ? L"com.apple.ResourceFork" : L"user.external";
    for (const bool empty : {false, true})
    for (const bool shared : {false, true})
    for (const unsigned operation : {0u, 1u, 2u, 3u})
    {
        const bool replace = operation == 1 || operation == 3;
        const bool external_replacement = operation == 3;
        const bool unlink = operation == 2;
        ExternalXattrFixtureSpec spec;
        spec.attribute_name = attribute_name;
        spec.block_count = 1024;
        spec.high_inode_id = spec.attribute_owner_inode = 17;
        spec.share_external_with_root = shared;
        spec.stream_reference_count = shared ? 2 : 1;
        spec.second_file_alias = unlink;
        if (empty)
        {
            spec.logical_size = spec.allocated_size = 0;
            spec.extents.clear();
            spec.physical_extents.clear();
        }
        std::vector<std::byte> descriptor;
        TempImageFile image(BuildExternalXattrRangeImage(spec, descriptor), "external-removal");
        MetadataStore::VolumeContext context;
        context.device_path = image.path.wstring(); context.volume_object_id = 101;
        context.allow_legacy_scaffold_for_fixtures = false;
        std::vector<std::byte> original(static_cast<std::size_t>(spec.logical_size));
        {
            MetadataStore before(context);
            std::size_t read = 0;
            if (!Require(before.PrepareNativeWritePath() &&
                    before.ReadCommittedExtendedAttributeRange(17, attribute_name, 0, original, read) &&
                    read == original.size(), "external removal starts from a validated stream")) return false;
            if (unlink)
            {
                MetadataStore::MutationRequest write;
                write.operation = MetadataStore::MutationOperation::Write;
                write.path = L"\\alias.bin";
                const std::vector<std::byte> payload(6000, std::byte{0x61});
                before.SetFilePayloadProvider([&](const auto&, auto) -> std::optional<std::vector<std::byte>> { return payload; });
                write.length = payload.size();
                if (!Require(before.StageMutation(write) == MetadataStore::MutationStatus::Applied &&
                        before.CommitPendingMutations() == MetadataStore::CommitStatus::Committed,
                        "external owner has independently allocated main-file data"))
                {
                    std::wcerr << before.LastMutationFailureReason() << L"; "
                        << before.LastCommitFailureReason() << L": " << before.LastCommitFailureDetail() << '\n';
                    return false;
                }
                MetadataStore::MutationRequest remove_alias;
                remove_alias.operation = MetadataStore::MutationOperation::Delete;
                remove_alias.path = L"\\second.bin";
                std::optional<UnlinkOutcome> outcome;
                if (!Require(before.StageMutation(remove_alias, nullptr, &outcome) == MetadataStore::MutationStatus::Applied &&
                        outcome && outcome->links_before == 2 && outcome->links_after == 1 &&
                        before.CommitPendingMutations() == MetadataStore::CommitStatus::Committed,
                        "first hard-link deletion retains the external attribute owner")) return false;
                MetadataStore one_link(context);
                std::vector<std::byte> observed(original.size());
                if (!Require(one_link.PrepareNativeWritePath() &&
                        !one_link.LookupCommittedInodeByPath(L"\\second.bin") &&
                        one_link.ReadCommittedExtendedAttributeRange(17, attribute_name, 0, observed, read) &&
                        read == original.size() && observed == original,
                        "first unlink preserves the complete external payload after reopening")) return false;
            }
        }
        for (unsigned phase = 0; phase != (shared ? 2u : 1u); ++phase)
        {
            MetadataStore metadata(context);
            if (!Require(metadata.PrepareNativeWritePath(), "external removal prepares")) return false;
            MetadataStore::MutationRequest remove;
            remove.operation = MetadataStore::MutationOperation::RemoveExtendedAttribute;
            remove.path = phase == 0 ? L"\\alias.bin" : L"\\";
            remove.secondary_path = phase == 0 ? attribute_wname : L"user.shared-external";
            if (replace)
            {
                remove.operation = MetadataStore::MutationOperation::SetExtendedAttribute;
                remove.inline_payload = {std::byte{0}, std::byte{0xff}, std::byte{0x43}};
                if (external_replacement) remove.inline_payload.resize(9001, std::byte{0x72});
                remove.length = remove.inline_payload.size();
            }
            if (unlink && phase == 0)
            {
                remove.operation = MetadataStore::MutationOperation::Delete;
                remove.secondary_path.clear();
            }
            if (!Require(metadata.StageMutation(remove) == MetadataStore::MutationStatus::Applied,
                    "external removal stages for a validated owner")) return false;
            std::vector<std::byte> before, after;
            if (!Require(metadata.Device().Read(0, static_cast<std::size_t>(std::filesystem::file_size(image.path)), before),
                    "external removal preimage reads")) return false;
            metadata.SetCommitStageHook([](std::string_view stage) { return stage != "before-apple-publish"; });
            if (!Require(metadata.CommitPendingMutations() == MetadataStore::CommitStatus::PersistFailed &&
                    metadata.LastCommitFailureReason() == L"AppleCommitInterruptedBeforePublish" &&
                    metadata.Device().Read(0, before.size(), after) && before == after,
                    "external removal interruption preserves descriptor, references and allocation"))
            {
                std::wcerr << L"empty=" << empty << L" shared=" << shared << L" phase=" << phase << L" "
                    << metadata.LastCommitFailureReason() << L": " << metadata.LastCommitFailureDetail() << '\n';
                return false;
            }
            metadata.SetCommitStageHook({});
            if (!Require(metadata.CommitPendingMutations() == MetadataStore::CommitStatus::Committed,
                    "external removal publishes atomically"))
            {
                std::wcerr << metadata.LastCommitFailureReason() << L": " << metadata.LastCommitFailureDetail() << '\n';
                return false;
            }
            MetadataStore reopened(context);
            if (!Require(reopened.PrepareNativeWritePath(), "retired external stream checkpoint reopens")) return false;
            const auto final_attribute = reopened.LookupCommittedExtendedAttribute(phase == 0 ? 17 : 2,
                phase == 0 ? attribute_name : "user.shared-external");
            if (!Require(replace ? final_attribute && (external_replacement
                    ? final_attribute->flags == kAppleXattrDataStream
                    : final_attribute->flags == kAppleXattrDataEmbedded && final_attribute->data == remove.inline_payload) : !final_attribute,
                    "external attribute removal or inline replacement survives fresh reopen")) return false;
            if (external_replacement)
            {
                std::vector<std::byte> payload(remove.inline_payload.size()); std::size_t read = 0;
                const auto new_id = apfsaccess::catalog::ReadU64LE(final_attribute->data, 0).value_or(0);
                if (!Require(new_id >= 0x6000 && new_id != kExternalXattrStreamId && new_id != 17 &&
                        reopened.ReadCommittedExtendedAttributeRange(phase == 0 ? 17 : 2,
                            phase == 0 ? attribute_name : "user.shared-external", 0, payload, read) &&
                        read == payload.size() && payload == remove.inline_payload,
                        "external replacement uses a new stream and reopens with exact binary bytes")) return false;
            }
            if (unlink && !Require(!reopened.LookupCommittedInodeByPath(L"\\alias.bin") &&
                    !reopened.LookupCommittedInodeByPath(L"\\second.bin"),
                    "last unlink removes the exact inode and both former paths")) return false;
            const bool retained = shared && phase == 0;
            if (retained)
            {
                std::vector<std::byte> bytes(original.size()); std::size_t read = 0;
                if (!Require(reopened.ReadCommittedExtendedAttributeRange(2, "user.shared-external", 0, bytes, read) &&
                        read == original.size() && bytes == original, "shared owner retains all original bytes")) return false;
            }
            apfsaccess::catalog::HeldFileSource source(image.path.string());
            std::string error;
            const auto view = LoadAppleCheckpointView(source, 0, source.SizeBytes(), error);
            if (!Require(view.has_value(), "external removal raw checkpoint loads")) return false;
            const auto& volume = view->volumes.front();
            std::vector<apfsaccess::catalog::BtreeRecord> records;
            if (!Require(apfsaccess::catalog::ReadBtreeLeafRecords(source, view->container.superblock.block_size,
                    volume.root_tree.physical_block, false, volume.superblock.omap_oid,
                    view->container.superblock.xid, records, error), "external removal raw tree loads")) return false;
            unsigned references = 0, extents = 0;
            for (const auto& record : records)
            {
                const auto key = apfsaccess::catalog::ReadU64LE(record.key, 0).value_or(0);
                if (unlink && !Require((key & 0x0fffffffffffffffULL) != 17,
                        "last unlink retires the main inode and main data records")) return false;
                if ((key & 0x0fffffffffffffffULL) != kExternalXattrStreamId) continue;
                if ((key >> 60) == 6)
                {
                    AppleDataStreamIdRecord ref;
                    if (!Require(DecodeAppleDataStreamIdRecord(record, ref, error) && ref.reference_count == 1,
                            "remaining reference count equals actual owner count")) return false;
                    ++references;
                }
                if ((key >> 60) == 8) ++extents;
            }
            if (!Require(references == (retained ? 1u : 0u) && extents == (retained && !empty ? 2u : 0u),
                    "last owner retires reference and all extent records including empty streams")) return false;
            records.clear();
            if (!Require(volume.extentref_tree && apfsaccess::catalog::ReadBtreeLeafRecords(source,
                    view->container.superblock.block_size, volume.extentref_tree->physical_block, true, 0,
                    view->container.superblock.xid, records, error), "external removal physical extent tree loads")) return false;
            unsigned physical = 0;
            for (const auto& record : records)
            {
                ApplePhysicalExtentRecord extent;
                if (!Require(DecodeApplePhysicalExtentRecord(record, extent, error), "external removal physical extent decodes")) return false;
                if (unlink && !Require(extent.owning_object_id != 17,
                        "last unlink retires main-file physical ownership independently")) return false;
                if (extent.owning_object_id == kExternalXattrStreamId) physical += static_cast<unsigned>(extent.block_count);
            }
            if (!Require(physical == (retained && !empty ? 2u : 0u),
                    "physical allocation references retire only with their last attribute owner")) return false;
        }
    }
    return true;
}

bool TestTransactionalExternalAttributeWrites(bool resource_fork = false)
{
    using namespace apfsaccess::rw;
    const auto name = resource_fork ? "com.apple.ResourceFork" : "user.new";
    ExternalXattrFixtureSpec spec;
    spec.block_count = 4096;
    spec.high_inode_id = spec.attribute_owner_inode = 17;
    std::vector<std::byte> descriptor;
    TempImageFile image(BuildExternalXattrRangeImage(spec, descriptor), "new-external-attributes");
    MetadataStore::VolumeContext context;
    context.device_path = image.path.wstring(); context.volume_object_id = 101;
    context.allow_legacy_scaffold_for_fixtures = false;
    for (const std::size_t size : {std::size_t{3804}, std::size_t{3805}, std::size_t{1024 * 1024}, std::size_t{0}})
    {
        MetadataStore metadata(context);
        if (!Require(metadata.PrepareNativeWritePath(), "new external attribute prepares")) return false;
        MetadataStore::MutationRequest set;
        set.operation = MetadataStore::MutationOperation::SetExtendedAttribute;
        set.path = L"\\alias.bin"; set.secondary_path = resource_fork ? L"com.apple.ResourceFork" : L"user.new";
        set.inline_payload.resize(size);
        for (std::size_t i = 0; i < size; ++i) set.inline_payload[i] = static_cast<std::byte>((i * 17 + 31) % 251);
        set.length = size;
        if (!Require(metadata.StageMutation(set) == MetadataStore::MutationStatus::Applied,
                "boundary attribute stages")) return false;
        auto other = set; other.secondary_path = L"user.second";
        if (!Require(metadata.StageMutation(other) == MetadataStore::MutationStatus::Applied,
                "two external attribute identities stage in one transaction")) return false;
        const auto pending = metadata.LookupWorkingExtendedAttribute(17, name);
        if (!Require(pending && pending->data == set.inline_payload, "pending external value exposes exact logical bytes")) return false;
        std::vector<std::byte> before, after;
        if (!Require(metadata.Device().Read(0, static_cast<std::size_t>(std::filesystem::file_size(image.path)), before),
                "new external attribute preimage reads")) return false;
        metadata.SetCommitStageHook([](std::string_view stage) { return stage != "before-apple-publish"; });
        if (!Require(metadata.CommitPendingMutations() == MetadataStore::CommitStatus::PersistFailed &&
                metadata.LastCommitFailureReason() == L"AppleCommitInterruptedBeforePublish" &&
                metadata.Device().Read(0, before.size(), after) && before == after,
                "new external allocation interruption leaves all old image bytes unchanged"))
        {
            std::wcerr << metadata.LastCommitFailureReason() << L": " << metadata.LastCommitFailureDetail() << '\n';
            return false;
        }
        metadata.SetCommitStageHook({});
        if (!Require(metadata.CommitPendingMutations() == MetadataStore::CommitStatus::Committed,
                "new external allocation publishes on retry")) return false;
        MetadataStore reopened(context);
        if (!Require(reopened.PrepareNativeWritePath() && reopened.VerifyIntegrity(),
                "new external checkpoint passes fresh integrity")) return false;
        std::set<std::uint64_t> stream_ids;
        for (const auto current_name : {name, "user.second"})
        {
            const auto attribute = reopened.LookupCommittedExtendedAttribute(17, current_name);
            std::vector<std::byte> actual(size); std::size_t read = 0;
            if (!Require(attribute && attribute->flags == (size > 3804 ? kAppleXattrDataStream : kAppleXattrDataEmbedded) &&
                    reopened.ReadCommittedExtendedAttributeRange(17, current_name, 0, actual, read) &&
                    read == size && actual == set.inline_payload,
                    "new external/embedded boundaries preserve every byte after fresh reopen")) return false;
            if (size > 3804)
            {
                const auto id = apfsaccess::catalog::ReadU64LE(attribute->data, 0).value_or(0);
                if (!Require(id >= 0x6000 && stream_ids.insert(id).second,
                        "each newly allocated external attribute gets a distinct reserved identity")) return false;
            }
        }
        const auto preserved = reopened.LookupCommittedExtendedAttribute(17, "user.external");
        if (!Require(preserved && preserved->data == descriptor, "unmodified external descriptor stays byte-identical")) return false;
    }
    return true;
}

bool TestNewExternalAttributePlannerRejectsInvalidBindings()
{
    using namespace apfsaccess::rw;
    ExternalXattrFixtureSpec spec;
    spec.block_count = 1024; spec.high_inode_id = spec.attribute_owner_inode = 17;
    std::vector<std::byte> original;
    TempImageFile image(BuildExternalXattrRangeImage(spec, original), "new-external-invalid");
    apfsaccess::catalog::HeldFileSource source(image.path.string());
    std::string error;
    const auto view = LoadAppleCheckpointView(source, 0, source.SizeBytes(), error);
    if (!Require(view && view->volumes.size() == 1, "new external planner checkpoint loads")) return false;
    const auto& volume = view->volumes.front();
    std::vector<apfsaccess::catalog::BtreeRecord> records;
    if (!Require(apfsaccess::catalog::ReadBtreeLeafRecords(source, view->container.superblock.block_size,
            volume.root_tree.physical_block, false, volume.superblock.omap_oid, view->container.superblock.xid,
            records, error), "new external planner raw records load")) return false;
    const auto id = volume.superblock.next_object_id;
    for (unsigned probe = 0; probe != 22; ++probe)
    {
        AppleVolumeTransactionRequest request;
        request.volume_object_id = 101; request.filesystem_records = records;
        AppleVolumeDataWrite data;
        data.file_private_id = id; data.bytes.assign(5000, std::byte{0x73});
        request.data_writes.push_back(data);
        AppleXattrRecord attribute{17, "user.new", kAppleXattrDataStream,
            std::vector<std::byte>(kAppleXattrDataStreamBytes, std::byte{0})};
        PutU64LE(attribute.data, 0, id); PutU64LE(attribute.data, 8, 5000);
        PutU64LE(attribute.data, 16, 8192); PutU64LE(attribute.data, 32, 5000);
        if (probe == 1) request.data_writes.clear();
        if (probe == 2) request.data_writes.push_back(data);
        if (probe == 3) PutU64LE(attribute.data, 8, 5001);
        if (probe == 4) PutU64LE(attribute.data, 16, 12288);
        if (probe == 5) PutU64LE(attribute.data, 24, 1);
        if (probe == 6) attribute.object_id = 999;
        if (probe == 7) attribute.flags |= kAppleXattrFileSystemOwned;
        if (probe == 11 || probe >= 17) attribute.name_utf8 = "com.apple.ResourceFork";
        if (probe == 12) attribute.name_utf8 = "com.apple.fs.opaque";
        if (probe == 13) attribute.name_utf8 = "com.apple.decmpfs";
        if (probe == 8 || probe == 14 || probe == 17 || probe == 18 || probe == 19 || probe == 20)
        {
            for (auto& record : request.filesystem_records)
            {
                const auto key = apfsaccess::catalog::ReadU64LE(record.key, 0).value_or(0);
                if ((key >> 60) != 3 || (key & 0x0fffffffffffffffULL) != 17) continue;
                AppleInodeRecord inode;
                if (!Require(ApfsExtendedRecordCodec::DecodeInode(record, inode, error), "new stream alias decodes")) return false;
                if (probe == 8) inode.private_id = id;
                else if (probe == 17) inode.mode = 0040755;
                else if (probe == 18) inode.mode = 0120777;
                else if (probe == 20) inode.private_id = 42;
                else if (probe == 14) inode.bsd_flags |= 0x20;
                if (!Require(EncodeAppleInodeRecord(inode, record, error), "new stream alias encodes")) return false;
                // Reach the raw planner with an identity the encoder would refuse.
                if (probe == 19) PutU64LE(record.value, 8, 0);
            }
        }
        if (probe == 21)
        {
            const auto size = WriteAheadLog::MaxExtendedAttributePayloadBytes + 1;
            request.data_writes.front().bytes.resize(size);
            PutU64LE(attribute.data, 8, size);
            PutU64LE(attribute.data, 16, (size + 4095) / 4096 * 4096);
            PutU64LE(attribute.data, 32, size);
        }
        apfsaccess::catalog::BtreeRecord encoded;
        if (probe == 15 || probe == 16)
        {
            AppleXattrRecord marker{probe == 15 ? 17ULL : 2ULL,
                "com.apple.decmpfs", kAppleXattrDataEmbedded, {}};
            if (!Require(EncodeAppleXattrRecord(marker, encoded, error), "compression marker encodes")) return false;
            request.filesystem_records.push_back(encoded);
        }
        if (probe == 9)
        {
            auto duplicate = attribute; duplicate.name_utf8 = "user.duplicate";
            if (!Require(EncodeAppleXattrRecord(duplicate, encoded, error), "second new stream owner encodes")) return false;
            request.filesystem_records.push_back(encoded);
        }
        if (probe == 10) { PutU64LE(attribute.data, 0, id - 1); request.data_writes[0].file_private_id = id - 1; }
        if (!Require(EncodeAppleXattrRecord(attribute, encoded, error), "new stream descriptor encodes")) return false;
        request.filesystem_records.push_back(encoded);
        if (!Require(SortAppleBtreeRecords(request.filesystem_records, AppleBtreeKeyOrder::FileSystemCaseSensitive, error),
                "new stream probe keeps a valid ordered tree")) return false;
        AppleVolumeTransactionPlan plan;
        error.clear();
        const auto planned = PlanAppleVolumeTransaction(source, *view, request, plan, error);
        const bool expected_refusal = probe == 19 ? error == "AppleInodeRecordIdentityInvalid" :
            error.starts_with("AppleVolumeAttribute");
        if (!Require((probe == 0 || probe == 11 || probe == 16) ? planned : !planned && expected_refusal,
                "new external binding probe " + std::to_string(probe) + ": " + error)) return false;
    }
    return true;
}

bool TestExternalAttributeProtectedOwnerMutations()
{
    using namespace apfsaccess::rw;
    for (unsigned probe = 0; probe != 10; ++probe)
    {
        ExternalXattrFixtureSpec spec;
        spec.block_count = 1024; spec.high_inode_id = spec.attribute_owner_inode = 17;
        if (probe == 1 || probe >= 7) spec.attribute_name = "com.apple.ResourceFork";
        if (probe == 2) spec.attribute_name = "com.apple.fs.opaque";
        if (probe == 3) spec.attribute_name = "com.apple.decmpfs";
        if (probe == 4 || probe == 6 || probe == 7 || probe == 9) spec.owner_bsd_flags = 0x20;
        if (probe == 5 || probe == 8) spec.owner_decmpfs = true;
        std::vector<std::byte> descriptor;
        TempImageFile image(BuildExternalXattrRangeImage(spec, descriptor), "protected-external-owner");
        apfsaccess::catalog::HeldFileSource source(image.path.string());
        std::string error;
        const auto view = LoadAppleCheckpointView(source, 0, source.SizeBytes(), error);
        if (!Require(view && view->volumes.size() == 1, "protected-owner checkpoint loads")) return false;
        std::vector<apfsaccess::catalog::BtreeRecord> records;
        const auto& volume = view->volumes.front();
        if (!Require(apfsaccess::catalog::ReadBtreeLeafRecords(source, view->container.superblock.block_size,
                volume.root_tree.physical_block, false, volume.superblock.omap_oid,
                view->container.superblock.xid, records, error), "protected-owner tree loads")) return false;
        AppleVolumeTransactionRequest unchanged;
        unchanged.volume_object_id = 101; unchanged.filesystem_records = records;
        AppleVolumeTransactionPlan plan;
        if (!Require(PlanAppleVolumeTransaction(source, *view, unchanged, plan, error),
                "exact unchanged protected stream can be preserved: " + error)) return false;
        AppleVolumeTransactionRequest removal;
        removal.volume_object_id = 101;
        for (auto record : records)
        {
            const auto key = apfsaccess::catalog::ReadU64LE(record.key, 0).value_or(0);
            const auto type = key >> 60, oid = key & 0x0fffffffffffffffULL;
            if (type == 4 && oid == 17)
            {
                AppleXattrRecord attribute;
                if (!Require(ApfsExtendedRecordCodec::DecodeXattr(record, attribute, error), "protected attribute decodes")) return false;
                if (attribute.name_utf8 == spec.attribute_name) continue;
            }
            if ((type == 6 || type == 8) && oid == kExternalXattrStreamId) continue;
            if ((probe == 6 || probe == 9) && type == 3 && oid == 17)
            {
                AppleInodeRecord inode;
                if (!Require(ApfsExtendedRecordCodec::DecodeInode(record, inode, error), "compressed inode decodes")) return false;
                inode.bsd_flags = 0;
                if (!Require(EncodeAppleInodeRecord(inode, record, error), "cleared compression flag encodes")) return false;
            }
            removal.filesystem_records.push_back(std::move(record));
        }
        for (const auto& extent : spec.extents)
            removal.released_data_blocks.push_back({extent.physical_block, extent.length_bytes / extent.block_size});
        const auto planned = PlanAppleVolumeTransaction(source, *view, removal, plan, error);
        if (!Require((probe == 0 || probe == 1) ? planned : !planned && error == "AppleVolumeAttributeContentTransformUnsupported",
                "ordinary fork retires; protected owner refuses including same-request flag clearing: " + error)) return false;

        MetadataStore::VolumeContext context;
        context.device_path = image.path.wstring(); context.volume_object_id = 101;
        context.allow_legacy_scaffold_for_fixtures = false;
        MetadataStore metadata(context);
        if (!Require(metadata.PrepareNativeWritePath(), "protected-owner staging loads")) return false;
        MetadataStore::MutationRequest request;
        request.operation = MetadataStore::MutationOperation::RemoveExtendedAttribute;
        request.path = L"\\alias.bin";
        request.secondary_path.assign(spec.attribute_name.begin(), spec.attribute_name.end());
        const auto staged = metadata.StageMutation(request);
        if (!Require((probe == 0 || probe == 1) ? staged == MetadataStore::MutationStatus::Applied :
                staged != MetadataStore::MutationStatus::Applied,
                "ordinary fork retirement stages; protected attribute retirement refuses")) return false;
    }
    return true;
}

bool TestExternalAttributeRetirementPlannerRejectsInvalidOwnership()
{
    using namespace apfsaccess::rw;
    for (const bool shared : {false, true})
    {
        ExternalXattrFixtureSpec spec;
        spec.block_count = 1024;
        spec.high_inode_id = spec.attribute_owner_inode = 17;
        spec.share_external_with_root = shared;
        spec.stream_reference_count = shared ? 2 : 1;
        std::vector<std::byte> descriptor;
        TempImageFile image(BuildExternalXattrRangeImage(spec, descriptor), "external-retirement-invalid");
        apfsaccess::catalog::HeldFileSource source(image.path.string());
        std::string error;
        const auto view = LoadAppleCheckpointView(source, 0, source.SizeBytes(), error);
        if (!Require(view.has_value(), "external retirement planner checkpoint loads")) return false;
        const auto& volume = view->volumes.front();
        std::vector<apfsaccess::catalog::BtreeRecord> records;
        if (!Require(apfsaccess::catalog::ReadBtreeLeafRecords(source, view->container.superblock.block_size,
                volume.root_tree.physical_block, false, volume.superblock.omap_oid,
                view->container.superblock.xid, records, error), "external retirement planner tree loads")) return false;
        const auto type = [](const auto& record) { return apfsaccess::catalog::ReadU64LE(record.key, 0).value_or(0) >> 60; };
        const auto oid = [](const auto& record) { return apfsaccess::catalog::ReadU64LE(record.key, 0).value_or(0) & 0x0fffffffffffffffULL; };
        AppleVolumeTransactionRequest valid;
        valid.volume_object_id = 101;
        for (const auto& record : records)
        {
            if (type(record) == 4 && oid(record) == 17) continue;
            if (!shared && oid(record) == kExternalXattrStreamId && (type(record) == 6 || type(record) == 8)) continue;
            valid.filesystem_records.push_back(record);
        }
        if (!shared) for (const auto& extent : spec.extents)
            valid.released_data_blocks.push_back({extent.physical_block, extent.length_bytes / extent.block_size});
        AppleVolumeTransactionPlan plan;
        if (!Require(PlanAppleVolumeTransaction(source, *view, valid, plan, error),
                "external retirement planner positive control: " + error)) return false;
        AppleVolumeTransactionRequest unchanged;
        unchanged.volume_object_id = 101; unchanged.filesystem_records = records;
        if (!Require(PlanAppleVolumeTransaction(source, *view, unchanged, plan, error),
                "unchanged external stream planner positive control: " + error)) return false;
        auto aliased = unchanged;
        for (auto& record : aliased.filesystem_records)
        {
            if (type(record) != 3 || oid(record) != 17) continue;
            AppleInodeRecord inode;
            if (!Require(ApfsExtendedRecordCodec::DecodeInode(record, inode, error), "unchanged-stream alias inode decodes")) return false;
            inode.private_id = kExternalXattrStreamId;
            if (!Require(EncodeAppleInodeRecord(inode, record, error), "unchanged-stream alias inode encodes")) return false;
        }
        if (!Require(!PlanAppleVolumeTransaction(source, *view, aliased, plan, error) &&
                error.starts_with("AppleVolumeAttribute"),
                "retained external stream refuses forged inode private-ID ownership: " + error)) return false;
        for (const auto* label : {"reference", "extents", "owner"})
        {
            auto invalid = valid;
            if (std::string_view(label) == "reference")
            {
                if (shared)
                {
                    std::erase_if(invalid.filesystem_records, [&](const auto& record) { return type(record) == 6 && oid(record) == kExternalXattrStreamId; });
                    apfsaccess::catalog::BtreeRecord encoded;
                    if (!Require(EncodeAppleDataStreamIdRecord({kExternalXattrStreamId, 1}, encoded, error), "forged reference encodes")) return false;
                    invalid.filesystem_records.push_back(encoded);
                }
                else for (const auto& record : records) if (type(record) == 6 && oid(record) == kExternalXattrStreamId) invalid.filesystem_records.push_back(record);
            }
            else if (std::string_view(label) == "extents")
            {
                if (shared)
                {
                    std::erase_if(invalid.filesystem_records, [&](const auto& record) { return type(record) == 8 && oid(record) == kExternalXattrStreamId; });
                    for (const auto& extent : spec.extents) invalid.released_data_blocks.push_back({extent.physical_block, extent.length_bytes / extent.block_size});
                }
                else
                {
                    for (const auto& record : records) if (type(record) == 8 && oid(record) == kExternalXattrStreamId) invalid.filesystem_records.push_back(record);
                    invalid.released_data_blocks.clear();
                }
            }
            else
            {
                if (shared)
                {
                    for (auto& record : invalid.filesystem_records)
                    {
                        if (type(record) != 4) continue;
                        AppleXattrRecord attribute;
                        if (!Require(ApfsExtendedRecordCodec::DecodeXattr(record, attribute, error), "remaining owner decodes")) return false;
                        attribute.name_utf8 = "user.forged-owner";
                        if (!Require(EncodeAppleXattrRecord(attribute, record, error), "forged owner encodes")) return false;
                    }
                }
                else for (const auto& record : records) if (type(record) == 4 && oid(record) == 17) invalid.filesystem_records.push_back(record);
            }
            if (!Require(SortAppleBtreeRecords(invalid.filesystem_records, AppleBtreeKeyOrder::FileSystemCaseSensitive, error), "invalid request remains a well-formed sorted tree")) return false;
            error.clear();
            if (!Require(!PlanAppleVolumeTransaction(source, *view, invalid, plan, error) &&
                    error.starts_with("AppleVolumeAttribute"), std::string(label) + " invalid ownership refuses before publication: " + error)) return false;
        }
    }
    return true;
}

bool TestContentWritesSupportPendingResourceFork()
{
    using namespace apfsaccess::rw;
    const auto bytes = BuildFileContentAttributeImage({}, 4096);
    if (!Require(!bytes.empty(), "pending fork fixture builds")) return false;
    TempImageFile image(bytes, "pending-resource-fork-content");
    MetadataStore::VolumeContext context;
    context.device_path = image.path.wstring(); context.volume_object_id = 101;
    context.allow_legacy_scaffold_for_fixtures = false;
    std::uint64_t retired_stream = 0;
    const std::vector<std::size_t> sizes{3805, 1024 * 1024, 3804, 0, 0};
    for (unsigned phase = 0; phase < sizes.size(); ++phase)
    {
        MetadataStore metadata(context);
        if (!Require(metadata.PrepareNativeWritePath(), "pending fork image prepares")) return false;
        MetadataStore::MutationRequest fork;
        fork.operation = phase == 4 ? MetadataStore::MutationOperation::RemoveExtendedAttribute :
            MetadataStore::MutationOperation::SetExtendedAttribute;
        fork.path = L"\\original"; fork.secondary_path = L"com.apple.ResourceFork";
        fork.inline_payload.resize(sizes[phase]); fork.length = sizes[phase];
        for (std::size_t i = 0; i < fork.inline_payload.size(); ++i)
            fork.inline_payload[i] = static_cast<std::byte>((i * 19 + phase) & 255);
        // Payload contents do not classify compression: only owner metadata does.
        if (fork.inline_payload.size() >= 4) PutU32LE(fork.inline_payload, 0, 0x636d7066);
        const std::vector<std::byte> main(phase == 0 ? 9000 : phase == 1 ? 12000 : phase == 2 ? 2 : 0,
            std::byte{0x5a});
        metadata.SetFilePayloadProvider([&](const auto&, auto) -> std::optional<std::vector<std::byte>> { return main; });
        MetadataStore::MutationRequest content;
        content.operation = phase == 0 ? MetadataStore::MutationOperation::Write : MetadataStore::MutationOperation::SetFileSize;
        content.path = fork.path; content.length = main.size();
        MetadataStore::PayloadIdentity fork_identity, main_identity;
        if (!Require(metadata.StageMutation(fork, &fork_identity) == MetadataStore::MutationStatus::Applied &&
                metadata.StageMutation(content, &main_identity) == MetadataStore::MutationStatus::Applied &&
                fork_identity.object_id == main_identity.object_id && fork_identity.generation == main_identity.generation,
                "fork and default data stage against the same inode generation")) return false;
        const auto pending = metadata.LookupWorkingExtendedAttribute(17, "com.apple.ResourceFork");
        if (!Require(phase == 4 ? !pending : pending && pending->data == fork.inline_payload,
                "working lookup distinguishes removal from a present empty fork")) return false;
        auto too_large = fork;
        too_large.operation = MetadataStore::MutationOperation::SetExtendedAttribute;
        too_large.inline_payload.resize(WriteAheadLog::MaxExtendedAttributePayloadBytes + 1);
        too_large.length = too_large.inline_payload.size();
        const auto count = metadata.PendingMutationCount();
        if (!Require(metadata.StageMutation(too_large) != MetadataStore::MutationStatus::Applied &&
                metadata.PendingMutationCount() == count,
                "one MiB plus one refuses without losing accepted fork and main data")) return false;
        if (!Require(metadata.CommitPendingMutations() == MetadataStore::CommitStatus::Committed,
                "simultaneous fork and main-data mutation publishes")) return false;
        MetadataStore reopened(context);
        if (!Require(reopened.PrepareNativeWritePath() && reopened.VerifyIntegrity(), "fork lifecycle reopens intact")) return false;
        std::vector<std::byte> actual;
        if (!Require(reopened.ReadCommittedFileRange(content.path, 0, main.size(), actual) && actual == main,
                "fresh reader returns the independent main-data bytes and size")) return false;
        const auto attribute = reopened.LookupCommittedExtendedAttribute(17, "com.apple.ResourceFork");
        std::vector<std::byte> actual_fork(sizes[phase]); std::size_t read = 0;
        if (!Require(phase == 4 ? !attribute : attribute &&
                reopened.ReadCommittedExtendedAttributeRange(17, "com.apple.ResourceFork", 0, actual_fork, read) &&
                read == sizes[phase] && actual_fork == fork.inline_payload &&
                attribute->flags == (sizes[phase] > 3804 ? kAppleXattrDataStream : kAppleXattrDataEmbedded),
                "fork external, inline, empty and deleted states reopen with exact bytes")) return false;
        apfsaccess::catalog::HeldFileSource source(image.path.string());
        std::string error;
        const auto view = LoadAppleCheckpointView(source, 0, source.SizeBytes(), error);
        if (!Require(view && view->volumes.size() == 1, "fork lifecycle raw checkpoint loads")) return false;
        const auto& volume = view->volumes.front();
        std::vector<apfsaccess::catalog::BtreeRecord> records;
        if (!Require(apfsaccess::catalog::ReadBtreeLeafRecords(source, view->container.superblock.block_size,
                volume.root_tree.physical_block, false, volume.superblock.omap_oid,
                view->container.superblock.xid, records, error), "fork lifecycle raw tree loads")) return false;
        unsigned forks = 0, references = 0;
        const auto current_stream = attribute && attribute->flags == kAppleXattrDataStream ?
            apfsaccess::catalog::ReadU64LE(attribute->data, 0).value_or(0) : 0;
        for (const auto& record : records)
        {
            const auto key = apfsaccess::catalog::ReadU64LE(record.key, 0).value_or(0);
            const auto oid = key & 0x0fffffffffffffffULL;
            const auto type = key >> 60;
            if (!Require(retired_stream == 0 || oid != retired_stream, "replaced fork has no stale stream records")) return false;
            if (type == 4 && oid == 17)
            {
                AppleXattrRecord raw;
                if (!Require(ApfsExtendedRecordCodec::DecodeXattr(record, raw, error), "raw fork decodes")) return false;
                if (raw.name_utf8 == "com.apple.ResourceFork")
                {
                    ++forks;
                    if (!Require(attribute && raw.flags == attribute->flags && raw.data == attribute->data,
                            "raw fork agrees with the reopened descriptor or inline bytes")) return false;
                }
            }
            if (type == 6 && oid == current_stream)
            {
                AppleDataStreamIdRecord ref;
                if (!Require(DecodeAppleDataStreamIdRecord(record, ref, error) && ref.reference_count == 1,
                        "fresh fork stream has exactly one owner")) return false;
                ++references;
            }
        }
        if (!Require(forks == (phase == 4 ? 0u : 1u) && references == (current_stream ? 1u : 0u),
                "raw records distinguish fork existence from stream allocation")) return false;
        if (retired_stream)
        {
            records.clear();
            if (!Require(volume.extentref_tree && apfsaccess::catalog::ReadBtreeLeafRecords(source,
                    view->container.superblock.block_size, volume.extentref_tree->physical_block, true, 0,
                    view->container.superblock.xid, records, error), "retired fork physical tree loads: " + error)) return false;
            for (const auto& record : records)
            {
                ApplePhysicalExtentRecord extent;
                if (!Require(DecodeApplePhysicalExtentRecord(record, extent, error) && extent.owning_object_id != retired_stream,
                        "replaced fork releases its independent physical references")) return false;
            }
        }
        retired_stream = current_stream;
    }
    return true;
}

bool TestResourceForkNewOwnerSameTransaction()
{
    using namespace apfsaccess::rw;
    TempImageFile image(BuildFileContentAttributeImage({}, 1024), "fork-new-owner");
    MetadataStore::VolumeContext context;
    context.device_path = image.path.wstring(); context.volume_object_id = 101;
    context.allow_legacy_scaffold_for_fixtures = false;
    MetadataStore metadata(context);
    if (!Require(metadata.PrepareNativeWritePath(), "new fork owner fixture prepares")) return false;
    MetadataStore::MutationRequest create;
    create.operation = MetadataStore::MutationOperation::CreateFile;
    create.path = L"\\new-owner";
    MetadataStore::PayloadIdentity identity;
    if (!Require(metadata.StageMutation(create, &identity) == MetadataStore::MutationStatus::Applied,
            "new fork owner stages before it exists in the committed tree")) return false;
    MetadataStore::MutationRequest fork;
    fork.operation = MetadataStore::MutationOperation::SetExtendedAttribute;
    fork.path = create.path; fork.secondary_path = L"com.apple.ResourceFork";
    fork.inline_payload.assign(5000, std::byte{0x61}); fork.length = fork.inline_payload.size();
    const std::vector<std::byte> main(8193, std::byte{0x29});
    metadata.SetFilePayloadProvider([&](const auto&, auto) -> std::optional<std::vector<std::byte>> { return main; });
    MetadataStore::MutationRequest write;
    write.operation = MetadataStore::MutationOperation::Write;
    write.path = create.path; write.length = main.size();
    if (!Require(metadata.StageMutation(fork) == MetadataStore::MutationStatus::Applied &&
            metadata.StageMutation(write) == MetadataStore::MutationStatus::Applied &&
            metadata.CommitPendingMutations() == MetadataStore::CommitStatus::Committed,
            "new owner, independent fork and default data publish together")) return false;
    MetadataStore reopened(context);
    if (!Require(reopened.PrepareNativeWritePath() && reopened.VerifyIntegrity(), "new fork owner reopens intact")) return false;
    const auto owner = reopened.LookupCommittedInodeByPath(create.path);
    std::vector<std::byte> actual_main, actual_fork(fork.inline_payload.size());
    std::size_t read = 0;
    if (!Require(owner && owner->object_id == identity.object_id && owner->mode == 0100644 &&
            reopened.ReadCommittedFileRange(create.path, 0, main.size(), actual_main) && actual_main == main &&
            reopened.ReadCommittedExtendedAttributeRange(identity.object_id, "com.apple.ResourceFork", 0, actual_fork, read) &&
            read == actual_fork.size() && actual_fork == fork.inline_payload,
            "fresh lookup binds independent main and fork bytes to the newly reserved inode")) return false;
    MetadataStore::MutationRequest rename;
    rename.operation = MetadataStore::MutationOperation::Rename;
    rename.path = create.path; rename.secondary_path = L"\\new-owner-renamed";
    if (!Require(reopened.StageMutation(rename) == MetadataStore::MutationStatus::Applied &&
            reopened.CommitPendingMutations() == MetadataStore::CommitStatus::Committed,
            "new fork owner rename publishes without changing its identity")) return false;
    MetadataStore renamed(context);
    if (!Require(renamed.PrepareNativeWritePath(), "renamed fork owner reopens")) return false;
    const auto renamed_owner = renamed.LookupCommittedInodeByPath(rename.secondary_path);
    return Require(renamed_owner && renamed_owner->object_id == identity.object_id &&
        !renamed.LookupCommittedInodeByPath(create.path) &&
        renamed.ReadCommittedExtendedAttributeRange(identity.object_id, "com.apple.ResourceFork", 0, actual_fork, read) &&
        read == actual_fork.size() && actual_fork == fork.inline_payload,
        "fork follows inode identity across rename and fresh remount");
}

bool TestResourceForkOwnerPolicyAndPlanner()
{
    using namespace apfsaccess::rw;
    for (unsigned probe = 0; probe != 13; ++probe)
    for (const bool existing : {false, true})
    {
        std::uint16_t mode = 0100644;
        const std::uint32_t flags = probe == 1 ? kAppleBsdCompressedFlag : 0;
        std::optional<std::vector<std::byte>> marker;
        if (probe >= 2 && probe <= 5)
        {
            marker = std::vector<std::byte>(probe == 2 ? 0 : probe == 3 ? 3 : 16, std::byte{0});
            if (marker->size() == 16)
            {
                PutU32LE(*marker, 0, 0x636d7066);
                PutU32LE(*marker, 4, probe == 4 ? 4 : 0xffffffff);
                PutU64LE(*marker, 8, 123);
            }
        }
        if (probe == 6) mode = 0040755;
        if (probe == 7) mode = 0120777;
        if (probe == 8) mode = 0010644;
        if (probe == 9) mode = 0140644;
        if (probe == 10) mode = 0020644;
        if (probe == 11) mode = 0060644;
        AppleXattrRecord fork{17, existing ? "com.apple.ResourceFork" : "", kAppleXattrDataEmbedded,
            {std::byte{0}, std::byte{0xff}, std::byte{0x43}}};
        if (probe == 12 && existing) fork.flags |= kAppleXattrFileSystemOwned;
        const bool supported = probe == 0 || (probe == 12 && !existing);
        const auto bytes = BuildFileContentAttributeImage(fork, 1024, mode, flags, marker);
        if (!Require(!bytes.empty(), "fork owner-policy image builds")) return false;
        TempImageFile image(bytes, "resource-fork-owner-policy");
        MetadataStore::VolumeContext context;
        context.device_path = image.path.wstring(); context.volume_object_id = 101;
        context.allow_legacy_scaffold_for_fixtures = false;
        for (unsigned operation = 0; operation != (existing ? 3u : 2u); ++operation)
        {
            MetadataStore metadata(context);
            if (!Require(metadata.PrepareNativeWritePath(), "fork owner-policy imports probe " +
                    std::to_string(probe) + " existing " + std::to_string(existing))) return false;
            MetadataStore::MutationRequest set;
            set.operation = operation == 2 ? MetadataStore::MutationOperation::RemoveExtendedAttribute :
                MetadataStore::MutationOperation::SetExtendedAttribute;
            set.path = L"\\original"; set.secondary_path = L"com.apple.ResourceFork";
            set.inline_payload.assign(operation == 2 ? 0 : operation == 0 ? 7 : 5000, std::byte{0x73});
            set.length = set.inline_payload.size();
            const auto staged = metadata.StageMutation(set);
            if (!Require(supported ? staged == MetadataStore::MutationStatus::Applied :
                    staged == MetadataStore::MutationStatus::UnsupportedOperation && metadata.PendingMutationCount() == 0,
                    "fork owner staging probe " + std::to_string(probe))) return false;
        }
        apfsaccess::catalog::HeldFileSource source(image.path.string());
        std::string error;
        const auto view = LoadAppleCheckpointView(source, 0, source.SizeBytes(), error);
        if (!Require(view && view->volumes.size() == 1, "fork bypass checkpoint loads")) return false;
        const auto& volume = view->volumes.front();
        std::vector<apfsaccess::catalog::BtreeRecord> records;
        if (!Require(apfsaccess::catalog::ReadBtreeLeafRecords(source, view->container.superblock.block_size,
                volume.root_tree.physical_block, false, volume.superblock.omap_oid,
                view->container.superblock.xid, records, error), "fork bypass raw tree loads")) return false;
        AppleVolumeTransactionRequest unchanged;
        unchanged.volume_object_id = 101; unchanged.filesystem_records = records;
        AppleVolumeTransactionPlan plan;
        if (!Require(PlanAppleVolumeTransaction(source, *view, unchanged, plan, error),
                "unchanged unsupported embedded fork remains preservable: " + error)) return false;
        for (unsigned operation = 0; operation != (existing ? 3u : 2u); ++operation)
        for (const bool disguise : {false, true})
        {
            auto request = unchanged;
            std::erase_if(request.filesystem_records, [&](const auto& record) {
                if ((apfsaccess::catalog::ReadU64LE(record.key, 0).value_or(0) >> 60) != 4) return false;
                AppleXattrRecord attribute;
                if (!ApfsExtendedRecordCodec::DecodeXattr(record, attribute, error)) return false;
                return attribute.object_id == 17 && (attribute.name_utf8 == "com.apple.ResourceFork" ||
                    (disguise && (attribute.name_utf8 == "com.apple.decmpfs" || attribute.name_utf8 == "com.apple.fs.symlink")));
            });
            if (disguise)
                for (auto& record : request.filesystem_records)
                {
                    const auto key = apfsaccess::catalog::ReadU64LE(record.key, 0).value_or(0);
                    if ((key >> 60) != 3 || (key & 0x0fffffffffffffffULL) != 17) continue;
                    AppleInodeRecord inode;
                    if (!Require(ApfsExtendedRecordCodec::DecodeInode(record, inode, error), "original raw owner decodes")) return false;
                    inode.mode = 0100644; inode.bsd_flags = 0; inode.children_or_links = 1;
                    if (!Require(EncodeAppleInodeRecord(inode, record, error), "disguised regular owner encodes")) return false;
                }
            if (operation != 2)
            {
                AppleXattrRecord candidate{17, "com.apple.ResourceFork", kAppleXattrDataEmbedded,
                    std::vector<std::byte>(7, std::byte{0x73})};
                if (operation == 1)
                {
                    const auto id = volume.superblock.next_object_id;
                    candidate.flags = kAppleXattrDataStream;
                    candidate.data.assign(kAppleXattrDataStreamBytes, std::byte{0});
                    PutU64LE(candidate.data, 0, id); PutU64LE(candidate.data, 8, 5000);
                    PutU64LE(candidate.data, 16, 8192); PutU64LE(candidate.data, 32, 5000);
                    AppleVolumeDataWrite data;
                    data.file_private_id = id; data.bytes.assign(5000, std::byte{0x73});
                    request.data_writes.push_back(std::move(data));
                }
                apfsaccess::catalog::BtreeRecord encoded;
                if (!Require(EncodeAppleXattrRecord(candidate, encoded, error), "direct fork candidate encodes")) return false;
                request.filesystem_records.push_back(std::move(encoded));
            }
            if (!Require(SortAppleBtreeRecords(request.filesystem_records, AppleBtreeKeyOrder::FileSystemCaseSensitive, error),
                    "direct fork request sorts")) return false;
            error.clear();
            const bool planned = PlanAppleVolumeTransaction(source, *view, request, plan, error);
            if (!Require(supported ? planned : !planned && error == "AppleVolumeAttributeContentTransformUnsupported",
                    "raw fork owner probe " + std::to_string(probe) + " operation " + std::to_string(operation) +
                    " disguise " + std::to_string(disguise) + ": " + error)) return false;
        }
        std::vector<std::byte> after;
        if (!Require(source.Read(0, bytes.size(), after) && after == bytes,
                "staging and raw planner probes leave the image unchanged")) return false;
    }
    return true;
}

bool TestResourceForkPendingOwnerTransitions()
{
    using namespace apfsaccess::rw;
    for (const bool committed_fork : {false, true})
    {
        AppleXattrRecord fork{17, committed_fork ? "com.apple.ResourceFork" : "", kAppleXattrDataEmbedded, {std::byte{1}}};
        TempImageFile image(BuildFileContentAttributeImage(fork, 1024), "fork-pending-transitions");
        MetadataStore::VolumeContext context;
        context.device_path = image.path.wstring(); context.volume_object_id = 101;
        context.allow_legacy_scaffold_for_fixtures = false;
        MetadataStore metadata(context);
        if (!Require(metadata.PrepareNativeWritePath(), "fork transitions prepare")) return false;
        MetadataStore::MutationRequest set;
        set.operation = MetadataStore::MutationOperation::SetExtendedAttribute;
        set.path = L"\\original"; set.secondary_path = L"com.apple.ResourceFork";
        set.inline_payload = {std::byte{2}}; set.length = 1;
        if (!Require(metadata.StageMutation(set) == MetadataStore::MutationStatus::Applied, "fork transition premise stages")) return false;
        MetadataStore::MutationRequest convert;
        convert.operation = MetadataStore::MutationOperation::SetSymbolicLinkTarget;
        convert.path = set.path; convert.secondary_path = L"./target";
        const auto count = metadata.PendingMutationCount();
        if (!Require(metadata.StageMutation(convert) != MetadataStore::MutationStatus::Applied &&
                metadata.PendingMutationCount() == count, "zero-size regular file cannot become a symlink with a fork")) return false;
        InodeMetadataPatch patch;
        patch.mask = InodeMetadataPatch::BsdFlags; patch.bsd_flags = kAppleBsdCompressedFlag;
        MetadataStore::MutationRequest flags;
        flags.operation = MetadataStore::MutationOperation::SetInodeMetadata; flags.path = set.path;
        if (!Require(EncodeInodeMetadataPatch(patch, flags.inline_payload), "fork flag patch encodes")) return false;
        flags.length = flags.inline_payload.size();
        if (!Require(metadata.StageMutation(flags) == MetadataStore::MutationStatus::UnsupportedOperation &&
                metadata.PendingMutationCount() == count, "later compressed flag cannot invalidate an accepted fork")) return false;
        set.operation = MetadataStore::MutationOperation::RemoveExtendedAttribute;
        set.inline_payload.clear(); set.length = 0;
        if (!Require(metadata.StageMutation(set) == MetadataStore::MutationStatus::Applied, "safe fork removal stages")) return false;
        if (!Require(metadata.StageMutation(convert) != MetadataStore::MutationStatus::Applied,
                "conversion waits for committed or pending-only fork retirement instead of failing late at publication")) return false;
        if (!Require(metadata.StageMutation(flags) == MetadataStore::MutationStatus::UnsupportedOperation &&
                metadata.CommitPendingMutations() == MetadataStore::CommitStatus::Committed,
                "safe removal commits after rejected owner changes")) return false;
        if (!Require(metadata.IsNativeWriteReady() && !metadata.IsRecoveryRequired(),
                "safe fork removal does not degrade the active native write path")) return false;
        MetadataStore reopened(context);
        if (!Require(reopened.PrepareNativeWritePath() &&
                !reopened.LookupCommittedExtendedAttribute(17, "com.apple.ResourceFork") &&
                reopened.StageMutation(convert) == MetadataStore::MutationStatus::Applied &&
                reopened.CommitPendingMutations() == MetadataStore::CommitStatus::Committed,
                "fresh fork-free owner can convert without mount degradation")) return false;
    }
    // Clearing the original compression bit, or converting an original symlink,
    // cannot authorize a fork create later in the same working transaction.
    for (const bool compressed : {false, true})
    {
        TempImageFile image(BuildFileContentAttributeImage({}, 1024, compressed ? 0100644 : 0120777,
            compressed ? kAppleBsdCompressedFlag : 0), "fork-original-owner");
        MetadataStore::VolumeContext context;
        context.device_path = image.path.wstring(); context.volume_object_id = 101;
        context.allow_legacy_scaffold_for_fixtures = false;
        MetadataStore metadata(context);
        if (!Require(metadata.PrepareNativeWritePath(), "original owner prepares")) return false;
        MetadataStore::MutationRequest change;
        change.path = L"\\original";
        change.operation = compressed ? MetadataStore::MutationOperation::SetInodeMetadata :
            MetadataStore::MutationOperation::RemoveSymbolicLinkTarget;
        if (compressed)
        {
            InodeMetadataPatch patch;
            patch.mask = InodeMetadataPatch::BsdFlags; patch.bsd_flags = 0;
            if (!Require(EncodeInodeMetadataPatch(patch, change.inline_payload), "flag clearing encodes")) return false;
            change.length = change.inline_payload.size();
        }
        if (!Require(metadata.StageMutation(change) == (compressed ? MetadataStore::MutationStatus::UnsupportedOperation :
                MetadataStore::MutationStatus::Applied),
                "compression cannot be cleared as a metadata-only change; link removal still stages")) return false;
        MetadataStore::MutationRequest fork;
        fork.path = change.path; fork.secondary_path = L"com.apple.ResourceFork";
        fork.operation = MetadataStore::MutationOperation::SetExtendedAttribute;
        fork.inline_payload = {std::byte{1}}; fork.length = 1;
        if (!Require(metadata.StageMutation(fork) == MetadataStore::MutationStatus::UnsupportedOperation &&
                metadata.PendingMutationCount() == (compressed ? 0 : 1), "original owner still vetoes fork creation")) return false;
    }
    return true;
}

bool TestNativeSpecialNodePreservation()
{
    using namespace apfsaccess::rw;
    bool ok = true;
    for (const std::uint16_t type : {0010000, 0140000, 0020000, 0060000})
    {
        const auto label = "special node " + std::to_string(type) + ": ";
        const auto expected_type = type == 0010000 ? MetadataStore::NodeType::Fifo :
            type == 0140000 ? MetadataStore::NodeType::Socket :
            type == 0020000 ? MetadataStore::NodeType::CharacterDevice : MetadataStore::NodeType::BlockDevice;
        BuilderStore fixture;
        fixture.authoritative_checkpoint = true;
        fixture.volumes[0].incompat = 0;
        auto& records = fixture.volumes[0].filesystem_records;
        std::string error;
        apfsaccess::catalog::BtreeRecord encoded;
        AppleInodeRecord root;
        root.object_id = root.parent_id = root.private_id = 2;
        root.children_or_links = 2; root.mode = 0040755;
        if (!Require(EncodeAppleInodeRecord(root, encoded, error), label + "root encodes")) return false;
        records.push_back(encoded);
        AppleInodeRecord original;
        original.object_id = original.private_id = 17; original.parent_id = 2;
        original.children_or_links = 2; original.mode = type | 0644;
        original.owner = 501; original.group = 20; original.bsd_flags = 0x8002;
        original.create_time = 1037; original.access_time = 4099;
        // Opaque extension preservation only; this is not a device-number ABI.
        const AppleExtendedField opaque{0xf0, 0, {std::byte{0x12}, std::byte{0xab}, std::byte{0x34}}};
        original.extended_fields.push_back(opaque);
        if (!Require(EncodeAppleInodeRecord(original, encoded, error), label + "inode encodes")) return false;
        records.push_back(encoded);
        for (const auto& [name, sibling] :
            {std::pair{"primary", 700ULL}, std::pair{"alias", 701ULL}})
        {
            AppleDirectoryRecord link;
            link.parent_id = 2; link.file_id = 17; link.flags = type >> 12; link.name_utf8 = name;
            if (!Require(EncodeAppleDirectoryRecord(link, encoded, error), label + "DREC encodes")) return false;
            records.push_back(encoded);
            if (!Require(EncodeAppleSiblingLinkRecord({17, sibling, 2, name}, encoded, error),
                    label + "sibling encodes")) return false;
            records.push_back(encoded);
            if (!Require(EncodeAppleSiblingMapRecord({sibling, 17}, encoded, error),
                    label + "sibling map encodes")) return false;
            records.push_back(encoded);
        }
        for (const auto malformed : {"uncompressed", "stream", "empty-stream", "empty-stream-field",
                "extent", "private-extent", "zero-extent", "short-extent"})
        {
            auto invalid = fixture;
            auto bad_inode = original;
            if (std::string(malformed) == "uncompressed") bad_inode.uncompressed_size = 1;
            if (std::string(malformed) == "stream" || std::string(malformed) == "empty-stream")
            {
                bad_inode.extended_fields.push_back({8, 0, std::vector<std::byte>(40, std::byte{0})});
                if (std::string(malformed) == "stream") bad_inode.extended_fields.back().data[0] = std::byte{1};
            }
            if (std::string(malformed) == "empty-stream-field") bad_inode.extended_fields.push_back({8, 0, {}});
            if (std::string(malformed) == "private-extent") bad_inode.private_id = 117;
            if (!Require(EncodeAppleInodeRecord(bad_inode, encoded, error), label + "bad payload inode encodes")) return false;
            invalid.volumes[0].filesystem_records[1] = encoded;
            if (std::string(malformed).find("extent") != std::string::npos)
            {
                if (!Require(EncodeAppleFileExtentRecord({bad_inode.private_id, 0, 4096, 1, 0, 4096}, encoded, error),
                        label + "attached extent encodes")) return false;
                if (std::string(malformed) == "zero-extent")
                    std::fill_n(encoded.value.begin(), 8, std::byte{0});
                if (std::string(malformed) == "short-extent") encoded.value.resize(8);
                invalid.volumes[0].filesystem_records.push_back(encoded);
            }
            TempImageFile bad_image(BuildStoreImage(invalid), "special-node-payload");
            MetadataStore::VolumeContext bad_context;
            bad_context.device_path = bad_image.path.wstring(); bad_context.volume_object_id = 101;
            bad_context.allow_legacy_scaffold_for_fixtures = false;
            MetadataStore rejected(bad_context);
            ok &= Require(!rejected.PrepareNativeWritePath(), label + malformed + " payload refuses import");
        }
        TempImageFile image(BuildStoreImage(fixture), "special-node-preservation");
        MetadataStore::VolumeContext context;
        context.device_path = image.path.wstring(); context.volume_object_id = 101;
        context.allow_legacy_scaffold_for_fixtures = false;
        MetadataStore metadata(context);
        if (!Require(metadata.PrepareNativeWritePath(), label + "native image prepares")) return false;
        const auto initial = metadata.LookupCommittedInodeByPath(L"\\primary");
        ok &= Require(initial && initial->mode == original.mode && initial->owner == 501 &&
            initial->group == 20 && initial->node_type == expected_type && initial->logical_size == 0 &&
            initial->data_physical_address == 0, label + "original type and zero-content placeholder import");
        const auto children = metadata.SnapshotCommittedDirectoryChildInodes(2);
        ok &= Require(children && children->size() == 2 &&
            std::all_of(children->begin(), children->end(), [&](const auto& child) {
                return child.node_type == expected_type && child.logical_size == 0 && !child.is_directory;
            }), label + "both links enumerate with special type and zero size");
        std::vector<std::byte> before, after;
        const auto size = static_cast<std::size_t>(std::filesystem::file_size(image.path));
        if (!Require(metadata.Device().Read(0, size, before), label + "baseline bytes read")) return false;
        for (const auto& [operation, length] : {
                std::pair{MetadataStore::MutationOperation::Write, 1ULL},
                std::pair{MetadataStore::MutationOperation::Write, 0ULL},
                std::pair{MetadataStore::MutationOperation::SetFileSize, 1ULL}})
        {
            MetadataStore::MutationRequest rejected;
            rejected.operation = operation; rejected.path = L"\\primary"; rejected.length = length;
            if (operation == MetadataStore::MutationOperation::Write && length != 0)
                rejected.inline_payload = {std::byte{0x5a}};
            ok &= Require(metadata.StageMutation(rejected) != MetadataStore::MutationStatus::Applied &&
                metadata.PendingMutationCount() == 0 && metadata.PendingDeallocationCount() == 0 &&
                metadata.Device().Read(0, size, after) && before == after,
                label + "content mutation refuses without pending mutations or byte changes");
        }
        InodeMetadataPatch patch;
        patch.mask = InodeMetadataPatch::Owner | InodeMetadataPatch::Group |
            InodeMetadataPatch::Mode | InodeMetadataPatch::ModificationTime;
        patch.owner = 502; patch.group = 21; patch.mode = 04750;
        patch.modification_time_utc = InodeMetadataPatch::UnixEpochTicks + 90;
        MetadataStore::MutationRequest request;
        request.operation = MetadataStore::MutationOperation::SetInodeMetadata; request.path = L"\\primary";
        if (!Require(EncodeInodeMetadataPatch(patch, request.inline_payload), label + "patch encodes")) return false;
        request.length = request.inline_payload.size();
        if (!Require(metadata.StageMutation(request) == MetadataStore::MutationStatus::Applied,
                label + "owner/time/permission patch stages")) return false;
        const auto working = metadata.LookupWorkingInodeByPath(L"\\alias");
        ok &= Require(working && working->mode == (type | 04750) && working->owner == 502 &&
            working->group == 21, label + "patch preserves type through both links");
        request = {}; request.operation = MetadataStore::MutationOperation::Rename;
        request.path = L"\\primary"; request.secondary_path = L"\\renamed";
        if (!Require(metadata.StageMutation(request) == MetadataStore::MutationStatus::Applied,
                label + "rename stages")) return false;
        request = {}; request.operation = MetadataStore::MutationOperation::Delete; request.path = L"\\alias";
        if (!Require(metadata.StageMutation(request) == MetadataStore::MutationStatus::Applied,
                label + "one-link unlink stages")) return false;
        const auto pending_count = metadata.PendingMutationCount();
        unsigned publication_refusals = 0;
        metadata.SetCommitStageHook([&](std::string_view stage) {
            if (stage != "before-apple-publish") return true;
            ++publication_refusals;
            return false;
        });
        const auto refused_commit = metadata.CommitPendingMutations();
        metadata.SetCommitStageHook({});
        ok &= Require(refused_commit == MetadataStore::CommitStatus::PersistFailed &&
            publication_refusals == 1 && metadata.PendingMutationCount() == pending_count,
            label + "prepublication refusal retains pending metadata, rename and unlink for retry");
        {
            MetadataStore unpublished(context);
            if (!Require(unpublished.PrepareNativeWritePath(), label + "prepublication image reopens")) return false;
            for (const auto* path : {L"\\primary", L"\\alias"})
            {
                const auto prior = unpublished.LookupCommittedInodeByPath(path);
                const auto link = unpublished.LookupCommittedDirectoryLinkByPath(path);
                ok &= Require(initial && prior && prior->object_id == 17 && prior->node_type == expected_type &&
                    prior->mode == original.mode && prior->owner == original.owner && prior->group == original.group &&
                    prior->link_count == 2 && prior->logical_size == 0 &&
                    prior->modification_time_utc == initial->modification_time_utc &&
                    link && link->child_object_id == 17 && link->flags == (type >> 12),
                    label + "prepublication reopen preserves original linked type and metadata");
            }
            ok &= Require(!unpublished.LookupCommittedInodeByPath(L"\\renamed"),
                label + "prepublication reopen retains original names");
        }
        if (!Require(metadata.CommitPendingMutations() == MetadataStore::CommitStatus::Committed,
                label + "one-link unlink and metadata retry commit")) return false;
        MetadataStore reopened(context);
        if (!Require(reopened.PrepareNativeWritePath(), label + "durable checkpoint reopens")) return false;
        const auto node = reopened.LookupCommittedInodeByPath(L"\\renamed");
        ok &= Require(node && node->object_id == 17 && node->mode == (type | 04750) &&
            node->owner == 502 && node->group == 21 && node->link_count == 1 && node->logical_size == 0 &&
            node->node_type == expected_type && node->data_physical_address == 0 &&
            node->modification_time_utc == patch.modification_time_utc &&
            !reopened.LookupCommittedInodeByPath(L"\\primary") && !reopened.LookupCommittedInodeByPath(L"\\alias"),
            label + "reopened namespace and metadata survive");
        MetadataStore::MutationRequest replacement;
        replacement.operation = MetadataStore::MutationOperation::CreateFile;
        replacement.path = L"\\renamed"; replacement.replace_if_exists = true;
        if (!Require(reopened.Device().Read(0, size, before), label + "reopened baseline reads")) return false;
        ok &= Require(reopened.StageMutation(replacement) != MetadataStore::MutationStatus::Applied &&
            reopened.PendingMutationCount() == 0 && reopened.PendingDeallocationCount() == 0 &&
            reopened.Device().Read(0, size, after) && before == after,
            label + "single-link replacement refuses after reopen without byte changes");
        const auto unchanged = reopened.LookupWorkingInodeByPath(L"\\renamed");
        ok &= Require(unchanged && unchanged->object_id == 17 && unchanged->node_type == expected_type &&
            unchanged->mode == (type | 04750), label + "replacement refusal preserves working special inode");
        {
            apfsaccess::catalog::HeldFileSource source(image.path.string());
            const auto checkpoint = LoadAppleCheckpointView(source, 0, source.SizeBytes(), error);
            if (!Require(checkpoint.has_value(), label + "raw checkpoint loads")) return false;
            const auto& volume = checkpoint->volumes.front();
            std::vector<apfsaccess::catalog::BtreeRecord> raw;
            if (!Require(apfsaccess::catalog::ReadBtreeLeafRecords(source,
                    checkpoint->container.superblock.block_size, volume.root_tree.physical_block,
                    false, volume.superblock.omap_oid, checkpoint->container.superblock.xid, raw, error),
                    label + "raw tree loads")) return false;
            bool found = false;
            for (const auto& record : raw)
            {
                AppleInodeRecord inode;
                if (!ApfsExtendedRecordCodec::DecodeInode(record, inode, error) || inode.object_id != 17) continue;
                found = true;
                ok &= Require(inode.mode == (type | 04750) && inode.owner == 502 && inode.group == 21 &&
                    inode.bsd_flags == original.bsd_flags && inode.children_or_links == 1 && inode.uncompressed_size == 0 &&
                    inode.modification_time == 9000 && inode.create_time == original.create_time &&
                    inode.access_time == original.access_time &&
                    std::count_if(inode.extended_fields.begin(), inode.extended_fields.end(), [&](const auto& field) {
                        return field.type == opaque.type && field.flags == opaque.flags && field.data == opaque.data;
                    }) == 1, label + "raw inode retains special type, flags, ownership, times and opaque extension");
            }
            ok &= Require(found, label + "raw inode remains present");
            AppleDirectoryRecord expected;
            expected.parent_id = 2; expected.file_id = 17; expected.flags = type >> 12;
            expected.name_utf8 = "renamed";
            if (!Require(EncodeAppleDirectoryRecord(expected, encoded, error), label + "expected DREC encodes")) return false;
            ok &= Require(std::count_if(raw.begin(), raw.end(), [&](const auto& record) {
                return record.key == encoded.key && record.value == encoded.value;
            }) == 1, label + "raw renamed DREC retains node kind using public codec");
        }
        request.path = L"\\renamed";
        if (!Require(reopened.StageMutation(request) == MetadataStore::MutationStatus::Applied &&
                reopened.CommitPendingMutations() == MetadataStore::CommitStatus::Committed,
                label + "final unlink commits")) return false;
        MetadataStore final(context);
        ok &= Require(final.PrepareNativeWritePath() && !final.LookupCommittedInodeByPath(L"\\renamed"),
            label + "final unlink survives reopen");
        request = {}; request.operation = MetadataStore::MutationOperation::CreateFile; request.path = L"\\regular";
        if (!Require(final.StageMutation(request) == MetadataStore::MutationStatus::Applied &&
                final.CommitPendingMutations() == MetadataStore::CommitStatus::Committed,
                label + "regular control creates")) return false;
        request = {}; request.operation = MetadataStore::MutationOperation::Write; request.path = L"\\regular";
        ok &= Require(final.StageMutation(request) == MetadataStore::MutationStatus::Applied,
            label + "regular zero-length write remains accepted");
        const auto regular = final.LookupWorkingInodeByPath(L"\\regular");
        ok &= Require(regular && regular->node_type == MetadataStore::NodeType::RegularFile && regular->logical_size == 0,
            label + "regular zero-length control retains type and size");
    }
    return ok;
}

bool TestTransactionalInodeMetadata()
{
    using namespace apfsaccess::rw;
    BuilderStore fixture;
    fixture.authoritative_checkpoint = true;
    fixture.volumes[0].incompat = 0;
    auto& records = fixture.volumes[0].filesystem_records;
    std::string error;
    apfsaccess::catalog::BtreeRecord encoded;
    AppleInodeRecord root;
    root.object_id = root.parent_id = root.private_id = 2;
    root.children_or_links = 2; root.mode = 0040755;
    if (!Require(EncodeAppleInodeRecord(root, encoded, error), "metadata root encodes")) return false;
    records.push_back(std::move(encoded));
    AppleInodeRecord original;
    original.object_id = original.private_id = 17; original.parent_id = 2;
    original.children_or_links = 2; original.mode = 0100644;
    constexpr std::uint32_t unknown_bsd_flag = 0x40000000;
    constexpr std::uint32_t updated_bsd_flags = unknown_bsd_flag | 0x8004;
    original.owner = 501; original.group = 20;
    original.bsd_flags = unknown_bsd_flag | 0x8002;
    original.default_protection_class = 7; original.reserved_pad = 0x55aa;
    original.create_time = 1'037; original.modification_time = 2'053;
    original.change_time = 3'071; original.access_time = 4'099;
    if (!Require(EncodeAppleInodeRecord(original, encoded, error), "metadata inode encodes")) return false;
    records.push_back(std::move(encoded));
    for (const auto& [name, sibling] :
        {std::pair{"primary", 700ULL}, std::pair{"alias", 701ULL}})
    {
        AppleDirectoryRecord link;
        link.parent_id = 2; link.file_id = 17; link.flags = 8; link.name_utf8 = name;
        if (!Require(EncodeAppleDirectoryRecord(link, encoded, error), "metadata directory link encodes")) return false;
        records.push_back(std::move(encoded));
        if (!Require(EncodeAppleSiblingLinkRecord({17, sibling, 2, name}, encoded, error),
                "metadata sibling link encodes")) return false;
        records.push_back(std::move(encoded));
        if (!Require(EncodeAppleSiblingMapRecord({sibling, 17}, encoded, error),
                "metadata sibling map encodes")) return false;
        records.push_back(std::move(encoded));
    }
    TempImageFile image(BuildStoreImage(fixture), "transactional-inode-metadata");
    MetadataStore::VolumeContext context;
    context.device_path = image.path.wstring(); context.volume_object_id = 101;
    context.allow_legacy_scaffold_for_fixtures = false;
    MetadataStore metadata(context);
    if (!Require(metadata.PrepareNativeWritePath(), "metadata image prepares")) return false;
    constexpr auto epoch = InodeMetadataPatch::UnixEpochTicks;
    const auto projected_root = metadata.LookupCommittedInodeByPath(L"\\");
    bool ok = Require(projected_root && projected_root->create_time_utc == epoch &&
        projected_root->modification_time_utc == epoch && projected_root->change_time_utc == epoch &&
        projected_root->access_time_utc == epoch, "raw zero timestamps mean Unix epoch, not absent dates");
    const auto read_raw = [&]() -> std::optional<AppleInodeRecord>
    {
        apfsaccess::catalog::HeldFileSource source(image.path.string());
        const auto checkpoint = LoadAppleCheckpointView(source, 0, source.SizeBytes(), error);
        if (!Require(checkpoint.has_value(), "metadata raw checkpoint loads")) return std::nullopt;
        std::vector<apfsaccess::catalog::BtreeRecord> raw;
        const auto& volume = checkpoint->volumes.front();
        if (!Require(apfsaccess::catalog::ReadBtreeLeafRecords(source,
                checkpoint->container.superblock.block_size, volume.root_tree.physical_block,
                false, volume.superblock.omap_oid, checkpoint->container.superblock.xid, raw, error),
                "metadata raw tree loads")) return std::nullopt;
        for (const auto& record : raw)
        {
            AppleInodeRecord inode;
            if (ApfsExtendedRecordCodec::DecodeInode(record, inode, error) && inode.object_id == 17) return inode;
        }
        Require(false, "metadata raw inode is present");
        return std::nullopt;
    };
    InodeMetadataPatch patch;
    patch.mask = InodeMetadataPatch::Owner;
    patch.owner = 502;
    MetadataStore::MutationRequest request;
    request.operation = MetadataStore::MutationOperation::SetInodeMetadata;
    request.path = L"\\alias";
    if (!Require(EncodeInodeMetadataPatch(patch, request.inline_payload), "native metadata patch encodes")) return false;
    request.length = request.inline_payload.size();
    MetadataStore::PayloadIdentity identity;
    if (!Require(metadata.StageMutation(request, &identity) == MetadataStore::MutationStatus::Applied,
            "owner metadata stages through alias")) return false;
    patch = {}; patch.mask = InodeMetadataPatch::Mode; patch.mode = 04750;
    request.path = L"\\primary";
    if (!Require(EncodeInodeMetadataPatch(patch, request.inline_payload), "mode metadata patch encodes")) return false;
    request.length = request.inline_payload.size();
    if (!Require(metadata.StageMutation(request) == MetadataStore::MutationStatus::Applied,
            "disjoint mode metadata stages through primary link")) return false;
    const auto before_bsd_patch = metadata.LookupWorkingInodeByPath(L"\\alias");
    ok &= Require(before_bsd_patch && before_bsd_patch->bsd_flags == original.bsd_flags &&
        before_bsd_patch->node_type == MetadataStore::NodeType::RegularFile,
        "owner and mode masks preserve every pre-existing BSD bit and the inode type");
    patch = {}; patch.mask = InodeMetadataPatch::BsdFlags; patch.bsd_flags = updated_bsd_flags;
    request.path = L"\\alias";
    if (!Require(EncodeInodeMetadataPatch(patch, request.inline_payload), "BSD metadata patch encodes")) return false;
    request.length = request.inline_payload.size();
    if (!Require(metadata.StageMutation(request) == MetadataStore::MutationStatus::Applied,
            "disjoint BSD metadata stages through alias with unknown bit retained")) return false;
    patch = {}; patch.mask = InodeMetadataPatch::Group | InodeMetadataPatch::ModificationTime;
    patch.group = 21; patch.modification_time_utc = epoch + 90;
    if (!Require(EncodeInodeMetadataPatch(patch, request.inline_payload), "remaining metadata patch encodes")) return false;
    request.length = request.inline_payload.size();
    if (!Require(metadata.StageMutation(request) == MetadataStore::MutationStatus::Applied,
            "remaining disjoint metadata stages in the same transaction")) return false;
    const auto pending = metadata.LookupWorkingInodeByPath(L"\\primary");
    ok &= Require(identity.object_id == 17 && pending && pending->owner == 502 &&
        pending->group == 21 && pending->mode == 0104750 && pending->bsd_flags == updated_bsd_flags &&
        pending->node_type == MetadataStore::NodeType::RegularFile &&
        pending->modification_time_utc == epoch + 90 &&
        pending->create_time_utc == epoch + 10 && pending->change_time_utc == epoch + 30 &&
        pending->access_time_utc == epoch + 40,
        "disjoint masked patches reach both aliases without collapsing type, dates or BSD bits");
    const auto count = metadata.PendingMutationCount();
    for (int fault = 0; fault != 6; ++fault)
    {
        auto invalid = request;
        if (fault == 0) invalid.inline_payload[4] = std::byte{0x80};
        if (fault == 1) ++invalid.length;
        if (fault == 2) invalid.timestamp_utc = epoch;
        if (fault == 3) invalid.object_id = 99, invalid.generation = identity.generation;
        if (fault == 4) invalid.object_id = 17, invalid.generation = identity.generation + 1;
        if (fault == 5) invalid.inline_payload.pop_back(), --invalid.length;
        ok &= Require(metadata.StageMutation(invalid) == MetadataStore::MutationStatus::InvalidRequest &&
            metadata.PendingMutationCount() == count, "invalid metadata admission leaves pending state intact");
    }
    metadata.SetCommitStageHook([](std::string_view stage) { return stage != "before-apple-publish"; });
    ok &= Require(metadata.CommitPendingMutations() == MetadataStore::CommitStatus::PersistFailed &&
        metadata.LookupCommittedInodeByPath(L"\\alias")->owner == original.owner,
        "failed metadata publication leaves original committed ownership intact");
    auto raw = read_raw();
    ok &= Require(raw && raw->owner == original.owner && raw->modification_time == original.modification_time,
        "raw image still contains pre-publication metadata");
    metadata.SetCommitStageHook({});
    if (!Require(metadata.CommitPendingMutations() == MetadataStore::CommitStatus::Committed,
            "metadata retry commits")) return false;
    raw = read_raw();
    ok &= Require(raw && raw->owner == 502 && raw->group == 21 && raw->mode == 0104750 &&
        raw->modification_time == 9'000 && raw->create_time == original.create_time &&
        raw->change_time == original.change_time && raw->access_time == original.access_time &&
        raw->bsd_flags == updated_bsd_flags && raw->reserved_pad == original.reserved_pad &&
        raw->default_protection_class == original.default_protection_class && raw->children_or_links == 2,
        "raw commit applies BSD flags and preserves inode type storage and all untouched fields");

    MetadataStore reopened(context);
    if (!Require(reopened.PrepareNativeWritePath(), "metadata image reopens")) return false;
    const auto reopened_metadata = reopened.LookupCommittedInodeByPath(L"\\primary");
    ok &= Require(reopened_metadata && reopened_metadata->owner == 502 &&
        reopened_metadata->group == 21 && reopened_metadata->mode == 0104750 &&
        reopened_metadata->bsd_flags == updated_bsd_flags &&
        reopened_metadata->node_type == MetadataStore::NodeType::RegularFile,
        "fresh reopen exposes committed owner, mode and BSD fields without changing inode type");
    patch = {}; patch.mask = InodeMetadataPatch::AccessTime; patch.access_time_utc = epoch;
    EncodeInodeMetadataPatch(patch, request.inline_payload);
    request.length = request.inline_payload.size();
    if (!Require(reopened.StageMutation(request) == MetadataStore::MutationStatus::Applied,
            "explicit epoch stages")) return false;
    patch = {}; patch.mask = InodeMetadataPatch::ChangeTime; patch.change_time_utc = epoch + 73;
    EncodeInodeMetadataPatch(patch, request.inline_payload);
    request.length = request.inline_payload.size();
    if (!Require(reopened.StageMutation(request) == MetadataStore::MutationStatus::Applied &&
            reopened.CommitPendingMutations() == MetadataStore::CommitStatus::Committed,
            "two disjoint metadata patches commit without dropping the earlier field")) return false;
    raw = read_raw();
    ok &= Require(raw && raw->access_time == 0 && raw->change_time == 7'300 &&
        raw->modification_time == 9'000 && raw->create_time == original.create_time &&
        raw->bsd_flags == updated_bsd_flags && raw->mode == 0104750,
        "later time patches preserve raw BSD flags, mode and unrelated fractional dates");
    MetadataStore final(context);
    if (!Require(final.PrepareNativeWritePath(), "metadata final checkpoint reopens")) return false;
    const auto primary = final.LookupCommittedInodeByPath(L"\\primary");
    const auto alias = final.LookupCommittedInodeByPath(L"\\alias");
    ok &= Require(primary && alias && primary->object_id == alias->object_id &&
        primary->access_time_utc == epoch && alias->change_time_utc == epoch + 73 &&
        alias->owner == 502 && alias->mode == 0104750 && alias->bsd_flags == updated_bsd_flags &&
        alias->node_type == MetadataStore::NodeType::RegularFile,
        "reopened aliases expose exact accepted fields including the preserved unknown BSD bit");
    MetadataStore::MutationRequest legacy;
    legacy.operation = MetadataStore::MutationOperation::SetBasicInfo;
    legacy.path = request.path; legacy.timestamp_utc = epoch + 101;
    if (!Require(final.StageMutation(legacy) == MetadataStore::MutationStatus::Applied &&
            final.CommitPendingMutations() == MetadataStore::CommitStatus::Committed,
            "legacy scalar timestamp remains compatible")) return false;
    raw = read_raw();
    ok &= Require(raw && raw->modification_time == 10'100 && raw->create_time == original.create_time &&
        raw->change_time == 7'300 && raw->access_time == 0,
        "legacy SetBasicInfo updates mtime without collapsing the other three dates");
    for (const bool directory : {false, true})
    {
        MetadataStore creating(context);
        if (!Require(creating.PrepareNativeWritePath(), "new-inode metadata image prepares")) return false;
        MetadataStore::MutationRequest create;
        create.operation = directory ? MetadataStore::MutationOperation::CreateDirectory :
            MetadataStore::MutationOperation::CreateFile;
        create.path = directory ? L"\\new-directory" : L"\\new-file";
        if (!Require(creating.StageMutation(create) == MetadataStore::MutationStatus::Applied,
                "new inode stages before its first checkpoint")) return false;
        request.path = create.path;
        patch = {}; patch.mask = InodeMetadataPatch::Mode;
        EncodeInodeMetadataPatch(patch, request.inline_payload);
        if (!Require(creating.StageMutation(request) == MetadataStore::MutationStatus::Applied,
                "explicit permission mode zero stages on new inode")) return false;
        patch = {}; patch.mask = InodeMetadataPatch::ModificationTime;
        patch.modification_time_utc = epoch + 111;
        EncodeInodeMetadataPatch(patch, request.inline_payload);
        if (!Require(creating.StageMutation(request) == MetadataStore::MutationStatus::Applied &&
                creating.CommitPendingMutations() == MetadataStore::CommitStatus::Committed,
                "new inode and masked metadata commit together")) return false;
        MetadataStore fresh_created(context);
        if (!Require(fresh_created.PrepareNativeWritePath(), "new inode metadata freshly reopens")) return false;
        const auto created = fresh_created.LookupCommittedInodeByPath(create.path);
        ok &= Require(created && created->mode == (directory ? 0040000 : 0100000) &&
            created->is_directory == directory && created->modification_time_utc == epoch + 111 &&
            created->create_time_utc == epoch && created->change_time_utc == epoch &&
            created->access_time_utc == epoch,
            "new inode retains explicit zero permissions and mtime-only patch leaves other raw times zero");
    }
    return ok;
}

std::vector<std::byte> BuildOrdinaryCowAliasImage()
{
    using namespace apfsaccess::rw;
    BuilderStore fixture;
    fixture.block_count = 8192;
    fixture.authoritative_checkpoint = true;
    fixture.volumes[0].incompat = 0;
    auto& records = fixture.volumes[0].filesystem_records;
    std::string error;
    apfsaccess::catalog::BtreeRecord encoded;
    AppleInodeRecord root;
    root.object_id = root.parent_id = root.private_id = 2;
    root.children_or_links = 2; root.mode = 0040755;
    if (!Require(EncodeAppleInodeRecord(root, encoded, error), "ordinary COW root encodes")) return {};
    records.push_back(std::move(encoded));
    AppleInodeRecord file;
    file.object_id = file.private_id = 17; file.parent_id = 2;
    file.children_or_links = 2; file.mode = 0100644;
    if (!Require(EncodeAppleInodeRecord(file, encoded, error), "ordinary COW inode encodes")) return {};
    records.push_back(std::move(encoded));
    for (const auto& [name, sibling] : {std::pair{"primary", 700ULL}, std::pair{"alias", 701ULL}})
    {
        AppleDirectoryRecord link;
        link.parent_id = 2; link.file_id = 17; link.flags = 8; link.name_utf8 = name;
        if (!Require(EncodeAppleDirectoryRecord(link, encoded, error), "ordinary COW link encodes")) return {};
        records.push_back(std::move(encoded));
        if (!Require(EncodeAppleSiblingLinkRecord({17, sibling, 2, name}, encoded, error),
                "ordinary COW sibling encodes")) return {};
        records.push_back(std::move(encoded));
        if (!Require(EncodeAppleSiblingMapRecord({sibling, 17}, encoded, error), "ordinary COW map encodes")) return {};
        records.push_back(std::move(encoded));
    }
    return BuildStoreImage(fixture);
}

struct OrdinaryCowSnapshot
{
    std::uint64_t xid = 0;
    std::uint64_t total_allocated_blocks = 0;
    std::map<std::uint64_t, apfsaccess::catalog::BtreeRecord> extents;
    std::map<std::uint64_t, apfsaccess::catalog::BtreeRecord> references;
};

bool ReadOrdinaryCowSnapshot(const std::filesystem::path& path, OrdinaryCowSnapshot& result)
{
    using namespace apfsaccess::rw;
    apfsaccess::catalog::HeldFileSource source(path.string());
    std::string error;
    const auto view = LoadAppleCheckpointView(source, 0, source.SizeBytes(), error);
    if (!Require(view && view->volumes.size() == 1, "ordinary COW raw checkpoint: " + error)) return false;
    result = {};
    result.xid = view->container.superblock.xid;
    const auto& volume = view->volumes.front();
    std::vector<std::byte> superblock;
    if (!Require(source.Read(volume.superblock_object.physical_block * view->container.superblock.block_size,
            view->container.superblock.block_size, superblock), "ordinary COW allocation accounting reads")) return false;
    result.total_allocated_blocks = apfsaccess::catalog::ReadU64LE(superblock, 0xE0).value();
    std::vector<apfsaccess::catalog::BtreeRecord> records;
    if (!Require(apfsaccess::catalog::ReadBtreeLeafRecords(source, view->container.superblock.block_size,
            volume.root_tree.physical_block, false, volume.superblock.omap_oid, result.xid, records, error),
            "ordinary COW raw extent tree: " + error)) return false;
    for (const auto& record : records)
    {
        const auto key = apfsaccess::catalog::ReadU64LE(record.key, 0).value_or(0);
        if ((key >> 60) == 8 && (key & 0x0fffffffffffffffULL) == 17)
            result.extents.emplace(apfsaccess::catalog::ReadU64LE(record.key, 8).value(), record);
    }
    if (volume.extentref_tree)
    {
        records.clear();
        if (!Require(apfsaccess::catalog::ReadBtreeLeafRecords(source, view->container.superblock.block_size,
                volume.extentref_tree->physical_block, true, 0, result.xid, records, error),
                "ordinary COW raw physical references: " + error)) return false;
        for (const auto& record : records)
        {
            ApplePhysicalExtentRecord extent;
            if (!Require(DecodeApplePhysicalExtentRecord(record, extent, error), "ordinary COW reference decodes")) return false;
            if (extent.owning_object_id == 17) result.references.emplace(extent.physical_block, record);
        }
    }
    return true;
}

std::uint64_t OrdinaryCowWriteCounterBytes(const apfsaccess::rw::BlockDevice& device)
{
    const auto json = device.PerformanceJson();
    std::uint64_t total = 0;
    // These are the two public write entry points. Other counters describe
    // their internal batching and must not be counted a second time.
    for (const auto* name : {"write", "batchWrite"})
    {
        const auto object = json.find(std::string("\"") + name + "\":{");
        const auto bytes = object == std::string::npos ? object : json.find("\"bytes\":", object);
        if (bytes != std::string::npos) total += std::stoull(json.substr(bytes + 8));
    }
    return total;
}

bool TestAppleOrdinaryExtentCow(bool legacy = false, bool faults = false, bool content_times = false,
    bool partial_fault = false)
{
    using namespace apfsaccess::rw;
    constexpr std::uint64_t chunk = 1024 * 1024;
    constexpr std::uint64_t allocation = 3 * chunk + 8192;
    TempImageFile image(BuildOrdinaryCowAliasImage(), "ordinary-cow");
    MetadataStore::VolumeContext context;
    context.device_path = image.path.wstring(); context.volume_object_id = 101;
    context.allow_legacy_scaffold_for_fixtures = false;
    std::vector<std::byte> expected(2 * chunk + 173);
    for (std::size_t i = 0; i < expected.size(); ++i) expected[i] = static_cast<std::byte>(1 + i % 251);
    MetadataStore metadata(context);
    if (!Require(metadata.PrepareNativeWritePath(), "ordinary COW writer prepares")) return false;
    MetadataStore::PayloadIdentity identity;
    std::uint64_t supplied = 0;
    std::size_t calls = 0, legacy_calls = 0;
    std::vector<std::pair<std::uint64_t, std::uint64_t>> acquired_ranges;
    bool refuse_second = false;
    bool refuse_first = false;
    int malformed_legacy = 0;
    metadata.SetFilePayloadProvider([&](const auto&, auto size) -> std::optional<std::vector<std::byte>> {
        ++legacy_calls;
        if (size != expected.size()) return std::nullopt;
        auto bytes = expected;
        if (malformed_legacy < 0) bytes.pop_back();
        if (malformed_legacy > 0) bytes.push_back(std::byte{0});
        return bytes;
    });
    if (!legacy)
        metadata.SetFilePayloadRangeProvider([&](const auto&, auto owner, auto offset, std::span<std::byte> bytes) {
            ++calls;
            if (partial_fault) acquired_ranges.emplace_back(offset, bytes.size());
            if (!Require(owner.object_id == identity.object_id && owner.generation == identity.generation &&
                    offset % 4096 == 0 && bytes.size() <= chunk && offset <= expected.size() &&
                    bytes.size() <= expected.size() - offset,
                    "ordinary provider gets stable identity, aligned bounded logical range")) return false;
            std::copy_n(expected.begin() + static_cast<std::ptrdiff_t>(offset), bytes.size(), bytes.begin());
            supplied += bytes.size();
            return !(refuse_first || (refuse_second && calls == 2));
        });
    const auto stage_write = [&](const wchar_t* path, std::uint64_t offset, std::uint64_t length) {
        MetadataStore::MutationRequest write;
        write.path = path; write.offset = offset; write.length = length;
        if (content_times)
        {
            write.object_id = 17;
            write.generation = metadata.CheckpointXid().value() + 1;
        }
        if (!Require(metadata.StageMutation(write, &identity) == MetadataStore::MutationStatus::Applied,
                "ordinary COW write stages")) return false;
        const auto staged = metadata.LookupWorkingInodeByPath(path);
        return Require(staged && identity.object_id == 17 && staged->object_id == identity.object_id &&
            identity.generation == metadata.CheckpointXid().value() + 1 && staged->xid == identity.generation,
            "staged write returns exact working object and transaction generation");
    };
    if (!stage_write(L"\\primary", 0, expected.size())) return false;
    MetadataStore::MutationRequest reserve;
    reserve.operation = MetadataStore::MutationOperation::SetAllocationSize;
    reserve.path = L"\\alias"; reserve.length = allocation;
    if (!Require(metadata.StageMutation(reserve, &identity) == MetadataStore::MutationStatus::Applied &&
            metadata.CommitPendingMutations() == MetadataStore::CommitStatus::Committed,
            "ordinary multi-chunk seed and explicit reservation publish")) return false;
    if (!Require(legacy ? legacy_calls == 1 : calls == 3 && supplied == expected.size() && legacy_calls == 0,
            "full rewrite fills bounded logical chunks or calls the legacy provider once")) return false;

    const auto check_content = [&](MetadataStore& reader, const std::vector<std::byte>& content) {
        for (const auto* path : {L"\\primary", L"\\alias"})
        {
            const auto inode = reader.LookupCommittedInodeByPath(path);
            std::vector<std::byte> actual;
            if (!Require(inode && inode->object_id == 17 && inode->logical_size == content.size() &&
                    inode->allocation_size == allocation &&
                    reader.ReadCommittedFileRange(path, 0, content.size(), actual) && actual == content,
                    "both aliases read exact bytes with separate EOF and allocation")) return false;
        }
        return true;
    };
    const auto check_fresh = [&](const std::vector<std::byte>& content) {
        MetadataStore reopened(context);
        if (!Require(reopened.PrepareNativeWritePath() && reopened.VerifyIntegrity(), "ordinary COW fresh integrity") ||
            !check_content(reopened, content)) return false;
        std::vector<std::byte> actual;
        std::string error, expected_hash, actual_hash;
        auto expected_digest = apfsaccess::observer::Sha256Stream::Create(error);
        auto actual_digest = apfsaccess::observer::Sha256Stream::Create(error);
        return Require(expected_digest && actual_digest &&
            reopened.ReadCommittedFileRange(L"\\alias", 0, content.size(), actual) &&
            expected_digest->Update(content.data(), content.size()) && expected_digest->FinalHex(expected_hash) &&
            actual_digest->Update(actual.data(), actual.size()) && actual_digest->FinalHex(actual_hash) &&
            expected_hash == actual_hash, "fresh alias SHA-256 matches expected payload");
    };
    if (!check_content(metadata, expected) || !check_fresh(expected)) return false;
    OrdinaryCowSnapshot before;
    if (!ReadOrdinaryCowSnapshot(image.path, before)) return false;
    const auto check_tail = [&](const OrdinaryCowSnapshot& snapshot) {
        apfsaccess::catalog::HeldFileSource source(image.path.string());
        std::uint64_t covered = 0;
        for (const auto& [offset, record] : snapshot.extents)
        {
            AppleFileExtentRecord extent;
            std::string error;
            if (!Require(DecodeAppleFileExtentRecord(record, 4096, extent, error) && offset == covered &&
                    extent.length_bytes % 4096 == 0 && extent.physical_block != 0,
                    "ordinary reserved allocation has complete aligned physical extents")) return false;
            covered += extent.length_bytes;
            if (covered <= expected.size()) continue;
            const auto begin = (std::max)(offset, static_cast<std::uint64_t>(expected.size()));
            std::vector<std::byte> tail;
            if (!Require(source.Read(extent.physical_block * 4096 + begin - offset,
                    static_cast<std::size_t>(covered - begin), tail) &&
                    std::all_of(tail.begin(), tail.end(), [](auto byte) { return byte == std::byte{0}; }),
                    "EOF padding and allocated bytes beyond EOF are zero")) return false;
        }
        return Require(covered == allocation, "ordinary allocation size matches all physical extents");
    };
    if (!check_tail(before)) return false;

    if (faults || legacy)
    {
        const auto old = expected;
        const auto image_size = static_cast<std::size_t>(metadata.Device().GetGeometry().total_bytes);
        std::vector<std::byte> old_image;
        if (!Require(metadata.Device().Read(0, image_size, old_image), "provider failure baseline reads")) return false;
        // A resize forces several payload windows, so failure occurs after one
        // successful chunk has already been materialized, before any publication.
        expected.resize(expected.size() + 8192, std::byte{0});
        MetadataStore::MutationRequest resize;
        resize.operation = MetadataStore::MutationOperation::SetFileSize;
        resize.path = L"\\alias"; resize.length = expected.size();
        if (!Require(metadata.StageMutation(resize, &identity) == MetadataStore::MutationStatus::Applied,
                "provider failure resize stages")) return false;
        for (const int malformed : (legacy ? std::vector<int>{-1, 1} : std::vector<int>{0}))
        {
            calls = 0; supplied = 0; legacy_calls = 0;
            malformed_legacy = malformed; refuse_second = faults;
            const auto result = metadata.CommitPendingMutations();
            std::vector<std::byte> actual_image;
            OrdinaryCowSnapshot refused;
            if (!Require(result == MetadataStore::CommitStatus::PersistFailed && metadata.PendingMutationCount() != 0 &&
                    metadata.Device().Read(0, image_size, actual_image) && actual_image == old_image &&
                    (legacy || (calls == 2 && legacy_calls == 0)),
                    "malformed provider cannot publish or bypass identity refusal") ||
                !ReadOrdinaryCowSnapshot(image.path, refused) ||
                !Require(refused.xid == before.xid, "provider refusal keeps prior checkpoint") || !check_fresh(old)) return false;
        }
        malformed_legacy = 0; refuse_second = false; calls = 0; supplied = 0;
        if (faults)
        {
            bool source_written = false;
            metadata.SetCommitStageHook([&](std::string_view stage) {
                if (stage != "before-apple-checkpoint-switch") return true;
                source_written = true;
                return false;
            });
            if (!Require(metadata.CommitPendingMutations() == MetadataStore::CommitStatus::PersistFailed && source_written &&
                    metadata.IsRecoveryRequired() && metadata.PendingMutationCount() != 0 &&
                    !metadata.LastCommitFailureReason().empty(),
                    "source-stage interruption retains pending work and recovery evidence")) return false;
            OrdinaryCowSnapshot interrupted;
            std::vector<std::byte> interrupted_image;
            if (!ReadOrdinaryCowSnapshot(image.path, interrupted) ||
                !Require(interrupted.xid == before.xid && metadata.Device().Read(0, image_size, interrupted_image) &&
                    interrupted_image != old_image, "source writes occurred without switching canonical checkpoint") ||
                !check_fresh(old)) return false;
            return true;
        }
        if (!Require(metadata.CommitPendingMutations() == MetadataStore::CommitStatus::Committed,
                "valid legacy provider retries malformed payloads")) return false;
        return check_content(metadata, expected) && check_fresh(expected);
    }

    const auto seed_inode = metadata.LookupCommittedInodeByPath(L"\\primary").value();
    std::uint64_t last_content_time = InodeMetadataPatch::UnixEpochTicks;
    std::uint64_t root_content_time = 0;
    const auto stage_times = [&](const wchar_t* path) {
        InodeMetadataPatch patch;
        patch.mask = InodeMetadataPatch::ModificationTime | InodeMetadataPatch::ChangeTime;
        last_content_time += 1000;
        patch.modification_time_utc = patch.change_time_utc = last_content_time;
        MetadataStore::MutationRequest request;
        request.operation = MetadataStore::MutationOperation::SetInodeMetadata;
        request.path = path; request.object_id = 17;
        request.generation = metadata.CheckpointXid().value() + 1;
        if (!Require(EncodeInodeMetadataPatch(patch, request.inline_payload), "host content times encode")) return false;
        request.length = request.inline_payload.size();
        if (!Require(metadata.StageMutation(request, &identity) == MetadataStore::MutationStatus::Applied,
                "host content times stage before write")) return false;
        const auto staged = metadata.LookupWorkingInodeByPath(path);
        return Require(staged && identity.object_id == 17 && identity.generation == request.generation &&
            staged->object_id == identity.object_id && staged->xid == identity.generation &&
            staged->modification_time_utc == last_content_time && staged->change_time_utc == last_content_time,
            "timestamp staging preserves exact object, generation and content times");
    };
    if (content_times && !partial_fault)
    {
        const auto pending = metadata.PendingMutationCount();
        for (const bool wrong_generation : {false, true})
        {
            MetadataStore::MutationRequest invalid;
            invalid.path = L"\\alias"; invalid.length = 1;
            invalid.object_id = wrong_generation ? 17 : 2;
            invalid.generation = metadata.CheckpointXid().value() + (wrong_generation ? 2 : 1);
            if (!Require(metadata.StageMutation(invalid) == MetadataStore::MutationStatus::InvalidRequest &&
                    metadata.PendingMutationCount() == pending,
                    "foreign write identity and wrong transaction generation are refused")) return false;
        }
        InodeMetadataPatch patch;
        patch.mask = InodeMetadataPatch::ModificationTime;
        patch.modification_time_utc = InodeMetadataPatch::UnixEpochTicks + 100;
        MetadataStore::MutationRequest invalid;
        invalid.operation = MetadataStore::MutationOperation::SetInodeMetadata;
        invalid.path = L"\\primary";
        if (!EncodeInodeMetadataPatch(patch, invalid.inline_payload)) return false;
        invalid.length = invalid.inline_payload.size();
        invalid.inline_payload[18] = std::byte{1};
        if (!Require(metadata.StageMutation(invalid) == MetadataStore::MutationStatus::InvalidRequest &&
                metadata.PendingMutationCount() == pending, "noncanonical content-time patch is refused")) return false;
    }

    for (unsigned phase = 0; phase != (content_times ? 11u : 6u); ++phase)
    {
        const auto old_content = expected;
        calls = 0; supplied = 0;
        if (partial_fault) acquired_ranges.clear();
        const bool full_fallback = content_times ? phase >= 5 : phase == 3 || phase == 4;
        const bool contiguous = content_times ? phase == 3 : phase == 5;
        std::vector<std::pair<std::uint64_t, std::uint64_t>> ranges;
        if (phase == 0) ranges = {{chunk + 123, 37}};
        if (phase == 1) ranges = {{chunk - 7, 23}};
        if (phase == 2) ranges = {{2 * chunk + 101, 20}, {2 * chunk + 111, 29}, {73, 19}};
        if (phase >= 3) ranges = {{chunk + 123, 37}};
        if (contiguous) ranges = {{chunk, chunk}};
        std::size_t write_number = 0;
        for (const auto& [offset, length] : ranges)
        {
            std::fill_n(expected.begin() + static_cast<std::ptrdiff_t>(offset), static_cast<std::size_t>(length),
                static_cast<std::byte>(0xa0 + phase));
            const auto* path = phase == 2 && write_number++ % 2 == 0 ? L"\\alias" : L"\\primary";
            if (content_times && !stage_times(path)) return false;
            if (!stage_write(path, offset, length)) return false;
            const auto staged = metadata.LookupWorkingInodeByPath(path);
            if (content_times && !Require(staged && staged->modification_time_utc == last_content_time &&
                    staged->change_time_utc == last_content_time,
                    "write after timestamp staging preserves both content times")) return false;
        }
        // A final metadata stage must not make eligibility depend on whether
        // the write-compaction index was cleared or rebuilt by another write.
        if (content_times && phase == 4 && !stage_times(L"\\alias")) return false;
        if (phase == (content_times ? 9u : 3u))
        {
            expected.resize(expected.size() + 8192, std::byte{0});
            MetadataStore::MutationRequest resize;
            resize.operation = MetadataStore::MutationOperation::SetFileSize;
            resize.path = L"\\alias"; resize.length = expected.size();
            if (!Require(metadata.StageMutation(resize, &identity) == MetadataStore::MutationStatus::Applied,
                    "resize excludes partial extent reuse")) return false;
        }
        if (phase == (content_times ? 10u : 4u))
        {
            MetadataStore::MutationRequest attributes;
            attributes.operation = MetadataStore::MutationOperation::SetExtendedAttribute;
            attributes.path = L"\\alias"; attributes.secondary_path = L"user.cow";
            attributes.inline_payload = {std::byte{0x42}}; attributes.length = 1;
            if (!Require(metadata.StageMutation(attributes, &identity) == MetadataStore::MutationStatus::Applied,
                    "mixed attribute batch excludes partial reuse")) return false;
        }
        if (content_times && phase >= 5 && phase <= 8)
        {
            InodeMetadataPatch patch;
            if (phase == 5) { patch.mask = InodeMetadataPatch::Owner; patch.owner = 502; }
            if (phase == 6) { patch.mask = InodeMetadataPatch::Mode; patch.mode = 0600; }
            if (phase == 7) { patch.mask = InodeMetadataPatch::BsdFlags; patch.bsd_flags = 0x8000; }
            if (phase == 8)
            {
                patch.mask = InodeMetadataPatch::ModificationTime | InodeMetadataPatch::ChangeTime;
                patch.modification_time_utc = patch.change_time_utc = last_content_time;
                root_content_time = last_content_time;
            }
            MetadataStore::MutationRequest extra;
            extra.operation = MetadataStore::MutationOperation::SetInodeMetadata;
            extra.path = phase == 8 ? L"\\" : L"\\alias";
            extra.object_id = phase == 8 ? 2 : 17;
            extra.generation = identity.generation;
            if (!Require(EncodeInodeMetadataPatch(patch, extra.inline_payload), "mixed metadata patch encodes")) return false;
            extra.length = extra.inline_payload.size();
            MetadataStore::PayloadIdentity extra_identity;
            if (!Require(metadata.StageMutation(extra, &extra_identity) == MetadataStore::MutationStatus::Applied &&
                    extra_identity.object_id == extra.object_id && extra_identity.generation == identity.generation,
                    "owner, mode, BSD or foreign-inode time patch stages with exact identity")) return false;
        }
        std::uint64_t touched = 0;
        std::set<std::uint64_t> replaced_offsets;
        for (const auto& [offset, record] : before.extents)
        {
            AppleFileExtentRecord extent;
            std::string error;
            if (!Require(DecodeAppleFileExtentRecord(record, 4096, extent, error), "old COW extent decodes")) return false;
            const bool replace = full_fallback || std::any_of(ranges.begin(), ranges.end(), [&](const auto& range) {
                return range.first < offset + extent.length_bytes && offset < range.first + range.second;
            });
            if (replace) { touched += extent.length_bytes; replaced_offsets.insert(offset); }
            if (contiguous && replace && !Require(extent.length_bytes == 4096,
                    "contiguous overwrite starts with planner-emitted 4 KiB extent records")) return false;
        }
        if (contiguous && !Require(replaced_offsets.size() == 256,
                "contiguous 1 MiB overwrite selects exactly 256 old records")) return false;
        std::vector<std::byte> old_image;
        const auto image_size = static_cast<std::size_t>(metadata.Device().GetGeometry().total_bytes);
        if (!Require(metadata.Device().Read(0, image_size, old_image), "COW traffic baseline reads")) return false;
        if (!check_content(metadata, old_content)) return false;
        if (partial_fault)
        {
            if (!Require(content_times && phase == 0 && !full_fallback && before.extents.size() > 1 &&
                    touched == 4096 && replaced_offsets == std::set<std::uint64_t>{chunk},
                    "partial fault selects only the one old extent touched by the 37-byte write")) return false;
            const auto working = metadata.LookupWorkingInodeByPath(L"\\alias");
            if (!Require(working && working->logical_size == old_content.size() &&
                    working->allocation_size == allocation && working->modification_time_utc == last_content_time &&
                    working->change_time_utc == last_content_time && !metadata.IsRecoveryRequired(),
                    "partial fault stages same-size content and canonical timestamps without recovery")) return false;
            const auto pending = metadata.PendingMutationCount();
            unsigned switch_hooks = 0;
            bool later_stage = false;
            metadata.SetCommitStageHook([&](std::string_view stage) {
                if (stage == "before-apple-final-flush" || stage == "after-apple-publish") later_stage = true;
                if (stage != "before-apple-checkpoint-switch") return true;
                ++switch_hooks;
                return false;
            });
            const auto result = metadata.CommitPendingMutations();
            metadata.SetCommitStageHook({});
            if (!Require(result == MetadataStore::CommitStatus::PersistFailed && switch_hooks == 1 && !later_stage &&
                    metadata.IsRecoveryRequired() && !metadata.IsCommitPathReady() && pending != 0 &&
                    metadata.PendingMutationCount() == pending && metadata.CheckpointXid() == before.xid &&
                    !metadata.LastCommitFailureReason().empty() && !metadata.RecoveryReason().empty() &&
                    calls == 1 && supplied == touched && legacy_calls == 0 &&
                    acquired_ranges == std::vector<std::pair<std::uint64_t, std::uint64_t>>{{chunk, 4096}},
                    "eligible partial COW reaches the post-source-write hook and fails with pending recovery truth")) return false;

            OrdinaryCowSnapshot interrupted;
            std::vector<std::byte> interrupted_image;
            apfsaccess::catalog::HeldFileSource source(image.path.string());
            if (!ReadOrdinaryCowSnapshot(image.path, interrupted) ||
                !Require(source.Read(0, image_size, interrupted_image) && interrupted_image != old_image &&
                    interrupted.xid == before.xid && interrupted.total_allocated_blocks == before.total_allocated_blocks &&
                    interrupted.extents.size() == before.extents.size() &&
                    interrupted.references.size() == before.references.size(),
                    "independent raw reopen retains old canonical XID and allocation after actual source changes")) return false;
            std::set<std::uint64_t> old_blocks;
            for (const auto& [offset, record] : before.extents)
            {
                const auto retained = interrupted.extents.find(offset);
                AppleFileExtentRecord extent;
                std::string error;
                if (!Require(retained != interrupted.extents.end() && retained->second.key == record.key &&
                        retained->second.value == record.value && DecodeAppleFileExtentRecord(record, 4096, extent, error) &&
                        before.references.contains(extent.physical_block),
                        "all old extent records, including untouched extents, remain byte-identical")) return false;
                for (std::uint64_t block = 0; block < extent.length_bytes / 4096; ++block)
                {
                    const auto physical = extent.physical_block + block;
                    const auto at = static_cast<std::size_t>(physical * 4096);
                    if (!Require(at <= image_size && 4096 <= image_size - at &&
                            std::equal(old_image.begin() + at, old_image.begin() + at + 4096,
                                interrupted_image.begin() + at),
                            "old referenced physical bytes survive, including the selected source extent")) return false;
                    old_blocks.insert(physical);
                }
            }
            for (const auto& [physical, record] : before.references)
            {
                const auto retained = interrupted.references.find(physical);
                if (!Require(retained != interrupted.references.end() && retained->second.key == record.key &&
                        retained->second.value == record.value,
                        "old physical ownership/reference records remain byte-identical")) return false;
            }
            // Locate the complete acquired payload in changed, newly written blocks.
            // Matching only changed blocks excludes pre-existing fixture bytes.
            std::size_t candidate_blocks = 0;
            for (std::size_t at = 0; at + 4096 <= image_size; at += 4096)
            {
                if (std::equal(old_image.begin() + at, old_image.begin() + at + 4096,
                        interrupted_image.begin() + at) ||
                    !std::equal(expected.begin() + chunk, expected.begin() + chunk + 4096,
                        interrupted_image.begin() + at)) continue;
                if (!Require(!old_blocks.contains(at / 4096),
                        "new partial COW payload occupies blocks outside every old file extent")) return false;
                ++candidate_blocks;
            }
            if (!Require(candidate_blocks == 1 &&
                    !std::equal(expected.begin() + chunk, expected.begin() + chunk + 4096,
                        old_content.begin() + chunk),
                    "exactly one changed new source block contains the edited payload, not just new metadata") ||
                !check_fresh(old_content)) return false;
            MetadataStore reopened(context);
            if (!Require(reopened.PrepareNativeWritePath() && reopened.CheckpointXid() == before.xid,
                    "independent native reopen selects the original canonical transaction")) return false;
            for (const auto* path : {L"\\primary", L"\\alias"})
            {
                const auto inode = reopened.LookupCommittedInodeByPath(path);
                if (!Require(inode && inode->xid == seed_inode.xid &&
                        inode->modification_time_utc == seed_inode.modification_time_utc &&
                        inode->change_time_utc == seed_inode.change_time_utc,
                        "unpublished content timestamps and generation do not leak through either alias")) return false;
            }
            // Exercise the public recovery entry point with the existing FailClosed
            // policy. This fixture has no host WAL; do not synthesize replay authority.
            if (!Require(!metadata.ReplayOrRecover() && metadata.IsRecoveryRequired() &&
                    !metadata.IsCommitPathReady() && metadata.PendingMutationCount() == pending &&
                    metadata.CommitPendingMutations() == MetadataStore::CommitStatus::NotWritable &&
                    metadata.IsRecoveryRequired() && metadata.PendingMutationCount() == pending &&
                    metadata.CheckpointXid() == before.xid && calls == 1 && legacy_calls == 0,
                    "FailClosed recovery and direct retry cannot report success or discard pending partial COW")) return false;
            std::vector<std::byte> after_retry;
            return Require(source.Read(0, image_size, after_retry) && after_retry == interrupted_image,
                "blocked recovery/retry writes no additional source or checkpoint bytes") && check_fresh(old_content);
        }
        if (content_times && contiguous)
        {
            // Exercise refusal on the eligible timestamp/write path, then retry
            // the same pending transaction with the exact provider identity.
            refuse_first = true;
            std::vector<std::byte> refused_image;
            if (!Require(metadata.CommitPendingMutations() == MetadataStore::CommitStatus::PersistFailed &&
                    calls == 1 && supplied == chunk && legacy_calls == 0 &&
                    metadata.PendingMutationCount() != 0 && metadata.CheckpointXid() == before.xid &&
                    metadata.Device().Read(0, image_size, refused_image) && refused_image == old_image,
                    "eligible content-time provider refusal leaves checkpoint and bytes unchanged") ||
                !check_fresh(old_content)) return false;
            refuse_first = false; calls = 0; supplied = 0;
        }
        const auto written_before = OrdinaryCowWriteCounterBytes(metadata.Device());
        if (!Require(metadata.CommitPendingMutations() == MetadataStore::CommitStatus::Committed,
                "ordinary COW update publishes")) return false;
        const auto written_after = OrdinaryCowWriteCounterBytes(metadata.Device());
        if (contiguous && !Require(calls == 1 && supplied == chunk && legacy_calls == 0 && touched == chunk,
                "contiguous 1 MiB overwrite coalesces 4 KiB records into one exact provider acquisition")) return false;
        if (!full_fallback && !Require(calls == (phase == 2 ? 2u : 1u) && legacy_calls == 0,
                "eligible ordinary writes acquire only contiguous selected windows")) return false;
        if (written_after != 0 && !Require(written_after > written_before &&
                written_after - written_before <= touched + 512 * 1024,
                "device write traffic is bounded by touched extents plus metadata")) return false;
        if (phase == 0 && written_after == 0)
            std::cout << "[INFO] ordinary COW device byte counters disabled; run this selector with "
                "APFSACCESS_PERF_COUNTERS=1 for the device traffic assertion" << std::endl;
        OrdinaryCowSnapshot after;
        if (!ReadOrdinaryCowSnapshot(image.path, after)) return false;
        std::uint64_t new_data_bytes = 0;
        for (const auto& [offset, record] : before.extents)
        {
            const auto next = after.extents.find(offset);
            if (!Require(next != after.extents.end(), "COW preserves extent coverage")) return false;
            const bool exact = record.key == next->second.key && record.value == next->second.value;
            if (!Require(exact == !replaced_offsets.contains(offset), "only overlapping complete old extent records change")) return false;
            const auto old_physical = apfsaccess::catalog::ReadU64LE(record.value, 8).value();
            const auto new_physical = apfsaccess::catalog::ReadU64LE(next->second.value, 8).value();
            if (!exact)
            {
                if (!Require(old_physical != new_physical, "changed extent uses COW physical blocks")) return false;
                new_data_bytes += apfsaccess::catalog::ReadU64LE(next->second.value, 0).value() & 0x00ffffffffffffffULL;
            }
            else
            {
                const auto old_ref = before.references.find(old_physical), next_ref = after.references.find(old_physical);
                if (!Require(old_ref != before.references.end() && next_ref != after.references.end() &&
                        old_ref->second.key == next_ref->second.key && old_ref->second.value == next_ref->second.value,
                        "untouched physical extent ownership is byte-identical")) return false;
            }
        }
        std::vector<std::byte> new_image;
        if (!Require(metadata.Device().Read(0, image_size, new_image), "COW traffic result reads")) return false;
        std::uint64_t changed_blocks = 0;
        for (std::size_t at = 0; at < image_size; at += 4096)
            if (!std::equal(old_image.begin() + at, old_image.begin() + at + 4096, new_image.begin() + at)) ++changed_blocks;
        if (!Require(new_data_bytes == touched && after.total_allocated_blocks >= before.total_allocated_blocks &&
                (after.total_allocated_blocks - before.total_allocated_blocks) * 4096 <= touched + 512 * 1024 &&
                changed_blocks * 4096 <= touched + 512 * 1024 &&
                (full_fallback ? supplied == expected.size() :
                    supplied <= touched && touched <= (contiguous ? chunk : 3 * 4096)),
                "new allocation and changed source bytes stay within touched extents plus metadata")) return false;
        if (!check_content(metadata, expected) || !check_fresh(expected) || !check_tail(after)) return false;
        if (content_times)
        {
            MetadataStore reopened(context);
            if (!Require(reopened.PrepareNativeWritePath(), "host timestamp checkpoint freshly reopens")) return false;
            if (root_content_time != 0)
            {
                const auto root = reopened.LookupCommittedInodeByPath(L"\\");
                if (!Require(root && root->modification_time_utc == root_content_time &&
                        root->change_time_utc == root_content_time,
                        "foreign-inode content times persist through full fallback")) return false;
            }
            for (const auto* path : {L"\\primary", L"\\alias"})
            {
                const auto inode = reopened.LookupCommittedInodeByPath(path);
                if (!Require(inode && inode->object_id == identity.object_id && inode->xid == identity.generation &&
                        inode->modification_time_utc == last_content_time && inode->change_time_utc == last_content_time &&
                        inode->create_time_utc == seed_inode.create_time_utc &&
                        inode->access_time_utc == seed_inode.access_time_utc &&
                        inode->owner == (phase >= 5 ? 502u : seed_inode.owner) &&
                        inode->mode == (phase >= 6 ? 0100600 : seed_inode.mode) &&
                        inode->bsd_flags == (phase >= 7 ? 0x8000u : seed_inode.bsd_flags),
                        "fresh aliases retain transaction identity, all timestamps and mixed metadata")) return false;
            }
        }
        before = std::move(after);
    }
    return true;
}

bool TestNativeAllocationSizePersistence()
{
    using namespace apfsaccess::rw;
    using apfsaccess::catalog::ReadU64LE;
    static_assert(static_cast<unsigned>(MetadataStore::MutationOperation::SetAllocationSize) == 13);
    TempImageFile image(BuildFileContentAttributeImage({}, 1024), "allocation-size");
    MetadataStore::VolumeContext context;
    context.device_path = image.path.wstring(); context.volume_object_id = 101;
    context.allow_legacy_scaffold_for_fixtures = false;
    std::vector<std::byte> expected(9000);
    for (std::size_t i = 0; i < expected.size(); ++i) expected[i] = static_cast<std::byte>(1 + i % 251);
    {
        MetadataStore seed(context);
        if (!Require(seed.PrepareNativeWritePath(), "allocation seed prepares")) return false;
        seed.SetFilePayloadProvider([&](const auto&, auto) -> std::optional<std::vector<std::byte>> { return expected; });
        MetadataStore::MutationRequest write;
        write.operation = MetadataStore::MutationOperation::Write;
        write.path = L"\\original"; write.length = expected.size();
        if (!Require(seed.StageMutation(write) == MetadataStore::MutationStatus::Applied &&
                seed.CommitPendingMutations() == MetadataStore::CommitStatus::Committed,
                "allocation seed publishes 9000 nonzero bytes")) return false;
    }
    std::wstring path = L"\\original";
    const auto check = [&](std::uint64_t allocation) -> bool
    {
        MetadataStore fresh(context);
        if (!Require(fresh.PrepareNativeWritePath(), "allocation checkpoint reopens")) return false;
        const auto inode = fresh.LookupCommittedInodeByPath(path);
        std::vector<std::byte> actual;
        bool ok = Require(inode && inode->logical_size == expected.size() && inode->allocation_size == allocation &&
            fresh.ReadCommittedFileRange(path, 0, expected.size(), actual) && actual == expected,
            "allocation and EOF reopen independently with exact prefix/zero-filled content");
        apfsaccess::catalog::HeldFileSource source(image.path.string());
        std::string error;
        const auto checkpoint = LoadAppleCheckpointView(source, 0, source.SizeBytes(), error);
        if (!Require(checkpoint.has_value(), "allocation raw checkpoint loads")) return false;
        const auto& volume = checkpoint->volumes.front();
        const auto block_size = checkpoint->container.superblock.block_size;
        std::vector<apfsaccess::catalog::BtreeRecord> records;
        if (!Require(apfsaccess::catalog::ReadBtreeLeafRecords(source, block_size,
                volume.root_tree.physical_block, false, volume.superblock.omap_oid,
                checkpoint->container.superblock.xid, records, error), "allocation raw tree reads")) return false;
        bool found_stream = false;
        std::uint64_t extent_bytes = 0;
        for (const auto& record : records)
        {
            AppleInodeRecord raw;
            if (ApfsExtendedRecordCodec::DecodeInode(record, raw, error) && raw.object_id == 17)
            {
                for (const auto& field : raw.extended_fields)
                    if (field.type == 8)
                    {
                        found_stream = true;
                        ok &= Require(ReadU64LE(field.data, 0) == expected.size() &&
                            ReadU64LE(field.data, 8) == allocation, "raw dstream stores EOF and allocation separately");
                    }
            }
            const auto key = ReadU64LE(record.key, 0).value_or(0);
            if ((key >> 60) != 8 || (key & 0x0fffffffffffffffULL) != 17) continue;
            const auto logical = ReadU64LE(record.key, 8).value_or(allocation);
            const auto length = ReadU64LE(record.value, 0).value_or(0) & 0x00ffffffffffffffULL;
            const auto physical = ReadU64LE(record.value, 8).value_or(0);
            if (!Require(length && length % block_size == 0 && logical <= allocation &&
                    length <= allocation - logical && physical != 0, "reserved extent is backed and block aligned")) return false;
            extent_bytes += length;
            std::vector<std::byte> bytes;
            if (!Require(fresh.Device().Read(physical * block_size, static_cast<std::size_t>(length), bytes),
                    "reserved physical extent reads")) return false;
            for (std::size_t i = 0; i < bytes.size(); ++i)
                if (bytes[i] != (logical + i < expected.size() ? expected[static_cast<std::size_t>(logical + i)] : std::byte{0}))
                    return Require(false, "raw allocated extent preserves prefix and zeros all bytes beyond EOF");
        }
        return Require(found_stream && extent_bytes == allocation, "raw allocation is fully backed by extents") && ok;
    };
    bool ok = true;
    // The provider supplies only EOF bytes; reserved physical tails must be zeroed by the writer.
    for (unsigned phase = 0; phase != 6; ++phase)
    {
        MetadataStore metadata(context);
        if (!Require(metadata.PrepareNativeWritePath(), "allocation mutation prepares")) return false;
        const auto identity = metadata.LookupWorkingPayloadIdentityByPath(path);
        if (!Require(identity.has_value(), "allocation identity resolves")) return false;
        const auto target_generation = metadata.CheckpointXid().value() + 1;
        auto eof_payload = expected;
        if (phase == 1) eof_payload.resize(4096);
        if (phase == 3) eof_payload.resize(9000, std::byte{0});
        metadata.SetFilePayloadRangeProvider([&](const std::wstring&, MetadataStore::PayloadIdentity owner,
                std::uint64_t offset, std::span<std::byte> destination) {
            if (owner.object_id != identity->object_id || owner.generation != target_generation ||
                offset > eof_payload.size() || destination.size() > eof_payload.size() - offset) return false;
            std::copy_n(eof_payload.begin() + static_cast<std::ptrdiff_t>(offset), destination.size(), destination.begin());
            return true;
        });
        MetadataStore::MutationRequest request;
        request.operation = MetadataStore::MutationOperation::SetAllocationSize;
        request.path = path; request.object_id = identity->object_id; request.generation = target_generation;
        request.length = phase == 1 ? 4096 : 32768;
        if (phase == 3) request.operation = MetadataStore::MutationOperation::SetFileSize, request.length = 9000;
        if (phase == 4)
        {
            request.operation = MetadataStore::MutationOperation::SetInodeMetadata;
            InodeMetadataPatch patch; patch.mask = InodeMetadataPatch::Owner; patch.owner = 502;
            if (!Require(EncodeInodeMetadataPatch(patch, request.inline_payload), "allocation metadata encodes")) return false;
            request.length = request.inline_payload.size();
        }
        if (phase == 5)
        {
            request.operation = MetadataStore::MutationOperation::Rename;
            request.secondary_path = L"\\renamed"; request.length = 0;
        }
        const auto before = metadata.LookupCommittedInodeByPath(path);
        const auto staged = metadata.StageMutation(request);
        if (!Require(staged == MetadataStore::MutationStatus::Applied,
                "allocation/EOF/metadata/rename stages with identity"))
        {
            std::wcerr << L"allocation phase=" << phase << L" status=" << static_cast<int>(staged)
                << L" reason=" << metadata.LastMutationFailureReason() << std::endl;
            return false;
        }
        if (phase == 0)
        {
            const auto working = metadata.LookupWorkingInodeByPath(path);
            ok &= Require(working && working->logical_size == 9000 && working->allocation_size == 32768,
                "reserve changes working allocation but not EOF");
            std::vector<std::byte> old_bytes, after;
            const auto size = static_cast<std::size_t>(std::filesystem::file_size(image.path));
            if (!Require(metadata.Device().Read(0, size, old_bytes), "allocation prepublication snapshot reads")) return false;
            const auto pending = metadata.PendingMutationCount();
            metadata.SetCommitStageHook([](std::string_view stage) { return stage != "before-apple-publish"; });
            ok &= Require(metadata.CommitPendingMutations() == MetadataStore::CommitStatus::PersistFailed &&
                metadata.PendingMutationCount() == pending && metadata.Device().Read(0, size, after) && old_bytes == after,
                "allocation prepublication failure retains retry and leaves image byte-identical");
            if (!Require(before && before->allocation_size.has_value(), "seed has native allocation")) return false;
            ok &= check(*before->allocation_size);
            metadata.SetCommitStageHook({});
        }
        if (!Require(metadata.CommitPendingMutations() == MetadataStore::CommitStatus::Committed,
                "allocation phase publishes or retries")) return false;
        if (phase == 1) expected.resize(4096);
        if (phase == 3) expected.resize(9000, std::byte{0});
        if (phase == 5) path = request.secondary_path;
        ok &= check(phase == 1 ? 4096 : 32768);
    }
    {
        MetadataStore metadata(context);
        if (!Require(metadata.PrepareNativeWritePath(), "allocation barrier image prepares")) return false;
        MetadataStore::MutationRequest mutation;
        mutation.path = path;
        mutation.operation = MetadataStore::MutationOperation::Write;
        mutation.length = 9000;
        if (!Require(metadata.StageMutation(mutation) == MetadataStore::MutationStatus::Applied,
                "write before allocation barrier stages")) return false;
        mutation.operation = MetadataStore::MutationOperation::SetAllocationSize;
        mutation.length = 4096;
        if (!Require(metadata.StageMutation(mutation) == MetadataStore::MutationStatus::Applied,
                "allocation truncation after pending write stages")) return false;
        mutation.operation = MetadataStore::MutationOperation::Write;
        mutation.length = 1;
        if (!Require(metadata.StageMutation(mutation) == MetadataStore::MutationStatus::Applied,
                "write after allocation barrier stages")) return false;
        ok &= Require(metadata.PendingMutationCount() == 3,
            "write compaction retains both sides of allocation barrier");
        mutation.operation = MetadataStore::MutationOperation::SetFileSize;
        mutation.length = 9000;
        if (!Require(metadata.StageMutation(mutation) == MetadataStore::MutationStatus::Applied,
                "EOF regrowth after allocation truncation stages")) return false;
        expected.resize(4096);
        expected[0] = std::byte{0xab};
        expected.resize(9000, std::byte{0});
        metadata.SetFilePayloadProvider([&](const auto&, auto) -> std::optional<std::vector<std::byte>> {
            return expected;
        });
        if (!Require(metadata.CommitPendingMutations() == MetadataStore::CommitStatus::Committed,
                "pending allocation/write sequence publishes")) return false;
        ok &= check(12288);
    }
    return ok;
}

bool TestNativeAllocationSizeEmptyAndRejections()
{
    using namespace apfsaccess::rw;
    bool ok = true;
    for (const std::uint16_t type : {0100000, 0040000, 0120000, 0010000, 0140000, 0020000, 0060000})
    {
        BuilderStore fixture;
        fixture.authoritative_checkpoint = true; fixture.volumes[0].incompat = 0;
        auto& records = fixture.volumes[0].filesystem_records;
        std::string error;
        apfsaccess::catalog::BtreeRecord encoded;
        AppleInodeRecord root;
        root.object_id = root.parent_id = root.private_id = 2; root.mode = 0040755; root.children_or_links = 1;
        if (!Require(EncodeAppleInodeRecord(root, encoded, error), "allocation rejection root encodes")) return false;
        records.push_back(encoded);
        AppleInodeRecord inode;
        inode.object_id = inode.private_id = 17; inode.parent_id = 2;
        inode.mode = type | 0644; inode.children_or_links = type == 0040000 ? 0 : 1;
        if (type == 0120000) inode.uncompressed_size = 1;
        if (!Require(EncodeAppleInodeRecord(inode, encoded, error), "allocation rejection inode encodes")) return false;
        records.push_back(encoded);
        AppleDirectoryRecord link;
        link.parent_id = 2; link.file_id = 17; link.flags = type >> 12; link.name_utf8 = "target";
        if (!Require(EncodeAppleDirectoryRecord(link, encoded, error), "allocation rejection link encodes")) return false;
        records.push_back(encoded);
        if (type == 0120000)
        {
            if (!Require(EncodeAppleXattrRecord({17, "com.apple.fs.symlink", kAppleXattrDataEmbedded,
                    {std::byte{'x'}}}, encoded, error), "allocation symlink encodes")) return false;
            records.push_back(encoded);
        }
        TempImageFile image(BuildStoreImage(fixture), "allocation-rejections");
        MetadataStore::VolumeContext context;
        context.device_path = image.path.wstring(); context.volume_object_id = 101;
        context.allow_legacy_scaffold_for_fixtures = false;
        MetadataStore metadata(context);
        if (!Require(metadata.PrepareNativeWritePath(), "allocation rejection image prepares"))
        {
            std::wcerr << L"allocation rejection type=" << type << L" reason="
                << metadata.LastCanonicalGateFailure() << std::endl;
            return false;
        }
        const auto identity = metadata.LookupWorkingInodeByPath(L"\\target");
        if (!Require(identity.has_value(), "allocation rejection identity resolves")) return false;
        MetadataStore::MutationRequest request;
        request.operation = MetadataStore::MutationOperation::SetAllocationSize;
        request.path = L"\\target"; request.object_id = identity->object_id;
        request.generation = metadata.CheckpointXid().value() + 1;
        std::vector<std::byte> before, after;
        const auto size = static_cast<std::size_t>(std::filesystem::file_size(image.path));
        if (!Require(metadata.Device().Read(0, size, before), "allocation rejection snapshot reads")) return false;
        const auto initial = metadata.LookupWorkingInodeByPath(request.path);
        if (!Require(initial.has_value(), "allocation rejection initial inode exists")) return false;
        // Exhaust only this small synthetic image; overflow values must fail admission before allocation.
        for (unsigned scenario = 0; scenario != (type == 0100000 ? 8u : 1u); ++scenario)
        {
            auto invalid = request; invalid.length = 32768;
            if (type == 0100000)
            {
                if (scenario == 0) invalid.length = ((size + 4095) / 4096 + 1) * 4096;
                if (scenario == 1) invalid.length = 1ULL << 63;
                if (scenario == 2) invalid.length = ~0ULL;
                if (scenario == 3) invalid.offset = 1;
                if (scenario == 4) invalid.inline_payload = {std::byte{1}};
                if (scenario == 5) ++invalid.object_id;
                if (scenario == 6) ++invalid.generation;
                if (scenario == 7) invalid.length = 32769;
            }
            const auto status = metadata.StageMutation(invalid);
            const auto working = metadata.LookupWorkingInodeByPath(request.path);
            ok &= Require(status != MetadataStore::MutationStatus::Applied && metadata.PendingMutationCount() == 0 &&
                working && working->logical_size == initial->logical_size && working->allocation_size == initial->allocation_size &&
                metadata.Device().Read(0, size, after) && before == after,
                "invalid type/envelope/overflow/exhaustion accepts no state and writes no bytes");
        }
        if (type != 0100000) continue;
        request.length = 32768;
        if (!Require(metadata.StageMutation(request) == MetadataStore::MutationStatus::Applied &&
                metadata.CommitPendingMutations() == MetadataStore::CommitStatus::Committed,
                "empty reservation succeeds after rejected allocations")) return false;
        MetadataStore reopened(context);
        if (!Require(reopened.PrepareNativeWritePath(), "empty allocation reopens")) return false;
        const auto empty = reopened.LookupCommittedInodeByPath(request.path);
        ok &= Require(empty && empty->logical_size == 0 && empty->allocation_size == 32768,
            "empty file retains zero EOF and durable reserved allocation");
        MetadataStore::MutationRequest remove;
        remove.operation = MetadataStore::MutationOperation::Delete;
        remove.path = request.path;
        if (!Require(reopened.StageMutation(remove) == MetadataStore::MutationStatus::Applied &&
                reopened.CommitPendingMutations() == MetadataStore::CommitStatus::Committed,
                "unlink of empty reserved file releases its allocation records")) return false;
        MetadataStore removed(context);
        if (!Require(removed.PrepareNativeWritePath(), "empty reserved unlink reopens")) return false;
        ok &= Require(!removed.LookupCommittedInodeByPath(request.path),
            "empty reserved inode is absent after fresh reopen");
    }
    return ok;
}

bool TestNativeAllocationSizeCreateSameBatch()
{
    using namespace apfsaccess::rw;
    using apfsaccess::catalog::ReadU64LE;
    TempImageFile image(BuildFileContentAttributeImage({}, 256), "allocation-create-batch");
    MetadataStore::VolumeContext context;
    context.device_path = image.path.wstring(); context.volume_object_id = 101;
    context.allow_legacy_scaffold_for_fixtures = false;
    MetadataStore metadata(context);
    if (!Require(metadata.PrepareNativeWritePath(), "create/reserve image prepares")) return false;
    MetadataStore::MutationRequest request;
    request.operation = MetadataStore::MutationOperation::CreateFile;
    request.path = L"\\reserved";
    if (!Require(metadata.StageMutation(request) == MetadataStore::MutationStatus::Applied,
            "new empty file stages without an intermediate commit")) return false;
    const auto inode = metadata.LookupWorkingInodeByPath(request.path);
    if (!Require(inode.has_value(), "new reservation inode resolves")) return false;
    request.operation = MetadataStore::MutationOperation::SetAllocationSize;
    request.object_id = inode->object_id;
    request.generation = metadata.CheckpointXid().value() + 1;
    request.length = 32768;
    metadata.SetFilePayloadRangeProvider([&](const std::wstring&, MetadataStore::PayloadIdentity owner,
            std::uint64_t offset, std::span<std::byte> destination) {
        return owner.object_id == request.object_id && owner.generation == request.generation &&
            offset == 0 && destination.empty();
    });
    if (!Require(metadata.StageMutation(request) == MetadataStore::MutationStatus::Applied &&
            metadata.CommitPendingMutations() == MetadataStore::CommitStatus::Committed,
            "create and reserve publish in the same batch")) return false;
    apfsaccess::catalog::HeldFileSource source(image.path.string());
    std::string error;
    const auto checkpoint = LoadAppleCheckpointView(source, 0, source.SizeBytes(), error);
    if (!Require(checkpoint.has_value(), "new reservation raw checkpoint loads")) return false;
    const auto& volume = checkpoint->volumes.front();
    const auto block_size = checkpoint->container.superblock.block_size;
    std::vector<apfsaccess::catalog::BtreeRecord> records;
    if (!Require(apfsaccess::catalog::ReadBtreeLeafRecords(source, block_size,
            volume.root_tree.physical_block, false, volume.superblock.omap_oid,
            checkpoint->container.superblock.xid, records, error), "new reservation raw tree reads")) return false;
    bool found_stream = false;
    std::uint64_t extent_bytes = 0;
    for (const auto& record : records)
    {
        AppleInodeRecord raw;
        if (ApfsExtendedRecordCodec::DecodeInode(record, raw, error) && raw.object_id == request.object_id)
            for (const auto& field : raw.extended_fields)
                if (field.type == 8)
                {
                    if (!Require(ReadU64LE(field.data, 0) == 0 && ReadU64LE(field.data, 8) == 32768,
                            "new raw dstream retains zero EOF and 32768 allocation")) return false;
                    found_stream = true;
                }
        const auto key = ReadU64LE(record.key, 0).value_or(0);
        if ((key >> 60) != 8 || (key & 0x0fffffffffffffffULL) != request.object_id) continue;
        const auto logical = ReadU64LE(record.key, 8).value_or(32768);
        const auto length = ReadU64LE(record.value, 0).value_or(0) & 0x00ffffffffffffffULL;
        const auto physical = ReadU64LE(record.value, 8).value_or(0);
        if (!Require(logical == extent_bytes && length != 0 && length % block_size == 0 &&
                extent_bytes <= 32768 && length <= 32768 - extent_bytes && physical != 0,
                "new reservation extents are contiguous logically and physically backed")) return false;
        std::vector<std::byte> bytes;
        if (!Require(source.Read(physical * block_size, static_cast<std::size_t>(length), bytes) &&
                bytes.size() == length && std::all_of(bytes.begin(), bytes.end(),
                    [](std::byte value) { return value == std::byte{0}; }),
                "new reservation physical bytes are all zero")) return false;
        extent_bytes += length;
    }
    return Require(found_stream && extent_bytes == 32768, "new raw allocation is fully backed beyond zero EOF");
}

bool TestNativeAllocationSizeContiguousEmptyImport()
{
    using namespace apfsaccess::rw;
    BuilderStore fixture;
    fixture.block_count = 256;
    fixture.authoritative_checkpoint = true;
    auto& volume = fixture.volumes[0];
    volume.incompat = 0;
    volume.additional_file_system_allocated_blocks = 8;
    auto& records = volume.filesystem_records;
    std::string error;
    apfsaccess::catalog::BtreeRecord encoded;
    AppleInodeRecord root;
    root.object_id = root.parent_id = root.private_id = 2;
    root.mode = 0040755; root.children_or_links = 1;
    if (!Require(EncodeAppleInodeRecord(root, encoded, error), "contiguous root encodes")) return false;
    records.push_back(encoded);
    AppleInodeRecord file;
    file.object_id = file.private_id = 17; file.parent_id = 2;
    file.mode = 0100644; file.children_or_links = 1;
    std::vector<std::byte> stream(40, std::byte{0});
    PutU64LE(stream, 8, 32768);
    file.extended_fields.push_back({8, 0, stream});
    if (!Require(EncodeAppleInodeRecord(file, encoded, error), "contiguous empty dstream encodes")) return false;
    records.push_back(encoded);
    if (!Require(EncodeAppleDirectoryRecord({2, 17, 0, 8, "reserved"}, encoded, error),
            "contiguous link encodes")) return false;
    records.push_back(encoded);
    if (!Require(EncodeAppleFileExtentRecord({17, 0, 32768, 128, 0, 4096}, encoded, error),
            "single contiguous backed extent encodes")) return false;
    records.push_back(encoded);
    if (!Require(SortAppleBtreeRecords(records, AppleBtreeKeyOrder::FileSystemCaseSensitive, error),
            "contiguous filesystem records sort")) return false;
    if (!Require(EncodeApplePhysicalExtentRecord({128, 8, kApplePhysicalExtentKindNew, 17, 1}, encoded, error),
            "contiguous physical ownership encodes")) return false;
    volume.extentref_records.push_back(encoded);
    // Seed nonzero blocks so the builder marks all eight allocated in its checksummed bitmap.
    for (std::uint64_t block = 128; block != 136; ++block)
        fixture.authoritative_seeded_main_blocks.push_back({block, std::vector<std::byte>(4096, std::byte{1})});
    auto bytes = BuildStoreImage(fixture);
    std::fill(bytes.begin() + 128 * 4096, bytes.begin() + 136 * 4096, std::byte{0});
    TempImageFile image(bytes, "allocation-contiguous-empty");
    MetadataStore::VolumeContext context;
    context.device_path = image.path.wstring(); context.volume_object_id = 101;
    context.allow_legacy_scaffold_for_fixtures = false;
    MetadataStore metadata(context);
    if (!Require(metadata.PrepareNativeWritePath(), "contiguous zero-EOF reservation passes default mount integrity")) return false;
    const auto inode = metadata.LookupCommittedInodeByPath(L"\\reserved");
    return Require(inode && inode->logical_size == 0 && inode->allocation_size == 32768 &&
        metadata.VerifyIntegrity(), "contiguous zero-EOF reservation passes explicit integrity");
}

bool TestNativeAllocationSizePendingShrinkReclaims()
{
    using namespace apfsaccess::rw;
    TempImageFile image(BuildFileContentAttributeImage({}, 256), "allocation-pending-shrink");
    MetadataStore::VolumeContext context;
    context.device_path = image.path.wstring(); context.volume_object_id = 101;
    context.allow_legacy_scaffold_for_fixtures = false;
    MetadataStore metadata(context);
    if (!Require(metadata.PrepareNativeWritePath(), "pending shrink image prepares")) return false;
    MetadataStore::MutationRequest request;
    request.operation = MetadataStore::MutationOperation::SetAllocationSize;
    request.path = L"\\original"; request.object_id = 17;
    request.generation = metadata.CheckpointXid().value() + 1;
    request.length = 32768;
    const auto baseline = metadata.DebugWorkingFreeExtentTotalBytes();
    if (!Require(metadata.StageMutation(request) == MetadataStore::MutationStatus::Applied,
            "pending empty reservation stages")) return false;
    const auto reserved = metadata.DebugWorkingFreeExtentTotalBytes();
    request.length = 4096;
    if (!Require(metadata.StageMutation(request) == MetadataStore::MutationStatus::Applied,
            "pending empty reservation shrinks before commit")) return false;
    const auto shrunk = metadata.DebugWorkingFreeExtentTotalBytes();
    const auto inode = metadata.LookupWorkingInodeByPath(request.path);
    return Require(baseline >= reserved + 32768 && shrunk >= reserved + 28672 && shrunk < baseline &&
        inode && inode->logical_size == 0 && inode->allocation_size == 4096 && metadata.PendingMutationCount() != 0,
        "shrinking pending reserve returns at least seven data blocks before any commit");
}

bool TestTransactionalEmbeddedAttributes()
{
    using namespace apfsaccess::rw;
    BuilderStore fixture;
    fixture.authoritative_checkpoint = true;
    fixture.volumes[0].incompat = 0;
    auto& records = fixture.volumes[0].filesystem_records;
    std::string error;
    apfsaccess::catalog::BtreeRecord encoded;
    AppleInodeRecord root;
    root.object_id = root.parent_id = root.private_id = 2;
    root.children_or_links = 1; root.mode = 0040755;
    if (!Require(EncodeAppleInodeRecord(root, encoded, error), "attribute root encodes")) return false;
    records.push_back(std::move(encoded));
    AppleInodeRecord file;
    file.object_id = file.private_id = 17; file.parent_id = 2;
    file.children_or_links = 1; file.mode = 0100644;
    if (!Require(EncodeAppleInodeRecord(file, encoded, error), "attribute inode encodes")) return false;
    records.push_back(std::move(encoded));
    AppleDirectoryRecord link;
    link.parent_id = 2; link.file_id = 17; link.flags = 8; link.name_utf8 = "original";
    if (!Require(EncodeAppleDirectoryRecord(link, encoded, error), "attribute link encodes")) return false;
    records.push_back(std::move(encoded));
    AppleXattrRecord preserved{17, "user.preserved", kAppleXattrDataEmbedded,
        {std::byte{0}, std::byte{0xff}, std::byte{0x43}}};
    if (!Require(EncodeAppleXattrRecord(preserved, encoded, error), "existing attribute encodes")) return false;
    const auto preserved_record = encoded;
    records.push_back(std::move(encoded));
    AppleXattrRecord external{17, "user.external", kAppleXattrDataStream, std::vector<std::byte>(48)};
    PutU64LE(external.data, 0, 777);
    if (!Require(EncodeAppleXattrRecord(external, encoded, error), "external attribute descriptor encodes")) return false;
    records.push_back(std::move(encoded));
    if (!Require(EncodeAppleDataStreamIdRecord({777, 1}, encoded, error), "external stream reference encodes")) return false;
    records.push_back(std::move(encoded));
    TempImageFile image(BuildStoreImage(fixture), "transactional-attributes");
    MetadataStore::VolumeContext context;
    context.device_path = image.path.wstring(); context.volume_object_id = 101;
    context.allow_legacy_scaffold_for_fixtures = false;
    MetadataStore metadata(context);
    if (!Require(metadata.PrepareNativeWritePath(), "attribute image prepares")) return false;
    const auto initial = metadata.LookupCommittedExtendedAttribute(17, "user.preserved");
    bool ok = Require(initial && initial->data == preserved.data,
        "native projection retains exact binary attributes");
    MetadataStore::MutationRequest set;
    set.operation = MetadataStore::MutationOperation::SetExtendedAttribute;
    set.path = L"\\original"; set.secondary_path = L"user.binary";
    set.inline_payload = {std::byte{0x51}, std::byte{0}, std::byte{0xff}};
    set.length = set.inline_payload.size();
    MetadataStore::PayloadIdentity identity;
    if (!Require(metadata.StageMutation(set, &identity) == MetadataStore::MutationStatus::Applied,
            "binary attribute stages with identity")) return false;
    const auto pending = metadata.LookupWorkingExtendedAttribute(17, "user.binary");
    ok &= Require(identity.object_id == 17 && pending && pending->data == set.inline_payload &&
        !metadata.LookupCommittedExtendedAttribute(17, "user.binary"),
        "pending attribute is distinct from committed state");
    const auto valid_pending_count = metadata.PendingMutationCount();
    for (const auto& invalid_name : {L"", L"com.apple.fs.symlink", L"com.apple.decmpfs"})
    {
        auto invalid = set; invalid.secondary_path = invalid_name;
        ok &= Require(metadata.StageMutation(invalid) == MetadataStore::MutationStatus::InvalidRequest,
            "reserved or empty attribute name refuses before publication");
    }
    auto invalid = set;
    const auto external_read = metadata.LookupCommittedExtendedAttribute(17, "user.external");
    ok &= Require(external_read && external_read->flags == kAppleXattrDataStream &&
        external_read->data == external.data, "external lookup returns a descriptor, not fabricated file bytes");
    invalid = set;
    invalid.inline_payload.resize(WriteAheadLog::MaxExtendedAttributePayloadBytes + 1); invalid.length = invalid.inline_payload.size();
    ok &= Require(metadata.StageMutation(invalid) == MetadataStore::MutationStatus::InvalidRequest,
        "oversized attribute mutation refuses");
    invalid = set; invalid.object_id = 99; invalid.generation = identity.generation;
    ok &= Require(metadata.StageMutation(invalid) == MetadataStore::MutationStatus::InvalidRequest,
        "attribute mutation rejects stale accepted identity");
    invalid = set; ++invalid.length;
    ok &= Require(metadata.StageMutation(invalid) == MetadataStore::MutationStatus::InvalidRequest &&
        metadata.PendingMutationCount() == valid_pending_count,
        "failed admission leaves the pending transaction unchanged");

    MetadataStore::MutationRequest rename;
    rename.operation = MetadataStore::MutationOperation::Rename;
    rename.path = set.path; rename.secondary_path = L"\\renamed";
    MetadataStore::MutationRequest create;
    create.operation = MetadataStore::MutationOperation::CreateFile; create.path = set.path;
    if (!Require(metadata.StageMutation(rename) == MetadataStore::MutationStatus::Applied &&
            metadata.StageMutation(create) == MetadataStore::MutationStatus::Applied,
            "attribute owner can rename and reuse old pathname before commit")) return false;
    if (!Require(metadata.CommitPendingMutations() == MetadataStore::CommitStatus::Committed,
            "attribute and namespace batch commits")) return false;
    MetadataStore reopened(context);
    if (!Require(reopened.PrepareNativeWritePath(), "attribute checkpoint reopens")) return false;
    const auto fresh = reopened.LookupCommittedExtendedAttribute(17, "user.binary");
    const auto replacement = reopened.LookupCommittedInodeByPath(L"\\original");
    ok &= Require(fresh && fresh->data == set.inline_payload && replacement &&
        replacement->object_id != 17 &&
        !reopened.LookupCommittedExtendedAttribute(replacement->object_id, "user.binary"),
        "attribute remains on original inode across rename and path reuse");
    {
        apfsaccess::catalog::HeldFileSource source(image.path.string());
        const auto checkpoint = LoadAppleCheckpointView(source, 0, source.SizeBytes(), error);
        if (!Require(checkpoint.has_value(), "attribute checkpoint has strict raw view")) return false;
        const auto& volume = checkpoint->volumes.front();
        std::vector<apfsaccess::catalog::BtreeRecord> raw;
        if (!Require(apfsaccess::catalog::ReadBtreeLeafRecords(source,
                checkpoint->container.superblock.block_size, volume.root_tree.physical_block,
                false, volume.superblock.omap_oid, checkpoint->container.superblock.xid, raw, error),
                "raw attribute tree reads")) return false;
        ok &= Require(std::count_if(raw.begin(), raw.end(), [&](const auto& record) {
                return record.key == preserved_record.key && record.value == preserved_record.value;
            }) == 1, "unmodified raw attribute is byte-identical after publication");
    }
    set.path = L"\\renamed"; set.inline_payload.clear(); set.length = 0;
    if (!Require(reopened.StageMutation(set) == MetadataStore::MutationStatus::Applied &&
            reopened.CommitPendingMutations() == MetadataStore::CommitStatus::Committed,
            "empty attribute is a durable set, not a delete")) return false;
    const auto empty = reopened.LookupCommittedExtendedAttribute(17, "user.binary");
    ok &= Require(empty && empty->data.empty(), "empty attribute remains present");
    auto remove = set; remove.operation = MetadataStore::MutationOperation::RemoveExtendedAttribute;
    if (!Require(reopened.StageMutation(remove) == MetadataStore::MutationStatus::Applied,
            "attribute removal stages")) return false;
    std::vector<std::byte> before, after;
    const auto image_size = static_cast<std::size_t>(std::filesystem::file_size(image.path));
    ok &= Require(reopened.Device().Read(0, image_size, before), "before fault bytes read");
    reopened.SetCommitStageHook([](std::string_view stage) { return stage != "before-apple-publish"; });
    ok &= Require(reopened.CommitPendingMutations() == MetadataStore::CommitStatus::PersistFailed &&
        reopened.Device().Read(0, image_size, after) && before == after &&
        reopened.LookupCommittedExtendedAttribute(17, "user.binary") &&
        !reopened.LookupWorkingExtendedAttribute(17, "user.binary"),
        "failed publication preserves disk and committed value while retaining pending removal");
    reopened.SetCommitStageHook({});
    if (!Require(reopened.CommitPendingMutations() == MetadataStore::CommitStatus::Committed,
            "pending attribute removal retries safely")) return false;
    MetadataStore final(context);
    ok &= Require(final.PrepareNativeWritePath() && !final.LookupCommittedExtendedAttribute(17, "user.binary") &&
        final.LookupCommittedExtendedAttribute(17, "user.preserved"), "removal survives fresh reopen without collateral loss");
    set.path = L"\\original"; set.inline_payload.assign(3804, std::byte{0x87}); set.length = 3804;
    if (!Require(final.StageMutation(set) == MetadataStore::MutationStatus::Applied &&
            final.CommitPendingMutations() == MetadataStore::CommitStatus::Committed,
            "maximum embedded value publishes")) return false;
    const auto maximum = final.LookupCommittedExtendedAttribute(replacement->object_id, "user.binary");
    ok &= Require(maximum && maximum->data == set.inline_payload, "maximum value reopens with exact bytes");
    MetadataStore::MutationRequest erase;
    erase.operation = MetadataStore::MutationOperation::Delete; erase.path = set.path;
    ok &= Require(final.StageMutation(erase) == MetadataStore::MutationStatus::Applied &&
        final.CommitPendingMutations() == MetadataStore::CommitStatus::Committed &&
        !final.LookupCommittedInodeByPath(set.path) &&
        !final.LookupCommittedExtendedAttribute(replacement->object_id, "user.binary"),
        "last-link delete releases embedded records without leaking an orphan attribute");
    return ok;
}

#include "NativeSparseMutationTests.h"
#include "NativeSparseReadValidationTests.h"
#include "NativeSparseReplayTests.h"

} // namespace

int main(int argc, char** argv)
{
    const std::string selected_test = argc == 3 && std::string(argv[1]) == "--test" ? argv[2] : "";
    unsigned selected_count = 0;
    auto run = [&](const char* name, bool (*fn)())
    {
        if (!selected_test.empty() && selected_test != name) return true;
        ++selected_count;
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
    ok &= run("TestExactCheckpointSelectsRetainedGeneration", TestExactCheckpointSelectsRetainedGeneration);
    ok &= run("TestExactCheckpointRejectsUnavailableAndCorruptGeneration", TestExactCheckpointRejectsUnavailableAndCorruptGeneration);
    ok &= run("TestExactCheckpointRejectsLegacyAndAmbiguousGeneration", TestExactCheckpointRejectsLegacyAndAmbiguousGeneration);
    ok &= run("TestExactCheckpointRejectsDuplicateOmapMappings", TestExactCheckpointRejectsDuplicateOmapMappings);
    ok &= run("TestExactCheckpointRejectsMalformedOmapRecords", TestExactCheckpointRejectsMalformedOmapRecords);
    ok &= run("TestExactCheckpointOmapDistinctXidSelection", TestExactCheckpointOmapDistinctXidSelection);
    ok &= run("TestExactCheckpointAcceptsMultilevelPhysicalOmap", TestExactCheckpointAcceptsMultilevelPhysicalOmap);
    ok &= run("TestExactCheckpointRejectsIncompleteOmapTraversal", TestExactCheckpointRejectsIncompleteOmapTraversal);
    ok &= run("TestAppleSpacemanAcceptsEmptyTier2DescriptorOffset", TestAppleSpacemanAcceptsEmptyTier2DescriptorOffset);
    ok &= run("TestAppleSpacemanAcceptsVariableArraysAfterFixedStructure", TestAppleSpacemanAcceptsVariableArraysAfterFixedStructure);
    ok &= run("TestAppleSpacemanAcceptsPairKeyFreeQueueFlags", TestAppleSpacemanAcceptsPairKeyFreeQueueFlags);
    ok &= run("TestAppleSpacemanAcceptsCibTableAfterFixedStructure", TestAppleSpacemanAcceptsCibTableAfterFixedStructure);
    ok &= run("TestAuthoritativeBuilderSeparatesCheckpointAndAllocatorAreas", TestAuthoritativeBuilderSeparatesCheckpointAndAllocatorAreas);
    ok &= run("TestAppleCheckpointViewRejectsMixedGenerationAndTypeDecoys", TestAppleCheckpointViewRejectsMixedGenerationAndTypeDecoys);
    ok &= run("TestApsbRoundTrip", TestApsbRoundTrip);
    ok &= run("TestOmapResolve", TestOmapResolve);
    ok &= run("TestInterpretation", TestInterpretation);
    ok &= run("TestMetadataStoreReportsSharedVolumeCapacity", TestMetadataStoreReportsSharedVolumeCapacity);
    ok &= run("TestMetadataStoreQuotaRefusalPreservesPendingRetry", TestMetadataStoreQuotaRefusalPreservesPendingRetry);
    ok &= run("TestNativeCapacityPreviewRollback", TestNativeCapacityPreviewRollback);
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
    ok &= run("TestNativeWriterFeatureAdmission", TestNativeWriterFeatureAdmission);
    ok &= run("TestMetadataStoreCommitsAppleFileToAuthoritativeImage", TestMetadataStoreCommitsAppleFileToAuthoritativeImage);
    ok &= run("TestAppleCommitRangeProviderRefusalIsAuthoritative", TestAppleCommitRangeProviderRefusalIsAuthoritative);
    ok &= run("TestMetadataStoreAppleTransactionLifecycle", TestMetadataStoreAppleTransactionLifecycle);
    ok &= run("TestReaderCatalogTombstoneShadows", TestReaderCatalogTombstoneShadows);
    ok &= run("TestReaderSelectsNewestCheckpoint", TestReaderSelectsNewestCheckpoint);
    ok &= run("TestReaderRejectsProximityScan", TestReaderRejectsProximityScan);
    ok &= run("TestReaderProjectsNormalizationInsensitiveUnicodeName", TestReaderProjectsNormalizationInsensitiveUnicodeName);
    ok &= run("TestReaderRejectsMismatchedDirectoryHash", TestReaderRejectsMismatchedDirectoryHash);
    ok &= run("TestReaderRejectsDirectoryKeyTrailingBytes", TestReaderRejectsDirectoryKeyTrailingBytes);
    ok &= run("TestReaderProjectsHardLinksAsOneInodeWithTwoLinks", TestReaderProjectsHardLinksAsOneInodeWithTwoLinks);
    ok &= run("TestReaderProjectsSymbolicLinkTargetWithoutResolvingIt", TestReaderProjectsSymbolicLinkTargetWithoutResolvingIt);
    ok &= run("TestEmptyDirectorySymbolicLinkConversion", [] { return TestEmptyDirectorySymbolicLinkConversion(); });
    ok &= run("TestDirectorySymbolicLinkRestoration", [] { return TestEmptyDirectorySymbolicLinkConversion(true); });
    ok &= run("TestSetSymbolicLinkTargetPreservesZeroPermissions", [] {
        return TestEmptyDirectorySymbolicLinkConversion(false, 0000);
    });
    ok &= run("TestRemoveSymbolicLinkTargetPreservesZeroPermissions", [] {
        return TestEmptyDirectorySymbolicLinkConversion(false, 0000, true);
    });
    ok &= run("TestRestoreDirectoryFromSymbolicLinkPreservesZeroPermissions", [] {
        return TestEmptyDirectorySymbolicLinkConversion(true, 0000);
    });
    ok &= run("TestDirectorySymbolicLinkConversionRejectsUnsafeState", [] { return TestDirectorySymbolicLinkConversionRejectsUnsafeState(); });
    ok &= run("TestDirectoryRestorationRejectsUnsafeState", [] { return TestDirectorySymbolicLinkConversionRejectsUnsafeState(true); });
    ok &= run("TestDirectorySymbolicLinkPendingTransitions", [] { return TestDirectorySymbolicLinkPendingTransitions(); });
    ok &= run("TestDirectorySetRestoreSameBatch", [] { return TestDirectorySymbolicLinkPendingTransitions("set-restore"); });
    ok &= run("TestDirectoryRestoreCreateChildSameBatch", [] { return TestDirectorySymbolicLinkPendingTransitions("restore-child"); });
    ok &= run("TestDirectoryRenameRestoreSetRenameSameBatch", [] { return TestDirectorySymbolicLinkPendingTransitions("rename-restore-set-rename"); });
    ok &= run("TestCommittedExtendedAttributeRangeReads", TestCommittedExtendedAttributeRangeReads);
    ok &= run("TestCommittedExternalAttributeRangeRejectsInvalidStreams", TestCommittedExternalAttributeRangeRejectsInvalidStreams);
    ok &= run("TestCreationPreservesExternalAttributeStream", TestCreationPreservesExternalAttributeStream);
    ok &= run("TestExternalAttributePartitionOffsets", TestExternalAttributePartitionOffsets);
    ok &= run("TestAppleObjectIdFloorBounds", TestAppleObjectIdFloorBounds);
    ok &= run("TestTransactionalEmbeddedAttributes", TestTransactionalEmbeddedAttributes);
    ok &= run("TestAppleOrdinaryExtentCow", [] { return TestAppleOrdinaryExtentCow(); });
    ok &= run("TestAppleOrdinaryContentTimeExtentCow", [] { return TestAppleOrdinaryExtentCow(false, false, true); });
    ok &= run("TestAppleOrdinaryPartialCowSourceFault", [] { return TestAppleOrdinaryExtentCow(false, false, true, true); });
    ok &= run("TestAppleOrdinaryChunkLegacyProvider", [] { return TestAppleOrdinaryExtentCow(true); });
    ok &= run("TestAppleOrdinaryChunkProviderAndSourceFault", [] { return TestAppleOrdinaryExtentCow(false, true); });
    ok &= run("TestNativeAllocationSizePersistence", TestNativeAllocationSizePersistence);
    ok &= run("TestNativeAllocationSizeEmptyAndRejections", TestNativeAllocationSizeEmptyAndRejections);
    ok &= run("TestNativeAllocationSizeCreateSameBatch", TestNativeAllocationSizeCreateSameBatch);
    ok &= run("TestNativeAllocationSizeContiguousEmptyImport", TestNativeAllocationSizeContiguousEmptyImport);
    ok &= run("TestNativeAllocationSizePendingShrinkReclaims", TestNativeAllocationSizePendingShrinkReclaims);
    ok &= run("TestTransactionalInodeMetadata", TestTransactionalInodeMetadata);
    ok &= run("TestNativeSpecialNodePreservation", TestNativeSpecialNodePreservation);
    ok &= run("TestOrdinaryEmbeddedAttributesSurviveContentWrites", TestOrdinaryEmbeddedAttributesSurviveContentWrites);
    ok &= run("TestContentWritesRefuseProtectedAttributes", TestContentWritesRefuseProtectedAttributes);
    ok &= run("TestCompressionDefaultDataAdmission", TestCompressionDefaultDataAdmission);
    ok &= run("TestNativeCompressionInlineReads", TestNativeCompressionInlineReads);
    ok &= run("TestNativeRemainingCompressionReads", TestNativeRemainingCompressionReads);
    ok &= run("TestNativeCompressionRewrite", [] { return TestNativeCompressionRewrite(); });
    ok &= run("TestNativeCompressionRewriteFaults", [] { return TestNativeCompressionRewrite(true); });
    ok &= run("TestNativeCompressionRewriteRefusals", TestNativeCompressionRewriteRefusals);
    ok &= run("TestNativeCompressionRewriteTimestamps", [] { return TestNativeCompressionRewrite(false, true); });
    ok &= run("TestNativeCompressionRewriteTimestampFaults", [] { return TestNativeCompressionRewrite(true, true); });
    ok &= run("TestNativeCompressionRewriteTimestampRefusals", TestNativeCompressionRewriteTimestampRefusals);
    ok &= run("TestNativeModernCompressionRewrite", [] { return TestNativeCompressionRewrite(false, false, true); });
    ok &= run("TestNativeModernCompressionRewriteFaults", [] { return TestNativeCompressionRewrite(true, false, true); });
    ok &= run("TestNativeModernCompressionRewriteTimestamps", [] { return TestNativeCompressionRewrite(false, true, true); });
    ok &= run("TestNativeRemainingCompressionRewrite", [] { return TestNativeCompressionRewrite(false, false, false, true); });
    ok &= run("TestNativeRemainingCompressionRewriteFaults", [] { return TestNativeCompressionRewrite(true, false, false, true); });
    ok &= run("TestNativeRemainingCompressionRewriteTimestamps", [] { return TestNativeCompressionRewrite(false, true, false, true); });
    ok &= run("TestNativeCompressionResourceReads", TestNativeCompressionResourceReads);
    ok &= run("TestNativeCompressionMalformedReads", TestNativeCompressionMalformedReads);
    ok &= run("TestNativeCompressionReadBudgets", TestNativeCompressionReadBudgets);
    ok &= run("TestNativeCompressionUnflaggedPadding", TestNativeCompressionUnflaggedPadding);
    ok &= run("TestNativeCompressionExactCheckpointSizes", TestNativeCompressionExactCheckpointSizes);
    ok &= run("TestNativeCompressionSnapshotIdentityAndPublication", TestNativeCompressionSnapshotIdentityAndPublication);
    ok &= run("TestCompressionPendingAndOriginalAdmission", TestCompressionPendingAndOriginalAdmission);
    ok &= run("TestSparseRecordPreservationAndRewrite", TestSparseRecordPreservationAndRewrite);
    ok &= run("TestNativeSparseMutation", [] { return TestNativeSparseMutation(); });
    ok &= run("TestNativeSparseHugeHole", [] { return TestNativeSparseMutation(true); });
    ok &= run("TestNativeSparseBeforePublication", [] { return TestNativeSparseMutation(false, "before-apple-checkpoint-switch"); });
    ok &= run("TestNativeSparseAfterPublication", [] { return TestNativeSparseMutation(false, "after-apple-publish"); });
    ok &= run("TestNativeSparseInvalidRecords", TestNativeSparseInvalidRecords);
    ok &= run("TestNativeSparseWalReplay", TestNativeSparseWalReplay);
    ok &= run("TestNativeSparseCommittedRegrowth353", TestNativeSparseCommittedRegrowth353);
    ok &= run("TestNativeSparseAllocationPathReuse353", TestNativeSparseAllocationPathReuse353);
    ok &= run("TestNativeSparsePreflightAllocationFailure353", TestNativeSparsePreflightAllocationFailure353);
    ok &= run("TestNativeSparseResizeRollback368", TestNativeSparseResizeRollback368);
    ok &= run("TestNativeSparseReadInvalidFields", TestNativeSparseReadInvalidFields);
    ok &= run("TestNativeSparseReadInvalidExtents", TestNativeSparseReadInvalidExtents);
    ok &= run("TestNativeSparseReadAllHole", TestNativeSparseReadAllHole);
    ok &= run("TestNativeSparseReadHugeHole", TestNativeSparseReadHugeHole);
    ok &= run("TestNativeSparseReadCompatibleMetadata", TestNativeSparseReadCompatibleMetadata);
    ok &= run("TestNativeSparseAllocationRenameWal357", TestNativeSparseAllocationRenameWal357);
    ok &= run("TestCompressionExternalRawAttributeAdmission", TestCompressionExternalRawAttributeAdmission);
    ok &= run("TestContentWritesSupportPendingResourceFork", TestContentWritesSupportPendingResourceFork);
    ok &= run("TestResourceForkNewOwnerSameTransaction", TestResourceForkNewOwnerSameTransaction);
    ok &= run("TestResourceForkOwnerPolicyAndPlanner", TestResourceForkOwnerPolicyAndPlanner);
    ok &= run("TestResourceForkPendingOwnerTransitions", TestResourceForkPendingOwnerTransitions);
    ok &= run("TestExternalAttributesSurviveContentWrites", [] { return TestExternalAttributesSurviveContentWrites(); });
    ok &= run("TestExternalAttributeRemovalRetiresOnlyLastOwner", [] { return TestExternalAttributeRemovalRetiresOnlyLastOwner(); });
    ok &= run("TestTransactionalExternalAttributeWrites", [] { return TestTransactionalExternalAttributeWrites(); });
    ok &= run("TestNewExternalAttributePlannerRejectsInvalidBindings", TestNewExternalAttributePlannerRejectsInvalidBindings);
    ok &= run("TestExternalAttributeProtectedOwnerMutations", TestExternalAttributeProtectedOwnerMutations);
    ok &= run("TestExternalAttributeRetirementPlannerRejectsInvalidOwnership", TestExternalAttributeRetirementPlannerRejectsInvalidOwnership);
    ok &= run("TestResourceForkSurvivesContentWrites", [] { return TestExternalAttributesSurviveContentWrites(true); });
    ok &= run("TestResourceForkRetiresOnlyLastOwner", [] { return TestExternalAttributeRemovalRetiresOnlyLastOwner(true); });
    ok &= run("TestTransactionalResourceForkWrites", [] { return TestTransactionalExternalAttributeWrites(true); });
    ok &= run("TestCatalogResolveVolumeContainerQualified", TestCatalogResolveVolumeContainerQualified);
    ok &= run("TestCatalogResolveVolumeByNameInScopedContainer", TestCatalogResolveVolumeByNameInScopedContainer);
    ok &= run("TestPortableSha256Vectors", TestPortableSha256Vectors);
    ok &= run("TestApfsBudgetRejectsReadBeforeAllocation", apfsaccess::read_budget_tests::TestApfsBudgetRejectsReadBeforeAllocation);
    ok &= run("TestApfsBudgetCumulativeViewsAndIdentity", apfsaccess::read_budget_tests::TestApfsBudgetCumulativeViewsAndIdentity);
    ok &= run("TestApfsBudgetRecordsBeforeAppend", apfsaccess::read_budget_tests::TestApfsBudgetRecordsBeforeAppend);
    ok &= run("TestApfsBudgetMalformedWalkClearsOutput", apfsaccess::read_budget_tests::TestApfsBudgetMalformedWalkClearsOutput);
    ok &= run("TestApfsBudgetRecursiveObjectMap", apfsaccess::read_budget_tests::TestApfsBudgetRecursiveObjectMap);
    ok &= run("TestApfsBudgetCheckpointAndNativeAdapter", apfsaccess::read_budget_tests::TestApfsBudgetCheckpointAndNativeAdapter);
    ok &= run("TestApfsRecoveryBudgetObjectExpansion", apfsaccess::recovery_budget_tests::TestApfsRecoveryBudgetObjectExpansion);
    ok &= run("TestApfsRecoveryBudgetSpacemanReferences", apfsaccess::recovery_budget_tests::TestApfsRecoveryBudgetSpacemanReferences);
    ok &= run("TestApfsRecoveryBudgetPendingHistory", apfsaccess::recovery_budget_tests::TestApfsRecoveryBudgetPendingHistory);
    ok &= run("TestApfsRecoveryBudgetAllocationFailure", apfsaccess::recovery_budget_tests::TestApfsRecoveryBudgetAllocationFailure);
    ok &= run("TestApfsRecoveryBudgetEncodedOwnership", apfsaccess::recovery_budget_tests::TestApfsRecoveryBudgetEncodedOwnership);
    if (!selected_test.empty() && selected_count != 1)
        ok &= Require(false, "unknown or duplicate test selector: " + selected_test);
    if (ok)
    {
        std::cout << "APFS COMPATIBILITY PASS" << std::endl;
        return 0;
    }
    std::cerr << "APFS COMPATIBILITY FAIL: " << g_failures << " check(s)" << std::endl;
    return 1;
}
