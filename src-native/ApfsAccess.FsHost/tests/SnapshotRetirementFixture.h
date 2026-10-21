#pragma once

#include "../../ApfsAccess.ApfsRwEngine/tests/SnapshotTestFixture.h"
#include "AppleVolumeTransaction.h"

#include <algorithm>
#include <array>
#include <memory>
#include <set>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace apfsaccess::testfixture {

// Completes the default dispatch fixture before Save. Throws without changing
// the caller's image; planning and proofs operate only on held memory sources.
inline void CompleteDispatchSnapshotRetirementFixture(SnapshotFixture& fixture) {
    using namespace apfsaccess::rw;
    const auto require = [](bool ok, const std::string& message) {
        if (!ok) throw std::runtime_error("dispatch retirement fixture: " + message);
    };
    std::string error;
    const auto require_api = [&](bool ok, const char* operation) {
        require(ok, std::string(operation) + ": " + error);
    };
    constexpr std::uint64_t block_count = 512;
    constexpr std::uint32_t block_size = 4096;
    require(fixture.bs == block_size && fixture.image.size() == block_count * block_size,
        "expected default 512-block, 4096-byte image");
    const ApfsSnapshotScope expected_scope{0, fixture.image.size(),
        std::string(32, 'a'), std::string(32, 'b'), 101, 20};
    require(fixture.scope == expected_scope, "expected checkpoint-20 dispatch scope");

    auto budget = std::make_shared<ApfsReadBudget>(65536, 256ull << 20,
        1000000, 256ull << 20);
    VectorRandomAccessSource original(fixture.image);
    BudgetedRandomAccessSource source(original, budget);
    const auto checkpoint = LoadAppleCheckpointView(source, 0, source.SizeBytes(), error);
    require(checkpoint.has_value(), "source checkpoint: " + error);
    const auto& nx = checkpoint->container.superblock;
    require(nx.block_size == block_size && nx.block_count == block_count &&
        nx.xid == 20 && nx.next_xid == 21 && nx.uuid_hex == expected_scope.container_uuid_hex &&
        nx.xp_desc_base_block == 11 && nx.xp_desc_block_count == 8 &&
        nx.xp_data_base_block == 19 && nx.xp_data_block_count == 8 &&
        checkpoint->container.superblock_physical_block == 12,
        "expected default authoritative checkpoint geometry");
    require(checkpoint->volumes.size() == 1, "expected sole volume 101");
    const auto& volume = checkpoint->volumes.front();
    require(volume.superblock.object_id == 101 && volume.superblock.xid == 20 &&
        volume.superblock.uuid_hex == expected_scope.volume_uuid_hex &&
        volume.superblock_object.physical_block == 4 && volume.superblock.omap_oid == 5 &&
        volume.object_map.object.physical_block == 5 && volume.object_map.tree.physical_block == 6 &&
        volume.superblock.root_oid == SnapshotFixture::root_oid &&
        volume.root_tree.physical_block == 7 && volume.extentref_tree &&
        volume.extentref_tree->physical_block == 8 && volume.snapshot_metadata_tree &&
        volume.snapshot_metadata_tree->physical_block == 9 &&
        volume.superblock.snap_meta_tree_oid == SnapshotFixture::snap_oid &&
        !volume.file_extent_tree && volume.superblock.space.allocated_block_count == 6,
        "expected uncompleted live volume graph and charge");
    require(checkpoint->container_object_map.object.physical_block == 2 &&
        checkpoint->container_object_map.tree.physical_block == 3 &&
        checkpoint->container_object_map.flags == 1 &&
        volume.object_map.snapshot_tree_oid == 185,
        "expected container and live snapshot OMAPs");

    const auto read_block = [&](std::uint64_t block) {
        Bytes bytes;
        require_api(source.Read(block * block_size, block_size, bytes), "source block read");
        return bytes;
    };
    const auto live_apsb = read_block(4);
    require(ReadU64LE(live_apsb, 0xD8) == 1 && ReadU64LE(live_apsb, 0xE0) == 6 &&
        ReadU64LE(live_apsb, 0xE8) == 0, "expected initial live accounting");
    std::vector<AppleSnapshotRecord> inventory;
    AppleSnapshotTreeRecords backup_trees;
    require_api(LoadAppleSnapshotRecords(source, *checkpoint, 101, inventory, error,
        10, backup_trees), "source exact backup inventory");
    require(inventory.size() == 1 && inventory.front().xid == 10 &&
        inventory.front().name_utf8 == "backup", "expected sole backup snapshot");
    const auto& backup = inventory.front().volume;
    const auto historical_apsb = read_block(180);
    require(backup.superblock_object.physical_block == 180 && backup.superblock.xid == 10 &&
        backup.superblock.object_id == 180 && backup.superblock.omap_oid == 181 &&
        backup.object_map.tree.physical_block == 6 && backup.root_tree.physical_block == 183 &&
        backup.superblock.root_oid == SnapshotFixture::root_oid && backup.extentref_tree &&
        backup.extentref_tree->physical_block == 184 && backup.superblock.snap_meta_tree_oid == 0 &&
        backup.superblock.snap_meta_tree_type == kObjectTypeBtree &&
        ReadU64LE(historical_apsb, 0x58) == 0 && ReadU64LE(historical_apsb, 0xD8) == 0 &&
        ReadU64LE(historical_apsb, 0xE0) == 0 && ReadU64LE(historical_apsb, 0xE8) == 0,
        "expected incomplete XID-10 historical descriptor");

    const auto read_tree = [&](const AppleObjectLocation& root, std::uint64_t omap) {
        BtreeReadPolicy policy;
        policy.enforce_object_identity = true;
        policy.require_complete_traversal = true;
        policy.reject_unsupported_flags = true;
        policy.root_object_id = root.object_id;
        policy.storage_type = root.type & kObjectStorageTypeMask;
        policy.subtype = root.subtype;
        std::vector<apfsaccess::catalog::BtreeRecord> records;
        const bool physical = policy.storage_type == kObjectPhysical;
        require_api(ReadBtreeLeafRecords(source, block_size, root.physical_block,
            physical, physical ? 0 : omap, nx.xid, policy, records, error), "source tree read");
        return records;
    };
    const auto mappings = read_tree(volume.object_map.tree, 0);
    const std::array<OmapRecordSpec, 3> expected_mappings{{
        {SnapshotFixture::root_oid, 183, 0, 10},
        {SnapshotFixture::root_oid, 7, 0, 20},
        {SnapshotFixture::snap_oid, 9, 0, 20}}};
    require(mappings.size() == expected_mappings.size(), "expected complete three-entry live OMAP");
    for (std::size_t i = 0; i < mappings.size(); ++i) {
        const auto& record = mappings[i];
        const auto& expected = expected_mappings[i];
        require(record.key.size() == 16 && record.value.size() == 16 &&
            ReadU64LE(record.key, 0) == expected.oid && ReadU64LE(record.key, 8) == expected.xid &&
            ReadU32LE(record.value, 0) == 0 && ReadU32LE(record.value, 4) == block_size &&
            ReadU64LE(record.value, 8) == expected.paddr, "expected exact historical/live OMAP mappings");
    }
    const auto live_fs = read_tree(volume.root_tree, volume.superblock.omap_oid);
    require(live_fs.size() == 1 && backup_trees.filesystem.size() == 1 &&
        ReadU64LE(live_fs.front().key, 0) == ((3ull << 60) | 2) &&
        live_fs.front().value == BuildRootInodeValue(2, 9) &&
        backup_trees.filesystem.front().key == live_fs.front().key &&
        backup_trees.filesystem.front().value == live_fs.front().value &&
        backup_trees.extentref.empty() && read_tree(*volume.extentref_tree, 0).empty(),
        "expected root-only live and backup file views with empty extentrefs");

    const auto& spaceman = checkpoint->spaceman;
    require(spaceman.object.physical_block == 19 && spaceman.chunks.size() == 1 &&
        spaceman.internal_pool.base_block == 43 && spaceman.internal_pool.block_count == 4 &&
        spaceman.internal_pool.bitmap_base_block == 27 &&
        spaceman.devices[0].block_count == block_count && spaceman.devices[0].cibs.size() == 1 &&
        spaceman.devices[1].block_count == 0, "expected default single-chunk allocator");
    const auto& chunk = spaceman.chunks.front();
    require(chunk.start_block == 0 && chunk.block_count == block_count && chunk.device_index == 0 &&
        chunk.cib_index == 0 && chunk.index_in_cib == 0 && chunk.bitmap_block == 44 &&
        spaceman.devices[0].cibs.front().object.physical_block == 43 &&
        chunk.allocation_bitmap.size() == block_size, "expected default CIB and bitmap locations");
    for (const auto& queue : spaceman.free_queues)
        require(queue.entries.empty() && queue.block_count == 0, "expected no queued allocator owners");
    const std::array<std::uint64_t, 5> old_overlays{{180, 181, 183, 184, 185}};
    const std::array<std::uint64_t, 2> new_blocks{{182, 186}};
    auto historical_omap = BuildOmap(6, 20, block_size, 181,
        kObjectPhysical | kObjectTypeOmap, kObjectPhysical | kObjectTypeBtree);
    FletcherForBlock(historical_omap, block_size);
    require(read_block(181) == historical_omap && backup.object_map.snapshot_tree_oid == 0,
        "exact separate historical OMAP with no borrowed live snapshot index");
    const auto allocated = [&](std::uint64_t block) {
        return (std::to_integer<unsigned>(chunk.allocation_bitmap.at(block / 8)) &
            (1u << (block % 8))) != 0;
    };
    for (const auto block : new_blocks) {
        const auto bytes = read_block(block);
        require(!allocated(block) && std::all_of(bytes.begin(), bytes.end(),
            [](std::byte value) { return value == std::byte{0}; }),
            "new historical node must be vacant and free: " + std::to_string(block));
    }
    for (std::uint64_t block = 0; block < block_count; ++block) {
        if (std::find(old_overlays.begin(), old_overlays.end(), block) != old_overlays.end()) continue;
        const bool base_owned = block == 0 || (block >= 2 && block <= 9) || (block >= 11 && block <= 46);
        require(allocated(block) == base_owned, "unexpected source allocator owner: " + std::to_string(block));
    }

    // Stage the correction so a refused production proof cannot leave a partial fixture.
    auto completed = fixture;
    completed.Put(181, BuildOmap(182, 10, block_size, 181,
        kObjectPhysical | kObjectTypeOmap, kObjectPhysical | kObjectTypeBtree));
    completed.Put(182, BuildBtreeNode(std::vector<OmapRecordSpec>{
        {SnapshotFixture::root_oid, 183, 0, 10},
        {SnapshotFixture::snap_oid, 186, 0, 10}},
        10, block_size, 0, 182, kObjectPhysical | kObjectTypeBtree, kObjectTypeOmap));
    completed.Put(186, BuildRawLeafNode({}, {}, 10, block_size, 0,
        SnapshotFixture::snap_oid, kObjectTypeBtree, kObjectTypeSnapMetaTree));
    completed.Edit(180, [](auto& bytes) {
        PutU64LE(bytes, 0x80, 181);
        PutU64LE(bytes, 0x98, SnapshotFixture::snap_oid);
        PutU64LE(bytes, 0x58, 6);
        PutU64LE(bytes, 0xE0, 6);
    });
    completed.Edit(4, [](auto& bytes) {
        PutU64LE(bytes, 0x58, 13);
        PutU64LE(bytes, 0xE0, 13);
    });
    auto bitmap = completed.Block(chunk.bitmap_block);
    std::uint32_t added = 0;
    for (const auto block : {180ull, 181ull, 182ull, 183ull, 184ull, 185ull, 186ull}) {
        auto& byte = bitmap.at(block / 8);
        const auto mask = 1u << (block % 8);
        if (!(std::to_integer<unsigned>(byte) & mask)) {
            byte |= static_cast<std::byte>(mask);
            ++added;
        }
    }
    require(chunk.free_count >= added && spaceman.devices[0].free_count >= added,
        "allocator free-count subtraction must not underflow");
    completed.Put(chunk.bitmap_block, std::move(bitmap), false);
    completed.Edit(spaceman.devices[0].cibs[chunk.cib_index].object.physical_block,
        [&](auto& bytes) { PutU32LE(bytes, 0x3C, chunk.free_count - added); });
    completed.Edit(spaceman.object.physical_block,
        [&](auto& bytes) { PutU64LE(bytes, 0x48, spaceman.devices[0].free_count - added); });

    VectorRandomAccessSource corrected(completed.image);
    BudgetedRandomAccessSource held(corrected, budget);
    const auto canonical = LoadAppleCheckpointView(held, 0, held.SizeBytes(), error);
    require(canonical.has_value(), "corrected canonical checkpoint: " + error);
    std::vector<std::uint64_t> census;
    std::vector<ApplePhysicalExtentRecord> payload;
    require_api(LoadAppleSnapshotCheckpointOwners(held, *canonical, census, payload, error),
        "corrected production owner census");
    // XID 10 names the backup file view, not a retained container checkpoint.
    const std::vector<std::uint64_t> pins{canonical->container.superblock.xid};
    std::vector<AppleRecoveryCheckpointView> recovery;
    require_api(LoadAppleSnapshotRecoveryCheckpoints(held, *canonical, pins, recovery, error),
        "corrected current-checkpoint recovery pin");
    require(recovery.empty(), "current pin must not invent an older container checkpoint");

    // An actual typed planner supplies the serialized after endpoint; none of its
    // publication writes are applied to the fixture or to an external target.
    AppleSnapshotCreateRequest create;
    create.volume_object_id = 101;
    create.name_utf8 = "dispatch-retirement-proof";
    create.creation_time_ns = 1;
    create.required_checkpoint_xids = pins;
    AppleSnapshotCreatePlan planned;
    require_api(PlanAppleSnapshotCreate(held, *canonical, create, planned, error),
        "corrected production create plan");
    AppleSnapshotRetirementProof proof;
    require_api(ProveAppleSnapshotRetirement(held, *canonical, planned.commit.publication,
        101, pins, proof, error), "corrected production before/after retirement proof");

    const std::set<std::uint64_t> volume_blocks{
        4, 5, 6, 7, 8, 9, 180, 181, 182, 183, 184, 185, 186};
    auto all_graph_blocks = volume_blocks;
    all_graph_blocks.insert({2, 3});
    const std::set<std::uint64_t> proven(proof.source_metadata_blocks.begin(),
        proof.source_metadata_blocks.end());
    require(proven == all_graph_blocks && proof.source_metadata_blocks.size() == proven.size() &&
        proof.source_owned_blocks.size() == 2 &&
        proof.source_owned_blocks[0].physical_block == 2 && proof.source_owned_blocks[0].block_count == 8 &&
        proof.source_owned_blocks[1].physical_block == 180 && proof.source_owned_blocks[1].block_count == 7,
        "production proof must identify exactly 13 volume blocks plus container OMAP blocks 2/3");
    const std::set<std::uint64_t> census_blocks(census.begin(), census.end());
    require(payload.empty() && std::includes(census_blocks.begin(), census_blocks.end(),
        proven.begin(), proven.end()), "production recovery census must retain the complete metadata-only graph");
    const auto& canonical_volume = canonical->volumes.at(0);
    const auto& canonical_chunk = canonical->spaceman.chunks.at(0);
    require(canonical_volume.superblock.space.allocated_block_count == volume_blocks.size() &&
        canonical_chunk.free_count == 460 && canonical->spaceman.devices[0].free_count == 460,
        "proved source must have charge 13 and matching chunk/device free count 460");
    require(planned.identity.snapshot_xid == 21 && planned.identity.name_utf8 == create.name_utf8,
        "production create plan must use the next checkpoint identity");
    std::vector<AppleSnapshotRecord> retained;
    AppleSnapshotTreeRecords retained_trees;
    require_api(LoadAppleSnapshotRecords(held, *canonical, 101, retained, error, 10, retained_trees),
        "corrected exact backup retention");
    require(retained.size() == 1 && retained.front().name_utf8 == "backup" &&
        retained.front().volume.superblock.omap_oid == 181 &&
        retained.front().volume.root_tree.physical_block == 183 &&
        retained.front().volume.extentref_tree &&
        retained.front().volume.extentref_tree->physical_block == 184 &&
        retained_trees.filesystem.size() == 1 && retained_trees.extentref.empty() &&
        retained_trees.filesystem.front().key == backup_trees.filesystem.front().key &&
        retained_trees.filesystem.front().value == backup_trees.filesystem.front().value,
        "correction must retain the backup XID-10 file view");
    require(!budget->Failed(), "shared read budget: " + std::string(budget->Failure()));
    fixture.image.swap(completed.image);
}

} // namespace apfsaccess::testfixture
