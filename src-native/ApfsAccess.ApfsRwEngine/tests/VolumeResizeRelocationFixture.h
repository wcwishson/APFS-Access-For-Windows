#pragma once
// Test fixture authoring before keeper preparation, using canonical records.
inline void MoveFixturePayloadToTail(Target& target)
{
    const auto cp = mc::Load(target); const auto& volume = cp.volumes.front(); const auto& sm = cp.spaceman;
    const auto tail = sm.chunks.back().start_block + 500; std::string error;
    std::map<std::uint64_t, std::uint64_t> moved; std::vector<apfsaccess::catalog::BtreeRecord> records;
    Check(ReadAppleVolumeFileSystemRecords(target, cp.container, volume, records, error), error);
    for (auto& record : records) if ((ReadU64LE(record.key, 0).value_or(0) >> 60) == 8) {
        AppleFileExtentRecord extent; Check(DecodeAppleFileExtentRecord(record, 4096, extent, error), error);
        Check(extent.object_id == 1030 && extent.physical_block && extent.length_bytes % 4096 == 0,
            "fixture has only the complete known stream");
        const auto destination = tail + moved.size();
        for (std::uint64_t i = 0; i < extent.length_bytes / 4096; ++i)
            Check(moved.emplace(extent.physical_block + i, destination + i).second, "fixture payload is not aliased");
        extent.physical_block = destination; Check(EncodeAppleFileExtentRecord(extent, record, error), error);
    }
    Check(moved.size() == 2 && sm.chunks.back().bitmap_block, "two actual payload blocks and existing tail bitmap");
    const auto serialize = [&](std::vector<apfsaccess::catalog::BtreeRecord> input, const AppleObjectLocation& location,
        AppleBtreeKeyOrder order) {
        Check(SortAppleBtreeRecords(input, order, error), error);
        AppleBtreeOptions options; options.block_size = 4096; options.root_object_id = location.object_id;
        options.root_physical_block = location.physical_block; options.xid = location.xid; options.subtype = location.subtype;
        options.storage_type = location.type & kObjectStorageTypeMask; options.key_order = order; options.max_nodes = 1;
        options.tree_flags = options.storage_type == kObjectPhysical ? kAppleBtreePhysical : 0;
        AppleSerializedBtree tree; Check(SerializeAppleBtree(input, options, tree, error) && tree.objects.size() == 1, error);
        Check(target.WriteBlock(location.physical_block, tree.objects.front().bytes), "fixture canonical leaf write");
    };
    serialize(std::move(records), volume.root_tree, volume.superblock.incompatible_features & kIncompatCaseInsensitive ?
        AppleBtreeKeyOrder::FileSystemHashedDirectory : AppleBtreeKeyOrder::FileSystemCaseSensitive);
    Check(volume.extentref_tree.has_value(), "fixture extent reference root"); records.clear();
    Check(ReadBtreeLeafRecords(target, 4096, volume.extentref_tree->physical_block, true, 0,
        volume.superblock.xid, records, error), error);
    for (auto& record : records) {
        ApplePhysicalExtentRecord extent; Check(DecodeApplePhysicalExtentRecord(record, extent, error), error);
        Check(moved.contains(extent.physical_block), "fixture extent belongs to the actual payload");
        const auto destination = moved.at(extent.physical_block);
        for (std::uint64_t i = 0; i < extent.block_count; ++i)
            Check(moved.at(extent.physical_block + i) == destination + i, "fixture physical extent remains contiguous");
        extent.physical_block = destination; Check(EncodeApplePhysicalExtentRecord(extent, record, error), error);
    }
    serialize(std::move(records), *volume.extentref_tree, AppleBtreeKeyOrder::PhysicalExtent);
    std::map<std::size_t, Bytes> bitmaps, cibs;
    for (const auto& [old, destination] : moved) {
        Bytes bytes; Check(target.Read(old * 4096, 4096, bytes) && target.WriteBlock(destination, bytes), "fixture payload copy");
        for (const auto& [block, set] : {std::pair{old, false}, std::pair{destination, true}}) {
            const auto i = static_cast<std::size_t>(block / sm.blocks_per_chunk); const auto& chunk = sm.chunks.at(i);
            auto [at, inserted] = bitmaps.try_emplace(i, chunk.allocation_bitmap); (void)inserted;
            Check(chunk.bitmap_block && vi::Bit(at->second, block - chunk.start_block) != set, "fixture changes exact owned/free bits");
            vi::SetBit(at->second, block - chunk.start_block, set);
        }
    }
    for (const auto& [i, bitmap] : bitmaps) {
        const auto& chunk = sm.chunks.at(i); std::uint64_t free = 0;
        for (std::uint64_t b = 0; b < chunk.block_count; ++b) if (!vi::Bit(bitmap, b)) ++free;
        auto [cib, inserted] = cibs.try_emplace(chunk.cib_index, sm.devices[0].cibs.at(chunk.cib_index).bytes); (void)inserted;
        vi::Put(cib->second, 0x28 + chunk.index_in_cib * 0x20 + 0x14, free, 4);
        Check(target.WriteBlock(chunk.bitmap_block, bitmap), "fixture exact bitmap write");
    }
    for (auto& [i, bytes] : cibs) { vi::Checksum(bytes); Check(target.WriteBlock(sm.devices[0].cibs.at(i).object.physical_block, bytes), "fixture CIB counters"); }
    Check(target.Flush(), "fixture durable before keeper preparation"); mc::Verify(target, mc::Load(target));
}
inline AppleObjectLocation AddFixtureHistoricalRoot(Target& target)
{
    const auto cp = mc::Load(target); const auto& volume = cp.volumes.front(); const auto& chunk = cp.spaceman.chunks.back();
    const auto destination = chunk.start_block + 600; std::string error; Bytes old;
    Check(chunk.bitmap_block && !vi::Bit(chunk.allocation_bitmap, destination - chunk.start_block) && volume.root_tree.xid > 1,
        "historical fixture has a genuine free tail block and older generation");
    Check(target.Read(volume.root_tree.physical_block * 4096, 4096, old), "historical root preimage");
    auto location = volume.root_tree; location.physical_block = destination; --location.xid;
    vi::Put(old, 16, location.xid); vi::Checksum(old);
    std::vector<apfsaccess::catalog::BtreeRecord> records;
    Check(ReadBtreeLeafRecords(target, 4096, volume.object_map.tree.physical_block, true, 0, cp.container.superblock.xid, records, error), error);
    apfsaccess::catalog::BtreeRecord mapping;
    Check(EncodeAppleOmapRecord({location.object_id, location.xid, 0, 4096, destination}, mapping, error), error);
    Check(std::none_of(records.begin(), records.end(), [&](const auto& r) { return r.key == mapping.key; }), "distinct historical root key");
    records.push_back(std::move(mapping)); Check(SortAppleBtreeRecords(records, AppleBtreeKeyOrder::ObjectMap, error), error);
    AppleBtreeOptions options; options.block_size = 4096; options.root_object_id = volume.object_map.tree.object_id;
    options.root_physical_block = volume.object_map.tree.physical_block; options.xid = volume.object_map.tree.xid;
    options.storage_type = kObjectPhysical; options.subtype = kObjectTypeOmap; options.tree_flags = kAppleBtreePhysical;
    options.key_order = AppleBtreeKeyOrder::ObjectMap; options.fixed_key_size = options.fixed_value_size = 16; options.max_nodes = 1;
    AppleSerializedBtree tree; Check(SerializeAppleBtree(records, options, tree, error) && tree.objects.size() == 1, error);
    Check(target.WriteBlock(destination, old) && target.WriteBlock(volume.object_map.tree.physical_block, tree.objects.front().bytes),
        "fixture historical root and canonical OMAP mapping");
    auto bitmap = chunk.allocation_bitmap; vi::SetBit(bitmap, destination - chunk.start_block, true);
    Check(target.WriteBlock(chunk.bitmap_block, bitmap), "historical root allocation bit");
    const auto& original_cib = cp.spaceman.devices[0].cibs.at(chunk.cib_index); auto cib = original_cib.bytes;
    vi::Put(cib, 0x28 + chunk.index_in_cib * 0x20 + 0x14, chunk.free_count - 1, 4); vi::Checksum(cib);
    auto spaceman = cp.spaceman.bytes; vi::Put(spaceman, 0x48, cp.spaceman.devices[0].free_count - 1); vi::Checksum(spaceman);
    Bytes apsb; Check(target.Read(volume.superblock_object.physical_block * 4096, 4096, apsb), "historical owner accounting preimage");
    vi::Put(apsb, 0x58, ReadU64LE(apsb, 0x58).value() + 1); vi::Put(apsb, 0xe0, ReadU64LE(apsb, 0xe0).value() + 1); vi::Checksum(apsb);
    Check(target.WriteBlock(original_cib.object.physical_block, cib) && target.WriteBlock(cp.spaceman.object.physical_block, spaceman) &&
        target.WriteBlock(volume.superblock_object.physical_block, apsb) && target.Flush(), "fixture exact owner counters and durability");
    mc::Verify(target, mc::Load(target)); std::vector<std::uint64_t> metadata; std::vector<ApplePhysicalExtentRecord> payload;
    Check(LoadAppleSnapshotCheckpointOwners(target, mc::Load(target), metadata, payload, error) &&
        std::find(metadata.begin(), metadata.end(), destination) != metadata.end(), "canonical full graph owns the authored historical root: " + error);
    return location;
}
