bool CaptureEmptyPlainGeneration(const std::shared_ptr<TrackedSource>& source,
    const ContainerCheckpointView& old, const AppleOmapView& object_map, const AppleCheckpointView& current,
    SoftwareVolumeRetainedGeneration& output, std::string& error)
{
    const auto fail = [&](const char* reason) { error = reason; return false; };
    if (!old.superblock.fs_oids.empty() || !old.superblock.xid ||
        old.superblock.xid >= current.container.superblock.xid || old.superblock.uuid_hex != current.container.superblock.uuid_hex ||
        old.superblock.block_size != block_size || old.superblock.block_count != current.container.superblock.block_count ||
        ReadU64LE(old.superblock_bytes, 0x510) != 0 || ReadU64LE(old.superblock_bytes, 0x518) != 0 ||
        ReadU64LE(old.superblock_bytes, 0x4F0) != 0 || object_map.snapshot_tree_oid)
        return fail("SoftwareTransitionEmptyHistoryCanonicalAbsenceRequired");
    Rows records; std::set<std::uint64_t> metadata{object_map.object.physical_block};
    if (!Tree(*source, object_map.tree, old.superblock.xid, records, &metadata, error) ||
        !records.values.empty()) return fail("SoftwareTransitionEmptyHistoryObjectMapNotEmpty");
    output.checkpoint = old;
    for (const auto block : metadata) {
        if (!Allocated(current.spaceman, block) || InReservedArea(current, block))
            return fail("SoftwareTransitionEmptyHistoryCurrentOwnerUnproved");
        BytesOwner raw;
        if (!Block(*source, block, raw.bytes)) return fail("SoftwareTransitionEmptyHistoryRawOwnerUnreadable");
        output.graph_guards.push_back({block, std::move(raw.bytes)});
        AddRange(output, block, SoftwareVolumeOwnerKind::Metadata);
    }
    std::set<std::uint64_t> checkpoint_blocks{old.superblock_physical_block};
    checkpoint_blocks.insert(old.checkpoint_map_blocks.begin(), old.checkpoint_map_blocks.end());
    for (const auto& mapping : old.mappings) {
        if (mapping.size_bytes != block_size) return fail("SoftwareTransitionEmptyHistoryEphemeralSize");
        checkpoint_blocks.insert(mapping.physical_block);
    }
    for (const auto block : checkpoint_blocks) {
        BytesOwner raw;
        if (!Block(*source, block, raw.bytes)) return fail("SoftwareTransitionEmptyHistoryCheckpointUnreadable");
        output.checkpoint_guards.push_back({block, std::move(raw.bytes)});
    }
    return !output.ranges.empty() && !output.checkpoint_guards.empty();
}
