// Private implementation included by AppleVolumeTransaction.cpp. No caller can
// supply this context or substitute a detached ownership view for the members.
namespace
{
enum class FusionAllocationProfile { Conservative, RetainedOwners };
enum class FusionObjectIdProfile { Original, CanonicalCensus, CompactedExtents };
struct FusionVolumePlanning
{
    const catalog::ApfsFusionStore& store;
    std::vector<std::uint64_t> tier2_blocks;
    std::set<std::uint64_t> retained_metadata;
    FusionAllocationProfile allocation_profile = FusionAllocationProfile::Conservative;
    std::vector<AppleCheckpointGuardBlock> reclamation_guards;
    FusionObjectIdProfile object_id_profile = FusionObjectIdProfile::Original;
};

AppleBtreeKeyOrder FusionFilesystemKeyOrder(const FusionVolumePlanning&, const catalog::ApsbVolume& volume)
{
    return ApfsNamePolicy::FromIncompatibleFeatures(volume.incompatible_features).UsesHashedDirectoryKeys()
        ? AppleBtreeKeyOrder::FileSystemHashedDirectory : AppleBtreeKeyOrder::FileSystemCaseSensitive;
}

bool FusionSharedSpace(const catalog::AppleCheckpointView& cp,
    catalog::ApfsSharedSpaceProjection& out, std::string& error)
{
    out = {};
    const auto& nx = cp.container.superblock;
    const auto total = nx.block_count;
    const auto free = cp.spaceman.devices[0].free_count + cp.spaceman.devices[1].free_count;
    if (!total || free > total || total > UINT64_MAX / nx.block_size ||
        cp.volumes.size() != nx.fs_oids.size()) return Fail(error, "FusionSpaceGeometryInvalid");
    out.total = {total, total * nx.block_size};
    out.free = {free, free * nx.block_size};
    out.used = {total - free, (total - free) * nx.block_size};
    std::uint64_t unmet = 0;
    std::set<std::uint64_t> ids;
    for (std::size_t i = 0; i < cp.volumes.size(); ++i) {
        const auto& v = cp.volumes[i]; const auto& s = v.superblock.space;
        if (v.superblock.object_id != nx.fs_oids[i] || !ids.insert(nx.fs_oids[i]).second ||
            s.allocated_block_count > total - free || s.reserve_block_count > total ||
            (s.quota_block_count && s.reserve_block_count > s.quota_block_count))
            return Fail(error, "FusionSpaceCountersInvalid");
        const auto own = s.reserve_block_count > s.allocated_block_count ?
            s.reserve_block_count - s.allocated_block_count : 0;
        if (own > free - unmet) return Fail(error, "FusionSpaceReservesExceedFree");
        unmet += own;
    }
    for (const auto& v : cp.volumes) {
        const auto& s = v.superblock.space;
        catalog::ApfsVolumeSpaceProjection p; p.object_id = v.superblock.object_id;
        p.allocated = {s.allocated_block_count, s.allocated_block_count * nx.block_size};
        const auto own = s.reserve_block_count > s.allocated_block_count ?
            s.reserve_block_count - s.allocated_block_count : 0;
        p.sibling_reserve_remaining = {unmet - own, (unmet - own) * nx.block_size};
        if (s.reserve_block_count) p.reserve = catalog::ApfsSpaceAmount{s.reserve_block_count, s.reserve_block_count * nx.block_size};
        if (s.quota_block_count) {
            if (s.quota_block_count > UINT64_MAX / nx.block_size) return Fail(error, "FusionSpaceCounterOverflow");
            p.quota = catalog::ApfsSpaceAmount{s.quota_block_count, s.quota_block_count * nx.block_size};
        }
        out.volumes.push_back(p);
    }
    return true;
}

bool LoadFusionPlanningCheckpoint(const catalog::ApfsFusionStore& binding,
    const catalog::RandomAccessSource& source, const catalog::ContainerCheckpointView& container,
    catalog::AppleCheckpointView& out, std::string& error)
{
    out = {};
    auto read = catalog::LoadAppleReadOnlyVolumeView(source, container, error);
    if (!read) return false;
    out.container = std::move(read->container);
    out.container_object_map = std::move(read->container_object_map);
    out.volumes = std::move(read->volumes);
    if (!catalog::LoadFusionPlanningAllocation(binding, source, out.container, out.spaceman, error))
    { out = {}; return false; }
    return true;
}

bool FusionOwnedRange(const catalog::ApfsFusionStore& store,
    const catalog::AppleCheckpointView& cp, std::uint64_t block, std::uint64_t count,
    std::uint64_t visible_xid, std::string& error)
{
    const auto& nx = cp.container.superblock;
    const auto& sm = cp.spaceman;
    catalog::FusionRoute route;
    if (!count || count > UINT64_MAX / nx.block_size ||
        !store.MapPhysical(block, 0, count * nx.block_size, route, error))
        return Fail(error, "FusionVolumeOwnerOutsideMember");
    const auto overlaps = [&](auto b, auto n) { return n && block < b + n && b < block + count; };
    const auto tier = catalog::kFusionTier2ByteAddress / nx.block_size;
    if (overlaps(0ull,1ull) || overlaps(tier,1ull) ||
        overlaps(nx.xp_desc_base_block,nx.xp_desc_block_count) ||
        overlaps(nx.xp_data_base_block,nx.xp_data_block_count) ||
        overlaps(nx.fusion_middle_tree_oid,1ull) ||
        overlaps(nx.fusion_writeback_start,nx.fusion_writeback_blocks) ||
        overlaps(sm.internal_pool.base_block,sm.internal_pool.block_count) ||
        overlaps(sm.internal_pool.bitmap_base_block,sm.internal_pool.bitmap_block_count))
        return Fail(error, "FusionVolumeOwnerReservedCollision");
    for (const auto& q : sm.free_queues) for (const auto& e : q.entries)
        if (e.xid <= visible_xid && overlaps(e.physical_block,e.block_count))
            return Fail(error, "FusionVolumeOwnerQueued");
    const std::size_t device = route.role == catalog::FusionMemberRole::Tier2 ? 1 : 0;
    const auto local = block - (device ? tier : 0);
    if (!sm.blocks_per_chunk || local > UINT64_MAX - count)
        return Fail(error, "FusionVolumeOwnerOutsideMember");
    const auto end = local + count;
    for (auto b = local; b < end;) {
        const auto ordinal = b / sm.blocks_per_chunk;
        const auto base = device ? sm.devices[0].chunk_count : 0;
        if (ordinal > UINT64_MAX - base) return Fail(error, "FusionVolumeChunkMissing");
        const auto index = base + ordinal;
        if (index >= sm.chunks.size()) return Fail(error, "FusionVolumeChunkMissing");
        const auto& chunk = sm.chunks[static_cast<std::size_t>(index)];
        const auto bit = b - chunk.start_block;
        if (chunk.device_index != device || b < chunk.start_block || bit >= chunk.block_count)
            return Fail(error, "FusionVolumeOwnerFree");
        const auto span = (std::min)({end - b, chunk.block_count - bit,
            sm.blocks_per_chunk - b % sm.blocks_per_chunk});
        if (!fusion_bitmap::RangeAllocated(chunk.allocation_bitmap, bit, span, store.ReadBudget(), error)) return false;
        b += span;
    }
    return true;
}

struct FusionLiveGraph
{
    std::set<std::uint64_t> metadata;
    std::vector<ApplePhysicalExtentRecord> payload;
};

bool ReadFusionLiveGraph(const catalog::ApfsFusionStore& store,
    const catalog::RandomAccessSource& source, const catalog::AppleCheckpointView& cp,
    FusionLiveGraph& graph, std::string& error)
{
    graph = {};
    const auto& nx = cp.container.superblock;
    const auto add_meta = [&](std::uint64_t b) {
        return (graph.metadata.insert(b).second || Fail(error,"FusionVolumeMetadataAlias")) &&
            FusionOwnedRange(store,cp,b,1,nx.xid,error);
    };
    const auto tree = [&](const catalog::AppleObjectLocation& location, std::uint64_t omap,
        std::vector<catalog::BtreeRecord>& records) {
        std::vector<std::uint64_t> blocks;
        if (!ReadTreeRecords(source,location,nx.block_size,omap,nx.xid,records,blocks,error)) return false;
        for (auto b : blocks) if (!add_meta(b)) return false;
        return true;
    };
    const auto map = [&](const catalog::AppleOmapView& omap, std::uint32_t flags) {
        std::vector<std::byte> bytes;
        if (!ReadObject(source,omap.object,nx.block_size,bytes) || omap.flags != flags ||
            catalog::ReadU32LE(bytes,0x20) != flags || omap.snapshot_tree_oid ||
            catalog::ReadU32LE(bytes,0x24).value_or(~0u) ||
            catalog::ReadU64LE(bytes,0x40).value_or(~0ull) ||
            catalog::ReadU64LE(bytes,0x48).value_or(~0ull) ||
            catalog::ReadU64LE(bytes,0x50).value_or(~0ull))
            return Fail(error,"FusionVolumeOmapProfileUnsupported");
        if (!add_meta(omap.object.physical_block)) return false;
        std::vector<catalog::BtreeRecord> records;
        return tree(omap.tree,0,records);
    };
    if (!map(cp.container_object_map,1)) return false;
    for (const auto& volume : cp.volumes) {
        const auto metadata_begin = graph.metadata.size();
        std::vector<std::byte> bytes;
        if (!CheckAppleVolumeWriteFeatures(nx,volume.superblock,error,true) ||
            !volume.root_tree.object_id || !volume.extentref_tree ||
            volume.snapshot_metadata_tree || volume.file_extent_tree ||
            !ReadObject(source,volume.superblock_object,nx.block_size,bytes) ||
            catalog::ReadU64LE(bytes,0xD8).value_or(~0ull) ||
            catalog::ReadU64LE(bytes,0xA0).value_or(~0ull) ||
            catalog::ReadU64LE(bytes,0xA8).value_or(~0ull) ||
            catalog::ReadU64LE(bytes,0x3E8).value_or(~0ull))
            return Fail(error,"FusionVolumeStateUnsupported");
        if (!add_meta(volume.superblock_object.physical_block) || !map(volume.object_map,0)) return false;
        std::vector<catalog::BtreeRecord> fs, refs;
        if (!tree(volume.root_tree,volume.superblock.omap_oid,fs) || !tree(*volume.extentref_tree,0,refs)) return false;
        if (!ApfsFusionReadSession::ValidatePlanningRecords(store,nx,volume.superblock,fs,error)) return false;
        std::vector<FileExtentUse> uses, removed;
        std::vector<PhysicalExtentState> physical;
        if (!CollectFileExtentChanges(fs,fs,nx.block_size,uses,removed,error) ||
            !DecodePhysicalExtentTree(refs,nx.block_count,physical,error,&store) ||
            !ValidatePhysicalExtentCoverage(uses,physical,nx.block_count,error,&store)) return false;
        std::uint64_t owned = graph.metadata.size() - metadata_begin;
        for (const auto& p : physical) {
            if (!FusionOwnedRange(store,cp,p.extent.physical_block,p.extent.block_count,nx.xid,error)) return false;
            if (p.extent.block_count > UINT64_MAX - owned) return Fail(error,"FusionVolumeOwnerCountOverflow");
            owned += p.extent.block_count;
            graph.payload.push_back(p.extent);
        }
        if (owned > volume.superblock.space.allocated_block_count)
            return Fail(error,"FusionVolumeAllocatedCounterBelowOwners");
    }
    std::sort(graph.payload.begin(),graph.payload.end(),[](const auto& a,const auto& b){return a.physical_block < b.physical_block;});
    std::uint64_t end = 0;
    for (const auto& p : graph.payload) {
        const auto meta = graph.metadata.lower_bound(p.physical_block);
        if (p.physical_block < end || (meta != graph.metadata.end() && *meta < p.physical_block + p.block_count))
            return Fail(error,"FusionVolumePayloadOwnerCollision");
        end = p.physical_block + p.block_count;
    }
    return true;
}

bool ComposeFusionVolume(FusionVolumePlanning& context, const catalog::RandomAccessSource& source,
    const catalog::AppleCheckpointView& cp, const AppleTransactionCommitRequest& request,
    AppleTransactionCommitPlan& out, std::string& error)
{
    out = {};
    const auto& nx = cp.container.superblock;
    const auto& allocation = request.allocation_plan;
    AppleCheckpointPublicationRequest publication;
    publication.expected_checkpoint_xid = nx.xid;
    publication.transaction_xid = nx.next_xid;
    publication.next_object_id = request.next_object_id;
    publication.container_object_map_oid = request.container_object_map_oid;
    publication.required_checkpoint_xids = request.required_checkpoint_xids;
    std::set<std::uint64_t> expected(allocation.allocated_main_blocks.begin(),allocation.allocated_main_blocks.end());
    expected.insert(context.tier2_blocks.begin(),context.tier2_blocks.end());
    if (expected.size() != allocation.allocated_main_blocks.size() + context.tier2_blocks.size())
        return Fail(error,"FusionVolumeAllocationDuplicate");
    std::vector<AppleCheckpointPlannedWrite> tier_writes;
    for (const auto& w : request.allocated_main_writes) {
        catalog::FusionRoute route;
        if (w.bytes.size() != nx.block_size || !expected.erase(w.physical_block) ||
            !context.store.MapPhysical(w.physical_block,0,w.bytes.size(),route,error))
            return Fail(error,"FusionVolumeWriteCoverageInvalid");
        if (route.role == catalog::FusionMemberRole::Main) publication.allocator_owned_writes.push_back(w);
        else tier_writes.push_back({AppleCheckpointWriteKind::AllocatorOwned,w.physical_block,0,w.bytes});
    }
    if (!expected.empty()) return Fail(error,"FusionVolumeWriteCoverageIncomplete");
    std::map<std::uint64_t,AppleCheckpointEphemeralObject> objects;
    auto sm = allocation.updated_spaceman.object; sm.physical_block = 0;
    objects.emplace(sm.object_id,AppleCheckpointEphemeralObject{0,sm,allocation.updated_spaceman.bytes});
    for (const auto& w : allocation.writes) {
        if (w.kind == AppleSpacemanWriteKind::FreeQueueTree) {
            if (!w.object_location || !objects.emplace(w.object_location->object_id,
                    AppleCheckpointEphemeralObject{0,*w.object_location,w.bytes}).second)
                return Fail(error,"FusionVolumeEphemeralCollision");
        } else publication.allocator_owned_writes.push_back({w.physical_block,w.bytes});
    }
    std::set<std::uint64_t> retired;
    for (const auto& q : cp.spaceman.free_queues) if (objects.contains(q.tree_oid))
        for (auto b : q.tree_blocks) {
            auto m = std::find_if(cp.container.mappings.begin(),cp.container.mappings.end(),
                [b](const auto& m){return m.physical_block == b;});
            if (m == cp.container.mappings.end()) return Fail(error,"FusionVolumeQueueMappingMissing");
            if (!objects.contains(m->object_id)) retired.insert(m->object_id);
        }
    for (const auto& m : cp.container.mappings) {
        if (objects.contains(m.object_id) || retired.contains(m.object_id)) continue;
        AppleCheckpointEphemeralObject object;
        object.file_system_oid = m.file_system_oid;
        object.object = {m.object_id,nx.next_xid,0,m.type,m.subtype,m.size_bytes};
        if (!m.size_bytes || m.size_bytes % nx.block_size) return Fail(error,"FusionVolumeEphemeralSizeInvalid");
        for (std::uint32_t i = 0; i < m.size_bytes / nx.block_size; ++i) {
            std::vector<std::byte> bytes;
            const auto b = nx.xp_data_base_block + (m.physical_block - nx.xp_data_base_block + i) % nx.xp_data_block_count;
            if (!ReadBlock(source,b,nx.block_size,bytes)) return Fail(error,"FusionVolumeEphemeralUnreadable");
            object.bytes.insert(object.bytes.end(),bytes.begin(),bytes.end());
        }
        for (unsigned i = 0; i < 8; ++i) object.bytes[16+i] = std::byte(nx.next_xid >> (i*8));
        if (!FinalizeAppleObjectChecksum(object.bytes,error)) return false;
        objects.emplace(m.object_id,std::move(object));
    }
    publication.retired_ephemeral_object_ids.assign(retired.begin(),retired.end());
    for (auto& [id,object] : objects) {
        if (id >= publication.next_object_id) {
            if (id == UINT64_MAX) return Fail(error,"FusionVolumeOidOverflow");
            publication.next_object_id = id + 1;
        }
        publication.ephemeral_objects.push_back(std::move(object));
    }
    if (!PlanAppleCheckpointPublication(source,cp.container,publication,out.publication,error)) return false;
    out.publication.before_superblock_writes.insert(out.publication.before_superblock_writes.end(),tier_writes.begin(),tier_writes.end());
    if (!FinalizeFusionCheckpointPublication(context.store,out.publication,error)) return false;

    SnapshotPublicationSource staged(source,out.publication);
    catalog::AppleCheckpointView after;
    if (!LoadFusionPlanningCheckpoint(context.store,staged,out.publication.published_checkpoint,after,error)) return false;
    FusionLiveGraph before_graph, after_graph;
    if (!ReadFusionLiveGraph(context.store,source,cp,before_graph,error) ||
        !ReadFusionLiveGraph(context.store,staged,after,after_graph,error)) return false;
    // Reparse the complete old graph through the same staged overlay, including
    // its old bitmap rotation, so a COW collision cannot hide behind counters.
    catalog::AppleCheckpointView retained;
    FusionLiveGraph retained_graph;
    if (!LoadFusionPlanningCheckpoint(context.store,staged,cp.container,retained,error) ||
        !ReadFusionLiveGraph(context.store,staged,retained,retained_graph,error))
    {
        error = "FusionVolumeOldCheckpointChanged:" + error;
        return false;
    }
    if (retained_graph.metadata != before_graph.metadata)
        return Fail(error,"FusionVolumeOldCheckpointChanged:MetadataIdentity");
    // Earlier live roots and payload remain allocated through their checkpoint.
    for (auto b : before_graph.metadata)
        if (!FusionOwnedRange(context.store,after,b,1,nx.xid,error) ||
            !AddGuard(source,b,nx.block_size,out.publication.guard_blocks)) return false;
    for (auto b : context.retained_metadata)
        if (!AddGuard(source,b,nx.block_size,out.publication.guard_blocks))
            return Fail(error,"FusionVolumeRetainedGuardUnreadable");
    for (const auto& p : before_graph.payload)
        if (!FusionOwnedRange(context.store,after,p.physical_block,p.block_count,nx.xid,error)) return false;
    std::set<std::uint64_t> allocator_guards;
    for (const auto& d : cp.spaceman.devices) {
        for (const auto& c : d.cibs) allocator_guards.insert(c.object.physical_block);
        for (const auto& c : d.cabs) allocator_guards.insert(c.object.physical_block);
    }
    for (const auto& c : cp.spaceman.chunks) if (c.bitmap_block) allocator_guards.insert(c.bitmap_block);
    for (const auto& b : cp.spaceman.internal_pool.active_bitmaps) allocator_guards.insert(b.physical_block);
    allocator_guards.insert(nx.fusion_middle_tree_oid);
    for (auto b : allocator_guards)
        if (!AddGuard(source,b,nx.block_size,out.publication.guard_blocks))
            return Fail(error,"FusionVolumeAllocatorGuardUnreadable");
    for (const auto& guard : context.reclamation_guards) {
        const auto existing = std::find_if(out.publication.guard_blocks.begin(),out.publication.guard_blocks.end(),
            [&](const auto& old) { return old.physical_block == guard.physical_block; });
        if (existing == out.publication.guard_blocks.end()) out.publication.guard_blocks.push_back(guard);
        else if (existing->bytes != guard.bytes) return Fail(error,"FusionVolumeReclamationObservationChanged");
    }
    return context.store.CheckAvailable(error);
}
}
