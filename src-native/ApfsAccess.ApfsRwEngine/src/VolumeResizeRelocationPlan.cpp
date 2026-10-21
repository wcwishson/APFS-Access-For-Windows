#include "VolumeResizeRelocation.h"
#include "ApfsSharedSpace.h"
#include "ApfsNameCodec.h"
#include <algorithm>
#include <map>
#include <optional>
#include <set>

namespace apfsaccess::rw::volume_image
{
namespace
{
using namespace catalog;
using format_evidence::Number;
using Record = catalog::BtreeRecord;
constexpr std::size_t RelocationWriteLimit = 4096;
class RelocationProofSource final : public RandomAccessSource
{
public:
    RelocationProofSource(const RandomAccessSource& source, const Plan& plan, std::uint64_t size) : source_(source), size_(size)
    {
        for (const auto& w : plan.publication.before_superblock_writes) writes_.emplace(w.physical_block, &w.bytes);
        writes_.emplace(plan.publication.superblock_write.physical_block, &plan.publication.superblock_write.bytes);
        writes_.emplace(0, &plan.anchor);
    }
    std::uint64_t SizeBytes() const override { return size_; }
    bool Read(std::uint64_t offset, std::size_t size, Bytes& out) const override
    {
        out.clear(); if (offset > size_ || size > size_ - offset || !source_.Read(offset, size, out) || out.size() != size) return false;
        if (!size) return true;
        for (auto i = writes_.lower_bound(offset / Block); i != writes_.end() && i->first * Block < offset + size; ++i) {
            const auto begin = (std::max)(offset, i->first * Block), end = (std::min<std::uint64_t>)(offset + size, (i->first + 1) * Block);
            std::copy(i->second->begin() + begin - i->first * Block, i->second->begin() + end - i->first * Block, out.begin() + begin - offset);
        }
        return true;
    }
private:
    const RandomAccessSource& source_; std::uint64_t size_; std::map<std::uint64_t, const Bytes*> writes_;
};
class Relocator
{
public:
    Relocator(const RandomAccessSource& s, const AppleCheckpointView& c, std::uint64_t target)
        : source(s), cp(c), count(target / Block), next_oid(c.container.superblock.next_oid) {}
    Bytes Read(std::uint64_t block) const
    {
        Bytes bytes; Require(source.Read(block * Block, Block, bytes) && bytes.size() == Block,
            "VolumeResizeRelocationReadFailed"); return bytes;
    }
    bool Free(std::uint64_t block) const
    {
        if (!block || block >= count || reserved.contains(block)) return false;
        const auto& chunks = cp.spaceman.chunks;
        const auto i = static_cast<std::size_t>(block / cp.spaceman.blocks_per_chunk);
        Require(i < chunks.size() && block >= chunks[i].start_block && block - chunks[i].start_block < chunks[i].block_count,
            "VolumeResizeRelocationChunkGap");
        return !chunks[i].bitmap_block || !Bit(chunks[i].allocation_bitmap, block - chunks[i].start_block);
    }
    std::uint64_t Allocate()
    {
        while (cursor < count && !Free(cursor)) ++cursor;
        Require(cursor < count && reserved.size() < RelocationWriteLimit, "VolumeResizeRelocationStagingExhausted");
        reserved.insert(cursor); return cursor++;
    }
    std::optional<std::uint64_t> TryContiguous(std::uint64_t length)
    {
        std::uint64_t run = 0;
        for (std::uint64_t b = 1; b < count; ++b) {
            run = Free(b) ? run + 1 : 0;
            if (run != length) continue;
            const auto first = b + 1 - length;
            Require(length <= RelocationWriteLimit - reserved.size(), "VolumeResizeRelocationStagingExhausted");
            for (auto n = first; n <= b; ++n) reserved.insert(n);
            return first;
        }
        return {};
    }
    std::uint64_t Contiguous(std::uint64_t length)
    {
        const auto first=TryContiguous(length);
        Require(first.has_value(),"VolumeResizeRelocationContiguousBootstrapRequired");return *first;
    }
    std::uint64_t Oid()
    {
        Require(next_oid < UINT64_MAX - 1, "VolumeResizeRelocationOidOverflow"); return next_oid++;
    }
    void Write(std::uint64_t block, Bytes bytes)
    {
        Require(reserved.contains(block) && bytes.size() == Block && writes.size() < RelocationWriteLimit &&
            writes.emplace(block, std::move(bytes)).second, "VolumeResizeRelocationWriteOverlap");
    }
    std::vector<Record> Records(const AppleObjectLocation& root, std::uint64_t map, std::uint64_t xid)
    {
        BtreeReadPolicy policy; policy.enforce_object_identity = policy.require_complete_traversal = policy.reject_unsupported_flags = true;
        policy.root_object_id = root.object_id; policy.storage_type = root.type & kObjectStorageTypeMask; policy.subtype = root.subtype;
        std::vector<std::uint64_t> visited; policy.visited_physical_blocks = &visited;
        std::vector<Record> records; std::string error;
        const auto ok = ReadBtreeLeafRecords(source, Block, root.physical_block,
            (root.type & kObjectStorageTypeMask) == kObjectPhysical, map, xid, policy, records, error);
        Require(ok, "VolumeResizeRelocationTreeUnreadable:" + error);
        Require(visited.size() <= RelocationWriteLimit, "VolumeResizeRelocationTreeQuota");
        covered.insert(visited.begin(), visited.end()); return records;
    }
    AppleSerializedBtree Tree(const std::vector<Record>& records, AppleBtreeOptions options,
        std::vector<Record>* child_mappings = nullptr, std::uint64_t mapping_xid = 0, bool ephemeral = false)
    {
        options.block_size = Block; options.max_nodes = RelocationWriteLimit;
        options.root_physical_block = 1; if (options.storage_type == kObjectPhysical) options.root_object_id = 1;
        options.first_child_physical_block = 2; options.first_child_object_id = next_oid;
        AppleSerializedBtree sizing; std::string error;
        auto ok = SerializeAppleBtree(records, options, sizing, error);
        Require(ok && !sizing.objects.empty(), "VolumeResizeRelocationTreeSizing:" + error);
        options.root_physical_block = ephemeral ? DataBlock() : Allocate();
        if (options.storage_type == kObjectPhysical) options.root_object_id = options.root_physical_block;
        for (std::size_t i = 1; i < sizing.objects.size(); ++i) {
            const auto block = ephemeral ? DataBlock() : Allocate();
            options.child_physical_blocks.push_back(block);
            options.child_object_ids.push_back(options.storage_type == kObjectPhysical ? block : Oid());
        }
        AppleSerializedBtree result; ok = SerializeAppleBtree(records, options, result, error);
        Require(ok && result.objects.size() == sizing.objects.size(), "VolumeResizeRelocationTreeSerialization:" + error);
        for (const auto& object : result.objects) {
            Write(object.location.physical_block, object.bytes);
            if (ephemeral) mappings.push_back({object.location.type, object.location.subtype, Block, 0,
                object.location.object_id, object.location.physical_block});
            if (child_mappings && object.location.object_id != result.root_object_id)
                child_mappings->push_back(Mapping(object.location.object_id, mapping_xid, object.location.physical_block));
        }
        return result;
    }
    Record Mapping(std::uint64_t oid, std::uint64_t xid, std::uint64_t block) const
    {
        Record record; std::string error; Require(EncodeAppleOmapRecord({oid, xid, 0, Block, block}, record, error), error); return record;
    }
    std::uint64_t DataBlock()
    {
        Require(data_next < data + 256, "VolumeResizeRelocationEphemeralQuota"); return data_next++;
    }
    static AppleBtreeOptions Options(std::uint64_t xid, std::uint32_t storage, std::uint32_t subtype, AppleBtreeKeyOrder order)
    {
        AppleBtreeOptions o; o.xid = xid; o.storage_type = storage; o.subtype = subtype; o.key_order = order;
        o.tree_flags = storage == kObjectPhysical ? kAppleBtreePhysical : storage == kObjectEphemeral ? kAppleBtreeEphemeral : 0;
        if (order == AppleBtreeKeyOrder::ObjectMap) o.fixed_key_size = o.fixed_value_size = 16;
        return o;
    }
    std::uint64_t Payload(std::uint64_t block) const
    { const auto p = payload.find(block); return p == payload.end() ? block : p->second; }
    std::vector<Record> FileRecords(const std::vector<Record>& records) const
    {
        std::vector<Record> result;
        for (const auto& record : records) {
            if ((ReadU64LE(record.key, 0).value_or(0) >> 60) != 8) { result.push_back(record); continue; }
            AppleFileExtentRecord extent; std::string error;
            Require(DecodeAppleFileExtentRecord(record, Block, extent, error), error);
            if (!extent.physical_block) { result.push_back(record); continue; }
            auto bytes = extent.length_bytes;
            while (bytes) {
                const auto physical = Payload(extent.physical_block); std::uint64_t blocks = 1;
                while (blocks * Block < bytes && Payload(extent.physical_block + blocks) == physical + blocks) ++blocks;
                auto part = extent; part.physical_block = physical; part.length_bytes = (std::min)(bytes, blocks * Block);
                Record encoded; Require(EncodeAppleFileExtentRecord(part, encoded, error), error); result.push_back(std::move(encoded));
                bytes -= part.length_bytes; extent.logical_address += part.length_bytes; extent.physical_block += blocks;
            }
        }
        return result;
    }
    std::vector<Record> ExtentRecords(const std::vector<Record>& records) const
    {
        std::vector<Record> result;
        for (const auto& record : records) {
            ApplePhysicalExtentRecord extent; std::string error; Require(DecodeApplePhysicalExtentRecord(record, extent, error), error);
            while (extent.block_count) {
                const auto physical = Payload(extent.physical_block); std::uint64_t blocks = 1;
                while (blocks < extent.block_count && Payload(extent.physical_block + blocks) == physical + blocks) ++blocks;
                auto part = extent; part.physical_block = physical; part.block_count = blocks;
                Record encoded; Require(EncodeApplePhysicalExtentRecord(part, encoded, error), error); result.push_back(std::move(encoded));
                extent.physical_block += blocks; extent.block_count -= blocks;
            }
        }
        std::string error; Require(SortAppleBtreeRecords(result, AppleBtreeKeyOrder::PhysicalExtent, error), error); return result;
    }
    const RandomAccessSource& source; const AppleCheckpointView& cp;
    std::uint64_t count, next_oid, cursor = 1, base = 0, data = 0, data_next = 0;
    std::set<std::uint64_t> reserved, covered, retired_main;
    std::map<std::uint64_t, Bytes> writes;
    std::map<std::uint64_t, std::uint64_t> payload;
    std::vector<CheckpointMapping> mappings;
};
}
static Plan BuildResizeRelocationPublicationImpl(const catalog::RandomAccessSource& source,
    const VolumeImageRequest& request, bool physical_snapshots)
{
    const auto inventory = InspectResizeRelocationSource(source, request);
    Require(!physical_snapshots || inventory.physical_snapshot_root_in_tail,
        "VolumeResizePhysicalSnapshotProfileMismatch");
    Require(!inventory.unknown_blocks, "VolumeResizeRelocationUnknownTailOwner");
    Plan plan; plan.before = AdmitSource(source, request, ImageAdmission::StreamedResize);
    const auto& cp = plan.before; const auto& nx = cp.container.superblock; const auto& old_sm = cp.spaceman;
    Require(old_sm.flags == 1 && old_sm.version == 1 && old_sm.devices[0].cabs.empty() &&
        old_sm.blocks_per_chunk == Block * 8 && old_sm.chunks_per_cib == (Block - 40) / 32 &&
        old_sm.internal_pool.bitmap_size_blocks == 1 && old_sm.internal_pool.bitmap_block_count == 16,
        "VolumeResizeRelocationSpacemanProfile");
    ValidateResizeAllocationZones(old_sm, request.target_bytes / Block);
    Relocator build(source, cp, request.target_bytes);
    const auto chunks = (build.count + old_sm.blocks_per_chunk - 1) / old_sm.blocks_per_chunk;
    const auto cibs = (chunks + old_sm.chunks_per_cib - 1) / old_sm.chunks_per_cib;
    const auto xid_offset = 0xa00 + cibs * 8, head_offset = xid_offset + 8, link_offset = head_offset + 16;
    Require(link_offset + 32 <= Block, "VolumeResizeRelocationCibQuota");
    std::uint64_t ip_queued = 0;
    for (const auto& entry : old_sm.free_queues[0].entries) {
        Require(entry.block_count <= RelocationWriteLimit - ip_queued, "VolumeResizeRelocationQueueQuota"); ip_queued += entry.block_count;
    }
    std::uint64_t pool = 32; while (pool < cibs + chunks + ip_queued + 24) pool *= 2;
    Require(pool <= Block * 8 && pool + 304 <= RelocationWriteLimit, "VolumeResizeRelocationPoolQuota");
    std::uint64_t ip_bitmap=0,ip=0;
    if(const auto bundled=build.TryContiguous(pool+304)){
        // Preserve the exact original placement whenever the old profile fits.
        build.base=*bundled;build.data=build.base+32;ip_bitmap=build.base+288;ip=build.base+304;
    }else{
        // Each on-disk region remains contiguous; their recorded bases need not
        // be adjacent. Reserve the two largest regions before the small rings.
        if(pool>=256){ip=build.Contiguous(pool);build.data=build.Contiguous(256);}
        else{build.data=build.Contiguous(256);ip=build.Contiguous(pool);}
        build.base=build.Contiguous(32);ip_bitmap=build.Contiguous(16);
    }
    build.data_next=build.data;
    for (const auto& volume : cp.volumes) build.next_oid = (std::max)(build.next_oid, ReadU64LE(build.Read(volume.superblock_object.physical_block), 0xb0).value());
    for (const auto& item : inventory.blocks) if (item.Has(ResizeTailRole::Payload)) {
        const auto destination = build.Allocate(); build.payload.emplace(item.physical_block, destination);
        build.Write(destination, build.Read(item.physical_block));
    }
    std::vector<Record> container_mappings;
    for (const auto& volume : cp.volumes) {
        const auto writes_before = build.writes.size(); const auto covered_before = build.covered;
        auto snapshot_oid = volume.superblock.snap_meta_tree_oid;
        const bool move_physical_snapshot = physical_snapshots && volume.snapshot_metadata_tree &&
            volume.snapshot_metadata_tree->type == (kObjectPhysical | kObjectTypeBtree) &&
            volume.snapshot_metadata_tree->physical_block >= build.count;
        if (move_physical_snapshot) {
            const auto& root = *volume.snapshot_metadata_tree;
            Require(root.object_id == root.physical_block && root.subtype == kObjectTypeSnapMetaTree &&
                root.object_id == snapshot_oid && volume.superblock.snap_meta_tree_type == root.type,
                "VolumeResizePhysicalSnapshotIdentityInvalid");
            const auto snapshots = build.Records(root, 0, nx.xid);
            Require(snapshots.empty(), "VolumeResizeRelocationSnapshotHistoryPresent");
            const auto rewritten = build.Tree(snapshots, Relocator::Options(nx.next_xid, kObjectPhysical,
                kObjectTypeSnapMetaTree, AppleBtreeKeyOrder::FileSystemCaseSensitive));
            snapshot_oid = rewritten.root_physical_block;
        }
        auto records = build.Records(volume.object_map.tree, 0, nx.xid);
        std::uint64_t selected_version = 0;
        for (const auto& r : records) if (ReadU64LE(r.key, 0) == volume.superblock.root_oid)
            selected_version = (std::max)(selected_version, ReadU64LE(r.key, 8).value());
        std::vector<Record> new_mappings;
        for (const auto& r : records) {
            const auto oid = ReadU64LE(r.key, 0).value(), xid = ReadU64LE(r.key, 8).value();
            if (oid != volume.superblock.root_oid &&
                (move_physical_snapshot || oid != volume.superblock.snap_meta_tree_oid)) continue;
            const auto physical = ReadU64LE(r.value, 8).value(); const auto bytes = build.Read(physical);
            AppleObjectLocation root{oid, ReadU64LE(bytes, 16).value(), physical, ReadU32LE(bytes, 24).value(), ReadU32LE(bytes, 28).value(), Block};
            auto tree_records = build.Records(root, volume.object_map.object.physical_block,
                oid == volume.superblock.root_oid && xid == selected_version ? nx.xid : xid);
            Require(oid == volume.superblock.root_oid || tree_records.empty(), "VolumeResizeRelocationSnapshotHistoryPresent");
            if (oid == volume.superblock.root_oid) tree_records = build.FileRecords(tree_records);
            auto options = Relocator::Options(root.xid, 0, root.subtype,
                ApfsNamePolicy::FromIncompatibleFeatures(volume.superblock.incompatible_features).UsesHashedDirectoryKeys() ?
                    AppleBtreeKeyOrder::FileSystemHashedDirectory : AppleBtreeKeyOrder::FileSystemCaseSensitive);
            options.root_object_id = oid;
            const auto rewritten = build.Tree(tree_records, options, &new_mappings, xid);
            new_mappings.push_back(build.Mapping(oid, xid, rewritten.root_physical_block));
        }
        std::string error; Require(SortAppleBtreeRecords(new_mappings, AppleBtreeKeyOrder::ObjectMap, error), error);
        const auto map_tree = build.Tree(new_mappings, Relocator::Options(nx.next_xid, kObjectPhysical, kObjectTypeOmap, AppleBtreeKeyOrder::ObjectMap));
        const auto map = build.Allocate(); Bytes map_bytes;
        Require(PatchAppleObjectMap(build.Read(volume.object_map.object.physical_block), map, nx.next_xid, map_tree.root_physical_block, map_bytes, error), error);
        build.Write(map, std::move(map_bytes)); build.covered.insert(volume.object_map.object.physical_block);
        Require(volume.extentref_tree.has_value() && !volume.file_extent_tree, "VolumeResizeRelocationExtentTreeProfile");
        const auto extent_records = build.ExtentRecords(build.Records(*volume.extentref_tree, 0, volume.superblock.xid));
        const auto extent_tree = build.Tree(extent_records, Relocator::Options(nx.next_xid, kObjectPhysical, kObjectTypeBlockRefTree, AppleBtreeKeyOrder::PhysicalExtent));
        const auto descriptor = build.Allocate(); const auto original = build.Read(volume.superblock_object.physical_block);
        build.covered.insert(volume.superblock_object.physical_block);
        std::set<std::uint64_t> removed;
        for (const auto block : build.covered) if (!covered_before.contains(block)) {
            removed.insert(block); if (block < build.count) build.retired_main.insert(block);
        }
        // Payload is charged once per owning volume, including shared historical references.
        std::set<std::uint64_t> volume_payload;
        const auto old_extent_records = build.Records(*volume.extentref_tree, 0, volume.superblock.xid);
        for (const auto& record : old_extent_records) {
            ApplePhysicalExtentRecord extent; Require(DecodeApplePhysicalExtentRecord(record, extent, error), error);
            for (auto block = (std::max)(extent.physical_block, build.count); block < extent.physical_block + extent.block_count; ++block)
                if (build.payload.contains(block)) { removed.insert(block); volume_payload.insert(block); }
        }
        const auto allocated = build.writes.size() - writes_before + 1 + volume_payload.size();
        const auto previous = ReadU64LE(original, 0x58).value();
        Require(previous <= UINT64_MAX - allocated && previous + allocated >= removed.size() && ReadU64LE(original, 0xe0).value() <= UINT64_MAX - allocated &&
            ReadU64LE(original, 0xe8).value() <= UINT64_MAX - removed.size(), "VolumeResizeRelocationAccountingOverflow");
        AppleVolumeAccountingUpdate accounting; accounting.xid = nx.next_xid; accounting.object_map_object_id = map;
        accounting.file_system_allocated_blocks = previous + allocated - removed.size();
        accounting.root_tree_object_id = volume.superblock.root_oid; accounting.extentref_tree_object_id = extent_tree.root_physical_block;
        accounting.snapshot_metadata_tree_object_id = snapshot_oid; accounting.next_object_id = build.next_oid;
        accounting.file_count = ReadU64LE(original, 0xb8).value(); accounting.directory_count = ReadU64LE(original, 0xc0).value();
        accounting.symlink_count = ReadU64LE(original, 0xc8).value(); accounting.other_object_count = ReadU64LE(original, 0xd0).value();
        accounting.total_blocks_allocated = ReadU64LE(original, 0xe0).value() + allocated;
        accounting.total_blocks_freed = ReadU64LE(original, 0xe8).value() + removed.size();
        accounting.last_modification_time = ReadU64LE(original, 0x100).value(); Bytes apsb;
        Require(PatchAppleVolumeSuperblock(original, accounting, apsb, error), error); build.Write(descriptor, std::move(apsb));
        container_mappings.push_back(build.Mapping(volume.superblock.object_id, nx.next_xid, descriptor));
    }
    std::string error; Require(SortAppleBtreeRecords(container_mappings, AppleBtreeKeyOrder::ObjectMap, error), error);
    const auto container_tree = build.Tree(container_mappings, Relocator::Options(nx.next_xid, kObjectPhysical, kObjectTypeOmap, AppleBtreeKeyOrder::ObjectMap));
    const auto container_map = build.Allocate(); Bytes map_bytes;
    Require(PatchAppleObjectMap(build.Read(cp.container_object_map.object.physical_block), container_map, nx.next_xid, container_tree.root_physical_block, map_bytes, error), error);
    build.Write(container_map, std::move(map_bytes));
    build.covered.insert(cp.container_object_map.object.physical_block);
    (void)build.Records(cp.container_object_map.tree, 0, nx.xid);
    if (cp.container_object_map.object.physical_block < build.count) build.retired_main.insert(cp.container_object_map.object.physical_block);
    {
        BtreeReadPolicy policy; std::vector<std::uint64_t> nodes; policy.visited_physical_blocks = &nodes;
        std::vector<Record> records; Require(ReadBtreeLeafRecords(source, Block, cp.container_object_map.tree.physical_block, true, 0, nx.xid, policy, records, error), error);
        for (const auto block : nodes) if (block < build.count) build.retired_main.insert(block);
    }
    const auto retire_reserved = [&](std::uint64_t start, std::uint64_t length) {
        for (auto block = start; block < (std::min)(build.count, start + length); ++block) {
            const auto& chunk = old_sm.chunks.at(static_cast<std::size_t>(block / old_sm.blocks_per_chunk));
            if (chunk.bitmap_block && Bit(chunk.allocation_bitmap, block - chunk.start_block)) build.retired_main.insert(block);
        }
    };
    retire_reserved(nx.xp_desc_base_block, nx.xp_desc_block_count); retire_reserved(nx.xp_data_base_block, nx.xp_data_block_count);
    retire_reserved(old_sm.internal_pool.bitmap_base_block, old_sm.internal_pool.bitmap_block_count);
    retire_reserved(old_sm.internal_pool.base_block, old_sm.internal_pool.block_count);
    const auto sm_physical = build.DataBlock();
    build.mappings.push_back({old_sm.object.type, old_sm.object.subtype, Block, 0, old_sm.object.object_id, sm_physical});
    Bytes pool_bitmap(Block); std::uint64_t pool_used = cibs + chunks;
    for (std::uint64_t i = 0; i < pool_used; ++i) SetBit(pool_bitmap, i, true);
    auto spaceman = old_sm.bytes;
    Put(spaceman, 16, nx.next_xid); Put(spaceman, 0x30, build.count); Put(spaceman, 0x38, chunks);
    Put(spaceman, 0x40, cibs, 4); Put(spaceman, 0x44, 0, 4); Put(spaceman, 0x50, 0xa00, 4);
    Put(spaceman, 0x90, 1, 4); Put(spaceman, 0x94, 16, 4); Put(spaceman, 0x98, pool);
    Put(spaceman, 0xa0, 1, 4); Put(spaceman, 0xa4, 16, 4); Put(spaceman, 0xa8, ip_bitmap); Put(spaceman, 0xb0, ip);
    Put(spaceman, 0x140, 1, 2); Put(spaceman, 0x142, 15, 2);
    Put(spaceman, 0x144, xid_offset, 4); Put(spaceman, 0x148, head_offset, 4); Put(spaceman, 0x14c, link_offset, 4);
    std::fill(spaceman.begin() + 0xa00, spaceman.end(), std::byte{});
    for (std::uint64_t i = 0; i < cibs; ++i) Put(spaceman, 0xa00 + i * 8, ip + i);
    Put(spaceman, xid_offset, nx.next_xid);
    for (unsigned i = 0; i < 16; ++i) Put(spaceman, link_offset + i * 2, i == 0 || i == 15 ? 0xffff : i + 1, 2);
    for (std::size_t q = 0; q < old_sm.free_queues.size(); ++q) {
        const auto& queue = old_sm.free_queues[q];
        Require(q < 2 || queue.entries.empty(), "VolumeResizeRelocationSecondaryQueue");
        if (!queue.tree_oid && (q != 1 || build.retired_main.empty())) { Require(queue.entries.empty(), "VolumeResizeRelocationQueueMissing"); continue; }
        std::vector<Record> records; std::map<std::uint64_t, std::uint64_t> queued; std::uint64_t total = 0;
        for (const auto& entry : queue.entries) for (std::uint64_t n = 0; n < entry.block_count; ++n) {
            const auto old = entry.physical_block + n; auto physical = old;
            if (!q) {
                Require(pool_used < pool, "VolumeResizeRelocationPoolQuota"); physical = ip + pool_used;
                SetBit(pool_bitmap, pool_used++, true); build.Write(physical, build.Read(old));
            } else if (old >= build.count) {
                Require(!build.payload.contains(old), "VolumeResizeRelocationQueuedLivePayload");
                physical = build.Allocate(); build.Write(physical, build.Read(old));
            }
            Require(queued.emplace(physical, entry.xid).second, "VolumeResizeRelocationQueueOverlap"); build.covered.insert(old);
        }
        if (q == 1) for (const auto block : build.retired_main)
            Require(queued.emplace(block, nx.next_xid).second, "VolumeResizeRelocationRetirementOverlap");
        std::uint64_t oldest = 0;
        for (const auto& [physical, xid] : queued) {
            Record record; Number(record.key, xid); Number(record.key, physical);
            records.push_back(std::move(record)); ++total; oldest = oldest ? (std::min)(oldest, xid) : xid;
        }
        Require(SortAppleBtreeRecords(records, AppleBtreeKeyOrder::SpacemanFreeQueue, error), error);
        auto options = Relocator::Options(nx.next_xid, kObjectEphemeral, kObjectTypeSpacemanFreeQueue, AppleBtreeKeyOrder::SpacemanFreeQueue);
        options.root_object_id = queue.tree_oid ? queue.tree_oid : build.Oid(); options.fixed_key_size = 16; options.fixed_value_size = 8;
        options.minimum_longest_key = 16; options.minimum_longest_value = 8;
        options.tree_flags |= kAppleBtreeUint64Keys | kAppleBtreeSequentialInsert | kAppleBtreeAllowGhosts;
        const auto tree = build.Tree(records, options, nullptr, 0, true); (void)tree;
        Put(spaceman, 0xc8 + q * 0x28, total); Put(spaceman, 0xd0 + q * 0x28, options.root_object_id);
        Put(spaceman, 0xd8 + q * 0x28, oldest); Put(spaceman, 0xe0 + q * 0x28, (std::max<std::size_t>)(8, tree.objects.size()), 2);
    }
    for (const auto& mapping : cp.container.mappings) {
        if (mapping.object_id == old_sm.object.object_id || std::any_of(old_sm.free_queues.begin(), old_sm.free_queues.end(),
            [&](const auto& queue) { return mapping.object_id == queue.tree_oid ||
                std::find(queue.tree_blocks.begin(), queue.tree_blocks.end(), mapping.physical_block) != queue.tree_blocks.end(); })) continue;
        Require(mapping.object_id == nx.reaper_oid && mapping.type == (kObjectEphemeral | 17) &&
            mapping.size_bytes == Block, "VolumeResizeRelocationEphemeralUnknown");
        auto bytes = build.Read(mapping.physical_block); Put(bytes, 16, nx.next_xid); Checksum(bytes);
        const auto physical = build.DataBlock(); build.Write(physical, std::move(bytes)); auto copy = mapping;
        copy.physical_block = physical; build.mappings.push_back(copy);
    }
    const auto in_range = [](std::uint64_t block, std::uint64_t start, std::uint64_t count) { return block >= start && block - start < count; };
    for (const auto& item : inventory.blocks) {
        const auto block = item.physical_block;
        Require(build.covered.contains(block) || build.payload.contains(block) ||
            in_range(block, nx.xp_desc_base_block, nx.xp_desc_block_count) ||
            in_range(block, nx.xp_data_base_block, nx.xp_data_block_count) ||
            in_range(block, old_sm.internal_pool.base_block, old_sm.internal_pool.block_count) ||
            in_range(block, old_sm.internal_pool.bitmap_base_block, old_sm.internal_pool.bitmap_block_count),
            "VolumeResizeRelocationUntransferredOwner");
    }
    const auto object = [&](std::uint64_t oid, std::uint32_t type, std::uint32_t subtype = 0) {
        Bytes bytes(Block); Put(bytes, 8, oid); Put(bytes, 16, nx.next_xid); Put(bytes, 24, type, 4); Put(bytes, 28, subtype, 4); return bytes;
    };
    std::vector<Bytes> cib_bytes;
    for (std::uint64_t i = 0; i < cibs; ++i) {
        auto bytes = object(ip + i, kObjectPhysical | kObjectTypeSpacemanCib);
        Put(bytes, 0x20, i, 4); Put(bytes, 0x24, (std::min<std::uint64_t>)(old_sm.chunks_per_cib, chunks - i * old_sm.chunks_per_cib), 4);
        cib_bytes.push_back(std::move(bytes));
    }
    std::uint64_t total_free = 0;
    for (std::uint64_t i = 0; i < chunks; ++i) {
        const auto start = i * old_sm.blocks_per_chunk, length = (std::min<std::uint64_t>)(old_sm.blocks_per_chunk, build.count - start);
        const auto& old = old_sm.chunks.at(static_cast<std::size_t>(i)); Bytes bitmap(Block);
        if (old.bitmap_block) bitmap = old.allocation_bitmap;
        for (auto b = length; b < old_sm.blocks_per_chunk; ++b) SetBit(bitmap, b, true);
        for (auto b = build.reserved.lower_bound(start); b != build.reserved.end() && *b < start + length; ++b) SetBit(bitmap, *b - start, true);
        std::uint64_t free = 0; for (std::uint64_t b = 0; b < length; ++b) if (!Bit(bitmap, b)) ++free;
        total_free += free; const auto at = 0x28 + (i % old_sm.chunks_per_cib) * 0x20;
        auto& cib = cib_bytes.at(static_cast<std::size_t>(i / old_sm.chunks_per_cib));
        Put(cib, at, nx.next_xid); Put(cib, at + 8, start); Put(cib, at + 0x10, length, 4); Put(cib, at + 0x14, free, 4);
        Put(cib, at + 0x18, ip + cibs + i); build.Write(ip + cibs + i, std::move(bitmap));
    }
    for (std::uint64_t i = 0; i < cibs; ++i) { Checksum(cib_bytes.at(static_cast<std::size_t>(i))); build.Write(ip + i, std::move(cib_bytes.at(static_cast<std::size_t>(i)))); }
    build.Write(ip_bitmap, std::move(pool_bitmap)); Put(spaceman, 0x48, total_free); Checksum(spaceman); build.Write(sm_physical, std::move(spaceman));
    const auto per_map = (Block - 40) / 40; const auto map_count = (build.mappings.size() + per_map - 1) / per_map;
    Require(map_count && map_count + 1 <= 32, "VolumeResizeRelocationCheckpointMapQuota");
    for (std::size_t i = 0; i < map_count; ++i) {
        auto bytes = object(build.base + i, kObjectPhysical | kObjectTypeCheckpointMap);
        Put(bytes, 0x20, i + 1 == map_count ? 1 : 0, 4);
        const auto begin = i * per_map, end = (std::min)(build.mappings.size(), begin + per_map); Put(bytes, 0x24, end - begin, 4);
        for (auto n = begin; n < end; ++n) {
            const auto& m = build.mappings[n]; const auto at = 0x28 + (n - begin) * 0x28;
            Put(bytes, at, m.type, 4); Put(bytes, at + 4, m.subtype, 4); Put(bytes, at + 8, m.size_bytes, 4);
            Put(bytes, at + 0x10, m.file_system_oid); Put(bytes, at + 0x18, m.object_id); Put(bytes, at + 0x20, m.physical_block);
        }
        Checksum(bytes); build.Write(build.base + i, std::move(bytes));
    }
    auto nx_bytes = cp.container.superblock_bytes; Put(nx_bytes, 16, nx.next_xid); Put(nx_bytes, 0x28, build.count);
    Put(nx_bytes, 0x58, build.next_oid); Put(nx_bytes, 0x60, nx.next_xid + 1);
    Put(nx_bytes, 0x68, 32, 4); Put(nx_bytes, 0x6c, 256, 4); Put(nx_bytes, 0x70, build.base); Put(nx_bytes, 0x78, build.data);
    Put(nx_bytes, 0x80, map_count + 1, 4); Put(nx_bytes, 0x84, build.data_next - build.data, 4);
    Put(nx_bytes, 0x88, 0, 4); Put(nx_bytes, 0x8c, map_count + 1, 4); Put(nx_bytes, 0x90, 0, 4); Put(nx_bytes, 0x94, build.data_next - build.data, 4);
    Put(nx_bytes, 0xa0, container_map); Put(nx_bytes, 0x4f0, ReadU64LE(nx_bytes, 0x4f0).value() & ~2ull); Checksum(nx_bytes);
    auto& publication = plan.publication; publication.block_size = Block; publication.expected_checkpoint_xid = nx.xid;
    publication.transaction_xid = nx.next_xid; publication.next_object_id = build.next_oid;
    publication.superblock_write = {AppleCheckpointWriteKind::CheckpointSuperblock, build.base + map_count, 1, nx_bytes};
    for (const auto block : build.reserved) if (!build.writes.contains(block) && block != publication.superblock_write.physical_block)
        build.Write(block, Bytes(Block));
    for (auto& [block, bytes] : build.writes)
        publication.before_superblock_writes.push_back({AppleCheckpointWriteKind::AllocatorOwned, block, ReadU64LE(bytes, 8).value_or(0), std::move(bytes)});
    publication.published_checkpoint.superblock_bytes = nx_bytes; publication.published_checkpoint.superblock = *ParseNxSuperblock(nx_bytes);
    publication.published_checkpoint.superblock_physical_block = publication.superblock_write.physical_block;
    publication.guard_blocks.push_back({0, build.Read(0)});
    publication.guard_blocks.push_back({cp.container.superblock_physical_block, cp.container.superblock_bytes});
    plan.anchor = nx_bytes; for (std::size_t at = 0x80; at <= 0x94; at += 4) Put(plan.anchor, at, 0, 4); Checksum(plan.anchor);
    FinishResizeSource(source, request, plan);
    RelocationProofSource post(source, plan, request.target_bytes);
    std::vector<std::uint64_t> metadata; std::vector<ApplePhysicalExtentRecord> owned;
    const auto complete = LoadAppleSnapshotCheckpointOwners(post, plan.after, metadata, owned, error);
    Require(complete && !metadata.empty(), "VolumeResizeRelocationPostOwnerGraph:" + error);
    ApfsSharedSpaceProjection space; Require(TryProjectAppleSharedSpace(plan.after, space, error), error);
    std::uint64_t promised = 0;
    for (const auto& volume : plan.after.volumes) {
        const auto& s = volume.superblock.space;
        const auto unmet = s.reserve_block_count > s.allocated_block_count ? s.reserve_block_count - s.allocated_block_count : 0;
        Require(unmet <= space.free.blocks && promised <= space.free.blocks - unmet, "VolumeResizeReserveCapacity"); promised += unmet;
    }
    return plan;
}
Plan BuildResizeRelocationPublication(const catalog::RandomAccessSource& source, const VolumeImageRequest& request)
{ return BuildResizeRelocationPublicationImpl(source, request, false); }
Plan BuildResizeRelocationPublicationV2(const catalog::RandomAccessSource& source, const VolumeImageRequest& request)
{ return BuildResizeRelocationPublicationImpl(source, request, true); }
}
