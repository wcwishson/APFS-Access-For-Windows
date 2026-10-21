#include "VolumeResizeInternal.h"
#include <algorithm>

namespace apfsaccess::rw::volume_image
{
namespace
{
using namespace catalog;
Bytes Object(std::uint64_t oid, std::uint64_t xid, std::uint32_t type, std::uint32_t subtype = 0)
{ Bytes b(Block); Put(b, 8, oid); Put(b, 16, xid); Put(b, 24, type, 4); Put(b, 28, subtype, 4); return b; }
void Uuid(Bytes& b, std::size_t at, const std::string& s)
{
    const auto nibble = [](char c) { return c <= '9' ? c - '0' : c - 'a' + 10; };
    for (unsigned i = 0; i < 16; ++i) b.at(at + i) = std::byte((nibble(s.at(2 * i)) << 4) | nibble(s.at(2 * i + 1)));
}
Bytes Tree(std::vector<BtreeRecord> records, std::uint64_t oid, std::uint64_t physical, std::uint64_t xid,
    std::uint32_t storage, std::uint32_t subtype, AppleBtreeKeyOrder order)
{
    AppleBtreeOptions o; o.block_size = Block; o.xid = xid; o.root_object_id = oid; o.root_physical_block = physical;
    o.storage_type = storage; o.subtype = subtype; o.key_order = order;
    o.tree_flags = storage == kObjectPhysical ? kAppleBtreePhysical : storage == kObjectEphemeral ? kAppleBtreeEphemeral : 0;
    if (order == AppleBtreeKeyOrder::ObjectMap) { o.fixed_key_size = 16; o.fixed_value_size = 16; }
    if (order == AppleBtreeKeyOrder::SpacemanFreeQueue) {
        o.fixed_key_size = 16; o.fixed_value_size = 8; o.minimum_longest_key = 16; o.minimum_longest_value = 8;
        o.tree_flags |= kAppleBtreeUint64Keys | kAppleBtreeSequentialInsert | kAppleBtreeAllowGhosts;
    }
    std::string e; Require(SortAppleBtreeRecords(records, order, e), e);
    AppleSerializedBtree tree; Require(SerializeAppleBtree(records, o, tree, e), e);
    Require(tree.objects.size() == 1, "VolumeFormatInitialTreeTooLarge"); return tree.objects.front().bytes;
}
BtreeRecord Mapping(std::uint64_t oid, std::uint64_t xid, std::uint64_t physical)
{ BtreeRecord r; std::string e; Require(EncodeAppleOmapRecord({oid, xid, 0, Block, physical}, r, e), e); return r; }
Bytes Omap(std::uint64_t block, std::uint64_t tree, std::uint64_t xid, bool container)
{
    auto b = Object(block, xid, kObjectPhysical | 11); Put(b, 0x20, container ? 1 : 0, 4);
    Put(b, 0x28, kObjectPhysical | 2, 4); Put(b, 0x30, tree); Checksum(b); return b;
}
}
static Plan BuildFormatPublicationWithStorage(const catalog::RandomAccessSource& source, const VolumeImageRequest& r,
    const catalog::AppleCheckpointView& checkpoint, bool flagged, bool bounded_cleanup = false)
{
    using namespace catalog;
    Require(IsFormat(r.operation), "VolumeFormatOperationMismatch"); Plan p; p.before = checkpoint;
    const auto& cp = p.before; const auto& nx = cp.container.superblock;
    const auto maximum_file_systems = ReadU32LE(cp.container.superblock_bytes, 0xb4).value_or(0);
    Require(maximum_file_systems && maximum_file_systems <= 100, "VolumeFormatSourceVolumeSlotsInvalid");
    std::string e;
    AppleSnapshotRetentionView snapshots; Require(LoadAppleSnapshotRetention(source, cp, snapshots, e), e);
    Require(snapshots.identities.empty() && !cp.container_object_map.snapshot_tree_oid, "VolumeFormatSnapshotOwnersPresent");
    // Reserving the complete new bootstrap layout through the existing allocator
    // keeps every pre-switch write away from current/retired owner blocks.
    // Keep the bootstrap rings fixed, but size the internal pool and direct CIB
    // table from the admitted device. Fully free chunks need no bitmap block.
    constexpr std::uint64_t VolumeOid = 1024, SpacemanOid = 0x4000, ReaperOid = 0x4003;
    constexpr std::uint64_t BlocksPerChunk = Block * 8ull;
    constexpr std::uint64_t ChunksPerCib = (Block - 40) / 32;
    const auto chunk_count = (nx.block_count + BlocksPerChunk - 1) / BlocksPerChunk;
    const auto cib_count = (chunk_count + ChunksPerCib - 1) / ChunksPerCib;
    const auto xid_offset = 0xa00 + cib_count * 8, head_offset = xid_offset + 8, link_offset = head_offset + 16;
    Require(nx.block_size == Block && nx.block_count && nx.block_count <= StreamedFormatLimit / Block &&
        chunk_count && cib_count && link_offset + 16 * 2 <= Block,
        "VolumeFormatChunkGeometryUnsupported");
    // A new layout smaller than one chunk touches at most two layout chunks
    // plus the anchor chunk. Keep at least 24 free internal-pool slots.
    std::uint64_t pool_blocks = 32;
    while (pool_blocks < cib_count + 3 + 24) pool_blocks *= 2;
    const auto layout_blocks = 304 + pool_blocks + 8;
    Require(pool_blocks <= Block * 8ull && layout_blocks < BlocksPerChunk,
        "VolumeFormatInternalPoolGeometryUnsupported");
    for (const auto& v : cp.volumes) Require(v.superblock.uuid_hex != r.new_volume_uuid, "VolumeFormatReusedVolumeUuid");
    AppleSpacemanAllocationRequest a; a.expected_checkpoint_xid = nx.xid; a.transaction_xid = nx.next_xid;
    a.oldest_required_checkpoint_xid = 1; a.main_block_count = layout_blocks; a.search_from_end = true; a.first_ephemeral_object_id = nx.next_oid;
    for (const auto& b : cp.spaceman.internal_pool.active_bitmaps) a.protected_internal_pool_bitmap_indices.push_back(b.rotation_index);
    AppleSpacemanAllocationPlan allocation; Require(PlanAppleSpacemanAllocation(cp.spaceman, a, allocation, e), e);
    auto blocks = allocation.allocated_main_blocks; std::sort(blocks.begin(), blocks.end());
    Require(blocks.size() == layout_blocks && blocks.front() && blocks.back() - blocks.front() + 1 == layout_blocks,
        "VolumeFormatContiguousFreeBootstrapRequired");
    const auto base = blocks.front(), data = base + 32, ip_bitmap = base + 288, ip = base + 304, main = ip + pool_blocks;
    // The allocator protects current ownership and deferred frees. The held
    // CLEAN WAL census and empty snapshots authorize retiring obsolete headers.
    auto& publication = p.publication; publication.block_size = Block;
    publication.expected_checkpoint_xid = nx.xid; publication.transaction_xid = nx.next_xid; publication.next_object_id = 0x5000;
    std::map<std::uint64_t, Bytes> fresh;
    // Initialize every reserved block; rotation/ring spare blocks must not retain
    // accidental headers that could be mistaken for a new-generation candidate.
    for (auto b : blocks) fresh[b] = Bytes(Block);
    const auto xid = nx.next_xid;
    fresh[main] = Omap(main, main + 1, xid, true);
    fresh[main + 1] = Tree({Mapping(VolumeOid, xid, main + 2)}, main + 1, main + 1, xid, kObjectPhysical, 11, AppleBtreeKeyOrder::ObjectMap);
    fresh[main + 3] = Omap(main + 3, main + 4, xid, false);
    auto volume_mappings = std::vector<BtreeRecord>{Mapping(1024, xid, main + 5)};
    if (!flagged) volume_mappings.push_back(Mapping(1025, xid, main + 7));
    fresh[main + 4] = Tree(std::move(volume_mappings), main + 4, main + 4, xid,
        kObjectPhysical, 11, AppleBtreeKeyOrder::ObjectMap);
    std::vector<BtreeRecord> fs;
    for (auto id : {2ull, 3ull}) {
        AppleInodeRecord inode; inode.object_id = inode.private_id = id; inode.parent_id = id == 2 ? 1 : 2;
        inode.mode = id == 2 ? 0040755 : 0040700; inode.children_or_links = id == 2 ? 1 : 0;
        BtreeRecord record; Require(EncodeAppleInodeRecord(inode, record, e), e); fs.push_back(std::move(record));
    }
    AppleDirectoryRecord private_dir; private_dir.parent_id = 2; private_dir.file_id = 3; private_dir.flags = 4; private_dir.name_utf8 = "private-dir";
    BtreeRecord record; Require(EncodeAppleDirectoryRecord(private_dir,
        ApfsNamePolicy::FromIncompatibleFeatures(r.case_sensitive ? 0 : kIncompatCaseInsensitive), record, e), e); fs.push_back(std::move(record));
    fresh[main + 5] = Tree(fs, 1024, main + 5, xid, 0, 14,
        r.case_sensitive ? AppleBtreeKeyOrder::FileSystemCaseSensitive : AppleBtreeKeyOrder::FileSystemHashedDirectory);
    fresh[main + 6] = Tree({}, main + 6, main + 6, xid, kObjectPhysical, 15, AppleBtreeKeyOrder::PhysicalExtent);
    fresh[main + 7] = Tree({}, flagged ? main + 7 : 1025, main + 7, xid, flagged ? kObjectPhysical : 0,
        16, AppleBtreeKeyOrder::FileSystemCaseSensitive);
    auto apsb = Object(VolumeOid, xid, 13); Put(apsb, 0x20, 0x42535041, 4);
    Put(apsb, 0x38, r.case_sensitive ? 0 : kIncompatCaseInsensitive); Put(apsb, 0x58, 6);
    Put(apsb, 0x74, 2, 4); Put(apsb, 0x78, kObjectPhysical | 2, 4); Put(apsb, 0x7c, (flagged ? kObjectPhysical : 0) | 2, 4);
    Put(apsb, 0x80, main + 3); Put(apsb, 0x88, 1024); Put(apsb, 0x90, main + 6); Put(apsb, 0x98, flagged ? main + 7 : 1025);
    Put(apsb, 0xb0, 1026); Put(apsb, 0xc0, 2); Put(apsb, 0xe0, 6); Uuid(apsb, 0xf0, r.new_volume_uuid);
    Put(apsb, 0x108, kFsFlagUnencrypted);
    for (std::size_t i = 0; i < r.name_utf8.size(); ++i) apsb.at(0x2c0 + i) = std::byte(static_cast<unsigned char>(r.name_utf8[i]));
    Checksum(apsb); const auto volume = ParseApsb(apsb);
    Require(volume && volume->name_valid && volume->name_utf8 == r.name_utf8, "VolumeFormatNameInvalid"); fresh[main + 2] = std::move(apsb);
    auto sm = Object(SpacemanOid, xid, kObjectEphemeral | 5);
    Put(sm, 0x20, Block, 4); Put(sm, 0x24, Block * 8, 4); Put(sm, 0x28, (Block - 40) / 32, 4); Put(sm, 0x2c, (Block - 40) / 8, 4);
    Put(sm, 0x30, nx.block_count); Put(sm, 0x38, chunk_count); Put(sm, 0x40, cib_count, 4);
    const auto free_count = nx.block_count - layout_blocks - 1;
    Put(sm, 0x48, free_count); Put(sm, 0x50, 0xa00, 4); Put(sm, 0x90, 1, 4); Put(sm, 0x94, 16, 4);
    Put(sm, 0x98, pool_blocks); Put(sm, 0xa0, 1, 4); Put(sm, 0xa4, 16, 4); Put(sm, 0xa8, ip_bitmap); Put(sm, 0xb0, ip);
    Put(sm, 0xd0, SpacemanOid + 1); Put(sm, 0xe0, 8, 2); Put(sm, 0xf8, SpacemanOid + 2); Put(sm, 0x108, 8, 2);
    Put(sm, 0x140, 1, 2); Put(sm, 0x142, 15, 2); Put(sm, 0x144, xid_offset, 4); Put(sm, 0x148, head_offset, 4); Put(sm, 0x14c, link_offset, 4);
    Put(sm, 0x150, 1, 4); Put(sm, 0x154, Block, 4); Put(sm, xid_offset, xid);
    for (std::uint64_t i = 0; i < cib_count; ++i) Put(sm, 0xa00 + i * 8, ip + i);
    for (unsigned i = 0; i < 16; ++i) Put(sm, link_offset + i * 2, i == 0 || i == 15 ? 0xffff : i + 1, 2);
    Checksum(sm); fresh[data] = std::move(sm);
    fresh[data + 1] = Tree({}, SpacemanOid + 1, data + 1, xid, kObjectEphemeral, 9, AppleBtreeKeyOrder::SpacemanFreeQueue);
    fresh[data + 2] = Tree({}, SpacemanOid + 2, data + 2, xid, kObjectEphemeral, 9, AppleBtreeKeyOrder::SpacemanFreeQueue);
    auto reaper = Object(ReaperOid, xid, kObjectEphemeral | 17); Put(reaper, 0x20, 1); Put(reaper, 0x40, 1, 4);
    Checksum(reaper); fresh[data + 3] = std::move(reaper);
    Bytes pool_bitmap(Block);
    std::vector<Bytes> cibs;
    for (std::uint64_t i = 0; i < cib_count; ++i) {
        auto cib = Object(ip + i, xid, kObjectPhysical | 7);
        Put(cib, 0x20, i, 4); Put(cib, 0x24, (std::min)(ChunksPerCib, chunk_count - i * ChunksPerCib), 4);
        cibs.push_back(std::move(cib)); SetBit(pool_bitmap, i, true);
    }
    auto next_bitmap_slot = cib_count;
    for (std::uint64_t i = 0; i < chunk_count; ++i) {
        const auto start = i * BlocksPerChunk;
        const auto count = (std::min)(BlocksPerChunk, nx.block_count - start);
        Bytes bitmap(Block); std::uint64_t allocated = 0;
        if (start == 0) { SetBit(bitmap, 0, true); ++allocated; }
        const auto begin = (std::max)(start, base), end = (std::min)(start + count, base + layout_blocks);
        for (auto b = begin; b < end; ++b) { SetBit(bitmap, b - start, true); ++allocated; }
        std::uint64_t bitmap_block = 0;
        if (allocated) {
            Require(next_bitmap_slot < pool_blocks, "VolumeFormatBitmapPoolExhausted");
            bitmap_block = ip + next_bitmap_slot;
            fresh[bitmap_block] = std::move(bitmap); SetBit(pool_bitmap, next_bitmap_slot++, true);
        }
        auto& cib = cibs[i / ChunksPerCib];
        const auto at = 0x28 + (i % ChunksPerCib) * 0x20;
        Put(cib, at, xid); Put(cib, at + 8, start); Put(cib, at + 0x10, count, 4);
        Put(cib, at + 0x14, count - allocated, 4); Put(cib, at + 0x18, bitmap_block);
    }
    fresh[ip_bitmap] = std::move(pool_bitmap);
    for (std::uint64_t i = 0; i < cib_count; ++i) { Checksum(cibs[i]); fresh[ip + i] = std::move(cibs[i]); }
    auto map = Object(base, xid, kObjectPhysical | 12); Put(map, 0x20, 1, 4); Put(map, 0x24, 4, 4);
    for (unsigned i = 0; i < 4; ++i) {
        const auto at = 0x28 + i * 0x28;
        Put(map, at, kObjectEphemeral | (i == 0 ? 5 : i == 3 ? 17 : 2), 4);
        Put(map, at + 4, i == 1 || i == 2 ? 9 : 0, 4); Put(map, at + 8, Block, 4);
        Put(map, at + 0x18, SpacemanOid + i); Put(map, at + 0x20, data + i);
    }
    Checksum(map); fresh[base] = std::move(map);
    auto anchor = Object(1, xid, (flagged ? kObjectEphemeral : 0) | 1); Put(anchor, 0x20, 0x4253584e, 4); Put(anchor, 0x24, Block, 4); Put(anchor, 0x28, nx.block_count);
    Put(anchor, 0x40, 2);
    Uuid(anchor, 0x48, r.new_container_uuid); Put(anchor, 0x58, 0x5000); Put(anchor, 0x60, xid + 1);
    Put(anchor, 0x68, 32, 4); Put(anchor, 0x6c, 256, 4); Put(anchor, 0x70, base); Put(anchor, 0x78, data);
    Put(anchor, 0x80, 2, 4); Put(anchor, 0x84, 4, 4); Put(anchor, 0x8c, 2, 4); Put(anchor, 0x94, 4, 4);
    Put(anchor, 0x98, SpacemanOid); Put(anchor, 0xa0, main); Put(anchor, 0xa8, ReaperOid); Put(anchor, 0xb4, maximum_file_systems, 4);
    Put(anchor, 0x520, (8ull << 32) | (4ull << 16) | 1);
    Put(anchor, 0xb8, VolumeOid); Checksum(anchor);
    fresh.erase(base + 1);
    for (const auto& [block, bytes] : fresh)
        publication.before_superblock_writes.push_back({AppleCheckpointWriteKind::AllocatorOwned, block, ReadU64LE(bytes, 8).value_or(0), bytes});
    publication.superblock_write = {AppleCheckpointWriteKind::CheckpointSuperblock, base + 1, 1, anchor};
    Bytes block_zero; Require(source.Read(0, Block, block_zero) && block_zero.size() == Block, "VolumeFormatAnchorReadFailed");
    publication.guard_blocks.push_back({0, std::move(block_zero)});
    publication.guard_blocks.push_back({cp.container.superblock_physical_block, cp.container.superblock_bytes});
    p.anchor = anchor;
    for (std::size_t at = 0x80; at <= 0x94; at += 4) Put(p.anchor, at, 0, 4);
    Checksum(p.anchor);
    if (bounded_cleanup && r.operation == VolumeImageOperation::Erase && nx.block_count <= Limit / Block) for (std::uint64_t b = 1; b < nx.block_count; ++b)
        if (b < base || b >= base + layout_blocks) p.cleanup.push_back({b, Bytes(Block)});
    return p;
}
Plan BuildFormatPublication(const catalog::RandomAccessSource& source, const VolumeImageRequest& r,
    const catalog::AppleCheckpointView& checkpoint) { return BuildFormatPublicationWithStorage(source, r, checkpoint, false); }
Plan BuildFormatPublicationV2(const catalog::RandomAccessSource& source, const VolumeImageRequest& r,
    const catalog::AppleCheckpointView& checkpoint) { return BuildFormatPublicationWithStorage(source, r, checkpoint, true); }
static Plan PlanFormatWithStorage(const Bytes& original, const VolumeImageRequest& r, const CleanImageHistoryAuthority* authority, bool flagged)
{
    Require(authority != nullptr, "VolumeImageRetentionAuthorityRequired");
    Require(IsFormat(r.operation), "VolumeFormatOperationMismatch");
    const auto checkpoint = Admit(original, r); authority->RequireFor(original, r, checkpoint);
    catalog::VectorRandomAccessSource source(original);
    auto p = BuildFormatPublicationWithStorage(source, r, checkpoint, flagged, true);
    FinishPlan(original, r, p);
    Require(p.after.volumes.size() == 1 && p.after.container.superblock.uuid_hex == r.new_container_uuid &&
        p.after.volumes.front().superblock.uuid_hex == r.new_volume_uuid && p.after.volumes.front().superblock.object_id == 1024,
        "VolumeFormatPostIdentityMismatch");
    return p;
}
Plan PlanFormat(const Bytes& original, const VolumeImageRequest& r, const CleanImageHistoryAuthority* authority)
{ return PlanFormatWithStorage(original, r, authority, false); }
Plan PlanFormatV2(const Bytes& original, const VolumeImageRequest& r, const CleanImageHistoryAuthority* authority)
{ return PlanFormatWithStorage(original, r, authority, true); }
}
namespace apfsaccess::rw
{
VolumeImageResult PrepareVolumeFormat(const VolumeImageRequest& r) { return volume_image::Prepare(r, true); }
VolumeImageResult ApplyVolumeFormat(const VolumeImageRequest& r, std::string_view t, const AppleCheckpointStageHook& h)
{ return volume_image::Run(r, t, true, false, false, h); }
VolumeImageResult RecoverVolumeFormat(const VolumeImageRequest& r, const AppleCheckpointStageHook& h)
{ return volume_image::Run(r, {}, true, true, false, h); }
VolumeImageResult CancelVolumeFormat(const VolumeImageRequest& r, std::string_view t)
{ return volume_image::Run(r, t, true, false, true, {}); }
}
