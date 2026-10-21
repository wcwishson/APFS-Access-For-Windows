#include "VolumeManagementInternal.h"
#include "ApfsVerifier.h"
#include "ApfsSharedSpace.h"
#include "NativeVolumeRename.h"
#include <algorithm>
#include <map>
#include <set>

namespace apfsaccess::rw::volume_management
{
using catalog::BtreeRecord;
namespace
{
using namespace catalog;
bool Fail(std::string& e, const char* why) { e = why; return false; }
void Put(std::vector<std::byte>& b, std::size_t at, std::uint64_t n, unsigned width = 8)
{ for (unsigned i = 0; i < width; ++i) b.at(at + i) = std::byte((n >> (8 * i)) & 255); }
bool ReadTree(const RandomAccessSource& s, const AppleCheckpointView& cp,
    const AppleObjectLocation& root, std::uint64_t omap, std::vector<BtreeRecord>& records,
    std::vector<std::uint64_t>& visited, std::string& e)
{
    BtreeReadPolicy p;
    p.enforce_object_identity = true; p.root_object_id = root.object_id;
    p.storage_type = root.type; p.subtype = root.subtype;
    p.require_complete_traversal = true; p.reject_unsupported_flags = true;
    std::vector<std::uint64_t> nodes;
    p.visited_physical_blocks = &nodes; p.ephemeral_checkpoint = &cp.container;
    const bool physical = (root.type & kObjectStorageTypeMask) == kObjectPhysical;
    if (!ReadBtreeLeafRecords(s, cp.container.superblock.block_size, root.physical_block,
        physical, physical ? 0 : omap, cp.container.superblock.xid, p, records, e)) return false;
    visited.insert(visited.end(), nodes.begin(), nodes.end()); return true;
}
bool Tree(const std::vector<BtreeRecord>& records, std::uint32_t bs, std::uint64_t xid,
    std::uint64_t oid, const std::vector<std::uint64_t>& blocks, std::uint32_t storage,
    std::uint32_t subtype, AppleBtreeKeyOrder order, AppleSerializedBtree& tree, std::string& e)
{
    AppleBtreeOptions o;
    o.block_size = bs; o.xid = xid; o.root_object_id = oid;
    o.root_physical_block = blocks.front(); o.first_child_object_id = oid + 1;
    o.first_child_physical_block = blocks.front() + 1;
    o.child_physical_blocks.assign(blocks.begin() + 1, blocks.end());
    o.storage_type = storage; o.subtype = subtype; o.key_order = order;
    o.tree_flags = storage == kObjectPhysical ? kAppleBtreePhysical : 0;
    if (order == AppleBtreeKeyOrder::ObjectMap) { o.fixed_key_size = 16; o.fixed_value_size = 16; }
    return SerializeAppleBtree(records, o, tree, e);
}
bool AddMap(std::vector<BtreeRecord>& records, std::uint64_t oid, std::uint64_t xid,
    std::uint64_t physical, std::uint32_t bs, std::string& e)
{
    BtreeRecord r;
    if (!EncodeAppleOmapRecord({oid, xid, 0, bs, physical}, r, e)) return false;
    records.push_back(std::move(r)); return true;
}
std::vector<std::byte> Omap(std::uint64_t block, std::uint64_t tree,
    std::uint64_t xid, std::uint32_t bs, std::string& e)
{
    std::vector<std::byte> b(bs);
    Put(b, 8, block); Put(b, 16, xid); Put(b, 24, kObjectPhysical | 11, 4);
    Put(b, 0x28, kObjectPhysical | 2, 4); Put(b, 0x30, tree);
    if (!FinalizeAppleObjectChecksum(b, e)) return {}; return b;
}
class Overlay final : public RandomAccessSource
{
    const RandomAccessSource& source_;
    const AppleCheckpointPublicationPlan& plan_;
public:
    Overlay(const RandomAccessSource& s, const AppleCheckpointPublicationPlan& p) : source_(s), plan_(p) {}
    std::uint64_t SizeBytes() const override { return source_.SizeBytes(); }
    bool Read(std::uint64_t offset, std::size_t n, std::vector<std::byte>& b) const override
    {
        if (!source_.Read(offset, n, b) || b.size() != n) return false;
        const auto apply = [&](const auto& w) {
            const auto start = w.physical_block * plan_.block_size;
            const auto lo = (std::max)(offset, start), hi = (std::min)(offset + n, start + w.bytes.size());
            if (lo < hi) std::copy_n(w.bytes.begin() + (lo - start), hi - lo, b.begin() + (lo - offset));
        };
        for (const auto& w : plan_.before_superblock_writes) apply(w);
        apply(plan_.superblock_write); return true;
    }
};
}

bool VerifyTopology(const catalog::RandomAccessSource& s, const catalog::AppleCheckpointView& cp, std::string& e)
{
    if (cp.volumes.empty()) return Fail(e, "VolumeManagementEmptyContainerVerificationUnavailable");
    catalog::VerificationScope scope;
    scope.source_identity = "exclusive-volume-management-image";
    scope.exact = {0, s.SizeBytes(), cp.container.superblock.uuid_hex,
        cp.volumes.front().superblock.uuid_hex, cp.volumes.front().superblock.object_id, cp.container.superblock.xid};
    const auto report = catalog::ApfsVerifier::Verify(s, scope);
    if (report.outcome != catalog::VerificationOutcome::Complete || !report.allocation_census) {
        e = "VolumeManagementVerificationIncomplete";
        if (!report.findings.empty()) e += ":" + report.findings.front().detail;
        return false;
    }
    return true;
}

static bool PlanTopologyWithSnapshotStorage(const catalog::RandomAccessSource& source, const VolumeManagementRequest& r,
    TopologyPlan& out, std::string& e, bool physical_snapshot) try
{
    using namespace catalog;
    out = {}; e.clear();
    auto cp = LoadAppleCheckpointView(source, 0, source.SizeBytes(), e);
    if (!cp) return false;
    const auto& nx = cp->container.superblock;
    const bool create = r.operation == VolumeManagementOperation::Create;
    if ((!create && r.operation != VolumeManagementOperation::Delete) || !r.volume_oid || !r.checkpoint_xid ||
        !ValidRenameUuid(r.container_uuid) || !ValidRenameUuid(r.volume_uuid) ||
        r.container_uuid != nx.uuid_hex || r.checkpoint_xid != nx.xid || nx.next_xid <= nx.xid ||
        nx.next_xid == UINT64_MAX || !nx.next_oid || nx.next_oid > UINT64_MAX - 4096)
        return Fail(e, "VolumeManagementExactIdentityMismatch");
    if (!create && (!r.name_utf8.empty() || r.quota_blocks || r.reserve_blocks || r.case_sensitive))
        return Fail(e, "VolumeManagementDeleteOptionsInvalid");
    if (create && (r.volume_oid != nx.next_oid || r.name_utf8.empty() || r.name_utf8.size() > 255 ||
        r.name_utf8.find('\0') != std::string::npos || (r.quota_blocks && r.reserve_blocks > r.quota_blocks)))
        return Fail(e, "VolumeManagementCreateOptionsInvalid");
    if (!VerifyTopology(source, *cp, e)) return false;
    for (const auto& mapping : cp->container.mappings)
        if (mapping.file_system_oid) return Fail(e, "VolumeManagementEphemeralVolumeOwnerUnproven");
    if (nx.reaper_oid) {
        const auto mapping = std::find_if(cp->container.mappings.begin(), cp->container.mappings.end(),
            [&](const auto& m) { return m.object_id == nx.reaper_oid; });
        std::vector<std::byte> reaper;
        if (mapping == cp->container.mappings.end() || mapping->size_bytes != nx.block_size ||
            !source.Read(mapping->physical_block * nx.block_size, nx.block_size, reaper) ||
            ReadU64LE(reaper, 0x30).value_or(1) || ReadU64LE(reaper, 0x38).value_or(1) ||
            ReadU32LE(reaper, 0x40).value_or(0) != 1 || ReadU32LE(reaper, 0x44).value_or(1) ||
            ReadU64LE(reaper, 0x50).value_or(1) || ReadU64LE(reaper, 0x58).value_or(1) ||
            ReadU32LE(reaper, 0x68).value_or(1) || ReadU32LE(reaper, 0x6c).value_or(1))
            return Fail(e, "VolumeManagementReaperWorkUnproven");
    }
    if (cp->container_object_map.snapshot_tree_oid)
        return Fail(e, "VolumeManagementContainerSnapshotsPresent");
    std::map<std::uint64_t, std::vector<std::uint64_t>> metadata;
    std::map<std::uint64_t, std::vector<ApplePhysicalExtentRecord>> payload;
    const AppleVolumeCheckpointView* target = nullptr;
    for (const auto& v : cp->volumes) {
        if (!CheckAppleVolumeWriteFeatures(nx, v.superblock, e)) return false;
        if (v.superblock.object_id == r.volume_oid) target = &v;
        if (create && (v.superblock.object_id == r.volume_oid || v.superblock.uuid_hex == r.volume_uuid))
            return Fail(e, "VolumeManagementDuplicateVolumeIdentity");
        std::vector<std::byte> sb;
        if (!source.Read(v.superblock_object.physical_block * nx.block_size, nx.block_size, sb))
            return Fail(e, "VolumeManagementSuperblockReadFailed");
        if (ReadU64LE(sb, 0xd8).value_or(1) || v.object_map.snapshot_tree_oid ||
            ReadU64LE(sb, 0xa0).value_or(1) || ReadU64LE(sb, 0xa8).value_or(1) ||
            ReadU64LE(sb, 0x3d0).value_or(1) || v.file_extent_tree)
            return Fail(e, "VolumeManagementSnapshotsOrPendingTransition");
        auto& owned = metadata[v.superblock.object_id];
        owned = {v.superblock_object.physical_block, v.object_map.object.physical_block};
        std::vector<BtreeRecord> records, fs, refs;
        if (!ReadTree(source, *cp, v.object_map.tree, 0, records, owned, e) ||
            !ReadTree(source, *cp, v.root_tree, v.superblock.omap_oid, fs, owned, e) || !v.extentref_tree ||
            !ReadTree(source, *cp, *v.extentref_tree, 0, refs, owned, e)) return false;
        // Delete cannot discharge historical or unknown OMAP ownership. Require
        // every mapping to name one of the complete currently walked trees.
        const auto mappings = records;
        if (v.snapshot_metadata_tree && (!ReadTree(source, *cp, *v.snapshot_metadata_tree,
            v.superblock.omap_oid, records, owned, e) || !records.empty()))
            return Fail(e, "VolumeManagementSnapshotsPresent");
        std::sort(owned.begin(), owned.end()); owned.erase(std::unique(owned.begin(), owned.end()), owned.end());
        if (!ValidateApplePayloadExtentGraph(fs, refs, nx.block_size, nx.block_count, payload[v.superblock.object_id], e) ||
            !ValidateAppleCheckpointPayloadOwnership(source, *cp, payload[v.superblock.object_id], e)) return false;
        std::uint64_t charge = owned.size();
        for (const auto& p : payload[v.superblock.object_id]) charge += p.block_count;
        if (charge != v.superblock.space.allocated_block_count)
            return Fail(e, "VolumeManagementHistoricalChargeUnproven");
        if (!create && v.superblock.object_id == r.volume_oid) {
            std::set<std::uint64_t> mapped;
            for (const auto& m : mappings) {
                if (m.key.size() != 16 || m.value.size() != 16 || ReadU32LE(m.value, 0).value_or(1) ||
                    ReadU32LE(m.value, 4) != nx.block_size ||
                    !mapped.insert(ReadU64LE(m.key, 0).value_or(0)).second ||
                    !std::binary_search(owned.begin(), owned.end(), ReadU64LE(m.value, 8).value_or(UINT64_MAX)))
                    return Fail(e, "VolumeManagementDeleteHistoricalOmapUnproven");
            }
        }
    }
    if (!create && (!target || target->superblock.uuid_hex != r.volume_uuid))
        return Fail(e, "VolumeManagementExactVolumeMismatch");
    if (!create && cp->volumes.size() == 1)
        return Fail(e, "VolumeManagementLastVolumeVerificationUnavailable");
    std::size_t slot = 100;
    const auto maximum = ReadU32LE(cp->container.superblock_bytes, 0xb4).value_or(0);
    if (!maximum || maximum > 100) return Fail(e, "VolumeManagementVolumeSlotsInvalid");
    for (std::size_t i = 0; i < maximum; ++i) {
        const auto id = ReadU64LE(cp->container.superblock_bytes, 0xb8 + 8 * i).value_or(UINT64_MAX);
        if ((create && !id) || (!create && id == r.volume_oid)) { slot = i; break; }
    }
    if (slot == 100) return Fail(e, "VolumeManagementNoVolumeSlot");
    std::vector<BtreeRecord> container_records;
    std::vector<std::uint64_t> old_container_tree;
    if (!ReadTree(source, *cp, cp->container_object_map.tree, 0, container_records, old_container_tree, e)) return false;
    if (create) {
        for (const auto& m : container_records)
            if (ReadU64LE(m.key, 0) == r.volume_oid) return Fail(e, "VolumeManagementOidAlreadyMapped");
        if (!AddMap(container_records, r.volume_oid, nx.next_xid, 1, nx.block_size, e)) return false;
    } else {
        unsigned erased = 0;
        std::erase_if(container_records, [&](const auto& m) {
            if (ReadU64LE(m.key, 0) != r.volume_oid) return false;
            ++erased; return true;
        });
        if (erased != 1) return Fail(e, "VolumeManagementDeleteContainerHistoryUnproven");
    }
    AppleSerializedBtree estimate;
    if (!Tree(container_records, nx.block_size, nx.next_xid, 1, {1}, kObjectPhysical, 11,
        AppleBtreeKeyOrder::ObjectMap, estimate, e)) return false;
    AppleSpacemanAllocationRequest allocation;
    allocation.expected_checkpoint_xid = nx.xid; allocation.transaction_xid = nx.next_xid;
    // Disable reclamation of unrelated historical queue debt in this profile.
    allocation.oldest_required_checkpoint_xid = 1;
    allocation.first_ephemeral_object_id = nx.next_oid + (create ? 1 : 0);
    allocation.main_block_count = estimate.objects.size() + 1 + (create ? 6 : 0);
    for (const auto& b : cp->spaceman.internal_pool.active_bitmaps)
        allocation.protected_internal_pool_bitmap_indices.push_back(b.rotation_index);
    if (!create) {
        // Complete verifier independently rejects cross-volume aliasing. Also
        // require explicit disjointness here before constructing any release.
        std::set<std::uint64_t> candidates(metadata[r.volume_oid].begin(), metadata[r.volume_oid].end());
        for (const auto& p : payload[r.volume_oid])
            for (auto i = 0ull; i < p.block_count; ++i) candidates.insert(p.physical_block + i);
        for (const auto& v : cp->volumes) if (v.superblock.object_id != r.volume_oid) {
            for (const auto b : metadata[v.superblock.object_id])
                if (candidates.contains(b)) return Fail(e, "VolumeManagementSiblingMetadataOwner");
            for (const auto& p : payload[v.superblock.object_id]) {
                const auto it = candidates.lower_bound(p.physical_block);
                if (it != candidates.end() && *it - p.physical_block < p.block_count)
                    return Fail(e, "VolumeManagementSiblingPayloadOwner");
            }
        }
        for (const auto b : candidates) allocation.released_blocks.push_back({b, 1});
    }
    TopologyPlan plan; plan.before = *cp;
    if (!PlanAppleSpacemanAllocation(cp->spaceman, allocation, plan.allocation, e)) return false;
    const auto& blocks = plan.allocation.allocated_main_blocks;
    if (blocks.size() != allocation.main_block_count) return Fail(e, "VolumeManagementAllocationMismatch");
    AppleTransactionCommitRequest commit;
    commit.allocation_plan = plan.allocation;
    commit.next_object_id = nx.next_oid + (create ? 1 : 0);
    commit.required_checkpoint_xids = {nx.xid};
    const auto append = [&](const AppleSerializedBtree& tree) {
        for (const auto& o : tree.objects) commit.allocated_main_writes.push_back({o.location.physical_block, o.bytes});
    };
    if (create) {
        // Six owned blocks: APSB, OMAP object/tree, FS root, extentrefs, snapshots.
        std::vector<BtreeRecord> fs;
        for (auto id : {2ull, 3ull}) {
            AppleInodeRecord inode;
            inode.object_id = inode.private_id = id; inode.parent_id = id == 2 ? 1 : 2;
            inode.mode = id == 2 ? 0040755 : 0040700; inode.children_or_links = id == 2 ? 1 : 0;
            BtreeRecord rec; if (!EncodeAppleInodeRecord(inode, rec, e)) return false; fs.push_back(std::move(rec));
        }
        AppleDirectoryRecord private_directory;
        private_directory.parent_id = 2; private_directory.file_id = 3;
        private_directory.flags = 4; private_directory.name_utf8 = "private-dir";
        BtreeRecord private_record;
        if (!EncodeAppleDirectoryRecord(private_directory,
            ApfsNamePolicy::FromIncompatibleFeatures(r.case_sensitive ? 0 : kIncompatCaseInsensitive), private_record, e)) return false;
        fs.push_back(std::move(private_record));
        AppleSerializedBtree tree;
        if (!Tree(fs, nx.block_size, nx.next_xid, 1024, {blocks[3]}, 0, 14,
            r.case_sensitive ? AppleBtreeKeyOrder::FileSystemCaseSensitive : AppleBtreeKeyOrder::FileSystemHashedDirectory, tree, e)) return false;
        append(tree);
        if (!Tree({}, nx.block_size, nx.next_xid, blocks[4], {blocks[4]}, kObjectPhysical, 15,
            AppleBtreeKeyOrder::PhysicalExtent, tree, e)) return false;
        append(tree);
        if (!Tree({}, nx.block_size, nx.next_xid, physical_snapshot ? blocks[5] : 1025, {blocks[5]}, physical_snapshot ? kObjectPhysical : 0, 16,
            AppleBtreeKeyOrder::FileSystemCaseSensitive, tree, e)) return false;
        append(tree);
        std::vector<BtreeRecord> maps;
        if (!AddMap(maps, 1024, nx.next_xid, blocks[3], nx.block_size, e) ||
            (!physical_snapshot && !AddMap(maps, 1025, nx.next_xid, blocks[5], nx.block_size, e)) ||
            !Tree(maps, nx.block_size, nx.next_xid, blocks[2], {blocks[2]}, kObjectPhysical, 11,
                AppleBtreeKeyOrder::ObjectMap, tree, e)) return false;
        append(tree);
        auto omap = Omap(blocks[1], blocks[2], nx.next_xid, nx.block_size, e);
        if (omap.empty()) return false; commit.allocated_main_writes.push_back({blocks[1], std::move(omap)});
        std::vector<std::byte> sb(nx.block_size);
        Put(sb, 8, r.volume_oid); Put(sb, 16, nx.next_xid); Put(sb, 24, 13, 4);
        Put(sb, 0x20, 0x42535041, 4); Put(sb, 0x24, slot, 4);
        Put(sb, 0x38, r.case_sensitive ? 0 : kIncompatCaseInsensitive);
        Put(sb, 0x48, r.reserve_blocks); Put(sb, 0x50, r.quota_blocks); Put(sb, 0x58, 6);
        Put(sb, 0x74, 2, 4); Put(sb, 0x78, kObjectPhysical | 2, 4); Put(sb, 0x7c, (physical_snapshot ? kObjectPhysical : 0) | 2, 4);
        Put(sb, 0x80, blocks[1]); Put(sb, 0x88, 1024); Put(sb, 0x90, blocks[4]); Put(sb, 0x98, physical_snapshot ? blocks[5] : 1025);
        Put(sb, 0xb0, 1026); Put(sb, 0xc0, 2); Put(sb, 0xe0, 6); Put(sb, 0x108, kFsFlagUnencrypted);
        for (std::size_t i = 0; i < 16; ++i) {
            const auto hex = [](char c) { return c <= '9' ? c - '0' : c - 'a' + 10; };
            sb[0xf0 + i] = std::byte(hex(r.volume_uuid[2 * i]) * 16 + hex(r.volume_uuid[2 * i + 1]));
        }
        for (std::size_t i = 0; i < r.name_utf8.size(); ++i) sb[0x2c0 + i] = std::byte(static_cast<unsigned char>(r.name_utf8[i]));
        if (!FinalizeAppleObjectChecksum(sb, e)) return false;
        const auto parsed = ParseApsb(sb);
        if (!parsed || !parsed->name_valid || parsed->name_utf8 != r.name_utf8)
            return Fail(e, "VolumeManagementInvalidUtf8Name");
        commit.allocated_main_writes.push_back({blocks[0], std::move(sb)});
        std::erase_if(container_records, [&](const auto& m) { return ReadU64LE(m.key, 0) == r.volume_oid; });
        if (!AddMap(container_records, r.volume_oid, nx.next_xid, blocks[0], nx.block_size, e)) return false;
    }
    const auto start = create ? 6u : 0u;
    std::vector<std::uint64_t> container_blocks(blocks.begin() + start, blocks.end() - 1);
    AppleSerializedBtree container_tree;
    if (!Tree(container_records, nx.block_size, nx.next_xid, container_blocks.front(), container_blocks,
        kObjectPhysical, 11, AppleBtreeKeyOrder::ObjectMap, container_tree, e)) return false;
    append(container_tree);
    std::vector<std::byte> old_omap, new_omap;
    if (!source.Read(cp->container_object_map.object.physical_block * nx.block_size, nx.block_size, old_omap) ||
        !PatchAppleObjectMap(old_omap, blocks.back(), nx.next_xid, container_tree.root_physical_block, new_omap, e)) return false;
    commit.container_object_map_oid = blocks.back();
    commit.allocated_main_writes.push_back({blocks.back(), std::move(new_omap)});
    AppleTransactionCommitPlan composed;
    if (!PlanAppleTransactionCommit(source, *cp, commit, composed, e)) return false;
    plan.publication = std::move(composed.publication);
    auto& sb = plan.publication.superblock_write.bytes;
    Put(sb, 0xb8 + 8 * slot, create ? r.volume_oid : 0);
    if (!FinalizeAppleObjectChecksum(sb, e)) return false;
    auto parsed = ParseNxSuperblock(sb);
    if (!parsed) return Fail(e, "VolumeManagementContainerSerializationInvalid");
    plan.publication.published_checkpoint.superblock = *parsed;
    plan.publication.published_checkpoint.superblock_bytes = sb;
    Overlay staged(source, plan.publication);
    auto after = LoadAppleCheckpointView(staged, 0, staged.SizeBytes(), e);
    if (!after || after->container.superblock.xid != nx.next_xid ||
        after->volumes.size() != cp->volumes.size() + (create ? 1 : -1) || !VerifyTopology(staged, *after, e)) return false;
    ApfsSharedSpaceProjection space;
    if (!TryProjectAppleSharedSpace(*after, space, e)) return false;
    std::uint64_t promises = 0;
    for (const auto& v : after->volumes) {
        const auto& s = v.superblock.space;
        const auto unmet = s.reserve_block_count > s.allocated_block_count ? s.reserve_block_count - s.allocated_block_count : 0;
        if (unmet > space.free.blocks || promises > space.free.blocks - unmet)
            return Fail(e, "VolumeManagementReserveCapacityExceeded");
        promises += unmet;
    }
    for (const auto& v : cp->volumes) {
        if (!create && v.superblock.object_id == r.volume_oid) continue;
        const auto peer = std::find_if(after->volumes.begin(), after->volumes.end(), [&](const auto& x) {
            return x.superblock.object_id == v.superblock.object_id; });
        std::vector<std::byte> before_bytes, after_bytes;
        if (peer == after->volumes.end() || peer->superblock_object.physical_block != v.superblock_object.physical_block ||
            !source.Read(v.superblock_object.physical_block * nx.block_size, nx.block_size, before_bytes) ||
            !staged.Read(peer->superblock_object.physical_block * nx.block_size, nx.block_size, after_bytes) || before_bytes != after_bytes)
            return Fail(e, "VolumeManagementSiblingChanged");
    }
    // Retained old metadata must never be overwritten, including all siblings.
    for (const auto& [id, owned] : metadata) for (const auto block : owned) {
        for (const auto& w : plan.publication.before_superblock_writes)
            if (w.physical_block == block) return Fail(e, "VolumeManagementLiveMetadataReused");
    }
    plan.after = *after;
    for (const auto& release : allocation.released_blocks) plan.released_blocks += release.block_count;
    out = std::move(plan); return true;
}
catch (const std::exception& ex) { out = {}; e = std::string("VolumeManagementPlanningException:") + ex.what(); return false; }
bool PlanTopology(const catalog::RandomAccessSource& source, const VolumeManagementRequest& r,
    TopologyPlan& out, std::string& e) { return PlanTopologyWithSnapshotStorage(source, r, out, e, false); }
bool PlanTopologyV2(const catalog::RandomAccessSource& source, const VolumeManagementRequest& r,
    TopologyPlan& out, std::string& e) { return PlanTopologyWithSnapshotStorage(source, r, out, e, true); }
}
