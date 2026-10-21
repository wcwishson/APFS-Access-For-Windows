#include "VolumeResizeInternal.h"
#include "AppleVolumeTransaction.h"
#include "ApfsVerifier.h"
#include "ApfsSharedSpace.h"
#include <algorithm>
#include <map>

namespace apfsaccess::rw::volume_image
{
using namespace catalog;
namespace
{
class FormatOverlay final : public RandomAccessSource
{
public:
    explicit FormatOverlay(const RandomAccessSource& source, std::uint64_t size = 0) : source_(source), size_(size ? size : source.SizeBytes()) {}
    std::uint64_t SizeBytes() const override { return size_; }
    void SetSize(std::uint64_t size) { size_ = size; }
    std::shared_ptr<ApfsReadBudget> ReadBudget() const override { return source_.ReadBudget(); }
    bool Read(std::uint64_t offset, std::size_t size, Bytes& out) const override
    {
        out.clear();
        if (offset > SizeBytes() || size > SizeBytes() - offset) return false;
        const auto original = offset < source_.SizeBytes() ? static_cast<std::size_t>((std::min<std::uint64_t>)(size, source_.SizeBytes() - offset)) : 0;
        if (original && (!source_.Read(offset, original, out) || out.size() != original)) { out.clear(); return false; }
        out.resize(size); // Only the explicitly new growth suffix is zero.
        if (!size) return true;
        const auto end = offset + size;
        for (auto it = blocks_.lower_bound(offset / Block); it != blocks_.end() && it->first <= (end - 1) / Block; ++it) {
            const auto start = it->first * Block;
            const auto from = (std::max)(offset, start), to = (std::min)(end, start + Block);
            std::copy(it->second.begin() + (from - start), it->second.begin() + (to - start), out.begin() + (from - offset));
        }
        return true;
    }
    void Add(const AppleCheckpointPhysicalWrite& write)
    {
        Require(write.bytes.size() == Block && write.physical_block < SizeBytes() / Block && blocks_.size() < 4096,
            "VolumeFormatOverlayBounds");
        Require(blocks_.emplace(write.physical_block, write.bytes).second, "VolumeFormatOverlayOverlap");
    }
private:
    const RandomAccessSource& source_;
    std::uint64_t size_;
    std::map<std::uint64_t, Bytes> blocks_;
};
// Extend only the allocator's fresh IP rotation. Old rotations and every old
// allocated slot remain intact until their checkpoint is no longer required.
std::uint64_t ReserveGeometryBitmap(const AppleSpacemanView& before,
    const std::vector<AppleRecoveryCheckpointView>& retained, AppleSpacemanAllocationPlan& allocation)
{
    auto& pool = allocation.updated_spaceman.internal_pool;
    for (std::size_t i = 0; i < pool.active_bitmaps.size(); ++i) {
        auto& bitmap = pool.active_bitmaps[i]; const auto first = i * Block * 8ull;
        if (bitmap.xid != allocation.transaction_xid || i >= before.internal_pool.active_bitmaps.size() ||
            bitmap.physical_block == before.internal_pool.active_bitmaps[i].physical_block) continue;
        const auto write = std::find_if(allocation.writes.begin(), allocation.writes.end(), [&](const auto& w) {
            return w.kind == AppleSpacemanWriteKind::InternalPoolBitmap && w.physical_block == bitmap.physical_block; });
        Require(write != allocation.writes.end() && write->bytes == bitmap.bytes, "VolumeResizeIpRotationWriteMissing");
        for (auto bit = 0ull; bit < Block * 8ull && first + bit < pool.block_count; ++bit) {
            if (Bit(bitmap.bytes, bit) || Bit(before.internal_pool.active_bitmaps[i].bytes, bit)) continue;
            const auto block = pool.base_block + first + bit;
            const auto free_in = [&](const auto& old) {
                const auto& ip = old.checkpoint.spaceman.internal_pool;
                return ip.base_block == pool.base_block && ip.block_count == pool.block_count &&
                    i < ip.active_bitmaps.size() && !Bit(ip.active_bitmaps[i].bytes, bit);
            };
            if (!std::all_of(retained.begin(), retained.end(), free_in)) continue;
            Require(block < before.devices[0].block_count, "VolumeResizeIpReservationBounds");
            SetBit(bitmap.bytes, bit, true); write->bytes = bitmap.bytes;
            allocation.allocated_internal_pool_blocks.push_back(block); return block;
        }
    }
    throw std::runtime_error("VolumeResizeGeometryInternalPoolExhausted");
}

void RetireGeometryBitmap(AppleSpacemanAllocationPlan& allocation, std::uint64_t block)
{
    auto& sm = allocation.updated_spaceman; auto& q = sm.free_queues[0]; const auto& pool = sm.internal_pool;
    Require(block >= pool.base_block && block - pool.base_block < pool.block_count && q.tree_oid &&
        q.tree_blocks.size() <= 1, "VolumeResizeBitmapRetirementUnproven");
    const auto bit = block - pool.base_block;
    Require(bit / (Block * 8ull) < pool.active_bitmaps.size() &&
        Bit(pool.active_bitmaps[bit / (Block * 8ull)].bytes, bit % (Block * 8ull)), "VolumeResizeRetiredBitmapNotOwned");
    for (const auto& entry : q.entries)
        Require(block < entry.physical_block || block - entry.physical_block >= entry.block_count, "VolumeResizeBitmapAlreadyRetired");
    q.entries.push_back({allocation.transaction_xid, block, 1});
    std::sort(q.entries.begin(), q.entries.end(), [](const auto& a, const auto& b) {
        return a.xid < b.xid || (a.xid == b.xid && a.physical_block < b.physical_block); });
    std::vector<catalog::BtreeRecord> records;
    for (const auto& entry : q.entries) {
        catalog::BtreeRecord record; record.key.resize(16); Put(record.key, 0, entry.xid); Put(record.key, 8, entry.physical_block);
        if (entry.block_count != 1) { record.value.resize(8); Put(record.value, 0, entry.block_count); }
        records.push_back(std::move(record));
    }
    AppleBtreeOptions options; options.block_size = Block; options.xid = allocation.transaction_xid;
    options.root_object_id = q.tree_oid; options.root_physical_block = 1; options.storage_type = kObjectEphemeral;
    options.subtype = kObjectTypeSpacemanFreeQueue; options.tree_flags = q.tree_flags;
    options.fixed_key_size = q.fixed_key_size; options.fixed_value_size = q.fixed_value_size;
    options.minimum_longest_key = q.longest_key; options.minimum_longest_value = q.longest_value;
    options.key_order = AppleBtreeKeyOrder::SpacemanFreeQueue; options.max_nodes = 1;
    AppleSerializedBtree tree; std::string error;
    Require(SerializeAppleBtree(records, options, tree, error) && tree.objects.size() == 1,
        "VolumeResizeBitmapRetirementQueueCapacity:" + error);
    const auto& object = tree.objects.front(); q.root = object.location; q.root.physical_block = 0; q.tree_blocks.clear();
    ++q.block_count; q.oldest_xid = q.entries.front().xid;
    Put(sm.bytes, 0xc8, q.block_count); Put(sm.bytes, 0xd8, q.oldest_xid);
    for (auto& root : sm.free_queue_roots) if (root.object_id == q.tree_oid) root = q.root;
    const auto existing = std::find_if(allocation.writes.begin(), allocation.writes.end(), [&](const auto& w) {
        return w.kind == AppleSpacemanWriteKind::FreeQueueTree && w.object_location && w.object_location->object_id == q.tree_oid; });
    AppleSpacemanPlannedWrite write; write.kind = AppleSpacemanWriteKind::FreeQueueTree;
    write.object_location = q.root; write.bytes = object.bytes;
    if (existing == allocation.writes.end()) allocation.writes.push_back(std::move(write)); else *existing = std::move(write);
    allocation.deferred_frees.push_back({0, block, 1}); Checksum(sm.bytes);
}

void PrepareGeometryCibs(const AppleSpacemanView& before, std::uint64_t count,
    const std::vector<AppleRecoveryCheckpointView>& retained, AppleSpacemanAllocationPlan& allocation)
{
    auto& sm = allocation.updated_spaceman;
    const auto chunks = (count + sm.blocks_per_chunk - 1) / sm.blocks_per_chunk;
    const auto cibs = (chunks + sm.chunks_per_cib - 1) / sm.chunks_per_cib;
    for (std::size_t i = 0; i < cibs; ++i) {
        const auto begin = i * static_cast<std::uint64_t>(sm.chunks_per_cib);
        const auto end = (std::min<std::uint64_t>)(begin + sm.chunks_per_cib, (std::max)(chunks, before.devices[0].chunk_count));
        if (count == before.devices[0].block_count || end * sm.blocks_per_chunk <= (std::min)(count, before.devices[0].block_count)) continue;
        if (i < before.devices[0].cibs.size() && sm.devices[0].cibs[i].object.physical_block != before.devices[0].cibs[i].object.physical_block) continue;
        const auto physical = ReserveGeometryBitmap(before, retained, allocation);
        AppleSpacemanCibView copy;
        if (i < before.devices[0].cibs.size()) { copy = sm.devices[0].cibs[i]; RetireGeometryBitmap(allocation, copy.object.physical_block); }
        else { copy = before.devices[0].cibs.front(); copy.index = static_cast<std::uint32_t>(i); copy.chunk_indices.clear();
            std::fill(copy.bytes.begin() + 0x28, copy.bytes.end(), std::byte{}); Put(copy.bytes, 0x20, i, 4); Put(copy.bytes, 0x24, 0, 4); }
        copy.object.object_id = copy.object.physical_block = physical; copy.object.xid = allocation.transaction_xid;
        Put(copy.bytes, 8, physical); Put(copy.bytes, 16, allocation.transaction_xid); Checksum(copy.bytes);
        if (i < sm.devices[0].cibs.size()) { sm.devices[0].cibs[i] = copy; Put(sm.bytes, sm.devices[0].address_offset + i * 8, physical); }
        else sm.devices[0].cibs.push_back(copy);
        allocation.writes.push_back({AppleSpacemanWriteKind::ChunkInfoBlock, physical, {}, copy.bytes});
    }
    Checksum(sm.bytes);
}
void GeometryAddressTable(Bytes& bytes, const AppleSpacemanView& sm, std::size_t count)
{
    const auto& pool = sm.internal_pool;
    const auto slice = [&](std::size_t at, std::size_t n) { Require(at <= bytes.size() && n <= bytes.size() - at, "VolumeResizeIpArrayBounds");
        return Bytes(bytes.begin() + at, bytes.begin() + at + n); };
    const auto xids = slice(pool.bitmap_xid_offset, pool.bitmap_size_blocks * 8ull);
    const auto indices = slice(pool.bitmap_index_offset, pool.bitmap_size_blocks * 2ull);
    const auto links = slice(pool.bitmap_free_next_offset, pool.bitmap_block_count * 2ull);
    const auto xid = 0xa00 + count * 8, index = xid + xids.size(), link = (index + indices.size() + 7) / 8 * 8;
    Require(link <= bytes.size() && links.size() <= bytes.size() - link, "VolumeResizeDirectCibTableCapacity");
    for (std::size_t i = 0; i < count; ++i) Put(bytes, 0xa00 + i * 8, sm.devices[0].cibs.at(i).object.physical_block);
    Put(bytes, 0x50, 0xa00, 4); Put(bytes, 0x144, xid, 4); Put(bytes, 0x148, index, 4); Put(bytes, 0x14c, link, 4);
    std::copy(xids.begin(), xids.end(), bytes.begin() + xid); std::copy(indices.begin(), indices.end(), bytes.begin() + index);
    std::copy(links.begin(), links.end(), bytes.begin() + link);
}
void PrepareGeometryBitmaps(const AppleSpacemanView& before, std::uint64_t count,
    const std::vector<AppleRecoveryCheckpointView>& retained, AppleSpacemanAllocationPlan& allocation)
{
    auto& sm = allocation.updated_spaceman;
    for (std::size_t i = 0; i < sm.chunks.size(); ++i) {
        auto& chunk = sm.chunks[i];
        if (chunk.start_block >= count) {
            if (chunk.bitmap_block) RetireGeometryBitmap(allocation, chunk.bitmap_block);
            continue;
        }
        const auto blocks = (std::min<std::uint64_t>)(sm.blocks_per_chunk, count - chunk.start_block);
        if (blocks == chunk.block_count || !chunk.bitmap_block || chunk.bitmap_block != before.chunks[i].bitmap_block) continue;
        const auto old = chunk.bitmap_block; chunk.bitmap_block = ReserveGeometryBitmap(before, retained, allocation);
        RetireGeometryBitmap(allocation, old);
        AppleSpacemanPlannedWrite write; write.kind = AppleSpacemanWriteKind::ChunkBitmap;
        write.physical_block = chunk.bitmap_block; write.bytes = chunk.allocation_bitmap; allocation.writes.push_back(std::move(write));
        auto& cib = sm.devices.at(chunk.device_index).cibs.at(chunk.cib_index);
        Put(cib.bytes, 0x40 + chunk.index_in_cib * 0x20, chunk.bitmap_block); Checksum(cib.bytes);
        const auto cib_write = std::find_if(allocation.writes.begin(), allocation.writes.end(), [&](const auto& w) {
            return w.kind == AppleSpacemanWriteKind::ChunkInfoBlock && w.physical_block == cib.object.physical_block; });
        Require(cib_write != allocation.writes.end(), "VolumeResizeGeometryCibNotCopied"); cib_write->bytes = cib.bytes;
    }
}
}
bool IsFormat(VolumeImageOperation op) { return op == VolumeImageOperation::Format || op == VolumeImageOperation::Erase; }
void ValidateRequest(const VolumeImageRequest& r)
{ ValidateRequest(r, ImageAdmission::BoundedImage); }
void ValidateRequest(const VolumeImageRequest& r, ImageAdmission admission)
{
    const auto uuid = [](const std::string& s) {
        return s.size() == 32 && s != std::string(32, '0') && std::all_of(s.begin(), s.end(),
            [](char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); });
    };
    Require(r.operation >= VolumeImageOperation::Grow && r.operation <= VolumeImageOperation::Erase,
        "VolumeImageOperationInvalid");
    Require(uuid(r.container_uuid) && uuid(r.volume_uuid) && r.volume_oid && r.checkpoint_xid,
        "VolumeImageExactIdentityRequired");
    Require(admission != ImageAdmission::StreamedFormat || r.operation == VolumeImageOperation::Format,
        "VolumeStreamedFormatOperationRequired");
    Require(admission != ImageAdmission::StreamedErase || r.operation == VolumeImageOperation::Erase,
        "VolumeStreamedEraseOperationRequired");
    Require(admission != ImageAdmission::StreamedResize || !IsFormat(r.operation), "VolumeStreamedResizeOperationRequired");
    const auto limit = admission != ImageAdmission::BoundedImage ? StreamedFormatLimit : Limit;
    Require(r.expected_bytes >= 1048576 && r.target_bytes >= 1048576 && r.expected_bytes <= limit && r.target_bytes <= limit &&
        r.expected_bytes % Block == 0 && r.target_bytes % Block == 0, "VolumeImageCapacityProfile");
    if (IsFormat(r.operation)) {
        Require(r.target_bytes == r.expected_bytes && uuid(r.new_container_uuid) && uuid(r.new_volume_uuid) &&
            r.new_container_uuid != r.container_uuid && r.new_volume_uuid != r.volume_uuid &&
            !r.name_utf8.empty() && r.name_utf8.size() < 256 && r.name_utf8.find('\0') == std::string::npos,
            "VolumeFormatOptionsInvalid");
    } else {
        Require(r.new_container_uuid.empty() && r.new_volume_uuid.empty() && r.name_utf8.empty() && r.new_volume_wal.empty() && !r.case_sensitive,
            "VolumeResizeUnexpectedFormatOptions");
        Require(r.operation == VolumeImageOperation::Grow ? r.target_bytes > r.expected_bytes : r.target_bytes < r.expected_bytes,
            "VolumeResizeDirectionInvalid");
    }
}
void Verify(const Bytes& b, const AppleCheckpointView& cp)
{
    VectorRandomAccessSource source(b); VerifySource(source, cp);
}
void VerifySource(const catalog::RandomAccessSource& source, const AppleCheckpointView& cp)
{
    Require(!cp.volumes.empty(), "VolumeImageEmptyContainerUnsupported");
    VerificationScope scope;
    scope.source_identity = "exclusive-offline-resize-format-image";
    scope.exact = {0, cp.container.superblock.block_count * Block, cp.container.superblock.uuid_hex, cp.volumes.front().superblock.uuid_hex,
        cp.volumes.front().superblock.object_id, cp.container.superblock.xid};
    const auto report = ApfsVerifier::Verify(source, scope);
    Require(report.outcome == VerificationOutcome::Complete && report.allocation_census.has_value(),
        "VolumeImageVerificationIncomplete" + (report.findings.empty() ? std::string{} : ":" + report.findings.front().detail));
}
AppleCheckpointView Admit(const Bytes& b, const VolumeImageRequest& r)
{
    ValidateRequest(r); Require(b.size() == r.expected_bytes, "VolumeImageCapacityMismatch");
    VectorRandomAccessSource source(b); return AdmitSource(source, r, ImageAdmission::BoundedImage);
}
AppleCheckpointView AdmitSource(const catalog::RandomAccessSource& source, const VolumeImageRequest& r, ImageAdmission admission)
{
    ValidateRequest(r, admission); Require(source.SizeBytes() == r.expected_bytes, "VolumeImageCapacityMismatch");
    std::string e; auto cp = LoadAppleCheckpointView(source, 0, source.SizeBytes(), e);
    Require(cp.has_value(), e);
    const auto& nx = cp->container.superblock;
    Require(nx.block_size == Block && nx.block_count * Block == source.SizeBytes() && nx.uuid_hex == r.container_uuid &&
        nx.xid == r.checkpoint_xid && nx.next_xid > nx.xid && nx.next_xid < UINT64_MAX && nx.next_oid < UINT64_MAX - 65536,
        "VolumeImageIdentityOrGeometryMismatch");
    const auto selected = std::find_if(cp->volumes.begin(), cp->volumes.end(), [&](const auto& v) {
        return v.superblock.object_id == r.volume_oid && v.superblock.uuid_hex == r.volume_uuid; });
    Require(selected != cp->volumes.end(), "VolumeImageVolumeIdentityMismatch");
    for (const auto& v : cp->volumes) Require(CheckAppleVolumeWriteFeatures(nx, v.superblock, e), e);
    const auto& raw = cp->container.superblock_bytes;
    Require(ReadU64LE(raw, 0x4e0) == 0 && ReadU64LE(raw, 0x4e8) == 0, "VolumeImageAppleRelocationPending");
    Require(ReadU64LE(raw, 0x4f8) == 0 && ReadU64LE(raw, 0x518) == 0 && ReadU64LE(raw, 0x578) == 0 &&
        ReadU64LE(raw, 0x540) == 0 && ReadU32LE(raw, 0xb0) == 0, "VolumeImageAuxiliaryOwnershipUnproven");
    Require((ReadU64LE(raw, 0x4f0).value_or(UINT64_MAX) & ~3ull) == 0, "VolumeImageContainerFlagsUnsupported");
    VerifySource(source, *cp);
    // These operations cannot transfer ownership of an in-progress reaper.
    if (nx.reaper_oid) {
        const auto m = std::find_if(cp->container.mappings.begin(), cp->container.mappings.end(),
            [&](const auto& x) { return x.object_id == nx.reaper_oid; });
        Require(m != cp->container.mappings.end() && m->size_bytes == Block, "VolumeImageReaperUnproven");
        Bytes reaper; Require(source.Read(m->physical_block * Block, Block, reaper), "VolumeImageReaperUnreadable");
        Require(ReadU64LE(reaper, 0x30) == 0 && ReadU64LE(reaper, 0x38) == 0 && ReadU32LE(reaper, 0x40) == 1 &&
            ReadU32LE(reaper, 0x44) == 0 && ReadU64LE(reaper, 0x50) == 0 && ReadU64LE(reaper, 0x58) == 0 &&
            ReadU32LE(reaper, 0x68) == 0 && ReadU32LE(reaper, 0x6c) == 0, "VolumeImageReaperWorkPending");
    }
    return *cp;
}
void FinishFormatSource(const catalog::RandomAccessSource& source, const VolumeImageRequest& r, Plan& p)
{
    const auto admission = r.operation == VolumeImageOperation::Erase ? ImageAdmission::StreamedErase : ImageAdmission::StreamedFormat;
    ValidateRequest(r, admission);
    Require(p.cleanup.empty() && p.postimage.empty() && p.destinations.empty(), "VolumeFormatStreamedPlanStateInvalid");
    const auto before = AdmitSource(source, r, admission);
    Require(before.container.superblock_bytes == p.before.container.superblock_bytes &&
        p.publication.transaction_xid == before.container.superblock.next_xid,
        "VolumeFormatStreamedPreimageMismatch");
    FormatOverlay staged(source);
    const auto add = [&](const auto& write) {
        staged.Add({write.physical_block, write.bytes});
        Require(p.destinations.insert(write.physical_block).second, "VolumeFormatOverlayOverlap");
    };
    for (const auto& write : p.publication.before_superblock_writes) add(write);
    add(p.publication.superblock_write);
    std::string error;
    const auto old = LoadAppleCheckpointView(staged, 0, staged.SizeBytes(), error);
    Require(old && old->container.superblock_bytes == before.container.superblock_bytes,
        "VolumeFormatStreamedOldCheckpointLost:" + error);
    VerifySource(staged, *old);
    add(AppleCheckpointPhysicalWrite{0, p.anchor});
    const auto after = LoadAppleCheckpointView(staged, 0, staged.SizeBytes(), error);
    Require(after.has_value(), "VolumeFormatStreamedNewCheckpointInvalid:" + error);
    VerifySource(staged, *after);
    Require(after->container.superblock.xid == p.publication.transaction_xid &&
        after->container.superblock.block_count * Block == r.target_bytes && after->volumes.size() == 1 &&
        after->container.superblock.uuid_hex == r.new_container_uuid &&
        after->volumes.front().superblock.uuid_hex == r.new_volume_uuid &&
        after->volumes.front().superblock.object_id == 1024, "VolumeFormatStreamedPostIdentityMismatch");
    p.after = *after;
}
void FinishPlan(const Bytes& original, const VolumeImageRequest& r, Plan& p)
{
    // Prove an intact old checkpoint after all staging and the descriptor write,
    // while block zero still selects the original UUID/geometry.
    Bytes staged = original; staged.resize((std::max)(r.expected_bytes, r.target_bytes));
    const auto apply = [&](const auto& w, bool exclusive) {
        Require(w.bytes.size() == Block && w.physical_block < staged.size() / Block, "VolumeImageWriteBounds");
        if (exclusive) Require(p.destinations.insert(w.physical_block).second, "VolumeImageWriteOverlap");
        std::copy(w.bytes.begin(), w.bytes.end(), staged.begin() + w.physical_block * Block);
    };
    for (const auto& w : p.publication.before_superblock_writes) apply(w, true);
    apply(p.publication.superblock_write, true);
    VectorRandomAccessSource old_source(staged); std::string e;
    auto old = LoadAppleCheckpointView(old_source, 0, staged.size(), e);
    Require(old && old->container.superblock_bytes == p.before.container.superblock_bytes, "VolumeImageOldCheckpointLostBeforeAnchor:" + e);
    Verify(staged, *old);
    Require(p.anchor.size() == Block && p.destinations.insert(0).second, "VolumeImageAnchorInvalid");
    std::copy(p.anchor.begin(), p.anchor.end(), staged.begin());
    for (const auto& w : p.cleanup) apply(w, true);
    staged.resize(r.target_bytes);
    for (auto b = r.expected_bytes / Block; b < r.target_bytes / Block; ++b) p.destinations.insert(b);
    VectorRandomAccessSource after_source(staged);
    auto after = LoadAppleCheckpointView(after_source, 0, staged.size(), e);
    Require(after.has_value(), "VolumeImageNewCheckpointInvalid:" + e); Verify(staged, *after);
    Require(after->container.superblock.block_count * Block == r.target_bytes &&
        after->container.superblock.xid == p.publication.transaction_xid, "VolumeImageNewCapacityMismatch");
    p.after = *after; p.postimage = std::move(staged);
}
namespace
{
constexpr std::size_t ResizeZoneBase = 0x158, ResizeZoneEnd = 0x9d8;

bool CanonicalResizeZoneReset(const AppleSpacemanView& sm, std::uint64_t target)
{
    constexpr std::uint64_t Chunk = 32768, Minimum = 1ull << 21, Maximum = 1ull << 22;
    const auto old = sm.devices[0].block_count;
    if (sm.bytes.size() < ResizeZoneEnd || target >= old || target < Minimum || old >= Maximum ||
        target % Chunk == 0 || old % Chunk == 0) return false;
    const auto chunks = (old + Chunk - 1) / Chunk;
    if ((target + Chunk - 1) / Chunk != chunks ||
        std::all_of(sm.bytes.begin() + ResizeZoneBase, sm.bytes.begin() + ResizeZoneEnd,
            [](auto b) { return b == std::byte{}; })) return false;
    Require(sm.flags == 1 && sm.version == 1 && sm.structure_size == ResizeZoneEnd &&
        ReadU32LE(sm.bytes, 0x20) == Block && sm.blocks_per_chunk == Chunk &&
        sm.chunks_per_cib == (Block - 0x28) / 0x20 && sm.cibs_per_cab == (Block - 0x28) / 8 && sm.object.size_bytes == Block &&
        sm.devices[0].chunk_count == chunks && sm.chunks.size() == chunks && sm.devices[0].cabs.empty() &&
        sm.devices[0].cibs.size() == (chunks + sm.chunks_per_cib - 1) / sm.chunks_per_cib && sm.devices[1].block_count == 0 &&
        sm.devices[1].chunk_count == 0 && sm.devices[1].cib_count == 0 && sm.devices[1].cab_count == 0 &&
        sm.devices[1].free_count == 0, "VolumeResizeZoneResetGeometryUnsupported");
    std::set<std::uint64_t> represented;
    for (std::size_t slot = 0; slot < 16; ++slot) {
        const auto at = ResizeZoneBase + slot * 0x88;
        if (slot >= 4) {
            Require(std::all_of(sm.bytes.begin() + at, sm.bytes.begin() + at + 0x88,
                [](auto b) { return b == std::byte{}; }), "VolumeResizeZoneResetUnusedRecordUnsupported");
            continue;
        }
        Require(ReadU16LE(sm.bytes, at + 0x80) == slot + 1 &&
            ReadU16LE(sm.bytes, at + 0x82).value() <= 6 && ReadU32LE(sm.bytes, at + 0x84) == 0,
            "VolumeResizeZoneResetHeaderUnsupported");
        for (std::size_t pair = 0; pair < 8; ++pair) {
            const auto start = ReadU64LE(sm.bytes, at + pair * 16).value();
            const auto end = ReadU64LE(sm.bytes, at + pair * 16 + 8).value();
            const auto chunk = start / Chunk;
            Require(start % Chunk == 0 && chunk >= 4 && chunk < chunks - 1 &&
                end == start + Chunk && end <= target && represented.insert(chunk).second,
                "VolumeResizeZoneResetBoundaryUnsupported");
        }
    }
    return true;
}
}

void FinishResizeSource(const RandomAccessSource& source, const VolumeImageRequest& r, Plan& p)
{
    const auto before = AdmitSource(source, r, ImageAdmission::StreamedResize);
    ValidateResizeAllocationZones(before.spaceman, r.target_bytes / Block);
    Require(before.container.superblock_bytes == p.before.container.superblock_bytes && p.cleanup.empty() && p.postimage.empty() &&
        p.destinations.empty() && p.publication.transaction_xid == before.container.superblock.next_xid,
        "VolumeResizeStreamedPreimageMismatch");
    FormatOverlay staged(source, (std::max)(r.expected_bytes, r.target_bytes));
    const auto add = [&](const auto& w) {
        Require(w.physical_block < r.target_bytes / Block && p.destinations.insert(w.physical_block).second,
            "VolumeResizeStreamedDestinationBounds"); staged.Add({w.physical_block, w.bytes});
    };
    for (const auto& w : p.publication.before_superblock_writes) add(w);
    add(p.publication.superblock_write);
    std::string error; const auto old = LoadAppleCheckpointView(staged, 0, staged.SizeBytes(), error);
    Require(old && old->container.superblock_bytes == before.container.superblock_bytes, "VolumeResizeStreamedOldCheckpointLost:" + error);
    VerifySource(staged, *old); add(AppleCheckpointPhysicalWrite{0, p.anchor}); staged.SetSize(r.target_bytes);
    const auto after = LoadAppleCheckpointView(staged, 0, staged.SizeBytes(), error);
    Require(after && after->container.superblock.uuid_hex == r.container_uuid &&
        after->container.superblock.xid == p.publication.transaction_xid &&
        after->container.superblock.block_count * Block == r.target_bytes && after->volumes.size() == before.volumes.size(),
        "VolumeResizeStreamedPostIdentityMismatch:" + error);
    VerifySource(staged, *after);
    Require(after->spaceman.bytes.size() >= ResizeZoneEnd, "VolumeResizeAllocationZonePolicyChanged");
    if (CanonicalResizeZoneReset(before.spaceman, r.target_bytes / Block))
        Require(std::all_of(after->spaceman.bytes.begin() + ResizeZoneBase,
            after->spaceman.bytes.begin() + ResizeZoneEnd, [](auto b) { return b == std::byte{}; }),
            "VolumeResizeAllocationZoneResetMissing");
    else Require(std::equal(before.spaceman.bytes.begin() + ResizeZoneBase,
        before.spaceman.bytes.begin() + ResizeZoneEnd, after->spaceman.bytes.begin() + ResizeZoneBase),
        "VolumeResizeAllocationZonePolicyChanged");
    p.after = *after;
}
void ValidateResizeAllocationZones(const AppleSpacemanView& sm, std::uint64_t target_blocks)
{
    constexpr std::size_t ZoneBase = 0x158, ZoneBytes = 136, ZonesPerDevice = 8;
    constexpr std::size_t ZoneEnd = ZoneBase + 2 * ZonesPerDevice * ZoneBytes;
    Require(sm.flags == 1 && sm.version == 1 && sm.structure_size >= ZoneEnd && sm.bytes.size() >= ZoneEnd &&
        sm.devices[0].address_offset >= ZoneEnd && ReadU32LE(sm.bytes, 0x144).value_or(0) >= ZoneEnd &&
        ReadU32LE(sm.bytes, 0x148).value_or(0) >= ZoneEnd && ReadU32LE(sm.bytes, 0x14c).value_or(0) >= ZoneEnd,
        "VolumeResizeSpacemanZoneLayoutUnproven");
    if (CanonicalResizeZoneReset(sm, target_blocks)) return;
    std::vector<std::pair<std::uint64_t, std::uint64_t>> current;
    std::set<std::uint16_t> ids;
    bool populated = false;
    for (std::size_t device = 0; device < 2; ++device) {
        current.clear(); ids.clear();
        for (std::size_t zone = 0; zone < ZonesPerDevice; ++zone) {
            const auto at = ZoneBase + (device * ZonesPerDevice + zone) * ZoneBytes;
            if (device) {
                Require(std::all_of(sm.bytes.begin() + at, sm.bytes.begin() + at + ZoneBytes,
                    [](auto b) { return b == std::byte{}; }), "VolumeResizeTier2AllocationZoneUnsupported");
                continue;
            }
            const auto id = ReadU16LE(sm.bytes, at + 128).value();
            const auto previous = ReadU16LE(sm.bytes, at + 130).value();
            Require(ReadU32LE(sm.bytes, at + 132) == 0 && previous <= 6,
                "VolumeResizeAllocationZoneHeaderProfileUnsupported");
            const bool history = std::any_of(sm.bytes.begin() + at + 16, sm.bytes.begin() + at + 128,
                [](auto b) { return b != std::byte{}; });
            Require(history || previous == 0, "VolumeResizeAllocationZoneHistoryProfileUnsupported");
            for (std::size_t boundary = 0; boundary < 8; ++boundary) {
                const auto start = ReadU64LE(sm.bytes, at + boundary * 16).value();
                const auto end = ReadU64LE(sm.bytes, at + boundary * 16 + 8).value();
                const bool empty = !start && !end;
                if (!boundary) Require(id ? !empty : empty, "VolumeResizeAllocationZoneIdentityProfileUnsupported");
                if (empty) continue;
                populated = true;
                // This is a restricted preserved-policy profile, not an APFS
                // unit definition. Treat endpoints as inclusive for these bounds.
                Require(start < end && !(start % Block) && !(end % Block) &&
                    end < sm.devices[0].block_count && end < target_blocks,
                    "VolumeResizeAllocationZoneBoundsUnproven");
                if (!boundary) {
                    Require(ids.insert(id).second && std::none_of(current.begin(), current.end(),
                        [&](const auto& other) { return start <= other.second && other.first <= end; }),
                        "VolumeResizeAllocationZoneOverlap");
                    current.emplace_back(start, end);
                }
            }
        }
    }
    // Apple's public reference does not define the boundary address units.
    // Preserve populated policy only when no original address space is removed.
    Require(!populated || target_blocks >= sm.devices[0].block_count,
        "VolumeResizeAllocationZoneShrinkUnitsUnproven");
}
Plan BuildResizePublication(const RandomAccessSource& source, const VolumeImageRequest& r, const AppleCheckpointView& checkpoint)
{
    Require(!IsFormat(r.operation), "VolumeResizeOperationMismatch"); Plan p; p.before = checkpoint;
    auto& cp = p.before; const auto& nx = cp.container.superblock; const auto& sm = cp.spaceman;
    const auto count = r.target_bytes / Block;
    ValidateResizeAllocationZones(sm, count);
    const bool reset_zones = CanonicalResizeZoneReset(sm, count);
    const auto chunks = (count + sm.blocks_per_chunk - 1) / sm.blocks_per_chunk;
    Require(!sm.chunks.empty() && sm.chunks.front().start_block == 0 && !sm.devices[0].cibs.empty() && sm.devices[0].cabs.empty() &&
        (chunks + sm.chunks_per_cib - 1) / sm.chunks_per_cib <= (Block - 0xa00 - 128) / 8 && count > 0,
        "VolumeResizeChunkTopologyChangeRequired");
    std::string e;
    AppleSnapshotRetentionView snapshots;
    Require(LoadAppleSnapshotRetention(source, cp, snapshots, e), e);
    Require(snapshots.identities.empty() && !cp.container_object_map.snapshot_tree_oid,
        "VolumeImageSnapshotHistoryAuthorityUnproven");
    const auto fit = [&](const AppleCheckpointView& view) {
        const auto& n = view.container.superblock;
        Require(n.xp_desc_base_block + n.xp_desc_block_count <= count && n.xp_data_base_block + n.xp_data_block_count <= count &&
            view.spaceman.internal_pool.base_block + view.spaceman.internal_pool.block_count <= count &&
            view.spaceman.internal_pool.bitmap_base_block + view.spaceman.internal_pool.bitmap_block_count <= count,
            "VolumeResizeReservedRegionWouldBeTruncated");
        for (const auto& c : view.spaceman.chunks) for (std::uint64_t i = 0; i < c.block_count; ++i)
            Require(c.start_block + i < count || !Bit(c.allocation_bitmap, i), "VolumeResizeAllocatedTailRequiresRelocation");
        for (const auto& q : view.spaceman.free_queues) for (const auto& entry : q.entries)
            Require(entry.physical_block < count && entry.block_count <= count - entry.physical_block, "VolumeResizeRetiredTailPinned");
    };
    if (r.operation == VolumeImageOperation::Shrink) {
        fit(cp);
        for (const auto b : snapshots.metadata_blocks) Require(b < count, "VolumeResizeSnapshotMetadataTail");
        for (const auto& x : snapshots.payload_extents)
            Require(x.physical_block < count && x.block_count <= count - x.physical_block, "VolumeResizeSnapshotPayloadTail");
    }
    // Current owners include the complete live/sibling/historical graph. The
    // recovery loader below returns only explicitly requested older XIDs.
    std::vector<std::uint64_t> current_metadata;
    std::vector<ApplePhysicalExtentRecord> current_payload;
    Require(LoadAppleSnapshotCheckpointOwners(source, cp, current_metadata, current_payload, e), e);
    Require(!current_metadata.empty(), "VolumeResizeCurrentOwnerCensusEmpty");
    if (r.operation == VolumeImageOperation::Shrink) {
        for (const auto block : current_metadata) Require(block < count, "VolumeResizeCurrentMetadataTail");
        for (const auto& x : current_payload)
            Require(x.physical_block < count && x.block_count <= count - x.physical_block, "VolumeResizeCurrentPayloadTail");
    }
    // CLEAN WAL authority does not promote obsolete descriptor headers to live
    // recovery pins. Embedded keeper originals reopen with their own geometry.
    const std::vector<std::uint64_t> pins{nx.xid};
    std::vector<AppleRecoveryCheckpointView> retained;
    Require(LoadAppleSnapshotRecoveryCheckpoints(source, cp, pins, retained, e), e);
    if (r.operation == VolumeImageOperation::Shrink) for (const auto& old : retained) {
        fit(old.checkpoint);
        for (auto b : old.metadata_blocks) Require(b < count, "VolumeResizeRetainedMetadataTail");
        for (const auto& x : old.payload_extents)
            Require(x.physical_block < count && x.block_count <= count - x.physical_block, "VolumeResizeRetainedPayloadTail");
    }
    AppleSpacemanAllocationRequest request; request.expected_checkpoint_xid = nx.xid; request.transaction_xid = nx.next_xid;
    request.oldest_required_checkpoint_xid = 1; request.main_block_count = 1; request.first_ephemeral_object_id = nx.next_oid;
    for (const auto& b : sm.internal_pool.active_bitmaps) request.protected_internal_pool_bitmap_indices.push_back(b.rotation_index);
    for (const auto& old : retained) for (const auto& b : old.checkpoint.spaceman.internal_pool.active_bitmaps)
        request.protected_internal_pool_bitmap_indices.push_back(b.rotation_index);
    auto& protected_rotations = request.protected_internal_pool_bitmap_indices;
    std::sort(protected_rotations.begin(), protected_rotations.end());
    protected_rotations.erase(std::unique(protected_rotations.begin(), protected_rotations.end()), protected_rotations.end());
    AppleSpacemanAllocationPlan allocation; Require(PlanAppleSpacemanAllocation(sm, request, allocation, e), e);
    const auto omap_block = allocation.allocated_main_blocks.at(0); Require(omap_block < count, "VolumeResizeStagingNeedsRelocation");
    PrepareGeometryCibs(sm, count, retained, allocation);
    PrepareGeometryBitmaps(sm, count, retained, allocation);
    Bytes old_omap, new_omap; Require(source.Read(cp.container_object_map.object.physical_block * Block, Block, old_omap), "VolumeResizeOmapRead");
    Require(PatchAppleObjectMap(old_omap, omap_block, nx.next_xid, cp.container_object_map.tree.physical_block, new_omap, e), e);
    AppleTransactionCommitRequest commit; commit.allocation_plan = allocation; commit.next_object_id = nx.next_oid;
    commit.container_object_map_oid = omap_block; commit.required_checkpoint_xids = pins;
    commit.allocated_main_writes.push_back({omap_block, new_omap});
    // Container-only publication has no replacement APSB or volume retirement.
    // Snapshot absence is proved above; retain the complete owner census below.
    AppleTransactionCommitPlan composed; Require(PlanAppleTransactionCommit(source, cp, commit, composed, e), e);
    p.publication = std::move(composed.publication);
    const auto& updated = allocation.updated_spaceman;
    auto resized = updated.chunks; resized.resize(static_cast<std::size_t>(chunks));
    std::uint64_t total_free = 0;
    for (std::size_t i = 0; i < resized.size(); ++i) {
        auto& chunk = resized[i]; const auto start = i * static_cast<std::uint64_t>(sm.blocks_per_chunk);
        const auto blocks = (std::min<std::uint64_t>)(sm.blocks_per_chunk, count - start);
        if (i >= updated.chunks.size()) {
            chunk.start_block = start; chunk.xid = nx.next_xid; chunk.device_index = 0;
            chunk.cib_index = i / sm.chunks_per_cib; chunk.index_in_cib = i % sm.chunks_per_cib;
            chunk.block_count = chunk.free_count = static_cast<std::uint32_t>(blocks);
        } else if (chunk.block_count != blocks) {
            const auto delta = static_cast<std::int64_t>(blocks) - chunk.block_count;
            const auto free = static_cast<std::int64_t>(chunk.free_count) + delta;
            Require(free >= 0 && free <= static_cast<std::int64_t>(blocks), "VolumeResizeChunkFreeCountInvalid");
            if (chunk.bitmap_block) {
                for (auto n = (std::min<std::uint64_t>)(chunk.block_count, blocks); n < (std::max<std::uint64_t>)(chunk.block_count, blocks); ++n)
                    SetBit(chunk.allocation_bitmap, n, delta < 0);
            }
            chunk.block_count = static_cast<std::uint32_t>(blocks); chunk.free_count = static_cast<std::uint32_t>(free); chunk.xid = nx.next_xid;
        }
        total_free += chunk.free_count;
    }
    std::map<std::uint64_t, Bytes> cibs;
    for (const auto& c : updated.devices[0].cibs) {
        auto bytes = c.bytes;
        const auto begin = c.index * static_cast<std::uint64_t>(sm.chunks_per_cib);
        if (begin >= chunks) continue;
        const auto entries = (std::min<std::uint64_t>)(sm.chunks_per_cib, chunks - begin);
        const auto clear = (std::max<std::uint64_t>)(entries, ReadU32LE(bytes, 0x24).value_or(sm.chunks_per_cib));
        Require(clear <= sm.chunks_per_cib && 0x28 + clear * 0x20 <= bytes.size(), "VolumeResizeCibEntryBounds");
        Put(bytes, 0x24, entries, 4);
        std::fill(bytes.begin() + 0x28, bytes.begin() + 0x28 + clear * 0x20, std::byte{});
        cibs.emplace(c.object.physical_block, std::move(bytes));
    }
    for (std::size_t i = 0; i < resized.size(); ++i) {
        const auto& c = resized[i]; auto& cib_bytes = cibs.at(updated.devices[0].cibs.at(c.cib_index).object.physical_block);
        const auto at = 0x28 + c.index_in_cib * 0x20;
        Put(cib_bytes, at, c.xid); Put(cib_bytes, at + 8, c.start_block); Put(cib_bytes, at + 0x10, c.block_count, 4);
        Put(cib_bytes, at + 0x14, c.free_count, 4); Put(cib_bytes, at + 0x18, c.bitmap_block);
    }
    for (auto& [physical, bytes] : cibs) { (void)physical; Checksum(bytes); }
    bool spaceman = false; std::set<std::uint64_t> written_cibs, bitmaps;
    for (auto& w : p.publication.before_superblock_writes) {
        Require(w.physical_block < count, "VolumeResizePublicationOutsideTarget");
        const auto chunk = std::find_if(resized.begin(), resized.end(), [&](const auto& c) { return c.bitmap_block == w.physical_block; });
        if (chunk != resized.end()) {
            w.bytes = chunk->allocation_bitmap; bitmaps.insert(w.physical_block);
        } else if (const auto cib = cibs.find(w.physical_block); cib != cibs.end()) {
            w.bytes = cib->second; written_cibs.insert(w.physical_block);
        } else if (w.object_id == sm.object.object_id) {
            Put(w.bytes, 0x30, count); Put(w.bytes, 0x38, chunks); Put(w.bytes, 0x48, total_free); Put(w.bytes, 0x40, cibs.size(), 4);
            GeometryAddressTable(w.bytes, updated, cibs.size());
            // Only physical placement hints are reset; allocator ownership stays in the ordinary plan.
            if (reset_zones) std::fill(w.bytes.begin() + ResizeZoneBase,
                w.bytes.begin() + ResizeZoneEnd, std::byte{});
            Checksum(w.bytes); spaceman = true;
        }
    }
    for (std::size_t i = 0; i < resized.size() && i < sm.chunks.size(); ++i)
        if (resized[i].bitmap_block && resized[i].block_count != sm.chunks[i].block_count)
            Require(bitmaps.contains(resized[i].bitmap_block), "VolumeResizeGeometryBitmapWriteMissing");
    for (const auto& [physical, bytes] : cibs) {
        const auto old = std::find_if(sm.devices[0].cibs.begin(), sm.devices[0].cibs.end(), [&](const auto& c) { return c.object.physical_block == physical; });
        Require(written_cibs.contains(physical) || (old != sm.devices[0].cibs.end() && old->bytes == bytes), "VolumeResizeGeometryCibNotCopied");
    }
    Require(!written_cibs.empty() && spaceman, "VolumeResizeGeometryWritesMissing");
    Put(p.publication.superblock_write.bytes, 0x28, count);
    Put(p.publication.superblock_write.bytes, 0x4f0, ReadU64LE(p.publication.superblock_write.bytes, 0x4f0).value() & ~2ull);
    Checksum(p.publication.superblock_write.bytes);
    p.publication.published_checkpoint.superblock_bytes = p.publication.superblock_write.bytes;
    p.publication.published_checkpoint.superblock = *ParseNxSuperblock(p.publication.superblock_write.bytes);
    p.anchor = p.publication.superblock_write.bytes;
    for (std::size_t at = 0x80; at <= 0x94; at += 4) Put(p.anchor, at, 0, 4);
    Checksum(p.anchor);
    FinishResizeSource(source, r, p);
    std::set<std::uint64_t> guarded;
    for (const auto& guard : p.publication.guard_blocks) guarded.insert(guard.physical_block);
    const auto preserved = [&](std::uint64_t block, std::uint64_t blocks) {
        Require(block < source.SizeBytes() / Block && blocks <= source.SizeBytes() / Block - block &&
            block < r.target_bytes / Block && blocks <= r.target_bytes / Block - block,
            "VolumeResizeRetainedOwnerBounds");
        const auto destination = p.destinations.lower_bound(block);
        Require(destination == p.destinations.end() || *destination - block >= blocks, "VolumeResizeRetainedOwnerChanged");
    };
    const auto guard = [&](std::uint64_t block) {
        if (guarded.insert(block).second) {
            Require((r.expected_bytes <= Limit && r.target_bytes <= Limit) || p.publication.guard_blocks.size() < 4096,
                "VolumeResizeGuardCapacityExceeded");
            Bytes bytes; Require(source.Read(block * Block, Block, bytes), "VolumeResizeRetainedGuardUnreadable");
            p.publication.guard_blocks.push_back({block, std::move(bytes)});
        }
    };
    const auto protect = [&](const auto& metadata, const auto& payload) {
        for (const auto block : metadata) if (block) {
            preserved(block, 1);
            guard(block);
        }
        for (const auto& extent : payload) {
            preserved(extent.physical_block, extent.block_count);
        }
    };
    protect(current_metadata, current_payload);
    for (const auto& old : retained) protect(old.metadata_blocks, old.payload_extents);
    ApfsSharedSpaceProjection space; Require(TryProjectAppleSharedSpace(p.after, space, e), e);
    std::uint64_t promised = 0;
    for (const auto& v : p.after.volumes) {
        const auto& s = v.superblock.space;
        const auto unmet = s.reserve_block_count > s.allocated_block_count ? s.reserve_block_count - s.allocated_block_count : 0;
        Require(unmet <= space.free.blocks && promised <= space.free.blocks - unmet, "VolumeResizeReserveCapacity"); promised += unmet;
    }
    return p;
}
Plan PlanResize(const Bytes& original, const VolumeImageRequest& r, const CleanImageHistoryAuthority* authority)
{
    Require(authority != nullptr, "VolumeImageRetentionAuthorityRequired");
    const auto before = Admit(original, r); authority->RequireFor(original, r, before);
    const auto chunks = (r.target_bytes / Block + before.spaceman.blocks_per_chunk - 1) / before.spaceman.blocks_per_chunk;
    Require(before.spaceman.chunks.size() <= 2 && chunks <= 2 && before.spaceman.devices[0].cibs.size() == 1,
        "VolumeResizeChunkTopologyChangeRequired");
    VectorRandomAccessSource source(original); auto p = BuildResizePublication(source, r, before);
    p.destinations.clear(); FinishPlan(original, r, p);
    // Preserve the original bounded publisher's payload guard contract.
    std::vector<std::uint64_t> metadata; std::vector<ApplePhysicalExtentRecord> payload; std::string error;
    Require(LoadAppleSnapshotCheckpointOwners(source, before, metadata, payload, error), error);
    std::set<std::uint64_t> guarded; for (const auto& g : p.publication.guard_blocks) guarded.insert(g.physical_block);
    for (const auto& extent : payload) for (std::uint64_t i = 0; i < extent.block_count; ++i) {
        const auto block = extent.physical_block + i;
        if (guarded.insert(block).second) { Bytes bytes; Require(source.Read(block * Block, Block, bytes), "VolumeResizeRetainedGuardUnreadable");
            p.publication.guard_blocks.push_back({block, std::move(bytes)}); }
    }
    return p;
}
}
namespace apfsaccess::rw
{
VolumeImageResult PrepareVolumeResize(const VolumeImageRequest& r) { return volume_image::Prepare(r, false); }
VolumeImageResult ApplyVolumeResize(const VolumeImageRequest& r, std::string_view t, const AppleCheckpointStageHook& h)
{ return volume_image::Run(r, t, false, false, false, h); }
VolumeImageResult RecoverVolumeResize(const VolumeImageRequest& r, const AppleCheckpointStageHook& h)
{ return volume_image::Run(r, {}, false, true, false, h); }
VolumeImageResult CancelVolumeResize(const VolumeImageRequest& r, std::string_view t)
{ return volume_image::Run(r, t, false, false, true, {}); }
}
