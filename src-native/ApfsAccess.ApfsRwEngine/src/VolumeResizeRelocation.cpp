#include "VolumeResizeRelocation.h"
#include <algorithm>
#include <map>

namespace apfsaccess::rw::volume_image
{
ResizeRelocationInventory InspectResizeRelocationSource(const catalog::RandomAccessSource& source,
    const VolumeImageRequest& request)
{
    Require(request.operation == VolumeImageOperation::Shrink, "VolumeResizeRelocationRequiresShrink");
    const auto checkpoint = AdmitSource(source, request, ImageAdmission::StreamedResize);
    const auto& nx = checkpoint.container.superblock; const auto& sm = checkpoint.spaceman;
    Require(!nx.xp_desc_noncontiguous && !nx.xp_data_noncontiguous && sm.devices.size() == 2 &&
        sm.devices[0].block_count == nx.block_count && sm.devices[1].block_count == 0,
        "VolumeResizeRelocationSingleStoreRequired");
    std::string error; AppleSnapshotRetentionView snapshots;
    Require(LoadAppleSnapshotRetention(source, checkpoint, snapshots, error), error);
    Require(snapshots.identities.empty() && !checkpoint.container_object_map.snapshot_tree_oid,
        "VolumeImageSnapshotHistoryAuthorityUnproven");
    constexpr std::size_t MaximumBlocks = 4096;
    const auto boundary = request.target_bytes / Block;
    std::map<std::uint64_t, std::uint32_t> tail;
    for (const auto& chunk : sm.chunks) {
        Require(chunk.device_index == 0 && chunk.start_block <= nx.block_count &&
            chunk.block_count <= nx.block_count - chunk.start_block, "VolumeResizeRelocationChunkBounds");
        const auto end = chunk.start_block + chunk.block_count;
        if (end <= boundary) continue;
        if (!chunk.bitmap_block) { Require(chunk.free_count == chunk.block_count,
            "VolumeResizeRelocationUnknownChunkAllocation"); continue; }
        Require(chunk.allocation_bitmap.size() == Block, "VolumeResizeRelocationBitmapUnreadable");
        for (auto block = (std::max)(boundary, chunk.start_block); block < end; ++block) if (Bit(chunk.allocation_bitmap, block - chunk.start_block)) {
            Require(tail.size() < MaximumBlocks, "VolumeResizeRelocationBlockQuotaExceeded");
            Require(tail.emplace(block, 0).second, "VolumeResizeRelocationOverlappingChunks");
        }
    }
    ResizeRelocationInventory result;
    for (const auto& volume : checkpoint.volumes)
        if (volume.snapshot_metadata_tree &&
            volume.snapshot_metadata_tree->type == (catalog::kObjectPhysical | catalog::kObjectTypeBtree) &&
            volume.snapshot_metadata_tree->physical_block >= boundary)
            result.physical_snapshot_root_in_tail = true;
    const auto mark = [&](std::uint64_t start, std::uint64_t count, ResizeTailRole role, bool reserved = false) {
        Require(start <= nx.block_count && count <= nx.block_count - start, "VolumeResizeRelocationOwnerBounds");
        const auto end = start + count;
        if (!count || end <= boundary) return;
        if (reserved) result.reserved_region_crosses_target = true;
        Require(end - (std::max)(start, boundary) <= MaximumBlocks, "VolumeResizeRelocationBlockQuotaExceeded");
        for (auto block = (std::max)(start, boundary); block < end; ++block) {
            const auto found = tail.find(block);
            Require(found != tail.end(), "VolumeResizeRelocationRequiredTailUnallocated");
            found->second |= static_cast<std::uint32_t>(role);
        }
    };
    mark(nx.xp_desc_base_block, nx.xp_desc_block_count, ResizeTailRole::Descriptor, true);
    mark(nx.xp_data_base_block, nx.xp_data_block_count, ResizeTailRole::CheckpointData, true);
    mark(sm.internal_pool.bitmap_base_block, sm.internal_pool.bitmap_block_count, ResizeTailRole::InternalPoolBitmap, true);
    mark(sm.internal_pool.base_block, sm.internal_pool.block_count, ResizeTailRole::InternalPool, true);
    std::vector<std::uint64_t> metadata; std::vector<ApplePhysicalExtentRecord> payload;
    const auto owners_loaded = LoadAppleSnapshotCheckpointOwners(source, checkpoint, metadata, payload, error);
    Require(owners_loaded && !metadata.empty(), "VolumeResizeRelocationOwnerGraphIncomplete:" + error);
    for (const auto block : metadata) mark(block, 1, ResizeTailRole::Metadata);
    for (const auto& extent : payload) mark(extent.physical_block, extent.block_count, ResizeTailRole::Payload);
    for (const auto& queue : sm.free_queues) for (const auto& entry : queue.entries)
        mark(entry.physical_block, entry.block_count, ResizeTailRole::Queued);
    result.blocks.reserve(tail.size());
    for (const auto& [block, roles] : tail) {
        Require(!(roles & static_cast<std::uint32_t>(ResizeTailRole::Payload)) ||
            !(roles & (static_cast<std::uint32_t>(ResizeTailRole::Metadata) |
                static_cast<std::uint32_t>(ResizeTailRole::Descriptor) | static_cast<std::uint32_t>(ResizeTailRole::CheckpointData) |
                static_cast<std::uint32_t>(ResizeTailRole::InternalPoolBitmap) | static_cast<std::uint32_t>(ResizeTailRole::InternalPool))),
            "VolumeResizeRelocationMetadataPayloadOverlap");
        Bytes bytes; Require(source.Read(block * Block, Block, bytes) && bytes.size() == Block,
            "VolumeResizeRelocationOriginalUnreadable");
        ResizeTailBlock item; item.physical_block = block; item.roles = roles;
        if (!roles) { item.roles = static_cast<std::uint32_t>(ResizeTailRole::Unknown); ++result.unknown_blocks; }
        item.original_sha256 = format_evidence::Hash(bytes); result.blocks.push_back(std::move(item));
    }
    return result;
}
}
