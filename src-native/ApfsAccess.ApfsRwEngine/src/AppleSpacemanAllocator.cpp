#include "AppleSpacemanAllocator.h"
#include "ApfsFusionAllocationPlan.h"
#include "ApfsFusionSpaceman.h"
#include "FusionPlanningParser.h"
#include "FusionReclamationProof.h"

#include "ApfsTransactionWriter.h"

#include <algorithm>
#include <array>
#include <iterator>
#include <limits>
#include <set>
#include <tuple>

namespace apfsaccess::rw
{
namespace
{

constexpr std::uint16_t kInvalidBitmapIndex = 0xFFFF;

bool Fail(std::string& out_error, const char* error)
{
    out_error = error;
    return false;
}

bool ResolveRetentionContext(const catalog::AppleSpacemanView& view,
    const AppleSpacemanAllocationRequest& request,
    std::uint64_t& out_oldest_required_checkpoint_xid,
    std::vector<std::uint16_t>& out_protected_bitmap_indices,
    std::string& out_error)
{
    out_oldest_required_checkpoint_xid =
        request.oldest_required_checkpoint_xid == 0
        ? request.expected_checkpoint_xid
        : request.oldest_required_checkpoint_xid;
    if (out_oldest_required_checkpoint_xid > request.expected_checkpoint_xid)
    {
        return Fail(out_error, "AppleSpacemanRetentionFloorInvalid");
    }

    out_protected_bitmap_indices =
        request.protected_internal_pool_bitmap_indices;
    const auto index_is_valid = [&view](std::uint16_t index) {
        return index != kInvalidBitmapIndex &&
            index < view.internal_pool.bitmap_block_count &&
            index < view.internal_pool.bitmap_free_next.size();
    };
    if (!std::all_of(out_protected_bitmap_indices.begin(),
            out_protected_bitmap_indices.end(), index_is_valid))
    {
        return Fail(out_error, "AppleSpacemanProtectedBitmapIndexInvalid");
    }
    for (const auto& bitmap : view.internal_pool.active_bitmaps)
    {
        if (!index_is_valid(bitmap.rotation_index))
        {
            return Fail(out_error, "AppleSpacemanBitmapRotationStateInvalid");
        }
        out_protected_bitmap_indices.push_back(bitmap.rotation_index);
    }
    std::sort(out_protected_bitmap_indices.begin(),
        out_protected_bitmap_indices.end());
    out_protected_bitmap_indices.erase(
        std::unique(out_protected_bitmap_indices.begin(),
            out_protected_bitmap_indices.end()),
        out_protected_bitmap_indices.end());
    return true;
}

void PutU16LE(std::vector<std::byte>& bytes, std::size_t offset, std::uint16_t value)
{
    bytes[offset] = static_cast<std::byte>(value & 0xFFu);
    bytes[offset + 1] = static_cast<std::byte>((value >> 8) & 0xFFu);
}

void PutU32LE(std::vector<std::byte>& bytes, std::size_t offset, std::uint32_t value)
{
    for (std::size_t index = 0; index < 4; ++index)
    {
        bytes[offset + index] =
            static_cast<std::byte>((value >> (index * 8)) & 0xFFu);
    }
}

void PutU64LE(std::vector<std::byte>& bytes, std::size_t offset, std::uint64_t value)
{
    for (std::size_t index = 0; index < 8; ++index)
    {
        bytes[offset + index] =
            static_cast<std::byte>((value >> (index * 8)) & 0xFFu);
    }
}

bool BitSet(const std::vector<std::byte>& bitmap, std::uint64_t bit)
{
    const auto byte_index = static_cast<std::size_t>(bit / 8);
    return byte_index < bitmap.size() &&
        (std::to_integer<unsigned int>(bitmap[byte_index]) &
            (1u << (bit % 8))) != 0;
}

void SetBit(std::vector<std::byte>& bitmap, std::uint64_t bit)
{
    bitmap[static_cast<std::size_t>(bit / 8)] |=
        static_cast<std::byte>(1u << (bit % 8));
}

void ClearBit(std::vector<std::byte>& bitmap, std::uint64_t bit)
{
    bitmap[static_cast<std::size_t>(bit / 8)] &=
        static_cast<std::byte>(~(1u << (bit % 8)));
}

bool ReserveInternalPoolBlock(
    catalog::AppleSpacemanView& view,
    std::uint64_t& out_block,
    std::set<std::size_t>& dirty_bitmaps)
{
    if (view.internal_pool.active_bitmaps.empty() ||
        view.internal_pool.active_bitmaps.front().bytes.empty())
    {
        return false;
    }
    const std::uint64_t bits_per_bitmap = static_cast<std::uint64_t>(
        view.internal_pool.active_bitmaps.front().bytes.size()) * 8;
    for (std::size_t bitmap_index = 0;
         bitmap_index < view.internal_pool.active_bitmaps.size(); ++bitmap_index)
    {
        auto& bitmap = view.internal_pool.active_bitmaps[bitmap_index];
        if (bitmap.bytes.size() !=
                view.internal_pool.active_bitmaps.front().bytes.size())
        {
            return false;
        }
        const std::uint64_t first_bit = bitmap_index * bits_per_bitmap;
        if (first_bit >= view.internal_pool.block_count)
        {
            break;
        }
        const std::uint64_t remaining = view.internal_pool.block_count - first_bit;
        const std::uint64_t bit_count = (std::min)(bits_per_bitmap, remaining);
        for (std::uint64_t bit = 0; bit < bit_count; ++bit)
        {
            if (BitSet(bitmap.bytes, bit))
            {
                continue;
            }
            SetBit(bitmap.bytes, bit);
            dirty_bitmaps.insert(bitmap_index);
            out_block = view.internal_pool.base_block + first_bit + bit;
            return true;
        }
    }
    return false;
}

bool RangeFits(std::uint64_t start, std::uint64_t count, std::uint64_t limit)
{
    return count != 0 && start < limit && count <= limit - start;
}

bool FindChunkIndex(const catalog::AppleSpacemanView& view,
    std::uint64_t block, std::size_t& out_index)
{
    const auto block_size = catalog::ReadU32LE(view.bytes, 0x20).value_or(0);
    if (!block_size) return false;
    const auto tier = catalog::kFusionTier2ByteAddress / block_size;
    const std::size_t device = block >= tier ? 1 : 0;
    if (device) block -= tier;
    const auto begin = std::lower_bound(view.chunks.begin(), view.chunks.end(), device,
        [](const auto& c, auto d) { return c.device_index < d; });
    const auto end = std::upper_bound(begin, view.chunks.end(), device,
        [](auto d, const auto& c) { return d < c.device_index; });
    const auto upper = std::upper_bound(begin,
        end, block, [](std::uint64_t value, const auto& chunk) {
            return value < chunk.start_block;
        });
    if (upper == begin)
    {
        return false;
    }
    const auto chunk = std::prev(upper);
    if (block < chunk->start_block ||
        block - chunk->start_block >= chunk->block_count)
    {
        return false;
    }
    out_index = static_cast<std::size_t>(
        std::distance(view.chunks.begin(), chunk));
    return true;
}

bool ClassifyDeferredFree(const catalog::AppleSpacemanView& view,
    std::uint64_t physical_block, std::uint64_t block_count,
    std::size_t& out_queue_index)
{
    const auto bs = catalog::ReadU32LE(view.bytes, 0x20).value_or(0);
    if (view.devices[1].block_count && bs && physical_block >= catalog::kFusionTier2ByteAddress / bs)
    {
        out_queue_index = 2;
        return RangeFits(physical_block - catalog::kFusionTier2ByteAddress / bs,
            block_count, view.devices[1].block_count);
    }
    if (!RangeFits(physical_block, block_count, view.devices[0].block_count))
    {
        return false;
    }
    const auto& pool = view.internal_pool;
    const bool starts_in_pool = physical_block >= pool.base_block &&
        physical_block - pool.base_block < pool.block_count;
    if (starts_in_pool)
    {
        if (block_count > pool.block_count - (physical_block - pool.base_block))
        {
            return false;
        }
        out_queue_index = 0;
        return true;
    }
    const std::uint64_t range_end = physical_block + block_count;
    const bool overlaps_pool = range_end > pool.base_block &&
        physical_block < pool.base_block + pool.block_count;
    if (overlaps_pool)
    {
        return false;
    }
    out_queue_index = 1;
    return true;
}

bool AddDeferredFree(AppleSpacemanAllocationPlan& plan,
    const catalog::AppleSpacemanView& view, std::uint64_t physical_block,
    std::uint64_t block_count, std::string& out_error)
{
    std::size_t queue_index = 0;
    if (!ClassifyDeferredFree(view, physical_block, block_count, queue_index))
    {
        return Fail(out_error, "AppleSpacemanDeferredFreeRangeInvalid");
    }
    plan.deferred_frees.push_back(
        {queue_index, physical_block, block_count});
    return true;
}

bool MainPoolRangeIsAllocated(const catalog::AppleSpacemanView& view,
    std::uint64_t physical_block, std::uint64_t block_count)
{
    std::size_t queue = 0;
    if (!ClassifyDeferredFree(view, physical_block, block_count, queue))
    {
        return false;
    }
    for (std::uint64_t block = physical_block;
         block < physical_block + block_count; ++block)
    {
        std::size_t chunk_index = 0;
        if (!FindChunkIndex(view, block, chunk_index))
        {
            return false;
        }
        const auto& chunk = view.chunks[chunk_index];
        const auto base = chunk.device_index ? catalog::kFusionTier2ByteAddress /
            catalog::ReadU32LE(view.bytes, 0x20).value() : 0;
        if (chunk.allocation_bitmap.empty() ||
            !BitSet(chunk.allocation_bitmap, block - base - chunk.start_block))
        {
            return false;
        }
    }
    return true;
}

bool ReclaimInternalPoolRange(catalog::AppleSpacemanView& view,
    std::uint64_t physical_block, std::uint64_t block_count,
    std::set<std::size_t>& dirty_bitmaps, std::string& out_error)
{
    auto& pool = view.internal_pool;
    if (pool.active_bitmaps.empty() ||
        physical_block < pool.base_block ||
        !RangeFits(physical_block - pool.base_block, block_count,
            pool.block_count))
    {
        return Fail(out_error, "AppleSpacemanFreeQueuePoolMismatch");
    }
    const std::uint64_t bits_per_bitmap = static_cast<std::uint64_t>(
        pool.active_bitmaps.front().bytes.size()) * 8;
    if (bits_per_bitmap == 0)
    {
        return Fail(out_error, "AppleSpacemanInternalPoolBitmapInvalid");
    }
    for (std::uint64_t ordinal = 0; ordinal < block_count; ++ordinal)
    {
        const std::uint64_t relative =
            physical_block - pool.base_block + ordinal;
        const auto bitmap_index = static_cast<std::size_t>(
            relative / bits_per_bitmap);
        const std::uint64_t bit = relative % bits_per_bitmap;
        if (bitmap_index >= pool.active_bitmaps.size() ||
            !BitSet(pool.active_bitmaps[bitmap_index].bytes, bit))
        {
            return Fail(out_error,
                "AppleSpacemanFreeQueueOwnershipMismatch");
        }
        ClearBit(pool.active_bitmaps[bitmap_index].bytes, bit);
        dirty_bitmaps.insert(bitmap_index);
    }
    return true;
}

bool ReclaimMainPoolRange(catalog::AppleSpacemanView& view,
    std::uint64_t physical_block, std::uint64_t block_count,
    std::uint64_t transaction_xid, std::set<std::size_t>& touched_chunks,
    std::string& out_error)
{
    if (!RangeFits(physical_block, block_count, view.devices[0].block_count))
    {
        return Fail(out_error, "AppleSpacemanFreeQueueRangeInvalid");
    }
    for (std::uint64_t ordinal = 0; ordinal < block_count; ++ordinal)
    {
        const std::uint64_t block = physical_block + ordinal;
        std::size_t chunk_index = 0;
        if (!FindChunkIndex(view, block, chunk_index))
        {
            return Fail(out_error,
                "AppleSpacemanFreeQueueOwnershipMismatch");
        }
        auto& chunk = view.chunks[chunk_index];
        const std::uint64_t bit = block - chunk.start_block;
        if (bit >= chunk.block_count || chunk.allocation_bitmap.empty() ||
            !BitSet(chunk.allocation_bitmap, bit) ||
            chunk.free_count >= chunk.block_count ||
            view.devices[0].free_count >= view.devices[0].block_count)
        {
            return Fail(out_error,
                "AppleSpacemanFreeQueueOwnershipMismatch");
        }
        ClearBit(chunk.allocation_bitmap, bit);
        ++chunk.free_count;
        ++view.devices[0].free_count;
        chunk.xid = transaction_xid;
        touched_chunks.insert(chunk_index);
    }
    return true;
}

#include "FusionTier2Reclamation.inc"

bool ReclaimMatureFreeQueues(catalog::AppleSpacemanView& view,
    std::uint64_t expected_checkpoint_xid,
    std::uint64_t oldest_required_checkpoint_xid,
    std::uint64_t transaction_xid,
    std::set<std::size_t>& dirty_ip_bitmaps,
    std::set<std::size_t>& touched_chunks,
    std::array<bool, 3>& rebuild_queue, std::string& out_error, bool internal_pool_only)
{
    for (std::size_t queue_index = 0;
         queue_index < view.free_queues.size(); ++queue_index)
    {
        auto& queue = view.free_queues[queue_index];
        if (internal_pool_only && queue_index != 0) continue;
        if (queue.entries.empty())
        {
            continue;
        }
        std::vector<catalog::AppleSpacemanFreeQueueEntry> retained_entries;
        retained_entries.reserve(queue.entries.size());
        bool reclaimed_any = false;
        for (const auto& entry : queue.entries)
        {
            if (entry.xid == 0 || entry.xid > expected_checkpoint_xid ||
                entry.xid >= transaction_xid)
            {
                return Fail(out_error, "AppleSpacemanFreeQueueXidInvalid");
            }
            if (entry.xid > oldest_required_checkpoint_xid)
            {
                retained_entries.push_back(entry);
                continue;
            }
            const bool reclaimed = queue_index == 0
                ? ReclaimInternalPoolRange(view, entry.physical_block,
                    entry.block_count, dirty_ip_bitmaps, out_error)
                : queue_index == 1
                    ? ReclaimMainPoolRange(view, entry.physical_block,
                        entry.block_count, transaction_xid, touched_chunks,
                        out_error)
                    : queue_index == 2 && view.devices[1].block_count
                        ? ReclaimFusionTier2Range(view,entry.physical_block,entry.block_count,
                            transaction_xid,touched_chunks,out_error)
                        : Fail(out_error, "AppleSpacemanFreeQueuePoolMismatch");
            if (!reclaimed)
            {
                return false;
            }
            reclaimed_any = true;
        }
        if (!reclaimed_any)
        {
            continue;
        }
        queue.entries = std::move(retained_entries);
        queue.block_count = 0;
        queue.oldest_xid = std::numeric_limits<std::uint64_t>::max();
        for (const auto& entry : queue.entries)
        {
            if (entry.block_count > std::numeric_limits<std::uint64_t>::max() -
                    queue.block_count)
            {
                return Fail(out_error, "AppleSpacemanFreeQueueCountOverflow");
            }
            queue.block_count += entry.block_count;
            queue.oldest_xid = (std::min)(queue.oldest_xid, entry.xid);
        }
        if (queue.entries.empty())
        {
            queue.oldest_xid = 0;
        }
        rebuild_queue[queue_index] = true;
    }
    return true;
}

bool NormalizeFreeQueueEntries(
    const catalog::AppleSpacemanFreeQueueView& queue,
    const std::vector<AppleSpacemanDeferredFree>& deferred_frees,
    std::size_t queue_index,
    std::uint64_t transaction_xid,
    std::vector<catalog::AppleSpacemanFreeQueueEntry>& out_entries,
    std::string& out_error)
{
    out_entries = queue.entries;
    for (const auto& deferred : deferred_frees)
    {
        if (deferred.queue_index == queue_index)
        {
            out_entries.push_back({transaction_xid, deferred.physical_block,
                deferred.block_count});
        }
    }
    std::vector<std::pair<std::uint64_t, std::uint64_t>> ranges;
    ranges.reserve(out_entries.size());
    for (const auto& entry : out_entries)
    {
        if (entry.xid == 0 || entry.physical_block == 0 ||
            entry.block_count == 0 ||
            entry.block_count > std::numeric_limits<std::uint64_t>::max() -
                entry.physical_block)
        {
            return Fail(out_error, "AppleSpacemanFreeQueueRecordInvalid");
        }
        ranges.emplace_back(entry.physical_block,
            entry.physical_block + entry.block_count);
    }
    std::sort(ranges.begin(), ranges.end());
    for (std::size_t index = 1; index < ranges.size(); ++index)
    {
        if (ranges[index].first < ranges[index - 1].second)
        {
            return Fail(out_error, "AppleSpacemanDeferredFreeOverlap");
        }
    }
    std::sort(out_entries.begin(), out_entries.end(), [](const auto& left,
                                                         const auto& right) {
        return std::tie(left.xid, left.physical_block) <
            std::tie(right.xid, right.physical_block);
    });
    std::vector<catalog::AppleSpacemanFreeQueueEntry> coalesced;
    coalesced.reserve(out_entries.size());
    for (const auto& entry : out_entries)
    {
        if (!coalesced.empty() && coalesced.back().xid == entry.xid &&
            coalesced.back().physical_block + coalesced.back().block_count ==
                entry.physical_block)
        {
            coalesced.back().block_count += entry.block_count;
        }
        else
        {
            coalesced.push_back(entry);
        }
    }
    out_entries = std::move(coalesced);
    return true;
}

catalog::BtreeRecord EncodeFreeQueueEntry(
    const catalog::AppleSpacemanFreeQueueEntry& entry)
{
    catalog::BtreeRecord record;
    record.key.resize(16, std::byte{0});
    PutU64LE(record.key, 0, entry.xid);
    PutU64LE(record.key, 8, entry.physical_block);
    if (entry.block_count != 1)
    {
        record.value.resize(8, std::byte{0});
        PutU64LE(record.value, 0, entry.block_count);
    }
    return record;
}

AppleBtreeOptions FreeQueueOptions(
    const catalog::AppleSpacemanFreeQueueView& queue,
    std::uint32_t block_size,
    std::uint64_t transaction_xid)
{
    AppleBtreeOptions options;
    options.block_size = block_size;
    options.xid = transaction_xid;
    options.root_object_id = queue.tree_oid;
    options.storage_type = catalog::kObjectEphemeral;
    options.subtype = catalog::kObjectTypeSpacemanFreeQueue;
    options.tree_flags = queue.tree_flags;
    options.fixed_key_size = queue.fixed_key_size;
    options.fixed_value_size = queue.fixed_value_size;
    options.minimum_longest_key = queue.longest_key;
    options.minimum_longest_value = queue.longest_value;
    options.key_order = AppleBtreeKeyOrder::SpacemanFreeQueue;
    options.max_nodes = queue.tree_node_limit;
    return options;
}

bool SameObjectLocation(const catalog::AppleObjectLocation& left,
    const catalog::AppleObjectLocation& right)
{
    return left.object_id == right.object_id && left.xid == right.xid &&
        left.physical_block == right.physical_block &&
        left.type == right.type && left.subtype == right.subtype &&
        left.size_bytes == right.size_bytes;
}

bool SameQueueEntries(
    const std::vector<catalog::AppleSpacemanFreeQueueEntry>& left,
    const std::vector<catalog::AppleSpacemanFreeQueueEntry>& right)
{
    return left.size() == right.size() &&
        std::equal(left.begin(), left.end(), right.begin(),
            [](const auto& lhs, const auto& rhs) {
                return lhs.xid == rhs.xid &&
                    lhs.physical_block == rhs.physical_block &&
                    lhs.block_count == rhs.block_count;
            });
}

bool SameSpacemanView(const catalog::AppleSpacemanView& left,
    const catalog::AppleSpacemanView& right)
{
    if (!SameObjectLocation(left.object, right.object) ||
        left.bytes != right.bytes ||
        left.blocks_per_chunk != right.blocks_per_chunk ||
        left.chunks_per_cib != right.chunks_per_cib ||
        left.cibs_per_cab != right.cibs_per_cab ||
        left.flags != right.flags ||
        left.internal_pool_bitmap_transaction_multiplier !=
            right.internal_pool_bitmap_transaction_multiplier ||
        left.version != right.version ||
        left.structure_size != right.structure_size ||
        left.free_queue_oids != right.free_queue_oids ||
        left.free_queue_roots.size() != right.free_queue_roots.size())
    {
        return false;
    }
    for (std::size_t index = 0; index < left.free_queue_roots.size(); ++index)
    {
        if (!SameObjectLocation(left.free_queue_roots[index],
                right.free_queue_roots[index]))
        {
            return false;
        }
    }
    for (std::size_t index = 0; index < left.free_queues.size(); ++index)
    {
        const auto& lhs = left.free_queues[index];
        const auto& rhs = right.free_queues[index];
        if (lhs.block_count != rhs.block_count || lhs.tree_oid != rhs.tree_oid ||
            lhs.oldest_xid != rhs.oldest_xid ||
            lhs.tree_node_limit != rhs.tree_node_limit ||
            lhs.tree_flags != rhs.tree_flags ||
            lhs.fixed_key_size != rhs.fixed_key_size ||
            lhs.fixed_value_size != rhs.fixed_value_size ||
            lhs.longest_key != rhs.longest_key ||
            lhs.longest_value != rhs.longest_value ||
            !SameObjectLocation(lhs.root, rhs.root) ||
            lhs.tree_blocks != rhs.tree_blocks ||
            !SameQueueEntries(lhs.entries, rhs.entries))
        {
            return false;
        }
    }
    const auto& left_pool = left.internal_pool;
    const auto& right_pool = right.internal_pool;
    if (left_pool.block_count != right_pool.block_count ||
        left_pool.bitmap_size_blocks != right_pool.bitmap_size_blocks ||
        left_pool.bitmap_block_count != right_pool.bitmap_block_count ||
        left_pool.bitmap_base_block != right_pool.bitmap_base_block ||
        left_pool.base_block != right_pool.base_block ||
        left_pool.bitmap_free_head != right_pool.bitmap_free_head ||
        left_pool.bitmap_free_tail != right_pool.bitmap_free_tail ||
        left_pool.bitmap_xid_offset != right_pool.bitmap_xid_offset ||
        left_pool.bitmap_index_offset != right_pool.bitmap_index_offset ||
        left_pool.bitmap_free_next_offset != right_pool.bitmap_free_next_offset ||
        left_pool.bitmap_free_next != right_pool.bitmap_free_next ||
        left_pool.active_bitmaps.size() != right_pool.active_bitmaps.size())
    {
        return false;
    }
    for (std::size_t index = 0;
         index < left_pool.active_bitmaps.size(); ++index)
    {
        const auto& lhs = left_pool.active_bitmaps[index];
        const auto& rhs = right_pool.active_bitmaps[index];
        if (lhs.xid != rhs.xid || lhs.physical_block != rhs.physical_block ||
            lhs.rotation_index != rhs.rotation_index || lhs.bytes != rhs.bytes)
        {
            return false;
        }
    }
    if (left.chunks.size() != right.chunks.size())
    {
        return false;
    }
    for (std::size_t index = 0; index < left.chunks.size(); ++index)
    {
        const auto& lhs = left.chunks[index];
        const auto& rhs = right.chunks[index];
        if (lhs.xid != rhs.xid || lhs.start_block != rhs.start_block ||
            lhs.block_count != rhs.block_count || lhs.free_count != rhs.free_count ||
            lhs.bitmap_block != rhs.bitmap_block ||
            lhs.device_index != rhs.device_index || lhs.cib_index != rhs.cib_index ||
            lhs.index_in_cib != rhs.index_in_cib ||
            lhs.allocation_bitmap != rhs.allocation_bitmap)
        {
            return false;
        }
    }
    for (std::size_t device_index = 0;
         device_index < left.devices.size(); ++device_index)
    {
        const auto& lhs = left.devices[device_index];
        const auto& rhs = right.devices[device_index];
        if (lhs.block_count != rhs.block_count ||
            lhs.chunk_count != rhs.chunk_count || lhs.cib_count != rhs.cib_count ||
            lhs.cab_count != rhs.cab_count || lhs.free_count != rhs.free_count ||
            lhs.address_offset != rhs.address_offset ||
            lhs.cabs.size() != rhs.cabs.size() || lhs.cibs.size() != rhs.cibs.size())
        {
            return false;
        }
        for (std::size_t index = 0; index < lhs.cabs.size(); ++index)
        {
            const auto& left_cab = lhs.cabs[index];
            const auto& right_cab = rhs.cabs[index];
            if (!SameObjectLocation(left_cab.object, right_cab.object) ||
                left_cab.index != right_cab.index ||
                left_cab.bytes != right_cab.bytes ||
                left_cab.cib_blocks != right_cab.cib_blocks)
            {
                return false;
            }
        }
        for (std::size_t index = 0; index < lhs.cibs.size(); ++index)
        {
            const auto& left_cib = lhs.cibs[index];
            const auto& right_cib = rhs.cibs[index];
            if (!SameObjectLocation(left_cib.object, right_cib.object) ||
                left_cib.index != right_cib.index ||
                left_cib.bytes != right_cib.bytes ||
                left_cib.chunk_indices != right_cib.chunk_indices)
            {
                return false;
            }
        }
    }
    return true;
}

bool SameCheckpointMappings(
    const std::vector<catalog::CheckpointMapping>& left,
    const std::vector<catalog::CheckpointMapping>& right)
{
    return left.size() == right.size() &&
        std::equal(left.begin(), left.end(), right.begin(),
            [](const auto& lhs, const auto& rhs) {
                return lhs.type == rhs.type && lhs.subtype == rhs.subtype &&
                    lhs.size_bytes == rhs.size_bytes &&
                    lhs.file_system_oid == rhs.file_system_oid &&
                    lhs.object_id == rhs.object_id &&
                    lhs.physical_block == rhs.physical_block;
            });
}

bool RotateInternalPoolBitmap(
    catalog::AppleSpacemanView& view,
    std::size_t bitmap_index,
    std::uint64_t transaction_xid,
    const std::vector<std::uint16_t>& protected_bitmap_indices,
    AppleSpacemanPlannedWrite& out_write,
    std::string& out_error)
{
    auto& pool = view.internal_pool;
    auto& bitmap = pool.active_bitmaps[bitmap_index];
    std::uint16_t previous_index = kInvalidBitmapIndex;
    std::uint16_t new_index = pool.bitmap_free_head;
    std::size_t visited = 0;
    while (new_index != kInvalidBitmapIndex)
    {
        if (new_index >= pool.bitmap_block_count ||
            new_index >= pool.bitmap_free_next.size() ||
            ++visited > pool.bitmap_free_next.size())
        {
            return Fail(out_error, "AppleSpacemanBitmapRotationStateInvalid");
        }
        if (!std::binary_search(protected_bitmap_indices.begin(),
                protected_bitmap_indices.end(), new_index))
        {
            break;
        }
        previous_index = new_index;
        new_index = pool.bitmap_free_next[new_index];
    }
    if (new_index == kInvalidBitmapIndex)
    {
        return Fail(out_error, previous_index == kInvalidBitmapIndex
                ? "AppleSpacemanBitmapRotationExhausted"
                : "AppleSpacemanBitmapRetentionExhausted");
    }
    const std::uint16_t next_head = pool.bitmap_free_next[new_index];
    const std::uint16_t old_index = bitmap.rotation_index;
    if (old_index >= pool.bitmap_block_count ||
        old_index >= pool.bitmap_free_next.size() ||
        pool.bitmap_free_next[old_index] != kInvalidBitmapIndex)
    {
        return Fail(out_error, "AppleSpacemanBitmapRotationStateInvalid");
    }
    if (previous_index == kInvalidBitmapIndex)
    {
        pool.bitmap_free_head = next_head;
    }
    else
    {
        pool.bitmap_free_next[previous_index] = next_head;
    }
    if (pool.bitmap_free_tail == new_index)
    {
        pool.bitmap_free_tail = previous_index;
    }
    pool.bitmap_free_next[new_index] = kInvalidBitmapIndex;
    if (pool.bitmap_free_head == kInvalidBitmapIndex)
    {
        pool.bitmap_free_head = old_index;
        pool.bitmap_free_tail = old_index;
    }
    else
    {
        if (pool.bitmap_free_tail == kInvalidBitmapIndex ||
            pool.bitmap_free_tail >= pool.bitmap_free_next.size())
        {
            return Fail(out_error, "AppleSpacemanBitmapRotationStateInvalid");
        }
        pool.bitmap_free_next[pool.bitmap_free_tail] = old_index;
        pool.bitmap_free_tail = old_index;
    }
    pool.bitmap_free_next[old_index] = kInvalidBitmapIndex;
    bitmap.rotation_index = new_index;
    bitmap.physical_block = pool.bitmap_base_block + new_index;
    bitmap.xid = transaction_xid;
    out_write.kind = AppleSpacemanWriteKind::InternalPoolBitmap;
    out_write.physical_block = bitmap.physical_block;
    out_write.bytes = bitmap.bytes;
    return true;
}

} // namespace

static bool PlanSpacemanAllocationImpl(
    const catalog::AppleSpacemanView& view,
    const AppleSpacemanAllocationRequest& request,
    AppleSpacemanAllocationPlan& out_plan,
    std::string& out_error, std::size_t tier2_block_count, bool fusion)
{
    out_plan = AppleSpacemanAllocationPlan{};
    out_error.clear();
    if (request.expected_checkpoint_xid == 0 ||
        request.expected_checkpoint_xid != view.object.xid)
    {
        return Fail(out_error, "AppleSpacemanCheckpointDrift");
    }
    if (request.transaction_xid <= request.expected_checkpoint_xid)
    {
        return Fail(out_error, "AppleSpacemanTransactionXidInvalid");
    }
    AppleSpacemanAllocationPlan plan;
    plan.expected_checkpoint_xid = request.expected_checkpoint_xid;
    plan.transaction_xid = request.transaction_xid;
    if (!ResolveRetentionContext(view, request,
            plan.effective_oldest_required_checkpoint_xid,
            plan.effective_protected_internal_pool_bitmap_indices, out_error))
    {
        return false;
    }
    plan.updated_spaceman = view;
    auto& updated = plan.updated_spaceman;
    std::set<std::size_t> touched_chunks;
    std::set<std::size_t> dirty_ip_bitmaps;
    std::array<bool, 3> rebuild_queue{};
    if (!ReclaimMatureFreeQueues(updated, request.expected_checkpoint_xid,
            plan.effective_oldest_required_checkpoint_xid,
            request.transaction_xid, dirty_ip_bitmaps, touched_chunks,
            rebuild_queue, out_error, request.reclaim_internal_pool_only))
    {
        return false;
    }
    if (updated.devices[0].free_count < request.main_block_count ||
        updated.devices[1].free_count < tier2_block_count ||
        tier2_block_count > SIZE_MAX - request.main_block_count)
    {
        return Fail(out_error, "AppleSpacemanMainPoolExhausted");
    }
    const std::array<std::size_t, 2> requested{request.main_block_count, tier2_block_count};
    std::array<std::size_t, 2> allocated{};
    const auto block_size = catalog::ReadU32LE(view.bytes, 0x20).value_or(0);
    const auto allocate_from_chunk = [&](std::size_t chunk_index) {
        auto& chunk = updated.chunks[chunk_index];
        const auto device = chunk.device_index;
        if (device >= 2 || allocated[device] == requested[device]) return;
        if (chunk.free_count == 0)
        {
            return;
        }
        if (chunk.allocation_bitmap.empty())
        {
            if (updated.internal_pool.active_bitmaps.empty())
            {
                return;
            }
            chunk.allocation_bitmap.assign(
                updated.internal_pool.active_bitmaps.front().bytes.size(),
                std::byte{0});
        }
        for (std::uint32_t ordinal = 0;
             ordinal < chunk.block_count &&
             allocated[device] < requested[device];
             ++ordinal)
        {
            const std::uint32_t bit = request.search_from_end
                ? chunk.block_count - 1 - ordinal
                : ordinal;
            if (BitSet(chunk.allocation_bitmap, bit))
            {
                continue;
            }
            SetBit(chunk.allocation_bitmap, bit);
            plan.allocated_main_blocks.push_back(chunk.start_block + bit +
                (device ? catalog::kFusionTier2ByteAddress / block_size : 0));
            ++allocated[device];
            --chunk.free_count;
            --updated.devices[device].free_count;
            chunk.xid = request.transaction_xid;
            touched_chunks.insert(chunk_index);
        }
    };
    if (request.search_from_end)
    {
        for (std::size_t ordinal = 0;
             ordinal < updated.chunks.size() &&
             plan.allocated_main_blocks.size() < request.main_block_count + tier2_block_count;
             ++ordinal)
        {
            allocate_from_chunk(updated.chunks.size() - 1 - ordinal);
        }
    }
    else
    {
        for (std::size_t index = 0;
             index < updated.chunks.size() &&
             plan.allocated_main_blocks.size() < request.main_block_count + tier2_block_count;
             ++index)
        {
            allocate_from_chunk(index);
        }
    }
    if (allocated != requested)
    {
        return Fail(out_error, "AppleSpacemanMainPoolExhausted");
    }

    const auto fail_internal_pool_exhaustion = [&]()
    {
        if (!fusion && plan.effective_oldest_required_checkpoint_xid < request.expected_checkpoint_xid)
        {
            // Diagnose retention pressure without changing the real request or
            // publishing anything. The probe cannot recurse: its floor is current.
            auto unpinned_request = request;
            unpinned_request.oldest_required_checkpoint_xid = request.expected_checkpoint_xid;
            AppleSpacemanAllocationPlan probe;
            std::string probe_error;
            if (PlanAppleSpacemanAllocation(view, unpinned_request, probe, probe_error))
            {
                return Fail(out_error, "AppleSpacemanInternalPoolRetentionExhausted");
            }
        }
        return Fail(out_error, "AppleSpacemanInternalPoolExhausted");
    };
    std::set<std::pair<std::size_t, std::size_t>> touched_cibs;
    for (const std::size_t chunk_index : touched_chunks)
    {
        auto& chunk = updated.chunks[chunk_index];
        std::uint64_t new_bitmap_block = 0;
        if (!ReserveInternalPoolBlock(updated, new_bitmap_block, dirty_ip_bitmaps))
        {
            return fail_internal_pool_exhaustion();
        }
        plan.allocated_internal_pool_blocks.push_back(new_bitmap_block);
        if (chunk.bitmap_block != 0)
        {
            if (!AddDeferredFree(plan, updated, chunk.bitmap_block, 1,
                    out_error))
            {
                return false;
            }
        }
        chunk.bitmap_block = new_bitmap_block;
        AppleSpacemanPlannedWrite bitmap_write;
        bitmap_write.kind = AppleSpacemanWriteKind::ChunkBitmap;
        bitmap_write.physical_block = new_bitmap_block;
        bitmap_write.bytes = chunk.allocation_bitmap;
        plan.writes.push_back(std::move(bitmap_write));
        touched_cibs.insert({chunk.device_index, chunk.cib_index});
    }

    std::set<std::pair<std::size_t, std::size_t>> touched_cabs;
    for (const auto& [device_index, cib_index] : touched_cibs)
    {
        auto& device = updated.devices[device_index];
        auto& cib = device.cibs[cib_index];
        std::uint64_t new_cib_block = 0;
        if (!ReserveInternalPoolBlock(updated, new_cib_block, dirty_ip_bitmaps))
        {
            return fail_internal_pool_exhaustion();
        }
        plan.allocated_internal_pool_blocks.push_back(new_cib_block);
        if (!AddDeferredFree(plan, updated, cib.object.physical_block, 1,
                out_error))
        {
            return false;
        }
        for (const std::size_t chunk_index : cib.chunk_indices)
        {
            const auto& chunk = updated.chunks[chunk_index];
            const std::size_t base = 0x28 + chunk.index_in_cib * 0x20;
            PutU64LE(cib.bytes, base, chunk.xid);
            PutU32LE(cib.bytes, base + 0x14, chunk.free_count);
            PutU64LE(cib.bytes, base + 0x18, chunk.bitmap_block);
        }
        PutU64LE(cib.bytes, 0x08, new_cib_block);
        PutU64LE(cib.bytes, 0x10, request.transaction_xid);
        if (!FinalizeAppleObjectChecksum(cib.bytes, out_error))
        {
            return false;
        }
        cib.object.object_id = new_cib_block;
        cib.object.xid = request.transaction_xid;
        cib.object.physical_block = new_cib_block;
        AppleSpacemanPlannedWrite cib_write;
        cib_write.kind = AppleSpacemanWriteKind::ChunkInfoBlock;
        cib_write.physical_block = new_cib_block;
        cib_write.bytes = cib.bytes;
        plan.writes.push_back(std::move(cib_write));

        if (device.cabs.empty())
        {
            PutU64LE(updated.bytes,
                device.address_offset + cib_index * 8,
                new_cib_block);
        }
        else
        {
            const std::size_t cab_index = cib_index / updated.cibs_per_cab;
            const std::size_t index_in_cab = cib_index % updated.cibs_per_cab;
            if (cab_index >= device.cabs.size() ||
                index_in_cab >= device.cabs[cab_index].cib_blocks.size())
            {
                return Fail(out_error, "AppleSpacemanCabStateInvalid");
            }
            auto& cab = device.cabs[cab_index];
            cab.cib_blocks[index_in_cab] = new_cib_block;
            PutU64LE(cab.bytes, 0x28 + index_in_cab * 8, new_cib_block);
            touched_cabs.insert({device_index, cab_index});
        }
    }

    for (const auto& [device_index, cab_index] : touched_cabs)
    {
        auto& device = updated.devices[device_index];
        auto& cab = device.cabs[cab_index];
        std::uint64_t new_cab_block = 0;
        if (!ReserveInternalPoolBlock(updated, new_cab_block, dirty_ip_bitmaps))
        {
            return fail_internal_pool_exhaustion();
        }
        plan.allocated_internal_pool_blocks.push_back(new_cab_block);
        if (!AddDeferredFree(plan, updated, cab.object.physical_block, 1,
                out_error))
        {
            return false;
        }
        PutU64LE(cab.bytes, 0x08, new_cab_block);
        PutU64LE(cab.bytes, 0x10, request.transaction_xid);
        if (!FinalizeAppleObjectChecksum(cab.bytes, out_error))
        {
            return false;
        }
        cab.object.object_id = new_cab_block;
        cab.object.xid = request.transaction_xid;
        cab.object.physical_block = new_cab_block;
        PutU64LE(updated.bytes,
            device.address_offset + cab_index * 8,
            new_cab_block);
        AppleSpacemanPlannedWrite cab_write;
        cab_write.kind = AppleSpacemanWriteKind::ChunkInfoAddressBlock;
        cab_write.physical_block = new_cab_block;
        cab_write.bytes = cab.bytes;
        plan.writes.push_back(std::move(cab_write));
    }

    for (const auto& release : request.released_blocks)
    {
        std::size_t queue_index = 0;
        if (!ClassifyDeferredFree(updated, release.physical_block,
                release.block_count, queue_index) || queue_index == 0 ||
            !MainPoolRangeIsAllocated(view, release.physical_block,
                release.block_count) ||
            !AddDeferredFree(plan, updated, release.physical_block,
                release.block_count, out_error))
        {
            if (out_error.empty())
            {
                out_error = "AppleSpacemanReleaseRangeInvalid";
            }
            return false;
        }
    }

    for (const auto& deferred : plan.deferred_frees)
    {
        if (deferred.queue_index >= rebuild_queue.size())
        {
            return Fail(out_error, "AppleSpacemanDeferredFreeQueueInvalid");
        }
        rebuild_queue[deferred.queue_index] = true;
    }
    const std::uint32_t queue_block_size = updated.internal_pool.active_bitmaps.empty()
        ? 0
        : static_cast<std::uint32_t>(
            updated.internal_pool.active_bitmaps.front().bytes.size());
    std::uint64_t next_ephemeral_object_id =
        request.first_ephemeral_object_id;
    for (std::size_t queue_index = 0;
         queue_index < rebuild_queue.size(); ++queue_index)
    {
        if (!rebuild_queue[queue_index])
        {
            continue;
        }
        auto& queue = updated.free_queues[queue_index];
        if (!queue.tree_oid)
        {
            if (!fusion || !next_ephemeral_object_id || next_ephemeral_object_id == UINT64_MAX)
                return Fail(out_error, "AppleSpacemanEphemeralObjectIdUnavailable");
            queue.tree_oid = next_ephemeral_object_id++;
            queue.tree_flags = kAppleBtreeEphemeral | kAppleBtreeAllowGhosts |
                kAppleBtreeUint64Keys | kAppleBtreeSequentialInsert;
            queue.fixed_key_size = queue.longest_key = 16;
            queue.fixed_value_size = queue.longest_value = 8;
            queue.tree_node_limit = 64;
            PutU64LE(updated.bytes, 0xC8 + queue_index * 0x28 + 8, queue.tree_oid);
            PutU16LE(updated.bytes, 0xC8 + queue_index * 0x28 + 0x18, queue.tree_node_limit);
        }
        std::vector<catalog::AppleSpacemanFreeQueueEntry> entries;
        if (!NormalizeFreeQueueEntries(queue, plan.deferred_frees,
                queue_index, request.transaction_xid, entries, out_error))
        {
            return false;
        }
        std::vector<catalog::BtreeRecord> records;
        records.reserve(entries.size());
        for (const auto& entry : entries)
        {
            records.push_back(EncodeFreeQueueEntry(entry));
        }

        AppleBtreeOptions dry_options = FreeQueueOptions(
            queue, queue_block_size, request.transaction_xid);
        dry_options.root_physical_block = 1;
        dry_options.first_child_object_id =
            queue.tree_oid == 0x7FFFFFFFFFFFF000ull
                ? 0x7FFFFFFFFFFFF800ull
                : 0x7FFFFFFFFFFFF000ull;
        dry_options.first_child_physical_block = 2;
        dry_options.max_nodes = (std::min<std::size_t>)(
            dry_options.max_nodes, 4096);
        AppleSerializedBtree dry_tree;
        std::string tree_error;
        if (!SerializeAppleBtree(records, dry_options, dry_tree, tree_error))
        {
            out_error = "AppleSpacemanFreeQueueSerializeFailed:" + tree_error;
            return false;
        }

        AppleBtreeOptions write_options = FreeQueueOptions(
            queue, queue_block_size, request.transaction_xid);
        write_options.max_nodes = (std::min<std::size_t>)(
            write_options.max_nodes, 4096);
        // Ephemeral nodes have no spaceman-owned physical address. Placeholder
        // positions satisfy the pure serializer; checkpoint publication places
        // every emitted object in the checkpoint data ring.
        write_options.root_physical_block = 1;
        const std::size_t child_count = dry_tree.objects.size() - 1;
        if (child_count != 0 && next_ephemeral_object_id == 0)
        {
            return Fail(out_error, "AppleSpacemanEphemeralObjectIdUnavailable");
        }
        for (std::size_t index = 0; index < child_count; ++index)
        {
            if (next_ephemeral_object_id == 0 ||
                next_ephemeral_object_id == queue.tree_oid ||
                next_ephemeral_object_id == updated.object.object_id)
            {
                return Fail(out_error, "AppleSpacemanEphemeralObjectIdInvalid");
            }
            write_options.child_object_ids.push_back(next_ephemeral_object_id);
            write_options.child_physical_blocks.push_back(index + 2);
            if (index + 1 != child_count)
            {
                if (next_ephemeral_object_id ==
                    std::numeric_limits<std::uint64_t>::max())
                {
                    return Fail(out_error, "AppleSpacemanEphemeralObjectIdOverflow");
                }
                ++next_ephemeral_object_id;
            }
        }
        if (child_count != 0)
        {
            if (next_ephemeral_object_id ==
                std::numeric_limits<std::uint64_t>::max())
            {
                return Fail(out_error, "AppleSpacemanEphemeralObjectIdOverflow");
            }
            ++next_ephemeral_object_id;
        }

        AppleSerializedBtree queue_tree;
        if (!SerializeAppleBtree(records, write_options, queue_tree, tree_error) ||
            queue_tree.objects.size() != dry_tree.objects.size())
        {
            out_error = "AppleSpacemanFreeQueueSerializeFailed:" + tree_error;
            return false;
        }
        const auto root_object = std::find_if(queue_tree.objects.begin(),
            queue_tree.objects.end(), [&queue](const auto& object) {
                return object.location.object_id == queue.tree_oid;
            });
        if (root_object == queue_tree.objects.end())
        {
            return Fail(out_error, "AppleSpacemanFreeQueueRootMissing");
        }
        queue.root = root_object->location;
        queue.root.physical_block = 0;
        queue.tree_blocks.clear();
        for (const auto& object : queue_tree.objects)
        {
            AppleSpacemanPlannedWrite write;
            write.kind = AppleSpacemanWriteKind::FreeQueueTree;
            write.object_location = object.location;
            write.object_location->physical_block = 0;
            write.bytes = object.bytes;
            plan.writes.push_back(std::move(write));
        }
        queue.entries = std::move(entries);
        queue.block_count = 0;
        for (const auto& entry : queue.entries)
        {
            if (entry.block_count > std::numeric_limits<std::uint64_t>::max() -
                    queue.block_count)
            {
                return Fail(out_error, "AppleSpacemanFreeQueueCountOverflow");
            }
            queue.block_count += entry.block_count;
        }
        queue.oldest_xid = queue.entries.empty() ? 0 : queue.entries.front().xid;
        constexpr std::size_t kFreeQueueBase = 0xC8;
        constexpr std::size_t kFreeQueueSize = 0x28;
        const std::size_t descriptor =
            kFreeQueueBase + queue_index * kFreeQueueSize;
        PutU64LE(updated.bytes, descriptor, queue.block_count);
        PutU64LE(updated.bytes, descriptor + 0x10, queue.oldest_xid);
    }
    updated.free_queue_roots.clear();
    for (const auto& queue : updated.free_queues)
    {
        if (queue.tree_oid != 0)
        {
            updated.free_queue_roots.push_back(queue.root);
        }
    }

    PutU64LE(updated.bytes, 0x48, updated.devices[0].free_count);
    if (fusion) PutU64LE(updated.bytes, 0x78, updated.devices[1].free_count);
    for (const std::size_t bitmap_index : dirty_ip_bitmaps)
    {
        AppleSpacemanPlannedWrite bitmap_write;
        if (!RotateInternalPoolBitmap(updated, bitmap_index,
                request.transaction_xid,
                plan.effective_protected_internal_pool_bitmap_indices,
                bitmap_write, out_error))
        {
            return false;
        }
        plan.writes.push_back(std::move(bitmap_write));
    }
    PutU16LE(updated.bytes, 0x140, updated.internal_pool.bitmap_free_head);
    PutU16LE(updated.bytes, 0x142, updated.internal_pool.bitmap_free_tail);
    for (std::size_t index = 0;
         index < updated.internal_pool.bitmap_free_next.size(); ++index)
    {
        PutU16LE(updated.bytes,
            updated.internal_pool.bitmap_free_next_offset + index * 2,
            updated.internal_pool.bitmap_free_next[index]);
    }
    for (std::size_t index = 0;
         index < updated.internal_pool.active_bitmaps.size(); ++index)
    {
        const auto& bitmap = updated.internal_pool.active_bitmaps[index];
        PutU64LE(updated.bytes,
            updated.internal_pool.bitmap_xid_offset + index * 8,
            bitmap.xid);
        PutU16LE(updated.bytes,
            updated.internal_pool.bitmap_index_offset + index * 2,
            bitmap.rotation_index);
    }
    PutU64LE(updated.bytes, 0x10, request.transaction_xid);
    if (!FinalizeAppleObjectChecksum(updated.bytes, out_error))
    {
        return false;
    }
    updated.object.xid = request.transaction_xid;
    out_plan = std::move(plan);
    return true;
}

bool PlanAppleSpacemanAllocation(const catalog::AppleSpacemanView& view,
    const AppleSpacemanAllocationRequest& request, AppleSpacemanAllocationPlan& out,
    std::string& error)
{
    out = {};
    if (view.devices[1].block_count) return Fail(error, "AppleSpacemanTier2BoundPlannerRequired");
    return PlanSpacemanAllocationImpl(view, request, out, error, 0, false);
}

namespace {
bool PlanFusionSpacemanAllocationImpl(const catalog::ApfsFusionStore& store,
    const AppleSpacemanAllocationRequest& input, std::size_t tier2_blocks,
    FusionSpacemanAllocationPlan& out, std::string& error,
    std::vector<AppleCheckpointGuardBlock>* reclaim_guards) try
{
    out = {};
    if (reclaim_guards) reclaim_guards->clear();
    catalog::AppleSpacemanView view;
    if (!catalog::LoadFusionSpacemanAllocationView(store, view, error)) return false;
    const auto& nx = store.Checkpoint().superblock;
    if (input.expected_checkpoint_xid != nx.xid || input.transaction_xid != nx.next_xid ||
        input.first_ephemeral_object_id < nx.next_oid)
        return Fail(error, "FusionAllocationIdentityMismatch");
    for (const auto& map : store.Checkpoint().mappings)
        if (map.object_id >= input.first_ephemeral_object_id)
            return Fail(error, "FusionAllocationEphemeralOidCollision");
    const auto overlaps = [](auto a, auto n, auto b, auto m) {
        return n && m && a < b + m && b < a + n;
    };
    for (const auto& release : input.released_blocks) {
        catalog::FusionRoute route;
        if (!release.block_count || release.block_count > UINT64_MAX / nx.block_size ||
            !store.MapPhysical(release.physical_block, 0, release.block_count * nx.block_size, route, error))
            return Fail(error, "FusionAllocationReleaseBounds");
        const auto b = release.physical_block, n = release.block_count;
        const auto tier = catalog::kFusionTier2ByteAddress / nx.block_size;
        if (overlaps(b,n,0ull,1ull) || overlaps(b,n,tier,1ull) ||
            overlaps(b,n,nx.xp_desc_base_block,static_cast<std::uint64_t>(nx.xp_desc_block_count)) ||
            overlaps(b,n,nx.xp_data_base_block,static_cast<std::uint64_t>(nx.xp_data_block_count)) ||
            overlaps(b,n,nx.fusion_middle_tree_oid,1ull) ||
            overlaps(b,n,nx.fusion_writeback_start,nx.fusion_writeback_blocks) ||
            overlaps(b,n,view.internal_pool.base_block,view.internal_pool.block_count) ||
            overlaps(b,n,view.internal_pool.bitmap_base_block,static_cast<std::uint64_t>(view.internal_pool.bitmap_block_count)))
            return Fail(error, "FusionAllocationReservedRelease");
        for (const auto& queue : view.free_queues) for (const auto& e : queue.entries)
            if (overlaps(b,n,e.physical_block,e.block_count))
                return Fail(error, "FusionAllocationAlreadyQueued");
    }
    auto request = input;
    request.oldest_required_checkpoint_xid = input.oldest_required_checkpoint_xid
        ? (std::min)(input.oldest_required_checkpoint_xid,nx.xid) : nx.xid;
    request.reclaim_internal_pool_only = true;
    std::set<std::uint64_t> historical_owners;
    std::set<std::uint64_t> seen_xids;
    for (std::uint32_t i = 0; i < nx.xp_desc_block_count; ++i) {
        std::vector<std::byte> bytes;
        if (!store.Read((nx.xp_desc_base_block + i) * nx.block_size, nx.block_size, bytes))
            return Fail(error, "FusionAllocationHistoryUnreadable");
        const auto header = catalog::ParseNxSuperblock(bytes);
        if (!header || !catalog::VerifyObjectChecksum(bytes, nx.block_size) ||
            header->xid > nx.xid || !seen_xids.insert(header->xid).second) continue;
        std::string ignored;
        auto old = catalog::LoadContainerCheckpointView(store, 0, store.SizeBytes(), ignored, header->xid);
        if (!old) continue; // An incomplete ring generation is not selectable.
        catalog::AppleSpacemanView historical;
        if (!catalog::LoadFusionPlanningAllocation(store, store, *old, historical, error)) return false;
        if (historical.internal_pool.base_block != view.internal_pool.base_block ||
            historical.internal_pool.block_count != view.internal_pool.block_count ||
            historical.internal_pool.bitmap_size_blocks != view.internal_pool.bitmap_size_blocks ||
            historical.internal_pool.bitmap_base_block != view.internal_pool.bitmap_base_block ||
            historical.internal_pool.bitmap_block_count != view.internal_pool.bitmap_block_count)
            return Fail(error, "FusionAllocationHistoricalPoolChanged");
        request.oldest_required_checkpoint_xid = (std::min)(request.oldest_required_checkpoint_xid,header->xid);
        for (const auto& bitmap : historical.internal_pool.active_bitmaps)
            request.protected_internal_pool_bitmap_indices.push_back(bitmap.rotation_index);
        const auto owned = [&](std::uint64_t b) {
            historical_owners.insert(b);
            if (b < view.internal_pool.base_block || b - view.internal_pool.base_block >= view.internal_pool.block_count) return false;
            const auto bit = b - view.internal_pool.base_block;
            const auto per = static_cast<std::uint64_t>(nx.block_size) * 8;
            return BitSet(view.internal_pool.active_bitmaps[static_cast<std::size_t>(bit/per)].bytes,bit%per);
        };
        for (const auto& d : historical.devices) {
            for (const auto& c : d.cibs) if (!owned(c.object.physical_block)) return Fail(error,"FusionAllocationHistoricalMetadataFree");
            for (const auto& c : d.cabs) if (!owned(c.object.physical_block)) return Fail(error,"FusionAllocationHistoricalMetadataFree");
        }
        for (const auto& c : historical.chunks) if (c.bitmap_block && !owned(c.bitmap_block))
            return Fail(error,"FusionAllocationHistoricalMetadataFree");
    }
    // Queue age is necessary but not sufficient: every selectable generation
    // must also prove that the candidate IP range has no remaining owner.
    for (const auto& entry : view.free_queues[0].entries)
        if (entry.xid <= request.oldest_required_checkpoint_xid) {
            const auto live = historical_owners.lower_bound(entry.physical_block);
            if (live != historical_owners.end() && *live - entry.physical_block < entry.block_count)
                return Fail(error, "FusionAllocationHistoricalReclaimCollision");
        }
    FusionReclamationCensus census;
    if (reclaim_guards) {
        // A typed entry requests a fresh canonical proof. No caller-provided
        // view, flag, or queue age alone can authorize device-block reuse.
        if (!CollectFusionReclamationCensus(store,census,error)) return false;
        request.oldest_required_checkpoint_xid = (std::min)(
            request.oldest_required_checkpoint_xid,census.oldest_checkpoint_xid);
        for (std::size_t q = 1; q < view.free_queues.size(); ++q)
            for (const auto& entry : view.free_queues[q].entries) {
                if (entry.xid > request.oldest_required_checkpoint_xid) continue;
                const auto owner = std::lower_bound(census.owners.begin(),census.owners.end(),entry.physical_block,
                    [](const auto& range,std::uint64_t b) { return range.physical_block+range.block_count <= b; });
                if (owner != census.owners.end() && owner->physical_block < entry.physical_block+entry.block_count)
                    return Fail(error,"FusionAllocationRetainedDeviceOwnerCollision");
            }
        request.reclaim_internal_pool_only = false;
    }
    AppleSpacemanAllocationPlan plan;
    if (!PlanSpacemanAllocationImpl(view, request, plan, error, tier2_blocks, true) ||
        !store.CheckAvailable(error)) return false;
    FusionSpacemanAllocationPlan candidate;
    const auto tier = catalog::kFusionTier2ByteAddress / nx.block_size;
    for (auto b : plan.allocated_main_blocks)
        if (b >= tier) candidate.allocated_tier2_blocks.push_back(b);
    std::erase_if(plan.allocated_main_blocks, [tier](auto b) { return b >= tier; });
    candidate.main = std::move(plan);
    if (reclaim_guards) *reclaim_guards = std::move(census.guards);
    out = std::move(candidate);
    return true;
}
catch (const std::bad_alloc&) { out = {}; return Fail(error, "FusionAllocationMemoryLimit"); }
catch (const std::length_error&) { out = {}; return Fail(error, "FusionAllocationMemoryLimit"); }
}

bool PlanFusionSpacemanAllocation(const catalog::ApfsFusionStore& store,
    const AppleSpacemanAllocationRequest& request, std::size_t tier2_blocks,
    FusionSpacemanAllocationPlan& out, std::string& error)
{
    return PlanFusionSpacemanAllocationImpl(store,request,tier2_blocks,out,error,nullptr);
}

bool PlanFusionReclaimingSpacemanAllocation(const catalog::ApfsFusionStore& store,
    const AppleSpacemanAllocationRequest& request, std::size_t tier2_blocks,
    FusionSpacemanAllocationPlan& out, std::vector<AppleCheckpointGuardBlock>& guards, std::string& error)
{
    return PlanFusionSpacemanAllocationImpl(store,request,tier2_blocks,out,error,&guards);
}

bool VerifyAppleSpacemanOwnershipUnchanged(
    const catalog::RandomAccessSource& source,
    std::uint64_t store_offset_bytes,
    std::uint64_t store_size_bytes,
    const catalog::ContainerCheckpointView& expected_checkpoint,
    const catalog::AppleSpacemanView& expected_view,
    std::string& out_error)
{
    out_error.clear();
    if (store_size_bytes == 0 || store_offset_bytes > source.SizeBytes() ||
        store_size_bytes > source.SizeBytes() - store_offset_bytes)
    {
        return Fail(out_error, "AppleSpacemanConcurrentDrift");
    }
    catalog::OffsetRandomAccessSource store(
        &source, store_offset_bytes, store_size_bytes);
    std::string load_error;
    const auto current_checkpoint = catalog::LoadContainerCheckpointView(
        store, 0, store_size_bytes, load_error);
    if (!current_checkpoint.has_value() ||
        current_checkpoint->superblock_physical_block !=
            expected_checkpoint.superblock_physical_block ||
        current_checkpoint->superblock_bytes !=
            expected_checkpoint.superblock_bytes ||
        current_checkpoint->checkpoint_map_blocks !=
            expected_checkpoint.checkpoint_map_blocks ||
        !SameCheckpointMappings(current_checkpoint->mappings,
            expected_checkpoint.mappings))
    {
        return Fail(out_error, "AppleSpacemanConcurrentDrift");
    }
    catalog::AppleSpacemanView current_view;
    if (!catalog::LoadAppleSpacemanOwnershipView(
            store, current_checkpoint.value(), current_view, load_error) ||
        !SameSpacemanView(current_view, expected_view))
    {
        return Fail(out_error, "AppleSpacemanConcurrentDrift");
    }
    return true;
}

} // namespace apfsaccess::rw
