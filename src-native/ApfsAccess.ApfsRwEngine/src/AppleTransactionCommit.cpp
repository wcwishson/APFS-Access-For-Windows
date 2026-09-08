#include "AppleTransactionCommit.h"

#include "ApfsTransactionWriter.h"

#include <algorithm>
#include <limits>
#include <new>
#include <stdexcept>
#include <unordered_map>
#include <unordered_set>

namespace apfsaccess::rw
{
namespace
{

bool Fail(std::string& out_error, const char* error)
{
    out_error = error;
    return false;
}

bool MaterializeRecovery(const catalog::RandomAccessSource& source,
    std::uint64_t count, std::uint64_t item_bytes, std::string& out_error)
{
    const auto budget = source.ReadBudget();
    if (!budget) return true;
    if (item_bytes != 0 && count > UINT64_MAX / item_bytes)
        (void)budget->Refuse("ApfsReadBudgetRecordLimit");
    else if (budget->Materialize(count, count * item_bytes)) return true;
    return Fail(out_error, budget->Failure());
}

template<class T>
bool ChargeRecoveryAppend(const catalog::RandomAccessSource& source,
    const std::vector<T>& values, std::uint64_t count, std::string& out_error)
{
    if (count > values.max_size() - values.size())
    {
        if (const auto budget = source.ReadBudget())
            (void)budget->Refuse("ApfsReadBudgetRecordLimit");
        return Fail(out_error, "AppleCheckpointRetentionAllocationFailed");
    }
    return MaterializeRecovery(source, count, sizeof(T), out_error);
}

struct RecoveryBudgetErrorScope
{
    const catalog::RandomAccessSource& source;
    std::string& error;
    ~RecoveryBudgetErrorScope()
    {
        const auto budget = source.ReadBudget();
        if (budget && budget->Failed()) error = budget->Failure();
    }
};

bool RecoveryAllocationFailed(const catalog::RandomAccessSource& source,
    std::string& out_error)
{
    const auto budget = source.ReadBudget();
    if (!budget) throw; // Preserve the unbudgeted caller's exception behavior.
    (void)budget->Refuse("ApfsReadBudgetAllocationFailed");
    return Fail(out_error, budget->Failure());
}

void PutU64(std::vector<std::byte>& bytes, std::size_t offset,
    std::uint64_t value)
{
    for (std::size_t index = 0; index < 8; ++index)
    {
        bytes[offset + index] =
            static_cast<std::byte>((value >> (index * 8)) & 0xffu);
    }
}

bool ReadBlock(const catalog::RandomAccessSource& source,
    std::uint64_t block, std::uint32_t block_size,
    std::vector<std::byte>& out_bytes)
{
    if (block_size == 0 || block > std::numeric_limits<std::uint64_t>::max() / block_size)
    {
        return false;
    }
    return source.Read(block * static_cast<std::uint64_t>(block_size),
        block_size, out_bytes) && out_bytes.size() == block_size;
}

bool ReadMappedObject(const catalog::RandomAccessSource& source,
    const catalog::NxSuperblock& nxsb,
    const catalog::CheckpointMapping& mapping,
    std::vector<std::byte>& out_bytes)
{
    out_bytes.clear();
    if (nxsb.block_size == 0 || mapping.size_bytes == 0 ||
        mapping.size_bytes % nxsb.block_size != 0 ||
        mapping.size_bytes / nxsb.block_size > nxsb.xp_data_block_count ||
        nxsb.xp_data_base_block > source.SizeBytes() / nxsb.block_size ||
        nxsb.xp_data_block_count > source.SizeBytes() / nxsb.block_size - nxsb.xp_data_base_block ||
        mapping.physical_block < nxsb.xp_data_base_block ||
        mapping.physical_block - nxsb.xp_data_base_block >=
            nxsb.xp_data_block_count)
    {
        return false;
    }
    // Reads charge their temporary blocks; this aggregate is a distinct copy.
    if (const auto budget = source.ReadBudget();
        budget && !budget->Materialize(0, mapping.size_bytes)) return false;
    out_bytes.resize(mapping.size_bytes);
    const auto first = mapping.physical_block - nxsb.xp_data_base_block;
    const auto blocks = mapping.size_bytes / nxsb.block_size;
    for (std::uint32_t ordinal = 0; ordinal < blocks; ++ordinal)
    {
        const auto relative = static_cast<std::uint32_t>(
            (first + ordinal) % nxsb.xp_data_block_count);
        std::vector<std::byte> block;
        if (!ReadBlock(source, nxsb.xp_data_base_block + relative,
                nxsb.block_size, block))
        {
            out_bytes.clear();
            return false;
        }
        std::copy(block.begin(), block.end(), out_bytes.begin() +
            static_cast<std::ptrdiff_t>(ordinal * nxsb.block_size));
    }
    return true;
}

bool AddStableGuard(const catalog::RandomAccessSource& source,
    std::uint64_t block, std::uint32_t block_size,
    std::vector<AppleCheckpointGuardBlock>& guards)
{
    if (std::any_of(guards.begin(), guards.end(), [block](const auto& guard) {
            return guard.physical_block == block;
        }))
    {
        return true;
    }
    AppleCheckpointGuardBlock guard;
    guard.physical_block = block;
    if (const auto budget = source.ReadBudget();
        budget && !budget->Materialize(1, sizeof(AppleCheckpointGuardBlock))) return false;
    if (!ReadBlock(source, block, block_size, guard.bytes))
    {
        return false;
    }
    guards.push_back(std::move(guard));
    return true;
}

bool AddEphemeral(
    AppleCheckpointEphemeralObject object,
    std::unordered_map<std::uint64_t, AppleCheckpointEphemeralObject>& objects,
    std::string& out_error)
{
    if (object.object.object_id == 0 ||
        !objects.emplace(object.object.object_id, std::move(object)).second)
    {
        return Fail(out_error, "AppleTransactionEphemeralDuplicate");
    }
    return true;
}

bool ValidateMainWriteCoverage(const AppleSpacemanAllocationPlan& allocation,
    const std::vector<AppleCheckpointPhysicalWrite>& writes,
    std::uint32_t block_size, std::string& out_error)
{
    std::unordered_set<std::uint64_t> allocated;
    for (const auto block : allocation.allocated_main_blocks)
    {
        if (block == 0 || !allocated.insert(block).second)
        {
            return Fail(out_error, "AppleTransactionMainAllocationInvalid");
        }
    }
    std::unordered_set<std::uint64_t> covered;
    for (const auto& write : writes)
    {
        if (write.physical_block == 0 || write.bytes.empty() ||
            write.bytes.size() % block_size != 0)
        {
            return Fail(out_error, "AppleTransactionMainWriteInvalid");
        }
        const auto blocks = write.bytes.size() / block_size;
        if (write.physical_block >
            std::numeric_limits<std::uint64_t>::max() - blocks)
        {
            return Fail(out_error, "AppleTransactionMainWriteInvalid");
        }
        for (std::size_t ordinal = 0; ordinal < blocks; ++ordinal)
        {
            const auto block = write.physical_block + ordinal;
            if (allocated.find(block) == allocated.end() ||
                !covered.insert(block).second)
            {
                return Fail(out_error, "AppleTransactionMainWriteInvalid");
            }
        }
    }
    return covered.size() == allocated.size()
        ? true
        : Fail(out_error, "AppleTransactionMainWriteIncomplete");
}

bool ReadCheckpointTree(const catalog::RandomAccessSource& source,
    const catalog::AppleCheckpointView& checkpoint,
    const catalog::AppleObjectLocation& root, std::uint64_t map_oid,
    std::vector<catalog::BtreeRecord>& records,
    std::vector<std::uint64_t>& metadata_blocks, std::string& out_error)
{
    catalog::BtreeReadPolicy policy;
    policy.enforce_object_identity = true;
    policy.require_complete_traversal = true;
    policy.root_object_id = root.object_id;
    policy.storage_type = root.type;
    policy.subtype = root.subtype;
    policy.ephemeral_checkpoint = &checkpoint.container;
    std::vector<std::uint64_t> visited;
    policy.visited_physical_blocks = &visited;
    const bool physical = (root.type & catalog::kObjectStorageTypeMask) == catalog::kObjectPhysical;
    if (!catalog::ReadBtreeLeafRecords(source, checkpoint.container.superblock.block_size,
            root.physical_block, physical, physical ? 0 : map_oid,
            checkpoint.container.superblock.xid, policy, records, out_error)) return false;
    if (std::any_of(visited.begin(), visited.end(), [&](std::uint64_t block) {
            return block >= checkpoint.container.superblock.block_count;
        })) return Fail(out_error, "AppleCheckpointMetadataOutsideContainer");
    // The parser charged visited; this is a separate retained copy.
    if (!ChargeRecoveryAppend(source, metadata_blocks, visited.size(), out_error)) return false;
    metadata_blocks.insert(metadata_blocks.end(), visited.begin(), visited.end());
    return true;
}

bool AppendSpacemanMetadataBlocks(const catalog::RandomAccessSource& source,
    const catalog::AppleCheckpointView& checkpoint,
    std::vector<std::uint64_t>& blocks, std::string& out_error)
{
    std::uint64_t count = 0;
    const auto add_count = [&](std::uint64_t amount) {
        if (amount > blocks.max_size() - blocks.size() - count)
        {
            if (const auto budget = source.ReadBudget())
                (void)budget->Refuse("ApfsReadBudgetRecordLimit");
            return Fail(out_error, "AppleCheckpointRetentionAllocationFailed");
        }
        count += amount;
        return true;
    };
    for (const auto& device : checkpoint.spaceman.devices)
        if (!add_count(device.cabs.size()) || !add_count(device.cibs.size())) return false;
    for (const auto& chunk : checkpoint.spaceman.chunks)
        if (chunk.bitmap_block != 0 && !add_count(1)) return false;
    if (!add_count(checkpoint.spaceman.internal_pool.active_bitmaps.size()) ||
        !ChargeRecoveryAppend(source, blocks, count, out_error)) return false;
    for (const auto& device : checkpoint.spaceman.devices)
    {
        for (const auto& cab : device.cabs) blocks.push_back(cab.object.physical_block);
        for (const auto& cib : device.cibs) blocks.push_back(cib.object.physical_block);
    }
    for (const auto& chunk : checkpoint.spaceman.chunks)
        if (chunk.bitmap_block != 0) blocks.push_back(chunk.bitmap_block);
    for (const auto& bitmap : checkpoint.spaceman.internal_pool.active_bitmaps)
        blocks.push_back(bitmap.physical_block);
    return true;
}

bool ChargeRecoveryPayloadGraph(const catalog::RandomAccessSource& source,
    const std::vector<catalog::BtreeRecord>& records,
    const std::vector<catalog::BtreeRecord>& extent_records, std::string& out_error)
{
    if (!source.ReadBudget()) return true;
    const auto files = static_cast<std::uint64_t>(std::count_if(records.begin(), records.end(),
        [](const auto& record) { return catalog::ReadU64LE(record.key, 0).value_or(0) >> 60 == 8; }));
    using Range = std::pair<std::uint64_t, std::uint64_t>;
    // ValidateApplePayloadExtentGraph has no source parameter. Reserve its
    // logical scratch here once: FileExtentUse, key-index map value, retained
    // flag, two reference events plus their merged copy and prefix counts,
    // and two range lists. Container node/capacity overhead is not an RSS quota.
    // Identical old/requested records produce no removed uses or byte copies.
    constexpr auto file_bytes = sizeof(AppleFileExtentRecord) + sizeof(const catalog::BtreeRecord*) +
        sizeof(std::pair<const Range, std::size_t>) + sizeof(bool) +
        6 * sizeof(Range) + 2 * sizeof(std::int64_t);
    // PhysicalExtentState, returned extent, and original/normalized ranges.
    constexpr auto physical_bytes = 2 * sizeof(ApplePhysicalExtentRecord) + 2 * sizeof(Range);
    return MaterializeRecovery(source, files, file_bytes, out_error) &&
        MaterializeRecovery(source, extent_records.size(), physical_bytes, out_error);
}

bool PayloadExtentAvoidsMetadata(const catalog::AppleCheckpointView& checkpoint,
    const std::vector<std::uint64_t>& sorted_metadata_blocks,
    const ApplePhysicalExtentRecord& extent)
{
    const auto& nxsb = checkpoint.container.superblock;
    const auto begin = extent.physical_block;
    if (begin == 0 || extent.block_count == 0 || begin >= nxsb.block_count ||
        extent.block_count > nxsb.block_count - begin) return false;
    const auto end = begin + extent.block_count;
    const auto intersects = [begin, end](std::uint64_t start, std::uint64_t count) {
        return count != 0 && start < end && (start >= begin || begin - start < count);
    };
    const auto& pool = checkpoint.spaceman.internal_pool;
    const auto metadata = std::lower_bound(sorted_metadata_blocks.begin(), sorted_metadata_blocks.end(), begin);
    return (metadata == sorted_metadata_blocks.end() || *metadata >= end) &&
        !intersects(nxsb.xp_desc_base_block, nxsb.xp_desc_block_count) &&
        !intersects(nxsb.xp_data_base_block, nxsb.xp_data_block_count) &&
        !intersects(pool.base_block, pool.block_count) &&
        !intersects(pool.bitmap_base_block, pool.bitmap_block_count);
}

bool CollectRecoveryMetadata(const catalog::RandomAccessSource& source,
    AppleRecoveryCheckpointView& retained, std::string& out_error)
{
    const auto& checkpoint = retained.checkpoint;
    const auto& nxsb = checkpoint.container.superblock;
    auto& blocks = retained.metadata_blocks;
    const auto read_tree = [&](const catalog::AppleObjectLocation& root,
                              std::uint64_t map_oid,
                              std::vector<catalog::BtreeRecord>& records) {
        return ReadCheckpointTree(source, checkpoint, root, map_oid, records, blocks, out_error);
    };
    const auto read_map = [&](const catalog::AppleOmapView& map) {
        if (map.snapshot_tree_oid != 0)
            return Fail(out_error, "AppleCheckpointRetentionSnapshotsUnsupported");
        if (!ChargeRecoveryAppend(source, blocks, 1, out_error)) return false;
        blocks.push_back(map.object.physical_block);
        std::vector<catalog::BtreeRecord> records;
        return read_tree(map.tree, 0, records);
    };
    if (!read_map(checkpoint.container_object_map)) return false;
    for (const auto& volume : checkpoint.volumes)
    {
        if (!ChargeRecoveryAppend(source, blocks, 1, out_error)) return false;
        blocks.push_back(volume.superblock_object.physical_block);
        if (!read_map(volume.object_map)) return false;
        std::vector<std::byte> superblock;
        if (!ReadBlock(source, volume.superblock_object.physical_block, nxsb.block_size, superblock))
            return Fail(out_error, "AppleCheckpointRetentionUnavailable");
        if (catalog::ReadU64LE(superblock, 0xD8).value_or(1) != 0)
            return Fail(out_error, "AppleCheckpointRetentionSnapshotsUnsupported");
        std::vector<catalog::BtreeRecord> records;
        if (!read_tree(volume.root_tree, volume.object_map.object.object_id, records)) return false;
        for (const auto& record : records)
        {
            const auto key = catalog::ReadU64LE(record.key, 0);
            if (!key.has_value()) return Fail(out_error, "AppleCheckpointRetentionGraphInvalid");
        }
        std::vector<catalog::BtreeRecord> extent_records;
        if (volume.extentref_tree.has_value() &&
            !read_tree(*volume.extentref_tree, volume.object_map.object.object_id, extent_records)) return false;
        std::vector<ApplePhysicalExtentRecord> payload;
        if (!ChargeRecoveryPayloadGraph(source, records, extent_records, out_error) ||
            !ValidateApplePayloadExtentGraph(records, extent_records, nxsb.block_size,
                nxsb.block_count, payload, out_error)) return false;
        if (!ChargeRecoveryAppend(source, retained.payload_extents, payload.size(), out_error)) return false;
        retained.payload_extents.insert(retained.payload_extents.end(), payload.begin(), payload.end());
        for (const auto* optional : {&volume.snapshot_metadata_tree, &volume.file_extent_tree})
        {
            if (!optional->has_value()) continue;
            records.clear();
            if (!read_tree(**optional, volume.object_map.object.object_id, records)) return false;
            if (!records.empty())
                return Fail(out_error, "AppleCheckpointRetentionPayloadHistoryUnproven");
        }
    }
    if (!AppendSpacemanMetadataBlocks(source, checkpoint, blocks, out_error)) return false;
    std::sort(blocks.begin(), blocks.end());
    blocks.erase(std::unique(blocks.begin(), blocks.end()), blocks.end());
    auto& payload = retained.payload_extents;
    std::sort(payload.begin(), payload.end(), [](const auto& left, const auto& right) {
        return left.physical_block < right.physical_block;
    });
    std::uint64_t previous_end = 0;
    for (const auto& extent : payload)
    {
        const auto begin = extent.physical_block;
        const auto end = begin + extent.block_count;
        if (begin < previous_end || !PayloadExtentAvoidsMetadata(checkpoint, blocks, extent))
            return Fail(out_error, "AppleCheckpointRetentionPayloadOverlap");
        previous_end = end;
    }
    return true;
}

bool PayloadExtentStillOwned(const catalog::AppleCheckpointView& checkpoint,
    const ApplePhysicalExtentRecord& extent, std::uint64_t retained_xid)
{
    const auto end = extent.physical_block + extent.block_count;
    auto cursor = extent.physical_block;
    const auto& spaceman = checkpoint.spaceman;
    while (cursor < end)
    {
        const auto found = std::find_if(spaceman.chunks.begin(), spaceman.chunks.end(),
            [cursor](const auto& chunk) { return chunk.device_index == 0 && cursor >= chunk.start_block &&
                cursor - chunk.start_block < chunk.block_count; });
        if (found == spaceman.chunks.end()) return false;
        const auto chunk_end = (std::min)(end, found->start_block + found->block_count);
        auto bit = cursor - found->start_block;
        const auto end_bit = chunk_end - found->start_block;
        if (end_bit > static_cast<std::uint64_t>(found->allocation_bitmap.size()) * 8) return false;
        while (bit < end_bit)
        {
            if (bit % 8 == 0 && end_bit - bit >= 8)
            {
                if (found->allocation_bitmap[bit / 8] != std::byte{0xff}) return false;
                bit += 8;
            }
            else
            {
                if ((std::to_integer<unsigned>(found->allocation_bitmap[bit / 8]) & (1u << (bit % 8))) == 0)
                    return false;
                ++bit;
            }
        }
        cursor = chunk_end;
    }
    return std::none_of(spaceman.free_queues[1].entries.begin(), spaceman.free_queues[1].entries.end(),
        [&](const auto& entry) { return entry.xid <= retained_xid && entry.physical_block < end &&
            extent.physical_block < entry.physical_block + entry.block_count; });
}

bool RecoveryPayloadQueueContinuous(const catalog::AppleCheckpointView& before,
    const catalog::AppleCheckpointView& after, const ApplePhysicalExtentRecord& extent)
{
    for (const auto& entry : before.spaceman.free_queues[1].entries)
    {
        auto cursor = (std::max)(extent.physical_block, entry.physical_block);
        const auto end = (std::min)(extent.physical_block + extent.block_count,
            entry.physical_block + entry.block_count);
        while (cursor < end)
        {
            auto covered = cursor;
            for (const auto& next : after.spaceman.free_queues[1].entries)
                if (next.xid == entry.xid && next.physical_block <= cursor &&
                    cursor - next.physical_block < next.block_count)
                    covered = (std::max)(covered, next.physical_block + next.block_count);
            if (covered == cursor) return false;
            cursor = (std::min)(covered, end);
        }
    }
    return true;
}

bool RecoveryBlockStillOwned(const catalog::AppleCheckpointView& current,
    std::uint64_t block, std::uint64_t retained_xid)
{
    const auto bit_set = [](const std::vector<std::byte>& bitmap, std::uint64_t bit) {
        return bit / 8 < bitmap.size() &&
            (std::to_integer<unsigned>(bitmap[bit / 8]) & (1u << (bit % 8))) != 0;
    };
    const auto& spaceman = current.spaceman;
    const auto& pool = spaceman.internal_pool;
    const bool internal = block >= pool.base_block && block - pool.base_block < pool.block_count;
    if (internal)
    {
        const auto relative = block - pool.base_block;
        const auto capacity = static_cast<std::uint64_t>(current.container.superblock.block_size) * 8;
        const auto index = relative / capacity;
        if (index >= pool.active_bitmaps.size() ||
            !bit_set(pool.active_bitmaps[index].bytes, relative % capacity)) return false;
    }
    else
    {
        const auto chunk = std::find_if(spaceman.chunks.begin(), spaceman.chunks.end(),
            [block](const auto& candidate) { return candidate.device_index == 0 &&
                block >= candidate.start_block && block - candidate.start_block < candidate.block_count; });
        if (chunk == spaceman.chunks.end() ||
            !bit_set(chunk->allocation_bitmap, block - chunk->start_block)) return false;
    }
    // Even an allocated block is unavailable if this publication's floor
    // would reclaim its existing deferred-free entry.
    const auto& queue = spaceman.free_queues[internal ? 0 : 1];
    return std::none_of(queue.entries.begin(), queue.entries.end(),
        [block, retained_xid](const auto& entry) {
            return block >= entry.physical_block && block - entry.physical_block < entry.block_count &&
                entry.xid <= retained_xid;
        });
}

const catalog::AppleSpacemanFreeQueueEntry* RecoveryQueueEntry(
    const catalog::AppleCheckpointView& checkpoint, std::uint64_t block)
{
    const auto& pool = checkpoint.spaceman.internal_pool;
    const bool internal = block >= pool.base_block && block - pool.base_block < pool.block_count;
    const auto& entries = checkpoint.spaceman.free_queues[internal ? 0 : 1].entries;
    const auto entry = std::find_if(entries.begin(), entries.end(), [block](const auto& value) {
        return block >= value.physical_block && block - value.physical_block < value.block_count;
    });
    return entry == entries.end() ? nullptr : &*entry;
}

bool VerifyRecoveryContinuity(const catalog::RandomAccessSource& source,
    const AppleRecoveryCheckpointView& pin,
    const std::vector<AppleRecoveryCheckpointView>& history,
    const catalog::AppleCheckpointView& current, std::string& out_error)
{
    const auto xid = pin.checkpoint.container.superblock.xid;
    const auto* previous = &pin.checkpoint;
    if (!MaterializeRecovery(source, pin.checkpoint.spaceman.internal_pool.active_bitmaps.size(),
            sizeof(bool), out_error)) return false;
    std::vector<bool> slot_became_free(pin.checkpoint.spaceman.internal_pool.active_bitmaps.size(), false);
    while (previous->container.superblock.xid != current.container.superblock.xid)
    {
        const auto next_xid = previous->container.superblock.next_xid;
        if (next_xid <= previous->container.superblock.xid || next_xid > current.container.superblock.xid)
            return Fail(out_error, "AppleCheckpointRetentionContinuityUnavailable");
        const catalog::AppleCheckpointView* next = &current;
        if (next_xid != current.container.superblock.xid)
        {
            const auto found = std::find_if(history.begin(), history.end(), [next_xid](const auto& value) {
                return value.checkpoint.container.superblock.xid == next_xid;
            });
            if (found == history.end())
                return Fail(out_error, "AppleCheckpointRetentionContinuityUnavailable");
            next = &found->checkpoint;
        }
        for (const auto block : pin.metadata_blocks)
        {
            if (!RecoveryBlockStillOwned(*next, block, xid))
                return Fail(out_error, "AppleCheckpointRetentionReclaimed");
            // Reclamation followed by allocation can leave the final bit set.
            // A queued block must remain queued at the same retirement XID.
            const auto* before = RecoveryQueueEntry(*previous, block);
            const auto* after = RecoveryQueueEntry(*next, block);
            if (before && (!after || after->xid != before->xid))
                return Fail(out_error, "AppleCheckpointRetentionContinuityUnavailable");
        }
        for (const auto& extent : pin.payload_extents)
        {
            if (!PayloadExtentStillOwned(*next, extent, xid))
                return Fail(out_error, "AppleCheckpointRetentionReclaimed");
            if (!RecoveryPayloadQueueContinuous(*previous, *next, extent))
                return Fail(out_error, "AppleCheckpointRetentionContinuityUnavailable");
        }
        const auto& bitmaps = pin.checkpoint.spaceman.internal_pool.active_bitmaps;
        for (std::size_t index = 0; index < bitmaps.size(); ++index)
        {
            const auto& bitmap = bitmaps[index];
            bool still_active = false;
            for (const auto& active : next->spaceman.internal_pool.active_bitmaps)
            {
                if (active.rotation_index != bitmap.rotation_index) continue;
                if (slot_became_free[index] || active.xid != bitmap.xid)
                    return Fail(out_error, "AppleCheckpointRetentionContinuityUnavailable");
                still_active = true;
            }
            if (!still_active) slot_became_free[index] = true;
        }
        previous = next;
    }
    return true;
}

} // namespace

bool ValidateAppleCheckpointPayloadOwnership(
    const catalog::RandomAccessSource& source,
    const catalog::AppleCheckpointView& checkpoint,
    const std::vector<ApplePhysicalExtentRecord>& payload_extents,
    std::string& out_error) try
{
    out_error.clear();
    RecoveryBudgetErrorScope budget_error{source, out_error};
    if (!MaterializeRecovery(source, 0, 0, out_error)) return false;
    const auto& nxsb = checkpoint.container.superblock;
    if (nxsb.block_size == 0 || nxsb.block_count == 0 ||
        nxsb.block_count > source.SizeBytes() / nxsb.block_size ||
        checkpoint.container.checkpoint_map_blocks.empty() ||
        checkpoint.volumes.size() != nxsb.fs_oids.size())
        return Fail(out_error, "ApplePayloadCheckpointInvalid");

    std::vector<std::uint64_t> blocks;
    const auto append_object = [&](const catalog::AppleObjectLocation& object) {
        const auto count = object.size_bytes / nxsb.block_size;
        if (count == 0 || object.size_bytes % nxsb.block_size != 0 ||
            object.physical_block >= nxsb.block_count || count > nxsb.block_count - object.physical_block)
            return Fail(out_error, "AppleCheckpointMetadataOutsideContainer");
        if (!ChargeRecoveryAppend(source, blocks, count, out_error)) return false;
        for (std::uint32_t ordinal = 0; ordinal < count; ++ordinal)
            blocks.push_back(object.physical_block + ordinal);
        return true;
    };
    const auto read_tree = [&](const catalog::AppleObjectLocation& root, std::uint64_t map_oid,
                              std::vector<catalog::BtreeRecord>& records) {
        return ReadCheckpointTree(source, checkpoint, root, map_oid, records, blocks, out_error);
    };
    const auto read_map = [&](const catalog::AppleOmapView& map) {
        if (map.snapshot_tree_oid != 0)
            return Fail(out_error, "ApplePayloadSnapshotMetadataUnproven");
        if (!append_object(map.object)) return false;
        std::vector<catalog::BtreeRecord> records;
        return read_tree(map.tree, 0, records);
    };
    if (!read_map(checkpoint.container_object_map)) return false;
    for (const auto& volume : checkpoint.volumes)
    {
        if (!append_object(volume.superblock_object) || !read_map(volume.object_map)) return false;
        std::vector<std::byte> superblock;
        if (!ReadBlock(source, volume.superblock_object.physical_block, nxsb.block_size, superblock))
            return Fail(out_error, "ApplePayloadVolumeUnreadable");
        // Snapshot roots are not part of AppleCheckpointView's current-volume graph.
        if (catalog::ReadU64LE(superblock, 0xD8).value_or(1) != 0)
            return Fail(out_error, "ApplePayloadSnapshotMetadataUnproven");
        std::vector<catalog::BtreeRecord> records;
        if (!read_tree(volume.root_tree, volume.superblock.omap_oid, records)) return false;
        for (const auto* optional : {&volume.extentref_tree, &volume.snapshot_metadata_tree,
                                    &volume.file_extent_tree})
        {
            if (!optional->has_value()) continue;
            if (!read_tree(**optional, volume.superblock.omap_oid, records)) return false;
            if (optional == &volume.snapshot_metadata_tree && !records.empty())
                return Fail(out_error, "ApplePayloadSnapshotMetadataUnproven");
        }
    }
    if (!AppendSpacemanMetadataBlocks(source, checkpoint, blocks, out_error)) return false;
    std::sort(blocks.begin(), blocks.end());
    blocks.erase(std::unique(blocks.begin(), blocks.end()), blocks.end());
    for (const auto& extent : payload_extents)
    {
        if (!PayloadExtentAvoidsMetadata(checkpoint, blocks, extent))
            return Fail(out_error, "ApplePayloadMetadataOverlap");
        if (!PayloadExtentStillOwned(checkpoint, extent, nxsb.xid))
            return Fail(out_error, "ApplePayloadNotAllocated");
    }
    return true;
}
catch (const std::bad_alloc&) { return RecoveryAllocationFailed(source, out_error); }
catch (const std::length_error&) { return RecoveryAllocationFailed(source, out_error); }

bool LoadAppleRecoveryCheckpoints(
    const catalog::RandomAccessSource& source,
    const catalog::AppleCheckpointView& checkpoint,
    const std::vector<std::uint64_t>& required_checkpoint_xids,
    std::vector<AppleRecoveryCheckpointView>& out_checkpoints,
    std::string& out_error) try
{
    out_checkpoints.clear();
    out_error.clear();
    RecoveryBudgetErrorScope budget_error{source, out_error};
    const auto& current = checkpoint.container.superblock;
    const auto& pool = checkpoint.spaceman.internal_pool;
    std::unordered_set<std::uint64_t> loaded;
    std::vector<AppleRecoveryCheckpointView> retained;
    if (!MaterializeRecovery(source, required_checkpoint_xids.size(), sizeof(std::uint64_t), out_error))
        return false;
    auto pending = required_checkpoint_xids;
    for (std::size_t index = 0; index < pending.size(); ++index)
    {
        const auto xid = pending[index];
        if (xid == 0 || xid > current.xid)
        {
            return Fail(out_error, "AppleCheckpointRetentionInvalid");
        }
        if (xid == current.xid || loaded.find(xid) != loaded.end())
        {
            continue;
        }
        if (!MaterializeRecovery(source, 1, sizeof(std::uint64_t), out_error)) return false;
        loaded.insert(xid);
        auto old = catalog::LoadAppleCheckpointView(
            source, 0, source.SizeBytes(), out_error, xid);
        if (!old.has_value())
        {
            return Fail(out_error, "AppleCheckpointRetentionUnavailable");
        }
        const auto& nxsb = old->container.superblock;
        const auto& old_pool = old->spaceman.internal_pool;
        if (nxsb.uuid_hex != current.uuid_hex ||
            nxsb.block_size != current.block_size || nxsb.block_count != current.block_count ||
            nxsb.xp_desc_base_block != current.xp_desc_base_block ||
            nxsb.xp_desc_block_count != current.xp_desc_block_count ||
            nxsb.xp_data_base_block != current.xp_data_base_block ||
            nxsb.xp_data_block_count != current.xp_data_block_count ||
            nxsb.spaceman_oid != current.spaceman_oid ||
            old_pool.base_block != pool.base_block || old_pool.block_count != pool.block_count ||
            old_pool.bitmap_base_block != pool.bitmap_base_block ||
            old_pool.bitmap_size_blocks != pool.bitmap_size_blocks ||
            old_pool.bitmap_block_count != pool.bitmap_block_count)
        {
            return Fail(out_error, "AppleCheckpointRetentionIdentityMismatch");
        }
        if (nxsb.next_xid <= xid || nxsb.next_xid > current.xid ||
            retained.size() >= current.xp_desc_block_count)
            return Fail(out_error, "AppleCheckpointRetentionContinuityUnavailable");
        if (nxsb.next_xid != current.xid)
        {
            if (!ChargeRecoveryAppend(source, pending, 1, out_error)) return false;
            pending.push_back(nxsb.next_xid);
        }
        // The checkpoint's owned buffers were charged by its loader; moving
        // them into retained requires only the new outer element here.
        if (!ChargeRecoveryAppend(source, retained, 1, out_error)) return false;
        AppleRecoveryCheckpointView history;
        history.checkpoint = std::move(*old);
        if (!CollectRecoveryMetadata(source, history, out_error)) return false;
        for (const auto block : history.metadata_blocks)
        {
            if (!RecoveryBlockStillOwned(history.checkpoint, block, xid) ||
                !RecoveryBlockStillOwned(checkpoint, block, xid))
                return Fail(out_error, "AppleCheckpointRetentionReclaimed");
        }
        for (const auto& extent : history.payload_extents)
            if (!PayloadExtentStillOwned(history.checkpoint, extent, xid) ||
                !PayloadExtentStillOwned(checkpoint, extent, xid))
                return Fail(out_error, "AppleCheckpointRetentionReclaimed");
        retained.push_back(std::move(history));
    }
    for (const auto& pin : retained)
        if (!VerifyRecoveryContinuity(source, pin, retained, checkpoint, out_error)) return false;
    if (!retained.empty() && !VerifyAppleSpacemanOwnershipUnchanged(source, 0,
            source.SizeBytes(), checkpoint.container, checkpoint.spaceman, out_error)) return false;
    out_checkpoints = std::move(retained);
    return true;
}
catch (const std::bad_alloc&)
{
    out_checkpoints.clear();
    return RecoveryAllocationFailed(source, out_error);
}
catch (const std::length_error&)
{
    out_checkpoints.clear();
    return RecoveryAllocationFailed(source, out_error);
}

bool FindAppleVolumeReplayBoundary(
    const catalog::RandomAccessSource& source,
    const catalog::AppleCheckpointView& checkpoint,
    std::uint64_t volume_object_id,
    std::uint64_t accepted_preimage_xid,
    AppleVolumeReplayBoundary& out_boundary,
    std::string& out_error) try
{
    out_boundary = {};
    out_error.clear();
    RecoveryBudgetErrorScope budget_error{source, out_error};
    if (!MaterializeRecovery(source, 0, 0, out_error)) return false;
    const auto current_xid = checkpoint.container.superblock.xid;
    if (volume_object_id == 0 || accepted_preimage_xid == 0 ||
        accepted_preimage_xid > current_xid || current_xid == UINT64_MAX)
        return Fail(out_error, "AppleVolumeReplayPreimageInvalid");
    const auto selected_volume = [&](const catalog::AppleCheckpointView& view)
        -> const catalog::AppleVolumeCheckpointView* {
        if (view.volumes.size() != view.container.superblock.fs_oids.size()) return nullptr;
        const catalog::AppleVolumeCheckpointView* result = nullptr;
        for (const auto& volume : view.volumes)
        {
            if (volume.superblock.object_id != volume_object_id) continue;
            if (result) return nullptr;
            result = &volume;
        }
        return result;
    };
    const auto same_object = [](const catalog::AppleObjectLocation& left,
                                const catalog::AppleObjectLocation& right) {
        return left.object_id == right.object_id && left.xid == right.xid &&
            left.physical_block == right.physical_block && left.size_bytes == right.size_bytes &&
            left.type == right.type && left.subtype == right.subtype;
    };
    const auto same_optional = [&](const auto& left, const auto& right) {
        return left.has_value() == right.has_value() && (!left || same_object(*left, *right));
    };
    const auto same_roots = [&](const catalog::AppleVolumeCheckpointView& left,
                               const catalog::AppleVolumeCheckpointView& right) {
        return left.superblock.uuid_hex == right.superblock.uuid_hex &&
            same_object(left.superblock_object, right.superblock_object) &&
            same_object(left.object_map.object, right.object_map.object) &&
            same_object(left.object_map.tree, right.object_map.tree) &&
            same_object(left.root_tree, right.root_tree) &&
            same_optional(left.extentref_tree, right.extentref_tree) &&
            same_optional(left.snapshot_metadata_tree, right.snapshot_metadata_tree) &&
            same_optional(left.file_extent_tree, right.file_extent_tree);
    };
    // Re-read the endpoint so a stale or caller-edited projection cannot serve
    // as an unchanged-volume proof. Historical ownership uses this exact view.
    const auto current = catalog::LoadAppleCheckpointView(source, 0, source.SizeBytes(), out_error, current_xid);
    const auto* supplied_volume = selected_volume(checkpoint);
    const auto* current_volume = current ? selected_volume(*current) : nullptr;
    if (!supplied_volume || !current_volume || current_volume->superblock.uuid_hex.empty() ||
        current->container.superblock.uuid_hex != checkpoint.container.superblock.uuid_hex ||
        !same_roots(*supplied_volume, *current_volume))
        return Fail(out_error, "AppleVolumeReplayEndpointMismatch");
    std::vector<AppleRecoveryCheckpointView> history;
    if (!MaterializeRecovery(source, 1, sizeof(std::uint64_t), out_error)) return false;
    if (!LoadAppleRecoveryCheckpoints(source, *current, {accepted_preimage_xid}, history, out_error)) return false;
    std::sort(history.begin(), history.end(), [](const auto& left, const auto& right) {
        return left.checkpoint.container.superblock.xid < right.checkpoint.container.superblock.xid;
    });
    // Every intermediate identity must be the same volume, including history
    // after its first changed checkpoint. Absence is never equivalent to empty.
    for (const auto& entry : history)
    {
        const auto* volume = selected_volume(entry.checkpoint);
        if (!volume || volume->superblock.uuid_hex != current_volume->superblock.uuid_hex)
            return Fail(out_error, "AppleVolumeReplayIdentityMismatch");
    }
    AppleVolumeReplayBoundary result{accepted_preimage_xid, {}};
    if (!history.empty())
    {
        if (history.front().checkpoint.container.superblock.xid != accepted_preimage_xid)
            return Fail(out_error, "AppleVolumeReplayHistoryUnavailable");
        const auto* before = &history.front().checkpoint;
        for (std::size_t index = 1; index <= history.size(); ++index)
        {
            const auto& after = index == history.size() ? *current : history[index].checkpoint;
            if (before->container.superblock.next_xid != after.container.superblock.xid ||
                after.container.superblock.xid != before->container.superblock.xid + 1)
                return Fail(out_error, "AppleVolumeReplayHistoryDiscontinuous");
            if (!result.first_changed_checkpoint_xid)
            {
                if (same_roots(*selected_volume(*before), *selected_volume(after)))
                    result.preimage_checkpoint_xid = after.container.superblock.xid;
                else
                    result.first_changed_checkpoint_xid = after.container.superblock.xid;
            }
            before = &after;
        }
    }
    out_boundary = result;
    return true;
}
catch (const std::bad_alloc&)
{
    out_boundary = {};
    return RecoveryAllocationFailed(source, out_error);
}
catch (const std::length_error&)
{
    out_boundary = {};
    return RecoveryAllocationFailed(source, out_error);
}

bool PlanAppleTransactionCommit(
    const catalog::RandomAccessSource& source,
    const catalog::AppleCheckpointView& checkpoint,
    const AppleTransactionCommitRequest& request,
    AppleTransactionCommitPlan& out_plan,
    std::string& out_error) try
{
    out_plan = {};
    out_error.clear();
    RecoveryBudgetErrorScope budget_error{source, out_error};
    if (!MaterializeRecovery(source, 0, 0, out_error)) return false;
    const auto& nxsb = checkpoint.container.superblock;
    const auto& allocation = request.allocation_plan;
    if (allocation.expected_checkpoint_xid != nxsb.xid ||
        allocation.transaction_xid != nxsb.next_xid ||
        allocation.updated_spaceman.object.object_id !=
            checkpoint.spaceman.object.object_id ||
        allocation.updated_spaceman.object.type !=
            checkpoint.spaceman.object.type ||
        allocation.updated_spaceman.object.subtype !=
            checkpoint.spaceman.object.subtype ||
        allocation.updated_spaceman.object.xid != allocation.transaction_xid ||
        request.next_object_id < nxsb.next_oid)
    {
        return Fail(out_error, "AppleTransactionAllocationIdentityInvalid");
    }
    if (!ValidateMainWriteCoverage(allocation,
            request.allocated_main_writes, nxsb.block_size, out_error))
    {
        return false;
    }

    std::vector<AppleRecoveryCheckpointView> retained;
    if (!LoadAppleRecoveryCheckpoints(source, checkpoint,
            request.required_checkpoint_xids, retained, out_error))
    {
        return false;
    }
    auto required_floor = nxsb.xid;
    for (const auto& old : retained)
    {
        required_floor = (std::min)(required_floor, old.checkpoint.container.superblock.xid);
        for (const auto& bitmap : old.checkpoint.spaceman.internal_pool.active_bitmaps)
        {
            const auto& protected_indices =
                allocation.effective_protected_internal_pool_bitmap_indices;
            if (std::find(protected_indices.begin(), protected_indices.end(),
                    bitmap.rotation_index) == protected_indices.end())
            {
                return Fail(out_error, "AppleTransactionRetentionProtectionMissing");
            }
        }
    }
    if (!retained.empty() &&
        (allocation.effective_oldest_required_checkpoint_xid == 0 ||
         allocation.effective_oldest_required_checkpoint_xid > required_floor))
    {
        return Fail(out_error, "AppleTransactionRetentionProtectionMissing");
    }

    AppleCheckpointPublicationRequest publication;
    publication.expected_checkpoint_xid = nxsb.xid;
    publication.transaction_xid = allocation.transaction_xid;
    publication.next_object_id = request.next_object_id;
    publication.container_object_map_oid = request.container_object_map_oid;
    publication.required_checkpoint_xids = request.required_checkpoint_xids;
    for (const auto& old : retained)
        publication.required_checkpoint_xids.push_back(old.checkpoint.container.superblock.xid);
    publication.allocator_owned_writes = request.allocated_main_writes;

    std::unordered_map<std::uint64_t, AppleCheckpointEphemeralObject> objects;
    for (const auto& object : request.additional_ephemeral_objects)
    {
        if (!AddEphemeral(object, objects, out_error))
        {
            return false;
        }
    }
    AppleCheckpointEphemeralObject spaceman;
    spaceman.object = allocation.updated_spaceman.object;
    spaceman.object.physical_block = 0;
    spaceman.object.size_bytes = static_cast<std::uint32_t>(
        allocation.updated_spaceman.bytes.size());
    spaceman.bytes = allocation.updated_spaceman.bytes;
    if (!AddEphemeral(std::move(spaceman), objects, out_error))
    {
        return false;
    }

    std::unordered_set<std::uint64_t> rebuilt_queue_roots;
    for (const auto& write : allocation.writes)
    {
        if (write.kind == AppleSpacemanWriteKind::FreeQueueTree)
        {
            if (!write.object_location.has_value() || write.physical_block != 0)
            {
                return Fail(out_error,
                    "AppleTransactionAllocatorWriteInvalid");
            }
            AppleCheckpointEphemeralObject object;
            object.object = write.object_location.value();
            object.object.physical_block = 0;
            object.bytes = write.bytes;
            if (!AddEphemeral(std::move(object), objects, out_error))
            {
                return false;
            }
        }
        else
        {
            if (write.physical_block == 0 ||
                write.bytes.size() != nxsb.block_size ||
                write.object_location.has_value())
            {
                return Fail(out_error,
                    "AppleTransactionAllocatorWriteInvalid");
            }
            publication.allocator_owned_writes.push_back(
                {write.physical_block, write.bytes});
        }
    }
    for (const auto& queue : allocation.updated_spaceman.free_queues)
    {
        if (queue.tree_oid != 0 && objects.find(queue.tree_oid) != objects.end())
        {
            rebuilt_queue_roots.insert(queue.tree_oid);
        }
    }

    std::unordered_set<std::uint64_t> retired;
    for (const auto& old_queue : checkpoint.spaceman.free_queues)
    {
        if (old_queue.tree_oid == 0 ||
            rebuilt_queue_roots.find(old_queue.tree_oid) ==
                rebuilt_queue_roots.end())
        {
            continue;
        }
        for (const auto physical_block : old_queue.tree_blocks)
        {
            const auto mapping = std::find_if(
                checkpoint.container.mappings.begin(),
                checkpoint.container.mappings.end(),
                [physical_block](const auto& candidate) {
                    return candidate.physical_block == physical_block;
                });
            if (mapping == checkpoint.container.mappings.end())
            {
                return Fail(out_error,
                    "AppleTransactionOldQueueMappingMissing");
            }
            if (objects.find(mapping->object_id) == objects.end())
            {
                retired.insert(mapping->object_id);
            }
        }
    }

    for (const auto& mapping : checkpoint.container.mappings)
    {
        if (objects.find(mapping.object_id) != objects.end() ||
            retired.find(mapping.object_id) != retired.end())
        {
            continue;
        }
        AppleCheckpointEphemeralObject object;
        object.file_system_oid = mapping.file_system_oid;
        object.object.object_id = mapping.object_id;
        object.object.xid = allocation.transaction_xid;
        object.object.type = mapping.type;
        object.object.subtype = mapping.subtype;
        object.object.size_bytes = mapping.size_bytes;
        if (!ReadMappedObject(source, nxsb, mapping, object.bytes))
        {
            return Fail(out_error, "AppleTransactionEphemeralReadFailed");
        }
        PutU64(object.bytes, 0x10, allocation.transaction_xid);
        if (!FinalizeAppleObjectChecksum(object.bytes, out_error) ||
            !AddEphemeral(std::move(object), objects, out_error))
        {
            return false;
        }
    }

    publication.retired_ephemeral_object_ids.assign(
        retired.begin(), retired.end());
    std::sort(publication.retired_ephemeral_object_ids.begin(),
        publication.retired_ephemeral_object_ids.end());
    publication.ephemeral_objects.reserve(objects.size());
    for (auto& [object_id, object] : objects)
    {
        (void)object_id;
        publication.ephemeral_objects.push_back(std::move(object));
    }
    std::sort(publication.ephemeral_objects.begin(),
        publication.ephemeral_objects.end(), [](const auto& left,
                                                 const auto& right) {
            return left.object.object_id < right.object.object_id;
        });

    AppleTransactionCommitPlan plan;
    if (!PlanAppleCheckpointPublication(source, checkpoint.container,
            publication, plan.publication, out_error))
    {
        return false;
    }
    const auto add_guard = [&](std::uint64_t block) {
        return AddStableGuard(source, block, nxsb.block_size,
            plan.publication.guard_blocks);
    };
    for (const auto& old : retained)
    {
        for (const auto& extent : old.payload_extents)
        {
            const auto end = extent.physical_block + extent.block_count;
            if (std::any_of(plan.publication.before_superblock_writes.begin(),
                    plan.publication.before_superblock_writes.end(), [&](const auto& write) {
                        return write.physical_block < end && extent.physical_block <
                            write.physical_block + write.bytes.size() / nxsb.block_size;
                    }))
                return Fail(out_error, "AppleTransactionRetainedBlockReused");
        }
        for (const auto block : old.metadata_blocks)
        {
            if (std::any_of(plan.publication.before_superblock_writes.begin(),
                    plan.publication.before_superblock_writes.end(),
                    [block](const auto& write) { return write.physical_block == block; }))
            {
                return Fail(out_error, "AppleTransactionRetainedBlockReused");
            }
            if (!add_guard(block))
            {
                return Fail(out_error, "AppleTransactionGuardUnreadable");
            }
        }
    }
    for (const auto& cab : checkpoint.spaceman.devices[0].cabs)
    {
        if (!add_guard(cab.object.physical_block))
        {
            return Fail(out_error, "AppleTransactionGuardUnreadable");
        }
    }
    for (const auto& cib : checkpoint.spaceman.devices[0].cibs)
    {
        if (!add_guard(cib.object.physical_block))
        {
            return Fail(out_error, "AppleTransactionGuardUnreadable");
        }
    }
    for (const auto& chunk : checkpoint.spaceman.chunks)
    {
        if (chunk.bitmap_block != 0 && !add_guard(chunk.bitmap_block))
        {
            return Fail(out_error, "AppleTransactionGuardUnreadable");
        }
    }
    for (const auto& bitmap :
         checkpoint.spaceman.internal_pool.active_bitmaps)
    {
        if (!add_guard(bitmap.physical_block))
        {
            return Fail(out_error, "AppleTransactionGuardUnreadable");
        }
    }
    out_plan = std::move(plan);
    return true;
}
catch (const std::bad_alloc&)
{
    out_plan = {};
    return RecoveryAllocationFailed(source, out_error);
}
catch (const std::length_error&)
{
    out_plan = {};
    return RecoveryAllocationFailed(source, out_error);
}

} // namespace apfsaccess::rw
