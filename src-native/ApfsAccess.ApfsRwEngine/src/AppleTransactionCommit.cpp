#include "AppleTransactionCommit.h"
#include "AppleCapacityPreviewInternal.h"
#include "AppleVolumeTransaction.h"
#include "AppleReadOnlyRetention.h"
#include "AppleReadOnlyRecordGraph.h"
#include "ApfsReadOnlyMetadataAdmission.h"

#include "ApfsTransactionWriter.h"
#include "ApfsExtendedRecordCodec.h"
#include "ApfsSharedSpace.h"
#include "SnapshotPlanningSource.h"
#include "ProfileRetentionContinuity.h"
#include "ApfsFusionStore.h"

#include <algorithm>
#include <limits>
#include <map>
#include <set>
#include <tuple>
#include <new>
#include <stdexcept>
#include <unordered_map>
#include <unordered_set>

namespace apfsaccess::rw
{
enum class RetentionAdmission { Strict, ReadOnlyInactiveTreeDefaults };

static bool HasPhysicalSnapshotMetadata(const catalog::AppleVolumeCheckpointView& volume) {
    return volume.snapshot_metadata_tree &&
        volume.superblock.snap_meta_tree_type == (catalog::kObjectPhysical | catalog::kObjectTypeBtree) &&
        volume.snapshot_metadata_tree->type == volume.superblock.snap_meta_tree_type &&
        volume.snapshot_metadata_tree->subtype == catalog::kObjectTypeSnapMetaTree &&
        volume.snapshot_metadata_tree->object_id == volume.superblock.snap_meta_tree_oid &&
        volume.snapshot_metadata_tree->physical_block == volume.superblock.snap_meta_tree_oid;
}

static bool LoadAppleSnapshotRetentionImpl(const catalog::RandomAccessSource& source,
    const catalog::AppleCheckpointView& checkpoint, AppleSnapshotRetentionView& out_retention,
    std::string& out_error, bool authoritative,
    std::shared_ptr<const std::vector<SnapshotRetentionCatalog>>* out_catalogs = nullptr,
    RetentionAdmission admission = RetentionAdmission::Strict);
static bool BorrowCompletedSnapshotRetention(const catalog::RandomAccessSource& source,
    const catalog::AppleCheckpointView& checkpoint, AppleSnapshotRetentionView& retention,
    std::shared_ptr<const std::vector<SnapshotRetentionCatalog>>* catalogs,
    bool authoritative, bool& found, std::string& error,
    RetentionAdmission admission = RetentionAdmission::Strict);
static bool EnsureSnapshotCurrentOwners(const catalog::RandomAccessSource& source,
    const catalog::AppleCheckpointView& checkpoint, std::string& error,
    RetentionAdmission admission = RetentionAdmission::Strict);
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

bool CheckRecoveryExtendedSnapshotMetadata(const catalog::RandomAccessSource& source,
    const catalog::AppleCheckpointView& checkpoint, std::string& error)
{
    const auto& nx = checkpoint.container.superblock;
    if (nx.block_size < 0x3F0 || !nx.block_count ||
        nx.block_count > source.SizeBytes() / nx.block_size)
        return Fail(error, "AppleSnapshotRetentionGeometryInvalid");
    // Reread only this admission field; the checkpoint/owner readers validate
    // the complete APSB. Empty inventories and borrowed proofs still need it.
    for (const auto& volume : checkpoint.volumes) {
        const auto block = volume.superblock_object.physical_block;
        std::vector<std::byte> bytes;
        if (!block || block >= nx.block_count ||
            !source.Read(block * nx.block_size + 0x3E8, 8, bytes) || bytes.size() != 8) {
            const auto budget = source.ReadBudget();
            return Fail(error, budget && budget->Failed() ? budget->Failure() :
                "AppleSnapshotRetentionApsbUnreadable");
        }
        if (volume.superblock.snap_meta_ext_oid != 0 || catalog::ReadU64LE(bytes, 0).value() != 0)
            return Fail(error, "SnapshotExtendedMetadataUnsupported");
    }
    return true;
}

// Key, three tree links, and conservative flag/alignment storage. Reserve the
// same node allowance for the sentinel, in addition to the set's header.
constexpr std::uint64_t kGuardIndexNodeBytes = sizeof(std::uint64_t) + 5 * sizeof(void*);

bool AddStableGuard(const catalog::RandomAccessSource& source,
    std::uint64_t block, std::uint32_t block_size,
    std::vector<AppleCheckpointGuardBlock>& guards,
    std::set<std::uint64_t>& index)
{
    if (index.contains(block))
    {
        return true;
    }
    AppleCheckpointGuardBlock guard;
    guard.physical_block = block;
    if (const auto budget = source.ReadBudget();
        budget && !budget->Materialize(2, sizeof(AppleCheckpointGuardBlock) + kGuardIndexNodeBytes)) return false;
    if (!ReadBlock(source, block, block_size, guard.bytes))
    {
        return false;
    }
    guards.push_back(std::move(guard));
    index.insert(block);
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
    std::uint32_t block_size, std::string& out_error,
    std::span<const std::uint64_t> capacity_payload = {})
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
    for (const auto block : capacity_payload)
        if (allocated.find(block) == allocated.end() || !covered.insert(block).second)
            return Fail(out_error, "AppleTransactionMainWriteInvalid");
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

bool AppendRetirementRecoveryOwners(const catalog::RandomAccessSource& source,
    const catalog::AppleCheckpointView& checkpoint, std::vector<std::uint64_t>& metadata,
    std::vector<ApplePhysicalExtentRecord>& payload, std::string& error,
    RetentionAdmission admission = RetentionAdmission::Strict);

bool CollectRecoveryMetadata(const catalog::RandomAccessSource& source,
    const catalog::AppleCheckpointView& checkpoint, std::vector<std::uint64_t>& blocks,
    std::vector<ApplePhysicalExtentRecord>& retained_payload, std::string& out_error, bool snapshot_aware = false,
    RetentionAdmission admission = RetentionAdmission::Strict)
{
    if (!CheckRecoveryExtendedSnapshotMetadata(source, checkpoint, out_error)) return false;
    if (snapshot_aware) {
        // The conservative descriptor closure includes the complete canonical
        // live/snapshot census as well as hidden historical OMAP edges.
        if (!AppendRetirementRecoveryOwners(source, checkpoint, blocks, retained_payload, out_error, admission) ||
            !AppendSpacemanMetadataBlocks(source, checkpoint, blocks, out_error)) return false;
        std::sort(blocks.begin(), blocks.end());
        blocks.erase(std::unique(blocks.begin(), blocks.end()), blocks.end());
        return true;
    }
    const auto& nxsb = checkpoint.container.superblock;
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
        if (!ChargeRecoveryAppend(source, retained_payload, payload.size(), out_error)) return false;
        retained_payload.insert(retained_payload.end(), payload.begin(), payload.end());
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
    auto& payload = retained_payload;
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

bool PayloadExtentStillOwned(const catalog::AppleSpacemanView& spaceman,
    const ApplePhysicalExtentRecord& extent, std::uint64_t retained_xid, std::uint64_t tier_base = 0)
{
    const unsigned device = tier_base && extent.physical_block >= tier_base ? 1u : 0u;
    const auto base = device ? tier_base : 0;
    const auto end = extent.physical_block - base + extent.block_count;
    auto cursor = extent.physical_block - base;
    while (cursor < end)
    {
        const auto found = std::find_if(spaceman.chunks.begin(), spaceman.chunks.end(),
            [cursor, device](const auto& chunk) { return chunk.device_index == device && cursor >= chunk.start_block &&
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
    const auto& queue = spaceman.free_queues[device ? 2 : 1];
    return std::none_of(queue.entries.begin(), queue.entries.end(),
        [&](const auto& entry) { return entry.xid <= retained_xid && entry.physical_block < end + base &&
            extent.physical_block < entry.physical_block + entry.block_count; });
}

bool RecoveryPayloadQueueContinuous(const catalog::AppleCheckpointView& before,
    const catalog::AppleCheckpointView& after, const ApplePhysicalExtentRecord& extent, bool fusion = false)
{
    const auto queue = fusion && extent.physical_block >= catalog::kFusionTier2ByteAddress / before.container.superblock.block_size ? 2u : 1u;
    for (const auto& entry : before.spaceman.free_queues[queue].entries)
    {
        auto cursor = (std::max)(extent.physical_block, entry.physical_block);
        const auto end = (std::min)(extent.physical_block + extent.block_count,
            entry.physical_block + entry.block_count);
        while (cursor < end)
        {
            auto covered = cursor;
            for (const auto& next : after.spaceman.free_queues[queue].entries)
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
    std::uint64_t block, std::uint64_t retained_xid, bool fusion = false)
{
    const auto bit_set = [](const std::vector<std::byte>& bitmap, std::uint64_t bit) {
        return bit / 8 < bitmap.size() &&
            (std::to_integer<unsigned>(bitmap[bit / 8]) & (1u << (bit % 8))) != 0;
    };
    const auto& spaceman = current.spaceman;
    const auto& pool = spaceman.internal_pool;
    const auto tier = fusion ? catalog::kFusionTier2ByteAddress / current.container.superblock.block_size : 0;
    const unsigned device = tier && block >= tier ? 1u : 0u;
    const auto local = block - (device ? tier : 0);
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
            [local, device](const auto& candidate) { return candidate.device_index == device &&
                local >= candidate.start_block && local - candidate.start_block < candidate.block_count; });
        if (chunk == spaceman.chunks.end() ||
            !bit_set(chunk->allocation_bitmap, local - chunk->start_block)) return false;
    }
    // Even an allocated block is unavailable if this publication's floor
    // would reclaim its existing deferred-free entry.
    const auto& queue = spaceman.free_queues[internal ? 0 : device ? 2 : 1];
    return std::none_of(queue.entries.begin(), queue.entries.end(),
        [block, retained_xid](const auto& entry) {
            return block >= entry.physical_block && block - entry.physical_block < entry.block_count &&
                entry.xid <= retained_xid;
        });
}

const catalog::AppleSpacemanFreeQueueEntry* RecoveryQueueEntry(
    const catalog::AppleCheckpointView& checkpoint, std::uint64_t block, bool fusion = false)
{
    const auto& pool = checkpoint.spaceman.internal_pool;
    const bool internal = block >= pool.base_block && block - pool.base_block < pool.block_count;
    const bool tier = fusion && block >= catalog::kFusionTier2ByteAddress / checkpoint.container.superblock.block_size;
    const auto& entries = checkpoint.spaceman.free_queues[internal ? 0 : tier ? 2 : 1].entries;
    const auto entry = std::find_if(entries.begin(), entries.end(), [block](const auto& value) {
        return block >= value.physical_block && block - value.physical_block < value.block_count;
    });
    return entry == entries.end() ? nullptr : &*entry;
}

bool VerifyRecoveryContinuity(const catalog::RandomAccessSource& source,
    const AppleRecoveryCheckpointView& pin,
    const std::vector<AppleRecoveryCheckpointView>& history,
    const catalog::AppleCheckpointView& current, std::string& out_error, bool fusion = false)
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
            if (!RecoveryBlockStillOwned(*next, block, xid, fusion))
                return Fail(out_error, "AppleCheckpointRetentionReclaimed");
            // Reclamation followed by allocation can leave the final bit set.
            // A queued block must remain queued at the same retirement XID.
            const auto* before = RecoveryQueueEntry(*previous, block, fusion);
            const auto* after = RecoveryQueueEntry(*next, block, fusion);
            if (before && (!after || after->xid != before->xid))
                return Fail(out_error, "AppleCheckpointRetentionContinuityUnavailable");
        }
        for (const auto& extent : pin.payload_extents)
        {
            if (!PayloadExtentStillOwned(next->spaceman, extent, xid,
                fusion ? catalog::kFusionTier2ByteAddress / next->container.superblock.block_size : 0))
                return Fail(out_error, "AppleCheckpointRetentionReclaimed");
            if (!RecoveryPayloadQueueContinuous(*previous, *next, extent, fusion))
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

bool VerifyProfileRecoveryContinuity(const catalog::RandomAccessSource& source,
    const AppleRecoveryCheckpointView& pin, const std::vector<AppleRecoveryCheckpointView>& history,
    const catalog::AppleCheckpointView& current, bool fusion, std::string& error)
{
    const auto& checkpoint = pin.checkpoint;
    const auto xid = checkpoint.container.superblock.xid;
    if (!MaterializeRecovery(source,pin.metadata_blocks.size()+pin.payload_extents.size(),0,error)) return false;
    for (const auto block : pin.metadata_blocks)
        if (!RecoveryBlockStillOwned(checkpoint,block,xid,fusion)) return Fail(error,"AppleCheckpointRetentionReclaimed");
    for (const auto& e : pin.payload_extents)
        if (!PayloadExtentStillOwned(checkpoint.spaceman,e,xid,
                fusion ? catalog::kFusionTier2ByteAddress/checkpoint.container.superblock.block_size : 0) ||
            (!fusion && !PayloadExtentAvoidsMetadata(checkpoint,pin.metadata_blocks,e)))
            return Fail(error,"AppleCheckpointRetentionPayloadOverlapOrReclaimed");
    return VerifyRecoveryContinuity(source, pin, history, current, error, fusion);
}

static bool LoadAppleSnapshotRetentionImpl(const catalog::RandomAccessSource& source,
    const catalog::AppleCheckpointView& checkpoint,
    AppleSnapshotRetentionView& out_retention, std::string& out_error, bool authoritative,
    std::shared_ptr<const std::vector<SnapshotRetentionCatalog>>* out_catalogs,
    RetentionAdmission admission) try
{
    const auto validate_payload = admission == RetentionAdmission::Strict ? ValidateApplePayloadExtentGraph : ValidateAppleReadOnlyPayloadExtentGraph;
    const auto resolve_layer = admission == RetentionAdmission::Strict ? ResolveAppleSnapshotExtentLayer : ResolveAppleReadOnlySnapshotExtentLayer;
    out_retention = {};
    if (out_catalogs) out_catalogs->reset();
    out_error.clear();
    if (!source.ReadBudget()) {
        auto budget = std::make_shared<catalog::ApfsReadBudget>(65536, 256ull << 20,
            1000000, 256ull << 20);
        catalog::BudgetedRandomAccessSource bounded(source, budget);
        return LoadAppleSnapshotRetentionImpl(bounded, checkpoint, out_retention, out_error, authoritative, out_catalogs, admission);
    }
    RecoveryBudgetErrorScope budget_error{source, out_error};
    if (!CheckRecoveryExtendedSnapshotMetadata(source, checkpoint, out_error)) return false;
    bool borrowed = false;
    if (!BorrowCompletedSnapshotRetention(source, checkpoint, out_retention, out_catalogs,
            authoritative, borrowed, out_error, admission)) return false;
    if (borrowed) return true;
    const auto& nx = checkpoint.container.superblock;
    if (!nx.block_size || !nx.block_count || nx.block_count > source.SizeBytes() / nx.block_size)
        return Fail(out_error, "AppleSnapshotRetentionGeometryInvalid");
    if (checkpoint.container_object_map.snapshot_tree_oid != 0)
        return Fail(out_error, "AppleSnapshotRetentionContainerSnapshotsUnsupported");
    bool any_snapshots = false;
    for (const auto& volume : checkpoint.volumes) {
        std::vector<std::byte> apsb;
        std::vector<catalog::BtreeRecord> inventory;
        std::vector<std::uint64_t> visited;
        if (!ReadBlock(source, volume.superblock_object.physical_block, nx.block_size, apsb))
            return Fail(out_error, "AppleSnapshotRetentionApsbUnreadable");
        if (volume.snapshot_metadata_tree && !ReadCheckpointTree(source, checkpoint,
            *volume.snapshot_metadata_tree, volume.superblock.omap_oid, inventory, visited, out_error)) return false;
        any_snapshots |= catalog::ReadU64LE(apsb, 0xD8).value_or(1) != 0 ||
            volume.object_map.snapshot_tree_oid != 0 || !inventory.empty();
    }
    if (!any_snapshots) return true;
    AppleSnapshotRetentionView result;
    std::vector<SnapshotRetentionCatalog> completed_catalogs;
    struct PayloadOwner { std::uint64_t volume; ApplePhysicalExtentRecord extent; };
    std::vector<PayloadOwner> owners;
    std::vector<std::uint64_t> collision_metadata;
    for (const auto& volume : checkpoint.volumes) {
        std::vector<std::byte> apsb;
        if (!ReadBlock(source, volume.superblock_object.physical_block, nx.block_size, apsb))
            return Fail(out_error, "AppleSnapshotRetentionApsbUnreadable");
        std::vector<catalog::BtreeRecord> inventory;
        if (volume.snapshot_metadata_tree && !ReadCheckpointTree(source, checkpoint,
            *volume.snapshot_metadata_tree, volume.superblock.omap_oid, inventory,
            collision_metadata, out_error)) return false;
        const bool has_snapshots = catalog::ReadU64LE(apsb, 0xD8).value_or(1) != 0 ||
            volume.object_map.snapshot_tree_oid != 0 || !inventory.empty();
        catalog::ApfsSnapshotScope scope{0, nx.block_count * nx.block_size,
            nx.uuid_hex, volume.superblock.uuid_hex, volume.superblock.object_id, nx.xid};
        catalog::AppleSnapshotCatalogRecords catalog;
        // Every peer must pass canonical layout, OMAP and tree admission before
        // its catalog can become reusable ownership evidence.
        if (!(admission == RetentionAdmission::Strict && !HasPhysicalSnapshotMetadata(volume) ?
            catalog::LoadAppleSnapshotCatalog(source, checkpoint, volume.superblock.object_id, catalog, out_error) :
            catalog::LoadAppleReadOnlySnapshotCatalog(source, checkpoint, volume.superblock.object_id, catalog, out_error))) return false;
        if (!ChargeRecoveryAppend(source, result.metadata_blocks, catalog.metadata_blocks.size(), out_error) ||
            !ChargeRecoveryAppend(source, collision_metadata, catalog.metadata_blocks.size(), out_error)) return false;
        result.metadata_blocks.insert(result.metadata_blocks.end(), catalog.metadata_blocks.begin(), catalog.metadata_blocks.end());
        collision_metadata.insert(collision_metadata.end(), catalog.metadata_blocks.begin(), catalog.metadata_blocks.end());
        std::vector<ApplePhysicalExtentRecord> prior, history;
        std::vector<std::vector<ApplePhysicalExtentRecord>> snapshot_payloads;
        for (std::size_t i = 0; i < catalog.inventory.size(); ++i) {
            const auto& snapshot = catalog.inventory[i];
            const auto& records = catalog.snapshots[i];
            std::vector<ApplePhysicalExtentRecord> payload;
            const auto& previous=out_catalogs && !snapshot_payloads.empty() ? snapshot_payloads.back() : prior;
            if (!ChargeRecoveryPayloadGraph(source, records.filesystem, records.extentref, out_error) ||
                !MaterializeRecovery(source, previous.size() + history.size(), 2048, out_error) ||
                !resolve_layer(previous, history, records.filesystem, records.extentref,
                    nx.block_size, nx.block_count, payload, out_error)) return false;
            catalog::ApfsSnapshotIdentity identity{scope, snapshot.xid, snapshot.name_utf8,
                snapshot.volume.superblock_object.physical_block, snapshot.volume.object_map.object.physical_block,
                snapshot.volume.object_map.tree.physical_block, snapshot.volume.root_tree.object_id,
                snapshot.volume.root_tree.physical_block, snapshot.volume.extentref_tree->physical_block};
            if (!ChargeRecoveryAppend(source, result.identities, 1, out_error) ||
                !MaterializeRecovery(source, identity.name_utf8.size() +
                    identity.scope.container_uuid_hex.size() + identity.scope.volume_uuid_hex.size(), 1, out_error) ||
                !ChargeRecoveryAppend(source, result.payload_extents, payload.size(), out_error)) return false;
            if (!ChargeRecoveryAppend(source, owners, payload.size(), out_error) ||
                !ChargeRecoveryAppend(source, history, payload.size(), out_error)) return false;
            for (const auto& extent : payload) owners.push_back({volume.superblock.object_id, extent});
            history.insert(history.end(), payload.begin(), payload.end());
            result.identities.push_back(std::move(identity));
            result.payload_extents.insert(result.payload_extents.end(), payload.begin(), payload.end());
            if(out_catalogs) {
                if(!ChargeRecoveryAppend(source,snapshot_payloads,1,out_error))return false;
                snapshot_payloads.push_back(std::move(payload));
            } else {
                if(!MaterializeRecovery(source,payload.size(),sizeof(ApplePhysicalExtentRecord),out_error))return false;
                prior=std::move(payload);
            }
        }
        // Current mappings are ownership evidence too. An allocated block may
        // still belong to a sibling payload or masquerade as snapshot metadata.
        auto live_fs = std::move(catalog.live.filesystem);
        auto live_refs = std::move(catalog.live.extentref);
        std::vector<ApplePhysicalExtentRecord> live_payload;
        const auto& previous=out_catalogs && !snapshot_payloads.empty() ? snapshot_payloads.back() : prior;
        if (!ChargeRecoveryPayloadGraph(source, live_fs, live_refs, out_error) ||
            !MaterializeRecovery(source, previous.size() + history.size(), 2048, out_error) ||
            !(has_snapshots ? resolve_layer(previous, history, live_fs, live_refs,
                nx.block_size, nx.block_count, live_payload, out_error) :
              validate_payload(live_fs, live_refs, nx.block_size, nx.block_count, live_payload, out_error)) ||
            !ChargeRecoveryAppend(source, owners, live_payload.size(), out_error)) return false;
        for (const auto& extent : live_payload) owners.push_back({volume.superblock.object_id, extent});
        if (out_catalogs) {
            if (!ChargeRecoveryAppend(source, completed_catalogs, 1, out_error)) return false;
            catalog.live.filesystem = std::move(live_fs); catalog.live.extentref = std::move(live_refs);
            completed_catalogs.push_back({volume.superblock.object_id, std::move(catalog), std::move(live_payload),std::move(snapshot_payloads)});
            const auto* base = &source;
            while (const auto* overlay = dynamic_cast<const SnapshotPublicationSource*>(base)) base = &overlay->Base();
            if (dynamic_cast<const SnapshotPlanningSource*>(base)) {
                auto& completed = completed_catalogs.back();
                if (!ChargeRecoveryAppend(source, completed.metadata_preimages,
                        completed.records.metadata_blocks.size(), out_error)) return false;
                for (const auto block : completed.records.metadata_blocks) {
                    if (!MaterializeRecovery(source, 1, nx.block_size, out_error)) return false;
                    std::vector<std::byte> actual;
                    if (!ReadBlock(source, block, nx.block_size, actual)) return false;
                    completed.metadata_preimages.emplace_back(block, std::move(actual));
                }
            }
        }
    }
    if (result.identities.empty()) return true;
    // Include every sibling's current metadata in the alias proof. Snapshot
    // payload must never masquerade as a sibling tree or allocator metadata.
    const auto add = [&](const catalog::AppleObjectLocation& object) {
        if (!ChargeRecoveryAppend(source, collision_metadata, 1, out_error)) return false;
        collision_metadata.push_back(object.physical_block); return true;
    };
    const auto tree = [&](const catalog::AppleObjectLocation& object, std::uint64_t map) {
        std::vector<catalog::BtreeRecord> records;
        return ReadCheckpointTree(source, checkpoint, object, map, records, collision_metadata, out_error);
    };
    if (!add(checkpoint.container_object_map.object) || !tree(checkpoint.container_object_map.tree, 0)) return false;
    for (const auto& volume : checkpoint.volumes) {
        if (!add(volume.superblock_object) || !add(volume.object_map.object) ||
            !tree(volume.object_map.tree, 0)) return false;
        // Inventory, live FS and extentref footprints came from the completed
        // walks above. The optional file-extent tree has not yet been walked.
        for (const auto* root : {&volume.file_extent_tree})
            if (*root && !tree(**root, volume.superblock.omap_oid)) return false;
    }
    std::vector<std::uint64_t> allocator_metadata;
    if (!AppendSpacemanMetadataBlocks(source, checkpoint, allocator_metadata, out_error) ||
        !ChargeRecoveryAppend(source, collision_metadata, allocator_metadata.size() + result.metadata_blocks.size(), out_error)) return false;
    collision_metadata.insert(collision_metadata.end(), allocator_metadata.begin(), allocator_metadata.end());
    std::sort(allocator_metadata.begin(), allocator_metadata.end());
    collision_metadata.insert(collision_metadata.end(), result.metadata_blocks.begin(), result.metadata_blocks.end());
    std::sort(collision_metadata.begin(), collision_metadata.end());
    std::sort(result.metadata_blocks.begin(), result.metadata_blocks.end());
    result.metadata_blocks.erase(std::unique(result.metadata_blocks.begin(), result.metadata_blocks.end()),
        result.metadata_blocks.end());
    for (const auto block : result.metadata_blocks) {
        ApplePhysicalExtentRecord extent{block, 1, kApplePhysicalExtentKindNew, 1, 1};
        // Require main-pool ownership and no queue debt at the current XID.
        if (!PayloadExtentAvoidsMetadata(checkpoint, allocator_metadata, extent) ||
            !PayloadExtentStillOwned(checkpoint.spaceman, extent, nx.xid))
            return Fail(out_error, "AppleSnapshotRetentionMetadataNotOwned");
    }
    struct OwnerEvent { std::uint64_t block, volume; int delta; };
    std::vector<OwnerEvent> events;
    if (!MaterializeRecovery(source, owners.size(), 2 * sizeof(OwnerEvent), out_error)) return false;
    for (const auto& owner : owners) {
        const auto& extent = owner.extent;
        events.push_back({extent.physical_block, owner.volume, 1});
        events.push_back({extent.physical_block + extent.block_count, owner.volume, -1});
        if (!PayloadExtentAvoidsMetadata(checkpoint, collision_metadata, extent))
            return Fail(out_error, "AppleSnapshotRetentionPayloadMetadataOverlap");
        if (!PayloadExtentStillOwned(checkpoint.spaceman, extent, nx.xid))
            return Fail(out_error, "AppleSnapshotRetentionPayloadNotOwned");
    }
    std::sort(events.begin(), events.end(), [](const auto& a, const auto& b) { return a.block < b.block; });
    std::unordered_map<std::uint64_t, std::int64_t> active;
    for (std::size_t i = 0; i < events.size();) {
        const auto block = events[i].block;
        do {
            const auto event = events[i++];
            auto& count = active[event.volume]; count += event.delta;
            if (count == 0) active.erase(event.volume);
        } while (i < events.size() && events[i].block == block);
        if (active.size() > 1) return Fail(out_error, "AppleSnapshotRetentionCrossVolumePayloadOverlap");
    }
    if (authoritative && !VerifyAppleSpacemanOwnershipUnchanged(source, 0, source.SizeBytes(),
        checkpoint.container, checkpoint.spaceman, out_error)) return false;
    out_retention = std::move(result);
    if (out_catalogs) {
        if (!MaterializeRecovery(source, 1, sizeof(completed_catalogs), out_error)) { out_retention={}; return false; }
        *out_catalogs = std::make_shared<const std::vector<SnapshotRetentionCatalog>>(std::move(completed_catalogs));
    }
    return true;
}
catch (const std::bad_alloc&) { out_retention = {}; return RecoveryAllocationFailed(source, out_error); }
catch (const std::length_error&) { out_retention = {}; return RecoveryAllocationFailed(source, out_error); }

bool LoadAppleSnapshotRetention(const catalog::RandomAccessSource& source,
    const catalog::AppleCheckpointView& checkpoint, AppleSnapshotRetentionView& out_retention, std::string& out_error)
{
    return LoadAppleSnapshotRetentionImpl(source,checkpoint,out_retention,out_error,true);
}

bool LoadAppleReadOnlySnapshotRetention(const catalog::RandomAccessSource& source,
    const catalog::AppleCheckpointView& checkpoint, AppleSnapshotRetentionView& out_retention, std::string& out_error)
{
    return LoadAppleSnapshotRetentionImpl(source, checkpoint, out_retention, out_error, true, nullptr,
        RetentionAdmission::ReadOnlyInactiveTreeDefaults);
}

bool LoadSnapshotPlanningRetentionCatalogs(const catalog::RandomAccessSource& source,
    const catalog::AppleCheckpointView& checkpoint, AppleSnapshotRetentionView& retention,
    std::shared_ptr<const std::vector<SnapshotRetentionCatalog>>& catalogs, std::string& error) try
{
    retention = {};
    catalogs.reset();
    error.clear();
    if (dynamic_cast<const SnapshotPlanningSource*>(&source) &&
        !EnsureSnapshotCurrentOwners(source, checkpoint, error)) return false;
    return LoadAppleSnapshotRetentionImpl(source,checkpoint,retention,error,true,&catalogs);
}
catch (const std::bad_alloc&) { retention = {}; catalogs.reset(); return RecoveryAllocationFailed(source, error); }
catch (const std::length_error&) { retention = {}; catalogs.reset(); return RecoveryAllocationFailed(source, error); }


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
        if (!PayloadExtentStillOwned(checkpoint.spaceman, extent, nxsb.xid))
            return Fail(out_error, "ApplePayloadNotAllocated");
    }
    return true;
}
catch (const std::bad_alloc&) { return RecoveryAllocationFailed(source, out_error); }
catch (const std::length_error&) { return RecoveryAllocationFailed(source, out_error); }

static bool LoadAppleRecoveryCheckpointsImpl(
    const catalog::RandomAccessSource& source,
    const catalog::AppleCheckpointView& checkpoint,
    const std::vector<std::uint64_t>& required_checkpoint_xids,
    std::vector<AppleRecoveryCheckpointView>& out_checkpoints,
    std::string& out_error, bool snapshot_aware,
    RetentionAdmission admission = RetentionAdmission::Strict) try
{
    out_checkpoints.clear();
    out_error.clear();
    RecoveryBudgetErrorScope budget_error{source, out_error};
    const auto& current = checkpoint.container.superblock;
    if (!CheckRecoveryExtendedSnapshotMetadata(source, checkpoint, out_error)) return false;
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
        if (!CollectRecoveryMetadata(source, history.checkpoint, history.metadata_blocks, history.payload_extents, out_error, snapshot_aware, admission)) return false;
        for (const auto block : history.metadata_blocks)
        {
            if (!RecoveryBlockStillOwned(history.checkpoint, block, xid) ||
                !RecoveryBlockStillOwned(checkpoint, block, xid))
                return Fail(out_error, "AppleCheckpointRetentionReclaimed");
        }
        for (const auto& extent : history.payload_extents)
            if (!PayloadExtentStillOwned(history.checkpoint.spaceman, extent, xid) ||
                !PayloadExtentStillOwned(checkpoint.spaceman, extent, xid))
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

bool LoadAppleRecoveryCheckpoints(const catalog::RandomAccessSource& source,
    const catalog::AppleCheckpointView& checkpoint, const std::vector<std::uint64_t>& required_checkpoint_xids,
    std::vector<AppleRecoveryCheckpointView>& out_checkpoints, std::string& out_error)
{
    return LoadAppleRecoveryCheckpointsImpl(source,checkpoint,required_checkpoint_xids,out_checkpoints,out_error,false);
}
// Full current/historical owner graph, including live and sibling payload.
static bool LoadSnapshotCheckpointOwnersByAdmission(const catalog::RandomAccessSource& source,
    const catalog::AppleCheckpointView& checkpoint, std::vector<std::uint64_t>& metadata,
    std::vector<ApplePhysicalExtentRecord>& payload, std::string& error, RetentionAdmission admission) try
{
    metadata.clear();payload.clear();
    if(!source.ReadBudget()) {
        auto budget=std::make_shared<catalog::ApfsReadBudget>(65536,256ull<<20,1000000,256ull<<20);
        catalog::BudgetedRandomAccessSource bounded(source,budget);
        return LoadSnapshotCheckpointOwnersByAdmission(bounded,checkpoint,metadata,payload,error,admission);
    }
    if(CollectRecoveryMetadata(source,checkpoint,metadata,payload,error,true,admission))return true;
    metadata.clear();payload.clear();return false;
}
catch(const std::bad_alloc&){metadata.clear();payload.clear();return RecoveryAllocationFailed(source,error);}
catch(const std::length_error&){metadata.clear();payload.clear();return RecoveryAllocationFailed(source,error);}

bool LoadAppleSnapshotCheckpointOwners(const catalog::RandomAccessSource& source,
    const catalog::AppleCheckpointView& checkpoint, std::vector<std::uint64_t>& metadata,
    std::vector<ApplePhysicalExtentRecord>& payload, std::string& error)
{
    return LoadSnapshotCheckpointOwnersByAdmission(source, checkpoint, metadata, payload, error, RetentionAdmission::Strict);
}

bool LoadAppleReadOnlySnapshotCheckpointOwners(const catalog::RandomAccessSource& source,
    const catalog::AppleCheckpointView& checkpoint, std::vector<std::uint64_t>& metadata,
    std::vector<ApplePhysicalExtentRecord>& payload, std::string& error)
{
    error.clear();
    return LoadSnapshotCheckpointOwnersByAdmission(source, checkpoint, metadata, payload, error,
        RetentionAdmission::ReadOnlyInactiveTreeDefaults);
}

static bool LoadSnapshotRecoveryByAdmission(const catalog::RandomAccessSource& source,
    const catalog::AppleCheckpointView& checkpoint, const std::vector<std::uint64_t>& required_checkpoint_xids,
    std::vector<AppleRecoveryCheckpointView>& out_checkpoints, std::string& out_error, RetentionAdmission admission) try
{
    if(!source.ReadBudget()){
        auto budget=std::make_shared<catalog::ApfsReadBudget>(65536,256ull<<20,1000000,256ull<<20);
        catalog::BudgetedRandomAccessSource bounded(source,budget);
        return LoadSnapshotRecoveryByAdmission(bounded,checkpoint,required_checkpoint_xids,out_checkpoints,out_error,admission);
    }
    const auto* planning_base = &source;
    while (const auto* overlay = dynamic_cast<const SnapshotPublicationSource*>(planning_base))
        planning_base = &overlay->Base();
    if (!dynamic_cast<const SnapshotPlanningSource*>(planning_base)) {
        SnapshotPlanningSource observation(source);
        const bool loaded = LoadSnapshotRecoveryByAdmission(observation, checkpoint,
            required_checkpoint_xids, out_checkpoints, out_error, admission);
        if (!loaded || !observation.VerifyUnchanged(out_error)) {
            out_checkpoints.clear();
            return false;
        }
        return true;
    }
    // Current-only pins still admit a checkpoint. Do not let the history
    // loader's current-XID shortcut omit its full historical owner closure.
    out_checkpoints.clear();
    const auto current = catalog::LoadAppleCheckpointView(source, 0, source.SizeBytes(), out_error);
    if (!current || current->container.superblock_bytes != checkpoint.container.superblock_bytes ||
        current->container.superblock_physical_block != checkpoint.container.superblock_physical_block)
        return Fail(out_error, "AppleSnapshotRetirementEndpointUnproven");
    if (!EnsureSnapshotCurrentOwners(source, *current, out_error, admission)) return false;
    return LoadAppleRecoveryCheckpointsImpl(source,*current,required_checkpoint_xids,out_checkpoints,out_error,true,admission);
}
catch (const std::bad_alloc&) {out_checkpoints.clear();return RecoveryAllocationFailed(source,out_error);}
catch (const std::length_error&) {out_checkpoints.clear();return RecoveryAllocationFailed(source,out_error);}

bool LoadAppleSnapshotRecoveryCheckpoints(const catalog::RandomAccessSource& source,
    const catalog::AppleCheckpointView& checkpoint, const std::vector<std::uint64_t>& required_checkpoint_xids,
    std::vector<AppleRecoveryCheckpointView>& out_checkpoints, std::string& out_error)
{
    return LoadSnapshotRecoveryByAdmission(source, checkpoint, required_checkpoint_xids, out_checkpoints, out_error,
        RetentionAdmission::Strict);
}

bool LoadAppleReadOnlySnapshotRecoveryCheckpoints(const catalog::RandomAccessSource& source,
    const catalog::AppleCheckpointView& checkpoint, const std::vector<std::uint64_t>& required_checkpoint_xids,
    std::vector<AppleRecoveryCheckpointView>& out_checkpoints, std::string& out_error)
{
    return LoadSnapshotRecoveryByAdmission(source, checkpoint, required_checkpoint_xids, out_checkpoints, out_error,
        RetentionAdmission::ReadOnlyInactiveTreeDefaults);
}

namespace {
using RetirementRanges = std::vector<AppleSpacemanReleaseRequest>;
struct RetirementGraph {
    std::map<std::uint64_t, RetirementRanges> owners;
    std::vector<std::uint64_t> metadata;
    RetirementRanges payload;
    AppleSnapshotRetentionView logical;
    std::shared_ptr<const std::vector<SnapshotRetentionCatalog>> catalogs;
};
struct RetirementGraphObservation {
    RetentionAdmission admission = RetentionAdmission::Strict;
    std::vector<std::byte> endpoint;
    std::uint64_t endpoint_block = 0;
    std::vector<std::pair<std::uint64_t, std::vector<std::byte>>> metadata;
    std::shared_ptr<const RetirementGraph> graph;
};
bool ValidateRetirementOwnership(const catalog::RandomAccessSource& source,
    const catalog::AppleCheckpointView& checkpoint, const RetirementGraph& graph, std::string& error);
}

struct SnapshotPlanningSource::State {
    std::shared_ptr<const catalog::SoftwareVolumeRetainedOwners> transition_owners;
    const catalog::ImmutableEncryptedReadSource* transition_source = nullptr;
    std::uint64_t transition_revision = 0;
    std::array<std::byte, 32> transition_original_jid{};
    std::vector<catalog::SoftwareVolumeOwnedRange> transition_exclusions;
    std::map<std::pair<std::uint64_t, std::size_t>, std::vector<std::byte>> dependencies;
    std::vector<std::byte> verification_scratch;
    std::size_t verification_scratch_reserved = 0;
    std::vector<std::byte> endpoint;
    std::uint64_t endpoint_block = 0;
    bool owners_complete = false;
    std::vector<std::uint64_t> metadata;
    std::vector<ApplePhysicalExtentRecord> payload;
    std::shared_ptr<const RetirementGraph> graph;
    std::vector<RetirementGraphObservation> staged_graphs;
    bool read_only_owners_complete = false;
    std::vector<std::uint64_t> read_only_metadata;
    std::vector<ApplePhysicalExtentRecord> read_only_payload;
    std::shared_ptr<const RetirementGraph> read_only_graph;
    unsigned commit_verification_depth = 0;
};

SnapshotPlanningSource::SnapshotPlanningSource(const catalog::RandomAccessSource& source)
    : source_(source), size_(source.SizeBytes()) {
    if (const auto budget = ReadBudget(); budget && budget->Materialize(1, sizeof(State)))
        state_ = std::make_unique<State>();
}
SnapshotPlanningSource::~SnapshotPlanningSource() = default;
std::uint64_t SnapshotPlanningSource::SizeBytes() const { return size_; }
std::shared_ptr<catalog::ApfsReadBudget> SnapshotPlanningSource::ReadBudget() const { return source_.ReadBudget(); }
bool SnapshotPlanningSource::Read(std::uint64_t offset, std::size_t size, std::vector<std::byte>& out) const {
    out.clear();
    const auto budget = ReadBudget();
    if (!budget || budget->Failed()) return false;
    if (source_.SizeBytes() != size_ || !source_.Read(offset, size, out) || out.size() != size) {
        out.clear(); return false;
    }
    const auto key = std::make_pair(offset, size);
    const auto found = state_->dependencies.find(key);
    if (found != state_->dependencies.end()) {
        if (found->second == out) return true;
        out.clear(); return budget->Refuse("AppleSnapshotPlanningSourceChanged");
    }
    if (!budget->Materialize(1, size + sizeof(decltype(state_->dependencies)::value_type))) { out.clear(); return false; }
    state_->dependencies.emplace(key, out);
    return true;
}
bool SnapshotPlanningSource::VerifyUnchanged(std::string& error) const {
    const auto budget = ReadBudget();
    if (!budget || budget->Failed()) return Fail(error, budget ? budget->Failure() : "AppleSnapshotPlanningBudgetMissing");
    if (source_.SizeBytes() != size_) return Fail(error, "AppleSnapshotPlanningSourceChanged");
    constexpr std::size_t batch_limit = 65536;
    auto& actual = state_->verification_scratch;
    for (auto begin = state_->dependencies.begin(); begin != state_->dependencies.end();) {
        auto end = std::next(begin);
        const auto offset = begin->first.first;
        auto size = begin->first.second;
        if (offset > size_ || size > size_ - offset) {
            (void)budget->Refuse("AppleSnapshotPlanningSourceChanged");
            return Fail(error, budget->Failure());
        }
        // Narrow admission fields can overlap captured full blocks. Batch their
        // union without gaps, but compare every original observation below.
        while (end != state_->dependencies.end() && end->first.first <= offset + size) {
            if (end->first.first > size_ || end->first.second > size_ - end->first.first) {
                (void)budget->Refuse("AppleSnapshotPlanningSourceChanged");
                return Fail(error, budget->Failure());
            }
            const auto overlap = static_cast<std::size_t>(offset + size - end->first.first);
            if (end->first.second > overlap) {
                const auto growth = end->first.second - overlap;
                if (size > batch_limit || growth > batch_limit - size) break;
                size += growth;
            }
            ++end;
        }
        if (batch_limit > state_->verification_scratch_reserved) {
            if (!budget->Materialize(1, batch_limit))
                return Fail(error, budget->Failure());
            actual.reserve(batch_limit);
            state_->verification_scratch_reserved = batch_limit;
        }
        // A single admitted multi-block object can exceed the batching bound.
        // Compare its complete tail without growing the verification scratch.
        std::size_t done = 0;
        do {
            const auto count = (std::min)(batch_limit, size - done);
            if (!source_.Read(offset + done, count, actual) || actual.size() != count || source_.SizeBytes() != size_) {
                (void)budget->Refuse("AppleSnapshotPlanningSourceChanged");
                return Fail(error, budget->Failure());
            }
            for (auto entry = begin; entry != end; ++entry) {
                const auto relative = entry->first.first - offset;
                const auto first = (std::max)(relative, static_cast<std::uint64_t>(done));
                const auto last = (std::min)(relative + entry->second.size(), static_cast<std::uint64_t>(done + count));
                if (first < last && !std::equal(entry->second.begin() + (first - relative),
                    entry->second.begin() + (last - relative), actual.begin() + (first - done))) {
                    (void)budget->Refuse("AppleSnapshotPlanningSourceChanged");
                    return Fail(error, budget->Failure());
                }
            }
            done += count;
        } while (done < size);
        begin = end;
    }
    return true;
}

class SnapshotPlanningEvidenceAccess {
    static bool VerifyBorrow(const SnapshotPlanningSource& observation, std::string& error) {
        if (!MaterializeRecovery(observation, 0, 0, error)) return false;
        return observation.state_ && observation.state_->commit_verification_depth != 0
            ? true : observation.VerifyUnchanged(error);
    }
public:
    static const SnapshotPlanningSource::State* Transition(const catalog::RandomAccessSource& source, std::string& error) {
        const auto* base = &source;
        while (const auto* overlay = dynamic_cast<const SnapshotPublicationSource*>(base)) base = &overlay->Base();
        const auto* observation = dynamic_cast<const SnapshotPlanningSource*>(base);
        if (!observation || !observation->state_ || !observation->state_->transition_owners) return nullptr;
        const auto* state = Operation(source, error);
        if (!state || !state->transition_owners) return nullptr;
        if (!state->transition_source || state->transition_source->Revision() != state->transition_revision ||
            state->transition_source->SourceIdentity() != state->transition_owners->SourceIdentity()) {
            Fail(error, "AppleSoftwareTransitionSourceChanged"); return nullptr;
        }
        return state;
    }
    // Only the ordinary commit wrapper may defer redundant full sweeps. Reads
    // still capture/compare bytes, and its final uncached sweep is mandatory.
    class CommitScope {
    public:
        CommitScope(const SnapshotPlanningSource& observation, std::string& error) {
            if (!observation.VerifyUnchanged(error)) return;
            state_ = observation.state_.get();
            ++state_->commit_verification_depth;
        }
        ~CommitScope() { if (state_) --state_->commit_verification_depth; }
        CommitScope(const CommitScope&) = delete;
        CommitScope& operator=(const CommitScope&) = delete;
        explicit operator bool() const { return state_ != nullptr; }
    private:
        SnapshotPlanningSource::State* state_ = nullptr;
    };
    static SnapshotPlanningSource::State* Operation(const catalog::RandomAccessSource& source, std::string& error) {
        auto* base = &source;
        while (const auto* overlay = dynamic_cast<const SnapshotPublicationSource*>(base)) base = &overlay->Base();
        const auto* observation = dynamic_cast<const SnapshotPlanningSource*>(base);
        if (!observation) return nullptr;
        if (source.ReadBudget() != observation->ReadBudget() || source.SizeBytes() != observation->SizeBytes()) {
            Fail(error,"AppleSnapshotPlanningEndpointChanged"); return nullptr;
        }
        if (!VerifyBorrow(*observation, error)) return nullptr;
        return observation->state_.get();
    }
    static SnapshotPlanningSource::State* Get(const catalog::RandomAccessSource& source,
        const catalog::AppleCheckpointView& checkpoint, std::string& error) {
        const auto* observation = dynamic_cast<const SnapshotPlanningSource*>(&source);
        if (!observation) return nullptr;
        if (!VerifyBorrow(*observation, error)) return nullptr;
        auto& state = *observation->state_;
        if (state.endpoint.empty()) {
            if (!MaterializeRecovery(source, 1, checkpoint.container.superblock_bytes.size(), error)) return nullptr;
            state.endpoint = checkpoint.container.superblock_bytes;
            state.endpoint_block = checkpoint.container.superblock_physical_block;
        } else if (state.endpoint != checkpoint.container.superblock_bytes ||
            state.endpoint_block != checkpoint.container.superblock_physical_block) {
            // Historical pins have a separately loaded exact checkpoint and
            // continuity proof. They cannot use the current endpoint's cache.
            return nullptr;
        }
        return &state;
    }
};

#include "SoftwareTransitionRetention.inc"

static bool EnsureSnapshotCurrentOwners(const catalog::RandomAccessSource& source,
    const catalog::AppleCheckpointView& checkpoint, std::string& error, RetentionAdmission admission) {
    auto* evidence = SnapshotPlanningEvidenceAccess::Get(source, checkpoint, error);
    if (!error.empty()) return false;
    const bool read_only = admission != RetentionAdmission::Strict;
    if (evidence && (read_only ? evidence->read_only_owners_complete : evidence->owners_complete)) return true;
    std::vector<std::uint64_t> metadata;
    std::vector<ApplePhysicalExtentRecord> payload;
    if (!LoadSnapshotCheckpointOwnersByAdmission(source, checkpoint, metadata, payload, error, admission)) return false;
    if (evidence) {
        (read_only ? evidence->read_only_metadata : evidence->metadata) = std::move(metadata);
        (read_only ? evidence->read_only_payload : evidence->payload) = std::move(payload);
        (read_only ? evidence->read_only_owners_complete : evidence->owners_complete) = true;
    }
    return true;
}

namespace {

void NormalizeRetirementRanges(RetirementRanges& ranges) {
    std::sort(ranges.begin(), ranges.end(), [](const auto& a, const auto& b) {
        return a.physical_block < b.physical_block;
    });
    std::size_t size = 0;
    for (const auto r : ranges) {
        if (size && r.physical_block <= ranges[size - 1].physical_block + ranges[size - 1].block_count) {
            auto& last = ranges[size - 1];
            last.block_count = (std::max)(last.physical_block + last.block_count,
                r.physical_block + r.block_count) - last.physical_block;
        } else ranges[size++] = r;
    }
    ranges.resize(size);
}

RetirementRanges RetirementDifference(const RetirementRanges& a, const RetirementRanges& b) {
    RetirementRanges result;
    std::size_t index = 0;
    for (const auto r : a) {
        auto at = r.physical_block;
        const auto end = at + r.block_count;
        while (index < b.size() && b[index].physical_block + b[index].block_count <= at) ++index;
        for (auto i = index; i < b.size() && b[i].physical_block < end; ++i) {
            if (b[i].physical_block > at) result.push_back({at, b[i].physical_block - at});
            at = (std::max)(at, b[i].physical_block + b[i].block_count);
            if (at >= end) break;
        }
        if (at < end) result.push_back({at, end - at});
    }
    return result;
}

std::uint64_t RetirementCount(const RetirementRanges& ranges) {
    std::uint64_t count = 0;
    for (const auto r : ranges) count += r.block_count;
    return count;
}

// Physical snapshot APSBs retain an older inventory and extent layer. Validate
// that layer against its own exact history, including clone multiplicities.
bool ValidateRetirementDescriptorPayload(const catalog::RandomAccessSource& source,
    const catalog::AppleCheckpointView& checkpoint, std::uint64_t descriptor_block,
    std::uint64_t filesystem_xid, std::uint64_t owner, bool live,
    const SnapshotRetentionCatalog* completed_live,
    const SnapshotRetentionCatalog* completed_catalog,
    const std::vector<catalog::BtreeRecord>& filesystem,
    const std::vector<catalog::BtreeRecord>& extentrefs,
    std::vector<ApplePhysicalExtentRecord>& payload, std::string& error, RetentionAdmission admission,
    bool proved_physical_snapshot) {
    const auto& nx = checkpoint.container.superblock;
    catalog::AppleSnapshotCatalogRecords fresh;
    if (!completed_live) {
        const bool strict_catalog = admission == RetentionAdmission::Strict && !proved_physical_snapshot;
        // The caller completely walked this physical tree. The shared
        // observational decoder also validates inactive tail type defaults;
        // payload ownership below still uses the strict mutation validator.
        const bool loaded = live ? (strict_catalog ?
            catalog::LoadAppleSnapshotCatalog(source, checkpoint, owner, fresh, error) :
            catalog::LoadAppleReadOnlySnapshotCatalog(source, checkpoint, owner, fresh, error)) :
            (strict_catalog ?
            catalog::LoadAppleSnapshotDescriptorCatalog(source, checkpoint, owner, descriptor_block, filesystem_xid, fresh, error) :
            catalog::LoadAppleReadOnlySnapshotDescriptorCatalog(source, checkpoint, owner, descriptor_block, filesystem_xid, fresh, error));
        if (!loaded) return false;
    }
    const auto& catalog = completed_live ? completed_live->records : fresh;
    const auto same_records = [](const auto& a, const auto& b) {
        return a.size() == b.size() && std::equal(a.begin(), a.end(), b.begin(),
            [](const auto& x, const auto& y) { return x.key == y.key && x.value == y.value; });
    };
    if (!same_records(filesystem, catalog.live.filesystem) || !same_records(extentrefs, catalog.live.extentref))
        return Fail(error, "AppleSnapshotRetirementCanonicalTreeMismatch");
    const std::vector<ApplePhysicalExtentRecord>* completed_payload =
        completed_live ? &completed_live->live_payload : nullptr;
    // The descriptor's own catalog still passes strict parsing above. Reuse
    // geometry only when its complete chronological inputs equal an owned prefix.
    if (!live && completed_catalog &&
        completed_catalog->records.inventory.size() == completed_catalog->records.snapshots.size() &&
        completed_catalog->snapshot_payloads.size() == completed_catalog->records.inventory.size()) {
        for (std::size_t i = 0; i < completed_catalog->records.inventory.size(); ++i) {
            const auto& snapshot = completed_catalog->records.inventory[i];
            const auto& selected = completed_catalog->records.snapshots[i];
            if (snapshot.xid != filesystem_xid || snapshot.volume.superblock_object.physical_block != descriptor_block ||
                catalog.inventory.size() != i || catalog.snapshots.size() != i ||
                !same_records(catalog.live.filesystem, selected.filesystem) ||
                !same_records(catalog.live.extentref, selected.extentref)) continue;
            bool equal = true;
            for (std::size_t j = 0; j < i; ++j) {
                const auto& own = catalog.inventory[j];
                const auto& prefix = completed_catalog->records.inventory[j];
                if (own.xid != prefix.xid || own.name_utf8 != prefix.name_utf8 ||
                    !same_records(catalog.snapshots[j].filesystem, completed_catalog->records.snapshots[j].filesystem) ||
                    !same_records(catalog.snapshots[j].extentref, completed_catalog->records.snapshots[j].extentref)) {
                    equal = false;
                    break;
                }
            }
            if (equal) completed_payload = &completed_catalog->snapshot_payloads[i];
            break;
        }
    }
    std::vector<ApplePhysicalExtentRecord> prior, history;
    const auto resolve = [&](const auto& fs, const auto& refs, auto& resolved) {
        if (!ChargeRecoveryPayloadGraph(source, fs, refs, error) ||
            !MaterializeRecovery(source, prior.size() + history.size(), 2048, error)) return false;
        // Deletion may rebase a complete layer to NEW records. Its exact FS
        // coverage still proves ownership; partial/UPDATE layers need history.
        const bool complete_new = std::all_of(refs.begin(), refs.end(), [&](const auto& raw) {
            ApplePhysicalExtentRecord r;
            return DecodeApplePhysicalExtentRecord(raw, r, error) && r.kind == kApplePhysicalExtentKindNew;
        });
        const auto validate_payload = admission == RetentionAdmission::Strict ? ValidateApplePayloadExtentGraph : ValidateAppleReadOnlyPayloadExtentGraph;
        const auto resolve_layer = admission == RetentionAdmission::Strict ? ResolveAppleSnapshotExtentLayer : ResolveAppleReadOnlySnapshotExtentLayer;
        if (complete_new && validate_payload(fs, refs, nx.block_size,
                nx.block_count, resolved, error)) return true;
        return resolve_layer(prior, history, fs, refs,
            nx.block_size, nx.block_count, resolved, error);
    };
    if (!completed_payload) for (const auto& trees : catalog.snapshots) {
        std::vector<ApplePhysicalExtentRecord> resolved;
        if (!resolve(trees.filesystem, trees.extentref, resolved) ||
            !ChargeRecoveryAppend(source, history, resolved.size(), error)) return false;
        history.insert(history.end(), resolved.begin(), resolved.end());
        prior = std::move(resolved);
    }
    if (completed_payload) {
        // These exact canonical inputs were resolved by this graph's retention
        // walk. Keep their per-view owner and reference counts until validation ends.
        if (!ChargeRecoveryAppend(source, payload, completed_payload->size(), error)) return false;
        payload = *completed_payload;
    } else if (!resolve(filesystem, extentrefs, payload)) return false;
    // Only physical ownership intervals leave this private validator. Preserve
    // every byte range while compacting its already charged result in place.
    std::sort(payload.begin(), payload.end(), [](const auto& a, const auto& b) { return a.physical_block < b.physical_block; });
    std::size_t kept = 0;
    for (const auto& extent : payload) {
        if (kept && extent.physical_block <= payload[kept - 1].physical_block + payload[kept - 1].block_count) {
            auto& previous = payload[kept - 1];
            previous.block_count = (std::max)(previous.physical_block + previous.block_count,
                extent.physical_block + extent.block_count) - previous.physical_block;
        } else payload[kept++] = extent;
    }
    payload.resize(kept);
    // An UPDATE to zero is still an edge into accepted history. Keep its
    // backing range until the descriptor which carries that edge is retired.
    for (const auto& raw : extentrefs) {
        ApplePhysicalExtentRecord r;
        if (!DecodeApplePhysicalExtentRecord(raw, r, error) || !r.physical_block ||
            r.physical_block >= nx.block_count || r.block_count > nx.block_count - r.physical_block ||
            !ChargeRecoveryAppend(source, payload, 1, error))
            return Fail(error, "AppleSnapshotRetirementExtentReferenceUnproven");
        payload.push_back(r);
    }
    return true;
}

// Conservative closure includes historical inventory/OMAP references even
// when they no longer name a public snapshot. They cannot become free until
// the last graph which references them has itself been retired.
bool BuildRetirementGraph(const catalog::RandomAccessSource& source,
    const catalog::AppleCheckpointView& checkpoint, RetirementGraph& graph, std::string& error, RetentionAdmission admission) {
    const auto& nx = checkpoint.container.superblock;
    const auto* transition = SnapshotPlanningEvidenceAccess::Transition(source, error);
    if (!error.empty()) return false;
    if (!LoadAppleSnapshotRetentionImpl(source, checkpoint, graph.logical, error, false, &graph.catalogs, admission)) return false;
    using IntervalMap = std::map<std::uint64_t, std::uint64_t>;
    std::map<std::uint64_t, IntervalMap> owner_intervals;
    IntervalMap payload_intervals;
    const auto include = [&](IntervalMap& ranges, std::uint64_t begin, std::uint64_t end) {
        auto at = ranges.upper_bound(begin);
        if (at != ranges.begin()) {
            auto previous = std::prev(at);
            if (previous->second >= begin) {
                previous->second = (std::max)(previous->second, end);
                while (at != ranges.end() && at->first <= previous->second) {
                    previous->second = (std::max)(previous->second, at->second); at = ranges.erase(at);
                }
                return true;
            }
        }
        while (at != ranges.end() && at->first <= end) {
            end = (std::max)(end, at->second); at = ranges.erase(at);
        }
        if (!MaterializeRecovery(source, 1, sizeof(IntervalMap::value_type), error)) return false;
        ranges.emplace(begin, end); return true;
    };
    const auto object = [&](std::uint64_t block, std::uint64_t oid, std::uint32_t type,
                            std::uint32_t subtype, std::uint64_t max_xid,
                            catalog::AppleObjectLocation& location, std::vector<std::byte>& bytes) {
        if (!block || block >= nx.block_count || !ReadBlock(source, block, nx.block_size, bytes) ||
            !catalog::VerifyObjectChecksum(bytes, nx.block_size) ||
            catalog::ReadU64LE(bytes, 8) != oid || catalog::ReadU32LE(bytes, 0x18) != type ||
            catalog::ReadU32LE(bytes, 0x1c) != subtype ||
            !catalog::ReadU64LE(bytes, 0x10).value_or(0) ||
            catalog::ReadU64LE(bytes, 0x10).value() > max_xid)
            return Fail(error, "AppleSnapshotRetirementObjectUnproven");
        location = {oid, catalog::ReadU64LE(bytes, 0x10).value(), block, type, subtype, nx.block_size};
        return true;
    };
    const auto add = [&](std::uint64_t owner, std::uint64_t block, std::uint64_t count, bool metadata) {
        if (!count || !block || block >= nx.block_count || count > nx.block_count - block)
            return Fail(error, "AppleSnapshotRetirementRangeUnproven");
        auto found = owner_intervals.find(owner);
        if (found == owner_intervals.end()) {
            if (!MaterializeRecovery(source, 1, sizeof(decltype(owner_intervals)::value_type), error)) return false;
            found = owner_intervals.emplace(owner, IntervalMap{}).first;
        }
        if (!include(found->second, block, block + count)) return false;
        if (metadata) {
            if (!ChargeRecoveryAppend(source, graph.metadata, 1, error)) return false;
            graph.metadata.push_back(block);
        } else {
            if (!include(payload_intervals, block, block + count)) return false;
        }
        return true;
    };
    std::vector<catalog::BtreeRecord> container_records;
    std::vector<std::uint64_t> container_blocks;
    if (!ReadCheckpointTree(source, checkpoint, checkpoint.container_object_map.tree, 0,
            container_records, container_blocks, error) ||
        !add(0, checkpoint.container_object_map.object.physical_block, 1, true)) return false;
    for (const auto block : container_blocks) if (!add(0, block, 1, true)) return false;
    std::set<std::uint64_t> container_oids;
    for (const auto& r : container_records) {
        if (r.key.size() != 16 || r.value.size() != 16 || catalog::ReadU32LE(r.value, 0) != 0u ||
            catalog::ReadU32LE(r.value, 4) != nx.block_size)
            return Fail(error, "AppleSnapshotRetirementOmapHistoryUnproven");
        const auto oid = catalog::ReadU64LE(r.key, 0).value();
        const auto v = std::find_if(checkpoint.volumes.begin(), checkpoint.volumes.end(),
            [&](const auto& x) { return x.superblock.object_id == oid; });
        if (v == checkpoint.volumes.end() || !container_oids.insert(oid).second ||
            catalog::ReadU64LE(r.value, 8) != v->superblock_object.physical_block ||
            catalog::ReadU64LE(r.key, 8).value_or(0) < v->superblock.xid ||
            catalog::ReadU64LE(r.key, 8).value() > nx.xid)
            return Fail(error, "AppleSnapshotRetirementOmapHistoryUnproven");
    }
    if (container_oids.size() != checkpoint.volumes.size())
        return Fail(error, "AppleSnapshotRetirementOmapHistoryUnproven");
    for (const auto& volume : checkpoint.volumes) {
        const auto owner = volume.superblock.object_id;
        const SnapshotRetentionCatalog* completed_catalog = nullptr;
        const auto* base = &source;
        while (const auto* overlay = dynamic_cast<const SnapshotPublicationSource*>(base)) base = &overlay->Base();
        if (dynamic_cast<const SnapshotPlanningSource*>(base) && graph.catalogs) {
            const auto found = std::find_if(graph.catalogs->begin(), graph.catalogs->end(),
                [&](const auto& value) { return value.volume_oid == owner; });
            if (found != graph.catalogs->end()) completed_catalog = &*found;
        }
        bool catalog_borrowed = false;
        using DescriptorView = std::pair<std::uint64_t, std::uint64_t>;
        std::vector<DescriptorView> pending{{volume.superblock_object.physical_block, nx.xid}};
        std::set<DescriptorView> apsbs;
        std::vector<std::uint64_t> walked;
        for (std::size_t at = 0; at < pending.size(); ++at) {
            const auto [block, filesystem_xid] = pending[at];
            if (!apsbs.insert(pending[at]).second) continue;
            if (!MaterializeRecovery(source, 1, 128, error)) return false;
            std::vector<std::byte> bytes;
            catalog::AppleObjectLocation location;
            const bool live = block == volume.superblock_object.physical_block && filesystem_xid == nx.xid;
            if (!object(block, live ? owner : block, live ? catalog::kObjectTypeFs :
                    catalog::kObjectPhysical | catalog::kObjectTypeFs, 0, nx.xid, location, bytes)) return false;
            const auto apsb = catalog::ParseApsb(bytes);
            const bool transition_inactive_tree = transition && live && apsb &&
                checkpoint.volumes.size() == 1 && owner == transition->transition_owners->VolumeObjectId() &&
                apsb->uuid_hex == transition->transition_owners->VolumeUuid() && apsb->fs_flags == catalog::kFsFlagUnencrypted &&
                catalog::ReadU64LE(bytes, 0xD8) == 0 && !volume.object_map.snapshot_tree_oid &&
                apsb->snap_meta_tree_type == (catalog::kObjectPhysical | catalog::kObjectTypeBtree);
            const bool ordinary_physical_candidate = !transition &&
                admission == RetentionAdmission::Strict && apsb &&
                apsb->snap_meta_tree_type == (catalog::kObjectPhysical | catalog::kObjectTypeBtree);
            const bool snapshot_type_supported = apsb && (apsb->snap_meta_tree_type == catalog::kObjectTypeBtree ||
                transition_inactive_tree || ordinary_physical_candidate ||
                (admission == RetentionAdmission::ReadOnlyInactiveTreeDefaults &&
                    apsb->snap_meta_tree_type == (catalog::kObjectPhysical | catalog::kObjectTypeBtree)));
            if (!apsb || apsb->uuid_hex != volume.superblock.uuid_hex ||
                !(apsb->fs_flags & catalog::kFsFlagUnencrypted) || apsb->readonly_features ||
                (apsb->incompatible_features & ~catalog::kVolumeSupportedIncompatibleFeaturesMask) ||
                apsb->root_tree_type != catalog::kObjectTypeBtree ||
                !snapshot_type_supported)
                return Fail(error, "AppleSnapshotRetirementHistoryUnproven");
            catalog::AppleVolumeCheckpointView descriptor;
            descriptor.superblock = *apsb;
            descriptor.superblock_object = location;
            // The live APSB is a container-OMAP object. Physical snapshot
            // descriptors belong to the volume; both remain retained metadata.
            if (!add(live ? 0 : owner, block, 1, true)) return false;
            const auto map_oid = apsb->omap_oid;
            if (!object(map_oid, map_oid, catalog::kObjectPhysical | catalog::kObjectTypeOmap,
                    0, nx.xid, location, bytes) || !add(owner, map_oid, 1, true)) return false;
            if (catalog::ReadU32LE(bytes, 0x20) != 0 ||
                catalog::ReadU32LE(bytes, 0x28) != (catalog::kObjectPhysical | catalog::kObjectTypeBtree) ||
                catalog::ReadU64LE(bytes, 0x48) != 0 || catalog::ReadU64LE(bytes, 0x50) != 0)
                return Fail(error, "AppleSnapshotRetirementOmapHistoryUnproven");
            const auto map_tree = catalog::ReadU64LE(bytes, 0x30).value_or(0);
            const auto snapshot_tree = catalog::ReadU64LE(bytes, 0x38).value_or(0);
            const auto map_xid = location.xid;
            const auto snapshot_count = catalog::ReadU32LE(bytes, 0x24).value();
            const auto snapshot_type = catalog::ReadU32LE(bytes, 0x2c).value();
            const auto snapshot_recent = catalog::ReadU64LE(bytes, 0x40).value();
            descriptor.object_map.object = location;
            descriptor.object_map.tree_type = catalog::kObjectPhysical | catalog::kObjectTypeBtree;
            descriptor.object_map.snapshot_tree_type = snapshot_type;
            descriptor.object_map.snapshot_tree_oid = snapshot_tree;
            if ((!snapshot_tree && (snapshot_count || snapshot_recent ||
                    (snapshot_type && snapshot_type != (catalog::kObjectPhysical | catalog::kObjectTypeBtree)))) ||
                (snapshot_tree && snapshot_type != (catalog::kObjectPhysical | catalog::kObjectTypeBtree)))
                return Fail(error, "AppleSnapshotRetirementOmapHistoryUnproven");
            const std::vector<catalog::BtreeRecord>* borrowed_tree=nullptr;
            const auto tree = [&](catalog::AppleObjectLocation root, std::uint64_t max_xid,
                                  std::vector<catalog::BtreeRecord>& records) {
                borrowed_tree=nullptr;
                records.clear();
                std::vector<std::uint64_t> visited;
                const auto same=[](const auto& a,const auto& b){return a.object_id==b.object_id&&a.xid==b.xid&&a.physical_block==b.physical_block&&a.type==b.type&&a.subtype==b.subtype&&a.size_bytes==b.size_bytes;};
                const std::vector<std::uint64_t>* completed_blocks=nullptr;
                const auto select=[&](const auto& view,const auto& trees,std::uint64_t selection){
                    if(!same(descriptor.object_map.object,view.object_map.object)||!same(descriptor.object_map.tree,view.object_map.tree))return;
                    if(same(root,view.root_tree)&&max_xid==selection){borrowed_tree=&trees.filesystem;completed_blocks=&trees.filesystem_blocks;}
                    if(view.extentref_tree&&same(root,*view.extentref_tree)&&max_xid==view.superblock.xid){borrowed_tree=&trees.extentref;completed_blocks=&trees.extentref_blocks;}
                };
                if(completed_catalog){
                    if(live)select(volume,completed_catalog->records.live,nx.xid);
                    else for(std::size_t i=0;i<completed_catalog->records.inventory.size();++i){
                        const auto& snapshot=completed_catalog->records.inventory[i];
                        if(snapshot.volume.superblock_object.physical_block==block&&snapshot.xid==filesystem_xid)
                            select(snapshot.volume,completed_catalog->records.snapshots[i],snapshot.xid);
                    }
                }
                if(borrowed_tree){
                    if(!ChargeRecoveryAppend(source,visited,completed_blocks->size(),error))return false;
                    catalog_borrowed = true;
                    visited=*completed_blocks;
                }else if (!catalog::ReadAppleSnapshotTree(source, nx.block_size, root, descriptor.object_map,
                        max_xid, nx.xid, records, visited, error)) return false;
                for (const auto b : visited) {
                    if (!add(owner, b, 1, true) || !ChargeRecoveryAppend(source, walked, 1, error)) return false;
                    walked.push_back(b);
                }
                return true;
            };
            std::vector<catalog::BtreeRecord> mappings, records;
            if (!object(map_tree, map_tree, catalog::kObjectPhysical | catalog::kObjectTypeBtree,
                    catalog::kObjectTypeOmap, nx.xid, location, bytes) ||
                !tree(location, nx.xid, mappings)) return false;
            descriptor.object_map.tree = location;
            std::uint64_t selected_root_xid = 0;
            for (const auto& record : mappings) {
                const auto version = catalog::ReadU64LE(record.key, 8).value_or(0);
                if (catalog::ReadU64LE(record.key, 0) == apsb->root_oid && version <= filesystem_xid)
                    selected_root_xid = (std::max)(selected_root_xid, version);
            }
            if (!selected_root_xid) return Fail(error, "AppleSnapshotRetirementFilesystemViewUnproven");
            std::vector<catalog::BtreeRecord> latest_filesystem;
            const std::vector<catalog::BtreeRecord>* latest_borrowed_filesystem=nullptr;
            std::uint64_t latest_fs_xid = 0, latest_snap_xid = 0;
            const auto snapshot_record = [&](const catalog::BtreeRecord& record) {
                const auto kind = catalog::ReadU64LE(record.key, 0).value_or(0) >> 60;
                if (kind == 1) {
                    if (record.key.size() != 8 || record.value.size() < 50 ||
                        catalog::ReadU32LE(record.value, 44) != 0 ||
                        catalog::ReadU32LE(record.value, 40) != (catalog::kObjectPhysical | catalog::kObjectTypeBtree) ||
                        !ChargeRecoveryAppend(source, pending, 1, error))
                        return Fail(error, "AppleSnapshotRetirementHistoryUnproven");
                    const auto snapshot_block = catalog::ReadU64LE(record.value, 8).value();
                    catalog::AppleObjectLocation snapshot_location;
                    std::vector<std::byte> snapshot_bytes;
                    if (!object(snapshot_block, snapshot_block,
                            catalog::kObjectPhysical | catalog::kObjectTypeFs, 0, nx.xid,
                            snapshot_location, snapshot_bytes)) return false;
                    const auto snapshot_apsb = catalog::ParseApsb(snapshot_bytes);
                    const auto snapshot_xid = catalog::ReadU64LE(record.key, 0).value() & 0x0fffffffffffffffull;
                    if (!snapshot_apsb || !snapshot_xid || snapshot_apsb->xid < snapshot_xid ||
                        snapshot_apsb->uuid_hex != volume.superblock.uuid_hex ||
                        !catalog::ReadU64LE(record.value, 0).value_or(0) ||
                        snapshot_apsb->extentref_tree_oid != catalog::ReadU64LE(record.value, 0) ||
                        snapshot_apsb->extentref_tree_type != catalog::ReadU32LE(record.value, 40))
                        return Fail(error, "AppleSnapshotRetirementInventoryRootUnproven");
                    pending.emplace_back(snapshot_block, snapshot_xid);
                } else if (kind != 11 || record.value.size() != 8)
                    return Fail(error, "AppleSnapshotRetirementHistoryUnproven");
                return true;
            };
            std::set<std::pair<std::uint64_t, std::uint64_t>> keys;
            for (const auto& r : mappings) {
                if (r.key.size() != 16 || r.value.size() != 16 || catalog::ReadU32LE(r.value, 0) != 0u ||
                    catalog::ReadU32LE(r.value, 4) != nx.block_size)
                    return Fail(error, "AppleSnapshotRetirementOmapHistoryUnproven");
                const auto oid = catalog::ReadU64LE(r.key, 0).value();
                const auto xid = catalog::ReadU64LE(r.key, 8).value();
                if (!oid || !xid || xid > map_xid ||
                    !MaterializeRecovery(source, 1, 64, error) || !keys.emplace(oid, xid).second)
                    return Fail(error, "AppleSnapshotRetirementOmapHistoryUnproven");
                const auto target = catalog::ReadU64LE(r.value, 8).value();
                std::vector<std::byte> mapped;
                if (!target || target >= nx.block_count || !ReadBlock(source, target, nx.block_size, mapped) ||
                    !catalog::VerifyObjectChecksum(mapped, nx.block_size) ||
                    catalog::ReadU64LE(mapped, 8) != oid || !catalog::ReadU64LE(mapped, 0x10).value_or(0) ||
                    catalog::ReadU64LE(mapped, 0x10).value() > xid ||
                    (catalog::ReadU32LE(mapped, 0x18) != catalog::kObjectTypeBtree &&
                        catalog::ReadU32LE(mapped, 0x18) != catalog::kObjectTypeBtreeNode) ||
                    (catalog::ReadU32LE(mapped, 0x1c) != catalog::kObjectTypeFsTree &&
                        catalog::ReadU32LE(mapped, 0x1c) != catalog::kObjectTypeSnapMetaTree))
                    return Fail(error, "AppleSnapshotRetirementOmapHistoryUnproven");
                if (oid != apsb->root_oid &&
                    (apsb->snap_meta_tree_type != catalog::kObjectTypeBtree || oid != apsb->snap_meta_tree_oid)) continue;
                const auto subtype = oid == apsb->root_oid ? catalog::kObjectTypeFsTree : catalog::kObjectTypeSnapMetaTree;
                if (!object(catalog::ReadU64LE(r.value, 8).value(), oid, catalog::kObjectTypeBtree,
                        subtype, xid, location, bytes) ||
                    !tree(location, subtype == catalog::kObjectTypeFsTree && xid == selected_root_xid ?
                        filesystem_xid : xid, records)) return false;
                const bool retain_filesystem = subtype == catalog::kObjectTypeFsTree && xid == selected_root_xid;
                if (retain_filesystem) {
                    latest_fs_xid = xid;
                    descriptor.root_tree = location;
                } else if (subtype == catalog::kObjectTypeSnapMetaTree && xid > latest_snap_xid) {
                    latest_snap_xid = xid;
                    descriptor.snapshot_metadata_tree = location;
                }
                const auto& selected_records=borrowed_tree?*borrowed_tree:records;
                for (const auto& record : selected_records) {
                    const auto kind = catalog::ReadU64LE(record.key, 0).value_or(0) >> 60;
                    if (subtype == catalog::kObjectTypeFsTree && kind == 8) {
                        AppleFileExtentRecord extent;
                        if (!DecodeAppleFileExtentRecord(record, nx.block_size, extent, error) ||
                            extent.crypto_id || !extent.length_bytes || extent.length_bytes > UINT64_MAX - (nx.block_size - 1) ||
                            (extent.physical_block && !add(owner, extent.physical_block,
                                (extent.length_bytes + nx.block_size - 1) / nx.block_size, false)))
                            return Fail(error, "AppleSnapshotRetirementPayloadUnproven");
                    } else if (subtype == catalog::kObjectTypeSnapMetaTree && !snapshot_record(record)) return false;
                }
                // The complete walk already charged these owned buffers. Keep
                // the newest descriptor after processing every historical edge.
                if (retain_filesystem) {
                    latest_borrowed_filesystem=borrowed_tree;
                    if(!borrowed_tree)latest_filesystem = std::move(records);
                }
            }
            for (const auto& r : mappings)
                if (std::find(walked.begin(), walked.end(), catalog::ReadU64LE(r.value, 8).value()) == walked.end())
                    return Fail(error, "AppleSnapshotRetirementOmapHistoryUnproven");
            if ((admission == RetentionAdmission::ReadOnlyInactiveTreeDefaults || transition_inactive_tree ||
                    ordinary_physical_candidate) && apsb->snap_meta_tree_oid &&
                apsb->snap_meta_tree_type == (catalog::kObjectPhysical | catalog::kObjectTypeBtree)) {
                if (!object(apsb->snap_meta_tree_oid, apsb->snap_meta_tree_oid, apsb->snap_meta_tree_type,
                        catalog::kObjectTypeSnapMetaTree, apsb->xid, location, bytes) ||
                    !tree(location, apsb->xid, records)) return false;
                if (transition_inactive_tree && !records.empty())
                    return Fail(error, "AppleReadOnlyPhysicalSnapshotHistoryUnsupported");
                for (const auto& record : records) if (!snapshot_record(record)) return false;
                descriptor.snapshot_metadata_tree = location;
                latest_snap_xid = location.xid;
            }
            if (snapshot_tree) {
                if (!object(snapshot_tree, snapshot_tree, catalog::kObjectPhysical | catalog::kObjectTypeBtree,
                        0x13, nx.xid, location, bytes) || !tree(location, nx.xid, records)) return false;
                std::set<std::uint64_t> snapshot_xids;
                for (const auto& r : records) {
                    if (r.key.size() != 8 || r.value.size() != 16 || catalog::ReadU32LE(r.value, 0) != 0u ||
                        catalog::ReadU32LE(r.value, 4) != 0 || catalog::ReadU64LE(r.value, 8) != 0 ||
                        !catalog::ReadU64LE(r.key, 0).value_or(0) || catalog::ReadU64LE(r.key, 0).value() > map_xid ||
                        !MaterializeRecovery(source, 1, 64, error) ||
                        !snapshot_xids.insert(catalog::ReadU64LE(r.key, 0).value()).second)
                        return Fail(error, "AppleSnapshotRetirementOmapHistoryUnproven");
                }
                if (snapshot_xids.size() != snapshot_count ||
                    snapshot_recent != (snapshot_xids.empty() ? 0 : *snapshot_xids.rbegin()))
                    return Fail(error, "AppleSnapshotRetirementOmapHistoryUnproven");
            }
            if (!object(apsb->extentref_tree_oid, apsb->extentref_tree_oid,
                    catalog::kObjectPhysical | catalog::kObjectTypeBtree, catalog::kObjectTypeBlockRefTree,
                    apsb->xid, location, bytes) || !tree(location, apsb->xid, records)) return false;
            descriptor.extentref_tree = location;
            std::vector<ApplePhysicalExtentRecord> referenced;
            const SnapshotRetentionCatalog* completed_live = nullptr;
            if (live && graph.catalogs) {
                const auto found = std::find_if(graph.catalogs->begin(), graph.catalogs->end(),
                    [&](const auto& c) { return c.volume_oid == owner; });
                if (found != graph.catalogs->end()) completed_live = &*found;
            }
            if (!latest_fs_xid || (apsb->snap_meta_tree_oid && !latest_snap_xid))
                return Fail(error, "AppleSnapshotRetirementExtentReferenceUnproven");
            std::string descriptor_error;
            if (!ValidateRetirementDescriptorPayload(source, checkpoint, block, filesystem_xid,
                    owner, live, completed_live, completed_catalog, latest_borrowed_filesystem?*latest_borrowed_filesystem:latest_filesystem,
                    borrowed_tree?*borrowed_tree:records, referenced, descriptor_error, admission, ordinary_physical_candidate))
                return Fail(error, descriptor_error.empty() ? "AppleSnapshotRetirementExtentReferenceUnproven" : descriptor_error.c_str());
            for (const auto& extent : referenced)
                if (!add(owner, extent.physical_block, extent.block_count, false)) return false;
            if (apsb->fext_tree_oid) return Fail(error, "AppleSnapshotRetirementHistoryUnproven");
        }
        // No ownership result escapes this pass before every borrowed catalog
        // byte is rechecked, including overlay bytes changed during the walk.
        if (catalog_borrowed) {
            if (!MaterializeRecovery(source, 1, nx.block_size, error)) return false;
            std::vector<std::byte> actual;
            for (const auto& [physical, expected] : completed_catalog->metadata_preimages) {
                if (!ReadBlock(source, physical, nx.block_size, actual)) return false;
                if (actual != expected) return Fail(error, "AppleSnapshotRetirementCanonicalTreeChanged");
            }
        }
    }
    for (const auto& [owner, ranges] : owner_intervals) {
        if (!MaterializeRecovery(source, 1, sizeof(decltype(graph.owners)::value_type), error)) return false;
        auto& output = graph.owners[owner];
        if (!ChargeRecoveryAppend(source, output, ranges.size(), error)) return false;
        for (const auto& [begin, end] : ranges) output.push_back({begin,end-begin});
    }
    if (!ChargeRecoveryAppend(source, graph.payload, payload_intervals.size(), error)) return false;
    for (const auto& [begin, end] : payload_intervals) graph.payload.push_back({begin,end-begin});
    std::sort(graph.metadata.begin(), graph.metadata.end());
    graph.metadata.erase(std::unique(graph.metadata.begin(), graph.metadata.end()), graph.metadata.end());
    for (const auto r : graph.payload) {
        const auto found = std::lower_bound(graph.metadata.begin(), graph.metadata.end(), r.physical_block);
        if (found != graph.metadata.end() && *found < r.physical_block + r.block_count)
            return Fail(error, "AppleSnapshotRetirementPayloadMetadataOverlap");
    }
    return ValidateRetirementOwnership(source, checkpoint, graph, error);
}

bool ValidateRetirementOwnership(const catalog::RandomAccessSource& source,
    const catalog::AppleCheckpointView& checkpoint, const RetirementGraph& graph, std::string& error) {
    const auto& nx = checkpoint.container.superblock;
    std::vector<std::uint64_t> allocator_metadata;
    if (!AppendSpacemanMetadataBlocks(source, checkpoint, allocator_metadata, error)) return false;
    std::sort(allocator_metadata.begin(), allocator_metadata.end());
    RetirementRanges all;
    for (const auto& [owner, ranges] : graph.owners) {
        for (const auto r : ranges) {
            if (!PayloadExtentAvoidsMetadata(checkpoint, allocator_metadata,
                    ApplePhysicalExtentRecord{r.physical_block, r.block_count, kApplePhysicalExtentKindNew, 1, 1}) ||
                !PayloadExtentStillOwned(checkpoint.spaceman,
                    ApplePhysicalExtentRecord{r.physical_block, r.block_count, kApplePhysicalExtentKindNew, 1, 1}, nx.xid))
                return Fail(error, "AppleSnapshotRetirementOwnershipUnproven");
            if (!ChargeRecoveryAppend(source, all, 1, error)) return false;
            all.push_back(r);
        }
    }
    std::sort(all.begin(), all.end(), [](const auto& a, const auto& b) {return a.physical_block < b.physical_block;});
    for (std::size_t i = 1; i < all.size(); ++i)
        if (all[i].physical_block < all[i - 1].physical_block + all[i - 1].block_count)
            return Fail(error, "AppleSnapshotRetirementCrossOwnerOverlap");
    return true;
}

// Accounting fields do not select a tree or an OMAP version. They are proved
// separately against the final serialized allocator, queue and APSB counters.
bool NormalizeGraphDescriptor(std::vector<std::byte>& bytes, std::uint32_t block_size) {
    const auto type = catalog::ReadU32LE(bytes,0x18).value_or(0);
    if ((type & catalog::kObjectTypeMask) != catalog::kObjectTypeFs) return true;
    if (!catalog::VerifyObjectChecksum(bytes,block_size) || !catalog::ParseApsb(bytes)) return false;
    for (const auto offset : {0u,0x58u,0xe0u,0xe8u})
        std::fill(bytes.begin()+offset,bytes.begin()+offset+8,std::byte{});
    return true;
}

bool FindCompletedRetirementGraph(const catalog::RandomAccessSource& source,
    const catalog::AppleCheckpointView& checkpoint, std::shared_ptr<const RetirementGraph>& graph, std::string& error,
    RetentionAdmission admission) {
    auto* operation = SnapshotPlanningEvidenceAccess::Operation(source,error);
    if (!error.empty()) return false;
    if (!operation) return true;
    for (const auto& saved : operation->staged_graphs) {
        if (saved.admission != admission || saved.endpoint != checkpoint.container.superblock_bytes ||
            saved.endpoint_block != checkpoint.container.superblock_physical_block) continue;
        bool identical = true;
        for (const auto& [block, bytes] : saved.metadata) {
            std::vector<std::byte> actual;
            if (!ReadBlock(source,block,checkpoint.container.superblock.block_size,actual))
                return Fail(error,source.ReadBudget()->Failed()?source.ReadBudget()->Failure():"AppleSnapshotPlanningSourceUnreadable");
            if (!NormalizeGraphDescriptor(actual,checkpoint.container.superblock.block_size) || actual != bytes) {
                identical = false; break;
            }
        }
        if (!identical) continue;
        // Parsed ownership may be identical while final allocator bytes differ.
        // Never lend the previous allocator's authority to this view.
        if (!ValidateRetirementOwnership(source,checkpoint,*saved.graph,error)) return false;
        graph = saved.graph; return true;
    }
    return true;
}

bool SaveCompletedRetirementGraph(const catalog::RandomAccessSource& source,
    const catalog::AppleCheckpointView& checkpoint, const std::shared_ptr<const RetirementGraph>& graph, std::string& error,
    RetentionAdmission admission) {
    auto* operation = SnapshotPlanningEvidenceAccess::Operation(source,error);
    if (!error.empty()) return false;
    if (!operation) return true;
    RetirementGraphObservation saved;
    saved.admission = admission;
    if (!MaterializeRecovery(source,1,sizeof(saved)+checkpoint.container.superblock_bytes.size(),error) ||
        !ChargeRecoveryAppend(source,saved.metadata,graph->metadata.size(),error)) return false;
    saved.endpoint=checkpoint.container.superblock_bytes;
    saved.endpoint_block=checkpoint.container.superblock_physical_block;
    for (const auto block : graph->metadata) {
        if (const auto budget = source.ReadBudget(); budget &&
            !budget->Materialize(0,checkpoint.container.superblock.block_size))
            return Fail(error,budget->Failure());
        std::vector<std::byte> bytes;
        if (!ReadBlock(source,block,checkpoint.container.superblock.block_size,bytes) ||
            !NormalizeGraphDescriptor(bytes,checkpoint.container.superblock.block_size))
            return Fail(error,"AppleSnapshotPlanningSourceUnreadable");
        saved.metadata.emplace_back(block,std::move(bytes));
    }
    saved.graph=graph;
    operation->staged_graphs.push_back(std::move(saved)); return true;
}

bool LoadRetirementGraph(const catalog::RandomAccessSource& source,
    const catalog::AppleCheckpointView& checkpoint, std::shared_ptr<const RetirementGraph>& graph, std::string& error,
    RetentionAdmission admission = RetentionAdmission::Strict) {
    if (!CheckRecoveryExtendedSnapshotMetadata(source, checkpoint, error)) return false;
    auto* evidence = SnapshotPlanningEvidenceAccess::Get(source, checkpoint, error);
    if (!error.empty()) return false;
    const bool read_only = admission != RetentionAdmission::Strict;
    if (evidence && (read_only ? evidence->read_only_graph : evidence->graph)) {
        graph = read_only ? evidence->read_only_graph : evidence->graph; return true;
    }
    if (!FindCompletedRetirementGraph(source,checkpoint,graph,error,admission)) return false;
    if (graph) return true;
    if (!MaterializeRecovery(source, 1, sizeof(RetirementGraph), error)) return false;
    auto result = std::make_shared<RetirementGraph>();
    if (!BuildRetirementGraph(source, checkpoint, *result, error, admission)) return false;
    NormalizeRetirementRanges(result->payload);
    graph = std::move(result);
    if (!SaveCompletedRetirementGraph(source,checkpoint,graph,error,admission)) { graph.reset(); return false; }
    if (evidence) (read_only ? evidence->read_only_graph : evidence->graph) = graph;
    return true;
}

bool AppendRetirementRecoveryOwners(const catalog::RandomAccessSource& source,
    const catalog::AppleCheckpointView& checkpoint, std::vector<std::uint64_t>& metadata,
    std::vector<ApplePhysicalExtentRecord>& payload, std::string& error, RetentionAdmission admission) {
    std::shared_ptr<const RetirementGraph> graph;
    if (!LoadRetirementGraph(source, checkpoint, graph, error, admission) ||
        !ChargeRecoveryAppend(source, metadata, graph->metadata.size(), error) ||
        !ChargeRecoveryAppend(source, payload, graph->payload.size(), error)) return false;
    metadata.insert(metadata.end(), graph->metadata.begin(), graph->metadata.end());
    std::sort(metadata.begin(), metadata.end());
    metadata.erase(std::unique(metadata.begin(), metadata.end()), metadata.end());
    for (const auto r : graph->payload)
        payload.push_back({r.physical_block, r.block_count, kApplePhysicalExtentKindNew, 1, 1});
    return true;
}
}

static bool BorrowCompletedSnapshotRetention(const catalog::RandomAccessSource& source,
    const catalog::AppleCheckpointView& checkpoint, AppleSnapshotRetentionView& retention,
    std::shared_ptr<const std::vector<SnapshotRetentionCatalog>>* catalogs,
    bool authoritative, bool& found, std::string& error, RetentionAdmission admission) {
    found = false;
    std::shared_ptr<const RetirementGraph> graph;
    if (!FindCompletedRetirementGraph(source, checkpoint, graph, error, admission)) return false;
    if (!graph) return true;
    if (authoritative && !VerifyAppleSpacemanOwnershipUnchanged(source, 0, source.SizeBytes(),
            checkpoint.container, checkpoint.spaceman, error)) return false;
    const auto& logical = graph->logical;
    if (!ChargeRecoveryAppend(source, retention.identities, logical.identities.size(), error) ||
        !ChargeRecoveryAppend(source, retention.metadata_blocks, logical.metadata_blocks.size(), error) ||
        !ChargeRecoveryAppend(source, retention.payload_extents, logical.payload_extents.size(), error)) return false;
    for (const auto& identity : logical.identities)
        if (!MaterializeRecovery(source, identity.name_utf8.size() + identity.scope.container_uuid_hex.size() +
                identity.scope.volume_uuid_hex.size(), 1, error)) return false;
    retention = logical;
    if (catalogs) *catalogs = graph->catalogs;
    found = true;
    return true;
}

static bool ProveAppleSnapshotRetirementImpl(const catalog::RandomAccessSource& source,
    const catalog::AppleCheckpointView& checkpoint, const AppleCheckpointPublicationPlan& publication,
    std::uint64_t volume_oid, const std::vector<std::uint64_t>& required_checkpoint_xids,
    AppleSnapshotRetirementProof& out_proof, std::string& error, bool retain_removed_metadata) try {
    out_proof = {}; error.clear();
    if (!source.ReadBudget()) {
        auto budget = std::make_shared<catalog::ApfsReadBudget>(65536, 256ull << 20, 1000000, 256ull << 20);
        catalog::BudgetedRandomAccessSource bounded(source, budget);
        return ProveAppleSnapshotRetirementImpl(bounded, checkpoint, publication, volume_oid,
            required_checkpoint_xids, out_proof, error, retain_removed_metadata);
    }
    RecoveryBudgetErrorScope scope{source, error};
    const auto current = catalog::LoadAppleCheckpointView(source, 0, source.SizeBytes(), error);
    if (!current || current->container.superblock_bytes != checkpoint.container.superblock_bytes ||
        current->container.superblock_physical_block != checkpoint.container.superblock_physical_block)
        return Fail(error, "AppleSnapshotRetirementEndpointUnproven");
    SnapshotPublicationSource staged(source, publication);
    auto next = catalog::LoadAppleCheckpointView(staged, 0, staged.SizeBytes(), error);
    if (!next || next->container.superblock.xid != checkpoint.container.superblock.next_xid ||
        next->container.superblock.uuid_hex != checkpoint.container.superblock.uuid_hex || !volume_oid)
        return Fail(error, "AppleSnapshotRetirementEndpointUnproven");
    std::shared_ptr<const RetirementGraph> before_graph, after_graph;
    if (!LoadRetirementGraph(source, *current, before_graph, error) ||
        !LoadRetirementGraph(staged, *next, after_graph, error)) return false;
    const auto& before = *before_graph;
    const auto& after = *after_graph;
    if (!before.owners.count(volume_oid) || before.owners.size() != after.owners.size())
        return Fail(error, "AppleSnapshotRetirementPeerChanged");
    AppleSnapshotRetirementProof proof;
    for (const auto& [owner, ranges] : before.owners) {
        if (owner) {
            const auto volume = std::find_if(current->volumes.begin(), current->volumes.end(),
                [&](const auto& v) { return v.superblock.object_id == owner; });
            // Exact deltas cannot repair an understated source charge. Larger
            // historical surplus remains charged; only a proved deficit refuses.
            if (volume == current->volumes.end() ||
                volume->superblock.space.allocated_block_count < RetirementCount(ranges))
                return Fail(error, "AppleSnapshotRetirementSourceChargeUnproven");
        }
        if (!ChargeRecoveryAppend(source, proof.source_owned_blocks, ranges.size(), error)) return false;
        proof.source_owned_blocks.insert(proof.source_owned_blocks.end(), ranges.begin(), ranges.end());
        const auto found = after.owners.find(owner);
        if (found == after.owners.end()) return Fail(error, "AppleSnapshotRetirementPeerChanged");
        auto removed = RetirementDifference(ranges, found->second);
        auto added = RetirementDifference(found->second, ranges);
        if (owner != 0 && owner != volume_oid && (!removed.empty() || !added.empty()))
            return Fail(error, "AppleSnapshotRetirementPeerChanged");
        if (retain_removed_metadata) {
            RetirementRanges metadata;
            if (!ChargeRecoveryAppend(source, metadata, before.metadata.size(), error)) return false;
            for (const auto block : before.metadata) metadata.push_back({block, 1});
            NormalizeRetirementRanges(metadata);
            removed = RetirementDifference(removed, metadata);
        }
        if (!ChargeRecoveryAppend(source, proof.releases, removed.size(), error)) return false;
        proof.releases.insert(proof.releases.end(), removed.begin(), removed.end());
        if (owner == volume_oid) {
            proof.allocated_volume_blocks = RetirementCount(added);
            proof.retired_volume_blocks = RetirementCount(removed);
            proof.retired_volume_payload_blocks = proof.retired_volume_blocks;
            for (const auto r : removed) {
                auto it = std::lower_bound(before.metadata.begin(), before.metadata.end(), r.physical_block);
                while (it != before.metadata.end() && *it < r.physical_block + r.block_count) {
                    --proof.retired_volume_payload_blocks; ++it;
                }
            }
        }
    }
    NormalizeRetirementRanges(proof.releases);
    NormalizeRetirementRanges(proof.source_owned_blocks);
    std::vector<AppleRecoveryCheckpointView> pins;
    if (!LoadAppleSnapshotRecoveryCheckpoints(source, checkpoint, required_checkpoint_xids, pins, error)) return false;
    for (const auto r : proof.releases) for (const auto& pin : pins) {
        const auto end = r.physical_block + r.block_count;
        for (const auto block : pin.metadata_blocks)
            if (block >= r.physical_block && block < end) return Fail(error, "AppleSnapshotDeleteRecoveryOwner");
        for (const auto& p : pin.payload_extents)
            if (p.physical_block < end && r.physical_block < p.physical_block + p.block_count)
                return Fail(error, "AppleSnapshotDeleteRecoveryOwner");
    }
    if (!ChargeRecoveryAppend(source, proof.source_metadata_blocks, before.metadata.size(), error)) return false;
    proof.source_metadata_blocks = before.metadata;
    for (const auto& pin : pins) {
        if (!ChargeRecoveryAppend(source, proof.source_metadata_blocks, pin.metadata_blocks.size(), error) ||
            !ChargeRecoveryAppend(source, proof.source_owned_blocks,
                pin.metadata_blocks.size() + pin.payload_extents.size(), error)) return false;
        proof.source_metadata_blocks.insert(proof.source_metadata_blocks.end(),
            pin.metadata_blocks.begin(), pin.metadata_blocks.end());
        for (const auto block : pin.metadata_blocks) proof.source_owned_blocks.push_back({block, 1});
        for (const auto& p : pin.payload_extents) proof.source_owned_blocks.push_back({p.physical_block, p.block_count});
    }
    std::sort(proof.source_metadata_blocks.begin(), proof.source_metadata_blocks.end());
    proof.source_metadata_blocks.erase(std::unique(proof.source_metadata_blocks.begin(), proof.source_metadata_blocks.end()),
        proof.source_metadata_blocks.end());
    NormalizeRetirementRanges(proof.source_owned_blocks);
    out_proof = std::move(proof); return true;
}
catch (const std::bad_alloc&) {out_proof = {}; return RecoveryAllocationFailed(source, error);}
catch (const std::length_error&) {out_proof = {}; return RecoveryAllocationFailed(source, error);}

bool ProveAppleSnapshotRetirement(const catalog::RandomAccessSource& source,
    const catalog::AppleCheckpointView& checkpoint, const AppleCheckpointPublicationPlan& publication,
    std::uint64_t volume_oid, const std::vector<std::uint64_t>& required_checkpoint_xids,
    AppleSnapshotRetirementProof& out_proof, std::string& error) {
    return ProveAppleSnapshotRetirementImpl(source, checkpoint, publication, volume_oid,
        required_checkpoint_xids, out_proof, error, false);
}

static bool FindAppleVolumeReplayBoundaryImpl(
    const catalog::RandomAccessSource& source,
    const catalog::AppleCheckpointView& checkpoint,
    std::uint64_t volume_object_id,
    std::uint64_t accepted_preimage_xid,
    AppleVolumeReplayBoundary& out_boundary,
    std::string& out_error, bool snapshot_profile) try
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
    if (!(snapshot_profile ? LoadAppleSnapshotRecoveryCheckpoints(source,*current,{accepted_preimage_xid},history,out_error)
        : LoadAppleRecoveryCheckpoints(source,*current,{accepted_preimage_xid},history,out_error)))return false;
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

static bool PlanAppleTransactionCommitImpl(
    const catalog::RandomAccessSource& source,
    const catalog::AppleCheckpointView& checkpoint,
    const AppleTransactionCommitRequest& request,
    AppleTransactionCommitPlan& out_plan,
    std::string& out_error, bool preserve_snapshots,
    const AppleSnapshotInventoryChange* inventory_change = nullptr,
    bool retirement_candidate = false, bool endpoint_bound = false,
    std::span<const std::uint64_t> capacity_payload = {}, bool capacity_only = false) try
{
    out_plan = {};
    out_error.clear();
    if (preserve_snapshots && !source.ReadBudget()) {
        auto budget = std::make_shared<catalog::ApfsReadBudget>(65536, 256ull << 20, 1000000, 256ull << 20);
        catalog::BudgetedRandomAccessSource bounded(source, budget);
        return PlanAppleTransactionCommitImpl(bounded, checkpoint, request, out_plan, out_error,
            preserve_snapshots, inventory_change, retirement_candidate, endpoint_bound);
    }
    if (preserve_snapshots && !endpoint_bound) {
        const auto current = catalog::LoadAppleCheckpointView(source, 0, source.SizeBytes(), out_error);
        if (!current || current->container.superblock_bytes != checkpoint.container.superblock_bytes ||
            current->container.superblock_physical_block != checkpoint.container.superblock_physical_block)
            return Fail(out_error, "AppleSnapshotRetirementEndpointUnproven");
        return PlanAppleTransactionCommitImpl(source, *current, request, out_plan, out_error,
            preserve_snapshots, inventory_change, retirement_candidate, true);
    }
    RecoveryBudgetErrorScope budget_error{source, out_error};
    if (!MaterializeRecovery(source, 0, 0, out_error)) return false;
    const auto& nxsb = checkpoint.container.superblock;
    const auto& allocation = request.allocation_plan;
    const bool retirement = request.snapshot_retirement_volume_oid != 0;
    if (capacity_only && (preserve_snapshots || retirement || inventory_change || retirement_candidate))
        return Fail(out_error, "AppleCapacityPreviewProfileUnsupported");
    if (retirement && !preserve_snapshots)
        return Fail(out_error, "AppleSnapshotRetirementTypedComposerRequired");
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
            request.allocated_main_writes, nxsb.block_size, out_error, capacity_payload))
    {
        return false;
    }

    AppleSnapshotRetentionView snapshot_retention;
    std::shared_ptr<const std::vector<SnapshotRetentionCatalog>> snapshot_catalogs;
    if (!LoadSnapshotPlanningRetentionCatalogs(source, checkpoint, snapshot_retention, snapshot_catalogs, out_error)) return false;
    AppleSnapshotDeleteReferencePlan deletion;
    if (inventory_change) {
        if (inventory_change->created.has_value() == inventory_change->removed.has_value())
            return Fail(out_error, "AppleSnapshotInventoryOperationInvalid");
        if (inventory_change->created && (inventory_change->created->snapshot_xid != nxsb.next_xid ||
            inventory_change->created->scope.checkpoint_xid != nxsb.next_xid ||
            inventory_change->created->scope.container_uuid_hex != nxsb.uuid_hex))
            return Fail(out_error, "AppleSnapshotInventoryCreateIdentityInvalid");
        if (inventory_change->removed && !PlanAppleSnapshotDeleteReferences(source, checkpoint,
            *inventory_change->removed, deletion, out_error)) return false;
    }
    const auto deletion_payload = [&](std::uint64_t block, std::uint64_t count) {
        if (!count || block >= nxsb.block_count || count > nxsb.block_count - block) return false;
        return std::any_of(deletion.unreferenced_payload.begin(), deletion.unreferenced_payload.end(),
            [&](const auto& r) {return r.physical_block <= block && block - r.physical_block <= r.block_count &&
                count <= r.block_count - (block - r.physical_block);});
    };
    const auto protects = [&](std::uint64_t block, std::uint64_t count) {
        if (!count || block >= nxsb.block_count || count > nxsb.block_count - block) return true;
        const auto end = block + count;
        const auto meta = std::lower_bound(snapshot_retention.metadata_blocks.begin(),
            snapshot_retention.metadata_blocks.end(), block);
        if (meta != snapshot_retention.metadata_blocks.end() && *meta < end) return true;
        return std::any_of(snapshot_retention.payload_extents.begin(), snapshot_retention.payload_extents.end(),
            [&](const auto& extent) { return extent.physical_block < end &&
                block < extent.physical_block + extent.block_count; });
    };
    if (!snapshot_retention.identities.empty()) {
        // The explicit preserving entry point proves exact snapshot identity,
        // all before/after allocation bytes and the new live reference layer.
        // The original compositor keeps its previous admission boundary.
        if (!preserve_snapshots && request.container_object_map_oid != 0 &&
            request.container_object_map_oid != checkpoint.container_object_map.object.object_id)
            return Fail(out_error, "AppleTransactionSnapshotRootReplacementUnsupported");
        for (const auto& release : allocation.deferred_frees)
            if (protects(release.physical_block, release.block_count) &&
                !deletion_payload(release.physical_block, release.block_count) && !retirement)
                return Fail(out_error, "AppleTransactionSnapshotBlockReleased");
        for (const auto block : allocation.allocated_main_blocks)
            if (protects(block, 1)) return Fail(out_error, "AppleTransactionSnapshotBlockReused");
        for (const auto block : snapshot_retention.metadata_blocks)
            if (!PayloadExtentStillOwned(allocation.updated_spaceman,
                ApplePhysicalExtentRecord{block, 1, kApplePhysicalExtentKindNew, 1, 1},
                retirement ? nxsb.xid : allocation.transaction_xid))
                return Fail(out_error, "AppleTransactionSnapshotOwnershipLost");
        for (const auto& extent : snapshot_retention.payload_extents)
            if (!PayloadExtentStillOwned(allocation.updated_spaceman, extent,
                    retirement ? nxsb.xid : allocation.transaction_xid) &&
                !inventory_change)
                return Fail(out_error, "AppleTransactionSnapshotOwnershipLost");
    }
    std::vector<AppleRecoveryCheckpointView> retained;
    const auto load_pins = preserve_snapshots ? LoadAppleSnapshotRecoveryCheckpoints : LoadAppleRecoveryCheckpoints;
    if (!load_pins(source, checkpoint,
            request.required_checkpoint_xids, retained, out_error))
    {
        return false;
    }
    if (inventory_change) {
        // No generic release permission is exposed by this typed composer.
        // Retained pin owners veto queuing even though the allocator would
        // postpone reuse until their floor has advanced.
        for (const auto& r : allocation.deferred_frees) {
            if (r.queue_index != 1) continue; // canonical allocator's own metadata
            if (!deletion_payload(r.physical_block, r.block_count) && !retirement)
                return Fail(out_error, "AppleSnapshotInventoryReleaseNotProven");
            const auto end = r.physical_block + r.block_count;
            for (const auto& pin : retained) {
                for (const auto b : pin.metadata_blocks)
                    if (b >= r.physical_block && b < end) return Fail(out_error, "AppleSnapshotDeleteRecoveryOwner");
                for (const auto& p : pin.payload_extents)
                    if (p.physical_block < end && r.physical_block < p.physical_block + p.block_count)
                        return Fail(out_error, "AppleSnapshotDeleteRecoveryOwner");
            }
        }
        // Every old payload must remain physically allocated, including data
        // queued by this transaction for the old checkpoint's recovery view.
        for (const auto& p : snapshot_retention.payload_extents)
            if (!PayloadExtentStillOwned(allocation.updated_spaceman, p, nxsb.xid))
                return Fail(out_error, "AppleTransactionSnapshotOwnershipLost");
    }
    auto required_floor = nxsb.xid;
    const auto prove_retirement = [&](AppleTransactionCommitPlan& plan, const auto& add_guard) {
        if (!preserve_snapshots || retirement_candidate) return true;
        // The volume is derived from actual APSB writes, not from the optional
        // request to retire metadata. Retaining old metadata still needs proof.
        std::uint64_t selected_oid = 0;
        for (const auto& write : request.allocated_main_writes) {
            if (write.bytes.size() != nxsb.block_size ||
                catalog::ReadU32LE(write.bytes, 0x18) != catalog::kObjectTypeFs) continue;
            const auto oid = catalog::ReadU64LE(write.bytes, 8).value_or(0);
            if (std::none_of(checkpoint.volumes.begin(), checkpoint.volumes.end(),
                    [&](const auto& v) { return v.superblock.object_id == oid; }) || selected_oid)
                return Fail(out_error, "AppleSnapshotRetirementVolumeMissing");
            selected_oid = oid;
        }
        if (!selected_oid || (retirement && selected_oid != request.snapshot_retirement_volume_oid))
            return Fail(out_error, "AppleSnapshotRetirementVolumeMissing");
        AppleSnapshotRetirementProof proof;
        if (!ProveAppleSnapshotRetirementImpl(source, checkpoint, plan.publication,
                selected_oid, request.required_checkpoint_xids, proof, out_error, !retirement)) return false;
        RetirementRanges requested;
        for (const auto& r : allocation.deferred_frees) if (r.queue_index == 1) {
            if (!ChargeRecoveryAppend(source, requested, 1, out_error)) return false;
            requested.push_back({r.physical_block, r.block_count});
        }
        NormalizeRetirementRanges(requested);
        if (!RetirementDifference(requested, proof.releases).empty() ||
            !RetirementDifference(proof.releases, requested).empty())
            return Fail(out_error, "AppleSnapshotRetirementReleaseNotProven");
        SnapshotPublicationSource staged(source, plan.publication);
        const auto after = catalog::LoadAppleCheckpointView(staged, 0, staged.SizeBytes(), out_error);
        if (!after) return false;
        const auto floor = allocation.effective_oldest_required_checkpoint_xid;
        if (!floor || floor > required_floor)
            return Fail(out_error, "AppleTransactionRetentionProtectionMissing");
        // The serialized queue is authoritative; the allocator's release
        // summary alone cannot prove deferred lifetime or a retirement XID.
        std::map<std::uint64_t, RetirementRanges> expected_queue, actual_queue;
        const auto append_queue = [&](auto& queues, std::uint64_t xid, const auto& range) {
            if (!MaterializeRecovery(source, 1, sizeof(AppleSpacemanReleaseRequest) + 64, out_error)) return false;
            queues[xid].push_back({range.physical_block, range.block_count});
            return true;
        };
        for (const auto& entry : checkpoint.spaceman.free_queues[1].entries)
            if (entry.xid > floor && !append_queue(expected_queue, entry.xid, entry)) return false;
        for (const auto r : proof.releases)
            if (!append_queue(expected_queue, allocation.transaction_xid, r)) return false;
        for (const auto& entry : after->spaceman.free_queues[1].entries)
            if (!append_queue(actual_queue, entry.xid, entry)) return false;
        if (expected_queue.size() != actual_queue.size())
            return Fail(out_error, "AppleSnapshotRetirementSerializedQueueUnproven");
        for (auto& [xid, ranges] : expected_queue) {
            const auto found = actual_queue.find(xid);
            if (found == actual_queue.end())
                return Fail(out_error, "AppleSnapshotRetirementSerializedQueueUnproven");
            NormalizeRetirementRanges(ranges);
            NormalizeRetirementRanges(found->second);
            if (!RetirementDifference(ranges, found->second).empty() ||
                !RetirementDifference(found->second, ranges).empty())
                return Fail(out_error, "AppleSnapshotRetirementSerializedQueueUnproven");
        }
        // Recheck every accepted history transition against actual staged
        // bitmaps/queues, including the full hidden ownership of the preimage.
        auto staged_pins = request.required_checkpoint_xids;
        if (!ChargeRecoveryAppend(source, staged_pins, 1, out_error)) return false;
        staged_pins.push_back(nxsb.xid);
        std::vector<AppleRecoveryCheckpointView> staged_history;
        if (!LoadAppleSnapshotRecoveryCheckpoints(staged, *after, staged_pins, staged_history, out_error)) return false;
        for (const auto& old : checkpoint.volumes) {
            const auto found = std::find_if(after->volumes.begin(), after->volumes.end(),
                [&](const auto& v) { return v.superblock.object_id == old.superblock.object_id; });
            std::vector<std::byte> a, b;
            if (found == after->volumes.end() || !ReadBlock(source, old.superblock_object.physical_block, nxsb.block_size, a) ||
                !ReadBlock(staged, found->superblock_object.physical_block, nxsb.block_size, b))
                return Fail(out_error, "AppleSnapshotRetirementCounterUnproven");
            const bool selected = old.superblock.object_id == selected_oid;
            if (catalog::ReadU64LE(a, 0x48) != catalog::ReadU64LE(b, 0x48) ||
                catalog::ReadU64LE(a, 0x50) != catalog::ReadU64LE(b, 0x50))
                return Fail(out_error, "AppleSnapshotRetirementLimitsChanged");
            const auto added = selected ? proof.allocated_volume_blocks : 0;
            const auto removed = selected ? proof.retired_volume_blocks : 0;
            for (const auto offset : {0x58u, 0xe0u, 0xe8u}) {
                auto expected = catalog::ReadU64LE(a, offset).value();
                const auto increase = offset == 0xe8 ? removed : added;
                if (increase > UINT64_MAX - expected) return Fail(out_error, "AppleSnapshotRetirementCounterUnproven");
                expected += increase;
                if (offset == 0x58) {
                    if (removed > expected) return Fail(out_error, "AppleSnapshotRetirementCounterUnproven");
                    expected -= removed;
                }
                if (catalog::ReadU64LE(b, offset) != expected)
                    return Fail(out_error, "AppleSnapshotRetirementCounterUnproven");
            }
        }
        const auto own = std::find_if(after->volumes.begin(), after->volumes.end(),
            [&](const auto& v) {return v.superblock.object_id == selected_oid;});
        const auto previous = std::find_if(checkpoint.volumes.begin(), checkpoint.volumes.end(),
            [&](const auto& v) {return v.superblock.object_id == selected_oid;});
        if (own == after->volumes.end() || previous == checkpoint.volumes.end())
            return Fail(out_error, "AppleSnapshotRetirementVolumeMissing");
        const auto& limits = own->superblock.space;
        const auto charge = limits.allocated_block_count;
        const auto free = after->spaceman.devices[0].free_count;
        if (limits.quota_block_count && charge > limits.quota_block_count && charge > previous->superblock.space.allocated_block_count)
            return Fail(out_error, "AppleVolumeQuotaExceeded");
        std::uint64_t siblings = 0;
        for (const auto& peer : after->volumes) {
            if (peer.superblock.object_id == selected_oid) continue;
            const auto& counters = peer.superblock.space;
            const auto unmet = counters.reserve_block_count > counters.allocated_block_count
                ? counters.reserve_block_count - counters.allocated_block_count : 0;
            if (unmet > UINT64_MAX - siblings) return Fail(out_error, "AppleVolumeSiblingReserveProtected");
            siblings += unmet;
        }
        if (free < siblings)
            return Fail(out_error, "AppleVolumeSiblingReserveProtected");
        const auto reserve = limits.reserve_block_count > charge ? limits.reserve_block_count - charge : 0;
        if (reserve > free - siblings)
            return Fail(out_error, "AppleVolumeReserveCapacityProtected");
        catalog::ApfsSharedSpaceProjection space;
        if (!catalog::TryProjectAppleSharedSpace(*after, space, out_error)) return false;
        for (const auto& write : plan.publication.before_superblock_writes) {
            const auto count = write.bytes.size() / nxsb.block_size;
            for (const auto r : proof.source_owned_blocks)
                if (write.physical_block < r.physical_block + r.block_count &&
                    r.physical_block < write.physical_block + count)
                    return Fail(out_error, "AppleSnapshotRetirementSourceReused");
        }
        for (const auto block : proof.source_metadata_blocks)
            if (!add_guard(block)) return Fail(out_error, "AppleTransactionGuardUnreadable");
        return true;
    };
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
    if (!(capacity_only
        ? capacity_detail::PlanPublication(source, checkpoint.container, publication,
            capacity_payload, plan.publication, out_error)
        : PlanAppleCheckpointPublication(source, checkpoint.container,
            publication, plan.publication, out_error)))
    {
        return false;
    }
    if (!MaterializeRecovery(source, 1,
            sizeof(std::set<std::uint64_t>) + kGuardIndexNodeBytes, out_error)) return false;
    std::set<std::uint64_t> guard_index;
    for (const auto& guard : plan.publication.guard_blocks) {
        if (guard_index.contains(guard.physical_block)) continue;
        if (!MaterializeRecovery(source, 1, kGuardIndexNodeBytes, out_error)) return false;
        guard_index.insert(guard.physical_block);
    }
    const auto add_guard = [&](std::uint64_t block) {
        return AddStableGuard(source, block, nxsb.block_size,
            plan.publication.guard_blocks, guard_index);
    };
    if (!preserve_snapshots) {
        // The ordinary entry point also observes a complete current owner
        // closure, including untouched peers and hidden descriptor edges.
        // Reuse that proof; do not parse the payload graph a second time.
        const auto* owners = SnapshotPlanningEvidenceAccess::Get(source, checkpoint, out_error);
        if (!owners || !owners->owners_complete || !out_error.empty())
            return Fail(out_error, "AppleTransactionCurrentOwnershipUnproven");
        for (const auto block : owners->metadata)
            if (!add_guard(block)) return Fail(out_error, "AppleTransactionGuardUnreadable");
    }
    // The old selected checkpoint may remain byte-identical after a commit.
    // Bind the destination descriptor slot too: it changes only at the switch,
    // so both pre-switch guard checks pass, while stale replay fails before I/O.
    if (preserve_snapshots && !add_guard(plan.publication.superblock_write.physical_block))
        return Fail(out_error, "AppleTransactionGuardUnreadable");
    // The candidate is a non-executable input to the retirement owner walk.
    // The final typed composer proves the inventory and live view below.
    if (!retirement_candidate && (!snapshot_retention.identities.empty() || inventory_change)) {
        for (const auto& write : plan.publication.before_superblock_writes)
            if (protects(write.physical_block, write.bytes.size() / nxsb.block_size))
                return Fail(out_error, "AppleTransactionSnapshotBlockReused");
        for (const auto block : snapshot_retention.metadata_blocks)
            if (!add_guard(block)) return Fail(out_error, "AppleTransactionGuardUnreadable");
        SnapshotPublicationSource staged(source, plan.publication);
        auto staged_checkpoint = catalog::LoadAppleCheckpointView(staged, 0, staged.SizeBytes(), out_error);
        AppleSnapshotRetentionView staged_retention;
        std::shared_ptr<const std::vector<SnapshotRetentionCatalog>> staged_catalogs;
        if (!staged_checkpoint || staged_checkpoint->container.superblock.xid != allocation.transaction_xid ||
            !LoadAppleSnapshotRetentionImpl(staged, *staged_checkpoint, staged_retention, out_error, true, &staged_catalogs)) {
            if (out_error.empty()) out_error = "AppleTransactionSnapshotStagedOwnershipInvalid";
            return false;
        }
        const auto expected_count = snapshot_retention.identities.size() +
            (inventory_change && inventory_change->created ? 1 : 0) -
            (inventory_change && inventory_change->removed ? 1 : 0);
        if (staged_retention.identities.size() != expected_count)
            return Fail(out_error, "AppleTransactionSnapshotInventoryChanged");
        for (const auto& old_identity : snapshot_retention.identities) {
            if (inventory_change && inventory_change->removed && old_identity == *inventory_change->removed) continue;
            auto expected = old_identity;
            expected.scope.checkpoint_xid = allocation.transaction_xid;
            const auto found = std::find_if(staged_retention.identities.begin(), staged_retention.identities.end(),
                [&](const auto& id){return id.snapshot_xid == expected.snapshot_xid && id.scope.volume_oid == expected.scope.volume_oid;});
            if (found == staged_retention.identities.end()) return Fail(out_error, "AppleTransactionSnapshotInventoryChanged");
            if (inventory_change && inventory_change->removed) {
                expected.superblock_physical_block = found->superblock_physical_block;
                expected.extentref_physical_block = found->extentref_physical_block;
                const auto select = [](const auto& catalogs, const auto& identity,
                    const SnapshotRetentionCatalog*& selected, std::size_t& index) {
                    if (!catalogs) return false;
                    for (const auto& catalog : *catalogs) {
                        if (catalog.volume_oid != identity.scope.volume_oid ||
                            catalog.records.inventory.size() != catalog.records.snapshots.size() ||
                            catalog.records.inventory.size() != catalog.snapshot_payloads.size()) continue;
                        for (std::size_t i = 0; i < catalog.records.inventory.size(); ++i)
                            if (catalog.records.inventory[i].xid == identity.snapshot_xid) {
                                selected = &catalog; index = i; return true;
                            }
                    }
                    return false;
                };
                const SnapshotRetentionCatalog* before_catalog = nullptr;
                const SnapshotRetentionCatalog* after_catalog = nullptr;
                std::size_t before_index = 0, after_index = 0;
                if (!select(snapshot_catalogs, old_identity, before_catalog, before_index) ||
                    !select(staged_catalogs, *found, after_catalog, after_index))
                    return Fail(out_error, "AppleSnapshotDeleteSurvivorViewMissing");
                const auto equal = [](const auto& a, const auto& b) {
                    return a.size() == b.size() && std::equal(a.begin(), a.end(), b.begin(),
                        [](const auto& x, const auto& y){return x.key == y.key && x.value == y.value;});};
                const auto& before_geometry = before_catalog->snapshot_payloads[before_index];
                const auto& after_geometry = after_catalog->snapshot_payloads[after_index];
                const bool equal_geometry = before_geometry.size() == after_geometry.size() &&
                    std::equal(before_geometry.begin(), before_geometry.end(), after_geometry.begin(),
                        [](const auto& a, const auto& b) {
                            return a.physical_block == b.physical_block && a.block_count == b.block_count &&
                                a.kind == b.kind && a.owning_object_id == b.owning_object_id &&
                                a.reference_count == b.reference_count;
                        });
                if (!equal(before_catalog->records.snapshots[before_index].filesystem,
                        after_catalog->records.snapshots[after_index].filesystem) || !equal_geometry)
                    return Fail(out_error, "AppleSnapshotDeleteSurvivorViewChanged");
                const auto& before_meta=before_catalog->records.inventory[before_index];
                const auto& after_meta=after_catalog->records.inventory[after_index];
                if (before_meta.create_time_ns!=after_meta.create_time_ns || before_meta.change_time_ns!=after_meta.change_time_ns ||
                    before_meta.inum!=after_meta.inum || before_meta.flags!=after_meta.flags)
                    return Fail(out_error, "AppleSnapshotDeleteSurvivorMetadataChanged");
                std::vector<std::byte> a, b;
                if (!ReadBlock(source, old_identity.superblock_physical_block, nxsb.block_size, a) ||
                    !ReadBlock(staged, found->superblock_physical_block, nxsb.block_size, b)) return Fail(out_error, "AppleTransactionGuardUnreadable");
                // Only checksum, physical OID, metadata XID and extent root
                // change. Historical namespace, counters and OMAP are stable.
                for (std::size_t j = 0; j < a.size(); ++j)
                    if (!(j < 24 || (j >= 0x90 && j < 0x98)) && a[j] != b[j])
                        return Fail(out_error, "AppleSnapshotDeleteSurvivorMetadataChanged");
            }
            if (!(expected == *found))
                return Fail(out_error, "AppleTransactionSnapshotInventoryChanged");
        }
        if (inventory_change && inventory_change->created &&
            std::find(staged_retention.identities.begin(), staged_retention.identities.end(),
                *inventory_change->created) == staged_retention.identities.end())
            return Fail(out_error, "AppleSnapshotCreateStagedIdentityMismatch");
        if (inventory_change) {
            const std::vector<SnapshotRetentionCatalog> empty_catalogs;
            const auto& catalogs = staged_catalogs ? *staged_catalogs : empty_catalogs;
            // Even final deletion (empty snapshot census) must prove exact
            // live coverage and allocator ownership independently of staging.
            for (const auto& volume : staged_checkpoint->volumes) {
                const auto old = std::find_if(checkpoint.volumes.begin(), checkpoint.volumes.end(),
                    [&](const auto& v){return v.superblock.object_id == volume.superblock.object_id;});
                if (old == checkpoint.volumes.end() || old->root_tree.physical_block != volume.root_tree.physical_block ||
                    old->superblock.root_oid != volume.superblock.root_oid)
                    return Fail(out_error, "AppleSnapshotInventoryLiveViewChanged");
                const auto found_catalog = std::find_if(catalogs.begin(), catalogs.end(),
                    [&](const auto& c) { return c.volume_oid == volume.superblock.object_id; });
                catalog::AppleSnapshotCatalogRecords empty_catalog;
                if (found_catalog == catalogs.end()) {
                    // Empty final deletion has no retention census. Establish
                    // its canonical live coverage and allocator proof here.
                    std::vector<ApplePhysicalExtentRecord> payload;
                    if (!(HasPhysicalSnapshotMetadata(volume) ?
                            catalog::LoadAppleReadOnlySnapshotCatalog(staged, *staged_checkpoint, volume.superblock.object_id,
                                empty_catalog, out_error) :
                            catalog::LoadAppleSnapshotCatalog(staged, *staged_checkpoint, volume.superblock.object_id,
                                empty_catalog, out_error)) ||
                        !ChargeRecoveryPayloadGraph(staged, empty_catalog.live.filesystem, empty_catalog.live.extentref, out_error) ||
                        !ValidateApplePayloadExtentGraph(empty_catalog.live.filesystem, empty_catalog.live.extentref,
                            nxsb.block_size, nxsb.block_count, payload, out_error) ||
                        !ValidateAppleCheckpointPayloadOwnership(staged, *staged_checkpoint, payload, out_error)) return false;
                }
                const auto& owned = found_catalog == catalogs.end() ? empty_catalog : found_catalog->records;
                const auto& fs = owned.live.filesystem;
                const auto& visited = owned.metadata_blocks;
                std::vector<catalog::BtreeRecord> old_fs; std::vector<std::uint64_t> old_visited;
                if (!ReadCheckpointTree(source, checkpoint, old->root_tree, old->superblock.omap_oid, old_fs, old_visited, out_error)) return false;
                const auto equal = [](const auto& a, const auto& b) {
                    return a.size()==b.size() && std::equal(a.begin(),a.end(),b.begin(),
                        [](const auto& x,const auto& y){return x.key==y.key && x.value==y.value;});};
                if (!equal(old_fs, fs)) return Fail(out_error, "AppleSnapshotInventoryLiveViewChanged");
                for (const auto block : old_visited) if (!add_guard(block)) return Fail(out_error, "AppleTransactionGuardUnreadable");
                if (inventory_change->created && inventory_change->created->scope.volume_oid == volume.superblock.object_id) {
                    const auto created = std::find_if(owned.inventory.begin(), owned.inventory.end(),
                        [&](const auto& s) { return s.xid == inventory_change->created->snapshot_xid; });
                    if (created == owned.inventory.end() ||
                        !equal(owned.snapshots[created-owned.inventory.begin()].filesystem, old_fs))
                        return Fail(out_error, "AppleSnapshotCreateViewChanged");
                }
                for (const auto block : visited)
                    if (std::find(allocation.allocated_main_blocks.begin(), allocation.allocated_main_blocks.end(), block) == allocation.allocated_main_blocks.end() && !add_guard(block))
                        return Fail(out_error, "AppleTransactionGuardUnreadable");
            }
        }
    }
    if (!prove_retirement(plan, add_guard)) return false;
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

bool PlanAppleTransactionCommit(const catalog::RandomAccessSource& source,
    const catalog::AppleCheckpointView& checkpoint, const AppleTransactionCommitRequest& request,
    AppleTransactionCommitPlan& out_plan, std::string& out_error) try
{
    out_plan = {};
    out_error.clear();
    if (!source.ReadBudget()) {
        auto budget = std::make_shared<catalog::ApfsReadBudget>(65536, 256ull << 20, 1000000, 256ull << 20);
        catalog::BudgetedRandomAccessSource bounded(source, budget);
        return PlanAppleTransactionCommit(bounded, checkpoint, request, out_plan, out_error);
    }
    RecoveryBudgetErrorScope budget_error{source, out_error};
    const auto* observation = dynamic_cast<const SnapshotPlanningSource*>(&source);
    if (!observation) {
        SnapshotPlanningSource observed(source);
        return PlanAppleTransactionCommit(observed, checkpoint, request, out_plan, out_error);
    }
    SnapshotPlanningEvidenceAccess::CommitScope operation(*observation, out_error);
    if (!operation) return false;
    // Bind the supplied allocator view before lending its allocation bits and
    // queues to the complete owner proof performed by the compositor.
    if (!VerifyAppleSpacemanOwnershipUnchanged(source, 0, source.SizeBytes(),
            checkpoint.container, checkpoint.spaceman, out_error)) return false;
    AppleTransactionCommitPlan candidate;
    if (!PlanAppleTransactionCommitImpl(source, checkpoint, request, candidate, out_error, false) ||
        !observation->VerifyUnchanged(out_error)) return false;
    out_plan = std::move(candidate);
    return true;
}
catch (const std::bad_alloc&) { out_plan = {}; return RecoveryAllocationFailed(source, out_error); }
catch (const std::length_error&) { out_plan = {}; return RecoveryAllocationFailed(source, out_error); }

bool capacity_detail::PlanCommit(const catalog::RandomAccessSource& source,
    const catalog::AppleCheckpointView& checkpoint, const AppleTransactionCommitRequest& request,
    std::span<const std::uint64_t> payload_blocks,
    AppleTransactionCommitPlan& out_plan, std::string& out_error) try
{
    out_plan = {};
    out_error.clear();
    if (!source.ReadBudget()) {
        auto budget = std::make_shared<catalog::ApfsReadBudget>(65536, 256ull << 20, 1000000, 256ull << 20);
        catalog::BudgetedRandomAccessSource bounded(source, budget);
        return PlanCommit(bounded, checkpoint, request, payload_blocks, out_plan, out_error);
    }
    RecoveryBudgetErrorScope budget_error{source, out_error};
    const auto* observation = dynamic_cast<const SnapshotPlanningSource*>(&source);
    if (!observation) {
        SnapshotPlanningSource observed(source);
        return PlanCommit(observed, checkpoint, request, payload_blocks, out_plan, out_error);
    }
    SnapshotPlanningEvidenceAccess::CommitScope operation(*observation, out_error);
    if (!operation || !VerifyAppleSpacemanOwnershipUnchanged(source, 0, source.SizeBytes(),
            checkpoint.container, checkpoint.spaceman, out_error)) return false;
    AppleTransactionCommitPlan candidate;
    if (!PlanAppleTransactionCommitImpl(source, checkpoint, request, candidate, out_error,
            false, nullptr, false, false, payload_blocks, true) ||
        !observation->VerifyUnchanged(out_error)) return false;
    if (!candidate.publication.superblock_write.bytes.empty())
        return Fail(out_error, "AppleCapacityPreviewExecutablePlan");
    out_plan = std::move(candidate);
    return true;
}
catch (const std::bad_alloc&) { out_plan = {}; return RecoveryAllocationFailed(source, out_error); }
catch (const std::length_error&) { out_plan = {}; return RecoveryAllocationFailed(source, out_error); }

bool PlanAppleSnapshotPreservingCommit(const catalog::RandomAccessSource& source,
    const catalog::AppleCheckpointView& checkpoint, const AppleTransactionCommitRequest& request,
    AppleTransactionCommitPlan& out_plan, std::string& out_error)
{
    return PlanAppleTransactionCommitImpl(source,checkpoint,request,out_plan,out_error,true);
}

bool PlanAppleSnapshotInventoryCommit(const catalog::RandomAccessSource& source,
    const catalog::AppleCheckpointView& checkpoint, const AppleTransactionCommitRequest& request,
    const AppleSnapshotInventoryChange& change, AppleTransactionCommitPlan& out_plan, std::string& out_error) try
{
    if (!source.ReadBudget()) {
        auto budget=std::make_shared<catalog::ApfsReadBudget>(65536,256ull<<20,1000000,256ull<<20);
        catalog::BudgetedRandomAccessSource bounded(source,budget);
        return PlanAppleSnapshotInventoryCommit(bounded,checkpoint,request,change,out_plan,out_error);
    }
    return PlanAppleTransactionCommitImpl(source, checkpoint, request, out_plan, out_error, true, &change);
}
catch (const std::bad_alloc&) {out_plan={};return RecoveryAllocationFailed(source,out_error);}
catch (const std::length_error&) {out_plan={};return RecoveryAllocationFailed(source,out_error);}

bool PlanAppleSnapshotRetirementCandidate(const catalog::RandomAccessSource& source,
    const catalog::AppleCheckpointView& checkpoint, const AppleTransactionCommitRequest& request,
    const AppleSnapshotInventoryChange* change, AppleCheckpointPublicationPlan& out_publication,
    std::string& out_error) try {
    out_publication = {};
    if (request.snapshot_retirement_volume_oid)
        return Fail(out_error, "AppleSnapshotRetirementCandidateInvalid");
    if (!source.ReadBudget()) {
        auto budget = std::make_shared<catalog::ApfsReadBudget>(65536, 256ull << 20, 1000000, 256ull << 20);
        catalog::BudgetedRandomAccessSource bounded(source, budget);
        return PlanAppleSnapshotRetirementCandidate(bounded, checkpoint, request, change, out_publication, out_error);
    }
    AppleTransactionCommitPlan candidate;
    if (!PlanAppleTransactionCommitImpl(source, checkpoint, request, candidate, out_error, true, change, true))
        return false;
    out_publication = std::move(candidate.publication);
    return true;
}
catch (const std::bad_alloc&) {out_publication={};return RecoveryAllocationFailed(source,out_error);}
catch (const std::length_error&) {out_publication={};return RecoveryAllocationFailed(source,out_error);}

} // namespace apfsaccess::rw

namespace apfsaccess::rw {
bool FindAppleVolumeReplayBoundary(const catalog::RandomAccessSource&s,const catalog::AppleCheckpointView&c,std::uint64_t v,std::uint64_t x,AppleVolumeReplayBoundary&b,std::string&e){return FindAppleVolumeReplayBoundaryImpl(s,c,v,x,b,e,false);}
bool FindAppleSnapshotVolumeReplayBoundary(const catalog::RandomAccessSource&s,const catalog::AppleCheckpointView&c,std::uint64_t v,std::uint64_t x,AppleVolumeReplayBoundary&b,std::string&e){return FindAppleVolumeReplayBoundaryImpl(s,c,v,x,b,e,true);}
}
