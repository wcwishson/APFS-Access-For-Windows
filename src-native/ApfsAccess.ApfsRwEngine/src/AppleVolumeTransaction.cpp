#include "AppleVolumeTransaction.h"
#include "AppleCapacityPreviewInternal.h"
#include "WindowsMetadataAttribute.h"
#include "AppleCloneRangeMapping.h"
#include "AppleReadOnlyRecordGraph.h"
#include "ApfsReadOnlyMetadataAdmission.h"
#include "ApfsFusionVolumePlan.h"
#include "ApfsFusionReadSession.h"
#include "FusionPlanningParser.h"
#include "FusionReclamationProof.h"
#include "FusionObjectIds.h"
#include "FusionExtentCoalescing.h"
#include "PlainExtentCoalescing.h"
#include "FusionBitmapRange.h"

#include "ApfsFusionStore.h"
#include "ApfsTransactionWriter.h"
#include "ApfsExtendedRecordCodec.h"
#include "ApfsSharedSpace.h"
#include "WriteAheadLog.h"
#include "SnapshotPlanningSource.h"
#include "SoftwareTransitionVolumeTransaction.h"
#include "BackupImageWriterProfile.h"
#include "NativeApfsReader.h"

#include <algorithm>
#include <initializer_list>
#include <limits>
#include <map>
#include <set>
#include <unordered_map>
#include <unordered_set>

namespace apfsaccess::rw
{
namespace
{

constexpr std::uint64_t kFsObjectIdMask = (1ull << 60) - 1;
constexpr std::uint64_t kFsRecordTypeDataStreamId = 6;
constexpr std::uint64_t kFsRecordTypeFileExtent = 8;

bool Fail(std::string& out_error, const char* error)
{
    out_error = error;
    return false;
}

bool ReadBlock(const catalog::RandomAccessSource& source,
    std::uint64_t block, std::uint32_t block_size,
    std::vector<std::byte>& out_bytes)
{
    if (block > std::numeric_limits<std::uint64_t>::max() / block_size)
    {
        return false;
    }
    return source.Read(block * static_cast<std::uint64_t>(block_size),
        block_size, out_bytes) && out_bytes.size() == block_size;
}

struct TreeShape
{
    std::uint32_t storage_type = 0;
    std::uint32_t subtype = 0;
    std::uint32_t tree_flags = 0;
    std::uint32_t fixed_key_size = 0;
    std::uint32_t fixed_value_size = 0;
    std::uint32_t longest_key = 0;
    std::uint32_t longest_value = 0;
};

bool ReadTreeShape(const catalog::RandomAccessSource& source,
    const catalog::AppleObjectLocation& root, std::uint32_t block_size,
    TreeShape& out_shape)
{
    std::vector<std::byte> bytes;
    if (root.physical_block == 0 || !ReadBlock(
            source, root.physical_block, block_size, bytes))
    {
        return false;
    }
    const auto info = bytes.size() - 40;
    if (catalog::ReadU32LE(bytes, info + 4).value_or(0) != block_size)
    {
        return false;
    }
    out_shape.storage_type = root.type & catalog::kObjectStorageTypeMask;
    out_shape.subtype = root.subtype;
    out_shape.tree_flags = catalog::ReadU32LE(bytes, info).value_or(0);
    out_shape.fixed_key_size =
        catalog::ReadU32LE(bytes, info + 8).value_or(0);
    out_shape.fixed_value_size =
        catalog::ReadU32LE(bytes, info + 12).value_or(0);
    out_shape.longest_key =
        catalog::ReadU32LE(bytes, info + 16).value_or(0);
    out_shape.longest_value =
        catalog::ReadU32LE(bytes, info + 20).value_or(0);
    return true;
}

bool ReadTreeRecords(const catalog::RandomAccessSource& source,
    const catalog::AppleObjectLocation& root, std::uint32_t block_size,
    std::uint64_t object_map_oid, std::uint64_t max_xid,
    std::vector<catalog::BtreeRecord>& out_records,
    std::vector<std::uint64_t>& out_blocks, std::string& out_error)
{
    out_blocks.clear();
    catalog::BtreeReadPolicy policy;
    policy.enforce_object_identity = true;
    policy.root_object_id = root.object_id;
    policy.storage_type = root.type;
    policy.subtype = root.subtype;
    policy.visited_physical_blocks = &out_blocks;
    const bool physical = (root.type & catalog::kObjectStorageTypeMask) ==
        catalog::kObjectPhysical;
    return catalog::ReadBtreeLeafRecords(source, block_size,
        root.physical_block, physical, physical ? 0 : object_map_oid,
        max_xid, policy, out_records, out_error);
}

bool ReadTreeObjectIds(const catalog::RandomAccessSource& source,
    std::span<const std::uint64_t> blocks, std::uint32_t block_size,
    std::unordered_set<std::uint64_t>& out_ids)
{
    out_ids.clear();
    for (const auto block : blocks)
    {
        std::vector<std::byte> bytes;
        if (!ReadBlock(source, block, block_size, bytes))
        {
            return false;
        }
        const auto oid = catalog::ReadU64LE(bytes, 0x08).value_or(0);
        if (oid == 0 || !out_ids.insert(oid).second)
        {
            return false;
        }
    }
    return true;
}

bool SerializeTree(const std::vector<catalog::BtreeRecord>& records,
    const TreeShape& shape, AppleBtreeKeyOrder order,
    std::uint32_t block_size, std::uint64_t xid,
    std::uint64_t virtual_root_oid, std::uint64_t first_child_oid,
    std::span<const std::uint64_t> blocks,
    AppleSerializedBtree& out_tree, std::string& out_error)
{
    AppleBtreeOptions options;
    options.block_size = block_size;
    options.xid = xid;
    options.storage_type = shape.storage_type;
    options.subtype = shape.subtype;
    options.tree_flags = shape.tree_flags;
    options.fixed_key_size = shape.fixed_key_size;
    options.fixed_value_size = shape.fixed_value_size;
    options.minimum_longest_key = shape.longest_key;
    options.minimum_longest_value = shape.longest_value;
    options.key_order = order;
    const bool physical = shape.storage_type == catalog::kObjectPhysical;
    if (blocks.empty())
    {
        options.root_physical_block = 1;
        options.root_object_id = physical ? 1 : virtual_root_oid;
        options.first_child_physical_block = 2;
        options.first_child_object_id = physical ? 2 : first_child_oid;
    }
    else
    {
        options.root_physical_block = blocks.back();
        options.root_object_id = physical ? blocks.back() : virtual_root_oid;
        for (std::size_t index = 0; index + 1 < blocks.size(); ++index)
        {
            options.child_physical_blocks.push_back(blocks[index]);
            options.child_object_ids.push_back(
                physical ? blocks[index] : first_child_oid + index);
        }
    }
    if (!SerializeAppleBtree(records, options, out_tree, out_error)) return false;
    if (!blocks.empty() && out_tree.objects.size() != blocks.size())
        return Fail(out_error, "AppleVolumeTransactionTreeAllocationCountMismatch");
    return true;
}

bool AddOmapRecord(std::vector<catalog::BtreeRecord>& records,
    std::uint64_t oid, std::uint64_t xid, std::uint64_t block,
    std::uint32_t block_size, std::string& out_error)
{
    AppleOmapRecord mapping;
    mapping.object_id = oid;
    mapping.xid = xid;
    mapping.size_bytes = block_size;
    mapping.physical_block = block;
    catalog::BtreeRecord encoded;
    if (!EncodeAppleOmapRecord(mapping, encoded, out_error))
    {
        return false;
    }
    records.push_back(std::move(encoded));
    return true;
}

void RemoveOmapRecords(std::vector<catalog::BtreeRecord>& records,
    const std::unordered_set<std::uint64_t>& object_ids)
{
    std::erase_if(records, [&object_ids](const auto& record) {
        return record.key.size() >= 8 && object_ids.contains(
            catalog::ReadU64LE(record.key, 0).value_or(0));
    });
}

bool AdjustCount(std::uint64_t value, std::int64_t delta,
    std::uint64_t& out_value)
{
    if (delta >= 0)
    {
        const auto amount = static_cast<std::uint64_t>(delta);
        if (amount > std::numeric_limits<std::uint64_t>::max() - value)
        {
            return false;
        }
        out_value = value + amount;
        return true;
    }
    const auto amount = static_cast<std::uint64_t>(-(delta + 1)) + 1;
    if (amount > value)
    {
        return false;
    }
    out_value = value - amount;
    return true;
}

bool ReplaceAllocationCount(std::uint64_t old_value,
    std::uint64_t added, std::uint64_t removed, std::uint64_t& out_value)
{
    if (removed > old_value ||
        added > std::numeric_limits<std::uint64_t>::max() -
            (old_value - removed))
    {
        return false;
    }
    out_value = old_value - removed + added;
    return true;
}

bool SumBlockCounts(std::initializer_list<std::uint64_t> counts,
    std::uint64_t& out_count)
{
    out_count = 0;
    for (const auto count : counts)
    {
        if (count > std::numeric_limits<std::uint64_t>::max() - out_count)
            return false;
        out_count += count;
    }
    return true;
}

bool SumReleasedBlocks(
    std::span<const AppleSpacemanReleaseRequest> releases,
    std::uint64_t& out_count)
{
    out_count = 0;
    std::unordered_set<std::uint64_t> blocks;
    for (const auto& release : releases)
    {
        if (release.physical_block == 0 || release.block_count == 0 ||
            release.physical_block >
                std::numeric_limits<std::uint64_t>::max() -
                    (release.block_count - 1))
        {
            return false;
        }
        for (std::uint64_t ordinal = 0; ordinal < release.block_count;
             ++ordinal)
        {
            if (!blocks.insert(release.physical_block + ordinal).second)
            {
                return false;
            }
        }
        if (release.block_count >
            std::numeric_limits<std::uint64_t>::max() - out_count)
        {
            return false;
        }
        out_count += release.block_count;
    }
    return true;
}

struct FileExtentUse
{
    AppleFileExtentRecord extent;
    const catalog::BtreeRecord* record = nullptr;
    std::uint64_t physical_owner_id = 0;
};

using ExternalStreamOwners = std::map<std::uint64_t, std::uint64_t>;

bool CollectExternalStreamOwners(const std::vector<catalog::BtreeRecord>& records,
    ExternalStreamOwners& out_owners, std::string& out_error)
{
    out_owners.clear();
    for (const auto& record : records)
    {
        if ((catalog::ReadU64LE(record.key, 0).value_or(0) >> 60) != 4) continue;
        AppleXattrRecord attribute;
        if (!ApfsExtendedRecordCodec::DecodeXattr(record, attribute, out_error)) return false;
        if ((attribute.flags & kAppleXattrDataStream) == 0) continue;
        const auto stream = catalog::ReadU64LE(attribute.data, 0).value_or(0);
        if (!stream || attribute.data.size() != kAppleXattrDataStreamBytes)
            return Fail(out_error, "AppleVolumeAttributeOwnerInvalid");
        const auto [found, inserted] = out_owners.emplace(stream, attribute.object_id);
        if (!inserted && found->second != attribute.object_id)
            return Fail(out_error, "AppleVolumeAttributeOwnerAmbiguous");
    }
    return true;
}

std::uint64_t PhysicalStreamOwner(const ExternalStreamOwners& owners, std::uint64_t stream)
{
    const auto found = owners.find(stream);
    return found == owners.end() ? stream : found->second;
}

bool DecodeFileExtentUse(const catalog::BtreeRecord& record,
    std::uint32_t block_size, FileExtentUse& out_use, bool encrypted = false,
    const ExternalStreamOwners& external_owners = {})
{
    std::string error;
    if (encrypted) {
        AppleEncryptedFileExtentRecord decoded;
        if (!DecodeAppleEncryptedFileExtentRecord(record, block_size,
                AppleEncryptedExtentProfile::OneKeyGenerationZero, decoded, error)) return false;
        out_use.extent = decoded.extent;
    } else if (!DecodeAppleFileExtentRecord(record, block_size, out_use.extent, error)) return false;
    out_use.record = &record;
    out_use.physical_owner_id = PhysicalStreamOwner(external_owners, out_use.extent.object_id);
    return true;
}

bool CollectFileExtentChanges(
    const std::vector<catalog::BtreeRecord>& old_records,
    const std::vector<catalog::BtreeRecord>& requested_records,
    std::uint32_t block_size, std::vector<FileExtentUse>& out_old_uses,
    std::vector<FileExtentUse>& out_removed_uses, std::string& out_error,
    const std::map<std::uint64_t, std::uint64_t>& clone_streams = {}, bool encrypted = false, bool observational = false,
    const AppleCloneRangeMapping* clone_range = nullptr)
{
    using ExtentKey = std::pair<std::uint64_t, std::uint64_t>;
    std::map<ExtentKey, std::size_t> old_by_key;
    ExternalStreamOwners old_external_owners, requested_external_owners;
    if (!CollectExternalStreamOwners(old_records, old_external_owners, out_error) ||
        !CollectExternalStreamOwners(requested_records, requested_external_owners, out_error)) return false;
    out_old_uses.clear();
    out_removed_uses.clear();
    for (const auto& record : old_records)
    {
        const auto header = catalog::ReadU64LE(record.key, 0);
        if (!header.has_value() ||
            (header.value() >> 60) != kFsRecordTypeFileExtent)
        {
            continue;
        }
        FileExtentUse use;
        if (!DecodeFileExtentUse(record, block_size, use, encrypted, old_external_owners))
        {
            return Fail(out_error, "AppleVolumeFileExtentRecordInvalid");
        }
        const ExtentKey key{
            use.extent.object_id,
            use.extent.logical_address,
        };
        if (!old_by_key.emplace(key, out_old_uses.size()).second)
        {
            return Fail(out_error, "AppleVolumeFileExtentRecordDuplicate");
        }
        out_old_uses.push_back(use);
    }

    std::uint64_t previous_owner = 0, previous_end = 0;
    for (const auto& [key, index] : old_by_key)
    {
        const auto& extent = out_old_uses[index].extent;
        if (key.first == previous_owner && extent.logical_address < previous_end)
            return Fail(out_error, "AppleVolumeFileExtentOverlap");
        previous_owner = key.first;
        previous_end = extent.logical_address + extent.length_bytes;
    }
    // Ordinary COW may retain exact subranges of an old record. The mapping,
    // crypto identity and owner must be unchanged; arbitrary remapping is forbidden.
    std::unordered_set<std::uint64_t> splittable_streams;
    for (const auto& use : out_old_uses)
        if (!use.extent.physical_block) splittable_streams.insert(use.extent.object_id);
    std::unordered_map<std::uint64_t, std::size_t> private_owners;
    std::unordered_set<std::uint64_t> ordinary_private_ids;
    for (const auto& record : old_records)
    {
        if ((catalog::ReadU64LE(record.key, 0).value_or(0) >> 60) != 3) continue;
        AppleInodeRecord inode;
        if (!(observational ? ApfsExtendedRecordCodec::DecodeInodeReadOnly(record, inode, out_error) :
            ApfsExtendedRecordCodec::DecodeInode(record, inode, out_error))) return false;
        if (old_external_owners.contains(inode.object_id) || old_external_owners.contains(inode.private_id))
            return Fail(out_error, "AppleVolumeAttributeInodeAlias");
        if (encrypted) continue; // Exact-record graph validation never splits encrypted mappings.
        ++private_owners[inode.private_id];
        if (inode.internal_flags & kAppleInodeSparseFlag) splittable_streams.insert(inode.private_id);
        if (inode.object_id == inode.private_id && (inode.mode & 0170000) == 0100000 &&
            !(inode.bsd_flags & kAppleBsdCompressedFlag))
        {
            ordinary_private_ids.insert(inode.private_id);
            splittable_streams.insert(inode.private_id);
        }
        for (const auto& field : inode.extended_fields)
            if (field.type == 8 && field.data.size() == 40 &&
                catalog::ReadU64LE(field.data, 8).value_or(UINT64_MAX) < catalog::ReadU64LE(field.data, 0).value_or(0))
                splittable_streams.insert(inode.private_id);
    }
    for (const auto& record : old_records)
    {
        if (encrypted) continue;
        if ((catalog::ReadU64LE(record.key, 0).value_or(0) >> 60) != 4) continue;
        AppleXattrRecord attribute;
        if (!ApfsExtendedRecordCodec::DecodeXattr(record, attribute, out_error)) return false;
        if (attribute.name_utf8 == "com.apple.decmpfs") ordinary_private_ids.erase(attribute.object_id);
    }
    std::erase_if(splittable_streams, [&](auto id) { return private_owners[id] != 1 || !ordinary_private_ids.contains(id); });
    const auto sparse_interval = [&](const auto& records, std::uint64_t object,
                                     std::uint64_t logical, std::uint64_t length) {
        if (!length || logical % block_size || length % block_size ||
            !ordinary_private_ids.contains(object) || private_owners[object] != 1) return false;
        unsigned matches = 0;
        for (const auto& record : records) {
            if (catalog::ReadU64LE(record.key, 0).value_or(0) != ((3ull << 60) | object)) continue;
            AppleInodeRecord inode;
            if (++matches != 1 || !ApfsExtendedRecordCodec::DecodeInode(record, inode, out_error) ||
                inode.private_id != object || (inode.mode & 0170000) != 0100000 ||
                (inode.bsd_flags & kAppleBsdCompressedFlag) || !(inode.internal_flags & kAppleInodeSparseFlag)) return false;
            const AppleExtendedField* stream = nullptr; const AppleExtendedField* sparse = nullptr;
            for (const auto& field : inode.extended_fields) {
                if (field.type == 8) { if (stream) return false; stream = &field; }
                if (field.type == kAppleInodeSparseBytesField) { if (sparse) return false; sparse = &field; }
            }
            if (!stream || stream->data.size() != 40 || !sparse || sparse->data.size() != 8 ||
                catalog::ReadU64LE(stream->data, 16).value_or(1)) return false;
            const auto size = catalog::ReadU64LE(stream->data, 0).value_or(UINT64_MAX);
            const auto allocated = catalog::ReadU64LE(stream->data, 8).value_or(UINT64_MAX);
            if (size > static_cast<std::uint64_t>(INT64_MAX) - (block_size - 1)) return false;
            const auto aligned = (size + block_size - 1) / block_size * block_size;
            if (allocated > aligned || allocated % block_size ||
                catalog::ReadU64LE(sparse->data, 0).value_or(UINT64_MAX) != aligned - allocated ||
                logical > aligned || length > aligned - logical) return false;
        }
        return matches == 1;
    };
    std::vector<std::vector<std::pair<std::uint64_t, std::uint64_t>>> retained(out_old_uses.size());
    for (const auto& record : requested_records)
    {
        if ((catalog::ReadU64LE(record.key, 0).value_or(0) >> 60) != kFsRecordTypeFileExtent) continue;
        FileExtentUse use;
        if (!DecodeFileExtentUse(record, block_size, use, encrypted, requested_external_owners))
            return Fail(out_error, "AppleVolumeFileExtentRecordInvalid");
        const auto clone = clone_streams.find(use.extent.object_id);
        const bool range_reference = clone_range && clone_range->Intersects(use.extent);
        if (range_reference && !clone_range->Covers(use.extent))
            return Fail(out_error, "AppleVolumeCloneRangeStraddlesBoundary");
        const auto source_id = range_reference ? clone_range->source_inode :
            clone == clone_streams.end() ? use.extent.object_id : clone->second;
        const auto source_logical = range_reference ? clone_range->source_offset +
            (use.extent.logical_address - clone_range->target_offset) : use.extent.logical_address;
        auto found = old_by_key.upper_bound({source_id, source_logical});
        const bool has_prior = found != old_by_key.begin();
        if (has_prior) --found;
        const auto* prior = has_prior ? &out_old_uses[found->second].extent : nullptr;
        const bool retains_zero = prior && prior->object_id == source_id && !prior->physical_block && !prior->crypto_id &&
            source_logical >= prior->logical_address && source_logical - prior->logical_address < prior->length_bytes &&
            use.extent.length_bytes <= prior->length_bytes - (source_logical - prior->logical_address);
        if (!encrypted && !use.extent.physical_block && !use.extent.crypto_id && clone == clone_streams.end() &&
            (range_reference || !retains_zero)) {
            if (!sparse_interval(requested_records, use.extent.object_id, use.extent.logical_address, use.extent.length_bytes))
                return Fail(out_error, "AppleVolumeSparseHoleScopeInvalid");
            if (range_reference) {
                if (!sparse_interval(old_records, source_id, source_logical, use.extent.length_bytes))
                    return Fail(out_error, "AppleVolumeCloneRangeSourceHoleInvalid");
                const auto end = source_logical + use.extent.length_bytes;
                for (const auto& original : out_old_uses)
                    if (original.extent.object_id == source_id && original.extent.physical_block &&
                        original.extent.logical_address < end && source_logical < original.extent.logical_address + original.extent.length_bytes)
                        return Fail(out_error, "AppleVolumeCloneRangeSourceMismatch");
            }
            // A newly serialized hole retains no old physical mapping. Exact
            // removed coverage and the release set are still derived below.
            continue;
        }
        if (!has_prior) return Fail(out_error, "AppleVolumeFileExtentMutationInvalid");
        const auto& old = out_old_uses[found->second];
        const auto& before = old.extent;
        const auto& next = use.extent;
        if (range_reference)
        {
            if (before.object_id != source_id || source_logical < before.logical_address || before.crypto_id || next.crypto_id ||
                source_logical - before.logical_address >= before.length_bytes ||
                next.length_bytes > before.length_bytes - (source_logical - before.logical_address) ||
                next.physical_block != (before.physical_block ? before.physical_block +
                    (source_logical - before.logical_address) / block_size : 0))
                return Fail(out_error, "AppleVolumeCloneRangeSourceMismatch");
            continue;
        }
        if (clone != clone_streams.end())
        {
            if (before.object_id != source_id || before.logical_address != next.logical_address ||
                old.record->value != record.value)
                return Fail(out_error, "AppleVolumeCloneExtentMismatch");
            continue; // A new reference does not retain the source's own mapping.
        }
        if (before.object_id != next.object_id || next.logical_address < before.logical_address ||
            next.logical_address - before.logical_address >= before.length_bytes ||
            next.length_bytes > before.length_bytes - (next.logical_address - before.logical_address))
            return Fail(out_error, "AppleVolumeFileExtentMutationInvalid");
        const bool exact = old.record->key == record.key && old.record->value == record.value;
        if (!exact && (!splittable_streams.contains(before.object_id) || before.crypto_id || next.crypto_id ||
            next.physical_block != (before.physical_block ? before.physical_block +
                (next.logical_address - before.logical_address) / block_size : 0)))
            return Fail(out_error, "AppleVolumeFileExtentMutationInvalid");
        retained[found->second].emplace_back(next.logical_address, next.logical_address + next.length_bytes);
    }
    for (std::size_t index = 0; index < out_old_uses.size(); ++index)
    {
        const auto& old = out_old_uses[index];
        auto& parts = retained[index];
        std::sort(parts.begin(), parts.end());
        auto cursor = old.extent.logical_address;
        const auto end = cursor + old.extent.length_bytes;
        const auto remove = [&](std::uint64_t begin, std::uint64_t finish) {
            if (begin == finish) return;
            auto fragment = old;
            fragment.extent.logical_address = begin;
            fragment.extent.length_bytes = finish - begin;
            if (fragment.extent.physical_block)
                fragment.extent.physical_block += (begin - old.extent.logical_address) / block_size;
            if (!parts.empty()) fragment.record = nullptr; // This is a subrange, not a removed whole record.
            out_removed_uses.push_back(fragment);
        };
        for (const auto& part : parts)
        {
            if (part.first < cursor) return Fail(out_error, "AppleVolumeFileExtentOverlap");
            remove(cursor, part.first);
            cursor = part.second;
        }
        remove(cursor, end);
    }
    return true;
}

// Materialize a bounded whole-stream clone from checked source records. No
// arbitrary physical block is accepted from the caller as a clone mapping.
bool PrepareCloneRecords(
    const std::vector<catalog::BtreeRecord>& old_records,
    const AppleVolumeTransactionRequest& request, std::uint64_t next_oid,
    std::uint32_t block_size,
    std::vector<catalog::BtreeRecord>& out_records,
    std::map<std::uint64_t, std::uint64_t>& out_streams,
    std::string& out_error)
{
    out_records = request.filesystem_records;
    out_streams.clear();
    if (request.clones.empty()) return true;
    std::map<std::uint64_t, AppleInodeRecord> old_inodes, next_inodes;
    const auto collect = [&](const auto& records, auto& inodes) {
        for (const auto& record : records)
        {
            if ((catalog::ReadU64LE(record.key, 0).value_or(0) >> 60) != 3) continue;
            AppleInodeRecord inode;
            if (!ApfsExtendedRecordCodec::DecodeInode(record, inode, out_error)) return false;
            if (!inodes.emplace(inode.object_id, inode).second)
                return Fail(out_error, "AppleVolumeCloneInodeDuplicate");
        }
        return true;
    };
    if (!collect(old_records, old_inodes) || !collect(out_records, next_inodes)) return false;
    // Inspect the complete caller-supplied attribute sets before materializing
    // any clone. decmpfs changes read interpretation even without the inode flag;
    // neither embedded nor external compression belongs to an ordinary clone.
    std::unordered_set<std::uint64_t> clone_inodes;
    for (const auto& clone : request.clones)
    {
        clone_inodes.insert(clone.source_inode_id);
        clone_inodes.insert(clone.target_inode_id);
    }
    // Index only requested extents, once per request. Pointers refer to the
    // immutable input, not out_records (which grows as targets are generated).
    using ExtentKey = std::pair<std::uint64_t, std::uint64_t>;
    std::map<ExtentKey, const catalog::BtreeRecord*> requested_extents;
    for (const auto& record : request.filesystem_records)
    {
        const auto header = catalog::ReadU64LE(record.key, 0).value_or(0);
        if ((header >> 60) == 4 && clone_inodes.contains(header & kFsObjectIdMask))
        {
            AppleXattrRecord attribute;
            if (!ApfsExtendedRecordCodec::DecodeXattr(record, attribute, out_error)) return false;
            if (attribute.name_utf8 == "com.apple.decmpfs")
                return Fail(out_error, "AppleVolumeCloneStreamUnsupported");
        }
        if ((header >> 60) != kFsRecordTypeFileExtent) continue;
        AppleFileExtentRecord extent;
        if (!DecodeAppleFileExtentRecord(record, block_size, extent, out_error))
            return Fail(out_error, "AppleVolumeFileExtentRecordInvalid");
        if (!requested_extents.emplace(ExtentKey{extent.object_id, extent.logical_address}, &record).second)
            return Fail(out_error, "AppleVolumeFileExtentRecordDuplicate");
    }
    std::unordered_set<std::uint64_t> marked;
    for (const auto& clone : request.clones)
    {
        const auto source = old_inodes.find(clone.source_inode_id);
        const auto target = next_inodes.find(clone.target_inode_id);
        const auto retained_source = next_inodes.find(clone.source_inode_id);
        if (source == old_inodes.end() || target == next_inodes.end() || retained_source == next_inodes.end() ||
            clone.target_inode_id < next_oid || !next_oid || old_inodes.contains(clone.target_inode_id) ||
            clone.target_inode_id == clone.source_inode_id ||
            !out_streams.emplace(clone.target_inode_id, clone.source_inode_id).second)
            return Fail(out_error, "AppleVolumeCloneIdentityInvalid");
        const auto& src = source->second;
        const auto& dst = target->second;
        const auto ordinary = [](const auto& inode) {
            // APFS-private, incomplete truncate, and Fusion-only pin flags.
            return inode.private_id == inode.object_id && (inode.mode & 0170000) == 0100000 &&
                !(inode.bsd_flags & kAppleBsdCompressedFlag) && !(inode.internal_flags & 0x3081);
        };
        const auto stream = [](const auto& inode) -> const AppleExtendedField* {
            const AppleExtendedField* found = nullptr;
            for (const auto& field : inode.extended_fields) if (field.type == 8)
            { if (found) return nullptr; found = &field; }
            return found;
        };
        const auto* src_stream = stream(src);
        const auto* dst_stream = stream(dst);
        const auto* retained_stream = stream(retained_source->second);
        if (!ordinary(src) || !ordinary(dst) || !ordinary(retained_source->second) ||
            !src_stream || !dst_stream || !retained_stream || src_stream->data.size() != 40 ||
            dst_stream->data != src_stream->data || retained_stream->data != src_stream->data ||
            catalog::ReadU64LE(src_stream->data, 16).value_or(1) != 0)
            return Fail(out_error, "AppleVolumeCloneStreamUnsupported");
        for (const auto& [id, inode] : old_inodes)
            if (id != src.object_id && inode.private_id == src.private_id)
                return Fail(out_error, "AppleVolumeSharedPrivateIdUnsupported");
        for (const auto& [id, inode] : next_inodes)
            if ((inode.private_id == src.private_id && id != src.object_id) ||
                (inode.private_id == dst.private_id && id != dst.object_id))
                return Fail(out_error, "AppleVolumeSharedPrivateIdUnsupported");
        for (const auto& write : request.data_writes)
            if (write.file_private_id == src.private_id || write.file_private_id == dst.private_id)
                return Fail(out_error, "AppleVolumeCloneConcurrentWriteUnsupported");
        bool source_reference = false;
        std::uint64_t physical_bytes = 0, logical_end = 0;
        for (const auto& record : old_records)
        {
            const auto header = catalog::ReadU64LE(record.key, 0).value_or(0);
            const auto id = header & kFsObjectIdMask, type = header >> 60;
            if (id == dst.object_id) return Fail(out_error, "AppleVolumeCloneTargetInUse");
            if (id != src.object_id) continue;
            if (type == 4)
            {
                AppleXattrRecord attribute;
                if (!ApfsExtendedRecordCodec::DecodeXattr(record, attribute, out_error)) return false;
                if (attribute.name_utf8 == "com.apple.decmpfs")
                    return Fail(out_error, "AppleVolumeCloneStreamUnsupported");
            }
            if (type == 6)
            {
                AppleDataStreamIdRecord reference;
                if (source_reference || !DecodeAppleDataStreamIdRecord(record, reference, out_error) || reference.reference_count != 1)
                    return Fail(out_error, "AppleVolumeCloneStreamUnsupported");
                source_reference = true;
            }
            if (type != 8) continue;
            AppleFileExtentRecord extent;
            if (!DecodeAppleFileExtentRecord(record, block_size, extent, out_error) || extent.crypto_id ||
                extent.logical_address != logical_end)
                return Fail(out_error, "AppleVolumeCloneExtentUnsupported");
            logical_end += extent.length_bytes;
            if (extent.physical_block) physical_bytes += extent.length_bytes;
            const auto retained = requested_extents.find({extent.object_id, extent.logical_address});
            if (retained == requested_extents.end() || retained->second->key != record.key ||
                retained->second->value != record.value)
                return Fail(out_error, "AppleVolumeCloneSourceChanged");
            extent.object_id = dst.object_id;
            catalog::BtreeRecord encoded;
            if (!EncodeAppleFileExtentRecord(extent, encoded, out_error)) return false;
            out_records.push_back(std::move(encoded));
        }
        const auto size = catalog::ReadU64LE(src_stream->data, 0).value_or(UINT64_MAX);
        if (!source_reference || !size || size > UINT64_MAX - (block_size - 1) ||
            logical_end != (size + block_size - 1) / block_size * block_size ||
            physical_bytes != catalog::ReadU64LE(src_stream->data, 8).value_or(UINT64_MAX))
            return Fail(out_error, "AppleVolumeCloneExtentCoverageInvalid");
        for (const auto& record : request.filesystem_records)
        {
            const auto header = catalog::ReadU64LE(record.key, 0).value_or(0);
            if ((header & kFsObjectIdMask) == dst.object_id && ((header >> 60) == 6 || (header >> 60) == 8))
                return Fail(out_error, "AppleVolumeCloneTargetInUse");
        }
        marked.insert(src.object_id); marked.insert(dst.object_id);
    }
    for (auto& record : out_records)
    {
        const auto header = catalog::ReadU64LE(record.key, 0).value_or(0);
        if ((header >> 60) != 3 || !marked.contains(header & kFsObjectIdMask)) continue;
        AppleInodeRecord inode;
        if (!ApfsExtendedRecordCodec::DecodeInode(record, inode, out_error)) return false;
        inode.internal_flags |= 0x400; // INODE_WAS_EVER_CLONED, never used as proof of exclusivity.
        if (!EncodeAppleInodeRecord(inode, record, out_error)) return false;
    }
    return true;
}

bool SameReleaseSet(const std::vector<FileExtentUse>& removed_uses,
    std::span<const AppleSpacemanReleaseRequest> requested,
    std::uint32_t block_size)
{
    std::vector<std::pair<std::uint64_t, std::uint64_t>> expected;
    std::vector<std::pair<std::uint64_t, std::uint64_t>> actual;
    expected.reserve(removed_uses.size());
    actual.reserve(requested.size());
    for (const auto& use : removed_uses)
    {
        if (use.extent.physical_block == 0) continue;
        expected.emplace_back(use.extent.physical_block,
            use.extent.length_bytes / block_size);
    }
    for (const auto& release : requested)
    {
        if (release.physical_block == 0 || release.block_count == 0 ||
            release.physical_block >
                std::numeric_limits<std::uint64_t>::max() -
                    (release.block_count - 1))
        {
            return false;
        }
        actual.emplace_back(release.physical_block, release.block_count);
    }
    std::sort(expected.begin(), expected.end());
    std::sort(actual.begin(), actual.end());
    return expected == actual;
}

struct DataStreamState
{
    AppleDataStreamIdRecord value;
    const catalog::BtreeRecord* record = nullptr;
};

bool CollectDataStreamRecords(
    const std::vector<catalog::BtreeRecord>& records,
    std::map<std::uint64_t, DataStreamState>& out_streams,
    std::string& out_error)
{
    out_streams.clear();
    for (const auto& record : records)
    {
        if (record.key.size() < 8)
        {
            continue;
        }
        const auto header = catalog::ReadU64LE(record.key, 0).value_or(0);
        if ((header >> 60) != kFsRecordTypeDataStreamId)
        {
            continue;
        }
        AppleDataStreamIdRecord value;
        std::string decode_error;
        if (!DecodeAppleDataStreamIdRecord(record, value, decode_error))
        {
            return Fail(out_error, "AppleVolumeDataStreamRecordInvalid");
        }
        if (!out_streams.emplace(value.object_id,
                DataStreamState{value, &record}).second)
        {
            return Fail(out_error, "AppleVolumeDataStreamRecordDuplicate");
        }
    }
    return true;
}

bool NormalizeDataStreamRecords(
    const std::vector<catalog::BtreeRecord>& old_records,
    const std::vector<catalog::BtreeRecord>& requested_records,
    const std::vector<FileExtentUse>& old_file_extents,
    const std::vector<FileExtentUse>& removed_file_extents,
    const std::vector<AppleVolumeDataWrite>& data_writes,
    std::uint32_t block_size,
    std::uint64_t minimum_new_object_id,
    const std::vector<CompressionRewrite>& compression_rewrites,
    const catalog::RandomAccessSource& source,
    std::uint64_t source_xid, std::uint64_t volume_id,
    const std::map<std::uint64_t, std::uint64_t>& clone_streams,
    std::vector<catalog::BtreeRecord>& out_records,
    std::string& out_error)
{
    std::map<std::uint64_t, DataStreamState> old_streams;
    std::map<std::uint64_t, DataStreamState> requested_streams;
    if (!CollectDataStreamRecords(old_records, old_streams, out_error) ||
        !CollectDataStreamRecords(
            requested_records, requested_streams, out_error))
    {
        return false;
    }

    std::unordered_map<std::uint64_t, std::size_t> old_extent_counts;
    std::unordered_map<std::uint64_t, std::size_t> removed_extent_counts;
    std::unordered_set<std::uint64_t> touched_streams;
    std::unordered_set<std::uint64_t> written_streams;
    for (const auto& use : old_file_extents)
    {
        ++old_extent_counts[use.extent.object_id];
    }
    for (const auto& use : removed_file_extents)
    {
        if (use.record) ++removed_extent_counts[use.extent.object_id];
        touched_streams.insert(use.extent.object_id);
    }
    for (const auto& data : data_writes)
    {
        if (data.file_private_id == 0)
        {
            return Fail(out_error, "AppleVolumeTransactionDataInvalid");
        }
        touched_streams.insert(data.file_private_id);
        written_streams.insert(data.file_private_id);
    }

    for (const auto& [target, source_stream] : clone_streams)
    {
        touched_streams.insert(target);
        written_streams.insert(target);
    }

    // Derive external-stream retirement from both trees. A caller-supplied
    // lower refcount alone cannot authorize reclaiming shared payload blocks.
    using AttributeOwners = std::map<std::pair<std::uint64_t, std::string>, AppleXattrRecord>;
    std::unordered_set<std::uint64_t> compressed_attribute_owners;
    AttributeOwners old_attributes, requested_attributes;
    const auto collect_owners = [&](const auto& records, auto& owners, auto& attributes)
    {
        for (const auto& record : records)
        {
            if ((catalog::ReadU64LE(record.key, 0).value_or(0) >> 60) != 4) continue;
            AppleXattrRecord attribute;
            if (!ApfsExtendedRecordCodec::DecodeXattr(record, attribute, out_error)) return false;
            if (!attributes.emplace(std::make_pair(attribute.object_id, attribute.name_utf8), attribute).second)
                return Fail(out_error, "AppleVolumeAttributeOwnerInvalid");
            if (attribute.name_utf8 == "com.apple.decmpfs")
                compressed_attribute_owners.insert(attribute.object_id);
            if ((attribute.flags & kAppleXattrDataStream) == 0) continue;
            const auto stream_id = catalog::ReadU64LE(attribute.data, 0).value_or(0);
            if (stream_id == 0 || attribute.data.size() != kAppleXattrDataStreamBytes ||
                !owners[stream_id].emplace(std::make_pair(attribute.object_id, attribute.name_utf8), attribute).second)
                return Fail(out_error, "AppleVolumeAttributeOwnerInvalid");
        }
        return true;
    };
    std::map<std::uint64_t, AttributeOwners> old_owners, requested_owners;
    if (!collect_owners(old_records, old_owners, old_attributes) ||
        !collect_owners(requested_records, requested_owners, requested_attributes)) return false;
    std::map<std::uint64_t, AppleInodeRecord> old_inode_ids, requested_inode_ids;
    const auto collect_inodes = [&](const auto& records, auto& ids)
    {
        for (const auto& record : records)
        {
            if ((catalog::ReadU64LE(record.key, 0).value_or(0) >> 60) != 3) continue;
            AppleInodeRecord inode;
            if (!ApfsExtendedRecordCodec::DecodeInode(record, inode, out_error)) return false;
            if ((inode.bsd_flags & kAppleBsdCompressedFlag) != 0)
                compressed_attribute_owners.insert(inode.object_id);
            if (old_owners.contains(inode.object_id) || old_owners.contains(inode.private_id) ||
                requested_owners.contains(inode.object_id) || requested_owners.contains(inode.private_id))
                return Fail(out_error, "AppleVolumeAttributeInodeAlias");
            if (!ids.emplace(inode.object_id, inode).second)
                return Fail(out_error, "AppleVolumeAttributeInodeDuplicate");
        }
        return true;
    };
    if (!collect_inodes(old_records, old_inode_ids) || !collect_inodes(requested_records, requested_inode_ids)) return false;
    if (!old_attributes.empty() || !requested_attributes.empty())
    {
        for (const auto& [id, owners] : old_owners)
            for (const auto& [key, attribute] : owners)
                if (!old_inode_ids.contains(attribute.object_id)) return Fail(out_error, "AppleVolumeAttributeOldOwnerMissing");
        for (const auto& [id, owners] : requested_owners)
            for (const auto& [key, attribute] : owners)
                if (!requested_inode_ids.contains(attribute.object_id)) return Fail(out_error, "AppleVolumeAttributeOwnerMissing");
    }
    std::map<std::uint64_t, std::uint32_t> validated_rewrites;
    for (const auto& proof : compression_rewrites)
    {
        CompressionRewrite checked;
        if (!DecodeCompressionRewrite(EncodeCompressionRewrite(proof), checked) ||
            proof.checkpoint != source_xid || proof.volume != volume_id ||
            !validated_rewrites.emplace(proof.object, proof.type).second ||
            !old_inode_ids.contains(proof.object) || !requested_inode_ids.contains(proof.object))
            return Fail(out_error, "AppleCompressionRewriteIdentityInvalid");
        const auto& old = old_inode_ids.at(proof.object);
        const auto& next = requested_inode_ids.at(proof.object);
        for (const auto& [key, attribute] : old_attributes)
        {
            if (key.first != proof.object || key.second == "com.apple.decmpfs" ||
                (CompressionRewrite::UsesResourceFork(proof.type) && key.second == "com.apple.ResourceFork")) continue;
            const auto retained = requested_attributes.find(key);
            if (retained == requested_attributes.end() || retained->second.flags != attribute.flags ||
                retained->second.data != attribute.data) return Fail(out_error, "AppleCompressionRewriteUnrelatedAttributeChanged");
        }
        for (const auto& [key, attribute] : requested_attributes)
            if (key.first == proof.object && !old_attributes.contains(key))
                return Fail(out_error, "AppleCompressionRewriteUnrelatedAttributeAdded");
        if ((old.mode & 0170000) != 0100000 || next.mode != old.mode ||
            old.private_id != proof.private_id || next.private_id != old.private_id ||
            !(old.bsd_flags & kAppleBsdCompressedFlag) || next.bsd_flags != (old.bsd_flags & ~kAppleBsdCompressedFlag) ||
            next.owner != old.owner || next.group != old.group || old_extent_counts[old.private_id] != 0 ||
            requested_attributes.contains({proof.object, "com.apple.decmpfs"}))
            return Fail(out_error, "AppleCompressionRewriteOwnerInvalid");
        for (const auto& field : old.extended_fields)
            if (field.type == 8 && (field.data.size() != 40 ||
                catalog::ReadU64LE(field.data, 0).value_or(1) != 0 ||
                catalog::ReadU64LE(field.data, 8).value_or(1) != 0 ||
                catalog::ReadU64LE(field.data, 16).value_or(1) != 0))
                return Fail(out_error, "AppleCompressionRewriteMixedSource");
        const auto authenticate = [&](const char* name, std::uint16_t flags,
                                      const auto& descriptor, const auto& bytes) {
            const auto found = old_attributes.find({proof.object, name});
            if (!flags) return found == old_attributes.end();
            if (found == old_attributes.end() || found->second.flags != flags || found->second.data != descriptor) return false;
            if (flags == kAppleXattrDataEmbedded) return descriptor == bytes;
            const auto id = catalog::ReadU64LE(descriptor, 0).value_or(0);
            if (catalog::ReadU64LE(descriptor, 8).value_or(UINT64_MAX) != bytes.size()) return false;
            std::uint64_t covered = 0;
            for (const auto& use : old_file_extents)
            {
                const auto& extent = use.extent;
                if (extent.object_id != id) continue;
                if (extent.logical_address != covered || !extent.physical_block || extent.crypto_id) return false;
                const auto count = covered < bytes.size() ? (std::min)(extent.length_bytes, bytes.size()-covered) : 0;
                std::vector<std::byte> chunk;
                if (count && (!source.Read(extent.physical_block * block_size, static_cast<std::size_t>(count), chunk) ||
                    chunk.size() != count || !std::equal(chunk.begin(), chunk.end(), bytes.begin()+static_cast<std::size_t>(covered)))) return false;
                covered += extent.length_bytes;
            }
            return covered == catalog::ReadU64LE(descriptor, 16).value_or(UINT64_MAX) && covered >= bytes.size();
        };
        if (!authenticate("com.apple.decmpfs", proof.decmpfs_flags, proof.decmpfs_descriptor, proof.decmpfs) ||
            !authenticate("com.apple.ResourceFork", proof.resource_flags, proof.resource_descriptor, proof.resource))
            return Fail(out_error, "AppleCompressionRewriteSourceMismatch");
        const auto fork = requested_attributes.find({proof.object, "com.apple.ResourceFork"});
        if (CompressionRewrite::UsesResourceFork(proof.type) ? fork != requested_attributes.end() :
            proof.resource_flags ? fork == requested_attributes.end() || fork->second.flags != proof.resource_flags ||
                fork->second.data != proof.resource_descriptor : fork != requested_attributes.end())
            return Fail(out_error, "AppleCompressionRewriteForkMismatch");
        ApfsCompressionResourceReader resource;
        if (CompressionRewrite::UsesResourceFork(proof.type))
        {
            resource.size = proof.resource.size();
            resource.read = [&](std::uint64_t at, std::span<std::byte> out) {
                if (at > proof.resource.size() || out.size() > proof.resource.size()-at) return std::size_t{0};
                std::copy_n(proof.resource.begin()+static_cast<std::size_t>(at), out.size(), out.begin()); return out.size(); };
        }
        std::vector<std::byte> decoded;
        for (std::uint64_t at = 0;;)
        {
            const auto count = (std::min)(std::uint64_t{65536}, proof.size-at);
            const auto decode = ApfsCompression::DecodeRange(proof.decmpfs, resource, at, count, {}, decoded);
            if (!decode)
            {
                out_error = std::string("AppleCompressionRewriteDecodeFailed:") + decode.detail;
                return false;
            }
            if (decoded.size() != count)
                return Fail(out_error, "AppleCompressionRewriteDecodeSizeMismatch");
            at += count; if (at == proof.size) break;
        }
    }
    const auto mutable_owner = [&](const AppleXattrRecord& attribute)
    {
        if (validated_rewrites.contains(attribute.object_id))
            return attribute.name_utf8 == "com.apple.decmpfs" || attribute.name_utf8 == "com.apple.ResourceFork" ||
                IsOrdinaryAppleXattrName(attribute.name_utf8);
        if (compressed_attribute_owners.contains(attribute.object_id)) return false;
        if (IsOrdinaryAppleXattrName(attribute.name_utf8)) return true;
        if (attribute.name_utf8 != "com.apple.ResourceFork") return false;
        const auto old = old_inode_ids.find(attribute.object_id);
        const auto next = requested_inode_ids.find(attribute.object_id);
        const auto supported = [&](const auto& inode) {
            return IsUncompressedAppleResourceForkOwner(inode.object_id, inode.private_id,
                inode.mode, inode.bsd_flags, compressed_attribute_owners.contains(inode.object_id));
        };
        if (old == old_inode_ids.end() && (next == requested_inode_ids.end() ||
                minimum_new_object_id == 0 || attribute.object_id < minimum_new_object_id)) return false;
        if ((old != old_inode_ids.end() && !supported(old->second)) ||
            (next != requested_inode_ids.end() && !supported(next->second)) ||
            (old != old_inode_ids.end() && next != requested_inode_ids.end() &&
                old->second.private_id != next->second.private_id)) return false;
        if (attribute.flags == kAppleXattrDataEmbedded)
            return attribute.data.size() <= WriteAheadLog::MaxExtendedAttributePayloadBytes;
        return attribute.flags == kAppleXattrDataStream && attribute.data.size() == kAppleXattrDataStreamBytes &&
            catalog::ReadU64LE(attribute.data, 8).value_or(UINT64_MAX) <= WriteAheadLog::MaxExtendedAttributePayloadBytes &&
            catalog::ReadU64LE(attribute.data, 24).value_or(1) == 0;
    };
    // Embedded forks must obey exactly the same owner policy as external ones.
    // Compare identities and original modes, not just the requested inode flags.
    AttributeOwners forks = old_attributes;
    forks.insert(requested_attributes.begin(), requested_attributes.end());
    for (const auto& [key, attribute] : forks)
    {
        if (key.second != "com.apple.ResourceFork") continue;
        const auto old = old_attributes.find(key), next = requested_attributes.find(key);
        const auto old_inode = old_inode_ids.find(key.first), next_inode = requested_inode_ids.find(key.first);
        if ((old != old_attributes.end() && old_inode == old_inode_ids.end()) ||
            (next != requested_attributes.end() && next_inode == requested_inode_ids.end()))
            return Fail(out_error, "AppleVolumeAttributeOwnerMissing");
        const bool unchanged = old != old_attributes.end() && next != requested_attributes.end() &&
            old->second.flags == next->second.flags && old->second.data == next->second.data;
        if (unchanged)
        {
            const auto& before = old_inode->second;
            const auto& after = next_inode->second;
            const bool owner_transition = (before.mode & 0170000) != (after.mode & 0170000) ||
                ((before.bsd_flags ^ after.bsd_flags) & kAppleBsdCompressedFlag) != 0 ||
                before.private_id != after.private_id ||
                old_attributes.contains({key.first, "com.apple.decmpfs"}) !=
                    requested_attributes.contains({key.first, "com.apple.decmpfs"});
            const bool content_change = touched_streams.contains(before.private_id) ||
                touched_streams.contains(after.private_id);
            if ((owner_transition && !validated_rewrites.contains(key.first)) || (content_change && !mutable_owner(attribute)))
                return Fail(out_error, "AppleVolumeAttributeContentTransformUnsupported");
            continue; // Exact unsupported records may still be preserved.
        }
        if ((old != old_attributes.end() && !mutable_owner(old->second)) ||
            (next != requested_attributes.end() && !mutable_owner(next->second)))
            return Fail(out_error, "AppleVolumeAttributeContentTransformUnsupported");
    }
    for (const auto& [id, owners] : requested_owners)
    {
        if (old_owners.contains(id)) continue;
        if (owners.size() != 1 || minimum_new_object_id == 0 || id < minimum_new_object_id || id >= kFsObjectIdMask ||
            old_streams.contains(id) || old_extent_counts[id] != 0)
            return Fail(out_error, "AppleVolumeAttributeNewStreamInvalid");
        const auto& attribute = owners.begin()->second;
        if (!mutable_owner(attribute))
            return Fail(out_error, "AppleVolumeAttributeContentTransformUnsupported");
        const auto data = std::find_if(data_writes.begin(), data_writes.end(),
            [id](const auto& write) { return write.file_private_id == id; });
        if (attribute.flags != kAppleXattrDataStream || data == data_writes.end() ||
            data->logical_address != 0 || data->crypto_id != 0 || data->bytes.empty() ||
            std::count_if(data_writes.begin(), data_writes.end(),
                [id](const auto& write) { return write.file_private_id == id; }) != 1 ||
            data->bytes.size() > std::numeric_limits<std::uint64_t>::max() - (block_size - 1) ||
            catalog::ReadU64LE(attribute.data, 8).value_or(0) != data->bytes.size() ||
            catalog::ReadU64LE(attribute.data, 16).value_or(0) !=
                (data->bytes.size() + block_size - 1) / block_size * block_size ||
            catalog::ReadU64LE(attribute.data, 24).value_or(1) != 0 ||
            catalog::ReadU64LE(attribute.data, 32).value_or(0) != data->bytes.size() ||
            catalog::ReadU64LE(attribute.data, 40).value_or(1) != 0)
            return Fail(out_error, "AppleVolumeAttributeNewPayloadInvalid");
    }
    std::unordered_map<std::uint64_t, std::vector<const AppleFileExtentRecord*>> attribute_extents;
    if (!old_owners.empty())
        for (const auto& use : old_file_extents)
            if (old_owners.contains(use.extent.object_id)) attribute_extents[use.extent.object_id].push_back(&use.extent);
    std::map<std::uint64_t, std::uint32_t> retired_attribute_streams;
    for (const auto& [id, owners] : old_owners)
    {
        const auto requested = requested_owners.find(id);
        const auto remaining = requested == requested_owners.end() ? 0 : requested->second.size();
        if (remaining >= owners.size())
        {
            if (remaining != owners.size() || written_streams.contains(id) || removed_extent_counts[id] != 0)
                return Fail(out_error, "AppleVolumeAttributeMutationUnsupported");
            for (const auto& [key, attribute] : requested->second)
            {
                const auto original = owners.find(key);
                if (original == owners.end() || original->second.flags != attribute.flags || original->second.data != attribute.data)
                    return Fail(out_error, "AppleVolumeAttributeOwnerMismatch");
            }
            continue;
        }
        const auto stream = old_streams.find(id);
        if (stream == old_streams.end() || stream->second.value.reference_count != owners.size() ||
            written_streams.contains(id)) return Fail(out_error, "AppleVolumeAttributeOwnerMismatch");
        const auto& descriptor = owners.begin()->second.data;
        for (const auto& [key, attribute] : owners)
        {
            if ((requested == requested_owners.end() || !requested->second.contains(key)) &&
                !mutable_owner(attribute))
                return Fail(out_error, "AppleVolumeAttributeContentTransformUnsupported");
            if (attribute.flags != kAppleXattrDataStream || attribute.data != descriptor ||
                catalog::ReadU64LE(descriptor, 24).value_or(1) != 0)
                return Fail(out_error, "AppleVolumeAttributeRetirementUnsupported");
        }
        if (requested != requested_owners.end())
        {
            for (const auto& [key, attribute] : requested->second)
            {
                const auto original = owners.find(key);
                if (original == owners.end() || original->second.flags != attribute.flags ||
                    original->second.data != attribute.data)
                    return Fail(out_error, "AppleVolumeAttributeOwnerMismatch");
            }
        }
        const auto requested_stream = requested_streams.find(id);
        if ((remaining == 0 && requested_stream != requested_streams.end()) ||
            (remaining != 0 && (requested_stream == requested_streams.end() ||
                requested_stream->second.record->key != stream->second.record->key ||
                requested_stream->second.record->value != stream->second.record->value)) ||
            (remaining == 0 ? removed_extent_counts[id] != old_extent_counts[id] : removed_extent_counts[id] != 0))
            return Fail(out_error, "AppleVolumeAttributeRetirementIncomplete");
        auto& extents = attribute_extents[id];
        std::sort(extents.begin(), extents.end(), [](const auto* a, const auto* b) { return a->logical_address < b->logical_address; });
        const auto allocated = catalog::ReadU64LE(descriptor, 16).value_or(0);
        std::uint64_t covered = 0;
        for (const auto* extent : extents)
        {
            if (extent->physical_block == 0 || extent->crypto_id != 0 || extent->logical_address != covered || covered > allocated ||
                extent->length_bytes > allocated - covered)
                return Fail(out_error, "AppleVolumeAttributeRetirementExtentInvalid");
            covered += extent->length_bytes;
        }
        if (covered != allocated || catalog::ReadU64LE(descriptor, 8).value_or(0) > allocated)
            return Fail(out_error, "AppleVolumeAttributeRetirementExtentInvalid");
        retired_attribute_streams.emplace(id, static_cast<std::uint32_t>(remaining));
    }

    for (const auto& [id, inode] : old_inode_ids)
    {
        const auto next = requested_inode_ids.find(id);
        if (next != requested_inode_ids.end() && next->second.private_id != inode.private_id &&
            ((inode.mode & 0170000) == 0100000 || old_extent_counts[inode.private_id] != 0))
            return Fail(out_error, "AppleVolumePrivateIdTransitionUnsupported");
    }
    std::map<std::uint64_t, std::pair<std::size_t, std::size_t>> private_counts;
    for (const auto& [id, inode] : old_inode_ids) ++private_counts[inode.private_id].first;
    for (const auto& [id, inode] : requested_inode_ids) ++private_counts[inode.private_id].second;
    for (const auto& [id, counts] : private_counts)
        if (counts.first != counts.second && (counts.first > 1 || counts.second > 1))
            return Fail(out_error, "AppleVolumeSharedPrivateIdUnsupported");
    for (const auto stream : touched_streams)
    {
        const auto count_owners = [stream](const auto& inodes) {
            return std::count_if(inodes.begin(), inodes.end(), [stream](const auto& item) {
                return item.second.private_id == stream;
            });
        };
        if (count_owners(old_inode_ids) > 1 || count_owners(requested_inode_ids) > 1)
            return Fail(out_error, "AppleVolumeSharedPrivateIdUnsupported");
    }

    for (const auto object_id : touched_streams)
    {
        if (retired_attribute_streams.contains(object_id)) continue;
        const auto old_stream = old_streams.find(object_id);
        const auto old_extent_count = old_extent_counts[object_id];
        if (old_stream == old_streams.end() && old_extent_count != 0)
        {
            return Fail(out_error, "AppleVolumeDataStreamRecordMissing");
        }
        if (old_stream != old_streams.end() &&
            old_stream->second.value.reference_count > 1)
        {
            return Fail(out_error,
                "AppleVolumeSharedDataStreamUnsupported");
        }
        const auto requested_stream = requested_streams.find(object_id);
        if (requested_stream != requested_streams.end())
        {
            if (requested_stream->second.value.reference_count > 1)
            {
                return Fail(out_error,
                    "AppleVolumeSharedDataStreamUnsupported");
            }
            if (old_stream != old_streams.end() &&
                (requested_stream->second.record->key !=
                     old_stream->second.record->key ||
                 requested_stream->second.record->value !=
                     old_stream->second.record->value))
            {
                return Fail(out_error,
                    "AppleVolumeDataStreamMutationInvalid");
            }
        }
    }

    for (const auto& [object_id, old_stream] : old_streams)
    {
        if (touched_streams.contains(object_id) || retired_attribute_streams.contains(object_id))
        {
            continue;
        }
        const auto requested_stream = requested_streams.find(object_id);
        if (requested_stream == requested_streams.end() ||
            requested_stream->second.record->key != old_stream.record->key ||
            requested_stream->second.record->value !=
                old_stream.record->value)
        {
            return Fail(out_error, "AppleVolumeDataStreamMutationInvalid");
        }
    }
    for (const auto& [object_id, requested_stream] : requested_streams)
    {
        if (!old_streams.contains(object_id) &&
            !written_streams.contains(object_id))
        {
            return Fail(out_error, "AppleVolumeDataStreamMutationInvalid");
        }
        if (!old_streams.contains(object_id) &&
            requested_stream.value.reference_count != 1)
        {
            return Fail(out_error,
                "AppleVolumeSharedDataStreamUnsupported");
        }
    }

    out_records.clear();
    out_records.reserve(requested_records.size() + written_streams.size());
    for (const auto& record : requested_records)
    {
        if (record.key.size() >= 8 &&
            (catalog::ReadU64LE(record.key, 0).value_or(0) >> 60) ==
                kFsRecordTypeDataStreamId)
        {
            continue;
        }
        out_records.push_back(record);
    }
    for (const auto& [object_id, old_stream] : old_streams)
    {
        if (const auto retired = retired_attribute_streams.find(object_id); retired != retired_attribute_streams.end())
        {
            if (retired->second != 0)
            {
                auto reference = old_stream.value;
                reference.reference_count = retired->second;
                catalog::BtreeRecord record;
                if (!EncodeAppleDataStreamIdRecord(reference, record, out_error)) return false;
                out_records.push_back(std::move(record));
            }
            continue;
        }
        const auto old_count = old_extent_counts[object_id];
        const auto removed_count = removed_extent_counts[object_id];
        const bool remains = written_streams.contains(object_id) ||
            old_count > removed_count || requested_streams.contains(object_id);
        if (!touched_streams.contains(object_id) || remains)
        {
            out_records.push_back(*old_stream.record);
        }
    }
    for (const auto object_id : written_streams)
    {
        if (old_streams.contains(object_id))
        {
            continue;
        }
        AppleDataStreamIdRecord value;
        value.object_id = object_id;
        value.reference_count = 1;
        catalog::BtreeRecord record;
        if (!EncodeAppleDataStreamIdRecord(value, record, out_error))
        {
            return false;
        }
        out_records.push_back(std::move(record));
    }
    return true;
}

struct PhysicalExtentState
{
    ApplePhysicalExtentRecord extent;
};

std::uint64_t ExtentEnd(const ApplePhysicalExtentRecord& extent)
{
    return extent.physical_block + extent.block_count;
}

std::uint64_t ExtentEnd(const FileExtentUse& use)
{
    return use.extent.physical_block +
        use.extent.length_bytes / use.extent.block_size;
}

bool DecodePhysicalExtentTree(
    const std::vector<catalog::BtreeRecord>& records,
    std::uint64_t container_block_count,
    std::vector<PhysicalExtentState>& out_extents,
    std::string& out_error, const catalog::ApfsFusionStore* fusion = nullptr)
{
    out_extents.clear();
    out_extents.reserve(records.size());
    for (const auto& record : records)
    {
        ApplePhysicalExtentRecord extent;
        catalog::FusionRoute route;
        if (!DecodeApplePhysicalExtentRecord(record, extent, out_error) ||
            (fusion ? (extent.block_count > UINT64_MAX / fusion->Checkpoint().superblock.block_size ||
                !fusion->MapPhysical(extent.physical_block, 0,
                    extent.block_count * fusion->Checkpoint().superblock.block_size, route, out_error)) :
                (extent.physical_block >= container_block_count ||
                 extent.block_count > container_block_count - extent.physical_block)))
        {
            return Fail(out_error, "AppleVolumePhysicalExtentRecordInvalid");
        }
        if (extent.kind != kApplePhysicalExtentKindNew)
            return Fail(out_error, "AppleVolumePhysicalExtentKindUnsupported");
        out_extents.push_back({extent});
    }
    std::sort(out_extents.begin(), out_extents.end(),
        [](const auto& left, const auto& right) {
            return left.extent.physical_block < right.extent.physical_block;
        });
    for (std::size_t index = 1; index < out_extents.size(); ++index)
    {
        if (ExtentEnd(out_extents[index - 1].extent) >
            out_extents[index].extent.physical_block)
        {
            return Fail(out_error, "AppleVolumePhysicalExtentOverlap");
        }
    }
    return true;
}

bool ValidatePhysicalExtentCoverage(
    const std::vector<FileExtentUse>& uses,
    const std::vector<PhysicalExtentState>& physical_extents,
    std::uint64_t container_block_count, std::string& out_error,
    const catalog::ApfsFusionStore* fusion = nullptr)
{
    struct ReferenceEvent
    {
        std::uint64_t block = 0;
        std::int64_t delta = 0;
    };
    std::vector<ReferenceEvent> events;
    events.reserve(uses.size() * 2);
    for (const auto& use : uses)
    {
        // Sparse records occupy logical ranges but own no physical blocks.
        if (use.extent.physical_block == 0) continue;
        const auto blocks = use.extent.length_bytes / use.extent.block_size;
        catalog::FusionRoute route;
        if (fusion ? !fusion->MapPhysical(use.extent.physical_block, 0,
                use.extent.length_bytes, route, out_error) :
            (use.extent.physical_block >= container_block_count ||
             blocks > container_block_count - use.extent.physical_block))
        {
            return Fail(out_error, "AppleVolumeFileExtentOutsideContainer");
        }
        events.push_back({use.extent.physical_block, 1});
        events.push_back({use.extent.physical_block + blocks, -1});

        auto found = std::upper_bound(physical_extents.begin(),
            physical_extents.end(), use.extent.physical_block,
            [](std::uint64_t block, const auto& candidate) {
                return block < candidate.extent.physical_block;
            });
        if (found != physical_extents.begin())
        {
            --found;
        }
        auto cursor = use.extent.physical_block;
        const auto end = use.extent.physical_block + blocks;
        while (cursor < end)
        {
            if (found == physical_extents.end() ||
                found->extent.physical_block > cursor ||
                ExtentEnd(found->extent) <= cursor)
            {
                return Fail(out_error, "AppleVolumePhysicalExtentMissing");
            }
            if (found->extent.reference_count == 1 &&
                found->extent.owning_object_id != use.physical_owner_id)
            {
                return Fail(out_error, "AppleVolumePhysicalExtentOwnerMismatch");
            }
            cursor = (std::min)(end, ExtentEnd(found->extent));
            ++found;
        }
    }

    std::sort(events.begin(), events.end(),
        [](const auto& left, const auto& right) {
            return left.block < right.block;
        });
    std::vector<ReferenceEvent> merged;
    for (const auto& event : events)
    {
        if (!merged.empty() && merged.back().block == event.block)
        {
            merged.back().delta += event.delta;
        }
        else
        {
            merged.push_back(event);
        }
    }
    std::vector<std::int64_t> counts(merged.size(), 0);
    std::int64_t count = 0;
    for (std::size_t index = 0; index < merged.size(); ++index)
    {
        count += merged[index].delta;
        if (count < 0)
        {
            return Fail(out_error, "AppleVolumePhysicalExtentReferenceInvalid");
        }
        counts[index] = count;
    }
    if (count != 0)
    {
        return Fail(out_error, "AppleVolumePhysicalExtentReferenceInvalid");
    }

    for (const auto& state : physical_extents)
    {
        const auto start = state.extent.physical_block;
        const auto end = ExtentEnd(state.extent);
        const auto at_start = std::upper_bound(merged.begin(), merged.end(),
            start, [](std::uint64_t block, const auto& event) {
                return block < event.block;
            });
        std::int64_t current = 0;
        std::size_t event_index = 0;
        if (at_start != merged.begin())
        {
            event_index = static_cast<std::size_t>(
                std::distance(merged.begin(), at_start) - 1);
            current = counts[event_index];
            ++event_index;
        }
        if (current != 0 && current != state.extent.reference_count)
        {
            return Fail(out_error, "AppleVolumePhysicalExtentRefcountMismatch");
        }
        while (event_index < merged.size() &&
            merged[event_index].block < end)
        {
            if (merged[event_index].block > start)
            {
                if (current == 0 && counts[event_index] != 0)
                {
                    return Fail(out_error,
                        "AppleVolumePhysicalExtentRefcountMismatch");
                }
                current = counts[event_index];
                if (current != state.extent.reference_count)
                {
                    return Fail(out_error,
                        "AppleVolumePhysicalExtentRefcountMismatch");
                }
            }
            ++event_index;
        }
    }
    return true;
}

// The release witness describes removed file mappings, including overlapping
// clone references. Only the interval sweep's zero-reference result reaches
// spaceman. Existing allocator checkpoint pins still delay reuse independently.
bool BuildRetainedPhysicalExtentRecords(
    const std::vector<PhysicalExtentState>& physical_extents,
    const std::vector<FileExtentUse>& removed_uses,
    const std::vector<catalog::BtreeRecord>& requested_records,
    std::uint32_t block_size,
    const std::map<std::uint64_t, std::uint64_t>& clone_streams,
    std::vector<catalog::BtreeRecord>& out_records,
    std::vector<AppleSpacemanReleaseRequest>& out_releases,
    std::string& out_error, const AppleCloneRangeMapping* clone_range = nullptr)
{
    struct Event
    {
        std::int64_t removed = 0;
        std::int64_t affected = 0;
        std::vector<std::pair<std::uint64_t, int>> owners;
        std::vector<std::pair<std::uint64_t, int>> original_owners;
    };
    std::map<std::uint64_t, Event> events;
    ExternalStreamOwners external_owners;
    if (!CollectExternalStreamOwners(requested_records, external_owners, out_error)) return false;
    for (const auto& use : removed_uses)
    {
        if (!use.extent.physical_block) continue;
        ++events[use.extent.physical_block].removed;
        --events[ExtentEnd(use)].removed;
        ++events[use.extent.physical_block].affected;
        --events[ExtentEnd(use)].affected;
        events[use.extent.physical_block].original_owners.emplace_back(use.physical_owner_id, 1);
        events[ExtentEnd(use)].original_owners.emplace_back(use.physical_owner_id, -1);
    }
    for (const auto& record : requested_records)
    {
        if ((catalog::ReadU64LE(record.key, 0).value_or(0) >> 60) != kFsRecordTypeFileExtent) continue;
        FileExtentUse use;
        if (!DecodeFileExtentUse(record, block_size, use, false, external_owners))
            return Fail(out_error, "AppleVolumeFileExtentRecordInvalid");
        if (!use.extent.physical_block) continue;
        events[use.extent.physical_block].owners.emplace_back(use.physical_owner_id, 1);
        events[ExtentEnd(use)].owners.emplace_back(use.physical_owner_id, -1);
        if (clone_streams.contains(use.extent.object_id) || (clone_range && clone_range->Covers(use.extent)))
        {
            --events[use.extent.physical_block].removed;
            ++events[ExtentEnd(use)].removed;
            ++events[use.extent.physical_block].affected;
            --events[ExtentEnd(use)].affected;
        }
        else
        {
            events[use.extent.physical_block].original_owners.emplace_back(use.physical_owner_id, 1);
            events[ExtentEnd(use)].original_owners.emplace_back(use.physical_owner_id, -1);
        }
    }
    std::int64_t removed = 0, affected = 0, owner_count = 0;
    std::map<std::uint64_t, std::int64_t> owners, original_owners;
    auto event = events.begin();
    const auto advance = [&](std::uint64_t block) {
        while (event != events.end() && event->first <= block)
        {
            removed += event->second.removed;
            affected += event->second.affected;
            for (const auto& [owner, delta] : event->second.owners)
            {
                owner_count += delta;
                auto& count = owners[owner];
                count += delta;
                if (!count) owners.erase(owner);
            }
            for (const auto& [owner, delta] : event->second.original_owners)
            {
                auto& count = original_owners[owner];
                count += delta;
                if (!count) original_owners.erase(owner);
            }
            ++event;
        }
    };
    out_records.clear();
    out_releases.clear();
    for (const auto& state : physical_extents)
    {
        auto cursor = state.extent.physical_block;
        const auto end = ExtentEnd(state.extent);
        while (cursor < end)
        {
            advance(cursor);
            const auto finish = event == events.end() ? end : (std::min)(end, event->first);
            const auto next_count = static_cast<std::int64_t>(state.extent.reference_count) - removed;
            if (next_count < 0 || next_count > INT32_MAX)
                return Fail(out_error, "AppleVolumePhysicalExtentReferenceUnderflow");
            auto fragment = state.extent;
            fragment.physical_block = cursor;
            fragment.block_count = finish - cursor;
            fragment.reference_count = static_cast<std::int32_t>(next_count);
            if (affected != 0)
            {
                if (!original_owners.contains(state.extent.owning_object_id))
                    return Fail(out_error, "AppleVolumePhysicalExtentOwnerUnproven");
                for (const auto& [owner, count] : original_owners)
                    if (count != 1) return Fail(out_error, "AppleVolumePhysicalSelfReferenceUnsupported");
                if (owner_count != fragment.reference_count)
                    return Fail(out_error, "AppleVolumePhysicalExtentRefcountMismatch");
                // Self-aliasing within a stream has no supported accounting
                // contract in this slice. Every surviving reference is distinct.
                for (const auto& [owner, count] : owners)
                    if (count != 1) return Fail(out_error, "AppleVolumePhysicalSelfReferenceUnsupported");
                if (fragment.reference_count != 0 && !owners.contains(fragment.owning_object_id))
                    fragment.owning_object_id = owners.begin()->first;
            }
            if (fragment.reference_count == 0)
            {
                if (!out_releases.empty() && out_releases.back().physical_block + out_releases.back().block_count == cursor)
                    out_releases.back().block_count += finish - cursor;
                else out_releases.push_back({cursor, finish - cursor});
            }
            else
            {
                catalog::BtreeRecord encoded;
                if (!EncodeApplePhysicalExtentRecord(fragment, encoded, out_error)) return false;
                out_records.push_back(std::move(encoded));
            }
            cursor = finish;
        }
    }
    return true;
}

void AddReleaseBlocks(std::vector<AppleSpacemanReleaseRequest>& releases,
    std::span<const std::uint64_t> blocks)
{
    for (const auto block : blocks)
    {
        releases.push_back({block, 1});
    }
}

bool ReadObject(const catalog::RandomAccessSource& source,
    const catalog::AppleObjectLocation& location, std::uint32_t block_size,
    std::vector<std::byte>& out_bytes)
{
    return location.size_bytes == block_size &&
        ReadBlock(source, location.physical_block, block_size, out_bytes);
}

void AppendTreeWrites(const AppleSerializedBtree& tree,
    std::vector<AppleCheckpointPhysicalWrite>& writes)
{
    for (const auto& object : tree.objects)
    {
        writes.push_back({object.location.physical_block, object.bytes});
    }
}

bool SameRecords(const std::vector<catalog::BtreeRecord>& left,
    const std::vector<catalog::BtreeRecord>& right)
{
    return left.size() == right.size() &&
        std::equal(left.begin(), left.end(), right.begin(),
            [](const auto& lhs, const auto& rhs) {
                return lhs.key == rhs.key && lhs.value == rhs.value;
            });
}

class OverlaySource final : public catalog::RandomAccessSource
{
public:
    OverlaySource(const catalog::RandomAccessSource& base,
        std::uint32_t block_size,
        std::span<const AppleCheckpointPhysicalWrite> writes)
        : base_(base), block_size_(block_size)
    {
        for (const auto& write : writes)
        {
            const auto blocks = write.bytes.size() / block_size_;
            for (std::size_t ordinal = 0; ordinal < blocks; ++ordinal)
            {
                const auto begin = write.bytes.begin() +
                    static_cast<std::ptrdiff_t>(ordinal * block_size_);
                overlays_.emplace(write.physical_block + ordinal,
                    std::vector<std::byte>(begin, begin + block_size_));
            }
        }
    }

    [[nodiscard]] std::uint64_t SizeBytes() const override
    {
        return base_.SizeBytes();
    }
    std::shared_ptr<catalog::ApfsReadBudget> ReadBudget() const override { return base_.ReadBudget(); }

    [[nodiscard]] bool Read(std::uint64_t offset, std::size_t size,
        std::vector<std::byte>& out) const override
    {
        if (!base_.Read(offset, size, out) || out.size() != size)
        {
            return false;
        }
        const auto end = offset + size;
        if (end < offset)
        {
            return false;
        }
        const auto first_block = offset / block_size_;
        const auto last_block = size == 0 ? first_block : (end - 1) / block_size_;
        for (auto block = first_block; block <= last_block; ++block)
        {
            const auto found = overlays_.find(block);
            if (found == overlays_.end())
            {
                continue;
            }
            const auto block_start = block * static_cast<std::uint64_t>(block_size_);
            const auto copy_start = (std::max)(offset, block_start);
            const auto copy_end = (std::min)(end, block_start + block_size_);
            std::copy(found->second.begin() +
                    static_cast<std::ptrdiff_t>(copy_start - block_start),
                found->second.begin() +
                    static_cast<std::ptrdiff_t>(copy_end - block_start),
                out.begin() + static_cast<std::ptrdiff_t>(copy_start - offset));
        }
        return true;
    }

private:
    const catalog::RandomAccessSource& base_;
    std::uint32_t block_size_;
    std::unordered_map<std::uint64_t, std::vector<std::byte>> overlays_;
};

bool AddGuard(const catalog::RandomAccessSource& source,
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
    if (!ReadBlock(source, block, block_size, guard.bytes))
    {
        return false;
    }
    guards.push_back(std::move(guard));
    return true;
}

} // namespace

static bool ValidateApplePayloadExtentGraphImpl(
    const std::vector<catalog::BtreeRecord>& filesystem_records,
    const std::vector<catalog::BtreeRecord>& extentref_records,
    std::uint32_t block_size, std::uint64_t container_block_count,
    std::vector<ApplePhysicalExtentRecord>& out_extents, std::string& out_error, bool encrypted, bool observational = false)
{
    out_extents.clear();
    out_error.clear();
    std::vector<FileExtentUse> uses;
    std::vector<FileExtentUse> removed;
    std::vector<PhysicalExtentState> physical;
    if (!CollectFileExtentChanges(filesystem_records, filesystem_records,
            block_size, uses, removed, out_error, {}, encrypted, observational) ||
        !DecodePhysicalExtentTree(extentref_records, container_block_count, physical, out_error) ||
        !ValidatePhysicalExtentCoverage(uses, physical, container_block_count, out_error)) return false;
    std::sort(uses.begin(), uses.end(), [](const auto& left, const auto& right) {
        return std::pair{left.extent.object_id, left.extent.logical_address} <
            std::pair{right.extent.object_id, right.extent.logical_address};
    });
    for (std::size_t index = 1; index < uses.size(); ++index)
    {
        const auto& left = uses[index - 1].extent;
        const auto& right = uses[index].extent;
        if (left.object_id == right.object_id && left.logical_address + left.length_bytes > right.logical_address)
            return Fail(out_error, "AppleVolumeLogicalExtentOverlap");
    }
    const auto normalize = [](std::vector<std::pair<std::uint64_t, std::uint64_t>> ranges) {
        std::sort(ranges.begin(), ranges.end());
        std::vector<std::pair<std::uint64_t, std::uint64_t>> merged;
        for (const auto& range : ranges)
        {
            if (!merged.empty() && range.first <= merged.back().second)
                merged.back().second = (std::max)(merged.back().second, range.second);
            else merged.push_back(range);
        }
        return merged;
    };
    std::vector<std::pair<std::uint64_t, std::uint64_t>> file_ranges;
    std::vector<std::pair<std::uint64_t, std::uint64_t>> physical_ranges;
    for (const auto& use : uses)
        if (use.extent.physical_block != 0) file_ranges.emplace_back(use.extent.physical_block, ExtentEnd(use));
    for (const auto& state : physical)
    {
        if (state.extent.kind != kApplePhysicalExtentKindNew)
            return Fail(out_error, "AppleVolumePhysicalExtentKindUnsupported");
        physical_ranges.emplace_back(state.extent.physical_block, ExtentEnd(state.extent));
    }
    if (normalize(std::move(file_ranges)) != normalize(std::move(physical_ranges)))
        return Fail(out_error, "AppleVolumePhysicalExtentCoverageIncomplete");
    out_extents.reserve(physical.size());
    for (const auto& state : physical) out_extents.push_back(state.extent);
    return true;
}

bool ValidateApplePayloadExtentGraph(const std::vector<catalog::BtreeRecord>& fs,
    const std::vector<catalog::BtreeRecord>& refs, std::uint32_t block_size,
    std::uint64_t blocks, std::vector<ApplePhysicalExtentRecord>& out, std::string& error)
{
    return ValidateApplePayloadExtentGraphImpl(fs, refs, block_size, blocks, out, error, false);
}

bool ValidateAppleEncryptedPayloadExtentGraph(const std::vector<catalog::BtreeRecord>& fs,
    const std::vector<catalog::BtreeRecord>& refs, std::uint32_t block_size,
    std::uint64_t blocks, std::vector<ApplePhysicalExtentRecord>& out, std::string& error)
{
    return ValidateApplePayloadExtentGraphImpl(fs, refs, block_size, blocks, out, error, true);
}

bool ValidateAppleReadOnlyPayloadExtentGraph(const std::vector<catalog::BtreeRecord>& fs,
    const std::vector<catalog::BtreeRecord>& refs, std::uint32_t block_size,
    std::uint64_t blocks, std::vector<ApplePhysicalExtentRecord>& out, std::string& error)
{
    return ValidateApplePayloadExtentGraphImpl(fs, refs, block_size, blocks, out, error, false, true);
}

namespace {
using SnapshotRanges = std::vector<ApplePhysicalExtentRecord>;
bool SnapshotRangesValid(const SnapshotRanges& ranges, std::uint64_t blocks,
    bool disjoint, std::string& error)
{
    std::uint64_t end = 0;
    for (const auto& range : ranges) {
        catalog::BtreeRecord record;
        if (range.kind != kApplePhysicalExtentKindNew ||
            !EncodeApplePhysicalExtentRecord(range, record, error) ||
            range.physical_block >= blocks || range.block_count > blocks - range.physical_block ||
            (disjoint && range.physical_block < end))
            return Fail(error, "AppleSnapshotResolvedRangeInvalid");
        end = range.physical_block + range.block_count;
    }
    return true;
}
const ApplePhysicalExtentRecord* SnapshotRangeAt(const SnapshotRanges& ranges, std::uint64_t block)
{
    auto it = std::upper_bound(ranges.begin(), ranges.end(), block,
        [](auto value, const auto& range) { return value < range.physical_block; });
    if (it == ranges.begin()) return nullptr;
    --it;
    return block - it->physical_block < it->block_count ? &*it : nullptr;
}
std::vector<std::pair<std::uint64_t, std::uint64_t>> SnapshotHistoryUnion(const SnapshotRanges& ranges)
{
    std::vector<std::pair<std::uint64_t, std::uint64_t>> result;
    for (const auto& r : ranges) result.emplace_back(r.physical_block, r.physical_block + r.block_count);
    std::sort(result.begin(), result.end());
    std::size_t used = 0;
    for (const auto r : result) {
        if (used && r.first <= result[used-1].second) result[used-1].second = (std::max)(result[used-1].second,r.second);
        else result[used++] = r;
    }
    result.resize(used); return result;
}
bool SnapshotHistoryAt(const std::vector<std::pair<std::uint64_t,std::uint64_t>>& ranges, std::uint64_t block)
{
    auto it = std::upper_bound(ranges.begin(), ranges.end(), std::pair{block, UINT64_MAX});
    return it != ranges.begin() && block < std::prev(it)->second;
}
void SnapshotBoundaries(const SnapshotRanges& ranges, std::vector<std::uint64_t>& points)
{
    for (const auto& r : ranges) { points.push_back(r.physical_block); points.push_back(r.physical_block+r.block_count); }
}
void SnapshotAppend(SnapshotRanges& ranges, ApplePhysicalExtentRecord range)
{
    if (!ranges.empty()) {
        auto& last = ranges.back();
        if (last.physical_block+last.block_count == range.physical_block &&
            last.kind == range.kind && last.owning_object_id == range.owning_object_id &&
            last.reference_count == range.reference_count) { last.block_count += range.block_count; return; }
    }
    ranges.push_back(range);
}
}

static bool ResolveSnapshotExtentLayerWithAdmission(const SnapshotRanges& prior, const SnapshotRanges& historical,
    const std::vector<catalog::BtreeRecord>& filesystem, const std::vector<catalog::BtreeRecord>& layer,
    std::uint32_t block_size, std::uint64_t container_blocks,
    SnapshotRanges& out_resolved, std::string& out_error, bool observational, bool encrypted = false)
{
    out_resolved.clear(); out_error.clear();
    if (!SnapshotRangesValid(prior,container_blocks,true,out_error) ||
        !SnapshotRangesValid(historical,container_blocks,false,out_error)) return false;
    SnapshotRanges changes;
    for (const auto& raw : layer) {
        ApplePhysicalExtentRecord r;
        if (!DecodeApplePhysicalExtentRecord(raw,r,out_error) || r.physical_block >= container_blocks ||
            r.block_count > container_blocks-r.physical_block) return Fail(out_error,"AppleSnapshotLayerRecordInvalid");
        changes.push_back(r);
    }
    std::sort(changes.begin(),changes.end(),[](const auto& a,const auto& b){return a.physical_block<b.physical_block;});
    for (std::size_t i=1;i<changes.size();++i)
        if (changes[i-1].physical_block+changes[i-1].block_count>changes[i].physical_block)
            return Fail(out_error,"AppleSnapshotLayerOverlap");
    const auto history = SnapshotHistoryUnion(historical);
    std::vector<std::uint64_t> points;
    SnapshotBoundaries(prior,points); SnapshotBoundaries(changes,points);
    for (const auto& r:history) {points.push_back(r.first);points.push_back(r.second);}
    std::sort(points.begin(),points.end());points.erase(std::unique(points.begin(),points.end()),points.end());
    SnapshotRanges resolved;
    for (std::size_t i=1;i<points.size();++i) {
        const auto start=points[i-1], length=points[i]-start;
        const auto* before=SnapshotRangeAt(prior,start);const auto* change=SnapshotRangeAt(changes,start);
        const bool held=SnapshotHistoryAt(history,start);
        if (before && !held) return Fail(out_error,"AppleSnapshotPriorOwnershipMissing");
        if (!before&&!change) continue;
        auto r=change?*change:*before;r.physical_block=start;r.block_count=length;
        std::int64_t count=before?before->reference_count:0;
        if (change) {
            if (change->kind==kApplePhysicalExtentKindNew) {
                if (held || before) return Fail(out_error,"AppleSnapshotNewOverlapsHistory");
                count=change->reference_count;
            } else {
                if (!held) return Fail(out_error,"AppleSnapshotUpdateWithoutHistory");
                count+=change->reference_count;
            }
        }
        if (count<0 || count>INT32_MAX) return Fail(out_error,"AppleSnapshotLayerRefcountOverflow");
        if (!count) continue;
        r.kind=kApplePhysicalExtentKindNew;r.reference_count=static_cast<std::int32_t>(count);
        SnapshotAppend(resolved,r);
    }
    std::vector<catalog::BtreeRecord> complete;
    for (const auto& r:resolved) {catalog::BtreeRecord raw;if(!EncodeApplePhysicalExtentRecord(r,raw,out_error))return false;complete.push_back(std::move(raw));}
    // This compares interval coverage, owner identity and the per-view mapping
    // multiplicity. Historical views are never added to a clone refcount.
    return ValidateApplePayloadExtentGraphImpl(filesystem,complete,block_size,container_blocks,out_resolved,out_error,encrypted,observational);
}

bool ResolveAppleSnapshotExtentLayer(const SnapshotRanges& prior, const SnapshotRanges& historical,
    const std::vector<catalog::BtreeRecord>& fs, const std::vector<catalog::BtreeRecord>& refs,
    std::uint32_t block_size, std::uint64_t blocks, SnapshotRanges& out, std::string& error)
{
    return ResolveSnapshotExtentLayerWithAdmission(prior,historical,fs,refs,block_size,blocks,out,error,false);
}

bool ResolveAppleReadOnlySnapshotExtentLayer(const SnapshotRanges& prior, const SnapshotRanges& historical,
    const std::vector<catalog::BtreeRecord>& fs, const std::vector<catalog::BtreeRecord>& refs,
    std::uint32_t block_size, std::uint64_t blocks, SnapshotRanges& out, std::string& error)
{
    return ResolveSnapshotExtentLayerWithAdmission(prior,historical,fs,refs,block_size,blocks,out,error,true);
}

bool ResolveAppleEncryptedReadOnlySnapshotExtentLayer(const SnapshotRanges& prior, const SnapshotRanges& historical,
    const std::vector<catalog::BtreeRecord>& fs, const std::vector<catalog::BtreeRecord>& refs,
    std::uint32_t block_size, std::uint64_t blocks, SnapshotRanges& out, std::string& error)
{
    return ResolveSnapshotExtentLayerWithAdmission(prior,historical,fs,refs,block_size,blocks,out,error,true,true);
}

bool ResolveAppleFusionReadOnlySnapshotExtentLayer(const catalog::ApfsFusionStore& source,
    const SnapshotRanges& prior, const SnapshotRanges& historical,
    const std::vector<catalog::BtreeRecord>& fs, const std::vector<catalog::BtreeRecord>& refs,
    SnapshotRanges& out, std::string& error)
{
    out.clear(); error.clear();
    if (!source.CheckAvailable(error)) return false;
    const auto block_size = source.Checkpoint().superblock.block_size;
    if (!block_size) return Fail(error, "AppleSnapshotFusionBlockSizeInvalid");
    const auto invalid = [&](const char* fallback) {
        if (error.empty()) error = fallback;
        return false;
    };
    const auto valid = [&](const ApplePhysicalExtentRecord& range) {
        const auto budget = source.ReadBudget();
        if (budget && !budget->Materialize(1, 0)) { error = budget->Failure(); return false; }
        catalog::FusionRoute route;
        return range.block_count && range.block_count <= UINT64_MAX / block_size &&
            source.MapPhysical(range.physical_block, 0, range.block_count * block_size, route, error);
    };
    for (const auto* ranges : {&prior, &historical})
        for (const auto& range : *ranges)
            if (!valid(range)) return invalid("AppleSnapshotFusionHistoryRangeInvalid");
    for (const auto& record : refs)
    {
        ApplePhysicalExtentRecord range;
        if (!DecodeApplePhysicalExtentRecord(record, range, error) || !valid(range))
            return invalid("AppleSnapshotFusionLayerRangeInvalid");
    }
    SnapshotRanges result;
    if (!ResolveSnapshotExtentLayerWithAdmission(prior, historical, fs, refs, block_size,
        source.SizeBytes() / block_size, result, error, true)) return false;
    for (const auto& range : result)
        if (!valid(range)) return invalid("AppleSnapshotFusionResolvedRangeInvalid");
    if (!source.CheckAvailable(error)) return false;
    out = std::move(result); return true;
}

bool PlanAppleSnapshotExtentLayer(const SnapshotRanges& prior, const SnapshotRanges& historical,
    const std::vector<catalog::BtreeRecord>& filesystem, const std::vector<catalog::BtreeRecord>& complete_extentrefs,
    std::uint32_t block_size,std::uint64_t container_blocks,
    std::vector<catalog::BtreeRecord>& out_layer,std::string& out_error)
{
    out_layer.clear();out_error.clear();SnapshotRanges after;
    if (!SnapshotRangesValid(prior,container_blocks,true,out_error) ||
        !SnapshotRangesValid(historical,container_blocks,false,out_error) ||
        !ValidateApplePayloadExtentGraph(filesystem,complete_extentrefs,block_size,container_blocks,after,out_error))return false;
    const auto history=SnapshotHistoryUnion(historical);
    std::vector<std::uint64_t> points;SnapshotBoundaries(prior,points);SnapshotBoundaries(after,points);
    for(const auto& r:history){points.push_back(r.first);points.push_back(r.second);}
    std::sort(points.begin(),points.end());points.erase(std::unique(points.begin(),points.end()),points.end());
    SnapshotRanges changes;
    for(std::size_t i=1;i<points.size();++i){
        const auto start=points[i-1];const auto* a=SnapshotRangeAt(prior,start);const auto* b=SnapshotRangeAt(after,start);
        if(!a&&!b)continue;
        if(a&&b&&a->reference_count==b->reference_count&&a->owning_object_id==b->owning_object_id)continue;
        auto r=b?*b:*a;r.physical_block=start;r.block_count=points[i]-start;
        if(SnapshotHistoryAt(history,start)){
            r.kind=kApplePhysicalExtentKindUpdate;
            r.reference_count=(b?b->reference_count:0)-(a?a->reference_count:0);
        }else{
            if(a)return Fail(out_error,"AppleSnapshotPriorOwnershipMissing");
            r.kind=kApplePhysicalExtentKindNew;
        }
        SnapshotAppend(changes,r);
    }
    std::vector<catalog::BtreeRecord> result;
    for(const auto& r:changes){catalog::BtreeRecord raw;if(!EncodeApplePhysicalExtentRecord(r,raw,out_error))return false;result.push_back(std::move(raw));}
    SnapshotRanges verified;
    if(!ResolveAppleSnapshotExtentLayer(prior,historical,filesystem,result,block_size,container_blocks,verified,out_error))return false;
    out_layer=std::move(result);return true;
}

bool CheckAppleVolumeWriteFeatures(
    const catalog::NxSuperblock& container,
    const catalog::ApsbVolume& volume,
    std::string& out_error,
    bool allow_fusion_profile)
{
    out_error.clear();
    // The Fusion profile is admitted only through the Fusion entry, which
    // plans against a bound-store-proven checkpoint. The exact incompatibility
    // word is the one the bind layer establishes; anything else stays refused.
    const bool fusion_profile = allow_fusion_profile &&
        container.incompatible_features ==
            (catalog::kNxIncompatFusion | catalog::kNxSupportedIncompatibleFeaturesMask);
    if (container.readonly_features != 0 ||
        (!fusion_profile && (container.incompatible_features & ~catalog::kNxSupportedIncompatibleFeaturesMask) != 0))
    {
        return Fail(out_error, "NativeAppleTransactionContainerFeatureUnsupported");
    }
    if ((volume.fs_flags & catalog::kFsFlagUnencrypted) == 0)
    {
        return Fail(out_error, "NativeAppleTransactionEncryptionUnsupported");
    }
    if (volume.readonly_features != 0 ||
        (volume.incompatible_features & ~catalog::kVolumeSupportedIncompatibleFeaturesMask) != 0 ||
        (volume.role_raw != 0 && volume.role_raw != 0x0040))
    {
        return Fail(out_error, "NativeAppleTransactionFeatureUnsupported");
    }
    if (volume.snap_meta_ext_oid != 0)
    {
        return Fail(out_error, "SnapshotExtendedMetadataUnsupported");
    }
    return true;
}

#include "BackupImageWriterProfile.inc"

static bool FinalizeSnapshotRetirement(const catalog::RandomAccessSource& source,
    const catalog::AppleCheckpointView& checkpoint, std::uint64_t volume_oid,
    AppleSpacemanAllocationRequest allocate, AppleTransactionCommitRequest& request,
    const AppleSnapshotInventoryChange* change, AppleTransactionCommitPlan& commit,
    AppleSpacemanAllocationPlan& allocation, std::string& error,
    std::uint64_t* retired_payload = nullptr) {
    AppleSnapshotRetirementProof proof;
    if (!ProveAppleSnapshotRetirement(source, checkpoint, commit.publication, volume_oid,
            request.required_checkpoint_xids, proof, error)) return false;
    allocate.released_blocks = proof.releases;
    AppleSpacemanAllocationPlan exact;
    if (!PlanAppleSpacemanAllocation(checkpoint.spaceman, allocate, exact, error)) return false;
    if (exact.allocated_main_blocks != allocation.allocated_main_blocks ||
        exact.allocated_internal_pool_blocks != allocation.allocated_internal_pool_blocks)
        return Fail(error, "AppleSnapshotRetirementAllocationChanged");
    const auto selected = std::find_if(checkpoint.volumes.begin(), checkpoint.volumes.end(),
        [&](const auto& v) {return v.superblock.object_id == volume_oid;});
    if (selected == checkpoint.volumes.end()) return Fail(error, "AppleSnapshotRetirementVolumeMissing");
    std::vector<std::byte> before;
    if (!ReadObject(source, selected->superblock_object, checkpoint.container.superblock.block_size, before))
        return Fail(error, "AppleSnapshotRetirementSourceUnreadable");
    bool patched = false;
    for (auto& write : request.allocated_main_writes) {
        const auto apsb = catalog::ParseApsb(write.bytes);
        if (!apsb || apsb->object_id != volume_oid ||
            catalog::ReadU32LE(write.bytes, 0x18) != catalog::kObjectTypeFs) continue;
        if (patched) return Fail(error, "AppleSnapshotRetirementVolumeAmbiguous");
        for (const auto offset : {0x58u, 0xe0u, 0xe8u}) {
            auto value = catalog::ReadU64LE(before, offset).value();
            const auto increase = offset == 0xe8 ? proof.retired_volume_blocks : proof.allocated_volume_blocks;
            if (increase > UINT64_MAX - value) return Fail(error, "AppleSnapshotRetirementAccountingOverflow");
            value += increase;
            if (offset == 0x58) {
                if (proof.retired_volume_blocks > value) return Fail(error, "AppleSnapshotRetirementAccountingOverflow");
                value -= proof.retired_volume_blocks;
            }
            for (std::size_t i = 0; i < 8; ++i) write.bytes[offset + i] = std::byte((value >> (8 * i)) & 0xff);
        }
        if (!FinalizeAppleObjectChecksum(write.bytes, error)) return false;
        patched = true;
    }
    if (!patched) return Fail(error, "AppleSnapshotRetirementVolumeMissing");
    request.allocation_plan = exact;
    request.next_object_id = checkpoint.container.superblock.next_oid;
    for (const auto& write : exact.writes) if (write.object_location)
        request.next_object_id = (std::max)(request.next_object_id, write.object_location->object_id + 1);
    request.snapshot_retirement_volume_oid = volume_oid;
    AppleTransactionCommitPlan final;
    if (!(change ? PlanAppleSnapshotInventoryCommit(source, checkpoint, request, *change, final, error) :
        PlanAppleSnapshotPreservingCommit(source, checkpoint, request, final, error))) return false;
    if (retired_payload) *retired_payload = proof.retired_volume_payload_blocks;
    allocation = std::move(exact); commit = std::move(final); return true;
}

namespace
{
bool SnapshotMetadataProfile(const catalog::AppleVolumeCheckpointView& volume,
    const std::vector<std::byte>& apsb)
{
    if (!volume.snapshot_metadata_tree) return false;
    const auto& root = *volume.snapshot_metadata_tree;
    const bool physical = root.type == (catalog::kObjectPhysical | catalog::kObjectTypeBtree);
    return (physical || root.type == catalog::kObjectTypeBtree) &&
        root.subtype == catalog::kObjectTypeSnapMetaTree &&
        root.type == volume.superblock.snap_meta_tree_type &&
        catalog::ReadU32LE(apsb, 0x7c) == root.type &&
        catalog::ReadU64LE(apsb, 0x98) == root.object_id &&
        root.object_id == volume.superblock.snap_meta_tree_oid &&
        (!physical || root.object_id == root.physical_block);
}

bool SnapshotMetadataChildIds(const catalog::AppleVolumeCheckpointView& volume,
    const std::vector<catalog::BtreeRecord>& mappings,
    const std::vector<catalog::BtreeRecord>& filesystem, std::size_t nodes,
    std::uint64_t& first, std::uint64_t& next, std::string& error)
{
    first = volume.snapshot_metadata_tree->object_id == 1 ? 2 : 1;
    next = volume.superblock.next_object_id;
    if (volume.snapshot_metadata_tree->type == (catalog::kObjectPhysical | catalog::kObjectTypeBtree))
        return nodes != 0;
    if (nodes <= 1) return nodes == 1;
    std::uint64_t maximum = volume.snapshot_metadata_tree->object_id;
    for (const auto& record : mappings) maximum = (std::max)(maximum, catalog::ReadU64LE(record.key, 0).value());
    for (const auto& record : filesystem) maximum = (std::max)(maximum, catalog::ReadU64LE(record.key, 0).value() & kFsObjectIdMask);
    if (maximum >= kFsObjectIdMask) return Fail(error, "AppleSnapshotMetadataObjectIdExhausted");
    first = (std::max)(next, maximum + 1);
    if (first > kFsObjectIdMask || nodes - 1 > kFsObjectIdMask - first)
        return Fail(error, "AppleSnapshotMetadataObjectIdExhausted");
    next = first + nodes - 1;
    return true;
}

bool SnapshotMetadataMappings(const catalog::RandomAccessSource& source,
    std::vector<catalog::BtreeRecord>& mappings,
    const std::unordered_set<std::uint64_t>& old_ids, const catalog::AppleObjectLocation& root,
    std::uint64_t first_child_oid, std::size_t nodes, std::uint64_t xid,
    std::uint32_t block_size, const AppleSerializedBtree* tree, std::string& error)
{
    // Physical metadata uses paddr identities and APSB pointers, independently
    // of numerically equal virtual object IDs in the filesystem OMAP.
    if (root.type == (catalog::kObjectPhysical | catalog::kObjectTypeBtree)) {
        if (tree && std::any_of(tree->objects.begin(), tree->objects.end(), [](const auto& object) {
                return object.location.object_id != object.location.physical_block ||
                    (object.location.type != (catalog::kObjectPhysical | catalog::kObjectTypeBtree) &&
                        object.location.type != (catalog::kObjectPhysical | catalog::kObjectTypeBtreeNode));
            })) return Fail(error, "AppleSnapshotMetadataPhysicalIdentityInvalid");
        return true;
    }
    const auto root_oid = root.object_id;
    if (!source.ReadBudget()->Materialize(nodes, nodes * (sizeof(catalog::BtreeRecord) + 32ull)))
        return Fail(error, source.ReadBudget()->Failure());
    // Replace only this live tree. Historical APSBs keep their old physical OMAP.
    std::erase_if(mappings, [&](const auto& record) {
        const auto oid = catalog::ReadU64LE(record.key, 0).value();
        return old_ids.contains(oid) || oid == root_oid ||
            (oid >= first_child_oid && oid - first_child_oid < nodes - 1);
    });
    if (tree) {
        for (const auto& object : tree->objects)
            if (!AddOmapRecord(mappings, object.location.object_id, xid, object.location.physical_block, block_size, error)) return false;
        return true;
    }
    if (!AddOmapRecord(mappings, root_oid, xid, 1, block_size, error)) return false;
    for (std::size_t i = 0; i + 1 < nodes; ++i)
        if (!AddOmapRecord(mappings, first_child_oid + i, xid, 1, block_size, error)) return false;
    return true;
}
}

bool PlanAppleSnapshotCreate(const catalog::RandomAccessSource& source,
    const catalog::AppleCheckpointView& checkpoint, const AppleSnapshotCreateRequest& request,
    AppleSnapshotCreatePlan& out_plan, std::string& out_error, bool allow_fusion_profile) try
{
    out_plan={};out_error.clear();
    if (!source.ReadBudget()) {
        auto budget=std::make_shared<catalog::ApfsReadBudget>(65536,256ull<<20,1000000,256ull<<20);
        catalog::BudgetedRandomAccessSource bounded(source,budget);
        return PlanAppleSnapshotCreate(bounded,checkpoint,request,out_plan,out_error,allow_fusion_profile);
    }
    if (!dynamic_cast<const SnapshotPlanningSource*>(&source)) {
        SnapshotPlanningSource observation(source);
        if (!PlanAppleSnapshotCreate(observation, checkpoint, request, out_plan, out_error, allow_fusion_profile) ||
            !observation.VerifyUnchanged(out_error)) {
            out_plan = {};
            if (source.ReadBudget()->Failed()) out_error = source.ReadBudget()->Failure();
            return false;
        }
        return true;
    }
    const auto& nx=checkpoint.container.superblock;
    if(!nx.block_size || nx.next_xid<=nx.xid || nx.next_xid>kFsObjectIdMask ||
        request.name_utf8.empty() || request.name_utf8.size()>255 ||
        request.name_utf8.find('\0')!=std::string::npos || !request.creation_time_ns ||
        request.snapshot_inum>kFsObjectIdMask)
        return Fail(out_error,"AppleSnapshotCreateRequestInvalid");
    const auto it=std::find_if(checkpoint.volumes.begin(),checkpoint.volumes.end(),[&](const auto& v){return v.superblock.object_id==request.volume_object_id;});
    if(it==checkpoint.volumes.end())return Fail(out_error,"AppleSnapshotCreateVolumeMissing");
    const auto& volume=*it;
    if(!CheckAppleVolumeWriteFeatures(nx,volume.superblock,out_error,allow_fusion_profile))return false;
    catalog::ApfsSnapshotScope scope{0,nx.block_count*nx.block_size,nx.uuid_hex,volume.superblock.uuid_hex,request.volume_object_id,nx.xid};
    std::vector<catalog::ApfsSnapshotInfo> inventory;
    AppleSnapshotRetentionView existing;
    std::shared_ptr<const std::vector<SnapshotRetentionCatalog>> existing_catalogs;
    if(!LoadSnapshotPlanningRetentionCatalogs(source,checkpoint,existing,existing_catalogs,out_error))return false;
    if(existing_catalogs){
        const auto count=std::count_if(existing.identities.begin(),existing.identities.end(),
            [&](const auto& id){return id.scope.volume_oid==request.volume_object_id;});
        if(!source.ReadBudget()->Materialize(count,count*sizeof(catalog::ApfsSnapshotInfo)))return Fail(out_error,source.ReadBudget()->Failure());
        for(const auto& id:existing.identities)if(id.scope.volume_oid==request.volume_object_id){
            if(!source.ReadBudget()->Materialize(1,id.name_utf8.size()+id.scope.container_uuid_hex.size()+id.scope.volume_uuid_hex.size()))return Fail(out_error,source.ReadBudget()->Failure());
            catalog::ApfsSnapshotInfo info;info.identity=id;inventory.push_back(std::move(info));
        }
    }else if(volume.snapshot_metadata_tree &&
        volume.snapshot_metadata_tree->type==(catalog::kObjectPhysical|catalog::kObjectTypeBtree)){
        catalog::AppleSnapshotCatalogRecords empty_catalog;
        if(!catalog::LoadAppleReadOnlySnapshotCatalog(source,checkpoint,request.volume_object_id,empty_catalog,out_error))return false;
        if(!empty_catalog.inventory.empty())return Fail(out_error,"AppleSnapshotCreateCanonicalLayerMissing");
    }else if(!catalog::ApfsSnapshotStore::Enumerate(source,scope,inventory,out_error))return false;
    if(std::any_of(inventory.begin(),inventory.end(),[&](const auto& s){return s.identity.name_utf8==request.name_utf8;}))
        return Fail(out_error,"AppleSnapshotCreateNameExists");
    if(!volume.extentref_tree || !volume.snapshot_metadata_tree || volume.file_extent_tree ||
        volume.root_tree.type!=catalog::kObjectTypeBtree ||
        (volume.snapshot_metadata_tree->type!=catalog::kObjectTypeBtree &&
            volume.snapshot_metadata_tree->type!=(catalog::kObjectPhysical|catalog::kObjectTypeBtree)) ||
        volume.extentref_tree->type!=(catalog::kObjectPhysical|catalog::kObjectTypeBtree))
        return Fail(out_error,"AppleSnapshotCreateTreeProfileUnsupported");
    std::vector<std::byte> apsb,omap,container_omap;
    if(!ReadObject(source,volume.superblock_object,nx.block_size,apsb)||
        !ReadObject(source,volume.object_map.object,nx.block_size,omap)||
        !ReadObject(source,checkpoint.container_object_map.object,nx.block_size,container_omap))return Fail(out_error,"AppleSnapshotCreateSourceUnreadable");
    if(!SnapshotMetadataProfile(volume,apsb))return Fail(out_error,"AppleSnapshotCreateTreeProfileUnsupported");
    const SnapshotRetentionCatalog* completed=nullptr;
    if(existing_catalogs){
        const auto found=std::find_if(existing_catalogs->begin(),existing_catalogs->end(),
            [&](const auto& value){return value.volume_oid==request.volume_object_id;});
        if(found==existing_catalogs->end())return Fail(out_error,"AppleSnapshotCreateCanonicalLayerMissing");
        completed=&*found;
    }
    std::vector<catalog::BtreeRecord> fs_storage,refs_storage,map_records,container_records,metadata_records,snapshot_map_records;
    const auto& fs=completed?completed->records.live.filesystem:fs_storage;
    const auto& refs=completed?completed->records.live.extentref:refs_storage;
    std::vector<std::uint64_t> guards,visited;
    const auto read=[&](const auto& root,std::uint64_t map,auto& records){
        if(!ReadTreeRecords(source,root,nx.block_size,map,nx.xid,records,visited,out_error))return false;
        guards.insert(guards.end(),visited.begin(),visited.end());return true;};
    if(completed){
        const auto count=completed->records.metadata_blocks.size();
        if(!source.ReadBudget()->Materialize(count,count*sizeof(std::uint64_t)))
            return Fail(out_error,source.ReadBudget()->Failure());
        guards.reserve(count);
        guards.insert(guards.end(),completed->records.metadata_blocks.begin(),completed->records.metadata_blocks.end());
    }
    else if(!read(volume.root_tree,volume.superblock.omap_oid,fs_storage)||!read(*volume.extentref_tree,0,refs_storage))return false;
    if(!read(volume.object_map.tree,0,map_records)||!read(checkpoint.container_object_map.tree,0,container_records)||
        !read(*volume.snapshot_metadata_tree,volume.superblock.omap_oid,metadata_records))return false;
    std::unordered_set<std::uint64_t> old_metadata_ids;
    if(!source.ReadBudget()->Materialize(visited.size(),visited.size()*64ull))return Fail(out_error,source.ReadBudget()->Failure());
    if(!ReadTreeObjectIds(source,visited,nx.block_size,old_metadata_ids))return Fail(out_error,"AppleSnapshotCreateMetadataIdentityInvalid");
    for(const auto& s:inventory){
        catalog::BtreeRecord r{std::vector<std::byte>(8),std::vector<std::byte>(16)};
        for(std::size_t n=0;n<8;++n)r.key[n]=static_cast<std::byte>(s.identity.snapshot_xid>>(8*n));
        // Enumerate has proved ordinary zero-flag/zero-oid OMAP entries.
        snapshot_map_records.push_back(std::move(r));
    }
    std::vector<ApplePhysicalExtentRecord> payload;
    if(!completed){
    if(!source.ReadBudget()->Materialize(fs.size()+refs.size(),(fs.size()+refs.size())*2048ull))return Fail(out_error,source.ReadBudget()->Failure());
    SnapshotRanges prior,history;
    for(const auto& s:inventory){
        catalog::ApfsSnapshotRecords records;
        if(!catalog::ApfsSnapshotStore::LoadExactResolvedRecords(source,s.identity,records,out_error)||
            !ValidateApplePayloadExtentGraph(records.trees.filesystem,records.trees.extentref,nx.block_size,nx.block_count,prior,out_error))return false;
        if(!source.ReadBudget()->Materialize(prior.size(),prior.size()*2048ull))return Fail(out_error,source.ReadBudget()->Failure());
        history.insert(history.end(),prior.begin(),prior.end());
    }
    if(!ResolveAppleSnapshotExtentLayer(prior,history,fs,refs,nx.block_size,nx.block_count,payload,out_error)||
        (existing.identities.empty()&&!ValidateAppleCheckpointPayloadOwnership(source,checkpoint,payload,out_error)))return false;
    }
    TreeShape map_shape,container_shape,meta_shape,extent_shape;
    if(!ReadTreeShape(source,volume.object_map.tree,nx.block_size,map_shape)||
        !ReadTreeShape(source,checkpoint.container_object_map.tree,nx.block_size,container_shape)||
        !ReadTreeShape(source,*volume.snapshot_metadata_tree,nx.block_size,meta_shape)||
        !ReadTreeShape(source,*volume.extentref_tree,nx.block_size,extent_shape))return Fail(out_error,"AppleSnapshotCreateTreeShapeInvalid");
    // Existing object serializers own layout and checksums. This local writer
    // only supplies canonical record fields; staged parsing is authoritative.
    const auto put=[](std::vector<std::byte>& bytes,std::size_t at,std::uint64_t value,std::size_t size=8){
        for(std::size_t n=0;n<size;++n)bytes[at+n]=static_cast<std::byte>(value>>(n*8));};
    const auto metadata=[&](std::uint64_t snapshot_block){
        catalog::BtreeRecord r{std::vector<std::byte>(8),std::vector<std::byte>(51+request.name_utf8.size())};
        put(r.key,0,(1ull<<60)|nx.next_xid);put(r.value,0,volume.extentref_tree->physical_block);
        put(r.value,8,snapshot_block);put(r.value,16,request.creation_time_ns);put(r.value,24,request.creation_time_ns);
        put(r.value,32,request.snapshot_inum);put(r.value,40,volume.extentref_tree->type,4);
        put(r.value,48,request.name_utf8.size()+1,2);
        for(std::size_t n=0;n<request.name_utf8.size();++n)r.value[50+n]=static_cast<std::byte>(request.name_utf8[n]);return r;};
    catalog::BtreeRecord name{std::vector<std::byte>(11+request.name_utf8.size()),std::vector<std::byte>(8)};
    put(name.key,0,(11ull<<60)|kFsObjectIdMask);put(name.key,8,request.name_utf8.size()+1,2);put(name.value,0,nx.next_xid);
    for(std::size_t n=0;n<request.name_utf8.size();++n)name.key[10+n]=static_cast<std::byte>(request.name_utf8[n]);
    catalog::BtreeRecord snap_map{std::vector<std::byte>(8),std::vector<std::byte>(16)};put(snap_map.key,0,nx.next_xid);
    snapshot_map_records.push_back(snap_map);
    metadata_records.push_back(metadata(1));metadata_records.push_back(name);
    RemoveOmapRecords(container_records,{request.volume_object_id});
    if(!AddOmapRecord(container_records,request.volume_object_id,nx.next_xid,1,nx.block_size,out_error))return false;
    AppleSerializedBtree estimated_map,estimated_container,estimated_meta,estimated_snapshots;
    TreeShape snap_shape;snap_shape.storage_type=catalog::kObjectPhysical;snap_shape.subtype=0x13;snap_shape.tree_flags=kAppleBtreePhysical;
    const auto placeholder_child=volume.snapshot_metadata_tree->object_id==1?2ull:1ull;
    if(!SerializeTree(metadata_records,meta_shape,AppleBtreeKeyOrder::FileSystemCaseSensitive,nx.block_size,nx.next_xid,
        volume.snapshot_metadata_tree->object_id,placeholder_child,{},estimated_meta,out_error))return false;
    const auto meta_count=estimated_meta.objects.size();
    std::uint64_t first_child_oid=0,next_volume_oid=0;
    if(!SnapshotMetadataChildIds(volume,map_records,fs,meta_count,first_child_oid,next_volume_oid,out_error)||
        !SnapshotMetadataMappings(source,map_records,old_metadata_ids,*volume.snapshot_metadata_tree,
            first_child_oid,meta_count,nx.next_xid,nx.block_size,nullptr,out_error)||
        !SerializeTree(map_records,map_shape,AppleBtreeKeyOrder::ObjectMap,nx.block_size,nx.next_xid,1,2,{},estimated_map,out_error)||
        !SerializeTree(container_records,container_shape,AppleBtreeKeyOrder::ObjectMap,nx.block_size,nx.next_xid,1,2,{},estimated_container,out_error)||
        !SerializeTree(snapshot_map_records,snap_shape,AppleBtreeKeyOrder::SnapshotObjectMap,nx.block_size,nx.next_xid,1,2,{},estimated_snapshots,out_error))return false;
    const auto map_count=estimated_map.objects.size(),container_count=estimated_container.objects.size(),snapshot_count=estimated_snapshots.objects.size();
    AppleSpacemanAllocationRequest allocation_request;
    allocation_request.expected_checkpoint_xid=nx.xid;allocation_request.transaction_xid=nx.next_xid;
    allocation_request.oldest_required_checkpoint_xid=nx.xid;allocation_request.first_ephemeral_object_id=nx.next_oid;
    if(!SumBlockCounts({5,meta_count,snapshot_count,map_count,container_count},allocation_request.main_block_count))
        return Fail(out_error,"AppleSnapshotCreateAllocationInvalid");
    std::vector<AppleRecoveryCheckpointView> retained;
    if(!LoadAppleSnapshotRecoveryCheckpoints(source,checkpoint,request.required_checkpoint_xids,retained,out_error))return false;
    for(const auto& old:retained){
        allocation_request.oldest_required_checkpoint_xid=(std::min)(allocation_request.oldest_required_checkpoint_xid,old.checkpoint.container.superblock.xid);
        for(const auto& bitmap:old.checkpoint.spaceman.internal_pool.active_bitmaps)
            allocation_request.protected_internal_pool_bitmap_indices.push_back(bitmap.rotation_index);
    }
    AppleSnapshotCreatePlan plan;
    if(!PlanAppleSpacemanAllocation(checkpoint.spaceman,allocation_request,plan.allocation,out_error))return false;
    const auto& blocks=plan.allocation.allocated_main_blocks;
    if(blocks.size()!=allocation_request.main_block_count)return Fail(out_error,"AppleSnapshotCreateAllocationInvalid");
    catalog::ApfsSharedSpaceProjection space;
    if(!catalog::TryProjectAppleSharedSpace(checkpoint,space,out_error))return false;
    const auto selected=std::find_if(space.volumes.begin(),space.volumes.end(),[&](const auto& v){return v.object_id==request.volume_object_id;});
    if(selected==space.volumes.end())return Fail(out_error,"AppleSnapshotCreateVolumeMissing");
    std::uint64_t new_volume_blocks=0;
    if(!SumBlockCounts({4,meta_count,snapshot_count,map_count},new_volume_blocks))return Fail(out_error,"AppleSnapshotCreateAllocationInvalid");
    std::uint64_t allocated=0;
    if(!AdjustCount(selected->allocated.blocks,static_cast<std::int64_t>(new_volume_blocks),allocated))return Fail(out_error,"AppleSnapshotCreateAccountingOverflow");
    std::vector<AppleCheckpointPhysicalWrite> writes;
    AppleSerializedBtree empty_tree,meta_tree,snapshot_map_tree,new_map_tree,new_container_tree;
    const auto one=[&](std::size_t n){return std::span<const std::uint64_t>(&blocks[n],1);};
    std::size_t cursor=5;
    const auto take=[&](std::size_t count){auto span=std::span<const std::uint64_t>(blocks).subspan(cursor,count);cursor+=count;return span;};
    const auto meta_blocks=take(meta_count),snapshot_blocks=take(snapshot_count),map_blocks=take(map_count),container_blocks=take(container_count);
    if(cursor!=blocks.size())return Fail(out_error,"AppleSnapshotCreateAllocationInvalid");
    metadata_records[metadata_records.size()-2]=metadata(blocks[0]);
    if(!SerializeTree({},extent_shape,AppleBtreeKeyOrder::PhysicalExtent,nx.block_size,nx.next_xid,1,2,one(4),empty_tree,out_error)||
        !SerializeTree(metadata_records,meta_shape,AppleBtreeKeyOrder::FileSystemCaseSensitive,nx.block_size,nx.next_xid,
            volume.snapshot_metadata_tree->object_id,first_child_oid,meta_blocks,meta_tree,out_error)||
        !SerializeTree(snapshot_map_records,snap_shape,AppleBtreeKeyOrder::SnapshotObjectMap,nx.block_size,nx.next_xid,1,2,snapshot_blocks,snapshot_map_tree,out_error))return false;
    AppendTreeWrites(empty_tree,writes);AppendTreeWrites(meta_tree,writes);AppendTreeWrites(snapshot_map_tree,writes);
    if(!SnapshotMetadataMappings(source,map_records,old_metadata_ids,*volume.snapshot_metadata_tree,
            first_child_oid,meta_count,nx.next_xid,nx.block_size,&meta_tree,out_error)||
        !SerializeTree(map_records,map_shape,AppleBtreeKeyOrder::ObjectMap,nx.block_size,nx.next_xid,1,2,
            map_blocks,new_map_tree,out_error))return false;
    AppendTreeWrites(new_map_tree,writes);
    std::vector<std::byte> new_map;
    if(!PatchAppleObjectMap(omap,blocks[2],nx.next_xid,new_map_tree.root_physical_block,new_map,out_error))return false;
    put(new_map,0x24,inventory.size()+1,4);put(new_map,0x2C,catalog::kObjectPhysical|catalog::kObjectTypeBtree,4);
    put(new_map,0x38,snapshot_map_tree.root_physical_block);put(new_map,0x40,nx.next_xid);
    if(!FinalizeAppleObjectChecksum(new_map,out_error))return false;
    writes.push_back({blocks[2],std::move(new_map)});
    auto snapshot_apsb=apsb;
    put(snapshot_apsb,0x08,blocks[0]);put(snapshot_apsb,0x10,nx.next_xid);put(snapshot_apsb,0x18,catalog::kObjectPhysical|catalog::kObjectTypeFs,4);
    if(!FinalizeAppleObjectChecksum(snapshot_apsb,out_error))return false;
    writes.push_back({blocks[0],std::move(snapshot_apsb)});
    AppleVolumeAccountingUpdate accounting;
    accounting.xid=nx.next_xid;accounting.object_map_object_id=blocks[2];accounting.root_tree_object_id=volume.superblock.root_oid;
    accounting.extentref_tree_object_id=blocks[4];
    accounting.snapshot_metadata_tree_object_id=meta_shape.storage_type==catalog::kObjectPhysical ?
        meta_tree.root_physical_block : volume.superblock.snap_meta_tree_oid;
    accounting.next_object_id=next_volume_oid;accounting.file_count=volume.superblock.file_count;
    accounting.directory_count=volume.superblock.directory_count;accounting.symlink_count=catalog::ReadU64LE(apsb,0xC8).value();
    accounting.other_object_count=catalog::ReadU64LE(apsb,0xD0).value();accounting.snapshot_count=inventory.size()+1;
    accounting.file_system_allocated_blocks=allocated;accounting.total_blocks_freed=catalog::ReadU64LE(apsb,0xE8).value();
    if(!AdjustCount(catalog::ReadU64LE(apsb,0xE0).value(),static_cast<std::int64_t>(new_volume_blocks),accounting.total_blocks_allocated))return Fail(out_error,"AppleSnapshotCreateAccountingOverflow");
    accounting.last_modification_time=request.creation_time_ns;
    std::vector<std::byte> live_apsb;
    if(!PatchAppleVolumeSuperblock(apsb,accounting,live_apsb,out_error))return false;
    writes.push_back({blocks[1],std::move(live_apsb)});
    RemoveOmapRecords(container_records,{request.volume_object_id});
    if(!AddOmapRecord(container_records,request.volume_object_id,nx.next_xid,blocks[1],nx.block_size,out_error)||
        !SerializeTree(container_records,container_shape,AppleBtreeKeyOrder::ObjectMap,nx.block_size,nx.next_xid,1,2,
            container_blocks,new_container_tree,out_error))return false;
    AppendTreeWrites(new_container_tree,writes);
    std::vector<std::byte> new_container;
    if(!PatchAppleObjectMap(container_omap,blocks[3],nx.next_xid,new_container_tree.root_physical_block,new_container,out_error))return false;
    writes.push_back({blocks[3],std::move(new_container)});
    AppleTransactionCommitRequest commit;
    commit.allocation_plan=plan.allocation;commit.container_object_map_oid=blocks[3];commit.allocated_main_writes=writes;
    commit.required_checkpoint_xids=request.required_checkpoint_xids;commit.next_object_id=nx.next_oid;
    for(const auto& w:plan.allocation.writes)if(w.object_location)commit.next_object_id=(std::max)(commit.next_object_id,w.object_location->object_id+1);
    catalog::ApfsSnapshotIdentity created;
    created.scope=scope;created.scope.checkpoint_xid=nx.next_xid;created.snapshot_xid=nx.next_xid;created.name_utf8=request.name_utf8;
    created.superblock_physical_block=blocks[0];created.omap_physical_block=volume.object_map.object.physical_block;
    created.omap_tree_physical_block=volume.object_map.tree.physical_block;created.root_oid=volume.root_tree.object_id;
    created.root_physical_block=volume.root_tree.physical_block;created.extentref_physical_block=volume.extentref_tree->physical_block;
    AppleSnapshotInventoryChange change;change.created=created;
    if(!PlanAppleSnapshotRetirementCandidate(source,checkpoint,commit,&change,plan.commit.publication,out_error))return false;
    if(!FinalizeSnapshotRetirement(source,checkpoint,request.volume_object_id,allocation_request,
        commit,&change,plan.commit,plan.allocation,out_error))return false;
    SnapshotPublicationSource staged(source,plan.commit.publication);
    auto staged_checkpoint=catalog::LoadAppleCheckpointView(staged,0,staged.SizeBytes(),out_error);
    AppleSnapshotRetentionView proof;
    if(!staged_checkpoint || !LoadAppleSnapshotRetention(staged,*staged_checkpoint,proof,out_error))return false;
    if(proof.identities.size()!=existing.identities.size()+1 ||
        std::find(proof.identities.begin(),proof.identities.end(),created)==proof.identities.end())
        return Fail(out_error,"AppleSnapshotCreateStagedIdentityMismatch");
    // Bind every old metadata preimage which the snapshot will retain, including
    // sibling reserve evidence. Newly allocated blocks have no old preimage.
    guards.insert(guards.end(),proof.metadata_blocks.begin(),proof.metadata_blocks.end());
    for(const auto& peer:checkpoint.volumes)guards.push_back(peer.superblock_object.physical_block);
    for(const auto block:guards)if(std::find(blocks.begin(),blocks.end(),block)==blocks.end()&&
        !AddGuard(source,block,nx.block_size,plan.commit.publication.guard_blocks))return Fail(out_error,"AppleSnapshotCreateGuardUnreadable");
    plan.identity=created;out_plan=std::move(plan);return true;
}
catch(const std::bad_alloc&){out_plan={};if(source.ReadBudget())source.ReadBudget()->Refuse("ApfsReadBudgetAllocationFailed");return Fail(out_error,"ApfsReadBudgetAllocationFailed");}
catch(const std::length_error&){out_plan={};if(source.ReadBudget())source.ReadBudget()->Refuse("ApfsReadBudgetAllocationFailed");return Fail(out_error,"ApfsReadBudgetAllocationFailed");}

bool PlanFusionSnapshotCreate(const catalog::ApfsFusionStore& store,
    const AppleSnapshotCreateRequest& request,
    AppleSnapshotCreatePlan& out_plan, std::string& out_error) try
{
    out_plan={};out_error.clear();
    // Fail fast on malformed requests without touching the store: empty or
    // oversized names, embedded NULs, zero timestamps, and out-of-mask inums
    // never need I/O. (Mirrors PlanAppleSnapshotCreate's request shape gate.)
    if (request.name_utf8.empty() || request.name_utf8.size() > 255 ||
        request.name_utf8.find('\0') != std::string::npos || !request.creation_time_ns ||
        request.snapshot_inum > kFsObjectIdMask)
        return Fail(out_error, "AppleSnapshotCreateRequestInvalid");
    std::string store_error;
    if (!store.CheckAvailable(store_error))
        return Fail(out_error, "AppleFusionSnapshotStoreUnavailable");
    // The planner needs the rich Apple view (omap, spaceman, volumes), loaded
    // here from the store itself so no detached caller view is trusted. Reads
    // route through the encoded address space; the tier gap is unreadable by
    // construction and fails closed, never selected.
    auto apple = catalog::LoadAppleCheckpointView(store, 0, store.SizeBytes(),
        store_error, store.Checkpoint().superblock.xid);
    if (!apple.has_value())
    {
        // Budget exhaustion during the Apple load is a dead store, not a
        // corrupt checkpoint: report StoreUnavailable so callers fail closed
        // on allowance, matching the exhausted-budget entry gate.
        std::string availability;
        if (!store.CheckAvailable(availability))
            return Fail(out_error, "AppleFusionSnapshotStoreUnavailable");
        return Fail(out_error, "AppleFusionSnapshotCheckpointUnloadable");
    }
    AppleSnapshotCreatePlan plan;
    if (!PlanAppleSnapshotCreate(store, *apple, request, plan, out_error, true))
        return false;
    if (!FinalizeFusionCheckpointPublication(store, plan.commit.publication, out_error))
        return false;
    out_plan = std::move(plan);
    return true;
}
catch(const std::bad_alloc&){out_plan={};return Fail(out_error,"ApfsReadBudgetAllocationFailed");}
catch(const std::length_error&){out_plan={};return Fail(out_error,"ApfsReadBudgetAllocationFailed");}

bool FinalizeFusionCheckpointPublication(const catalog::ApfsFusionStore& store,
    AppleCheckpointPublicationPlan& out_publication, std::string& out_error) try
{
    out_error.clear();
    std::string store_error;
    if (!store.CheckAvailable(store_error))
        return Fail(out_error, "AppleFusionSnapshotStoreUnavailable");
    const auto bs = store.Checkpoint().superblock.block_size;
    if (!bs || (bs & (bs - 1)) || bs < 4096 || bs > 65536)
        return Fail(out_error, "AppleFusionSnapshotBlockGeometryInvalid");
    // Checkpoint-kind writes must be main-local: only allocator-owned payload
    // may address the second tier. Anything else is a planner/store
    // disagreement and refuses before publication. Mirrors the bind rule,
    // including the block-zero exclusion.
    const auto main_blocks = store.Members()[0].total_blocks;
    if (!main_blocks) return Fail(out_error, "AppleFusionSnapshotMemberGeometryInvalid");
    const auto main_local = [&](std::uint64_t block, std::uint64_t count) {
        return count && block && block < main_blocks && count <= main_blocks - block; };
    for (const auto& write : out_publication.before_superblock_writes)
    {
        if (write.bytes.empty() || write.bytes.size() % bs)
            return Fail(out_error, "AppleFusionSnapshotWriteShapeInvalid");
        const auto count = write.bytes.size() / bs;
        if (write.kind != AppleCheckpointWriteKind::AllocatorOwned &&
            !main_local(write.physical_block, count))
            return Fail(out_error, "AppleFusionSnapshotCheckpointNotMainLocal");
    }
    const auto staged_bs = out_publication.superblock_write.bytes.size();
    if (out_publication.block_size != bs || staged_bs != bs)
        return Fail(out_error, "AppleFusionSnapshotBlockGeometryInvalid");
    const auto& staged = out_publication.superblock_write;
    if (staged.kind != AppleCheckpointWriteKind::CheckpointSuperblock ||
        !main_local(staged.physical_block, 1))
        return Fail(out_error, "AppleFusionSnapshotCheckpointNotMainLocal");
    // Tier-2 anchor mirror: the staged main anchor with the tier role bit,
    // re-checksummed. The source byte must carry the clear main role bit and
    // the bound fusion UUID; anything else is not the canonical main anchor.
    auto mirror = staged.bytes;
    const auto& fusion_uuid = store.Checkpoint().superblock.fusion_uuid;
    for (std::size_t i = 0; i < 15; ++i)
        if (mirror[0x500 + i] != fusion_uuid[i])
            return Fail(out_error, "AppleFusionSnapshotAnchorUuidMismatch");
    if (mirror[0x50F] != fusion_uuid[15] || (mirror[0x50F] & std::byte{1}) != std::byte{0})
        return Fail(out_error, "AppleFusionSnapshotAnchorUuidMismatch");
    mirror[0x50F] |= std::byte{1};
    if (!FinalizeAppleObjectChecksum(mirror, out_error)) return false;
    AppleCheckpointPlannedWrite anchor;
    anchor.kind = AppleCheckpointWriteKind::FusionTier2Anchor;
    anchor.physical_block = catalog::kFusionTier2ByteAddress / bs;
    anchor.object_id = staged.object_id;
    anchor.bytes = std::move(mirror);
    out_publication.fusion_tier2_anchor_write = std::move(anchor);
    return true;
}
catch(const std::bad_alloc&){return Fail(out_error,"ApfsReadBudgetAllocationFailed");}
catch(const std::length_error&){return Fail(out_error,"ApfsReadBudgetAllocationFailed");}

#include "FusionVolumePlanning.inc"

static bool PlanAppleVolumeTransactionImpl(
    const catalog::RandomAccessSource& source,
    const catalog::AppleCheckpointView& checkpoint,
    const AppleVolumeTransactionRequest& request,
    AppleVolumeTransactionPlan& out_plan, std::string& out_error, bool snapshot_profile,
    bool preserve_sibling_snapshots = false, FusionVolumePlanning* fusion = nullptr,
    const BackupImageWriterAdmission* backup = nullptr,
    std::size_t exact_extentref_nodes = 0, unsigned extentref_replans = 0,
    const AppleCloneRangeMapping* clone_range = nullptr, bool metadata_only_snapshot = false,
    bool compact_plain_layout = false,
    const std::span<const std::uint64_t>* capacity_bytes = nullptr)
{
    out_plan = {};
    out_error.clear();
    if (capacity_bytes && capacity_bytes->size() != request.data_writes.size())
        return Fail(out_error, "AppleCapacityPreviewGeometryInvalid");
    const auto data_size = [&](const AppleVolumeDataWrite& data) -> std::uint64_t {
        return capacity_bytes ? (*capacity_bytes)[&data - request.data_writes.data()] : data.bytes.size();
    };
    const auto& nxsb = checkpoint.container.superblock;
    if (request.volume_object_id == 0 || request.filesystem_records.empty() ||
        nxsb.next_xid == 0 || nxsb.block_size == 0)
    {
        return Fail(out_error, "AppleVolumeTransactionRequestInvalid");
    }
    const auto volume_it = std::find_if(checkpoint.volumes.begin(),
        checkpoint.volumes.end(), [&request](const auto& volume) {
            return volume.superblock.object_id == request.volume_object_id;
        });
    if (volume_it == checkpoint.volumes.end())
    {
        return Fail(out_error, "AppleVolumeTransactionVolumeMissing");
    }
    const auto& volume = *volume_it;
    if (metadata_only_snapshot && (fusion || backup || clone_range ||
        !request.preserve_source_metadata || request.volume_reserve_quota ||
        !request.data_writes.empty() || !request.clones.empty() ||
        !request.compression_rewrites.empty() || !request.released_data_blocks.empty() ||
        request.file_count_delta || request.directory_count_delta || request.symlink_count_delta ||
        request.other_object_count_delta || request.last_modification_time))
        return Fail(out_error, "AppleSnapshotMetadataOperationUnsupported");
    const bool preserve_container_snapshots = snapshot_profile || (preserve_sibling_snapshots &&
        std::any_of(checkpoint.volumes.begin(), checkpoint.volumes.end(), [](const auto& peer) {
            return peer.object_map.snapshot_tree_oid != 0;
        }));
    if (request.preserve_source_metadata) {
        if (!request.data_writes.empty() || !request.clones.empty() || !request.compression_rewrites.empty() ||
            !request.released_data_blocks.empty())
            return Fail(out_error, "ApplePreservingMetadataDataMutationUnsupported");
        for (const auto& queue : checkpoint.spaceman.free_queues)
            for (const auto& entry : queue.entries)
                if (entry.xid <= 1) return Fail(out_error, "ApplePreservingMetadataQueueFloorUnsupported");
    }
    if (!CheckAppleVolumeWriteFeatures(nxsb, volume.superblock, out_error, fusion != nullptr))
    {
        if (!backup || &checkpoint != &backup->checkpoint || !snapshot_profile || fusion ||
            volume.superblock.role_raw != 0x0180) return false;
        out_error.clear();
    }
    if (checkpoint.container_object_map.flags != 1u ||
        std::any_of(checkpoint.volumes.begin(), checkpoint.volumes.end(),
            [](const auto& peer) { return peer.object_map.flags != 0; }))
        return Fail(out_error, "AppleVolumeTransactionOmapRoleFlagsUnsupported");
    // One verified checkpoint supplies the entire shared pool and volume set.
    // Projection failures are structural evidence/accounting errors, never a
    // clean quota/reserve refusal. Its available value is a reporting bound;
    // admission below uses the actual allocator delta, including COW overhead.
    catalog::ApfsSharedSpaceProjection shared_space;
    if (!(fusion ? FusionSharedSpace(checkpoint, shared_space, out_error) :
            catalog::TryProjectAppleSharedSpace(checkpoint, shared_space, out_error)))
        return false;
    const auto selected_space = std::find_if(shared_space.volumes.begin(),
        shared_space.volumes.end(), [&request](const auto& space) {
            return space.object_id == request.volume_object_id;
        });
    if (selected_space == shared_space.volumes.end())
        return Fail(out_error, "AppleVolumeTransactionVolumeMissing");
    if (request.volume_reserve_quota) {
        auto revised = checkpoint;
        for (auto& v : revised.volumes) if (v.superblock.object_id == request.volume_object_id) {
            v.superblock.space.reserve_block_count = request.volume_reserve_quota->first;
            v.superblock.space.quota_block_count = request.volume_reserve_quota->second;
            if (v.superblock.space.quota_block_count &&
                v.superblock.space.quota_block_count < v.superblock.space.allocated_block_count)
                return Fail(out_error, "AppleVolumeQuotaExceeded");
        }
        catalog::ApfsSharedSpaceProjection proposed;
        if (!catalog::TryProjectAppleSharedSpace(revised, proposed, out_error)) return false;
        const auto limits = std::find_if(proposed.volumes.begin(), proposed.volumes.end(),
            [&](const auto& v) { return v.object_id == request.volume_object_id; });
        *selected_space = *limits;
    }
    if ((volume.root_tree.type & catalog::kObjectStorageTypeMask) != 0)
    {
        return Fail(out_error, "AppleVolumeTransactionRootStorageUnsupported");
    }

    std::vector<std::byte> apsb_bytes;
    std::vector<std::byte> volume_omap_bytes;
    std::vector<std::byte> container_omap_bytes;
    if (!ReadObject(source, volume.superblock_object, nxsb.block_size,
            apsb_bytes) ||
        !ReadObject(source, volume.object_map.object, nxsb.block_size,
            volume_omap_bytes) ||
        !ReadObject(source, checkpoint.container_object_map.object,
            nxsb.block_size, container_omap_bytes))
    {
        return Fail(out_error, "AppleVolumeTransactionObjectReadFailed");
    }
    if (catalog::ReadU32LE(container_omap_bytes, 0x20) != 1u ||
        catalog::ReadU32LE(volume_omap_bytes, 0x20) != 0u)
        return Fail(out_error, "AppleVolumeTransactionOmapRoleFlagsChanged");
    // Reuse the authoritative APSB parser to bind the typed counters to source
    // evidence. Retain sibling evidence as publication guards as well: a plan
    // must not publish after a sibling's reserve/identity changes in place.
    std::vector<AppleCheckpointGuardBlock> space_guards;
    for (const auto& peer : checkpoint.volumes)
    {
        const auto& expected = peer.superblock;
        std::vector<std::byte> peer_bytes;
        const bool selected = expected.object_id == request.volume_object_id;
        if (!selected && !ReadObject(source, peer.superblock_object,
                nxsb.block_size, peer_bytes))
            return Fail(out_error, "AppleVolumeSpaceEvidenceChanged");
        const auto parsed = catalog::ParseApsb(selected ? apsb_bytes : peer_bytes);
        if (!parsed || parsed->object_id != expected.object_id ||
            parsed->xid != expected.xid || parsed->uuid_hex != expected.uuid_hex ||
            parsed->space.allocated_block_count != expected.space.allocated_block_count ||
            parsed->space.quota_block_count != expected.space.quota_block_count ||
            parsed->space.reserve_block_count != expected.space.reserve_block_count)
            return Fail(out_error, "AppleVolumeSpaceEvidenceChanged");
        if (!selected)
        {
            std::vector<std::byte> peer_omap_bytes;
            if (!ReadObject(source, peer.object_map.object, nxsb.block_size, peer_omap_bytes) ||
                catalog::ReadU32LE(peer_omap_bytes, 0x20) != 0u)
                return Fail(out_error, "AppleVolumeTransactionOmapRoleFlagsChanged");
            space_guards.push_back({peer.object_map.object.physical_block, std::move(peer_omap_bytes)});
            space_guards.push_back({peer.superblock_object.physical_block, std::move(peer_bytes)});
        }
    }
    const auto snapshot_count =
        catalog::ReadU64LE(apsb_bytes, 0xD8).value_or(
            std::numeric_limits<std::uint64_t>::max());
    std::vector<catalog::BtreeRecord> snapshot_records;
    std::vector<std::uint64_t> snapshot_blocks;
    if (volume.snapshot_metadata_tree.has_value() &&
        (!ReadTreeRecords(source, volume.snapshot_metadata_tree.value(),
             nxsb.block_size, volume.superblock.omap_oid, nxsb.xid,
             snapshot_records, snapshot_blocks, out_error) ||
         (!snapshot_profile && !snapshot_records.empty())))
    {
        return Fail(out_error, "AppleVolumeSnapshotsUnsupported");
    }
    if ((!snapshot_profile && (snapshot_count != 0 || volume.object_map.snapshot_tree_oid != 0)) ||
        checkpoint.container_object_map.snapshot_tree_oid != 0)
    {
        return Fail(out_error, "AppleVolumeSnapshotsUnsupported");
    }

    AppleSnapshotRetentionView snapshot_retention;
    std::shared_ptr<const std::vector<SnapshotRetentionCatalog>> snapshot_catalogs;
    const SnapshotRetentionCatalog* completed = nullptr;
    std::vector<ApplePhysicalExtentRecord> snapshot_prior, snapshot_history;
    if (preserve_container_snapshots &&
        !LoadSnapshotPlanningRetentionCatalogs(source, checkpoint, snapshot_retention, snapshot_catalogs, out_error)) return false;
    if (snapshot_catalogs) {
        const auto found = std::find_if(snapshot_catalogs->begin(), snapshot_catalogs->end(),
            [&](const auto& catalog) { return catalog.volume_oid == request.volume_object_id; });
        if (found != snapshot_catalogs->end()) completed = &*found;
    }
    if (snapshot_profile) {
        if (!snapshot_count) return Fail(out_error,"AppleSnapshotLiveInventoryMissing");
        if (completed) {
            // These exact layers and their ownership were already validated by
            // the invocation's source-bound retention graph.
            for (const auto& payload : completed->snapshot_payloads) {
                if (!source.ReadBudget()->Materialize(payload.size(), payload.size() * sizeof(ApplePhysicalExtentRecord)))
                    return Fail(out_error, source.ReadBudget()->Failure());
                snapshot_history.insert(snapshot_history.end(), payload.begin(), payload.end());
            }
            if (!completed->snapshot_payloads.empty()) {
                const auto& last = completed->snapshot_payloads.back();
                if (!source.ReadBudget()->Materialize(last.size(), last.size() * sizeof(ApplePhysicalExtentRecord)))
                    return Fail(out_error, source.ReadBudget()->Failure());
                snapshot_prior = last;
            }
        } else {
            for (const auto& id : snapshot_retention.identities) {
                if (id.scope.volume_oid != request.volume_object_id) continue;
                catalog::ApfsSnapshotRecords records;
                if (!catalog::ApfsSnapshotStore::LoadExactResolvedRecords(source,id,records,out_error) ||
                    !ValidateApplePayloadExtentGraph(records.trees.filesystem,records.trees.extentref,
                        nxsb.block_size,nxsb.block_count,snapshot_prior,out_error)) return false;
                snapshot_history.insert(snapshot_history.end(),snapshot_prior.begin(),snapshot_prior.end());
            }
        }
    }

    if (volume.file_extent_tree.has_value())
    {
        std::vector<catalog::BtreeRecord> fext_records;
        std::vector<std::uint64_t> fext_blocks;
        if (!ReadTreeRecords(source, *volume.file_extent_tree, nxsb.block_size,
                volume.superblock.omap_oid, nxsb.xid, fext_records, fext_blocks, out_error) ||
            !fext_records.empty())
            return Fail(out_error, "AppleVolumeFileExtentTreeUnsupported");
    }

    TreeShape fs_shape;
    TreeShape extentref_shape;
    TreeShape volume_omap_shape;
    TreeShape container_omap_shape;
    if (!ReadTreeShape(source, volume.root_tree, nxsb.block_size, fs_shape) ||
        (volume.extentref_tree.has_value() &&
         !ReadTreeShape(source, volume.extentref_tree.value(),
             nxsb.block_size, extentref_shape)) ||
        !ReadTreeShape(source, volume.object_map.tree, nxsb.block_size,
            volume_omap_shape) ||
        !ReadTreeShape(source, checkpoint.container_object_map.tree,
            nxsb.block_size, container_omap_shape))
    {
        return Fail(out_error, "AppleVolumeTransactionTreeShapeInvalid");
    }
    if (volume.extentref_tree.has_value() &&
        (extentref_shape.storage_type != catalog::kObjectPhysical ||
         extentref_shape.subtype != catalog::kObjectTypeBlockRefTree))
    {
        return Fail(out_error, "AppleVolumeExtentReferenceTreeInvalid");
    }

    std::vector<catalog::BtreeRecord> old_fs_storage;
    std::vector<std::uint64_t> old_fs_blocks_storage;
    const auto& old_fs_records = completed ? completed->records.live.filesystem : old_fs_storage;
    const auto& old_fs_blocks = completed ? completed->records.live.filesystem_blocks : old_fs_blocks_storage;
    std::vector<catalog::BtreeRecord> old_extentref_records;
    std::vector<std::uint64_t> old_extentref_blocks;
    std::vector<catalog::BtreeRecord> volume_omap_records;
    std::vector<std::uint64_t> old_volume_omap_blocks;
    std::vector<catalog::BtreeRecord> container_omap_records;
    std::vector<std::uint64_t> old_container_omap_blocks;
    if ((!completed && !ReadTreeRecords(source, volume.root_tree, nxsb.block_size,
            volume.superblock.omap_oid, nxsb.xid, old_fs_storage,
            old_fs_blocks_storage, out_error)) ||
        (volume.extentref_tree.has_value() &&
         !ReadTreeRecords(source, volume.extentref_tree.value(),
             nxsb.block_size, 0, nxsb.xid, old_extentref_records,
             old_extentref_blocks, out_error)) ||
        !ReadTreeRecords(source, volume.object_map.tree, nxsb.block_size,
            0, nxsb.xid, volume_omap_records, old_volume_omap_blocks,
            out_error) ||
        !ReadTreeRecords(source, checkpoint.container_object_map.tree,
            nxsb.block_size, 0, nxsb.xid, container_omap_records,
            old_container_omap_blocks, out_error))
    {
        return false;
    }

    if (snapshot_profile) {
        std::vector<ApplePhysicalExtentRecord> resolved_storage;
        if (!completed && !ResolveAppleSnapshotExtentLayer(snapshot_prior,snapshot_history,old_fs_records,old_extentref_records,
            nxsb.block_size,nxsb.block_count,resolved_storage,out_error)) return false;
        const auto& resolved = completed ? completed->live_payload : resolved_storage;
        if (!source.ReadBudget()->Materialize(resolved.size(), resolved.size() * (sizeof(catalog::BtreeRecord) + 28)))
            return Fail(out_error, source.ReadBudget()->Failure());
        old_extentref_records.clear();
        for (const auto& extent : resolved) {
            catalog::BtreeRecord record;
            if (!EncodeApplePhysicalExtentRecord(extent,record,out_error)) return false;
            old_extentref_records.push_back(std::move(record));
        }
    }
    if (metadata_only_snapshot && !SameRecords(request.filesystem_records, old_fs_records))
        return Fail(out_error, "AppleSnapshotMetadataFilesystemChanged");
    if (capacity_bytes) {
        const auto content_dependent = [](const auto& records) {
            std::unordered_set<std::uint64_t> inodes;
            for (const auto& record : records) {
                if ((catalog::ReadU64LE(record.key, 0).value_or(0) >> 60) != 3) continue;
                AppleInodeRecord inode; std::string error;
                if (!ApfsExtendedRecordCodec::DecodeInode(record, inode, error) ||
                    !inodes.insert(inode.object_id).second ||
                    (inode.bsd_flags & kAppleBsdCompressedFlag) ||
                    (inode.internal_flags & kAppleInodeSparseFlag) ||
                    (inode.mode & 0170000) == 0120000) return true;
            }
            std::set<std::pair<std::uint64_t, std::string>> attributes;
            for (const auto& record : records) {
                const auto type = catalog::ReadU64LE(record.key, 0).value_or(0) >> 60;
                if (type == 4) {
                    AppleXattrRecord attribute; std::string error;
                    if (!ApfsExtendedRecordCodec::DecodeXattr(record, attribute, error) ||
                        attribute.flags != kAppleXattrDataEmbedded ||
                        !inodes.contains(attribute.object_id) ||
                        !attributes.emplace(attribute.object_id, attribute.name_utf8).second) return true;
                    if (attribute.name_utf8 == "com.apfsaccess.windows.attributes") {
                        std::uint32_t attributes = 0;
                        if (!windows_metadata::DecodeAttributes(attribute.data, attributes)) return true;
                    } else if (attribute.name_utf8 == "com.apfsaccess.windows.security") {
                        if (!windows_metadata::ValidSecurityPayload(attribute.data)) return true;
                    } else return true;
                }
            }
            return false;
        };
        if (content_dependent(old_fs_records) || content_dependent(request.filesystem_records))
            return Fail(out_error, "AppleCapacityPreviewProfileUnsupported");
    }
    std::vector<catalog::BtreeRecord> requested_filesystem_records;
    std::map<std::uint64_t, std::uint64_t> clone_streams;
    if (!PrepareCloneRecords(old_fs_records, request, volume.superblock.next_object_id,
            nxsb.block_size, requested_filesystem_records, clone_streams, out_error)) return false;
    std::vector<FileExtentUse> old_file_extents;
    std::vector<FileExtentUse> removed_file_extents;
    if (!CollectFileExtentChanges(old_fs_records,
            requested_filesystem_records, nxsb.block_size, old_file_extents,
            removed_file_extents, out_error, clone_streams, false, false, clone_range))
    {
        return false;
    }
    if (!SameReleaseSet(removed_file_extents,
            request.released_data_blocks, nxsb.block_size))
    {
        return Fail(out_error, "AppleVolumeReleaseSetMismatch");
    }
    const bool rewrite_extentrefs =
        (snapshot_profile && !metadata_only_snapshot) || !removed_file_extents.empty() || !request.data_writes.empty() || !clone_streams.empty() || clone_range;
    if (rewrite_extentrefs && !volume.extentref_tree.has_value())
    {
        return Fail(out_error, "AppleVolumeExtentReferenceTreeMissing");
    }
    std::vector<PhysicalExtentState> physical_extents;
    std::vector<catalog::BtreeRecord> extentref_records;
    std::vector<AppleSpacemanReleaseRequest> data_releases;
    if (rewrite_extentrefs &&
        (!DecodePhysicalExtentTree(old_extentref_records, nxsb.block_count,
             physical_extents, out_error, fusion ? &fusion->store : nullptr) ||
         !ValidatePhysicalExtentCoverage(old_file_extents, physical_extents,
             nxsb.block_count, out_error, fusion ? &fusion->store : nullptr) ||
         !BuildRetainedPhysicalExtentRecords(physical_extents,
             removed_file_extents, requested_filesystem_records, nxsb.block_size, clone_streams,
             extentref_records, data_releases, out_error, clone_range)))
    {
        return false;
    }
    std::vector<catalog::BtreeRecord> normalized_filesystem_records;
    auto normalized_clones = clone_streams;
    if (clone_range) normalized_clones.emplace(clone_range->target_inode, clone_range->source_inode);
    if (!NormalizeDataStreamRecords(old_fs_records,
            requested_filesystem_records, old_file_extents,
            removed_file_extents, request.data_writes, nxsb.block_size, volume.superblock.next_object_id,
            request.compression_rewrites, source, nxsb.xid, request.volume_object_id, normalized_clones,
            normalized_filesystem_records, out_error))
    {
        return false;
    }
    if (metadata_only_snapshot) {
        const auto order = ApfsNamePolicy::FromIncompatibleFeatures(volume.superblock.incompatible_features).UsesHashedDirectoryKeys()
            ? AppleBtreeKeyOrder::FileSystemHashedDirectory : AppleBtreeKeyOrder::FileSystemCaseSensitive;
        if (!SortAppleBtreeRecords(normalized_filesystem_records, order, out_error) ||
            !SameRecords(normalized_filesystem_records, old_fs_records))
            return Fail(out_error, "AppleSnapshotMetadataNormalizationChanged");
    }
    std::unordered_set<std::uint64_t> old_fs_object_ids;
    if (fusion && fusion->object_id_profile == FusionObjectIdProfile::CompactedExtents &&
        (!fusion_compact::FileRecords(normalized_filesystem_records, nxsb.block_size, out_error, source.ReadBudget()) ||
         !fusion_compact::PhysicalRecords(extentref_records, out_error, source.ReadBudget()))) return false;
    if (!ReadTreeObjectIds(source, old_fs_blocks, nxsb.block_size,
            old_fs_object_ids))
    {
        return Fail(out_error, "AppleVolumeTransactionOldTreeInvalid");
    }

    std::uint64_t maximum_fs_oid = 0;
    for (const auto& record : normalized_filesystem_records)
    {
        if (record.key.size() < 8)
        {
            return Fail(out_error, "AppleVolumeTransactionRecordInvalid");
        }
        maximum_fs_oid = (std::max)(maximum_fs_oid,
            catalog::ReadU64LE(record.key, 0).value_or(0) & kFsObjectIdMask);
    }

    ExternalStreamOwners requested_external_owners;
    if (!CollectExternalStreamOwners(normalized_filesystem_records, requested_external_owners, out_error)) return false;
    plain_compact::Owners compact_owners;
    if (compact_plain_layout && !snapshot_profile && !fusion && !backup && !clone_range &&
        !request.preserve_source_metadata && request.clones.empty() && request.compression_rewrites.empty() &&
        requested_external_owners.empty() && checkpoint.spaceman.devices[1].block_count == 0 &&
        (volume.superblock.fs_flags & catalog::kFsFlagUnencrypted) &&
        std::none_of(checkpoint.volumes.begin(), checkpoint.volumes.end(), [](const auto& v) { return v.object_map.snapshot_tree_oid != 0; }))
        compact_owners = plain_compact::Eligible(old_fs_records, normalized_filesystem_records,
            old_extentref_records, request.data_writes, nxsb.block_size);
    // Mixed/ambiguous batches use the existing representation throughout.
    const bool compact_payload = !compact_owners.empty() &&
        std::all_of(request.data_writes.begin(), request.data_writes.end(), [&](const auto& data) {
            return compact_owners.contains(data.file_private_id);
        });
    std::size_t payload_block_count = 0;
    auto estimated_records = normalized_filesystem_records;
    for (const auto& data : request.data_writes)
    {
        if (data.file_private_id == 0 || data_size(data) == 0 ||
            data.logical_address % nxsb.block_size != 0 ||
            data_size(data) > std::numeric_limits<std::size_t>::max() -
                (nxsb.block_size - 1))
        {
            return Fail(out_error, "AppleVolumeTransactionDataInvalid");
        }
        maximum_fs_oid = (std::max)(maximum_fs_oid, data.file_private_id);
        const auto blocks =
            (data_size(data) + nxsb.block_size - 1) / nxsb.block_size;
        if (blocks > std::numeric_limits<std::size_t>::max() -
                payload_block_count)
        {
            return Fail(out_error, "AppleVolumeTransactionDataInvalid");
        }
        payload_block_count += blocks;
        if (compact_payload) continue;
        for (std::size_t ordinal = 0; ordinal < blocks; ++ordinal)
        {
            AppleFileExtentRecord extent;
            extent.object_id = data.file_private_id;
            extent.logical_address = data.logical_address +
                ordinal * static_cast<std::uint64_t>(nxsb.block_size);
            extent.length_bytes = nxsb.block_size;
            extent.physical_block = 1;
            extent.crypto_id = data.crypto_id;
            extent.block_size = nxsb.block_size;
            catalog::BtreeRecord encoded;
            if (!EncodeAppleFileExtentRecord(extent, encoded, out_error))
            {
                return false;
            }
            estimated_records.push_back(std::move(encoded));
        }
    }
    if (snapshot_profile) {
        const auto held=SnapshotHistoryUnion(snapshot_history);
        std::vector<AppleSpacemanReleaseRequest> releasable;
        for(const auto& range:data_releases){
            auto cursor=range.physical_block;const auto end=cursor+range.block_count;
            for(const auto& h:held){
                if(h.second<=cursor)continue;if(h.first>=end)break;
                if(h.first>cursor)releasable.push_back({cursor,h.first-cursor});
                cursor=(std::min)(end,(std::max)(cursor,h.second));
            }
            if(cursor<end)releasable.push_back({cursor,end-cursor});
        }
        data_releases=std::move(releasable);
    }
    std::vector<AppleSpacemanReleaseRequest> releases = data_releases;
    std::vector<AppleSpacemanReleaseRequest> volume_metadata_releases;
    if (!snapshot_profile && !request.preserve_source_metadata) {
    AddReleaseBlocks(volume_metadata_releases, old_fs_blocks);
    if (rewrite_extentrefs)
    {
        AddReleaseBlocks(volume_metadata_releases, old_extentref_blocks);
    }
    AddReleaseBlocks(volume_metadata_releases, old_volume_omap_blocks);
    volume_metadata_releases.push_back({volume.object_map.object.physical_block, 1});
    volume_metadata_releases.push_back({volume.superblock_object.physical_block, 1});
    // A sibling snapshot may retain shared OMAP roots and selected metadata.
    // Exclude those exact owned blocks before allocation, keeping volume charges.
    const auto held_metadata = [&](const AppleSpacemanReleaseRequest& range) {
        const auto block = std::lower_bound(snapshot_retention.metadata_blocks.begin(),
            snapshot_retention.metadata_blocks.end(), range.physical_block);
        return block != snapshot_retention.metadata_blocks.end() &&
            *block - range.physical_block < range.block_count;
    };
    volume_metadata_releases.erase(std::remove_if(volume_metadata_releases.begin(),
        volume_metadata_releases.end(), held_metadata), volume_metadata_releases.end());
    releases.insert(releases.end(), volume_metadata_releases.begin(), volume_metadata_releases.end());
    std::vector<AppleSpacemanReleaseRequest> container_metadata_releases;
    AddReleaseBlocks(container_metadata_releases, old_container_omap_blocks);
    container_metadata_releases.push_back({checkpoint.container_object_map.object.physical_block, 1});
    container_metadata_releases.erase(std::remove_if(container_metadata_releases.begin(),
        container_metadata_releases.end(), held_metadata), container_metadata_releases.end());
    releases.insert(releases.end(), container_metadata_releases.begin(), container_metadata_releases.end());
    }
    std::uint64_t released_block_count = 0;
    if (!SumReleasedBlocks(releases, released_block_count))
    {
        return Fail(out_error, "AppleVolumeTransactionReleaseInvalid");
    }
    std::uint64_t released_data_block_count = 0;
    if (!SumReleasedBlocks(data_releases,
            released_data_block_count))
    {
        return Fail(out_error, "AppleVolumeTransactionReleaseInvalid");
    }

    AppleSpacemanAllocationRequest allocation_request;
    allocation_request.expected_checkpoint_xid = nxsb.xid;
    allocation_request.transaction_xid = nxsb.next_xid;
    allocation_request.main_block_count = payload_block_count;
    allocation_request.first_ephemeral_object_id = nxsb.next_oid;
    allocation_request.released_blocks = releases;
    const bool retire_snapshot_metadata = preserve_container_snapshots && !request.preserve_source_metadata;
    if (retire_snapshot_metadata) allocation_request.released_blocks.clear();
    std::vector<AppleRecoveryCheckpointView> retained;
    const auto load_pins = preserve_container_snapshots ? LoadAppleSnapshotRecoveryCheckpoints : LoadAppleRecoveryCheckpoints;
    if (!fusion && !load_pins(source, checkpoint,
            request.required_checkpoint_xids, retained, out_error))
    {
        return false;
    }
    allocation_request.oldest_required_checkpoint_xid = nxsb.xid;
    for (const auto& old : retained)
    {
        allocation_request.oldest_required_checkpoint_xid = (std::min)(
            allocation_request.oldest_required_checkpoint_xid,
            old.checkpoint.container.superblock.xid);
        for (const auto& bitmap : old.checkpoint.spaceman.internal_pool.active_bitmaps)
        {
            allocation_request.protected_internal_pool_bitmap_indices.push_back(
                bitmap.rotation_index);
        }
    }
    if (request.preserve_source_metadata) allocation_request.oldest_required_checkpoint_xid = 1;
    if (!ConfigureSoftwareTransitionAllocation(source, checkpoint, allocation_request, out_error)) return false;

    std::vector<std::uint64_t> probed_payload_blocks;
    std::vector<catalog::BtreeRecord> compact_extentref_records;
    if (compact_payload) {
        // Allocation is pure and prefix-stable for identical retention/release
        // inputs. Size both trees from real runs, then prove the final prefix.
        AppleSpacemanAllocationPlan probe;
        if (!PlanAppleSpacemanAllocation(checkpoint.spaceman, allocation_request, probe, out_error)) return false;
        probed_payload_blocks = std::move(probe.allocated_main_blocks);
        compact_extentref_records = extentref_records;
        if (!plain_compact::AppendPayloadRecords(request.data_writes, probed_payload_blocks, compact_owners,
                nxsb.block_size, estimated_records, compact_extentref_records, out_error, capacity_bytes) ||
            !plain_compact::Coalesce(estimated_records, compact_extentref_records, compact_owners,
                nxsb.block_size, out_error, source.ReadBudget())) return false;
    }

    if (maximum_fs_oid == kFsObjectIdMask)
    {
        return Fail(out_error, "AppleVolumeTransactionObjectIdExhausted");
    }
    const auto old_next_oid =
        catalog::ReadU64LE(apsb_bytes, 0xB0).value_or(0);
    auto first_child_oid = (std::max)(old_next_oid,
        maximum_fs_oid + 1);
    if (fusion && fusion->object_id_profile != FusionObjectIdProfile::Original &&
        !fusion_ids::Next(first_child_oid, volume.root_tree.object_id, old_fs_records,
            estimated_records, volume_omap_records, first_child_oid, out_error)) return false;
    const auto fs_order = fusion ? FusionFilesystemKeyOrder(*fusion, volume.superblock) :
        ApfsNamePolicy::FromIncompatibleFeatures(volume.superblock.incompatible_features).UsesHashedDirectoryKeys()
        ? AppleBtreeKeyOrder::FileSystemHashedDirectory
        : AppleBtreeKeyOrder::FileSystemCaseSensitive;

    AppleSerializedBtree estimated_fs_tree;
    if (!SerializeTree(estimated_records, fs_shape, fs_order,
            nxsb.block_size, nxsb.next_xid, volume.root_tree.object_id,
            first_child_oid, {}, estimated_fs_tree, out_error))
    {
        return false;
    }
    const auto fs_node_count = estimated_fs_tree.objects.size();
    if (fusion && fusion->object_id_profile != FusionObjectIdProfile::Original &&
        (fs_node_count == 0 || !fusion_ids::Range(first_child_oid, fs_node_count - 1, out_error))) return false;
    std::unordered_set<std::uint64_t> new_fs_oids;
    new_fs_oids.insert(volume.root_tree.object_id);
    for (std::size_t index = 0; index + 1 < fs_node_count; ++index)
    {
        new_fs_oids.insert(first_child_oid + index);
    }

    AppleSerializedBtree estimated_extentref_tree;
    std::size_t extentref_node_count = 0;
    if (rewrite_extentrefs)
    {
        if (nxsb.block_count > kFsObjectIdMask ||
            payload_block_count > kFsObjectIdMask - nxsb.block_count)
        {
            return Fail(out_error,
                "AppleVolumePhysicalExtentPlaceholderExhausted");
        }
        auto estimated_extentref_records = compact_payload ? compact_extentref_records : extentref_records;
        if (snapshot_profile && !PlanAppleSnapshotExtentLayer(snapshot_prior,snapshot_history,
            normalized_filesystem_records,extentref_records,nxsb.block_size,nxsb.block_count,
            estimated_extentref_records,out_error)) return false;
        auto placeholder_block = nxsb.block_count;
        for (const auto& data : request.data_writes)
        {
            if (compact_payload) break;
            const auto blocks =
                (data_size(data) + nxsb.block_size - 1) / nxsb.block_size;
            for (std::size_t ordinal = 0; ordinal < blocks; ++ordinal)
            {
                ApplePhysicalExtentRecord extent;
                extent.physical_block = placeholder_block++;
                extent.block_count = 1;
                extent.kind = kApplePhysicalExtentKindNew;
                extent.owning_object_id = PhysicalStreamOwner(requested_external_owners, data.file_private_id);
                extent.reference_count = 1;
                catalog::BtreeRecord encoded;
                if (!EncodeApplePhysicalExtentRecord(
                        extent, encoded, out_error))
                {
                    return false;
                }
                estimated_extentref_records.push_back(std::move(encoded));
            }
        }
        if (!SerializeTree(estimated_extentref_records, extentref_shape,
                AppleBtreeKeyOrder::PhysicalExtent, nxsb.block_size,
                nxsb.next_xid, volume.extentref_tree->object_id, 1, {},
                estimated_extentref_tree, out_error))
        {
            return false;
        }
        extentref_node_count = exact_extentref_nodes ? exact_extentref_nodes : estimated_extentref_tree.objects.size();
    }

    RemoveOmapRecords(volume_omap_records, old_fs_object_ids);
    for (const auto oid : new_fs_oids)
    {
        if (!AddOmapRecord(volume_omap_records, oid, nxsb.next_xid, 1,
                nxsb.block_size, out_error))
        {
            return false;
        }
    }
    AppleSerializedBtree estimated_volume_omap_tree;
    if (!SerializeTree(volume_omap_records, volume_omap_shape,
            AppleBtreeKeyOrder::ObjectMap, nxsb.block_size, nxsb.next_xid,
            1, 2, {}, estimated_volume_omap_tree, out_error))
    {
        return false;
    }

    RemoveOmapRecords(container_omap_records,
        std::unordered_set<std::uint64_t>{request.volume_object_id});
    if (!AddOmapRecord(container_omap_records, request.volume_object_id,
            nxsb.next_xid, 1, nxsb.block_size, out_error))
    {
        return false;
    }
    AppleSerializedBtree estimated_container_omap_tree;
    if (!SerializeTree(container_omap_records, container_omap_shape,
            AppleBtreeKeyOrder::ObjectMap, nxsb.block_size, nxsb.next_xid,
            1, 2, {}, estimated_container_omap_tree, out_error))
    {
        return false;
    }


    const auto volume_omap_node_count =
        estimated_volume_omap_tree.objects.size();
    const auto container_omap_node_count =
        estimated_container_omap_tree.objects.size();
    std::uint64_t new_volume_blocks = 0;
    std::uint64_t old_volume_blocks = 0;
    std::uint64_t removed_volume_blocks = 0;
    std::uint64_t total_main_blocks = 0;
    std::uint64_t resulting_allocated_blocks = 0;
    // The snapshot ownership graph assigns the live APSB to the container.
    // Keep its physical allocation while charging only the volume OMAP here.
    const std::uint64_t volume_objects = metadata_only_snapshot ? 1 : 2;
    const std::uint64_t container_objects = metadata_only_snapshot ? 2 : 1;
    if (!SumBlockCounts({payload_block_count, fs_node_count, extentref_node_count,
            volume_omap_node_count, volume_objects}, new_volume_blocks) ||
        !SumReleasedBlocks(volume_metadata_releases, old_volume_blocks) ||
        !SumBlockCounts({old_volume_blocks, released_data_block_count}, removed_volume_blocks) ||
        !SumBlockCounts({new_volume_blocks, container_omap_node_count, container_objects}, total_main_blocks) ||
        total_main_blocks > std::numeric_limits<std::size_t>::max() ||
        !ReplaceAllocationCount(selected_space->allocated.blocks,
            new_volume_blocks, removed_volume_blocks, resulting_allocated_blocks))
        return Fail(out_error, "AppleVolumeTransactionAccountingInvalid");
    allocation_request.main_block_count = static_cast<std::size_t>(total_main_blocks);
    AppleSpacemanAllocationPlan allocation;
    if (fusion) {
        allocation_request.main_block_count -= payload_block_count;
        FusionSpacemanAllocationPlan planned;
        if (fusion->allocation_profile == FusionAllocationProfile::RetainedOwners) {
            if (!PlanFusionReclaimingSpacemanAllocation(fusion->store,allocation_request,payload_block_count,
                    planned,fusion->reclamation_guards,out_error)) return false;
        } else if (!PlanFusionSpacemanAllocation(fusion->store,allocation_request,payload_block_count,planned,out_error)) return false;
        fusion->tier2_blocks = std::move(planned.allocated_tier2_blocks);
        allocation = std::move(planned.main);
    }
    else if (!PlanAppleSpacemanAllocation(checkpoint.spaceman,
            allocation_request, allocation, out_error))
    {
        return false;
    }
    std::vector<std::uint64_t> allocated_blocks;
    if (fusion) allocated_blocks = fusion->tier2_blocks;
    allocated_blocks.insert(allocated_blocks.end(), allocation.allocated_main_blocks.begin(), allocation.allocated_main_blocks.end());
    if (allocated_blocks.size() != total_main_blocks)
    {
        return Fail(out_error, "AppleVolumeTransactionAllocationInvalid");
    }
    if (compact_payload && !std::equal(probed_payload_blocks.begin(), probed_payload_blocks.end(), allocated_blocks.begin()))
        return Fail(out_error, "ApplePlainPayloadAllocationPrefixChanged");

    // A clean capacity refusal must not conceal a stale checkpoint/allocator.
    // Successful plans undergo the existing publication checkpoint checks.
    const auto refuse_capacity = [&](const char* reason) {
        if (fusion) return fusion->store.CheckAvailable(out_error) && Fail(out_error, reason);
        return VerifyAppleSpacemanOwnershipUnchanged(source, 0, source.SizeBytes(),
            checkpoint.container, checkpoint.spaceman, out_error) && Fail(out_error, reason);
    };
    // Charge net volume ownership to quota, not temporary COW ownership. An
    // already-over-quota volume can still shrink or perform a non-growing update.
    if (!retire_snapshot_metadata && selected_space->quota && resulting_allocated_blocks > selected_space->quota->blocks &&
        (request.volume_reserve_quota || resulting_allocated_blocks > selected_space->allocated.blocks))
        return refuse_capacity("AppleVolumeQuotaExceeded");
    const auto reusable_free = allocation.updated_spaceman.devices[0].free_count +
        (fusion ? allocation.updated_spaceman.devices[1].free_count : 0);
    if (reusable_free > shared_space.total.blocks ||
        resulting_allocated_blocks > shared_space.total.blocks - reusable_free)
        return Fail(out_error, "AppleVolumeTransactionAccountingInvalid");
    // This count includes only frees actually reclaimed by the allocator after
    // retention checks. Current releases and pinned old checkpoints stay charged.
    // Protect all siblings' unmet reserves once against the same remaining pool.
    if (!retire_snapshot_metadata && reusable_free < selected_space->sibling_reserve_remaining.blocks)
        return refuse_capacity("AppleVolumeSiblingReserveProtected");
    const auto own_unmet = selected_space->reserve &&
        selected_space->reserve->blocks > resulting_allocated_blocks
        ? selected_space->reserve->blocks - resulting_allocated_blocks : 0;
    // Temporary COW blocks cannot consume the remaining reserve promise and
    // leave a checkpoint that the next authoritative projection must reject.
    if (!retire_snapshot_metadata && own_unmet > reusable_free - selected_space->sibling_reserve_remaining.blocks)
        return refuse_capacity("AppleVolumeReserveCapacityProtected");

    std::size_t cursor = 0;
    std::vector<AppleCheckpointPhysicalWrite> writes;
    std::vector<catalog::BtreeRecord> filesystem_records =
        normalized_filesystem_records;
    std::vector<std::uint64_t> payload_blocks;
    payload_blocks.reserve(payload_block_count);
    for (const auto& data : request.data_writes)
    {
        const auto blocks =
            (data_size(data) + nxsb.block_size - 1) / nxsb.block_size;
        for (std::size_t ordinal = 0; ordinal < blocks; ++ordinal)
        {
            const auto physical_block =
                allocated_blocks[cursor++];
            payload_blocks.push_back(physical_block);
            if (!capacity_bytes) {
                std::vector<std::byte> bytes(nxsb.block_size, std::byte{0});
                const auto source_offset = ordinal * nxsb.block_size;
                const auto count = (std::min)(static_cast<std::size_t>(nxsb.block_size),
                    data.bytes.size() - source_offset);
                std::copy_n(data.bytes.begin() + static_cast<std::ptrdiff_t>(source_offset), count, bytes.begin());
                writes.push_back({physical_block, std::move(bytes)});
            }

            if (compact_payload) continue;

            AppleFileExtentRecord extent;
            extent.object_id = data.file_private_id;
            extent.logical_address = data.logical_address +
                ordinal * static_cast<std::uint64_t>(nxsb.block_size);
            extent.length_bytes = nxsb.block_size;
            extent.physical_block = physical_block;
            extent.crypto_id = data.crypto_id;
            extent.block_size = nxsb.block_size;
            catalog::BtreeRecord encoded;
            if (!EncodeAppleFileExtentRecord(extent, encoded, out_error))
            {
                return false;
            }
            filesystem_records.push_back(std::move(encoded));

            ApplePhysicalExtentRecord physical_extent;
            physical_extent.physical_block = physical_block;
            physical_extent.block_count = 1;
            physical_extent.kind = kApplePhysicalExtentKindNew;
            physical_extent.owning_object_id = PhysicalStreamOwner(requested_external_owners, data.file_private_id);
            physical_extent.reference_count = 1;
            catalog::BtreeRecord physical_record;
            if (!EncodeApplePhysicalExtentRecord(
                    physical_extent, physical_record, out_error))
            {
                return false;
            }
            extentref_records.push_back(std::move(physical_record));
        }
    }
    if (compact_payload) {
        filesystem_records = std::move(estimated_records);
        extentref_records = std::move(compact_extentref_records);
    }

    const auto fs_blocks_begin = allocated_blocks.begin() +
        static_cast<std::ptrdiff_t>(cursor);
    cursor += fs_node_count;
    const std::span<const std::uint64_t> fs_blocks(
        &*fs_blocks_begin, fs_node_count);
    AppleSerializedBtree fs_tree;
    if (!SerializeTree(filesystem_records, fs_shape, fs_order,
            nxsb.block_size, nxsb.next_xid, volume.root_tree.object_id,
            first_child_oid, fs_blocks, fs_tree, out_error))
    {
        return false;
    }
    AppendTreeWrites(fs_tree, writes);

    if (snapshot_profile && rewrite_extentrefs) {
        std::vector<catalog::BtreeRecord> layer;
        if (!PlanAppleSnapshotExtentLayer(snapshot_prior,snapshot_history,filesystem_records,extentref_records,
            nxsb.block_size,nxsb.block_count,layer,out_error)) return false;
        extentref_records=std::move(layer);
    }
    if (snapshot_profile && !fusion && !backup && rewrite_extentrefs) {
        // Snapshot layers coalesce actual adjacent allocations differently from
        // placeholder blocks. Replan before publication with the measured size.
        AppleSerializedBtree exact_extentref_tree;
        if (!SerializeTree(extentref_records, extentref_shape, AppleBtreeKeyOrder::PhysicalExtent,
                nxsb.block_size, nxsb.next_xid, volume.extentref_tree->object_id, 1, {},
                exact_extentref_tree, out_error)) return false;
        const auto nodes = exact_extentref_tree.objects.size();
        if (nodes != extentref_node_count) {
            if (!nodes || extentref_replans >= 4)
                return Fail(out_error, "AppleVolumeExtentrefPlanSizingUnstable");
            return PlanAppleVolumeTransactionImpl(source, checkpoint, request, out_plan, out_error,
                snapshot_profile, preserve_sibling_snapshots, fusion, backup, nodes, extentref_replans + 1, clone_range, metadata_only_snapshot);
        }
    }
    AppleSerializedBtree extentref_tree;
    if (rewrite_extentrefs)
    {
        const auto extentref_blocks_begin =
            allocated_blocks.begin() +
            static_cast<std::ptrdiff_t>(cursor);
        cursor += extentref_node_count;
        const std::span<const std::uint64_t> extentref_blocks(
            &*extentref_blocks_begin, extentref_node_count);
        if (!SerializeTree(extentref_records, extentref_shape,
                AppleBtreeKeyOrder::PhysicalExtent, nxsb.block_size,
                nxsb.next_xid, volume.extentref_tree->object_id, 1,
                extentref_blocks, extentref_tree, out_error))
        {
            return false;
        }
        AppendTreeWrites(extentref_tree, writes);
    }

    RemoveOmapRecords(volume_omap_records, new_fs_oids);
    for (const auto& object : fs_tree.objects)
    {
        if (!AddOmapRecord(volume_omap_records, object.location.object_id,
                nxsb.next_xid, object.location.physical_block,
                nxsb.block_size, out_error))
        {
            return false;
        }
    }
    const auto volume_omap_tree_begin =
        allocated_blocks.begin() +
        static_cast<std::ptrdiff_t>(cursor);
    cursor += volume_omap_node_count;
    const std::span<const std::uint64_t> volume_omap_tree_blocks(
        &*volume_omap_tree_begin, volume_omap_node_count);
    AppleSerializedBtree volume_omap_tree;
    if (!SerializeTree(volume_omap_records, volume_omap_shape,
            AppleBtreeKeyOrder::ObjectMap, nxsb.block_size, nxsb.next_xid,
            1, 2, volume_omap_tree_blocks, volume_omap_tree, out_error))
    {
        return false;
    }
    AppendTreeWrites(volume_omap_tree, writes);
    const auto volume_omap_block =
        allocated_blocks[cursor++];
    std::vector<std::byte> new_volume_omap;
    if (!PatchAppleObjectMap(volume_omap_bytes, volume_omap_block,
            nxsb.next_xid, volume_omap_tree.root_physical_block,
            new_volume_omap, out_error))
    {
        return false;
    }
    writes.push_back({volume_omap_block, new_volume_omap});

    const auto apsb_block = allocated_blocks[cursor++];
    AppleVolumeAccountingUpdate accounting;
    accounting.xid = nxsb.next_xid;
    accounting.object_map_object_id = volume_omap_block;
    accounting.root_tree_object_id = volume.superblock.root_oid;
    accounting.extentref_tree_object_id =
        rewrite_extentrefs ? extentref_tree.root_physical_block :
            volume.superblock.extentref_tree_oid;
    accounting.snapshot_metadata_tree_object_id =
        volume.superblock.snap_meta_tree_oid;
    accounting.next_object_id = first_child_oid + fs_node_count - 1;
    if (!AdjustCount(volume.superblock.file_count, request.file_count_delta,
            accounting.file_count) ||
        !AdjustCount(volume.superblock.directory_count,
            request.directory_count_delta, accounting.directory_count) ||
        !AdjustCount(catalog::ReadU64LE(apsb_bytes, 0xC8).value_or(0),
            request.symlink_count_delta, accounting.symlink_count) ||
        !AdjustCount(catalog::ReadU64LE(apsb_bytes, 0xD0).value_or(0),
            request.other_object_count_delta, accounting.other_object_count))
    {
        return Fail(out_error, "AppleVolumeTransactionAccountingInvalid");
    }
    accounting.snapshot_count = snapshot_count;
    accounting.file_system_allocated_blocks = resulting_allocated_blocks;
    const auto old_total_allocated =
        catalog::ReadU64LE(apsb_bytes, 0xE0).value_or(0);
    const auto old_total_freed =
        catalog::ReadU64LE(apsb_bytes, 0xE8).value_or(0);
    if (new_volume_blocks > std::numeric_limits<std::uint64_t>::max() -
            old_total_allocated ||
        removed_volume_blocks >
            std::numeric_limits<std::uint64_t>::max() - old_total_freed)
    {
        return Fail(out_error, "AppleVolumeTransactionAccountingInvalid");
    }
    accounting.total_blocks_allocated =
        old_total_allocated + new_volume_blocks;
    accounting.total_blocks_freed = old_total_freed + removed_volume_blocks;
    accounting.last_modification_time = request.last_modification_time != 0 ?
        request.last_modification_time :
        catalog::ReadU64LE(apsb_bytes, 0x100).value_or(0);
    std::vector<std::byte> new_apsb;
    if (!PatchAppleVolumeSuperblock(
            apsb_bytes, accounting, new_apsb, out_error))
    {
        return false;
    }
    writes.push_back({apsb_block, new_apsb});

    RemoveOmapRecords(container_omap_records,
        std::unordered_set<std::uint64_t>{request.volume_object_id});
    if (!AddOmapRecord(container_omap_records, request.volume_object_id,
            nxsb.next_xid, apsb_block, nxsb.block_size, out_error))
    {
        return false;
    }
    const auto container_omap_tree_begin =
        allocated_blocks.begin() +
        static_cast<std::ptrdiff_t>(cursor);
    cursor += container_omap_node_count;
    const std::span<const std::uint64_t> container_omap_tree_blocks(
        &*container_omap_tree_begin, container_omap_node_count);
    AppleSerializedBtree container_omap_tree;
    if (!SerializeTree(container_omap_records, container_omap_shape,
            AppleBtreeKeyOrder::ObjectMap, nxsb.block_size, nxsb.next_xid,
            1, 2, container_omap_tree_blocks, container_omap_tree,
            out_error))
    {
        return false;
    }
    AppendTreeWrites(container_omap_tree, writes);
    const auto container_omap_block =
        allocated_blocks[cursor++];
    std::vector<std::byte> new_container_omap;
    if (!PatchAppleObjectMap(container_omap_bytes, container_omap_block,
            nxsb.next_xid, container_omap_tree.root_physical_block,
            new_container_omap, out_error))
    {
        return false;
    }
    writes.push_back({container_omap_block, new_container_omap});
    if (cursor != allocated_blocks.size())
    {
        return Fail(out_error, "AppleVolumeTransactionAllocationInvalid");
    }

    OverlaySource staged(source, nxsb.block_size, writes);
    const auto mapped_apsb = catalog::ResolveOmapValue(staged,
        nxsb.block_size, container_omap_block, request.volume_object_id,
        nxsb.next_xid, out_error);
    const auto mapped_root = catalog::ResolveOmapValue(staged,
        nxsb.block_size, volume_omap_block, volume.root_tree.object_id,
        nxsb.next_xid, out_error);
    std::vector<catalog::BtreeRecord> round_trip_records;
    std::vector<std::uint64_t> round_trip_blocks;
    catalog::AppleObjectLocation staged_root = volume.root_tree;
    staged_root.xid = nxsb.next_xid;
    staged_root.physical_block = fs_tree.root_physical_block;
    if (!mapped_apsb.has_value() || mapped_apsb->physical_block != apsb_block ||
        !mapped_root.has_value() ||
        mapped_root->physical_block != fs_tree.root_physical_block ||
        !ReadTreeRecords(staged, staged_root, nxsb.block_size,
            volume_omap_block, nxsb.next_xid, round_trip_records,
            round_trip_blocks, out_error))
    {
        return Fail(out_error, "AppleVolumeTransactionRoundTripFailed");
    }
    auto expected_records = filesystem_records;
    if (!SortAppleBtreeRecords(expected_records, fs_order, out_error) ||
        !SortAppleBtreeRecords(round_trip_records, fs_order, out_error) ||
        !SameRecords(expected_records, round_trip_records))
    {
        return Fail(out_error, "AppleVolumeTransactionRoundTripFailed");
    }
    if (rewrite_extentrefs)
    {
        catalog::AppleObjectLocation staged_extentref =
            volume.extentref_tree.value();
        staged_extentref.object_id = extentref_tree.root_physical_block;
        staged_extentref.physical_block = extentref_tree.root_physical_block;
        staged_extentref.xid = nxsb.next_xid;
        std::vector<catalog::BtreeRecord> round_trip_extentrefs;
        std::vector<std::uint64_t> round_trip_extentref_blocks;
        auto expected_extentrefs = extentref_records;
        if (catalog::ReadU64LE(new_apsb, 0x90).value_or(0) !=
                extentref_tree.root_physical_block ||
            !ReadTreeRecords(staged, staged_extentref, nxsb.block_size, 0,
                nxsb.next_xid, round_trip_extentrefs,
                round_trip_extentref_blocks, out_error) ||
            !SortAppleBtreeRecords(expected_extentrefs,
                AppleBtreeKeyOrder::PhysicalExtent, out_error) ||
            !SortAppleBtreeRecords(round_trip_extentrefs,
                AppleBtreeKeyOrder::PhysicalExtent, out_error) ||
            !SameRecords(expected_extentrefs, round_trip_extentrefs))
        {
            return Fail(out_error,
                "AppleVolumeExtentReferenceRoundTripFailed");
        }
        if (snapshot_profile) {
            std::vector<ApplePhysicalExtentRecord> resolved;
            if (!ResolveAppleSnapshotExtentLayer(snapshot_prior,snapshot_history,filesystem_records,round_trip_extentrefs,
                nxsb.block_size,nxsb.block_count,resolved,out_error)) return false;
            round_trip_extentrefs.clear();
            for(const auto& extent:resolved){catalog::BtreeRecord r;if(!EncodeApplePhysicalExtentRecord(extent,r,out_error))return false;round_trip_extentrefs.push_back(std::move(r));}
        }
        std::vector<FileExtentUse> staged_file_extents;
        std::vector<FileExtentUse> staged_removed_extents;
        std::vector<PhysicalExtentState> staged_physical_extents;
        if (!CollectFileExtentChanges(filesystem_records,
                filesystem_records, nxsb.block_size, staged_file_extents,
                staged_removed_extents, out_error) ||
            !DecodePhysicalExtentTree(round_trip_extentrefs, nxsb.block_count,
                staged_physical_extents, out_error, fusion ? &fusion->store : nullptr) ||
            !ValidatePhysicalExtentCoverage(staged_file_extents,
                staged_physical_extents, nxsb.block_count, out_error, fusion ? &fusion->store : nullptr))
        {
            return Fail(out_error,
                "AppleVolumeExtentReferenceGraphInvalid");
        }
    }

    AppleTransactionCommitRequest commit_request;
    commit_request.allocation_plan = allocation;
    commit_request.container_object_map_oid = container_omap_block;
    commit_request.required_checkpoint_xids = request.required_checkpoint_xids;
    commit_request.allocated_main_writes = writes;
    commit_request.next_object_id = nxsb.next_oid;
    for (const auto& write : allocation.writes)
    {
        if (write.object_location.has_value() &&
            write.object_location->object_id >= commit_request.next_object_id)
        {
            commit_request.next_object_id =
                write.object_location->object_id + 1;
        }
    }
    AppleTransactionCommitPlan commit;
    const auto compose = preserve_container_snapshots ? PlanAppleSnapshotPreservingCommit : PlanAppleTransactionCommit;
    if (!(fusion ? ComposeFusionVolume(*fusion, source, checkpoint, commit_request, commit, out_error) :
        retire_snapshot_metadata ? PlanAppleSnapshotRetirementCandidate(source, checkpoint,
            commit_request, nullptr, commit.publication, out_error) :
        capacity_bytes ? capacity_detail::PlanCommit(source, checkpoint,
            commit_request, payload_blocks, commit, out_error) :
        compose(source, checkpoint, commit_request, commit, out_error)))
    {
        return false;
    }
    if (retire_snapshot_metadata && !FinalizeSnapshotRetirement(source, checkpoint,
            request.volume_object_id, allocation_request, commit_request, nullptr, commit, allocation, out_error))
        return false;
    for (auto& guard : space_guards)
        commit.publication.guard_blocks.push_back(std::move(guard));
    std::vector<std::uint64_t> guarded_blocks = old_fs_blocks;
    if (rewrite_extentrefs)
    {
        guarded_blocks.insert(guarded_blocks.end(),
            old_extentref_blocks.begin(), old_extentref_blocks.end());
    }
    guarded_blocks.insert(guarded_blocks.end(), old_volume_omap_blocks.begin(),
        old_volume_omap_blocks.end());
    guarded_blocks.push_back(volume.object_map.object.physical_block);
    guarded_blocks.push_back(volume.superblock_object.physical_block);
    guarded_blocks.insert(guarded_blocks.end(),
        old_container_omap_blocks.begin(), old_container_omap_blocks.end());
    guarded_blocks.push_back(
        checkpoint.container_object_map.object.physical_block);
    for (const auto block : guarded_blocks)
    {
        if (!AddGuard(source, block, nxsb.block_size,
                commit.publication.guard_blocks))
        {
            return Fail(out_error, "AppleVolumeTransactionGuardUnreadable");
        }
    }

    out_plan.allocation = std::move(allocation);
    out_plan.commit = std::move(commit);
    out_plan.payload_blocks = std::move(payload_blocks);
    out_plan.filesystem_records = std::move(filesystem_records);
    return true;
}

bool PlanAppleBackupImageTransaction(const catalog::RandomAccessSource& source,
    const catalog::AppleCheckpointView& expected, const AppleVolumeTransactionRequest& request,
    AppleVolumeTransactionPlan& out, std::string& error) try
{
    out = {};
    error.clear();
    if (!source.ReadBudget()) {
        auto budget = std::make_shared<catalog::ApfsReadBudget>(65536, 256ull << 20, 1000000, 256ull << 20);
        catalog::BudgetedRandomAccessSource bounded(source, budget);
        return PlanAppleBackupImageTransaction(bounded, expected, request, out, error);
    }
    if (request.volume_reserve_quota || request.preserve_source_metadata || !request.compression_rewrites.empty())
        return Fail(error, "BackupWriterOperationProfileUnsupported");
    SnapshotPlanningSource observed(source);
    BackupImageWriterAdmission admitted;
    AppleVolumeTransactionPlan candidate;
    if (!AdmitBackupImageWriter(observed, expected, request.volume_object_id, admitted, error) ||
        !PlanAppleVolumeTransactionImpl(observed, admitted.checkpoint, request, candidate, error, true, false, nullptr, &admitted) ||
        !VerifyBackupImagePublication(observed, admitted, candidate, error) || !observed.VerifyUnchanged(error))
        return false;
    out = std::move(candidate);
    return true;
}
catch (const std::bad_alloc&) { out = {}; return Fail(error, "ApfsReadBudgetAllocationFailed"); }
catch (const std::length_error&) { out = {}; return Fail(error, "ApfsReadBudgetAllocationFailed"); }

bool PlanAppleSnapshotDeleteReferences(const catalog::RandomAccessSource& source,
    const catalog::AppleCheckpointView& checkpoint,const catalog::ApfsSnapshotIdentity& expected,
    AppleSnapshotDeleteReferencePlan& out_plan,std::string& out_error) try
{
    const auto identity=expected;out_plan={};out_error.clear();
    if (!source.ReadBudget()) {
        auto budget=std::make_shared<catalog::ApfsReadBudget>(65536,256ull<<20,1000000,256ull<<20);
        catalog::BudgetedRandomAccessSource bounded(source,budget);
        return PlanAppleSnapshotDeleteReferences(bounded,checkpoint,identity,out_plan,out_error);
    }
    const auto& nx=checkpoint.container.superblock;
    AppleSnapshotRetentionView retention;
    std::shared_ptr<const std::vector<SnapshotRetentionCatalog>> catalogs;
    if(!LoadSnapshotPlanningRetentionCatalogs(source,checkpoint,retention,catalogs,out_error))return false;
    if(std::find(retention.identities.begin(),retention.identities.end(),identity)==retention.identities.end())
        return Fail(out_error,"AppleSnapshotDeleteExactIdentityMismatch");
    const auto volume=std::find_if(checkpoint.volumes.begin(),checkpoint.volumes.end(),[&](const auto& v){return v.superblock.object_id==identity.scope.volume_oid;});
    if(volume==checkpoint.volumes.end()||!volume->extentref_tree)return Fail(out_error,"AppleSnapshotDeleteVolumeMissing");
    if(!catalogs)return Fail(out_error,"AppleSnapshotDeleteLayerMissing");
    const auto catalog=std::find_if(catalogs->begin(),catalogs->end(),[&](const auto& c){return c.volume_oid==identity.scope.volume_oid;});
    if(catalog==catalogs->end() || catalog->records.inventory.size()!=catalog->snapshot_payloads.size() ||
        catalog->records.inventory.size()!=catalog->records.snapshots.size())return Fail(out_error,"AppleSnapshotDeleteLayerMissing");
    AppleSnapshotDeleteReferencePlan result;result.removed=identity;
    SnapshotRanges empty,new_history;
    const SnapshotRanges* new_prior=&empty;
    const SnapshotRanges* deleted=nullptr;
    const auto full_records=[&](const SnapshotRanges& geometry,std::vector<catalog::BtreeRecord>& records){
        if(!source.ReadBudget()->Materialize(geometry.size(),geometry.size()*(sizeof(catalog::BtreeRecord)+28ull)))
            return Fail(out_error,source.ReadBudget()->Failure());
        records.reserve(geometry.size());
        for(const auto& extent:geometry){
            catalog::BtreeRecord record;
            if(!EncodeApplePhysicalExtentRecord(extent,record,out_error))return false;
            records.push_back(std::move(record));
        }
        return true;};
    for(std::size_t i=0;i<catalog->records.inventory.size();++i){
        const auto& snapshot=catalog->records.inventory[i];
        const auto& resolved=catalog->snapshot_payloads[i];
        if(snapshot.xid==identity.snapshot_xid){deleted=&resolved;continue;}
        std::vector<catalog::BtreeRecord> full;
        if(!full_records(resolved,full))return false;
        if(!source.ReadBudget()->Materialize(resolved.size()+new_history.size(),(resolved.size()+new_history.size())*2048ull))return Fail(out_error,source.ReadBudget()->Failure());
        AppleSnapshotReferenceReplacement replacement;replacement.snapshot_xid=snapshot.xid;
        if(!PlanAppleSnapshotExtentLayer(*new_prior,new_history,catalog->records.snapshots[i].filesystem,full,
            nx.block_size,nx.block_count,replacement.extentref_records,out_error))return false;
        if(!source.ReadBudget()->Materialize(resolved.size(),resolved.size()*sizeof(ApplePhysicalExtentRecord)))return Fail(out_error,source.ReadBudget()->Failure());
        new_prior=&resolved;new_history.insert(new_history.end(),resolved.begin(),resolved.end());
        result.replacements.push_back(std::move(replacement));
    }
    if(!deleted)return Fail(out_error,"AppleSnapshotDeleteLayerMissing");
    const auto& live=catalog->live_payload;
    const auto& live_fs=catalog->records.live.filesystem;
    std::vector<catalog::BtreeRecord> full;
    if(!full_records(live,full))return false;
    const auto live_work=live.size()+new_history.size()+live_fs.size();
    if(!source.ReadBudget()->Materialize(live_work,live_work*2048ull))return Fail(out_error,source.ReadBudget()->Failure());
    AppleSnapshotReferenceReplacement live_replacement;
    if(!PlanAppleSnapshotExtentLayer(*new_prior,new_history,live_fs,full,nx.block_size,nx.block_count,live_replacement.extentref_records,out_error))return false;
    result.replacements.push_back(std::move(live_replacement));
    if(!source.ReadBudget()->Materialize(live.size(),live.size()*sizeof(ApplePhysicalExtentRecord)))return Fail(out_error,source.ReadBudget()->Failure());
    new_history.insert(new_history.end(),live.begin(),live.end());
    const auto held=SnapshotHistoryUnion(new_history), removed=SnapshotHistoryUnion(*deleted);
    for(const auto& range:removed){
        auto cursor=range.first;
        for(const auto& h:held){
            if(h.second<=cursor)continue;if(h.first>=range.second)break;
            if(h.first>cursor)result.unreferenced_payload.push_back({cursor,h.first-cursor});
            cursor=(std::min)(range.second,(std::max)(cursor,h.second));
        }
        if(cursor<range.second)result.unreferenced_payload.push_back({cursor,range.second-cursor});
    }
    out_plan=std::move(result);return true;
}
catch(const std::bad_alloc&){out_plan={};if(source.ReadBudget())source.ReadBudget()->Refuse("ApfsReadBudgetAllocationFailed");return Fail(out_error,"ApfsReadBudgetAllocationFailed");}
catch(const std::length_error&){out_plan={};if(source.ReadBudget())source.ReadBudget()->Refuse("ApfsReadBudgetAllocationFailed");return Fail(out_error,"ApfsReadBudgetAllocationFailed");}

bool PlanAppleSnapshotDelete(const catalog::RandomAccessSource& source,
    const catalog::AppleCheckpointView& checkpoint, const AppleSnapshotDeleteRequest& request,
    AppleSnapshotDeletePlan& out_plan, std::string& out_error) try
{
    out_plan={};out_error.clear();
    if(!source.ReadBudget()){
        auto budget=std::make_shared<catalog::ApfsReadBudget>(65536,256ull<<20,1000000,256ull<<20);
        catalog::BudgetedRandomAccessSource bounded(source,budget);
        return PlanAppleSnapshotDelete(bounded,checkpoint,request,out_plan,out_error);
    }
    if(!dynamic_cast<const SnapshotPlanningSource*>(&source)){
        SnapshotPlanningSource observation(source);
        if(!PlanAppleSnapshotDelete(observation,checkpoint,request,out_plan,out_error) ||
            !observation.VerifyUnchanged(out_error)){
            out_plan={};
            if(source.ReadBudget()->Failed())out_error=source.ReadBudget()->Failure();
            return false;
        }
        return true;
    }
    const auto& nx=checkpoint.container.superblock;
    if(!request.modification_time_ns || nx.next_xid<=nx.xid || nx.next_xid>kFsObjectIdMask)
        return Fail(out_error,"AppleSnapshotDeleteRequestInvalid");
    std::vector<AppleRecoveryCheckpointView> pins;
    if(!LoadAppleSnapshotRecoveryCheckpoints(source,checkpoint,request.required_checkpoint_xids,pins,out_error))return false;
    AppleSnapshotDeleteReferencePlan references;
    if(!PlanAppleSnapshotDeleteReferences(source,checkpoint,request.expected,references,out_error))return false;
    const auto vi=std::find_if(checkpoint.volumes.begin(),checkpoint.volumes.end(),
        [&](const auto& v){return v.superblock.object_id==request.expected.scope.volume_oid;});
    if(vi==checkpoint.volumes.end())return Fail(out_error,"AppleSnapshotDeleteVolumeMissing");
    const auto& volume=*vi;
    if(!CheckAppleVolumeWriteFeatures(nx,volume.superblock,out_error))return false;
    if(!volume.snapshot_metadata_tree || !volume.extentref_tree || volume.file_extent_tree ||
        volume.root_tree.type!=catalog::kObjectTypeBtree ||
        (volume.snapshot_metadata_tree->type!=catalog::kObjectTypeBtree &&
            volume.snapshot_metadata_tree->type!=(catalog::kObjectPhysical|catalog::kObjectTypeBtree)) ||
        volume.extentref_tree->type!=(catalog::kObjectPhysical|catalog::kObjectTypeBtree))
        return Fail(out_error,"AppleSnapshotDeleteTreeProfileUnsupported");
    AppleSnapshotRetentionView retained_inventory;
    std::shared_ptr<const std::vector<SnapshotRetentionCatalog>> retained_catalogs;
    if(!LoadSnapshotPlanningRetentionCatalogs(source,checkpoint,retained_inventory,retained_catalogs,out_error))return false;
    if(!retained_catalogs)return Fail(out_error,"AppleSnapshotDeleteLayerMissing");
    std::vector<const catalog::ApfsSnapshotIdentity*> inventory;
    if(!source.ReadBudget()->Materialize(retained_inventory.identities.size(),
        retained_inventory.identities.size()*sizeof(const catalog::ApfsSnapshotIdentity*)))
        return Fail(out_error,source.ReadBudget()->Failure());
    inventory.reserve(retained_inventory.identities.size());
    for(const auto& identity:retained_inventory.identities)
        if(identity.scope.volume_oid==request.expected.scope.volume_oid && identity!=request.expected)
            inventory.push_back(&identity);
    const auto survivors=inventory.size();
    std::vector<std::byte> apsb,omap,container_omap;
    if(!ReadObject(source,volume.superblock_object,nx.block_size,apsb)||
        !ReadObject(source,volume.object_map.object,nx.block_size,omap)||
        !ReadObject(source,checkpoint.container_object_map.object,nx.block_size,container_omap))
        return Fail(out_error,"AppleSnapshotDeleteSourceUnreadable");
    if(!SnapshotMetadataProfile(volume,apsb))return Fail(out_error,"AppleSnapshotDeleteTreeProfileUnsupported");
    const auto put=[](std::vector<std::byte>& b,std::size_t at,std::uint64_t value,std::size_t n=8){
        for(std::size_t i=0;i<n;++i)b[at+i]=static_cast<std::byte>(value>>(8*i));};
    std::vector<catalog::BtreeRecord> metadata,map_records,container_records,snapshot_map;
    std::vector<std::uint64_t> guards,visited;
    const auto read=[&](const auto& root,std::uint64_t map,auto& records){
        if(!ReadTreeRecords(source,root,nx.block_size,map,nx.xid,records,visited,out_error))return false;
        guards.insert(guards.end(),visited.begin(),visited.end());return true;};
    catalog::AppleObjectLocation snapshot_root;
    snapshot_root.object_id=volume.object_map.snapshot_tree_oid;snapshot_root.physical_block=snapshot_root.object_id;
    snapshot_root.type=catalog::kObjectPhysical|catalog::kObjectTypeBtree;snapshot_root.subtype=0x13;
    if(!read(*volume.snapshot_metadata_tree,volume.superblock.omap_oid,metadata))return false;
    std::unordered_set<std::uint64_t> old_metadata_ids;
    if(!source.ReadBudget()->Materialize(visited.size(),visited.size()*64ull))return Fail(out_error,source.ReadBudget()->Failure());
    if(!ReadTreeObjectIds(source,visited,nx.block_size,old_metadata_ids))return Fail(out_error,"AppleSnapshotDeleteMetadataIdentityInvalid");
    if(!read(volume.object_map.tree,0,map_records)||!read(checkpoint.container_object_map.tree,0,container_records)||
        !read(snapshot_root,0,snapshot_map))return false;
    const auto removed_xid=request.expected.snapshot_xid;
    std::erase_if(metadata,[&](const auto& r){const auto key=catalog::ReadU64LE(r.key,0).value();
        return (key>>60==1 && (key&kFsObjectIdMask)==removed_xid)||
            (key>>60==11 && catalog::ReadU64LE(r.value,0).value()==removed_xid);});
    std::erase_if(snapshot_map,[&](const auto& r){return catalog::ReadU64LE(r.key,0).value()==removed_xid;});
    if(metadata.size()!=survivors*2 || snapshot_map.size()!=survivors)
        return Fail(out_error,"AppleSnapshotDeleteInventoryMismatch");
    TreeShape meta_shape,map_shape,container_shape,extent_shape,snapshot_shape;
    if(!ReadTreeShape(source,*volume.snapshot_metadata_tree,nx.block_size,meta_shape)||
        !ReadTreeShape(source,volume.object_map.tree,nx.block_size,map_shape)||
        !ReadTreeShape(source,checkpoint.container_object_map.tree,nx.block_size,container_shape)||
        !ReadTreeShape(source,*volume.extentref_tree,nx.block_size,extent_shape)||
        !ReadTreeShape(source,snapshot_root,nx.block_size,snapshot_shape))return Fail(out_error,"AppleSnapshotDeleteTreeShapeInvalid");
    std::uint64_t first_child_oid=volume.snapshot_metadata_tree->object_id==1?2:1;
    std::uint64_t next_volume_oid=volume.superblock.next_object_id;
    const auto tree=[&](const auto& records,const auto& shape,auto order,std::uint64_t oid,
        std::span<const std::uint64_t> blocks,AppleSerializedBtree& result){
        return SerializeTree(records,shape,order,nx.block_size,nx.next_xid,oid,
            first_child_oid,blocks,result,out_error);};
    RemoveOmapRecords(container_records,{volume.superblock.object_id});
    if(!AddOmapRecord(container_records,volume.superblock.object_id,nx.next_xid,1,nx.block_size,out_error))return false;
    AppleSerializedBtree estimated;
    const auto estimate=[&](const auto& records,const auto& shape,auto order,std::uint64_t oid,std::size_t& count){
        if(!tree(records,shape,order,oid,{},estimated))return false;
        count=estimated.objects.size();return count!=0;};
    std::size_t meta_nodes=0,map_nodes=0,container_nodes=0,snapshot_nodes=0;
    const auto selected_catalog=std::find_if(retained_catalogs->begin(),retained_catalogs->end(),
        [&](const auto& c){return c.volume_oid==volume.superblock.object_id;});
    if(selected_catalog==retained_catalogs->end())return Fail(out_error,"AppleSnapshotDeleteLayerMissing");
    if(!estimate(metadata,meta_shape,AppleBtreeKeyOrder::FileSystemCaseSensitive,volume.snapshot_metadata_tree->object_id,meta_nodes)||
        !SnapshotMetadataChildIds(volume,map_records,selected_catalog->records.live.filesystem,
            meta_nodes,first_child_oid,next_volume_oid,out_error)||
        !SnapshotMetadataMappings(source,map_records,old_metadata_ids,*volume.snapshot_metadata_tree,
            first_child_oid,meta_nodes,nx.next_xid,nx.block_size,nullptr,out_error)||
        !estimate(map_records,map_shape,AppleBtreeKeyOrder::ObjectMap,1,map_nodes)||
        !estimate(container_records,container_shape,AppleBtreeKeyOrder::ObjectMap,1,container_nodes)||
        (survivors&&!estimate(snapshot_map,snapshot_shape,AppleBtreeKeyOrder::SnapshotObjectMap,1,snapshot_nodes)))return false;
    std::vector<std::size_t> extent_nodes;
    if(!source.ReadBudget()->Materialize(references.replacements.size(),references.replacements.size()*sizeof(std::size_t)))
        return Fail(out_error,source.ReadBudget()->Failure());
    extent_nodes.reserve(references.replacements.size());
    for(const auto& replacement:references.replacements){
        std::size_t count=0;
        if(!estimate(replacement.extentref_records,extent_shape,AppleBtreeKeyOrder::PhysicalExtent,1,count))return false;
        extent_nodes.push_back(count);
    }
    const auto replacement_index=[&](std::uint64_t xid){
        const auto it=std::find_if(references.replacements.begin(),references.replacements.end(),
            [&](const auto& r){return r.snapshot_xid==xid;});
        return static_cast<std::size_t>(it-references.replacements.begin());};
    const auto live_index=replacement_index(0);
    if(live_index==references.replacements.size())return Fail(out_error,"AppleSnapshotDeleteLayerMissing");
    std::uint64_t required_blocks=3;
    const auto add_blocks=[&](std::uint64_t count){
        if(count>UINT64_MAX-required_blocks)return Fail(out_error,"AppleSnapshotDeleteAllocationInvalid");
        required_blocks+=count;return true;};
    if(!add_blocks(meta_nodes)||!add_blocks(map_nodes)||!add_blocks(container_nodes)||
        !add_blocks(snapshot_nodes)||!add_blocks(survivors))return false;
    for(const auto count:extent_nodes)if(!add_blocks(count))return false;
    AppleSpacemanAllocationRequest allocate;
    allocate.expected_checkpoint_xid=nx.xid;allocate.transaction_xid=nx.next_xid;
    allocate.oldest_required_checkpoint_xid=nx.xid;allocate.first_ephemeral_object_id=nx.next_oid;
    allocate.main_block_count=required_blocks;
    // Keep every source owner for staging; the independent full graph derives
    // the actual retirements, including historical inventory references.
    for(const auto& pin:pins){
        allocate.oldest_required_checkpoint_xid=(std::min)(allocate.oldest_required_checkpoint_xid,pin.checkpoint.container.superblock.xid);
        for(const auto& b:pin.checkpoint.spaceman.internal_pool.active_bitmaps)allocate.protected_internal_pool_bitmap_indices.push_back(b.rotation_index);
        for(const auto& r:allocate.released_blocks){
            for(const auto& p:pin.payload_extents)if(p.physical_block<r.physical_block+r.block_count && r.physical_block<p.physical_block+p.block_count)
                return Fail(out_error,"AppleSnapshotDeleteRecoveryOwner");
            for(const auto b:pin.metadata_blocks)if(b>=r.physical_block && b-r.physical_block<r.block_count)
                return Fail(out_error,"AppleSnapshotDeleteRecoveryOwner");
        }
    }
    AppleSnapshotDeletePlan plan;
    if(!SumReleasedBlocks(allocate.released_blocks,plan.released_payload_blocks)||
        !PlanAppleSpacemanAllocation(checkpoint.spaceman,allocate,plan.allocation,out_error))return false;
    const auto& blocks=plan.allocation.allocated_main_blocks;
    if(blocks.size()!=allocate.main_block_count)return Fail(out_error,"AppleSnapshotDeleteAllocationInvalid");
    std::size_t cursor=3;
    const auto take=[&](std::size_t count){
        const auto span=std::span<const std::uint64_t>(blocks).subspan(cursor,count);
        cursor+=count;return span;};
    const auto meta_blocks=take(meta_nodes),live_blocks=take(extent_nodes[live_index]),
        map_blocks=take(map_nodes),container_blocks=take(container_nodes),snapshot_blocks=take(snapshot_nodes);
    struct HistoricalBlocks { std::uint64_t apsb,extent_root;std::span<const std::uint64_t> extents; };
    std::vector<HistoricalBlocks> historical_blocks;
    if(!source.ReadBudget()->Materialize(survivors,survivors*sizeof(HistoricalBlocks)))
        return Fail(out_error,source.ReadBudget()->Failure());
    historical_blocks.reserve(survivors);
    for(const auto& survivor:inventory){
        const auto index=replacement_index(survivor->snapshot_xid);
        if(index==references.replacements.size())return Fail(out_error,"AppleSnapshotDeleteLayerMissing");
        const auto apsb_block=take(1).front();
        const auto assigned=take(extent_nodes[index]);
        historical_blocks.push_back({apsb_block,assigned.back(),assigned});
    }
    if(cursor!=blocks.size())return Fail(out_error,"AppleSnapshotDeleteAllocationInvalid");
    catalog::ApfsSharedSpaceProjection space;
    if(!catalog::TryProjectAppleSharedSpace(checkpoint,space,out_error))return false;
    const auto selected=std::find_if(space.volumes.begin(),space.volumes.end(),[&](const auto& v){return v.object_id==volume.superblock.object_id;});
    if(selected==space.volumes.end())return Fail(out_error,"AppleSnapshotDeleteVolumeMissing");
    const std::uint64_t added=blocks.size()-1-container_nodes;
    std::uint64_t allocated=0;
    if(plan.released_payload_blocks>INT64_MAX || !AdjustCount(selected->allocated.blocks,static_cast<std::int64_t>(added),allocated)||
        !AdjustCount(allocated,-static_cast<std::int64_t>(plan.released_payload_blocks),allocated))return Fail(out_error,"AppleSnapshotDeleteAccountingOverflow");
    std::vector<AppleCheckpointPhysicalWrite> writes;
    for(std::size_t i=0;i<survivors;++i){
        const auto& s=inventory[i];const auto& assigned=historical_blocks[i];
        const auto replacement=std::find_if(references.replacements.begin(),references.replacements.end(),
            [&](const auto& r){return r.snapshot_xid==s->snapshot_xid;});
        if(replacement==references.replacements.end())return Fail(out_error,"AppleSnapshotDeleteLayerMissing");
        if(!tree(replacement->extentref_records,extent_shape,AppleBtreeKeyOrder::PhysicalExtent,1,assigned.extents,estimated))return false;
        AppendTreeWrites(estimated,writes);
        std::vector<std::byte> historical;
        if(!ReadBlock(source,s->superblock_physical_block,nx.block_size,historical))return Fail(out_error,"AppleSnapshotDeleteSourceUnreadable");
        put(historical,8,assigned.apsb);put(historical,0x10,nx.next_xid);put(historical,0x90,assigned.extents.back());
        if(!FinalizeAppleObjectChecksum(historical,out_error))return false;
        writes.push_back({assigned.apsb,std::move(historical)});
        const auto m=std::find_if(metadata.begin(),metadata.end(),[&](const auto& r){return catalog::ReadU64LE(r.key,0).value()==((1ull<<60)|s->snapshot_xid);});
        if(m==metadata.end())return Fail(out_error,"AppleSnapshotDeleteMetadataMissing");
        put(m->value,0,assigned.extents.back());put(m->value,8,assigned.apsb);
    }
    const auto live=std::find_if(references.replacements.begin(),references.replacements.end(),[](const auto& r){return !r.snapshot_xid;});
    if(live==references.replacements.end())return Fail(out_error,"AppleSnapshotDeleteLayerMissing");
    if(!tree(live->extentref_records,extent_shape,AppleBtreeKeyOrder::PhysicalExtent,1,live_blocks,estimated))return false;
    AppendTreeWrites(estimated,writes);
    if(!tree(metadata,meta_shape,AppleBtreeKeyOrder::FileSystemCaseSensitive,volume.snapshot_metadata_tree->object_id,meta_blocks,estimated))return false;
    AppendTreeWrites(estimated,writes);
    if(!SnapshotMetadataMappings(source,map_records,old_metadata_ids,*volume.snapshot_metadata_tree,
        first_child_oid,meta_nodes,nx.next_xid,nx.block_size,&estimated,out_error))return false;
    if(survivors){if(!tree(snapshot_map,snapshot_shape,AppleBtreeKeyOrder::SnapshotObjectMap,1,snapshot_blocks,estimated))return false;AppendTreeWrites(estimated,writes);}
    if(!tree(map_records,map_shape,AppleBtreeKeyOrder::ObjectMap,1,map_blocks,estimated))return false;
    AppendTreeWrites(estimated,writes);
    std::vector<std::byte> new_map;
    if(!PatchAppleObjectMap(omap,blocks[1],nx.next_xid,map_blocks.back(),new_map,out_error))return false;
    put(new_map,0x24,survivors,4);put(new_map,0x2C,survivors?(catalog::kObjectPhysical|catalog::kObjectTypeBtree):0,4);
    put(new_map,0x38,survivors?snapshot_blocks.back():0);put(new_map,0x40,survivors?inventory.back()->snapshot_xid:0);
    if(!FinalizeAppleObjectChecksum(new_map,out_error))return false;
    writes.push_back({blocks[1],std::move(new_map)});
    AppleVolumeAccountingUpdate accounting;
    accounting.xid=nx.next_xid;accounting.object_map_object_id=blocks[1];accounting.root_tree_object_id=volume.superblock.root_oid;
    accounting.extentref_tree_object_id=live_blocks.back();
    accounting.snapshot_metadata_tree_object_id=meta_shape.storage_type==catalog::kObjectPhysical ?
        meta_blocks.back() : volume.superblock.snap_meta_tree_oid;
    accounting.next_object_id=next_volume_oid;accounting.file_count=volume.superblock.file_count;
    accounting.directory_count=volume.superblock.directory_count;accounting.symlink_count=catalog::ReadU64LE(apsb,0xC8).value();
    accounting.other_object_count=catalog::ReadU64LE(apsb,0xD0).value();accounting.snapshot_count=survivors;
    accounting.file_system_allocated_blocks=allocated;accounting.last_modification_time=request.modification_time_ns;
    if(!AdjustCount(catalog::ReadU64LE(apsb,0xE0).value(),static_cast<std::int64_t>(added),accounting.total_blocks_allocated)||
        !AdjustCount(catalog::ReadU64LE(apsb,0xE8).value(),static_cast<std::int64_t>(plan.released_payload_blocks),accounting.total_blocks_freed))
        return Fail(out_error,"AppleSnapshotDeleteAccountingOverflow");
    std::vector<std::byte> live_apsb;
    if(!PatchAppleVolumeSuperblock(apsb,accounting,live_apsb,out_error))return false;
    writes.push_back({blocks[0],std::move(live_apsb)});
    RemoveOmapRecords(container_records,{volume.superblock.object_id});
    if(!AddOmapRecord(container_records,volume.superblock.object_id,nx.next_xid,blocks[0],nx.block_size,out_error)||
        !tree(container_records,container_shape,AppleBtreeKeyOrder::ObjectMap,1,container_blocks,estimated))return false;
    AppendTreeWrites(estimated,writes);
    std::vector<std::byte> new_container;
    if(!PatchAppleObjectMap(container_omap,blocks[2],nx.next_xid,container_blocks.back(),new_container,out_error))return false;
    writes.push_back({blocks[2],std::move(new_container)});
    AppleTransactionCommitRequest commit;
    commit.allocation_plan=plan.allocation;commit.container_object_map_oid=blocks[2];commit.allocated_main_writes=std::move(writes);
    commit.required_checkpoint_xids=request.required_checkpoint_xids;commit.next_object_id=nx.next_oid;
    for(const auto& w:plan.allocation.writes)if(w.object_location)commit.next_object_id=(std::max)(commit.next_object_id,w.object_location->object_id+1);
    AppleSnapshotInventoryChange change;change.removed=request.expected;
    if(!PlanAppleSnapshotRetirementCandidate(source,checkpoint,commit,&change,plan.commit.publication,out_error))return false;
    if(!FinalizeSnapshotRetirement(source,checkpoint,volume.superblock.object_id,allocate,commit,&change,
        plan.commit,plan.allocation,out_error,&plan.released_payload_blocks))return false;
    for(const auto b:guards)if(!AddGuard(source,b,nx.block_size,plan.commit.publication.guard_blocks))return Fail(out_error,"AppleSnapshotDeleteGuardUnreadable");
    for(const auto& peer:checkpoint.volumes)if(!AddGuard(source,peer.superblock_object.physical_block,nx.block_size,plan.commit.publication.guard_blocks))return Fail(out_error,"AppleSnapshotDeleteGuardUnreadable");
    for(std::size_t i=0;i<survivors;++i){auto id=*inventory[i];id.scope.checkpoint_xid=nx.next_xid;
        id.superblock_physical_block=historical_blocks[i].apsb;id.extentref_physical_block=historical_blocks[i].extent_root;plan.surviving.push_back(std::move(id));}
    plan.removed=request.expected;out_plan=std::move(plan);return true;
}
catch(const std::bad_alloc&){out_plan={};if(source.ReadBudget())source.ReadBudget()->Refuse("ApfsReadBudgetAllocationFailed");return Fail(out_error,"ApfsReadBudgetAllocationFailed");}
catch(const std::length_error&){out_plan={};if(source.ReadBudget())source.ReadBudget()->Refuse("ApfsReadBudgetAllocationFailed");return Fail(out_error,"ApfsReadBudgetAllocationFailed");}

#include "FusionReclamationProof.inc"

namespace {
bool PlanFusionVolumeTransactionImpl(const catalog::ApfsFusionStore& store,
    const AppleVolumeTransactionRequest& request, FusionVolumeTransactionPlan& out,
    std::string& error, FusionAllocationProfile profile,
    FusionObjectIdProfile object_ids = FusionObjectIdProfile::Original) try
{
    out = {};
    if (request.volume_reserve_quota || !request.clones.empty() || !request.compression_rewrites.empty())
        return Fail(error, "FusionVolumeExtendedMutationUnsupported");
    catalog::AppleSpacemanView current;
    if (!catalog::LoadFusionSpacemanAllocationView(store,current,error)) return false;
    SnapshotPlanningSource observed(store);
    catalog::AppleCheckpointView cp;
    if (!LoadFusionPlanningCheckpoint(store,observed,store.Checkpoint(),cp,error)) return false;
    FusionLiveGraph graph;
    if (!ReadFusionLiveGraph(store,observed,cp,graph,error)) return false;
    FusionVolumePlanning context{store,{},{}};
    context.allocation_profile = profile;
    context.object_id_profile = object_ids;
    for (auto xid : request.required_checkpoint_xids) {
        if (!xid || xid > cp.container.superblock.xid) return Fail(error,"FusionVolumeRecoveryPinInvalid");
        auto container = catalog::LoadContainerCheckpointView(observed,0,observed.SizeBytes(),error,xid);
        catalog::AppleCheckpointView historical;
        FusionLiveGraph old_graph;
        if (!container || !LoadFusionPlanningCheckpoint(store,observed,*container,historical,error) ||
            !ReadFusionLiveGraph(store,observed,historical,old_graph,error)) return false;
        for (auto b : old_graph.metadata) {
            if (!FusionOwnedRange(store,cp,b,1,xid,error)) return false;
            context.retained_metadata.insert(b);
        }
        for (const auto& p : old_graph.payload)
            if (!FusionOwnedRange(store,cp,p.physical_block,p.block_count,xid,error)) return false;
    }
    FusionVolumeTransactionPlan candidate;
    if (!PlanAppleVolumeTransactionImpl(observed,cp,request,candidate.transaction,error,false,false,&context) ||
        !observed.VerifyUnchanged(error) || !store.CheckAvailable(error)) return false;
    candidate.allocated_tier2_blocks = std::move(context.tier2_blocks);
    out = std::move(candidate);
    return true;
}
catch (const std::bad_alloc&) { out = {}; return Fail(error,"FusionVolumeMemoryLimit"); }
catch (const std::length_error&) { out = {}; return Fail(error,"FusionVolumeMemoryLimit"); }
}

bool PlanFusionVolumeTransaction(const catalog::ApfsFusionStore& store,
    const AppleVolumeTransactionRequest& request, FusionVolumeTransactionPlan& out, std::string& error)
{
    return PlanFusionVolumeTransactionImpl(store,request,out,error,FusionAllocationProfile::Conservative);
}

bool PlanFusionReclaimingVolumeTransaction(const catalog::ApfsFusionStore& store,
    const AppleVolumeTransactionRequest& request, FusionVolumeTransactionPlan& out, std::string& error)
{
    return PlanFusionVolumeTransactionImpl(store,request,out,error,FusionAllocationProfile::RetainedOwners);
}

bool PlanFusionCanonicalVolumeTransaction(const catalog::ApfsFusionStore& store,
    const AppleVolumeTransactionRequest& request, FusionVolumeTransactionPlan& out, std::string& error)
{
    return PlanFusionVolumeTransactionImpl(store,request,out,error,FusionAllocationProfile::RetainedOwners,
        FusionObjectIdProfile::CanonicalCensus);
}

bool PlanFusionCompactedVolumeTransaction(const catalog::ApfsFusionStore& store,
    const AppleVolumeTransactionRequest& request, FusionVolumeTransactionPlan& out, std::string& error)
{
    return PlanFusionVolumeTransactionImpl(store,request,out,error,FusionAllocationProfile::RetainedOwners,
        FusionObjectIdProfile::CompactedExtents);
}

bool PlanAppleVolumeTransaction(const catalog::RandomAccessSource& source,
    const catalog::AppleCheckpointView& checkpoint,const AppleVolumeTransactionRequest& request,
    AppleVolumeTransactionPlan& out_plan,std::string& out_error)
{
    return PlanAppleVolumeTransactionImpl(source,checkpoint,request,out_plan,out_error,false);
}
bool PlanApplePlainCompactTransaction(const catalog::RandomAccessSource& source,
    const catalog::AppleCheckpointView& checkpoint, const AppleVolumeTransactionRequest& request,
    AppleVolumeTransactionPlan& out_plan, std::string& out_error, bool preserve_sibling_snapshots) try
{
    if (preserve_sibling_snapshots && !source.ReadBudget()) {
        auto budget = std::make_shared<catalog::ApfsReadBudget>(65536, 256ull << 20, 1000000, 256ull << 20);
        catalog::BudgetedRandomAccessSource bounded(source, budget);
        return PlanApplePlainCompactTransaction(bounded, checkpoint, request, out_plan, out_error, true);
    }
    if (preserve_sibling_snapshots && !dynamic_cast<const SnapshotPlanningSource*>(&source)) {
        SnapshotPlanningSource observation(source);
        const bool planned = PlanApplePlainCompactTransaction(observation, checkpoint, request, out_plan, out_error, true);
        std::string source_error;
        const bool unchanged = observation.VerifyUnchanged(source_error);
        if (!planned || !unchanged) {
            out_plan = {};
            if (!unchanged) out_error = std::move(source_error);
            if (source.ReadBudget()->Failed()) out_error = source.ReadBudget()->Failure();
            return false;
        }
        return true;
    }
    return PlanAppleVolumeTransactionImpl(source, checkpoint, request, out_plan, out_error,
        false, preserve_sibling_snapshots, nullptr, nullptr, 0, 0, nullptr, false, true);
}
catch (const std::bad_alloc&) { out_plan = {}; if (source.ReadBudget()) source.ReadBudget()->Refuse("ApfsReadBudgetAllocationFailed"); return Fail(out_error, "ApfsReadBudgetAllocationFailed"); }
catch (const std::length_error&) { out_plan = {}; if (source.ReadBudget()) source.ReadBudget()->Refuse("ApfsReadBudgetAllocationFailed"); return Fail(out_error, "ApfsReadBudgetAllocationFailed"); }

AppleCapacityPreviewResult PreviewApplePlainCompactCapacity(
    const catalog::RandomAccessSource& source, const catalog::AppleCheckpointView& checkpoint,
    const AppleVolumeTransactionRequest& request, std::span<const std::uint64_t> payload_bytes,
    AppleVolumeCapacityPreview& out_preview, std::string& out_error) try
{
    out_preview = {};
    out_error.clear();
    const auto selected = std::find_if(checkpoint.volumes.begin(), checkpoint.volumes.end(),
        [&](const auto& v) { return v.superblock.object_id == request.volume_object_id; });
    if (selected == checkpoint.volumes.end()) {
        out_error = "AppleVolumeTransactionVolumeMissing";
        return AppleCapacityPreviewResult::Refused;
    }
    if (request.preserve_source_metadata || !request.clones.empty() || !request.compression_rewrites.empty() ||
        std::any_of(request.data_writes.begin(), request.data_writes.end(), [](const auto& data) { return data.crypto_id != 0; }) ||
        request.volume_reserve_quota || checkpoint.spaceman.devices[1].block_count ||
        !(selected->superblock.fs_flags & catalog::kFsFlagUnencrypted) || selected->superblock.role_raw == 0x0180 ||
        std::any_of(checkpoint.volumes.begin(), checkpoint.volumes.end(),
            [](const auto& v) { return v.object_map.snapshot_tree_oid != 0; }))
        return AppleCapacityPreviewResult::Unsupported;
    if (payload_bytes.size() != request.data_writes.size() ||
        std::any_of(request.data_writes.begin(), request.data_writes.end(),
            [](const auto& d) { return !d.bytes.empty(); })) {
        out_error = "AppleCapacityPreviewGeometryInvalid";
        return AppleCapacityPreviewResult::Refused;
    }
    AppleVolumeTransactionPlan candidate;
    if (!PlanAppleVolumeTransactionImpl(source, checkpoint, request, candidate, out_error,
            false, false, nullptr, nullptr, 0, 0, nullptr, false, true, &payload_bytes))
        return out_error == "AppleCapacityPreviewProfileUnsupported"
            ? AppleCapacityPreviewResult::Unsupported : AppleCapacityPreviewResult::Refused;
    if (!candidate.commit.publication.superblock_write.bytes.empty()) {
        out_error = "AppleCapacityPreviewExecutablePlan";
        return AppleCapacityPreviewResult::Refused;
    }
    out_preview.allocation = std::move(candidate.allocation);
    out_preview.payload_blocks = std::move(candidate.payload_blocks);
    out_preview.filesystem_records = std::move(candidate.filesystem_records);
    out_preview.metadata_write_count = candidate.commit.publication.before_superblock_writes.size();
    for (const auto& write : candidate.commit.publication.before_superblock_writes)
        out_preview.metadata_write_bytes += write.bytes.size();
    return AppleCapacityPreviewResult::Planned;
}
catch (const std::bad_alloc&) { out_preview = {}; out_error = "AppleCapacityPreviewAllocationFailed"; return AppleCapacityPreviewResult::Refused; }
catch (const std::length_error&) { out_preview = {}; out_error = "AppleCapacityPreviewAllocationFailed"; return AppleCapacityPreviewResult::Refused; }

bool PlanAppleCloneRangeTransaction(const catalog::RandomAccessSource& source,
    const catalog::AppleCheckpointView& checkpoint, const AppleVolumeTransactionRequest& request,
    const AppleCloneRangeMapping& range, AppleVolumeTransactionPlan& out, std::string& error)
{
    out = {}; error.clear();
    if (!range.source_inode || !range.target_inode || range.source_inode == range.target_inode ||
        !range.length || range.length >= (1ull << 32) || range.source_offset > INT64_MAX || range.target_offset > INT64_MAX ||
        range.length > INT64_MAX - range.source_offset || range.length > INT64_MAX - range.target_offset ||
        range.source_offset % 4096 || range.target_offset % 4096 || range.length % 4096 ||
        checkpoint.container.superblock.block_size != 4096 || checkpoint.volumes.size() != 1 ||
        !request.data_writes.empty() || !request.clones.empty() || !request.compression_rewrites.empty() ||
        request.preserve_source_metadata || request.volume_reserve_quota || request.file_count_delta ||
        request.directory_count_delta || request.symlink_count_delta || request.other_object_count_delta)
        return Fail(error, "AppleVolumeCloneRangeProfileInvalid");
    return PlanAppleVolumeTransactionImpl(source, checkpoint, request, out, error, false, false, nullptr, nullptr, 0, 0, &range);
}
bool PlanSoftwareTransitionPlainTransaction(const catalog::ImmutableEncryptedReadSource& source,
    const catalog::AppleCheckpointView& checkpoint, const AppleVolumeTransactionRequest& request,
    std::shared_ptr<const catalog::SoftwareVolumeRetainedOwners> owners, const std::array<std::byte, 32>& jid,
    AppleVolumeTransactionPlan& out_plan, std::string& error) try
{
    out_plan = {}; error.clear();
    if (!source.ReadBudget() || !owners || request.volume_object_id != owners->VolumeObjectId())
        return Fail(error, "AppleSoftwareTransitionCapabilityRequired");
    SnapshotPlanningSource observed(source);
    if (!BindSoftwareTransitionRetention(observed, source, owners, jid, error)) return false;
    auto current = catalog::LoadAppleCheckpointView(observed, 0, source.SizeBytes(), error);
    if (!current || current->container.superblock_bytes != checkpoint.container.superblock_bytes ||
        current->container.superblock_physical_block != checkpoint.container.superblock_physical_block)
        return Fail(error, "AppleSoftwareTransitionEndpointChanged");
    // Opaque history grants exclusions, never an old decrypted read context.
    for (auto xid : request.required_checkpoint_xids)
        if (xid != current->container.superblock.xid && xid <= owners->MintedCheckpointXid())
            return Fail(error, "AppleSoftwareTransitionOpaqueReadPinUnsupported");
    AppleVolumeTransactionPlan candidate;
    if (!PlanAppleVolumeTransactionImpl(observed, *current, request, candidate, error, false) ||
        !VerifySoftwareTransitionPublication(observed, candidate.allocation, candidate.commit.publication, error) ||
        !observed.VerifyUnchanged(error)) return false;
    out_plan = std::move(candidate); return true;
}
catch (const std::bad_alloc&) { out_plan = {}; return Fail(error, "ApfsReadBudgetAllocationFailed"); }
catch (const std::length_error&) { out_plan = {}; return Fail(error, "ApfsReadBudgetAllocationFailed"); }
bool PlanAppleSnapshotLiveTransaction(const catalog::RandomAccessSource& source,
    const catalog::AppleCheckpointView& checkpoint,const AppleVolumeTransactionRequest& request,
    AppleVolumeTransactionPlan& out_plan,std::string& out_error) try
{
    if (!source.ReadBudget()) {
        auto budget=std::make_shared<catalog::ApfsReadBudget>(65536,256ull<<20,1000000,256ull<<20);
        catalog::BudgetedRandomAccessSource bounded(source,budget);
        return PlanAppleSnapshotLiveTransaction(bounded,checkpoint,request,out_plan,out_error);
    }
    if (!dynamic_cast<const SnapshotPlanningSource*>(&source)) {
        SnapshotPlanningSource observation(source);
        const bool planned = PlanAppleSnapshotLiveTransaction(observation, checkpoint, request, out_plan, out_error);
        std::string source_error;
        const bool unchanged = observation.VerifyUnchanged(source_error);
        if (!planned || !unchanged) {
            out_plan = {};
            if (!unchanged) out_error = std::move(source_error);
            if (source.ReadBudget()->Failed()) out_error = source.ReadBudget()->Failure();
            return false;
        }
        return true;
    }
    return PlanAppleVolumeTransactionImpl(source,checkpoint,request,out_plan,out_error,true);
}
catch(const std::bad_alloc&){out_plan={};if(source.ReadBudget())source.ReadBudget()->Refuse("ApfsReadBudgetAllocationFailed");return Fail(out_error,"ApfsReadBudgetAllocationFailed");}
catch(const std::length_error&){out_plan={};if(source.ReadBudget())source.ReadBudget()->Refuse("ApfsReadBudgetAllocationFailed");return Fail(out_error,"ApfsReadBudgetAllocationFailed");}

bool PlanAppleSnapshotMetadataTransaction(const catalog::RandomAccessSource& source,
    const catalog::AppleCheckpointView& checkpoint, const AppleVolumeTransactionRequest& request,
    AppleVolumeTransactionPlan& out_plan, std::string& out_error) try
{
    out_plan = {};
    if (!source.ReadBudget()) {
        auto budget = std::make_shared<catalog::ApfsReadBudget>(65536, 256ull << 20, 1000000, 256ull << 20);
        catalog::BudgetedRandomAccessSource bounded(source, budget);
        return PlanAppleSnapshotMetadataTransaction(bounded, checkpoint, request, out_plan, out_error);
    }
    if (!dynamic_cast<const SnapshotPlanningSource*>(&source)) {
        SnapshotPlanningSource observed(source);
        const bool planned = PlanAppleSnapshotMetadataTransaction(observed, checkpoint, request, out_plan, out_error);
        std::string changed;
        if (!observed.VerifyUnchanged(changed)) { out_plan = {}; out_error = std::move(changed); return false; }
        return planned;
    }
    const auto volume = std::find_if(checkpoint.volumes.begin(), checkpoint.volumes.end(),
        [&](const auto& v) { return v.superblock.object_id == request.volume_object_id; });
    if (volume == checkpoint.volumes.end()) return Fail(out_error, "AppleSnapshotMetadataVolumeMissing");
    return PlanAppleVolumeTransactionImpl(source, checkpoint, request, out_plan, out_error,
        volume->object_map.snapshot_tree_oid != 0, true, nullptr, nullptr, 0, 0, nullptr, true);
}
catch (const std::bad_alloc&) { out_plan = {}; if (source.ReadBudget()) source.ReadBudget()->Refuse("ApfsReadBudgetAllocationFailed"); return Fail(out_error, "ApfsReadBudgetAllocationFailed"); }
catch (const std::length_error&) { out_plan = {}; if (source.ReadBudget()) source.ReadBudget()->Refuse("ApfsReadBudgetAllocationFailed"); return Fail(out_error, "ApfsReadBudgetAllocationFailed"); }

bool PlanAppleSnapshotSiblingTransaction(const catalog::RandomAccessSource& source,
    const catalog::AppleCheckpointView& checkpoint, const AppleVolumeTransactionRequest& request,
    AppleVolumeTransactionPlan& out_plan, std::string& out_error) try
{
    if (!source.ReadBudget()) {
        auto budget = std::make_shared<catalog::ApfsReadBudget>(65536, 256ull << 20, 1000000, 256ull << 20);
        catalog::BudgetedRandomAccessSource bounded(source, budget);
        return PlanAppleSnapshotSiblingTransaction(bounded, checkpoint, request, out_plan, out_error);
    }
    if (!dynamic_cast<const SnapshotPlanningSource*>(&source)) {
        SnapshotPlanningSource observation(source);
        const bool planned = PlanAppleSnapshotSiblingTransaction(observation, checkpoint, request, out_plan, out_error);
        std::string source_error;
        const bool unchanged = observation.VerifyUnchanged(source_error);
        if (!planned || !unchanged) {
            out_plan = {};
            if (!unchanged) out_error = std::move(source_error);
            if (source.ReadBudget()->Failed()) out_error = source.ReadBudget()->Failure();
            return false;
        }
        return true;
    }
    return PlanAppleVolumeTransactionImpl(source, checkpoint, request, out_plan, out_error, false, true);
}
catch (const std::bad_alloc&) { out_plan = {}; if (source.ReadBudget()) source.ReadBudget()->Refuse("ApfsReadBudgetAllocationFailed"); return Fail(out_error, "ApfsReadBudgetAllocationFailed"); }
catch (const std::length_error&) { out_plan = {}; if (source.ReadBudget()) source.ReadBudget()->Refuse("ApfsReadBudgetAllocationFailed"); return Fail(out_error, "ApfsReadBudgetAllocationFailed"); }

} // namespace apfsaccess::rw
