#include "AppleVolumeTransaction.h"

#include "ApfsTransactionWriter.h"
#include "ApfsExtendedRecordCodec.h"
#include "WriteAheadLog.h"

#include <algorithm>
#include <limits>
#include <map>
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
    return SerializeAppleBtree(records, options, out_tree, out_error) &&
        (blocks.empty() || out_tree.objects.size() == blocks.size());
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
};

bool DecodeFileExtentUse(const catalog::BtreeRecord& record,
    std::uint32_t block_size, FileExtentUse& out_use)
{
    std::string error;
    if (!DecodeAppleFileExtentRecord(record, block_size, out_use.extent, error)) return false;
    out_use.record = &record;
    return true;
}

bool CollectFileExtentChanges(
    const std::vector<catalog::BtreeRecord>& old_records,
    const std::vector<catalog::BtreeRecord>& requested_records,
    std::uint32_t block_size, std::vector<FileExtentUse>& out_old_uses,
    std::vector<FileExtentUse>& out_removed_uses, std::string& out_error)
{
    using ExtentKey = std::pair<std::uint64_t, std::uint64_t>;
    std::map<ExtentKey, std::size_t> old_by_key;
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
        if (!DecodeFileExtentUse(record, block_size, use))
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
    // Sparse COW may retain exact subranges of an old record. The mapping,
    // crypto identity and owner must be unchanged; arbitrary remapping is forbidden.
    std::unordered_set<std::uint64_t> sparse_ids;
    for (const auto& use : out_old_uses)
        if (!use.extent.physical_block) sparse_ids.insert(use.extent.object_id);
    std::unordered_map<std::uint64_t, std::size_t> private_owners;
    std::unordered_set<std::uint64_t> ordinary_private_ids;
    for (const auto& record : old_records)
    {
        if ((catalog::ReadU64LE(record.key, 0).value_or(0) >> 60) != 3) continue;
        AppleInodeRecord inode;
        if (!ApfsExtendedRecordCodec::DecodeInode(record, inode, out_error)) return false;
        ++private_owners[inode.private_id];
        if (inode.internal_flags & kAppleInodeSparseFlag) sparse_ids.insert(inode.private_id);
        if (inode.object_id == inode.private_id && (inode.mode & 0170000) == 0100000 &&
            !(inode.bsd_flags & kAppleBsdCompressedFlag)) ordinary_private_ids.insert(inode.private_id);
        for (const auto& field : inode.extended_fields)
            if (field.type == 8 && field.data.size() == 40 &&
                catalog::ReadU64LE(field.data, 8).value_or(UINT64_MAX) < catalog::ReadU64LE(field.data, 0).value_or(0))
                sparse_ids.insert(inode.private_id);
    }
    for (const auto& record : old_records)
    {
        if ((catalog::ReadU64LE(record.key, 0).value_or(0) >> 60) != 4) continue;
        AppleXattrRecord attribute;
        if (!ApfsExtendedRecordCodec::DecodeXattr(record, attribute, out_error)) return false;
        if (attribute.name_utf8 == "com.apple.decmpfs") ordinary_private_ids.erase(attribute.object_id);
    }
    std::erase_if(sparse_ids, [&](auto id) { return private_owners[id] != 1 || !ordinary_private_ids.contains(id); });
    std::vector<std::vector<std::pair<std::uint64_t, std::uint64_t>>> retained(out_old_uses.size());
    for (const auto& record : requested_records)
    {
        if ((catalog::ReadU64LE(record.key, 0).value_or(0) >> 60) != kFsRecordTypeFileExtent) continue;
        FileExtentUse use;
        if (!DecodeFileExtentUse(record, block_size, use))
            return Fail(out_error, "AppleVolumeFileExtentRecordInvalid");
        auto found = old_by_key.upper_bound({use.extent.object_id, use.extent.logical_address});
        if (found == old_by_key.begin()) return Fail(out_error, "AppleVolumeFileExtentMutationInvalid");
        --found;
        const auto& old = out_old_uses[found->second];
        const auto& before = old.extent;
        const auto& next = use.extent;
        if (before.object_id != next.object_id || next.logical_address < before.logical_address ||
            next.logical_address - before.logical_address >= before.length_bytes ||
            next.length_bytes > before.length_bytes - (next.logical_address - before.logical_address))
            return Fail(out_error, "AppleVolumeFileExtentMutationInvalid");
        const bool exact = old.record->key == record.key && old.record->value == record.value;
        if (!exact && (!sparse_ids.contains(before.object_id) || before.crypto_id || next.crypto_id ||
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
            if (!parts.empty()) fragment.record = nullptr; // Require exclusive ownership for splitting.
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
    if (!old_attributes.empty() || !requested_attributes.empty())
    {
        if (!collect_inodes(old_records, old_inode_ids) || !collect_inodes(requested_records, requested_inode_ids)) return false;
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
                (proof.type == 4 && key.second == "com.apple.ResourceFork")) continue;
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
        if (proof.type == 4 ? fork != requested_attributes.end() :
            proof.resource_flags ? fork == requested_attributes.end() || fork->second.flags != proof.resource_flags ||
                fork->second.data != proof.resource_descriptor : fork != requested_attributes.end())
            return Fail(out_error, "AppleCompressionRewriteForkMismatch");
        ApfsCompressionResourceReader resource;
        resource.size = proof.resource.size();
        resource.read = [&](std::uint64_t at, std::span<std::byte> out) {
            if (at > proof.resource.size() || out.size() > proof.resource.size()-at) return std::size_t{0};
            std::copy_n(proof.resource.begin()+static_cast<std::size_t>(at), out.size(), out.begin()); return out.size(); };
        std::vector<std::byte> decoded;
        for (std::uint64_t at = 0;;)
        {
            const auto count = (std::min)(std::uint64_t{65536}, proof.size-at);
            if (!ApfsCompression::DecodeRange(proof.decmpfs, resource, at, count, {}, decoded) || decoded.size() != count)
                return Fail(out_error, "AppleCompressionRewriteDecodeFailed");
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
    std::string& out_error)
{
    out_extents.clear();
    out_extents.reserve(records.size());
    for (const auto& record : records)
    {
        ApplePhysicalExtentRecord extent;
        if (!DecodeApplePhysicalExtentRecord(record, extent, out_error) ||
            extent.physical_block >= container_block_count ||
            extent.block_count > container_block_count - extent.physical_block)
        {
            return Fail(out_error, "AppleVolumePhysicalExtentRecordInvalid");
        }
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
    std::uint64_t container_block_count, std::string& out_error)
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
        if (use.extent.physical_block >= container_block_count ||
            blocks > container_block_count - use.extent.physical_block)
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
                found->extent.owning_object_id != use.extent.object_id)
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

bool BuildRetainedPhysicalExtentRecords(
    const std::vector<PhysicalExtentState>& physical_extents,
    const std::vector<FileExtentUse>& removed_uses,
    std::vector<catalog::BtreeRecord>& out_records,
    std::string& out_error)
{
    std::vector<std::pair<std::uint64_t, std::uint64_t>> removed;
    removed.reserve(removed_uses.size());
    for (const auto& use : removed_uses)
    {
        if (use.extent.physical_block == 0) continue;
        removed.emplace_back(use.extent.physical_block, ExtentEnd(use));
    }
    std::sort(removed.begin(), removed.end());
    for (std::size_t index = 1; index < removed.size(); ++index)
    {
        if (removed[index - 1].second > removed[index].first)
        {
            return Fail(out_error, "AppleVolumeSharedExtentUnsupported");
        }
    }

    out_records.clear();
    std::size_t first_removed = 0;
    for (const auto& state : physical_extents)
    {
        const auto physical_start = state.extent.physical_block;
        const auto physical_end = ExtentEnd(state.extent);
        while (first_removed < removed.size() &&
            removed[first_removed].second <= physical_start)
        {
            ++first_removed;
        }
        auto cursor = physical_start;
        auto index = first_removed;
        while (index < removed.size() && removed[index].first < physical_end)
        {
            if (state.extent.reference_count > 1)
            {
                return Fail(out_error, "AppleVolumeSharedExtentUnsupported");
            }
            const auto remove_start = (std::max)(cursor, removed[index].first);
            const auto remove_end = (std::min)(physical_end,
                removed[index].second);
            if (remove_start > cursor)
            {
                auto fragment = state.extent;
                fragment.physical_block = cursor;
                fragment.block_count = remove_start - cursor;
                catalog::BtreeRecord encoded;
                if (!EncodeApplePhysicalExtentRecord(
                        fragment, encoded, out_error))
                {
                    return false;
                }
                out_records.push_back(std::move(encoded));
            }
            cursor = (std::max)(cursor, remove_end);
            ++index;
        }
        if (cursor < physical_end)
        {
            auto fragment = state.extent;
            fragment.physical_block = cursor;
            fragment.block_count = physical_end - cursor;
            catalog::BtreeRecord encoded;
            if (!EncodeApplePhysicalExtentRecord(fragment, encoded, out_error))
            {
                return false;
            }
            out_records.push_back(std::move(encoded));
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

bool ValidateApplePayloadExtentGraph(
    const std::vector<catalog::BtreeRecord>& filesystem_records,
    const std::vector<catalog::BtreeRecord>& extentref_records,
    std::uint32_t block_size, std::uint64_t container_block_count,
    std::vector<ApplePhysicalExtentRecord>& out_extents, std::string& out_error)
{
    out_extents.clear();
    out_error.clear();
    std::vector<FileExtentUse> uses;
    std::vector<FileExtentUse> removed;
    std::vector<PhysicalExtentState> physical;
    if (!CollectFileExtentChanges(filesystem_records, filesystem_records,
            block_size, uses, removed, out_error) ||
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

bool CheckAppleVolumeWriteFeatures(
    const catalog::NxSuperblock& container,
    const catalog::ApsbVolume& volume,
    std::string& out_error)
{
    out_error.clear();
    if (container.readonly_features != 0 ||
        (container.incompatible_features & ~catalog::kNxSupportedIncompatibleFeaturesMask) != 0)
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
    return true;
}

bool PlanAppleVolumeTransaction(
    const catalog::RandomAccessSource& source,
    const catalog::AppleCheckpointView& checkpoint,
    const AppleVolumeTransactionRequest& request,
    AppleVolumeTransactionPlan& out_plan, std::string& out_error)
{
    out_plan = {};
    out_error.clear();
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
    if (!CheckAppleVolumeWriteFeatures(nxsb, volume.superblock, out_error))
    {
        return false;
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
    const auto snapshot_count =
        catalog::ReadU64LE(apsb_bytes, 0xD8).value_or(
            std::numeric_limits<std::uint64_t>::max());
    std::vector<catalog::BtreeRecord> snapshot_records;
    std::vector<std::uint64_t> snapshot_blocks;
    if (volume.snapshot_metadata_tree.has_value() &&
        (!ReadTreeRecords(source, volume.snapshot_metadata_tree.value(),
             nxsb.block_size, volume.superblock.omap_oid, nxsb.xid,
             snapshot_records, snapshot_blocks, out_error) ||
         !snapshot_records.empty()))
    {
        return Fail(out_error, "AppleVolumeSnapshotsUnsupported");
    }
    if (snapshot_count != 0)
    {
        return Fail(out_error, "AppleVolumeSnapshotsUnsupported");
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

    std::vector<catalog::BtreeRecord> old_fs_records;
    std::vector<std::uint64_t> old_fs_blocks;
    std::vector<catalog::BtreeRecord> old_extentref_records;
    std::vector<std::uint64_t> old_extentref_blocks;
    std::vector<catalog::BtreeRecord> volume_omap_records;
    std::vector<std::uint64_t> old_volume_omap_blocks;
    std::vector<catalog::BtreeRecord> container_omap_records;
    std::vector<std::uint64_t> old_container_omap_blocks;
    if (!ReadTreeRecords(source, volume.root_tree, nxsb.block_size,
            volume.superblock.omap_oid, nxsb.xid, old_fs_records,
            old_fs_blocks, out_error) ||
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

    std::vector<FileExtentUse> old_file_extents;
    std::vector<FileExtentUse> removed_file_extents;
    if (!CollectFileExtentChanges(old_fs_records,
            request.filesystem_records, nxsb.block_size, old_file_extents,
            removed_file_extents, out_error))
    {
        return false;
    }
    if (!SameReleaseSet(removed_file_extents,
            request.released_data_blocks, nxsb.block_size))
    {
        return Fail(out_error, "AppleVolumeReleaseSetMismatch");
    }
    const bool rewrite_extentrefs =
        !removed_file_extents.empty() || !request.data_writes.empty();
    if (rewrite_extentrefs && !volume.extentref_tree.has_value())
    {
        return Fail(out_error, "AppleVolumeExtentReferenceTreeMissing");
    }
    std::vector<PhysicalExtentState> physical_extents;
    std::vector<catalog::BtreeRecord> extentref_records;
    if (rewrite_extentrefs &&
        (!DecodePhysicalExtentTree(old_extentref_records, nxsb.block_count,
             physical_extents, out_error) ||
         !ValidatePhysicalExtentCoverage(old_file_extents, physical_extents,
             nxsb.block_count, out_error) ||
         !BuildRetainedPhysicalExtentRecords(physical_extents,
             removed_file_extents, extentref_records, out_error)))
    {
        return false;
    }
    std::unordered_set<std::uint64_t> split_owners;
    for (const auto& use : removed_file_extents)
        if (!use.record) split_owners.insert(use.extent.object_id);
    for (const auto& use : old_file_extents)
    {
        if (!split_owners.contains(use.extent.object_id) || !use.extent.physical_block) continue;
        auto at = std::upper_bound(physical_extents.begin(), physical_extents.end(), use.extent.physical_block,
            [](auto block, const auto& state) { return block < state.extent.physical_block; });
        if (at != physical_extents.begin()) --at;
        auto cursor = use.extent.physical_block;
        const auto end = ExtentEnd(use);
        while (cursor < end)
        {
            if (at == physical_extents.end() || at->extent.physical_block > cursor || ExtentEnd(at->extent) <= cursor ||
                at->extent.reference_count != 1 || at->extent.owning_object_id != use.extent.object_id)
                return Fail(out_error, "AppleVolumeSparseSharedExtentUnsupported");
            cursor = (std::min)(end, ExtentEnd(at->extent));
            ++at;
        }
    }
    std::vector<catalog::BtreeRecord> normalized_filesystem_records;
    if (!NormalizeDataStreamRecords(old_fs_records,
            request.filesystem_records, old_file_extents,
            removed_file_extents, request.data_writes, nxsb.block_size, volume.superblock.next_object_id,
            request.compression_rewrites, source, nxsb.xid, request.volume_object_id,
            normalized_filesystem_records, out_error))
    {
        return false;
    }
    std::unordered_set<std::uint64_t> old_fs_object_ids;
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

    std::size_t payload_block_count = 0;
    auto estimated_records = normalized_filesystem_records;
    for (const auto& data : request.data_writes)
    {
        if (data.file_private_id == 0 || data.bytes.empty() ||
            data.logical_address % nxsb.block_size != 0 ||
            data.bytes.size() > std::numeric_limits<std::size_t>::max() -
                (nxsb.block_size - 1))
        {
            return Fail(out_error, "AppleVolumeTransactionDataInvalid");
        }
        maximum_fs_oid = (std::max)(maximum_fs_oid, data.file_private_id);
        const auto blocks =
            (data.bytes.size() + nxsb.block_size - 1) / nxsb.block_size;
        if (blocks > std::numeric_limits<std::size_t>::max() -
                payload_block_count)
        {
            return Fail(out_error, "AppleVolumeTransactionDataInvalid");
        }
        payload_block_count += blocks;
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
    if (maximum_fs_oid == kFsObjectIdMask)
    {
        return Fail(out_error, "AppleVolumeTransactionObjectIdExhausted");
    }
    const auto old_next_oid =
        catalog::ReadU64LE(apsb_bytes, 0xB0).value_or(0);
    const auto first_child_oid = (std::max)(old_next_oid,
        maximum_fs_oid + 1);
    const auto fs_order =
        (volume.superblock.incompatible_features &
            catalog::kIncompatCaseInsensitive) != 0
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
        auto estimated_extentref_records = extentref_records;
        auto placeholder_block = nxsb.block_count;
        for (const auto& data : request.data_writes)
        {
            const auto blocks =
                (data.bytes.size() + nxsb.block_size - 1) / nxsb.block_size;
            for (std::size_t ordinal = 0; ordinal < blocks; ++ordinal)
            {
                ApplePhysicalExtentRecord extent;
                extent.physical_block = placeholder_block++;
                extent.block_count = 1;
                extent.kind = kApplePhysicalExtentKindNew;
                extent.owning_object_id = data.file_private_id;
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
        extentref_node_count = estimated_extentref_tree.objects.size();
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

    std::vector<AppleSpacemanReleaseRequest> data_releases;
    data_releases.reserve(removed_file_extents.size());
    for (const auto& use : removed_file_extents)
    {
        if (use.extent.physical_block == 0) continue;
        data_releases.push_back({
            use.extent.physical_block,
            use.extent.length_bytes / nxsb.block_size,
        });
    }
    std::vector<AppleSpacemanReleaseRequest> releases = data_releases;
    AddReleaseBlocks(releases, old_fs_blocks);
    if (rewrite_extentrefs)
    {
        AddReleaseBlocks(releases, old_extentref_blocks);
    }
    AddReleaseBlocks(releases, old_volume_omap_blocks);
    releases.push_back({volume.object_map.object.physical_block, 1});
    releases.push_back({volume.superblock_object.physical_block, 1});
    AddReleaseBlocks(releases, old_container_omap_blocks);
    releases.push_back(
        {checkpoint.container_object_map.object.physical_block, 1});
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

    const auto volume_omap_node_count =
        estimated_volume_omap_tree.objects.size();
    const auto container_omap_node_count =
        estimated_container_omap_tree.objects.size();
    const auto total_main_blocks = payload_block_count + fs_node_count +
        extentref_node_count +
        volume_omap_node_count + 2 + container_omap_node_count + 1;
    AppleSpacemanAllocationRequest allocation_request;
    allocation_request.expected_checkpoint_xid = nxsb.xid;
    allocation_request.transaction_xid = nxsb.next_xid;
    allocation_request.main_block_count = total_main_blocks;
    allocation_request.first_ephemeral_object_id = nxsb.next_oid;
    allocation_request.released_blocks = releases;
    std::vector<AppleRecoveryCheckpointView> retained;
    if (!LoadAppleRecoveryCheckpoints(source, checkpoint,
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
    AppleSpacemanAllocationPlan allocation;
    if (!PlanAppleSpacemanAllocation(checkpoint.spaceman,
            allocation_request, allocation, out_error))
    {
        return false;
    }
    if (allocation.allocated_main_blocks.size() != total_main_blocks)
    {
        return Fail(out_error, "AppleVolumeTransactionAllocationInvalid");
    }

    std::size_t cursor = 0;
    std::vector<AppleCheckpointPhysicalWrite> writes;
    std::vector<catalog::BtreeRecord> filesystem_records =
        normalized_filesystem_records;
    std::vector<std::uint64_t> payload_blocks;
    payload_blocks.reserve(payload_block_count);
    for (const auto& data : request.data_writes)
    {
        const auto blocks =
            (data.bytes.size() + nxsb.block_size - 1) / nxsb.block_size;
        for (std::size_t ordinal = 0; ordinal < blocks; ++ordinal)
        {
            const auto physical_block =
                allocation.allocated_main_blocks[cursor++];
            payload_blocks.push_back(physical_block);
            std::vector<std::byte> bytes(nxsb.block_size, std::byte{0});
            const auto source_offset = ordinal * nxsb.block_size;
            const auto count = (std::min)(
                static_cast<std::size_t>(nxsb.block_size),
                data.bytes.size() - source_offset);
            std::copy_n(data.bytes.begin() +
                    static_cast<std::ptrdiff_t>(source_offset),
                count, bytes.begin());
            writes.push_back({physical_block, std::move(bytes)});

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
            physical_extent.owning_object_id = data.file_private_id;
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

    const auto fs_blocks_begin = allocation.allocated_main_blocks.begin() +
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

    AppleSerializedBtree extentref_tree;
    if (rewrite_extentrefs)
    {
        const auto extentref_blocks_begin =
            allocation.allocated_main_blocks.begin() +
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
        allocation.allocated_main_blocks.begin() +
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
        allocation.allocated_main_blocks[cursor++];
    std::vector<std::byte> new_volume_omap;
    if (!PatchAppleObjectMap(volume_omap_bytes, volume_omap_block,
            nxsb.next_xid, volume_omap_tree.root_physical_block,
            new_volume_omap, out_error))
    {
        return false;
    }
    writes.push_back({volume_omap_block, new_volume_omap});

    const auto apsb_block = allocation.allocated_main_blocks[cursor++];
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
    const auto new_volume_blocks = payload_block_count + fs_node_count +
        extentref_node_count +
        volume_omap_node_count + 2;
    const auto old_volume_blocks = old_fs_blocks.size() +
        (rewrite_extentrefs ? old_extentref_blocks.size() : 0) +
        old_volume_omap_blocks.size() + 2;
    if (!ReplaceAllocationCount(
            catalog::ReadU64LE(apsb_bytes, 0x58).value_or(0),
            new_volume_blocks,
            old_volume_blocks + released_data_block_count,
            accounting.file_system_allocated_blocks))
    {
        return Fail(out_error, "AppleVolumeTransactionAccountingInvalid");
    }
    const auto old_total_allocated =
        catalog::ReadU64LE(apsb_bytes, 0xE0).value_or(0);
    const auto old_total_freed =
        catalog::ReadU64LE(apsb_bytes, 0xE8).value_or(0);
    if (new_volume_blocks > std::numeric_limits<std::uint64_t>::max() -
            old_total_allocated ||
        old_volume_blocks + released_data_block_count >
            std::numeric_limits<std::uint64_t>::max() - old_total_freed)
    {
        return Fail(out_error, "AppleVolumeTransactionAccountingInvalid");
    }
    accounting.total_blocks_allocated =
        old_total_allocated + new_volume_blocks;
    accounting.total_blocks_freed = old_total_freed + old_volume_blocks +
        released_data_block_count;
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
        allocation.allocated_main_blocks.begin() +
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
        allocation.allocated_main_blocks[cursor++];
    std::vector<std::byte> new_container_omap;
    if (!PatchAppleObjectMap(container_omap_bytes, container_omap_block,
            nxsb.next_xid, container_omap_tree.root_physical_block,
            new_container_omap, out_error))
    {
        return false;
    }
    writes.push_back({container_omap_block, new_container_omap});
    if (cursor != allocation.allocated_main_blocks.size())
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
        std::vector<FileExtentUse> staged_file_extents;
        std::vector<FileExtentUse> staged_removed_extents;
        std::vector<PhysicalExtentState> staged_physical_extents;
        if (!CollectFileExtentChanges(filesystem_records,
                filesystem_records, nxsb.block_size, staged_file_extents,
                staged_removed_extents, out_error) ||
            !DecodePhysicalExtentTree(round_trip_extentrefs, nxsb.block_count,
                staged_physical_extents, out_error) ||
            !ValidatePhysicalExtentCoverage(staged_file_extents,
                staged_physical_extents, nxsb.block_count, out_error))
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
    if (!PlanAppleTransactionCommit(
            source, checkpoint, commit_request, commit, out_error))
    {
        return false;
    }
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

} // namespace apfsaccess::rw
