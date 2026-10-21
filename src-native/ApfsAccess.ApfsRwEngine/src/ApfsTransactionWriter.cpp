#include "ApfsTransactionWriter.h"

#include <algorithm>
#include <iterator>
#include <limits>
#include <tuple>
#include <unordered_set>
#include <utility>

namespace apfsaccess::rw
{
namespace
{

constexpr std::size_t kBtreeNodeHeaderBytes = 0x38;
constexpr std::size_t kBtreeInfoBytes = 40;
constexpr std::uint16_t kBtreeNodeRoot = 0x0001;
constexpr std::uint16_t kBtreeNodeLeaf = 0x0002;
constexpr std::uint16_t kBtreeNodeFixedKv = 0x0004;
constexpr std::uint64_t kFsObjectIdMask = (1ull << 60) - 1;
constexpr std::uint64_t kFileExtentLengthMask = 0x00FFFFFFFFFFFFFFull;
constexpr std::size_t kMaximumFsKeyBytes = 832;
constexpr std::size_t kMaximumFsValueBytes = 3808;
constexpr std::size_t kMaximumEmbeddedXattrBytes = 3804;

bool Fail(std::string& out_error, const char* error)
{
    out_error = error;
    return false;
}

bool IsPowerOfTwo(std::uint32_t value)
{
    return value != 0 && (value & (value - 1)) == 0;
}

std::size_t AlignUp(std::size_t value, std::size_t alignment)
{
    const auto remainder = value % alignment;
    return remainder == 0 ? value : value + (alignment - remainder);
}

void PutU16(std::vector<std::byte>& bytes, std::size_t offset, std::uint16_t value)
{
    bytes[offset] = static_cast<std::byte>(value & 0xffu);
    bytes[offset + 1] = static_cast<std::byte>((value >> 8) & 0xffu);
}

void PutU32(std::vector<std::byte>& bytes, std::size_t offset, std::uint32_t value)
{
    for (std::size_t index = 0; index < 4; ++index)
    {
        bytes[offset + index] = static_cast<std::byte>((value >> (index * 8)) & 0xffu);
    }
}

void PutU64(std::vector<std::byte>& bytes, std::size_t offset, std::uint64_t value)
{
    for (std::size_t index = 0; index < 8; ++index)
    {
        bytes[offset + index] = static_cast<std::byte>((value >> (index * 8)) & 0xffu);
    }
}

void AppendU16(std::vector<std::byte>& bytes, std::uint16_t value)
{
    const auto offset = bytes.size();
    bytes.resize(offset + 2);
    PutU16(bytes, offset, value);
}

void AppendU32(std::vector<std::byte>& bytes, std::uint32_t value)
{
    const auto offset = bytes.size();
    bytes.resize(offset + 4);
    PutU32(bytes, offset, value);
}

void AppendU64(std::vector<std::byte>& bytes, std::uint64_t value)
{
    const auto offset = bytes.size();
    bytes.resize(offset + 8);
    PutU64(bytes, offset, value);
}

int CompareBytes(
    const std::vector<std::byte>& left,
    std::size_t left_start,
    std::size_t left_length,
    const std::vector<std::byte>& right,
    std::size_t right_start,
    std::size_t right_length)
{
    const auto common = (std::min)(left_length, right_length);
    for (std::size_t index = 0; index < common; ++index)
    {
        const auto lhs = std::to_integer<unsigned char>(left[left_start + index]);
        const auto rhs = std::to_integer<unsigned char>(right[right_start + index]);
        if (lhs != rhs)
        {
            return lhs < rhs ? -1 : 1;
        }
    }
    if (left_length == right_length)
    {
        return 0;
    }
    return left_length < right_length ? -1 : 1;
}

bool ValidateName(const std::string& name, std::size_t maximum_bytes, std::string& out_error)
{
    if (name.empty() || name.size() > maximum_bytes ||
        name.find('\0') != std::string::npos)
    {
        return Fail(out_error, "AppleRecordNameInvalid");
    }
    return true;
}

bool MakeFsKey(std::uint64_t object_id, std::uint8_t record_type,
    std::vector<std::byte>& out_key, std::string& out_error)
{
    if (object_id == 0 || object_id > kFsObjectIdMask || record_type == 0 || record_type > 13)
    {
        return Fail(out_error, "AppleRecordObjectIdInvalid");
    }
    out_key.clear();
    AppendU64(out_key, (static_cast<std::uint64_t>(record_type) << 60) | object_id);
    return true;
}

bool ValidateFsKey(const std::vector<std::byte>& key,
    AppleBtreeKeyOrder order, std::string& out_error)
{
    if (key.size() < 8 || key.size() > kMaximumFsKeyBytes)
    {
        return Fail(out_error, "AppleBtreeFsKeyInvalid");
    }
    const auto key_header = catalog::ReadU64LE(key, 0).value_or(0);
    const auto object_id = key_header & kFsObjectIdMask;
    const auto record_type = static_cast<std::uint8_t>(key_header >> 60);
    if (object_id == 0 || record_type == 0 || record_type > 13)
    {
        return Fail(out_error, "AppleBtreeFsKeyInvalid");
    }
    if (record_type == 4 || record_type == 11)
    {
        const auto length = catalog::ReadU16LE(key, 8).value_or(0);
        if (length == 0 || key.size() != 10 + length || key.back() != std::byte{0} ||
            (record_type == 11 && object_id != kFsObjectIdMask))
        {
            return Fail(out_error, record_type == 4 ?
                "AppleBtreeXattrKeyInvalid" : "AppleBtreeSnapshotNameKeyInvalid");
        }
    }
    else if (record_type == 9)
    {
        if (order == AppleBtreeKeyOrder::FileSystemHashedDirectory)
        {
            const auto packed = catalog::ReadU32LE(key, 8).value_or(0);
            const auto length = packed & 0x3ffu;
            if (length == 0 || key.size() != 12 + length || key.back() != std::byte{0})
            {
                return Fail(out_error, "AppleBtreeDirectoryKeyInvalid");
            }
        }
        else
        {
            const auto length = catalog::ReadU16LE(key, 8).value_or(0);
            if (length == 0 || key.size() != 10 + length || key.back() != std::byte{0})
            {
                return Fail(out_error, "AppleBtreeDirectoryKeyInvalid");
            }
        }
    }
    else if ((record_type == 5 || record_type == 8 || record_type == 13) && key.size() != 16)
    {
        return Fail(out_error, "AppleBtreeFsKeyInvalid");
    }
    else if ((record_type == 1 || record_type == 2 || record_type == 3 ||
              record_type == 6 || record_type == 7 || record_type == 10 ||
              record_type == 12) && key.size() != 8)
    {
        return Fail(out_error, "AppleBtreeFsKeyInvalid");
    }
    return true;
}

int CompareFsKeys(const std::vector<std::byte>& left,
    const std::vector<std::byte>& right, AppleBtreeKeyOrder order)
{
    const auto left_header = catalog::ReadU64LE(left, 0).value();
    const auto right_header = catalog::ReadU64LE(right, 0).value();
    const auto left_identity = std::make_tuple(left_header & kFsObjectIdMask, left_header >> 60);
    const auto right_identity = std::make_tuple(right_header & kFsObjectIdMask, right_header >> 60);
    if (left_identity != right_identity)
    {
        return left_identity < right_identity ? -1 : 1;
    }
    const auto record_type = static_cast<std::uint8_t>(left_header >> 60);
    if (record_type == 4 || record_type == 11)
    {
        return CompareBytes(left, 10, left.size() - 11, right, 10, right.size() - 11);
    }
    if (record_type == 9)
    {
        if (order == AppleBtreeKeyOrder::FileSystemHashedDirectory)
        {
            const auto left_hash = catalog::ReadU32LE(left, 8).value() >> 10;
            const auto right_hash = catalog::ReadU32LE(right, 8).value() >> 10;
            if (left_hash != right_hash)
            {
                return left_hash < right_hash ? -1 : 1;
            }
            return CompareBytes(left, 12, left.size() - 13, right, 12, right.size() - 13);
        }
        return CompareBytes(left, 10, left.size() - 11, right, 10, right.size() - 11);
    }
    if ((record_type == 5 || record_type == 8 || record_type == 13) && left.size() == 16)
    {
        const auto lhs = catalog::ReadU64LE(left, 8).value();
        const auto rhs = catalog::ReadU64LE(right, 8).value();
        if (lhs != rhs)
        {
            return lhs < rhs ? -1 : 1;
        }
        return 0;
    }
    return CompareBytes(left, 8, left.size() - 8, right, 8, right.size() - 8);
}

int CompareKeys(const std::vector<std::byte>& left,
    const std::vector<std::byte>& right, AppleBtreeKeyOrder order)
{
    if (order == AppleBtreeKeyOrder::ObjectMap ||
        order == AppleBtreeKeyOrder::SpacemanFreeQueue)
    {
        const auto left_pair = std::make_pair(
            catalog::ReadU64LE(left, 0).value(), catalog::ReadU64LE(left, 8).value());
        const auto right_pair = std::make_pair(
            catalog::ReadU64LE(right, 0).value(), catalog::ReadU64LE(right, 8).value());
        if (left_pair == right_pair)
        {
            return 0;
        }
        return left_pair < right_pair ? -1 : 1;
    }
    if (order == AppleBtreeKeyOrder::PhysicalExtent || order == AppleBtreeKeyOrder::SnapshotObjectMap)
    {
        const auto lhs = catalog::ReadU64LE(left, 0).value();
        const auto rhs = catalog::ReadU64LE(right, 0).value();
        if (lhs == rhs)
        {
            return 0;
        }
        return lhs < rhs ? -1 : 1;
    }
    if (order == AppleBtreeKeyOrder::FileSystemCaseSensitive ||
        order == AppleBtreeKeyOrder::FileSystemHashedDirectory)
    {
        return CompareFsKeys(left, right, order);
    }
    return CompareBytes(left, 0, left.size(), right, 0, right.size());
}

bool EncodeExtendedFields(const std::vector<AppleExtendedField>& fields,
    std::vector<std::byte>& out_blob, std::string& out_error)
{
    out_blob.clear();
    if (fields.empty())
    {
        return true;
    }
    if (fields.size() > std::numeric_limits<std::uint16_t>::max())
    {
        return Fail(out_error, "AppleExtendedFieldCountInvalid");
    }
    auto ordered = fields;
    std::sort(ordered.begin(), ordered.end(), [](const auto& left, const auto& right) {
        return left.type < right.type;
    });
    std::size_t value_bytes = 0;
    std::uint8_t previous_type = 0;
    for (const auto& field : ordered)
    {
        if (field.type == 0 || field.type == previous_type ||
            field.data.size() > std::numeric_limits<std::uint16_t>::max())
        {
            return Fail(out_error, "AppleExtendedFieldInvalid");
        }
        previous_type = field.type;
        const auto padded = AlignUp(field.data.size(), 8);
        if (padded < field.data.size() || value_bytes > std::numeric_limits<std::uint16_t>::max() - padded)
        {
            return Fail(out_error, "AppleExtendedFieldSizeInvalid");
        }
        value_bytes += padded;
    }
    const auto descriptor_bytes = ordered.size() * 4;
    const auto used_data = descriptor_bytes + value_bytes;
    if (used_data > std::numeric_limits<std::uint16_t>::max())
    {
        return Fail(out_error, "AppleExtendedFieldSizeInvalid");
    }
    AppendU16(out_blob, static_cast<std::uint16_t>(ordered.size()));
    AppendU16(out_blob, static_cast<std::uint16_t>(used_data));
    for (const auto& field : ordered)
    {
        out_blob.push_back(static_cast<std::byte>(field.type));
        out_blob.push_back(static_cast<std::byte>(field.flags));
        AppendU16(out_blob, static_cast<std::uint16_t>(field.data.size()));
    }
    for (const auto& field : ordered)
    {
        out_blob.insert(out_blob.end(), field.data.begin(), field.data.end());
        out_blob.insert(out_blob.end(), AlignUp(field.data.size(), 8) - field.data.size(), std::byte{0});
    }
    return true;
}

bool NodeUsesFixedKv(const AppleBtreeOptions& options, bool leaf)
{
    return options.fixed_key_size != 0 && (!leaf || options.fixed_value_size != 0);
}

std::size_t StoredLength(std::size_t length, bool aligned)
{
    return aligned ? AlignUp(length, 8) : length;
}

bool NodeFits(const std::vector<catalog::BtreeRecord>& records,
    bool root, bool leaf, const AppleBtreeOptions& options)
{
    const bool fixed = NodeUsesFixedKv(options, leaf);
    const bool aligned = (options.tree_flags & kAppleBtreeKvNonAligned) == 0;
    const auto raw_table_bytes = records.size() * (fixed ? 4u : 8u);
    const auto table_bytes = aligned ? AlignUp(raw_table_bytes, 8) : raw_table_bytes;
    std::size_t used = kBtreeNodeHeaderBytes + table_bytes + (root ? kBtreeInfoBytes : 0);
    for (const auto& record : records)
    {
        const auto expected_value_size = leaf ? options.fixed_value_size : sizeof(std::uint64_t);
        const bool ghost = leaf && record.value.empty();
        if (ghost && (options.tree_flags & kAppleBtreeAllowGhosts) == 0)
        {
            return false;
        }
        if ((options.fixed_key_size != 0 && record.key.size() != options.fixed_key_size) ||
            (!ghost && expected_value_size != 0 && record.value.size() != expected_value_size))
        {
            return false;
        }
        if (record.key.size() > std::numeric_limits<std::uint16_t>::max() ||
            record.value.size() > std::numeric_limits<std::uint16_t>::max())
        {
            return false;
        }
        const auto key_bytes = StoredLength(record.key.size(), aligned);
        const auto value_bytes = StoredLength(record.value.size(), aligned);
        if (used > options.block_size || key_bytes > options.block_size - used)
        {
            return false;
        }
        used += key_bytes;
        if (used > options.block_size || value_bytes > options.block_size - used)
        {
            return false;
        }
        used += value_bytes;
    }
    return used <= options.block_size;
}

struct PendingTreeNode
{
    std::uint64_t object_id = 0;
    std::uint64_t physical_block = 0;
    std::uint16_t level = 0;
    std::vector<catalog::BtreeRecord> records;
};

bool BuildNode(const PendingTreeNode& node, bool root,
    const AppleBtreeOptions& options, std::uint32_t longest_key,
    std::uint32_t longest_value, std::uint64_t leaf_key_count,
    std::uint64_t node_count, AppleSerializedObject& out_object,
    std::string& out_error)
{
    const bool leaf = node.level == 0;
    if (!NodeFits(node.records, root, leaf, options))
    {
        return Fail(out_error, "AppleBtreeNodeOverflow");
    }
    const bool fixed = NodeUsesFixedKv(options, leaf);
    const bool aligned = (options.tree_flags & kAppleBtreeKvNonAligned) == 0;
    const auto entry_size = fixed ? 4u : 8u;
    const auto raw_table_bytes = node.records.size() * entry_size;
    const auto table_bytes = aligned ? AlignUp(raw_table_bytes, 8) : raw_table_bytes;
    if (table_bytes > std::numeric_limits<std::uint16_t>::max())
    {
        return Fail(out_error, "AppleBtreeTableOverflow");
    }

    std::vector<std::byte> bytes(options.block_size, std::byte{0});
    PutU64(bytes, 0x08, node.object_id);
    PutU64(bytes, 0x10, options.xid);
    const auto base_type = root ? catalog::kObjectTypeBtree : catalog::kObjectTypeBtreeNode;
    PutU32(bytes, 0x18, options.storage_type | base_type);
    PutU32(bytes, 0x1C, options.subtype);
    std::uint16_t node_flags = 0;
    if (root)
    {
        node_flags |= kBtreeNodeRoot;
    }
    if (leaf)
    {
        node_flags |= kBtreeNodeLeaf;
    }
    if (fixed)
    {
        node_flags |= kBtreeNodeFixedKv;
    }
    PutU16(bytes, 0x20, node_flags);
    PutU16(bytes, 0x22, node.level);
    PutU32(bytes, 0x24, static_cast<std::uint32_t>(node.records.size()));
    PutU16(bytes, 0x28, 0);
    PutU16(bytes, 0x2A, static_cast<std::uint16_t>(table_bytes));

    const auto info_start = root ? options.block_size - kBtreeInfoBytes : options.block_size;
    const auto key_area_start = kBtreeNodeHeaderBytes + table_bytes;
    std::size_t key_cursor = key_area_start;
    std::size_t value_cursor = info_start;
    for (std::size_t index = 0; index < node.records.size(); ++index)
    {
        const auto& record = node.records[index];
        const bool ghost = leaf && record.value.empty();
        const auto key_span = StoredLength(record.key.size(), aligned);
        const auto value_span = ghost ? 0 : StoredLength(record.value.size(), aligned);
        if (!ghost)
        {
            value_cursor -= value_span;
        }
        const auto key_offset = key_cursor - key_area_start;
        const auto value_offset = ghost ? std::numeric_limits<std::uint16_t>::max() :
            info_start - value_cursor;
        if (key_offset > std::numeric_limits<std::uint16_t>::max() ||
            value_offset > std::numeric_limits<std::uint16_t>::max())
        {
            return Fail(out_error, "AppleBtreeEntryOffsetOverflow");
        }
        const auto toc = kBtreeNodeHeaderBytes + index * entry_size;
        PutU16(bytes, toc, static_cast<std::uint16_t>(key_offset));
        if (fixed)
        {
            PutU16(bytes, toc + 2, static_cast<std::uint16_t>(value_offset));
        }
        else
        {
            PutU16(bytes, toc + 2, static_cast<std::uint16_t>(record.key.size()));
            PutU16(bytes, toc + 4, static_cast<std::uint16_t>(value_offset));
            PutU16(bytes, toc + 6, static_cast<std::uint16_t>(record.value.size()));
        }
        std::copy(record.key.begin(), record.key.end(), bytes.begin() + key_cursor);
        if (!ghost)
        {
            std::copy(record.value.begin(), record.value.end(), bytes.begin() + value_cursor);
        }
        key_cursor += key_span;
    }
    if (key_cursor > value_cursor)
    {
        return Fail(out_error, "AppleBtreeNodeOverlap");
    }
    const auto key_used = key_cursor - key_area_start;
    const auto free_bytes = value_cursor - key_cursor;
    if (key_used > std::numeric_limits<std::uint16_t>::max() ||
        free_bytes > std::numeric_limits<std::uint16_t>::max())
    {
        return Fail(out_error, "AppleBtreeFreeSpaceOverflow");
    }
    PutU16(bytes, 0x2C, static_cast<std::uint16_t>(key_used));
    PutU16(bytes, 0x2E, static_cast<std::uint16_t>(free_bytes));
    PutU16(bytes, 0x30, std::numeric_limits<std::uint16_t>::max());
    PutU16(bytes, 0x34, std::numeric_limits<std::uint16_t>::max());

    if (root)
    {
        PutU32(bytes, info_start, options.tree_flags);
        PutU32(bytes, info_start + 4, options.block_size);
        PutU32(bytes, info_start + 8, options.fixed_key_size);
        PutU32(bytes, info_start + 12, options.fixed_value_size);
        PutU32(bytes, info_start + 16, longest_key);
        PutU32(bytes, info_start + 20, longest_value);
        PutU64(bytes, info_start + 24, leaf_key_count);
        PutU64(bytes, info_start + 32, node_count);
    }
    if (!FinalizeAppleObjectChecksum(bytes, out_error))
    {
        return false;
    }
    out_object.location.object_id = node.object_id;
    out_object.location.xid = options.xid;
    out_object.location.physical_block = node.physical_block;
    out_object.location.type = options.storage_type | base_type;
    out_object.location.subtype = options.subtype;
    out_object.location.size_bytes = options.block_size;
    out_object.bytes = std::move(bytes);
    return true;
}

bool NextChildIdentity(const AppleBtreeOptions& options, std::size_t child_index,
    std::uint64_t& out_oid, std::uint64_t& out_block, std::string& out_error)
{
    if (!options.child_object_ids.empty() || !options.child_physical_blocks.empty())
    {
        if (options.child_object_ids.size() != options.child_physical_blocks.size() ||
            child_index >= options.child_object_ids.size())
        {
            return Fail(out_error, "AppleBtreeChildAllocationInvalid");
        }
        out_oid = options.child_object_ids[child_index];
        out_block = options.child_physical_blocks[child_index];
        if (out_oid == 0 || out_block == 0)
        {
            return Fail(out_error, "AppleBtreeChildAllocationInvalid");
        }
        for (std::size_t index = 0; index < child_index; ++index)
        {
            if (options.child_object_ids[index] == out_oid ||
                options.child_physical_blocks[index] == out_block)
            {
                return Fail(out_error, "AppleBtreeAllocationOverlap");
            }
        }
    }
    else
    {
        if (options.first_child_object_id == 0 ||
            options.first_child_physical_block == 0 ||
            child_index > std::numeric_limits<std::uint64_t>::max() -
                options.first_child_object_id ||
            child_index > std::numeric_limits<std::uint64_t>::max() -
                options.first_child_physical_block)
        {
            return Fail(out_error, "AppleBtreeChildAllocationInvalid");
        }
        out_oid = options.first_child_object_id + child_index;
        out_block = options.first_child_physical_block + child_index;
    }
    if (out_oid == options.root_object_id || out_block == options.root_physical_block)
    {
        return Fail(out_error, "AppleBtreeAllocationOverlap");
    }
    if ((options.storage_type & catalog::kObjectStorageTypeMask) == catalog::kObjectPhysical &&
        out_oid != out_block)
    {
        return Fail(out_error, "AppleBtreePhysicalIdentityInvalid");
    }
    return true;
}

} // namespace

bool SortAppleBtreeRecords(std::vector<catalog::BtreeRecord>& records,
    AppleBtreeKeyOrder order, std::string& out_error)
{
    out_error.clear();
    for (const auto& record : records)
    {
        if (record.key.empty())
        {
            return Fail(out_error, "AppleBtreeKeyEmpty");
        }
        if (order == AppleBtreeKeyOrder::ObjectMap)
        {
            if (record.key.size() != 16 || record.value.size() != 16)
            {
                return Fail(out_error, "AppleBtreeOmapRecordInvalid");
            }
        }
        else if (order == AppleBtreeKeyOrder::SpacemanFreeQueue)
        {
            if (record.key.size() != 16 ||
                (!record.value.empty() && record.value.size() != 8) ||
                catalog::ReadU64LE(record.key, 0).value_or(0) == 0 ||
                catalog::ReadU64LE(record.key, 8).value_or(0) == 0 ||
                (!record.value.empty() &&
                    catalog::ReadU64LE(record.value, 0).value_or(0) <= 1))
            {
                return Fail(out_error, "AppleBtreeFreeQueueRecordInvalid");
            }
        }
        else if (order == AppleBtreeKeyOrder::SnapshotObjectMap)
        {
            if (record.key.size()!=8 || record.value.size()!=16 ||
                catalog::ReadU64LE(record.key,0).value_or(0)==0 ||
                catalog::ReadU64LE(record.value,0).value_or(1)!=0 ||
                catalog::ReadU64LE(record.value,8).value_or(1)!=0)
                return Fail(out_error,"AppleBtreeSnapshotOmapRecordUnsupported");
        }
        else if (order == AppleBtreeKeyOrder::PhysicalExtent)
        {
            ApplePhysicalExtentRecord decoded;
            if (!DecodeApplePhysicalExtentRecord(record, decoded, out_error))
            {
                return false;
            }
        }
        else if (order == AppleBtreeKeyOrder::FileSystemCaseSensitive ||
            order == AppleBtreeKeyOrder::FileSystemHashedDirectory)
        {
            if (!ValidateFsKey(record.key, order, out_error) ||
                record.value.size() > kMaximumFsValueBytes)
            {
                if (out_error.empty())
                {
                    out_error = "AppleBtreeFsValueInvalid";
                }
                return false;
            }
        }
    }
    std::sort(records.begin(), records.end(), [order](const auto& left, const auto& right) {
        return CompareKeys(left.key, right.key, order) < 0;
    });
    for (std::size_t index = 1; index < records.size(); ++index)
    {
        if (CompareKeys(records[index - 1].key, records[index].key, order) == 0)
        {
            return Fail(out_error, "AppleBtreeDuplicateKey");
        }
    }
    return true;
}

bool FinalizeAppleObjectChecksum(std::vector<std::byte>& object, std::string& out_error)
{
    out_error.clear();
    if (object.size() < 12 || object.size() % sizeof(std::uint32_t) != 0)
    {
        return Fail(out_error, "AppleObjectSizeInvalid");
    }
    std::fill(object.begin(), object.begin() + 8, std::byte{0});
    const auto checksum = catalog::Fletcher64(object.data() + 8, object.size() - 8);
    if (!checksum.has_value())
    {
        return Fail(out_error, "AppleObjectChecksumFailed");
    }
    PutU64(object, 0, checksum.value());
    if (!catalog::VerifyObjectChecksum(object, object.size()))
    {
        return Fail(out_error, "AppleObjectChecksumSelfCheckFailed");
    }
    return true;
}

bool SerializeAppleBtree(const std::vector<catalog::BtreeRecord>& records,
    const AppleBtreeOptions& options, AppleSerializedBtree& out_tree,
    std::string& out_error)
{
    out_tree = {};
    out_error.clear();
    constexpr std::uint32_t kSupportedTreeFlags =
        kAppleBtreeUint64Keys | kAppleBtreeSequentialInsert | kAppleBtreeAllowGhosts |
        kAppleBtreeEphemeral | kAppleBtreePhysical | kAppleBtreeKvNonAligned;
    if (!IsPowerOfTwo(options.block_size) || options.block_size < 4096 ||
        options.block_size > 65536)
    {
        return Fail(out_error, "AppleBtreeBlockSizeInvalid");
    }
    if (options.xid == 0)
    {
        return Fail(out_error, "AppleBtreeXidInvalid");
    }
    if (options.root_object_id == 0 || options.root_physical_block == 0)
    {
        return Fail(out_error, "AppleBtreeRootIdentityInvalid");
    }
    if (options.max_nodes == 0 || options.max_nodes > 4096)
    {
        return Fail(out_error, "AppleBtreeNodeLimitInvalid");
    }
    if ((options.tree_flags & ~kSupportedTreeFlags) != 0)
    {
        return Fail(out_error, "AppleBtreeFlagsInvalid");
    }
    if ((options.storage_type & ~catalog::kObjectStorageTypeMask) != 0 ||
        (options.storage_type != 0 &&
         options.storage_type != catalog::kObjectPhysical &&
         options.storage_type != catalog::kObjectEphemeral))
    {
        return Fail(out_error, "AppleBtreeStorageTypeInvalid");
    }
    if (options.child_object_ids.size() != options.child_physical_blocks.size())
    {
        return Fail(out_error, "AppleBtreeChildAllocationInvalid");
    }
    if (options.fixed_key_size > std::numeric_limits<std::uint16_t>::max() ||
        options.fixed_value_size > std::numeric_limits<std::uint16_t>::max())
    {
        return Fail(out_error, "AppleBtreeFixedSizeInvalid");
    }
    const auto storage = options.storage_type & catalog::kObjectStorageTypeMask;
    if ((storage == catalog::kObjectPhysical) !=
            ((options.tree_flags & kAppleBtreePhysical) != 0) ||
        (storage == catalog::kObjectEphemeral) !=
            ((options.tree_flags & kAppleBtreeEphemeral) != 0) ||
        (storage == catalog::kObjectPhysical &&
            options.root_object_id != options.root_physical_block))
    {
        return Fail(out_error, "AppleBtreeStoragePolicyInvalid");
    }

    auto sorted = records;
    if (!SortAppleBtreeRecords(sorted, options.key_order, out_error))
    {
        return false;
    }
    std::uint32_t longest_key = 0;
    std::uint32_t longest_value = 0;
    for (const auto& record : sorted)
    {
        longest_key = (std::max)(longest_key, static_cast<std::uint32_t>(record.key.size()));
        longest_value = (std::max)(longest_value, static_cast<std::uint32_t>(record.value.size()));
    }
    longest_key = (std::max)(longest_key, options.minimum_longest_key);
    longest_value = (std::max)(longest_value, options.minimum_longest_value);

    PendingTreeNode root;
    root.object_id = options.root_object_id;
    root.physical_block = options.root_physical_block;
    root.level = 0;
    if (NodeFits(sorted, true, true, options))
    {
        root.records = sorted;
    }
    else
    {
        std::vector<PendingTreeNode> nonroot_nodes;
        auto level_records = sorted;
        std::uint16_t level = 0;
        while (true)
        {
            std::vector<PendingTreeNode> level_nodes;
            std::size_t cursor = 0;
            while (cursor < level_records.size())
            {
                PendingTreeNode node;
                node.level = level;
                while (cursor < level_records.size())
                {
                    auto candidate = node.records;
                    candidate.push_back(level_records[cursor]);
                    if (!NodeFits(candidate, false, level == 0, options))
                    {
                        break;
                    }
                    node.records.push_back(level_records[cursor]);
                    ++cursor;
                }
                if (node.records.empty())
                {
                    return Fail(out_error, "AppleBtreeRecordTooLarge");
                }
                const auto allocation_index = nonroot_nodes.size() + level_nodes.size();
                if (allocation_index >= options.max_nodes - 1 ||
                    !NextChildIdentity(options, allocation_index,
                        node.object_id, node.physical_block, out_error))
                {
                    if (out_error.empty())
                    {
                        out_error = "AppleBtreeNodeLimitExceeded";
                    }
                    return false;
                }
                level_nodes.push_back(std::move(node));
            }

            std::vector<catalog::BtreeRecord> parents;
            parents.reserve(level_nodes.size());
            for (const auto& child : level_nodes)
            {
                catalog::BtreeRecord parent;
                parent.key = child.records.front().key;
                AppendU64(parent.value, child.object_id);
                parents.push_back(std::move(parent));
            }
            nonroot_nodes.insert(nonroot_nodes.end(),
                std::make_move_iterator(level_nodes.begin()),
                std::make_move_iterator(level_nodes.end()));
            if (level == std::numeric_limits<std::uint16_t>::max())
            {
                return Fail(out_error, "AppleBtreeHeightOverflow");
            }
            ++level;
            if (NodeFits(parents, true, false, options))
            {
                root.level = level;
                root.records = std::move(parents);
                const auto node_count = static_cast<std::uint64_t>(nonroot_nodes.size() + 1);
                AppleSerializedBtree built;
                built.root_object_id = root.object_id;
                built.root_physical_block = root.physical_block;
                built.height = static_cast<std::uint16_t>(root.level + 1);
                built.objects.reserve(static_cast<std::size_t>(node_count));
                for (const auto& node : nonroot_nodes)
                {
                    AppleSerializedObject object;
                    if (!BuildNode(node, false, options, longest_key, longest_value,
                            sorted.size(), node_count, object, out_error))
                    {
                        return false;
                    }
                    built.objects.push_back(std::move(object));
                }
                AppleSerializedObject root_object;
                if (!BuildNode(root, true, options, longest_key, longest_value,
                        sorted.size(), node_count, root_object, out_error))
                {
                    return false;
                }
                built.objects.push_back(std::move(root_object));
                out_tree = std::move(built);
                return true;
            }
            level_records = std::move(parents);
        }
    }

    AppleSerializedBtree built;
    built.root_object_id = root.object_id;
    built.root_physical_block = root.physical_block;
    built.height = 1;
    AppleSerializedObject root_object;
    if (!BuildNode(root, true, options, longest_key, longest_value,
            sorted.size(), 1, root_object, out_error))
    {
        return false;
    }
    built.objects.push_back(std::move(root_object));
    out_tree = std::move(built);
    return true;
}

bool EncodeAppleOmapRecord(const AppleOmapRecord& value,
    catalog::BtreeRecord& out_record, std::string& out_error)
{
    out_record = {};
    out_error.clear();
    const bool deleted = (value.flags & kAppleOmapValueDeleted) != 0;
    if (value.object_id == 0 || value.xid == 0 ||
        (!deleted && (value.size_bytes == 0 || value.physical_block == 0)) ||
        (deleted && (value.size_bytes != 0 || value.physical_block != 0)))
    {
        return Fail(out_error, "AppleOmapRecordInvalid");
    }
    AppendU64(out_record.key, value.object_id);
    AppendU64(out_record.key, value.xid);
    AppendU32(out_record.value, value.flags);
    AppendU32(out_record.value, value.size_bytes);
    AppendU64(out_record.value, value.physical_block);
    return true;
}

bool EncodeAppleInodeRecord(const AppleInodeRecord& value,
    catalog::BtreeRecord& out_record, std::string& out_error)
{
    out_record = {};
    out_error.clear();
    if (!MakeFsKey(value.object_id, 3, out_record.key, out_error) ||
        value.parent_id == 0 || value.private_id == 0 || value.children_or_links < 0)
    {
        if (out_error.empty())
        {
            out_error = "AppleInodeRecordInvalid";
        }
        return false;
    }
    AppendU64(out_record.value, value.parent_id);
    AppendU64(out_record.value, value.private_id);
    AppendU64(out_record.value, value.create_time);
    AppendU64(out_record.value, value.modification_time);
    AppendU64(out_record.value, value.change_time);
    AppendU64(out_record.value, value.access_time);
    AppendU64(out_record.value, value.internal_flags);
    AppendU32(out_record.value, static_cast<std::uint32_t>(value.children_or_links));
    AppendU32(out_record.value, value.default_protection_class);
    AppendU32(out_record.value, value.write_generation);
    AppendU32(out_record.value, value.bsd_flags);
    AppendU32(out_record.value, value.owner);
    AppendU32(out_record.value, value.group);
    AppendU16(out_record.value, value.mode);
    AppendU16(out_record.value, value.reserved_pad);
    AppendU64(out_record.value, value.uncompressed_size);
    std::vector<std::byte> extended;
    if (!EncodeExtendedFields(value.extended_fields, extended, out_error))
    {
        out_record = {};
        return false;
    }
    out_record.value.insert(out_record.value.end(), extended.begin(), extended.end());
    if (out_record.value.size() > kMaximumFsValueBytes)
    {
        out_record = {};
        return Fail(out_error, "AppleInodeRecordTooLarge");
    }
    return true;
}

bool EncodeAppleDirectoryRecord(const AppleDirectoryRecord& value,
    catalog::BtreeRecord& out_record, std::string& out_error)
{
    out_record = {};
    out_error.clear();
    if (!MakeFsKey(value.parent_id, 9, out_record.key, out_error) ||
        value.file_id == 0 || !ValidateName(value.name_utf8, 1022, out_error))
    {
        if (out_error.empty())
        {
            out_error = "AppleDirectoryRecordInvalid";
        }
        out_record = {};
        return false;
    }
    const auto name_length = value.name_utf8.size() + 1;
    if (value.hashed_name)
    {
        if (name_length > 0x3ffu || value.name_hash > 0x3fffffu)
        {
            out_record = {};
            return Fail(out_error, "AppleDirectoryHashInvalid");
        }
        AppendU32(out_record.key,
            (value.name_hash << 10) | static_cast<std::uint32_t>(name_length));
    }
    else
    {
        if (name_length > std::numeric_limits<std::uint16_t>::max())
        {
            out_record = {};
            return Fail(out_error, "AppleDirectoryNameInvalid");
        }
        AppendU16(out_record.key, static_cast<std::uint16_t>(name_length));
    }
    for (const char character : value.name_utf8)
    {
        out_record.key.push_back(static_cast<std::byte>(static_cast<unsigned char>(character)));
    }
    out_record.key.push_back(std::byte{0});
    AppendU64(out_record.value, value.file_id);
    AppendU64(out_record.value, value.date_added);
    AppendU16(out_record.value, value.flags);
    std::vector<std::byte> extended;
    if (!EncodeExtendedFields(value.extended_fields, extended, out_error))
    {
        out_record = {};
        return false;
    }
    out_record.value.insert(out_record.value.end(), extended.begin(), extended.end());
    if (out_record.key.size() > kMaximumFsKeyBytes ||
        out_record.value.size() > kMaximumFsValueBytes)
    {
        out_record = {};
        return Fail(out_error, "AppleDirectoryRecordTooLarge");
    }
    return true;
}

bool EncodeAppleDirectoryRecord(const AppleDirectoryRecord& value,
    const ApfsNamePolicy& name_policy,
    catalog::BtreeRecord& out_record, std::string& out_error)
{
    const auto bytes = std::span(
        reinterpret_cast<const std::byte*>(value.name_utf8.data()),
        value.name_utf8.size());
    const auto decoded = ApfsNameCodec::Decode(bytes, name_policy);
    if (!decoded.ok())
    {
        out_record = {};
        out_error = "AppleDirectoryNameInvalid:" + decoded.detail;
        return false;
    }

    AppleDirectoryRecord canonical = value;
    canonical.hashed_name = name_policy.UsesHashedDirectoryKeys();
    canonical.name_hash = decoded.value->directory_hash.value_or(0);
    return EncodeAppleDirectoryRecord(canonical, out_record, out_error);
}

bool EncodeAppleFileExtentRecord(const AppleFileExtentRecord& value,
    catalog::BtreeRecord& out_record, std::string& out_error)
{
    out_record = {};
    out_error.clear();
    if (!MakeFsKey(value.object_id, 8, out_record.key, out_error) ||
        value.block_size == 0 || !IsPowerOfTwo(value.block_size) ||
        value.length_bytes == 0 || value.length_bytes > kFileExtentLengthMask ||
        (value.physical_block == 0 && value.crypto_id != 0) || value.logical_address % value.block_size != 0 ||
        value.length_bytes % value.block_size != 0)
    {
        if (out_error.empty())
        {
            out_error = "AppleFileExtentRecordInvalid";
        }
        out_record = {};
        return false;
    }
    AppendU64(out_record.key, value.logical_address);
    AppendU64(out_record.value, value.length_bytes);
    AppendU64(out_record.value, value.physical_block);
    AppendU64(out_record.value, value.crypto_id);
    return true;
}

static bool DecodeFileExtentFields(const catalog::BtreeRecord& record,
    std::uint32_t block_size, std::uint8_t allowed_flags, AppleFileExtentRecord& out_value,
    std::uint8_t& out_flags, std::string& out_error)
{
    out_value = {};
    out_flags = 0;
    out_error.clear();
    if (record.key.size() != 16 || record.value.size() != 24)
        return Fail(out_error, "AppleFileExtentRecordInvalid");
    const auto flags = static_cast<std::uint8_t>(catalog::ReadU64LE(record.value, 0).value() >> 56);
    if ((flags & ~allowed_flags) != 0)
        return Fail(out_error, allowed_flags ? "AppleEncryptedFileExtentFlagsUnsupported" : "AppleFileExtentRecordInvalid");
    const auto header = catalog::ReadU64LE(record.key, 0).value_or(0);
    AppleFileExtentRecord decoded{
        header & kFsObjectIdMask,
        catalog::ReadU64LE(record.key, 8).value_or(0),
        catalog::ReadU64LE(record.value, 0).value_or(0) & kFileExtentLengthMask,
        catalog::ReadU64LE(record.value, 8).value_or(0),
        catalog::ReadU64LE(record.value, 16).value_or(0),
        block_size};
    if ((header >> 60) != 8 || decoded.object_id == 0 || block_size == 0 || !IsPowerOfTwo(block_size) ||
        decoded.length_bytes == 0 || (decoded.physical_block == 0 && decoded.crypto_id != 0) ||
        decoded.logical_address % block_size != 0 || decoded.length_bytes % block_size != 0 ||
        decoded.length_bytes > std::numeric_limits<std::uint64_t>::max() - decoded.logical_address ||
        decoded.length_bytes / block_size > std::numeric_limits<std::uint64_t>::max() - decoded.physical_block)
        return Fail(out_error, "AppleFileExtentRecordInvalid");
    out_value = decoded;
    out_flags = flags;
    return true;
}

bool DecodeAppleFileExtentRecord(const catalog::BtreeRecord& record,
    std::uint32_t block_size, AppleFileExtentRecord& out_value, std::string& out_error)
{
    std::uint8_t flags = 0;
    return DecodeFileExtentFields(record, block_size, 0, out_value, flags, out_error);
}

static bool ValidateEncryptedExtent(const AppleEncryptedFileExtentRecord& value,
    AppleEncryptedExtentProfile profile, std::string& out_error)
{
    if (profile != AppleEncryptedExtentProfile::OneKeyGenerationZero)
        return Fail(out_error, "AppleEncryptedFileExtentProfileUnsupported");
    if ((value.flags & ~1u) != 0)
        return Fail(out_error, "AppleEncryptedFileExtentFlagsUnsupported");
    const auto& extent = value.extent;
    if (extent.block_size < 4096 || extent.block_size > 65536 || !IsPowerOfTwo(extent.block_size))
        return Fail(out_error, "AppleEncryptedFileExtentBlockSizeInvalid");
    constexpr auto maximum = std::numeric_limits<std::uint64_t>::max();
    if (extent.length_bytes == 0 || extent.length_bytes % extent.block_size != 0 ||
        extent.length_bytes > maximum - extent.logical_address ||
        extent.length_bytes / extent.block_size > maximum - extent.physical_block)
        return Fail(out_error, "AppleFileExtentRecordInvalid");
    if (extent.physical_block == 0)
        return extent.crypto_id == 0 || Fail(out_error, "AppleEncryptedFileExtentCryptoIdInvalid");
    const auto blocks = extent.length_bytes / extent.block_size;
    const auto units = static_cast<std::uint64_t>(extent.block_size / 512);
    if (!extent.crypto_id || blocks - 1 > maximum - extent.crypto_id ||
        extent.crypto_id + blocks - 1 > (maximum - (units - 1)) / units)
        return Fail(out_error, "AppleEncryptedFileExtentCryptoIdInvalid");
    return true;
}

bool EncodeAppleEncryptedFileExtentRecord(const AppleEncryptedFileExtentRecord& value,
    AppleEncryptedExtentProfile profile, catalog::BtreeRecord& out_record, std::string& out_error)
{
    out_record = {};
    out_error.clear();
    if (!ValidateEncryptedExtent(value, profile, out_error) ||
        !EncodeAppleFileExtentRecord(value.extent, out_record, out_error))
        return false;
    PutU64(out_record.value, 0, value.extent.length_bytes | (static_cast<std::uint64_t>(value.flags) << 56));
    return true;
}

bool DecodeAppleEncryptedFileExtentRecord(const catalog::BtreeRecord& record,
    std::uint32_t block_size, AppleEncryptedExtentProfile profile,
    AppleEncryptedFileExtentRecord& out_value, std::string& out_error)
{
    out_value = {};
    out_error.clear();
    if (profile != AppleEncryptedExtentProfile::OneKeyGenerationZero)
        return Fail(out_error, "AppleEncryptedFileExtentProfileUnsupported");
    AppleEncryptedFileExtentRecord decoded;
    if (!DecodeFileExtentFields(record, block_size, 1, decoded.extent, decoded.flags, out_error) ||
        !ValidateEncryptedExtent(decoded, profile, out_error))
        return false;
    out_value = decoded;
    return true;
}

bool EncodeAppleDataStreamIdRecord(const AppleDataStreamIdRecord& value,
    catalog::BtreeRecord& out_record, std::string& out_error)
{
    out_record = {};
    out_error.clear();
    if (!MakeFsKey(value.object_id, 6, out_record.key, out_error) ||
        value.reference_count == 0)
    {
        out_record = {};
        return Fail(out_error, "AppleDataStreamIdRecordInvalid");
    }
    AppendU32(out_record.value, value.reference_count);
    return true;
}

bool DecodeAppleDataStreamIdRecord(const catalog::BtreeRecord& record,
    AppleDataStreamIdRecord& out_value, std::string& out_error)
{
    out_value = {};
    out_error.clear();
    if (record.key.size() != 8 || record.value.size() != 4)
    {
        return Fail(out_error, "AppleDataStreamIdRecordInvalid");
    }
    const auto header = catalog::ReadU64LE(record.key, 0).value_or(0);
    const auto reference_count =
        catalog::ReadU32LE(record.value, 0).value_or(0);
    const auto object_id = header & kFsObjectIdMask;
    if ((header >> 60) != 6 || object_id == 0 || reference_count == 0)
    {
        return Fail(out_error, "AppleDataStreamIdRecordInvalid");
    }
    out_value.object_id = object_id;
    out_value.reference_count = reference_count;
    return true;
}

bool EncodeApplePhysicalExtentRecord(const ApplePhysicalExtentRecord& value,
    catalog::BtreeRecord& out_record, std::string& out_error)
{
    out_record = {};
    out_error.clear();
    if (value.physical_block == 0 || value.physical_block > kFsObjectIdMask ||
        value.block_count == 0 || value.block_count > kFsObjectIdMask ||
        value.physical_block > kFsObjectIdMask - (value.block_count - 1) ||
        (value.kind != kApplePhysicalExtentKindNew &&
         value.kind != kApplePhysicalExtentKindUpdate) ||
        value.owning_object_id == 0 ||
        value.owning_object_id > kFsObjectIdMask ||
        (value.kind == kApplePhysicalExtentKindNew && value.reference_count <= 0))
    {
        return Fail(out_error, "ApplePhysicalExtentRecordInvalid");
    }

    AppendU64(out_record.key,
        (2ull << 60) | value.physical_block);
    AppendU64(out_record.value,
        (static_cast<std::uint64_t>(value.kind) << 60) |
            value.block_count);
    AppendU64(out_record.value, value.owning_object_id);
    AppendU32(out_record.value,
        static_cast<std::uint32_t>(value.reference_count));
    return true;
}

bool DecodeApplePhysicalExtentRecord(const catalog::BtreeRecord& record,
    ApplePhysicalExtentRecord& out_value, std::string& out_error)
{
    out_value = {};
    out_error.clear();
    if (record.key.size() != 8 || record.value.size() != 20)
    {
        return Fail(out_error, "ApplePhysicalExtentRecordInvalid");
    }
    const auto header = catalog::ReadU64LE(record.key, 0).value_or(0);
    const auto len_and_kind =
        catalog::ReadU64LE(record.value, 0).value_or(0);
    ApplePhysicalExtentRecord decoded;
    decoded.physical_block = header & kFsObjectIdMask;
    decoded.block_count = len_and_kind & kFsObjectIdMask;
    decoded.kind = static_cast<std::uint8_t>(len_and_kind >> 60);
    decoded.owning_object_id =
        catalog::ReadU64LE(record.value, 8).value_or(0);
    decoded.reference_count = static_cast<std::int32_t>(
        catalog::ReadU32LE(record.value, 16).value_or(0));
    if ((header >> 60) != 2 || decoded.physical_block == 0 ||
        decoded.block_count == 0 ||
        decoded.physical_block > kFsObjectIdMask -
            (decoded.block_count - 1) ||
        (decoded.kind != kApplePhysicalExtentKindNew &&
         decoded.kind != kApplePhysicalExtentKindUpdate) ||
        decoded.owning_object_id == 0 ||
        decoded.owning_object_id > kFsObjectIdMask ||
        (decoded.kind == kApplePhysicalExtentKindNew && decoded.reference_count <= 0))
    {
        return Fail(out_error, "ApplePhysicalExtentRecordInvalid");
    }
    out_value = decoded;
    return true;
}

bool EncodeAppleSiblingLinkRecord(const AppleSiblingLinkRecord& value,
    catalog::BtreeRecord& out_record, std::string& out_error)
{
    out_record = {};
    out_error.clear();
    if (!MakeFsKey(value.inode_id, 5, out_record.key, out_error) ||
        value.sibling_id == 0 || value.parent_id == 0 ||
        !ValidateName(value.name_utf8, kMaximumFsValueBytes - 11, out_error))
    {
        if (out_error.empty())
        {
            out_error = "AppleSiblingLinkInvalid";
        }
        out_record = {};
        return false;
    }
    AppendU64(out_record.key, value.sibling_id);
    AppendU64(out_record.value, value.parent_id);
    AppendU16(out_record.value, static_cast<std::uint16_t>(value.name_utf8.size() + 1));
    for (const char character : value.name_utf8)
    {
        out_record.value.push_back(static_cast<std::byte>(static_cast<unsigned char>(character)));
    }
    out_record.value.push_back(std::byte{0});
    return true;
}

bool EncodeAppleSiblingMapRecord(const AppleSiblingMapRecord& value,
    catalog::BtreeRecord& out_record, std::string& out_error)
{
    out_record = {};
    out_error.clear();
    if (!MakeFsKey(value.sibling_id, 12, out_record.key, out_error) || value.file_id == 0)
    {
        if (out_error.empty())
        {
            out_error = "AppleSiblingMapInvalid";
        }
        out_record = {};
        return false;
    }
    AppendU64(out_record.value, value.file_id);
    return true;
}

bool EncodeAppleXattrRecord(const AppleXattrRecord& value,
    catalog::BtreeRecord& out_record, std::string& out_error)
{
    out_record = {};
    out_error.clear();
    const auto storage_flags = value.flags & (kAppleXattrDataStream | kAppleXattrDataEmbedded);
    constexpr std::uint16_t kSupportedFlags =
        kAppleXattrDataStream | kAppleXattrDataEmbedded | kAppleXattrFileSystemOwned;
    const auto stream_id = storage_flags == kAppleXattrDataStream
        ? catalog::ReadU64LE(value.data, 0).value_or(0) : 0;
    if (!MakeFsKey(value.object_id, 4, out_record.key, out_error) ||
        !ValidateName(value.name_utf8, kMaximumFsKeyBytes - 11, out_error) ||
        (value.flags & ~kSupportedFlags) != 0 ||
        (storage_flags != kAppleXattrDataStream && storage_flags != kAppleXattrDataEmbedded) ||
        value.data.size() > std::numeric_limits<std::uint16_t>::max() ||
        (storage_flags == kAppleXattrDataStream &&
            (value.data.size() != kAppleXattrDataStreamBytes || stream_id == 0 || stream_id > kFsObjectIdMask)) ||
        (storage_flags == kAppleXattrDataEmbedded &&
            value.data.size() > kMaximumEmbeddedXattrBytes))
    {
        if (out_error.empty())
        {
            out_error = "AppleXattrRecordInvalid";
        }
        out_record = {};
        return false;
    }
    AppendU16(out_record.key, static_cast<std::uint16_t>(value.name_utf8.size() + 1));
    for (const char character : value.name_utf8)
    {
        out_record.key.push_back(static_cast<std::byte>(static_cast<unsigned char>(character)));
    }
    out_record.key.push_back(std::byte{0});
    AppendU16(out_record.value, value.flags);
    AppendU16(out_record.value, storage_flags == kAppleXattrDataEmbedded ?
        static_cast<std::uint16_t>(value.data.size()) : 0);
    out_record.value.insert(out_record.value.end(), value.data.begin(), value.data.end());
    return true;
}

bool PatchAppleObjectMap(const std::vector<std::byte>& original,
    std::uint64_t physical_block, std::uint64_t xid,
    std::uint64_t tree_physical_block,
    std::vector<std::byte>& out_object_map, std::string& out_error)
{
    out_object_map.clear();
    out_error.clear();
    if (original.size() < 0x40 ||
        !catalog::VerifyObjectChecksum(original, original.size()) ||
        catalog::ReadU64LE(original, 0x08).value_or(0) == 0 ||
        xid <= catalog::ReadU64LE(original, 0x10).value_or(0) ||
        catalog::ReadU32LE(original, 0x18).value_or(0) !=
            (catalog::kObjectPhysical | catalog::kObjectTypeOmap) ||
        catalog::ReadU32LE(original, 0x28).value_or(0) !=
            (catalog::kObjectPhysical | catalog::kObjectTypeBtree) ||
        catalog::ReadU64LE(original, 0x30).value_or(0) == 0 ||
        physical_block == 0 || tree_physical_block == 0 ||
        physical_block == tree_physical_block)
    {
        return Fail(out_error, "AppleObjectMapUpdateInvalid");
    }
    out_object_map = original;
    PutU64(out_object_map, 0x08, physical_block);
    PutU64(out_object_map, 0x10, xid);
    PutU64(out_object_map, 0x30, tree_physical_block);
    if (!FinalizeAppleObjectChecksum(out_object_map, out_error))
    {
        out_object_map.clear();
        return false;
    }
    if (catalog::ReadU64LE(out_object_map, 0x08).value_or(0) !=
            physical_block ||
        catalog::ReadU64LE(out_object_map, 0x10).value_or(0) != xid ||
        catalog::ReadU64LE(out_object_map, 0x30).value_or(0) !=
            tree_physical_block)
    {
        out_object_map.clear();
        return Fail(out_error, "AppleObjectMapUpdateSelfCheckFailed");
    }
    return true;
}

bool PatchAppleVolumeSuperblock(const std::vector<std::byte>& original,
    const AppleVolumeAccountingUpdate& update,
    std::vector<std::byte>& out_superblock, std::string& out_error)
{
    out_superblock.clear();
    out_error.clear();
    const auto parsed = catalog::ParseApsb(original);
    if (!parsed.has_value() || original.size() < 0x108 ||
        update.xid <= parsed->xid || update.root_tree_object_id == 0 ||
        update.extentref_tree_object_id == 0 || update.next_object_id == 0 ||
        update.next_object_id < catalog::ReadU64LE(original, 0xB0).value_or(0) ||
        update.total_blocks_allocated < catalog::ReadU64LE(original, 0xE0).value_or(0) ||
        update.total_blocks_freed < catalog::ReadU64LE(original, 0xE8).value_or(0) ||
        update.total_blocks_freed > update.total_blocks_allocated)
    {
        return Fail(out_error, "AppleVolumeAccountingInvalid");
    }
    out_superblock = original;
    PutU64(out_superblock, 0x10, update.xid);
    PutU64(out_superblock, 0x58, update.file_system_allocated_blocks);
    if (update.object_map_object_id != 0)
    {
        PutU64(out_superblock, 0x80, update.object_map_object_id);
    }
    PutU64(out_superblock, 0x88, update.root_tree_object_id);
    PutU64(out_superblock, 0x90, update.extentref_tree_object_id);
    PutU64(out_superblock, 0x98, update.snapshot_metadata_tree_object_id);
    PutU64(out_superblock, 0xB0, update.next_object_id);
    PutU64(out_superblock, 0xB8, update.file_count);
    PutU64(out_superblock, 0xC0, update.directory_count);
    PutU64(out_superblock, 0xC8, update.symlink_count);
    PutU64(out_superblock, 0xD0, update.other_object_count);
    PutU64(out_superblock, 0xD8, update.snapshot_count);
    PutU64(out_superblock, 0xE0, update.total_blocks_allocated);
    PutU64(out_superblock, 0xE8, update.total_blocks_freed);
    PutU64(out_superblock, 0x100, update.last_modification_time);
    if (!FinalizeAppleObjectChecksum(out_superblock, out_error))
    {
        out_superblock.clear();
        return false;
    }
    const auto reparsed = catalog::ParseApsb(out_superblock);
    const auto expected_object_map = update.object_map_object_id != 0 ?
        update.object_map_object_id : parsed->omap_oid;
    if (!reparsed.has_value() || reparsed->xid != update.xid ||
        reparsed->omap_oid != expected_object_map ||
        reparsed->root_oid != update.root_tree_object_id ||
        reparsed->extentref_tree_oid != update.extentref_tree_object_id ||
        reparsed->snap_meta_tree_oid != update.snapshot_metadata_tree_object_id)
    {
        out_superblock.clear();
        return Fail(out_error, "AppleVolumeAccountingSelfCheckFailed");
    }
    return true;
}

} // namespace apfsaccess::rw
