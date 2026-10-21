#include "ApfsFormat.h"
#include "ApfsNameCodec.h"
#include "ApfsTransactionWriter.h"
#include "RandomAccessSource.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <limits>
#include <string>
#include <string_view>
#include <vector>

namespace
{
using apfsaccess::catalog::BtreeReadPolicy;
using apfsaccess::catalog::BtreeRecord;
using apfsaccess::catalog::ReadBtreeLeafRecords;
using apfsaccess::catalog::ReadU16LE;
using apfsaccess::catalog::ReadU32LE;
using apfsaccess::catalog::ReadU64LE;
using apfsaccess::catalog::VectorRandomAccessSource;
using namespace apfsaccess::rw;

int g_failures = 0;

bool Require(bool condition, const std::string& message)
{
    if (!condition)
    {
        std::cerr << "[FAIL] " << message << std::endl;
        ++g_failures;
    }
    return condition;
}

void PutU32(std::vector<std::byte>& bytes, std::size_t offset, std::uint32_t value)
{
    for (std::size_t index = 0; index < 4; ++index)
    {
        bytes[offset + index] = static_cast<std::byte>((value >> (index * 8)) & 0xffu);
    }
}

void PutU16(std::vector<std::byte>& bytes, std::size_t offset, std::uint16_t value)
{
    for (std::size_t index = 0; index < 2; ++index)
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

std::vector<std::byte> Bytes(const std::string& text)
{
    std::vector<std::byte> bytes;
    bytes.reserve(text.size());
    for (const char value : text)
    {
        bytes.push_back(static_cast<std::byte>(static_cast<unsigned char>(value)));
    }
    return bytes;
}

bool SameRecord(const BtreeRecord& left, const BtreeRecord& right)
{
    return left.key == right.key && left.value == right.value;
}

std::vector<std::byte> Materialize(const AppleSerializedBtree& tree, std::uint32_t block_size)
{
    std::uint64_t maximum_block = 0;
    for (const auto& object : tree.objects)
    {
        maximum_block = (std::max)(maximum_block, object.location.physical_block);
    }
    if (maximum_block > 4096)
    {
        return {};
    }
    std::vector<std::byte> image(
        static_cast<std::size_t>(maximum_block + 1) * block_size, std::byte{0});
    for (const auto& object : tree.objects)
    {
        const auto offset = static_cast<std::size_t>(object.location.physical_block) * block_size;
        std::copy(object.bytes.begin(), object.bytes.end(), image.begin() + offset);
    }
    return image;
}

AppleBtreeOptions PhysicalOptions(AppleBtreeKeyOrder order, std::uint32_t subtype)
{
    AppleBtreeOptions options;
    options.block_size = 4096;
    options.xid = 77;
    options.root_object_id = 10;
    options.root_physical_block = 10;
    options.first_child_object_id = 20;
    options.first_child_physical_block = 20;
    options.storage_type = apfsaccess::catalog::kObjectPhysical;
    options.subtype = subtype;
    options.tree_flags = kAppleBtreePhysical;
    options.key_order = order;
    return options;
}

bool RoundTripPhysical(
    const AppleSerializedBtree& tree,
    const AppleBtreeOptions& options,
    const std::vector<BtreeRecord>& expected)
{
    const auto image = Materialize(tree, options.block_size);
    if (!Require(!image.empty(), "materialized tree image"))
    {
        return false;
    }
    VectorRandomAccessSource source(image);
    BtreeReadPolicy policy;
    policy.enforce_object_identity = true;
    policy.root_object_id = options.root_object_id;
    policy.storage_type = options.storage_type;
    policy.subtype = options.subtype;
    std::vector<BtreeRecord> records;
    std::string error;
    bool ok = Require(ReadBtreeLeafRecords(
        source,
        options.block_size,
        options.root_physical_block,
        true,
        0,
        options.xid,
        policy,
        records,
        error), "independent reader accepts serialized tree: " + error);
    ok &= Require(records.size() == expected.size(), "round-trip record count");
    if (records.size() == expected.size())
    {
        for (std::size_t index = 0; index < records.size(); ++index)
        {
            ok &= Require(SameRecord(records[index], expected[index]),
                "round-trip record " + std::to_string(index));
        }
    }
    return ok;
}

bool TestVariableTreeGrowthShrinkAndDeterminism()
{
    auto options = PhysicalOptions(
        AppleBtreeKeyOrder::FileSystemCaseSensitive,
        apfsaccess::catalog::kObjectTypeFsTree);
    std::vector<BtreeRecord> records;
    for (std::uint64_t index = 0; index < 420; ++index)
    {
        AppleFileExtentRecord extent;
        extent.object_id = 100 + (index / 3);
        extent.logical_address = (index % 3) * 4096;
        extent.length_bytes = 4096;
        extent.physical_block = 5000 + index;
        extent.block_size = 4096;
        BtreeRecord record;
        std::string error;
        if (!Require(EncodeAppleFileExtentRecord(extent, record, error),
                "encode file extent: " + error))
        {
            return false;
        }
        record.value.insert(record.value.end(), 32, static_cast<std::byte>(index & 0xffu));
        records.push_back(std::move(record));
    }
    std::reverse(records.begin(), records.end());

    AppleSerializedBtree first;
    AppleSerializedBtree second;
    std::string error;
    bool ok = Require(SerializeAppleBtree(records, options, first, error),
        "serialize split variable tree: " + error);
    ok &= Require(first.height >= 2 && first.objects.size() > 1,
        "variable tree grows past one root leaf");
    ok &= Require(SerializeAppleBtree(records, options, second, error),
        "serialize variable tree deterministically: " + error);
    ok &= Require(first.height == second.height && first.objects.size() == second.objects.size(),
        "deterministic tree shape");
    if (first.objects.size() == second.objects.size())
    {
        for (std::size_t index = 0; index < first.objects.size(); ++index)
        {
            ok &= Require(first.objects[index].location.object_id ==
                    second.objects[index].location.object_id &&
                    first.objects[index].bytes == second.objects[index].bytes,
                "deterministic object " + std::to_string(index));
        }
    }

    std::vector<BtreeRecord> sorted = records;
    ok &= Require(SortAppleBtreeRecords(sorted, options.key_order, error),
        "sort expected records: " + error);
    ok &= RoundTripPhysical(first, options, sorted);

    AppleSerializedBtree shrunk;
    ok &= Require(SerializeAppleBtree({sorted.front()}, options, shrunk, error),
        "serialize shrunk tree: " + error);
    ok &= Require(shrunk.height == 1 && shrunk.objects.size() == 1,
        "tree shrinks to one root leaf");
    ok &= Require((ReadU16LE(shrunk.objects.back().bytes, 0x20).value_or(0) & 0x3u) == 0x3u,
        "shrunk root carries root and leaf flags");
    return ok;
}

bool TestFixedOmapTreeAndTombstone()
{
    auto options = PhysicalOptions(
        AppleBtreeKeyOrder::ObjectMap,
        apfsaccess::catalog::kObjectTypeOmap);
    options.fixed_key_size = 16;
    options.fixed_value_size = 16;
    std::vector<BtreeRecord> records;
    for (std::uint64_t oid = 1; oid <= 360; ++oid)
    {
        AppleOmapRecord mapping;
        mapping.object_id = oid;
        mapping.xid = 50 + oid;
        mapping.size_bytes = 4096;
        mapping.physical_block = 1000 + oid;
        BtreeRecord record;
        std::string error;
        if (!Require(EncodeAppleOmapRecord(mapping, record, error),
                "encode object-map record: " + error))
        {
            return false;
        }
        records.push_back(std::move(record));
    }
    AppleOmapRecord deleted;
    deleted.object_id = 180;
    deleted.xid = 999;
    deleted.flags = kAppleOmapValueDeleted;
    BtreeRecord tombstone;
    std::string error;
    bool ok = Require(EncodeAppleOmapRecord(deleted, tombstone, error),
        "encode object-map tombstone: " + error);
    records.push_back(tombstone);
    options.xid = 999;

    AppleSerializedBtree tree;
    ok &= Require(SerializeAppleBtree(records, options, tree, error),
        "serialize fixed object-map tree: " + error);
    ok &= Require(tree.height >= 2, "fixed tree splits");
    std::vector<BtreeRecord> sorted = records;
    ok &= Require(SortAppleBtreeRecords(sorted, options.key_order, error),
        "sort object-map records: " + error);
    ok &= RoundTripPhysical(tree, options, sorted);
    if (!tree.objects.empty())
    {
        const auto& root = tree.objects.back().bytes;
        ok &= Require(ReadU32LE(root, root.size() - 40).value_or(0) == kAppleBtreePhysical,
            "root records physical-tree flag");
        ok &= Require(ReadU32LE(root, root.size() - 32).value_or(0) == 16,
            "root records fixed key size");
        ok &= Require(ReadU32LE(root, root.size() - 28).value_or(0) == 16,
            "root records fixed leaf value size");
        ok &= Require(ReadU64LE(root, root.size() - 16).value_or(0) == records.size(),
            "root records leaf key count");
        ok &= Require(ReadU64LE(root, root.size() - 8).value_or(0) == tree.objects.size(),
            "root records node count");
    }
    return ok;
}

bool TestMixedFixedAndVariableLayouts()
{
    auto fixed_keys = PhysicalOptions(AppleBtreeKeyOrder::Lexicographic,
        apfsaccess::catalog::kObjectTypeBlockRefTree);
    fixed_keys.fixed_key_size = 8;
    std::vector<BtreeRecord> records;
    for (std::uint64_t index = 0; index < 400; ++index)
    {
        BtreeRecord record;
        record.key.resize(8);
        PutU64(record.key, 0, index + 1);
        record.value.resize(13 + (index % 11), static_cast<std::byte>(index & 0xffu));
        records.push_back(std::move(record));
    }
    AppleSerializedBtree tree;
    std::string error;
    bool ok = Require(SerializeAppleBtree(records, fixed_keys, tree, error),
        "serialize fixed-key variable-value tree: " + error);
    ok &= Require(tree.height >= 2, "fixed-key variable-value tree splits");
    if (tree.objects.size() > 1)
    {
        ok &= Require((ReadU16LE(tree.objects.front().bytes, 0x20).value_or(0) & 0x4u) == 0,
            "variable-value leaf uses location table");
        ok &= Require((ReadU16LE(tree.objects.back().bytes, 0x20).value_or(0) & 0x4u) != 0,
            "fixed-key internal node uses offset table");
    }
    std::vector<BtreeRecord> sorted = records;
    ok &= Require(SortAppleBtreeRecords(sorted, fixed_keys.key_order, error),
        "sort fixed-key variable-value records");
    ok &= RoundTripPhysical(tree, fixed_keys, sorted);

    auto fixed_values = PhysicalOptions(AppleBtreeKeyOrder::Lexicographic,
        apfsaccess::catalog::kObjectTypeBlockRefTree);
    fixed_values.fixed_value_size = 16;
    records.clear();
    for (std::uint64_t index = 0; index < 360; ++index)
    {
        BtreeRecord record;
        record.key = Bytes("key-" + std::to_string(index));
        record.value.resize(16, static_cast<std::byte>(index & 0xffu));
        records.push_back(std::move(record));
    }
    ok &= Require(SerializeAppleBtree(records, fixed_values, tree, error),
        "serialize variable-key fixed-value tree: " + error);
    if (!tree.objects.empty())
    {
        for (const auto& object : tree.objects)
        {
            ok &= Require((ReadU16LE(object.bytes, 0x20).value_or(0) & 0x4u) == 0,
                "variable-key node uses location table");
        }
    }
    sorted = records;
    ok &= Require(SortAppleBtreeRecords(sorted, fixed_values.key_order, error),
        "sort variable-key fixed-value records");
    ok &= RoundTripPhysical(tree, fixed_values, sorted);
    return ok;
}

bool TestGhostsAndRootHistoryFields()
{
    auto options = PhysicalOptions(AppleBtreeKeyOrder::Lexicographic,
        apfsaccess::catalog::kObjectTypeSpacemanFreeQueue);
    options.tree_flags |= kAppleBtreeAllowGhosts;
    options.minimum_longest_key = 64;
    options.minimum_longest_value = 128;
    BtreeRecord ghost{Bytes("a"), {}};
    BtreeRecord live{Bytes("b"), Bytes("value")};
    AppleSerializedBtree tree;
    std::string error;
    bool ok = Require(SerializeAppleBtree({live, ghost}, options, tree, error),
        "serialize tree with ghost: " + error);
    if (!tree.objects.empty())
    {
        const auto& root = tree.objects.back().bytes;
        ok &= Require(ReadU16LE(root, 0x3c).value_or(0) == 0xffffu,
            "ghost uses invalid value offset");
        ok &= Require(ReadU16LE(root, 0x30).value_or(0) == 0xffffu &&
                ReadU16LE(root, 0x34).value_or(0) == 0xffffu,
            "empty free lists use invalid offsets");
        ok &= Require(ReadU32LE(root, root.size() - 24).value_or(0) == 64 &&
                ReadU32LE(root, root.size() - 20).value_or(0) == 128,
            "historical longest key and value sizes are preserved");
    }
    const auto image = Materialize(tree, options.block_size);
    VectorRandomAccessSource source(image);
    BtreeReadPolicy policy{true, options.root_object_id, options.storage_type, options.subtype};
    std::vector<BtreeRecord> visible;
    ok &= Require(ReadBtreeLeafRecords(source, options.block_size,
            options.root_physical_block, true, 0, options.xid,
            policy, visible, error), "reader accepts ghost tree: " + error);
    ok &= Require(visible.size() == 1 && SameRecord(visible.front(), live),
        "reader omits the ghost and preserves the live record");

    policy.include_ghost_records = true;
    visible.clear();
    ok &= Require(ReadBtreeLeafRecords(source, options.block_size,
            options.root_physical_block, true, 0, options.xid,
            policy, visible, error), "opt-in reader accepts ghost tree: " + error);
    ok &= Require(visible.size() == 2 && SameRecord(visible[0], ghost) &&
            SameRecord(visible[1], live),
        "opt-in reader retains ghost records for free-queue accounting");

    options.tree_flags &= ~kAppleBtreeAllowGhosts;
    ok &= Require(!SerializeAppleBtree({live, ghost}, options, tree, error),
        "empty value is rejected when ghosts are disabled");
    return ok;
}

bool TestEphemeralTreeUsesCheckpointMappedExplicitChildren()
{
    AppleBtreeOptions options;
    options.block_size = 4096;
    options.xid = 91;
    options.root_object_id = 900;
    options.root_physical_block = 10;
    options.storage_type = apfsaccess::catalog::kObjectEphemeral;
    options.subtype = apfsaccess::catalog::kObjectTypeSpacemanFreeQueue;
    options.tree_flags = kAppleBtreeEphemeral | kAppleBtreeAllowGhosts;
    options.fixed_key_size = 16;
    options.fixed_value_size = 8;
    options.key_order = AppleBtreeKeyOrder::SpacemanFreeQueue;
    for (std::uint64_t index = 0; index < 64; ++index)
    {
        options.child_object_ids.push_back(1000 + index);
        options.child_physical_blocks.push_back(50 + index * 3);
    }

    std::vector<BtreeRecord> records;
    for (std::uint64_t index = 0; index < 400; ++index)
    {
        BtreeRecord record;
        record.key.resize(16, std::byte{0});
        PutU64(record.key, 0, 70 + index / 100);
        PutU64(record.key, 8, 2000 + index);
        if ((index % 3) != 0)
        {
            record.value.resize(8, std::byte{0});
            PutU64(record.value, 0, 2);
        }
        records.push_back(std::move(record));
    }
    std::reverse(records.begin(), records.end());

    AppleSerializedBtree tree;
    std::string error;
    bool ok = Require(SerializeAppleBtree(records, options, tree, error),
        "serialize checkpoint-mapped ephemeral tree: " + error);
    ok &= Require(tree.objects.size() > 1,
        "ephemeral fixture grows child nodes");
    if (!ok)
    {
        return false;
    }

    const auto image = Materialize(tree, options.block_size);
    VectorRandomAccessSource source(image);
    apfsaccess::catalog::ContainerCheckpointView checkpoint;
    for (const auto& object : tree.objects)
    {
        if (object.location.object_id == options.root_object_id)
        {
            continue;
        }
        apfsaccess::catalog::CheckpointMapping mapping;
        mapping.type = object.location.type;
        mapping.subtype = object.location.subtype;
        mapping.size_bytes = object.location.size_bytes;
        mapping.object_id = object.location.object_id;
        mapping.physical_block = object.location.physical_block;
        checkpoint.mappings.push_back(mapping);
    }

    BtreeReadPolicy policy;
    policy.enforce_object_identity = true;
    policy.root_object_id = options.root_object_id;
    policy.storage_type = options.storage_type;
    policy.subtype = options.subtype;
    policy.include_ghost_records = true;
    policy.ephemeral_checkpoint = &checkpoint;
    std::vector<std::uint64_t> visited_blocks;
    policy.visited_physical_blocks = &visited_blocks;
    std::vector<BtreeRecord> visible;
    ok &= Require(ReadBtreeLeafRecords(source, options.block_size,
            options.root_physical_block, false, 0, options.xid,
            policy, visible, error),
        "reader resolves ephemeral children through checkpoint mappings: " + error);
    auto expected = records;
    ok &= Require(SortAppleBtreeRecords(expected, options.key_order, error),
        "sort expected free-queue records: " + error);
    ok &= Require(visible.size() == expected.size(),
        "mapped ephemeral tree retains every record");
    if (visible.size() == expected.size())
    {
        for (std::size_t index = 0; index < visible.size(); ++index)
        {
            ok &= Require(SameRecord(visible[index], expected[index]),
                "mapped ephemeral record " + std::to_string(index));
        }
    }
    ok &= Require(visited_blocks.size() == tree.objects.size() &&
            std::find(visited_blocks.begin(), visited_blocks.end(), 50) !=
                visited_blocks.end() &&
            std::find(visited_blocks.begin(), visited_blocks.end(), 53) !=
                visited_blocks.end(),
        "reader reports the exact non-contiguous tree blocks it consumed");
    return ok;
}

bool TestRecordEncoders()
{
    bool ok = true;
    std::string error;
    BtreeRecord record;
    std::vector<BtreeRecord> encoded_records;

    AppleInodeRecord inode;
    inode.object_id = 17;
    inode.parent_id = 2;
    inode.private_id = 117;
    inode.create_time = 100;
    inode.modification_time = 200;
    inode.change_time = 300;
    inode.access_time = 400;
    inode.children_or_links = 2;
    inode.write_generation = 9;
    inode.owner = 501;
    inode.group = 20;
    inode.mode = 0100644;
    inode.uncompressed_size = 8192;
    AppleExtendedField stream;
    stream.type = 8;
    stream.data.resize(40, std::byte{0});
    PutU64(stream.data, 0, 8192);
    PutU64(stream.data, 8, 8192);
    inode.extended_fields.push_back(stream);
    ok &= Require(EncodeAppleInodeRecord(inode, record, error), "inode encoding: " + error);
    ok &= Require(ReadU64LE(record.key, 0).value_or(0) == ((3ull << 60) | 17),
        "inode key layout");
    ok &= Require(record.value.size() == 0x5c + 4 + 4 + 40, "inode xfield layout size");
    ok &= Require(ReadU64LE(record.value, 0x08).value_or(0) == 117, "inode private id");
    ok &= Require(ReadU16LE(record.value, 0x50).value_or(0) == 0100644, "inode mode");
    ok &= Require(ReadU16LE(record.value, 0x5c).value_or(0) == 1, "inode xfield count");
    ok &= Require(ReadU16LE(record.value, 0x5e).value_or(0) == 44,
        "inode xfield used-data includes its descriptor table");
    encoded_records.push_back(record);
    inode.children_or_links = -1;
    ok &= Require(!EncodeAppleInodeRecord(inode, record, error),
        "negative inode child/link count rejected");

    AppleDirectoryRecord directory;
    directory.parent_id = 2;
    directory.file_id = 17;
    directory.date_added = 500;
    directory.flags = 8;
    directory.name_utf8 = "Report.txt";
    directory.name_hash = 0x12345;
    directory.hashed_name = true;
    const auto foldedNames = ApfsNamePolicy::FromIncompatibleFeatures(0x1);
    ok &= Require(EncodeAppleDirectoryRecord(directory, foldedNames, record, error),
        "hashed directory encoding: " + error);
    ok &= Require(ReadU64LE(record.key, 0).value_or(0) == ((9ull << 60) | 2),
        "directory key layout");
    ok &= Require((ReadU32LE(record.key, 8).value_or(0) & 0x3ffu) == 11,
        "directory key includes terminating nul length");
    ok &= Require((ReadU32LE(record.key, 8).value_or(0) >> 10) == 0x28c52d,
        "directory key includes codec-computed APFS hash");
    ok &= Require(record.key.back() == std::byte{0}, "directory name is nul terminated");
    ok &= Require(ReadU64LE(record.value, 0).value_or(0) == 17, "directory child id");
    encoded_records.push_back(record);

    AppleSiblingLinkRecord sibling;
    sibling.inode_id = 17;
    sibling.sibling_id = 700;
    sibling.parent_id = 2;
    sibling.name_utf8 = "Report.txt";
    ok &= Require(EncodeAppleSiblingLinkRecord(sibling, record, error),
        "sibling-link encoding: " + error);
    ok &= Require(ReadU64LE(record.key, 0).value_or(0) == ((5ull << 60) | 17),
        "sibling-link key layout");
    ok &= Require(ReadU64LE(record.key, 8).value_or(0) == 700, "sibling id");
    ok &= Require(ReadU64LE(record.value, 0).value_or(0) == 2, "sibling parent");
    encoded_records.push_back(record);
    sibling.name_utf8.assign(3800, 'x');
    ok &= Require(!EncodeAppleSiblingLinkRecord(sibling, record, error),
        "oversized sibling-link value rejected by its encoder");

    AppleSiblingMapRecord sibling_map{700, 17};
    ok &= Require(EncodeAppleSiblingMapRecord(sibling_map, record, error),
        "sibling-map encoding: " + error);
    ok &= Require(ReadU64LE(record.key, 0).value_or(0) == ((12ull << 60) | 700),
        "sibling-map key layout");
    ok &= Require(ReadU64LE(record.value, 0).value_or(0) == 17, "sibling-map inode");
    encoded_records.push_back(record);

    AppleXattrRecord xattr;
    xattr.object_id = 17;
    xattr.name_utf8 = "user.note";
    xattr.flags = kAppleXattrDataEmbedded;
    xattr.data = Bytes("hello");
    ok &= Require(EncodeAppleXattrRecord(xattr, record, error), "xattr encoding: " + error);
    ok &= Require(ReadU64LE(record.key, 0).value_or(0) == ((4ull << 60) | 17),
        "xattr key layout");
    ok &= Require(ReadU16LE(record.key, 8).value_or(0) == 10, "xattr name length");
    ok &= Require(ReadU16LE(record.value, 0).value_or(0) == kAppleXattrDataEmbedded,
        "xattr flags");
    ok &= Require(ReadU16LE(record.value, 2).value_or(0) == 5, "xattr value length");
    encoded_records.push_back(record);

    xattr.flags = kAppleXattrDataStream;
    xattr.data.assign(48, std::byte{0});
    PutU64(xattr.data, 0, 777);
    PutU64(xattr.data, 8, 8193);
    PutU64(xattr.data, 16, 12288);
    ok &= Require(EncodeAppleXattrRecord(xattr, record, error),
        "stream xattr encoding: " + error);
    ok &= Require(ReadU16LE(record.value, 2).value_or(1) == 0,
        "stream xattr leaves ignored embedded length zero");
    xattr.data.push_back(std::byte{0});
    ok &= Require(!EncodeAppleXattrRecord(xattr, record, error),
        "stream xattr requires one complete data-stream descriptor");

    AppleFileExtentRecord extent;
    extent.object_id = 117;
    extent.logical_address = 4096;
    extent.length_bytes = 8192;
    extent.physical_block = 900;
    extent.crypto_id = 4;
    extent.block_size = 4096;
    ok &= Require(EncodeAppleFileExtentRecord(extent, record, error),
        "file-extent encoding: " + error);
    ok &= Require(ReadU64LE(record.key, 0).value_or(0) == ((8ull << 60) | 117),
        "file-extent key layout");
    ok &= Require(ReadU64LE(record.value, 0).value_or(0) == 8192, "file-extent length");
    ok &= Require(ReadU64LE(record.value, 8).value_or(0) == 900, "file-extent block");
    encoded_records.push_back(record);

    ok &= Require(SortAppleBtreeRecords(
            encoded_records, AppleBtreeKeyOrder::FileSystemHashedDirectory, error),
        "sort mixed encoded records: " + error);
    auto options = PhysicalOptions(
        AppleBtreeKeyOrder::FileSystemHashedDirectory,
        apfsaccess::catalog::kObjectTypeFsTree);
    AppleSerializedBtree tree;
    ok &= Require(SerializeAppleBtree(encoded_records, options, tree, error),
        "serialize mixed encoded records: " + error);
    ok &= RoundTripPhysical(tree, options, encoded_records);
    return ok;
}

bool TestFileExtentDecodeIsStrict()
{
    AppleFileExtentRecord extent{117, 4096, 8192, 900, 4, 4096};
    BtreeRecord encoded;
    std::string error;
    if (!Require(EncodeAppleFileExtentRecord(extent, encoded, error), "strict extent fixture encodes"))
        return false;
    AppleFileExtentRecord decoded;
    bool ok = Require(DecodeAppleFileExtentRecord(encoded, 4096, decoded, error) &&
            decoded.object_id == 117 && decoded.logical_address == 4096 &&
            decoded.length_bytes == 8192 && decoded.physical_block == 900 && decoded.crypto_id == 4,
        "file extent decodes without losing any field");
    auto sparse = encoded;
    PutU64(sparse.value, 8, 0);
    PutU64(sparse.value, 16, 0);
    ok &= Require(DecodeAppleFileExtentRecord(sparse, 4096, decoded, error) &&
            decoded.physical_block == 0 && decoded.logical_address == 4096 && decoded.length_bytes == 8192,
        "sparse record retains its logical range without physical ownership");
    PutU64(sparse.value, 16, 4);
    ok &= Require(!DecodeAppleFileExtentRecord(sparse, 4096, decoded, error),
        "sparse record cannot carry a physical crypto identity");
    for (int mode = 0; mode < 13; ++mode)
    {
        auto invalid = encoded;
        std::uint32_t block_size = 4096;
        if (mode < 8) PutU64(invalid.value, 0, 8192ULL | (1ULL << (56 + mode)));
        else if (mode == 8) PutU64(invalid.key, 8, 0xfffffffffffff000ULL);
        else if (mode == 9) PutU64(invalid.value, 8, 0xffffffffffffffffULL);
        else if (mode == 10) invalid.key.push_back(std::byte{0});
        else if (mode == 11) invalid.value.pop_back();
        else block_size = 3;
        decoded = extent;
        ok &= Require(!DecodeAppleFileExtentRecord(invalid, block_size, decoded, error) &&
                decoded.object_id == 0 && decoded.length_bytes == 0,
            "flags/overflow/malformed extent must reject with empty output, mode=" + std::to_string(mode));
    }
    return ok;
}

bool TestEncryptedFileExtentCodec()
{
    constexpr auto profile = AppleEncryptedExtentProfile::OneKeyGenerationZero;
    const auto hex = [](std::string_view text) {
        std::vector<std::byte> bytes;
        const auto digit = [](char c) { return c <= '9' ? c - '0' : c - 'a' + 10; };
        for (std::size_t i = 0; i < text.size(); i += 2)
            bytes.push_back(static_cast<std::byte>((digit(text[i]) << 4) | digit(text[i + 1])));
        return bytes;
    };
    struct Fixture { const char* key; const char* value; std::uint64_t object_id, physical; };
    // Actual raw records from authenticated ciphertext images, not codec output.
    // native-filevault.raw SHA256 1a46eb22cdab37ae553c5c70b7b172419c9cda7285de7f5b4fd3129c73e29171
    // dfvfs-apfs-encrypted.dmg SHA256 33fe6f183aeb1a95fec68efdab17d59aedbad3d8ef1a117d411117376d9d8485
    const Fixture fixtures[] = {
        {"10000000000000800000000000000000", "001000000000000159010000000000005901000000000000", 16, 345},
        {"15000000000000800000000000000000", "001000000000000179000000000000007900000000000000", 21, 121},
    };
    unsigned checks = 0;
    const auto check = [&](bool condition, const std::string& message) {
        ++checks; return Require(condition, "encrypted extent: " + message);
    };
    bool ok = true;
    std::string error;
    for (const auto& fixture : fixtures)
    {
        const BtreeRecord raw{hex(fixture.key), hex(fixture.value)};
        const auto original = raw;
        AppleEncryptedFileExtentRecord decoded;
        if (!check(DecodeAppleEncryptedFileExtentRecord(raw, 4096, profile, decoded, error),
                "actual flag-1 record decodes: " + error)) return false;
        ok &= check(decoded.flags == 1 && decoded.extent.object_id == fixture.object_id &&
            decoded.extent.logical_address == 0 && decoded.extent.length_bytes == 4096 &&
            decoded.extent.physical_block == fixture.physical && decoded.extent.crypto_id == fixture.physical &&
            decoded.extent.block_size == 4096, "actual fields and crypto identity survive");
        BtreeRecord encoded;
        ok &= check(EncodeAppleEncryptedFileExtentRecord(decoded, profile, encoded, error) && SameRecord(raw, encoded),
            "actual raw key/value bytes re-encode exactly");
        AppleFileExtentRecord ordinary{1, 1, 1, 1, 1, 1};
        ok &= check(!DecodeAppleFileExtentRecord(raw, 4096, ordinary, error) &&
            ordinary.object_id == 0 && ordinary.crypto_id == 0 && error == "AppleFileExtentRecordInvalid",
            "ordinary decoder still refuses actual flag 1");
        ok &= check(SameRecord(raw, original), "input record is unchanged");
    }
    const BtreeRecord raw{hex(fixtures[0].key), hex(fixtures[0].value)};
    AppleEncryptedFileExtentRecord valid;
    if (!DecodeAppleEncryptedFileExtentRecord(raw, 4096, profile, valid, error)) return false;
    for (const auto flags : {0u, 1u})
    {
        auto value = valid;
        value.flags = static_cast<std::uint8_t>(flags);
        value.extent.crypto_id = 0x123456789ULL;
        value.extent.length_bytes = 8192;
        BtreeRecord encoded;
        AppleEncryptedFileExtentRecord decoded;
        ok &= check(EncodeAppleEncryptedFileExtentRecord(value, profile, encoded, error) &&
            DecodeAppleEncryptedFileExtentRecord(encoded, 4096, profile, decoded, error) &&
            decoded.flags == flags && decoded.extent.crypto_id == value.extent.crypto_id &&
            decoded.extent.length_bytes == 8192, "synthetic multiblock ID remains raw, never allocated or incremented");
        value.extent.physical_block = value.extent.crypto_id = 0;
        ok &= check(EncodeAppleEncryptedFileExtentRecord(value, profile, encoded, error) &&
            DecodeAppleEncryptedFileExtentRecord(encoded, 4096, profile, decoded, error) &&
            decoded.flags == flags && !decoded.extent.crypto_id && !decoded.extent.physical_block,
            "existing sparse-hole representation survives either supported flag");
    }
    for (unsigned flag = 2; flag <= 0x80; flag <<= 1)
    {
        auto invalid = raw;
        invalid.value[7] = static_cast<std::byte>(flag | 1);
        auto decoded = valid;
        ok &= check(!DecodeAppleEncryptedFileExtentRecord(invalid, 4096, profile, decoded, error) &&
            decoded.extent.object_id == 0 && decoded.flags == 0 && error == "AppleEncryptedFileExtentFlagsUnsupported",
            "unknown/mixed flag refuses with empty output");
    }
    for (unsigned fault = 0; fault < 20; ++fault)
    {
        auto invalid = raw;
        std::uint32_t block_size = 4096;
        if (fault == 0) invalid.key.pop_back();
        if (fault == 1) invalid.value.pop_back();
        if (fault == 2) invalid.key.push_back(std::byte{});
        if (fault == 3) invalid.value.push_back(std::byte{});
        if (fault == 4) PutU64(invalid.key, 0, 8ULL << 60);
        if (fault == 5) PutU64(invalid.key, 0, (9ULL << 60) | 16);
        if (fault == 6) PutU64(invalid.key, 8, 4095);
        if (fault == 7) PutU64(invalid.value, 0, 1ULL << 56);
        if (fault == 8) PutU64(invalid.value, 0, (1ULL << 56) | 4095);
        if (fault == 9) PutU64(invalid.key, 8, 0xfffffffffffff000ULL);
        if (fault == 10) PutU64(invalid.value, 8, UINT64_MAX);
        if (fault == 11) PutU64(invalid.value, 16, 0);
        if (fault == 12) PutU64(invalid.value, 16, UINT64_MAX);
        if (fault == 13) PutU64(invalid.value, 16, UINT64_MAX / 8 + 1);
        if (fault == 14) { PutU64(invalid.value, 0, (1ULL << 56) | 8192); PutU64(invalid.value, 16, UINT64_MAX / 8); }
        if (fault == 15) PutU64(invalid.value, 8, 0);
        if (fault == 16) block_size = 512;
        if (fault == 17) block_size = 3;
        if (fault == 18) block_size = 131072;
        if (fault == 19) block_size = 0;
        auto decoded = valid;
        ok &= check(!DecodeAppleEncryptedFileExtentRecord(invalid, block_size, profile, decoded, error) &&
            decoded.extent.object_id == 0 && decoded.extent.crypto_id == 0 && decoded.flags == 0 && !error.empty(),
            "malformed/length/overflow/crypto-ID refusal " + std::to_string(fault));
    }
    for (unsigned fault = 0; fault < 13; ++fault)
    {
        auto invalid = valid;
        if (fault == 0) invalid.flags = 0x81;
        if (fault == 1) invalid.extent.object_id = 0;
        if (fault == 2) invalid.extent.object_id = 1ULL << 60;
        if (fault == 3) invalid.extent.logical_address = 4095;
        if (fault == 4) invalid.extent.length_bytes = 0;
        if (fault == 5) invalid.extent.length_bytes = 4095;
        if (fault == 6) invalid.extent.length_bytes = 1ULL << 56;
        if (fault == 7) invalid.extent.physical_block = 0;
        if (fault == 8) invalid.extent.crypto_id = 0;
        if (fault == 9) invalid.extent.crypto_id = UINT64_MAX;
        if (fault == 10) invalid.extent.physical_block = UINT64_MAX;
        if (fault == 11) invalid.extent.logical_address = 0xfffffffffffff000ULL;
        if (fault == 12) invalid.extent.block_size = 512;
        auto encoded = raw;
        ok &= check(!EncodeAppleEncryptedFileExtentRecord(invalid, profile, encoded, error) &&
            encoded.key.empty() && encoded.value.empty() && !error.empty(),
            "invalid encode clears output " + std::to_string(fault));
    }
    auto boundary = valid;
    boundary.extent.length_bytes = 8192;
    boundary.extent.crypto_id = UINT64_MAX / 8 - 1;
    BtreeRecord encoded;
    AppleEncryptedFileExtentRecord decoded;
    ok &= check(EncodeAppleEncryptedFileExtentRecord(boundary, profile, encoded, error) &&
        DecodeAppleEncryptedFileExtentRecord(encoded, 4096, profile, decoded, error) &&
        decoded.extent.crypto_id == boundary.extent.crypto_id, "last representable tweak range is accepted unchanged");
    const auto unknown = static_cast<AppleEncryptedExtentProfile>(99);
    decoded = valid;
    ok &= check(!DecodeAppleEncryptedFileExtentRecord(raw, 4096, unknown, decoded, error) &&
        decoded.extent.object_id == 0 && decoded.flags == 0 && error == "AppleEncryptedFileExtentProfileUnsupported",
        "unknown decode profile refuses");
    encoded = raw;
    ok &= check(!EncodeAppleEncryptedFileExtentRecord(valid, unknown, encoded, error) &&
        encoded.key.empty() && encoded.value.empty() && error == "AppleEncryptedFileExtentProfileUnsupported",
        "unknown encode profile refuses");
    std::cout << "ENCRYPTED EXTENT CODEC " << (ok ? "PASS " : "FAIL ") << checks << " checks\n";
    return ok;
}

bool TestPayloadExtentGraphRequiresExactCoverage()
{
    std::string error;
    const auto file = [&](std::uint64_t oid, std::uint64_t logical, std::uint64_t block, std::uint64_t count) {
        BtreeRecord record;
        AppleFileExtentRecord extent{oid, logical, count * 4096, block, 0, 4096};
        Require(EncodeAppleFileExtentRecord(extent, record, error), "payload graph file extent encodes");
        return record;
    };
    const auto physical = [&](std::uint64_t owner, std::uint64_t block, std::uint64_t count, int references) {
        BtreeRecord record;
        ApplePhysicalExtentRecord extent{block, count, kApplePhysicalExtentKindNew, owner, references};
        Require(EncodeApplePhysicalExtentRecord(extent, record, error), "payload graph physical extent encodes");
        return record;
    };
    const std::vector<BtreeRecord> files{file(117, 0, 64, 16)};
    const std::vector<BtreeRecord> physicals{physical(117, 64, 16, 1)};
    std::vector<ApplePhysicalExtentRecord> ranges;
    bool ok = Require(ValidateApplePayloadExtentGraph(files, physicals, 4096, 512, ranges, error) &&
            ranges.size() == 1 && ranges.front().physical_block == 64 && ranges.front().block_count == 16,
        "payload graph returns a bounded interval, not one entry per byte/block");
    ok &= Require(ValidateApplePayloadExtentGraph({file(117, 0, 64, 16), file(118, 0, 64, 16)},
            {physical(117, 64, 16, 2)}, 4096, 512, ranges, error) && ranges.size() == 1,
        "fully represented shared payload remains one protected range");
    for (int mode = 0; mode < 9; ++mode)
    {
        auto bad_files = files;
        auto bad_physical = physicals;
        if (mode == 0) bad_physical.clear();
        else if (mode == 1) bad_physical = {physical(118, 64, 16, 1)};
        else if (mode == 2) bad_physical = {physical(117, 64, 16, 2)};
        else if (mode == 3) bad_physical.push_back(physical(118, 100, 4, 1));
        else if (mode == 4) bad_physical = {physical(117, 64, 8, 1)};
        else if (mode == 5) bad_files.push_back(files.front());
        else if (mode == 6) { bad_files.push_back(file(117, 4096, 100, 4)); bad_physical.push_back(physical(117, 100, 4, 1)); }
        else if (mode == 7) { bad_files = {file(117, 0, 510, 16)}; bad_physical = {physical(117, 510, 16, 1)}; }
        else PutU64(bad_files.front().value, 0, (1ULL << 63) | 65536);
        const auto refused = !ValidateApplePayloadExtentGraph(bad_files, bad_physical, 4096, 512, ranges, error);
        ok &= Require(refused && ranges.empty(), "incomplete/ambiguous payload graph refuses, mode=" + std::to_string(mode));
    }
    AppleXattrRecord external;
    external.object_id = 23;
    external.name_utf8 = "com.apple.ResourceFork";
    external.flags = kAppleXattrDataStream;
    external.data.resize(kAppleXattrDataStreamBytes);
    PutU64(external.data, 0, 24);
    PutU64(external.data, 8, 4096);
    PutU64(external.data, 16, 4096);
    BtreeRecord attribute;
    ok &= Require(EncodeAppleXattrRecord(external, attribute, error), "external attribute descriptor encodes");
    const std::vector<BtreeRecord> attribute_files{file(24, 0, 98, 1), attribute};
    ok &= Require(ValidateApplePayloadExtentGraph(attribute_files, {physical(23, 98, 1, 1)},
            4096, 512, ranges, error) && ranges.size() == 1 && ranges.front().owning_object_id == 23,
        "external attribute physical owner is its header object ID, distinct from stream ID");
    ok &= Require(!ValidateApplePayloadExtentGraph(attribute_files, {physical(24, 98, 1, 1)},
            4096, 512, ranges, error) && ranges.empty() && error == "AppleVolumePhysicalExtentOwnerMismatch",
        "external stream ID cannot impersonate the physical owner");
    auto wrong_attribute = attribute_files;
    external.object_id = 25;
    ok &= Require(EncodeAppleXattrRecord(external, wrong_attribute.back(), error), "alternate owner encodes");
    ok &= Require(!ValidateApplePayloadExtentGraph(wrong_attribute, {physical(23, 98, 1, 1)},
            4096, 512, ranges, error) && ranges.empty(), "wrong external attribute owner refuses");
    wrong_attribute.push_back(attribute);
    ok &= Require(!ValidateApplePayloadExtentGraph(wrong_attribute, {physical(23, 98, 1, 1)},
            4096, 512, ranges, error) && ranges.empty() && error == "AppleVolumeAttributeOwnerAmbiguous",
        "contradictory external stream owners refuse");
    AppleInodeRecord alias_inode;
    alias_inode.object_id = alias_inode.private_id = 24;
    alias_inode.parent_id = 2;
    alias_inode.mode = 0100644;
    BtreeRecord alias;
    ok &= Require(EncodeAppleInodeRecord(alias_inode, alias, error), "alias control inode encodes");
    auto aliased_files = attribute_files;
    aliased_files.push_back(alias);
    ok &= Require(!ValidateApplePayloadExtentGraph(aliased_files, {physical(23, 98, 1, 1)},
            4096, 512, ranges, error) && ranges.empty() && error == "AppleVolumeAttributeInodeAlias",
        "external stream cannot also be an inode data stream");
    AppleEncryptedFileExtentRecord encrypted;
    encrypted.extent = {24, 0, 4096, 98, 98, 4096};
    BtreeRecord encrypted_extent;
    ok &= Require(EncodeAppleEncryptedFileExtentRecord(encrypted,
        AppleEncryptedExtentProfile::OneKeyGenerationZero, encrypted_extent, error), "encrypted owner control encodes");
    std::vector<BtreeRecord> encrypted_files{encrypted_extent, attribute};
    ok &= Require(ValidateAppleEncryptedPayloadExtentGraph(encrypted_files, {physical(23, 98, 1, 1)},
        4096, 512, ranges, error), "encrypted external stream retains its distinct header owner");
    encrypted_files.push_back(alias);
    ok &= Require(!ValidateAppleEncryptedPayloadExtentGraph(encrypted_files, {physical(23, 98, 1, 1)},
        4096, 512, ranges, error) && ranges.empty() && error == "AppleVolumeAttributeInodeAlias",
        "encrypted external stream cannot also be an inode data stream");
    auto valid_owner = alias_inode;
    valid_owner.object_id = valid_owner.private_id = 23;
    ok &= Require(EncodeAppleInodeRecord(valid_owner, encrypted_files.back(), error), "non-aliased encrypted owner encodes");
    ok &= Require(ValidateAppleEncryptedPayloadExtentGraph(encrypted_files, {physical(23, 98, 1, 1)},
        4096, 512, ranges, error), "encrypted owning inode is distinct from its attribute stream");
    return ok;
}

bool TestPhysicalExtentRecordCodecAndOrdering()
{
    ApplePhysicalExtentRecord extent;
    extent.physical_block = 900;
    extent.block_count = 8;
    extent.kind = kApplePhysicalExtentKindNew;
    extent.owning_object_id = 117;
    extent.reference_count = 2;

    BtreeRecord record;
    std::string error;
    bool ok = Require(EncodeApplePhysicalExtentRecord(extent, record, error),
        "physical-extent encoding: " + error);
    ok &= Require(record.key.size() == 8 &&
            ReadU64LE(record.key, 0).value_or(0) == ((2ull << 60) | 900),
        "physical-extent key layout");
    ok &= Require(record.value.size() == 20 &&
            ReadU64LE(record.value, 0).value_or(0) ==
                ((1ull << 60) | 8) &&
            ReadU64LE(record.value, 8).value_or(0) == 117 &&
            ReadU32LE(record.value, 16).value_or(0) == 2,
        "physical-extent value layout");

    ApplePhysicalExtentRecord decoded;
    ok &= Require(DecodeApplePhysicalExtentRecord(record, decoded, error),
        "physical-extent decoding: " + error);
    ok &= Require(decoded.physical_block == extent.physical_block &&
            decoded.block_count == extent.block_count &&
            decoded.kind == extent.kind &&
            decoded.owning_object_id == extent.owning_object_id &&
            decoded.reference_count == extent.reference_count,
        "physical-extent codec round trip");

    auto earlier = extent;
    earlier.physical_block = 800;
    BtreeRecord earlier_record;
    ok &= Require(EncodeApplePhysicalExtentRecord(
            earlier, earlier_record, error),
        "second physical-extent encoding: " + error);
    std::vector<BtreeRecord> records{record, earlier_record};
    ok &= Require(SortAppleBtreeRecords(
            records, AppleBtreeKeyOrder::PhysicalExtent, error) &&
            ReadU64LE(records.front().key, 0).value_or(0) ==
                ((2ull << 60) | 800),
        "physical extents sort by physical block");

    auto invalid = extent;
    invalid.reference_count = 0;
    ok &= Require(!EncodeApplePhysicalExtentRecord(invalid, record, error),
        "zero physical-extent reference count rejected");
    invalid = extent;
    invalid.kind = 0;
    ok &= Require(!EncodeApplePhysicalExtentRecord(invalid, record, error),
        "invalid physical-extent kind rejected");
    return ok;
}

bool TestDataStreamIdRecordCodec()
{
    AppleDataStreamIdRecord stream;
    stream.object_id = 0x1234;
    stream.reference_count = 2;
    apfsaccess::catalog::BtreeRecord record;
    std::string error;
    bool ok = Require(EncodeAppleDataStreamIdRecord(stream, record, error),
        "data-stream ID record encodes: " + error);
    ok &= Require(record.key.size() == 8 && record.value.size() == 4 &&
            (ReadU64LE(record.key, 0).value_or(0) >> 60) == 6 &&
            ReadU32LE(record.value, 0).value_or(0) == 2,
        "data-stream ID record uses APFS type 6 and packed refcount");

    AppleDataStreamIdRecord decoded;
    ok &= Require(DecodeAppleDataStreamIdRecord(record, decoded, error) &&
            decoded.object_id == stream.object_id &&
            decoded.reference_count == stream.reference_count,
        "data-stream ID record round trips: " + error);

    auto invalid = stream;
    invalid.reference_count = 0;
    ok &= Require(!EncodeAppleDataStreamIdRecord(invalid, record, error) &&
            error == "AppleDataStreamIdRecordInvalid",
        "zero-reference data-stream ID is rejected");
    invalid = stream;
    invalid.object_id = 0;
    ok &= Require(!EncodeAppleDataStreamIdRecord(invalid, record, error) &&
            error == "AppleDataStreamIdRecordInvalid",
        "zero data-stream ID is rejected");
    record.key.push_back(std::byte{0});
    ok &= Require(!DecodeAppleDataStreamIdRecord(record, decoded, error) &&
            error == "AppleDataStreamIdRecordInvalid",
        "malformed data-stream ID record is rejected");
    return ok;
}

bool TestVolumeAccountingPatch()
{
    std::vector<std::byte> original(4096, std::byte{0});
    for (std::size_t index = 0; index < original.size(); ++index)
    {
        original[index] = static_cast<std::byte>((index * 37u + 11u) & 0xffu);
    }
    PutU64(original, 0x08, 1234);
    PutU64(original, 0x10, 40);
    PutU32(original, 0x18, apfsaccess::catalog::kObjectPhysical |
        apfsaccess::catalog::kObjectTypeFs);
    PutU32(original, 0x20, apfsaccess::catalog::kApsbMagic);
    PutU64(original, 0x58, 20);
    PutU32(original, 0x70, apfsaccess::catalog::kObjectTypeBtree);
    PutU32(original, 0x74, apfsaccess::catalog::kObjectPhysical |
        apfsaccess::catalog::kObjectTypeBtree);
    PutU32(original, 0x78, apfsaccess::catalog::kObjectPhysical |
        apfsaccess::catalog::kObjectTypeBtree);
    PutU64(original, 0x80, 50);
    PutU64(original, 0x88, 60);
    PutU64(original, 0x90, 70);
    PutU64(original, 0x98, 80);
    PutU64(original, 0xB0, 100);
    PutU64(original, 0xB8, 3);
    PutU64(original, 0xC0, 2);
    PutU64(original, 0xE0, 30);
    PutU64(original, 0xE8, 10);
    for (std::size_t index = 0; index < 16; ++index)
    {
        original[0xF0 + index] = static_cast<std::byte>(index + 1);
    }
    original[0x120] = std::byte{0xA5};
    std::string error;
    bool ok = Require(FinalizeAppleObjectChecksum(original, error),
        "seed APSB checksum: " + error);

    AppleVolumeAccountingUpdate update;
    update.xid = 41;
    update.object_map_object_id = 51;
    update.file_system_allocated_blocks = 24;
    update.root_tree_object_id = 61;
    update.extentref_tree_object_id = 71;
    update.snapshot_metadata_tree_object_id = 81;
    update.next_object_id = 101;
    update.file_count = 4;
    update.directory_count = 3;
    update.symlink_count = 1;
    update.other_object_count = 2;
    update.snapshot_count = 1;
    update.total_blocks_allocated = 35;
    update.total_blocks_freed = 11;
    update.last_modification_time = 999;
    std::vector<std::byte> patched;
    ok &= Require(PatchAppleVolumeSuperblock(original, update, patched, error),
        "patch APSB accounting: " + error);
    ok &= Require(apfsaccess::catalog::VerifyObjectChecksum(patched, patched.size()),
        "patched APSB checksum");
    ok &= Require(ReadU64LE(patched, 0x10).value_or(0) == 41, "patched APSB xid");
    ok &= Require(ReadU64LE(patched, 0x58).value_or(0) == 24, "patched fs allocation");
    ok &= Require(ReadU64LE(patched, 0x80).value_or(0) == 51, "patched volume object map");
    ok &= Require(ReadU64LE(patched, 0x88).value_or(0) == 61, "patched root tree");
    ok &= Require(ReadU64LE(patched, 0xB8).value_or(0) == 4, "patched file count");
    ok &= Require(ReadU64LE(patched, 0xC0).value_or(0) == 3, "patched directory count");
    ok &= Require(ReadU64LE(patched, 0x100).value_or(0) == 999, "patched modification time");
    ok &= Require(patched[0x120] == std::byte{0xA5}, "unknown APSB bytes preserved");
    ok &= Require(ReadU64LE(patched, 0x08) == ReadU64LE(original, 0x08),
        "APSB object identity preserved");

    auto expected = original;
    auto accept_changed_range = [&patched, &expected](std::size_t offset, std::size_t size) {
        std::copy_n(patched.begin() + static_cast<std::ptrdiff_t>(offset), size,
            expected.begin() + static_cast<std::ptrdiff_t>(offset));
    };
    accept_changed_range(0x00, 0x08);
    accept_changed_range(0x10, 0x08);
    accept_changed_range(0x58, 0x08);
    accept_changed_range(0x80, 0x20);
    accept_changed_range(0xB0, 0x40);
    accept_changed_range(0x100, 0x08);
    ok &= Require(patched == expected,
        "APSB patch changes only declared accounting and checksum bytes");

    auto deletion = update;
    deletion.xid = 42;
    deletion.file_system_allocated_blocks = 18;
    deletion.file_count = 2;
    deletion.total_blocks_allocated = 35;
    deletion.total_blocks_freed = 13;
    std::vector<std::byte> deletion_patched;
    ok &= Require(PatchAppleVolumeSuperblock(
            original, deletion, deletion_patched, error),
        "current filesystem allocation count may decrease after deletion: " + error);
    ok &= Require(ReadU64LE(deletion_patched, 0x58).value_or(0) == 18,
        "deletion accounting stores the reduced current allocation count");

    auto invalid = update;
    invalid.xid = 40;
    std::vector<std::byte> rejected;
    ok &= Require(!PatchAppleVolumeSuperblock(original, invalid, rejected, error) && rejected.empty(),
        "non-increasing APSB xid rejected");
    return ok;
}

bool TestObjectMapCopyOnWritePatch()
{
    std::vector<std::byte> original(4096, std::byte{0});
    PutU64(original, 0x08, 12);
    PutU64(original, 0x10, 40);
    PutU32(original, 0x18, apfsaccess::catalog::kObjectPhysical |
        apfsaccess::catalog::kObjectTypeOmap);
    PutU32(original, 0x28, apfsaccess::catalog::kObjectPhysical |
        apfsaccess::catalog::kObjectTypeBtree);
    PutU64(original, 0x30, 13);
    original[0x90] = std::byte{0xA5};
    std::string error;
    bool ok = Require(FinalizeAppleObjectChecksum(original, error),
        "seed OMAP checksum: " + error);

    std::vector<std::byte> patched;
    ok &= Require(PatchAppleObjectMap(original, 50, 41, 51, patched, error),
        "copy-on-write OMAP patch succeeds: " + error);
    ok &= Require(apfsaccess::catalog::VerifyObjectChecksum(
            patched, patched.size()),
        "copied OMAP checksum");
    ok &= Require(ReadU64LE(patched, 0x08).value_or(0) == 50 &&
            ReadU64LE(patched, 0x10).value_or(0) == 41 &&
            ReadU64LE(patched, 0x30).value_or(0) == 51,
        "copied OMAP carries new identity, xid, and tree");
    ok &= Require(patched[0x90] == std::byte{0xA5},
        "copied OMAP preserves unknown fields");

    auto expected = original;
    auto accept_changed_range = [&patched, &expected](std::size_t offset,
                                                        std::size_t size) {
        std::copy_n(patched.begin() + static_cast<std::ptrdiff_t>(offset), size,
            expected.begin() + static_cast<std::ptrdiff_t>(offset));
    };
    accept_changed_range(0x00, 0x08);
    accept_changed_range(0x08, 0x10);
    accept_changed_range(0x30, 0x08);
    ok &= Require(patched == expected,
        "OMAP patch changes only declared fields and checksum");

    std::vector<std::byte> rejected;
    ok &= Require(!PatchAppleObjectMap(original, 50, 40, 51,
            rejected, error) && rejected.empty(),
        "non-increasing OMAP xid is rejected");
    return ok;
}

bool TestFileSystemKeyTypeValidationAndSnapshotOrdering()
{
    constexpr std::uint64_t kSnapshotNameObjectId = 0x0fffffffffffffffull;
    auto snapshot_name = [](const std::string& name) {
        BtreeRecord record;
        record.key.resize(10 + name.size() + 1, std::byte{0});
        PutU64(record.key, 0, (11ull << 60) | kSnapshotNameObjectId);
        PutU16(record.key, 8, static_cast<std::uint16_t>(name.size() + 1));
        std::copy(name.begin(), name.end(),
            reinterpret_cast<char*>(record.key.data() + 10));
        record.value = Bytes("snapshot");
        return record;
    };

    std::string error;
    std::vector<BtreeRecord> snapshots{
        snapshot_name("Zulu"),
        snapshot_name("Alpha"),
    };
    bool ok = Require(SortAppleBtreeRecords(
            snapshots, AppleBtreeKeyOrder::FileSystemCaseSensitive, error),
        "snapshot-name keys accepted: " + error);
    ok &= Require(snapshots.size() == 2 &&
            std::string(reinterpret_cast<const char*>(snapshots[0].key.data() + 10), 5) == "Alpha",
        "snapshot-name keys sort lexicographically");

    for (const std::uint8_t invalid_type : {std::uint8_t{14}, std::uint8_t{15}})
    {
        BtreeRecord invalid;
        invalid.key.resize(8, std::byte{0});
        PutU64(invalid.key, 0, (static_cast<std::uint64_t>(invalid_type) << 60) | 5);
        std::vector<BtreeRecord> records{invalid};
        ok &= Require(!SortAppleBtreeRecords(
                records, AppleBtreeKeyOrder::FileSystemCaseSensitive, error),
            "reserved filesystem record type rejected");
    }

    BtreeRecord malformed_crypto_state;
    malformed_crypto_state.key.resize(16, std::byte{0});
    PutU64(malformed_crypto_state.key, 0, (7ull << 60) | 5);
    std::vector<BtreeRecord> malformed{malformed_crypto_state};
    ok &= Require(!SortAppleBtreeRecords(
            malformed, AppleBtreeKeyOrder::FileSystemCaseSensitive, error),
        "fixed-width crypto-state key rejects trailing bytes");
    return ok;
}

bool TestRejectsInvalidInputsAndFutureXid()
{
    auto options = PhysicalOptions(
        AppleBtreeKeyOrder::ObjectMap,
        apfsaccess::catalog::kObjectTypeOmap);
    options.fixed_key_size = 16;
    options.fixed_value_size = 16;
    AppleOmapRecord mapping{1, 77, 0, 4096, 100};
    BtreeRecord record;
    std::string error;
    bool ok = Require(EncodeAppleOmapRecord(mapping, record, error), "seed valid OMAP record");
    AppleSerializedBtree tree;
    ok &= Require(SerializeAppleBtree({record}, options, tree, error), "seed valid tree");

    auto duplicate = std::vector<BtreeRecord>{record, record};
    ok &= Require(!SerializeAppleBtree(duplicate, options, tree, error),
        "duplicate keys rejected");
    auto bad_block = options;
    bad_block.block_size = 3000;
    ok &= Require(!SerializeAppleBtree({record}, bad_block, tree, error),
        "non-power-of-two block rejected");
    auto overlap = options;
    overlap.first_child_physical_block = overlap.root_physical_block;
    overlap.first_child_object_id = overlap.root_object_id;
    std::vector<BtreeRecord> many(400, record);
    for (std::size_t index = 0; index < many.size(); ++index)
    {
        PutU64(many[index].key, 0, index + 1);
    }
    ok &= Require(!SerializeAppleBtree(many, overlap, tree, error),
        "root/child allocation overlap rejected");

    ok &= Require(SerializeAppleBtree({record}, options, tree, error), "rebuild valid tree");
    auto image = Materialize(tree, options.block_size);
    VectorRandomAccessSource source(image);
    BtreeReadPolicy policy{true, options.root_object_id, options.storage_type, options.subtype};
    std::vector<BtreeRecord> output;
    ok &= Require(!ReadBtreeLeafRecords(source, options.block_size,
            options.root_physical_block, true, 0, options.xid - 1,
            policy, output, error) && error == "CatalogBtreeFutureXid",
        "independent reader rejects future xid");
    return ok;
}
} // namespace

int main(int argc, char** argv)
{
    if (argc == 2 && std::string_view(argv[1]) == "--encrypted-extents-only")
        return TestEncryptedFileExtentCodec() && g_failures == 0 ? 0 : 1;
    bool ok = true;
    ok &= TestVariableTreeGrowthShrinkAndDeterminism();
    ok &= TestFixedOmapTreeAndTombstone();
    ok &= TestMixedFixedAndVariableLayouts();
    ok &= TestGhostsAndRootHistoryFields();
    ok &= TestEphemeralTreeUsesCheckpointMappedExplicitChildren();
    ok &= TestRecordEncoders();
    ok &= TestFileExtentDecodeIsStrict();
    ok &= TestEncryptedFileExtentCodec();
    ok &= TestPayloadExtentGraphRequiresExactCoverage();
    ok &= TestPhysicalExtentRecordCodecAndOrdering();
    ok &= TestDataStreamIdRecordCodec();
    ok &= TestVolumeAccountingPatch();
    ok &= TestObjectMapCopyOnWritePatch();
    ok &= TestFileSystemKeyTypeValidationAndSnapshotOrdering();
    ok &= TestRejectsInvalidInputsAndFutureXid();
    if (ok && g_failures == 0)
    {
        std::cout << "APFS APPLE TRANSACTION WRITER PASS" << std::endl;
        return 0;
    }
    std::cerr << "APFS APPLE TRANSACTION WRITER FAIL: " << g_failures << " check(s)" << std::endl;
    return 1;
}
