#pragma once

#include "ApfsFormat.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace apfsaccess::rw
{

inline constexpr std::uint32_t kAppleBtreeUint64Keys = 0x00000001;
inline constexpr std::uint32_t kAppleBtreeSequentialInsert = 0x00000002;
inline constexpr std::uint32_t kAppleBtreeAllowGhosts = 0x00000004;
inline constexpr std::uint32_t kAppleBtreeEphemeral = 0x00000008;
inline constexpr std::uint32_t kAppleBtreePhysical = 0x00000010;
inline constexpr std::uint32_t kAppleBtreeKvNonAligned = 0x00000040;

inline constexpr std::uint32_t kAppleOmapValueDeleted = 0x00000001;
inline constexpr std::uint16_t kAppleXattrDataStream = 0x0001;
inline constexpr std::uint16_t kAppleXattrDataEmbedded = 0x0002;
inline constexpr std::uint16_t kAppleXattrFileSystemOwned = 0x0004;

enum class AppleBtreeKeyOrder
{
    Lexicographic,
    ObjectMap,
    SpacemanFreeQueue,
    PhysicalExtent,
    FileSystemCaseSensitive,
    FileSystemHashedDirectory,
};

struct AppleBtreeOptions
{
    std::uint32_t block_size = 0;
    std::uint64_t xid = 0;
    std::uint64_t root_object_id = 0;
    std::uint64_t root_physical_block = 0;
    std::uint64_t first_child_object_id = 0;
    std::uint64_t first_child_physical_block = 0;
    std::vector<std::uint64_t> child_object_ids;
    std::vector<std::uint64_t> child_physical_blocks;
    std::uint32_t storage_type = 0;
    std::uint32_t subtype = 0;
    std::uint32_t tree_flags = 0;
    std::uint32_t fixed_key_size = 0;
    std::uint32_t fixed_value_size = 0;
    std::uint32_t minimum_longest_key = 0;
    std::uint32_t minimum_longest_value = 0;
    AppleBtreeKeyOrder key_order = AppleBtreeKeyOrder::Lexicographic;
    std::size_t max_nodes = 4096;
};

struct AppleSerializedObject
{
    catalog::AppleObjectLocation location;
    std::vector<std::byte> bytes;
};

struct AppleSerializedBtree
{
    std::uint64_t root_object_id = 0;
    std::uint64_t root_physical_block = 0;
    std::uint16_t height = 0;
    std::vector<AppleSerializedObject> objects;
};

// Sorts in APFS key order and rejects malformed or duplicate keys.
bool SortAppleBtreeRecords(
    std::vector<catalog::BtreeRecord>& records,
    AppleBtreeKeyOrder order,
    std::string& out_error);

// Rebuilds a complete copy-on-write tree in memory. The caller owns block/OID
// reservation; this function never performs I/O.
bool SerializeAppleBtree(
    const std::vector<catalog::BtreeRecord>& records,
    const AppleBtreeOptions& options,
    AppleSerializedBtree& out_tree,
    std::string& out_error);

// Writes the checksum at bytes [0,8) after zeroing it. The object must be a
// complete, four-byte-aligned on-disk object.
bool FinalizeAppleObjectChecksum(
    std::vector<std::byte>& object,
    std::string& out_error);

struct AppleOmapRecord
{
    std::uint64_t object_id = 0;
    std::uint64_t xid = 0;
    std::uint32_t flags = 0;
    std::uint32_t size_bytes = 0;
    std::uint64_t physical_block = 0;
};

struct AppleExtendedField
{
    std::uint8_t type = 0;
    std::uint8_t flags = 0;
    std::vector<std::byte> data;
};

struct AppleInodeRecord
{
    std::uint64_t object_id = 0;
    std::uint64_t parent_id = 0;
    std::uint64_t private_id = 0;
    std::uint64_t create_time = 0;
    std::uint64_t modification_time = 0;
    std::uint64_t change_time = 0;
    std::uint64_t access_time = 0;
    std::uint64_t internal_flags = 0;
    std::int32_t children_or_links = 0;
    std::uint32_t default_protection_class = 0;
    std::uint32_t write_generation = 0;
    std::uint32_t bsd_flags = 0;
    std::uint32_t owner = 0;
    std::uint32_t group = 0;
    std::uint16_t mode = 0;
    std::uint64_t uncompressed_size = 0;
    std::vector<AppleExtendedField> extended_fields;
};

struct AppleDirectoryRecord
{
    std::uint64_t parent_id = 0;
    std::uint64_t file_id = 0;
    std::uint64_t date_added = 0;
    std::uint16_t flags = 0;
    std::string name_utf8;
    bool hashed_name = false;
    std::uint32_t name_hash = 0;
    std::vector<AppleExtendedField> extended_fields;
};

struct AppleFileExtentRecord
{
    std::uint64_t object_id = 0;
    std::uint64_t logical_address = 0;
    std::uint64_t length_bytes = 0;
    std::uint64_t physical_block = 0;
    std::uint64_t crypto_id = 0;
    std::uint32_t block_size = 0;
};

struct AppleDataStreamIdRecord
{
    std::uint64_t object_id = 0;
    std::uint32_t reference_count = 0;
};

inline constexpr std::uint8_t kApplePhysicalExtentKindNew = 1;
inline constexpr std::uint8_t kApplePhysicalExtentKindUpdate = 2;

struct ApplePhysicalExtentRecord
{
    std::uint64_t physical_block = 0;
    std::uint64_t block_count = 0;
    std::uint8_t kind = kApplePhysicalExtentKindNew;
    std::uint64_t owning_object_id = 0;
    std::int32_t reference_count = 0;
};

struct AppleSiblingLinkRecord
{
    std::uint64_t inode_id = 0;
    std::uint64_t sibling_id = 0;
    std::uint64_t parent_id = 0;
    std::string name_utf8;
};

struct AppleSiblingMapRecord
{
    std::uint64_t sibling_id = 0;
    std::uint64_t file_id = 0;
};

struct AppleXattrRecord
{
    std::uint64_t object_id = 0;
    std::string name_utf8;
    std::uint16_t flags = 0;
    std::vector<std::byte> data;
};

bool EncodeAppleOmapRecord(
    const AppleOmapRecord& value,
    catalog::BtreeRecord& out_record,
    std::string& out_error);
bool EncodeAppleInodeRecord(
    const AppleInodeRecord& value,
    catalog::BtreeRecord& out_record,
    std::string& out_error);
bool EncodeAppleDirectoryRecord(
    const AppleDirectoryRecord& value,
    catalog::BtreeRecord& out_record,
    std::string& out_error);
bool EncodeAppleFileExtentRecord(
    const AppleFileExtentRecord& value,
    catalog::BtreeRecord& out_record,
    std::string& out_error);
bool EncodeAppleDataStreamIdRecord(
    const AppleDataStreamIdRecord& value,
    catalog::BtreeRecord& out_record,
    std::string& out_error);
bool DecodeAppleDataStreamIdRecord(
    const catalog::BtreeRecord& record,
    AppleDataStreamIdRecord& out_value,
    std::string& out_error);
bool EncodeApplePhysicalExtentRecord(
    const ApplePhysicalExtentRecord& value,
    catalog::BtreeRecord& out_record,
    std::string& out_error);
bool DecodeApplePhysicalExtentRecord(
    const catalog::BtreeRecord& record,
    ApplePhysicalExtentRecord& out_value,
    std::string& out_error);
bool EncodeAppleSiblingLinkRecord(
    const AppleSiblingLinkRecord& value,
    catalog::BtreeRecord& out_record,
    std::string& out_error);
bool EncodeAppleSiblingMapRecord(
    const AppleSiblingMapRecord& value,
    catalog::BtreeRecord& out_record,
    std::string& out_error);
bool EncodeAppleXattrRecord(
    const AppleXattrRecord& value,
    catalog::BtreeRecord& out_record,
    std::string& out_error);

// Copies a checksum-valid physical OMAP object to a newly allocated physical
// identity and points it at a newly serialized physical OMAP tree. Unknown
// fields are retained byte-for-byte.
bool PatchAppleObjectMap(
    const std::vector<std::byte>& original,
    std::uint64_t physical_block,
    std::uint64_t xid,
    std::uint64_t tree_physical_block,
    std::vector<std::byte>& out_object_map,
    std::string& out_error);

struct AppleVolumeAccountingUpdate
{
    std::uint64_t xid = 0;
    // Zero preserves the existing volume object-map identity.
    std::uint64_t object_map_object_id = 0;
    std::uint64_t file_system_allocated_blocks = 0;
    std::uint64_t root_tree_object_id = 0;
    std::uint64_t extentref_tree_object_id = 0;
    std::uint64_t snapshot_metadata_tree_object_id = 0;
    std::uint64_t next_object_id = 0;
    std::uint64_t file_count = 0;
    std::uint64_t directory_count = 0;
    std::uint64_t symlink_count = 0;
    std::uint64_t other_object_count = 0;
    std::uint64_t snapshot_count = 0;
    std::uint64_t total_blocks_allocated = 0;
    std::uint64_t total_blocks_freed = 0;
    std::uint64_t last_modification_time = 0;
};

// Copies an existing checksum-valid APSB, changes only transaction/accounting
// fields, and recomputes its object checksum. Unknown and reserved bytes are
// preserved byte-for-byte.
bool PatchAppleVolumeSuperblock(
    const std::vector<std::byte>& original,
    const AppleVolumeAccountingUpdate& update,
    std::vector<std::byte>& out_superblock,
    std::string& out_error);

} // namespace apfsaccess::rw
