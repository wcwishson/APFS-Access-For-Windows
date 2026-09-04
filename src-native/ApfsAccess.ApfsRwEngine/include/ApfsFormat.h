#pragma once

// Portable, bounds-checked APFS on-disk readers shared by the catalog parser
// and the repo-owned observer. All multi-byte integers are explicit
// little-endian; no structure is ever reinterpreted from raw bytes.
//
// Field-offset sources:
//   [CODE] verified against NativeApfsReader.cpp / NativeApfsBackend.cs in
//          this repository (cited per reader).
//   [APPLE] from the published Apple File System Reference layout. Production
//          checkpoint identity and safety decisions validate these fields as a
//          mutually consistent, checksum-correct transaction view; real-macOS
//          byte validation remains an explicit C0b/C0-final external gate.

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "RandomAccessSource.h"

namespace apfsaccess::catalog
{

// ---- little-endian readers: nullopt past the end ---------------------------

[[nodiscard]] std::optional<std::uint16_t> ReadU16LE(
    const std::vector<std::byte>& buffer, std::size_t offset);
[[nodiscard]] std::optional<std::uint32_t> ReadU32LE(
    const std::vector<std::byte>& buffer, std::size_t offset);
[[nodiscard]] std::optional<std::uint64_t> ReadU64LE(
    const std::vector<std::byte>& buffer, std::size_t offset);

// ---- checksums --------------------------------------------------------------

// APFS object Fletcher64 over the u32-LE words of `data` ([CODE]:
// NativeApfsBackend.ComputeApfsObjectChecksum). `size` must be a nonzero
// multiple of 4.
[[nodiscard]] std::optional<std::uint64_t> Fletcher64(
    const std::byte* data, std::size_t size);

// Verifies the u64 checksum at block[0:8] against Fletcher64(block[8:size]).
// Requires size == block_size and rejects zero/all-ones stored values
// ([CODE]: NativeApfsBackend.HasValidApfsObjectChecksum).
[[nodiscard]] bool VerifyObjectChecksum(
    const std::vector<std::byte>& block, std::size_t block_size);

// Standard IEEE CRC32 ([CODE]: NativeApfsBackend.ComputeCrc32).
[[nodiscard]] std::uint32_t Crc32(const std::byte* data, std::size_t size);

// ---- identifiers ------------------------------------------------------------

// Mixed-endian GPT GUID rendered lowercase `xxxxxxxx-xxxx-...`, matching
// System.Guid(byte[]) interpretation of the same 16 bytes.
[[nodiscard]] std::string GuidToStringLower(const std::byte* sixteen_bytes);
// Raw 16 bytes rendered as 32 lowercase hex digits (APFS uuid_t is opaque;
// round-trip only, never reordered).
[[nodiscard]] std::string BytesToHexLower(const std::byte* data, std::size_t size);

// ---- constants --------------------------------------------------------------

inline constexpr std::uint32_t kNxsbMagic = 0x4253584E; // 'NXSB'
inline constexpr std::uint32_t kApsbMagic = 0x42535041; // 'APSB'
inline constexpr std::uint32_t kNxSuperblockObjectType = 0x00000001;
inline constexpr std::uint32_t kObjectTypeMask = 0x0000FFFF;
inline constexpr std::uint32_t kObjectTypeOmap = 0x0000000B;
inline constexpr std::uint32_t kObjectTypeCheckpointMap = 0x0000000C;
inline constexpr std::uint32_t kObjectTypeSpaceman = 0x00000005;
inline constexpr std::uint32_t kObjectTypeSpacemanCab = 0x00000006;
inline constexpr std::uint32_t kObjectTypeSpacemanCib = 0x00000007;
inline constexpr std::uint32_t kObjectTypeSpacemanBitmap = 0x00000008;
inline constexpr std::uint32_t kObjectTypeBtree = 0x00000002;
inline constexpr std::uint32_t kObjectTypeBtreeNode = 0x00000003;
inline constexpr std::uint32_t kObjectTypeFs = 0x0000000D;
inline constexpr std::uint32_t kObjectTypeFsTree = 0x0000000E;
inline constexpr std::uint32_t kObjectTypeBlockRefTree = 0x0000000F;
inline constexpr std::uint32_t kObjectTypeSnapMetaTree = 0x00000010;
inline constexpr std::uint32_t kObjectTypeFileExtentTree = 0x0000001F;
inline constexpr std::uint32_t kObjectTypeSpacemanFreeQueue = 0x00000009;
inline constexpr std::uint32_t kObjectStorageTypeMask = 0xC0000000;
inline constexpr std::uint32_t kObjectEphemeral = 0x80000000;
inline constexpr std::uint32_t kObjectPhysical = 0x40000000;
inline constexpr std::uint32_t kObjectNoHeader = 0x20000000;

// GPT APFS partition type GUID bytes in mixed-endian order:
// 7C3457EF-0000-11AA-AA11-00306543ECAC ([CODE]: ApfsPartitionTypeGuid).
inline constexpr std::array<std::byte, 16> kApfsPartitionTypeGuidBytes = {
    std::byte{0xEF}, std::byte{0x57}, std::byte{0x34}, std::byte{0x7C},
    std::byte{0x00}, std::byte{0x00}, std::byte{0xAA}, std::byte{0x11},
    std::byte{0xAA}, std::byte{0x11}, std::byte{0x00}, std::byte{0x30},
    std::byte{0x65}, std::byte{0x43}, std::byte{0xEC}, std::byte{0xAC},
};

// APFS feature tables. Optional features are informational. Unsupported
// read-only-compatible and incompatible features gate writes downstream.
inline constexpr std::uint64_t kNxKnownOptionalFeaturesMask = 0x3ULL;
inline constexpr std::uint64_t kNxSupportedIncompatibleFeaturesMask = 0x2ULL;
inline constexpr std::uint64_t kNxKnownIncompatibleFeaturesMask = 0x103ULL;
inline constexpr std::uint64_t kVolumeKnownOptionalFeaturesMask = 0x1FULL;
inline constexpr std::uint64_t kIncompatCaseInsensitive = 0x1ULL;
inline constexpr std::uint64_t kVolumeSupportedIncompatibleFeaturesMask =
    kIncompatCaseInsensitive;
inline constexpr std::uint64_t kVolumeKnownIncompatibleFeaturesMask = 0x7FULL;
inline constexpr std::uint64_t kFsFlagUnencrypted = 0x1ULL; // [APPLE]
inline constexpr std::uint64_t kFsFlagOneKey = 0x8ULL; // [APPLE]

// ---- GPT --------------------------------------------------------------------

struct GptPartition
{
    std::uint32_t number = 0; // 1-based entry index
    std::string type_guid; // lowercase GUID-D
    std::string unique_guid; // lowercase GUID-D
    std::uint64_t start_bytes = 0;
    std::uint64_t size_bytes = 0;
    std::string name_utf8; // entry name, best effort
};

struct GptLayout
{
    std::uint64_t sector_size = 0;
    std::string disk_guid; // lowercase GUID-D
    std::vector<GptPartition> partitions; // in entry order, nonempty types only
};

// Parses GPT at `base_offset` (a whole disk). Probes sector sizes {512, 4096},
// validates the header and entry-array CRC32, and requires 128-byte entries
// ([CODE] layout: NativeApfsBackend.TryReadGptPartitions). Entries outside
// the declared usable range or overlapping a previous entry fail the parse.
[[nodiscard]] std::optional<GptLayout> ParseGpt(
    const RandomAccessSource& source, std::uint64_t base_offset, std::uint64_t size_bytes);

// ---- container superblock (NXSB) --------------------------------------------

struct NxSuperblock
{
    std::uint64_t object_id = 0;
    std::uint64_t xid = 0;
    std::uint32_t block_size = 0;
    std::uint64_t block_count = 0;
    std::uint64_t features = 0;
    std::uint64_t readonly_features = 0;
    std::uint64_t incompatible_features = 0;
    std::string uuid_hex; // 32 lowercase hex digits
    std::uint64_t next_oid = 0;
    std::uint64_t next_xid = 0;
    std::uint64_t omap_oid = 0;
    std::uint64_t spaceman_oid = 0;
    std::uint64_t reaper_oid = 0;
    std::vector<std::uint64_t> fs_oids; // nonzero nx_fs_oid slots, in order
    std::uint32_t xp_desc_blocks_raw = 0;
    std::uint32_t xp_data_blocks_raw = 0;
    std::uint32_t xp_desc_block_count = 0; // high-bit flag removed
    std::uint32_t xp_data_block_count = 0; // high-bit flag removed
    bool xp_desc_noncontiguous = false;
    bool xp_data_noncontiguous = false;
    std::uint64_t xp_desc_base_block = 0; // checkpoint descriptor area start
    std::uint64_t xp_data_base_block = 0; // checkpoint data area start
    std::uint32_t xp_desc_next = 0;
    std::uint32_t xp_data_next = 0;
    std::uint32_t xp_desc_index = 0;
    std::uint32_t xp_desc_len = 0;
    std::uint32_t xp_data_index = 0;
    std::uint32_t xp_data_len = 0;
};

// Parses one block_size-sized NXSB block ([CODE] offsets:
// NativeApfsBackend.TryParseApfsContainerHeader). Requires magic, sane
// geometry, a valid object checksum, and a nonzero UUID.
[[nodiscard]] std::optional<NxSuperblock> ParseNxSuperblock(
    const std::vector<std::byte>& block);

struct CheckpointMapping
{
    std::uint32_t type = 0;
    std::uint32_t subtype = 0;
    std::uint32_t size_bytes = 0;
    std::uint64_t file_system_oid = 0;
    std::uint64_t object_id = 0;
    std::uint64_t physical_block = 0;

};

struct ContainerCheckpointView
{
    NxSuperblock superblock;
    std::uint64_t superblock_physical_block = 0;
    std::vector<std::byte> superblock_bytes;
    std::vector<std::uint64_t> checkpoint_map_blocks;
    std::vector<CheckpointMapping> mappings;
};

// Reconstructs the newest complete Apple checkpoint. Block zero supplies only
// area geometry. A descriptor-ring NXSB is accepted only when its declared
// map blocks, mapped ephemeral objects, checksums, types, and bounds all
// validate. Malformed newer generations are skipped in favor of an older
// complete generation. Noncontiguous descriptor/data trees currently fail
// closed with an explicit error.
[[nodiscard]] std::optional<ContainerCheckpointView> LoadContainerCheckpointView(
    const RandomAccessSource& source,
    std::uint64_t store_offset_bytes,
    std::uint64_t store_size_bytes,
    std::string& out_error);

// Compatibility wrapper returning only the selected NXSB. New code that needs
// transactional state must use LoadContainerCheckpointView.
[[nodiscard]] std::optional<NxSuperblock> SelectContainerCheckpoint(
    const RandomAccessSource& source,
    std::uint64_t store_offset_bytes,
    std::uint64_t store_size_bytes);

// ---- object map / btree records ----------------------------------------------

struct BtreeRecord
{
    std::vector<std::byte> key;
    std::vector<std::byte> value;
};

struct BtreeReadPolicy
{
    bool enforce_object_identity = false;
    std::uint64_t root_object_id = 0;
    std::uint32_t storage_type = 0;
    std::uint32_t subtype = 0;
    bool include_ghost_records = false;
    const ContainerCheckpointView* ephemeral_checkpoint = nullptr;
    std::vector<std::uint64_t>* visited_physical_blocks = nullptr;
};

// Reads all leaf records under `root_block`, mirroring
// NativeApfsReader::ReadBtreeRecords exactly (same bounds, cycle cap, and
// physical/virtual child addressing). Returns false on any malformed node.
bool ReadBtreeLeafRecords(
    const RandomAccessSource& source,
    std::uint32_t block_size,
    std::uint64_t root_block,
    bool child_addresses_are_physical,
    std::uint64_t child_object_map_oid, // used when children are virtual
    std::uint64_t max_xid_hint, // enforced: nodes newer than this fail
    std::vector<BtreeRecord>& out_records,
    std::string& out_error);

bool ReadBtreeLeafRecords(
    const RandomAccessSource& source,
    std::uint32_t block_size,
    std::uint64_t root_block,
    bool child_addresses_are_physical,
    std::uint64_t child_object_map_oid,
    std::uint64_t max_xid_hint,
    const BtreeReadPolicy& policy,
    std::vector<BtreeRecord>& out_records,
    std::string& out_error);

struct OmapValue
{
    std::uint32_t flags = 0;
    std::uint32_t size = 0;
    std::uint64_t physical_block = 0;
    std::uint64_t xid = 0;
};

// Resolves `oid` through the object map `map_oid`, mirroring
// NativeApfsReader::ResolveObjectMapValue (newest xid <= max_xid wins,
// including tombstones: a newest deleted or zero-block record shadows older
// live mappings and resolves to nothing).
[[nodiscard]] std::optional<OmapValue> ResolveOmapValue(
    const RandomAccessSource& source,
    std::uint32_t block_size,
    std::uint64_t map_oid,
    std::uint64_t oid,
    std::uint64_t max_xid,
    std::string& out_error);

// ---- volume superblock (APSB) -------------------------------------------------

struct ApsbVolume
{
    std::uint64_t object_id = 0;
    std::uint64_t xid = 0;
    std::uint32_t root_tree_type = 0;
    std::uint32_t extentref_tree_type = 0;
    std::uint32_t snap_meta_tree_type = 0;
    std::uint64_t omap_oid = 0;
    std::uint64_t root_oid = 0;
    std::uint64_t extentref_tree_oid = 0;
    std::uint64_t snap_meta_tree_oid = 0;
    std::uint64_t fext_tree_oid = 0;
    std::uint32_t fext_tree_type = 0;
    std::uint64_t file_count = 0;
    std::uint64_t directory_count = 0;
    std::uint64_t features = 0;
    std::uint64_t readonly_features = 0;
    std::uint64_t incompatible_features = 0;
    std::string uuid_hex; // 32 lowercase hex digits, "" when zero
    std::string name_utf8; // best effort; see name_valid
    bool name_valid = false; // strict UTF-8 and NUL-terminated in bounds
    std::uint64_t fs_flags = 0;
    std::uint16_t role_raw = 0;
    std::string group_hex; // 32 lowercase hex digits, "" when zero
};

// Parses one block_size-sized APSB block using the Apple File System Reference
// apfs_superblock_t layout.
// Requires APSB magic, FS object type, valid checksum, and nonzero
// oid/omap/root. Does NOT judge freshness (caller compares xid).
[[nodiscard]] std::optional<ApsbVolume> ParseApsb(
    const std::vector<std::byte>& block);

struct AppleObjectLocation
{
    std::uint64_t object_id = 0;
    std::uint64_t xid = 0;
    std::uint64_t physical_block = 0;
    std::uint32_t type = 0;
    std::uint32_t subtype = 0;
    std::uint32_t size_bytes = 0;

};

struct AppleOmapView
{
    AppleObjectLocation object;
    AppleObjectLocation tree;
    std::uint32_t flags = 0;
    std::uint32_t tree_type = 0;
    std::uint32_t snapshot_tree_type = 0;
    std::uint64_t snapshot_tree_oid = 0;
};

struct AppleSpacemanFreeQueueEntry
{
    std::uint64_t xid = 0;
    std::uint64_t physical_block = 0;
    std::uint64_t block_count = 0;

};

struct AppleSpacemanFreeQueueView
{
    std::uint64_t block_count = 0;
    std::uint64_t tree_oid = 0;
    std::uint64_t oldest_xid = 0;
    std::uint16_t tree_node_limit = 0;
    std::uint32_t tree_flags = 0;
    std::uint32_t fixed_key_size = 0;
    std::uint32_t fixed_value_size = 0;
    std::uint32_t longest_key = 0;
    std::uint32_t longest_value = 0;
    AppleObjectLocation root;
    std::vector<std::uint64_t> tree_blocks;
    std::vector<AppleSpacemanFreeQueueEntry> entries;

};

struct AppleSpacemanInternalPoolBitmapView
{
    std::uint64_t xid = 0;
    std::uint64_t physical_block = 0;
    std::uint16_t rotation_index = 0;
    std::vector<std::byte> bytes;

};

struct AppleSpacemanInternalPoolView
{
    std::uint64_t block_count = 0;
    std::uint32_t bitmap_size_blocks = 0;
    std::uint32_t bitmap_block_count = 0;
    std::uint64_t bitmap_base_block = 0;
    std::uint64_t base_block = 0;
    std::uint16_t bitmap_free_head = 0;
    std::uint16_t bitmap_free_tail = 0;
    std::uint32_t bitmap_xid_offset = 0;
    std::uint32_t bitmap_index_offset = 0;
    std::uint32_t bitmap_free_next_offset = 0;
    std::vector<std::uint16_t> bitmap_free_next;
    std::vector<AppleSpacemanInternalPoolBitmapView> active_bitmaps;

};

struct AppleSpacemanChunkView
{
    std::uint64_t xid = 0;
    std::uint64_t start_block = 0;
    std::uint32_t block_count = 0;
    std::uint32_t free_count = 0;
    std::uint64_t bitmap_block = 0;
    std::size_t device_index = 0;
    std::size_t cib_index = 0;
    std::size_t index_in_cib = 0;
    std::vector<std::byte> allocation_bitmap;

};

struct AppleSpacemanCibView
{
    AppleObjectLocation object;
    std::uint32_t index = 0;
    std::vector<std::byte> bytes;
    std::vector<std::size_t> chunk_indices;

};

struct AppleSpacemanCabView
{
    AppleObjectLocation object;
    std::uint32_t index = 0;
    std::vector<std::byte> bytes;
    std::vector<std::uint64_t> cib_blocks;

};

struct AppleSpacemanDeviceView
{
    std::uint64_t block_count = 0;
    std::uint64_t chunk_count = 0;
    std::uint32_t cib_count = 0;
    std::uint32_t cab_count = 0;
    std::uint64_t free_count = 0;
    std::uint32_t address_offset = 0;
    std::vector<AppleSpacemanCabView> cabs;
    std::vector<AppleSpacemanCibView> cibs;

};

struct AppleSpacemanView
{
    AppleObjectLocation object;
    std::vector<std::byte> bytes;
    std::uint32_t blocks_per_chunk = 0;
    std::uint32_t chunks_per_cib = 0;
    std::uint32_t cibs_per_cab = 0;
    std::uint32_t flags = 0;
    std::uint32_t internal_pool_bitmap_transaction_multiplier = 0;
    std::uint32_t version = 0;
    std::uint32_t structure_size = 0;
    std::array<AppleSpacemanDeviceView, 2> devices;
    AppleSpacemanInternalPoolView internal_pool;
    std::array<AppleSpacemanFreeQueueView, 3> free_queues;
    std::vector<AppleSpacemanChunkView> chunks;
    // Compatibility projections retained while consumers migrate to the
    // typed queue views above.
    std::array<std::uint64_t, 3> free_queue_oids{};
    std::vector<AppleObjectLocation> free_queue_roots;

};

// Loads the spaceman ownership graph for an already selected checkpoint.
// `source` is relative to the same APFS store as `checkpoint`.
bool LoadAppleSpacemanOwnershipView(
    const RandomAccessSource& source,
    const ContainerCheckpointView& checkpoint,
    AppleSpacemanView& out_view,
    std::string& out_error);

struct AppleVolumeCheckpointView
{
    ApsbVolume superblock;
    AppleObjectLocation superblock_object;
    AppleOmapView object_map;
    AppleObjectLocation root_tree;
    std::optional<AppleObjectLocation> extentref_tree;
    std::optional<AppleObjectLocation> snapshot_metadata_tree;
    std::optional<AppleObjectLocation> file_extent_tree;
};

struct AppleCheckpointView
{
    ContainerCheckpointView container;
    AppleOmapView container_object_map;
    AppleSpacemanView spaceman;
    std::vector<AppleVolumeCheckpointView> volumes;
};

// Loads all transaction roots needed by the native reader and writer from one
// complete descriptor-ring generation. This API is strict: legacy two-copy
// synthetic superblocks and descriptor-less fixtures are never accepted.
[[nodiscard]] std::optional<AppleCheckpointView> LoadAppleCheckpointView(
    const RandomAccessSource& source,
    std::uint64_t store_offset_bytes,
    std::uint64_t store_size_bytes,
    std::string& out_error);

// ---- single-authority interpretation (known-bit table v1) ---------------------

[[nodiscard]] std::string CaseModeFor(std::uint64_t incompatible_features);
[[nodiscard]] std::string EncryptionModeFor(std::uint64_t fs_flags);
[[nodiscard]] std::vector<std::string> RolesFor(std::uint16_t role_raw);
[[nodiscard]] std::vector<std::string> HexBits(std::uint64_t mask);
// Bits set in `value` outside `known_mask`, as sorted unique "0x..." strings.
[[nodiscard]] std::vector<std::string> UnknownBits(
    std::uint64_t value, std::uint64_t known_mask);
[[nodiscard]] bool IsValidUtf8(const std::byte* data, std::size_t size);

} // namespace apfsaccess::catalog
