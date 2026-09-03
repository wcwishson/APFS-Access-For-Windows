#pragma once

// Portable, bounds-checked APFS on-disk readers shared by the catalog parser
// and the repo-owned observer. All multi-byte integers are explicit
// little-endian; no structure is ever reinterpreted from raw bytes.
//
// Field-offset sources:
//   [CODE] verified against NativeApfsReader.cpp / NativeApfsBackend.cs in
//          this repository (cited per reader).
//   [APPLE] recalled from the published APFS reference layout; real-macOS
//          byte validation of [APPLE]-only fields is an explicit C0b/C0-final
//          external gate. [APPLE] fields are advisory: identity and safety
//          decisions never depend on them alone.

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
inline constexpr std::uint32_t kObjectTypeBtree = 0x00000002;
inline constexpr std::uint32_t kObjectTypeBtreeNode = 0x00000003;
inline constexpr std::uint32_t kObjectTypeFs = 0x0000000D;

// GPT APFS partition type GUID bytes in mixed-endian order:
// 7C3457EF-0000-11AA-AA11-00306543ECAC ([CODE]: ApfsPartitionTypeGuid).
inline constexpr std::array<std::byte, 16> kApfsPartitionTypeGuidBytes = {
    std::byte{0xEF}, std::byte{0x57}, std::byte{0x34}, std::byte{0x7C},
    std::byte{0x00}, std::byte{0x00}, std::byte{0xAA}, std::byte{0x11},
    std::byte{0xAA}, std::byte{0x11}, std::byte{0x00}, std::byte{0x30},
    std::byte{0x65}, std::byte{0x43}, std::byte{0xEC}, std::byte{0xAC},
};

// Known-bit table v1 (see task-1-interface-freeze.md section 5).
// [APPLE] except where noted; unknown bits fail closed downstream.
inline constexpr std::uint64_t kIncompatCaseInsensitive = 0x10ULL; // known benign
inline constexpr std::uint64_t kIncompatKnownBenignMask = kIncompatCaseInsensitive;
inline constexpr std::uint64_t kFsFlagUnencrypted = 0x1ULL; // [APPLE]
inline constexpr std::uint64_t kFsFlagEffaceable = 0x2ULL; // [APPLE]
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
// ([CODE] layout: NativeApfsBackend.TryReadGptPartitions).
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
    std::uint64_t omap_oid = 0;
    std::vector<std::uint64_t> fs_oids; // nonzero nx_fs_oid slots, in order
};

// Parses one block_size-sized NXSB block ([CODE] offsets:
// NativeApfsBackend.TryParseApfsContainerHeader). Requires magic, sane
// geometry, a valid object checksum, and a nonzero UUID.
[[nodiscard]] std::optional<NxSuperblock> ParseNxSuperblock(
    const std::vector<std::byte>& block);

// Selects the newest valid checkpoint between the blocks at store-relative
// blocks 0 and 1. Both valid requires equal UUID and geometry, else nullopt.
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

// Reads all leaf records under `root_block`, mirroring
// NativeApfsReader::ReadBtreeRecords exactly (same bounds, cycle cap, and
// physical/virtual child addressing). Returns false on any malformed node.
bool ReadBtreeLeafRecords(
    const RandomAccessSource& source,
    std::uint32_t block_size,
    std::uint64_t root_block,
    bool child_addresses_are_physical,
    std::uint64_t child_object_map_oid, // used when children are virtual
    std::uint64_t max_xid_hint, // informational upper bound for children
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
// NativeApfsReader::ResolveObjectMapValue (newest xid <= max_xid, skipping
// deleted and zero-block entries).
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
    std::uint64_t omap_oid = 0;
    std::uint64_t root_oid = 0;
    std::uint64_t extent_tree_oid = 0;
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

// Parses one block_size-sized APSB block ([CODE] offsets: 0x80/0x88/0xB8/0xC0/
// 0x408 in NativeApfsReader::ParseVolumeSuperblock; remainder [APPLE]).
// Requires APSB magic, FS object type, valid checksum, and nonzero
// oid/omap/root. Does NOT judge freshness (caller compares xid).
[[nodiscard]] std::optional<ApsbVolume> ParseApsb(
    const std::vector<std::byte>& block);

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
