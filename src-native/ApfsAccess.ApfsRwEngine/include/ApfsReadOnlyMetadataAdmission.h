#pragma once

#include "ApfsFormat.h"

namespace apfsaccess::catalog
{
// Apple apfs_superblock_t and apfsprogs apfsck/super.c (a6f9ec1485af):
// zero OIDs with zero/exact physical-B-tree type defaults describe no active
// tail tree. Reserved-field semantics remain unknown outside this narrow case.
// This observational check grants no mutation, allocation or release authority.
namespace readonly_metadata_detail
{
[[nodiscard]] inline bool CheckInactiveTreeDefaults(
    const std::vector<std::byte>& bytes, const ApsbVolume& expected, std::string& error, std::uint64_t fs_flags)
{
    const auto fail = [&](const char* reason) { error = reason; return false; };
    if (bytes.size() < 4096 || bytes.size() > 65536 || (bytes.size() & (bytes.size() - 1)))
        return fail("SnapshotReadOnlyApsbBoundsInvalid");
    const auto parsed = ParseApsb(bytes);
    if (!parsed) return fail("SnapshotReadOnlyApsbInvalid");
    const auto& volume = *parsed;
    if (volume.object_id != expected.object_id || volume.xid != expected.xid ||
        volume.uuid_hex != expected.uuid_hex || volume.omap_oid != expected.omap_oid ||
        volume.root_oid != expected.root_oid || volume.fext_tree_oid != expected.fext_tree_oid ||
        volume.root_tree_type != expected.root_tree_type || volume.extentref_tree_type != expected.extentref_tree_type ||
        volume.snap_meta_tree_type != expected.snap_meta_tree_type || volume.extentref_tree_oid != expected.extentref_tree_oid ||
        volume.snap_meta_tree_oid != expected.snap_meta_tree_oid || volume.file_count != expected.file_count ||
        volume.directory_count != expected.directory_count || volume.next_object_id != expected.next_object_id ||
        volume.name_utf8 != expected.name_utf8 || volume.name_valid != expected.name_valid || volume.group_hex != expected.group_hex ||
        volume.space.reserve_block_count != expected.space.reserve_block_count ||
        volume.space.quota_block_count != expected.space.quota_block_count ||
        volume.space.allocated_block_count != expected.space.allocated_block_count ||
        volume.fext_tree_type != expected.fext_tree_type || volume.fs_flags != expected.fs_flags ||
        volume.features != expected.features || volume.readonly_features != expected.readonly_features ||
        volume.incompatible_features != expected.incompatible_features || volume.role_raw != expected.role_raw ||
        volume.snap_meta_ext_oid != expected.snap_meta_ext_oid)
        return fail("SnapshotReadOnlyApsbBindingMismatch");
    if (volume.uuid_hex.empty() || !volume.xid || !volume.name_valid ||
        volume.fs_flags != fs_flags || (volume.features & ~kVolumeKnownOptionalFeaturesMask) ||
        volume.readonly_features || (volume.incompatible_features & ~kVolumeSupportedIncompatibleFeaturesMask))
        return fail("SnapshotVolumeFeaturesUnsupported");
    const auto type = ReadU32LE(bytes, 0x18);
    if ((type != kObjectTypeFs && type != (kObjectPhysical | kObjectTypeFs)) || ReadU32LE(bytes, 0x1C) != 0u)
        return fail("SnapshotReadOnlyApsbObjectFlagsUnsupported");
    const auto reserved_type = ReadU32LE(bytes, 0x414);
    const auto reserved_oid = ReadU64LE(bytes, 0x418);
    const auto integrity_oid = ReadU64LE(bytes, 0x400);
    const auto inactive_type = [](std::uint32_t value) {
        return value == 0 || value == (kObjectPhysical | kObjectTypeBtree);
    };
    if (!reserved_type || !reserved_oid || !integrity_oid || *reserved_oid || *integrity_oid ||
        volume.fext_tree_oid || !inactive_type(volume.fext_tree_type) || !inactive_type(*reserved_type))
        return fail("SnapshotVolumeStateOrReservedFieldsUnsupported");
    error.clear();
    return true;
}
}

[[nodiscard]] inline bool CheckAppleReadOnlyInactiveTreeDefaults(
    const std::vector<std::byte>& bytes, const ApsbVolume& expected, std::string& error)
{
    return readonly_metadata_detail::CheckInactiveTreeDefaults(bytes, expected, error, kFsFlagUnencrypted);
}

// APSB tail facts only. Caller must already hold the canonical ONEKEY metadata
// context; this helper neither decrypts nor grants generic crypto admission.
[[nodiscard]] inline bool CheckAppleReadOnlyOneKeyInactiveTreeDefaults(
    const std::vector<std::byte>& bytes, const ApsbVolume& expected, std::string& error)
{
    return readonly_metadata_detail::CheckInactiveTreeDefaults(bytes, expected, error, kFsFlagOneKey);
}

// Explicit observational counterparts. Existing catalog/descriptor exports
// remain strict, including all transaction, retirement and encrypted callers.
// These reuse the canonical walker on original checked bytes and share the
// caller's exact allowance. Any failure clears the complete output.
[[nodiscard]] bool LoadAppleReadOnlySnapshotCatalog(const RandomAccessSource& source,
    const AppleCheckpointView& checkpoint, std::uint64_t volume_oid,
    AppleSnapshotCatalogRecords& out_catalog, std::string& out_error);
[[nodiscard]] bool LoadAppleReadOnlySnapshotCatalog(const RandomAccessSource& source,
    const AppleCheckpointView& checkpoint, std::uint64_t volume_oid,
    AppleSnapshotCatalogRecords& out_catalog,
    std::vector<AppleSnapshotMetadataClaim>& out_owners, std::string& out_error);
[[nodiscard]] bool LoadAppleReadOnlySnapshotDescriptorCatalog(const RandomAccessSource& source,
    const AppleCheckpointView& checkpoint, std::uint64_t owner_volume_oid,
    std::uint64_t descriptor_block, std::uint64_t filesystem_xid,
    AppleSnapshotCatalogRecords& out_catalog, std::string& out_error);
}
