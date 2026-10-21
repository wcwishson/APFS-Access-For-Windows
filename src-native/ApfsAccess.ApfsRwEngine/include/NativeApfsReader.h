#pragma once

#include "BlockDevice.h"
#include "BtreeMutationCodec.h"
#include "MetadataStore.h"
#include "ApfsNameCodec.h"
#include "RandomAccessSource.h"
#include "ApfsSnapshotStore.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace apfsaccess::rw
{
struct NativeApfsVolumeProjection
{
    std::uint64_t checkpoint_xid = 0;
    std::uint64_t volume_object_id = 0;
    std::uint64_t volume_superblock_block = 0;
    std::uint64_t volume_object_map_oid = 0;
    std::uint64_t root_tree_oid = 0;
    std::uint64_t root_tree_block = 0;
    std::uint64_t file_extent_tree_oid = 0;
    std::uint64_t file_extent_tree_block = 0;
    std::uint64_t root_directory_inode = 0;
    std::uint64_t highest_file_system_object_id = 0;
    std::uint64_t total_blocks = 0;
    std::uint32_t block_size = 0;
    std::uint64_t incompatible_features = 0;
    ApfsNamePolicy name_policy{};
    std::vector<MetadataStore::InodeRecord> inodes;
    std::vector<MetadataStore::DirectoryLink> directory_links;
    std::vector<BtreeRecord> btree_records;
    std::unordered_map<std::uint64_t, std::map<std::string, AppleXattrRecord>> extended_attributes_by_inode;
    std::unordered_map<std::uint64_t, std::shared_ptr<const std::vector<MetadataStore::FileExtent>>> attribute_stream_extents;
    std::unordered_map<std::uint64_t, std::vector<MetadataStore::FileExtent>> read_extents_by_inode;
    // Firmlink marker census: opaque `com.apple.fs.firmlink` attributes
    // observed during projection. Reported only; the projection never
    // interprets payloads, resolves paths, or builds routes from them.
    std::uint64_t firmlink_markers_unsupported = 0;
};

// Distinct immutable result: no implicit conversion to a writable live view.
// Physical byte addresses/blocks in View() are relative to the supplied source;
// identity locations remain relative to its exact store window. No writer token.
class NativeApfsSnapshotProjection final
{
public:
    const catalog::ApfsSnapshotInfo& Snapshot() const noexcept { return snapshot_; }
    const NativeApfsVolumeProjection& View() const noexcept { return view_; }
private:
    friend class NativeApfsReader;
    catalog::ApfsSnapshotInfo snapshot_;
    NativeApfsVolumeProjection view_;
};

class NativeApfsReader
{
public:
    [[nodiscard]] static bool ValidateObservationalFileSystemRecords(
        const std::vector<catalog::BtreeRecord>& records, const catalog::NxSuperblock& container,
        const catalog::ApsbVolume& volume, const std::shared_ptr<catalog::ApfsReadBudget>& budget,
        std::string& error);
    [[nodiscard]] static bool TryProjectObservationalFileSystemRecords(
        const std::vector<catalog::BtreeRecord>& records, const catalog::NxSuperblock& container,
        const catalog::ApsbVolume& volume, const std::shared_ptr<catalog::ApfsReadBudget>& budget,
        NativeApfsVolumeProjection& projection, std::string& error);
    // Read-only directory7 references are checked against literal IS_PURGEABLE
    // regular inodes, then excluded from ordinary namespace/link counts. Names
    // remain opaque; reserved inode xfield15 is not admitted. No OS policy or
    // mutation authority. The caller authenticates the complete FS-tree walk.
    [[nodiscard]] static bool TryProjectMarkedReferenceFileSystemRecords(
        const std::vector<catalog::BtreeRecord>& records, const catalog::NxSuperblock& container,
        const catalog::ApsbVolume& volume, const std::shared_ptr<catalog::ApfsReadBudget>& budget,
        NativeApfsVolumeProjection& projection, std::string& error);
    // Source-free reuse of the strict namespace/link, stream and attribute
    // validators. Records must be a complete authoritative FS-tree walk.
    // This authenticates no checkpoint and grants no read/write capability.
    // Requires an operation budget; publishes no partial projection on failure.
    // Conservatively refuses inode xfields other than name/dstream/sparse bytes,
    // nonzero xfield flags, directory xfields and unknown inode/xattr flags.
    [[nodiscard]] static bool ValidateOrdinaryFileSystemRecords(
        const std::vector<catalog::BtreeRecord>& records,
        const catalog::NxSuperblock& container, const catalog::ApsbVolume& volume,
        const std::shared_ptr<catalog::ApfsReadBudget>& budget,
        std::string& out_error);

    // Same source-free checks, with the historical clone hint admitted only on
    // regular files in a backup-role graph. This grants no writer capability;
    // the caller must prove checkpoint, allocator and snapshot retention scope.
    [[nodiscard]] static bool ValidateBackupWriterFileSystemRecords(
        const std::vector<catalog::BtreeRecord>& records,
        const catalog::NxSuperblock& container, const catalog::ApsbVolume& volume,
        const std::shared_ptr<catalog::ApfsReadBudget>& budget,
        std::string& out_error);

    // Historical-only codec admission on the same strict backup metadata
    // profile. Caller must first prove canonical snapshot ownership/exclusion;
    // source is the bounded, zero-based whole store owning these exact records.
    [[nodiscard]] static bool ValidateBackupHistoricalFileSystemRecords(
        const catalog::RandomAccessSource& source,
        const std::vector<catalog::BtreeRecord>& records,
        const catalog::NxSuperblock& container, const catalog::ApsbVolume& volume,
        std::string& out_error);

    // Same validators and complete-walk preconditions as the discard wrapper.
    // Extents in this source-free result are STORE-relative. Pair only with the
    // admitted zero-based store view, never a parent source and nonzero window.
    // Ownership/allocator and exact-checkpoint admission remain caller duties.
    [[nodiscard]] static bool TryProjectOrdinaryFileSystemRecords(
        const std::vector<catalog::BtreeRecord>& records,
        const catalog::NxSuperblock& container, const catalog::ApsbVolume& volume,
        const std::shared_ptr<catalog::ApfsReadBudget>& budget,
        NativeApfsVolumeProjection& out_projection, std::string& out_error);

    // Requires a stable read-only source for the operation and subsequent data
    // reads. Explicit snapshot identity only; this never loads a live fallback.
    // Shares source.ReadBudget(), or installs one bounded operation allowance.
    // On failure resets out_projection, including late namespace/extent errors.
    // Bounded subset: complete KIND_NEW extentref graph, ordinary streams with
    // explicit hole coverage and supported external xattrs. Compressed default
    // forks require canonical historical decmpfs/fork ownership and codec framing;
    // byte decoding remains bounded and fail-closed on the immutable store.
    // The store window must equal NXSB geometry and start on a block boundary.
    [[nodiscard]] static bool TryLoadSnapshotProjection(
        const catalog::RandomAccessSource& source,
        const catalog::ApfsSnapshotIdentity& expected,
        std::shared_ptr<const NativeApfsSnapshotProjection>& out_projection,
        std::string& out_error);

    // Optional shared cumulative parser allowance, attached before cataloging.
    // Budgeted calls require complete namespace and attribute ownership walks.
    // Any failure clears out_projection; no unbudgeted retry occurs.
    [[nodiscard]] static bool TryLoadVolumeProjection(
        const BlockDevice& device,
        std::uint64_t volume_object_id,
        NativeApfsVolumeProjection& out_projection,
        std::wstring& out_error,
        std::optional<std::uint64_t> exact_checkpoint_xid = std::nullopt,
        std::shared_ptr<catalog::ApfsReadBudget> budget = {});

private:
    static bool ProjectReadOnlyRecordsWithAdmission(const std::vector<catalog::BtreeRecord>& records,
        const catalog::NxSuperblock& container, const catalog::ApsbVolume& volume,
        std::uint64_t routed_address_blocks, const std::shared_ptr<catalog::ApfsReadBudget>& budget,
        NativeApfsVolumeProjection& projection, std::string& error, bool observational,
        bool backup_clone_hint = false,
        const catalog::RandomAccessSource* historical_compression_source = nullptr);
    static bool ProjectReadOnlyRecordsWithProfile(const std::vector<catalog::BtreeRecord>& records,
        const catalog::NxSuperblock& container, const catalog::ApsbVolume& volume,
        std::uint64_t routed_address_blocks, const std::shared_ptr<catalog::ApfsReadBudget>& budget,
        NativeApfsVolumeProjection& projection, std::string& error, bool observational,
        bool backup_clone_hint, const catalog::RandomAccessSource* historical_compression_source,
        bool fusion_private_namespace, bool marked_reference_namespace = false);
    static bool ProjectFileSystemTreeWithAdmission(const std::vector<catalog::BtreeRecord>& records,
        std::uint32_t block_size, std::uint64_t total_blocks, std::uint64_t xid,
        const ApfsNamePolicy& name_policy, NativeApfsVolumeProjection& projection,
        bool require_complete_namespace, const std::shared_ptr<catalog::ApfsReadBudget>& budget,
        std::uint64_t routed_address_blocks, std::string* ordinary_record_error, bool observational,
        bool backup_clone_hint = false);
    static bool ProjectFileSystemTreeWithProfile(const std::vector<catalog::BtreeRecord>& records,
        std::uint32_t block_size, std::uint64_t total_blocks, std::uint64_t xid,
        const ApfsNamePolicy& name_policy, NativeApfsVolumeProjection& projection,
        bool require_complete_namespace, const std::shared_ptr<catalog::ApfsReadBudget>& budget,
        std::uint64_t routed_address_blocks, std::string* ordinary_record_error, bool observational,
        bool backup_clone_hint, bool fusion_private_namespace, bool marked_reference_namespace = false);
    friend class MetadataStore;
    friend struct NativeCheckpointHandoffTestAccess;
    struct ValidatedCheckpointProjection
    {
        const BlockDevice& device;
        const catalog::RandomAccessSource& source;
        const catalog::AppleCheckpointView& checkpoint;
        const MetadataStore::VolumeContext& expected;
        std::uint64_t checkpoint_xid;
        std::optional<BlockDevice::StableImageIdentity> image_identity;
        std::string raw_identity;
        bool consumed = false;

        ValidatedCheckpointProjection(const BlockDevice& device,
            const catalog::RandomAccessSource& source,
            const catalog::AppleCheckpointView& checkpoint,
            const MetadataStore::VolumeContext& expected, std::uint64_t xid,
            std::optional<BlockDevice::StableImageIdentity> image_identity, std::string raw_identity)
            : device(device), source(source), checkpoint(checkpoint), expected(expected),
              checkpoint_xid(xid), image_identity(std::move(image_identity)), raw_identity(std::move(raw_identity)) {}
        ValidatedCheckpointProjection(const ValidatedCheckpointProjection&) = delete;
        ValidatedCheckpointProjection& operator=(const ValidatedCheckpointProjection&) = delete;
    };
    // Only the current synchronous MetadataStore load may supply this context.
    static bool TryLoadVolumeProjectionFromValidatedCheckpoint(
        ValidatedCheckpointProjection& context,
        NativeApfsVolumeProjection& projection, std::wstring& error);
    static bool TryLoadVolumeProjectionImpl(const BlockDevice& device,
        std::uint64_t volume_object_id, NativeApfsVolumeProjection& projection,
        std::wstring& error, std::optional<std::uint64_t> exact_checkpoint_xid,
        std::shared_ptr<catalog::ApfsReadBudget> budget,
        const ValidatedCheckpointProjection* context);
    friend class ApfsFusionReadSession;
    static bool ProjectFusionReadOnlyRecords(const std::vector<catalog::BtreeRecord>& records,
        const catalog::NxSuperblock& container, const catalog::ApsbVolume& volume,
        std::uint64_t routed_address_blocks,
        const std::shared_ptr<catalog::ApfsReadBudget>& budget,
        NativeApfsVolumeProjection& projection, std::string& error);
    static bool ProjectReadOnlyRecords(const std::vector<catalog::BtreeRecord>& records,
        const catalog::NxSuperblock& container, const catalog::ApsbVolume& volume,
        std::uint64_t routed_address_blocks,
        const std::shared_ptr<catalog::ApfsReadBudget>& budget,
        NativeApfsVolumeProjection& projection, std::string& error);
    struct ObjectMapValue
    {
        std::uint32_t flags = 0;
        std::uint32_t size = 0;
        std::uint64_t physical_block = 0;
        std::uint64_t xid = 0;
    };

    using RawBtreeRecord = catalog::BtreeRecord;

    struct VolumeSuperblock
    {
        std::uint64_t object_id = 0;
        std::uint64_t xid = 0;
        std::uint64_t object_map_oid = 0;
        std::uint64_t root_tree_oid = 0;
        std::uint64_t file_extent_tree_oid = 0;
        std::uint64_t file_count = 0;
        std::uint64_t directory_count = 0;
    };

    struct ObjectMapRecordsCacheKey
    {
        std::uint32_t block_size = 0;
        std::uint64_t map_oid = 0;

        bool operator==(const ObjectMapRecordsCacheKey& other) const noexcept
        {
            return block_size == other.block_size && map_oid == other.map_oid;
        }
    };

    struct ObjectMapValueCacheKey
    {
        std::uint32_t block_size = 0;
        std::uint64_t map_oid = 0;
        std::uint64_t object_id = 0;
        std::uint64_t xid = 0;

        bool operator==(const ObjectMapValueCacheKey& other) const noexcept
        {
            return block_size == other.block_size &&
                   map_oid == other.map_oid &&
                   object_id == other.object_id &&
                   xid == other.xid;
        }
    };

    struct ObjectMapRecordsCacheKeyHash
    {
        std::size_t operator()(const ObjectMapRecordsCacheKey& key) const noexcept
        {
            auto seed = std::hash<std::uint32_t>{}(key.block_size);
            seed ^= std::hash<std::uint64_t>{}(key.map_oid) + 0x9e3779b97f4a7c15ull + (seed << 6) + (seed >> 2);
            return seed;
        }
    };

    struct ObjectMapValueCacheKeyHash
    {
        std::size_t operator()(const ObjectMapValueCacheKey& key) const noexcept
        {
            auto seed = std::hash<std::uint32_t>{}(key.block_size);
            seed ^= std::hash<std::uint64_t>{}(key.map_oid) + 0x9e3779b97f4a7c15ull + (seed << 6) + (seed >> 2);
            seed ^= std::hash<std::uint64_t>{}(key.object_id) + 0x9e3779b97f4a7c15ull + (seed << 6) + (seed >> 2);
            seed ^= std::hash<std::uint64_t>{}(key.xid) + 0x9e3779b97f4a7c15ull + (seed << 6) + (seed >> 2);
            return seed;
        }
    };

    struct ProjectionLookupCache
    {
        std::unordered_map<ObjectMapRecordsCacheKey, std::vector<RawBtreeRecord>, ObjectMapRecordsCacheKeyHash> object_map_records;
        std::unordered_map<ObjectMapValueCacheKey, std::optional<ObjectMapValue>, ObjectMapValueCacheKeyHash> object_map_values;
    };

    [[nodiscard]] static bool ReadBlock(
        const BlockDevice& device,
        std::uint32_t block_size,
        std::uint64_t block_index,
        std::vector<std::byte>& out_block);

    [[nodiscard]] static std::optional<ObjectMapValue> ResolveObjectMapValue(
        const BlockDevice& device,
        std::uint32_t block_size,
        std::uint64_t map_oid,
        std::uint64_t object_id,
        std::uint64_t xid,
        ProjectionLookupCache* cache = nullptr);

    [[nodiscard]] static bool ReadObjectMapRecords(
        const BlockDevice& device,
        std::uint32_t block_size,
        std::uint64_t map_oid,
        std::vector<RawBtreeRecord>& out_records);

    [[nodiscard]] static bool ReadBtreeRecords(
        const BlockDevice& device,
        std::uint32_t block_size,
        std::uint64_t root_block,
        bool child_addresses_are_physical,
        std::optional<std::uint64_t> child_object_map_oid,
        std::uint64_t xid,
        std::vector<RawBtreeRecord>& out_records,
        ProjectionLookupCache* cache = nullptr);

    [[nodiscard]] static bool ParseVolumeSuperblock(
        const std::vector<std::byte>& block,
        VolumeSuperblock& out_superblock);

    [[nodiscard]] static bool ProjectFileSystemTree(
        const std::vector<RawBtreeRecord>& records,
        std::uint32_t block_size,
        std::uint64_t total_blocks,
        std::uint64_t xid,
        const ApfsNamePolicy& name_policy,
        NativeApfsVolumeProjection& projection,
        bool require_complete_namespace,
        const std::shared_ptr<catalog::ApfsReadBudget>& budget = {},
        std::uint64_t routed_address_blocks = 0,
        // Nonnull folds source-free ordinary admission into this decode pass.
        std::string* ordinary_record_error = nullptr);
};
} // namespace apfsaccess::rw
