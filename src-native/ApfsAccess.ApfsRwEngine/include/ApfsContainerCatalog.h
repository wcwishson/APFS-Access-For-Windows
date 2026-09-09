#pragma once

// Typed physical-disk, GPT-partition, physical-store, container, and volume
// topology parsed by the single authoritative native reader. Managed, IPC,
// CLI, and GUI layers are lossless projections of these descriptors and must
// not independently infer APFS identities or feature support.
//
// Stable identity grammar (Task 1 canonical encoding):
//   disk:      apfs-disk:<slug>
//   partition: apfs-part:<guid-lower>
//   store:     apfs-store:<partition-guid-lower> | apfs-store:raw
//   container: apfs-container:<hex32-lower>
//   volume:    apfs-vol:<container-hex32-lower>:<oid-decimal>
//   group:     apfs-group:<hex32-lower>

#include <cstdint>
#include <string>
#include <vector>

#include "ApfsFormat.h"
#include "ApfsSharedSpace.h"

namespace apfsaccess::rw
{
class BlockDevice;
} // namespace apfsaccess::rw

namespace apfsaccess::catalog
{
class ApfsFusionStore;
enum class CatalogValidation { Legacy, CompleteAllocator, ReadOnlyObjects };
enum class VolumeReadSupport { Ordinary, EncryptionUnsupported, FeaturesUnsupported, FileExtentTreeUnsupported };

struct GptPartitionDescriptor
{
    std::string stable_partition_id; // apfs-part:<guid>
    std::uint32_t partition_number = 0;
    std::string partition_guid; // lowercase GUID-D
    std::string type_guid; // lowercase GUID-D
    std::string name_utf8; // best effort
    std::string usage; // apfs|other
    std::uint64_t offset_bytes = 0;
    std::uint64_t length_bytes = 0;
};

struct ApfsPhysicalStoreDescriptor
{
    std::string stable_store_id;
    std::string partition_id; // "" for partitionless stores
    std::string container_uuid_hex;
    std::uint64_t offset_bytes = 0;
    std::uint64_t size_bytes = 0;
    std::uint32_t block_size_bytes = 0; // from the store checkpoint
    std::uint64_t total_blocks = 0; // from the store checkpoint
};

struct ApfsVolumeDescriptor
{
    std::string stable_volume_id;
    VolumeReadSupport read_support = VolumeReadSupport::Ordinary;
    std::uint64_t object_id = 0;
    std::string volume_uuid_hex; // "" when zero
    std::string group_uuid_hex; // "" when zero
    std::string name_utf8;
    bool name_valid = false;
    std::uint16_t role_raw = 0;
    std::string role_name; // exact on-disk role; zero is "none"
    std::vector<std::string> roles;
    // Known only when loaded through the strict Apple checkpoint reader.
    std::optional<ApfsVolumeSpaceCounters> space;
    bool group_metadata_valid = true;
    std::string group_association_status; // none|incomplete|valid-system-data|ambiguous|malformed
    std::string case_mode; // sensitive|insensitive|unknown
    std::string encryption_mode; // none|password|hardware-bound|unknown
    bool locked = false;
    std::uint64_t compatible_features = 0;
    std::uint64_t readonly_features = 0;
    std::uint64_t incompatible_features = 0;
    std::uint64_t name_policy_features = 0;
    std::vector<std::string> compatible_bits;
    std::vector<std::string> readonly_bits;
    std::vector<std::string> incompatible_bits;
    std::vector<std::string> unknown_bits;
    std::uint64_t superblock_block = 0;
    std::uint64_t superblock_xid = 0;
};

struct ApfsVolumeGroupDescriptor
{
    // Keep the existing apfs-group:<uuid> spelling. Relationship identity is
    // the pair (container_uuid_hex, group_uuid_hex), never group UUID alone.
    std::string container_uuid_hex;
    std::string group_uuid_hex;
    std::vector<std::string> member_volume_ids; // apfs-vol:<container>:<oid>
    // valid-system-data|incomplete|ambiguous|malformed
    std::string association_status;
    // Filled only for one well-formed System/Data pair. These are metadata
    // relationships, not firmlink routing or mount/write authorization.
    std::string system_volume_id;
    std::string data_volume_id;
};

struct ApfsContainerDescriptor
{
    std::string container_uuid_hex;
    std::vector<std::string> member_store_ids;
    std::vector<ApfsVolumeDescriptor> volumes;
    std::vector<ApfsVolumeGroupDescriptor> groups; // >= 2 members; singleton status stays on volume
    std::vector<std::string> orphan_volume_oids; // resolved but unlisted (info)
    std::uint32_t block_size = 0;
    std::uint64_t checkpoint_xid = 0;
    std::uint64_t total_blocks = 0;
    std::uint64_t compatible_features = 0;
    std::uint64_t readonly_features = 0;
    std::uint64_t incompatible_features = 0;
    std::vector<std::string> compatible_bits;
    std::vector<std::string> readonly_bits;
    std::vector<std::string> incompatible_bits;
    std::vector<std::string> unknown_bits;
    CatalogValidation validation = CatalogValidation::Legacy;
    bool fusion = false; // more than one member store
};

struct ResolvedMountVolume
{
    std::string container_uuid_hex;
    std::string volume_uuid_hex;
    std::string name_utf8;
    std::uint64_t object_id = 0;
    std::uint64_t incompatible_features = 0;
};

enum class CatalogLoadPolicy
{
    AllowLegacySynthetic,
    StrictApple,
};

struct ApfsStoreCheckpointView
{
    std::string stable_store_id;
    AppleCheckpointView checkpoint;
};

class ApfsContainerCatalog
{
public:
    static bool TryLoadFusion(const ApfsFusionStore& source, const std::string& disk_id,
        const std::string& device_identifier, ApfsContainerCatalog& out, std::string& error);
    bool CheckAvailable(std::string& error) const;
    const AppleReadOnlyVolumeView* TryGetReadOnlyVolumeView() const;
    // Loads one image file (regular fixture). `disk_id` becomes the disk slug
    // (apfs-disk:<disk_id>); `device_identifier` is recorded verbatim.
    static bool TryLoadImage(
        const RandomAccessSource& image,
        const std::string& disk_id,
        const std::string& device_identifier,
        ApfsContainerCatalog& out_catalog,
        std::string& out_error,
        CatalogLoadPolicy policy = CatalogLoadPolicy::AllowLegacySynthetic);

    // Loads a Windows block device (the plan's TryLoadDevice signature).
    static bool TryLoadDevice(
        const rw::BlockDevice& device,
        ApfsContainerCatalog& out_catalog,
        std::wstring& out_error,
        CatalogLoadPolicy policy = CatalogLoadPolicy::StrictApple);

    // Name resolution for mount: exactly one volume with `name_utf8` across
    // all containers, else false (ambiguity and absence both fail closed).
    // Never falls back to the first volume or to object ID 0.
    [[nodiscard]] bool TryResolveVolumeByName(
        const std::string& name_utf8, ResolvedMountVolume& out_volume, std::string& out_error) const;
    [[nodiscard]] bool TryResolveVolumeByOid(
        std::uint64_t object_id, ResolvedMountVolume& out_volume, std::string& out_error) const;
    // Container-qualified exact resolution: the volume must live in the named
    // container. Fails closed on absent containers, absent OIDs, and (by
    // construction) cross-container ambiguity.
    [[nodiscard]] bool TryResolveVolume(
        const std::string& container_uuid_hex, std::uint64_t object_id,
        ResolvedMountVolume& out_volume, std::string& out_error) const;
    // Container-scoped name resolution: exactly one volume with `name_utf8`
    // in the named container, else false. Lets duplicate display names stay
    // independently addressable under --container-id.
    [[nodiscard]] bool TryResolveVolumeByNameInContainer(
        const std::string& container_uuid_hex, const std::string& name_utf8,
        ResolvedMountVolume& out_volume, std::string& out_error) const;

    [[nodiscard]] const std::string& DiskId() const noexcept { return disk_id_; }
    [[nodiscard]] const std::string& DeviceIdentifier() const noexcept { return device_identifier_; }
    [[nodiscard]] const std::string& DiskGuid() const noexcept { return disk_guid_; }
    [[nodiscard]] std::uint64_t DiskSizeBytes() const noexcept { return IsAvailableNoThrow() ? disk_size_bytes_ : 0; }
    [[nodiscard]] const std::vector<GptPartitionDescriptor>& Partitions() const noexcept { return partitions_; }
    [[nodiscard]] const std::vector<ApfsPhysicalStoreDescriptor>& Stores() const noexcept { static const std::vector<ApfsPhysicalStoreDescriptor> empty; return IsAvailableNoThrow() ? stores_ : empty; }
    [[nodiscard]] const std::vector<ApfsContainerDescriptor>& Containers() const noexcept { static const std::vector<ApfsContainerDescriptor> empty; return IsAvailableNoThrow() ? containers_ : empty; }
    [[nodiscard]] const AppleCheckpointView* TryGetAppleCheckpointView(
        const std::string& stable_store_id) const noexcept;
    // Uses the privately retained strict checkpoint; legacy/Fusion space is
    // unknown and returns false. No observer/service/WinFsp wiring is implied.
    [[nodiscard]] bool TryProjectSharedSpace(const std::string& container_uuid_hex,
        ApfsSharedSpaceProjection& out, std::string& error) const;

private:
    bool IsAvailableNoThrow() const noexcept
    {
        try { std::string error; return CheckAvailable(error); }
        catch (...) { return false; }
    }
    std::function<bool(std::string&)> availability_;
    std::optional<AppleReadOnlyVolumeView> readonly_view_;
    std::string disk_id_;
    std::string device_identifier_;
    std::string disk_guid_; // GPT disk GUID, "" for partitionless stores
    std::uint64_t disk_size_bytes_ = 0;
    std::vector<GptPartitionDescriptor> partitions_;
    std::vector<ApfsPhysicalStoreDescriptor> stores_;
    std::vector<ApfsContainerDescriptor> containers_;
    std::vector<ApfsStoreCheckpointView> checkpoint_views_;
};

} // namespace apfsaccess::catalog
