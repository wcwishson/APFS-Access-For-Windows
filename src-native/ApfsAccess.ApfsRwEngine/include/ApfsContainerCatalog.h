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

namespace apfsaccess::rw
{
class BlockDevice;
} // namespace apfsaccess::rw

namespace apfsaccess::catalog
{

struct GptPartitionDescriptor
{
    std::string stable_partition_id; // apfs-part:<guid>
    std::uint32_t partition_number = 0;
    std::string partition_guid; // lowercase GUID-D
    std::string type_guid; // lowercase GUID-D
    std::string name_utf8; // best effort
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
};

struct ApfsVolumeDescriptor
{
    std::uint64_t object_id = 0;
    std::string volume_uuid_hex; // "" when zero
    std::string group_uuid_hex; // "" when zero
    std::string name_utf8;
    bool name_valid = false;
    std::uint16_t role_raw = 0;
    std::vector<std::string> roles;
    std::string case_mode; // sensitive|insensitive|unknown
    std::string encryption_mode; // none|password|hardware-bound|unknown
    bool locked = false;
    std::uint64_t compatible_features = 0;
    std::uint64_t readonly_features = 0;
    std::uint64_t incompatible_features = 0;
    std::vector<std::string> compatible_bits;
    std::vector<std::string> readonly_bits;
    std::vector<std::string> incompatible_bits;
    std::vector<std::string> unknown_bits;
    std::uint64_t superblock_block = 0;
    std::uint64_t superblock_xid = 0;
};

struct ApfsVolumeGroupDescriptor
{
    std::string group_uuid_hex;
    std::vector<std::string> member_volume_ids; // apfs-vol:<container>:<oid>
};

struct ApfsContainerDescriptor
{
    std::string container_uuid_hex;
    std::vector<std::string> member_store_ids;
    std::vector<ApfsVolumeDescriptor> volumes;
    std::vector<ApfsVolumeGroupDescriptor> groups; // >= 2 members only
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
    bool fusion = false; // more than one member store
};

struct ResolvedMountVolume
{
    std::string container_uuid_hex;
    std::string volume_uuid_hex;
    std::string name_utf8;
    std::uint64_t object_id = 0;
};

class ApfsContainerCatalog
{
public:
    // Loads one image file (regular fixture). `disk_id` becomes the disk slug
    // (apfs-disk:<disk_id>); `device_identifier` is recorded verbatim.
    static bool TryLoadImage(
        const RandomAccessSource& image,
        const std::string& disk_id,
        const std::string& device_identifier,
        ApfsContainerCatalog& out_catalog,
        std::string& out_error);

    // Loads a Windows block device (the plan's TryLoadDevice signature).
    static bool TryLoadDevice(
        const rw::BlockDevice& device,
        ApfsContainerCatalog& out_catalog,
        std::wstring& out_error);

    // Name resolution for mount: exactly one volume with `name_utf8` across
    // all containers, else false (ambiguity and absence both fail closed).
    // Never falls back to the first volume or to object ID 0.
    [[nodiscard]] bool TryResolveVolumeByName(
        const std::string& name_utf8, ResolvedMountVolume& out_volume, std::string& out_error) const;
    [[nodiscard]] bool TryResolveVolumeByOid(
        std::uint64_t object_id, ResolvedMountVolume& out_volume, std::string& out_error) const;

    [[nodiscard]] const std::string& DiskId() const noexcept { return disk_id_; }
    [[nodiscard]] const std::string& DeviceIdentifier() const noexcept { return device_identifier_; }
    [[nodiscard]] const std::string& DiskGuid() const noexcept { return disk_guid_; }
    [[nodiscard]] std::uint64_t DiskSizeBytes() const noexcept { return disk_size_bytes_; }
    [[nodiscard]] const std::vector<GptPartitionDescriptor>& Partitions() const noexcept { return partitions_; }
    [[nodiscard]] const std::vector<ApfsPhysicalStoreDescriptor>& Stores() const noexcept { return stores_; }
    [[nodiscard]] const std::vector<ApfsContainerDescriptor>& Containers() const noexcept { return containers_; }

private:
    std::string disk_id_;
    std::string device_identifier_;
    std::string disk_guid_; // GPT disk GUID, "" for partitionless stores
    std::uint64_t disk_size_bytes_ = 0;
    std::vector<GptPartitionDescriptor> partitions_;
    std::vector<ApfsPhysicalStoreDescriptor> stores_;
    std::vector<ApfsContainerDescriptor> containers_;
};

} // namespace apfsaccess::catalog
