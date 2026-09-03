#include "ApfsContainerCatalog.h"

#include "BlockDevice.h"

#include <algorithm>
#include <cwchar>
#include <unordered_map>
#include <unordered_set>

namespace apfsaccess::catalog
{
namespace
{

std::string ToNarrow(const std::wstring& wide)
{
    std::string narrow;
    narrow.reserve(wide.size());
    for (wchar_t ch : wide)
    {
        narrow.push_back(ch < 0x80 ? static_cast<char>(ch) : '?');
    }
    return narrow;
}

std::string StoreIdFor(const std::string& partition_id)
{
    if (partition_id.empty())
    {
        return "apfs-store:raw";
    }
    return "apfs-store:" + partition_id.substr(std::string("apfs-part:").size());
}

std::string VolumeIdFor(const std::string& container_hex, std::uint64_t oid)
{
    return "apfs-vol:" + container_hex + ":" + std::to_string(oid);
}

bool AppendUnique(std::vector<std::string>& list, const std::string& value)
{
    if (std::find(list.begin(), list.end(), value) != list.end())
    {
        return false;
    }
    list.push_back(value);
    return true;
}

struct StoreCheckpoint
{
    NxSuperblock superblock;
};

bool LoadStoreCheckpoint(
    const RandomAccessSource& store_view,
    const std::string& what,
    StoreCheckpoint& out,
    std::string& out_error)
{
    auto checkpoint = SelectContainerCheckpoint(store_view, 0, store_view.SizeBytes());
    if (!checkpoint.has_value())
    {
        out_error = "CatalogCheckpointInvalid:" + what;
        return false;
    }
    out.superblock = std::move(checkpoint.value());
    return true;
}

bool LoadStoreVolumes(
    const RandomAccessSource& store_view,
    const StoreCheckpoint& checkpoint,
    const std::string& container_hex,
    std::vector<ApfsVolumeDescriptor>& out_volumes,
    std::vector<std::string>& out_orphans,
    std::string& out_error)
{
    out_volumes.clear();
    out_orphans.clear();
    const NxSuperblock& nxsb = checkpoint.superblock;
    if (nxsb.fs_oids.empty())
    {
        out_error = "CatalogNoVolumes:" + container_hex;
        return false;
    }
    std::unordered_set<std::uint64_t> seen;
    for (const std::uint64_t oid : nxsb.fs_oids)
    {
        if (!seen.insert(oid).second)
        {
            out_error = "CatalogDuplicateVolumeOid:" + std::to_string(oid);
            return false;
        }
    }
    std::vector<std::byte> block;
    for (const std::uint64_t oid : nxsb.fs_oids)
    {
        std::string resolve_error;
        auto mapping = ResolveOmapValue(
            store_view, nxsb.block_size, nxsb.omap_oid, oid, nxsb.xid, resolve_error);
        if (!mapping.has_value() || mapping->physical_block == 0)
        {
            out_error = "CatalogVolumeUnresolvable:" + std::to_string(oid) + ":" + resolve_error;
            return false;
        }
        const std::uint64_t byte_offset = mapping->physical_block * nxsb.block_size;
        block.clear();
        if (!store_view.Read(byte_offset, nxsb.block_size, block) || block.size() != nxsb.block_size)
        {
            out_error = "CatalogVolumeBlockUnreadable:" + std::to_string(oid);
            return false;
        }
        auto parsed = ParseApsb(block);
        if (!parsed.has_value())
        {
            out_error = "CatalogVolumeSuperblockInvalid:" + std::to_string(oid);
            return false;
        }
        const ApsbVolume& volume = parsed.value();
        if (volume.object_id != oid)
        {
            out_error = "CatalogVolumeOidMismatch:" + std::to_string(oid);
            return false;
        }
        if (volume.xid > nxsb.xid)
        {
            out_error = "CatalogVolumeStaleXid:" + std::to_string(oid);
            return false;
        }
        ApfsVolumeDescriptor descriptor;
        descriptor.object_id = oid;
        descriptor.volume_uuid_hex = volume.uuid_hex;
        descriptor.group_uuid_hex = volume.group_hex;
        descriptor.name_utf8 = volume.name_utf8;
        descriptor.name_valid = volume.name_valid;
        descriptor.role_raw = volume.role_raw;
        descriptor.roles = RolesFor(volume.role_raw);
        descriptor.case_mode = CaseModeFor(volume.incompatible_features);
        descriptor.encryption_mode = EncryptionModeFor(volume.fs_flags);
        descriptor.locked = descriptor.encryption_mode != "none";
        descriptor.compatible_features = volume.features;
        descriptor.readonly_features = volume.readonly_features;
        descriptor.incompatible_features =
            volume.incompatible_features & ~kIncompatKnownBenignMask;
        descriptor.compatible_bits = HexBits(volume.features);
        descriptor.readonly_bits = HexBits(volume.readonly_features);
        descriptor.incompatible_bits = HexBits(descriptor.incompatible_features);
        descriptor.unknown_bits = UnknownBits(volume.readonly_features, 0);
        const auto unknown_incompat =
            UnknownBits(volume.incompatible_features, kIncompatKnownBenignMask);
        descriptor.unknown_bits.insert(
            descriptor.unknown_bits.end(), unknown_incompat.begin(), unknown_incompat.end());
        std::sort(descriptor.unknown_bits.begin(), descriptor.unknown_bits.end());
        descriptor.unknown_bits.erase(
            std::unique(descriptor.unknown_bits.begin(), descriptor.unknown_bits.end()),
            descriptor.unknown_bits.end());
        descriptor.superblock_block = mapping->physical_block;
        descriptor.superblock_xid = volume.xid;
        out_volumes.push_back(std::move(descriptor));
    }
    return true;
}

} // namespace

bool ApfsContainerCatalog::TryLoadImage(
    const RandomAccessSource& image,
    const std::string& disk_id,
    const std::string& device_identifier,
    ApfsContainerCatalog& out_catalog,
    std::string& out_error)
{
    out_catalog = ApfsContainerCatalog{};
    out_error.clear();
    if (disk_id.empty() || device_identifier.empty())
    {
        out_error = "CatalogDiskIdentityMissing";
        return false;
    }
    const std::uint64_t disk_size = image.SizeBytes();
    if (disk_size == 0)
    {
        out_error = "CatalogEmptyImage";
        return false;
    }
    out_catalog.disk_id_ = "apfs-disk:" + disk_id;
    out_catalog.device_identifier_ = device_identifier;
    out_catalog.disk_size_bytes_ = disk_size;
    out_catalog.disk_guid_.clear();

    struct StoreSlot
    {
        std::string partition_id;
        std::uint64_t offset = 0;
        std::uint64_t size = 0;
    };
    std::vector<StoreSlot> slots;
    if (auto layout = ParseGpt(image, 0, disk_size); layout.has_value())
    {
        out_catalog.disk_guid_ = layout->disk_guid;
        for (const GptPartition& partition : layout->partitions)
        {
            GptPartitionDescriptor descriptor;
            descriptor.stable_partition_id = "apfs-part:" + partition.unique_guid;
            descriptor.partition_number = partition.number;
            descriptor.partition_guid = partition.unique_guid;
            descriptor.type_guid = partition.type_guid;
            descriptor.name_utf8 = partition.name_utf8;
            descriptor.offset_bytes = partition.start_bytes;
            descriptor.length_bytes = partition.size_bytes;
            out_catalog.partitions_.push_back(descriptor);
            if (partition.type_guid == GuidToStringLower(kApfsPartitionTypeGuidBytes.data()))
            {
                slots.push_back({descriptor.stable_partition_id, partition.start_bytes, partition.size_bytes});
            }
        }
    }
    else
    {
        // Partitionless store: NXSB must open the image.
        std::vector<std::byte> probe;
        if (!image.Read(0, 4096, probe))
        {
            out_error = "CatalogNoGptNoSuperblock";
            return false;
        }
        const bool looks_partitionless =
            probe.size() >= 0x24 && ReadU32LE(probe, 0x20).value_or(0) == kNxsbMagic;
        if (!looks_partitionless)
        {
            out_error = "CatalogNoGptNoSuperblock";
            return false;
        }
        slots.push_back({"", 0, disk_size});
    }
    if (slots.empty())
    {
        out_error = "CatalogNoApfsStores";
        return false;
    }

    // Load one checkpoint per store through a store-relative view, then group
    // stores into containers by UUID.
    struct LoadedStore
    {
        StoreSlot slot;
        StoreCheckpoint checkpoint;
        OffsetRandomAccessSource view;
        LoadedStore(StoreSlot s, const OffsetRandomAccessSource& v)
            : slot(std::move(s))
            , view(v)
        {
        }
    };
    std::vector<LoadedStore> loaded;
    std::vector<OffsetRandomAccessSource> views;
    views.reserve(slots.size());
    for (const StoreSlot& slot : slots)
    {
        views.emplace_back(&image, slot.offset, slot.size);
    }
    for (std::size_t index = 0; index < slots.size(); ++index)
    {
        LoadedStore entry(slots[index], views[index]);
        if (!LoadStoreCheckpoint(
                entry.view,
                entry.slot.partition_id.empty() ? "raw" : entry.slot.partition_id,
                entry.checkpoint, out_error))
        {
            return false;
        }
        loaded.push_back(std::move(entry));
    }

    std::unordered_map<std::string, std::size_t> container_index;
    for (const LoadedStore& entry : loaded)
    {
        const std::string& uuid = entry.checkpoint.superblock.uuid_hex;
        ApfsPhysicalStoreDescriptor store;
        store.stable_store_id = StoreIdFor(entry.slot.partition_id);
        store.partition_id = entry.slot.partition_id;
        store.container_uuid_hex = uuid;
        store.offset_bytes = entry.slot.offset;
        store.size_bytes = entry.slot.size;
        // Duplicate stable store IDs mean two partitions share one GUID.
        for (const auto& existing : out_catalog.stores_)
        {
            if (existing.stable_store_id == store.stable_store_id)
            {
                out_error = "CatalogDuplicateStoreId:" + store.stable_store_id;
                return false;
            }
        }
        out_catalog.stores_.push_back(store);

        auto found = container_index.find(uuid);
        if (found == container_index.end())
        {
            ApfsContainerDescriptor container;
            container.container_uuid_hex = uuid;
            container.block_size = entry.checkpoint.superblock.block_size;
            container.checkpoint_xid = entry.checkpoint.superblock.xid;
            container.total_blocks = entry.checkpoint.superblock.block_count;
            container.compatible_features = entry.checkpoint.superblock.features;
            container.readonly_features = entry.checkpoint.superblock.readonly_features;
            container.incompatible_features = entry.checkpoint.superblock.incompatible_features &
                ~kIncompatKnownBenignMask;
            container.compatible_bits = HexBits(container.compatible_features);
            container.readonly_bits = HexBits(container.readonly_features);
            container.incompatible_bits = HexBits(container.incompatible_features);
            container.unknown_bits =
                UnknownBits(entry.checkpoint.superblock.readonly_features, 0);
            const auto unknown_incompat = UnknownBits(
                entry.checkpoint.superblock.incompatible_features, kIncompatKnownBenignMask);
            container.unknown_bits.insert(
                container.unknown_bits.end(), unknown_incompat.begin(), unknown_incompat.end());
            std::sort(container.unknown_bits.begin(), container.unknown_bits.end());
            container.unknown_bits.erase(
                std::unique(container.unknown_bits.begin(), container.unknown_bits.end()),
                container.unknown_bits.end());
            container_index[uuid] = out_catalog.containers_.size();
            out_catalog.containers_.push_back(std::move(container));
        }
        ApfsContainerDescriptor& container =
            out_catalog.containers_[container_index[uuid]];
        if (container.block_size != entry.checkpoint.superblock.block_size ||
            container.total_blocks != entry.checkpoint.superblock.block_count)
        {
            out_error = "CatalogFusionGeometryMismatch:" + uuid;
            return false;
        }
        if (container.checkpoint_xid != entry.checkpoint.superblock.xid)
        {
            out_error = "CatalogFusionXidMismatch:" + uuid;
            return false;
        }
        container.member_store_ids.push_back(store.stable_store_id);
    }

    // Resolve volumes per container through the FIRST member store's checkpoint.
    // (Multi-store checkpoint agreement was verified above; block routing
    // across stores is Task 9 scope.)
    for (const LoadedStore& entry : loaded)
    {
        const std::string& uuid = entry.checkpoint.superblock.uuid_hex;
        ApfsContainerDescriptor& container =
            out_catalog.containers_[container_index[uuid]];
        if (!container.volumes.empty() || !container.orphan_volume_oids.empty())
        {
            continue;
        }
        std::vector<ApfsVolumeDescriptor> volumes;
        std::vector<std::string> orphans;
        if (!LoadStoreVolumes(
                entry.view, entry.checkpoint, uuid, volumes, orphans, out_error))
        {
            return false;
        }
        container.volumes = std::move(volumes);
        container.orphan_volume_oids = std::move(orphans);
    }

    for (ApfsContainerDescriptor& container : out_catalog.containers_)
    {
        container.fusion = container.member_store_ids.size() > 1;
        if (container.volumes.empty())
        {
            out_error = "CatalogNoVolumes:" + container.container_uuid_hex;
            return false;
        }
        std::unordered_set<std::string> volume_uuids;
        for (const ApfsVolumeDescriptor& volume : container.volumes)
        {
            if (!volume.volume_uuid_hex.empty() &&
                !volume_uuids.insert(volume.volume_uuid_hex).second)
            {
                out_error = "CatalogDuplicateVolumeUuid:" + volume.volume_uuid_hex;
                return false;
            }
        }
        // Cross-validated volume groups: the same nonzero group UUID must be
        // observed on at least two volumes before a group node is emitted.
        // A lone group UUID stays on its volume record only.
        std::unordered_map<std::string, std::vector<std::string>> grouped;
        for (const ApfsVolumeDescriptor& volume : container.volumes)
        {
            if (!volume.group_uuid_hex.empty())
            {
                grouped[volume.group_uuid_hex].push_back(
                    VolumeIdFor(container.container_uuid_hex, volume.object_id));
            }
        }
        for (const auto& [group_hex, members] : grouped)
        {
            if (members.size() >= 2)
            {
                ApfsVolumeGroupDescriptor group;
                group.group_uuid_hex = group_hex;
                group.member_volume_ids = members;
                container.groups.push_back(std::move(group));
            }
        }
    }
    return true;
}

bool ApfsContainerCatalog::TryLoadDevice(
    const rw::BlockDevice& device,
    ApfsContainerCatalog& out_catalog,
    std::wstring& out_error)
{
    out_error.clear();
    const std::wstring path = device.Path();
    std::string narrow = ToNarrow(path);
    if (narrow.empty())
    {
        out_error = L"CatalogDevicePathInvalid";
        return false;
    }
    // Block-device adapter without copying: forward reads with zero base.
    class DeviceSource final : public RandomAccessSource
    {
    public:
        explicit DeviceSource(const ::apfsaccess::rw::BlockDevice& device)
            : device_(device)
        {
        }
        [[nodiscard]] std::uint64_t SizeBytes() const override
        {
            return device_.GetGeometry().total_bytes;
        }
        [[nodiscard]] bool Read(
            std::uint64_t offset, std::size_t size, std::vector<std::byte>& out) const override
        {
            out.clear();
            if (size == 0)
            {
                return true;
            }
            return device_.Read(offset, size, out) && out.size() == size;
        }

    private:
        const ::apfsaccess::rw::BlockDevice& device_;
    };
    DeviceSource source(device);
    const std::uint64_t total = source.SizeBytes();
    if (total == 0)
    {
        out_error = L"CatalogDeviceEmpty";
        return false;
    }
    std::string error;
    // Disk slug: narrow device path with separators flattened.
    std::string slug;
    for (char ch : narrow)
    {
        const bool keep = (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
            (ch >= '0' && ch <= '9');
        slug.push_back(keep ? ch : '-');
    }
    while (!slug.empty() && slug.front() == '-')
    {
        slug.erase(slug.begin());
    }
    if (slug.empty())
    {
        slug = "device";
    }
    if (!TryLoadImage(source, slug, narrow, out_catalog, error))
    {
        out_error.assign(error.begin(), error.end());
        return false;
    }
    return true;
}

bool ApfsContainerCatalog::TryResolveVolumeByName(
    const std::string& name_utf8, ResolvedMountVolume& out_volume, std::string& out_error) const
{
    out_volume = ResolvedMountVolume{};
    out_error.clear();
    if (name_utf8.empty())
    {
        out_error = "CatalogVolumeNameMissing";
        return false;
    }
    ResolvedMountVolume candidate;
    bool found = false;
    std::size_t hits = 0;
    for (const ApfsContainerDescriptor& container : containers_)
    {
        for (const ApfsVolumeDescriptor& volume : container.volumes)
        {
            if (volume.name_utf8 != name_utf8)
            {
                continue;
            }
            ++hits;
            if (!found)
            {
                candidate.container_uuid_hex = container.container_uuid_hex;
                candidate.volume_uuid_hex = volume.volume_uuid_hex;
                candidate.name_utf8 = volume.name_utf8;
                candidate.object_id = volume.object_id;
                found = true;
            }
        }
    }
    if (hits != 1)
    {
        out_error = hits == 0 ? "CatalogVolumeNameMissing:" + name_utf8
                              : "CatalogVolumeNameAmbiguous:" + name_utf8;
        return false;
    }
    out_volume = candidate;
    return true;
}

bool ApfsContainerCatalog::TryResolveVolumeByOid(
    std::uint64_t object_id, ResolvedMountVolume& out_volume, std::string& out_error) const
{
    out_volume = ResolvedMountVolume{};
    out_error.clear();
    if (object_id == 0)
    {
        out_error = "CatalogVolumeOidZero";
        return false;
    }
    for (const ApfsContainerDescriptor& container : containers_)
    {
        for (const ApfsVolumeDescriptor& volume : container.volumes)
        {
            if (volume.object_id != object_id)
            {
                continue;
            }
            out_volume.container_uuid_hex = container.container_uuid_hex;
            out_volume.volume_uuid_hex = volume.volume_uuid_hex;
            out_volume.name_utf8 = volume.name_utf8;
            out_volume.object_id = volume.object_id;
            return true;
        }
    }
    out_error = "CatalogVolumeOidMissing:" + std::to_string(object_id);
    return false;
}

} // namespace apfsaccess::catalog
