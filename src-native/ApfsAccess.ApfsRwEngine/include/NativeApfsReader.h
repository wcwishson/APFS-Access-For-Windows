#pragma once

#include "BlockDevice.h"
#include "BtreeMutationCodec.h"
#include "MetadataStore.h"

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
    std::uint64_t total_blocks = 0;
    std::uint32_t block_size = 0;
    std::vector<MetadataStore::InodeRecord> inodes;
    std::vector<BtreeRecord> btree_records;
    std::unordered_map<std::uint64_t, std::vector<MetadataStore::FileExtent>> read_extents_by_inode;
};

class NativeApfsReader
{
public:
    [[nodiscard]] static bool TryLoadVolumeProjection(
        const BlockDevice& device,
        std::uint64_t volume_object_id,
        NativeApfsVolumeProjection& out_projection,
        std::wstring& out_error);

private:
    struct ObjectMapValue
    {
        std::uint32_t flags = 0;
        std::uint32_t size = 0;
        std::uint64_t physical_block = 0;
        std::uint64_t xid = 0;
    };

    struct RawBtreeRecord
    {
        std::vector<std::byte> key;
        std::vector<std::byte> value;
    };

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
        NativeApfsVolumeProjection& projection);
};
} // namespace apfsaccess::rw
