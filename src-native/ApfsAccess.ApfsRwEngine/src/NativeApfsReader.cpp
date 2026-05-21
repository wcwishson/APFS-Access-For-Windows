#include "NativeApfsReader.h"

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <cwchar>
#include <iostream>
#include <iterator>
#include <limits>
#include <queue>
#include <unordered_map>
#include <unordered_set>
#include <Windows.h>

namespace apfsaccess::rw
{
namespace
{
constexpr std::uint32_t kNxsbMagic = 0x4253584E; // 'NXSB'
constexpr std::uint32_t kApsbMagic = 0x42535041; // 'APSB'
constexpr std::uint32_t kObjectTypeMask = 0x0000FFFF;
constexpr std::uint32_t kObjectTypeOmap = 0x0000000B;
constexpr std::uint32_t kObjectTypeBtree = 0x00000002;
constexpr std::uint32_t kObjectTypeBtreeNode = 0x00000003;
constexpr std::uint32_t kObjectTypeFs = 0x0000000D;
constexpr std::uint32_t kObjectTypeCheckpointMap = 0x0000000C;
constexpr std::uint16_t kBtnodeRoot = 0x0001;
constexpr std::uint16_t kBtnodeLeaf = 0x0002;
constexpr std::uint16_t kBtnodeFixedKvSize = 0x0004;
constexpr std::uint64_t kApfsObjectIdMask = 0x0fffffffffffffffull;
constexpr std::uint64_t kApfsObjectTypeShift = 60;
constexpr std::uint64_t kApfsTypeInode = 3;
constexpr std::uint64_t kApfsTypeFileExtent = 8;
constexpr std::uint64_t kApfsTypeDirectoryRecord = 9;
constexpr std::uint64_t kRootDirectoryInode = 2;
constexpr std::uint8_t kInodeExtendedFieldDataStream = 8;
constexpr std::size_t kInodeUncompressedSizeOffset = 0x54;
constexpr std::size_t kInodeExtendedFieldsOffset = 0x5C;
constexpr std::uint64_t kWindowsFileTimeUnixEpochTicks = 116444736000000000ull;
constexpr std::uint16_t kModeTypeMask = 0170000;
constexpr std::uint16_t kModeDirectory = 0040000;
constexpr std::uint16_t kModeRegular = 0100000;
constexpr std::uint16_t kModeSymlink = 0120000;
constexpr std::uint16_t kDrecTypeMask = 0x000f;
constexpr std::uint16_t kDrecTypeDirectory = 4;
constexpr std::uint16_t kDrecTypeRegular = 8;
constexpr std::uint16_t kDrecTypeSymlink = 10;
constexpr std::size_t kObjectHeaderBytes = 0x20;
constexpr std::size_t kBtreeDataOffset = 0x38;
constexpr std::size_t kBtreeInfoBytes = 40;

std::uint16_t ReadLe16(const std::vector<std::byte>& buffer, std::size_t offset)
{
    if (offset + sizeof(std::uint16_t) > buffer.size())
    {
        return 0;
    }
    return static_cast<std::uint16_t>(std::to_integer<unsigned char>(buffer[offset + 0])) |
           (static_cast<std::uint16_t>(std::to_integer<unsigned char>(buffer[offset + 1])) << 8);
}

std::uint32_t ReadLe32(const std::vector<std::byte>& buffer, std::size_t offset)
{
    if (offset + sizeof(std::uint32_t) > buffer.size())
    {
        return 0;
    }
    return static_cast<std::uint32_t>(std::to_integer<unsigned char>(buffer[offset + 0])) |
           (static_cast<std::uint32_t>(std::to_integer<unsigned char>(buffer[offset + 1])) << 8) |
           (static_cast<std::uint32_t>(std::to_integer<unsigned char>(buffer[offset + 2])) << 16) |
           (static_cast<std::uint32_t>(std::to_integer<unsigned char>(buffer[offset + 3])) << 24);
}

std::uint64_t ReadLe64(const std::vector<std::byte>& buffer, std::size_t offset)
{
    if (offset + sizeof(std::uint64_t) > buffer.size())
    {
        return 0;
    }

    std::uint64_t value = 0;
    for (int index = 0; index < 8; ++index)
    {
        value |= static_cast<std::uint64_t>(std::to_integer<unsigned char>(buffer[offset + static_cast<std::size_t>(index)])) << (index * 8);
    }
    return value;
}

void AppendLe32(std::vector<std::byte>& buffer, std::uint32_t value)
{
    buffer.push_back(static_cast<std::byte>(value & 0xffu));
    buffer.push_back(static_cast<std::byte>((value >> 8) & 0xffu));
    buffer.push_back(static_cast<std::byte>((value >> 16) & 0xffu));
    buffer.push_back(static_cast<std::byte>((value >> 24) & 0xffu));
}

void AppendLe64(std::vector<std::byte>& buffer, std::uint64_t value)
{
    for (int index = 0; index < 8; ++index)
    {
        buffer.push_back(static_cast<std::byte>((value >> (index * 8)) & 0xffu));
    }
}

void AppendWideString(std::vector<std::byte>& buffer, const std::wstring& value)
{
    AppendLe32(buffer, static_cast<std::uint32_t>(value.size()));
    for (const auto ch : value)
    {
        const auto code_unit = static_cast<std::uint16_t>(ch);
        buffer.push_back(static_cast<std::byte>(code_unit & 0xffu));
        buffer.push_back(static_cast<std::byte>((code_unit >> 8) & 0xffu));
    }
}

std::wstring NormalizePath(const std::wstring& path)
{
    if (path.empty() || path == L"\\")
    {
        return L"\\";
    }

    std::wstring normalized = path;
    std::replace(normalized.begin(), normalized.end(), L'/', L'\\');
    if (normalized.front() != L'\\')
    {
        normalized.insert(normalized.begin(), L'\\');
    }
    while (normalized.size() > 1 && normalized.back() == L'\\')
    {
        normalized.pop_back();
    }
    return normalized;
}

std::wstring JoinPath(const std::wstring& parent, const std::wstring& name)
{
    const auto normalized_parent = NormalizePath(parent);
    if (normalized_parent == L"\\")
    {
        return L"\\" + name;
    }
    return normalized_parent + L"\\" + name;
}

std::wstring Utf8ToWide(const std::vector<std::byte>& bytes, std::size_t offset, std::size_t length)
{
    while (length > 0 && std::to_integer<unsigned char>(bytes[offset + length - 1]) == 0)
    {
        --length;
    }
    std::wstring result;
    result.reserve(length);
    for (std::size_t index = 0; index < length; ++index)
    {
        const auto ch = std::to_integer<unsigned char>(bytes[offset + index]);
        result.push_back(static_cast<wchar_t>(ch < 0x80 ? ch : L'?'));
    }
    return result;
}

bool IsSupportedFileTypeFromMode(std::uint16_t mode)
{
    const auto type = static_cast<std::uint16_t>(mode & kModeTypeMask);
    return type == kModeDirectory || type == kModeRegular || type == kModeSymlink;
}

bool IsDirectoryMode(std::uint16_t mode)
{
    return static_cast<std::uint16_t>(mode & kModeTypeMask) == kModeDirectory;
}

bool IsDirectoryDrec(std::uint16_t flags)
{
    return static_cast<std::uint16_t>(flags & kDrecTypeMask) == kDrecTypeDirectory;
}

bool IsSupportedDrec(std::uint16_t flags)
{
    const auto type = static_cast<std::uint16_t>(flags & kDrecTypeMask);
    return type == kDrecTypeDirectory || type == kDrecTypeRegular || type == kDrecTypeSymlink;
}

std::uint64_t AlignUp(std::uint64_t value, std::uint64_t alignment)
{
    if (alignment == 0)
    {
        return value;
    }
    const auto remainder = value % alignment;
    if (remainder == 0)
    {
        return value;
    }
    if (value > (std::numeric_limits<std::uint64_t>::max() - (alignment - remainder)))
    {
        return 0;
    }
    return value + (alignment - remainder);
}

bool NormalizeFileExtents(
    std::vector<MetadataStore::FileExtent> extents,
    std::vector<MetadataStore::FileExtent>& normalized)
{
    normalized.clear();
    if (extents.empty())
    {
        return true;
    }

    std::sort(extents.begin(), extents.end(), [](const auto& lhs, const auto& rhs)
    {
        if (lhs.logical_offset != rhs.logical_offset)
        {
            return lhs.logical_offset < rhs.logical_offset;
        }
        if (lhs.physical_address != rhs.physical_address)
        {
            return lhs.physical_address < rhs.physical_address;
        }
        return lhs.bytes < rhs.bytes;
    });

    std::uint64_t previous_end = 0;
    bool has_previous = false;
    for (const auto& extent : extents)
    {
        if (extent.bytes == 0 ||
            extent.logical_offset > (std::numeric_limits<std::uint64_t>::max() - extent.bytes) ||
            extent.physical_address > (std::numeric_limits<std::uint64_t>::max() - extent.bytes))
        {
            return false;
        }
        if (!normalized.empty())
        {
            const auto& previous = normalized.back();
            if (extent.logical_offset == previous.logical_offset &&
                extent.physical_address == previous.physical_address &&
                extent.bytes == previous.bytes)
            {
                continue;
            }
        }
        if (has_previous && extent.logical_offset < previous_end)
        {
            return false;
        }

        previous_end = extent.logical_offset + extent.bytes;
        has_previous = true;
        normalized.push_back(extent);
    }

    return true;
}

std::optional<MetadataStore::FileExtent> TryResolveSingleExtentProjection(
    const std::vector<MetadataStore::FileExtent>& extents,
    std::uint64_t logical_size)
{
    if (logical_size == 0 || extents.size() != 1)
    {
        return std::nullopt;
    }

    const auto& extent = extents.front();
    if (extent.logical_offset != 0 ||
        extent.physical_address == 0 ||
        extent.bytes < logical_size)
    {
        return std::nullopt;
    }

    return MetadataStore::FileExtent
    {
        0,
        extent.physical_address,
        logical_size
    };
}

bool IsReadTraceEnabled()
{
    static const bool enabled = []()
    {
        wchar_t value[8]{};
        const auto chars = GetEnvironmentVariableW(L"APFSACCESS_TRACE_READS", value, static_cast<DWORD>(std::size(value)));
        return chars > 0 && value[0] != L'\0' && value[0] != L'0';
    }();
    return enabled;
}

struct InodeDataStreamInfo
{
    std::uint64_t logical_size = 0;
    std::uint64_t allocated_size = std::numeric_limits<std::uint64_t>::max();
};

std::optional<InodeDataStreamInfo> ReadInodeDataStreamInfo(const std::vector<std::byte>& inode_value)
{
    if (inode_value.size() < kInodeExtendedFieldsOffset + 4)
    {
        return std::nullopt;
    }

    const auto field_count = static_cast<std::size_t>(ReadLe16(inode_value, kInodeExtendedFieldsOffset));
    const auto used_data = static_cast<std::size_t>(ReadLe16(inode_value, kInodeExtendedFieldsOffset + 2));
    if (field_count == 0 || used_data == 0)
    {
        return std::nullopt;
    }

    const auto metadata_bytes = field_count * 4;
    if (field_count > 1024 ||
        metadata_bytes > inode_value.size() - (kInodeExtendedFieldsOffset + 4) ||
        used_data > inode_value.size() - (kInodeExtendedFieldsOffset + 4 + metadata_bytes))
    {
        return std::nullopt;
    }

    const auto field_table_start = kInodeExtendedFieldsOffset + 4;
    auto data_cursor = field_table_start + metadata_bytes;
    const auto data_end = data_cursor + used_data;
    if (data_cursor > data_end || data_end > inode_value.size())
    {
        return std::nullopt;
    }

    for (std::size_t index = 0; index < field_count; ++index)
    {
        const auto field_offset = field_table_start + (index * 4);
        if (field_offset + 4 > inode_value.size())
        {
            return std::nullopt;
        }

        const auto field_type = std::to_integer<unsigned char>(inode_value[field_offset]);
        const auto field_size = static_cast<std::size_t>(ReadLe16(inode_value, field_offset + 2));
        if (field_size > data_end - data_cursor)
        {
            return std::nullopt;
        }

        if (field_type == kInodeExtendedFieldDataStream && field_size >= sizeof(std::uint64_t))
        {
            InodeDataStreamInfo info{};
            info.logical_size = ReadLe64(inode_value, data_cursor);
            if (field_size >= sizeof(std::uint64_t) * 2)
            {
                info.allocated_size = ReadLe64(inode_value, data_cursor + sizeof(std::uint64_t));
            }
            else
            {
                info.allocated_size = AlignUp(info.logical_size, 8);
            }
            return info;
        }

        const auto padded_size = static_cast<std::size_t>(AlignUp(field_size, 8));
        if (padded_size < field_size || padded_size > data_end - data_cursor)
        {
            return std::nullopt;
        }
        data_cursor += padded_size;
    }

    return std::nullopt;
}

std::uint64_t ApfsNanosecondsToFileTime(std::uint64_t apfs_nanoseconds)
{
    if (apfs_nanoseconds == 0)
    {
        return 0;
    }

    const auto filetime_ticks = apfs_nanoseconds / 100;
    if (filetime_ticks > std::numeric_limits<std::uint64_t>::max() - kWindowsFileTimeUnixEpochTicks)
    {
        return 0;
    }
    return kWindowsFileTimeUnixEpochTicks + filetime_ticks;
}
} // namespace

bool NativeApfsReader::TryLoadVolumeProjection(
    const BlockDevice& device,
    std::uint64_t volume_object_id,
    NativeApfsVolumeProjection& out_projection,
    std::wstring& out_error)
{
    out_projection = {};
    out_error.clear();

    std::vector<std::byte> nxsb;
    if (!device.Read(0, 0xC0, nxsb) || nxsb.size() < 0xC0 || ReadLe32(nxsb, 0x20) != kNxsbMagic)
    {
        out_error = L"NativeApfsNxsbMissing";
        return false;
    }

    const auto block_size = ReadLe32(nxsb, 0x24);
    const auto total_blocks = ReadLe64(nxsb, 0x28);
    const auto checkpoint_xid = ReadLe64(nxsb, 0x10);
    const auto nx_omap_oid = ReadLe64(nxsb, 0xA0);
    const auto selected_volume_oid = volume_object_id != 0 ? volume_object_id : ReadLe64(nxsb, 0xB8);
    if (block_size == 0 || nx_omap_oid == 0 || selected_volume_oid == 0)
    {
        out_error = L"NativeApfsNxsbIncomplete";
        return false;
    }
    if (selected_volume_oid == nx_omap_oid)
    {
        out_error = L"CanonicalObjectMapCheckpointMissing";
        return false;
    }

    const auto volume_map = ResolveObjectMapValue(device, block_size, nx_omap_oid, selected_volume_oid, checkpoint_xid);
    if (!volume_map.has_value() || volume_map->physical_block == 0)
    {
        out_error = L"NativeApfsVolumeObjectMapMissing";
        return false;
    }

    std::vector<std::byte> volume_superblock;
    if (!ReadBlock(device, block_size, volume_map->physical_block, volume_superblock))
    {
        out_error = L"NativeApfsVolumeSuperblockReadFailed";
        return false;
    }

    VolumeSuperblock volume{};
    if (!ParseVolumeSuperblock(volume_superblock, volume))
    {
        out_error = L"NativeApfsVolumeSuperblockInvalid";
        return false;
    }

    auto selected_volume_superblock_block = volume_map->physical_block;
    auto root_map = ResolveObjectMapValue(device, block_size, volume.object_map_oid, volume.root_tree_oid, checkpoint_xid);
    if (!root_map.has_value() || root_map->physical_block == 0)
    {
        std::optional<ObjectMapValue> fallback_root_map;
        VolumeSuperblock fallback_volume{};
        std::uint64_t fallback_volume_block = 0;
        const auto scan_radius = static_cast<std::uint64_t>(512);
        const auto start_block = volume_map->physical_block > scan_radius
            ? volume_map->physical_block - scan_radius
            : 1;
        const auto end_block = total_blocks == 0
            ? volume_map->physical_block + scan_radius
            : std::min(total_blocks - 1, volume_map->physical_block + scan_radius);
        for (std::uint64_t candidate_block = start_block; candidate_block <= end_block; ++candidate_block)
        {
            std::vector<std::byte> candidate_superblock;
            if (!ReadBlock(device, block_size, candidate_block, candidate_superblock))
            {
                continue;
            }

            VolumeSuperblock candidate_volume{};
            if (!ParseVolumeSuperblock(candidate_superblock, candidate_volume) ||
                candidate_volume.object_id != selected_volume_oid ||
                candidate_volume.xid > checkpoint_xid)
            {
                continue;
            }

            auto candidate_root_map = ResolveObjectMapValue(
                device,
                block_size,
                candidate_volume.object_map_oid,
                candidate_volume.root_tree_oid,
                checkpoint_xid);
            if (!candidate_root_map.has_value() || candidate_root_map->physical_block == 0)
            {
                continue;
            }

            if (!fallback_root_map.has_value() ||
                candidate_volume.xid > fallback_volume.xid)
            {
                fallback_root_map = candidate_root_map;
                fallback_volume = candidate_volume;
                fallback_volume_block = candidate_block;
            }
        }

        if (!fallback_root_map.has_value())
        {
            out_error = L"NativeApfsRootTreeMapMissing";
            return false;
        }

        volume = fallback_volume;
        root_map = fallback_root_map;
        selected_volume_superblock_block = fallback_volume_block;
        if (IsReadTraceEnabled())
        {
            std::wcerr << L"[NativeApfsReader] using older readable APFS volume checkpoint"
                       << L" volumeBlock=" << selected_volume_superblock_block
                       << L" volumeXid=" << volume.xid
                       << L" rootTreeBlock=" << root_map->physical_block
                       << std::endl;
        }
    }

    out_projection.checkpoint_xid = checkpoint_xid;
    out_projection.volume_object_id = selected_volume_oid;
    out_projection.volume_superblock_block = selected_volume_superblock_block;
    out_projection.volume_object_map_oid = volume.object_map_oid;
    out_projection.root_tree_oid = volume.root_tree_oid;
    out_projection.root_tree_block = root_map->physical_block;
    out_projection.file_extent_tree_oid = volume.file_extent_tree_oid;
    out_projection.root_directory_inode = kRootDirectoryInode;
    out_projection.total_blocks = total_blocks;
    out_projection.block_size = block_size;

    std::vector<RawBtreeRecord> fs_records;
    if (!ReadBtreeRecords(
            device,
            block_size,
            root_map->physical_block,
            /*child_addresses_are_physical=*/false,
            volume.object_map_oid,
            checkpoint_xid,
            fs_records))
    {
        out_error = L"NativeApfsRootTreeReadFailed";
        return false;
    }

    if (volume.file_extent_tree_oid != 0)
    {
        const auto file_extent_map = ResolveObjectMapValue(
            device,
            block_size,
            volume.object_map_oid,
            volume.file_extent_tree_oid,
            checkpoint_xid);
        if (file_extent_map.has_value() && file_extent_map->physical_block != 0)
        {
            std::vector<RawBtreeRecord> file_extent_records;
            if (ReadBtreeRecords(
                    device,
                    block_size,
                    file_extent_map->physical_block,
                    /*child_addresses_are_physical=*/false,
                    volume.object_map_oid,
                    checkpoint_xid,
                    file_extent_records))
            {
                out_projection.file_extent_tree_block = file_extent_map->physical_block;
                fs_records.insert(
                    fs_records.end(),
                    std::make_move_iterator(file_extent_records.begin()),
                    std::make_move_iterator(file_extent_records.end()));
            }
            else if (IsReadTraceEnabled())
            {
                std::wcerr << L"[NativeApfsReader] file extent tree read failed"
                           << L" oid=" << volume.file_extent_tree_oid
                           << L" block=" << file_extent_map->physical_block
                           << std::endl;
            }
        }
        else if (IsReadTraceEnabled())
        {
            std::wcerr << L"[NativeApfsReader] file extent tree map missing"
                       << L" oid=" << volume.file_extent_tree_oid
                       << std::endl;
        }
    }

    if (!ProjectFileSystemTree(fs_records, block_size, total_blocks, checkpoint_xid, out_projection))
    {
        out_error = L"NativeApfsRootTreeProjectionFailed";
        return false;
    }

    return true;
}

bool NativeApfsReader::ReadBlock(
    const BlockDevice& device,
    std::uint32_t block_size,
    std::uint64_t block_index,
    std::vector<std::byte>& out_block)
{
    out_block.clear();
    if (block_size == 0 || block_index == 0)
    {
        return false;
    }
    if (block_index > (std::numeric_limits<std::uint64_t>::max() / static_cast<std::uint64_t>(block_size)))
    {
        return false;
    }
    return device.Read(block_index * static_cast<std::uint64_t>(block_size), block_size, out_block) &&
           out_block.size() >= block_size;
}

std::optional<NativeApfsReader::ObjectMapValue> NativeApfsReader::ResolveObjectMapValue(
    const BlockDevice& device,
    std::uint32_t block_size,
    std::uint64_t map_oid,
    std::uint64_t object_id,
    std::uint64_t xid)
{
    std::vector<RawBtreeRecord> records;
    if (!ReadObjectMapRecords(device, block_size, map_oid, records))
    {
        return std::nullopt;
    }

    std::optional<ObjectMapValue> selected;
    for (const auto& record : records)
    {
        if (record.key.size() < 16 || record.value.size() < 16)
        {
            continue;
        }
        const auto candidate_oid = ReadLe64(record.key, 0);
        const auto candidate_xid = ReadLe64(record.key, 8);
        if (candidate_oid != object_id || candidate_xid > xid)
        {
            continue;
        }

        ObjectMapValue value{};
        value.flags = ReadLe32(record.value, 0);
        value.size = ReadLe32(record.value, 4);
        value.physical_block = ReadLe64(record.value, 8);
        value.xid = candidate_xid;
        if ((value.flags & 0x1u) != 0 || value.physical_block == 0)
        {
            continue;
        }
        if (!selected.has_value() || value.xid > selected->xid)
        {
            selected = value;
        }
    }

    return selected;
}

bool NativeApfsReader::ReadObjectMapRecords(
    const BlockDevice& device,
    std::uint32_t block_size,
    std::uint64_t map_oid,
    std::vector<RawBtreeRecord>& out_records)
{
    out_records.clear();
    std::vector<std::byte> omap;
    if (!ReadBlock(device, block_size, map_oid, omap))
    {
        return false;
    }
    if ((ReadLe32(omap, 0x18) & kObjectTypeMask) != kObjectTypeOmap)
    {
        return false;
    }

    const auto tree_oid = ReadLe64(omap, 0x30);
    if (tree_oid == 0)
    {
        return false;
    }
    return ReadBtreeRecords(
        device,
        block_size,
        tree_oid,
        /*child_addresses_are_physical=*/true,
        std::nullopt,
        ReadLe64(omap, 0x10),
        out_records);
}

bool NativeApfsReader::ReadBtreeRecords(
    const BlockDevice& device,
    std::uint32_t block_size,
    std::uint64_t root_block,
    bool child_addresses_are_physical,
    std::optional<std::uint64_t> child_object_map_oid,
    std::uint64_t xid,
    std::vector<RawBtreeRecord>& out_records)
{
    out_records.clear();
    if (root_block == 0)
    {
        return false;
    }

    std::queue<std::uint64_t> pending;
    pending.push(root_block);
    std::unordered_set<std::uint64_t> visited;
    visited.reserve(4096);

    while (!pending.empty())
    {
        const auto block_index = pending.front();
        pending.pop();
        if (!visited.insert(block_index).second)
        {
            continue;
        }
        if (visited.size() > 4096)
        {
            return false;
        }

        std::vector<std::byte> block;
        if (!ReadBlock(device, block_size, block_index, block))
        {
            return false;
        }
        const auto object_type = ReadLe32(block, 0x18) & kObjectTypeMask;
        if (object_type != kObjectTypeBtree && object_type != kObjectTypeBtreeNode)
        {
            return false;
        }

        const auto flags = ReadLe16(block, 0x20);
        const auto level = ReadLe16(block, 0x22);
        const auto key_count = ReadLe32(block, 0x24);
        const auto table_offset = ReadLe16(block, 0x28);
        const auto table_length = ReadLe16(block, 0x2A);
        const auto free_offset = ReadLe16(block, 0x2C);
        const auto free_length = ReadLe16(block, 0x2E);
        const auto fixed_kv = (flags & kBtnodeFixedKvSize) != 0;
        const auto is_root = (flags & kBtnodeRoot) != 0;
        const auto info_start = is_root ? (block.size() - kBtreeInfoBytes) : block.size();
        const auto key_size = is_root ? ReadLe32(block, info_start + 8) : 0;
        const auto value_size = is_root ? ReadLe32(block, info_start + 12) : 0;
        const auto entry_size = fixed_kv ? 4u : 8u;
        const auto table_start = kBtreeDataOffset + static_cast<std::size_t>(table_offset);
        const auto key_area_start = kBtreeDataOffset + static_cast<std::size_t>(table_offset) + static_cast<std::size_t>(table_length);
        const auto free_start = key_area_start + static_cast<std::size_t>(free_offset);
        const auto value_area_start = free_start + static_cast<std::size_t>(free_length);
        const auto value_area_end = info_start;

        if (key_count > 100000 ||
            table_start > block.size() ||
            key_area_start > block.size() ||
            value_area_start > block.size() ||
            value_area_end > block.size() ||
            value_area_start > value_area_end ||
            static_cast<std::uint64_t>(key_count) * entry_size > (block.size() - table_start))
        {
            return false;
        }

        for (std::uint32_t index = 0; index < key_count; ++index)
        {
            const auto entry_offset = table_start + static_cast<std::size_t>(index) * entry_size;
            std::uint16_t key_offset = 0;
            std::uint16_t key_length = 0;
            std::uint16_t value_offset = 0;
            std::uint16_t value_length = 0;
            if (fixed_kv)
            {
                key_offset = ReadLe16(block, entry_offset);
                value_offset = ReadLe16(block, entry_offset + 2);
                key_length = static_cast<std::uint16_t>(key_size);
                value_length = static_cast<std::uint16_t>(value_size != 0 ? value_size : sizeof(std::uint64_t));
            }
            else
            {
                key_offset = ReadLe16(block, entry_offset);
                key_length = ReadLe16(block, entry_offset + 2);
                value_offset = ReadLe16(block, entry_offset + 4);
                value_length = ReadLe16(block, entry_offset + 6);
            }

            if (key_offset == 0xffffu || value_offset == 0xffffu)
            {
                continue;
            }
            if (key_area_start + key_offset > block.size() ||
                key_length > block.size() - (key_area_start + key_offset) ||
                value_offset > value_area_end ||
                value_length > value_area_end ||
                value_area_end - value_offset > block.size() ||
                value_length > block.size() - (value_area_end - value_offset))
            {
                return false;
            }

            const auto key_start = key_area_start + key_offset;
            const auto value_start = value_area_end - value_offset;
            RawBtreeRecord record{};
            record.key.assign(
                block.begin() + static_cast<std::vector<std::byte>::difference_type>(key_start),
                block.begin() + static_cast<std::vector<std::byte>::difference_type>(key_start + key_length));
            record.value.assign(
                block.begin() + static_cast<std::vector<std::byte>::difference_type>(value_start),
                block.begin() + static_cast<std::vector<std::byte>::difference_type>(value_start + value_length));

            if (level == 0)
            {
                out_records.push_back(std::move(record));
                continue;
            }

            if (record.value.size() < sizeof(std::uint64_t))
            {
                return false;
            }
            auto child_block = ReadLe64(record.value, 0);
            if (!child_addresses_are_physical)
            {
                if (!child_object_map_oid.has_value())
                {
                    return false;
                }
                const auto child_mapping = ResolveObjectMapValue(device, block_size, child_object_map_oid.value(), child_block, xid);
                if (!child_mapping.has_value())
                {
                    return false;
                }
                child_block = child_mapping->physical_block;
            }
            if (child_block != 0)
            {
                pending.push(child_block);
            }
        }
    }

    return true;
}

bool NativeApfsReader::ParseVolumeSuperblock(
    const std::vector<std::byte>& block,
    VolumeSuperblock& out_superblock)
{
    out_superblock = {};
    if (block.size() < 0xF8 ||
        (ReadLe32(block, 0x18) & kObjectTypeMask) != kObjectTypeFs ||
        ReadLe32(block, 0x20) != kApsbMagic)
    {
        return false;
    }

    out_superblock.object_id = ReadLe64(block, 0x08);
    out_superblock.xid = ReadLe64(block, 0x10);
    out_superblock.object_map_oid = ReadLe64(block, 0x80);
    out_superblock.root_tree_oid = ReadLe64(block, 0x88);
    out_superblock.file_count = ReadLe64(block, 0xB8);
    out_superblock.directory_count = ReadLe64(block, 0xC0);
    if (block.size() >= 0x410)
    {
        out_superblock.file_extent_tree_oid = ReadLe64(block, 0x408);
    }
    return out_superblock.object_id != 0 &&
           out_superblock.object_map_oid != 0 &&
           out_superblock.root_tree_oid != 0;
}

bool NativeApfsReader::ProjectFileSystemTree(
    const std::vector<RawBtreeRecord>& records,
    std::uint32_t block_size,
    std::uint64_t total_blocks,
    std::uint64_t xid,
    NativeApfsVolumeProjection& projection)
{
    if (block_size == 0)
    {
        return false;
    }
    const auto volume_bytes = total_blocks > 0 && total_blocks <= (std::numeric_limits<std::uint64_t>::max() / block_size)
        ? total_blocks * static_cast<std::uint64_t>(block_size)
        : std::numeric_limits<std::uint64_t>::max();

    struct RawInode
    {
        std::uint64_t object_id = 0;
        std::uint64_t parent_id = 0;
        std::uint64_t private_id = 0;
        std::uint64_t logical_size = 0;
        std::uint64_t allocated_size = std::numeric_limits<std::uint64_t>::max();
        std::uint64_t timestamp = 0;
        std::uint16_t mode = 0;
        bool is_directory = false;
        bool has_data_stream_info = false;
    };

    struct RawDirectoryEntry
    {
        std::uint64_t parent_id = 0;
        std::uint64_t child_id = 0;
        std::uint64_t timestamp = 0;
        std::uint16_t flags = 0;
        std::wstring name;
    };

    std::unordered_map<std::uint64_t, RawInode> raw_inodes;
    std::vector<RawDirectoryEntry> directory_entries;
    std::unordered_map<std::uint64_t, std::vector<MetadataStore::FileExtent>> read_extents_by_private_id;

    for (const auto& record : records)
    {
        if (record.key.size() < sizeof(std::uint64_t))
        {
            continue;
        }

        const auto obj_id_and_type = ReadLe64(record.key, 0);
        const auto object_id = obj_id_and_type & kApfsObjectIdMask;
        const auto record_type = (obj_id_and_type >> kApfsObjectTypeShift) & 0x0f;
        if (object_id == 0)
        {
            continue;
        }

        if (record_type == kApfsTypeInode)
        {
            if (record.value.size() < 0x5C)
            {
                continue;
            }
            RawInode inode{};
            inode.object_id = object_id;
            inode.parent_id = ReadLe64(record.value, 0x00);
            inode.private_id = ReadLe64(record.value, 0x08);
            inode.timestamp = ApfsNanosecondsToFileTime(ReadLe64(record.value, 0x18));
            inode.logical_size = ReadLe64(record.value, kInodeUncompressedSizeOffset);
            inode.mode = ReadLe16(record.value, 0x50);
            if (!IsSupportedFileTypeFromMode(inode.mode))
            {
                continue;
            }
            inode.is_directory = IsDirectoryMode(inode.mode);
            if (!inode.is_directory)
            {
                if (auto data_stream = ReadInodeDataStreamInfo(record.value); data_stream.has_value())
                {
                    inode.logical_size = data_stream->logical_size;
                    inode.allocated_size = data_stream->allocated_size;
                    inode.has_data_stream_info = true;
                }
                if (inode.logical_size > volume_bytes)
                {
                    inode.logical_size = 0;
                    inode.allocated_size = 0;
                }
            }
            raw_inodes[inode.object_id] = inode;
        }
        else if (record_type == kApfsTypeDirectoryRecord)
        {
            if (record.key.size() < 12 || record.value.size() < 18)
            {
                continue;
            }
            const auto name_len_and_hash = ReadLe32(record.key, 8);
            const auto name_length = static_cast<std::size_t>(name_len_and_hash & 0x3ffu);
            if (name_length == 0 || record.key.size() < 12 + name_length)
            {
                continue;
            }
            RawDirectoryEntry entry{};
            entry.parent_id = object_id;
            entry.name = Utf8ToWide(record.key, 12, name_length);
            entry.child_id = ReadLe64(record.value, 0x00);
            entry.timestamp = ReadLe64(record.value, 0x08);
            entry.flags = ReadLe16(record.value, 0x10);
            if (entry.name.empty() ||
                entry.name == L"." ||
                entry.name == L".." ||
                entry.child_id == 0 ||
                !IsSupportedDrec(entry.flags))
            {
                continue;
            }
            directory_entries.push_back(std::move(entry));
        }
        else if (record_type == kApfsTypeFileExtent)
        {
            if (record.key.size() < 16 || record.value.size() < 24)
            {
                continue;
            }
            const auto logical_offset = ReadLe64(record.key, 8);
            const auto length = ReadLe64(record.value, 0) & 0x00ffffffffffffffull;
            const auto physical_block = ReadLe64(record.value, 8);
            if (length == 0)
            {
                continue;
            }
            if (logical_offset > (std::numeric_limits<std::uint64_t>::max() - length) ||
                physical_block > (std::numeric_limits<std::uint64_t>::max() / block_size))
            {
                continue;
            }
            const auto physical_address = physical_block * block_size;
            if (physical_address > (std::numeric_limits<std::uint64_t>::max() - length) ||
                physical_address + length > volume_bytes)
            {
                continue;
            }
            read_extents_by_private_id[object_id].push_back(
                MetadataStore::FileExtent
                {
                    logical_offset,
                    physical_address,
                    length
                });
        }
    }

    if (!raw_inodes.contains(kRootDirectoryInode))
    {
        return false;
    }

    std::unordered_map<std::uint64_t, std::vector<RawDirectoryEntry>> children_by_parent;
    for (const auto& entry : directory_entries)
    {
        if (!raw_inodes.contains(entry.child_id))
        {
            continue;
        }
        children_by_parent[entry.parent_id].push_back(entry);
    }

    projection.inodes.clear();
    projection.btree_records.clear();
    projection.inodes.reserve(raw_inodes.size());
    projection.btree_records.reserve(records.size());
    std::queue<std::pair<std::uint64_t, std::wstring>> pending;
    std::unordered_set<std::uint64_t> visited_inodes;
    pending.push({ kRootDirectoryInode, L"\\" });

    while (!pending.empty())
    {
        auto [object_id, path] = std::move(pending.front());
        pending.pop();
        if (!visited_inodes.insert(object_id).second)
        {
            continue;
        }
        auto inode_it = raw_inodes.find(object_id);
        if (inode_it == raw_inodes.end())
        {
            continue;
        }
        const auto& raw_inode = inode_it->second;

        MetadataStore::InodeRecord inode{};
        inode.object_id = raw_inode.object_id;
        inode.parent_object_id = object_id == kRootDirectoryInode ? kRootDirectoryInode : raw_inode.parent_id;
        inode.full_path = NormalizePath(path);
        inode.name = inode.full_path == L"\\" ? L"" : inode.full_path.substr(inode.full_path.find_last_of(L'\\') + 1);
        inode.is_directory = raw_inode.is_directory;
        inode.logical_size = raw_inode.is_directory ? 0 : raw_inode.logical_size;
        inode.xid = xid;
        inode.timestamp_utc = raw_inode.timestamp;

        if (!inode.is_directory && inode.logical_size > 0)
        {
            if (auto read_extents_it = read_extents_by_private_id.find(raw_inode.private_id);
                read_extents_it != read_extents_by_private_id.end())
            {
                std::vector<MetadataStore::FileExtent> normalized_extents;
                if (NormalizeFileExtents(read_extents_it->second, normalized_extents))
                {
                    projection.read_extents_by_inode[inode.object_id] = normalized_extents;
                    if (auto single_extent = TryResolveSingleExtentProjection(normalized_extents, inode.logical_size);
                        single_extent.has_value())
                    {
                        inode.data_physical_address = single_extent->physical_address;
                        projection.btree_records.push_back(
                            BtreeMutationCodec::EncodeExtentRecord(
                                inode.object_id,
                                0,
                                single_extent->physical_address,
                                single_extent->bytes,
                                xid,
                                false));
                    }
                }
                else if (IsReadTraceEnabled())
                {
                    std::wcerr << L"[NativeApfsReader] invalid data extent set"
                               << L" object=" << inode.object_id
                               << L" privateId=" << raw_inode.private_id
                               << L" path=" << inode.full_path
                               << std::endl;
                }
            }
            else if (raw_inode.has_data_stream_info && raw_inode.allocated_size == 0)
            {
                projection.read_extents_by_inode[inode.object_id] = {};
                inode.data_physical_address = 0;
            }
            else if (IsReadTraceEnabled())
            {
                std::wcerr << L"[NativeApfsReader] no data extent"
                           << L" object=" << inode.object_id
                           << L" privateId=" << raw_inode.private_id
                           << L" path=" << inode.full_path
                           << L" logicalSize=" << raw_inode.logical_size
                           << L" allocatedSize=" << raw_inode.allocated_size
                           << L" hasDstream=" << (raw_inode.has_data_stream_info ? L"true" : L"false")
                           << std::endl;
            }
        }

        if (inode.object_id != kRootDirectoryInode)
        {
            projection.btree_records.push_back(
                BtreeMutationCodec::EncodeInodeRecord(
                    inode.object_id,
                    inode.parent_object_id,
                    inode.name,
                    inode.is_directory,
                    inode.logical_size,
                    inode.data_physical_address,
                    inode.timestamp_utc,
                    xid,
                    false));
        }
        projection.inodes.push_back(inode);

        if (!inode.is_directory)
        {
            continue;
        }

        if (auto child_it = children_by_parent.find(object_id); child_it != children_by_parent.end())
        {
            for (const auto& child : child_it->second)
            {
                if (child.child_id == object_id || !raw_inodes.contains(child.child_id))
                {
                    continue;
                }
                const auto child_path = JoinPath(inode.full_path, child.name);
                projection.btree_records.push_back(
                    BtreeMutationCodec::EncodeDirectoryRecord(
                        object_id,
                        child.name,
                        child.child_id,
                        xid,
                        false));
                pending.push({ child.child_id, child_path });
            }
        }
    }

    return !projection.inodes.empty();
}
} // namespace apfsaccess::rw
