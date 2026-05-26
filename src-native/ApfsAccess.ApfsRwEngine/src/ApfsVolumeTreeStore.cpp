#include "ApfsVolumeTreeStore.h"

#include <algorithm>
#include <cstdint>
#include <limits>
#include <string>
#include <unordered_map>
#include <unordered_set>

namespace apfsaccess::rw
{
namespace
{
struct DecodedBtreeInode
{
    std::uint64_t object_id = 0;
    std::uint64_t parent_object_id = 0;
    std::uint64_t xid = 0;
    bool is_directory = false;
    std::uint64_t logical_size = 0;
    std::uint64_t data_physical_address = 0;
    std::uint64_t timestamp_utc = 0;
    std::wstring name;
};

struct DecodedBtreeDirectoryEntry
{
    std::uint64_t parent_object_id = 0;
    std::wstring entry_name;
    std::uint64_t child_object_id = 0;
    std::uint64_t xid = 0;
};

struct DecodedBtreeExtent
{
    std::uint64_t object_id = 0;
    std::uint64_t logical_offset = 0;
    std::uint64_t physical_address = 0;
    std::uint64_t extent_bytes = 0;
    std::uint64_t xid = 0;
};

bool TryReadLe32(const std::vector<std::byte>& buffer, std::size_t offset, std::uint32_t& value)
{
    if (offset > (std::numeric_limits<std::size_t>::max() - sizeof(std::uint32_t)) ||
        (offset + sizeof(std::uint32_t)) > buffer.size())
    {
        return false;
    }

    value = static_cast<std::uint32_t>(std::to_integer<unsigned char>(buffer[offset + 0])) |
            (static_cast<std::uint32_t>(std::to_integer<unsigned char>(buffer[offset + 1])) << 8) |
            (static_cast<std::uint32_t>(std::to_integer<unsigned char>(buffer[offset + 2])) << 16) |
            (static_cast<std::uint32_t>(std::to_integer<unsigned char>(buffer[offset + 3])) << 24);
    return true;
}

bool TryReadLe64(const std::vector<std::byte>& buffer, std::size_t offset, std::uint64_t& value)
{
    if (offset > (std::numeric_limits<std::size_t>::max() - sizeof(std::uint64_t)) ||
        (offset + sizeof(std::uint64_t)) > buffer.size())
    {
        return false;
    }

    value = 0;
    for (std::size_t i = 0; i < sizeof(std::uint64_t); ++i)
    {
        value |= static_cast<std::uint64_t>(std::to_integer<unsigned char>(buffer[offset + i])) << (i * 8);
    }
    return true;
}

bool TryReadWideStringWithLength(const std::vector<std::byte>& buffer, std::size_t& cursor, std::wstring& value)
{
    value.clear();

    std::uint32_t length = 0;
    if (!TryReadLe32(buffer, cursor, length))
    {
        return false;
    }
    cursor += sizeof(std::uint32_t);

    if (length == 0)
    {
        return true;
    }
    if (length > (std::numeric_limits<std::uint32_t>::max() / sizeof(std::uint16_t)))
    {
        return false;
    }

    const auto required_bytes = static_cast<std::uint64_t>(length) * sizeof(std::uint16_t);
    if (required_bytes > (std::numeric_limits<std::size_t>::max() - cursor))
    {
        return false;
    }
    if (static_cast<std::size_t>(required_bytes) > (buffer.size() - cursor))
    {
        return false;
    }

    value.reserve(length);
    for (std::uint32_t index = 0; index < length; ++index)
    {
        const auto lo = static_cast<std::uint16_t>(std::to_integer<unsigned char>(buffer[cursor + 0]));
        const auto hi = static_cast<std::uint16_t>(std::to_integer<unsigned char>(buffer[cursor + 1]));
        const auto code_unit = static_cast<std::uint16_t>(lo | (hi << 8));
        value.push_back(static_cast<wchar_t>(code_unit));
        cursor += 2;
    }

    return true;
}

bool IsValidKindPrefix(const BtreeRecord& record)
{
    if (record.key.empty())
    {
        return false;
    }

    const auto prefix = std::to_integer<unsigned char>(record.key.front());
    return prefix == static_cast<unsigned char>(record.kind);
}

std::string BuildBtreeKeyBlob(const std::vector<std::byte>& key)
{
    return std::string(
        reinterpret_cast<const char*>(key.data()),
        reinterpret_cast<const char*>(key.data()) + static_cast<std::ptrdiff_t>(key.size()));
}

std::wstring BuildDirectoryEntryIndexKey(std::uint64_t parent_object_id, const std::wstring& entry_name)
{
    std::wstring key = std::to_wstring(parent_object_id);
    key.push_back(L'\x1f');
    key += entry_name;
    return key;
}

bool DecodeBtreeInodeRecord(const BtreeRecord& record, DecodedBtreeInode& decoded)
{
    constexpr std::size_t kExpectedKeyBytes = 1 + 8 + 8;
    constexpr std::uint32_t kDirectoryFlag = 0x1u;
    constexpr std::uint32_t kTombstoneFlag = 0x2u;
    constexpr std::uint32_t kTimestampPresentFlag = 0x4u;
    if (record.key.size() != kExpectedKeyBytes)
    {
        return false;
    }
    if (!TryReadLe64(record.key, 1, decoded.parent_object_id) ||
        !TryReadLe64(record.key, 9, decoded.object_id))
    {
        return false;
    }

    std::size_t cursor = 0;
    std::uint32_t flags = 0;
    if (!TryReadLe64(record.value, cursor, decoded.xid))
    {
        return false;
    }
    cursor += 8;
    if (!TryReadLe32(record.value, cursor, flags))
    {
        return false;
    }
    cursor += 4;
    if (!TryReadLe64(record.value, cursor, decoded.logical_size))
    {
        return false;
    }
    cursor += 8;
    if (!TryReadLe64(record.value, cursor, decoded.data_physical_address))
    {
        return false;
    }
    cursor += 8;
    if ((flags & kTimestampPresentFlag) != 0)
    {
        if (!TryReadLe64(record.value, cursor, decoded.timestamp_utc))
        {
            return false;
        }
        cursor += 8;
    }
    if (!TryReadWideStringWithLength(record.value, cursor, decoded.name))
    {
        return false;
    }
    if (cursor != record.value.size())
    {
        return false;
    }

    decoded.is_directory = (flags & kDirectoryFlag) != 0;
    if ((flags & kTombstoneFlag) != 0 ||
        (flags & ~(kDirectoryFlag | kTimestampPresentFlag)) != 0)
    {
        return false;
    }
    if (decoded.object_id == 0 || decoded.parent_object_id == 0 || decoded.name.empty() || decoded.xid == 0)
    {
        return false;
    }
    if (decoded.is_directory)
    {
        if (decoded.logical_size != 0 || decoded.data_physical_address != 0)
        {
            return false;
        }
    }

    return true;
}

bool DecodeBtreeDirectoryRecord(const BtreeRecord& record, DecodedBtreeDirectoryEntry& decoded)
{
    if (record.key.size() < 1 + 8 + 4)
    {
        return false;
    }
    if (!TryReadLe64(record.key, 1, decoded.parent_object_id))
    {
        return false;
    }

    std::size_t key_cursor = 1 + 8;
    if (!TryReadWideStringWithLength(record.key, key_cursor, decoded.entry_name))
    {
        return false;
    }
    if (key_cursor != record.key.size() || decoded.entry_name.empty())
    {
        return false;
    }

    if (record.value.size() != (8 + 8 + 1))
    {
        return false;
    }
    if (!TryReadLe64(record.value, 0, decoded.xid) ||
        !TryReadLe64(record.value, 8, decoded.child_object_id))
    {
        return false;
    }

    const auto tombstone_flag = std::to_integer<unsigned char>(record.value[16]);
    if (decoded.parent_object_id == 0 ||
        decoded.child_object_id == 0 ||
        decoded.xid == 0 ||
        tombstone_flag != 0)
    {
        return false;
    }

    return true;
}

bool DecodeBtreeExtentRecord(const BtreeRecord& record, DecodedBtreeExtent& decoded)
{
    constexpr std::size_t kExpectedKeyBytes = 1 + 8 + 8;
    if (record.key.size() != kExpectedKeyBytes)
    {
        return false;
    }
    if (!TryReadLe64(record.key, 1, decoded.object_id) ||
        !TryReadLe64(record.key, 9, decoded.logical_offset))
    {
        return false;
    }
    if (decoded.object_id == 0)
    {
        return false;
    }

    if (record.value.size() != (8 + 8 + 8 + 1))
    {
        return false;
    }
    if (!TryReadLe64(record.value, 0, decoded.xid) ||
        !TryReadLe64(record.value, 8, decoded.physical_address) ||
        !TryReadLe64(record.value, 16, decoded.extent_bytes))
    {
        return false;
    }

    const auto tombstone_flag = std::to_integer<unsigned char>(record.value[24]);
    if (decoded.xid == 0 ||
        decoded.extent_bytes == 0 ||
        tombstone_flag != 0)
    {
        return false;
    }

    return true;
}

bool HasLogicalExtentCoverage(
    std::vector<DecodedBtreeExtent> extents,
    std::uint64_t logical_size,
    std::uint64_t anchor_physical_address)
{
    if (logical_size == 0)
    {
        return extents.empty();
    }
    if (extents.empty())
    {
        return false;
    }

    std::sort(extents.begin(), extents.end(), [](const DecodedBtreeExtent& lhs, const DecodedBtreeExtent& rhs)
    {
        if (lhs.logical_offset == rhs.logical_offset)
        {
            return lhs.physical_address < rhs.physical_address;
        }
        return lhs.logical_offset < rhs.logical_offset;
    });

    if (extents.front().logical_offset != 0 ||
        extents.front().physical_address != anchor_physical_address)
    {
        return false;
    }

    std::uint64_t covered_until = 0;
    for (const auto& extent : extents)
    {
        if (extent.extent_bytes == 0 ||
            extent.physical_address == 0 ||
            extent.logical_offset != covered_until ||
            extent.logical_offset > (std::numeric_limits<std::uint64_t>::max() - extent.extent_bytes))
        {
            return false;
        }

        covered_until = extent.logical_offset + extent.extent_bytes;
        if (covered_until >= logical_size)
        {
            return true;
        }
    }

    return false;
}
} // namespace

bool ApfsVolumeTreeStore::TryProjectFromBtreeRecords(
    const std::vector<BtreeRecord>& records,
    ApfsVolumeTreeProjection& out_projection,
    std::wstring& out_error) const
{
    out_projection = {};
    out_error.clear();

    std::unordered_set<std::string> dedupe_keys;
    dedupe_keys.reserve(records.size());
    std::unordered_map<std::uint64_t, DecodedBtreeInode> decoded_inodes_by_object;
    std::unordered_map<std::wstring, DecodedBtreeDirectoryEntry> decoded_directory_entries;
    std::unordered_map<std::uint64_t, std::vector<DecodedBtreeExtent>> decoded_extents_by_object;
    decoded_inodes_by_object.reserve(records.size());
    decoded_directory_entries.reserve(records.size());
    decoded_extents_by_object.reserve(records.size());

    for (const auto& record : records)
    {
        if (!IsValidKindPrefix(record))
        {
            out_error = L"BtreeRecordKindPrefixMismatch";
            return false;
        }
        if (record.tombstone)
        {
            out_error = L"BtreeRecordTombstoneUnsupported";
            return false;
        }

        if (record.value.empty())
        {
            out_error = L"BtreeRecordMissingValue";
            return false;
        }

        auto key_blob = BuildBtreeKeyBlob(record.key);
        if (!dedupe_keys.insert(std::move(key_blob)).second)
        {
            out_error = L"BtreeRecordDuplicateKey";
            return false;
        }

        switch (record.kind)
        {
        case BtreeRecordKind::Inode:
        {
            DecodedBtreeInode decoded{};
            if (!DecodeBtreeInodeRecord(record, decoded))
            {
                out_error = L"BtreeInodeDecodeInvalid";
                return false;
            }
            if (!decoded_inodes_by_object.emplace(decoded.object_id, std::move(decoded)).second)
            {
                out_error = L"BtreeInodeDuplicateObjectId";
                return false;
            }
            break;
        }
        case BtreeRecordKind::DirectoryEntry:
        {
            DecodedBtreeDirectoryEntry decoded{};
            if (!DecodeBtreeDirectoryRecord(record, decoded))
            {
                out_error = L"BtreeDirectoryDecodeInvalid";
                return false;
            }
            auto key = BuildDirectoryEntryIndexKey(decoded.parent_object_id, decoded.entry_name);
            if (!decoded_directory_entries.emplace(std::move(key), std::move(decoded)).second)
            {
                out_error = L"BtreeDirectoryDuplicateEntry";
                return false;
            }
            break;
        }
        case BtreeRecordKind::FileExtent:
        {
            DecodedBtreeExtent decoded{};
            if (!DecodeBtreeExtentRecord(record, decoded))
            {
                out_error = L"BtreeExtentDecodeInvalid";
                return false;
            }
            decoded_extents_by_object[decoded.object_id].push_back(std::move(decoded));
            break;
        }
        default:
            out_error = L"BtreeRecordKindUnsupported";
            return false;
        }
    }

    for (const auto& [object_id, inode] : decoded_inodes_by_object)
    {
        if (!inode.is_directory &&
            inode.logical_size > 0 &&
            inode.data_physical_address != 0 &&
            !decoded_extents_by_object.contains(object_id))
        {
            out_error = L"BtreeExtentMissingForFileInode";
            return false;
        }

        if (inode.logical_size == 0 &&
            decoded_extents_by_object.contains(object_id))
        {
            out_error = L"BtreeExtentUnexpectedForZeroLengthInode";
            return false;
        }
    }

    for (const auto& [object_id, extents] : decoded_extents_by_object)
    {
        auto inode_it = decoded_inodes_by_object.find(object_id);
        if (inode_it == decoded_inodes_by_object.end() || inode_it->second.is_directory)
        {
            out_error = L"BtreeExtentMissingInode";
            return false;
        }
        if (!HasLogicalExtentCoverage(
                extents,
                inode_it->second.logical_size,
                inode_it->second.data_physical_address))
        {
            out_error = L"BtreeExtentInodeMismatch";
            return false;
        }
    }

    std::unordered_map<std::uint64_t, std::size_t> inbound_links;
    inbound_links.reserve(decoded_inodes_by_object.size());
    for (const auto& [object_id, _] : decoded_inodes_by_object)
    {
        inbound_links.emplace(object_id, 0);
    }

    for (const auto& [_, entry] : decoded_directory_entries)
    {
        auto child_it = decoded_inodes_by_object.find(entry.child_object_id);
        if (child_it == decoded_inodes_by_object.end())
        {
            out_error = L"BtreeDirectoryMissingChildInode";
            return false;
        }
        if (child_it->second.parent_object_id != entry.parent_object_id ||
            child_it->second.name != entry.entry_name)
        {
            out_error = L"BtreeDirectoryChildMismatch";
            return false;
        }

        if (auto parent_it = decoded_inodes_by_object.find(entry.parent_object_id);
            parent_it != decoded_inodes_by_object.end() && !parent_it->second.is_directory)
        {
            out_error = L"BtreeDirectoryParentNotDirectory";
            return false;
        }

        ++inbound_links[entry.child_object_id];
    }

    for (const auto& [object_id, link_count] : inbound_links)
    {
        if (link_count == 0)
        {
            out_error = L"BtreeInodeUnlinked";
            return false;
        }

        const auto& inode = decoded_inodes_by_object.at(object_id);
        if (inode.parent_object_id == 0)
        {
            out_error = L"BtreeInodeParentInvalid";
            return false;
        }
    }

    std::size_t extent_record_count = 0;
    for (const auto& [_, extents] : decoded_extents_by_object)
    {
        extent_record_count += extents.size();
    }

    out_projection.inode_record_count = decoded_inodes_by_object.size();
    out_projection.directory_entry_record_count = decoded_directory_entries.size();
    out_projection.extent_record_count = extent_record_count;
    return true;
}
} // namespace apfsaccess::rw
