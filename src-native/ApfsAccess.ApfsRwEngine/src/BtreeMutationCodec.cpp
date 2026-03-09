#include "BtreeMutationCodec.h"

#include <array>

namespace
{
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

void AppendWideString(std::vector<std::byte>& buffer, std::wstring_view text)
{
    AppendLe32(buffer, static_cast<std::uint32_t>(text.size()));
    for (const auto ch : text)
    {
        const auto code_unit = static_cast<std::uint16_t>(ch);
        buffer.push_back(static_cast<std::byte>(code_unit & 0xffu));
        buffer.push_back(static_cast<std::byte>((code_unit >> 8) & 0xffu));
    }
}
} // namespace

namespace apfsaccess::rw
{
BtreeRecord BtreeMutationCodec::EncodeInodeRecord(
    std::uint64_t object_id,
    std::uint64_t parent_object_id,
    std::wstring_view name,
    bool is_directory,
    std::uint64_t logical_size,
    std::uint64_t data_physical_address,
    std::uint64_t timestamp_utc,
    std::uint64_t xid,
    bool tombstone
)
{
    BtreeRecord record{};
    record.kind = BtreeRecordKind::Inode;
    record.tombstone = tombstone;

    record.key.reserve(1 + (8 * 2));
    record.key.push_back(static_cast<std::byte>(record.kind));
    AppendLe64(record.key, parent_object_id);
    AppendLe64(record.key, object_id);

    std::uint32_t flags = 0;
    if (is_directory)
    {
        flags |= 0x1u;
    }
    if (tombstone)
    {
        flags |= 0x2u;
    }
    if (timestamp_utc != 0)
    {
        flags |= 0x4u;
    }

    record.value.reserve(64 + (name.size() * 2));
    AppendLe64(record.value, xid);
    AppendLe32(record.value, flags);
    AppendLe64(record.value, logical_size);
    AppendLe64(record.value, data_physical_address);
    if (timestamp_utc != 0)
    {
        AppendLe64(record.value, timestamp_utc);
    }
    AppendWideString(record.value, name);

    return record;
}

BtreeRecord BtreeMutationCodec::EncodeDirectoryRecord(
    std::uint64_t parent_object_id,
    std::wstring_view entry_name,
    std::uint64_t child_object_id,
    std::uint64_t xid,
    bool tombstone
)
{
    BtreeRecord record{};
    record.kind = BtreeRecordKind::DirectoryEntry;
    record.tombstone = tombstone;

    record.key.reserve(1 + 8 + 4 + (entry_name.size() * 2));
    record.key.push_back(static_cast<std::byte>(record.kind));
    AppendLe64(record.key, parent_object_id);
    AppendWideString(record.key, entry_name);

    record.value.reserve(8 + 8 + 1);
    AppendLe64(record.value, xid);
    AppendLe64(record.value, child_object_id);
    record.value.push_back(static_cast<std::byte>(tombstone ? 1 : 0));

    return record;
}

BtreeRecord BtreeMutationCodec::EncodeExtentRecord(
    std::uint64_t object_id,
    std::uint64_t logical_offset,
    std::uint64_t physical_address,
    std::uint64_t extent_bytes,
    std::uint64_t xid,
    bool tombstone
)
{
    BtreeRecord record{};
    record.kind = BtreeRecordKind::FileExtent;
    record.tombstone = tombstone;

    record.key.reserve(1 + 8 + 8);
    record.key.push_back(static_cast<std::byte>(record.kind));
    AppendLe64(record.key, object_id);
    AppendLe64(record.key, logical_offset);

    record.value.reserve(8 + 8 + 8 + 1);
    AppendLe64(record.value, xid);
    AppendLe64(record.value, physical_address);
    AppendLe64(record.value, extent_bytes);
    record.value.push_back(static_cast<std::byte>(tombstone ? 1 : 0));

    return record;
}
} // namespace apfsaccess::rw
