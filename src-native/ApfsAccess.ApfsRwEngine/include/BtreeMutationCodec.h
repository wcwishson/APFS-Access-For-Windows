#pragma once

#include <cstddef>
#include <cstdint>
#include <string_view>
#include <vector>

namespace apfsaccess::rw
{
enum class BtreeRecordKind : std::uint8_t
{
    Inode = 1,
    DirectoryEntry = 2,
    FileExtent = 3,
};

struct BtreeRecord
{
    BtreeRecordKind kind = BtreeRecordKind::Inode;
    bool tombstone = false;
    std::vector<std::byte> key;
    std::vector<std::byte> value;
};

class BtreeMutationCodec
{
public:
    [[nodiscard]] static BtreeRecord EncodeInodeRecord(
        std::uint64_t object_id,
        std::uint64_t parent_object_id,
        std::wstring_view name,
        bool is_directory,
        std::uint64_t logical_size,
        std::uint64_t data_physical_address,
        std::uint64_t timestamp_utc,
        std::uint64_t xid,
        bool tombstone = false
    );

    [[nodiscard]] static BtreeRecord EncodeDirectoryRecord(
        std::uint64_t parent_object_id,
        std::wstring_view entry_name,
        std::uint64_t child_object_id,
        std::uint64_t xid,
        bool tombstone = false
    );

    [[nodiscard]] static BtreeRecord EncodeExtentRecord(
        std::uint64_t object_id,
        std::uint64_t logical_offset,
        std::uint64_t physical_address,
        std::uint64_t extent_bytes,
        std::uint64_t xid,
        bool tombstone = false
    );
};
} // namespace apfsaccess::rw
