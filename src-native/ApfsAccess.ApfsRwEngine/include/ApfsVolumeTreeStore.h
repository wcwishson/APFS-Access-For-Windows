#pragma once

#include "BtreeMutationCodec.h"

#include <cstddef>
#include <string>
#include <unordered_map>
#include <vector>

namespace apfsaccess::rw
{
struct ApfsVolumeTreeProjection
{
    std::size_t inode_record_count = 0;
    std::size_t directory_entry_record_count = 0;
    std::size_t extent_record_count = 0;
};

class ApfsVolumeTreeStore
{
public:
    [[nodiscard]] bool TryProjectFromBtreeRecords(
        const std::vector<BtreeRecord>& records,
        ApfsVolumeTreeProjection& out_projection,
        std::wstring& out_error,
        const std::unordered_map<std::uint64_t, std::uint64_t>& native_allocations = {}) const;
};
} // namespace apfsaccess::rw
