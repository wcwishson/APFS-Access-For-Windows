#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace apfsaccess::rw
{
struct ApfsObjectMapEntry
{
    std::uint64_t object_id = 0;
    std::uint64_t physical_address = 0;
    std::uint64_t logical_size = 0;
    std::uint64_t xid = 0;
};

class ApfsObjectMapStore
{
public:
    [[nodiscard]] bool TryParseCheckpointV3(
        const std::vector<std::byte>& checkpoint_block,
        std::vector<ApfsObjectMapEntry>& out_entries,
        std::uint64_t& out_checkpoint_xid) const;

    [[nodiscard]] bool ValidateEntries(
        const std::vector<ApfsObjectMapEntry>& entries) const;
};
} // namespace apfsaccess::rw

