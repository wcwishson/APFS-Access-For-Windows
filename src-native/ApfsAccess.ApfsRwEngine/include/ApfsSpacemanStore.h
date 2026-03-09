#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace apfsaccess::rw
{
struct ApfsExtent
{
    std::uint64_t physical_address = 0;
    std::uint64_t bytes = 0;
};

class ApfsSpacemanStore
{
public:
    [[nodiscard]] bool TryParseCheckpointV3(
        const std::vector<std::byte>& checkpoint_block,
        std::vector<ApfsExtent>& out_allocations,
        std::vector<ApfsExtent>& out_free_extents,
        std::uint64_t& out_checkpoint_xid) const;

    [[nodiscard]] bool ValidateState(
        const std::vector<ApfsExtent>& allocations,
        const std::vector<ApfsExtent>& free_extents) const;
};
} // namespace apfsaccess::rw

