#pragma once

#include <cstdint>
#include <string>

namespace apfsaccess::rw
{
// Expected namespace result captured by native staging, not a publication
// receipt. Recovery must still compare it with committed APFS metadata.
struct UnlinkOutcome
{
    std::uint64_t object_id = 0;
    std::uint64_t generation_before = 0;
    std::uint64_t generation_after = 0;
    std::uint64_t parent_object_id = 0;
    std::uint32_t links_before = 0;
    std::uint32_t links_after = 0;
    std::string path_utf8;

    bool operator==(const UnlinkOutcome&) const = default;
};
} // namespace apfsaccess::rw
