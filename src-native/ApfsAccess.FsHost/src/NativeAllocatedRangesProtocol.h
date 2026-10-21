#pragma once
#include "NativeAllocatedRanges.h"

namespace apfsaccess::fshost::allocated_ranges_control
{
// Custom, read-only METHOD_BUFFERED API. Not FSCTL_QUERY_ALLOCATED_RANGES.
inline constexpr std::uint32_t Version = 2;
inline constexpr std::uint32_t Query = (0x8000u << 16) | (1u << 14) | (0x812u << 2);
struct Request
{
    std::uint32_t version = Version, reserved = 0;
    std::uint64_t offset = 0, length = 0;
    rw::NativeAllocatedRangeStamp expected;
};
struct Reply
{
    std::uint32_t version = Version, reserved = 0;
    rw::NativeAllocatedRangeStamp observed;
    std::uint64_t next_offset = 0;
    std::uint32_t range_count = 0, more_ranges = 0;
    std::array<rw::NativeAllocatedRange, 64> ranges{};
};
static_assert(sizeof(Request) == 64 && sizeof(Reply) == 1088);
}
