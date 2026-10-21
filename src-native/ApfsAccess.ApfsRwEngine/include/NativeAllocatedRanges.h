#pragma once
#include <array>
#include <cstdint>
#include <span>

namespace apfsaccess::rw
{
struct NativeAllocatedRangeStamp
{
    std::uint64_t inode = 0, checkpoint = 0, epoch = 0, file_size = 0, allocation_size = 0;
    bool operator==(const NativeAllocatedRangeStamp&) const = default;
};
struct NativeAllocatedRange { std::uint64_t offset = 0, length = 0; };
struct NativeAllocatedRangePage
{
    std::array<NativeAllocatedRange, 64> ranges{};
    std::uint64_t next_offset = 0;
    std::uint32_t count = 0;
    bool more = false;
};
enum class NativeAllocatedRangeStatus { Ok, InvalidRange, InvalidProjection, StateChanged };

// The caller holds the committed read gate and supplies the complete canonical
// projection. This validates/paginates it; it grants no mutation authority.
template<class Extent>
NativeAllocatedRangeStatus CollectNativeAllocatedRangePage(std::span<const Extent> extents,
    const NativeAllocatedRangeStamp& observed, const NativeAllocatedRangeStamp& expected,
    std::uint64_t offset, std::uint64_t length, NativeAllocatedRangePage& output)
{
    output = {};
    if (offset > INT64_MAX || length > static_cast<std::uint64_t>(INT64_MAX) - offset)
        return NativeAllocatedRangeStatus::InvalidRange;
    if (!observed.inode || !observed.checkpoint || observed.file_size > INT64_MAX ||
        observed.allocation_size > INT64_MAX || extents.size() > 1000000)
        return NativeAllocatedRangeStatus::InvalidProjection;
    if (expected != NativeAllocatedRangeStamp{} && expected != observed)
        return NativeAllocatedRangeStatus::StateChanged;
    NativeAllocatedRangePage page;
    const auto requested_end = offset + length;
    const auto end = requested_end < observed.file_size ? requested_end : observed.file_size;
    page.next_offset = end;
    std::uint64_t previous_end = 0, allocated = 0;
    for (const auto& extent : extents)
    {
        if (!extent.bytes || extent.logical_offset < previous_end ||
            extent.bytes > UINT64_MAX - extent.logical_offset ||
            (extent.physical_address && extent.bytes > UINT64_MAX - extent.physical_address))
            return NativeAllocatedRangeStatus::InvalidProjection;
        previous_end = extent.logical_offset + extent.bytes;
        if (extent.physical_address)
        {
            if (extent.bytes > UINT64_MAX - allocated) return NativeAllocatedRangeStatus::InvalidProjection;
            allocated += extent.bytes;
        }
        if (page.more || !extent.physical_address || previous_end <= offset || extent.logical_offset >= end)
            continue;
        const auto begin = extent.logical_offset > offset ? extent.logical_offset : offset;
        const auto finish = previous_end < end ? previous_end : end;
        if (begin >= finish) continue;
        if (page.count && page.ranges[page.count - 1].offset + page.ranges[page.count - 1].length == begin)
            page.ranges[page.count - 1].length += finish - begin;
        else if (page.count == page.ranges.size())
        {
            const auto& last = page.ranges.back();
            page.next_offset = last.offset + last.length;
            page.more = true;
        }
        else page.ranges[page.count++] = {begin, finish - begin};
    }
    if (allocated != observed.allocation_size) return NativeAllocatedRangeStatus::InvalidProjection;
    output = page;
    return NativeAllocatedRangeStatus::Ok;
}
}
