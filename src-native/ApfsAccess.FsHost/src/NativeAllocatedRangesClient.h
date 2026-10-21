#pragma once
#include "NativeAllocatedRangesProtocol.h"
#include <string>
#include <vector>

namespace apfsaccess::fshost::allocated_ranges_control
{
class Collector
{
public:
    Collector(std::uint64_t offset, std::uint64_t length) : offset_(offset), length_(length), cursor_(offset) {}
    Request Next() const { return {Version, 0, cursor_, offset_ + length_ - cursor_, stamp_}; }
    bool Accept(const Reply& reply)
    {
        if (failed_ || complete_) return Refuse("UnexpectedPage");
        if (offset_ > INT64_MAX || length_ > static_cast<std::uint64_t>(INT64_MAX) - offset_)
            return Refuse("InvalidRange");
        if (++pages_ > 1024 || reply.version != Version || reply.reserved || reply.more_ranges > 1 ||
            reply.range_count > reply.ranges.size() || !reply.observed.inode || !reply.observed.checkpoint ||
            reply.observed.file_size > INT64_MAX || reply.observed.allocation_size > INT64_MAX)
            return Refuse("InvalidReply");
        if (stamp_ != rw::NativeAllocatedRangeStamp{} && stamp_ != reply.observed)
            return Refuse("StateChanged");
        const auto limit = (offset_ + length_) < reply.observed.file_size ? offset_ + length_ : reply.observed.file_size;
        std::uint64_t prior = cursor_, page_bytes = 0;
        for (std::size_t i = 0; i < reply.ranges.size(); ++i)
        {
            const auto& range = reply.ranges[i];
            if (i >= reply.range_count)
            {
                if (range.offset || range.length) return Refuse("UnexpectedPadding");
                continue;
            }
            if (!range.length || range.offset < prior || range.offset > limit || range.length > limit - range.offset)
                return Refuse("InvalidRanges");
            if (reported_bytes_ > reply.observed.allocation_size || page_bytes > reply.observed.allocation_size - reported_bytes_ ||
                range.length > reply.observed.allocation_size - reported_bytes_ - page_bytes)
                return Refuse("AllocationExceeded");
            page_bytes += range.length;
            prior = range.offset + range.length;
        }
        if (reply.more_ranges ? (!reply.range_count || reply.next_offset != prior || reply.next_offset <= cursor_ || reply.next_offset >= limit)
                              : reply.next_offset != limit)
            return Refuse("InvalidCursor");
        if (reply.range_count > 65536 - ranges_.size()) return Refuse("RangeLimit");
        stamp_ = reply.observed;
        reported_bytes_ += page_bytes;
        ranges_.insert(ranges_.end(), reply.ranges.begin(), reply.ranges.begin() + reply.range_count);
        cursor_ = reply.next_offset; complete_ = reply.more_ranges == 0;
        return true;
    }
    bool Complete() const { return complete_ && !failed_; }
    const auto& Stamp() const { return stamp_; }
    const auto& Ranges() const { return ranges_; }
    const auto& Error() const { return error_; }
    bool Refuse(std::string reason)
    {
        ranges_.clear(); stamp_ = {}; reported_bytes_ = 0; failed_ = true; complete_ = false; error_ = std::move(reason); return false;
    }
private:
    std::uint64_t offset_, length_, cursor_;
    std::uint64_t reported_bytes_ = 0;
    std::uint32_t pages_ = 0;
    bool complete_ = false, failed_ = false;
    rw::NativeAllocatedRangeStamp stamp_;
    std::vector<rw::NativeAllocatedRange> ranges_;
    std::string error_;
};
}
