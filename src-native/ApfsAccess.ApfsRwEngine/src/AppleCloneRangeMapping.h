#pragma once
#include "AppleVolumeTransaction.h"

namespace apfsaccess::rw
{
// Internal planner input, derived from complete canonical source/target trees.
// It is never durable acceptance or permission to publish caller-supplied bytes.
struct AppleCloneRangeMapping
{
    std::uint64_t source_inode = 0, target_inode = 0;
    std::uint64_t source_offset = 0, target_offset = 0, length = 0;

    bool Intersects(const AppleFileExtentRecord& extent) const
    {
        return extent.object_id == target_inode && extent.logical_address < target_offset + length &&
            target_offset < extent.logical_address + extent.length_bytes;
    }
    bool Covers(const AppleFileExtentRecord& extent) const
    {
        return extent.object_id == target_inode && extent.logical_address >= target_offset &&
            extent.logical_address - target_offset < length &&
            extent.length_bytes <= length - (extent.logical_address - target_offset);
    }
};
bool PlanAppleCloneRangeTransaction(const catalog::RandomAccessSource&,
    const catalog::AppleCheckpointView&, const AppleVolumeTransactionRequest&,
    const AppleCloneRangeMapping&, AppleVolumeTransactionPlan&, std::string&);
}
