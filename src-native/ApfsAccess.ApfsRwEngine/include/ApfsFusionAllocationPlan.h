#pragma once

#include "AppleSpacemanAllocator.h"
#include "ApfsFusionStore.h"

namespace apfsaccess::rw
{
struct FusionSpacemanAllocationPlan
{
    AppleSpacemanAllocationPlan main;
    // Encoded physical addresses, never device-local chunk offsets.
    std::vector<std::uint64_t> allocated_tier2_blocks;
};

// Planning only. Ownership is parsed from these exact held members. The bounded
// profile retains every queued free and uses only zero spare IP bitmap slots
// excluded from all selectable historical checkpoints.
// Caller retention fields can tighten protection but cannot permit reclamation.
bool PlanFusionSpacemanAllocation(const catalog::ApfsFusionStore& store,
    const AppleSpacemanAllocationRequest& request, std::size_t tier2_block_count,
    FusionSpacemanAllocationPlan& out_plan, std::string& error);
}
