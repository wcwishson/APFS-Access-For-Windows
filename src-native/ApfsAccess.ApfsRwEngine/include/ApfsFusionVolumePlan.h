#pragma once
#include "ApfsFusionAllocationPlan.h"
#include "AppleVolumeTransaction.h"

namespace apfsaccess::rw
{
struct FusionVolumeTransactionPlan
{
    AppleVolumeTransactionPlan transaction;
    std::vector<std::uint64_t> allocated_tier2_blocks;
};

// Complete ordinary volume mutation planner over exact held Fusion members.
// Payload uses Tier2; metadata uses main. Every live sibling is traversed and
// guarded. Snapshot/encrypted/cache-active profiles retain their refusals.
// A plan is not an original-WAL publication witness and grants no write access.
bool PlanFusionVolumeTransaction(const catalog::ApfsFusionStore& store,
    const AppleVolumeTransactionRequest& request, FusionVolumeTransactionPlan& out,
    std::string& error);
}
