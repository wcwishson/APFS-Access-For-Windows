#pragma once

#include "ApfsFusionVolumePlan.h"
#include "ApfsFusionAllocationPlan.h"

namespace apfsaccess::rw {

// Private output of a canonical walk, never accepted from a mutation caller.
struct FusionReclamationCensus {
    std::uint64_t oldest_checkpoint_xid = 0;
    std::vector<AppleSpacemanReleaseRequest> owners;
    std::vector<AppleCheckpointGuardBlock> guards;
};

bool CollectFusionReclamationCensus(const catalog::ApfsFusionStore&,
    FusionReclamationCensus&, std::string&);
bool PlanFusionReclaimingSpacemanAllocation(const catalog::ApfsFusionStore&,
    const AppleSpacemanAllocationRequest&, std::size_t tier2_blocks,
    FusionSpacemanAllocationPlan&, std::vector<AppleCheckpointGuardBlock>&, std::string&);
bool PlanFusionReclaimingVolumeTransaction(const catalog::ApfsFusionStore&,
    const AppleVolumeTransactionRequest&, FusionVolumeTransactionPlan&, std::string&);
// New original commitments use the parsed volume OMAP/filesystem ID census.
// The earlier entry remains stable for rederiving already accepted witnesses.
bool PlanFusionCanonicalVolumeTransaction(const catalog::ApfsFusionStore&,
    const AppleVolumeTransactionRequest&, FusionVolumeTransactionPlan&, std::string&);
bool PlanFusionCompactedVolumeTransaction(const catalog::ApfsFusionStore&,
    const AppleVolumeTransactionRequest&, FusionVolumeTransactionPlan&, std::string&);

}
