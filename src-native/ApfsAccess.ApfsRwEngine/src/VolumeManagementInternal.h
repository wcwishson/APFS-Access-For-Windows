#pragma once
#include "VolumeManagement.h"

namespace apfsaccess::rw::volume_management
{
struct TopologyPlan
{
    AppleSpacemanAllocationPlan allocation;
    AppleCheckpointPublicationPlan publication;
    catalog::AppleCheckpointView before, after;
    std::uint64_t released_blocks = 0;
};
// No writes. Input must be a stable store-relative image. The keeper, not a
// caller-supplied boolean, establishes the external WAL census and image lease.
bool PlanTopology(const catalog::RandomAccessSource&, const VolumeManagementRequest&,
    TopologyPlan&, std::string&);
bool PlanTopologyV2(const catalog::RandomAccessSource&, const VolumeManagementRequest&,
    TopologyPlan&, std::string&);
bool VerifyTopology(const catalog::RandomAccessSource&, const catalog::AppleCheckpointView&,
    std::string&);
}
