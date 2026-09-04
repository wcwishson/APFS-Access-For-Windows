#pragma once

#include "AppleCheckpointPublisher.h"
#include "AppleSpacemanAllocator.h"

#include <cstdint>
#include <string>
#include <vector>

namespace apfsaccess::rw
{

struct AppleTransactionCommitRequest
{
    AppleSpacemanAllocationPlan allocation_plan;
    std::uint64_t next_object_id = 0;
    std::uint64_t container_object_map_oid = 0;
    // Every main-pool block reserved by allocation_plan must be covered once,
    // and no other main-pool block may be supplied here.
    std::vector<AppleCheckpointPhysicalWrite> allocated_main_writes;
    // Optional replacements for non-spaceman ephemeral objects.
    std::vector<AppleCheckpointEphemeralObject> additional_ephemeral_objects;
};

struct AppleTransactionCommitPlan
{
    AppleCheckpointPublicationPlan publication;
};

// Composes a verified spaceman allocation with staged payload/metadata and a
// complete checkpoint-data generation. This function performs no writes.
bool PlanAppleTransactionCommit(
    const catalog::RandomAccessSource& source,
    const catalog::AppleCheckpointView& checkpoint,
    const AppleTransactionCommitRequest& request,
    AppleTransactionCommitPlan& out_plan,
    std::string& out_error);

} // namespace apfsaccess::rw
