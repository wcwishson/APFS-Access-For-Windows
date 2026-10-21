#pragma once

#include "AppleTransactionCommit.h"

namespace apfsaccess::rw::capacity_detail
{
// Internal previews carry exact payload block identities, never payload bytes.
// Their publication output has no executable superblock and is discarded by
// the typed volume-preview entry point after all ordinary source checks.
bool PlanPublication(const catalog::RandomAccessSource& source,
    const catalog::ContainerCheckpointView& checkpoint,
    const AppleCheckpointPublicationRequest& request,
    std::span<const std::uint64_t> payload_blocks,
    AppleCheckpointPublicationPlan& out_plan, std::string& error);

bool PlanCommit(const catalog::RandomAccessSource& source,
    const catalog::AppleCheckpointView& checkpoint,
    const AppleTransactionCommitRequest& request,
    std::span<const std::uint64_t> payload_blocks,
    AppleTransactionCommitPlan& out_plan, std::string& error);
}
