#pragma once
#include "NativeSparsePlan.h"

namespace apfsaccess::rw
{
struct NativeCloneRangeRequest
{
    std::uint64_t source_offset = 0, target_offset = 0, length = 0, timestamp_ns = 0;
    bool operator==(const NativeCloneRangeRequest&) const = default;
};
struct NativeCloneRangeState
{
    NativeSparseState source, target;
};
bool NativeCloneRangeRequestIsValid(const NativeCloneRangeRequest&);
// Read-only canonical planning for two existing ordinary streams. Every shared
// extent is derived from the held source graph; no payload copy is performed.
// Actual acceptance and publication require the separate owner session.
bool PlanNativeCloneRangeTransaction(const catalog::RandomAccessSource&,
    const catalog::AppleCheckpointView&, std::uint64_t volume_oid,
    std::uint64_t source_inode, std::uint64_t target_inode, const NativeCloneRangeRequest&,
    NativeCloneRangeState& before, AppleVolumeTransactionPlan&, std::string& error);
// New publication emits complete explicit hole coverage. The prior entrypoint
// remains the byte-exact planner for accepted NCR1 recovery.
bool PlanNativeCloneRangeTransactionV2(const catalog::RandomAccessSource&,
    const catalog::AppleCheckpointView&, std::uint64_t volume_oid,
    std::uint64_t source_inode, std::uint64_t target_inode, const NativeCloneRangeRequest&,
    NativeCloneRangeState& before, AppleVolumeTransactionPlan&, std::string& error);
}
