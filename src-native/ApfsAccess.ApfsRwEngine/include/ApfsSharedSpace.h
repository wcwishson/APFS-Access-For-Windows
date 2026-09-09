#pragma once

#include "ApfsFormat.h"

namespace apfsaccess::catalog
{
struct ApfsSpaceAmount
{
    std::uint64_t blocks = 0;
    std::uint64_t bytes = 0;
};

struct ApfsVolumeSpaceProjection
{
    std::uint64_t object_id = 0;
    ApfsSpaceAmount allocated;
    // Projection exists only for known Apple counters. nullopt here means
    // unset reserve/quota; it does not mean an unreadable counter.
    std::optional<ApfsSpaceAmount> reserve;
    std::optional<ApfsSpaceAmount> quota;
    ApfsSpaceAmount sibling_reserve_remaining;
    ApfsSpaceAmount available;
    // Neither snapshots nor purgeable bytes can be inferred from APSB totals.
    std::optional<ApfsSpaceAmount> snapshot;
    std::optional<ApfsSpaceAmount> purgeable;
};

struct ApfsSharedSpaceProjection
{
    std::string container_uuid_hex;
    std::uint64_t checkpoint_xid = 0;
    std::uint32_t allocation_unit_bytes = 0;
    ApfsSpaceAmount total;
    ApfsSpaceAmount free;
    ApfsSpaceAmount used;
    std::vector<ApfsVolumeSpaceProjection> volumes;
};

// Pure checked accounting over an unchanged LoadAppleCheckpointView result.
// This function does not authenticate caller-constructed views. Prefer the
// catalog entry point, which supplies its privately retained verified view.
// Single-store only, matching the authoritative reader's current support.
// Available = min(free - siblings' unmet reserves, remaining configured quota).
// Values describe one checkpoint; they are not independent promises to every
// volume, reservation serialization, allocation enforcement or write admission.
// Failure clears output; snapshot/purgeable remain unknown on success.
bool TryProjectAppleSharedSpace(const AppleCheckpointView& checkpoint,
    ApfsSharedSpaceProjection& out, std::string& error);
}
