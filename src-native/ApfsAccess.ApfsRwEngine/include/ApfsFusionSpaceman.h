#pragma once

#include "ApfsFusionStore.h"

#include <cstdint>
#include <string>

namespace apfsaccess::catalog
{
// Bind-validated two-tier spaceman ownership for one complete Fusion member
// set. This is the smallest correct native abstraction the planner,
// publisher, allocator geometry, and recovery selection can share: per-device
// block/free accounting with exact member-geometry binding, checkpoint-area
// confinement rules, and generation binding. It deliberately stops before
// chunk-bitmap ownership; LoadFusionSpacemanAllocationView below performs that
// separate canonical walk. External interoperability remains separate evidence.
//
// Sources of truth, in order: (1) the bound store's member geometry
// (exact file identities verified at bind, re-verified per read); (2) the
// checksum/XID/OID/type-bound spaceman bytes read live through the store at
// the pinned checkpoint generation; (3) the pinned checkpoint's own area
// fields. A torn or advanced member fails closed; callers rebind and retry.
// The ordinary single-store path never touches this API.
struct FusionSpacemanDeviceOwnership
{
    std::uint64_t block_count = 0;
    std::uint64_t chunk_count = 0;
    std::uint32_t cib_count = 0;
    std::uint32_t cab_count = 0;
    std::uint64_t free_count = 0;
};

struct FusionSpacemanOwnership
{
    std::uint32_t block_size = 0;
    std::uint64_t checkpoint_xid = 0; // generation this view is bound to
    FusionSpacemanDeviceOwnership main_;
    FusionSpacemanDeviceOwnership tier2_;
    std::uint64_t combined_block_count = 0;
    // Checkpoint descriptor/data areas; always main-local and disjoint.
    std::uint64_t desc_base_block = 0;
    std::uint32_t desc_block_count = 0;
    std::uint64_t data_base_block = 0;
    std::uint32_t data_block_count = 0;
};

// Loads and revalidates current member bytes against the store's pinned
// checkpoint and member geometry. Fails closed with an exact code when any
// member is torn, resized, advanced past the pinned generation, or
// inconsistent with the bound set. Never synthesizes accounting.
[[nodiscard]] bool LoadFusionSpacemanOwnership(const ApfsFusionStore& store,
    FusionSpacemanOwnership& out_ownership, std::string& out_error);

// Canonical allocation truth from the exact bound members and checkpoint.
// Chunk start_block is DEVICE-LOCAL; device_index selects its member. Object,
// bitmap and free-queue physical addresses remain Fusion-encoded. This view
// must not be fed to the single-device allocator. No caller ownership flags,
// detached checkpoint, or arbitrary RandomAccessSource can enter this API.
// Supported layout: main-local internal pool and empty Fusion caches.
[[nodiscard]] bool LoadFusionSpacemanAllocationView(const ApfsFusionStore& store,
    AppleSpacemanView& out_view, std::string& out_error);
} // namespace apfsaccess::catalog
