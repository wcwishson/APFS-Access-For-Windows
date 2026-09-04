#pragma once

#include "ApfsFormat.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace apfsaccess::rw
{

enum class AppleSpacemanWriteKind
{
    ChunkBitmap,
    ChunkInfoBlock,
    ChunkInfoAddressBlock,
    FreeQueueTree,
    InternalPoolBitmap,
};

struct AppleSpacemanPlannedWrite
{
    AppleSpacemanWriteKind kind = AppleSpacemanWriteKind::ChunkBitmap;
    std::uint64_t physical_block = 0;
    std::optional<catalog::AppleObjectLocation> object_location;
    std::vector<std::byte> bytes;
};

struct AppleSpacemanDeferredFree
{
    std::size_t queue_index = 0;
    std::uint64_t physical_block = 0;
    std::uint64_t block_count = 0;
};

struct AppleSpacemanReleaseRequest
{
    std::uint64_t physical_block = 0;
    std::uint64_t block_count = 0;
};

struct AppleSpacemanAllocationRequest
{
    std::uint64_t expected_checkpoint_xid = 0;
    std::uint64_t transaction_xid = 0;
    std::size_t main_block_count = 0;
    bool search_from_end = false;
    std::uint64_t first_ephemeral_object_id = 0;
    std::vector<AppleSpacemanReleaseRequest> released_blocks;
};

struct AppleSpacemanAllocationPlan
{
    std::uint64_t expected_checkpoint_xid = 0;
    std::uint64_t transaction_xid = 0;
    std::vector<std::uint64_t> allocated_main_blocks;
    std::vector<std::uint64_t> allocated_internal_pool_blocks;
    std::vector<AppleSpacemanDeferredFree> deferred_frees;
    std::vector<AppleSpacemanPlannedWrite> writes;
    catalog::AppleSpacemanView updated_spaceman;
};

// Produces a complete in-memory allocator delta. The input view is never
// mutated and this function performs no I/O.
bool PlanAppleSpacemanAllocation(
    const catalog::AppleSpacemanView& view,
    const AppleSpacemanAllocationRequest& request,
    AppleSpacemanAllocationPlan& out_plan,
    std::string& out_error);

// Reselects the current container checkpoint and compares every allocator-owned
// identity and ownership map with the snapshot used for planning.
bool VerifyAppleSpacemanOwnershipUnchanged(
    const catalog::RandomAccessSource& source,
    std::uint64_t store_offset_bytes,
    std::uint64_t store_size_bytes,
    const catalog::ContainerCheckpointView& expected_checkpoint,
    const catalog::AppleSpacemanView& expected_view,
    std::string& out_error);

} // namespace apfsaccess::rw
