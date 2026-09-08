#pragma once

#include "ApfsFormat.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace apfsaccess::rw
{

class BlockDevice;

enum class AppleCheckpointWriteKind
{
    AllocatorOwned,
    CheckpointData,
    CheckpointMap,
    CheckpointSuperblock,
};

struct AppleCheckpointPhysicalWrite
{
    std::uint64_t physical_block = 0;
    std::vector<std::byte> bytes;
};

struct AppleCheckpointEphemeralObject
{
    std::uint64_t file_system_oid = 0;
    catalog::AppleObjectLocation object;
    std::vector<std::byte> bytes;
};

struct AppleCheckpointPublicationRequest
{
    std::uint64_t expected_checkpoint_xid = 0;
    std::uint64_t transaction_xid = 0;
    std::uint64_t next_object_id = 0;
    // Zero preserves nx_omap_oid. A replacement must be a staged physical
    // OMAP object at this allocator-owned block.
    std::uint64_t container_object_map_oid = 0;
    // Exact unresolved-recovery generations; each is reloaded from this store.
    std::vector<std::uint64_t> required_checkpoint_xids;
    std::vector<AppleCheckpointPhysicalWrite> allocator_owned_writes;
    // This is the complete ephemeral object set for the new checkpoint, not
    // merely the objects changed by this transaction.
    std::vector<AppleCheckpointEphemeralObject> ephemeral_objects;
    // Old non-root ephemeral identities omitted from the new checkpoint must
    // be named explicitly. This lets rebuilt ephemeral trees retire old child
    // nodes without turning an accidental omission into a valid checkpoint.
    std::vector<std::uint64_t> retired_ephemeral_object_ids;
};

struct AppleCheckpointPlannedWrite
{
    AppleCheckpointWriteKind kind = AppleCheckpointWriteKind::AllocatorOwned;
    std::uint64_t physical_block = 0;
    std::uint64_t object_id = 0;
    std::vector<std::byte> bytes;
};

struct AppleCheckpointGuardBlock
{
    std::uint64_t physical_block = 0;
    std::vector<std::byte> bytes;
};

struct AppleCheckpointPublicationPlan
{
    std::uint32_t block_size = 0;
    std::uint64_t expected_checkpoint_xid = 0;
    std::uint64_t transaction_xid = 0;
    std::uint64_t next_object_id = 0;
    std::vector<AppleCheckpointGuardBlock> guard_blocks;
    std::vector<AppleCheckpointPlannedWrite> before_superblock_writes;
    AppleCheckpointPlannedWrite superblock_write;
    catalog::ContainerCheckpointView published_checkpoint;
};

// Builds a deterministic transaction without performing I/O. `source` and
// `checkpoint` must describe the same currently selected store-relative view.
bool PlanAppleCheckpointPublication(
    const catalog::RandomAccessSource& source,
    const catalog::ContainerCheckpointView& checkpoint,
    const AppleCheckpointPublicationRequest& request,
    AppleCheckpointPublicationPlan& out_plan,
    std::string& out_error);

class AppleCheckpointWriteTarget
{
public:
    virtual ~AppleCheckpointWriteTarget() = default;

    virtual bool ReadBlock(
        std::uint64_t physical_block,
        std::uint32_t block_size,
        std::vector<std::byte>& out_bytes) = 0;
    // Reads a nonempty whole-block prefix of at most max_blocks adjacent
    // blocks. The default reads exactly one block, preserving legacy targets'
    // read/compare order and stopping before the next read on a mismatch.
    virtual bool ReadBlockRange(
        std::uint64_t physical_block,
        std::uint32_t block_size,
        std::size_t max_blocks,
        std::vector<std::byte>& out_bytes)
    {
        return block_size != 0 && max_blocks != 0 &&
            ReadBlock(physical_block, block_size, out_bytes) &&
            out_bytes.size() == block_size;
    }
    virtual bool WriteBlock(
        std::uint64_t physical_block,
        std::span<const std::byte> bytes) = 0;
    virtual bool WriteBlocks(
        std::span<const AppleCheckpointPlannedWrite> writes)
    {
        for (const auto& write : writes)
        {
            if (!WriteBlock(write.physical_block, write.bytes))
            {
                return false;
            }
        }
        return true;
    }
    virtual bool Flush() = 0;
};

using AppleCheckpointStageHook =
    std::function<bool(std::string_view stage)>;

// Rechecks the selected checkpoint, writes and verifies every non-publishing
// block, flushes, writes the new NXSB last, verifies it, and flushes again.
bool ExecuteAppleCheckpointPublication(
    AppleCheckpointWriteTarget& target,
    const AppleCheckpointPublicationPlan& plan,
    std::string& out_error,
    const AppleCheckpointStageHook& stage_hook = {});

bool ExecuteAppleCheckpointPublication(
    BlockDevice& device,
    const AppleCheckpointPublicationPlan& plan,
    std::string& out_error,
    const AppleCheckpointStageHook& stage_hook = {});

} // namespace apfsaccess::rw
