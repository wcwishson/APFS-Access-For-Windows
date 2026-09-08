#pragma once

#include "AppleCheckpointPublisher.h"
#include "AppleSpacemanAllocator.h"
#include "ApfsTransactionWriter.h"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace apfsaccess::rw
{

struct AppleTransactionCommitRequest
{
    AppleSpacemanAllocationPlan allocation_plan;
    std::uint64_t next_object_id = 0;
    std::uint64_t container_object_map_oid = 0;
    std::vector<std::uint64_t> required_checkpoint_xids;
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

struct AppleRecoveryCheckpointView
{
    catalog::AppleCheckpointView checkpoint;
    std::vector<std::uint64_t> metadata_blocks;
    std::vector<ApplePhysicalExtentRecord> payload_extents;
};

// source and payload blocks are relative to the same store as the exact,
// authoritative checkpoint. Traverses every volume's current metadata and
// requires allocated, non-queued payload outside metadata/reserved ranges.
bool ValidateAppleCheckpointPayloadOwnership(
    const catalog::RandomAccessSource& source,
    const catalog::AppleCheckpointView& checkpoint,
    const std::vector<ApplePhysicalExtentRecord>& payload_extents,
    std::string& out_error);

// Reloads and traverses exact historical metadata, proving current ownership
// before allocation. Payload ranges require complete extent ownership and
// continuous allocation/queue history. Current XID is already protected.
bool LoadAppleRecoveryCheckpoints(
    const catalog::RandomAccessSource& source,
    const catalog::AppleCheckpointView& checkpoint,
    const std::vector<std::uint64_t>& required_checkpoint_xids,
    std::vector<AppleRecoveryCheckpointView>& out_checkpoints,
    std::string& out_error);

struct AppleVolumeReplayBoundary
{
    std::uint64_t preimage_checkpoint_xid = 0;
    // Present when this volume first changed after the accepted preimage.
    // The caller must still prove that change matches its accepted mutations.
    std::optional<std::uint64_t> first_changed_checkpoint_xid;
};

// Follows the retained checkpoint chain from the original WAL preimage. Only
// checkpoints with identical selected-volume roots can advance the preimage.
// This is a read-only boundary proof, not an applied-transaction receipt.
bool FindAppleVolumeReplayBoundary(
    const catalog::RandomAccessSource& source,
    const catalog::AppleCheckpointView& checkpoint,
    std::uint64_t volume_object_id,
    std::uint64_t accepted_preimage_xid,
    AppleVolumeReplayBoundary& out_boundary,
    std::string& out_error);

// Composes a verified spaceman allocation with staged payload/metadata and a
// complete checkpoint-data generation. This function performs no writes.
bool PlanAppleTransactionCommit(
    const catalog::RandomAccessSource& source,
    const catalog::AppleCheckpointView& checkpoint,
    const AppleTransactionCommitRequest& request,
    AppleTransactionCommitPlan& out_plan,
    std::string& out_error);

} // namespace apfsaccess::rw
