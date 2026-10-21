#pragma once

#include "AppleCheckpointPublisher.h"
#include "AppleSpacemanAllocator.h"
#include "ApfsTransactionWriter.h"
#include "ApfsSnapshotStore.h"

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
    // Typed snapshot planners only: request exact metadata retirement for this
    // volume. Zero retains removed metadata; both modes independently prove
    // serialized ownership, queues, exact counters, limits and recovery pins.
    std::uint64_t snapshot_retirement_volume_oid = 0;
};

struct AppleTransactionCommitPlan
{
    AppleCheckpointPublicationPlan publication;
};

struct AppleSnapshotRetirementProof
{
    std::vector<AppleSpacemanReleaseRequest> releases;
    std::vector<std::uint64_t> source_metadata_blocks;
    std::vector<AppleSpacemanReleaseRequest> source_owned_blocks;
    std::uint64_t allocated_volume_blocks = 0;
    std::uint64_t retired_volume_blocks = 0;
    std::uint64_t retired_volume_payload_blocks = 0;
};
// Read-only, bounded before/serialized-after proof. Includes complete OMAP
// versions and historical inventory closure; peers and explicit recovery pins
// cannot be discharged. Existing unproven charge is never reset to a census.
bool ProveAppleSnapshotRetirement(const catalog::RandomAccessSource& source,
    const catalog::AppleCheckpointView& checkpoint,
    const AppleCheckpointPublicationPlan& publication, std::uint64_t volume_oid,
    const std::vector<std::uint64_t>& required_checkpoint_xids,
    AppleSnapshotRetirementProof& out_proof, std::string& out_error);

struct AppleRecoveryCheckpointView
{
    catalog::AppleCheckpointView checkpoint;
    std::vector<std::uint64_t> metadata_blocks;
    std::vector<ApplePhysicalExtentRecord> payload_extents;
};

// Read-only ownership census. Chronological NEW/UPDATE layers are resolved
// against exact per-snapshot mappings; the current live layer is checked too.
// Metadata includes shared/live inventory roots conservatively. Payload may
// overlap between snapshot views and is never summed into live refcounts.
// Source must remain stable, store-relative, and bound to this current
// authoritative checkpoint. Failure clears the entire output. A supplied read
// budget is shared; otherwise a bounded default is installed for this walk.
struct AppleSnapshotRetentionView
{
    std::vector<catalog::ApfsSnapshotIdentity> identities;
    std::vector<std::uint64_t> metadata_blocks;
    std::vector<ApplePhysicalExtentRecord> payload_extents;
};
bool LoadAppleSnapshotRetention(const catalog::RandomAccessSource& source,
    const catalog::AppleCheckpointView& checkpoint,
    AppleSnapshotRetentionView& out_retention, std::string& out_error);

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

// Complete snapshot/live/sibling graph for runtime preimage hashing.
bool LoadAppleSnapshotCheckpointOwners(const catalog::RandomAccessSource&,
    const catalog::AppleCheckpointView&,std::vector<std::uint64_t>&,
    std::vector<ApplePhysicalExtentRecord>&,std::string&);

bool FindAppleSnapshotVolumeReplayBoundary(const catalog::RandomAccessSource&,const catalog::AppleCheckpointView&,
    std::uint64_t volume_oid,std::uint64_t preimage_xid,AppleVolumeReplayBoundary&,std::string&);

// Composes a verified spaceman allocation with staged payload/metadata and a
// complete checkpoint-data generation. This function performs no writes.
// Existing snapshots receive conservative metadata/payload ownership guards
// and a staged serialized-ownership proof. This original entry point refuses
// snapshot-bearing root replacement; the explicit preserving composer below
// supports that profile. Snapshot WAL history and deletion remain refused.
bool PlanAppleTransactionCommit(
    const catalog::RandomAccessSource& source,
    const catalog::AppleCheckpointView& checkpoint,
    const AppleTransactionCommitRequest& request,
    AppleTransactionCommitPlan& out_plan,
    std::string& out_error);

// Narrow composer for replacing live roots while preserving every exact
// snapshot identity and all retained bytes. No snapshot removal is authorized.
bool PlanAppleSnapshotPreservingCommit(const catalog::RandomAccessSource& source,
    const catalog::AppleCheckpointView& checkpoint, const AppleTransactionCommitRequest& request,
    AppleTransactionCommitPlan& out_plan, std::string& out_error);

// Exactly one inventory operation. The composer independently proves the
// exact before/after views. Opt-in metadata retirement also requires the full
// independent ownership/counter proof; recovery pins are independently read.
struct AppleSnapshotInventoryChange
{
    std::optional<catalog::ApfsSnapshotIdentity> created;
    std::optional<catalog::ApfsSnapshotIdentity> removed;
};
bool PlanAppleSnapshotInventoryCommit(const catalog::RandomAccessSource& source,
    const catalog::AppleCheckpointView& checkpoint, const AppleTransactionCommitRequest& request,
    const AppleSnapshotInventoryChange& change, AppleTransactionCommitPlan& out_plan,
    std::string& out_error);

// Planning-only serialized candidate for the ownership walk. It deliberately
// cannot return an executable commit plan; public typed composers always prove
// counters, queues and capacity independently before returning such a plan.
bool PlanAppleSnapshotRetirementCandidate(const catalog::RandomAccessSource& source,
    const catalog::AppleCheckpointView& checkpoint, const AppleTransactionCommitRequest& request,
    const AppleSnapshotInventoryChange* change, AppleCheckpointPublicationPlan& out_publication,
    std::string& out_error);

// Explicit snapshot-aware read-only recovery census. Includes every historical
// snapshot owner and resolved live UPDATE layer, then uses the same allocation,
// retirement-queue and bitmap-rotation continuity proof as ordinary pins.
// This is not WAL acceptance, a receipt, or authorization to retire any pin.
bool LoadAppleSnapshotRecoveryCheckpoints(const catalog::RandomAccessSource& source,
    const catalog::AppleCheckpointView& checkpoint,
    const std::vector<std::uint64_t>& required_checkpoint_xids,
    std::vector<AppleRecoveryCheckpointView>& out_checkpoints, std::string& out_error);

} // namespace apfsaccess::rw
