#pragma once

#include "AppleTransactionCommit.h"
#include "CompressionRewrite.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace apfsaccess::catalog { class ApfsFusionStore; }

namespace apfsaccess::rw
{

struct AppleVolumeDataWrite
{
    std::uint64_t file_private_id = 0;
    std::uint64_t logical_address = 0;
    std::uint64_t crypto_id = 0;
    std::vector<std::byte> bytes;
};

struct AppleVolumeCloneRequest
{
    // Whole uncompressed regular-file stream, into a newly allocated inode ID.
    // Namespace/inode creation remains supplied in filesystem_records.
    std::uint64_t source_inode_id = 0;
    std::uint64_t target_inode_id = 0;
};

struct AppleVolumeTransactionRequest
{
    // Native metadata planner only: atomic reserve/quota pair in APFS blocks.
    // Zero reserve means none; zero quota means no configured maximum.
    std::optional<std::pair<std::uint64_t, std::uint64_t>> volume_reserve_quota;
    std::uint64_t volume_object_id = 0;
    std::vector<std::uint64_t> required_checkpoint_xids;
    // Complete replacement record set for the filesystem tree, excluding
    // extents generated for data_writes. Data-stream ID records are checked
    // and normalized against the old tree and data_writes.
    std::vector<catalog::BtreeRecord> filesystem_records;
    std::vector<AppleVolumeDataWrite> data_writes;
    // Native planner input only. A host must durably accept clone identity and
    // source preimage before exposing this operation. MetadataStore supplies the
    // typed native acceptance API; this planner alone is not an acceptance API.
    std::vector<AppleVolumeCloneRequest> clones;
    // Exact source evidence from the dedicated MetadataStore transition.
    std::vector<CompressionRewrite> compression_rewrites;
    // Exact multiset of relinquished file-extent mappings, not allocator frees.
    // Clone mappings can overlap; the planner derives the zero-reference ranges.
    std::vector<AppleSpacemanReleaseRequest> released_data_blocks;
    std::int64_t file_count_delta = 0;
    std::int64_t directory_count_delta = 0;
    std::int64_t symlink_count_delta = 0;
    std::int64_t other_object_count_delta = 0;
    // Zero preserves the existing APSB modification time.
    std::uint64_t last_modification_time = 0;
    // Conservative metadata-only COW: retain source tree/OMAP/APSB blocks,
    // charge all new volume metadata, and disable eligible queue reclamation.
    // Refuses data mutations and queues at XID 1 (the lowest retention floor).
    bool preserve_source_metadata = false;
};

struct AppleVolumeTransactionPlan
{
    AppleSpacemanAllocationPlan allocation;
    AppleTransactionCommitPlan commit;
    std::vector<std::uint64_t> payload_blocks;
    std::vector<catalog::BtreeRecord> filesystem_records;
};

// Native planning only; no durable acceptance or coordinator/host surface.
// Bounded multi-snapshot profile, with all source metadata retained. inum is
// opaque Apple metadata supplied by the caller, not an invented directory entry.
struct AppleSnapshotCreateRequest
{
    std::uint64_t volume_object_id = 0;
    std::string name_utf8;
    std::uint64_t creation_time_ns = 0;
    std::uint64_t snapshot_inum = 0;
    std::vector<std::uint64_t> required_checkpoint_xids;
};
struct AppleSnapshotCreatePlan
{
    AppleSpacemanAllocationPlan allocation;
    AppleTransactionCommitPlan commit;
    catalog::ApfsSnapshotIdentity identity;
};
bool PlanAppleSnapshotCreate(const catalog::RandomAccessSource& source,
    const catalog::AppleCheckpointView& checkpoint, const AppleSnapshotCreateRequest& request,
    AppleSnapshotCreatePlan& out_plan, std::string& out_error,
    bool allow_fusion_profile = false);

bool CheckAppleVolumeWriteFeatures(
    const catalog::NxSuperblock& container,
    const catalog::ApsbVolume& volume,
    std::string& out_error,
    // Set only by the Fusion entry below, which plans against a
    // bound-store-proven checkpoint: the store's bind already established the
    // supported Fusion profile (clean anchors, empty caches, main-local
    // checkpoint), so the incompatibility gate admits exactly that profile.
    // Every other caller must leave it false.
    bool allow_fusion_profile = false);

// Builds a complete single-volume Apple APFS copy-on-write transaction without
// performing I/O. Snapshot-bearing volumes remain fail-closed until snapshot
// reference accounting is implemented.
bool PlanAppleVolumeTransaction(
    const catalog::RandomAccessSource& source,
    const catalog::AppleCheckpointView& checkpoint,
    const AppleVolumeTransactionRequest& request,
    AppleVolumeTransactionPlan& out_plan,
    std::string& out_error);

// Forward ordinary ingest uses allocation-run records. Legacy/replay callers
// retain the entry above; both paths perform identical ownership validation.
bool PlanApplePlainCompactTransaction(
    const catalog::RandomAccessSource& source,
    const catalog::AppleCheckpointView& checkpoint,
    const AppleVolumeTransactionRequest& request,
    AppleVolumeTransactionPlan& out_plan,
    std::string& out_error, bool preserve_sibling_snapshots = false);

enum class AppleCapacityPreviewResult { Planned, Unsupported, Refused };

// Deliberately has no publication plan or conversion to one.
struct AppleVolumeCapacityPreview
{
    AppleSpacemanAllocationPlan allocation;
    std::vector<std::uint64_t> payload_blocks;
    std::vector<catalog::BtreeRecord> filesystem_records;
    std::size_t metadata_write_count = 0;
    std::uint64_t metadata_write_bytes = 0;
};

// Each data_writes entry supplies identity/offset/crypto only, with empty bytes;
// payload_bytes supplies its exact length. Content-dependent and nonplain
// profiles return Unsupported so the caller can retain full byte validation.
AppleCapacityPreviewResult PreviewApplePlainCompactCapacity(
    const catalog::RandomAccessSource& source,
    const catalog::AppleCheckpointView& checkpoint,
    const AppleVolumeTransactionRequest& request,
    std::span<const std::uint64_t> payload_bytes,
    AppleVolumeCapacityPreview& out_preview, std::string& out_error);

// Opt-in ordinary writer for a volume without local snapshots, in a container
// whose siblings retain snapshots. Uses the fully validating snapshot compositor
// and snapshot-aware recovery pins; selected-volume reference accounting remains
// ordinary. Local snapshot-bearing volumes still require the live entry below.
bool PlanAppleSnapshotSiblingTransaction(
    const catalog::RandomAccessSource& source,
    const catalog::AppleCheckpointView& checkpoint,
    const AppleVolumeTransactionRequest& request,
    AppleVolumeTransactionPlan& out_plan,
    std::string& out_error);

// Canonical reference records required after removing one exact snapshot.
// This is a read-only deletion preflight, NOT a publication/reclamation permit.
// PlanAppleSnapshotDelete performs physical publication and pin-owner checks.
struct AppleSnapshotReferenceReplacement
{
    std::uint64_t snapshot_xid = 0; // zero denotes the live extent-reference tree
    std::vector<catalog::BtreeRecord> extentref_records;
};
struct AppleSnapshotDeleteReferencePlan
{
    catalog::ApfsSnapshotIdentity removed;
    std::vector<AppleSnapshotReferenceReplacement> replacements;
    std::vector<AppleSpacemanReleaseRequest> unreferenced_payload;
};
bool PlanAppleSnapshotDeleteReferences(const catalog::RandomAccessSource& source,
    const catalog::AppleCheckpointView& checkpoint, const catalog::ApfsSnapshotIdentity& expected,
    AppleSnapshotDeleteReferencePlan& out_plan, std::string& out_error);

struct AppleSnapshotDeleteRequest
{
    catalog::ApfsSnapshotIdentity expected;
    std::uint64_t modification_time_ns = 0;
    std::vector<std::uint64_t> required_checkpoint_xids;
};
struct AppleSnapshotDeletePlan
{
    AppleSpacemanAllocationPlan allocation;
    AppleTransactionCommitPlan commit;
    catalog::ApfsSnapshotIdentity removed;
    std::vector<catalog::ApfsSnapshotIdentity> surviving;
    std::uint64_t released_payload_blocks = 0;
};
// Native atomic deletion: rebase retained layers, COW their physical metadata,
// remove inventory, defer only proven unreferenced payload via spaceman.
// All previous metadata stays allocated and charged in this bounded profile.
bool PlanAppleSnapshotDelete(const catalog::RandomAccessSource& source,
    const catalog::AppleCheckpointView& checkpoint, const AppleSnapshotDeleteRequest& request,
    AppleSnapshotDeletePlan& out_plan, std::string& out_error);

// Fusion snapshot-create entry: plans against a bound-store-proven Fusion
// checkpoint (the store object itself, never a detached view), then finalizes
// below. The store's bind established the supported profile; availability is
// re-verified here. File-data planners stay refused for Fusion sets.
bool PlanFusionSnapshotCreate(const catalog::ApfsFusionStore& store,
    const AppleSnapshotCreateRequest& request,
    AppleSnapshotCreatePlan& out_plan, std::string& out_error);

// Verifies a checkpoint publication plan against the bound store's Fusion
// profile and derives the tier-2 anchor mirror: every checkpoint-kind write
// must be main-local (only allocator-owned payload may address the second
// tier), and the staged superblock must be the canonical main anchor whose
// fusion UUID matches the bound set. Attaches the mirror for the executor's
// ordered anchor stage. Usable on any planner-produced publication, not only
// snapshot creates.
bool FinalizeFusionCheckpointPublication(const catalog::ApfsFusionStore& store,
    AppleCheckpointPublicationPlan& plan, std::string& out_error);

// Explicit native snapshot-bearing mutation profile. Proves current/history
// ownership, emits a signed live layer and preserves all old metadata. It is
// not wired to MetadataStore/WAL acceptance or coordinator/host admission.
bool PlanAppleSnapshotLiveTransaction(const catalog::RandomAccessSource& source,
    const catalog::AppleCheckpointView& checkpoint, const AppleVolumeTransactionRequest& request,
    AppleVolumeTransactionPlan& out_plan, std::string& out_error);

// Metadata-only checkpoint: the full filesystem record set must equal its
// canonical preimage. Retains source metadata and existing reference layers;
// no payload, stream, count, timestamp, quota or snapshot inventory change.
bool PlanAppleSnapshotMetadataTransaction(const catalog::RandomAccessSource& source,
    const catalog::AppleCheckpointView& checkpoint, const AppleVolumeTransactionRequest& request,
    AppleVolumeTransactionPlan& out_plan, std::string& out_error);

} // namespace apfsaccess::rw
