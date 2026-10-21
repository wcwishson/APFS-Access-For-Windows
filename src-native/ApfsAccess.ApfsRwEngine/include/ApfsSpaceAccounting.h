#pragma once

#include "ApfsSharedSpace.h"
#include "ApfsVerifier.h"

namespace apfsaccess::catalog
{
// Physical payload reachability for the complete inventory of one volume at
// one checkpoint. Each physical block is counted once across clones/snapshots.
// Includes ordinary data and external attribute streams; excludes holes and
// metadata. The two partitions sum to referenced_payload.
struct ApfsSnapshotPayloadSpaceObservation
{
    std::string source_identity;
    ApfsSnapshotScope scope;
    std::uint32_t allocation_unit_bytes = 0;
    std::uint64_t snapshot_count = 0;
    ApfsSpaceAmount referenced_payload;
    ApfsSpaceAmount shared_with_live_payload;
    ApfsSpaceAmount absent_from_live_payload;
};

// Bounded read-only building block for single-volume ordinary, single-store
// images. Caller holds a stable source for the whole operation; the byte API
// authenticates neither its file/device kind nor source_identity's label.
// Requires the verifier's complete covered current subset and canonical
// snapshot ownership checks. Reuses one cumulative allowance for verification,
// exact checkpoint/catalog reads, signed reference resolution and interval work.
// Broader verification/payload-content requests are refused, never weakened.
//
// absent_from_live_payload means reachable from snapshots but absent from this
// volume's current payload graph. It is NOT exclusive to an individual snapshot,
// a reclaim candidate, or deletion savings: retained checkpoints/OMAP versions
// may still own it. Total snapshot, purgeable and reclaimable amounts remain
// unknown. Never assign this payload subset to a total snapshot-space field.
// Empty verified inventory yields known zero payload amounts. Unsupported scope,
// budget exhaustion, corruption or read failure clears out to unknown.
[[nodiscard]] bool TryObserveAppleSnapshotPayloadSpace(
    const RandomAccessSource& source, const VerificationScope& scope,
    std::optional<ApfsSnapshotPayloadSpaceObservation>& out, std::string& error);

// Physical set measures, never logical refcounts or APSB allocation charges.
// referenced = shared_with_live + absent_from_live. The other measures overlap:
// shared_with_other_snapshots includes blocks also shared with live. unique_in_
// visible_inventory excludes live and every other visible snapshot.
struct ApfsSnapshotAttributionAmounts
{
    ApfsSpaceAmount referenced, shared_with_live, absent_from_live;
    ApfsSpaceAmount shared_with_other_snapshots, unique_in_visible_inventory;
    ApfsSpaceAmount retained_or_peer_protected;
    // Unique visible blocks minus independently authenticated retained/peer
    // owners. Hidden OMAP owners may still protect them: an upper bound only.
    ApfsSpaceAmount potential_reclaim_upper_bound;
};

struct ApfsSnapshotSpaceAttributionRow
{
    std::uint64_t snapshot_xid = 0;
    std::string name_utf8;
    // Metadata is the canonical selected view's APSB/OMAP/FS/extentref
    // dependency footprint. Shared catalog/container scaffolding is separate.
    ApfsSnapshotAttributionAmounts metadata, payload;
    // The admitted ordinary inode profile excludes INODE_IS_PURGEABLE and
    // reserved purgeability xfields. Known zero marks is not OS purgeability.
    ApfsSpaceAmount purgeable_marked_payload;
    std::optional<ApfsSpaceAmount> apple_purgeable, reclaimable;
};

struct ApfsSnapshotSpaceAttribution
{
    std::string source_identity;
    ApfsSnapshotScope scope;
    std::uint32_t allocation_unit_bytes = 0;
    std::vector<std::uint64_t> retained_checkpoint_xids;
    // Union across all rows, not the sum of per-row footprints.
    ApfsSpaceAmount referenced_metadata, referenced_payload;
    // Complete canonical inventory metadata, including live/shared scaffolding.
    ApfsSpaceAmount catalog_metadata;
    std::vector<ApfsSnapshotSpaceAttributionRow> snapshots; // Increasing XID.
    // Set only at complete publication; encoding retains this exact allowance.
    bool complete = false;
    std::shared_ptr<ApfsReadBudget> read_budget;
};

struct ProfileSnapshotGraphReport;
struct ApfsProfileSnapshotAttributionRow
{
    std::uint64_t snapshot_xid = 0;
    std::string name_utf8;
    AppleObjectLocation descriptor;
    ApfsSpaceAmount declared_filesystem_allocation;
    ApfsSnapshotAttributionAmounts metadata, payload;
};
// A finite profile result, distinct from exhaustive ordinary attribution.
// Protection covers only the explicitly proved parent chain and visible peers.
// Potential release is an upper bound; hidden owners and Apple policy remain
// unproved. Raw saved volume counters never become independent snapshot charges.
struct ApfsProfileSnapshotSpaceAttribution
{
    CurrentVerificationProfile profile = CurrentVerificationProfile::FusionCleanCache;
    VerificationScope endpoint_scope;
    std::optional<std::uint64_t> from_xid;
    std::vector<VerificationStoreBinding> stores;
    std::vector<std::uint64_t> protected_checkpoint_xids;
    std::uint32_t allocation_unit_bytes = 0;
    ApfsSpaceAmount live_metadata, live_payload;
    ApfsSpaceAmount referenced_snapshot_metadata, referenced_snapshot_payload;
    std::vector<ApfsProfileSnapshotAttributionRow> snapshots;
    bool complete = false;
    std::shared_ptr<ApfsReadBudget> read_budget;
    std::optional<ApfsSpaceAmount> snapshot_allocation_charge, apple_purgeable, reclaimable;
};

// Pure bounded set accounting over a complete canonical profile graph. It
// creates no source, crypto, mutation or release authority. The caller retains
// that graph's exact held-source binding and shared allowance through encoding.
// All selected endpoint snapshot dependencies must occur in the protected graph.
[[nodiscard]] bool TryAttributeVerifiedProfileSnapshotSpace(
    const ProfileSnapshotGraphReport& graph, std::optional<ApfsProfileSnapshotSpaceAttribution>& out,
    std::string& error, const std::function<bool()>& within_deadline);

// Complete latest-checkpoint ordinary single-store profile, including peers.
// Always requests exhaustive retained ownership under the same sticky budget.
// Reuses canonical typed metadata claims and chronological signed extent layers.
// Caller must hold a stable source throughout. No file/device identity or write
// authority is granted by this byte API. Any failure clears the entire result.
// Existing payload-only observation/verifier structs and wire versions are unchanged.
[[nodiscard]] bool TryAttributeAppleSnapshotSpace(
    const RandomAccessSource& source, const VerificationScope& scope,
    std::optional<ApfsSnapshotSpaceAttribution>& out, std::string& error,
    const std::function<bool()>& within_deadline = {});

// Explicit observational inactive-tree admission; the original API stays strict.
// Amount meanings, unknown policy values and source/budget requirements match it.
[[nodiscard]] bool TryAttributeAppleSnapshotSpaceReadOnly(
    const RandomAccessSource& source, const VerificationScope& scope,
    std::optional<ApfsSnapshotSpaceAttribution>& out, std::string& error,
    const std::function<bool()>& within_deadline = {});

struct ApfsSnapshotAllocationCounterRow
{
    std::uint64_t snapshot_xid = 0;
    std::string name_utf8;
    AppleObjectLocation descriptor;
    // Exact parsed apfs_fs_alloc_count at descriptor.xid. Snapshot deletion may
    // COW this descriptor later than snapshot_xid. This reported volume counter
    // is not an independently reconstructed snapshot allocation/deletion charge.
    ApfsSpaceAmount declared_filesystem_allocation;
};

struct ApfsSnapshotAllocationCounters
{
    std::string source_identity;
    ApfsSnapshotScope scope;
    std::uint32_t allocation_unit_bytes = 0;
    std::vector<ApfsSnapshotAllocationCounterRow> snapshots;
    bool complete = false;
    std::shared_ptr<ApfsReadBudget> read_budget;
    std::optional<ApfsSpaceAmount> snapshot_allocation_charge, apple_purgeable, reclaimable;
};

// Separate declared-counter observation after the existing complete ordinary
// read-only attribution proof. Reuses ParseApsb results from the canonical
// catalog, never derives a logical charge from physical footprints or sums
// overlapping snapshot counters. Failure resets all output; allowance is shared.
[[nodiscard]] bool TryObserveAppleSnapshotAllocationCountersReadOnly(
    const RandomAccessSource& source, const VerificationScope& scope,
    std::optional<ApfsSnapshotAllocationCounters>& out, std::string& error,
    const std::function<bool()>& within_deadline = {});

struct ApfsMarkedFileExtentRecordView
{
    std::uint64_t view_xid = 0;
    std::string snapshot_name_utf8; // Empty only for the current view.
    bool current = false;
    std::uint64_t marked_regular_inode_count = 0, want_only_regular_inode_count = 0;
    ApfsSpaceAmount referenced_physical;
};

// A canonical record-subset observation, not a volume verification result.
// Measures the union of non-hole FILE_EXTENT records whose stream is referenced
// by a regular-file inode with INODE_IS_PURGEABLE. WANT alone is not a mark.
// Includes physical record padding and shared ranges once. Excludes metadata,
// attribute-only streams and policy charges. It does not certify namespace,
// logical stream completeness, allocation-bit/orphan coverage or deletion savings.
struct ApfsMarkedFileExtentRecordsObservation
{
    std::string source_identity;
    ApfsSnapshotScope scope;
    std::uint32_t allocation_unit_bytes = 0;
    std::vector<ApfsMarkedFileExtentRecordView> views; // Snapshots by XID; current last.
    ApfsSpaceAmount referenced_physical_union;
    std::optional<ApfsSpaceAmount> apple_purgeable, reclaimable, snapshot_allocation_charge;
    bool complete = false;
    std::shared_ptr<ApfsReadBudget> read_budget;
};

// Exact latest ordinary single-store source/window/volume/checkpoint. Uses the
// canonical catalog and chronological signed reference graphs, under one sticky
// allowance and final dependency-byte revalidation. The caller holds the source;
// its identity label/file kind is not authenticated by this byte API. Unknown
// inode flags/xfields, record kinds or graph history refuse the entire subset.
// Existing verifier/attribution admission, result layouts and wire stay unchanged.
[[nodiscard]] bool TryObserveAppleMarkedFileExtentRecords(
    const RandomAccessSource& source, const VerificationScope& scope,
    std::optional<ApfsMarkedFileExtentRecordsObservation>& out, std::string& error,
    const std::function<bool()>& within_deadline = {});

// Stronger, separate observational subset: all selected current/snapshot
// namespaces and directory7 target relations are validated, and their canonical
// catalog metadata/payload references are allocated and nonqueued. Directory7
// names remain opaque. The existing literal FILE_EXTENT measure is retained;
// the separate marked-file payload includes canonically owned external xattrs.
// No hidden-owner census, retirement or OS policy.
// Existing result layouts and ordinary/default mutation admission stay exact.
struct ApfsMarkedFilePayloadView
{
    ApfsSpaceAmount referenced_physical;
    std::vector<VerificationBlockRange> ranges; // Same view order as records.
};
struct ApfsMarkedReferenceSpaceObservation
{
    ApfsMarkedFileExtentRecordsObservation records;
    bool namespace_and_directory7_references_verified = false;
    bool catalog_metadata_and_payload_allocation_verified = false;
    std::vector<ApfsMarkedFilePayloadView> marked_file_payload;
    ApfsSpaceAmount marked_file_payload_union;
};
[[nodiscard]] bool TryObserveAppleMarkedReferenceSpaceReadOnly(
    const RandomAccessSource& source, const VerificationScope& scope,
    std::optional<ApfsMarkedReferenceSpaceObservation>& out, std::string& error,
    const std::function<bool()>& within_deadline = {});

// Separate all-owner accounting; the v1 marked record result/layout is unchanged.
// Same-view unmarked clones remain owners even when their physical ranges equal
// marked ranges. Retained protection covers only the explicitly requested chain.
struct ApfsMarkedOwnerView
{
    std::vector<VerificationBlockRange> metadata_ranges, payload_ranges, unmarked_payload_ranges;
    ApfsSnapshotAttributionAmounts metadata, marked_payload;
    ApfsSpaceAmount shared_with_unmarked_in_view;
};
struct ApfsMarkedOwnerSpaceAttribution
{
    ApfsMarkedReferenceSpaceObservation marked;
    std::optional<std::uint64_t> from_xid;
    std::vector<std::uint64_t> checkpoint_xids;
    std::vector<VerificationBlockRange> protected_metadata, protected_payload;
    std::vector<VerificationBlockRange> catalog_metadata_ranges;
    std::vector<ApfsMarkedOwnerView> views; // Marked view order, current last.
    ApfsSpaceAmount visible_metadata_union, visible_payload_union;
    ApfsSpaceAmount catalog_metadata;
    bool explicit_owner_graphs_verified = false;
};
// Pure bounded consistency check, creates no source or completeness authority.
[[nodiscard]] bool ValidateAppleMarkedOwnerSpaceAmounts(const ApfsMarkedOwnerSpaceAttribution& result,
    const std::function<bool()>& within_deadline, std::string& error);
[[nodiscard]] bool TryAttributeAppleMarkedOwnerSpaceReadOnly(
    const RandomAccessSource& source, const VerificationScope& scope, std::optional<std::uint64_t> from_xid,
    std::optional<ApfsMarkedOwnerSpaceAttribution>& out, std::string& error,
    const std::function<bool()>& within_deadline = {});
}
