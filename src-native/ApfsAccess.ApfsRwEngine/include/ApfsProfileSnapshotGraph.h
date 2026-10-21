#pragma once

#include "ApfsProfileHistory.h"
#include "ApfsSharedSpace.h"

namespace apfsaccess::catalog
{
struct ProfileSnapshotViewGraph
{
    std::uint64_t volume_oid = 0, view_xid = 0;
    bool current = false;
    std::string name_utf8;
    AppleObjectLocation descriptor;
    // Parsed apfs_fs_alloc_count in this exact checked descriptor. The descriptor
    // may have been COW'd after view_xid. This is neither a per-snapshot charge
    // nor deletion savings, and must not be summed across shared snapshots.
    ApfsSpaceAmount declared_filesystem_allocation;
    std::uint64_t filesystem_record_count = 0;
    // Exact selected-view APSB/OMAP/FS/extentref dependencies. Container and
    // shared catalog scaffolding remains in the checkpoint protected union.
    std::vector<VerificationBlockRange> metadata_ranges, payload_ranges;
};

struct ProfileSnapshotCheckpointGraph
{
    RetainedProfileCheckpointGraph protected_graph;
    // All peers; increasing volume OID, snapshots by XID, current last.
    std::vector<ProfileSnapshotViewGraph> views;
};

// A separate finite visible-inventory graph proof. Never encode as current or
// retained v1, and never claim exhaustive hidden-OMAP/orphan completeness.
// Failure clears selected/stores/chain/checkpoints atomically. Scalar policy
// amounts remain unknown even when every requested visible graph is complete.
struct ProfileSnapshotGraphReport
{
    CurrentVerificationProfile profile = CurrentVerificationProfile::FusionCleanCache;
    VerificationScope endpoint_scope;
    std::optional<std::uint64_t> from_xid;
    VerificationOutcome outcome = VerificationOutcome::Incomplete;
    std::optional<VerifiedCheckpointIdentity> selected;
    std::vector<VerificationStoreBinding> stores;
    std::uint32_t allocation_unit_bytes = 0;
    std::vector<std::uint64_t> chain_xids;
    std::vector<ProfileSnapshotCheckpointGraph> checkpoints;
    std::vector<VerificationFinding> findings;
    std::uint64_t source_reads = 0, source_read_bytes = 0;
    std::shared_ptr<ApfsReadBudget> read_budget;
    std::optional<std::uint64_t> snapshot_allocation_charge_bytes, apple_purgeable_bytes, reclaimable_bytes;
};

[[nodiscard]] ProfileSnapshotGraphReport VerifyFusionSnapshotProfile(
    const ApfsFusionStore& source, const VerificationScope& endpoint_scope,
    const std::array<std::string, 2>& member_store_ids,
    std::optional<std::uint64_t> from_xid, const std::function<bool()>& within_deadline);

[[nodiscard]] ProfileSnapshotGraphReport VerifyEncryptedSnapshotProfile(
    const ApfsVerifierEncryptedSource& source, ApfsEncryptedReadSession& session,
    const VerificationScope& endpoint_scope, std::optional<std::uint64_t> from_xid,
    const std::function<bool()>& within_deadline);
}
