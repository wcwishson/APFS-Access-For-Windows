#pragma once

#include "ApfsVerifier.h"

namespace apfsaccess::catalog
{
// Explicit requested checkpoint chain, not exhaustive hidden OMAP/snapshot or
// orphan accounting. The graph ranges include every peer's selected APSB,
// OMAP and filesystem/extentref tree, plus canonical current payload records.
// Each range remains allocated at every later complete checkpoint. Retirement
// entries at/before its owning XID refuse; later entries must persist at the
// same XID. Internal-pool rotation follows the canonical recovery proof.
// No mutation/release authority is granted.
struct RetainedProfileCheckpointGraph
{
    std::uint64_t checkpoint_xid = 0;
    std::vector<VerificationBlockRange> metadata_ranges, payload_ranges;
};

struct RetainedProfileHistoryReport
{
    CurrentVerificationProfile profile = CurrentVerificationProfile::FusionCleanCache;
    VerificationScope endpoint_scope;
    std::uint64_t from_xid = 0;
    VerificationOutcome outcome = VerificationOutcome::Incomplete;
    std::vector<VerificationStoreBinding> stores;
    // Both remain empty on any failure; the latest endpoint is included.
    std::vector<std::uint64_t> chain_xids;
    std::vector<RetainedProfileCheckpointGraph> checkpoints;
    std::vector<VerificationFinding> findings;
    std::optional<VerifiedCheckpointIdentity> selected;
    std::uint32_t allocation_unit_bytes = 0;
    // True only after every requested checkpoint's canonical namespace and
    // physical protection proof completes. Empty on any failure.
    std::optional<bool> historical_namespace_verified;
    std::uint64_t source_reads = 0, source_read_bytes = 0;
    std::shared_ptr<ApfsReadBudget> read_budget;
    std::optional<std::uint64_t> snapshot_allocation_charge_bytes, apple_purgeable_bytes, reclaimable_bytes;
};

// Exact held latest Fusion binding and explicit 0 < from_xid < endpoint XID.
// Reuses canonical descriptor, peer graph and two-device allocator parsers.
// Shared cumulative budget/deadline; ordinary APIs and current v1 wire remain
// unchanged. Unsupported snapshots/history/advanced allocator generations
// refuse rather than replacing a historical bitmap with the current bitmap.
[[nodiscard]] RetainedProfileHistoryReport VerifyFusionRetainedHistory(
    const ApfsFusionStore& source, const VerificationScope& endpoint_scope,
    const std::array<std::string, 2>& member_store_ids, std::uint64_t from_xid,
    const std::function<bool()>& within_deadline);

// Same finite graph/physical protection proof, with each earlier generation
// independently admitted by the session's canonical same-VEK keybag-era mint.
// Historical namespace uses the same canonical session projector. This remains
// a finite proof: no snapshot/hidden-target/orphan accounting is supplied.
[[nodiscard]] RetainedProfileHistoryReport VerifyEncryptedRetainedHistory(
    const ApfsVerifierEncryptedSource& source, ApfsEncryptedReadSession& session,
    const VerificationScope& endpoint_scope, std::uint64_t from_xid,
    const std::function<bool()>& within_deadline);
}
