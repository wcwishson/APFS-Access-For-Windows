#pragma once

#include "AppleTransactionCommit.h"

namespace apfsaccess::rw
{
// Explicit observational proof. Reuses the canonical retention graph and all
// allocator/queue continuity checks, with read-only inactive-tree admission.
// Cache entries are policy-separated from strict mutation proofs. These results
// grant no publication, pin-retirement, reclaimability or write authority.
[[nodiscard]] bool LoadAppleReadOnlySnapshotRetention(const catalog::RandomAccessSource& source,
    const catalog::AppleCheckpointView& checkpoint,
    AppleSnapshotRetentionView& out_retention, std::string& out_error);
[[nodiscard]] bool LoadAppleReadOnlySnapshotCheckpointOwners(const catalog::RandomAccessSource& source,
    const catalog::AppleCheckpointView& checkpoint, std::vector<std::uint64_t>& metadata,
    std::vector<ApplePhysicalExtentRecord>& payload, std::string& error);
[[nodiscard]] bool LoadAppleReadOnlySnapshotRecoveryCheckpoints(const catalog::RandomAccessSource& source,
    const catalog::AppleCheckpointView& checkpoint,
    const std::vector<std::uint64_t>& required_checkpoint_xids,
    std::vector<AppleRecoveryCheckpointView>& out_checkpoints, std::string& out_error);
}
