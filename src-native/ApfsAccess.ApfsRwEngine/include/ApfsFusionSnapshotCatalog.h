#pragma once

#include "ApfsFusionStore.h"

namespace apfsaccess::catalog
{
// Canonical read-only catalog at one exact held Fusion checkpoint. This parses
// all selected-volume snapshots; it grants no mutation/release authority and
// does not certify allocator ownership or policy charges. Failure is atomic.
[[nodiscard]] bool LoadAppleFusionReadOnlySnapshotCatalog(
    const ApfsFusionStore& source, std::uint64_t exact_checkpoint_xid,
    std::uint64_t volume_oid, const std::string& volume_uuid_hex,
    AppleSnapshotCatalogRecords& output,
    std::vector<AppleSnapshotMetadataClaim>& owners, std::string& error);
}
