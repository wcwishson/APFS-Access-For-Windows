#pragma once

#include "ApfsFormat.h"

namespace apfsaccess::catalog
{
// All fields are exact. UUIDs are the existing opaque 32-lowercase-hex format.
// A caller must hold a stable source for the complete operation. No latest-XID
// fallback, name normalization, proximity scan, or implicit volume selection.
struct ApfsSnapshotScope
{
    std::uint64_t store_offset_bytes = 0;
    std::uint64_t store_size_bytes = 0;
    std::string container_uuid_hex;
    std::string volume_uuid_hex;
    std::uint64_t volume_oid = 0;
    std::uint64_t checkpoint_xid = 0;
    bool operator==(const ApfsSnapshotScope& other) const;
};

struct ApfsSnapshotIdentity
{
    ApfsSnapshotScope scope;
    std::uint64_t snapshot_xid = 0;
    std::string name_utf8;
    std::uint64_t superblock_physical_block = 0;
    std::uint64_t omap_physical_block = 0;
    std::uint64_t omap_tree_physical_block = 0;
    std::uint64_t root_oid = 0;
    std::uint64_t root_physical_block = 0;
    std::uint64_t extentref_physical_block = 0;
    bool operator==(const ApfsSnapshotIdentity& other) const;
};

struct ApfsSnapshotInfo
{
    ApfsSnapshotIdentity identity;
    // No UUID exists in the base metadata/name records. Extended metadata is
    // refused explicitly in this slice, so this optional remains disengaged.
    std::optional<std::string> snapshot_uuid_hex;
    AppleSnapshotRecord metadata;
};

// A read-only, exact record bundle. Addresses remain relative to scope's store.
struct ApfsSnapshotRecords
{
    ApfsSnapshotInfo snapshot;
    AppleCheckpointView checkpoint;
    AppleSnapshotTreeRecords trees;
};

class ApfsSnapshotStore final
{
public:
    // All-or-nothing inventory, ordered by snapshot XID. Empty success means a
    // valid, empty metadata tree and consistent zero APSB/OMAP counts.
    static bool Enumerate(const RandomAccessSource& source, const ApfsSnapshotScope& scope,
        std::vector<ApfsSnapshotInfo>& out_snapshots, std::string& out_error);

    // Revalidates all identity fields and returns the selected historical trees
    // captured during that same walk. Preserves source.ReadBudget(); no retry.
    static bool LoadExactRecords(const RandomAccessSource& source,
        const ApfsSnapshotIdentity& expected, ApfsSnapshotRecords& out_records,
        std::string& out_error);

    // Re-reads authoritative bytes; never treats a cached descriptor as proof.
    // Mismatched XID/name/root identity fails, without selecting another view.
    static bool ValidateExact(const RandomAccessSource& source,
        const ApfsSnapshotIdentity& expected, ApfsSnapshotInfo& out_snapshot,
        std::string& out_error);
};
} // namespace apfsaccess::catalog
