#include "ApfsSnapshotStore.h"
#include "ApfsTransactionWriter.h"
#include "ApfsReadOnlyMetadataAdmission.h"

#include <algorithm>
#include <stdexcept>
#include <tuple>

namespace apfsaccess::catalog
{
bool ApfsSnapshotScope::operator==(const ApfsSnapshotScope& other) const
{
    return std::tie(store_offset_bytes, store_size_bytes, container_uuid_hex,
        volume_uuid_hex, volume_oid, checkpoint_xid) ==
        std::tie(other.store_offset_bytes, other.store_size_bytes, other.container_uuid_hex,
            other.volume_uuid_hex, other.volume_oid, other.checkpoint_xid);
}

bool ApfsSnapshotIdentity::operator==(const ApfsSnapshotIdentity& other) const
{
    return std::tie(scope, snapshot_xid, name_utf8, superblock_physical_block,
        omap_physical_block, omap_tree_physical_block, root_oid,
        root_physical_block, extentref_physical_block) ==
        std::tie(other.scope, other.snapshot_xid, other.name_utf8, other.superblock_physical_block,
            other.omap_physical_block, other.omap_tree_physical_block, other.root_oid,
            other.root_physical_block, other.extentref_physical_block);
}

namespace
{
bool UuidValid(const std::string& uuid)
{
    return uuid.size() == 32 && uuid != std::string(32, '0') &&
        std::all_of(uuid.begin(), uuid.end(), [](char c) {
            return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        });
}
}

static bool EnumerateRecords(const RandomAccessSource& source,
    const ApfsSnapshotScope& scope, std::vector<ApfsSnapshotInfo>& out_snapshots,
    std::string& out_error, std::uint64_t selected_xid = 0,
    ApfsSnapshotRecords* selected_records = nullptr,
    AppleSnapshotCatalogRecords* owned_catalog = nullptr)
{
    out_snapshots.clear();
    out_error.clear();
    if (!UuidValid(scope.container_uuid_hex) || !UuidValid(scope.volume_uuid_hex) ||
        scope.volume_oid == 0 || scope.checkpoint_xid == 0 || scope.store_size_bytes == 0 ||
        scope.store_offset_bytes > source.SizeBytes() ||
        scope.store_size_bytes > source.SizeBytes() - scope.store_offset_bytes)
    {
        out_error = "SnapshotScopeInvalid";
        return false;
    }
    // One bounded allowance shared by checkpoint, OMAP, snapshot and FS walks.
    // Preserve any stricter caller-owned allowance and its sticky failure.
    auto budget = source.ReadBudget();
    if (!budget) budget = std::make_shared<ApfsReadBudget>(65536, 256ull * 1024 * 1024,
        1000000, 256ull * 1024 * 1024);
    BudgetedRandomAccessSource bounded(source, budget);
    OffsetRandomAccessSource store(&bounded, scope.store_offset_bytes, scope.store_size_bytes);
    auto checkpoint = LoadAppleCheckpointView(store, 0, store.SizeBytes(), out_error,
        scope.checkpoint_xid);
    if (!checkpoint) return false;
    if (checkpoint->container.superblock.uuid_hex != scope.container_uuid_hex ||
        checkpoint->container.superblock.xid != scope.checkpoint_xid)
    {
        out_error = "SnapshotContainerIdentityMismatch";
        return false;
    }
    const AppleVolumeCheckpointView* selected = nullptr;
    unsigned uuid_matches = 0;
    for (const auto& volume : checkpoint->volumes)
    {
        if (volume.superblock.uuid_hex == scope.volume_uuid_hex) ++uuid_matches;
        if (volume.superblock.object_id == scope.volume_oid) selected = &volume;
    }
    if (!selected || selected->superblock.uuid_hex != scope.volume_uuid_hex || uuid_matches != 1)
    {
        out_error = "SnapshotVolumeIdentityMismatchOrAmbiguous";
        return false;
    }
    std::vector<AppleSnapshotRecord> raw;
    AppleSnapshotTreeRecords trees;
    AppleSnapshotCatalogRecords catalog;
    const bool physical_metadata = selected->snapshot_metadata_tree &&
        selected->superblock.snap_meta_tree_type == (kObjectPhysical | kObjectTypeBtree) &&
        selected->snapshot_metadata_tree->type == selected->superblock.snap_meta_tree_type &&
        selected->snapshot_metadata_tree->subtype == kObjectTypeSnapMetaTree &&
        selected->snapshot_metadata_tree->object_id == selected->superblock.snap_meta_tree_oid &&
        selected->snapshot_metadata_tree->physical_block == selected->superblock.snap_meta_tree_oid;
    if (owned_catalog || physical_metadata)
    {
        if (!(physical_metadata ?
                LoadAppleReadOnlySnapshotCatalog(store, *checkpoint, scope.volume_oid, catalog, out_error) :
                LoadAppleSnapshotCatalog(store, *checkpoint, scope.volume_oid, catalog, out_error))) return false;
        if (selected_xid) {
            const auto found = std::find_if(catalog.inventory.begin(), catalog.inventory.end(),
                [&](const auto& snapshot) { return snapshot.xid == selected_xid; });
            if (found != catalog.inventory.end()) trees = std::move(catalog.snapshots.at(found - catalog.inventory.begin()));
        }
        raw = std::move(catalog.inventory);
    }
    else if (!LoadAppleSnapshotRecords(store, *checkpoint, scope.volume_oid, raw,
        out_error, selected_xid, trees)) return false;
    std::vector<ApfsSnapshotInfo> result;
    for (auto& snapshot : raw)
    {
        if (!budget->Materialize(1, sizeof(ApfsSnapshotInfo) + snapshot.name_utf8.size()))
        {
            out_error = budget->Failure();
            return false;
        }
        ApfsSnapshotInfo item;
        auto& id = item.identity;
        id.scope = scope;
        id.snapshot_xid = snapshot.xid;
        id.name_utf8 = snapshot.name_utf8;
        id.superblock_physical_block = snapshot.volume.superblock_object.physical_block;
        id.omap_physical_block = snapshot.volume.object_map.object.physical_block;
        id.omap_tree_physical_block = snapshot.volume.object_map.tree.physical_block;
        id.root_oid = snapshot.volume.root_tree.object_id;
        id.root_physical_block = snapshot.volume.root_tree.physical_block;
        id.extentref_physical_block = snapshot.volume.extentref_tree->physical_block;
        item.metadata = std::move(snapshot);
        result.push_back(std::move(item));
    }
    out_snapshots = std::move(result);
    if (selected_records)
    {
        selected_records->checkpoint = std::move(*checkpoint);
        selected_records->trees = std::move(trees);
    }
    if (owned_catalog) *owned_catalog = std::move(catalog);
    return true;
}

bool ApfsSnapshotStore::Enumerate(const RandomAccessSource& source,
    const ApfsSnapshotScope& scope, std::vector<ApfsSnapshotInfo>& out_snapshots,
    std::string& out_error)
{
    return EnumerateRecords(source, scope, out_snapshots, out_error);
}

bool ApfsSnapshotStore::LoadExactRecords(const RandomAccessSource& source,
    const ApfsSnapshotIdentity& expected, ApfsSnapshotRecords& out_records,
    std::string& out_error)
{
    bool complete = false;
    struct ClearOnFailure
    {
        ApfsSnapshotRecords& records;
        const bool& complete;
        ~ClearOnFailure() { if (!complete) records = {}; }
    } clear{out_records, complete};
    try
    {
        const auto identity = expected; // supports expected aliasing the output
        out_records = {};
        ApfsSnapshotRecords result;
        std::vector<ApfsSnapshotInfo> snapshots;
        if (!EnumerateRecords(source, identity.scope, snapshots, out_error,
            identity.snapshot_xid, &result)) return false;
        const auto found = std::find_if(snapshots.begin(), snapshots.end(), [&](const auto& item) {
            return item.identity == identity;
        });
        if (found == snapshots.end())
        {
            out_error = "SnapshotExactIdentityMismatchOrMissing";
            return false;
        }
        result.snapshot = std::move(*found);
        out_records = std::move(result);
        complete = true;
        return true;
    }
    catch (const std::bad_alloc&)
    {
        if (const auto budget = source.ReadBudget()) (void)budget->Refuse("ApfsReadBudgetAllocationFailed");
        out_error = "ApfsReadBudgetAllocationFailed";
        return false;
    }
    catch (const std::length_error&)
    {
        if (const auto budget = source.ReadBudget()) (void)budget->Refuse("ApfsReadBudgetAllocationFailed");
        out_error = "ApfsReadBudgetAllocationFailed";
        return false;
    }
}

bool ApfsSnapshotStore::LoadExactProjectionRecords(const RandomAccessSource& source,
    const ApfsSnapshotIdentity& expected, ApfsSnapshotRecords& out_records,
    std::vector<rw::ApplePhysicalExtentRecord>& out_geometry, std::string& out_error)
{
    const auto identity = expected;
    out_records = {}; out_geometry.clear(); out_error.clear();
    auto budget = source.ReadBudget();
    if (!budget) budget = std::make_shared<ApfsReadBudget>(65536, 256ull << 20, 1000000, 256ull << 20);
    BudgetedRandomAccessSource bounded(source, budget);
    try {
        std::vector<ApfsSnapshotInfo> inventory;
        ApfsSnapshotRecords raw;
        AppleSnapshotCatalogRecords catalog;
        if (!EnumerateRecords(bounded, identity.scope, inventory, out_error, 0, &raw, &catalog)) return false;
        const auto exact = std::find_if(inventory.begin(), inventory.end(),
            [&](const auto& item) {return item.identity == identity;});
        if (exact == inventory.end()) {
            out_error = "SnapshotExactIdentityMismatchOrMissing"; return false;
        }
        if (catalog.snapshots.size() != inventory.size()) {
            out_error = "SnapshotInventoryCountMismatch"; return false;
        }
        std::vector<rw::ApplePhysicalExtentRecord> prior, historical;
        for (std::size_t i = 0; i < inventory.size(); ++i) {
            auto& item = inventory[i];
            if (item.identity.snapshot_xid > identity.snapshot_xid) break;
            auto& trees = catalog.snapshots[i];
            const auto& nx = raw.checkpoint.container.superblock;
            // Charge the interval sweep, its normalized records, validation and
            // accumulated ownership. No payload bytes or per-block expansion.
            const auto count = prior.size() + historical.size() + trees.filesystem.size() + trees.extentref.size();
            if (!budget->Materialize(count, count * 2048ull)) {out_error=budget->Failure();return false;}
            std::vector<rw::ApplePhysicalExtentRecord> resolved;
            if (!rw::ResolveAppleSnapshotExtentLayer(prior, historical, trees.filesystem,
                trees.extentref, nx.block_size, nx.block_count, resolved, out_error)) return false;
            if (item.identity == identity) {
                raw.snapshot = std::move(item);
                raw.trees = std::move(trees);
                raw.trees.metadata_blocks = std::move(catalog.metadata_blocks);
                out_geometry=std::move(resolved);
                out_records=std::move(raw);return true;
            }
            historical.insert(historical.end(), resolved.begin(), resolved.end());
            prior=std::move(resolved);
        }
        out_error="SnapshotExactIdentityMismatchOrMissing";return false;
    } catch (const std::bad_alloc&) {
        (void)budget->Refuse("ApfsReadBudgetAllocationFailed");out_error=budget->Failure();return false;
    } catch (const std::length_error&) {
        (void)budget->Refuse("ApfsReadBudgetAllocationFailed");out_error=budget->Failure();return false;
    }
}

bool ApfsSnapshotStore::LoadExactResolvedRecords(const RandomAccessSource& source,
    const ApfsSnapshotIdentity& expected, ApfsSnapshotRecords& out_records, std::string& out_error) {
    const auto identity=expected;
    out_records={};
    ApfsSnapshotRecords records;
    std::vector<rw::ApplePhysicalExtentRecord> geometry;
    if (!LoadExactProjectionRecords(source,identity,records,geometry,out_error)) return false;
    try {
        records.trees.extentref.clear();
        for (const auto& extent : geometry) {
            BtreeRecord encoded;
            if (!rw::EncodeApplePhysicalExtentRecord(extent,encoded,out_error)) return false;
            records.trees.extentref.push_back(std::move(encoded));
        }
        out_records=std::move(records);return true;
    } catch (const std::bad_alloc&) {
        if (const auto budget=source.ReadBudget()) (void)budget->Refuse("ApfsReadBudgetAllocationFailed");
        out_error="ApfsReadBudgetAllocationFailed";return false;
    } catch (const std::length_error&) {
        if (const auto budget=source.ReadBudget()) (void)budget->Refuse("ApfsReadBudgetAllocationFailed");
        out_error="ApfsReadBudgetAllocationFailed";return false;
    }
}

bool ApfsSnapshotStore::ValidateExact(const RandomAccessSource& source,
    const ApfsSnapshotIdentity& expected, ApfsSnapshotInfo& out_snapshot, std::string& out_error)
{
    // expected may refer to out_snapshot.identity in an in-place revalidation.
    const auto expected_identity = expected;
    out_snapshot = {};
    std::vector<ApfsSnapshotInfo> snapshots;
    if (!Enumerate(source, expected_identity.scope, snapshots, out_error)) return false;
    const auto found = std::find_if(snapshots.begin(), snapshots.end(), [&](const auto& item) {
        return item.identity == expected_identity;
    });
    if (found == snapshots.end())
    {
        out_error = "SnapshotExactIdentityMismatchOrMissing";
        return false;
    }
    out_snapshot = std::move(*found);
    return true;
}
} // namespace apfsaccess::catalog
