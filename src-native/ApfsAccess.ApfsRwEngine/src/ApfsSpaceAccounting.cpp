#include "ApfsSpaceAccounting.h"
#include "ApfsProfileSnapshotGraph.h"
#include "ApfsFusionStore.h"

#include "ApfsTransactionWriter.h"
#include "ApfsExtendedRecordCodec.h"
#include "AppleReadOnlyRecordGraph.h"
#include "AppleTransactionCommit.h"
#include "AppleReadOnlyRetention.h"
#include "ApfsReadOnlyMetadataAdmission.h"
#include "SnapshotPlanningSource.h"
#include "NativeApfsReader.h"
#include "ProfileRetentionContinuity.h"

#include <algorithm>
#include <limits>
#include <stdexcept>
#include <unordered_set>

namespace apfsaccess::catalog
{
namespace
{
using rw::ApplePhysicalExtentRecord;
struct Range { std::uint64_t begin, end; };

// A checkpoint-ring scan must not turn a failed backing read into success by
// selecting another readable copy. Keep I/O failure sticky through every walk.
class AccountingSource final : public RandomAccessSource
{
public:
    explicit AccountingSource(const RandomAccessSource& source, std::function<bool()> allowed = {})
        : source_(source), allowed_(std::move(allowed)) {}
    std::uint64_t SizeBytes() const override { return source_.SizeBytes(); }
    std::shared_ptr<ApfsReadBudget> ReadBudget() const override { return source_.ReadBudget(); }
    bool Read(std::uint64_t offset, std::size_t size, std::vector<std::byte>& out) const override
    {
        out.clear();
        if (failed || (allowed_ && !allowed_())) { failed = true; return false; }
        if (!source_.Read(offset, size, out) || out.size() != size)
        { failed = true; out.clear(); return false; }
        return true;
    }
    mutable bool failed = false;
private:
    const RandomAccessSource& source_;
    std::function<bool()> allowed_;
};

bool Charge(const std::shared_ptr<ApfsReadBudget>& budget, std::uint64_t count,
    std::uint64_t unit, std::string& error)
{
    if (unit && count > (std::numeric_limits<std::uint64_t>::max)() / unit)
        (void)budget->Refuse("SnapshotSpaceWorkOverflow");
    else if (budget->Materialize(count, count * unit)) return true;
    error = budget->Failure();
    return false;
}

bool Union(const std::vector<ApplePhysicalExtentRecord>& extents,
    std::uint64_t container_blocks, const std::shared_ptr<ApfsReadBudget>& budget,
    std::vector<Range>& ranges, std::string& error)
{
    if (!Charge(budget, extents.size(), sizeof(Range), error)) return false;
    ranges.reserve(extents.size());
    for (const auto& extent : extents)
    {
        if (!extent.block_count || extent.physical_block >= container_blocks ||
            extent.block_count > container_blocks - extent.physical_block ||
            extent.kind != rw::kApplePhysicalExtentKindNew || extent.reference_count <= 0)
        { error = "SnapshotSpaceResolvedExtentInvalid"; return false; }
        ranges.push_back({extent.physical_block, extent.physical_block + extent.block_count});
    }
    std::sort(ranges.begin(), ranges.end(), [](const auto& a, const auto& b) {
        return a.begin < b.begin || (a.begin == b.begin && a.end < b.end);
    });
    std::size_t size = 0;
    for (const auto range : ranges)
    {
        if (size && range.begin <= ranges[size - 1].end)
            ranges[size - 1].end = (std::max)(ranges[size - 1].end, range.end);
        else ranges[size++] = range;
    }
    ranges.resize(size);
    return true;
}

bool Amount(std::uint64_t blocks, std::uint32_t block_size, ApfsSpaceAmount& out,
    std::string& error)
{
    if (!block_size || blocks > (std::numeric_limits<std::uint64_t>::max)() / block_size)
    { error = "SnapshotSpaceByteOverflow"; return false; }
    out = {blocks, blocks * block_size};
    return true;
}
}

bool TryObserveAppleSnapshotPayloadSpace(const RandomAccessSource& source,
    const VerificationScope& scope, std::optional<ApfsSnapshotPayloadSpaceObservation>& out,
    std::string& error)
{
    out.reset();
    error.clear();
    if (scope.require_whole_volume || scope.require_payload_content_hashes || scope.observe_payload_content)
    { error = "SnapshotSpaceScopeUnsupported"; return false; }
    auto budget = source.ReadBudget();
    try
    {
        if (!budget) budget = std::make_shared<ApfsReadBudget>(scope.max_reads,
            scope.max_read_bytes, scope.max_records, scope.max_record_bytes);
        else budget->LimitRemainingTo(scope.max_reads, scope.max_read_bytes,
            scope.max_records, scope.max_record_bytes);
        BudgetedRandomAccessSource allowance(source, budget);
        AccountingSource bounded(allowance);
        const auto verified = ApfsVerifier::Verify(bounded, scope);
        if (verified.outcome != VerificationOutcome::Complete || !verified.selected ||
            !verified.allocation_census)
        {
            error = budget->Failed() ? budget->Failure() : "SnapshotSpaceVerificationIncomplete";
            if (!budget->Failed() && !verified.findings.empty())
                error += ":" + verified.findings.front().detail;
            return false;
        }
        const auto& exact = scope.exact;
        OffsetRandomAccessSource store(&bounded, exact.store_offset_bytes, exact.store_size_bytes);
        const auto checkpoint = LoadAppleCheckpointView(store, 0, store.SizeBytes(), error, exact.checkpoint_xid);
        if (!checkpoint) return false;
        const auto& nx = checkpoint->container.superblock;
        if (checkpoint->volumes.size() != 1)
        { error = "SnapshotSpaceMultipleVolumesUnsupported"; return false; }
        const auto& volume = checkpoint->volumes.front();
        if (nx.uuid_hex != exact.container_uuid_hex || nx.xid != exact.checkpoint_xid ||
            volume.superblock.object_id != exact.volume_oid || volume.superblock.uuid_hex != exact.volume_uuid_hex ||
            store.SizeBytes() % nx.block_size || store.SizeBytes() / nx.block_size != nx.block_count ||
            exact.store_offset_bytes % nx.block_size)
        { error = "SnapshotSpaceIdentityOrGeometryMismatch"; return false; }

        AppleSnapshotCatalogRecords catalog;
        if (!LoadAppleSnapshotCatalog(store, *checkpoint, exact.volume_oid, catalog, error)) return false;
        if (catalog.inventory.size() != catalog.snapshots.size())
        { error = "SnapshotSpaceInventoryCountMismatch"; return false; }
        std::vector<ApplePhysicalExtentRecord> prior, history, live;
        // Resolve chronological layers before counting physical reachability.
        // Signed UPDATE counts and clone refcounts are never space amounts.
        const auto resolve = [&](const AppleSnapshotTreeRecords& trees,
            std::vector<ApplePhysicalExtentRecord>& resolved) {
            for (const auto count : {prior.size(), history.size(), trees.filesystem.size(), trees.extentref.size()})
                if (!Charge(budget, count, 2048, error)) return false;
            return rw::ResolveAppleSnapshotExtentLayer(prior, history, trees.filesystem,
                trees.extentref, nx.block_size, nx.block_count, resolved, error);
        };
        for (const auto& trees : catalog.snapshots)
        {
            std::vector<ApplePhysicalExtentRecord> resolved;
            if (!resolve(trees, resolved) || !Charge(budget, resolved.size(), sizeof(ApplePhysicalExtentRecord), error))
                return false;
            history.insert(history.end(), resolved.begin(), resolved.end());
            prior = std::move(resolved);
        }
        if (!resolve(catalog.live, live)) return false;
        std::vector<Range> snapshots, current;
        if (!Union(history, nx.block_count, budget, snapshots, error) ||
            !Union(live, nx.block_count, budget, current, error)) return false;
        std::uint64_t referenced = 0, shared = 0;
        for (const auto range : snapshots) referenced += range.end - range.begin;
        std::size_t i = 0, j = 0;
        while (i < snapshots.size() && j < current.size())
        {
            const auto begin = (std::max)(snapshots[i].begin, current[j].begin);
            const auto end = (std::min)(snapshots[i].end, current[j].end);
            if (end > begin) shared += end - begin;
            if (snapshots[i].end < current[j].end) ++i;
            else ++j;
        }
        if (!Charge(budget, 1, sizeof(ApfsSnapshotPayloadSpaceObservation) + scope.source_identity.size() +
            exact.container_uuid_hex.size() + exact.volume_uuid_hex.size(), error)) return false;
        ApfsSnapshotPayloadSpaceObservation result;
        result.source_identity = scope.source_identity;
        result.scope = exact;
        result.allocation_unit_bytes = nx.block_size;
        result.snapshot_count = catalog.inventory.size();
        if (!Amount(referenced, nx.block_size, result.referenced_payload, error) ||
            !Amount(shared, nx.block_size, result.shared_with_live_payload, error) ||
            !Amount(referenced - shared, nx.block_size, result.absent_from_live_payload, error)) return false;
        if (bounded.failed || budget->Failed())
        { error = budget->Failed() ? budget->Failure() : "SnapshotSpaceSourceReadFailed"; return false; }
        out = std::move(result);
        return true;
    }
    catch (const std::bad_alloc&)
    {
        if (budget) (void)budget->Refuse("ApfsReadBudgetAllocationFailed");
        error = "ApfsReadBudgetAllocationFailed";
    }
    catch (const std::length_error&)
    {
        if (budget) (void)budget->Refuse("ApfsReadBudgetAllocationFailed");
        error = "ApfsReadBudgetAllocationFailed";
    }
    catch (const std::exception&) { error = "SnapshotSpaceSourceException"; }
    return false;
}

namespace
{
struct AttributionWork
{
    std::shared_ptr<ApfsReadBudget> budget;
    const std::function<bool()>& deadline;
    std::string& error;
    bool Tick()
    {
        if (deadline && !deadline()) (void)budget->Refuse("SnapshotAttributionDeadline");
        if (!budget->Failed()) return true;
        error = budget->Failure(); return false;
    }
    bool Take(std::uint64_t count, std::uint64_t unit)
    { return Tick() && Charge(budget, count, unit, error); }
    bool Normalize(std::vector<Range>& ranges)
    {
        if (!Take(ranges.size(), sizeof(Range))) return false;
        std::sort(ranges.begin(), ranges.end(), [](const auto& a, const auto& b) {
            return a.begin < b.begin || (a.begin == b.begin && a.end < b.end);
        });
        std::size_t used = 0;
        for (const auto range : ranges)
        {
            if (!Tick()) return false;
            if (used && range.begin <= ranges[used - 1].end)
                ranges[used - 1].end = (std::max)(ranges[used - 1].end, range.end);
            else ranges[used++] = range;
        }
        ranges.resize(used); return true;
    }
    bool Append(std::vector<Range>& target, std::uint64_t block, std::uint64_t count, std::uint64_t limit)
    {
        if (!count || block >= limit || count > limit - block)
        { error = "SnapshotAttributionRangeInvalid"; return false; }
        if (!Take(1, sizeof(Range))) return false;
        target.push_back({block, block + count}); return true;
    }
    bool Join(std::vector<Range>& target, const std::vector<Range>& extra)
    {
        if (!Take(extra.size(), sizeof(Range))) return false;
        target.insert(target.end(), extra.begin(), extra.end()); return Normalize(target);
    }
    bool Difference(const std::vector<Range>& left, const std::vector<Range>& right, std::vector<Range>& out)
    {
        std::size_t j = 0;
        for (const auto range : left)
        {
            if (!Tick()) return false;
            auto at = range.begin;
            while (j < right.size() && right[j].end <= at) { if (!Tick()) return false; ++j; }
            for (auto k = j; k < right.size() && right[k].begin < range.end; ++k)
            {
                if (!Tick()) return false;
                if (right[k].begin > at)
                {
                    if (!Take(1, sizeof(Range))) return false;
                    out.push_back({at, right[k].begin});
                }
                at = (std::max)(at, right[k].end);
                if (at >= range.end) break;
            }
            if (at < range.end)
            {
                if (!Take(1, sizeof(Range))) return false;
                out.push_back({at, range.end});
            }
        }
        return true;
    }
    bool Count(const std::vector<Range>& ranges, std::uint32_t bs, ApfsSpaceAmount& out)
    {
        std::uint64_t count = 0;
        for (const auto range : ranges)
        {
            if (!Tick()) return false;
            if (range.end - range.begin > UINT64_MAX - count)
            { error = "SnapshotAttributionCountOverflow"; return false; }
            count += range.end - range.begin;
        }
        return Amount(count, bs, out, error);
    }
    bool Measure(const std::vector<Range>& ranges, const std::vector<Range>& live,
        const std::vector<Range>& other, const std::vector<Range>& external,
        std::uint32_t bs, ApfsSnapshotAttributionAmounts& out)
    {
        std::vector<Range> absent, no_other, visible, unique, candidate, unprotected;
        if (!Difference(ranges, live, absent) || !Difference(ranges, other, no_other) ||
            !Join(visible, live) || !Join(visible, other) || !Difference(ranges, visible, unique) ||
            !Difference(unique, external, candidate) || !Difference(ranges, external, unprotected) ||
            !Count(ranges, bs, out.referenced) || !Count(absent, bs, out.absent_from_live) ||
            !Count(no_other, bs, out.shared_with_other_snapshots) ||
            !Count(unique, bs, out.unique_in_visible_inventory) ||
            !Count(candidate, bs, out.potential_reclaim_upper_bound) ||
            !Count(unprotected, bs, out.retained_or_peer_protected)) return false;
        if (!Amount(out.referenced.blocks - out.absent_from_live.blocks, bs, out.shared_with_live, error) ||
            !Amount(out.referenced.blocks - out.shared_with_other_snapshots.blocks, bs, out.shared_with_other_snapshots, error) ||
            !Amount(out.referenced.blocks - out.retained_or_peer_protected.blocks, bs, out.retained_or_peer_protected, error)) return false;
        return true;
    }
};

struct AttributionView { std::vector<Range> metadata, payload; };

bool AttributionCatalog(const RandomAccessSource& store, const AppleCheckpointView& checkpoint,
    std::uint64_t oid, AttributionWork& work, AppleSnapshotCatalogRecords& catalog,
    std::vector<AttributionView>& snapshots, AttributionView& live, bool read_only,
    const std::function<bool(const AppleSnapshotTreeRecords&)>* marked_records = nullptr,
    std::vector<AppleSnapshotMetadataClaim>* out_owners = nullptr,
    std::vector<ApplePhysicalExtentRecord>* out_resolved = nullptr)
{
    std::vector<AppleSnapshotMetadataClaim> owners;
    if (!work.Tick() || !(read_only ?
        LoadAppleReadOnlySnapshotCatalog(store, checkpoint, oid, catalog, owners, work.error) :
        LoadAppleSnapshotCatalog(store, checkpoint, oid, catalog, owners, work.error))) return false;
    if (catalog.inventory.size() != catalog.snapshots.size())
    { work.error = "SnapshotAttributionInventoryMismatch"; return false; }
    for (const auto& item : catalog.inventory)
        if (!item.xid || item.xid > checkpoint.container.superblock.xid)
        { work.error = "SnapshotAttributionViewIdentityAmbiguous"; return false; }
    if (!work.Take(catalog.snapshots.size(), sizeof(AttributionView))) return false;
    snapshots.resize(catalog.snapshots.size());
    const auto& nx = checkpoint.container.superblock;
    const auto metadata = [&](const AppleVolumeCheckpointView& volume,
        const AppleSnapshotTreeRecords& trees, std::uint64_t xid, AttributionView& view) {
        if (trees.filesystem_blocks.empty() || trees.extentref_blocks.empty() ||
            !work.Append(view.metadata, volume.superblock_object.physical_block, 1, nx.block_count))
        { if (work.error.empty()) work.error = "SnapshotAttributionMetadataCoverageMissing"; return false; }
        for (const auto* blocks : {&trees.filesystem_blocks, &trees.extentref_blocks})
            for (const auto block : *blocks)
                if (!work.Append(view.metadata, block, 1, nx.block_count)) return false;
        bool object = false, node = false;
        // A creation XID can equal the live endpoint. Bind OMAP dependencies
        // to its exact physical map identity as well as the view XID; selected
        // FS/extentref walks and APSB locations already carry exact identities.
        for (const auto& owner : owners)
        {
            if (!work.Take(1, 1)) return false;
            if (owner.volume_oid != oid || owner.view_xid != xid ||
                owner.map_oid != volume.object_map.object.object_id) continue;
            if (owner.metadata_class != AppleSnapshotMetadataClass::OmapObject &&
                owner.metadata_class != AppleSnapshotMetadataClass::OmapNode &&
                owner.metadata_class != AppleSnapshotMetadataClass::OmapSnapshotNode) continue;
            object |= owner.metadata_class == AppleSnapshotMetadataClass::OmapObject;
            node |= owner.metadata_class == AppleSnapshotMetadataClass::OmapNode;
            if (!work.Append(view.metadata, owner.physical_block, owner.block_count, nx.block_count)) return false;
        }
        if (!object || !node) { work.error = "SnapshotAttributionOmapCoverageMissing"; return false; }
        return true;
    };
    const auto volume = std::find_if(checkpoint.volumes.begin(), checkpoint.volumes.end(),
        [&](const auto& item) { return item.superblock.object_id == oid; });
    if (volume == checkpoint.volumes.end()) { work.error = "SnapshotAttributionVolumeMissing"; return false; }
    if (!metadata(*volume, catalog.live, nx.xid, live)) return false;
    for (std::size_t i = 0; i < snapshots.size(); ++i)
        if (!metadata(catalog.inventory[i].volume, catalog.snapshots[i], catalog.inventory[i].xid, snapshots[i])) return false;
    std::vector<ApplePhysicalExtentRecord> prior, historical;
    const auto resolve = [&](const AppleSnapshotTreeRecords& trees, AttributionView& view) {
        for (const auto count : {prior.size(), historical.size(), trees.filesystem.size(), trees.extentref.size()})
            if (!work.Take(count, 2048)) return false;
        std::vector<ApplePhysicalExtentRecord> resolved;
        if (!(read_only ? rw::ResolveAppleReadOnlySnapshotExtentLayer : rw::ResolveAppleSnapshotExtentLayer)(prior, historical, trees.filesystem, trees.extentref,
            nx.block_size, nx.block_count, resolved, work.error)) return false;
        for (const auto& extent : resolved)
            if (!work.Append(view.payload, extent.physical_block, extent.block_count, nx.block_count)) return false;
        if (marked_records)
        {
            if (!(*marked_records)(trees)) return false;
        }
        else
        {
        // Primary format: INODE_IS_PURGEABLE (0x80000), not the WANT flag.
        // The authoritative ordinary profile rejects these marks/xfields; never
        // promote a future wider decoder to known-zero marked payload silently.
        for (const auto& record : trees.filesystem)
        {
            if (!work.Tick()) return false;
            if (record.key.empty() || (ReadU64LE(record.key, 0).value_or(0) >> 60) != 3) continue;
            rw::AppleInodeRecord inode;
            if (!work.Take(1, record.value.size() + sizeof(inode)) ||
                !(read_only ? rw::ApfsExtendedRecordCodec::DecodeInodeReadOnly : rw::ApfsExtendedRecordCodec::DecodeInode)(record, inode, work.error)) return false;
            if (inode.internal_flags & 0x180000ull || std::any_of(inode.extended_fields.begin(), inode.extended_fields.end(),
                [](const auto& field) { return field.type == 15; }))
            { work.error = "SnapshotAttributionPurgeableProfileUnsupported"; return false; }
        }
        }
        if (!work.Take(resolved.size(), sizeof(ApplePhysicalExtentRecord))) return false;
        historical.insert(historical.end(), resolved.begin(), resolved.end());
        prior = std::move(resolved);
        return work.Normalize(view.metadata) && work.Normalize(view.payload);
    };
    for (std::size_t i = 0; i < snapshots.size(); ++i)
        if (!resolve(catalog.snapshots[i], snapshots[i])) return false;
    if (!resolve(catalog.live, live)) return false;
    if (out_owners) *out_owners = std::move(owners);
    if (out_resolved) *out_resolved = std::move(historical);
    return true;
}

bool MarkedExtentRecords(const AppleSnapshotTreeRecords& trees, const NxSuperblock& nx,
    AttributionWork& work, ApfsMarkedFileExtentRecordView& row, std::vector<Range>& ranges,
    const std::unordered_set<std::uint64_t>* additional_streams = nullptr)
{
    constexpr std::uint64_t marked = 0x80000, wants = 0x100000;
    constexpr std::uint64_t allowed = 0x8 | 0x20 | 0x40 | 0x100 | 0x8000 |
        rw::kAppleInodeSparseFlag | rw::kAppleInodeHasUncompressedSize | marked | wants;
    std::unordered_set<std::uint64_t> streams;
    for (const auto& record : trees.filesystem)
    {
        if (!work.Take(1, 1)) return false;
        const auto key = ReadU64LE(record.key, 0);
        if (!key || ((*key >> 60) != 3 && (*key >> 60) != 4 && (*key >> 60) != 5 &&
            (*key >> 60) != 6 && (*key >> 60) != 8 && (*key >> 60) != 9 && (*key >> 60) != 12))
        { work.error = "MarkedExtentFilesystemRecordUnsupported"; return false; }
        if ((*key >> 60) != 3) continue;
        rw::AppleInodeRecord inode;
        if (!work.Take(1, record.value.size() + sizeof(inode)) ||
            !rw::ApfsExtendedRecordCodec::DecodeInodeReadOnly(record, inode, work.error)) return false;
        if (inode.reserved_pad || (inode.internal_flags & ~allowed) ||
            (inode.bsd_flags & rw::kAppleBsdCompressedFlag))
        { work.error = "MarkedExtentInodeProfileUnsupported"; return false; }
        for (const auto& field : inode.extended_fields)
            if ((field.type != 4 && field.type != 8 && field.type != 13) ||
                (field.flags && !((field.type == 4 && field.flags == 2) || (field.type == 8 && field.flags == 32))))
            { work.error = "MarkedExtentInodeFieldUnsupported"; return false; }
        if (!(inode.internal_flags & (marked | wants))) continue;
        if ((inode.mode & 0170000) != 0100000 || !inode.private_id)
        { work.error = "MarkedExtentNonRegularInodeUnsupported"; return false; }
        if (inode.internal_flags & marked)
        {
            if (!work.Take(1, sizeof(std::uint64_t) + 64)) return false;
            streams.insert(inode.private_id); ++row.marked_regular_inode_count;
        }
        else ++row.want_only_regular_inode_count;
    }
    for (const auto& record : trees.filesystem)
    {
        if (!work.Take(1, 1)) return false;
        if ((ReadU64LE(record.key, 0).value_or(0) >> 60) != 8) continue;
        rw::AppleFileExtentRecord extent;
        if (!rw::DecodeAppleFileExtentRecord(record, nx.block_size, extent, work.error)) return false;
        if (extent.crypto_id) { work.error = "MarkedExtentEncryptedRecordUnsupported"; return false; }
        if (extent.physical_block && (streams.contains(extent.object_id) ||
            (additional_streams && additional_streams->contains(extent.object_id))) &&
            !work.Append(ranges, extent.physical_block, extent.length_bytes / nx.block_size, nx.block_count)) return false;
    }
    return work.Normalize(ranges) && work.Count(ranges, nx.block_size, row.referenced_physical);
}
}

static bool AttributeSnapshotSpaceWithAdmission(const RandomAccessSource& source, const VerificationScope& scope,
    std::optional<ApfsSnapshotSpaceAttribution>& out, std::string& error,
    const std::function<bool()>& within_deadline, bool read_only)
{
    out.reset(); error.clear();
    if (scope.require_whole_volume || scope.require_payload_content_hashes || scope.observe_payload_content)
    { error = "SnapshotAttributionScopeUnsupported"; return false; }
    auto budget = source.ReadBudget();
    try
    {
        if (!budget) budget = std::make_shared<ApfsReadBudget>(scope.max_reads, scope.max_read_bytes,
            scope.max_records, scope.max_record_bytes);
        else budget->LimitRemainingTo(scope.max_reads, scope.max_read_bytes, scope.max_records, scope.max_record_bytes);
        AttributionWork work{budget, within_deadline, error};
        if (!work.Tick()) return false;
        BudgetedRandomAccessSource allowance(source, budget);
        AccountingSource bounded(allowance, [&] { return work.Tick(); });
        auto requested = scope; requested.account_retained_ownership = true;
        const auto verified = read_only ? ApfsVerifier::VerifyReadOnly(bounded, requested, [&] { return work.Tick(); }) :
            ApfsVerifier::Verify(bounded, requested, [&] { return work.Tick(); });
        if (verified.outcome != VerificationOutcome::Complete || !verified.selected || !verified.retained_ownership)
        {
            if (budget->Failed()) error = budget->Failure();
            else error = "SnapshotAttributionVerificationIncomplete" +
                (verified.findings.empty() ? std::string{} : ":" + verified.findings.front().detail);
            return false;
        }
        OffsetRandomAccessSource store(&bounded, scope.exact.store_offset_bytes, scope.exact.store_size_bytes);
        const auto checkpoint = LoadAppleCheckpointView(store, 0, store.SizeBytes(), error, scope.exact.checkpoint_xid);
        if (!checkpoint || !work.Tick()) return false;
        const auto& nx = checkpoint->container.superblock;
        if (nx.uuid_hex != scope.exact.container_uuid_hex || nx.xid != scope.exact.checkpoint_xid ||
            nx.block_count > UINT64_MAX / nx.block_size || nx.block_count * nx.block_size != store.SizeBytes())
        { error = "SnapshotAttributionIdentityMismatch"; return false; }
        const auto selected = std::find_if(checkpoint->volumes.begin(), checkpoint->volumes.end(), [&](const auto& volume) {
            return volume.superblock.object_id == scope.exact.volume_oid;
        });
        if (selected == checkpoint->volumes.end() || selected->superblock.uuid_hex != scope.exact.volume_uuid_hex)
        { error = "SnapshotAttributionIdentityMismatch"; return false; }
        if (!work.Take(1, sizeof(ApfsSnapshotSpaceAttribution) + scope.source_identity.size() +
            scope.exact.container_uuid_hex.size() + scope.exact.volume_uuid_hex.size())) return false;
        ApfsSnapshotSpaceAttribution result;
        result.source_identity = scope.source_identity; result.scope = scope.exact;
        result.allocation_unit_bytes = nx.block_size;
        if (!work.Take(verified.retained_ownership->checkpoint_xids.size(), sizeof(std::uint64_t))) return false;
        result.retained_checkpoint_xids = verified.retained_ownership->checkpoint_xids;
        AppleSnapshotCatalogRecords catalog;
        std::vector<AttributionView> views;
        AttributionView live;
        if (!AttributionCatalog(store, *checkpoint, scope.exact.volume_oid, work, catalog, views, live, read_only)) return false;
        std::vector<Range> external, all_metadata, all_payload, catalog_metadata;
        for (const auto block : catalog.metadata_blocks)
            if (!work.Append(catalog_metadata, block, 1, nx.block_count)) return false;
        if (!work.Normalize(catalog_metadata) || !work.Count(catalog_metadata, nx.block_size, result.catalog_metadata)) return false;
        // Historical claims authenticate independent roots, including hidden
        // descriptors and peer volumes. Never subtract the target from a union
        // and assume that all remaining shared ownership has disappeared.
        std::vector<rw::AppleRecoveryCheckpointView> history;
        if (!(read_only ? rw::LoadAppleReadOnlySnapshotRecoveryCheckpoints(store, *checkpoint, result.retained_checkpoint_xids, history, error) :
            rw::LoadAppleSnapshotRecoveryCheckpoints(store, *checkpoint, result.retained_checkpoint_xids, history, error))) return false;
        for (const auto& old : history)
        {
            for (const auto block : old.metadata_blocks)
                if (!work.Append(external, block, 1, nx.block_count)) return false;
            for (const auto& extent : old.payload_extents)
                if (!work.Append(external, extent.physical_block, extent.block_count, nx.block_count)) return false;
        }
        for (const auto& volume : checkpoint->volumes)
        {
            if (volume.superblock.object_id == scope.exact.volume_oid) continue;
            AppleSnapshotCatalogRecords peer;
            std::vector<AttributionView> peer_snapshots;
            AttributionView peer_live;
            if (!AttributionCatalog(store, *checkpoint, volume.superblock.object_id, work, peer, peer_snapshots, peer_live, read_only)) return false;
            for (const auto block : peer.metadata_blocks)
                if (!work.Append(external, block, 1, nx.block_count)) return false;
            if (!work.Join(external, peer_live.payload)) return false;
            for (const auto& view : peer_snapshots)
                if (!work.Join(external, view.payload)) return false;
        }
        if (!work.Normalize(external) || !work.Take(views.size(), sizeof(ApfsSnapshotSpaceAttributionRow))) return false;
        for (std::size_t i = 0; i < views.size(); ++i)
        {
            std::vector<Range> other_metadata, other_payload;
            for (std::size_t j = 0; j < views.size(); ++j)
            {
                if (!work.Take(1, 1)) return false; // Bound work even for empty views.
                if (i != j && (!work.Join(other_metadata, views[j].metadata) || !work.Join(other_payload, views[j].payload))) return false;
            }
            ApfsSnapshotSpaceAttributionRow row;
            if (!work.Take(1, catalog.inventory[i].name_utf8.size())) return false;
            row.snapshot_xid = catalog.inventory[i].xid; row.name_utf8 = catalog.inventory[i].name_utf8;
            if (!work.Measure(views[i].metadata, live.metadata, other_metadata, external, nx.block_size, row.metadata) ||
                !work.Measure(views[i].payload, live.payload, other_payload, external, nx.block_size, row.payload) ||
                !work.Join(all_metadata, views[i].metadata) || !work.Join(all_payload, views[i].payload)) return false;
            result.snapshots.push_back(std::move(row));
        }
        if (!work.Count(all_metadata, nx.block_size, result.referenced_metadata) ||
            !work.Count(all_payload, nx.block_size, result.referenced_payload) || !work.Tick() || bounded.failed)
        { if (error.empty()) error = "SnapshotAttributionSourceReadFailed"; return false; }
        result.complete = true; result.read_budget = budget;
        out = std::move(result); return true;
    }
    catch (const std::bad_alloc&) { if (budget) (void)budget->Refuse("ApfsReadBudgetAllocationFailed"); error = "ApfsReadBudgetAllocationFailed"; }
    catch (const std::length_error&) { if (budget) (void)budget->Refuse("ApfsReadBudgetAllocationFailed"); error = "ApfsReadBudgetAllocationFailed"; }
    catch (const std::exception&) { error = "SnapshotAttributionSourceException"; }
    return false;
}

bool TryAttributeAppleSnapshotSpace(const RandomAccessSource& source, const VerificationScope& scope,
    std::optional<ApfsSnapshotSpaceAttribution>& out, std::string& error, const std::function<bool()>& within_deadline)
{
    return AttributeSnapshotSpaceWithAdmission(source, scope, out, error, within_deadline, false);
}

bool TryAttributeAppleSnapshotSpaceReadOnly(const RandomAccessSource& source, const VerificationScope& scope,
    std::optional<ApfsSnapshotSpaceAttribution>& out, std::string& error, const std::function<bool()>& within_deadline)
{
    return AttributeSnapshotSpaceWithAdmission(source, scope, out, error, within_deadline, true);
}

bool TryObserveAppleSnapshotAllocationCountersReadOnly(const RandomAccessSource& source, const VerificationScope& scope,
    std::optional<ApfsSnapshotAllocationCounters>& out, std::string& error, const std::function<bool()>& within_deadline)
{
    out.reset(); error.clear();
    if (scope.account_retained_ownership || scope.retained_from_xid)
    { error = "SnapshotAllocationCounterScopeUnsupported"; return false; }
    auto budget = source.ReadBudget();
    try
    {
        if (!budget) budget = std::make_shared<ApfsReadBudget>(scope.max_reads, scope.max_read_bytes,
            scope.max_records, scope.max_record_bytes);
        else budget->LimitRemainingTo(scope.max_reads, scope.max_read_bytes, scope.max_records, scope.max_record_bytes);
        AttributionWork work{budget, within_deadline, error};
        BudgetedRandomAccessSource allowance(source, budget);
        AccountingSource bounded(allowance, [&] { return work.Tick(); });
        std::optional<ApfsSnapshotSpaceAttribution> attribution;
        if (!TryAttributeAppleSnapshotSpaceReadOnly(bounded, scope, attribution, error, within_deadline) ||
            !attribution || !attribution->complete || !work.Tick()) return false;
        rw::SnapshotPlanningSource observed(bounded);
        OffsetRandomAccessSource store(&observed, scope.exact.store_offset_bytes, scope.exact.store_size_bytes);
        const auto checkpoint = LoadAppleCheckpointView(store, 0, store.SizeBytes(), error, scope.exact.checkpoint_xid);
        if (!checkpoint || checkpoint->container.superblock.uuid_hex != scope.exact.container_uuid_hex)
        { if (error.empty()) error = "SnapshotAllocationCounterBindingMismatch"; return false; }
        AppleSnapshotCatalogRecords catalog;
        std::vector<AppleSnapshotMetadataClaim> owners;
        if (!LoadAppleReadOnlySnapshotCatalog(store, *checkpoint, scope.exact.volume_oid, catalog, owners, error) ||
            catalog.inventory.size() != attribution->snapshots.size())
        { if (error.empty()) error = "SnapshotAllocationCounterInventoryMismatch"; return false; }
        ApfsSnapshotAllocationCounters result;
        if (!work.Take(1, sizeof(result) + scope.source_identity.size()) ||
            !work.Take(catalog.inventory.size(), sizeof(ApfsSnapshotAllocationCounterRow))) return false;
        result.source_identity = scope.source_identity; result.scope = scope.exact;
        result.allocation_unit_bytes = checkpoint->container.superblock.block_size;
        for (std::size_t i = 0; i < catalog.inventory.size(); ++i)
        {
            const auto& snapshot = catalog.inventory[i]; const auto& expected = attribution->snapshots[i];
            const auto& descriptor = snapshot.volume.superblock_object;
            const auto blocks = snapshot.volume.superblock.space.allocated_block_count;
            if (!work.Tick() || snapshot.xid != expected.snapshot_xid || snapshot.name_utf8 != expected.name_utf8 ||
                snapshot.volume.superblock.uuid_hex != scope.exact.volume_uuid_hex ||
                descriptor.xid < snapshot.xid || descriptor.xid > scope.exact.checkpoint_xid ||
                descriptor.object_id != descriptor.physical_block || descriptor.size_bytes != result.allocation_unit_bytes ||
                descriptor.type != (kObjectPhysical | kObjectTypeFs) || descriptor.subtype ||
                blocks > UINT64_MAX / result.allocation_unit_bytes ||
                blocks > scope.exact.store_size_bytes / result.allocation_unit_bytes)
            { if (error.empty()) error = "SnapshotAllocationCounterDescriptorInvalid"; return false; }
            if (!work.Take(1, snapshot.name_utf8.size())) return false;
            result.snapshots.push_back({snapshot.xid, snapshot.name_utf8, descriptor,
                {blocks, blocks * result.allocation_unit_bytes}});
        }
        if (bounded.failed || !observed.VerifyUnchanged(error) || !work.Tick())
        { if (error.empty()) error = "SnapshotAllocationCounterSourceChanged"; return false; }
        result.complete = true; result.read_budget = budget;
        out = std::move(result); return true;
    }
    catch (const std::bad_alloc&) { if (budget) (void)budget->Refuse("ApfsReadBudgetAllocationFailed"); error = "ApfsReadBudgetAllocationFailed"; }
    catch (const std::length_error&) { if (budget) (void)budget->Refuse("ApfsReadBudgetAllocationFailed"); error = "ApfsReadBudgetAllocationFailed"; }
    catch (...) { error = "SnapshotAllocationCounterReadFailure"; }
    return false;
}

#include "MarkedOwnerSpaceAccounting.inc"

static bool ObserveAppleMarkedFileExtentRecordsImpl(const RandomAccessSource& source, const VerificationScope& scope,
    std::optional<ApfsMarkedFileExtentRecordsObservation>& out, std::string& error,
    const std::function<bool()>& within_deadline, bool marked_references,
    ApfsMarkedReferenceSpaceObservation* expanded = nullptr, ApfsMarkedOwnerSpaceAttribution* attributed = nullptr)
{
    out.reset(); error.clear();
    if (scope.require_whole_volume || scope.require_payload_content_hashes || scope.observe_payload_content ||
        scope.account_retained_ownership || scope.retained_from_xid || scope.source_identity.empty())
    { error = "MarkedExtentScopeUnsupported"; return false; }
    auto budget = source.ReadBudget();
    try
    {
        if (!budget) budget = std::make_shared<ApfsReadBudget>(scope.max_reads, scope.max_read_bytes,
            scope.max_records, scope.max_record_bytes);
        else budget->LimitRemainingTo(scope.max_reads, scope.max_read_bytes, scope.max_records, scope.max_record_bytes);
        AttributionWork work{budget, within_deadline, error};
        if (!work.Tick()) return false;
        BudgetedRandomAccessSource allowance(source, budget);
        AccountingSource bounded(allowance, [&] { return work.Tick(); });
        if (scope.exact.store_offset_bytes > source.SizeBytes() || !scope.exact.store_size_bytes ||
            scope.exact.store_size_bytes > source.SizeBytes() - scope.exact.store_offset_bytes)
        { error = "MarkedExtentStoreWindowInvalid"; return false; }
        OffsetRandomAccessSource store(&bounded, scope.exact.store_offset_bytes, scope.exact.store_size_bytes);
        rw::SnapshotPlanningSource stable(store);
        auto checkpoint = LoadAppleCheckpointView(stable, 0, stable.SizeBytes(), error);
        if (!checkpoint || !work.Tick()) return false;
        const auto& nx = checkpoint->container.superblock;
        if (nx.uuid_hex != scope.exact.container_uuid_hex || nx.xid != scope.exact.checkpoint_xid ||
            nx.block_count > UINT64_MAX / nx.block_size || nx.block_count * nx.block_size != stable.SizeBytes())
        { error = "MarkedExtentIdentityMismatch"; return false; }
        const auto selected = std::find_if(checkpoint->volumes.begin(), checkpoint->volumes.end(),
            [&](const auto& volume) { return volume.superblock.object_id == scope.exact.volume_oid; });
        if (selected == checkpoint->volumes.end() || selected->superblock.uuid_hex != scope.exact.volume_uuid_hex)
        { error = "MarkedExtentIdentityMismatch"; return false; }
        if ((nx.features & ~kNxKnownOptionalFeaturesMask) || nx.readonly_features ||
            (nx.incompatible_features & ~kNxSupportedIncompatibleFeaturesMask) ||
            (selected->superblock.features & ~kVolumeKnownOptionalFeaturesMask) ||
            selected->superblock.fs_flags != kFsFlagUnencrypted ||
            !rw::CheckAppleVolumeWriteFeatures(nx, selected->superblock, error))
        { error = "MarkedExtentFeaturesUnsupported"; return false; }
        if (!work.Take(1, sizeof(ApfsMarkedFileExtentRecordsObservation) + scope.source_identity.size() +
            scope.exact.container_uuid_hex.size() + scope.exact.volume_uuid_hex.size())) return false;
        ApfsMarkedFileExtentRecordsObservation result;
        result.source_identity = scope.source_identity; result.scope = scope.exact; result.allocation_unit_bytes = nx.block_size;
        if (attributed) { attributed->marked.records.scope = scope.exact; attributed->marked.records.allocation_unit_bytes = nx.block_size; }
        std::vector<Range> all, all_file_payload;
        AppleSnapshotCatalogRecords catalog; std::vector<AttributionView> snapshots; AttributionView live;
        std::vector<AppleSnapshotMetadataClaim> owners; std::vector<ApplePhysicalExtentRecord> resolved;
        const std::function<bool(const AppleSnapshotTreeRecords&)> observe = [&](const auto& trees) {
            std::unordered_set<std::uint64_t> attribute_streams, unmarked_streams;
            if (marked_references)
            {
                const auto index = result.views.size();
                const auto& descriptor = index < catalog.inventory.size() ?
                    catalog.inventory[index].volume.superblock : selected->superblock;
                rw::NativeApfsVolumeProjection projection;
                if (!rw::NativeApfsReader::TryProjectMarkedReferenceFileSystemRecords(
                    trees.filesystem, nx, descriptor, budget, projection, error) || !work.Tick()) return false;
                for (const auto& inode : projection.inodes)
                {
                    if (!work.Take(1, 0)) return false;
                    const bool marked = (inode.internal_flags & 0x80000) != 0;
                    if (attributed && !marked)
                    {
                        if (!work.Take(1, sizeof(std::uint64_t) + 64)) return false;
                        unmarked_streams.insert(inode.private_id);
                    }
                    if (!marked && !attributed) continue;
                    const auto attributes = projection.extended_attributes_by_inode.find(inode.object_id);
                    if (attributes == projection.extended_attributes_by_inode.end()) continue;
                    for (const auto& [name, attribute] : attributes->second)
                    {
                        if (!work.Take(1, 0)) return false;
                        if (!(attribute.flags & rw::kAppleXattrDataStream)) continue;
                        // This canonical descriptor and stream relation were
                        // already checked by the namespace/stream projector.
                        const auto stream = ReadU64LE(attribute.data, 0).value_or(0);
                        if (!stream || !projection.attribute_stream_extents.contains(stream))
                        { error = "MarkedReferenceAttributeStreamInvalid"; return false; }
                        if (!work.Take(1, sizeof(std::uint64_t) + 64)) return false;
                        if (marked) attribute_streams.insert(stream);
                        else unmarked_streams.insert(stream);
                    }
                }
            }
            ApfsMarkedFileExtentRecordView row; std::vector<Range> ranges;
            if (!work.Take(1, sizeof(row)) || !MarkedExtentRecords(trees, nx, work, row, ranges) ||
                !work.Join(all, ranges)) return false;
            if (expanded)
            {
                ApfsMarkedFileExtentRecordView full; std::vector<Range> file_ranges;
                if (!MarkedExtentRecords(trees, nx, work, full, file_ranges, &attribute_streams) ||
                    !work.Join(all_file_payload, file_ranges) ||
                    !work.Take(1, sizeof(ApfsMarkedFilePayloadView)) ||
                    !work.Take(file_ranges.size(), sizeof(VerificationBlockRange))) return false;
                ApfsMarkedFilePayloadView view; view.referenced_physical = full.referenced_physical;
                for (const auto& range : file_ranges) view.ranges.push_back({range.begin, range.end - range.begin});
                expanded->marked_file_payload.push_back(std::move(view));
            }
            if (attributed)
            {
                std::vector<Range> unmarked;
                for (const auto& record : trees.filesystem)
                {
                    if (!work.Take(1, 0)) return false;
                    if ((ReadU64LE(record.key, 0).value_or(0) >> 60) != 8) continue;
                    rw::AppleFileExtentRecord extent;
                    if (!rw::DecodeAppleFileExtentRecord(record, nx.block_size, extent, error)) return false;
                    if (extent.physical_block && unmarked_streams.contains(extent.object_id) &&
                        !work.Append(unmarked, extent.physical_block, extent.length_bytes / nx.block_size, nx.block_count)) return false;
                }
                if (!work.Normalize(unmarked) || !work.Take(1, sizeof(ApfsMarkedOwnerView))) return false;
                ApfsMarkedOwnerView view;
                if (!OwnerRanges(unmarked, view.unmarked_payload_ranges, work)) return false;
                attributed->views.push_back(std::move(view));
            }
            result.views.push_back(std::move(row)); return true;
        };
        if (!AttributionCatalog(stable, *checkpoint, scope.exact.volume_oid, work, catalog, snapshots, live, true, &observe,
            marked_references ? &owners : nullptr, marked_references ? &resolved : nullptr)) return false;
        if (result.views.size() != catalog.inventory.size() + 1)
        { error = "MarkedExtentInventoryMismatch"; return false; }
        for (std::size_t i = 0; i < catalog.inventory.size(); ++i)
        {
            if (!work.Take(1, catalog.inventory[i].name_utf8.size())) return false;
            result.views[i].view_xid = catalog.inventory[i].xid;
            result.views[i].snapshot_name_utf8 = catalog.inventory[i].name_utf8;
        }
        result.views.back().current = true; result.views.back().view_xid = nx.xid;
        if (!work.Count(all, nx.block_size, result.referenced_physical_union)) return false;
        if (expanded && !work.Count(all_file_payload, nx.block_size, expanded->marked_file_payload_union)) return false;
        if (attributed && !BuildMarkedOwnerSpace(stable, *checkpoint, work, catalog, snapshots, live, *attributed)) return false;
        if (marked_references)
        {
            rw::AppleRecoveryCheckpointView pin;
            pin.checkpoint = std::move(*checkpoint); pin.payload_extents = std::move(resolved);
            for (const auto& owner : owners)
            {
                if (!owner.block_count || owner.physical_block >= pin.checkpoint.container.superblock.block_count ||
                    owner.block_count > pin.checkpoint.container.superblock.block_count - owner.physical_block)
                { error = "MarkedReferenceMetadataRangeInvalid"; return false; }
                if (!work.Take(owner.block_count, sizeof(std::uint64_t))) return false;
                for (std::uint64_t i = 0; i < owner.block_count; ++i)
                    pin.metadata_blocks.push_back(owner.physical_block + i);
            }
            std::sort(pin.metadata_blocks.begin(), pin.metadata_blocks.end());
            pin.metadata_blocks.erase(std::unique(pin.metadata_blocks.begin(), pin.metadata_blocks.end()), pin.metadata_blocks.end());
            if (!rw::VerifyProfileRecoveryContinuity(stable, pin, {}, pin.checkpoint, false, error)) return false;
        }
        if (!stable.VerifyUnchanged(error) || !work.Tick() || bounded.failed) return false;
        result.complete = true; result.read_budget = budget; out = std::move(result); return true;
    }
    catch (const std::bad_alloc&) { if (budget) (void)budget->Refuse("ApfsReadBudgetAllocationFailed"); error = "ApfsReadBudgetAllocationFailed"; }
    catch (const std::length_error&) { if (budget) (void)budget->Refuse("ApfsReadBudgetAllocationFailed"); error = "ApfsReadBudgetAllocationFailed"; }
    catch (const std::exception&) { error = "MarkedExtentSourceException"; }
    return false;
}

bool TryObserveAppleMarkedFileExtentRecords(const RandomAccessSource& source, const VerificationScope& scope,
    std::optional<ApfsMarkedFileExtentRecordsObservation>& out, std::string& error,
    const std::function<bool()>& within_deadline)
{
    return ObserveAppleMarkedFileExtentRecordsImpl(source, scope, out, error, within_deadline, false);
}

bool TryObserveAppleMarkedReferenceSpaceReadOnly(const RandomAccessSource& source, const VerificationScope& scope,
    std::optional<ApfsMarkedReferenceSpaceObservation>& out, std::string& error,
    const std::function<bool()>& within_deadline)
{
    out.reset(); std::optional<ApfsMarkedFileExtentRecordsObservation> records;
    ApfsMarkedReferenceSpaceObservation result;
    if (!ObserveAppleMarkedFileExtentRecordsImpl(source, scope, records, error, within_deadline, true, &result)) return false;
    result.records = std::move(*records);
    result.namespace_and_directory7_references_verified = result.catalog_metadata_and_payload_allocation_verified = true;
    out = std::move(result); return true;
}

bool TryAttributeAppleMarkedOwnerSpaceReadOnly(const RandomAccessSource& source, const VerificationScope& scope,
    std::optional<std::uint64_t> from_xid, std::optional<ApfsMarkedOwnerSpaceAttribution>& out,
    std::string& error, const std::function<bool()>& within_deadline)
{
    out.reset(); error.clear();
    if (from_xid && (!*from_xid || *from_xid >= scope.exact.checkpoint_xid))
    { error = "MarkedOwnerHistoryScopeInvalid"; return false; }
    ApfsMarkedOwnerSpaceAttribution result; result.from_xid = from_xid;
    std::optional<ApfsMarkedFileExtentRecordsObservation> records;
    if (!ObserveAppleMarkedFileExtentRecordsImpl(source, scope, records, error, within_deadline,
        true, &result.marked, &result)) return false;
    result.marked.records = std::move(*records);
    result.marked.namespace_and_directory7_references_verified = result.marked.catalog_metadata_and_payload_allocation_verified = true;
    out = std::move(result); return true;
}
#include "ProfileSnapshotSpaceAttribution.inc"
}
